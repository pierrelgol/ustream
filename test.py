#!/usr/bin/env python3
import argparse
import hashlib
import os
import socket
import struct
import sys
import time

DEFAULT_PORT = 5004
DEFAULT_OUT = "dump.h264"

START_CODE_3 = b"\x00\x00\x01"
START_CODE_4 = b"\x00\x00\x00\x01"


def detect_start_code_len(path):
    with open(path, "rb") as f:
        data = f.read(1024 * 1024)
    i = 0
    while i + 3 < len(data):
        if data[i : i + 4] == START_CODE_4:
            return 4
        if data[i : i + 3] == START_CODE_3:
            return 3
        i += 1
    return 4


def collect_start_code_lengths(path):
    lengths = []
    buf = b""
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            data = buf + chunk
            i = 0
            end = len(data) - 4
            while i <= end:
                if data[i : i + 4] == START_CODE_4:
                    lengths.append(4)
                    i += 4
                elif data[i : i + 3] == START_CODE_3:
                    lengths.append(3)
                    i += 3
                else:
                    i += 1
            buf = data[i:]
    return lengths


def hash_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def parse_rtp_header(data):
    if len(data) < 12:
        return None
    b0, b1, seq, ts, ssrc = struct.unpack(">BBHII", data[:12])
    version = b0 >> 6
    padding = (b0 >> 5) & 1
    extension = (b0 >> 4) & 1
    csrc_count = b0 & 0x0F
    marker = (b1 >> 7) & 1
    payload_type = b1 & 0x7F
    header_len = 12 + csrc_count * 4
    if len(data) < header_len:
        return None
    if extension:
        if len(data) < header_len + 4:
            return None
        ext_len = struct.unpack(">H", data[header_len + 2 : header_len + 4])[0]
        header_len += 4 + ext_len * 4
        if len(data) < header_len:
            return None
    if padding:
        pad = data[-1]
        if pad == 0 or pad > len(data) - header_len:
            return None
        payload = data[header_len : -pad]
    else:
        payload = data[header_len:]
    return {
        "version": version,
        "marker": marker,
        "payload_type": payload_type,
        "sequence": seq,
        "timestamp": ts,
        "ssrc": ssrc,
        "payload": payload,
    }


def main():
    parser = argparse.ArgumentParser(
        description="RTP/H.264 receiver that reconstitutes a raw H.264 stream."
    )
    parser.add_argument("--input", required=True, help="Original input file to compare against.")
    parser.add_argument("--output", default=DEFAULT_OUT, help="Output H.264 path.")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Bind port.")
    parser.add_argument("--duration", type=float, default=0, help="Capture duration in seconds.")
    parser.add_argument("--idle-timeout", type=float, default=2.0, help="Stop after idle seconds.")
    parser.add_argument(
        "--recv-buffer",
        type=int,
        default=4 * 1024 * 1024,
        help="Requested UDP receive buffer size in bytes.",
    )
    parser.add_argument(
        "--no-preserve-start-codes",
        action="store_true",
        help="Do not preserve input start-code lengths in output.",
    )
    parser.add_argument(
        "--start-code",
        choices=["auto", "3", "4"],
        default="auto",
        help="Start code length to write into output.",
    )
    args = parser.parse_args()

    start_code_len = detect_start_code_len(args.input) if args.start_code == "auto" else int(args.start_code)
    start_code = START_CODE_4 if start_code_len == 4 else START_CODE_3
    preserve_start_codes = not args.no_preserve_start_codes
    start_code_seq = collect_start_code_lengths(args.input) if preserve_start_codes else []
    start_code_index = 0
    start_code_3_count = sum(1 for x in start_code_seq if x == 3)
    start_code_4_count = sum(1 for x in start_code_seq if x == 4)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if args.recv_buffer > 0:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, args.recv_buffer)
    effective_buf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
    sock.bind((args.host, args.port))
    sock.settimeout(0.5)

    out = open(args.output, "wb")

    fu_buffer = None

    packets = 0
    bytes_payload = 0
    nal_units = 0
    fu_complete = 0
    fu_errors = 0
    stap_units = 0
    marker_count = 0
    lost_packets = 0
    out_of_order = 0
    dup_packets = 0

    last_seq = None
    start_time = time.time()
    capture_start = None
    last_packet_time = None

    print(f"Listening on UDP {args.host}:{args.port}")
    print(f"UDP receive buffer: {effective_buf} bytes")
    if preserve_start_codes and start_code_seq:
        print(
            f"Writing {args.output} (preserve start codes: {start_code_4_count}x4, {start_code_3_count}x3)"
        )
    else:
        print(f"Writing {args.output} (start code {start_code_len} bytes)")

    last_report = start_time
    last_report_packets = 0
    report_interval = 0.5

    def next_start_code():
        nonlocal start_code_index
        if start_code_index < len(start_code_seq):
            length = start_code_seq[start_code_index]
            start_code_index += 1
            return START_CODE_4 if length == 4 else START_CODE_3
        return start_code

    try:
        while True:
            now = time.time()
            if capture_start is not None and args.duration > 0 and now - capture_start >= args.duration:
                break
            if (
                capture_start is not None
                and args.idle_timeout > 0
                and last_packet_time is not None
                and now - last_packet_time >= args.idle_timeout
            ):
                break

            try:
                data, _ = sock.recvfrom(65536)
            except socket.timeout:
                continue

            header = parse_rtp_header(data)
            if not header or header["version"] != 2:
                continue

            payload = header["payload"]
            if not payload:
                continue

            seq = header["sequence"]
            if last_seq is None:
                last_seq = seq
            else:
                delta = (seq - last_seq) & 0xFFFF
                if delta == 0:
                    dup_packets += 1
                elif delta == 1:
                    pass
                elif delta < 0x8000:
                    lost_packets += delta - 1
                else:
                    out_of_order += 1
                last_seq = seq

            if capture_start is None:
                capture_start = now
                last_report = now
                last_report_packets = 0
                sys.stdout.write("Receiving...\n")
                sys.stdout.flush()

            packets += 1
            bytes_payload += len(payload)
            last_packet_time = now
            if header["marker"]:
                marker_count += 1

            nal_type = payload[0] & 0x1F

            if nal_type < 24:
                out.write(next_start_code())
                out.write(payload)
                nal_units += 1
                fu_buffer = None

            elif nal_type == 24:
                offset = 1
                while offset + 2 <= len(payload):
                    nal_len = struct.unpack(">H", payload[offset : offset + 2])[0]
                    offset += 2
                    if offset + nal_len > len(payload):
                        fu_errors += 1
                        break
                    nal = payload[offset : offset + nal_len]
                    offset += nal_len
                    if nal:
                        out.write(next_start_code())
                        out.write(nal)
                        nal_units += 1
                        stap_units += 1

            elif nal_type == 28:
                if len(payload) < 2:
                    fu_errors += 1
                    continue
                fu_indicator = payload[0]
                fu_header = payload[1]
                start = (fu_header >> 7) & 1
                end = (fu_header >> 6) & 1
                orig_type = fu_header & 0x1F

                nal_f = fu_indicator & 0x80
                nal_nri = fu_indicator & 0x60
                reconstructed_header = bytes([nal_f | nal_nri | orig_type])
                fragment = payload[2:]

                if start:
                    fu_buffer = bytearray()
                    fu_buffer += next_start_code()
                    fu_buffer += reconstructed_header
                    fu_buffer += fragment
                else:
                    if fu_buffer is None:
                        fu_errors += 1
                        continue
                    fu_buffer += fragment

                if end and fu_buffer is not None:
                    out.write(fu_buffer)
                    nal_units += 1
                    fu_complete += 1
                    fu_buffer = None
            else:
                fu_errors += 1

            if now - last_report >= report_interval:
                elapsed = 0.0 if capture_start is None else now - capture_start
                interval = max(1e-6, now - last_report)
                pps = (packets - last_report_packets) / interval
                mb = bytes_payload / (1024 * 1024)
                line = (
                    f"\rPackets {packets} | Payload {mb:.2f} MiB | "
                    f"NAL {nal_units} | Loss {lost_packets} | "
                    f"OOO {out_of_order} | {pps:6.1f} pkt/s | {elapsed:6.1f}s"
                )
                sys.stdout.write(line + " " * max(0, 4))
                sys.stdout.flush()
                last_report = now
                last_report_packets = packets

    except KeyboardInterrupt:
        pass
    finally:
        sys.stdout.write("\n")
        out.close()
        sock.close()

    input_hash = hash_file(args.input)
    output_hash = hash_file(args.output)
    input_size = os.path.getsize(args.input)
    output_size = os.path.getsize(args.output)
    expected_nals = len(start_code_seq) if start_code_seq else None

    loss_pct = 0.0
    if input_size > 0:
        loss_pct = max(0.0, 1.0 - (output_size / input_size)) * 100.0

    print("")
    print("RTP Receive Summary")
    print("-" * 60)
    print(f"Packets received : {packets}")
    print(f"Payload bytes    : {bytes_payload}")
    print(f"Seq gaps (lost)  : {lost_packets}")
    print(f"Out-of-order     : {out_of_order}")
    print(f"Duplicates       : {dup_packets}")
    print(f"Markers          : {marker_count}")
    print(f"NAL units        : {nal_units}")
    print(f"FU-A complete    : {fu_complete}")
    print(f"STAP-A units     : {stap_units}")
    print(f"Decode errors    : {fu_errors}")
    if expected_nals is not None:
        print(f"Input NAL count  : {expected_nals}")
    print("")
    print("File Comparison")
    print("-" * 60)
    print(f"Input  : {args.input} ({input_size} bytes)")
    print(f"Output : {args.output} ({output_size} bytes)")
    print(f"Hash in : {input_hash}")
    print(f"Hash out: {output_hash}")
    print(f"Exact match: {'YES' if input_hash == output_hash else 'NO'}")
    print(f"Size delta : {output_size - input_size} bytes")
    print(f"Loss       : {loss_pct:.2f}%")


if __name__ == "__main__":
    main()
