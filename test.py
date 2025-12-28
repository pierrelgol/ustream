#!/usr/bin/env python3
import socket
import struct
import sys

PORT = 5004
OUT = "dump.h264"

START_CODE = b"\x00\x00\x00\x01"

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", PORT))

    f = open(OUT, "wb")

    fu_buffer = None
    fu_type = None

    print(f"Listening on UDP {PORT}, writing to {OUT}")

    while True:
        data, _ = sock.recvfrom(65536)
        if len(data) < 12:
            continue

        # --- RTP header ---
        b0, b1, seq, ts, ssrc = struct.unpack(">BBHII", data[:12])
        version = b0 >> 6
        marker = (b1 >> 7) & 1
        payload_type = b1 & 0x7F

        payload = data[12:]

        if not payload:
            continue

        nal_header = payload[0]
        nal_type = nal_header & 0x1F

        # --- Single NAL ---
        if nal_type < 24:
            f.write(START_CODE)
            f.write(payload)
            fu_buffer = None

        # --- FU-A ---
        elif nal_type == 28:
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
                fu_buffer += START_CODE
                fu_buffer += reconstructed_header
                fu_buffer += fragment
                fu_type = orig_type
            else:
                if fu_buffer is None:
                    print("ERROR: FU-A continuation without start")
                    continue
                fu_buffer += fragment

            if end:
                f.write(fu_buffer)
                fu_buffer = None
                fu_type = None

        else:
            print(f"Unhandled NAL type {nal_type}")

        # Optional: observe frame boundaries
        if marker:
            sys.stdout.write(".")
            sys.stdout.flush()

    f.close()

if __name__ == "__main__":
    main()

