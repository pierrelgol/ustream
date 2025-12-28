from dataclasses import dataclass
from typing import Iterator, List

START_CODE_3 = b"\x00\x00\x01"
START_CODE_4 = b"\x00\x00\x00\x01"


@dataclass
class NALUnit:
    nal_ref_idc: int
    nal_unit_type: int
    payload: bytes


def find_start_codes(data: bytes) -> List[int]:
    positions = []
    i = 0
    while i < len(data) - 3:
        if data[i:i+4] == START_CODE_4:
            positions.append(i)
            i += 4
        elif data[i:i+3] == START_CODE_3:
            positions.append(i)
            i += 3
        else:
            i += 1
    return positions


def parse_annexb(data: bytes) -> Iterator[NALUnit]:
    starts = find_start_codes(data)
    starts.append(len(data))  # sentinel

    for i in range(len(starts) - 1):
        start = starts[i]

        # Skip start code
        if data[start:start+4] == START_CODE_4:
            nal_start = start + 4
        else:
            nal_start = start + 3

        nal_end = starts[i + 1]
        nal = data[nal_start:nal_end]
        if not nal:
            continue

        header = nal[0]
        forbidden_zero_bit = (header >> 7) & 1
        if forbidden_zero_bit != 0:
            raise ValueError("Invalid NAL (forbidden_zero_bit set)")

        nal_ref_idc = (header >> 5) & 0b11
        nal_unit_type = header & 0b11111

        yield NALUnit(
            nal_ref_idc=nal_ref_idc,
            nal_unit_type=nal_unit_type,
            payload=nal[1:],
        )

def main() -> None:
    with open("input.h264", "rb") as f:
        data = f.read()

    for nal in parse_annexb(data):
        print(
            f"NAL type={nal.nal_unit_type:2d} "
            f"ref={nal.nal_ref_idc} "
            f"size={len(nal.payload)}"
        )


if __name__ == "__main__":
    main()
