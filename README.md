# ustream

Toy experiment for streaming H.264 over RTP/UDP on localhost. This is not a
production-ready implementation; it is meant for learning, iteration, and
testing.

## Quick Start
- Build: `zig build`
- Run sender: `zig build run -- input.h264 30`
- Run receiver: `python3 test.py --input input.h264`
- Stream with ffplay:
  - `ffplay -protocol_whitelist file,udp,rtp -i session.sdp`
  - Or direct RTP: `ffplay -fflags nobuffer -flags low_delay -i rtp://127.0.0.1:5004`

## Notes
- The sender reads raw Annex B H.264 and packetizes into RTP (PT=96).
- `test.py` reassembles the stream and compares hashes against the input.
- For best results, start the receiver before the sender.
