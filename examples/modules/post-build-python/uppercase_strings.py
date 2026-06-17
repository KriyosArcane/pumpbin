#!/usr/bin/env python3
"""Demo PumpBin post-build module in pure Python.

Reads the implant bytes from stdin (PumpBin wire protocol v1),
applies a transformation, writes the mutated bytes back to stdout.

To use:
    cp -r pumpbin/examples/modules/post-build-python  \
          ~/.config/pumpbin/modules/uppercase-strings
    chmod +x ~/.config/pumpbin/modules/uppercase-strings/uppercase_strings.py
    pumpbin-cli module list            # should show "uppercase-strings (external: ...)"
    pumpbin-cli module test uppercase-strings sample.bin -o out.bin
"""
import json
import struct
import sys


def read_frame(stream):
    raw = stream.read(4)
    if len(raw) != 4:
        raise EOFError(f"partial length prefix: got {len(raw)}/4 bytes")
    (n,) = struct.unpack("<I", raw)
    buf = stream.read(n)
    if len(buf) != n:
        raise EOFError(f"truncated frame: got {len(buf)}/{n} bytes")
    return buf


def write_frame(stream, payload):
    stream.write(struct.pack("<I", len(payload)))
    stream.write(payload)


def write_error(message):
    header = {"protocol": 1, "error": message}
    write_frame(sys.stdout.buffer, json.dumps(header).encode("utf-8"))
    write_frame(sys.stdout.buffer, b"")
    sys.stdout.buffer.flush()


def parse_args(header):
    """Convert the request header's args list into a plain dict.

    PumpBin sends args as a JSON array of "key=value" strings:
        {"args": ["donor=/tmp/mrt.exe", "clone=true"]}
    This helper turns that into {"donor": "/tmp/mrt.exe", "clone": "true"}.
    Values containing "=" are handled correctly (only the first "=" splits).
    """
    args = {}
    for item in header.get("args", []):
        key, sep, val = item.partition("=")
        if sep:
            args[key] = val
    return args


def main():
    try:
        header = json.loads(read_frame(sys.stdin.buffer))
        if header.get("protocol", 0) > 1:
            write_error(f"this module speaks protocol 1 only, host sent {header['protocol']}")
            sys.exit(1)
        payload = read_frame(sys.stdin.buffer)

        args = parse_args(header)  # {"key": "value", ...}; use args.get("key", default)

        mutated = bytes(b - 32 if 0x61 <= b <= 0x7A else b for b in payload)

        resp = {"protocol": 1}
        write_frame(sys.stdout.buffer, json.dumps(resp).encode("utf-8"))
        write_frame(sys.stdout.buffer, mutated)
        sys.stdout.buffer.flush()
    except Exception as e:
        write_error(f"{type(e).__name__}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
