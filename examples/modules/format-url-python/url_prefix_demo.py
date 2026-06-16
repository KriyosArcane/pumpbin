#!/usr/bin/env python3
"""Demo PumpBin format-url module in pure Python."""
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
    write_frame(sys.stdout.buffer, json.dumps({"protocol": 1, "error": message}).encode())
    write_frame(sys.stdout.buffer, b"")
    sys.stdout.buffer.flush()


def parse_args(header):
    args = {}
    for item in header.get("args", []):
        key, sep, value = item.partition("=")
        if sep:
            args[key] = value
    return args


def main():
    try:
        header = json.loads(read_frame(sys.stdin.buffer))
        if header.get("protocol", 0) > 1:
            write_error(f"this module speaks protocol 1 only, host sent {header['protocol']}")
            sys.exit(1)
        payload = read_frame(sys.stdin.buffer)
        args = parse_args(header)

        url = payload.decode("utf-8")
        formatted = f"{args.get('prefix', '')}{url}"

        resp = {"protocol": 1, "string": formatted}
        write_frame(sys.stdout.buffer, json.dumps(resp).encode())
        write_frame(sys.stdout.buffer, formatted.encode("utf-8"))
        sys.stdout.buffer.flush()
    except Exception as e:
        write_error(f"{type(e).__name__}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
