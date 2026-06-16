#!/usr/bin/env python3
"""Demo PumpBin encrypt module in pure Python."""
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


def parse_key(value):
    key = int(value, 0)
    if not 0 <= key <= 255:
        raise ValueError("key must fit in one byte")
    return key


def main():
    try:
        header = json.loads(read_frame(sys.stdin.buffer))
        if header.get("protocol", 0) > 1:
            write_error(f"this module speaks protocol 1 only, host sent {header['protocol']}")
            sys.exit(1)
        payload = read_frame(sys.stdin.buffer)
        args = parse_args(header)
        key = parse_key(args.get("key", "0xaa"))

        encrypted = bytes(byte ^ key for byte in payload)

        write_frame(sys.stdout.buffer, json.dumps({"protocol": 1}).encode())
        write_frame(sys.stdout.buffer, encrypted)
        sys.stdout.buffer.flush()
    except Exception as e:
        write_error(f"{type(e).__name__}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
