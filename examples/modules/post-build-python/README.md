# post-build-python — minimal PumpBin module in pure Python

This is the smallest possible PumpBin post-build module. Two files,
no dependencies, ~50 lines of Python.

## Install

```
cp -r post-build-python ~/.config/pumpbin/modules/uppercase-strings
chmod +x ~/.config/pumpbin/modules/uppercase-strings/uppercase_strings.py
pumpbin-cli module list         # should list uppercase-strings
```

## Test in isolation (no implant needed)

```
echo "hello world" > /tmp/in
pumpbin-cli module test uppercase-strings /tmp/in -o /tmp/out
cat /tmp/out                     # → HELLO WORLD
```

## Use in a generate pipeline

```
pumpbin-cli generate --pack loader.b1n --shellcode sc.bin --platform linux -t exe \
    -o implant --post uppercase-strings
```

## Files

- `pumpbin-module.toml` — manifest. Tells PumpBin: name, kind,
  protocol version, executable filename, supported platforms.
- `uppercase_strings.py` — the actual module. Reads from stdin,
  writes to stdout, exits 0 on success / non-zero on failure.

## Adapting

1. Pick a new module name (kebab-case). Edit `name`/`description`
   in `pumpbin-module.toml`.
2. Rename the directory and the .py file to match.
3. Edit the "your transformation goes here" block in the .py.
4. Reinstall under the new directory name.

## Wire protocol (v1, summary)

stdin and stdout speak length-prefixed frames: a u32 LE length
followed by that many bytes. Per invocation:

- stdin frame 0 → JSON header (`{"protocol": 1, "kind": "post-build", "id": "...", "args": [...]}`)
- stdin frame 1 → raw implant bytes
- stdout frame 0 → JSON response header (`{"protocol": 1}` on success; add `"error": "..."` on failure)
- stdout frame 1 → mutated implant bytes
- exit code      → 0 ok, non-zero failure

Full spec: see [MODULES.md](../../../MODULES.md) in the repo root.
