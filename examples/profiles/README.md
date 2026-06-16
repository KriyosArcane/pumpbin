# PumpBin Profiles

Profiles are TOML files that drive `pumpbin-cli build`. Instead of passing
flags on every invocation, a profile captures all build parameters in a
single, version-controllable file.

## Quick start

```sh
pumpbin-cli build -f examples/profiles/simple.toml
```

See `simple.toml` in this directory for a minimal annotated example.

## Shellcode types

| Type | Example |
|------|---------|
| `file` | `source = "file"` and `path = "payload.bin"` |
| `url` | `source = "url"` and `url = "https://example/payload.bin"` |
| `base64` | `source = "base64"` and `data = "..."` |
| `hex` | `source = "hex"` and `data = "fc4883..."` |

## Reference

Each profile declares `schema = "pumpbin.profile/v1"` at the top level and has four required sections: `[pack]`, `[target]`, `[shellcode]`, and `[output]`.

