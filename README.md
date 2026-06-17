<div align="center">
  <a href="https://github.com/KriyosArcane/pumpbin/releases/latest">
    <img alt="GitHub Release" src="https://img.shields.io/github/v/release/KriyosArcane/pumpbin?sort=semver&filter=v*.*.*&display_name=tag&style=for-the-badge&labelColor=%2324273a&color=%238aadf4"></a>

  <a href="https://github.com/KriyosArcane/pumpbin/actions">
    <img alt="CI" src="https://img.shields.io/github/actions/workflow/status/KriyosArcane/pumpbin/rust.yml?branch=main&style=for-the-badge&labelColor=%2324273a&label=CI"></a>

  <a href="https://github.com/KriyosArcane/pumpbin/blob/main/LICENSE">
    <img alt="GitHub License" src="https://img.shields.io/github/license/KriyosArcane/pumpbin?style=for-the-badge&labelColor=%2324273a&color=%23eed49f"></a>
</div>

# PumpBin

<p align="center">
  <img src="logo/pumpbin-256x256.png" height="30%" width="30%">
</p>

PumpBin is a Rust CLI for stamping shellcode into compiled loader templates.

A `.b1n` file is a reusable loader pack. It contains loader bytes, metadata, placeholder rules, and optional modules.

Use PumpBin only for systems and payloads you own or are authorized to test.

## Install

```sh
git clone https://github.com/KriyosArcane/pumpbin.git
cd pumpbin
cargo build --release --bin pumpbin-cli
```

The binary is `target/release/pumpbin-cli`.

## Basic Use

A loader must contain the shellcode and size markers. See the [loader template guide](https://pumpbin.b1n.io/dev/start.html#create-binary-implant-template) if you need to make one.

The output examples below omit volatile timestamp prefixes from log lines.

Create a scaffolded loader:

```console
$ pumpbin-cli new-loader myloader --platform linux --pack
PB  myloader              linux/exe  [*] cargo build (release)
    Finished `release` profile [optimized] target(s) in 2.33s
PB  myloader              linux/exe  [+] packed -> myloader/myloader.b1n
wrote myloader/myloader.b1n
Scaffolded and packed: myloader/myloader.b1n
```

Inspect the loader pack:

```console
$ pumpbin-cli inspect myloader/myloader.b1n
Path:        myloader/myloader.b1n
Pack:        myloader
Author:      pumpbin-cli pack
Version:     0.1.0
Save type:   Local
src_prefix:  "$$SHELLCODE$$"
size_holder: "$$99999$$"
max_len:     1048576 bytes
Description: Built with pumpbin-cli pack

Pipeline hooks:
  encrypt:        <none>

Platforms (1):
  Linux -> exe

Modules (0):
  <none>
```

Stamp shellcode into an existing loader:

```console
$ pumpbin-cli stamp myloader/target/release/myloader payload.bin -o stamped
PB  myloader              linux/exe  [*] reading loader
PB  myloader              linux/exe  [*] injecting shellcode (3 B)
INFO replace_binary{plugin=myloader bin_len=1350744 pass_count=0}: shellcode processed encrypted_len=3
INFO replace_binary{plugin=myloader bin_len=1350744 pass_count=0}: pass entries applied pass_count=0
INFO replace_binary{plugin=myloader bin_len=1350744 pass_count=0}: post-build complete
PB  myloader              linux/exe  [+] wrote stamped
stamped
```

Create and use a loader pack:

```console
$ pumpbin-cli create-b1n --template myloader/target/release/myloader --output loader.b1n
INFO Created .b1n loader pack output=loader.b1n

$ pumpbin-cli generate --pack loader.b1n --shellcode payload.bin -o implant
PB  loader.b1n            linux/exe  [*] loading pack
PB  loader.b1n            linux/exe  [*] injecting shellcode (3 B)
INFO replace_binary{plugin=loader bin_len=1350744 pass_count=0}: shellcode processed encrypted_len=3
INFO replace_binary{plugin=loader bin_len=1350744 pass_count=0}: pass entries applied pass_count=0
INFO replace_binary{plugin=loader bin_len=1350744 pass_count=0}: post-build complete
PB  loader.b1n            linux/exe  [+] wrote implant
implant
```

## Markers

Default shellcode marker: `$$SHELLCODE$$`

Default size marker: `$$99999$$`

Run `pumpbin-cli inspect <loader>` before packing to confirm the markers are present.

## Modules

Module kinds:

- `encrypt`: runs before shellcode is stamped. Add one to a pack with `--encrypt-module`.
- `post-build`: runs after shellcode is stamped. Add one during generation with `--post id:key=value`.

`--post` is for the `generate` pipeline. `module test` runs one module by hand and passes its settings with `--arg`.

```sh
pumpbin-cli module list
pumpbin-cli module list --options --id byte-patch
pumpbin-cli generate --pack loader.b1n --shellcode payload.bin --post byte-patch:patches=4831d2:4833d2
pumpbin-cli module test byte-patch implant.exe --arg patches=4831d2:4833d2 -o patched.exe
```

```console
$ pumpbin-cli module list
encrypt:
  aes-gcm (built-in): AES-256-GCM with random key/nonce per generation
  xor (built-in): Single-byte XOR with random non-zero key
post_build:
  pe-version-info (built-in): Patch VS_VERSION_INFO StringFileInfo entries in a PE
  byte-patch (built-in): Apply in-place hex byte substitutions to the implant (equal-length pairs only)
  cert-graft (built-in): Graft a donor PE's WIN_CERTIFICATE onto the implant (cert blob only; use external `trustmebro` for full clone)

$ pumpbin-cli module list --options --id byte-patch
post_build:
  byte-patch (built-in): Apply in-place hex byte substitutions to the implant (equal-length pairs only)
    patches: string (required)
        Comma-separated <hex_from>:<hex_to> pairs; each pair must be equal length
    mode: string [default: all]
        `all` (replace every occurrence) or `first` (replace only first)

$ pumpbin-cli generate --pack loader.b1n --shellcode payload.bin --post byte-patch:patches=9090:9091 -o post-implant
PB  loader.b1n            linux/exe  [*] loading pack
PB  loader.b1n            linux/exe  [*] injecting shellcode (3 B) + byte-patch
INFO replace_binary{plugin=loader bin_len=1350744 pass_count=0}: post-build complete
PB  loader.b1n            linux/exe  [+] wrote post-implant
post-implant

$ pumpbin-cli module test byte-patch implant.exe --arg patches=4831d2:4833d2 -o patched.exe
module 'byte-patch' post-build: 3 → 3 bytes (1 bytes changed)
wrote patched.exe
```

External modules live under `~/.config/pumpbin/modules/<id>/`. See [MODULES.md](MODULES.md).

## Help

```console
$ pumpbin-cli --help
Implant build pipeline: stamp shellcode into a loader, apply post-build transforms, get an implant.

Usage: pumpbin-cli [OPTIONS] <COMMAND>

Commands:
  generate     Stamp shellcode into a .b1n loader pack
  batch        Stamp every matching shellcode file in a directory
  create-b1n   Wrap a compiled loader binary as a reusable .b1n pack
  stamp        Stamp shellcode into a compiled loader binary
  pack         Build a scaffolded loader crate and assemble its .b1n pack
  inspect      Inspect a .b1n pack, loader binary, or generated implant
  module       List and test modules
  new-loader   Scaffold a marker-ready Rust loader crate
  completions  Print shell completion script to stdout
  help         Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version

Output:
      --log-level <FILTER>  Override log level. Accepts EnvFilter syntax, e.g. `debug` or `pumpbin=debug`. Takes precedence over `PUMPBIN_LOG`
```

Run `pumpbin-cli <command> --help` for command-specific flags.

## License

MIT. See [LICENSE](LICENSE).
