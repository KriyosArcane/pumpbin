# post-build-rust: minimal PumpBin module in Rust

A small Cargo crate that becomes a single executable PumpBin can
invoke as a post-build module.

## Install

```
cp -r post-build-rust ~/my-marker
cd ~/my-marker
cargo build --release
mkdir -p ~/.config/pumpbin/modules/marker-append
cp target/release/marker-append      ~/.config/pumpbin/modules/marker-append/
cp pumpbin-module.toml               ~/.config/pumpbin/modules/marker-append/
pumpbin-cli module list              # → marker-append (external: ...)
```

## Test in isolation

```
echo "hello" > /tmp/in
pumpbin-cli module test marker-append /tmp/in -o /tmp/out
hexdump -C /tmp/out    # last byte is 0xAA
```

Pass an arg:

```
pumpbin-cli module test marker-append /tmp/in -o /tmp/out --arg marker=0xCC
hexdump -C /tmp/out    # last byte is 0xCC
```

The Rust SDK exposes `parse_args`, `arg`, and `required_arg` helpers so modules do not need to hand-parse the `Vec<String>` from the wire protocol.

## Use in a generate pipeline

```
pumpbin-cli generate --pack loader.b1n --shellcode sc.bin --platform linux -t exe \
    -o implant --post marker-append:marker=0xBB
```

## Adapting

1. Pick a new module name. Edit `name` in `pumpbin-module.toml`,
   `package.name` in `Cargo.toml`, the directory you copy into
   `~/.config/pumpbin/modules/`, and `--post <new-name>`.
2. Replace the body of the closure in `src/main.rs` with your
   transformation.
3. Rebuild + reinstall.

## When publishing outside the pumpbin tree

`Cargo.toml` uses a path dep on `pumpbin-module-sdk`. When you ship
your module as a stand-alone repo, switch it to a git dep:

```toml
pumpbin-module-sdk = { git = "https://github.com/KriyosArcane/pumpbin.git", subpath = "module-sdk" }
```

(Or pin to a crates.io version when that exists.)
