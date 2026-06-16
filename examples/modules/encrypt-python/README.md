# xor-demo-encrypt

Tiny external `encrypt` module written in Python. It XORs raw shellcode bytes with a single-byte key and returns the encrypted bytes to PumpBin.

This is an authoring example, not an OPSEC recommendation.

## Install

```bash
mkdir -p ~/.config/pumpbin/modules/xor-demo-encrypt
cp xor_demo_encrypt.py pumpbin-module.toml ~/.config/pumpbin/modules/xor-demo-encrypt/
chmod +x ~/.config/pumpbin/modules/xor-demo-encrypt/xor_demo_encrypt.py
pumpbin-cli module list --options --id xor-demo-encrypt
```

## Test

```bash
printf '\\x90\\xcc\\xc3' > /tmp/sc.bin
pumpbin-cli module test xor-demo-encrypt --input /tmp/sc.bin --output /tmp/sc.xor --arg key=0x41
```

## Use

Bake the module into a loader pack with `--encrypt-module xor-demo-encrypt`. Runtime args are scoped by module id:

```bash
pumpbin-cli generate --pack loader.b1n --shellcode payload.bin \
  --module-config module:xor-demo-encrypt.key=0x41
```
