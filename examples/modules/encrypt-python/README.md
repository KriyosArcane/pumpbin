# xor-demo-encrypt

Tiny external `encrypt` module written in Python. It XORs raw shellcode bytes with a single-byte key and returns the encrypted bytes to PumpBin.

This is an authoring example, not production guidance.

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
pumpbin-cli module test xor-demo-encrypt /tmp/sc.bin --output /tmp/sc.xor --arg key=0x41
```

## Use

Bake the module and its args into a loader pack:

```bash
pumpbin-cli create-b1n --template loader.exe --output loader.b1n \
  --encrypt-module xor-demo-encrypt \
  --module-config module:xor-demo-encrypt.key=0x41
```
