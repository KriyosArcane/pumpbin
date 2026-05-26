# PumpBin Plugin Ideas: 50 Candidates (2026 Q2)

This catalog is a fresh ideation cycle.
All names are candidate ideas, not final crate names.

## encrypt_shellcode (10)
1. E01 - xor-single-byte-rotating - single-byte xor with rotating seed.
2. E02 - xor-key16-random-pass - xor with 16-byte generated key returned via pass markers.
3. E03 - xorstream-keyed-pass - xorshift keystream and marker pass replacement.
4. E04 - block-swap-obfuscator - deterministic byte block shuffling.
5. E05 - nibble-scramble - swap nibbles + xor post-pass.
6. E06 - additive-stream-encoder - rolling additive encoding with key pass.
7. E07 - sparse-mask-xor - xor only selected offsets for low pattern density.
8. E08 - two-layer-xor-salt - dual xor rounds with salt marker.
9. E09 - checksum-bound-encoder - encoding keyed to payload checksum.
10. E10 - byte-run-collapser - converts repeating runs to compact encoded form.

## format_encrypted_shellcode (10)
11. F01 - c-array-compact - compact C array output for shellcode buffers.
12. F02 - chunked-hex-array - chunked hex formatting with stable line width.
13. F03 - powershell-byte-array - PowerShell-ready byte array formatter.
14. F04 - rust-byte-array - Rust const byte array formatter.
15. F05 - python-bytes-literal - Python bytes literal output formatter.
16. F06 - json-envelope-base64 - JSON wrapper with base64 payload field.
17. F07 - csv-byte-list - CSV byte output for simple parser tooling.
18. F08 - csharp-byte-array - C# style initializer output.
19. F09 - header-plus-payload - prepends simple metadata header.
20. F10 - escaped-string-formatter - escaped string style output bytes.

## format_url_remote (10)
21. R01 - append-static-query - append fixed query args.
22. R02 - url-lowercase-normalizer - normalize host/path casing rules.
23. R03 - path-token-injector - inject campaign token into URL path.
24. R04 - url-path-campaign-wrap - add campaign and version query in deterministic format.
25. R05 - url-signature-lite - append lightweight deterministic signature.
26. R06 - endpoint-rotate-seed - deterministic endpoint rotation by seed.
27. R07 - fragment-stripper - remove URL fragments before embedding.
28. R08 - domain-fallback-list - append fallback domains to encoded path.
29. R09 - url-padding-random-safe - deterministic padding to fixed visual length.
30. R10 - protocol-upgrade-enforcer - force https with strict normalization.

## upload_final_shellcode_remote (10)
31. U01 - local-save-fallback - always return empty URL to trigger host fallback.
32. U02 - data-url-inline - convert payload to data URL (base64).
33. U03 - data-url-inline-gzip-flag - data URL with pseudo metadata flag.
34. U04 - filehash-url-deriver - URL path built from deterministic hash.
35. U05 - size-bucket-url-map - map payload size to deterministic endpoint path.
36. U06 - base64-data-url-inline - stable base64 data URL output for remote mode.
37. U07 - chunk-hash-path-builder - split hash segments into URL hierarchy.
38. U08 - extension-switch-uploader - choose extension by payload fingerprint.
39. U09 - pseudo-presigned-url - deterministic signed-style query URL.
40. U10 - upload-audit-tag-url - append audit token to output URL.

## post_binary (10)
41. P01 - patch-build-timestamp-fixed - patch fixed build timestamp marker.
42. P02 - patch-campaign-and-team - patch campaign and team markers.
43. P03 - marker-patch-metadata - patch multiple metadata placeholders safely.
44. P04 - marker-scan-report-nochange - scan markers and return unchanged binary.
45. P05 - section-name-normalizer - patch section-like markers.
46. P06 - compile-id-shortener - patch compile ID marker to short deterministic value.
47. P07 - checksum-tag-inserter - patch checksum marker bytes.
48. P08 - dual-marker-phase-patcher - staged patch for two marker groups.
49. P09 - marker-pad-fixer - enforce fixed-length marker replacement.
50. P10 - marker-hardened-failclose - strict patching with fail-close behavior.
