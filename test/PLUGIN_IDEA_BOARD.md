# PumpBin Plugin Idea Board (Brainstorm + Ranking)

## Candidate Ideas
1. XOR-32 random key encryptor (`encrypt_shellcode`)
2. RC4 stream encryptor with key placeholder (`encrypt_shellcode`)
3. Chunked XOR with key+salt placeholders (`encrypt_shellcode`)
4. URL signer with timestamp query (`format_url_remote`)
5. URL rotator from comma-separated endpoint pool (`format_url_remote`)
6. JSON envelope formatter for encrypted payload (`format_encrypted_shellcode`)
7. Base64 + line-split formatter (`format_encrypted_shellcode`)
8. Upload via HTTP PUT and return final URL (`upload_final_shellcode_remote`)
9. Placeholder-based build tag patcher (`post_binary`)
10. Placeholder-based campaign ID patcher (`post_binary`)

## Ranking Criteria
- Value for operators
- Low breakage risk
- Ease of integration with templates
- Determinism and debugability
- Build/runtime simplicity

## Judged Ranking (Best First)
1. XOR-32 random key encryptor
2. RC4 stream encryptor
3. Chunked XOR key+salt encryptor
4. Placeholder build tag patcher
5. Placeholder campaign ID patcher
6. URL signer with timestamp query
7. URL rotator pool
8. JSON envelope formatter
9. Base64 line-split formatter
10. HTTP PUT uploader

## Why Top 5 Won
- They provide immediate practical utility.
- They can be implemented with minimal host/environment assumptions.
- They avoid network dependencies for initial rollout.
- They are easy to document with placeholder contracts.
