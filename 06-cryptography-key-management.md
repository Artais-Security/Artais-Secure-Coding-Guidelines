# Secure Coding Guidelines: Cryptography and Key Management

## 1. Purpose and Scope

This section establishes requirements for the use of cryptography and the management of cryptographic keys in applications developed or maintained by Artais Security. Cryptography is uniquely unforgiving: subtle implementation errors produce systems that appear to work but provide no security. This guideline mandates the use of vetted libraries and prohibits cryptographic invention.

These guidelines map to OWASP ASVS V6 (Stored Cryptography) and V9 (Communications), OWASP Top 10 2021 A02 (Cryptographic Failures), PCI DSS 4.0 Requirements 3.5–3.7 and 4, HIPAA §164.312(a)(2)(iv) and §164.312(e)(2)(ii), NIST SP 800-57 (Key Management), NIST SP 800-131A (Algorithm Transitions), FIPS 140-3, and CWE-310, CWE-327, CWE-330, CWE-338, CWE-759, CWE-916.

## 2. General Principles

Do not invent cryptography. Use well-reviewed, actively maintained libraries (libsodium, Tink, BouncyCastle, the platform's native cryptographic provider). Do not implement primitives (block ciphers, modes, hash functions, MAC constructions, signature schemes) from specifications.

Algorithms shall be selected from current NIST-approved or equivalent regulator-approved sets. Algorithm choices and key sizes shall meet the minimums in NIST SP 800-131A and shall be reviewed annually as guidance evolves.

Keys shall be generated, stored, used, and destroyed in accordance with a documented key management plan. The plan shall identify each key, its purpose, its lifetime, its storage mechanism, and its rotation schedule.

## 3. Normative Requirements

### Algorithm Selection

For symmetric encryption: AES-256-GCM or ChaCha20-Poly1305 with authenticated encryption. AES-CBC with a separately computed HMAC is acceptable for legacy systems but shall not be used in new development. AES-ECB, DES, 3DES, RC4, and Blowfish are prohibited.

For hashing of non-password data: SHA-256, SHA-384, SHA-512, or SHA-3 variants. MD5 and SHA-1 are prohibited for any security purpose, including HMAC, signatures, certificate verification, and integrity.

For password storage: Argon2id, scrypt, or bcrypt per the Authentication guideline. PBKDF2 is acceptable where FIPS is required, with at least 600,000 iterations of SHA-256 per OWASP guidance.

For MAC: HMAC-SHA-256 or HMAC-SHA-512, or the authenticator built into an AEAD mode.

For asymmetric encryption: RSA-OAEP with at least 3072-bit keys, or ECIES with P-256 or X25519. RSA-PKCS#1 v1.5 encryption is prohibited.

For signatures: RSA-PSS with SHA-256, ECDSA with P-256 or P-384, or Ed25519. RSA-PKCS#1 v1.5 signatures are acceptable for legacy compatibility but shall not be used in new development.

For key agreement: ECDH with P-256 or X25519. Static-static DH is prohibited.

For random number generation: the platform CSPRNG (`getrandom`, `BCryptGenRandom`, `/dev/urandom`, `SecureRandom`, `os.urandom`, `crypto.randomBytes`). `rand`, `random`, `Math.random`, and time-based seeding are prohibited for any security purpose.

### Key Management

Keys shall be generated using the library's key generation API, never derived from low-entropy sources. Encryption keys shall not be reused across purposes; use HKDF to derive purpose-specific subkeys from a master.

Keys shall be stored in a dedicated key management system: AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault, or an HSM. Keys shall not be stored in source code, configuration files, environment variables in plaintext, container images, or unencrypted disk.

Keys shall have documented rotation schedules. Symmetric encryption keys protecting data at rest shall be rotated at intervals appropriate to the data sensitivity and key usage volume. Signing keys for short-lived tokens (JWT signing) shall be rotated frequently (weekly or monthly) and previous keys shall remain available for verification until all issued tokens expire.

Key destruction shall be verifiable. Soft deletion in cloud KMS shall be followed by hard deletion after the recovery window required by the regulatory regime.

### TLS

TLS 1.2 minimum, TLS 1.3 preferred. SSLv2, SSLv3, TLS 1.0, and TLS 1.1 are prohibited.

Cipher suites shall be limited to those in the Mozilla Modern or Intermediate configurations. Server-side cipher preference shall be enforced.

Certificates shall be verified including hostname, chain, expiration, and revocation status. Disabling certificate verification is a critical defect; it shall not appear in production code paths.

Certificate pinning is encouraged for mobile applications and high-value API clients, with a documented pin rotation and breakglass procedure.

## 4. Language-Specific Guidance

### 4.1 Java

Use the JCA/JCE with a current provider, or Google Tink for a higher-level API that prevents misuse. For most applications, Tink is preferred:

~~~java
AeadConfig.register();
KeysetHandle keysetHandle = KeysetHandle.generateNew(KeyTemplates.get("AES256_GCM"));
Aead aead = keysetHandle.getPrimitive(Aead.class);
byte[] ciphertext = aead.encrypt(plaintext, associatedData);
~~~

For raw JCE, always specify the full transformation including mode and padding: `Cipher.getInstance("AES/GCM/NoPadding")`, never `Cipher.getInstance("AES")` (which defaults to ECB).

Use `SecureRandom` for all random data. The default constructor on Linux uses NativePRNG which reads from `/dev/urandom`.

For TLS, use the platform's `SSLContext` and rely on default trust managers. Implementing a custom `X509TrustManager` is almost always a mistake; if you do, do not return early or skip validation for any reason. Hostname verification is performed by `HttpsURLConnection` and modern HTTP clients automatically; do not disable.

For JWT, see the Authentication guideline. Specifically, always validate the algorithm explicitly.

### 4.2 Python

Use the `cryptography` library (`pyca/cryptography`) as the primary cryptographic library. Its high-level recipes layer (`Fernet` for authenticated symmetric encryption) is suitable for most use cases:

~~~python
from cryptography.fernet import Fernet
key = Fernet.generate_key()  # store securely
f = Fernet(key)
token = f.encrypt(b"sensitive data")
plaintext = f.decrypt(token)
~~~

For lower-level operations, use the `hazmat` layer, but only after reading the warning at the top of the documentation. Use `AESGCM` from `cryptography.hazmat.primitives.ciphers.aead` for authenticated encryption.

`pycrypto` is deprecated and unmaintained; do not use. `pycryptodome` is acceptable but `cryptography` is preferred.

For random data, use `secrets` for security-sensitive randomness, not `random`:

~~~python
import secrets
token = secrets.token_urlsafe(32)
~~~

For TLS, use `ssl.create_default_context()` and do not override its defaults. `ssl.CERT_NONE`, `check_hostname=False`, and custom `_create_unverified_context` are prohibited in production.

For JWT, see the Authentication guideline.

### 4.3 C

Use `libsodium` as the primary cryptographic library. Its API is designed to be misuse-resistant:

~~~c
unsigned char key[crypto_secretbox_KEYBYTES];
crypto_secretbox_keygen(key);
unsigned char nonce[crypto_secretbox_NONCEBYTES];
randombytes_buf(nonce, sizeof nonce);
unsigned char ciphertext[crypto_secretbox_MACBYTES + msg_len];
crypto_secretbox_easy(ciphertext, msg, msg_len, nonce, key);
~~~

For random data, use `randombytes_buf` from libsodium, `getrandom(2)` on Linux, or `arc4random_buf` on BSD. Do not use `rand`, `random`, or seed from `time()`.

For TLS, use OpenSSL 3.x or LibreSSL. Use `SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)`. Use `SSL_CTX_set_default_verify_paths` and `SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL)`. Set the expected hostname with `SSL_set1_host` (OpenSSL 1.0.2+) so that hostname verification is performed during the handshake.

Zeroize key material with `sodium_memzero` or `explicit_bzero`. Plain `memset` may be optimized away by the compiler.

For password hashing, `crypto_pwhash_str` from libsodium uses Argon2id.

### 4.4 C++

The C guidance applies. Wrap libsodium or OpenSSL handles in RAII types. `std::unique_ptr` with a custom deleter is suitable for OpenSSL's `BIO*`, `SSL_CTX*`, `EVP_CIPHER_CTX*`:

~~~cpp
struct EvpCipherCtxDeleter { void operator()(EVP_CIPHER_CTX* p) const noexcept { EVP_CIPHER_CTX_free(p); } };
using EvpCipherCtx = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;
~~~

For higher-level cryptography in C++, consider Botan or Crypto++ as alternatives to direct OpenSSL or libsodium use. Both are vetted, but their APIs invite some misuse; prefer libsodium where possible.

Boost.Asio with TLS provides a usable wrapper around OpenSSL contexts; ensure verification is enabled and hostname is set.

For secret material, use a zeroizing allocator or wrap secrets in a type whose destructor calls `sodium_memzero`. Standard `std::string` does not zeroize.

## 5. Verification

Static analysis shall flag use of deprecated algorithms (MD5, SHA-1, DES, 3DES, RC4), insecure modes (ECB), and weak RNGs in security contexts. Dependency scanning shall identify outdated cryptographic libraries with known CVEs. TLS configuration shall be tested with tools such as `testssl.sh` and verified against Mozilla SSL Configuration Generator output. Code review shall confirm that no cryptographic primitive is implemented in application code and that all algorithm choices match the approved list. Key management plans shall be reviewed annually.

## 6. References

- OWASP ASVS v4.0.3, V6 and V9
- OWASP Top 10 2021, A02
- OWASP Cryptographic Storage, Transport Layer Protection Cheat Sheets
- PCI DSS v4.0, Requirements 3.5–3.7, 4
- HIPAA Security Rule, 45 CFR §164.312(a)(2)(iv), §164.312(e)(2)(ii)
- NIST SP 800-57 (Key Management)
- NIST SP 800-131A (Algorithm Transitions)
- FIPS 140-3
- CWE-310, CWE-327, CWE-330, CWE-338, CWE-759, CWE-916
