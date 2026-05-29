# Secure Coding Guidelines: Data Protection (At Rest and In Transit)

## 1. Purpose and Scope

This section establishes requirements for protecting sensitive data throughout its lifecycle: classification, in-transit protection, at-rest protection, in-use protection, retention, and destruction. The Cryptography guideline specifies the primitives; this section specifies where and how they shall be applied.

These guidelines map to OWASP ASVS V6 and V9, OWASP Top 10 2021 A02, PCI DSS 4.0 Requirements 3 and 4, HIPAA §164.312(a)(2)(iv), §164.312(c)(1), §164.312(e), NIST SP 800-53 SC and MP families, GDPR Article 32, and CWE-311, CWE-312, CWE-319, CWE-359.

## 2. General Principles

Data shall be classified and the classification shall drive control selection. A documented classification scheme shall identify, at minimum: public, internal, confidential, and restricted categories (or the equivalent organizational scheme).

Data shall be protected appropriately at every state: in transit between systems, at rest in storage, in use during processing, and in backup or archive. Protection includes encryption, access control, integrity verification, and minimization.

Data minimization is the strongest control. The most secure data is data not collected, not stored, or destroyed when no longer needed. Retention shall be the minimum required by business and regulatory purpose.

## 3. Normative Requirements

### Data in Transit

All data crossing a network boundary, including within data center networks, shall be protected by TLS 1.2 minimum, TLS 1.3 preferred. Plaintext protocols (HTTP, FTP, Telnet, unencrypted SMTP, plain LDAP) are prohibited for any data above public classification.

Internal service-to-service traffic shall use mutual TLS (mTLS) where the threat model includes east-west attackers. Service mesh deployments (Istio, Linkerd) can provide this transparently.

Certificate and key management for TLS follows the Cryptography guideline. Automated renewal (ACME with Let's Encrypt or an internal CA) is preferred over manual rotation.

HTTP Strict Transport Security (HSTS) shall be enabled on all public-facing HTTPS endpoints. Submission to the HSTS preload list is encouraged for production domains.

### Data at Rest

Database files, file system contents holding application data, object storage, and backups shall be encrypted at rest. Cloud-native encryption (RDS encryption, S3 SSE, GCS CMEK, Azure SSE) is acceptable; customer-managed keys (CMEK) are preferred over provider-managed keys for sensitive data.

Application-layer encryption shall be used in addition to storage-layer encryption for the highest sensitivity data: cardholder data (PCI DSS 4.0 Requirement 3.5.1), authentication credentials, and signing keys. Application-layer encryption protects against database administrators, backup theft, and certain misconfiguration classes.

Field-level encryption with deterministic encryption (for searchable fields) or randomized encryption (for non-searchable fields) shall be used where row-level access control alone is insufficient.

Backup encryption keys shall be managed separately from production keys to permit recovery in the event of production key compromise.

### Data in Use

Sensitive data in memory shall be minimized in scope and lifetime. Secret material shall be zeroized after use per the Cryptography guideline. Heap dumps and core dumps shall be disabled in production for processes handling sensitive data, or shall be encrypted and access-controlled.

Process isolation shall be used to separate components handling different sensitivity levels. A single process handling both public and restricted data presents a larger attack surface than separated processes communicating over an authenticated channel.

### Retention and Destruction

Data retention shall be defined per data category, with retention periods set to the minimum of business need and regulatory minimum. Retention beyond these is a liability.

Data destruction shall be verifiable. Deletion from primary storage shall propagate to replicas, backups, and caches according to documented timelines. Cryptographic erasure (destroying the key) is an acceptable destruction method where the data is encrypted with a per-record or per-tenant key.

Personal data subject to GDPR Article 17 (right to erasure) shall have a documented deletion workflow covering all storage locations.

### PII, PHI, and PAN Handling

Personally identifiable information shall be tagged in the data model and access shall be logged. PII shall not appear in URLs, query strings, log messages, or analytics payloads.

Protected Health Information shall be handled per HIPAA: minimum necessary use, access logging, encryption in transit and at rest, and Business Associate Agreements with subprocessors.

Primary Account Numbers shall be tokenized at the earliest opportunity in the data flow. Where PAN must be stored, only the masked form (first six and last four digits) and a token are stored in application databases; the full PAN is stored only in PCI-scoped vaults. CVV/CVV2 and PIN data shall never be stored.

## 4. Language-Specific Guidance

### 4.1 Java

For HTTP clients, use the platform's `HttpClient` (Java 11+) or Apache HttpClient with default TLS configuration. Do not disable hostname verification or certificate validation.

For application-layer encryption, use Google Tink (preferred) or AWS Encryption SDK / GCP Tink + KMS integration:

~~~java
AeadConfig.register();
KmsClient kmsClient = ... // configured
KeysetHandle keysetHandle = KeysetHandle.read(
    JsonKeysetReader.withFile(new File("encrypted-keyset.json")),
    kmsClient.getAead("aws-kms://arn:..."));
Aead aead = keysetHandle.getPrimitive(Aead.class);
~~~

For database column encryption, use the JPA `AttributeConverter` pattern with a key fetched from the secrets manager. Deterministic encryption requires a separate construction (Tink's `DeterministicAead`) and shall be limited to fields requiring equality search.

For zeroization, use `char[]` rather than `String` for short-lived secret material and call `Arrays.fill(arr, '\0')` after use.

### 4.2 Python

Use `requests` or `httpx` with default TLS verification. Never set `verify=False` in production.

For application-layer encryption, use the `cryptography` library's `Fernet` for symmetric encryption with rotating keys via `MultiFernet`, or the AWS Encryption SDK for KMS-integrated encryption.

For database column encryption with SQLAlchemy, implement a `TypeDecorator` that encrypts on bind and decrypts on result. Cache the data key in memory with a TTL.

For PII handling, use `pydantic.SecretStr` for fields that should not appear in `repr()` or default serialization. Custom log filters shall redact tagged fields.

### 4.3 C

For TLS, use OpenSSL 3.x. Configure with `SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)`, `SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL)`, and `SSL_set1_host(ssl, expected_host)`.

For application-layer encryption, use libsodium's `crypto_secretbox` or `crypto_aead_chacha20poly1305_ietf` for symmetric encryption, with keys fetched from a secrets manager via a TLS-protected client.

For at-rest data, prefer database-level encryption configured at the storage layer (PostgreSQL with `pgcrypto` for column encryption with caution, or full-disk encryption with LUKS).

Disable core dumps for sensitive processes: `setrlimit(RLIMIT_CORE, &(struct rlimit){0, 0})` early in startup and `prctl(PR_SET_DUMPABLE, 0)`.

### 4.4 C++

The C guidance applies. Wrap OpenSSL handles in RAII as shown in the Cryptography guideline. Use C++ wrappers (Boost.Asio with SSL) where they reduce error surface.

For application-layer encryption, prefer libsodium over OpenSSL EVP for new code. Botan provides a C++-native API as an alternative.

For zeroization, use the libsodium secure allocator pattern from the Secrets Management guideline.

## 5. Verification

TLS configuration shall be tested with `testssl.sh`, SSL Labs, or equivalent. Database encryption settings shall be verified per environment. Backup encryption shall be verified annually by attempting to read a backup without the appropriate key. Data flow diagrams shall be reviewed at each architectural change to confirm classification-appropriate protection at each hop. Penetration testing shall verify that PII does not appear in URLs, logs, or unauthenticated responses. Annual data inventory and retention review shall confirm minimization.

## 6. References

- OWASP ASVS v4.0.3, V6, V9
- OWASP Top 10 2021, A02
- OWASP Cryptographic Storage, Transport Layer Protection, HSTS Cheat Sheets
- PCI DSS v4.0, Requirements 3, 4
- HIPAA Security Rule, 45 CFR §164.312(a)(2)(iv), §164.312(c)(1), §164.312(e)
- NIST SP 800-53 Rev. 5, SC and MP control families
- GDPR Articles 5, 17, 32
- CWE-311, CWE-312, CWE-319, CWE-359
