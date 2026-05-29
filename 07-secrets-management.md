# Secure Coding Guidelines: Secrets Management

## 1. Purpose and Scope

This section establishes requirements for handling application secrets: API keys, database credentials, encryption keys, signing keys, OAuth client secrets, service account tokens, and similar bearer credentials. Hardcoded secrets and leaked credentials are the most common initial access vector reported in breach investigations.

These guidelines map to OWASP ASVS V6.4 (Secret Management) and V14.1 (Build), OWASP Top 10 2021 A02 and A07, PCI DSS 4.0 Requirements 3.5 and 8.6.3, NIST SP 800-53 IA-5 (Authenticator Management), CWE-798 (Use of Hardcoded Credentials), and CWE-540 (Inclusion of Sensitive Information in Source Code).

## 2. General Principles

Secrets shall be loaded at runtime from a dedicated secrets management system. Source code, configuration files committed to version control, container images, build artifacts, and environment variables in shared infrastructure are not acceptable secret storage.

Secrets shall be scoped to the principal that uses them. Shared service accounts holding broad permissions are prohibited where per-service credentials are feasible.

Secret access shall be logged. Every read of a secret shall produce an audit record identifying the caller, the secret, and the time.

## 3. Normative Requirements

A dedicated secrets management system shall be used: HashiCorp Vault, AWS Secrets Manager, AWS Systems Manager Parameter Store (with KMS encryption), GCP Secret Manager, Azure Key Vault, or an equivalent HSM-backed system. Local files holding secrets, including `.env` files, are acceptable only for local development on developer workstations and shall never be deployed to shared environments.

Secrets shall be rotated on a documented schedule. Rotation shall be automated where the secrets manager supports it. Rotation frequency shall meet the regulatory minimum: PCI DSS requires that shared credentials be changed at least every 90 days; cryptographic keys follow the Cryptography guideline.

Secret leakage shall trigger immediate rotation. A documented incident response procedure shall cover credential leakage detection, scope assessment, rotation, and post-incident review.

Secrets shall not appear in logs (see the Application Logging guideline), in error messages returned to clients, in stack traces, in support tickets, in screenshots, or in observability data sent to third parties. APM tools shall be configured to scrub known secret patterns.

Source code repositories shall be scanned for secrets pre-commit (git hooks), at push time (CI), and continuously (organization-wide scanning). Detected secrets shall be treated as compromised and rotated.

For machine-to-machine authentication, prefer short-lived workload identities (cloud IAM roles, SPIFFE/SPIRE) over long-lived API keys. Where API keys are unavoidable, they shall be scoped narrowly and revocable.

For developer access to production secrets, just-in-time elevation with approval and time-bounded grants shall be implemented. Standing access to production secrets by individual developers is prohibited.

## 4. Language-Specific Guidance

### 4.1 Java

Use the cloud provider's SDK (AWS SDK Secrets Manager client, Google Cloud Secret Manager client, Azure Identity + Key Vault) or a vendor-neutral wrapper (Spring Cloud Vault, MicroProfile Config with a secrets backend).

Fetch secrets at startup or on demand; cache with a TTL that allows for rotation. Implement a refresh mechanism that re-fetches on rotation signals rather than process restart.

Hold secrets in `char[]` rather than `String` where the library permits, because strings live in the constant pool and cannot be reliably zeroized. Zero the array after use:

~~~java
char[] secret = vault.getSecret("db-password");
try {
    useSecret(secret);
} finally {
    java.util.Arrays.fill(secret, '\0');
}
~~~

For Spring Boot, externalize all credentials via `spring.config.import=vault://...` or equivalent; do not place credentials in `application.properties`.

Never log a secret. Custom Jackson serializers shall redact fields named `password`, `secret`, `token`, `key`, and configured patterns.

### 4.2 Python

Use `boto3` Secrets Manager, `google-cloud-secret-manager`, `azure-keyvault-secrets`, or `hvac` (HashiCorp Vault). Wrap in a thin caching layer if cost is a concern, with TTL appropriate to rotation cadence.

Do not commit `.env` files. Use `python-dotenv` only for local development with a `.env.example` template in the repository and `.env` in `.gitignore`.

Hold secrets in local variables with the smallest possible scope. Python does not provide reliable memory zeroization for `str` objects; for highly sensitive secrets (signing keys), use `bytearray` and zero after use, accepting that Python's memory model limits the guarantee.

For configuration, use `pydantic-settings` with secrets loaded from the secrets manager via a custom settings source. Mark sensitive fields with `SecretStr` so that `repr()` does not leak.

Pre-commit hooks shall include `detect-secrets` or `gitleaks`. CI shall run a scan on every PR.

### 4.3 C

Load secrets from the secrets manager via its REST API using a vetted HTTP client (libcurl with TLS verification enabled) or via a sidecar (Vault agent, AWS Secrets Manager Lambda extension) that exposes secrets on a local Unix socket.

Allocate secret buffers with `sodium_malloc` (libsodium), which provides guard pages and resists certain memory disclosure vulnerabilities. Free with `sodium_free`, which zeroes before release.

Use `explicit_bzero` or `sodium_memzero` to zero secret material that does not live in libsodium-managed memory.

Be careful with `getenv`: environment variables are visible to other processes on the same host with sufficient privileges (`/proc/<pid>/environ`). Where the deployment requires environment-based secrets, document the trust boundary and consider clearing the environment after read.

Do not include secrets in core dumps. Call `prctl(PR_SET_DUMPABLE, 0)` on Linux after loading secrets if appropriate.

### 4.4 C++

The C guidance applies. Use libsodium's secure allocator via a custom allocator type and pass to standard containers:

~~~cpp
template<typename T>
struct SodiumAllocator {
    using value_type = T;
    T* allocate(std::size_t n) { return static_cast<T*>(sodium_malloc(n * sizeof(T))); }
    void deallocate(T* p, std::size_t) noexcept { sodium_free(p); }
};
using SecretString = std::basic_string<char, std::char_traits<char>, SodiumAllocator<char>>;
~~~

Wrap secret-bearing types so that `operator<<` is not defined, preventing accidental logging. Custom serializers shall redact.

For configuration, use a library that supports a secrets backend (Boost.PropertyTree with a custom resolver, or a hand-rolled loader). Avoid `getenv` for sensitive values where possible.

## 5. Verification

Source code scanning with `gitleaks`, `trufflehog`, `detect-secrets`, or equivalent shall run pre-commit and in CI. Container images shall be scanned for embedded secrets before promotion. Build outputs shall be checked. Logging output, error traces, and observability data shall be sampled and verified to contain no secrets. Secret rotation shall be tested periodically by forcing a rotation and verifying that the application recovers without manual intervention. Incident response procedures for leaked secrets shall be exercised at least annually.

## 6. References

- OWASP ASVS v4.0.3, V6.4, V14.1
- OWASP Top 10 2021, A02, A07
- OWASP Secrets Management Cheat Sheet
- PCI DSS v4.0, Requirements 3.5, 8.6.3
- NIST SP 800-53 Rev. 5, IA-5
- CWE-798, CWE-540, CWE-256, CWE-260
