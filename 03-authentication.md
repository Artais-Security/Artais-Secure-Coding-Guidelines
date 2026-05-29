# Secure Coding Guidelines: Authentication

## 1. Purpose and Scope

This section establishes requirements for authenticating users, services, and devices in applications developed or maintained by Artais Security. Authentication failures are among the most consequential application defects: a broken login flow undermines every downstream control. This guideline addresses credential handling, password storage, multi-factor authentication, federated authentication, and machine-to-machine authentication.

These guidelines map to OWASP ASVS V2 (Authentication), OWASP Top 10 2021 A07 (Identification and Authentication Failures), PCI DSS 4.0 Requirements 8.2–8.6, HIPAA Security Rule §164.312(d), NIST SP 800-63B (Authentication and Lifecycle Management), NIST SP 800-53 IA family, and CWE-287, CWE-307, CWE-521, CWE-522, CWE-798.

## 2. General Principles

Authentication establishes the identity of a principal to a level of assurance appropriate to the risk of the system. NIST SP 800-63 defines three Authenticator Assurance Levels (AAL1, AAL2, AAL3); the appropriate level shall be selected based on the data classification and threat model of the application and documented in the system's security design.

Authentication shall be performed by a centralized, hardened module — never reimplemented per service. Where federated identity is available (OIDC, SAML), it shall be preferred over local password databases. Where local authentication is unavoidable, it shall use a vetted library, not a hand-rolled implementation.

Credentials shall be treated as the most sensitive class of data the application handles. Authentication failures shall not leak information about which factor failed.

## 3. Normative Requirements

Passwords shall meet the requirements of NIST SP 800-63B Section 5.1.1.2: minimum eight characters for user-chosen secrets, allowing all printable characters including spaces, with no composition rules (no forced mix of upper/lower/digit/special), no periodic rotation, and screening against breached-password lists. Maximum length shall be at least 64 characters.

Passwords shall be stored using a memory-hard or compute-hard key derivation function: Argon2id (preferred), scrypt, or bcrypt. PBKDF2 is acceptable only where FIPS validation is required. Parameters shall meet current OWASP Password Storage Cheat Sheet recommendations. SHA-family hashes, MD5, and unsalted hashes are prohibited.

Multi-factor authentication shall be required for all administrative access and for any access to systems handling cardholder data (PCI DSS 4.0 Requirement 8.4) or protected health information. Acceptable factors at AAL2 include TOTP authenticators, push-based authenticators with number matching, and FIDO2/WebAuthn. SMS-based OTP is permitted only as a fallback and shall be deprecated where alternatives exist. Email-based OTP is not an acceptable second factor; it merely confirms email access.

Failed authentication attempts shall be rate-limited per account and per source. Account lockout, if used, shall be configured to prevent denial of service against legitimate users (a soft lockout with exponential backoff is generally preferable to a hard lockout). Failed-attempt counters shall be tracked server-side.

Authentication error messages shall be uniform: "invalid username or password" rather than distinguishing the two cases. Account enumeration through registration, password reset, or login response timing shall be prevented.

Credentials in transit shall use TLS 1.2 or higher with cipher suites from the current Mozilla Modern or Intermediate configuration. HTTP Basic and Digest authentication outside TLS are prohibited.

Hardcoded credentials, API keys, or secrets in source code are prohibited (CWE-798). Credentials shall be loaded from a secrets management system at runtime.

## 4. Language-Specific Guidance

### 4.1 Java

Use Spring Security for authentication in Spring applications, or a vetted equivalent (Apache Shiro, Pac4j). Do not implement custom filter chains, password comparison, or token validation outside the framework.

For password hashing, use the Spring Security `Argon2PasswordEncoder` or `BCryptPasswordEncoder` with a work factor of at least 12 for bcrypt or current OWASP-recommended parameters for Argon2id.

For password comparison, always use constant-time comparison (`MessageDigest.isEqual` on equal-length byte arrays, or the encoder's `matches` method). Direct `String.equals` on password hashes is acceptable because hashes are equal-length, but use the framework method to avoid mistakes.

For JWT handling, use `jjwt` or `nimbus-jose-jwt`. Always verify signature with the expected algorithm explicitly; never accept the `alg` header from the token. Reject `none` algorithm. Verify `iss`, `aud`, `exp`, `nbf`, and `iat` claims.

For WebAuthn, use the Yubico `java-webauthn-server` library.

### 4.2 Python

Use a vetted framework: Django's built-in auth with `PASSWORD_HASHERS = ['django.contrib.auth.hashers.Argon2PasswordHasher', ...]`; Flask with Flask-Login and `passlib`; FastAPI with `fastapi-users` or `authlib`.

For password hashing, use `argon2-cffi` directly or via `passlib.hash.argon2`:

~~~python
from argon2 import PasswordHasher
ph = PasswordHasher()  # uses safe defaults
hash_str = ph.hash(password)
try:
    ph.verify(hash_str, candidate)
except VerifyMismatchError:
    # authentication failed
    ...
~~~

For constant-time comparison of secrets or tokens, use `hmac.compare_digest`, never `==`.

For JWT, use `pyjwt` or `authlib`. Always specify the expected algorithm in the `decode` call:

~~~python
jwt.decode(token, key, algorithms=["RS256"], audience=expected_aud, issuer=expected_iss)
~~~

For TOTP, use `pyotp` with appropriate window settings. For WebAuthn, use `py_webauthn`.

Never use `pickle` for session data and never trust client-provided session identifiers; use the framework's session machinery, which signs and encrypts.

### 4.3 C

Authentication in C is typically delegated to platform mechanisms: PAM on Linux, the Windows authentication API, or Kerberos via GSS-API. Implementing password authentication in C application code is strongly discouraged.

When PAM is used, follow its conversation API correctly. Do not log the contents of `pam_response` structures. Zero credentials in memory after use with `explicit_bzero` (BSD/glibc 2.25+) or `memset_s` (C11 Annex K), since plain `memset` may be optimized away.

For password hashing within a system context (e.g., a daemon managing its own credential store), use `libsodium`'s `crypto_pwhash_str` (Argon2id) or `libargon2`. Do not use `crypt(3)` without explicitly specifying a modern algorithm prefix (`$y$` for yescrypt, `$argon2id$`).

For TLS-protected credential transport, use a vetted TLS library (OpenSSL 3.x, LibreSSL, or BoringSSL) and verify the peer certificate and hostname. Failure to verify is a critical defect, not a warning.

### 4.4 C++

The C guidance applies. Prefer C++ wrappers around platform mechanisms where they exist (Boost.Asio with OpenSSL bindings, Poco::Net::HTTPSClientSession).

Use `libsodium` via its C++ bindings or directly. RAII wrappers shall ensure that secret material is zeroized in destructors:

~~~cpp
class Secret {
    std::vector<unsigned char> buf_;
public:
    explicit Secret(size_t n) : buf_(n) {}
    ~Secret() { sodium_memzero(buf_.data(), buf_.size()); }
    unsigned char* data() noexcept { return buf_.data(); }
    size_t size() const noexcept { return buf_.size(); }
};
~~~

Disable copy and move where leaks would be unacceptable, or implement them to maintain the zeroization invariant.

For JWT in C++, use `jwt-cpp` and explicitly specify allowed algorithms during verification.

## 5. Verification

Static analysis shall flag use of weak hash functions for password storage and any hardcoded secrets. Dynamic testing shall include credential stuffing simulations, brute-force protection verification, MFA bypass attempts, and session-related attacks. Penetration testing shall cover account enumeration, password reset flows, and MFA enrollment flows. Dependency scanning shall verify that authentication libraries are current with security patches.

## 6. References

- OWASP ASVS v4.0.3, V2
- OWASP Top 10 2021, A07
- OWASP Authentication, Password Storage, Forgot Password Cheat Sheets
- PCI DSS v4.0, Requirements 8.2–8.6
- HIPAA Security Rule, 45 CFR §164.312(d)
- NIST SP 800-63B
- NIST SP 800-53 Rev. 5, IA control family
- CWE-287, CWE-307, CWE-521, CWE-522, CWE-798
