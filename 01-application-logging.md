# Secure Coding Guidelines: Application Logging

## 1. Purpose and Scope

This section establishes secure logging requirements for all applications developed, maintained, or deployed by Artais Security and its client engagements. Application logging is a foundational security control supporting incident detection, forensic investigation, regulatory compliance, and operational accountability. Inadequate or insecure logging is consistently cited as a contributing factor in breach post-mortems and is explicitly enumerated as a top application security risk by OWASP.

These guidelines map to and satisfy the requirements of OWASP ASVS v4.0.3 (Section V7: Error Handling and Logging), OWASP Top 10 2021 (A09: Security Logging and Monitoring Failures), PCI DSS 4.0 (Requirement 10), HIPAA Security Rule §164.312(b) (Audit Controls), NIST SP 800-53 Rev. 5 (AU family), NIST SP 800-92 (Log Management), and CWE-117, CWE-532, CWE-778, and CWE-779.

## 2. General Principles

Every production application must produce structured, tamper-resistant, time-synchronized logs sufficient to reconstruct security-relevant events. Logging is not a feature to be added late; it must be designed alongside authentication, authorization, and data-handling code from the start. The threat model for logs is twofold: logs must be trustworthy enough to support investigation, and logs themselves must not become an attack surface or a source of data leakage.

Developers shall treat log records as security-sensitive artifacts. They are written defensively, transmitted securely, stored with integrity protections, and retained according to the data classification and regulatory regime applicable to the system.

## 3. Events That Must Be Logged

The following events shall be captured in all applications handling regulated, sensitive, or business-critical data. This list aligns with PCI DSS 4.0 Requirement 10.2, HIPAA audit control expectations, NIST SP 800-53 AU-2, and OWASP ASVS V7.1.

* Authentication events must be logged in full: successful logins, failed login attempts, logouts, session creation and termination, password changes, multi-factor challenges and their outcomes, and account lockouts. 
* Authorization events including access grants, access denials, privilege escalations, and role or permission changes must be captured.
* All administrative actions, including configuration changes, user provisioning, and security policy modifications, require logging.
* Access to sensitive data defined as cardholder data, protected health information, personally identifiable information, authentication credentials, or cryptographic keys, must generate an audit record.
* Input validation failures, output encoding failures, and security control failures (including failed integrity checks and cryptographic operation failures) must be recorded.
* Application errors and exceptions that may indicate attack activity, including all uncaught exceptions reaching the application boundary, must be logged.
* Use of higher-risk functionality such as data export, bulk operations, and file uploads requires explicit logging.
* Startup, shutdown, and restart of the application and its logging subsystem must be captured.

## 4. Required Log Record Content

Each log record shall contain, at minimum, the following fields, consistent with PCI DSS 4.0 Requirement 10.2.2 and NIST SP 800-53 AU-3:

* A timestamp in ISO 8601 format with timezone offset or expressed in UTC. 
* A unique event identifier or correlation ID enabling cross-system event tracing.
* The event type or category.
* The identity of the user or service principal associated with the event, or an explicit indicator of anonymity where applicable.
* The source of the event, including hostname, process identifier, and source IP address where relevant.
* The action attempted and its outcome (success, failure, error). The resource or object affected.
* The severity level.
* The application name and version.

System clocks shall be synchronized via NTP from an authoritative time source. Clock drift exceeding acceptable tolerance (typically one second for systems in PCI scope per Requirement 10.6) must itself generate an alert.

## 5. Data That Must Never Be Logged

The following categories of data are prohibited from appearing in log records under any circumstance, whether by direct logging, exception traces, debug output, or third-party library logging:

* Passwords, passphrases, and password hashes in any form.
* Authentication tokens, session identifiers, API keys, OAuth tokens, JWTs, and refresh tokens.
* Cryptographic keys, key material, initialization vectors paired with ciphertext, and seeds.
* Full primary account numbers (PAN); if PAN must appear for operational reasons, it shall be masked to display at most the first six and last four digits, per PCI DSS 4.0 Requirement 3.4. Card verification values (CVV/CVV2/CID), PIN blocks, and full magnetic stripe data are prohibited from storage in any form, including logs, per PCI DSS 4.0 Requirement 3.2.
* Protected health information beyond the minimum necessary for the operational purpose of the log. Social Security numbers, government identifiers, and full dates of birth.
* Personal contact information that is not required for the event's audit purpose.

Where a field of this type is unavoidable in a log context — for example, a username that may itself be sensitive — it shall be hashed, tokenized, or truncated before being written. Developers shall not rely on log redaction as a primary control; sensitive values should be excluded at the call site.

## 6. Log Injection and Output Neutralization

CWE-117 (Improper Output Neutralization for Logs) is a frequently exploited weakness. All untrusted input that may appear in a log record must be neutralized before being written. This includes removing or escaping CR/LF characters, control characters, ANSI escape sequences, and any format specifiers consumed by the logging framework.

Structured logging (JSON, key-value, or similar) is the preferred mitigation, because user input is placed into a typed field rather than interpolated into a free-form message string. Where free-form messages are unavoidable, parameterized logging APIs shall be used and user-controlled values shall be passed as parameters, never concatenated into the format string.

## 7. Log Storage, Transmission, and Protection

Logs shall be transmitted to a centralized log management system over an authenticated, encrypted channel (TLS 1.2 minimum, TLS 1.3 preferred). Local-only logging is not acceptable for production systems in regulated scope.

Logs in transit and at rest shall be protected against unauthorized modification. Append-only storage, write-once media, cryptographic chaining, or signed log records shall be used where the regulatory regime requires demonstrable integrity (PCI DSS 4.0 Requirement 10.3.4, HIPAA §164.312(c)(1)). Access to log data shall be restricted to personnel with a documented operational need, and access to logs shall itself be logged.

Retention periods shall meet the longest applicable requirement: PCI DSS requires one year minimum with three months immediately available; HIPAA requires six years from the date of creation or last effective date; SOX and other regimes may extend further. Retention schedules shall be documented per system.

## 8. Logging Subsystem Resilience

The failure of the logging subsystem shall not cause the failure of the application's security controls, but it also must not silently mask security-relevant events. Applications shall define a documented behavior for log subsystem failure: either fail-closed (deny the operation) for high-assurance systems, or fail-safe with local buffering and alerting for availability-sensitive systems. Silent failure is prohibited.

Logging shall be asynchronous or buffered where performance demands it, but buffers shall be bounded and flushed on graceful shutdown. Loss of buffered events during a crash shall be considered in the threat model.

## 9. Language-Specific Guidance

### 9.1 Java

Use SLF4J as the logging facade with Logback or Log4j 2 as the implementation. Direct use of `System.out`, `System.err`, `printStackTrace()`, or `java.util.logging` in application code is prohibited in production paths.

Always use parameterized logging. The parameterized form defers string construction until the logger has decided to emit the record, and it isolates user input from the format string:

~~~java
// CORRECT
logger.info("Authentication failed for user={} sourceIp={}", username, sourceIp);

// INCORRECT — string concatenation, vulnerable to log injection if username contains CRLF
logger.info("Authentication failed for user=" + username + " sourceIp=" + sourceIp);
~~~

Neutralize CRLF and control characters in any untrusted value before logging. A reusable sanitizer should be provided by a shared library:

~~~java
public static String sanitizeForLog(String input) {
    if (input == null) return "null";
    return input.replaceAll("[\\r\\n\\t\\p{Cntrl}]", "_");
}
~~~

Configure Logback or Log4j 2 to emit JSON via `logstash-logback-encoder` or the Log4j 2 `JsonTemplateLayout`. This eliminates most injection risk by placing user input in typed fields.

Following the Log4Shell incident (CVE-2021-44228), ensure Log4j 2 is at 2.17.1 or later, and that `formatMsgNoLookups` defaults and JNDI lookup restrictions are in place. Verify your dependency tree, including transitive dependencies, with a software composition analysis tool.

Never log exception objects containing sensitive request data without filtering. Configure the `ThrowableProxyConverter` or equivalent to truncate stack traces in production. Mask sensitive fields using a custom converter or a Jackson `@JsonSerialize` annotation on the DTOs being logged.

For audit logs that require integrity, use a dedicated `Logger` writing to a separate appender, with the appender targeting an append-only sink (SIEM, syslog-ng with hash chaining, or an immutable cloud log service).

### 9.2 Python

Use the standard library `logging` module configured at application startup. Avoid `print()` for anything that must persist beyond local development.

Use the `%`-style or `{}`-style parameterized form so that argument formatting is deferred and isolated:

~~~python
# CORRECT
logger.info("Authentication failed for user=%s sourceIp=%s", username, source_ip)

# INCORRECT — f-string evaluates regardless of log level and concatenates untrusted input
logger.info(f"Authentication failed for user={username} sourceIp={source_ip}")
~~~

The f-string form is not categorically wrong, but it loses the lazy-evaluation benefit and makes it easier to slip user input into the format position. Prefer the parameterized form for any value that could originate from outside the application.

Sanitize untrusted values:

~~~python
import re
_LOG_SANITIZE = re.compile(r"[\r\n\t\x00-\x1f\x7f]")

def sanitize_for_log(value: object) -> str:
    if value is None:
        return "null"
    return _LOG_SANITIZE.sub("_", str(value))
~~~

Use `python-json-logger` or a similar formatter to emit structured JSON. Configure `logging.config.dictConfig` from a single, version-controlled configuration. Do not allow per-module ad hoc handler configuration in production code.

Use `logging.Filter` subclasses to redact sensitive fields uniformly. A central `SensitiveDataFilter` should match against a documented list of field names (`password`, `token`, `authorization`, `api_key`, `ssn`, `pan`, etc.) and replace their values with a redaction marker.

`logging.exception()` includes the traceback automatically — verify that the exception types in scope do not carry sensitive data in their `args` or `__cause__`. Custom exception classes that wrap request data must override `__str__` to redact.

For audit logs distinct from operational logs, create a separate logger (`audit = logging.getLogger("audit")`) with its own handler that writes to the centralized audit sink and does not propagate to the root logger.

If using a third-party framework (Django, Flask, FastAPI), ensure request-logging middleware is configured to exclude `Authorization`, `Cookie`, and `Set-Cookie` headers, and any request body fields matching the sensitive-field list.

### 9.3 C

C provides no managed logging facility, and the most common vulnerabilities in C logging are format string bugs (CWE-134) and unbounded buffer writes (CWE-120). Both are exploitable for code execution, not merely log corruption.

Never pass untrusted input as the format string. The format string must always be a compile-time constant:

~~~c
/* CORRECT */
syslog(LOG_WARNING, "Authentication failed for user=%s sourceIp=%s", user, ip);

/* CRITICAL VULNERABILITY — format string injection */
syslog(LOG_WARNING, user_supplied_message);

/* ALSO WRONG — user is in the format position */
fprintf(log_fp, user);
~~~

Compile with `-Wformat -Wformat-security -Werror=format-security` (GCC/Clang) to make format string misuse a build failure. This should be enforced in CI.

Use `syslog(3)` for system logging on POSIX platforms. It handles severity levels, facility codes, and centralized forwarding via syslog daemons (rsyslog, syslog-ng), which can chain to TLS-protected remote collectors. Open the connection with `openlog()` specifying the program name and `LOG_PID | LOG_CONS`.

When constructing log messages with `snprintf`, always check the return value and bound the buffer. Truncate untrusted strings to a known maximum length before logging, and replace control characters:

~~~c
static void sanitize_for_log(const char *in, char *out, size_t out_sz) {
    size_t i = 0;
    if (out_sz == 0) return;
    for (; in && in[i] && i < out_sz - 1; i++) {
        unsigned char c = (unsigned char)in[i];
        out[i] = (c < 0x20 || c == 0x7f) ? '_' : (char)c;
    }
    out[i] = '\0';
}
~~~

Do not log pointers, addresses, or memory contents in production builds; this leaks information useful for bypassing ASLR. Wrap such logging in `#ifdef DEBUG` and ensure release builds define `NDEBUG`.

Be cautious with `errno` and `strerror`: `strerror` is not thread-safe. Use `strerror_r` (POSIX) or `strerror_s` (Annex K) and capture `errno` immediately after the failing call before any other library function is invoked.

For applications with audit requirements, consider the Linux Audit framework (`libaudit`) for kernel-mediated audit records that user-space code cannot tamper with.

### 9.4 C++

The format string and buffer hazards of C apply equally to C++ when C APIs are used. In addition, C++ introduces RAII and exception considerations that affect logging design.

Prefer a vetted logging library: `spdlog` is the common choice and supports asynchronous logging, rotating files, syslog sinks, and structured output. `glog` and `Boost.Log` are alternatives. Do not use `iostream` for production logging; it lacks severity levels, structured output, and thread-safety guarantees needed for audit-grade logs.

`spdlog` uses `fmt`-style formatting, which is type-safe and not vulnerable to classic format string injection. Even so, the format string itself must be a compile-time constant:

~~~cpp
// CORRECT
spdlog::warn("Authentication failed for user={} sourceIp={}", user, ip);

// WRONG — runtime format string from untrusted source
spdlog::warn(fmt::runtime(user_supplied), arg);
~~~

Sanitize untrusted strings before logging. A small utility in your common library:

~~~cpp
std::string sanitize_for_log(std::string_view in) {
    std::string out;
    out.reserve(in.size());
    for (unsigned char c : in) {
        out.push_back((c < 0x20 || c == 0x7f) ? '_' : static_cast<char>(c));
    }
    return out;
}
~~~

Logging from destructors must not throw. Wrap any logging call in a destructor with `try { ... } catch (...) {}` and prefer `spdlog`'s no-throw configuration. A logging exception during stack unwinding will terminate the process.

Be deliberate about what gets logged when exceptions are caught at the application boundary. `e.what()` strings frequently embed input data — sanitize them. Custom exception classes that carry request context must provide a `redacted_what()` accessor and use it for logging.

For multithreaded applications, use the async logger configuration and ensure the logger is initialized before any thread that will log is started, and shut down only after all logging threads have joined. `spdlog::shutdown()` must be called at controlled exit.

Configure spdlog with a JSON pattern or a custom formatter to produce structured records suitable for ingestion by Splunk, Elastic, or any SIEM. Route audit-grade events to a separate logger with its own sink, and forward that sink to your immutable audit store.

## 10. Verification

Compliance with this section shall be verified through a combination of static analysis (rules covering CWE-117, CWE-134, CWE-532), dependency scanning (for known-vulnerable logging libraries), code review checklists, and runtime verification of log content against the prohibited-data list. Logging configuration shall be reviewed at each release. Penetration tests shall include attempts at log injection and shall verify that sensitive data does not appear in any log destination.

## 11. References

- OWASP ASVS v4.0.3, V7
- OWASP Top 10 2021, A09
- OWASP Logging Cheat Sheet
- PCI DSS v4.0, Requirements 3, 10
- HIPAA Security Rule, 45 CFR §164.312(b) and (c)
- NIST SP 800-53 Rev. 5, AU control family
- NIST SP 800-92, Guide to Computer Security Log Management
- CWE-117, CWE-134, CWE-532, CWE-778, CWE-779
- CERT Secure Coding Standard, FIO and ERR sections
