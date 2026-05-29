# Secure Coding Guidelines: Error and Exception Handling

## 1. Purpose and Scope

This section establishes requirements for error and exception handling. Error handling sits at the intersection of security, reliability, and usability: poor handling leaks sensitive information to attackers, masks ongoing attacks, and corrupts application state in ways that undermine other controls.

These guidelines map to OWASP ASVS V7 (Error Handling and Logging), OWASP Top 10 2021 A04 (Insecure Design) and A09, NIST SP 800-53 SI-11 (Error Handling), and CWE-209 (Information Exposure Through Error Message), CWE-248 (Uncaught Exception), CWE-390 (Detection of Error Condition Without Action), CWE-391 (Unchecked Error Condition), and CWE-755 (Improper Handling of Exceptional Conditions).

## 2. General Principles

Errors are security events. They shall be logged with sufficient context for investigation, handled in a way that preserves application invariants, and reported to clients without disclosing internal state.

Two distinct audiences consume error information. Operators and developers need detail: stack traces, internal identifiers, contextual data. End users and external clients need only enough to know that something failed and what (if anything) they can do. The detailed view shall be confined to internal logs and never returned to external clients.

Failure modes shall be documented in the threat model. The application's response to each failure category — input validation failure, authentication failure, authorization failure, resource exhaustion, downstream dependency failure, internal invariant violation — shall be specified.

## 3. Normative Requirements

A global error handler shall be installed at the application boundary. Any exception propagating out of a handler shall be caught, logged, and converted to a generic client response (HTTP 500 with no detail, or the framework's standard error envelope). Stack traces, exception class names, file paths, and internal identifiers shall not appear in client-facing responses.

Custom error pages shall be configured for all error status codes. Default framework error pages frequently disclose framework versions, configuration, and stack details.

Errors shall fail closed for security controls. An authorization check that throws shall result in denial, not in bypass. A cryptographic operation failure shall result in operation failure, not in silent fallback to plaintext.

Return values from functions that can fail shall be checked. In C, this means checking every system call and library call return; the use of `(void)` cast to silence warnings is acceptable only when the failure is genuinely irrelevant, and the rationale shall be documented. In other languages, exceptions or `Result`/`Option`-like types are preferred to error-by-return.

Resource cleanup shall be guaranteed regardless of error path. File handles, network connections, locks, allocated memory, and security-relevant state (e.g., temporary elevation) shall be released on every exit from the scope. Use RAII (C++), `try-with-resources` (Java), context managers (Python), or `goto cleanup` (C).

Sensitive data in exception objects shall be sanitized before logging. The Application Logging guideline applies to exception traces equally.

Errors shall not be silently swallowed. An empty catch block is a defect unless the action being taken is documented (typically with a comment and a debug-level log entry).

Different error types shall not leak which one occurred when the distinction is itself information. Authentication failures should not distinguish "no such user" from "wrong password" in client responses; the same generic response is used.

## 4. Language-Specific Guidance

### 4.1 Java

Install a global exception handler: `@ControllerAdvice` with `@ExceptionHandler` methods in Spring, or a `ContainerResponseFilter` in JAX-RS. The handler shall map exception types to HTTP status codes and generic response bodies.

Disable Spring Boot's default error attribute exposure in production: set `server.error.include-message=never`, `server.error.include-binding-errors=never`, `server.error.include-stacktrace=never`, `server.error.include-exception=false`.

Use `try-with-resources` for any `AutoCloseable`. Multi-resource statements are valid:

~~~java
try (var conn = ds.getConnection();
     var stmt = conn.prepareStatement(sql)) {
    // ...
}
~~~

Do not catch `Throwable` or `Exception` at fine granularity to "be safe"; this masks `Error` (such as `OutOfMemoryError`) and prevents the JVM from handling them. Catch specific exceptions where you can act on them; let everything else propagate to the global handler.

Avoid `e.printStackTrace()` entirely; it writes to stderr and lacks context.

Define a custom exception hierarchy for the application. Exceptions carrying sensitive data shall override `getMessage()` to provide a sanitized message and shall not include the sensitive data in the `cause` chain.

### 4.2 Python

Install a global exception handler in the framework: `app.errorhandler(Exception)` in Flask, custom `exception_handlers` in FastAPI, custom `EXCEPTION_HANDLER` in DRF, middleware in Django.

Configure `DEBUG=False` in production. Django's debug mode discloses settings, environment variables, and source code in tracebacks; this is appropriate only for local development.

Use context managers for resource handling:

~~~python
with open(path) as f:
    data = f.read()
~~~

For locks, network connections, and other resources without a built-in context manager, use `contextlib.contextmanager` to write one.

Use specific exception types in `except` clauses. `except Exception` is acceptable at the application boundary; `except:` (bare) is prohibited because it catches `KeyboardInterrupt` and `SystemExit`.

`logging.exception()` is the right tool for logging exceptions with traceback; do not concatenate `str(e)` into a log message.

For custom exceptions carrying data, override `__str__` to redact and provide a separate `.context` attribute consumed only by internal logging.

### 4.3 C

Every system call, library call, and allocation shall have its return value checked. `malloc`, `calloc`, `realloc`, `fopen`, `open`, `read`, `write`, `recv`, `send`, `getline`, `fgets`, `snprintf`, and others return values that indicate failure; ignoring them is a defect.

Use `goto cleanup` patterns for multi-resource cleanup:

~~~c
int do_work(void) {
    int ret = -1;
    FILE *fp = NULL;
    char *buf = NULL;

    fp = fopen(path, "r");
    if (!fp) goto cleanup;

    buf = malloc(SIZE);
    if (!buf) goto cleanup;

    /* ... */
    ret = 0;

cleanup:
    free(buf);
    if (fp) fclose(fp);
    return ret;
}
~~~

`errno` shall be captured immediately after the failing call, before any other library call that may modify it. `strerror` is not thread-safe; use `strerror_r` (POSIX) or `strerror_s` (Annex K).

Do not use `assert` for runtime error handling: assertions are compiled out with `NDEBUG`. Use explicit error returns.

Signal handlers shall be async-signal-safe: only async-signal-safe functions (per POSIX `signal-safety(7)`) may be called. Logging from signal handlers requires special care.

### 4.4 C++

Use RAII for all resource management. `std::unique_ptr` with custom deleters, `std::lock_guard`, `std::fstream`, and library-provided scope guards.

Prefer exceptions for error propagation in C++ unless the codebase has a documented exception-free policy. Mark functions `noexcept` only when you are certain no exception will propagate.

Do not throw exceptions across module or library boundaries with incompatible ABIs. C interface layers shall translate exceptions to error codes.

Destructors shall not throw. If cleanup in a destructor can fail, log and swallow rather than throw:

~~~cpp
~Resource() noexcept {
    try { do_cleanup(); }
    catch (const std::exception& e) { log_error("cleanup failed: {}", e.what()); }
    catch (...) { log_error("cleanup failed: unknown"); }
}
~~~

Use `std::expected` (C++23) or a `Result<T, E>` type for fallible operations where exceptions are not appropriate (hot paths, library boundaries).

`std::terminate` from an uncaught exception is fail-closed and acceptable; `abort()` from undefined behavior is not. Use sanitizers (ASan, UBSan) in development and testing.

## 5. Verification

Static analysis shall flag unchecked return values, empty catch blocks, and exception types that include `getMessage`-style accessors on sensitive data. Code review shall confirm that the global error handler is configured and that no handler returns stack traces to clients. Fault injection testing shall verify behavior under downstream failure. Penetration testing shall verify that error messages do not disclose internal state.

## 6. References

- OWASP ASVS v4.0.3, V7
- OWASP Top 10 2021, A04, A09
- OWASP Error Handling Cheat Sheet
- NIST SP 800-53 Rev. 5, SI-11
- CWE-209, CWE-248, CWE-390, CWE-391, CWE-755
- CERT Secure Coding: ERR00-J, ERR33-C, ERR50-CPP
