# Secure Coding Guidelines: Cookies and Browser Storage

## 1. Purpose and Scope

This section establishes requirements for cookies, localStorage, sessionStorage, and other browser-side state mechanisms. Cookies in particular have security-relevant attributes that must be set correctly; absent or incorrect attributes are a common source of session hijacking, CSRF, and information disclosure vulnerabilities.

These guidelines map to OWASP ASVS V3 (Session Management) and V8 (Data Protection), OWASP Top 10 2021 A05, PCI DSS 4.0 Requirements 6.2.4 and 8.2.8, and CWE-614 (Sensitive Cookie Without Secure Attribute), CWE-1004 (Sensitive Cookie Without HttpOnly), CWE-1275 (Sensitive Cookie with Improper SameSite).

## 2. General Principles

Cookies are the primary mechanism for session continuity in browsers. Every cookie shall be configured with attributes appropriate to its sensitivity and purpose. The default for a new cookie shall be the most restrictive set of attributes, relaxed only with documented justification.

Browser storage (`localStorage`, `sessionStorage`, IndexedDB) is accessible to any JavaScript running on the origin. Storing sensitive data there is equivalent to making it readable by any XSS vulnerability in the application; it shall be avoided.

## 3. Normative Requirements

### Cookie Attributes

`Secure` shall be set on all cookies. Cookies shall be served only over HTTPS. The development environment shall also use HTTPS; the cost is low and the parity prevents bugs.

`HttpOnly` shall be set on all cookies unless the cookie is specifically designed to be read by JavaScript (a small minority — e.g., a CSRF token in a double-submit pattern). Session cookies and authentication cookies shall always be HttpOnly.

`SameSite` shall be set explicitly to `Lax` or `Strict`. `SameSite=Lax` is the modern browser default; setting it explicitly documents intent and prevents proxy behavior from altering it. Use `Strict` for session cookies in applications that do not support top-level cross-site navigation use cases.

`SameSite=None` requires `Secure` and shall be used only for cookies that must be sent on cross-site requests (third-party authentication, embed scenarios). Document the cross-site purpose.

`Domain` shall not be set unless required for cross-subdomain access. A cookie without `Domain` is scoped to the origin only, which is the most restrictive option.

`Path` shall be set to the most specific path that satisfies the application's needs, typically `/`. Cookies do not provide isolation between paths in any security-meaningful way (the same-origin policy applies to the origin, not the path), so `Path` is for organization rather than security.

`Expires` and `Max-Age` shall be set with awareness of their security implications. Session cookies (without expiry) persist only in memory and are cleared when the browser closes; persistent cookies survive. Use session cookies for authentication where the use case allows.

### Cookie Prefixes

`__Host-` and `__Secure-` prefixes encode required attributes into the cookie name and are enforced by browsers:

- `__Host-` requires `Secure`, no `Domain` attribute, and `Path=/`. This prevents subdomain takeover and overwrite attacks. Use for session cookies.
- `__Secure-` requires `Secure`. Use where `__Host-`'s restrictions are too strict but `Secure` is still required.

Session cookies should be named `__Host-session` or similar.

### Browser Storage

Do not store secrets in `localStorage`, `sessionStorage`, or IndexedDB. This includes:

- Authentication tokens (JWTs, session identifiers, API keys)
- Cryptographic keys
- Personal data subject to confidentiality requirements
- Anything that an attacker with XSS should not obtain

Store session identifiers in HttpOnly cookies. Where the application architecture requires a token in a header (single-page applications calling APIs), evaluate the tradeoffs: a token in `localStorage` is exposed to XSS; a token in an HttpOnly cookie requires CSRF protection. Generally, the HttpOnly cookie + CSRF token pattern is preferred over `localStorage` token storage.

Cache appropriate data in browser storage only when it is non-sensitive (UI preferences, draft content, public reference data).

### Cookie Tracking and Privacy

For applications subject to ePrivacy Directive (EU) or analogous regulations, non-essential cookies require consent. Authentication cookies are typically considered essential and exempt from consent requirements; analytics and marketing cookies require opt-in.

Document the cookie inventory: name, purpose, attributes, lifetime, third-party or first-party, essential vs. non-essential. Update on every cookie addition.

## 4. Language-Specific Guidance

### 4.1 Java

For Spring Boot, configure session cookie attributes in `application.properties`:

~~~properties
server.servlet.session.cookie.secure=true
server.servlet.session.cookie.http-only=true
server.servlet.session.cookie.same-site=lax
server.servlet.session.cookie.name=__Host-session
~~~

The `__Host-` prefix requires `Path=/`, which is the default.

For arbitrary cookies set in code, use `ResponseCookie`:

~~~java
ResponseCookie cookie = ResponseCookie.from("__Host-pref", value)
    .secure(true)
    .httpOnly(true)
    .sameSite("Lax")
    .path("/")
    .maxAge(Duration.ofDays(30))
    .build();
response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
~~~

Avoid the older `javax.servlet.http.Cookie` class, which lacks `SameSite` support and uses string manipulation that can be error-prone.

### 4.2 Python

For Django, configure in `settings.py`:

~~~python
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_NAME = "__Host-sessionid"
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = False  # CSRF token cookie is read by JS in double-submit
CSRF_COOKIE_SAMESITE = "Lax"
~~~

For Flask:

~~~python
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_NAME="__Host-session",
)
~~~

For FastAPI/Starlette, configure `SessionMiddleware` with `https_only=True` and `same_site="lax"`. For arbitrary cookies, use `response.set_cookie` with all attributes explicit:

~~~python
response.set_cookie(
    key="__Host-pref",
    value=value,
    secure=True,
    httponly=True,
    samesite="lax",
    path="/",
    max_age=2592000,
)
~~~

### 4.3 C

For C-based HTTP servers, construct the `Set-Cookie` header explicitly. Use a helper to ensure no cookie is set without the required attributes:

~~~c
static int set_secure_cookie(struct MHD_Response *resp,
                              const char *name, const char *value,
                              int max_age, const char *samesite) {
    char buf[1024];
    int n = snprintf(buf, sizeof buf,
        "%s=%s; Path=/; Secure; HttpOnly; SameSite=%s; Max-Age=%d",
        name, value, samesite, max_age);
    if (n < 0 || (size_t)n >= sizeof buf) return -1;
    return MHD_add_response_header(resp, "Set-Cookie", buf);
}
~~~

The `value` shall be URL-encoded if it may contain special characters. The `name` shall be from a known set; do not allow user input as cookie names.

### 4.4 C++

For Crow, Drogon, Pistache, or cpp-httplib, use the framework's cookie API. Drogon's `Cookie` class supports the relevant attributes:

~~~cpp
Cookie cookie("__Host-session", session_id);
cookie.setSecure(true);
cookie.setHttpOnly(true);
cookie.setSameSite(Cookie::SameSite::kLax);
cookie.setPath("/");
cookie.setMaxAge(86400);
resp->addCookie(std::move(cookie));
~~~

Wrap cookie creation in a factory that enforces the required defaults; do not let raw cookie construction happen at call sites.

## 5. Verification

The `artais-cookie-cop` tool shall be run against all production endpoints in CI and during deployment verification. The cookie inventory shall be reviewed quarterly. Penetration testing shall include cookie attribute verification, browser storage inspection, and CSRF testing. Static analysis shall flag cookie creation without the required attributes.

## 6. References

- OWASP ASVS v4.0.3, V3, V8
- OWASP Top 10 2021, A05
- OWASP Session Management, HTML5 Security Cheat Sheets
- PCI DSS v4.0, Requirements 6.2.4, 8.2.8
- CWE-614, CWE-1004, CWE-1275
- RFC 6265bis (Cookies: HTTP State Management Mechanism)
