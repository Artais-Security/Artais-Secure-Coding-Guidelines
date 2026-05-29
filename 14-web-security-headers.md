# Secure Coding Guidelines: Web Application Security Headers

## 1. Purpose and Scope

This section establishes requirements for HTTP response headers that browsers and intermediaries use to enforce security policies. Security headers are inexpensive, effective defense-in-depth controls that defend against a wide range of attacks including XSS, clickjacking, MIME sniffing, and information disclosure.

These guidelines map to OWASP ASVS V14.4 (HTTP Security Headers) and V14.5, OWASP Top 10 2021 A05 (Security Misconfiguration), PCI DSS 4.0 Requirement 6.2.4, and CWE-693 (Protection Mechanism Failure), CWE-1021 (Improper Restriction of Rendered UI Layers).

The Content Security Policy and CORS guidelines specify those headers in detail. This section covers the remaining required headers and provides the integrated baseline.

## 2. General Principles

Security headers are set by default at the framework or reverse proxy layer. Per-endpoint exceptions shall require documented justification.

Headers shall be tested in production with each release. Drift between intended and actual headers is a common defect; automated verification is mandatory.

Headers shall apply to all responses, including error responses, redirects, and static assets. A common mistake is configuring headers only on the main application path, leaving error pages and static files exposed.

## 3. Normative Requirements

The following headers shall be set on all responses unless explicitly exempted:

### Strict-Transport-Security

`Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`

HSTS shall be enabled on all HTTPS endpoints. `max-age` shall be at least 31536000 (one year). `includeSubDomains` shall be set unless a documented subdomain cannot support HTTPS. `preload` and HSTS preload list submission are encouraged for production domains.

HSTS shall not be set on responses served over HTTP.

### Content-Security-Policy

`Content-Security-Policy: ...` (per the CSP guideline)

A restrictive CSP shall be set for all HTML responses. The specific policy is application-dependent; see the CSP guideline.

### X-Content-Type-Options

`X-Content-Type-Options: nosniff`

Set on all responses. Prevents browsers from MIME-sniffing the response and treating content as a different type than declared.

### X-Frame-Options

`X-Frame-Options: DENY` (or `SAMEORIGIN` for applications that require same-origin framing)

Set on all HTML responses. The CSP `frame-ancestors` directive supersedes this header in modern browsers; both shall be set for compatibility.

### Referrer-Policy

`Referrer-Policy: strict-origin-when-cross-origin`

Set on all responses. This is the modern browser default but shall be set explicitly to override server defaults and proxy behavior.

For applications handling sensitive URLs (with tokens in query strings — which should be avoided anyway), use `Referrer-Policy: no-referrer`.

### Permissions-Policy

`Permissions-Policy: camera=(), microphone=(), geolocation=(), interest-cohort=()`

Set on all HTML responses. Disable APIs not used by the application. Enumerate explicitly; do not rely on browser defaults.

### Cache-Control

`Cache-Control: no-store` for responses containing sensitive data or per-user content.

For static assets, long cache lifetimes with content-hash filenames are appropriate. For dynamic responses, `private` and explicit `max-age` based on freshness needs.

Avoid `no-cache` alone; pair with `no-store` for sensitive data.

### Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, Cross-Origin-Resource-Policy

For applications using SharedArrayBuffer or requiring isolation from cross-origin documents:

`Cross-Origin-Opener-Policy: same-origin`
`Cross-Origin-Embedder-Policy: require-corp`
`Cross-Origin-Resource-Policy: same-origin`

These provide cross-origin isolation. They are required for some browser features and recommended as defense-in-depth against Spectre-class attacks.

### Headers That Shall Be Removed

`Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, and similar server identification headers shall be suppressed. They provide reconnaissance value to attackers and no value to clients.

### Deprecated Headers

`X-XSS-Protection` is deprecated. It shall not be set; modern browsers ignore or have removed support. CSP supersedes it.

`Public-Key-Pins` (HPKP) is deprecated and shall not be used. Use Certificate Transparency monitoring instead.

`Expect-CT` is being phased out as Certificate Transparency becomes mandatory.

## 4. Language-Specific Guidance

### 4.1 Java

For Spring Boot, configure security headers in `SecurityFilterChain`:

~~~java
http.headers(headers -> headers
    .contentTypeOptions(Customizer.withDefaults())
    .httpStrictTransportSecurity(hsts -> hsts
        .maxAgeInSeconds(31536000)
        .includeSubDomains(true)
        .preload(true))
    .frameOptions(frame -> frame.deny())
    .referrerPolicy(ref -> ref.policy(STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
    .permissionsPolicy(pp -> pp.policy("camera=(), microphone=(), geolocation=()"))
    .contentSecurityPolicy(csp -> csp.policyDirectives(/* see CSP guideline */))
);
~~~

Remove the `Server` header by configuring the embedded server (`server.tomcat.servlet.relaxed-query-chars`-style properties depending on container) or strip via a `Filter`.

### 4.2 Python

For Django, use `django.middleware.security.SecurityMiddleware` and the related settings:

~~~python
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
X_FRAME_OPTIONS = "DENY"
~~~

For CSP, use `django-csp`. For Permissions-Policy, add a middleware that sets the header.

For Flask, use `flask-talisman` for most headers. Configure explicitly rather than accepting defaults:

~~~python
Talisman(app,
    content_security_policy=...,
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    referrer_policy="strict-origin-when-cross-origin",
    frame_options="DENY")
~~~

For FastAPI/Starlette, use `secure` or write a small middleware. There is no built-in security headers middleware.

### 4.3 C

For C-based HTTP servers, set headers explicitly per response. The libmicrohttpd, mongoose, and h2o APIs each provide header-setting calls.

Centralize header setting in a function called from every response path. Test that the function is called by all paths in CI with an integration test.

For TLS termination at a reverse proxy (nginx, HAProxy), set headers at the proxy and verify they reach the client.

### 4.4 C++

For Crow, Drogon, Pistache, and cpp-httplib, configure headers via the framework's middleware/filter mechanism. Set on all response paths via a default-response wrapper.

Example for Drogon:

~~~cpp
app().registerPostHandlingAdvice([](const HttpRequestPtr& req, const HttpResponsePtr& resp) {
    resp->addHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
    resp->addHeader("X-Content-Type-Options", "nosniff");
    resp->addHeader("X-Frame-Options", "DENY");
    resp->addHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    // ...
});
~~~

## 5. Verification

The Artais security headers tool (or an equivalent CLI scanner) shall verify the presence and value of required headers in CI and in production monitoring. Tools such as Mozilla Observatory, securityheaders.com, and `testssl.sh` provide additional verification. Penetration testing shall verify headers on error pages, redirects, and static assets, not only on main application paths. Headers shall be reviewed at each release.

## 6. References

- OWASP ASVS v4.0.3, V14.4, V14.5
- OWASP Top 10 2021, A05
- OWASP Secure Headers Project
- PCI DSS v4.0, Requirement 6.2.4
- CWE-693, CWE-1021
- MDN HTTP Headers documentation
