# Secure Coding Guidelines: Content Security Policy (CSP)

## 1. Purpose and Scope

This section establishes requirements for Content Security Policy in web applications. CSP is the most effective defense-in-depth mechanism against cross-site scripting (XSS) and a strong control against data exfiltration and clickjacking. A correctly configured CSP can mitigate vulnerabilities that would otherwise be exploitable; a misconfigured CSP provides false assurance.

These guidelines map to OWASP ASVS V14.4.1 and V14.5, OWASP Top 10 2021 A05, and CWE-1021, CWE-79, and CSP Level 3 specification.

## 2. General Principles

CSP is a defense-in-depth control. The primary defense against XSS remains output encoding per the Input Validation and Output Encoding guideline. CSP catches what the primary defense misses.

CSP shall be configured per application, with the policy tailored to the application's actual resource needs. Generic policies copied from articles are usually either too permissive (providing no real protection) or too restrictive (breaking functionality and creating pressure to weaken).

A strict CSP using nonces or hashes is preferred over an allowlist-based policy. Allowlists are difficult to maintain securely and are often bypassable.

## 3. Normative Requirements

### Required Directives

A baseline CSP for a new application shall include:

~~~
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-<random>' 'strict-dynamic';
  style-src 'self' 'nonce-<random>';
  img-src 'self' data:;
  font-src 'self';
  connect-src 'self';
  frame-ancestors 'none';
  form-action 'self';
  base-uri 'none';
  object-src 'none';
  upgrade-insecure-requests;
  report-uri /csp-report;
  report-to csp-endpoint;
~~~

Applications shall deviate from this baseline only with documented justification.

### Script Source

`script-src` shall not include `'unsafe-inline'` or `'unsafe-eval'`. Where inline scripts are required, they shall be authorized via per-response nonces or hashes.

Nonces shall be cryptographically random, at least 128 bits, generated per response. They shall not be reused across responses.

`'strict-dynamic'` is preferred for modern applications: it propagates trust from a nonced script to scripts it loads, eliminating the need to enumerate every script host.

Allowlist-based `script-src` (host names) is acceptable for legacy applications but is generally less secure than the nonce + `'strict-dynamic'` approach because allowed CDNs often host content that bypasses CSP.

### Style Source

`style-src` shall avoid `'unsafe-inline'`. Where inline styles are required, use nonces. CSS-in-JS frameworks may require accommodation; document and review.

### Frame Ancestors

`frame-ancestors 'none'` shall be set for applications that should not be framed. For applications that legitimately frame themselves (in-app embeds), `frame-ancestors 'self'`. For controlled third-party framing, enumerate the parents explicitly.

This directive supersedes `X-Frame-Options` in modern browsers; set both for compatibility.

### Form Action and Base URI

`form-action 'self'` prevents forms from being submitted to attacker-controlled hosts via DOM manipulation.

`base-uri 'none'` prevents `<base>` tag injection from redirecting relative URLs.

### Object and Plugin Content

`object-src 'none'` blocks plugins (Flash, Java applets, deprecated technologies) and is broadly safe.

### Mixed Content

`upgrade-insecure-requests` directs browsers to upgrade HTTP subresource requests to HTTPS. Use this even when the application has no HTTP resources, as defense against accidental introduction.

`block-all-mixed-content` is deprecated; `upgrade-insecure-requests` plus HSTS replaces it.

### Reporting

`report-uri` and `report-to` shall be configured to capture violations. Reports shall be reviewed periodically and used to refine the policy. A reporting-only policy (`Content-Security-Policy-Report-Only`) shall be used during policy rollout to identify issues without breaking functionality.

### Sandbox

The `sandbox` directive applies sandbox restrictions to the document. Useful for embedded user-generated content; not appropriate for the primary application response.

### Trusted Types

For applications that handle DOM-XSS sinks (innerHTML, document.write, eval), the `require-trusted-types-for 'script'` directive enforces the Trusted Types API. This requires application code changes but provides strong protection against DOM-XSS.

## 4. Language-Specific Guidance

### 4.1 Java

For Spring Security, configure CSP in `SecurityFilterChain`:

~~~java
http.headers(headers -> headers
    .contentSecurityPolicy(csp -> csp.policyDirectives(
        "default-src 'self'; " +
        "script-src 'self' 'nonce-" + nonce + "' 'strict-dynamic'; " +
        "style-src 'self' 'nonce-" + nonce + "'; " +
        // ... rest of policy
        "report-to csp-endpoint"
    ))
);
~~~

For per-response nonces, use a filter that generates a nonce, stores it in the request attributes for template rendering, and writes it into the CSP header. Thymeleaf and similar template engines have mechanisms to access request attributes for inline script nonces.

For Spring's CSP reporting, expose a `/csp-report` endpoint that accepts `application/csp-report` content type and forwards reports to monitoring.

### 4.2 Python

For Django, use `django-csp`:

~~~python
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'", "'strict-dynamic'")
CSP_STYLE_SRC = ("'self'",)
CSP_FRAME_ANCESTORS = ("'none'",)
CSP_FORM_ACTION = ("'self'",)
CSP_BASE_URI = ("'none'",)
CSP_OBJECT_SRC = ("'none'",)
CSP_UPGRADE_INSECURE_REQUESTS = True
CSP_INCLUDE_NONCE_IN = ("script-src", "style-src")
CSP_REPORT_URI = "/csp-report"
~~~

`django-csp` generates nonces and exposes them in templates via `{{ request.csp_nonce }}`. Use this in template `<script nonce="{{ request.csp_nonce }}">` blocks.

For Flask, use `flask-talisman` with `content_security_policy_nonce_in`:

~~~python
Talisman(app, content_security_policy={
    "default-src": "'self'",
    "script-src": ["'self'", "'strict-dynamic'"],
    # ...
}, content_security_policy_nonce_in=["script-src", "style-src"])
~~~

For FastAPI, set the header in middleware. Generate the nonce per request and expose it to templates via the request state.

### 4.3 C

For C-based HTTP servers, generate the nonce per response using a CSPRNG (`getrandom`, libsodium's `randombytes_buf`), base64-encode it, and embed it in both the CSP header and the response body's inline scripts.

Centralize CSP construction in a single function. Test the policy with `curl` and a browser-based viewer.

### 4.4 C++

For Crow, Drogon, Pistache, and cpp-httplib, generate the nonce per request, store it in the request context, and write it into the CSP header in a response post-processor.

For applications using template engines (e.g., Drogon's CSP-aware templates), pass the nonce as a template variable.

## 5. Verification

CSP shall be validated using Google CSP Evaluator or the Mozilla Observatory in CI. CSP reports shall be monitored continuously; a sudden surge in reports typically indicates either a deployment issue or an active attack. Penetration testing shall include CSP bypass attempts targeting allowlisted sources, dangling DOM-XSS, and base-uri injection. The policy shall be reviewed at every release. Reporting-only mode shall precede enforcement mode for any significant policy change.

## 6. References

- OWASP ASVS v4.0.3, V14.4.1, V14.5
- OWASP Top 10 2021, A05
- OWASP CSP Cheat Sheet
- CSP Level 3 specification (W3C)
- CWE-1021, CWE-79
- Google CSP Evaluator
