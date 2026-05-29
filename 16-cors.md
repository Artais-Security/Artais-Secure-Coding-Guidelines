# Secure Coding Guidelines: Cross-Origin Resource Sharing (CORS)

## 1. Purpose and Scope

This section establishes requirements for configuring Cross-Origin Resource Sharing in web applications and APIs. CORS is frequently misconfigured: overly permissive settings (`Access-Control-Allow-Origin: *` with credentials, dynamic origin reflection without validation) effectively disable the same-origin policy for the affected endpoints.

These guidelines map to OWASP ASVS V14.5, OWASP Top 10 2021 A05, and CWE-942 (Permissive Cross-Domain Policy with Untrusted Domains).

## 2. General Principles

The same-origin policy is the browser's primary defense against cross-site attacks. CORS is a mechanism to selectively relax that policy for legitimate cross-origin interaction. Every relaxation shall be intentional and minimal.

The default for a new application shall be no CORS configuration, which means the browser will block cross-origin requests. Adding CORS shall be a deliberate decision per endpoint or per set of endpoints, with the allowed origins documented.

## 3. Normative Requirements

### Origin Validation

`Access-Control-Allow-Origin: *` shall not be used in conjunction with `Access-Control-Allow-Credentials: true`. Modern browsers reject this combination, but it shall not appear in configuration regardless.

For APIs requiring credentials (cookies, Authorization headers in cross-origin contexts), the `Access-Control-Allow-Origin` response shall be a specific origin string echoed from a validated allowlist of origins, with `Vary: Origin` set to prevent cache poisoning.

Dynamic origin reflection without validation is prohibited. The pattern `Access-Control-Allow-Origin: <request Origin header>` is a vulnerability if the allowlist is unchecked. Validate against the allowlist and respond only with allowlisted origins.

`null` origins (from sandboxed iframes, file:// URLs) shall not be in the allowlist. Reflecting `Origin: null` defeats security boundaries.

Wildcard subdomains (`*.example.com`) require careful matching. Use a full match against a precompiled allowlist or a vetted matching library; do not substring-match.

### Methods and Headers

`Access-Control-Allow-Methods` shall enumerate only the methods used by the endpoint. Do not include all HTTP methods.

`Access-Control-Allow-Headers` shall enumerate only the headers the application reads. Do not include `*`.

`Access-Control-Expose-Headers` shall enumerate only headers that need to be visible to the cross-origin caller.

### Preflight

The preflight cache (`Access-Control-Max-Age`) shall be set to a reasonable value (typically 5 to 10 minutes) to balance performance against the ability to revoke CORS configurations. Avoid the browser's maximum (typically 7200 seconds in Firefox, 600 in Chromium).

Preflight handling shall be performed by the framework or middleware. Do not hand-roll preflight responses; they are easy to get wrong.

### Credentials

`Access-Control-Allow-Credentials: true` shall be set only when the endpoint requires cookies or HTTP authentication in cross-origin requests. Most APIs using bearer tokens in the `Authorization` header do not need credentials mode, because the token is supplied by the JavaScript client rather than the browser's credential store.

When credentials are allowed, the origin allowlist shall be strict and shall not include public or community-controlled domains.

### Internal vs. External APIs

APIs not intended for cross-origin use shall not configure CORS at all. The absence of CORS headers causes browsers to block cross-origin requests, which is the desired behavior.

APIs intended only for the same application's frontend shall configure CORS only for that frontend's origin, not for general internet access.

Public APIs intended for any origin (no credentials) may use `Access-Control-Allow-Origin: *` without `Allow-Credentials`. Document the intent explicitly.

## 4. Language-Specific Guidance

### 4.1 Java

For Spring Boot, configure CORS in `SecurityFilterChain` or globally via `WebMvcConfigurer`:

~~~java
@Bean
CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(List.of("https://app.example.com", "https://admin.example.com"));
    config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
    config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
    config.setExposedHeaders(List.of("X-Request-Id"));
    config.setAllowCredentials(true);
    config.setMaxAge(600L);
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/api/**", config);
    return source;
}
~~~

Do not use `setAllowedOriginPatterns` with overly broad patterns. Validate any pattern against the threat model.

### 4.2 Python

For Django, use `django-cors-headers`:

~~~python
CORS_ALLOWED_ORIGINS = [
    "https://app.example.com",
    "https://admin.example.com",
]
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
CORS_ALLOW_HEADERS = ["authorization", "content-type"]
CORS_PREFLIGHT_MAX_AGE = 600
~~~

`CORS_ALLOW_ALL_ORIGINS = True` shall not be set on credentialed endpoints.

For Flask, use `flask-cors`:

~~~python
CORS(app,
    resources={r"/api/*": {
        "origins": ["https://app.example.com"],
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Authorization", "Content-Type"],
        "supports_credentials": True,
        "max_age": 600,
    }})
~~~

For FastAPI/Starlette, use the built-in `CORSMiddleware`:

~~~python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.example.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)
~~~

`allow_origins=["*"]` with `allow_credentials=True` is silently downgraded by the middleware but the configuration is still incorrect; do not use it.

### 4.3 C

For C-based HTTP servers, implement CORS handling in middleware. The logic:

1. Read the `Origin` header from the request.
2. Match against an in-memory allowlist (validated at startup).
3. If matched, set `Access-Control-Allow-Origin: <origin>` and `Vary: Origin`.
4. For preflight (OPTIONS with `Access-Control-Request-Method`), set the methods/headers allowlist.
5. Set `Access-Control-Max-Age`, `Access-Control-Allow-Credentials` as appropriate.

Test the implementation with both allowed and disallowed origins, and with edge cases (`null` origin, empty origin, malformed origin).

### 4.4 C++

Use the framework's CORS support. Drogon, Crow, and Pistache provide CORS plugins or middleware. Configure explicitly:

~~~cpp
// Drogon example
app().registerPreRoutingAdvice([allowed_origins = ...](const HttpRequestPtr& req, ...) {
    auto origin = req->getHeader("Origin");
    if (allowed_origins.count(origin)) {
        // set CORS headers on response
    }
});
~~~

Centralize the allowlist; do not duplicate it across endpoints.

## 5. Verification

The Artais CORS tool (or equivalent) shall test CORS configurations from outside the application, including credential mode tests and origin reflection tests. Misconfigured CORS shall be a blocking finding. Production monitoring shall verify `Vary: Origin` accompanies dynamic CORS responses. Penetration testing shall include CORS misconfiguration discovery, especially for endpoints not initially intended for cross-origin use.

## 6. References

- OWASP ASVS v4.0.3, V14.5
- OWASP Top 10 2021, A05
- OWASP HTML5 Security Cheat Sheet (CORS section)
- CWE-942, CWE-346
- Fetch standard, CORS protocol section
