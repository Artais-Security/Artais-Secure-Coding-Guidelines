# Secure Coding Guidelines: Rate Limiting, Quotas, and Abuse Prevention

## 1. Purpose and Scope

This section establishes requirements for rate limiting, quota enforcement, and abuse prevention in applications and APIs. Rate limiting protects against brute force, scraping, denial of service, resource exhaustion, cost abuse (for cloud-backed or AI-backed APIs), and noisy-neighbor patterns. It is also a usability and reliability control.

These guidelines map to OWASP ASVS V11 (Business Logic), OWASP API Security Top 10 API4 (Unrestricted Resource Consumption), and CWE-307 (Improper Restriction of Excessive Authentication Attempts), CWE-770 (Allocation of Resources Without Limits).

## 2. General Principles

Every public-facing endpoint shall have a rate limit. Defaults shall be conservative; specific endpoints may have higher limits where justified by usage patterns.

Rate limits shall be enforced server-side. Client-side throttling is a courtesy, not a security control.

Rate limits shall apply per authenticated principal, per IP address (or other identifier for unauthenticated traffic), and where appropriate per endpoint. Combined limits at multiple levels prevent a single dimension from being abused.

## 3. Normative Requirements

### Granularity

Rate limits shall be defined per (identity, endpoint) pair where the threat model warrants endpoint-specific behavior. Authentication endpoints, password reset, MFA enrollment, and similar high-risk endpoints shall have stricter limits than general API access.

Per-IP limits provide a baseline for unauthenticated traffic. Per-account limits protect against credential abuse. Per-tenant limits in multi-tenant systems prevent one tenant from impacting others.

For expensive operations (LLM inference, video processing, report generation), per-operation quotas shall be enforced in addition to request-rate limits. A user making one expensive request per minute can still exceed cost budgets.

### Algorithm

Token bucket or sliding window are the standard algorithms. Fixed-window counters are simpler but allow burst attacks at window boundaries.

Distributed enforcement (multiple application instances) requires a shared state store. Redis is the common choice; verify the implementation handles concurrent decrement correctly.

For high-traffic systems, sampling or probabilistic counting (e.g., probabilistic counters with periodic reconciliation) may be acceptable; ensure the implementation cannot be gamed by attackers who understand the sampling.

### Response

Rate-limited requests shall return HTTP 429 Too Many Requests with `Retry-After` header indicating when the client may retry. Returning 200 with an error payload is incorrect.

`X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset` (or RFC 9759 standardized variants) headers may be returned to permit client-side adaptation.

For abuse rather than legitimate throttling, returning 429 alone is insufficient. Account lockout, captcha, or other progressive controls per the threat model may be appropriate.

### Authentication-Specific Limits

Login attempts shall be rate-limited per account and per IP. After a documented number of failures, additional measures shall apply: increased delays, captcha, temporary lockout with notification to the legitimate user.

Account enumeration via the login endpoint shall be prevented by returning identical responses for failed authentication regardless of whether the username exists, including timing.

Password reset, MFA enrollment, and similar flows shall have their own rate limits separate from authentication.

### Cost-Based Limiting

For APIs with significant per-request cost (LLM inference, third-party API forwarding), token-based or unit-based limiting shall be implemented in addition to request-rate limiting. Per-tenant monthly budgets shall be enforced with alerts before exhaustion.

### Bypass Considerations

Authenticated administrative requests may bypass rate limits in some designs; the bypass shall be explicit and logged. Internal service calls bypassing rate limits shall be authenticated as such.

Rate limit bypass for "trusted IPs" (offices, partners) is a common but risky pattern. Document and review periodically.

### Detection

Sustained rate-limit-triggered traffic from a single source is itself a signal. Connect rate limiting with security monitoring; many rate-limit events from a single source may warrant blocking at a lower layer (WAF, network).

Anomaly detection shall identify shifts in legitimate usage patterns to distinguish from attack traffic.

## 4. Language-Specific Guidance

### 4.1 Java

For Spring Boot, use Resilience4j, Bucket4j, or a service mesh (Istio rate limit, Envoy local rate limit) for distributed enforcement.

With Bucket4j and Redis:

~~~java
ProxyManager<String> proxyManager = ...;  // Redis-backed
Supplier<BucketConfiguration> cfg = () -> BucketConfiguration.builder()
    .addLimit(Bandwidth.simple(100, Duration.ofMinutes(1)))
    .build();

Bucket bucket = proxyManager.builder().build(userKey, cfg);
if (!bucket.tryConsume(1)) {
    return ResponseEntity.status(429).header("Retry-After", "60").build();
}
~~~

For API Gateway-fronted services, prefer enforcing at the gateway (AWS API Gateway, Kong, Tyk) for consistency across services.

For Spring Security, configure brute force protection on authentication endpoints via `AbstractAuthenticationFailureEvent` listeners that track failures in a distributed store.

### 4.2 Python

For FastAPI, use `slowapi`:

~~~python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address, storage_uri="redis://localhost:6379")
app.state.limiter = limiter

@app.post("/login")
@limiter.limit("5/minute")
def login(request: Request, ...): ...
~~~

For Django, use `django-ratelimit` with a Redis cache backend.

For Flask, `flask-limiter` with Redis backend.

For higher-throughput needs, push enforcement to a reverse proxy (nginx, HAProxy) or API gateway. Application-level limiting is appropriate when limits depend on application-level identity (account, tenant, plan).

### 4.3 C

For C-based services, implement rate limiting against a Redis instance via `hiredis` or `redis++`. Token bucket logic:

~~~c
/* simplified pseudocode */
long now = time(NULL);
long tokens = redis_hget(key, "tokens");
long last = redis_hget(key, "last");
tokens = min(MAX, tokens + (now - last) * RATE);
if (tokens >= cost) {
    tokens -= cost;
    redis_hset(key, "tokens", tokens);
    redis_hset(key, "last", now);
    return ALLOW;
}
return DENY;
~~~

Atomicity matters; use Redis Lua scripts or `WATCH/MULTI/EXEC` to avoid race conditions.

For embedded systems or appliances, in-memory rate limiting with periodic eviction may be appropriate; document the lack of cross-instance coordination.

### 4.4 C++

The C guidance applies. C++ frameworks (Drogon, Crow, Pistache) may have rate-limiting middleware; verify the implementation. For high-performance services, a custom Redis-backed implementation following the C example is reasonable.

For services running in service meshes, prefer mesh-level rate limiting where it suffices.

## 5. Verification

Rate limits shall be tested via load testing during pre-production and via synthetic monitoring in production. Authentication brute force shall be tested by intentional excess. Quota systems for cost-based limits shall have alerting on approach to limit and shall be tested in staging. Penetration testing shall include rate limit bypass attempts: header manipulation (X-Forwarded-For if used naively), distributed requests, key rotation patterns.

## 6. References

- OWASP ASVS v4.0.3, V11
- OWASP API Security Top 10, API4
- OWASP Authentication Cheat Sheet, brute force section
- CWE-307, CWE-770, CWE-799
- RFC 6585 (HTTP 429), RFC 7231 (Retry-After)
- RFC 9759 (Rate Limit Header Fields)
