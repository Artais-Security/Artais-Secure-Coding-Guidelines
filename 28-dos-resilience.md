# Secure Coding Guidelines: Denial of Service Resilience

## 1. Purpose and Scope

This section establishes requirements for application resilience against denial of service. Rate limiting (separate guideline) addresses volumetric abuse at the request level; this guideline addresses application-level DoS vectors: resource exhaustion through algorithmic complexity, memory pressure, slow client attacks, regular expression catastrophic backtracking, decompression bombs, and connection state attacks.

These guidelines map to OWASP ASVS V11.1 (Business Logic Security), OWASP API Security Top 10 API4, NIST SP 800-53 SC-5 (Denial of Service Protection), and CWE-400 (Uncontrolled Resource Consumption), CWE-409 (Improper Handling of Highly Compressed Data), CWE-1333 (Inefficient Regular Expression Complexity), CWE-770.

## 2. General Principles

Every resource the application allocates from external input is a potential DoS vector: memory, CPU time, file descriptors, threads, connections, disk space, downstream service quota. Each resource consumption shall be bounded.

Resilience is not perfection: the goal is graceful degradation and rapid recovery rather than absolute prevention. A well-designed application sheds load before falling over.

## 3. Normative Requirements

### Input Size Limits

Request body size, header size, URL length, and individual field length shall be bounded. Limits shall be configured at the reverse proxy or load balancer layer, the framework layer, and within parsing code. Multiple layers prevent a single misconfiguration from allowing unbounded input.

For binary inputs (uploads), see the File Handling guideline. For text inputs, limits shall reflect the data model: usernames of 1000 characters serve no purpose.

For structured inputs (JSON, XML, YAML), depth limits and array size limits shall be enforced by the parser configuration.

### Algorithmic Complexity

Operations whose complexity depends on input shall have a known worst-case bound. Operations with super-linear complexity in user-controlled input shall be reviewed: regex matching, sort operations on user-supplied keys, deserialization of user-supplied structures, graph traversal of user-supplied graphs.

Hash collision attacks (CWE-407) shall be mitigated by using hash maps with randomized hash seeds. Most modern languages and stdlib hash maps randomize by default; verify.

Regular expressions shall be reviewed for catastrophic backtracking. Patterns with nested quantifiers (`(a+)+`, `(a|a)*`) shall be replaced with linear-time equivalents (possessive quantifiers, atomic groups, or rewritten patterns). Use linear-time regex engines (RE2, Hyperscan, Rust's `regex` crate) for any regex on untrusted input where the engine is selectable.

### Decompression and Expansion

Compressed inputs shall have decompressed size bounded. A zip bomb expands a small input to gigabytes; cap the decompressed size and entry count.

XML expansion attacks (billion laughs) shall be prevented by disabling DTD processing and entity expansion in XML parsers.

JSON, YAML, and protobuf decoded sizes shall be bounded similarly.

### Timeouts

Every I/O operation shall have a timeout: HTTP client requests, database queries, downstream service calls, lock acquisitions, queue dequeues. Infinite waits cause cascading failure.

Server-side request timeouts shall be enforced. A client connecting and sending one byte every 30 seconds (Slowloris) shall be terminated.

Concurrent request budget per connection shall be bounded for HTTP/2 (`MAX_CONCURRENT_STREAMS`).

### Connection and Thread Limits

Maximum concurrent connections, threads, and file descriptors shall be configured. The application shall reject new work rather than spawn unbounded threads.

For thread pool exhaustion, separate pools for different work types (`fail-fast`-friendly bulkheading) prevent slow operations from blocking fast ones.

For database connections, connection pool size shall be tuned to the database's capacity divided by the number of application instances.

### Backpressure

Async or message-driven architectures shall implement backpressure. Producers shall slow when consumers cannot keep up. Unbounded queues are an anti-pattern.

For HTTP services, return 503 Service Unavailable with `Retry-After` when overloaded. Load shedding is preferable to cascading failure.

### Downstream Cascade

Calls to downstream services shall use circuit breakers. After a documented number of failures, the circuit opens and requests fail fast rather than wait for timeouts. Half-open state allows probe requests after a recovery interval.

Retry logic shall include exponential backoff and jitter. Synchronized retries from many clients (thundering herd) can prevent recovery; jitter desynchronizes.

Bulkheading: separate connection pools, thread pools, and resource pools per downstream dependency. A failure in one downstream shall not exhaust resources used for another.

### Cache Considerations

Caches reduce load but introduce their own DoS vectors. Cache stampede (many requests racing to refresh a cold entry) can amplify load on the origin; mitigate with lock-on-write or staggered refresh.

Negative caching (caching the fact that an object does not exist) defends against pathological lookup patterns.

### Resource Quotas

Per-tenant quotas shall be enforced for multi-tenant systems. CPU, memory, storage, and request rate quotas prevent one tenant from impacting others.

## 4. Language-Specific Guidance

### 4.1 Java

Configure timeouts on `RestTemplate`, `WebClient`, and HTTP clients:

~~~java
HttpClient.newBuilder()
    .connectTimeout(Duration.ofSeconds(5))
    .build();
HttpRequest.newBuilder(uri)
    .timeout(Duration.ofSeconds(30))
    .build();
~~~

For Tomcat (Spring Boot embedded), set `server.tomcat.max-connections`, `max-threads`, `connection-timeout`, and `max-swallow-size`.

For JSON parsing limits with Jackson, configure `StreamReadConstraints` (Jackson 2.15+):

~~~java
ObjectMapper mapper = JsonMapper.builder()
    .streamReadConstraints(StreamReadConstraints.builder()
        .maxNestingDepth(50)
        .maxStringLength(1_000_000)
        .build())
    .build();
~~~

For circuit breakers, Resilience4j provides `CircuitBreaker`, `RateLimiter`, `Bulkhead`, and `TimeLimiter` decorators.

For regex on untrusted input, consider `re2j` (Google's RE2 port) instead of `java.util.regex` to avoid catastrophic backtracking.

### 4.2 Python

For HTTP, always set timeouts:

~~~python
httpx.get(url, timeout=httpx.Timeout(5.0, read=30.0, connect=5.0))
requests.get(url, timeout=(5, 30))  # (connect, read)
~~~

Never call `requests.get(url)` without a timeout — the default is no timeout.

For Django/Flask/FastAPI, set request body size limits in the framework and the proxy.

For regex, `re` is backtracking-based and vulnerable. Use Google's `re2` (`pip install google-re2`) for untrusted patterns or untrusted inputs against complex patterns.

For circuit breakers, `pybreaker` or `circuitbreaker` libraries. For async, `aiocircuitbreaker`.

For asyncio, use `asyncio.wait_for` with explicit timeouts on all awaits that could block.

### 4.3 C

Configure timeouts on all sockets: `SO_RCVTIMEO`, `SO_SNDTIMEO`, or `poll`/`select` with timeout.

For libcurl, set `CURLOPT_CONNECTTIMEOUT` and `CURLOPT_TIMEOUT` per the SSRF guideline.

For regex, prefer `re2` (C++ library with C bindings) over POSIX regex or PCRE for untrusted inputs. PCRE2 has JIT and backtracking control flags (`PCRE2_MATCH_HEURISTIC_LIMIT_BACKTRACKING`-style); configure if PCRE2 must be used.

Use `setrlimit` to bound process resources: `RLIMIT_CPU`, `RLIMIT_AS`, `RLIMIT_NOFILE`, `RLIMIT_NPROC`.

For decompression, use `inflate`/`deflate` with explicit output buffer caps. Reject when output exceeds cap.

### 4.4 C++

The C guidance applies. Use C++ wrappers (Boost.Asio with deadline timers, cpp-httplib with `set_read_timeout`).

For regex, prefer RE2 (C++) over `std::regex` for untrusted patterns. `std::regex` is backtracking-based and slow.

Use `std::stop_token` (C++20) for cooperative cancellation of long-running operations.

For thread pools, prefer `std::async` with `std::launch::async` only when bounded; for unbounded work, use a pool library (Boost.Asio thread pool, folly) with explicit size.

## 5. Verification

Load testing shall reach and exceed expected production traffic. Chaos engineering shall introduce downstream failure, latency, and resource pressure. Regex inventory shall be reviewed; patterns operating on untrusted input shall be tested for catastrophic backtracking with tools like ReDoSHunter. Decompression and parser limits shall be tested with crafted inputs. Penetration testing shall include slow client attacks, deeply nested inputs, large inputs at all size limits, and algorithmic complexity attacks.

## 6. References

- OWASP ASVS v4.0.3, V11.1
- OWASP API Security Top 10, API4
- NIST SP 800-53 Rev. 5, SC-5
- CWE-400, CWE-409, CWE-1333, CWE-407, CWE-770
- OWASP Regular Expression Denial of Service - ReDoS
- Release It! by Michael Nygard (patterns: circuit breaker, bulkhead, timeout, backpressure)
