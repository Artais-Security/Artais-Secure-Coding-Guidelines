# Secure Coding Guidelines: API Security (REST, GraphQL, gRPC)

## 1. Purpose and Scope

This section establishes requirements for designing and implementing application programming interfaces — REST, GraphQL, gRPC, and WebSocket — exposed by applications developed or maintained by Artais Security. APIs are increasingly the primary attack surface for modern applications; the OWASP API Security Top 10 enumerates classes of failure specific to API design and implementation.

These guidelines map to OWASP API Security Top 10 (2023), OWASP ASVS V13 (API and Web Service), PCI DSS 4.0 Requirement 6.2, and CWE-285, CWE-639 (Authorization Bypass Through User-Controlled Key), CWE-770 (Resource Allocation Without Limits), CWE-915 (Mass Assignment).

## 2. General Principles

APIs are first-class application surface. The same authentication, authorization, validation, encoding, logging, error handling, and rate limiting requirements that apply to web applications apply to APIs, with additional requirements specific to machine-to-machine interaction patterns.

API contracts shall be defined explicitly: OpenAPI/Swagger for REST, the schema for GraphQL, .proto for gRPC. Contracts shall be the source of truth for input validation, output shape, and version compatibility.

Backward-compatible changes shall be preferred. Breaking changes shall require explicit version transitions with deprecation notices and sunset timelines.

## 3. Normative Requirements

### Authentication and Authorization

Every API endpoint shall require authentication unless explicitly designated as public. Default-deny applies at the endpoint registration level: an endpoint without an authentication decorator/configuration shall be rejected at build time.

Object-level authorization (BOLA, OWASP API1) shall be enforced on every endpoint that operates on user-owned resources. Per the Access Control guideline, fetch the resource, verify ownership or permission, then act.

Function-level authorization (BFLA, OWASP API5) shall be enforced separately. An authenticated user shall not be able to invoke endpoints reserved for higher-privilege users. Administrative endpoints shall be on documented paths and shall verify role explicitly.

For bearer tokens, validate the token's signature, expiration, issuer, and audience on every request. Cache validation results within the request to avoid repeated cryptographic operations.

### Input Validation

All inputs shall be validated per the Input Validation guideline. Validation shall match the API contract: required fields present, types correct, ranges enforced, enums constrained.

Mass assignment (OWASP API6) shall be prevented. The set of fields acceptable from the client shall be explicitly enumerated; binding directly to ORM entities from request bodies is prohibited. Use explicit DTOs.

Property-level filtering shall be applied to output. Internal fields (timestamps, soft-delete flags, owner IDs unrelated to the requester) shall not be returned unless explicitly intended.

### Resource Limits and Rate Limiting

Rate limiting shall be applied per the Rate Limiting guideline. Per-user, per-IP, and per-endpoint limits shall be configured.

Pagination shall be required for any endpoint returning a collection. Maximum page size shall be enforced. Cursor-based pagination is preferred for large datasets.

Maximum request body size shall be enforced per the File Handling guideline.

For GraphQL, query complexity analysis and depth limits shall be configured. Reject queries exceeding complexity or depth thresholds.

### Versioning

API version shall be in the URL path (`/v1/`), the `Accept` header, or a documented mechanism. Mixing versions in a single client is acceptable; mixing versions in a single request is not.

Deprecated endpoints shall return a `Deprecation` header per RFC 9745 and a `Sunset` header per RFC 8594.

### Error Handling

Error responses shall use the framework's standard format (Problem Details for HTTP per RFC 9457, gRPC status codes, GraphQL `errors` array). Internal details shall not be exposed per the Error Handling guideline.

HTTP status codes shall be used semantically: 400 for client errors, 401 for unauthenticated, 403 for unauthorized, 404 for missing or unreadable, 409 for conflict, 422 for validation failure, 429 for rate limit, 5xx for server errors. Returning 200 with an error payload is prohibited.

### CORS, Headers, Cookies

For browser-facing APIs, CORS shall be configured per the CORS guideline. Security headers per the Web Application Security Headers guideline shall apply.

For APIs not intended for browser use, CORS shall be configured to deny rather than permit-all.

### Documentation

The API contract shall be published. For public APIs, documentation shall be accessible. For internal APIs, documentation shall be accessible to authorized developers. Documentation shall not expose internal-only endpoints.

OpenAPI specs shall be validated against the implementation in CI; drift between spec and implementation shall be a build failure.

## 4. Language-Specific Guidance

### 4.1 Java

For Spring Boot REST APIs, use `@RestController` with explicit `@RequestMapping`. Validate request bodies with `@Valid` on Bean Validation–annotated DTOs. Authorize with `@PreAuthorize` per the Access Control guideline.

For OpenAPI, use `springdoc-openapi` to generate the spec from controller annotations. Validate the spec in CI with `openapi-generator` and contract tests.

For GraphQL, use Spring for GraphQL or DGS. Configure `MaxQueryComplexityInstrumentation` and `MaxQueryDepthInstrumentation`. Disable introspection in production for non-public APIs.

For gRPC, use grpc-java with interceptors for authentication, authorization, logging, and rate limiting. Define services in .proto and generate stubs; do not modify generated code.

Disable Spring's default error attributes (per Error Handling guideline) and provide a `@ControllerAdvice` returning Problem Details:

~~~java
@ExceptionHandler(NotFoundException.class)
public ResponseEntity<ProblemDetail> handle(NotFoundException e) {
    var pd = ProblemDetail.forStatusAndDetail(NOT_FOUND, "resource not found");
    return ResponseEntity.status(NOT_FOUND).body(pd);
}
~~~

### 4.2 Python

For FastAPI, define request and response models with Pydantic. Use `response_model` on path operations to filter output:

~~~python
@app.get("/users/{user_id}", response_model=UserPublic)
def get_user(user_id: UUID, current: User = Depends(get_current_user)):
    user = require_authorized(current, "user:read", user_id)
    return user  # response_model strips fields not in UserPublic
~~~

For Django REST Framework, use serializers with explicit `fields` lists. Avoid `fields = '__all__'` on user-facing serializers. Use separate serializers for input and output where the shapes differ.

For Flask, use Marshmallow or Pydantic for validation and serialization. Flask-Smorest provides OpenAPI generation with Marshmallow.

For GraphQL, use Strawberry or Ariadne. Implement complexity and depth limits via plugins. Disable introspection in production for non-public APIs.

For gRPC, use grpcio with interceptors per the framework documentation. Validate inputs with protovalidate.

For rate limiting, slowapi (FastAPI/Starlette) or django-ratelimit. Back with Redis for distributed enforcement.

### 4.3 C

C is uncommon for new API development. When used (high-performance services, embedded HTTP servers), choose a framework that provides routing, header parsing, and TLS termination: libmicrohttpd, mongoose, or h2o.

Input validation is fully manual; follow the Input Validation guideline strictly. Use a vetted JSON parser (`json-c`, `jansson`, `cJSON` with care) with depth and size limits configured.

For authentication, implement bearer token validation with libsodium or OpenSSL. Cache validated tokens with a TTL to avoid repeat cryptographic work.

Generate OpenAPI specs by hand or with a separate documentation pipeline; keep them in sync with code via contract tests.

### 4.4 C++

For HTTP/REST in C++, use Pistache, Crow, Drogon, or cpp-httplib. Each provides routing and middleware hooks. Drogon includes ORM integration; the others are leaner.

For gRPC, grpc-cpp is mature. Define services in .proto; do not modify generated code. Use interceptors for cross-cutting concerns.

For JSON, use nlohmann/json or RapidJSON. Validate against a JSON schema with `valijson` or generate validators from OpenAPI.

For OpenAPI generation, use `openapi-generator` with the cpp-restsdk template or document the API in a separate file maintained alongside the implementation.

Use a request context object that carries authenticated principal, request ID, and other cross-cutting state; pass it explicitly to handlers to make authorization decisions testable.

## 5. Verification

OpenAPI specifications shall be validated against implementations in CI. Contract tests shall cover representative request/response pairs. API fuzzing with tools such as RESTler, Schemathesis, or ZAP API scanner shall be performed periodically. Authorization testing per the Access Control guideline shall cover every endpoint. Rate limit configuration shall be tested. Penetration testing shall include the OWASP API Security Top 10 categories explicitly.

## 6. References

- OWASP API Security Top 10 (2023)
- OWASP ASVS v4.0.3, V13
- OWASP REST Security Cheat Sheet
- OWASP GraphQL Cheat Sheet
- PCI DSS v4.0, Requirement 6.2
- CWE-285, CWE-639, CWE-770, CWE-915
- RFC 9457 (Problem Details for HTTP), RFC 8594 (Sunset), RFC 9745 (Deprecation)
