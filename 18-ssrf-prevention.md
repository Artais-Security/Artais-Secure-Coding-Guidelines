# Secure Coding Guidelines: Server-Side Request Forgery (SSRF) Prevention

## 1. Purpose and Scope

This section establishes requirements for preventing Server-Side Request Forgery in applications that make outbound HTTP or other network requests. SSRF allows attackers to use a vulnerable server as a proxy to reach internal services, cloud metadata endpoints, or to scan internal networks. SSRF has been the initial access vector for several high-impact breaches.

These guidelines map to OWASP ASVS V12.6 (SSRF Protection), OWASP Top 10 2021 A10 (Server-Side Request Forgery), and CWE-918 (Server-Side Request Forgery).

## 2. General Principles

Any application code that makes a network request to a URL derived from user input is a potential SSRF source. This includes obvious cases (URL fetching, webhook delivery, link preview generation) and subtle cases (XML external entity processing, PDF rendering, server-side image processing, OpenID Connect discovery, SAML metadata fetching).

The defense is layered: validate the target before resolution, validate after resolution, restrict network egress at the host or container, and avoid making requests to user-supplied URLs at all where possible.

## 3. Normative Requirements

### Architectural Defenses

Where the application's purpose does not require fetching arbitrary user-supplied URLs, do not implement the feature. Where it does (webhook delivery, link previews), isolate the fetching component into a separate service with restricted network access.

Outbound network traffic from application services shall be restricted at the network layer. Egress firewall rules or cloud security groups shall deny outbound connections to:

- The cloud metadata service IP (169.254.169.254 on AWS, GCP, Azure; equivalent on others).
- Private RFC 1918 address space (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) except where specifically required.
- Link-local addresses (169.254.0.0/16, fe80::/10).
- Loopback (127.0.0.0/8, ::1).
- Cloud-specific internal ranges.

Outbound traffic shall be allowed only to specifically required destinations, on the protocols and ports required.

### Input Validation

URLs from user input shall be parsed with a vetted URL parser before validation. The parsed components (scheme, host, port, path) shall be validated:

- Scheme: allowlist (`http`, `https`). Reject `file`, `gopher`, `dict`, `ftp`, `ldap`, `jar`, custom schemes, and `javascript`.
- Host: resolve and check against denylist after resolution.
- Port: allowlist (typically 80 and 443).

Host validation shall account for:

- DNS rebinding: validate before resolution and again after, or use a resolver that returns the same IP for the entire request lifetime.
- IPv4 representations: decimal, hex, octal, integer (`http://2130706433` for 127.0.0.1). Parse and canonicalize.
- IPv6 representations: full and compressed forms, IPv4-mapped (`::ffff:127.0.0.1`), and IPv4-compatible. Canonicalize and check.
- URL parsing differences: ambiguous URLs may be parsed differently by validation code and the HTTP client. Use the same library for both.

### Resolution and Connection Control

Use an HTTP client that allows custom connection-time validation, so the application can re-check the resolved IP just before connecting. The cycle of validate-resolve-connect can be defeated by DNS rebinding if the resolution between validate and connect changes; "pin" the resolved IP and use it for the connection.

Disable HTTP redirects, or validate redirect targets recursively. An attacker may supply a URL that resolves to an allowed host but redirects to a forbidden one.

Set connection timeouts and total request timeouts to bound the impact of unresponsive or slow targets.

Disable plaintext HTTP downgrade. If the request is to `https://`, do not follow redirects to `http://`.

### Cloud Metadata Endpoints

Application code shall not access the cloud metadata endpoint directly. Where the application needs credentials, it shall use the cloud provider's SDK, which handles metadata access correctly and supports IMDSv2 (AWS) and equivalent secured access.

On AWS, IMDSv2 shall be enforced at the instance level (require session token). This prevents many SSRF-to-credential-theft attacks even if application-level SSRF protection fails.

### XXE and Server-Side Parsers

XML parsers, JSON Schema validators (`$ref`), and other formats that support external references shall be configured to disable external entity resolution. Per the Input Validation guideline.

PDF, SVG, and document conversion libraries may make outbound requests during processing. Configure them to disable external fetches, or run them in network-isolated containers.

## 4. Language-Specific Guidance

### 4.1 Java

For HTTP clients, use the platform `HttpClient` or Apache HttpClient 5 with a custom `DnsResolver` that pins resolved addresses for the request lifetime.

For URL validation:

~~~java
URI uri = URI.create(input);
if (!Set.of("http", "https").contains(uri.getScheme())) throw new IllegalArgumentException();

InetAddress[] addrs = InetAddress.getAllByName(uri.getHost());
for (InetAddress a : addrs) {
    if (a.isLoopbackAddress() || a.isLinkLocalAddress() || a.isSiteLocalAddress() ||
        a.isAnyLocalAddress() || a.isMulticastAddress()) {
        throw new SecurityException("forbidden target");
    }
    // also check cloud metadata IPs explicitly
}
~~~

Use the resolved address to construct the request (`InetSocketAddress` + custom client config), not the original hostname, to prevent DNS rebinding.

Disable XML external entities on `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, and `TransformerFactory` per the OWASP XXE Prevention Cheat Sheet.

### 4.2 Python

For HTTP, use `requests` with care or `httpx` with custom transport. Both follow redirects by default; disable or validate:

~~~python
resp = httpx.get(url, follow_redirects=False, timeout=5.0)
~~~

For URL validation, use `urllib.parse` plus `ipaddress`:

~~~python
import ipaddress, socket
from urllib.parse import urlparse

def validate_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("scheme")
    host = parsed.hostname
    if host is None:
        raise ValueError("host")
    for family, _, _, _, sockaddr in socket.getaddrinfo(host, None):
        addr = ipaddress.ip_address(sockaddr[0])
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
            raise ValueError("target forbidden")
        if str(addr) in ("169.254.169.254", "fd00:ec2::254"):
            raise ValueError("metadata")
    return url
~~~

For higher assurance, use a library like `safeurl` or wrap a custom socket creation function that re-checks the connected peer.

For XML/JSON parsing, use `defusedxml` and configure JSON Schema validators to disable `$ref` resolution to URLs.

### 4.3 C

For C, use libcurl with explicit configuration:

~~~c
curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);  // or validate manually
curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
~~~

For address validation, use `getaddrinfo` and check each returned address against the denylist. Resolve once and use `CURLOPT_RESOLVE` to bind the connection to the validated address, preventing DNS rebinding.

Do not implement HTTP redirect following manually; if needed, validate each redirect target through the full validation pipeline.

### 4.4 C++

Use libcurl with a C++ wrapper (cpp-httplib for clients, or curlpp). Apply the libcurl configuration above.

Encapsulate the validation logic in a `SafeUrlFetcher` class so that no other code path can issue outbound requests without going through validation.

For asynchronous frameworks (Boost.Asio with Beast), wrap the resolver to perform validation and pin addresses.

## 5. Verification

Static analysis shall flag HTTP client construction without validation in code paths that receive user input. Penetration testing shall include SSRF attempts against all features that accept URLs or content references, including indirect surfaces (XML, JSON Schema, PDF rendering, image fetching). Network egress controls shall be tested by attempting forbidden connections from application hosts. Cloud metadata access shall be specifically tested.

## 6. References

- OWASP ASVS v4.0.3, V12.6
- OWASP Top 10 2021, A10
- OWASP SSRF Prevention Cheat Sheet
- CWE-918
- AWS IMDSv2 documentation
