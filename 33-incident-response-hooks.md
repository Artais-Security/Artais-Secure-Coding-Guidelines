# Secure Coding Guidelines: Incident Response Hooks in Application Code

## 1. Purpose and Scope

This section establishes requirements for the application-level capabilities that support security incident response. Incident response is a process owned by the security operations function, but the application code shall provide the affordances that make response possible: forensic visibility, kill switches, evidence preservation, and rapid mitigation deployment.

These guidelines map to NIST SP 800-61 (Computer Security Incident Handling Guide), NIST SP 800-53 IR family, PCI DSS 4.0 Requirement 12.10, HIPAA §164.308(a)(6), and the OWASP Incident Response Cheat Sheet.

## 2. General Principles

The application shall be operable under attack. Response actions — invalidating sessions, blocking IP ranges, disabling features, rotating credentials — shall be possible without code deployment for time-critical mitigation.

Incident response affordances are designed before they are needed. Building them under pressure during an incident produces ineffective controls.

The application shall produce the evidence that response and post-incident investigation require, per the Application Logging guideline. This section adds requirements specific to active incidents.

## 3. Normative Requirements

### Kill Switches and Feature Flags

Security-relevant feature flags shall exist for:

- Disabling specific endpoints (e.g., file upload, registration, password reset)
- Disabling specific external integrations
- Enabling stricter rate limits or maintenance mode
- Forcing logout of all users (mass session invalidation)
- Rotating signing keys for tokens
- Blocking specific IP ranges or ASNs at the application layer (complementing WAF)

Flags shall be toggleable without code deployment. The flag-management system shall require authentication and shall log toggles to the audit trail.

Flag effects shall be testable in staging before production use.

### Session Invalidation

The application shall support immediate invalidation of all sessions for a user, a group of users, or all users. Implementation depends on session model:

- Server-side sessions: delete from the session store.
- JWT-based: add tokens or principals to a revocation list with TTL.
- Cookie-based with rotating signing keys: rotate the signing key to invalidate all existing tokens.

The invalidation shall be effective within seconds, not minutes. Cached authentication decisions shall respect invalidation.

### Credential and Key Rotation

The application shall support rotation of:

- Service account credentials
- API keys
- Cryptographic signing keys
- Encryption keys protecting data (with re-encryption capability)
- Database passwords (with credential refresh in connection pools)

Rotation shall be tested periodically by forcing a rotation in production and verifying continued operation.

Multiple key versions shall be supported during rotation. Old keys shall be retained for the necessary period (token TTL for signing keys, indefinite for encrypted data unless re-encrypted).

### Audit and Evidence

The application shall log evidence at the granularity required for post-incident investigation:

- Authentication events (success and failure) per the Application Logging guideline
- Authorization decisions for sensitive resources
- Administrative actions
- Data access for regulated data
- Configuration changes
- Error events
- Security-relevant feature flag toggles

Logs shall be tamper-evident or stored in append-only systems (per the Logging guideline). Forensic analysis requires confidence that logs reflect what happened.

Application metrics shall include security-relevant indicators: authentication failure rate, authorization denial rate, error rate by class, request volume by client, secret access frequency.

### Forensic Snapshots

For applications handling sensitive data, the deployment platform shall support taking snapshots of running instances for forensic analysis without disrupting operation. This is typically a platform capability (EBS snapshot, VM snapshot, persistent disk snapshot) but the application architecture shall be compatible.

Memory captures may be required for advanced analysis. Operating system support (volatility-compatible tools) and policy (when to capture, who can capture) shall be documented.

### Communication Channels

The application shall expose a status mechanism (status page, in-app banner) that the response team can update during an incident to inform users.

For applications with user-facing components, in-app communication may be required to instruct users (rotate credentials, log out and back in, take other action).

### Containment

The application shall support containment actions:

- Quarantining suspect user accounts (preserved but locked)
- Quarantining suspect data records (preserved but inaccessible)
- Restricting permissions of compromised service accounts
- Rolling back to known-good state where feasible

Containment shall preserve evidence. Deleting suspect accounts is poor incident response; locking with preservation is correct.

### Runbook Integration

Common response actions shall be documented in runbooks accessible to the on-call security responder. Runbooks shall be tested in tabletop exercises.

Runbooks shall reference the application's specific controls. Generic runbooks ("respond to credential compromise") shall reference application-specific procedures ("to rotate service account X in application Y, run the following command...").

### Tabletop and Game Day Exercises

Incident response shall be practiced. Tabletop exercises (discussion-based scenarios) shall occur quarterly. Game day exercises (live drills, in some cases involving real production with controlled blast radius) shall occur annually.

Findings from exercises shall produce engineering work to improve the application's response affordances.

### Post-Incident

After an incident, the application's role in the incident shall be reviewed:

- Were detection signals adequate?
- Did containment actions work as expected?
- Was evidence preserved?
- Did runbooks match the actual situation?
- What application-level controls would have prevented or mitigated?

The retrospective shall produce engineering work. Findings without action items repeat as future incidents.

## 4. Implementation Patterns

This guideline is largely architectural; per-language guidance is less specific than other sections. Common patterns:

### 4.1 Configuration-Driven Response

A control plane (database table, key-value store, feature flag service) holds runtime configuration. The application consults the configuration with low latency (typically cached with short TTL) on each request or session.

Changes to the configuration propagate without deployment. The configuration shall be authenticated and authorized; unauthorized writes are themselves an incident.

### 4.2 Allowlist and Denylist

Per-IP, per-user, per-API-key allowlists and denylists shall be supported. The application consults them as early in the request as practical.

For high-volume services, in-memory caches of denylists with short TTLs reduce latency overhead. The cache TTL bounds how stale the denylist can be during an incident.

### 4.3 Circuit Breaker for Compromised Dependencies

When a dependency is suspected of compromise, the application shall be able to fail closed: stop calling the dependency, return safe degraded responses, or stop the affected feature entirely.

The circuit-breaker pattern from the DoS Resilience guideline applies: manual trip during an incident, automatic detection when integrated with monitoring.

### 4.4 Just-in-Time Privilege

Administrative actions in the application shall require just-in-time elevation, with logging. During an incident, the response team's elevations are particularly important to track for both action audit and future review.

### 4.5 Honeytokens

For applications with high security stakes, honeytokens — credentials, records, or files that appear legitimate but are designed to be triggered — provide detection of unauthorized access. The application shall be designed to ignore the honeytokens during normal operation while a monitoring system alerts on their use.

## 5. Verification

Kill switches and feature flags shall be tested in staging on a documented cadence. Credential rotation shall be exercised. Session invalidation shall be tested. Tabletop exercises shall be scored against documented criteria. Annual review shall assess whether the application's incident response affordances match the threat model. Incidents and near-misses shall be reviewed for response-effectiveness lessons.

## 6. References

- NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide)
- NIST SP 800-53 Rev. 5, IR control family
- PCI DSS v4.0, Requirement 12.10
- HIPAA Security Rule, 45 CFR §164.308(a)(6)
- OWASP Incident Response Cheat Sheet
- SANS Incident Response process
