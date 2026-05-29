# Artais Secure Coding Guidelines

A reference set of secure coding guidelines maintained by [Artais Security](https://github.com/Artais-Security). Each section is a self-contained markdown document covering a single domain of secure software development, with mappings to relevant standards (OWASP ASVS, OWASP Top 10, PCI DSS 4.0, HIPAA, NIST SP 800-53, NIST SSDF, CWE) and concrete language-specific guidance for Java, Python, C, and C++.

These guidelines are intended for use by engineering teams as a normative reference, by code reviewers as a checklist, and by security architects as input to project-specific secure development plans.

## Scope and Intent

Every guideline in this repository follows the same shape:

- **Purpose and scope** — what the guideline covers and which standards it satisfies.
- **General principles** — the threat model and design posture for the domain.
- **Normative requirements** — what must, should, and shall not be done.
- **Language-specific guidance** — concrete Java, Python, C, and C++ examples.
- **Verification** — how compliance is checked (static analysis, review, runtime).
- **References** — the standards mapped to the section.

The guidelines are written to be opinionated where the standards permit a choice, and explicit where the standards mandate behavior. They are not a substitute for a formal compliance assessment, but they are designed so that an application built to these guidelines will satisfy the corresponding controls in the listed regimes.

## Status

| # | Guideline | Status |
|---|---|---|
| 01 | [Application Logging](./01-application-logging.md) | ✅ Done |
| 02 | Input Validation and Output Encoding | ⬜ TODO |
| 03 | Authentication | ⬜ TODO |
| 04 | Session Management | ⬜ TODO |
| 05 | Access Control and Authorization | ⬜ TODO |
| 06 | Cryptography and Key Management | ⬜ TODO |
| 07 | Secrets Management | ⬜ TODO |
| 08 | Error and Exception Handling | ⬜ TODO |
| 09 | Data Protection (At Rest and In Transit) | ⬜ TODO |
| 10 | Database Access and Query Construction | ⬜ TODO |
| 11 | File Handling and Uploads | ⬜ TODO |
| 12 | Memory Management and Safe Concurrency | ⬜ TODO |
| 13 | API Security (REST, GraphQL, gRPC) | ⬜ TODO |
| 14 | Web Application Security Headers | ⬜ TODO |
| 15 | Cookies and Browser Storage | ⬜ TODO |
| 16 | Cross-Origin Resource Sharing (CORS) | ⬜ TODO |
| 17 | Content Security Policy (CSP) | ⬜ TODO |
| 18 | Server-Side Request Forgery (SSRF) Prevention | ⬜ TODO |
| 19 | Deserialization and Object Injection | ⬜ TODO |
| 20 | Dependency and Supply Chain Security | ⬜ TODO |
| 21 | Software Bill of Materials (SBOM) | ⬜ TODO |
| 22 | Build, CI/CD, and Release Integrity | ⬜ TODO |
| 23 | Container and Image Security | ⬜ TODO |
| 24 | Infrastructure as Code (IaC) Security | ⬜ TODO |
| 25 | Cloud Configuration and IAM | ⬜ TODO |
| 26 | Secure Defaults and Configuration Management | ⬜ TODO |
| 27 | Rate Limiting, Quotas, and Abuse Prevention | ⬜ TODO |
| 28 | Denial of Service Resilience | ⬜ TODO |
| 29 | Threat Modeling Practice | ⬜ TODO |
| 30 | Security Testing (SAST, DAST, IAST, SCA) | ⬜ TODO |
| 31 | Code Review for Security | ⬜ TODO |
| 32 | Vulnerability Disclosure and Patch Management | ⬜ TODO |
| 33 | Incident Response Hooks in Application Code | ⬜ TODO |
| 34 | Privacy by Design (GDPR, CCPA) | ⬜ TODO |
| 35 | Mobile Application Security | ⬜ TODO |
| 36 | LLM and AI Integration Security | ⬜ TODO |

Open items are tracked on the project board. Contributions and proposed sections are welcome via pull request.

## Standards Mapped

The guidelines collectively map to the following frameworks. Individual sections cite the specific controls and requirements that apply.

- OWASP ASVS v4.0.3
- OWASP Top 10 2021 (and 2025 as published)
- OWASP API Security Top 10
- OWASP Mobile Top 10 / MASVS
- OWASP LLM Top 10
- PCI DSS 4.0
- HIPAA Security Rule (45 CFR §164.308–§164.312)
- NIST SP 800-53 Rev. 5
- NIST SP 800-218 (SSDF)
- NIST SP 800-92 (Log Management)
- NIST Cybersecurity Framework 2.0
- CWE Top 25 / SANS Top 25
- CERT Secure Coding Standards (C, C++, Java)
- CIS Controls v8
- ISO/IEC 27001 / 27002 / 27034
- SOC 2 Trust Services Criteria
- GDPR (Article 25, Data Protection by Design)

## How to Use This Repository

For engineering teams, these documents serve as the normative reference for new development. New services are expected to be built against the applicable guidelines from day one. Each guideline includes a verification section describing how compliance is checked.

For code reviewers, the language-specific sections of each guideline can be used directly as a review checklist. Pull requests should be evaluated against the requirements that apply to the touched code.

For security architects, the guidelines are the input to project-specific Secure Development Plans. The standards mappings make it straightforward to demonstrate coverage for audits and assessments.

## Tooling

Several of these guidelines are supported by tools in the broader Artais toolkit:

- [`artais-cookie-cop`](https://github.com/Artais-Security) — cookie security auditing
- Security headers, CORS, CSP, threat modeling, and entropy analysis tools

Additional tools are planned to provide CI-friendly enforcement of these guidelines (static checks for prohibited logging patterns, dependency and SBOM analysis, IaC misconfiguration scanning).

## Contributing

Contributions follow the structure described in [CONTRIBUTING.md](./CONTRIBUTING.md) (forthcoming). Proposed new sections should include the same six-part structure as existing guidelines and must cite the standards they map to.

## License

See [LICENSE](./LICENSE).
