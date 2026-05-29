# Secure Coding Guidelines: Security Testing (SAST, DAST, IAST, SCA)

## 1. Purpose and Scope

This section establishes requirements for security testing throughout the development lifecycle. Security testing combines static analysis of source code, dynamic testing of running applications, instrumentation-based interactive analysis, and dependency scanning. No single technique covers all vulnerability classes; layered testing is the practical approach.

These guidelines map to OWASP ASVS V14 (Configuration) and the verification levels overall, NIST SP 800-218 (SSDF) tasks PW.7, PW.8, and RV, PCI DSS 4.0 Requirements 6.3.2 and 11, and the OWASP Web Security Testing Guide.

## 2. General Principles

Security testing complements but does not replace secure design and secure implementation. A pipeline that finds every bug late is worse than one that prevents bugs.

Tooling matters less than coverage and triage discipline. A well-tuned commodity scanner with prompt finding triage outperforms a state-of-the-art scanner whose output is ignored.

Findings shall be tracked from discovery through remediation. A finding that disappears from the report without resolution is a future incident.

## 3. Normative Requirements

### Static Application Security Testing (SAST)

SAST shall run on every pull request and on the main branch on a continuous or scheduled basis. PR scans block merge on new high-severity findings.

The SAST tool shall be tuned to the project's languages and frameworks. Rules shall be updated when new languages or frameworks are adopted.

False positives shall be triaged and suppressed with documented justification. A scanner whose suppressions are unjustified loses value.

Custom rules shall be added for organization-specific patterns: prohibited functions, mandatory authorization annotations, log redaction patterns.

### Dynamic Application Security Testing (DAST)

DAST shall run against a deployed instance of the application — staging environments are typical. DAST coverage is bounded by what the scanner can reach: authenticate the scanner where possible, provide it with an API spec for systematic coverage.

DAST runs may be scheduled (weekly, monthly) for full crawls and on-demand for PR-specific testing of changed features.

DAST findings shall be confirmed before remediation begins. Automated DAST has high false positive rates; manual confirmation distinguishes findings from noise.

### Interactive Application Security Testing (IAST)

IAST instruments the running application to combine code visibility (like SAST) with runtime visibility (like DAST). Where the deployment supports it, IAST in staging or QA environments produces lower-false-positive findings than DAST alone.

IAST agents introduce overhead and shall not be deployed to production except with explicit approval.

### Software Composition Analysis (SCA)

SCA covers dependency vulnerabilities and is addressed in the Dependency and Supply Chain Security guideline.

### Fuzzing

Code that parses untrusted input shall be fuzzed. Coverage-guided fuzzers (libFuzzer, AFL++, Jazzer for JVM, atheris for Python, cargo-fuzz for Rust) are most effective.

Fuzz targets shall be maintained alongside the code, like unit tests. They shall run in CI (short runs per build) and as scheduled longer-duration jobs.

Crashes and findings from fuzzing shall be triaged like other bugs. Crash-only findings often have security implications even when they appear to be reliability issues.

### Penetration Testing

Penetration testing by qualified internal or external testers shall occur:

- Before initial production release of a significant new application.
- Annually for production applications in scope.
- After major architectural changes.

Penetration testing scope shall include the threat model's high-priority concerns. Authenticated testing covers more than unauthenticated; provide test credentials.

Findings shall be tracked through remediation. Retest findings to confirm fixes.

### Security Unit and Integration Tests

Security-sensitive behavior shall have automated tests like other behavior. Authorization, input validation, output encoding, and other security controls shall have tests that fail when the control is removed or broken.

Tests written from a misuse perspective (negative tests, evil user stories) complement positive tests.

### Bug Bounty and External Reporting

Public-facing applications shall have a documented vulnerability disclosure channel per the Vulnerability Disclosure guideline. For some applications, a bug bounty program adds incentive for external researchers.

Bug bounty findings shall flow into the same intake as other security findings.

### Findings Management

A single system shall hold security findings from all sources: SAST, DAST, IAST, SCA, fuzzing, pentest, bug bounty, incident review. Duplicate findings across sources shall be deduplicated.

Findings shall have: source, severity, asset, status, owner, target date, remediation notes.

SLA for remediation shall match severity per the Dependency guideline (Critical: 7 days, High: 30 days, etc.). CISA KEV-listed issues are immediate.

Metrics on findings — time to detection, time to remediation, false positive rate, repeat findings — shall be tracked and reviewed quarterly.

### Test Environment Security

Test environments running production-like data shall have production-like security controls. Test environments are a common path for attackers to gather information about production.

Production data in test environments shall be sanitized or replaced with synthetic data. PII in test environments is an exposure.

Scanner credentials and test accounts shall be controlled. A scanner account with broad permissions is itself a target.

## 4. Language-Specific Guidance

### 4.1 Java

For SAST, SpotBugs with FindSecBugs, SonarQube with security rules, Semgrep, CodeQL, Checkmarx, Veracode, Snyk Code. SpotBugs + FindSecBugs is the open-source baseline.

For fuzzing, Jazzer (libFuzzer for JVM). Define fuzz targets in test code:

~~~java
public class ParserFuzzTest {
    @FuzzTest
    void parse(byte[] data) {
        try { MyParser.parse(data); }
        catch (ParserException ignored) {}
    }
}
~~~

For DAST, OWASP ZAP, Burp Suite, Acunetix.

For dependency scanning, OWASP Dependency-Check, Snyk, Sonatype Nexus IQ.

### 4.2 Python

For SAST, Bandit (Python-specific), Semgrep with Python rules, CodeQL.

For type checking that catches some security-relevant bugs, mypy or pyright with strict modes.

For fuzzing, Atheris (Python wrapping libFuzzer) or Hypothesis for property-based testing:

~~~python
@given(st.binary())
def test_parse_doesnt_crash(data):
    try: parse(data)
    except ParseError: pass
~~~

For SCA, pip-audit, safety, Snyk, Dependabot.

For dynamic, OWASP ZAP automation in CI.

### 4.3 C

For SAST, the open-source toolchain produces substantial value:

- `clang-tidy` with security checks
- `clang-analyzer` (Clang Static Analyzer)
- `cppcheck`
- `Flawfinder` for legacy unsafe API use
- `Coverity`, `PVS-Studio`, `CodeQL` (commercial / source-available)

For runtime, sanitizers under CI: AddressSanitizer, UBSan, MSan, TSan. Each on a separate build.

For fuzzing, libFuzzer (integrated with clang `-fsanitize=fuzzer`), AFL++, honggfuzz. Define fuzz harnesses for every parser.

For dynamic, run the application under Valgrind in integration tests for leak detection.

### 4.4 C++

The C guidance applies. Additionally:

- `clang-tidy` with C++ Core Guidelines checks
- `include-what-you-use` for hygiene
- `cppcheck` with `--enable=warning,style,performance,portability`
- `iwyu`

C++ specific: review use of `reinterpret_cast`, `const_cast`, raw pointer manipulation, manual memory management — these are the spots where memory safety bugs concentrate.

## 5. Verification

Test coverage shall be a release metric. The percentage of code reached by SAST, DAST, and tests with security assertions shall be tracked. Tool effectiveness shall be evaluated periodically — purple team exercises and retrospective analysis of incidents that bypassed testing inform tuning. Penetration test reports shall be reviewed at the management level. Annual security testing strategy review shall assess whether the testing program addresses the threats identified in threat modeling.

## 6. References

- OWASP ASVS v4.0.3
- OWASP Web Security Testing Guide
- NIST SP 800-218 (SSDF) tasks PW.7, PW.8, RV
- PCI DSS v4.0, Requirements 6.3.2, 11
- OWASP CI/CD Security
- Building Security In Maturity Model (BSIMM)
