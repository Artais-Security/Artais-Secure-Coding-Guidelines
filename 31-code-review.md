# Secure Coding Guidelines: Code Review for Security

## 1. Purpose and Scope

This section establishes requirements for security-focused code review. Code review is the highest-bandwidth quality control in software development; for security, it complements automated tooling by catching design flaws, contextual issues, and patterns that scanners miss.

These guidelines map to NIST SP 800-218 (SSDF) task PW.7, OWASP Code Review Guide, PCI DSS 4.0 Requirement 6.3.2, and ISO/IEC 27034 (Application Security).

## 2. General Principles

Every change to production code shall be reviewed. The reviewer shall be a different engineer than the author, with sufficient context to evaluate the change.

Security is one dimension of code review along with correctness, performance, maintainability, and style. Reviewers shall consider security implications without making it the only criterion; security is most effective when integrated, not bolted on.

Reviewers are accountable for what they approve. Approving without reading is a discipline issue. Time pressure is not a justification.

## 3. Normative Requirements

### Reviewer Coverage

Every PR shall have at least one approving reviewer who did not author the change. Two reviewers shall be required for:

- Changes to security-sensitive code (authentication, authorization, cryptography, session handling)
- Changes to deployment pipelines and infrastructure code
- Changes affecting compliance-scoped systems (PCI, HIPAA, etc.)
- Changes proposed by external contributors or new team members

CODEOWNERS files (or equivalent) shall designate review responsibility for security-sensitive paths.

### Reviewer Qualifications

Reviewers shall have sufficient context to evaluate the change. Reviewing code in an unfamiliar codebase or domain without orientation is not effective.

Reviewers shall be trained on common security patterns and anti-patterns for the languages and frameworks in use. The organization shall provide periodic training.

### PR Hygiene

PRs shall be appropriately sized. Large PRs receive worse review than small PRs; a PR exceeding several hundred lines (excluding generated code, vendored sources, and bulk renames) shall typically be split.

PRs shall include description: what changes, why, and how to verify. Reviewers should not need to reverse-engineer the intent.

Tests and documentation shall accompany functional changes. A PR adding a feature without tests is incomplete.

CI checks shall pass before review effort is invested. Asking reviewers to look at broken code wastes their time.

### Review Focus

For security, reviewers shall consider:

- **Authentication and authorization**: Is the change reachable without authentication that should be required? Does it correctly check authorization on the resources it operates on? Does it introduce new endpoints needing controls?

- **Input handling**: Where does data enter? Is it validated? Is it appropriately encoded at output? Are there new injection sinks (SQL, shell, file paths, URLs)?

- **Secrets and credentials**: Hardcoded values? Secrets in test fixtures that might leak? Logging that might include credentials?

- **Cryptography**: New cryptographic operations using vetted libraries and approved algorithms? Key management appropriate?

- **Error handling**: Failures producing safe states? Stack traces not leaking to clients? Resources cleaned up on error paths?

- **Logging**: Sensitive data redacted? Sufficient context for incident response?

- **Dependencies**: New dependencies justified, reviewed, pinned with lockfile updates?

- **Configuration**: New configuration with safe defaults? Documentation updated?

- **Tests**: Security-relevant behavior covered by automated tests?

- **Concurrency**: Shared state correctly synchronized? Race conditions in security-relevant decisions?

Reviewers shall apply the threat model when relevant. Changes to elements identified in the threat model warrant heightened attention.

### Comments and Discussion

Comments shall be specific and actionable. "This is wrong" is not useful; "This concatenates user input into a SQL query, allowing injection — use a parameterized query" is.

Disagreements shall be resolved before merge. Where author and reviewer cannot agree, escalation to a senior engineer or architect is the path, not deadlock or override.

Suggestions versus blockers shall be distinguished. "nit:" or "optional:" prefixes signal preferences that don't block merge; absent prefix is a blocker.

### Approval and Merge

Reviewers shall not approve their own changes. Self-approval defeats the purpose of review.

Branch protection shall enforce review requirements at the version control system level. Procedures relying on convention are bypassed.

Merge to protected branches shall be via PR. Direct pushes shall be prohibited.

### Post-Merge

Findings from production incidents shall be reviewed against the PRs that introduced the affected code. The point is process improvement, not blame; if review missed a class of issue, the team learns to look for it.

PR templates shall be updated based on lessons learned.

### Automated Review Augmentation

Automated PR checks reduce reviewer load:

- SAST results visible in PR
- Coverage delta visible in PR
- Dependency changes flagged
- Migration changes flagged
- License changes flagged
- Configuration changes summarized

Reviewers shall verify automated checks are not silenced or bypassed without justification.

## 4. Language-Specific Reviewer Focus

While the general principles are language-agnostic, certain patterns deserve attention by language:

### 4.1 Java

- New `Statement` or `prepareStatement` with concatenation — should be parameterized
- New `ObjectInputStream.readObject` on untrusted data
- `@PreAuthorize` missing on new controller methods
- `SecureRandom` vs `Random` for security purposes
- Disabled certificate verification in HTTP clients
- New dependencies in `pom.xml` or `build.gradle`
- Logging that includes object `toString()` of entities with sensitive fields
- `try`-without-`catch` patterns that might leak exceptions to clients
- Unsafe reflection (`Class.forName` on user input)

### 4.2 Python

- `subprocess` calls with `shell=True`
- `eval`, `exec`, `compile` with non-constant inputs
- `pickle.loads`, `yaml.load` (without SafeLoader), `marshal.loads`
- `requests.get` without `timeout`, `verify=False`
- SQL strings using `%`, `.format()`, or f-strings with user input
- New `@app.route` without authentication decorator
- New Django views or DRF viewsets without permission checks
- Type annotations missing on security-sensitive functions

### 4.3 C

- New `strcpy`, `strcat`, `sprintf`, `gets`, `scanf("%s")` — typically defects
- Allocation followed by unchecked use
- Integer arithmetic on sizes without overflow checks
- `system()`, `popen()` with constructed strings
- New thread creation without corresponding synchronization
- File operations using path-based APIs where fd-based exists (`access` + `open`, `stat` + `open`)
- New mutex without matching destroy
- Conditional compilation that may exclude security checks

### 4.4 C++

C concerns apply. Additionally:

- New raw `new`/`delete` (should typically be smart pointers)
- `reinterpret_cast`, `const_cast` outside C-API boundaries
- Throwing destructors (UB risk)
- Move-from-then-use patterns
- Iterator invalidation in concurrent code
- Custom allocators on containers holding sensitive data (zeroization?)
- New `extern "C"` boundaries — exception propagation correctly contained?

## 5. Verification

Review compliance shall be a build-time check via branch protection. Review quality shall be assessed via periodic sampling: senior engineers re-review approved PRs to identify missed issues. Code review training shall be refreshed annually. Retrospectives following incidents shall include "did review catch this?" as a standard question. Metrics on review (time-to-first-review, time-to-merge, review depth as inferred from comment density) shall be tracked, with awareness that gaming these metrics is easy.

## 6. References

- NIST SP 800-218 (SSDF) task PW.7
- OWASP Code Review Guide
- PCI DSS v4.0, Requirement 6.3.2
- ISO/IEC 27034
- Google Engineering Practices documentation on code review
