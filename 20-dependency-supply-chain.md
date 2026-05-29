# Secure Coding Guidelines: Dependency and Supply Chain Security

## 1. Purpose and Scope

This section establishes requirements for managing third-party dependencies and protecting the software supply chain. Modern applications consist largely of third-party code; vulnerabilities and malicious packages in dependencies are now a primary attack vector. This guideline covers dependency selection, version management, vulnerability monitoring, and protection against typosquatting and dependency confusion.

These guidelines map to OWASP ASVS V14 (Configuration), OWASP Top 10 2021 A06 (Vulnerable and Outdated Components) and A08, PCI DSS 4.0 Requirement 6.3.2, NIST SP 800-218 (SSDF), Executive Order 14028, SLSA framework, and CWE-1104 (Use of Unmaintained Third-Party Components), CWE-1357 (Reliance on Insufficiently Trustworthy Component).

## 2. General Principles

Every dependency is a security decision. Adding a dependency adds its code, its maintainers' code, its transitive dependencies, and the risk that any of them may be compromised. The set of dependencies shall be minimized to those that provide substantial value.

Dependency provenance shall be verifiable. Lockfiles, integrity hashes, and signature verification shall ensure that the dependencies used at build time are the ones intended.

Vulnerabilities in dependencies shall be discovered promptly and remediated on a documented timeline aligned with severity.

## 3. Normative Requirements

### Dependency Selection

New dependencies shall be evaluated before adoption:

- Maintenance status: active commits, recent releases, responsive issue handling.
- Security history: published vulnerabilities, response times.
- License compatibility with the project's license obligations.
- Author and organization reputation.
- Transitive dependency tree: each addition may bring many.
- Alternatives: prefer broadly-used, well-funded libraries over niche ones.

Dependencies on packages with a single maintainer for security-critical functionality warrant extra scrutiny. Dependencies on packages with fewer than approximately 100 downloads per week or no recent releases shall be reviewed quarterly for replacement.

### Version Pinning

Lockfiles shall be committed to the repository: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, `requirements.txt` with pinned versions, `pom.xml` (with explicit versions, no ranges), `Cargo.lock`, `go.sum`.

Lockfiles shall include integrity hashes (`integrity` for npm, `sha256` for Pipfile.lock, equivalents in others). Builds shall verify hashes against the lockfile.

Dependency ranges without lockfiles are prohibited for production code. Floating versions (`^1.0.0`, `~1.0.0`, `latest`, `*`) without a lockfile produce non-reproducible builds.

### Vulnerability Scanning

Software Composition Analysis (SCA) shall run continuously: on every pull request, on a periodic schedule against the main branch, and on tagged releases. Tools include `npm audit`, `pip-audit`, `cargo audit`, `govulncheck`, `dependabot`, `renovate`, `snyk`, `mend`, `trivy`.

Vulnerability response shall follow a documented SLA based on severity:

- Critical (CVSS 9.0+): patch or mitigate within 7 days.
- High (CVSS 7.0–8.9): patch or mitigate within 30 days.
- Medium (CVSS 4.0–6.9): patch or mitigate within 90 days.
- Low: address on next regular update cycle.

These intervals are baselines; regulatory requirements (PCI DSS, others) may impose stricter timelines.

Active exploitation (CISA KEV catalog) accelerates the response. CISA KEV-listed vulnerabilities shall be remediated immediately regardless of CVSS.

### Provenance and Integrity

Dependencies shall be fetched from authoritative sources: npm registry (registry.npmjs.org), PyPI (pypi.org), Maven Central, RubyGems, crates.io, Go module proxy. Mirrors are acceptable only if they cryptographically verify origin.

Internal artifacts shall be published to a private registry with access control. Internal package names shall not collide with public namespace; configure the package manager to refuse public lookups for internal scopes (dependency confusion defense).

For npm, configure scoped packages (`@org/name`) and ensure the scope resolves only to the private registry.

For Python, use `--index-url` with a private index. Tools like `pip-audit` and `bandersnatch` can mirror PyPI; consider for highest-assurance environments.

For Maven, configure repositories with `<repository>` blocks in `pom.xml` and authentication in `settings.xml`. Use `<mirrors>` to force internal proxy resolution.

Where the toolchain supports it, verify signatures (Sigstore, PGP). Sigstore-based attestation (cosign) is becoming standard; adopt for new infrastructure.

### Typosquatting Defense

New dependencies shall be added through code review. The reviewer shall verify the package name against the intended package (`requests` vs `request`, `numpy` vs `numpi`, `lodash` vs `lodahs`).

Automated checks shall warn on new dependencies that closely match popular package names. Several SCA tools provide this signal.

### Transitive Dependencies

The transitive dependency graph shall be visible. Lockfiles record the full graph; review changes to the graph in PRs, not just direct dependency changes.

Pin transitive dependencies where security-critical via the package manager's override mechanism (`overrides` in npm, `dependency_overrides` in Pubspec, `resolutions` in Yarn, `--upgrade-package` patterns in pip).

### Deprecation and End-of-Life

Dependencies that reach end-of-life shall be replaced or forked-and-maintained. Continued use of unmaintained dependencies for security-critical functionality is prohibited.

A quarterly review shall identify dependencies approaching EOL and plan migration.

## 4. Language-Specific Guidance

### 4.1 Java

For Maven, declare versions explicitly. Use `dependencyManagement` to centralize transitive versions. Enable `enforce` plugin rules to forbid SNAPSHOT and range versions:

~~~xml
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-enforcer-plugin</artifactId>
    <executions>
        <execution>
            <goals><goal>enforce</goal></goals>
            <configuration>
                <rules>
                    <requireUpperBoundDeps/>
                    <bannedDependencies>
                        <excludes>
                            <exclude>*:*:*:*:*-SNAPSHOT</exclude>
                        </excludes>
                    </bannedDependencies>
                </rules>
            </configuration>
        </execution>
    </executions>
</plugin>
~~~

For Gradle, use the version catalog and dependency locking (`gradle dependencies --write-locks`). Enable verification metadata for hashes and signatures.

Run OWASP Dependency-Check, Snyk, or Trivy in CI. For high-assurance projects, also run `Gradle/Maven` repository verification.

For private artifacts, use Sonatype Nexus or JFrog Artifactory with namespace allocation policies preventing public-package shadowing.

### 4.2 Python

Use `uv`, `poetry`, or `pip-tools` to manage dependencies and lockfiles. `requirements.txt` alone is acceptable if it is generated from a source list with pinned versions and hashes (`pip-compile --generate-hashes`):

~~~
# requirements.txt
requests==2.31.0 \
    --hash=sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f \
    --hash=sha256:942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1
~~~

Install with `pip install -r requirements.txt --require-hashes` to enforce.

Run `pip-audit` in CI. Dependabot or Renovate for automated updates.

For private packages, host on a private PyPI (devpi, jfrog, AWS CodeArtifact, Azure Artifacts). Configure `pip` and `uv` with `--index-url` and `--extra-index-url` carefully; misordered indexes are a dependency-confusion vector.

### 4.3 C

C dependency management is fragmented. Common approaches:

- System packages (`apt`, `yum`, `apk`): track distribution security advisories.
- Vendored sources: commit dependency source to the repository or a submodule. Document version, source URL, and patches applied.
- Package managers (`vcpkg`, `conan`): use lockfiles where supported, scan with the package manager's audit features.

For vendored dependencies, document the update process. Vulnerability tracking is manual; subscribe to oss-security and project-specific channels.

For system packages, use distribution-provided security tracking (Ubuntu USN, Red Hat RHSA, Alpine SecDB).

### 4.4 C++

The C guidance applies. For modern C++ projects, prefer `vcpkg` or `conan` over vendored sources. Both maintain version-pinned lockfiles.

Run `cargo-audit`-equivalent tools where available; the C++ SCA ecosystem is less mature than other languages but `trivy`, `grype`, and SBOM-based scanners cover common cases.

For header-only libraries vendored into the project, include the upstream version in a comment and check the upstream advisory feed.

## 5. Verification

SCA tools shall run on every PR and shall block merges introducing high-severity vulnerabilities. Lockfile integrity shall be verified in CI. Dependency budget metrics (count, age, EOL status) shall be reported per release. Dependency review meetings shall occur quarterly. Penetration testing shall include dependency confusion tests against internal namespaces.

## 6. References

- OWASP ASVS v4.0.3, V14
- OWASP Top 10 2021, A06, A08
- OWASP Dependency Check, Dependency Track projects
- PCI DSS v4.0, Requirement 6.3.2
- NIST SP 800-218 (SSDF), tasks PW.4 and PW.6
- Executive Order 14028
- SLSA framework (slsa.dev)
- CISA Known Exploited Vulnerabilities catalog
- CWE-1104, CWE-1357
