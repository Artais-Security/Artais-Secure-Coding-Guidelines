# Secure Coding Guidelines: Build, CI/CD, and Release Integrity

## 1. Purpose and Scope

This section establishes requirements for securing the build, continuous integration, continuous delivery, and release process. The build pipeline produces the artifacts that run in production; compromise of the pipeline is equivalent to compromise of production. Recent supply chain incidents (SolarWinds, Codecov, GitHub Actions abuses) have made pipeline integrity a board-level concern.

These guidelines map to NIST SP 800-218 (SSDF) tasks PO, PS, PW, and RV, SLSA framework requirements, OWASP Top 10 CI/CD Security Risks, Executive Order 14028, and CWE-829 (Inclusion of Functionality from Untrusted Control Sphere).

## 2. General Principles

The build pipeline is part of the production system. The same controls applied to production hosts and applications shall apply to the build pipeline: access control, change management, monitoring, vulnerability management, secret protection.

Builds shall be reproducible from source. A given commit shall produce the same artifact regardless of when or where the build runs, modulo timestamps and other unavoidable variation.

Provenance — the record of how an artifact was built — shall be captured, signed, and verifiable. Consumers of artifacts shall be able to confirm the artifact came from the expected source commit through the expected pipeline.

## 3. Normative Requirements

### Source Integrity

The source code repository shall be the single source of truth for code. Builds shall consume only the repository contents and declared dependencies; ad-hoc files injected at build time are prohibited.

Branch protection shall be configured on the main branch: require pull requests, require approving review from a code owner, require status checks, dismiss stale reviews on new commits, restrict who can push. Force pushes and history rewrites on protected branches shall be prohibited.

Commits to protected branches shall be signed (GPG, SSH, or Sigstore). Unsigned commits shall be rejected by branch protection or detected and remediated.

### Build Environment

Build runners shall be ephemeral. A build shall start from a clean environment and that environment shall be destroyed after the build. Persistent build hosts accumulate compromise; ephemeral hosts reset the attack surface per build.

Build runners shall be hardened. The host OS shall be minimal, kept current, and monitored. Network access shall be restricted to the destinations the build legitimately requires (package registries, artifact repositories).

Build runners shall not be exposed to untrusted code in privileged contexts. Pull request builds from forks shall use a separate, lower-privilege runner that cannot access secrets used for releases.

### Pipeline Configuration

Pipeline definitions shall be in code (`.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`, etc.) and shall be reviewed like application code. Changes to pipelines shall require approval from designated reviewers.

Third-party actions, plugins, and steps shall be pinned to specific commits (not tags or branches) and shall be reviewed before adoption. `actions/checkout@v4` is acceptable for organization-trusted actions; arbitrary third-party actions shall be pinned by SHA.

Secrets used in builds shall be scoped to the minimum jobs and steps that need them. Pull request and fork builds shall not have access to release secrets.

`pull_request_target` (GitHub Actions) and similar privileged-context triggers shall be used only with documented review of the security implications.

### Artifact Production

Artifacts shall be reproducible. Sources of nondeterminism (timestamps, embedded paths, random data) shall be eliminated or documented. Reproducibility shall be tested periodically.

Artifacts shall be signed by the build system. Signing keys shall live in an HSM or KMS, not in the build environment as files. Sigstore keyless signing is the current preferred mechanism.

SBOMs and provenance attestations shall accompany artifacts per the SBOM guideline.

### Release Process

Production deployments shall use signed, attested artifacts. Deployment systems shall verify signatures and provenance before deploying.

Rollback procedures shall be documented and tested. Rolling back to a previous artifact shall be possible without a new build.

Emergency change procedures shall exist for production hotfixes but shall require post-incident review and shall maintain the same provenance and signing requirements.

### SLSA Levels

The organization shall target a specific SLSA level for each application category:

- SLSA Level 1: provenance produced.
- SLSA Level 2: provenance authenticated, hosted build service.
- SLSA Level 3: source and build platform meet additional requirements (isolation, non-falsifiable provenance).
- SLSA Level 4 (now Build Track Level 4): two-party review, hermetic builds.

Document the target level per system and the gap analysis.

### Secrets in Builds

Secrets shall be loaded from a secrets manager into the build runner via short-lived credentials. Long-lived secrets in CI environment variables are discouraged; prefer OIDC federation with cloud providers.

Secrets shall not be printed to build logs. CI platforms typically mask known secrets but only if the secrets manager is configured. Build scripts shall not `echo`, `cat`, or otherwise emit secret values.

### Monitoring

Build pipeline activity shall be logged: who triggered builds, what changed, what was published. Logs shall be retained per the Application Logging guideline.

Anomaly detection shall apply to the pipeline: unusual job invocations, new external dependencies, modified pipeline definitions, off-hours builds, builds from unusual locations.

## 4. Language-Specific Guidance

### 4.1 Java

For Maven builds, use the Maven Wrapper (`mvnw`) committed to the repo to ensure consistent Maven version. Pin plugin versions in `pluginManagement`. Configure repository checksums.

For Gradle, use the Gradle Wrapper with `distributionSha256Sum` in `gradle-wrapper.properties`. Enable dependency verification (`gradle --write-verification-metadata sha256`).

For signing, use Sigstore Cosign or Maven's GPG plugin. Publish signatures with artifacts.

For deployment, ensure the deployment automation verifies the GPG signature or Sigstore attestation before promoting to production.

### 4.2 Python

Use lockfiles with hashes per the Dependency guideline. Build wheels reproducibly with `SOURCE_DATE_EPOCH`:

~~~
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
python -m build --wheel
~~~

Sign with Sigstore (`sigstore-python`) and publish to a private index with attestations.

For Docker images, use a deterministic builder (BuildKit) with reproducible options. Pin the Python base image by digest.

### 4.3 C

C builds are often the least reproducible due to embedded timestamps, build paths, and compiler version variation. Address each:

- Use `-ffile-prefix-map` and `-fdebug-prefix-map` to strip build paths.
- Set `SOURCE_DATE_EPOCH` for embedded timestamps.
- Pin compiler version and standard library version.
- Use deterministic archive tools (`ar D` flag).

Run `diffoscope` between two independent builds to identify non-determinism sources.

For signing, sign the produced binaries or packages (dpkg-sig, rpmsign, signify). Distribute signatures with artifacts.

### 4.4 C++

The C guidance applies. C++ builds add concerns around template instantiation order (typically deterministic but can vary), link-time optimization (LTO) determinism, and ABI variance across compiler versions.

For large C++ projects, ccache and sccache improve build performance; configure for reproducibility by setting `--hash-dir` to a stable value and pinning compiler.

## 5. Verification

Pipeline definitions shall be reviewed at every change. SLSA compliance shall be assessed annually. Reproducibility shall be tested periodically by performing independent builds and comparing artifacts. Build logs shall be sampled for secret leakage. Signing and verification shall be tested end-to-end on each release. Penetration testing scope shall include the CI/CD environment.

## 6. References

- NIST SP 800-218 (SSDF) tasks PO, PS, PW, RV
- SLSA framework (slsa.dev)
- OWASP Top 10 CI/CD Security Risks
- Executive Order 14028
- Sigstore documentation
- Reproducible Builds project (reproducible-builds.org)
- CWE-829, CWE-494
