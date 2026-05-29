# Secure Coding Guidelines: Container and Image Security

## 1. Purpose and Scope

This section establishes requirements for building, distributing, and running container images. Containers are the predominant deployment unit; their security depends on image construction practices, runtime configuration, and the integrity of the registry pipeline.

These guidelines map to NIST SP 800-190 (Application Container Security Guide), CIS Docker Benchmark, CIS Kubernetes Benchmark, OWASP Docker Top 10, and the Pod Security Standards.

## 2. General Principles

A container image is a build artifact. The Build, CI/CD, and Release Integrity guideline applies in full: signed, reproducible, accompanied by SBOM and provenance.

Container runtime security is layered on the host: kernel isolation features, runtime constraints (capabilities, seccomp, AppArmor/SELinux), network policy, and orchestrator policy (Pod Security Admission). The application image is one of several layers; weak isolation at any layer undermines the others.

## 3. Normative Requirements

### Image Construction

Base images shall be from trusted sources: official distribution images, vendor images, or organization-maintained base images. Random images from Docker Hub are prohibited.

Base images shall be minimal. Distroless, Alpine, or `scratch` are preferred for production over general-purpose images. The image shall contain only the binaries required to run the application; package managers, shells, and debug tools are unnecessary in production.

Base images shall be pinned by digest, not tag. `FROM ubuntu:22.04` is mutable; `FROM ubuntu@sha256:abcd...` is immutable.

The image shall not run as root. Define a non-root user explicitly:

~~~dockerfile
FROM alpine:3.20
RUN adduser -D -u 10001 app
USER app
~~~

The application's working files shall be owned by the non-root user. The image shall not include sudo, setuid binaries, or capabilities not required.

Secrets shall not be embedded in images. Multi-stage builds shall not leak secrets from build stages. ARG and ENV values shall not contain secrets.

Image layers shall be ordered for cacheability: rarely-changing layers first (system packages, application dependencies), frequently-changing layers last (application code). This is operationally important and also reduces the blast radius of a compromised intermediate base image.

### Image Scanning

Images shall be scanned for vulnerabilities before promotion to production. `trivy`, `grype`, `clair`, `snyk`, or equivalent SCA tools shall run on every image build.

Vulnerability response shall follow the SLA defined in the Dependency and Supply Chain guideline. Critical and KEV-listed vulnerabilities shall block deployment.

Images shall be scanned periodically after deployment. New CVEs may apply to already-deployed images; trigger rebuilds and rollouts on critical findings.

Image scanning shall include base image OS packages, application dependencies, and embedded binaries.

### Image Signing

Production images shall be signed. Sigstore Cosign with keyless signing is the current standard:

~~~
cosign sign $IMAGE
cosign attest --predicate sbom.json --type cyclonedx $IMAGE
~~~

Deployment systems shall verify signatures. Kubernetes admission controllers (Kyverno, OPA Gatekeeper with cosign verification, Sigstore Policy Controller) shall enforce signature verification.

### Registry Security

Registry access shall be authenticated. Anonymous pulls from internal registries are prohibited.

Registry credentials shall be scoped: build robots have push access to their own namespaces, deployment robots have pull access to deployment namespaces, developers have read-only access for inspection.

Image immutability shall be enforced where possible: registries that support immutable tags shall be configured to disallow overwriting.

Periodic registry cleanup shall remove unreferenced images per a documented retention policy.

### Runtime Configuration

Containers shall run with the minimum capability set. Drop all capabilities and add only those required:

~~~yaml
securityContext:
  capabilities:
    drop: ["ALL"]
  runAsNonRoot: true
  runAsUser: 10001
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  seccompProfile:
    type: RuntimeDefault
~~~

`privileged: true` is prohibited except for documented infrastructure components.

Host namespaces (hostPID, hostNetwork, hostIPC) shall not be shared with application containers.

Host paths shall not be mounted into application containers. ConfigMaps, Secrets, and projected volumes provide the equivalent functionality without exposing host filesystem.

Resource limits (CPU, memory) shall be set on every container to prevent resource exhaustion attacks affecting co-tenants.

### Network Policy

Network policy shall default to deny and explicitly allow required traffic. Default-allow in a multi-tenant cluster is a misconfiguration.

For Kubernetes, NetworkPolicy resources or service mesh policies (Istio AuthorizationPolicy, Linkerd policies) shall be applied.

East-west traffic between services in the cluster shall use mTLS where the threat model warrants. Service mesh provides this transparently.

### Pod Security Standards

Production namespaces shall enforce the Pod Security Standards `restricted` profile. Workloads requiring exceptions shall document and justify them.

`baseline` is the minimum for any namespace; `privileged` shall be limited to system components in dedicated namespaces.

### Secrets

Secrets shall be loaded per the Secrets Management guideline. Kubernetes Secrets stored in etcd are base64-encoded, not encrypted by default; enable encryption at rest (`EncryptionConfiguration`) and prefer external secrets operators (External Secrets Operator, CSI Secret Store) backed by a proper secrets manager.

Secrets shall not be passed via environment variables when files are an option, because environment variables appear in process listings and crash dumps.

### Multi-Tenancy

In multi-tenant clusters (multiple teams, multiple applications), namespaces shall be the isolation boundary, augmented by network policy, RBAC, and resource quotas.

Highest-sensitivity workloads (PCI scope, regulated workloads) shall run in dedicated clusters or use stronger isolation (Kata Containers, gVisor) where co-residency is unacceptable.

## 4. Language-Specific Guidance

### 4.1 Java

Use a slim or distroless JRE image:

~~~dockerfile
FROM eclipse-temurin:21-jre-alpine
RUN adduser -D -u 10001 app
USER app
WORKDIR /app
COPY --chown=app:app target/app.jar app.jar
ENTRYPOINT ["java", "-jar", "app.jar"]
~~~

For production, prefer `gcr.io/distroless/java21-debian12` which contains only the JRE.

Use jlink to produce a custom runtime image with only required modules, reducing attack surface:

~~~
jlink --add-modules java.base,java.logging,java.net.http --output /opt/jre-min
~~~

GraalVM native-image produces a single binary with no JVM at all; consider for security-critical services where the tradeoffs are acceptable.

### 4.2 Python

Use a slim or distroless Python image:

~~~dockerfile
FROM python:3.12-slim AS builder
RUN pip install --no-cache-dir --user -r requirements.txt --require-hashes

FROM gcr.io/distroless/python3-debian12
COPY --from=builder /root/.local /home/app/.local
COPY --chown=10001:10001 app/ /app/
USER 10001
ENTRYPOINT ["python", "/app/main.py"]
~~~

Do not run `pip install` in the production stage; do it in a build stage and copy only the installed packages.

For applications served by a WSGI/ASGI server, run the server as the non-root user. Avoid `--workers` configurations that spawn root child processes.

### 4.3 C

C applications producing container images benefit most from `FROM scratch` or `gcr.io/distroless/static`. Statically link or include only the required shared libraries:

~~~dockerfile
FROM debian:bookworm AS builder
RUN apt-get update && apt-get install -y build-essential
COPY . /src
RUN cd /src && make static

FROM gcr.io/distroless/static-debian12
COPY --from=builder /src/app /app
USER 65532
ENTRYPOINT ["/app"]
~~~

Static linking simplifies the image but complicates security update tracking; document the static dependencies in the SBOM.

### 4.4 C++

The C guidance applies. For C++ applications, ensure the C++ standard library is either statically linked or present in the runtime image. `gcr.io/distroless/cc-debian12` includes glibc and libstdc++.

For C++ applications using dynamic linking, run `ldd` against the binary to confirm all required libraries are in the image and pin those library versions in the SBOM.

## 5. Verification

Image scanning shall block production deployment of images with critical findings. Pod Security Standards enforcement shall be tested with workloads designed to violate them. Network policies shall be tested with scenario-based traffic. Signature verification shall be tested in admission control. Compliance against CIS Docker and CIS Kubernetes Benchmarks shall be assessed quarterly with `kube-bench`, `docker-bench-security`, or equivalent. Runtime security monitoring (Falco, Tetragon) shall alert on container escapes and policy violations.

## 6. References

- NIST SP 800-190 (Application Container Security Guide)
- CIS Docker Benchmark, CIS Kubernetes Benchmark
- OWASP Docker Top 10
- Kubernetes Pod Security Standards
- Sigstore Cosign documentation
- Trivy, Grype documentation
