# Secure Coding Guidelines: Infrastructure as Code (IaC) Security

## 1. Purpose and Scope

This section establishes requirements for the secure development and operation of Infrastructure as Code: Terraform, OpenTofu, Pulumi, AWS CloudFormation, Azure Bicep/ARM, Google Cloud Deployment Manager, Ansible, Helm charts, and Kubernetes manifests. IaC is the substrate of modern infrastructure; a misconfigured IaC template propagates the misconfiguration at scale.

These guidelines map to NIST SP 800-53 CM (Configuration Management) controls, CIS Benchmarks for the target platforms, and the OWASP Top 10 CI/CD risks intersection with infrastructure.

## 2. General Principles

IaC is code. The Code Review, Secrets Management, Build, and Logging guidelines apply. IaC repositories shall be subject to the same access control, branch protection, and review requirements as application source.

Drift between IaC and deployed reality undermines the guarantees of IaC. Out-of-band changes shall be either eliminated by access control or reconciled promptly.

Defaults in cloud provider services are often insecure (publicly accessible storage, unencrypted disks, open security groups). IaC shall set secure values explicitly rather than rely on defaults.

## 3. Normative Requirements

### Repository and Review

IaC shall live in version control with the same protections as application code: branch protection, required reviews, signed commits, CI checks.

Changes affecting security-sensitive resources (IAM policies, network controls, encryption configuration, public exposure) shall require review from a designated security reviewer in addition to the standard reviewer.

Module versions shall be pinned. Terraform modules referenced from registries or git shall use specific versions or commit SHAs, never `latest` or floating refs.

### State Management

Terraform state files contain secrets and infrastructure details. State shall be stored in an encrypted backend (S3 with KMS, GCS with CMEK, Azure Storage with CMK, Terraform Cloud). Local state in repositories is prohibited.

State backend access shall be authenticated and authorized. State locking shall be enabled (DynamoDB, GCS native locking, Terraform Cloud) to prevent concurrent modification.

State backups shall be retained per disaster recovery requirements.

### Secrets in IaC

Secrets shall not appear in IaC source or state files where avoidable. Reference secrets from a secrets manager:

~~~hcl
data "aws_secretsmanager_secret_version" "db" {
  secret_id = "prod/db/password"
}
resource "aws_db_instance" "main" {
  password = data.aws_secretsmanager_secret_version.db.secret_string
  # ...
}
~~~

Even with secrets manager references, the resolved secret may appear in state. Mark sensitive variables and use the provider's `sensitive` mechanism.

For Kubernetes Secrets in Helm, use SealedSecrets, SOPS, or External Secrets Operator. Plain YAML Secrets in Git are prohibited.

### Static Analysis

IaC shall be scanned for misconfigurations in CI: `tfsec`, `checkov`, `terrascan`, `kube-linter`, `kubesec`, `trivy config`. Findings above a documented severity shall block merge.

Custom organizational policies shall be added to the scanner configuration: required tags, allowed regions, mandatory encryption, prohibited resource types.

### Plan Review

`terraform plan` (or equivalent) shall run in CI on every PR and the output shall be visible to reviewers. The plan reveals what will change; review based on the plan, not only on the source diff.

Apply shall be gated on PR approval and shall run in a controlled environment, not on developer machines.

### Cloud Account Configuration

Cloud accounts shall follow the Cloud Configuration and IAM guideline: minimal root account use, organization-wide guardrails (AWS Organizations SCPs, GCP Organization Policies, Azure Policy), CloudTrail/CloudAudit logging enabled, region restrictions if applicable.

Production accounts shall be separate from development accounts. Production IaC shall not have credentials for development resources and vice versa.

### Network Defaults

Network resources shall default to closed:

- Security groups, firewalls, NSGs shall have explicit allow rules and shall not contain `0.0.0.0/0` ingress on management ports (SSH, RDP, database ports) without documented exception.
- VPCs shall not have public subnets unless required; database tiers shall be in private subnets.
- Storage buckets shall block public access at the account level (S3 Block Public Access, GCS Uniform Bucket-Level Access, Azure Storage public access disabled).

### Encryption Defaults

Storage shall be encrypted at rest. Database instances, disks, object storage, message queues, and cache layers shall have encryption enabled in IaC with customer-managed keys where the threat model warrants.

TLS shall be required on services that support it: ALB/NLB with TLS listeners only, RDS with `rds.force_ssl`, S3 bucket policies requiring `aws:SecureTransport`.

### Tagging and Labeling

Resources shall be tagged with owner, application, environment, data classification, and cost center. Tagging policies shall be enforced (AWS Tag Policies, GCP labels with constraints).

Tags drive automated security response: data-classification tags determine encryption requirements, environment tags determine access controls, owner tags determine notification on findings.

### Logging and Monitoring

CloudTrail, Cloud Audit Logs, or Azure Activity Logs shall be enabled across all regions and accounts. Logs shall be centralized to a security-controlled account.

VPC Flow Logs (or equivalent) shall be enabled for production VPCs.

Security monitoring tools (AWS GuardDuty, Azure Defender, GCP Security Command Center) shall be enabled and findings routed to the security team.

### Module Reuse

Internal modules encapsulating secure defaults shall be developed and used in preference to defining resources directly. A `secure_s3_bucket` module sets encryption, blocks public access, configures logging; teams using the module inherit the controls.

Modules shall be versioned, tested, and have a documented upgrade path.

## 4. Tooling and Approach Guidance

This guideline does not have language-specific subsections in the same sense as application guidelines, because IaC tooling spans declarative DSLs (HCL, YAML), JSON, and general-purpose languages (Pulumi). Instead:

### 4.1 Terraform / OpenTofu

Use modules from the Terraform Registry only after review. Pin to specific versions.

Use `tflint` for lint and `tfsec` or `checkov` for security scan. Integrate both in pre-commit hooks and CI.

For multi-account, use AWS Provider's `assume_role` with separate role per account; don't use long-lived access keys.

State per environment shall be isolated. Workspaces are acceptable for small projects; separate backends per environment are preferred for production isolation.

For sensitive outputs, mark `sensitive = true` to prevent display in plan output.

### 4.2 Kubernetes Manifests / Helm

Use `kube-linter`, `kubesec`, `polaris`, or `trivy config` to scan manifests.

Enforce Pod Security Standards per the Container guideline. Use admission controllers (Kyverno, OPA Gatekeeper) to enforce policies at apply time.

For Helm charts, pin chart versions in releases. Review chart sources before adoption. Override insecure defaults via values.

GitOps tooling (ArgoCD, Flux) reduces drift but requires that the Git repository be the source of truth and protected accordingly.

### 4.3 Ansible

Use `ansible-lint` and `ansible-later` for linting and policy. Vault all secrets with `ansible-vault` or use a secrets manager via lookup plugins.

Prefer modules over `shell` and `command`. Where shell is necessary, quote arguments and avoid user-controlled input.

Pin collection versions in `requirements.yml`.

### 4.4 Pulumi / CDK / Bicep

These use general-purpose languages or higher-level DSLs. Apply standard language-specific guidance plus the IaC concerns above.

For Pulumi, secrets shall be stored as Pulumi secrets, encrypted at rest. Output a secret via `Output.secret` to prevent display.

For AWS CDK, use the security-focused construct libraries (`aws-cdk-lib` with secure defaults) and consider `cdk-nag` to flag misconfigurations.

For Bicep, use `bicep lint` and Azure Policy as Code to enforce.

## 5. Verification

IaC scanners shall run on every PR and shall block merge on critical findings. Drift detection shall run periodically (daily or per-deployment) and alert on out-of-band changes. The CIS Benchmark for the target platform shall be assessed quarterly. State backend access shall be audited annually. Module inventories shall be reviewed for currency.

## 6. References

- CIS Benchmarks (AWS, Azure, GCP, Kubernetes)
- NIST SP 800-53 Rev. 5, CM control family
- HashiCorp Terraform documentation
- Open Policy Agent and Conftest documentation
- CNCF Security TAG resources
- OWASP Top 10 CI/CD Security Risks
