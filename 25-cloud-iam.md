# Secure Coding Guidelines: Cloud Configuration and IAM

## 1. Purpose and Scope

This section establishes requirements for cloud account configuration and identity and access management. Cloud IAM is a primary attack surface; misconfigured policies and overly broad roles have been the root cause of many high-profile cloud breaches. This guideline applies to AWS, Google Cloud, Azure, and other major providers.

These guidelines map to CIS Foundations Benchmarks (AWS, Azure, GCP), NIST SP 800-53 AC family, PCI DSS 4.0 Requirement 7, HIPAA §164.312(a)(1), and the OWASP Cloud-Native Application Security Top 10.

## 2. General Principles

Cloud IAM expresses authorization between principals (users, services, federated identities) and resources. Mistakes in IAM produce blast radius proportional to the cloud account's reach.

Least privilege applies to cloud identities as it does to application authorization. Standing access shall be replaced with just-in-time elevation where the workflow supports it.

Cloud accounts shall be structured to limit blast radius. Multiple accounts (or subscriptions, or projects) provide stronger isolation than RBAC within a single account.

## 3. Normative Requirements

### Account Structure

Organizations shall use a multi-account structure: separate accounts for production, staging, development, security tooling, log archive, and shared services. AWS Organizations, GCP Resource Hierarchy, and Azure Management Groups support this.

Cross-account access shall be explicit and minimal. IAM roles assumed across account boundaries are preferable to shared credentials.

Account-level guardrails shall be applied: AWS Service Control Policies, GCP Organization Policy Constraints, Azure Policy. Guardrails prevent specific actions across all identities in scope: forbid regions, require encryption, prevent public S3 access, prevent IAM changes by application principals.

### Root and Initial Identities

The root account (or equivalent) shall be used only for account-creation activities. Day-to-day operations shall use IAM users or federated identities.

Root credentials shall have MFA enabled and shall be stored in a controlled location accessible only to designated administrators.

The initial deployment of IAM shall create a bootstrap administrator role with documented controls; ongoing administration shall use that role rather than root.

### Federated Identity

Human users shall authenticate via federated identity: SAML or OIDC from the corporate identity provider (Okta, Azure AD, Google Workspace). Local IAM users for human users are prohibited.

Federated sessions shall have lifetimes appropriate to the access level (typically 1 hour for admin, 8 hours for read-only).

Identity provider claims shall map to cloud roles via documented attribute mapping. Group membership in the IdP shall drive role grants.

### Service Identities

Workload-to-cloud authentication shall use workload identity:

- AWS: EC2 instance profiles, ECS task roles, EKS Pod Identity or IRSA.
- GCP: Workload Identity Federation, service account impersonation.
- Azure: Managed Identity (system-assigned or user-assigned).

Long-lived access keys for service accounts shall be eliminated. Where unavoidable (CI accessing cloud), use short-lived credentials via OIDC federation (GitHub Actions OIDC, GitLab OIDC, etc.).

Each service shall have its own identity. Shared service accounts across services are prohibited.

### Policy Design

Policies shall grant specific actions on specific resources. Wildcards in actions (`s3:*`) or resources (`Resource: *`) shall be justified and reviewed.

Permission boundaries (AWS) or Conditional Access (Azure) shall be used to cap the privileges that lower-privileged administrators can grant.

`AssumeRole` policies shall scope trust narrowly: specific principals, specific external IDs (for cross-account third-party), conditions on source IP or VPC endpoint where applicable.

For S3, GCS, and equivalent, bucket policies shall not allow `Principal: *` without conditions restricting the access (e.g., to VPC, account, or specific external accounts). Public buckets shall be explicitly justified and tagged.

For databases and queues, resource-based policies shall enforce TLS (`aws:SecureTransport`) and may enforce source VPC.

### Privileged Access

Administrative actions (IAM changes, security group changes, deletion of audit logs) shall require MFA in addition to authentication. AWS `aws:MultiFactorAuthPresent` condition, GCP IAM conditions, Azure Conditional Access.

Standing administrator access shall be replaced with just-in-time elevation. AWS IAM Identity Center permission sets with time-bound assignments, Azure PIM, GCP roles requiring approval.

Break-glass procedures for emergency access shall exist with explicit logging and post-event review.

### Logging and Audit

CloudTrail (AWS), Cloud Audit Logs (GCP), or Activity Logs (Azure) shall be enabled in all regions and shall capture both management and data plane events for sensitive services (S3, KMS, Secrets Manager).

Logs shall be centralized to a separate logging account with restricted access. Log integrity shall be verified (log file validation, immutable storage).

VPC Flow Logs (or equivalent) shall be enabled for production VPCs and sent to the central logging account.

Security findings (GuardDuty, Security Hub, Security Command Center, Defender for Cloud) shall be aggregated and triaged. Auto-remediation for documented patterns is encouraged.

### Network Configuration

Default security groups, firewalls, and NSGs shall not be relied on as security boundaries. Define explicit rules.

Public-facing resources shall be minimized. Application Load Balancers, API Gateways, and Cloud Front are appropriate fronts; direct internet exposure of EC2/Compute Engine/VMs and databases is prohibited.

VPC peering, Transit Gateway, and equivalent shall be reviewed for overly broad routing.

Private connectivity (VPC Endpoints, Private Service Connect, Private Link) shall be used for AWS-internal access to AWS services, avoiding exposure of traffic to the internet.

### Encryption Configuration

Default encryption shall be enabled on all services that support it: EBS, S3, RDS, DynamoDB, GCS, Persistent Disk, Cloud SQL, Cosmos DB, Storage Accounts.

Customer-managed keys (CMK) shall be used for sensitive data per the Cryptography guideline. KMS keys shall have appropriate key policies and shall be rotated.

KMS keys shall be in the same region as the resources they protect to limit regional dependency, with cross-region key replication for disaster recovery only where needed.

## 4. Provider-Specific Guidance

### 4.1 AWS

Use AWS Organizations with SCPs for guardrails. AWS Control Tower provides a managed baseline.

Use IAM Identity Center (formerly AWS SSO) with IdP federation. Permission Sets define role templates; assignments are time-bound.

Use IRSA or EKS Pod Identity for Kubernetes workloads. Avoid long-lived credentials in pods.

Use Access Analyzer to identify external sharing of S3, IAM, KMS, and other resources. Findings should be triaged and remediated.

Use CloudTrail with log file validation enabled, sent to a separate logging account's S3 bucket with bucket policy preventing modification.

Use GuardDuty across the organization. Enable Security Hub for cross-service finding aggregation.

### 4.2 GCP

Use Resource Hierarchy with Organization Policies for guardrails.

Use Workload Identity Federation for non-GCP workloads. For GKE, use Workload Identity (the GKE feature, not Federation) for pod-to-service-account binding.

Use IAM Recommender to identify over-privileged service accounts.

Use Cloud Asset Inventory and Security Command Center for visibility.

VPC Service Controls provide network-level isolation around sensitive resources (BigQuery, GCS).

### 4.3 Azure

Use Management Groups with Azure Policy for guardrails.

Use Entra ID (Azure AD) as the identity provider, with Conditional Access enforcing MFA on privileged operations.

Use Managed Identities for Azure resource authentication. User-assigned managed identities are preferred for non-trivial scenarios.

Use Privileged Identity Management (PIM) for just-in-time elevation.

Use Microsoft Defender for Cloud for visibility and findings. Azure Sentinel for SIEM integration.

## 5. Verification

CIS Benchmark assessments shall run quarterly using `prowler`, `scout suite`, `cloudsploit`, or commercial CSPM tools. Continuous monitoring via CSPM tools (Wiz, Orca, Lacework, native services) shall produce alerts on misconfiguration. Annual access reviews shall verify least-privilege grants for human users. Service account credential ages shall be audited; long-lived credentials older than the rotation policy are findings. Penetration testing shall include IAM enumeration and privilege escalation paths.

## 6. References

- CIS Foundations Benchmarks (AWS, Azure, GCP)
- NIST SP 800-53 Rev. 5, AC control family
- PCI DSS v4.0, Requirement 7
- HIPAA Security Rule, 45 CFR §164.312(a)(1)
- AWS Well-Architected Framework, Security Pillar
- Google Cloud Security Foundations Guide
- Microsoft Cloud Adoption Framework, Security
- OWASP Cloud-Native Application Security Top 10
