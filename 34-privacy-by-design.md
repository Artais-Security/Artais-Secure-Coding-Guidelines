# Secure Coding Guidelines: Privacy by Design (GDPR, CCPA)

## 1. Purpose and Scope

This section establishes requirements for privacy-respecting design and implementation. Privacy is related to but distinct from security: security protects data from unauthorized access; privacy governs what data is collected, how it is used, and the rights of the data subjects. Both regimes intersect heavily in practice.

These guidelines map to GDPR Articles 5, 17, 20, 25, 32, 33, 34, and 35; CCPA/CPRA requirements; HIPAA Privacy Rule; NIST Privacy Framework; ISO/IEC 27701; and CWE-359 (Privacy Violation).

## 2. General Principles

Privacy by design means privacy is built into the system from inception, not added later. The cheapest moment to implement privacy controls is before data is collected.

Data subjects (the people the data is about) have rights regarding their data. The application shall provide affordances for those rights: access, correction, deletion, portability, restriction.

Data minimization is the most powerful privacy control. Data not collected cannot be breached, requested, retained, or misused.

## 3. Normative Requirements

### Lawful Basis and Purpose

Each category of personal data shall have a documented lawful basis (consent, contract, legitimate interest, legal obligation, vital interest, public task — per GDPR Article 6) and a specific purpose.

Data shall not be processed for purposes incompatible with the original collection purpose. Re-purposing requires re-evaluation of lawful basis and may require fresh consent.

### Data Minimization

Collection shall be limited to data necessary for the documented purpose. "Might be useful" is not a justification.

Fields collected during registration, transactions, and profile management shall be reviewed for necessity. Optional fields shall be clearly marked.

Storage shall be minimized through retention limits, automatic deletion, and aggregation of data no longer needed at identifying granularity.

### Consent

Where consent is the lawful basis, it shall be:

- Freely given (no service degradation for refusal of optional consent)
- Specific (separate consents for separate purposes)
- Informed (clear description of what consent covers)
- Unambiguous (no pre-ticked boxes; explicit affirmative action)
- Revocable as easily as it was given

Consent records shall be auditable: when, what was consented to, by whom.

For cookies and similar tracking technologies, consent management shall comply with the ePrivacy Directive where applicable.

### Transparency

Privacy notices shall describe what data is collected, why, with whom it is shared, how long it is retained, and what rights data subjects have. Notices shall be accessible, current, and written in plain language.

Material changes to privacy practices shall be communicated to affected users.

### Data Subject Rights

The application shall support, with documented response timelines (typically 30 days under GDPR):

- **Access** (Article 15): provide a copy of the data subject's personal data, processing purposes, recipients, retention period, and rights.
- **Rectification** (Article 16): correct inaccurate data.
- **Erasure** (Article 17, "right to be forgotten"): delete data where lawful basis no longer exists.
- **Portability** (Article 20): export data in a machine-readable format.
- **Restriction** (Article 18): mark data for limited processing.
- **Objection** (Article 21): stop processing on grounds of legitimate interest.

Identity verification shall precede fulfillment of rights requests. The verification mechanism shall be proportionate to the sensitivity.

Rights requests shall be logged for audit per the Application Logging guideline.

### Privacy Impact Assessments

A Data Protection Impact Assessment (DPIA) shall be conducted for processing likely to result in high risk to data subjects (GDPR Article 35): large-scale processing of sensitive data, systematic monitoring, automated decision-making with legal or similar significant effects.

The DPIA shall be conducted before processing begins. It informs design decisions and produces a documented risk-and-mitigation record.

### Pseudonymization and Anonymization

Where the purpose can be achieved with pseudonymized or anonymized data, do not collect or retain identifying data.

Pseudonymization (data is identifiable with additional information held separately) is required by GDPR Article 32 as a security measure where appropriate. Effective pseudonymization isolates the linking information under stricter access control.

Anonymization (data cannot be linked back to a subject by any reasonable means) removes the data from privacy regulation. Anonymization is harder than it appears; differential privacy techniques may be appropriate for high-stakes datasets.

### Cross-Border Transfers

International transfers of personal data shall use a valid transfer mechanism under the applicable regime: Standard Contractual Clauses, Adequacy Decisions, Binding Corporate Rules, etc. for GDPR.

Cloud service providers' data residency configurations shall be selected to keep data within required jurisdictions where applicable.

### Breach Notification

Personal data breaches shall be reportable to supervisory authorities (within 72 hours under GDPR Article 33) and to affected data subjects where high risk (Article 34).

The application's logging and detection capabilities shall support breach scope determination: what data was affected, who was affected, what controls failed.

The incident response process per the Incident Response guideline shall integrate breach notification workflows.

### Children's Data

Where the application may collect data from children (under 13 in the US under COPPA, under 16 in EU member states under GDPR Article 8 with variation), additional controls apply: parental consent, restricted features, special protections.

Age verification shall be implemented if the application is not intended for children but might attract them.

### Automated Decision-Making

Automated decisions producing legal or similarly significant effects (Article 22) shall have:

- Human review mechanism on request
- Explanation of the logic involved
- Right to contest the decision

Algorithmic decision-making (including AI-driven decisions) about employment, credit, housing, education, and similar shall be reviewed for fairness and disparate impact in addition to privacy.

## 4. Implementation Patterns

This guideline is largely architectural and process-focused; per-language guidance follows general patterns:

### 4.1 Data Inventory

A data inventory shall exist mapping each piece of personal data to: source, purpose, lawful basis, retention period, location, sharing, and accountable team. The inventory drives downstream requirements; without it, GDPR compliance is impossible.

Automated discovery tools (data classification scanners, schema scanners) help maintain the inventory but do not replace it.

### 4.2 Tagging in Code

Personal data shall be tagged in the data model. Annotations (e.g., `@PII`, `@PHI` in Java; `Annotated[str, "PII"]` in Python with Pydantic; type aliases) make data classification visible in code and inform downstream tooling (log redaction, export filtering, encryption configuration).

### 4.3 Rights Request Implementation

A documented service shall handle rights requests:

- Identity verification
- Data assembly (across all stores: primary DB, caches, search index, analytics, backups, third-party processors)
- Action execution (export, deletion, correction)
- Audit logging

Per-store deletion is the hardest part; data sprawl across systems complicates erasure. Design the data flow so that personal data has clear locations.

### 4.4 Retention Automation

Automated deletion or anonymization shall execute on documented retention schedules. Manual deletion does not scale.

Retention shall account for legal holds (litigation, regulatory investigation). Deletion shall pause for affected records when a hold applies.

### 4.5 Pseudonymization in Practice

Use stable pseudonymous IDs in logs and analytics rather than raw identifiers. The mapping table is held under stricter access control.

For analytics, prefer aggregated or differentially private summaries over per-user logs. Where per-user data is needed, segregate from production systems.

## 5. Verification

The data inventory shall be reviewed quarterly. Rights request handling shall be tested annually (test requests through the full pipeline). DPIAs shall be reviewed when triggering conditions occur. Privacy notices shall be reviewed for accuracy when systems change. External audits or assessments (ISO 27701, SOC 2, regulatory) shall validate the program. Incidents involving personal data shall be reviewed against the privacy program.

## 6. References

- GDPR (Regulation (EU) 2016/679)
- CCPA / CPRA (California Civil Code §1798.100 et seq.)
- HIPAA Privacy Rule (45 CFR Part 164, Subpart E)
- NIST Privacy Framework
- ISO/IEC 27701 (Privacy Information Management)
- ISO/IEC 29100 (Privacy framework)
- COPPA (Children's Online Privacy Protection Act)
- ePrivacy Directive (Directive 2002/58/EC)
- CWE-359
