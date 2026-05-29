# Secure Coding Guidelines: Threat Modeling Practice

## 1. Purpose and Scope

This section establishes requirements for threat modeling: the structured analysis of a system to identify security risks early in design. Threat modeling is the practice that distinguishes "secure by design" from "secure by patching". Investment in threat modeling shifts defect discovery left of implementation, where remediation is least expensive.

These guidelines map to NIST SP 800-218 (SSDF) tasks PW.1 and PW.2, OWASP Application Threat Modeling, the Threat Modeling Manifesto, ISO/IEC 27001 risk assessment requirements, and the Microsoft Security Development Lifecycle.

## 2. General Principles

Threat modeling is a continuous practice, not a one-time gate. A model produced once and never updated rapidly diverges from the system it describes and becomes useless.

Threat modeling shall be performed by the engineers who will build the system, with facilitation from security where helpful. Models produced entirely by security teams without engineering participation tend not to inform implementation.

The output of threat modeling is a list of actionable risks, ranked by some combination of likelihood and impact, with assigned mitigations and owners. A model that ends as a diagram without an action list has not been completed.

## 3. Normative Requirements

### When to Threat Model

Threat models shall be produced for new systems before implementation begins. The point of threat modeling is to influence design; threat modeling an implemented system is remediation, not design.

Threat models shall be updated when the system undergoes significant change: new trust boundary, new external interface, new data class, new dependency, change in deployment topology. Trivial changes do not warrant model updates.

Quarterly or semi-annual review of existing models shall confirm they remain accurate.

### Approach

The four-question framework shall structure the analysis (per the Threat Modeling Manifesto):

1. What are we working on?
2. What can go wrong?
3. What are we going to do about it?
4. Did we do a good job?

A data flow diagram (DFD) shall represent the system's components, data flows, trust boundaries, and external entities. The DFD is a tool for shared understanding; it does not need to be exhaustive but shall cover the elements relevant to security analysis.

STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) shall structure the "what can go wrong" enumeration. For each element in the DFD, the team shall consider each STRIDE category.

Alternative frameworks (LINDDUN for privacy, PASTA for attack-tree-style analysis, kill chain analysis) may complement or replace STRIDE depending on the system's risk profile.

### Documentation

Threat models shall be documented in version control alongside the code they describe. The model is engineering documentation, not security paperwork; it lives with the system.

Each identified threat shall include:

- Description of the threat scenario
- Affected components or data flows
- Likelihood and impact assessment (qualitative or quantitative)
- Existing mitigations
- Additional mitigations proposed
- Risk acceptance decision if no mitigation is planned

Out-of-scope items shall be documented explicitly. "We are not defending against nation-state physical access" is a valid scope statement.

### Trust Boundaries

Trust boundaries shall be identified explicitly. At each boundary, the data crossing shall be enumerated and the controls in place described.

Common boundaries: external user to application, application to database, application to third-party service, container to host, tenant to tenant in multi-tenant systems, privilege levels within a process.

### Risk Ranking

Risks shall be ranked to drive prioritization. CVSS, DREAD, or organization-specific frameworks are acceptable; consistency within the model matters more than the specific framework.

Risk scoring shall feed into the work backlog. High-risk items shall be addressed before lower-risk items in the same iteration.

### Mitigation Ownership

Every identified mitigation shall have an owner and a target date. Mitigations recorded without ownership are wishes, not commitments.

Accepted risks (decision to not mitigate) shall be approved at a documented authority level proportional to the risk.

### Integration with Development

Threat model findings shall produce tickets in the engineering tracker, linked to the model. The engineering team shall not need to consult the threat model separately to know what to do.

Acceptance criteria for stories implementing security-sensitive features shall reference the relevant threat-model controls.

### Review

Threat models shall be reviewed by a security-experienced engineer not on the team that produced the model, to catch blind spots.

Regular threat modeling retrospectives shall evaluate whether the practice is producing findings that translate into prevented vulnerabilities.

## 4. Practical Guidance and Tooling

Unlike other guidelines, threat modeling does not have language-specific sections — the practice is language-agnostic. Instead:

### 4.1 Process Patterns

Whiteboard sessions with the development team work well for initial models. Capture the DFD in a tool afterwards.

Time-box sessions to 60–90 minutes. Multiple sessions are better than marathons; engineers retain more.

Threat libraries (OWASP ASVS as a checklist, MITRE ATT&CK for attacker techniques, the Common Threat List from various sources) help surface threats engineers might miss.

For agile teams, lightweight per-story threat modeling ("evil user stories") integrates with the development flow.

### 4.2 Tools

For DFD documentation:
- Microsoft Threat Modeling Tool (Windows, free)
- OWASP Threat Dragon (web-based, free, open source)
- pytm (Python-based, threat-modeling-as-code)
- threagile (YAML-based, threat-modeling-as-code)
- IriusRisk, ThreatModeler, SD Elements (commercial)

Threat-modeling-as-code approaches integrate with version control and can drive findings into CI. The Artais threat modeling tool, where applicable, supports this workflow.

### 4.3 Templates and Patterns

The organization shall maintain templates for common system patterns: web application, REST API, microservice, batch pipeline, mobile-backend, AI-integrated application.

Templates accelerate threat modeling by surfacing typical threats and controls; teams customize rather than enumerate from scratch.

### 4.4 Integration with Other Guidelines

Threat models inform which other guidelines in this repository apply most strongly to a given system. A system with no PII may de-emphasize the Privacy by Design guideline; a system with significant cryptographic operations elevates the Cryptography guideline.

Outputs from threat modeling feed:

- Security testing scope (per the Security Testing guideline)
- Logging requirements (per the Application Logging guideline)
- Incident response planning (per the Incident Response guideline)
- Code review focus (per the Code Review guideline)

## 5. Verification

Threat models shall be reviewed at design milestones and before major releases. Threat model coverage of the organization's systems shall be tracked as a metric. Findings from incidents shall be reviewed against the corresponding threat models — were the threats anticipated? Where they were not, the modeling process shall be updated to catch the missed pattern. Annual review of the threat modeling practice itself shall assess effectiveness.

## 6. References

- Threat Modeling Manifesto (threatmodelingmanifesto.org)
- OWASP Application Threat Modeling
- Microsoft Threat Modeling Tool documentation
- NIST SP 800-218 (SSDF) tasks PW.1, PW.2
- Adam Shostack, "Threat Modeling: Designing for Security"
- MITRE ATT&CK Framework
- ISO/IEC 27005 (Risk Management)
