# Secure Coding Guidelines: LLM and AI Integration Security

## 1. Purpose and Scope

This section establishes requirements for the secure integration of large language models and AI systems into applications. AI components introduce a distinctive set of security concerns that are not adequately addressed by traditional application security guidelines alone: untrusted text becomes executable instruction, model outputs are non-deterministic and can be manipulated, and the integration patterns (tools, retrieval, agents) create new attack surfaces.

These guidelines map to OWASP Top 10 for LLM Applications (2025), NIST AI Risk Management Framework (AI RMF 1.0), MITRE ATLAS (Adversarial Threat Landscape for AI Systems), and emerging regulatory frameworks including the EU AI Act.

## 2. General Principles

LLM outputs are untrusted. The model's output is influenced by training data, system prompt, user input, and retrieved context — any of which may be controlled or influenced by an attacker. Treat outputs as user input flowing into downstream systems.

Inputs to LLMs that include any user-controlled text — including indirect input via retrieved documents, tool outputs, or shared conversation history — are subject to prompt injection. There is no current technique that reliably prevents prompt injection in the general case. Defense is at the boundary: limit what the LLM can do, validate what it produces.

Confidentiality of system prompts, tool definitions, and similar shall not be assumed. They can be extracted via prompt injection and many other means. Sensitive logic and credentials shall not live in the prompt.

## 3. Normative Requirements

### Threat Modeling

LLM integrations shall be threat-modeled per the Threat Modeling guideline. Specific threats include:

- Prompt injection (direct and indirect)
- Sensitive information disclosure (training data extraction, system prompt extraction, conversation history leakage)
- Insecure output handling (downstream injection via model output)
- Excessive agency (over-broad tool permissions)
- Supply chain attacks via models, plugins, or training data
- Denial of service (resource consumption attacks)
- Model theft (extraction via API)
- Misinformation and hallucination affecting downstream decisions

### Input Boundaries

User input to the LLM shall pass through the same validation as input to any other component. Length limits, character set restrictions, and content moderation shall apply.

Indirect input (retrieved documents, tool outputs, file contents, web pages) shall be tagged as untrusted. Where the LLM is being asked to process untrusted content (summarize a web page, analyze a document), the system prompt shall explicitly note the content as untrusted and instruct the model accordingly. This is not a strong defense but reduces incidental failures.

Inputs containing previously generated AI content (chat history, prior turns) shall be treated as semi-trusted: less than user input, more than fully untrusted retrievals, because it has already been through model output. Earlier prompt injection can persist.

### Output Handling

LLM output shall be encoded and validated at every downstream boundary:

- For display in HTML, encode per the Output Encoding guideline.
- For execution as SQL, parameterize per the Database Access guideline.
- For execution as shell commands, treat as untrusted user input and prohibit shell execution where possible.
- For URLs and file paths, validate per the SSRF and File Handling guidelines.

If the application acts on LLM output (executing tools, making API calls, writing data), the action shall be authorized as the user invoking the LLM, not as a privileged AI service identity. Permissions of the AI integration shall not exceed the user's permissions.

For high-impact actions, require human confirmation. The "agent that books your travel" pattern shall confirm before purchase; the "agent that approves invoices" pattern shall require human approval.

### Tool/Function Calling

Tools exposed to LLMs shall be designed assuming the LLM can be coerced into calling them with attacker-controlled arguments. Tool inputs shall be validated as untrusted.

Tool authorization shall be at the user level. The LLM cannot legitimately invoke a tool the user is not authorized to use; the system shall enforce this.

Tool descriptions shall not include sensitive information; they are visible to the model and extractable.

Tool invocations shall be logged. The audit trail shall include: tool name, arguments, calling user, model identity, timestamp.

Tools shall fail closed. A tool that cannot determine its authorization shall refuse, not proceed.

### Retrieval Augmented Generation (RAG)

For RAG systems, the retrieval corpus shall be controlled. Allowing arbitrary documents into the corpus opens an indirect prompt injection path.

Retrieved documents shall be tagged with their source and trust level in the prompt. Document boundaries shall be clearly delimited.

Access control on retrieval shall match access control on the source documents. A user querying RAG shall not retrieve documents they could not access directly.

Embeddings models and vector stores shall be patched and updated. Vector store access shall be authenticated.

### Agents and Multi-Step Reasoning

Agent loops (LLM repeatedly calling tools, processing results, calling more tools) shall have:

- Maximum step counts
- Maximum tool-call counts
- Per-step authorization
- Per-step logging
- Human-in-the-loop checkpoints for sensitive operations

Agent budgets (time, tokens, dollars) shall be enforced per invocation and per user.

Goal-following behavior shall be reviewed for path deviation. An agent told to "process incoming emails" may be prompted to "delete all emails" by a malicious email; safeguards shall prevent.

### Sensitive Data in Prompts

The system prompt and conversation history shall not include data the calling user is not authorized to see. Tenant isolation shall apply to LLM context.

Conversation history may persist on the inference provider's infrastructure. Confirm contractually and configure to align with data protection requirements.

PII in prompts shall be minimized. Where PII is necessary for the task, document the lawful basis under the Privacy by Design guideline.

### Provider and Model Selection

Third-party LLM providers (OpenAI, Anthropic, Google, AWS Bedrock, Azure OpenAI) shall be assessed per the dependency selection criteria plus AI-specific concerns:

- Data handling and retention policies
- Training opt-out mechanisms
- Regional availability and data residency
- SLA and incident response
- Model versioning and deprecation policies

Self-hosted models from public weights shall be verified for provenance. Models from unknown sources may contain backdoors or be fine-tuned with intent.

Model versions shall be pinned where possible. Behavior changes across versions can break security assumptions (improved prompt-injection resistance is welcome; new tool-calling defaults may not be).

### Cost and Rate Controls

Per-user and per-tenant token budgets shall be enforced per the Rate Limiting guideline. AI inference is expensive; cost amplification attacks are practical.

Token caps on individual responses shall prevent runaway generation.

### Content Moderation

Output content moderation shall apply where the application surfaces LLM output to users. The model may produce harassment, misinformation, regulated content (medical advice, financial advice, legal advice), or content violating the application's terms.

Moderation may use a separate model, rule-based filters, or provider-supplied moderation endpoints. The choice depends on the threat model and required precision/recall.

### Monitoring and Detection

LLM interaction logs shall capture: model identity, prompt (or hash for sensitive cases), response, tools invoked, tokens used, latency, user identity, request identity.

Anomalous patterns shall produce alerts: unusually high token usage per user, repeated identical prompts (possible scripted abuse), unusual tool-call patterns, content moderation triggers.

Privacy considerations: do not log full prompts and responses containing user PII without justification. Hash or sample where appropriate.

### Training Data

If the organization trains or fine-tunes models, training data shall be governed:

- Sourced lawfully (licensed or owned)
- Sanitized of PII unless intentionally retained with consent
- Reviewed for poisoning
- Documented for reproducibility and audit

Model artifacts (weights, fine-tuning datasets) shall be stored per data classification.

## 4. Pattern-Specific Guidance

This guideline is largely architectural. Specific patterns require specific attention:

### 4.1 Chat Applications

The simplest pattern: user sends messages, LLM responds. Concerns:

- Session boundaries (one user's conversation shall not leak to another)
- History retention per privacy policy
- Output rendering (Markdown, HTML, links — each is an injection sink)
- User-uploaded content as context (treat as untrusted)

### 4.2 Code Generation and Execution

LLM-generated code shall not be executed without review. Where automation requires execution (test runners, code interpreters), sandbox the execution: container, gVisor, separate VM, with no production credentials or network access.

Code suggestions to developers shall be marked as such. Developer review and the Code Review guideline apply to AI-generated code.

### 4.3 RAG and Search

Per the RAG section above. Additionally:

- Citations from retrieved sources prevent some hallucination but do not prevent injection from those sources.
- "Answer only from provided context" instructions are not reliable against capable injection.

### 4.4 Agentic and Workflow Systems

Agents have all the concerns above plus:

- Increased tool surface
- Persistence of state across runs (poisoning earlier runs affects later)
- Composition of capabilities — individually-safe tools may be unsafe in combination

Highly autonomous systems shall have human oversight, kill switches per the Incident Response Hooks guideline, and conservative defaults.

### 4.5 LLM-as-Validator

Patterns where one LLM checks another LLM's output (jailbreak detection, content moderation, output filtering) provide some uplift but are not strong security boundaries. Treat as defense-in-depth, not primary control.

## 5. Verification

LLM integrations shall be threat-modeled and penetration-tested. Red teaming with prompt injection techniques is a specialized skill; the OWASP LLM project, MITRE ATLAS, and the AI security research community publish techniques to test against. Monitoring data shall be reviewed for indicators of abuse. Budget consumption shall be alerted on. Annual review of the LLM integration shall reassess against the evolving threat landscape, which is moving rapidly.

## 6. References

- OWASP Top 10 for LLM Applications (2025)
- NIST AI Risk Management Framework (AI RMF 1.0)
- NIST AI 100-2 (Adversarial Machine Learning: A Taxonomy and Terminology)
- MITRE ATLAS (atlas.mitre.org)
- EU AI Act
- Google Secure AI Framework (SAIF)
- Microsoft Responsible AI Standard
- OWASP Machine Learning Security Top 10
