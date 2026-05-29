# Contributing

Thanks for your interest in contributing to the Artais Secure Coding Guidelines. This document covers what to expect when opening issues and pull requests against this repository.

## Scope

This repository is a normative reference. Contributions are accepted in the following categories:

- **Corrections** — factual errors, broken standards mappings, out-of-date library or version references, typos.
- **Clarifications** — wording that is ambiguous or could be misread by an engineer trying to apply the guideline.
- **Expansions** — additional language coverage (Go, Rust, JavaScript/TypeScript, C# are reasonable candidates), new normative requirements that fill a gap in an existing section, or new sections covering a domain not yet addressed.
- **Tooling** — references to additional verification tools, CI integrations, or links to companion tools in the Artais toolkit.

Contributions outside these categories — opinion pieces, philosophy posts, or rewrites that don't change normative content — are unlikely to be merged.

## Structure

Every guideline in this repository follows the same six-part structure. New sections must follow it. Existing sections must not break it.

1. **Purpose and Scope** — what the section covers, which standards it maps to, what is explicitly out of scope.
2. **General Principles** — the threat model and design posture for the domain.
3. **Normative Requirements** — what shall, should, and shall not be done. Use "shall" for mandatory requirements, "should" for strong recommendations.
4. **Language-Specific Guidance** — concrete guidance for Java, Python, C, and C++ at minimum. Sections that are inherently architectural or process-focused (Threat Modeling, Incident Response, Privacy by Design) may substitute pattern or tooling subsections for language ones.
5. **Verification** — how compliance is checked: static analysis, code review, dynamic testing, runtime monitoring.
6. **References** — the standards, frameworks, and authoritative sources the section maps to.

Inner code fences within markdown shall use tildes (`~~~`) rather than backticks, to avoid fence collision in both chat rendering and on GitHub when the section is nested in a larger document.

## Style

- Imperative voice for requirements. "Validate input at the trust boundary" rather than "we validate input at the trust boundary."
- "Shall" for mandatory, "should" for recommended, "may" for optional, "shall not" / "should not" for prohibitions.
- Concrete library and version references where applicable, with the understanding that they will need periodic updates.
- Cite specific standards by control or section number. "OWASP ASVS V5.3" is more useful than "OWASP."

## Pull Request Process

1. Open an issue first for substantive changes — new sections, structural rewrites, or changes that touch multiple guidelines. Smaller corrections can go directly to a PR.
2. Each PR shall touch one guideline (or one cross-cutting concern across guidelines), not a mix.
3. PRs adding new normative requirements shall include the standards mapping that justifies them.
4. PRs changing existing requirements shall note what changed and why in the PR description, including any standards changes that motivated the update.

## Review

PRs are reviewed by Artais Security maintainers. Expect feedback within a few business days for substantive PRs. Style and formatting nits are handled inline; structural feedback may require revision rounds.

## Companion Tools

Several guidelines reference companion tools in the [Artais Security](https://github.com/Artais-Security) toolkit (`artais-cookie-cop` and others). Contributions to those tools are welcomed in their own repositories.

## Conduct

Be constructive. Disagree on substance, not on the person. Standards and best practices evolve; what was secure in 2018 may not be in 2026, and what's secure today will likely need revisiting.

## License

By contributing, you agree that your contributions will be licensed under the same license as the repository (see [LICENSE](./LICENSE)).
