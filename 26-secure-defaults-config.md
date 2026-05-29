# Secure Coding Guidelines: Secure Defaults and Configuration Management

## 1. Purpose and Scope

This section establishes requirements for application configuration: secure default values, environment-specific overrides, configuration sources, and validation. Misconfiguration ranks consistently in the OWASP Top 10 and is the root cause of many incidents that appear to be vulnerabilities but are actually deployment errors.

These guidelines map to OWASP ASVS V14 (Configuration), OWASP Top 10 2021 A05 (Security Misconfiguration), NIST SP 800-53 CM family, CIS Benchmarks, and CWE-1188 (Insecure Default Initialization).

## 2. General Principles

Secure by default. The configuration shipped with the application shall be safe to run; turning on security features shall not require additional steps. Insecure modes (debug, verbose error pages, permissive CORS) shall require explicit opt-in.

Configuration shall be explicit. Defaults should be safe but obvious. Hidden defaults make it difficult to reason about deployed behavior.

Environment-specific configuration shall override base defaults via documented mechanisms. The production configuration shall not be derived from a development baseline by accident.

## 3. Normative Requirements

### Configuration Sources

The order of precedence shall be documented: command-line arguments override environment variables override configuration files override built-in defaults (or the reverse, depending on framework convention). The framework's documented order shall be respected and not overridden.

Configuration files shall be in a single documented format per project. Mixing YAML, JSON, TOML, and INI within one application increases the risk of subtle misconfiguration.

Configuration files containing secrets shall be loaded from the secrets management system per the Secrets Management guideline, not from files in the image or filesystem.

### Validation at Startup

Configuration shall be validated at application startup. Required values shall be checked for presence and well-formedness. Invalid configuration shall cause the application to fail to start with a clear error message rather than to start in an undefined state.

Configuration schemas (JSON Schema, Pydantic models, Spring `@ConfigurationProperties` with validation, custom validators) shall be used. Schema violations are startup failures.

Sentinel values that indicate "not configured" (`CHANGEME`, `INSECURE`, default API keys from documentation) shall be rejected at startup. The application shall not start with placeholder values in production.

### Environment Awareness

The application shall know which environment it is running in (production, staging, development) via an explicit environment variable or configuration value. Behavior shall be tied to environment, not inferred from hostname or other ambient signals.

Production environments shall have specific safeguards: debug modes disabled, verbose logging disabled, development endpoints not registered, default credentials rejected, dummy data not loaded.

The application shall warn on startup if running in production with development-oriented settings, or shall refuse to start.

### Debug and Development Features

Debug endpoints, admin consoles, profiling endpoints, and remote debuggers shall not be exposed in production. If they exist, they shall be bound to localhost only and shall require authentication.

Stack traces and detailed error information shall not be returned to clients in production (per the Error Handling guideline).

Default credentials shall not be present in production. Initial admin accounts shall require a setup flow that forces credential creation.

### Feature Flags

Feature flags controlling security-relevant behavior shall be reviewed like code. The flag system shall log flag evaluations for sensitive flags.

Flag default values shall be the safe option. A flag controlling "enable new auth check" should default to enabled; a flag controlling "bypass auth check for debugging" should default to disabled and have access controls on toggling it.

Flag state shall be observable in production. Per-environment dashboards shall show current flag values.

### Configuration Drift

Drift between intended and actual configuration shall be detected. For containerized deployments, configuration is part of the image or supplied at deploy time; drift typically indicates either an out-of-band change (which shouldn't be possible if access control is correct) or a discrepancy in the IaC pipeline.

Configuration audits shall occur on a documented cadence. Mature organizations use continuous reconciliation (GitOps) to eliminate drift by construction.

### Reload and Hot Configuration

Configuration changes generally require restart for safety. Where hot reload is supported, the reload mechanism shall be authenticated and audited.

Sensitive configuration (cryptographic keys, secrets) shall be reloadable to support rotation per the Secrets Management guideline.

### Backwards Compatibility

Configuration schema changes shall maintain backwards compatibility within minor versions. Migration steps shall be documented for major version transitions.

Removed configuration options shall produce a warning if encountered, not silent ignore.

## 4. Language-Specific Guidance

### 4.1 Java

For Spring Boot, use `@ConfigurationProperties` with `@Validated` and Bean Validation annotations:

~~~java
@ConfigurationProperties("app.db")
@Validated
public record DbConfig(
    @NotBlank String url,
    @NotBlank String user,
    @NotNull @Min(1) Integer poolSize
) {}
~~~

`application.yml` provides defaults; environment-specific files (`application-production.yml`) override. Spring resolves the active profile via `SPRING_PROFILES_ACTIVE`.

Profile-specific beans (`@Profile("production")`) shall replace development-only beans (in-memory databases, mock external services).

`management.endpoints.web.exposure.include` shall be limited in production to non-sensitive endpoints (`health`, `info`); Actuator endpoints like `env`, `heapdump`, and `shutdown` shall not be exposed publicly.

Suppress server identification: `server.tomcat.send-server-version=false`, `server.error.include-message=never`.

### 4.2 Python

For FastAPI/Pydantic, use `pydantic-settings`:

~~~python
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import HttpUrl, PostgresDsn, SecretStr, Field

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="forbid")
    environment: Literal["development", "staging", "production"]
    database_url: PostgresDsn
    secret_key: SecretStr = Field(min_length=32)

    def model_post_init(self, _):
        if self.environment == "production":
            if self.secret_key.get_secret_value() in ("CHANGEME", "dev-secret"):
                raise ValueError("placeholder secret in production")
~~~

For Django, configure per-environment settings modules (`settings/production.py` importing from `settings/base.py`). Use `django-environ` or `pydantic-settings` for type-safe environment variable loading.

`DEBUG=False` in production. `ALLOWED_HOSTS` shall not contain wildcards. `SECRET_KEY` shall be loaded from the secrets manager, not from settings files.

For Flask, use `app.config.from_envvar` or `from_object` with a per-environment class. Disable `DEBUG` and `TESTING` in production.

### 4.3 C

C applications typically use configuration files (INI, YAML, JSON, custom) and environment variables. Use a vetted parser for the chosen format.

Parse configuration at startup, validate, and store in an immutable struct passed to the rest of the application. Avoid configuration globals; pass an explicit context.

For boolean and enum values, accept only documented spellings ("true"/"false", not "1"/"0" if the documented form is the former). Reject unknown values rather than treating them as one or the other.

For numeric values, validate ranges. Negative numbers, zero, or extreme values often have security implications (timeouts of zero, sizes of MAX_INT).

### 4.4 C++

The C guidance applies. Use a C++ configuration library (Boost.PropertyTree, cpptoml, yaml-cpp, nlohmann/json) and wrap in a typed configuration struct.

Use `constexpr` and `static_assert` to enforce compile-time defaults where possible.

For runtime validation, return `std::expected` from the parser and require callers to handle the error path.

## 5. Verification

Configuration schema validation shall run in CI on representative configurations. Production startup shall be tested with intentionally incomplete or invalid configurations to confirm fail-closed behavior. Configuration audits shall compare deployed configuration against expected configuration periodically. Penetration testing shall include attempts to access debug endpoints, default credentials, and known-default configurations. CIS Benchmark assessments cover infrastructure configuration; application configuration baselines shall be developed and assessed similarly.

## 6. References

- OWASP ASVS v4.0.3, V14
- OWASP Top 10 2021, A05
- OWASP Application Security Verification Standard
- NIST SP 800-53 Rev. 5, CM control family
- CIS Benchmarks for relevant platforms
- CWE-1188, CWE-13, CWE-16
