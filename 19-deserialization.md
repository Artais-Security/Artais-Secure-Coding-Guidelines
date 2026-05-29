# Secure Coding Guidelines: Deserialization and Object Injection

## 1. Purpose and Scope

This section establishes requirements for deserializing data from untrusted sources. Deserialization vulnerabilities have produced some of the most severe application security incidents on record because they often allow direct remote code execution. The defenses are well understood but require disciplined application across every deserialization site in a codebase.

These guidelines map to OWASP ASVS V5.5 (Deserialization Prevention), OWASP Top 10 2021 A08 (Software and Data Integrity Failures), and CWE-502 (Deserialization of Untrusted Data), CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes).

## 2. General Principles

Deserialization converts a byte stream into in-memory objects. When the byte stream is attacker-controlled and the deserialization format supports type information, the attacker can choose which classes are instantiated and what state they hold. Many languages and libraries have classes that perform dangerous actions during construction or finalization, producing gadgets that chain into code execution.

The strongest defense is to avoid deserializing untrusted data with a type-aware deserializer. Use data-only formats (JSON, Protocol Buffers, MessagePack with strict schemas) and never use format features that allow the byte stream to specify which type to instantiate.

## 3. Normative Requirements

### Format Selection

Prefer JSON, Protocol Buffers, or MessagePack with explicit schemas over format-native serialization (Java serialization, Python `pickle`, .NET `BinaryFormatter`, PHP `unserialize`). The format-native serializers carry type information and are exploitable; the data-only formats are not.

Where format-native serialization is unavoidable (legacy interop), the data shall be authenticated with HMAC or a signature before deserialization. The application shall verify the signature with a key the attacker cannot influence before performing any deserialization.

YAML deserialization shall use safe modes only (`yaml.safe_load` in Python, `SafeConstructor` in SnakeYAML). Default YAML modes in many libraries support arbitrary object construction and are equivalent to `pickle`.

XML deserialization shall be configured per the Input Validation guideline (XXE prevention) and shall not bind to arbitrary classes via type attributes.

### Type Restrictions

Where a typed deserializer is used (Jackson with `@JsonTypeInfo`, .NET `JsonSerializer` with `TypeNameHandling`, Java serialization), the set of acceptable types shall be restricted to an explicit allowlist. Denylists have repeatedly been bypassed and are not acceptable.

Polymorphic deserialization shall use a sealed type hierarchy where the language supports it (`sealed` classes in Java 17+, `Union` types in Python with discriminator fields).

### Integrity

Serialized data persisted or transmitted across trust boundaries shall be authenticated. Use a MAC (HMAC) or signature appropriate to the trust model. Verification shall happen before parsing.

Cookies, session tokens, and similar serialized blobs shall be authenticated. Many frameworks provide signed cookies (Django, Flask); use them and never trust unsigned serialized data from a client.

### Input Constraints

Maximum sizes shall be enforced on serialized payloads. Deeply nested or expansive payloads can produce denial of service even without code execution.

Parser depth limits shall be configured for nested structures.

## 4. Language-Specific Guidance

### 4.1 Java

Java's built-in serialization (`ObjectInputStream`) is fundamentally unsafe for untrusted input. Replace it with JSON or another format. Where it remains in legacy code:

- Use `ObjectInputFilter` (Java 9+, also available via `JEP 290`) to restrict deserializable classes:

~~~java
var filter = ObjectInputFilter.Config.createFilter(
    "com.example.app.dto.*;java.util.ArrayList;!*");
ObjectInputFilter.Config.setSerialFilter(filter);
~~~

- Configure a global filter via the `jdk.serialFilter` system property.

For Jackson, do not enable `enableDefaultTyping` or `activateDefaultTyping`. If polymorphic deserialization is needed, use `@JsonTypeInfo` with `JsonTypeInfo.Id.NAME` and an explicit `@JsonSubTypes` enumeration:

~~~java
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
@JsonSubTypes({
    @JsonSubTypes.Type(value = TextMessage.class, name = "text"),
    @JsonSubTypes.Type(value = ImageMessage.class, name = "image"),
})
public sealed interface Message permits TextMessage, ImageMessage { }
~~~

For SnakeYAML, use `SafeConstructor` or migrate to `snakeyaml-engine` with strict configuration.

XStream requires explicit `addPermission` configuration; the default has been hardened but explicit configuration is required.

### 4.2 Python

`pickle`, `cPickle`, `dill`, `shelve`, and `marshal` shall not be used to deserialize untrusted data. They are equivalent to executing arbitrary Python code.

For YAML, use `yaml.safe_load`:

~~~python
import yaml
data = yaml.safe_load(stream)  # never yaml.load without SafeLoader
~~~

For JSON, the standard library `json` module is safe by default. For Pydantic, use strict types and `model_config = ConfigDict(extra="forbid")` to reject unknown fields.

For polymorphic JSON deserialization in Pydantic v2, use discriminated unions:

~~~python
class TextMessage(BaseModel):
    type: Literal["text"]
    body: str

class ImageMessage(BaseModel):
    type: Literal["image"]
    url: str

Message = Annotated[Union[TextMessage, ImageMessage], Field(discriminator="type")]
~~~

For Django, signed cookies and session backends use HMAC; rely on these rather than custom serialization.

For Celery and similar task queues, configure `task_serializer = "json"` and `accept_content = ["json"]`. Never accept `pickle` from worker queues.

### 4.3 C

C does not have language-level serialization, but deserialization vulnerabilities arise in parsers (JSON, XML, custom binary formats, Protocol Buffers, ASN.1).

Use vetted parsers with depth and size limits configured. Hand-rolled binary parsers shall be fuzzed before use.

For ASN.1, use a recent OpenSSL or libtasn1 version and apply size limits. ASN.1 parsing bugs have been a recurring source of CVEs across the ecosystem.

For HMAC verification on serialized data, use libsodium's `crypto_auth_hmacsha256` and compare with `sodium_memcmp` (constant time). Never use `memcmp` for MAC comparison.

### 4.4 C++

The C guidance applies. For C++ serialization libraries (Boost.Serialization, cereal, Protocol Buffers C++), prefer Protocol Buffers or Cap'n Proto, which have well-defined schemas and no polymorphism via stream content.

Boost.Serialization shall not be used on untrusted input. It supports class registration that lets attackers select classes.

For JSON, nlohmann/json and RapidJSON are safe by default. Configure size and depth limits.

## 5. Verification

Static analysis shall flag use of unsafe deserializers (`pickle`, `yaml.load`, `ObjectInputStream`, `BinaryFormatter`). SAST rules for CWE-502 shall be enabled. Dependency scanning shall flag known-vulnerable deserialization libraries. Fuzzing shall be applied to all parsers that consume external input. Penetration testing shall include deserialization payloads targeted at the deserializers in use. Periodic review shall confirm no new deserialization sites have been introduced without integrity protection.

## 6. References

- OWASP ASVS v4.0.3, V5.5
- OWASP Top 10 2021, A08
- OWASP Deserialization Cheat Sheet
- CWE-502, CWE-915
- ysoserial, ysoserial.net (gadget chains, for defensive understanding)
