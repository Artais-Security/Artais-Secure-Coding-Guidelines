# Secure Coding Guidelines: Input Validation and Output Encoding

## 1. Purpose and Scope

This section establishes requirements for validating untrusted input and encoding output across all applications developed or maintained by Artais Security. Input validation and output encoding are the primary defenses against injection attacks (SQL, command, LDAP, XPath, XSS), and their absence is the root cause of the majority of high-severity application vulnerabilities reported each year.

These guidelines map to OWASP ASVS V5 (Validation, Sanitization, and Encoding), OWASP Top 10 2021 A03 (Injection), PCI DSS 4.0 Requirement 6.2.4, NIST SP 800-53 SI-10 (Information Input Validation), CWE-20, CWE-79, CWE-89, CWE-78, CWE-94, and CERT Secure Coding rules IDS00-J, IDS01-PL, and STR02-C.

## 2. General Principles

All input from outside the trust boundary of the application is untrusted. This includes HTTP request data, file contents, environment variables, database results from systems shared with other applications, message queue payloads, and inter-service RPC arguments. Trust is not transitive: data that was validated by a peer service shall be revalidated at the receiving boundary.

Validation occurs as close to the trust boundary as possible and shall be performed on the server. Client-side validation is acceptable as a usability aid only; it is never a security control. Validation shall be positive (allowlist) wherever the input domain is known. Negative (denylist) validation is permitted only when the input domain is open-ended and a denylist is the only feasible approach; in such cases, the denylist shall be documented and reviewed.

Output encoding is the dual of input validation. Data crossing an output boundary into another interpreter — HTML, JavaScript, SQL, shell, LDAP, XML, JSON, OS command — shall be encoded for that specific interpreter using a context-aware encoder. Concatenating data into a query, command, or markup string is prohibited.

## 3. Normative Requirements

Input shall be validated for type, length, range, format, and semantic content. Strings shall have a maximum length enforced before any further processing. Numeric inputs shall be range-checked. Enumerated values shall be matched against the allowed set. Structured inputs (JSON, XML, YAML) shall be parsed with a hardened parser, with external entity processing, recursive expansion, and unbounded depth disabled.

Canonicalization shall precede validation. Decoding (URL, HTML entity, Unicode, percent, base64) shall be performed to a single canonical form before any validation rule is applied, to prevent double-encoding bypasses. After canonicalization, the validated value shall be used; the original encoded form shall not be reintroduced later in the request lifecycle.

Output encoding shall be performed by a vetted, context-aware library, not by hand-rolled escape functions. The encoder shall match the output context exactly: HTML body, HTML attribute, JavaScript string literal, JavaScript identifier, CSS value, URL component, SQL identifier, shell argument. Mixing contexts is a defect.

Parameterized queries (prepared statements) shall be used for all database access. Dynamic SQL string construction with user input is prohibited. Where a query requires a dynamic identifier (table or column name), the identifier shall be matched against an allowlist.

For OS commands, the application shall invoke programs directly with argument arrays via APIs that do not invoke a shell. Where a shell is unavoidable, all arguments shall be quoted and validated against a strict allowlist.

## 4. Language-Specific Guidance

### 4.1 Java

Use the Bean Validation API (Jakarta Validation, formerly JSR-380) with Hibernate Validator for declarative input validation at the controller boundary. Annotate DTOs with `@NotNull`, `@Size`, `@Pattern`, `@Min`, `@Max`, `@Email`, and custom constraints; annotate handler parameters with `@Valid`.

For database access, use `PreparedStatement` with `?` placeholders, JPA criteria queries, or JOOQ. String concatenation into JDBC `Statement` is prohibited. For dynamic identifiers, use an allowlist:

~~~java
private static final Set<String> SORT_COLUMNS = Set.of("id", "created_at", "name");
String sortColumn = SORT_COLUMNS.contains(input) ? input : "id";
~~~

For HTML output, use the template engine's contextual auto-escaping (Thymeleaf, JSP with `<c:out>`, Mustache). For manual encoding, use OWASP Java Encoder (`Encode.forHtml`, `Encode.forHtmlAttribute`, `Encode.forJavaScript`, `Encode.forUriComponent`). Do not use `StringEscapeUtils` for security-relevant encoding; its escaping is not context-aware.

For XML, disable external entity processing on `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, and `TransformerFactory`. The OWASP XXE Prevention Cheat Sheet enumerates the required feature flags per parser.

For OS commands, use `ProcessBuilder` with an argument list. Never pass user input to `Runtime.exec(String)`, which tokenizes on whitespace.

### 4.2 Python

Validate request bodies and query parameters with Pydantic (FastAPI), Marshmallow (Flask), or Django forms/serializers. Define explicit field types, constraints, and validators. Reject unknown fields by default (`model_config = ConfigDict(extra="forbid")` in Pydantic v2).

For database access, use parameterized queries via the DB-API:

~~~python
# CORRECT
cursor.execute("SELECT * FROM users WHERE email = %s", (email,))

# WRONG — SQL injection
cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")
~~~

When using an ORM (SQLAlchemy, Django ORM), use the ORM's query API rather than `text()` or raw SQL. If `text()` is necessary, bind parameters with `:name` placeholders.

For HTML output, rely on the template engine's autoescape (Jinja2 with `autoescape=True`, Django templates by default). For manual encoding, use `markupsafe.escape` for HTML body context. For other contexts (JavaScript, URL, CSS), use a context-aware library; do not improvise.

For XML, use `defusedxml` in place of `xml.etree`, `xml.sax`, or `lxml` defaults. For YAML, use `yaml.safe_load`, never `yaml.load` without a SafeLoader.

For subprocess invocation, pass arguments as a list and never set `shell=True` with user input:

~~~python
# CORRECT
subprocess.run(["/usr/bin/convert", input_path, output_path], check=True)

# WRONG — shell injection
subprocess.run(f"convert {input_path} {output_path}", shell=True)
~~~

### 4.3 C

Input validation in C requires special attention to integer overflow, buffer bounds, and string termination. Length checks shall precede any copy or arithmetic. Use `size_t` for sizes and check for overflow before allocation:

~~~c
if (count > SIZE_MAX / sizeof(item_t)) {
    /* would overflow */
    return -1;
}
items = calloc(count, sizeof(item_t));
~~~

Use bounded string functions: `snprintf`, `strncpy` with explicit null termination, or safer wrappers (`strlcpy`, `strlcat` on BSD/musl, or implementations from a vetted utility library). Check return values of all I/O and parsing functions.

For SQL access from C, use the database driver's parameter binding API (`PQexecParams` in libpq, `sqlite3_bind_*` in SQLite, `mysql_stmt_bind_param` in MySQL). Never construct SQL via `sprintf`.

For shell command execution, prefer `execve` with an argument vector. `system()` and `popen()` invoke a shell and are prohibited for any command incorporating untrusted data.

Validate all integer conversions. `atoi` provides no error indication; use `strtol` and check `errno`, `endptr`, and range bounds.

### 4.4 C++

The C guidance applies. In addition, prefer `std::string` and `std::string_view` over C strings, and use the standard library's bounded operations.

For parsing, use a vetted library (RapidJSON, nlohmann/json, Boost.PropertyTree with caution) and configure depth and size limits. Do not write hand-rolled parsers for security-sensitive formats.

For database access, use prepared statements via the driver's C++ binding (libpqxx, mysqlx, SOCI). For ORMs (sqlpp11, ODB), use parameterized query APIs.

For command execution, use `boost::process` or a direct `posix_spawn`/`execve` wrapper. Avoid `std::system`.

For HTML or other output, do not write encoding by hand. Use a vetted library (CTML for HTML construction is not security-focused; integrate with a templating engine that auto-escapes).

Apply `[[nodiscard]]` to validation functions so that callers cannot silently drop the result.

## 5. Verification

Static analysis shall flag string concatenation into SQL, shell, or markup contexts. SAST rules for CWE-89, CWE-78, CWE-79, and CWE-20 shall be enabled and tuned. Dynamic testing shall include fuzzing of all external input surfaces. Code review shall verify that every external input is validated at the boundary and that every output crossing an interpreter boundary is encoded appropriately. Penetration testing shall include injection attempts in all input fields.

## 6. References

- OWASP ASVS v4.0.3, V5
- OWASP Top 10 2021, A03
- OWASP Input Validation, XSS Prevention, SQL Injection Prevention, XXE Prevention Cheat Sheets
- PCI DSS v4.0, Requirement 6.2.4
- NIST SP 800-53 Rev. 5, SI-10
- CWE-20, CWE-78, CWE-79, CWE-89, CWE-94, CWE-643, CWE-611
- CERT Secure Coding: IDS00-J, IDS01-PL, STR02-C, INT04-C
