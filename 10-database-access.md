# Secure Coding Guidelines: Database Access and Query Construction

## 1. Purpose and Scope

This section establishes requirements for secure database access in applications. SQL injection remains one of the most damaging classes of application vulnerability and is among the easiest to prevent with disciplined query construction. This guideline also covers NoSQL injection, ORM use, connection management, and database-side controls accessible from application code.

These guidelines map to OWASP ASVS V5.3 (Output Encoding and Injection Prevention), OWASP Top 10 2021 A03 (Injection), PCI DSS 4.0 Requirement 6.2.4, and CWE-89 (SQL Injection), CWE-943 (Improper Neutralization in Data Query Logic).

## 2. General Principles

All queries shall be parameterized. The query structure shall be defined statically; user input shall be supplied only as bound parameters. String concatenation, format strings, and template substitution into query text with user input are prohibited.

Database connections shall use least-privilege accounts. The application's runtime database user shall not have schema modification (DDL), administrative, or cross-tenant privileges. Separate users shall be used for migrations.

The application's database account credentials shall be loaded from the secrets management system per the Secrets Management guideline.

## 3. Normative Requirements

### Query Construction

All queries containing user-influenced data shall use parameterized queries (prepared statements). The database driver shall handle escaping. Application code shall not perform manual escaping.

Dynamic identifiers (table names, column names, sort directions, schema names) shall be validated against an allowlist before incorporation into a query. The database driver typically does not provide parameterization for identifiers; the application is responsible.

Dynamic ORDER BY direction (ASC/DESC), LIMIT/OFFSET values, and similar shall be validated as enums or numeric ranges, not passed through unvalidated.

Stored procedures shall be parameterized internally; calling a stored procedure does not by itself prevent injection if the procedure builds dynamic SQL from its parameters.

### NoSQL

NoSQL queries (MongoDB, DynamoDB, Cosmos DB, Redis) shall use the driver's parameterized query API. Server-side JavaScript evaluation (`$where`, `mapReduce`) with user input is prohibited.

For document databases, validate that user input is of the expected scalar type before use in queries. Many NoSQL injection attacks exploit the ability to pass an object where a scalar was expected (`{"$ne": ""}` for password fields, for example).

### Connection Management

Connections shall be pooled and lifecycle-managed. Connection leaks shall be detected and addressed. The pool size shall be tuned to the application's concurrency model and the database's capacity.

TLS shall be required for database connections traversing untrusted networks. For cloud-managed databases, enforce TLS in the database configuration in addition to client configuration.

Statement timeouts shall be configured to bound the impact of pathological queries. Per-statement timeouts at the application level and `statement_timeout` at the database level both apply.

### Database-Side Controls

Row-level security shall be used where the database supports it (PostgreSQL RLS, SQL Server RLS) for multi-tenant or per-user data isolation, as a defense-in-depth layer beneath application-level authorization.

Sensitive columns shall be encrypted at the application layer per the Data Protection guideline. Column-level encryption in the database is acceptable for some categories but does not defend against application-level access by the runtime user.

Audit logging at the database level shall be enabled for sensitive data access and for administrative actions. Application-level audit logging per the Application Logging guideline does not replace database-level audit.

### Migrations and Schema

Schema migrations shall be applied via a documented tool (Flyway, Liquibase, Alembic, Django migrations, Rails migrations). Manual `ALTER TABLE` in production is prohibited.

Migrations shall be reviewed for security implications: introduction of columns holding sensitive data, removal of constraints, changes to indexes that affect query patterns.

The migration user shall have schema privileges; the runtime user shall not.

## 4. Language-Specific Guidance

### 4.1 Java

Use `PreparedStatement` with `?` placeholders for plain JDBC:

~~~java
try (var stmt = conn.prepareStatement("SELECT id, email FROM users WHERE org_id = ? AND active = ?")) {
    stmt.setLong(1, orgId);
    stmt.setBoolean(2, true);
    try (var rs = stmt.executeQuery()) {
        // ...
    }
}
~~~

For JPA, use named parameters (`:name`) or positional parameters (`?1`) with `Query.setParameter`. Avoid `EntityManager.createNativeQuery` with concatenated input.

For JOOQ, the DSL produces parameterized queries automatically. `DSL.field(String)` with user input is the escape hatch and shall be guarded by an allowlist.

For sort columns, define an enum and convert:

~~~java
public enum SortColumn {
    ID("id"), CREATED("created_at"), NAME("name");
    private final String column;
    SortColumn(String c) { this.column = c; }
    public String column() { return column; }
}
~~~

For HikariCP connection pool, set `connectionTimeout`, `maximumPoolSize`, `leakDetectionThreshold`, and `validationTimeout` explicitly. Use `dataSource.serverName`-style properties; do not concatenate the JDBC URL with user input.

For database TLS, set `sslmode=verify-full` (PostgreSQL JDBC) or equivalent.

### 4.2 Python

For raw DB-API access (psycopg, mysqlclient, sqlite3), always use parameterized queries:

~~~python
# psycopg2/psycopg3
cur.execute("SELECT id, email FROM users WHERE org_id = %s AND active = %s", (org_id, True))
~~~

The exact parameter style varies by driver (`%s`, `?`, `:name`). Use the driver's style consistently.

For SQLAlchemy ORM, use the query API. For Core, use the `text()` construct with bound parameters via `:name`:

~~~python
stmt = text("SELECT id FROM users WHERE email = :email")
result = conn.execute(stmt, {"email": email})
~~~

Avoid `.format()` and f-strings in any SQL construction. The SQLAlchemy 2.x query API makes this hard to get wrong; use it.

For Django ORM, the QuerySet API is parameterized. `extra()` and `RawSQL()` accept parameter dicts; use them. `Manager.raw()` should be avoided.

For MongoDB with PyMongo, ensure that user input intended as a scalar is typed before query construction. Pydantic input validation at the API boundary covers this. Filter dictionaries shall be constructed in code; do not pass user-controlled dictionaries directly into `find()`.

### 4.3 C

Use the database driver's prepared statement API. For libpq:

~~~c
const char *params[] = { org_id_str, NULL };
PGresult *res = PQexecParams(conn,
    "SELECT id, email FROM users WHERE org_id = $1",
    1, NULL, params, NULL, NULL, 0);
~~~

For SQLite, use `sqlite3_prepare_v2` followed by `sqlite3_bind_*` and `sqlite3_step`. Do not use `sqlite3_exec` with concatenated SQL.

For MySQL, use `mysql_stmt_prepare` with `mysql_stmt_bind_param`. Do not use `mysql_query` with concatenated input.

Manage connection lifetime explicitly. Wrap connection acquisition and release in a consistent pattern; track open statements to ensure they are finalized.

Set query timeouts via the driver-specific mechanism (`PGconn` parameter `statement_timeout`, `sqlite3_busy_timeout`, `mysql_options` with `MYSQL_OPT_READ_TIMEOUT`).

### 4.4 C++

Use a C++ database library: libpqxx for PostgreSQL, SOCI for cross-database access, or the MySQL Connector/C++. These provide parameterized query APIs:

~~~cpp
pqxx::work tx{conn};
auto result = tx.exec_params(
    "SELECT id, email FROM users WHERE org_id = $1 AND active = $2",
    org_id, true);
tx.commit();
~~~

For ORMs (sqlpp11, ODB), use the type-safe query construction. These libraries make injection nearly impossible if used as intended.

RAII shall manage transaction lifetime. A transaction object's destructor shall roll back if not explicitly committed. Most libraries follow this convention; verify in the library you use.

Connection pooling can be implemented with a class wrapping the pool and returning RAII handles. Several libraries provide this (e.g., libpqxx's `connection_pool` extension).

## 5. Verification

Static analysis shall flag SQL string concatenation and format strings. SAST rules for CWE-89 and CWE-943 shall be enabled. Database query logs in development and staging shall be reviewed for unexpected query patterns. Penetration testing shall include SQL injection attempts (manual and automated via SQLMap) on all parameters. ORM use shall be reviewed for unsafe escape hatches. Database user privilege grants shall be audited annually against least-privilege expectations.

## 6. References

- OWASP ASVS v4.0.3, V5.3
- OWASP Top 10 2021, A03
- OWASP SQL Injection Prevention Cheat Sheet
- OWASP Query Parameterization Cheat Sheet
- PCI DSS v4.0, Requirement 6.2.4
- CWE-89, CWE-943, CWE-564
- CERT Secure Coding: IDS00-J
