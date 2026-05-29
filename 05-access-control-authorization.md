# Secure Coding Guidelines: Access Control and Authorization

## 1. Purpose and Scope

This section establishes requirements for enforcing access control in applications developed or maintained by Artais Security. Broken access control is consistently the highest-ranked category in the OWASP Top 10 and is the root cause of most data exposure incidents. This guideline covers authorization models, enforcement points, and common access control failure modes.

These guidelines map to OWASP ASVS V4 (Access Control), OWASP Top 10 2021 A01 (Broken Access Control), OWASP API Security Top 10 API1 (BOLA) and API5 (BFLA), PCI DSS 4.0 Requirement 7, HIPAA §164.312(a)(1), NIST SP 800-53 AC family, and CWE-284, CWE-285, CWE-639, CWE-862, CWE-863.

## 2. General Principles

Access control decisions shall be made server-side at every protected operation. The client may use authorization information to render appropriate UI, but the server shall never trust the client's assertion of permission.

Authorization shall be enforced on every request, not only on initial navigation or session establishment. Each handler shall determine the authenticated principal, the requested resource, and the requested action, and shall consult the authorization policy.

Default-deny shall be the policy. Resources without an explicit allow rule shall be inaccessible. Listing or enumeration of resources shall require the same authorization as access.

The authorization model — RBAC, ABAC, ReBAC, or a hybrid — shall be documented in the system's security design. The model shall be implemented in a single, testable policy module rather than scattered through handlers.

## 3. Normative Requirements

The principle of least privilege shall apply to all principals: users, services, and processes shall be granted the minimum permissions necessary for their function. Standing administrative access shall be replaced with just-in-time elevation where feasible.

Object-level authorization (preventing access to resources owned by others) shall be enforced on every read, write, update, and delete. Indirect object references via opaque identifiers do not substitute for authorization; the server shall verify ownership or permission even when the identifier appears unguessable.

Function-level authorization shall be enforced. Administrative endpoints shall not be accessible to non-administrative users regardless of UI gating. URL paths, HTTP methods, and parameter combinations are all access-controlled surfaces.

Server-to-server calls shall authenticate the calling service and authorize the action. "Internal network" is not an access control boundary in modern architectures. Zero-trust principles apply.

Authorization decisions shall be logged at the granularity defined in the Application Logging guideline. Denied access shall be logged with the principal, the resource, the requested action, and the policy decision rationale.

Privilege escalation paths — role changes, group membership changes, permission grants — shall require additional authorization (the principal performing the change must themselves have permission to grant) and shall be logged as security events.

Time-of-check vs. time-of-use (TOCTOU) shall be avoided in authorization decisions. The decision shall be made against the same data that the action consumes.

## 4. Language-Specific Guidance

### 4.1 Java

Use Spring Security method-level authorization with `@PreAuthorize` and `@PostAuthorize` annotations, backed by a policy expression language or by a custom `PermissionEvaluator`. Class-level or controller-level annotations are insufficient because they miss methods added later; annotate every method explicitly.

For object-level authorization, implement a `PermissionEvaluator` that takes the resource and action and consults the domain model. Avoid embedding ownership checks inline; they get forgotten:

~~~java
@PreAuthorize("hasPermission(#documentId, 'Document', 'read')")
public Document getDocument(UUID documentId) { ... }
~~~

For more complex policies, integrate an external policy engine (Open Policy Agent via REST, Casbin) and treat policy as code with its own review and testing.

Avoid the deprecated `@Secured` and role-only checks for non-trivial systems; they encode role names in code and cannot express object-level constraints.

For URL-based authorization, define rules in `SecurityFilterChain` configuration and treat any unmatched path as `denyAll()`.

### 4.2 Python

In Django, use the permissions framework and object-level permissions via `django-guardian` or a custom permission backend. Decorate views with `@permission_required` or use DRF's `permission_classes`. Implement `has_object_permission` on every DRF viewset that handles user-owned resources.

In Flask, use Flask-Principal or implement decorators that check permissions before the handler runs. For object-level checks, fetch the resource first and verify ownership before performing the action; failing to do so is the root cause of IDOR vulnerabilities:

~~~python
@app.route("/documents/<doc_id>")
@login_required
def get_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if doc.owner_id != current_user.id and not current_user.is_admin:
        abort(403)
    return render(doc)
~~~

In FastAPI, use dependency injection for authorization. A `Depends(require_permission("document:read"))` pattern makes authorization explicit at every endpoint. Combine with a policy engine for non-trivial systems.

For policy engines, `oso` provides a Python-native policy language; OPA can be called over HTTP with `opa-python-client`.

### 4.3 C

C applications enforcing access control typically do so against system primitives (POSIX permissions, capabilities, SELinux, AppArmor). Application-level RBAC in C is rare and error-prone.

Where it is implemented, use a table-driven approach with the policy in configuration, not in code. Drop privileges with `setuid`, `setgid`, and `setgroups` early in process startup; verify the drop succeeded by attempting to re-acquire (which should fail) before proceeding.

For file access, use `openat`, `faccessat`, and `*at` family functions to avoid TOCTOU races between path resolution and access. Do not use `access(2)` followed by `open(2)`; check permissions on the open file descriptor instead.

For network services, bind to localhost where the service is internal; firewall rules are an additional layer, not a substitute for application binding.

### 4.4 C++

Apply the C guidance. For application-level authorization, use a policy framework rather than embedding checks. `cpprestsdk` and other frameworks provide hooks; use them.

RAII can model authorized scopes: an `AuthorizedContext` acquired at handler entry, holding a reference to the policy decision, and consulted by downstream code. This makes it harder to forget the check, because the resource needed for the operation is the context object itself.

Be cautious with C++ exceptions in authorization paths. A throw from within an authorization check must not leave the application in a state where the denied action could still proceed. Use `[[nodiscard]]` on policy decision return types.

## 5. Verification

Static analysis shall identify handlers lacking authorization annotations or decorators. A coverage report listing every handler and its associated policy shall be reviewed at each release. Dynamic testing shall include horizontal access (User A accessing User B's resources) and vertical access (non-admin attempting admin actions) tests for every endpoint. Authorization fuzzing tools (Burp Autorize, IAST plugins) shall be used. Code review shall verify that object-level checks are present for every handler that operates on user-owned resources.

## 6. References

- OWASP ASVS v4.0.3, V4
- OWASP Top 10 2021, A01
- OWASP API Security Top 10, API1 and API5
- OWASP Authorization Cheat Sheet
- PCI DSS v4.0, Requirement 7
- HIPAA Security Rule, 45 CFR §164.312(a)(1)
- NIST SP 800-53 Rev. 5, AC control family
- CWE-284, CWE-285, CWE-639, CWE-862, CWE-863
