# Secure Coding Guidelines: File Handling and Uploads

## 1. Purpose and Scope

This section establishes requirements for handling files within applications: reading from disk, writing to disk, accepting uploads, serving downloads, and processing untrusted file content. File handling combines several common vulnerability classes: path traversal, arbitrary file upload, deserialization, XXE, zip-slip, and resource exhaustion.

These guidelines map to OWASP ASVS V12 (Files and Resources), OWASP Top 10 2021 A01 and A05, PCI DSS 4.0 Requirement 6.2, and CWE-22 (Path Traversal), CWE-23, CWE-73, CWE-434 (Unrestricted Upload of File with Dangerous Type), CWE-552, and CWE-409 (Improper Handling of Highly Compressed Data).

## 2. General Principles

Untrusted file content is untrusted input. File names, file paths, file contents, file metadata (EXIF, document properties), and archive structure are all subject to validation.

Files received from clients shall be treated as adversarial. Type, size, name, and content shall all be checked. Server-side determination of type from content shall take precedence over client-claimed MIME type or extension.

Uploaded files shall be stored outside the web-served directory and shall not be executed. Where files must be served back to users, they shall be served with appropriate `Content-Type`, `Content-Disposition`, and `X-Content-Type-Options: nosniff` headers.

## 3. Normative Requirements

### Path Construction

File paths constructed from user input shall be canonicalized and verified to remain within an allowed base directory. Canonicalization shall resolve `.`, `..`, symbolic links, and platform-specific path constructs.

The check shall be performed on the canonical path against the canonical base, using a prefix comparison that accounts for directory boundaries. A naive `startsWith` check on path strings has been the source of multiple historical CVEs; use the platform's path API (`Path.toRealPath`, `realpath`, `os.path.realpath`).

User-supplied filenames shall not be used directly as on-disk filenames. Instead, generate an opaque identifier and store the original filename as metadata.

Reserved names on Windows (CON, PRN, AUX, NUL, COM1-9, LPT1-9, with or without extension) shall be rejected. Names beginning with `.` shall be rejected unless explicitly allowed. Path separators in user-supplied filenames shall be rejected.

### Upload Handling

Maximum file size shall be enforced at the proxy layer, the application framework layer, and within request body parsing. Multiple layers prevent a single misconfiguration from allowing unbounded uploads.

File type shall be verified by inspecting content (magic bytes), not by trusting extension or client-supplied MIME type. Use a vetted library (Apache Tika, libmagic, python-magic) for type detection.

Uploaded files shall be scanned for malware where the threat model warrants it. ClamAV, commercial AV APIs, or cloud-provided scanning services are options. Scanning shall occur before the file is made available to other users.

Image files shall be re-encoded server-side to strip embedded scripts and metadata, and to defeat polyglot files. Office documents and PDFs shall be processed in sandboxed environments if their content will be rendered or extracted.

Where files are accepted for processing (parsing, conversion), processing shall occur in a constrained environment: low-privilege user, resource limits (CPU, memory, file descriptors), no network access except to required services, and timeouts.

### Archive Extraction

Archive extraction shall guard against path traversal (zip-slip), zip-bomb (compression ratio attack), and excessive entry count. Validate each entry's resolved path before writing. Cap the total uncompressed size and entry count.

### Output and Download

Files served to users shall have `X-Content-Type-Options: nosniff`. User-uploaded files shall be served with `Content-Disposition: attachment` unless the file is known-safe and rendering is required.

User-uploaded content shall be served from a separate domain or subdomain where session cookies are not scoped, to defeat XSS via uploaded HTML or SVG.

### Temporary Files

Temporary files shall be created with secure permissions (mode 0600 or equivalent) and in a directory not writable by other users (`/tmp` is acceptable on Linux with `O_CREAT | O_EXCL`). Use `mkstemp`, `tempfile.NamedTemporaryFile`, `Files.createTempFile`, or `std::filesystem` with explicit permission setting.

Temporary files shall be cleaned up on all exit paths, including error paths.

## 4. Language-Specific Guidance

### 4.1 Java

For path construction, use `java.nio.file.Path` and `Path.normalize` followed by a verified prefix check:

~~~java
Path base = Paths.get("/var/app/uploads").toRealPath();
Path target = base.resolve(userInput).normalize().toRealPath();
if (!target.startsWith(base)) {
    throw new SecurityException("path traversal");
}
~~~

For uploads in Spring Boot, configure `spring.servlet.multipart.max-file-size` and `max-request-size`. Validate uploaded files in the controller before persisting.

For file type detection, use Apache Tika:

~~~java
Tika tika = new Tika();
String type = tika.detect(inputStream);
~~~

For image re-encoding, use `javax.imageio.ImageIO.read` followed by `ImageIO.write` to a chosen format. This strips metadata and rejects malformed inputs.

For ZIP extraction, validate each entry:

~~~java
try (var zip = new ZipInputStream(in)) {
    ZipEntry entry;
    while ((entry = zip.getNextEntry()) != null) {
        Path resolved = base.resolve(entry.getName()).normalize();
        if (!resolved.startsWith(base)) throw new SecurityException("zip slip");
        // also check size, count
    }
}
~~~

For temporary files, use `Files.createTempFile` with `PosixFilePermissions` explicitly set on POSIX systems.

### 4.2 Python

For path construction, use `pathlib.Path` with `resolve` and an explicit base check:

~~~python
from pathlib import Path
base = Path("/var/app/uploads").resolve()
target = (base / user_input).resolve()
if not target.is_relative_to(base):  # Python 3.9+
    raise PermissionError("path traversal")
~~~

For uploads in Flask, configure `MAX_CONTENT_LENGTH` and use `werkzeug.utils.secure_filename` as a baseline; do not rely on it as the sole control.

For Django, use `FileField` with explicit `validators` and a custom storage class that strips dangerous attributes. Configure `DATA_UPLOAD_MAX_MEMORY_SIZE` and `FILE_UPLOAD_MAX_MEMORY_SIZE`.

For type detection, use `python-magic`:

~~~python
import magic
mime = magic.from_buffer(data, mime=True)
~~~

For image re-encoding, use Pillow with the `Image.open` then `save` pattern, and verify with `Image.verify` first. Be aware that Pillow has had its own CVEs; keep current.

For ZIP, use `zipfile.ZipFile` and validate entries before extracting. Cap `file_size` and `compress_size`.

For temporary files, `tempfile.NamedTemporaryFile` creates with mode 0600 by default on POSIX.

### 4.3 C

For path construction, use `realpath(3)` and prefix-check the result. Be aware of `realpath`'s buffer size requirements and the `PATH_MAX` limitations.

Use the `*at` family of system calls (`openat`, `unlinkat`, `mkdirat`) anchored on an opened directory file descriptor. This prevents TOCTOU races between path resolution and the operation.

~~~c
int dirfd = open("/var/app/uploads", O_DIRECTORY | O_RDONLY);
int fd = openat(dirfd, user_filename, O_CREAT | O_WRONLY | O_NOFOLLOW | O_EXCL, 0600);
~~~

`O_NOFOLLOW` prevents symlink traversal at the final component. `O_EXCL` prevents overwriting existing files.

For temporary files, `mkstemp` creates with mode 0600. Use `mkostemp` with `O_CLOEXEC` to prevent leakage across `exec`.

Be cautious with `tmpnam` and `tempnam`; they are vulnerable to TOCTOU races. Do not use.

For file size limits, set `RLIMIT_FSIZE` for child processes that write files.

### 4.4 C++

Use `std::filesystem` (C++17+) with care: `std::filesystem::canonical` performs the equivalent of `realpath`. Wrap operations in try/catch since filesystem operations throw on error.

~~~cpp
auto base = std::filesystem::canonical("/var/app/uploads");
auto target = std::filesystem::weakly_canonical(base / user_input);
if (target.string().rfind(base.string() + "/", 0) != 0) {
    throw std::runtime_error("path traversal");
}
~~~

For race-free operations, fall back to the POSIX `*at` family via `<fcntl.h>` when `std::filesystem`'s race semantics are insufficient.

For temporary files, `std::filesystem::temp_directory_path` returns the directory but does not create a file. Use `mkstemp` from C or a Boost.Filesystem equivalent.

For uploads, use the web framework's multipart parser with size limits set explicitly. Validate type with libmagic.

## 5. Verification

Static analysis shall flag path construction from user input without canonicalization, use of `tmpnam`, and string-based `startsWith` checks for path containment. Penetration testing shall include path traversal payloads, zip-slip archives, oversized uploads, polyglot files, and uploads of files with executable extensions. Upload size limits shall be tested at each enforcement layer. Type detection shall be tested with content/extension mismatches.

## 6. References

- OWASP ASVS v4.0.3, V12
- OWASP Top 10 2021, A01, A05
- OWASP File Upload Cheat Sheet
- OWASP Path Traversal Article
- PCI DSS v4.0, Requirement 6.2
- CWE-22, CWE-23, CWE-73, CWE-434, CWE-552, CWE-409
- CERT Secure Coding: FIO01-J, FIO02-C, FIO15-C, FIO16-J
