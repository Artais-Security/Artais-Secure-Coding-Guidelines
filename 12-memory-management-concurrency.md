# Secure Coding Guidelines: Memory Management and Safe Concurrency

## 1. Purpose and Scope

This section establishes requirements for safe memory management and concurrent programming. Memory safety defects (use-after-free, buffer overflow, double-free) and concurrency defects (race conditions, TOCTOU, deadlock) account for a substantial share of severe vulnerabilities in C and C++ code and remain possible in higher-level languages through unsafe constructs or framework misuse.

These guidelines map to OWASP ASVS V5 and V11, NIST SP 800-53 SI-16, and CWE-119, CWE-120, CWE-125, CWE-362 (Race Condition), CWE-367 (TOCTOU), CWE-401 (Memory Leak), CWE-415 (Double Free), CWE-416 (Use After Free), CWE-476 (NULL Pointer Dereference), and CERT Secure Coding rules in the MEM, CON, and ARR sections.

## 2. General Principles

Memory safety is non-negotiable. Where a memory-safe language is feasible, it is preferred over C and C++. Where C or C++ is required, the project shall adopt a documented memory safety strategy combining compiler features, runtime sanitizers, static analysis, and code review.

Concurrent code shall be designed with explicit synchronization. Sharing data across threads without synchronization is undefined behavior in C++ and a data race in nearly all languages. The default for shared mutable state shall be locked; reasoning about lock-free code requires expertise that shall be documented and reviewed.

## 3. Normative Requirements

### Memory Management

All allocations shall have a clearly defined owner and lifetime. RAII (C++), `try-with-resources` (Java), `with` (Python), or explicit `goto cleanup` (C) shall guarantee cleanup on all paths.

Bounds checking shall be enforced on all buffer accesses. Where the language does not check by default (C, C++ raw arrays), the application shall validate indices before access.

Use-after-free shall be prevented by clear ownership models. In C++, prefer `std::unique_ptr` and `std::shared_ptr` over raw owning pointers. In C, set pointers to NULL after free where the pointer remains in scope and could be reused.

Integer operations on sizes shall guard against overflow. Multiplication of count by element size shall be checked before use in allocation.

Sensitive data in memory shall be zeroized after use using a function the compiler cannot eliminate (`explicit_bzero`, `sodium_memzero`, `memset_s`).

### Concurrency

Shared mutable state shall be protected by a lock, an atomic, or a higher-level synchronization primitive (channel, queue). The protection mechanism shall be documented at the declaration of the shared data.

Lock acquisition order shall be consistent across the codebase to prevent deadlock. Document the canonical order.

Compound operations on shared data (check-then-act, read-modify-write) shall be atomic. A `Map.containsKey` followed by `Map.put` is not atomic; use `Map.putIfAbsent` or hold a lock.

TOCTOU vulnerabilities shall be eliminated by performing the check and the action against the same resource handle, not against a name that could be re-bound. File operations shall use `*at` family calls or hold file descriptors across the check.

Signal handlers (C/C++) shall only call async-signal-safe functions. The list is in POSIX `signal-safety(7)`.

Thread-local storage shall be used for data that does not need to cross threads. This avoids synchronization overhead and eliminates a class of race conditions.

### Resource Limits

Resource consumption shall be bounded. Maximum allocations, maximum thread count, maximum file descriptor count, and maximum request processing time shall be configured. Unbounded resource consumption is a denial-of-service vector.

Recursion shall be bounded. Functions that recurse on user input shall have explicit depth limits or shall be rewritten iteratively.

## 4. Language-Specific Guidance

### 4.1 Java

Java's garbage collector eliminates most memory safety concerns, but resource leaks (file handles, connections, native memory) and concurrency defects remain.

Use `try-with-resources` for all `AutoCloseable`. Use `java.util.concurrent` primitives (`ConcurrentHashMap`, `AtomicInteger`, `ReentrantLock`, `ReadWriteLock`) rather than rolling your own.

Prefer `synchronized` on private lock objects over `synchronized` on `this`, to prevent external code from locking against your monitor.

For shared state across requests, use immutable data where possible. `record` types (Java 16+) and final fields make this natural.

Be aware of false sharing on cache lines for high-throughput shared atomics; `@Contended` (with `-XX:-RestrictContended`) addresses this in tight loops.

For native memory (NIO direct buffers, JNI), use `MemorySegment` (Java 22+ FFM API) which provides scope-based deterministic cleanup. Older `sun.misc.Unsafe` use shall be eliminated.

For TOCTOU avoidance on files, use `java.nio.file.Files` with file attribute views and channels rather than `File` predicate calls followed by operations.

### 4.2 Python

Python's reference counting and garbage collector handle most memory concerns. Context managers handle non-memory resources.

For concurrency, the GIL serializes Python bytecode execution, so single-statement operations on built-in types are typically atomic. Compound operations are not; use `threading.Lock`, `queue.Queue`, or `concurrent.futures` primitives.

`asyncio` introduces a different concurrency model. Race conditions are still possible across `await` points; protect shared state with `asyncio.Lock`. Do not call blocking I/O from coroutines; use `asyncio.to_thread` or async libraries.

`multiprocessing` provides true parallelism. Inter-process communication via `Queue` or `Pipe` requires picklable objects; avoid pickling untrusted data.

For C extensions, ensure the extension is thread-safe and that reference counting is correct. Memory bugs in extensions corrupt the Python heap.

For recursive parsing or processing of user input, set `sys.setrecursionlimit` explicitly to a value appropriate for the workload, and prefer iterative algorithms.

### 4.3 C

Compile with `-Wall -Wextra -Wpedantic -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=3 -fstack-clash-protection -fcf-protection=full` (GCC/Clang). Link with `-Wl,-z,relro,-z,now -Wl,-z,noexecstack`. Enable PIE for executables.

Run under sanitizers in development and CI: AddressSanitizer (`-fsanitize=address`), UndefinedBehaviorSanitizer (`-fsanitize=undefined`), ThreadSanitizer (`-fsanitize=thread`) on separate builds. Sanitizers catch many bugs that static analysis misses.

Use `calloc` rather than `malloc` for buffers that will hold sensitive data, to ensure zeroed initial contents. Check return values:

~~~c
items = calloc(count, sizeof(item_t));
if (!items) { return -1; }
~~~

`calloc` itself checks for `count * sizeof` overflow; use it in preference to `malloc(count * sizeof(...))` for that reason.

After freeing, set pointers to NULL if they remain in scope. Use macros for this pattern:

~~~c
#define FREE(p) do { free(p); (p) = NULL; } while (0)
~~~

For threads, use `pthread_mutex_t`, `pthread_rwlock_t`, and `pthread_cond_t`. Initialize all mutexes with `pthread_mutex_init` (or static `PTHREAD_MUTEX_INITIALIZER`) and destroy them. Always pair lock with unlock; use cleanup handlers (`pthread_cleanup_push`) or refactor for clear cleanup paths.

For atomics, use C11 `<stdatomic.h>`. Document memory order explicitly; default `memory_order_seq_cst` is correct but heavy.

Avoid signal handlers for non-trivial work. Use `signalfd` (Linux) or a self-pipe to defer handling to the main event loop.

### 4.4 C++

The C compiler flags apply. Additionally enable `-Wnon-virtual-dtor -Wold-style-cast -Wcast-align -Woverloaded-virtual -Wconversion -Wsign-conversion -Wnull-dereference -Wdouble-promotion`.

Use modern C++: `std::unique_ptr` and `std::shared_ptr` for ownership, `std::array` and `std::vector` for buffers, `std::string` and `std::string_view` for text, `std::span` (C++20) for non-owning views.

Avoid raw `new` and `delete`. `std::make_unique` and `std::make_shared` are preferred.

For concurrency, use `std::mutex`, `std::scoped_lock`, `std::shared_mutex`, `std::atomic`, `std::condition_variable`. RAII lock guards prevent forgotten unlocks. `std::scoped_lock` (C++17) takes multiple mutexes and acquires them in deadlock-free order.

For data structures shared across threads, prefer message passing via `std::queue` with a mutex/condvar, or libraries like Folly's `MPMCQueue`. Lock-free programming is appropriate only with documented expertise and review.

For non-trivial concurrent code, ThreadSanitizer is essential. Helgrind (Valgrind) is an alternative.

Use `[[nodiscard]]` on factory functions returning owned resources. Use `final` on classes not designed for inheritance to prevent slicing.

For exception safety, follow the strong guarantee where possible: operations either complete or leave state unchanged. Use `std::swap` and the copy-and-swap idiom for assignment operators of resource-managing types.

For C++ FFI exposing a C ABI, all exceptions shall be caught at the boundary and translated to error codes. Letting exceptions cross the FFI is undefined behavior.

## 5. Verification

Compilation shall include all hardening flags listed above and shall be treated as an error on warnings. Sanitizers shall run in CI on at least one build per change. Static analysis (clang-tidy, Coverity, CodeQL, PVS-Studio) shall run continuously with security-focused rule sets. Memory testing shall include leak detection (Valgrind, ASan leak detection). Fuzzing (libFuzzer, AFL++) shall be applied to parsers and any code that processes untrusted input. Stress and chaos testing shall verify concurrent behavior under contention.

## 6. References

- OWASP ASVS v4.0.3, V5, V11
- NIST SP 800-53 Rev. 5, SI-16
- CWE-119, CWE-120, CWE-125, CWE-362, CWE-367, CWE-401, CWE-415, CWE-416, CWE-476
- CERT Secure Coding: MEM, CON, ARR, POS sections
- C++ Core Guidelines (Stroustrup, Sutter)
