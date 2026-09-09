# openFile() Path Traversal Analysis — LegacyStorageBackendContentProvider

## Task
Analyze whether LegacyStorageBackendContentProvider's `openFile()` is vulnerable to path traversal.

## Analysis

### URI Resolution Flow

`openFile()` (LegacyStorageBackendContentProvider.java:164) resolves URIs through this chain:

1. **UriMatcher** at line 176: `this.a.match(uri)` — accepts only pattern `*` (single wildcard path segment) under the authority. This means the URI path must be exactly ONE segment. A path like `../../etc/passwd` would be split into multiple path segments and **would NOT match** (returns -1, throws FileNotFoundException).

2. **`lex.d(uri)`** at line 183 — resolves the URI to an internal document object (`msj`/`msc`). The resolution works through TWO lookup methods:
   - **`local_id` query parameter**: Passes the value to `new LocalSpec(queryParameter)` → `kdoVar.m(localSpec)` — a **database ID lookup**, not a filesystem path. The local_id is used as a key into an internal database mapping; path traversal characters in the ID would simply fail the lookup and return null.
   - **`enc=` prefix in path segment**: Parses `enc=<value>` from the single path segment (split by `:`) → creates `new LocalSpec(str.substring(8))` for `encoded=...` values → another **database ID lookup** via `kdoVar.m()`.

3. **`mtb.a()`** at line 193 (for reads): Takes the resolved `kyg` document object (NOT a path), the content kind, and MIME type → delegates to `mvz.c()` which works with DriveCore's internal content cache system. The file content is retrieved through Drive's abstraction layer (`nxk` futures), not by constructing a filesystem path from the URI.

4. **Write path** (line 192–): Also uses the `kyg` document object → creates a pipe → writes through DriveCore's upload API. Again, no filesystem path constructed from URI input.

### Key Observation: No Filesystem Path Construction from URI

The critical finding is that **no part of the URI is used to construct a filesystem path**. The entire flow is:

```
URI → UriMatcher (single segment only) → lex.d() (database ID lookup) → kyg object → DriveCore internal cache API
```

The URI parameters (`local_id`, `enc=`) are treated as opaque database keys, not filesystem paths. Even if you inject `../` into these values, they'd be looked up as literal strings in the document database and simply return null.

### UriMatcher Protection

The `UriMatcher` pattern `"*"` (line 158 in `onCreate()`) matches exactly one path segment. This is a natural defense against path traversal because:
- `content://authority/../../etc` has 3 path segments → match returns -1
- `content://authority/..%2F..%2Fetc` — Android's `Uri.getPathSegments()` URL-decodes but still counts `/` as delimiters, so encoded slashes become real slashes and create multiple segments → mismatch

### Conclusion

**Path traversal is NOT viable** against this provider. The implementation uses database ID lookups, not filesystem path resolution, and the UriMatcher naturally blocks multi-segment paths. The vulnerability in VRP #35 (query() metadata leak without permission check, and feature-flag-gated openFile/call) remains valid but is an **authorization bypass**, not a path traversal.

## Verdict: DEAD END for path traversal specifically
The openFile() vulnerability class does not apply here because URIs are resolved to document objects via database lookups rather than being translated to filesystem paths.
