# KNPM Mirrorlist Format v1

KNPM's local mirrorlist is read from `/etc/knpm/mirrorlist` by default. To inspect another file, use `knpm mirrors /path/to/file`. The environment variable `KNPM_MIRRORLIST` can override the default path when no path argument is supplied.

## Syntax

A mirrorlist contains one or more HTTP(S) base URLs in a `[mirror]` section. Blank lines and lines beginning with `#` are ignored. Entries retain their written order; duplicate resolved URLs are shown once.

```ini
# KhaymOS official mirrorlist
[mirror]
https://khaymos.duckdns.org/repo/$arch/$khaymos
# Optional fallback mirror:
https://mirror.example.net/khaymos/$arch/$repo
```

Supported substitutions:

- `$arch` or `${arch}` expands to `x86_64`.
- `$khaymos`, `${khaymos}`, `$repo`, and `${repo}` expand to `khaymos`.

A URL without an explicit scheme is treated as HTTPS. Only HTTP and HTTPS schemes are accepted. URLs with whitespace, credentials, query strings, fragments, or backslashes are rejected. Prefer HTTPS for public mirrors.

The parsed URL is a repository base path, not the URL of the mirrorlist file itself. For example, the official URL resolves to:

```text
https://khaymos.duckdns.org/repo/x86_64/khaymos
```

## Current implementation boundary

The `knpm mirrors` command validates and prints configured URLs. It does not yet fetch repository indexes or packages. A subsequent repository-client change must define and validate the remote index format and checksum-verify downloaded `.khmpkg` files before installation.
