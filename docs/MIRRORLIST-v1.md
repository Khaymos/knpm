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

## Remote repository behavior

The `knpm mirrors` command validates and prints configured URLs. `knpm sync` tries mirrors in order, fetches `index.tsv`, validates the `KHAYMOS-REPO-INDEX-1` header and package records, and caches the selected index. `knpm search [QUERY]` searches the cached index; run sync first.

`knpm install PACKAGE_NAME` refreshes the index, resolves named dependencies, downloads packages from configured mirrors, checks the SHA-256 of the complete archive against the index, confirms that the archive metadata matches the index, and then passes each archive through KNPM's existing package/manifest validation before installing it. Dependencies are installed first. All required archives are fetched and verified before installation starts.

The client currently uses the system `curl` command for HTTP(S) transport, allows HTTPS redirects only, and bounds index/archive sizes. Public mirrors should use HTTPS. SHA-256 does not authenticate an index by itself; signed metadata, package upgrades, and automatic removal of orphaned dependencies are not implemented yet.
