# KNPM — Khayil's Nexus Package Manager

Current version: 0.1

KNPM verifies, inspects, installs, adopts, lists, and removes local `.khmpkg` packages.

## Mirrorlist support

KNPM can parse and validate mirrorlists with:

```sh
knpm mirrors
knpm mirrors /path/to/mirrorlist
```

By default, it reads `/etc/knpm/mirrorlist`. Set `KNPM_MIRRORLIST` to use another file without passing a path.

The mirrorlist syntax and supported placeholders are documented in [docs/MIRRORLIST-v1.md](docs/MIRRORLIST-v1.md).

**Scope note:** this change adds local mirrorlist parsing and inspection only. Remote repository indexes, downloads, and `knpm install PACKAGE_NAME` are separate work and are not claimed to be supported by this change.
