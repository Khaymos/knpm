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

## Remote repositories

KNPM uses the repository base URLs in the configured mirrorlist to fetch the versioned `index.tsv` index. The client validates the index header, fields, package names, versions, architecture, safe archive filenames, SHA-256 values, dependency names, sorting, and duplicate identities before using records.

```sh
sudo knpm sync
knpm search bash
sudo knpm install bash
```

`knpm sync` downloads the index and caches it under `/var/lib/knpm/repository-cache-v1`. `knpm search [QUERY]` searches that cache, so sync before searching for the first time or after repository updates. `knpm install PACKAGE_NAME` refreshes the index, resolves dependencies, downloads every required archive before changing the system, checks each full-file SHA-256 against the index, validates package metadata and its internal manifest, and installs dependencies before the requested package. Use `KNPM_ROOT=/path/to/root` for a disposable target root.

Remote operations currently use the system `curl` command for HTTP(S) transport. HTTPS is preferred for public repositories. The index checksum detects file corruption or mirror mismatch; it does not authenticate a compromised index. Signed repository metadata and package upgrades are not implemented yet.
