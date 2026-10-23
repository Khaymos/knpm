use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    env,
    error::Error,
    fs::{self, File, OpenOptions, Permissions},
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tar::Archive;

mod repository;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const MAX_COMPRESSED_PACKAGE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_TOTAL_PAYLOAD_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 250_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    File,
    Directory,
    Symlink,
}

impl Kind {
    fn from_manifest(s: &str) -> Result<Self> {
        match s {
            "F" => Ok(Self::File),
            "D" => Ok(Self::Directory),
            "L" => Ok(Self::Symlink),
            _ => Err(invalid(format!("unsupported manifest type: {s}"))),
        }
    }

    fn from_tar(t: tar::EntryType) -> Result<Self> {
        if t.is_file() {
            Ok(Self::File)
        } else if t.is_dir() {
            Ok(Self::Directory)
        } else if t.is_symlink() {
            Ok(Self::Symlink)
        } else {
            Err(invalid("hard links and special files are not supported"))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    kind: Kind,
    mode: u32,
    sha256: String,
}

#[derive(Debug, Clone)]
struct Metadata {
    name: String,
    version: String,
    arch: String,
    description: String,
    depends: Vec<String>,
}

#[derive(Debug)]
struct Package {
    metadata: Metadata,
    metadata_bytes: Vec<u8>,
    manifest_bytes: Vec<u8>,
    entries: BTreeMap<String, Entry>,
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Result<Self> {
        let base = env::temp_dir();
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();

        for attempt in 0..32_u32 {
            let path = base.join(format!("knpm-{}-{stamp}-{attempt}", std::process::id()));

            match fs::create_dir(&path) {
                Ok(()) => {
                    if let Err(e) = fs::set_permissions(&path, Permissions::from_mode(0o700)) {
                        let _ = fs::remove_dir_all(&path);
                        return Err(e.into());
                    }
                    return Ok(Self(path));
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }

        Err(invalid("cannot allocate a temporary directory"))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Lock(PathBuf);

impl Lock {
    fn acquire(path: PathBuf) -> Result<Self> {
        match fs::create_dir(&path) {
            Ok(()) => Ok(Self(path)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(invalid(format!(
                "package database is locked: {} (check for a stale lock)",
                path.display()
            ))),
            Err(e) => Err(e.into()),
        }
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.0);
    }
}

struct InstallTransaction {
    files: Vec<PathBuf>,
    dirs: Vec<PathBuf>,
    temporary_records: Vec<PathBuf>,
    overridden_files: Vec<(PathBuf, PathBuf)>,
    owner_record_backups: Vec<(PathBuf, PathBuf)>,
    committed: bool,
}

impl InstallTransaction {
    fn new() -> Self {
        Self {
            files: Vec::new(),
            dirs: Vec::new(),
            temporary_records: Vec::new(),
            overridden_files: Vec::new(),
            owner_record_backups: Vec::new(),
            committed: false,
        }
    }

    fn commit(&mut self) {
        self.committed = true;
    }

    fn cleanup_backups(&mut self) {
        for (_, backup) in &self.overridden_files {
            if let Err(e) = fs::remove_file(backup) {
                eprintln!(
                    "knpm: warning: cannot clean override backup {}: {e}",
                    backup.display()
                );
            }
        }

        for (_, backup) in &self.owner_record_backups {
            if let Err(e) = fs::remove_dir_all(backup) {
                eprintln!(
                    "knpm: warning: cannot clean package-record backup {}: {e}",
                    backup.display()
                );
            }
        }

        self.overridden_files.clear();
        self.owner_record_backups.clear();
    }
}

impl Drop for InstallTransaction {
    fn drop(&mut self) {
        if self.committed {
            return;
        }

        eprintln!("knpm: rolling back incomplete installation");

        for path in &self.dirs {
            let _ = fs::set_permissions(path, Permissions::from_mode(0o700));
        }

        // Remove newly installed payload entries before restoring old ones.
        for path in self.files.iter().rev() {
            let _ = fs::remove_file(path);
        }

        for path in self.dirs.iter().rev() {
            let _ = fs::remove_dir(path);
        }

        // Restore previous package records.
        for (original, backup) in self.owner_record_backups.iter().rev() {
            if path_exists(backup) {
                if path_exists(original) {
                    let _ = fs::remove_dir_all(original);
                }

                if let Err(e) = fs::rename(backup, original) {
                    eprintln!(
                        "knpm: ERROR: cannot restore package record {}: {e}",
                        original.display()
                    );
                }
            }
        }

        // Restore the payload entries that were overridden.
        for (original, backup) in self.overridden_files.iter().rev() {
            if path_exists(backup) {
                if path_exists(original) {
                    let _ = fs::remove_file(original);
                }

                if let Err(e) = fs::rename(backup, original) {
                    eprintln!(
                        "knpm: ERROR: cannot restore overridden path {}: {e}",
                        original.display()
                    );
                }
            }
        }

        for path in &self.temporary_records {
            let _ = fs::remove_dir_all(path);
        }
    }
}

struct RemoveTransaction {
    moved: Vec<(PathBuf, PathBuf)>,
    record_move: Option<(PathBuf, PathBuf)>,
    committed: bool,
}

impl RemoveTransaction {
    fn new() -> Self {
        Self {
            moved: Vec::new(),
            record_move: None,
            committed: false,
        }
    }

    fn commit(&mut self) {
        self.committed = true;
        self.record_move = None;
    }
}

impl Drop for RemoveTransaction {
    fn drop(&mut self) {
        if self.committed {
            return;
        }

        if let Some((original, backup)) = &self.record_move {
            if path_exists(backup) && !path_exists(original) {
                let _ = fs::rename(backup, original);
            }
        }

        for (original, backup) in self.moved.iter().rev() {
            if path_exists(backup) && !path_exists(original) {
                let _ = fs::rename(backup, original);
            }
        }
    }
}

struct PreparedPackage {
    package: Package,
    _temporary: TempDir,
    payload: PathBuf,
}

#[derive(Debug)]
struct OverrideConflict {
    owner_record: PathBuf,
}

fn invalid(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidData, message.into()))
}

fn path_exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn valid_name(s: &str) -> bool {
    let mut chars = s.chars();

    matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || "+_.-".contains(c))
}

fn valid_version(s: &str) -> bool {
    let mut chars = s.chars();

    matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || "+_.:~-".contains(c))
}

fn validate_relpath(path: &str) -> Result<()> {
    if path.is_empty() || path.starts_with('/') || path.contains(['\t', '\r', '\n']) {
        return Err(invalid(format!("unsafe package path: {path:?}")));
    }

    for part in path.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(invalid(format!("unsafe path component in {path:?}")));
        }
    }

    Ok(())
}

fn read_limited<R: Read>(reader: &mut R, limit: usize) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    reader.take(limit as u64 + 1).read_to_end(&mut result)?;

    if result.len() > limit {
        return Err(invalid("package control file exceeds size limit"));
    }

    Ok(result)
}

fn hash_reader<R: Read>(reader: &mut R) -> Result<String> {
    let mut sha = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        sha.update(&buffer[..count]);
    }

    Ok(format!("{:x}", sha.finalize()))
}

fn hash_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn serialize_manifest(entries: &BTreeMap<String, Entry>) -> Vec<u8> {
    let mut output = String::new();

    for (path, entry) in entries {
        let kind = match entry.kind {
            Kind::File => "F",
            Kind::Directory => "D",
            Kind::Symlink => "L",
        };

        output.push_str(&format!(
            "{kind}\t{:04o}\t{}\t{}\n",
            entry.mode, entry.sha256, path
        ));
    }

    output.into_bytes()
}

fn parse_metadata(bytes: &[u8]) -> Result<Metadata> {
    let text = std::str::from_utf8(bytes)?;
    let mut fields = HashMap::<String, String>::new();

    for line in text.lines() {
        if line.is_empty() {
            continue;
        }

        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| invalid("malformed metadata line"))?;

        match key {
            "format" | "name" | "version" | "arch" | "description" | "depends" => {}
            _ => return Err(invalid(format!("unknown metadata key: {key}"))),
        }

        if fields.insert(key.to_string(), value.to_string()).is_some() {
            return Err(invalid(format!("duplicate metadata key: {key}")));
        }
    }

    for key in [
        "format",
        "name",
        "version",
        "arch",
        "description",
        "depends",
    ] {
        if !fields.contains_key(key) {
            return Err(invalid(format!("missing metadata key: {key}")));
        }
    }

    if fields["format"] != "KHMPKG-1" {
        return Err(invalid("unsupported package format"));
    }

    let name = fields["name"].clone();
    let version = fields["version"].clone();
    let arch = fields["arch"].clone();
    let description = fields["description"].clone();

    if !valid_name(&name) {
        return Err(invalid("invalid package name"));
    }

    if !valid_version(&version) {
        return Err(invalid("invalid package version"));
    }

    if arch != "x86_64" && arch != "noarch" {
        return Err(invalid(format!("unsupported architecture: {arch}")));
    }

    if description.contains(['\r', '\n']) {
        return Err(invalid("description contains a line break"));
    }

    let depends = if fields["depends"].is_empty() {
        Vec::new()
    } else {
        fields["depends"].split(',').map(str::to_string).collect()
    };

    for dep in &depends {
        if !valid_name(dep) {
            return Err(invalid(format!("invalid dependency name: {dep}")));
        }
    }

    Ok(Metadata {
        name,
        version,
        arch,
        description,
        depends,
    })
}

fn parse_manifest(bytes: &[u8]) -> Result<BTreeMap<String, Entry>> {
    let text = std::str::from_utf8(bytes)?;
    let mut entries = BTreeMap::new();
    let mut previous: Option<String> = None;

    for (index, line) in text.lines().enumerate() {
        if line.is_empty() {
            return Err(invalid(format!("empty manifest line {}", index + 1)));
        }

        let fields: Vec<&str> = line.split('\t').collect();

        if fields.len() != 4 {
            return Err(invalid(format!(
                "manifest line {} must have four fields",
                index + 1
            )));
        }

        let kind = Kind::from_manifest(fields[0])?;
        let mode_text = fields[1];
        let digest = fields[2].to_ascii_lowercase();
        let path = fields[3];

        validate_relpath(path)?;

        if mode_text.len() != 4 || !mode_text.chars().all(|c| ('0'..='7').contains(&c)) {
            return Err(invalid(format!("invalid mode for {path}")));
        }

        let mode = u32::from_str_radix(mode_text, 8)?;

        if kind == Kind::Directory {
            if digest != "-" {
                return Err(invalid(format!("directory digest must be '-' for {path}")));
            }
        } else if digest.len() != 64 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(invalid(format!("invalid SHA-256 for {path}")));
        }

        if let Some(prev) = &previous {
            if prev.as_bytes() >= path.as_bytes() {
                return Err(invalid("manifest paths must be uniquely sorted"));
            }
        }

        previous = Some(path.to_string());

        if entries
            .insert(
                path.to_string(),
                Entry {
                    kind,
                    mode,
                    sha256: digest,
                },
            )
            .is_some()
        {
            return Err(invalid(format!("duplicate manifest path: {path}")));
        }
    }

    if entries.is_empty() {
        return Err(invalid("empty manifest"));
    }

    for path in entries.keys() {
        let mut child = path.as_str();

        while let Some((parent, _)) = child.rsplit_once('/') {
            if !matches!(entries.get(parent), Some(e) if e.kind == Kind::Directory) {
                return Err(invalid(format!(
                    "parent directory is not listed as a directory: {path}"
                )));
            }
            child = parent;
        }
    }

    Ok(entries)
}

fn open_regular_package(path: &Path) -> Result<File> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            return Err(invalid("package must be a regular, non-symlink file"));
        }
        Err(error) => return Err(error.into()),
    };

    let metadata = file.metadata()?;

    if !metadata.is_file() {
        return Err(invalid("package must be a regular, non-symlink file"));
    }

    if metadata.len() > MAX_COMPRESSED_PACKAGE_BYTES {
        return Err(invalid(format!(
            "compressed package exceeds the {}-byte limit",
            MAX_COMPRESSED_PACKAGE_BYTES
        )));
    }

    Ok(file)
}

fn inspect_archive(path: &Path) -> Result<Package> {
    let file = open_regular_package(path)?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);

    let mut seen = HashSet::new();
    let mut control_root = false;
    let mut data_root = false;
    let mut metadata_bytes = None;
    let mut manifest_bytes = None;
    let mut actual = BTreeMap::<String, Entry>::new();
    let mut archive_entry_count: usize = 0;
    let mut total_payload_bytes: u64 = 0;

    for item in archive.entries()? {
        let mut item = item?;

        archive_entry_count = archive_entry_count
            .checked_add(1)
            .ok_or_else(|| invalid("archive entry count overflow"))?;

        if archive_entry_count > MAX_ARCHIVE_ENTRIES {
            return Err(invalid(format!(
                "archive exceeds the {}-entry limit",
                MAX_ARCHIVE_ENTRIES
            )));
        }

        let raw = item
            .path()?
            .to_str()
            .ok_or_else(|| invalid("non-UTF-8 archive member path"))?
            .to_string();

        let member = raw.trim_end_matches('/').to_string();
        validate_relpath(&member)?;

        if !seen.insert(member.clone()) {
            return Err(invalid(format!("duplicate archive member: {member}")));
        }

        if member == "CONTROL" || member == "data" {
            if !item.header().entry_type().is_dir() {
                return Err(invalid(format!("{member} must be a directory")));
            }

            if member == "CONTROL" {
                control_root = true;
            } else {
                data_root = true;
            }
            continue;
        }

        if member == "CONTROL/metadata" {
            if !item.header().entry_type().is_file() {
                return Err(invalid("CONTROL/metadata must be a regular file"));
            }
            metadata_bytes = Some(read_limited(&mut item, 1024 * 1024)?);
            continue;
        }

        if member == "CONTROL/manifest" {
            if !item.header().entry_type().is_file() {
                return Err(invalid("CONTROL/manifest must be a regular file"));
            }
            manifest_bytes = Some(read_limited(&mut item, 16 * 1024 * 1024)?);
            continue;
        }

        let relative = member
            .strip_prefix("data/")
            .ok_or_else(|| invalid(format!("unexpected archive member: {member}")))?;

        validate_relpath(relative)?;

        let kind = Kind::from_tar(item.header().entry_type())?;
        let mode = item.header().mode()? & 0o7777;

        if kind == Kind::File {
            total_payload_bytes = total_payload_bytes
                .checked_add(item.size())
                .ok_or_else(|| invalid("payload size overflow"))?;

            if total_payload_bytes > MAX_TOTAL_PAYLOAD_BYTES {
                return Err(invalid(format!(
                    "payload exceeds the {}-byte uncompressed limit",
                    MAX_TOTAL_PAYLOAD_BYTES
                )));
            }
        }

        let digest = match kind {
            Kind::Directory => "-".to_string(),
            Kind::File => hash_reader(&mut item)?,
            Kind::Symlink => {
                let target = item
                    .link_name()?
                    .ok_or_else(|| invalid(format!("missing link target: {relative}")))?;

                let text = target
                    .to_str()
                    .ok_or_else(|| invalid("non-UTF-8 symlink target"))?;

                if text.contains(['\t', '\r', '\n']) {
                    return Err(invalid("invalid symbolic-link target"));
                }

                hash_bytes(text.as_bytes())
            }
        };

        actual.insert(
            relative.to_string(),
            Entry {
                kind,
                mode,
                sha256: digest,
            },
        );
    }

    let mut decoder = archive.into_inner();
    let mut trailing = [0_u8; 8192];

    loop {
        let count = decoder.read(&mut trailing)?;
        if count == 0 {
            break;
        }

        if trailing[..count].iter().any(|byte| *byte != 0) {
            return Err(invalid("non-zero data after tar end-of-archive markers"));
        }
    }

    if !control_root || !data_root {
        return Err(invalid("archive must contain CONTROL/ and data/"));
    }

    let metadata_bytes = metadata_bytes.ok_or_else(|| invalid("CONTROL/metadata is missing"))?;

    let manifest_bytes = manifest_bytes.ok_or_else(|| invalid("CONTROL/manifest is missing"))?;

    let metadata = parse_metadata(&metadata_bytes)?;
    let entries = parse_manifest(&manifest_bytes)?;

    if entries != actual {
        return Err(invalid("payload inventory does not match the manifest"));
    }

    Ok(Package {
        metadata,
        metadata_bytes,
        manifest_bytes,
        entries,
    })
}

fn prepare_package(path: &Path) -> Result<PreparedPackage> {
    let mut source = open_regular_package(path)?;
    let temporary = TempDir::new()?;
    let copy = temporary.0.join("package.khmpkg");

    let mut copied_package = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&copy)?;

    io::copy(&mut source, &mut copied_package)?;
    copied_package.sync_all()?;
    drop(copied_package);

    let package = inspect_archive(&copy)?;

    let extract = temporary.0.join("extracted");
    fs::create_dir(&extract)?;

    let file = open_regular_package(&copy)?;
    let mut archive = Archive::new(GzDecoder::new(file));

    for item in archive.entries()? {
        let mut item = item?;
        if !item.unpack_in(&extract)? {
            return Err(invalid("archive extraction rejected an unsafe path"));
        }
    }

    let payload = extract.join("data");

    if !payload.is_dir() || payload.is_symlink() {
        return Err(invalid("package data directory missing after extraction"));
    }

    Ok(PreparedPackage {
        package,
        _temporary: temporary,
        payload,
    })
}

fn resolve_root() -> Result<PathBuf> {
    let requested = env::var_os("KNPM_ROOT").unwrap_or_else(|| "/".into());
    let meta = fs::symlink_metadata(&requested)?;

    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(invalid("target root must be a real directory"));
    }

    Ok(fs::canonicalize(requested)?)
}

fn require_privilege_for_system(root: &Path) -> Result<()> {
    if root == Path::new("/") && unsafe { libc::geteuid() } != 0 {
        return Err(invalid("install/remove on the real system require root"));
    }
    Ok(())
}

fn database_path(root: &Path, create: bool) -> Result<Option<PathBuf>> {
    let mut current = root.to_path_buf();

    for part in ["var", "lib", "knpm", "installed"] {
        current.push(part);

        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(invalid(format!(
                    "refusing symlink in package database path: {}",
                    current.display()
                )));
            }
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => {
                return Err(invalid(format!(
                    "package database component is not a directory: {}",
                    current.display()
                )));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound && !create => {
                return Ok(None);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound && create => {
                match fs::create_dir(&current) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e.into()),
                }

                let meta = fs::symlink_metadata(&current)?;

                if meta.file_type().is_symlink() || !meta.is_dir() {
                    return Err(invalid(format!(
                        "unsafe package database path: {}",
                        current.display()
                    )));
                }
            }
            Err(e) => return Err(e.into()),
        }
    }

    Ok(Some(root.join("var/lib/knpm")))
}

fn check_parent_paths(root: &Path, relative: &str) -> Result<()> {
    validate_relpath(relative)?;

    let parts: Vec<&str> = relative.split('/').collect();
    let mut current = root.to_path_buf();

    for part in &parts[..parts.len() - 1] {
        current.push(part);

        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(invalid(format!(
                    "refusing to traverse target symlink: {}",
                    current.display()
                )));
            }
            Ok(meta) if !meta.is_dir() => {
                return Err(invalid(format!(
                    "target parent is not a directory: {}",
                    current.display()
                )));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

fn read_record_metadata(record: &Path) -> Result<Metadata> {
    let path = record.join("metadata");
    let meta = fs::symlink_metadata(&path)?;

    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(invalid("installed metadata is not a regular file"));
    }

    parse_metadata(&fs::read(path)?)
}

fn read_record_manifest(record: &Path) -> Result<BTreeMap<String, Entry>> {
    let path = record.join("manifest");
    let meta = fs::symlink_metadata(&path)?;

    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(invalid("installed manifest is not a regular file"));
    }

    parse_manifest(&fs::read(path)?)
}

fn check_other_owners(
    root: &Path,
    installed_dir: &Path,
    package: &Package,
    override_existing: bool,
) -> Result<BTreeMap<String, OverrideConflict>> {
    let mut conflicts = BTreeMap::new();

    for item in fs::read_dir(installed_dir)? {
        let item = item?;
        let filename = item.file_name();

        let Some(name) = filename.to_str() else {
            return Err(invalid("non-UTF-8 package database entry"));
        };

        if name.starts_with('.') || name == package.metadata.name {
            continue;
        }

        let record = item.path();
        let meta = fs::symlink_metadata(&record)?;

        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(invalid(format!("invalid installed package record: {name}")));
        }

        let manifest = read_record_manifest(&record)?;

        for (path, entry) in &package.entries {
            let Some(other) = manifest.get(path) else {
                continue;
            };

            if entry.kind == Kind::Directory && other.kind == Kind::Directory {
                continue;
            }

            // Directories are shared, not replaceable. Only a file or symlink
            // may be transferred to the incoming package.
            if !override_existing || entry.kind == Kind::Directory || other.kind == Kind::Directory
            {
                return Err(invalid(format!("path already owned by {name}: {path}")));
            }

            // Don't overwrite a path that has already been changed or damaged.
            verify_installed_entry(root, path, other)?;

            if conflicts
                .insert(
                    path.clone(),
                    OverrideConflict {
                        owner_record: record.clone(),
                    },
                )
                .is_some()
            {
                return Err(invalid(format!(
                    "multiple packages claim the same non-directory path: {path}"
                )));
            }
        }
    }

    Ok(conflicts)
}

fn check_dependencies(installed_dir: &Path, package: &Package) -> Result<()> {
    for dependency in &package.metadata.depends {
        let record = installed_dir.join(dependency);

        if !record.is_dir() || record.is_symlink() {
            return Err(invalid(format!(
                "missing dependency '{dependency}'; install it first"
            )));
        }

        let metadata = read_record_metadata(&record)?;

        if metadata.name != *dependency {
            return Err(invalid(format!("dependency record mismatch: {dependency}")));
        }
    }

    Ok(())
}

fn preflight_install(
    root: &Path,
    package: &Package,
    conflicts: &BTreeMap<String, OverrideConflict>,
) -> Result<()> {
    for (relative, entry) in &package.entries {
        check_parent_paths(root, relative)?;

        let destination = root.join(relative);

        match fs::symlink_metadata(&destination) {
            Ok(meta) if entry.kind == Kind::Directory => {
                if meta.file_type().is_symlink() || !meta.is_dir() {
                    return Err(invalid(format!(
                        "directory conflicts with existing path: {relative}"
                    )));
                }
            }
            Ok(_) => {
                if !conflicts.contains_key(relative) {
                    return Err(invalid(format!(
                        "refusing to overwrite existing unowned path: {relative}"
                    )));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if conflicts.contains_key(relative) {
                    return Err(invalid(format!(
                        "owned path is missing and cannot be overridden: {relative}"
                    )));
                }
            }
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

fn write_package_record(
    record: &Path,
    metadata_bytes: &[u8],
    manifest_bytes: &[u8],
    created_dirs: &str,
) -> Result<()> {
    fs::create_dir(record)?;
    fs::write(record.join("metadata"), metadata_bytes)?;
    fs::write(record.join("manifest"), manifest_bytes)?;
    fs::write(record.join("created-dirs"), created_dirs)?;

    for filename in ["metadata", "manifest", "created-dirs"] {
        fs::set_permissions(record.join(filename), Permissions::from_mode(0o644))?;
    }

    fs::set_permissions(record, Permissions::from_mode(0o755))?;
    Ok(())
}

fn rewrite_owner_record(
    owner_record: &Path,
    transferred_paths: &HashSet<String>,
    transaction: &mut InstallTransaction,
    index: usize,
) -> Result<()> {
    let metadata_bytes = fs::read(owner_record.join("metadata"))?;
    let manifest = read_record_manifest(owner_record)?;

    let mut retained = BTreeMap::new();

    for (path, entry) in manifest {
        if !transferred_paths.contains(&path) {
            retained.insert(path, entry);
        }
    }

    if retained.is_empty() {
        return Err(invalid(format!(
            "override would leave package {} with an empty manifest",
            owner_record
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
        )));
    }

    let created_file = owner_record.join("created-dirs");
    let created_text = fs::read_to_string(&created_file)
        .map_err(|_| invalid("missing created-dirs database file"))?;

    // Only non-directory entries are transferred, so the previous package's
    // created-directory list remains valid.
    let temporary = unique_sibling(owner_record, "override-record-new", index)?;
    transaction.temporary_records.push(temporary.clone());

    write_package_record(
        &temporary,
        &metadata_bytes,
        &serialize_manifest(&retained),
        &created_text,
    )?;

    let backup = unique_sibling(owner_record, "override-record-old", index)?;

    fs::rename(owner_record, &backup)?;
    transaction
        .owner_record_backups
        .push((owner_record.to_path_buf(), backup));

    fs::rename(&temporary, owner_record)?;

    Ok(())
}

fn install(archive_path: &Path, override_existing: bool) -> Result<()> {
    let root = resolve_root()?;
    require_privilege_for_system(&root)?;

    let prepared = prepare_package(archive_path)?;
    let package = &prepared.package;

    let db =
        database_path(&root, true)?.ok_or_else(|| invalid("cannot create package database"))?;

    let installed_dir = db.join("installed");
    let _lock = Lock::acquire(db.join("lock"))?;

    let record = installed_dir.join(&package.metadata.name);

    if path_exists(&record) {
        return Err(invalid(format!(
            "{} is already installed; upgrades are not supported yet",
            package.metadata.name
        )));
    }

    check_dependencies(&installed_dir, package)?;

    let conflicts = check_other_owners(&root, &installed_dir, package, override_existing)?;

    preflight_install(&root, package, &conflicts)?;

    let mut transaction = InstallTransaction::new();
    let mut created_rel = Vec::<String>::new();

    // Back up all files and symlinks that will be transferred to this package.
    for (index, (relative, _conflict)) in conflicts.iter().enumerate() {
        let destination = root.join(relative);
        let backup = unique_sibling(&destination, "override", index)?;

        fs::rename(&destination, &backup)?;
        transaction.overridden_files.push((destination, backup));
    }

    // Remove transferred paths from the old owners' manifests. Each owner
    // record is rewritten once, even if several paths are transferred.
    let mut owner_paths: HashMap<PathBuf, HashSet<String>> = HashMap::new();

    for (relative, conflict) in &conflicts {
        owner_paths
            .entry(conflict.owner_record.clone())
            .or_default()
            .insert(relative.clone());
    }

    for (index, (owner_record, paths)) in owner_paths.iter().enumerate() {
        rewrite_owner_record(owner_record, paths, &mut transaction, index)?;
    }

    // Create new directories first, with temporary permissions.
    for (relative, entry) in &package.entries {
        if entry.kind != Kind::Directory {
            continue;
        }

        let destination = root.join(relative);

        if !path_exists(&destination) {
            fs::create_dir(&destination)?;
            transaction.dirs.push(destination);
            created_rel.push(relative.clone());
        }
    }

    // Install files and symlinks after directories exist.
    for (relative, entry) in &package.entries {
        if entry.kind == Kind::Directory {
            continue;
        }

        let source = prepared.payload.join(relative);
        let destination = root.join(relative);

        match entry.kind {
            Kind::File => {
                let source_meta = fs::symlink_metadata(&source)?;

                if !source_meta.is_file() || source_meta.file_type().is_symlink() {
                    return Err(invalid(format!(
                        "package payload is not a regular file: {relative}"
                    )));
                }

                transaction.files.push(destination.clone());
                fs::copy(&source, &destination)?;
                fs::set_permissions(&destination, Permissions::from_mode(entry.mode))?;
            }
            Kind::Symlink => {
                let source_meta = fs::symlink_metadata(&source)?;

                if !source_meta.file_type().is_symlink() {
                    return Err(invalid(format!(
                        "package payload is not a symlink: {relative}"
                    )));
                }

                let target = fs::read_link(&source)?;
                symlink(target, &destination)?;
                transaction.files.push(destination);
            }
            Kind::Directory => unreachable!(),
        }
    }

    for relative in created_rel.iter().rev() {
        let entry = &package.entries[relative];
        fs::set_permissions(root.join(relative), Permissions::from_mode(entry.mode))?;
    }

    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let temporary_record = installed_dir.join(format!(
        ".tmp-{}-{}-{stamp}",
        package.metadata.name,
        std::process::id()
    ));

    transaction.temporary_records.push(temporary_record.clone());

    let created_text = if created_rel.is_empty() {
        String::new()
    } else {
        format!("{}\n", created_rel.join("\n"))
    };

    write_package_record(
        &temporary_record,
        &package.metadata_bytes,
        &package.manifest_bytes,
        &created_text,
    )?;

    fs::rename(&temporary_record, &record)?;

    transaction.commit();
    transaction.cleanup_backups();

    if override_existing && !conflicts.is_empty() {
        println!("Overrode {} previously owned path(s).", conflicts.len());
    }

    println!(
        "Installed: {} {}",
        package.metadata.name, package.metadata.version
    );

    Ok(())
}

fn adopt_package(archive_path: &Path) -> Result<()> {
    let root = resolve_root()?;
    require_privilege_for_system(&root)?;

    let package = inspect_archive(archive_path)?;

    for (relative, entry) in &package.entries {
        verify_installed_entry(&root, relative, entry)?;
    }

    let db =
        database_path(&root, true)?.ok_or_else(|| invalid("cannot create package database"))?;

    let installed_dir = db.join("installed");
    let _lock = Lock::acquire(db.join("lock"))?;

    let record = installed_dir.join(&package.metadata.name);

    if path_exists(&record) {
        return Err(invalid(format!(
            "{} is already registered; adoption refused",
            package.metadata.name
        )));
    }

    check_dependencies(&installed_dir, &package)?;

    check_other_owners(&root, &installed_dir, &package, false)?;

    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let temporary_record = installed_dir.join(format!(
        ".tmp-adopt-{}-{}-{stamp}",
        package.metadata.name,
        std::process::id()
    ));

    let mut transaction = InstallTransaction::new();
    transaction.temporary_records.push(temporary_record.clone());

    write_package_record(
        &temporary_record,
        &package.metadata_bytes,
        &package.manifest_bytes,
        "",
    )?;

    fs::rename(&temporary_record, &record)?;
    transaction.commit();

    println!(
        "Adopted: {} {}",
        package.metadata.name, package.metadata.version
    );

    Ok(())
}

fn list_packages() -> Result<()> {
    let root = resolve_root()?;

    let Some(db) = database_path(&root, false)? else {
        println!("No packages installed.");
        return Ok(());
    };

    let installed = db.join("installed");

    println!("{:<28} {:<16} {:<10}", "NAME", "VERSION", "ARCH");
    println!("{:<28} {:<16} {:<10}", "----", "-------", "----");

    let mut records = fs::read_dir(installed)?
        .map(|e| e.map(|v| v.path()))
        .collect::<io::Result<Vec<_>>>()?;

    records.sort();

    for record in records {
        let Some(filename) = record.file_name().and_then(|s| s.to_str()) else {
            return Err(invalid("invalid installed package name"));
        };

        if filename.starts_with('.') {
            continue;
        }

        let meta = fs::symlink_metadata(&record)?;

        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(invalid(format!(
                "invalid package database entry: {filename}"
            )));
        }

        let package = read_record_metadata(&record)?;

        if package.name != filename {
            return Err(invalid(format!(
                "package database name mismatch: {filename}"
            )));
        }

        println!(
            "{:<28} {:<16} {:<10}",
            package.name, package.version, package.arch
        );
    }

    Ok(())
}

fn verify_installed_entry(root: &Path, relative: &str, entry: &Entry) -> Result<()> {
    check_parent_paths(root, relative)?;

    let path = root.join(relative);

    let meta = fs::symlink_metadata(&path)
        .map_err(|_| invalid(format!("installed path is missing: {relative}")))?;

    match entry.kind {
        Kind::File => {
            if !meta.is_file() || meta.file_type().is_symlink() {
                return Err(invalid(format!("installed file changed type: {relative}")));
            }

            let mode = meta.mode() & 0o7777;

            if mode != entry.mode {
                return Err(invalid(format!("installed file mode changed: {relative}")));
            }

            let digest = hash_reader(&mut File::open(&path)?)?;

            if digest != entry.sha256 {
                return Err(invalid(format!("installed file was modified: {relative}")));
            }
        }
        Kind::Directory => {
            if !meta.is_dir() || meta.file_type().is_symlink() {
                return Err(invalid(format!(
                    "installed directory changed type: {relative}"
                )));
            }
        }
        Kind::Symlink => {
            if !meta.file_type().is_symlink() {
                return Err(invalid(format!(
                    "installed symlink changed type: {relative}"
                )));
            }

            let target = fs::read_link(&path)?;
            let text = target
                .to_str()
                .ok_or_else(|| invalid("non-UTF-8 installed symlink"))?;

            if hash_bytes(text.as_bytes()) != entry.sha256 {
                return Err(invalid(format!(
                    "installed symlink was modified: {relative}"
                )));
            }
        }
    }

    Ok(())
}

fn unique_sibling(path: &Path, label: &str, index: usize) -> Result<PathBuf> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("cannot find path parent"))?;

    let name = path
        .file_name()
        .ok_or_else(|| invalid("cannot find path filename"))?
        .to_string_lossy();

    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();

    for attempt in 0..32_u32 {
        let candidate = parent.join(format!(
            ".knpm-{label}-{name}-{}-{stamp}-{index}-{attempt}",
            std::process::id()
        ));

        if !path_exists(&candidate) {
            return Ok(candidate);
        }
    }

    Err(invalid("cannot allocate unique temporary path"))
}

fn remove_package(name: &str) -> Result<()> {
    if !valid_name(name) {
        return Err(invalid(format!("invalid package name: {name}")));
    }

    let root = resolve_root()?;
    require_privilege_for_system(&root)?;

    let Some(db) = database_path(&root, false)? else {
        return Err(invalid(format!("package is not installed: {name}")));
    };

    let installed_dir = db.join("installed");
    let _lock = Lock::acquire(db.join("lock"))?;

    let record = installed_dir.join(name);

    let record_meta = fs::symlink_metadata(&record)
        .map_err(|_| invalid(format!("package is not installed: {name}")))?;

    if record_meta.file_type().is_symlink() || !record_meta.is_dir() {
        return Err(invalid("invalid installed package record"));
    }

    let metadata = read_record_metadata(&record)?;

    if metadata.name != name {
        return Err(invalid("installed package name mismatch"));
    }

    let mut directories_owned_by_others = HashSet::<String>::new();

    for item in fs::read_dir(&installed_dir)? {
        let item = item?;
        let other_record = item.path();
        let other_name = item.file_name().to_string_lossy().into_owned();

        if other_name.starts_with('.') || other_name == name {
            continue;
        }

        let other_meta = fs::symlink_metadata(&other_record)?;

        if other_meta.file_type().is_symlink() || !other_meta.is_dir() {
            return Err(invalid(format!(
                "invalid installed package record: {other_name}"
            )));
        }

        let other = read_record_metadata(&other_record)?;

        if other.depends.iter().any(|dep| dep == name) {
            return Err(invalid(format!(
                "cannot remove {name}: required by {other_name}"
            )));
        }

        let other_entries = read_record_manifest(&other_record)?;

        for (relative, entry) in other_entries {
            if entry.kind == Kind::Directory {
                directories_owned_by_others.insert(relative);
            }
        }
    }

    let entries = read_record_manifest(&record)?;

    for (relative, entry) in &entries {
        verify_installed_entry(&root, relative, entry)?;
    }

    let created_file = record.join("created-dirs");

    let created_text = fs::read_to_string(&created_file)
        .map_err(|_| invalid("missing created-dirs database file"))?;

    let mut created_dirs = Vec::new();
    let mut seen_dirs = HashSet::new();

    for line in created_text.lines() {
        validate_relpath(line)?;

        if !matches!(entries.get(line), Some(e) if e.kind == Kind::Directory) {
            return Err(invalid(format!("invalid created-directory record: {line}")));
        }

        if !seen_dirs.insert(line.to_string()) {
            return Err(invalid(format!(
                "duplicate created-directory record: {line}"
            )));
        }

        created_dirs.push(line.to_string());
    }

    let mut transaction = RemoveTransaction::new();

    for (relative, entry) in &entries {
        if entry.kind == Kind::Directory {
            continue;
        }

        let original = root.join(relative);
        let backup = unique_sibling(&original, "remove", transaction.moved.len())?;

        fs::rename(&original, &backup)?;
        transaction.moved.push((original, backup));
    }

    let record_backup = unique_sibling(&record, "record", 0)?;

    fs::rename(&record, &record_backup)?;
    transaction.record_move = Some((record.clone(), record_backup.clone()));

    transaction.commit();

    let mut cleanup_failed = false;

    for (_, backup) in &transaction.moved {
        if let Err(e) = fs::remove_file(backup) {
            eprintln!("knpm: warning: cannot clean {}: {e}", backup.display());
            cleanup_failed = true;
        }
    }

    for relative in created_dirs.iter().rev() {
        if directories_owned_by_others.contains(relative) {
            continue;
        }

        if let Err(e) = fs::remove_dir(root.join(relative)) {
            if e.kind() != io::ErrorKind::DirectoryNotEmpty && e.kind() != io::ErrorKind::NotFound {
                eprintln!("knpm: warning: cannot remove directory {relative}: {e}");
            }
        }
    }

    if let Err(e) = fs::remove_dir_all(&record_backup) {
        eprintln!(
            "knpm: warning: cannot clean package record {}: {e}",
            record_backup.display()
        );
        cleanup_failed = true;
    }

    println!("Removed: {name}");

    if cleanup_failed {
        eprintln!("knpm: warning: cleanup left hidden temporary entries");
    }

    Ok(())
}

const DEFAULT_MIRRORLIST_PATH: &str = "/etc/knpm/mirrorlist";
const DEFAULT_REPOSITORY_ARCH: &str = "x86_64";
const DEFAULT_REPOSITORY_NAME: &str = "khaymos";

fn normalize_mirror_url(value: &str) -> Result<String> {
    let value = value.trim();

    if value.is_empty() || value.contains(['\t', '\r', '\n', ' ']) {
        return Err(invalid("mirror URL is empty or contains whitespace"));
    }

    let expanded = value
        .replace("${arch}", DEFAULT_REPOSITORY_ARCH)
        .replace("$arch", DEFAULT_REPOSITORY_ARCH)
        .replace("${khaymos}", DEFAULT_REPOSITORY_NAME)
        .replace("$khaymos", DEFAULT_REPOSITORY_NAME)
        .replace("${repo}", DEFAULT_REPOSITORY_NAME)
        .replace("$repo", DEFAULT_REPOSITORY_NAME);

    let url = if expanded.contains("://") {
        expanded
    } else {
        format!("https://{expanded}")
    };

    let (scheme, remainder) = url
        .split_once("://")
        .ok_or_else(|| invalid("mirror URL must use HTTP or HTTPS"))?;

    if scheme != "https" && scheme != "http" {
        return Err(invalid("mirror URL must use HTTP or HTTPS"));
    }

    let authority = remainder.split('/').next().unwrap_or_default();

    if authority.is_empty()
        || authority.contains('@')
        || authority.contains(['?', '#', '\\'])
        || remainder.contains(['?', '#', '\\'])
    {
        return Err(invalid(
            "mirror URL must have a host and must not contain credentials, a query, or a fragment",
        ));
    }

    Ok(url.trim_end_matches('/').to_string())
}

fn parse_mirrorlist(contents: &str) -> Result<Vec<String>> {
    let mut in_mirror_section = false;
    let mut found_mirror_section = false;
    let mut mirrors = Vec::<String>::new();

    for (index, raw_line) in contents.lines().enumerate() {
        let line = raw_line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            let section = line[1..line.len() - 1].trim();
            in_mirror_section = section == "mirror";
            found_mirror_section |= in_mirror_section;
            continue;
        }

        if !in_mirror_section {
            continue;
        }

        let url = normalize_mirror_url(line).map_err(|error| {
            invalid(format!("invalid mirror URL on line {}: {error}", index + 1))
        })?;

        if !mirrors.iter().any(|existing| existing == &url) {
            mirrors.push(url);
        }
    }

    if !found_mirror_section {
        return Err(invalid("mirrorlist is missing the [mirror] section"));
    }

    if mirrors.is_empty() {
        return Err(invalid("mirrorlist contains no usable mirror URLs"));
    }

    Ok(mirrors)
}

fn load_mirrorlist(path: &Path) -> Result<Vec<String>> {
    let contents = fs::read_to_string(path).map_err(|error| {
        invalid(format!(
            "cannot read mirrorlist {}: {error}",
            path.display()
        ))
    })?;
    parse_mirrorlist(&contents)
}

fn configured_mirrorlist_path() -> PathBuf {
    env::var_os("KNPM_MIRRORLIST")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_MIRRORLIST_PATH))
}

fn list_mirrors(path: &Path) -> Result<()> {
    let mirrors = load_mirrorlist(path)?;
    println!("Mirrorlist: {}", path.display());

    for (index, mirror) in mirrors.iter().enumerate() {
        println!("{:>2}. {}", index + 1, mirror);
    }

    Ok(())
}

fn usage() {
    eprintln!(
        "KNPM — Khayil's Nexus Package Manager\n\
Usage:\n\
knpm --version\n\
knpm verify PACKAGE.khmpkg\n\
knpm info PACKAGE.khmpkg\n\
knpm adopt PACKAGE.khmpkg\n\
knpm list\n\
knpm install PACKAGE.khmpkg [--override]\n\
knpm install --override PACKAGE.khmpkg\n\
knpm remove PACKAGE_NAME\n\
knpm sync\n\
knpm search [QUERY]\n\
knpm mirrors [MIRRORLIST_FILE]\n\
knpm help\n\
For a disposable target root, set KNPM_ROOT=/path/to/root."
    );
}

fn run() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(String::as_str) {
        Some("--version") | Some("-V") => {
            if args.len() != 2 {
                return Err(invalid("usage: knpm --version"));
            }
            println!("KNPM {}", env!("CARGO_PKG_VERSION"));
        }
        Some("help") | Some("--help") | Some("-h") => usage(),
        Some("verify") | Some("info") => {
            if args.len() != 3 {
                return Err(invalid("expected one package path"));
            }

            let package = inspect_archive(Path::new(&args[2]))?;

            if args[1] == "verify" {
                println!(
                    "Verified: {} {} ({} entries)",
                    package.metadata.name,
                    package.metadata.version,
                    package.entries.len()
                );
            } else {
                println!("Name:         {}", package.metadata.name);
                println!("Version:      {}", package.metadata.version);
                println!("Architecture: {}", package.metadata.arch);
                println!("Description:  {}", package.metadata.description);

                println!(
                    "Dependencies: {}",
                    if package.metadata.depends.is_empty() {
                        "none".to_string()
                    } else {
                        package.metadata.depends.join(", ")
                    }
                );

                println!("Entries:      {}", package.entries.len());
            }
        }
        Some("adopt") => {
            if args.len() != 3 {
                return Err(invalid("usage: knpm adopt PACKAGE.khmpkg"));
            }
            adopt_package(Path::new(&args[2]))?;
        }
        Some("list") => {
            if args.len() != 2 {
                return Err(invalid("usage: knpm list"));
            }
            list_packages()?;
        }
        Some("install") => {
            let (override_existing, package_arg) = match args.as_slice() {
                [_, _, flag, package] if flag == "--override" => (true, package),
                [_, _, package, flag] if flag == "--override" => (true, package),
                [_, _, package] => (false, package),
                _ => {
                    return Err(invalid(
                        "usage: knpm install [--override] PACKAGE.khmpkg [--override]",
                    ));
                }
            };

            if package_arg.ends_with(".khmpkg") || Path::new(package_arg).exists() {
                install(Path::new(package_arg), override_existing)?;
            } else {
                repository::install_by_name(package_arg, override_existing)?;
            }
        }
        Some("sync") => {
            if args.len() != 2 {
                return Err(invalid("usage: knpm sync"));
            }
            repository::sync()?;
        }
        Some("search") => {
            if args.len() > 3 {
                return Err(invalid("usage: knpm search [QUERY]"));
            }
            repository::search(args.get(2).map(String::as_str))?;
        }
        Some("mirrors") | Some("mirrorlist") => {
            if args.len() > 3 {
                return Err(invalid("usage: knpm mirrors [MIRRORLIST_FILE]"));
            }

            let path = if args.len() == 3 {
                PathBuf::from(&args[2])
            } else {
                configured_mirrorlist_path()
            };

            list_mirrors(&path)?;
        }
        Some("remove") | Some("uninstall") => {
            if args.len() != 3 {
                return Err(invalid("usage: knpm remove PACKAGE_NAME"));
            }
            remove_package(&args[2])?;
        }
        _ => return Err(invalid("unknown command; try 'knpm help'")),
    }

    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("knpm: error: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use std::io::empty;
    use tar::{Builder, EntryType, Header};

    fn metadata_text(depends: &str) -> Vec<u8> {
        format!(
            "format=KHMPKG-1\nname=demo\nversion=1.0\narch=x86_64\ndescription=Demo package\ndepends={depends}\n"
        )
        .into_bytes()
    }

    fn manifest_text(payload: &[u8], mode: u32) -> Vec<u8> {
        format!(
            "D\t0755\t-\tusr\nD\t0755\t-\tusr/bin\nF\t{mode:04o}\t{}\tusr/bin/demo\n",
            hash_bytes(payload)
        )
        .into_bytes()
    }

    fn append_dir(builder: &mut Builder<GzEncoder<File>>, path: &str) {
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::Directory);
        header.set_size(0);
        header.set_mode(0o755);
        header.set_mtime(0);
        header.set_cksum();
        builder
            .append_data(&mut header, path, empty())
            .expect("append test directory");
    }

    fn append_file(builder: &mut Builder<GzEncoder<File>>, path: &str, bytes: &[u8], mode: u32) {
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::Regular);
        header.set_size(bytes.len() as u64);
        header.set_mode(mode);
        header.set_mtime(0);
        header.set_cksum();
        builder
            .append_data(&mut header, path, bytes)
            .expect("append test file");
    }

    fn write_test_archive(
        temp: &TempDir,
        metadata: &[u8],
        manifest: &[u8],
        payload_path: &str,
        payload: &[u8],
        duplicate_payload: bool,
    ) -> PathBuf {
        let path = temp.0.join("test.khmpkg");
        let file = File::create(&path).expect("create test package");
        let encoder = GzEncoder::new(file, Compression::default());
        let mut builder = Builder::new(encoder);

        append_dir(&mut builder, "CONTROL");
        append_dir(&mut builder, "data");
        append_file(&mut builder, "CONTROL/metadata", metadata, 0o644);
        append_file(&mut builder, "CONTROL/manifest", manifest, 0o644);
        append_dir(&mut builder, "data/usr");
        append_dir(&mut builder, "data/usr/bin");
        append_file(&mut builder, payload_path, payload, 0o755);

        if duplicate_payload {
            append_file(&mut builder, payload_path, payload, 0o755);
        }

        builder
            .into_inner()
            .expect("finish test tar archive")
            .finish()
            .expect("finish test gzip stream");

        path
    }

    #[test]
    fn accepts_valid_package_names() {
        for name in ["bash", "gcc-runtime", "lib32+compat", "x.y_z"] {
            assert!(valid_name(name), "expected {name:?} to be valid");
        }
    }

    #[test]
    fn rejects_invalid_package_names() {
        for name in ["", ".hidden", "-leading", "name/path", "with space", "é"] {
            assert!(!valid_name(name), "expected {name:?} to be invalid");
        }
    }

    #[test]
    fn accepts_valid_versions() {
        for version in ["1", "1.2.3", "16.1.0", "1.0~rc1", "2:1.4+khaymos"] {
            assert!(valid_version(version), "expected {version:?} to be valid");
        }
    }

    #[test]
    fn rejects_invalid_versions() {
        for version in ["", ".1", "-1", "version with spaces", "1/2"] {
            assert!(
                !valid_version(version),
                "expected {version:?} to be invalid"
            );
        }
    }

    #[test]
    fn accepts_safe_relative_paths() {
        for path in ["bin/knpm", "usr/bin/bash", "usr/share/doc/knpm/README"] {
            assert!(validate_relpath(path).is_ok(), "rejected {path:?}");
        }
    }

    #[test]
    fn rejects_unsafe_relative_paths() {
        for path in [
            "",
            "/etc/passwd",
            "../escape",
            "usr/../etc/passwd",
            "usr//bin/knpm",
            "usr/./bin",
            "usr/\tbin",
            "usr/\nfile",
        ] {
            assert!(
                validate_relpath(path).is_err(),
                "accepted unsafe path {path:?}"
            );
        }
    }

    #[test]
    fn parses_metadata_and_dependencies() {
        let metadata = parse_metadata(&metadata_text("glibc,zlib")).unwrap();

        assert_eq!(metadata.name, "demo");
        assert_eq!(metadata.version, "1.0");
        assert_eq!(metadata.arch, "x86_64");
        assert_eq!(metadata.description, "Demo package");
        assert_eq!(
            metadata.depends,
            vec!["glibc".to_string(), "zlib".to_string()]
        );
    }

    #[test]
    fn rejects_duplicate_metadata_fields() {
        let text = String::from_utf8(metadata_text("")).unwrap() + "name=another\n";
        assert!(parse_metadata(text.as_bytes()).is_err());
    }

    #[test]
    fn rejects_unknown_metadata_fields() {
        let text = String::from_utf8(metadata_text("")).unwrap() + "maintainer=somebody\n";
        assert!(parse_metadata(text.as_bytes()).is_err());
    }

    #[test]
    fn rejects_unsupported_architecture() {
        let text = String::from_utf8(metadata_text(""))
            .unwrap()
            .replace("arch=x86_64", "arch=aarch64");
        assert!(parse_metadata(text.as_bytes()).is_err());
    }

    #[test]
    fn rejects_invalid_dependency_names() {
        assert!(parse_metadata(&metadata_text("glibc,../evil")).is_err());
    }

    #[test]
    fn serializes_and_parses_manifest_consistently() {
        let payload = b"test executable\n";
        let manifest = manifest_text(payload, 0o755);
        let parsed = parse_manifest(&manifest).unwrap();

        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed["usr"].kind, Kind::Directory);
        assert_eq!(parsed["usr/bin"].kind, Kind::Directory);
        assert_eq!(parsed["usr/bin/demo"].kind, Kind::File);
        assert_eq!(parsed["usr/bin/demo"].sha256, hash_bytes(payload));
        assert_eq!(
            parse_manifest(&serialize_manifest(&parsed)).unwrap(),
            parsed
        );
    }

    #[test]
    fn rejects_unsorted_manifest_paths() {
        let text = format!(
            "F\t0755\t{}\tusr/bin/demo\nD\t0755\t-\tusr\nD\t0755\t-\tusr/bin\n",
            hash_bytes(b"x")
        );
        assert!(parse_manifest(text.as_bytes()).is_err());
    }

    #[test]
    fn rejects_manifest_entries_without_parent_directories() {
        let text = format!("F\t0755\t{}\tusr/bin/demo\n", hash_bytes(b"x"));
        assert!(parse_manifest(text.as_bytes()).is_err());
    }

    #[test]
    fn rejects_manifest_path_traversal() {
        let text = format!("F\t0755\t{}\t../escape\n", hash_bytes(b"x"));
        assert!(parse_manifest(text.as_bytes()).is_err());
    }

    #[test]
    fn inspect_archive_accepts_a_valid_package() {
        let temp = TempDir::new().unwrap();
        let payload = b"test executable\n";
        let archive = write_test_archive(
            &temp,
            &metadata_text(""),
            &manifest_text(payload, 0o755),
            "data/usr/bin/demo",
            payload,
            false,
        );

        let package = inspect_archive(&archive).unwrap();

        assert_eq!(package.metadata.name, "demo");
        assert_eq!(package.metadata.version, "1.0");
        assert_eq!(package.entries.len(), 3);
    }

    #[test]
    fn inspect_archive_rejects_payload_digest_mismatch() {
        let temp = TempDir::new().unwrap();
        let manifest = manifest_text(b"different payload", 0o755);
        let archive = write_test_archive(
            &temp,
            &metadata_text(""),
            &manifest,
            "data/usr/bin/demo",
            b"actual payload",
            false,
        );

        assert!(inspect_archive(&archive).is_err());
    }

    #[test]
    fn inspect_archive_rejects_duplicate_members() {
        let temp = TempDir::new().unwrap();
        let payload = b"test executable\n";
        let archive = write_test_archive(
            &temp,
            &metadata_text(""),
            &manifest_text(payload, 0o755),
            "data/usr/bin/demo",
            payload,
            true,
        );

        assert!(inspect_archive(&archive).is_err());
    }

    #[test]
    fn inspect_archive_rejects_malformed_metadata() {
        let temp = TempDir::new().unwrap();
        let payload = b"test executable\n";
        let metadata = String::from_utf8(metadata_text("")).unwrap() + "name=duplicate\n";
        let archive = write_test_archive(
            &temp,
            metadata.as_bytes(),
            &manifest_text(payload, 0o755),
            "data/usr/bin/demo",
            payload,
            false,
        );

        assert!(inspect_archive(&archive).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_package_symlink() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let real_file = temp.0.join("real.khmpkg");
        fs::write(&real_file, b"not a package").unwrap();
        let symlink_path = temp.0.join("link.khmpkg");
        symlink(&real_file, &symlink_path).unwrap();

        assert!(open_regular_package(&symlink_path).is_err());
    }

    #[test]
    fn parses_mirrorlist_expands_placeholders_and_preserves_order() {
        let input = r#"
# Official mirror first.
[mirror]
khaymos.duckdns.org/repo/$arch/$khaymos
https://backup.example/repo/${arch}/${repo}/
https://backup.example/repo/x86_64/khaymos
[other]
ignored.example/repo
"#;

        assert_eq!(
            parse_mirrorlist(input).unwrap(),
            vec![
                "https://khaymos.duckdns.org/repo/x86_64/khaymos",
                "https://backup.example/repo/x86_64/khaymos",
            ]
        );
    }

    #[test]
    fn mirrorlist_requires_a_mirror_section_and_entry() {
        assert!(parse_mirrorlist("https://example.invalid/repo").is_err());
        assert!(parse_mirrorlist("[mirror]\n# only a comment\n").is_err());
    }

    #[test]
    fn mirrorlist_rejects_unsupported_schemes_and_credentials() {
        assert!(parse_mirrorlist("[mirror]\nftp://example.invalid/repo\n").is_err());
        assert!(parse_mirrorlist("[mirror]\nhttps://user@example.invalid/repo\n").is_err());
        assert!(parse_mirrorlist("[mirror]\nhttps://example.invalid/repo?x=1\n").is_err());
        assert!(parse_mirrorlist("[mirror]\nhttps://example.invalid/repo#fragment\n").is_err());
    }
}
