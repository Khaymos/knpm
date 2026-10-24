use super::{
    Result, TempDir, database_path, hash_reader, inspect_archive, install, invalid,
    load_mirrorlist, open_regular_package, require_privilege_for_system, resolve_root, valid_name,
    valid_version,
};
use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

const INDEX_MAGIC: &str = "# KHAYMOS-REPO-INDEX-1";
const INDEX_FIELDS: &str = "name\tversion\tarch\tfilename\tsha256\tdepends\tdescription";
const CACHE_MAGIC: &str = "# KNPM-REPOSITORY-CACHE-1";
const MAX_INDEX_BYTES: u64 = 32 * 1024 * 1024;
const MAX_DOWNLOAD_TIME_SECONDS: &str = "600";

#[derive(Debug, Clone, PartialEq, Eq)]
struct RepositoryPackage {
    name: String,
    version: String,
    arch: String,
    filename: String,
    sha256: String,
    depends: Vec<String>,
    description: String,
}

fn safe_filename(filename: &str) -> bool {
    filename.ends_with(".khmpkg")
        && filename.len() > ".khmpkg".len()
        && filename
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || "+_.:~-".contains(ch))
        && filename
            .chars()
            .next()
            .map(|ch| ch.is_ascii_alphanumeric())
            .unwrap_or(false)
}

fn parse_index(bytes: &[u8]) -> Result<Vec<RepositoryPackage>> {
    if bytes.len() as u64 > MAX_INDEX_BYTES {
        return Err(invalid("repository index exceeds the 32 MiB size limit"));
    }

    let text = std::str::from_utf8(bytes)?;
    if text.contains(['\r', '\0']) {
        return Err(invalid("repository index contains CR or NUL bytes"));
    }

    let mut lines = text.lines();
    if lines.next() != Some(INDEX_MAGIC) {
        return Err(invalid("unsupported repository index magic"));
    }
    if lines.next() != Some(INDEX_FIELDS) {
        return Err(invalid("repository index has an invalid field header"));
    }

    let mut records = Vec::new();
    let mut identities = HashSet::<(String, String, String)>::new();
    let mut filenames = HashSet::<String>::new();
    let mut previous_key: Option<(String, String, String, String)> = None;

    for (offset, line) in lines.enumerate() {
        let line_number = offset + 3;
        if line.is_empty() {
            return Err(invalid(format!(
                "empty repository index record on line {line_number}"
            )));
        }

        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 7 {
            return Err(invalid(format!(
                "repository index line {line_number} must have seven tab-separated fields"
            )));
        }

        let name = fields[0];
        let version = fields[1];
        let arch = fields[2];
        let filename = fields[3];
        let sha256 = fields[4];
        let depends_text = fields[5];
        let description = fields[6];

        if !valid_name(name) {
            return Err(invalid(format!(
                "invalid package name on index line {line_number}"
            )));
        }
        if !valid_version(version) {
            return Err(invalid(format!(
                "invalid package version on index line {line_number}"
            )));
        }
        if arch != "x86_64" && arch != "noarch" {
            return Err(invalid(format!(
                "unsupported package architecture on index line {line_number}"
            )));
        }
        if !safe_filename(filename) {
            return Err(invalid(format!(
                "unsafe package filename on index line {line_number}"
            )));
        }
        if sha256.len() != 64
            || !sha256
                .chars()
                .all(|ch| ch.is_ascii_digit() || ('a'..='f').contains(&ch))
        {
            return Err(invalid(format!(
                "invalid SHA-256 on index line {line_number}"
            )));
        }
        if description.chars().any(char::is_control) {
            return Err(invalid(format!(
                "invalid description on index line {line_number}"
            )));
        }

        let depends = if depends_text.is_empty() {
            Vec::new()
        } else {
            depends_text.split(',').map(str::to_string).collect()
        };
        let mut seen_dependencies = HashSet::new();
        for dependency in &depends {
            if !valid_name(dependency) {
                return Err(invalid(format!(
                    "invalid dependency on index line {line_number}: {dependency}"
                )));
            }
            if !seen_dependencies.insert(dependency) {
                return Err(invalid(format!(
                    "duplicate dependency on index line {line_number}: {dependency}"
                )));
            }
        }

        let identity = (name.to_string(), version.to_string(), arch.to_string());
        if !identities.insert(identity) {
            return Err(invalid(format!(
                "duplicate package identity on index line {line_number}: {name} {version} ({arch})"
            )));
        }
        if !filenames.insert(filename.to_string()) {
            return Err(invalid(format!("duplicate package filename: {filename}")));
        }

        let key = (
            name.to_string(),
            arch.to_string(),
            version.to_string(),
            filename.to_string(),
        );
        if previous_key
            .as_ref()
            .map(|previous| previous > &key)
            .unwrap_or(false)
        {
            return Err(invalid("repository index records are not sorted"));
        }
        previous_key = Some(key);

        records.push(RepositoryPackage {
            name: name.to_string(),
            version: version.to_string(),
            arch: arch.to_string(),
            filename: filename.to_string(),
            sha256: sha256.to_string(),
            depends,
            description: description.to_string(),
        });
    }

    if records.is_empty() {
        return Err(invalid("repository index contains no packages"));
    }

    Ok(records)
}

fn split_epoch(version: &str) -> (u64, &str) {
    if let Some((epoch, remainder)) = version.split_once(':')
        && !epoch.is_empty()
        && epoch.bytes().all(|byte| byte.is_ascii_digit())
    {
        return (epoch.parse::<u64>().unwrap_or(u64::MAX), remainder);
    }
    (0, version)
}

// A small natural version comparison: epochs and digit runs compare numerically;
// '~' sorts before a release without a prerelease suffix.
fn compare_version_body(left: &str, right: &str) -> Ordering {
    let a = left.as_bytes();
    let b = right.as_bytes();
    let (mut i, mut j) = (0, 0);

    loop {
        let a_tilde = a.get(i) == Some(&b'~');
        let b_tilde = b.get(j) == Some(&b'~');
        if a_tilde || b_tilde {
            match (a_tilde, b_tilde) {
                (true, true) => {
                    i += 1;
                    j += 1;
                    continue;
                }
                (true, false) => return Ordering::Less,
                (false, true) => return Ordering::Greater,
                (false, false) => unreachable!(),
            }
        }

        while i < a.len() && !a[i].is_ascii_alphanumeric() && a[i] != b'~' {
            i += 1;
        }
        while j < b.len() && !b[j].is_ascii_alphanumeric() && b[j] != b'~' {
            j += 1;
        }

        if i == a.len() || j == b.len() {
            return match (i == a.len(), j == b.len()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                (false, false) => unreachable!(),
            };
        }

        let a_numeric = a[i].is_ascii_digit();
        let b_numeric = b[j].is_ascii_digit();
        if a_numeric != b_numeric {
            return if a_numeric {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }

        let start_i = i;
        let start_j = j;
        if a_numeric {
            while i < a.len() && a[i].is_ascii_digit() {
                i += 1;
            }
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }

            let mut number_a = &a[start_i..i];
            let mut number_b = &b[start_j..j];
            while number_a.first() == Some(&b'0') {
                number_a = &number_a[1..];
            }
            while number_b.first() == Some(&b'0') {
                number_b = &number_b[1..];
            }

            let order = number_a
                .len()
                .cmp(&number_b.len())
                .then_with(|| number_a.cmp(number_b));
            if order != Ordering::Equal {
                return order;
            }
        } else {
            while i < a.len() && a[i].is_ascii_alphabetic() {
                i += 1;
            }
            while j < b.len() && b[j].is_ascii_alphabetic() {
                j += 1;
            }

            let segment_a = String::from_utf8_lossy(&a[start_i..i]).to_ascii_lowercase();
            let segment_b = String::from_utf8_lossy(&b[start_j..j]).to_ascii_lowercase();
            let order = segment_a.cmp(&segment_b);
            if order != Ordering::Equal {
                return order;
            }
        }
    }
}

fn compare_versions(left: &str, right: &str) -> Ordering {
    let (left_epoch, left_body) = split_epoch(left);
    let (right_epoch, right_body) = split_epoch(right);
    left_epoch
        .cmp(&right_epoch)
        .then_with(|| compare_version_body(left_body, right_body))
}

fn select_package<'a>(
    records: &'a [RepositoryPackage],
    name: &str,
) -> Result<&'a RepositoryPackage> {
    records
        .iter()
        .filter(|record| {
            record.name == name && (record.arch == "x86_64" || record.arch == "noarch")
        })
        .max_by(|left, right| {
            compare_versions(&left.version, &right.version).then_with(|| {
                match (left.arch.as_str(), right.arch.as_str()) {
                    ("x86_64", "noarch") => Ordering::Greater,
                    ("noarch", "x86_64") => Ordering::Less,
                    _ => Ordering::Equal,
                }
            })
        })
        .ok_or_else(|| invalid(format!("package not found in repository: {name}")))
}

fn resolve_dependency(
    name: &str,
    records: &[RepositoryPackage],
    installed: &HashSet<String>,
    visiting: &mut HashSet<String>,
    visited: &mut HashSet<String>,
    order: &mut Vec<RepositoryPackage>,
) -> Result<()> {
    if installed.contains(name) || visited.contains(name) {
        return Ok(());
    }
    if !visiting.insert(name.to_string()) {
        return Err(invalid(format!(
            "dependency cycle detected at package: {name}"
        )));
    }

    let package = select_package(records, name)?.clone();
    for dependency in &package.depends {
        resolve_dependency(dependency, records, installed, visiting, visited, order)?;
    }

    visiting.remove(name);
    visited.insert(name.to_string());
    order.push(package);
    Ok(())
}

fn resolve_install_order(
    requested: &str,
    records: &[RepositoryPackage],
    installed: &HashSet<String>,
) -> Result<Vec<RepositoryPackage>> {
    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();
    let mut order = Vec::new();
    resolve_dependency(
        requested,
        records,
        installed,
        &mut visiting,
        &mut visited,
        &mut order,
    )?;
    Ok(order)
}

fn curl_command(url: &str, max_seconds: &str) -> Command {
    let mut command = Command::new("curl");
    command
        .arg("--fail")
        .arg("--silent")
        .arg("--show-error")
        .arg("--location")
        .arg("--max-redirs")
        .arg("5")
        .arg("--proto")
        .arg("=http,https")
        .arg("--proto-redir")
        .arg("=https")
        .arg("--connect-timeout")
        .arg("10")
        .arg("--max-time")
        .arg(max_seconds)
        .arg("--url")
        .arg(url);
    command
}

fn curl_bytes(url: &str, max_bytes: u64) -> Result<Vec<u8>> {
    let mut child = curl_command(url, "60")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            invalid(format!(
                "cannot start curl ({error}); install curl to use remote repositories"
            ))
        })?;

    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| invalid("cannot read curl output"))?;
    let mut result = Vec::new();
    let mut buffer = [0_u8; 64 * 1024];

    loop {
        let count = match stdout.read(&mut buffer) {
            Ok(count) => count,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.into());
            }
        };
        if count == 0 {
            break;
        }

        if (result.len() as u64).saturating_add(count as u64) > max_bytes {
            drop(stdout);
            let _ = child.kill();
            let _ = child.wait_with_output();
            return Err(invalid("download exceeds the allowed size limit"));
        }
        result.extend_from_slice(&buffer[..count]);
    }
    drop(stdout);

    let output = child.wait_with_output()?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(invalid(if message.is_empty() {
            format!("curl failed to download {url}")
        } else {
            format!("curl failed for {url}: {message}")
        }));
    }

    Ok(result)
}

fn curl_to_file(url: &str, path: &Path, max_bytes: u64) -> Result<()> {
    let mut child = curl_command(url, MAX_DOWNLOAD_TIME_SECONDS)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            invalid(format!(
                "cannot start curl ({error}); install curl to use remote repositories"
            ))
        })?;

    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| invalid("cannot read curl output"))?;

    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) => {
            drop(stdout);
            let _ = child.kill();
            let _ = child.wait_with_output();
            return Err(error.into());
        }
    };

    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    let transfer_result: Result<()> = loop {
        let count = match stdout.read(&mut buffer) {
            Ok(count) => count,
            Err(error) => break Err(error.into()),
        };
        if count == 0 {
            break Ok(());
        }

        total = total.saturating_add(count as u64);
        if total > max_bytes {
            break Err(invalid("download exceeds the allowed size limit"));
        }
        if let Err(error) = file.write_all(&buffer[..count]) {
            break Err(error.into());
        }
    };

    drop(stdout);
    if let Err(error) = transfer_result {
        let _ = child.kill();
        let _ = child.wait_with_output();
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }

    let output = child.wait_with_output()?;
    if !output.status.success() {
        drop(file);
        let _ = fs::remove_file(path);
        let message = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(invalid(if message.is_empty() {
            format!("curl failed to download {url}")
        } else {
            format!("curl failed for {url}: {message}")
        }));
    }

    file.sync_all()?;
    drop(file);
    Ok(())
}

fn cache_path(root: &Path, create: bool) -> Result<Option<PathBuf>> {
    let Some(database) = database_path(root, create)? else {
        return Ok(None);
    };
    let path = database.join("repository-cache-v1");

    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => Err(invalid(
            "repository cache must be a regular, non-symlink file",
        )),
        Ok(_) => Ok(Some(path)),
        Err(error) if error.kind() == io::ErrorKind::NotFound && !create => Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound && create => Ok(Some(path)),
        Err(error) => Err(error.into()),
    }
}

fn write_cache(root: &Path, base: &str, index: &[u8]) -> Result<()> {
    let path = cache_path(root, true)?.ok_or_else(|| invalid("cannot create repository cache"))?;
    let mut data = format!("{CACHE_MAGIC}\n{base}\n").into_bytes();
    data.extend_from_slice(index);
    atomic_write(&path, &data)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(invalid(format!(
                "refusing to replace an unsafe cache path: {}",
                path.display()
            )));
        }
    }

    let parent = path
        .parent()
        .ok_or_else(|| invalid("repository cache has no parent directory"))?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();

    for attempt in 0..32_u32 {
        let temporary = parent.join(format!(
            ".knpm-cache-{}-{stamp}-{attempt}",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o644);

        let mut file = match options.open(&temporary) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        };

        if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
            drop(file);
            let _ = fs::remove_file(&temporary);
            return Err(error.into());
        }
        drop(file);

        if let Err(error) = fs::rename(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(error.into());
        }

        if let Ok(directory) = File::open(parent) {
            let _ = directory.sync_all();
        }
        return Ok(());
    }

    Err(invalid("cannot allocate a temporary repository cache file"))
}

fn fetch_repository(mirrors: &[String]) -> Result<(String, Vec<u8>, Vec<RepositoryPackage>)> {
    let mut errors = Vec::new();

    for base in mirrors {
        let url = format!("{}/index.tsv", base.trim_end_matches('/'));
        match curl_bytes(&url, MAX_INDEX_BYTES) {
            Ok(bytes) => match parse_index(&bytes) {
                Ok(records) => return Ok((base.clone(), bytes, records)),
                Err(error) => errors.push(format!("{base}: invalid index: {error}")),
            },
            Err(error) => errors.push(format!("{base}: {error}")),
        }
    }

    Err(invalid(format!(
        "could not fetch a valid repository index from any configured mirror:\n{}",
        errors.join("\n")
    )))
}

fn read_cached_repository(
    root: &Path,
    mirrors: &[String],
) -> Result<(String, Vec<u8>, Vec<RepositoryPackage>)> {
    let path = cache_path(root, false)?
        .ok_or_else(|| invalid("no cached repository index; run 'knpm sync' or 'knpm update' first"))?;
    let metadata = fs::symlink_metadata(&path)?;
    if metadata.len() > MAX_INDEX_BYTES + 4096 {
        return Err(invalid("cached repository index exceeds the size limit"));
    }

    let contents = fs::read_to_string(&path)?;
    let mut parts = contents.splitn(3, '\n');
    if parts.next() != Some(CACHE_MAGIC) {
        return Err(invalid("repository cache has an invalid header"));
    }
    let base = parts
        .next()
        .ok_or_else(|| invalid("repository cache is missing its mirror URL"))?;
    let index_text = parts
        .next()
        .ok_or_else(|| invalid("repository cache is missing its index"))?;
    if !mirrors.iter().any(|mirror| mirror == base) {
        return Err(invalid(
            "cached repository mirror is not present in the current mirrorlist; run 'knpm sync'",
        ));
    }

    let index = index_text.as_bytes().to_vec();
    let records = parse_index(&index)?;
    Ok((base.to_string(), index, records))
}

fn fetch_and_cache(
    root: &Path,
    mirrors: &[String],
) -> Result<(String, Vec<u8>, Vec<RepositoryPackage>)> {
    let (base, bytes, records) = fetch_repository(mirrors)?;
    write_cache(root, &base, &bytes)?;
    Ok((base, bytes, records))
}

fn installed_names(root: &Path) -> Result<HashSet<String>> {
    let mut installed = HashSet::new();
    let Some(database) = database_path(root, false)? else {
        return Ok(installed);
    };
    let directory = database.join("installed");

    for item in fs::read_dir(directory)? {
        let item = item?;
        let filename = item.file_name();
        let Some(name) = filename.to_str() else {
            return Err(invalid("non-UTF-8 installed package database entry"));
        };
        if name.starts_with('.') {
            continue;
        }

        let metadata = fs::symlink_metadata(item.path())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(invalid(format!("invalid installed package record: {name}")));
        }
        let record = super::read_record_metadata(&item.path())?;
        if record.name != name {
            return Err(invalid(format!(
                "installed package record name mismatch: {name}"
            )));
        }
        installed.insert(name.to_string());
    }

    Ok(installed)
}

fn installed_versions(root: &Path) -> Result<HashMap<String, String>> {
    let mut installed = HashMap::new();
    let Some(database) = database_path(root, false)? else {
        return Ok(installed);
    };
    let directory = database.join("installed");

    for item in fs::read_dir(directory)? {
        let item = item?;
        let filename = item.file_name();
        let Some(name) = filename.to_str() else {
            return Err(invalid("non-UTF-8 installed package database entry"));
        };
        if name.starts_with('.') {
            continue;
        }

        let metadata = fs::symlink_metadata(item.path())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(invalid(format!("invalid installed package record: {name}")));
        }

        let record = super::read_record_metadata(&item.path())?;
        if record.name != name {
            return Err(invalid(format!(
                "installed package record name mismatch: {name}"
            )));
        }
        installed.insert(name.to_string(), record.version);
    }

    Ok(installed)
}

fn available_updates(
    installed: &HashMap<String, String>,
    records: &[RepositoryPackage],
) -> Vec<(String, String, String)> {
    let mut updates = Vec::new();

    for (name, installed_version) in installed {
        let Ok(available) = select_package(records, name) else {
            // Locally installed packages do not need to exist in the configured
            // repository to remain installed.
            continue;
        };

        if compare_versions(&available.version, installed_version) == Ordering::Greater {
            updates.push((
                name.clone(),
                installed_version.clone(),
                available.version.clone(),
            ));
        }
    }

    updates.sort_by(|left, right| left.0.cmp(&right.0));
    updates
}

fn verify_download(path: &Path, expected: &RepositoryPackage) -> Result<()> {
    let mut file = open_regular_package(path)?;
    let digest = hash_reader(&mut file)?;
    if digest != expected.sha256 {
        return Err(invalid(format!(
            "SHA-256 mismatch for downloaded package {}",
            expected.filename
        )));
    }

    let package = inspect_archive(path)?;
    if package.metadata.name != expected.name
        || package.metadata.version != expected.version
        || package.metadata.arch != expected.arch
        || package.metadata.depends != expected.depends
        || package.metadata.description != expected.description
    {
        return Err(invalid(format!(
            "downloaded package metadata does not match the repository index: {}",
            expected.filename
        )));
    }

    Ok(())
}

fn download_package(
    mirrors: &[String],
    package: &RepositoryPackage,
    destination_dir: &Path,
) -> Result<PathBuf> {
    let destination = destination_dir.join(&package.filename);
    let mut errors = Vec::new();

    for mirror in mirrors {
        if destination.exists() {
            fs::remove_file(&destination)?;
        }

        let url = format!(
            "{}/packages/{}",
            mirror.trim_end_matches('/'),
            package.filename
        );

        match curl_to_file(&url, &destination, super::MAX_COMPRESSED_PACKAGE_BYTES) {
            Ok(()) => match verify_download(&destination, package) {
                Ok(()) => return Ok(destination),
                Err(error) => {
                    errors.push(format!("{mirror}: {error}"));
                    let _ = fs::remove_file(&destination);
                }
            },
            Err(error) => {
                errors.push(format!("{mirror}: {error}"));
                let _ = fs::remove_file(&destination);
            }
        }
    }

    Err(invalid(format!(
        "could not download and verify {} from any configured mirror:\n{}",
        package.name,
        errors.join("\n")
    )))
}

fn package_installed(root: &Path, name: &str) -> Result<bool> {
    let Some(database) = database_path(root, false)? else {
        return Ok(false);
    };
    let record_path = database.join("installed").join(name);

    match fs::symlink_metadata(&record_path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(invalid(format!("invalid installed package record: {name}")))
        }
        Ok(_) => {
            let metadata = super::read_record_metadata(&record_path)?;
            if metadata.name != name {
                return Err(invalid(format!("installed package name mismatch: {name}")));
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn sync() -> Result<()> {
    let root = resolve_root()?;
    require_privilege_for_system(&root)?;
    let mirrors = load_mirrorlist(&super::configured_mirrorlist_path())?;
    let (base, _bytes, records) = fetch_and_cache(&root, &mirrors)?;

    println!("Repository synchronized: {} package(s)", records.len());
    println!("Mirror: {base}");
    Ok(())
}

pub(super) fn search(query: Option<&str>) -> Result<()> {
    let root = resolve_root()?;
    let mirrors = load_mirrorlist(&super::configured_mirrorlist_path())?;
    let (base, _bytes, records) = read_cached_repository(&root, &mirrors)?;
    let needle = query.unwrap_or_default().to_ascii_lowercase();

    let mut latest = HashMap::<String, RepositoryPackage>::new();
    for record in records {
        if record.arch != "x86_64" && record.arch != "noarch" {
            continue;
        }

        match latest.get(&record.name) {
            Some(current) => {
                let order = compare_versions(&record.version, &current.version);
                let prefer_arch = record.arch == "x86_64" && current.arch == "noarch";
                if order == Ordering::Greater || (order == Ordering::Equal && prefer_arch) {
                    latest.insert(record.name.clone(), record);
                }
            }
            None => {
                latest.insert(record.name.clone(), record);
            }
        }
    }

    let mut results: Vec<RepositoryPackage> = latest
        .into_values()
        .filter(|record| {
            needle.is_empty()
                || record.name.to_ascii_lowercase().contains(&needle)
                || record.description.to_ascii_lowercase().contains(&needle)
        })
        .collect();
    results.sort_by(|left, right| left.name.cmp(&right.name));

    if results.is_empty() {
        println!("No matching packages.");
        return Ok(());
    }

    println!("Repository: {base}");
    println!(
        "{:<28} {:<16} {:<10} DESCRIPTION",
        "NAME", "VERSION", "ARCH"
    );
    println!(
        "{:<28} {:<16} {:<10} -----------",
        "----", "-------", "----"
    );
    for record in &results {
        println!(
            "{:<28} {:<16} {:<10} {}",
            record.name, record.version, record.arch, record.description
        );
    }
    println!("\n{} package(s) found.", results.len());
    Ok(())
}

pub(super) fn outdated() -> Result<()> {
    let root = resolve_root()?;
    let installed = installed_versions(&root)?;

    if installed.is_empty() {
        println!("No packages installed.");
        return Ok(());
    }

    let mirrors = load_mirrorlist(&super::configured_mirrorlist_path())?;
    let (base, _bytes, records) = read_cached_repository(&root, &mirrors)?;
    let updates = available_updates(&installed, &records);

    if updates.is_empty() {
        println!("All installed packages are up to date.");
        println!("Checked repository: {base}");
        return Ok(());
    }

    println!("Repository: {base}");
    println!("{:<28} {:<16} AVAILABLE", "NAME", "INSTALLED");
    println!("{:<28} {:<16} ---------", "----", "---------");
    for (name, installed_version, available_version) in &updates {
        println!("{:<28} {:<16} {}", name, installed_version, available_version);
    }
    println!("\n{} update(s) available.", updates.len());
    println!("Run 'knpm update' to refresh the repository index.");
    println!("Package upgrades are not implemented yet.");

    Ok(())
}

pub(super) fn install_by_name(name: &str, override_existing: bool) -> Result<()> {
    if !valid_name(name) {
        return Err(invalid(format!("invalid package name: {name}")));
    }

    let root = resolve_root()?;
    require_privilege_for_system(&root)?;
    if package_installed(&root, name)? {
        return Err(invalid(format!(
            "{name} is already installed; upgrades are not supported yet"
        )));
    }

    let mirrors = load_mirrorlist(&super::configured_mirrorlist_path())?;
    let (_base, _bytes, records) = fetch_and_cache(&root, &mirrors)?;
    let installed = installed_names(&root)?;
    let order = resolve_install_order(name, &records, &installed)?;

    if order.is_empty() {
        return Err(invalid(format!("nothing to install for package: {name}")));
    }

    let temporary = TempDir::new()?;
    let mut archives = HashMap::<String, PathBuf>::new();

    // Download and fully verify every archive before changing the installed system.
    for package in &order {
        let path = download_package(&mirrors, package, &temporary.0)?;
        archives.insert(package.name.clone(), path);
    }

    for package in &order {
        let archive = archives
            .get(&package.name)
            .ok_or_else(|| invalid("internal error: downloaded package missing"))?;
        install(archive, override_existing && package.name == name)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index_row(
        name: &str,
        version: &str,
        arch: &str,
        filename: &str,
        depends: &str,
        description: &str,
    ) -> String {
        format!(
            "{name}\t{version}\t{arch}\t{filename}\t{}\t{depends}\t{description}\n",
            "a".repeat(64)
        )
    }

    fn make_index(rows: &[String]) -> Vec<u8> {
        format!("{INDEX_MAGIC}\n{INDEX_FIELDS}\n{}", rows.concat()).into_bytes()
    }

    #[test]
    fn parses_a_valid_repository_index() {
        let index = make_index(&[
            index_row(
                "bash",
                "5.3",
                "x86_64",
                "bash-5.3.khmpkg",
                "glibc",
                "GNU shell",
            ),
            index_row(
                "glibc",
                "2.44",
                "x86_64",
                "glibc-2.44.khmpkg",
                "",
                "GNU C library",
            ),
        ]);
        let records = parse_index(&index).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].name, "bash");
        assert_eq!(records[0].depends, vec!["glibc"]);
    }

    #[test]
    fn rejects_invalid_index_headers_and_rows() {
        assert!(parse_index(b"# wrong\nname\n").is_err());
        assert!(parse_index(format!("{INDEX_MAGIC}\nwrong\n").as_bytes()).is_err());
        let row = index_row("bash", "5.3", "x86_64", "../bash.khmpkg", "", "shell");
        assert!(parse_index(&make_index(&[row])).is_err());
        let row = index_row("bash", "5.3", "x86_64", "bash.khmpkg", "", "shell")
            .replace(&"a".repeat(64), "xyz");
        assert!(parse_index(&make_index(&[row])).is_err());
    }

    #[test]
    fn rejects_duplicate_identity_filename_and_unsorted_records() {
        let duplicate = index_row("bash", "5.3", "x86_64", "bash-5.3.khmpkg", "", "shell");
        assert!(parse_index(&make_index(&[duplicate.clone(), duplicate])).is_err());

        let first = index_row(
            "zlib",
            "1.0",
            "x86_64",
            "zlib-1.0.khmpkg",
            "",
            "compression",
        );
        let second = index_row("bash", "5.3", "x86_64", "bash-5.3.khmpkg", "", "shell");
        assert!(parse_index(&make_index(&[first, second])).is_err());
    }

    #[test]
    fn selects_versions_naturally_and_honors_epochs() {
        assert_eq!(compare_versions("10.0", "9.9"), Ordering::Greater);
        assert_eq!(compare_versions("1:1.0", "2.0"), Ordering::Greater);
        assert_eq!(compare_versions("1.0~rc1", "1.0"), Ordering::Less);
    }

    #[test]
    fn finds_newer_available_versions_for_installed_packages() {
        let installed = HashMap::from([
            ("bash".to_string(), "5.2".to_string()),
            ("glibc".to_string(), "2.44".to_string()),
            ("local-only".to_string(), "1.0".to_string()),
        ]);
        let records = vec![
            RepositoryPackage {
                name: "bash".to_string(),
                version: "5.3".to_string(),
                arch: "x86_64".to_string(),
                filename: "bash-5.3.khmpkg".to_string(),
                sha256: "a".repeat(64),
                depends: Vec::new(),
                description: "shell".to_string(),
            },
            RepositoryPackage {
                name: "bash".to_string(),
                version: "5.3".to_string(),
                arch: "noarch".to_string(),
                filename: "bash-5.3-noarch.khmpkg".to_string(),
                sha256: "b".repeat(64),
                depends: Vec::new(),
                description: "shell".to_string(),
            },
            RepositoryPackage {
                name: "glibc".to_string(),
                version: "2.44".to_string(),
                arch: "x86_64".to_string(),
                filename: "glibc-2.44.khmpkg".to_string(),
                sha256: "c".repeat(64),
                depends: Vec::new(),
                description: "GNU C library".to_string(),
            },
        ];

        assert_eq!(
            available_updates(&installed, &records),
            vec![("bash".to_string(), "5.2".to_string(), "5.3".to_string())]
        );
    }

    #[test]
    fn does_not_report_downgrades_as_updates() {
        let installed = HashMap::from([("bash".to_string(), "9.0".to_string())]);
        let records = vec![RepositoryPackage {
            name: "bash".to_string(),
            version: "5.3".to_string(),
            arch: "x86_64".to_string(),
            filename: "bash-5.3.khmpkg".to_string(),
            sha256: "a".repeat(64),
            depends: Vec::new(),
            description: "shell".to_string(),
        }];

        assert!(available_updates(&installed, &records).is_empty());
    }

    #[test]
    fn resolves_dependencies_before_requested_package() {
        let records = vec![
            RepositoryPackage {
                name: "bash".to_string(),
                version: "5.3".to_string(),
                arch: "x86_64".to_string(),
                filename: "bash-5.3.khmpkg".to_string(),
                sha256: "a".repeat(64),
                depends: vec!["glibc".to_string()],
                description: "shell".to_string(),
            },
            RepositoryPackage {
                name: "glibc".to_string(),
                version: "2.44".to_string(),
                arch: "x86_64".to_string(),
                filename: "glibc-2.44.khmpkg".to_string(),
                sha256: "b".repeat(64),
                depends: Vec::new(),
                description: "library".to_string(),
            },
        ];
        let order = resolve_install_order("bash", &records, &HashSet::new()).unwrap();
        assert_eq!(
            order
                .iter()
                .map(|record| record.name.as_str())
                .collect::<Vec<_>>(),
            vec!["glibc", "bash"]
        );
    }

    #[test]
    fn rejects_dependency_cycles_and_missing_dependencies() {
        let mut a = RepositoryPackage {
            name: "alpha".to_string(),
            version: "1".to_string(),
            arch: "noarch".to_string(),
            filename: "alpha-1.khmpkg".to_string(),
            sha256: "a".repeat(64),
            depends: vec!["beta".to_string()],
            description: "alpha".to_string(),
        };
        let b = RepositoryPackage {
            name: "beta".to_string(),
            version: "1".to_string(),
            arch: "noarch".to_string(),
            filename: "beta-1.khmpkg".to_string(),
            sha256: "b".repeat(64),
            depends: vec!["alpha".to_string()],
            description: "beta".to_string(),
        };
        assert!(resolve_install_order("alpha", &[a.clone(), b.clone()], &HashSet::new()).is_err());

        a.depends = vec!["missing".to_string()];
        assert!(resolve_install_order("alpha", &[a], &HashSet::new()).is_err());
    }
}
