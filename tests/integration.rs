use flate2::{Compression, write::GzEncoder};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{Write, empty},
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};
use tar::{Builder, EntryType, Header};

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let base = std::env::temp_dir();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after the Unix epoch")
            .as_nanos();

        for attempt in 0..32_u32 {
            let path = base.join(format!(
                "knpm-integration-{}-{stamp}-{attempt}",
                std::process::id()
            ));

            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("cannot create test directory {}: {error}", path.display()),
            }
        }

        panic!("cannot allocate a unique KNPM integration-test directory");
    }

    fn root(&self) -> PathBuf {
        let root = self.0.join("root");
        fs::create_dir(&root).expect("create temporary target root");
        root
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn append_dir<W: Write>(builder: &mut Builder<W>, path: &str) {
    let mut header = Header::new_gnu();
    header.set_entry_type(EntryType::Directory);
    header.set_size(0);
    header.set_mode(0o755);
    header.set_mtime(0);
    header.set_cksum();

    builder
        .append_data(&mut header, path, empty())
        .expect("append directory to test package");
}

fn append_file<W: Write>(builder: &mut Builder<W>, path: &str, bytes: &[u8], mode: u32) {
    let mut header = Header::new_gnu();
    header.set_entry_type(EntryType::Regular);
    header.set_size(bytes.len() as u64);
    header.set_mode(mode);
    header.set_mtime(0);
    header.set_cksum();

    builder
        .append_data(&mut header, path, bytes)
        .expect("append file to test package");
}

fn write_package(
    base: &TestDir,
    package_name: &str,
    depends: &[&str],
    payload_path: &str,
    payload: &[u8],
) -> PathBuf {
    assert!(!payload_path.starts_with('/'));
    assert!(
        payload_path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
    );

    let mut directories = BTreeSet::new();
    let components: Vec<&str> = payload_path.split('/').collect();
    for end in 1..components.len() {
        directories.insert(components[..end].join("/"));
    }

    let mut manifest = String::new();
    for directory in &directories {
        manifest.push_str(&format!("D\t0755\t-\t{directory}\n"));
    }
    manifest.push_str(&format!("F\t0755\t{}\t{payload_path}\n", sha256(payload)));

    let metadata = format!(
        "format=KHMPKG-1\nname={package_name}\nversion=1.0\narch=x86_64\ndescription=Integration test package\ndepends={}\n",
        depends.join(",")
    );

    let path = base.0.join(format!("{package_name}.khmpkg"));
    let file = File::create(&path).expect("create test package file");
    let encoder = GzEncoder::new(file, Compression::default());
    let mut builder = Builder::new(encoder);

    append_dir(&mut builder, "CONTROL");
    append_file(&mut builder, "CONTROL/metadata", metadata.as_bytes(), 0o644);
    append_file(&mut builder, "CONTROL/manifest", manifest.as_bytes(), 0o644);
    append_dir(&mut builder, "data");

    for directory in &directories {
        append_dir(&mut builder, &format!("data/{directory}"));
    }
    append_file(
        &mut builder,
        &format!("data/{payload_path}"),
        payload,
        0o755,
    );

    builder
        .into_inner()
        .expect("finish test package tar archive")
        .finish()
        .expect("finish test package gzip stream");

    path
}

fn run_knpm(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_knpm"))
        .args(args)
        .env("KNPM_ROOT", root)
        .output()
        .expect("launch KNPM test binary")
}

fn assert_success(output: &Output, operation: &str) {
    assert!(
        output.status.success(),
        "{operation} should succeed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_failure(output: &Output, operation: &str) {
    assert!(
        !output.status.success(),
        "{operation} should fail\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn installs_lists_and_removes_a_package_in_a_temporary_root() {
    let temp = TestDir::new();
    let root = temp.root();
    let payload = b"#!/bin/sh\necho installed-by-knpm\n";
    let archive = write_package(&temp, "demo", &[], "usr/bin/demo", payload);

    let install = run_knpm(&root, &["install", archive.to_str().unwrap()]);
    assert_success(&install, "install demo");

    let installed_file = root.join("usr/bin/demo");
    assert_eq!(fs::read(&installed_file).unwrap(), payload);
    assert_eq!(
        fs::metadata(&installed_file)
            .unwrap()
            .permissions()
            .readonly(),
        false
    );

    let list = run_knpm(&root, &["list"]);
    assert_success(&list, "list packages");
    assert!(
        String::from_utf8_lossy(&list.stdout).contains("demo"),
        "package list did not contain demo: {}",
        String::from_utf8_lossy(&list.stdout)
    );

    let remove = run_knpm(&root, &["remove", "demo"]);
    assert_success(&remove, "remove demo");
    assert!(!installed_file.exists(), "installed file should be removed");
    assert!(
        !root.join("var/lib/knpm/installed/demo").exists(),
        "package database record should be removed"
    );
    assert!(
        !root.join("usr/bin").exists(),
        "created directories should be cleaned up"
    );
}

#[test]
fn enforces_dependencies_before_installation() {
    let temp = TestDir::new();
    let root = temp.root();
    let app = write_package(&temp, "demo-app", &["glibc"], "usr/bin/demo-app", b"app");
    let app_file = root.join("usr/bin/demo-app");

    let missing_dependency = run_knpm(&root, &["install", app.to_str().unwrap()]);
    assert_failure(&missing_dependency, "install app without glibc");
    assert!(
        String::from_utf8_lossy(&missing_dependency.stderr).contains("missing dependency 'glibc'"),
        "unexpected dependency error: {}",
        String::from_utf8_lossy(&missing_dependency.stderr)
    );
    assert!(
        !app_file.exists(),
        "package payload must not be installed on dependency failure"
    );

    let glibc = write_package(
        &temp,
        "glibc",
        &[],
        "usr/lib/libc-test.so",
        b"test libc placeholder",
    );
    let install_glibc = run_knpm(&root, &["install", glibc.to_str().unwrap()]);
    assert_success(&install_glibc, "install dependency");

    let install_app = run_knpm(&root, &["install", app.to_str().unwrap()]);
    assert_success(&install_app, "install app after dependency");
    assert!(
        app_file.exists(),
        "app payload should exist after dependencies are installed"
    );
}

#[test]
fn refuses_to_overwrite_an_unowned_existing_file() {
    let temp = TestDir::new();
    let root = temp.root();
    let existing = root.join("usr/bin/demo");
    fs::create_dir_all(existing.parent().unwrap()).unwrap();
    fs::write(&existing, b"owned by the user, not KNPM").unwrap();

    let archive = write_package(&temp, "demo", &[], "usr/bin/demo", b"replacement");
    let output = run_knpm(&root, &["install", archive.to_str().unwrap()]);

    assert_failure(&output, "install over an unowned file");
    assert_eq!(
        fs::read(&existing).unwrap(),
        b"owned by the user, not KNPM",
        "KNPM must preserve unowned files"
    );
    assert!(
        !root.join("var/lib/knpm/installed/demo").exists(),
        "failed install must not register the package"
    );
}

#[test]
fn override_transfers_file_ownership_between_packages() {
    let temp = TestDir::new();
    let root = temp.root();
    let old_archive = write_package(
        &temp,
        "old-tool",
        &[],
        "usr/bin/shared-tool",
        b"old version",
    );
    let new_archive = write_package(
        &temp,
        "new-tool",
        &[],
        "usr/bin/shared-tool",
        b"new version",
    );

    let install_old = run_knpm(&root, &["install", old_archive.to_str().unwrap()]);
    assert_success(&install_old, "install old package");

    let denied = run_knpm(&root, &["install", new_archive.to_str().unwrap()]);
    assert_failure(&denied, "install conflicting package without override");
    assert_eq!(
        fs::read(root.join("usr/bin/shared-tool")).unwrap(),
        b"old version"
    );

    let override_result = run_knpm(
        &root,
        &["install", "--override", new_archive.to_str().unwrap()],
    );
    assert_success(&override_result, "override old package file");

    assert_eq!(
        fs::read(root.join("usr/bin/shared-tool")).unwrap(),
        b"new version"
    );

    let old_manifest =
        fs::read_to_string(root.join("var/lib/knpm/installed/old-tool/manifest")).unwrap();
    let new_manifest =
        fs::read_to_string(root.join("var/lib/knpm/installed/new-tool/manifest")).unwrap();
    assert!(
        !old_manifest.contains("usr/bin/shared-tool"),
        "old package should no longer claim the transferred file"
    );
    assert!(
        new_manifest.contains("usr/bin/shared-tool"),
        "new package should claim the transferred file"
    );
}

#[test]
fn failed_override_restores_the_original_file() {
    let temp = TestDir::new();
    let root = temp.root();
    let old_archive = write_package(
        &temp,
        "old-tool",
        &[],
        "usr/bin/shared-tool",
        b"old version",
    );
    let new_archive = write_package(
        &temp,
        "new-tool",
        &[],
        "usr/bin/shared-tool",
        b"new version",
    );

    let install_old = run_knpm(&root, &["install", old_archive.to_str().unwrap()]);
    assert_success(&install_old, "install old package");

    // Force a failure after KNPM backs up the old payload but before it can
    // rewrite the old package's database record.
    let old_record = root.join("var/lib/knpm/installed/old-tool");
    fs::remove_file(old_record.join("created-dirs")).unwrap();

    let result = run_knpm(
        &root,
        &["install", "--override", new_archive.to_str().unwrap()],
    );
    assert_failure(&result, "override with a damaged owner record");

    assert_eq!(
        fs::read(root.join("usr/bin/shared-tool")).unwrap(),
        b"old version",
        "rollback must restore the original payload"
    );
    assert!(
        !root.join("var/lib/knpm/installed/new-tool").exists(),
        "failed package must not be registered"
    );

    // No hidden backup should remain after transaction rollback.
    let entries: Vec<_> = fs::read_dir(root.join("usr/bin"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries, vec![std::ffi::OsString::from("shared-tool")]);
}

fn append_symlink<W: Write>(builder: &mut Builder<W>, path: &str, target: &str) {
    let mut header = Header::new_gnu();
    header.set_entry_type(EntryType::Symlink);
    header.set_size(0);
    header.set_mode(0o777);
    header.set_mtime(0);
    builder
        .append_link(&mut header, path, target)
        .expect("append symbolic link to test package");
}

fn write_package_with_symlink(base: &TestDir) -> PathBuf {
    let package_name = "demo-links";
    let payload = b"symlink target contents\n";
    let target = "real";
    let metadata = format!(
        "format=KHMPKG-1\nname={package_name}\nversion=1.0\narch=x86_64\ndescription=Symlink integration test\ndepends=\n"
    );
    let manifest = format!(
        "D\t0755\t-\tusr\nD\t0755\t-\tusr/bin\nF\t0755\t{}\tusr/bin/real\nL\t0777\t{}\tusr/bin/shortcut\n",
        sha256(payload),
        sha256(target.as_bytes())
    );

    let path = base.0.join(format!("{package_name}.khmpkg"));
    let file = File::create(&path).expect("create symlink test package");
    let encoder = GzEncoder::new(file, Compression::default());
    let mut builder = Builder::new(encoder);

    append_dir(&mut builder, "CONTROL");
    append_file(&mut builder, "CONTROL/metadata", metadata.as_bytes(), 0o644);
    append_file(&mut builder, "CONTROL/manifest", manifest.as_bytes(), 0o644);
    append_dir(&mut builder, "data");
    append_dir(&mut builder, "data/usr");
    append_dir(&mut builder, "data/usr/bin");
    append_file(&mut builder, "data/usr/bin/real", payload, 0o755);
    append_symlink(&mut builder, "data/usr/bin/shortcut", target);

    builder
        .into_inner()
        .expect("finish symlink test tar archive")
        .finish()
        .expect("finish symlink test gzip stream");

    path
}

fn write_traversal_archive(base: &TestDir) -> PathBuf {
    let path = base.0.join("traversal.khmpkg");
    let file = File::create(&path).expect("create traversal test archive");
    let mut encoder = GzEncoder::new(file, Compression::default());

    // Construct the 512-byte POSIX tar header directly: the tar crate's
    // public header/path helpers intentionally reject parent-directory paths.
    let mut header = [0_u8; 512];
    let name = b"../outside";
    header[..name.len()].copy_from_slice(name);
    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    header[124..136].copy_from_slice(b"00000000000\0");
    header[136..148].copy_from_slice(b"00000000000\0");
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");

    let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    let checksum_field = format!("{checksum:06o}\0 ");
    assert_eq!(checksum_field.len(), 8);
    header[148..156].copy_from_slice(checksum_field.as_bytes());

    encoder
        .write_all(&header)
        .expect("write malicious tar header");
    encoder
        .write_all(&[0_u8; 1024])
        .expect("write tar end markers");
    encoder.finish().expect("finish traversal test gzip stream");

    path
}

#[test]
fn install_and_remove_package_symlink() {
    let temp = TestDir::new();
    let root = temp.root();
    let archive = write_package_with_symlink(&temp);

    let install = run_knpm(&root, &["install", archive.to_str().unwrap()]);
    assert_success(&install, "install package containing a relative symlink");

    let real_file = root.join("usr/bin/real");
    let shortcut = root.join("usr/bin/shortcut");
    assert_eq!(fs::read_link(&shortcut).unwrap(), Path::new("real"));
    assert_eq!(fs::read(&shortcut).unwrap(), fs::read(&real_file).unwrap());

    let remove = run_knpm(&root, &["remove", "demo-links"]);
    assert_success(&remove, "remove package containing a relative symlink");
    assert!(!real_file.exists(), "target file should be removed");
    assert!(!shortcut.exists(), "symlink should be removed");
    assert!(
        !root.join("var/lib/knpm/installed/demo-links").exists(),
        "package record should be removed"
    );
}

#[test]
fn refuses_to_remove_a_dependency_used_by_another_package() {
    let temp = TestDir::new();
    let root = temp.root();
    let dependency = write_package(
        &temp,
        "libbase",
        &[],
        "usr/lib/libbase.so",
        b"library placeholder",
    );
    let app = write_package(&temp, "demo-app", &["libbase"], "usr/bin/demo-app", b"app");

    let install_dependency = run_knpm(&root, &["install", dependency.to_str().unwrap()]);
    assert_success(&install_dependency, "install libbase");

    let install_app = run_knpm(&root, &["install", app.to_str().unwrap()]);
    assert_success(&install_app, "install package depending on libbase");

    let remove_dependency = run_knpm(&root, &["remove", "libbase"]);
    assert_failure(
        &remove_dependency,
        "remove dependency still required by demo-app",
    );
    assert!(
        String::from_utf8_lossy(&remove_dependency.stderr).contains("required by demo-app"),
        "unexpected dependency-removal error: {}",
        String::from_utf8_lossy(&remove_dependency.stderr)
    );
    assert!(
        root.join("var/lib/knpm/installed/libbase").exists(),
        "required dependency record must remain"
    );
    assert!(
        root.join("usr/lib/libbase.so").exists(),
        "required dependency files must remain"
    );
}

#[test]
fn refuses_to_remove_a_package_if_an_installed_file_was_modified() {
    let temp = TestDir::new();
    let root = temp.root();
    let archive = write_package(&temp, "demo", &[], "usr/bin/demo", b"original content");

    let install = run_knpm(&root, &["install", archive.to_str().unwrap()]);
    assert_success(&install, "install demo");

    let installed_file = root.join("usr/bin/demo");
    fs::write(&installed_file, b"modified after installation").unwrap();

    let remove = run_knpm(&root, &["remove", "demo"]);
    assert_failure(&remove, "remove package with modified payload");
    assert!(
        String::from_utf8_lossy(&remove.stderr).contains("installed file was modified"),
        "unexpected removal error: {}",
        String::from_utf8_lossy(&remove.stderr)
    );
    assert_eq!(
        fs::read(&installed_file).unwrap(),
        b"modified after installation",
        "KNPM must not delete a file it can no longer verify"
    );
    assert!(
        root.join("var/lib/knpm/installed/demo").exists(),
        "package record should remain when removal is refused"
    );
}

#[test]
fn rejects_archive_path_traversal_before_installation() {
    let temp = TestDir::new();
    let root = temp.root();
    let archive = write_traversal_archive(&temp);

    let install = run_knpm(&root, &["install", archive.to_str().unwrap()]);
    assert_failure(&install, "install archive containing a traversal member");
    assert!(
        String::from_utf8_lossy(&install.stderr).contains("unsafe path component"),
        "unexpected traversal error: {}",
        String::from_utf8_lossy(&install.stderr)
    );
    assert!(
        !root.join("var/lib/knpm").exists(),
        "invalid archive must be rejected before creating the target package database"
    );
}

#[test]
fn rejects_non_archive_package_without_modifying_target_root() {
    let temp = TestDir::new();
    let root = temp.root();
    let archive = temp.0.join("broken.khmpkg");
    fs::write(&archive, b"this is not a gzip-compressed tar archive").unwrap();

    let install = run_knpm(&root, &["install", archive.to_str().unwrap()]);
    assert_failure(&install, "install malformed package archive");
    assert!(
        !root.join("var/lib/knpm").exists(),
        "malformed archive must not create package database files"
    );
}
