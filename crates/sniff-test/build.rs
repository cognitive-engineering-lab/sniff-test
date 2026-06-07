use std::path::Path;
use std::time::UNIX_EPOCH;
use std::{env, ffi::OsString, fs, process::Command};

fn main() {
    println!("cargo::rerun-if-env-changed=RUSTC");
    emit_source_stamp("SNIFF_TEST_SOURCE_STAMP", &["build.rs", "src"]);

    let rustc = env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    let output = Command::new(&rustc)
        .args(["--print", "target-libdir"])
        .output()
        .expect("failed to run rustc --print target-libdir");

    assert!(
        output.status.success(),
        "rustc --print target-libdir failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let libdir = String::from_utf8(output.stdout).expect("target libdir was not valid utf-8");
    println!("cargo::rustc-link-arg=-Wl,-rpath,{}", libdir.trim());
}

fn emit_source_stamp(name: &str, paths: &[&str]) {
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR")
        .map(std::path::PathBuf::from)
        .expect("CARGO_MANIFEST_DIR should be set by Cargo");
    let mut stamp = 0;

    for path in paths {
        let path = manifest_dir.join(path);
        println!("cargo::rerun-if-changed={}", path.display());
        stamp = stamp.max(max_modified_secs(&path));
    }

    println!("cargo::rustc-env={name}={stamp}");
}

fn max_modified_secs(path: &Path) -> u64 {
    let Ok(metadata) = fs::metadata(path) else {
        return 0;
    };

    if metadata.is_dir() {
        let Ok(entries) = fs::read_dir(path) else {
            return 0;
        };
        entries
            .filter_map(Result::ok)
            .map(|entry| max_modified_secs(&entry.path()))
            .max()
            .unwrap_or(0)
    } else {
        metadata
            .modified()
            .ok()
            .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |duration| duration.as_secs())
    }
}
