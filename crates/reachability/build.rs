use std::{env, ffi::OsString, process::Command};

fn main() {
    println!("cargo::rerun-if-env-changed=RUSTC");

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
