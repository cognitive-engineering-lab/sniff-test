use std::{env, fs, io, path::Path, process::Command};

fn main() {
    build_frontend().unwrap_or_else(|error| panic!("failed to build audit GUI frontend: {error}"));
}

fn build_frontend() -> io::Result<()> {
    let source = Path::new("frontend");
    let output = env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR");
    let frontend = Path::new(&output).join("frontend");
    fs::create_dir_all(&frontend)?;

    let manifests = ["package.json", "package-lock.json"];
    let install = !frontend.join("node_modules/.package-lock.json").is_file()
        || manifests.iter().any(|name| {
            fs::read(source.join(name)).ok()
                != fs::read(frontend.join(format!(".installed-{name}"))).ok()
        });

    for name in [
        "package.json",
        "package-lock.json",
        "index.html",
        "tsconfig.json",
        "src",
    ] {
        println!("cargo:rerun-if-changed=frontend/{name}");
        let destination = frontend.join(name);
        // Remove old inputs so deleted source files cannot survive in OUT_DIR.
        if destination.is_dir() {
            fs::remove_dir_all(&destination)?;
        } else if destination.exists() {
            fs::remove_file(&destination)?;
        }
        copy(&source.join(name), &destination)?;
    }
    println!("cargo:rerun-if-env-changed=PATH");

    if install {
        npm(
            &frontend,
            &["ci", "--include=dev", "--no-audit", "--no-fund"],
        )?;
        for name in manifests {
            fs::copy(
                source.join(name),
                frontend.join(format!(".installed-{name}")),
            )?;
        }
    }
    npm(&frontend, &["run", "build"])?;
    println!(
        "cargo:rustc-env=SNIFF_TEST_AUDIT_ASSETS={}",
        frontend.join("dist").display()
    );
    Ok(())
}

fn copy(source: &Path, destination: &Path) -> io::Result<()> {
    if source.is_dir() {
        fs::create_dir_all(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            copy(&entry.path(), &destination.join(entry.file_name()))?;
        }
    } else {
        fs::copy(source, destination)?;
    }
    Ok(())
}

fn npm(directory: &Path, arguments: &[&str]) -> io::Result<()> {
    let mut command = if cfg!(windows) {
        let mut command = Command::new("cmd");
        command.args(["/C", "npm"]);
        command
    } else {
        Command::new("npm")
    };
    let status = command.args(arguments).current_dir(directory).status().map_err(|error| {
        io::Error::new(error.kind(), format!("could not run npm: {error}. Install Node.js 22 or newer and ensure node and npm are on PATH."))
    })?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "npm {} failed ({status}); see its output above",
            arguments.join(" ")
        )));
    }
    Ok(())
}
