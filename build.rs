use std::env;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=OMEGAJAIL_RELEASE");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/tags");
    println!("cargo:rerun-if-changed=.git/packed-refs");

    let version = env::var("OMEGAJAIL_RELEASE")
        .ok()
        .filter(|version| !version.trim().is_empty())
        .or_else(git_describe)
        .unwrap_or_else(|| env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION is set"));

    println!("cargo:rustc-env=OMEGAJAIL_VERSION={version}");
}

fn git_describe() -> Option<String> {
    let output = Command::new("git")
        .args(["describe", "--tags", "--always", "--dirty"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let version = String::from_utf8(output.stdout).ok()?;
    let version = version.trim();
    if version.is_empty() {
        None
    } else {
        Some(version.to_owned())
    }
}
