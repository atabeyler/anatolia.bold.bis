use std::env;
use std::process::Command;

// Embeds the current commit SHA into the binary at compile time so
// GET /api/health can report exactly which build is live. Prefers an
// explicit GIT_COMMIT_SHA build-time env var (set via Docker ARG/ENV,
// since a container build context may not include .git), and falls back
// to reading the checkout directly (Render's native build, local dev).
fn main() {
    let commit_sha = env::var("GIT_COMMIT_SHA").ok().or_else(|| {
        Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|sha| sha.trim().to_string())
    });

    println!(
        "cargo:rustc-env=GIT_COMMIT_SHA={}",
        commit_sha.unwrap_or_else(|| "unknown".to_string())
    );
    println!("cargo:rerun-if-env-changed=GIT_COMMIT_SHA");
    println!("cargo:rerun-if-changed=../.git/HEAD");
}
