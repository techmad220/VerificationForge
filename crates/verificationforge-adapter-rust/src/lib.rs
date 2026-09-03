use std::fs;
use std::path::{Path, PathBuf};
use verificationforge_core::{
    CheckKind, CheckResult, CheckStatus, ExecutionAdapter, Finding, LanguageAdapter,
    LanguageDetection,
};

pub struct RustAdapter;

impl LanguageAdapter for RustAdapter {
    fn id(&self) -> &'static str {
        "rust"
    }

    fn detect(&self, repo: &Path) -> Option<LanguageDetection> {
        let manifest = repo.join("Cargo.toml").is_file();
        (manifest || contains_extension(repo, "rs")).then(|| LanguageDetection {
            adapter_id: self.id().into(),
            language: "Rust".into(),
            confidence_percent: if manifest { 100 } else { 80 },
        })
    }

    fn run_check(
        &self,
        check: CheckKind,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
    ) -> CheckResult {
        match check {
            CheckKind::Build => run_cargo(
                execution,
                repo,
                check,
                &["check", "--workspace", "--all-targets", "--locked"],
            ),
            CheckKind::TypeCheck => CheckResult::skipped(
                name(check),
                "cargo check performs Rust type checking and is already executed by the build gate",
            ),
            CheckKind::Lint => run_cargo(
                execution,
                repo,
                check,
                &[
                    "clippy",
                    "--workspace",
                    "--all-targets",
                    "--",
                    "-D",
                    "warnings",
                ],
            ),
            CheckKind::Test => run_cargo(
                execution,
                repo,
                check,
                &["test", "--workspace", "--all-targets", "--locked"],
            ),
            CheckKind::Dependencies => {
                run_cargo(execution, repo, check, &["tree", "--workspace", "--locked"])
            }
            CheckKind::Placeholders => scan_placeholders(repo),
            CheckKind::Security => optional_cargo_tool(execution, repo, check, "audit", &["audit"]),
            CheckKind::Coverage => optional_cargo_tool(
                execution,
                repo,
                check,
                "llvm-cov",
                &[
                    "llvm-cov",
                    "--workspace",
                    "--all-features",
                    "--summary-only",
                ],
            ),
            CheckKind::Mutation => optional_cargo_tool(
                execution,
                repo,
                check,
                "mutants",
                &["mutants", "--workspace", "--no-times"],
            ),
            CheckKind::Fuzz => run_fuzz(execution, repo),
            CheckKind::Concurrency => optional_cargo_tool(
                execution,
                repo,
                check,
                "miri",
                &["miri", "test", "--workspace"],
            ),
            CheckKind::Contracts
            | CheckKind::Stress
            | CheckKind::FaultInjection
            | CheckKind::Ui
            | CheckKind::FormalProof => CheckResult::unsupported(
                name(check),
                format!(
                    "Rust adapter has no configured {} harness for this repository",
                    check.as_str()
                ),
            ),
        }
    }
}

fn name(check: CheckKind) -> String {
    format!("rust:{}", check.as_str())
}

fn run_cargo(
    execution: &dyn ExecutionAdapter,
    repo: &Path,
    check: CheckKind,
    values: &[&str],
) -> CheckResult {
    run_command(execution, repo, check, "cargo", values)
}

fn run_command(
    execution: &dyn ExecutionAdapter,
    repo: &Path,
    check: CheckKind,
    program: &str,
    values: &[&str],
) -> CheckResult {
    let args = values
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    match execution.execute(program, &args, repo) {
        Ok(output) if output.success() => CheckResult::pass(name(check)),
        Ok(output) => CheckResult::fail(
            name(check),
            "VF_COMMAND_FAILED",
            failure_message(
                program,
                values,
                output.exit_code,
                &output.stderr,
                &output.stdout,
            ),
        ),
        Err(error) => CheckResult::fail(name(check), "VF_EXECUTION_FAILED", error),
    }
}

fn optional_cargo_tool(
    execution: &dyn ExecutionAdapter,
    repo: &Path,
    check: CheckKind,
    subcommand: &str,
    run_args: &[&str],
) -> CheckResult {
    let version_args = vec![subcommand.to_owned(), "--version".to_owned()];
    let available = execution
        .execute("cargo", &version_args, repo)
        .map(|output| output.success())
        .unwrap_or(false);
    if !available {
        return CheckResult::unsupported(
            name(check),
            format!("cargo {subcommand} is not installed or not available"),
        );
    }
    run_cargo(execution, repo, check, run_args)
}

fn run_fuzz(execution: &dyn ExecutionAdapter, repo: &Path) -> CheckResult {
    let list_args = vec!["fuzz".to_owned(), "list".to_owned()];
    let Ok(list) = execution.execute("cargo", &list_args, repo) else {
        return CheckResult::unsupported(name(CheckKind::Fuzz), "cargo-fuzz is not available");
    };
    if !list.success() {
        return CheckResult::unsupported(name(CheckKind::Fuzz), "cargo-fuzz is not available");
    }

    let targets = list
        .stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if targets.is_empty() {
        return CheckResult::unsupported(
            name(CheckKind::Fuzz),
            "cargo-fuzz is installed but this repository has no fuzz targets",
        );
    }

    for target in targets {
        let args = vec![
            "fuzz".to_owned(),
            "run".to_owned(),
            target.clone(),
            "--".to_owned(),
            "-max_total_time=15".to_owned(),
        ];
        match execution.execute("cargo", &args, repo) {
            Ok(output) if output.success() => {}
            Ok(output) => {
                return CheckResult::fail(
                    name(CheckKind::Fuzz),
                    "VF_FUZZ_FAILED",
                    failure_message(
                        "cargo",
                        &["fuzz", "run", &target],
                        output.exit_code,
                        &output.stderr,
                        &output.stdout,
                    ),
                );
            }
            Err(error) => {
                return CheckResult::fail(name(CheckKind::Fuzz), "VF_EXECUTION_FAILED", error);
            }
        }
    }

    CheckResult::pass(name(CheckKind::Fuzz))
}

fn scan_placeholders(repo: &Path) -> CheckResult {
    let patterns = [
        ["to", "do!("].concat(),
        ["unimplemented", "!("].concat(),
        ["TO", "DO:"].concat(),
        ["FIX", "ME:"].concat(),
        ["X", "XX:"].concat(),
    ];
    let mut findings = Vec::new();

    for path in source_files(repo, "rs") {
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        for (index, line) in content.lines().enumerate() {
            if let Some(pattern) = patterns
                .iter()
                .find(|pattern| line.contains(pattern.as_str()))
            {
                findings.push(Finding {
                    code: "VF_PLACEHOLDER".into(),
                    message: format!(
                        "{}:{} contains placeholder marker {}",
                        display_relative(repo, &path),
                        index + 1,
                        pattern
                    ),
                    blocking: true,
                });
            }
        }
    }

    if findings.is_empty() {
        CheckResult::pass(name(CheckKind::Placeholders))
    } else {
        CheckResult {
            check: name(CheckKind::Placeholders),
            status: CheckStatus::Fail,
            findings,
        }
    }
}

fn failure_message(
    program: &str,
    args: &[&str],
    exit_code: i32,
    stderr: &str,
    stdout: &str,
) -> String {
    let detail = if stderr.trim().is_empty() {
        stdout
    } else {
        stderr
    };
    let detail = detail.trim();
    let detail = detail.chars().take(4000).collect::<String>();
    format!(
        "{} {} exited with code {}{}{}",
        program,
        args.join(" "),
        exit_code,
        if detail.is_empty() { "" } else { ": " },
        detail
    )
}

fn contains_extension(repo: &Path, extension: &str) -> bool {
    !source_files(repo, extension).is_empty()
}

fn source_files(repo: &Path, extension: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();
    visit(repo, extension, 0, &mut files);
    files
}

fn visit(path: &Path, extension: &str, depth: usize, files: &mut Vec<PathBuf>) {
    if depth > 32 {
        return;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let child = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if matches!(name.as_ref(), ".git" | "target" | "vendor" | "node_modules") {
                continue;
            }
            visit(&child, extension, depth + 1, files);
        } else if file_type.is_file()
            && child.extension().and_then(|value| value.to_str()) == Some(extension)
        {
            files.push(child);
        }
    }
}

fn display_relative(repo: &Path, path: &Path) -> String {
    path.strip_prefix(repo)
        .unwrap_or(path)
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("verificationforge-rust-{nonce}"))
    }

    #[test]
    fn detects_nested_rust_source() {
        let root = temp_dir();
        fs::create_dir_all(root.join("src/nested")).expect("create dirs");
        fs::write(root.join("src/nested/lib.rs"), "pub fn value() -> u8 { 1 }")
            .expect("write source");
        assert!(RustAdapter.detect(&root).is_some());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn placeholder_scan_blocks_real_placeholder_macro() {
        let root = temp_dir();
        fs::create_dir_all(root.join("src")).expect("create dirs");
        let marker = ["to", "do!();"].concat();
        fs::write(
            root.join("src/lib.rs"),
            format!("pub fn value() {{ {marker} }}"),
        )
        .expect("write source");
        let result = scan_placeholders(&root);
        assert_eq!(result.status, CheckStatus::Fail);
        fs::remove_dir_all(root).ok();
    }
}
