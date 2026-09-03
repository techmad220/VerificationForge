use std::fs;
use std::path::{Path, PathBuf};

use verificationforge_core::{
    CheckKind, CheckResult, CheckStatus, ExecutionAdapter, Finding, LanguageAdapter,
    LanguageDetection, run_repository_harness,
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
            CheckKind::Concurrency => run_concurrency(execution, repo),
            CheckKind::Contracts => required_repository_harness(execution, repo, check),
            CheckKind::Stress => required_repository_harness(execution, repo, check),
            CheckKind::FaultInjection => required_repository_harness(execution, repo, check),
            CheckKind::Ui => {
                if has_ui_assets(repo) {
                    required_repository_harness(execution, repo, check)
                } else {
                    CheckResult::skipped(
                        name(check),
                        "no UI assets or common Rust web/UI framework markers were detected",
                    )
                }
            }
            CheckKind::FormalProof => required_repository_harness(execution, repo, check),
        }
    }
}

fn name(check: CheckKind) -> String {
    format!("rust:{}", check.as_str())
}

fn repository_harness(
    execution: &dyn ExecutionAdapter,
    repo: &Path,
    check: CheckKind,
) -> Option<CheckResult> {
    run_repository_harness(repo, execution, name(check), check.as_str())
}

fn required_repository_harness(
    execution: &dyn ExecutionAdapter,
    repo: &Path,
    check: CheckKind,
) -> CheckResult {
    repository_harness(execution, repo, check).unwrap_or_else(|| {
        CheckResult::unsupported(
            name(check),
            format!(
                "required repository harness is missing: .verificationforge/{}.argv",
                check.as_str()
            ),
        )
    })
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
        Ok(output) if output.success() => CheckResult::pass_with_evidence(
            name(check),
            format!("command={} {} exit=0", program, values.join(" ")),
        ),
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
    if available {
        return run_cargo(execution, repo, check, run_args);
    }
    repository_harness(execution, repo, check).unwrap_or_else(|| {
        CheckResult::unsupported(
            name(check),
            format!(
                "cargo {subcommand} is unavailable and .verificationforge/{}.argv is missing",
                check.as_str()
            ),
        )
    })
}

fn run_fuzz(execution: &dyn ExecutionAdapter, repo: &Path) -> CheckResult {
    let list_args = vec!["fuzz".to_owned(), "list".to_owned()];
    let Ok(list) = execution.execute("cargo", &list_args, repo) else {
        return fallback_fuzz_harness(execution, repo);
    };
    if !list.success() {
        return fallback_fuzz_harness(execution, repo);
    }

    let targets = list
        .stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if targets.is_empty() {
        return fallback_fuzz_harness(execution, repo);
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

    CheckResult::pass_with_evidence(
        name(CheckKind::Fuzz),
        "cargo fuzz completed all discovered targets with max_total_time=15",
    )
}

fn fallback_fuzz_harness(execution: &dyn ExecutionAdapter, repo: &Path) -> CheckResult {
    repository_harness(execution, repo, CheckKind::Fuzz).unwrap_or_else(|| {
        CheckResult::unsupported(
            name(CheckKind::Fuzz),
            "cargo-fuzz is unavailable or has no targets and .verificationforge/fuzz.argv is missing",
        )
    })
}

fn run_concurrency(execution: &dyn ExecutionAdapter, repo: &Path) -> CheckResult {
    if !has_concurrency_markers(repo) {
        return CheckResult::skipped(
            name(CheckKind::Concurrency),
            "no Rust concurrency or async markers were detected",
        );
    }

    let version_args = vec!["miri".to_owned(), "--version".to_owned()];
    let miri_available = execution
        .execute("cargo", &version_args, repo)
        .map(|output| output.success())
        .unwrap_or(false);
    if miri_available {
        return run_cargo(
            execution,
            repo,
            CheckKind::Concurrency,
            &["miri", "test", "--workspace"],
        );
    }

    repository_harness(execution, repo, CheckKind::Concurrency).unwrap_or_else(|| {
        CheckResult::unsupported(
            name(CheckKind::Concurrency),
            "concurrency markers detected but neither cargo miri nor .verificationforge/concurrency.argv is available",
        )
    })
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
    let files = source_files(repo, "rs");

    for path in &files {
        let Ok(content) = fs::read_to_string(path) else {
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
                        display_relative(repo, path),
                        index + 1,
                        pattern
                    ),
                    blocking: true,
                });
            }
        }
        findings.extend(scan_semantic_fakes(repo, path, &content));
    }

    if findings.is_empty() {
        CheckResult::pass_with_evidence(
            name(CheckKind::Placeholders),
            format!(
                "scanned {} Rust source files for placeholder and fake-success patterns",
                files.len()
            ),
        )
    } else {
        CheckResult {
            check: name(CheckKind::Placeholders),
            status: CheckStatus::Fail,
            findings,
        }
    }
}

fn scan_semantic_fakes(repo: &Path, path: &Path, content: &str) -> Vec<Finding> {
    let lines = content.lines().collect::<Vec<_>>();
    let mut findings = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let Some(function_name) = rust_function_name(trimmed) else {
            continue;
        };
        let public = trimmed.starts_with("pub ") || trimmed.starts_with("pub(");
        let sensitive = sensitive_gate_name(function_name);
        if !(public || sensitive) {
            continue;
        }

        if let Some(body) = inline_rust_body(trimmed) {
            if body.is_empty() && public {
                findings.push(fake_finding(
                    repo,
                    path,
                    index,
                    function_name,
                    "public function has an empty implementation",
                ));
            } else if sensitive && constant_bool_body(body) {
                findings.push(fake_finding(
                    repo,
                    path,
                    index,
                    function_name,
                    "authorization/permission function returns a constant boolean",
                ));
            }
            continue;
        }

        if trimmed.contains('{') {
            let next = lines
                .iter()
                .enumerate()
                .skip(index + 1)
                .find(|(_, candidate)| {
                    let candidate = candidate.trim();
                    !candidate.is_empty() && !candidate.starts_with("//")
                });
            if let Some((body_index, body_line)) = next {
                let body_line = body_line.trim();
                if body_line == "}" && public {
                    findings.push(fake_finding(
                        repo,
                        path,
                        body_index,
                        function_name,
                        "public function has an empty implementation",
                    ));
                } else if sensitive && constant_bool_body(body_line) {
                    findings.push(fake_finding(
                        repo,
                        path,
                        body_index,
                        function_name,
                        "authorization/permission function returns a constant boolean",
                    ));
                }
            }
        }
    }
    findings
}

fn rust_function_name(line: &str) -> Option<&str> {
    let marker = line.find("fn ")?;
    let prefix = &line[..marker];
    if prefix.contains('"') || prefix.contains("//") || prefix.contains("/*") {
        return None;
    }
    let rest = &line[marker + 3..];
    let end = rest
        .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .unwrap_or(rest.len());
    (end > 0).then_some(&rest[..end])
}

fn inline_rust_body(line: &str) -> Option<&str> {
    let open = line.find('{')?;
    let close = line.rfind('}')?;
    (close > open).then_some(line[open + 1..close].trim())
}

fn sensitive_gate_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "authoriz",
        "authenticate",
        "permission",
        "has_access",
        "can_access",
        "is_admin",
        "allow_access",
    ]
    .iter()
    .any(|marker| name.contains(marker))
}

fn constant_bool_body(body: &str) -> bool {
    let normalized = body
        .chars()
        .filter(|character| !character.is_whitespace() && *character != ';')
        .collect::<String>()
        .to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "true" | "false" | "returntrue" | "returnfalse"
    )
}

fn fake_finding(
    repo: &Path,
    path: &Path,
    index: usize,
    function_name: &str,
    reason: &str,
) -> Finding {
    Finding {
        code: "VF_FAKE_IMPLEMENTATION".into(),
        message: format!(
            "{}:{} function {}: {}",
            display_relative(repo, path),
            index + 1,
            function_name,
            reason
        ),
        blocking: true,
    }
}

fn has_concurrency_markers(repo: &Path) -> bool {
    source_files(repo, "rs").iter().any(|path| {
        fs::read_to_string(path).is_ok_and(|content| {
            [
                "std::thread",
                "tokio::",
                "async_std::",
                "Mutex<",
                "RwLock<",
                "Atomic",
                "async fn ",
                ".await",
                "spawn(",
            ]
            .iter()
            .any(|marker| content.contains(marker))
        })
    })
}

fn has_ui_assets(repo: &Path) -> bool {
    ["html", "css", "js", "ts", "tsx", "jsx"]
        .iter()
        .any(|extension| contains_extension(repo, extension))
        || ["templates", "static", "frontend", "web", "ui"]
            .iter()
            .any(|directory| repo.join(directory).is_dir())
        || source_files(repo, "rs").iter().any(|path| {
            fs::read_to_string(path).is_ok_and(|content| {
                [
                    "yew::", "leptos::", "dioxus::", "egui::", "iced::", "tauri::",
                ]
                .iter()
                .any(|marker| content.contains(marker))
            })
        })
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

    #[test]
    fn placeholder_scan_blocks_constant_authorization() {
        let root = temp_dir();
        fs::create_dir_all(root.join("src")).expect("create dirs");
        fs::write(
            root.join("src/lib.rs"),
            "pub fn authorize_user() -> bool { true }\n",
        )
        .expect("write source");
        let result = scan_placeholders(&root);
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.code == "VF_FAKE_IMPLEMENTATION")
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn semantic_scanner_ignores_embedded_source_text() {
        assert_eq!(
            rust_function_name("let fixture = \"pub fn authorize_user() -> bool { true }\";"),
            None
        );
        assert_eq!(
            rust_function_name("// pub fn authorize_user() -> bool { true }"),
            None
        );
    }

    #[test]
    fn clean_placeholder_scan_carries_evidence() {
        let root = temp_dir();
        fs::create_dir_all(root.join("src")).expect("create dirs");
        fs::write(root.join("src/lib.rs"), "pub fn value() -> u8 { 1 }").expect("write source");
        let result = scan_placeholders(&root);
        assert_eq!(result.status, CheckStatus::Pass);
        assert!(result.has_reproducible_evidence());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn ui_check_is_not_applicable_for_plain_library() {
        let root = temp_dir();
        fs::create_dir_all(root.join("src")).expect("create dirs");
        fs::write(root.join("src/lib.rs"), "pub fn value() -> u8 { 1 }").expect("write source");
        assert!(!has_ui_assets(&root));
        fs::remove_dir_all(root).ok();
    }
}
