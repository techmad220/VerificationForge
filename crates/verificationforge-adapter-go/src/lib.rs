use std::fs;
use std::path::{Path, PathBuf};

use verificationforge_core::{
    CheckKind, CheckResult, CheckStatus, ExecutionAdapter, Finding, LanguageAdapter,
    LanguageDetection, SymbolId, run_repository_harness,
};

const MAX_SCAN_BYTES: u64 = 2 * 1024 * 1024;

pub struct GoAdapter;

impl LanguageAdapter for GoAdapter {
    fn id(&self) -> &'static str {
        "go"
    }

    fn detect(&self, repo: &Path) -> Option<LanguageDetection> {
        let files = repository_files(repo);
        let manifest = files.iter().any(|path| {
            path.file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|name| matches!(name, "go.mod" | "go.work"))
        });
        let source = files.iter().any(|path| is_go_source(path));
        (manifest || source).then(|| LanguageDetection {
            adapter_id: self.id().into(),
            language: "Go".into(),
            confidence_percent: if manifest { 100 } else { 85 },
        })
    }

    fn inventory_symbols(&self, repo: &Path) -> Result<Vec<SymbolId>, String> {
        let mut symbols = Vec::new();
        for path in repository_files(repo)
            .into_iter()
            .filter(|path| is_go_source(path))
        {
            let relative = display_relative(repo, &path);
            symbols.push(SymbolId(format!("go:file:{relative}")));
            let Ok(content) = fs::read_to_string(&path) else {
                continue;
            };
            for line in content.lines() {
                let trimmed = line.trim();
                if let Some(package) = trimmed.strip_prefix("package ") {
                    let package = identifier(package);
                    if !package.is_empty() {
                        symbols.push(SymbolId(format!("go:package:{package}")));
                    }
                }
                if let Some(name) = go_function_name(trimmed) {
                    symbols.push(SymbolId(format!("go:function:{relative}:{name}")));
                }
                for (keyword, kind) in [("type ", "type"), ("var ", "var"), ("const ", "const")] {
                    if let Some(rest) = trimmed.strip_prefix(keyword) {
                        let name = identifier(rest);
                        if !name.is_empty() && name != "(" {
                            symbols.push(SymbolId(format!("go:{kind}:{relative}:{name}")));
                        }
                    }
                }
            }
        }
        symbols.sort();
        symbols.dedup();
        Ok(symbols)
    }

    fn run_check(
        &self,
        check: CheckKind,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
    ) -> CheckResult {
        match check {
            CheckKind::Build => run_go(execution, repo, check, &["build", "./..."]),
            CheckKind::TypeCheck => {
                run_go(execution, repo, check, &["test", "-run", "^$", "./..."])
            }
            CheckKind::Lint => run_go(execution, repo, check, &["vet", "./..."]),
            CheckKind::Test => {
                if has_test_files(repo) {
                    run_go(execution, repo, check, &["test", "./..."])
                } else {
                    optional_repository_harness(
                        execution,
                        repo,
                        check,
                        "no Go *_test.go files were found",
                    )
                }
            }
            CheckKind::Coverage => {
                if has_test_files(repo) {
                    run_go(execution, repo, check, &["test", "-cover", "./..."])
                } else {
                    optional_repository_harness(
                        execution,
                        repo,
                        check,
                        "coverage requires Go *_test.go files",
                    )
                }
            }
            CheckKind::Dependencies => run_go(execution, repo, check, &["list", "-deps", "./..."]),
            CheckKind::Placeholders => scan_placeholders(repo),
            CheckKind::Security => {
                if executable_available(execution, repo, "govulncheck") {
                    run_command(execution, repo, check, "govulncheck", &["./..."])
                } else {
                    optional_repository_harness(
                        execution,
                        repo,
                        check,
                        "govulncheck is not available",
                    )
                }
            }
            CheckKind::Concurrency => {
                if has_concurrency_markers(repo) {
                    run_go(execution, repo, check, &["test", "-race", "./..."])
                } else {
                    CheckResult::skipped(
                        name(check),
                        "no Go goroutine/channel/synchronization markers were detected",
                    )
                }
            }
            CheckKind::Mutation
            | CheckKind::Fuzz
            | CheckKind::Contracts
            | CheckKind::Stress
            | CheckKind::FaultInjection
            | CheckKind::FormalProof => required_repository_harness(execution, repo, check),
            CheckKind::Ui => {
                if has_ui_assets(repo) {
                    required_repository_harness(execution, repo, check)
                } else {
                    CheckResult::skipped(
                        name(check),
                        "no UI assets or common Go web template markers were detected",
                    )
                }
            }
        }
    }
}

fn name(check: CheckKind) -> String {
    format!("go:{}", check.as_str())
}

fn repository_harness(
    execution: &dyn ExecutionAdapter,
    repo: &Path,
    check: CheckKind,
) -> Option<CheckResult> {
    let harness = format!("go-{}", check.as_str());
    run_repository_harness(repo, execution, name(check), &harness)
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
                "required Go verification harness is missing: .verificationforge/go-{}.argv",
                check.as_str()
            ),
        )
    })
}

fn optional_repository_harness(
    execution: &dyn ExecutionAdapter,
    repo: &Path,
    check: CheckKind,
    native_message: &str,
) -> CheckResult {
    repository_harness(execution, repo, check).unwrap_or_else(|| {
        CheckResult::unsupported(
            name(check),
            format!(
                "{native_message} and .verificationforge/go-{}.argv is missing",
                check.as_str()
            ),
        )
    })
}

fn run_go(
    execution: &dyn ExecutionAdapter,
    repo: &Path,
    check: CheckKind,
    args: &[&str],
) -> CheckResult {
    run_command(execution, repo, check, "go", args)
}

fn run_command(
    execution: &dyn ExecutionAdapter,
    repo: &Path,
    check: CheckKind,
    program: &str,
    args: &[&str],
) -> CheckResult {
    let owned = args
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    match execution.execute(program, &owned, repo) {
        Ok(output) if output.success() => CheckResult::pass_with_evidence(
            name(check),
            format!("command={program} {} exit=0", args.join(" ")),
        ),
        Ok(output) => CheckResult::fail(
            name(check),
            "VF_COMMAND_FAILED",
            format!(
                "command={program} {} exit={} stderr={} stdout={}",
                args.join(" "),
                output.exit_code,
                sanitize_output(&output.stderr),
                sanitize_output(&output.stdout)
            ),
        ),
        Err(error) => CheckResult::fail(
            name(check),
            if program == "go" {
                "VF_GO_EXECUTION_FAILED"
            } else {
                "VF_EXECUTION_FAILED"
            },
            error,
        ),
    }
}

fn executable_available(execution: &dyn ExecutionAdapter, repo: &Path, program: &str) -> bool {
    execution
        .execute(program, &["-version".to_owned()], repo)
        .or_else(|_| execution.execute(program, &["--version".to_owned()], repo))
        .map(|result| result.success())
        .unwrap_or(false)
}

fn scan_placeholders(repo: &Path) -> CheckResult {
    let files = repository_files(repo)
        .into_iter()
        .filter(|path| is_go_source(path))
        .collect::<Vec<_>>();
    let mut findings = Vec::new();
    let explicit = [
        (["TO", "DO:"].concat(), "TODO"),
        (["FIX", "ME:"].concat(), "FIXME"),
        (["X", "XX:"].concat(), "XXX"),
    ];

    for path in &files {
        let Ok(metadata) = fs::metadata(path) else {
            continue;
        };
        if metadata.len() > MAX_SCAN_BYTES {
            continue;
        }
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        for (index, line) in content.lines().enumerate() {
            if let Some((_, label)) = explicit.iter().find(|(marker, _)| line.contains(marker)) {
                findings.push(Finding {
                    code: "VF_PLACEHOLDER".into(),
                    message: format!(
                        "{}:{} contains placeholder marker {label}",
                        display_relative(repo, path),
                        index + 1
                    ),
                    blocking: true,
                });
            }
            let lower = line.to_ascii_lowercase();
            if lower.contains("panic(")
                && (lower.contains("not implemented") || lower.contains("placeholder"))
            {
                findings.push(Finding {
                    code: "VF_PLACEHOLDER".into(),
                    message: format!(
                        "{}:{} contains a placeholder panic",
                        display_relative(repo, path),
                        index + 1
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
                "scanned {} Go source files for placeholder and fake-success patterns",
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
        let Some(function_name) = go_function_name(trimmed) else {
            continue;
        };
        let exported = function_name
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_uppercase());
        let sensitive = sensitive_gate_name(function_name);
        if !(exported || sensitive) {
            continue;
        }

        if let Some(body) = inline_go_body(trimmed) {
            if body.is_empty() && exported {
                findings.push(fake_finding(
                    repo,
                    path,
                    index,
                    function_name,
                    "exported function has an empty implementation",
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
                if body_line == "}" && exported {
                    findings.push(fake_finding(
                        repo,
                        path,
                        body_index,
                        function_name,
                        "exported function has an empty implementation",
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

fn go_function_name(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("func ")?.trim_start();
    let rest = if rest.starts_with('(') {
        let close = rest.find(')')?;
        rest[close + 1..].trim_start()
    } else {
        rest
    };
    let end = rest
        .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .unwrap_or(rest.len());
    (end > 0).then_some(&rest[..end])
}

fn inline_go_body(line: &str) -> Option<&str> {
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
        "hasaccess",
        "canaccess",
        "isadmin",
        "allowaccess",
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

fn has_test_files(repo: &Path) -> bool {
    repository_files(repo).iter().any(|path| {
        path.file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|name| name.ends_with("_test.go"))
    })
}

fn has_concurrency_markers(repo: &Path) -> bool {
    repository_files(repo)
        .into_iter()
        .filter(|path| is_go_source(path))
        .any(|path| {
            fs::read_to_string(path).is_ok_and(|content| {
                [
                    "go func",
                    "go ",
                    "chan ",
                    "<-chan",
                    "chan<-",
                    "sync.Mutex",
                    "sync.RWMutex",
                    "sync.WaitGroup",
                    "sync/atomic",
                ]
                .iter()
                .any(|marker| content.contains(marker))
            })
        })
}

fn has_ui_assets(repo: &Path) -> bool {
    repository_files(repo).iter().any(|path| {
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        matches!(
            extension.as_str(),
            "html" | "htm" | "css" | "js" | "ts" | "tsx" | "jsx" | "tmpl"
        )
    })
}

fn identifier(value: &str) -> &str {
    let value = value.trim_start();
    let end = value
        .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .unwrap_or(value.len());
    &value[..end]
}

fn is_go_source(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("go"))
}

fn repository_files(repo: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    visit(repo, 0, &mut files);
    files
}

fn visit(path: &Path, depth: usize, files: &mut Vec<PathBuf>) {
    if depth > 48 {
        return;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let child = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if matches!(
                name.as_ref(),
                ".git" | "vendor" | "target" | "node_modules" | ".verificationforge"
            ) {
                continue;
            }
            visit(&child, depth + 1, files);
        } else if kind.is_file() {
            files.push(child);
        }
    }
}

fn display_relative(repo: &Path, path: &Path) -> String {
    path.strip_prefix(repo)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn sanitize_output(value: &str) -> String {
    value
        .chars()
        .take(1000)
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};
    use verificationforge_core::ExecutionResult;

    #[derive(Default)]
    struct RecordingExecution {
        calls: Mutex<Vec<(String, Vec<String>)>>,
    }

    impl ExecutionAdapter for RecordingExecution {
        fn id(&self) -> &'static str {
            "recording"
        }

        fn execute(
            &self,
            program: &str,
            args: &[String],
            _cwd: &Path,
        ) -> Result<ExecutionResult, String> {
            self.calls
                .lock()
                .expect("calls lock poisoned")
                .push((program.into(), args.to_vec()));
            Ok(ExecutionResult {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("verificationforge-go-{name}-{nonce}"))
    }

    fn fixture(name: &str, source: &str) -> PathBuf {
        let root = temp_dir(name);
        fs::create_dir_all(&root).expect("create root");
        fs::write(
            root.join("go.mod"),
            "module verificationforge.example/test\n\ngo 1.22\n",
        )
        .expect("write module");
        fs::write(root.join("main.go"), source).expect("write source");
        root
    }

    #[test]
    fn detects_module_and_inventories_go_symbols() {
        let root = fixture(
            "detect",
            "package service\ntype Server struct{}\nfunc NewServer() *Server { return &Server{} }\nfunc (s *Server) Serve() {}\n",
        );
        let detection = GoAdapter.detect(&root).expect("Go detected");
        assert_eq!(detection.adapter_id, "go");
        assert_eq!(detection.confidence_percent, 100);
        let symbols = GoAdapter.inventory_symbols(&root).expect("inventory");
        assert!(symbols.contains(&SymbolId("go:package:service".into())));
        assert!(symbols.iter().any(|symbol| symbol.0.contains(":NewServer")));
        assert!(symbols.iter().any(|symbol| symbol.0.contains(":Serve")));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn native_patch_checks_preserve_go_argv_and_emit_evidence() {
        let root = fixture("commands", "package main\nfunc main() {}\n");
        fs::write(
            root.join("main_test.go"),
            "package main\nimport \"testing\"\nfunc TestMainPackage(t *testing.T) {}\n",
        )
        .expect("write tests");
        let execution = RecordingExecution::default();
        for check in [
            CheckKind::Build,
            CheckKind::TypeCheck,
            CheckKind::Lint,
            CheckKind::Test,
            CheckKind::Dependencies,
        ] {
            let result = GoAdapter.run_check(check, &root, &execution);
            assert_eq!(result.status, CheckStatus::Pass);
            assert!(result.has_reproducible_evidence());
        }
        let calls = execution.calls.lock().expect("calls lock poisoned");
        assert_eq!(
            calls[0],
            ("go".into(), vec!["build".into(), "./...".into()])
        );
        assert_eq!(
            calls[1],
            (
                "go".into(),
                vec!["test".into(), "-run".into(), "^$".into(), "./...".into()]
            )
        );
        assert_eq!(calls[2], ("go".into(), vec!["vet".into(), "./...".into()]));
        assert_eq!(calls[3], ("go".into(), vec!["test".into(), "./...".into()]));
        assert_eq!(
            calls[4],
            (
                "go".into(),
                vec!["list".into(), "-deps".into(), "./...".into()]
            )
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn test_check_does_not_fake_success_without_tests() {
        let root = fixture("no-tests", "package main\nfunc main() {}\n");
        let result = GoAdapter.run_check(CheckKind::Test, &root, &RecordingExecution::default());
        assert_eq!(result.status, CheckStatus::Unsupported);
        assert!(!result.has_reproducible_evidence());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn placeholder_and_constant_authorization_are_blocking() {
        let marker = ["FIX", "ME:"].concat();
        let source = format!(
            "package auth\n// {marker} replace temporary rule\nfunc Authorize() bool {{ return true }}\n"
        );
        let root = fixture("fake-auth", &source);
        let result = GoAdapter.run_check(
            CheckKind::Placeholders,
            &root,
            &RecordingExecution::default(),
        );
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.has_blocking_finding());
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.code == "VF_FAKE_IMPLEMENTATION")
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn advanced_checks_fail_closed_without_go_specific_harness() {
        let root = fixture("advanced", "package main\nfunc main() {}\n");
        let result =
            GoAdapter.run_check(CheckKind::Mutation, &root, &RecordingExecution::default());
        assert_eq!(result.status, CheckStatus::Unsupported);
        assert!(!result.has_reproducible_evidence());
        fs::remove_dir_all(root).ok();
    }
}
