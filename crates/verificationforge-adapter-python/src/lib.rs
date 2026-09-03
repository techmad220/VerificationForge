use std::fs;
use std::path::{Path, PathBuf};
use verificationforge_core::{
    CheckKind, CheckResult, CheckStatus, ExecutionAdapter, Finding, LanguageAdapter,
    LanguageDetection,
};

pub struct PythonAdapter;

impl LanguageAdapter for PythonAdapter {
    fn id(&self) -> &'static str {
        "python"
    }

    fn detect(&self, repo: &Path) -> Option<LanguageDetection> {
        let manifest = ["pyproject.toml", "setup.py", "requirements.txt"]
            .iter()
            .any(|name| repo.join(name).is_file());
        (manifest || contains_extension(repo, "py")).then(|| LanguageDetection {
            adapter_id: self.id().into(),
            language: "Python".into(),
            confidence_percent: if manifest { 100 } else { 80 },
        })
    }

    fn run_check(
        &self,
        check: CheckKind,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
    ) -> CheckResult {
        let Some(python) = python_program(execution, repo) else {
            return CheckResult::fail(
                name(check),
                "VF_PYTHON_MISSING",
                "Python repository detected but neither python3 nor python is executable",
            );
        };

        match check {
            CheckKind::Build => run_python(
                execution,
                repo,
                check,
                &python,
                &["-m", "compileall", "-q", "."],
            ),
            CheckKind::TypeCheck => {
                if module_available(execution, repo, &python, "mypy") {
                    run_python(execution, repo, check, &python, &["-m", "mypy", "."])
                } else if executable_available(execution, repo, "pyright") {
                    run_command(execution, repo, check, "pyright", &["."])
                } else {
                    CheckResult::unsupported(
                        name(check),
                        "neither mypy nor pyright is available",
                    )
                }
            }
            CheckKind::Lint => {
                if module_available(execution, repo, &python, "ruff") {
                    run_python(
                        execution,
                        repo,
                        check,
                        &python,
                        &["-m", "ruff", "check", "."],
                    )
                } else if executable_available(execution, repo, "ruff") {
                    run_command(execution, repo, check, "ruff", &["check", "."])
                } else {
                    CheckResult::unsupported(name(check), "ruff is not available")
                }
            }
            CheckKind::Test => run_tests(execution, repo, &python),
            CheckKind::Coverage => run_coverage(execution, repo, &python),
            CheckKind::Mutation => {
                if module_available(execution, repo, &python, "mutmut") {
                    run_python(
                        execution,
                        repo,
                        check,
                        &python,
                        &["-m", "mutmut", "run"],
                    )
                } else {
                    CheckResult::unsupported(name(check), "mutmut is not available")
                }
            }
            CheckKind::Security => {
                if module_available(execution, repo, &python, "bandit") {
                    run_python(
                        execution,
                        repo,
                        check,
                        &python,
                        &["-m", "bandit", "-r", ".", "-q"],
                    )
                } else {
                    CheckResult::unsupported(name(check), "bandit is not available")
                }
            }
            CheckKind::Dependencies => run_python(
                execution,
                repo,
                check,
                &python,
                &["-m", "pip", "check"],
            ),
            CheckKind::Placeholders => scan_placeholders(repo),
            CheckKind::Fuzz
            | CheckKind::Concurrency
            | CheckKind::Contracts
            | CheckKind::Stress
            | CheckKind::FaultInjection
            | CheckKind::Ui
            | CheckKind::FormalProof => CheckResult::unsupported(
                name(check),
                format!(
                    "Python adapter has no configured {} harness for this repository",
                    check.as_str()
                ),
            ),
        }
    }
}

fn name(check: CheckKind) -> String {
    format!("python:{}", check.as_str())
}

fn python_program(execution: &dyn ExecutionAdapter, repo: &Path) -> Option<String> {
    ["python3", "python"].into_iter().find_map(|program| {
        let args = vec!["--version".to_owned()];
        execution
            .execute(program, &args, repo)
            .ok()
            .filter(|result| result.success())
            .map(|_| program.to_owned())
    })
}

fn executable_available(execution: &dyn ExecutionAdapter, repo: &Path, program: &str) -> bool {
    execution
        .execute(program, &["--version".to_owned()], repo)
        .map(|result| result.success())
        .unwrap_or(false)
}

fn module_available(
    execution: &dyn ExecutionAdapter,
    repo: &Path,
    python: &str,
    module: &str,
) -> bool {
    let code = format!(
        "import importlib.util,sys;sys.exit(0 if importlib.util.find_spec({module:?}) else 1)"
    );
    execution
        .execute(python, &["-c".to_owned(), code], repo)
        .map(|result| result.success())
        .unwrap_or(false)
}

fn run_tests(execution: &dyn ExecutionAdapter, repo: &Path, python: &str) -> CheckResult {
    if !has_test_files(repo) {
        return CheckResult::unsupported(
            name(CheckKind::Test),
            "no Python test_*.py or *_test.py files were found",
        );
    }
    if module_available(execution, repo, python, "pytest") {
        run_python(
            execution,
            repo,
            CheckKind::Test,
            python,
            &["-m", "pytest", "-q"],
        )
    } else {
        run_python(
            execution,
            repo,
            CheckKind::Test,
            python,
            &["-m", "unittest", "discover", "-v"],
        )
    }
}

fn run_coverage(execution: &dyn ExecutionAdapter, repo: &Path, python: &str) -> CheckResult {
    if !module_available(execution, repo, python, "coverage") {
        return CheckResult::unsupported(name(CheckKind::Coverage), "coverage.py is not available");
    }
    if !has_test_files(repo) {
        return CheckResult::unsupported(
            name(CheckKind::Coverage),
            "coverage cannot run because no Python tests were found",
        );
    }

    let run = if module_available(execution, repo, python, "pytest") {
        run_python(
            execution,
            repo,
            CheckKind::Coverage,
            python,
            &["-m", "coverage", "run", "-m", "pytest", "-q"],
        )
    } else {
        run_python(
            execution,
            repo,
            CheckKind::Coverage,
            python,
            &[
                "-m",
                "coverage",
                "run",
                "-m",
                "unittest",
                "discover",
                "-v",
            ],
        )
    };
    if run.status != CheckStatus::Pass {
        return run;
    }

    run_python(
        execution,
        repo,
        CheckKind::Coverage,
        python,
        &["-m", "coverage", "report"],
    )
}

fn run_python(
    execution: &dyn ExecutionAdapter,
    repo: &Path,
    check: CheckKind,
    python: &str,
    values: &[&str],
) -> CheckResult {
    run_command(execution, repo, check, python, values)
}

fn run_command(
    execution: &dyn ExecutionAdapter,
    repo: &Path,
    check: CheckKind,
    program: &str,
    values: &[&str],
) -> CheckResult {
    let args = values.iter().map(|value| (*value).to_owned()).collect::<Vec<_>>();
    match execution.execute(program, &args, repo) {
        Ok(output) if output.success() => CheckResult::pass(name(check)),
        Ok(output) => CheckResult::fail(
            name(check),
            "VF_COMMAND_FAILED",
            failure_message(program, values, output.exit_code, &output.stderr, &output.stdout),
        ),
        Err(error) => CheckResult::fail(name(check), "VF_EXECUTION_FAILED", error),
    }
}

fn scan_placeholders(repo: &Path) -> CheckResult {
    let patterns = [
        ["TO", "DO:"].concat(),
        ["FIX", "ME:"].concat(),
        ["X", "XX:"].concat(),
        ["NotImplemented", "Error"].concat(),
    ];
    let mut findings = Vec::new();

    for path in source_files(repo, "py") {
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        for (index, line) in content.lines().enumerate() {
            if let Some(pattern) = patterns.iter().find(|pattern| line.contains(pattern.as_str())) {
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
    let detail = if stderr.trim().is_empty() { stdout } else { stderr };
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

fn has_test_files(repo: &Path) -> bool {
    source_files(repo, "py").iter().any(|path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .map(|name| name.starts_with("test_") || name.ends_with("_test.py"))
            .unwrap_or(false)
    })
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
            if matches!(
                name.as_ref(),
                ".git" | "target" | "vendor" | "node_modules" | ".venv" | "venv" | "__pycache__"
            ) {
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
        std::env::temp_dir().join(format!("verificationforge-python-{nonce}"))
    }

    #[test]
    fn detects_nested_python_source() {
        let root = temp_dir();
        fs::create_dir_all(root.join("package/nested")).expect("create dirs");
        fs::write(root.join("package/nested/module.py"), "VALUE = 1\n").expect("write source");
        assert!(PythonAdapter.detect(&root).is_some());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn placeholder_scan_blocks_not_implemented() {
        let root = temp_dir();
        fs::create_dir_all(root.join("package")).expect("create dirs");
        let marker = ["NotImplemented", "Error"].concat();
        fs::write(
            root.join("package/module.py"),
            format!("def value():\n    raise {marker}\n"),
        )
        .expect("write source");
        let result = scan_placeholders(&root);
        assert_eq!(result.status, CheckStatus::Fail);
        fs::remove_dir_all(root).ok();
    }
}
