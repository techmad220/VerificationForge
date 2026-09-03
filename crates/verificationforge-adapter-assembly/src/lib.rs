use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use verificationforge_core::{
    CheckKind, CheckResult, CheckStatus, ExecutionAdapter, Finding, ImpactScope, LanguageAdapter,
    LanguageDetection, SymbolId, run_repository_harness,
};

const MAX_SCAN_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Dialect {
    Gnu,
    Nasm,
}

pub struct AssemblyAdapter;

impl LanguageAdapter for AssemblyAdapter {
    fn id(&self) -> &'static str {
        "assembly"
    }

    fn detect(&self, repo: &Path) -> Option<LanguageDetection> {
        let files = source_files(repo);
        if files.is_empty() {
            return None;
        }
        Some(LanguageDetection {
            adapter_id: self.id().into(),
            language: "Assembly".into(),
            confidence_percent: 94,
        })
    }

    fn inventory_symbols(&self, repo: &Path) -> Result<Vec<SymbolId>, String> {
        let mut symbols = Vec::new();
        for path in source_files(repo) {
            let relative = display_relative(repo, &path);
            symbols.push(SymbolId(format!("assembly:file:{relative}")));
            let Ok(content) = fs::read_to_string(&path) else {
                continue;
            };
            for raw in content.lines() {
                let line = strip_comment(raw).trim();
                if line.is_empty() {
                    continue;
                }
                if let Some(label) = line.strip_suffix(':') {
                    let label = label.trim();
                    if is_symbol_name(label) {
                        symbols.push(SymbolId(format!("assembly:label:{relative}:{label}")));
                    }
                }
                for directive in [".globl ", ".global ", "global "] {
                    if let Some(name) = line.strip_prefix(directive) {
                        let name = name.split_whitespace().next().unwrap_or_default();
                        if is_symbol_name(name) {
                            symbols.push(SymbolId(format!("assembly:global:{relative}:{name}")));
                        }
                    }
                }
            }
        }
        symbols.sort();
        symbols.dedup();
        Ok(symbols)
    }

    fn run_parse_check(&self, repo: &Path, execution: &dyn ExecutionAdapter) -> CheckResult {
        assemble_all(repo, execution, "parse", false)
    }

    fn run_format_check(&self, repo: &Path, _execution: &dyn ExecutionAdapter) -> CheckResult {
        deterministic_format_check(repo)
    }

    fn run_targeted_tests(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        scope: &ImpactScope,
    ) -> CheckResult {
        let affected = scope.changed_paths.iter().any(|path| is_assembly_path(Path::new(path)));
        if !affected && !scope.requires_full_verification {
            return CheckResult::skipped(
                "assembly:targeted-test",
                "no changed assembly path maps to the assembly adapter",
            );
        }
        rename_check(run_tests(repo, execution), "assembly:targeted-test")
    }

    fn run_integration_tests(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        _scope: &ImpactScope,
    ) -> CheckResult {
        if has_named_test(repo, "integration") {
            rename_check(run_tests(repo, execution), "assembly:checkpoint-integration")
        } else {
            CheckResult::skipped(
                "assembly:checkpoint-integration",
                "no assembly integration-test surface detected",
            )
        }
    }

    fn run_property_tests(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        _scope: &ImpactScope,
    ) -> CheckResult {
        if has_named_test(repo, "property") {
            rename_check(run_tests(repo, execution), "assembly:checkpoint-property")
        } else {
            CheckResult::skipped(
                "assembly:checkpoint-property",
                "no assembly property-test surface detected",
            )
        }
    }

    fn run_ui_verification(
        &self,
        _repo: &Path,
        _execution: &dyn ExecutionAdapter,
        _scope: &ImpactScope,
    ) -> CheckResult {
        CheckResult::skipped("assembly:checkpoint-ui", "assembly source exposes no native UI surface")
    }

    fn run_api_verification(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        _scope: &ImpactScope,
    ) -> CheckResult {
        if repository_contains(repo, &[".globl ", ".global ", "global "]) {
            required_harness(execution, repo, "checkpoint-api")
        } else {
            CheckResult::skipped(
                "assembly:checkpoint-api",
                "no exported assembly API surface detected",
            )
        }
    }

    fn run_check(
        &self,
        check: CheckKind,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
    ) -> CheckResult {
        match check {
            CheckKind::Build | CheckKind::TypeCheck => {
                assemble_all(repo, execution, check.as_str(), false)
            }
            CheckKind::Lint => assemble_all(repo, execution, check.as_str(), true),
            CheckKind::Test => run_tests(repo, execution),
            CheckKind::Dependencies => dependency_inventory(repo),
            CheckKind::Security | CheckKind::Placeholders => authenticity_scan(repo, check.as_str()),
            CheckKind::Concurrency => {
                if repository_contains(
                    repo,
                    &["lock ", "lock\n", "xchg", "cmpxchg", "mfence", "lfence", "sfence"],
                ) {
                    required_harness(execution, repo, check.as_str())
                } else {
                    CheckResult::skipped(
                        "assembly:concurrency",
                        "no assembly concurrency/atomic markers detected",
                    )
                }
            }
            CheckKind::Ui => CheckResult::skipped(
                "assembly:ui",
                "assembly source exposes no native UI surface",
            ),
            CheckKind::Coverage
            | CheckKind::Mutation
            | CheckKind::Fuzz
            | CheckKind::Contracts
            | CheckKind::Stress
            | CheckKind::FaultInjection
            | CheckKind::FormalProof => required_harness(execution, repo, check.as_str()),
        }
    }
}

fn assemble_all(
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: &str,
    warnings_as_errors: bool,
) -> CheckResult {
    let files = source_files(repo);
    if files.is_empty() {
        return CheckResult::unsupported(
            format!("assembly:{check_name}"),
            "no assembly source files were found",
        );
    }
    let out_dir = temp_output_dir("objects");
    if let Err(error) = fs::create_dir_all(&out_dir) {
        return CheckResult::fail(
            format!("assembly:{check_name}"),
            "VF_ASM_TEMP_FAILED",
            format!("cannot create temporary assembly output directory: {error}"),
        );
    }

    let mut gnu = 0usize;
    let mut nasm = 0usize;
    for (index, path) in files.iter().enumerate() {
        let relative = display_relative(repo, path);
        let object = out_dir.join(format!("unit-{index}.o"));
        let result = match dialect(path) {
            Dialect::Gnu => {
                gnu += 1;
                let mut args = vec!["-c".into(), relative.clone(), "-o".into(), object.display().to_string()];
                if warnings_as_errors {
                    args.insert(0, "-Wa,--fatal-warnings".into());
                }
                execution.execute("gcc", &args, repo)
            }
            Dialect::Nasm => {
                nasm += 1;
                let mut args = vec![
                    "-f".into(),
                    "elf64".into(),
                    relative.clone(),
                    "-o".into(),
                    object.display().to_string(),
                ];
                if warnings_as_errors {
                    args.insert(0, "-Werror".into());
                    args.insert(0, "-Wall".into());
                }
                execution.execute("nasm", &args, repo)
            }
        };
        match result {
            Ok(output) if output.success() => {}
            Ok(output) => {
                let _ = fs::remove_dir_all(&out_dir);
                return CheckResult::fail(
                    format!("assembly:{check_name}"),
                    "VF_ASM_ASSEMBLE_FAILED",
                    format!(
                        "failed to assemble {relative}: exit={} stderr={} stdout={}",
                        output.exit_code,
                        sanitize_output(&output.stderr),
                        sanitize_output(&output.stdout)
                    ),
                );
            }
            Err(error) => {
                let _ = fs::remove_dir_all(&out_dir);
                return CheckResult::fail(
                    format!("assembly:{check_name}"),
                    "VF_ASM_TOOLCHAIN_FAILED",
                    format!("cannot assemble {relative}: {error}"),
                );
            }
        }
    }
    let _ = fs::remove_dir_all(&out_dir);
    CheckResult::pass_with_evidence(
        format!("assembly:{check_name}"),
        format!(
            "native assembly completed files={} gnu={} nasm={} warnings_as_errors={warnings_as_errors}",
            files.len(), gnu, nasm
        ),
    )
}

fn run_tests(repo: &Path, execution: &dyn ExecutionAdapter) -> CheckResult {
    let tests = test_files(repo);
    if tests.is_empty() {
        return CheckResult::unsupported("assembly:test", "no assembly test programs were found");
    }
    let out_dir = temp_output_dir("tests");
    if let Err(error) = fs::create_dir_all(&out_dir) {
        return CheckResult::fail(
            "assembly:test",
            "VF_ASM_TEMP_FAILED",
            format!("cannot create temporary assembly test directory: {error}"),
        );
    }

    for (index, path) in tests.iter().enumerate() {
        let relative = display_relative(repo, path);
        let object = out_dir.join(format!("test-{index}.o"));
        let binary = out_dir.join(format!("test-{index}"));
        let assemble = match dialect(path) {
            Dialect::Gnu => execution.execute(
                "gcc",
                &[
                    "-c".into(),
                    relative.clone(),
                    "-o".into(),
                    object.display().to_string(),
                ],
                repo,
            ),
            Dialect::Nasm => execution.execute(
                "nasm",
                &[
                    "-f".into(),
                    "elf64".into(),
                    relative.clone(),
                    "-o".into(),
                    object.display().to_string(),
                ],
                repo,
            ),
        };
        if !execution_succeeded(assemble, &format!("assemble test {relative}")) {
            let _ = fs::remove_dir_all(&out_dir);
            return CheckResult::fail(
                "assembly:test",
                "VF_ASM_TEST_ASSEMBLE_FAILED",
                format!("assembly test failed to assemble: {relative}"),
            );
        }
        let linked = execution.execute(
            "gcc",
            &[
                "-no-pie".into(),
                object.display().to_string(),
                "-o".into(),
                binary.display().to_string(),
            ],
            repo,
        );
        if !execution_succeeded(linked, &format!("link test {relative}")) {
            let _ = fs::remove_dir_all(&out_dir);
            return CheckResult::fail(
                "assembly:test",
                "VF_ASM_TEST_LINK_FAILED",
                format!("assembly test failed to link: {relative}"),
            );
        }
        let program = binary.display().to_string();
        match execution.execute(&program, &[], repo) {
            Ok(output) if output.success() => {}
            Ok(output) => {
                let _ = fs::remove_dir_all(&out_dir);
                return CheckResult::fail(
                    "assembly:test",
                    "VF_ASM_TEST_FAILED",
                    format!("{relative} exited with code {}", output.exit_code),
                );
            }
            Err(error) => {
                let _ = fs::remove_dir_all(&out_dir);
                return CheckResult::fail(
                    "assembly:test",
                    "VF_ASM_TEST_EXECUTION_FAILED",
                    format!("cannot execute {relative}: {error}"),
                );
            }
        }
    }
    let _ = fs::remove_dir_all(&out_dir);
    CheckResult::pass_with_evidence(
        "assembly:test",
        format!("assembled linked and executed assembly test programs={}", tests.len()),
    )
}

fn deterministic_format_check(repo: &Path) -> CheckResult {
    let mut checked = 0usize;
    for path in source_files(repo) {
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        checked += 1;
        for (index, line) in content.lines().enumerate() {
            if line.ends_with(' ') || line.ends_with('\t') {
                return CheckResult::fail(
                    "assembly:format",
                    "VF_ASM_FORMAT_TRAILING_WHITESPACE",
                    format!("{}:{} has trailing whitespace", display_relative(repo, &path), index + 1),
                );
            }
            if line.contains('\r') {
                return CheckResult::fail(
                    "assembly:format",
                    "VF_ASM_FORMAT_CRLF",
                    format!("{}:{} contains carriage-return whitespace", display_relative(repo, &path), index + 1),
                );
            }
        }
    }
    CheckResult::pass_with_evidence(
        "assembly:format",
        format!("deterministic assembly whitespace policy accepted files={checked}"),
    )
}

fn dependency_inventory(repo: &Path) -> CheckResult {
    let mut includes = 0usize;
    for path in source_files(repo) {
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        for raw in content.lines() {
            let line = strip_comment(raw).trim_start();
            if line.starts_with(".include ") || line.starts_with("%include ") || line.starts_with("#include ") {
                includes += 1;
            }
        }
    }
    CheckResult::pass_with_evidence(
        "assembly:dependencies",
        format!("assembly include/dependency directives inventoried count={includes}"),
    )
}

fn authenticity_scan(repo: &Path, check_name: &str) -> CheckResult {
    let mut findings = Vec::new();
    for path in source_files(repo) {
        let Ok(metadata) = fs::metadata(&path) else {
            continue;
        };
        if metadata.len() > MAX_SCAN_BYTES {
            continue;
        }
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        for (index, raw) in content.lines().enumerate() {
            let lower = raw.to_ascii_lowercase();
            if ["todo", "fixme", "xxx", "not implemented", "placeholder"]
                .iter()
                .any(|marker| lower.contains(marker))
            {
                findings.push(Finding {
                    code: "VF_ASM_PLACEHOLDER".into(),
                    message: format!("{}:{} contains unfinished implementation marker", display_relative(repo, &path), index + 1),
                    blocking: true,
                });
            }
            if lower.contains("password") && (lower.contains("db ") || lower.contains(".ascii") || lower.contains(".string")) {
                findings.push(Finding {
                    code: "VF_ASM_EMBEDDED_SECRET".into(),
                    message: format!("{}:{} appears to embed credential-like data", display_relative(repo, &path), index + 1),
                    blocking: true,
                });
            }
        }
    }
    if findings.is_empty() {
        CheckResult::pass_with_evidence(
            format!("assembly:{check_name}"),
            "assembly authenticity/security scan found no blocking markers",
        )
    } else {
        CheckResult {
            check: format!("assembly:{check_name}"),
            status: CheckStatus::Fail,
            findings,
        }
    }
}

fn required_harness(
    execution: &dyn ExecutionAdapter,
    repo: &Path,
    check_name: &str,
) -> CheckResult {
    run_repository_harness(
        repo,
        execution,
        format!("assembly:{check_name}"),
        &format!("assembly-{check_name}"),
    )
    .unwrap_or_else(|| {
        CheckResult::unsupported(
            format!("assembly:{check_name}"),
            format!(
                "assembly {check_name} requires .verificationforge/assembly-{check_name}.argv evidence"
            ),
        )
    })
}

fn source_files(repo: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_files(repo, repo, &mut files);
    files.sort();
    files
}

fn collect_files(root: &Path, current: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(current) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|value| value.to_str()).unwrap_or_default();
            if matches!(name, ".git" | "target" | "node_modules" | "vendor" | ".venv" | "dist" | "build") {
                continue;
            }
            collect_files(root, &path, files);
        } else if is_assembly_path(&path) {
            let _ = root;
            files.push(path);
        }
    }
}

fn test_files(repo: &Path) -> Vec<PathBuf> {
    source_files(repo)
        .into_iter()
        .filter(|path| {
            let relative = display_relative(repo, path).to_ascii_lowercase();
            relative.starts_with("tests/")
                || relative.starts_with("test/")
                || relative.contains("/tests/")
                || relative.contains("/test/")
                || relative.contains("_test.")
                || relative.contains(".test.")
        })
        .collect()
}

fn has_named_test(repo: &Path, marker: &str) -> bool {
    test_files(repo)
        .iter()
        .any(|path| display_relative(repo, path).to_ascii_lowercase().contains(marker))
}

fn is_assembly_path(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|value| value.to_str()),
        Some("s" | "S" | "asm")
    )
}

fn dialect(path: &Path) -> Dialect {
    if path.extension().and_then(|value| value.to_str()) == Some("asm") {
        Dialect::Nasm
    } else {
        Dialect::Gnu
    }
}

fn display_relative(repo: &Path, path: &Path) -> String {
    path.strip_prefix(repo)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn strip_comment(line: &str) -> &str {
    let semicolon = line.find(';');
    let hash = line.find('#');
    let index = match (semicolon, hash) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    };
    index.map_or(line, |index| &line[..index])
}

fn is_symbol_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '$' | '@'))
}

fn repository_contains(repo: &Path, markers: &[&str]) -> bool {
    source_files(repo).into_iter().any(|path| {
        fs::read_to_string(path)
            .map(|content| markers.iter().any(|marker| content.contains(marker)))
            .unwrap_or(false)
    })
}

fn temp_output_dir(kind: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "verificationforge-assembly-{}-{kind}",
        process::id()
    ))
}

fn execution_succeeded(result: Result<verificationforge_core::ExecutionResult, String>, _context: &str) -> bool {
    matches!(result, Ok(output) if output.success())
}

fn rename_check(mut result: CheckResult, name: &str) -> CheckResult {
    result.check = name.into();
    result
}

fn sanitize_output(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}
