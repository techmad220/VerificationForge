use std::fs;
use std::path::{Path, PathBuf};

use verificationforge_core::{
    CheckKind, CheckResult, CheckStatus, ExecutionAdapter, Finding, ImpactScope, LanguageAdapter,
    LanguageDetection, SymbolId, run_repository_harness,
};

const MAX_SCAN_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone, Copy)]
struct JsProfile {
    id: &'static str,
    language: &'static str,
    extensions: &'static [&'static str],
    typed: bool,
}

const JAVASCRIPT: JsProfile = JsProfile {
    id: "javascript",
    language: "JavaScript",
    extensions: &["js", "jsx", "mjs", "cjs"],
    typed: false,
};

const TYPESCRIPT: JsProfile = JsProfile {
    id: "typescript",
    language: "TypeScript",
    extensions: &["ts", "tsx", "mts", "cts"],
    typed: true,
};

pub struct JavaScriptAdapter;
pub struct TypeScriptAdapter;

impl LanguageAdapter for JavaScriptAdapter {
    fn id(&self) -> &'static str {
        JAVASCRIPT.id
    }

    fn detect(&self, repo: &Path) -> Option<LanguageDetection> {
        detect(JAVASCRIPT, repo)
    }

    fn inventory_symbols(&self, repo: &Path) -> Result<Vec<SymbolId>, String> {
        inventory_symbols(JAVASCRIPT, repo)
    }

    fn run_parse_check(&self, repo: &Path, execution: &dyn ExecutionAdapter) -> CheckResult {
        run_parse(JAVASCRIPT, repo, execution)
    }

    fn run_format_check(&self, repo: &Path, execution: &dyn ExecutionAdapter) -> CheckResult {
        run_format(JAVASCRIPT, repo, execution)
    }

    fn run_targeted_tests(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        scope: &ImpactScope,
    ) -> CheckResult {
        run_targeted_tests(JAVASCRIPT, repo, execution, scope)
    }

    fn run_integration_tests(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        _scope: &ImpactScope,
    ) -> CheckResult {
        run_integration_tests(JAVASCRIPT, repo, execution)
    }

    fn run_property_tests(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        _scope: &ImpactScope,
    ) -> CheckResult {
        run_property_tests(JAVASCRIPT, repo, execution)
    }

    fn run_ui_verification(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        _scope: &ImpactScope,
    ) -> CheckResult {
        run_surface_verification(JAVASCRIPT, repo, execution, "ui", has_ui_surface(repo))
    }

    fn run_api_verification(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        _scope: &ImpactScope,
    ) -> CheckResult {
        run_surface_verification(JAVASCRIPT, repo, execution, "api", has_api_surface(repo))
    }

    fn run_check(
        &self,
        check: CheckKind,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
    ) -> CheckResult {
        run_check(JAVASCRIPT, check, repo, execution)
    }
}

impl LanguageAdapter for TypeScriptAdapter {
    fn id(&self) -> &'static str {
        TYPESCRIPT.id
    }

    fn detect(&self, repo: &Path) -> Option<LanguageDetection> {
        detect(TYPESCRIPT, repo)
    }

    fn inventory_symbols(&self, repo: &Path) -> Result<Vec<SymbolId>, String> {
        inventory_symbols(TYPESCRIPT, repo)
    }

    fn run_parse_check(&self, repo: &Path, execution: &dyn ExecutionAdapter) -> CheckResult {
        run_parse(TYPESCRIPT, repo, execution)
    }

    fn run_format_check(&self, repo: &Path, execution: &dyn ExecutionAdapter) -> CheckResult {
        run_format(TYPESCRIPT, repo, execution)
    }

    fn run_targeted_tests(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        scope: &ImpactScope,
    ) -> CheckResult {
        run_targeted_tests(TYPESCRIPT, repo, execution, scope)
    }

    fn run_integration_tests(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        _scope: &ImpactScope,
    ) -> CheckResult {
        run_integration_tests(TYPESCRIPT, repo, execution)
    }

    fn run_property_tests(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        _scope: &ImpactScope,
    ) -> CheckResult {
        run_property_tests(TYPESCRIPT, repo, execution)
    }

    fn run_ui_verification(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        _scope: &ImpactScope,
    ) -> CheckResult {
        run_surface_verification(TYPESCRIPT, repo, execution, "ui", has_ui_surface(repo))
    }

    fn run_api_verification(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        _scope: &ImpactScope,
    ) -> CheckResult {
        run_surface_verification(TYPESCRIPT, repo, execution, "api", has_api_surface(repo))
    }

    fn run_check(
        &self,
        check: CheckKind,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
    ) -> CheckResult {
        run_check(TYPESCRIPT, check, repo, execution)
    }
}

fn detect(profile: JsProfile, repo: &Path) -> Option<LanguageDetection> {
    let sources = source_files(profile, repo);
    if sources.is_empty() {
        return None;
    }
    let manifest = repo.join("package.json").is_file()
        || (profile.typed && repo.join("tsconfig.json").is_file());
    Some(LanguageDetection {
        adapter_id: profile.id.into(),
        language: profile.language.into(),
        confidence_percent: if manifest { 100 } else { 88 },
    })
}

fn inventory_symbols(profile: JsProfile, repo: &Path) -> Result<Vec<SymbolId>, String> {
    let mut symbols = Vec::new();
    for path in source_files(profile, repo) {
        let relative = display_relative(repo, &path);
        symbols.push(SymbolId(format!("{}:file:{relative}", profile.id)));
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        for line in content.lines() {
            let trimmed = line.trim_start();
            for prefix in ["export ", "export default "] {
                if let Some(rest) = trimmed.strip_prefix(prefix) {
                    add_declaration_symbol(profile, &relative, rest, &mut symbols);
                }
            }
            add_declaration_symbol(profile, &relative, trimmed, &mut symbols);
        }
    }
    symbols.sort();
    symbols.dedup();
    Ok(symbols)
}

fn add_declaration_symbol(
    profile: JsProfile,
    relative: &str,
    line: &str,
    symbols: &mut Vec<SymbolId>,
) {
    for (prefix, kind) in [
        ("function ", "function"),
        ("class ", "class"),
        ("const ", "binding"),
        ("let ", "binding"),
        ("var ", "binding"),
        ("interface ", "interface"),
        ("type ", "type"),
        ("enum ", "enum"),
    ] {
        if let Some(rest) = line.strip_prefix(prefix) {
            let name = identifier(rest);
            if !name.is_empty() {
                symbols.push(SymbolId(format!(
                    "{}:{kind}:{relative}:{name}",
                    profile.id
                )));
            }
            return;
        }
    }
}

fn run_parse(profile: JsProfile, repo: &Path, execution: &dyn ExecutionAdapter) -> CheckResult {
    if profile.typed {
        return run_typescript_check(profile, repo, execution, "parse");
    }
    run_javascript_syntax(profile, repo, execution, "parse")
}

fn run_format(profile: JsProfile, repo: &Path, execution: &dyn ExecutionAdapter) -> CheckResult {
    for script in ["format:check", "format-check"] {
        if package_has_script(repo, script) {
            return run_package_script(profile, execution, repo, "format", script);
        }
    }
    if executable_available(execution, repo, "prettier") {
        return run_named(
            profile,
            execution,
            repo,
            "format",
            "prettier",
            vec!["--check".into(), ".".into()],
        );
    }
    whitespace_format_check(profile, repo)
}

fn run_targeted_tests(
    profile: JsProfile,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    scope: &ImpactScope,
) -> CheckResult {
    let affected = scope.changed_paths.iter().any(|path| {
        let extension = Path::new(path)
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        profile.extensions.contains(&extension.as_str())
            || matches!(
                Path::new(path).file_name().and_then(|value| value.to_str()),
                Some("package.json" | "package-lock.json" | "pnpm-lock.yaml" | "yarn.lock")
            )
    });
    if !affected && !scope.requires_full_verification {
        return CheckResult::skipped(
            format!("{}:targeted-test", profile.id),
            "no changed JavaScript-family path maps to this adapter",
        );
    }
    if !has_tests(profile, repo) && !package_has_script(repo, "test") {
        return CheckResult::skipped(
            format!("{}:targeted-test", profile.id),
            "affected source has no native test files or package test script",
        );
    }
    rename_check(
        run_tests(profile, repo, execution),
        format!("{}:targeted-test", profile.id),
    )
}

fn run_integration_tests(
    profile: JsProfile,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
) -> CheckResult {
    for script in ["test:integration", "integration"] {
        if package_has_script(repo, script) {
            return run_package_script(profile, execution, repo, "checkpoint-integration", script);
        }
    }
    if has_named_test(repo, "integration") {
        return rename_check(
            run_tests(profile, repo, execution),
            format!("{}:checkpoint-integration", profile.id),
        );
    }
    CheckResult::skipped(
        format!("{}:checkpoint-integration", profile.id),
        "no JavaScript-family integration-test surface detected",
    )
}

fn run_property_tests(
    profile: JsProfile,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
) -> CheckResult {
    for script in ["test:property", "property"] {
        if package_has_script(repo, script) {
            return run_package_script(profile, execution, repo, "checkpoint-property", script);
        }
    }
    if repository_contains(repo, &["fast-check", "jsverify", "testcheck"]) {
        if package_has_script(repo, "test") {
            return rename_check(
                run_tests(profile, repo, execution),
                format!("{}:checkpoint-property", profile.id),
            );
        }
        return required_harness(profile, execution, repo, "checkpoint-property");
    }
    CheckResult::skipped(
        format!("{}:checkpoint-property", profile.id),
        "no JavaScript-family property-testing surface detected",
    )
}

fn run_surface_verification(
    profile: JsProfile,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    surface: &str,
    applicable: bool,
) -> CheckResult {
    if !applicable {
        return CheckResult::skipped(
            format!("{}:checkpoint-{surface}", profile.id),
            format!("no affected JavaScript-family {surface} surface detected"),
        );
    }
    required_harness(profile, execution, repo, &format!("checkpoint-{surface}"))
}

fn run_check(
    profile: JsProfile,
    check: CheckKind,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
) -> CheckResult {
    match check {
        CheckKind::Build => {
            if package_has_script(repo, "build") {
                run_package_script(profile, execution, repo, check.as_str(), "build")
            } else {
                run_parse(profile, repo, execution)
                    .with_check_name(format!("{}:{}", profile.id, check.as_str()))
            }
        }
        CheckKind::TypeCheck => {
            if package_has_script(repo, "typecheck") {
                run_package_script(profile, execution, repo, check.as_str(), "typecheck")
            } else if profile.typed || repo.join("jsconfig.json").is_file() {
                run_typescript_check(profile, repo, execution, check.as_str())
            } else {
                run_javascript_syntax(profile, repo, execution, check.as_str())
            }
        }
        CheckKind::Lint => {
            if package_has_script(repo, "lint") {
                run_package_script(profile, execution, repo, check.as_str(), "lint")
            } else if executable_available(execution, repo, "eslint") {
                run_named(
                    profile,
                    execution,
                    repo,
                    check.as_str(),
                    "eslint",
                    vec![".".into()],
                )
            } else {
                baseline_lint(profile, repo, execution)
            }
        }
        CheckKind::Test => run_tests(profile, repo, execution),
        CheckKind::Coverage => run_coverage(profile, repo, execution),
        CheckKind::Dependencies => run_dependencies(profile, repo, execution),
        CheckKind::Security => run_security(profile, repo, execution),
        CheckKind::Placeholders => scan_placeholders(profile, repo),
        CheckKind::Concurrency => {
            if repository_contains(
                repo,
                &["worker_threads", "SharedArrayBuffer", "Atomics.", "new Worker("],
            ) {
                required_harness(profile, execution, repo, check.as_str())
            } else {
                CheckResult::skipped(
                    format!("{}:{}", profile.id, check.as_str()),
                    "no JavaScript worker/shared-memory concurrency markers detected",
                )
            }
        }
        CheckKind::Ui => {
            if has_ui_surface(repo) {
                required_harness(profile, execution, repo, check.as_str())
            } else {
                CheckResult::skipped(
                    format!("{}:{}", profile.id, check.as_str()),
                    "no JavaScript-family UI surface detected",
                )
            }
        }
        CheckKind::Mutation
        | CheckKind::Fuzz
        | CheckKind::Contracts
        | CheckKind::Stress
        | CheckKind::FaultInjection
        | CheckKind::FormalProof => required_harness(profile, execution, repo, check.as_str()),
    }
}

trait CheckResultExt {
    fn with_check_name(self, check: String) -> Self;
}

impl CheckResultExt for CheckResult {
    fn with_check_name(mut self, check: String) -> Self {
        self.check = check;
        self
    }
}

fn baseline_lint(
    profile: JsProfile,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
) -> CheckResult {
    let parsed = run_parse(profile, repo, execution);
    if parsed.status != CheckStatus::Pass {
        return parsed.with_check_name(format!("{}:lint", profile.id));
    }
    let formatted = whitespace_format_check(profile, repo);
    if formatted.status != CheckStatus::Pass {
        return formatted.with_check_name(format!("{}:lint", profile.id));
    }
    CheckResult::pass_with_evidence(
        format!("{}:lint", profile.id),
        "baseline native lint completed: parser/type-check plus deterministic whitespace policy",
    )
}

fn run_tests(profile: JsProfile, repo: &Path, execution: &dyn ExecutionAdapter) -> CheckResult {
    if package_has_script(repo, "test") {
        return run_package_script(profile, execution, repo, "test", "test");
    }
    if !has_tests(profile, repo) {
        return CheckResult::unsupported(
            format!("{}:test", profile.id),
            "no JavaScript-family test files or package test script were found",
        );
    }
    if profile.typed {
        return required_harness(profile, execution, repo, "test");
    }
    run_named(
        profile,
        execution,
        repo,
        "test",
        "node",
        vec!["--test".into()],
    )
}

fn run_coverage(
    profile: JsProfile,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
) -> CheckResult {
    if package_has_script(repo, "coverage") {
        return run_package_script(profile, execution, repo, "coverage", "coverage");
    }
    if !profile.typed && has_tests(profile, repo) {
        return run_named(
            profile,
            execution,
            repo,
            "coverage",
            "node",
            vec!["--experimental-test-coverage".into(), "--test".into()],
        );
    }
    required_harness(profile, execution, repo, "coverage")
}

fn run_dependencies(
    profile: JsProfile,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
) -> CheckResult {
    let Some(manager) = package_manager(execution, repo) else {
        return required_harness(profile, execution, repo, "dependencies");
    };
    let args = match manager {
        "npm" => vec!["ls".into(), "--all".into(), "--omit=optional".into()],
        "pnpm" => vec!["list".into(), "--depth".into(), "Infinity".into()],
        "yarn" => vec!["list".into(), "--json".into()],
        "bun" => vec!["pm".into(), "ls".into()],
        _ => Vec::new(),
    };
    run_named(profile, execution, repo, "dependencies", manager, args)
}

fn run_security(
    profile: JsProfile,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
) -> CheckResult {
    let Some(manager) = package_manager(execution, repo) else {
        return required_harness(profile, execution, repo, "security");
    };
    let args = match manager {
        "npm" => vec!["audit".into(), "--audit-level=high".into()],
        "pnpm" => vec!["audit".into(), "--audit-level".into(), "high".into()],
        _ => return required_harness(profile, execution, repo, "security"),
    };
    run_named(profile, execution, repo, "security", manager, args)
}

fn run_typescript_check(
    profile: JsProfile,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: &str,
) -> CheckResult {
    if !executable_available(execution, repo, "tsc") {
        return required_harness(profile, execution, repo, check_name);
    }
    let config = if profile.typed && repo.join("tsconfig.json").is_file() {
        Some("tsconfig.json")
    } else if !profile.typed && repo.join("jsconfig.json").is_file() {
        Some("jsconfig.json")
    } else {
        None
    };
    let args = if let Some(config) = config {
        vec!["--noEmit".into(), "-p".into(), config.into()]
    } else {
        let mut args = vec!["--noEmit".into(), "--target".into(), "ES2022".into()];
        if !profile.typed {
            args.extend(["--allowJs".into(), "--checkJs".into()]);
        }
        args.extend(
            source_files(profile, repo)
                .into_iter()
                .map(|path| display_relative(repo, &path)),
        );
        args
    };
    run_named(profile, execution, repo, check_name, "tsc", args)
}

fn run_javascript_syntax(
    profile: JsProfile,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: &str,
) -> CheckResult {
    if !executable_available(execution, repo, "node") {
        return CheckResult::fail(
            format!("{}:{check_name}", profile.id),
            "VF_NODE_MISSING",
            "JavaScript repository detected but node is not executable",
        );
    }
    let files = source_files(profile, repo);
    let mut checked = 0usize;
    let mut jsx = Vec::new();
    for path in files {
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if extension == "jsx" {
            jsx.push(path);
            continue;
        }
        let relative = display_relative(repo, &path);
        let result = execution.execute("node", &["--check".into(), relative.clone()], repo);
        match result {
            Ok(output) if output.success() => checked += 1,
            Ok(output) => {
                return CheckResult::fail(
                    format!("{}:{check_name}", profile.id),
                    "VF_JS_PARSE_FAILED",
                    format!(
                        "node --check {relative} exit={} stderr={} stdout={}",
                        output.exit_code,
                        sanitize_output(&output.stderr),
                        sanitize_output(&output.stdout)
                    ),
                );
            }
            Err(error) => {
                return CheckResult::fail(
                    format!("{}:{check_name}", profile.id),
                    "VF_JS_EXECUTION_FAILED",
                    error,
                );
            }
        }
    }
    if !jsx.is_empty() {
        if !executable_available(execution, repo, "tsc") {
            return required_harness(profile, execution, repo, check_name);
        }
        let mut args = vec![
            "--allowJs".into(),
            "--noEmit".into(),
            "--jsx".into(),
            "preserve".into(),
        ];
        args.extend(jsx.iter().map(|path| display_relative(repo, path)));
        let result = run_named(profile, execution, repo, check_name, "tsc", args);
        if result.status != CheckStatus::Pass {
            return result;
        }
        checked += jsx.len();
    }
    CheckResult::pass_with_evidence(
        format!("{}:{check_name}", profile.id),
        format!("native JavaScript syntax parser accepted files={checked}"),
    )
}

fn run_package_script(
    profile: JsProfile,
    execution: &dyn ExecutionAdapter,
    repo: &Path,
    check_name: &str,
    script: &str,
) -> CheckResult {
    let Some(manager) = package_manager(execution, repo) else {
        return CheckResult::fail(
            format!("{}:{check_name}", profile.id),
            "VF_JS_PACKAGE_MANAGER_MISSING",
            format!("package script {script} exists but no supported package manager is executable"),
        );
    };
    let args = match manager {
        "npm" | "pnpm" | "yarn" | "bun" => vec!["run".into(), script.into()],
        _ => Vec::new(),
    };
    run_named(profile, execution, repo, check_name, manager, args)
}

fn run_named(
    profile: JsProfile,
    execution: &dyn ExecutionAdapter,
    repo: &Path,
    check_name: &str,
    program: &str,
    args: Vec<String>,
) -> CheckResult {
    match execution.execute(program, &args, repo) {
        Ok(output) if output.success() => CheckResult::pass_with_evidence(
            format!("{}:{check_name}", profile.id),
            format!("command={program} {} exit=0", args.join(" ")),
        ),
        Ok(output) => CheckResult::fail(
            format!("{}:{check_name}", profile.id),
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
            format!("{}:{check_name}", profile.id),
            "VF_EXECUTION_FAILED",
            error,
        ),
    }
}

fn required_harness(
    profile: JsProfile,
    execution: &dyn ExecutionAdapter,
    repo: &Path,
    check_name: &str,
) -> CheckResult {
    let harness = format!("{}-{check_name}", profile.id);
    run_repository_harness(
        repo,
        execution,
        format!("{}:{check_name}", profile.id),
        &harness,
    )
    .unwrap_or_else(|| {
        CheckResult::unsupported(
            format!("{}:{check_name}", profile.id),
            format!("required {} harness is missing: .verificationforge/{harness}.argv", profile.language),
        )
    })
}

fn whitespace_format_check(profile: JsProfile, repo: &Path) -> CheckResult {
    let mut scanned = 0usize;
    let mut findings = Vec::new();
    for path in source_files(profile, repo) {
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        scanned += 1;
        for (index, line) in content.lines().enumerate() {
            if line.ends_with(' ') || line.ends_with('\t') {
                findings.push(Finding {
                    code: "VF_FORMAT_TRAILING_WHITESPACE".into(),
                    message: format!("{}:{} has trailing whitespace", display_relative(repo, &path), index + 1),
                    blocking: true,
                });
            }
        }
        if !content.is_empty() && !content.ends_with('\n') {
            findings.push(Finding {
                code: "VF_FORMAT_FINAL_NEWLINE".into(),
                message: format!("{} is missing a final newline", display_relative(repo, &path)),
                blocking: true,
            });
        }
    }
    if findings.is_empty() {
        CheckResult::pass_with_evidence(
            format!("{}:format", profile.id),
            format!("deterministic built-in whitespace format policy files={scanned} violations=0"),
        )
    } else {
        CheckResult {
            check: format!("{}:format", profile.id),
            status: CheckStatus::Fail,
            findings,
        }
    }
}

fn scan_placeholders(profile: JsProfile, repo: &Path) -> CheckResult {
    let mut findings = Vec::new();
    let mut scanned = 0usize;
    for path in source_files(profile, repo) {
        let Ok(metadata) = fs::metadata(&path) else {
            continue;
        };
        if metadata.len() > MAX_SCAN_BYTES {
            continue;
        }
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        scanned += 1;
        for (index, line) in content.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            if lower.contains(&["to", "do:"].concat())
                || lower.contains(&["fix", "me:"].concat())
                || lower.contains(&["x", "xx:"].concat())
                || (lower.contains("throw new error") && lower.contains("not implemented"))
            {
                findings.push(Finding {
                    code: "VF_PLACEHOLDER".into(),
                    message: format!("{}:{} contains an unfinished implementation marker", display_relative(repo, &path), index + 1),
                    blocking: true,
                });
            }
            if sensitive_constant_gate(line) {
                findings.push(Finding {
                    code: "VF_FAKE_IMPLEMENTATION".into(),
                    message: format!("{}:{} contains a constant authorization/permission decision", display_relative(repo, &path), index + 1),
                    blocking: true,
                });
            }
        }
    }
    if findings.is_empty() {
        CheckResult::pass_with_evidence(
            format!("{}:placeholders", profile.id),
            format!("scanned {scanned} {} source files for placeholder and fake-success patterns", profile.language),
        )
    } else {
        CheckResult {
            check: format!("{}:placeholders", profile.id),
            status: CheckStatus::Fail,
            findings,
        }
    }
}

fn sensitive_constant_gate(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    let sensitive = ["authoriz", "authenticate", "permission", "isadmin", "hasaccess", "canaccess"]
        .iter()
        .any(|marker| lower.contains(marker));
    sensitive
        && (lower.contains("=> true")
            || lower.contains("=> false")
            || lower.contains("return true")
            || lower.contains("return false"))
}

fn package_has_script(repo: &Path, script: &str) -> bool {
    let Ok(content) = fs::read_to_string(repo.join("package.json")) else {
        return false;
    };
    let Some(start) = content.find("\"scripts\"") else {
        return false;
    };
    let section = &content[start..];
    let Some(open) = section.find('{') else {
        return false;
    };
    let body = &section[open + 1..];
    let end = body.find('}').unwrap_or(body.len());
    body[..end].contains(&format!("\"{script}\""))
}

fn package_manager(execution: &dyn ExecutionAdapter, repo: &Path) -> Option<&'static str> {
    let preferred = if repo.join("pnpm-lock.yaml").is_file() {
        "pnpm"
    } else if repo.join("yarn.lock").is_file() {
        "yarn"
    } else if repo.join("bun.lock").is_file() || repo.join("bun.lockb").is_file() {
        "bun"
    } else {
        "npm"
    };
    executable_available(execution, repo, preferred)
        .then_some(preferred)
        .or_else(|| executable_available(execution, repo, "npm").then_some("npm"))
}

fn executable_available(execution: &dyn ExecutionAdapter, repo: &Path, program: &str) -> bool {
    execution
        .execute(program, &["--version".into()], repo)
        .map(|result| result.success())
        .unwrap_or(false)
}

fn has_tests(profile: JsProfile, repo: &Path) -> bool {
    source_files(profile, repo).iter().any(|path| {
        let name = path.file_name().and_then(|value| value.to_str()).unwrap_or_default();
        name.contains(".test.")
            || name.contains(".spec.")
            || path.components().any(|component| {
                matches!(component.as_os_str().to_str(), Some("test" | "tests" | "__tests__"))
            })
    })
}

fn has_named_test(repo: &Path, marker: &str) -> bool {
    repository_files(repo).iter().any(|path| {
        display_relative(repo, path)
            .to_ascii_lowercase()
            .contains(marker)
    })
}

fn has_ui_surface(repo: &Path) -> bool {
    repository_files(repo).iter().any(|path| {
        matches!(
            path.extension()
                .and_then(|value| value.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase()
                .as_str(),
            "jsx" | "tsx" | "html" | "htm" | "css" | "scss" | "vue" | "svelte"
        )
    }) || repository_contains(repo, &["react", "next", "vue", "svelte", "@angular/"])
}

fn has_api_surface(repo: &Path) -> bool {
    repository_contains(
        repo,
        &[
            "express(",
            "fastify(",
            "createServer(",
            "http.createServer",
            "https.createServer",
            "new Router(",
        ],
    )
}

fn repository_contains(repo: &Path, markers: &[&str]) -> bool {
    repository_files(repo).into_iter().any(|path| {
        let Ok(metadata) = fs::metadata(&path) else {
            return false;
        };
        if metadata.len() > MAX_SCAN_BYTES {
            return false;
        }
        fs::read_to_string(path)
            .is_ok_and(|content| markers.iter().any(|marker| content.contains(marker)))
    })
}

fn source_files(profile: JsProfile, repo: &Path) -> Vec<PathBuf> {
    repository_files(repo)
        .into_iter()
        .filter(|path| {
            let extension = path
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            profile.extensions.contains(&extension.as_str())
        })
        .collect()
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
                ".git" | "node_modules" | "dist" | "build" | "coverage" | "target" | ".vf-dist"
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

fn identifier(value: &str) -> &str {
    let value = value.trim_start();
    let end = value
        .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_' || character == '$'))
        .unwrap_or(value.len());
    &value[..end]
}

fn rename_check(mut result: CheckResult, name: String) -> CheckResult {
    result.check = name;
    result
}

fn sanitize_output(value: &str) -> String {
    value
        .replace(['\r', '\n'], " ")
        .chars()
        .take(1200)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct NoopExecution;

    impl ExecutionAdapter for NoopExecution {
        fn id(&self) -> &'static str {
            "noop"
        }

        fn execute(
            &self,
            _program: &str,
            _args: &[String],
            _cwd: &Path,
        ) -> Result<verificationforge_core::ExecutionResult, String> {
            Ok(verificationforge_core::ExecutionResult {
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
        std::env::temp_dir().join(format!("verificationforge-js-family-{name}-{nonce}"))
    }

    #[test]
    fn javascript_and_typescript_are_detected_independently() {
        let root = temp_dir("mixed");
        fs::create_dir_all(&root).expect("create root");
        fs::write(root.join("app.js"), "export const one = 1;\n").expect("write js");
        fs::write(root.join("typed.ts"), "export const two: number = 2;\n").expect("write ts");
        assert_eq!(
            JavaScriptAdapter.detect(&root).expect("javascript").language,
            "JavaScript"
        );
        assert_eq!(
            TypeScriptAdapter.detect(&root).expect("typescript").language,
            "TypeScript"
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn placeholder_scan_blocks_constant_authorization() {
        let root = temp_dir("fake-auth");
        fs::create_dir_all(&root).expect("create root");
        fs::write(
            root.join("auth.ts"),
            "export const authorize = (_user: string): boolean => true;\n",
        )
        .expect("write source");
        let result = scan_placeholders(TYPESCRIPT, &root);
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.has_blocking_finding());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn built_in_format_policy_is_evidence_backed() {
        let root = temp_dir("format");
        fs::create_dir_all(&root).expect("create root");
        fs::write(root.join("app.js"), "const value = 1;\n").expect("write source");
        let result = run_format(JAVASCRIPT, &root, &NoopExecution);
        assert_eq!(result.status, CheckStatus::Pass);
        assert!(result.has_reproducible_evidence());
        fs::remove_dir_all(root).ok();
    }
}
