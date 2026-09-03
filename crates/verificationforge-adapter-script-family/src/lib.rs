use std::fs;
use std::path::{Path, PathBuf};

use verificationforge_core::{
    CheckKind, CheckResult, CheckStatus, ExecutionAdapter, Finding, ImpactScope, LanguageAdapter,
    LanguageDetection, SymbolId, run_repository_harness,
};

const MAX_SCAN_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScriptLanguage {
    Bash,
    PowerShell,
    Php,
}

impl ScriptLanguage {
    fn id(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::PowerShell => "powershell",
            Self::Php => "php",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Bash => "Bash",
            Self::PowerShell => "PowerShell",
            Self::Php => "PHP",
        }
    }

    fn extensions(self) -> &'static [&'static str] {
        match self {
            Self::Bash => &["sh", "bash"],
            Self::PowerShell => &["ps1", "psm1", "psd1"],
            Self::Php => &["php", "phtml"],
        }
    }
}

pub struct BashAdapter;
pub struct PowerShellAdapter;
pub struct PhpAdapter;

macro_rules! impl_adapter {
    ($adapter:ty, $language:expr) => {
        impl LanguageAdapter for $adapter {
            fn id(&self) -> &'static str {
                $language.id()
            }

            fn detect(&self, repo: &Path) -> Option<LanguageDetection> {
                detect($language, repo)
            }

            fn inventory_symbols(&self, repo: &Path) -> Result<Vec<SymbolId>, String> {
                inventory_symbols($language, repo)
            }

            fn run_parse_check(
                &self,
                repo: &Path,
                execution: &dyn ExecutionAdapter,
            ) -> CheckResult {
                run_parse($language, repo, execution, "parse")
            }

            fn run_format_check(
                &self,
                repo: &Path,
                _execution: &dyn ExecutionAdapter,
            ) -> CheckResult {
                whitespace_format_check($language, repo, "format")
            }

            fn run_targeted_tests(
                &self,
                repo: &Path,
                execution: &dyn ExecutionAdapter,
                scope: &ImpactScope,
            ) -> CheckResult {
                run_targeted_tests($language, repo, execution, scope)
            }

            fn run_integration_tests(
                &self,
                repo: &Path,
                execution: &dyn ExecutionAdapter,
                _scope: &ImpactScope,
            ) -> CheckResult {
                run_named_test_surface($language, repo, execution, "integration")
            }

            fn run_property_tests(
                &self,
                repo: &Path,
                execution: &dyn ExecutionAdapter,
                _scope: &ImpactScope,
            ) -> CheckResult {
                run_named_test_surface($language, repo, execution, "property")
            }

            fn run_ui_verification(
                &self,
                repo: &Path,
                execution: &dyn ExecutionAdapter,
                _scope: &ImpactScope,
            ) -> CheckResult {
                run_surface_verification($language, repo, execution, "ui", has_ui_surface(repo))
            }

            fn run_api_verification(
                &self,
                repo: &Path,
                execution: &dyn ExecutionAdapter,
                _scope: &ImpactScope,
            ) -> CheckResult {
                run_surface_verification($language, repo, execution, "api", has_api_surface(repo))
            }

            fn run_check(
                &self,
                check: CheckKind,
                repo: &Path,
                execution: &dyn ExecutionAdapter,
            ) -> CheckResult {
                run_check($language, check, repo, execution)
            }
        }
    };
}

impl_adapter!(BashAdapter, ScriptLanguage::Bash);
impl_adapter!(PowerShellAdapter, ScriptLanguage::PowerShell);
impl_adapter!(PhpAdapter, ScriptLanguage::Php);

fn detect(language: ScriptLanguage, repo: &Path) -> Option<LanguageDetection> {
    let sources = source_files(language, repo);
    if sources.is_empty() {
        return None;
    }
    let manifest = match language {
        ScriptLanguage::Bash => repo.join(".shellcheckrc").is_file(),
        ScriptLanguage::PowerShell => sources.iter().any(|path| {
            path.extension()
                .and_then(|value| value.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("psd1"))
        }),
        ScriptLanguage::Php => repo.join("composer.json").is_file(),
    };
    Some(LanguageDetection {
        adapter_id: language.id().into(),
        language: language.name().into(),
        confidence_percent: if manifest { 100 } else { 90 },
    })
}

fn inventory_symbols(language: ScriptLanguage, repo: &Path) -> Result<Vec<SymbolId>, String> {
    let mut symbols = Vec::new();
    for path in source_files(language, repo) {
        let relative = display_relative(repo, &path);
        symbols.push(SymbolId(format!("{}:file:{relative}", language.id())));
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        for line in content.lines() {
            let trimmed = line.trim();
            match language {
                ScriptLanguage::Bash => {
                    if let Some(name) = bash_function_name(trimmed) {
                        symbols.push(SymbolId(format!(
                            "{}:function:{relative}:{name}",
                            language.id()
                        )));
                    }
                }
                ScriptLanguage::PowerShell => {
                    if let Some(rest) = trimmed
                        .strip_prefix("function ")
                        .or_else(|| trimmed.strip_prefix("Function "))
                    {
                        let name = identifier(rest);
                        if !name.is_empty() {
                            symbols.push(SymbolId(format!(
                                "{}:function:{relative}:{name}",
                                language.id()
                            )));
                        }
                    }
                }
                ScriptLanguage::Php => {
                    for (prefix, kind) in [("function ", "function"), ("class ", "class")] {
                        if let Some(rest) = trimmed.strip_prefix(prefix) {
                            let name = identifier(rest.trim_start_matches('&'));
                            if !name.is_empty() {
                                symbols.push(SymbolId(format!(
                                    "{}:{kind}:{relative}:{name}",
                                    language.id()
                                )));
                            }
                        }
                    }
                }
            }
        }
    }
    symbols.sort();
    symbols.dedup();
    Ok(symbols)
}

fn bash_function_name(line: &str) -> Option<String> {
    if let Some(rest) = line.strip_prefix("function ") {
        let name = identifier(rest);
        return (!name.is_empty()).then_some(name);
    }
    let before = line.split_once("()")?.0.trim();
    let name = identifier(before);
    (!name.is_empty()).then_some(name)
}

fn run_check(
    language: ScriptLanguage,
    check: CheckKind,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
) -> CheckResult {
    match check {
        CheckKind::Build | CheckKind::TypeCheck => rename_check(
            run_parse(language, repo, execution, check.as_str()),
            format!("{}:{}", language.id(), check.as_str()),
        ),
        CheckKind::Lint => run_lint(language, repo, execution),
        CheckKind::Test => run_tests(language, repo, execution),
        CheckKind::Dependencies => run_dependencies(language, repo, execution),
        CheckKind::Security => run_security(language, repo, execution),
        CheckKind::Placeholders => scan_authenticity(language, repo),
        CheckKind::Concurrency => {
            if has_concurrency_surface(language, repo) {
                required_harness(language, repo, execution, check.as_str())
            } else {
                CheckResult::skipped(
                    format!("{}:{}", language.id(), check.as_str()),
                    "no script-family concurrency surface detected",
                )
            }
        }
        CheckKind::Ui => {
            if has_ui_surface(repo) {
                required_harness(language, repo, execution, check.as_str())
            } else {
                CheckResult::skipped(
                    format!("{}:{}", language.id(), check.as_str()),
                    "no script-family UI surface detected",
                )
            }
        }
        CheckKind::Coverage
        | CheckKind::Mutation
        | CheckKind::Fuzz
        | CheckKind::Contracts
        | CheckKind::Stress
        | CheckKind::FaultInjection
        | CheckKind::FormalProof => required_harness(language, repo, execution, check.as_str()),
    }
}

fn run_parse(
    language: ScriptLanguage,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: &str,
) -> CheckResult {
    match language {
        ScriptLanguage::Bash => run_bash_parse(repo, execution, check_name),
        ScriptLanguage::PowerShell => run_powershell_parse(repo, execution, check_name),
        ScriptLanguage::Php => run_php_parse(repo, execution, check_name),
    }
}

fn run_bash_parse(
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: &str,
) -> CheckResult {
    if !executable_available(execution, repo, "bash") {
        return tool_missing(ScriptLanguage::Bash, check_name, "bash");
    }
    run_per_file(
        ScriptLanguage::Bash,
        repo,
        execution,
        check_name,
        "bash",
        |relative| vec!["-n".into(), relative.into()],
    )
}

fn run_powershell_parse(
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: &str,
) -> CheckResult {
    if !executable_available(execution, repo, "pwsh") {
        return tool_missing(ScriptLanguage::PowerShell, check_name, "pwsh");
    }
    let files = source_files(ScriptLanguage::PowerShell, repo);
    if files.is_empty() {
        return CheckResult::unsupported("powershell:parse", "no PowerShell sources found");
    }
    for path in &files {
        let relative = display_relative(repo, path);
        let quoted = relative.replace(''', "''");
        let script = format!(
            "$tokens=$null; $errors=$null; [System.Management.Automation.Language.Parser]::ParseFile('{quoted}', [ref]$tokens, [ref]$errors) > $null; if ($errors.Count -gt 0) {{ $errors | ForEach-Object {{ Write-Error $_.Message }}; exit 1 }}"
        );
        let args = vec![
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-Command".into(),
            script,
        ];
        match execution.execute("pwsh", &args, repo) {
            Ok(output) if output.success() => {}
            Ok(output) => {
                return command_failed(
                    ScriptLanguage::PowerShell,
                    check_name,
                    "pwsh parser",
                    &relative,
                    &output,
                );
            }
            Err(error) => {
                return execution_failed(ScriptLanguage::PowerShell, check_name, error);
            }
        }
    }
    CheckResult::pass_with_evidence(
        format!("powershell:{check_name}"),
        format!("PowerShell AST parser accepted files={}", files.len()),
    )
}

fn run_php_parse(
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: &str,
) -> CheckResult {
    if !executable_available(execution, repo, "php") {
        return tool_missing(ScriptLanguage::Php, check_name, "php");
    }
    run_per_file(
        ScriptLanguage::Php,
        repo,
        execution,
        check_name,
        "php",
        |relative| vec!["-l".into(), relative.into()],
    )
}

fn run_lint(
    language: ScriptLanguage,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
) -> CheckResult {
    match language {
        ScriptLanguage::Bash => {
            if !executable_available(execution, repo, "shellcheck") {
                return tool_missing(language, "lint", "shellcheck");
            }
            let files = source_files(language, repo);
            let args = files
                .iter()
                .map(|path| display_relative(repo, path))
                .collect::<Vec<_>>();
            run_named(language, repo, execution, "lint", "shellcheck", args)
        }
        ScriptLanguage::PowerShell => {
            if !executable_available(execution, repo, "pwsh") {
                return tool_missing(language, "lint", "pwsh");
            }
            let files = source_files(language, repo);
            let paths = files
                .iter()
                .map(|path| format!("'{}'", display_relative(repo, path).replace('\'', "''")))
                .collect::<Vec<_>>()
                .join(",");
            let script = format!(
                "Import-Module PSScriptAnalyzer -ErrorAction Stop; $findings=@({paths} | ForEach-Object {{ Invoke-ScriptAnalyzer -Path $_ -Severity Warning,Error }}); if ($findings.Count -gt 0) {{ $findings | Format-Table | Out-String | Write-Error; exit 1 }}"
            );
            run_named(
                language,
                repo,
                execution,
                "lint",
                "pwsh",
                vec![
                    "-NoProfile".into(),
                    "-NonInteractive".into(),
                    "-Command".into(),
                    script,
                ],
            )
        }
        ScriptLanguage::Php => {
            let parsed = run_php_parse(repo, execution, "lint");
            if parsed.status != CheckStatus::Pass {
                return parsed;
            }
            let formatted = whitespace_format_check(language, repo, "lint-format");
            if formatted.status != CheckStatus::Pass {
                return rename_check(formatted, "php:lint".into());
            }
            CheckResult::pass_with_evidence(
                "php:lint",
                "PHP lint completed with php -l over every source plus deterministic whitespace policy",
            )
        }
    }
}

fn run_tests(
    language: ScriptLanguage,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
) -> CheckResult {
    let tests = test_files(language, repo);
    if tests.is_empty() {
        return CheckResult::unsupported(
            format!("{}:test", language.id()),
            format!("no {} test scripts were found", language.name()),
        );
    }
    let program = match language {
        ScriptLanguage::Bash => "bash",
        ScriptLanguage::PowerShell => "pwsh",
        ScriptLanguage::Php => "php",
    };
    if !executable_available(execution, repo, program) {
        return tool_missing(language, "test", program);
    }
    for path in &tests {
        let relative = display_relative(repo, path);
        let args = match language {
            ScriptLanguage::PowerShell => vec![
                "-NoProfile".into(),
                "-NonInteractive".into(),
                "-File".into(),
                relative.clone(),
            ],
            _ => vec![relative.clone()],
        };
        match execution.execute(program, &args, repo) {
            Ok(output) if output.success() => {}
            Ok(output) => {
                return command_failed(language, "test", program, &relative, &output);
            }
            Err(error) => return execution_failed(language, "test", error),
        }
    }
    CheckResult::pass_with_evidence(
        format!("{}:test", language.id()),
        format!("native {} executable tests passed files={}", language.name(), tests.len()),
    )
}

fn run_targeted_tests(
    language: ScriptLanguage,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    scope: &ImpactScope,
) -> CheckResult {
    let affected = scope.requires_full_verification
        || scope.changed_paths.iter().any(|path| {
            Path::new(path)
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|extension| {
                    language
                        .extensions()
                        .iter()
                        .any(|candidate| extension.eq_ignore_ascii_case(candidate))
                })
        });
    if !affected {
        return CheckResult::skipped(
            format!("{}:targeted-test", language.id()),
            "no changed path maps to this script adapter",
        );
    }
    if test_files(language, repo).is_empty() {
        return CheckResult::skipped(
            format!("{}:targeted-test", language.id()),
            "affected script source has no native test files",
        );
    }
    rename_check(
        run_tests(language, repo, execution),
        format!("{}:targeted-test", language.id()),
    )
}

fn run_named_test_surface(
    language: ScriptLanguage,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    surface: &str,
) -> CheckResult {
    if test_files(language, repo).iter().any(|path| {
        display_relative(repo, path)
            .to_ascii_lowercase()
            .contains(surface)
    }) {
        return rename_check(
            run_tests(language, repo, execution),
            format!("{}:checkpoint-{surface}", language.id()),
        );
    }
    CheckResult::skipped(
        format!("{}:checkpoint-{surface}", language.id()),
        format!("no {} {surface}-test surface detected", language.name()),
    )
}

fn run_dependencies(
    language: ScriptLanguage,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
) -> CheckResult {
    if language == ScriptLanguage::Php && repo.join("composer.json").is_file() {
        if !executable_available(execution, repo, "composer") {
            return tool_missing(language, "dependencies", "composer");
        }
        return run_named(
            language,
            repo,
            execution,
            "dependencies",
            "composer",
            vec!["validate".into(), "--no-check-publish".into(), "--strict".into()],
        );
    }
    let markers = match language {
        ScriptLanguage::Bash => &["source ", ". "][..],
        ScriptLanguage::PowerShell => &["Import-Module ", "#requires -Modules "][..],
        ScriptLanguage::Php => &["require ", "require_once ", "include ", "include_once "][..],
    };
    let count = count_markers(language, repo, markers);
    CheckResult::pass_with_evidence(
        format!("{}:dependencies", language.id()),
        format!(
            "native {} dependency-surface inventory completed declarations={count}",
            language.name()
        ),
    )
}

fn run_security(
    language: ScriptLanguage,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
) -> CheckResult {
    match language {
        ScriptLanguage::Bash => {
            if executable_available(execution, repo, "shellcheck") {
                let files = source_files(language, repo);
                let mut args = vec!["--severity=warning".into()];
                args.extend(files.iter().map(|path| display_relative(repo, path)));
                run_named(language, repo, execution, "security", "shellcheck", args)
            } else {
                required_harness(language, repo, execution, "security")
            }
        }
        ScriptLanguage::PowerShell => {
            if executable_available(execution, repo, "pwsh") {
                rename_check(run_lint(language, repo, execution), "powershell:security".into())
            } else {
                required_harness(language, repo, execution, "security")
            }
        }
        ScriptLanguage::Php => {
            if repo.join("composer.lock").is_file()
                && executable_available(execution, repo, "composer")
            {
                run_named(
                    language,
                    repo,
                    execution,
                    "security",
                    "composer",
                    vec!["audit".into(), "--locked".into()],
                )
            } else {
                required_harness(language, repo, execution, "security")
            }
        }
    }
}

fn scan_authenticity(language: ScriptLanguage, repo: &Path) -> CheckResult {
    let mut findings = Vec::new();
    let mut scanned = 0usize;
    for path in source_files(language, repo) {
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
            let placeholder = lower.contains(&["to", "do:"].concat())
                || lower.contains(&["fix", "me:"].concat())
                || lower.contains(&["x", "xx:"].concat())
                || lower.contains("notimplemented")
                || lower.contains("placeholder implementation")
                || lower.contains("stub implementation");
            let auth_context = lower.contains("auth")
                || lower.contains("permission")
                || lower.contains("authorize")
                || lower.contains("access");
            let constant_allow = auth_context
                && match language {
                    ScriptLanguage::Bash => lower.contains("return 0") || lower.contains("echo true"),
                    ScriptLanguage::PowerShell => lower.contains("return $true"),
                    ScriptLanguage::Php => lower.contains("return true"),
                };
            if placeholder || constant_allow {
                findings.push(Finding {
                    code: if placeholder {
                        "VF_PLACEHOLDER".into()
                    } else {
                        "VF_FAKE_AUTHORIZATION".into()
                    },
                    message: format!(
                        "{}:{} contains a high-confidence unfinished/fake implementation pattern",
                        display_relative(repo, &path),
                        index + 1
                    ),
                    blocking: true,
                });
            }
        }
    }
    if findings.is_empty() {
        CheckResult::pass_with_evidence(
            format!("{}:placeholders", language.id()),
            format!(
                "native {} authenticity scan files={scanned} findings=0",
                language.name()
            ),
        )
    } else {
        CheckResult {
            check: format!("{}:placeholders", language.id()),
            status: CheckStatus::Fail,
            findings,
        }
    }
}

fn whitespace_format_check(
    language: ScriptLanguage,
    repo: &Path,
    check_name: &str,
) -> CheckResult {
    let mut checked = 0usize;
    for path in source_files(language, repo) {
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        checked += 1;
        for (index, line) in content.lines().enumerate() {
            if line.ends_with(' ') || line.ends_with('\t') {
                return CheckResult::fail(
                    format!("{}:{check_name}", language.id()),
                    "VF_SCRIPT_FORMAT",
                    format!(
                        "{}:{} contains trailing whitespace",
                        display_relative(repo, &path),
                        index + 1
                    ),
                );
            }
        }
        if !content.is_empty() && !content.ends_with('\n') {
            return CheckResult::fail(
                format!("{}:{check_name}", language.id()),
                "VF_SCRIPT_FORMAT",
                format!("{} must end with a newline", display_relative(repo, &path)),
            );
        }
    }
    CheckResult::pass_with_evidence(
        format!("{}:{check_name}", language.id()),
        format!(
            "deterministic {} whitespace format policy accepted files={checked}",
            language.name()
        ),
    )
}

fn run_per_file<F>(
    language: ScriptLanguage,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: &str,
    program: &str,
    args_for: F,
) -> CheckResult
where
    F: Fn(&str) -> Vec<String>,
{
    let files = source_files(language, repo);
    if files.is_empty() {
        return CheckResult::unsupported(
            format!("{}:{check_name}", language.id()),
            format!("no {} source files found", language.name()),
        );
    }
    for path in &files {
        let relative = display_relative(repo, path);
        let args = args_for(&relative);
        match execution.execute(program, &args, repo) {
            Ok(output) if output.success() => {}
            Ok(output) => {
                return command_failed(language, check_name, program, &relative, &output);
            }
            Err(error) => return execution_failed(language, check_name, error),
        }
    }
    CheckResult::pass_with_evidence(
        format!("{}:{check_name}", language.id()),
        format!(
            "native {} command={program} accepted files={}",
            language.name(),
            files.len()
        ),
    )
}

fn run_named(
    language: ScriptLanguage,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: &str,
    program: &str,
    args: Vec<String>,
) -> CheckResult {
    match execution.execute(program, &args, repo) {
        Ok(output) if output.success() => CheckResult::pass_with_evidence(
            format!("{}:{check_name}", language.id()),
            format!("command={} {} exit=0", program, args.join(" ")),
        ),
        Ok(output) => command_failed(language, check_name, program, "repository", &output),
        Err(error) => execution_failed(language, check_name, error),
    }
}

fn required_harness(
    language: ScriptLanguage,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: &str,
) -> CheckResult {
    run_repository_harness(
        repo,
        execution,
        format!("{}:{check_name}", language.id()),
        &format!("{}-{check_name}", language.id()),
    )
    .unwrap_or_else(|| {
        CheckResult::unsupported(
            format!("{}:{check_name}", language.id()),
            format!(
                "{} native adapter requires .verificationforge/{}-{check_name}.argv for this verification surface",
                language.name(),
                language.id()
            ),
        )
    })
}

fn run_surface_verification(
    language: ScriptLanguage,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    surface: &str,
    applicable: bool,
) -> CheckResult {
    if !applicable {
        return CheckResult::skipped(
            format!("{}:checkpoint-{surface}", language.id()),
            format!("no {} {surface} surface detected", language.name()),
        );
    }
    required_harness(language, repo, execution, &format!("checkpoint-{surface}"))
}

fn has_ui_surface(repo: &Path) -> bool {
    repository_contains(repo, &["System.Windows.Forms", "PresentationFramework", "dialog", "zenity"])
}

fn has_api_surface(repo: &Path) -> bool {
    repository_contains(
        repo,
        &[
            "http://",
            "https://",
            "Invoke-RestMethod",
            "Invoke-WebRequest",
            "curl ",
            "$_SERVER",
            "header(",
        ],
    )
}

fn has_concurrency_surface(language: ScriptLanguage, repo: &Path) -> bool {
    let markers = match language {
        ScriptLanguage::Bash => &["&", "wait ", "coproc "][..],
        ScriptLanguage::PowerShell => &["Start-Job", "ForEach-Object -Parallel", "Start-ThreadJob"][..],
        ScriptLanguage::Php => &["pcntl_fork", "parallel\\", "Fiber("][..],
    };
    repository_contains(repo, markers)
}

fn count_markers(language: ScriptLanguage, repo: &Path, markers: &[&str]) -> usize {
    source_files(language, repo)
        .into_iter()
        .filter_map(|path| fs::read_to_string(path).ok())
        .map(|content| {
            content
                .lines()
                .filter(|line| markers.iter().any(|marker| line.trim_start().starts_with(marker)))
                .count()
        })
        .sum()
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
            .ok()
            .is_some_and(|content| markers.iter().any(|marker| content.contains(marker)))
    })
}

fn executable_available(execution: &dyn ExecutionAdapter, repo: &Path, program: &str) -> bool {
    let args = match program {
        "bash" => vec!["--version".into()],
        "pwsh" => vec!["-NoProfile".into(), "-Command".into(), "$PSVersionTable.PSVersion.ToString()".into()],
        "php" => vec!["--version".into()],
        "shellcheck" => vec!["--version".into()],
        "composer" => vec!["--version".into()],
        _ => vec!["--version".into()],
    };
    execution
        .execute(program, &args, repo)
        .map(|result| result.success())
        .unwrap_or(false)
}

fn tool_missing(language: ScriptLanguage, check_name: &str, tool: &str) -> CheckResult {
    CheckResult::fail(
        format!("{}:{check_name}", language.id()),
        "VF_SCRIPT_TOOLCHAIN_MISSING",
        format!(
            "{} repository detected but required native tool {tool} is not executable",
            language.name()
        ),
    )
}

fn command_failed(
    language: ScriptLanguage,
    check_name: &str,
    command: &str,
    subject: &str,
    output: &verificationforge_core::ExecutionResult,
) -> CheckResult {
    CheckResult::fail(
        format!("{}:{check_name}", language.id()),
        "VF_SCRIPT_CHECK_FAILED",
        format!(
            "{command} failed subject={subject} exit={} stderr={} stdout={}",
            output.exit_code,
            sanitize_output(&output.stderr),
            sanitize_output(&output.stdout)
        ),
    )
}

fn execution_failed(language: ScriptLanguage, check_name: &str, error: String) -> CheckResult {
    CheckResult::fail(
        format!("{}:{check_name}", language.id()),
        "VF_SCRIPT_EXECUTION_FAILED",
        error,
    )
}

fn rename_check(mut result: CheckResult, name: String) -> CheckResult {
    result.check = name;
    result
}

fn source_files(language: ScriptLanguage, repo: &Path) -> Vec<PathBuf> {
    repository_files(repo)
        .into_iter()
        .filter(|path| {
            path.extension()
                .and_then(|value| value.to_str())
                .is_some_and(|extension| {
                    language
                        .extensions()
                        .iter()
                        .any(|candidate| extension.eq_ignore_ascii_case(candidate))
                })
        })
        .collect()
}

fn test_files(language: ScriptLanguage, repo: &Path) -> Vec<PathBuf> {
    source_files(language, repo)
        .into_iter()
        .filter(|path| is_test_source(path))
        .collect()
}

fn is_test_source(path: &Path) -> bool {
    let relative = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    relative.contains("/test/")
        || relative.contains("/tests/")
        || name.contains("test.")
        || name.starts_with("test_")
        || name.contains("_test.")
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
                ".git"
                    | "target"
                    | "node_modules"
                    | "vendor"
                    | ".venv"
                    | "venv"
                    | "dist"
                    | "build"
                    | ".idea"
                    | ".vscode"
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

fn identifier(value: &str) -> String {
    value
        .chars()
        .take_while(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
        .collect()
}

fn sanitize_output(value: &str) -> String {
    value.replace(['\r', '\n'], " ").trim().to_owned()
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
        std::env::temp_dir().join(format!("verificationforge-script-family-{name}-{nonce}"))
    }

    #[test]
    fn detects_each_script_language_independently() {
        let root = temp_dir("detect");
        fs::create_dir_all(&root).expect("create root");
        fs::write(root.join("a.sh"), "#!/usr/bin/env bash\necho ok\n").expect("write bash");
        fs::write(root.join("b.ps1"), "Write-Output 'ok'\n").expect("write ps");
        fs::write(root.join("c.php"), "<?php echo 'ok';\n").expect("write php");
        assert_eq!(BashAdapter.detect(&root).expect("bash").language, "Bash");
        assert_eq!(
            PowerShellAdapter.detect(&root).expect("powershell").language,
            "PowerShell"
        );
        assert_eq!(PhpAdapter.detect(&root).expect("php").language, "PHP");
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn native_parse_checks_emit_reproducible_evidence() {
        let root = temp_dir("parse");
        fs::create_dir_all(&root).expect("create root");
        fs::write(root.join("a.sh"), "echo ok\n").expect("write bash");
        let execution = RecordingExecution::default();
        let result = BashAdapter.run_parse_check(&root, &execution);
        assert_eq!(result.status, CheckStatus::Pass);
        assert!(result.has_reproducible_evidence());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn constant_authorization_shortcuts_are_blocked() {
        let root = temp_dir("fake-auth");
        fs::create_dir_all(&root).expect("create root");
        fs::write(
            root.join("auth.php"),
            "<?php\nfunction authorizeUser(): bool { return true; }\n",
        )
        .expect("write php");
        let result = PhpAdapter.run_check(CheckKind::Placeholders, &root, &RecordingExecution::default());
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.code == "VF_FAKE_AUTHORIZATION")
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn advanced_checks_fail_closed_without_harness() {
        let root = temp_dir("advanced");
        fs::create_dir_all(&root).expect("create root");
        fs::write(root.join("a.ps1"), "Write-Output 'ok'\n").expect("write ps");
        let result = PowerShellAdapter.run_check(
            CheckKind::Mutation,
            &root,
            &RecordingExecution::default(),
        );
        assert_eq!(result.status, CheckStatus::Unsupported);
        fs::remove_dir_all(root).ok();
    }
}
