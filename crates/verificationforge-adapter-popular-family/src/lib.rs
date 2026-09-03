use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;

use verificationforge_core::{
    CheckKind, CheckResult, CheckStatus, ExecutionAdapter, Finding, ImpactScope, LanguageAdapter,
    LanguageDetection, SymbolId, run_repository_harness,
};

const MAX_SCAN_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug)]
pub struct LanguageSpec {
    pub id: &'static str,
    pub language: &'static str,
    pub extensions: &'static [&'static str],
    pub manifests: &'static [&'static str],
}

#[derive(Clone, Copy)]
pub struct PopularLanguageAdapter {
    spec: &'static LanguageSpec,
}

impl PopularLanguageAdapter {
    pub const fn new(spec: &'static LanguageSpec) -> Self {
        Self { spec }
    }
}

impl LanguageAdapter for PopularLanguageAdapter {
    fn id(&self) -> &'static str {
        self.spec.id
    }

    fn detect(&self, repo: &Path) -> Option<LanguageDetection> {
        let files = repository_files(repo);
        if !files.iter().any(|path| source_matches(self.spec, path)) {
            return None;
        }
        let manifest = files.iter().any(|path| {
            path.file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|name| self.spec.manifests.contains(&name))
        });
        Some(LanguageDetection {
            adapter_id: self.spec.id.into(),
            language: self.spec.language.into(),
            confidence_percent: if manifest { 98 } else { 88 },
        })
    }

    fn inventory_symbols(&self, repo: &Path) -> Result<Vec<SymbolId>, String> {
        let mut symbols = source_files(self.spec, repo)
            .into_iter()
            .filter_map(|path| {
                path.strip_prefix(repo)
                    .ok()
                    .map(|relative| relative.to_string_lossy().replace('\\', "/"))
            })
            .map(|relative| SymbolId(format!("{}:file:{relative}", self.spec.id)))
            .collect::<Vec<_>>();
        symbols.sort();
        symbols.dedup();
        Ok(symbols)
    }

    fn run_parse_check(&self, repo: &Path, execution: &dyn ExecutionAdapter) -> CheckResult {
        run_native_validation(self.spec, repo, execution, "parse")
    }

    fn run_format_check(&self, repo: &Path, _execution: &dyn ExecutionAdapter) -> CheckResult {
        deterministic_format_check(self.spec, repo)
    }

    fn run_targeted_tests(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        scope: &ImpactScope,
    ) -> CheckResult {
        let affected = scope
            .changed_paths
            .iter()
            .any(|path| source_matches(self.spec, Path::new(path)));
        if !affected && !scope.requires_full_verification {
            return CheckResult::skipped(
                format!("{}:targeted-test", self.spec.id),
                "no changed path maps to this language adapter",
            );
        }
        rename_check(
            run_native_tests(self.spec, repo, execution),
            format!("{}:targeted-test", self.spec.id),
        )
    }

    fn run_integration_tests(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        _scope: &ImpactScope,
    ) -> CheckResult {
        if has_named_test(self.spec, repo, "integration") {
            rename_check(
                run_native_tests(self.spec, repo, execution),
                format!("{}:checkpoint-integration", self.spec.id),
            )
        } else {
            CheckResult::skipped(
                format!("{}:checkpoint-integration", self.spec.id),
                "no integration-test surface detected",
            )
        }
    }

    fn run_property_tests(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        _scope: &ImpactScope,
    ) -> CheckResult {
        if has_named_test(self.spec, repo, "property") {
            rename_check(
                run_native_tests(self.spec, repo, execution),
                format!("{}:checkpoint-property", self.spec.id),
            )
        } else {
            CheckResult::skipped(
                format!("{}:checkpoint-property", self.spec.id),
                "no property-test surface detected",
            )
        }
    }

    fn run_ui_verification(
        &self,
        _repo: &Path,
        _execution: &dyn ExecutionAdapter,
        _scope: &ImpactScope,
    ) -> CheckResult {
        CheckResult::skipped(
            format!("{}:checkpoint-ui", self.spec.id),
            "language-level adapter exposes no framework-specific UI surface",
        )
    }

    fn run_api_verification(
        &self,
        _repo: &Path,
        _execution: &dyn ExecutionAdapter,
        _scope: &ImpactScope,
    ) -> CheckResult {
        CheckResult::skipped(
            format!("{}:checkpoint-api", self.spec.id),
            "language-level adapter exposes no framework-specific API contract surface",
        )
    }

    fn run_check(
        &self,
        check: CheckKind,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
    ) -> CheckResult {
        match check {
            CheckKind::Build | CheckKind::TypeCheck | CheckKind::Lint => {
                run_native_validation(self.spec, repo, execution, check.as_str())
            }
            CheckKind::Test => run_native_tests(self.spec, repo, execution),
            CheckKind::Dependencies => dependency_inventory(self.spec, repo),
            CheckKind::Placeholders => authenticity_scan(self.spec, repo, check.as_str()),
            CheckKind::Security
            | CheckKind::Coverage
            | CheckKind::Mutation
            | CheckKind::Fuzz
            | CheckKind::Contracts
            | CheckKind::Stress
            | CheckKind::FaultInjection
            | CheckKind::FormalProof => required_harness(self.spec, repo, execution, check.as_str()),
            CheckKind::Concurrency => {
                if repository_contains(
                    self.spec,
                    repo,
                    &[
                        "thread", "mutex", "lock", "atomic", "async", "await", "spawn", "channel",
                        "process",
                    ],
                ) {
                    required_harness(self.spec, repo, execution, check.as_str())
                } else {
                    CheckResult::skipped(
                        format!("{}:concurrency", self.spec.id),
                        "no concurrency markers detected",
                    )
                }
            }
            CheckKind::Ui => CheckResult::skipped(
                format!("{}:ui", self.spec.id),
                "language-level adapter exposes no native UI surface",
            ),
        }
    }
}

pub fn popular_language_adapters() -> Vec<Arc<dyn LanguageAdapter>> {
    SPECS
        .iter()
        .map(|spec| Arc::new(PopularLanguageAdapter::new(spec)) as Arc<dyn LanguageAdapter>)
        .collect()
}

pub fn is_popular_native_language_id(id: &str) -> bool {
    SPECS.iter().any(|spec| spec.id == id)
}

fn run_native_validation(
    spec: &LanguageSpec,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: &str,
) -> CheckResult {
    match spec.id {
        "hcl" => run_repo_command(
            spec,
            repo,
            execution,
            check_name,
            "terraform",
            &["validate", "-no-color"],
        ),
        "visual-basic" => run_repo_command(
            spec,
            repo,
            execution,
            check_name,
            "dotnet",
            &["build", "-nologo", "-v:q"],
        ),
        "gleam" => run_repo_command(spec, repo, execution, check_name, "gleam", &["check"]),
        _ => run_each_source(spec, repo, execution, check_name),
    }
}

fn run_each_source(
    spec: &LanguageSpec,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: &str,
) -> CheckResult {
    let files = source_files(spec, repo);
    if files.is_empty() {
        return CheckResult::unsupported(
            format!("{}:{check_name}", spec.id),
            "no source files were found",
        );
    }

    let temp = temp_output_dir(spec.id);
    if let Err(error) = fs::create_dir_all(&temp) {
        return CheckResult::fail(
            format!("{}:{check_name}", spec.id),
            "VF_NATIVE_TEMP_FAILED",
            format!("cannot create native-toolchain temp directory: {error}"),
        );
    }

    let mut checked = 0usize;
    for (index, path) in files.iter().enumerate() {
        let relative = display_relative(repo, path);
        let Some((program, args)) = validation_command(spec, path, &relative, &temp, index) else {
            continue;
        };
        let result = execute(spec, execution, repo, check_name, program, &args);
        if result.status != CheckStatus::Pass {
            return result;
        }
        checked += 1;
    }

    if checked == 0 {
        CheckResult::unsupported(
            format!("{}:{check_name}", spec.id),
            "detected sources do not map to a supported native command",
        )
    } else {
        CheckResult::pass_with_evidence(
            format!("{}:{check_name}", spec.id),
            format!(
                "native toolchain verified language={} files={checked}",
                spec.language
            ),
        )
    }
}

fn validation_command(
    spec: &LanguageSpec,
    path: &Path,
    relative: &str,
    temp: &Path,
    index: usize,
) -> Option<(&'static str, Vec<String>)> {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let object = temp.join(format!("unit-{index}.o"));
    let q_single = expression_single_quote(relative);
    let q_double = expression_double_quote(relative);

    Some(match spec.id {
        "swift" => ("swiftc", vec!["-typecheck".into(), relative.into()]),
        "objective-c" => (
            "clang",
            vec![
                "-fsyntax-only".into(),
                "-Wall".into(),
                "-Wextra".into(),
                "-Werror".into(),
                "-x".into(),
                "objective-c".into(),
                relative.into(),
            ],
        ),
        "dart" => ("dart", vec!["analyze".into(), relative.into()]),
        "ruby" => ("ruby", vec!["-c".into(), relative.into()]),
        "lua" => ("luac", vec!["-p".into(), relative.into()]),
        "perl" => ("perl", vec!["-c".into(), relative.into()]),
        "r" => (
            "Rscript",
            vec![
                "--vanilla".into(),
                "-e".into(),
                format!("parse(file='{q_single}')"),
            ],
        ),
        "julia" => (
            "julia",
            vec![
                "--startup-file=no".into(),
                "--history-file=no".into(),
                "-e".into(),
                format!("Meta.parseall(read(\"{q_double}\", String))"),
            ],
        ),
        "haskell" => (
            "ghc",
            vec!["-fno-code".into(), "-fforce-recomp".into(), relative.into()],
        ),
        "ocaml" => (
            "ocamlc",
            vec!["-stop-after".into(), "parsing".into(), relative.into()],
        ),
        "fsharp" => (
            "dotnet",
            vec!["fsi".into(), "--nologo".into(), "--exec".into(), relative.into()],
        ),
        "elixir" => ("elixir", vec![relative.into()]),
        "erlang" if extension == "escript" => ("escript", vec![relative.into()]),
        "erlang" => (
            "erlc",
            vec!["-o".into(), temp.display().to_string(), relative.into()],
        ),
        "zig" => ("zig", vec!["test".into(), relative.into()]),
        "nim" => (
            "nim",
            vec![
                "check".into(),
                "--hints:off".into(),
                "--verbosity:0".into(),
                relative.into(),
            ],
        ),
        "d" => (
            "ldc2",
            vec!["-c".into(), format!("-of={}", object.display()), relative.into()],
        ),
        "fortran" => (
            "gfortran",
            vec!["-fsyntax-only".into(), "-Wall".into(), "-Wextra".into(), relative.into()],
        ),
        "cobol" => (
            "cobc",
            vec!["-fsyntax-only".into(), "-Wall".into(), relative.into()],
        ),
        "sql" => (
            "sqlfluff",
            vec!["parse".into(), "--dialect".into(), "ansi".into(), relative.into()],
        ),
        "groovy" => (
            "groovyc",
            vec!["-d".into(), temp.display().to_string(), relative.into()],
        ),
        "clojure" => ("clojure", vec![relative.into()]),
        "object-pascal" => (
            "fpc",
            vec![
                "-Cn".into(),
                "-S2".into(),
                format!("-FU{}", temp.display()),
                format!("-FE{}", temp.display()),
                relative.into(),
            ],
        ),
        "matlab" => (
            "octave",
            vec![
                "--no-gui".into(),
                "--quiet".into(),
                "--eval".into(),
                format!("source('{q_single}')"),
            ],
        ),
        "tcl" => ("tclsh", vec![relative.into()]),
        "nix" => ("nix-instantiate", vec!["--parse".into(), relative.into()]),
        "ada" => (
            "gnatmake",
            vec![
                "-q".into(),
                "-gnatc".into(),
                format!("-D{}", temp.display()),
                relative.into(),
            ],
        ),
        _ => return None,
    })
}

fn run_native_tests(
    spec: &LanguageSpec,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
) -> CheckResult {
    match spec.id {
        "gleam" => {
            return run_repo_command(spec, repo, execution, "test", "gleam", &["test"]);
        }
        "visual-basic" => {
            return CheckResult::skipped(
                format!("{}:test", spec.id),
                "no Visual Basic test project was inferred; dotnet build already verifies the project",
            );
        }
        "hcl" => {
            let has_tests = repository_files(repo).iter().any(|path| {
                path.file_name()
                    .and_then(|value| value.to_str())
                    .is_some_and(|name| name.ends_with(".tftest.hcl"))
            });
            if has_tests {
                return run_repo_command(
                    spec,
                    repo,
                    execution,
                    "test",
                    "terraform",
                    &["test", "-no-color"],
                );
            }
            return CheckResult::skipped(
                format!("{}:test", spec.id),
                "no Terraform .tftest.hcl files detected",
            );
        }
        _ => {}
    }

    let tests = test_files(spec, repo);
    if tests.is_empty() {
        return CheckResult::skipped(format!("{}:test", spec.id), "no native test files detected");
    }

    let temp = temp_output_dir(&format!("{}-tests", spec.id));
    if let Err(error) = fs::create_dir_all(&temp) {
        return CheckResult::fail(
            format!("{}:test", spec.id),
            "VF_NATIVE_TEMP_FAILED",
            format!("cannot create native-test temp directory: {error}"),
        );
    }

    for (index, path) in tests.iter().enumerate() {
        let relative = display_relative(repo, path);
        let result = run_test_file(spec, repo, execution, path, &relative, &temp, index);
        if result.status != CheckStatus::Pass {
            return result;
        }
    }

    CheckResult::pass_with_evidence(
        format!("{}:test", spec.id),
        format!("native tests executed language={} files={}", spec.language, tests.len()),
    )
}

fn run_test_file(
    spec: &LanguageSpec,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    path: &Path,
    relative: &str,
    temp: &Path,
    index: usize,
) -> CheckResult {
    let output = temp.join(format!("test-{index}"));
    let q_single = expression_single_quote(relative);

    match spec.id {
        "swift" => execute(spec, execution, repo, "test", "swift", &[relative.into()]),
        "objective-c" => compile_then_run(
            spec,
            repo,
            execution,
            "clang",
            &[
                "-Wall".into(),
                "-Wextra".into(),
                "-Werror".into(),
                "-x".into(),
                "objective-c".into(),
                relative.into(),
                "-o".into(),
                output.display().to_string(),
            ],
            &output,
        ),
        "dart" => execute(spec, execution, repo, "test", "dart", &[relative.into()]),
        "ruby" => execute(spec, execution, repo, "test", "ruby", &[relative.into()]),
        "lua" => execute(spec, execution, repo, "test", "lua", &[relative.into()]),
        "perl" => execute(spec, execution, repo, "test", "perl", &[relative.into()]),
        "r" => execute(
            spec,
            execution,
            repo,
            "test",
            "Rscript",
            &["--vanilla".into(), relative.into()],
        ),
        "julia" => execute(
            spec,
            execution,
            repo,
            "test",
            "julia",
            &["--startup-file=no".into(), "--history-file=no".into(), relative.into()],
        ),
        "haskell" => execute(spec, execution, repo, "test", "runghc", &[relative.into()]),
        "ocaml" => execute(spec, execution, repo, "test", "ocaml", &[relative.into()]),
        "fsharp" => execute(
            spec,
            execution,
            repo,
            "test",
            "dotnet",
            &["fsi".into(), "--nologo".into(), "--exec".into(), relative.into()],
        ),
        "elixir" => execute(spec, execution, repo, "test", "elixir", &[relative.into()]),
        "erlang" => {
            let extension = path.extension().and_then(|value| value.to_str()).unwrap_or_default();
            if extension.eq_ignore_ascii_case("escript") {
                execute(spec, execution, repo, "test", "escript", &[relative.into()])
            } else {
                execute(
                    spec,
                    execution,
                    repo,
                    "test",
                    "erlc",
                    &["-o".into(), temp.display().to_string(), relative.into()],
                )
            }
        }
        "zig" => execute(spec, execution, repo, "test", "zig", &["test".into(), relative.into()]),
        "nim" => execute(
            spec,
            execution,
            repo,
            "test",
            "nim",
            &[
                "r".into(),
                "--hints:off".into(),
                "--verbosity:0".into(),
                format!("--out:{}", output.display()),
                relative.into(),
            ],
        ),
        "d" => execute(spec, execution, repo, "test", "ldc2", &["-run".into(), relative.into()]),
        "fortran" => compile_then_run(
            spec,
            repo,
            execution,
            "gfortran",
            &[
                "-Wall".into(),
                "-Wextra".into(),
                relative.into(),
                "-o".into(),
                output.display().to_string(),
            ],
            &output,
        ),
        "cobol" => compile_then_run(
            spec,
            repo,
            execution,
            "cobc",
            &[
                "-x".into(),
                "-Wall".into(),
                "-o".into(),
                output.display().to_string(),
                relative.into(),
            ],
            &output,
        ),
        "sql" => execute(
            spec,
            execution,
            repo,
            "test",
            "sqlite3",
            &[":memory:".into(), format!(".read {relative}")],
        ),
        "groovy" => execute(spec, execution, repo, "test", "groovy", &[relative.into()]),
        "clojure" => execute(spec, execution, repo, "test", "clojure", &[relative.into()]),
        "object-pascal" => compile_then_run(
            spec,
            repo,
            execution,
            "fpc",
            &[
                "-S2".into(),
                format!("-FU{}", temp.display()),
                format!("-FE{}", temp.display()),
                format!("-o{}", output.display()),
                relative.into(),
            ],
            &output,
        ),
        "matlab" => execute(
            spec,
            execution,
            repo,
            "test",
            "octave",
            &[
                "--no-gui".into(),
                "--quiet".into(),
                "--eval".into(),
                format!("source('{q_single}')"),
            ],
        ),
        "tcl" => execute(spec, execution, repo, "test", "tclsh", &[relative.into()]),
        "nix" => execute(
            spec,
            execution,
            repo,
            "test",
            "nix-instantiate",
            &["--eval".into(), relative.into()],
        ),
        "ada" => compile_then_run(
            spec,
            repo,
            execution,
            "gnatmake",
            &[
                "-q".into(),
                format!("-D{}", temp.display()),
                format!("-o{}", output.display()),
                relative.into(),
            ],
            &output,
        ),
        _ => CheckResult::unsupported(
            format!("{}:test", spec.id),
            format!("no native test command is configured for {}", spec.language),
        ),
    }
}

fn compile_then_run(
    spec: &LanguageSpec,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    program: &str,
    args: &[String],
    output: &Path,
) -> CheckResult {
    let compiled = execute(spec, execution, repo, "test", program, args);
    if compiled.status != CheckStatus::Pass {
        return compiled;
    }
    execute(spec, execution, repo, "test", output.to_string_lossy().as_ref(), &[])
}

fn run_repo_command(
    spec: &LanguageSpec,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: &str,
    program: &str,
    args: &[&str],
) -> CheckResult {
    let args = args.iter().map(|value| (*value).to_owned()).collect::<Vec<_>>();
    execute(spec, execution, repo, check_name, program, &args)
}

fn execute(
    spec: &LanguageSpec,
    execution: &dyn ExecutionAdapter,
    repo: &Path,
    check_name: &str,
    program: &str,
    args: &[String],
) -> CheckResult {
    match execution.execute(program, args, repo) {
        Ok(output) if output.success() => CheckResult::pass_with_evidence(
            format!("{}:{check_name}", spec.id),
            format!("command={} {} exit=0", program, args.join(" ")),
        ),
        Ok(output) => CheckResult::fail(
            format!("{}:{check_name}", spec.id),
            "VF_NATIVE_TOOLCHAIN_FAILED",
            format!(
                "{} {} exited with code {}: {}",
                program,
                args.join(" "),
                output.exit_code,
                command_detail(&output.stdout, &output.stderr)
            ),
        ),
        Err(error) => CheckResult::fail(
            format!("{}:{check_name}", spec.id),
            "VF_NATIVE_TOOLCHAIN_UNAVAILABLE",
            format!("cannot execute {program}: {error}"),
        ),
    }
}

fn deterministic_format_check(spec: &LanguageSpec, repo: &Path) -> CheckResult {
    let files = source_files(spec, repo);
    let mut findings = Vec::new();
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
        if !content.is_empty() && !content.ends_with('\n') {
            findings.push(Finding {
                code: "VF_FORMAT_FINAL_NEWLINE".into(),
                message: format!("{} lacks a final newline", display_relative(repo, path)),
                blocking: true,
            });
        }
        for (index, line) in content.lines().enumerate() {
            if line.ends_with(' ') || line.ends_with('\t') {
                findings.push(Finding {
                    code: "VF_FORMAT_TRAILING_WHITESPACE".into(),
                    message: format!(
                        "{}:{} has trailing whitespace",
                        display_relative(repo, path),
                        index + 1
                    ),
                    blocking: true,
                });
            }
        }
    }
    if findings.is_empty() {
        CheckResult::pass_with_evidence(
            format!("{}:format", spec.id),
            format!(
                "deterministic whitespace policy language={} files={}",
                spec.language,
                files.len()
            ),
        )
    } else {
        CheckResult {
            check: format!("{}:format", spec.id),
            status: CheckStatus::Fail,
            findings,
        }
    }
}

fn authenticity_scan(spec: &LanguageSpec, repo: &Path, check_name: &str) -> CheckResult {
    let mut findings = Vec::new();
    let mut scanned = 0usize;
    for path in source_files(spec, repo) {
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
            let marker = if lower.contains(&["to", "do:"].concat())
                || lower.contains(&["to", "do!("].concat())
            {
                Some("TODO")
            } else if lower.contains(&["fix", "me:"].concat()) {
                Some("FIXME")
            } else if lower.contains(&["x", "xx:"].concat()) {
                Some("XXX")
            } else if lower.contains("notimplemented")
                || lower.contains("not implemented")
                || lower.contains("placeholder implementation")
                || lower.contains("stub implementation")
            {
                Some("stub")
            } else {
                None
            };
            if let Some(marker) = marker {
                findings.push(Finding {
                    code: "VF_PLACEHOLDER".into(),
                    message: format!(
                        "{}:{} contains placeholder marker {marker}",
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
            format!("{}:{check_name}", spec.id),
            format!(
                "authenticity scan language={} files={scanned} findings=0",
                spec.language
            ),
        )
    } else {
        CheckResult {
            check: format!("{}:{check_name}", spec.id),
            status: CheckStatus::Fail,
            findings,
        }
    }
}

fn dependency_inventory(spec: &LanguageSpec, repo: &Path) -> CheckResult {
    let files = repository_files(repo);
    let manifests = files
        .iter()
        .filter_map(|path| path.file_name().and_then(|value| value.to_str()))
        .filter(|name| spec.manifests.contains(name))
        .count();
    CheckResult::pass_with_evidence(
        format!("{}:dependencies", spec.id),
        format!("dependency inventory language={} manifests={manifests}", spec.language),
    )
}

fn required_harness(
    spec: &LanguageSpec,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: &str,
) -> CheckResult {
    let harness = format!("{}-{check_name}", spec.id);
    run_repository_harness(
        repo,
        execution,
        format!("{}:{check_name}", spec.id),
        &harness,
    )
    .unwrap_or_else(|| {
        CheckResult::unsupported(
            format!("{}:{check_name}", spec.id),
            format!(
                "{} requires .verificationforge/{harness}.argv for this advanced check",
                spec.language
            ),
        )
    })
}

fn source_files(spec: &LanguageSpec, repo: &Path) -> Vec<PathBuf> {
    repository_files(repo)
        .into_iter()
        .filter(|path| source_matches(spec, path))
        .collect()
}

fn source_matches(spec: &LanguageSpec, path: &Path) -> bool {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !spec.extensions.iter().any(|candidate| *candidate == extension) {
        return false;
    }
    if spec.id == "objective-c" {
        if extension == "mm" {
            return true;
        }
        return fs::read_to_string(path).is_ok_and(|content| objective_c_markers(&content));
    }
    if spec.id == "matlab" && extension == "m" {
        return fs::read_to_string(path).is_ok_and(|content| !objective_c_markers(&content));
    }
    true
}

fn objective_c_markers(content: &str) -> bool {
    content.contains("#import")
        || content.contains("@interface")
        || content.contains("@implementation")
        || content.contains("@protocol")
        || content.contains("@autoreleasepool")
}

fn test_files(spec: &LanguageSpec, repo: &Path) -> Vec<PathBuf> {
    source_files(spec, repo)
        .into_iter()
        .filter(|path| is_test_path(repo, path))
        .collect()
}

fn is_test_path(repo: &Path, path: &Path) -> bool {
    let relative = display_relative(repo, path).to_ascii_lowercase();
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    relative.contains("/test/")
        || relative.contains("/tests/")
        || relative.contains("/spec/")
        || relative.contains("/specs/")
        || name.contains("_test")
        || name.contains(".test.")
        || name.contains("_spec")
        || name.contains(".spec.")
        || name.starts_with("test_")
}

fn has_named_test(spec: &LanguageSpec, repo: &Path, marker: &str) -> bool {
    test_files(spec, repo).iter().any(|path| {
        display_relative(repo, path)
            .to_ascii_lowercase()
            .contains(marker)
    })
}

fn repository_contains(spec: &LanguageSpec, repo: &Path, needles: &[&str]) -> bool {
    source_files(spec, repo).into_iter().any(|path| {
        fs::metadata(&path)
            .ok()
            .is_some_and(|metadata| metadata.len() <= MAX_SCAN_BYTES)
            && fs::read_to_string(&path).is_ok_and(|content| {
                let lower = content.to_ascii_lowercase();
                needles.iter().any(|needle| lower.contains(needle))
            })
    })
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
            if ignored_directory(name.as_ref()) {
                continue;
            }
            visit(&child, depth + 1, files);
        } else if kind.is_file() {
            files.push(child);
        }
    }
}

fn ignored_directory(name: &str) -> bool {
    matches!(
        name,
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
            | ".gradle"
            | ".dart_tool"
            | ".terraform"
            | ".bundle"
            | "_build"
            | "deps"
            | ".elixir_ls"
            | ".stack-work"
            | ".cabal-sandbox"
            | ".nimble"
            | "zig-cache"
            | ".zig-cache"
    )
}

fn temp_output_dir(id: &str) -> PathBuf {
    std::env::temp_dir().join(format!("verificationforge-{id}-{}", process::id()))
}

fn display_relative(repo: &Path, path: &Path) -> String {
    path.strip_prefix(repo)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn expression_single_quote(value: &str) -> String {
    value.replace('\'', "''")
}

fn expression_double_quote(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn command_detail(stdout: &str, stderr: &str) -> String {
    let detail = if stderr.trim().is_empty() { stdout } else { stderr };
    let compact = detail.split_whitespace().collect::<Vec<_>>().join(" ");
    compact.chars().take(1000).collect()
}

fn rename_check(mut result: CheckResult, name: String) -> CheckResult {
    result.check = name;
    result
}

macro_rules! spec {
    ($id:literal, $language:literal, [$($extension:literal),* $(,)?], [$($manifest:literal),* $(,)?]) => {
        LanguageSpec {
            id: $id,
            language: $language,
            extensions: &[$($extension),*],
            manifests: &[$($manifest),*],
        }
    };
}

#[rustfmt::skip]
pub static SPECS: &[LanguageSpec] = &[
    spec!("swift", "Swift", ["swift"], ["Package.swift"]),
    spec!("objective-c", "Objective-C", ["m", "mm"], ["Podfile"]),
    spec!("dart", "Dart", ["dart"], ["pubspec.yaml"]),
    spec!("ruby", "Ruby", ["rb", "rake"], ["Gemfile", "Rakefile"]),
    spec!("lua", "Lua", ["lua"], []),
    spec!("perl", "Perl", ["pl", "pm", "t"], ["Makefile.PL", "Build.PL", "cpanfile"]),
    spec!("r", "R", ["r", "rmd"], ["DESCRIPTION", "renv.lock"]),
    spec!("julia", "Julia", ["jl"], ["Project.toml", "Manifest.toml"]),
    spec!("haskell", "Haskell", ["hs", "lhs"], ["stack.yaml", "cabal.project"]),
    spec!("ocaml", "OCaml", ["ml", "mli"], ["dune-project", "opam"]),
    spec!("fsharp", "F#", ["fs", "fsi", "fsx"], ["global.json"]),
    spec!("elixir", "Elixir", ["ex", "exs"], ["mix.exs"]),
    spec!("erlang", "Erlang", ["erl", "escript"], ["rebar.config", "rebar.lock"]),
    spec!("zig", "Zig", ["zig"], ["build.zig", "build.zig.zon"]),
    spec!("nim", "Nim", ["nim", "nims"], ["nimble"]),
    spec!("d", "D", ["d", "di"], ["dub.json", "dub.sdl"]),
    spec!("fortran", "Fortran", ["f", "for", "f90", "f95", "f03", "f08"], ["fpm.toml"]),
    spec!("cobol", "COBOL", ["cob", "cbl"], []),
    spec!("sql", "SQL", ["sql"], [".sqlfluff"]),
    spec!("hcl", "HCL / Terraform", ["tf"], [".terraform.lock.hcl"]),
    spec!("groovy", "Groovy", ["groovy", "gvy", "gy", "gsh"], ["build.gradle"]),
    spec!("clojure", "Clojure", ["clj", "cljs", "cljc"], ["deps.edn", "project.clj"]),
    spec!("visual-basic", "Visual Basic .NET", ["vb"], ["global.json", "Directory.Build.props"]),
    spec!("object-pascal", "Object Pascal / Delphi", ["pas", "pp", "p"], []),
    spec!("matlab", "MATLAB / Octave", ["m"], []),
    spec!("tcl", "Tcl", ["tcl"], []),
    spec!("nix", "Nix", ["nix"], ["flake.nix"]),
    spec!("gleam", "Gleam", ["gleam"], ["gleam.toml"]),
    spec!("ada", "Ada", ["adb", "ads"], ["alire.toml"]),
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("verificationforge-popular-{name}-{nonce}"))
    }

    fn spec_by_id(id: &str) -> &'static LanguageSpec {
        SPECS.iter().find(|spec| spec.id == id).expect("spec exists")
    }

    #[test]
    fn detects_hcl_and_groovy() {
        let root = temp_dir("detect");
        fs::create_dir_all(&root).expect("create root");
        fs::write(root.join("main.tf"), "terraform {}\n").expect("write hcl");
        fs::write(root.join("demo.groovy"), "println 'ok'\n").expect("write groovy");
        assert!(PopularLanguageAdapter::new(spec_by_id("hcl")).detect(&root).is_some());
        assert!(PopularLanguageAdapter::new(spec_by_id("groovy")).detect(&root).is_some());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn disambiguates_objective_c_and_matlab_m_files() {
        let root = temp_dir("ambiguous-m");
        fs::create_dir_all(&root).expect("create root");
        fs::write(
            root.join("main.m"),
            "#import <stdio.h>\nint main(void) { return 0; }\n",
        )
        .expect("write objective-c");
        let objective_c = PopularLanguageAdapter::new(spec_by_id("objective-c"));
        let matlab = PopularLanguageAdapter::new(spec_by_id("matlab"));
        assert!(objective_c.detect(&root).is_some());
        assert!(matlab.detect(&root).is_none());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn recognizes_new_native_ids() {
        for id in ["swift", "ruby", "hcl", "clojure", "visual-basic", "ada"] {
            assert!(is_popular_native_language_id(id));
        }
        assert!(!is_popular_native_language_id("rust"));
    }
}
