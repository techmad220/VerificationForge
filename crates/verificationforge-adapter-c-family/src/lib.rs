use std::fs;
use std::path::{Path, PathBuf};

use verificationforge_core::{
    CheckKind, CheckResult, CheckStatus, ExecutionAdapter, Finding, ImpactScope, LanguageAdapter,
    LanguageDetection, SymbolId, run_repository_harness,
};

const MAX_SCAN_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone, Copy)]
struct NativeProfile {
    id: &'static str,
    language: &'static str,
    extensions: &'static [&'static str],
    compiler: &'static str,
    standard: &'static str,
}

const C: NativeProfile = NativeProfile {
    id: "c",
    language: "C",
    extensions: &["c"],
    compiler: "cc",
    standard: "c17",
};

const CPP: NativeProfile = NativeProfile {
    id: "cpp",
    language: "C++",
    extensions: &["cc", "cpp", "cxx"],
    compiler: "c++",
    standard: "c++20",
};

pub struct CAdapter;
pub struct CppAdapter;
pub struct CSharpAdapter;

impl LanguageAdapter for CAdapter {
    fn id(&self) -> &'static str {
        C.id
    }

    fn detect(&self, repo: &Path) -> Option<LanguageDetection> {
        detect_native(C, repo)
    }

    fn inventory_symbols(&self, repo: &Path) -> Result<Vec<SymbolId>, String> {
        inventory_native(C, repo)
    }

    fn run_parse_check(&self, repo: &Path, execution: &dyn ExecutionAdapter) -> CheckResult {
        native_syntax_check(C, repo, execution, "parse", false)
    }

    fn run_format_check(&self, repo: &Path, _execution: &dyn ExecutionAdapter) -> CheckResult {
        whitespace_format_check(C.id, C.language, &source_files(C, repo), repo)
    }

    fn run_targeted_tests(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        scope: &ImpactScope,
    ) -> CheckResult {
        native_targeted_tests(C, repo, execution, scope)
    }

    fn run_integration_tests(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        _scope: &ImpactScope,
    ) -> CheckResult {
        native_integration_tests(C, repo, execution)
    }

    fn run_property_tests(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        _scope: &ImpactScope,
    ) -> CheckResult {
        native_property_tests(C, repo, execution)
    }

    fn run_ui_verification(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        _scope: &ImpactScope,
    ) -> CheckResult {
        native_surface_verification(C, repo, execution, "ui", has_native_ui_surface(repo))
    }

    fn run_api_verification(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        _scope: &ImpactScope,
    ) -> CheckResult {
        native_surface_verification(C, repo, execution, "api", has_native_api_surface(repo))
    }

    fn run_check(
        &self,
        check: CheckKind,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
    ) -> CheckResult {
        run_native_check(C, check, repo, execution)
    }
}

impl LanguageAdapter for CppAdapter {
    fn id(&self) -> &'static str {
        CPP.id
    }

    fn detect(&self, repo: &Path) -> Option<LanguageDetection> {
        detect_native(CPP, repo)
    }

    fn inventory_symbols(&self, repo: &Path) -> Result<Vec<SymbolId>, String> {
        inventory_native(CPP, repo)
    }

    fn run_parse_check(&self, repo: &Path, execution: &dyn ExecutionAdapter) -> CheckResult {
        native_syntax_check(CPP, repo, execution, "parse", false)
    }

    fn run_format_check(&self, repo: &Path, _execution: &dyn ExecutionAdapter) -> CheckResult {
        whitespace_format_check(CPP.id, CPP.language, &source_files(CPP, repo), repo)
    }

    fn run_targeted_tests(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        scope: &ImpactScope,
    ) -> CheckResult {
        native_targeted_tests(CPP, repo, execution, scope)
    }

    fn run_integration_tests(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        _scope: &ImpactScope,
    ) -> CheckResult {
        native_integration_tests(CPP, repo, execution)
    }

    fn run_property_tests(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        _scope: &ImpactScope,
    ) -> CheckResult {
        native_property_tests(CPP, repo, execution)
    }

    fn run_ui_verification(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        _scope: &ImpactScope,
    ) -> CheckResult {
        native_surface_verification(CPP, repo, execution, "ui", has_native_ui_surface(repo))
    }

    fn run_api_verification(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        _scope: &ImpactScope,
    ) -> CheckResult {
        native_surface_verification(CPP, repo, execution, "api", has_native_api_surface(repo))
    }

    fn run_check(
        &self,
        check: CheckKind,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
    ) -> CheckResult {
        run_native_check(CPP, check, repo, execution)
    }
}

impl LanguageAdapter for CSharpAdapter {
    fn id(&self) -> &'static str {
        "csharp"
    }

    fn detect(&self, repo: &Path) -> Option<LanguageDetection> {
        let sources = files_with_extensions(repo, &["cs"]);
        if sources.is_empty() {
            return None;
        }
        let manifest = !files_with_extensions(repo, &["csproj", "sln", "slnx"]).is_empty();
        Some(LanguageDetection {
            adapter_id: self.id().into(),
            language: "C#".into(),
            confidence_percent: if manifest { 100 } else { 88 },
        })
    }

    fn inventory_symbols(&self, repo: &Path) -> Result<Vec<SymbolId>, String> {
        inventory_csharp(repo)
    }

    fn run_parse_check(&self, repo: &Path, execution: &dyn ExecutionAdapter) -> CheckResult {
        dotnet_build(repo, execution, "parse", false)
    }

    fn run_format_check(&self, repo: &Path, _execution: &dyn ExecutionAdapter) -> CheckResult {
        whitespace_format_check("csharp", "C#", &files_with_extensions(repo, &["cs"]), repo)
    }

    fn run_targeted_tests(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        scope: &ImpactScope,
    ) -> CheckResult {
        let affected = scope.changed_paths.iter().any(|path| {
            matches!(
                Path::new(path).extension().and_then(|value| value.to_str()),
                Some("cs" | "csproj" | "sln" | "slnx")
            )
        });
        if !affected && !scope.requires_full_verification {
            return CheckResult::skipped(
                "csharp:targeted-test",
                "no changed C# path maps to the C# adapter",
            );
        }
        if test_projects(repo).is_empty() {
            return CheckResult::skipped(
                "csharp:targeted-test",
                "affected C# source has no native test project",
            );
        }
        rename_check(run_csharp_tests(repo, execution), "csharp:targeted-test")
    }

    fn run_integration_tests(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        _scope: &ImpactScope,
    ) -> CheckResult {
        if test_projects(repo).iter().any(|path| {
            display_relative(repo, path)
                .to_ascii_lowercase()
                .contains("integration")
        }) {
            rename_check(
                run_csharp_tests(repo, execution),
                "csharp:checkpoint-integration",
            )
        } else {
            CheckResult::skipped(
                "csharp:checkpoint-integration",
                "no C# integration-test project detected",
            )
        }
    }

    fn run_property_tests(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        _scope: &ImpactScope,
    ) -> CheckResult {
        if repository_contains(repo, &["FsCheck", "Hedgehog"]) {
            if test_projects(repo).is_empty() {
                required_harness("csharp", "C#", execution, repo, "checkpoint-property")
            } else {
                rename_check(
                    run_csharp_tests(repo, execution),
                    "csharp:checkpoint-property",
                )
            }
        } else {
            CheckResult::skipped(
                "csharp:checkpoint-property",
                "no C# property-testing surface detected",
            )
        }
    }

    fn run_ui_verification(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        _scope: &ImpactScope,
    ) -> CheckResult {
        csharp_surface_verification(repo, execution, "ui", has_csharp_ui_surface(repo))
    }

    fn run_api_verification(
        &self,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
        _scope: &ImpactScope,
    ) -> CheckResult {
        csharp_surface_verification(repo, execution, "api", has_csharp_api_surface(repo))
    }

    fn run_check(
        &self,
        check: CheckKind,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
    ) -> CheckResult {
        run_csharp_check(check, repo, execution)
    }
}

fn detect_native(profile: NativeProfile, repo: &Path) -> Option<LanguageDetection> {
    let sources = source_files(profile, repo);
    if sources.is_empty() {
        return None;
    }
    let manifest = repo.join("CMakeLists.txt").is_file()
        || repo.join("Makefile").is_file()
        || repo.join("meson.build").is_file();
    Some(LanguageDetection {
        adapter_id: profile.id.into(),
        language: profile.language.into(),
        confidence_percent: if manifest { 100 } else { 90 },
    })
}

fn inventory_native(profile: NativeProfile, repo: &Path) -> Result<Vec<SymbolId>, String> {
    let mut symbols = Vec::new();
    for path in source_files(profile, repo) {
        let relative = display_relative(repo, &path);
        symbols.push(SymbolId(format!("{}:file:{relative}", profile.id)));
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        for line in content.lines() {
            let trimmed = line.trim();
            for (prefix, kind) in [
                ("struct ", "struct"),
                ("class ", "class"),
                ("enum ", "enum"),
                ("typedef ", "typedef"),
            ] {
                if let Some(rest) = trimmed.strip_prefix(prefix) {
                    let name = identifier(rest);
                    if !name.is_empty() {
                        symbols.push(SymbolId(format!("{}:{kind}:{relative}:{name}", profile.id)));
                    }
                }
            }
            if let Some(name) = c_function_name(trimmed) {
                symbols.push(SymbolId(format!(
                    "{}:function:{relative}:{name}",
                    profile.id
                )));
            }
        }
    }
    symbols.sort();
    symbols.dedup();
    Ok(symbols)
}

fn run_native_check(
    profile: NativeProfile,
    check: CheckKind,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
) -> CheckResult {
    match check {
        CheckKind::Build => compile_native_objects(profile, repo, execution),
        CheckKind::TypeCheck => {
            native_syntax_check(profile, repo, execution, check.as_str(), false)
        }
        CheckKind::Lint => native_syntax_check(profile, repo, execution, check.as_str(), true),
        CheckKind::Test => run_native_tests(profile, repo, execution),
        CheckKind::Dependencies => native_dependencies(profile, repo, execution),
        CheckKind::Placeholders => scan_native_placeholders(profile, repo),
        CheckKind::Concurrency => {
            if has_native_concurrency(repo) {
                required_harness(
                    profile.id,
                    profile.language,
                    execution,
                    repo,
                    check.as_str(),
                )
            } else {
                CheckResult::skipped(
                    format!("{}:{}", profile.id, check.as_str()),
                    "no native thread/atomic concurrency markers detected",
                )
            }
        }
        CheckKind::Ui => {
            if has_native_ui_surface(repo) {
                required_harness(
                    profile.id,
                    profile.language,
                    execution,
                    repo,
                    check.as_str(),
                )
            } else {
                CheckResult::skipped(
                    format!("{}:{}", profile.id, check.as_str()),
                    "no native UI surface detected",
                )
            }
        }
        CheckKind::Coverage
        | CheckKind::Mutation
        | CheckKind::Fuzz
        | CheckKind::Security
        | CheckKind::Contracts
        | CheckKind::Stress
        | CheckKind::FaultInjection
        | CheckKind::FormalProof => required_harness(
            profile.id,
            profile.language,
            execution,
            repo,
            check.as_str(),
        ),
    }
}

fn compile_native_objects(
    profile: NativeProfile,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
) -> CheckResult {
    if !executable_available(execution, repo, profile.compiler) {
        return CheckResult::fail(
            format!("{}:build", profile.id),
            "VF_NATIVE_COMPILER_MISSING",
            format!(
                "{} repository detected but {} is not executable",
                profile.language, profile.compiler
            ),
        );
    }
    let mut files = source_files(profile, repo)
        .into_iter()
        .filter(|path| !is_test_source(path))
        .collect::<Vec<_>>();
    if files.is_empty() {
        files = source_files(profile, repo);
    }
    let mut compiled = 0usize;
    for (index, path) in files.iter().enumerate() {
        let output = std::env::temp_dir().join(format!(
            "verificationforge-{}-{}-{index}.o",
            profile.id,
            std::process::id()
        ));
        let args = vec![
            format!("-std={}", profile.standard),
            "-Wall".into(),
            "-Wextra".into(),
            "-c".into(),
            display_relative(repo, path),
            "-o".into(),
            output.to_string_lossy().into_owned(),
        ];
        let result = execution.execute(profile.compiler, &args, repo);
        fs::remove_file(&output).ok();
        match result {
            Ok(value) if value.success() => compiled += 1,
            Ok(value) => {
                return CheckResult::fail(
                    format!("{}:build", profile.id),
                    "VF_NATIVE_BUILD_FAILED",
                    command_failure(profile.compiler, &args, &value),
                );
            }
            Err(error) => {
                return CheckResult::fail(
                    format!("{}:build", profile.id),
                    "VF_NATIVE_EXECUTION_FAILED",
                    error,
                );
            }
        }
    }
    CheckResult::pass_with_evidence(
        format!("{}:build", profile.id),
        format!(
            "compiler={} standard={} translation-units={compiled} objects-written-outside-repository=true",
            profile.compiler, profile.standard
        ),
    )
}

fn native_syntax_check(
    profile: NativeProfile,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: &str,
    strict_warnings: bool,
) -> CheckResult {
    if !executable_available(execution, repo, profile.compiler) {
        return CheckResult::fail(
            format!("{}:{check_name}", profile.id),
            "VF_NATIVE_COMPILER_MISSING",
            format!("{} is not executable", profile.compiler),
        );
    }
    let files = source_files(profile, repo);
    let mut args = vec![
        format!("-std={}", profile.standard),
        "-fsyntax-only".into(),
        "-Wall".into(),
        "-Wextra".into(),
    ];
    if strict_warnings {
        args.extend(["-Wpedantic".into(), "-Werror".into()]);
    }
    args.extend(files.iter().map(|path| display_relative(repo, path)));
    run_named(
        profile.id,
        execution,
        repo,
        check_name,
        profile.compiler,
        args,
    )
}

fn native_targeted_tests(
    profile: NativeProfile,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    scope: &ImpactScope,
) -> CheckResult {
    let affected = scope.changed_paths.iter().any(|path| {
        Path::new(path)
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|extension| profile.extensions.contains(&extension))
    });
    if !affected && !scope.requires_full_verification {
        return CheckResult::skipped(
            format!("{}:targeted-test", profile.id),
            format!(
                "no changed {} source maps to this adapter",
                profile.language
            ),
        );
    }
    if native_test_sources(profile, repo).is_empty() && !make_has_target(repo, "test") {
        return CheckResult::skipped(
            format!("{}:targeted-test", profile.id),
            format!("affected {} source has no native tests", profile.language),
        );
    }
    rename_check(
        run_native_tests(profile, repo, execution),
        &format!("{}:targeted-test", profile.id),
    )
}

fn native_integration_tests(
    profile: NativeProfile,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
) -> CheckResult {
    if native_test_sources(profile, repo).iter().any(|path| {
        display_relative(repo, path)
            .to_ascii_lowercase()
            .contains("integration")
    }) {
        rename_check(
            run_native_tests(profile, repo, execution),
            &format!("{}:checkpoint-integration", profile.id),
        )
    } else {
        CheckResult::skipped(
            format!("{}:checkpoint-integration", profile.id),
            format!("no {} integration-test source detected", profile.language),
        )
    }
}

fn native_property_tests(
    profile: NativeProfile,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
) -> CheckResult {
    if repository_contains(
        repo,
        &[
            "rapidcheck",
            "Catch2::Generators",
            "RC_ASSERT",
            "hypothesis::",
        ],
    ) {
        if native_test_sources(profile, repo).is_empty() {
            required_harness(
                profile.id,
                profile.language,
                execution,
                repo,
                "checkpoint-property",
            )
        } else {
            rename_check(
                run_native_tests(profile, repo, execution),
                &format!("{}:checkpoint-property", profile.id),
            )
        }
    } else {
        CheckResult::skipped(
            format!("{}:checkpoint-property", profile.id),
            format!("no {} property-testing surface detected", profile.language),
        )
    }
}

fn native_surface_verification(
    profile: NativeProfile,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    surface: &str,
    applicable: bool,
) -> CheckResult {
    if !applicable {
        return CheckResult::skipped(
            format!("{}:checkpoint-{surface}", profile.id),
            format!("no {} {surface} surface detected", profile.language),
        );
    }
    required_harness(
        profile.id,
        profile.language,
        execution,
        repo,
        &format!("checkpoint-{surface}"),
    )
}

fn run_native_tests(
    profile: NativeProfile,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
) -> CheckResult {
    if make_has_target(repo, "test") {
        return run_named(
            profile.id,
            execution,
            repo,
            "test",
            "make",
            vec!["test".into()],
        );
    }
    let tests = native_test_sources(profile, repo);
    if tests.is_empty() {
        return required_harness(profile.id, profile.language, execution, repo, "test");
    }
    let libraries = source_files(profile, repo)
        .into_iter()
        .filter(|path| !is_test_source(path) && !is_entrypoint_source(path))
        .collect::<Vec<_>>();
    let mut executed = 0usize;
    for (index, test) in tests.iter().enumerate() {
        let output = std::env::temp_dir().join(format!(
            "verificationforge-{}-test-{}-{index}",
            profile.id,
            std::process::id()
        ));
        let mut args = vec![
            format!("-std={}", profile.standard),
            "-Wall".into(),
            "-Wextra".into(),
            "-Werror".into(),
            display_relative(repo, test),
        ];
        args.extend(libraries.iter().map(|path| display_relative(repo, path)));
        args.extend(["-o".into(), output.to_string_lossy().into_owned()]);
        match execution.execute(profile.compiler, &args, repo) {
            Ok(value) if value.success() => {}
            Ok(value) => {
                fs::remove_file(&output).ok();
                return CheckResult::fail(
                    format!("{}:test", profile.id),
                    "VF_NATIVE_TEST_BUILD_FAILED",
                    command_failure(profile.compiler, &args, &value),
                );
            }
            Err(error) => {
                fs::remove_file(&output).ok();
                return CheckResult::fail(
                    format!("{}:test", profile.id),
                    "VF_NATIVE_EXECUTION_FAILED",
                    error,
                );
            }
        }
        let program = output.to_string_lossy().into_owned();
        let result = execution.execute(&program, &[], repo);
        fs::remove_file(&output).ok();
        match result {
            Ok(value) if value.success() => executed += 1,
            Ok(value) => {
                return CheckResult::fail(
                    format!("{}:test", profile.id),
                    "VF_NATIVE_TEST_FAILED",
                    command_failure(&program, &[], &value),
                );
            }
            Err(error) => {
                return CheckResult::fail(
                    format!("{}:test", profile.id),
                    "VF_NATIVE_TEST_EXECUTION_FAILED",
                    error,
                );
            }
        }
    }
    CheckResult::pass_with_evidence(
        format!("{}:test", profile.id),
        format!("native compiled test executables passed={executed}"),
    )
}

fn native_dependencies(
    profile: NativeProfile,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
) -> CheckResult {
    let files = source_files(profile, repo);
    let mut args = vec![format!("-std={}", profile.standard), "-MM".into()];
    args.extend(files.iter().map(|path| display_relative(repo, path)));
    run_named(
        profile.id,
        execution,
        repo,
        "dependencies",
        profile.compiler,
        args,
    )
}

fn scan_native_placeholders(profile: NativeProfile, repo: &Path) -> CheckResult {
    scan_placeholders(
        profile.id,
        profile.language,
        &source_files(profile, repo),
        repo,
    )
}

fn native_test_sources(profile: NativeProfile, repo: &Path) -> Vec<PathBuf> {
    source_files(profile, repo)
        .into_iter()
        .filter(|path| is_test_source(path))
        .collect()
}

fn is_test_source(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    name.starts_with("test_")
        || name.contains("_test.")
        || name.contains(".test.")
        || path
            .components()
            .any(|component| matches!(component.as_os_str().to_str(), Some("test" | "tests")))
}

fn is_entrypoint_source(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(
        name.as_str(),
        "main.c" | "main.cc" | "main.cpp" | "main.cxx"
    )
}

fn make_has_target(repo: &Path, target: &str) -> bool {
    let Ok(content) = fs::read_to_string(repo.join("Makefile")) else {
        return false;
    };
    content.lines().any(|line| {
        line.trim_start()
            .strip_prefix(target)
            .is_some_and(|rest| rest.trim_start().starts_with(':'))
    })
}

fn has_native_concurrency(repo: &Path) -> bool {
    repository_contains(
        repo,
        &[
            "pthread_",
            "std::thread",
            "std::atomic",
            "stdatomic.h",
            "atomic_",
        ],
    )
}

fn has_native_ui_surface(repo: &Path) -> bool {
    repository_contains(
        repo,
        &[
            "gtk_",
            "QApplication",
            "QWidget",
            "ImGui::",
            "SDL_CreateWindow",
            "glfwCreateWindow",
        ],
    )
}

fn has_native_api_surface(repo: &Path) -> bool {
    repository_contains(
        repo,
        &["socket(", "bind(", "listen(", "accept(", "curl_easy_"],
    )
}

fn run_csharp_check(
    check: CheckKind,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
) -> CheckResult {
    match check {
        CheckKind::Build => dotnet_build(repo, execution, check.as_str(), false),
        CheckKind::TypeCheck => dotnet_build(repo, execution, check.as_str(), false),
        CheckKind::Lint => dotnet_build(repo, execution, check.as_str(), true),
        CheckKind::Test => run_csharp_tests(repo, execution),
        CheckKind::Dependencies => csharp_dependencies(repo, execution),
        CheckKind::Security => csharp_security(repo, execution),
        CheckKind::Placeholders => {
            scan_placeholders("csharp", "C#", &files_with_extensions(repo, &["cs"]), repo)
        }
        CheckKind::Concurrency => {
            if repository_contains(
                repo,
                &["System.Threading", "Task.Run", "Thread(", "Parallel."],
            ) {
                required_harness("csharp", "C#", execution, repo, check.as_str())
            } else {
                CheckResult::skipped(
                    "csharp:concurrency",
                    "no C# thread/task concurrency markers detected",
                )
            }
        }
        CheckKind::Ui => {
            if has_csharp_ui_surface(repo) {
                required_harness("csharp", "C#", execution, repo, check.as_str())
            } else {
                CheckResult::skipped("csharp:ui", "no C# UI surface detected")
            }
        }
        CheckKind::Coverage
        | CheckKind::Mutation
        | CheckKind::Fuzz
        | CheckKind::Contracts
        | CheckKind::Stress
        | CheckKind::FaultInjection
        | CheckKind::FormalProof => {
            required_harness("csharp", "C#", execution, repo, check.as_str())
        }
    }
}

fn dotnet_build(
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: &str,
    warnings_as_errors: bool,
) -> CheckResult {
    if !executable_available(execution, repo, "dotnet") {
        return CheckResult::fail(
            format!("csharp:{check_name}"),
            "VF_DOTNET_MISSING",
            "C# repository detected but dotnet is not executable",
        );
    }
    let Some(target) = dotnet_target(repo) else {
        return CheckResult::fail(
            format!("csharp:{check_name}"),
            "VF_CSHARP_PROJECT_MISSING",
            "C# source was detected but no .sln/.slnx/.csproj project was found",
        );
    };
    let mut args = vec!["build".into(), target, "--nologo".into(), "-v:q".into()];
    if warnings_as_errors {
        args.push("-warnaserror".into());
    }
    run_named("csharp", execution, repo, check_name, "dotnet", args)
}

fn run_csharp_tests(repo: &Path, execution: &dyn ExecutionAdapter) -> CheckResult {
    let projects = test_projects(repo);
    if projects.is_empty() {
        return required_harness("csharp", "C#", execution, repo, "test");
    }
    let mut executed = 0usize;
    for project in projects {
        let relative = display_relative(repo, &project);
        let content = fs::read_to_string(&project).unwrap_or_default();
        let framework = [
            "Microsoft.NET.Test.Sdk",
            "xunit",
            "NUnit",
            "MSTest.TestFramework",
        ]
        .iter()
        .any(|marker| content.contains(marker));
        let args = if framework {
            vec!["test".into(), relative, "--nologo".into(), "-v:q".into()]
        } else {
            vec![
                "run".into(),
                "--project".into(),
                relative,
                "--nologo".into(),
            ]
        };
        let result = execution.execute("dotnet", &args, repo);
        match result {
            Ok(value) if value.success() => executed += 1,
            Ok(value) => {
                return CheckResult::fail(
                    "csharp:test",
                    "VF_CSHARP_TEST_FAILED",
                    command_failure("dotnet", &args, &value),
                );
            }
            Err(error) => {
                return CheckResult::fail("csharp:test", "VF_CSHARP_TEST_EXECUTION_FAILED", error);
            }
        }
    }
    CheckResult::pass_with_evidence(
        "csharp:test",
        format!("native dotnet test/executable projects passed={executed}"),
    )
}

fn csharp_dependencies(repo: &Path, execution: &dyn ExecutionAdapter) -> CheckResult {
    let Some(target) = dotnet_target(repo) else {
        return CheckResult::fail(
            "csharp:dependencies",
            "VF_CSHARP_PROJECT_MISSING",
            "cannot inspect C# dependencies without a project or solution",
        );
    };
    run_named(
        "csharp",
        execution,
        repo,
        "dependencies",
        "dotnet",
        vec![
            "list".into(),
            target,
            "package".into(),
            "--include-transitive".into(),
        ],
    )
}

fn csharp_security(repo: &Path, execution: &dyn ExecutionAdapter) -> CheckResult {
    let Some(target) = dotnet_target(repo) else {
        return required_harness("csharp", "C#", execution, repo, "security");
    };
    run_named(
        "csharp",
        execution,
        repo,
        "security",
        "dotnet",
        vec![
            "list".into(),
            target,
            "package".into(),
            "--vulnerable".into(),
            "--include-transitive".into(),
        ],
    )
}

fn csharp_surface_verification(
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    surface: &str,
    applicable: bool,
) -> CheckResult {
    if !applicable {
        return CheckResult::skipped(
            format!("csharp:checkpoint-{surface}"),
            format!("no C# {surface} surface detected"),
        );
    }
    required_harness(
        "csharp",
        "C#",
        execution,
        repo,
        &format!("checkpoint-{surface}"),
    )
}

fn has_csharp_ui_surface(repo: &Path) -> bool {
    repository_contains(
        repo,
        &[
            "UseWPF",
            "UseWindowsForms",
            "Microsoft.Maui",
            "Avalonia",
            "Microsoft.AspNetCore.Components",
        ],
    )
}

fn has_csharp_api_surface(repo: &Path) -> bool {
    repository_contains(
        repo,
        &[
            "Microsoft.AspNetCore",
            "MapGet(",
            "MapPost(",
            "ControllerBase",
            "HttpListener",
        ],
    )
}

fn inventory_csharp(repo: &Path) -> Result<Vec<SymbolId>, String> {
    let mut symbols = Vec::new();
    for path in files_with_extensions(repo, &["cs"]) {
        let relative = display_relative(repo, &path);
        symbols.push(SymbolId(format!("csharp:file:{relative}")));
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        for line in content.lines() {
            let trimmed = line.trim();
            for (marker, kind) in [
                (" class ", "class"),
                (" record ", "record"),
                (" struct ", "struct"),
                (" interface ", "interface"),
                (" enum ", "enum"),
            ] {
                if let Some(index) = format!(" {trimmed} ").find(marker) {
                    let padded = format!(" {trimmed} ");
                    let rest = &padded[index + marker.len()..];
                    let name = identifier(rest);
                    if !name.is_empty() {
                        symbols.push(SymbolId(format!("csharp:{kind}:{relative}:{name}")));
                    }
                }
            }
        }
    }
    symbols.sort();
    symbols.dedup();
    Ok(symbols)
}

fn dotnet_target(repo: &Path) -> Option<String> {
    let files = repository_files(repo);
    for extension in ["slnx", "sln", "csproj"] {
        if let Some(path) = files.iter().find(|path| {
            path.extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case(extension))
                && !is_test_project(path)
        }) {
            return Some(display_relative(repo, path));
        }
    }
    files.iter().find_map(|path| {
        path.extension()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("csproj"))
            .then(|| display_relative(repo, path))
    })
}

fn test_projects(repo: &Path) -> Vec<PathBuf> {
    files_with_extensions(repo, &["csproj"])
        .into_iter()
        .filter(|path| is_test_project(path))
        .collect()
}

fn is_test_project(path: &Path) -> bool {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    lower.contains("/test")
        || lower.contains("\\test")
        || lower.contains(".tests.csproj")
        || lower.contains(".test.csproj")
}

fn scan_placeholders(id: &str, language: &str, files: &[PathBuf], repo: &Path) -> CheckResult {
    let mut findings = Vec::new();
    let mut scanned = 0usize;
    for path in files {
        let Ok(metadata) = fs::metadata(path) else {
            continue;
        };
        if metadata.len() > MAX_SCAN_BYTES {
            continue;
        }
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        scanned += 1;
        for (index, line) in content.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            if lower.contains(&["to", "do:"].concat())
                || lower.contains(&["fix", "me:"].concat())
                || lower.contains(&["x", "xx:"].concat())
                || lower.contains("notimplementedexception")
                || (lower.contains("abort(") && lower.contains("not implemented"))
            {
                findings.push(Finding {
                    code: "VF_PLACEHOLDER".into(),
                    message: format!(
                        "{}:{} contains an unfinished implementation marker",
                        display_relative(repo, path),
                        index + 1
                    ),
                    blocking: true,
                });
            }
            if sensitive_constant_gate(line) {
                findings.push(Finding {
                    code: "VF_FAKE_IMPLEMENTATION".into(),
                    message: format!(
                        "{}:{} contains a constant authorization/permission decision",
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
            format!("{id}:placeholders"),
            format!(
                "scanned {scanned} {language} source files for placeholder and fake-success patterns"
            ),
        )
    } else {
        CheckResult {
            check: format!("{id}:placeholders"),
            status: CheckStatus::Fail,
            findings,
        }
    }
}

fn sensitive_constant_gate(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    let sensitive = [
        "authoriz",
        "authenticate",
        "permission",
        "isadmin",
        "hasaccess",
        "canaccess",
    ]
    .iter()
    .any(|marker| lower.contains(marker));
    sensitive
        && (lower.contains("return true")
            || lower.contains("return false")
            || lower.contains("=> true")
            || lower.contains("=> false"))
}

fn whitespace_format_check(
    id: &str,
    _language: &str,
    files: &[PathBuf],
    repo: &Path,
) -> CheckResult {
    let mut findings = Vec::new();
    let mut scanned = 0usize;
    for path in files {
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        scanned += 1;
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
        if !content.is_empty() && !content.ends_with('\n') {
            findings.push(Finding {
                code: "VF_FORMAT_FINAL_NEWLINE".into(),
                message: format!(
                    "{} is missing a final newline",
                    display_relative(repo, path)
                ),
                blocking: true,
            });
        }
    }
    if findings.is_empty() {
        CheckResult::pass_with_evidence(
            format!("{id}:format"),
            format!("deterministic built-in whitespace format policy files={scanned} violations=0"),
        )
    } else {
        CheckResult {
            check: format!("{id}:format"),
            status: CheckStatus::Fail,
            findings,
        }
    }
}

fn required_harness(
    id: &str,
    language: &str,
    execution: &dyn ExecutionAdapter,
    repo: &Path,
    check_name: &str,
) -> CheckResult {
    let harness = format!("{id}-{check_name}");
    run_repository_harness(repo, execution, format!("{id}:{check_name}"), &harness).unwrap_or_else(
        || {
            CheckResult::unsupported(
                format!("{id}:{check_name}"),
                format!(
                    "required {language} harness is missing: .verificationforge/{harness}.argv"
                ),
            )
        },
    )
}

fn run_named(
    id: &str,
    execution: &dyn ExecutionAdapter,
    repo: &Path,
    check_name: &str,
    program: &str,
    args: Vec<String>,
) -> CheckResult {
    match execution.execute(program, &args, repo) {
        Ok(output) if output.success() => CheckResult::pass_with_evidence(
            format!("{id}:{check_name}"),
            format!("command={program} {} exit=0", args.join(" ")),
        ),
        Ok(output) => CheckResult::fail(
            format!("{id}:{check_name}"),
            "VF_COMMAND_FAILED",
            command_failure(program, &args, &output),
        ),
        Err(error) => CheckResult::fail(format!("{id}:{check_name}"), "VF_EXECUTION_FAILED", error),
    }
}

fn executable_available(execution: &dyn ExecutionAdapter, repo: &Path, program: &str) -> bool {
    execution
        .execute(program, &["--version".into()], repo)
        .map(|result| result.success())
        .unwrap_or(false)
}

fn command_failure(
    program: &str,
    args: &[String],
    output: &verificationforge_core::ExecutionResult,
) -> String {
    format!(
        "command={program} {} exit={} stderr={} stdout={}",
        args.join(" "),
        output.exit_code,
        sanitize_output(&output.stderr),
        sanitize_output(&output.stdout)
    )
}

fn source_files(profile: NativeProfile, repo: &Path) -> Vec<PathBuf> {
    files_with_extensions(repo, profile.extensions)
}

fn files_with_extensions(repo: &Path, extensions: &[&str]) -> Vec<PathBuf> {
    repository_files(repo)
        .into_iter()
        .filter(|path| {
            path.extension()
                .and_then(|value| value.to_str())
                .is_some_and(|extension| {
                    extensions
                        .iter()
                        .any(|candidate| extension.eq_ignore_ascii_case(candidate))
                })
        })
        .collect()
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
                ".git" | "target" | "build" | "out" | "bin" | "obj" | "node_modules" | ".vs"
            ) {
                continue;
            }
            visit(&child, depth + 1, files);
        } else if kind.is_file() {
            files.push(child);
        }
    }
}

fn c_function_name(line: &str) -> Option<&str> {
    if !line.contains('(') || !line.contains('{') {
        return None;
    }
    let open = line.find('(')?;
    let before = line[..open].trim_end();
    let name = before.split_whitespace().last()?;
    let name = name.trim_matches(|character: char| character == '*' || character == '&');
    if name.is_empty()
        || matches!(name, "if" | "for" | "while" | "switch" | "catch")
        || name.contains("::operator")
    {
        None
    } else {
        Some(name)
    }
}

fn identifier(value: &str) -> &str {
    let value =
        value.trim_start_matches(|character: char| character == '*' || character.is_whitespace());
    let end = value
        .find(|character: char| {
            !(character.is_ascii_alphanumeric() || character == '_' || character == ':')
        })
        .unwrap_or(value.len());
    &value[..end]
}

fn display_relative(repo: &Path, path: &Path) -> String {
    path.strip_prefix(repo)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn rename_check(mut result: CheckResult, name: &str) -> CheckResult {
    result.check = name.into();
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

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("verificationforge-c-family-{name}-{nonce}"))
    }

    #[test]
    fn c_cpp_and_csharp_detect_independently() {
        let root = temp_dir("mixed");
        fs::create_dir_all(&root).expect("create root");
        fs::write(root.join("a.c"), "int a(void) { return 1; }\n").expect("write c");
        fs::write(root.join("b.cpp"), "int b() { return 2; }\n").expect("write cpp");
        fs::write(root.join("C.cs"), "public class C {}\n").expect("write csharp");
        fs::write(
            root.join("C.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk\" />\n",
        )
        .expect("write project");
        assert_eq!(CAdapter.detect(&root).expect("c").language, "C");
        assert_eq!(CppAdapter.detect(&root).expect("cpp").language, "C++");
        assert_eq!(CSharpAdapter.detect(&root).expect("csharp").language, "C#");
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn csharp_constant_authorization_is_blocked() {
        let root = temp_dir("fake-auth");
        fs::create_dir_all(&root).expect("create root");
        fs::write(
            root.join("Auth.cs"),
            "public static class Auth { public static bool Authorize(string user) => true; }\n",
        )
        .expect("write source");
        let result = scan_placeholders(
            "csharp",
            "C#",
            &files_with_extensions(&root, &["cs"]),
            &root,
        );
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.has_blocking_finding());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn native_format_policy_is_evidence_backed() {
        let root = temp_dir("format");
        fs::create_dir_all(&root).expect("create root");
        fs::write(
            root.join("add.c"),
            "int add(int a, int b) { return a + b; }\n",
        )
        .expect("write source");
        let result = whitespace_format_check(C.id, C.language, &source_files(C, &root), &root);
        assert_eq!(result.status, CheckStatus::Pass);
        assert!(result.has_reproducible_evidence());
        fs::remove_dir_all(root).ok();
    }
}
