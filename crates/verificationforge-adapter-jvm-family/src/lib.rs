use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use verificationforge_core::{
    CheckKind, CheckResult, CheckStatus, ExecutionAdapter, Finding, ImpactScope, LanguageAdapter,
    LanguageDetection, SymbolId, run_repository_harness,
};

const MAX_SCAN_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone, Copy)]
enum JvmLanguage {
    Java,
    Kotlin,
    Scala,
}

impl JvmLanguage {
    fn id(self) -> &'static str {
        match self {
            Self::Java => "java",
            Self::Kotlin => "kotlin",
            Self::Scala => "scala",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Java => "Java",
            Self::Kotlin => "Kotlin",
            Self::Scala => "Scala",
        }
    }

    fn extensions(self) -> &'static [&'static str] {
        match self {
            Self::Java => &["java"],
            Self::Kotlin => &["kt", "kts"],
            Self::Scala => &["scala", "sc"],
        }
    }
}

pub struct JavaAdapter;
pub struct KotlinAdapter;
pub struct ScalaAdapter;

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
                compile_check($language, repo, execution, "parse", false)
            }

            fn run_format_check(
                &self,
                repo: &Path,
                _execution: &dyn ExecutionAdapter,
            ) -> CheckResult {
                whitespace_format_check($language, repo)
            }

            fn run_targeted_tests(
                &self,
                repo: &Path,
                execution: &dyn ExecutionAdapter,
                scope: &ImpactScope,
            ) -> CheckResult {
                targeted_tests($language, repo, execution, scope)
            }

            fn run_integration_tests(
                &self,
                repo: &Path,
                execution: &dyn ExecutionAdapter,
                _scope: &ImpactScope,
            ) -> CheckResult {
                integration_tests($language, repo, execution)
            }

            fn run_property_tests(
                &self,
                repo: &Path,
                execution: &dyn ExecutionAdapter,
                _scope: &ImpactScope,
            ) -> CheckResult {
                property_tests($language, repo, execution)
            }

            fn run_ui_verification(
                &self,
                repo: &Path,
                execution: &dyn ExecutionAdapter,
                _scope: &ImpactScope,
            ) -> CheckResult {
                surface_verification(
                    $language,
                    repo,
                    execution,
                    "ui",
                    has_ui_surface($language, repo),
                )
            }

            fn run_api_verification(
                &self,
                repo: &Path,
                execution: &dyn ExecutionAdapter,
                _scope: &ImpactScope,
            ) -> CheckResult {
                surface_verification(
                    $language,
                    repo,
                    execution,
                    "api",
                    has_api_surface($language, repo),
                )
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

impl_adapter!(JavaAdapter, JvmLanguage::Java);
impl_adapter!(KotlinAdapter, JvmLanguage::Kotlin);
impl_adapter!(ScalaAdapter, JvmLanguage::Scala);

fn detect(language: JvmLanguage, repo: &Path) -> Option<LanguageDetection> {
    let sources = source_files(language, repo);
    if sources.is_empty() {
        return None;
    }
    let files = repository_files(repo);
    let manifest = files.iter().any(|path| {
        let name = path.file_name().and_then(|value| value.to_str()).unwrap_or_default();
        match language {
            JvmLanguage::Java => matches!(
                name,
                "pom.xml" | "build.gradle" | "build.gradle.kts" | "gradlew" | "mvnw"
            ),
            JvmLanguage::Kotlin => matches!(
                name,
                "build.gradle.kts" | "settings.gradle.kts" | "gradlew" | "pom.xml" | "mvnw"
            ),
            JvmLanguage::Scala => matches!(name, "build.sbt" | "scala-cli.conf"),
        }
    });
    Some(LanguageDetection {
        adapter_id: language.id().into(),
        language: language.name().into(),
        confidence_percent: if manifest { 100 } else { 90 },
    })
}

fn inventory_symbols(language: JvmLanguage, repo: &Path) -> Result<Vec<SymbolId>, String> {
    let mut symbols = Vec::new();
    for path in source_files(language, repo) {
        let relative = display_relative(repo, &path);
        symbols.push(SymbolId(format!("{}:file:{relative}", language.id())));
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        for line in content.lines() {
            let trimmed = line.trim();
            let padded = format!(" {trimmed} ");
            for (marker, kind) in [
                (" class ", "class"),
                (" interface ", "interface"),
                (" enum ", "enum"),
                (" record ", "record"),
                (" object ", "object"),
                (" trait ", "trait"),
                (" data class ", "class"),
                (" fun ", "function"),
                (" def ", "function"),
            ] {
                if let Some(index) = padded.find(marker) {
                    let rest = &padded[index + marker.len()..];
                    let name = identifier(rest);
                    if !name.is_empty() {
                        symbols.push(SymbolId(format!(
                            "{}:{kind}:{relative}:{name}",
                            language.id()
                        )));
                    }
                }
            }
            if matches!(language, JvmLanguage::Java) {
                if let Some(name) = java_method_name(trimmed) {
                    symbols.push(SymbolId(format!(
                        "{}:method:{relative}:{name}",
                        language.id()
                    )));
                }
            }
        }
    }
    symbols.sort();
    symbols.dedup();
    Ok(symbols)
}

fn run_check(
    language: JvmLanguage,
    check: CheckKind,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
) -> CheckResult {
    match check {
        CheckKind::Build => build_check(language, repo, execution),
        CheckKind::TypeCheck => compile_check(language, repo, execution, check.as_str(), false),
        CheckKind::Lint => lint_check(language, repo, execution),
        CheckKind::Test => run_tests(language, repo, execution),
        CheckKind::Dependencies => dependency_check(language, repo, execution),
        CheckKind::Placeholders => scan_placeholders(language, repo),
        CheckKind::Concurrency => {
            if has_concurrency_surface(language, repo) {
                required_harness(language, repo, execution, check.as_str())
            } else {
                CheckResult::skipped(
                    format!("{}:{}", language.id(), check.as_str()),
                    format!("no {} concurrency surface detected", language.name()),
                )
            }
        }
        CheckKind::Ui => {
            if has_ui_surface(language, repo) {
                required_harness(language, repo, execution, check.as_str())
            } else {
                CheckResult::skipped(
                    format!("{}:{}", language.id(), check.as_str()),
                    format!("no {} UI surface detected", language.name()),
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
        | CheckKind::FormalProof => required_harness(language, repo, execution, check.as_str()),
    }
}

fn build_check(
    language: JvmLanguage,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
) -> CheckResult {
    if let Some(result) = build_system_command(language, repo, execution, "build") {
        return result;
    }
    compile_check(language, repo, execution, "build", false)
}

fn lint_check(
    language: JvmLanguage,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
) -> CheckResult {
    if let Some(result) = build_system_command(language, repo, execution, "lint") {
        return result;
    }
    compile_check(language, repo, execution, "lint", true)
}

fn compile_check(
    language: JvmLanguage,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: &str,
    warnings_as_errors: bool,
) -> CheckResult {
    let mut sources = source_files(language, repo)
        .into_iter()
        .filter(|path| !is_test_source(path))
        .collect::<Vec<_>>();
    if sources.is_empty() {
        sources = source_files(language, repo);
    }
    if sources.is_empty() {
        return CheckResult::unsupported(
            format!("{}:{check_name}", language.id()),
            format!("no {} source files found", language.name()),
        );
    }
    match language {
        JvmLanguage::Java => compile_java(repo, execution, check_name, warnings_as_errors, &sources),
        JvmLanguage::Kotlin => {
            compile_kotlin(repo, execution, check_name, warnings_as_errors, &sources)
        }
        JvmLanguage::Scala => {
            compile_scala(repo, execution, check_name, warnings_as_errors, &sources)
        }
    }
}

fn compile_java(
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: &str,
    warnings_as_errors: bool,
    sources: &[PathBuf],
) -> CheckResult {
    if !executable_available(execution, repo, "javac") {
        return tool_missing(JvmLanguage::Java, check_name, "javac");
    }
    let output = temp_path("verificationforge-java-classes");
    if let Err(error) = fs::create_dir_all(&output) {
        return execution_failure(JvmLanguage::Java, check_name, error.to_string());
    }
    let mut args = vec!["-d".into(), output.to_string_lossy().into_owned()];
    if warnings_as_errors {
        args.extend(["-Xlint:all".into(), "-Werror".into()]);
    } else {
        args.push("-Xlint:all".into());
    }
    args.extend(sources.iter().map(|path| display_relative(repo, path)));
    let result = run_named(
        JvmLanguage::Java,
        execution,
        repo,
        check_name,
        "javac",
        args,
    );
    fs::remove_dir_all(output).ok();
    result
}

fn compile_kotlin(
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: &str,
    warnings_as_errors: bool,
    sources: &[PathBuf],
) -> CheckResult {
    if !executable_available(execution, repo, "kotlinc") {
        return tool_missing(JvmLanguage::Kotlin, check_name, "kotlinc");
    }
    let output = temp_path("verificationforge-kotlin-classes");
    if let Err(error) = fs::create_dir_all(&output) {
        return execution_failure(JvmLanguage::Kotlin, check_name, error.to_string());
    }
    let mut args = sources
        .iter()
        .map(|path| display_relative(repo, path))
        .collect::<Vec<_>>();
    if warnings_as_errors {
        args.push("-Werror".into());
    }
    args.extend(["-d".into(), output.to_string_lossy().into_owned()]);
    let result = run_named(
        JvmLanguage::Kotlin,
        execution,
        repo,
        check_name,
        "kotlinc",
        args,
    );
    fs::remove_dir_all(output).ok();
    result
}

fn compile_scala(
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: &str,
    warnings_as_errors: bool,
    sources: &[PathBuf],
) -> CheckResult {
    if !executable_available(execution, repo, "scala-cli") {
        return tool_missing(JvmLanguage::Scala, check_name, "scala-cli");
    }
    let mut args = vec!["compile".into()];
    args.extend(sources.iter().map(|path| display_relative(repo, path)));
    args.push("--server=false".into());
    if warnings_as_errors {
        args.extend(["--scalac-option".into(), "-Werror".into()]);
    }
    run_named(
        JvmLanguage::Scala,
        execution,
        repo,
        check_name,
        "scala-cli",
        args,
    )
}

fn targeted_tests(
    language: JvmLanguage,
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
        language.extensions().contains(&extension.as_str()) || is_jvm_manifest_path(path)
    });
    if !affected && !scope.requires_full_verification {
        return CheckResult::skipped(
            format!("{}:targeted-test", language.id()),
            format!("no changed {} path maps to this adapter", language.name()),
        );
    }
    if test_files(language, repo).is_empty() && !has_build_system_test(repo) {
        return CheckResult::skipped(
            format!("{}:targeted-test", language.id()),
            format!("affected {} source has no native tests", language.name()),
        );
    }
    rename_check(
        run_tests(language, repo, execution),
        format!("{}:targeted-test", language.id()),
    )
}

fn run_tests(
    language: JvmLanguage,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
) -> CheckResult {
    if let Some(result) = build_system_command(language, repo, execution, "test") {
        return result;
    }
    match language {
        JvmLanguage::Java => direct_java_tests(repo, execution),
        JvmLanguage::Kotlin => direct_kotlin_tests(repo, execution),
        JvmLanguage::Scala => direct_scala_tests(repo, execution),
    }
}

fn direct_java_tests(repo: &Path, execution: &dyn ExecutionAdapter) -> CheckResult {
    if !executable_available(execution, repo, "javac") || !executable_available(execution, repo, "java") {
        return tool_missing(JvmLanguage::Java, "test", "javac/java");
    }
    let tests = test_files(JvmLanguage::Java, repo);
    if tests.is_empty() {
        return required_harness(JvmLanguage::Java, repo, execution, "test");
    }
    let sources = source_files(JvmLanguage::Java, repo)
        .into_iter()
        .filter(|path| !is_test_source(path))
        .collect::<Vec<_>>();
    let output = temp_path("verificationforge-java-test-classes");
    if let Err(error) = fs::create_dir_all(&output) {
        return execution_failure(JvmLanguage::Java, "test", error.to_string());
    }
    let mut args = vec!["-d".into(), output.to_string_lossy().into_owned()];
    args.extend(sources.iter().chain(tests.iter()).map(|path| display_relative(repo, path)));
    let compile = execution.execute("javac", &args, repo);
    match compile {
        Ok(value) if value.success() => {}
        Ok(value) => {
            fs::remove_dir_all(&output).ok();
            return command_failed(JvmLanguage::Java, "test", "javac", &args, &value);
        }
        Err(error) => {
            fs::remove_dir_all(&output).ok();
            return execution_failure(JvmLanguage::Java, "test", error);
        }
    }
    let mut executed = 0usize;
    for test in tests {
        let content = fs::read_to_string(&test).unwrap_or_default();
        if !content.contains("static void main") {
            fs::remove_dir_all(&output).ok();
            return required_harness(JvmLanguage::Java, repo, execution, "test");
        }
        let class_name = java_class_name(&test, &content);
        let run_args = vec![
            "-ea".into(),
            "-cp".into(),
            output.to_string_lossy().into_owned(),
            class_name,
        ];
        match execution.execute("java", &run_args, repo) {
            Ok(value) if value.success() => executed += 1,
            Ok(value) => {
                fs::remove_dir_all(&output).ok();
                return command_failed(JvmLanguage::Java, "test", "java", &run_args, &value);
            }
            Err(error) => {
                fs::remove_dir_all(&output).ok();
                return execution_failure(JvmLanguage::Java, "test", error);
            }
        }
    }
    fs::remove_dir_all(&output).ok();
    CheckResult::pass_with_evidence(
        "java:test",
        format!("native javac/java executable tests passed={executed}"),
    )
}

fn direct_kotlin_tests(repo: &Path, execution: &dyn ExecutionAdapter) -> CheckResult {
    if !executable_available(execution, repo, "kotlinc") || !executable_available(execution, repo, "java") {
        return tool_missing(JvmLanguage::Kotlin, "test", "kotlinc/java");
    }
    let tests = test_files(JvmLanguage::Kotlin, repo);
    if tests.is_empty() {
        return required_harness(JvmLanguage::Kotlin, repo, execution, "test");
    }
    let sources = source_files(JvmLanguage::Kotlin, repo)
        .into_iter()
        .filter(|path| !is_test_source(path))
        .collect::<Vec<_>>();
    let mut executed = 0usize;
    for test in tests {
        let content = fs::read_to_string(&test).unwrap_or_default();
        if !content.contains("fun main(") && !content.contains("fun main()") {
            return required_harness(JvmLanguage::Kotlin, repo, execution, "test");
        }
        let jar = temp_path("verificationforge-kotlin-test").with_extension("jar");
        let mut args = sources
            .iter()
            .chain(std::iter::once(&test))
            .map(|path| display_relative(repo, path))
            .collect::<Vec<_>>();
        args.extend([
            "-include-runtime".into(),
            "-d".into(),
            jar.to_string_lossy().into_owned(),
        ]);
        match execution.execute("kotlinc", &args, repo) {
            Ok(value) if value.success() => {}
            Ok(value) => {
                fs::remove_file(&jar).ok();
                return command_failed(
                    JvmLanguage::Kotlin,
                    "test",
                    "kotlinc",
                    &args,
                    &value,
                );
            }
            Err(error) => {
                fs::remove_file(&jar).ok();
                return execution_failure(JvmLanguage::Kotlin, "test", error);
            }
        }
        let run_args = vec!["-jar".into(), jar.to_string_lossy().into_owned()];
        match execution.execute("java", &run_args, repo) {
            Ok(value) if value.success() => executed += 1,
            Ok(value) => {
                fs::remove_file(&jar).ok();
                return command_failed(JvmLanguage::Kotlin, "test", "java", &run_args, &value);
            }
            Err(error) => {
                fs::remove_file(&jar).ok();
                return execution_failure(JvmLanguage::Kotlin, "test", error);
            }
        }
        fs::remove_file(jar).ok();
    }
    CheckResult::pass_with_evidence(
        "kotlin:test",
        format!("native kotlinc/java executable tests passed={executed}"),
    )
}

fn direct_scala_tests(repo: &Path, execution: &dyn ExecutionAdapter) -> CheckResult {
    if !executable_available(execution, repo, "scala-cli") {
        return tool_missing(JvmLanguage::Scala, "test", "scala-cli");
    }
    if repository_contains(repo, &["munit.", "org.scalatest", "weaver."]) {
        return run_named(
            JvmLanguage::Scala,
            execution,
            repo,
            "test",
            "scala-cli",
            vec!["test".into(), ".".into(), "--server=false".into()],
        );
    }
    let tests = test_files(JvmLanguage::Scala, repo);
    if tests.is_empty() {
        return required_harness(JvmLanguage::Scala, repo, execution, "test");
    }
    let sources = source_files(JvmLanguage::Scala, repo)
        .into_iter()
        .filter(|path| !is_test_source(path))
        .collect::<Vec<_>>();
    let mut executed = 0usize;
    for test in tests {
        let content = fs::read_to_string(&test).unwrap_or_default();
        if !content.contains("@main") && !content.contains("def main(") {
            return required_harness(JvmLanguage::Scala, repo, execution, "test");
        }
        let mut args = vec!["run".into()];
        args.extend(sources.iter().map(|path| display_relative(repo, path)));
        args.push(display_relative(repo, &test));
        args.push("--server=false".into());
        match execution.execute("scala-cli", &args, repo) {
            Ok(value) if value.success() => executed += 1,
            Ok(value) => {
                return command_failed(
                    JvmLanguage::Scala,
                    "test",
                    "scala-cli",
                    &args,
                    &value,
                );
            }
            Err(error) => return execution_failure(JvmLanguage::Scala, "test", error),
        }
    }
    CheckResult::pass_with_evidence(
        "scala:test",
        format!("native scala-cli executable tests passed={executed}"),
    )
}

fn integration_tests(
    language: JvmLanguage,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
) -> CheckResult {
    if test_files(language, repo).iter().any(|path| {
        display_relative(repo, path)
            .to_ascii_lowercase()
            .contains("integration")
    }) {
        rename_check(
            run_tests(language, repo, execution),
            format!("{}:checkpoint-integration", language.id()),
        )
    } else {
        CheckResult::skipped(
            format!("{}:checkpoint-integration", language.id()),
            format!("no {} integration-test surface detected", language.name()),
        )
    }
}

fn property_tests(
    language: JvmLanguage,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
) -> CheckResult {
    let markers: &[&str] = match language {
        JvmLanguage::Java => &["jqwik", "QuickTheory", "junit-quickcheck"],
        JvmLanguage::Kotlin => &["io.kotest.property", "checkAll(", "Arb."],
        JvmLanguage::Scala => &["ScalaCheck", "org.scalacheck", "Gen["],
    };
    if repository_contains(repo, markers) {
        if test_files(language, repo).is_empty() {
            required_harness(language, repo, execution, "checkpoint-property")
        } else {
            rename_check(
                run_tests(language, repo, execution),
                format!("{}:checkpoint-property", language.id()),
            )
        }
    } else {
        CheckResult::skipped(
            format!("{}:checkpoint-property", language.id()),
            format!("no {} property-testing surface detected", language.name()),
        )
    }
}

fn surface_verification(
    language: JvmLanguage,
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
    required_harness(
        language,
        repo,
        execution,
        &format!("checkpoint-{surface}"),
    )
}

fn dependency_check(
    language: JvmLanguage,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
) -> CheckResult {
    if repo.join("mvnw").is_file() {
        return run_named(
            language,
            execution,
            repo,
            "dependencies",
            "./mvnw",
            vec!["-q".into(), "dependency:tree".into()],
        );
    }
    if repo.join("pom.xml").is_file() && executable_available(execution, repo, "mvn") {
        return run_named(
            language,
            execution,
            repo,
            "dependencies",
            "mvn",
            vec!["-q".into(), "dependency:tree".into()],
        );
    }
    if repo.join("gradlew").is_file() {
        return run_named(
            language,
            execution,
            repo,
            "dependencies",
            "./gradlew",
            vec!["dependencies".into(), "--no-daemon".into()],
        );
    }
    if matches!(language, JvmLanguage::Scala)
        && repo.join("build.sbt").is_file()
        && executable_available(execution, repo, "sbt")
    {
        return run_named(
            language,
            execution,
            repo,
            "dependencies",
            "sbt",
            vec!["-batch".into(), "update".into()],
        );
    }
    if !has_dependency_manifest(repo) {
        return CheckResult::pass_with_evidence(
            format!("{}:dependencies", language.id()),
            format!("{} repository has no dependency manifest; native source-only dependency surface is empty", language.name()),
        );
    }
    required_harness(language, repo, execution, "dependencies")
}

fn build_system_command(
    language: JvmLanguage,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    operation: &str,
) -> Option<CheckResult> {
    let check_name = match operation {
        "test" => "test",
        "lint" => "lint",
        _ => "build",
    };
    if repo.join("mvnw").is_file() {
        let goal = match operation {
            "test" => "test",
            "lint" => "verify",
            _ => "package",
        };
        return Some(run_named(
            language,
            execution,
            repo,
            check_name,
            "./mvnw",
            vec!["-q".into(), goal.into(), "-DskipTests=false".into()],
        ));
    }
    if repo.join("pom.xml").is_file() && executable_available(execution, repo, "mvn") {
        let goal = match operation {
            "test" => "test",
            "lint" => "verify",
            _ => "package",
        };
        return Some(run_named(
            language,
            execution,
            repo,
            check_name,
            "mvn",
            vec!["-q".into(), goal.into(), "-DskipTests=false".into()],
        ));
    }
    if repo.join("gradlew").is_file() {
        let task = match operation {
            "test" => "test",
            "lint" => "check",
            _ => "assemble",
        };
        return Some(run_named(
            language,
            execution,
            repo,
            check_name,
            "./gradlew",
            vec![task.into(), "--no-daemon".into()],
        ));
    }
    if matches!(language, JvmLanguage::Scala)
        && repo.join("build.sbt").is_file()
        && executable_available(execution, repo, "sbt")
    {
        let task = match operation {
            "test" => "test",
            "lint" => "compile",
            _ => "compile",
        };
        return Some(run_named(
            language,
            execution,
            repo,
            check_name,
            "sbt",
            vec!["-batch".into(), task.into()],
        ));
    }
    None
}

fn scan_placeholders(language: JvmLanguage, repo: &Path) -> CheckResult {
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
            if lower.contains(&["to", "do:"].concat())
                || lower.contains(&["fix", "me:"].concat())
                || lower.contains(&["x", "xx:"].concat())
                || lower.contains("unsupportedoperationexception(\"not implemented")
                || lower.contains("notimplementederror")
                || lower.contains("???")
            {
                findings.push(Finding {
                    code: "VF_PLACEHOLDER".into(),
                    message: format!(
                        "{}:{} contains an unfinished implementation marker",
                        display_relative(repo, &path),
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
                "scanned {scanned} {} source files for placeholder and fake-success patterns",
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

fn whitespace_format_check(language: JvmLanguage, repo: &Path) -> CheckResult {
    let mut findings = Vec::new();
    let mut scanned = 0usize;
    for path in source_files(language, repo) {
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        scanned += 1;
        for (index, line) in content.lines().enumerate() {
            if line.ends_with(' ') || line.ends_with('\t') {
                findings.push(Finding {
                    code: "VF_FORMAT_TRAILING_WHITESPACE".into(),
                    message: format!(
                        "{}:{} has trailing whitespace",
                        display_relative(repo, &path),
                        index + 1
                    ),
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
            format!("{}:format", language.id()),
            format!(
                "deterministic built-in whitespace format policy files={scanned} violations=0"
            ),
        )
    } else {
        CheckResult {
            check: format!("{}:format", language.id()),
            status: CheckStatus::Fail,
            findings,
        }
    }
}

fn required_harness(
    language: JvmLanguage,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: &str,
) -> CheckResult {
    let harness = format!("{}-{check_name}", language.id());
    run_repository_harness(
        repo,
        execution,
        format!("{}:{check_name}", language.id()),
        &harness,
    )
    .unwrap_or_else(|| {
        CheckResult::unsupported(
            format!("{}:{check_name}", language.id()),
            format!(
                "required {} harness is missing: .verificationforge/{harness}.argv",
                language.name()
            ),
        )
    })
}

fn run_named(
    language: JvmLanguage,
    execution: &dyn ExecutionAdapter,
    repo: &Path,
    check_name: &str,
    program: &str,
    args: Vec<String>,
) -> CheckResult {
    match execution.execute(program, &args, repo) {
        Ok(output) if output.success() => CheckResult::pass_with_evidence(
            format!("{}:{check_name}", language.id()),
            format!("command={program} {} exit=0", args.join(" ")),
        ),
        Ok(output) => command_failed(language, check_name, program, &args, &output),
        Err(error) => execution_failure(language, check_name, error),
    }
}

fn command_failed(
    language: JvmLanguage,
    check_name: &str,
    program: &str,
    args: &[String],
    output: &verificationforge_core::ExecutionResult,
) -> CheckResult {
    CheckResult::fail(
        format!("{}:{check_name}", language.id()),
        "VF_JVM_COMMAND_FAILED",
        format!(
            "command={program} {} exit={} stderr={} stdout={}",
            args.join(" "),
            output.exit_code,
            sanitize_output(&output.stderr),
            sanitize_output(&output.stdout)
        ),
    )
}

fn tool_missing(language: JvmLanguage, check_name: &str, tool: &str) -> CheckResult {
    CheckResult::fail(
        format!("{}:{check_name}", language.id()),
        "VF_JVM_TOOLCHAIN_MISSING",
        format!("{} repository detected but {tool} is not executable", language.name()),
    )
}

fn execution_failure(language: JvmLanguage, check_name: &str, error: String) -> CheckResult {
    CheckResult::fail(
        format!("{}:{check_name}", language.id()),
        "VF_JVM_EXECUTION_FAILED",
        error,
    )
}

fn executable_available(execution: &dyn ExecutionAdapter, repo: &Path, program: &str) -> bool {
    execution
        .execute(program, &["--version".into()], repo)
        .map(|result| result.success())
        .unwrap_or(false)
}

fn source_files(language: JvmLanguage, repo: &Path) -> Vec<PathBuf> {
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

fn test_files(language: JvmLanguage, repo: &Path) -> Vec<PathBuf> {
    source_files(language, repo)
        .into_iter()
        .filter(|path| is_test_source(path))
        .collect()
}

fn is_test_source(path: &Path) -> bool {
    let relative = path.to_string_lossy().replace('\\', "/").to_ascii_lowercase();
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    relative.contains("/src/test/")
        || relative.contains("/test/")
        || relative.contains("/tests/")
        || name.contains("test.")
        || name.ends_with("test.java")
        || name.ends_with("test.kt")
        || name.ends_with("test.scala")
        || name.starts_with("test_")
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
                    | "build"
                    | "out"
                    | ".gradle"
                    | ".idea"
                    | ".bsp"
                    | ".scala-build"
                    | ".metals"
            ) {
                continue;
            }
            visit(&child, depth + 1, files);
        } else if kind.is_file() {
            files.push(child);
        }
    }
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

fn has_concurrency_surface(language: JvmLanguage, repo: &Path) -> bool {
    let markers: &[&str] = match language {
        JvmLanguage::Java => &[
            "java.util.concurrent",
            "Thread(",
            "synchronized",
            "CompletableFuture",
        ],
        JvmLanguage::Kotlin => &[
            "kotlinx.coroutines",
            "launch {",
            "async {",
            "Dispatchers.",
        ],
        JvmLanguage::Scala => &[
            "scala.concurrent",
            "Future {",
            "ExecutionContext",
            "cats.effect",
            "ZIO[",
        ],
    };
    repository_contains(repo, markers)
}

fn has_ui_surface(language: JvmLanguage, repo: &Path) -> bool {
    let markers: &[&str] = match language {
        JvmLanguage::Java => &["javax.swing", "javafx.", "android.app", "androidx."],
        JvmLanguage::Kotlin => &[
            "androidx.compose",
            "android.app",
            "androidx.activity",
            "javafx.",
        ],
        JvmLanguage::Scala => &["scalafx.", "javafx.", "slinky.", "Laminar"],
    };
    repository_contains(repo, markers)
}

fn has_api_surface(language: JvmLanguage, repo: &Path) -> bool {
    let markers: &[&str] = match language {
        JvmLanguage::Java => &[
            "org.springframework.web",
            "jakarta.ws.rs",
            "javax.ws.rs",
            "HttpServer.create",
        ],
        JvmLanguage::Kotlin => &[
            "io.ktor.server",
            "org.springframework.web",
            "routing {",
            "embeddedServer(",
        ],
        JvmLanguage::Scala => &[
            "http4s",
            "akka.http",
            "pekko.http",
            "cask.MainRoutes",
            "tapir.",
        ],
    };
    repository_contains(repo, markers)
}

fn has_dependency_manifest(repo: &Path) -> bool {
    repository_files(repo).iter().any(|path| {
        matches!(
            path.file_name().and_then(|value| value.to_str()),
            Some(
                "pom.xml"
                    | "build.gradle"
                    | "build.gradle.kts"
                    | "settings.gradle"
                    | "settings.gradle.kts"
                    | "build.sbt"
            )
        )
    })
}

fn has_build_system_test(repo: &Path) -> bool {
    has_dependency_manifest(repo) || repo.join("gradlew").is_file() || repo.join("mvnw").is_file()
}

fn is_jvm_manifest_path(path: &str) -> bool {
    matches!(
        Path::new(path).file_name().and_then(|value| value.to_str()),
        Some(
            "pom.xml"
                | "build.gradle"
                | "build.gradle.kts"
                | "settings.gradle"
                | "settings.gradle.kts"
                | "build.sbt"
                | "gradlew"
                | "mvnw"
        )
    )
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
            || lower.contains("= true")
            || lower.contains("= false"))
}

fn java_class_name(path: &Path, content: &str) -> String {
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("Test")
        .to_owned();
    let package = content.lines().find_map(|line| {
        let trimmed = line.trim();
        trimmed
            .strip_prefix("package ")
            .and_then(|rest| rest.strip_suffix(';'))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    });
    package.map_or(stem.clone(), |package| format!("{package}.{stem}"))
}

fn java_method_name(line: &str) -> Option<&str> {
    if !line.contains('(') || line.starts_with("if ") || line.starts_with("for ") {
        return None;
    }
    let open = line.find('(')?;
    let before = line[..open].trim_end();
    let candidate = before.split_whitespace().last()?;
    let candidate = candidate.trim_matches(|character: char| character == '<' || character == '>');
    if candidate.is_empty()
        || matches!(candidate, "if" | "for" | "while" | "switch" | "catch" | "new")
    {
        None
    } else {
        Some(candidate)
    }
}

fn identifier(value: &str) -> &str {
    let value = value.trim_start_matches(|character: char| character.is_whitespace() || character == '`');
    let end = value
        .find(|character: char| {
            !(character.is_ascii_alphanumeric() || character == '_' || character == '$')
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

fn temp_path(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    std::env::temp_dir().join(format!("{prefix}-{}-{nonce}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("verificationforge-jvm-family-{name}-{nonce}"))
    }

    #[test]
    fn java_kotlin_and_scala_detect_independently() {
        let root = fixture("mixed");
        fs::create_dir_all(&root).expect("create root");
        fs::write(root.join("A.java"), "class A {}\n").expect("write java");
        fs::write(root.join("B.kt"), "class B\n").expect("write kotlin");
        fs::write(root.join("C.scala"), "class C\n").expect("write scala");
        assert_eq!(JavaAdapter.detect(&root).expect("java").language, "Java");
        assert_eq!(KotlinAdapter.detect(&root).expect("kotlin").language, "Kotlin");
        assert_eq!(ScalaAdapter.detect(&root).expect("scala").language, "Scala");
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn constant_authorization_is_blocked() {
        let root = fixture("fake-auth");
        fs::create_dir_all(&root).expect("create root");
        fs::write(
            root.join("Auth.java"),
            "class Auth { boolean authorize(String user) { return true; } }\n",
        )
        .expect("write source");
        let result = scan_placeholders(JvmLanguage::Java, &root);
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.has_blocking_finding());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn built_in_format_policy_is_evidence_backed() {
        let root = fixture("format");
        fs::create_dir_all(&root).expect("create root");
        fs::write(root.join("A.kt"), "class A\n").expect("write source");
        let result = whitespace_format_check(JvmLanguage::Kotlin, &root);
        assert_eq!(result.status, CheckStatus::Pass);
        assert!(result.has_reproducible_evidence());
        fs::remove_dir_all(root).ok();
    }
}
