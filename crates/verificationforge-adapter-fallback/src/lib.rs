use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use verificationforge_core::{
    CheckKind, CheckResult, CheckStatus, ExecutionAdapter, Finding, LanguageAdapter,
    LanguageDetection, SymbolId, run_repository_harness,
};

const MAX_SCAN_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug)]
pub struct LanguageProfile {
    pub id: &'static str,
    pub language: &'static str,
    pub extensions: &'static [&'static str],
    pub manifests: &'static [&'static str],
}

#[derive(Debug, Clone, Copy)]
pub struct FallbackLanguageAdapter {
    profile: &'static LanguageProfile,
}

impl FallbackLanguageAdapter {
    pub const fn new(profile: &'static LanguageProfile) -> Self {
        Self { profile }
    }

    fn harness_name(&self, check: CheckKind) -> String {
        format!("{}-{}", self.profile.id, check.as_str())
    }

    fn name(&self, check: CheckKind) -> String {
        format!("{}:{}", self.profile.id, check.as_str())
    }

    fn required_harness(
        &self,
        check: CheckKind,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
    ) -> CheckResult {
        let harness = self.harness_name(check);
        run_repository_harness(repo, execution, self.name(check), &harness).unwrap_or_else(|| {
            CheckResult::fail(
                self.name(check),
                "VF_FALLBACK_HARNESS_REQUIRED",
                format!(
                    "{} fallback verification requires .verificationforge/{harness}.argv; native first-class adapter not installed",
                    self.profile.language
                ),
            )
        })
    }
}

impl LanguageAdapter for FallbackLanguageAdapter {
    fn id(&self) -> &'static str {
        self.profile.id
    }

    fn detect(&self, repo: &Path) -> Option<LanguageDetection> {
        let files = repository_files(repo);
        let manifest = files.iter().any(|path| {
            path.file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|name| self.profile.manifests.contains(&name))
        });
        let source = files
            .iter()
            .any(|path| path_extension_matches(path, self.profile.extensions));
        source.then(|| LanguageDetection {
            adapter_id: self.profile.id.into(),
            language: self.profile.language.into(),
            confidence_percent: if manifest { 95 } else { 75 },
        })
    }

    fn inventory_symbols(&self, repo: &Path) -> Result<Vec<SymbolId>, String> {
        let mut symbols = repository_files(repo)
            .into_iter()
            .filter(|path| path_extension_matches(path, self.profile.extensions))
            .filter_map(|path| {
                path.strip_prefix(repo)
                    .ok()
                    .map(|relative| relative.to_string_lossy().replace('\\', "/"))
            })
            .map(|relative| SymbolId(format!("{}:file:{relative}", self.profile.id)))
            .collect::<Vec<_>>();
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
            CheckKind::Placeholders => scan_placeholders(self.profile, repo),
            _ => self.required_harness(check, repo, execution),
        }
    }
}

pub fn builtin_fallback_adapters() -> Vec<Arc<dyn LanguageAdapter>> {
    PROFILES
        .iter()
        .map(|profile| Arc::new(FallbackLanguageAdapter::new(profile)) as Arc<dyn LanguageAdapter>)
        .collect()
}

fn scan_placeholders(profile: &LanguageProfile, repo: &Path) -> CheckResult {
    let mut findings = Vec::new();
    let mut scanned = 0usize;
    for path in repository_files(repo)
        .into_iter()
        .filter(|path| path_extension_matches(path, profile.extensions))
    {
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
            if let Some(marker) = placeholder_marker(line) {
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
            format!("{}:placeholders", profile.id),
            format!(
                "generic placeholder scan language={} files={scanned} findings=0",
                profile.language
            ),
        )
    } else {
        CheckResult {
            check: format!("{}:placeholders", profile.id),
            status: CheckStatus::Fail,
            findings,
        }
    }
}

fn placeholder_marker(line: &str) -> Option<&'static str> {
    let lower = line.to_ascii_lowercase();
    if lower.contains(&["to", "do:"].concat()) || lower.contains(&["to", "do!("].concat()) {
        return Some("TODO");
    }
    if lower.contains(&["fix", "me:"].concat()) {
        return Some("FIXME");
    }
    if lower.contains(&["x", "xx:"].concat()) {
        return Some("XXX");
    }
    if lower.contains(&["unimplemented", "!("].concat()) {
        return Some("unimplemented");
    }
    if lower.contains("notimplemented") || lower.contains("not implemented") {
        return Some("NotImplemented");
    }
    if lower.contains("placeholder implementation") || lower.contains("stub implementation") {
        return Some("stub");
    }
    None
}

fn path_extension_matches(path: &Path, extensions: &[&str]) -> bool {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    extensions.iter().any(|candidate| *candidate == extension)
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
    )
}

fn display_relative(repo: &Path, path: &Path) -> String {
    path.strip_prefix(repo)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

macro_rules! profile {
    ($id:literal, $language:literal, [$($extension:literal),* $(,)?], [$($manifest:literal),* $(,)?]) => {
        LanguageProfile {
            id: $id,
            language: $language,
            extensions: &[$($extension),*],
            manifests: &[$($manifest),*],
        }
    };
}

#[rustfmt::skip]
pub static PROFILES: &[LanguageProfile] = &[
    profile!("c", "C", ["c", "h"], ["CMakeLists.txt", "Makefile", "meson.build"]),
    profile!("cpp", "C++", ["cc", "cpp", "cxx", "hh", "hpp", "hxx"], ["CMakeLists.txt", "Makefile", "meson.build"]),
    profile!("csharp", "C#", ["cs", "csx"], ["global.json", "Directory.Build.props"]),
    profile!("java", "Java", ["java"], ["pom.xml", "build.gradle", "build.gradle.kts", "gradlew"]),
    profile!("kotlin", "Kotlin", ["kt", "kts"], ["build.gradle.kts", "settings.gradle.kts", "gradlew"]),
    profile!("scala", "Scala", ["scala", "sc"], ["build.sbt"]),
    profile!("go", "Go", ["go"], ["go.mod", "go.work"]),
    profile!("javascript", "JavaScript", ["js", "jsx", "mjs", "cjs"], ["package.json"]),
    profile!("typescript", "TypeScript", ["ts", "tsx", "mts", "cts"], ["tsconfig.json"]),
    profile!("swift", "Swift", ["swift"], ["Package.swift"]),
    profile!("objective-c", "Objective-C", ["m", "mm"], ["Podfile"]),
    profile!("dart", "Dart", ["dart"], ["pubspec.yaml"]),
    profile!("php", "PHP", ["php", "phtml"], ["composer.json"]),
    profile!("ruby", "Ruby", ["rb", "rake"], ["Gemfile", "Rakefile"]),
    profile!("lua", "Lua", ["lua"], ["rockspec"]),
    profile!("perl", "Perl", ["pl", "pm", "t"], ["Makefile.PL", "Build.PL", "cpanfile"]),
    profile!("r", "R", ["r", "rmd"], ["DESCRIPTION", "renv.lock"]),
    profile!("julia", "Julia", ["jl"], ["Project.toml", "Manifest.toml"]),
    profile!("haskell", "Haskell", ["hs", "lhs"], ["stack.yaml", "cabal.project"]),
    profile!("ocaml", "OCaml", ["ml", "mli"], ["dune-project", "opam"]),
    profile!("fsharp", "F#", ["fs", "fsi", "fsx"], ["global.json"]),
    profile!("elixir", "Elixir", ["ex", "exs"], ["mix.exs"]),
    profile!("erlang", "Erlang", ["erl", "hrl"], ["rebar.config", "rebar.lock"]),
    profile!("zig", "Zig", ["zig"], ["build.zig", "build.zig.zon"]),
    profile!("nim", "Nim", ["nim", "nims"], ["nimble"]),
    profile!("d", "D", ["d", "di"], ["dub.json", "dub.sdl"]),
    profile!("fortran", "Fortran", ["f", "for", "f90", "f95", "f03", "f08"], ["fpm.toml"]),
    profile!("cobol", "COBOL", ["cob", "cbl", "cpy"], []),
    profile!("bash", "Bash", ["sh", "bash"], []),
    profile!("powershell", "PowerShell", ["ps1", "psm1", "psd1"], []),
    profile!("sql", "SQL", ["sql"], []),
    profile!("solidity", "Solidity", ["sol"], ["foundry.toml", "hardhat.config.js", "hardhat.config.ts"]),
    profile!("vyper", "Vyper", ["vy"], ["ape-config.yaml", "brownie-config.yaml"]),
    profile!("move", "Move", ["move"], ["Move.toml"]),
    profile!("cairo", "Cairo", ["cairo"], ["Scarb.toml"]),
    profile!("html-css", "HTML/CSS", ["html", "htm", "css", "scss", "sass", "less"], []),
    profile!("glsl", "GLSL", ["glsl", "vert", "frag", "geom", "comp", "tesc", "tese"], []),
    profile!("hlsl", "HLSL", ["hlsl", "fx", "fxh"], []),
    profile!("wgsl", "WGSL", ["wgsl"], []),
];

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
        std::env::temp_dir().join(format!("verificationforge-fallback-{name}-{nonce}"))
    }

    fn profile(id: &str) -> &'static LanguageProfile {
        PROFILES
            .iter()
            .find(|profile| profile.id == id)
            .expect("profile exists")
    }

    #[test]
    fn detects_unrelated_languages_without_core_changes() {
        let root = temp_dir("mixed");
        fs::create_dir_all(root.join("web")).expect("create web");
        fs::write(root.join("go.mod"), "module example.test/demo\n").expect("write go.mod");
        fs::write(root.join("main.go"), "package main\nfunc main() {}\n").expect("write go");
        fs::write(root.join("web/app.ts"), "export const value: number = 1;\n").expect("write ts");
        fs::write(root.join("web/tsconfig.json"), "{}\n").expect("write tsconfig");

        let go = FallbackLanguageAdapter::new(profile("go"));
        let typescript = FallbackLanguageAdapter::new(profile("typescript"));
        assert_eq!(go.detect(&root).expect("go detected").language, "Go");
        assert_eq!(
            typescript
                .detect(&root)
                .expect("typescript detected")
                .language,
            "TypeScript"
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn shared_manifest_does_not_create_false_language_detection() {
        let root = temp_dir("manifest-only");
        fs::create_dir_all(&root).expect("create root");
        fs::write(root.join("CMakeLists.txt"), "project(demo)\n").expect("write cmake");
        fs::write(root.join("main.c"), "int main(void) { return 0; }\n").expect("write c");

        let c = FallbackLanguageAdapter::new(profile("c"));
        let cpp = FallbackLanguageAdapter::new(profile("cpp"));
        assert!(c.detect(&root).is_some());
        assert!(cpp.detect(&root).is_none());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn fallback_requires_real_per_language_harness() {
        let root = temp_dir("required-harness");
        fs::create_dir_all(&root).expect("create root");
        fs::write(root.join("main.go"), "package main\n").expect("write go");
        let adapter = FallbackLanguageAdapter::new(profile("go"));
        let execution = RecordingExecution::default();
        let result = adapter.run_check(CheckKind::Build, &root, &execution);
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.code == "VF_FALLBACK_HARNESS_REQUIRED")
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn fallback_harness_preserves_argv_and_emits_evidence() {
        let root = temp_dir("harness");
        fs::create_dir_all(root.join(".verificationforge")).expect("create harness dir");
        fs::write(root.join("main.go"), "package main\n").expect("write go");
        fs::write(
            root.join(".verificationforge/go-build.argv"),
            "go\nbuild\n./...\n",
        )
        .expect("write harness");
        let adapter = FallbackLanguageAdapter::new(profile("go"));
        let execution = RecordingExecution::default();
        let result = adapter.run_check(CheckKind::Build, &root, &execution);
        assert_eq!(result.status, CheckStatus::Pass);
        assert!(result.has_reproducible_evidence());
        assert_eq!(
            execution
                .calls
                .lock()
                .expect("calls lock poisoned")
                .as_slice(),
            &[("go".into(), vec!["build".into(), "./...".into()])]
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn generic_placeholder_scan_blocks_explicit_stubs() {
        let root = temp_dir("placeholders");
        fs::create_dir_all(&root).expect("create root");
        let marker = ["FIX", "ME:"].concat();
        fs::write(
            root.join("main.go"),
            format!("package main\n// {marker} implement auth\n"),
        )
        .expect("write go");
        let adapter = FallbackLanguageAdapter::new(profile("go"));
        let result = adapter.run_check(
            CheckKind::Placeholders,
            &root,
            &RecordingExecution::default(),
        );
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.has_blocking_finding());
        fs::remove_dir_all(root).ok();
    }
}
