use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use verificationforge_core::{CheckResult, ExecutionAdapter, ImpactScope, run_repository_harness};

use super::{cargo_package_name, display_relative, has_ui_assets, run_named_command, source_files};

pub(crate) fn run_integration_tests(
    execution: &dyn ExecutionAdapter,
    repo: &Path,
    scope: &ImpactScope,
) -> CheckResult {
    if !scope.requires_full_verification && rust_target_paths(scope).is_empty() {
        return CheckResult::skipped(
            "rust:checkpoint-integration",
            "no affected Rust/Cargo path requires integration verification",
        );
    }

    if scope.requires_full_verification {
        if !repository_has_integration_tests(repo) {
            return CheckResult::unsupported(
                "rust:checkpoint-integration",
                "checkpoint requires integration tests but no Rust integration-test target was discovered",
            );
        }
        return run_named_command(
            execution,
            repo,
            "rust:checkpoint-integration",
            "cargo",
            &["test", "--workspace", "--tests", "--locked"],
        );
    }

    let Some(packages) = checkpoint_packages(repo, scope) else {
        return CheckResult::unsupported(
            "rust:checkpoint-integration",
            "affected Rust packages could not be mapped for integration verification",
        );
    };
    for (package, root) in &packages {
        if !package_has_integration_tests(root) {
            return CheckResult::unsupported(
                "rust:checkpoint-integration",
                format!("affected package {package} has no integration-test target"),
            );
        }
        let args = vec![
            "test".to_owned(),
            "--package".to_owned(),
            package.clone(),
            "--tests".to_owned(),
            "--locked".to_owned(),
        ];
        match execution.execute("cargo", &args, repo) {
            Ok(output) if output.success() => {}
            Ok(output) => {
                return CheckResult::fail(
                    "rust:checkpoint-integration",
                    "VF_CHECKPOINT_INTEGRATION_FAILED",
                    command_failure("integration tests", package, &output),
                );
            }
            Err(error) => {
                return CheckResult::fail(
                    "rust:checkpoint-integration",
                    "VF_EXECUTION_FAILED",
                    error,
                );
            }
        }
    }

    CheckResult::pass_with_evidence(
        "rust:checkpoint-integration",
        format!(
            "affected Rust integration tests passed packages={}",
            package_names(&packages)
        ),
    )
}

pub(crate) fn run_property_tests(
    execution: &dyn ExecutionAdapter,
    repo: &Path,
    scope: &ImpactScope,
) -> CheckResult {
    if !scope.requires_full_verification && rust_target_paths(scope).is_empty() {
        return CheckResult::skipped(
            "rust:checkpoint-property",
            "no affected Rust/Cargo path requires property verification",
        );
    }

    if scope.requires_full_verification {
        if !source_has_property_markers(repo) {
            return CheckResult::unsupported(
                "rust:checkpoint-property",
                "checkpoint requires property verification but no Rust property-test markers were discovered",
            );
        }
        return run_named_command(
            execution,
            repo,
            "rust:checkpoint-property",
            "cargo",
            &["test", "--workspace", "--all-targets", "--locked"],
        );
    }

    let Some(packages) = checkpoint_packages(repo, scope) else {
        return CheckResult::unsupported(
            "rust:checkpoint-property",
            "affected Rust packages could not be mapped for property verification",
        );
    };
    for (package, root) in &packages {
        if !source_has_property_markers(root) {
            return CheckResult::unsupported(
                "rust:checkpoint-property",
                format!("affected package {package} has no property-test marker"),
            );
        }
        let args = vec![
            "test".to_owned(),
            "--package".to_owned(),
            package.clone(),
            "--all-targets".to_owned(),
            "--locked".to_owned(),
        ];
        match execution.execute("cargo", &args, repo) {
            Ok(output) if output.success() => {}
            Ok(output) => {
                return CheckResult::fail(
                    "rust:checkpoint-property",
                    "VF_CHECKPOINT_PROPERTY_FAILED",
                    command_failure("property verification", package, &output),
                );
            }
            Err(error) => {
                return CheckResult::fail("rust:checkpoint-property", "VF_EXECUTION_FAILED", error);
            }
        }
    }

    CheckResult::pass_with_evidence(
        "rust:checkpoint-property",
        format!(
            "affected Rust property verification passed packages={}",
            package_names(&packages)
        ),
    )
}

pub(crate) fn run_ui_verification(
    execution: &dyn ExecutionAdapter,
    repo: &Path,
    scope: &ImpactScope,
) -> CheckResult {
    if !scope_has_ui_surface(repo, scope) {
        return CheckResult::skipped(
            "rust:checkpoint-ui",
            "no affected Rust/UI surface was detected for this checkpoint",
        );
    }
    run_repository_harness(repo, execution, "rust:checkpoint-ui", "checkpoint-ui").unwrap_or_else(
        || {
            CheckResult::unsupported(
                "rust:checkpoint-ui",
                "affected UI surface detected but .verificationforge/checkpoint-ui.argv is missing",
            )
        },
    )
}

pub(crate) fn run_api_verification(
    execution: &dyn ExecutionAdapter,
    repo: &Path,
    scope: &ImpactScope,
) -> CheckResult {
    if !scope_has_api_surface(repo, scope) {
        return CheckResult::skipped(
            "rust:checkpoint-api",
            "no affected API/protocol surface was detected for this checkpoint",
        );
    }
    run_repository_harness(
        repo,
        execution,
        "rust:checkpoint-api",
        "checkpoint-api",
    )
    .unwrap_or_else(|| {
        CheckResult::unsupported(
            "rust:checkpoint-api",
            "affected API surface detected but .verificationforge/checkpoint-api.argv is missing",
        )
    })
}

fn rust_target_paths(scope: &ImpactScope) -> BTreeSet<String> {
    let mut paths = scope
        .changed_paths
        .iter()
        .filter(|path| rust_relevant_path(path))
        .cloned()
        .collect::<BTreeSet<_>>();
    for symbol in &scope.affected_symbols {
        if let Some(path) = symbol.0.strip_prefix("rust:file:") {
            paths.insert(path.to_owned());
        }
    }
    paths
}

fn rust_relevant_path(relative: &str) -> bool {
    let path = Path::new(relative);
    path.extension().and_then(|value| value.to_str()) == Some("rs")
        || path
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|name| matches!(name, "Cargo.toml" | "Cargo.lock"))
}

fn rust_package_info_for_path(repo: &Path, relative: &str) -> Option<(String, PathBuf)> {
    let absolute = repo.join(relative);
    let mut directory = if absolute.is_dir() {
        absolute
    } else {
        absolute.parent()?.to_path_buf()
    };
    loop {
        let manifest = directory.join("Cargo.toml");
        if manifest.is_file()
            && let Ok(content) = fs::read_to_string(&manifest)
            && let Some(name) = cargo_package_name(&content)
        {
            return Some((name, directory));
        }
        if directory == repo {
            break;
        }
        let parent = directory.parent()?;
        if !parent.starts_with(repo) {
            break;
        }
        directory = parent.to_path_buf();
    }
    None
}

fn checkpoint_packages(repo: &Path, scope: &ImpactScope) -> Option<BTreeSet<(String, PathBuf)>> {
    let paths = rust_target_paths(scope);
    if paths.is_empty() {
        return None;
    }
    let mut packages = BTreeSet::new();
    for path in paths {
        packages.insert(rust_package_info_for_path(repo, &path)?);
    }
    Some(packages)
}

fn package_has_integration_tests(root: &Path) -> bool {
    !source_files(&root.join("tests"), "rs").is_empty()
}

fn repository_has_integration_tests(repo: &Path) -> bool {
    source_files(repo, "rs").iter().any(|path| {
        path.strip_prefix(repo).is_ok_and(|relative| {
            relative
                .components()
                .any(|part| part.as_os_str().to_string_lossy() == "tests")
        })
    })
}

fn source_has_property_markers(root: &Path) -> bool {
    source_files(root, "rs").iter().any(|path| {
        fs::read_to_string(path).is_ok_and(|content| {
            [
                "proptest!",
                "quickcheck!",
                "#[quickcheck]",
                "fn property_",
                "fn prop_",
            ]
            .iter()
            .any(|marker| content.contains(marker))
        })
    })
}

fn package_names(packages: &BTreeSet<(String, PathBuf)>) -> String {
    packages
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

fn command_failure(
    label: &str,
    package: &str,
    output: &verificationforge_core::ExecutionResult,
) -> String {
    let detail = if output.stderr.trim().is_empty() {
        output.stdout.trim()
    } else {
        output.stderr.trim()
    };
    format!(
        "cargo {label} for {package} exited with code {}{}{}",
        output.exit_code,
        if detail.is_empty() { "" } else { ": " },
        detail.chars().take(4000).collect::<String>()
    )
}

fn scope_has_ui_surface(repo: &Path, scope: &ImpactScope) -> bool {
    if scope.requires_full_verification {
        return has_ui_assets(repo);
    }
    scoped_paths(scope).iter().any(|relative| {
        let path = Path::new(relative);
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        if ["html", "css", "js", "ts", "tsx", "jsx"].contains(&extension)
            || path.components().any(|item| {
                ["ui", "web", "frontend", "templates", "static"]
                    .contains(&item.as_os_str().to_string_lossy().as_ref())
            })
        {
            return true;
        }
        extension == "rs"
            && fs::read_to_string(repo.join(relative)).is_ok_and(|content| {
                [
                    "yew::", "leptos::", "dioxus::", "egui::", "iced::", "tauri::",
                ]
                .iter()
                .any(|marker| content.contains(marker))
            })
    })
}

fn scope_has_api_surface(repo: &Path, scope: &ImpactScope) -> bool {
    let markers = [
        "axum::",
        "actix_web::",
        "rocket::",
        "warp::",
        "tonic::",
        "jsonrpsee",
        "Router::new",
        "TcpListener",
        "#[get(",
        "#[post(",
        "utoipa::",
    ];
    if scope.requires_full_verification {
        return source_files(repo, "rs").iter().any(|path| {
            fs::read_to_string(path)
                .is_ok_and(|content| markers.iter().any(|marker| content.contains(marker)))
        }) || repository_has_api_descriptor(repo);
    }

    scoped_paths(scope).iter().any(|relative| {
        let lower = relative.to_ascii_lowercase();
        if lower.ends_with(".proto") || lower.contains("openapi") || lower.contains("swagger") {
            return true;
        }
        Path::new(relative)
            .extension()
            .and_then(|value| value.to_str())
            == Some("rs")
            && fs::read_to_string(repo.join(relative))
                .is_ok_and(|content| markers.iter().any(|marker| content.contains(marker)))
    })
}

fn scoped_paths(scope: &ImpactScope) -> BTreeSet<String> {
    let mut paths = scope.changed_paths.clone();
    for symbol in &scope.affected_symbols {
        if let Some(path) = symbol.0.strip_prefix("rust:file:") {
            paths.insert(path.to_owned());
        }
    }
    paths
}

fn repository_has_api_descriptor(repo: &Path) -> bool {
    let mut stack = vec![repo.to_path_buf()];
    let mut depth = 0usize;
    while let Some(directory) = stack.pop() {
        if depth > 4096 {
            return false;
        }
        depth += 1;
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_symlink() {
                continue;
            }
            if kind.is_dir() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if !matches!(name.as_ref(), ".git" | "target" | "vendor" | "node_modules") {
                    stack.push(path);
                }
                continue;
            }
            if !kind.is_file() {
                continue;
            }
            let relative = display_relative(repo, &path).to_ascii_lowercase();
            if relative.ends_with(".proto")
                || relative.contains("openapi")
                || relative.contains("swagger")
            {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};
    use verificationforge_core::SymbolId;

    #[derive(Default)]
    struct RecordingExecution {
        calls: Mutex<Vec<(String, Vec<String>)>>,
    }

    impl ExecutionAdapter for RecordingExecution {
        fn id(&self) -> &'static str {
            "checkpoint-recording"
        }

        fn execute(
            &self,
            program: &str,
            args: &[String],
            _cwd: &Path,
        ) -> Result<verificationforge_core::ExecutionResult, String> {
            self.calls
                .lock()
                .expect("calls lock poisoned")
                .push((program.into(), args.to_vec()));
            Ok(verificationforge_core::ExecutionResult {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    fn temp_dir() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("verificationforge-rust-checkpoint-{nonce}"))
    }

    fn package_fixture(root: &Path) {
        fs::create_dir_all(root.join("src")).expect("create src");
        fs::create_dir_all(root.join("tests")).expect("create tests");
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"checkpoint-demo\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("write manifest");
        fs::write(
            root.join("src/lib.rs"),
            "pub fn value(input: u8) -> u8 { input }\n#[cfg(test)] mod tests { #[test] fn property_identity() { for value in 0..=10 { assert_eq!(super::value(value), value); } } }\n",
        )
        .expect("write source");
        fs::write(
            root.join("tests/integration.rs"),
            "#[test] fn integration_path() { assert_eq!(2 + 2, 4); }\n",
        )
        .expect("write integration");
    }

    fn scope() -> ImpactScope {
        ImpactScope {
            changed_paths: ["src/lib.rs".into()].into_iter().collect(),
            affected_symbols: [SymbolId("rust:file:src/lib.rs".into())]
                .into_iter()
                .collect(),
            requires_full_verification: false,
        }
    }

    #[test]
    fn affected_package_runs_integration_and_property_verification() {
        let root = temp_dir();
        package_fixture(&root);
        let execution = RecordingExecution::default();
        let integration = run_integration_tests(&execution, &root, &scope());
        let property = run_property_tests(&execution, &root, &scope());
        assert_eq!(
            integration.status,
            verificationforge_core::CheckStatus::Pass
        );
        assert_eq!(property.status, verificationforge_core::CheckStatus::Pass);
        assert!(integration.has_reproducible_evidence());
        assert!(property.has_reproducible_evidence());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn missing_property_marker_fails_closed() {
        let root = temp_dir();
        package_fixture(&root);
        fs::write(root.join("src/lib.rs"), "pub fn value() -> u8 { 1 }\n").expect("replace source");
        let result = run_property_tests(&RecordingExecution::default(), &root, &scope());
        assert_eq!(
            result.status,
            verificationforge_core::CheckStatus::Unsupported
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn affected_api_without_harness_is_not_silently_skipped() {
        let root = temp_dir();
        package_fixture(&root);
        fs::write(
            root.join("src/lib.rs"),
            "pub fn route_marker() { let _ = \"axum::Router::new\"; }\n",
        )
        .expect("write api marker");
        let result = run_api_verification(&RecordingExecution::default(), &root, &scope());
        assert_eq!(
            result.status,
            verificationforge_core::CheckStatus::Unsupported
        );
        fs::remove_dir_all(root).ok();
    }
}
