use std::path::Path;

use verificationforge_core::{
    CheckKind, CheckResult, CheckStatus, ImpactScope, LanguageDetection, UniversalCodeGraph,
};

use crate::{ContentAddress, ImpactPlan, RepositorySnapshot, VerificationEngine, plan_impact};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PatchGatePhase {
    Parse,
    Format,
    Build,
    TypeCheck,
    Lint,
    Secrets,
    Placeholders,
    Impact,
    TargetedTests,
}

impl PatchGatePhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Parse => "parse",
            Self::Format => "format",
            Self::Build => "build",
            Self::TypeCheck => "type-check",
            Self::Lint => "lint",
            Self::Secrets => "secrets",
            Self::Placeholders => "placeholders",
            Self::Impact => "impact",
            Self::TargetedTests => "targeted-tests",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PatchGateEntry {
    pub phase: PatchGatePhase,
    pub adapter_id: String,
    pub language: String,
    pub result: CheckResult,
}

#[derive(Debug, Clone)]
pub struct PatchGateReport {
    pub baseline_address: ContentAddress,
    pub current_address: ContentAddress,
    pub detections: Vec<LanguageDetection>,
    pub impact: ImpactPlan,
    pub entries: Vec<PatchGateEntry>,
    pub accepted: bool,
}

pub struct PatchGate;

impl PatchGate {
    pub fn verify(
        engine: &VerificationEngine,
        repo: &Path,
        baseline: &RepositorySnapshot,
        graph: &UniversalCodeGraph,
    ) -> Result<PatchGateReport, String> {
        let current = RepositorySnapshot::capture(repo)?;
        let baseline_address = baseline
            .address
            .clone()
            .ok_or_else(|| "patch baseline snapshot is missing its content address".to_owned())?;
        let current_address = current
            .address
            .clone()
            .ok_or_else(|| "current repository snapshot is missing its content address".to_owned())?;
        let diff = baseline.diff(&current);
        let impact = plan_impact(&diff, graph);
        let scope = ImpactScope {
            changed_paths: impact.changed_paths.clone(),
            affected_symbols: impact.affected_symbols.clone(),
            requires_full_verification: impact.requires_full_verification,
        };
        let detections = engine.registry.detect(repo);
        if detections.is_empty() {
            return Ok(PatchGateReport {
                baseline_address,
                current_address,
                detections,
                impact,
                entries: vec![PatchGateEntry {
                    phase: PatchGatePhase::Parse,
                    adapter_id: "runtime".into(),
                    language: "unknown".into(),
                    result: CheckResult::fail(
                        "patch:language-detection",
                        "VF_NO_LANGUAGE",
                        "no registered language adapter recognized this repository",
                    ),
                }],
                accepted: false,
            });
        }

        let mut entries = Vec::new();
        for detection in &detections {
            let Some(adapter) = engine.registry.adapter(&detection.adapter_id) else {
                entries.push(PatchGateEntry {
                    phase: PatchGatePhase::Parse,
                    adapter_id: detection.adapter_id.clone(),
                    language: detection.language.clone(),
                    result: CheckResult::fail(
                        "patch:adapter-resolution",
                        "VF_ADAPTER_MISSING",
                        format!(
                            "detected adapter {} is no longer registered",
                            detection.adapter_id
                        ),
                    ),
                });
                continue;
            };

            push(
                &mut entries,
                PatchGatePhase::Parse,
                detection,
                adapter.run_parse_check(repo, engine.execution.as_ref()),
            );
            push(
                &mut entries,
                PatchGatePhase::Format,
                detection,
                adapter.run_format_check(repo, engine.execution.as_ref()),
            );
            push(
                &mut entries,
                PatchGatePhase::Build,
                detection,
                adapter.run_check(CheckKind::Build, repo, engine.execution.as_ref()),
            );
            push(
                &mut entries,
                PatchGatePhase::TypeCheck,
                detection,
                adapter.run_check(CheckKind::TypeCheck, repo, engine.execution.as_ref()),
            );
            push(
                &mut entries,
                PatchGatePhase::Lint,
                detection,
                adapter.run_check(CheckKind::Lint, repo, engine.execution.as_ref()),
            );
            push(
                &mut entries,
                PatchGatePhase::Placeholders,
                detection,
                adapter.run_check(CheckKind::Placeholders, repo, engine.execution.as_ref()),
            );

            let targeted = if scope.changed_paths.is_empty() {
                CheckResult::skipped(
                    format!("{}:targeted-test", adapter.id()),
                    "no repository paths changed relative to the patch baseline",
                )
            } else {
                adapter.run_targeted_tests(repo, engine.execution.as_ref(), &scope)
            };
            push(
                &mut entries,
                PatchGatePhase::TargetedTests,
                detection,
                targeted,
            );
        }

        entries.push(PatchGateEntry {
            phase: PatchGatePhase::Impact,
            adapter_id: "runtime".into(),
            language: "repository".into(),
            result: CheckResult::pass_with_evidence(
                "patch:impact",
                format!(
                    "baseline={} current={} changed-paths={} seed-symbols={} affected-symbols={} full-verification-fallback={}",
                    baseline_address.0,
                    current_address.0,
                    impact.changed_paths.len(),
                    impact.seed_symbols.len(),
                    impact.affected_symbols.len(),
                    impact.requires_full_verification
                ),
            ),
        });

        for specialist in &engine.registry.specialists {
            if specialist.supports(CheckKind::Security) {
                entries.push(PatchGateEntry {
                    phase: PatchGatePhase::Secrets,
                    adapter_id: specialist.id().into(),
                    language: "repository".into(),
                    result: specialist.run_check(
                        CheckKind::Security,
                        repo,
                        engine.execution.as_ref(),
                    ),
                });
            }
            if specialist.supports(CheckKind::Placeholders) {
                entries.push(PatchGateEntry {
                    phase: PatchGatePhase::Placeholders,
                    adapter_id: specialist.id().into(),
                    language: "repository".into(),
                    result: specialist.run_check(
                        CheckKind::Placeholders,
                        repo,
                        engine.execution.as_ref(),
                    ),
                });
            }
        }

        let accepted = entries.iter().all(patch_entry_accepts);
        Ok(PatchGateReport {
            baseline_address,
            current_address,
            detections,
            impact,
            entries,
            accepted,
        })
    }
}

fn push(
    entries: &mut Vec<PatchGateEntry>,
    phase: PatchGatePhase,
    detection: &LanguageDetection,
    result: CheckResult,
) {
    entries.push(PatchGateEntry {
        phase,
        adapter_id: detection.adapter_id.clone(),
        language: detection.language.clone(),
        result,
    });
}

fn patch_entry_accepts(entry: &PatchGateEntry) -> bool {
    match entry.result.status {
        CheckStatus::Fail | CheckStatus::Unsupported => false,
        CheckStatus::Pass => {
            entry.result.has_reproducible_evidence() && !entry.result.has_blocking_finding()
        }
        CheckStatus::Skipped => matches!(
            entry.phase,
            PatchGatePhase::TypeCheck | PatchGatePhase::TargetedTests
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};
    use verificationforge_core::{
        CodeNode, CodeNodeKind, ExecutionAdapter, ExecutionResult, LanguageAdapter, SymbolId,
    };

    use crate::AdapterRegistry;

    struct DemoAdapter {
        format_supported: bool,
        bare_build_pass: bool,
        seen_scope: Arc<Mutex<Option<ImpactScope>>>,
    }

    impl LanguageAdapter for DemoAdapter {
        fn id(&self) -> &'static str {
            "demo"
        }

        fn detect(&self, _repo: &Path) -> Option<LanguageDetection> {
            Some(LanguageDetection {
                adapter_id: "demo".into(),
                language: "Demo".into(),
                confidence_percent: 100,
            })
        }

        fn run_check(
            &self,
            check: CheckKind,
            _repo: &Path,
            _execution: &dyn ExecutionAdapter,
        ) -> CheckResult {
            if check == CheckKind::Build && self.bare_build_pass {
                return CheckResult::pass("demo:build");
            }
            if check == CheckKind::TypeCheck {
                return CheckResult::skipped(
                    "demo:type-check",
                    "demo build performs type checking",
                );
            }
            CheckResult::pass_with_evidence(
                format!("demo:{}", check.as_str()),
                format!("demo {} evidence", check.as_str()),
            )
        }

        fn run_parse_check(
            &self,
            _repo: &Path,
            _execution: &dyn ExecutionAdapter,
        ) -> CheckResult {
            CheckResult::pass_with_evidence("demo:parse", "demo parser accepted source")
        }

        fn run_format_check(
            &self,
            _repo: &Path,
            _execution: &dyn ExecutionAdapter,
        ) -> CheckResult {
            if self.format_supported {
                CheckResult::pass_with_evidence("demo:format", "demo formatter is clean")
            } else {
                CheckResult::unsupported("demo:format", "demo formatter unavailable")
            }
        }

        fn run_targeted_tests(
            &self,
            _repo: &Path,
            _execution: &dyn ExecutionAdapter,
            scope: &ImpactScope,
        ) -> CheckResult {
            *self.seen_scope.lock().expect("scope lock poisoned") = Some(scope.clone());
            CheckResult::pass_with_evidence(
                "demo:targeted-test",
                format!(
                    "targeted affected-symbols={} full={}",
                    scope.affected_symbols.len(),
                    scope.requires_full_verification
                ),
            )
        }
    }

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
        ) -> Result<ExecutionResult, String> {
            Ok(ExecutionResult {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("verificationforge-patch-{name}-{nonce}"))
    }

    fn engine(adapter: DemoAdapter) -> VerificationEngine {
        let mut registry = AdapterRegistry::default();
        registry.register(Arc::new(adapter));
        VerificationEngine::new(registry, Arc::new(NoopExecution))
    }

    fn baseline_and_current() -> (std::path::PathBuf, RepositorySnapshot) {
        let repo = temp_dir("repo");
        fs::create_dir_all(&repo).expect("create repo");
        fs::write(repo.join("service.demo"), "before").expect("write baseline");
        let baseline = RepositorySnapshot::capture(&repo).expect("capture baseline");
        fs::write(repo.join("service.demo"), "after").expect("write current");
        (repo, baseline)
    }

    fn mapped_graph() -> UniversalCodeGraph {
        let symbol = SymbolId("demo:function:service".into());
        let mut graph = UniversalCodeGraph::default();
        graph.add_node(CodeNode {
            id: symbol,
            kind: CodeNodeKind::Function,
            language: Some("Demo".into()),
            path: Some("service.demo".into()),
            display_name: "service".into(),
        });
        graph
    }

    #[test]
    fn mapped_change_reaches_targeted_test_scope() {
        let (repo, baseline) = baseline_and_current();
        let seen_scope = Arc::new(Mutex::new(None));
        let engine = engine(DemoAdapter {
            format_supported: true,
            bare_build_pass: false,
            seen_scope: seen_scope.clone(),
        });
        let report = PatchGate::verify(&engine, &repo, &baseline, &mapped_graph())
            .expect("patch gate should run");
        assert!(report.accepted);
        assert!(!report.impact.requires_full_verification);
        let scope = seen_scope
            .lock()
            .expect("scope lock poisoned")
            .clone()
            .expect("targeted scope recorded");
        assert!(scope.changed_paths.contains("service.demo"));
        assert!(scope
            .affected_symbols
            .contains(&SymbolId("demo:function:service".into())));
        assert!(!scope.requires_full_verification);
        fs::remove_dir_all(repo).ok();
    }

    #[test]
    fn unmapped_change_forces_safe_full_verification_scope() {
        let (repo, baseline) = baseline_and_current();
        let seen_scope = Arc::new(Mutex::new(None));
        let engine = engine(DemoAdapter {
            format_supported: true,
            bare_build_pass: false,
            seen_scope: seen_scope.clone(),
        });
        let report = PatchGate::verify(
            &engine,
            &repo,
            &baseline,
            &UniversalCodeGraph::default(),
        )
        .expect("patch gate should run");
        assert!(report.accepted);
        assert!(report.impact.requires_full_verification);
        assert!(seen_scope
            .lock()
            .expect("scope lock poisoned")
            .as_ref()
            .is_some_and(|scope| scope.requires_full_verification));
        fs::remove_dir_all(repo).ok();
    }

    #[test]
    fn unsupported_required_format_phase_blocks_patch() {
        let (repo, baseline) = baseline_and_current();
        let engine = engine(DemoAdapter {
            format_supported: false,
            bare_build_pass: false,
            seen_scope: Arc::new(Mutex::new(None)),
        });
        let report = PatchGate::verify(&engine, &repo, &baseline, &mapped_graph())
            .expect("patch gate should run");
        assert!(!report.accepted);
        assert!(report.entries.iter().any(|entry| {
            entry.phase == PatchGatePhase::Format
                && entry.result.status == CheckStatus::Unsupported
        }));
        fs::remove_dir_all(repo).ok();
    }

    #[test]
    fn bare_pass_cannot_satisfy_required_patch_phase() {
        let (repo, baseline) = baseline_and_current();
        let engine = engine(DemoAdapter {
            format_supported: true,
            bare_build_pass: true,
            seen_scope: Arc::new(Mutex::new(None)),
        });
        let report = PatchGate::verify(&engine, &repo, &baseline, &mapped_graph())
            .expect("patch gate should run");
        assert!(!report.accepted);
        assert!(report.entries.iter().any(|entry| {
            entry.phase == PatchGatePhase::Build
                && entry.result.status == CheckStatus::Pass
                && !entry.result.has_reproducible_evidence()
        }));
        fs::remove_dir_all(repo).ok();
    }

    #[test]
    fn unchanged_repository_skips_targeted_tests_only() {
        let repo = temp_dir("unchanged");
        fs::create_dir_all(&repo).expect("create repo");
        fs::write(repo.join("service.demo"), "stable").expect("write repo");
        let baseline = RepositorySnapshot::capture(&repo).expect("capture baseline");
        let engine = engine(DemoAdapter {
            format_supported: true,
            bare_build_pass: false,
            seen_scope: Arc::new(Mutex::new(None)),
        });
        let report = PatchGate::verify(&engine, &repo, &baseline, &mapped_graph())
            .expect("patch gate should run");
        assert!(report.accepted);
        assert!(report.entries.iter().any(|entry| {
            entry.phase == PatchGatePhase::TargetedTests
                && entry.result.status == CheckStatus::Skipped
        }));
        fs::remove_dir_all(repo).ok();
    }
}
