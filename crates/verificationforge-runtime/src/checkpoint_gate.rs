use std::path::Path;

use verificationforge_core::{
    CheckKind, CheckResult, CheckStatus, ImpactScope, LanguageDetection, UniversalCodeGraph,
};

use crate::{PatchGate, PatchGateReport, RepositorySnapshot, VerificationEngine};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CheckpointGatePhase {
    Integration,
    Property,
    Security,
    Dependencies,
    Ui,
    Api,
}

impl CheckpointGatePhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Integration => "integration",
            Self::Property => "property",
            Self::Security => "security",
            Self::Dependencies => "dependencies",
            Self::Ui => "ui",
            Self::Api => "api",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CheckpointGateEntry {
    pub phase: CheckpointGatePhase,
    pub adapter_id: String,
    pub language: String,
    pub result: CheckResult,
}

#[derive(Debug, Clone)]
pub struct CheckpointGateReport {
    pub patch: PatchGateReport,
    pub entries: Vec<CheckpointGateEntry>,
    pub accepted: bool,
}

pub struct CheckpointGate;

impl CheckpointGate {
    pub fn verify(
        engine: &VerificationEngine,
        repo: &Path,
        baseline: &RepositorySnapshot,
        graph: &UniversalCodeGraph,
    ) -> Result<CheckpointGateReport, String> {
        let patch = PatchGate::verify(engine, repo, baseline, graph)?;
        if !patch.accepted {
            return Ok(CheckpointGateReport {
                patch,
                entries: Vec::new(),
                accepted: false,
            });
        }

        let scope = ImpactScope {
            changed_paths: patch.impact.changed_paths.clone(),
            affected_symbols: patch.impact.affected_symbols.clone(),
            requires_full_verification: patch.impact.requires_full_verification,
        };
        let no_changes = scope.changed_paths.is_empty();
        let mut entries = Vec::new();

        for detection in &patch.detections {
            let Some(adapter) = engine.registry.adapter(&detection.adapter_id) else {
                entries.push(CheckpointGateEntry {
                    phase: CheckpointGatePhase::Integration,
                    adapter_id: detection.adapter_id.clone(),
                    language: detection.language.clone(),
                    result: CheckResult::fail(
                        "checkpoint:adapter-resolution",
                        "VF_ADAPTER_MISSING",
                        format!(
                            "detected adapter {} is no longer registered",
                            detection.adapter_id
                        ),
                    ),
                });
                continue;
            };

            let integration = if no_changes {
                CheckResult::skipped(
                    format!("{}:checkpoint-integration", adapter.id()),
                    "no repository paths changed relative to the checkpoint baseline",
                )
            } else {
                adapter.run_integration_tests(repo, engine.execution.as_ref(), &scope)
            };
            push(
                &mut entries,
                CheckpointGatePhase::Integration,
                detection,
                integration,
            );

            let property = if no_changes {
                CheckResult::skipped(
                    format!("{}:checkpoint-property", adapter.id()),
                    "no repository paths changed relative to the checkpoint baseline",
                )
            } else {
                adapter.run_property_tests(repo, engine.execution.as_ref(), &scope)
            };
            push(
                &mut entries,
                CheckpointGatePhase::Property,
                detection,
                property,
            );

            push(
                &mut entries,
                CheckpointGatePhase::Dependencies,
                detection,
                adapter.run_check(CheckKind::Dependencies, repo, engine.execution.as_ref()),
            );
            push(
                &mut entries,
                CheckpointGatePhase::Ui,
                detection,
                adapter.run_ui_verification(repo, engine.execution.as_ref(), &scope),
            );
            push(
                &mut entries,
                CheckpointGatePhase::Api,
                detection,
                adapter.run_api_verification(repo, engine.execution.as_ref(), &scope),
            );
        }

        for specialist in &engine.registry.specialists {
            if specialist.supports(CheckKind::Security) {
                entries.push(CheckpointGateEntry {
                    phase: CheckpointGatePhase::Security,
                    adapter_id: specialist.id().into(),
                    language: "repository".into(),
                    result: specialist.run_check(
                        CheckKind::Security,
                        repo,
                        engine.execution.as_ref(),
                    ),
                });
            }
        }

        if !entries
            .iter()
            .any(|entry| entry.phase == CheckpointGatePhase::Security)
        {
            entries.push(CheckpointGateEntry {
                phase: CheckpointGatePhase::Security,
                adapter_id: "runtime".into(),
                language: "repository".into(),
                result: CheckResult::fail(
                    "checkpoint:security",
                    "VF_CHECKPOINT_SECURITY_MISSING",
                    "checkpoint verification requires at least one repository security specialist",
                ),
            });
        }

        let accepted = entries.iter().all(checkpoint_entry_accepts);
        Ok(CheckpointGateReport {
            patch,
            entries,
            accepted,
        })
    }
}

fn push(
    entries: &mut Vec<CheckpointGateEntry>,
    phase: CheckpointGatePhase,
    detection: &LanguageDetection,
    result: CheckResult,
) {
    entries.push(CheckpointGateEntry {
        phase,
        adapter_id: detection.adapter_id.clone(),
        language: detection.language.clone(),
        result,
    });
}

fn checkpoint_entry_accepts(entry: &CheckpointGateEntry) -> bool {
    match entry.result.status {
        CheckStatus::Fail | CheckStatus::Unsupported => false,
        CheckStatus::Pass => {
            entry.result.has_reproducible_evidence() && !entry.result.has_blocking_finding()
        }
        CheckStatus::Skipped => matches!(
            entry.phase,
            CheckpointGatePhase::Integration
                | CheckpointGatePhase::Property
                | CheckpointGatePhase::Ui
                | CheckpointGatePhase::Api
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
        patch_ok: bool,
        property_ok: bool,
        ui_applicable_without_verifier: bool,
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
            if check == CheckKind::TypeCheck {
                return CheckResult::skipped("demo:type-check", "build includes type checking");
            }
            CheckResult::pass_with_evidence(
                format!("demo:{}", check.as_str()),
                format!("demo {} evidence", check.as_str()),
            )
        }

        fn run_parse_check(&self, _repo: &Path, _execution: &dyn ExecutionAdapter) -> CheckResult {
            if self.patch_ok {
                CheckResult::pass_with_evidence("demo:parse", "parse evidence")
            } else {
                CheckResult::fail("demo:parse", "VF_DEMO_PARSE", "parse failed")
            }
        }

        fn run_format_check(&self, _repo: &Path, _execution: &dyn ExecutionAdapter) -> CheckResult {
            CheckResult::pass_with_evidence("demo:format", "format evidence")
        }

        fn run_targeted_tests(
            &self,
            _repo: &Path,
            _execution: &dyn ExecutionAdapter,
            _scope: &ImpactScope,
        ) -> CheckResult {
            CheckResult::pass_with_evidence("demo:targeted-test", "targeted test evidence")
        }

        fn run_integration_tests(
            &self,
            _repo: &Path,
            _execution: &dyn ExecutionAdapter,
            scope: &ImpactScope,
        ) -> CheckResult {
            *self.seen_scope.lock().expect("scope lock poisoned") = Some(scope.clone());
            CheckResult::pass_with_evidence("demo:checkpoint-integration", "integration evidence")
        }

        fn run_property_tests(
            &self,
            _repo: &Path,
            _execution: &dyn ExecutionAdapter,
            _scope: &ImpactScope,
        ) -> CheckResult {
            if self.property_ok {
                CheckResult::pass_with_evidence("demo:checkpoint-property", "property evidence")
            } else {
                CheckResult::unsupported("demo:checkpoint-property", "property verifier missing")
            }
        }

        fn run_ui_verification(
            &self,
            _repo: &Path,
            _execution: &dyn ExecutionAdapter,
            _scope: &ImpactScope,
        ) -> CheckResult {
            if self.ui_applicable_without_verifier {
                CheckResult::unsupported("demo:checkpoint-ui", "UI detected but verifier missing")
            } else {
                CheckResult::skipped("demo:checkpoint-ui", "no UI surface detected")
            }
        }

        fn run_api_verification(
            &self,
            _repo: &Path,
            _execution: &dyn ExecutionAdapter,
            _scope: &ImpactScope,
        ) -> CheckResult {
            CheckResult::skipped("demo:checkpoint-api", "no API surface detected")
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
        std::env::temp_dir().join(format!("verificationforge-checkpoint-{name}-{nonce}"))
    }

    fn engine(adapter: DemoAdapter) -> VerificationEngine {
        let mut registry = AdapterRegistry::default();
        registry.register(Arc::new(adapter));
        VerificationEngine::new(registry, Arc::new(NoopExecution))
    }

    fn baseline_and_current() -> (std::path::PathBuf, RepositorySnapshot, UniversalCodeGraph) {
        let repo = temp_dir("repo");
        fs::create_dir_all(&repo).expect("create repo");
        fs::write(repo.join("service.demo"), "before").expect("write baseline");
        let baseline = RepositorySnapshot::capture(&repo).expect("capture baseline");
        fs::write(repo.join("service.demo"), "after").expect("write current");
        let mut graph = UniversalCodeGraph::default();
        graph.add_node(CodeNode {
            id: SymbolId("demo:function:service".into()),
            kind: CodeNodeKind::Function,
            language: Some("Demo".into()),
            path: Some("service.demo".into()),
            display_name: "service".into(),
        });
        (repo, baseline, graph)
    }

    #[test]
    fn checkpoint_composes_patch_and_propagates_impact_scope() {
        let (repo, baseline, graph) = baseline_and_current();
        let seen_scope = Arc::new(Mutex::new(None));
        let report = CheckpointGate::verify(
            &engine(DemoAdapter {
                patch_ok: true,
                property_ok: true,
                ui_applicable_without_verifier: false,
                seen_scope: seen_scope.clone(),
            }),
            &repo,
            &baseline,
            &graph,
        )
        .expect("checkpoint should run");
        assert!(report.patch.accepted);
        assert!(report.accepted);
        assert!(
            seen_scope
                .lock()
                .expect("scope lock poisoned")
                .as_ref()
                .is_some_and(|scope| scope.changed_paths.contains("service.demo"))
        );
        fs::remove_dir_all(repo).ok();
    }

    #[test]
    fn failed_patch_prevents_checkpoint_from_claiming_success() {
        let (repo, baseline, graph) = baseline_and_current();
        let report = CheckpointGate::verify(
            &engine(DemoAdapter {
                patch_ok: false,
                property_ok: true,
                ui_applicable_without_verifier: false,
                seen_scope: Arc::new(Mutex::new(None)),
            }),
            &repo,
            &baseline,
            &graph,
        )
        .expect("checkpoint should run");
        assert!(!report.patch.accepted);
        assert!(!report.accepted);
        assert!(report.entries.is_empty());
        fs::remove_dir_all(repo).ok();
    }

    #[test]
    fn missing_property_verification_blocks_checkpoint() {
        let (repo, baseline, graph) = baseline_and_current();
        let report = CheckpointGate::verify(
            &engine(DemoAdapter {
                patch_ok: true,
                property_ok: false,
                ui_applicable_without_verifier: false,
                seen_scope: Arc::new(Mutex::new(None)),
            }),
            &repo,
            &baseline,
            &graph,
        )
        .expect("checkpoint should run");
        assert!(!report.accepted);
        assert!(report.entries.iter().any(|entry| {
            entry.phase == CheckpointGatePhase::Property
                && entry.result.status == CheckStatus::Unsupported
        }));
        fs::remove_dir_all(repo).ok();
    }

    #[test]
    fn detected_ui_without_verifier_blocks_checkpoint() {
        let (repo, baseline, graph) = baseline_and_current();
        let report = CheckpointGate::verify(
            &engine(DemoAdapter {
                patch_ok: true,
                property_ok: true,
                ui_applicable_without_verifier: true,
                seen_scope: Arc::new(Mutex::new(None)),
            }),
            &repo,
            &baseline,
            &graph,
        )
        .expect("checkpoint should run");
        assert!(!report.accepted);
        assert!(report.entries.iter().any(|entry| {
            entry.phase == CheckpointGatePhase::Ui
                && entry.result.status == CheckStatus::Unsupported
        }));
        fs::remove_dir_all(repo).ok();
    }
}
