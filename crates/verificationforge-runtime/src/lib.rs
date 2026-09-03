use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use crate::authenticity::NativeAuthenticitySpecialist;
use crate::security::NativeSecuritySpecialist;
use verificationforge_core::{LanguageAdapter, SpecialistVerificationAdapter};
pub use verificationforge_core::{
    CheckKind, CheckResult, CheckStatus, ExecutionAdapter, ExecutionResult, LanguageDetection,
    VerificationLevel,
};

pub struct AdapterRegistry {
    languages: Vec<Arc<dyn LanguageAdapter>>,
    specialists: Vec<Arc<dyn SpecialistVerificationAdapter>>,
}

impl Default for AdapterRegistry {
    fn default() -> Self {
        Self {
            languages: Vec::new(),
            specialists: vec![
                Arc::new(NativeSecuritySpecialist),
                Arc::new(NativeAuthenticitySpecialist),
            ],
        }
    }
}

impl AdapterRegistry {
    pub fn register(&mut self, adapter: Arc<dyn LanguageAdapter>) {
        if !self
            .languages
            .iter()
            .any(|existing| existing.id() == adapter.id())
        {
            self.languages.push(adapter);
        }
    }

    pub fn register_specialist(&mut self, adapter: Arc<dyn SpecialistVerificationAdapter>) {
        if !self
            .specialists
            .iter()
            .any(|existing| existing.id() == adapter.id())
        {
            self.specialists.push(adapter);
        }
    }

    pub fn detect(&self, repo: &Path) -> Vec<LanguageDetection> {
        let mut detections: Vec<_> = self
            .languages
            .iter()
            .filter_map(|adapter| adapter.detect(repo))
            .collect();
        detections.sort_by(|a, b| {
            b.confidence_percent
                .cmp(&a.confidence_percent)
                .then_with(|| a.language.cmp(&b.language))
        });
        detections
    }

    pub fn adapter_ids(&self) -> Vec<&'static str> {
        self.languages.iter().map(|adapter| adapter.id()).collect()
    }

    pub fn specialist_ids(&self) -> Vec<&'static str> {
        self.specialists.iter().map(|adapter| adapter.id()).collect()
    }

    fn adapter(&self, id: &str) -> Option<&Arc<dyn LanguageAdapter>> {
        self.languages.iter().find(|adapter| adapter.id() == id)
    }
}

#[derive(Debug, Clone)]
pub struct AdapterCheckResult {
    pub adapter_id: String,
    pub language: String,
    pub result: CheckResult,
}

#[derive(Debug, Clone)]
pub struct VerificationReport {
    pub level: VerificationLevel,
    pub detections: Vec<LanguageDetection>,
    pub checks: Vec<AdapterCheckResult>,
    pub accepted: bool,
}

impl VerificationReport {
    pub fn failed_checks(&self) -> usize {
        self.checks
            .iter()
            .filter(|entry| entry.result.status == CheckStatus::Fail)
            .count()
    }

    pub fn unsupported_checks(&self) -> usize {
        self.checks
            .iter()
            .filter(|entry| entry.result.status == CheckStatus::Unsupported)
            .count()
    }
}

pub struct VerificationEngine {
    registry: AdapterRegistry,
    execution: Arc<dyn ExecutionAdapter>,
}

impl VerificationEngine {
    pub fn new(registry: AdapterRegistry, execution: Arc<dyn ExecutionAdapter>) -> Self {
        Self {
            registry,
            execution,
        }
    }

    pub fn verify(&self, repo: &Path, level: VerificationLevel) -> VerificationReport {
        let detections = self.registry.detect(repo);
        if detections.is_empty() {
            return VerificationReport {
                level,
                detections,
                checks: vec![AdapterCheckResult {
                    adapter_id: "runtime".into(),
                    language: "unknown".into(),
                    result: CheckResult::fail(
                        "runtime:language-detection",
                        "VF_NO_LANGUAGE",
                        "no registered language adapter recognized this repository",
                    ),
                }],
                accepted: false,
            };
        }

        let mut checks = Vec::new();
        let level_checks = level.checks();
        for detection in &detections {
            let Some(adapter) = self.registry.adapter(&detection.adapter_id) else {
                checks.push(AdapterCheckResult {
                    adapter_id: detection.adapter_id.clone(),
                    language: detection.language.clone(),
                    result: CheckResult::fail(
                        "runtime:adapter-resolution",
                        "VF_ADAPTER_MISSING",
                        format!(
                            "detected adapter {} is no longer registered",
                            detection.adapter_id
                        ),
                    ),
                });
                continue;
            };

            for check in &level_checks {
                checks.push(AdapterCheckResult {
                    adapter_id: detection.adapter_id.clone(),
                    language: detection.language.clone(),
                    result: adapter.run_check(*check, repo, self.execution.as_ref()),
                });
            }
        }

        let mut specialist_checks = level_checks;
        if !specialist_checks.contains(&CheckKind::Security) {
            specialist_checks.push(CheckKind::Security);
        }
        for check in specialist_checks {
            for specialist in self
                .registry
                .specialists
                .iter()
                .filter(|specialist| specialist.supports(check))
            {
                checks.push(AdapterCheckResult {
                    adapter_id: specialist.id().into(),
                    language: "repository".into(),
                    result: specialist.run_check(check, repo, self.execution.as_ref()),
                });
            }
        }

        let accepted = checks.iter().all(|entry| match entry.result.status {
            CheckStatus::Fail => false,
            CheckStatus::Unsupported => !level.unsupported_is_blocking(),
            CheckStatus::Pass | CheckStatus::Skipped => !entry.result.has_blocking_finding(),
        });

        VerificationReport {
            level,
            detections,
            checks,
            accepted,
        }
    }
}

#[derive(Default)]
pub struct ProcessExecutionAdapter;

impl ExecutionAdapter for ProcessExecutionAdapter {
    fn id(&self) -> &'static str {
        "local-process"
    }

    fn execute(
        &self,
        program: &str,
        args: &[String],
        cwd: &Path,
    ) -> Result<ExecutionResult, String> {
        let output = Command::new(program)
            .args(args)
            .current_dir(cwd)
            .output()
            .map_err(|error| format!("failed to execute {program}: {error}"))?;

        Ok(ExecutionResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use verificationforge_core::LanguageAdapter;

    struct DemoAdapter {
        id: &'static str,
        language: &'static str,
        fail_test: bool,
    }

    impl LanguageAdapter for DemoAdapter {
        fn id(&self) -> &'static str {
            self.id
        }

        fn detect(&self, _repo: &Path) -> Option<LanguageDetection> {
            Some(LanguageDetection {
                adapter_id: self.id.into(),
                language: self.language.into(),
                confidence_percent: 100,
            })
        }

        fn run_check(
            &self,
            check: CheckKind,
            _repo: &Path,
            _execution: &dyn ExecutionAdapter,
        ) -> CheckResult {
            if self.fail_test && check == CheckKind::Test {
                CheckResult::fail(
                    format!("{}:test", self.id),
                    "DEMO_TEST_FAILURE",
                    "test failed",
                )
            } else if check == CheckKind::TypeCheck {
                CheckResult::skipped(format!("{}:type-check", self.id), "covered by build")
            } else {
                CheckResult::pass(format!("{}:{}", self.id, check.as_str()))
            }
        }
    }

    #[derive(Default)]
    struct FakeExecution {
        calls: Mutex<BTreeMap<String, usize>>,
    }

    impl ExecutionAdapter for FakeExecution {
        fn id(&self) -> &'static str {
            "fake"
        }

        fn execute(
            &self,
            program: &str,
            _args: &[String],
            _cwd: &Path,
        ) -> Result<ExecutionResult, String> {
            *self
                .calls
                .lock()
                .expect("lock poisoned")
                .entry(program.into())
                .or_default() += 1;
            Ok(ExecutionResult {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn duplicate_adapter_ids_are_not_registered_twice() {
        let mut registry = AdapterRegistry::default();
        registry.register(Arc::new(DemoAdapter {
            id: "demo",
            language: "Demo",
            fail_test: false,
        }));
        registry.register(Arc::new(DemoAdapter {
            id: "demo",
            language: "Demo",
            fail_test: false,
        }));
        assert_eq!(registry.adapter_ids(), vec!["demo"]);
        assert_eq!(
            registry.specialist_ids(),
            vec!["native-security", "native-authenticity"]
        );
    }

    #[test]
    fn mixed_language_verification_runs_every_detected_adapter() {
        let mut registry = AdapterRegistry::default();
        registry.register(Arc::new(DemoAdapter {
            id: "one",
            language: "One",
            fail_test: false,
        }));
        registry.register(Arc::new(DemoAdapter {
            id: "two",
            language: "Two",
            fail_test: false,
        }));
        let engine = VerificationEngine::new(registry, Arc::new(FakeExecution::default()));
        let report = engine.verify(Path::new("."), VerificationLevel::Patch);
        assert_eq!(report.detections.len(), 2);
        assert!(report.accepted);
        assert_eq!(report.checks.len(), 12);
        assert!(report
            .checks
            .iter()
            .any(|entry| entry.adapter_id == "native-security"));
        assert!(report
            .checks
            .iter()
            .any(|entry| entry.adapter_id == "native-authenticity"));
    }

    #[test]
    fn a_failed_check_blocks_acceptance() {
        let mut registry = AdapterRegistry::default();
        registry.register(Arc::new(DemoAdapter {
            id: "demo",
            language: "Demo",
            fail_test: true,
        }));
        let engine = VerificationEngine::new(registry, Arc::new(FakeExecution::default()));
        let report = engine.verify(Path::new("."), VerificationLevel::Patch);
        assert!(!report.accepted);
        assert_eq!(report.failed_checks(), 1);
    }
}
