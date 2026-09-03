use std::path::{Path, PathBuf};

use verificationforge_core::{VerificationLevel, VerificationPolicy};

use crate::{
    CertificationArtifact, JournalEventKind, RepositorySnapshot, RunJournal, VerificationEngine,
    VerificationReport,
};

#[derive(Debug, Clone)]
pub struct VerificationSession {
    pub snapshot: RepositorySnapshot,
    pub report: VerificationReport,
    pub certification: CertificationArtifact,
    pub journal_path: Option<PathBuf>,
}

impl VerificationSession {
    pub fn run(
        engine: &VerificationEngine,
        repo: &Path,
        level: VerificationLevel,
        policy: &VerificationPolicy,
    ) -> Result<Self, String> {
        Self::run_internal(engine, repo, level, policy, None)
    }

    pub fn run_journaled(
        engine: &VerificationEngine,
        repo: &Path,
        level: VerificationLevel,
        policy: &VerificationPolicy,
        journal_root: &Path,
    ) -> Result<Self, String> {
        Self::run_internal(engine, repo, level, policy, Some(journal_root))
    }

    fn run_internal(
        engine: &VerificationEngine,
        repo: &Path,
        level: VerificationLevel,
        policy: &VerificationPolicy,
        journal_root: Option<&Path>,
    ) -> Result<Self, String> {
        let snapshot = RepositorySnapshot::capture(repo)?;
        let repository_address = snapshot
            .address
            .clone()
            .ok_or_else(|| "repository snapshot did not produce a content address".to_owned())?;

        let mut journal = match journal_root {
            Some(root) => {
                let run_id = format!("vf-{}", &repository_address.0[..16]);
                Some(RunJournal::create(root, run_id)?)
            }
            None => None,
        };

        if let Some(journal) = journal.as_mut() {
            journal.append(
                JournalEventKind::Checkpoint,
                &format!("snapshot={}", repository_address.0),
            )?;
            journal.append(
                JournalEventKind::Progress,
                &format!("verification-level={level:?}"),
            )?;
        }

        let report = engine.verify(repo, level);
        if let Some(journal) = journal.as_mut() {
            journal.append(
                JournalEventKind::Checkpoint,
                &format!(
                    "checks={} failed={} unsupported={}",
                    report.checks.len(),
                    report.failed_checks(),
                    report.unsupported_checks()
                ),
            )?;
        }

        let certification = CertificationArtifact::from_report(&report, repository_address, policy);
        if let Some(journal) = journal.as_mut() {
            journal.append(
                if certification.accepted {
                    JournalEventKind::Completed
                } else {
                    JournalEventKind::Failed
                },
                &format!(
                    "certification={} accepted={}",
                    certification.id.0, certification.accepted
                ),
            )?;
        }

        Ok(Self {
            snapshot,
            report,
            certification,
            journal_path: journal.map(|entry| entry.path().to_path_buf()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use verificationforge_core::{
        CheckKind, CheckResult, ExecutionAdapter, ExecutionResult, LanguageAdapter,
        LanguageDetection, RiskTier,
    };

    use crate::AdapterRegistry;

    struct DemoAdapter;

    impl LanguageAdapter for DemoAdapter {
        fn id(&self) -> &'static str {
            "demo"
        }

        fn detect(&self, _repo: &Path) -> Option<LanguageDetection> {
            Some(LanguageDetection {
                adapter_id: self.id().into(),
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
            CheckResult::pass(format!("demo:{}", check.as_str()))
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

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("verificationforge-session-{name}-{nonce}"))
    }

    #[test]
    fn session_binds_snapshot_report_policy_and_journal() {
        let repo = temp_dir("repo");
        let journals = temp_dir("journals");
        fs::create_dir_all(&repo).expect("create repo");
        fs::write(repo.join("input.txt"), "stable content").expect("write fixture");

        let mut registry = AdapterRegistry::default();
        registry.register(Arc::new(DemoAdapter));
        let engine = VerificationEngine::new(registry, Arc::new(NoopExecution));
        let mut policy = VerificationPolicy::for_risk(RiskTier::Low);
        policy.required_checks.clear();

        let session = VerificationSession::run_journaled(
            &engine,
            &repo,
            VerificationLevel::Patch,
            &policy,
            &journals,
        )
        .expect("run session");

        assert!(session.certification.accepted);
        assert!(session.snapshot.address.is_some());
        assert!(
            session
                .journal_path
                .as_ref()
                .is_some_and(|path| path.is_file())
        );

        fs::remove_dir_all(repo).ok();
        fs::remove_dir_all(journals).ok();
    }
}
