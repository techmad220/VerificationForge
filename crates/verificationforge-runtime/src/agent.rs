use std::path::Path;
use std::sync::Arc;

use verificationforge_core::{
    DevelopmentFirewallPolicy, ExecutionAdapter, ExecutionResult, Finding, RequirementId, RiskTier,
    SymbolId,
};

use crate::{OperationContext, OperationPurpose, OperationTelemetry, TrackedDevelopmentSession};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentActionMetadata {
    pub purpose: OperationPurpose,
    pub related_files: Vec<String>,
    pub symbols: Vec<SymbolId>,
    pub evidence_ids: Vec<String>,
}

impl AgentActionMetadata {
    pub fn with_purpose(mut self, purpose: OperationPurpose) -> Self {
        self.purpose = purpose;
        self
    }

    pub fn with_related_file(mut self, file: impl Into<String>) -> Self {
        self.related_files.push(file.into());
        self
    }

    pub fn with_symbols(mut self, symbols: impl IntoIterator<Item = SymbolId>) -> Self {
        self.symbols.extend(symbols);
        self
    }

    pub fn with_evidence(mut self, evidence_ids: impl IntoIterator<Item = String>) -> Self {
        self.evidence_ids.extend(evidence_ids);
        self
    }

    fn context(self, requirement: RequirementId) -> OperationContext {
        let mut context = OperationContext::for_requirement(requirement)
            .with_purpose(self.purpose)
            .with_symbols(self.symbols)
            .with_evidence(self.evidence_ids);
        for file in self.related_files {
            context = context.with_file(file);
        }
        context
    }
}

/// Agent-facing development boundary.
///
/// The runtime deliberately owns the tracked controlled session and exposes no mutable accessor for
/// it. An agent must first bind work to a non-empty requirement and then use `AgentBuildTask` for
/// repository mutations, commands, tests, commits and certification requests. This keeps the
/// development firewall and operation telemetry on the only agent-facing mutation path.
pub struct AgentDevelopmentRuntime {
    session: TrackedDevelopmentSession,
}

impl AgentDevelopmentRuntime {
    pub fn new(
        repo: &Path,
        agent: impl Into<String>,
        risk: RiskTier,
        policy: DevelopmentFirewallPolicy,
        execution: Arc<dyn ExecutionAdapter>,
    ) -> Result<Self, String> {
        Ok(Self {
            session: TrackedDevelopmentSession::new(repo, agent, risk, policy, execution)?,
        })
    }

    pub fn repository(&self) -> &Path {
        self.session.repository()
    }

    pub fn telemetry(&self) -> &OperationTelemetry {
        self.session.telemetry()
    }

    pub fn active_findings(&self) -> &[Finding] {
        self.session.active_findings()
    }

    /// Supplies engine-derived findings to the firewall boundary before agent work continues.
    pub fn apply_engine_findings(&mut self, findings: Vec<Finding>) {
        self.session.set_active_findings(findings);
    }

    pub fn bind_requirement(
        &mut self,
        requirement: RequirementId,
    ) -> Result<AgentBuildTask<'_>, String> {
        if requirement.0.trim().is_empty() {
            return Err("agent build task requires a non-empty requirement id".into());
        }
        Ok(AgentBuildTask {
            session: &mut self.session,
            requirement,
        })
    }
}

pub struct AgentBuildTask<'a> {
    session: &'a mut TrackedDevelopmentSession,
    requirement: RequirementId,
}

impl AgentBuildTask<'_> {
    pub fn requirement(&self) -> &RequirementId {
        &self.requirement
    }

    pub fn write_file(
        &mut self,
        relative: &Path,
        content: &[u8],
        metadata: AgentActionMetadata,
    ) -> Result<(), String> {
        self.session.write_file(
            relative,
            content,
            metadata.context(self.requirement.clone()),
        )
    }

    pub fn write_dependency_file(
        &mut self,
        relative: &Path,
        content: &[u8],
        metadata: AgentActionMetadata,
    ) -> Result<(), String> {
        self.session.write_dependency_file(
            relative,
            content,
            metadata.context(self.requirement.clone()),
        )
    }

    pub fn patch_file(
        &mut self,
        relative: &Path,
        expected: &str,
        replacement: &str,
        metadata: AgentActionMetadata,
    ) -> Result<(), String> {
        self.session.patch_file(
            relative,
            expected,
            replacement,
            metadata.context(self.requirement.clone()),
        )
    }

    pub fn delete_file(
        &mut self,
        relative: &Path,
        metadata: AgentActionMetadata,
    ) -> Result<(), String> {
        self.session
            .delete_file(relative, metadata.context(self.requirement.clone()))
    }

    pub fn rename_file(
        &mut self,
        from: &Path,
        to: &Path,
        metadata: AgentActionMetadata,
    ) -> Result<(), String> {
        self.session
            .rename_file(from, to, metadata.context(self.requirement.clone()))
    }

    pub fn run_command(
        &mut self,
        program: &str,
        args: &[String],
        metadata: AgentActionMetadata,
    ) -> Result<ExecutionResult, String> {
        self.session
            .run_command(program, args, metadata.context(self.requirement.clone()))
    }

    pub fn run_fix_command(
        &mut self,
        program: &str,
        args: &[String],
        metadata: AgentActionMetadata,
    ) -> Result<ExecutionResult, String> {
        self.run_command(
            program,
            args,
            metadata.with_purpose(OperationPurpose::FixAttempt),
        )
    }

    pub fn run_test(
        &mut self,
        program: &str,
        args: &[String],
        metadata: AgentActionMetadata,
    ) -> Result<ExecutionResult, String> {
        self.session
            .run_test(program, args, metadata.context(self.requirement.clone()))
    }

    pub fn run_regression_test(
        &mut self,
        program: &str,
        args: &[String],
        metadata: AgentActionMetadata,
    ) -> Result<ExecutionResult, String> {
        self.run_test(
            program,
            args,
            metadata.with_purpose(OperationPurpose::RegressionTest),
        )
    }

    pub fn commit(
        &mut self,
        message: &str,
        metadata: AgentActionMetadata,
    ) -> Result<ExecutionResult, String> {
        self.session
            .commit(message, metadata.context(self.requirement.clone()))
    }

    pub fn authorize_certification(
        &mut self,
        engine_certification_id: String,
        metadata: AgentActionMetadata,
    ) -> Result<(), String> {
        self.session.authorize_certification(
            engine_certification_id,
            metadata.context(self.requirement.clone()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};
    use verificationforge_core::{AgentOperationKind, ExecutionResult};

    #[derive(Default)]
    struct RecordingExecution {
        calls: Mutex<Vec<(String, Vec<String>)>>,
    }

    impl ExecutionAdapter for RecordingExecution {
        fn id(&self) -> &'static str {
            "agent-runtime-recording"
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

    fn temp_dir() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("verificationforge-agent-runtime-{nonce}"))
    }

    fn runtime(root: &Path, execution: Arc<dyn ExecutionAdapter>) -> AgentDevelopmentRuntime {
        AgentDevelopmentRuntime::new(
            root,
            "builder-agent",
            RiskTier::High,
            DevelopmentFirewallPolicy::default(),
            execution,
        )
        .expect("create agent runtime")
    }

    #[test]
    fn task_binds_requirement_and_routes_mutation_command_and_regression_test() {
        let root = temp_dir();
        fs::create_dir_all(root.join("src")).expect("create src");
        let execution = Arc::new(RecordingExecution::default());
        let mut runtime = runtime(&root, execution.clone());
        let requirement = RequirementId("REQ-AGENT-BUILD".into());
        let symbol = SymbolId("rust:function:src/lib.rs::value".into());

        {
            let mut task = runtime
                .bind_requirement(requirement.clone())
                .expect("bind requirement");
            task.write_file(
                Path::new("src/lib.rs"),
                b"pub fn value() -> u8 { 1 }\n",
                AgentActionMetadata::default().with_symbols([symbol.clone()]),
            )
            .expect("controlled write");
            task.run_command(
                "cargo",
                &["check".into(), "--workspace".into()],
                AgentActionMetadata::default().with_related_file("src/lib.rs"),
            )
            .expect("controlled command");
            task.run_regression_test(
                "cargo",
                &["test".into(), "--workspace".into()],
                AgentActionMetadata::default().with_evidence(["evidence-regression".into()]),
            )
            .expect("controlled regression test");
        }

        let operations = runtime.telemetry().operations();
        assert_eq!(operations.len(), 3);
        assert!(
            operations
                .iter()
                .all(|operation| operation.requirement.as_ref() == Some(&requirement))
        );
        assert!(
            operations
                .iter()
                .all(|operation| operation.agent == "builder-agent")
        );
        assert_eq!(operations[0].kind, AgentOperationKind::Write);
        assert_eq!(operations[0].symbols, vec![symbol]);
        assert_eq!(operations[1].kind, AgentOperationKind::Command);
        assert_eq!(operations[1].files, vec!["src/lib.rs"]);
        assert_eq!(operations[2].kind, AgentOperationKind::Test);
        assert_eq!(operations[2].purpose, OperationPurpose::RegressionTest);
        assert_eq!(operations[2].evidence_ids, vec!["evidence-regression"]);
        assert_eq!(
            execution.calls.lock().expect("calls lock poisoned").len(),
            2
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn blank_requirement_cannot_open_agent_build_task() {
        let root = temp_dir();
        fs::create_dir_all(&root).expect("create root");
        let mut runtime = runtime(&root, Arc::new(RecordingExecution::default()));
        let error = runtime
            .bind_requirement(RequirementId("   ".into()))
            .err()
            .expect("blank requirement must fail");
        assert!(error.contains("non-empty requirement"));
        assert!(runtime.telemetry().operations().is_empty());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn direct_git_file_mutation_is_denied_and_traced() {
        let root = temp_dir();
        fs::create_dir_all(root.join(".git")).expect("create git");
        let mut runtime = runtime(&root, Arc::new(RecordingExecution::default()));
        {
            let mut task = runtime
                .bind_requirement(RequirementId("REQ-GIT-BOUNDARY".into()))
                .expect("bind requirement");
            let error = task
                .write_file(
                    Path::new(".git/config"),
                    b"forbidden",
                    AgentActionMetadata::default(),
                )
                .expect_err("direct git mutation must fail");
            assert!(error.contains("direct .git mutation is forbidden"));
        }
        let operation = runtime
            .telemetry()
            .operations()
            .last()
            .expect("rejection trace");
        assert!(!operation.outcome.accepted);
        assert_eq!(operation.kind, AgentOperationKind::Write);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn commit_without_engine_evidence_never_reaches_git() {
        let root = temp_dir();
        fs::create_dir_all(&root).expect("create root");
        let execution = Arc::new(RecordingExecution::default());
        let mut runtime = runtime(&root, execution.clone());
        {
            let mut task = runtime
                .bind_requirement(RequirementId("REQ-COMMIT".into()))
                .expect("bind requirement");
            let error = task
                .commit("agent commit", AgentActionMetadata::default())
                .expect_err("evidence-free commit must fail");
            assert!(error.contains("VF_FIREWALL_EVIDENCE_REQUIRED"));
        }
        assert!(
            execution
                .calls
                .lock()
                .expect("calls lock poisoned")
                .is_empty()
        );
        assert_eq!(runtime.telemetry().failed_operations().count(), 1);
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn engine_blocker_prevents_agent_commit() {
        let root = temp_dir();
        fs::create_dir_all(&root).expect("create root");
        let execution = Arc::new(RecordingExecution::default());
        let mut runtime = runtime(&root, execution.clone());
        runtime.apply_engine_findings(vec![Finding {
            code: "VF_SECURITY_CRITICAL".into(),
            message: "critical verification blocker".into(),
            blocking: true,
        }]);
        {
            let mut task = runtime
                .bind_requirement(RequirementId("REQ-BLOCKED".into()))
                .expect("bind requirement");
            let error = task
                .commit(
                    "blocked commit",
                    AgentActionMetadata::default().with_evidence(["evidence-1".into()]),
                )
                .expect_err("blocking finding must prevent commit");
            assert!(error.contains("VF_FIREWALL_ACTIVE_BLOCKER"));
        }
        assert!(
            execution
                .calls
                .lock()
                .expect("calls lock poisoned")
                .is_empty()
        );
        fs::remove_dir_all(root).ok();
    }
}
