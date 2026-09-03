use std::path::Path;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use verificationforge_core::{
    AgentOperationKind, DevelopmentFirewallPolicy, ExecutionAdapter, ExecutionResult, Finding,
    RequirementId, RiskTier, SymbolId,
};

use crate::ControlledDevelopmentSession;

const MAX_SUMMARY_CHARS: usize = 2_000;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OperationPurpose {
    #[default]
    Normal,
    FixAttempt,
    RegressionTest,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OperationContext {
    pub requirement: Option<RequirementId>,
    pub purpose: OperationPurpose,
    pub files: Vec<String>,
    pub symbols: Vec<SymbolId>,
    pub evidence_ids: Vec<String>,
}

impl OperationContext {
    pub fn for_requirement(requirement: RequirementId) -> Self {
        Self {
            requirement: Some(requirement),
            ..Self::default()
        }
    }

    pub fn with_purpose(mut self, purpose: OperationPurpose) -> Self {
        self.purpose = purpose;
        self
    }

    pub fn with_file(mut self, file: impl Into<String>) -> Self {
        self.files.push(file.into());
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandInvocation {
    pub program: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationOutcome {
    pub accepted: bool,
    pub exit_code: Option<i32>,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationTraceEntry {
    pub sequence: u64,
    pub agent: String,
    pub requirement: Option<RequirementId>,
    pub kind: AgentOperationKind,
    pub purpose: OperationPurpose,
    pub target: String,
    pub files: Vec<String>,
    pub symbols: Vec<SymbolId>,
    pub evidence_ids: Vec<String>,
    pub command: Option<CommandInvocation>,
    pub started_unix_ms: u128,
    pub duration_ms: u128,
    pub outcome: OperationOutcome,
}

#[derive(Debug, Default)]
pub struct OperationTelemetry {
    next_sequence: u64,
    operations: Vec<OperationTraceEntry>,
}

impl OperationTelemetry {
    pub fn operations(&self) -> &[OperationTraceEntry] {
        &self.operations
    }

    pub fn failed_operations(&self) -> impl Iterator<Item = &OperationTraceEntry> {
        self.operations
            .iter()
            .filter(|operation| !operation.outcome.accepted)
    }

    pub fn fix_attempts(&self) -> impl Iterator<Item = &OperationTraceEntry> {
        self.operations
            .iter()
            .filter(|operation| operation.purpose == OperationPurpose::FixAttempt)
    }

    pub fn regression_tests(&self) -> impl Iterator<Item = &OperationTraceEntry> {
        self.operations
            .iter()
            .filter(|operation| operation.purpose == OperationPurpose::RegressionTest)
    }

    pub fn operations_for_requirement(
        &self,
        requirement: &RequirementId,
    ) -> Vec<&OperationTraceEntry> {
        self.operations
            .iter()
            .filter(|operation| operation.requirement.as_ref() == Some(requirement))
            .collect()
    }

    fn record(&mut self, mut operation: OperationTraceEntry) {
        self.next_sequence += 1;
        operation.sequence = self.next_sequence;
        self.operations.push(operation);
    }
}

#[derive(Debug, Clone)]
struct TraceSpec {
    requirement: Option<RequirementId>,
    kind: AgentOperationKind,
    purpose: OperationPurpose,
    target: String,
    files: Vec<String>,
    symbols: Vec<SymbolId>,
    evidence_ids: Vec<String>,
    command: Option<CommandInvocation>,
}

impl TraceSpec {
    fn new(
        kind: AgentOperationKind,
        target: impl Into<String>,
        mut files: Vec<String>,
        context: OperationContext,
        command: Option<CommandInvocation>,
    ) -> Self {
        for file in context.files {
            if !files.contains(&file) {
                files.push(file);
            }
        }
        Self {
            requirement: context.requirement,
            kind,
            purpose: context.purpose,
            target: target.into(),
            files,
            symbols: context.symbols,
            evidence_ids: context.evidence_ids,
            command,
        }
    }
}

pub struct TrackedDevelopmentSession {
    inner: ControlledDevelopmentSession,
    agent: String,
    telemetry: OperationTelemetry,
}

impl TrackedDevelopmentSession {
    pub fn new(
        repo: &Path,
        agent: impl Into<String>,
        risk: RiskTier,
        policy: DevelopmentFirewallPolicy,
        execution: Arc<dyn ExecutionAdapter>,
    ) -> Result<Self, String> {
        let agent = agent.into();
        let inner =
            ControlledDevelopmentSession::new(repo, agent.clone(), risk, policy, execution)?;
        Ok(Self {
            inner,
            agent,
            telemetry: OperationTelemetry::default(),
        })
    }

    pub fn repository(&self) -> &Path {
        self.inner.repository()
    }

    pub fn controlled_session(&self) -> &ControlledDevelopmentSession {
        &self.inner
    }

    pub fn controlled_session_mut(&mut self) -> &mut ControlledDevelopmentSession {
        &mut self.inner
    }

    pub fn telemetry(&self) -> &OperationTelemetry {
        &self.telemetry
    }

    pub fn active_findings(&self) -> &[Finding] {
        self.inner.active_findings()
    }

    pub fn set_active_findings(&mut self, findings: Vec<Finding>) {
        self.inner.set_active_findings(findings);
    }

    pub fn write_file(
        &mut self,
        relative: &Path,
        content: &[u8],
        context: OperationContext,
    ) -> Result<(), String> {
        let target = display_target(relative);
        let spec = TraceSpec::new(
            AgentOperationKind::Write,
            target.clone(),
            vec![target],
            context,
            None,
        );
        let Some(requirement) = spec.requirement.clone() else {
            return self.reject(spec, "tracked write requires an explicit requirement");
        };
        self.capture_unit(spec, |inner| {
            inner.write_file(relative, content, requirement)
        })
    }

    pub fn write_dependency_file(
        &mut self,
        relative: &Path,
        content: &[u8],
        context: OperationContext,
    ) -> Result<(), String> {
        let target = display_target(relative);
        let spec = TraceSpec::new(
            AgentOperationKind::DependencyChange,
            target.clone(),
            vec![target],
            context,
            None,
        );
        let Some(requirement) = spec.requirement.clone() else {
            return self.reject(
                spec,
                "tracked dependency change requires an explicit requirement",
            );
        };
        self.capture_unit(spec, |inner| {
            inner.write_dependency_file(relative, content, requirement)
        })
    }

    pub fn patch_file(
        &mut self,
        relative: &Path,
        expected: &str,
        replacement: &str,
        context: OperationContext,
    ) -> Result<(), String> {
        let target = display_target(relative);
        let spec = TraceSpec::new(
            AgentOperationKind::Patch,
            target.clone(),
            vec![target],
            context,
            None,
        );
        let Some(requirement) = spec.requirement.clone() else {
            return self.reject(spec, "tracked patch requires an explicit requirement");
        };
        self.capture_unit(spec, |inner| {
            inner.patch_file(relative, expected, replacement, requirement)
        })
    }

    pub fn delete_file(
        &mut self,
        relative: &Path,
        context: OperationContext,
    ) -> Result<(), String> {
        let target = display_target(relative);
        let spec = TraceSpec::new(
            AgentOperationKind::Delete,
            target.clone(),
            vec![target],
            context,
            None,
        );
        let Some(requirement) = spec.requirement.clone() else {
            return self.reject(spec, "tracked delete requires an explicit requirement");
        };
        self.capture_unit(spec, |inner| inner.delete_file(relative, requirement))
    }

    pub fn rename_file(
        &mut self,
        from: &Path,
        to: &Path,
        context: OperationContext,
    ) -> Result<(), String> {
        let source = display_target(from);
        let destination = display_target(to);
        let spec = TraceSpec::new(
            AgentOperationKind::Rename,
            format!("{source} -> {destination}"),
            vec![source, destination],
            context,
            None,
        );
        let Some(requirement) = spec.requirement.clone() else {
            return self.reject(spec, "tracked rename requires an explicit requirement");
        };
        self.capture_unit(spec, |inner| inner.rename_file(from, to, requirement))
    }

    pub fn run_command(
        &mut self,
        program: &str,
        args: &[String],
        context: OperationContext,
    ) -> Result<ExecutionResult, String> {
        let command = CommandInvocation {
            program: program.to_owned(),
            args: args.to_vec(),
        };
        let spec = TraceSpec::new(
            AgentOperationKind::Command,
            program,
            Vec::new(),
            context,
            Some(command),
        );
        let Some(requirement) = spec.requirement.clone() else {
            return self.reject_execution(
                spec,
                "tracked command requires an explicit requirement",
            );
        };
        self.capture_execution(spec, |inner| {
            inner.run_command(program, args, requirement)
        })
    }

    pub fn run_test(
        &mut self,
        program: &str,
        args: &[String],
        context: OperationContext,
    ) -> Result<ExecutionResult, String> {
        let requirement = context.requirement.clone();
        let command = CommandInvocation {
            program: program.to_owned(),
            args: args.to_vec(),
        };
        let spec = TraceSpec::new(
            AgentOperationKind::Test,
            program,
            Vec::new(),
            context,
            Some(command),
        );
        self.capture_execution(spec, |inner| {
            inner.run_test(program, args, requirement)
        })
    }

    pub fn commit(
        &mut self,
        message: &str,
        context: OperationContext,
    ) -> Result<ExecutionResult, String> {
        let command = CommandInvocation {
            program: "git".into(),
            args: vec!["commit".into(), "-m".into(), message.into()],
        };
        let spec = TraceSpec::new(
            AgentOperationKind::Commit,
            "git commit",
            Vec::new(),
            context,
            Some(command),
        );
        let Some(requirement) = spec.requirement.clone() else {
            return self.reject_execution(spec, "tracked commit requires an explicit requirement");
        };
        let evidence_ids = spec.evidence_ids.clone();
        self.capture_execution(spec, |inner| {
            inner.commit(message, requirement, evidence_ids)
        })
    }

    pub fn authorize_certification(
        &mut self,
        engine_certification_id: String,
        context: OperationContext,
    ) -> Result<(), String> {
        let spec = TraceSpec::new(
            AgentOperationKind::Certification,
            "repository certification",
            Vec::new(),
            context,
            None,
        );
        let Some(requirement) = spec.requirement.clone() else {
            return self.reject(
                spec,
                "tracked certification requires an explicit requirement",
            );
        };
        let evidence_ids = spec.evidence_ids.clone();
        self.capture_unit(spec, |inner| {
            inner.authorize_certification(requirement, evidence_ids, engine_certification_id)
        })
    }

    fn capture_unit<F>(&mut self, spec: TraceSpec, action: F) -> Result<(), String>
    where
        F: FnOnce(&mut ControlledDevelopmentSession) -> Result<(), String>,
    {
        let started_unix_ms = unix_ms();
        let started = Instant::now();
        let result = action(&mut self.inner);
        let outcome = match &result {
            Ok(()) => OperationOutcome {
                accepted: true,
                exit_code: None,
                summary: "operation accepted".into(),
            },
            Err(error) => OperationOutcome {
                accepted: false,
                exit_code: None,
                summary: summarize(error),
            },
        };
        self.record_trace(
            spec,
            started_unix_ms,
            started.elapsed().as_millis(),
            outcome,
        );
        result
    }

    fn capture_execution<F>(
        &mut self,
        spec: TraceSpec,
        action: F,
    ) -> Result<ExecutionResult, String>
    where
        F: FnOnce(&mut ControlledDevelopmentSession) -> Result<ExecutionResult, String>,
    {
        let started_unix_ms = unix_ms();
        let started = Instant::now();
        let result = action(&mut self.inner);
        let outcome = match &result {
            Ok(output) => OperationOutcome {
                accepted: true,
                exit_code: Some(output.exit_code),
                summary: "command accepted".into(),
            },
            Err(error) => OperationOutcome {
                accepted: false,
                exit_code: None,
                summary: summarize(error),
            },
        };
        self.record_trace(
            spec,
            started_unix_ms,
            started.elapsed().as_millis(),
            outcome,
        );
        result
    }

    fn reject(&mut self, spec: TraceSpec, message: &str) -> Result<(), String> {
        self.record_rejection(spec, message);
        Err(message.into())
    }

    fn reject_execution(
        &mut self,
        spec: TraceSpec,
        message: &str,
    ) -> Result<ExecutionResult, String> {
        self.record_rejection(spec, message);
        Err(message.into())
    }

    fn record_rejection(&mut self, spec: TraceSpec, message: &str) {
        self.record_trace(
            spec,
            unix_ms(),
            0,
            OperationOutcome {
                accepted: false,
                exit_code: None,
                summary: summarize(message),
            },
        );
    }

    fn record_trace(
        &mut self,
        spec: TraceSpec,
        started_unix_ms: u128,
        duration_ms: u128,
        outcome: OperationOutcome,
    ) {
        self.telemetry.record(OperationTraceEntry {
            sequence: 0,
            agent: self.agent.clone(),
            requirement: spec.requirement,
            kind: spec.kind,
            purpose: spec.purpose,
            target: spec.target,
            files: spec.files,
            symbols: spec.symbols,
            evidence_ids: spec.evidence_ids,
            command: spec.command,
            started_unix_ms,
            duration_ms,
            outcome,
        });
    }
}

fn display_target(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

fn summarize(value: &str) -> String {
    value.chars().take(MAX_SUMMARY_CHARS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

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

    fn temp_dir() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("verificationforge-telemetry-{nonce}"))
    }

    fn requirement() -> RequirementId {
        RequirementId("REQ-TRACE".into())
    }

    fn symbol() -> SymbolId {
        SymbolId("rust:function:src/lib.rs::value".into())
    }

    fn context(purpose: OperationPurpose) -> OperationContext {
        OperationContext::for_requirement(requirement())
            .with_purpose(purpose)
            .with_symbols([symbol()])
    }

    #[test]
    fn tracks_files_symbols_commands_results_and_special_attempts() {
        let root = temp_dir();
        fs::create_dir_all(root.join("src")).expect("create src");
        let execution = Arc::new(RecordingExecution::default());
        let mut session = TrackedDevelopmentSession::new(
            &root,
            "agent-a",
            RiskTier::High,
            DevelopmentFirewallPolicy::default(),
            execution.clone(),
        )
        .expect("create tracked session");

        session
            .write_file(
                Path::new("src/lib.rs"),
                b"pub fn value() -> u8 { 1 }\n",
                context(OperationPurpose::Normal),
            )
            .expect("write source");
        session
            .patch_file(
                Path::new("src/lib.rs"),
                "1",
                "2",
                context(OperationPurpose::FixAttempt),
            )
            .expect("patch fix");
        let args = vec!["test".into(), "--workspace".into(), "--locked".into()];
        session
            .run_test(
                "cargo",
                &args,
                context(OperationPurpose::RegressionTest)
                    .with_evidence(["evidence-regression".into()]),
            )
            .expect("regression test");

        let operations = session.telemetry().operations();
        assert_eq!(operations.len(), 3);
        assert_eq!(operations[0].files, vec!["src/lib.rs"]);
        assert_eq!(operations[0].symbols, vec![symbol()]);
        assert_eq!(operations[1].purpose, OperationPurpose::FixAttempt);
        assert_eq!(operations[2].purpose, OperationPurpose::RegressionTest);
        assert_eq!(operations[2].evidence_ids, vec!["evidence-regression"]);
        assert_eq!(
            operations[2].command,
            Some(CommandInvocation {
                program: "cargo".into(),
                args: args.clone(),
            })
        );
        assert_eq!(operations[2].outcome.exit_code, Some(0));
        assert!(
            operations
                .iter()
                .all(|operation| operation.outcome.accepted)
        );
        assert!(
            operations
                .iter()
                .all(|operation| operation.started_unix_ms > 0)
        );
        assert_eq!(session.telemetry().fix_attempts().count(), 1);
        assert_eq!(session.telemetry().regression_tests().count(), 1);
        assert_eq!(
            session
                .telemetry()
                .operations_for_requirement(&requirement())
                .len(),
            3
        );
        assert_eq!(
            execution
                .calls
                .lock()
                .expect("calls lock poisoned")
                .as_slice(),
            &[("cargo".into(), args)]
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn denied_operation_is_preserved_in_telemetry() {
        let root = temp_dir();
        fs::create_dir_all(&root).expect("create root");
        let execution = Arc::new(RecordingExecution::default());
        let mut session = TrackedDevelopmentSession::new(
            &root,
            "agent-a",
            RiskTier::Critical,
            DevelopmentFirewallPolicy::default(),
            execution.clone(),
        )
        .expect("create tracked session");
        session.set_active_findings(vec![Finding {
            code: "VF_SECURITY_CRITICAL".into(),
            message: "critical finding remains".into(),
            blocking: true,
        }]);

        let error = session
            .commit(
                "blocked commit",
                context(OperationPurpose::Normal).with_evidence(["evidence-1".into()]),
            )
            .expect_err("commit must be denied");
        assert!(error.contains("VF_FIREWALL_ACTIVE_BLOCKER"));

        let operation = session
            .telemetry()
            .operations()
            .last()
            .expect("trace entry");
        assert!(!operation.outcome.accepted);
        assert!(
            operation
                .outcome
                .summary
                .contains("VF_FIREWALL_ACTIVE_BLOCKER")
        );
        assert_eq!(session.telemetry().failed_operations().count(), 1);
        assert!(
            execution
                .calls
                .lock()
                .expect("calls lock poisoned")
                .is_empty()
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn missing_requirement_is_traced_before_execution() {
        let root = temp_dir();
        fs::create_dir_all(&root).expect("create root");
        let execution = Arc::new(RecordingExecution::default());
        let mut session = TrackedDevelopmentSession::new(
            &root,
            "agent-a",
            RiskTier::High,
            DevelopmentFirewallPolicy::default(),
            execution,
        )
        .expect("create tracked session");

        let error = session
            .run_command("cargo", &["check".into()], OperationContext::default())
            .expect_err("unscoped command must fail");
        assert!(error.contains("explicit requirement"));
        let operation = session.telemetry().operations().last().expect("trace entry");
        assert!(!operation.outcome.accepted);
        assert_eq!(operation.command.as_ref().expect("command").args, ["check"]);
        fs::remove_dir_all(root).ok();
    }
}
