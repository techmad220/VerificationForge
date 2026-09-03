use std::path::Path;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use verificationforge_core::{
    AgentOperationKind, DevelopmentFirewallPolicy, ExecutionAdapter, ExecutionResult, Finding,
    RequirementId, RiskTier, SymbolId,
};

use crate::ControlledDevelopmentSession;

const MAX_SUMMARY_CHARS: usize = 2_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationPurpose {
    Normal,
    FixAttempt,
    RegressionTest,
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

    pub fn for_requirement<'a>(
        &'a self,
        requirement: &'a RequirementId,
    ) -> impl Iterator<Item = &'a OperationTraceEntry> + 'a {
        self.operations
            .iter()
            .filter(move |operation| operation.requirement.as_ref() == Some(requirement))
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
        let inner = ControlledDevelopmentSession::new(
            repo,
            agent.clone(),
            risk,
            policy,
            execution,
        )?;
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
        requirement: RequirementId,
        symbols: Vec<SymbolId>,
    ) -> Result<(), String> {
        let target = display_target(relative);
        let spec = TraceSpec {
            requirement: Some(requirement.clone()),
            kind: AgentOperationKind::Write,
            purpose: OperationPurpose::Normal,
            target: target.clone(),
            files: vec![target],
            symbols,
            evidence_ids: Vec::new(),
            command: None,
        };
        self.capture_unit(spec, |inner| inner.write_file(relative, content, requirement))
    }

    pub fn write_dependency_file(
        &mut self,
        relative: &Path,
        content: &[u8],
        requirement: RequirementId,
        symbols: Vec<SymbolId>,
    ) -> Result<(), String> {
        let target = display_target(relative);
        let spec = TraceSpec {
            requirement: Some(requirement.clone()),
            kind: AgentOperationKind::DependencyChange,
            purpose: OperationPurpose::Normal,
            target: target.clone(),
            files: vec![target],
            symbols,
            evidence_ids: Vec::new(),
            command: None,
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
        requirement: RequirementId,
        symbols: Vec<SymbolId>,
    ) -> Result<(), String> {
        self.patch_with_purpose(
            relative,
            expected,
            replacement,
            requirement,
            symbols,
            OperationPurpose::Normal,
        )
    }

    pub fn patch_fix(
        &mut self,
        relative: &Path,
        expected: &str,
        replacement: &str,
        requirement: RequirementId,
        symbols: Vec<SymbolId>,
    ) -> Result<(), String> {
        self.patch_with_purpose(
            relative,
            expected,
            replacement,
            requirement,
            symbols,
            OperationPurpose::FixAttempt,
        )
    }

    pub fn delete_file(
        &mut self,
        relative: &Path,
        requirement: RequirementId,
        symbols: Vec<SymbolId>,
    ) -> Result<(), String> {
        let target = display_target(relative);
        let spec = TraceSpec {
            requirement: Some(requirement.clone()),
            kind: AgentOperationKind::Delete,
            purpose: OperationPurpose::Normal,
            target: target.clone(),
            files: vec![target],
            symbols,
            evidence_ids: Vec::new(),
            command: None,
        };
        self.capture_unit(spec, |inner| inner.delete_file(relative, requirement))
    }

    pub fn rename_file(
        &mut self,
        from: &Path,
        to: &Path,
        requirement: RequirementId,
        symbols: Vec<SymbolId>,
    ) -> Result<(), String> {
        let source = display_target(from);
        let destination = display_target(to);
        let target = format!("{source} -> {destination}");
        let spec = TraceSpec {
            requirement: Some(requirement.clone()),
            kind: AgentOperationKind::Rename,
            purpose: OperationPurpose::Normal,
            target,
            files: vec![source, destination],
            symbols,
            evidence_ids: Vec::new(),
            command: None,
        };
        self.capture_unit(spec, |inner| inner.rename_file(from, to, requirement))
    }

    pub fn run_command(
        &mut self,
        program: &str,
        args: &[String],
        requirement: RequirementId,
        symbols: Vec<SymbolId>,
    ) -> Result<ExecutionResult, String> {
        self.run_command_with_purpose(
            AgentOperationKind::Command,
            OperationPurpose::Normal,
            program,
            args,
            Some(requirement),
            Vec::new(),
            symbols,
        )
    }

    pub fn run_fix_command(
        &mut self,
        program: &str,
        args: &[String],
        requirement: RequirementId,
        symbols: Vec<SymbolId>,
    ) -> Result<ExecutionResult, String> {
        self.run_command_with_purpose(
            AgentOperationKind::Command,
            OperationPurpose::FixAttempt,
            program,
            args,
            Some(requirement),
            Vec::new(),
            symbols,
        )
    }

    pub fn run_test(
        &mut self,
        program: &str,
        args: &[String],
        requirement: Option<RequirementId>,
        symbols: Vec<SymbolId>,
    ) -> Result<ExecutionResult, String> {
        self.run_command_with_purpose(
            AgentOperationKind::Test,
            OperationPurpose::Normal,
            program,
            args,
            requirement,
            Vec::new(),
            symbols,
        )
    }

    pub fn run_regression_test(
        &mut self,
        program: &str,
        args: &[String],
        requirement: RequirementId,
        evidence_ids: Vec<String>,
        symbols: Vec<SymbolId>,
    ) -> Result<ExecutionResult, String> {
        self.run_command_with_purpose(
            AgentOperationKind::Test,
            OperationPurpose::RegressionTest,
            program,
            args,
            Some(requirement),
            evidence_ids,
            symbols,
        )
    }

    pub fn commit(
        &mut self,
        message: &str,
        requirement: RequirementId,
        evidence_ids: Vec<String>,
        symbols: Vec<SymbolId>,
    ) -> Result<ExecutionResult, String> {
        let args = vec!["commit".to_owned(), "-m".to_owned(), message.to_owned()];
        let spec = TraceSpec {
            requirement: Some(requirement.clone()),
            kind: AgentOperationKind::Commit,
            purpose: OperationPurpose::Normal,
            target: "git commit".into(),
            files: Vec::new(),
            symbols,
            evidence_ids: evidence_ids.clone(),
            command: Some(CommandInvocation {
                program: "git".into(),
                args,
            }),
        };
        self.capture_execution(spec, |inner| {
            inner.commit(message, requirement, evidence_ids)
        })
    }

    pub fn authorize_certification(
        &mut self,
        requirement: RequirementId,
        evidence_ids: Vec<String>,
        engine_certification_id: String,
        symbols: Vec<SymbolId>,
    ) -> Result<(), String> {
        let spec = TraceSpec {
            requirement: Some(requirement.clone()),
            kind: AgentOperationKind::Certification,
            purpose: OperationPurpose::Normal,
            target: "repository certification".into(),
            files: Vec::new(),
            symbols,
            evidence_ids: evidence_ids.clone(),
            command: None,
        };
        self.capture_unit(spec, |inner| {
            inner.authorize_certification(requirement, evidence_ids, engine_certification_id)
        })
    }

    fn patch_with_purpose(
        &mut self,
        relative: &Path,
        expected: &str,
        replacement: &str,
        requirement: RequirementId,
        symbols: Vec<SymbolId>,
        purpose: OperationPurpose,
    ) -> Result<(), String> {
        let target = display_target(relative);
        let spec = TraceSpec {
            requirement: Some(requirement.clone()),
            kind: AgentOperationKind::Patch,
            purpose,
            target: target.clone(),
            files: vec![target],
            symbols,
            evidence_ids: Vec::new(),
            command: None,
        };
        self.capture_unit(spec, |inner| {
            inner.patch_file(relative, expected, replacement, requirement)
        })
    }

    fn run_command_with_purpose(
        &mut self,
        kind: AgentOperationKind,
        purpose: OperationPurpose,
        program: &str,
        args: &[String],
        requirement: Option<RequirementId>,
        evidence_ids: Vec<String>,
        symbols: Vec<SymbolId>,
    ) -> Result<ExecutionResult, String> {
        let spec = TraceSpec {
            requirement: requirement.clone(),
            kind,
            purpose,
            target: program.to_owned(),
            files: Vec::new(),
            symbols,
            evidence_ids,
            command: Some(CommandInvocation {
                program: program.to_owned(),
                args: args.to_vec(),
            }),
        };
        match kind {
            AgentOperationKind::Test => self.capture_execution(spec, |inner| {
                inner.run_test(program, args, requirement)
            }),
            AgentOperationKind::Command => {
                let requirement = requirement
                    .ok_or_else(|| "tracked command requires an explicit requirement".to_owned())?;
                self.capture_execution(spec, |inner| {
                    inner.run_command(program, args, requirement)
                })
            }
            _ => Err("tracked command received a non-command operation kind".into()),
        }
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
        self.record_trace(spec, started_unix_ms, started.elapsed().as_millis(), outcome);
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
        self.record_trace(spec, started_unix_ms, started.elapsed().as_millis(), outcome);
        result
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
                requirement(),
                vec![symbol()],
            )
            .expect("write source");
        session
            .patch_fix(
                Path::new("src/lib.rs"),
                "1",
                "2",
                requirement(),
                vec![symbol()],
            )
            .expect("patch fix");
        let args = vec!["test".into(), "--workspace".into(), "--locked".into()];
        session
            .run_regression_test(
                "cargo",
                &args,
                requirement(),
                vec!["evidence-regression".into()],
                vec![symbol()],
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
        assert!(operations.iter().all(|operation| operation.outcome.accepted));
        assert!(operations.iter().all(|operation| operation.started_unix_ms > 0));
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
                requirement(),
                vec!["evidence-1".into()],
                vec![symbol()],
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
}
