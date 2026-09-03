use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use verificationforge_core::{
    AgentOperationKind, ControlledOperationRequest, DevelopmentFirewallPolicy, ExecutionAdapter,
    ExecutionResult, Finding, OperationLedger, RequirementId, RiskTier,
};

pub struct ControlledDevelopmentSession {
    repo: PathBuf,
    agent: String,
    risk: RiskTier,
    policy: DevelopmentFirewallPolicy,
    execution: Arc<dyn ExecutionAdapter>,
    ledger: OperationLedger,
    active_findings: Vec<Finding>,
}

impl ControlledDevelopmentSession {
    pub fn new(
        repo: &Path,
        agent: impl Into<String>,
        risk: RiskTier,
        policy: DevelopmentFirewallPolicy,
        execution: Arc<dyn ExecutionAdapter>,
    ) -> Result<Self, String> {
        let repo = repo
            .canonicalize()
            .map_err(|error| format!("cannot resolve repository {}: {error}", repo.display()))?;
        if !repo.is_dir() {
            return Err(format!("repository {} is not a directory", repo.display()));
        }
        let agent = agent.into();
        if agent.trim().is_empty() {
            return Err(
                "controlled development session requires a non-empty agent identity".into(),
            );
        }
        Ok(Self {
            repo,
            agent,
            risk,
            policy,
            execution,
            ledger: OperationLedger::default(),
            active_findings: Vec::new(),
        })
    }

    pub fn repository(&self) -> &Path {
        &self.repo
    }

    pub fn ledger(&self) -> &OperationLedger {
        &self.ledger
    }

    pub fn active_findings(&self) -> &[Finding] {
        &self.active_findings
    }

    pub fn set_active_findings(&mut self, findings: Vec<Finding>) {
        self.active_findings = findings;
    }

    pub fn read_file(&mut self, relative: &Path) -> Result<String, String> {
        let target = display_target(relative);
        let path = match self.resolve_existing(relative) {
            Ok(path) => path,
            Err(error) => {
                self.record(AgentOperationKind::Read, None, target, false, Vec::new());
                return Err(error);
            }
        };
        let request = self.request(
            AgentOperationKind::Read,
            target.clone(),
            None,
            Vec::new(),
            None,
        );
        if let Err(error) = self.authorize(&request) {
            self.record(AgentOperationKind::Read, None, target, false, Vec::new());
            return Err(error);
        }
        match fs::read_to_string(&path) {
            Ok(content) => {
                self.record(AgentOperationKind::Read, None, target, true, Vec::new());
                Ok(content)
            }
            Err(error) => {
                self.record(
                    AgentOperationKind::Read,
                    None,
                    target.clone(),
                    false,
                    Vec::new(),
                );
                Err(format!("cannot read {target}: {error}"))
            }
        }
    }

    pub fn write_file(
        &mut self,
        relative: &Path,
        content: &[u8],
        requirement: RequirementId,
    ) -> Result<(), String> {
        self.write_controlled(AgentOperationKind::Write, relative, content, requirement)
    }

    pub fn write_dependency_file(
        &mut self,
        relative: &Path,
        content: &[u8],
        requirement: RequirementId,
    ) -> Result<(), String> {
        self.write_controlled(
            AgentOperationKind::DependencyChange,
            relative,
            content,
            requirement,
        )
    }

    pub fn patch_file(
        &mut self,
        relative: &Path,
        expected: &str,
        replacement: &str,
        requirement: RequirementId,
    ) -> Result<(), String> {
        let target = display_target(relative);
        if expected.is_empty() {
            self.record(
                AgentOperationKind::Patch,
                Some(requirement),
                target,
                false,
                Vec::new(),
            );
            return Err("exact patch match cannot be empty".into());
        }
        let path = match self.resolve_existing(relative) {
            Ok(path) => path,
            Err(error) => {
                self.record(
                    AgentOperationKind::Patch,
                    Some(requirement),
                    target,
                    false,
                    Vec::new(),
                );
                return Err(error);
            }
        };
        let content = fs::read_to_string(&path)
            .map_err(|error| format!("cannot read {target} for patching: {error}"))?;
        let matches = content.match_indices(expected).count();
        if matches != 1 {
            self.record(
                AgentOperationKind::Patch,
                Some(requirement),
                target.clone(),
                false,
                Vec::new(),
            );
            return Err(format!(
                "exact patch for {target} requires one match, found {matches}"
            ));
        }

        let request = self.request(
            AgentOperationKind::Patch,
            target.clone(),
            Some(requirement.clone()),
            Vec::new(),
            None,
        );
        if let Err(error) = self.authorize(&request) {
            self.record(
                AgentOperationKind::Patch,
                Some(requirement),
                target,
                false,
                Vec::new(),
            );
            return Err(error);
        }

        let updated = content.replacen(expected, replacement, 1);
        match fs::write(&path, updated.as_bytes()) {
            Ok(()) => {
                self.record(
                    AgentOperationKind::Patch,
                    Some(requirement),
                    target,
                    true,
                    Vec::new(),
                );
                Ok(())
            }
            Err(error) => {
                self.record(
                    AgentOperationKind::Patch,
                    Some(requirement),
                    target.clone(),
                    false,
                    Vec::new(),
                );
                Err(format!("cannot patch {target}: {error}"))
            }
        }
    }

    pub fn delete_file(
        &mut self,
        relative: &Path,
        requirement: RequirementId,
    ) -> Result<(), String> {
        let target = display_target(relative);
        let path = match self.resolve_existing(relative) {
            Ok(path) => path,
            Err(error) => {
                self.record(
                    AgentOperationKind::Delete,
                    Some(requirement),
                    target,
                    false,
                    Vec::new(),
                );
                return Err(error);
            }
        };
        if !path.is_file() {
            self.record(
                AgentOperationKind::Delete,
                Some(requirement),
                target.clone(),
                false,
                Vec::new(),
            );
            return Err(format!("controlled delete only accepts files: {target}"));
        }
        let request = self.request(
            AgentOperationKind::Delete,
            target.clone(),
            Some(requirement.clone()),
            Vec::new(),
            None,
        );
        if let Err(error) = self.authorize(&request) {
            self.record(
                AgentOperationKind::Delete,
                Some(requirement),
                target,
                false,
                Vec::new(),
            );
            return Err(error);
        }
        match fs::remove_file(&path) {
            Ok(()) => {
                self.record(
                    AgentOperationKind::Delete,
                    Some(requirement),
                    target,
                    true,
                    Vec::new(),
                );
                Ok(())
            }
            Err(error) => {
                self.record(
                    AgentOperationKind::Delete,
                    Some(requirement),
                    target.clone(),
                    false,
                    Vec::new(),
                );
                Err(format!("cannot delete {target}: {error}"))
            }
        }
    }

    pub fn rename_file(
        &mut self,
        from: &Path,
        to: &Path,
        requirement: RequirementId,
    ) -> Result<(), String> {
        let source_target = display_target(from);
        let destination_target = display_target(to);
        let operation_target = format!("{source_target} -> {destination_target}");
        let source = match self.resolve_existing(from) {
            Ok(path) => path,
            Err(error) => {
                self.record(
                    AgentOperationKind::Rename,
                    Some(requirement),
                    operation_target,
                    false,
                    Vec::new(),
                );
                return Err(error);
            }
        };
        if !source.is_file() {
            self.record(
                AgentOperationKind::Rename,
                Some(requirement),
                operation_target.clone(),
                false,
                Vec::new(),
            );
            return Err(format!(
                "controlled rename only accepts files: {source_target}"
            ));
        }
        let destination = match self.resolve_for_write(to) {
            Ok(path) => path,
            Err(error) => {
                self.record(
                    AgentOperationKind::Rename,
                    Some(requirement),
                    operation_target,
                    false,
                    Vec::new(),
                );
                return Err(error);
            }
        };
        if destination.exists() {
            self.record(
                AgentOperationKind::Rename,
                Some(requirement),
                operation_target,
                false,
                Vec::new(),
            );
            return Err(format!(
                "rename destination already exists: {destination_target}"
            ));
        }
        let request = self.request(
            AgentOperationKind::Rename,
            operation_target.clone(),
            Some(requirement.clone()),
            Vec::new(),
            None,
        );
        if let Err(error) = self.authorize(&request) {
            self.record(
                AgentOperationKind::Rename,
                Some(requirement),
                operation_target,
                false,
                Vec::new(),
            );
            return Err(error);
        }
        match fs::rename(&source, &destination) {
            Ok(()) => {
                self.record(
                    AgentOperationKind::Rename,
                    Some(requirement),
                    operation_target,
                    true,
                    Vec::new(),
                );
                Ok(())
            }
            Err(error) => {
                self.record(
                    AgentOperationKind::Rename,
                    Some(requirement),
                    operation_target.clone(),
                    false,
                    Vec::new(),
                );
                Err(format!("cannot rename {operation_target}: {error}"))
            }
        }
    }

    pub fn run_command(
        &mut self,
        program: &str,
        args: &[String],
        requirement: RequirementId,
    ) -> Result<ExecutionResult, String> {
        self.execute_controlled(
            AgentOperationKind::Command,
            program,
            args,
            Some(requirement),
            Vec::new(),
        )
    }

    pub fn run_test(
        &mut self,
        program: &str,
        args: &[String],
        requirement: Option<RequirementId>,
    ) -> Result<ExecutionResult, String> {
        self.execute_controlled(
            AgentOperationKind::Test,
            program,
            args,
            requirement,
            Vec::new(),
        )
    }

    pub fn commit(
        &mut self,
        message: &str,
        requirement: RequirementId,
        evidence_ids: Vec<String>,
    ) -> Result<ExecutionResult, String> {
        if message.trim().is_empty() {
            self.record(
                AgentOperationKind::Commit,
                Some(requirement),
                "git commit",
                false,
                evidence_ids,
            );
            return Err("commit message cannot be empty".into());
        }
        let args = vec!["commit".to_owned(), "-m".to_owned(), message.to_owned()];
        self.execute_controlled(
            AgentOperationKind::Commit,
            "git",
            &args,
            Some(requirement),
            evidence_ids,
        )
    }

    pub fn authorize_certification(
        &mut self,
        requirement: RequirementId,
        evidence_ids: Vec<String>,
        engine_certification_id: String,
    ) -> Result<(), String> {
        let target = "repository certification".to_owned();
        let request = self.request(
            AgentOperationKind::Certification,
            target.clone(),
            Some(requirement.clone()),
            evidence_ids.clone(),
            Some(engine_certification_id),
        );
        match self.authorize(&request) {
            Ok(()) => {
                self.record(
                    AgentOperationKind::Certification,
                    Some(requirement),
                    target,
                    true,
                    evidence_ids,
                );
                Ok(())
            }
            Err(error) => {
                self.record(
                    AgentOperationKind::Certification,
                    Some(requirement),
                    target,
                    false,
                    evidence_ids,
                );
                Err(error)
            }
        }
    }

    fn write_controlled(
        &mut self,
        kind: AgentOperationKind,
        relative: &Path,
        content: &[u8],
        requirement: RequirementId,
    ) -> Result<(), String> {
        let target = display_target(relative);
        let path = match self.resolve_for_write(relative) {
            Ok(path) => path,
            Err(error) => {
                self.record(kind, Some(requirement), target, false, Vec::new());
                return Err(error);
            }
        };
        let request = self.request(
            kind,
            target.clone(),
            Some(requirement.clone()),
            Vec::new(),
            None,
        );
        if let Err(error) = self.authorize(&request) {
            self.record(kind, Some(requirement), target, false, Vec::new());
            return Err(error);
        }
        match fs::write(&path, content) {
            Ok(()) => {
                self.record(kind, Some(requirement), target, true, Vec::new());
                Ok(())
            }
            Err(error) => {
                self.record(kind, Some(requirement), target.clone(), false, Vec::new());
                Err(format!("cannot write {target}: {error}"))
            }
        }
    }

    fn execute_controlled(
        &mut self,
        kind: AgentOperationKind,
        program: &str,
        args: &[String],
        requirement: Option<RequirementId>,
        evidence_ids: Vec<String>,
    ) -> Result<ExecutionResult, String> {
        if program.trim().is_empty() {
            self.record(kind, requirement, "command", false, evidence_ids);
            return Err("controlled command requires a non-empty program".into());
        }
        let target = program.to_owned();
        let request = self.request(
            kind,
            target.clone(),
            requirement.clone(),
            evidence_ids.clone(),
            None,
        );
        if let Err(error) = self.authorize(&request) {
            self.record(kind, requirement, target, false, evidence_ids);
            return Err(error);
        }
        match self.execution.execute(program, args, &self.repo) {
            Ok(output) if output.success() => {
                self.record(kind, requirement, target, true, evidence_ids);
                Ok(output)
            }
            Ok(output) => {
                self.record(kind, requirement, target.clone(), false, evidence_ids);
                Err(format!(
                    "controlled command {target} exited with code {}: {}",
                    output.exit_code,
                    command_detail(&output)
                ))
            }
            Err(error) => {
                self.record(kind, requirement, target.clone(), false, evidence_ids);
                Err(format!("controlled command {target} failed: {error}"))
            }
        }
    }

    fn request(
        &self,
        kind: AgentOperationKind,
        target: String,
        requirement: Option<RequirementId>,
        evidence_ids: Vec<String>,
        engine_certification_id: Option<String>,
    ) -> ControlledOperationRequest {
        ControlledOperationRequest {
            agent: self.agent.clone(),
            requirement,
            kind,
            target,
            risk: self.risk,
            evidence_ids,
            engine_certification_id,
            active_findings: self.active_findings.clone(),
        }
    }

    fn authorize(&self, request: &ControlledOperationRequest) -> Result<(), String> {
        let decision = self.policy.evaluate(request);
        if decision.allowed {
            return Ok(());
        }
        Err(decision
            .blockers
            .iter()
            .map(|finding| format!("{}: {}", finding.code, finding.message))
            .collect::<Vec<_>>()
            .join("; "))
    }

    fn record(
        &mut self,
        kind: AgentOperationKind,
        requirement: Option<RequirementId>,
        target: impl Into<String>,
        accepted: bool,
        evidence_ids: Vec<String>,
    ) {
        self.ledger.record(
            self.agent.clone(),
            requirement,
            kind,
            target,
            accepted,
            evidence_ids,
        );
    }

    fn resolve_existing(&self, relative: &Path) -> Result<PathBuf, String> {
        self.validate_relative(relative)?;
        self.reject_symlink_components(relative)?;
        let candidate = self.repo.join(relative);
        let resolved = candidate
            .canonicalize()
            .map_err(|error| format!("cannot resolve {}: {error}", candidate.display()))?;
        if !resolved.starts_with(&self.repo) {
            return Err(format!(
                "path escapes repository boundary: {}",
                relative.display()
            ));
        }
        Ok(resolved)
    }

    fn resolve_for_write(&self, relative: &Path) -> Result<PathBuf, String> {
        self.validate_relative(relative)?;
        self.reject_symlink_components(relative)?;
        let candidate = self.repo.join(relative);
        let parent = candidate
            .parent()
            .ok_or_else(|| format!("path has no parent: {}", relative.display()))?;
        let resolved_parent = parent.canonicalize().map_err(|error| {
            format!(
                "cannot resolve parent {} for {}: {error}",
                parent.display(),
                relative.display()
            )
        })?;
        if !resolved_parent.starts_with(&self.repo) {
            return Err(format!(
                "path escapes repository boundary: {}",
                relative.display()
            ));
        }
        let file_name = candidate
            .file_name()
            .ok_or_else(|| format!("path has no file name: {}", relative.display()))?;
        Ok(resolved_parent.join(file_name))
    }

    fn validate_relative(&self, relative: &Path) -> Result<(), String> {
        if relative.as_os_str().is_empty() {
            return Err("controlled path cannot be empty".into());
        }
        if relative.is_absolute() {
            return Err(format!(
                "absolute paths are forbidden in controlled operations: {}",
                relative.display()
            ));
        }
        for component in relative.components() {
            match component {
                Component::Normal(value) => {
                    if value == ".git" {
                        return Err(
                            "direct .git mutation is forbidden; use controlled VCS operations"
                                .into(),
                        );
                    }
                }
                Component::CurDir => {}
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(format!(
                        "path traversal is forbidden in controlled operations: {}",
                        relative.display()
                    ));
                }
            }
        }
        Ok(())
    }

    fn reject_symlink_components(&self, relative: &Path) -> Result<(), String> {
        let mut current = self.repo.clone();
        for component in relative.components() {
            let Component::Normal(value) = component else {
                continue;
            };
            current.push(value);
            match fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(format!(
                        "symlink traversal is forbidden in controlled operations: {}",
                        relative.display()
                    ));
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(error) => {
                    return Err(format!(
                        "cannot inspect path component {}: {error}",
                        current.display()
                    ));
                }
            }
        }
        Ok(())
    }
}

fn display_target(relative: &Path) -> String {
    relative.to_string_lossy().replace('\\', "/")
}

fn command_detail(output: &ExecutionResult) -> String {
    let detail = if output.stderr.trim().is_empty() {
        output.stdout.trim()
    } else {
        output.stderr.trim()
    };
    detail.chars().take(2000).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Default)]
    struct FakeExecution {
        calls: Mutex<Vec<(String, Vec<String>)>>,
        results: Mutex<BTreeMap<String, ExecutionResult>>,
    }

    impl ExecutionAdapter for FakeExecution {
        fn id(&self) -> &'static str {
            "fake"
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
            Ok(self
                .results
                .lock()
                .expect("results lock poisoned")
                .get(program)
                .cloned()
                .unwrap_or(ExecutionResult {
                    exit_code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                }))
        }
    }

    fn temp_dir() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("verificationforge-development-{nonce}"))
    }

    fn requirement() -> RequirementId {
        RequirementId("REQ-1".into())
    }

    fn session(root: &Path, execution: Arc<dyn ExecutionAdapter>) -> ControlledDevelopmentSession {
        ControlledDevelopmentSession::new(
            root,
            "agent-a",
            RiskTier::High,
            DevelopmentFirewallPolicy::default(),
            execution,
        )
        .expect("create controlled session")
    }

    #[test]
    fn safe_read_write_patch_rename_delete_are_enforced_and_logged() {
        let root = temp_dir();
        fs::create_dir_all(root.join("src")).expect("create src");
        let execution = Arc::new(FakeExecution::default());
        let mut session = session(&root, execution);

        session
            .write_file(Path::new("src/value.txt"), b"old", requirement())
            .expect("write");
        assert_eq!(
            session.read_file(Path::new("src/value.txt")).expect("read"),
            "old"
        );
        session
            .patch_file(Path::new("src/value.txt"), "old", "new", requirement())
            .expect("patch");
        session
            .rename_file(
                Path::new("src/value.txt"),
                Path::new("src/renamed.txt"),
                requirement(),
            )
            .expect("rename");
        session
            .delete_file(Path::new("src/renamed.txt"), requirement())
            .expect("delete");

        assert!(!root.join("src/renamed.txt").exists());
        assert_eq!(session.ledger().operations.len(), 5);
        assert!(
            session
                .ledger()
                .operations
                .iter()
                .all(|operation| operation.accepted)
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn traversal_and_direct_git_mutation_are_rejected_without_writes() {
        let root = temp_dir();
        fs::create_dir_all(root.join("src")).expect("create src");
        fs::create_dir_all(root.join(".git")).expect("create git dir");
        let execution = Arc::new(FakeExecution::default());
        let mut session = session(&root, execution);

        assert!(
            session
                .write_file(Path::new("../escape.txt"), b"bad", requirement())
                .is_err()
        );
        assert!(
            session
                .write_file(Path::new(".git/config"), b"bad", requirement())
                .is_err()
        );
        assert!(
            !root
                .parent()
                .expect("root parent")
                .join("escape.txt")
                .exists()
        );
        assert_eq!(session.ledger().operations.len(), 2);
        assert!(
            session
                .ledger()
                .operations
                .iter()
                .all(|operation| !operation.accepted)
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn exact_patch_rejects_ambiguous_match() {
        let root = temp_dir();
        fs::create_dir_all(root.join("src")).expect("create src");
        fs::write(root.join("src/value.txt"), "same same").expect("write fixture");
        let execution = Arc::new(FakeExecution::default());
        let mut session = session(&root, execution);
        let error = session
            .patch_file(Path::new("src/value.txt"), "same", "new", requirement())
            .expect_err("ambiguous patch must fail");
        assert!(error.contains("requires one match"));
        assert_eq!(
            fs::read_to_string(root.join("src/value.txt")).expect("read fixture"),
            "same same"
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn controlled_commands_use_exact_argv_and_are_logged() {
        let root = temp_dir();
        fs::create_dir_all(&root).expect("create root");
        let execution = Arc::new(FakeExecution::default());
        let mut session = session(&root, execution.clone());
        let args = vec!["test".into(), "--workspace".into(), "--locked".into()];
        session
            .run_test("cargo", &args, Some(requirement()))
            .expect("test command");
        assert_eq!(
            execution
                .calls
                .lock()
                .expect("calls lock poisoned")
                .as_slice(),
            &[("cargo".into(), args)]
        );
        assert!(
            session
                .ledger()
                .operations
                .last()
                .expect("operation")
                .accepted
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn commit_requires_evidence_before_git_is_called() {
        let root = temp_dir();
        fs::create_dir_all(&root).expect("create root");
        let execution = Arc::new(FakeExecution::default());
        let mut session = session(&root, execution.clone());
        let error = session
            .commit("verified change", requirement(), Vec::new())
            .expect_err("commit without evidence must fail");
        assert!(error.contains("VF_FIREWALL_EVIDENCE_REQUIRED"));
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
    fn blocking_finding_prevents_commit_and_certification() {
        let root = temp_dir();
        fs::create_dir_all(&root).expect("create root");
        let execution = Arc::new(FakeExecution::default());
        let mut session = session(&root, execution.clone());
        session.set_active_findings(vec![Finding {
            code: "VF_SECURITY_CRITICAL".into(),
            message: "critical issue".into(),
            blocking: true,
        }]);

        assert!(
            session
                .commit("verified change", requirement(), vec!["evidence-1".into()])
                .is_err()
        );
        assert!(
            session
                .authorize_certification(
                    requirement(),
                    vec!["evidence-1".into()],
                    "vf-cert-1".into(),
                )
                .is_err()
        );
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
    fn certification_requires_engine_issued_id() {
        let root = temp_dir();
        fs::create_dir_all(&root).expect("create root");
        let execution = Arc::new(FakeExecution::default());
        let mut session = session(&root, execution);
        let error = session
            .authorize_certification(requirement(), vec!["evidence-1".into()], String::new())
            .expect_err("blank certification id must fail");
        assert!(error.contains("VF_FIREWALL_ENGINE_CERTIFICATION_REQUIRED"));
        fs::remove_dir_all(root).ok();
    }
}
