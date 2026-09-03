use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VerificationLevel {
    Patch,
    Checkpoint,
    Commit,
    Certification,
    Formal,
}

impl VerificationLevel {
    pub fn checks(self) -> Vec<CheckKind> {
        let mut checks = vec![
            CheckKind::Build,
            CheckKind::TypeCheck,
            CheckKind::Lint,
            CheckKind::Test,
            CheckKind::Placeholders,
        ];

        if self >= Self::Checkpoint {
            checks.extend([
                CheckKind::Dependencies,
                CheckKind::Security,
                CheckKind::Contracts,
            ]);
        }
        if self >= Self::Commit {
            checks.extend([
                CheckKind::Coverage,
                CheckKind::Mutation,
                CheckKind::Fuzz,
                CheckKind::Concurrency,
            ]);
        }
        if self >= Self::Certification {
            checks.extend([CheckKind::Stress, CheckKind::FaultInjection, CheckKind::Ui]);
        }
        if self >= Self::Formal {
            checks.push(CheckKind::FormalProof);
        }

        checks
    }

    pub fn unsupported_is_blocking(self) -> bool {
        self >= Self::Commit
    }
}

impl std::str::FromStr for VerificationLevel {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "patch" => Ok(Self::Patch),
            "checkpoint" => Ok(Self::Checkpoint),
            "commit" => Ok(Self::Commit),
            "certification" | "certify" => Ok(Self::Certification),
            "formal" => Ok(Self::Formal),
            other => Err(format!("unknown verification level: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CheckKind {
    Build,
    TypeCheck,
    Lint,
    Test,
    Coverage,
    Mutation,
    Fuzz,
    Security,
    Dependencies,
    Placeholders,
    Concurrency,
    Contracts,
    Stress,
    FaultInjection,
    Ui,
    FormalProof,
}

impl CheckKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::TypeCheck => "type-check",
            Self::Lint => "lint",
            Self::Test => "test",
            Self::Coverage => "coverage",
            Self::Mutation => "mutation",
            Self::Fuzz => "fuzz",
            Self::Security => "security",
            Self::Dependencies => "dependencies",
            Self::Placeholders => "placeholders",
            Self::Concurrency => "concurrency",
            Self::Contracts => "contracts",
            Self::Stress => "stress",
            Self::FaultInjection => "fault-injection",
            Self::Ui => "ui",
            Self::FormalProof => "formal-proof",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    Fail,
    Skipped,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub code: String,
    pub message: String,
    pub blocking: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub check: String,
    pub status: CheckStatus,
    pub findings: Vec<Finding>,
}

impl CheckResult {
    pub fn pass(check: impl Into<String>) -> Self {
        Self {
            check: check.into(),
            status: CheckStatus::Pass,
            findings: Vec::new(),
        }
    }

    pub fn pass_with_evidence(check: impl Into<String>, evidence: impl Into<String>) -> Self {
        Self {
            check: check.into(),
            status: CheckStatus::Pass,
            findings: vec![Finding {
                code: "VF_EVIDENCE".into(),
                message: evidence.into(),
                blocking: false,
            }],
        }
    }

    pub fn fail(
        check: impl Into<String>,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            check: check.into(),
            status: CheckStatus::Fail,
            findings: vec![Finding {
                code: code.into(),
                message: message.into(),
                blocking: true,
            }],
        }
    }

    pub fn unsupported(check: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            check: check.into(),
            status: CheckStatus::Unsupported,
            findings: vec![Finding {
                code: "VF_UNSUPPORTED".into(),
                message: message.into(),
                blocking: false,
            }],
        }
    }

    pub fn skipped(check: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            check: check.into(),
            status: CheckStatus::Skipped,
            findings: vec![Finding {
                code: "VF_SKIPPED".into(),
                message: message.into(),
                blocking: false,
            }],
        }
    }

    pub fn has_blocking_finding(&self) -> bool {
        self.findings.iter().any(|finding| finding.blocking)
    }

    pub fn has_reproducible_evidence(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.code == "VF_EVIDENCE" && !finding.message.trim().is_empty())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl ExecutionResult {
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequirementId(pub String);
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymbolId(pub String);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImpactScope {
    pub changed_paths: BTreeSet<String>,
    pub affected_symbols: BTreeSet<SymbolId>,
    pub requires_full_verification: bool,
}

#[derive(Debug, Default, Clone)]
pub struct RequirementGraph {
    pub requirements: BTreeSet<RequirementId>,
    pub implemented_by: BTreeMap<RequirementId, BTreeSet<SymbolId>>,
}

#[derive(Debug, Default, Clone)]
pub struct CodeGraph {
    pub symbols: BTreeSet<SymbolId>,
    pub dependencies: BTreeMap<SymbolId, BTreeSet<SymbolId>>,
}

#[derive(Debug, Default, Clone)]
pub struct EvidenceGraph {
    pub evidence: BTreeMap<RequirementId, Vec<CheckResult>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanguageDetection {
    pub adapter_id: String,
    pub language: String,
    pub confidence_percent: u8,
}

pub trait LanguageAdapter: Send + Sync {
    fn id(&self) -> &'static str;
    fn detect(&self, repo: &Path) -> Option<LanguageDetection>;

    fn inventory_symbols(&self, _repo: &Path) -> Result<Vec<SymbolId>, String> {
        Ok(Vec::new())
    }

    fn run_check(
        &self,
        check: CheckKind,
        _repo: &Path,
        _execution: &dyn ExecutionAdapter,
    ) -> CheckResult {
        CheckResult::unsupported(
            format!("{}:{}", self.id(), check.as_str()),
            format!(
                "{} adapter does not implement {}",
                self.id(),
                check.as_str()
            ),
        )
    }

    fn run_parse_check(
        &self,
        _repo: &Path,
        _execution: &dyn ExecutionAdapter,
    ) -> CheckResult {
        CheckResult::unsupported(
            format!("{}:parse", self.id()),
            format!("{} adapter does not implement patch parse verification", self.id()),
        )
    }

    fn run_format_check(
        &self,
        _repo: &Path,
        _execution: &dyn ExecutionAdapter,
    ) -> CheckResult {
        CheckResult::unsupported(
            format!("{}:format", self.id()),
            format!("{} adapter does not implement patch format verification", self.id()),
        )
    }

    fn run_targeted_tests(
        &self,
        _repo: &Path,
        _execution: &dyn ExecutionAdapter,
        _scope: &ImpactScope,
    ) -> CheckResult {
        CheckResult::unsupported(
            format!("{}:targeted-test", self.id()),
            format!("{} adapter does not implement impact-targeted tests", self.id()),
        )
    }
}

pub trait ToolchainAdapter: Send + Sync {
    fn id(&self) -> &'static str;
    fn available(&self) -> bool;
}

pub trait ExecutionAdapter: Send + Sync {
    fn id(&self) -> &'static str;
    fn execute(
        &self,
        program: &str,
        args: &[String],
        cwd: &Path,
    ) -> Result<ExecutionResult, String>;
}

pub fn run_repository_harness(
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: impl Into<String>,
    harness_name: &str,
) -> Option<CheckResult> {
    let check_name = check_name.into();
    let relative = format!(".verificationforge/{harness_name}.argv");
    let path = repo.join(&relative);
    if !path.is_file() {
        return None;
    }

    let content = match fs::read_to_string(&path) {
        Ok(content) => content,
        Err(error) => {
            return Some(CheckResult::fail(
                check_name,
                "VF_HARNESS_READ_FAILED",
                format!("cannot read {relative}: {error}"),
            ));
        }
    };
    let mut command = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'));
    let Some(program) = command.next() else {
        return Some(CheckResult::fail(
            check_name,
            "VF_HARNESS_EMPTY",
            format!("{relative} contains no executable command"),
        ));
    };
    let args = command.map(str::to_owned).collect::<Vec<_>>();

    match execution.execute(program, &args, repo) {
        Ok(output) if output.success() => Some(CheckResult::pass_with_evidence(
            check_name,
            format!(
                "harness={relative} command={} {} exit=0",
                program,
                args.join(" ")
            ),
        )),
        Ok(output) => Some(CheckResult::fail(
            check_name,
            "VF_HARNESS_FAILED",
            format!(
                "harness {relative} command {} {} exited with code {}: {}",
                program,
                args.join(" "),
                output.exit_code,
                command_detail(&output)
            ),
        )),
        Err(error) => Some(CheckResult::fail(
            check_name,
            "VF_HARNESS_EXECUTION_FAILED",
            format!("cannot execute {relative}: {error}"),
        )),
    }
}

fn command_detail(output: &ExecutionResult) -> String {
    let detail = if output.stderr.trim().is_empty() {
        output.stdout.trim()
    } else {
        output.stderr.trim()
    };
    detail.chars().take(4000).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn graph_links_requirement_to_symbol() {
        let requirement = RequirementId("REQ-1".into());
        let symbol = SymbolId("crate::verify".into());
        let mut graph = RequirementGraph::default();
        graph.requirements.insert(requirement.clone());
        graph
            .implemented_by
            .entry(requirement.clone())
            .or_default()
            .insert(symbol.clone());
        assert!(graph.implemented_by[&requirement].contains(&symbol));
    }

    #[test]
    fn commit_level_blocks_unsupported_checks() {
        assert!(!VerificationLevel::Patch.unsupported_is_blocking());
        assert!(VerificationLevel::Commit.unsupported_is_blocking());
    }

    #[test]
    fn certification_contains_deep_checks() {
        let checks = VerificationLevel::Certification.checks();
        assert!(checks.contains(&CheckKind::Mutation));
        assert!(checks.contains(&CheckKind::FaultInjection));
        assert!(checks.contains(&CheckKind::Ui));
        assert!(!checks.contains(&CheckKind::FormalProof));
    }

    #[test]
    fn evidence_backed_pass_is_distinguishable_from_bare_pass() {
        let bare = CheckResult::pass("demo:build");
        let backed = CheckResult::pass_with_evidence("demo:build", "command=demo build exit=0");
        assert!(!bare.has_reproducible_evidence());
        assert!(backed.has_reproducible_evidence());
    }

    struct RecordingExecution {
        call: Mutex<Option<(String, Vec<String>)>>,
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
            *self.call.lock().expect("lock poisoned") = Some((program.into(), args.to_vec()));
            Ok(ExecutionResult {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn repository_harness_preserves_argument_boundaries() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("vf-harness-{nonce}"));
        fs::create_dir_all(root.join(".verificationforge")).expect("create harness dir");
        fs::write(
            root.join(".verificationforge/contracts.argv"),
            "# exact argv\ncargo\ntest\n--workspace\n--locked\n",
        )
        .expect("write harness");
        let execution = RecordingExecution {
            call: Mutex::new(None),
        };
        let result = run_repository_harness(&root, &execution, "rust:contracts", "contracts")
            .expect("harness exists");
        assert_eq!(result.status, CheckStatus::Pass);
        assert!(result.has_reproducible_evidence());
        assert_eq!(
            execution.call.lock().expect("lock poisoned").clone(),
            Some((
                "cargo".into(),
                vec!["test".into(), "--workspace".into(), "--locked".into()]
            ))
        );
        fs::remove_dir_all(root).ok();
    }
}
