use std::collections::{BTreeMap, BTreeSet};
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
