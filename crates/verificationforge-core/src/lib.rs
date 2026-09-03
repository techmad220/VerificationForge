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
    pub language: String,
    pub confidence_percent: u8,
}

pub trait LanguageAdapter: Send + Sync {
    fn id(&self) -> &'static str;
    fn detect(&self, repo: &Path) -> Option<LanguageDetection>;
    fn inventory_symbols(&self, _repo: &Path) -> Result<Vec<SymbolId>, String> {
        Ok(Vec::new())
    }
    fn build(&self, _repo: &Path) -> CheckResult {
        CheckResult::pass(format!("{}:build", self.id()))
    }
    fn type_check(&self, _repo: &Path) -> CheckResult {
        CheckResult::pass(format!("{}:type", self.id()))
    }
    fn lint(&self, _repo: &Path) -> CheckResult {
        CheckResult::pass(format!("{}:lint", self.id()))
    }
    fn test(&self, _repo: &Path) -> CheckResult {
        CheckResult::pass(format!("{}:test", self.id()))
    }
    fn coverage(&self, _repo: &Path) -> CheckResult {
        CheckResult::pass(format!("{}:coverage", self.id()))
    }
    fn mutation(&self, _repo: &Path) -> CheckResult {
        CheckResult::pass(format!("{}:mutation", self.id()))
    }
    fn fuzz(&self, _repo: &Path) -> CheckResult {
        CheckResult::pass(format!("{}:fuzz", self.id()))
    }
    fn security(&self, _repo: &Path) -> CheckResult {
        CheckResult::pass(format!("{}:security", self.id()))
    }
    fn dependencies(&self, _repo: &Path) -> CheckResult {
        CheckResult::pass(format!("{}:dependencies", self.id()))
    }
    fn placeholders(&self, _repo: &Path) -> CheckResult {
        CheckResult::pass(format!("{}:placeholders", self.id()))
    }
    fn concurrency(&self, _repo: &Path) -> CheckResult {
        CheckResult::pass(format!("{}:concurrency", self.id()))
    }
}

pub trait ToolchainAdapter: Send + Sync {
    fn id(&self) -> &'static str;
    fn available(&self) -> bool;
}

pub trait ExecutionAdapter: Send + Sync {
    fn id(&self) -> &'static str;
    fn execute(&self, program: &str, args: &[String], cwd: &Path) -> Result<i32, String>;
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
}
