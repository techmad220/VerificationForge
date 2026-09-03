use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::{
    CheckKind, CheckResult, CheckStatus, EvidenceGraph, Finding, RequirementGraph, RequirementId,
    SymbolId, VerificationLevel,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RequirementKind {
    Functional,
    Interface,
    Security,
    Reliability,
    Performance,
    Accessibility,
    Persistence,
    Concurrency,
    Compatibility,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequirementSpec {
    pub id: RequirementId,
    pub title: String,
    pub kind: RequirementKind,
    pub description: String,
    pub preconditions: Vec<String>,
    pub postconditions: Vec<String>,
    pub invariants: Vec<String>,
    pub error_behaviors: Vec<String>,
    pub security_rules: Vec<String>,
    pub performance_rules: Vec<String>,
}

impl RequirementSpec {
    pub fn new(
        id: impl Into<String>,
        title: impl Into<String>,
        kind: RequirementKind,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: RequirementId(id.into()),
            title: title.into(),
            kind,
            description: description.into(),
            preconditions: Vec::new(),
            postconditions: Vec::new(),
            invariants: Vec::new(),
            error_behaviors: Vec::new(),
            security_rules: Vec::new(),
            performance_rules: Vec::new(),
        }
    }

    pub fn obligations(&self) -> Vec<VerificationObligation> {
        let mut output = vec![VerificationObligation {
            requirement: self.id.clone(),
            kind: ObligationKind::Functional,
            statement: self.description.clone(),
        }];
        push_obligations(
            &mut output,
            &self.id,
            ObligationKind::Precondition,
            &self.preconditions,
        );
        push_obligations(
            &mut output,
            &self.id,
            ObligationKind::Postcondition,
            &self.postconditions,
        );
        push_obligations(
            &mut output,
            &self.id,
            ObligationKind::Invariant,
            &self.invariants,
        );
        push_obligations(
            &mut output,
            &self.id,
            ObligationKind::ErrorBehavior,
            &self.error_behaviors,
        );
        push_obligations(
            &mut output,
            &self.id,
            ObligationKind::Security,
            &self.security_rules,
        );
        push_obligations(
            &mut output,
            &self.id,
            ObligationKind::Performance,
            &self.performance_rules,
        );
        output
    }
}

fn push_obligations(
    target: &mut Vec<VerificationObligation>,
    requirement: &RequirementId,
    kind: ObligationKind,
    statements: &[String],
) {
    for statement in statements {
        target.push(VerificationObligation {
            requirement: requirement.clone(),
            kind,
            statement: statement.clone(),
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObligationKind {
    Functional,
    Precondition,
    Postcondition,
    Invariant,
    ErrorBehavior,
    Security,
    Performance,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationObligation {
    pub requirement: RequirementId,
    pub kind: ObligationKind,
    pub statement: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateTransition {
    pub from: String,
    pub event: String,
    pub to: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StateMachineModel {
    pub states: BTreeSet<String>,
    pub initial_state: Option<String>,
    pub transitions: Vec<StateTransition>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StateModelAnalysis {
    pub reachable: BTreeSet<String>,
    pub unreachable: BTreeSet<String>,
    pub invalid_transitions: Vec<StateTransition>,
}

impl StateMachineModel {
    pub fn analyze(&self) -> StateModelAnalysis {
        let invalid_transitions = self
            .transitions
            .iter()
            .filter(|item| !self.states.contains(&item.from) || !self.states.contains(&item.to))
            .cloned()
            .collect::<Vec<_>>();
        let mut reachable = BTreeSet::new();
        let mut queue = VecDeque::new();
        if let Some(initial) = &self.initial_state
            && self.states.contains(initial)
        {
            reachable.insert(initial.clone());
            queue.push_back(initial.clone());
        }
        while let Some(state) = queue.pop_front() {
            for transition in self.transitions.iter().filter(|item| item.from == state) {
                if self.states.contains(&transition.to) && reachable.insert(transition.to.clone()) {
                    queue.push_back(transition.to.clone());
                }
            }
        }
        let unreachable = self
            .states
            .difference(&reachable)
            .cloned()
            .collect::<BTreeSet<_>>();
        StateModelAnalysis {
            reachable,
            unreachable,
            invalid_transitions,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CodeNodeKind {
    Repository,
    Package,
    Module,
    File,
    Type,
    Function,
    Variable,
    Api,
    UiControl,
    Database,
    Process,
    NetworkBoundary,
    FilesystemBoundary,
    NativeBoundary,
    SecurityBoundary,
    ConcurrencyPrimitive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeNode {
    pub id: SymbolId,
    pub kind: CodeNodeKind,
    pub language: Option<String>,
    pub path: Option<String>,
    pub display_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CodeEdgeKind {
    Contains,
    Calls,
    Reads,
    Writes,
    Imports,
    DependsOn,
    Implements,
    Exposes,
    Handles,
    Sends,
    Receives,
    CrossesBoundary,
    SynchronizesWith,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CodeEdge {
    pub from: SymbolId,
    pub to: SymbolId,
    pub kind: CodeEdgeKind,
}

#[derive(Debug, Clone, Default)]
pub struct UniversalCodeGraph {
    pub nodes: BTreeMap<SymbolId, CodeNode>,
    pub edges: BTreeSet<CodeEdge>,
}

impl UniversalCodeGraph {
    pub fn add_node(&mut self, node: CodeNode) {
        self.nodes.insert(node.id.clone(), node);
    }

    pub fn add_edge(&mut self, edge: CodeEdge) -> Result<(), String> {
        if !self.nodes.contains_key(&edge.from) {
            return Err(format!("unknown source symbol {}", edge.from.0));
        }
        if !self.nodes.contains_key(&edge.to) {
            return Err(format!("unknown target symbol {}", edge.to.0));
        }
        self.edges.insert(edge);
        Ok(())
    }

    pub fn dependency_cone<I>(&self, seeds: I) -> BTreeSet<SymbolId>
    where
        I: IntoIterator<Item = SymbolId>,
    {
        let mut affected = BTreeSet::new();
        let mut queue = VecDeque::new();
        for seed in seeds {
            if self.nodes.contains_key(&seed) && affected.insert(seed.clone()) {
                queue.push_back(seed);
            }
        }
        while let Some(current) = queue.pop_front() {
            for edge in &self.edges {
                if edge.to == current && affected.insert(edge.from.clone()) {
                    queue.push_back(edge.from.clone());
                }
                if matches!(
                    edge.kind,
                    CodeEdgeKind::Writes | CodeEdgeKind::Sends | CodeEdgeKind::CrossesBoundary
                ) && edge.from == current
                    && affected.insert(edge.to.clone())
                {
                    queue.push_back(edge.to.clone());
                }
            }
        }
        affected
    }

    pub fn symbols_for_paths<'a, I>(&self, paths: I) -> BTreeSet<SymbolId>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let paths = paths.into_iter().collect::<BTreeSet<_>>();
        self.nodes
            .values()
            .filter(|node| {
                node.path
                    .as_deref()
                    .is_some_and(|path| paths.contains(path))
            })
            .map(|node| node.id.clone())
            .collect()
    }
}

impl RequirementGraph {
    pub fn orphaned_requirements(&self) -> BTreeSet<RequirementId> {
        self.requirements
            .iter()
            .filter(|requirement| {
                self.implemented_by
                    .get(*requirement)
                    .is_none_or(BTreeSet::is_empty)
            })
            .cloned()
            .collect()
    }

    pub fn unrequested_symbols(&self, code: &UniversalCodeGraph) -> BTreeSet<SymbolId> {
        let requested = self
            .implemented_by
            .values()
            .flatten()
            .cloned()
            .collect::<BTreeSet<_>>();
        code.nodes
            .keys()
            .filter(|symbol| !requested.contains(*symbol))
            .cloned()
            .collect()
    }
}

impl EvidenceGraph {
    pub fn record(&mut self, requirement: RequirementId, result: CheckResult) {
        self.evidence.entry(requirement).or_default().push(result);
    }

    pub fn requirements_without_passing_evidence(&self) -> BTreeSet<RequirementId> {
        self.evidence
            .iter()
            .filter(|(_, results)| {
                !results
                    .iter()
                    .any(|result| result.status == CheckStatus::Pass)
            })
            .map(|(requirement, _)| requirement.clone())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceLink {
    pub id: String,
    pub requirement: Option<RequirementId>,
    pub symbol: Option<SymbolId>,
    pub check: String,
    pub artifact: Option<String>,
    pub content_address: String,
    pub timestamp_ms: u128,
}

#[derive(Debug, Clone, Default)]
pub struct EvidenceLedger {
    pub links: Vec<EvidenceLink>,
}

impl EvidenceLedger {
    pub fn append(&mut self, link: EvidenceLink) -> Result<(), String> {
        if self.links.iter().any(|item| item.id == link.id) {
            return Err(format!("duplicate evidence id {}", link.id));
        }
        self.links.push(link);
        Ok(())
    }

    pub fn for_requirement(&self, requirement: &RequirementId) -> Vec<&EvidenceLink> {
        self.links
            .iter()
            .filter(|link| link.requirement.as_ref() == Some(requirement))
            .collect()
    }

    pub fn stale_for_address(&self, content_address: &str) -> Vec<&EvidenceLink> {
        self.links
            .iter()
            .filter(|link| link.content_address != content_address)
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Threat {
    pub id: String,
    pub boundary: String,
    pub description: String,
    pub mitigation: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ThreatModel {
    pub assets: BTreeSet<String>,
    pub trust_boundaries: BTreeSet<String>,
    pub threats: Vec<Threat>,
}

impl ThreatModel {
    pub fn unmitigated(&self) -> Vec<&Threat> {
        self.threats
            .iter()
            .filter(|threat| threat.mitigation.as_deref().is_none_or(str::is_empty))
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RiskTier {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct VerificationPolicy {
    pub name: String,
    pub version: u64,
    pub risk: RiskTier,
    pub minimum_level: VerificationLevel,
    pub required_checks: BTreeSet<CheckKind>,
    pub block_unsupported: bool,
    pub block_skipped: bool,
}

impl VerificationPolicy {
    pub fn for_risk(risk: RiskTier) -> Self {
        let minimum_level = match risk {
            RiskTier::Low => VerificationLevel::Patch,
            RiskTier::Medium => VerificationLevel::Checkpoint,
            RiskTier::High => VerificationLevel::Commit,
            RiskTier::Critical => VerificationLevel::Certification,
        };
        Self {
            name: format!("default-{risk:?}").to_ascii_lowercase(),
            version: 1,
            risk,
            minimum_level,
            required_checks: minimum_level.checks().into_iter().collect(),
            block_unsupported: minimum_level >= VerificationLevel::Commit,
            block_skipped: false,
        }
    }

    pub fn evaluate(&self, level: VerificationLevel, results: &[CheckResult]) -> PolicyDecision {
        let mut blockers = Vec::new();
        if level < self.minimum_level {
            blockers.push(Finding {
                code: "VF_POLICY_LEVEL".into(),
                message: format!(
                    "policy {} requires {:?} or stronger, got {:?}",
                    self.name, self.minimum_level, level
                ),
                blocking: true,
            });
        }
        for result in results {
            if result.status == CheckStatus::Fail || result.has_blocking_finding() {
                blockers.extend(
                    result
                        .findings
                        .iter()
                        .filter(|finding| finding.blocking)
                        .cloned(),
                );
                if result.status == CheckStatus::Fail && result.findings.is_empty() {
                    blockers.push(Finding {
                        code: "VF_POLICY_FAILED_CHECK".into(),
                        message: format!("{} failed", result.check),
                        blocking: true,
                    });
                }
            }
            if self.block_unsupported && result.status == CheckStatus::Unsupported {
                blockers.push(Finding {
                    code: "VF_POLICY_UNSUPPORTED".into(),
                    message: format!("{} is unsupported", result.check),
                    blocking: true,
                });
            }
            if self.block_skipped && result.status == CheckStatus::Skipped {
                blockers.push(Finding {
                    code: "VF_POLICY_SKIPPED".into(),
                    message: format!("{} was skipped", result.check),
                    blocking: true,
                });
            }
        }
        for required in &self.required_checks {
            let suffix = format!(":{}", required.as_str());
            if !results.iter().any(|result| result.check.ends_with(&suffix)) {
                blockers.push(Finding {
                    code: "VF_POLICY_MISSING_CHECK".into(),
                    message: format!("required check {} produced no evidence", required.as_str()),
                    blocking: true,
                });
            }
        }
        PolicyDecision {
            accepted: blockers.is_empty(),
            blockers,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyDecision {
    pub accepted: bool,
    pub blockers: Vec<Finding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentOperationKind {
    Read,
    Write,
    Patch,
    Delete,
    Rename,
    DependencyChange,
    Command,
    Test,
    Commit,
    Certification,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentOperation {
    pub sequence: u64,
    pub agent: String,
    pub requirement: Option<RequirementId>,
    pub kind: AgentOperationKind,
    pub target: String,
    pub accepted: bool,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct OperationLedger {
    next_sequence: u64,
    pub operations: Vec<AgentOperation>,
}

impl OperationLedger {
    pub fn record(
        &mut self,
        agent: impl Into<String>,
        requirement: Option<RequirementId>,
        kind: AgentOperationKind,
        target: impl Into<String>,
        accepted: bool,
        evidence_ids: Vec<String>,
    ) -> &AgentOperation {
        self.next_sequence += 1;
        self.operations.push(AgentOperation {
            sequence: self.next_sequence,
            agent: agent.into(),
            requirement,
            kind,
            target: target.into(),
            accepted,
            evidence_ids,
        });
        self.operations.last().expect("operation was appended")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenanceRecord {
    pub agent: String,
    pub requirement: Option<RequirementId>,
    pub patch_address: String,
    pub verification_address: String,
    pub commit: Option<String>,
    pub build_artifact: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ProvenanceChain {
    pub records: Vec<ProvenanceRecord>,
}

impl ProvenanceChain {
    pub fn append(&mut self, record: ProvenanceRecord) {
        self.records.push(record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specification_generates_obligations_before_code_exists() {
        let mut spec = RequirementSpec::new(
            "REQ-AUTH",
            "Authorize access",
            RequirementKind::Security,
            "Only authorized principals may access the resource",
        );
        spec.invariants
            .push("denied users never receive data".into());
        spec.security_rules
            .push("authorization is checked server-side".into());
        let obligations = spec.obligations();
        assert_eq!(obligations.len(), 3);
        assert!(
            obligations
                .iter()
                .any(|item| item.kind == ObligationKind::Invariant)
        );
    }

    #[test]
    fn state_analysis_finds_unreachable_and_invalid_states() {
        let model = StateMachineModel {
            states: ["idle", "running", "dead"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            initial_state: Some("idle".into()),
            transitions: vec![
                StateTransition {
                    from: "idle".into(),
                    event: "start".into(),
                    to: "running".into(),
                },
                StateTransition {
                    from: "missing".into(),
                    event: "bad".into(),
                    to: "idle".into(),
                },
            ],
        };
        let analysis = model.analyze();
        assert!(analysis.reachable.contains("running"));
        assert!(analysis.unreachable.contains("dead"));
        assert_eq!(analysis.invalid_transitions.len(), 1);
    }

    #[test]
    fn dependency_cone_walks_reverse_dependencies() {
        let mut graph = UniversalCodeGraph::default();
        for id in ["db", "service", "api"] {
            graph.add_node(CodeNode {
                id: SymbolId(id.into()),
                kind: CodeNodeKind::Function,
                language: Some("Rust".into()),
                path: Some(format!("src/{id}.rs")),
                display_name: id.into(),
            });
        }
        graph
            .add_edge(CodeEdge {
                from: SymbolId("service".into()),
                to: SymbolId("db".into()),
                kind: CodeEdgeKind::DependsOn,
            })
            .expect("valid edge");
        graph
            .add_edge(CodeEdge {
                from: SymbolId("api".into()),
                to: SymbolId("service".into()),
                kind: CodeEdgeKind::Calls,
            })
            .expect("valid edge");
        let affected = graph.dependency_cone([SymbolId("db".into())]);
        assert_eq!(affected.len(), 3);
    }

    #[test]
    fn high_risk_policy_rejects_patch_only_evidence() {
        let policy = VerificationPolicy::for_risk(RiskTier::High);
        let results = vec![CheckResult::pass("rust:build")];
        let decision = policy.evaluate(VerificationLevel::Patch, &results);
        assert!(!decision.accepted);
        assert!(!decision.blockers.is_empty());
    }
}
