use std::collections::{BTreeMap, BTreeSet};

use crate::{
    CheckResult, CheckStatus, CodeEdge, CodeNode, EvidenceGraph, EvidenceLedger, EvidenceLink,
    RequirementGraph, RequirementId, SymbolId, UniversalCodeGraph,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RequirementProofStatus {
    MissingImplementation,
    MissingEvidence,
    Proven,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequirementProofSummary {
    pub requirement: RequirementId,
    pub status: RequirementProofStatus,
    pub implementation_symbols: BTreeSet<SymbolId>,
    pub proven_symbols: BTreeSet<SymbolId>,
    pub evidence_ids: BTreeSet<String>,
}

#[derive(Debug, Clone, Default)]
pub struct VerificationGraphModel {
    requirements: RequirementGraph,
    code: UniversalCodeGraph,
    evidence: EvidenceGraph,
    ledger: EvidenceLedger,
    evidence_results: BTreeMap<String, CheckResult>,
}

impl VerificationGraphModel {
    pub fn requirements(&self) -> &RequirementGraph {
        &self.requirements
    }

    pub fn code(&self) -> &UniversalCodeGraph {
        &self.code
    }

    pub fn evidence(&self) -> &EvidenceGraph {
        &self.evidence
    }

    pub fn ledger(&self) -> &EvidenceLedger {
        &self.ledger
    }

    pub fn evidence_result(&self, evidence_id: &str) -> Option<&CheckResult> {
        self.evidence_results.get(evidence_id)
    }

    pub fn add_requirement(&mut self, requirement: RequirementId) -> bool {
        self.requirements.requirements.insert(requirement)
    }

    pub fn add_code_node(&mut self, node: CodeNode) -> bool {
        let inserted = !self.code.nodes.contains_key(&node.id);
        self.code.add_node(node);
        inserted
    }

    pub fn add_code_edge(&mut self, edge: CodeEdge) -> Result<(), String> {
        self.code.add_edge(edge)
    }

    pub fn link_implementation(
        &mut self,
        requirement: &RequirementId,
        symbol: &SymbolId,
    ) -> Result<bool, String> {
        self.ensure_requirement(requirement)?;
        self.ensure_symbol(symbol)?;
        Ok(self
            .requirements
            .implemented_by
            .entry(requirement.clone())
            .or_default()
            .insert(symbol.clone()))
    }

    pub fn record_evidence(
        &mut self,
        link: EvidenceLink,
        result: CheckResult,
    ) -> Result<(), String> {
        if link.id.trim().is_empty() {
            return Err("evidence id cannot be empty".into());
        }
        if link.content_address.trim().is_empty() {
            return Err("evidence content address cannot be empty".into());
        }
        if self.evidence_results.contains_key(&link.id)
            || self.ledger.links.iter().any(|existing| existing.id == link.id)
        {
            return Err(format!("duplicate evidence id {}", link.id));
        }

        let requirement = link
            .requirement
            .as_ref()
            .ok_or_else(|| "integrated evidence must reference a requirement".to_owned())?;
        let symbol = link
            .symbol
            .as_ref()
            .ok_or_else(|| "integrated evidence must reference an implementation symbol".to_owned())?;
        self.ensure_requirement(requirement)?;
        self.ensure_symbol(symbol)?;

        let linked = self
            .requirements
            .implemented_by
            .get(requirement)
            .is_some_and(|symbols| symbols.contains(symbol));
        if !linked {
            return Err(format!(
                "symbol {} is not linked as an implementation of requirement {}",
                symbol.0, requirement.0
            ));
        }
        if link.check != result.check {
            return Err(format!(
                "evidence check {} does not match result check {}",
                link.check, result.check
            ));
        }

        self.ledger.append(link.clone())?;
        self.evidence.record(requirement.clone(), result.clone());
        self.evidence_results.insert(link.id, result);
        Ok(())
    }

    pub fn proof_status(
        &self,
        requirement: &RequirementId,
    ) -> Result<RequirementProofSummary, String> {
        self.ensure_requirement(requirement)?;
        let implementation_symbols = self
            .requirements
            .implemented_by
            .get(requirement)
            .cloned()
            .unwrap_or_default();
        if implementation_symbols.is_empty() {
            return Ok(RequirementProofSummary {
                requirement: requirement.clone(),
                status: RequirementProofStatus::MissingImplementation,
                implementation_symbols,
                proven_symbols: BTreeSet::new(),
                evidence_ids: BTreeSet::new(),
            });
        }

        let mut proven_symbols = BTreeSet::new();
        let mut evidence_ids = BTreeSet::new();
        for link in &self.ledger.links {
            if link.requirement.as_ref() != Some(requirement) {
                continue;
            }
            let Some(symbol) = link.symbol.as_ref() else {
                continue;
            };
            if !implementation_symbols.contains(symbol) {
                continue;
            }
            let Some(result) = self.evidence_results.get(&link.id) else {
                continue;
            };
            if result.status == CheckStatus::Pass && result.has_reproducible_evidence() {
                proven_symbols.insert(symbol.clone());
                evidence_ids.insert(link.id.clone());
            }
        }

        let status = if proven_symbols == implementation_symbols {
            RequirementProofStatus::Proven
        } else {
            RequirementProofStatus::MissingEvidence
        };
        Ok(RequirementProofSummary {
            requirement: requirement.clone(),
            status,
            implementation_symbols,
            proven_symbols,
            evidence_ids,
        })
    }

    pub fn unproven_requirements(&self) -> BTreeSet<RequirementId> {
        self.requirements
            .requirements
            .iter()
            .filter(|requirement| {
                self.proof_status(requirement)
                    .is_ok_and(|summary| summary.status != RequirementProofStatus::Proven)
            })
            .cloned()
            .collect()
    }

    pub fn orphaned_requirements(&self) -> BTreeSet<RequirementId> {
        self.requirements.orphaned_requirements()
    }

    pub fn unrequested_symbols(&self) -> BTreeSet<SymbolId> {
        self.requirements.unrequested_symbols(&self.code)
    }

    pub fn stale_evidence(&self, current_content_address: &str) -> Vec<&EvidenceLink> {
        self.ledger.stale_for_address(current_content_address)
    }

    fn ensure_requirement(&self, requirement: &RequirementId) -> Result<(), String> {
        if self.requirements.requirements.contains(requirement) {
            Ok(())
        } else {
            Err(format!("unknown requirement {}", requirement.0))
        }
    }

    fn ensure_symbol(&self, symbol: &SymbolId) -> Result<(), String> {
        if self.code.nodes.contains_key(symbol) {
            Ok(())
        } else {
            Err(format!("unknown implementation symbol {}", symbol.0))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CodeNodeKind, Finding};

    fn requirement(value: &str) -> RequirementId {
        RequirementId(value.into())
    }

    fn symbol(value: &str) -> SymbolId {
        SymbolId(value.into())
    }

    fn node(value: &str) -> CodeNode {
        CodeNode {
            id: symbol(value),
            kind: CodeNodeKind::Function,
            language: Some("Rust".into()),
            path: Some("src/lib.rs".into()),
            display_name: value.into(),
        }
    }

    fn link(
        id: &str,
        requirement: &RequirementId,
        symbol: &SymbolId,
        check: &str,
        content_address: &str,
    ) -> EvidenceLink {
        EvidenceLink {
            id: id.into(),
            requirement: Some(requirement.clone()),
            symbol: Some(symbol.clone()),
            check: check.into(),
            artifact: Some("target/test-artifact".into()),
            content_address: content_address.into(),
            timestamp_ms: 1,
        }
    }

    #[test]
    fn cross_graph_links_reject_unknown_nodes() {
        let mut graph = VerificationGraphModel::default();
        let req = requirement("REQ-1");
        let sym = symbol("rust:function:value");

        assert!(graph.link_implementation(&req, &sym).is_err());
        graph.add_requirement(req.clone());
        assert!(graph.link_implementation(&req, &sym).is_err());
        graph.add_code_node(node(&sym.0));
        assert!(graph.link_implementation(&req, &sym).expect("link"));
        assert!(!graph.link_implementation(&req, &sym).expect("dedupe"));
    }

    #[test]
    fn requirement_is_proven_only_when_every_linked_symbol_has_reproducible_evidence() {
        let mut graph = VerificationGraphModel::default();
        let req = requirement("REQ-1");
        let first = symbol("rust:function:first");
        let second = symbol("rust:function:second");
        graph.add_requirement(req.clone());
        graph.add_code_node(node(&first.0));
        graph.add_code_node(node(&second.0));
        graph
            .link_implementation(&req, &first)
            .expect("link first");
        graph
            .link_implementation(&req, &second)
            .expect("link second");

        let initial = graph.proof_status(&req).expect("initial status");
        assert_eq!(initial.status, RequirementProofStatus::MissingEvidence);

        graph
            .record_evidence(
                link("evidence-1", &req, &first, "rust:test", "snapshot-a"),
                CheckResult::pass_with_evidence("rust:test", "cargo test exit=0"),
            )
            .expect("first evidence");
        let partial = graph.proof_status(&req).expect("partial status");
        assert_eq!(partial.status, RequirementProofStatus::MissingEvidence);
        assert_eq!(partial.proven_symbols, BTreeSet::from([first.clone()]));

        graph
            .record_evidence(
                link("evidence-2", &req, &second, "rust:test", "snapshot-a"),
                CheckResult::pass_with_evidence("rust:test", "cargo test exit=0"),
            )
            .expect("second evidence");
        let complete = graph.proof_status(&req).expect("complete status");
        assert_eq!(complete.status, RequirementProofStatus::Proven);
        assert_eq!(complete.proven_symbols, BTreeSet::from([first, second]));
        assert_eq!(complete.evidence_ids.len(), 2);
        assert!(graph.unproven_requirements().is_empty());
    }

    #[test]
    fn bare_pass_and_failure_are_recorded_but_cannot_prove_code() {
        let mut graph = VerificationGraphModel::default();
        let req = requirement("REQ-1");
        let sym = symbol("rust:function:value");
        graph.add_requirement(req.clone());
        graph.add_code_node(node(&sym.0));
        graph.link_implementation(&req, &sym).expect("link");

        graph
            .record_evidence(
                link("bare", &req, &sym, "rust:test", "snapshot-a"),
                CheckResult::pass("rust:test"),
            )
            .expect("record bare pass");
        graph
            .record_evidence(
                link("failed", &req, &sym, "rust:lint", "snapshot-a"),
                CheckResult {
                    check: "rust:lint".into(),
                    status: CheckStatus::Fail,
                    findings: vec![Finding {
                        code: "VF_TEST_FAILURE".into(),
                        message: "lint failed".into(),
                        blocking: true,
                    }],
                },
            )
            .expect("record failure");

        let summary = graph.proof_status(&req).expect("proof status");
        assert_eq!(summary.status, RequirementProofStatus::MissingEvidence);
        assert!(summary.proven_symbols.is_empty());
        assert!(graph.evidence_result("bare").is_some());
        assert!(graph.evidence_result("failed").is_some());
    }

    #[test]
    fn evidence_must_bind_to_the_declared_requirement_implementation_and_check() {
        let mut graph = VerificationGraphModel::default();
        let req = requirement("REQ-1");
        let other = requirement("REQ-2");
        let linked = symbol("rust:function:linked");
        let unlinked = symbol("rust:function:unlinked");
        graph.add_requirement(req.clone());
        graph.add_requirement(other.clone());
        graph.add_code_node(node(&linked.0));
        graph.add_code_node(node(&unlinked.0));
        graph.link_implementation(&req, &linked).expect("link");

        assert!(
            graph
                .record_evidence(
                    link("wrong-symbol", &req, &unlinked, "rust:test", "snapshot-a"),
                    CheckResult::pass_with_evidence("rust:test", "evidence"),
                )
                .is_err()
        );
        assert!(
            graph
                .record_evidence(
                    link("wrong-check", &req, &linked, "rust:test", "snapshot-a"),
                    CheckResult::pass_with_evidence("rust:lint", "evidence"),
                )
                .is_err()
        );
        assert!(
            graph
                .record_evidence(
                    link("wrong-requirement", &other, &linked, "rust:test", "snapshot-a"),
                    CheckResult::pass_with_evidence("rust:test", "evidence"),
                )
                .is_err()
        );
        assert!(graph.ledger().links.is_empty());
    }

    #[test]
    fn integrated_queries_surface_orphans_unrequested_code_and_stale_evidence() {
        let mut graph = VerificationGraphModel::default();
        let proven_req = requirement("REQ-PROVEN");
        let orphan_req = requirement("REQ-ORPHAN");
        let requested = symbol("rust:function:requested");
        let unrequested = symbol("rust:function:unrequested");
        graph.add_requirement(proven_req.clone());
        graph.add_requirement(orphan_req.clone());
        graph.add_code_node(node(&requested.0));
        graph.add_code_node(node(&unrequested.0));
        graph
            .link_implementation(&proven_req, &requested)
            .expect("link");
        graph
            .record_evidence(
                link(
                    "evidence-old",
                    &proven_req,
                    &requested,
                    "rust:test",
                    "snapshot-old",
                ),
                CheckResult::pass_with_evidence("rust:test", "cargo test exit=0"),
            )
            .expect("record evidence");

        assert_eq!(graph.orphaned_requirements(), BTreeSet::from([orphan_req]));
        assert_eq!(graph.unrequested_symbols(), BTreeSet::from([unrequested]));
        assert_eq!(graph.stale_evidence("snapshot-new").len(), 1);
        assert!(graph.stale_evidence("snapshot-old").is_empty());
    }

    #[test]
    fn evidence_record_is_atomic_on_duplicate_id() {
        let mut graph = VerificationGraphModel::default();
        let req = requirement("REQ-1");
        let sym = symbol("rust:function:value");
        graph.add_requirement(req.clone());
        graph.add_code_node(node(&sym.0));
        graph.link_implementation(&req, &sym).expect("link");
        let first = link("same-id", &req, &sym, "rust:test", "snapshot-a");
        graph
            .record_evidence(
                first.clone(),
                CheckResult::pass_with_evidence("rust:test", "first"),
            )
            .expect("first record");
        let before_ledger = graph.ledger().links.len();
        let before_results = graph.evidence().evidence[&req].len();

        assert!(
            graph
                .record_evidence(
                    first,
                    CheckResult::pass_with_evidence("rust:test", "second"),
                )
                .is_err()
        );
        assert_eq!(graph.ledger().links.len(), before_ledger);
        assert_eq!(graph.evidence().evidence[&req].len(), before_results);
    }
}
