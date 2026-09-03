use std::collections::BTreeSet;

use crate::{
    CheckStatus, EvidenceGraph, RequirementGraph, RequirementId, SymbolId,
};

impl EvidenceGraph {
    pub fn requirements_without_evidence(
        &self,
        requirements: &RequirementGraph,
    ) -> BTreeSet<RequirementId> {
        requirements
            .requirements
            .iter()
            .filter(|requirement| {
                self.evidence
                    .get(*requirement)
                    .is_none_or(|results| results.is_empty())
            })
            .cloned()
            .collect()
    }

    pub fn requirements_without_reproducible_pass(
        &self,
        requirements: &RequirementGraph,
    ) -> BTreeSet<RequirementId> {
        requirements
            .requirements
            .iter()
            .filter(|requirement| {
                !self
                    .evidence
                    .get(*requirement)
                    .is_some_and(|results| {
                        results.iter().any(|result| {
                            result.status == CheckStatus::Pass
                                && result.has_reproducible_evidence()
                        })
                    })
            })
            .cloned()
            .collect()
    }

    pub fn weakly_proven_symbols(
        &self,
        requirements: &RequirementGraph,
    ) -> BTreeSet<SymbolId> {
        let weak_requirements = self.requirements_without_reproducible_pass(requirements);
        weak_requirements
            .iter()
            .filter_map(|requirement| requirements.implemented_by.get(requirement))
            .flatten()
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CheckResult, EvidenceGraph};

    #[test]
    fn missing_and_bare_evidence_are_reported_as_weak() {
        let requirement_a = RequirementId("REQ-A".into());
        let requirement_b = RequirementId("REQ-B".into());
        let symbol_a = SymbolId("symbol-a".into());
        let symbol_b = SymbolId("symbol-b".into());
        let mut requirements = RequirementGraph::default();
        requirements.requirements.extend([
            requirement_a.clone(),
            requirement_b.clone(),
        ]);
        requirements
            .implemented_by
            .entry(requirement_a.clone())
            .or_default()
            .insert(symbol_a.clone());
        requirements
            .implemented_by
            .entry(requirement_b.clone())
            .or_default()
            .insert(symbol_b.clone());

        let mut evidence = EvidenceGraph::default();
        evidence.record(requirement_a.clone(), CheckResult::pass("rust:test"));

        assert_eq!(
            evidence.requirements_without_evidence(&requirements),
            [requirement_b.clone()].into_iter().collect()
        );
        assert_eq!(
            evidence.requirements_without_reproducible_pass(&requirements),
            [requirement_a, requirement_b].into_iter().collect()
        );
        assert_eq!(
            evidence.weakly_proven_symbols(&requirements),
            [symbol_a, symbol_b].into_iter().collect()
        );
    }

    #[test]
    fn evidence_backed_pass_removes_requirement_from_weak_set() {
        let requirement = RequirementId("REQ-A".into());
        let mut requirements = RequirementGraph::default();
        requirements.requirements.insert(requirement.clone());
        let mut evidence = EvidenceGraph::default();
        evidence.record(
            requirement.clone(),
            CheckResult::pass_with_evidence("rust:test", "command=cargo test exit=0"),
        );
        assert!(
            evidence
                .requirements_without_reproducible_pass(&requirements)
                .is_empty()
        );
    }
}
