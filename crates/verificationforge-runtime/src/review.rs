use std::collections::BTreeSet;
use std::sync::Arc;

use verificationforge_core::{
    AdversarialChallenge, AdversarialReviewAdapter, ObligationKind, RequirementSpec,
    VerificationObligation,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewedObligation {
    pub reviewer_id: String,
    pub obligation: VerificationObligation,
    pub rationale: String,
}

pub struct ReviewRegistry {
    reviewers: Vec<Arc<dyn AdversarialReviewAdapter>>,
}

impl Default for ReviewRegistry {
    fn default() -> Self {
        Self {
            reviewers: vec![Arc::new(NativeAdversarialReviewer)],
        }
    }
}

impl ReviewRegistry {
    pub fn register(&mut self, reviewer: Arc<dyn AdversarialReviewAdapter>) {
        if !self
            .reviewers
            .iter()
            .any(|existing| existing.id() == reviewer.id())
        {
            self.reviewers.push(reviewer);
        }
    }

    pub fn reviewer_ids(&self) -> Vec<&'static str> {
        self.reviewers.iter().map(|reviewer| reviewer.id()).collect()
    }

    pub fn review_requirement(&self, specification: &RequirementSpec) -> Vec<ReviewedObligation> {
        let mut output = Vec::new();
        let mut seen = BTreeSet::new();
        for reviewer in &self.reviewers {
            for challenge in reviewer.review_requirement(specification) {
                let key = (
                    reviewer.id().to_owned(),
                    challenge.kind,
                    challenge.statement.clone(),
                );
                if !seen.insert(key) {
                    continue;
                }
                output.push(ReviewedObligation {
                    reviewer_id: reviewer.id().into(),
                    obligation: VerificationObligation {
                        requirement: specification.id.clone(),
                        kind: challenge.kind,
                        statement: challenge.statement,
                    },
                    rationale: challenge.rationale,
                });
            }
        }
        output.sort_by(|left, right| {
            left.reviewer_id
                .cmp(&right.reviewer_id)
                .then_with(|| left.obligation.kind.cmp(&right.obligation.kind))
                .then_with(|| left.obligation.statement.cmp(&right.obligation.statement))
        });
        output
    }

    pub fn review_requirements<'a>(
        &self,
        specifications: impl IntoIterator<Item = &'a RequirementSpec>,
    ) -> Vec<ReviewedObligation> {
        let mut output = specifications
            .into_iter()
            .flat_map(|specification| self.review_requirement(specification))
            .collect::<Vec<_>>();
        output.sort_by(|left, right| {
            left.obligation
                .requirement
                .cmp(&right.obligation.requirement)
                .then_with(|| left.reviewer_id.cmp(&right.reviewer_id))
                .then_with(|| left.obligation.kind.cmp(&right.obligation.kind))
                .then_with(|| left.obligation.statement.cmp(&right.obligation.statement))
        });
        output
    }
}

#[derive(Debug, Default)]
pub struct NativeAdversarialReviewer;

impl AdversarialReviewAdapter for NativeAdversarialReviewer {
    fn id(&self) -> &'static str {
        "native-adversarial-reviewer"
    }

    fn review_requirement(&self, specification: &RequirementSpec) -> Vec<AdversarialChallenge> {
        let mut challenges = vec![AdversarialChallenge::new(
            ObligationKind::Functional,
            format!(
                "exercise boundary, invalid, repeated, and reordered scenarios for: {}",
                specification.description
            ),
            "semantic review challenges the happy path before implementation can be accepted",
        )];

        push_challenges(
            &mut challenges,
            ObligationKind::Precondition,
            &specification.preconditions,
            "violate precondition and verify safe rejection or recovery",
            "preconditions must be challenged, not merely restated",
        );
        push_challenges(
            &mut challenges,
            ObligationKind::Postcondition,
            &specification.postconditions,
            "force partial failure, retry, and duplicate execution while verifying postcondition",
            "postconditions must survive adverse execution paths",
        );
        push_challenges(
            &mut challenges,
            ObligationKind::Invariant,
            &specification.invariants,
            "attempt to violate invariant with boundary values, reordered operations, and repeated actions",
            "invariants require active attempts to falsify them",
        );
        push_challenges(
            &mut challenges,
            ObligationKind::ErrorBehavior,
            &specification.error_behaviors,
            "force the failure path and verify error behavior",
            "declared failures require executable negative-path evidence",
        );
        push_challenges(
            &mut challenges,
            ObligationKind::Security,
            &specification.security_rules,
            "attempt bypass with unauthorized, malformed, replayed, and alternate-path input while verifying security rule",
            "security assertions require adversarial bypass attempts",
        );
        push_challenges(
            &mut challenges,
            ObligationKind::Performance,
            &specification.performance_rules,
            "exercise saturation, burst, and worst-case input while verifying performance rule",
            "performance requirements require adverse-load evidence",
        );

        challenges
    }
}

fn push_challenges(
    target: &mut Vec<AdversarialChallenge>,
    kind: ObligationKind,
    statements: &[String],
    action: &str,
    rationale: &str,
) {
    for statement in statements {
        target.push(AdversarialChallenge::new(
            kind,
            format!("{action}: {statement}"),
            rationale,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use verificationforge_core::{RequirementId, RequirementKind};

    struct DuplicateReviewer;

    impl AdversarialReviewAdapter for DuplicateReviewer {
        fn id(&self) -> &'static str {
            "duplicate-reviewer"
        }

        fn review_requirement(&self, _specification: &RequirementSpec) -> Vec<AdversarialChallenge> {
            let challenge = AdversarialChallenge::new(
                ObligationKind::Security,
                "attempt authorization bypass",
                "negative security proof",
            );
            vec![challenge.clone(), challenge]
        }
    }

    fn specification() -> RequirementSpec {
        let mut specification = RequirementSpec::new(
            "REQ-REVIEW",
            "Authorize request",
            RequirementKind::Security,
            "authorized requests receive the protected result",
        );
        specification
            .preconditions
            .push("caller identity is available".into());
        specification
            .postconditions
            .push("no unauthorized data is returned".into());
        specification
            .invariants
            .push("authorization is checked before access".into());
        specification
            .error_behaviors
            .push("denied requests return an explicit error".into());
        specification
            .security_rules
            .push("authorization cannot be bypassed".into());
        specification
            .performance_rules
            .push("authorization completes within the request budget".into());
        specification
    }

    #[test]
    fn native_reviewer_turns_semantics_into_adversarial_obligations() {
        let registry = ReviewRegistry::default();
        let reviewed = registry.review_requirement(&specification());
        assert_eq!(reviewed.len(), 7);
        assert!(reviewed.iter().all(|item| {
            item.obligation.requirement == RequirementId("REQ-REVIEW".into())
                && item.reviewer_id == "native-adversarial-reviewer"
        }));
        assert!(reviewed.iter().any(|item| {
            item.obligation.kind == ObligationKind::Security
                && item.obligation.statement.contains("attempt bypass")
        }));
        assert!(reviewed.iter().any(|item| {
            item.obligation.kind == ObligationKind::Invariant
                && item.obligation.statement.contains("attempt to violate")
        }));
    }

    #[test]
    fn registry_deduplicates_reviewer_ids_and_duplicate_challenges() {
        let mut registry = ReviewRegistry::default();
        registry.register(Arc::new(DuplicateReviewer));
        registry.register(Arc::new(DuplicateReviewer));
        assert_eq!(
            registry
                .reviewer_ids()
                .iter()
                .filter(|id| **id == "duplicate-reviewer")
                .count(),
            1
        );
        let reviewed = registry.review_requirement(&specification());
        assert_eq!(
            reviewed
                .iter()
                .filter(|item| item.reviewer_id == "duplicate-reviewer")
                .count(),
            1
        );
    }

    #[test]
    fn multi_requirement_review_preserves_requirement_scope() {
        let registry = ReviewRegistry::default();
        let first = specification();
        let mut second = specification();
        second.id = RequirementId("REQ-SECOND".into());
        let reviewed = registry.review_requirements([&first, &second]);
        assert!(reviewed.iter().any(|item| {
            item.obligation.requirement == RequirementId("REQ-REVIEW".into())
        }));
        assert!(reviewed.iter().any(|item| {
            item.obligation.requirement == RequirementId("REQ-SECOND".into())
        }));
    }
}
