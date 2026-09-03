use std::path::Path;
use std::sync::Arc;
use verificationforge_core::{LanguageAdapter, LanguageDetection};

#[derive(Default)]
pub struct AdapterRegistry {
    languages: Vec<Arc<dyn LanguageAdapter>>,
}

impl AdapterRegistry {
    pub fn register(&mut self, adapter: Arc<dyn LanguageAdapter>) {
        if !self
            .languages
            .iter()
            .any(|existing| existing.id() == adapter.id())
        {
            self.languages.push(adapter);
        }
    }

    pub fn detect(&self, repo: &Path) -> Vec<LanguageDetection> {
        let mut detections: Vec<_> = self
            .languages
            .iter()
            .filter_map(|adapter| adapter.detect(repo))
            .collect();
        detections.sort_by(|a, b| {
            b.confidence_percent
                .cmp(&a.confidence_percent)
                .then_with(|| a.language.cmp(&b.language))
        });
        detections
    }

    pub fn adapter_ids(&self) -> Vec<&'static str> {
        self.languages.iter().map(|adapter| adapter.id()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use verificationforge_core::{CheckResult, LanguageDetection};

    struct Demo;
    impl LanguageAdapter for Demo {
        fn id(&self) -> &'static str {
            "demo"
        }
        fn detect(&self, _repo: &Path) -> Option<LanguageDetection> {
            Some(LanguageDetection {
                language: "Demo".into(),
                confidence_percent: 100,
            })
        }
        fn build(&self, _repo: &Path) -> CheckResult {
            CheckResult::pass("demo:build")
        }
    }

    #[test]
    fn duplicate_adapter_ids_are_not_registered_twice() {
        let mut registry = AdapterRegistry::default();
        registry.register(Arc::new(Demo));
        registry.register(Arc::new(Demo));
        assert_eq!(registry.adapter_ids(), vec!["demo"]);
    }
}
