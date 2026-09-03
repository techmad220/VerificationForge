use std::path::Path;
use verificationforge_core::{LanguageAdapter, LanguageDetection};

pub struct RustAdapter;

impl LanguageAdapter for RustAdapter {
    fn id(&self) -> &'static str {
        "rust"
    }

    fn detect(&self, repo: &Path) -> Option<LanguageDetection> {
        (repo.join("Cargo.toml").is_file() || contains_extension(repo, "rs")).then(|| {
            LanguageDetection {
                language: "Rust".into(),
                confidence_percent: if repo.join("Cargo.toml").is_file() {
                    100
                } else {
                    80
                },
            }
        })
    }
}

fn contains_extension(repo: &Path, extension: &str) -> bool {
    let Ok(entries) = std::fs::read_dir(repo) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let path = entry.path();
        path.extension().and_then(|value| value.to_str()) == Some(extension)
    })
}
