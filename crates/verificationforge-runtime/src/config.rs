use std::fs;
use std::path::Path;

use verificationforge_core::{RiskTier, VerificationLevel, VerificationPolicy};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepositoryConfig {
    pub risk: Option<RiskTier>,
    pub minimum_level: Option<VerificationLevel>,
    pub block_unsupported: Option<bool>,
    pub block_skipped: Option<bool>,
}

impl RepositoryConfig {
    pub fn load(repo: &Path) -> Result<Self, String> {
        let path = repo.join("verificationforge.toml");
        if !path.is_file() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(&path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        Self::parse(&content)
    }

    pub fn parse(content: &str) -> Result<Self, String> {
        let mut config = Self::default();
        let mut section = String::new();

        for (index, raw_line) in content.lines().enumerate() {
            let line = strip_comment(raw_line).trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                section = line[1..line.len() - 1].trim().to_ascii_lowercase();
                continue;
            }
            let Some((raw_key, raw_value)) = line.split_once('=') else {
                return Err(format!(
                    "verificationforge.toml:{} expected key = value",
                    index + 1
                ));
            };
            let key = raw_key.trim().to_ascii_lowercase();
            let value = raw_value.trim();
            match (section.as_str(), key.as_str()) {
                ("project", "risk") => config.risk = Some(parse_risk(unquote(value))?),
                ("policy", "minimum_level") => {
                    config.minimum_level = Some(unquote(value).parse::<VerificationLevel>()?)
                }
                ("policy", "block_unsupported") => {
                    config.block_unsupported = Some(parse_bool(value, index + 1)?)
                }
                ("policy", "block_skipped") => {
                    config.block_skipped = Some(parse_bool(value, index + 1)?)
                }
                _ => {}
            }
        }

        Ok(config)
    }

    pub fn policy(&self, fallback_risk: RiskTier) -> VerificationPolicy {
        let mut policy = VerificationPolicy::for_risk(self.risk.unwrap_or(fallback_risk));
        if let Some(level) = self.minimum_level {
            policy.minimum_level = level;
            policy.required_checks = level.checks().into_iter().collect();
        }
        if let Some(value) = self.block_unsupported {
            policy.block_unsupported = value;
        }
        if let Some(value) = self.block_skipped {
            policy.block_skipped = value;
        }
        policy
    }
}

fn parse_risk(value: &str) -> Result<RiskTier, String> {
    match value.to_ascii_lowercase().as_str() {
        "low" => Ok(RiskTier::Low),
        "medium" => Ok(RiskTier::Medium),
        "high" => Ok(RiskTier::High),
        "critical" => Ok(RiskTier::Critical),
        other => Err(format!(
            "unknown risk tier in verificationforge.toml: {other}"
        )),
    }
}

fn parse_bool(value: &str, line: usize) -> Result<bool, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(format!(
            "verificationforge.toml:{line} expected boolean, got {other}"
        )),
    }
}

fn unquote(value: &str) -> &str {
    let value = value.trim();
    value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(value)
        .trim()
}

fn strip_comment(line: &str) -> &str {
    let mut quoted = false;
    for (index, character) in line.char_indices() {
        match character {
            '"' => quoted = !quoted,
            '#' if !quoted => return &line[..index],
            _ => {}
        }
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_repository_risk_and_policy_overrides() {
        let config = RepositoryConfig::parse(
            r#"
            [project]
            risk = "critical"

            [policy]
            minimum_level = "commit"
            block_unsupported = true
            block_skipped = true
            "#,
        )
        .expect("parse config");
        assert_eq!(config.risk, Some(RiskTier::Critical));
        assert_eq!(config.minimum_level, Some(VerificationLevel::Commit));
        let policy = config.policy(RiskTier::Low);
        assert_eq!(policy.risk, RiskTier::Critical);
        assert_eq!(policy.minimum_level, VerificationLevel::Commit);
        assert!(policy.block_unsupported);
        assert!(policy.block_skipped);
    }

    #[test]
    fn ignores_unknown_future_keys() {
        let config = RepositoryConfig::parse(
            r#"
            [project]
            name = "demo"
            risk = "high"
            [future]
            anything = "allowed"
            "#,
        )
        .expect("parse config");
        assert_eq!(config.risk, Some(RiskTier::High));
    }
}
