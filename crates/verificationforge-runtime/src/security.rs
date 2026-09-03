use std::fs;
use std::path::{Path, PathBuf};

use verificationforge_core::{
    CheckKind, CheckResult, CheckStatus, ExecutionAdapter, Finding, SpecialistDomain,
    SpecialistVerificationAdapter,
};

const MAX_SCAN_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Default)]
pub struct NativeSecuritySpecialist;

impl SpecialistVerificationAdapter for NativeSecuritySpecialist {
    fn id(&self) -> &'static str {
        "native-security"
    }

    fn domains(&self) -> &'static [SpecialistDomain] {
        &[SpecialistDomain::Security, SpecialistDomain::Provenance]
    }

    fn supports(&self, check: CheckKind) -> bool {
        check == CheckKind::Security
    }

    fn run_check(
        &self,
        check: CheckKind,
        repo: &Path,
        _execution: &dyn ExecutionAdapter,
    ) -> CheckResult {
        if check != CheckKind::Security {
            return CheckResult::unsupported(
                format!("{}:{}", self.id(), check.as_str()),
                "native security specialist only handles repository security checks",
            );
        }
        scan_repository(repo)
    }
}

fn scan_repository(repo: &Path) -> CheckResult {
    let files = repository_text_files(repo);
    let mut findings = Vec::new();
    let mut readable_files = 0usize;

    for path in &files {
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        readable_files += 1;
        scan_secrets(repo, path, &content, &mut findings);
        scan_suspicious_triggers(repo, path, &content, &mut findings);
    }

    if findings.is_empty() {
        CheckResult::pass_with_evidence(
            "native-security:security",
            format!(
                "native repository security scan files={readable_files} hardcoded-secrets=0 suspicious-triggers=0"
            ),
        )
    } else {
        CheckResult {
            check: "native-security:security".into(),
            status: CheckStatus::Fail,
            findings,
        }
    }
}

fn scan_secrets(repo: &Path, path: &Path, content: &str, findings: &mut Vec<Finding>) {
    let private_key_tail = ["PRIVATE", " KEY-----"].concat();
    let github_classic = ["gh", "p_"].concat();
    let github_fine_grained = ["github", "_pat_"].concat();
    let aws_access_key = ["AK", "IA"].concat();
    let slack_bot = ["xo", "xb-"].concat();
    let slack_user = ["xo", "xp-"].concat();
    let stripe_live = ["sk", "_live_"].concat();

    for (index, line) in content.lines().enumerate() {
        let line_number = index + 1;
        if line.contains("BEGIN") && line.contains(&private_key_tail) {
            findings.push(secret_finding(
                repo,
                path,
                line_number,
                "private-key material",
            ));
            continue;
        }
        if contains_prefixed_token(line, &github_classic, 24)
            || contains_prefixed_token(line, &github_fine_grained, 24)
        {
            findings.push(secret_finding(
                repo,
                path,
                line_number,
                "GitHub access token",
            ));
            continue;
        }
        if contains_prefixed_token(line, &aws_access_key, 20) {
            findings.push(secret_finding(repo, path, line_number, "cloud access key"));
            continue;
        }
        if contains_prefixed_token(line, &slack_bot, 24)
            || contains_prefixed_token(line, &slack_user, 24)
        {
            findings.push(secret_finding(
                repo,
                path,
                line_number,
                "messaging access token",
            ));
            continue;
        }
        if contains_prefixed_token(line, &stripe_live, 20) {
            findings.push(secret_finding(
                repo,
                path,
                line_number,
                "live payment secret key",
            ));
            continue;
        }
        if let Some(name) = hardcoded_secret_assignment(line) {
            findings.push(secret_finding(repo, path, line_number, &name));
        }
    }
}

fn contains_prefixed_token(line: &str, prefix: &str, minimum_len: usize) -> bool {
    let mut offset = 0usize;
    while let Some(relative) = line[offset..].find(prefix) {
        let start = offset + relative;
        let length = line[start..]
            .chars()
            .take_while(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
            })
            .count();
        if length >= minimum_len {
            return true;
        }
        offset = start.saturating_add(prefix.len());
        if offset >= line.len() {
            break;
        }
    }
    false
}

fn hardcoded_secret_assignment(line: &str) -> Option<String> {
    let mut operator_index = None;
    let bytes = line.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'=' {
            let previous = index.checked_sub(1).and_then(|value| bytes.get(value));
            let next = bytes.get(index + 1);
            if previous == Some(&b'=') || next == Some(&b'=') || next == Some(&b'>') {
                continue;
            }
            operator_index = Some(index);
            break;
        }
        if *byte == b':' {
            let previous = index.checked_sub(1).and_then(|value| bytes.get(value));
            let next = bytes.get(index + 1);
            if previous == Some(&b':') || next == Some(&b':') {
                continue;
            }
            operator_index = Some(index);
            break;
        }
    }

    let operator_index = operator_index?;
    let name = trailing_identifier(&line[..operator_index])?;
    let normalized = name.to_ascii_lowercase();
    if !sensitive_assignment_name(&normalized) {
        return None;
    }

    let right = line[operator_index + 1..].trim_start();
    if right.starts_with("env!")
        || right.starts_with("option_env!")
        || right.contains("env::var")
        || right.contains("getenv")
        || right.contains("environ[")
        || right.starts_with("std::env")
    {
        return None;
    }

    let quote = right.chars().next()?;
    if !matches!(quote, '\'' | '"') {
        return None;
    }
    let remainder = &right[quote.len_utf8()..];
    let end = remainder.find(quote)?;
    let value = &remainder[..end];
    if value.len() < 8 || obvious_non_secret(value) {
        return None;
    }

    Some(format!("hardcoded credential field {name}"))
}

fn trailing_identifier(left: &str) -> Option<&str> {
    let trimmed = left
        .trim_end_matches(|character: char| !character.is_ascii_alphanumeric() && character != '_');
    let start = trimmed
        .rfind(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .map(|index| index + 1)
        .unwrap_or(0);
    let value = &trimmed[start..];
    (!value.is_empty()).then_some(value)
}

fn sensitive_assignment_name(name: &str) -> bool {
    matches!(
        name,
        "password"
            | "passwd"
            | "api_key"
            | "apikey"
            | "secret_key"
            | "client_secret"
            | "access_token"
            | "auth_token"
            | "refresh_token"
            | "private_key"
    ) || name.ends_with("_password")
        || name.ends_with("_secret")
        || name.ends_with("_token")
}

fn obvious_non_secret(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized.is_empty()
        || normalized.contains("example")
        || normalized.contains("placeholder")
        || normalized.contains("changeme")
        || normalized.contains("your_")
        || normalized.contains("your-")
        || normalized == "password"
        || normalized == "not-a-secret"
        || normalized.starts_with("${")
        || normalized.starts_with("{{")
}

fn secret_finding(repo: &Path, path: &Path, line: usize, kind: &str) -> Finding {
    Finding {
        code: "VF_HARDCODED_SECRET".into(),
        message: format!(
            "{}:{line} contains {kind}; secret values are intentionally redacted",
            display_relative(repo, path)
        ),
        blocking: true,
    }
}

fn scan_suspicious_triggers(repo: &Path, path: &Path, content: &str, findings: &mut Vec<Finding>) {
    if !is_source_file(path) {
        return;
    }
    let lines = content.lines().collect::<Vec<_>>();
    let triggers = trigger_markers();
    let actions = sensitive_action_markers();

    for (index, line) in lines.iter().enumerate() {
        let lower = line.to_ascii_lowercase();
        if !looks_conditional(&lower) || !triggers.iter().any(|marker| lower.contains(marker)) {
            continue;
        }

        let end = (index + 9).min(lines.len());
        let window = lines[index..end]
            .iter()
            .map(|line| line.to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join("\n");
        if let Some(action) = actions
            .iter()
            .find(|marker| window.contains(marker.as_str()))
        {
            findings.push(Finding {
                code: "VF_SUSPICIOUS_TRIGGER".into(),
                message: format!(
                    "{}:{} condition depends on environment/identity/time/random/VCS state near sensitive action marker {action}",
                    display_relative(repo, path),
                    index + 1
                ),
                blocking: true,
            });
        }
    }
}

fn looks_conditional(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("if ")
        || trimmed.starts_with("if(")
        || trimmed.starts_with("match ")
        || trimmed.starts_with("when ")
        || trimmed.starts_with("case ")
        || trimmed.contains(" if ")
}

fn trigger_markers() -> Vec<String> {
    vec![
        ["std::", "env::var"].concat(),
        ["os.", "getenv"].concat(),
        ["process.", "env"].concat(),
        ["system", "time"].concat(),
        ["date", "time.now"].concat(),
        ["time.", "now"].concat(),
        ["host", "name"].concat(),
        ["user", "name"].concat(),
        ["current_", "user"].concat(),
        ["rand", "om"].concat(),
        ["thread_", "rng"].concat(),
        ["git ", "branch"].concat(),
        ["git ", "rev-parse"].concat(),
        ["machine", "_id"].concat(),
        ["license", "_key"].concat(),
    ]
}

fn sensitive_action_markers() -> Vec<String> {
    vec![
        ["remove", "_file"].concat(),
        ["remove", "_dir"].concat(),
        ["delete", "("].concat(),
        ["unlink", "("].concat(),
        ["subprocess", "."].concat(),
        ["os.", "system"].concat(),
        ["command::", "new"].concat(),
        ["process::", "command"].concat(),
        ["chmod", "("].concat(),
        ["kill", "("].concat(),
        ["terminate", "("].concat(),
        ["socket", "("].concat(),
        ["requests.", "post"].concat(),
        ["httpclient", "::"].concat(),
    ]
}

fn repository_text_files(repo: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    visit(repo, 0, &mut files);
    files
}

fn visit(path: &Path, depth: usize, files: &mut Vec<PathBuf>) {
    if depth > 32 {
        return;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };

    for entry in entries.flatten() {
        let child = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if ignored_directory(name.as_ref()) {
                continue;
            }
            visit(&child, depth + 1, files);
            continue;
        }
        if !kind.is_file() || !is_scannable_file(&child) {
            continue;
        }
        if fs::metadata(&child).is_ok_and(|metadata| metadata.len() <= MAX_SCAN_BYTES) {
            files.push(child);
        }
    }
}

fn ignored_directory(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | "target"
            | "node_modules"
            | "vendor"
            | ".venv"
            | "venv"
            | "dist"
            | "build"
            | ".idea"
            | ".vscode"
    )
}

fn is_scannable_file(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if name.starts_with(".env")
        || matches!(
            name,
            "Dockerfile" | "Containerfile" | "Makefile" | "Gemfile" | "Podfile"
        )
    {
        return true;
    }
    matches!(
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "rs" | "py"
            | "pyi"
            | "toml"
            | "json"
            | "yaml"
            | "yml"
            | "ini"
            | "cfg"
            | "conf"
            | "properties"
            | "js"
            | "jsx"
            | "ts"
            | "tsx"
            | "sh"
            | "bash"
            | "zsh"
            | "ps1"
            | "java"
            | "kt"
            | "kts"
            | "cs"
            | "go"
            | "php"
            | "rb"
            | "swift"
            | "sql"
            | "html"
            | "htm"
            | "xml"
    )
}

fn is_source_file(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "rs" | "py"
            | "js"
            | "jsx"
            | "ts"
            | "tsx"
            | "sh"
            | "bash"
            | "ps1"
            | "java"
            | "kt"
            | "kts"
            | "cs"
            | "go"
            | "php"
            | "rb"
            | "swift"
    )
}

fn display_relative(repo: &Path, path: &Path) -> String {
    path.strip_prefix(repo)
        .unwrap_or(path)
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("verificationforge-security-{nonce}"))
    }

    #[test]
    fn hardcoded_credentials_are_blocking_and_redacted() {
        let root = temp_dir();
        fs::create_dir_all(root.join("src")).expect("create src");
        let secret = ["super", "secret-value"].concat();
        fs::write(root.join("src/app.py"), format!("api_key = \"{secret}\"\n"))
            .expect("write source");

        let result = scan_repository(&root);
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.code == "VF_HARDCODED_SECRET")
        );
        assert!(
            result
                .findings
                .iter()
                .all(|finding| !finding.message.contains(&secret))
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn environment_loaded_credentials_are_allowed() {
        let root = temp_dir();
        fs::create_dir_all(root.join("src")).expect("create src");
        fs::write(
            root.join("src/app.rs"),
            "let access_token = std::env::var(\"ACCESS_TOKEN\")?;\n",
        )
        .expect("write source");
        let result = scan_repository(&root);
        assert_eq!(result.status, CheckStatus::Pass);
        assert!(result.has_reproducible_evidence());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn suspicious_environment_trigger_near_sensitive_action_is_blocking() {
        let root = temp_dir();
        fs::create_dir_all(root.join("src")).expect("create src");
        let trigger = ["std::", "env::var"].concat();
        let action = ["remove", "_file"].concat();
        fs::write(
            root.join("src/app.rs"),
            format!(
                "if {trigger}(\"SPECIAL_HOST\").is_ok() {{\n    std::fs::{action}(\"important.db\")?;\n}}\n"
            ),
        )
        .expect("write source");
        let result = scan_repository(&root);
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.code == "VF_SUSPICIOUS_TRIGGER")
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn clean_repository_produces_reproducible_security_evidence() {
        let root = temp_dir();
        fs::create_dir_all(root.join("src")).expect("create src");
        fs::write(
            root.join("src/lib.rs"),
            "pub fn add(a: u8, b: u8) -> u8 { a + b }\n",
        )
        .expect("write source");
        let result = scan_repository(&root);
        assert_eq!(result.status, CheckStatus::Pass);
        assert!(result.has_reproducible_evidence());
        fs::remove_dir_all(root).ok();
    }
}
