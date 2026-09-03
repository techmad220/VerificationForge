use std::fs;
use std::path::{Path, PathBuf};

use verificationforge_core::{
    CheckKind, CheckResult, CheckStatus, ExecutionAdapter, Finding, SpecialistDomain,
    SpecialistVerificationAdapter,
};

const MAX_SCAN_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Default)]
pub struct NativeAuthenticitySpecialist;

impl SpecialistVerificationAdapter for NativeAuthenticitySpecialist {
    fn id(&self) -> &'static str {
        "native-authenticity"
    }

    fn domains(&self) -> &'static [SpecialistDomain] {
        &[
            SpecialistDomain::StaticAnalysis,
            SpecialistDomain::Contracts,
        ]
    }

    fn supports(&self, check: CheckKind) -> bool {
        check == CheckKind::Placeholders
    }

    fn run_check(
        &self,
        check: CheckKind,
        repo: &Path,
        _execution: &dyn ExecutionAdapter,
    ) -> CheckResult {
        if !self.supports(check) {
            return CheckResult::unsupported(
                format!("{}:{}", self.id(), check.as_str()),
                "native authenticity specialist only handles placeholder/authenticity checks",
            );
        }
        scan_repository(repo)
    }
}

fn scan_repository(repo: &Path) -> CheckResult {
    let files = repository_source_files(repo);
    let mut findings = Vec::new();
    let mut readable = 0usize;

    for path in &files {
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        readable += 1;
        scan_explicit_placeholders(repo, path, &content, &mut findings);
        scan_semantic_fakes(repo, path, &content, &mut findings);
    }

    if findings.is_empty() {
        CheckResult::pass_with_evidence(
            "native-authenticity:placeholders",
            format!(
                "repository authenticity scan files={readable} critical-placeholders=0 critical-fake-implementations=0"
            ),
        )
    } else {
        CheckResult {
            check: "native-authenticity:placeholders".into(),
            status: CheckStatus::Fail,
            findings,
        }
    }
}

fn scan_explicit_placeholders(
    repo: &Path,
    path: &Path,
    content: &str,
    findings: &mut Vec<Finding>,
) {
    let markers = [
        (["TO", "DO:"].concat(), "unfinished work marker"),
        (["FIX", "ME:"].concat(), "unfinished fix marker"),
        (["X", "XX:"].concat(), "unfinished work marker"),
        (["unimplemented", "!("].concat(), "unimplemented macro"),
        (["todo", "!("].concat(), "unfinished-work macro"),
        (
            ["NotImplemented", "Error"].concat(),
            "not-implemented exception",
        ),
        (
            ["UnsupportedOperation", "Exception"].concat(),
            "unsupported-operation exception",
        ),
    ];

    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if test_assertion_line(path, trimmed) {
            continue;
        }
        if let Some((_, description)) = markers
            .iter()
            .find(|(marker, _)| line.contains(marker.as_str()))
        {
            findings.push(blocking_finding(
                "VF_CRITICAL_PLACEHOLDER",
                repo,
                path,
                index + 1,
                description,
            ));
            continue;
        }

        let lower = line.to_ascii_lowercase();
        if lower.contains("panic(")
            && (lower.contains("not implemented")
                || lower.contains("not yet implemented")
                || lower.contains("placeholder"))
        {
            findings.push(blocking_finding(
                "VF_CRITICAL_PLACEHOLDER",
                repo,
                path,
                index + 1,
                "not-implemented panic",
            ));
        }
    }
}

fn scan_semantic_fakes(repo: &Path, path: &Path, content: &str, findings: &mut Vec<Finding>) {
    match extension(path).as_str() {
        "py" | "pyi" => scan_python(repo, path, content, findings),
        "rb" => scan_ruby(repo, path, content, findings),
        "rs" | "go" | "js" | "jsx" | "ts" | "tsx" | "java" | "kt" | "kts" | "cs" | "swift"
        | "php" | "c" | "h" | "cc" | "cpp" | "cxx" | "hpp" | "hh" => {
            scan_braced(repo, path, content, findings)
        }
        _ => {}
    }
}

#[derive(Debug, Clone, Copy)]
struct Signature<'a> {
    name: &'a str,
    externally_visible: bool,
}

fn scan_braced(repo: &Path, path: &Path, content: &str, findings: &mut Vec<Finding>) {
    let ext = extension(path);
    let lines = content.lines().collect::<Vec<_>>();
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let Some(signature) = signature_for(trimmed, &ext) else {
            continue;
        };
        let sensitive = sensitive_gate_name(signature.name);
        if !sensitive && !signature.externally_visible {
            continue;
        }

        if let Some(body) = inline_body(trimmed) {
            if signature.externally_visible && body_is_empty(body) {
                findings.push(fake_finding(
                    repo,
                    path,
                    index + 1,
                    signature.name,
                    "externally visible function has an empty implementation",
                ));
            } else if sensitive && constant_decision_body(body) {
                findings.push(fake_finding(
                    repo,
                    path,
                    index + 1,
                    signature.name,
                    "authorization/authentication/permission decision is constant",
                ));
            }
            continue;
        }

        if !trimmed.contains('{') {
            continue;
        }
        let Some((body_index, body)) = next_code_line(&lines, index + 1) else {
            continue;
        };
        if signature.externally_visible && body == "}" {
            findings.push(fake_finding(
                repo,
                path,
                body_index + 1,
                signature.name,
                "externally visible function has an empty implementation",
            ));
        } else if sensitive && constant_decision_body(body) {
            findings.push(fake_finding(
                repo,
                path,
                body_index + 1,
                signature.name,
                "authorization/authentication/permission decision is constant",
            ));
        }
    }
}

fn signature_for<'a>(line: &'a str, ext: &str) -> Option<Signature<'a>> {
    match ext {
        "rs" => rust_signature(line),
        "go" => go_signature(line),
        "js" | "jsx" | "ts" | "tsx" => javascript_signature(line),
        _ => public_method_signature(line),
    }
}

fn rust_signature(line: &str) -> Option<Signature<'_>> {
    let function = line.find("fn ")?;
    let prefix = &line[..function];
    if prefix.contains('"') || prefix.contains("//") {
        return None;
    }
    let name = identifier(&line[function + 3..]);
    (!name.is_empty()).then_some(Signature {
        name,
        externally_visible: line.starts_with("pub ") || line.starts_with("pub("),
    })
}

fn go_signature(line: &str) -> Option<Signature<'_>> {
    let rest = line.strip_prefix("func ")?.trim_start();
    let rest = if rest.starts_with('(') {
        let close = rest.find(')')?;
        rest[close + 1..].trim_start()
    } else {
        rest
    };
    let name = identifier(rest);
    (!name.is_empty()).then_some(Signature {
        name,
        externally_visible: name
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_uppercase()),
    })
}

fn javascript_signature(line: &str) -> Option<Signature<'_>> {
    let externally_visible = line.starts_with("export ")
        || line.starts_with("exports.")
        || line.starts_with("module.exports");
    let name = if let Some(function) = line.find("function ") {
        identifier(&line[function + "function ".len()..])
    } else if let Some(arrow) = line.find("=>") {
        let left = line[..arrow].trim_end();
        let candidate = left
            .split(['=', ' ', ':'])
            .rfind(|value| !value.is_empty())
            .unwrap_or_default();
        identifier(candidate)
    } else {
        ""
    };
    (!name.is_empty()).then_some(Signature {
        name,
        externally_visible,
    })
}

fn public_method_signature(line: &str) -> Option<Signature<'_>> {
    let paren = line.find('(')?;
    let left = line[..paren].trim_end();
    let name = left
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .rfind(|value| !value.is_empty())
        .unwrap_or_default();
    if name.is_empty() || matches!(name, "if" | "for" | "while" | "switch" | "catch") {
        return None;
    }
    Some(Signature {
        name,
        externally_visible: false,
    })
}

fn scan_python(repo: &Path, path: &Path, content: &str, findings: &mut Vec<Finding>) {
    let lines = content.lines().collect::<Vec<_>>();
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed
            .strip_prefix("def ")
            .or_else(|| trimmed.strip_prefix("async def "))
        else {
            continue;
        };
        let name = identifier(rest);
        if name.is_empty() {
            continue;
        }
        let indent = line.len().saturating_sub(trimmed.len());
        let Some((body_index, body)) = next_indented_code_line(&lines, index + 1, indent) else {
            continue;
        };
        let body = body.trim();
        if !name.starts_with('_') && matches!(body, "pass" | "...") {
            findings.push(fake_finding(
                repo,
                path,
                body_index + 1,
                name,
                "externally visible function has no implementation",
            ));
        } else if sensitive_gate_name(name) && constant_decision_body(body) {
            findings.push(fake_finding(
                repo,
                path,
                body_index + 1,
                name,
                "authorization/authentication/permission decision is constant",
            ));
        }
    }
}

fn scan_ruby(repo: &Path, path: &Path, content: &str, findings: &mut Vec<Finding>) {
    let lines = content.lines().collect::<Vec<_>>();
    for (index, line) in lines.iter().enumerate() {
        let Some(rest) = line.trim().strip_prefix("def ") else {
            continue;
        };
        let name = identifier(rest);
        if name.is_empty() {
            continue;
        }
        let Some((body_index, body)) = next_code_line(&lines, index + 1) else {
            continue;
        };
        if body == "end" {
            findings.push(fake_finding(
                repo,
                path,
                body_index + 1,
                name,
                "method has an empty implementation",
            ));
        } else if sensitive_gate_name(name) && constant_decision_body(body) {
            findings.push(fake_finding(
                repo,
                path,
                body_index + 1,
                name,
                "authorization/authentication/permission decision is constant",
            ));
        }
    }
}

fn sensitive_gate_name(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase().replace('_', "");
    [
        "authoriz",
        "authenticate",
        "permission",
        "hasaccess",
        "canaccess",
        "isadmin",
        "allowaccess",
        "checkaccess",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

fn constant_decision_body(body: &str) -> bool {
    let normalized = body
        .chars()
        .filter(|character| {
            !character.is_whitespace() && !matches!(character, ';' | '{' | '}' | '(' | ')')
        })
        .collect::<String>()
        .to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "true" | "false" | "returntrue" | "returnfalse" | "return1" | "return0" | "1" | "0"
    )
}

fn inline_body(line: &str) -> Option<&str> {
    let open = line.find('{')?;
    let close = line.rfind('}')?;
    (close > open).then_some(line[open + 1..close].trim())
}

fn body_is_empty(body: &str) -> bool {
    let body = body.trim();
    body.is_empty() || body == ";"
}

fn next_code_line<'a>(lines: &'a [&'a str], start: usize) -> Option<(usize, &'a str)> {
    lines
        .iter()
        .enumerate()
        .skip(start)
        .find_map(|(index, line)| {
            let trimmed = line.trim();
            (!trimmed.is_empty() && !is_comment(trimmed)).then_some((index, trimmed))
        })
}

fn next_indented_code_line<'a>(
    lines: &'a [&'a str],
    start: usize,
    parent_indent: usize,
) -> Option<(usize, &'a str)> {
    for (index, line) in lines.iter().enumerate().skip(start) {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len().saturating_sub(trimmed.len());
        if indent <= parent_indent {
            return None;
        }
        return Some((index, trimmed));
    }
    None
}

fn is_comment(line: &str) -> bool {
    line.starts_with("//")
        || line.starts_with('#')
        || line.starts_with("/*")
        || line.starts_with('*')
}

fn test_assertion_line(path: &Path, line: &str) -> bool {
    let file = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let test_file = file.contains("test") || file.contains("spec");
    test_file && (line.contains("assert") || line.contains("expect(") || line.contains("fixture"))
}

fn identifier(value: &str) -> &str {
    let value = value.trim_start_matches(|character: char| {
        !(character.is_ascii_alphabetic() || character == '_')
    });
    let end = value
        .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .unwrap_or(value.len());
    &value[..end]
}

fn fake_finding(repo: &Path, path: &Path, line: usize, function: &str, reason: &str) -> Finding {
    Finding {
        code: "VF_CRITICAL_FAKE_IMPLEMENTATION".into(),
        message: format!(
            "{}:{line} function {function}: {reason}",
            display_relative(repo, path)
        ),
        blocking: true,
    }
}

fn blocking_finding(code: &str, repo: &Path, path: &Path, line: usize, reason: &str) -> Finding {
    Finding {
        code: code.into(),
        message: format!("{}:{line} {reason}", display_relative(repo, path)),
        blocking: true,
    }
}

fn repository_source_files(repo: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    visit(repo, 0, &mut files);
    files
}

fn visit(path: &Path, depth: usize, files: &mut Vec<PathBuf>) {
    if depth > 48 {
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
        } else if kind.is_file()
            && source_file(&child)
            && fs::metadata(&child).is_ok_and(|metadata| metadata.len() <= MAX_SCAN_BYTES)
        {
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
            | ".verificationforge"
    )
}

fn source_file(path: &Path) -> bool {
    matches!(
        extension(path).as_str(),
        "rs" | "py"
            | "pyi"
            | "go"
            | "js"
            | "jsx"
            | "ts"
            | "tsx"
            | "java"
            | "kt"
            | "kts"
            | "cs"
            | "swift"
            | "php"
            | "rb"
            | "c"
            | "h"
            | "cc"
            | "cpp"
            | "cxx"
            | "hpp"
            | "hh"
            | "m"
            | "mm"
            | "dart"
            | "scala"
            | "lua"
            | "pl"
            | "pm"
            | "r"
            | "jl"
            | "hs"
            | "ml"
            | "fs"
            | "ex"
            | "exs"
            | "erl"
            | "hrl"
            | "zig"
            | "nim"
            | "d"
            | "f"
            | "f90"
            | "f95"
            | "cob"
            | "cbl"
            | "sh"
            | "bash"
            | "zsh"
            | "ps1"
            | "sql"
            | "sol"
            | "vy"
            | "move"
            | "cairo"
    )
}

fn extension(path: &Path) -> String {
    path.extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn display_relative(repo: &Path, path: &Path) -> String {
    path.strip_prefix(repo)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct NoExecution;

    impl ExecutionAdapter for NoExecution {
        fn id(&self) -> &'static str {
            "none"
        }

        fn execute(
            &self,
            _program: &str,
            _args: &[String],
            _cwd: &Path,
        ) -> Result<verificationforge_core::ExecutionResult, String> {
            Err("execution is not used by authenticity checks".into())
        }
    }

    fn root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("verificationforge-authenticity-{name}-{nonce}"))
    }

    fn scan_file(name: &str, file: &str, content: &str) -> CheckResult {
        let root = root(name);
        fs::create_dir_all(&root).expect("create root");
        fs::write(root.join(file), content).expect("write fixture");
        let result =
            NativeAuthenticitySpecialist.run_check(CheckKind::Placeholders, &root, &NoExecution);
        fs::remove_dir_all(root).ok();
        result
    }

    #[test]
    fn clean_implementation_emits_reproducible_evidence() {
        let result = scan_file(
            "clean",
            "service.py",
            "def authorize(user, resource):\n    return user.can_access(resource)\n",
        );
        assert_eq!(result.status, CheckStatus::Pass);
        assert!(result.has_reproducible_evidence());
    }

    #[test]
    fn explicit_unfinished_marker_is_blocking() {
        let marker = ["TO", "DO:"].concat();
        let source = format!(
            "def calculate(value):\n    # {marker} implement real calculation\n    return value\n"
        );
        let result = scan_file("marker", "service.py", &source);
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.code == "VF_CRITICAL_PLACEHOLDER")
        );
    }

    #[test]
    fn python_pass_and_constant_authorization_are_blocking() {
        let pass_result = scan_file(
            "python-pass",
            "service.py",
            "def persist(value):\n    pass\n",
        );
        assert_eq!(pass_result.status, CheckStatus::Fail);

        let auth_result = scan_file(
            "python-auth",
            "auth.py",
            "def authorize(user):\n    return True\n",
        );
        assert_eq!(auth_result.status, CheckStatus::Fail);
        assert!(
            auth_result
                .findings
                .iter()
                .any(|finding| finding.code == "VF_CRITICAL_FAKE_IMPLEMENTATION")
        );
    }

    #[test]
    fn go_and_rust_critical_fakes_are_blocking() {
        let go = scan_file(
            "go-auth",
            "auth.go",
            "package auth\nfunc Authorize(user string) bool { return true }\n",
        );
        assert_eq!(go.status, CheckStatus::Fail);

        let rust = scan_file("rust-empty", "lib.rs", "pub fn persist(value: &str) {}\n");
        assert_eq!(rust.status, CheckStatus::Fail);
    }

    #[test]
    fn javascript_exported_empty_and_constant_auth_are_blocking() {
        let empty = scan_file(
            "js-empty",
            "service.js",
            "export function persist(value) {}\n",
        );
        assert_eq!(empty.status, CheckStatus::Fail);

        let auth = scan_file(
            "js-auth",
            "auth.js",
            "export function authorize(user) { return true; }\n",
        );
        assert_eq!(auth.status, CheckStatus::Fail);
    }

    #[test]
    fn embedded_rust_source_text_is_not_treated_as_live_code() {
        let result = scan_file(
            "rust-fixture-text",
            "lib.rs",
            "pub fn demo() { let source = \"pub fn authorize_user() -> bool { true }\"; }\n",
        );
        assert_eq!(result.status, CheckStatus::Pass);
    }

    #[test]
    fn non_sensitive_constant_helper_is_not_false_positive() {
        let result = scan_file(
            "go-helper",
            "feature.go",
            "package feature\nfunc enabled() bool { return true }\n",
        );
        assert_eq!(result.status, CheckStatus::Pass);
    }
}
