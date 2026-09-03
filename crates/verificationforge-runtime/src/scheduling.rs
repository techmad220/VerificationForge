use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use verificationforge_core::{
    CheckKind, CheckResult, CheckStatus, Finding, SymbolId, UniversalCodeGraph, VerificationLevel,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentAddress(pub String);

impl ContentAddress {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        const OFFSET: u128 = 0x6c62272e07bb014262b821756295c58d;
        const PRIME: u128 = 0x0000000001000000000000000000013b;
        let mut hash = OFFSET;
        for byte in bytes {
            hash ^= u128::from(*byte);
            hash = hash.wrapping_mul(PRIME);
        }
        Self(format!("{hash:032x}"))
    }

    pub fn combine<'a, I>(parts: I) -> Self
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let mut bytes = Vec::new();
        for part in parts {
            bytes.extend_from_slice(&(part.len() as u64).to_le_bytes());
            bytes.extend_from_slice(part);
        }
        Self::from_bytes(&bytes)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepositorySnapshot {
    pub files: BTreeMap<String, ContentAddress>,
    pub address: Option<ContentAddress>,
}

impl RepositorySnapshot {
    pub fn capture(repo: &Path) -> Result<Self, String> {
        let mut files = BTreeMap::new();
        visit_files(repo, repo, 0, &mut |relative, path| {
            let bytes = fs::read(path)
                .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
            files.insert(relative, ContentAddress::from_bytes(&bytes));
            Ok(())
        })?;
        let mut canonical = Vec::new();
        for (path, address) in &files {
            canonical.extend_from_slice(&(path.len() as u64).to_le_bytes());
            canonical.extend_from_slice(path.as_bytes());
            canonical.extend_from_slice(address.0.as_bytes());
        }
        Ok(Self {
            files,
            address: Some(ContentAddress::from_bytes(&canonical)),
        })
    }

    pub fn diff(&self, newer: &Self) -> SnapshotDiff {
        let mut result = SnapshotDiff::default();
        for (path, address) in &newer.files {
            match self.files.get(path) {
                None => {
                    result.added.insert(path.clone());
                    result.changed.insert(path.clone());
                }
                Some(previous) if previous != address => {
                    result.changed.insert(path.clone());
                }
                Some(_) => {}
            }
        }
        for path in self.files.keys() {
            if !newer.files.contains_key(path) {
                result.removed.insert(path.clone());
                result.changed.insert(path.clone());
            }
        }
        result
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SnapshotDiff {
    pub changed: BTreeSet<String>,
    pub added: BTreeSet<String>,
    pub removed: BTreeSet<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImpactPlan {
    pub changed_paths: BTreeSet<String>,
    pub seed_symbols: BTreeSet<SymbolId>,
    pub affected_symbols: BTreeSet<SymbolId>,
    pub requires_full_verification: bool,
}

pub fn plan_impact(diff: &SnapshotDiff, graph: &UniversalCodeGraph) -> ImpactPlan {
    let changed_paths = diff.changed.clone();
    let seed_symbols = graph.symbols_for_paths(changed_paths.iter().map(String::as_str));
    let mapped_paths = seed_symbols
        .iter()
        .filter_map(|symbol| graph.nodes.get(symbol))
        .filter_map(|node| node.path.clone())
        .collect::<BTreeSet<_>>();
    let requires_full_verification = changed_paths
        .iter()
        .any(|path| !mapped_paths.contains(path));
    let affected_symbols = graph.dependency_cone(seed_symbols.iter().cloned());
    ImpactPlan {
        changed_paths,
        seed_symbols,
        affected_symbols,
        requires_full_verification,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CacheKey(pub ContentAddress);

impl CacheKey {
    pub fn new(
        snapshot: &ContentAddress,
        adapter_id: &str,
        check: CheckKind,
        level: VerificationLevel,
        policy_version: u64,
    ) -> Self {
        let level_text = format!("{level:?}");
        let policy_text = policy_version.to_string();
        Self(ContentAddress::combine([
            snapshot.0.as_bytes(),
            adapter_id.as_bytes(),
            check.as_str().as_bytes(),
            level_text.as_bytes(),
            policy_text.as_bytes(),
        ]))
    }
}

pub trait VerificationCache: Send + Sync {
    fn get(&self, key: &CacheKey) -> Result<Option<CheckResult>, String>;
    fn put(&mut self, key: &CacheKey, result: &CheckResult) -> Result<(), String>;
}

#[derive(Debug, Clone, Default)]
pub struct MemoryVerificationCache {
    entries: BTreeMap<CacheKey, CheckResult>,
}

impl VerificationCache for MemoryVerificationCache {
    fn get(&self, key: &CacheKey) -> Result<Option<CheckResult>, String> {
        Ok(self.entries.get(key).cloned())
    }

    fn put(&mut self, key: &CacheKey, result: &CheckResult) -> Result<(), String> {
        self.entries.insert(key.clone(), result.clone());
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct FileVerificationCache {
    root: PathBuf,
}

impl FileVerificationCache {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn path_for(&self, key: &CacheKey) -> PathBuf {
        self.root.join(format!("{}.vfcache", key.0.0))
    }
}

impl VerificationCache for FileVerificationCache {
    fn get(&self, key: &CacheKey) -> Result<Option<CheckResult>, String> {
        let path = self.path_for(key);
        if !path.is_file() {
            return Ok(None);
        }
        let content = fs::read_to_string(&path)
            .map_err(|error| format!("cannot read cache {}: {error}", path.display()))?;
        decode_result(&content).map(Some)
    }

    fn put(&mut self, key: &CacheKey, result: &CheckResult) -> Result<(), String> {
        fs::create_dir_all(&self.root)
            .map_err(|error| format!("cannot create cache {}: {error}", self.root.display()))?;
        let path = self.path_for(key);
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, encode_result(result))
            .map_err(|error| format!("cannot write cache {}: {error}", temporary.display()))?;
        fs::rename(&temporary, &path)
            .map_err(|error| format!("cannot publish cache {}: {error}", path.display()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResourceRequest {
    pub cpu_slots: u16,
    pub memory_mb: u64,
    pub gpu_mb: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResourceBudget {
    pub cpu_slots: u16,
    pub memory_mb: u64,
    pub gpu_mb: u64,
}

impl ResourceBudget {
    fn fits(self, request: ResourceRequest) -> bool {
        request.cpu_slots <= self.cpu_slots
            && request.memory_mb <= self.memory_mb
            && request.gpu_mb <= self.gpu_mb
    }

    fn can_add(self, used: ResourceRequest, request: ResourceRequest) -> bool {
        used.cpu_slots.saturating_add(request.cpu_slots) <= self.cpu_slots
            && used.memory_mb.saturating_add(request.memory_mb) <= self.memory_mb
            && used.gpu_mb.saturating_add(request.gpu_mb) <= self.gpu_mb
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationTask {
    pub id: String,
    pub adapter_id: String,
    pub check: CheckKind,
    pub resources: ResourceRequest,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScheduleBatch {
    pub tasks: Vec<VerificationTask>,
    pub resources: ResourceRequest,
}

pub fn schedule_tasks(
    tasks: impl IntoIterator<Item = VerificationTask>,
    budget: ResourceBudget,
) -> Result<Vec<ScheduleBatch>, String> {
    let mut batches = Vec::<ScheduleBatch>::new();
    for task in tasks {
        if !budget.fits(task.resources) {
            return Err(format!(
                "task {} exceeds scheduler resource budget",
                task.id
            ));
        }
        let mut pending = Some(task);
        for batch in &mut batches {
            let candidate = pending.as_ref().expect("task exists until scheduled");
            if budget.can_add(batch.resources, candidate.resources) {
                let candidate = pending.take().expect("task exists until scheduled");
                batch.resources.cpu_slots += candidate.resources.cpu_slots;
                batch.resources.memory_mb += candidate.resources.memory_mb;
                batch.resources.gpu_mb += candidate.resources.gpu_mb;
                batch.tasks.push(candidate);
                break;
            }
        }
        if let Some(candidate) = pending {
            batches.push(ScheduleBatch {
                resources: candidate.resources,
                tasks: vec![candidate],
            });
        }
    }
    Ok(batches)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalEventKind {
    Started,
    Progress,
    Heartbeat,
    Checkpoint,
    Completed,
    Failed,
}

#[derive(Debug, Clone)]
pub struct RunJournal {
    path: PathBuf,
    pub run_id: String,
    pub last_heartbeat_ms: u128,
}

impl RunJournal {
    pub fn create(root: &Path, run_id: impl Into<String>) -> Result<Self, String> {
        let run_id = run_id.into();
        fs::create_dir_all(root)
            .map_err(|error| format!("cannot create journal root {}: {error}", root.display()))?;
        let path = root.join(format!("{run_id}.journal"));
        let mut journal = Self {
            path,
            run_id,
            last_heartbeat_ms: now_ms(),
        };
        journal.append(JournalEventKind::Started, "run started")?;
        Ok(journal)
    }

    pub fn append(&mut self, kind: JournalEventKind, message: &str) -> Result<(), String> {
        let timestamp = now_ms();
        if matches!(
            kind,
            JournalEventKind::Heartbeat | JournalEventKind::Progress
        ) {
            self.last_heartbeat_ms = timestamp;
        }
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|error| format!("cannot open journal {}: {error}", self.path.display()))?;
        writeln!(
            file,
            "{timestamp}\t{kind:?}\t{}",
            message.replace(['\r', '\n', '\t'], " ")
        )
        .map_err(|error| format!("cannot append journal {}: {error}", self.path.display()))?;
        file.sync_data()
            .map_err(|error| format!("cannot sync journal {}: {error}", self.path.display()))
    }

    pub fn heartbeat(&mut self, message: &str) -> Result<(), String> {
        self.append(JournalEventKind::Heartbeat, message)
    }

    pub fn stalled(&self, current_ms: u128, timeout_ms: u128) -> bool {
        current_ms.saturating_sub(self.last_heartbeat_ms) > timeout_ms
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn visit_files<F>(repo: &Path, path: &Path, depth: usize, visitor: &mut F) -> Result<(), String>
where
    F: FnMut(String, &Path) -> Result<(), String>,
{
    if depth > 64 {
        return Err(format!(
            "repository traversal exceeded depth at {}",
            path.display()
        ));
    }
    let mut entries = fs::read_dir(path)
        .map_err(|error| format!("cannot read directory {}: {error}", path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot enumerate directory {}: {error}", path.display()))?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot inspect {}: {error}", entry.path().display()))?;
        if file_type.is_symlink() {
            continue;
        }
        let child = entry.path();
        if file_type.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if matches!(
                name.as_ref(),
                ".git" | "target" | "node_modules" | ".venv" | "venv" | "__pycache__"
            ) {
                continue;
            }
            visit_files(repo, &child, depth + 1, visitor)?;
        } else if file_type.is_file() {
            let relative = child
                .strip_prefix(repo)
                .map_err(|error| format!("cannot relativize {}: {error}", child.display()))?
                .to_string_lossy()
                .replace('\\', "/");
            visitor(relative, &child)?;
        }
    }
    Ok(())
}

fn encode_result(result: &CheckResult) -> String {
    let status = match result.status {
        CheckStatus::Pass => "pass",
        CheckStatus::Fail => "fail",
        CheckStatus::Skipped => "skipped",
        CheckStatus::Unsupported => "unsupported",
    };
    let mut output = format!(
        "{status}\n{}\n{}\n",
        hex_encode(result.check.as_bytes()),
        result.findings.len()
    );
    for finding in &result.findings {
        output.push_str(&format!(
            "{}\t{}\t{}\n",
            hex_encode(finding.code.as_bytes()),
            if finding.blocking { "1" } else { "0" },
            hex_encode(finding.message.as_bytes())
        ));
    }
    output
}

fn decode_result(content: &str) -> Result<CheckResult, String> {
    let mut lines = content.lines();
    let status = match lines
        .next()
        .ok_or_else(|| "cache missing status".to_owned())?
    {
        "pass" => CheckStatus::Pass,
        "fail" => CheckStatus::Fail,
        "skipped" => CheckStatus::Skipped,
        "unsupported" => CheckStatus::Unsupported,
        other => return Err(format!("unknown cached status {other}")),
    };
    let check = decode_text(
        lines
            .next()
            .ok_or_else(|| "cache missing check".to_owned())?,
    )?;
    let count = lines
        .next()
        .ok_or_else(|| "cache missing finding count".to_owned())?
        .parse::<usize>()
        .map_err(|error| format!("invalid cached finding count: {error}"))?;
    let mut findings = Vec::with_capacity(count);
    for _ in 0..count {
        let line = lines
            .next()
            .ok_or_else(|| "cache missing finding row".to_owned())?;
        let mut parts = line.splitn(3, '\t');
        let code = decode_text(
            parts
                .next()
                .ok_or_else(|| "cache missing finding code".to_owned())?,
        )?;
        let blocking = match parts
            .next()
            .ok_or_else(|| "cache missing finding blocking flag".to_owned())?
        {
            "1" => true,
            "0" => false,
            other => return Err(format!("invalid cached blocking flag {other}")),
        };
        let message = decode_text(
            parts
                .next()
                .ok_or_else(|| "cache missing finding message".to_owned())?,
        )?;
        findings.push(Finding {
            code,
            message,
            blocking,
        });
    }
    Ok(CheckResult {
        check,
        status,
        findings,
    })
}

fn decode_text(value: &str) -> Result<String, String> {
    String::from_utf8(hex_decode(value)?)
        .map_err(|error| format!("cached value is not utf-8: {error}"))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn hex_decode(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("hex value has odd length".into());
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = hex_digit(pair[0])?;
            let low = hex_digit(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_digit(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(format!("invalid hex digit {}", char::from(value))),
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use verificationforge_core::{CodeNode, CodeNodeKind};

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("verificationforge-{name}-{nonce}"))
    }

    #[test]
    fn snapshot_diff_and_impact_are_content_addressed() {
        let root = temp_dir("snapshot");
        fs::create_dir_all(root.join("src")).expect("create directory");
        fs::write(root.join("src/lib.rs"), "pub fn value() -> u8 { 1 }").expect("write source");
        let first = RepositorySnapshot::capture(&root).expect("capture first");
        fs::write(root.join("src/lib.rs"), "pub fn value() -> u8 { 2 }").expect("update source");
        let second = RepositorySnapshot::capture(&root).expect("capture second");
        assert_ne!(first.address, second.address);
        let diff = first.diff(&second);
        assert!(diff.changed.contains("src/lib.rs"));

        let mut graph = UniversalCodeGraph::default();
        graph.add_node(CodeNode {
            id: SymbolId("crate::value".into()),
            kind: CodeNodeKind::Function,
            language: Some("Rust".into()),
            path: Some("src/lib.rs".into()),
            display_name: "value".into(),
        });
        let plan = plan_impact(&diff, &graph);
        assert!(!plan.requires_full_verification);
        assert!(
            plan.affected_symbols
                .contains(&SymbolId("crate::value".into()))
        );
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn file_cache_round_trips_findings() {
        let root = temp_dir("cache");
        let mut cache = FileVerificationCache::new(&root);
        let key = CacheKey(ContentAddress::from_bytes(b"key"));
        let result = CheckResult::fail("rust:test", "BROKEN", "failure details");
        cache.put(&key, &result).expect("cache put");
        assert_eq!(cache.get(&key).expect("cache get"), Some(result));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn scheduler_never_overcommits_budget() {
        let budget = ResourceBudget {
            cpu_slots: 2,
            memory_mb: 1024,
            gpu_mb: 0,
        };
        let tasks = (0..3)
            .map(|index| VerificationTask {
                id: format!("task-{index}"),
                adapter_id: "rust".into(),
                check: CheckKind::Test,
                resources: ResourceRequest {
                    cpu_slots: 1,
                    memory_mb: 512,
                    gpu_mb: 0,
                },
            })
            .collect::<Vec<_>>();
        let batches = schedule_tasks(tasks, budget).expect("schedule tasks");
        assert_eq!(batches.len(), 2);
        assert!(batches.iter().all(|batch| batch.resources.cpu_slots <= 2));
    }

    #[test]
    fn journal_detects_stalls() {
        let root = temp_dir("journal");
        let journal = RunJournal::create(&root, "run-1").expect("create journal");
        assert!(journal.stalled(journal.last_heartbeat_ms + 1001, 1000));
        assert!(journal.path().is_file());
        fs::remove_dir_all(root).ok();
    }
}
