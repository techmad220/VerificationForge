use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisedTaskState {
    Pending,
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisedTask {
    pub id: String,
    pub state: SupervisedTaskState,
    pub waiting_on: BTreeSet<String>,
    pub last_progress_ms: u128,
    pub last_heartbeat_ms: u128,
    pub checkpoint: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LivenessReport {
    pub stalled: BTreeSet<String>,
    pub hung: BTreeSet<String>,
    pub deadlocked: BTreeSet<String>,
}

impl LivenessReport {
    pub fn healthy(&self) -> bool {
        self.stalled.is_empty() && self.hung.is_empty() && self.deadlocked.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct RunSupervisor {
    path: PathBuf,
    pub run_id: String,
    tasks: BTreeMap<String, SupervisedTask>,
}

impl RunSupervisor {
    pub fn create(root: &Path, run_id: impl Into<String>) -> Result<Self, String> {
        fs::create_dir_all(root).map_err(|error| {
            format!("cannot create supervisor root {}: {error}", root.display())
        })?;
        let run_id = run_id.into();
        validate_id("run", &run_id)?;
        let supervisor = Self {
            path: root.join(format!("{run_id}.vflive")),
            run_id,
            tasks: BTreeMap::new(),
        };
        supervisor.persist()?;
        Ok(supervisor)
    }

    pub fn recover(root: &Path, run_id: impl Into<String>) -> Result<Self, String> {
        let run_id = run_id.into();
        validate_id("run", &run_id)?;
        let path = root.join(format!("{run_id}.vflive"));
        let content = fs::read_to_string(&path)
            .map_err(|error| format!("cannot read supervisor {}: {error}", path.display()))?;
        let tasks = decode_tasks(&content)?;
        Ok(Self {
            path,
            run_id,
            tasks,
        })
    }

    pub fn register_task(
        &mut self,
        id: impl Into<String>,
        waiting_on: impl IntoIterator<Item = String>,
        timestamp_ms: u128,
    ) -> Result<(), String> {
        let id = id.into();
        validate_id("task", &id)?;
        if self.tasks.contains_key(&id) {
            return Err(format!("task {id} is already registered"));
        }
        let waiting_on = waiting_on.into_iter().collect::<BTreeSet<_>>();
        if waiting_on.contains(&id) {
            return Err(format!("task {id} cannot wait on itself"));
        }
        if waiting_on
            .iter()
            .any(|dependency| dependency.trim().is_empty())
        {
            return Err(format!("task {id} contains an empty dependency id"));
        }
        self.tasks.insert(
            id.clone(),
            SupervisedTask {
                id,
                state: SupervisedTaskState::Pending,
                waiting_on,
                last_progress_ms: timestamp_ms,
                last_heartbeat_ms: timestamp_ms,
                checkpoint: None,
            },
        );
        self.persist()
    }

    pub fn start_task(&mut self, id: &str, timestamp_ms: u128) -> Result<(), String> {
        let task = self.task_mut(id)?;
        if task.state != SupervisedTaskState::Pending {
            return Err(format!(
                "task {id} cannot start from state {:?}",
                task.state
            ));
        }
        task.state = SupervisedTaskState::Running;
        task.last_progress_ms = timestamp_ms;
        task.last_heartbeat_ms = timestamp_ms;
        self.persist()
    }

    pub fn heartbeat(&mut self, id: &str, timestamp_ms: u128) -> Result<(), String> {
        let task = self.running_task_mut(id)?;
        if timestamp_ms < task.last_heartbeat_ms {
            return Err(format!("task {id} heartbeat timestamp moved backwards"));
        }
        task.last_heartbeat_ms = timestamp_ms;
        self.persist()
    }

    pub fn progress(&mut self, id: &str, timestamp_ms: u128) -> Result<(), String> {
        let task = self.running_task_mut(id)?;
        if timestamp_ms < task.last_progress_ms || timestamp_ms < task.last_heartbeat_ms {
            return Err(format!("task {id} progress timestamp moved backwards"));
        }
        task.last_progress_ms = timestamp_ms;
        task.last_heartbeat_ms = timestamp_ms;
        self.persist()
    }

    pub fn checkpoint(
        &mut self,
        id: &str,
        checkpoint: impl Into<String>,
        timestamp_ms: u128,
    ) -> Result<(), String> {
        let checkpoint = checkpoint.into();
        if checkpoint.trim().is_empty() {
            return Err("checkpoint value cannot be empty".into());
        }
        let task = self.running_task_mut(id)?;
        if timestamp_ms < task.last_progress_ms || timestamp_ms < task.last_heartbeat_ms {
            return Err(format!("task {id} checkpoint timestamp moved backwards"));
        }
        task.checkpoint = Some(checkpoint);
        task.last_progress_ms = timestamp_ms;
        task.last_heartbeat_ms = timestamp_ms;
        self.persist()
    }

    pub fn complete_task(&mut self, id: &str, timestamp_ms: u128) -> Result<(), String> {
        self.finish_task(id, SupervisedTaskState::Completed, timestamp_ms)
    }

    pub fn fail_task(&mut self, id: &str, timestamp_ms: u128) -> Result<(), String> {
        self.finish_task(id, SupervisedTaskState::Failed, timestamp_ms)
    }

    pub fn task(&self, id: &str) -> Option<&SupervisedTask> {
        self.tasks.get(id)
    }

    pub fn report(
        &self,
        current_ms: u128,
        heartbeat_timeout_ms: u128,
        progress_timeout_ms: u128,
    ) -> LivenessReport {
        let mut report = LivenessReport::default();
        for task in self.tasks.values() {
            if task.state != SupervisedTaskState::Running {
                continue;
            }
            let heartbeat_age = current_ms.saturating_sub(task.last_heartbeat_ms);
            let progress_age = current_ms.saturating_sub(task.last_progress_ms);
            if heartbeat_age > heartbeat_timeout_ms {
                report.hung.insert(task.id.clone());
            } else if progress_age > progress_timeout_ms {
                report.stalled.insert(task.id.clone());
            }
        }
        report.deadlocked = self.deadlocked_tasks();
        report
    }

    fn finish_task(
        &mut self,
        id: &str,
        state: SupervisedTaskState,
        timestamp_ms: u128,
    ) -> Result<(), String> {
        let task = self.running_task_mut(id)?;
        if timestamp_ms < task.last_progress_ms || timestamp_ms < task.last_heartbeat_ms {
            return Err(format!("task {id} completion timestamp moved backwards"));
        }
        task.state = state;
        task.last_progress_ms = timestamp_ms;
        task.last_heartbeat_ms = timestamp_ms;
        self.persist()
    }

    fn deadlocked_tasks(&self) -> BTreeSet<String> {
        let candidates = self
            .tasks
            .values()
            .filter(|task| {
                matches!(
                    task.state,
                    SupervisedTaskState::Pending | SupervisedTaskState::Running
                )
            })
            .filter(|task| !task.waiting_on.is_empty())
            .map(|task| task.id.clone())
            .collect::<BTreeSet<_>>();
        let mut deadlocked = BTreeSet::new();
        for candidate in &candidates {
            let mut visiting = BTreeSet::new();
            let mut visited = BTreeSet::new();
            if self.reaches_cycle(
                candidate,
                candidate,
                &candidates,
                &mut visiting,
                &mut visited,
            ) {
                deadlocked.insert(candidate.clone());
            }
        }
        deadlocked
    }

    fn reaches_cycle(
        &self,
        origin: &str,
        current: &str,
        candidates: &BTreeSet<String>,
        visiting: &mut BTreeSet<String>,
        visited: &mut BTreeSet<String>,
    ) -> bool {
        if !visiting.insert(current.to_owned()) {
            return current == origin;
        }
        if !visited.insert(current.to_owned()) {
            visiting.remove(current);
            return false;
        }
        let cyclic = self.tasks.get(current).is_some_and(|task| {
            task.waiting_on.iter().any(|dependency| {
                candidates.contains(dependency)
                    && (dependency == origin
                        || self.reaches_cycle(origin, dependency, candidates, visiting, visited))
            })
        });
        visiting.remove(current);
        cyclic
    }

    fn task_mut(&mut self, id: &str) -> Result<&mut SupervisedTask, String> {
        self.tasks
            .get_mut(id)
            .ok_or_else(|| format!("unknown supervised task {id}"))
    }

    fn running_task_mut(&mut self, id: &str) -> Result<&mut SupervisedTask, String> {
        let task = self.task_mut(id)?;
        if task.state != SupervisedTaskState::Running {
            return Err(format!("task {id} is not running"));
        }
        Ok(task)
    }

    fn persist(&self) -> Result<(), String> {
        let encoded = encode_tasks(&self.tasks);
        let temporary = self.path.with_extension("tmp");
        fs::write(&temporary, encoded)
            .map_err(|error| format!("cannot write supervisor {}: {error}", temporary.display()))?;
        fs::rename(&temporary, &self.path)
            .map_err(|error| format!("cannot publish supervisor {}: {error}", self.path.display()))
    }
}

fn validate_id(label: &str, id: &str) -> Result<(), String> {
    if id.trim().is_empty() {
        return Err(format!("{label} id cannot be empty"));
    }
    if id.contains(['\n', '\r', '\t', '|', ',']) {
        return Err(format!(
            "{label} id contains unsupported delimiter characters"
        ));
    }
    Ok(())
}

fn encode_tasks(tasks: &BTreeMap<String, SupervisedTask>) -> String {
    let mut output = String::new();
    for task in tasks.values() {
        let state = match task.state {
            SupervisedTaskState::Pending => "pending",
            SupervisedTaskState::Running => "running",
            SupervisedTaskState::Completed => "completed",
            SupervisedTaskState::Failed => "failed",
        };
        let waiting_on = task
            .waiting_on
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(",");
        let checkpoint = task.checkpoint.clone().unwrap_or_default();
        output.push_str(&format!(
            "{}|{}|{}|{}|{}|{}\n",
            task.id,
            state,
            task.last_progress_ms,
            task.last_heartbeat_ms,
            waiting_on,
            checkpoint.replace(['\n', '\r', '\t', '|'], " ")
        ));
    }
    output
}

fn decode_tasks(content: &str) -> Result<BTreeMap<String, SupervisedTask>, String> {
    let mut tasks = BTreeMap::new();
    for (index, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let parts = line.splitn(6, '|').collect::<Vec<_>>();
        if parts.len() != 6 {
            return Err(format!("invalid supervisor row {}", index + 1));
        }
        validate_id("task", parts[0])?;
        let state = match parts[1] {
            "pending" => SupervisedTaskState::Pending,
            "running" => SupervisedTaskState::Running,
            "completed" => SupervisedTaskState::Completed,
            "failed" => SupervisedTaskState::Failed,
            other => return Err(format!("invalid supervised task state {other}")),
        };
        let last_progress_ms = parts[2]
            .parse::<u128>()
            .map_err(|error| format!("invalid progress timestamp: {error}"))?;
        let last_heartbeat_ms = parts[3]
            .parse::<u128>()
            .map_err(|error| format!("invalid heartbeat timestamp: {error}"))?;
        let waiting_on = if parts[4].is_empty() {
            BTreeSet::new()
        } else {
            parts[4].split(',').map(str::to_owned).collect()
        };
        let checkpoint = if parts[5].is_empty() {
            None
        } else {
            Some(parts[5].to_owned())
        };
        let task = SupervisedTask {
            id: parts[0].to_owned(),
            state,
            waiting_on,
            last_progress_ms,
            last_heartbeat_ms,
            checkpoint,
        };
        if tasks.insert(task.id.clone(), task).is_some() {
            return Err(format!("duplicate supervised task {}", parts[0]));
        }
    }
    Ok(tasks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("verificationforge-{name}-{nonce}"))
    }

    #[test]
    fn checkpoint_survives_recovery() {
        let root = root("checkpoint-recovery");
        let mut supervisor = RunSupervisor::create(&root, "run-1").expect("create");
        supervisor
            .register_task("compile", Vec::<String>::new(), 10)
            .expect("register");
        supervisor.start_task("compile", 20).expect("start");
        supervisor
            .checkpoint("compile", "object-42", 30)
            .expect("checkpoint");

        let recovered = RunSupervisor::recover(&root, "run-1").expect("recover");
        let task = recovered.task("compile").expect("task");
        assert_eq!(task.state, SupervisedTaskState::Running);
        assert_eq!(task.checkpoint.as_deref(), Some("object-42"));
        assert_eq!(task.last_progress_ms, 30);
        assert_eq!(task.last_heartbeat_ms, 30);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn report_distinguishes_stall_from_hang() {
        let root = root("stall-hang");
        let mut supervisor = RunSupervisor::create(&root, "run-1").expect("create");
        supervisor
            .register_task("stalled", Vec::<String>::new(), 0)
            .expect("register stalled");
        supervisor
            .register_task("hung", Vec::<String>::new(), 0)
            .expect("register hung");
        supervisor.start_task("stalled", 0).expect("start stalled");
        supervisor.start_task("hung", 0).expect("start hung");
        supervisor.heartbeat("stalled", 90).expect("heartbeat");

        let report = supervisor.report(100, 20, 50);
        assert_eq!(report.stalled, BTreeSet::from(["stalled".to_owned()]));
        assert_eq!(report.hung, BTreeSet::from(["hung".to_owned()]));
        assert!(report.deadlocked.is_empty());
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn dependency_cycle_is_reported_as_deadlock() {
        let root = root("deadlock");
        let mut supervisor = RunSupervisor::create(&root, "run-1").expect("create");
        supervisor
            .register_task("a", ["b".to_owned()], 0)
            .expect("register a");
        supervisor
            .register_task("b", ["c".to_owned()], 0)
            .expect("register b");
        supervisor
            .register_task("c", ["a".to_owned()], 0)
            .expect("register c");

        let report = supervisor.report(0, 100, 100);
        assert_eq!(
            report.deadlocked,
            BTreeSet::from(["a".to_owned(), "b".to_owned(), "c".to_owned()])
        );
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn acyclic_dependencies_and_completed_tasks_do_not_deadlock() {
        let root = root("acyclic");
        let mut supervisor = RunSupervisor::create(&root, "run-1").expect("create");
        supervisor
            .register_task("base", Vec::<String>::new(), 0)
            .expect("register base");
        supervisor
            .register_task("child", ["base".to_owned()], 0)
            .expect("register child");
        supervisor.start_task("base", 1).expect("start base");
        supervisor.complete_task("base", 2).expect("complete base");
        assert!(supervisor.report(2, 100, 100).deadlocked.is_empty());
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn backwards_timestamps_and_invalid_transitions_fail_closed() {
        let root = root("fail-closed");
        let mut supervisor = RunSupervisor::create(&root, "run-1").expect("create");
        supervisor
            .register_task("task", Vec::<String>::new(), 10)
            .expect("register");
        assert!(supervisor.heartbeat("task", 11).is_err());
        supervisor.start_task("task", 20).expect("start");
        assert!(supervisor.heartbeat("task", 19).is_err());
        assert!(supervisor.progress("task", 19).is_err());
        supervisor.complete_task("task", 30).expect("complete");
        assert!(supervisor.complete_task("task", 31).is_err());
        fs::remove_dir_all(root).expect("cleanup");
    }
}
