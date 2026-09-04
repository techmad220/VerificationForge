use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use verificationforge_core::{StateMachineModel, StateTransition};
use verificationforge_runtime::{
    CacheKey, CheckKind, CheckResult, ContentAddress, ExecutionAdapter, FileVerificationCache,
    ProcessExecutionAdapter, ResourceBudget, ResourceRequest, VerificationCache, VerificationLevel,
    VerificationTask, schedule_tasks,
};

#[test]
fn self_adversarial_workload() {
    let mode = env::var("VF_SELF_MODE").unwrap_or_else(|_| "smoke".into());
    let seed_text = env::var("VF_SELF_SEED").unwrap_or_else(|_| "verificationforge-smoke".into());
    let requested = env::var("VF_SELF_ITERATIONS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(64)
        .max(1);
    let seed = seed_from_text(&seed_text);

    match mode.as_str() {
        "smoke" => fuzz_cases(seed, requested.min(128)),
        "fuzz" => fuzz_cases(seed, requested),
        "concurrency" => concurrency_cases(seed, requested),
        "stress" => stress_cases(seed, requested),
        "fault" => fault_cases(seed, requested),
        "resource" => resource_cases(seed, requested),
        other => panic!("unknown VF_SELF_MODE={other}"),
    }

    println!("VF_SELF_MODE={mode}");
    println!("VF_SELF_CASES={requested}");
    println!("VF_SELF_FAILURES=0");
}

fn fuzz_cases(seed: u64, iterations: usize) {
    for index in 0..iterations {
        let mut rng = XorShift64::new(seed ^ (index as u64).wrapping_mul(0x9e3779b97f4a7c15));
        let len = (rng.next() as usize % 1024) + 1;
        let mut bytes = vec![0u8; len];
        for byte in &mut bytes {
            *byte = rng.next() as u8;
        }

        let first = ContentAddress::from_bytes(&bytes);
        let second = ContentAddress::from_bytes(&bytes);
        assert_eq!(first, second, "content addressing must be deterministic");

        let split = len / 2;
        let framed = ContentAddress::combine([&bytes[..split], &bytes[split..]]);
        let differently_framed = ContentAddress::combine([&bytes[..], &[][..]]);
        if split != len {
            assert_ne!(
                framed, differently_framed,
                "content-address framing must preserve part boundaries"
            );
        }

        let state_count = 2 + (rng.next() as usize % 7);
        let states = (0..state_count)
            .map(|value| format!("S{value}"))
            .collect::<BTreeSet<_>>();
        let mut model = StateMachineModel {
            states: states.clone(),
            initial_state: Some("S0".into()),
            transitions: Vec::new(),
        };
        for step in 0..state_count * 2 {
            let from = format!("S{}", rng.next() as usize % state_count);
            let invalid = step == state_count * 2 - 1 && (rng.next() & 1) == 1;
            let to = if invalid {
                "MISSING".into()
            } else {
                format!("S{}", rng.next() as usize % state_count)
            };
            model.transitions.push(StateTransition {
                from,
                event: format!("e{step}"),
                to,
            });
        }
        let analysis = model.analyze();
        assert!(analysis.reachable.is_subset(&states));
        assert!(analysis.unreachable.is_subset(&states));
        for transition in &analysis.invalid_transitions {
            assert!(
                !states.contains(&transition.from) || !states.contains(&transition.to),
                "only transitions outside the declared state set may be invalid"
            );
        }
    }
}

fn concurrency_cases(seed: u64, iterations: usize) {
    let workers = iterations.min(8).max(1);
    let completed = AtomicUsize::new(0);
    thread::scope(|scope| {
        for worker in 0..workers {
            let completed = &completed;
            scope.spawn(move || {
                let mut index = worker;
                while index < iterations {
                    let case_seed = seed ^ (index as u64).wrapping_mul(0xd6e8feb86659fd93);
                    let tasks = scheduling_tasks(case_seed, 16);
                    let budget = ResourceBudget {
                        cpu_slots: 4,
                        memory_mb: 1024,
                        gpu_mb: 0,
                    };
                    let first = schedule_tasks(tasks.clone(), budget).expect("schedule first pass");
                    let second = schedule_tasks(tasks, budget).expect("schedule second pass");
                    assert_eq!(first, second, "scheduler must remain deterministic under load");
                    completed.fetch_add(1, Ordering::SeqCst);
                    index += workers;
                }
            });
        }
    });
    assert_eq!(completed.load(Ordering::SeqCst), iterations);
}

fn stress_cases(seed: u64, iterations: usize) {
    for index in 0..iterations {
        let tasks = scheduling_tasks(seed ^ index as u64, 64);
        let budget = ResourceBudget {
            cpu_slots: 8,
            memory_mb: 4096,
            gpu_mb: 0,
        };
        let batches = schedule_tasks(tasks.clone(), budget).expect("stress schedule");
        let scheduled = batches.iter().map(|batch| batch.tasks.len()).sum::<usize>();
        assert_eq!(scheduled, tasks.len());
        for batch in batches {
            assert!(batch.resources.cpu_slots <= budget.cpu_slots);
            assert!(batch.resources.memory_mb <= budget.memory_mb);
            assert!(batch.resources.gpu_mb <= budget.gpu_mb);
        }
    }
}

fn fault_cases(seed: u64, iterations: usize) {
    let root = temp_dir("fault");
    fs::create_dir_all(&root).expect("create fault root");
    let execution = ProcessExecutionAdapter;

    for index in 0..iterations {
        let snapshot = ContentAddress::from_bytes(
            format!("{seed}:{index}").as_bytes(),
        );
        let key = CacheKey::new(
            &snapshot,
            "self-fault",
            CheckKind::Build,
            VerificationLevel::Patch,
            1,
        );
        let cache_root = root.join(format!("cache-{index}"));
        fs::create_dir_all(&cache_root).expect("create cache root");
        let cache = FileVerificationCache::new(&cache_root);
        let cache_path = cache_root.join(format!("{}.vfcache", key.0.0));
        fs::write(&cache_path, "corrupt\ncache\npayload\n").expect("write corrupt cache");
        assert!(
            cache.get(&key).is_err(),
            "corrupt cache data must fail closed instead of becoming PASS evidence"
        );

        let model = StateMachineModel {
            states: ["ready".to_owned(), "done".to_owned()]
                .into_iter()
                .collect(),
            initial_state: Some("ready".into()),
            transitions: vec![StateTransition {
                from: "ready".into(),
                event: "fault".into(),
                to: format!("missing-{index}"),
            }],
        };
        assert_eq!(model.analyze().invalid_transitions.len(), 1);

        if index % 32 == 0 {
            let missing = format!("vf-definitely-missing-{seed:x}-{index}");
            assert!(
                execution.execute(&missing, &[], &root).is_err(),
                "process launch failures must be surfaced"
            );
        }
    }

    fs::remove_dir_all(root).ok();
}

fn resource_cases(seed: u64, iterations: usize) {
    let root = temp_dir("resource");
    fs::create_dir_all(&root).expect("create resource root");
    let before = fd_count();
    let mut cache = FileVerificationCache::new(root.join("cache"));

    for index in 0..iterations {
        let snapshot = ContentAddress::from_bytes(format!("{seed}:{index}").as_bytes());
        let key = CacheKey::new(
            &snapshot,
            "resource-self-check",
            CheckKind::Test,
            VerificationLevel::Commit,
            1,
        );
        let result = CheckResult::pass_with_evidence(
            "self:resource",
            format!("case={index} seed={seed:x}"),
        );
        cache.put(&key, &result).expect("cache put");
        let restored = cache.get(&key).expect("cache get").expect("cache hit");
        assert_eq!(restored.status, result.status);
        assert!(restored.has_reproducible_evidence());
    }

    drop(cache);
    let after = fd_count();
    if let (Some(before), Some(after)) = (before, after) {
        assert_eq!(
            after, before,
            "self-adversarial cache workload leaked file descriptors"
        );
    }
    fs::remove_dir_all(root).ok();
}

fn scheduling_tasks(seed: u64, count: usize) -> Vec<VerificationTask> {
    let mut rng = XorShift64::new(seed);
    (0..count)
        .map(|index| VerificationTask {
            id: format!("task-{seed:x}-{index}"),
            adapter_id: "self".into(),
            check: if index % 2 == 0 {
                CheckKind::Build
            } else {
                CheckKind::Test
            },
            resources: ResourceRequest {
                cpu_slots: 1 + (rng.next() as u16 % 2),
                memory_mb: 32 + (rng.next() % 224),
                gpu_mb: 0,
            },
        })
        .collect()
}

fn fd_count() -> Option<usize> {
    #[cfg(target_os = "linux")]
    {
        fs::read_dir("/proc/self/fd").ok().map(|entries| entries.count())
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn temp_dir(label: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos();
    env::temp_dir().join(format!(
        "verificationforge-self-{label}-{}-{nonce}",
        std::process::id()
    ))
}

fn seed_from_text(value: &str) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut hash = OFFSET;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash.max(1)
}

#[derive(Clone, Copy)]
struct XorShift64(u64);

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }
}
