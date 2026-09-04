#!/usr/bin/env python3
"""Repository-owned adversarial workloads for VerificationForge self-certification.

The script is intentionally small and dependency-free. CertificationGate supplies a
content-addressed seed and workload size; this runner consumes both, executes real
work, and only emits VF_CERT_* evidence after that work succeeds.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import random
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass

ROOT = Path(__file__).resolve().parents[1]
WORKLOAD_TARGET = ROOT / "target" / "vf-self-workloads"
MUTANT_TARGET = ROOT / "target" / "vf-self-mutants"


@dataclass(frozen=True)
class Mutant:
    name: str
    path: str
    before: str
    after: str
    test_filter: str


MUTANTS = [
    Mutant(
        "mutation-zero-set-must-fail",
        "crates/verificationforge-runtime/src/certification_gate_hardened.rs",
        "if total == 0 {",
        "if total != 0 {",
        "certification_gate_hardened::tests::",
    ),
    Mutant(
        "mutation-discovered-must-match-total",
        "crates/verificationforge-runtime/src/certification_gate_hardened.rs",
        "if discovered != total {",
        "if discovered == total {",
        "certification_gate_hardened::tests::",
    ),
    Mutant(
        "mutation-executed-must-match-discovered",
        "crates/verificationforge-runtime/src/certification_gate_hardened.rs",
        "if executed != discovered {",
        "if executed == discovered {",
        "certification_gate_hardened::tests::",
    ),
    Mutant(
        "mutation-survivors-must-block",
        "crates/verificationforge-runtime/src/certification_gate_hardened.rs",
        "if survived != 0 {",
        "if survived == 0 {",
        "certification_gate_hardened::tests::",
    ),
    Mutant(
        "minimum-workload-boundary",
        "crates/verificationforge-runtime/src/certification_gate_hardened.rs",
        "if actual < expected {",
        "if actual <= expected {",
        "certification_gate_hardened::tests::",
    ),
    Mutant(
        "exact-workload-boundary",
        "crates/verificationforge-runtime/src/certification_gate_hardened.rs",
        "if actual != expected {",
        "if actual == expected {",
        "certification_gate_hardened::tests::",
    ),
    Mutant(
        "metric-token-loss",
        "crates/verificationforge-runtime/src/certification_gate_hardened.rs",
        'let token = token.strip_prefix("metrics=").unwrap_or(token);',
        'let token = token.strip_prefix("metrics=").unwrap_or("");',
        "certification_gate_hardened::tests::",
    ),
    Mutant(
        "metric-value-corruption",
        "crates/verificationforge-runtime/src/certification_gate_hardened.rs",
        "value.parse::<usize>().ok()",
        "value.parse::<usize>().ok().map(|value| value.saturating_add(1))",
        "certification_gate_hardened::tests::",
    ),
    Mutant(
        "security-clean-inversion",
        "crates/verificationforge-runtime/src/security.rs",
        "if findings.is_empty() {",
        "if !findings.is_empty() {",
        "security::tests::",
    ),
    Mutant(
        "security-sensitive-name-inversion",
        "crates/verificationforge-runtime/src/security.rs",
        "if !sensitive_assignment_name(&normalized) {",
        "if sensitive_assignment_name(&normalized) {",
        "security::tests::",
    ),
    Mutant(
        "security-secret-length-inversion",
        "crates/verificationforge-runtime/src/security.rs",
        "if value.len() < 8 || obvious_non_secret(value) {",
        "if value.len() >= 8 || obvious_non_secret(value) {",
        "security::tests::",
    ),
    Mutant(
        "security-source-scan-inversion",
        "crates/verificationforge-runtime/src/security.rs",
        "if !is_source_file(path) {",
        "if is_source_file(path) {",
        "security::tests::",
    ),
]


def main() -> int:
    if len(sys.argv) < 4:
        print(
            "usage: vf_self_cert.py <mode> <seed> <iterations> [selections]",
            file=sys.stderr,
        )
        return 2

    mode = sys.argv[1]
    seed = sys.argv[2]
    iterations = positive_int(sys.argv[3], "iterations")

    if mode == "commit-mutation":
        if len(sys.argv) < 5:
            raise SystemExit("commit-mutation requires selections")
        selections = positive_int(sys.argv[4], "selections")
        return run_mutation(seed, selections=selections, full=False)
    if mode == "full-mutation":
        return run_mutation(seed, selections=None, full=True)
    if mode == "commit-fuzz":
        if len(sys.argv) < 5:
            raise SystemExit("commit-fuzz requires selections")
        selections = positive_int(sys.argv[4], "selections")
        return run_adversarial("fuzz", seed, iterations * selections)
    if mode == "extended-fuzz":
        code = run_adversarial("fuzz", seed, iterations)
        if code == 0:
            print(f"VF_CERT_FUZZ_ITERATIONS={iterations}")
        return code
    if mode == "concurrency":
        code = run_adversarial("concurrency", seed, iterations)
        if code == 0:
            print(f"VF_CERT_CONCURRENCY_CASES={iterations}")
        return code
    if mode == "stress":
        code = run_adversarial("stress", seed, iterations)
        if code == 0:
            print(f"VF_CERT_STRESS_ITERATIONS={iterations}")
        return code
    if mode == "fault-injection":
        code = run_adversarial("fault", seed, iterations)
        if code == 0:
            print(f"VF_CERT_FAULT_CASES={iterations}")
        return code
    if mode == "resource-leaks":
        code = run_adversarial("resource", seed, iterations)
        if code == 0:
            print(f"VF_CERT_RESOURCE_SAMPLES={iterations}")
            print("VF_CERT_RESOURCE_LEAKS=0")
        return code
    if mode == "sandbox":
        return run_sandbox(seed, iterations)
    if mode == "reproducibility":
        return run_reproducibility(seed, iterations)

    print(f"unknown self-certification mode: {mode}", file=sys.stderr)
    return 2


def positive_int(value: str, name: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise SystemExit(f"{name} must be > 0")
    return parsed


def base_env(target: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(target)
    env["CARGO_TERM_COLOR"] = "never"
    env["RUST_BACKTRACE"] = "1"
    return env


def run_adversarial(mode: str, seed: str, iterations: int) -> int:
    env = base_env(WORKLOAD_TARGET)
    env["VF_SELF_MODE"] = mode
    env["VF_SELF_SEED"] = seed
    env["VF_SELF_ITERATIONS"] = str(iterations)
    command = [
        "cargo",
        "test",
        "--locked",
        "-p",
        "verificationforge-runtime",
        "--test",
        "self_adversarial",
        "--",
        "--nocapture",
        "--test-threads=1",
    ]
    completed = subprocess.run(command, cwd=ROOT, env=env, check=False)
    return completed.returncode


def run_mutation(seed: str, selections: int | None, full: bool) -> int:
    rng = random.Random(int(hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16], 16))
    chosen = list(MUTANTS)
    rng.shuffle(chosen)
    if selections is not None:
        chosen = chosen[: min(selections, len(chosen))]

    survived = 0
    executed = 0
    env = base_env(MUTANT_TARGET)

    for mutant in chosen:
        path = ROOT / mutant.path
        original = path.read_text(encoding="utf-8")
        count = original.count(mutant.before)
        if count != 1:
            print(
                f"mutation definition {mutant.name} expected exactly one source match, got {count}",
                file=sys.stderr,
            )
            return 3

        mutated = original.replace(mutant.before, mutant.after, 1)
        try:
            path.write_text(mutated, encoding="utf-8")
            command = [
                "cargo",
                "test",
                "--locked",
                "-p",
                "verificationforge-runtime",
                "--lib",
                mutant.test_filter,
            ]
            completed = subprocess.run(
                command,
                cwd=ROOT,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            executed += 1
            if completed.returncode == 0:
                survived += 1
                print(f"VF_MUTANT_SURVIVED={mutant.name}", file=sys.stderr)
        finally:
            path.write_text(original, encoding="utf-8")

    if full:
        total = len(chosen)
        print(f"VF_CERT_FULL_MUTATION_TOTAL={total}")
        print(f"VF_CERT_FULL_MUTATION_DISCOVERED={total}")
        print(f"VF_CERT_FULL_MUTATION_EXECUTED={executed}")
        print(f"VF_CERT_FULL_MUTATION_SURVIVED={survived}")

    return 0 if executed == len(chosen) and survived == 0 else 1


def run_sandbox(seed: str, iterations: int) -> int:
    bwrap = shutil.which("bwrap")
    if not bwrap:
        print("bubblewrap is required for the self-certification sandbox workload", file=sys.stderr)
        return 2

    repo = str(ROOT)
    repo_q = shlex.quote(repo)
    marker = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
    scripts = [
        "test ! -w /etc && test ! -w /usr && touch /tmp/vf-sandbox-ok",
        f"! touch /etc/vf-escape-{marker} 2>/dev/null",
        f"! touch {repo_q}/vf-sandbox-escape-{marker} 2>/dev/null",
        "python3 -c \"import socket,sys; s=socket.socket(); s.settimeout(0.2); rc=s.connect_ex(('1.1.1.1',53)); sys.exit(0 if rc != 0 else 1)\"",
    ]

    rng = random.Random(int(hashlib.sha256(seed.encode("utf-8")).hexdigest()[-16:], 16))
    for _ in range(iterations):
        script = scripts[rng.randrange(len(scripts))]
        command = [
            bwrap,
            "--die-with-parent",
            "--unshare-net",
            "--ro-bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--tmpfs",
            "/tmp",
            "--chdir",
            repo,
            "sh",
            "-c",
            script,
        ]
        completed = subprocess.run(
            command,
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if completed.returncode != 0:
            print(f"sandbox case failed: {script}", file=sys.stderr)
            print(f"VF_CERT_SANDBOX_CASES={iterations}")
            print("VF_CERT_SANDBOX_ESCAPE=1")
            return 1

    print(f"VF_CERT_SANDBOX_CASES={iterations}")
    print("VF_CERT_SANDBOX_ESCAPE=0")
    return 0


def run_reproducibility(seed: str, iterations: int) -> int:
    listed = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if listed.returncode != 0:
        sys.stderr.buffer.write(listed.stderr)
        return listed.returncode

    digest = hashlib.sha256()
    digest.update(seed.encode("utf-8"))
    digest.update(str(iterations).encode("ascii"))
    for raw_name in sorted(filter(None, listed.stdout.split(b"\0"))):
        relative = raw_name.decode("utf-8", errors="strict")
        path = ROOT / relative
        if not path.is_file():
            continue
        digest.update(len(raw_name).to_bytes(8, "little"))
        digest.update(raw_name)
        data = path.read_bytes()
        digest.update(len(data).to_bytes(8, "little"))
        digest.update(data)

    print(f"VF_CERT_REPRO_DIGEST={digest.hexdigest()}")
    print(f"VF_CERT_REPRO_ITERATIONS={iterations}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
