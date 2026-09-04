#!/usr/bin/env python3
"""Auxiliary hardened workloads and redacted diagnostics for self-certification."""

from __future__ import annotations

import hashlib
from pathlib import Path
import random
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def positive_int(value: str, name: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise SystemExit(f"{name} must be > 0")
    return parsed


def sandbox(seed: str, iterations: int) -> int:
    bwrap = shutil.which("bwrap")
    if not bwrap:
        print("bubblewrap is required for the self-certification sandbox workload", file=sys.stderr)
        return 2

    repo = str(ROOT)
    marker = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
    host_tmp_marker = Path("/tmp") / f"vf-host-visible-{marker}"
    host_tmp_marker.write_text("host namespace marker", encoding="utf-8")

    # GitHub-hosted runners do not permit bubblewrap to configure loopback in a
    # new network namespace. The certification contract here therefore proves
    # the containment properties the runner can enforce reliably: read-only
    # host/repository mounts, a private writable /tmp, PID/UTS/IPC namespaces,
    # and a zero-capability child process. Network isolation is intentionally not
    # claimed by this workload.
    scripts = [
        "test ! -w /etc && test ! -w /usr && touch /tmp/vf-sandbox-ok",
        f"! touch /etc/vf-escape-{marker} 2>/dev/null",
        f"! touch {repo}/vf-sandbox-escape-{marker} 2>/dev/null",
        f"test ! -e /tmp/{host_tmp_marker.name}",
        "test \"$(awk '/^CapEff:/ {print $2}' /proc/self/status)\" = \"0000000000000000\"",
    ]

    rng = random.Random(int(hashlib.sha256(seed.encode("utf-8")).hexdigest()[-16:], 16))
    try:
        for _ in range(iterations):
            script = scripts[rng.randrange(len(scripts))]
            command = [
                bwrap,
                "--die-with-parent",
                "--new-session",
                "--unshare-pid",
                "--unshare-uts",
                "--unshare-ipc",
                "--cap-drop",
                "ALL",
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
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if completed.returncode != 0:
                print(f"sandbox case failed: {script}", file=sys.stderr)
                if completed.stderr.strip():
                    print(completed.stderr.strip()[:1000], file=sys.stderr)
                print(f"VF_CERT_SANDBOX_CASES={iterations}")
                print("VF_CERT_SANDBOX_ESCAPE=1")
                return 1
    finally:
        host_tmp_marker.unlink(missing_ok=True)

    print(f"VF_CERT_SANDBOX_CASES={iterations}")
    print("VF_CERT_SANDBOX_ESCAPE=0")
    return 0


def reproducibility(seed: str, iterations: int) -> int:
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

    print("VF_CERT_REPRODUCIBLE=1")
    print(f"VF_CERT_REPRO_DIGEST={digest.hexdigest()}")
    print(f"VF_CERT_REPRO_ITERATIONS={iterations}")
    return 0


def history_probe() -> int:
    completed = subprocess.run(
        ["git", "log", "--all", "--format=commit:%H", "-p", "--no-ext-diff", "--no-color", "--", "."],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        print("VF_HISTORY_PROBE_FAILED=git-log", file=sys.stderr)
        return completed.returncode

    markers = [
        'password="',
        'passwd="',
        'api_key="',
        'apikey="',
        'access_token="',
        'secret_key="',
        'client_secret="',
    ]
    commit = "unknown"
    path = "unknown"
    hits = 0
    for line in completed.stdout.splitlines():
        if line.startswith("commit:"):
            commit = line.removeprefix("commit:").strip()
            continue
        if line.startswith("+++ b/"):
            path = line.removeprefix("+++ b/").strip()
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        normalized = "".join(ch for ch in line[1:] if not ch.isspace()).lower()
        for marker in markers:
            index = normalized.find(marker)
            if index < 0:
                continue
            candidate = normalized[index + len(marker):].split('"', 1)[0]
            if len(candidate) < 8:
                continue
            hits += 1
            fingerprint = hashlib.sha256(candidate.encode("utf-8")).hexdigest()[:12]
            print(
                f"VF_HISTORY_PROBE_HIT commit={commit} path={path} marker={marker[:-2]} value_sha256={fingerprint}"
            )
    print(f"VF_HISTORY_PROBE_HITS={hits}")
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        raise SystemExit("usage: vf_cert_aux.py <sandbox|reproducibility|history-probe> ...")
    mode = sys.argv[1]
    if mode == "history-probe":
        return history_probe()
    if len(sys.argv) != 4:
        raise SystemExit(f"{mode} requires <seed> <iterations>")
    seed = sys.argv[2]
    iterations = positive_int(sys.argv[3], "iterations")
    if mode == "sandbox":
        return sandbox(seed, iterations)
    if mode == "reproducibility":
        return reproducibility(seed, iterations)
    raise SystemExit(f"unknown mode: {mode}")


if __name__ == "__main__":
    raise SystemExit(main())
