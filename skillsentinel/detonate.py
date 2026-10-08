"""`--detonate`: run skill scripts in a disposable bwrap sandbox, record egress attempts.

Honest fallback: if bwrap is unavailable, detonation is skipped and reported as such.
Egress observation intercepts common network tools (curl/wget/nc/ssh/...) via PATH
shims that log the destination. Raw-socket traffic is NOT blocked: the sandbox shares
the host network, so the report records observed attempts, not a guarantee.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field, asdict
from pathlib import Path

NETLOG_HELPER = r"""#!/usr/bin/env python3
import sys, os
log = os.environ.get("SANDBOX_NETLOG", "/netlog.txt")
with open(log, "a") as f:
    f.write(sys.argv[0].rsplit("/", 1)[-1] + " " + " ".join(sys.argv[1:]) + "\n")
sys.exit(7)
"""

SHIM_TOOLS = ("curl", "wget", "nc", "ncat", "ping", "telnet", "ssh", "scp", "ftp", "dig")


@dataclass
class DetonationReport:
    file: str
    executed: bool
    sandbox: str
    exit_code: int | None = None
    stdout_tail: str = ""
    stderr_tail: str = ""
    network_attempts: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _tails(out: str, err: str, n: int = 500) -> tuple[str, str]:
    return out[-n:], err[-n:]


def find_scripts(root: Path) -> list[Path]:
    scripts = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue
        if p.suffix in (".sh", ".py", ".bash") or p.name == "install":
            scripts.append(p)
    return scripts


def _base_bind_args() -> list[str]:
    """Bind the minimal read-only host dirs needed to run python/sh."""
    args = []
    for d in ("/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc/alternatives"):
        if Path(d).exists():
            args += ["--ro-bind", d, d]
    return args


def detonate_file(path: Path, timeout: int = 10) -> DetonationReport:
    bwrap = shutil.which("bwrap")
    if bwrap is None:
        return DetonationReport(
            file=str(path), executed=False, sandbox="none",
            notes=["bwrap not available — detonation skipped "
                   "(install bubblewrap to enable)"],
        )

    with tempfile.TemporaryDirectory(prefix="ssdet_") as tmp:
        tmpdir = Path(tmp)
        netlog = tmpdir / "netlog.txt"
        netlog.touch()
        work = tmpdir / "work"
        work.mkdir()
        home = tmpdir / "home"
        home.mkdir()
        script_copy = work / path.name
        script_copy.write_bytes(path.read_bytes())
        if script_copy.suffix in (".sh", ".bash") or script_copy.name == "install":
            script_copy.chmod(0o755)

        shims = tmpdir / "shims"
        shims.mkdir()
        for tool in SHIM_TOOLS:
            f = shims / tool
            f.write_text(NETLOG_HELPER)
            f.chmod(0o755)

        cmd = [
            bwrap,
            *_base_bind_args(),
            "--proc", "/proc",
            "--dev", "/dev",
            "--tmpfs", "/tmp",
            "--ro-bind", str(work), "/work",
            "--ro-bind", str(shims), "/shims",
            "--bind", str(home), "/home/sandbox",
            "--bind", str(netlog), "/netlog.txt",
            "--chdir", "/work",
            "--die-with-parent",
            "--new-session",
        ]
        if script_copy.suffix == ".py":
            cmd += ["python3", f"/work/{path.name}"]
        else:
            cmd += ["/bin/sh", f"/work/{path.name}"]

        env = {
            "PATH": "/shims:/usr/bin:/bin",
            "HOME": "/home/sandbox",
            "SANDBOX_NETLOG": "/netlog.txt",
        }
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, env=env,
            )
            rc, out, err = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as e:
            rc = None
            out = (e.stdout or "")
            out = out.decode() if isinstance(out, bytes) else out
            err = "detonation timed out"
        except OSError as e:
            return DetonationReport(
                file=str(path), executed=False, sandbox="bwrap",
                notes=[f"failed to launch bwrap: {e}"],
            )

        try:
            attempts = [l for l in netlog.read_text().splitlines() if l.strip()]
        except OSError:
            attempts = []

        o, e2 = _tails(out, err)
        return DetonationReport(
            file=str(path), executed=True, sandbox="bwrap",
            exit_code=rc, stdout_tail=o, stderr_tail=e2,
            network_attempts=attempts,
            notes=["egress observed via PATH shims (curl/wget/nc/ssh/...); "
                   "raw-socket egress is not intercepted"],
        )


def detonate_tree(root: Path) -> list[DetonationReport]:
    return [detonate_file(p) for p in find_scripts(root)]
