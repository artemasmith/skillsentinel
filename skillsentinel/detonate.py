"""`--detonate`: run skill scripts in a disposable bwrap sandbox, record egress attempts.

Network isolation by default: the sandbox is built with --unshare-net, so no process
inside can open a connection — attempted tool egress (curl/wget/nc/ssh/...) is still
observed via PATH shims that log the destination. If the host bwrap cannot honor
--unshare-net, detonation is refused outright (never a live-egress fallback); the
caller reports it on stderr and exits 2. `allow_net=True` lifts the isolation
explicitly and stamps the report with a 'network NOT isolated' warning. If bwrap is
unavailable, detonation is skipped and reported as such.
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


class DetonationRefusedError(RuntimeError):
    """bwrap cannot guarantee network isolation — detonation must not run."""


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


def _bwrap_can_isolate_network(bwrap: str) -> bool:
    """Non-destructive preflight: can this bwrap build a --unshare-net sandbox?

    Runs /usr/bin/true in a throwaway sandbox with the same base binds the real
    detonation uses. Old bwrap builds reject the option outright ("unrecognized
    option", exit 1); any probe failure counts as "cannot isolate", so the caller
    refuses instead of running untrusted code with live egress.
    """
    try:
        proc = subprocess.run(
            [bwrap, "--unshare-net", *_base_bind_args(), "/usr/bin/true"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def detonate_file(path: Path, timeout: int = 10,
                  allow_net: bool = False) -> DetonationReport:
    bwrap = shutil.which("bwrap")
    if bwrap is None:
        return DetonationReport(
            file=str(path), executed=False, sandbox="none",
            notes=["bwrap not available — detonation skipped "
                   "(install bubblewrap to enable)"],
        )

    if not allow_net and not _bwrap_can_isolate_network(bwrap):
        raise DetonationRefusedError(
            f"{bwrap} does not support --unshare-net — detonation refused: "
            "a sandbox without network isolation would run untrusted code with "
            "real egress. Upgrade bubblewrap to a build with --unshare-net "
            "support, or pass --allow-net to explicitly accept a networked "
            "sandbox.")

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
        ]
        if not allow_net:
            cmd.append("--unshare-net")
        cmd += ["--die-with-parent", "--new-session"]
        if script_copy.suffix == ".py":
            cmd += ["python3", f"/work/{path.name}"]
        else:
            cmd += ["/bin/sh", f"/work/{path.name}"]

        env = {
            "PATH": "/shims:/usr/bin:/bin",
            "HOME": "/home/sandbox",
            "SANDBOX_NETLOG": "/netlog.txt",
        }
        timeout_note = None
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, env=env,
            )
            rc, out, err = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as e:
            # the sandbox was killed at the deadline — recorded as a warning,
            # never propagated: one runaway script must not end the run
            rc = None
            out = (e.stdout or "")
            out = out.decode() if isinstance(out, bytes) else out
            err = "detonation timed out"
            timeout_note = (f"detonation timed out after {timeout} s — the "
                            "script was killed; scanning continues")
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
        if allow_net:
            net_note = ("network NOT isolated (--allow-net): the sandbox shares "
                        "the host network — real egress is possible")
        else:
            net_note = ("network isolated (--unshare-net): no connection can be "
                        "opened from inside the sandbox")
        notes = [net_note,
                 "attempted tool egress is logged via PATH shims "
                 "(curl/wget/nc/ssh/...)"]
        if timeout_note is not None:
            notes.append(timeout_note)
        return DetonationReport(
            file=str(path), executed=True, sandbox="bwrap",
            exit_code=rc, stdout_tail=o, stderr_tail=e2,
            network_attempts=attempts,
            notes=notes,
        )


def detonate_tree(root: Path, allow_net: bool = False,
                  timeout: int = 10) -> list[DetonationReport]:
    return [detonate_file(p, timeout=timeout, allow_net=allow_net)
            for p in find_scripts(root)]
