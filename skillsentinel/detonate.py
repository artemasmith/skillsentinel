"""`--detonate`: run skill scripts in a disposable bwrap sandbox, record egress attempts.

Network isolation by default: the sandbox is built with --unshare-net, so no process
inside can open a connection — attempted tool egress (curl/wget/nc/ssh/...) is still
observed via PATH shims that log the destination. The sandbox also gets its own PID
namespace (--unshare-pid): killing the bwrap supervisor at a detonation timeout takes
the whole sandbox tree down with it, so a payload cannot survive as a host orphan.
The capability preflight runs in every mode: if the host bwrap cannot honor the unshare
options the mode relies on (--unshare-net and --unshare-pid; only --unshare-pid under
`allow_net=True`), detonation is refused outright (never a live-egress or
leaky-process-tree fallback); the caller reports it on stderr and exits 2.
`allow_net=True` lifts the network isolation explicitly and stamps the report with a
'network NOT isolated' warning. If bwrap is unavailable, detonation is skipped and
reported as such.
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

# What counts as a detonatable script (V7: a .js miner or an SS044 PowerShell
# cradle must detonate too, not only shell/python). Everything else — prose,
# configs, data — stays untouched.
SCRIPT_SUFFIXES = (".sh", ".bash", ".py", ".js", ".rb", ".pl", ".ps1")
# Interpreter per suffix; shell scripts (and files named `install`) run under
# /bin/sh. A missing interpreter (e.g. no pwsh on the host) surfaces honestly
# as a non-zero exit in the report, never as a silent skip.
INTERPRETERS = {".py": "python3", ".js": "node", ".rb": "ruby",
                ".pl": "perl", ".ps1": "pwsh"}


class DetonationRefusedError(RuntimeError):
    """bwrap cannot guarantee sandbox isolation — detonation must not run."""


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
    # A single script file is a valid target too (V6): `scan tool.sh
    # --detonate` used to rglob the file's (nonexistent) children and print a
    # silent "(0 scripts)".
    candidates = [root] if root.is_file() else sorted(root.rglob("*"))
    scripts = []
    for p in candidates:
        if not p.is_file() or p.is_symlink():
            continue
        if p.suffix in SCRIPT_SUFFIXES or p.name == "install":
            scripts.append(p)
    return scripts


def _base_bind_args() -> list[str]:
    """Bind the minimal read-only host dirs needed to run python/sh."""
    args = []
    for d in ("/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc/alternatives"):
        if Path(d).exists():
            args += ["--ro-bind", d, d]
    return args


def _bwrap_capability_probe(bwrap: str, flags: list[str]) -> tuple[bool, str]:
    """Non-destructive preflight: can this bwrap build the sandbox we need?

    Runs /usr/bin/true once in a throwaway sandbox with `flags` — the unshare
    options the caller's mode relies on: --unshare-net (no egress from the
    sandbox) and --unshare-pid (the payload dies with the bwrap supervisor, so
    a timeout cannot leave it running as a host orphan) — plus the same base
    binds the real detonation uses. Old bwrap builds reject the options
    outright ("unrecognized option", exit 1); any probe failure counts as
    "cannot isolate", so the caller refuses instead of running untrusted code
    with live egress or a leaking process tree. Returns (ok, detail), where
    detail carries the probe's stderr (or launch failure) so the refusal
    message can name the flag that was missing.
    """
    try:
        proc = subprocess.run(
            [bwrap, *flags, *_base_bind_args(), "/usr/bin/true"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, f"probe did not complete: {e}"
    return proc.returncode == 0, (proc.stderr or "").strip()


def detonate_file(path: Path, timeout: int | None = 10,
                  allow_net: bool = False) -> DetonationReport:
    bwrap = shutil.which("bwrap")
    if bwrap is None:
        return DetonationReport(
            file=str(path), executed=False, sandbox="none",
            notes=["bwrap not available — detonation skipped "
                   "(install bubblewrap to enable)"],
        )

    # preflight in every mode: a detonation timeout must never leave payload
    # processes on the host, so --unshare-pid is probed (and required) even
    # when network isolation is lifted; --unshare-net is probed alongside it
    # only in the mode that actually uses it
    probe_flags = (["--unshare-pid"] if allow_net
                   else ["--unshare-net", "--unshare-pid"])
    capable, detail = _bwrap_capability_probe(bwrap, probe_flags)
    if not capable:
        detail_note = f" Probe said: {detail}" if detail else ""
        if allow_net:
            raise DetonationRefusedError(
                f"{bwrap} does not support --unshare-pid — detonation "
                "refused: without its own PID namespace a detonation timeout "
                "can leave payload processes running on the host, and "
                "--allow-net lifts only the network guarantee, not this one. "
                f"Upgrade bubblewrap to a build with --unshare-pid support."
                f"{detail_note}")
        raise DetonationRefusedError(
            f"{bwrap} does not support --unshare-net/--unshare-pid — "
            "detonation refused: without them the sandbox would run untrusted "
            "code with real egress and a detonation timeout could leave "
            "payload processes running on the host. Upgrade bubblewrap to a "
            "build with --unshare-net and --unshare-pid support, or pass "
            f"--allow-net to explicitly accept a networked sandbox."
            f"{detail_note}")

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
        # own PID namespace: when the bwrap supervisor is killed at a timeout,
        # the kernel tears down the whole sandbox tree — without it the payload
        # would outlive the monitor as an orphan host process
        cmd += ["--unshare-pid", "--die-with-parent", "--new-session"]
        # interpreter by suffix; anything unlisted (a git hook, `install`)
        # keeps the historical default of running under /bin/sh
        interp = INTERPRETERS.get(script_copy.suffix, "/bin/sh")
        cmd += [interp, f"/work/{path.name}"]

        env = {
            "PATH": "/shims:/usr/bin:/bin",
            "HOME": "/home/sandbox",
            "SANDBOX_NETLOG": "/netlog.txt",
        }
        timeout_note = None
        run_kwargs: dict = {"capture_output": True, "text": True, "env": env}
        if timeout is not None and timeout > 0:
            run_kwargs["timeout"] = timeout
        try:
            proc = subprocess.run(cmd, **run_kwargs)
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
                  timeout: int | None = 10) -> list[DetonationReport]:
    return [detonate_file(p, timeout=timeout, allow_net=allow_net)
            for p in find_scripts(root)]
