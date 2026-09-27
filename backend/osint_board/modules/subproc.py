"""Run sandboxed external scanners (the ``tool_*`` catalog modules).

Every tool module builds an argv, runs the binary with :func:`run_tool` (an async subprocess with a timeout),
and hands the captured output to a **pure** ``parse_*`` function — the same "emit, never persist" contract as
HTTP-driven modules, so a fixture plus the parser exercises each tool offline. Lookup tests monkeypatch
``run_tool``; parser tests never spawn a process.

Binaries resolve on ``PATH``; deployment installs them into the tools worker image
(``deploy/docker/tools.Dockerfile``). A missing binary raises :class:`ToolNotFound` (a configuration error the
run records), a timed-out scan raises :class:`ToolTimeout`; modules usually catch the timeout and treat it as
"no findings" while letting a missing binary fail the run.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import signal
from collections.abc import Sequence
from dataclasses import dataclass

#: Every platform setting — module API keys (``OSINT_MODULE_*``), the database and redis URLs — lives under this
#: env prefix (see ``config.Settings``), so a scanner subprocess is given the environment with it stripped out.
_SECRET_ENV_PREFIX = "OSINT_"


class ToolError(RuntimeError):
    """The external binary cannot be run for some reason; see subclasses."""


class ToolNotFound(ToolError):
    """The binary (argv[0]) is not on ``PATH`` — install the tools worker image."""


class ToolTimeout(ToolError):
    """The scan ran past its timeout; partial output is discarded."""


@dataclass(slots=True)
class ToolResult:
    argv: list[str]
    stdout: str
    stderr: str
    returncode: int | None


def as_scan_target(value: str) -> str:
    """A positional scan target that cannot be mistaken for an option flag.

    argv is handed to :func:`asyncio.create_subprocess_exec` (never a shell), so the one injection vector left is
    a target whose value *is* a flag — a scanner would parse ``-oN`` / ``--script`` as its own switch rather than
    a host to scan. A real IP, CIDR or hostname never starts with ``-`` (the entity detector forbids it), so a
    value that does is refused rather than passed through as a positional."""
    if value.startswith("-"):
        raise ToolError(f"refusing a flag-like scan target {value!r}")
    return value


def _child_env(env: dict[str, str] | None) -> dict[str, str]:
    """The environment a scanner subprocess runs with: the caller's explicit ``env`` if given, otherwise the
    worker's environment with every ``OSINT_`` (secret-bearing) variable removed. Third-party binaries — and
    CMSeeK's own Python — never need the platform's API keys or database URL, and must not be able to read them."""
    if env is not None:
        return env
    return {k: v for k, v in os.environ.items() if not k.startswith(_SECRET_ENV_PREFIX)}


async def run_tool(
    argv: Sequence[str],
    *,
    timeout: float = 900.0,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
    max_bytes: int = 64 << 20,
) -> ToolResult:
    """Run ``argv`` to completion; the returned stdout/stderr are each truncated to ``max_bytes`` bytes.

    Returns the result whatever the exit code — scanners report findings with non-zero exits all the time,
    and the module's parser decides what the output means. The child runs with the platform's secrets stripped
    from its environment (:func:`_child_env`) in its own session, so a timeout reaps any grandchildren it spawned
    (e.g. testssl.sh's ``openssl`` calls). ``max_bytes`` bounds what is decoded and returned, not the scanner's
    own peak memory; a runaway process is bounded by the tools container's memory limit.
    """
    argv = list(argv)
    binary = shutil.which(argv[0])
    if binary is None:
        raise ToolNotFound(f"{argv[0]!r} is not on PATH (the tools worker image installs it)")
    argv[0] = binary
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_child_env(env),
            cwd=cwd,
            start_new_session=True,  # own process group, so a timeout can reap the scanner's children too
        )
    except OSError as exc:
        raise ToolError(f"cannot start {binary!r}: {exc}") from exc
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout)
    except TimeoutError:
        _kill_group(proc)
        with contextlib.suppress(ProcessLookupError):  # pragma: no cover - race on exit
            await proc.wait()
        raise ToolTimeout(f"{argv[0]!r} timed out after {timeout:.0f}s") from None
    except asyncio.CancelledError:
        # The job was cancelled out from under us (arq's own job deadline, a worker shutdown): SIGKILL the group
        # so the scanner and its children do not outlive the job. asyncio's child watcher reaps the zombie; we
        # re-raise at once rather than await, which under cancellation could hang or re-raise before the kill.
        _kill_group(proc)
        raise
    return ToolResult(
        argv=argv,
        stdout=stdout[:max_bytes].decode("utf-8", errors="replace"),
        stderr=stderr[:max_bytes].decode("utf-8", errors="replace"),
        returncode=proc.returncode,
    )


def _kill_group(proc: asyncio.subprocess.Process) -> None:
    """SIGKILL the child's whole process group (it leads its own session), falling back to the direct child if
    the group is already gone — so a scanner that forked helpers does not leave orphans behind on a timeout."""
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    with contextlib.suppress(ProcessLookupError):
        proc.kill()
