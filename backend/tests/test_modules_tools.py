"""Phase-2 external-scanner modules (the ``tool_*`` catalog entries).

Offline contract (docs/03-module-framework.md, CLAUDE.md): every tool has a pure ``parse_*`` exercised against a
captured-output fixture, and the ``lookup`` path is driven by monkeypatching :func:`osint_board.modules.subproc.run_tool`
— no process is ever spawned. Authorisation-gated tools are checked both ways (refused passively, allowed in scope).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from osint_board.entities.types import EntityType
from osint_board.modules import subproc
from osint_board.modules.base import AuthorizationError, Scope
from osint_board.modules.impl.tool_cmseek import parse_cmseek_json
from osint_board.modules.impl.tool_nbtscan import parse_nbtscan
from osint_board.modules.impl.tool_nmap import parse_nmap_xml
from osint_board.modules.impl.tool_nuclei import parse_nuclei_jsonl
from osint_board.modules.impl.tool_onesixtyone import parse_onesixtyone
from osint_board.modules.impl.tool_snallygaster import parse_snallygaster
from osint_board.modules.impl.tool_testssl import parse_testssl_json
from osint_board.modules.impl.tool_wafw00f import parse_wafw00f_json
from osint_board.modules.impl.tool_whatweb import parse_whatweb_json
from osint_board.modules.types import EntityRef

TOOLS = Path(__file__).parent / "fixtures" / "tools"


def _read(name: str) -> str:
    return (TOOLS / name).read_text()


def _by_type(emits, etype: EntityType):
    return [e for e in emits if e.type is etype]


def patch_run_tool(monkeypatch, *, stdout: str = "", stderr: str = "", writes: dict[str, str] | None = None):
    """Replace ``subproc.run_tool`` with a coroutine that returns canned output and, for tools that read a file
    the binary writes, drops fixture content at the path following a flag in argv (``writes={flag: content}``)."""

    async def _fake(argv, *, timeout=900.0, env=None, cwd=None, max_bytes=64 << 20):  # noqa: ANN001
        argv = list(argv)
        for flag, content in (writes or {}).items():
            if flag in argv:
                Path(argv[argv.index(flag) + 1]).write_text(content)
        return subproc.ToolResult(argv=argv, stdout=stdout, stderr=stderr, returncode=0)

    monkeypatch.setattr(subproc, "run_tool", _fake)


def patch_timeout(monkeypatch):
    async def _fake(argv, **kwargs):  # noqa: ANN001
        raise subproc.ToolTimeout("boom")

    monkeypatch.setattr(subproc, "run_tool", _fake)


# ---- nmap --------------------------------------------------------------------------------------------------------


def test_parse_nmap_xml_open_ports_software_and_os():
    target = EntityRef(EntityType.IP, "203.0.113.10")
    emits = parse_nmap_xml(_read("nmap.xml"), target)
    ports = {e.value for e in _by_type(emits, EntityType.OPEN_PORT)}
    assert ports == {"203.0.113.10:22", "203.0.113.10:80"}  # the closed 443 is dropped, the down host skipped
    software = {e.value for e in _by_type(emits, EntityType.SOFTWARE)}
    assert software == {"OpenSSH 8.9p1 Ubuntu 3ubuntu0.4", "nginx 1.18.0"}
    os_match = _by_type(emits, EntityType.OPERATING_SYSTEM)
    assert len(os_match) == 1 and os_match[0].value == "Linux 5.4 - 5.15"
    assert os_match[0].confidence == pytest.approx(0.96)  # best osmatch accuracy


def test_parse_nmap_xml_tolerates_banner_before_xml():
    xml = "Starting Nmap 7.94\n" + _read("nmap.xml")
    assert parse_nmap_xml(xml, EntityRef(EntityType.IP, "203.0.113.10"))
    assert parse_nmap_xml("not xml at all", EntityRef(EntityType.IP, "x")) == []


async def test_nmap_lookup_is_authorisation_gated(registry, monkeypatch):
    patch_run_tool(monkeypatch, stdout=_read("nmap.xml"))
    target = EntityRef(EntityType.IP, "203.0.113.10")

    passive = registry.instantiate("tool_nmap", scope=Scope(allow_active=False))
    with pytest.raises(AuthorizationError):
        [e async for e in passive.lookup(target)]

    scoped = registry.instantiate("tool_nmap", scope=Scope(allow_active=True, targets=["203.0.113.0/24"]))
    emits = [e async for e in scoped.lookup(target)]
    assert {e.type for e in emits} <= set(scoped.spec.produces)
    assert any(e.type is EntityType.OPEN_PORT for e in emits)


async def test_nmap_lookup_timeout_is_no_findings(registry, monkeypatch):
    patch_timeout(monkeypatch)
    mod = registry.instantiate("tool_nmap", scope=Scope(allow_active=True))
    assert [e async for e in mod.lookup(EntityRef(EntityType.IP, "203.0.113.10"))] == []


# ---- nuclei ------------------------------------------------------------------------------------------------------


def test_parse_nuclei_jsonl_one_vuln_per_finding_with_severity_confidence():
    target = EntityRef(EntityType.URL, "https://target.example")
    emits = parse_nuclei_jsonl(_read("nuclei.jsonl"), target)
    assert all(e.type is EntityType.VULNERABILITY for e in emits)
    assert len(emits) == 3  # three JSON lines; the two non-JSON banners are ignored
    crit = next(e for e in emits if "CVE-2021-44228" in e.value)
    assert crit.confidence == 1.0 and crit.meta["cve"] == ["CVE-2021-44228"]
    assert min(e.confidence for e in emits) < crit.confidence  # info/low rank below critical


async def test_nuclei_lookup_gated_and_filtered(registry, monkeypatch):
    patch_run_tool(monkeypatch, stdout=_read("nuclei.jsonl"))
    target = EntityRef(EntityType.URL, "https://target.example")
    with pytest.raises(AuthorizationError):
        [e async for e in registry.instantiate("tool_nuclei", scope=Scope()).lookup(target)]
    mod = registry.instantiate("tool_nuclei", scope=Scope(allow_active=True))
    emits = [e async for e in mod.lookup(target)]
    assert emits and all(e.type is EntityType.VULNERABILITY for e in emits)


# ---- whatweb (reads a JSON file the binary writes) ---------------------------------------------------------------


def test_parse_whatweb_json_plugins_become_software():
    emits = parse_whatweb_json(_read("whatweb.json"), EntityRef(EntityType.URL, "https://www.example.com/"))
    names = {e.value for e in emits}
    assert {"nginx", "WordPress", "PHP"} <= names
    wp = next(e for e in emits if e.value == "WordPress")
    assert "6.4.2" in wp.meta["values"]


async def test_whatweb_lookup_reads_logfile_and_scans_hostname_as_https(registry, monkeypatch):
    seen = {}

    async def _fake(argv, *, timeout=900.0, env=None, cwd=None, max_bytes=64 << 20):  # noqa: ANN001
        argv = list(argv)
        seen["argv"] = argv
        Path(argv[argv.index("--log-json") + 1]).write_text(_read("whatweb.json"))
        return subproc.ToolResult(argv=argv, stdout="", stderr="", returncode=0)

    monkeypatch.setattr(subproc, "run_tool", _fake)
    mod = registry.instantiate("tool_whatweb")
    emits = [e async for e in mod.lookup(EntityRef(EntityType.HOSTNAME, "www.example.com"))]
    assert "https://www.example.com/" in seen["argv"]  # a bare hostname is scanned over https
    assert {"nginx", "WordPress"} <= {e.value for e in emits}


# ---- testssl (reads a JSON file the binary writes) ---------------------------------------------------------------


def test_parse_testssl_json_vulns_and_one_certificate():
    emits = parse_testssl_json(_read("testssl.json"), EntityRef(EntityType.HOSTNAME, "www.example.com"))
    vulns = _by_type(emits, EntityType.VULNERABILITY)
    ids = {e.meta["id"] for e in vulns}
    assert {"BREACH", "RC4", "cert_expDate"} <= ids  # WARN counts; OK/INFO findings do not
    assert "heartbleed" not in ids and "service" not in ids
    certs = _by_type(emits, EntityType.CERTIFICATE)
    assert len(certs) == 1
    # identity is the SHA-256 fingerprint (stable/unique), not the expiry date; the full facts live in meta
    assert certs[0].value == "AB:CD:EF:00:11:22:33:44:55:66:77:88:99"
    assert certs[0].meta["entries"]["cert_commonName"] == "www.example.com"


def test_parse_testssl_cert_value_falls_back_to_host_qualified_expiry():
    # no fingerprint/serial in the output: the value must stay unique per host and never be the empty string
    text = '[{"id":"cert_notAfter","severity":"OK","finding":"2025-12-31 23:59"}]'
    cert = _by_type(parse_testssl_json(text, EntityRef(EntityType.HOSTNAME, "www.example.com")), EntityType.CERTIFICATE)
    assert cert[0].value == "www.example.com:2025-12-31 23:59"


async def test_testssl_lookup_reads_jsonfile(registry, monkeypatch):
    patch_run_tool(monkeypatch, writes={"--jsonfile": _read("testssl.json")})
    mod = registry.instantiate("tool_testssl")
    emits = [e async for e in mod.lookup(EntityRef(EntityType.HOSTNAME, "www.example.com"))]
    assert _by_type(emits, EntityType.CERTIFICATE) and _by_type(emits, EntityType.VULNERABILITY)


# ---- wafw00f -----------------------------------------------------------------------------------------------------


def test_parse_wafw00f_json_only_detected_rows():
    emits = parse_wafw00f_json(_read("wafw00f.json"), EntityRef(EntityType.URL, "https://www.example.com/"))
    values = [e.value for e in emits]
    assert values == ["Cloudflare", "Generic"]  # the detected:false row is dropped, order preserved
    cf = emits[0]
    assert cf.meta["manufacturer"] == "Cloudflare Inc." and cf.relation == "protected_by"
    assert emits[1].meta["manufacturer"] is None  # "Unknown" is normalised away


async def test_wafw00f_lookup_probes_https_for_a_hostname(registry, monkeypatch):
    seen = {}

    async def _fake(argv, **kwargs):  # noqa: ANN001
        seen["argv"] = list(argv)
        return subproc.ToolResult(argv=list(argv), stdout=_read("wafw00f.json"), stderr="", returncode=0)

    monkeypatch.setattr(subproc, "run_tool", _fake)
    mod = registry.instantiate("tool_wafw00f")
    emits = [e async for e in mod.lookup(EntityRef(EntityType.HOSTNAME, "www.example.com"))]
    assert "https://www.example.com/" in seen["argv"]  # a bare hostname is probed over https
    assert [e.value for e in emits] == ["Cloudflare", "Generic"]


# ---- snallygaster ------------------------------------------------------------------------------------------------


def test_parse_snallygaster_url_and_vulnerability_per_finding():
    emits = parse_snallygaster(_read("snallygaster.json"), EntityRef(EntityType.HOSTNAME, "www.example.com"))
    urls = _by_type(emits, EntityType.URL)
    vulns = _by_type(emits, EntityType.VULNERABILITY)
    assert len(urls) == 3 and len(vulns) == 3  # the two malformed rows (missing cause/url) are skipped
    git = next(e for e in vulns if e.meta["cause"] == "gitdir")
    assert git.value.startswith("gitdir on https://www.example.com/.git/config")
    assert git.parent.type is EntityType.URL


async def test_snallygaster_lookup_gated_and_strips_scheme(registry, monkeypatch):
    seen = {}

    async def _fake(argv, **kwargs):  # noqa: ANN001
        seen["argv"] = list(argv)
        return subproc.ToolResult(argv=list(argv), stdout=_read("snallygaster.json"), stderr="", returncode=0)

    monkeypatch.setattr(subproc, "run_tool", _fake)
    target = EntityRef(EntityType.URL, "https://www.example.com/path")
    with pytest.raises(AuthorizationError):
        [e async for e in registry.instantiate("tool_snallygaster", scope=Scope()).lookup(target)]
    mod = registry.instantiate("tool_snallygaster", scope=Scope(allow_active=True))
    emits = [e async for e in mod.lookup(target)]
    assert seen["argv"][-1] == "www.example.com"  # bare host, no scheme/path
    assert _by_type(emits, EntityType.VULNERABILITY)


# ---- nbtscan -----------------------------------------------------------------------------------------------------


def test_parse_nbtscan_names_and_ports_only_for_responders():
    emits = parse_nbtscan(_read("nbtscan.txt"), EntityRef(EntityType.NETBLOCK, "192.0.2.0/29"))
    hostnames = {e.value for e in _by_type(emits, EntityType.HOSTNAME)}
    ports = {e.value for e in _by_type(emits, EntityType.OPEN_PORT)}
    assert hostnames == {"fileserver", "workstation"}
    assert ports == {"192.0.2.3:137", "192.0.2.4:137"}
    # the *timeout* (192.0.2.5) and blank-name "-" (192.0.2.6) sentinel rows are non-responders: nothing emitted
    assert "192.0.2.5:137" not in ports and "192.0.2.6:137" not in ports


async def test_nbtscan_lookup_gated(registry, monkeypatch):
    patch_run_tool(monkeypatch, stdout=_read("nbtscan.txt"))
    target = EntityRef(EntityType.NETBLOCK, "192.0.2.0/29")
    with pytest.raises(AuthorizationError):
        [e async for e in registry.instantiate("tool_nbtscan", scope=Scope()).lookup(target)]
    mod = registry.instantiate("tool_nbtscan", scope=Scope(allow_active=True))
    assert [e async for e in mod.lookup(target)]


# ---- onesixtyone -------------------------------------------------------------------------------------------------


def test_parse_onesixtyone_ports_and_sysdescr():
    emits = parse_onesixtyone(_read("onesixtyone.txt"), EntityRef(EntityType.NETBLOCK, "192.0.2.0/24"))
    ports = {e.value for e in _by_type(emits, EntityType.OPEN_PORT)}
    software = _by_type(emits, EntityType.SOFTWARE)
    # 192.0.2.22 answered "public" with an empty sysDescr: it is still an open SNMP port, just no software
    assert ports == {"192.0.2.20:161", "192.0.2.21:161", "192.0.2.22:161"}
    assert {e.parent.value for e in software} == {"192.0.2.20", "192.0.2.21"}  # not the empty-descr .22
    assert any("Linux gw01" in e.value for e in software)
    assert all(e.meta["service"] == "snmp" for e in software)


async def test_onesixtyone_lookup_gated(registry, monkeypatch):
    patch_run_tool(monkeypatch, stdout=_read("onesixtyone.txt"))
    target = EntityRef(EntityType.NETBLOCK, "192.0.2.0/24")
    with pytest.raises(AuthorizationError):
        [e async for e in registry.instantiate("tool_onesixtyone", scope=Scope()).lookup(target)]
    mod = registry.instantiate("tool_onesixtyone", scope=Scope(allow_active=True))
    assert _by_type([e async for e in mod.lookup(target)], EntityType.OPEN_PORT)


# ---- cmseek (reads a JSON file from its own Result tree) ---------------------------------------------------------


def test_parse_cmseek_json_detected_cms_as_software():
    emits = parse_cmseek_json(_read("cmseek.json"), EntityRef(EntityType.URL, "https://www.example.com/"))
    assert len(emits) == 1
    assert emits[0].value == "WordPress 6.4.2"
    assert emits[0].meta["product"] == "WordPress" and emits[0].meta["version"] == "6.4.2"


def test_parse_cmseek_json_no_cms_is_no_emit():
    assert parse_cmseek_json('{"cms_id": "", "cms_name": null}', EntityRef(EntityType.URL, "x")) == []
    assert parse_cmseek_json("not json", EntityRef(EntityType.URL, "x")) == []


def test_parse_cmseek_json_unknown_version_is_bare_name():
    # CMSeeK detects the CMS but not the version: "0" (its sentinel) and a missing value both mean unknown, so the
    # emitted software is "Joomla" — not "Joomla 0"/"Joomla None" that would never merge with the canonical node
    for payload in ('{"cms_name": "Joomla", "cms_version": "0"}', '{"cms_name": "Joomla"}'):
        emits = parse_cmseek_json(payload, EntityRef(EntityType.URL, "x"))
        assert len(emits) == 1 and emits[0].value == "Joomla" and emits[0].meta["version"] is None


def test_cmseek_result_dir_matches_cmseek_sanitising():
    from osint_board.modules.impl.tool_cmseek import _result_dir

    # pins the module's URL→dir mapping explicitly, so the fixture-driven lookup test (which uses _result_dir on
    # both sides) can't silently absorb a change to it; matching upstream CMSeeK exactly is a deployment concern
    assert _result_dir("https://www.example.com/") == "www.example.com"
    assert _result_dir("http://www.example.com") == "www.example.com"
    assert _result_dir("https://example.com:8443/path") == "example.com_8443_path"


async def test_cmseek_lookup_reads_result_tree(registry, monkeypatch, tmp_path):
    from osint_board.modules.impl.tool_cmseek import _result_dir

    root = tmp_path / "cmseek"
    root.mkdir()
    (root / "cmseek.py").write_text("# stub")
    url = "http://www.example.com/"

    async def _fake(argv, *, timeout=900.0, env=None, cwd=None, max_bytes=64 << 20):  # noqa: ANN001
        # CMSeeK writes its Result tree under the working directory it is run in (cwd), not the checkout root
        result = Path(cwd) / "Result" / _result_dir(url) / "cms.json"
        result.parent.mkdir(parents=True, exist_ok=True)
        result.write_text(_read("cmseek.json"))
        return subproc.ToolResult(argv=list(argv), stdout="", stderr="", returncode=0)

    monkeypatch.setattr(subproc, "run_tool", _fake)
    mod = registry.instantiate("tool_cmseek", config={"cmseek_dir": str(root)})
    emits = [e async for e in mod.lookup(EntityRef(EntityType.HOSTNAME, "www.example.com"))]
    assert [e.value for e in emits] == ["WordPress 6.4.2"]


async def test_cmseek_lookup_timeout_is_no_findings(registry, monkeypatch, tmp_path):
    root = tmp_path / "cmseek"
    root.mkdir()
    (root / "cmseek.py").write_text("# stub")
    patch_timeout(monkeypatch)
    mod = registry.instantiate("tool_cmseek", config={"cmseek_dir": str(root)})
    assert [e async for e in mod.lookup(EntityRef(EntityType.HOSTNAME, "www.example.com"))] == []


async def test_cmseek_lookup_missing_checkout_raises(registry, monkeypatch, tmp_path):
    mod = registry.instantiate("tool_cmseek", config={"cmseek_dir": str(tmp_path / "absent")})
    with pytest.raises(subproc.ToolNotFound):
        [e async for e in mod.lookup(EntityRef(EntityType.HOSTNAME, "www.example.com"))]


# ---- subproc.run_tool helper (spawns a trivial process to exercise the sandbox, never a scanner) -----------------


def test_as_scan_target_refuses_flag_like_values():
    assert subproc.as_scan_target("203.0.113.10") == "203.0.113.10"
    assert subproc.as_scan_target("www.example.com") == "www.example.com"
    for bad in ("-oN", "--script=http-vuln", "-"):
        with pytest.raises(subproc.ToolError):
            subproc.as_scan_target(bad)


def test_child_env_strips_only_the_platform_secret_prefix(monkeypatch):
    monkeypatch.setenv("OSINT_MODULE_SHODAN_API_KEY", "secret")
    monkeypatch.setenv("OSINT_DATABASE_URL", "postgres://u:p@h/db")
    monkeypatch.setenv("KEEP_ME", "yes")
    env = subproc._child_env(None)
    assert "OSINT_MODULE_SHODAN_API_KEY" not in env and "OSINT_DATABASE_URL" not in env
    assert env["KEEP_ME"] == "yes"  # non-OSINT vars a tool may need (PATH, HOME, proxies) are kept
    assert subproc._child_env({"A": "b"}) == {"A": "b"}  # an explicit env is used verbatim


async def test_nmap_lookup_refuses_a_flag_like_target(registry, monkeypatch):
    called = False

    async def _fake(*a, **k):  # noqa: ANN002, ANN003
        nonlocal called
        called = True
        return subproc.ToolResult([], "", "", 0)

    monkeypatch.setattr(subproc, "run_tool", _fake)
    mod = registry.instantiate("tool_nmap", scope=Scope(allow_active=True))
    with pytest.raises(subproc.ToolError):
        [e async for e in mod.lookup(EntityRef(EntityType.HOSTNAME, "-oN=/tmp/pwned"))]
    assert not called  # the guard fires before any process would be spawned


async def test_run_tool_scrubs_platform_secrets_from_the_child(monkeypatch):
    monkeypatch.setenv("OSINT_MODULE_SECRET", "leaky")
    monkeypatch.setenv("KEEP_ME", "yes")
    code = "import os;print(os.environ.get('OSINT_MODULE_SECRET'), os.environ.get('KEEP_ME'))"
    result = await subproc.run_tool([sys.executable, "-c", code])
    assert result.stdout.strip() == "None yes"  # OSINT_ secrets scrubbed, other env kept


async def test_run_tool_times_out():
    with pytest.raises(subproc.ToolTimeout):
        await subproc.run_tool([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.3)


async def test_run_tool_missing_binary_raises_toolnotfound():
    with pytest.raises(subproc.ToolNotFound):
        await subproc.run_tool(["osint-board-no-such-binary-zzz"])


def _proc_dead(pid: int) -> bool:
    """True when pid no longer exists or is a reaped zombie (Linux /proc, deterministic for the cancel test)."""
    try:
        with open(f"/proc/{pid}/stat") as fh:
            state = fh.read().rsplit(")", 1)[1].split()[0]
        return state == "Z"
    except (FileNotFoundError, ProcessLookupError, IndexError):
        return True


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="uses /proc to observe the child")
async def test_run_tool_kills_the_child_on_cancellation(tmp_path):
    import asyncio

    pidfile = tmp_path / "pid"
    code = f"import os, time; open({str(pidfile)!r}, 'w').write(str(os.getpid())); time.sleep(60)"
    task = asyncio.ensure_future(subproc.run_tool([sys.executable, "-c", code], timeout=120))
    for _ in range(100):  # wait for the child to record its pid
        await asyncio.sleep(0.05)
        if pidfile.exists():
            break
    pid = int(pidfile.read_text())

    task.cancel()  # simulate arq's job deadline / worker shutdown cancelling the coroutine mid-scan
    with pytest.raises(asyncio.CancelledError):
        await task

    for _ in range(100):
        if _proc_dead(pid):
            break
        await asyncio.sleep(0.05)
    assert _proc_dead(pid)  # the scanner was SIGKILLed, not left running after the job was gone
