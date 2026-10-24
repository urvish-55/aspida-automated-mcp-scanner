"""Spec #62 backend: attack paths, heatmap, compare, triage persistence, search, health. Evidence-only behaviour."""

import asyncio
import time

import httpx
import pytest

from backend.analysis.investigate import build_analysis, build_attack_paths, compare_scans
from backend.api.app import app
from backend.database.session import init_db
from backend.tests.test_api_integration import CLEAN, POISONED


def _tool(name, caps):
    return {"name": name, "description": "", "input_schema": {}, "capabilities": caps}


def _finding(fid, cat, sev="high", tools=("a",), status="suspected", rule="POISON-001"):
    return {"id": fid, "rule_id": rule, "category": cat, "severity": sev, "confidence": "high", "status": status, "title": f"{rule} t", "affected_tools": list(tools), "evidence": []}


def test_no_evidence_means_no_attack_path():
    tools = [_tool("a", ["filesystem_read"]), _tool("b", ["network_access"])]
    assert build_attack_paths(tools, []) == []
    # capabilities alone (no injection finding, no combo finding) never produce a path
    assert build_attack_paths(tools, [_finding("1", "schema")]) == []


def test_complete_path_requires_every_evidenced_stage():
    tools = [_tool("a", []), _tool("r", ["filesystem_read"]), _tool("n", ["network_access"])]
    paths = build_attack_paths(tools, [_finding("1", "prompt_injection")])
    exfil = [p for p in paths if p["kind"] == "data_exfiltration"]
    assert exfil and exfil[0]["complete"] is True
    last = exfil[0]["nodes"][-1]
    assert last["status"] == "potential"  # the outcome is never presented as evidenced
    assert exfil[0]["nodes"][1]["status"] == "potential"  # invocation is a mechanism, not an observation


def test_incomplete_path_lists_missing_stage_instead_of_inventing_one():
    tools = [_tool("a", []), _tool("r", ["filesystem_read"])]  # no network tool anywhere
    paths = build_attack_paths(tools, [_finding("1", "unicode")])
    exfil = [p for p in paths if p["kind"] == "data_exfiltration"]
    assert exfil and exfil[0]["complete"] is False
    assert exfil[0]["missing_stages"] == ["egress"]
    assert "incomplete" in exfil[0]["label"].lower()
    cmd = [p for p in paths if p["kind"] == "command_execution"]
    assert cmd and cmd[0]["missing_stages"] == ["execution"]


def test_heatmap_and_exposure_are_derived_from_findings_and_capabilities():
    tools = [_tool("run", ["shell_execution"]), _tool("calm", [])]
    scan = {"id": "s", "target_label": "t"}
    out = build_analysis(scan, tools, [_finding("1", "prompt_injection", "critical", ("run",))])
    row = {r["tool"]: {c["column"]: c["level"] for c in r["cells"]} for r in out["heatmap"]["rows"]}
    assert row["run"]["shell"] == "info" and row["run"]["poisoning"] == "critical"
    assert row["calm"]["poisoning"] == "none"
    ranking = [t["name"] for t in out["tools"]]
    assert ranking[0] == "run"
    assert "not part of the RISK-1" in out["exposure_note"]


def test_compare_new_resolved_and_changed():
    a_f = [_finding("1", "schema", "low", ("x",), rule="SCHEMA-001"), _finding("2", "schema", "high", ("y",), rule="SCHEMA-010")]
    b_f = [_finding("3", "schema", "high", ("x",), rule="SCHEMA-001"), _finding("4", "schema", "low", ("z",), rule="SCHEMA-020")]
    a = {"id": "A", "risk_score": 50}
    b = {"id": "B", "risk_score": 20}
    out = compare_scans(a, [_tool("x", ["network_access"])], a_f, b, [_tool("x", []), _tool("n", [])], b_f)
    assert [f["rule_id"] for f in out["new_findings"]] == ["SCHEMA-020"]
    assert [f["rule_id"] for f in out["resolved_findings"]] == ["SCHEMA-010"]
    assert out["changed_severity"][0]["from"] == "low" and out["changed_severity"][0]["to"] == "high"
    assert out["tools_added"] == ["n"]
    assert out["capabilities_changed"][0]["removed"] == ["network_access"]


@pytest.fixture
async def client():
    await init_db()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def _scan(client, cfg) -> dict:
    r = await client.post("/api/scans", json={"target_type": "config", "target_config": cfg})
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    deadline = time.time() + 30
    while time.time() < deadline:
        d = (await client.get(f"/api/scans/{sid}")).json()
        if d["status"] in ("completed", "failed", "cancelled"):
            return d
        await asyncio.sleep(0.2)
    raise TimeoutError


async def test_triage_status_persists_and_is_validated(client):
    d = await _scan(client, POISONED)
    fid = d["findings"][0]["id"]
    assert d["findings"][0]["triage_status"] == "open"
    r = await client.patch(f"/api/findings/{fid}/triage", json={"status": "in_progress", "note": "fixing in sprint"})
    assert r.status_code == 200 and r.json()["triage_status"] == "in_progress"
    again = (await client.get(f"/api/scans/{d['id']}")).json()
    f = next(x for x in again["findings"] if x["id"] == fid)
    assert f["triage_status"] == "in_progress" and f["triage_note"] == "fixing in sprint"
    assert (await client.patch(f"/api/findings/{fid}/triage", json={"status": "secure"})).status_code == 422
    assert (await client.patch("/api/findings/doesnotexist/triage", json={"status": "open"})).status_code == 404
    # deleting the scan removes its triage rows
    assert (await client.delete(f"/api/scans/{d['id']}")).status_code == 204
    assert (await client.get(f"/api/findings/{fid}")).status_code == 404


async def test_cross_scan_findings_filters_and_facets(client):
    d = await _scan(client, POISONED)
    r = (await client.get("/api/findings", params={"scan_id": d["id"], "severity": "high,critical", "limit": 5})).json()
    assert r["total"] >= 1 and all(i["severity"] in ("high", "critical") for i in r["items"])
    assert "severity" in r["facets"] and "tool" in r["facets"]
    assert all(i["scan_id"] == d["id"] for i in r["items"])
    q = (await client.get("/api/findings", params={"scan_id": d["id"], "q": "zzzz-no-such-thing"})).json()
    assert q["total"] == 0 and q["items"] == []
    await client.delete(f"/api/scans/{d['id']}")


async def test_analysis_search_compare_and_activity(client):
    a = await _scan(client, POISONED)
    b = await _scan(client, CLEAN)
    an = (await client.get(f"/api/scans/{a['id']}/analysis")).json()
    assert {t["name"] for t in an["tools"]} == {"read_file", "run_command"}
    assert an["heatmap"]["rows"] and an["graph"]["nodes"][0]["kind"] == "server"
    clean_an = (await client.get(f"/api/scans/{b['id']}/analysis")).json()
    assert clean_an["attack_paths"] == []
    cmp_ = (await client.get("/api/compare", params={"a": a["id"], "b": b["id"]})).json()
    assert cmp_["a"]["id"] == a["id"] and cmp_["resolved_findings"]
    assert (await client.get("/api/compare", params={"a": a["id"], "b": "nope"})).status_code == 404
    s = (await client.get("/api/search", params={"q": "run_command"})).json()
    assert s["tools"]["total"] == 1 and s["scans"]["total"] >= 0
    act = (await client.get("/api/activity")).json()
    assert act["items"] and "scan_label" in act["items"][0]
    assert (await client.get("/api/notifications")).json()["items"]
    h = (await client.get("/api/tools/history", params={"name": "read_file"})).json()
    assert h["items"]
    for x in (a, b):
        await client.delete(f"/api/scans/{x['id']}")


async def test_discover_is_offline_preview(client):
    r = await client.post("/api/discover", json={"target_config": POISONED})
    assert r.status_code == 200
    body = r.json()
    assert body["tool_count"] == 2 and body["resources"] is None and "Nothing was executed" in body["note"]
    assert (await client.post("/api/discover", json={})).status_code == 422
    assert (await client.post("/api/discover", json={"target_config": "{not json"})).status_code == 422


async def test_ml_info_and_system_health_are_truthful(client):
    ml = (await client.get("/api/ml/info")).json()
    if ml["available"]:
        assert (ml["real_world_training_samples"] == 0) == bool(ml["dataset"].get("synthetic"))
        assert "advisory" in ml["note"]
    else:
        assert ml["reason"]
    h = (await client.get("/api/system/health")).json()
    ids = {c["id"] for c in h["components"]}
    assert {"backend", "database", "connector", "ml", "llm", "worker", "reports"} <= ids
    assert h["overall"] in ("healthy", "degraded", "unavailable")


@pytest.mark.asyncio
async def test_unicode_inspect_flags_invisible_and_homoglyph(client):
    text = "tool​name ‮аpple read file"  # ZWSP, RLO, Cyrillic 'a' in a Latin word? (apple), NBSP
    r = (await client.post("/api/unicode/inspect", json={"text": text})).json()
    by = {c["codepoint"]: c for c in r["chars"]}
    assert by["U+200B"]["name"] == "ZERO WIDTH SPACE" and by["U+200B"]["invisible"] and by["U+200B"]["suspicious"]
    assert by["U+202E"]["bidi"] == "RLO" and "Bidirectional" in by["U+202E"]["suspicious"]
    assert by["U+00A0"]["suspicious"] and by["U+00A0"]["utf8"] == "C2 A0"
    assert r["suspicious_count"] >= 3 and r["length"] == len(text)
    plain = (await client.post("/api/unicode/inspect", json={"text": "read_file"})).json()
    assert plain["suspicious_count"] == 0
    assert (await client.post("/api/unicode/inspect", json={"text": ""})).status_code == 422


def test_unicode_analyzer_flags_tag_characters() -> None:
    from backend.scanners.static.unicode_analyzer import scan_text

    hidden = "".join(chr(0xE0000 + ord(c)) for c in "ignore")
    hits = scan_text("Returns a title." + hidden, "description", "description")
    assert len(hits) == 6
    assert all(h.klass == "invisible" and h.name.startswith("TAG CHARACTER") for h in hits)
