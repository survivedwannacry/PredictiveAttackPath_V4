"""
PredictiveAttackPath — Threat Intel Correlator

Fuses output from three detection engines:
  1. Regex log analyzer (custom 600+ patterns)
  2. YARA scanner (malware/tool identification)
  3. Sigma rule engine (SIEM-grade detection rules)

Produces a unified correlation summary including:
  - Identified tooling (from YARA)
  - SIEM detection coverage (from Sigma)
  - Detection gaps (techniques without Sigma coverage)
  - Actionable recommendations
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Set

from log_analyzer import DetectedTechnique
from sigma_engine import SigmaRuleMatch
from yara_scanner import YaraMatch

logger = logging.getLogger(__name__)


@dataclass
class ThreatCorrelation:
    """Correlated threat intelligence summary."""

    # Identified adversary tools (from YARA)
    tooling_identified: List[str] = field(default_factory=list)
    tooling_details: List[Dict] = field(default_factory=list)

    # Detection coverage metrics
    techniques_with_sigma: int = 0
    total_detected_techniques: int = 0
    sigma_coverage_pct: float = 0.0

    # Detection gaps
    detection_gaps: List[Dict] = field(default_factory=list)

    # Cross-referenced MITRE techniques (found by multiple engines)
    cross_confirmed_techniques: List[str] = field(default_factory=list)

    # Recommendations
    recommendations: List[str] = field(default_factory=list)

    # Severity summary
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0


def correlate(
    detected_techniques: List[DetectedTechnique],
    yara_matches: List[YaraMatch],
    sigma_matches: List[SigmaRuleMatch],
) -> ThreatCorrelation:
    """
    Correlate findings from all three engines into a unified summary.

    Args:
        detected_techniques: Regex engine detections
        yara_matches: YARA scanner matches
        sigma_matches: Sigma rule matches

    Returns:
        ThreatCorrelation with fused intelligence
    """
    result = ThreatCorrelation()

    # ── Collect technique IDs from each engine ────────────────

    regex_techniques = {d.technique_id for d in detected_techniques}

    yara_techniques = set()  # type: Set[str]
    for ym in yara_matches:
        yara_techniques.update(ym.mitre_techniques)

    sigma_techniques = set()  # type: Set[str]
    for sm in sigma_matches:
        sigma_techniques.update(sm.mitre_techniques)

    all_techniques = regex_techniques | yara_techniques | sigma_techniques

    # ── Tooling identification (from YARA) ────────────────────

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_yara = sorted(
        yara_matches,
        key=lambda y: severity_order.get(y.severity, 4),
    )

    for ym in sorted_yara:
        tool_name = ym.rule_name.replace("_", " ")
        result.tooling_identified.append(tool_name)
        result.tooling_details.append({
            "tool": tool_name,
            "severity": ym.severity,
            "description": ym.description,
            "match_count": ym.match_count,
            "mitre_techniques": ym.mitre_techniques,
        })

    # ── Sigma detection coverage ──────────────────────────────

    result.total_detected_techniques = len(regex_techniques)

    # Which regex-detected techniques also have Sigma matches?
    covered = regex_techniques & sigma_techniques
    result.techniques_with_sigma = len(covered)
    result.sigma_coverage_pct = (
        round(len(covered) / len(regex_techniques) * 100, 1)
        if regex_techniques else 0.0
    )

    # ── Detection gaps ────────────────────────────────────────

    uncovered = regex_techniques - sigma_techniques
    for tech_id in sorted(uncovered):
        det = next(
            (d for d in detected_techniques if d.technique_id == tech_id),
            None,
        )
        if det:
            result.detection_gaps.append({
                "technique_id": tech_id,
                "technique_name": det.technique_name,
                "tactic": det.tactic,
            })

    # ── Cross-confirmation ────────────────────────────────────

    # Techniques found by 2+ engines are high-confidence
    for tech_id in sorted(all_techniques):
        engines = 0
        if tech_id in regex_techniques:
            engines += 1
        if tech_id in yara_techniques:
            engines += 1
        if tech_id in sigma_techniques:
            engines += 1
        if engines >= 2:
            result.cross_confirmed_techniques.append(tech_id)

    # ── Severity summary ──────────────────────────────────────

    for ym in yara_matches:
        if ym.severity == "critical":
            result.critical_findings += 1
        elif ym.severity == "high":
            result.high_findings += 1
        elif ym.severity == "medium":
            result.medium_findings += 1
        else:
            result.low_findings += 1

    for sm in sigma_matches:
        if sm.severity == "critical":
            result.critical_findings += 1
        elif sm.severity == "high":
            result.high_findings += 1
        elif sm.severity == "medium":
            result.medium_findings += 1
        else:
            result.low_findings += 1

    # ── Recommendations ───────────────────────────────────────

    if result.tooling_identified:
        tools_str = ", ".join(result.tooling_identified[:3])
        result.recommendations.append(
            "Identified adversary tooling: {}. "
            "Run IOC sweep across all endpoints.".format(tools_str)
        )

    if result.detection_gaps:
        gap_ids = ", ".join(
            g["technique_id"] for g in result.detection_gaps[:5]
        )
        result.recommendations.append(
            "Detection gaps found for: {}. "
            "Deploy Sigma/SIEM rules covering these techniques.".format(gap_ids)
        )

    if result.sigma_coverage_pct < 50 and result.total_detected_techniques > 0:
        result.recommendations.append(
            "SIEM coverage is {:.0f}% — consider expanding Sigma rule "
            "deployment for better detection.".format(
                result.sigma_coverage_pct
            )
        )

    if any(ym.severity == "critical" for ym in yara_matches):
        result.recommendations.append(
            "Critical malware/tool detected. "
            "Isolate affected hosts immediately."
        )

    if result.cross_confirmed_techniques:
        result.recommendations.append(
            "High-confidence techniques (multi-engine confirmed): {}. "
            "Prioritize investigation of these.".format(
                ", ".join(result.cross_confirmed_techniques[:5])
            )
        )

    if not result.recommendations:
        result.recommendations.append(
            "No critical findings. Continue monitoring."
        )

    return result
