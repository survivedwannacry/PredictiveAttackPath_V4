"""
PredictiveAttackPath — Log Analyzer

Scans raw log text against the regex pattern library to identify
MITRE ATT&CK techniques present in the data.

Features:
  - Line-by-line scanning with match location tracking
  - Confidence adjustment based on multiple pattern hits
  - Deduplication and ranking of results
  - Support for multi-line pattern matching
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from regex_patterns import TECHNIQUE_PATTERNS

logger = logging.getLogger(__name__)


@dataclass
class PatternMatch:
    """A single regex match in the log."""

    line_number: int
    line_text: str
    matched_text: str
    pattern_index: int  # Which pattern in the technique's list matched


@dataclass
class DetectedTechnique:
    """A technique detected in the log with all supporting evidence."""

    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    matches: list[PatternMatch] = field(default_factory=list)

    @property
    def match_count(self) -> int:
        return len(self.matches)

    @property
    def first_line(self) -> int:
        return min(m.line_number for m in self.matches) if self.matches else 0

    @property
    def last_line(self) -> int:
        return max(m.line_number for m in self.matches) if self.matches else 0


class LogAnalyzer:
    """Scans log text for MITRE ATT&CK technique indicators."""

    def __init__(self) -> None:
        self.patterns = TECHNIQUE_PATTERNS

    def analyze(self, log_text: str) -> list[DetectedTechnique]:
        """
        Analyze raw log text and return detected techniques.

        Args:
            log_text: Raw log content (multi-line string)

        Returns:
            List of DetectedTechnique sorted by confidence (descending)
        """
        lines = log_text.split("\n")
        detections: dict[str, DetectedTechnique] = {}

        # ── Phase 1: Line-by-line scanning ────────────────────────
        for line_idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue

            for tech_id, tech_info in self.patterns.items():
                for pat_idx, pattern in enumerate(tech_info["patterns"]):
                    match = pattern.search(stripped)
                    if match:
                        pm = PatternMatch(
                            line_number=line_idx,
                            line_text=stripped[:200],  # Truncate for safety
                            matched_text=match.group(0)[:100],
                            pattern_index=pat_idx,
                        )

                        if tech_id not in detections:
                            detections[tech_id] = DetectedTechnique(
                                technique_id=tech_id,
                                technique_name=tech_info["name"],
                                tactic=tech_info["tactic"],
                                confidence=tech_info["confidence"],
                                matches=[pm],
                            )
                        else:
                            detections[tech_id].matches.append(pm)

        # ── Phase 2: Confidence adjustment ────────────────────────
        # More distinct pattern matches = higher confidence
        for det in detections.values():
            distinct_patterns = len(
                set(m.pattern_index for m in det.matches)
            )
            distinct_lines = len(set(m.line_number for m in det.matches))

            # Boost: +5% per additional distinct pattern (capped at 1.0)
            pattern_boost = min(0.15, (distinct_patterns - 1) * 0.05)
            # Boost: +2% per additional distinct line (capped)
            line_boost = min(0.10, (distinct_lines - 1) * 0.02)

            det.confidence = min(1.0, det.confidence + pattern_boost + line_boost)

        # ── Phase 3: Sort by confidence ───────────────────────────
        results = sorted(
            detections.values(), key=lambda d: d.confidence, reverse=True
        )

        logger.info(
            "Log analysis complete: %d techniques detected across %d lines",
            len(results),
            len(lines),
        )
        return results

    def analyze_with_positions(
        self, log_text: str
    ) -> tuple[list[DetectedTechnique], dict[int, list[dict]]]:
        """
        Analyze log and return both detections and per-line annotation data.

        Returns:
            detections: List of detected techniques
            line_annotations: Mapping of line_number → list of
                              {technique_id, technique_name, start, end, type}
        """
        detections = self.analyze(log_text)

        # Build line annotations for the UI highlighting
        line_annotations: dict[int, list[dict]] = {}
        detected_ids = {d.technique_id for d in detections}

        for det in detections:
            for match in det.matches:
                ann = {
                    "technique_id": det.technique_id,
                    "technique_name": det.technique_name,
                    "tactic": det.tactic,
                    "matched_text": match.matched_text,
                    "type": "detected",
                }
                line_annotations.setdefault(match.line_number, []).append(ann)

        return detections, line_annotations

    @property
    def loaded_pattern_count(self) -> int:
        """Number of technique IDs with patterns."""
        return len(self.patterns)

    @property
    def total_regex_count(self) -> int:
        """Total individual regex patterns loaded."""
        return sum(len(p["patterns"]) for p in self.patterns.values())
