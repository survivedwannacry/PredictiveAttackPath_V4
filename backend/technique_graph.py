"""
PredictiveAttackPath — Technique Co-occurrence Graph & Prediction Engine

Builds a weighted undirected graph where:
  - Nodes  = ATT&CK Techniques (T-codes)
  - Edges  = "Shared adversary group usage"
  - Weight = Number of intrusion sets that use BOTH techniques

Prediction Algorithm:
  1. Given a set of detected techniques, walk all graph neighbors.
  2. Each neighbor accumulates a normalized score based on edge weights.
  3. If attribution matches a known group, boost neighbors in that
     group's playbook by ATTRIBUTION_BOOST_MULTIPLIER.
  4. Return top-N predictions sorted by score.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from itertools import combinations

import networkx as nx

from config import (
    ATTRIBUTION_BOOST_MULTIPLIER,
    DEFAULT_TOP_N_PREDICTIONS,
    MIN_CONFIDENCE_THRESHOLD,
    TACTIC_DISPLAY_NAMES,
    TACTIC_ORDER,
)
from mitre_data_loader import MitreDataset

logger = logging.getLogger(__name__)


@dataclass
class Prediction:
    """A predicted next-step technique."""

    technique_id: str
    technique_name: str
    tactic: str
    probability: float
    reasoning: str
    contributing_groups: list[str] = field(default_factory=list)


@dataclass
class Attribution:
    """Attribution match for a threat group."""

    group_id: str
    group_name: str
    aliases: list[str]
    match_score: float
    matched_techniques: list[str]
    full_playbook_size: int


@dataclass
class AttackStage:
    """A stage in the reconstructed kill chain."""

    tactic: str
    tactic_display: str
    techniques: list[str]
    order: int


class TechniqueGraph:
    """Weighted co-occurrence graph for ATT&CK technique prediction."""

    def __init__(self, dataset: MitreDataset) -> None:
        self.dataset = dataset
        self.graph = nx.Graph()
        self.max_weight: float = 1.0

        # Group index: technique_id → set of group_ids that use it
        self._tech_to_groups: dict[str, set[str]] = {}

        self._build_graph()

    # ── Graph Construction ────────────────────────────────────────

    def _build_graph(self) -> None:
        """Build the full technique co-occurrence graph."""

        # Step 1: Add all techniques as nodes with metadata
        for tech_id, tech in self.dataset.techniques.items():
            self.graph.add_node(
                tech_id,
                name=tech.name,
                tactics=tech.tactics,
                is_subtechnique=tech.is_subtechnique,
                parent_id=tech.parent_id,
            )

        # Step 2: Build inverted index (technique → groups)
        for group in self.dataset.groups.values():
            for tech_id in group.technique_ids:
                self._tech_to_groups.setdefault(tech_id, set()).add(group.group_id)

        # Step 3: For each group, create edges between all pairs of
        #         techniques in that group's playbook
        edge_weights: dict[tuple[str, str], int] = {}

        for group in self.dataset.groups.values():
            valid_techs = [
                t for t in group.technique_ids if t in self.dataset.techniques
            ]
            for t1, t2 in combinations(sorted(valid_techs), 2):
                key = (t1, t2)
                edge_weights[key] = edge_weights.get(key, 0) + 1

        # Step 4: Add weighted edges
        for (t1, t2), weight in edge_weights.items():
            self.graph.add_edge(t1, t2, weight=weight)

        self.max_weight = max(
            (d.get("weight", 1) for _, _, d in self.graph.edges(data=True)),
            default=1,
        )

        logger.info(
            "Technique graph built: %d nodes, %d edges, max_weight=%d",
            self.graph.number_of_nodes(),
            self.graph.number_of_edges(),
            self.max_weight,
        )

    # ── Prediction ────────────────────────────────────────────────

    def predict_next_techniques(
        self,
        detected_ids: list[str],
        top_n: int = DEFAULT_TOP_N_PREDICTIONS,
        enable_attribution_boost: bool = True,
    ) -> tuple[list[Prediction], list[Attribution], list[AttackStage]]:
        """
        Given detected technique IDs, predict what comes next.

        Returns:
            predictions:   Ranked list of likely next techniques
            attributions:  Matched APT groups
            attack_path:   Kill-chain stage reconstruction
        """
        detected_set = set(detected_ids) & set(self.graph.nodes)

        if not detected_set:
            return [], [], []

        # ── Phase 1: Attribution ──────────────────────────────────
        attributions = self._attribute_groups(detected_set)

        # Collect technique IDs from top-matching groups for boosting
        boost_techniques: set[str] = set()
        if enable_attribution_boost and attributions:
            for attr in attributions[:3]:  # Top 3 groups
                group = self.dataset.groups.get(attr.group_id)
                if group:
                    boost_techniques.update(group.technique_ids)

        # ── Phase 2: Neighbor Scoring ─────────────────────────────
        neighbor_scores: dict[str, float] = {}
        neighbor_groups: dict[str, set[str]] = {}

        for det_tech in detected_set:
            if det_tech not in self.graph:
                continue
            for neighbor in self.graph.neighbors(det_tech):
                if neighbor in detected_set:
                    continue  # Skip already-detected

                edge_data = self.graph[det_tech][neighbor]
                weight = edge_data.get("weight", 1)
                normalized = weight / self.max_weight

                neighbor_scores[neighbor] = (
                    neighbor_scores.get(neighbor, 0.0) + normalized
                )

                # Track which groups contribute
                shared = self._tech_to_groups.get(det_tech, set()) & \
                         self._tech_to_groups.get(neighbor, set())
                neighbor_groups.setdefault(neighbor, set()).update(shared)

        # ── Phase 3: Attribution Boost ────────────────────────────
        if enable_attribution_boost:
            for tech_id in neighbor_scores:
                if tech_id in boost_techniques:
                    neighbor_scores[tech_id] *= ATTRIBUTION_BOOST_MULTIPLIER

        # ── Phase 4: Normalize to [0, 1] ─────────────────────────
        if neighbor_scores:
            max_score = max(neighbor_scores.values())
            if max_score > 0:
                for k in neighbor_scores:
                    neighbor_scores[k] /= max_score

        # ── Phase 5: Build Predictions ────────────────────────────
        sorted_neighbors = sorted(
            neighbor_scores.items(), key=lambda x: x[1], reverse=True
        )

        predictions: list[Prediction] = []
        for tech_id, score in sorted_neighbors[:top_n]:
            if score < MIN_CONFIDENCE_THRESHOLD:
                continue

            tech = self.dataset.techniques.get(tech_id)
            if not tech:
                continue

            groups_contributing = neighbor_groups.get(tech_id, set())
            group_names = []
            for gid in groups_contributing:
                g = self.dataset.groups.get(gid)
                if g:
                    group_names.append(g.name)

            primary_tactic = tech.tactics[0] if tech.tactics else "unknown"

            n_groups = len(groups_contributing)
            reasoning = (
                f"Co-used by {n_groups} group{'s' if n_groups != 1 else ''} "
                f"with detected techniques"
            )
            if tech_id in boost_techniques:
                reasoning += " (attribution-boosted)"

            predictions.append(
                Prediction(
                    technique_id=tech_id,
                    technique_name=tech.name,
                    tactic=TACTIC_DISPLAY_NAMES.get(primary_tactic, primary_tactic),
                    probability=round(score, 4),
                    reasoning=reasoning,
                    contributing_groups=sorted(group_names),
                )
            )

        # ── Phase 6: Build Attack Path ────────────────────────────
        attack_path = self._build_attack_path(detected_set, predictions)

        return predictions, attributions, attack_path

    # ── Attribution ───────────────────────────────────────────────

    def _attribute_groups(self, detected_set: set[str]) -> list[Attribution]:
        """Score each intrusion set by overlap with detected techniques."""
        attributions: list[Attribution] = []

        for group in self.dataset.groups.values():
            if not group.technique_ids:
                continue

            group_tech_set = set(group.technique_ids)
            overlap = detected_set & group_tech_set

            if not overlap:
                continue

            # Jaccard-like score weighted toward detected coverage
            # score = |overlap| / |detected| * 0.6 + |overlap| / |group_techs| * 0.4
            det_coverage = len(overlap) / len(detected_set)
            group_coverage = len(overlap) / len(group_tech_set)
            score = det_coverage * 0.6 + group_coverage * 0.4

            attributions.append(
                Attribution(
                    group_id=group.group_id,
                    group_name=group.name,
                    aliases=group.aliases,
                    match_score=round(score, 4),
                    matched_techniques=sorted(overlap),
                    full_playbook_size=len(group.technique_ids),
                )
            )

        attributions.sort(key=lambda a: a.match_score, reverse=True)
        return attributions[:10]  # Top 10 matches

    # ── Attack Path Reconstruction ────────────────────────────────

    def _build_attack_path(
        self, detected_set: set[str], predictions: list[Prediction]
    ) -> list[AttackStage]:
        """Build kill-chain stage view from detected + predicted techniques."""
        tactic_to_techs: dict[str, list[str]] = {}

        # Add detected techniques
        for tech_id in detected_set:
            tech = self.dataset.techniques.get(tech_id)
            if not tech:
                continue
            for tactic in tech.tactics:
                tactic_to_techs.setdefault(tactic, []).append(tech_id)

        # Add top predictions (marked differently in output)
        for pred in predictions[:5]:
            tech = self.dataset.techniques.get(pred.technique_id)
            if not tech:
                continue
            for tactic in tech.tactics:
                tech_label = f"{pred.technique_id}*"  # * = predicted
                tactic_to_techs.setdefault(tactic, []).append(tech_label)

        # Build ordered stages
        stages: list[AttackStage] = []
        for idx, tactic_slug in enumerate(TACTIC_ORDER):
            techs = tactic_to_techs.get(tactic_slug, [])
            if techs:
                stages.append(
                    AttackStage(
                        tactic=tactic_slug,
                        tactic_display=TACTIC_DISPLAY_NAMES.get(
                            tactic_slug, tactic_slug
                        ),
                        techniques=sorted(set(techs)),
                        order=idx,
                    )
                )

        return stages

    # ── Utility ───────────────────────────────────────────────────

    def get_technique_info(self, technique_id: str) -> dict | None:
        """Return metadata for a single technique."""
        tech = self.dataset.techniques.get(technique_id)
        if not tech:
            return None
        groups_using = self._tech_to_groups.get(technique_id, set())
        return {
            "technique_id": tech.technique_id,
            "name": tech.name,
            "tactics": tech.tactics,
            "platforms": tech.platforms,
            "groups_using_count": len(groups_using),
            "is_subtechnique": tech.is_subtechnique,
        }

    @property
    def stats(self) -> dict:
        """Return graph statistics."""
        return {
            "total_techniques": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "total_groups": len(self.dataset.groups),
            "max_edge_weight": self.max_weight,
            "avg_degree": (
                round(
                    sum(d for _, d in self.graph.degree()) / self.graph.number_of_nodes(),
                    2,
                )
                if self.graph.number_of_nodes() > 0
                else 0
            ),
        }
