"""
PredictiveAttackPath — MITRE ATT&CK STIX Data Loader

Downloads the complete Enterprise ATT&CK STIX bundle and extracts:
  - Attack Patterns  (techniques & sub-techniques)
  - Intrusion Sets    (APT groups)
  - Relationships     (group → uses → technique)
  - Tactics           (kill-chain phases)

Supports two sources:
  1. GitHub raw JSON  (primary — fast, reliable)
  2. TAXII 2.0 server (fallback)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests

from config import (
    DATA_DIR,
    MITRE_GITHUB_URL,
    MITRE_STIX_FILE,
)

logger = logging.getLogger(__name__)


# ── Data Classes ──────────────────────────────────────────────────


@dataclass
class Technique:
    """Single ATT&CK technique or sub-technique."""

    technique_id: str  # e.g. "T1059.001"
    stix_id: str  # e.g. "attack-pattern--..."
    name: str  # e.g. "PowerShell"
    description: str = ""
    tactics: list[str] = field(default_factory=list)  # kill-chain phase names
    is_subtechnique: bool = False
    parent_id: str | None = None  # e.g. "T1059" for sub-techniques
    platforms: list[str] = field(default_factory=list)
    data_sources: list[str] = field(default_factory=list)
    detection: str = ""
    url: str = ""
    revoked: bool = False
    deprecated: bool = False


@dataclass
class IntrusionSet:
    """APT group / threat actor."""

    group_id: str  # e.g. "G0016"
    stix_id: str
    name: str  # e.g. "APT29"
    aliases: list[str] = field(default_factory=list)
    description: str = ""
    technique_stix_ids: list[str] = field(default_factory=list)
    technique_ids: list[str] = field(default_factory=list)  # resolved T-codes


@dataclass
class MitreDataset:
    """Complete parsed ATT&CK dataset."""

    techniques: dict[str, Technique] = field(default_factory=dict)  # keyed by T-code
    groups: dict[str, IntrusionSet] = field(default_factory=dict)  # keyed by G-code
    stix_id_to_technique_id: dict[str, str] = field(default_factory=dict)
    tactic_techniques: dict[str, list[str]] = field(default_factory=dict)
    version: str = ""


# ── Loader ────────────────────────────────────────────────────────


class MitreDataLoader:
    """Loads and parses MITRE ATT&CK Enterprise STIX data."""

    def __init__(self) -> None:
        self.dataset = MitreDataset()
        self._raw_bundle: dict[str, Any] = {}

    # ── Public API ────────────────────────────────────────────────

    def load(self, force_download: bool = False) -> MitreDataset:
        """Load dataset from cache or download fresh."""
        if MITRE_STIX_FILE.exists() and not force_download:
            logger.info("Loading cached MITRE data from %s", MITRE_STIX_FILE)
            self._raw_bundle = json.loads(MITRE_STIX_FILE.read_text(encoding="utf-8"))
        else:
            self._download()

        self._parse_bundle()
        self._resolve_relationships()
        self._build_tactic_index()

        logger.info(
            "MITRE dataset loaded: %d techniques, %d groups",
            len(self.dataset.techniques),
            len(self.dataset.groups),
        )
        return self.dataset

    # ── Download ──────────────────────────────────────────────────

    def _download(self) -> None:
        """Download enterprise-attack.json from GitHub."""
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        logger.info("Downloading MITRE ATT&CK data from GitHub...")

        try:
            resp = requests.get(MITRE_GITHUB_URL, timeout=120)
            resp.raise_for_status()
            self._raw_bundle = resp.json()
            MITRE_STIX_FILE.write_text(
                json.dumps(self._raw_bundle, indent=2), encoding="utf-8"
            )
            logger.info("MITRE data saved to %s", MITRE_STIX_FILE)
        except requests.RequestError as exc:
            logger.warning("GitHub download failed: %s — trying TAXII fallback", exc)
            self._download_taxii()

    def _download_taxii(self) -> None:
        """Fallback: pull data via TAXII 2.0 and convert to bundle format."""
        try:
            from stix2 import MemoryStore
            from taxii2client.v20 import Collection

            from config import TAXII_API_ROOT, TAXII_COLLECTION_ID

            collection_url = f"{TAXII_API_ROOT}/{TAXII_COLLECTION_ID}/"
            collection = Collection(collection_url)
            logger.info("Fetching from TAXII: %s", collection_url)

            stix_content = collection.get_objects()
            # Convert to our expected format
            self._raw_bundle = {
                "type": "bundle",
                "id": "bundle--taxii-download",
                "objects": stix_content.get("objects", []),
            }
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            MITRE_STIX_FILE.write_text(
                json.dumps(self._raw_bundle, indent=2), encoding="utf-8"
            )
            logger.info("TAXII data saved to %s", MITRE_STIX_FILE)
        except ImportError:
            raise RuntimeError(
                "Cannot download MITRE data: requests failed and "
                "stix2/taxii2-client not installed. "
                "Run: pip install stix2 taxii2-client"
            )
        except Exception as exc:
            raise RuntimeError(f"Both download methods failed. TAXII error: {exc}")

    # ── Parsing ───────────────────────────────────────────────────

    def _parse_bundle(self) -> None:
        """Parse all STIX objects from the bundle."""
        objects = self._raw_bundle.get("objects", [])
        self.dataset.version = self._raw_bundle.get("id", "unknown")

        # Temporary storage for relationships
        self._relationships: list[dict] = []

        for obj in objects:
            obj_type = obj.get("type", "")

            if obj_type == "attack-pattern":
                self._parse_technique(obj)
            elif obj_type == "intrusion-set":
                self._parse_group(obj)
            elif obj_type == "relationship":
                self._relationships.append(obj)

    def _parse_technique(self, obj: dict) -> None:
        """Parse an attack-pattern STIX object into a Technique."""
        # Skip revoked / deprecated
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            return

        # Extract T-code from external references
        technique_id = ""
        url = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", "")
                url = ref.get("url", "")
                break

        if not technique_id:
            return

        # Extract tactics from kill chain phases
        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactics.append(phase["phase_name"])

        tech = Technique(
            technique_id=technique_id,
            stix_id=obj["id"],
            name=obj.get("name", ""),
            description=obj.get("description", ""),
            tactics=tactics,
            is_subtechnique=obj.get("x_mitre_is_subtechnique", False),
            platforms=obj.get("x_mitre_platforms", []),
            data_sources=obj.get("x_mitre_data_sources", []),
            detection=obj.get("x_mitre_detection", ""),
            url=url,
        )

        # Determine parent for sub-techniques (T1059.001 → T1059)
        if tech.is_subtechnique and "." in technique_id:
            tech.parent_id = technique_id.split(".")[0]

        self.dataset.techniques[technique_id] = tech
        self.dataset.stix_id_to_technique_id[obj["id"]] = technique_id

    def _parse_group(self, obj: dict) -> None:
        """Parse an intrusion-set STIX object into an IntrusionSet."""
        if obj.get("revoked", False):
            return

        group_id = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                group_id = ref.get("external_id", "")
                break

        if not group_id:
            return

        group = IntrusionSet(
            group_id=group_id,
            stix_id=obj["id"],
            name=obj.get("name", ""),
            aliases=obj.get("aliases", []),
            description=obj.get("description", ""),
        )
        self.dataset.groups[group_id] = group

    # ── Relationship Resolution ───────────────────────────────────

    def _resolve_relationships(self) -> None:
        """Resolve 'uses' relationships: intrusion-set → attack-pattern."""
        # Build STIX ID → group lookup
        stix_to_group: dict[str, IntrusionSet] = {}
        for group in self.dataset.groups.values():
            stix_to_group[group.stix_id] = group

        for rel in self._relationships:
            if rel.get("relationship_type") != "uses":
                continue
            if rel.get("revoked", False):
                continue

            source_ref = rel.get("source_ref", "")
            target_ref = rel.get("target_ref", "")

            # We want: intrusion-set --uses--> attack-pattern
            if not source_ref.startswith("intrusion-set--"):
                continue
            if not target_ref.startswith("attack-pattern--"):
                continue

            group = stix_to_group.get(source_ref)
            technique_id = self.dataset.stix_id_to_technique_id.get(target_ref)

            if group and technique_id:
                group.technique_stix_ids.append(target_ref)
                group.technique_ids.append(technique_id)

        # Deduplicate
        for group in self.dataset.groups.values():
            group.technique_ids = sorted(set(group.technique_ids))
            group.technique_stix_ids = sorted(set(group.technique_stix_ids))

        # Cleanup
        del self._relationships

    def _build_tactic_index(self) -> None:
        """Build tactic → techniques mapping."""
        for tech in self.dataset.techniques.values():
            for tactic in tech.tactics:
                self.dataset.tactic_techniques.setdefault(tactic, []).append(
                    tech.technique_id
                )
