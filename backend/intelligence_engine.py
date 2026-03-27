"""
PredictiveAttackPath — Intelligence Engine (FastAPI)

Endpoints:
    POST /analyze_log     — Full log analysis with predictions
    GET  /health          — Engine status
    GET  /techniques      — List all loaded techniques
    GET  /technique/{id}  — Single technique detail
    GET  /groups          — List all loaded intrusion sets
    GET  /stats           — Graph & engine statistics
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from config import (
    CORS_ORIGINS,
    DEFAULT_TOP_N_PREDICTIONS,
    TACTIC_DISPLAY_NAMES,
)
from log_analyzer import LogAnalyzer
from mitre_data_loader import MitreDataLoader, MitreDataset
from sigma_engine import SigmaEngine
from technique_graph import TechniqueGraph
from threat_correlator import correlate as correlate_threats
from yara_scanner import YaraScanner

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("intelligence_engine")

dataset: Optional[MitreDataset] = None
graph: Optional[TechniqueGraph] = None
analyzer: Optional[LogAnalyzer] = None
yara_scanner: Optional[YaraScanner] = None
sigma_engine: Optional[SigmaEngine] = None
boot_time: float = 0


@asynccontextmanager
async def lifespan(app: FastAPI):
    global dataset, graph, analyzer, yara_scanner, sigma_engine, boot_time

    t0 = time.time()
    logger.info("=" * 60)
    logger.info("  Predictive Attack Path — Intelligence Engine")
    logger.info("=" * 60)

    logger.info("[1/5] Loading MITRE ATT&CK data...")
    loader = MitreDataLoader()
    dataset = loader.load()

    logger.info("[2/5] Building technique graph...")
    graph = TechniqueGraph(dataset)

    logger.info("[3/5] Initializing log analyzer...")
    analyzer = LogAnalyzer()

    logger.info("[4/5] Initializing YARA scanner...")
    yara_scanner = YaraScanner()

    logger.info("[5/5] Initializing Sigma engine...")
    sigma_engine = SigmaEngine()

    boot_time = time.time() - t0
    logger.info(
        "Engine ready in %.2fs — %d techniques, %d groups, "
        "%d regex, %d YARA rules, %d Sigma rules",
        boot_time,
        len(dataset.techniques),
        len(dataset.groups),
        analyzer.total_regex_count,
        yara_scanner.rule_count,
        sigma_engine.rule_count,
    )
    logger.info("=" * 60)
    yield
    logger.info("Intelligence Engine shutting down.")


app = FastAPI(
    title="Predictive Attack Path — Intelligence Engine",
    description=(
        "Analyzes raw logs for MITRE ATT&CK techniques with YARA "
        "malware scanning and Sigma SIEM rule evaluation."
    ),
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request / Response Models ─────────────────────────────────────

class AnalyzeRequest(BaseModel):
    log_text: str = Field(..., min_length=1)
    top_n_predictions: int = Field(DEFAULT_TOP_N_PREDICTIONS, ge=1, le=50)
    attribution_boost: bool = Field(True)

class MatchDetail(BaseModel):
    line: int
    text: str
    confidence: float

class DetectedTechniqueResponse(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    match_count: int
    matches: list[MatchDetail]

class PredictionResponse(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    probability: float
    reasoning: str
    contributing_groups: list[str]

class AttributionResponse(BaseModel):
    group_id: str
    group_name: str
    aliases: list[str]
    match_score: float
    matched_techniques: list[str]
    full_playbook_size: int

class AttackStageResponse(BaseModel):
    tactic: str
    tactic_display: str
    techniques: list[str]
    order: int

class YaraMatchStringResponse(BaseModel):
    identifier: str
    matched_data: str
    line_number: int
    line_text: str

class YaraMatchResponse(BaseModel):
    rule_name: str
    severity: str
    description: str
    author: str
    mitre_techniques: list[str]
    match_count: int
    matched_strings: list[YaraMatchStringResponse]

class SigmaMatchResponse(BaseModel):
    rule_id: str
    rule_name: str
    severity: str
    description: str
    mitre_techniques: list[str]
    source: str
    match_count: int
    matched_lines: list[int]
    matched_text: list[str]

class CorrelationResponse(BaseModel):
    tooling_identified: list[str]
    tooling_details: list[dict]
    techniques_with_sigma: int
    total_detected_techniques: int
    sigma_coverage_pct: float
    detection_gaps: list[dict]
    cross_confirmed_techniques: list[str]
    recommendations: list[str]
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int

class AnalyzeResponse(BaseModel):
    detected_techniques: list[DetectedTechniqueResponse]
    likely_next_steps: list[PredictionResponse]
    attacker_attribution: list[AttributionResponse]
    attack_path: list[AttackStageResponse]
    yara_matches: list[YaraMatchResponse]
    sigma_matches: list[SigmaMatchResponse]
    threat_correlation: CorrelationResponse
    analysis_time_ms: float
    line_annotations: dict[str, list[dict]] = {}

class HealthResponse(BaseModel):
    status: str
    techniques_loaded: int
    groups_loaded: int
    regex_patterns: int
    yara_rules: int
    yara_engine: str
    sigma_rules: int
    sigma_custom_rules: int
    graph_nodes: int
    graph_edges: int
    boot_time_seconds: float


# ── Endpoints ─────────────────────────────────────────────────────

@app.post("/analyze_log", response_model=AnalyzeResponse)
async def analyze_log(request: AnalyzeRequest):
    if not analyzer or not graph:
        raise HTTPException(status_code=503, detail="Engine not initialized")

    t0 = time.time()

    detections, line_annotations = analyzer.analyze_with_positions(request.log_text)
    yara_results = yara_scanner.scan(request.log_text) if yara_scanner else []
    sigma_results = sigma_engine.evaluate(request.log_text) if sigma_engine else []

    detected_ids = [d.technique_id for d in detections]
    predictions, attributions, attack_path = graph.predict_next_techniques(
        detected_ids=detected_ids,
        top_n=request.top_n_predictions,
        enable_attribution_boost=request.attribution_boost,
    )

    correlation = correlate_threats(detections, yara_results, sigma_results)
    elapsed_ms = (time.time() - t0) * 1000

    detected_response = []
    for det in detections:
        matches = [
            MatchDetail(line=m.line_number, text=m.line_text[:150], confidence=det.confidence)
            for m in det.matches[:10]
        ]
        detected_response.append(DetectedTechniqueResponse(
            technique_id=det.technique_id,
            technique_name=det.technique_name,
            tactic=TACTIC_DISPLAY_NAMES.get(det.tactic, det.tactic),
            confidence=round(det.confidence, 4),
            match_count=det.match_count,
            matches=matches,
        ))

    prediction_response = [
        PredictionResponse(
            technique_id=p.technique_id, technique_name=p.technique_name,
            tactic=p.tactic, probability=p.probability,
            reasoning=p.reasoning, contributing_groups=p.contributing_groups,
        ) for p in predictions
    ]

    attribution_response = [
        AttributionResponse(
            group_id=a.group_id, group_name=a.group_name, aliases=a.aliases,
            match_score=a.match_score, matched_techniques=a.matched_techniques,
            full_playbook_size=a.full_playbook_size,
        ) for a in attributions
    ]

    path_response = [
        AttackStageResponse(
            tactic=s.tactic, tactic_display=s.tactic_display,
            techniques=s.techniques, order=s.order,
        ) for s in attack_path
    ]

    yara_response = [
        YaraMatchResponse(
            rule_name=ym.rule_name, severity=ym.severity,
            description=ym.description, author=ym.author,
            mitre_techniques=ym.mitre_techniques,
            match_count=ym.match_count,
            matched_strings=[
                YaraMatchStringResponse(
                    identifier=s.identifier, matched_data=s.matched_data,
                    line_number=s.line_number, line_text=s.line_text[:150],
                ) for s in ym.matched_strings[:5]
            ],
        ) for ym in yara_results
    ]

    sigma_response = [
        SigmaMatchResponse(
            rule_id=sm.rule_id, rule_name=sm.rule_name,
            severity=sm.severity, description=sm.description,
            mitre_techniques=sm.mitre_techniques, source=sm.source,
            match_count=sm.match_count,
            matched_lines=sm.matched_lines[:10],
            matched_text=sm.matched_text[:5],
        ) for sm in sigma_results
    ]

    correlation_response = CorrelationResponse(
        tooling_identified=correlation.tooling_identified,
        tooling_details=correlation.tooling_details,
        techniques_with_sigma=correlation.techniques_with_sigma,
        total_detected_techniques=correlation.total_detected_techniques,
        sigma_coverage_pct=correlation.sigma_coverage_pct,
        detection_gaps=correlation.detection_gaps,
        cross_confirmed_techniques=correlation.cross_confirmed_techniques,
        recommendations=correlation.recommendations,
        critical_findings=correlation.critical_findings,
        high_findings=correlation.high_findings,
        medium_findings=correlation.medium_findings,
        low_findings=correlation.low_findings,
    )

    str_annotations = {str(k): v for k, v in line_annotations.items()}

    logger.info(
        "Analysis complete: %d detected, %d predicted, %d groups, "
        "%d YARA, %d Sigma, %.1fms",
        len(detected_response), len(prediction_response),
        len(attribution_response), len(yara_response),
        len(sigma_response), elapsed_ms,
    )

    return AnalyzeResponse(
        detected_techniques=detected_response,
        likely_next_steps=prediction_response,
        attacker_attribution=attribution_response,
        attack_path=path_response,
        yara_matches=yara_response,
        sigma_matches=sigma_response,
        threat_correlation=correlation_response,
        analysis_time_ms=round(elapsed_ms, 2),
        line_annotations=str_annotations,
    )


@app.get("/health", response_model=HealthResponse)
async def health():
    if not analyzer or not graph or not dataset:
        raise HTTPException(status_code=503, detail="Engine not initialized")
    stats = graph.stats
    return HealthResponse(
        status="operational",
        techniques_loaded=len(dataset.techniques),
        groups_loaded=len(dataset.groups),
        regex_patterns=analyzer.total_regex_count,
        yara_rules=yara_scanner.rule_count if yara_scanner else 0,
        yara_engine=yara_scanner.engine_type if yara_scanner else "none",
        sigma_rules=sigma_engine.rule_count if sigma_engine else 0,
        sigma_custom_rules=sigma_engine.custom_rule_count if sigma_engine else 0,
        graph_nodes=stats["total_techniques"],
        graph_edges=stats["total_edges"],
        boot_time_seconds=round(boot_time, 2),
    )


@app.get("/techniques")
async def list_techniques():
    if not dataset:
        raise HTTPException(status_code=503, detail="Engine not initialized")
    from regex_patterns import TECHNIQUE_PATTERNS
    result = []
    for tech_id, tech in sorted(dataset.techniques.items()):
        has_patterns = tech_id in TECHNIQUE_PATTERNS
        pattern_count = len(TECHNIQUE_PATTERNS[tech_id]["patterns"]) if has_patterns else 0
        result.append({
            "technique_id": tech_id, "name": tech.name, "tactics": tech.tactics,
            "is_subtechnique": tech.is_subtechnique,
            "has_regex_patterns": has_patterns, "regex_pattern_count": pattern_count,
        })
    return {"techniques": result, "total": len(result)}


@app.get("/technique/{technique_id}")
async def get_technique(technique_id: str):
    if not graph:
        raise HTTPException(status_code=503, detail="Engine not initialized")
    info = graph.get_technique_info(technique_id)
    if not info:
        raise HTTPException(status_code=404, detail="Technique not found")
    return info


@app.get("/groups")
async def list_groups():
    if not dataset:
        raise HTTPException(status_code=503, detail="Engine not initialized")
    result = []
    for gid, group in sorted(dataset.groups.items()):
        result.append({
            "group_id": gid, "name": group.name, "aliases": group.aliases,
            "technique_count": len(group.technique_ids),
            "techniques": group.technique_ids[:20],
        })
    return {"groups": result, "total": len(result)}


@app.get("/stats")
async def stats():
    if not graph or not dataset or not analyzer:
        raise HTTPException(status_code=503, detail="Engine not initialized")
    from regex_patterns import get_tactic_coverage
    graph_stats = graph.stats
    tactic_cov = get_tactic_coverage()
    return {
        "graph": graph_stats,
        "mitre_data": {
            "total_techniques": len(dataset.techniques),
            "total_groups": len(dataset.groups),
        },
        "regex_engine": {
            "techniques_covered": analyzer.loaded_pattern_count,
            "total_patterns": analyzer.total_regex_count,
            "tactic_coverage": tactic_cov,
        },
        "yara_engine": {
            "rule_count": yara_scanner.rule_count if yara_scanner else 0,
            "engine_type": yara_scanner.engine_type if yara_scanner else "none",
        },
        "sigma_engine": {
            "total_rules": sigma_engine.rule_count if sigma_engine else 0,
            "builtin_rules": sigma_engine.builtin_rule_count if sigma_engine else 0,
            "custom_rules": sigma_engine.custom_rule_count if sigma_engine else 0,
        },
    }
