# Changelog

## [2.0.0] — 2026-03-27

### Added
- **YARA scanner** with 10 built-in rules detecting Cobalt Strike, Mimikatz, web shells, Impacket, PsExec, DNS tunneling tools, packers, cryptominers, and ransomware
- **Sigma rule engine** with 30+ built-in SIEM detection rules covering all 14 ATT&CK tactics
- **Threat correlator** fusing all three engines with detection gap analysis and recommendations
- Custom YARA rules support (place .yar files in `backend/rules/yara/`)
- Custom Sigma rules support (place .yml files in `backend/rules/sigma/`)
- Three new output panel sections: YARA matches, Sigma alerts, Correlated threat intel
- SIEM coverage percentage and detection gap reporting
- Cross-engine technique confirmation

### Changed
- Backend API v2.0: `/analyze_log` response now includes `yara_matches`, `sigma_matches`, and `threat_correlation`
- `/health` endpoint now reports YARA and Sigma engine status
- `/stats` endpoint includes all three engine metrics
- Updated requirements.txt with yara-python and pyyaml (both optional)

## [1.0.0] — 2026-03-27

### Added
- Sublime Text plugin with full MITRE ATT&CK log analysis
- Backend auto-start: no manual terminal needed
- 600+ regex patterns covering all 14 ATT&CK tactics
- Weighted co-occurrence graph with 691 techniques and 181 APT groups
- Threat group attribution with Jaccard scoring
- Predictive next-step analysis with attribution boost
- Kill chain reconstruction across tactic stages
- In-editor highlighting (orange = detected, red squiggly = predicted)
- Output panel with formatted results
- Auto-analyze on save (optional)
- Configurable Python command for backend launch
- 3 test logs: APT29, APT28, multi-stage blended attack
- Full test suite with pytest
- Standalone validation script
