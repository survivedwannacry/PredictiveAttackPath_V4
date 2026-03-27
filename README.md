# Predictive Attack Path

> **Paste a log. Detect MITRE ATT&CK techniques. Identify adversary tools. Predict what the attacker will do next.**

A Sublime Text plugin backed by a local Python engine that analyzes raw logs using three detection engines — regex patterns, YARA malware signatures, and Sigma SIEM rules — then attributes activity to known threat groups and predicts the adversary's next steps using graph-based co-occurrence analysis.

![Python 3.10+](https://img.shields.io/badge/backend-Python%203.10+-blue.svg)
![Sublime Text 4](https://img.shields.io/badge/editor-Sublime%20Text%204-orange.svg)
![MITRE ATT&CK v15](https://img.shields.io/badge/MITRE%20ATT%26CK-v15-red.svg)

---

## Features

- **Three detection engines** working together on every log:
  - **Regex engine** — 600+ custom patterns covering all 14 MITRE ATT&CK tactics
  - **YARA scanner** — identifies adversary tools and malware (Cobalt Strike, Mimikatz, web shells, etc.)
  - **Sigma engine** — 30+ built-in SIEM rules + support for custom `.yml` rules from SigmaHQ
- **Threat correlation** — fuses all three engines into a unified intelligence summary with detection gap analysis and actionable recommendations
- **Weighted co-occurrence graph** built from real APT group playbooks (691 techniques, 181 groups, 39K+ edges)
- **Threat group attribution** — matches detected techniques against known APT profiles
- **Predictive next steps** — graph neighbor scoring with attribution boost
- **Kill chain reconstruction** — maps the attack across MITRE tactic stages
- **In-editor highlighting** — orange underlines for detected lines, red squiggly for predicted
- **Auto-start backend** — the engine launches automatically when you first analyze; no manual terminal needed
- **Zero plugin dependencies** — uses only Python stdlib + Sublime Text API

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                  Sublime Text Editor                          │
│   Ctrl+Shift+A → sends buffer to local backend               │
│   Results in bottom panel + line highlights                  │
└────────────────────────┬─────────────────────────────────────┘
                         │  HTTP POST /analyze_log
                         ▼
┌──────────────────────────────────────────────────────────────┐
│        Python Intelligence Engine (localhost:8000)            │
│                                                              │
│  ┌──────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │  Regex   │  │    Sigma     │  │    YARA      │           │
│  │  Engine  │  │    Engine    │  │   Scanner    │           │
│  │ 600+ pat │  │  30+ rules   │  │  10+ rules   │           │
│  └────┬─────┘  └──────┬───────┘  └──────┬───────┘           │
│       └───────────┬────┴────────────┬────┘                   │
│                   ▼                 ▼                         │
│        ┌─────────────────────────────────┐                   │
│        │   Merged detection set          │                   │
│        └──────────────┬──────────────────┘                   │
│                       ▼                                      │
│  ┌──────────────┐  ┌──────────────────────────┐              │
│  │  Technique   │  │  Threat Correlator       │              │
│  │  Graph       │  │  Tools + gaps + recs     │              │
│  │  Predictions │  │  SIEM coverage analysis  │              │
│  └──────────────┘  └──────────────────────────┘              │
│                                                              │
│  Output: Detected techniques, YARA hits, Sigma alerts,       │
│          Predictions, Attribution, Kill chain, Recommendations│
└──────────────────────────────────────────────────────────────┘
```

## How the Detection Engines Work

**Regex engine** scans each log line against 600+ compiled patterns mapped to MITRE ATT&CK technique IDs. Multiple pattern matches increase confidence.

**YARA scanner** identifies adversary tools and malware families. The built-in rules detect Cobalt Strike, Mimikatz, Impacket, web shells, DNS tunneling tools, packers, ransomware, and more. If `yara-python` is installed, native YARA matching is used; otherwise a regex-based fallback provides the same coverage.

**Sigma engine** evaluates SIEM-grade detection rules against the log. Each rule includes severity, MITRE mapping, and detection logic. Built-in rules cover 30+ attack patterns. Custom `.yml` rules from the SigmaHQ repository can be added to `backend/rules/sigma/`.

**Threat correlator** fuses all three engines: identifies adversary tooling (YARA), calculates SIEM detection coverage (Sigma), finds techniques with no SIEM rule coverage (gaps), cross-confirms techniques detected by multiple engines, and generates actionable recommendations.

## Installation

### Prerequisites

- **Sublime Text 4** (or 3, build 4000+)
- **Python 3.10+** installed on your system (for the backend)
- **pip** packages: `pip install -r backend/requirements.txt`

### Step 1 — Clone or download

```bash
git clone https://github.com/YOUR_USERNAME/PredictiveAttackPath.git
```

### Step 2 — Install backend dependencies

```bash
cd PredictiveAttackPath/backend
pip install -r requirements.txt
```

Note: `yara-python` and `pyyaml` are optional. The engine works without them (using built-in fallback rules), but installing them enables native YARA scanning and custom Sigma rule loading.

### Step 3 — Install the Sublime Text plugin

1. Open Sublime Text → **Preferences → Browse Packages…**
2. Create a folder called `PredictiveAttackPath` inside Packages
3. Copy these files into it:
   - `PredictiveAttackPath.py`
   - `PredictiveAttackPath.sublime-commands`
   - `PredictiveAttackPath.sublime-settings`
   - `Default.sublime-keymap`
   - The entire `backend/` folder
4. Restart Sublime Text

### Step 4 — Configure Python path (if needed)

Open **Preferences → Package Settings → PredictiveAttackPath → Settings**:

```json
{
    "python_cmd": ["py", "-3"]
}
```

| OS      | Typical value                                    |
|---------|--------------------------------------------------|
| Windows | `["py", "-3"]` or `["C:/Python312/python.exe"]` |
| macOS   | `["python3"]`                                    |
| Linux   | `["python3"]`                                    |

## Usage

1. Open a log file in Sublime Text
2. Press **Ctrl+Shift+A** (the backend starts automatically on first use)
3. Results appear in the bottom panel with highlighted lines

### Keyboard shortcuts

| Shortcut          | Action                          |
|-------------------|---------------------------------|
| `Ctrl+Shift+A`   | Analyze current document        |
| `Ctrl+Shift+X`   | Clear highlights & results      |
| `Ctrl+Shift+R`   | Re-show results panel           |

### Output sections

The analysis panel now includes seven sections:

1. **Detected techniques** — regex-matched ATT&CK techniques with confidence scores
2. **YARA matches** — identified adversary tools and malware families
3. **Sigma rule matches** — SIEM detection rules that fired, with severity levels
4. **Predicted next steps** — graph-predicted techniques the attacker may use next
5. **Attacker attribution** — matched APT groups ranked by score
6. **Kill chain path** — attack progression across MITRE tactics
7. **Correlated threat intel** — fused summary with SIEM coverage gaps and recommendations

## Adding Custom Rules

### Custom YARA rules

Place `.yar` or `.yara` files in `backend/rules/yara/`. They are loaded automatically on startup.

### Custom Sigma rules

Place `.yml` files in `backend/rules/sigma/`. Each file should follow the [Sigma specification](https://github.com/SigmaHQ/sigma-specification). Example:

```yaml
title: Suspicious PowerShell Download
id: custom-001
status: experimental
level: high
tags:
    - attack.execution
    - attack.t1059.001
detection:
    keywords:
        - 'DownloadString'
        - 'Invoke-WebRequest'
    condition: keywords
```

Requires `pyyaml` to be installed: `pip install pyyaml`

## Test Logs

| File | Simulates | Key Techniques |
|------|-----------|----------------|
| `apt29_simulation.log` | Cozy Bear / The Dukes | T1566, T1059.001, T1053, T1071 |
| `apt28_simulation.log` | Fancy Bear / Sofacy | T1190, T1203, T1027, T1041 |
| `multi_stage_attack.log` | Blended campaign | 12+ techniques across kill chain |

## Configuration

```json
{
    "engine_url": "http://127.0.0.1:8000",
    "health_path": "/health",
    "python_cmd": ["py", "-3"],
    "backend_entry": "run.py",
    "startup_timeout_sec": 15,
    "top_n_predictions": 10,
    "auto_analyze_on_save": false
}
```

## Project Structure

```
PredictiveAttackPath/
├── PredictiveAttackPath.py              # Sublime Text plugin
├── PredictiveAttackPath.sublime-commands
├── PredictiveAttackPath.sublime-settings
├── Default.sublime-keymap
├── backend/
│   ├── intelligence_engine.py   # FastAPI app + endpoints
│   ├── log_analyzer.py          # Regex detection engine
│   ├── regex_patterns.py        # 600+ technique patterns
│   ├── yara_scanner.py          # YARA malware scanner
│   ├── sigma_engine.py          # Sigma SIEM rule engine
│   ├── threat_correlator.py     # Multi-engine fusion
│   ├── technique_graph.py       # NetworkX prediction graph
│   ├── mitre_data_loader.py     # STIX data loader
│   ├── config.py                # Settings
│   ├── run.py                   # Entry point
│   ├── requirements.txt
│   ├── rules/
│   │   ├── yara/                # Custom YARA rules (.yar)
│   │   └── sigma/               # Custom Sigma rules (.yml)
│   ├── validate.py              # Standalone validator
│   └── test_engine.py           # Test suite
├── test_logs/                   # Simulated APT logs
├── scripts/
│   └── download_mitre_data.py
├── docs/
│   └── PROBABILITY_MODEL.md
├── .gitignore
├── LICENSE
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
└── SECURITY.md
```
## Demo Screenshots

### Raw log input
![Raw Logs of Multi-staged attack](docs/screenshots/Raw%20Logs%20of%20Multi-staged%20attack.png)

### Detected techniques
![Detected Techniques](docs/screenshots/Detected%20Techniques.png)

### YARA / Sigma matches
![Yara-Sigma Matches](docs/screenshots/Yara-Sigma%20Matches.png)

### Predicted next steps
![Predicted next steps](docs/screenshots/Predicted%20next%20steps.png)

### Kill chain
![Kill Chain](docs/screenshots/Kill%20Chain.png)

### Attacker attribution
![Attacker attribution](docs/screenshots/Attacker%20attribution.png)

### CTI and recommendations
![CTI and recommendations](docs/screenshots/cti-and-recommendations.png)

## Troubleshooting

**"Python not found"** → Set `python_cmd` in settings to your Python 3.10+ path.

**"Backend failed to start within 15 seconds"** → Run manually: `cd backend && python run.py`

**YARA shows "fallback-regex" in health** → Install native YARA: `pip install yara-python`

**Custom Sigma rules not loading** → Install PyYAML: `pip install pyyaml`

**First run is slow** → The backend downloads MITRE ATT&CK data (~25 MB) on first launch.

## Security & Privacy

All analysis happens locally. No log data is sent to external servers. The only outbound request is the initial MITRE ATT&CK download from GitHub.
