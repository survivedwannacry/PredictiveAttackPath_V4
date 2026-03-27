"""
PredictiveAttackPath — Configuration
"""
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MITRE_STIX_FILE = DATA_DIR / "enterprise-attack.json"

# ── MITRE Data Sources ────────────────────────────────────────────
# Primary: MITRE ATT&CK STIX bundle from GitHub (most reliable)
MITRE_GITHUB_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
    "/master/enterprise-attack/enterprise-attack.json"
)

# Fallback: TAXII 2.0 Server
TAXII_SERVER_URL = "https://cti-taxii.mitre.org/taxii2"
TAXII_API_ROOT = "https://cti-taxii.mitre.org/stix/collections"
TAXII_COLLECTION_ID = "95ecc380-afe9-11e4-9b6c-751b66dd541e"  # Enterprise

# ── API Settings ──────────────────────────────────────────────────
API_HOST = "127.0.0.1"
API_PORT = 8000
API_WORKERS = 1
CORS_ORIGINS = ["*"]  # Restrict in production

# ── Analysis Settings ─────────────────────────────────────────────
DEFAULT_TOP_N_PREDICTIONS = 10
ATTRIBUTION_BOOST_MULTIPLIER = 1.5
MIN_CONFIDENCE_THRESHOLD = 0.3
MAX_NEIGHBOR_DEPTH = 2  # Hops in graph for predictions

# ── MITRE Tactic Order (Kill Chain) ──────────────────────────────
TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

TACTIC_DISPLAY_NAMES = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}
