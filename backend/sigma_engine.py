"""
PredictiveAttackPath — Sigma Rule Engine

Evaluates Sigma detection rules against raw log text to identify
known attack patterns, suspicious behaviors, and policy violations.

Sigma rules are community-maintained YAML detection signatures from
the SigmaHQ repository. Each rule includes:
  - Detection logic (keywords, field matches)
  - MITRE ATT&CK mapping
  - Severity level
  - Description and references

This engine includes built-in rules covering the most common
attack patterns. Additional .yml files can be placed in rules/sigma/.

Features:
  - Built-in rules for 30+ common attack patterns
  - Loads custom .yml rules from rules/sigma/ directory
  - Line-by-line keyword and field matching
  - Severity classification (critical/high/medium/low/informational)
  - MITRE ATT&CK technique cross-referencing
  - No external dependencies (PyYAML is optional for custom rules)
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ── Data Classes ──────────────────────────────────────────────────

@dataclass
class SigmaRuleMatch:
    """A Sigma rule that fired against the log."""
    rule_id: str
    rule_name: str
    severity: str  # critical, high, medium, low, informational
    description: str
    mitre_techniques: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    source: str = "built-in"
    reference: str = ""
    matched_lines: List[int] = field(default_factory=list)
    matched_text: List[str] = field(default_factory=list)
    match_count: int = 0


@dataclass
class SigmaRule:
    """Internal representation of a Sigma detection rule."""
    rule_id: str
    title: str
    description: str
    severity: str
    mitre_techniques: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    source: str = "built-in"
    reference: str = ""
    # Detection: list of keyword groups. Each group is OR'd internally,
    # groups are AND'd with each other (simplified Sigma logic).
    keyword_groups: List[List[str]] = field(default_factory=list)
    # If True, ALL keyword groups must match. If False, ANY group matches.
    condition_all: bool = False


# ── Built-in Rules ────────────────────────────────────────────────

def _builtin_rules() -> List[SigmaRule]:
    """Return built-in Sigma detection rules."""
    rules = []

    def _add(title, desc, severity, techniques, tactics,
             keywords, condition_all=False, reference=""):
        rules.append(SigmaRule(
            rule_id=str(uuid.uuid5(uuid.NAMESPACE_DNS, title))[:8],
            title=title,
            description=desc,
            severity=severity,
            mitre_techniques=techniques,
            mitre_tactics=tactics,
            source="SigmaHQ (built-in)",
            reference=reference,
            keyword_groups=keywords,
            condition_all=condition_all,
        ))

    # ── Execution ─────────────────────────────────────────────
    _add(
        "Encoded PowerShell command line",
        "Detects PowerShell with encoded command and execution policy bypass",
        "high",
        ["T1059.001"], ["execution"],
        [[r"powershell.*-enc", r"powershell.*-encodedcommand",
          r"powershell.*-ep\s+bypass", r"powershell.*-windowstyle\s+hidden"]],
    )
    _add(
        "Suspicious PowerShell download cradle",
        "Detects PowerShell downloading and executing remote content",
        "high",
        ["T1059.001", "T1105"], ["execution"],
        [[r"downloadstring", r"downloadfile", r"invoke-webrequest",
          r"iwr\s+http", r"iex.*new-object.*net\.webclient",
          r"bitstransfer"]],
    )
    _add(
        "WMI process creation",
        "Detects remote process creation via WMI",
        "medium",
        ["T1047"], ["execution"],
        [[r"wmic.*process.*call.*create", r"wmic.*process.*list",
          r"invoke-wmimethod.*create"]],
    )
    _add(
        "Rundll32 suspicious execution",
        "Detects rundll32 loading DLLs from temp directories",
        "medium",
        ["T1218.011"], ["defense-evasion"],
        [[r"rundll32.*\\temp\\", r"rundll32.*\\appdata\\.*\.dll",
          r"rundll32.*,\s*\w+\s*$"]],
    )

    # ── Persistence ───────────────────────────────────────────
    _add(
        "Scheduled task creation for persistence",
        "Detects schtasks used to create persistent scheduled tasks",
        "high",
        ["T1053.005"], ["persistence"],
        [[r"schtasks\s+/create", r"schtasks.*\\\\.*powershell",
          r"schtasks.*/sc\s+(daily|hourly|onlogon|onstart)"]],
    )
    _add(
        "Registry Run key modification",
        "Detects modification of registry Run keys for persistence",
        "high",
        ["T1547.001"], ["persistence"],
        [[r"currentversion\\\\run", r"currentversion/run",
          r"hkcu.*\\run\\", r"hklm.*\\run\\",
          r"reg\s+add.*currentversion.*run"]],
    )
    _add(
        "Systemd service creation",
        "Detects creation of systemd services for persistence on Linux",
        "high",
        ["T1543.002"], ["persistence"],
        [[r"/etc/systemd/system/.*\.service",
          r"systemctl\s+(enable|daemon-reload)",
          r"ExecStart.*--daemon"]],
    )
    _add(
        "Cron job persistence",
        "Detects creation of cron jobs for persistent execution",
        "medium",
        ["T1053.003"], ["persistence"],
        [[r"/etc/cron\.", r"crontab\s+-", r"\*/\d+\s+\*\s+\*\s+\*\s+\*"]],
    )

    # ── Credential Access ─────────────────────────────────────
    _add(
        "Mimikatz credential dumping",
        "Detects Mimikatz usage for credential extraction from LSASS",
        "critical",
        ["T1003.001", "T1003.006"], ["credential-access"],
        [[r"sekurlsa::logonpasswords", r"sekurlsa::pth",
          r"lsadump::dcsync", r"lsadump::sam",
          r"kerberos::golden", r"mimikatz"]],
    )
    _add(
        "LSASS memory access",
        "Detects processes accessing LSASS memory for credential theft",
        "critical",
        ["T1003.001"], ["credential-access"],
        [[r"lsass\.exe.*0x1010", r"lsass.*GrantedAccess",
          r"comsvcs\.dll.*MiniDump.*lsass",
          r"procdump.*lsass"]],
    )
    _add(
        "NTDS.dit extraction",
        "Detects attempts to copy or dump the Active Directory database",
        "critical",
        ["T1003.003"], ["credential-access"],
        [[r"ntdsutil.*ifm", r"ntds\.dit",
          r"vssadmin.*create\s+shadow",
          r"HarddiskVolumeShadowCopy.*ntds"]],
    )
    _add(
        "Kerberoasting activity",
        "Detects Kerberoasting attacks for service account credential theft",
        "high",
        ["T1558.003"], ["credential-access"],
        [[r"invoke-kerberoast", r"hashcat\s+-m\s+13100",
          r"GetUserSPNs", r"kerberoast"]],
    )

    # ── Discovery ─────────────────────────────────────────────
    _add(
        "System information discovery",
        "Detects reconnaissance commands gathering system information",
        "low",
        ["T1082", "T1016"], ["discovery"],
        [[r"systeminfo", r"ipconfig\s+/all", r"whoami\s+/all",
          r"uname\s+-a", r"cat\s+/etc/os-release"]],
    )
    _add(
        "Domain trust enumeration",
        "Detects enumeration of Active Directory trust relationships",
        "medium",
        ["T1482"], ["discovery"],
        [[r"nltest\s+/domain_trusts", r"Get-ADTrust",
          r"dsquery\s+trust"]],
    )
    _add(
        "Network service scanning",
        "Detects internal network port scanning activity",
        "medium",
        ["T1046"], ["discovery"],
        [[r"nmap\s+-s[STAUNFX]", r"nmap.*-p\s+\d+",
          r"masscan", r"proxychains.*nmap"]],
    )
    _add(
        "Container and Kubernetes discovery",
        "Detects enumeration of container infrastructure",
        "medium",
        ["T1613"], ["discovery"],
        [[r"kubectl\s+get\s+(pods|secrets|namespaces)",
          r"docker\s+(ps|inspect|images)",
          r"kubectl.*--all-namespaces"]],
    )
    _add(
        "Cloud infrastructure discovery",
        "Detects cloud API calls for infrastructure enumeration",
        "medium",
        ["T1580"], ["discovery"],
        [[r"aws\s+ec2\s+describe-instances",
          r"aws\s+s3\s+ls",
          r"aws\s+iam\s+list",
          r"169\.254\.169\.254/latest/meta-data"]],
    )

    # ── Defense Evasion ───────────────────────────────────────
    _add(
        "Windows Defender real-time protection disabled",
        "Detects disabling of Windows Defender real-time monitoring",
        "high",
        ["T1562.001"], ["defense-evasion"],
        [[r"Set-MpPreference.*DisableRealtimeMonitoring.*true",
          r"DisableRealtimeMonitoring",
          r"Real-time protection turned OFF"]],
    )
    _add(
        "Windows event log clearing",
        "Detects clearing of Windows event logs to cover tracks",
        "high",
        ["T1070.001"], ["defense-evasion"],
        [[r"wevtutil\s+cl\s+(Security|System|Application)",
          r"Clear-EventLog"]],
    )
    _add(
        "Timestomping detected",
        "Detects modification of file timestamps to evade forensics",
        "medium",
        ["T1070.006"], ["defense-evasion"],
        [[r"timestomp", r"touch\s+-t\s+\d{12}",
          r"SetFileTime"]],
    )
    _add(
        "Log file truncation",
        "Detects truncation of system log files",
        "high",
        ["T1070"], ["defense-evasion"],
        [[r"truncate\s+-s\s+0.*log",
          r">\s*/var/log/",
          r"echo.*>\s*.*\.log",
          r"history\s+-c"]],
    )
    _add(
        "Cloud logging disabled",
        "Detects disabling of cloud audit trail logging",
        "critical",
        ["T1562.008"], ["defense-evasion"],
        [[r"cloudtrail.*stop-logging",
          r"cloudtrail.*delete-trail",
          r"disable.*cloud.*logging"]],
    )
    _add(
        "Firewall rule modification",
        "Detects modification of firewall rules to allow malicious traffic",
        "medium",
        ["T1562.004"], ["defense-evasion"],
        [[r"netsh.*advfirewall.*set.*off",
          r"netsh.*firewall.*add.*allowedprogram",
          r"ufw\s+disable",
          r"iptables\s+-F"]],
    )

    # ── Lateral Movement ──────────────────────────────────────
    _add(
        "Pass the Hash detected",
        "Detects pass-the-hash lateral movement techniques",
        "critical",
        ["T1550.002"], ["lateral-movement"],
        [[r"pass.the.hash", r"sekurlsa::pth",
          r"-hashes\s+[0-9a-f]+:",
          r"Logon Type (3|9).*pass"]],
    )
    _add(
        "SMB administrative share access",
        "Detects access to administrative shares for lateral movement",
        "high",
        ["T1021.002"], ["lateral-movement"],
        [[r"net\s+use\s+\\\\.*\\\$",
          r"\\\\.*\\C\$",
          r"\\\\.*\\ADMIN\$",
          r"psexec.*\\\\"]],
    )
    _add(
        "SSH lateral movement with key",
        "Detects SSH authentication using stolen keys",
        "medium",
        ["T1021.004"], ["lateral-movement"],
        [[r"ssh\s+-i\s+.*id_rsa",
          r"Accepted\s+publickey\s+for",
          r"ssh.*\.ssh/"]],
    )

    # ── Exfiltration ──────────────────────────────────────────
    _add(
        "DNS exfiltration detected",
        "Detects data exfiltration over DNS queries",
        "critical",
        ["T1048.001", "T1071.004"], ["exfiltration"],
        [[r"dns.*exfil", r"chunk\d+\.",
          r"dns.*tunnel.*base64",
          r"TXT.*exfil"]],
    )
    _add(
        "Large data upload over HTTPS",
        "Detects suspiciously large uploads that may indicate exfiltration",
        "high",
        ["T1041"], ["exfiltration"],
        [[r"upload.*\d+\s*(GB|MB).*HTTPS",
          r"exfiltration.*over.*C2",
          r"POST.*upload.*\d+\.\d+\s*GB"]],
    )
    _add(
        "Cloud storage exfiltration",
        "Detects data exfiltration to attacker-controlled cloud storage",
        "critical",
        ["T1537"], ["exfiltration"],
        [[r"aws\s+s3\s+cp.*exfil",
          r"s3://.*exfil",
          r"gsutil.*cp.*exfil",
          r"azcopy.*exfil"]],
    )

    # ── Initial Access ────────────────────────────────────────
    _add(
        "Spearphishing attachment delivery",
        "Detects delivery of spearphishing emails with malicious attachments",
        "high",
        ["T1566.001"], ["initial-access"],
        [[r"spearphishing.*attachment",
          r"\.docm.*macro",
          r"macro.*execution.*detected",
          r"DKIM.*FAIL.*spearphish"]],
    )
    _add(
        "Exploit of public-facing application",
        "Detects exploitation of web application vulnerabilities",
        "high",
        ["T1190"], ["initial-access"],
        [[r"CVE-\d{4}-\d+.*exploit",
          r"deserialization.*attack",
          r"remote code execution.*attempt",
          r"SQL.*injection.*attempt"]],
    )
    _add(
        "Supply chain compromise",
        "Detects supply chain attack indicators",
        "critical",
        ["T1195.001"], ["initial-access"],
        [[r"dependency\s+confusion",
          r"typosquat",
          r"trojanized.*package",
          r"supply.chain.*compromise"]],
    )

    # ── Collection ────────────────────────────────────────────
    _add(
        "Database dump detected",
        "Detects database exfiltration via dump commands",
        "high",
        ["T1005"], ["collection"],
        [[r"mysqldump.*--all-databases",
          r"pg_dumpall", r"pg_dump",
          r"mongodump"]],
    )

    # ── Privilege Escalation ──────────────────────────────────
    _add(
        "Local privilege escalation exploit",
        "Detects exploitation of local vulnerabilities for privilege escalation",
        "critical",
        ["T1068"], ["privilege-escalation"],
        [[r"CVE-2021-4034.*pwnkit",
          r"privilege.*escalation",
          r"now running as root",
          r"SUID.*enumeration"]],
    )

    return rules


# ── Sigma Engine ──────────────────────────────────────────────────

class SigmaEngine:
    """Evaluates Sigma rules against raw log text."""

    def __init__(self, rules_dir: Optional[str] = None) -> None:
        self._rules = []  # type: List[SigmaRule]
        self._custom_rule_count = 0

        if rules_dir is None:
            rules_dir = str(
                Path(__file__).resolve().parent / "rules" / "sigma"
            )

        # Load built-in rules
        self._rules = _builtin_rules()

        # Load custom YAML rules
        self._load_custom_rules(rules_dir)

        logger.info(
            "Sigma engine loaded: %d built-in + %d custom rules",
            len(self._rules) - self._custom_rule_count,
            self._custom_rule_count,
        )

    def _load_custom_rules(self, rules_dir: str) -> None:
        """Load .yml Sigma rules from directory."""
        try:
            import yaml
        except ImportError:
            logger.info(
                "PyYAML not installed — custom Sigma rules skipped. "
                "Install with: pip install pyyaml"
            )
            return

        rules_path = Path(rules_dir)
        if not rules_path.is_dir():
            return

        for yml_file in sorted(rules_path.glob("*.yml")):
            try:
                content = yaml.safe_load(yml_file.read_text(encoding="utf-8"))
                if not content or not isinstance(content, dict):
                    continue

                rule = self._parse_sigma_yaml(content, yml_file.stem)
                if rule:
                    self._rules.append(rule)
                    self._custom_rule_count += 1
            except Exception as exc:
                logger.warning("Failed to load Sigma rule %s: %s", yml_file, exc)

    def _parse_sigma_yaml(self, data: Dict, filename: str) -> Optional[SigmaRule]:
        """Parse a Sigma YAML file into a SigmaRule."""
        title = data.get("title", filename)
        description = data.get("description", "")
        severity = data.get("level", "medium")
        rule_id = data.get("id", str(uuid.uuid5(uuid.NAMESPACE_DNS, title))[:8])

        # Extract MITRE techniques and tactics
        techniques = []  # type: List[str]
        tactics = []  # type: List[str]
        tags = data.get("tags", [])
        if isinstance(tags, list):
            for tag in tags:
                tag_str = str(tag)
                if tag_str.startswith("attack.t"):
                    techniques.append(tag_str.replace("attack.", "").upper())
                elif tag_str.startswith("attack."):
                    tactics.append(tag_str.replace("attack.", ""))

        # Extract detection keywords
        detection = data.get("detection", {})
        keyword_groups = []  # type: List[List[str]]

        if isinstance(detection, dict):
            for key, value in detection.items():
                if key == "condition":
                    continue
                if isinstance(value, list):
                    # List of strings → keyword group
                    group = [str(v) for v in value if v]
                    if group:
                        keyword_groups.append(group)
                elif isinstance(value, dict):
                    # Dict with field: value pairs → extract values
                    group = []
                    for fk, fv in value.items():
                        if isinstance(fv, list):
                            group.extend(str(v) for v in fv if v)
                        elif isinstance(fv, str):
                            group.append(fv)
                    if group:
                        keyword_groups.append(group)
                elif isinstance(value, str):
                    keyword_groups.append([value])

        if not keyword_groups:
            return None

        condition_str = str(detection.get("condition", ""))
        condition_all = " and " in condition_str.lower()

        return SigmaRule(
            rule_id=rule_id[:8],
            title=title,
            description=description,
            severity=severity,
            mitre_techniques=techniques,
            mitre_tactics=tactics,
            source="custom ({})".format(filename),
            keyword_groups=keyword_groups,
            condition_all=condition_all,
        )

    def evaluate(self, log_text: str) -> List[SigmaRuleMatch]:
        """Evaluate all loaded Sigma rules against log text."""
        results = []
        lines = log_text.split("\n")

        for rule in self._rules:
            match = self._evaluate_rule(rule, log_text, lines)
            if match:
                results.append(match)

        # Sort by severity
        severity_order = {
            "critical": 0, "high": 1, "medium": 2,
            "low": 3, "informational": 4
        }
        results.sort(key=lambda r: severity_order.get(r.severity, 5))

        return results

    def _evaluate_rule(self, rule: SigmaRule, log_text: str,
                       lines: List[str]) -> Optional[SigmaRuleMatch]:
        """Evaluate a single rule against the log."""
        all_matched_lines = set()  # type: Set[int]
        all_matched_text = []  # type: List[str]
        groups_matched = 0

        for keyword_group in rule.keyword_groups:
            group_hit = False
            for keyword in keyword_group:
                try:
                    pattern = re.compile(keyword, re.IGNORECASE)
                except re.error:
                    pattern = re.compile(re.escape(keyword), re.IGNORECASE)

                for line_idx, line in enumerate(lines, start=1):
                    if pattern.search(line):
                        group_hit = True
                        all_matched_lines.add(line_idx)
                        all_matched_text.append(line.strip()[:150])

            if group_hit:
                groups_matched += 1

        # Check condition
        if rule.condition_all:
            # ALL groups must match
            if groups_matched < len(rule.keyword_groups):
                return None
        else:
            # ANY group matches
            if groups_matched == 0:
                return None

        return SigmaRuleMatch(
            rule_id=rule.rule_id,
            rule_name=rule.title,
            severity=rule.severity,
            description=rule.description,
            mitre_techniques=rule.mitre_techniques,
            mitre_tactics=rule.mitre_tactics,
            source=rule.source,
            reference=rule.reference,
            matched_lines=sorted(all_matched_lines)[:20],
            matched_text=all_matched_text[:10],
            match_count=len(all_matched_lines),
        )

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    @property
    def custom_rule_count(self) -> int:
        return self._custom_rule_count

    @property
    def builtin_rule_count(self) -> int:
        return len(self._rules) - self._custom_rule_count
