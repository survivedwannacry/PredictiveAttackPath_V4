"""
PredictiveAttackPath — YARA Scanner

Scans raw log text against YARA rules to identify known malware
families, toolkits, packers, and adversary tools.

Features:
  - Loads all .yar / .yara files from the rules/yara/ directory
  - Scans log text for string matches and byte patterns
  - Returns matched rule name, metadata (author, severity, description),
    and the specific strings that triggered each match
  - Gracefully degrades if yara-python is not installed

Install:
    pip install yara-python
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Try to import yara ────────────────────────────────────────────

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.info(
        "yara-python not installed — YARA scanning disabled. "
        "Install with: pip install yara-python"
    )


# ── Data Classes ──────────────────────────────────────────────────

@dataclass
class YaraMatchDetail:
    """A single string match within a YARA rule hit."""
    offset: int
    identifier: str
    matched_data: str
    line_number: int = 0
    line_text: str = ""


@dataclass
class YaraMatch:
    """A YARA rule that matched against the log."""
    rule_name: str
    namespace: str
    tags: List[str] = field(default_factory=list)
    severity: str = "medium"
    description: str = ""
    author: str = ""
    reference: str = ""
    mitre_techniques: List[str] = field(default_factory=list)
    matched_strings: List[YaraMatchDetail] = field(default_factory=list)

    @property
    def match_count(self) -> int:
        return len(self.matched_strings)


# ── Built-in Rules (no .yar files needed) ─────────────────────────

# These are string-based pattern rules compiled at runtime.
# They detect common adversary tools and malware indicators
# directly in log text without requiring YARA rule files.

BUILTIN_YARA_SOURCE = r"""
rule CobaltStrike_Beacon {
    meta:
        description = "Cobalt Strike beacon callback indicators"
        author = "PredictiveAttackPath"
        severity = "critical"
        mitre = "T1071.001,T1059.001"
    strings:
        $cb1 = "cobalt strike" nocase
        $cb2 = "beacon callback" nocase
        $cb3 = "cobaltstrike" nocase
        $pipe1 = /\\\\\.\\pipe\\MSSE-[0-9a-f]{4}-server/ nocase
        $pipe2 = /\\\\\.\\pipe\\msagent_[0-9a-f]/ nocase
        $ua1 = "Mozilla/4.0 (compatible; MSIE 7.0" nocase
        $ua2 = "Mozilla/5.0 (compatible; MSIE 9.0" nocase
        $sleep1 = "beacon> sleep" nocase
    condition:
        any of them
}

rule Mimikatz_Indicators {
    meta:
        description = "Mimikatz credential dumping tool signatures"
        author = "PredictiveAttackPath"
        severity = "critical"
        mitre = "T1003.001,T1003.006,T1550.002"
    strings:
        $mimi1 = "mimikatz" nocase
        $mimi2 = "sekurlsa::logonpasswords" nocase
        $mimi3 = "sekurlsa::pth" nocase
        $mimi4 = "lsadump::dcsync" nocase
        $mimi5 = "lsadump::sam" nocase
        $mimi6 = "kerberos::golden" nocase
        $mimi7 = "privilege::debug" nocase
        $mimi8 = "token::elevate" nocase
        $dump1 = /comsvcs\.dll[,\s]+MiniDump/i nocase
        $dump2 = "procdump" nocase
        $lsass1 = /lsass\.exe.*0x1010/ nocase
        $lsass2 = /GrantedAccess.*0x1FFFFF/ nocase
    condition:
        any of them
}

rule WebShell_Generic {
    meta:
        description = "Generic web shell indicators"
        author = "PredictiveAttackPath"
        severity = "high"
        mitre = "T1505.003"
    strings:
        $ws1 = "eval($_POST" nocase
        $ws2 = "eval($_GET" nocase
        $ws3 = "eval($_REQUEST" nocase
        $ws4 = "china chopper" nocase
        $ws5 = "c99shell" nocase
        $ws6 = "r57shell" nocase
        $ws7 = "b374k" nocase
        $ws8 = /<%\s*eval\s*request/ nocase
        $ws9 = "wso shell" nocase
        $ws10 = "webshell" nocase
    condition:
        any of them
}

rule Impacket_Tools {
    meta:
        description = "Impacket suite tool indicators"
        author = "PredictiveAttackPath"
        severity = "high"
        mitre = "T1550.002,T1021.002,T1003.006"
    strings:
        $imp1 = "impacket-wmiexec" nocase
        $imp2 = "impacket-smbexec" nocase
        $imp3 = "impacket-psexec" nocase
        $imp4 = "impacket-secretsdump" nocase
        $imp5 = "impacket-atexec" nocase
        $imp6 = "impacket-dcomexec" nocase
        $imp7 = /\-hashes\s+[0-9a-f]+:[0-9a-f]+/ nocase
    condition:
        any of them
}

rule Packed_Binary_Indicators {
    meta:
        description = "Packed or obfuscated binary indicators"
        author = "PredictiveAttackPath"
        severity = "medium"
        mitre = "T1027.002"
    strings:
        $upx1 = "packed with UPX" nocase
        $upx2 = "UPX compressed" nocase
        $pack1 = "high entropy sections" nocase
        $pack2 = "entropy:" nocase
        $pack3 = "themida" nocase
        $pack4 = "vmprotect" nocase
    condition:
        any of them
}

rule Chisel_Tunnel {
    meta:
        description = "Chisel tunneling tool indicators"
        author = "PredictiveAttackPath"
        severity = "high"
        mitre = "T1572,T1090"
    strings:
        $ch1 = "chisel client" nocase
        $ch2 = "chisel server" nocase
        $ch3 = /chisel.*R:\d+:socks/ nocase
        $ch4 = /chisel.*--fingerprint/ nocase
    condition:
        any of them
}

rule PsExec_Usage {
    meta:
        description = "PsExec remote execution indicators"
        author = "PredictiveAttackPath"
        severity = "high"
        mitre = "T1569.002,T1021.002"
    strings:
        $ps1 = "psexec.exe" nocase
        $ps2 = "psexec64.exe" nocase
        $ps3 = /psexec\s+\\\\/ nocase
        $ps4 = "PSEXESVC" nocase
    condition:
        any of them
}

rule DNS_Tunneling_Tool {
    meta:
        description = "DNS tunneling tool indicators"
        author = "PredictiveAttackPath"
        severity = "high"
        mitre = "T1071.004,T1572"
    strings:
        $dns1 = "dnscat" nocase
        $dns2 = "dns tunnel" nocase
        $dns3 = "dns exfiltration" nocase
        $dns4 = "iodine tunnel" nocase
        $dns5 = /chunk\d+\..*TXT/ nocase
    condition:
        any of them
}

rule Cryptominer_Indicators {
    meta:
        description = "Cryptocurrency miner indicators"
        author = "PredictiveAttackPath"
        severity = "medium"
        mitre = "T1496"
    strings:
        $xmr1 = "xmrig" nocase
        $xmr2 = "monero" nocase
        $xmr3 = "stratum+tcp" nocase
        $xmr4 = "cryptonight" nocase
        $xmr5 = "mining pool" nocase
        $xmr6 = "hashrate" nocase
    condition:
        any of them
}

rule Ransomware_Indicators {
    meta:
        description = "Ransomware activity indicators"
        author = "PredictiveAttackPath"
        severity = "critical"
        mitre = "T1486,T1490"
    strings:
        $rw1 = "ransomware" nocase
        $rw2 = "your files have been encrypted" nocase
        $rw3 = "bitcoin wallet" nocase
        $rw4 = "decrypt key" nocase
        $rw5 = "ransom note" nocase
        $rw6 = ".locked" nocase
        $rw7 = /vssadmin.*delete.*shadow/i nocase
    condition:
        any of them
}
"""


# ── Fallback Scanner (no yara-python needed) ──────────────────────

class _FallbackRule:
    """Lightweight pattern rule parsed from YARA source text."""

    def __init__(self, name: str, meta: Dict[str, str],
                 strings: List[str], is_nocase: List[bool]):
        self.name = name
        self.meta = meta
        self.patterns = []  # compiled regexes
        self.identifiers = strings

        import re
        for s, nc in zip(strings, is_nocase):
            flags = re.IGNORECASE if nc else 0
            try:
                self.patterns.append(re.compile(s, flags))
            except re.error:
                pass


def _parse_builtin_rules() -> List[_FallbackRule]:
    """Parse the built-in YARA source into lightweight regex rules."""
    import re

    rules = []
    # Split by 'rule <name> {'
    rule_blocks = re.split(r'\brule\s+(\w+)\s*\{', BUILTIN_YARA_SOURCE)

    i = 1
    while i < len(rule_blocks) - 1:
        name = rule_blocks[i].strip()
        body = rule_blocks[i + 1]
        i += 2

        # Parse meta section
        meta = {}  # type: Dict[str, str]
        meta_match = re.search(r'meta:\s*\n(.*?)(?=strings:|condition:|$)',
                               body, re.DOTALL)
        if meta_match:
            for m in re.finditer(r'(\w+)\s*=\s*"([^"]*)"', meta_match.group(1)):
                meta[m.group(1)] = m.group(2)

        # Parse strings section
        string_patterns = []
        is_nocase = []
        strings_match = re.search(r'strings:\s*\n(.*?)(?=condition:|$)',
                                  body, re.DOTALL)
        if strings_match:
            for line in strings_match.group(1).strip().split('\n'):
                line = line.strip()
                if not line or line.startswith('//'):
                    continue
                nc = 'nocase' in line.lower()

                # Regex pattern: $var = /pattern/
                rx = re.search(r'=\s*/(.*?)/[i]?', line)
                if rx:
                    string_patterns.append(rx.group(1))
                    is_nocase.append(nc)
                    continue

                # String pattern: $var = "string"
                sx = re.search(r'=\s*"([^"]*)"', line)
                if sx:
                    string_patterns.append(re.escape(sx.group(1)))
                    is_nocase.append(nc)

        if string_patterns:
            rules.append(_FallbackRule(name, meta, string_patterns, is_nocase))

    return rules


# ── Scanner ───────────────────────────────────────────────────────

class YaraScanner:
    """Scans log text against YARA rules for malware/tool identification."""

    def __init__(self, rules_dir: Optional[str] = None) -> None:
        self._yara_rules = None   # type: Any  # yara.Rules if available
        self._fallback_rules = []  # type: List[_FallbackRule]
        self._rule_count = 0
        self._using_yara = False

        if rules_dir is None:
            rules_dir = str(
                Path(__file__).resolve().parent / "rules" / "yara"
            )

        self._load_rules(rules_dir)

    def _load_rules(self, rules_dir: str) -> None:
        """Load YARA rules from directory + built-in rules."""
        rule_files = {}  # type: Dict[str, str]
        rules_path = Path(rules_dir)

        # Collect .yar and .yara files
        if rules_path.is_dir():
            for f in rules_path.glob("*.yar"):
                rule_files[f.stem] = str(f)
            for f in rules_path.glob("*.yara"):
                rule_files[f.stem] = str(f)

        if YARA_AVAILABLE:
            try:
                # Compile built-in + file-based rules
                sources = {"builtin": BUILTIN_YARA_SOURCE}
                if rule_files:
                    self._yara_rules = yara.compile(
                        sources=sources, filepaths=rule_files
                    )
                else:
                    self._yara_rules = yara.compile(sources=sources)

                self._using_yara = True
                self._rule_count = len(
                    list(self._yara_rules)
                ) if hasattr(self._yara_rules, '__iter__') else 10
                logger.info(
                    "YARA scanner loaded: native yara-python, "
                    "%d file rules + built-in rules",
                    len(rule_files),
                )
                return
            except Exception as exc:
                logger.warning("YARA compile failed: %s — using fallback", exc)

        # Fallback: parse built-in rules as regex
        self._fallback_rules = _parse_builtin_rules()
        self._rule_count = len(self._fallback_rules)
        logger.info(
            "YARA scanner loaded: fallback regex mode, %d built-in rules",
            self._rule_count,
        )

    def scan(self, log_text: str) -> List[YaraMatch]:
        """Scan log text and return all YARA matches."""
        if self._using_yara and self._yara_rules is not None:
            return self._scan_native(log_text)
        return self._scan_fallback(log_text)

    def _scan_native(self, log_text: str) -> List[YaraMatch]:
        """Scan using native yara-python."""
        results = []
        lines = log_text.split("\n")

        try:
            matches = self._yara_rules.match(data=log_text.encode("utf-8", errors="replace"))
        except Exception as exc:
            logger.warning("YARA scan error: %s", exc)
            return []

        for match in matches:
            meta = match.meta if hasattr(match, 'meta') else {}
            mitre_str = meta.get("mitre", "")
            mitre_techniques = [
                t.strip() for t in mitre_str.split(",") if t.strip()
            ]

            details = []
            if hasattr(match, 'strings'):
                for string_match in match.strings:
                    offset = string_match.offset if hasattr(string_match, 'offset') else 0
                    identifier = str(string_match.identifier) if hasattr(string_match, 'identifier') else ""
                    data = ""
                    if hasattr(string_match, 'instances'):
                        for inst in string_match.instances:
                            data = str(inst)[:100]
                            break
                    line_num, line_txt = self._offset_to_line(log_text, offset, lines)
                    details.append(YaraMatchDetail(
                        offset=offset,
                        identifier=identifier,
                        matched_data=data,
                        line_number=line_num,
                        line_text=line_txt,
                    ))

            results.append(YaraMatch(
                rule_name=match.rule,
                namespace=match.namespace if hasattr(match, 'namespace') else "",
                tags=list(match.tags) if hasattr(match, 'tags') else [],
                severity=meta.get("severity", "medium"),
                description=meta.get("description", ""),
                author=meta.get("author", ""),
                reference=meta.get("reference", ""),
                mitre_techniques=mitre_techniques,
                matched_strings=details,
            ))

        return results

    def _scan_fallback(self, log_text: str) -> List[YaraMatch]:
        """Scan using fallback regex rules."""
        import re
        results = []
        lines = log_text.split("\n")

        for rule in self._fallback_rules:
            details = []
            for pat_idx, pattern in enumerate(rule.patterns):
                for m in pattern.finditer(log_text):
                    offset = m.start()
                    line_num, line_txt = self._offset_to_line(
                        log_text, offset, lines
                    )
                    ident = rule.identifiers[pat_idx] if pat_idx < len(rule.identifiers) else ""
                    details.append(YaraMatchDetail(
                        offset=offset,
                        identifier=ident,
                        matched_data=m.group(0)[:100],
                        line_number=line_num,
                        line_text=line_txt,
                    ))

            if details:
                mitre_str = rule.meta.get("mitre", "")
                mitre_techniques = [
                    t.strip() for t in mitre_str.split(",") if t.strip()
                ]
                results.append(YaraMatch(
                    rule_name=rule.name,
                    namespace="builtin",
                    severity=rule.meta.get("severity", "medium"),
                    description=rule.meta.get("description", ""),
                    author=rule.meta.get("author", ""),
                    reference=rule.meta.get("reference", ""),
                    mitre_techniques=mitre_techniques,
                    matched_strings=details,
                ))

        return results

    @staticmethod
    def _offset_to_line(text: str, offset: int,
                        lines: List[str]) -> tuple:
        """Convert byte offset to line number and line text."""
        current = 0
        for i, line in enumerate(lines, start=1):
            end = current + len(line) + 1  # +1 for \n
            if offset < end:
                return i, line.strip()[:200]
            current = end
        return len(lines), ""

    @property
    def rule_count(self) -> int:
        return self._rule_count

    @property
    def engine_type(self) -> str:
        return "yara-python" if self._using_yara else "fallback-regex"
