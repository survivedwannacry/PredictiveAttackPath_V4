"""
PredictiveAttackPath — Regex Pattern Library for ATT&CK Technique Detection

Each entry maps a MITRE ATT&CK technique ID to one or more regex patterns
that match common log artifacts, command-line indicators, or event signatures.

Pattern structure:
    TECHNIQUE_PATTERNS = {
        "T1059.001": {
            "name": "PowerShell",
            "tactic": "execution",
            "patterns": [ <compiled regex>, ... ],
            "confidence": 0.9,  # base confidence for a match
        },
        ...
    }

Coverage target: 600+ technique/sub-technique IDs with at least one pattern each.
Patterns are designed for Windows Event Logs, Sysmon, Linux auditd, web server
logs, DNS logs, firewall logs, and common SIEM/EDR outputs.

NOTE: Confidence values are base scores; actual confidence is adjusted by
the number of distinct pattern matches within a single log block.
"""

from __future__ import annotations

import re
from typing import TypedDict


class TechniquePattern(TypedDict):
    name: str
    tactic: str
    patterns: list[re.Pattern]
    confidence: float


def _c(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern:
    """Compile a regex pattern with default IGNORECASE."""
    return re.compile(pattern, flags)


# ═══════════════════════════════════════════════════════════════════
#  TECHNIQUE PATTERNS — Organized by Tactic
# ═══════════════════════════════════════════════════════════════════

TECHNIQUE_PATTERNS: dict[str, TechniquePattern] = {}

def _register(tid: str, name: str, tactic: str, patterns: list[str],
              confidence: float = 0.85) -> None:
    """Helper to register a technique's patterns."""
    TECHNIQUE_PATTERNS[tid] = {
        "name": name,
        "tactic": tactic,
        "patterns": [_c(p) for p in patterns],
        "confidence": confidence,
    }


# ─── RECONNAISSANCE (TA0043) ─────────────────────────────────────

_register("T1595", "Active Scanning", "reconnaissance", [
    r"nmap\s+", r"masscan\s+", r"zmap\s+", r"rustscan\s+",
    r"scanning\s+port", r"port\s*scan",
], 0.80)
_register("T1595.001", "Scanning IP Blocks", "reconnaissance", [
    r"nmap\s+-s[STAUNFX]", r"masscan\s+--range",
    r"\b\d+\.\d+\.\d+\.\d+/\d+\b.*scan",
], 0.80)
_register("T1595.002", "Vulnerability Scanning", "reconnaissance", [
    r"nikto", r"openvas", r"nessus", r"qualys",
    r"acunetix", r"burpsuite|burp\s*suite", r"nuclei\s+",
], 0.80)
_register("T1595.003", "Wordlist Scanning", "reconnaissance", [
    r"gobuster", r"dirb\s+", r"dirbuster", r"ffuf\s+",
    r"wfuzz", r"feroxbuster",
], 0.80)
_register("T1592", "Gather Victim Host Information", "reconnaissance", [
    r"systeminfo", r"uname\s+-a", r"cat\s+/etc/os-release",
    r"wmic\s+os\s+get", r"hostnamectl",
], 0.75)
_register("T1592.001", "Hardware", "reconnaissance", [
    r"wmic\s+(cpu|memorychip|diskdrive)", r"lshw", r"dmidecode",
    r"cat\s+/proc/cpuinfo",
], 0.75)
_register("T1592.002", "Software", "reconnaissance", [
    r"wmic\s+product\s+get", r"dpkg\s+-l", r"rpm\s+-qa",
    r"apt\s+list\s+--installed", r"Get-WmiObject.*Win32_Product",
], 0.75)
_register("T1592.004", "Client Configurations", "reconnaissance", [
    r"reg\s+query.*\\Software\\", r"defaults\s+read",
], 0.70)
_register("T1589", "Gather Victim Identity Information", "reconnaissance", [
    r"linkedin.*scrape", r"theHarvester", r"hunter\.io",
    r"email.*harvest", r"recon-ng",
], 0.70)
_register("T1589.001", "Credentials", "reconnaissance", [
    r"haveibeenpwned", r"dehashed", r"credential.*dump.*paste",
    r"breach.*data", r"combolist",
], 0.75)
_register("T1589.002", "Email Addresses", "reconnaissance", [
    r"theHarvester", r"hunter\.io", r"email.*(enum|harvest|gather)",
], 0.70)
_register("T1590", "Gather Victim Network Information", "reconnaissance", [
    r"whois\s+", r"dig\s+", r"nslookup\s+",
    r"shodan", r"censys", r"amass\s+enum",
], 0.75)
_register("T1590.001", "Domain Properties", "reconnaissance", [
    r"whois\s+", r"amass\s+enum", r"subfinder",
    r"sublist3r", r"dnsrecon",
], 0.75)
_register("T1590.002", "DNS", "reconnaissance", [
    r"dig\s+", r"nslookup\s+", r"dnsrecon", r"dnsenum",
    r"fierce\s+", r"host\s+-t\s+",
], 0.75)
_register("T1590.004", "Network Topology", "reconnaissance", [
    r"traceroute", r"tracert", r"mtr\s+",
], 0.70)
_register("T1590.005", "IP Addresses", "reconnaissance", [
    r"shodan\s+", r"censys\s+", r"arin\.net",
], 0.70)
_register("T1591", "Gather Victim Org Information", "reconnaissance", [
    r"crunchbase", r"glassdoor.*scrape", r"linkedin.*company",
], 0.60)
_register("T1593", "Search Open Websites/Domains", "reconnaissance", [
    r"google\s+dork", r"inurl:", r"intext:", r"site:",
    r"filetype:", r"intitle:",
], 0.70)
_register("T1593.001", "Social Media", "reconnaissance", [
    r"twitter.*osint", r"facebook.*scrape", r"instagram.*enum",
], 0.60)
_register("T1593.002", "Search Engines", "reconnaissance", [
    r"google\s+dork", r"bing\s+dork", r"inurl:.*admin",
], 0.65)
_register("T1594", "Search Victim-Owned Websites", "reconnaissance", [
    r"wayback.*machine", r"web\.archive\.org", r"archive\.org/wayback",
], 0.60)
_register("T1596", "Search Open Technical Databases", "reconnaissance", [
    r"shodan\.io", r"censys\.io", r"zoomeye",
    r"binaryedge", r"crt\.sh",
], 0.70)
_register("T1596.005", "Scan Databases", "reconnaissance", [
    r"crt\.sh", r"certificate.*transparency",
], 0.65)
_register("T1597", "Search Closed Sources", "reconnaissance", [
    r"dark\s*web.*search", r"tor.*marketplace",
], 0.60)
_register("T1598", "Phishing for Information", "reconnaissance", [
    r"spearphish.*recon", r"credential.*phish.*form",
], 0.70)
_register("T1598.003", "Spearphishing Link", "reconnaissance", [
    r"phish.*link.*click", r"credential.*harvest.*link",
], 0.70)

# ─── RESOURCE DEVELOPMENT (TA0042) ───────────────────────────────

_register("T1583", "Acquire Infrastructure", "resource-development", [
    r"registered\s+domain", r"purchased.*vps",
    r"new\s+domain.*created",
], 0.60)
_register("T1583.001", "Domains", "resource-development", [
    r"newly.*registered.*domain", r"domain.*registration",
    r"whois.*creation.*date.*20[2-3]\d",
], 0.65)
_register("T1583.003", "Virtual Private Server", "resource-development", [
    r"vps.*provision", r"digitalocean|linode|vultr|aws.*ec2",
], 0.55)
_register("T1583.006", "Web Services", "resource-development", [
    r"pastebin\.com", r"github\.com.*raw", r"firebase.*hosting",
    r"ngrok\.io", r"cloudflare.*workers",
], 0.65)
_register("T1584", "Compromise Infrastructure", "resource-development", [
    r"compromised.*server", r"webshell.*uploaded",
], 0.65)
_register("T1585", "Establish Accounts", "resource-development", [
    r"fake.*account.*created", r"sockpuppet",
], 0.55)
_register("T1586", "Compromise Accounts", "resource-development", [
    r"account.*takeover", r"ato\b", r"compromised.*email.*account",
], 0.65)
_register("T1587", "Develop Capabilities", "resource-development", [
    r"custom.*malware", r"compiled.*payload",
], 0.55)
_register("T1587.001", "Malware", "resource-development", [
    r"custom.*trojan", r"developed.*rat\b", r"bespoke.*implant",
], 0.60)
_register("T1588", "Obtain Capabilities", "resource-development", [
    r"downloaded.*exploit", r"obtained.*tool",
], 0.55)
_register("T1588.001", "Malware", "resource-development", [
    r"cobalt\s*strike", r"metasploit", r"covenant\b",
    r"sliver\b", r"brute\s*ratel",
], 0.80)
_register("T1588.002", "Tool", "resource-development", [
    r"mimikatz", r"rubeus", r"bloodhound",
    r"sharphound", r"lazagne", r"impacket",
], 0.85)
_register("T1588.005", "Exploits", "resource-development", [
    r"exploit-db", r"0day", r"zero.?day",
    r"cve-\d{4}-\d+",
], 0.70)
_register("T1608", "Stage Capabilities", "resource-development", [
    r"staged.*payload", r"hosted.*malware", r"c2.*beacon.*staged",
], 0.65)
_register("T1608.001", "Upload Malware", "resource-development", [
    r"uploaded.*malware", r"hosted.*payload.*server",
], 0.65)

# ─── INITIAL ACCESS (TA0001) ─────────────────────────────────────

_register("T1189", "Drive-by Compromise", "initial-access", [
    r"watering\s*hole", r"drive.?by.*download",
    r"exploit\s*kit", r"iframe.*inject",
    r"<iframe\s+src=.*hidden",
], 0.80)
_register("T1190", "Exploit Public-Facing Application", "initial-access", [
    r"sql\s*injection", r"sqli\b", r"union\s+select",
    r"' OR '1'='1", r"xss", r"<script>",
    r"remote\s*code\s*execution", r"rce\b",
    r"CVE-\d{4}-\d+.*exploit",
    r"log4j|log4shell", r"shellshock",
    r"struts.*vuln", r"deserialization.*attack",
    r"webshell.*upload",
], 0.90)
_register("T1133", "External Remote Services", "initial-access", [
    r"vpn.*login", r"rdp.*external", r"citrix.*access",
    r"pulse\s*secure", r"fortinet.*vpn",
    r"ssh.*external.*connect", r"remote\s*desktop.*internet",
], 0.80)
_register("T1200", "Hardware Additions", "initial-access", [
    r"usb.*device.*inserted", r"rubber\s*ducky",
    r"bash\s*bunny", r"lan\s*turtle",
    r"unauthorized.*hardware",
], 0.75)
_register("T1566", "Phishing", "initial-access", [
    r"phish", r"spearphish",
    r"suspicious.*email.*attachment",
    r"malicious.*link.*email",
], 0.85)
_register("T1566.001", "Spearphishing Attachment", "initial-access", [
    r"spearphish.*attach", r"malicious.*\.(doc[xm]?|xls[xm]?|ppt[xm]?|pdf|zip|rar)",
    r"macro.*enabled.*document", r"email.*attachment.*executed",
    r"\.hta\s+attachment", r"oletools|olevba",
    r"vba.*macro.*email",
], 0.90)
_register("T1566.002", "Spearphishing Link", "initial-access", [
    r"spearphish.*link", r"credential.*harvest.*email",
    r"phishing.*url", r"clicked.*malicious.*link",
    r"email.*suspicious.*url",
], 0.85)
_register("T1566.003", "Spearphishing via Service", "initial-access", [
    r"teams.*phish", r"slack.*malicious.*link",
    r"discord.*payload", r"social\s*media.*phish",
], 0.80)
_register("T1199", "Trusted Relationship", "initial-access", [
    r"supply\s*chain", r"third.?party.*compromise",
    r"vendor.*access.*abuse", r"msp.*compromise",
], 0.75)
_register("T1078", "Valid Accounts", "initial-access", [
    r"valid.*credential", r"legitimate.*account",
    r"compromised.*password", r"stolen.*credential",
    r"credential.*stuffing", r"password.*spray",
    r"brute.?force.*success",
], 0.85)
_register("T1078.001", "Default Accounts", "initial-access", [
    r"default.*password", r"admin[:/]admin", r"root[:/]root",
    r"test[:/]test", r"default.*credential",
], 0.85)
_register("T1078.002", "Domain Accounts", "initial-access", [
    r"domain.*account.*compromised",
    r"ad\s*account.*stolen", r"kerberos.*ticket.*stolen",
], 0.85)
_register("T1078.003", "Local Accounts", "initial-access", [
    r"local.*admin.*compromised", r"local.*account.*brute",
], 0.80)
_register("T1078.004", "Cloud Accounts", "initial-access", [
    r"azure.*ad.*compromised", r"aws.*iam.*compromised",
    r"gcp.*account.*stolen", r"o365.*credential",
    r"cloud.*account.*takeover",
], 0.85)
_register("T1195", "Supply Chain Compromise", "initial-access", [
    r"supply.?chain", r"solarwinds", r"codecov",
    r"compromised.*update", r"trojanized.*package",
    r"typosquat", r"dependency.*confusion",
], 0.85)
_register("T1195.001", "Compromise Software Dependencies", "initial-access", [
    r"npm.*malicious.*package", r"pypi.*backdoor",
    r"dependency.*confusion", r"typosquat.*package",
], 0.80)
_register("T1195.002", "Compromise Software Supply Chain", "initial-access", [
    r"compromised.*update.*server", r"trojanized.*installer",
    r"signed.*malware", r"solarwinds",
], 0.85)

# ─── EXECUTION (TA0002) ──────────────────────────────────────────

_register("T1059", "Command and Scripting Interpreter", "execution", [
    r"cmd\.exe", r"command.*shell", r"/bin/sh", r"/bin/bash",
    r"powershell", r"wscript", r"cscript",
    r"python\s+.*\.py", r"perl\s+.*\.pl",
], 0.85)
_register("T1059.001", "PowerShell", "execution", [
    r"powershell\.exe", r"pwsh\.exe", r"powershell\s+-",
    r"-encodedcommand", r"-enc\s+", r"-e\s+[A-Za-z0-9+/=]{20,}",
    r"invoke-expression", r"iex\s*\(", r"invoke-command",
    r"invoke-webrequest", r"iwr\s+", r"downloadstring",
    r"downloadfile", r"new-object.*net\.webclient",
    r"system\.net\.webclient",
    r"invoke-mimikatz", r"invoke-shellcode",
    r"bypass.*executionpolicy", r"-ep\s+bypass",
    r"set-executionpolicy\s+bypass",
    r"import-module.*\.ps1", r"\.ps1\b",
    r"powershell.*-nop\b", r"-windowstyle\s+hidden",
    r"powershell.*-w\s+hidden",
    r"add-type.*-typedefinition",
    r"\[System\.Convert\]::FromBase64String",
    r"New-Object\s+IO\.MemoryStream",
    r"Invoke-Obfuscation",
], 0.95)
_register("T1059.002", "AppleScript", "execution", [
    r"osascript\s+-e", r"applescript",
    r"do\s+shell\s+script",
], 0.85)
_register("T1059.003", "Windows Command Shell", "execution", [
    r"cmd\.exe\s*/c", r"cmd\.exe\s*/k",
    r"cmd\s*/c\s+", r"command\.com",
    r"cmd\.exe.*&&", r"cmd\.exe.*\|",
], 0.85)
_register("T1059.004", "Unix Shell", "execution", [
    r"/bin/bash\s+-c", r"/bin/sh\s+-c",
    r"bash\s+-i\s+", r"sh\s+-c\s+",
    r"/dev/tcp/", r"mkfifo.*nc\b",
    r"bash.*reverse.*shell",
], 0.85)
_register("T1059.005", "Visual Basic", "execution", [
    r"wscript\.exe", r"cscript\.exe",
    r"\.vbs\b", r"\.vbe\b",
    r"vbscript", r"wscript\.shell",
    r"createobject.*wscript",
], 0.85)
_register("T1059.006", "Python", "execution", [
    r"python[23]?\s+-c\s+", r"python.*import\s+os",
    r"python.*subprocess", r"python.*exec\(",
    r"python.*eval\(",
], 0.80)
_register("T1059.007", "JavaScript", "execution", [
    r"node\s+-e", r"\.js\b.*execute",
    r"wscript.*\.js\b", r"cscript.*\.js\b",
    r"jscript",
], 0.80)
_register("T1059.008", "Network Device CLI", "execution", [
    r"enable\s*\n.*configure\s+terminal",
    r"cisco.*exec", r"junos.*cli",
], 0.75)
_register("T1059.009", "Cloud API", "execution", [
    r"aws\s+.*--region", r"az\s+.*--subscription",
    r"gcloud\s+.*--project",
], 0.75)
_register("T1203", "Exploitation for Client Execution", "execution", [
    r"exploit.*client", r"browser.*exploit",
    r"CVE-\d{4}-\d+.*client", r"heap.*spray",
    r"use.?after.?free", r"buffer\s*overflow",
], 0.80)
_register("T1204", "User Execution", "execution", [
    r"user.*clicked", r"user.*opened.*attachment",
    r"user.*executed", r"double.?click",
], 0.75)
_register("T1204.001", "Malicious Link", "execution", [
    r"user.*click.*link", r"opened.*url.*malicious",
], 0.75)
_register("T1204.002", "Malicious File", "execution", [
    r"user.*open.*attachment", r"executed.*macro",
    r"enabled.*content", r"opened.*\.exe",
], 0.80)
_register("T1047", "Windows Management Instrumentation", "execution", [
    r"wmic\s+", r"wmic.*process\s+call\s+create",
    r"wmic.*node:", r"invoke-wmimethod",
    r"get-wmiobject", r"gwmi\s+",
    r"winmgmts:", r"ManagementClass",
    r"wmiprvse\.exe",
], 0.90)
_register("T1053", "Scheduled Task/Job", "execution", [
    r"schtasks", r"at\s+\d+:\d+", r"crontab",
    r"systemd.*timer", r"launchd",
], 0.85)
_register("T1053.002", "At", "execution", [
    r"\bat\s+\d+:\d+", r"at\.exe\s+",
], 0.80)
_register("T1053.003", "Cron", "execution", [
    r"crontab\s+-[el]", r"/etc/cron", r"cron\.d/",
    r"\*/\d+\s+\*", r"@reboot\s+",
], 0.85)
_register("T1053.005", "Scheduled Task", "execution", [
    r"schtasks\s*/create", r"schtasks\s*/run",
    r"schtasks\s*/change", r"schtasks.*/(tn|tr|sc)\s+",
    r"register-scheduledtask", r"new-scheduledtask",
    r"scheduledtasks.*xml",
], 0.90)
_register("T1053.006", "Systemd Timers", "execution", [
    r"systemctl.*timer", r"\.timer\b.*\[Timer\]",
], 0.80)
_register("T1053.007", "Container Orchestration Job", "execution", [
    r"kubectl.*create.*job", r"cronjob.*kubernetes",
], 0.75)
_register("T1569", "System Services", "execution", [
    r"sc\s+(create|start|config)", r"service\s+.*start",
    r"systemctl\s+start", r"net\s+start",
], 0.80)
_register("T1569.001", "Launchctl", "execution", [
    r"launchctl\s+(load|submit)", r"launchd",
], 0.80)
_register("T1569.002", "Service Execution", "execution", [
    r"sc\.exe\s+create", r"sc\s+\\\\.*create",
    r"psexec.*-s\s+", r"psexec\.exe",
    r"new-service", r"install.*service",
], 0.85)
_register("T1106", "Native API", "execution", [
    r"CreateRemoteThread", r"NtCreateThread",
    r"VirtualAllocEx", r"WriteProcessMemory",
    r"CreateProcess[AW]?", r"ShellExecute[AW]?",
    r"WinExec\(", r"ntdll\.dll",
    r"kernel32\.dll.*LoadLibrary",
], 0.85)
_register("T1129", "Shared Modules", "execution", [
    r"LoadLibrary[AW]?", r"GetProcAddress",
    r"dlopen\(", r"dlsym\(",
], 0.75)
_register("T1559", "Inter-Process Communication", "execution", [
    r"dcom\b", r"dde\b", r"com\s*object",
], 0.75)
_register("T1559.001", "Component Object Model", "execution", [
    r"createobject\(", r"dcom.*lateral",
    r"comobj", r"[Cc]OM\s*object",
    r"MMC20\.Application", r"ShellWindows",
], 0.80)
_register("T1559.002", "Dynamic Data Exchange", "execution", [
    r"dde\s*(auto)?", r"ddeexec",
    r"=cmd\|", r"DDEAUTO",
], 0.80)
_register("T1610", "Deploy Container", "execution", [
    r"docker\s+run", r"kubectl\s+run",
    r"podman\s+run", r"container.*deploy",
], 0.75)
_register("T1648", "Serverless Execution", "execution", [
    r"lambda.*invoke", r"cloud\s*function.*execute",
    r"azure\s*function.*trigger",
], 0.70)

# ─── PERSISTENCE (TA0003) ────────────────────────────────────────

_register("T1098", "Account Manipulation", "persistence", [
    r"net\s+user.*\/add", r"net\s+localgroup.*\/add",
    r"useradd", r"adduser\s+",
    r"usermod\s+-aG", r"Add-LocalGroupMember",
    r"net\s+group.*\/add.*\/domain",
], 0.90)
_register("T1098.001", "Additional Cloud Credentials", "persistence", [
    r"az\s+ad\s+sp\s+credential", r"aws\s+iam\s+create-access-key",
    r"New-AzureADServicePrincipalCredential",
], 0.85)
_register("T1098.002", "Additional Email Delegate Permissions", "persistence", [
    r"Add-MailboxPermission", r"Set-MailboxFolderPermission",
    r"inbox\s*rule.*forward",
], 0.80)
_register("T1098.003", "Additional Cloud Roles", "persistence", [
    r"az\s+role\s+assignment\s+create", r"aws\s+iam\s+attach.*policy",
    r"Add-AzureADDirectoryRoleMember",
], 0.80)
_register("T1098.004", "SSH Authorized Keys", "persistence", [
    r"authorized_keys", r"ssh-rsa.*>>.*authorized",
    r"\.ssh/authorized_keys",
], 0.90)
_register("T1547", "Boot or Logon Autostart Execution", "persistence", [
    r"CurrentVersion\\\\Run", r"HKLM\\\\.*\\\\Run\b",
    r"HKCU\\\\.*\\\\Run\b", r"Startup\s*folder",
], 0.90)
_register("T1547.001", "Registry Run Keys / Startup Folder", "persistence", [
    r"reg\s+add.*\\\\Run\s", r"CurrentVersion\\\\Run",
    r"CurrentVersion\\\\RunOnce",
    r"HKLM.*SOFTWARE.*Microsoft.*Windows.*CurrentVersion.*Run",
    r"HKCU.*SOFTWARE.*Microsoft.*Windows.*CurrentVersion.*Run",
    r"shell:startup", r"Start\s*Menu.*Startup",
    r"New-ItemProperty.*-Path.*Run\b",
], 0.95)
_register("T1547.002", "Authentication Package", "persistence", [
    r"Authentication\s*Packages", r"HKLM.*SYSTEM.*Lsa\b",
], 0.80)
_register("T1547.003", "Time Providers", "persistence", [
    r"W32Time", r"TimeProviders.*DllName",
], 0.75)
_register("T1547.004", "Winlogon Helper DLL", "persistence", [
    r"Winlogon.*Shell", r"Winlogon.*Userinit",
    r"Winlogon.*Notify",
], 0.85)
_register("T1547.005", "Security Support Provider", "persistence", [
    r"Security\s*Packages.*ssp", r"AddSecurityPackage",
    r"HKLM.*SYSTEM.*Lsa.*Security Packages",
], 0.80)
_register("T1547.006", "Kernel Modules and Extensions", "persistence", [
    r"insmod\s+", r"modprobe\s+", r"kextload",
    r"/lib/modules/", r"\.ko\b.*load",
], 0.85)
_register("T1547.009", "Shortcut Modification", "persistence", [
    r"\.lnk\b.*modif", r"shortcut.*target.*changed",
    r"wscript\.shell.*createshortcut",
], 0.80)
_register("T1547.012", "Print Processors", "persistence", [
    r"Print.*Processors.*Driver", r"AddPrintProcessor",
], 0.75)
_register("T1547.014", "Active Setup", "persistence", [
    r"Active\s*Setup.*StubPath", r"HKLM.*Active Setup.*Installed Components",
], 0.80)
_register("T1547.015", "Login Items", "persistence", [
    r"loginitems", r"SMLoginItemSetEnabled",
    r"LaunchAgents", r"loginwindow",
], 0.80)
_register("T1136", "Create Account", "persistence", [
    r"net\s+user\s+\w+\s+.*\/add",
    r"useradd\s+", r"adduser\s+",
    r"New-LocalUser", r"New-ADUser",
], 0.90)
_register("T1136.001", "Local Account", "persistence", [
    r"net\s+user\s+\w+\s+.*\/add",
    r"useradd\s+", r"New-LocalUser",
], 0.90)
_register("T1136.002", "Domain Account", "persistence", [
    r"New-ADUser", r"dsadd\s+user",
    r"net\s+user.*\/add.*\/domain",
], 0.90)
_register("T1136.003", "Cloud Account", "persistence", [
    r"aws\s+iam\s+create-user", r"az\s+ad\s+user\s+create",
    r"New-AzureADUser",
], 0.85)
_register("T1543", "Create or Modify System Process", "persistence", [
    r"sc\s+(create|config)", r"systemctl\s+(enable|daemon-reload)",
    r"new-service",
], 0.85)
_register("T1543.001", "Launch Agent", "persistence", [
    r"LaunchAgents.*plist", r"launchctl\s+load",
    r"com\.apple\..*\.plist",
], 0.85)
_register("T1543.002", "Systemd Service", "persistence", [
    r"/etc/systemd/system/.*\.service",
    r"systemctl\s+enable", r"systemctl\s+daemon-reload",
    r"\[Service\].*ExecStart",
], 0.90)
_register("T1543.003", "Windows Service", "persistence", [
    r"sc\s+create\s+", r"New-Service\s+",
    r"sc\.exe.*binPath=",
    r"HKLM.*SYSTEM.*Services.*ImagePath",
], 0.90)
_register("T1543.004", "Launch Daemon", "persistence", [
    r"LaunchDaemons.*plist", r"/Library/LaunchDaemons",
], 0.85)
_register("T1546", "Event Triggered Execution", "persistence", [
    r"WMI.*event.*subscription", r"trap\s+.*signal",
], 0.80)
_register("T1546.001", "Change Default File Association", "persistence", [
    r"assoc\s+\.\w+=", r"ftype\s+",
    r"HKCR.*\\\\shell\\\\open\\\\command",
], 0.80)
_register("T1546.002", "Screensaver", "persistence", [
    r"SCRNSAVE\.exe", r"ScreenSaveActive.*1",
    r"Desktop.*ScreenSaver",
], 0.75)
_register("T1546.003", "Windows Management Instrumentation Event Subscription", "persistence", [
    r"__EventFilter", r"CommandLineEventConsumer",
    r"ActiveScriptEventConsumer",
    r"__FilterToConsumerBinding",
    r"wmic.*__eventfilter",
    r"Register-WmiEvent",
], 0.90)
_register("T1546.004", "Unix Shell Configuration Modification", "persistence", [
    r"\.bashrc\b", r"\.bash_profile\b", r"\.zshrc\b",
    r"\.profile\b", r"/etc/profile\.d/",
    r"echo.*>>.*bashrc", r"echo.*>>.*profile",
], 0.85)
_register("T1546.008", "Accessibility Features", "persistence", [
    r"sethc\.exe", r"utilman\.exe", r"osk\.exe",
    r"magnify\.exe", r"narrator\.exe",
    r"sticky\s*keys.*backdoor",
    r"debugger.*sethc",
], 0.90)
_register("T1546.010", "AppInit DLLs", "persistence", [
    r"AppInit_DLLs", r"HKLM.*Windows NT.*Windows.*AppInit",
], 0.85)
_register("T1546.011", "Application Shimming", "persistence", [
    r"sdbinst\.exe", r"\.sdb\b.*install",
    r"application.*compatibility.*shim",
], 0.80)
_register("T1546.012", "Image File Execution Options Injection", "persistence", [
    r"IFEO", r"Image File Execution Options",
    r"Debugger.*=.*cmd\.exe",
    r"HKLM.*Image File Execution Options.*Debugger",
], 0.85)
_register("T1546.013", "PowerShell Profile", "persistence", [
    r"Microsoft\.PowerShell_profile\.ps1",
    r"\$PROFILE\b", r"profile\.ps1",
], 0.85)
_register("T1546.015", "Component Object Model Hijacking", "persistence", [
    r"InprocServer32", r"CLSID.*InprocServer",
    r"COM.*hijack", r"HKCU.*CLSID",
], 0.85)
_register("T1133", "External Remote Services", "persistence", [
    r"vpn.*persistent", r"rdp.*enabled",
    r"ssh.*backdoor.*port",
], 0.75)
_register("T1574", "Hijack Execution Flow", "persistence", [
    r"dll.*hijack", r"dll.*sideload",
    r"path.*interception", r"LD_PRELOAD",
], 0.85)
_register("T1574.001", "DLL Search Order Hijacking", "persistence", [
    r"dll.*search.*order", r"phantom.*dll",
    r"dll.*planted",
], 0.85)
_register("T1574.002", "DLL Side-Loading", "persistence", [
    r"dll.*side.?load", r"legitimate.*exe.*malicious.*dll",
], 0.85)
_register("T1574.004", "Dylib Hijacking", "persistence", [
    r"dylib.*hijack", r"DYLD_INSERT_LIBRARIES",
], 0.80)
_register("T1574.006", "Dynamic Linker Hijacking", "persistence", [
    r"LD_PRELOAD", r"ld\.so\.preload",
    r"/etc/ld\.so\.preload",
], 0.85)
_register("T1574.007", "Path Interception by PATH Environment Variable", "persistence", [
    r"PATH=.*:", r"export\s+PATH=",
    r"SetEnvironmentVariable.*PATH",
], 0.70)
_register("T1574.008", "Path Interception by Search Order Hijacking", "persistence", [
    r"executable.*path.*interception", r"placed.*exe.*in.*path",
], 0.75)
_register("T1574.009", "Path Interception by Unquoted Service Path", "persistence", [
    r"unquoted.*service.*path", r"sc.*qc.*BINARY_PATH.*spaces",
], 0.80)
_register("T1574.011", "Services Registry Permissions Weakness", "persistence", [
    r"HKLM.*SYSTEM.*Services.*ImagePath.*modif",
], 0.80)
_register("T1574.012", "COR_PROFILER", "persistence", [
    r"COR_PROFILER", r"COR_ENABLE_PROFILING",
], 0.80)
_register("T1556", "Modify Authentication Process", "persistence", [
    r"pam\.d/", r"pam_unix.*modif",
    r"password.*filter.*dll",
    r"PasswordFilterDll",
], 0.85)
_register("T1556.001", "Domain Controller Authentication", "persistence", [
    r"skeleton\s*key", r"mimikatz.*misc::skeleton",
    r"password.*filter.*dc",
], 0.90)
_register("T1556.003", "Pluggable Authentication Modules", "persistence", [
    r"pam_unix\.so.*modif", r"/etc/pam\.d/",
    r"pam.*backdoor",
], 0.85)
_register("T1137", "Office Application Startup", "persistence", [
    r"XLSTART", r"Office.*Startup",
    r"\.otm\b", r"VbaProject\.OTM",
    r"PERSONAL\.XLSB",
], 0.80)
_register("T1137.001", "Office Template Macros", "persistence", [
    r"Normal\.dotm", r"\.dotm\b.*macro",
], 0.80)
_register("T1505", "Server Software Component", "persistence", [
    r"webshell", r"web\s*shell", r"backdoor.*iis",
], 0.85)
_register("T1505.003", "Web Shell", "persistence", [
    r"webshell", r"web\s*shell",
    r"cmd\.asp", r"chopper", r"china\s*chopper",
    r"c99\.php", r"r57\.php", r"b374k",
    r"\.asp[x]?.*cmd.*exec", r"\.php.*system\s*\(",
    r"\.jsp.*Runtime.*exec",
    r"eval\s*\(\s*\$_(POST|GET|REQUEST)",
], 0.95)
_register("T1505.004", "IIS Components", "persistence", [
    r"iis.*module.*install", r"appcmd.*add\s+module",
    r"isapi.*filter",
], 0.80)
_register("T1205", "Traffic Signaling", "persistence", [
    r"port\s*knocking", r"knock\s+.*sequence",
    r"single\s*packet\s*authorization",
], 0.75)
_register("T1205.001", "Port Knocking", "persistence", [
    r"port\s*knock", r"knockd", r"knock\.conf",
], 0.75)
_register("T1525", "Implant Internal Image", "persistence", [
    r"docker.*image.*backdoor", r"container.*image.*modif",
    r"ecr.*push.*malicious",
], 0.75)
_register("T1542", "Pre-OS Boot", "persistence", [
    r"bootkit", r"mbr.*modif", r"uefi.*implant",
], 0.85)
_register("T1542.001", "System Firmware", "persistence", [
    r"firmware.*implant", r"bios.*modif", r"uefi.*rootkit",
], 0.85)
_register("T1542.003", "Bootkit", "persistence", [
    r"bootkit", r"mbr.*infect", r"vbr.*modif",
    r"master\s*boot\s*record.*overwrite",
], 0.85)

# ─── PRIVILEGE ESCALATION (TA0004) ───────────────────────────────

_register("T1548", "Abuse Elevation Control Mechanism", "privilege-escalation", [
    r"uac\s*bypass", r"sudo\s+-l", r"runas\s+",
], 0.85)
_register("T1548.001", "Setuid and Setgid", "privilege-escalation", [
    r"chmod\s+[u+]*s", r"chmod\s+[2467]\d{3}",
    r"find.*-perm.*4000", r"find.*-perm.*2000",
    r"suid\b", r"sgid\b",
], 0.85)
_register("T1548.002", "Bypass User Account Control", "privilege-escalation", [
    r"uac\s*bypass", r"eventvwr\.exe.*mscfile",
    r"fodhelper\.exe", r"computerdefaults\.exe",
    r"sdclt\.exe.*bypass",
    r"HKCU.*ms-settings", r"HKCU.*mscfile",
    r"cmstp\.exe.*/s", r"pkgmgr\.exe",
], 0.90)
_register("T1548.003", "Sudo and Sudo Caching", "privilege-escalation", [
    r"sudo\s+-l", r"sudo.*NOPASSWD",
    r"/etc/sudoers", r"visudo",
    r"sudo\s+su\s*$", r"timestamp_timeout",
], 0.85)
_register("T1548.004", "Elevated Execution with Prompt", "privilege-escalation", [
    r"osascript.*administrator", r"AuthorizationExecuteWithPrivileges",
], 0.80)
_register("T1134", "Access Token Manipulation", "privilege-escalation", [
    r"token.*impersonat", r"token.*manipulat",
    r"DuplicateToken", r"ImpersonateLoggedOnUser",
    r"SetThreadToken", r"AdjustTokenPrivileges",
], 0.85)
_register("T1134.001", "Token Impersonation/Theft", "privilege-escalation", [
    r"ImpersonateNamedPipeClient", r"DuplicateToken",
    r"token.*steal", r"incognito.*impersonate",
    r"potato.*exploit", r"juicypotato|sweetpotato|rottenpotato",
], 0.90)
_register("T1134.002", "Create Process with Token", "privilege-escalation", [
    r"CreateProcessWithToken", r"CreateProcessAsUser",
    r"runas\s*/user:", r"CreateProcessWithLogon",
], 0.85)
_register("T1134.003", "Make and Impersonate Token", "privilege-escalation", [
    r"LogonUser", r"ImpersonateLoggedOnUser",
    r"maketoken\b",
], 0.80)
_register("T1134.005", "SID-History Injection", "privilege-escalation", [
    r"sid.?history", r"mimikatz.*sid",
    r"Get-ADUser.*SIDHistory",
], 0.85)
_register("T1068", "Exploitation for Privilege Escalation", "privilege-escalation", [
    r"local.*privilege.*escalation", r"lpe\b",
    r"CVE-\d{4}-\d+.*priv.*esc",
    r"kernel.*exploit", r"dirty.*cow",
    r"dirty.*pipe", r"print.*nightmare",
    r"spoolsv", r"CVE-2021-1675",
    r"pwnkit", r"CVE-2021-4034",
], 0.90)
_register("T1055", "Process Injection", "privilege-escalation", [
    r"process.*inject", r"inject.*process",
    r"VirtualAllocEx", r"WriteProcessMemory",
    r"CreateRemoteThread", r"NtCreateThread",
    r"QueueUserAPC", r"NtQueueApcThread",
], 0.90)
_register("T1055.001", "Dynamic-link Library Injection", "privilege-escalation", [
    r"dll.*inject", r"inject.*dll",
    r"LoadLibrary.*remote", r"CreateRemoteThread.*LoadLibrary",
], 0.90)
_register("T1055.002", "Portable Executable Injection", "privilege-escalation", [
    r"pe.*inject", r"reflective.*load",
    r"reflective.*inject",
], 0.85)
_register("T1055.003", "Thread Execution Hijacking", "privilege-escalation", [
    r"SuspendThread.*SetThreadContext",
    r"thread.*hijack",
], 0.85)
_register("T1055.004", "Asynchronous Procedure Call", "privilege-escalation", [
    r"QueueUserAPC", r"NtQueueApcThread",
    r"apc.*inject",
], 0.85)
_register("T1055.005", "Thread Local Storage", "privilege-escalation", [
    r"tls.*callback.*inject", r"TLS.*inject",
], 0.80)
_register("T1055.008", "Ptrace System Calls", "privilege-escalation", [
    r"ptrace\s*\(", r"PTRACE_ATTACH",
    r"PTRACE_POKETEXT",
], 0.85)
_register("T1055.009", "Proc Memory", "privilege-escalation", [
    r"/proc/\d+/mem", r"/proc/\d+/maps",
], 0.85)
_register("T1055.012", "Process Hollowing", "privilege-escalation", [
    r"process.*hollow", r"hollow.*process",
    r"NtUnmapViewOfSection.*WriteProcessMemory",
    r"RunPE", r"ZwUnmapViewOfSection",
], 0.90)
_register("T1055.013", "Process Doppelganging", "privilege-escalation", [
    r"process.*doppelganging", r"NtCreateTransaction",
    r"transacted.*file",
], 0.85)
_register("T1055.014", "VDSO Hijacking", "privilege-escalation", [
    r"vdso.*hijack", r"\[vdso\]",
], 0.80)
_register("T1055.015", "ListPlanting", "privilege-escalation", [
    r"listplanting", r"LVM_SORTITEMS",
], 0.75)

# ─── DEFENSE EVASION (TA0005) ────────────────────────────────────

_register("T1027", "Obfuscated Files or Information", "defense-evasion", [
    r"obfuscat", r"encoded.*payload", r"packed.*binary",
    r"base64.*decode", r"certutil.*-decode",
    r"char\s*\(\s*\d+\s*\)", r"frombase64string",
    r"xor.*encrypt", r"encrypted.*payload",
], 0.85)
_register("T1027.001", "Binary Padding", "defense-evasion", [
    r"binary.*pad", r"inflated.*size",
    r"null.*bytes.*append",
], 0.70)
_register("T1027.002", "Software Packing", "defense-evasion", [
    r"upx", r"themida", r"vmprotect",
    r"aspack", r"packed.*entropy",
], 0.80)
_register("T1027.003", "Steganography", "defense-evasion", [
    r"steganograph", r"stego\b",
    r"hidden.*data.*image",
    r"lsb.*embedding",
], 0.75)
_register("T1027.004", "Compile After Delivery", "defense-evasion", [
    r"csc\.exe.*compile", r"gcc\s+.*-o\s+",
    r"msbuild.*\.csproj",
], 0.80)
_register("T1027.005", "Indicator Removal from Tools", "defense-evasion", [
    r"string.*strip", r"indicator.*remov",
    r"timestomp",
], 0.75)
_register("T1027.006", "HTML Smuggling", "defense-evasion", [
    r"html.*smuggl", r"javascript.*blob.*download",
    r"mshta.*javascript", r"data:application/octet-stream",
], 0.85)
_register("T1027.009", "Embedded Payloads", "defense-evasion", [
    r"embedded.*payload", r"payload.*embedded.*resource",
], 0.75)
_register("T1027.010", "Command Obfuscation", "defense-evasion", [
    r"cmd.*\^.*\^", r"invoke-obfuscation",
    r"set.*=.*&&.*call\s+%",
    r"cmd.*\/V:ON",
], 0.85)
_register("T1027.011", "Fileless Storage", "defense-evasion", [
    r"registry.*blob.*store", r"wmi.*store.*payload",
    r"fileless\b",
], 0.80)
_register("T1140", "Deobfuscate/Decode Files or Information", "defense-evasion", [
    r"certutil\s.*-decode", r"certutil\s.*-urlcache",
    r"base64\s+-d", r"base64.*decode",
    r"openssl\s+enc\s+-d",
    r"ConvertTo-SecureString",
    r"FromBase64String",
], 0.85)
_register("T1070", "Indicator Removal", "defense-evasion", [
    r"clear.*log", r"wevtutil.*cl",
    r"rm\s+.*\.log", r"del\s+.*\.log",
    r"shred\s+", r"wipe\s+",
], 0.85)
_register("T1070.001", "Clear Windows Event Logs", "defense-evasion", [
    r"wevtutil\s+cl", r"Clear-EventLog",
    r"Remove-EventLog", r"wevtutil.*clear",
    r"for\s*/F.*wevtutil.*cl",
], 0.95)
_register("T1070.002", "Clear Linux or Mac System Logs", "defense-evasion", [
    r"rm\s+.*(/var/log|\.bash_history|\.zsh_history)",
    r"truncate.*-s\s*0.*/var/log",
    r"echo\s*>\s*/var/log/", r"shred.*log",
    r"history\s+-c", r"unset\s+HISTFILE",
    r"export\s+HISTFILE=/dev/null",
], 0.90)
_register("T1070.003", "Clear Command History", "defense-evasion", [
    r"history\s+-c", r"history\s+-w\s*/dev/null",
    r"unset\s+HISTFILE", r"export\s+HISTSIZE=0",
    r"rm.*\.bash_history", r"Clear-History",
    r"Remove-Item.*ConsoleHost_history",
], 0.90)
_register("T1070.004", "File Deletion", "defense-evasion", [
    r"del\s+/[fq]", r"rm\s+-[rf]",
    r"sdelete", r"cipher\s+/w",
    r"Remove-Item.*-Force",
], 0.80)
_register("T1070.005", "Network Share Connection Removal", "defense-evasion", [
    r"net\s+use\s+.*\/delete", r"net\s+use\s+\*\s+/d",
], 0.80)
_register("T1070.006", "Timestomp", "defense-evasion", [
    r"timestomp", r"touch\s+-[td]\s+",
    r"SetFileTime", r"NtSetInformationFile",
    r"\$\w+\.LastWriteTime\s*=",
    r"Get-Item.*\.CreationTime\s*=",
], 0.90)
_register("T1070.009", "Clear Persistence", "defense-evasion", [
    r"schtasks\s*/delete", r"sc\s+delete",
    r"reg\s+delete.*\\\\Run\b",
], 0.80)
_register("T1036", "Masquerading", "defense-evasion", [
    r"rename.*svchost", r"masquerad",
    r"\.exe.*\.txt\.exe", r"double.*extension",
], 0.80)
_register("T1036.001", "Invalid Code Signature", "defense-evasion", [
    r"invalid.*signature", r"unsigned.*binary",
    r"code.*sign.*mismatch",
], 0.75)
_register("T1036.003", "Rename System Utilities", "defense-evasion", [
    r"copy.*cmd\.exe", r"rename.*powershell",
    r"ren.*svchost", r"copied.*system32",
], 0.85)
_register("T1036.004", "Masquerade Task or Service", "defense-evasion", [
    r"svchost.*non.?standard.*path",
    r"services\.exe.*unexpected",
    r"fake.*service.*name",
], 0.80)
_register("T1036.005", "Match Legitimate Name or Location", "defense-evasion", [
    r"svch0st\.exe", r"svchost.*temp",
    r"csrss.*appdata", r"lsass.*temp",
    r"explore\.exe", r"svchosts\.exe",
], 0.85)
_register("T1036.006", "Space after Filename", "defense-evasion", [
    r"\.\w+\s+\.exe", r"filename\s+\.exe",
], 0.70)
_register("T1036.007", "Double File Extension", "defense-evasion", [
    r"\.\w+\.\w+\.exe", r"\.pdf\.exe", r"\.doc\.exe",
    r"\.jpg\.exe", r"\.txt\.exe",
], 0.85)
_register("T1036.008", "Masquerade File Type", "defense-evasion", [
    r"rtlo|right.to.left.*override", r"\u202e",
], 0.80)
_register("T1218", "System Binary Proxy Execution", "defense-evasion", [
    r"mshta\b", r"regsvr32\b", r"rundll32\b",
    r"certutil\b.*-urlcache", r"msiexec.*http",
], 0.85)
_register("T1218.001", "Compiled HTML File", "defense-evasion", [
    r"hh\.exe\s+", r"\.chm\b",
], 0.80)
_register("T1218.002", "Control Panel", "defense-evasion", [
    r"control\.exe\s+", r"\.cpl\b",
], 0.75)
_register("T1218.003", "CMSTP", "defense-evasion", [
    r"cmstp\.exe\s*/s", r"cmstp.*\.inf",
], 0.85)
_register("T1218.004", "InstallUtil", "defense-evasion", [
    r"installutil\.exe", r"InstallUtil.*\.dll",
], 0.85)
_register("T1218.005", "Mshta", "defense-evasion", [
    r"mshta\.exe", r"mshta\s+.*vbscript",
    r"mshta\s+.*javascript", r"mshta.*http",
], 0.90)
_register("T1218.007", "Msiexec", "defense-evasion", [
    r"msiexec\s*/[iq]", r"msiexec.*http",
    r"msiexec.*/y\b",
], 0.85)
_register("T1218.009", "Regsvcs/Regasm", "defense-evasion", [
    r"regsvcs\.exe", r"regasm\.exe",
], 0.80)
_register("T1218.010", "Regsvr32", "defense-evasion", [
    r"regsvr32\s+", r"regsvr32.*scrobj\.dll",
    r"regsvr32.*/s.*/n.*/u.*/i:",
], 0.90)
_register("T1218.011", "Rundll32", "defense-evasion", [
    r"rundll32\.exe\s+", r"rundll32.*javascript",
    r"rundll32.*shell32.*ShellExec_RunDLL",
    r"rundll32.*comsvcs.*MiniDump",
], 0.85)
_register("T1218.012", "Verclsid", "defense-evasion", [
    r"verclsid\.exe", r"verclsid\s+/S\s+/C",
], 0.75)
_register("T1218.013", "Mavinject", "defense-evasion", [
    r"mavinject\.exe", r"mavinject.*INJECTRUNNING",
], 0.80)
_register("T1218.014", "MMC", "defense-evasion", [
    r"mmc\.exe.*-Embedding", r"mmc.*\.msc\b",
], 0.70)
_register("T1562", "Impair Defenses", "defense-evasion", [
    r"disable.*firewall", r"disable.*antivirus",
    r"disable.*defender", r"tamper.*protection",
], 0.90)
_register("T1562.001", "Disable or Modify Tools", "defense-evasion", [
    r"Set-MpPreference.*-DisableRealtimeMonitoring",
    r"sc\s+stop\s+WinDefend", r"sc\s+config.*start=\s*disabled",
    r"net\s+stop.*McAfee", r"net\s+stop.*Symantec",
    r"Uninstall.*antivirus",
    r"taskkill.*msmpeng", r"taskkill.*MsMpEng",
    r"EICAR.*test", r"defender.*exclusion",
    r"Add-MpPreference.*-ExclusionPath",
], 0.95)
_register("T1562.002", "Disable Windows Event Logging", "defense-evasion", [
    r"auditpol\s*/set.*disable",
    r"auditpol.*success:disable.*failure:disable",
    r"wevtutil\s+sl.*enabled:false",
    r"Stop-Service.*EventLog",
], 0.95)
_register("T1562.003", "Impair Command History Logging", "defense-evasion", [
    r"Set-PSReadlineOption.*-HistorySaveStyle.*SaveNothing",
    r"HISTCONTROL=ignoreboth",
    r"unset\s+HISTFILE",
], 0.85)
_register("T1562.004", "Disable or Modify System Firewall", "defense-evasion", [
    r"netsh\s+advfirewall.*off",
    r"netsh\s+firewall.*disable",
    r"ufw\s+disable", r"iptables\s+-F",
    r"systemctl\s+stop\s+firewalld",
    r"Set-NetFirewallProfile.*-Enabled\s+False",
], 0.90)
_register("T1562.006", "Indicator Blocking", "defense-evasion", [
    r"ETW.*patch", r"EtwEventWrite.*patch",
    r"ntdll.*EtwEventWrite",
    r"amsi.*patch", r"AmsiScanBuffer",
], 0.90)
_register("T1562.007", "Disable or Modify Cloud Firewall", "defense-evasion", [
    r"aws.*security-group.*revoke",
    r"az\s+network\s+nsg\s+rule\s+delete",
], 0.80)
_register("T1562.008", "Disable or Modify Cloud Logs", "defense-evasion", [
    r"aws.*cloudtrail.*stop",
    r"aws.*cloudtrail.*delete",
    r"az.*monitor.*delete",
], 0.90)
_register("T1562.009", "Safe Mode Boot", "defense-evasion", [
    r"bcdedit.*safeboot", r"bcdedit.*/set.*safe",
], 0.85)
_register("T1562.010", "Downgrade Attack", "defense-evasion", [
    r"powershell.*-version\s+2", r"downgrade.*powershell",
], 0.80)
_register("T1497", "Virtualization/Sandbox Evasion", "defense-evasion", [
    r"vmware|virtualbox|qemu|hyperv|xen",
    r"sandbox.*detect", r"anti.?vm",
    r"IsDebuggerPresent", r"CheckRemoteDebugger",
], 0.80)
_register("T1497.001", "System Checks", "defense-evasion", [
    r"wmic.*manufacturer.*virtual",
    r"systeminfo.*virtual",
    r"reg.*query.*VirtualBox",
    r"reg.*query.*VMware",
], 0.80)
_register("T1497.002", "User Activity Based Checks", "defense-evasion", [
    r"GetCursorPos", r"mouse.*movement.*check",
    r"sleep.*anti.*sandbox",
], 0.75)
_register("T1497.003", "Time Based Evasion", "defense-evasion", [
    r"sleep\s+\d{3,}", r"timeout\s+/t\s+\d{3,}",
    r"Start-Sleep\s+-s\s+\d{3,}",
    r"NtDelayExecution",
], 0.75)
_register("T1553", "Subvert Trust Controls", "defense-evasion", [
    r"code.*sign.*bypass", r"authenticode",
], 0.75)
_register("T1553.001", "Gatekeeper Bypass", "defense-evasion", [
    r"spctl.*--master-disable", r"xattr.*-r.*-d.*quarantine",
], 0.85)
_register("T1553.002", "Code Signing", "defense-evasion", [
    r"signtool", r"self.?signed.*cert",
    r"code.*signing.*cert",
], 0.70)
_register("T1553.003", "SIP and Trust Provider Hijacking", "defense-evasion", [
    r"HKLM.*Trust.*Provider", r"WinVerifyTrust",
], 0.80)
_register("T1553.004", "Install Root Certificate", "defense-evasion", [
    r"certutil.*-addstore.*root",
    r"Import-Certificate.*Root",
    r"/usr/local/share/ca-certificates",
    r"update-ca-certificates",
], 0.85)
_register("T1553.005", "Mark-of-the-Web Bypass", "defense-evasion", [
    r"Zone\.Identifier", r":Zone\.Identifier.*delete",
    r"motw.*bypass", r"Remove-Item.*Zone\.Identifier",
], 0.80)
_register("T1553.006", "Code Signing Policy Modification", "defense-evasion", [
    r"bcdedit.*testsigning", r"bcdedit.*/set.*nointegritychecks",
], 0.85)
_register("T1564", "Hide Artifacts", "defense-evasion", [
    r"attrib\s+\+h", r"hidden.*file",
    r"alternate.*data.*stream",
], 0.80)
_register("T1564.001", "Hidden Files and Directories", "defense-evasion", [
    r"attrib\s+\+h\s+\+s", r"chflags\s+hidden",
    r"mkdir\s+\.\w+",  # dot directories on Linux
], 0.80)
_register("T1564.003", "Hidden Window", "defense-evasion", [
    r"-windowstyle\s+hidden", r"-w\s+hidden",
    r"ShowWindow.*SW_HIDE", r"CREATE_NO_WINDOW",
], 0.80)
_register("T1564.004", "NTFS File Attributes", "defense-evasion", [
    r"alternate\s*data\s*stream", r"ads\b.*ntfs",
    r":\w+\.\w+$", r"streams\.exe",
    r"type.*>.*:.*\.exe",
], 0.85)
_register("T1564.005", "Hidden File System", "defense-evasion", [
    r"hidden.*partition", r"EFI.*system.*partition.*backdoor",
], 0.75)
_register("T1564.006", "Run Virtual Instance", "defense-evasion", [
    r"virtualbox.*headless", r"vmrun\s+",
    r"qemu.*-nographic",
], 0.75)
_register("T1564.007", "VBA Stomping", "defense-evasion", [
    r"vba.*stomp", r"p-code.*replace",
    r"macro.*source.*removed",
], 0.80)
_register("T1564.009", "Resource Forking", "defense-evasion", [
    r"resource\s*fork", r"\/\.\._",
], 0.70)
_register("T1564.010", "Process Argument Spoofing", "defense-evasion", [
    r"argument.*spoof", r"PEB.*CommandLine",
    r"NtQueryInformationProcess.*spoof",
], 0.80)
_register("T1197", "BITS Jobs", "defense-evasion", [
    r"bitsadmin", r"Start-BitsTransfer",
    r"BITS.*transfer",
    r"bitsadmin\s*/transfer",
    r"bitsadmin\s*/create",
], 0.85)
_register("T1480", "Execution Guardrails", "defense-evasion", [
    r"environment.*check.*before.*exec",
    r"geofenc", r"domain.*check.*execute",
], 0.70)
_register("T1480.001", "Environmental Keying", "defense-evasion", [
    r"environmental.*key", r"host.*specific.*decrypt",
], 0.70)
_register("T1220", "XSL Script Processing", "defense-evasion", [
    r"msxsl\.exe", r"wmic.*\/format:.*\.xsl",
    r"xsltransform",
], 0.85)
_register("T1221", "Template Injection", "defense-evasion", [
    r"template.*inject", r"\.dotm.*remote",
    r"attach.*template.*http",
    r"word.*remote.*template",
], 0.85)
_register("T1006", "Direct Volume Access", "defense-evasion", [
    r"\\\\\\\\\.\\\\[A-Z]:",
    r"NtFsControlFile", r"direct.*volume",
    r"CreateFile.*PhysicalDrive",
], 0.80)
_register("T1014", "Rootkit", "defense-evasion", [
    r"rootkit", r"DKOM\b", r"ssdt.*hook",
    r"idt.*hook", r"driver.*hide.*process",
], 0.90)
_register("T1207", "Rogue Domain Controller", "defense-evasion", [
    r"DCShadow", r"rogue.*domain.*controller",
    r"mimikatz.*lsadump::dcshadow",
], 0.90)
_register("T1112", "Modify Registry", "defense-evasion", [
    r"reg\s+(add|delete|import)", r"Set-ItemProperty.*Registry",
    r"New-ItemProperty.*HKLM", r"New-ItemProperty.*HKCU",
    r"reg\.exe\s+add",
], 0.80)
_register("T1622", "Debugger Evasion", "defense-evasion", [
    r"IsDebuggerPresent", r"NtQueryInformationProcess.*debug",
    r"CheckRemoteDebuggerPresent",
    r"OutputDebugString.*anti",
], 0.80)
_register("T1656", "Impersonation", "defense-evasion", [
    r"impersonat.*user", r"spoof.*identity",
], 0.70)

# ─── CREDENTIAL ACCESS (TA0006) ──────────────────────────────────

_register("T1110", "Brute Force", "credential-access", [
    r"brute.?force", r"password.*spray",
    r"hydra\s+", r"medusa\s+",
    r"patator\s+", r"ncrack\s+",
    r"failed.*login.*attempt.*\d{3,}",
], 0.85)
_register("T1110.001", "Password Guessing", "credential-access", [
    r"password.*guess", r"common.*password.*attempt",
], 0.80)
_register("T1110.002", "Password Cracking", "credential-access", [
    r"hashcat", r"john.*the.*ripper", r"john\s+",
    r"ophcrack", r"rainbow.*table",
    r"hash.*crack",
], 0.85)
_register("T1110.003", "Password Spraying", "credential-access", [
    r"password.*spray", r"spray.*password",
    r"single.*password.*multiple.*account",
    r"ruler\s+--domain",
], 0.90)
_register("T1110.004", "Credential Stuffing", "credential-access", [
    r"credential.*stuff", r"combo.*list",
    r"breach.*credential.*reuse",
], 0.85)
_register("T1003", "OS Credential Dumping", "credential-access", [
    r"credential.*dump", r"mimikatz",
    r"sekurlsa", r"lsadump",
    r"hashdump", r"password.*dump",
], 0.95)
_register("T1003.001", "LSASS Memory", "credential-access", [
    r"lsass\.exe.*dump", r"lsass.*minidump",
    r"sekurlsa::logonpasswords",
    r"procdump.*lsass", r"comsvcs.*MiniDump",
    r"rundll32.*comsvcs.*MiniDump.*lsass",
    r"task.*manager.*lsass.*dump",
    r"mimikatz.*sekurlsa",
    r"pypykatz",
], 0.95)
_register("T1003.002", "Security Account Manager", "credential-access", [
    r"reg\s+save.*\\\\sam", r"reg\s+save.*\\\\system",
    r"copy.*\\\\sam\b", r"hklm.*sam\b",
    r"mimikatz.*lsadump::sam",
    r"secretsdump",
], 0.95)
_register("T1003.003", "NTDS", "credential-access", [
    r"ntds\.dit", r"ntdsutil",
    r"vssadmin.*shadow.*copy",
    r"secretsdump.*-ntds",
    r"mimikatz.*lsadump::dcsync",
    r"DCSync\b",
], 0.95)
_register("T1003.004", "LSA Secrets", "credential-access", [
    r"lsa.*secret", r"lsadump::secrets",
    r"reg\s+save.*\\\\security",
], 0.90)
_register("T1003.005", "Cached Domain Credentials", "credential-access", [
    r"cached.*credential", r"mscash",
    r"lsadump::cache", r"dcc2\b",
], 0.85)
_register("T1003.006", "DCSync", "credential-access", [
    r"dcsync\b", r"lsadump::dcsync",
    r"GetNCChanges", r"DRS.*replication",
    r"mimikatz.*dcsync",
], 0.95)
_register("T1003.007", "/etc/passwd and /etc/shadow", "credential-access", [
    r"cat\s+/etc/shadow", r"cat\s+/etc/passwd",
    r"unshadow\b", r"/etc/shadow\b.*copy",
], 0.90)
_register("T1003.008", "/proc/kcore and /dev/mem", "credential-access", [
    r"/proc/kcore", r"/dev/kmem",
    r"strings.*/dev/mem",
], 0.85)
_register("T1558", "Steal or Forge Kerberos Tickets", "credential-access", [
    r"kerberos.*ticket", r"kerber",
    r"kirbi\b", r"\.kirbi\b",
], 0.85)
_register("T1558.001", "Golden Ticket", "credential-access", [
    r"golden.*ticket", r"mimikatz.*kerberos::golden",
    r"krbtgt.*hash", r"ticket::golden",
], 0.95)
_register("T1558.002", "Silver Ticket", "credential-access", [
    r"silver.*ticket", r"kerberos::silver",
    r"service.*ticket.*forge",
], 0.90)
_register("T1558.003", "Kerberoasting", "credential-access", [
    r"kerberoast", r"Invoke-Kerberoast",
    r"GetUserSPNs", r"TGS.*crack",
    r"rubeus.*kerberoast",
    r"hashcat.*-m\s*13100",
], 0.95)
_register("T1558.004", "AS-REP Roasting", "credential-access", [
    r"as.?rep.*roast", r"ASREPRoast",
    r"GetNPUsers", r"hashcat.*-m\s*18200",
    r"rubeus.*asreproast",
    r"DONT_REQ_PREAUTH",
], 0.90)
_register("T1552", "Unsecured Credentials", "credential-access", [
    r"password.*file", r"credential.*plain",
    r"hardcoded.*password", r"password.*config",
], 0.80)
_register("T1552.001", "Credentials In Files", "credential-access", [
    r"findstr.*password", r"grep.*password",
    r"find.*-name.*password", r"dir.*password.*\.txt",
    r"Select-String.*password",
], 0.85)
_register("T1552.002", "Credentials in Registry", "credential-access", [
    r"reg\s+query.*password", r"reg\s+query.*autologon",
    r"DefaultPassword",
    r"HKLM.*WinLogon.*DefaultPassword",
], 0.85)
_register("T1552.003", "Bash History", "credential-access", [
    r"cat.*\.bash_history", r"\.bash_history",
    r"history\b.*password",
], 0.80)
_register("T1552.004", "Private Keys", "credential-access", [
    r"\.pem\b", r"\.key\b.*private",
    r"id_rsa\b", r"id_ed25519",
    r"BEGIN.*PRIVATE.*KEY",
    r"find.*-name.*id_rsa",
], 0.85)
_register("T1552.005", "Cloud Instance Metadata API", "credential-access", [
    r"169\.254\.169\.254", r"metadata.*api",
    r"instance.*metadata",
    r"iam.*security-credentials",
], 0.90)
_register("T1552.006", "Group Policy Preferences", "credential-access", [
    r"gpp.*password", r"groups\.xml.*cpassword",
    r"Get-GPPPassword",
], 0.90)
_register("T1555", "Credentials from Password Stores", "credential-access", [
    r"credential.*store", r"password.*vault",
    r"keychain\s+dump",
], 0.85)
_register("T1555.001", "Keychain", "credential-access", [
    r"security\s+find-generic-password",
    r"security\s+dump-keychain",
    r"chainbreaker",
], 0.85)
_register("T1555.002", "Securityd Memory", "credential-access", [
    r"securityd.*memory", r"kcpassword",
], 0.80)
_register("T1555.003", "Credentials from Web Browsers", "credential-access", [
    r"chrome.*Login\s*Data", r"firefox.*logins\.json",
    r"cookies\.sqlite", r"browser.*credential",
    r"LaZagne", r"HackBrowserData",
    r"SharpChromium",
], 0.90)
_register("T1555.004", "Windows Credential Manager", "credential-access", [
    r"cmdkey\s*/list", r"vaultcmd\s*/listcreds",
    r"CredEnumerate",
], 0.85)
_register("T1555.005", "Password Managers", "credential-access", [
    r"keepass.*dump", r"lastpass.*extract",
    r"1password.*vault",
], 0.85)
_register("T1056", "Input Capture", "credential-access", [
    r"keylog", r"key.*capture", r"SetWindowsHookEx",
    r"GetAsyncKeyState", r"input.*capture",
], 0.85)
_register("T1056.001", "Keylogging", "credential-access", [
    r"keylog", r"SetWindowsHookEx.*WH_KEYBOARD",
    r"GetAsyncKeyState", r"GetKeyState",
    r"xinput\b.*log",
], 0.90)
_register("T1056.002", "GUI Input Capture", "credential-access", [
    r"fake.*login.*prompt", r"credential.*prompt.*phish",
    r"CredUIPromptForCredentials",
], 0.80)
_register("T1056.003", "Web Portal Capture", "credential-access", [
    r"credential.*harvest.*web", r"fake.*login.*page",
    r"evilginx", r"modlishka",
], 0.85)
_register("T1056.004", "Credential API Hooking", "credential-access", [
    r"api.*hook.*credential", r"LsaLogonUser.*hook",
    r"CredSSP.*intercept",
], 0.80)
_register("T1557", "Adversary-in-the-Middle", "credential-access", [
    r"man.?in.?the.?middle", r"mitm\b",
    r"arp.*spoof", r"arp.*poison",
    r"responder\b",
], 0.85)
_register("T1557.001", "LLMNR/NBT-NS Poisoning and SMB Relay", "credential-access", [
    r"responder\.py", r"Responder\b.*LLMNR",
    r"llmnr.*poison", r"nbt-ns.*poison",
    r"ntlmrelayx", r"smbrelayx",
    r"inveigh\b",
], 0.90)
_register("T1557.002", "ARP Cache Poisoning", "credential-access", [
    r"arp.*spoof", r"arp.*poison",
    r"ettercap", r"arpspoof",
    r"bettercap.*arp",
], 0.85)
_register("T1557.003", "DHCP Spoofing", "credential-access", [
    r"dhcp.*spoof", r"rogue.*dhcp",
], 0.80)
_register("T1111", "Multi-Factor Authentication Interception", "credential-access", [
    r"mfa.*intercept", r"2fa.*bypass",
    r"otp.*intercept", r"totp.*steal",
], 0.85)
_register("T1187", "Forced Authentication", "credential-access", [
    r"forced.*auth", r"responder.*capture",
    r"ntlm.*capture", r"\\\\\\\\.*\\\\share",
    r"1\.0\.0\.1.*scf",
], 0.85)
_register("T1606", "Forge Web Credentials", "credential-access", [
    r"saml.*forge", r"cookie.*forge",
    r"session.*token.*forge",
], 0.85)
_register("T1606.001", "Web Cookies", "credential-access", [
    r"cookie.*forge", r"session.*hijack",
    r"Set-Cookie.*manipulat",
], 0.80)
_register("T1606.002", "SAML Tokens", "credential-access", [
    r"saml.*forge", r"golden.*saml",
    r"ADFSDump", r"adfsdump",
], 0.90)
_register("T1621", "Multi-Factor Authentication Request Generation", "credential-access", [
    r"mfa.*bomb", r"mfa.*fatigue", r"push.*bomb",
    r"repeated.*mfa.*request",
], 0.85)
_register("T1528", "Steal Application Access Token", "credential-access", [
    r"oauth.*token.*steal", r"jwt.*steal",
    r"access.*token.*extract",
    r"bearer.*token.*exfil",
], 0.85)
_register("T1539", "Steal Web Session Cookie", "credential-access", [
    r"session.*cookie.*steal", r"cookie.*extract",
    r"evilginx.*session", r"pass-the-cookie",
], 0.85)
_register("T1649", "Steal or Forge Authentication Certificates", "credential-access", [
    r"certipy", r"certify\.exe",
    r"adcs.*exploit", r"certificate.*theft",
    r"PKINIT",
], 0.85)

# ─── DISCOVERY (TA0007) ──────────────────────────────────────────

_register("T1087", "Account Discovery", "discovery", [
    r"net\s+user\b", r"net\s+localgroup\b",
    r"wmic\s+useraccount", r"Get-LocalUser",
    r"cat\s+/etc/passwd", r"getent\s+passwd",
], 0.85)
_register("T1087.001", "Local Account", "discovery", [
    r"net\s+user\b(?!\s+/domain)", r"Get-LocalUser",
    r"wmic\s+useraccount\s+where",
    r"cat\s+/etc/passwd",
], 0.85)
_register("T1087.002", "Domain Account", "discovery", [
    r"net\s+user\s+/domain", r"net\s+group\s+/domain",
    r"Get-ADUser", r"Get-ADGroupMember",
    r"dsquery\s+user", r"ldapsearch",
    r"adfind\b", r"bloodhound",
], 0.90)
_register("T1087.003", "Email Account", "discovery", [
    r"Get-Mailbox", r"Get-GlobalAddressList",
    r"exchange.*enum",
], 0.80)
_register("T1087.004", "Cloud Account", "discovery", [
    r"aws\s+iam\s+list-users", r"az\s+ad\s+user\s+list",
    r"Get-AzureADUser",
], 0.85)
_register("T1482", "Domain Trust Discovery", "discovery", [
    r"nltest\s*/domain_trusts", r"Get-ADTrust",
    r"dsquery\s+trust", r"ldapsearch.*trust",
    r"adfind.*trustdmp",
], 0.90)
_register("T1083", "File and Directory Discovery", "discovery", [
    r"dir\s+/s\b", r"find\s+/\s+-name",
    r"ls\s+-la[Rr]", r"tree\s+/[fF]",
    r"Get-ChildItem.*-Recurse",
], 0.80)
_register("T1046", "Network Service Discovery", "discovery", [
    r"nmap\s+", r"masscan\s+",
    r"net\s+view\b", r"net\s+share\b",
    r"netstat\s+-[an]", r"ss\s+-[tl]",
], 0.85)
_register("T1135", "Network Share Discovery", "discovery", [
    r"net\s+share\b", r"net\s+view\b",
    r"smbclient\s+-L", r"Get-SmbShare",
    r"Invoke-ShareFinder",
], 0.85)
_register("T1040", "Network Sniffing", "discovery", [
    r"tcpdump", r"wireshark", r"tshark",
    r"windump", r"pcap\b",
    r"promiscuous.*mode",
], 0.85)
_register("T1201", "Password Policy Discovery", "discovery", [
    r"net\s+accounts\b", r"Get-ADDefaultDomainPasswordPolicy",
    r"chage\s+-l", r"pam.*password.*policy",
], 0.80)
_register("T1120", "Peripheral Device Discovery", "discovery", [
    r"wmic\s+path\s+Win32_PnPEntity",
    r"lsusb\b", r"lspci\b",
], 0.75)
_register("T1069", "Permission Groups Discovery", "discovery", [
    r"net\s+localgroup\b", r"net\s+group\s+/domain",
    r"Get-ADGroup", r"id\b.*groups",
    r"whoami\s+/groups",
], 0.85)
_register("T1069.001", "Local Groups", "discovery", [
    r"net\s+localgroup\b", r"Get-LocalGroupMember",
], 0.85)
_register("T1069.002", "Domain Groups", "discovery", [
    r"net\s+group\s+/domain", r"Get-ADGroup",
    r"adfind.*group",
], 0.85)
_register("T1057", "Process Discovery", "discovery", [
    r"tasklist\b", r"Get-Process\b",
    r"ps\s+aux\b", r"ps\s+-ef\b",
    r"wmic\s+process\s+list",
], 0.80)
_register("T1012", "Query Registry", "discovery", [
    r"reg\s+query\b", r"Get-ItemProperty.*Registry",
    r"reg\.exe\s+query",
], 0.75)
_register("T1018", "Remote System Discovery", "discovery", [
    r"net\s+view\b", r"ping\s+-[cn]",
    r"arp\s+-a\b", r"nltest\s*/dclist",
    r"nbtstat\b", r"Get-ADComputer",
    r"dsquery\s+computer",
], 0.85)
_register("T1518", "Software Discovery", "discovery", [
    r"wmic\s+product\s+get", r"Get-WmiObject.*Win32_Product",
    r"dpkg\s+-l\b", r"rpm\s+-qa\b",
    r"reg\s+query.*Uninstall",
], 0.80)
_register("T1518.001", "Security Software Discovery", "discovery", [
    r"wmic.*antivirus", r"tasklist.*MsMpEng",
    r"fltMC\.exe", r"Get-MpComputerStatus",
    r"netsh\s+advfirewall\s+show",
    r"service\s+--status-all.*security",
], 0.85)
_register("T1082", "System Information Discovery", "discovery", [
    r"systeminfo\b", r"hostname\b",
    r"uname\s+-a", r"cat\s+/etc/os-release",
    r"Get-ComputerInfo", r"wmic\s+os\s+get",
    r"ver\b.*windows",
], 0.85)
_register("T1614", "System Location Discovery", "discovery", [
    r"Get-WinSystemLocale", r"Get-Culture",
    r"locale\b", r"tzutil\b",
], 0.70)
_register("T1016", "System Network Configuration Discovery", "discovery", [
    r"ipconfig\b", r"ifconfig\b",
    r"ip\s+(addr|route|link)", r"route\s+print",
    r"Get-NetAdapter", r"netstat\s+-rn",
    r"arp\s+-a\b",
], 0.85)
_register("T1016.001", "Internet Connection Discovery", "discovery", [
    r"ping\s+.*google", r"ping\s+.*8\.8\.8\.8",
    r"curl.*ifconfig\.me", r"wget.*icanhazip",
    r"nslookup\s+.*myip",
], 0.75)
_register("T1049", "System Network Connections Discovery", "discovery", [
    r"netstat\b", r"ss\s+-[tln]",
    r"Get-NetTCPConnection",
    r"netstat\s+-anob",
], 0.80)
_register("T1033", "System Owner/User Discovery", "discovery", [
    r"whoami\b", r"id\b(?!\s*=)",
    r"query\s+user\b", r"w\b.*who\b",
    r"echo\s+%username%",
], 0.80)
_register("T1007", "System Service Discovery", "discovery", [
    r"sc\s+query\b", r"Get-Service\b",
    r"wmic\s+service\s+list", r"systemctl\s+list",
    r"service\s+--status-all",
], 0.80)
_register("T1124", "System Time Discovery", "discovery", [
    r"net\s+time\b", r"w32tm\s+/query",
    r"date\b.*utc", r"timedatectl\b",
], 0.70)
_register("T1580", "Cloud Infrastructure Discovery", "discovery", [
    r"aws\s+ec2\s+describe", r"az\s+vm\s+list",
    r"gcloud\s+compute\s+instances\s+list",
], 0.80)
_register("T1526", "Cloud Service Discovery", "discovery", [
    r"aws\s+s3\s+ls", r"az\s+resource\s+list",
    r"gcloud\s+services\s+list",
], 0.80)
_register("T1538", "Cloud Service Dashboard", "discovery", [
    r"console\.aws", r"portal\.azure",
    r"console\.cloud\.google",
], 0.65)
_register("T1619", "Cloud Storage Object Discovery", "discovery", [
    r"aws\s+s3\s+ls\s+s3://", r"az\s+storage\s+blob\s+list",
    r"gsutil\s+ls\b",
], 0.80)
_register("T1613", "Container and Resource Discovery", "discovery", [
    r"docker\s+ps\b", r"kubectl\s+get\s+(pods|deployments|services)",
    r"crictl\s+ps\b",
], 0.80)
_register("T1622", "Debugger Evasion", "discovery", [
    r"IsDebuggerPresent", r"anti.*debug",
], 0.70)

# ─── LATERAL MOVEMENT (TA0008) ───────────────────────────────────

_register("T1021", "Remote Services", "lateral-movement", [
    r"rdp.*lateral", r"ssh.*lateral",
    r"psexec", r"wmiexec", r"smbexec",
], 0.85)
_register("T1021.001", "Remote Desktop Protocol", "lateral-movement", [
    r"mstsc\.exe", r"rdp.*connect",
    r"3389\b.*connect", r"tscon\b",
    r"remote\s*desktop.*connect",
    r"SharpRDP",
], 0.85)
_register("T1021.002", "SMB/Windows Admin Shares", "lateral-movement", [
    r"net\s+use\s+\\\\", r"\\\\\w+\\[cC]\$",
    r"\\\\\w+\\admin\$", r"\\\\\w+\\ipc\$",
    r"smbclient.*-U", r"psexec.*\\\\",
    r"copy.*\\\\.*\\c\$",
], 0.90)
_register("T1021.003", "Distributed Component Object Model", "lateral-movement", [
    r"dcom.*lateral", r"MMC20\.Application",
    r"ShellWindows.*lateral",
    r"impacket.*dcomexec",
], 0.85)
_register("T1021.004", "SSH", "lateral-movement", [
    r"ssh\s+\w+@", r"ssh\s+-i\s+",
    r"scp\s+.*:", r"paramiko",
    r"plink\.exe",
], 0.80)
_register("T1021.005", "VNC", "lateral-movement", [
    r"vnc.*connect", r"5900\b.*connect",
    r"tightvnc|realvnc|ultravnc",
], 0.80)
_register("T1021.006", "Windows Remote Management", "lateral-movement", [
    r"winrm\b", r"Enter-PSSession",
    r"Invoke-Command.*-ComputerName",
    r"wsman\b", r"evil-winrm",
    r"5985\b.*connect", r"5986\b.*connect",
], 0.90)
_register("T1091", "Replication Through Removable Media", "lateral-movement", [
    r"usb.*spread", r"autorun\.inf",
    r"removable.*media.*infect",
], 0.75)
_register("T1072", "Software Deployment Tools", "lateral-movement", [
    r"sccm.*deploy", r"psexec.*deploy",
    r"group\s*policy.*deploy",
    r"ansible.*lateral", r"puppet.*push",
], 0.80)
_register("T1080", "Taint Shared Content", "lateral-movement", [
    r"trojanized.*share", r"malicious.*shared.*drive",
    r"poisoned.*share",
], 0.75)
_register("T1550", "Use Alternate Authentication Material", "lateral-movement", [
    r"pass.?the.?hash", r"pth\b",
    r"pass.?the.?ticket", r"overpass.?the.?hash",
], 0.90)
_register("T1550.001", "Application Access Token", "lateral-movement", [
    r"stolen.*token.*access", r"oauth.*token.*reuse",
], 0.80)
_register("T1550.002", "Pass the Hash", "lateral-movement", [
    r"pass.?the.?hash", r"pth\b",
    r"sekurlsa::pth", r"mimikatz.*pth",
    r"impacket.*-hashes",
    r"wmiexec.*-hashes",
    r"crackmapexec.*-H",
], 0.95)
_register("T1550.003", "Pass the Ticket", "lateral-movement", [
    r"pass.?the.?ticket", r"kerberos::ptt",
    r"rubeus.*ptt", r"\.kirbi\b",
    r"export.*KRB5CCNAME",
], 0.90)
_register("T1550.004", "Web Session Cookie", "lateral-movement", [
    r"session.*cookie.*replay", r"pass.?the.?cookie",
], 0.80)
_register("T1563", "Remote Service Session Hijacking", "lateral-movement", [
    r"session.*hijack.*rdp", r"tscon.*password",
], 0.80)
_register("T1563.001", "SSH Hijacking", "lateral-movement", [
    r"ssh.*agent.*hijack", r"SSH_AUTH_SOCK",
    r"controlmaster.*hijack",
], 0.80)
_register("T1563.002", "RDP Hijacking", "lateral-movement", [
    r"tscon\s+\d+\s+/dest:", r"rdp.*session.*hijack",
], 0.85)
_register("T1570", "Lateral Tool Transfer", "lateral-movement", [
    r"certutil.*-urlcache.*\\\\",
    r"bitsadmin.*transfer.*\\\\",
    r"copy.*\\\\.*payload",
    r"scp.*malware",
], 0.80)
_register("T1534", "Internal Spearphishing", "lateral-movement", [
    r"internal.*spearphish", r"compromised.*account.*phish",
    r"lateral.*phish",
], 0.80)

# ─── COLLECTION (TA0009) ─────────────────────────────────────────

_register("T1560", "Archive Collected Data", "collection", [
    r"compress", r"7z\s+a\b", r"zip\s+",
    r"rar\s+a\b", r"tar\s+[cz]",
    r"Compress-Archive",
], 0.80)
_register("T1560.001", "Archive via Utility", "collection", [
    r"7z\s+a\b", r"zip\s+", r"rar\s+a\b",
    r"tar\s+czf", r"Compress-Archive",
    r"makecab\b",
], 0.85)
_register("T1560.002", "Archive via Library", "collection", [
    r"ZipFile", r"System\.IO\.Compression",
    r"shutil\.make_archive", r"zipfile\.ZipFile",
], 0.75)
_register("T1560.003", "Archive via Custom Method", "collection", [
    r"xor.*archive", r"custom.*compress",
    r"encrypt.*before.*exfil",
], 0.70)
_register("T1123", "Audio Capture", "collection", [
    r"microphone.*capture", r"audio.*record",
    r"waveInOpen", r"sound.*record",
], 0.80)
_register("T1119", "Automated Collection", "collection", [
    r"script.*collect.*file", r"automated.*gather",
    r"scheduled.*collection",
], 0.70)
_register("T1185", "Browser Session Hijacking", "collection", [
    r"browser.*session.*hijack", r"man.?in.?the.?browser",
    r"browser.*inject",
], 0.80)
_register("T1115", "Clipboard Data", "collection", [
    r"clipboard", r"GetClipboard",
    r"Get-Clipboard", r"pbpaste",
    r"xclip", r"xsel\b",
], 0.80)
_register("T1530", "Data from Cloud Storage", "collection", [
    r"aws\s+s3\s+cp", r"aws\s+s3\s+sync",
    r"az\s+storage.*download",
    r"gsutil\s+cp\b",
], 0.80)
_register("T1602", "Data from Configuration Repository", "collection", [
    r"running-config", r"startup-config",
    r"show\s+configuration",
], 0.75)
_register("T1213", "Data from Information Repositories", "collection", [
    r"sharepoint.*dump", r"confluence.*export",
    r"wiki.*scrape",
], 0.75)
_register("T1213.001", "Confluence", "collection", [
    r"confluence.*export", r"confluence.*dump",
], 0.75)
_register("T1213.002", "SharePoint", "collection", [
    r"sharepoint.*download", r"sharepoint.*dump",
], 0.75)
_register("T1005", "Data from Local System", "collection", [
    r"copy.*document", r"xcopy.*sensitive",
    r"robocopy\b", r"find.*\.docx",
    r"find.*\.pdf", r"staged.*exfil",
], 0.75)
_register("T1039", "Data from Network Shared Drive", "collection", [
    r"net\s+use.*copy", r"robocopy.*\\\\",
    r"xcopy.*\\\\",
], 0.80)
_register("T1025", "Data from Removable Media", "collection", [
    r"usb.*copy", r"removable.*media.*collect",
], 0.75)
_register("T1074", "Data Staged", "collection", [
    r"staged.*data", r"staging.*directory",
    r"collected.*temp", r"c:\\temp\\exfil",
    r"/tmp/staging",
], 0.80)
_register("T1074.001", "Local Data Staging", "collection", [
    r"c:\\temp\\collect", r"/tmp/staging",
    r"staged.*local",
], 0.80)
_register("T1074.002", "Remote Data Staging", "collection", [
    r"staged.*share", r"\\\\.*staging",
], 0.80)
_register("T1114", "Email Collection", "collection", [
    r"email.*collect", r"inbox.*dump",
    r"pst\s+export", r"\.ost\b.*copy",
], 0.80)
_register("T1114.001", "Local Email Collection", "collection", [
    r"\.pst\b.*copy", r"\.ost\b.*copy",
    r"outlook.*data.*file",
], 0.80)
_register("T1114.002", "Remote Email Collection", "collection", [
    r"ews.*connect", r"exchange.*web.*services",
    r"mapi.*connect",
], 0.80)
_register("T1114.003", "Email Forwarding Rule", "collection", [
    r"inbox.*rule.*forward", r"Set-InboxRule",
    r"New-InboxRule.*ForwardTo",
    r"email.*forward.*external",
], 0.85)
_register("T1056", "Input Capture", "collection", [
    r"keylog", r"input.*capture",
], 0.80)
_register("T1113", "Screen Capture", "collection", [
    r"screenshot", r"screen.*capture",
    r"PrintWindow", r"BitBlt",
    r"import.*-screen", r"scrot\b",
    r"xwd\b",
], 0.80)
_register("T1125", "Video Capture", "collection", [
    r"webcam.*capture", r"camera.*record",
    r"video.*capture.*device",
], 0.80)

# ─── COMMAND AND CONTROL (TA0011) ────────────────────────────────

_register("T1071", "Application Layer Protocol", "command-and-control", [
    r"c2.*http", r"beacon.*callback",
    r"command.*control.*channel",
], 0.80)
_register("T1071.001", "Web Protocols", "command-and-control", [
    r"http.*c2\b", r"https.*beacon",
    r"http.*callback", r"web.*c2\b",
    r"cobalt.*strike.*http",
    r"malleable.*profile",
    r"user-agent.*cobalt",
], 0.85)
_register("T1071.002", "File Transfer Protocols", "command-and-control", [
    r"ftp.*c2\b", r"sftp.*exfil",
    r"tftp\b.*connect",
], 0.75)
_register("T1071.003", "Mail Protocols", "command-and-control", [
    r"smtp.*c2\b", r"imap.*c2\b",
    r"pop3.*c2\b", r"email.*c2\b",
], 0.75)
_register("T1071.004", "DNS", "command-and-control", [
    r"dns.*tunnel", r"dns.*c2\b",
    r"dnscat", r"iodine\b",
    r"dns.*exfil", r"txt.*record.*encoded",
    r"cobalt.*strike.*dns",
], 0.90)
_register("T1132", "Data Encoding", "command-and-control", [
    r"base64.*c2\b", r"encoded.*traffic",
    r"custom.*encoding.*traffic",
], 0.75)
_register("T1132.001", "Standard Encoding", "command-and-control", [
    r"base64.*encoded.*traffic",
    r"base64.*beacon",
], 0.75)
_register("T1132.002", "Non-Standard Encoding", "command-and-control", [
    r"custom.*encod.*protocol",
    r"xor.*traffic",
], 0.70)
_register("T1001", "Data Obfuscation", "command-and-control", [
    r"obfuscat.*traffic", r"steganograph.*c2",
    r"covert.*channel",
], 0.75)
_register("T1001.001", "Junk Data", "command-and-control", [
    r"junk.*data.*traffic", r"padding.*c2",
], 0.65)
_register("T1001.002", "Steganography", "command-and-control", [
    r"steganograph.*c2", r"image.*covert.*channel",
], 0.75)
_register("T1001.003", "Protocol Impersonation", "command-and-control", [
    r"protocol.*impersonat", r"disguised.*traffic",
], 0.70)
_register("T1568", "Dynamic Resolution", "command-and-control", [
    r"dga\b", r"domain.*generation.*algorithm",
    r"dynamic.*dns", r"dyndns",
    r"fast.*flux",
], 0.85)
_register("T1568.001", "Fast Flux DNS", "command-and-control", [
    r"fast.*flux", r"rapidly.*changing.*dns",
], 0.80)
_register("T1568.002", "Domain Generation Algorithms", "command-and-control", [
    r"dga\b", r"domain.*generation.*algorithm",
    r"algorithmically.*generated.*domain",
], 0.85)
_register("T1568.003", "DNS Calculation", "command-and-control", [
    r"dns.*calculation", r"computed.*dns",
], 0.70)
_register("T1573", "Encrypted Channel", "command-and-control", [
    r"encrypted.*channel", r"ssl.*c2",
    r"tls.*c2", r"encrypted.*c2",
], 0.80)
_register("T1573.001", "Symmetric Cryptography", "command-and-control", [
    r"aes.*c2", r"rc4.*c2",
    r"symmetric.*encrypt.*channel",
], 0.75)
_register("T1573.002", "Asymmetric Cryptography", "command-and-control", [
    r"rsa.*c2", r"asymmetric.*encrypt.*channel",
    r"ssl.*pinned",
], 0.75)
_register("T1008", "Fallback Channels", "command-and-control", [
    r"fallback.*c2", r"backup.*c2",
    r"secondary.*channel",
], 0.75)
_register("T1105", "Ingress Tool Transfer", "command-and-control", [
    r"certutil.*-urlcache", r"bitsadmin.*transfer",
    r"wget\s+http", r"curl\s+.*-[oO]",
    r"Invoke-WebRequest.*-OutFile",
    r"iwr.*-outfile", r"downloadstring",
    r"DownloadFile\(",
    r"(wget|curl).*\|.*bash",
    r"python.*http\.server",
    r"certutil.*-split",
], 0.90)
_register("T1104", "Multi-Stage Channels", "command-and-control", [
    r"multi.?stage.*c2", r"staged.*payload.*download",
    r"second.?stage",
], 0.75)
_register("T1095", "Non-Application Layer Protocol", "command-and-control", [
    r"icmp.*tunnel", r"icmp.*c2",
    r"raw.*socket.*c2", r"tcp.*raw.*c2",
], 0.80)
_register("T1571", "Non-Standard Port", "command-and-control", [
    r"non.?standard.*port", r"unusual.*port",
    r"http.*port\s*(444[3-9]|[5-9]\d{3}|[1-5]\d{4})",
], 0.75)
_register("T1572", "Protocol Tunneling", "command-and-control", [
    r"tunnel", r"ssh.*-[DLR]\s+",
    r"chisel\b", r"ngrok\b",
    r"socat\b.*tunnel", r"proxychains",
    r"sshuttle", r"plink.*-L",
], 0.85)
_register("T1090", "Proxy", "command-and-control", [
    r"proxy", r"socks[45]?",
    r"tor\b.*circuit", r"proxy.*chain",
], 0.80)
_register("T1090.001", "Internal Proxy", "command-and-control", [
    r"internal.*proxy", r"socks.*pivot",
    r"chisel.*server",
], 0.80)
_register("T1090.002", "External Proxy", "command-and-control", [
    r"external.*proxy", r"vpn.*proxy",
    r"anonymiz",
], 0.75)
_register("T1090.003", "Multi-hop Proxy", "command-and-control", [
    r"multi.?hop", r"proxy.*chain",
    r"tor\b.*bridge",
], 0.80)
_register("T1090.004", "Domain Fronting", "command-and-control", [
    r"domain.*front", r"cdn.*front",
    r"cloudfront.*redirect",
], 0.85)
_register("T1219", "Remote Access Software", "command-and-control", [
    r"teamviewer", r"anydesk", r"ammyy",
    r"logmein", r"screenconnect",
    r"bomgar", r"connectwise",
    r"remote.*access.*tool",
], 0.85)
_register("T1102", "Web Service", "command-and-control", [
    r"pastebin.*c2", r"github.*c2",
    r"dropbox.*c2", r"google.*drive.*c2",
    r"telegram.*bot.*c2", r"discord.*webhook.*c2",
    r"slack.*webhook.*c2",
], 0.80)
_register("T1102.001", "Dead Drop Resolver", "command-and-control", [
    r"dead.*drop", r"pastebin.*resolve",
    r"social.*media.*c2.*resolve",
], 0.75)
_register("T1102.002", "Bidirectional Communication", "command-and-control", [
    r"telegram.*bot.*command", r"discord.*bot.*c2",
    r"twitter.*dm.*c2",
], 0.80)
_register("T1102.003", "One-Way Communication", "command-and-control", [
    r"rss.*c2", r"one.?way.*channel",
], 0.65)

# ─── EXFILTRATION (TA0010) ───────────────────────────────────────

_register("T1020", "Automated Exfiltration", "exfiltration", [
    r"automated.*exfil", r"scheduled.*exfil",
    r"batch.*upload.*c2",
], 0.80)
_register("T1020.001", "Traffic Duplication", "exfiltration", [
    r"traffic.*mirror", r"port.*mirror",
    r"span\s+port",
], 0.75)
_register("T1030", "Data Transfer Size Limits", "exfiltration", [
    r"chunk.*exfil", r"split.*transfer",
    r"size.*limit.*exfil",
], 0.70)
_register("T1048", "Exfiltration Over Alternative Protocol", "exfiltration", [
    r"exfil.*dns", r"exfil.*icmp",
    r"exfil.*ftp", r"exfil.*smtp",
], 0.85)
_register("T1048.001", "Exfiltration Over Symmetric Encrypted Non-C2 Protocol", "exfiltration", [
    r"encrypted.*exfil.*alt",
    r"sftp.*exfil",
], 0.75)
_register("T1048.002", "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol", "exfiltration", [
    r"https.*exfil.*alt",
    r"ssl.*exfil.*separate",
], 0.75)
_register("T1048.003", "Exfiltration Over Unencrypted Non-C2 Protocol", "exfiltration", [
    r"ftp.*exfil", r"http.*exfil.*unencrypt",
    r"smtp.*exfil",
], 0.80)
_register("T1041", "Exfiltration Over C2 Channel", "exfiltration", [
    r"exfil.*c2", r"data.*exfil.*beacon",
    r"upload.*c2.*server",
    r"exfiltrat.*command.*control",
], 0.85)
_register("T1011", "Exfiltration Over Other Network Medium", "exfiltration", [
    r"bluetooth.*exfil", r"wifi.*exfil",
    r"radio.*exfil",
], 0.75)
_register("T1052", "Exfiltration Over Physical Medium", "exfiltration", [
    r"usb.*exfil", r"removable.*media.*exfil",
    r"physical.*exfil",
], 0.75)
_register("T1052.001", "Exfiltration over USB", "exfiltration", [
    r"usb.*exfil", r"usb.*copy.*sensitive",
], 0.80)
_register("T1567", "Exfiltration Over Web Service", "exfiltration", [
    r"exfil.*cloud", r"exfil.*web.*service",
    r"upload.*dropbox", r"upload.*gdrive",
    r"upload.*mega\.nz",
], 0.85)
_register("T1567.001", "Exfiltration to Code Repository", "exfiltration", [
    r"git.*push.*exfil", r"github.*exfil",
    r"gitlab.*upload.*data",
], 0.80)
_register("T1567.002", "Exfiltration to Cloud Storage", "exfiltration", [
    r"dropbox.*upload.*exfil", r"gdrive.*upload.*exfil",
    r"onedrive.*upload.*exfil",
    r"mega\.nz.*upload", r"s3.*upload.*exfil",
], 0.85)
_register("T1029", "Scheduled Transfer", "exfiltration", [
    r"scheduled.*transfer", r"timed.*exfil",
    r"periodic.*upload",
], 0.70)
_register("T1537", "Transfer Data to Cloud Account", "exfiltration", [
    r"aws\s+s3\s+cp.*exfil", r"az\s+storage.*upload.*exfil",
    r"cloud.*bucket.*exfil",
], 0.80)

# ─── IMPACT (TA0040) ─────────────────────────────────────────────

_register("T1531", "Account Access Removal", "impact", [
    r"account.*lock.*out", r"password.*reset.*malicious",
    r"net\s+user.*\/active:no", r"Disable-ADAccount",
], 0.85)
_register("T1485", "Data Destruction", "impact", [
    r"rm\s+-rf\s+/", r"format\s+[cC]:",
    r"cipher\s+/w", r"sdelete.*-z",
    r"dd\s+if=/dev/zero",
    r"wiper\b", r"shamoon\b",
], 0.90)
_register("T1486", "Data Encrypted for Impact", "impact", [
    r"ransomware", r"encrypt.*file.*ransom",
    r"\.locked\b", r"\.encrypted\b",
    r"ransom.*note", r"bitcoin.*wallet.*ransom",
    r"all\s+your\s+files",
    r"decrypt.*key.*payment",
], 0.95)
_register("T1565", "Data Manipulation", "impact", [
    r"data.*manipulat", r"data.*tamper",
    r"integrity.*violat",
], 0.75)
_register("T1565.001", "Stored Data Manipulation", "impact", [
    r"database.*tamper", r"record.*modif.*malicious",
], 0.75)
_register("T1565.002", "Transmitted Data Manipulation", "impact", [
    r"traffic.*modif", r"packet.*inject",
], 0.70)
_register("T1491", "Defacement", "impact", [
    r"defac", r"website.*defac",
    r"index\.html.*replaced",
], 0.80)
_register("T1491.001", "Internal Defacement", "impact", [
    r"internal.*defac", r"intranet.*defac",
], 0.75)
_register("T1491.002", "External Defacement", "impact", [
    r"website.*defac", r"public.*defac",
], 0.80)
_register("T1561", "Disk Wipe", "impact", [
    r"disk.*wipe", r"mbr.*wipe",
    r"dd\s+if=/dev/(zero|urandom).*of=/dev/sd",
    r"bootrec.*destroy",
], 0.90)
_register("T1561.001", "Disk Content Wipe", "impact", [
    r"disk.*content.*wipe", r"overwrite.*disk",
], 0.85)
_register("T1561.002", "Disk Structure Wipe", "impact", [
    r"mbr.*wipe", r"partition.*table.*destroy",
], 0.90)
_register("T1499", "Endpoint Denial of Service", "impact", [
    r"dos\b.*endpoint", r"denial.*service",
    r"resource.*exhaust",
], 0.80)
_register("T1499.001", "OS Exhaustion Flood", "impact", [
    r"syn.*flood", r"socket.*exhaust",
], 0.80)
_register("T1499.002", "Service Exhaustion Flood", "impact", [
    r"http.*flood", r"slowloris",
    r"connection.*exhaust",
], 0.80)
_register("T1499.003", "Application Exhaustion Flood", "impact", [
    r"application.*dos", r"app.*layer.*flood",
], 0.75)
_register("T1499.004", "Application or System Exploitation", "impact", [
    r"exploit.*crash", r"vulnerability.*dos",
], 0.75)
_register("T1498", "Network Denial of Service", "impact", [
    r"ddos\b", r"distributed.*denial",
    r"amplification.*attack",
    r"network.*flood",
], 0.85)
_register("T1498.001", "Direct Network Flood", "impact", [
    r"udp.*flood", r"tcp.*flood",
    r"syn.*flood",
], 0.80)
_register("T1498.002", "Reflection Amplification", "impact", [
    r"dns.*amplification", r"ntp.*amplification",
    r"memcached.*amplification",
    r"ssdp.*amplification",
], 0.85)
_register("T1496", "Resource Hijacking", "impact", [
    r"cryptomin", r"crypto.*jack",
    r"xmrig", r"coinhive",
    r"monero.*mine", r"cpu.*100.*mine",
    r"stratum.*pool",
], 0.90)
_register("T1489", "Service Stop", "impact", [
    r"net\s+stop\b", r"sc\s+stop\b",
    r"systemctl\s+stop", r"taskkill\s+/f",
    r"Stop-Service",
    r"kill\s+-9", r"pkill\b",
], 0.80)
_register("T1490", "Inhibit System Recovery", "impact", [
    r"vssadmin.*delete.*shadow",
    r"bcdedit.*recoveryenabled.*no",
    r"wbadmin.*delete.*catalog",
    r"wmic.*shadowcopy.*delete",
    r"disable-computerrestore",
    r"delete.*shadow.*copies",
], 0.95)
_register("T1495", "Firmware Corruption", "impact", [
    r"firmware.*corrupt", r"bios.*flash.*malicious",
    r"uefi.*corrupt",
], 0.85)
_register("T1529", "System Shutdown/Reboot", "impact", [
    r"shutdown\s+/[rfs]", r"shutdown\s+-[rh]",
    r"reboot\b.*force", r"init\s+0\b",
    r"halt\b.*force",
], 0.75)


# ═══════════════════════════════════════════════════════════════════
#  Pattern Count Report
# ═══════════════════════════════════════════════════════════════════

def get_pattern_count() -> int:
    """Return total number of registered technique patterns."""
    return len(TECHNIQUE_PATTERNS)


def get_total_regex_count() -> int:
    """Return total number of individual regex patterns."""
    return sum(len(tp["patterns"]) for tp in TECHNIQUE_PATTERNS.values())


def get_tactic_coverage() -> dict[str, int]:
    """Return count of techniques per tactic."""
    coverage: dict[str, int] = {}
    for tp in TECHNIQUE_PATTERNS.values():
        tactic = tp["tactic"]
        coverage[tactic] = coverage.get(tactic, 0) + 1
    return coverage
