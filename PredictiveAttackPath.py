"""
PredictiveAttackPath — Sublime Text Plugin
==========================================
Analyzes the current document for MITRE ATT&CK techniques,
attributes activity to threat groups, and predicts adversary
next steps using the Python Intelligence Engine.

No external dependencies — uses only Python stdlib + Sublime Text API.

Features:
    - Auto-starts the backend when you first analyze a log
    - Highlights detected technique lines (orange) and predicted (red)
    - Shows results in a bottom output panel
    - Configurable via PredictiveAttackPath.sublime-settings

Install:
    Copy this folder to:
    Windows : %APPDATA%\\Sublime Text\\Packages\\PredictiveAttackPath\\
    macOS   : ~/Library/Application Support/Sublime Text/Packages/PredictiveAttackPath/
    Linux   : ~/.config/sublime-text/Packages/PredictiveAttackPath/
"""



import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

import sublime
import sublime_plugin

# ── Constants ─────────────────────────────────────────────────────

PLUGIN_NAME    = "PredictiveAttackPath"
SETTINGS_FILE  = "PredictiveAttackPath.sublime-settings"
PANEL_NAME     = "attack_path_output"

# Region keys (used to highlight lines in the buffer)
REGION_DETECTED    = "pap_detected"
REGION_PREDICTED   = "pap_predicted"

# Scope names -> Sublime colour scheme colours
SCOPE_DETECTED  = "region.orangish"   # orange underline for confirmed hits
SCOPE_PREDICTED = "region.redish"     # red underline for predicted next steps

# Tactic icons (plain unicode, no emoji dependencies)
TACTIC_ICONS = {
    "Reconnaissance":        "[RECON]",
    "Resource Development":  "[RDEV]",
    "Initial Access":        "[INIT]",
    "Execution":             "[EXEC]",
    "Persistence":           "[PERS]",
    "Privilege Escalation":  "[PRIV]",
    "Defense Evasion":       "[EVAD]",
    "Credential Access":     "[CRED]",
    "Discovery":             "[DISC]",
    "Lateral Movement":      "[LATM]",
    "Collection":            "[COLL]",
    "Command and Control":   "[C2]",
    "Exfiltration":          "[EXFL]",
    "Impact":                "[IMPT]",
}

# ── Backend Process Tracking ──────────────────────────────────────

_backend_process = None        # type: Optional[subprocess.Popen]
_backend_lock = threading.Lock()

# ── Settings helpers ──────────────────────────────────────────────

def _settings():
    # type: () -> sublime.Settings
    return sublime.load_settings(SETTINGS_FILE)

def _engine_url():
    # type: () -> str
    return _settings().get("engine_url", "http://127.0.0.1:8000").rstrip("/")

def _health_path():
    # type: () -> str
    return _settings().get("health_path", "/health")

def _top_n():
    # type: () -> int
    return int(_settings().get("top_n_predictions", 10))

def _auto_analyze_on_save():
    # type: () -> bool
    return bool(_settings().get("auto_analyze_on_save", False))

def _python_cmd():
    # type: () -> List[str]
    """Return the Python command used to launch the backend.

    IMPORTANT: We never use sys.executable here because Sublime Text
    ships its own embedded Python runtime which cannot run FastAPI.
    Instead we read a configurable command from settings.
    """
    cmd = _settings().get("python_cmd", None)
    if cmd:
        return cmd if isinstance(cmd, list) else [cmd]

    # Platform defaults
    if sys.platform == "win32":
        return ["py", "-3"]
    else:
        return ["python3"]

def _backend_entry():
    # type: () -> str
    return _settings().get("backend_entry", "run.py")

def _startup_timeout():
    # type: () -> int
    return int(_settings().get("startup_timeout_sec", 15))

def _backend_dir():
    # type: () -> str
    """Locate the backend/ directory relative to this plugin file."""
    plugin_dir = os.path.dirname(os.path.abspath(__file__))
    backend = os.path.join(plugin_dir, "backend")
    if os.path.isdir(backend):
        return backend
    # Fallback: maybe user placed backend/ one level up
    parent = os.path.dirname(plugin_dir)
    backend_alt = os.path.join(parent, "backend")
    if os.path.isdir(backend_alt):
        return backend_alt
    return backend  # Return expected path even if missing (error later)

# ── HTTP helpers (no third-party libs) ────────────────────────────

def _post_json(url, payload, timeout=30):
    # type: (str, dict, int) -> dict
    data = json.dumps(payload).encode("utf-8")
    req  = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))

def _get_json(url, timeout=10):
    # type: (str, int) -> dict
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))

# ── Backend Health Check ──────────────────────────────────────────

def _is_backend_running():
    # type: () -> bool
    """Check if the backend is reachable by hitting the health endpoint."""
    try:
        url = _engine_url() + _health_path()
        _get_json(url, timeout=3)
        return True
    except Exception:
        return False

# ── Backend Auto-Start ────────────────────────────────────────────

def _start_backend():
    # type: () -> Optional[subprocess.Popen]
    """Launch the backend as a subprocess.

    Uses a lock to prevent duplicate launches. Returns the Popen
    object on success, or None on failure.
    """
    global _backend_process

    with _backend_lock:
        # Double-check: maybe another thread started it
        if _is_backend_running():
            return _backend_process

        # Check if we already have a live process
        if _backend_process is not None and _backend_process.poll() is None:
            # Process is running but not responding yet — don't spawn again
            return _backend_process

        backend_dir = _backend_dir()
        entry_file = os.path.join(backend_dir, _backend_entry())

        if not os.path.isfile(entry_file):
            sublime.error_message(
                "{}: Cannot find backend entry point.\n\n"
                "Expected: {}\n\n"
                "Make sure the backend/ folder is inside your plugin directory."
                .format(PLUGIN_NAME, entry_file)
            )
            return None

        cmd = _python_cmd() + [_backend_entry()]

        # On Windows, hide the console window
        startupinfo = None
        creationflags = 0
        if sys.platform == "win32":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0  # SW_HIDE
            creationflags = subprocess.CREATE_NO_WINDOW

        try:
            _backend_process = subprocess.Popen(
                cmd,
                cwd=backend_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                startupinfo=startupinfo,
                creationflags=creationflags,
            )
            return _backend_process
        except FileNotFoundError:
            sublime.error_message(
                "{}: Python not found.\n\n"
                "Command tried: {}\n\n"
                "Fix this in Settings:\n"
                "  Preferences > Package Settings > PredictiveAttackPath > Settings\n\n"
                "Set \"python_cmd\" to your Python 3 path, e.g.:\n"
                "  [\"C:/Python312/python.exe\"]\n"
                "  [\"python3\"]\n"
                "  [\"py\", \"-3\"]"
                .format(PLUGIN_NAME, " ".join(cmd))
            )
            return None
        except Exception as exc:
            sublime.error_message(
                "{}: Failed to start backend.\n\n"
                "Command: {}\n"
                "Directory: {}\n"
                "Error: {}"
                .format(PLUGIN_NAME, " ".join(cmd), backend_dir, exc)
            )
            return None

def _wait_for_backend(timeout_sec=15):
    # type: (int) -> bool
    """Poll the health endpoint until the backend responds or timeout."""
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        if _is_backend_running():
            return True
        # Check if process died
        if _backend_process is not None and _backend_process.poll() is not None:
            return False
        time.sleep(0.5)
    return False

def _ensure_backend(callback):
    # type: (Callable[[], None]) -> None
    """Ensure backend is running, then call callback on the main thread.

    If the backend is already running, callback fires immediately.
    Otherwise, starts it in a background thread and calls callback
    once it's ready (or shows an error if startup fails).
    """
    if _is_backend_running():
        callback()
        return

    sublime.status_message("{}: Starting backend...".format(PLUGIN_NAME))

    def _worker():
        proc = _start_backend()
        if proc is None:
            return  # Error already shown

        timeout = _startup_timeout()
        ready = _wait_for_backend(timeout)

        if ready:
            sublime.set_timeout(callback, 0)
            sublime.set_timeout(
                lambda: sublime.status_message(
                    "{}: Backend ready".format(PLUGIN_NAME)
                ),
                0,
            )
        else:
            # Try to read stderr for debugging
            stderr_text = ""
            try:
                if proc.stderr:
                    stderr_text = proc.stderr.read(2000).decode("utf-8", errors="replace")
            except Exception:
                pass

            sublime.set_timeout(
                lambda: sublime.error_message(
                    "{}: Backend failed to start within {} seconds.\n\n"
                    "Troubleshooting:\n"
                    "1. Open a terminal and run:\n"
                    "   cd {}\n"
                    "   {} {}\n\n"
                    "2. Check if dependencies are installed:\n"
                    "   pip install -r requirements.txt\n\n"
                    "{}".format(
                        PLUGIN_NAME,
                        timeout,
                        _backend_dir(),
                        " ".join(_python_cmd()),
                        _backend_entry(),
                        "Stderr:\n" + stderr_text if stderr_text else "",
                    )
                ),
                0,
            )

    threading.Thread(target=_worker, daemon=True).start()

# ── Output panel ──────────────────────────────────────────────────

def _get_panel(window):
    # type: (sublime.Window) -> sublime.View
    panel = window.find_output_panel(PANEL_NAME)
    if panel is None:
        panel = window.create_output_panel(PANEL_NAME)
        panel.settings().set("word_wrap", False)
        panel.settings().set("gutter", False)
        panel.settings().set("line_numbers", False)
        panel.settings().set("scroll_past_end", False)
        panel.assign_syntax(
            "Packages/Text/Plain text.tmLanguage"
        )
    return panel

def _write_panel(window, text):
    # type: (sublime.Window, str) -> None
    panel = _get_panel(window)
    panel.run_command("select_all")
    panel.run_command("right_delete")
    panel.run_command("append", {"characters": text})
    window.run_command("show_panel", {"panel": "output.{}".format(PANEL_NAME)})

# ── Result formatter ──────────────────────────────────────────────

def _format_results(result, elapsed_ms):
    # type: (dict, float) -> str
    lines = []  # type: List[str]
    sep  = "=" * 70
    dash = "-" * 70

    lines.append(sep)
    lines.append("  PREDICTIVE ATTACK PATH  —  Analysis Results")
    lines.append(sep)
    lines.append("  Analysis time : {:.0f} ms".format(elapsed_ms))
    lines.append("")

    # ── Detected Techniques ──────────────────────────────────
    detected = result.get("detected_techniques", [])
    lines.append("[DETECTED TECHNIQUES]  ({} found)".format(len(detected)))
    lines.append(dash)
    if detected:
        lines.append("  {:<12}  {:<22}  {:>5}  Name".format("ID", "Tactic", "Conf"))
        lines.append("  {}  {}  {}  {}".format("-" * 12, "-" * 22, "-" * 5, "-" * 30))
        for t in detected:
            conf = "{:.0f}%".format(t.get("confidence", 0) * 100)
            lines.append(
                "  {:<12}  {:<22}  {:>5}  {}".format(
                    t.get("technique_id", ""),
                    t.get("tactic", ""),
                    conf,
                    t.get("technique_name", ""),
                )
            )
            for m in t.get("matches", [])[:3]:
                lines.append(
                    "    line {:>4}:  {}".format(
                        m.get("line", "?"),
                        m.get("text", "").strip()[:60],
                    )
                )
    else:
        lines.append("  (none detected)")
    lines.append("")

    # ── Predicted Next Steps ─────────────────────────────────
    predicted = result.get("likely_next_steps", [])
    lines.append("[PREDICTED NEXT STEPS]  ({} predicted)".format(len(predicted)))
    lines.append(dash)
    if predicted:
        lines.append("  {:<12}  {:>5}  {:<22}  Name".format("ID", "Prob", "Tactic"))
        lines.append("  {}  {}  {}  {}".format("-" * 12, "-" * 5, "-" * 22, "-" * 30))
        for p in predicted:
            prob = "{:.0f}%".format(p.get("probability", 0) * 100)
            lines.append(
                "  {:<12}  {:>5}  {:<22}  {}".format(
                    p.get("technique_id", ""),
                    prob,
                    p.get("tactic", ""),
                    p.get("technique_name", ""),
                )
            )
            reasoning = p.get("reasoning", "")
            if reasoning:
                lines.append("    Reason: {}".format(reasoning))
    else:
        lines.append("  (none predicted)")
    lines.append("")

    # ── Attacker Attribution ─────────────────────────────────
    attribution = result.get("attacker_attribution", [])
    lines.append("[ATTACKER ATTRIBUTION]  ({} groups matched)".format(len(attribution)))
    lines.append(dash)
    if attribution:
        lines.append("  {:<10}  {:>5}  {:>7}  {:>8}  Name".format(
            "Group ID", "Score", "Matched", "Playbook"
        ))
        lines.append("  {}  {}  {}  {}  {}".format(
            "-" * 10, "-" * 5, "-" * 7, "-" * 8, "-" * 30
        ))
        for a in attribution:
            score   = "{:.0f}%".format(a.get("match_score", 0) * 100)
            matched = len(a.get("matched_techniques", []))
            playbook = a.get("full_playbook_size", 0)
            lines.append(
                "  {:<10}  {:>5}  {:>7}  {:>8}  {}".format(
                    a.get("group_id", ""),
                    score,
                    matched,
                    playbook,
                    a.get("group_name", ""),
                )
            )
            aliases = a.get("aliases", [])
            if aliases:
                lines.append("    Aliases: {}".format(", ".join(aliases[:4])))
    else:
        lines.append("  (no groups matched)")
    lines.append("")

    # ── Attack Path (Kill Chain) ─────────────────────────────
    attack_path = result.get("attack_path", [])
    lines.append("[ATTACK PATH — KILL CHAIN]  ({} stages)".format(len(attack_path)))
    lines.append(dash)
    if attack_path:
        top_group = (
            attribution[0].get("group_name", "Unknown")
            if attribution else "Unknown"
        )
        lines.append("  Active Campaign — likely: {}".format(top_group))
        lines.append("")
        for stage in attack_path:
            tactic  = stage.get("tactic_display", stage.get("tactic", ""))
            icon    = TACTIC_ICONS.get(tactic, "[    ]")
            techs   = stage.get("techniques", [])
            lines.append("  {} {}".format(icon, tactic))
            for tech in techs:
                is_predicted = tech.endswith("*")
                tech_id      = tech.rstrip("*")
                marker       = "-> (PREDICTED)" if is_predicted else "ok"
                lines.append("      {}  {}".format(marker, tech_id))
    else:
        lines.append("  (no attack path reconstructed)")

    lines.append("")

    # ── YARA Matches ─────────────────────────────────────────
    yara_matches = result.get("yara_matches", [])
    if yara_matches:
        lines.append("[YARA MATCHES]  ({} rules triggered)".format(len(yara_matches)))
        lines.append(dash)
        for ym in yara_matches:
            sev = ym.get("severity", "medium").upper()
            lines.append(
                "  [{sev}] {name}".format(
                    sev=sev, name=ym.get("rule_name", ""),
                )
            )
            desc = ym.get("description", "")
            if desc:
                lines.append("    {}".format(desc))
            mitre = ym.get("mitre_techniques", [])
            if mitre:
                lines.append("    MITRE: {}".format(", ".join(mitre)))
            for s in ym.get("matched_strings", [])[:3]:
                lines.append(
                    "    line {:>4}: {}".format(
                        s.get("line_number", "?"),
                        s.get("matched_data", "")[:60],
                    )
                )
        lines.append("")

    # ── Sigma Matches ────────────────────────────────────────
    sigma_matches = result.get("sigma_matches", [])
    if sigma_matches:
        lines.append("[SIGMA RULE MATCHES]  ({} rules triggered)".format(len(sigma_matches)))
        lines.append(dash)
        for sm in sigma_matches:
            sev = sm.get("severity", "medium").upper()
            lines.append(
                "  [{sev}] {name}".format(
                    sev=sev, name=sm.get("rule_name", ""),
                )
            )
            desc = sm.get("description", "")
            if desc:
                lines.append("    {}".format(desc))
            mitre = sm.get("mitre_techniques", [])
            src = sm.get("source", "")
            if mitre or src:
                parts = []
                if src:
                    parts.append("Source: {}".format(src))
                if mitre:
                    parts.append("Maps to: {}".format(", ".join(mitre)))
                lines.append("    {}".format(" | ".join(parts)))
        lines.append("")

    # ── Threat Correlation Summary ───────────────────────────
    corr = result.get("threat_correlation", {})
    if corr:
        lines.append("[CORRELATED THREAT INTEL]")
        lines.append(dash)

        tooling = corr.get("tooling_identified", [])
        if tooling:
            lines.append(
                "  Tooling identified : {}".format(", ".join(tooling))
            )

        cov = corr.get("sigma_coverage_pct", 0)
        t_with = corr.get("techniques_with_sigma", 0)
        t_total = corr.get("total_detected_techniques", 0)
        lines.append(
            "  SIEM coverage      : {}/{} techniques ({:.0f}%)".format(
                t_with, t_total, cov
            )
        )

        gaps = corr.get("detection_gaps", [])
        if gaps:
            gap_ids = ", ".join(g.get("technique_id", "") for g in gaps[:5])
            lines.append(
                "  Detection gaps     : {}".format(gap_ids)
            )

        confirmed = corr.get("cross_confirmed_techniques", [])
        if confirmed:
            lines.append(
                "  Multi-engine conf. : {}".format(", ".join(confirmed[:5]))
            )

        crit = corr.get("critical_findings", 0)
        high = corr.get("high_findings", 0)
        med = corr.get("medium_findings", 0)
        lines.append(
            "  Severity summary   : {} critical, {} high, {} medium".format(
                crit, high, med
            )
        )

        lines.append("")
        recs = corr.get("recommendations", [])
        if recs:
            lines.append("  Recommendations:")
            for i, rec in enumerate(recs, 1):
                lines.append("    {}. {}".format(i, rec))

        lines.append("")

    lines.append(sep)
    return "\n".join(lines)

# ── Core analysis logic ────────────────────────────────────────────

def _run_analysis(view, on_done):
    # type: (sublime.View, Callable) -> None
    """Read the full buffer, POST to the intelligence engine,
    then call on_done(result_dict, elapsed_ms) on the main thread.
    """
    log_text = view.substr(sublime.Region(0, view.size()))
    if not log_text.strip():
        sublime.status_message("{}: document is empty".format(PLUGIN_NAME))
        return

    url     = "{}/analyze_log".format(_engine_url())
    payload = {
        "log_text":           log_text,
        "top_n_predictions":  _top_n(),
        "attribution_boost":  True,
    }

    def _worker():
        t0 = time.time()
        try:
            result     = _post_json(url, payload)
            elapsed_ms = (time.time() - t0) * 1000
            sublime.set_timeout(lambda: on_done(result, elapsed_ms), 0)
        except urllib.error.URLError as exc:
            msg = (
                "{plugin}: Cannot reach engine at {url}\n"
                "Start it with:  cd backend && python run.py\n"
                "Error: {err}".format(
                    plugin=PLUGIN_NAME, url=_engine_url(), err=exc
                )
            )
            sublime.set_timeout(
                lambda: sublime.error_message(msg), 0
            )
        except Exception as exc:
            sublime.set_timeout(
                lambda: sublime.error_message(
                    "{}: {}".format(PLUGIN_NAME, exc)
                ),
                0,
            )

    threading.Thread(target=_worker, daemon=True).start()

# ── Highlighting helpers ───────────────────────────────────────────

def _apply_highlights(view, result):
    # type: (sublime.View, dict) -> None
    """Highlight detected technique lines (orange) in the buffer."""
    detected_regions = []   # type: List[sublime.Region]
    predicted_regions = []  # type: List[sublime.Region]

    # Detected technique lines
    for tech in result.get("detected_techniques", []):
        for match in tech.get("matches", []):
            line_num = match.get("line", 0)
            if line_num < 1:
                continue
            # Sublime lines are 0-indexed
            line_region = view.line(view.text_point(line_num - 1, 0))
            detected_regions.append(line_region)

    # Predicted technique: scan buffer for matching technique IDs or names
    all_text = view.substr(sublime.Region(0, view.size()))
    for pred in result.get("likely_next_steps", []):
        tech_id   = pred.get("technique_id", "")
        tech_name = pred.get("technique_name", "")
        for term in (tech_id, tech_name):
            if not term:
                continue
            start = 0
            lower_text = all_text.lower()
            lower_term = term.lower()
            while True:
                pos = lower_text.find(lower_term, start)
                if pos == -1:
                    break
                line_region = view.line(pos)
                predicted_regions.append(line_region)
                start = pos + len(lower_term)

    view.add_regions(
        REGION_DETECTED,
        detected_regions,
        SCOPE_DETECTED,
        "dot",
        sublime.DRAW_NO_FILL,
    )
    view.add_regions(
        REGION_PREDICTED,
        predicted_regions,
        SCOPE_PREDICTED,
        "bookmark",
        sublime.DRAW_NO_FILL | sublime.DRAW_SQUIGGLY_UNDERLINE,
    )

def _clear_highlights(view):
    # type: (sublime.View) -> None
    view.erase_regions(REGION_DETECTED)
    view.erase_regions(REGION_PREDICTED)

# ── Commands ──────────────────────────────────────────────────────

class PredictiveAttackPathAnalyzeCommand(sublime_plugin.TextCommand):
    """
    Analyze the current document.
    Bound to: Ctrl+Shift+A  (see Default.sublime-keymap)
    Also available via: Tools > Command Palette > Attack Path: Analyze
    """

    def run(self, edit):
        # type: (sublime.Edit) -> None
        view   = self.view
        window = view.window()
        sublime.status_message("{}: Preparing analysis...".format(PLUGIN_NAME))
        _write_panel(window, "{}: Preparing analysis...\n".format(PLUGIN_NAME))

        def _do_analysis():
            sublime.status_message("{}: Analyzing...".format(PLUGIN_NAME))
            _write_panel(window, "{}: Analyzing document, please wait...\n".format(PLUGIN_NAME))

            def on_done(result, elapsed_ms):
                # type: (dict, float) -> None
                _apply_highlights(view, result)
                output = _format_results(result, elapsed_ms)
                _write_panel(window, output)

                detected  = len(result.get("detected_techniques", []))
                predicted = len(result.get("likely_next_steps", []))
                groups    = len(result.get("attacker_attribution", []))
                sublime.status_message(
                    "{plugin}: {det} detected, {pred} predicted, "
                    "{grp} groups matched — {ms:.0f}ms".format(
                        plugin=PLUGIN_NAME,
                        det=detected,
                        pred=predicted,
                        grp=groups,
                        ms=elapsed_ms,
                    )
                )

            _run_analysis(view, on_done)

        # Ensure backend is running before analyzing
        _ensure_backend(_do_analysis)

    def is_enabled(self):
        # type: () -> bool
        return self.view.size() > 0


class PredictiveAttackPathClearCommand(sublime_plugin.TextCommand):
    """
    Clear all highlights and close the results panel.
    Bound to: Ctrl+Shift+X
    """

    def run(self, edit):
        # type: (sublime.Edit) -> None
        _clear_highlights(self.view)
        window = self.view.window()
        window.destroy_output_panel(PANEL_NAME)
        sublime.status_message("{}: Cleared".format(PLUGIN_NAME))


class PredictiveAttackPathHealthCommand(sublime_plugin.WindowCommand):
    """
    Check if the Intelligence Engine is reachable and show its stats.
    Available via: Command Palette > Attack Path: Check Engine Health
    """

    def run(self):
        # type: () -> None
        url = "{}/health".format(_engine_url())
        sublime.status_message("{}: Checking engine health...".format(PLUGIN_NAME))

        def _worker():
            try:
                h = _get_json(url)
                msg = (
                    "Intelligence Engine — OK\n\n"
                    "  Techniques loaded : {tech:,}\n"
                    "  Groups loaded     : {grp:,}\n"
                    "  Regex patterns    : {rgx:,}\n"
                    "  Graph nodes       : {nodes:,}\n"
                    "  Graph edges       : {edges:,}\n"
                    "  Boot time         : {boot:.2f}s\n"
                    "  URL               : {url}".format(
                        tech=h.get("techniques_loaded", "?"),
                        grp=h.get("groups_loaded", "?"),
                        rgx=h.get("regex_patterns", "?"),
                        nodes=h.get("graph_nodes", "?"),
                        edges=h.get("graph_edges", "?"),
                        boot=h.get("boot_time_seconds", 0),
                        url=_engine_url(),
                    )
                )
                sublime.set_timeout(
                    lambda: sublime.message_dialog(msg), 0
                )
            except urllib.error.URLError:
                sublime.set_timeout(
                    lambda: sublime.error_message(
                        "Cannot reach Intelligence Engine at {url}\n\n"
                        "Start it with:\n"
                        "  cd backend\n"
                        "  python run.py".format(url=_engine_url())
                    ),
                    0,
                )
            except Exception as exc:
                sublime.set_timeout(
                    lambda: sublime.error_message(
                        "{}: {}".format(PLUGIN_NAME, exc)
                    ),
                    0,
                )

        threading.Thread(target=_worker, daemon=True).start()


class PredictiveAttackPathToggleAutoAnalyzeCommand(sublime_plugin.WindowCommand):
    """
    Toggle automatic analysis on every file save.
    Available via: Command Palette > Attack Path: Toggle Auto-Analyze on Save
    """

    def run(self):
        # type: () -> None
        settings  = _settings()
        current   = settings.get("auto_analyze_on_save", False)
        new_value = not current
        settings.set("auto_analyze_on_save", new_value)
        sublime.save_settings(SETTINGS_FILE)
        state = "ENABLED" if new_value else "DISABLED"
        sublime.status_message(
            "{}: Auto-analyze on save {}".format(PLUGIN_NAME, state)
        )

    def is_checked(self):
        # type: () -> bool
        return _auto_analyze_on_save()


class PredictiveAttackPathShowPanelCommand(sublime_plugin.WindowCommand):
    """Re-show the results panel if it was closed."""

    def run(self):
        # type: () -> None
        panel = self.window.find_output_panel(PANEL_NAME)
        if panel:
            self.window.run_command(
                "show_panel", {"panel": "output.{}".format(PANEL_NAME)}
            )
        else:
            sublime.status_message(
                "{}: No results yet — run Analyze first".format(PLUGIN_NAME)
            )

# ── Event Listener (auto-analyze on save) ─────────────────────────

class PredictiveAttackPathListener(sublime_plugin.EventListener):
    """
    Listens for post-save events and triggers analysis automatically
    when auto_analyze_on_save is enabled in settings.
    """

    def on_post_save_async(self, view):
        # type: (sublime.View) -> None
        if not _auto_analyze_on_save():
            return
        view.run_command("predictive_attack_path_analyze")
