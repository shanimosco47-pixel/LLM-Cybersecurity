#!/usr/bin/env python3
"""Skill Guard: scans Claude Code skills with Cisco's skill-scanner.

Entry points:
  hook-pre       PreToolUse hook. Scans a skill before Write/Edit lands on disk.
  hook-post      PostToolUse hook. Detects skills that changed (any install
                 method run by Claude) and quarantines dangerous ones.
  hook-session   SessionStart hook. Same check, for installs made outside
                 Claude (/plugin install, manual copy).
  scan-all       Full rescan of every known skill and the claude.ai gate archive.
  daily          Optional scanner upgrade, then scan-all. Run by the scheduler.
  watch-gate     Polls the claude.ai gate inbox and scans every dropped .zip.
  install-hooks / uninstall-hooks   Merge or remove our entries in
                 ~/.claude/settings.json.
  status / restore NAME
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

HOME = Path(os.environ.get("SKILL_GUARD_HOME_OVERRIDE", Path.home()))
GUARD_DIR = Path(os.environ.get("SKILL_GUARD_DIR", HOME / ".skill-guard"))
CLAUDE_DIR = HOME / ".claude"
STATE_FILE = GUARD_DIR / "state.json"
CONFIG_FILE = GUARD_DIR / "config.json"
LOG_FILE = GUARD_DIR / "guard.log"
REPORTS_DIR = GUARD_DIR / "reports"
QUARANTINE_DIR = GUARD_DIR / "quarantine"

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}
HOOK_MARKER = "skill-guard"

DEFAULT_CONFIG = {
    # Findings at or above this severity block / quarantine a skill.
    "block_severity": "HIGH",
    "use_behavioral": True,
    "scan_timeout_seconds": 120,
    "gate_dir": str(HOME / "SkillGate"),
    "auto_update_scanner": True,
    "notify": True,
    # Zip safety limits for the claude.ai gate.
    "max_zip_bytes": 50 * 1024 * 1024,
    "max_zip_members": 2000,
}

# Read deny rules also block Edit/Write on the same path.
DENY_RULES = [
    "Read(~/.ssh/**)",
    "Read(~/.aws/**)",
    "Read(~/.azure/**)",
    "Read(~/.gnupg/**)",
    "Read(~/.kube/**)",
    "Read(~/.docker/config.json)",
    "Read(~/.git-credentials)",
    "Read(**/.env)",
    "Read(**/.env.*)",
    "Edit(~/.skill-guard/**)",
    "Edit(~/.claude/settings.json)",
]

PLACEHOLDER_SKILL_MD = (
    "---\nname: pending-skill\ndescription: Placeholder added by Skill Guard "
    "so the scanner can inspect bundled files.\n---\n"
)


# --------------------------------------------------------------------------- utils

def now_iso() -> str:
    return dt.datetime.now().isoformat(timespec="seconds")


def log(msg: str) -> None:
    GUARD_DIR.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{now_iso()} {msg}\n")


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def save_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    cfg.update(load_json(CONFIG_FILE, {}))
    return cfg


def load_state() -> dict:
    state = load_json(STATE_FILE, {})
    state.setdefault("skills", {})
    state.setdefault("projects", [])
    return state


def sev_rank(sev: str | None) -> int:
    try:
        return SEVERITIES.index((sev or "INFO").upper())
    except ValueError:
        return 0


def notify(title: str, message: str) -> None:
    """Desktop notification. Text goes through env vars, never into the script."""
    if not load_config().get("notify", True):
        return
    env = dict(os.environ, SG_TITLE=title[:120], SG_MSG=message[:400])
    try:
        if os.name == "nt":
            script = (
                "$t=[Security.SecurityElement]::Escape($env:SG_TITLE);"
                "$m=[Security.SecurityElement]::Escape($env:SG_MSG);"
                "[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]|Out-Null;"
                "[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]|Out-Null;"
                "$x=New-Object Windows.Data.Xml.Dom.XmlDocument;"
                "$x.LoadXml(\"<toast><visual><binding template='ToastGeneric'><text>$t</text><text>$m</text></binding></visual></toast>\");"
                "$app='{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe';"
                "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($x))"
            )
            subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                env=env, timeout=30, capture_output=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        elif sys.platform == "darwin":
            subprocess.run(
                ["osascript", "-e",
                 "display notification (system attribute \"SG_MSG\") with title (system attribute \"SG_TITLE\")"],
                env=env, timeout=30, capture_output=True,
            )
        elif shutil.which("notify-send"):
            subprocess.run(["notify-send", title, message], timeout=30, capture_output=True)
    except (OSError, subprocess.SubprocessError) as e:
        log(f"notify failed: {e}")


# --------------------------------------------------------------------------- skill discovery

def skill_roots(extra_projects: list[str] | None = None) -> list[Path]:
    roots = [CLAUDE_DIR / "skills", CLAUDE_DIR / "plugins"]
    for p in extra_projects or []:
        roots.append(Path(p) / ".claude" / "skills")
    return roots


def find_skill_dirs(root: Path) -> list[Path]:
    found: list[Path] = []
    if not root.is_dir():
        return found
    for dirpath, dirnames, filenames in os.walk(root):
        if "SKILL.md" in filenames:
            found.append(Path(dirpath))
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
    return found


def fingerprint(skill_dir: Path) -> str:
    h = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(skill_dir):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            p = Path(dirpath) / name
            try:
                st = p.stat()
            except OSError:
                continue
            rel = p.relative_to(skill_dir).as_posix()
            h.update(f"{rel}\0{st.st_size}\0{st.st_mtime_ns}\n".encode())
    return h.hexdigest()


def skill_dir_for_path(file_path: Path) -> Path | None:
    """Return the skill directory a file belongs to, or None if not a skill file."""
    parts = file_path.parts
    for i in range(len(parts) - 2):
        if parts[i] == ".claude" and parts[i + 1] == "skills" and i + 2 < len(parts) - 1:
            return Path(*parts[: i + 3])
    plugins = CLAUDE_DIR / "plugins"
    try:
        file_path.relative_to(plugins)
    except ValueError:
        return None
    if file_path.name == "SKILL.md":
        return file_path.parent
    for parent in file_path.parents:
        if parent == plugins:
            break
        if (parent / "SKILL.md").is_file():
            return parent
    return None


# --------------------------------------------------------------------------- scanning

def scanner_exe() -> str:
    bindir = Path(sys.executable).parent
    for name in ("skill-scanner.exe", "skill-scanner"):
        if (bindir / name).exists():
            return str(bindir / name)
    return shutil.which("skill-scanner") or "skill-scanner"


def scan_dir(skill_dir: Path, label: str | None = None) -> dict:
    """Run the scanner. Returns {verdict: safe|blocked|error, max_severity, findings, report}."""
    cfg = load_config()
    target = skill_dir
    tmp = None
    if not (skill_dir / "SKILL.md").is_file():
        # The scanner refuses folders without SKILL.md; scan the scripts anyway.
        tmp = Path(tempfile.mkdtemp(prefix="sg-scan-"))
        target = tmp / skill_dir.name
        shutil.copytree(skill_dir, target)
        (target / "SKILL.md").write_text(PLACEHOLDER_SKILL_MD, encoding="utf-8")
    cmd = [scanner_exe(), "scan", str(target), "--format", "json", "--compact"]
    if cfg.get("use_behavioral", True):
        cmd.append("--use-behavioral")
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=cfg["scan_timeout_seconds"],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        data = json.loads(proc.stdout)
    except (OSError, subprocess.SubprocessError, ValueError) as e:
        err = locals().get("proc")
        detail = (err.stderr.strip()[-300:] if err is not None and err.stderr else str(e))
        log(f"scan error {skill_dir}: {detail}")
        return {"verdict": "error", "max_severity": None, "findings": [], "error": detail}
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)

    findings = data.get("findings", [])
    worst = max((f.get("severity") for f in findings), key=sev_rank, default="INFO")
    blocked = sev_rank(worst) >= sev_rank(cfg["block_severity"])
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_label = "".join(c if c.isalnum() or c in "-_" else "_" for c in (label or skill_dir.name))[:60]
    report = REPORTS_DIR / f"{stamp}_{safe_label}.json"
    save_json(report, data)
    verdict = "blocked" if blocked else "safe"
    log(f"scan {verdict} max={worst} findings={len(findings)} {skill_dir}")
    return {"verdict": verdict, "max_severity": worst, "findings": findings, "report": str(report)}


def describe(result: dict, limit: int = 6) -> str:
    cfg = load_config()
    if result["verdict"] == "error":
        return f"scanner error: {result.get('error', 'unknown')}"
    bad = [f for f in result["findings"] if sev_rank(f.get("severity")) >= sev_rank(cfg["block_severity"])]
    bad.sort(key=lambda f: -sev_rank(f.get("severity")))
    lines = [f"- [{f.get('severity')}] {f.get('title')} ({f.get('rule_id')}) in {Path(str(f.get('file_path'))).name}"
             for f in bad[:limit]]
    if len(bad) > limit:
        lines.append(f"- ... and {len(bad) - limit} more")
    lines.append(f"Full report: {result.get('report')}")
    return "\n".join(lines)


def quarantine(skill_dir: Path) -> Path:
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = QUARANTINE_DIR / f"{stamp}_{skill_dir.name}"
    shutil.move(str(skill_dir), str(dest))
    save_json(dest.with_name(dest.name + ".origin.json"), {"origin": str(skill_dir), "at": now_iso()})
    log(f"quarantined {skill_dir} -> {dest}")
    return dest


def check_changes(projects: list[str] | None = None, force: bool = False) -> list[dict]:
    """Scan skills that are new or changed since the last scan. Quarantine blocked ones."""
    state = load_state()
    for p in projects or []:
        if p and p not in state["projects"]:
            state["projects"].append(p)
    seen: set[str] = set()
    incidents: list[dict] = []
    for root in skill_roots(state["projects"]):
        for skill_dir in find_skill_dirs(root):
            key = str(skill_dir)
            seen.add(key)
            fp = fingerprint(skill_dir)
            prev = state["skills"].get(key)
            if prev and prev.get("fp") == fp and (
                    prev.get("verdict") == "restored-by-user"
                    or (not force and prev.get("verdict") != "error")):
                continue
            result = scan_dir(skill_dir)
            entry = {"fp": fp, "verdict": result["verdict"], "max_severity": result["max_severity"],
                     "scanned_at": now_iso(), "report": result.get("report")}
            if result["verdict"] == "blocked":
                dest = quarantine(skill_dir)
                entry["quarantined_to"] = str(dest)
                incidents.append({"skill": key, "quarantined_to": str(dest), "result": result})
                state["skills"].pop(key, None)
                seen.discard(key)
                continue
            if result["verdict"] == "error":
                incidents.append({"skill": key, "quarantined_to": None, "result": result})
            state["skills"][key] = entry
    for key in list(state["skills"]):
        if key not in seen:
            del state["skills"][key]
    save_json(STATE_FILE, state)
    return incidents


def incidents_text(incidents: list[dict]) -> str:
    out = []
    for inc in incidents:
        if inc["quarantined_to"]:
            out.append(f"SKILL GUARD: dangerous skill quarantined.\nSkill: {inc['skill']}\n"
                       f"Moved to: {inc['quarantined_to']}\n{describe(inc['result'])}")
        else:
            out.append(f"SKILL GUARD: could not scan {inc['skill']} ({describe(inc['result'])}). "
                       "Treat this skill as untrusted until it is scanned.")
    return "\n\n".join(out)


# --------------------------------------------------------------------------- hooks

def read_hook_input() -> dict:
    try:
        return json.loads(sys.stdin.read() or "{}")
    except ValueError:
        return {}


def stage_edit(skill_dir: Path, file_path: Path, tool: str, tool_input: dict) -> Path | None:
    """Copy the skill to a temp dir and apply the pending change. None = cannot stage."""
    tmp = Path(tempfile.mkdtemp(prefix="sg-stage-"))
    staged = tmp / skill_dir.name
    if skill_dir.is_dir():
        shutil.copytree(skill_dir, staged, ignore=shutil.ignore_patterns(*SKIP_DIRS))
    else:
        staged.mkdir(parents=True)
    target = staged / file_path.relative_to(skill_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    if tool == "Write":
        target.write_text(tool_input.get("content", ""), encoding="utf-8")
        return staged
    if tool in ("Edit", "MultiEdit"):
        if not target.is_file():
            return None
        text = target.read_text(encoding="utf-8", errors="replace")
        edits = tool_input.get("edits") or [tool_input]
        for e in edits:
            old, new = e.get("old_string", ""), e.get("new_string", "")
            if not old or old not in text:
                return None
            text = text.replace(old, new) if e.get("replace_all") else text.replace(old, new, 1)
        target.write_text(text, encoding="utf-8")
        return staged
    return None


def hook_pre() -> int:
    data = read_hook_input()
    tool = data.get("tool_name", "")
    tool_input = data.get("tool_input") or {}
    raw = tool_input.get("file_path")
    if tool not in ("Write", "Edit", "MultiEdit") or not raw:
        return 0
    file_path = Path(raw)
    if not file_path.is_absolute():
        file_path = Path(data.get("cwd") or os.getcwd()) / file_path
    skill_dir = skill_dir_for_path(file_path)
    if not skill_dir:
        return 0
    staged = stage_edit(skill_dir, file_path, tool, tool_input)
    if staged is None:
        return 0  # PostToolUse rescans whatever lands on disk.
    try:
        result = scan_dir(staged, label=skill_dir.name)
    finally:
        shutil.rmtree(staged.parent, ignore_errors=True)
    if result["verdict"] == "safe":
        return 0
    if result["verdict"] == "blocked":
        decision = "deny"
        reason = (f"Skill Guard blocked this change to skill '{skill_dir.name}'. "
                  f"Cisco skill-scanner found dangerous content:\n{describe(result)}\n"
                  "Do not try to bypass this block. Tell the user what was found.")
        notify("Skill Guard: skill blocked", f"{skill_dir.name}: {result['max_severity']}")
    else:
        decision = "ask"
        reason = f"Skill Guard could not scan skill '{skill_dir.name}' ({describe(result)}). Allow anyway?"
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": reason,
    }}))
    return 0


def hook_post() -> int:
    data = read_hook_input()
    incidents = check_changes(projects=[data.get("cwd")] if data.get("cwd") else None)
    if not incidents:
        return 0
    if any(i["quarantined_to"] for i in incidents):
        notify("Skill Guard: skill quarantined", f"{len(incidents)} skill(s) need attention")
    print(json.dumps({"decision": "block", "reason": incidents_text(incidents) +
                      "\nTell the user about this. Do not restore or reinstall the skill."}))
    return 0


def hook_session() -> int:
    data = read_hook_input()
    incidents = check_changes(projects=[data.get("cwd")] if data.get("cwd") else None)
    if not incidents:
        return 0
    if any(i["quarantined_to"] for i in incidents):
        notify("Skill Guard: skill quarantined", f"{len(incidents)} skill(s) need attention")
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "SessionStart",
        "additionalContext": incidents_text(incidents) +
        "\nAt the start of your first reply, warn the user about the above.",
        "reloadSkills": True,
    }}))
    return 0


# --------------------------------------------------------------------------- claude.ai gate

def gate_dirs() -> dict[str, Path]:
    base = Path(load_config()["gate_dir"])
    dirs = {name: base / name for name in ("inbox", "approved", "rejected")}
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    return dirs


def safe_extract(zip_path: Path, dest: Path) -> None:
    cfg = load_config()
    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        if len(infos) > cfg["max_zip_members"]:
            raise ValueError(f"too many files in zip ({len(infos)})")
        if sum(i.file_size for i in infos) > cfg["max_zip_bytes"]:
            raise ValueError("zip expands beyond the size limit (possible zip bomb)")
        root = dest.resolve()
        for info in infos:
            out = (dest / info.filename).resolve()
            if root != out and root not in out.parents:
                raise ValueError(f"unsafe path in zip: {info.filename}")
        zf.extractall(dest)


def scan_package(path: Path) -> tuple[str, str]:
    """Scan a gate .zip or folder. Returns (verdict, text report)."""
    tmp = Path(tempfile.mkdtemp(prefix="sg-gate-"))
    try:
        if path.is_dir():
            root = path
        else:
            root = tmp / "x"
            safe_extract(path, root)
        skills = find_skill_dirs(root)
        if not skills:
            return "blocked", "No SKILL.md found. This is not a valid skill package."
        verdict, parts = "safe", []
        for s in skills:
            r = scan_dir(s, label=s.name)
            parts.append(f"## {s.name}: {r['verdict'].upper()} (max {r['max_severity']})\n{describe(r)}")
            if r["verdict"] == "blocked" or (r["verdict"] == "error" and verdict == "safe"):
                verdict = r["verdict"]
        return verdict, "\n\n".join(parts)
    except (zipfile.BadZipFile, ValueError, OSError) as e:
        return "blocked", f"Rejected before scanning: {e}"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def process_gate_item(item: Path, dirs: dict[str, Path]) -> str:
    verdict, text = scan_package(item)
    dest_dir = dirs["approved"] if verdict == "safe" else dirs["rejected"]
    dest = dest_dir / item.name
    if dest.exists():
        dest = dest_dir / f"{dt.datetime.now():%Y%m%d-%H%M%S}_{item.name}"
    shutil.move(str(item), str(dest))
    header = {"safe": "APPROVED: safe to upload to claude.ai",
              "blocked": "REJECTED: do NOT upload this skill",
              "error": "NOT SCANNED: scanner failed, do not upload yet"}[verdict]
    Path(str(dest) + ".report.txt").write_text(f"{header}\nScanned: {now_iso()}\n\n{text}\n", encoding="utf-8")
    log(f"gate {verdict} {item.name}")
    notify(f"Skill Guard: {header.split(':')[0]}", item.name)
    return verdict


def watch_gate(interval: float = 5.0, once: bool = False) -> int:
    dirs = gate_dirs()
    sizes: dict[str, tuple[int, int]] = {}
    while True:
        for item in sorted(dirs["inbox"].iterdir()):
            if item.name.endswith(".report.txt") or item.name.startswith("."):
                continue
            if item.is_file() and item.suffix.lower() not in (".zip", ".skill"):
                continue
            st = item.stat()
            sig = (st.st_size, st.st_mtime_ns)
            # Wait until the file stops changing (download/copy finished).
            if not once and (sizes.get(item.name) != sig or time.time() - st.st_mtime < 3):
                sizes[item.name] = sig
                continue
            sizes.pop(item.name, None)
            try:
                process_gate_item(item, dirs)
            except OSError as e:
                log(f"gate error {item}: {e}")
        if once:
            return 0
        time.sleep(interval)


def rescan_gate_archive() -> list[str]:
    """Re-scan approved claude.ai uploads; newly flagged ones move to rejected."""
    dirs = gate_dirs()
    flagged = []
    for item in sorted(dirs["approved"].iterdir()):
        if item.name.endswith(".report.txt"):
            continue
        verdict, text = scan_package(item)
        if verdict == "blocked":
            dest = dirs["rejected"] / item.name
            shutil.move(str(item), str(dest))
            report = Path(str(item) + ".report.txt")
            if report.exists():
                report.unlink()
            Path(str(dest) + ".report.txt").write_text(
                "REJECTED ON RESCAN: this skill was approved earlier but is now flagged.\n"
                "DELETE IT FROM claude.ai (Settings > Capabilities > Skills).\n"
                f"Scanned: {now_iso()}\n\n{text}\n", encoding="utf-8")
            flagged.append(item.name)
    return flagged


# --------------------------------------------------------------------------- scheduled scans

def scan_all() -> int:
    incidents = check_changes(force=True)
    flagged = rescan_gate_archive()
    quarantined = [i for i in incidents if i["quarantined_to"]]
    errors = [i for i in incidents if not i["quarantined_to"]]
    summary = (f"{now_iso()} full scan: {len(load_state()['skills'])} skills ok, "
               f"{len(quarantined)} quarantined, {len(errors)} scan errors, "
               f"{len(flagged)} claude.ai uploads newly flagged")
    log(summary)
    print(summary)
    if incidents:
        print(incidents_text(incidents))
    for name in flagged:
        print(f"claude.ai upload newly flagged, delete it from claude.ai: {name}")
    if quarantined or flagged:
        notify("Skill Guard: threats found in daily scan",
               f"{len(quarantined)} quarantined, {len(flagged)} claude.ai skills to delete. See {LOG_FILE}")
    elif errors:
        notify("Skill Guard: scan errors", f"{len(errors)} skills could not be scanned. See {LOG_FILE}")
    return 1 if (quarantined or flagged) else 0


def daily() -> int:
    if load_config().get("auto_update_scanner", True):
        proc = subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "--upgrade",
                               "cisco-ai-skill-scanner"], capture_output=True, text=True,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        log(f"scanner upgrade exit={proc.returncode} {proc.stderr.strip()[-200:]}")
    return scan_all()


# --------------------------------------------------------------------------- settings.json

def hook_command(sub: str) -> str:
    py = Path(sys.executable).as_posix()
    script = Path(__file__).resolve().as_posix()
    return f'"{py}" "{script}" {sub}'


def is_ours(group: dict) -> bool:
    return any(HOOK_MARKER in h.get("command", "") and "guard.py" in h.get("command", "")
               for h in group.get("hooks", []))


def install_hooks(settings_path: Path, deny: bool = True) -> None:
    settings = load_json(settings_path, {}) if settings_path.exists() else {}
    if settings_path.exists():
        backup = settings_path.with_name(f"settings.backup-{dt.datetime.now():%Y%m%d-%H%M%S}.json")
        shutil.copy2(settings_path, backup)
        print(f"Backed up {settings_path} -> {backup}")
    hooks = settings.setdefault("hooks", {})
    wanted = {
        "PreToolUse": ("Write|Edit|MultiEdit", "hook-pre", 180),
        "PostToolUse": ("Bash|PowerShell|Write|Edit|MultiEdit", "hook-post", 600),
        "SessionStart": (None, "hook-session", 600),
    }
    for event, (matcher, sub, timeout) in wanted.items():
        groups = [g for g in hooks.get(event, []) if not is_ours(g)]
        group = {"hooks": [{"type": "command", "command": hook_command(sub), "timeout": timeout}]}
        if matcher:
            group = {"matcher": matcher, **group}
        groups.append(group)
        hooks[event] = groups
    if deny:
        perms = settings.setdefault("permissions", {})
        rules = perms.setdefault("deny", [])
        for r in DENY_RULES:
            if r not in rules:
                rules.append(r)
    save_json(settings_path, settings)
    print(f"Hooks installed in {settings_path}")


def uninstall_hooks(settings_path: Path) -> None:
    if not settings_path.exists():
        return
    settings = load_json(settings_path, {})
    hooks = settings.get("hooks", {})
    for event in list(hooks):
        hooks[event] = [g for g in hooks[event] if not is_ours(g)]
        if not hooks[event]:
            del hooks[event]
    if not hooks:
        settings.pop("hooks", None)
    deny = settings.get("permissions", {}).get("deny")
    if deny is not None:
        settings["permissions"]["deny"] = [r for r in deny if r not in DENY_RULES]
    save_json(settings_path, settings)
    print(f"Hooks removed from {settings_path}")


# --------------------------------------------------------------------------- misc commands

def status() -> int:
    state = load_state()
    print(f"Tracked skills: {len(state['skills'])}")
    for k, v in sorted(state["skills"].items()):
        print(f"  [{v['verdict']}] {v.get('max_severity')}  {k}  ({v['scanned_at']})")
    q = sorted(p.name for p in QUARANTINE_DIR.glob("*") if p.is_dir()) if QUARANTINE_DIR.exists() else []
    print(f"Quarantined: {len(q)}")
    for name in q:
        print(f"  {name}")
    return 0


def restore(name: str) -> int:
    src = QUARANTINE_DIR / name
    meta = load_json(src.with_name(src.name + ".origin.json"), {})
    if not src.is_dir() or not meta.get("origin"):
        print(f"Not found in quarantine: {name}")
        return 1
    origin = Path(meta["origin"])
    if origin.exists():
        print(f"Refusing to overwrite existing {origin}")
        return 1
    shutil.move(str(src), str(origin))
    state = load_state()
    # Mark as reviewed so the next hook does not quarantine it again.
    state["skills"][str(origin)] = {"fp": fingerprint(origin), "verdict": "restored-by-user",
                                    "max_severity": None, "scanned_at": now_iso()}
    save_json(STATE_FILE, state)
    log(f"restored by user {origin}")
    print(f"Restored to {origin}. It is trusted as-is; any later change to it is scanned again.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="skill-guard")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for c in ("hook-pre", "hook-post", "hook-session", "scan-all", "daily", "status"):
        sub.add_parser(c)
    w = sub.add_parser("watch-gate")
    w.add_argument("--once", action="store_true")
    for c in ("install-hooks", "uninstall-hooks"):
        p = sub.add_parser(c)
        p.add_argument("--settings", default=str(CLAUDE_DIR / "settings.json"))
        if c == "install-hooks":
            p.add_argument("--no-deny-rules", action="store_true")
    r = sub.add_parser("restore")
    r.add_argument("name")
    args = ap.parse_args(argv)

    GUARD_DIR.mkdir(parents=True, exist_ok=True)
    try:
        if args.cmd == "hook-pre":
            return hook_pre()
        if args.cmd == "hook-post":
            return hook_post()
        if args.cmd == "hook-session":
            return hook_session()
        if args.cmd == "scan-all":
            return scan_all()
        if args.cmd == "daily":
            return daily()
        if args.cmd == "watch-gate":
            return watch_gate(once=args.once)
        if args.cmd == "install-hooks":
            install_hooks(Path(args.settings), deny=not args.no_deny_rules)
            return 0
        if args.cmd == "uninstall-hooks":
            uninstall_hooks(Path(args.settings))
            return 0
        if args.cmd == "status":
            return status()
        if args.cmd == "restore":
            return restore(args.name)
    except Exception as e:  # noqa: BLE001 - a crashing hook must never break Claude Code
        log(f"{args.cmd} crashed: {e!r}")
        if args.cmd.startswith("hook-"):
            return 0
        raise
    return 0


if __name__ == "__main__":
    sys.exit(main())
