"""
Handles dependency resolution, tool selection, and binary checking.
"""
import os
import shutil
import subprocess
from typing import List, Tuple

from . import registry # Imports SCANNERS and TOOL_BINARIES from registry.py

_APT_CACHE_UPDATED = False
TECH_REVEALING_SCANNERS = {
    "nmap",
    "whatweb",
    "nuclei",
    "vulners",
    "nmap-ssh-scripts",
    "nmap-ftp-scripts",
    "nmap-smb-scripts",
    "enum4linux",
    "wpscan",
    "joomscan",
    "sqlmap",
    "dirb",
    "ffuf",
    "nikto",
    "sslyze",
    "wapiti",
    "skipfish",
}

# Best-effort installers for environments where tools are missing at runtime.
# Commands are executed without shell expansion for safety.
TOOL_INSTALL_COMMANDS = {
    "nmap": [["apt-get", "install", "-y", "nmap"]],
    "vulners": [["apt-get", "install", "-y", "nmap"]],
    "nmap-ssh-scripts": [["apt-get", "install", "-y", "nmap"]],
    "nmap-ftp-scripts": [["apt-get", "install", "-y", "nmap"]],
    "nmap-smb-scripts": [["apt-get", "install", "-y", "nmap"]],
    "whatweb": [["apt-get", "install", "-y", "whatweb"]],
    "nuclei": [["apt-get", "install", "-y", "nuclei"]],
    "searchsploit": [["apt-get", "install", "-y", "exploitdb"]],
    # Nikto is provisioned at Docker image build time (Dockerfile.backend).
    # Runtime auto-install is intentionally disabled for this tool.
    "dirb": [["apt-get", "install", "-y", "dirb"]],
    "ffuf": [["apt-get", "install", "-y", "ffuf"]],
    "wpscan": [["gem", "install", "wpscan"]],
    "joomscan": [["apt-get", "install", "-y", "joomscan"]],
    "sslyze": [["pip3", "install", "sslyze"]],
    "sqlmap": [["apt-get", "install", "-y", "sqlmap"]],
    "enum4linux": [["apt-get", "install", "-y", "enum4linux"]],
    "wapiti": [["apt-get", "install", "-y", "wapiti"]],
    "skipfish": [["apt-get", "install", "-y", "skipfish"]],
}


def _with_privilege_if_needed(cmd: List[str]) -> List[str]:
    if not cmd:
        return cmd
    requires_root = cmd[0] in {"apt", "apt-get", "pip", "pip3", "gem"}
    if not requires_root:
        return cmd
    if hasattr(os, "geteuid") and os.geteuid() != 0 and shutil.which("sudo"):
        return ["sudo", *cmd]
    return cmd


def _run_install_command(cmd: List[str]) -> Tuple[bool, str]:
    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=900,
            check=False,
        )
    except FileNotFoundError:
        return False, f"Installer command not found: {' '.join(cmd)}"
    except Exception as exc:
        return False, f"Installer command failed unexpectedly: {exc}"

    output = (completed.stdout or "").strip()
    if completed.returncode != 0:
        tail = output[-600:] if output else "No command output."
        return False, f"Exit code {completed.returncode}: {tail}"
    return True, output[-400:] if output else "Completed successfully."


def _ensure_apt_cache_updated() -> Tuple[bool, List[str]]:
    global _APT_CACHE_UPDATED
    if _APT_CACHE_UPDATED:
        return True, []

    cmd = _with_privilege_if_needed(["apt-get", "update"])
    ok, details = _run_install_command(cmd)
    if ok:
        _APT_CACHE_UPDATED = True
        return True, ["[INSTALL] apt package index updated.\n"]
    return False, [f"[INSTALL] Failed to run apt-get update: {details}\n"]


def ensure_tool_available(tool_name: str, auto_install: bool = False) -> Tuple[bool, List[str]]:
    """
    Ensure a tool's binary exists in PATH.
    If missing and auto_install=True, attempts best-effort installation.
    """
    logs: List[str] = []
    binary = registry.TOOL_BINARIES.get(tool_name, tool_name)

    if shutil.which(binary):
        return True, logs

    logs.append(f"[INSTALL] Missing tool binary for '{tool_name}' (expected: '{binary}').\n")
    if not auto_install:
        return False, logs

    install_steps = TOOL_INSTALL_COMMANDS.get(tool_name) or TOOL_INSTALL_COMMANDS.get(binary)
    if not install_steps:
        logs.append(
            f"[INSTALL] No installer recipe is configured for '{tool_name}'. "
            "Please install it manually.\n"
        )
        return False, logs

    for raw_cmd in install_steps:
        if not raw_cmd:
            continue

        # Refresh apt metadata once before apt installs.
        if raw_cmd[0] in {"apt", "apt-get"} and "install" in raw_cmd:
            cache_ok, cache_logs = _ensure_apt_cache_updated()
            logs.extend(cache_logs)
            if not cache_ok:
                return False, logs

        cmd = _with_privilege_if_needed(raw_cmd)
        logs.append(f"[INSTALL] Running: {' '.join(cmd)}\n")
        ok, details = _run_install_command(cmd)
        if not ok:
            logs.append(f"[INSTALL] Command failed for '{tool_name}': {details}\n")
            return False, logs
        logs.append(f"[INSTALL] Step completed for '{tool_name}'.\n")

    if shutil.which(binary):
        logs.append(f"[INSTALL] '{tool_name}' is now available and will be executed.\n")
        return True, logs

    logs.append(
        f"[INSTALL] Installation finished but binary '{binary}' is still missing from PATH.\n"
    )
    return False, logs

def get_scanner_by_name(name: str):
    """Finds a scanner's configuration dictionary by its name."""
    for sc in registry.SCANNERS:
        if sc['name'] == name:
            return sc
    return None

def resolve_enabled_scanners(enable_arg: str) -> List[str]:
    """Resolves the --enable argument into a list of scanner names."""
    if not enable_arg or not enable_arg.strip():
        # Default to all scanners.
        return [sc['name'] for sc in registry.SCANNERS]
    
    arg = enable_arg.lower().strip()
    if arg == 'all':
        return [sc['name'] for sc in registry.SCANNERS]
        
    requested = {n.strip() for n in enable_arg.split(',') if n.strip()}
    
    # Ensure nmap is implicitly enabled if any other tool depends on it
    needs_nmap = any(
        'nmap' in (((get_scanner_by_name(name) or {}).get('depends_on')) or []) for name in requested
    )
    if needs_nmap:
        requested.add('nmap')

    # Auto-enable SearchSploit whenever a technology-revealing scanner is selected.
    if requested.intersection(TECH_REVEALING_SCANNERS):
        requested.add("searchsploit")
        
    return [sc['name'] for sc in registry.SCANNERS if sc['name'] in requested]

def build_execution_groups(enabled_names: List[str]) -> List[List[str]]:
    """Builds a list of execution groups based on tool dependencies."""
    remaining = set(enabled_names)
    groups = []
    
    while remaining:
        ready = []
        for name in list(remaining):
            scanner = get_scanner_by_name(name)
            if not scanner: continue
            
            deps = scanner.get('depends_on', [])
            # Check if all dependencies are satisfied (i.e., not in the remaining set)
            if all(dep not in remaining for dep in deps):
                ready.append(name)
        
        if not ready:
            # Circular dependency detected
            raise RuntimeError(f"Could not resolve dependencies. Possible circular dependency in: {remaining}")
            
        groups.append(sorted(ready))
        remaining.difference_update(ready)
        
    return groups

def check_tool_binaries(enabled_names: List[str]) -> list:
    """Checks if the binaries for enabled tools exist on the system PATH."""
    missing = []
    for name in enabled_names:
        binary = registry.TOOL_BINARIES.get(name, name)
        if not shutil.which(binary):
            missing.append((name, binary))
    return missing
