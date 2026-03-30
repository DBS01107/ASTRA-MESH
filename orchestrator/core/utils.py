"""
Utility functions for the orchestration engine.
Includes helpers for target validation, command construction, and file path generation.
"""
import re
import shlex
from typing import Any, Dict, List, Optional

def log_error(message: str):
    """Log error messages."""
    print(f"[ERROR] {message}")

def sanitize_target(target: str) -> str:
    """
    Sanitizes a string to be safe for use in filenames and command-line arguments.
    Replaces anything that isn't a letter, number, dot, underscore, or hyphen with an underscore.
    """
    return re.sub(r"[^a-zA-Z0-9\._-]", "_", target)


def normalize_dynamic_flags(flags: Any) -> List[str]:
    """
    Normalizes dynamic tool flags into a safe argument token list.
    Accepts a string (shell-like), a list/tuple, or a scalar value.
    """
    if flags is None:
        return []

    tokens: List[str] = []
    if isinstance(flags, str):
        tokens.extend(shlex.split(flags))
    elif isinstance(flags, (list, tuple)):
        for item in flags:
            if item is None:
                continue
            if isinstance(item, str):
                tokens.extend(shlex.split(item))
            else:
                tokens.append(str(item))
    else:
        tokens.append(str(flags))

    cleaned: List[str] = []
    for token in tokens:
        normalized = token.strip()
        if not normalized:
            continue
        if any(ch in normalized for ch in ("\n", "\r", "\x00")):
            continue
        cleaned.append(normalized)
    return cleaned

def is_valid_target(target: str) -> bool:
    """
    Validates if the target is a well-formed IP, domain, or URL.
    """
    ip_regex = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    domain_regex = re.compile(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
    url_regex = re.compile(r"^(https?://)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(/.*)?$")
    return bool(ip_regex.match(target) or domain_regex.match(target) or url_regex.match(target))

def ensure_http_scheme(target: str) -> str:
    """
    Ensures a target string has an HTTP scheme for URL-based tools.
    """
    if not target.startswith(('http://', 'https://')):
        # A simple check for port 443 to guess https
        if ':443' in target:
            return f"https://{target}"
        return f"http://{target}"
    return target

def get_output_filepath(scanner_config: Dict, display_target: str, primary_target: str) -> str:
    """
    Generates a consistent output filepath based on the tool's command template.
    This allows the engine to know exactly where to find a tool's output for parsing.
    """
    template = scanner_config.get("cmd_template", "")
    
    # Regex to find an output path like '-o orchestrator/output/raw/...' or '--log=orchestrator/output/raw/...'
    # This is a robust way to extract the intended filename from the command template.
    match = re.search(r'[\s=](orchestrator/output/raw/[^\s]+)', template)
    
    if not match:
        # If no output file is specified in the template (e.g., for enum4linux),
        # create a sensible default log file.
        sanitized_display_target = sanitize_target(display_target)
        return f"orchestrator/output/raw/{sanitized_display_target}_{scanner_config['name']}.log"

    file_template = match.group(1)
    
    # The "file_target" is a sanitized version of the specific URL or host being scanned
    file_token = sanitize_target(display_target)
    
    # Replace placeholders to create the final, concrete file path
    filepath = file_template.replace("{file_target}", file_token).replace("{target}", sanitize_target(primary_target))
    return filepath


def command_builder(
    scanner: Dict,
    display_target: str,
    primary_target: str,
    output_file: str,
    dynamic_flags: Optional[Any] = None,
) -> List[str]:
    """
    Builds a secure, tokenized command list for subprocess from a scanner template.
    It replaces all placeholders and returns a list of arguments to prevent shell injection.
    """
    template = scanner.get("cmd_template")
    if not template:
        return []

    # 1. Replace all placeholders with their actual values
    cmd_str = template.replace("{scan_target}", display_target)\
                      .replace("{target}", primary_target)

    # 2. Find the generic output path in the template (e.g., 'orchestrator/output/raw/{file_target}_wpscan.json')
    #    and replace it with the specific, calculated output file path.
    template_output_match = re.search(r'[\s=](orchestrator/output/raw/[^\s]+)', template)
    if template_output_match:
        cmd_str = cmd_str.replace(template_output_match.group(1), output_file)

    # 3. Use shlex.split to safely parse the command string into a list.
    # This is the most secure way to prepare a command for subprocess.
    args = shlex.split(cmd_str)

    # 4. Inject dynamic flags (if present) right after the binary.
    # This keeps options in a generally valid position for most tools.
    extra_flags = normalize_dynamic_flags(dynamic_flags)
    if extra_flags and args:
        args = [args[0], *extra_flags, *args[1:]]

    return args

