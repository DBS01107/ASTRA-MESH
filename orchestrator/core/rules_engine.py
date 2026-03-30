import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional

from .findings import StandardFinding


# ---------------------------------------------------------
# Rule Loader (SAFE)
# ---------------------------------------------------------

def load_rules_from_directory(directory: str = "orchestrator/rules") -> List[Dict[str, Any]]:
    """
    Loads all .yaml rule files from a specified directory.
    Safely handles empty or comment-only files.
    """
    rules: List[Dict[str, Any]] = []
    rule_path = Path(directory)

    if not rule_path.is_dir():
        print(f"[!] Rules directory not found: {directory}")
        return []

    for file_path in rule_path.glob("*.yaml"):
        with open(file_path, "r") as f:
            try:
                doc = yaml.safe_load(f)

                if not doc:
                    continue

                if isinstance(doc, list):
                    rules.extend(doc)
                else:
                    rules.append(doc)

            except yaml.YAMLError as e:
                print(f"[!] Error loading rule file {file_path}: {e}")

    return rules


# ---------------------------------------------------------
# Rule Evaluation Engine
# ---------------------------------------------------------

def evaluate_findings(
    findings: List[StandardFinding],
    all_rules: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Evaluates findings against all rules and returns triggered actions.
    Preserves risk_level from findings so graph can filter appropriately.
    """
    triggered_actions: List[Dict[str, Any]] = []

    for finding in findings:
        for rule in all_rules:
            rule_source_tool = rule.get("source_tool")
            if rule_source_tool and getattr(finding, "source_tool", None) != rule_source_tool:
                continue

            triggers = _extract_triggers(rule)
            if not _check_all_triggers(finding, triggers):
                continue

            action = _extract_action(rule)
            if not action:
                continue

            # -------------------------------------------------
            # Target Resolution
            # -------------------------------------------------
            target_type = action.get("target_type", "host_of_finding")

            if target_type == "url_of_finding":
                action["target"] = finding.target
            elif target_type == "cve_of_finding":
                action["target"] = finding.cve_id or finding.finding_value
            else:
                action["target"] = finding.target

            # -------------------------------------------------
            # Port-aware scans
            # -------------------------------------------------
            if getattr(finding, "port", None):
                action.setdefault("port", finding.port)

            # -------------------------------------------------
            # Preserve risk level from finding
            # -------------------------------------------------
            action["risk_level"] = getattr(finding, "risk_level", "enum")

            # -------------------------------------------------
            # Deterministic finding_id (never crash graph)
            # -------------------------------------------------
            if "finding_id" not in action:
                fid = f"{finding.source_tool}:{finding.finding_type}:{finding.finding_value}:{finding.target}"
                action["finding_id"] = fid

            if action not in triggered_actions:
                triggered_actions.append(action)

    return triggered_actions


# ---------------------------------------------------------
# Trigger Evaluation
# ---------------------------------------------------------

def _check_all_triggers(
    finding: StandardFinding,
    triggers: List[Dict[str, str]]
) -> bool:
    """
    Checks if a finding satisfies ALL trigger conditions.
    """
    if not triggers:
        return False

    for trigger in triggers:
        field = trigger.get("field")
        match_type = trigger.get("match_type")
        expected_value = trigger.get("value")

        actual_value = _get_finding_attribute(finding, field)

        if actual_value is None:
            return False

        match = False

        if match_type == "equals":
            if isinstance(actual_value, list):
                match = any(str(item).lower() == str(expected_value).lower() for item in actual_value)
            else:
                match = str(actual_value).lower() == str(expected_value).lower()

        elif match_type == "contains":
            if isinstance(actual_value, list):
                expected = str(expected_value).lower()
                match = any(expected in str(item).lower() for item in actual_value)
            else:
                match = str(expected_value).lower() in str(actual_value).lower()

        if not match:
            return False

    return True


# ---------------------------------------------------------
# Attribute Resolver (dot-notation safe)
# ---------------------------------------------------------

def _get_finding_attribute(
    finding: StandardFinding,
    field_specifier: str
) -> Optional[Any]:
    """
    Safely retrieves nested attributes using dot notation.
    Example: 'details.service'
    """
    if not field_specifier: 
        return None

    current_value: Any = finding

    for part in field_specifier.split("."):
        if isinstance(current_value, StandardFinding):
            if hasattr(current_value, part):
                current_value = getattr(current_value, part)
            else:
                return None
        elif isinstance(current_value, dict):
            current_value = current_value.get(part)
        else:
            return None

    return current_value


def _extract_triggers(rule: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Supports both rule schemas:
    - New schema: triggers/action
    - Legacy schema: when/then
    """
    triggers = rule.get("triggers")
    if isinstance(triggers, list):
        return triggers

    when_clause = rule.get("when")
    if not isinstance(when_clause, dict):
        return []

    converted: List[Dict[str, str]] = []
    for field, value in when_clause.items():
        if value is None or value == "":
            continue

        if field == "contains":
            converted.append({
                "field": "finding_value",
                "match_type": "contains",
                "value": str(value),
            })
            continue

        converted.append({
            "field": str(field),
            "match_type": "equals",
            "value": str(value),
        })

    return converted


def _extract_action(rule: Dict[str, Any]) -> Dict[str, Any]:
    action = rule.get("action")
    if isinstance(action, dict):
        return action.copy()

    legacy_then = rule.get("then")
    if isinstance(legacy_then, dict):
        return legacy_then.copy()

    return {}
