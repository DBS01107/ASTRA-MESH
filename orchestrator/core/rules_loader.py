"""
Load and provide rule context to AI for intelligent decision-making.
"""

import yaml
import os
from typing import Dict, List, Any

RULES_DIR = os.path.join(os.path.dirname(__file__), '..', 'rules')

def load_rules() -> Dict[str, List[Dict[str, Any]]]:
    """Load all rules from YAML files."""
    rules = {}
    
    rule_files = ['auth.yaml', 'database.yaml', 'network.yaml', 'vulnerabilities.yaml', 'web.yaml']
    
    for rule_file in rule_files:
        path = os.path.join(RULES_DIR, rule_file)
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    file_rules = yaml.safe_load(f) or []
                    category = rule_file.replace('.yaml', '')
                    rules[category] = file_rules
            except Exception as e:
                print(f"[!] Error loading {rule_file}: {e}")
    
    return rules

def get_rules_context_for_ai() -> str:
    """
    Get a formatted string of rules that AI can use for decision-making.
    """
    rules = load_rules()
    
    context = "## DECISION RULES FOR TOOL RECOMMENDATIONS ##\n\n"
    context += "These rules define when specific tools should be triggered:\n\n"
    
    for category, rule_list in rules.items():
        context += f"### {category.upper()} RULES ###\n"
        
        for rule in rule_list:
            if isinstance(rule, dict):
                rule_id = rule.get('id', 'unknown')
                description = rule.get('description', '')
                triggers = rule.get('triggers', [])
                when = rule.get('when', {})
                action = rule.get('then', rule.get('action', {}))
                
                tool = action.get('tool_to_run', action.get('action_tool', 'N/A'))
                
                context += f"- **{rule_id}**: {description}\n"
                
                # Add trigger conditions
                if triggers:
                    context += "  Triggers when:\n"
                    for trigger in triggers:
                        if isinstance(trigger, dict):
                            field = trigger.get('field', '')
                            value = trigger.get('value', '')
                            context += f"    • {field} = {value}\n"
                elif when:
                    finding_type = when.get('finding_type', '')
                    service = when.get('service', '')
                    contains = when.get('contains', '')
                    context += f"  Triggers when: finding_type={finding_type}, service={service}, contains={contains}\n"
                
                # Add recommended action/tool
                if tool and tool != 'N/A':
                    context += f"  → Trigger Tool: **{tool}**\n"
                
                context += "\n"
        
        context += "\n"
    
    return context

def match_rules_to_findings(findings: List[Any]) -> Dict[str, Any]:
    """
    Match discovered findings against rules to determine which tools should run.
    
    Returns a dict of matched rules and recommended tools.
    """
    rules = load_rules()
    matched_rules = {
        'auth': [],
        'network': [],
        'web': [],
        'database': [],
        'vulnerabilities': []
    }
    
    # For each finding, check if it matches any rules
    for finding in findings:
        capability = getattr(finding, 'capability', None)
        finding_type = getattr(finding, 'finding_type', '')
        service = getattr(finding, 'service', '')
        severity = getattr(finding, 'severity', '')
        risk_level = getattr(finding, 'risk_level', '')
        
        # Check against rules
        for category, rule_list in rules.items():
            for rule in rule_list:
                if not isinstance(rule, dict):
                    continue
                
                rule_id = rule.get('id', '')
                
                # Try to match rule triggers
                triggers = rule.get('triggers', [])
                when = rule.get('when', {})
                
                matched = False
                
                # Match against 'when' clauses
                if when:
                    finding_type_match = when.get('finding_type') == finding_type
                    service_match = when.get('service', '') == '' or when.get('service') == service
                    severity_match = when.get('severity', '') == '' or when.get('severity') == severity
                    
                    if finding_type_match and service_match and severity_match:
                        matched = True
                
                # Match against 'triggers' (new format)
                if triggers and not matched:
                    all_triggered = True
                    for trigger in triggers:
                        if isinstance(trigger, dict):
                            field = trigger.get('field', '')
                            value = trigger.get('value', '')
                            match_type = trigger.get('match_type', 'equals')
                            
                            field_value = None
                            if field == 'capability':
                                field_value = capability
                            elif field == 'finding_type':
                                field_value = finding_type
                            elif field == 'details.service':
                                field_value = service
                            
                            if match_type == 'equals' and field_value != value:
                                all_triggered = False
                                break
                            elif match_type == 'contains' and (not field_value or value not in str(field_value)):
                                all_triggered = False
                                break
                    
                    if all_triggered and triggers:
                        matched = True
                
                if matched:
                    action = rule.get('then', rule.get('action', {}))
                    matched_rules[category].append({
                        'rule_id': rule_id,
                        'description': rule.get('description', ''),
                        'finding': f"{finding_type}:{finding.finding_value}",
                        'target': getattr(finding, 'target', ''),
                        'technique': action.get('technique', ''),
                        'impact': action.get('impact', ''),
                        'tool': action.get('tool_to_run', action.get('action_tool', '')),
                        'flags': action.get('flags', action.get('tool_flags', [])),
                    })
    
    return matched_rules

def format_matched_rules_for_ai(matched_rules: Dict[str, Any]) -> str:
    """Format matched rules for inclusion in AI context."""
    context = "## MATCHED RULES FROM FINDINGS ##\n\n"
    
    found_any = False
    for category, matches in matched_rules.items():
        if matches:
            found_any = True
            context += f"### {category.upper()} ###\n"
            for match in matches:
                context += f"- **{match['rule_id']}**: {match['description']}\n"
                context += f"  Finding: {match['finding']}\n"
                if match['technique']:
                    context += f"  Technique: {match['technique']}\n"
                if match['impact']:
                    context += f"  Impact: {match['impact']}\n"
                if match['tool']:
                    context += f"  **Recommended Tool: {match['tool']}**\n"
                if match.get('flags'):
                    context += f"  Suggested Flags: {match.get('flags')}\n"
                context += "\n"
    
    if not found_any:
        context += "No specific rules matched current findings.\n"
    
    return context
