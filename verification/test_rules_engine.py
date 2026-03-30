#!/usr/bin/env python3
"""
Test that rules-based decision making works correctly.
Demonstrates how findings trigger tool recommendations based on rules.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'orchestrator'))

from core.rules_loader import load_rules, get_rules_context_for_ai, match_rules_to_findings, format_matched_rules_for_ai
from core.findings import StandardFinding

print("=" * 80)
print("ASTRA RULES-BASED DECISION ENGINE TEST")
print("=" * 80)

# Test 1: Load rules
print("\n[1] Loading Rules...")
rules = load_rules()
print(f"    Loaded {len(rules)} rule categories:")
for category in rules.keys():
    print(f"    - {category}: {len(rules[category])} rules")

# Test 2: Display rules context
print("\n[2] Rules Context for AI (first 500 chars):")
rules_context = get_rules_context_for_ai()
print(f"    {rules_context[:500]}...")

# Test 3: Create sample findings like what we'd get from scanme.nmap.org
print("\n[3] Creating Sample Findings from Scanme.nmap.org Scan...")
sample_findings = [
    StandardFinding(
        id="nmap_port_45.33.32.156_22",
        source_tool="nmap",
        target="45.33.32.156",
        finding_type="open_port",
        finding_value="22",
        port=22,
        service="ssh",
        version="OpenSSH_6.6.1p1",
        capability=None,
        risk_level="enum",
        severity="info",
    ),
    StandardFinding(
        id="nmap_ssh_version_45.33.32.156",
        source_tool="nmap",
        target="45.33.32.156",
        finding_type="service_version",
        finding_value="OpenSSH_6.6.1p1",
        port=22,
        service="ssh",
        version="OpenSSH_6.6.1p1",
        capability="remote_access",
        risk_level="enum",
        severity="info",
    ),
    StandardFinding(
        id="nuclei_ssh_auth_methods",
        source_tool="nuclei",
        target="45.33.32.156:22",
        finding_type="ssh_auth",
        finding_value="password_auth_enabled",
        port=22,
        service="ssh",
        capability="password_auth",
        risk_level="misconfig",
        severity="medium",
    ),
    StandardFinding(
        id="nuclei_terrapin",
        source_tool="nuclei",
        target="45.33.32.156:22",
        finding_type="crypto_weakness",
        finding_value="chacha20_poly1305_vulnerable",
        port=22,
        service="ssh",
        capability="weak_crypto",
        risk_level="exploit",
        severity="medium",
    ),
    StandardFinding(
        id="nmap_port_45.33.32.156_80",
        source_tool="nmap",
        target="45.33.32.156",
        finding_type="open_port",
        finding_value="80",
        port=80,
        service="http",
        version="Apache/2.4.41",
        capability=None,
        risk_level="enum",
        severity="info",
    ),
]

print(f"    Created {len(sample_findings)} findings:")
for f in sample_findings:
    print(f"    - {f.finding_type}: {f.finding_value} (capability: {f.capability}, risk: {f.risk_level})")

# Test 4: Match rules to findings
print("\n[4] Matching Rules to Findings...")
matched = match_rules_to_findings(sample_findings)
print("    Matched Rules:")
for category, matches in matched.items():
    if matches:
        print(f"    [{category.upper()}]")
        for match in matches:
            print(f"      - {match['rule_id']}")
            if match['tool']:
                print(f"        → Trigger Tool: {match['tool']}")

# Test 5: Format for AI
print("\n[5] Formatted Rules Context for AI:")
formatted = format_matched_rules_for_ai(matched)
print(formatted[:800])

# Test 6: Show what tools should be recommended
print("\n[6] EXPECTED TOOL RECOMMENDATIONS BASED ON RULES:")
print("    Based on findings:")
print("    - SSH password authentication enabled → enum4linux, nmap-ssh-scripts")
print("    - SSH weak crypto detected → nmap-ssh-scripts")
print("    - HTTP service detected → nikto, dirb, wpscan")
print("\n    The AI should now recognize these patterns and recommend accordingly!")

print("\n" + "=" * 80)
print("CONCLUSION:")
print("=" * 80)
print("""
The rules engine now provides the AI with:

1. MATCHED RULES - Specific rules triggered by current findings
2. DECISION RULES - Template rules for how to respond to patterns
3. RECOMMENDED TOOLS - Specific tools for each matched rule

This replaces generic recommendations with findings-driven tool selection.

Example: 
  OLD: "We found SSH, maybe run ssh_enum?"
  NEW: "Found SSH password auth + weak crypto (rules matched). 
        Rules recommend: nmap-ssh-scripts and enum4linux"
""")
