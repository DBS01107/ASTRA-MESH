#!/usr/bin/env python3
"""Test AI command generation with new format."""
import sys
sys.path.insert(0, '.')

from orchestrator.core.findings import StandardFinding
from ai.planning_agent import analyze_dynamic_scan

findings = [
    StandardFinding(
        id="1",
        source_tool="nmap",
        finding_type='port',
        finding_value='SSH on 22',
        target='scanme.nmap.org',
        capability='ssh_service',
        risk_level='enum',
    ),
    StandardFinding(
        id="2",
        source_tool="nuclei",
        finding_type='vulnerability',
        finding_value='Apache mod_negotiation',
        target='http://scanme.nmap.org',
        capability='web_exposed',
        risk_level='exploit',
    )
]

print("Testing AI command generation...")
result = analyze_dynamic_scan(findings, ['nmap', 'whatweb'])
print(f"\nResult type: {type(result)}")
if isinstance(result, list) and len(result) > 0:
    print(f"??? Got {len(result)} recommendations:")
    for r in result:
        print(f"  - Tool: {r.get('tool')}")
        print(f"    Cmd:  {r.get('command')}")
