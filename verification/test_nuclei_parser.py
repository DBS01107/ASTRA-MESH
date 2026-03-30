#!/usr/bin/env python3
"""
Test nuclei parser directly
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from orchestrator.core import parsers

# Test with the actual nuclei file
nuclei_file = "orchestrator/output/raw/http___scanme.nmap.org_nuclei.jsonl"

print(f"Testing nuclei parser on: {nuclei_file}")
print(f"File exists: {os.path.exists(nuclei_file)}")
print()

try:
    findings = parsers.parse_nuclei_jsonl(nuclei_file, "http://scanme.nmap.org")
    print(f"✓ Parser returned {len(findings)} findings")
    
    if findings:
        print("\n--- Sample Finding ---")
        f = findings[0]
        print(f"  ID: {f.id}")
        print(f"  Tool: {f.source_tool}")
        print(f"  Target: {f.target}")
        print(f"  Type: {f.finding_type}")
        print(f"  Value: {f.finding_value}")
        print(f"  Risk: {f.risk_level}")
        print(f"  Capability: {f.capability}")
    else:
        print("⚠ No findings parsed!")
        
except Exception as e:
    print(f"✗ Parser failed: {e}")
    import traceback
    traceback.print_exc()
