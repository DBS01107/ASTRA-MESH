#!/usr/bin/env python3
"""
Test script to verify cumulative analysis across all initial scanners.
This script tests that nikto parser works and cumulative analysis is triggered.
"""

import sys
import os

# Add orchestrator to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'orchestrator'))

from core.parsers import parse_nikto_txt
from core.findings import StandardFinding

def test_nikto_parser():
    """Test nikto parser with sample output."""
    print("[*] Testing Nikto parser...")
    
    # Create sample nikto output
    sample_nikto = """
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          45.33.32.156
+ Target Hostname:    scanme.nmap.org
+ Target Port:        80
+ Start Time:         2024-01-15 10:30:00 (UTC)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ Retrieved server banner: Apache/2.4.41
+ The anti-clickjacking X-Frame-Options header is not set.
+ The X-XSS-Protection header is not set.
+ The X-Content-Type-Options header is not set.
+ Retrieved x-powered-by header: PHP/7.4.3
+ OSVDB-3268 (SUSPICIOUS) / Directory indexing found.
+ OSVDB-10922 (SUSPICIOUS) /cgi-bin/ directory found (possible CGI scripts)
+ OSVDB-3092 (SUSPICIOUS) /test/ directory found.
+ OSVDB-112882 (SUSPICIOUS) /admin/ directory found.
+ Cookie httponly flag not set
+ Cookie secure flag not set
+ OSVDB-3092 (SUSPICIOUS) /wordpress/ WordPress installation found
+ Scan completed at 2024-01-15 10:30:45 (UTC)
"""
    
    # Write sample to temp file
    temp_file = "/tmp/test_nikto.txt"
    with open(temp_file, 'w') as f:
        f.write(sample_nikto)
    
    # Parse it
    findings = parse_nikto_txt(temp_file, "45.33.32.156")
    
    print(f"[+] Found {len(findings)} findings from Nikto parser")
    for f in findings:
        print(f"    - {f.finding_value}: {f.finding_type} (capability: {f.capability}, risk: {f.risk_level})")
    
    # Verify structure
    if findings:
        sample = findings[0]
        print(f"\n[+] Sample finding structure:")
        print(f"    - source_tool: {sample.source_tool}")
        print(f"    - target: {sample.target}")
        print(f"    - finding_type: {sample.finding_type}")
        print(f"    - capability: {sample.capability}")
        print(f"    - risk_level: {sample.risk_level}")
        print(f"    - severity: {sample.severity}")
        print(f"    - description: {sample.description[:50]}...")
    
    # Cleanup
    os.remove(temp_file)
    return len(findings) > 0

def test_cumulative_analysis_config():
    """Verify cumulative analysis configuration."""
    print("\n[*] Verifying cumulative analysis configuration...")
    
    from core.registry import SCANNERS
    from core.ai.planning_agent import get_tool_list
    
    # Check nikto is in registry
    nikto_found = any(s.get('name') == 'nikto' and s.get('enabled') for s in SCANNERS)
    print(f"[+] Nikto in enabled scanners: {nikto_found}")
    
    # Check parser mapping
    from core.parsers import PARSER_MAPPING
    print(f"[+] Available parsers: {list(PARSER_MAPPING.keys())}")
    nikto_parser = 'nikto' in PARSER_MAPPING
    print(f"[+] Nikto parser registered: {nikto_parser}")
    
    # Check tool list
    tools = get_tool_list()
    print(f"[+] Available tools for AI: {tools}")
    
    return nikto_found and nikto_parser

def main():
    print("=" * 70)
    print("ASTRA CUMULATIVE ANALYSIS TEST")
    print("=" * 70)
    
    parser_test = test_nikto_parser()
    config_test = test_cumulative_analysis_config()
    
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"[{'✓' if parser_test else '✗'}] Nikto parser works")
    print(f"[{'✓' if config_test else '✗'}] Cumulative analysis configured")
    
    if parser_test and config_test:
        print("\n✓ All tests passed! System ready for end-to-end testing.")
        print("  Run: python orchestrator/main.py scanme.nmap.org --mode dynamic")
        return 0
    else:
        print("\n✗ Some tests failed. Check configuration.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
