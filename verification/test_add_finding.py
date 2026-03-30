#!/usr/bin/env python3
"""
Test script to verify graph.add_finding() works correctly
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from orchestrator.core.graph import graph_db
from orchestrator.core.models import StandardFinding

# Create a test finding
test_finding = StandardFinding(
    id="test-finding-001",
    title="Test Vulnerability - Outdated Apache",
    description="Apache/2.4.7 is outdated",
    severity="medium",
    target="scanme.nmap.org",
    source_tool="test",
    raw_data={"version": "2.4.7"}
)

print("[*] Testing graph.add_finding()...")
print(f"[*] Adding finding: {test_finding.title}")

# Add to graph
graph_db.add_finding(test_finding)

print("[+] Finding added successfully!")
print(f"[*] Graph now has {len(graph_db.g.nodes)} nodes")

# Check if it's in Neo4j
print("\n[*] Checking Neo4j...")
from check_neo4j_data import main as check_neo4j
check_neo4j()
