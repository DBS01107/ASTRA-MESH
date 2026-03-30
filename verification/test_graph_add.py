#!/usr/bin/env python3
"""
Test if graph.add_finding works
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from orchestrator.core.graph import AstraGraph
from orchestrator.core.findings import StandardFinding

# Create a test finding
finding = StandardFinding(
    id="test_finding_1",
    source_tool="nuclei",
    target="http://test.com",
    finding_type="vulnerability",
    finding_value="test-vuln",
    risk_level="info",
    capability="test_capability"
)

print("Creating graph and adding finding...")
graph = AstraGraph()
graph.add_asset("test.com")

try:
    graph.add_finding(finding)
    print("✓ Finding added successfully!")
except Exception as e:
    print(f"✗ Failed to add finding: {e}")
    import traceback
    traceback.print_exc()

# Check Neo4j
print("\nChecking Neo4j...")
os.system("python check_neo4j_data.py")
