#!/usr/bin/env python3
"""
Clear all Neo4j graph data for a fresh start
"""
import os
from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()

uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
user = os.getenv("NEO4J_USER", "neo4j")
password = os.getenv("NEO4J_PASSWORD")

print(f"Connecting to {uri}...")
driver = GraphDatabase.driver(uri, auth=(user, password))

try:
    with driver.session() as session:
        # Delete all nodes and relationships
        result = session.run("MATCH (n) DETACH DELETE n")
        print("✓ All Neo4j data cleared!")
        
        # Verify
        count = session.run("MATCH (n) RETURN count(n) as count").single()["count"]
        print(f"✓ Current node count: {count}")
finally:
    driver.close()
