
from neo4j import GraphDatabase, basic_auth
import os
from dotenv import load_dotenv

load_dotenv()

uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
user = os.getenv("NEO4J_USER", "neo4j")
password = os.getenv("NEO4J_PASSWORD", "password")

print(f"Querying {uri}...")

query = """
MATCH (n)
OPTIONAL MATCH (n)-[r]->(m)
RETURN n.name as Name, labels(n) as Labels, type(r) as Relation, m.name as Target
"""

try:
    driver = GraphDatabase.driver(uri, auth=basic_auth(user, password))
    with driver.session() as session:
        result = session.run(query)
        print("\n--- NEO4J GRAPH DATA ---")
        count = 0
        for record in result:
            count += 1
            node_name = record["Name"]
            node_labels = record["Labels"]
            relation = record["Relation"]
            target = record["Target"]
            
            label_str = f"[{', '.join(node_labels)}]"
            if relation:
                print(f"{label_str} {node_name} --[{relation}]--> {target}")
            else:
                print(f"{label_str} {node_name}")
        
        if count == 0:
            print("No nodes found in the database. (Did the previous run fail to add them?)")
        else:
            print(f"\nTotal Records: {count}")
            
    driver.close()
except Exception as e:
    print(f"FAILURE: {e}")
