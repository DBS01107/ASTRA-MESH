
from neo4j import GraphDatabase, basic_auth
import os
from dotenv import load_dotenv

load_dotenv()

uri = os.getenv("NEO4J_URI")
user = os.getenv("NEO4J_USER")
password = os.getenv("NEO4J_PASSWORD")

print(f"Connecting to {uri} as {user} with password ending in '...{password[-3:] if len(password)>3 else password}'")

try:
    driver = GraphDatabase.driver(uri, auth=basic_auth(user, password))
    driver.verify_connectivity()
    print("SUCCESS: Connected to Neo4j!")
    driver.close()
except Exception as e:
    print(f"FAILURE: {e}")
