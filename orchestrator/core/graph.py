import networkx as nx
import os
import logging
from dotenv import load_dotenv
from neo4j import GraphDatabase, basic_auth

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)

class AstraGraph:
    _shared_instance = None

    def __new__(cls, isolated: bool = False):
        if isolated:
            return super().__new__(cls)
        if cls._shared_instance is None:
            cls._shared_instance = super().__new__(cls)
        return cls._shared_instance

    def __init__(self, isolated: bool = False):
        if getattr(self, "_initialized", False):
            return

        self.g = nx.DiGraph()
        self.driver = None
        self._connect_neo4j()
        self._initialized = True

    def _connect_neo4j(self):
        uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
        user = os.environ.get("NEO4J_USER", "neo4j")
        password = os.environ.get("NEO4J_PASSWORD", "")
        
        if uri and user and password:
            try:
                self.driver = GraphDatabase.driver(uri, auth=basic_auth(user, password))
                # Verify connection
                self.driver.verify_connectivity()
                logger.info("Connected to Neo4j database.")
            except Exception as e:
                logger.warning(f"Failed to connect to Neo4j: {e}. Graph will be local only.")
                self.driver = None

    def close(self):
        if self.driver:
            self.driver.close()

    def _run_query(self, query, parameters=None):
        if not self.driver:
            return
        try:
            with self.driver.session() as session:
                session.run(query, parameters or {})
        except Exception as e:
            logger.error(f"Neo4j query failed: {e}")

    def add_asset(self, asset):
        self.g.add_node(asset, type="asset")
        
        # Neo4j
        query = """
        MERGE (a:Asset {name: $name})
        """
        self._run_query(query, {"name": asset})

    def add_finding(self, finding):
        """
        finding is a StandardFinding object
        """
        finding_id = finding.id
        asset = finding.target

        # Create a descriptive label from finding data
        title = f"{finding.finding_type}: {finding.finding_value}" if finding.finding_value else finding.finding_type

        # Local
        self.add_asset(asset)
        if not self.g.has_node(finding_id):
            self.g.add_node(
                finding_id,
                type="finding",
                label=f"Finding: {title}",
                severity=finding.severity,
                tool=finding.source_tool
            )
        self.g.add_edge(asset, finding_id, relation="exposes")

        # Neo4j
        query = """
        MERGE (a:Asset {name: $asset})
        MERGE (f:Finding {id: $id})
        SET f.name = $title,
            f.title = $title, 
            f.finding_type = $finding_type,
            f.finding_value = $finding_value,
            f.severity = $severity, 
            f.tool = $tool,
            f.risk_level = $risk_level,
            f.capability = $capability,
            f.cve_id = $cve_id,
            f.cvss_score = $cvss_score
        MERGE (a)-[:EXPOSES]->(f)
        """
        params = {
            "asset": asset,
            "id": finding_id,
            "title": title,
            "finding_type": finding.finding_type,
            "finding_value": finding.finding_value,
            "severity": finding.severity,
            "tool": finding.source_tool,
            "risk_level": finding.risk_level,
            "capability": finding.capability,
            "cve_id": getattr(finding, "cve_id", None),
            "cvss_score": getattr(finding, "cvss_score", None)
        }
        self._run_query(query, params)

    def add_attack_node(self, node_type, value, parent_id, relation="leads_to"):
        """
        Adds a generic node to the attack graph (Technique, Impact, etc.)
        """
        node_id = f"{node_type}:{value}"
        
        # Local
        self.g.add_node(node_id, type=node_type, label=value)
        if parent_id and self.g.has_node(parent_id):
            self.g.add_edge(parent_id, node_id, relation=relation)

        # Neo4j
        # We assume parent exists, but we MATCH it. If not found, we create a placeholder?
        # Better to MERGE parent if possible, but generic generic is hard.
        # We'll just MATCH parent by ID (Finding ID or other Node ID)
        
        # Determine labels dynamically is tricky in Cypher params, so we use string fmt for Label safely
        # Note: In a real app, sanitize inputs. Here we assume internal robust usage.
        
        neo4j_label = node_type.capitalize()
        
        query = f"""
        MERGE (n:{neo4j_label} {{name: $value}})
        WITH n
        MATCH (p) WHERE p.id = $parent_id OR p.name = $parent_id
        MERGE (p)-[:{relation.upper()}]->(n)
        """
        self._run_query(query, {"value": value, "parent_id": parent_id})

    def get_attack_paths(self):
        """
        Get attack paths from assets to impacts/exploits.
        Local Graph implementation.
        """
        paths = []
        for node in self.g.nodes:
            if self.g.nodes[node].get("type") != "asset":
                continue
            for target in self.g.nodes:
                if self.g.nodes[target].get("type") in ["impact", "exploit"]:
                    try:
                        for path in nx.all_simple_paths(self.g, node, target):
                            paths.append(path)
                    except nx.NetworkXNoPath:
                        continue
        return paths

# Singleton instance
graph_db = AstraGraph()
