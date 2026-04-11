
import logging
import asyncio
import os
import re
import shlex
import time
from typing import List, Dict, Any, Optional, Tuple

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Ensure API key is set for the library to detect, or pass it explicitly if supported
if not os.environ.get("GOOGLE_API_KEY"):
    print("[!] Warning: GOOGLE_API_KEY not found in environment. Agent may fail.")

# Configure ADK to use API keys directly (not Vertex AI)
os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "False"

try:
    from google.adk.agents import Agent
    from google.adk.sessions import InMemorySessionService
    from google.adk.runners import Runner
    import google.genai.types as types
except ImportError:
    # Fallback for development/testing if package missing
    print("[!] Warning: google-adk not found. Using mock classes.")
    
    class Agent:
        def __init__(self, name, model, description, instruction, tools): pass

    class InMemorySessionService:
        async def create_session(self, app_name, user_id, session_id): return "mock_session"

    class Runner:
        def __init__(self, agent, app_name, session_service): self.agent = agent
        async def run_async(self, user_id, session_id, new_message):
             yield MockEvent("Mock analysis complete.")

    class MockEvent:
        def __init__(self, text): self.text = text
        def is_final_response(self): return True
        @property
        def content(self): return type('obj', (object,), {'parts': [type('obj', (object,), {'text': self.text})]})()
    
    class types:
        class Content:
             def __init__(self, role, parts): pass
        class Part:
             def __init__(self, text): pass

from google_adk.tools import ScanTools
from orchestrator.core.registry import SCANNERS
from orchestrator.core.rules_loader import get_rules_context_for_ai, match_rules_to_findings, format_matched_rules_for_ai
from google_adk.exploitdb import search_exploitdb, format_exploits_for_ai
from orchestrator.core import state

logger = logging.getLogger(__name__)

UNKNOWN_VERSION_TOKENS = {"", "unknown", "n/a", "na", "none", "null", "-"}

SERVICE_FOLLOWUP_TOOL_MAP = {
    "ssh": ["nmap-ssh-scripts"],
    "ftp": ["nmap-ftp-scripts"],
    "smb": ["nmap-smb-scripts", "enum4linux"],
    "http": ["nikto", "dirb", "ffuf"],
    "https": ["sslyze", "nikto", "dirb", "ffuf"],
    "mysql": ["sqlmap"],
    "mssql": ["sqlmap"],
    "postgresql": ["sqlmap"],
}

KEYWORD_FOLLOWUP_TOOL_MAP = {
    "wordpress": ["wpscan"],
    "joomla": ["joomscan"],
    "apache": ["nikto"],
    "nginx": ["nikto"],
    "php": ["nuclei"],
}

# Wrap tools for the agent
# Note: Tools must be standalone functions for ADK to introspect them correctly
def get_cve_details(cve_id: str) -> str:
    """
    Fetches detailed information for a CVE from NVD, including severity and potential exploits.
    Args:
        cve_id: The CVE ID to search for (e.g., CVE-2023-1234).
    """
    return ScanTools.get_cve_details(cve_id)

def recommend_tool(service: str, port: int) -> str:
    """
    Suggests a specific tool command to run for a given service and port.
    Args:
        service: The service name (e.g., 'ssh', 'http').
        port: The port number.
    """
    return ScanTools.recommend_tool_command(service, port)

def suggest_scan(target: str, scan_type: str, reason: str) -> str:
    """
    Suggests a follow-up scan for a target.
    Args:
        target: The target IP or URL.
        scan_type: The type of scan (e.g., 'Nikto', 'Nmap Vulners').
        reason: Why this scan is needed.
    """
    return ScanTools.suggest_scan(target, scan_type, reason)

def add_attack_node(type: str, value: str, parent_id: str) -> str:
    """
    Adds a node to the attack graph.
    Args:
        type: Node type ('technique', 'impact', 'vulnerability').
        value: Name/Description of the node (e.g., 'Remote Code Execution').
        parent_id: ID of the parent node or Finding ID this connects to.
    """
    return ScanTools.add_attack_node(type, value, parent_id)

class ScanAgent:
    """
    Wrapper around Google ADK Agent to provide synchronous interface for the Orchestrator.
    """
    def __init__(self, model_name: str = "gemini-2.5-flash"):
        self.model_name = model_name
        self.app_name = "astra_security_scan"
        self.default_user_id = "astra_user"
        self.default_session_id = "default"
        
        # Initialize ADK components
        self.adk_agent = Agent(
            name="security_consultant",
            model=model_name,
            description="Expert security consultant and penetration tester.",
            instruction=(
                "You are an expert penetration tester assisting with a security scan. "
                "Analyze the provided findings. Identify critical vulnerabilities (CVEs). "
                "Analyze the provided findings. Identify critical vulnerabilities (CVEs). "
                "Use the 'get_cve_details' tool to verify CVE severity and check for exploit references. "
                "Use 'add_attack_node' to build an attack graph linking findings to techniques and impacts. "
                "Use 'suggest_scan' to request further info if needed. "
                "Provide a concise, actionable summary of the most dangerous findings and what to do next."
            ),
            tools=[get_cve_details, recommend_tool, suggest_scan, add_attack_node]
        )
        
        self.session_service = InMemorySessionService()
        self.runner = Runner(
            agent=self.adk_agent,
            app_name=self.app_name,
            session_service=self.session_service
        )
        self.latest_reasoning = "Waiting for scan data..."
        self.latest_reasoning_by_session: Dict[str, str] = {
            self.default_session_id: self.latest_reasoning
        }
        self.recommendation_cooldown_seconds = max(
            0,
            int(os.environ.get("ASTRA_AI_RECOMMEND_COOLDOWN_SEC", "45")),
        )
        self.recommendation_backoff_seconds = max(
            5,
            int(os.environ.get("ASTRA_AI_RECOMMEND_BACKOFF_SEC", "120")),
        )
        self.recommendation_max_calls_per_session = max(
            1,
            int(os.environ.get("ASTRA_AI_RECOMMEND_MAX_CALLS", "6")),
        )
        self._last_ai_recommendation_call_ts: Dict[str, float] = {}
        self._ai_recommendation_call_count: Dict[str, int] = {}
        self._ai_recommendation_backoff_until_ts: Dict[str, float] = {}

    def _resolve_session_id(self, session_id: Optional[str]) -> str:
        if session_id is None:
            return self.default_session_id
        normalized = str(session_id).strip()
        return normalized or self.default_session_id

    def _resolve_user_id(self, session_id: str) -> str:
        return f"{self.default_user_id}:{session_id}"

    async def _run_analysis_async(self, prompt: str, session_id: Optional[str] = None) -> str:
        resolved_session_id = self._resolve_session_id(session_id)
        resolved_user_id = self._resolve_user_id(resolved_session_id)
        session_token = state.set_current_session(resolved_session_id)

        async def _gemini(p: str) -> str:
            try:
                await self.session_service.create_session(
                    app_name=self.app_name,
                    user_id=resolved_user_id,
                    session_id=resolved_session_id,
                )
            except Exception as e:
                logger.debug(f"Session creation skipped (may already exist): {e}")

            content = types.Content(role='user', parts=[types.Part(text=p)])
            final_response_text = "No response generated."
            async for event in self.runner.run_async(
                user_id=resolved_user_id,
                session_id=resolved_session_id,
                new_message=content,
            ):
                if hasattr(event, 'is_final_response') and event.is_final_response():
                    if event.content and event.content.parts:
                        final_response_text = event.content.parts[0].text
                    break
            return final_response_text

        try:
            return await _gemini(prompt)
        finally:
            state.reset_current_session(session_token)

    def analyze_findings(self, findings: List[Dict[str, Any]], session_id: Optional[str] = None) -> str:
        """
        Main entry point for the agent to analyze a list of findings.
        Synchronous wrapper.
        """
        # specialized prompt construction
        finding_summaries = []
        for f in findings:
            cve = "N/A"
            val = "N/A"
            typ = "unknown"

            if hasattr(f, "cve_id"):
                cve = getattr(f, "cve_id", "N/A") or "N/A"
                val = getattr(f, "finding_value", "N/A")
                typ = getattr(f, "finding_type", "unknown")
            elif isinstance(f, dict):
                cve = f.get("cve_id", "N/A")
                val = f.get("finding_value", "N/A")
                typ = f.get("finding_type", "unknown")
            
            finding_summaries.append(f"- Type: {typ}, Value: {val}, CVE: {cve}")

        prompt = (
            "Here are the latest scan findings:\n"
            + "\n".join(finding_summaries) + "\n\n"
            "Analyze these findings. Prioritize any CVEs with high scores or known exploits. "
            "Suggest the next best actions."
        )
        
        try:
            return asyncio.run(self._run_analysis_async(prompt, session_id=session_id))
        except Exception as e:
            logger.error(f"Agent execution failed: {e}")
            return f"Agent error: {e}"

    def recommend_next_scans(
        self,
        findings: List[Dict[str, Any]],
        executed_tools: List[str],
        session_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Recommends next scan tools based on findings, rules, and exploitdb data.
        Returns list of recommendations: [{"tool": "tool_name", "target": "target", "reason": "why"}]
        """
        resolved_session_id = self._resolve_session_id(session_id)
        matched_rules: Dict[str, Any] = {}

        # 1. Enrich findings summary + collect service/version inventory.
        finding_summaries = []
        service_inventory = []
        
        for f in findings:
            data = self._normalize_finding(f)
            typ = data["finding_type"]
            val = data["finding_value"][:120]
            risk = data["risk_level"]
            service = data["service"]
            version = data["version"]
            target = data["target"]

            finding_summaries.append(f"- {typ}: {val} (risk: {risk})")
            
            # Track discovered services from any finding that exposes normalized service evidence.
            if service and service != "unknown":
                service_inventory.append({
                    "service": service,
                    "version": version,
                    "target": target,
                })
        technology_inventory = self._build_technology_inventory(findings)

        # 2. Get Rules Context
        try:
            rules_context = get_rules_context_for_ai()
            matched_rules = match_rules_to_findings(findings)
            matched_rules_text = format_matched_rules_for_ai(matched_rules)
            if matched_rules_text:
                rules_context += "\nMATCHED RULES:\n" + matched_rules_text
        except Exception as e:
            logger.warning(f"Could not load rules context: {e}")
            rules_context = "No specific rules matched."

        # 3. Run SearchSploit for:
        #    - concrete network services (version-gated for precision),
        #    - fingerprinted web technologies (best effort, even without version).
        all_service_versions_known = self._all_service_versions_known(service_inventory)
        searchsploit_recommendations: List[Dict[str, Any]] = []
        searchsploit_reasoning = ""
        service_exploit_context = "SearchSploit deferred: waiting for complete service version discovery."
        technology_exploit_context = "No fingerprinted technologies available for SearchSploit lookup."
        service_exploits: List[Dict[str, Any]] = []
        technology_exploits: List[Dict[str, Any]] = []

        try:
            if all_service_versions_known:
                service_exploits = self._searchsploit_inventory(service_inventory)
                if service_exploits:
                    service_exploit_context = format_exploits_for_ai(service_exploits)
                else:
                    service_exploit_context = (
                        "SearchSploit executed for all discovered service versions but returned no direct exploit matches."
                    )
            else:
                missing = sorted(
                    {entry["service"] for entry in service_inventory if not self._is_known_version(entry["version"])}
                )
                if missing:
                    service_exploit_context = (
                        "SearchSploit deferred: missing service versions for "
                        + ", ".join(missing[:10])
                        + "."
                    )
        except Exception as e:
            logger.warning(f"ExploitDB search error: {e}")
            service_exploit_context = "Service-based SearchSploit lookup failed unexpectedly."

        try:
            if technology_inventory:
                technology_exploits = self._searchsploit_technology_inventory(technology_inventory)
                if technology_exploits:
                    technology_exploit_context = format_exploits_for_ai(technology_exploits)
                else:
                    technology_exploit_context = (
                        "SearchSploit executed for fingerprinted technologies but returned no direct exploit matches."
                    )
        except Exception as e:
            logger.warning(f"Technology SearchSploit lookup error: {e}")
            technology_exploit_context = "Technology-based SearchSploit lookup failed unexpectedly."

        combined_exploits = self._dedupe_exploit_matches([*service_exploits, *technology_exploits])
        state.update_searchsploit_matches(combined_exploits, session_id=resolved_session_id)

        if combined_exploits:
            searchsploit_recommendations = self._derive_searchsploit_recommendations(
                combined_exploits,
                executed_tools,
            )
            searchsploit_reasoning = (
                "SearchSploit analyzed both discovered service versions and fingerprinted technologies to "
                "surface exploit references for follow-up validation."
            )

        exploitdb_context = (
            "SERVICE/PORT INVENTORY SEARCH:\n"
            + service_exploit_context[:1500]
            + "\n\nTECHNOLOGY INVENTORY SEARCH:\n"
            + technology_exploit_context[:1500]
        )

        # 4. Construct Comprehensive Prompt
        available_tools = [scanner.get("name") for scanner in SCANNERS if scanner.get("name")]
        rules_based_recommendations = self._derive_rule_recommendations(
            matched_rules,
            executed_tools,
            available_tools,
        )
        heuristic_recommendations = self._derive_service_heuristic_recommendations(
            findings,
            executed_tools,
            available_tools,
        )

        rules_reasoning = ""
        if rules_based_recommendations:
            rules_reasoning = "Rules engine provided deterministic follow-up actions."

        heuristic_reasoning = ""
        if heuristic_recommendations:
            heuristic_reasoning = (
                "Service heuristics identified additional follow-up tools despite limited AI output."
            )
        
        rules_context_trimmed = rules_context[:800]
        prompt = (
            "You are the Planning Agent for a cybersecurity scanner.\n"
            "Findings:\n" + "\n".join(finding_summaries[:20]) + "\n\n"
            f"ExploitDB:\n{exploitdb_context}\n\n"
            f"Rules:\n{rules_context_trimmed}\n\n"
            f"Executed: {', '.join(executed_tools)}\n"
            f"Available: {', '.join(available_tools)}\n\n"
            "Recommend 2-3 tools not yet executed. "
            "Reply ONLY with JSON: "
            "{\"reasoning\":\"...\",\"recommendations\":[{\"tool\":\"name\",\"target\":\"optional\",\"flags\":[],\"reason\":\"why\"}]}"
        )

        ai_reasoning = ""
        ai_recommendations: List[Dict[str, Any]] = []

        can_call_ai, skip_reason = self._can_call_ai_recommendations(resolved_session_id)
        if not can_call_ai:
            ai_reasoning = skip_reason
        else:
            self._mark_ai_recommendation_call(resolved_session_id)
            try:
                logger.info("Requesting AI recommendations from Google ADK...")
                response = asyncio.run(
                    self._run_analysis_async(prompt, session_id=resolved_session_id)
                )

                if self._is_rate_limited_error(response):
                    self._apply_ai_recommendation_backoff(resolved_session_id)
                    ai_reasoning = (
                        "AI recommendation step hit provider rate limits (429), so deterministic guidance is in use."
                    )
                    response = ""
                
                # Try to parse JSON from response
                import json
                import re
                
                # Extract JSON object from response
                json_match = re.search(r'\{.*\}', response, re.DOTALL)
                if json_match:
                    try:
                        data = json.loads(json_match.group())
                    except json.JSONDecodeError as json_error:
                        logger.warning(f"Failed to decode AI recommendations JSON: {json_error}")
                        if not ai_reasoning:
                            ai_reasoning = (
                                "AI recommendation output was malformed, so deterministic guidance is in use."
                            )
                    else:
                        raw_reasoning = str(data.get("reasoning", "") or "").strip()
                        if raw_reasoning:
                            ai_reasoning = raw_reasoning
                        elif not ai_reasoning:
                            ai_reasoning = (
                                "AI recommendation reasoning was not returned, so deterministic guidance is in use."
                            )

                        raw_recommendations = data.get("recommendations", [])
                        if isinstance(raw_recommendations, list):
                            ai_recommendations = raw_recommendations
                        else:
                            logger.warning(
                                "AI recommendations payload did not include a list for 'recommendations'."
                            )
                elif response.strip():
                    logger.warning(f"Could not parse recommendations from: {response}")
                    if not ai_reasoning:
                        ai_reasoning = (
                            "AI recommendation output was unstructured, so deterministic guidance is in use."
                        )
                elif not ai_reasoning:
                    ai_reasoning = (
                        "AI recommendation response was empty, so deterministic guidance is in use."
                    )
            except Exception as e:
                logger.error(f"Failed to get recommendations: {e}")
                if self._is_rate_limited_error(e):
                    self._apply_ai_recommendation_backoff(resolved_session_id)
                    ai_reasoning = (
                        "AI recommendation step hit provider rate limits (429), so deterministic guidance is in use."
                    )
                else:
                    ai_reasoning = "AI recommendation step failed; using deterministic guidance."

        deterministic_recommendations = self._merge_recommendations(
            rules_based_recommendations,
            searchsploit_recommendations,
            executed_tools,
            available_tools,
        )
        deterministic_recommendations = self._merge_recommendations(
            deterministic_recommendations,
            heuristic_recommendations,
            executed_tools,
            available_tools,
        )
        merged_recommendations = self._merge_recommendations(
            deterministic_recommendations,
            ai_recommendations,
            executed_tools,
            available_tools,
        )

        reasoning_parts = [
            part
            for part in [rules_reasoning, searchsploit_reasoning, heuristic_reasoning, ai_reasoning]
            if part
        ]
        self.latest_reasoning = (
            " ".join(reasoning_parts)
            if reasoning_parts
            else "AI reasoning unavailable for this iteration; deterministic guidance is in use."
        )
        self.latest_reasoning_by_session[resolved_session_id] = self.latest_reasoning
        state.update_reasoning(self.latest_reasoning, session_id=resolved_session_id)

        return merged_recommendations

    def _normalize_finding(self, finding: Any) -> Dict[str, str]:
        if isinstance(finding, dict):
            details = finding.get("details", {}) or {}
            return {
                "finding_type": str(finding.get("finding_type", "unknown")),
                "finding_value": str(finding.get("finding_value", "N/A")),
                "risk_level": str(finding.get("risk_level", "unknown")),
                "service": self._norm_text(finding.get("service") or details.get("service")),
                "version": self._norm_text(finding.get("version") or details.get("version")),
                "target": str(finding.get("target", "") or ""),
            }

        details = getattr(finding, "details", {}) or {}
        if not isinstance(details, dict):
            details = {}
        return {
            "finding_type": str(getattr(finding, "finding_type", "unknown")),
            "finding_value": str(getattr(finding, "finding_value", "N/A")),
            "risk_level": str(getattr(finding, "risk_level", "unknown")),
            "service": self._norm_text(getattr(finding, "service", "") or details.get("service")),
            "version": self._norm_text(getattr(finding, "version", "") or details.get("version")),
            "target": str(getattr(finding, "target", "") or ""),
        }

    def _all_service_versions_known(self, service_inventory: List[Dict[str, str]]) -> bool:
        if not service_inventory:
            return False
        return all(self._is_known_version(entry.get("version")) for entry in service_inventory)

    def _build_technology_inventory(self, findings: List[Any]) -> List[Dict[str, str]]:
        inventory: List[Dict[str, str]] = []
        seen = set()
        for finding in findings:
            if isinstance(finding, dict):
                finding_type = str(finding.get("finding_type", "") or "")
                finding_value = str(finding.get("finding_value", "") or "")
                target = str(finding.get("target", "") or "")
                details = finding.get("details", {}) or {}
            else:
                finding_type = str(getattr(finding, "finding_type", "") or "")
                finding_value = str(getattr(finding, "finding_value", "") or "")
                target = str(getattr(finding, "target", "") or "")
                details = getattr(finding, "details", {}) or {}

            if not isinstance(details, dict):
                details = {}

            raw_version = details.get("version", "")
            if isinstance(raw_version, list):
                version = ""
                for entry in raw_version:
                    candidate = self._norm_text(entry)
                    if candidate:
                        version = candidate
                        break
            else:
                version = self._norm_text(raw_version)

            candidates: List[Any] = []
            if finding_type.lower() in {"technology", "framework_detection", "cms_detection", "web_service"}:
                candidates.append(finding_value)
            for details_key in ("name", "product", "technology", "framework", "cms", "service"):
                candidates.append(details.get(details_key))

            for candidate_value in candidates:
                if isinstance(candidate_value, (list, tuple, set)):
                    normalized_values = [self._norm_text(item) for item in candidate_value]
                else:
                    normalized_values = [self._norm_text(candidate_value)]

                for technology in normalized_values:
                    if (
                        not technology
                        or technology in UNKNOWN_VERSION_TOKENS
                        or technology.isdigit()
                    ):
                        continue

                    key = (technology, version if self._is_known_version(version) else "")
                    if key in seen:
                        continue
                    seen.add(key)
                    inventory.append(
                        {
                            "technology": technology,
                            "version": version if self._is_known_version(version) else "",
                            "target": target,
                        }
                    )

        return inventory

    def _searchsploit_inventory(self, service_inventory: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        exploits: List[Dict[str, Any]] = []
        seen_pairs = set()

        for entry in service_inventory:
            service = entry.get("service", "")
            version = entry.get("version", "")
            target = entry.get("target", "")
            if not service or not self._is_known_version(version):
                continue

            key = (service, version)
            if key in seen_pairs:
                continue
            seen_pairs.add(key)

            matches = search_exploitdb(software=service, version=version)
            for match in matches:
                match.setdefault("service", service)
                match.setdefault("version", version)
                match.setdefault("target", target)
                exploits.append(match)

        return exploits

    def _searchsploit_technology_inventory(
        self,
        technology_inventory: List[Dict[str, str]],
    ) -> List[Dict[str, Any]]:
        exploits: List[Dict[str, Any]] = []
        seen_queries = set()

        for entry in technology_inventory:
            technology = entry.get("technology", "")
            version = entry.get("version", "")
            target = entry.get("target", "")

            if not technology:
                continue

            query_key = (
                technology,
                version if self._is_known_version(version) else "",
            )
            if query_key in seen_queries:
                continue
            seen_queries.add(query_key)

            if self._is_known_version(version):
                matches = search_exploitdb(software=technology, version=version)
            else:
                matches = search_exploitdb(query=technology)

            for match in matches:
                match.setdefault("service", technology)
                match.setdefault("version", version if self._is_known_version(version) else "")
                match.setdefault("target", target)
                exploits.append(match)

        return exploits

    def _dedupe_exploit_matches(self, exploits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        deduped: List[Dict[str, Any]] = []
        seen = set()
        for exploit in exploits:
            if not isinstance(exploit, dict):
                continue

            key = (
                str(exploit.get("edb_id", "") or ""),
                str(exploit.get("title", "") or ""),
                str(exploit.get("path", "") or ""),
                str(exploit.get("target", "") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(exploit)
        return deduped

    def _derive_searchsploit_recommendations(
        self,
        exploits: List[Dict[str, Any]],
        executed_tools: List[str],
    ) -> List[Dict[str, Any]]:
        recommendations: List[Dict[str, Any]] = []
        recommended_tools = set()
        executed_tools_set = set(executed_tools)
        available_tools = {scanner.get("name") for scanner in SCANNERS if scanner.get("name")}

        for exploit in exploits:
            service = self._norm_text(exploit.get("service"))
            version = self._norm_text(exploit.get("version"))
            target = str(exploit.get("target", "") or "")
            title = str(exploit.get("title", "") or "")
            path = str(exploit.get("path", "") or "")
            context = f"{service} {version} {title} {path}".lower()

            tool_candidates = list(SERVICE_FOLLOWUP_TOOL_MAP.get(service, []))
            for keyword, keyword_tools in KEYWORD_FOLLOWUP_TOOL_MAP.items():
                if keyword in context:
                    tool_candidates.extend(keyword_tools)

            for tool in tool_candidates:
                if tool in recommended_tools or tool in executed_tools_set or tool not in available_tools:
                    continue

                reason_service = f"{service} {version}".strip()
                reason_scope = reason_service if reason_service else "detected service"
                recommendation: Dict[str, Any] = {
                    "tool": tool,
                    "reason": (
                        f"SearchSploit matched public exploits for {reason_scope}; "
                        f"run {tool} for targeted validation."
                    ),
                }
                if target:
                    recommendation["target"] = target

                recommendations.append(recommendation)
                recommended_tools.add(tool)

                # Keep deterministic guidance concise.
                if len(recommendations) >= 5:
                    return recommendations

        return recommendations

    def _derive_rule_recommendations(
        self,
        matched_rules: Dict[str, Any],
        executed_tools: List[str],
        available_tools: List[str],
    ) -> List[Dict[str, Any]]:
        recommendations: List[Dict[str, Any]] = []
        recommended_tools = set()
        executed_tools_set = set(executed_tools)
        allowed_tools = set(available_tools)

        for matches in matched_rules.values():
            for match in matches:
                if not isinstance(match, dict):
                    continue

                tool = match.get("tool")
                if not tool or tool in recommended_tools or tool in executed_tools_set or tool not in allowed_tools:
                    continue

                rule_id = match.get("rule_id", "rule")
                description = match.get("description", "Matched findings indicate further validation is needed.")
                target = str(match.get("target", "") or "")
                recommendation: Dict[str, Any] = {
                    "tool": tool,
                    "reason": f"{rule_id} matched: {description}",
                }
                if target:
                    recommendation["target"] = target
                flags = self._normalize_flags(match.get("flags"))
                if flags:
                    recommendation["flags"] = flags

                recommendations.append(recommendation)
                recommended_tools.add(tool)

        return recommendations

    def _derive_service_heuristic_recommendations(
        self,
        findings: List[Any],
        executed_tools: List[str],
        available_tools: List[str],
    ) -> List[Dict[str, Any]]:
        recommendations: List[Dict[str, Any]] = []
        recommended_tools = set()
        executed_tools_set = set(executed_tools)
        allowed_tools = set(available_tools)

        for finding in findings:
            data = self._normalize_finding(finding)
            service = data.get("service", "")
            target = data.get("target", "")
            finding_type = data.get("finding_type", "")
            finding_value = data.get("finding_value", "")
            context = f"{finding_type} {finding_value} {service}".lower()

            tool_candidates = list(SERVICE_FOLLOWUP_TOOL_MAP.get(service, []))
            for keyword, keyword_tools in KEYWORD_FOLLOWUP_TOOL_MAP.items():
                if keyword in context:
                    tool_candidates.extend(keyword_tools)

            if "cve-" in context:
                tool_candidates.append("nuclei")

            if finding_type == "web_service":
                tool_candidates.extend(["nikto", "nuclei"])

            for tool in tool_candidates:
                if tool in recommended_tools or tool in executed_tools_set or tool not in allowed_tools:
                    continue

                recommendation: Dict[str, Any] = {
                    "tool": tool,
                    "reason": f"Heuristic follow-up for detected {service or finding_type}.",
                }
                if target:
                    recommendation["target"] = target
                dynamic_flags = self._derive_dynamic_flags(tool, data)
                if dynamic_flags:
                    recommendation["flags"] = dynamic_flags

                recommendations.append(recommendation)
                recommended_tools.add(tool)

                if len(recommendations) >= 8:
                    return recommendations

        return recommendations

    def _merge_recommendations(
        self,
        deterministic_recommendations: List[Dict[str, Any]],
        ai_recommendations: List[Dict[str, Any]],
        executed_tools: List[str],
        available_tools: List[str],
    ) -> List[Dict[str, Any]]:
        merged: List[Dict[str, Any]] = []
        seen = set()
        executed_tools_set = set(executed_tools)
        allowed_tools = set(available_tools)

        for source in (deterministic_recommendations, ai_recommendations):
            for rec in source:
                if not isinstance(rec, dict):
                    continue

                tool = rec.get("tool")
                if not tool or tool in executed_tools_set or tool not in allowed_tools:
                    continue

                target = rec.get("target", "")
                dedupe_key = (tool, target)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)

                normalized: Dict[str, Any] = {
                    "tool": tool,
                    "reason": rec.get("reason", "Follow-up scan recommended."),
                }
                if target:
                    normalized["target"] = target
                flags = self._normalize_flags(rec.get("flags"))
                if flags:
                    normalized["flags"] = flags

                merged.append(normalized)

        return merged

    @staticmethod
    def _is_rate_limited_error(error: Any) -> bool:
        message = str(error).lower()
        return any(marker in message for marker in [
            "429", "rate limit", "quota", "exhausted", "limit reached", "403"
        ])

    def _apply_ai_recommendation_backoff(self, session_id: str) -> None:
        self._ai_recommendation_backoff_until_ts[session_id] = (
            time.monotonic() + self.recommendation_backoff_seconds
        )

    def _mark_ai_recommendation_call(self, session_id: str) -> None:
        self._last_ai_recommendation_call_ts[session_id] = time.monotonic()
        current_calls = self._ai_recommendation_call_count.get(session_id, 0)
        self._ai_recommendation_call_count[session_id] = current_calls + 1

    def _can_call_ai_recommendations(self, session_id: str) -> Tuple[bool, str]:
        now = time.monotonic()

        backoff_until = self._ai_recommendation_backoff_until_ts.get(session_id, 0.0)
        if now < backoff_until:
            wait_seconds = int(backoff_until - now)
            return (
                False,
                f"AI recommendation calls are temporarily throttled after provider rate limits; "
                f"retrying automatically in about {wait_seconds}s while deterministic guidance remains active.",
            )

        call_count = self._ai_recommendation_call_count.get(session_id, 0)
        if call_count >= self.recommendation_max_calls_per_session:
            return (
                False,
                "AI recommendation call budget reached for this scan session; "
                "continuing with deterministic guidance to prevent provider throttling.",
            )

        last_call = self._last_ai_recommendation_call_ts.get(session_id)
        if last_call is not None:
            elapsed = now - last_call
            if elapsed < self.recommendation_cooldown_seconds:
                wait_seconds = int(self.recommendation_cooldown_seconds - elapsed)
                return (
                    False,
                    f"AI recommendation cooldown active ({wait_seconds}s remaining); using deterministic guidance.",
                )

        return True, ""

    def _normalize_flags(self, flags: Any) -> List[str]:
        if flags is None:
            return []

        tokens: List[str] = []
        if isinstance(flags, str):
            tokens.extend(shlex.split(flags))
        elif isinstance(flags, (list, tuple)):
            for item in flags:
                if item is None:
                    continue
                if isinstance(item, str):
                    tokens.extend(shlex.split(item))
                else:
                    tokens.append(str(item))
        else:
            tokens.append(str(flags))

        cleaned = []
        for token in tokens:
            value = token.strip()
            if not value:
                continue
            if any(ch in value for ch in ("\n", "\r", "\x00")):
                continue
            cleaned.append(value)
        return cleaned

    def _derive_dynamic_flags(self, tool: str, finding: Dict[str, str]) -> List[str]:
        context = f"{finding.get('finding_type', '')} {finding.get('finding_value', '')}".lower()

        if tool == "nuclei" and "cve-" in context:
            return ["-severity", "critical,high,medium"]
        if tool == "sqlmap" and ("injection" in context or "sqli" in context):
            return ["--risk=3", "--level=5"]
        if tool.startswith("nmap-") and finding.get("risk_level") in {"misconfig", "exploit"}:
            return ["-Pn"]
        return []

    def _extract_relevant_context_lines(
        self,
        context: str,
        question: str,
        limit: int = 8,
    ) -> List[str]:
        lines = [line.strip() for line in context.splitlines() if line.strip()]
        if not lines:
            return []

        tokens = {
            token
            for token in re.split(r"[^a-zA-Z0-9]+", question.lower())
            if len(token) >= 3
        }
        if not tokens:
            return lines[-limit:]

        scored = []
        for line in lines:
            lowered = line.lower()
            score = sum(1 for token in tokens if token in lowered)
            if score > 0:
                scored.append((score, line))

        if not scored:
            return lines[-limit:]

        scored.sort(key=lambda item: item[0], reverse=True)
        selected = []
        seen = set()
        for _, line in scored:
            if line in seen:
                continue
            seen.add(line)
            selected.append(line)
            if len(selected) >= limit:
                break
        return selected

    def _local_rag_fallback_answer(self, context: str, question: str) -> str:
        relevant_lines = self._extract_relevant_context_lines(context, question, limit=8)
        if not relevant_lines:
            return (
                "AI provider is currently rate-limited (429), and I could not find enough local context lines "
                "to answer accurately. Please retry in a minute."
            )

        evidence = "\n".join(f"- {line[:260]}" for line in relevant_lines)
        return (
            "AI provider is currently rate-limited (429), so I used local context retrieval.\n\n"
            f"Question: {question}\n\n"
            f"Relevant evidence:\n{evidence}\n\n"
            "Suggestion: retry shortly for full AI synthesis, but the evidence above reflects the most relevant "
            "scan context currently available."
        )

    @staticmethod
    def _norm_text(value: Any) -> str:
        if value is None:
            return ""
        return str(value).strip().lower()

    @staticmethod
    def _is_known_version(version: Any) -> bool:
        normalized = ScanAgent._norm_text(version)
        return normalized not in UNKNOWN_VERSION_TOKENS

    def get_latest_reasoning(self, session_id: Optional[str] = None) -> str:
        if session_id is None:
            return self.latest_reasoning
        resolved_session_id = self._resolve_session_id(session_id)
        return self.latest_reasoning_by_session.get(resolved_session_id, self.latest_reasoning)

    async def answer_question_async(
        self,
        context: str,
        question: str,
        session_id: Optional[str] = None,
    ) -> str:
        """
        Async version of answer_question.
        """
        prompt = (
            f"Context (Logs/Data):\n{context}\n\n"
            f"User Question: {question}\n\n"
            "Please provide a helpful, concise answer as a security expert."
        )
        try:
            response = await self._run_analysis_async(prompt, session_id=session_id)
            if self._is_rate_limited_error(response):
                return self._local_rag_fallback_answer(context, question)
            return response
        except Exception as e:
            logger.error(f"Chat failed: {e}")
            if self._is_rate_limited_error(e):
                return self._local_rag_fallback_answer(context, question)
            return f"I encountered an error processing your request: {e}"

    def answer_question(self, context: str, question: str, session_id: Optional[str] = None) -> str:
        """
        Answers a user question based on provided context (e.g., logs).
        Synchronous wrapper.
        """
        try:
            return asyncio.run(
                self.answer_question_async(context, question, session_id=session_id)
            )
        except Exception as e:
            logger.error(f"Chat failed: {e}")
            return f"Agent error: {e}"
