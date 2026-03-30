"""
Catalog of web security checks ASTRA tracks and how they map to scanners.
"""
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Sequence, Tuple

from . import registry


@dataclass(frozen=True)
class CheckDefinition:
    check_id: str
    name: str
    group: str
    tools: Tuple[str, ...]
    keywords: Tuple[str, ...]


GROUP_LABELS: Dict[str, str] = {
    "general": "General Tests",
    "passive": "Passive Checks",
    "active": "Active Checks",
}

GROUP_DEFAULT_TOOLS: Dict[str, Tuple[str, ...]] = {
    "general": ("whatweb", "nikto", "nuclei", "dirb", "ffuf", "sslyze"),
    "passive": ("nikto", "nuclei", "sslyze", "whatweb", "wapiti", "skipfish"),
    "active": ("nuclei", "wapiti", "sqlmap", "ffuf", "skipfish"),
}


def _slug(value: str) -> str:
    chars = []
    for ch in value.lower():
        if ch.isalnum():
            chars.append(ch)
        elif ch in {" ", "-", "/", "(", ")"}:
            chars.append("_")
    while "__" in "".join(chars):
        chars = list("".join(chars).replace("__", "_"))
    return "".join(chars).strip("_")


def _check(
    name: str,
    group: str,
    *,
    tools: Sequence[str] = (),
    keywords: Sequence[str] = (),
) -> CheckDefinition:
    resolved_tools = tuple(dict.fromkeys(tools or GROUP_DEFAULT_TOOLS[group]))
    resolved_keywords = tuple(dict.fromkeys((kw.lower() for kw in (keywords or (name,)))))
    return CheckDefinition(
        check_id=_slug(name),
        name=name,
        group=group,
        tools=resolved_tools,
        keywords=resolved_keywords,
    )


CHECK_DEFINITIONS: Tuple[CheckDefinition, ...] = (
    # General Tests
    _check("Fingerprint Website", "general", keywords=("technology", "whatweb", "web service")),
    _check("Server Software Vulnerabilities", "general", keywords=("server", "cve", "vulnerability")),
    _check("Robots.txt", "general", keywords=("robots.txt", "robots")),
    _check("JavaScript Libraries", "general", keywords=("javascript", "js library")),
    _check("SSL/TLS Certificates", "general", tools=("sslyze", "nikto", "nuclei"), keywords=("tls", "ssl", "certificate")),
    _check("Client Access Policies", "general", keywords=("crossdomain", "client access", "policy")),
    _check("HTTP Debug Methods", "general", tools=("nikto", "nuclei"), keywords=("trace", "debug method", "http method")),
    _check("Security.txt File Missing", "general", tools=("nuclei", "nikto", "ffuf"), keywords=("security.txt", "security txt")),
    _check("CORS Misconfiguration", "general", tools=("nuclei", "wapiti", "nikto"), keywords=("cors", "access-control-allow-origin")),
    _check("Resource Discovery", "general", tools=("dirb", "ffuf", "nuclei", "skipfish"), keywords=("discovery", "resource", "endpoint")),
    _check("Find Sensitive Files", "general", tools=("dirb", "ffuf", "nuclei", "nikto"), keywords=("sensitive file", "exposed_files", "config", ".env", ".git")),
    _check("Find Admin Consoles", "general", tools=("dirb", "ffuf", "nuclei", "nikto"), keywords=("admin", "console", "dashboard")),
    _check("Find Interesting Files", "general", tools=("dirb", "ffuf", "nuclei"), keywords=("interesting file", "backup", "log", "old")),
    _check("Information Disclosure", "general", keywords=("information disclosure", "disclosure", "leak")),
    _check("Software Identification", "general", keywords=("technology", "version", "fingerprint")),
    _check("Misconfigurations", "general", keywords=("misconfig", "configuration", "weak setting")),
    _check("Find GraphQL Endpoint", "general", tools=("nuclei", "ffuf", "dirb"), keywords=("graphql", "/graphql")),
    _check("Fuzz OpenAPI Locations", "general", tools=("ffuf", "dirb", "nuclei"), keywords=("openapi", "swagger", "api-docs")),
    # Passive Checks
    _check("Security Headers", "passive", keywords=("security header", "csp", "hsts", "x-frame-options")),
    _check("Cookie Security", "passive", keywords=("cookie", "httponly", "secure", "samesite")),
    _check("Directory Listing", "passive", keywords=("directory listing", "indexing", "mod-negotiation-listing")),
    _check("Secure Communication", "passive", tools=("sslyze", "nuclei", "nikto"), keywords=("tls", "ssl", "https")),
    _check("Weak Password Submission", "passive", tools=("wapiti", "nuclei", "skipfish"), keywords=("password policy", "weak password")),
    _check("Commented Code/Error Codes", "passive", tools=("nuclei", "nikto", "wapiti"), keywords=("comment", "stack trace", "error code")),
    _check("Clear Text Submission of Credentials", "passive", tools=("wapiti", "nuclei"), keywords=("clear text", "credential", "http auth")),
    _check("Verify Domain Sources", "passive", tools=("whatweb", "nuclei"), keywords=("domain source", "origin", "referer")),
    _check("Mixed Encryptions Content", "passive", tools=("nuclei", "wapiti", "skipfish"), keywords=("mixed content", "http resource")),
    _check("Sensitive Data Crawl", "passive", tools=("nuclei", "wapiti", "skipfish"), keywords=("sensitive data", "pii", "token exposure")),
    _check("Find Login Interfaces", "passive", tools=("ffuf", "dirb", "nuclei", "whatweb"), keywords=("login", "signin", "auth")),
    _check("Find File Upload", "passive", tools=("ffuf", "dirb", "nuclei", "wapiti"), keywords=("upload", "multipart", "file upload")),
    _check("Path Disclosure", "passive", tools=("nuclei", "nikto", "wapiti"), keywords=("path disclosure", "filesystem path")),
    _check("SQL Statement in Request Parameter", "passive", tools=("wapiti", "nuclei"), keywords=("sql statement", "select ", "union ")),
    _check("Password Returned in Later Response", "passive", tools=("wapiti", "nuclei"), keywords=("password returned", "credential leak")),
    _check("Session Token in URL", "passive", tools=("nuclei", "wapiti", "nikto"), keywords=("session token in url", "token=", "sid=")),
    _check("API Endpoints", "passive", tools=("ffuf", "dirb", "nuclei"), keywords=("api", "endpoint", "rest")),
    # Active Checks
    _check("SQL Injection", "active", tools=("sqlmap", "nuclei", "wapiti"), keywords=("sqli", "sql injection")),
    _check("XSS", "active", tools=("nuclei", "wapiti", "skipfish"), keywords=("xss", "cross-site scripting")),
    _check("Local File Inclusion", "active", tools=("nuclei", "wapiti"), keywords=("lfi", "local file inclusion")),
    _check("OS Command Injection", "active", tools=("nuclei", "wapiti"), keywords=("command injection", "cmdi", "rce")),
    _check("Server-Side Request Forgery (SSRF)", "active", tools=("nuclei", "wapiti"), keywords=("ssrf", "server-side request forgery")),
    _check("Open Redirect", "active", tools=("nuclei", "wapiti"), keywords=("open redirect", "redirect")),
    _check("Broken Authentication", "active", tools=("nuclei", "wapiti"), keywords=("broken authentication", "auth bypass")),
    _check("PHP Code Injection", "active", tools=("nuclei", "wapiti"), keywords=("php code injection", "php injection")),
    _check("Server-Side JavaScript Code Injection", "active", tools=("nuclei", "wapiti"), keywords=("javascript code injection", "nodejs injection")),
    _check("Ruby Code Injection", "active", tools=("nuclei", "wapiti"), keywords=("ruby code injection", "ruby injection")),
    _check("Python Code Injection", "active", tools=("nuclei", "wapiti"), keywords=("python code injection", "python injection")),
    _check("Perl Code Injection", "active", tools=("nuclei", "wapiti"), keywords=("perl code injection", "perl injection")),
    _check("Log4j Remote Code Execution", "active", tools=("nuclei",), keywords=("log4j", "log4shell")),
    _check("Server-Side Template Injection (SSTI)", "active", tools=("nuclei", "wapiti"), keywords=("ssti", "template injection")),
    _check("XML External Entity Injection (XXE)", "active", tools=("nuclei", "wapiti"), keywords=("xxe", "xml external entity")),
    _check("ViewState Remote Code Execution", "active", tools=("nuclei",), keywords=("viewstate", "asp.net")),
    _check("Client-Side Prototype Pollution", "active", tools=("nuclei",), keywords=("prototype pollution")),
    _check("Exposed Backup Files", "active", tools=("dirb", "ffuf", "nuclei", "nikto"), keywords=("backup file", ".bak", ".zip", ".old")),
    _check("Request URL Override", "active", tools=("nuclei", "wapiti"), keywords=("url override", "x-original-url", "x-rewrite-url")),
    _check("HTTP Request Smuggling", "active", tools=("nuclei",), keywords=("request smuggling", "te.cl", "cl.te")),
    _check("Cross-Site Request Forgery (CSRF)", "active", tools=("nuclei", "wapiti"), keywords=("csrf", "cross-site request forgery")),
    _check("Insecure Deserialization", "active", tools=("nuclei", "wapiti"), keywords=("deserialization", "insecure deserialization")),
    _check("NoSQL Injection", "active", tools=("nuclei", "wapiti"), keywords=("nosql", "nosql injection", "mongo")),
    _check("Session Fixation", "active", tools=("nuclei", "wapiti"), keywords=("session fixation")),
    _check("Enumerable Parameter (IDOR)", "active", tools=("nuclei", "wapiti", "ffuf"), keywords=("idor", "insecure direct object reference")),
    _check("JWT Weaknesses", "active", tools=("nuclei",), keywords=("jwt", "token weakness", "none algorithm")),
    _check("Response Header Injection", "active", tools=("nuclei", "wapiti"), keywords=("response header injection", "crlf injection")),
)


def _available_tool_names() -> Tuple[str, ...]:
    return tuple(scanner.get("name") for scanner in registry.SCANNERS if scanner.get("name"))


def get_checks_catalog() -> List[Dict[str, Any]]:
    available_tools = set(_available_tool_names())
    catalog: List[Dict[str, Any]] = []
    for check in CHECK_DEFINITIONS:
        catalog.append(
            {
                "id": check.check_id,
                "name": check.name,
                "group": check.group,
                "group_label": GROUP_LABELS.get(check.group, check.group),
                "tools": [tool for tool in check.tools if tool in available_tools],
            }
        )
    return catalog


def _finding_to_search_blob(finding: Any) -> str:
    if isinstance(finding, dict):
        data = finding
    else:
        data = {
            "source_tool": getattr(finding, "source_tool", ""),
            "finding_type": getattr(finding, "finding_type", ""),
            "finding_value": getattr(finding, "finding_value", ""),
            "capability": getattr(finding, "capability", ""),
            "severity": getattr(finding, "severity", ""),
            "target": getattr(finding, "target", ""),
            "cve_id": getattr(finding, "cve_id", ""),
            "details": getattr(finding, "details", {}) or {},
        }

    details = data.get("details", {}) or {}
    if not isinstance(details, dict):
        details = {}

    tags_value = details.get("tags", [])
    if isinstance(tags_value, str):
        tags_text = tags_value
    elif isinstance(tags_value, (list, tuple, set)):
        tags_text = " ".join(str(item) for item in tags_value)
    else:
        tags_text = str(tags_value)

    parts = [
        str(data.get("source_tool", "")),
        str(data.get("finding_type", "")),
        str(data.get("finding_value", "")),
        str(data.get("capability", "")),
        str(data.get("severity", "")),
        str(data.get("target", "")),
        str(data.get("cve_id", "")),
        str(details.get("name", "")),
        str(details.get("description", "")),
        tags_text,
    ]
    return " ".join(parts).lower()


def _is_detected(check: CheckDefinition, finding_blobs: Iterable[str]) -> bool:
    for blob in finding_blobs:
        for keyword in check.keywords:
            if keyword and keyword in blob:
                return True
    return False


def evaluate_check_coverage(
    selected_scanners: Sequence[str],
    findings: Sequence[Any] = (),
) -> Dict[str, Any]:
    available_tools = set(_available_tool_names())
    selected = set(selected_scanners)
    finding_blobs = [_finding_to_search_blob(finding) for finding in findings]

    checks_payload: List[Dict[str, Any]] = []
    summary = {"total": 0, "detected": 0, "covered": 0, "uncovered": 0}
    group_summary: Dict[str, Dict[str, Any]] = {
        group: {"id": group, "label": label, "total": 0, "detected": 0, "covered": 0, "uncovered": 0}
        for group, label in GROUP_LABELS.items()
    }

    for check in CHECK_DEFINITIONS:
        mapped_tools = [tool for tool in check.tools if tool in available_tools]
        matched_tools = [tool for tool in mapped_tools if tool in selected]
        detected = _is_detected(check, finding_blobs)

        if detected:
            status = "detected"
        elif matched_tools:
            status = "covered"
        else:
            status = "uncovered"

        summary["total"] += 1
        summary[status] += 1

        group_bucket = group_summary[check.group]
        group_bucket["total"] += 1
        group_bucket[status] += 1

        checks_payload.append(
            {
                "id": check.check_id,
                "name": check.name,
                "group": check.group,
                "group_label": GROUP_LABELS.get(check.group, check.group),
                "status": status,
                "tools": mapped_tools,
                "matched_tools": matched_tools,
            }
        )

    groups_payload = list(group_summary.values())
    return {"summary": summary, "groups": groups_payload, "checks": checks_payload}
