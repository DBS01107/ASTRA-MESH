"""
The core orchestration engine.
Supports both static (pre-defined) and dynamic (adaptive) scanning modes.
Coordinates the entire scan process, from dependency resolution to execution and parsing.
"""
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from . import dependencies, runner, parsers, rules_engine, utils
from .findings import StandardFinding
from .graph import AstraGraph
from . import state


def run_orchestrator(
    primary_target: str,
    enable_arg: str,
    concurrency: int,
    mode: str,
    dry_run: bool = False,
    graph: Optional[AstraGraph] = None,
    session_id: Optional[str] = None,
):
    """
    The main orchestration function. Yields log lines for real-time display.
    """
    resolved_session_id = state.ensure_session(session_id)
    session_token = state.set_current_session(resolved_session_id)

    sanitized_target = utils.sanitize_target(primary_target)
    os.makedirs("orchestrator/output/raw", exist_ok=True)
    session_graph = graph or AstraGraph()

    try:
        # --- Initial Setup ---
        enabled_scanners = dependencies.resolve_enabled_scanners(enable_arg)
        yield f"[+] Mode selected: '{mode.upper()}'\n"
        yield f"[+] Initial scanners: {enabled_scanners}\n"

        # --- Route to the correct mode ---
        if mode == 'dynamic':
            session_graph.add_asset(sanitized_target)
            yield from _run_dynamic_mode(
                session_graph,
                sanitized_target,
                enabled_scanners,
                concurrency,
                dry_run,
                session_id=resolved_session_id,
            )
        else:
            session_graph.add_asset(sanitized_target)
            yield from _run_static_mode(
                session_graph,
                sanitized_target,
                enabled_scanners,
                concurrency,
                dry_run,
            )
    finally:
        state.reset_current_session(session_token)


def _run_static_mode(graph, target: str, enabled_scanners: list, concurrency: int, dry_run: bool):
    """
    Runs a fixed, pre-calculated execution plan from start to finish.
    """
    execution_groups = dependencies.build_execution_groups(enabled_scanners)
    yield "[+] Static execution plan calculated:\n"
    for i, group in enumerate(execution_groups):
        yield f"    - Group {i+1}: {group}\n"

    master_findings_list = []

    for group in execution_groups:
        yield f"\n[~] Running group: {group}\n"
        for result in _execute_group(graph, group, target, master_findings_list, concurrency, dry_run):
            if isinstance(result, str):
                yield result
            else:
                master_findings_list.append(result)
    
    yield "\n" + "="*50 + "\n"
    yield "[+] SCAN COMPLETE. All static groups finished.\n"
    yield f"[+] Total findings collected: {len(master_findings_list)}\n"
    yield "="*50 + "\n"


def _run_dynamic_mode(
    graph,
    target: str,
    enabled_scanners: list,
    concurrency: int,
    dry_run: bool,
    session_id: Optional[str] = None,
):
    """
    Runs an adaptive scan with AI-driven tool recommendations.
    Iteratively executes scanners and uses AI to decide what to scan next.
    """
    # DIRECT GOOGLE ADK INTEGRATION - planning_agent removed
    from google_adk.agent import ScanAgent
    
    # Initialize Google ADK Agent EARLY
    scan_agent = ScanAgent()
    resolved_session_id = state.ensure_session(session_id)

    master_findings_list = []
    executed_tools = set()
    iteration = 0
    max_iterations = 3  # Prevent infinite loops

    yield "[+] Starting dynamic AI-driven scan (Incremental AI Analysis Enabled)...\n"

    # First iteration: Run initial scanners
    initial_groups = dependencies.build_execution_groups(enabled_scanners)
    yield "[+] Initial scanners to execute:\n"
    for i, group in enumerate(initial_groups):
        yield f"    - Group {i+1}: {group}\n"

    for group in initial_groups:
        yield f"\n[~] Running initial group: {group}\n"

        for result in _execute_group(graph, group, target, master_findings_list, concurrency, dry_run):
            if isinstance(result, str):
                yield result
            else:
                master_findings_list.append(result)
        
        executed_tools.update(group)

    # Iterative AI-driven scanning
    while iteration < max_iterations:
        yield f"\n[*] Iteration {iteration}: Collected {len(master_findings_list)} findings\n"
        
        # Summarize findings by risk level
        yield "[+] Findings by risk level:\n"
        risk_counts = {}
        for f in master_findings_list:
            risk = getattr(f, 'risk_level', 'unknown')
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        for risk, count in risk_counts.items():
            yield f"    - {risk}: {count}\n"

        # Get AI recommendations DIRECTLY from Google ADK
        try:
            yield "\n[AI] Calling Google ADK Agent for scan recommendations...\n"
            
            # Get structured recommendations from Google ADK
            recommendations = scan_agent.recommend_next_scans(
                master_findings_list, 
                list(executed_tools),
                session_id=resolved_session_id,
            )
            
            yield f"[AI] Google ADK recommended {len(recommendations)} tools\n"
            
            if not recommendations:
                yield "[AI] No additional tools recommended. Scan complete.\n"
                break
            
            # Filter recommendations for tools that haven't been executed yet.
            # We dedupe by tool so the engine runs one follow-up action per scanner per iteration.
            new_recommendations = []
            seen_tools = set()
            for recommendation in recommendations:
                tool_name = recommendation.get("tool")
                if not tool_name or tool_name in executed_tools or tool_name in seen_tools:
                    continue
                seen_tools.add(tool_name)
                new_recommendations.append(recommendation)

            if not new_recommendations:
                yield "[AI] All recommended tools already executed. Scan complete.\n"
                break

            yield f"[AI] Executing {len(new_recommendations)} AI-recommended actions...\n"

            recommendations_by_target = {}
            for recommendation in new_recommendations:
                rec_target = recommendation.get("target", target) or target
                recommendations_by_target.setdefault(rec_target, []).append(recommendation)

            # Execute recommendations in target batches so independent tools can run concurrently.
            for rec_target, target_recommendations in recommendations_by_target.items():
                tools_for_target = []
                tool_options: Dict[str, Dict[str, Any]] = {}
                for recommendation in target_recommendations:
                    tool_name = recommendation.get("tool", "")
                    if not tool_name:
                        continue

                    reason = recommendation.get("reason", "AI recommendation")
                    flags = recommendation.get("flags")
                    yield f"[AI] {reason}\n"

                    available, install_logs = dependencies.ensure_tool_available(
                        tool_name,
                        auto_install=True,
                    )
                    for install_log in install_logs:
                        yield install_log

                    if not available:
                        yield f"[AI] Skipping '{tool_name}' because installation/availability check failed.\n"
                        continue

                    tools_for_target.append(tool_name)
                    if flags:
                        tool_options[tool_name] = {"flags": flags}
                        yield f"[AI] Applying dynamic flags for {tool_name}: {flags}\n"

                if not tools_for_target:
                    continue

                yield f"[AI] Running tools on {rec_target}: {tools_for_target}\n"

                # Execute each target batch with normal concurrent orchestration flow.
                for result in _execute_group(
                    graph,
                    tools_for_target,
                    rec_target,
                    master_findings_list,
                    concurrency,
                    dry_run,
                    tool_options=tool_options,
                ):
                    if hasattr(result, 'finding_type'):
                        yield f"[+] [{result.source_tool}] Found: {result.finding_type} -> {result.finding_value}\n"
                        master_findings_list.append(result)
                    elif isinstance(result, str):
                        yield result

                executed_tools.update(tools_for_target)
 
        except Exception as e:
            import traceback
            yield f"[!] AI recommendation failed: {e}\n"
            traceback.print_exc()
            yield "[!] Continuing with manual analysis.\n"
            break

        iteration += 1

    # Final summary
    yield f"\n[*] ===== FINAL SCAN SUMMARY =====\n"
    yield f"[*] Total findings collected: {len(master_findings_list)}\n"
    yield f"[*] Tools executed: {list(executed_tools)}\n"
    yield f"[*] Iterations completed: {iteration}\n"

    # AI-generated summary
    if master_findings_list:
        try:
            yield "\n[AI] Generating comprehensive security analysis...\n"
            final_analysis = scan_agent.analyze_findings(
                master_findings_list,
                session_id=resolved_session_id,
            )
            yield f"\n[AI] === SECURITY ANALYSIS SUMMARY ===\n{final_analysis}\n"
        except Exception as e:
             yield f"[!] AI summary generation failed: {e}\n"

    if master_findings_list:
        # Log findings summary
        yield "[+] Findings by risk level:\n"
        risk_counts = {}
        high_risk_findings = []
        
        for f in master_findings_list:
            risk = getattr(f, 'risk_level', 'unknown')
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
            if risk == 'exploit':
                high_risk_findings.append(f)
        
        for risk, count in sorted(risk_counts.items()):
            yield f"    - {risk}: {count}\n"

        # Log high-value findings with details
        if high_risk_findings:
            yield f"\n[!] {len(high_risk_findings)} CRITICAL FINDINGS DETECTED:\n"
            for f in high_risk_findings[:10]:
                cap = getattr(f, 'capability', 'unknown')
                severity = getattr(f, 'severity', 'unknown')
                yield f"    [CRITICAL] {cap}: {f.finding_value}\n"
                yield f"              Target: {f.target} | Severity: {severity}\n"


def _execute_group(
    graph,
    group: list,
    target: str,
    master_findings: list,
    concurrency: int,
    dry_run: bool,
    tool_options: Optional[Dict[str, Dict[str, Any]]] = None,
):
    """
    Helper function to execute a single group of tools and parse their results.
    Yields log lines (str) and StandardFinding objects AS THEY COMPLETE.
    """
    tasks_to_run = []
    options_by_tool = tool_options or {}

    # 1. Build the list of all commands for this group
    for tool_name in group:
        scanner_config = dependencies.get_scanner_by_name(tool_name)
        if not scanner_config:
            yield f"[!] Scanner '{tool_name}' is not registered. Skipping.\n"
            continue

        if scanner_config.get("internal"):
            if tool_name == "searchsploit":
                for internal_result in _run_internal_searchsploit(
                    target=target,
                    findings=master_findings,
                    dry_run=dry_run,
                ):
                    if isinstance(internal_result, str):
                        yield internal_result
                    else:
                        graph.add_finding(internal_result)
                        state.add_finding(internal_result)
                        yield internal_result
                continue

            yield f"[!] Internal scanner '{tool_name}' is not supported by engine runtime. Skipping.\n"
            continue

        dynamic_flags = options_by_tool.get(tool_name, {}).get("flags")

        if scanner_config.get("requires_url"):
            # Find web service URLs from all findings so far
            web_targets = {f.target for f in master_findings if f.finding_type == "web_service"}
            # Fallback if no web services have been found yet
            if not web_targets:
                web_targets = {utils.ensure_http_scheme(target)}

            for url in web_targets:
                output_file = utils.get_output_filepath(scanner_config, url, target)
                cmd_args = utils.command_builder(
                    scanner_config,
                    url,
                    target,
                    output_file,
                    dynamic_flags=dynamic_flags,
                )
                tasks_to_run.append({'tool': tool_name, 'cmd': cmd_args, 'url': url, 'file': output_file})
        else:
            output_file = utils.get_output_filepath(scanner_config, target, target)
            cmd_args = utils.command_builder(
                scanner_config,
                target,
                target,
                output_file,
                dynamic_flags=dynamic_flags,
            )
            tasks_to_run.append({'tool': tool_name, 'cmd': cmd_args, 'url': target, 'file': output_file})

    # 2. Execute commands concurrently AND PARSE IMMEDIATELY upon completion
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        future_to_task = {executor.submit(runner.run_command, task['cmd'], task['tool'], task['url'], dry_run): task for task in tasks_to_run}

        for future in as_completed(future_to_task):
            task = future_to_task[future]
            try:
                # Yield logs from the tool execution FIRST
                for line in future.result():
                    yield line
                
                # IMMEDIATELY Parse results for this completed task
                yield f"[*] Parsing results for {task['tool']}\n"
                parser_func = parsers.get_parser_for_tool(task['tool'])
                if parser_func:
                    try:
                        # Pass the URL for context, needed by some parsers
                        findings = parser_func(task['file'], task.get('url'))
                        yield f"[+] [{task['tool']}] Parsed {len(findings)} findings\n"
                        for finding in findings:
                            # Add finding to graph database
                            graph.add_finding(finding)
                            state.add_finding(finding)
                            yield finding  # Yield the structured finding object
                    except Exception as e:
                        yield f"[!] Error parsing output for {task['tool']} from {task['file']}: {e}\n"

            except Exception as e:
                yield f"[!!!] ERROR in task '{task['tool']} on {task['url']}': {e}\n"


_UNKNOWN_VERSION_TOKENS = {"", "unknown", "n/a", "na", "none", "null", "-"}


def _norm_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _is_known_version(version: str) -> bool:
    normalized = _norm_text(version)
    if not normalized or normalized in _UNKNOWN_VERSION_TOKENS:
        return False
    return any(ch.isdigit() for ch in normalized)


def _iter_candidate_values(raw: Any) -> List[str]:
    values: List[str] = []
    if raw is None:
        return values
    if isinstance(raw, (list, tuple, set)):
        for item in raw:
            values.extend(_iter_candidate_values(item))
        return values
    values.append(str(raw))
    return values


def _extract_searchsploit_inventory(findings: List[Any]) -> List[Dict[str, str]]:
    inventory: List[Dict[str, str]] = []
    seen = set()

    for finding in findings:
        if isinstance(finding, dict):
            finding_type = str(finding.get("finding_type", "") or "")
            finding_value = finding.get("finding_value", "")
            target = str(finding.get("target", "") or "")
            service = finding.get("service")
            version = finding.get("version")
            details = finding.get("details", {}) or {}
        else:
            finding_type = str(getattr(finding, "finding_type", "") or "")
            finding_value = getattr(finding, "finding_value", "")
            target = str(getattr(finding, "target", "") or "")
            service = getattr(finding, "service", "")
            version = getattr(finding, "version", "")
            details = getattr(finding, "details", {}) or {}

        if not isinstance(details, dict):
            details = {}

        version_text = _norm_text(version or details.get("version"))
        service_text = _norm_text(service or details.get("service"))

        # Service inventory from any tool (nmap, parser enrichments, etc.).
        if service_text and service_text not in _UNKNOWN_VERSION_TOKENS:
            key = ("service", service_text, version_text if _is_known_version(version_text) else "", target)
            if key not in seen:
                seen.add(key)
                inventory.append(
                    {
                        "technology": service_text,
                        "version": version_text if _is_known_version(version_text) else "",
                        "target": target,
                    }
                )

        # Technology candidates from all findings/details.
        raw_candidates: List[Any] = []
        if finding_type.lower() in {"technology", "framework_detection", "cms_detection", "web_service"}:
            raw_candidates.append(finding_value)
        for details_key in ("product", "name", "technology", "framework", "cms"):
            raw_candidates.append(details.get(details_key))

        for raw_candidate in raw_candidates:
            for candidate_value in _iter_candidate_values(raw_candidate):
                candidate = _norm_text(candidate_value)
                if (
                    not candidate
                    or candidate in _UNKNOWN_VERSION_TOKENS
                    or candidate.isdigit()
                ):
                    continue
                key = ("technology", candidate, version_text if _is_known_version(version_text) else "", target)
                if key in seen:
                    continue
                seen.add(key)
                inventory.append(
                    {
                        "technology": candidate,
                        "version": version_text if _is_known_version(version_text) else "",
                        "target": target,
                    }
                )

    return inventory


def _run_internal_searchsploit(target: str, findings: List[Any], dry_run: bool):
    yield "[*] [searchsploit] Running automatic exploit reference enrichment from detected technologies.\n"

    inventory = _extract_searchsploit_inventory(findings)
    if not inventory:
        state.update_searchsploit_matches([], session_id=state.get_current_session())
        yield "[*] [searchsploit] No technology/service evidence available yet.\n"
        return

    if dry_run:
        yield f"    [searchsploit] DRY RUN would query {len(inventory)} technology/service fingerprints.\n"
        return

    from google_adk.exploitdb import (
        search_exploitdb, search_nvd_recent_cves, search_github_advisories,
        fetch_cve_remediation, search_github_advisories_by_cve,
    )

    raw_matches: List[Dict[str, Any]] = []
    seen_queries = set()
    for entry in inventory:
        technology = _norm_text(entry.get("technology"))
        version = _norm_text(entry.get("version"))
        target_hint = str(entry.get("target", "") or "")
        if not technology:
            continue

        query_key = (technology, version if _is_known_version(version) else "")
        if query_key in seen_queries:
            continue
        seen_queries.add(query_key)

        if _is_known_version(version):
            matches = search_exploitdb(software=technology, version=version)
        else:
            matches = search_exploitdb(query=technology)

        for match in matches:
            normalized = dict(match)
            normalized.setdefault("service", technology)
            normalized.setdefault("version", version if _is_known_version(version) else "")
            normalized.setdefault(
                "query",
                f"{technology} {version}".strip() if _is_known_version(version) else technology,
            )
            normalized.setdefault("target", target_hint or target)
            raw_matches.append(normalized)

    deduped_matches: List[Dict[str, Any]] = []
    seen_matches = set()
    for match in raw_matches:
        dedupe_key = (
            str(match.get("edb_id", "") or ""),
            str(match.get("title", "") or ""),
            str(match.get("path", "") or ""),
            str(match.get("target", "") or ""),
        )
        if dedupe_key in seen_matches:
            continue
        seen_matches.add(dedupe_key)
        deduped_matches.append(match)

    state.update_searchsploit_matches(deduped_matches, session_id=state.get_current_session())

    # --- Zero-Day Intelligence via NVD ---
    zeroday_matches: List[Dict[str, Any]] = []
    seen_zeroday_keywords: set = set()
    for entry in inventory:
        keyword = _norm_text(entry.get("technology"))
        if not keyword or keyword in seen_zeroday_keywords:
            continue
        seen_zeroday_keywords.add(keyword)
        try:
            nvd_results = search_nvd_recent_cves(keyword=keyword, days_back=90, max_results=5)
            zeroday_matches.extend(nvd_results)
            if nvd_results:
                yield f"[+] [zeroday] NVD returned {len(nvd_results)} recent CVE(s) for '{keyword}'\n"
        except Exception as exc:
            yield f"[!] [zeroday] NVD lookup failed for '{keyword}': {exc}\n"

    state.update_zeroday_matches(zeroday_matches, session_id=state.get_current_session())
    if zeroday_matches:
        yield f"[+] [zeroday] Total recent CVEs from NVD: {len(zeroday_matches)}\n"
    else:
        yield "[*] [zeroday] No recent NVD CVEs found for detected technologies.\n"

    # --- Unverified External Web Intel (GitHub Advisories) ---
    unverified_matches: List[Dict[str, Any]] = []
    seen_unverified_keywords: set = set()
    for entry in inventory:
        keyword = _norm_text(entry.get("technology"))
        if not keyword or keyword in seen_unverified_keywords:
            continue
        seen_unverified_keywords.add(keyword)
        try:
            gh_results = search_github_advisories(keyword=keyword, max_results=5)
            unverified_matches.extend(gh_results)
            if gh_results:
                yield f"[+] [web-intel] GitHub Advisories returned {len(gh_results)} result(s) for '{keyword}'\n"
        except Exception as exc:
            yield f"[!] [web-intel] GitHub Advisories lookup failed for '{keyword}': {exc}\n"

    if unverified_matches:
        yield f"[+] [web-intel] Total unverified external intel items: {len(unverified_matches)}\n"
        yield "[!] [web-intel] NOTE: External web intel is UNVERIFIED and may contain false positives.\n"
        state.update_zeroday_matches(
            zeroday_matches + unverified_matches,
            session_id=state.get_current_session(),
        )
    elif not zeroday_matches:
        yield "[*] [web-intel] No external web intel found for detected technologies.\n"

    # --- CVE Remediation Enrichment ---
    # Collect unique CVE IDs from all findings (Nuclei, Nikto, Searchsploit, Nmap vulners)
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    seen_cves: set = set()
    for finding in findings:
        cve_id = None
        if isinstance(finding, dict):
            cve_id = finding.get("cve_id") or ""
            # Also scan finding_value in case cve_id field is empty
            if not cve_id:
                fv = str(finding.get("finding_value") or "")
                m = cve_pattern.match(fv)
                if m:
                    cve_id = m.group(0)
        else:
            cve_id = getattr(finding, "cve_id", "") or ""
            if not cve_id:
                fv = str(getattr(finding, "finding_value", "") or "")
                m = cve_pattern.match(fv)
                if m:
                    cve_id = m.group(0)
        if cve_id and cve_pattern.match(cve_id):
            seen_cves.add(cve_id.upper())

    if seen_cves:
        yield f"[+] [remediation] Fetching remediation data for {len(seen_cves)} CVE(s) from findings...\n"
        for cve_id in sorted(seen_cves):
            try:
                nvd_detail = fetch_cve_remediation(cve_id)
                ghsa_detail = search_github_advisories_by_cve(cve_id)
                if nvd_detail or ghsa_detail:
                    entry = nvd_detail or {"cve_id": cve_id}
                    if ghsa_detail:
                        entry["ghsa"] = ghsa_detail
                    state.update_remediation(cve_id, entry, session_id=state.get_current_session())
                    yield f"[+] [remediation] Enriched {cve_id}" + (
                        f" (GHSA: {ghsa_detail['ghsa_id']})" if ghsa_detail else ""
                    ) + "\n"
            except Exception as exc:
                yield f"[!] [remediation] Failed to enrich {cve_id}: {exc}\n"
    else:
        yield "[*] [remediation] No CVE IDs found in findings to enrich.\n"

    if not deduped_matches:
        yield "[+] [searchsploit] No ExploitDB matches found for detected technologies.\n"
        return

    yield f"[+] [searchsploit] Matched {len(deduped_matches)} ExploitDB records.\n"
    cve_pattern = re.compile(r"(CVE-\d{4}-\d{4,7})", flags=re.IGNORECASE)

    for index, match in enumerate(deduped_matches):
        title = str(match.get("title", "") or "")
        path = str(match.get("path", "") or "")
        query = str(match.get("query", "") or "")
        edb_id = str(match.get("edb_id", "") or "")
        target_hint = str(match.get("target", "") or target)
        cve_match = cve_pattern.search(f"{title} {path}")
        cve_id = cve_match.group(1).upper() if cve_match else None

        finding_value = cve_id or title or (f"EDB-{edb_id}" if edb_id else query)
        finding_id = f"searchsploit_{edb_id or index}_{utils.sanitize_target(target_hint)}_{index}"

        finding = StandardFinding(
            id=finding_id,
            source_tool="searchsploit",
            target=target_hint,
            finding_type="vulnerability",
            finding_value=finding_value,
            severity="high" if cve_id else "medium",
            capability="exploit_reference_found",
            risk_level="exploit",
            cve_id=cve_id,
            details={
                "name": title,
                "query": query,
                "path": path,
                "edb_id": edb_id,
                "source": "exploitdb",
                "service": str(match.get("service", "") or ""),
                "version": str(match.get("version", "") or ""),
                "platform": str(match.get("platform", "") or ""),
                "date": str(match.get("date", "") or ""),
            },
        )
        yield finding
