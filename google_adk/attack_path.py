from .client import get_model

def generate_attack_path_dot(findings):
    model = get_model(json_mode=False)
    
    findings_data = [
        f"Tool: {f.source_tool}, Type: {f.finding_type}, Value: {f.finding_value}" 
        for f in findings
    ]
    
    prompt = f"""
    Act as a Lead Penetration Tester. Analyze these findings:
    {findings_data}
    
    Create a visual attack path graph. 
    1. Identify the entry point (e.g., Internet).
    2. Connect it to open ports/services.
    3. Connect services to specific vulnerabilities (CVEs/Misconfigs).
    
    Output strictly valid Graphviz DOT format. 
    Start with 'digraph AttackPath {{' and end with '}}'.
    Use 'rankdir=LR;'.
    Do not include markdown formatting (```).
    """
    
    try:
        response = model.generate_content(prompt)
        # Clean up potential markdown formatting if the model slips
        text = response.text.replace("```dot", "").replace("```", "").strip()
        return text
    except Exception as e:
        print(f"[AI Error] Graph generation failed: {e}")
        return "digraph G { label=\"Error generating graph\"; }"