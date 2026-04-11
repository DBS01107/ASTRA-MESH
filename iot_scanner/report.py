import json
from typing import List, Dict
import matplotlib.pyplot as plt
import numpy as np
import os

def write_report(assessment: List[Dict], outpath: str = 'iot_report.json'):
    with open(outpath, 'w') as f:
        json.dump({"assessment": assessment}, f, indent=2)

def plot_heatmap(assessment: List[Dict], outdir: str = 'reports'):
    os.makedirs(outdir, exist_ok=True)
    ips = [a.get('ip') for a in assessment]
    scores = [a.get('risk_score', 0.0) for a in assessment]
    # simple horizontal bar heatmap
    y = np.arange(len(ips))
    cmap = plt.get_cmap('hot')
    colors = [cmap(s/10.0) for s in scores]
    plt.figure(figsize=(8, max(4, len(ips)*0.3)))
    plt.barh(y, scores, color=colors)
    plt.yticks(y, ips)
    plt.xlabel('Risk Score (0-10)')
    plt.title('IoT Devices Risk Heatmap')
    outimg = os.path.join(outdir, 'risk_heatmap.png')
    plt.tight_layout()
    plt.savefig(outimg)
    plt.close()
    return outimg

def write_html_report(assessment: List[Dict], outpath: str = 'iot_report.html', heatmap_img: str = None):
    html = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        "<meta charset='utf-8'>",
        "<title>ASTRA IoT Security Report</title>",
        "<style>",
        "body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0f172a; color: #e2e8f0; margin: 0; padding: 20px; }",
        "h1, h2, h3 { color: #f8fafc; }",
        ".device-card { background: #1e293b; border-left: 5px solid #3b82f6; padding: 15px; margin-bottom: 20px; border-radius: 5px; }",
        ".critical { border-left-color: #ef4444; }",
        ".high { border-left-color: #f97316; }",
        ".badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; background: #334155; margin-right: 5px; }",
        ".badge-critical { background: #ef4444; color: white; }",
        ".badge-protocol { background: #8b5cf6; color: white; }",
        "ul { margin-top: 5px; }",
        "li { margin-bottom: 5px; }",
        "</style>",
        "</head>",
        "<body>",
        "<h1>ASTRA IoT LAN Security Report</h1>"
    ]
    
    if heatmap_img and os.path.exists(heatmap_img):
        html.append(f"<h2>Network Heatmap</h2>")
        html.append(f"<img src='{os.path.basename(heatmap_img)}' alt='Heatmap' style='max-width: 100%; height: auto; border-radius: 8px;'/>")
    
    html.append("<h2>Discovered Devices</h2>")
    
    for device in sorted(assessment, key=lambda x: x.get('risk_score', 0), reverse=True):
        score = device.get('risk_score', 0)
        card_class = "device-card critical" if score >= 7.0 else ("device-card high" if score >= 4.0 else "device-card")
        
        vendor_text = device.get('vendor') or 'Unknown Vendor'
        ip = device.get('ip') or 'Unknown IP'
        mac = device.get('mac') or 'Unknown MAC'
        
        html.append(f"<div class='{card_class}'>")
        html.append(f"<h3>{vendor_text} Device ({ip})</h3>")
        html.append(f"<p><strong>MAC:</strong> {mac} | <strong>Risk Score:</strong> <span class='badge'>{score}/10</span></p>")
        
        flags = device.get('flags', {})
        if flags:
            html.append("<p><strong>Flags:</strong> ")
            for flag, active in flags.items():
                if active:
                    html.append(f"<span class='badge badge-critical'>{flag.replace('_', ' ').upper()}</span>")
            html.append("</p>")

        protocol_findings = device.get('protocol_findings', [])
        if protocol_findings:
            html.append("<h4>🛑 Protocol Vulnerabilities</h4><ul>")
            for pf in protocol_findings:
                issue = pf.get('issue', 'Unknown Issue').upper()
                port = pf.get('port', 'Unknown Port')
                evidence = pf.get('evidence', '')
                html.append(f"<li><span class='badge badge-protocol'>PORT {port}</span> <strong>{issue}</strong>: <i>{evidence}</i></li>")
            html.append("</ul>")
            
        cve_matches = device.get('matches', [])
        if cve_matches:
            html.append("<h4>⚠️ CVE Matches</h4><ul>")
            for cve in cve_matches:
                html.append(f"<li><strong>{cve.get('cve')}</strong> (CVSS {cve.get('cvss')}): {cve.get('desc')}</li>")
            html.append("</ul>")

        html.append("</div>")

    html.append("</body></html>")
    
    with open(outpath, 'w') as f:
        f.write("\n".join(html))
    return outpath

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("infile", help="assessment JSON file")
    p.add_argument("--out-json", default="iot_report.json")
    p.add_argument("--out-html", default="iot_report.html")
    p.add_argument("--out-dir", default="reports")
    args = p.parse_args()

    with open(args.infile) as f:
        data = json.load(f)
    
    assessment = data.get("assessment", [])
    
    # 1. Output JSON
    write_report(assessment, args.out_json)
    print(f"[*] JSON report saved to {args.out_json}")
    
    # 2. Output Heatmap Image
    img_path = plot_heatmap(assessment, args.out_dir)
    print(f"[*] Risk heatmap saved to {img_path}")
    
    # 3. Output HTML Report (incorporating protocol vulnerabilities)
    html_path = write_html_report(assessment, args.out_html, img_path)
    print(f"[*] Beautiful HTML report saved to {html_path}")
