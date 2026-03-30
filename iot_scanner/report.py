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
