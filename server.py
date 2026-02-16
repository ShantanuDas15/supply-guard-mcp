from fastmcp import FastMCP
import joblib
import requests
import requests.packages.urllib3.util.connection as urllib3_cn
import socket
from fpdf import FPDF
import pandas as pd
import numpy as np
import math
from collections import Counter

# --- SENIOR DEV FIX: FORCE IPv4 ---
# This prevents "Address family not supported" errors in containers that disable IPv6
def allowed_gai_family():
    return socket.AF_INET

urllib3_cn.allowed_gai_family = allowed_gai_family

# Initialize the FastMCP server
mcp = FastMCP("SupplyGuard Forensics")

# --- LOAD THE BRAIN ---
try:
    print("Loading forensic model...")
    model = joblib.load("risk_model.joblib")
    print("Model loaded successfully.")
except Exception as e:
    print(f"WARNING: Model could not load. Prediction tool will fail. Error: {e}")
    model = None

# --- TOOL 1: Fact Checker ---
@mcp.tool()
def check_known_vulnerabilities(package_name: str, ecosystem: str = "PyPI") -> str:
    """Queries OSV database for known CVEs."""
    url = "https://api.osv.dev/v1/query"
    payload = {"package": {"name": package_name, "ecosystem": ecosystem}}
    try:
        resp = requests.post(url, json=payload, timeout=5)
        data = resp.json()
        if "vulns" in data:
            ids = [v['id'] for v in data['vulns']]
            return f"CRITICAL: Found {len(ids)} vulnerabilities: {', '.join(ids[:3])}..."
        return "CLEAN: No known CVEs found."
    except Exception as e:
        return f"API Error: {str(e)}"

# --- TOOL 2: Explainable ML Predictor ---
@mcp.tool()
def predict_package_risk(package_name: str, author_age_days: int, num_versions: int, download_count: int) -> str:
    """Predicts malware risk using Random Forest model."""
    if model is None: return "Error: Model not loaded."

    # Feature Engineering
    prob = [float(package_name.count(c)) / len(package_name) for c in dict(Counter(package_name))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])

    features = pd.DataFrame([{
        "author_age_days": author_age_days,
        "num_versions": num_versions,
        "name_entropy": entropy
    }])
    
    probs = model.predict_proba(features)[0]
    risk_score = probs[1]
    
    # Explainability
    reasons = []
    if author_age_days < 30: reasons.append(f"New author account ({author_age_days} days)")
    if num_versions < 3: reasons.append(f"Low version count ({num_versions})")
    if entropy > 3.0: reasons.append("High-entropy (random) package name")
    
    explanation = "; ".join(reasons) if reasons else "Normal metadata."
    
    if risk_score > 0.7:
        return (f"🚨 HIGH RISK (Score: {risk_score:.2f})\nVERDICT: MALWARE PREDICTED\n"
                f"DRIVERS: {explanation}\nRECOMMENDATION: Block.")
    return f"PASS (Score: {risk_score:.2f}). {explanation}"

@mcp.tool()
def generate_audit_report(package_name: str, risk_score: float, author_age: int, explanation: str) -> str:
    """Generates PDF and uploads to tmpfiles.org (IPv4 forced)."""
    try:
        # 1. Generate PDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("helvetica", style="B", size=20)
        pdf.cell(0, 10, "SupplyGuard Audit Report", new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.ln(10)
        
        pdf.set_font("helvetica", size=12)
        pdf.cell(0, 10, f"Package: {package_name}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 10, f"Risk Score: {risk_score:.2f}", new_x="LMARGIN", new_y="NEXT")
        
        pdf.set_font("helvetica", style="I", size=10)
        safe_expl = explanation.encode('latin-1', 'replace').decode('latin-1')
        pdf.multi_cell(0, 10, f"Details: {safe_expl}")
        
        pdf_bytes = pdf.output()

        # 2. Upload (Using requests with IPv4 forced)
        # We use tmpfiles.org API which is very reliable
        url = "https://tmpfiles.org/api/v1/upload"
        files = {'file': (f"{package_name}_audit.pdf", pdf_bytes)}
        
        resp = requests.post(url, files=files, timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            # tmpfiles returns a URL like https://tmpfiles.org/12345/file.pdf
            # We need to format it to be clickable/downloadable
            raw_url = data['data']['url']
            # User friendly message
            return f"📄 **Report Ready**\nDownload here: {raw_url}"
        else:
            return f"Upload failed: {resp.status_code}"

    except Exception as e:
        return f"System Error: {str(e)}"

@mcp.resource("guidelines://security_policy")
def get_security_policy() -> str:
    return "POLICY: No packages with author_age < 30 days allowed."