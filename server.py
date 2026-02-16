from fastmcp import FastMCP, Context
import joblib
import httpx
import numpy as np
import pandas as pd

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

# --- TOOL 1: The Fact Checker ---
@mcp.tool()
async def check_known_vulnerabilities(package_name: str, ecosystem: str = "PyPI") -> str:
    """
    Queries the OSV (Open Source Vulnerability) database for CONFIRMED vulnerabilities (CVEs).
    Use this FIRST to check if a package has known security issues.
    """
    url = "https://api.osv.dev/v1/query"
    payload = {"package": {"name": package_name, "ecosystem": ecosystem}}
    
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(url, json=payload, timeout=5.0)
            data = resp.json()
        except Exception as e:
            return f"API Error: Could not connect to OSV database. {str(e)}"
    
    if "vulns" in data:
        ids = [v['id'] for v in data['vulns']]
        return f"CRITICAL: Found {len(ids)} confirmed vulnerabilities. IDs: {', '.join(ids[:5])}..."
    
    return "CLEAN: No known CVEs found in public databases."

# --- TOOL 2: The ML Predictor ---
@mcp.tool()
def predict_package_risk(package_name: str, author_age_days: int, num_versions: int, download_count: int) -> str:
    """
    Uses the internal Random Forest model to PREDICT if a package is malicious based on metadata.
    Use this when a package has NO known CVEs but looks suspicious.
    """
    if model is None:
        return "Error: ML Model is not loaded on the server."

    # 1. Feature Engineering
    import math
    from collections import Counter
    
    prob = [float(package_name.count(c)) / len(package_name) for c in dict(Counter(package_name))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])

    # 2. Prepare Feature Vector
    features = pd.DataFrame([{
        "author_age_days": author_age_days,
        "num_versions": num_versions,
        "name_entropy": entropy
    }])
    
    # 3. Inference
    # predict_proba returns [prob_safe, prob_malicious]
    probs = model.predict_proba(features)[0] 
    risk_score = probs[1]
    
    # 4. Human-Readable Output
    if risk_score > 0.7:
        return f"HIGH RISK ALERT (Score: {risk_score:.2f}): The ML model predicts this is MALWARE. Indicators: High name entropy ({entropy:.2f}), low reputation."
    elif risk_score > 0.4:
        return f"SUSPICIOUS (Score: {risk_score:.2f}): Review code manually."
    else:
        return f"PASS (Score: {risk_score:.2f}): Model classifies as benign."

@mcp.resource("guidelines://security_policy")
def get_security_policy() -> str:
    return "POLICY: No packages with author_age < 30 days allowed."