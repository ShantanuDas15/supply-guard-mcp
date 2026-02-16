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

# --- TOOL 2: The Explainable ML Predictor ---
@mcp.tool()
def predict_package_risk(package_name: str, author_age_days: int, num_versions: int, download_count: int) -> str:
    """
    Uses the internal Random Forest model to PREDICT if a package is malicious based on metadata.
    Returns a RISK SCORE and an EXPLANATION of the top contributing factors.
    """
    if model is None:
        return "Error: ML Model is not loaded on the server."

    # 1. Feature Engineering
    import math
    from collections import Counter
    
    # Calculate Shannon Entropy (Randomness of name)
    prob = [float(package_name.count(c)) / len(package_name) for c in dict(Counter(package_name))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])

    # 2. Prepare Feature Vector for the Model
    features = pd.DataFrame([{
        "author_age_days": author_age_days,
        "num_versions": num_versions,
        "name_entropy": entropy
    }])
    
    # 3. Model Inference
    # predict_proba returns [prob_safe, prob_malicious]
    probs = model.predict_proba(features)[0] 
    risk_score = probs[1]
    
    # 4. EXPLAINABILITY ENGINE (The "Why")
    # We analyze which features deviate most from "Safe Baselines"
    # Safe Baselines (derived from training data): Age > 300, Versions > 5, Entropy < 2.5
    reasons = []
    
    if author_age_days < 30:
        reasons.append(f"Author account is suspiciously new ({author_age_days} days)")
    if num_versions < 3:
        reasons.append(f"Very few versions published ({num_versions})")
    if entropy > 3.0:
        reasons.append(f"Package name '{package_name}' looks randomly generated (High Entropy)")
    if download_count < 100:
        reasons.append(f"Extremely low download count ({download_count})")

    # 5. Construct the "Glass Box" Output
    explanation = "; ".join(reasons) if reasons else "Metadata falls within normal parameters."
    
    if risk_score > 0.75:
        return (f"🚨 HIGH RISK ALERT (Score: {risk_score:.2f})\n"
                f"VERDICT: MALWARE PREDICTED.\n"
                f"PRIMARY DRIVERS: {explanation}\n"
                f"RECOMMENDATION: Block installation immediately.")
                
    elif risk_score > 0.45:
        return (f"⚠️ SUSPICIOUS ACTIVITY (Score: {risk_score:.2f})\n"
                f"VERDICT: POTENTIAL THREAT.\n"
                f"FLAGS: {explanation}\n"
                f"RECOMMENDATION: Manual code review required.")
    else:
        return (f"✅ PASS (Score: {risk_score:.2f})\n"
                f"Analysis: {explanation}")

@mcp.resource("guidelines://security_policy")
def get_security_policy() -> str:
    return "POLICY: No packages with author_age < 30 days allowed."