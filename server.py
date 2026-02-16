from fastmcp import FastMCP, Context, Image
import joblib
import httpx
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import io

# Initialize the FastMCP server
# REMOVED: dependencies=["scikit-learn", "pandas", "joblib", "httpx"]
# Horizon will pick these up automatically from your requirements.txt file.
mcp = FastMCP("SupplyGuard Forensics")

# --- LOAD THE BRAIN ---
# We load the model at the top level so it stays in memory (efficient)
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
    Args:
        package_name: The name of the package (e.g., 'requests', 'pandas')
        ecosystem: The package manager (default: 'PyPI', others: 'npm', 'Maven')
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
        # Return a summarized list of CVEs
        ids = [v['id'] for v in data['vulns']]
        return f"CRITICAL: Found {len(ids)} confirmed vulnerabilities. IDs: {', '.join(ids[:5])}..."
    
    return "CLEAN: No known CVEs found in public databases."

# --- TOOL 2: The ML Predictor ---
@mcp.tool()
def predict_package_risk(package_name: str, author_age_days: int, num_versions: int, download_count: int) -> str:
    """
    Uses the internal Random Forest model to PREDICT if a package is malicious based on metadata.
    Use this when a package has NO known CVEs but looks suspicious (e.g., typosquatting, new author).
    
    Args:
        package_name: Name of the package
        author_age_days: Age of the author's account in days
        num_versions: Total number of versions released
        download_count: Monthly downloads
    """
    if model is None:
        return "Error: ML Model is not loaded on the server."

    # 1. Feature Engineering (Must match training logic exactly!)
    # Simple "Entropy" calculation (randomness of string)
    import math
    from collections import Counter
    
    prob = [float(package_name.count(c)) / len(package_name) for c in dict(Counter(package_name))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])

    # 2. Prepare Feature Vector
    # Order must be: [author_age_days, num_versions, name_entropy]
    features = pd.DataFrame([{
        "author_age_days": author_age_days,
        "num_versions": num_versions,
        "name_entropy": entropy
    }])
    
    # 3. Inference
    prediction = model.predict(features)[0]
    probs = model.predict_proba(features)[0] # [prob_safe, prob_malicious]
    risk_score = probs[1]
    
    # 4. Human-Readable Output
    if risk_score > 0.7:
        return f"HIGH RISK ALERT (Score: {risk_score:.2f}): The ML model predicts this is MALWARE. Indicators: High name entropy ({entropy:.2f}), low reputation."
    elif risk_score > 0.4:
        return f"SUSPICIOUS (Score: {risk_score:.2f}): Review code manually."
    else:
        return f"PASS (Score: {risk_score:.2f}): Model classifies as benign."

# --- TOOL 3: Visualization (Gauge) ---
@mcp.tool()
def visualize_risk_score(risk_score: float) -> Image:
    """
    Generates a visual Gauge Chart (speedometer style) for the risk score.
    Call this when the user asks to 'see' the risk or wants a report.
    Args:
        risk_score: A float between 0.0 (Safe) and 1.0 (Malicious).
    """
    # 1. Setup the plot
    fig, ax = plt.subplots(figsize=(6, 3))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis('off') # Hide axes
    
    # 2. Draw the "Risk Bar" (Green to Red gradient)
    # We cheat a bit for a simple visual: A colored rectangle bar
    gradient = np.linspace(0, 1, 256)
    gradient = np.vstack((gradient, gradient))
    ax.imshow(gradient, aspect='auto', cmap='RdYlGn_r', extent=[0, 1, 0, 0.3])
    
    # 3. Draw the Marker (The "Needle")
    ax.plot([risk_score, risk_score], [0, 0.4], color='black', linewidth=3, marker='v', markersize=10)
    
    # 4. Add Text Labels
    ax.text(0.0, -0.1, "SAFE", fontsize=12, color='green', ha='center')
    ax.text(0.5, -0.1, "SUSPICIOUS", fontsize=12, color='orange', ha='center')
    ax.text(1.0, -0.1, "MALICIOUS", fontsize=12, color='red', ha='center')
    ax.set_title(f"Forensic Risk Assessment: {risk_score:.2f}", fontsize=14, weight='bold')

    # 5. Save to Buffer (In-memory image)
    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight')
    plt.close(fig)
    buf.seek(0)
    
    # 6. Return as FastMCP Image
    return Image(data=buf.read(), format="png")

# --- RESOURCE: Policy Documents ---
@mcp.resource("guidelines://security_policy")
def get_security_policy() -> str:
    """Returns the company's software supply chain security policy."""
    return """
    SECURITY POLICY v2.0:
    1. No packages allowed with Author Age < 30 days.
    2. Any package with 'CRITICAL' CVEs is automatically blocked.
    3. Packages with > 0.7 ML Risk Score require VP approval.
    """