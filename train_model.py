import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import random
import string

# --- 1. Synthetic Data Generation ---
def generate_synthetic_data(n_benign=1000, n_malicious=50):
    data = []
    
    # Generate BENIGN packages (Established, safe)
    for _ in range(n_benign):
        data.append({
            "author_age_days": np.random.randint(365, 3000), # Old accounts
            "num_versions": np.random.randint(5, 100),       # Many releases
            "download_count": np.random.randint(1000, 1000000), # High usage
            "name_entropy": np.random.uniform(1.0, 2.5),     # Normal names like 'requests'
            "is_malicious": 0
        })

    # Generate MALICIOUS packages (The "Supply Chain Attack" profile)
    for _ in range(n_malicious):
        data.append({
            "author_age_days": np.random.randint(0, 30),     # Brand new accounts
            "num_versions": np.random.randint(1, 3),         # 1 or 2 versions
            "download_count": np.random.randint(0, 100),     # No one uses it yet
            "name_entropy": np.random.uniform(3.0, 5.0),     # Random names like 'x8z9q'
            "is_malicious": 1
        })
    
    return pd.DataFrame(data)

print("generating dataset...")
df = generate_synthetic_data()

# --- 2. Training the Model ---
X = df[["author_age_days", "num_versions", "name_entropy"]]
y = df["is_malicious"]

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train Random Forest
print("Training Random Forest Classifier...")
clf = RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=42)
clf.fit(X_train, y_train)

# Evaluate
y_pred = clf.predict(X_test)
print("\nModel Performance Report:")
print(classification_report(y_test, y_pred))

# --- 3. Save the Artifact ---
print("Saving model to 'risk_model.joblib'...")
joblib.dump(clf, "risk_model.joblib")
print("Done.")