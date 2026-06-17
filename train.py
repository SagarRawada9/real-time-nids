import os, warnings
warnings.filterwarnings("ignore")

import pandas as pd, numpy as np, joblib, seaborn as sns, matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from lightgbm import LGBMClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
from imblearn.over_sampling import SMOTE

# --- PATHS ---
DATA_PATH = "data/CICIDS2017_sample.csv"
MODEL_DIR, RESULTS_DIR = "models", "results"
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

# --- TOP FEATURES ---
TOP_FEATURES = [
    'Bwd Packet Length Std','Init_Win_bytes_forward','average_packet_size',
    'Packet Length Variance','bwd_packet_length_mean','Packet Length Std',
    'Avg Bwd Segment Size','Bwd Packets/s','Init_Win_bytes_backward',
    'Bwd Packet Length Max','Packet Length Mean','Max Packet Length',
    'Subflow Bwd Bytes','Fwd Header Length','fwd_packet_length_mean'
]

# --- LOAD DATASET ---
print(f"Loading {DATA_PATH}")
df = pd.read_csv(DATA_PATH)
df.columns = df.columns.str.strip()
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.fillna(df.median(numeric_only=True), inplace=True)

df['Label'] = df['Label'].astype(str).str.strip().replace({
    'BENIGN':'Normal','DoS':'DoS','PortScan':'PortScan',
    'BruteForce':'BruteForce','WebAttack':'WebAttack',
    'Bot':'Bot','Infiltration':'Infiltration'
})

X = df[[f for f in TOP_FEATURES if f in df.columns]]
y = df['Label']

# --- CORRELATION HEATMAP ---
plt.figure(figsize=(11,9))
sns.heatmap(X.corr(), cmap="coolwarm", annot=False, linewidths=0.3)
plt.title("Feature Correlation Heatmap", fontsize=14)
plt.tight_layout()
plt.savefig(os.path.join(RESULTS_DIR, "feature_correlation.png"))
plt.close()
print("Saved feature correlation heatmap.")

# --- ENCODE & SCALE ---
le, sc = LabelEncoder(), StandardScaler()
y_enc = le.fit_transform(y)
X_scaled = sc.fit_transform(X)
joblib.dump(le, f"{MODEL_DIR}/label_encoder.pkl")
joblib.dump(sc, f"{MODEL_DIR}/scaler.pkl")

# --- SPLIT & BALANCE ---
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y_enc, test_size=0.2, stratify=y_enc)
X_train, y_train = SMOTE(random_state=42).fit_resample(X_train, y_train)

# --- MODELS ---
models = {
    "RandomForest": RandomForestClassifier(n_estimators=250, n_jobs=-1, random_state=42, class_weight='balanced'),
    "LightGBM": LGBMClassifier(n_estimators=300, learning_rate=0.1, max_depth=-1, class_weight='balanced', random_state=42),
    "LogisticRegression": LogisticRegression(max_iter=1000, class_weight='balanced', n_jobs=-1)
}

results = []

for name, model in models.items():
    print(f"\n Training {name}...")
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average='weighted')
    rec  = recall_score(y_test, y_pred, average='weighted')
    f1   = f1_score(y_test, y_pred, average='weighted')

    results.append([name, acc, prec, rec, f1])
    print(f"{name} Metrics:")
    print(classification_report(y_test, y_pred, target_names=le.classes_))

    # --- Confusion Matrix ---
    plt.figure(figsize=(7,6))
    cm = confusion_matrix(y_test, y_pred)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=le.classes_, yticklabels=le.classes_)
    plt.title(f"{name} Confusion Matrix", fontsize=13)
    plt.xlabel("Predicted"); plt.ylabel("Actual")
    plt.tight_layout()
    plt.savefig(os.path.join(RESULTS_DIR, f"{name}_confusion.png"))
    plt.close()

# --- COMPARISON ---
df_res = pd.DataFrame(results, columns=["Model","Accuracy","Precision","Recall","F1"])
df_res.sort_values("Accuracy", ascending=False, inplace=True)
print("\n Model Comparison Summary:")
print(df_res.to_string(index=False))

# --- BAR CHART (Accuracy-based) ---
plt.figure(figsize=(8,5))
sns.barplot(x="Model", y="Accuracy", data=df_res, palette="viridis")
plt.title("Model Comparison (Accuracy)", fontsize=13)
plt.tight_layout()
plt.savefig(os.path.join(RESULTS_DIR, "model_comparison.png"))
plt.close()

# --- SAVE BEST MODEL (Accuracy-based) ---
best = df_res.iloc[0]
best_model = models[best["Model"]]
joblib.dump(best_model, f"{MODEL_DIR}/rf_final.pkl")
print(f"\n Best Model: {best['Model']} (Accuracy={best['Accuracy']:.4f}) saved as models/rf_final.pkl")
print("All confusion matrices and comparison graph saved in /results/")
