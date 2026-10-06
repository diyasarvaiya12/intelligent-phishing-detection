import os
import sys
import json
import pickle

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from feature_extraction import FEATURE_COLUMNS

# Path configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "..", "data", "phishing_dataset.csv")
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")
METRICS_PATH = os.path.join(BASE_DIR, "model_metrics.json")

print("==================================================")
print(" INTELLIGENT PHISHING DETECTION - MODEL TRAINING  ")
print("==================================================")
print("Features used for training (17 lexical URL features):")
for feat in FEATURE_COLUMNS:
    print(f" - {feat}")

# Check if scikit-learn is available and unblocked by Windows Security
SKLEARN_AVAILABLE = False
try:
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import (
        accuracy_score,
        precision_score,
        recall_score,
        f1_score,
        confusion_matrix
    )
    SKLEARN_AVAILABLE = True
    print("\n[OK] scikit-learn and pandas loaded successfully.")
except Exception as e:
    print(f"\n[Notice] scikit-learn / pandas C-extension unavailable ({e}).")
    print("Running with pure-Python Random Forest engine (bypasses Windows Application Control)...")
    SKLEARN_AVAILABLE = False

if SKLEARN_AVAILABLE:
    # ====================================================
    # PATH A: SCIKIT-LEARN RANDOM FOREST (STANDARD FLOW)
    # ====================================================
    print("\nLoading dataset using pandas...")
    df = pd.read_csv(DATASET_PATH)
    print(f"Dataset loaded: {df.shape[0]} rows, {df.shape[1]} columns")

    X = df[FEATURE_COLUMNS]
    y = df["label"]

    print("\nPerforming 80-20 train-test split (stratified)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    print(f"Training samples: {len(X_train)}")
    print(f"Testing samples : {len(X_test)}")

    print("\nTraining RandomForestClassifier (100 estimators)...")
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)
    print("Model training completed!")

    print("\nEvaluating model on test set...")
    y_pred = model.predict(X_test)

    # Note: In PhiUSIIL dataset, label 1 = Legitimate, label 0 = Phishing.
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    cm = confusion_matrix(y_test, y_pred).tolist()

    engine_name = "scikit-learn RandomForestClassifier"

else:
    # ====================================================
    # PATH B: PURE-PYTHON RANDOM FOREST FALLBACK
    # ====================================================
    import csv
    import random
    from rf_engine import PureRandomForestClassifier

    print("\nLoading dataset using standard library CSV reader...")
    all_X = []
    all_y = []

    with open(DATASET_PATH, mode="r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                features = [float(row[col]) for col in FEATURE_COLUMNS]
                lbl = int(row["label"])
                all_X.append(features)
                all_y.append(lbl)
            except (ValueError, KeyError):
                continue

    total_rows = len(all_X)
    print(f"Dataset loaded: {total_rows} valid rows")

    # Use a representative stratified sample for pure-Python execution speed
    random.seed(42)
    sample_size = min(12000, total_rows)
    print(f"Sampling {sample_size} stratified rows for pure-Python model training...")

    # Stratified sample
    idx_0 = [i for i, y_val in enumerate(all_y) if y_val == 0]
    idx_1 = [i for i, y_val in enumerate(all_y) if y_val == 1]
    n0 = int(sample_size * (len(idx_0) / total_rows))
    n1 = sample_size - n0

    sample_indices = random.sample(idx_0, n0) + random.sample(idx_1, n1)
    random.shuffle(sample_indices)

    sub_X = [all_X[i] for i in sample_indices]
    sub_y = [all_y[i] for i in sample_indices]

    split_idx = int(0.80 * len(sub_X))
    X_train, y_train = sub_X[:split_idx], sub_y[:split_idx]
    X_test, y_test = sub_X[split_idx:], sub_y[split_idx:]

    print(f"Training samples: {len(X_train)}")
    print(f"Testing samples : {len(X_test)}")

    print("\nTraining Pure-Python Random Forest model (15 trees, max_depth=8)...")
    model = PureRandomForestClassifier(n_estimators=15, max_depth=8, random_state=42)
    model.fit(X_train, y_train)
    print("Model training completed!")

    print("\nEvaluating model on test set...")
    y_pred = model.predict(X_test)

    # Compute classification metrics
    n_test = len(y_test)
    tp = sum(1 for yt, yp in zip(y_test, y_pred) if yt == 1 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_test, y_pred) if yt == 0 and yp == 0)
    fp = sum(1 for yt, yp in zip(y_test, y_pred) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_test, y_pred) if yt == 1 and yp == 0)

    acc = (tp + tn) / n_test if n_test > 0 else 0.0
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    cm = [[tn, fp], [fn, tp]]

    engine_name = "Pure-Python Random Forest (Smart App Control Safe)"

# ==========================================
# DISPLAY & SAVE RESULTS
# ==========================================
print("\n========== MODEL EVALUATION RESULTS ==========")
print(f"Engine    : {engine_name}")
print(f"Accuracy  : {acc * 100:.2f}%")
print(f"Precision : {prec * 100:.2f}%")
print(f"Recall    : {rec * 100:.2f}%")
print(f"F1 Score  : {f1 * 100:.2f}%")
print("Confusion Matrix [[TN, FP], [FN, TP]]:")
print(f"  {cm[0]}")
print(f"  {cm[1]}")

metrics_data = {
    "engine": engine_name,
    "accuracy": round(acc, 4),
    "precision": round(prec, 4),
    "recall": round(rec, 4),
    "f1_score": round(f1, 4),
    "confusion_matrix": cm,
    "feature_columns": FEATURE_COLUMNS,
    "label_meanings": {
        "0": "Phishing",
        "1": "Legitimate"
    }
}

with open(METRICS_PATH, "w", encoding="utf-8") as f:
    json.dump(metrics_data, f, indent=4)
print(f"\n[OK] Metrics saved to: {METRICS_PATH}")

with open(MODEL_PATH, "wb") as f:
    pickle.dump(model, f)
print(f"[OK] Trained model saved to: {MODEL_PATH}")
print("\nTraining workflow completed successfully!")