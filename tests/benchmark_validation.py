"""
tests/benchmark_validation.py - Model Performance Benchmark & Metric Report
"""
import os
import sys
import pickle
import pandas as pd
import numpy as np

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.features import HTTPFeatureExtractor

def evaluate_performance(test_csv="data/raw/http_corpus.csv", model_path="ml/model.pkl"):
    if not os.path.exists(test_csv):
        raise FileNotFoundError(f"Dataset not found at {test_csv}. Run ml/bootstrap_dataset.py first.")
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model not found at {model_path}. Run ml/train.py first.")

    df = pd.read_csv(test_csv)
    
    try:
        import joblib
        model = joblib.load(model_path)
    except Exception:
        with open(model_path, "rb") as f:
            model = pickle.load(f)

    extractor = HTTPFeatureExtractor()

    X = []
    y_true = df["label"].values

    for _, row in df.iterrows():
        features = extractor.extract(
            payload=str(row["raw_query"]),
            status_code=int(row["status_code"]),
            response_body=str(row["response_body_sample"])
        )
        X.append(features.tolist() if hasattr(features, "tolist") else list(features))

    feat_input = np.array(X) if hasattr(np, "array") else X
    y_pred = model.predict(feat_input)
    probs = model.predict_proba(feat_input)
    y_probs = [p[1] for p in probs]

    # Calculate metrics
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    print("\n" + "=" * 50)
    print("      AEGISSCAN-ML BENCHMARK VALIDATION")
    print("=" * 50)
    print(f"Confusion Matrix:")
    print(f"  True Negatives (TN):  {tn:>5}  | False Positives (FP): {fp:>5}")
    print(f"  False Negatives (FN): {fn:>5}  | True Positives (TP):  {tp:>5}")
    print("-" * 50)
    print(f"Precision: {precision * 100:.2f}%  (Low FP rate)")
    print(f"Recall:    {recall * 100:.2f}%  (High exploit detection)")
    print(f"F1-Score:  {f1 * 100:.2f}%")
    print("=" * 50 + "\n")

if __name__ == "__main__":
    evaluate_performance()
