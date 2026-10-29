"""
ml/train.py - Model Training and Evaluation Pipeline
"""
import os
import sys
import pickle
import pandas as pd

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.features import HTTPFeatureExtractor
from ml.classifier import HybridClassifier

def train_model(data_path="data/raw/http_corpus.csv", model_output="ml/model.pkl"):
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Dataset not found at {data_path}. Run ml/bootstrap_dataset.py first.")

    df = pd.read_csv(data_path)
    extractor = HTTPFeatureExtractor()
    
    X = []
    y = df["label"].values
    
    print("[*] Extracting features from dataset...")
    for _, row in df.iterrows():
        features = extractor.extract(
            payload=str(row["raw_query"]),
            status_code=int(row["status_code"]),
            response_body=str(row["response_body_sample"])
        )
        X.append(features.tolist() if hasattr(features, "tolist") else list(features))
        
    split_idx = int(len(X) * 0.8)
    X_train, X_test = X[:split_idx], X[split_idx:]
    y_train, y_test = y[:split_idx], y[split_idx:]
    
    use_sklearn = False
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import classification_report, accuracy_score
        use_sklearn = True
    except Exception:
        use_sklearn = False

    if use_sklearn:
        print("[*] Training Scikit-Learn RandomForestClassifier...")
        model = RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42)
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        print(f"\n[+] Model Accuracy: {acc * 100:.2f}%")
        print("\nDetailed Performance Report:")
        print(classification_report(y_test, y_pred, target_names=["Benign", "Attack/Exploit"]))
    else:
        print("[*] Training Hybrid Feature Logistic Ensemble (Pure Python & Policy Safe)...")
        model = HybridClassifier()
        model.fit(X_train, y_train, epochs=50)
        y_pred = model.predict(X_test)
        correct = sum(1 for yt, yp in zip(y_test, y_pred) if yt == yp)
        acc = correct / len(y_test)
        print(f"\n[+] Model Accuracy: {acc * 100:.2f}%")
        print(f"    - Evaluated Test Samples: {len(y_test)}")
        print(f"    - Correct Predictions:   {correct}")
    
    os.makedirs(os.path.dirname(model_output), exist_ok=True)
    with open(model_output, "wb") as f:
        pickle.dump(model, f)
    print(f"[+] Serialized model saved to {model_output}")

if __name__ == "__main__":
    train_model()
