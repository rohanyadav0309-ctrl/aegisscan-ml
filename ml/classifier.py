"""
ml/classifier.py - Portable Statistical Classifier
"""
import math

class HybridClassifier:
    """
    Pure-Python statistical classifier conforming to scikit-learn's API (.predict, .predict_proba).
    Guarantees 100% functionality across all platforms and Windows security policies.
    """
    def __init__(self, weights=None, bias=0.0):
        self.weights = weights or []
        self.bias = bias
        self.means = []
        self.stds = []

    def _sigmoid(self, z):
        if z < -25: return 0.0
        if z > 25: return 1.0
        return 1.0 / (1.0 + math.exp(-z))

    def fit(self, X, y, lr=0.03, epochs=50):
        n_features = len(X[0])
        self.weights = [0.0] * n_features
        self.bias = 0.0
        m = len(X)
        
        # Normalize features
        self.means = [sum(X[i][j] for i in range(m)) / m for j in range(n_features)]
        self.stds = [math.sqrt(sum((X[i][j] - self.means[j])**2 for i in range(m)) / m) + 1e-6 for j in range(n_features)]
        
        norm_X = [[(X[i][j] - self.means[j]) / self.stds[j] for j in range(n_features)] for i in range(m)]

        for _ in range(epochs):
            for i in range(m):
                xi = norm_X[i]
                yi = y[i]
                z = sum(w * x for w, x in zip(self.weights, xi)) + self.bias
                pred = self._sigmoid(z)
                err = pred - yi
                for j in range(n_features):
                    self.weights[j] -= lr * err * xi[j]
                self.bias -= lr * err

    def predict_proba(self, X):
        res = []
        n_features = len(self.weights)
        for x in X:
            norm_x = [(x[j] - self.means[j]) / self.stds[j] for j in range(n_features)]
            z = sum(w * val for w, val in zip(self.weights, norm_x)) + self.bias
            p1 = self._sigmoid(z)
            res.append([1.0 - p1, p1])
        return res

    def predict(self, X):
        probs = self.predict_proba(X)
        return [1 if p[1] >= 0.5 else 0 for p in probs]
