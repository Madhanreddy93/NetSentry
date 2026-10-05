"""Train and apply behavior-based anomaly models using normal traffic only."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

from .features import model_matrix
from .simulator import generate_traffic

DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[1] / "models" / "netsentry.joblib"
DEFAULT_METRICS_PATH = Path(__file__).resolve().parents[1] / "data" / "metrics.json"
MODEL_TYPES = ("Isolation Forest", "One-Class SVM")
DEFAULT_SENSITIVITY = 0.01


class AnomalyDetector:
    """Scaler plus an unsupervised estimator and normal-score threshold."""

    def __init__(self, model_type: str = "Isolation Forest", sensitivity: float = DEFAULT_SENSITIVITY) -> None:
        if model_type not in MODEL_TYPES:
            raise ValueError(f"model_type must be one of {MODEL_TYPES}")
        self.model_type = model_type
        self.sensitivity = float(np.clip(sensitivity, 0.01, 0.20))
        estimator = IsolationForest(n_estimators=160, contamination="auto", random_state=42, n_jobs=-1) if model_type == "Isolation Forest" else OneClassSVM(kernel="rbf", gamma="scale", nu=0.05)
        self.pipeline: Pipeline = Pipeline([("scaler", StandardScaler()), ("detector", estimator)])
        self.threshold = 0.0
        self._is_fitted = False

    def fit(self, normal_features: pd.DataFrame) -> "AnomalyDetector":
        matrix = model_matrix(normal_features)
        if len(matrix) < 10:
            raise ValueError("At least 10 normal feature windows are required to train")
        self._training_matrix = matrix.copy()
        self.pipeline.fit(matrix)
        normal_scores = self._score_matrix(matrix)
        self.threshold = float(np.quantile(normal_scores, 1.0 - self.sensitivity))
        self._is_fitted = True
        return self

    def _score_matrix(self, matrix: pd.DataFrame) -> np.ndarray:
        estimator: Any = self.pipeline.named_steps["detector"]
        scaled = self.pipeline.named_steps["scaler"].transform(matrix)
        if hasattr(estimator, "decision_function"):
            return -np.asarray(estimator.decision_function(scaled), dtype=float).reshape(-1)
        return -np.asarray(estimator.score_samples(scaled), dtype=float).reshape(-1)

    def predict(self, features: pd.DataFrame, sensitivity: float | None = None) -> pd.DataFrame:
        if not self._is_fitted:
            raise RuntimeError("Train or load the detector before prediction")
        chosen = float(np.clip(sensitivity if sensitivity is not None else self.sensitivity, 0.01, 0.20))
        matrix = model_matrix(features)
        scores = self._score_matrix(matrix)
        # The threshold is recalibrated against scores from the normal training set.
        training_scores = self._score_matrix(self._training_matrix)
        threshold = float(np.quantile(training_scores, 1.0 - chosen))
        return pd.DataFrame({"anomaly_score": scores, "threshold": threshold, "is_anomaly": scores > threshold}, index=features.index)

    def save(self, path: str | Path = DEFAULT_MODEL_PATH) -> None:
        if not self._is_fitted:
            raise RuntimeError("Cannot save an untrained detector")
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"detector": self, "training_matrix": self._training_matrix}, destination)

    @classmethod
    def load(cls, path: str | Path = DEFAULT_MODEL_PATH) -> "AnomalyDetector":
        stored = joblib.load(path)
        detector: cls = stored["detector"]
        detector._training_matrix = stored["training_matrix"]
        detector._is_fitted = True
        return detector


def train_default_model(
    model_type: str = "Isolation Forest",
    sensitivity: float = DEFAULT_SENSITIVITY,
    duration_seconds: int = 300,
    path: str | Path = DEFAULT_MODEL_PATH,
) -> AnomalyDetector:
    """Fit on synthetic normal windows only and persist the resulting model."""
    from .features import extract_features

    normal_packets = generate_traffic(duration_seconds, "normal", seed=91)
    normal_features = extract_features(normal_packets)
    detector = AnomalyDetector(model_type, sensitivity)
    detector._training_matrix = model_matrix(normal_features)
    detector.fit(normal_features)
    detector.save(path)
    return detector


def evaluate_model(
    detector: AnomalyDetector,
    metrics_path: str | Path = DEFAULT_METRICS_PATH,
    sensitivity: float = DEFAULT_SENSITIVITY,
) -> dict[str, Any]:
    """Evaluate on mixed synthetic traffic and persist readable metrics JSON."""
    from .features import extract_features

    mixed = extract_features(generate_traffic(60, "mixed", seed=181))
    predictions = detector.predict(mixed, sensitivity)
    truth = mixed["ground_truth_attack"].astype(bool).to_numpy()
    predicted = predictions["is_anomaly"].to_numpy(dtype=bool)
    tn, fp, fn, tp = confusion_matrix(truth, predicted, labels=[False, True]).ravel()
    metrics = {
        "precision": float(precision_score(truth, predicted, zero_division=0)),
        "recall": float(recall_score(truth, predicted, zero_division=0)),
        "f1": float(f1_score(truth, predicted, zero_division=0)),
        "false_positive_rate": float(fp / max(fp + tn, 1)),
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
        "labels": ["Normal", "Attack"],
        "evaluated_windows": int(len(mixed)),
        "model": detector.model_type,
        "sensitivity": sensitivity,
    }
    target = Path(metrics_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


def load_or_train(path: str | Path = DEFAULT_MODEL_PATH) -> AnomalyDetector:
    """Load the saved model, or automatically train a normal-only model."""
    try:
        return AnomalyDetector.load(path)
    except (FileNotFoundError, EOFError, KeyError, ValueError):
        return train_default_model(path=path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Train and evaluate NetSentry's simulation-only detector")
    parser.add_argument("--train", action="store_true", help="Train the model on normal synthetic traffic")
    parser.add_argument("--evaluate", action="store_true", help="Evaluate on labeled mixed synthetic traffic")
    args = parser.parse_args()
    detector = train_default_model() if args.train else load_or_train()
    if args.evaluate:
        metrics = evaluate_model(detector)
        print(json.dumps(metrics, indent=2))
    elif not args.train:
        print(f"Model ready: {detector.model_type}")


if __name__ == "__main__":
    main()