"""Evaluate the experimental local PathProof priority ranker."""

from __future__ import annotations

from typing import Any

from .features import extract_feature_rows, load_dataset, severity_baseline_scores


def _load_sklearn() -> Any:
    try:
        from sklearn.linear_model import LogisticRegression
    except ImportError as exc:
        raise RuntimeError(
            "scikit-learn is required for the ranking prototype; install python/requirements.txt"
        ) from exc
    return LogisticRegression


def train_model(records: list[dict[str, Any]] | None = None) -> Any:
    records = records if records is not None else load_dataset()
    _, rows, labels = extract_feature_rows(records)
    LogisticRegression = _load_sklearn()
    model = LogisticRegression(random_state=0, solver="liblinear", max_iter=200)
    model.fit(rows, labels)
    return model


def learned_scores(model: Any, records: list[dict[str, Any]]) -> list[float]:
    _, rows, _ = extract_feature_rows(records)
    probabilities = model.predict_proba(rows)
    classes = list(model.classes_)
    positive_index = classes.index(1)
    return [float(row[positive_index]) for row in probabilities]


def evaluate_dataset(records: list[dict[str, Any]] | None = None) -> dict[str, float | int]:
    records = records if records is not None else load_dataset()
    _, rows, labels = extract_feature_rows(records)
    model = train_model(records)
    learned = learned_scores(model, records)
    severity = [float(score) for score in severity_baseline_scores(records)]
    positive_count = sum(labels)
    return {
        "records": len(records),
        "features": len(rows[0]) if rows else 0,
        "positive_labels": positive_count,
        "learned_top_k_recall": _top_k_recall(learned, labels, positive_count),
        "severity_top_k_recall": _top_k_recall(severity, labels, positive_count),
        "learned_pairwise_accuracy": _pairwise_accuracy(learned, labels),
    }


def _top_k_recall(scores: list[float], labels: list[int], k: int) -> float:
    if k <= 0:
        return 0.0
    ranked = sorted(range(len(scores)), key=lambda index: (-scores[index], index))
    found = sum(labels[index] for index in ranked[:k])
    return round(found / k, 3)


def _pairwise_accuracy(scores: list[float], labels: list[int]) -> float:
    total = 0
    correct = 0.0
    for left in range(len(labels)):
        for right in range(left + 1, len(labels)):
            if labels[left] == labels[right]:
                continue
            total += 1
            higher = left if labels[left] > labels[right] else right
            lower = right if higher == left else left
            if scores[higher] > scores[lower]:
                correct += 1
            elif scores[higher] == scores[lower]:
                correct += 0.5
    if total == 0:
        return 0.0
    return round(correct / total, 3)


def main() -> int:
    try:
        metrics = evaluate_dataset()
    except RuntimeError as exc:
        print(str(exc))
        return 2
    print("PathProof experimental ranking evaluation")
    for key in sorted(metrics):
        print(f"{key}: {metrics[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
