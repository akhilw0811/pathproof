"""Train the experimental local PathProof priority ranker."""

from __future__ import annotations

from .evaluate import train_model
from .features import FEATURE_NAMES, extract_feature_rows, load_dataset


def main() -> int:
    records = load_dataset()
    _, rows, labels = extract_feature_rows(records)
    try:
        model = train_model(records)
    except RuntimeError as exc:
        print(str(exc))
        return 2
    accuracy = round(float(model.score(rows, labels)), 3)
    print("PathProof experimental scikit-learn ranker")
    print(f"model: LogisticRegression")
    print(f"records: {len(records)}")
    print(f"features: {len(FEATURE_NAMES)}")
    print(f"positive_priority_labels: {sum(labels)}")
    print(f"training_accuracy: {accuracy}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
