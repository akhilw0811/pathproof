# PathProof Ranking Prototype

This is an experimental local scikit-learn priority ranker for already
verified PathProof findings.

The fixture labels represent local prioritization examples only. They are not
vulnerability truth, and they do not replace PathProof's deterministic Go
rules, graph evidence, finding IDs, severities, or SARIF output.

Run from the `python/` directory after installing optional dependencies:

```sh
python -m pip install -r requirements.txt
python -m pathproof_ranking.train_ranker
python -m pathproof_ranking.evaluate
```

The prototype reads only structured PathProof-style JSON fields. It does not
parse raw Kubernetes manifests, GitHub Actions workflows, Terraform files,
policy JSON, source evidence prose, secrets, tokens, credentials, or absolute
machine paths.
