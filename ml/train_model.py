"""Train and evaluate the Random Forest intrusion detector.

* Features come from ``services/ebpf-agent/ids_agent/features.py`` -- the
  same code the live agent runs, so train/serve skew is impossible.
* The model is a multi-class Random Forest (benign + 9 attack categories).
  P(malicious) = 1 - P(benign) drives detection; the arg-max attack class
  drives the MITRE mapping of alerts.
* Evaluation Module (offline part): stratified hold-out, unseen-template
  generalisation, 5-fold CV, edge-case subset, per-category recall,
  inference latency and an Isolation-Forest baseline (the v0 approach).

Outputs:
    ml/model/ids_model.joblib   model bundle loaded by the agent
    ml/model/evaluation.json    metrics shown on the dashboard

Usage:  python ml/train_model.py [--data ml/training_data.csv]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score, recall_score,
                             roc_auc_score)
from sklearn.model_selection import StratifiedKFold, train_test_split

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "services", "ebpf-agent"))
from ids_agent.features import FEATURE_NAMES, extract  # noqa: E402

WIN_COLS = ["win_exec_count", "win_distinct_bins", "win_connect_count", "win_distinct_dst",
            "win_sensitive_opens", "win_shell_count", "win_new_binary"]
THRESHOLD = 0.5
RF_PARAMS = dict(n_estimators=150, max_depth=22, min_samples_leaf=1, max_features="sqrt",
                 class_weight=None, random_state=42, n_jobs=-1)  # see JOURNAL: balanced weights -> 4.6% FPR


def build_matrix(df: pd.DataFrame) -> np.ndarray:
    rows = []
    for r in df.to_dict("records"):
        ev = {k: ("" if (isinstance(v, float) and np.isnan(v)) else v) for k, v in r.items()}
        rows.append(extract(ev, {k: r[k] for k in WIN_COLS}))
    return np.asarray(rows, dtype=np.float32)


def binary_metrics(y_true, p_mal, threshold=THRESHOLD) -> dict:
    y_pred = (p_mal >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    out = {
        "samples": int(len(y_true)),
        "detection_rate": round(tp / (tp + fn), 4) if tp + fn else None,
        "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else None,
        "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_true, y_pred, zero_division=0), 4),
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }
    if len(set(y_true)) == 2:
        out["roc_auc"] = round(roc_auc_score(y_true, p_mal), 4)
    return out


def p_malicious(model, X) -> np.ndarray:
    benign_idx = list(model.classes_).index("benign")
    return 1.0 - model.predict_proba(X)[:, benign_idx]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=os.path.join(HERE, "training_data.csv"))
    ap.add_argument("--out", default=os.path.join(HERE, "model"))
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    print(f"Loading {a.data}")
    df = pd.read_csv(a.data, keep_default_na=False)
    t0 = time.time()
    X = build_matrix(df)
    y_cat = df["attack_category"].to_numpy()
    y_bin = df["is_malicious"].to_numpy().astype(int)
    print(f"  {len(df)} rows, {X.shape[1]} features extracted in {time.time() - t0:.1f}s")

    report: dict = {"generated_at": datetime.now(timezone.utc).isoformat(), "model": "RandomForestClassifier",
                    "sklearn_version": sklearn.__version__, "params": {k: v for k, v in RF_PARAMS.items() if k != "n_jobs"},
                    "threshold": THRESHOLD, "dataset": {
                        "rows": int(len(df)), "malicious": int(y_bin.sum()), "benign": int((1 - y_bin).sum()),
                        "edge_case_rows": int(df["is_edge_case"].sum()), "templates": int(df["template"].nunique()),
                        "features": len(FEATURE_NAMES),
                        "categories": {k: int(v) for k, v in df["attack_category"].value_counts().items()}}}

    # ---- 1. stratified hold-out --------------------------------------------------------
    idx_tr, idx_te = train_test_split(np.arange(len(df)), test_size=0.2, stratify=y_cat, random_state=42)
    rf = RandomForestClassifier(**RF_PARAMS).fit(X[idx_tr], y_cat[idx_tr])
    pm = p_malicious(rf, X[idx_te])
    report["holdout"] = binary_metrics(y_bin[idx_te], pm)

    pred_cat = rf.predict(X[idx_te])
    per_cat = {}
    for c in sorted(set(y_cat)):
        m = y_cat[idx_te] == c
        if c == "benign":
            per_cat[c] = {"samples": int(m.sum()), "correct_rate": round(float((pm[m] < THRESHOLD).mean()), 4)}
        else:
            per_cat[c] = {"samples": int(m.sum()), "detection_rate": round(float((pm[m] >= THRESHOLD).mean()), 4),
                          "category_accuracy": round(float((pred_cat[m] == c).mean()), 4)}
    report["per_category"] = per_cat

    edge = df["is_edge_case"].to_numpy()[idx_te] == 1
    report["edge_cases"] = binary_metrics(y_bin[idx_te][edge], pm[edge])
    report["non_edge_cases"] = binary_metrics(y_bin[idx_te][~edge], pm[~edge])

    per_tpl = {}
    tpl_te = df["template"].to_numpy()[idx_te]
    for t in sorted(set(tpl_te)):
        m = tpl_te == t
        lab = int(y_bin[idx_te][m][0])
        rate = float((pm[m] >= THRESHOLD).mean())
        per_tpl[t] = {"label": "malicious" if lab else "benign", "samples": int(m.sum()),
                      "flagged_rate": round(rate, 4)}
    report["per_template"] = per_tpl

    # ---- 2. unseen templates: hold out whole template families ----------------------
    rng = np.random.RandomState(1)
    tpls = df[["template", "is_malicious"]].drop_duplicates()
    held = []
    for lab in (0, 1):
        names = tpls[tpls.is_malicious == lab]["template"].tolist()
        held += list(rng.choice(names, size=max(2, len(names) // 5), replace=False))
    m_held = df["template"].isin(held).to_numpy()
    rf_u = RandomForestClassifier(**RF_PARAMS).fit(X[~m_held], y_cat[~m_held])
    report["unseen_templates"] = binary_metrics(y_bin[m_held], p_malicious(rf_u, X[m_held]))
    report["unseen_templates"]["held_out_templates"] = sorted(held)

    # ---- 3. 5-fold CV --------------------------------------------------------------------
    f1s, dets, fprs = [], [], []
    for tr, te in StratifiedKFold(5, shuffle=True, random_state=0).split(X, y_cat):
        m = RandomForestClassifier(**RF_PARAMS).fit(X[tr], y_cat[tr])
        bm = binary_metrics(y_bin[te], p_malicious(m, X[te]))
        f1s.append(bm["f1"]); dets.append(bm["detection_rate"]); fprs.append(bm["false_positive_rate"])  # noqa: E702
    report["cross_validation"] = {"folds": 5, "f1_mean": round(float(np.mean(f1s)), 4), "f1_std": round(float(np.std(f1s)), 4),
                                  "detection_rate_mean": round(float(np.mean(dets)), 4),
                                  "false_positive_rate_mean": round(float(np.mean(fprs)), 4)}

    # ---- 4. baseline: unsupervised Isolation Forest (v0 approach) on benign data ------
    iso = IsolationForest(n_estimators=150, contamination=0.01, random_state=42)
    benign_tr = idx_tr[y_bin[idx_tr] == 0]
    iso.fit(X[benign_tr])
    iso_score = -iso.score_samples(X[idx_te])
    iso_thr = np.quantile(-iso.score_samples(X[benign_tr]), 0.99)
    report["baseline_isolation_forest"] = binary_metrics(y_bin[idx_te], (iso_score >= iso_thr).astype(float))

    # ---- 5. final model on all data + latency ---------------------------------------
    final = RandomForestClassifier(**RF_PARAMS).fit(X, y_cat)
    final.n_jobs = 1  # inference in the agent is single-threaded
    one = X[:1]
    final.predict_proba(one)
    t0 = time.perf_counter()
    for _ in range(200):
        final.predict_proba(one)
    single_ms = (time.perf_counter() - t0) / 200 * 1000
    batch = X[:256]
    t0 = time.perf_counter()
    for _ in range(20):
        final.predict_proba(batch)
    batch_ms = (time.perf_counter() - t0) / 20 / len(batch) * 1000
    report["inference_latency_ms"] = {"single_event": round(single_ms, 3), "per_event_in_batch_of_256": round(batch_ms, 4)}

    imp = sorted(zip(FEATURE_NAMES, final.feature_importances_), key=lambda x: -x[1])
    report["feature_importance"] = [{"feature": f, "importance": round(float(v), 4)} for f, v in imp[:25]]
    report["classes"] = list(final.classes_)

    bundle = {"model": final, "feature_names": FEATURE_NAMES, "classes": list(final.classes_), "threshold": THRESHOLD,
              "trained_at": report["generated_at"], "sklearn_version": sklearn.__version__,
              "version": datetime.now(timezone.utc).strftime("rf-%Y%m%d-%H%M%S")}
    report["model_version"] = bundle["version"]
    joblib.dump(bundle, os.path.join(a.out, "ids_model.joblib"), compress=3)
    with open(os.path.join(a.out, "evaluation.json"), "w") as fh:
        json.dump(report, fh, indent=2)

    h, u, e, b = report["holdout"], report["unseen_templates"], report["edge_cases"], report["baseline_isolation_forest"]
    print("\n=== Evaluation ===")
    fmt = "  {:<28} det={:<7} fpr={:<7} prec={:<7} f1={:<7} auc={}"
    print(fmt.format("hold-out (20%)", h["detection_rate"], h["false_positive_rate"], h["precision"], h["f1"], h.get("roc_auc")))
    print(fmt.format("edge cases only", e["detection_rate"], e["false_positive_rate"], e["precision"], e["f1"], e.get("roc_auc")))
    print(fmt.format("unseen template families", u["detection_rate"], u["false_positive_rate"], u["precision"], u["f1"],
                     u.get("roc_auc")))
    print(fmt.format("baseline IsolationForest", b["detection_rate"], b["false_positive_rate"], b["precision"], b["f1"], "-"))
    cv = report["cross_validation"]
    print(f"  5-fold CV F1 = {cv['f1_mean']} ± {cv['f1_std']}")
    print("  per category:", {k: v.get("detection_rate", v.get("correct_rate")) for k, v in per_cat.items()})
    print(f"  inference: {single_ms:.2f} ms single, {batch_ms:.4f} ms/event batched")
    print("  top features:", ", ".join(f["feature"] for f in report["feature_importance"][:8]))
    weak = {k: v["flagged_rate"] for k, v in per_tpl.items()
            if (v["label"] == "malicious" and v["flagged_rate"] < 0.9) or (v["label"] == "benign" and v["flagged_rate"] > 0.05)}
    if weak:
        print("  weakest templates:", weak)
    print(f"\nSaved model bundle {bundle['version']} -> {a.out}/ids_model.joblib")


if __name__ == "__main__":
    main()
