"""Evaluate the trained IDS model on an independent test dataset.

Loads the deployed bundle (ml/model/ids_model.joblib) and scores a dataset
that was generated with a different seed from the training data, e.g.

    python ml/generate_dataset.py --benign 12000 --malicious 8000 --seed 2026 --out ml/test_data.csv
    python ml/evaluate_model.py --data ml/test_data.csv

Reports:
  * binary (benign vs malicious) confusion matrix, accuracy, precision,
    recall / detection rate, specificity, FPR, F1, MCC, ROC-AUC, PR-AUC
  * multi-class confusion matrix + per-class precision / recall / F1
    (macro and weighted averages)
  * edge-case vs non-edge-case subsets
  * the full agent decision (ML + rules), as deployed in detector.py
  * a threshold sweep
  * how many test feature vectors also appear in the training data

Output: ml/model/test_evaluation.json (override with --out)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, average_precision_score, classification_report, confusion_matrix,
                             f1_score, matthews_corrcoef, precision_score, recall_score, roc_auc_score)

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "services", "ebpf-agent"))
sys.path.insert(0, HERE)
from ids_agent.detector import Detector  # noqa: E402
from ids_agent.features import FEATURE_NAMES  # noqa: E402
from train_model import build_matrix  # noqa: E402


def build_matrix_parallel(df: pd.DataFrame, workers: int) -> np.ndarray:
    """Feature extraction split across processes (it is pure Python and CPU-bound)."""
    if workers <= 1 or len(df) < 50_000:
        return build_matrix(df)
    from concurrent.futures import ProcessPoolExecutor
    chunks = np.array_split(np.arange(len(df)), workers * 4)
    with ProcessPoolExecutor(max_workers=workers) as ex:
        return np.vstack(list(ex.map(build_matrix, (df.iloc[c] for c in chunks))))


def binary_report(y_true, y_pred, score=None) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    out = {
        "samples": int(len(y_true)),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
        "recall_detection_rate": round(recall_score(y_true, y_pred, zero_division=0), 4),
        "specificity": round(tn / (tn + fp), 4) if tn + fp else None,
        "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else None,
        "false_negative_rate": round(fn / (fn + tp), 4) if fn + tp else None,
        "f1": round(f1_score(y_true, y_pred, zero_division=0), 4),
        "mcc": round(matthews_corrcoef(y_true, y_pred), 4),
    }
    if score is not None and len(set(y_true)) == 2:
        out["roc_auc"] = round(roc_auc_score(y_true, score), 4)
        out["pr_auc"] = round(average_precision_score(y_true, score), 4)
    return out


def print_binary(title, r):
    cm = r["confusion_matrix"]
    print(f"\n--- {title} ({r['samples']} samples) ---")
    print("                    predicted benign  predicted malicious")
    print(f"  actual benign     {cm['tn']:>16}  {cm['fp']:>19}")
    print(f"  actual malicious  {cm['fn']:>16}  {cm['tp']:>19}")
    keys = ["accuracy", "precision", "recall_detection_rate", "specificity", "false_positive_rate", "f1", "mcc",
            "roc_auc", "pr_auc"]
    print("  " + "  ".join(f"{k}={r[k]}" for k in keys if k in r))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=os.path.join(HERE, "test_data.csv"))
    ap.add_argument("--model", default=os.path.join(HERE, "model", "ids_model.joblib"))
    ap.add_argument("--train-data", default=os.path.join(HERE, "training_data.csv"))
    ap.add_argument("--out", default=os.path.join(HERE, "model", "test_evaluation.json"))
    ap.add_argument("--label-col", default="is_malicious", help="binary ground-truth column")
    ap.add_argument("--binary-only", action="store_true",
                    help="skip the multi-class section (datasets without attack categories, e.g. BETH)")
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 1, help="processes for feature extraction")
    ap.add_argument("--group-col", help="also report binary metrics per value of this column (e.g. host)")
    a = ap.parse_args()

    bundle = joblib.load(a.model)
    model, threshold = bundle["model"], float(bundle["threshold"])
    model.n_jobs = -1
    classes = list(bundle["classes"])
    print(f"Model {bundle.get('version')}  threshold={threshold}  classes={len(classes)}")

    df = pd.read_csv(a.data, keep_default_na=False)
    X = build_matrix_parallel(df, a.workers)
    y_bin = df[a.label_col].to_numpy().astype(int)
    y_cat = df["attack_category"].to_numpy()
    print(f"Test set {a.data}: {len(df)} rows ({y_bin.sum()} malicious, {(1 - y_bin).sum()} benign)")

    proba = model.predict_proba(X)
    p_mal = 1.0 - proba[:, classes.index("benign")]
    y_pred_bin = (p_mal >= threshold).astype(int)
    y_pred_cat = model.predict(X)

    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "model_version": bundle.get("version"),
              "test_data": os.path.relpath(a.data, os.path.join(HERE, "..")), "label_column": a.label_col,
              "threshold": threshold}

    # ---- 1. binary -------------------------------------------------------------------
    report["binary_ml"] = binary_report(y_bin, y_pred_bin, p_mal)
    print_binary("Binary: Random Forest only", report["binary_ml"])

    # ---- 2. multi-class --------------------------------------------------------------
    if not a.binary_only:
        multiclass_section(report, y_cat, y_pred_cat, classes)

    # ---- 2b. per group ---------------------------------------------------------------
    if a.group_col:
        groups = df[a.group_col].to_numpy()
        report["per_group"] = {}
        for g in sorted(set(groups)):
            m = groups == g
            report["per_group"][str(g)] = binary_report(y_bin[m], y_pred_bin[m], p_mal[m])
            print_binary(f"{a.group_col} = {g}", report["per_group"][str(g)])

    # ---- 3. edge cases ---------------------------------------------------------------
    edge = df["is_edge_case"].to_numpy() == 1
    if edge.any() and (~edge).any():
        report["edge_cases"] = binary_report(y_bin[edge], y_pred_bin[edge], p_mal[edge])
        report["non_edge_cases"] = binary_report(y_bin[~edge], y_pred_bin[~edge], p_mal[~edge])
        print_binary("Edge cases only", report["edge_cases"])
        print_binary("Non-edge cases", report["non_edge_cases"])

    # ---- 4. full agent decision: ML + rules (detector.Detector.assess) ---------------
    det = Detector(a.model)
    records = df.to_dict("records")
    y_pred_agent = np.array([int(det.assess(r, {}, list(X[i]), float(p_mal[i]), "")["suspicious"])
                             for i, r in enumerate(records)])
    report["binary_agent_ml_plus_rules"] = binary_report(y_bin, y_pred_agent)
    print_binary("Binary: deployed agent (ML + rules)", report["binary_agent_ml_plus_rules"])

    # ---- 5. threshold sweep ----------------------------------------------------------
    sweep = []
    for t in (0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9):
        r = binary_report(y_bin, (p_mal >= t).astype(int))
        sweep.append({"threshold": t, **{k: r[k] for k in ("precision", "recall_detection_rate",
                                                            "false_positive_rate", "f1", "accuracy")}})
    report["threshold_sweep"] = sweep
    print("\n--- Threshold sweep (ML only) ---")
    print("  thr   precision  recall   fpr      f1       accuracy")
    for s in sweep:
        print(f"  {s['threshold']:.1f}   {s['precision']:<9}  {s['recall_detection_rate']:<7}  "
              f"{s['false_positive_rate']:<7}  {s['f1']:<7}  {s['accuracy']}")

    # ---- 6. per template: where the errors are ---------------------------------------
    tpl = df["template"].to_numpy()
    errs = {}
    for t in sorted(set(tpl)):
        m = tpl == t
        wrong = int((y_pred_bin[m] != y_bin[m]).sum())
        if wrong:
            errs[t] = {"label": "malicious" if y_bin[m][0] else "benign", "samples": int(m.sum()), "errors": wrong,
                       "error_rate": round(wrong / m.sum(), 4)}
    report["templates_with_errors"] = dict(sorted(errs.items(), key=lambda kv: -kv[1]["error_rate"]))
    print("\n--- Templates with misclassifications (ML only) ---")
    for t, v in report["templates_with_errors"].items():
        print(f"  {t:<40} {v['label']:<9} {v['errors']:>4}/{v['samples']:<5} ({v['error_rate']:.1%})")

    # ---- 7. overlap with training data -----------------------------------------------
    if os.path.exists(a.train_data):
        tr = pd.read_csv(a.train_data, keep_default_na=False)
        seen = {row.tobytes() for row in build_matrix(tr)}
        dup = np.array([row.tobytes() in seen for row in X])
        report["train_overlap"] = {"identical_feature_vectors": int(dup.sum()), "fraction": round(float(dup.mean()), 4)}
        if (~dup).any() and len(set(y_bin[~dup])) == 2:
            report["unseen_vectors_only"] = binary_report(y_bin[~dup], y_pred_bin[~dup], p_mal[~dup])
        print(f"\nTest rows whose feature vector also occurs in training data: {dup.sum()} ({dup.mean():.1%})")
        if "unseen_vectors_only" in report:
            print_binary("Binary: only feature vectors never seen in training", report["unseen_vectors_only"])

    report["features"] = len(FEATURE_NAMES)
    with open(a.out, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"\nSaved {a.out}")



def multiclass_section(report, y_cat, y_pred_cat, classes):
    """Only rows whose true label is one of the model's classes (drops e.g. BETH's unlabelled attacks)."""
    known = np.isin(y_cat, classes)
    y_cat, y_pred_cat = y_cat[known], y_pred_cat[known]
    labels = classes
    cm = confusion_matrix(y_cat, y_pred_cat, labels=labels)
    cr = classification_report(y_cat, y_pred_cat, labels=labels, output_dict=True, zero_division=0)
    report["multiclass"] = {
        "accuracy": round(accuracy_score(y_cat, y_pred_cat), 4),
        "f1_macro": round(f1_score(y_cat, y_pred_cat, average="macro", zero_division=0), 4),
        "f1_weighted": round(f1_score(y_cat, y_pred_cat, average="weighted", zero_division=0), 4),
        "labels": labels,
        "confusion_matrix": cm.tolist(),
        "per_class": {c: {k: round(v, 4) if isinstance(v, float) else v for k, v in cr[c].items()} for c in labels},
    }
    print(f"\n--- Multi-class (benign + {len(labels) - 1} attack categories) ---")
    print(classification_report(y_cat, y_pred_cat, labels=labels, digits=4, zero_division=0))
    short = [c[:8] for c in labels]
    print("Confusion matrix (rows = actual, cols = predicted):")
    print(" " * 22 + "".join(f"{s:>9}" for s in short))
    for c, row in zip(labels, cm):
        print(f"  {c:<20}" + "".join(f"{v:>9}" for v in row))


if __name__ == "__main__":
    main()
