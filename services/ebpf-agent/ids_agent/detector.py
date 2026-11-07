"""Detection + Risk & Alert Modules.

Random Forest (ML) + rules -> risk score (0-100) -> severity Low/Medium/High.
"""
from __future__ import annotations

import hashlib
import logging

import joblib
import numpy as np

from . import rules as rules_mod
from .features import FEATURE_NAMES

log = logging.getLogger("ids.detector")

CATEGORY_INFO = {
    "reverse_shell": ("T1059.004", "Execution", "Reverse shell / interactive command channel"),
    "dropper": ("T1105", "Command and Control", "Malicious payload download or execution"),
    "crypto_miner": ("T1496", "Impact", "Crypto-currency mining"),
    "privilege_escalation": ("T1068", "Privilege Escalation", "Privilege escalation attempt"),
    "container_escape": ("T1611", "Privilege Escalation", "Container escape attempt"),
    "credential_access": ("T1552", "Credential Access", "Credential or secret access"),
    "discovery": ("T1613", "Discovery", "Reconnaissance inside the cluster"),
    "defense_evasion": ("T1070", "Defense Evasion", "Defense evasion / anti-forensics"),
    "lateral_movement": ("T1021", "Lateral Movement", "Lateral movement attempt"),
}
RULE_SCORE = {"High": 90, "Medium": 70, "Low": 45}
PLATFORM_ML_THRESHOLD = 0.75


def severity_of(score: float) -> str:
    if score >= 80:
        return "High"
    if score >= 60:
        return "Medium"
    return "Low"


class Detector:
    def __init__(self, model_path: str, threshold_override: float = 0.0):
        bundle = joblib.load(model_path)
        if list(bundle["feature_names"]) != list(FEATURE_NAMES):
            raise RuntimeError("model feature names do not match ids_agent.features - retrain the model")
        self.model = bundle["model"]
        self.model.n_jobs = 1
        self.classes = list(bundle["classes"])
        self.benign_idx = self.classes.index("benign")
        self.threshold = threshold_override or float(bundle["threshold"])
        self.version = bundle.get("version", "unknown")
        log.info("loaded model %s (%d classes, threshold %.2f)", self.version, len(self.classes), self.threshold)

    def predict(self, X: np.ndarray):
        """Returns (p_malicious[], predicted_attack_category[])."""
        if len(X) == 0:
            return np.zeros(0), []
        proba = self.model.predict_proba(X)
        p_mal = 1.0 - proba[:, self.benign_idx]
        masked = proba.copy()
        masked[:, self.benign_idx] = -1
        cats = [self.classes[i] for i in masked.argmax(axis=1)]
        return p_mal, cats

    def assess(self, ev: dict, k8s: dict, fvec: list[float], p_mal: float, ml_category: str) -> dict:
        """Combine rules and ML into a decision with a risk score."""
        feats = dict(zip(FEATURE_NAMES, fvec))
        hits = rules_mod.evaluate(ev, feats)
        # Platform namespaces (control plane, add-ons, CI, this IDS) run lots of
        # legitimate infrastructure traffic: an ML-only verdict there needs high
        # confidence, otherwise rule corroboration (seen live: nginx -> backend:8000).
        threshold = max(self.threshold, PLATFORM_ML_THRESHOLD) if feats["ns_system"] and not hits else self.threshold
        ml_hit = p_mal >= threshold

        ml_score = p_mal * 100.0
        rule_score = max((RULE_SCORE[r.severity] for r in hits), default=0)
        score = max(ml_score if ml_hit else 0.0, rule_score)
        if hits and ml_hit:
            score += 5  # corroborated by both detectors
        if hits or ml_hit:
            if feats["uid_root"]:
                score += 3
            if feats["ns_system"] and not hits:
                score -= 10  # platform namespaces are noisier; need rule corroboration
        score = float(max(0.0, min(100.0, score)))

        suspicious = bool(hits) or ml_hit
        if hits:
            top = max(hits, key=lambda r: RULE_SCORE[r.severity])
            category = top.category
        else:
            category = ml_category
        mitre_id, tactic, title = CATEGORY_INFO.get(category, ("T1059", "Execution", "Suspicious behaviour"))
        mitre = sorted({r.mitre for r in hits} | ({mitre_id} if ml_hit or not hits else set()))
        return {
            "suspicious": suspicious,
            "probability": round(float(p_mal), 4),
            "ml_detected": bool(ml_hit),
            "ml_category": ml_category,
            "category": category if suspicious else "benign",
            "risk_score": round(score, 1) if suspicious else round(ml_score, 1),
            "severity": severity_of(score) if suspicious else None,
            "rules": [{"id": r.id, "name": r.name, "severity": r.severity} for r in hits],
            "mitre": mitre if suspicious else [],
            "tactic": tactic if suspicious else None,
            "title": (hits[0].name if hits else title) if suspicious else None,
        }


def dedup_key(ev: dict, k8s: dict, decision: dict) -> str:
    """Identical alerts from the same container collapse into one (count++)."""
    subject = ev.get("cmdline") or ev.get("path") or f"{ev.get('daddr')}:{ev.get('dport')}"
    raw = "|".join([k8s.get("namespace", ""), k8s.get("workload", ""), k8s.get("container", ""),
                    ev["event_type"], ev.get("comm", ""), decision["category"], subject[:200]])
    return hashlib.sha1(raw.encode()).hexdigest()
