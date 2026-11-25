"""Build the final train / test datasets from every source generated so far.

TRAIN  (datasets/final/train.csv)
  * synthetic     ml/training_data.csv                (generate_dataset.py --seed 7, all 9 attack categories)
  * beth_dev      real *benign* BETH events from the development hosts only
                  (evil=0 and sus=0, exact duplicates removed, sampled to --beth-benign rows:
                  every unique exec/connect/setuid/chmod/mount/memfd event + random file opens)

TEST   (datasets/final/test.csv)  - never used for training or tuning
  * synthetic     ml/test_data.csv                    (generate_dataset.py --seed 2026)
  * beth_test     all BETH events of the held-out hosts (labelled_testing_data = host 217, ip-10-100-1-105)
  * k8s_escape    Splunk/Isovalent Tetragon container escape (hand-labelled, 25 events)

BETH is split by *host*, never by row, so near-duplicate events of one machine cannot leak
between train and test.  A manifest with row counts is written next to the CSVs.

Usage:
    python ml/build_final_dataset.py [--beth-benign 25000] [--seed 11] [--out datasets/final]
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone

import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
CONVERTED = os.path.join(ROOT, "datasets", "converted")

BETH_TEST_FILES = {"labelled_testing_data.csv", "labelled_2021may-ip-10-100-1-105.csv"}
COLUMNS = ["event_type", "comm", "parent_comm", "uid", "path", "cmdline", "argc", "flags", "arg2",
           "dport", "daddr", "namespace", "win_exec_count", "win_distinct_bins", "win_connect_count",
           "win_distinct_dst", "win_sensitive_opens", "win_shell_count", "win_new_binary",
           "is_malicious", "attack_category", "mitre_technique", "template", "is_edge_case", "source", "host"]
DEDUP_COLS = ["event_type", "comm", "parent_comm", "uid", "path", "cmdline", "flags", "dport", "daddr",
              "win_exec_count", "win_distinct_bins", "win_connect_count", "win_distinct_dst",
              "win_sensitive_opens", "win_shell_count", "win_new_binary"]


def _read(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        raise SystemExit(f"missing {path} - generate/convert it first (see ml/convert_external.py)")
    return pd.read_csv(path, keep_default_na=False)


def _finish(df: pd.DataFrame, source: str, host: str | None = None) -> pd.DataFrame:
    df = df.copy()
    df["source"] = source
    if host is not None or "host" not in df.columns:
        df["host"] = host or ""
    return df[COLUMNS]


def sample_beth_benign(dev: pd.DataFrame, n: int, seed: int) -> pd.DataFrame:
    b = dev[(dev.is_malicious == 0) & (dev.sus == 0)].drop_duplicates(DEDUP_COLS)
    rare = b[b.event_type != "open"]
    opens = b[b.event_type == "open"]
    k = max(0, min(len(opens), n - len(rare)))
    out = pd.concat([rare, opens.sample(n=k, random_state=seed)])
    out = out.assign(attack_category="benign", mitre_technique="", is_edge_case=0,
                     template="beth_" + out.event_type)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--beth-benign", type=int, default=25000, help="real benign BETH rows added to training")
    ap.add_argument("--seed", type=int, default=11)
    ap.add_argument("--out", default=os.path.join(ROOT, "datasets", "final"))
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    syn_train = _finish(_read(os.path.join(HERE, "training_data.csv")), "synthetic")
    syn_test = _finish(_read(os.path.join(HERE, "test_data.csv")), "synthetic")
    beth = _read(os.path.join(CONVERTED, "beth.csv"))
    k8s = _finish(_read(os.path.join(CONVERTED, "isovalent.csv")), "k8s_escape", host="eks-node")

    is_test = beth.source_file.isin(BETH_TEST_FILES)
    beth_dev, beth_test = beth[~is_test], beth[is_test]
    assert not set(beth_dev.host) & set(beth_test.host), "BETH host appears in both train and test"

    beth_train = _finish(sample_beth_benign(beth_dev, a.beth_benign, a.seed), "beth_dev")
    beth_test = _finish(beth_test, "beth_test")

    train = pd.concat([syn_train, beth_train], ignore_index=True).sample(frac=1, random_state=a.seed)
    test = pd.concat([syn_test, beth_test, k8s], ignore_index=True)
    train.to_csv(os.path.join(a.out, "train.csv"), index=False)
    test.to_csv(os.path.join(a.out, "test.csv"), index=False)

    def counts(df):
        return {s: {"rows": int(len(g)), "malicious": int(g.is_malicious.sum()),
                    "benign": int((g.is_malicious == 0).sum()), "hosts": sorted(h for h in set(g.host) if h)}
                for s, g in df.groupby("source")}

    manifest = {"generated_at": datetime.now(timezone.utc).isoformat(), "seed": a.seed,
                "train": {"rows": int(len(train)), "by_source": counts(train),
                          "categories": {k: int(v) for k, v in train.attack_category.value_counts().items()}},
                "test": {"rows": int(len(test)), "by_source": counts(test)},
                "beth_split": {"train_hosts": sorted(set(beth_dev.host)), "test_hosts": sorted(set(beth_test.host))}}
    with open(os.path.join(a.out, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=2)

    for part in ("train", "test"):
        print(f"{part}.csv: {manifest[part]['rows']} rows")
        for s, c in manifest[part]["by_source"].items():
            print(f"  {s:<11} {c['rows']:>7} rows  ({c['malicious']} malicious, {c['benign']} benign)  {c['hosts']}")
    print(f"BETH train hosts: {manifest['beth_split']['train_hosts']}")
    print(f"BETH test hosts:  {manifest['beth_split']['test_hosts']}")
    print(f"Wrote {a.out}/train.csv, test.csv, manifest.json")


if __name__ == "__main__":
    main()
