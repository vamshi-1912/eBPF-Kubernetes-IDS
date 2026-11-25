# Model scores – `rf-20261122-223113`

Trained on `datasets/final/train.csv`, tested on `datasets/final/test.csv`
(built by `ml/build_final_dataset.py`, seed 11). Decision threshold 0.5.

```
python ml/build_final_dataset.py
python ml/train_model.py --data datasets/final/train.csv --out ml/model_final
python ml/evaluate_model.py --data datasets/final/test.csv --model ml/model_final/ids_model.joblib \
       --train-data datasets/final/train.csv --group-col source --out ml/model_final/final_test_evaluation.json
```

## Model
RandomForestClassifier, 10 classes (benign + 9 attack categories), 74 features.
`n_estimators=150, max_depth=22, min_samples_leaf=1, max_features="sqrt", class_weight=None, random_state=42`.
P(malicious) = 1 − P(benign).

## Data
| Split | Source | Rows | Malicious | Benign |
|---|---|---|---|---|
| train | synthetic (seed 7) | 40,000 | 10,000 | 30,000 |
| train | BETH benign, 15 development hosts (deduplicated, sampled) | 25,000 | 0 | 25,000 |
| test | synthetic (seed 2026) | 20,000 | 8,000 | 12,000 |
| test | BETH held-out hosts `ip-10-100-1-217`, `ip-10-100-1-105` | 262,825 | 147,308 | 115,517 |
| test | Kubernetes escape (Splunk / Isovalent Tetragon) | 25 | 7 | 18 |

BETH is split by host; no host appears in both train and test.

## 1. Validation on the training data (`ml/model_final/evaluation.json`)
| Check | Samples | Accuracy | Precision | Recall | FPR | F1 | ROC-AUC |
|---|---|---|---|---|---|---|---|
| Stratified 20 % hold-out | 13,000 | 0.9975 | 0.9945 | 0.9895 | 0.0010 | 0.9920 | 0.9999 |
| Hold-out, edge cases only | 4,906 | 0.9945 | 0.9906 | 0.9842 | 0.0026 | 0.9874 | 0.9995 |
| Unseen template families | 7,711 | 0.9684 | 0.9894 | 0.9105 | 0.0046 | 0.9483 | 0.9971 |
| 5-fold CV | – | – | – | 0.9877 | 0.0010 | 0.9912 ± 0.0006 | – |
| Baseline: Isolation Forest | 13,000 | 0.8679 | 0.7737 | 0.2000 | 0.0106 | 0.3178 | 0.5947 |

Hold-out confusion matrix: TN 10,989 · FP 11 · FN 21 · TP 1,979.
Inference: 18.1 ms for one event, 0.117 ms per event in a batch of 256.

## 2. Test set (`ml/model_final/final_test_evaluation.json`)

### Binary (benign vs malicious), per source
| Test source | Samples | Accuracy | Precision | Recall | FPR | F1 | MCC | ROC-AUC | TN | FP | FN | TP |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Synthetic | 20,000 | 0.9939 | 0.9986 | 0.9860 | 0.0009 | **0.9923** | 0.9872 | 0.9998 | 11,989 | 11 | 112 | 7,888 |
| BETH (real hosts) | 262,825 | 0.4427 | 0.9988 | 0.0056 | 0.0000 | **0.0112** | 0.0497 | 0.9995 | 115,516 | 1 | 146,479 | 829 |
| Kubernetes escape | 25 | 0.7200 | 0.5000 | 0.1429 | 0.0556 | **0.2222** | 0.1445 | 0.6746 | 17 | 1 | 6 | 1 |
| **All, ML only** | 282,850 | 0.4817 | 0.9985 | 0.0561 | 0.0001 | 0.1063 | 0.1612 | 0.9991 | 127,522 | 13 | 146,597 | 8,718 |
| **All, ML + rules (agent)** | 282,850 | 0.4794 | 0.9230 | 0.0566 | 0.0057 | 0.1066 | 0.1402 | – | 126,802 | 733 | 146,527 | 8,788 |

### Multi-class (rows with a known category: synthetic + Kubernetes + BETH benign)
Accuracy 0.9968 · macro F1 0.9554 · weighted F1 0.9968

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| benign | 0.9981 | 1.0000 | 0.9991 | 127,535 |
| container_escape | 0.9975 | 0.9736 | 0.9854 | 833 |
| credential_access | 0.9987 | 0.9544 | 0.9761 | 812 |
| crypto_miner | 0.9972 | 0.9273 | 0.9610 | 757 |
| defense_evasion | 0.9983 | 0.9190 | 0.9570 | 630 |
| discovery | 0.9344 | 0.9712 | 0.9525 | 939 |
| dropper | 0.9701 | 0.9719 | 0.9710 | 1,102 |
| lateral_movement | 0.9590 | 0.7524 | 0.8432 | 311 |
| privilege_escalation | 0.9205 | 0.9399 | 0.9301 | 949 |
| reverse_shell | 0.9994 | 0.9582 | 0.9783 | 1,674 |

Confusion matrix (rows = actual, columns = predicted, same class order):
```
benign               127533    0    0    0    1    1    0    0    0    0
container_escape         22  811    0    0    0    0    0    0    0    0
credential_access        30    1  775    0    0    0    0    0    6    0
crypto_miner             28    0    0  702    0    0   27    0    0    0
defense_evasion          21    1    0    0  579    0    0    0   29    0
discovery                21    0    1    0    0  912    0    5    0    0
dropper                  28    0    0    0    0    0 1071    0    3    0
lateral_movement         22    0    0    0    0   54    0  234    0    1
privilege_escalation     52    0    0    0    0    0    5    0  892    0
reverse_shell            14    0    0    2    0    9    1    5   39 1604
```

## 3. Comparison with the deployed model (`rf-20261107-161508`, synthetic data only)
Same test set, threshold 0.5, ML only:

| Test source | Deployed: F1 / Recall / FP | This model: F1 / Recall / FP |
|---|---|---|
| Synthetic | 0.9921 / 0.9862 / 15 | 0.9923 / 0.9860 / 11 |
| BETH | 0.6869 / 0.5248 / 481 | 0.0112 / 0.0056 / 1 |
| Kubernetes escape | 0.2222 / 0.1429 / 1 | 0.2222 / 0.1429 / 1 |

## Interpretation
- **Synthetic:** essentially unchanged (F1 0.992). Adding 25k real benign events did not hurt the 9-category detection.
- **BETH false positives:** fell from 481 to 1. The real benign host activity (`ps` reading `/proc`, `sshd`, systemd) is now learned.
- **BETH recall collapsed at threshold 0.5.** 144,801 of the 147,308 BETH attack events are one behaviour: a bot SSH-scanning thousands of IPs. Benign `sshd → :22` connects in the new training data push its score to 0.47, just below 0.5. Ranking is still excellent (ROC-AUC 0.9995), but the threshold is not crossed. The cause is a training gap: no synthetic attack has more than 12 distinct destinations in a window, against a median of about 3,200 for the scanner.
- **Other BETH attacks** (≈2,500 events): BETH labels every event in the attacker's session, including routine `uname`, `grep` and systemd calls, and real misses such as `wget <ip>/ssh` and `modprobe msr`. Recall on these is about 0 for both models.
- **Kubernetes escape:** only `nsenter --target 1` is flagged; host shell, `mount -t proc`, `cat /root/.ssh/authorized_keys` and recon are missed. The incident itself is still detected.
- **Threshold:** the sweep in the JSON shows F1 ≈ 0.99 at 0.2–0.3. This must **not** be used to pick the threshold, because it is tuned on the test set and driven by the single scanner cluster.
- 33 % of test feature vectors also occur in train, mostly identical benign file opens on BETH hosts running the same OS image. Scores restricted to unseen vectors are in the JSON (`unseen_vectors_only`).

**Verdict:** do not deploy over `rf-20261107-161508` yet. Next step: add a generic mass-scan / worm-spread attack template (T1046 / T1021) to `ml/generate_dataset.py`, pick the threshold on training data only, retrain and re-test once.
