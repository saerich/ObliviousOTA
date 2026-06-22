from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, RepeatedStratifiedKFold, cross_val_predict
from sklearn.metrics import (
    roc_auc_score,
    accuracy_score,
    balanced_accuracy_score,
    classification_report
)
from scipy.stats import t
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

data = pd.read_csv("Data/MergedExecutions.csv")

data.columns = [
    "policy", "ordering", "S", "ttfb_ms", "ttlb_ms", "blocks_sent",
    "perm_id", "target_position", "Slot0", "Slot1", "Slot2", "Slot3"
]

for col in ["ttfb_ms", "ttlb_ms", "blocks_sent", "target_position"]:
    data[col] = pd.to_numeric(data[col])

data["target_position"] = data["target_position"].astype(int)
data["duration"] = data["ttlb_ms"] - data["ttfb_ms"]

FEATURES = ["ttfb_ms", "ttlb_ms", "blocks_sent", "duration"]
SLOT_COLS = ["Slot0", "Slot1", "Slot2", "Slot3"]

def slot_to_firmware(row, slot_position):
    return row[SLOT_COLS[int(slot_position)]]

labels = []
auroc_means = []
ci_lowers = []
ci_uppers = []

for policy in ["EarlyClose", "FixedBudget"]:
    for ordering in ["Ordered", "Unordered"]:
        sub = data[(data.policy == policy) & (data.ordering == ordering)].copy()

        if len(sub) == 0 or sub["target_position"].nunique() < 2:
            print(f"Skipping {policy} + {ordering}: no matching rows")
            continue

        X = sub[FEATURES]
        y_slot = sub["target_position"]

        model = RandomForestClassifier(
            n_estimators=100,
            random_state=42
        )

        # Single non-overlapping CV for readable accuracy/report.
        cv_predict = StratifiedKFold(
            n_splits=5,
            shuffle=True,
            random_state=42
        )

        predicted_slots = cross_val_predict(
            model,
            X,
            y_slot,
            cv=cv_predict,
            method="predict"
        )

        pred_slot_probs = cross_val_predict(
            model,
            X,
            y_slot,
            cv=cv_predict,
            method="predict_proba"
        )

        actual_firmware = [
            slot_to_firmware(row, row["target_position"])
            for _, row in sub.iterrows()
        ]

        predicted_firmware = [
            slot_to_firmware(row, pred_slot)
            for (_, row), pred_slot in zip(sub.iterrows(), predicted_slots)
        ]

        slot_acc = accuracy_score(y_slot, predicted_slots)
        fw_acc = accuracy_score(actual_firmware, predicted_firmware)
        fw_bal_acc = balanced_accuracy_score(actual_firmware, predicted_firmware)

        slot_auroc_single = roc_auc_score(
            y_slot,
            pred_slot_probs,
            multi_class="ovr"
        )

        # Repeated CV for AUROC confidence interval.
        cv_auc = RepeatedStratifiedKFold(
            n_splits=5,
            n_repeats=20,
            random_state=42
        )

        fold_aurocs = []

        for train_idx, test_idx in cv_auc.split(X, y_slot):
            X_train = X.iloc[train_idx]
            X_test = X.iloc[test_idx]
            y_train = y_slot.iloc[train_idx]
            y_test = y_slot.iloc[test_idx]

            fold_model = RandomForestClassifier(
                n_estimators=100,
                random_state=42
            )

            fold_model.fit(X_train, y_train)
            y_prob = fold_model.predict_proba(X_test)

            fold_auc = roc_auc_score(
                y_test,
                y_prob,
                multi_class="ovr"
            )

            fold_aurocs.append(fold_auc)

        fold_aurocs = np.array(fold_aurocs)

        mean_auc = fold_aurocs.mean()
        std_auc = fold_aurocs.std(ddof=1)
        se_auc = std_auc / np.sqrt(len(fold_aurocs))
        tval = t.ppf(0.975, df=len(fold_aurocs) - 1)

        ci_low = mean_auc - tval * se_auc
        ci_high = mean_auc + tval * se_auc

        label = (
            policy.replace("EarlyClose", "Early Close")
                  .replace("FixedBudget", "Fixed Budget")
            + "\n" + ordering
        )

        labels.append(label)
        auroc_means.append(mean_auc)
        ci_lowers.append(ci_low)
        ci_uppers.append(ci_high)

        print("=" * 80)
        print(f"{policy} + {ordering}")
        print(f"Slot-position accuracy:     {slot_acc:.4f}")
        print(f"Firmware accuracy:          {fw_acc:.4f}")
        print(f"Firmware balanced accuracy: {fw_bal_acc:.4f}")
        print(f"Slot AUROC single CV:       {slot_auroc_single:.4f}")
        print(f"Slot AUROC repeated CV:     {mean_auc:.4f}")
        print(f"95% CI:                     {ci_low:.4f} {ci_high:.4f}")
        print()
        print(classification_report(actual_firmware, predicted_firmware))

# Plot AUROC with 95% CI.
auroc_means = np.array(auroc_means)
ci_lowers = np.array(ci_lowers)
ci_uppers = np.array(ci_uppers)

yerr = np.array([
    auroc_means - ci_lowers,
    ci_uppers - auroc_means
])

x = np.arange(len(labels))

plt.figure(figsize=(8, 5))
plt.bar(x, auroc_means, yerr=yerr, capsize=6)
plt.xticks(x, labels)
plt.ylabel("Slot-position AUROC")
plt.ylim(0, 1.1)
plt.title("Slot-position AUROC by ordering and operation mode with 95% CI")
plt.tight_layout()
plt.show()