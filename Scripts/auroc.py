from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import RepeatedStratifiedKFold, cross_val_score
from scipy.stats import t
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

data = pd.read_csv("Data/MergedExecutions.csv")
#Mode,Ordering,Slots,TTFB Miliseconds,TTLB Miliseconds,Blocks,Id,ActualSlot
data.columns = ["policy","ordering","S","ttfb_ms","ttlb_ms","blocks_sent","perm_id","target_position"]
data["duration"] = pd.to_numeric(data["ttlb_ms"]) - pd.to_numeric(data["ttfb_ms"])

FEATURES = ["ttfb_ms","ttlb_ms","blocks_sent","duration"]

auroc = np.array([])
ci_lower = np.array([])
ci_upper = np.array([])
labels = []

for policy in ["EarlyClose", "FixedBudget"]:
    for ordering in ["Ordered", "Unordered"]:
        sub = data[(data.policy == policy) & (data.ordering==ordering)]
        X = sub[FEATURES]
        Y = sub["target_position"]

        if len(sub) == 0 or Y.nunique() < 2:
            print(f"Skipping {policy} + {ordering}: no matching rows")
            continue

        model = RandomForestClassifier(n_estimators=100, random_state=42)
        cv = RepeatedStratifiedKFold(n_splits=5, n_repeats=20, random_state=42)
        auc = cross_val_score(model, X, Y, cv=cv, scoring="roc_auc_ovr")

        meanAuc = auc.mean()
        stdAuc = auc.std(ddof=1)
        seAuc = stdAuc / np.sqrt(len(auc))

        tval = t.ppf(0.975, df=len(auc)-1)

        ciLow = meanAuc - tval * seAuc
        ciHigh = meanAuc + tval * seAuc

        labels.append(policy.replace("EarlyClose", "Early Close").replace("FixedBudget", "Fixed Budget") + "\n" + ordering)
        auroc = np.append(auroc, meanAuc)
        ci_lower = np.append(ci_lower, ciLow)
        ci_upper = np.append(ci_upper, ciHigh)

        print(f"{policy} + {ordering}: AUROC: {meanAuc:.4f}, 95% CI: {ciLow:.4f} {ciHigh:.4f}")

yerr_lower = auroc - ci_lower
yerr_upper = ci_upper - auroc
yerr = np.array([yerr_lower, yerr_upper])

x = np.arange(len(labels))

plt.figure(figsize=(8, 5))
plt.bar(x, auroc, yerr=yerr, capsize=6)
plt.xticks(x, labels)
plt.ylabel("AUROC")
plt.ylim(0, 1.1)
plt.title("A graph to show AUROC by ordering and operation mode with 95% CI")
plt.tight_layout()
plt.show()