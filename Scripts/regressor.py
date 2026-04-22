import re
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor
from sklearn.linear_model import LinearRegression
from sklearn.metrics import r2_score

from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline

X = []
y = []

with open("../Data/Header.csv", "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue

        parts = line.split(",", 5)
        if len(parts) != 6:
            continue

        dt, beta1, beta2, stream_size, firmware_count, tail = parts

        try:
            stream_size = int(stream_size)
            firmware_count = int(firmware_count)
        except ValueError:
            continue

        if re.fullmatch(r"[0-9A-Fa-f]*", beta1):
            beta1_len = len(beta1) // 2
        else:
            beta1_len = 0

        if re.fullmatch(r"[0-9A-Fa-f]*", beta2):
            beta2_len = len(beta2) // 2
        else:
            beta2_len = 0

        blocks = re.findall(r"\[([^\[\]]+)\]", tail)
        if not blocks:
            continue

        parsed_blocks = []
        hash_lens = []
        nonce_lens = []
        ct_lens = []
        ct_means = []
        ct_stds = []

        for block in blocks:
            fields = [x.strip() for x in block.split("|")]
            if len(fields) != 4:
                continue

            fw_hash, actual_size, nonce, ciphertext = fields

            try:
                actual_size = int(actual_size)
            except ValueError:
                continue

            if re.fullmatch(r"[0-9A-Fa-f]*", fw_hash):
                hlen = len(fw_hash) // 2
            else:
                hlen = 0

            if re.fullmatch(r"[0-9A-Fa-f]*", nonce):
                nlen = len(nonce) // 2
            else:
                nlen = 0

            if re.fullmatch(r"[0-9A-Fa-f]*", ciphertext):
                clen = len(ciphertext) // 2
            else:
                clen = 0

            if clen > 0 and len(ciphertext) % 2 == 0:
                arr = np.frombuffer(bytes.fromhex(ciphertext), dtype=np.uint8)
                ct_byte_mean = float(arr.mean())
                ct_byte_std = float(arr.std())
            else:
                ct_byte_mean = 0.0
                ct_byte_std = 0.0

            parsed_blocks.append((actual_size, hlen, nlen, clen, ct_byte_mean, ct_byte_std))
            hash_lens.append(hlen)
            nonce_lens.append(nlen)
            ct_lens.append(clen)
            ct_means.append(ct_byte_mean)
            ct_stds.append(ct_byte_std)

        if not parsed_blocks:
            continue

        global_features = [
            stream_size,
            firmware_count,
            beta1_len,
            beta2_len,
            len(line),
            len(tail),
            len(parsed_blocks),
            sum(ct_lens),
            float(np.mean(ct_lens)),
            float(np.std(ct_lens)),
            min(ct_lens),
            max(ct_lens),
            float(np.mean(nonce_lens)),
            float(np.std(nonce_lens)),
            float(np.mean(hash_lens)),
            float(np.std(hash_lens)),
            float(np.mean(ct_means)),
            float(np.std(ct_means)),
            float(np.mean(ct_stds)),
            float(np.std(ct_stds)),
        ]

        for actual_size, hlen, nlen, clen, ct_byte_mean, ct_byte_std in parsed_blocks:
            features = global_features + [
                hlen,
                nlen,
                clen,
                ct_byte_mean,
                ct_byte_std,
            ]
            X.append(features)
            y.append(actual_size)

X = np.array(X, dtype=float)
y = np.array(y, dtype=float)

if len(X) < 10:
    raise RuntimeError(f"Not enough parsed samples: {len(X)}")

print(f"Parsed samples: {len(X)}")
print(f"Feature count: {X.shape[1]}")
print(f"Target min/max: {y.min()} / {y.max()}")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42
)

lin = LinearRegression()
lin.fit(X_train, y_train)
lin_r2 = r2_score(y_test, lin.predict(X_test))

rf = RandomForestRegressor(
    n_estimators=300,
    random_state=42,
    min_samples_leaf=2
)
rf.fit(X_train, y_train)
rf_r2 = r2_score(y_test, rf.predict(X_test))

print(f"Blind Fetch Linear Regression R²: {lin_r2:.6f}")
print(f"Blind Fetch Random Forest Regression R²: {rf_r2:.6f}")

corrs = []
for i in range(X.shape[1]):
    if np.std(X[:, i]) == 0:
        corrs.append(0.0)
    else:
        corrs.append(float(np.corrcoef(X[:, i], y)[0, 1]))

# print("Max |feature,target correlation|:", max(abs(c) for c in corrs))

rows = []

with open("../Data/PlainHeader.csv", "r") as f:
    next(f, None)  # skip header if present
    for line in f:
        line = line.strip()
        if not line:
            continue

        parts = line.split(",", 2)
        if len(parts) != 3:
            continue

        dt, firmware_count, tail = parts
        firmware_count = int(firmware_count)

        blocks = re.findall(r"\[([^\[\]]+)\]", tail)
        for idx, b in enumerate(blocks):
            fw_name, actual_size = b.split("||")
            rows.append({
                "fw_name": fw_name,
                "idx": idx,
                "firmware_count": firmware_count,
                "actual_size": int(actual_size),
            })

df = pd.DataFrame(rows)

X = df[["fw_name"]]
y = df["actual_size"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42
)

# --- Linear ---
lin = Pipeline([
    ("prep", ColumnTransformer([
        ("name", OneHotEncoder(handle_unknown="ignore"), ["fw_name"])
    ])),
    ("reg", LinearRegression())
])

lin.fit(X_train, y_train)
lin_pred = lin.predict(X_test)
lin_r2 = r2_score(y_test, lin_pred)

# --- Random Forest ---
rf = Pipeline([
    ("prep", ColumnTransformer([
        ("name", OneHotEncoder(handle_unknown="ignore"), ["fw_name"])
    ])),
    ("reg", RandomForestRegressor(n_estimators=200, random_state=42))
])

rf.fit(X_train, y_train)
rf_pred = rf.predict(X_test)
rf_r2 = r2_score(y_test, rf_pred)

print(f"Static Manifest Linear Regression R²: {lin_r2:.6f}")
print(f"Static Manifest Random Forest Regression R²: {rf_r2:.6f}")