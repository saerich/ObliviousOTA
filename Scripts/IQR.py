import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick

def print_stats(name, series):
    q1 = series.quantile(0.25)
    q3 = series.quantile(0.75)
    iqr = q3 - q1

    print(f"{name}:")
    print(f"  Median: {series.median():.3f}")
    print(f"  Q1    : {q1:.3f}")
    print(f"  Q3    : {q3:.3f}")
    print(f"  IQR   : {iqr:.3f}")
    print()

def load_execution_csv(path: str) -> pd.DataFrame:

    df = pd.read_csv(
        path,
        header=None,
        names=["Start Time", "TTFB", "TTLB", "Blocks", "Order", "IsTerminated", "TerminatedAt"],
    )

    df["TTFB_ms"] = pd.to_numeric(df["TTFB"])
    df["TTLB_ms"] = pd.to_numeric(df["TTLB"])

    df = df.dropna(subset=["TTFB_ms", "TTLB_ms"]).copy()
    return df


non_tls_file = "Data/NonTLSExecutions.csv"
tls_file = "Data/TLSExecutions.csv"

non_tls = load_execution_csv(non_tls_file)
tls = load_execution_csv(tls_file)


print("TTFB (ms):")
print_stats("Non-TLS", non_tls["TTFB_ms"])
print_stats("TLS", tls["TTFB_ms"])

print("TTLB (ms):")
print_stats("Non-TLS", non_tls["TTLB_ms"])
print_stats("TLS", tls["TTLB_ms"])

# ---- Plot 1: TTFB horizontal box plot ----
plt.figure(figsize=(10, 4))
plt.boxplot(
    [non_tls["TTFB_ms"], tls["TTFB_ms"]],
    vert=False,
    labels=["Non-TLS", "TLS"],
    patch_artist=False,
    showmeans=True,
)
plt.title("Median Time to First Byte")
plt.xlabel("Milliseconds")
plt.ylabel("Connection Type")
plt.tight_layout()
plt.show()

# ---- Plot 2: TTLB horizontal box plot ----
plt.figure(figsize=(10, 4))
plt.boxplot(
    [non_tls["TTLB_ms"], tls["TTLB_ms"]],
    vert=False,
    labels=["Non-TLS", "TLS"],
    patch_artist=False,
    showmeans=True,
)
plt.title("Median Time to Last Byte")
plt.xlabel("Milliseconds")
plt.ylabel("Connection Type")
plt.gca().xaxis.set_major_formatter(mtick.StrMethodFormatter('{x:,.0f}'))
plt.tight_layout()
plt.show()
