import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

df = pd.read_csv("Data/UnorderedSlotHeatmap.csv", index_col=0)

plt.figure(figsize=(8, 4.8))
ax = sns.heatmap(
    df,
    annot=True,
    fmt=".2f",
    cmap="YlGnBu",
    vmin=0.0,
    vmax=1.0,
    linewidths=0.5,
    linecolor="white",
    cbar_kws={"label": "Probability"}
)

ax.set_title("Unordered Executions: Position -> Firmware", pad=12)
ax.set_xlabel("Firmware")
ax.set_ylabel("Slot")

plt.tight_layout()
plt.show()

df = pd.read_csv("Data/OrderedSlotHeatmap.csv", index_col=0)

plt.figure(figsize=(8, 4.8))
ax = sns.heatmap(
    df,
    annot=True,
    fmt=".2f",
    cmap="YlGnBu",
    vmin=0.0,
    vmax=1.0,
    linewidths=0.5,
    linecolor="white",
    cbar_kws={"label": "Probability"}
)

ax.set_title("Ordered Executions: Position -> Firmware", pad=12)
ax.set_xlabel("Firmware")
ax.set_ylabel("Slot")

plt.tight_layout()
plt.show()