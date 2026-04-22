import pandas as pd

dataSets = {
    "Unordered, Fixed Budget": pd.read_csv("Data/UnorderedFixedBudgetMemoryTrace.csv"),
    "Unordered, Close Early": pd.read_csv("Data/UnorderedCloseEarlyMemoryTrace.csv"),
    "Ordered, Fixed Budget": pd.read_csv("Data/OrderedFixedBudgetMemoryTrace.csv"),
    "Ordered, Close Early": pd.read_csv("Data/OrderedCloseEarlyMemoryTrace.csv")
}

for name, frame in dataSets.items():
    avg_peak = frame["Peak Heap"].mean()
    avg_low = frame["Lowest Heap"].mean()

    print(f"{name} Average Peak Heap: {avg_peak}, Average low heap: {avg_low}")