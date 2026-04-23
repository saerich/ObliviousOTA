import csv
import matplotlib.pyplot as plt

def get_avg(filename):
    deltas = []

    with open(filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        
        for row in reader:
            try:
                delta = int(row["Delta"])
                deltas.append(delta)
            except:
                pass

    deltas_sec = [d / 1_000_000 for d in deltas]
    return sum(deltas_sec) / len(deltas_sec)

# Compute both averages
avg_plain = get_avg("Data/PlainTiming.csv")
avg_blind = get_avg("Data/BlindFetchTiming.csv")

print("Plain Average:", avg_plain, "seconds")
print("Blind Average:", avg_blind, "seconds")

# Plot both
labels = ["esp_https_ota", "Blind Fetch"]
values = [avg_plain, avg_blind]

plt.bar(labels, values)
plt.ylabel("Time (seconds)")
plt.title("Average Execution Time of esp_https_ota vs Blind Fetch")
plt.tight_layout()

plt.show()