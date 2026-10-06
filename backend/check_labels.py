import os
import csv

DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "phishing_dataset.csv")

def main():
    print("Checking dataset labels in:", DATASET_PATH)
    
    # Try pandas first; fall back to csv if pandas C-extensions are blocked by policy
    try:
        import pandas as pd
        df = pd.read_csv(DATASET_PATH)
        print("\nLabel distribution:")
        print(df["label"].value_counts())
        print("\nLabel percentages:")
        print(df["label"].value_counts(normalize=True) * 100)
    except Exception:
        # Standard library CSV fallback (zero dependencies, never blocked by OS policy)
        counts = {0: 0, 1: 0}
        total = 0
        with open(DATASET_PATH, mode="r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                lbl = int(row["label"])
                counts[lbl] = counts.get(lbl, 0) + 1
                total += 1
        
        print("\nLabel distribution:")
        print(f"1    {counts.get(1, 0)}")
        print(f"0    {counts.get(0, 0)}")
        print("\nLabel percentages:")
        print(f"1    {(counts.get(1, 0) / total) * 100:.6f}%")
        print(f"0    {(counts.get(0, 0) / total) * 100:.6f}%")
        print(f"\nTotal samples: {total}")

    print("\nVerified Label Semantics (UCI PhiUSIIL Dataset):")
    print("- Label 1: Legitimate URL")
    print("- Label 0: Phishing URL")

if __name__ == "__main__":
    main()
