import pandas as pd

# Load dataset
df = pd.read_csv("../data/phishing_dataset.csv")

print("\n--- DATASET SHAPE ---")
print(df.shape)

print("\n--- COLUMN NAMES ---")
print(df.columns.tolist())

print("\n--- FIRST 5 ROWS ---")
print(df.head())

print("\n--- DATA TYPES ---")
print(df.dtypes)

print("\n--- MISSING VALUES ---")
print(df.isnull().sum())

print("\n--- DUPLICATE ROWS ---")
print(df.duplicated().sum())

print("\n--- LABEL DISTRIBUTION ---")
print(df["label"].value_counts())

print("\n--- LABEL PERCENTAGES ---")
print(df["label"].value_counts(normalize=True) * 100)