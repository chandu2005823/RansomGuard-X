
import pandas as pd
import json

csv_path = r"C:\Users\tiriv\Downloads\mlran-main\mlran-main\5_mlran_dataset\Phase5A_Live_Telemetry\phase5a_benign_telemetry.csv"
jsonl_path = r"C:\Users\tiriv\Downloads\mlran-main\mlran-main\5_mlran_dataset\Phase5A_Live_Telemetry\phase5a_collection_context.jsonl"

df = pd.read_csv(csv_path)

print(f"Rows: {len(df)}")
features = df.columns[3:24]
print(f"Feature columns: {len(features)}")
metadata = df.columns[:3]
print(f"Metadata columns: {len(metadata)}")
label_dist = df["label"].value_counts().to_dict()
print(f"Label distribution: {label_dist}")

print("\nFeature statistics:")
always_zero = []
low_var = []
high_var = []

for f in features:
    min_v = df[f].min()
    max_v = df[f].max()
    mean_v = df[f].mean()
    median_v = df[f].median()
    std_v = df[f].std() if len(df) > 1 else 0.0
    nz_count = (df[f] != 0).sum()
    nz_pct = (nz_count / len(df)) * 100
    
    print(f"{f}: min={min_v}, max={max_v}, mean={mean_v:.2f}, median={median_v:.2f}, std={std_v:.2f}, non-zero={nz_count} ({nz_pct:.1f}%)")
    
    if nz_count == 0:
        always_zero.append(f)
    elif std_v < 0.5:
        low_var.append(f)
    elif std_v > 2.0:
        high_var.append(f)

print(f"\nAlways-zero: {always_zero}")
print(f"Low-variation: {low_var}")
print(f"High-variation: {high_var}")

missing = df.isnull().sum().sum()
dups = df.duplicated(subset=["collection_session_id", "timestamp"]).sum()
print(f"\nIntegrity:\nMissing values: {missing}\nDuplicate windows: {dups}")

with open(jsonl_path, "r") as f:
    lines = f.readlines()
print(f"JSONL records: {len(lines)}")
sessions = df["collection_session_id"].nunique()
print(f"Total sessions: {sessions}")

