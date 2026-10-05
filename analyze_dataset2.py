import pandas as pd
import json

csv_path = r"C:\Users\tiriv\Downloads\mlran-main\mlran-main\5_mlran_dataset\Phase5A_Live_Telemetry\phase5a_benign_telemetry.csv"
jsonl_path = r"C:\Users\tiriv\Downloads\mlran-main\mlran-main\5_mlran_dataset\Phase5A_Live_Telemetry\phase5a_collection_context.jsonl"

df = pd.read_csv(csv_path)
features = df.columns[3:24]

total_rows = len(df)
unique_sessions = df["collection_session_id"].nunique()
idle_windows = (df[features].sum(axis=1) == 0).sum()
active_windows = total_rows - idle_windows

print(f"Total rows: {total_rows}")
print(f"Unique sessions: {unique_sessions}")
print(f"Total collection duration: {total_rows * 10} seconds")
print(f"Idle windows: {idle_windows}")
print(f"Active windows: {active_windows}")
print("\nFEATURE DISTRIBUTION:")
print(f"{'Feature':<40} | {'Min':<4} | {'Max':<5} | {'Mean':<6} | {'Non-zero':<8} | {'Non-zero %'}")
print("-" * 85)

persistently_zero = []
for f in features:
    min_v = df[f].min()
    max_v = df[f].max()
    mean_v = df[f].mean()
    nz_count = (df[f] != 0).sum()
    nz_pct = (nz_count / total_rows) * 100
    print(f"{f:<40} | {min_v:<4} | {max_v:<5} | {mean_v:<6.2f} | {nz_count:<8} | {nz_pct:.1f}%")
    if nz_count == 0:
        persistently_zero.append(f)

label_dist = df["label"].value_counts().to_dict()
win_size_dist = df["window_size"].value_counts().to_dict()
nans = df.isnull().sum().sum()
dups = df.duplicated(subset=["collection_session_id", "timestamp"]).sum()

with open(jsonl_path, "r") as f:
    lines = f.readlines()
jsonl_count = len(lines)

print(f"\nLABEL DISTRIBUTION: {label_dist}")
print(f"WINDOW SIZE: {win_size_dist}")
print(f"NaNs: {nans}")
print(f"Duplicates: {dups}")
print(f"CSV/JSONL alignment: {total_rows == jsonl_count} ({total_rows} vs {jsonl_count})")
print(f"Persistently zero features: {persistently_zero}")

