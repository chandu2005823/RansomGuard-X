import pandas as pd
import json

df = pd.read_csv(r'C:\Users\tiriv\Downloads\mlran-main\mlran-main\5_mlran_dataset\Phase5A_Live_Telemetry\phase5a_benign_telemetry.csv')

def categorize_session(rows, dur, start_time):
    # simple heuristic based on row counts/durs from my memory
    pass

sessions = df['collection_session_id'].unique()
for s in sessions:
    subset = df[df['collection_session_id'] == s].copy()
    subset['timestamp'] = pd.to_datetime(subset['timestamp'])
    start = subset['timestamp'].min()
    end = subset['timestamp'].max()
    dur = (end - start).total_seconds() + 10
    print(f"Session {s}: {len(subset)} rows | Dur: {dur}s | Start: {start} | End: {end}")
