import os
import csv
import json
import pandas as pd
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

def validate_phase5b(csv_path, jsonl_path):
    if not os.path.exists(csv_path):
        logging.warning(f"Malicious CSV not found at {csv_path}. (Expected during preparation)")
        return
    if not os.path.exists(jsonl_path):
        logging.warning(f"Malicious JSONL not found at {jsonl_path}. (Expected during preparation)")
        return

    # Load CSV
    try:
        df = pd.read_csv(csv_path)
        logging.info(f"Loaded CSV with {len(df)} rows.")
    except Exception as e:
        logging.error(f"Failed to load CSV: {e}")
        return

    # 1. Schema / Feature order
    expected_headers = [
        "collection_session_id", "timestamp", "window_size",
        "fs_01_creation_count", "fs_02_modification_count", "fs_03_deletion_count",
        "fs_04_rename_count", "fs_05_unique_extensions_modified", "fs_06_executable_files_dropped",
        "pr_01_child_process_count", "pr_02_suspicious_child_count", "pr_03_process_termination_count",
        "rg_01_registry_keys_created", "rg_02_registry_values_modified", "rg_03_persistence_registry_mods",
        "mem_01_remote_threads_created", "mem_02_cross_process_access",
        "nw_01_outbound_connections_count", "nw_02_unique_destination_ips",
        "dll_01_image_load_count", "dll_02_unsigned_image_load_count",
        "rel_01_spawned_by_vulnerable_app", "tmp_01_file_operations_per_second",
        "tmp_02_registry_modifications_per_sec", "label"
    ]
    if list(df.columns) == expected_headers:
        logging.info("Schema and 21-feature canonical order matches perfectly.")
    else:
        logging.error(f"Schema mismatch! Expected {expected_headers}, got {list(df.columns)}")

    # 2. NaNs
    if df.isna().sum().sum() == 0:
        logging.info("No NaNs detected.")
    else:
        logging.error(f"NaNs detected: {df.isna().sum()}")

    # 3. Duplicate Windows
    dupes = df.duplicated(subset=['collection_session_id', 'timestamp'])
    if dupes.sum() == 0:
        logging.info("No duplicate session/timestamp windows detected.")
    else:
        logging.error(f"Found {dupes.sum()} duplicate windows.")

    # 4. Session Uniqueness
    sessions = df['collection_session_id'].unique()
    logging.info(f"Total unique sessions: {len(sessions)}")

    # 5. Label Distribution
    logging.info(f"Label distribution:\n{df['label'].value_counts().to_string()}")
    if (df['label'] != 1).any():
        logging.error("Found rows where label is NOT 1. Phase 5B must strictly be label=1.")

    # 6. JSONL Alignment & Provenance
    json_records = []
    with open(jsonl_path, 'r') as f:
        for line in f:
            json_records.append(json.loads(line.strip()))
    
    if len(json_records) == len(df):
        logging.info("CSV and JSONL row counts perfectly align.")
    else:
        logging.error(f"Alignment error! CSV has {len(df)} rows, JSONL has {len(json_records)} rows.")

    scenarios = {}
    for rec in json_records:
        scen = rec.get("scenario_id", "unknown")
        scenarios[scen] = scenarios.get(scen, 0) + 1
        assert rec.get("source_type") == "emulator"
        assert rec.get("scenario_type") == "ransomware_behavior_emulation"
        assert rec.get("label") == 1
    
    logging.info("Provenance validated successfully.")
    logging.info(f"Scenario distribution: {scenarios}")

    # 7. Feature Ranges
    feature_cols = expected_headers[3:24]
    logging.info("Feature Ranges:")
    for col in feature_cols:
        min_v = df[col].min()
        max_v = df[col].max()
        if min_v < 0:
            logging.error(f"Feature {col} has negative values.")
        logging.info(f"  {col}: {min_v} to {max_v}")

if __name__ == "__main__":
    base_dir = r"C:\Users\tiriv\Downloads\mlran-main\mlran-main\5_mlran_dataset\Phase5B_Malicious_Telemetry"
    validate_phase5b(
        os.path.join(base_dir, "phase5b_malicious_telemetry.csv"),
        os.path.join(base_dir, "phase5b_collection_context.jsonl")
    )
