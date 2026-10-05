import os
import pandas as pd
import numpy as np
import json
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

def run_combined_eda(benign_csv, benign_jsonl, malicious_csv, malicious_jsonl):
    if not os.path.exists(malicious_csv):
        logging.warning("Phase 5B malicious dataset not found. Running EDA purely as a validation template.")
        return

    b_df = pd.read_csv(benign_csv)
    m_df = pd.read_csv(malicious_csv)
    combined_df = pd.concat([b_df, m_df], ignore_index=True)
    
    b_ctx = [json.loads(l) for l in open(benign_jsonl)]
    m_ctx = [json.loads(l) for l in open(malicious_jsonl)]
    combined_ctx = b_ctx + m_ctx
    
    logging.info("--- COMBINED DATASET EDA ---")
    
    # Sample counts
    logging.info(f"Total Rows: {len(combined_df)} (Benign: {len(b_df)}, Malicious: {len(m_df)})")
    
    # Session counts
    unique_sessions = combined_df['collection_session_id'].nunique()
    logging.info(f"Total Unique Sessions: {unique_sessions}")
    
    # Label counts
    logging.info(f"Label Counts:\n{combined_df['label'].value_counts().to_string()}")
    
    # Scenario counts & Provenance
    scenarios = pd.Series([ctx.get('scenario_id', 'unknown') for ctx in combined_ctx]).value_counts()
    logging.info(f"Scenario Breakdown:\n{scenarios.to_string()}")
    
    source_types = pd.Series([ctx.get('source_type', 'unknown') for ctx in combined_ctx]).value_counts()
    logging.info(f"Provenance Source Types:\n{source_types.to_string()}")
    
    # Idle/Active counts
    feature_cols = combined_df.columns[3:24]
    row_sums = combined_df[feature_cols].sum(axis=1)
    idle_count = (row_sums == 0).sum()
    active_count = (row_sums > 0).sum()
    logging.info(f"Idle Windows (All features 0): {idle_count}")
    logging.info(f"Active Windows (At least 1 feature > 0): {active_count}")
    
    # Per-feature distributions & Zero-variance
    logging.info("\n--- FEATURE DISTRIBUTIONS ---")
    zero_variance_features = []
    for col in feature_cols:
        mean = combined_df[col].mean()
        std = combined_df[col].std()
        max_v = combined_df[col].max()
        logging.info(f"{col:35s} | Mean: {mean:6.2f} | Std: {std:6.2f} | Max: {max_v:6.2f}")
        if std == 0 or pd.isna(std):
            zero_variance_features.append(col)
            
    logging.info(f"\nZero-Variance Features (Ignored by models): {zero_variance_features}")
    
    # Feature correlations
    # (Using pearson, ignoring zero variance to prevent warnings)
    valid_cols = [c for c in feature_cols if c not in zero_variance_features]
    if valid_cols:
        corr_matrix = combined_df[valid_cols].corr().abs()
        # Find high correlations > 0.8
        high_corr = np.where((corr_matrix > 0.8) & (corr_matrix < 1.0))
        high_corr_pairs = [(valid_cols[x], valid_cols[y]) for x, y in zip(*high_corr) if x < y]
        logging.info(f"\nHigh Feature Correlations (>0.8): {high_corr_pairs}")

if __name__ == "__main__":
    b_csv = r"C:\Users\tiriv\Downloads\mlran-main\mlran-main\5_mlran_dataset\Phase5A_Live_Telemetry\phase5a_benign_telemetry.csv"
    b_jsonl = r"C:\Users\tiriv\Downloads\mlran-main\mlran-main\5_mlran_dataset\Phase5A_Live_Telemetry\phase5a_collection_context.jsonl"
    m_csv = r"C:\Users\tiriv\Downloads\mlran-main\mlran-main\5_mlran_dataset\Phase5B_Malicious_Telemetry\phase5b_malicious_telemetry.csv"
    m_jsonl = r"C:\Users\tiriv\Downloads\mlran-main\mlran-main\5_mlran_dataset\Phase5B_Malicious_Telemetry\phase5b_collection_context.jsonl"
    
    run_combined_eda(b_csv, b_jsonl, m_csv, m_jsonl)
