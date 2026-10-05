import warnings
warnings.filterwarnings('ignore')
import argparse
import pandas as pd
import time
import logging

from ml_inference import MLInferenceEngine
from alert_logger import AlertLogger

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger("ReplayDemo")

def run_replay(csv_path, model_path="6_experiments/windows_rf_model.pkl", num_samples=10, delay=1.0):
    logger.info("--- RANSOMGUARD-X REPLAY DEMO ---")
    logger.info("DEMO ONLY - MODEL VALIDATED ON SYNTHETIC DATA")
    logger.info("These predictions do NOT represent real ransomware detections.\n")

    ml_engine = MLInferenceEngine(model_path)
    alert_logger = AlertLogger(log_file="ransomguard_replay_alerts.log")
    
    if not ml_engine.is_available:
        logger.error(f"Cannot run replay: Model not found at {model_path}.")
        return

    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        logger.error(f"Failed to load CSV {csv_path}: {e}")
        return

    logger.info(f"Loaded CSV {csv_path} with {len(df)} rows.")
    
    # Process several existing benign rows
    # We will pick some rows, ideally skip pure 0 rows to show feature activity, but keep chronological if possible
    # We'll just slice the dataframe. Let's take rows where sum of features > 0 to make the demo interesting.
    feature_cols = df.columns[3:24]
    
    active_df = df[df[feature_cols].sum(axis=1) > 0]
    if len(active_df) == 0:
        logger.warning("No active windows found in CSV, using idle rows.")
        active_df = df
        
    sample_df = active_df.head(num_samples)
    
    for _, row in sample_df.iterrows():
        timestamp = row['timestamp']
        machine_vec = row[feature_cols].tolist()
        label = row.get('label', 0)
        
        is_ransomware, prob = ml_engine.predict(machine_vec)
        
        logger.info(f"Time: {timestamp} | Ground Truth Label: {label}")
        logger.info(f"Vector Activity: {sum(machine_vec):.2f}")
        
        if is_ransomware:
            logger.warning(f"  [DETECTION THRESHOLD CROSSED] - Prob: {prob:.2f} (Demo Threshold)")
            alert_logger.log_alert(prob, machine_vec, suspicious_processes=[{"note": "demo_replay"}])
        else:
            logger.info(f"  [SAFE] - Prob: {prob:.2f}")
            
        print("-" * 60)
        time.sleep(delay)
        
    logger.info("Replay completed successfully.")
    logger.info("DEMO ONLY - MODEL VALIDATED ON SYNTHETIC DATA")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RansomGuard-X Safe Replay Demo")
    parser.add_argument("--replay", required=True, help="Path to Phase 5A benign CSV")
    parser.add_argument("--model", default="6_experiments/windows_rf_model.pkl", help="Path to the model .pkl")
    parser.add_argument("--samples", type=int, default=5, help="Number of rows to replay")
    
    args = parser.parse_args()
    
    run_replay(args.replay, model_path=args.model, num_samples=args.samples)
