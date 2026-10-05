import os
import time
import uuid
import socket
import pandas as pd
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from live_detection_pipeline import LiveDetectionPipeline

def collect_benign_session(duration_minutes=20, custom_session_id=None):
    output_dir = "5_mlran_dataset/Phase5B_Live_Telemetry/benign_pilot"
    os.makedirs(output_dir, exist_ok=True)
    
    if custom_session_id:
        session_id = custom_session_id
    else:
        session_id = f"benign_{uuid.uuid4().hex[:8]}"
        
    hostname = socket.gethostname()
    
    print(f"Starting Benign Pilot Collection")
    print(f"Session ID: {session_id}")
    print(f"Target Duration: {duration_minutes} minutes")
    
    pipeline = LiveDetectionPipeline(window_size=10)
    
    # 20 minutes * 60 seconds / 10 seconds per window = 120 windows
    # Since collect_snapshot takes ~10.6s, we just run 120 iterations
    target_windows = int((duration_minutes * 60) / 10)
    
    rows = []
    
    for i in range(target_windows):
        print(f"Collecting window {i+1}/{target_windows}...")
        try:
            start_time_val = time.time()
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time_val))
            
            row_features, behavioral_text, end_time_val = pipeline.collect_snapshot()
            
            duration = end_time_val - start_time_val
            
            # Construct row
            row = {
                "timestamp": timestamp,
                "session_id": session_id,
                "label": 0,
                "behavioral_text": behavioral_text,
                "hostname": hostname,
                "collection_status": "SUCCESS",
                "collection_start_time": start_time_val,
                "collection_end_time": end_time_val,
                "collection_duration": duration
            }
            
            # Add all 21 canonical features
            for k, v in row_features.items():
                row[k] = v
                
            rows.append(row)
        except Exception as e:
            print(f"Error collecting window {i+1}: {e}")
            
    df = pd.DataFrame(rows)
    csv_path = os.path.join(output_dir, f"{session_id}.csv")
    df.to_csv(csv_path, index=False)
    print(f"Collection complete. Saved {len(rows)} rows to {csv_path}")
    
if __name__ == "__main__":
    duration = 20
    custom_session = None
    
    if len(sys.argv) > 1:
        duration = int(sys.argv[1])
    if len(sys.argv) > 2:
        custom_session = sys.argv[2]
        
    collect_benign_session(duration, custom_session)
