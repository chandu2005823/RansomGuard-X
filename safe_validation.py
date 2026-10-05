import threading
import time
import os
import subprocess
import urllib.request
import sys

# Ensure parent directory is in path to import pipeline
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from live_detection_pipeline import LiveDetectionPipeline

def run_pipeline():
    pipeline = LiveDetectionPipeline()
    pipeline.execute_pipeline()

def safe_validation():
    print("\n=======================================================")
    print("SAFE BENIGN VALIDATION (Application + File + Network)")
    
    t = threading.Thread(target=run_pipeline)
    t.start()
    
    # Wait for the pipeline's monitors to initialize
    time.sleep(2)
    
    # 1. Normal Application
    p = subprocess.Popen(["notepad.exe"])
    
    # 2. Normal File Activity
    os.makedirs("ransomguard_test_files", exist_ok=True)
    fpath = "ransomguard_test_files/normal_text.txt"
    with open(fpath, "w") as f: f.write("Testing synchronization fix")
    
    # 3. Normal Network Activity
    try:
        urllib.request.urlopen("https://www.example.com").read()
    except:
        pass
        
    time.sleep(4)
    p.kill()
    
    t.join()

if __name__ == "__main__":
    safe_validation()
