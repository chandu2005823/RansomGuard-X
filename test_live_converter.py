import threading
import time
import os
import subprocess
import urllib.request
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from live_detection_pipeline import LiveDetectionPipeline

def test_benign_windows():
    print("Testing benign windows...")
    pipeline = LiveDetectionPipeline()
    pipeline.execute_pipeline()

def run_background_activity():
    # 1. Normal Application
    p = subprocess.Popen(["notepad.exe"])
    
    # 2. Normal File Activity
    os.makedirs("ransomguard_test_files", exist_ok=True)
    fpath = "ransomguard_test_files/normal_text.txt"
    with open(fpath, "w") as f: f.write("Testing live domain converter")
    for i in range(10):
        with open(fpath, "a") as f: f.write(f"\nLine {i}")
        time.sleep(0.1)
    
    # 3. Normal Network Activity
    try:
        urllib.request.urlopen("https://www.example.com").read()
    except:
        pass
        
    time.sleep(4)
    p.kill()

if __name__ == "__main__":
    t = threading.Thread(target=run_background_activity)
    t.start()
    
    time.sleep(1) # Let the background thread start doing things
    test_benign_windows()
    t.join()
