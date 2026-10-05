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

def scenario_1():
    print("\n=======================================================")
    print("SCENARIO 1: Idle/background activity")
    t = threading.Thread(target=run_pipeline)
    t.start()
    t.join()

def scenario_2():
    print("\n=======================================================")
    print("SCENARIO 2: Create and edit a normal text file")
    t = threading.Thread(target=run_pipeline)
    t.start()
    time.sleep(2)
    os.makedirs("ransomguard_test_files", exist_ok=True)
    fpath = "ransomguard_test_files/normal_text.txt"
    with open(fpath, "w") as f: f.write("Hello")
    time.sleep(1)
    with open(fpath, "a") as f: f.write(" World")
    t.join()

def scenario_3():
    print("\n=======================================================")
    print("SCENARIO 3: Open/use normal application (Notepad)")
    t = threading.Thread(target=run_pipeline)
    t.start()
    time.sleep(2)
    p = subprocess.Popen(["notepad.exe"])
    time.sleep(5)
    p.kill()
    t.join()

def scenario_4():
    print("\n=======================================================")
    print("SCENARIO 4: Browse normally")
    t = threading.Thread(target=run_pipeline)
    t.start()
    time.sleep(2)
    try:
        urllib.request.urlopen("https://www.google.com").read()
        time.sleep(1)
        urllib.request.urlopen("https://www.github.com").read()
    except Exception as e:
        print(f"Browsing error: {e}")
    t.join()

def scenario_5():
    print("\n=======================================================")
    print("SCENARIO 5: Create/modify several harmless files")
    t = threading.Thread(target=run_pipeline)
    t.start()
    time.sleep(2)
    os.makedirs("ransomguard_test_files", exist_ok=True)
    for i in range(10):
        with open(f"ransomguard_test_files/file_{i}.txt", "w") as f:
            f.write(f"Data {i}")
    time.sleep(1)
    for i in range(10):
        with open(f"ransomguard_test_files/file_{i}.txt", "a") as f:
            f.write(f" Modified {i}")
    t.join()

if __name__ == "__main__":
    scenario_1()
    scenario_2()
    scenario_3()
    scenario_4()
    scenario_5()
