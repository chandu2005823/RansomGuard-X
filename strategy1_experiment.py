import threading
import time
import os
import subprocess
import urllib.request
import sys
import copy

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from live_detection_pipeline import LiveDetectionPipeline
from live_bert_inference import LiveBERTInference
from bert_xai import BertXAI

def run_experiment(scenario_name, action_func):
    print(f"\n{'='*70}")
    print(f"SCENARIO: {scenario_name}")
    print(f"{'='*70}")
    
    # 1. Setup pipeline
    pipeline = LiveDetectionPipeline()
    
    # 2. Run background thread to trigger action
    t = threading.Thread(target=action_func)
    t.start()
    
    # 3. Collect snapshot synchronously (the pipeline handles 10s window)
    row_raw, _ = pipeline.collect_snapshot()
    t.join()
    
    # Extract 11 common features
    COMMON_11 = [
        'fs_02_modification_count', 'fs_06_executable_files_dropped',
        'pr_01_child_process_count', 'pr_02_suspicious_child_count',
        'rg_01_registry_keys_created', 'rg_02_registry_values_modified', 'rg_03_persistence_registry_mods',
        'mem_01_remote_threads_created', 'mem_02_cross_process_access',
        'nw_01_outbound_connections_count', 'dll_01_image_load_count'
    ]
    
    # Create clipped row
    row_clipped = copy.deepcopy(row_raw)
    for feat in COMMON_11:
        if row_clipped.get(feat, 0) > 0:
            row_clipped[feat] = 1
            
    # Load BERT
    bert_inf = LiveBERTInference()
    
    print("\n--- A. CURRENT RAW-COUNT REPRESENTATION ---")
    text_a = bert_inf.convert_to_text(row_raw)
    res_a = bert_inf.predict(row_raw)
    pred_a = res_a['prediction']
    prob_b_a = res_a['benign_probability']
    prob_r_a = res_a['ransomware_probability']
    print("11 Feature Values:")
    for f in COMMON_11:
        print(f"  {f}: {row_raw.get(f, 0)}")
    print(f"Text: '{text_a}'")
    print(f"Prediction: {pred_a}")
    print(f"Probabilities - Benign: {prob_b_a:.4f} | Ransomware: {prob_r_a:.4f}")
    
    print("\n--- B. BINARY CLIPPED REPRESENTATION (Strategy 1) ---")
    text_b = bert_inf.convert_to_text(row_clipped)
    res_b = bert_inf.predict(row_clipped)
    pred_b = res_b['prediction']
    prob_b_b = res_b['benign_probability']
    prob_r_b = res_b['ransomware_probability']
    print("11 Feature Values:")
    for f in COMMON_11:
        print(f"  {f}: {row_clipped.get(f, 0)}")
    print(f"Text: '{text_b}'")
    print(f"Prediction: {pred_b}")
    print(f"Probabilities - Benign: {prob_b_b:.4f} | Ransomware: {prob_r_b:.4f}")
    
    print("\nPrediction Changed? ", "YES" if pred_a != pred_b else "NO")
    
    print("\n[LIME XAI for Representation B]")
    try:
        xai = BertXAI(bert_inf.pipeline)
        explanation = xai.explain(text_b)
        print("Top Terms:")
        for word, weight in explanation:
            print(f"  * '{word}' -> Weight: {weight:.4f}")
    except Exception as e:
        print(f"LIME Error: {e}")


def action_idle():
    time.sleep(1)

def action_file_mod():
    time.sleep(2)
    os.makedirs("ransomguard_test_files", exist_ok=True)
    fpath = "ransomguard_test_files/exp_text.txt"
    with open(fpath, "w") as f: f.write("Start")
    for i in range(15):
        with open(fpath, "a") as f: f.write(f"\nLine {i}")
        time.sleep(0.1)

def action_app_network():
    time.sleep(2)
    p = subprocess.Popen(["notepad.exe"])
    try:
        urllib.request.urlopen("https://www.example.com").read()
    except:
        pass
    time.sleep(6)
    p.kill()

if __name__ == "__main__":
    run_experiment("Idle / No Activity", action_idle)
    run_experiment("Normal File Modification", action_file_mod)
    run_experiment("Normal Application & Network Activity", action_app_network)
