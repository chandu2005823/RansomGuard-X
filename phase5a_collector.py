import time
import threading
import logging
import json
import os
import uuid
import csv
from datetime import datetime
import winreg
import psutil

# Reuse existing architecture monitors
from process_monitor import ProcessMonitor
from file_monitor import FileMonitor
from network_monitor import NetworkMonitor
from registry_monitor import RegistryMonitor
from feature_extractor import ProcessFeatureState, FeatureExtractor

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger("Phase5A_Collector")

class Phase5ACollector:
    def __init__(self, window_size=10, test_dir="ransomguard_test_files"):
        self.window_size = window_size
        self.session_id = str(uuid.uuid4())
        
        # Directories and Files
        self.output_dir = r"C:\Users\tiriv\Downloads\mlran-main\mlran-main\5_mlran_dataset\Phase5A_Live_Telemetry"
        self.csv_path = os.path.join(self.output_dir, "phase5a_benign_telemetry.csv")
        self.jsonl_path = os.path.join(self.output_dir, "phase5a_collection_context.jsonl")
        
        # Initialize modular components (No ML Engine)
        self.feature_extractor = FeatureExtractor(window_size=window_size)
        self.file_monitor = FileMonitor(target_directory=test_dir, window_size=window_size)
        self.network_monitor = NetworkMonitor(window_size=window_size, poll_interval=1.0)
        
        registry_paths = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
        ]
        self.registry_monitor = RegistryMonitor(monitored_paths=registry_paths, window_size=window_size, poll_interval=1.0)
        
        self.running = False
        self._collection_thread = None
        
        self._initialize_csv()

    def _initialize_csv(self):
        file_exists = os.path.isfile(self.csv_path)
        headers = [
            "collection_session_id", "timestamp", "window_size",
            "fs_01_creation_count", "fs_02_modification_count", "fs_03_deletion_count",
            "fs_04_rename_count", "fs_05_unique_extensions_modified", "fs_06_executable_files_dropped",
            "pr_01_child_process_count", "pr_02_suspicious_child_count", "pr_03_process_termination_count",
            "rg_01_registry_keys_created", "rg_02_registry_values_modified", "rg_03_persistence_registry_mods",
            "mem_01_remote_threads_created", "mem_02_cross_process_access",
            "nw_01_outbound_connections_count", "nw_02_unique_destination_ips",
            "dll_01_image_load_count", "dll_02_unsigned_image_load_count",
            "rel_01_spawned_by_vulnerable_app",
            "tmp_01_file_operations_per_second", "tmp_02_registry_modifications_per_sec",
            "label"
        ]
        if not file_exists:
            with open(self.csv_path, mode='w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(headers)
            logger.info(f"Initialized new CSV dataset: {self.csv_path}")
        else:
            logger.info(f"Appending to existing CSV dataset: {self.csv_path}")

    def start(self):
        logger.info(f"Starting Phase 5A Benign Telemetry Collector (Window: {self.window_size}s)")
        logger.info(f"Session ID: {self.session_id}")
        logger.info("ML Inference is completely DISABLED. Label is fixed to 0 (BENIGN).")
        
        self.running = True
        self.feature_extractor.start()
        self.file_monitor.start()
        self.network_monitor.start()
        self.registry_monitor.start()
        
        self._collection_thread = threading.Thread(target=self._collection_loop, daemon=True)
        self._collection_thread.start()

    def stop(self):
        logger.info("Stopping Collector...")
        self.running = False
        self.feature_extractor.stop()
        self.file_monitor.stop()
        self.network_monitor.stop()
        self.registry_monitor.stop()
        if self._collection_thread:
            self._collection_thread.join()

    def _collection_loop(self):
        while self.running:
            time.sleep(self.window_size)
            
            # Fetch all states exactly as in live agent
            process_states = self.feature_extractor.states
            
            with self.file_monitor._lock:
                global_fs = self.file_monitor.features
                fs_01 = global_fs.fs_01_creation_count
                fs_02 = global_fs.fs_02_modification_count
                fs_03 = global_fs.fs_03_deletion_count
                fs_04 = global_fs.fs_04_rename_count
                fs_05 = len(global_fs.fs_05_unique_exts)
                fs_06 = global_fs.fs_06_exe_dropped
            
            with self.network_monitor._lock:
                network_states = self.network_monitor.states
                
            with self.registry_monitor._lock:
                global_rg = self.registry_monitor.features
                rg_01 = global_rg.rg_01_keys_created
                rg_02 = global_rg.rg_02_values_modified
                rg_03 = global_rg.rg_03_persistence_mods
                
            active_pids = set(process_states.keys()).union(network_states.keys())
            
            # 1. Initialize Machine-Level Vector
            machine_vec = [0] * 21
            
            # Project global features directly into the machine vector
            machine_vec[0] = fs_01
            machine_vec[1] = fs_02
            machine_vec[2] = fs_03
            machine_vec[3] = fs_04
            machine_vec[4] = fs_05
            machine_vec[5] = fs_06
            machine_vec[9] = rg_01
            machine_vec[10] = rg_02
            machine_vec[11] = rg_03
            
            suspicious_processes = []
            
            # 2. Aggregate PID-level features into the machine vector
            for pid in active_pids:
                pid_vec = [0] * 21
                if pid in process_states:
                    pid_vec = process_states[pid].get_feature_vector(self.window_size)
                
                pid_nw_01 = 0
                pid_nw_02 = 0
                if pid in network_states:
                    nw_state = network_states[pid]
                    pid_nw_01 = nw_state.nw_01_outbound_conns
                    pid_nw_02 = len(nw_state.nw_02_unique_ips)
                    nw_state.reset()
                
                # Sum PR, MEM, NW, DLL, REL
                machine_vec[6] += pid_vec[6]
                machine_vec[7] += pid_vec[7]
                machine_vec[8] += pid_vec[8]
                machine_vec[12] += pid_vec[12]
                machine_vec[13] += pid_vec[13]
                machine_vec[14] += pid_nw_01
                machine_vec[15] += pid_nw_02
                machine_vec[16] += pid_vec[16]
                machine_vec[17] += pid_vec[17]
                machine_vec[18] += pid_vec[18]
                
                # Context gathering for this PID
                pid_activity = sum([pid_vec[6], pid_vec[7], pid_vec[8], pid_vec[12], pid_vec[13], pid_nw_01, pid_nw_02, pid_vec[16], pid_vec[17]])
                if pid_activity > 0:
                    try:
                        p_name = psutil.Process(pid).name()
                    except:
                        p_name = "UNKNOWN"
                    suspicious_processes.append({
                        "pid": pid,
                        "name": p_name,
                        "process_activity": pid_activity,
                        "features": {
                            "child_processes": pid_vec[6],
                            "outbound_conns": pid_nw_01,
                            "image_loads": pid_vec[16]
                        }
                    })
                    
            # 3. Recalculate Machine-Level Temporal Rates
            total_file_ops = fs_01 + fs_02 + fs_03 + fs_04
            machine_vec[19] = round(total_file_ops / float(self.window_size), 4)
            total_reg_ops = rg_01 + rg_02
            machine_vec[20] = round(total_reg_ops / float(self.window_size), 4)
            
            # Enforce 0 for unavailable features
            machine_vec[12] = 0 # MEM_01
            machine_vec[13] = 0 # MEM_02
            machine_vec[17] = 0 # DLL_02
            
            # Record genuine zero activity as an authentic idle baseline
            

            current_time = datetime.utcnow().isoformat()
            
            # Write to CSV
            csv_row = [self.session_id, current_time, self.window_size] + machine_vec + [0] # 0 is BENIGN label
            with open(self.csv_path, mode='a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(csv_row)
                
            # Write context to JSONL
            context_record = {
                "collection_session_id": self.session_id,
                "timestamp": current_time,
                "window_size": self.window_size,
                "active_pids": suspicious_processes,
                "global_activity": {
                    "file_events": total_file_ops,
                    "registry_events": total_reg_ops
                },
                "feature_vector": machine_vec
            }
            with open(self.jsonl_path, mode='a') as f:
                f.write(json.dumps(context_record) + "\n")
                
            logger.info(f"✅ Recorded 10s Window Snapshot -> CSV | Activity: {sum(machine_vec)}")

def run_collector(duration=30):
    collector = Phase5ACollector(window_size=10)
    
    # Dry Run Reporting
    print("\n--- PHASE 5A INITIALIZATION REPORT ---")
    print(f"Output Directory: {collector.output_dir}")
    print(f"CSV Path: {collector.csv_path}")
    print(f"JSONL Path: {collector.jsonl_path}")
    print("Feature Count: 21 + 1 (Label)")
    print("Feature Order: Canonical (fs_01-06, pr_01-03, rg_01-03, mem_01-02, nw_01-02, dll_01-02, rel_01, tmp_01-02)")
    print("Collection Interval: 10 seconds")
    print("ML Status: COMPLETELY DISABLED")
    print("Unavailable Features Hardcoded 0: MEM_01, MEM_02, DLL_02")
    if os.path.exists(collector.csv_path):
        print("Existing Data: PRESERVED (Will append safely)")
    else:
        print("Existing Data: NONE (Creating fresh)")
    print("--------------------------------------\n")
    
    collector.start()
    
    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        pass
    finally:
        collector.stop()
        logger.info("Phase 5A Collection Complete.")

if __name__ == "__main__":
    # Run a brief test collection of authentic benign telemetry for 35 seconds (3-4 windows)
    run_collector(35)
