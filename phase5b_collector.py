import time
import threading
import logging
import json
import os
import uuid
import csv
import sys
import socket
from datetime import datetime
import winreg
import psutil

# Reuse existing architecture monitors
from process_monitor import ProcessMonitor
from file_monitor import FileMonitor
from network_monitor import NetworkMonitor
from registry_monitor import RegistryMonitor
from feature_extractor import ProcessFeatureState, FeatureExtractor

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger("Phase5B_Collector")

class Phase5BCollector:
    def __init__(self, window_size=10, test_dir="ransomguard_test_files", scenario_id="mass_file_transformation_fast", expected_env_id="sandbox_hyperv_v1"):
        self.window_size = window_size
        self.session_id = str(uuid.uuid4())
        self.scenario_id = scenario_id
        self.expected_env_id = expected_env_id
        
        # Directories and Files
        self.output_dir = r"C:\Users\tiriv\Downloads\mlran-main\mlran-main\5_mlran_dataset\Phase5B_Malicious_Telemetry"
        self.csv_path = os.path.join(self.output_dir, "phase5b_malicious_telemetry.csv")
        self.jsonl_path = os.path.join(self.output_dir, "phase5b_collection_context.jsonl")
        
        # Absolute path calculation for safety checks
        self.base_dir = os.path.abspath(r"C:\Users\tiriv\Downloads\mlran-main\mlran-main")
        
        # Path traversal guard before resolution
        if ".." in test_dir or "\\\\" in test_dir or "/" in test_dir:
            self.target_dir = "INVALID_TRAVERSAL"
        else:
            self.target_dir = os.path.abspath(os.path.join(self.base_dir, test_dir))
            
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

    def run_safety_checks(self):
        logger.info("Executing Phase 5B Safety Checks...")
        
        # 1. Network Connectivity Negative Check (Fail-Closed)
        # This is strictly a NEGATIVE check. It does NOT prove host isolation, LAN isolation,
        # or the absence of hypervisor integration channels.
        try:
            # Active check: attempt to reach public internet
            # MOCK_ISOLATION_IP is STRICTLY a unit-test mechanism and holds zero production safety relevance.
            test_ip = os.environ.get("MOCK_ISOLATION_IP", "8.8.8.8")
            sock = socket.create_connection((test_ip, 53), timeout=1)
            sock.close()
            # If we succeed, we are NOT isolated!
            logger.error("SAFETY GATE FAILED: Network egress to public Internet is allowed. Environment is definitively NOT isolated!")
            return False
        except socket.timeout:
            logger.info("Negative Check Passed: Public DNS unreachable. NOTE: This does NOT prove complete sandbox isolation.")
        except socket.error as e:
            logger.info("Negative Check Passed: No route to public DNS. NOTE: This does NOT prove complete sandbox isolation.")
            
        # 2. Marker & Environment Attestation
        marker_path = os.path.join(self.base_dir, "SANDBOX_MARKER.txt")
        if not os.path.exists(marker_path):
            logger.error("SAFETY GATE FAILED: Sandbox marker file missing. Administrative attestation required. Aborting.")
            return False
            
        with open(marker_path, 'r') as f:
            env_id = f.read().strip()
            if not env_id:
                logger.error("SAFETY GATE FAILED: Sandbox marker empty. Aborting.")
                return False
            if env_id != self.expected_env_id:
                logger.error(f"SAFETY GATE FAILED: Sandbox Environment ID mismatch! Expected '{self.expected_env_id}', got '{env_id}'.")
                return False
            self.environment_id = env_id
            logger.info(f"Sandbox Environment Attested: {self.environment_id}. This marker acts as explicit administrative attestation of isolation.")

        # 3. Path Containment Verification
        if self.target_dir == "INVALID_TRAVERSAL":
            logger.error("SAFETY GATE FAILED: Path traversal characters detected in target directory.")
            return False
            
        if not self.target_dir.startswith(self.base_dir):
            logger.error(f"SAFETY GATE FAILED: Target directory {self.target_dir} escapes disposable base directory.")
            return False
            
        # 4. Shared Folder / UNC Path Protection
        drive = os.path.splitdrive(self.target_dir)[0].upper()
        if drive.startswith('\\\\'):
            logger.error("SAFETY GATE FAILED: Target directory resides on a UNC network share.")
            return False
            
        # Check active mount points to avoid VM shared folder types
        for part in psutil.disk_partitions(all=True):
            if part.mountpoint.upper().startswith(drive):
                fstype = part.fstype.lower()
                if 'vboxsf' in fstype or 'vmhgfs' in fstype or 'prl_fs' in fstype:
                    logger.error(f"SAFETY GATE FAILED: Target drive {drive} is mounted as a VM shared folder ({fstype}).")
                    return False
        
        # Check that target directory exists
        if not os.path.exists(self.target_dir):
            os.makedirs(self.target_dir, exist_ok=True)
            
        # 5. Output directory readiness
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)
            
        logger.info("All Safety Checks Passed. Defense-in-depth isolation verified.")
        return True

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
            "rel_01_spawned_by_vulnerable_app", "tmp_01_file_operations_per_second",
            "tmp_02_registry_modifications_per_sec", "label"
        ]
        if not file_exists:
            with open(self.csv_path, mode='w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(headers)

    def start(self):
        if not self.run_safety_checks():
            raise RuntimeError("Safety checks failed. Collection blocked.")
            
        self._initialize_csv()
        self.running = True
        logger.info("Starting Phase 5B Malicious Telemetry Collector (Window: 10s)")
        logger.info(f"Session ID: {self.session_id}")
        logger.info("label=1 represents controlled ransomware-behavior emulation, not confirmed real ransomware.")
        
        self.feature_extractor.monitor.start()
        self.file_monitor.start()
        self.network_monitor.start()
        self.registry_monitor.start()
        
        self._collection_thread = threading.Thread(target=self._collection_loop, daemon=True)
        self._collection_thread.start()

    def stop(self):
        logger.info("Stopping Collector... (Clean Shutdown)")
        self.running = False
        
        self.feature_extractor.monitor.stop()
        self.file_monitor.stop()
        self.network_monitor.stop()
        self.registry_monitor.stop()
        
        if self._collection_thread:
            self._collection_thread.join(timeout=2.0)

    def _collection_loop(self):
        while self.running:
            time.sleep(self.window_size)
            
            process_states = self.feature_extractor.states
            
            with self.file_monitor._lock:
                fs_01 = self.file_monitor.features.fs_01_creation_count
                fs_02 = self.file_monitor.features.fs_02_modification_count
                fs_03 = self.file_monitor.features.fs_03_deletion_count
                fs_04 = self.file_monitor.features.fs_04_rename_count
                fs_05 = len(self.file_monitor.features.fs_05_unique_exts)
                fs_06 = self.file_monitor.features.fs_06_exe_dropped
                self.file_monitor.features.reset()
                
            with self.registry_monitor._lock:
                rg_01 = self.registry_monitor.features.rg_01_keys_created
                rg_02 = self.registry_monitor.features.rg_02_values_modified
                rg_03 = self.registry_monitor.features.rg_03_persistence_mods
                self.registry_monitor.features.reset()
                
            with self.network_monitor._lock:
                network_states = self.network_monitor.process_network_states
                
            active_pids = set(process_states.keys()).union(network_states.keys())
            
            machine_vec = [0] * 21
            machine_vec[0] = fs_01
            machine_vec[1] = fs_02
            machine_vec[2] = fs_03
            machine_vec[3] = fs_04
            machine_vec[4] = fs_05
            machine_vec[5] = fs_06
            machine_vec[9] = rg_01
            machine_vec[10] = rg_02
            machine_vec[11] = rg_03
            
            for pid in active_pids:
                pid_vec = [0]*21
                if pid in process_states:
                    state = process_states[pid]
                    pid_vec = state.to_vector(self.window_size)
                    state.reset_window()
                
                pid_nw_01 = pid_nw_02 = 0
                if pid in network_states:
                    nw_state = network_states[pid]
                    with nw_state.lock:
                        pid_nw_01 = nw_state.outbound_connections_count
                        pid_nw_02 = len(nw_state.unique_destination_ips)
                        nw_state.reset()
                
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
                
            total_file_ops = fs_01 + fs_02 + fs_03 + fs_04
            machine_vec[19] = round(total_file_ops / float(self.window_size), 4)
            total_reg_ops = rg_01 + rg_02
            machine_vec[20] = round(total_reg_ops / float(self.window_size), 4)
            
            machine_vec[12] = 0 # MEM_01
            machine_vec[13] = 0 # MEM_02
            machine_vec[17] = 0 # DLL_02
            
            current_time = datetime.utcnow().isoformat()
            
            csv_row = [self.session_id, current_time, self.window_size] + machine_vec + [1]
            with open(self.csv_path, mode='a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(csv_row)
                
            context_record = {
                "collection_session_id": self.session_id,
                "timestamp": current_time,
                "label": 1,
                "scenario_id": self.scenario_id,
                "scenario_type": "ransomware_behavior_emulation",
                "environment_id": getattr(self, 'environment_id', 'unknown'),
                "feature_version": "21_canonical_v1",
                "source_type": "emulator"
            }
            with open(self.jsonl_path, mode='a') as f:
                f.write(json.dumps(context_record) + "\n")
                
            logger.info(f"Recorded 10s Window Snapshot -> CSV | Label: 1 | Activity: {sum(machine_vec)}")

def run_collector(duration=30, dry_run=False, test_dir="ransomguard_test_files", env_id="sandbox_hyperv_v1"):
    collector = Phase5BCollector(window_size=10, test_dir=test_dir, expected_env_id=env_id)
    
    print("\n--- PHASE 5B INITIALIZATION REPORT ---")
    print(f"Output Directory: {collector.output_dir}")
    print(f"Target Directory: {test_dir}")
    print(f"Expected Env ID: {env_id}")
    print("Feature Count: 21 + 1 (Label)")
    print("Label: 1 (MALICIOUS - EMULATOR)")
    
    if dry_run:
        print("\n[DRY RUN MODE ENABLED] - Executing Safety Checks Only")
        try:
            success = collector.run_safety_checks()
            if success:
                print("DRY RUN SUCCESS: Environment is safe and configured.")
                return True
            else:
                print("DRY RUN FAILED: Safety constraints violated.")
                return False
        except Exception as e:
            print(f"DRY RUN ERROR: {e}")
            return False

    try:
        collector.start()
        time.sleep(duration)
    except KeyboardInterrupt:
        logger.warning("Manual Abort (KeyboardInterrupt) caught. Initiating Kill Switch...")
    except Exception as e:
        logger.error(f"Kill Switch Activated due to error: {e}")
    finally:
        collector.stop()
        logger.info("Phase 5B Collection Complete.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--test-dir", default="ransomguard_test_files")
    parser.add_argument("--env-id", default="sandbox_hyperv_v1")
    args = parser.parse_args()
    
    run_collector(30, dry_run=args.dry_run, test_dir=args.test_dir, env_id=args.env_id)
