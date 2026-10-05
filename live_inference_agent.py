import time
import logging
import threading
from collections import defaultdict
import os

from process_monitor import ProcessMonitor, ProcessEvent
from file_monitor import FileMonitor
from network_monitor import NetworkMonitor
from registry_monitor import RegistryMonitor
from ml_inference import MLInferenceEngine
from alert_logger import AlertLogger
from feature_extractor import ProcessFeatureState, FeatureExtractor
import winreg

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger("LiveAgent")

class LiveInferenceAgent:
    def __init__(self, window_size=10, model_path="6_experiments/windows_rf_model.pkl", test_dir="ransomguard_test_files"):
        self.window_size = window_size
        self.model_path = model_path
        
        # 1. Initialize modular components
        self.ml_engine = MLInferenceEngine(self.model_path)
        self.alert_logger = AlertLogger()
        self.feature_extractor = FeatureExtractor(window_size=window_size)
        
        # 2. File, Network, and Registry Monitors
        self.file_monitor = FileMonitor(target_directory=test_dir, window_size=window_size)
        self.network_monitor = NetworkMonitor(window_size=window_size, poll_interval=1.0)
        
        # We monitor critical system locations globally for registry features
        registry_paths = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
        ]
        self.registry_monitor = RegistryMonitor(monitored_paths=registry_paths, window_size=window_size, poll_interval=1.0)
        
        self.running = False
        self._inference_thread = None

    def start(self):
        logger.info(f"Starting RansomGuard-X Phase 4 Live Agent (Window: {self.window_size}s)")
        
        if not self.ml_engine.is_available:
            logger.warning("Agent running in telemetry-only mode (MODEL_NOT_AVAILABLE).")
            
        self.running = True
        self.feature_extractor.start()
        self.file_monitor.start()
        self.network_monitor.start()
        self.registry_monitor.start()
        
        self._inference_thread = threading.Thread(target=self._inference_loop, daemon=True)
        self._inference_thread.start()

    def stop(self):
        logger.info("Stopping Live Agent...")
        self.running = False
        self.feature_extractor.stop()
        self.file_monitor.stop()
        self.network_monitor.stop()
        self.registry_monitor.stop()
        if self._inference_thread:
            self._inference_thread.join()

    def _inference_loop(self):
        while self.running:
            time.sleep(self.window_size)
            
            # Extract states
            process_states = self.feature_extractor.states
            
            # Safely grab the global file features for this window
            with self.file_monitor._lock:
                global_fs = self.file_monitor.features
                fs_01 = global_fs.fs_01_creation_count
                fs_02 = global_fs.fs_02_modification_count
                fs_03 = global_fs.fs_03_deletion_count
                fs_04 = global_fs.fs_04_rename_count
                fs_05 = len(global_fs.fs_05_unique_exts)
                fs_06 = global_fs.fs_06_exe_dropped
                
            # Safely grab network states
            with self.network_monitor._lock:
                network_states = self.network_monitor.states
                
            # Safely grab registry states
            with self.registry_monitor._lock:
                global_rg = self.registry_monitor.features
                rg_01 = global_rg.rg_01_keys_created
                rg_02 = global_rg.rg_02_values_modified
                rg_03 = global_rg.rg_03_persistence_mods
                
            active_pids = list(process_states.keys())
            
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
                state = process_states[pid]
                pid_vec = state.get_feature_vector(self.window_size)
                
                pid_nw_01 = 0
                pid_nw_02 = 0
                if pid in network_states:
                    nw_state = network_states[pid]
                    pid_nw_01 = nw_state.nw_01_outbound_conns
                    pid_nw_02 = len(nw_state.nw_02_unique_ips)
                    nw_state.reset()
                
                # Sum PR (6,7,8), MEM (12,13), NW (14,15), DLL (16,17), REL (18)
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
                
                # If this PID was highly active, save it for the investigation context
                pid_activity = sum([pid_vec[6], pid_vec[7], pid_vec[8], pid_vec[12], pid_vec[13], pid_nw_01, pid_nw_02, pid_vec[16], pid_vec[17]])
                if pid_activity > 0:
                    import psutil
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
            machine_vec[19] = total_file_ops / float(self.window_size)
            total_reg_ops = rg_01 + rg_02
            machine_vec[20] = total_reg_ops / float(self.window_size)
            
            # Distinguish genuine zero activity from errors
            if sum(machine_vec) == 0:
                continue
                
            # We have machine-level activity, run inference
            if self.ml_engine.is_available:
                is_ransomware, prob = self.ml_engine.predict(machine_vec)
                
                if is_ransomware:
                    logger.warning(f"🚨 [MACHINE DETECTION] System flagged as RANSOMWARE (Prob: {prob:.2f})")
                    self.alert_logger.log_alert(prob, machine_vec, suspicious_processes=suspicious_processes)
                else:
                    logger.info(f"✅ [SYSTEM SAFE] (Prob: {prob:.2f}) - Context: {len(suspicious_processes)} active PIDs")
            else:
                logger.info(f"📊 [TELEMETRY] Machine Vector: {machine_vec}")

def test_agent():
    agent = LiveInferenceAgent(window_size=5)
    agent.start()
    
    logger.info("Live Agent running. Generating safe network and file activity...")
    try:
        # Create dummy file to trigger FS features
        test_file = os.path.join("ransomguard_test_files", "agent_test.txt")
        with open(test_file, 'w') as f:
            f.write("test")
        
        time.sleep(11) # Wait for two window flushes
        
        # Cleanup
        if os.path.exists(test_file):
            os.remove(test_file)
    except KeyboardInterrupt:
        pass
    
    agent.stop()
    logger.info("Live Agent Test completed.")

if __name__ == "__main__":
    test_agent()
