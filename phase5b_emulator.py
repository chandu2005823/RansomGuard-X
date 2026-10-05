import os
import time
import random
import socket
import threading
import subprocess
import shutil
import logging
import psutil

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger("Phase5B_Emulator")

class Phase5BEmulator:
    def __init__(self, target_dir="ransomguard_test_files", scenario_id="mass_file_transformation_fast", max_runtime=300):
        self.base_dir = os.path.abspath(r"C:\Users\tiriv\Downloads\mlran-main\mlran-main")
        
        # Path traversal guard before resolution
        if ".." in target_dir or "\\\\" in target_dir or "/" in target_dir:
            self.target_dir = "INVALID_TRAVERSAL"
        else:
            self.target_dir = os.path.abspath(os.path.join(self.base_dir, target_dir))
            
        self.scenario_id = scenario_id
        self.max_runtime = max_runtime
        self.running = False
        self.start_time = 0
        self.expected_env_id = "sandbox_hyperv_v1"
        self._threads = []

    def run_safety_checks(self):
        logger.info("Executing Phase 5B Emulator Safety Checks...")
        
        # 1. Network Connectivity Negative Check (Fail-Closed)
        try:
            test_ip = os.environ.get("MOCK_ISOLATION_IP", "8.8.8.8")
            sock = socket.create_connection((test_ip, 53), timeout=1)
            sock.close()
            logger.error("SAFETY GATE FAILED: Network egress to public Internet is allowed. Environment is definitively NOT isolated!")
            return False
        except socket.timeout:
            pass
        except socket.error:
            pass
            
        # 2. Marker & Environment Attestation
        marker_path = os.path.join(self.base_dir, "SANDBOX_MARKER.txt")
        if not os.path.exists(marker_path):
            logger.error("SAFETY GATE FAILED: Sandbox marker file missing. Administrative attestation required. Aborting.")
            return False
            
        with open(marker_path, 'r') as f:
            env_id = f.read().strip()
            if not env_id or env_id != self.expected_env_id:
                logger.error(f"SAFETY GATE FAILED: Sandbox Environment ID mismatch! Expected '{self.expected_env_id}', got '{env_id}'.")
                return False
                
        # 3. Path Containment Verification
        if self.target_dir == "INVALID_TRAVERSAL":
            logger.error("SAFETY GATE FAILED: Path traversal characters detected in target directory.")
            return False
        if not self.target_dir.startswith(self.base_dir):
            logger.error(f"SAFETY GATE FAILED: Target directory escapes disposable base directory.")
            return False
            
        # 4. Shared Folder / UNC Path Protection
        drive = os.path.splitdrive(self.target_dir)[0].upper()
        if drive.startswith('\\\\'):
            logger.error("SAFETY GATE FAILED: Target directory resides on a UNC network share.")
            return False
            
        for part in psutil.disk_partitions(all=True):
            if part.mountpoint.upper().startswith(drive):
                fstype = part.fstype.lower()
                if 'vboxsf' in fstype or 'vmhgfs' in fstype or 'prl_fs' in fstype:
                    logger.error(f"SAFETY GATE FAILED: Target drive is mounted as a VM shared folder ({fstype}).")
                    return False
                    
        logger.info("Emulator Safety Checks Passed.")
        return True

    def _check_timeout(self):
        if time.time() - self.start_time > self.max_runtime:
            logger.warning("Global maximum runtime exceeded. Triggering abort.")
            self.running = False
            return True
        return False

    def _simulate_network_beaconing(self, count=10, delay=0.5):
        logger.info(f"Simulating network beaconing ({count} connections to loopback)...")
        for _ in range(count):
            if not self.running or self._check_timeout(): break
            try:
                # Strictly restricted to loopback
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                sock.connect(("127.0.0.1", 445))
            except:
                pass
            finally:
                sock.close()
            time.sleep(delay)

    def _simulate_process_spawning(self, count=10, delay=0.5):
        logger.info(f"Simulating process spawning ({count} harmless processes)...")
        for _ in range(count):
            if not self.running or self._check_timeout(): break
            # Safe built-in processes only
            subprocess.Popen(["cmd.exe", "/c", "echo", "controlled process emulation"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(delay)

    def _get_target_files(self):
        files = []
        for root, _, filenames in os.walk(self.target_dir):
            for filename in filenames:
                files.append(os.path.join(root, filename))
        return files

    def _simulate_file_transformation(self, rate=0.01, max_files=5000):
        logger.info("Simulating non-cryptographic ransomware-behavior file emulation...")
        files = self._get_target_files()
        random.shuffle(files)
        
        count = 0
        for file_path in files:
            if not self.running or self._check_timeout(): break
            if count >= max_files: break
            
            # Non-cryptographic controlled file-transformation emulation
            try:
                # Modify
                with open(file_path, 'a') as f:
                    f.write("\nTransformation emulation signature.")
                # Rename to .locked proxy
                new_path = file_path + ".locked"
                os.rename(file_path, new_path)
                count += 1
            except Exception:
                pass
                
            time.sleep(rate)

    def run_scenario(self):
        if not self.run_safety_checks():
            logger.error("Safety checks failed. Aborting execution.")
            return

        self.running = True
        self.start_time = time.time()
        logger.info(f"Starting scenario: {self.scenario_id}")
        logger.info("This is non-cryptographic ransomware-behavior emulation.")
        
        try:
            if self.scenario_id == "mass_file_transformation_fast":
                self._simulate_file_transformation(rate=0.005)
                
            elif self.scenario_id == "slow_file_transformation":
                self._simulate_file_transformation(rate=1.0)
                
            elif self.scenario_id == "file_and_process_burst":
                t1 = threading.Thread(target=self._simulate_process_spawning, args=(20, 0.1))
                t1.start()
                self._threads.append(t1)
                time.sleep(2)
                self._simulate_file_transformation(rate=0.05)
                
            elif self.scenario_id == "network_beaconing_then_transform":
                self._simulate_network_beaconing(count=15, delay=0.2)
                self._simulate_file_transformation(rate=0.05)
                
            elif self.scenario_id == "process_and_module_activity_sim":
                self._simulate_process_spawning(count=50, delay=0.2)
                
            elif self.scenario_id == "pure_network_and_process":
                t1 = threading.Thread(target=self._simulate_process_spawning, args=(15, 0.3))
                t2 = threading.Thread(target=self._simulate_network_beaconing, args=(15, 0.3))
                t1.start()
                t2.start()
                self._threads.extend([t1, t2])
                for t in self._threads:
                    t.join()
            else:
                logger.error(f"Unknown scenario ID: {self.scenario_id}")
                
        except KeyboardInterrupt:
            logger.warning("Manual Abort Triggered (KeyboardInterrupt)!")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
        finally:
            self.stop()
            
    def stop(self):
        self.running = False
        for t in self._threads:
            t.join(timeout=1.0)
        logger.info("Emulator Execution Terminated and Cleaned Up.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--scenario", default="mass_file_transformation_fast")
    args = parser.parse_args()

    emulator = Phase5BEmulator(scenario_id=args.scenario)
    
    print("\n--- PHASE 5B EMULATOR INITIALIZATION ---")
    print(f"Scenario: {args.scenario}")
    print("Warning: Random scenario selection is intended to increase variation.")
    print("Actual diversity/balance will be verified after collection, it is not guaranteed.")
    
    if args.dry_run:
        print("\n[DRY RUN MODE ENABLED]")
        success = emulator.run_safety_checks()
        if success:
            print("DRY RUN SUCCESS: Environment is isolated and verified.")
        else:
            print("DRY RUN FAILED: Safety constraints violated.")
    else:
        # Deliberately preventing execution on current host as requested.
        print("\nEXECUTION BLOCKED: 'Do not execute the implementation after coding' enforced.")
