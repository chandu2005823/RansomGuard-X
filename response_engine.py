import psutil
import logging
from datetime import datetime
import json
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger("ResponseEngine")

class SafeMitigator:
    def __init__(self, dry_run=True, log_file="ransomguard_mitigation.log"):
        self.dry_run = dry_run
        self.log_file = log_file
        
        # A minimal heuristic list to prevent touching critical Windows subsystems
        self.system_critical_processes = {
            "svchost.exe", "csrss.exe", "wininit.exe", "smss.exe",
            "lsass.exe", "services.exe", "explorer.exe", "winlogon.exe",
            "spoolsv.exe", "taskmgr.exe", "system", "registry"
        }

    def _log_action(self, pid, process_name, action, result):
        import datetime as dt
        record = {
            "timestamp": dt.datetime.now(dt.UTC).isoformat(),
            "pid": pid,
            "process_name": process_name,
            "requested_action": action,
            "result": result,
            "dry_run": self.dry_run
        }
        with open(self.log_file, "a") as f:
            f.write(json.dumps(record) + "\n")
        logger.info(f"Mitigation Logged: {record}")

    def _inspect_process(self, pid):
        try:
            if not psutil.pid_exists(pid):
                return False, None, "PID does not exist."
                
            proc = psutil.Process(pid)
            if not proc.is_running():
                return False, None, "Process is no longer running."
                
            name = proc.name().lower()
            if name in self.system_critical_processes:
                return False, name, f"Process '{name}' is marked as system-critical. Access denied."
                
            return True, proc, "Process is valid and safe to target."
        except psutil.NoSuchProcess:
            return False, None, "Process terminated during inspection."
        except psutil.AccessDenied:
            return False, None, "Access denied to process."
        except Exception as e:
            return False, None, f"Inspection error: {e}"

    def safe_suspend(self, pid, confirm=False):
        """
        Safely and reversibly suspends a target process.
        Requires explicit confirmation bypass unless running in dry-run mode.
        """
        is_safe, proc, msg = self._inspect_process(pid)
        name = proc.name() if isinstance(proc, psutil.Process) else (proc if proc else "UNKNOWN")
        
        if not is_safe:
            self._log_action(pid, name, "SUSPEND", f"FAILED: {msg}")
            return False, msg

        if self.dry_run:
            msg = f"[DRY-RUN] Would have safely suspended PID {pid} ({name})."
            self._log_action(pid, name, "SUSPEND", msg)
            return True, msg

        if not confirm:
            msg = f"Suspension of PID {pid} ({name}) requires explicit manual confirmation."
            self._log_action(pid, name, "SUSPEND", "FAILED: Missing manual confirmation.")
            return False, msg
            
        try:
            proc.suspend()
            msg = f"SUCCESSFULLY suspended PID {pid} ({name})."
            self._log_action(pid, name, "SUSPEND", msg)
            return True, msg
        except Exception as e:
            msg = f"Failed to suspend PID {pid}: {e}"
            self._log_action(pid, name, "SUSPEND", msg)
            return False, msg

    def safe_resume(self, pid, confirm=False):
        """
        Resumes a previously suspended process.
        """
        is_safe, proc, msg = self._inspect_process(pid)
        name = proc.name() if isinstance(proc, psutil.Process) else (proc if proc else "UNKNOWN")
        
        if not is_safe:
            self._log_action(pid, name, "RESUME", f"FAILED: {msg}")
            return False, msg

        if self.dry_run:
            msg = f"[DRY-RUN] Would have resumed PID {pid} ({name})."
            self._log_action(pid, name, "RESUME", msg)
            return True, msg
            
        if not confirm:
            msg = f"Resumption of PID {pid} ({name}) requires explicit manual confirmation."
            self._log_action(pid, name, "RESUME", "FAILED: Missing manual confirmation.")
            return False, msg

        try:
            proc.resume()
            msg = f"SUCCESSFULLY resumed PID {pid} ({name})."
            self._log_action(pid, name, "RESUME", msg)
            return True, msg
        except Exception as e:
            msg = f"Failed to resume PID {pid}: {e}"
            self._log_action(pid, name, "RESUME", msg)
            return False, msg

if __name__ == "__main__":
    # Test only the safe inspection/dry-run functionality
    mitigator = SafeMitigator(dry_run=True)
    
    # Let's find a harmless process (like the current python process itself)
    current_pid = os.getpid()
    
    logger.info("--- Testing SafeMitigator (DRY RUN ONLY) ---")
    success, msg = mitigator.safe_suspend(current_pid, confirm=True)
    logger.info(f"Result: {msg}")
    
    # Try hitting a critical process to see it blocked
    # (Assuming pid 4 is 'System' on Windows)
    success, msg = mitigator.safe_suspend(4, confirm=True)
    logger.info(f"Result: {msg}")
