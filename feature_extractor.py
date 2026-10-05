import time
import threading
import logging
from collections import defaultdict
import psutil

# Import the monitor we built in the previous phase
from process_monitor import ProcessMonitor

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("FeatureExtractor")

class ProcessFeatureState:
    """Holds the 21-feature state for a single PID."""
    def __init__(self, pid):
        self.pid = pid
        # FILE_SYSTEM
        self.fs_01 = 0
        self.fs_02 = 0
        self.fs_03 = 0
        self.fs_04 = 0
        self.fs_05_exts = set()
        self.fs_06 = 0
        
        # PROCESS
        self.pr_01 = 0
        self.pr_02 = 0
        self.pr_03 = 0
        
        # REGISTRY
        self.rg_01 = 0
        self.rg_02 = 0
        self.rg_03 = 0
        
        # MEMORY
        self.mem_01 = 0
        self.mem_02 = 0
        
        # NETWORK
        self.nw_01 = 0
        self.nw_02_ips = set()
        
        # DLL/IMAGE
        self.dll_01 = 0
        self.dll_02 = 0
        self.known_dlls = set() # Add known DLLs tracker
        
        # RELATIONSHIP
        self.rel_01 = 0
        
        # TEMPORAL counters
        self.file_ops = 0
        self.reg_ops = 0

    def get_feature_vector(self, window_size):
        """Returns the 21-element numerical feature array."""
        tmp_01 = self.file_ops / float(window_size)
        tmp_02 = self.reg_ops / float(window_size)
        
        return [
            self.fs_01, self.fs_02, self.fs_03, self.fs_04, len(self.fs_05_exts), self.fs_06,
            self.pr_01, self.pr_02, self.pr_03,
            self.rg_01, self.rg_02, self.rg_03,
            self.mem_01, self.mem_02,
            self.nw_01, len(self.nw_02_ips),
            self.dll_01, self.dll_02,
            self.rel_01,
            tmp_01, tmp_02
        ]

    def reset_window(self):
        """Clears transient counts for the next time window."""
        self.fs_01 = self.fs_02 = self.fs_03 = self.fs_04 = self.fs_06 = 0
        self.fs_05_exts.clear()
        
        self.pr_01 = self.pr_02 = self.pr_03 = 0
        self.rg_01 = self.rg_02 = self.rg_03 = 0
        self.mem_01 = self.mem_02 = 0
        
        self.nw_01 = 0
        self.nw_02_ips.clear()
        
        self.file_ops = self.reg_ops = 0
        self.dll_01 = 0 # Now correctly delta-based

class FeatureExtractor:
    def __init__(self, window_size=10, auto_flush=True):
        self.window_size = window_size
        self.auto_flush = auto_flush
        self.monitor = ProcessMonitor(poll_interval=1.0)
        self.states = defaultdict(lambda: ProcessFeatureState(0))
        self.running = False

    def start(self):
        self.running = True
        self.monitor.start()
        if self.auto_flush:
            threading.Thread(target=self._extraction_loop, daemon=True).start()
        logger.info(f"Feature Extractor started with {self.window_size}s sliding window.")

    def stop(self):
        self.running = False
        self.monitor.stop()

    def _enrich_process_state(self, pid, state):
        """Uses psutil to actively poll network/file/dll state for the PID."""
        try:
            proc = psutil.Process(pid)
            
            # DLL/Image Loads (Approximation using memory maps)
            try:
                maps = proc.memory_maps()
                current_maps = {m.path for m in maps}
                new_maps = current_maps - state.known_dlls
                state.dll_01 += len(new_maps)
                state.known_dlls.update(new_maps)
            except:
                pass
                
            # Network Connections
            try:
                conns = proc.connections(kind='inet')
                state.nw_01 = len(conns)
                for c in conns:
                    if c.raddr:
                        state.nw_02_ips.add(c.raddr.ip)
            except:
                pass
                
            # File Operations (Approximation using open files)
            try:
                files = proc.open_files()
                # We can't tell if created/modified/deleted, but we can detect activity
                state.file_ops += len(files)
            except:
                pass
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    def _process_events(self, events):
        """Translates raw process events into ML features."""
        for evt in events:
            if evt.event_type == 'CREATED':
                # Mark the child state
                child_state = self.states[evt.pid]
                child_state.pid = evt.pid
                
                # Check vulnerable parent (REL_01)
                try:
                    if evt.ppid:
                        parent_proc = psutil.Process(evt.ppid)
                        p_name = parent_proc.name().lower()
                        if p_name in ['winword.exe', 'excel.exe', 'chrome.exe', 'iexplore.exe']:
                            child_state.rel_01 = 1
                except:
                    pass
                
                # Update the parent state
                if evt.ppid:
                    parent_state = self.states[evt.ppid]
                    parent_state.pid = evt.ppid
                    parent_state.pr_01 += 1 # Child process spawned
                    
                    if evt.name and evt.name.lower() in ['cmd.exe', 'powershell.exe', 'vssadmin.exe']:
                        parent_state.pr_02 += 1 # Suspicious child
                        
            elif evt.event_type == 'TERMINATED':
                # Attribute termination to the terminating process
                if evt.pid in self.states:
                    self.states[evt.pid].pr_03 += 1

    def flush(self):
        """Synchronously processes queued events and enriches states."""
        events = self.monitor.get_events()
        self._process_events(events)
        active_pids = list(self.states.keys())
        for pid in active_pids:
            self._enrich_process_state(pid, self.states[pid])

    def _extraction_loop(self):
        while self.running:
            time.sleep(self.window_size)
            
            # 1. Fetch raw events from monitor
            events = self.monitor.get_events()
            
            # 2. Process event-based features (Creations/Terminations)
            self._process_events(events)
            
            # 3. Actively poll running processes for state-based features (Network/DLLs)
            active_pids = list(self.states.keys())
            for pid in active_pids:
                self._enrich_process_state(pid, self.states[pid])
            
            # 4. Generate the feature vectors
            logger.info(f"--- Extracted Features (Last {self.window_size}s) ---")
            dead_pids = []
            for pid, state in list(self.states.items()):
                vec = state.get_feature_vector(self.window_size)
                # Only print if the process actually did something interesting
                if sum(vec) > 0:
                    logger.info(f"PID {pid} Vector: {vec}")
                
                # Reset window for the next 10s
                state.reset_window()
                if not psutil.pid_exists(pid):
                    dead_pids.append(pid)
                    
            for pid in dead_pids:
                if pid in self.states:
                    del self.states[pid]


def test_extractor():
    extractor = FeatureExtractor(window_size=5)
    extractor.start()
    
    logger.info("Feature Extractor running. Generate some network or child process activity...")
    try:
        time.sleep(16)
    except KeyboardInterrupt:
        pass
        
    extractor.stop()
    logger.info("Test completed.")

if __name__ == "__main__":
    test_extractor()
