import winreg
import time
import threading
import logging
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger("RegistryMonitor")

class RegistryFeatures:
    """Aggregates registry behavioral features over a time window."""
    def __init__(self):
        self.rg_01_keys_created = 0
        self.rg_02_values_modified = 0
        self.rg_03_persistence_mods = 0

    def reset(self):
        self.rg_01_keys_created = 0
        self.rg_02_values_modified = 0
        self.rg_03_persistence_mods = 0

    def __str__(self):
        return f"KeysCreated={self.rg_01_keys_created}, ValuesModified={self.rg_02_values_modified}, PersistenceMods={self.rg_03_persistence_mods}"


class RegistryMonitor:
    def __init__(self, monitored_paths, window_size=5, poll_interval=1.0, auto_flush=True):
        """
        monitored_paths: list of tuples (HKEY_CONSTANT, "Sub\\Path")
        """
        self.monitored_paths = monitored_paths
        self.window_size = window_size
        self.poll_interval = poll_interval
        self.auto_flush = auto_flush
        
        self.features = RegistryFeatures()
        self._lock = threading.Lock()
        
        self.running = False
        self._poll_thread = None
        self._window_thread = None
        
        # State tracking: path -> { 'subkeys': set(), 'values': {name: data} }
        self.state_cache = {}

    def _read_key_state(self, hkey, subpath):
        """Reads the current subkeys and values for a registry key."""
        state = {'subkeys': set(), 'values': {}}
        try:
            with winreg.OpenKey(hkey, subpath, 0, winreg.KEY_READ) as key:
                # Read subkeys
                num_subkeys, num_values, _ = winreg.QueryInfoKey(key)
                for i in range(num_subkeys):
                    try:
                        name = winreg.EnumKey(key, i)
                        state['subkeys'].add(name)
                    except EnvironmentError:
                        break
                        
                # Read values
                for i in range(num_values):
                    try:
                        name, data, _ = winreg.EnumValue(key, i)
                        # We convert data to string for easy comparison (handles ints, bytes, etc.)
                        state['values'][name] = str(data)
                    except EnvironmentError:
                        break
        except FileNotFoundError:
            # Key doesn't exist (yet)
            return None
        except PermissionError:
            # We don't have access to this key
            pass
        except Exception as e:
            pass
            
        return state

    def _initialize_cache(self):
        """Build the baseline state without triggering alerts."""
        for hkey, subpath in self.monitored_paths:
            path_str = f"{hkey}\\{subpath}"
            self.state_cache[path_str] = self._read_key_state(hkey, subpath)

    def start(self):
        logger.info(f"Starting Registry Monitor (Window: {self.window_size}s, Poll: {self.poll_interval}s)")
        logger.info("Safety Constraint Active: Read-only polling. No modifications.")
        logger.info("Note: PID attribution is impossible for Registry polling in pure user-mode Python. Aggregating globally.")
        
        self._initialize_cache()
        self.running = True
        
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()
        
        if self.auto_flush:
            self._window_thread = threading.Thread(target=self._window_loop, daemon=True)
            self._window_thread.start()

    def stop(self):
        logger.info("Stopping Registry Monitor...")
        self.running = False
        if self._poll_thread:
            self._poll_thread.join()
        if self._window_thread:
            self._window_thread.join()

    def _poll_loop(self):
        while self.running:
            for hkey, subpath in self.monitored_paths:
                path_str = f"{hkey}\\{subpath}"
                is_persistence = "run" in subpath.lower() or "services" in subpath.lower()
                
                current_state = self._read_key_state(hkey, subpath)
                old_state = self.state_cache.get(path_str)
                
                if current_state and old_state:
                    # Detect new subkeys
                    new_keys = current_state['subkeys'] - old_state['subkeys']
                    if new_keys:
                        with self._lock:
                            self.features.rg_01_keys_created += len(new_keys)
                            if is_persistence:
                                self.features.rg_03_persistence_mods += len(new_keys)
                                
                    # Detect value modifications (or new values)
                    for val_name, val_data in current_state['values'].items():
                        if val_name not in old_state['values'] or old_state['values'][val_name] != val_data:
                            with self._lock:
                                self.features.rg_02_values_modified += 1
                                if is_persistence:
                                    self.features.rg_03_persistence_mods += 1
                                    
                elif current_state and not old_state:
                    # The entire monitored key was just created
                    with self._lock:
                        self.features.rg_01_keys_created += 1
                        if is_persistence:
                            self.features.rg_03_persistence_mods += 1
                            
                self.state_cache[path_str] = current_state
                
            time.sleep(self.poll_interval)

    def _window_loop(self):
        while self.running:
            time.sleep(self.window_size)
            with self._lock:
                if (self.features.rg_01_keys_created > 0 or 
                    self.features.rg_02_values_modified > 0 or 
                    self.features.rg_03_persistence_mods > 0):
                    
                    logger.info(f"--- Extracted Registry Features (Last {self.window_size}s) ---")
                    logger.info(str(self.features))
                    
                self.features.reset()
