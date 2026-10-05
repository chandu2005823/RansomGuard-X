import time
import os
import threading
import logging
from collections import defaultdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger("FileMonitor")

class FileSystemFeatures:
    """Aggregates the required file system features over a time window."""
    def __init__(self):
        self.fs_01_creation_count = 0
        self.fs_02_modification_count = 0
        self.fs_03_deletion_count = 0
        self.fs_04_rename_count = 0
        self.fs_05_unique_exts = set()
        self.fs_06_exe_dropped = 0

    def reset(self):
        self.fs_01_creation_count = 0
        self.fs_02_modification_count = 0
        self.fs_03_deletion_count = 0
        self.fs_04_rename_count = 0
        self.fs_05_unique_exts.clear()
        self.fs_06_exe_dropped = 0

    def __str__(self):
        return (f"Creations={self.fs_01_creation_count}, Mods={self.fs_02_modification_count}, "
                f"Deletions={self.fs_03_deletion_count}, Renames={self.fs_04_rename_count}, "
                f"UniqueExts={len(self.fs_05_unique_exts)}, ExesDropped={self.fs_06_exe_dropped}")

class MLRanEventHandler(FileSystemEventHandler):
    """Handles watchdog file events and updates the feature aggregates."""
    def __init__(self, feature_state, lock):
        super().__init__()
        self.state = feature_state
        self.lock = lock

    def _process_extension(self, file_path, is_creation=False):
        _, ext = os.path.splitext(file_path)
        ext = ext.lower().replace('.', '')
        if ext:
            with self.lock:
                self.state.fs_05_unique_exts.add(ext)
                if is_creation and ext in ['exe', 'dll', 'bat', 'ps1']:
                    self.state.fs_06_exe_dropped += 1

    def on_created(self, event):
        if event.is_directory:
            return
        with self.lock:
            self.state.fs_01_creation_count += 1
        self._process_extension(event.src_path, is_creation=True)

    def on_modified(self, event):
        if event.is_directory:
            return
        with self.lock:
            self.state.fs_02_modification_count += 1
        self._process_extension(event.src_path)

    def on_deleted(self, event):
        if event.is_directory:
            return
        with self.lock:
            self.state.fs_03_deletion_count += 1
        self._process_extension(event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            return
        with self.lock:
            self.state.fs_04_rename_count += 1
        self._process_extension(event.dest_path)


class FileMonitor:
    def __init__(self, target_directory, window_size=5, auto_flush=True):
        self.target_directory = target_directory
        self.window_size = window_size
        self.auto_flush = auto_flush
        self.features = FileSystemFeatures()
        self._lock = threading.Lock()
        self.observer = None
        self.running = False
        self._window_thread = None

    def start(self):
        if not os.path.exists(self.target_directory):
            try:
                os.makedirs(self.target_directory)
            except Exception as e:
                logger.error(f"Could not create target directory: {e}")
                return

        logger.info(f"Starting File Monitor on directory: {self.target_directory}")
        logger.info(f"Sliding Window Size: {self.window_size} seconds")
        logger.info("Note: PID attribution is impossible in pure user-mode Python without ETW/Sysmon. Aggregating globally for the directory.")
        
        event_handler = MLRanEventHandler(self.features, self._lock)
        self.observer = Observer()
        self.observer.schedule(event_handler, self.target_directory, recursive=True)
        self.observer.start()
        
        self.running = True
        if self.auto_flush:
            self._window_thread = threading.Thread(target=self._window_loop, daemon=True)
            self._window_thread.start()

    def stop(self):
        logger.info("Stopping File Monitor...")
        self.running = False
        if self.observer:
            self.observer.stop()
            self.observer.join()
        if self._window_thread:
            self._window_thread.join()

    def _window_loop(self):
        """Flushes the feature counters every time window."""
        while self.running:
            time.sleep(self.window_size)
            with self._lock:
                # We only print the vector if activity actually occurred
                if (self.features.fs_01_creation_count > 0 or 
                    self.features.fs_02_modification_count > 0 or 
                    self.features.fs_03_deletion_count > 0 or 
                    self.features.fs_04_rename_count > 0):
                    logger.info(f"--- Extracted File Features (Last {self.window_size}s) ---")
                    logger.info(str(self.features))
                
                self.features.reset()
