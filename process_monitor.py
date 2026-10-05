import psutil
import time
import threading
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("ProcessMonitor")

class ProcessEvent:
    """Internal event structure for process monitoring."""
    def __init__(self, event_type, pid, timestamp, name=None, path=None, ppid=None, cpu_percent=None, memory_bytes=None, error=None):
        self.event_type = event_type  # 'CREATED', 'TERMINATED', 'SNAPSHOT', 'ERROR'
        self.pid = pid
        self.timestamp = timestamp
        self.name = name
        self.path = path
        self.ppid = ppid
        self.cpu_percent = cpu_percent
        self.memory_bytes = memory_bytes
        self.error = error

    def __str__(self):
        if self.event_type == 'ERROR':
            return f"[{self.event_type}] PID: {self.pid} - {self.error}"
        elif self.event_type == 'TERMINATED':
            return f"[{self.event_type}] PID: {self.pid}"
        else:
            return (f"[{self.event_type}] PID: {self.pid} | Name: {self.name} | "
                    f"PPID: {self.ppid} | CPU: {self.cpu_percent}% | Mem: {self.memory_bytes} bytes | Path: {self.path}")

class ProcessMonitor:
    def __init__(self, poll_interval=2.0):
        self.poll_interval = poll_interval
        self.known_pids = set()
        self.running = False
        self._thread = None
        self.event_queue = []
        self._lock = threading.Lock()
    
    def start(self):
        """Starts the process monitoring thread."""
        logger.info(f"Starting Process Monitor (Interval: {self.poll_interval}s)")
        self.running = True
        
        # Initialize the known PIDs silently on startup so we only trigger 'CREATED' for genuinely new processes
        self.known_pids = set(psutil.pids())
        
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()
        
    def stop(self):
        """Stops the process monitoring thread."""
        logger.info("Stopping Process Monitor...")
        self.running = False
        if self._thread:
            self._thread.join()

    def get_events(self):
        """Returns collected events and clears the internal queue."""
        with self._lock:
            events = list(self.event_queue)
            self.event_queue.clear()
        return events

    def _add_event(self, event):
        with self._lock:
            self.event_queue.append(event)

    def _get_process_info(self, pid):
        """Safely extracts process information, handling permission/lifecycle errors."""
        try:
            proc = psutil.Process(pid)
            
            # Using proc.as_dict() safely fetches multiple attributes at once
            info = proc.as_dict(attrs=['pid', 'name', 'exe', 'ppid', 'cpu_percent', 'memory_info'])
            
            # memory_info().rss represents the Resident Set Size (actual physical memory used)
            mem_bytes = info['memory_info'].rss if info['memory_info'] else None
            
            return {
                'name': info['name'],
                'path': info['exe'],
                'ppid': info['ppid'],
                'cpu_percent': info['cpu_percent'],
                'memory_bytes': mem_bytes
            }
            
        except psutil.AccessDenied:
            # We know the process exists, but we don't have rights to read its path/memory
            try:
                # Sometimes we can at least get the name even if access is denied
                proc = psutil.Process(pid)
                return {'name': proc.name(), 'path': 'ACCESS_DENIED', 'ppid': None, 'cpu_percent': 0.0, 'memory_bytes': 0}
            except:
                self._add_event(ProcessEvent('ERROR', pid, time.time(), error="AccessDenied"))
                return None
                
        except psutil.NoSuchProcess:
            # Process died before we could inspect it
            return None
            
        except Exception as e:
            self._add_event(ProcessEvent('ERROR', pid, time.time(), error=str(e)))
            return None

    def _poll_loop(self):
        while self.running:
            current_pids = set(psutil.pids())
            
            # Detect Terminated Processes
            terminated_pids = self.known_pids - current_pids
            for pid in terminated_pids:
                self._add_event(ProcessEvent('TERMINATED', pid, time.time()))
                
            # Detect New Processes
            new_pids = current_pids - self.known_pids
            for pid in new_pids:
                info = self._get_process_info(pid)
                if info:
                    self._add_event(ProcessEvent(
                        'CREATED', pid, time.time(),
                        name=info['name'], path=info['path'], ppid=info['ppid'],
                        cpu_percent=info['cpu_percent'], memory_bytes=info['memory_bytes']
                    ))

            # Update known PIDs
            self.known_pids = current_pids
            
            # Wait for next poll
            time.sleep(self.poll_interval)


def test_monitor():
    """Standalone test function for the Process Monitor."""
    logger.info("Initializing Process Monitor Test...")
    monitor = ProcessMonitor(poll_interval=2.0)
    monitor.start()
    
    logger.info("Monitor running. Please open or close some applications (e.g., Notepad, Calculator) to generate events.")
    logger.info("Test will run for 15 seconds...\n")
    
    try:
        for i in range(15):
            time.sleep(1)
            # Fetch and print events every second
            events = monitor.get_events()
            for evt in events:
                print(evt)
    except KeyboardInterrupt:
        logger.info("Test interrupted by user.")
        
    monitor.stop()
    logger.info("Process Monitor Test Completed.")

if __name__ == "__main__":
    test_monitor()
