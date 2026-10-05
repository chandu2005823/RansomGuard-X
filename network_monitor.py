import psutil
import time
import threading
import logging
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger("NetworkMonitor")

class NetworkFeatureState:
    """Stores the aggregated network features for a single process."""
    def __init__(self):
        self.nw_01_outbound_conns = 0
        self.nw_02_unique_ips = set()
        self.known_connections = set() # (local_ip, local_port, remote_ip, remote_port)

    def reset(self):
        """Reset counts for the sliding time window."""
        self.nw_01_outbound_conns = 0
        self.nw_02_unique_ips.clear()

    def __str__(self):
        return f"OutboundConns={self.nw_01_outbound_conns}, UniqueIPs={len(self.nw_02_unique_ips)}"


class NetworkMonitor:
    def __init__(self, window_size=5, poll_interval=1.0, auto_flush=True):
        self.window_size = window_size
        self.poll_interval = poll_interval
        self.auto_flush = auto_flush
        self.running = False
        
        self.states = defaultdict(NetworkFeatureState)
        self._lock = threading.Lock()
        
        self._poll_thread = None
        self._window_thread = None
        
        # Track global bytes to log network volume context (as requested)
        self.last_net_io = None

    def start(self):
        logger.info(f"Starting Network Behavioral Monitor (Window: {self.window_size}s, Poll: {self.poll_interval}s)")
        logger.info("Safety Constraint Active: Tracking ONLY metadata (IPs/Ports/State). No packet inspection.")
        
        self.running = True
        try:
            self.last_net_io = psutil.net_io_counters()
        except:
            self.last_net_io = None
            
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()
        
        if self.auto_flush:
            self._window_thread = threading.Thread(target=self._window_loop, daemon=True)
            self._window_thread.start()

    def stop(self):
        logger.info("Stopping Network Monitor...")
        self.running = False
        if self._poll_thread:
            self._poll_thread.join()
        if self._window_thread:
            self._window_thread.join()

    def _poll_loop(self):
        """Rapidly polls the OS connection table to catch short-lived connections."""
        while self.running:
            try:
                # 'inet' filters for IPv4/IPv6 connections (ignoring UNIX sockets)
                connections = psutil.net_connections(kind='inet')
                
                with self._lock:
                    for conn in connections:
                        # We only care about connections with a remote endpoint (ESTABLISHED, SYN_SENT, etc.)
                        # and that can be tied to a PID.
                        if conn.raddr and conn.pid:
                            laddr = conn.laddr
                            raddr = conn.raddr
                            
                            # Create a unique tuple for this connection instance
                            conn_tuple = (laddr.ip, laddr.port, raddr.ip, raddr.port)
                            
                            state = self.states[conn.pid]
                            
                            if conn_tuple not in state.known_connections:
                                state.known_connections.add(conn_tuple)
                                state.nw_01_outbound_conns += 1
                                state.nw_02_unique_ips.add(raddr.ip)
                                
            except psutil.AccessDenied:
                # On Windows, running net_connections without Admin can sometimes throw AccessDenied
                # if attempting to inspect system processes.
                pass
            except Exception as e:
                logger.error(f"Network polling error: {e}")
                
            time.sleep(self.poll_interval)

    def _window_loop(self):
        """Flushes the feature counters and calculates rates every time window."""
        while self.running:
            time.sleep(self.window_size)
            
            with self._lock:
                active_pids = list(self.states.keys())
                has_activity = False
                
                logger.info(f"--- Extracted Network Features (Last {self.window_size}s) ---")
                
                for pid in active_pids:
                    state = self.states[pid]
                    if state.nw_01_outbound_conns > 0:
                        has_activity = True
                        try:
                            proc_name = psutil.Process(pid).name()
                        except:
                            proc_name = "UNKNOWN"
                            
                        logger.info(f"PID: {pid} ({proc_name}) -> {state}")
                        
                    state.reset()
                
                if not has_activity:
                    logger.info("No outbound network activity detected.")
                    
                # Print global bandwidth usage for context
                try:
                    current_io = psutil.net_io_counters()
                    if current_io and self.last_net_io:
                        bytes_sent = current_io.bytes_sent - self.last_net_io.bytes_sent
                        bytes_recv = current_io.bytes_recv - self.last_net_io.bytes_recv
                        logger.info(f"[Global Traffic] Sent: {bytes_sent} bytes | Recv: {bytes_recv} bytes")
                    self.last_net_io = current_io
                except:
                    pass


def test_network_monitor():
    monitor = NetworkMonitor(window_size=5, poll_interval=1.0)
    monitor.start()
    
    logger.info("[TEST] Network Monitor running. Generating safe outbound connection...")
    try:
        import urllib.request
        # Generate safe outbound traffic
        time.sleep(1)
        urllib.request.urlopen('http://example.com', timeout=3)
        time.sleep(1)
        urllib.request.urlopen('http://example.org', timeout=3)
        
        logger.info("[TEST] Test requests complete. Waiting for feature window flush...")
        time.sleep(5)
    except Exception as e:
        logger.error(f"[TEST] Request failed: {e}")
        time.sleep(5) # Wait for window flush anyway
    finally:
        monitor.stop()
        logger.info("[TEST] Network Monitor Test completed.")

if __name__ == "__main__":
    test_network_monitor()
