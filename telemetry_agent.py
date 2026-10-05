import time
import win32evtlog
import xml.etree.ElementTree as ET
from collections import defaultdict
import threading
import sys

# Define our 21 RansomGuard-X Windows-Native Features
class ProcessFeatures:
    def __init__(self, pid):
        self.pid = pid
        self.last_update = time.time()
        
        # FILE_SYSTEM_BEHAVIOR
        self.fs_01_creation_count = 0
        self.fs_02_modification_count = 0  # Requires ETW
        self.fs_03_deletion_count = 0
        self.fs_04_rename_count = 0        # Requires ETW
        self.fs_05_unique_exts = set()
        self.fs_06_exe_dropped = 0
        
        # PROCESS_BEHAVIOR
        self.pr_01_child_count = 0
        self.pr_02_suspicious_child = 0
        self.pr_03_terminated = 0
        
        # REGISTRY_BEHAVIOR
        self.rg_01_keys_created = 0
        self.rg_02_values_modified = 0
        self.rg_03_persistence_mods = 0
        
        # MEMORY_BEHAVIOR
        self.mem_01_remote_threads = 0
        self.mem_02_cross_access = 0
        
        # NETWORK_BEHAVIOR
        self.nw_01_outbound_conns = 0
        self.nw_02_unique_ips = set()
        
        # DLL/IMAGE_BEHAVIOR
        self.dll_01_image_loads = 0
        self.dll_02_unsigned_loads = 0
        
        # PROCESS_RELATIONSHIP
        self.rel_01_vulnerable_parent = 0
        
        # TEMPORAL (Calculated dynamically)
        self.file_operations = 0
        self.registry_operations = 0

    def reset_window(self):
        # We preserve persistent traits (like vulnerable parent), but reset counts for the new time window
        self.fs_01_creation_count = 0
        self.fs_02_modification_count = 0
        self.fs_03_deletion_count = 0
        self.fs_04_rename_count = 0
        self.fs_05_unique_exts = set()
        self.fs_06_exe_dropped = 0
        self.pr_01_child_count = 0
        self.pr_02_suspicious_child = 0
        self.pr_03_terminated = 0
        self.rg_01_keys_created = 0
        self.rg_02_values_modified = 0
        self.rg_03_persistence_mods = 0
        self.mem_01_remote_threads = 0
        self.mem_02_cross_access = 0
        self.nw_01_outbound_conns = 0
        self.nw_02_unique_ips = set()
        self.dll_01_image_loads = 0
        self.dll_02_unsigned_loads = 0
        self.file_operations = 0
        self.registry_operations = 0
        self.last_update = time.time()

# Global tracking
process_stats = defaultdict(lambda: ProcessFeatures(0))
AGGREGATION_WINDOW = 10 # Seconds

def extract_event_data(xml_str):
    """Parses Windows Event XML format into a usable dictionary."""
    data = {}
    try:
        root = ET.fromstring(xml_str)
        ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        event_data = root.find('e:EventData', ns)
        if event_data is not None:
            for data_node in event_data.findall('e:Data', ns):
                name = data_node.get('Name')
                text = data_node.text
                if name and text:
                    data[name] = text
    except Exception as e:
        pass
    return data

def process_sysmon_event(event_id, data):
    """Updates the behavioral features for the responsible PID based on the Sysmon event."""
    
    # Identify responsible PID
    pid_str = data.get('ProcessId') or data.get('SourceProcessId')
    if not pid_str:
        return
    try:
        pid = int(pid_str)
    except:
        return
        
    stats = process_stats[pid]
    stats.pid = pid
    
    # Event 1: Process Creation
    if event_id == 1:
        parent_pid_str = data.get('ParentProcessId')
        if parent_pid_str:
            try:
                parent_pid = int(parent_pid_str)
                parent_stats = process_stats[parent_pid]
                parent_stats.pr_01_child_count += 1
                
                # PR_02 Suspicious Child
                image = (data.get('Image') or "").lower()
                if "cmd.exe" in image or "powershell.exe" in image or "vssadmin.exe" in image:
                    parent_stats.pr_02_suspicious_child += 1
                    
                # REL_01 Vulnerable Parent
                parent_image = (data.get('ParentImage') or "").lower()
                if "winword.exe" in parent_image or "excel.exe" in parent_image or "chrome.exe" in parent_image:
                    stats.rel_01_vulnerable_parent = 1
            except:
                pass
                
    # Event 3: Network Connection
    elif event_id == 3:
        stats.nw_01_outbound_conns += 1
        dst_ip = data.get('DestinationIp')
        if dst_ip:
            stats.nw_02_unique_ips.add(dst_ip)
            
    # Event 5: Process Terminate
    elif event_id == 5:
        # The process being terminated isn't the actor, unless it's suicide.
        # But for PR_03, we track terminations. We'll simplify for now.
        stats.pr_03_terminated += 1
        
    # Event 7: Image Loaded
    elif event_id == 7:
        stats.dll_01_image_loads += 1
        if data.get('Signed', 'true').lower() == 'false':
            stats.dll_02_unsigned_loads += 1
            
    # Event 8: CreateRemoteThread
    elif event_id == 8:
        stats.mem_01_remote_threads += 1
        
    # Event 10: ProcessAccess
    elif event_id == 10:
        stats.mem_02_cross_access += 1
        
    # Event 11: FileCreate
    elif event_id == 11:
        stats.fs_01_creation_count += 1
        stats.file_operations += 1
        target = (data.get('TargetFilename') or "").lower()
        if "." in target:
            ext = target.split(".")[-1]
            stats.fs_05_unique_exts.add(ext)
            if ext in ['exe', 'dll', 'bat', 'ps1']:
                stats.fs_06_exe_dropped += 1
                
    # Event 12, 13, 14: Registry
    elif event_id in [12, 13, 14]:
        stats.registry_operations += 1
        if event_id == 12:
            stats.rg_01_keys_created += 1
        elif event_id == 13:
            stats.rg_02_values_modified += 1
            
        target_obj = (data.get('TargetObject') or "").lower()
        if "currentversion\\run" in target_obj or "services" in target_obj:
            stats.rg_03_persistence_mods += 1
            
    # Event 26: File Delete Logged
    elif event_id == 26:
        stats.fs_03_deletion_count += 1
        stats.file_operations += 1

def telemetry_listener():
    """Polls the Windows Event Log for Sysmon events."""
    print("[*] Starting Sysmon Telemetry Listener...")
    server = 'localhost'
    logtype = 'Microsoft-Windows-Sysmon/Operational'
    
    try:
        hand = win32evtlog.OpenEventLog(server, logtype)
    except Exception as e:
        print(f"[!] FAILED TO OPEN SYSMON LOG: {e}")
        print("[!] Note: You must be running as Administrator, and Sysmon must be installed.")
        return

    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    
    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if events:
            for event in events:
                try:
                    xml_str = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                    data = extract_event_data(xml_str)
                    event_id = event.EventID & 0xFFFF
                    process_sysmon_event(event_id, data)
                except Exception as e:
                    pass
        else:
            time.sleep(1)

def aggregator_thread():
    """Outputs the aggregated feature vector every time window."""
    while True:
        time.sleep(AGGREGATION_WINDOW)
        print(f"\n--- Aggregated Features (Last {AGGREGATION_WINDOW}s) ---")
        
        # Only print processes that did something in this window
        active_pids = []
        for pid, stats in list(process_stats.items()):
            if (stats.fs_01_creation_count > 0 or stats.registry_operations > 0 or 
                stats.nw_01_outbound_conns > 0 or stats.mem_01_remote_threads > 0 or
                stats.pr_01_child_count > 0):
                
                # Calculate Temporal rates
                tmp_01_fs_rate = stats.file_operations / AGGREGATION_WINDOW
                tmp_02_reg_rate = stats.registry_operations / AGGREGATION_WINDOW
                
                print(f"PID: {pid}")
                print(f"  FS: Created={stats.fs_01_creation_count}, Deleted={stats.fs_03_deletion_count}, "
                      f"UniqueExts={len(stats.fs_05_unique_exts)}, ExeDropped={stats.fs_06_exe_dropped}")
                print(f"  PR: Childs={stats.pr_01_child_count}, SuspChilds={stats.pr_02_suspicious_child}, "
                      f"VulnParent={stats.rel_01_vulnerable_parent}")
                print(f"  RG: Created={stats.rg_01_keys_created}, Modified={stats.rg_02_values_modified}, "
                      f"Persistence={stats.rg_03_persistence_mods}")
                print(f"  NW: Conns={stats.nw_01_outbound_conns}, UniqueIPs={len(stats.nw_02_unique_ips)}")
                print(f"  MEM: RemoteThreads={stats.mem_01_remote_threads}, CrossAccess={stats.mem_02_cross_access}")
                print(f"  DLL: Loaded={stats.dll_01_image_loads}, Unsigned={stats.dll_02_unsigned_loads}")
                print(f"  TMP: FS_Rate={tmp_01_fs_rate}/s, REG_Rate={tmp_02_reg_rate}/s")
                
                # Reset window
                stats.reset_window()

if __name__ == "__main__":
    t = threading.Thread(target=telemetry_listener, daemon=True)
    t.start()
    
    try:
        aggregator_thread()
    except KeyboardInterrupt:
        print("Exiting...")
        sys.exit(0)
