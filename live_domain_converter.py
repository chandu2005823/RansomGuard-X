def get_volume_bucket(value):
    if value == 0: return None
    elif value <= 5: return "minimal"
    elif value <= 25: return "moderate"
    elif value <= 100: return "high-volume"
    else: return "extreme-volume"

def get_rate_bucket(value):
    if value == 0.0: return None
    elif value <= 1.0: return "low"
    elif value <= 10.0: return "moderate"
    elif value <= 50.0: return "high"
    else: return "extreme"

def get_unique_bucket(value):
    if value == 0: return None
    elif value <= 3: return "few"
    elif value <= 10: return "multiple"
    else: return "many"

def convert_live_21_to_text(row):
    """
    Converts a 21-feature live telemetry dictionary into the Live-Domain BERT text representation.
    """
    sections = []
    
    # 1. FILE BEHAVIOR
    file_parts = []
    
    vol = get_volume_bucket(row.get('fs_02_modification_count', 0))
    if vol: file_parts.append(f"{vol} file modifications")
    
    vol = get_volume_bucket(row.get('fs_01_creation_count', 0))
    if vol: file_parts.append(f"{vol} file creations")
    
    vol = get_volume_bucket(row.get('fs_03_deletion_count', 0))
    if vol: file_parts.append(f"{vol} file deletions")
    
    vol = get_volume_bucket(row.get('fs_04_rename_count', 0))
    if vol: file_parts.append(f"{vol} file renames")
    
    vol = get_volume_bucket(row.get('fs_06_executable_files_dropped', 0))
    if vol: file_parts.append(f"{vol} executable-file drops")
    
    rate = get_rate_bucket(row.get('tmp_01_file_operations_per_second', 0.0))
    if rate: file_parts.append(f"{rate} file-operation rate")
    
    uniq = get_unique_bucket(row.get('fs_05_unique_extensions_modified', 0))
    if uniq: file_parts.append(f"activity across {uniq} unique file extensions")
    
    if file_parts:
        sections.append("File behavior: " + "; ".join(file_parts) + ".")

    # 2. PROCESS BEHAVIOR
    proc_parts = []
    
    vol = get_volume_bucket(row.get('pr_01_child_process_count', 0))
    if vol: proc_parts.append(f"{vol} child-process creation")
    
    vol = get_volume_bucket(row.get('pr_03_process_termination_count', 0))
    if vol: proc_parts.append(f"{vol} process termination")
    
    if row.get('rel_01_spawned_by_vulnerable_app', 0) > 0:
        proc_parts.append("vulnerable-parent relationship observed")
        
    if row.get('pr_02_suspicious_child_count', 0) > 0:
        proc_parts.append("suspicious child-process activity observed")
        
    if proc_parts:
        sections.append("Process behavior: " + "; ".join(proc_parts) + ".")

    # 3. NETWORK BEHAVIOR
    net_parts = []
    
    vol = get_volume_bucket(row.get('nw_01_outbound_connections_count', 0))
    if vol: 
        # The template uses "high outbound-connection volume", so we adjust the text slightly
        # get_volume_bucket returns "high-volume", we can format it as "{vol} outbound connections" or string replace
        vol_str = vol.replace("-volume", "") if "-volume" in vol else vol
        net_parts.append(f"{vol_str} outbound-connection volume" if vol in ["high-volume", "extreme-volume"] else f"{vol} outbound-connection volume")
        
    uniq = get_unique_bucket(row.get('nw_02_unique_destination_ips', 0))
    if uniq: net_parts.append(f"activity across {uniq} destination IP addresses")
    
    if net_parts:
        sections.append("Network behavior: " + "; ".join(net_parts) + ".")

    # 4. REGISTRY BEHAVIOR
    reg_parts = []
    
    vol = get_volume_bucket(row.get('rg_01_registry_keys_created', 0))
    if vol: reg_parts.append(f"{vol.replace('-volume', '')} registry-key creation")
    
    vol = get_volume_bucket(row.get('rg_02_registry_values_modified', 0))
    if vol: reg_parts.append(f"{vol.replace('-volume', '')} registry-value modification")
    
    rate = get_rate_bucket(row.get('tmp_02_registry_modifications_per_sec', 0.0))
    if rate: reg_parts.append(f"{rate} registry-modification rate")
    
    if row.get('rg_03_persistence_registry_mods', 0) > 0:
        reg_parts.append("persistence-related registry modification observed")
        
    if reg_parts:
        sections.append("Registry behavior: " + "; ".join(reg_parts) + ".")

    # 5. MEMORY BEHAVIOR
    mem_parts = []
    
    if row.get('mem_01_remote_threads_created', 0) > 0:
        mem_parts.append("remote-thread creation observed")
        
    if row.get('mem_02_cross_process_access', 0) > 0:
        mem_parts.append("cross-process memory access observed")
        
    if mem_parts:
        sections.append("Memory behavior: " + "; ".join(mem_parts) + ".")

    # 6. DLL BEHAVIOR
    dll_parts = []
    
    vol = get_volume_bucket(row.get('dll_01_image_load_count', 0))
    if vol: dll_parts.append(f"{vol.replace('-volume', '')} DLL-load volume")
    
    if row.get('dll_02_unsigned_image_load_count', 0) > 0:
        dll_parts.append("unsigned DLL activity observed")
        
    if dll_parts:
        sections.append("DLL behavior: " + "; ".join(dll_parts) + ".")

    # FINAL ASSEMBLY
    if not sections:
        return "No monitored behavioral events were observed during this window."
        
    return " ".join(sections)
