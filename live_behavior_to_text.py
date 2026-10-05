import pandas as pd

def convert_21_features_to_text(row):
    """
    Converts the 21-feature numerical Windows telemetry vector into structured 
    behavioral text suitable for Transformer ingestion (Option-B integration).
    """
    
    sections = []
    
    # --- FILE SYSTEM ---
    fs_text = []
    if row.get('fs_01_creation_count', 0) > 0:
        fs_text.append(f"created {int(row['fs_01_creation_count'])} files")
    if row.get('fs_02_modification_count', 0) > 0:
        fs_text.append(f"modified {int(row['fs_02_modification_count'])} files")
    if row.get('fs_03_deletion_count', 0) > 0:
        fs_text.append(f"deleted {int(row['fs_03_deletion_count'])} files")
    if row.get('fs_04_rename_count', 0) > 0:
        fs_text.append(f"renamed {int(row['fs_04_rename_count'])} files")
    if row.get('fs_05_unique_extensions_modified', 0) > 0:
        fs_text.append(f"modified {int(row['fs_05_unique_extensions_modified'])} unique file extensions")
    if row.get('fs_06_executable_files_dropped', 0) > 0:
        fs_text.append(f"dropped {int(row['fs_06_executable_files_dropped'])} executable files")
    if fs_text:
        sections.append("File behavior: " + ", ".join(fs_text) + ".")
        
    # --- PROCESS ---
    pr_text = []
    if row.get('pr_01_child_process_count', 0) > 0:
        pr_text.append(f"spawned {int(row['pr_01_child_process_count'])} child processes")
    if row.get('pr_02_suspicious_child_count', 0) > 0:
        pr_text.append(f"spawned {int(row['pr_02_suspicious_child_count'])} suspicious processes")
    if row.get('pr_03_process_termination_count', 0) > 0:
        pr_text.append(f"terminated {int(row['pr_03_process_termination_count'])} processes")
    if pr_text:
        sections.append("Process behavior: " + ", ".join(pr_text) + ".")
        
    # --- REGISTRY ---
    rg_text = []
    if row.get('rg_01_registry_keys_created', 0) > 0:
        rg_text.append(f"created {int(row['rg_01_registry_keys_created'])} registry keys")
    if row.get('rg_02_registry_values_modified', 0) > 0:
        rg_text.append(f"modified {int(row['rg_02_registry_values_modified'])} registry values")
    if row.get('rg_03_persistence_registry_mods', 0) > 0:
        rg_text.append(f"performed {int(row['rg_03_persistence_registry_mods'])} persistence registry modifications")
    if rg_text:
        sections.append("Registry behavior: " + ", ".join(rg_text) + ".")
        
    # --- MEMORY ---
    mem_text = []
    if row.get('mem_01_remote_threads_created', 0) > 0:
        mem_text.append(f"created {int(row['mem_01_remote_threads_created'])} remote threads")
    if row.get('mem_02_cross_process_access', 0) > 0:
        mem_text.append(f"accessed {int(row['mem_02_cross_process_access'])} cross-process memory spaces")
    if mem_text:
        sections.append("Memory behavior: " + ", ".join(mem_text) + ".")
        
    # --- NETWORK ---
    nw_text = []
    if row.get('nw_01_outbound_connections_count', 0) > 0:
        nw_text.append(f"made {int(row['nw_01_outbound_connections_count'])} outbound connections")
    if row.get('nw_02_unique_destination_ips', 0) > 0:
        nw_text.append(f"connected to {int(row['nw_02_unique_destination_ips'])} unique IPs")
    if nw_text:
        sections.append("Network behavior: " + ", ".join(nw_text) + ".")
        
    # --- DLL ---
    dll_text = []
    if row.get('dll_01_image_load_count', 0) > 0:
        dll_text.append(f"loaded {int(row['dll_01_image_load_count'])} DLL images")
    if row.get('dll_02_unsigned_image_load_count', 0) > 0:
        dll_text.append(f"loaded {int(row['dll_02_unsigned_image_load_count'])} unsigned DLL images")
    if dll_text:
        sections.append("DLL behavior: " + ", ".join(dll_text) + ".")
        
    # --- RELATIONSHIP ---
    rel_text = []
    if row.get('rel_01_spawned_by_vulnerable_app', 0) > 0:
        rel_text.append("spawned by a vulnerable application")
    if rel_text:
        sections.append("Relationship behavior: " + ", ".join(rel_text) + ".")
        
    # --- TEMPORAL ---
    tmp_text = []
    if row.get('tmp_01_file_operations_per_second', 0) > 0:
        tmp_text.append(f"{float(row['tmp_01_file_operations_per_second']):.2f} file operations per second")
    if row.get('tmp_02_registry_modifications_per_sec', 0) > 0:
        tmp_text.append(f"{float(row['tmp_02_registry_modifications_per_sec']):.2f} registry modifications per second")
    if tmp_text:
        sections.append("Temporal behavior: " + ", ".join(tmp_text) + ".")

    if not sections:
        return "The process performed no observable malicious behavior during this window."
        
    return " ".join(sections)

def test_conversion():
    csv_path = '5_mlran_dataset/Phase5A_Live_Telemetry/phase5a_benign_telemetry.csv'
    try:
        df = pd.read_csv(csv_path)
    except FileNotFoundError:
        print(f"Test CSV not found at {csv_path}")
        return
        
    print("--- Option-B Transformer Integration Offline Test ---")
    
    # Find a row that has some activity, rather than all zeroes if possible
    # Just take row 0 first
    row = df.iloc[0]
    
    # Extract the 21 features strictly
    features_21 = [
        'fs_01_creation_count', 'fs_02_modification_count', 'fs_03_deletion_count', 'fs_04_rename_count', 
        'fs_05_unique_extensions_modified', 'fs_06_executable_files_dropped', 'pr_01_child_process_count', 
        'pr_02_suspicious_child_count', 'pr_03_process_termination_count', 'rg_01_registry_keys_created', 
        'rg_02_registry_values_modified', 'rg_03_persistence_registry_mods', 'mem_01_remote_threads_created', 
        'mem_02_cross_process_access', 'nw_01_outbound_connections_count', 'nw_02_unique_destination_ips', 
        'dll_01_image_load_count', 'dll_02_unsigned_image_load_count', 'rel_01_spawned_by_vulnerable_app', 
        'tmp_01_file_operations_per_second', 'tmp_02_registry_modifications_per_sec'
    ]
    
    # Print numerical features
    print("\n[Input 21-Feature Vector]")
    for feat in features_21:
        if feat in row:
            print(f"  {feat}: {row[feat]}")
            
    # Generate text
    text_output = convert_21_features_to_text(row)
    print("\n[Generated Behavioral Text]")
    print(text_output)
    
if __name__ == "__main__":
    test_conversion()
