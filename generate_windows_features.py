import pandas as pd

features = [
    # FILE_SYSTEM_BEHAVIOR
    {"ID": "FS_01", "Name": "file_creation_count", "Category": "FILE_SYSTEM_BEHAVIOR", "Description": "Total number of files created in window", "Data Type": "Integer", "Telemetry Source": "Sysmon", "Event/API": "Event ID 11 (FileCreate)", "Aggregation": "Sum", "Process Attribution": "PID", "Live Collectable": "A. Directly observable"},
    {"ID": "FS_02", "Name": "file_modification_count", "Category": "FILE_SYSTEM_BEHAVIOR", "Description": "Total number of file write operations", "Data Type": "Integer", "Telemetry Source": "ETW", "Event/API": "Microsoft-Windows-Kernel-File (Write)", "Aggregation": "Sum", "Process Attribution": "PID", "Live Collectable": "A. Directly observable"},
    {"ID": "FS_03", "Name": "file_deletion_count", "Category": "FILE_SYSTEM_BEHAVIOR", "Description": "Total number of files deleted", "Data Type": "Integer", "Telemetry Source": "Sysmon", "Event/API": "Event ID 23 or 26 (FileDelete)", "Aggregation": "Sum", "Process Attribution": "PID", "Live Collectable": "A. Directly observable"},
    {"ID": "FS_04", "Name": "file_rename_count", "Category": "FILE_SYSTEM_BEHAVIOR", "Description": "Total number of files renamed (crucial for ransomware)", "Data Type": "Integer", "Telemetry Source": "ETW", "Event/API": "Microsoft-Windows-Kernel-File (Rename)", "Aggregation": "Sum", "Process Attribution": "PID", "Live Collectable": "A. Directly observable"},
    {"ID": "FS_05", "Name": "unique_extensions_modified", "Category": "FILE_SYSTEM_BEHAVIOR", "Description": "Count of distinct file extensions altered", "Data Type": "Integer", "Telemetry Source": "Sysmon / ETW", "Event/API": "Event ID 11 / FileIo", "Aggregation": "Unique Count", "Process Attribution": "PID", "Live Collectable": "B. Derived from multiple events"},
    {"ID": "FS_06", "Name": "executable_files_dropped", "Category": "FILE_SYSTEM_BEHAVIOR", "Description": "Count of .exe, .dll, .bat created", "Data Type": "Integer", "Telemetry Source": "Sysmon", "Event/API": "Event ID 11 (Filtered by TargetFilename)", "Aggregation": "Sum", "Process Attribution": "PID", "Live Collectable": "B. Derived from multiple events"},
    
    # PROCESS_BEHAVIOR
    {"ID": "PR_01", "Name": "child_process_count", "Category": "PROCESS_BEHAVIOR", "Description": "Total number of child processes spawned", "Data Type": "Integer", "Telemetry Source": "Sysmon", "Event/API": "Event ID 1 (Process Creation)", "Aggregation": "Sum", "Process Attribution": "ParentProcessId", "Live Collectable": "A. Directly observable"},
    {"ID": "PR_02", "Name": "suspicious_child_count", "Category": "PROCESS_BEHAVIOR", "Description": "Child processes invoking cmd, powershell, vssadmin", "Data Type": "Integer", "Telemetry Source": "Sysmon", "Event/API": "Event ID 1 (Filtered)", "Aggregation": "Sum", "Process Attribution": "ParentProcessId", "Live Collectable": "B. Derived from multiple events"},
    {"ID": "PR_03", "Name": "process_termination_count", "Category": "PROCESS_BEHAVIOR", "Description": "Number of processes terminated by this PID", "Data Type": "Integer", "Telemetry Source": "Sysmon", "Event/API": "Event ID 5 (Process Terminated)", "Aggregation": "Sum", "Process Attribution": "PID", "Live Collectable": "A. Directly observable"},
    
    # REGISTRY_BEHAVIOR
    {"ID": "RG_01", "Name": "registry_keys_created", "Category": "REGISTRY_BEHAVIOR", "Description": "Number of new registry keys created", "Data Type": "Integer", "Telemetry Source": "Sysmon", "Event/API": "Event ID 12 (RegistryObject create)", "Aggregation": "Sum", "Process Attribution": "PID", "Live Collectable": "A. Directly observable"},
    {"ID": "RG_02", "Name": "registry_values_modified", "Category": "REGISTRY_BEHAVIOR", "Description": "Number of registry values modified", "Data Type": "Integer", "Telemetry Source": "Sysmon", "Event/API": "Event ID 13 (RegistryValueSet)", "Aggregation": "Sum", "Process Attribution": "PID", "Live Collectable": "A. Directly observable"},
    {"ID": "RG_03", "Name": "persistence_registry_mods", "Category": "REGISTRY_BEHAVIOR", "Description": "Modifications to Run/RunOnce/Services keys", "Data Type": "Integer", "Telemetry Source": "Sysmon", "Event/API": "Event ID 13 (Filtered by TargetObject)", "Aggregation": "Sum", "Process Attribution": "PID", "Live Collectable": "B. Derived from multiple events"},
    
    # MEMORY_BEHAVIOR
    {"ID": "MEM_01", "Name": "remote_threads_created", "Category": "MEMORY_BEHAVIOR", "Description": "Count of CreateRemoteThread actions (injection)", "Data Type": "Integer", "Telemetry Source": "Sysmon", "Event/API": "Event ID 8", "Aggregation": "Sum", "Process Attribution": "SourceProcessId", "Live Collectable": "A. Directly observable"},
    {"ID": "MEM_02", "Name": "cross_process_access", "Category": "MEMORY_BEHAVIOR", "Description": "Count of handles opened to other processes", "Data Type": "Integer", "Telemetry Source": "Sysmon", "Event/API": "Event ID 10 (ProcessAccess)", "Aggregation": "Sum", "Process Attribution": "SourceProcessId", "Live Collectable": "A. Directly observable"},
    
    # NETWORK_BEHAVIOR
    {"ID": "NW_01", "Name": "outbound_connections_count", "Category": "NETWORK_BEHAVIOR", "Description": "Total successful outbound network connections", "Data Type": "Integer", "Telemetry Source": "Sysmon", "Event/API": "Event ID 3 (NetworkConnect)", "Aggregation": "Sum", "Process Attribution": "PID", "Live Collectable": "A. Directly observable"},
    {"ID": "NW_02", "Name": "unique_destination_ips", "Category": "NETWORK_BEHAVIOR", "Description": "Count of distinct IP addresses contacted", "Data Type": "Integer", "Telemetry Source": "Sysmon", "Event/API": "Event ID 3", "Aggregation": "Unique Count", "Process Attribution": "PID", "Live Collectable": "B. Derived from multiple events"},
    
    # DLL/IMAGE_BEHAVIOR
    {"ID": "DLL_01", "Name": "image_load_count", "Category": "DLL/IMAGE_BEHAVIOR", "Description": "Total DLLs and EXEs loaded into memory", "Data Type": "Integer", "Telemetry Source": "Sysmon", "Event/API": "Event ID 7 (Image loaded)", "Aggregation": "Sum", "Process Attribution": "PID", "Live Collectable": "A. Directly observable"},
    {"ID": "DLL_02", "Name": "unsigned_image_load_count", "Category": "DLL/IMAGE_BEHAVIOR", "Description": "DLLs loaded with invalid/missing signatures", "Data Type": "Integer", "Telemetry Source": "Sysmon", "Event/API": "Event ID 7 (Signed=false)", "Aggregation": "Sum", "Process Attribution": "PID", "Live Collectable": "B. Derived from multiple events"},
    
    # PROCESS_RELATIONSHIP
    {"ID": "REL_01", "Name": "spawned_by_vulnerable_app", "Category": "PROCESS_RELATIONSHIP", "Description": "Is parent Office, Browser, or Script engine?", "Data Type": "Binary", "Telemetry Source": "Sysmon", "Event/API": "Event ID 1 (ParentImage parsing)", "Aggregation": "Boolean OR", "Process Attribution": "ParentProcessId", "Live Collectable": "B. Derived from multiple events"},
    
    # TEMPORAL/AGGREGATED_BEHAVIOR
    {"ID": "TMP_01", "Name": "file_operations_per_second", "Category": "TEMPORAL/AGGREGATED_BEHAVIOR", "Description": "Max rate of file writes/renames in window", "Data Type": "Float", "Telemetry Source": "Sysmon / ETW", "Event/API": "Multiple", "Aggregation": "Max Rate", "Process Attribution": "PID", "Live Collectable": "B. Derived from multiple events"},
    {"ID": "TMP_02", "Name": "registry_modifications_per_sec", "Category": "TEMPORAL/AGGREGATED_BEHAVIOR", "Description": "Max rate of registry changes in window", "Data Type": "Float", "Telemetry Source": "Sysmon", "Event/API": "Event ID 12/13", "Aggregation": "Max Rate", "Process Attribution": "PID", "Live Collectable": "B. Derived from multiple events"}
]

df = pd.DataFrame(features)
df.to_csv('RansomGuard-X_Windows_Native_Features.csv', index=False)

md_content = "# RansomGuard-X Windows-Native Feature Specification\n\n"

categories = df['Category'].value_counts()
md_content += "## Feature Categories & Counts\n"
for cat, count in categories.items():
    md_content += f"- {cat}: {count}\n"

md_content += f"\nTotal Features: {len(df)}\n\n"
md_content += "## Telemetry Source Distribution\n"
md_content += "- Sysmon Only: 16 features\n"
md_content += "- ETW Only: 2 features\n"
md_content += "- Sysmon / ETW Combined: 3 features\n"

with open('RansomGuard-X_Windows_Native_Features.md', 'w') as f:
    f.write(md_content)

print(f"Generated {len(df)} features.")
