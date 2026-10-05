import pandas as pd
import json

df = pd.read_csv('RansomGuard-X_Full_Feature_Table.csv')
direct_df = df[df['Category'] == 'A. DIRECT_BEHAVIOR'].copy()

results = []
metrics = {"DIRECT_MATCH": 0, "DERIVABLE": 0, "APPROXIMATE_MATCH": 0, "NOT_AVAILABLE": 0}

for _, row in direct_df.iterrows():
    f_name = row['Feature name']
    f_idx = row['Feature index']
    f_id = row['Original feature/column ID']
    f_type = row['Feature type']
    
    proposed_src = ""
    exact_event = ""
    coll_method = ""
    proc_attr = "PID matching"
    conf = ""
    notes = ""
    
    if f_name.startswith("SYSTEM:DLL_LOADED:"):
        dll = f_name.split(":")[2]
        proposed_src = "ETW / Sysmon"
        exact_event = "ETW: ImageLoad / Sysmon: Event 7"
        coll_method = "DIRECT_MATCH"
        conf = "High"
        notes = f"Matches exact DLL load: {dll}"
        
    elif f_name.startswith("SYSTEM:GUID:"):
        proposed_src = "API Hooking (CoCreateInstance)"
        exact_event = "None in standard ETW/Sysmon"
        coll_method = "NOT_AVAILABLE"
        conf = "Low"
        notes = "COM object instantiations cannot be easily collected via standard Sysmon."
        
    elif f_name.startswith("DROP:EXTENSION:"):
        ext = f_name.split(":")[2]
        proposed_src = "Sysmon"
        exact_event = "Sysmon: Event 11 (File Create)"
        coll_method = "DERIVABLE"
        conf = "High"
        notes = f"Parse TargetFilename for .{ext}"
        
    elif f_name.startswith("REG:"):
        proposed_src = "Sysmon / ETW"
        exact_event = "Sysmon: Event 12,13,14 / ETW: Registry"
        coll_method = "DIRECT_MATCH"
        conf = "High"
        notes = "Captures exact registry key/value interaction."
        
    elif f_name.startswith("FILE:") or f_name.startswith("DIRECTORY:"):
        proposed_src = "Sysmon / ETW"
        exact_event = "Sysmon: Event 11 / ETW: FileIo"
        coll_method = "APPROXIMATE_MATCH"
        conf = "Medium"
        notes = "Abstracts away exact API used to write/create."
        
    elif f_name.startswith("API:"):
        api = f_name.split(":", 1)[1]
        
        # Memory / Injection APIs
        if api in ["NtProtectVirtualMemory", "VirtualAllocEx", "WriteProcessMemory", "NtAllocateVirtualMemory", "NtSetContextThread", "NtGetContextThread"]:
            proposed_src = "ETW (TiEtw) / Sysmon"
            exact_event = "Sysmon: Event 8 (CreateRemoteThread) / ETW Threat-Intelligence"
            coll_method = "APPROXIMATE_MATCH"
            conf = "Medium"
            notes = "TiEtw requires PPL. Sysmon approximates memory access."
            
        # Process / Thread APIs
        elif api in ["CreateProcessInternalW", "NtOpenProcess", "OpenServiceW", "CreateToolhelp32Snapshot", "EnumProcesses", "GetExitCodeProcess", "Process32NextW", "SetServiceStatus"]:
            proposed_src = "ETW / Sysmon"
            exact_event = "Sysmon: Event 1, 10"
            coll_method = "APPROXIMATE_MATCH"
            conf = "Medium"
            notes = "Sysmon logs process create/access, not the specific internal API."
            
        # File / IO APIs
        elif api in ["NtWriteFile", "NtQueryInformationFile", "FlushFileBuffers", "GetTempPathW", "GetTempFileNameA", "GetFileAttributesA", "SetFilePointerEx", "SetFileTime", "ReadFile"]:
            proposed_src = "ETW / Sysmon"
            exact_event = "Sysmon: Event 11 / ETW FileIo"
            coll_method = "APPROXIMATE_MATCH"
            conf = "Low"
            notes = "ETW/Sysmon tracks the action (File Write) but abstracts the specific API call (NtWriteFile vs WriteFile)."
            
        # Pure User-Mode / Helper APIs (No ETW/Sysmon equivalent without hooking)
        else:
            proposed_src = "API Hooking (e.g., Frida, Detours)"
            exact_event = "None in standard ETW/Sysmon"
            coll_method = "NOT_AVAILABLE"
            conf = "Low"
            notes = f"Silent user-mode API ({api}). Cannot be collected via standard Windows telemetry without injecting a hooking DLL."
            
    metrics[coll_method] += 1
            
    results.append({
        "Feature index": f_idx,
        "Original feature/column ID": f_id,
        "Feature name": f_name,
        "Category": "A. DIRECT_BEHAVIOR",
        "Feature type": f_type,
        "Meaning": row["Meaning"],
        "Cuckoo source/event": row["Cuckoo source/event"],
        "Proposed Windows Source": proposed_src,
        "Exact Windows Event/API": exact_event,
        "Collection Method": coll_method,
        "Process Attribution": proc_attr,
        "Confidence": conf,
        "Notes": notes
    })

res_df = pd.DataFrame(results)
res_df.to_csv("RansomGuard-X_Telemetry_Validation.csv", index=False)

import sys
print(f"1. DIRECT_MATCH: {metrics['DIRECT_MATCH']}")
print(f"2. DERIVABLE: {metrics['DERIVABLE']}")
print(f"3. APPROXIMATE_MATCH: {metrics['APPROXIMATE_MATCH']}")
print(f"4. NOT_AVAILABLE: {metrics['NOT_AVAILABLE']}")
pct = ((metrics['DIRECT_MATCH'] + metrics['DERIVABLE'] + metrics['APPROXIMATE_MATCH']) / len(direct_df)) * 100
print(f"5. Percentage realistic reproduction: {pct:.2f}%")
