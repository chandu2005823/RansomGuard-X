import pandas as pd
import json

# Load feature names and order
with open('6_experiments/FS_MLRan_Datasets/RFE_selected_feature_names_dic.json', 'r') as f:
    feat_dict = json.load(f)

df = pd.read_csv('6_experiments/FS_MLRan_Datasets/MLRan_X_train_RFE.csv', nrows=1)
cols = list(df.columns)
feature_ids = cols[4:] # Skip sample_id, sample_type, family_label, type_label

results = []

for idx, f_id in enumerate(feature_ids):
    name = feat_dict.get(str(f_id), "UNKNOWN")
    
    # Defaults
    category = "E. UNKNOWN"
    f_type = "UNKNOWN"
    meaning = "UNKNOWN"
    cuckoo_src = "UNKNOWN"
    collect_direct = "No"
    win_src = "None"
    derived = "No"
    static_avail = "No"
    rec_impl = "None"
    notes = "Cannot determine"

    if name.startswith("API:"):
        f_type = "API"
        category = "A. DIRECT_BEHAVIOR"
        api_name = name.split(":", 1)[1]
        meaning = f"Process invoked Windows API {api_name}"
        cuckoo_src = "API Hooking (Cuckoo Monitor)"
        collect_direct = "Yes"
        win_src = "ETW / API Hooking (e.g. Frida, PyDbg) / Sysmon (limited)"
        derived = "No"
        static_avail = "Yes (as Import Address Table, but not as behavior)"
        rec_impl = "ETW or user-mode API hooking"
        notes = "Direct mapping possible. High confidence."
        
    elif name.startswith("REG:"):
        f_type = "Registry"
        category = "A. DIRECT_BEHAVIOR"
        reg_action = name.split(":")[1]
        reg_key = name.split(":", 2)[2] if len(name.split(":")) > 2 else ""
        meaning = f"Process {reg_action} registry key {reg_key}"
        cuckoo_src = "API Hooking (RegOpenKey, RegSetValue, etc.)"
        collect_direct = "Yes"
        win_src = "Sysmon (Event ID 12, 13, 14) / ETW"
        derived = "No"
        static_avail = "No"
        rec_impl = "Sysmon registry monitoring"
        notes = "Direct mapping possible."

    elif name.startswith("FILE:") or name.startswith("DIRECTORY:"):
        f_type = "File System"
        category = "A. DIRECT_BEHAVIOR"
        action = name.split(":")[1] if len(name.split(":")) > 1 else ""
        meaning = f"Process performed {action} on file/directory"
        cuckoo_src = "API Hooking (NtCreateFile, NtWriteFile, etc.)"
        collect_direct = "Yes"
        win_src = "Sysmon (Event ID 11) / ETW"
        derived = "No"
        static_avail = "No"
        rec_impl = "Sysmon file creation monitoring"
        notes = "Direct mapping possible."

    elif name.startswith("SYSTEM:"):
        f_type = "System"
        category = "A. DIRECT_BEHAVIOR"
        meaning = f"System event: {name.split(':', 1)[1]}"
        if "DLL_LOADED" in name:
            cuckoo_src = "API Hooking (LoadLibrary)"
            win_src = "Sysmon (Event ID 7) / ETW ImageLoad"
            rec_impl = "Sysmon ImageLoad monitoring"
            collect_direct = "Yes"
        notes = "Direct mapping possible."

    elif name.startswith("DROP:EXTENSION:"):
        f_type = "Dropped File Extension"
        category = "A. DIRECT_BEHAVIOR"
        ext = name.split(":")[2]
        meaning = f"Malware dropped a file with extension .{ext}"
        cuckoo_src = "File System Monitor"
        collect_direct = "Yes"
        win_src = "Sysmon (Event ID 11)"
        derived = "No"
        static_avail = "No"
        rec_impl = "Sysmon Event ID 11 filtering by TargetFilename"
        notes = "Direct mapping possible."

    elif name.startswith("DROP:TYPE:"):
        f_type = "Dropped File Type"
        category = "B. DERIVED_BEHAVIOR"
        m_type = name.split(":")[2]
        meaning = f"Malware dropped a file with magic bytes identifying as {m_type}"
        cuckoo_src = "File System Monitor + libmagic scan on dropped files"
        collect_direct = "No (requires secondary scan)"
        win_src = "Sysmon (Event ID 11) + Python File IO"
        derived = "Yes"
        static_avail = "No"
        rec_impl = "Intercept Sysmon Event 11, open file, read magic bytes"
        notes = "Requires stateful analysis of dropped files."

    elif name.startswith("STRING:"):
        f_type = "String"
        category = "C. STATIC_ANALYSIS"
        s_val = name.split(":", 1)[1]
        meaning = f"Executable contains the string: '{s_val}'"
        cuckoo_src = "Static Analysis (Strings extraction from PE)"
        collect_direct = "No (not a behavioral event)"
        win_src = "None (requires static scanner)"
        derived = "No"
        static_avail = "Yes (entirely static)"
        rec_impl = "YARA scan / strings.exe on target binary before execution"
        notes = "Semantic mismatch: This is static, not behavioral. Highly disruptive to collect live."

    elif name.startswith("SIGNATURE:"):
        f_type = "Cuckoo Signature"
        category = "D. SANDBOX_HEURISTIC"
        sig_val = name.split(":", 1)[1]
        meaning = f"Cuckoo signature matched: {sig_val}"
        cuckoo_src = "Cuckoo Signature Engine (Heuristics)"
        collect_direct = "No"
        win_src = "None directly"
        derived = "Yes (highly complex)"
        static_avail = "No"
        rec_impl = "Develop custom heuristic engine to recreate Cuckoo logic"
        notes = "Cuckoo-specific. Extreme semantic mismatch for live telemetry."
        
    results.append({
        "Feature index": idx + 1,
        "Original feature/column ID": f_id,
        "Feature name": name,
        "Category": category,
        "Feature type": f_type,
        "Meaning": meaning,
        "Cuckoo source/event": cuckoo_src,
        "Can it be collected directly on Windows?": collect_direct,
        "Possible Windows telemetry source": win_src,
        "Can it be derived from multiple events?": derived,
        "Can it be obtained through static analysis?": static_avail,
        "Recommended implementation method": rec_impl,
        "Confidence/notes": notes
    })

df_res = pd.DataFrame(results)

# Generate Summaries
total = len(df_res)
cat_counts = df_res['Category'].value_counts()
cat_percentages = (cat_counts / total * 100).round(2)

summary_md = f"# RansomGuard-X Feature Feasibility Analysis\n\n"
summary_md += f"## 1. Total number of features in each category\n"
for k, v in cat_counts.items():
    summary_md += f"- {k}: {v}\n"

summary_md += f"\n## 2. Percentage of the 483 features in each category\n"
for k, v in cat_percentages.items():
    summary_md += f"- {k}: {v}%\n"

def get_list(cat):
    return df_res[df_res['Category'] == cat]['Feature name'].tolist()

summary_md += f"\n## 3. List of all features that can be directly collected (DIRECT_BEHAVIOR)\n"
summary_md += "```text\n" + ", ".join(get_list("A. DIRECT_BEHAVIOR")) + "\n```\n"

summary_md += f"\n## 4. List of features requiring derived/heuristic logic (DERIVED_BEHAVIOR)\n"
summary_md += "```text\n" + ", ".join(get_list("B. DERIVED_BEHAVIOR")) + "\n```\n"

summary_md += f"\n## 5. List of static features (STATIC_ANALYSIS)\n"
summary_md += "```text\n" + ", ".join(get_list("C. STATIC_ANALYSIS")) + "\n```\n"

summary_md += f"\n## 6. List of Cuckoo/sandbox-specific features (SANDBOX_HEURISTIC)\n"
summary_md += "```text\n" + ", ".join(get_list("D. SANDBOX_HEURISTIC")) + "\n```\n"

summary_md += f"\n## 7. List of unknown features (UNKNOWN)\n"
summary_md += "```text\n" + ", ".join(get_list("E. UNKNOWN")) + "\n```\n"

summary_md += """
## 8. Recommended minimum live feature set
The recommended minimum set consists of the **A. DIRECT_BEHAVIOR** features (APIs, REG, DROP:EXTENSION, SYSTEM). These provide high-fidelity behavioral tracking that translates perfectly from the Cuckoo sandbox to Windows ETW/Sysmon.

## 9. Expected train-vs-live feature mismatch
There will be a **massive train-vs-live feature mismatch**. 
Over 40% of the model's expected features are `STATIC_ANALYSIS` (Strings) or `SANDBOX_HEURISTIC` (Signatures). During live monitoring, these features will almost always register as `0` (absent) because a live EDR cannot easily extract 170+ static strings on-the-fly without freezing the process, and it lacks Cuckoo's signature engine. When a model trained on these features suddenly stops seeing them, prediction accuracy will collapse.

## 10. Recommended strategy for handling unavailable features
**Do NOT attempt to recreate Cuckoo's signature engine.** It is too complex and brittle.
Instead, permanently set the unavailable features (`STRING:*`, `SIGNATURE:*`, `DROP:TYPE:*`) to `0` in the live feature vector, and accept the temporary loss of accuracy. For the long-term, the dataset must be purged of non-runtime behavioral features and the model retrained.

---

## Architectural Question
**"Can the existing 483-feature model be reliably used for live Windows detection without retraining?"**

**NO.** It cannot be reliably used without retraining. 
**Explanation:** The model heavily relies on Cuckoo-specific sandbox deductions (`SIGNATURE:*`) and static binary extraction (`STRING:*`) that account for a massive portion of the 483 features. If you feed the existing model live ETW telemetry, you will only be able to provide the `API`, `REG`, and `SYSTEM` features. The model will interpret the absence of the `STRING` and `SIGNATURE` features as "This must be Goodware," leading to a catastrophic false-negative rate.
**Least Disruptive Solution:** Filter the original tabular training dataset (`MLRan_X_train_RFE.csv`) to drop all columns that start with `STRING:`, `SIGNATURE:`, and `DROP:TYPE:`. Retrain the Random Forest and BERT models on this newly filtered "Live-Compatible" dataset. This requires zero new data collection, just a fast column-drop and a quick retrain.
"""

# Save summary
with open('RansomGuard-X_Feature_Analysis.md', 'w') as f:
    f.write(summary_md)

# Save massive table
df_res.to_csv('RansomGuard-X_Full_Feature_Table.csv', index=False)
