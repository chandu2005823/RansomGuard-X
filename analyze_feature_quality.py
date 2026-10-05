import pandas as pd
import json

def analyze_features():
    train_df = pd.read_csv('6_experiments/historical_common_train.csv')
    test_df = pd.read_csv('6_experiments/historical_common_test.csv')
    
    # Combine or just analyze train?
    # Prompt says "Analyze historical_common_train.csv and historical_common_test.csv"
    df = pd.concat([train_df, test_df], ignore_index=True)
    
    # 11 features we kept
    features = [
        "dll_01_image_load_count",
        "fs_02_modification_count",
        "pr_01_child_process_count",
        "mem_02_cross_process_access",
        "rg_01_registry_keys_created",
        "rg_02_registry_values_modified",
        "fs_06_executable_files_dropped",
        "rg_03_persistence_registry_mods",
        "mem_01_remote_threads_created",
        "pr_02_suspicious_child_count",
        "nw_01_outbound_connections_count"
    ]
    
    status_map = {
        "dll_01_image_load_count": "PROXY",
        "fs_02_modification_count": "PROXY",
        "pr_01_child_process_count": "DIRECT",
        "mem_02_cross_process_access": "DIRECT",
        "rg_01_registry_keys_created": "DIRECT",
        "rg_02_registry_values_modified": "DIRECT",
        "fs_06_executable_files_dropped": "DIRECT",
        "rg_03_persistence_registry_mods": "DIRECT",
        "mem_01_remote_threads_created": "DIRECT",
        "pr_02_suspicious_child_count": "PROXY",
        "nw_01_outbound_connections_count": "PROXY"
    }
    
    report = {}
    
    df_0 = df[df['sample_type'] == 0]
    df_1 = df[df['sample_type'] == 1]
    
    def get_stats(data, feat):
        if len(data) == 0:
            return {"non_zero_pct": 0, "mean": 0, "median": 0, "min": 0, "max": 0}
        vals = data[feat]
        non_zero = (vals > 0).mean() * 100
        return {
            "non_zero_pct": round(non_zero, 2),
            "mean": round(vals.mean(), 4),
            "median": round(vals.median(), 4),
            "min": int(vals.min()),
            "max": int(vals.max())
        }

    for feat in features:
        stats_0 = get_stats(df_0, feat)
        stats_1 = get_stats(df_1, feat)
        
        # Is it a true count or just binary?
        max_val_overall = max(stats_0["max"], stats_1["max"])
        is_binary = max_val_overall <= 1
        
        # Meaningful separation? (heuristic: difference in non_zero_pct > 5% or mean diff is significant)
        diff_non_zero = abs(stats_1["non_zero_pct"] - stats_0["non_zero_pct"])
        separation = "YES" if diff_non_zero >= 5.0 else "NO"
        
        # Too sparse? (< 1% overall)
        overall_non_zero = (df[feat] > 0).mean() * 100
        is_sparse = overall_non_zero < 1.0
        
        warning = ""
        if is_sparse:
            warning = "TOO SPARSE (<1% presence). "
        if not is_binary and status_map[feat] == 'PROXY':
            warning += "PROXY aggregate acts as a pseudo-count. "
        if separation == "NO":
            warning += "POOR CLASS SEPARATION. "
            
        report[feat] = {
            "status": status_map[feat],
            "is_true_count": not is_binary,
            "class_0_Goodware": stats_0,
            "class_1_Ransomware": stats_1,
            "meaningful_separation": separation,
            "flags": warning.strip() if warning else "OK"
        }
        
    with open('6_experiments/common_feature_quality_report.json', 'w') as f:
        json.dump(report, f, indent=2)
        
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    analyze_features()
