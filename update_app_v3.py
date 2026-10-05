import os

NEW_APP_CONTENT = """import streamlit as st
import pandas as pd
import time
import os
import re
from datetime import datetime

# ML Inference Engine and Alert Logger
try:
    from ml_inference import MLInferenceEngine
    from alert_logger import AlertLogger
    from response_engine import SafeMitigator
    from live_bert_inference import LiveBERTInference
    from bert_xai import BertXAI
    from live_detection_pipeline import LiveDetectionPipeline
except ImportError as e:
    st.error(f"Failed to import modules: {e}")

st.set_page_config(page_title="RansomGuard-X SOC", layout="wide", initial_sidebar_state="expanded")

# --- CUSTOM CSS FOR SOC THEME ---
st.markdown(\"""
<style>
    .threat-card-safe { background-color: #0E2A15; border: 2px solid #3FB950; border-radius: 10px; padding: 25px; text-align: center; margin-bottom: 20px; }
    .threat-card-alert { background-color: #2D1114; border: 2px solid #F85149; border-radius: 10px; padding: 25px; text-align: center; margin-bottom: 20px; }
    .threat-card-pending { background-color: #2D2311; border: 2px solid #D29922; border-radius: 10px; padding: 25px; text-align: center; margin-bottom: 20px; }
    
    .threat-title { font-size: 2.5rem; font-weight: 900; letter-spacing: 2px; margin-bottom: 5px; }
    .threat-sub { font-size: 1.1rem; color: #8B949E; }
    
    .metric-card { background-color: #1E2530; border: 1px solid #2C3545; border-radius: 8px; padding: 15px; text-align: center; }
    .metric-title { color: #8B949E; font-size: 0.85rem; text-transform: uppercase; font-weight: 600; margin-bottom: 5px; }
    .metric-value { color: #E6EDF3; font-size: 1.1rem; font-weight: bold; }
    
    .status-safe { color: #3FB950; }
    .status-warn { color: #D29922; }
    .status-alert { color: #F85149; }
    .status-neutral { color: #8B949E; }
    
    .behavior-card { background-color: #161B22; border: 1px solid #30363D; border-radius: 8px; padding: 15px; margin-bottom: 20px; }
    .behavior-line { font-size: 1.05rem; color: #E6EDF3; margin-bottom: 8px; padding-left: 10px; border-left: 3px solid #58A6FF; }
    
    .section-title { font-size: 1.2rem; font-weight: 600; color: #C9D1D9; margin-top: 20px; margin-bottom: 10px; border-bottom: 1px solid #30363D; padding-bottom: 5px; }
    
    .feature-card { background-color: #161B22; border: 1px solid #30363D; border-radius: 6px; padding: 10px; margin-bottom: 10px; }
    .feature-group-title { color: #58A6FF; font-size: 0.9rem; font-weight: 600; margin-bottom: 8px; border-bottom: 1px solid #30363D; padding-bottom: 4px; }
    .feature-row { display: flex; justify-content: space-between; font-size: 0.85rem; margin-bottom: 3px; }
    .feature-name { color: #C9D1D9; }
    
    .val-zero { color: #8B949E; }
    .val-active { color: #58A6FF; font-weight: 600; }
    .val-high { color: #D29922; font-weight: bold; }
</style>
\""", unsafe_allow_html=True)

# Initialize Session State
if 'replay_index' not in st.session_state: st.session_state.replay_index = 0
if 'alerts' not in st.session_state: st.session_state.alerts = []
if 'is_playing' not in st.session_state: st.session_state.is_playing = False
if 'mitigation_logs' not in st.session_state: st.session_state.mitigation_logs = []

if 'model' not in st.session_state: st.session_state.model = MLInferenceEngine("6_experiments/windows_rf_model.pkl")
if 'bert_engine' not in st.session_state: st.session_state.bert_engine = LiveBERTInference()
if 'bert_xai' not in st.session_state: st.session_state.bert_xai = BertXAI(inference_engine=st.session_state.bert_engine)
if 'alert_logger' not in st.session_state: st.session_state.alert_logger = AlertLogger("ransomguard_alerts_demo.log")
if 'mitigator' not in st.session_state: st.session_state.mitigator = SafeMitigator(dry_run=True, log_file="ransomguard_mitigation_demo.log")

# --- 1. TOP HEADER ---
st.markdown(\"""
<div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 15px;">
    <div style="display: flex; align-items: center;">
        <div style="font-size: 2.2rem; margin-right: 15px;">🛡️</div>
        <div>
            <h1 style="margin: 0; padding: 0; font-size: 1.6rem; color: #E6EDF3; letter-spacing: 1px;">RANSOMGUARD-X</h1>
            <div style="color: #8B949E; font-size: 0.9rem; font-weight: 500;">AI-Powered Ransomware Detection & Response</div>
        </div>
    </div>
    <div style="text-align: right;">
        <span style="color: #3FB950; font-weight: bold; font-size: 0.9rem;">● MONITORING ACTIVE</span>
    </div>
</div>
\""", unsafe_allow_html=True)

# --- SIDEBAR CONTROL CENTER ---
st.sidebar.markdown("### 🎛️ RANSOMGUARD-X CONTROL CENTER")
st.sidebar.markdown("---")

st.sidebar.markdown("**Monitoring Mode**")
mode = st.sidebar.radio("Select Source:", ["REPLAY VALIDATION DATA", "LIVE BENIGN TELEMETRY"], label_visibility="collapsed")

st.sidebar.markdown("---")
st.sidebar.markdown("**Model Status**")
if st.session_state.model.is_available:
    st.sidebar.markdown("🟢 Legacy RF: **Loaded**")
else:
    st.sidebar.markdown("🔴 Legacy RF: **Offline**")

st.sidebar.markdown("🟡 Live-Domain BERT: **Not Trained**")

st.sidebar.markdown("---")
if mode == "LIVE BENIGN TELEMETRY":
    st.sidebar.markdown("**Live Controls**")
    capture_live = st.sidebar.button("Capture 10s Telemetry Snapshot", use_container_width=True)
else:
    st.sidebar.markdown("**Replay Controls**")
    col_prev, col_next = st.sidebar.columns(2)
    prev_clicked = col_prev.button("⏪ Prev", use_container_width=True)
    next_clicked = col_next.button("Next ⏩", use_container_width=True)
    play_clicked = st.sidebar.button("Play / Pause Auto-Replay", use_container_width=True)

feature_names = [
    "fs_01_creation_count", "fs_02_modification_count", "fs_03_deletion_count",
    "fs_04_rename_count", "fs_05_unique_extensions_modified", "fs_06_executable_files_dropped",
    "pr_01_child_process_count", "pr_02_suspicious_child_count", "pr_03_process_termination_count",
    "rg_01_registry_keys_created", "rg_02_registry_values_modified", "rg_03_persistence_registry_mods",
    "mem_01_remote_threads_created", "mem_02_cross_process_access",
    "nw_01_outbound_connections_count", "nw_02_unique_destination_ips",
    "dll_01_image_load_count", "dll_02_unsigned_image_load_count",
    "rel_01_spawned_by_vulnerable_app", "tmp_01_file_operations_per_second",
    "tmp_02_registry_modifications_per_sec"
]

def format_val(val, threshold_high=20):
    if val == 0: return f'<span class="val-zero">0</span>'
    elif val >= threshold_high: return f'<span class="val-high">{val}</span>'
    else: return f'<span class="val-active">{val}</span>'

def split_behavioral_text(text):
    if text == "No monitored behavioral events were observed during this window.":
        return [text]
    # Split by standard sentences
    parts = [p.strip() for p in text.split(". ") if p.strip()]
    if parts and not parts[-1].endswith("."): parts[-1] += "."
    return parts

def render_dashboard(vector, timestamp, label_gt="N/A", live_behavioral_text=None, is_replay=False):
    row = dict(zip(feature_names, vector))
    
    if live_behavioral_text: bert_text = live_behavioral_text
    else:
        from live_domain_converter import convert_live_21_to_text
        bert_text = convert_live_21_to_text(row)
        
    rf_is_ransomware, rf_prob = st.session_state.model.predict(vector) if st.session_state.model.is_available else (False, 0.0)
    rf_explanation = st.session_state.model.explain_prediction(vector) if st.session_state.model.is_available else []
    
    # 2. PRIMARY THREAT STATUS CARD
    is_bert_loaded = st.session_state.bert_engine.is_loaded
    bert_is_ransomware = None
    bert_prob = None
    bert_explanation = []
    
    if is_bert_loaded:
        # If the new Live-Domain BERT exists in the future, this handles it.
        # But for now, we know it's not loaded, so this won't execute.
        # (Assuming bert_engine.is_loaded will be True when Phase5B is done)
        bert_result = st.session_state.bert_engine.predict(row)
        bert_is_ransomware = (bert_result['prediction'] == 'Ransomware')
        bert_prob = bert_result['ransomware_probability']
        if sum(vector) > 0:
            xai_result = st.session_state.bert_xai.explain(row, num_samples=30)
            bert_explanation = xai_result.get('top_contributions', [])
            
    if is_replay:
        st.warning(f"⚠️ **REPLAY VALIDATION DATA:** Ground Truth Label: {label_gt}")
        
    if not is_bert_loaded:
        threat_class = "threat-card-pending"
        title_color = "#D29922"
        title_text = "🟡 ANALYSIS PENDING"
        sub_text = "Live-Domain BERT is not trained yet.<br>Telemetry collection is active."
        det_status = "Pending"
    else:
        if bert_is_ransomware:
            threat_class = "threat-card-alert"
            title_color = "#F85149"
            title_text = "🔴 RANSOMWARE DETECTED"
            sub_text = f"Risk Score: {bert_prob*100:.1f}%"
            det_status = "Alert"
            if f"{timestamp}" not in [a['time'] for a in st.session_state.alerts]:
                st.session_state.alerts.insert(0, {"time": timestamp, "prob": bert_prob, "type": "Behavioral Anomaly"})
        else:
            threat_class = "threat-card-safe"
            title_color = "#3FB950"
            title_text = "🟢 SYSTEM SAFE"
            sub_text = f"Risk Score: {bert_prob*100:.1f}%"
            det_status = "Safe"

    st.markdown(f\"""
    <div class="{threat_class}">
        <div class="threat-title" style="color: {title_color};">{title_text}</div>
        <div class="threat-sub">{sub_text}</div>
    </div>
    \""", unsafe_allow_html=True)

    # 3. TOP SUMMARY CARDS
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f\"""<div class="metric-card"><div class="metric-title">System Monitoring</div><div class="metric-value status-safe">Active</div></div>\""", unsafe_allow_html=True)
    with c2:
        st.markdown(f\"""<div class="metric-card"><div class="metric-title">Telemetry Status</div><div class="metric-value status-neutral">10s Window</div></div>\""", unsafe_allow_html=True)
    with c3:
        bert_status = "LOADED" if is_bert_loaded else "NOT TRAINED"
        bert_color = "status-safe" if is_bert_loaded else "status-warn"
        st.markdown(f\"""<div class="metric-card"><div class="metric-title">Live-Domain BERT</div><div class="metric-value {bert_color}">{bert_status}</div></div>\""", unsafe_allow_html=True)
    with c4:
        det_color = "status-warn" if not is_bert_loaded else ("status-alert" if bert_is_ransomware else "status-safe")
        st.markdown(f\"""<div class="metric-card"><div class="metric-title">Detection Status</div><div class="metric-value {det_color}">{det_status.upper()}</div></div>\""", unsafe_allow_html=True)

    # 4. BEHAVIORAL INTELLIGENCE
    st.markdown("<div class='section-title'>WHAT BEHAVIOR WAS OBSERVED?</div>", unsafe_allow_html=True)
    st.markdown("<div style='font-size:0.85rem; color:#8B949E; margin-bottom:10px;'>Phase 5B Behavioral Intelligence</div>", unsafe_allow_html=True)
    
    parts = split_behavioral_text(bert_text)
    html_lines = "".join([f"<div class='behavior-line'>{p}</div>" for p in parts])
    st.markdown(f"<div class='behavior-card'>{html_lines}</div>", unsafe_allow_html=True)
    
    # 6. WHY DID THE MODEL DECIDE THIS? (XAI)
    st.markdown("<div class='section-title'>WHY DID THE MODEL DECIDE THIS?</div>", unsafe_allow_html=True)
    if not is_bert_loaded:
        st.info("XAI unavailable until Live-Domain BERT is trained.")
    else:
        if len(bert_explanation) > 0:
            for phrase, weight in bert_explanation:
                st.write(f"- `{phrase}` (Weight: {weight:.4f})")
        else:
            st.write("No significant malicious contributions identified.")

    # 5. WHAT TELEMETRY SUPPORTS IT? (21-Feature Telemetry)
    st.markdown("<div class='section-title'>WHAT TELEMETRY SUPPORTS IT?</div>", unsafe_allow_html=True)
    with st.expander("Technical Telemetry — 21 Features", expanded=True):
        r1c1, r1c2, r1c3, r1c4 = st.columns(4)
        with r1c1:
            st.markdown(f\"""
            <div class="feature-card"><div class="feature-group-title">FILE SYSTEM</div>
            <div class="feature-row"><span class="feature-name">Creations</span> {format_val(vector[0])}</div>
            <div class="feature-row"><span class="feature-name">Modifications</span> {format_val(vector[1])}</div>
            <div class="feature-row"><span class="feature-name">Deletions</span> {format_val(vector[2])}</div>
            <div class="feature-row"><span class="feature-name">Renames</span> {format_val(vector[3])}</div>
            <div class="feature-row"><span class="feature-name">Unique Exts</span> {format_val(vector[4])}</div>
            <div class="feature-row"><span class="feature-name">Exec Drops</span> {format_val(vector[5], 2)}</div></div>
            \""", unsafe_allow_html=True)
        with r1c2:
            st.markdown(f\"""
            <div class="feature-card"><div class="feature-group-title">PROCESS</div>
            <div class="feature-row"><span class="feature-name">Children</span> {format_val(vector[6])}</div>
            <div class="feature-row"><span class="feature-name">Suspicious</span> {format_val(vector[7], 1)}</div>
            <div class="feature-row"><span class="feature-name">Terminations</span> {format_val(vector[8])}</div></div>
            <div class="feature-card"><div class="feature-group-title">RELATIONSHIP</div>
            <div class="feature-row"><span class="feature-name">Vuln Parent</span> {format_val(vector[18], 1)}</div></div>
            \""", unsafe_allow_html=True)
        with r1c3:
            st.markdown(f\"""
            <div class="feature-card"><div class="feature-group-title">NETWORK</div>
            <div class="feature-row"><span class="feature-name">Outbound</span> {format_val(vector[14], 50)}</div>
            <div class="feature-row"><span class="feature-name">Unique IPs</span> {format_val(vector[15], 10)}</div></div>
            <div class="feature-card"><div class="feature-group-title">MEMORY</div>
            <div class="feature-row"><span class="feature-name">Rem Threads</span> {format_val(vector[12], 1)}</div>
            <div class="feature-row"><span class="feature-name">Cross Proc</span> {format_val(vector[13], 1)}</div></div>
            \""", unsafe_allow_html=True)
        with r1c4:
            st.markdown(f\"""
            <div class="feature-card"><div class="feature-group-title">REGISTRY</div>
            <div class="feature-row"><span class="feature-name">Keys Created</span> {format_val(vector[9])}</div>
            <div class="feature-row"><span class="feature-name">Vals Mod</span> {format_val(vector[10])}</div>
            <div class="feature-row"><span class="feature-name">Persistence</span> {format_val(vector[11], 1)}</div></div>
            <div class="feature-card"><div class="feature-group-title">DLL</div>
            <div class="feature-row"><span class="feature-name">Image Loads</span> {format_val(vector[16], 100)}</div>
            <div class="feature-row"><span class="feature-name">Unsigned</span> {format_val(vector[17], 1)}</div></div>
            <div class="feature-card"><div class="feature-group-title">TEMPORAL</div>
            <div class="feature-row"><span class="feature-name">File Ops/s</span> {format_val(round(vector[19],1))}</div>
            <div class="feature-row"><span class="feature-name">Reg Ops/s</span> {format_val(round(vector[20],1))}</div></div>
            \""", unsafe_allow_html=True)

    # 8. WHAT RESPONSE ACTIONS ARE AVAILABLE?
    st.markdown("<div class='section-title'>WHAT RESPONSE ACTIONS ARE AVAILABLE?</div>", unsafe_allow_html=True)
    c_alert, c_resp = st.columns(2)
    
    with c_alert:
        st.markdown("#### Alert History")
        if len(st.session_state.alerts) == 0:
            st.markdown("<div style='font-size:0.9rem; color:#8B949E;'>No alerts recorded.</div>", unsafe_allow_html=True)
        else:
            for alert in st.session_state.alerts[:5]:
                st.markdown(f\"""
                <div style='background-color:#2D1114; border:1px solid #F85149; border-radius:4px; padding:8px; margin-bottom:8px;'>
                    <div style='font-size:0.75rem; color:#F85149; font-weight:bold;'>{alert['time']}</div>
                    <div style='font-size:0.9rem; color:#E6EDF3;'>{alert['type']} (Risk: {alert['prob']*100:.1f}%)</div>
                </div>
                \""", unsafe_allow_html=True)

    with c_resp:
        st.markdown("#### Defensive Response")
        st.markdown(f\"""
        <div class="metric-card" style="border-left: 4px solid #58A6FF; text-align: left; padding: 10px;">
            <div class="metric-title">Mitigator Mode</div>
            <div class="metric-value status-active" style="color:#58A6FF;">{'DRY-RUN' if st.session_state.mitigator.dry_run else 'ACTIVE'}</div>
        </div>
        \""", unsafe_allow_html=True)
        
        target_pid = st.number_input("Target Process ID (PID)", min_value=0, step=1, value=0)
        confirm_action = st.checkbox("Require explicit confirmation", value=False)
        
        b1, b2 = st.columns(2)
        if b1.button("Suspend Process", use_container_width=True):
            success, msg = st.session_state.mitigator.safe_suspend(target_pid, confirm=confirm_action)
            st.session_state.mitigation_logs.insert(0, f"[{datetime.now().strftime('%H:%M:%S')}] SUSPEND {target_pid}: {msg}")
            
        if b2.button("Resume Process", use_container_width=True):
            success, msg = st.session_state.mitigator.safe_resume(target_pid, confirm=confirm_action)
            st.session_state.mitigation_logs.insert(0, f"[{datetime.now().strftime('%H:%M:%S')}] RESUME {target_pid}: {msg}")
            
        if len(st.session_state.mitigation_logs) > 0:
            st.markdown("<div style='font-size:0.85rem; color:#8B949E; margin-top:10px;'><b>Action Log:</b></div>", unsafe_allow_html=True)
            for log in st.session_state.mitigation_logs[:5]:
                st.markdown(f"<div style='font-size:0.8rem; border-left:2px solid #30363D; padding-left:8px; margin-bottom:4px;'>{log}</div>", unsafe_allow_html=True)

    # 9. LEGACY RF
    st.markdown("---")
    with st.expander("Research Baseline — Legacy Random Forest", expanded=False):
        if st.session_state.model.is_available:
            rf_color = "red" if rf_is_ransomware else "green"
            st.markdown(f"**RF Risk Score:** <span style='color:{rf_color}'>{(rf_prob*100):.1f}%</span>", unsafe_allow_html=True)
            if sum(vector) > 0 and len(rf_explanation) > 0:
                st.markdown("**RF Feature Attribution:**")
                for ex in rf_explanation:
                    st.write(f"- **{ex['feature_name']}**: Value = **{ex['feature_value']}** *(Contrib: {ex['contribution']:.4f})*")
        else:
            st.info("RF Engine offline")

# --- MAIN EXECUTION ROUTING ---

if mode == "REPLAY VALIDATION DATA":
    csv_path = r"5_mlran_dataset\Phase5A_Live_Telemetry\phase5a_benign_telemetry.csv"
    if os.path.exists(csv_path):
        df = pd.read_csv(csv_path)
        
        st.sidebar.markdown(f"<div style='font-size:0.85rem; color:#8B949E;'>Rows loaded: {len(df)}</div>", unsafe_allow_html=True)
        
        if prev_clicked and st.session_state.replay_index > 0:
            st.session_state.replay_index -= 1
        if next_clicked and st.session_state.replay_index < len(df) - 1:
            st.session_state.replay_index += 1
            
        st.sidebar.markdown(f"<div style='font-size:0.85rem; color:#8B949E;'>Current Row: {st.session_state.replay_index}</div>", unsafe_allow_html=True)
        
        if play_clicked:
            st.session_state.is_playing = not st.session_state.is_playing
            
        row = df.iloc[st.session_state.replay_index]
        vector = row[feature_names].tolist()
        timestamp = row.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        label = row.get('label', 0)
        
        render_dashboard(vector, timestamp, label_gt=label, is_replay=True)
        
        if st.session_state.is_playing:
            time.sleep(1)
            if st.session_state.replay_index < len(df) - 1:
                st.session_state.replay_index += 1
                st.rerun()
            else:
                st.session_state.is_playing = False
    else:
        st.error(f"CSV not found at {csv_path}")

elif mode == "LIVE BENIGN TELEMETRY":
    if capture_live:
        with st.spinner("Capturing 10s of live Windows telemetry..."):
            try:
                pipeline = LiveDetectionPipeline()
                row, behavioral_text, end_time_val = pipeline.collect_snapshot()
                
                machine_vec = [row[feat] for feat in feature_names]
                
                st.session_state.last_live_vector = machine_vec
                st.session_state.last_live_text = behavioral_text
                st.session_state.last_live_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
            except Exception as e:
                st.error(f"Live monitoring failed: {e}")
                
    if 'last_live_vector' in st.session_state:
        render_dashboard(st.session_state.last_live_vector, st.session_state.last_live_time, live_behavioral_text=st.session_state.last_live_text)
    else:
        st.info("Click 'Capture 10s Telemetry Snapshot' in the sidebar to view live data.")
"""

with open('app_v3.py', 'w', encoding='utf-8') as f:
    f.write(NEW_APP_CONTENT)

# Replace app.py with app_v3.py safely
os.replace('app_v3.py', 'app.py')
print("Successfully generated and replaced app.py")
