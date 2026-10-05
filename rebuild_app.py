import os

NEW_APP_CONTENT = """import streamlit as st
import pandas as pd
import time
import os
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

st.set_page_config(page_title="RansomGuard-X SOC Dashboard", layout="wide", initial_sidebar_state="expanded")

# --- CUSTOM CSS FOR SOC THEME ---
st.markdown(\"""
<style>
    .metric-card {
        background-color: #1E2530;
        border: 1px solid #2C3545;
        border-radius: 8px;
        padding: 15px;
        margin-bottom: 15px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .metric-title {
        color: #8B949E;
        font-size: 0.85rem;
        text-transform: uppercase;
        font-weight: 600;
        margin-bottom: 5px;
    }
    .metric-value {
        color: #E6EDF3;
        font-size: 1.2rem;
        font-weight: bold;
    }
    .status-safe { color: #3FB950; }
    .status-warn { color: #D29922; }
    .status-alert { color: #F85149; }
    .status-neutral { color: #8B949E; }
    
    .feature-card {
        background-color: #161B22;
        border: 1px solid #30363D;
        border-radius: 6px;
        padding: 10px;
        margin-bottom: 10px;
    }
    .feature-group-title {
        color: #58A6FF;
        font-size: 0.9rem;
        font-weight: 600;
        margin-bottom: 8px;
        border-bottom: 1px solid #30363D;
        padding-bottom: 4px;
    }
    .feature-row {
        display: flex;
        justify-content: space-between;
        font-size: 0.85rem;
        margin-bottom: 3px;
    }
    .feature-name { color: #C9D1D9; }
    
    .val-zero { color: #8B949E; }
    .val-active { color: #58A6FF; font-weight: 600; }
    .val-high { color: #D29922; font-weight: bold; }
</style>
\""", unsafe_allow_html=True)

# Initialize Session State
if 'replay_index' not in st.session_state:
    st.session_state.replay_index = 0
if 'alerts' not in st.session_state:
    st.session_state.alerts = []
if 'is_playing' not in st.session_state:
    st.session_state.is_playing = False
if 'mitigation_logs' not in st.session_state:
    st.session_state.mitigation_logs = []

if 'model' not in st.session_state:
    st.session_state.model = MLInferenceEngine("6_experiments/windows_rf_model.pkl")
if 'bert_engine' not in st.session_state:
    st.session_state.bert_engine = LiveBERTInference()
if 'bert_xai' not in st.session_state:
    st.session_state.bert_xai = BertXAI(inference_engine=st.session_state.bert_engine)
if 'alert_logger' not in st.session_state:
    st.session_state.alert_logger = AlertLogger("ransomguard_alerts_demo.log")
if 'mitigator' not in st.session_state:
    st.session_state.mitigator = SafeMitigator(dry_run=True, log_file="ransomguard_mitigation_demo.log")

# --- HEADER ---
st.markdown(\"""
<div style="display: flex; align-items: center; margin-bottom: 20px;">
    <div style="font-size: 2.5rem; margin-right: 15px;">🛡️</div>
    <div>
        <h1 style="margin: 0; padding: 0; font-size: 1.8rem; color: #E6EDF3;">RansomGuard-X</h1>
        <div style="color: #58A6FF; font-size: 0.9rem; font-weight: 500;">AI-Powered Ransomware Detection & Response</div>
    </div>
</div>
\""", unsafe_allow_html=True)

# --- SIDEBAR CONTROL CENTER ---
st.sidebar.markdown("### 🎛️ RANSOMGUARD-X CONTROL CENTER")
st.sidebar.markdown("---")

st.sidebar.markdown("**Monitoring Mode**")
mode = st.sidebar.radio("Select Source:", ["Replay Validation Data", "Live Benign Telemetry"], label_visibility="collapsed")

st.sidebar.markdown("---")
st.sidebar.markdown("**Model Status**")
if st.session_state.model.is_available:
    st.sidebar.markdown("🟢 Legacy RF: **Loaded**")
else:
    st.sidebar.markdown("🔴 Legacy RF: **Offline**")

st.sidebar.markdown("🟡 Live-Domain BERT: **Not Trained**")

st.sidebar.markdown("---")
st.sidebar.markdown("**Live Controls**")
capture_live = st.sidebar.button("Capture 10s Telemetry Snapshot", use_container_width=True)

st.sidebar.markdown("---")
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
    if val == 0:
        return f'<span class="val-zero">0</span>'
    elif val >= threshold_high:
        return f'<span class="val-high">{val}</span>'
    else:
        return f'<span class="val-active">{val}</span>'

def render_dashboard(vector, timestamp, label_gt="N/A", live_behavioral_text=None, is_replay=False):
    # Convert list vector back to dict row
    row = dict(zip(feature_names, vector))
    
    # Behavioral Text Generation
    if live_behavioral_text:
        bert_text = live_behavioral_text
    else:
        from live_domain_converter import convert_live_21_to_text
        bert_text = convert_live_21_to_text(row)
        
    # RF Tabular Inference (Legacy)
    rf_is_ransomware, rf_prob = st.session_state.model.predict(vector) if st.session_state.model.is_available else (False, 0.0)
    rf_explanation = st.session_state.model.explain_prediction(vector) if st.session_state.model.is_available else []
    
    primary_prob = rf_prob
    is_ransomware = rf_is_ransomware
    
    # Log Alert
    if is_ransomware:
        if f"{timestamp}" not in [a['time'] for a in st.session_state.alerts]:
            st.session_state.alerts.insert(0, {"time": timestamp, "prob": primary_prob, "type": "Behavioral Anomaly"})
            st.session_state.alert_logger.log_alert(primary_prob, vector)
            
    # --- TOP STATUS AREA ---
    if is_replay:
        st.warning("⚠️ **REPLAY VALIDATION DATA:** This is historical validation data, not live telemetry.")
        
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f\"""
        <div class="metric-card">
            <div class="metric-title">System Status</div>
            <div class="metric-value status-safe">Active</div>
        </div>
        \""", unsafe_allow_html=True)
    with c2:
        st.markdown(f\"""
        <div class="metric-card">
            <div class="metric-title">Monitoring Window</div>
            <div class="metric-value">10s Snapshot</div>
        </div>
        \""", unsafe_allow_html=True)
    with c3:
        st.markdown(f\"""
        <div class="metric-card">
            <div class="metric-title">Live-Domain BERT</div>
            <div class="metric-value status-warn">NOT TRAINED</div>
        </div>
        \""", unsafe_allow_html=True)
    with c4:
        det_class = "status-warn"
        det_text = "ANALYSIS PENDING"
        st.markdown(f\"""
        <div class="metric-card">
            <div class="metric-title">Threat Status</div>
            <div class="metric-value {det_class}">{det_text}</div>
        </div>
        \""", unsafe_allow_html=True)

    # --- MAIN CONTENT ---
    m_col1, m_col2 = st.columns([2, 1])
    
    with m_col1:
        # BEHAVIORAL INTELLIGENCE
        st.markdown("### Behavioral Intelligence")
        st.info(f"{bert_text}")
        
        # MODEL / XAI
        st.markdown("### Why did the model make this decision?")
        st.markdown("<div class='metric-card' style='text-align: center; color: #8B949E;'>XAI will appear after the Live-Domain BERT model is trained.</div>", unsafe_allow_html=True)
        
        # LIVE TELEMETRY
        st.markdown("### Live Telemetry (21 Features)")
        
        r1c1, r1c2, r1c3, r1c4 = st.columns(4)
        with r1c1:
            st.markdown(f\"""
            <div class="feature-card">
                <div class="feature-group-title">FILE SYSTEM</div>
                <div class="feature-row"><span class="feature-name">Creations</span> {format_val(vector[0])}</div>
                <div class="feature-row"><span class="feature-name">Modifications</span> {format_val(vector[1])}</div>
                <div class="feature-row"><span class="feature-name">Deletions</span> {format_val(vector[2])}</div>
                <div class="feature-row"><span class="feature-name">Renames</span> {format_val(vector[3])}</div>
                <div class="feature-row"><span class="feature-name">Unique Exts</span> {format_val(vector[4])}</div>
                <div class="feature-row"><span class="feature-name">Exec Drops</span> {format_val(vector[5], 2)}</div>
            </div>
            \""", unsafe_allow_html=True)
        with r1c2:
            st.markdown(f\"""
            <div class="feature-card">
                <div class="feature-group-title">PROCESS</div>
                <div class="feature-row"><span class="feature-name">Children</span> {format_val(vector[6])}</div>
                <div class="feature-row"><span class="feature-name">Suspicious</span> {format_val(vector[7], 1)}</div>
                <div class="feature-row"><span class="feature-name">Terminations</span> {format_val(vector[8])}</div>
            </div>
            <div class="feature-card">
                <div class="feature-group-title">RELATIONSHIP</div>
                <div class="feature-row"><span class="feature-name">Vuln Parent</span> {format_val(vector[18], 1)}</div>
            </div>
            \""", unsafe_allow_html=True)
        with r1c3:
            st.markdown(f\"""
            <div class="feature-card">
                <div class="feature-group-title">NETWORK</div>
                <div class="feature-row"><span class="feature-name">Outbound</span> {format_val(vector[14], 50)}</div>
                <div class="feature-row"><span class="feature-name">Unique IPs</span> {format_val(vector[15], 10)}</div>
            </div>
            <div class="feature-card">
                <div class="feature-group-title">MEMORY</div>
                <div class="feature-row"><span class="feature-name">Rem Threads</span> {format_val(vector[12], 1)}</div>
                <div class="feature-row"><span class="feature-name">Cross Proc</span> {format_val(vector[13], 1)}</div>
            </div>
            \""", unsafe_allow_html=True)
        with r1c4:
            st.markdown(f\"""
            <div class="feature-card">
                <div class="feature-group-title">REGISTRY</div>
                <div class="feature-row"><span class="feature-name">Keys Created</span> {format_val(vector[9])}</div>
                <div class="feature-row"><span class="feature-name">Vals Mod</span> {format_val(vector[10])}</div>
                <div class="feature-row"><span class="feature-name">Persistence</span> {format_val(vector[11], 1)}</div>
            </div>
            <div class="feature-card">
                <div class="feature-group-title">DLL</div>
                <div class="feature-row"><span class="feature-name">Image Loads</span> {format_val(vector[16], 100)}</div>
                <div class="feature-row"><span class="feature-name">Unsigned</span> {format_val(vector[17], 1)}</div>
            </div>
            <div class="feature-card">
                <div class="feature-group-title">TEMPORAL</div>
                <div class="feature-row"><span class="feature-name">File Ops/s</span> {format_val(round(vector[19],1))}</div>
                <div class="feature-row"><span class="feature-name">Reg Ops/s</span> {format_val(round(vector[20],1))}</div>
            </div>
            \""", unsafe_allow_html=True)
            
    with m_col2:
        st.markdown("### Defensive Response")
        st.markdown(f\"""
        <div class="metric-card" style="border-left: 4px solid #58A6FF;">
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

        st.markdown("<br>### Alert History", unsafe_allow_html=True)
        if len(st.session_state.alerts) == 0:
            st.markdown("<div style='font-size:0.9rem; color:#8B949E;'>No alerts recorded.</div>", unsafe_allow_html=True)
        else:
            for alert in st.session_state.alerts[:5]:
                st.markdown(f\"""
                <div style='background-color:#2D1114; border:1px solid #F85149; border-radius:4px; padding:8px; margin-bottom:8px;'>
                    <div style='font-size:0.75rem; color:#F85149; font-weight:bold;'>{alert['time']}</div>
                    <div style='font-size:0.9rem; color:#E6EDF3;'>{alert['type']}</div>
                </div>
                \""", unsafe_allow_html=True)
                
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

if mode == "Replay Validation Data":
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

elif mode == "Live Benign Telemetry":
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

with open('app_new.py', 'w', encoding='utf-8') as f:
    f.write(NEW_APP_CONTENT)

# Replace app.py with app_new.py safely
os.replace('app_new.py', 'app.py')
print("Successfully generated and replaced app.py")
