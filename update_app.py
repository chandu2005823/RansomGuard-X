import re

with open('app.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Change render_dashboard signature and logic
new_render_dashboard = """def render_dashboard(vector, timestamp, label_gt="N/A", live_behavioral_text=None):
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
    
    # Primary Alert relies on RF until Live BERT is ready
    primary_prob = rf_prob
    is_ransomware = rf_is_ransomware
    
    with col1:
        st.subheader(f"Time: {timestamp} | System Status: Active")
        
        # Display Behavioral Text
        st.markdown("### 21-Feature Behavioral Text (Phase 5B)")
        st.info(f"**Behavioral Text:** `{bert_text}`")
        
        # Display BERT Results
        st.markdown("### Live-Domain BERT Engine")
        st.warning("**Live-Domain BERT: NOT TRAINED**")
        st.markdown("**Prediction:** —")
        st.markdown("**Probabilities:** —")
        
        # Display Legacy RF Results
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
            
        st.markdown("---")
        
        if is_ransomware:
            st.error("POTENTIAL BEHAVIORAL ALERT DETECTED (via Legacy RF)")
            if f"{timestamp}" not in [a['time'] for a in st.session_state.alerts]:
                st.session_state.alerts.insert(0, {"time": timestamp, "prob": primary_prob, "type": "Ransomware-Like Behavior"})
                st.session_state.alert_logger.log_alert(primary_prob, vector)
        else:
            st.success("SYSTEM SAFE (via Legacy RF)")
            
        st.write(f"Ground Truth Label: {label_gt}")
        
        # Feature Groups Display
        st.markdown("#### Raw 21-Feature Telemetry Vector")
"""

# Regex replacement for render_dashboard
content = re.sub(r'def render_dashboard\(vector, timestamp, label_gt="N/A"\):.*?(?=        fg_col1, fg_col2, fg_col3, fg_col4 = st\.columns\(4\))', new_render_dashboard, content, flags=re.DOTALL)

# 2. Update Live Mode call
live_call_old = r'render_dashboard\(st\.session_state\.last_live_vector, st\.session_state\.last_live_time, label_gt="UNKNOWN \(Live\)"\)'
live_call_new = r'render_dashboard(st.session_state.last_live_vector, st.session_state.last_live_time, label_gt="UNKNOWN (Live)", live_behavioral_text=st.session_state.last_live_text)'
content = content.replace(live_call_old, live_call_new)

# Update state assignment in Live Mode
content = content.replace("st.session_state.last_live_vector = machine_vec\n                st.session_state.last_live_time = datetime.now().strftime(\"%Y-%m-%d %H:%M:%S\")", "st.session_state.last_live_vector = machine_vec\n                st.session_state.last_live_text = behavioral_text\n                st.session_state.last_live_time = datetime.now().strftime(\"%Y-%m-%d %H:%M:%S\")")


# 3. Update Sidebar info
content = content.replace('st.sidebar.success("o. BERT Model: Loaded (11-Feature NLP)")', 'st.sidebar.success("o. BERT Model: Loaded (Legacy 11-Feature)")')
content = content.replace('st.sidebar.warning("?o BERT Model: Not Ready (Training...)")', 'st.sidebar.warning("?o Live-Domain BERT: Not Trained")')

content = content.replace('mode = st.sidebar.radio("Select Mode:", ["REPLAY DEMO (Phase 5A CSV)", "LIVE BENIGN TELEMETRY (10s Snapshot)"])', 'mode = st.sidebar.radio("Select Mode:", ["REPLAY VALIDATION DATA (Phase 5A CSV)", "LIVE BENIGN TELEMETRY (10s Snapshot)"])')
content = content.replace('if mode.startswith("REPLAY DEMO"):', 'if mode.startswith("REPLAY VALIDATION DATA"):')


with open('app.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Done updating app.py")
