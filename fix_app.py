import re

with open('app.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix is_bert_loaded logic
old_logic = "    is_bert_loaded = st.session_state.bert_engine.is_loaded"
new_logic = """    # Enforce Live-Domain BERT specifically (ignore historical 11-feature fallback)
    model_dir = getattr(st.session_state.bert_engine, 'model_dir', '')
    is_live_domain = "common_behavior" not in model_dir.lower()
    is_bert_loaded = st.session_state.bert_engine.is_loaded and is_live_domain"""

content = content.replace(old_logic, new_logic)

# Fix RF Display disclaimer
old_rf_html = """st.markdown(f"**RF Risk Score:** <span style='color:{rf_color}'>{(rf_prob*100):.1f}%</span>", unsafe_allow_html=True)"""
new_rf_html = """st.markdown(f"**Legacy RF Risk Score:** <span style='color:{rf_color}'>{(rf_prob*100):.1f}%</span>", unsafe_allow_html=True)
            st.caption("*(Not the Live-Domain BERT prediction)*")"""

content = content.replace(old_rf_html, new_rf_html)

with open('app.py', 'w', encoding='utf-8') as f:
    f.write(content)
