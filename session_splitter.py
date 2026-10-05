import pandas as pd
import numpy as np
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

def group_split_by_session(df, session_col='collection_session_id', train_pct=0.7, val_pct=0.15, test_pct=0.15, seed=42):
    """
    Performs a strict Session-level split (GroupKFold equivalent) to prevent temporal leakage.
    Ensures consecutive 10-second windows from the same session stay together.
    """
    np.random.seed(seed)
    sessions = df[session_col].unique()
    np.random.shuffle(sessions)
    
    n_sessions = len(sessions)
    train_end = int(n_sessions * train_pct)
    val_end = train_end + int(n_sessions * val_pct)
    
    train_sessions = set(sessions[:train_end])
    val_sessions = set(sessions[train_end:val_end])
    test_sessions = set(sessions[val_end:])
    
    train_df = df[df[session_col].isin(train_sessions)].copy()
    val_df = df[df[session_col].isin(val_sessions)].copy()
    test_df = df[df[session_col].isin(test_sessions)].copy()
    
    logging.info(f"Split {n_sessions} unique sessions.")
    logging.info(f"Train: {len(train_sessions)} sessions ({len(train_df)} rows)")
    logging.info(f"Val:   {len(val_sessions)} sessions ({len(val_df)} rows)")
    logging.info(f"Test:  {len(test_sessions)} sessions ({len(test_df)} rows)")
    
    # Assert absolutely zero overlap
    overlap_train_val = train_sessions.intersection(val_sessions)
    overlap_train_test = train_sessions.intersection(test_sessions)
    assert len(overlap_train_val) == 0, "Leakage detected between train and val!"
    assert len(overlap_train_test) == 0, "Leakage detected between train and test!"
    
    return train_df, val_df, test_df

if __name__ == "__main__":
    logging.info("Session Split Utility Initialized. (Do not run on malicious data until Phase 5B collection is formally completed).")
