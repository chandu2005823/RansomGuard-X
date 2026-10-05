import pandas as pd
from ml_inference import MLInferenceEngine
import json

def test_xai():
    csv_path = r"C:\Users\tiriv\Downloads\mlran-main\mlran-main\5_mlran_dataset\Phase5A_Live_Telemetry\phase5a_benign_telemetry.csv"
    model_path = r"C:\Users\tiriv\Downloads\mlran-main\mlran-main\6_experiments\windows_rf_model.pkl"
    
    df = pd.read_csv(csv_path)
    engine = MLInferenceEngine(model_path)
    
    # Grab an active row
    feature_cols = df.columns[3:24]
    active_df = df[df[feature_cols].sum(axis=1) > 0]
    
    if len(active_df) > 0:
        row = active_df.iloc[0]
        vector = row[feature_cols].tolist()
        
        is_ransomware, prob = engine.predict(vector)
        print(f"Prediction: Ransomware={is_ransomware}, Prob={prob:.2f}")
        
        explanation = engine.explain_prediction(vector)
        print("\nTop 3 Contributing Features:")
        print(json.dumps(explanation, indent=2))
    else:
        print("No active rows found in dataset.")

if __name__ == "__main__":
    import warnings
    warnings.filterwarnings('ignore')
    test_xai()
