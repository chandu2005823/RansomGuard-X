import sys
import os
import psutil
import pandas as pd
import importlib

print(f"Python Version: {sys.version}")
packages = ['torch', 'transformers', 'datasets', 'sklearn', 'pandas', 'numpy']
for pkg in packages:
    try:
        if pkg == 'sklearn':
            import sklearn
            print(f"scikit-learn: {sklearn.__version__}")
        else:
            mod = importlib.import_module(pkg)
            print(f"{pkg}: {mod.__version__}")
    except ImportError:
        print(f"{pkg}: NOT INSTALLED")

try:
    import torch
    print(f"PyTorch Version: {torch.__version__}")
    print(f"CUDA Available: {torch.cuda.is_available()}")
    if torch.cuda.is_available():
        print(f"GPU Name: {torch.cuda.get_device_name(0)}")
except ImportError:
    pass

print(f"Total System RAM: {psutil.virtual_memory().total / (1024**3):.2f} GB")

train_file = "6_experiments/FS_MLRan_Datasets/MLRan_X_train_RFE.csv"
labels_file = "6_experiments/FS_MLRan_Datasets/MLRan_labels.csv"

# Fallback if they are directly in 6_experiments
if not os.path.exists(train_file):
    train_file = "6_experiments/MLRan_X_train_RFE.csv"
if not os.path.exists(labels_file):
    labels_file = "6_experiments/MLRan_labels.csv"
    
print("\n--- Dataset Inspection ---")
try:
    print(f"Train File Size: {os.path.getsize(train_file) / (1024**2):.2f} MB")
    df_train = pd.read_csv(train_file)
    print(f"Train Rows: {df_train.shape[0]}")
    print(f"Train Features/Columns: {df_train.shape[1]}")
    
    if os.path.exists(labels_file):
        print(f"Labels File Size: {os.path.getsize(labels_file) / (1024**2):.2f} MB")
        df_labels = pd.read_csv(labels_file)
        print(f"Labels Rows: {df_labels.shape[0]}")
    else:
        print("Labels file not found as a separate file. Checking inside train file...")
        if 'type_label' in df_train.columns:
            print(f"Label Distribution:\n{df_train['type_label'].value_counts()}")
        elif 'family_label' in df_train.columns:
            print(f"Label Distribution:\n{df_train['family_label'].value_counts()}")
        elif 'label' in df_train.columns:
            print(f"Label Distribution:\n{df_train['label'].value_counts()}")
            
    print("\n--- Checking for Validation/Test sets ---")
    test_files = ['6_experiments/FS_MLRan_Datasets/MLRan_X_test_RFE.csv', '6_experiments/MLRan_X_test_RFE.csv']
    test_found = False
    for tf in test_files:
        if os.path.exists(tf):
            print(f"Found Test Set: {tf} | Size: {os.path.getsize(tf)/(1024**2):.2f} MB")
            test_found = True
            break
    if not test_found:
        print("No separate Test/Validation set found.")
        
except Exception as e:
    print(f"Error inspecting datasets: {e}")
