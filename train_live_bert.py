import os
import sys
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, roc_auc_score, confusion_matrix
from sklearn.utils.class_weight import compute_class_weight
import torch
from transformers import BertTokenizer, BertForSequenceClassification, Trainer, TrainingArguments
from torch import nn

class ImbalancedTrainer(Trainer):
    def __init__(self, class_weights=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.class_weights = class_weights

    def compute_loss(self, model, inputs, return_outputs=False):
        labels = inputs.pop("labels")
        outputs = model(**inputs)
        logits = outputs.logits
        if self.class_weights is not None:
            loss_fct = nn.CrossEntropyLoss(weight=self.class_weights.to(self.args.device))
            loss = loss_fct(logits.view(-1, self.model.config.num_labels), labels.view(-1))
        else:
            loss_fct = nn.CrossEntropyLoss()
            loss = loss_fct(logits.view(-1, self.model.config.num_labels), labels.view(-1))
        return (loss, outputs) if return_outputs else loss

class LiveBertDataset(torch.utils.data.Dataset):
    def __init__(self, encodings, labels):
        self.encodings = encodings
        self.labels = labels

    def __getitem__(self, idx):
        item = {key: torch.tensor(val[idx]) for key, val in self.encodings.items()}
        item['labels'] = torch.tensor(self.labels[idx])
        return item

    def __len__(self):
        return len(self.labels)

def compute_metrics(pred):
    labels = pred.label_ids
    preds = pred.predictions.argmax(-1)
    
    acc = accuracy_score(labels, preds)
    precision, recall, f1, _ = precision_recall_fscore_support(labels, preds, average='binary', zero_division=0)
    
    # ROC-AUC requires probabilities of the positive class
    # Apply softmax to logits
    probs = np.exp(pred.predictions) / np.sum(np.exp(pred.predictions), axis=-1, keepdims=True)
    try:
        roc_auc = roc_auc_score(labels, probs[:, 1])
    except ValueError:
        roc_auc = 0.0 # Occurs if only one class is present in evaluation
        
    return {
        'accuracy': acc,
        'f1': f1,
        'precision': precision,
        'recall': recall,
        'roc_auc': roc_auc
    }

def split_by_session(df):
    """
    Split 70/15/15 based on session_id to prevent leakage.
    """
    gss1 = GroupShuffleSplit(n_splits=1, train_size=0.7, random_state=42)
    train_idx, temp_idx = next(gss1.split(df, groups=df['session_id']))
    
    train_df = df.iloc[train_idx]
    temp_df = df.iloc[temp_idx]
    
    gss2 = GroupShuffleSplit(n_splits=1, train_size=0.5, random_state=42) # split remaining 30% into 15% / 15%
    val_idx, test_idx = next(gss2.split(temp_df, groups=temp_df['session_id']))
    
    val_df = temp_df.iloc[val_idx]
    test_df = temp_df.iloc[test_idx]
    
    return train_df, val_df, test_df

def validate_dataset(csv_path):
    print(f"\n--- VALIDATING DATASET: {csv_path} ---")
    if not os.path.exists(csv_path):
        print("[-] Dataset not found.")
        return False
        
    df = pd.read_csv(csv_path)
    
    required_cols = ['session_id', 'label', 'behavioral_text']
    for col in required_cols:
        if col not in df.columns:
            print(f"[-] Missing required column: {col}")
            return False
            
    # Check classes
    classes = df['label'].unique()
    print(f"[+] Total Rows: {len(df)}")
    print(f"[+] Unique Sessions: {df['session_id'].nunique()}")
    print(f"[+] Classes Present: {classes}")
    
    if len(classes) < 2:
        print("[-] Warning: Both Benign (0) and Ransomware (1) classes must be present for final training.")
        
    num_sessions = df['session_id'].nunique()
    if num_sessions < 3:
        print("[-] Cannot perform split isolation check: At least 3 unique sessions required to split into Train/Val/Test.")
        print("--- VALIDATION INCOMPLETE (Dataset too small) ---\n")
        return True
        
    # Test Split Leakage
    train_df, val_df, test_df = split_by_session(df)
    train_sessions = set(train_df['session_id'])
    val_sessions = set(val_df['session_id'])
    test_sessions = set(test_df['session_id'])
    
    leakage_1 = train_sessions.intersection(val_sessions)
    leakage_2 = train_sessions.intersection(test_sessions)
    leakage_3 = val_sessions.intersection(test_sessions)
    
    if leakage_1 or leakage_2 or leakage_3:
        print("[-] CRITICAL ERROR: Session leakage detected across splits!")
        return False
        
    print("[+] Split Isolation Check: PASSED (No leakage)")
    print(f"    Train Sessions: {len(train_sessions)} ({len(train_df)} rows)")
    print(f"    Val Sessions: {len(val_sessions)} ({len(val_df)} rows)")
    print(f"    Test Sessions: {len(test_sessions)} ({len(test_df)} rows)")
    print("--- VALIDATION COMPLETE ---\n")
    return True

def train_live_domain_bert(csv_path, output_dir="6_experiments/live_domain_bert_model"):
    if not validate_dataset(csv_path):
        return
        
    df = pd.read_csv(csv_path)
    classes = df['label'].unique()
    if len(classes) < 2:
        print("[-] Aborting Training: Both classes (0 and 1) are required to train the model.")
        return
        
    # Split Data
    train_df, val_df, test_df = split_by_session(df)
    
    # Save Split Manifests
    os.makedirs(output_dir, exist_ok=True)
    manifest = {
        "train_sessions": list(train_df['session_id'].unique()),
        "val_sessions": list(val_df['session_id'].unique()),
        "test_sessions": list(test_df['session_id'].unique())
    }
    with open(os.path.join(output_dir, "split_manifest.json"), "w") as f:
        json.dump(manifest, f, indent=4)
        
    # Tokenize
    tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
    
    train_encodings = tokenizer(train_df['behavioral_text'].tolist(), truncation=True, padding='max_length', max_length=128)
    val_encodings = tokenizer(val_df['behavioral_text'].tolist(), truncation=True, padding='max_length', max_length=128)
    test_encodings = tokenizer(test_df['behavioral_text'].tolist(), truncation=True, padding='max_length', max_length=128)
    
    train_dataset = LiveBertDataset(train_encodings, train_df['label'].tolist())
    val_dataset = LiveBertDataset(val_encodings, val_df['label'].tolist())
    test_dataset = LiveBertDataset(test_encodings, test_df['label'].tolist())
    
    # Handle Class Imbalance
    class_weights = compute_class_weight('balanced', classes=np.unique(train_df['label']), y=train_df['label'])
    weights_tensor = torch.tensor(class_weights, dtype=torch.float32)
    print(f"[+] Computed Class Weights: {weights_tensor}")
    
    # Model
    model = BertForSequenceClassification.from_pretrained('bert-base-uncased', num_labels=2)
    
    training_args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=3,
        per_device_train_batch_size=16,
        per_device_eval_batch_size=16,
        warmup_steps=100,
        weight_decay=0.01,
        logging_dir='./logs',
        logging_steps=10,
        evaluation_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
    )
    
    trainer = ImbalancedTrainer(
        class_weights=weights_tensor,
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        compute_metrics=compute_metrics
    )
    
    print("\n[+] Starting Training...")
    trainer.train()
    
    print("\n[+] Evaluating on untouch TEST set...")
    test_results = trainer.predict(test_dataset)
    metrics = test_results.metrics
    print(f"Test Accuracy: {metrics.get('test_accuracy')}")
    print(f"Test Precision: {metrics.get('test_precision')}")
    print(f"Test Recall: {metrics.get('test_recall')}")
    print(f"Test F1: {metrics.get('test_f1')}")
    print(f"Test ROC-AUC: {metrics.get('test_roc_auc')}")
    
    # Confusion Matrix
    preds = test_results.predictions.argmax(-1)
    cm = confusion_matrix(test_df['label'].tolist(), preds)
    print("Confusion Matrix:\n", cm)
    
    # Save Model & Config
    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)
    
    metrics_report = {
        "metrics": metrics,
        "confusion_matrix": cm.tolist()
    }
    with open(os.path.join(output_dir, "test_metrics.json"), "w") as f:
        json.dump(metrics_report, f, indent=4)
        
    print(f"\n[+] Pipeline Complete! Assets saved to: {output_dir}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python train_live_bert.py <csv_path> <mode>")
        print("Modes: 'validate' or 'train'")
        sys.exit(1)
        
    csv_path = sys.argv[1]
    mode = sys.argv[2]
    
    if mode == "validate":
        validate_dataset(csv_path)
    elif mode == "train":
        train_live_domain_bert(csv_path)
    else:
        print("Invalid mode. Use 'validate' or 'train'.")
