import os
import json
import pandas as pd
import numpy as np
import time
import torch
from transformers import BertTokenizer, BertForSequenceClassification, Trainer, TrainingArguments
from datasets import Dataset
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

"""
ARCHITECTURAL NOTE:
This training script specifically trains on the HISTORICAL Cuckoo Sandbox dataset using the 
483-feature RFE-selected feature space translated into textual sequences.
It does NOT train on the live Windows 21-feature telemetry space (which remains strictly 
allocated to the tabular Random Forest pipeline).
"""

def convert_row_to_text(row, feature_names_dict):
    active_features = []
    metadata = ['sample_id', 'sample_type', 'family_label', 'type_label']
    for col in row.index:
        if col in metadata:
            continue
        if row[col] == 1:
            name = feature_names_dict.get(col, col)
            if name.startswith("API:"):
                active_features.append(f"called API {name[4:]}")
            elif name.startswith("STRING:"):
                active_features.append(f"used string {name[7:]}")
            elif name.startswith("SYSTEM:DLL_LOADED:"):
                active_features.append(f"loaded DLL {name[18:]}")
            elif name.startswith("SYSTEM:GUID:"):
                active_features.append(f"accessed GUID {name[12:]}")
            elif name.startswith("DROP:EXTENSION:"):
                active_features.append(f"dropped {name[15:]} file")
            elif name.startswith("DROP:TYPE:"):
                active_features.append(f"dropped file of type {name[10:].replace('_', ' ')}")
            elif name.startswith("SIGNATURE:"):
                active_features.append(f"triggered signature {name[10:].replace('_', ' ')}")
            else:
                active_features.append(name.replace("_", " "))
    return "The process " + ", ".join(active_features) + "."

def prepare_dataset(df_path, feature_names_dict, num_samples=None):
    df = pd.read_csv(df_path)
    if num_samples is not None:
        # Keep class balance roughly if possible, but for smoke test just take random or head
        # Let's shuffle and take num_samples
        df = df.sample(n=num_samples, random_state=42)
        
    texts = []
    labels = []
    for _, row in df.iterrows():
        texts.append(convert_row_to_text(row, feature_names_dict))
        labels.append(int(row['sample_type']))
        
    return Dataset.from_dict({"text": texts, "labels": labels})

def compute_metrics(eval_pred):
    logits, labels = eval_pred
    # softmax to get probabilities for class 1
    probs = np.exp(logits) / np.sum(np.exp(logits), axis=-1, keepdims=True)
    probs_class_1 = probs[:, 1]
    predictions = np.argmax(logits, axis=-1)
    
    acc = accuracy_score(labels, predictions)
    prec = precision_score(labels, predictions, zero_division=0)
    rec = recall_score(labels, predictions, zero_division=0)
    f1 = f1_score(labels, predictions, zero_division=0)
    
    try:
        auc = roc_auc_score(labels, probs_class_1)
    except ValueError:
        auc = 0.5 # In case only one class is present in batch
        
    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "roc_auc": auc
    }

def main():
    print("--- Historical Cuckoo Behavioral-Text Transformer Experiment (Full Training) ---")
    start_time = time.time()
    
    train_path = "6_experiments/FS_MLRan_Datasets/MLRan_X_train_RFE.csv"
    test_path = "6_experiments/FS_MLRan_Datasets/MLRan_X_test_RFE.csv"
    dict_path = "6_experiments/FS_MLRan_Datasets/RFE_selected_feature_names_dic.json"
    
    with open(dict_path, 'r') as f:
        feature_names_dict = json.load(f)
        
    print("Preparing datasets (Full Split)...")
    train_dataset = prepare_dataset(train_path, feature_names_dict, num_samples=None)
    test_dataset = prepare_dataset(test_path, feature_names_dict, num_samples=None)
    
    print("Loading Tokenizer...")
    model_name = "bert-base-uncased"
    tokenizer = BertTokenizer.from_pretrained(model_name)
    
    def tokenize_fn(examples):
        return tokenizer(examples["text"], padding="max_length", truncation=True, max_length=256)
        
    tokenized_train = train_dataset.map(tokenize_fn, batched=True)
    tokenized_test = test_dataset.map(tokenize_fn, batched=True)
    
    print("Loading Model...")
    # Explicitly move to CPU
    device = torch.device("cpu")
    model = BertForSequenceClassification.from_pretrained(model_name, num_labels=2)
    model.to(device)
    
    training_args = TrainingArguments(
        output_dir="./6_experiments/bert_full_output",
        eval_strategy="epoch",
        learning_rate=2e-5,
        per_device_train_batch_size=8,
        per_device_eval_batch_size=8,
        num_train_epochs=1,
        weight_decay=0.01,
        use_cpu=True,
        logging_dir='./6_experiments/bert_full_logs',
        logging_steps=50,
        save_strategy="epoch"
    )
    
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_train,
        eval_dataset=tokenized_test,
        compute_metrics=compute_metrics
    )
    
    print(f"Starting Training on CPU... Train size: {len(tokenized_train)} | Test size: {len(tokenized_test)}")
    trainer.train()
    
    print("Evaluating...")
    eval_result = trainer.evaluate()
    
    print("\n--- Full Training Results ---")
    print(json.dumps(eval_result, indent=2))
    
    print("Saving Model and Tokenizer...")
    trainer.save_model("./6_experiments/bert_historical_cuckoo_model")
    tokenizer.save_pretrained("./6_experiments/bert_historical_cuckoo_model")
    
    # Save metrics
    with open("6_experiments/bert_full_metrics.json", "w") as f:
        json.dump(eval_result, f, indent=2)
        
    # Generate Confusion Matrix
    print("Generating Confusion Matrix...")
    predictions = trainer.predict(tokenized_test)
    y_pred = np.argmax(predictions.predictions, axis=-1)
    y_true = predictions.label_ids
    
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Goodware', 'Ransomware'], yticklabels=['Goodware', 'Ransomware'])
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.title('BERT Full Dataset Confusion Matrix')
    plt.tight_layout()
    plt.savefig('6_experiments/bert_full_confusion_matrix.png')
    
    duration = time.time() - start_time
    print(f"\nFull training completed in {duration:.2f} seconds.")
    print("Files saved: bert_historical_cuckoo_model/, bert_full_metrics.json, bert_full_confusion_matrix.png")

if __name__ == "__main__":
    main()
