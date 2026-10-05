import pandas as pd
import json

df = pd.read_csv('6_experiments/FS_MLRan_Datasets/MLRan_X_test_RFE.csv', nrows=1)
print(f'Total columns: {len(df.columns)}')
cols = list(df.columns)
print(f'Feature columns count (excluding ids/labels): {len(cols) - 4}')

with open('6_experiments/FS_MLRan_Datasets/RFE_selected_feature_names_dic.json', 'r') as f:
    feat_dict = json.load(f)

print(f'Features in dict: {len(feat_dict)}')
print(list(feat_dict.items())[:20])

# check for any unknown or non-binary features
df_full = pd.read_csv('6_experiments/FS_MLRan_Datasets/MLRan_X_test_RFE.csv', nrows=100)
features = df_full.drop(columns=['sample_id', 'sample_type', 'family_label', 'type_label'])
print(f"Unique values in feature columns: {pd.unique(features.values.ravel())}")
