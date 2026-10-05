import os
import pickle
import numpy as np
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("MLInference")

class MLInferenceEngine:
    def __init__(self, model_path):
        self.model_path = model_path
        self.model = None
        self.is_available = False
        
        self.load_model()

    def load_model(self):
        if not os.path.exists(self.model_path):
            logger.warning(f"MODEL_NOT_AVAILABLE: The 21-feature model was not found at {self.model_path}")
            return
            
        try:
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
            self.is_available = True
            logger.info("Successfully loaded 21-feature Windows-native model.")
        except Exception as e:
            logger.error(f"MODEL_NOT_AVAILABLE: Failed to load model - {e}")
            self.is_available = False

    def predict(self, feature_vector):
        """
        Takes a 21-element list, returns (is_ransomware_bool, probability_float).
        """
        if not self.is_available:
            return None, 0.0
            
        try:
            # Ensure it's a 2D array for sklearn
            vec = np.array(feature_vector).reshape(1, -1)
            
            # Predict proba returns [[prob_goodware, prob_ransomware]]
            probs = self.model.predict_proba(vec)[0]
            ransomware_prob = probs[1]
            
            is_ransomware = bool(self.model.predict(vec)[0] == 1)
            
            return is_ransomware, ransomware_prob
            
        except Exception as e:
            logger.error(f"Inference error: {e}")
            return None, 0.0

    def explain_prediction(self, feature_vector):
        """
        Feature importance-based explanation.
        Provides a local approximation by multiplying global feature importance by local feature values.
        Returns the top 3 contributing features.
        """
        if not self.is_available or not hasattr(self.model, "feature_importances_"):
            return []
            
        feature_names = [
            ("fs_01_creation_count", "File System"), 
            ("fs_02_modification_count", "File System"), 
            ("fs_03_deletion_count", "File System"),
            ("fs_04_rename_count", "File System"), 
            ("fs_05_unique_extensions_modified", "File System"), 
            ("fs_06_executable_files_dropped", "File System"),
            ("pr_01_child_process_count", "Process"), 
            ("pr_02_suspicious_child_count", "Process"), 
            ("pr_03_process_termination_count", "Process"),
            ("rg_01_registry_keys_created", "Registry"), 
            ("rg_02_registry_values_modified", "Registry"), 
            ("rg_03_persistence_registry_mods", "Registry"),
            ("mem_01_remote_threads_created", "Memory"), 
            ("mem_02_cross_process_access", "Memory"),
            ("nw_01_outbound_connections_count", "Network"), 
            ("nw_02_unique_destination_ips", "Network"),
            ("dll_01_image_load_count", "DLL/Module"), 
            ("dll_02_unsigned_image_load_count", "DLL/Module"),
            ("rel_01_spawned_by_vulnerable_app", "Relationship"), 
            ("tmp_01_file_operations_per_second", "Temporal"),
            ("tmp_02_registry_modifications_per_sec", "Temporal")
        ]
        
        importances = self.model.feature_importances_
        contributions = []
        
        for i, val in enumerate(feature_vector):
            if val > 0:
                # contribution = feature_importance * feature_value
                contribution = float(importances[i] * val)
                contributions.append({
                    "feature_name": feature_names[i][0],
                    "feature_group": feature_names[i][1],
                    "feature_value": float(val),
                    "model_importance": float(importances[i]),
                    "contribution": contribution
                })
                
        # Sort by highest contribution
        contributions = sorted(contributions, key=lambda x: x["contribution"], reverse=True)
        return contributions[:3]
