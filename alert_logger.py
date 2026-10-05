import logging
import json
import os
from datetime import datetime

class AlertLogger:
    def __init__(self, log_file="ransomguard_alerts.log"):
        self.log_file = log_file
        self.logger = logging.getLogger("AlertLogger")
        self.logger.setLevel(logging.INFO)
        
        # Setup file handler
        fh = logging.FileHandler(self.log_file)
        fh.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
        self.logger.addHandler(fh)
        
        # Avoid double console printing if parent logger already handles it
        self.logger.propagate = False

    def log_alert(self, probability, features, error=False, error_msg=None, suspicious_processes=None):
        if error:
            record = {
                "type": "ERROR",
                "timestamp": datetime.utcnow().isoformat(),
                "message": error_msg
            }
        else:
            record = {
                "type": "MACHINE_DETECTION",
                "timestamp": datetime.utcnow().isoformat(),
                "probability": round(probability, 4),
                "features": features,
                "suspicious_processes": suspicious_processes or []
            }
            
        json_record = json.dumps(record)
        self.logger.info(json_record)
        return json_record
