import os
import time
import shutil
import logging
from file_monitor import FileMonitor

logging.basicConfig(level=logging.INFO, format='%(message)s')

TEST_DIR = os.path.join(os.getcwd(), "ransomguard_test_files")

def simulate_safe_activity():
    """Simulates harmless file operations to trigger the monitor."""
    logging.info("\n[TEST] Generating safe file activity...\n")
    
    # 1. Create files
    file1 = os.path.join(TEST_DIR, "test_doc.txt")
    file2 = os.path.join(TEST_DIR, "test_app.exe")
    
    with open(file1, 'w') as f:
        f.write("Hello World")
    with open(file2, 'w') as f:
        f.write("MZ... fake exe")
        
    time.sleep(1) # Let the watchdog catch it
    
    # 2. Modify files
    with open(file1, 'a') as f:
        f.write("\nModifying the document.")
        
    time.sleep(1)
    
    # 3. Rename files (Simulating encryption)
    renamed_file1 = file1 + ".encrypted"
    os.rename(file1, renamed_file1)
    
    time.sleep(1)
    
    # 4. Delete files
    os.remove(file2)
    os.remove(renamed_file1)

def run_test():
    # Cleanup previous test if exists
    if os.path.exists(TEST_DIR):
        shutil.rmtree(TEST_DIR)
    os.makedirs(TEST_DIR)

    monitor = FileMonitor(target_directory=TEST_DIR, window_size=5)
    monitor.start()
    
    time.sleep(2) # Give monitor time to attach
    
    try:
        simulate_safe_activity()
        logging.info("[TEST] Activity generation complete. Waiting for final feature window flush...")
        time.sleep(6) # Wait for the 5-second window to flush
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop()
        
        # Cleanup
        if os.path.exists(TEST_DIR):
            shutil.rmtree(TEST_DIR)
        logging.info("\n[TEST] Cleaned up test directory. Test finished.")

if __name__ == "__main__":
    run_test()
