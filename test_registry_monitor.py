import winreg
import time
import logging
from registry_monitor import RegistryMonitor

logging.basicConfig(level=logging.INFO, format='%(message)s')

TEST_SUBPATH = r"Software\RansomGuardTestKey"
PERSISTENCE_TEST_SUBPATH = r"Software\Microsoft\Windows\CurrentVersion\Run" # We will monitor it, but not modify it, or wait, we can create a dummy value here and safely delete it.

def simulate_safe_activity():
    logging.info("\n[TEST] Generating safe registry activity...\n")
    
    # 1. Create a brand new test key (Triggers rg_01_keys_created on Software if monitored, but we are monitoring the test key directly. Wait, if we monitor Software, it's too huge. We monitor Software\\RansomGuardTestKey. Let's create it.)
    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, TEST_SUBPATH)
        
        # 2. Add a value (Triggers rg_02_values_modified)
        winreg.SetValueEx(key, "TestValue1", 0, winreg.REG_SZ, "SafeData")
        winreg.CloseKey(key)
    except Exception as e:
        logging.error(f"[TEST] Failed to create test key: {e}")

    time.sleep(1.5) # Let poll catch it
    
    # 3. Modify the value (Triggers rg_02_values_modified)
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, TEST_SUBPATH, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, "TestValue1", 0, winreg.REG_SZ, "ModifiedSafeData")
        winreg.CloseKey(key)
    except Exception as e:
        logging.error(f"[TEST] Failed to modify test key: {e}")
        
    time.sleep(1.5)
    
    # 4. Simulate persistence modification (Create a dummy Run value, then immediately delete it)
    try:
        run_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, PERSISTENCE_TEST_SUBPATH, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(run_key, "RansomGuardDummySafeTest", 0, winreg.REG_SZ, "C:\\dummy.exe")
        winreg.CloseKey(run_key)
    except Exception as e:
        logging.error(f"[TEST] Failed to modify Run key: {e}")

    time.sleep(1.5)

def run_test():
    # Make sure test key is clean before starting
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, TEST_SUBPATH)
    except:
        pass
        
    # We will monitor our test key, and the Run key for persistence tests
    paths_to_monitor = [
        (winreg.HKEY_CURRENT_USER, TEST_SUBPATH),
        (winreg.HKEY_CURRENT_USER, PERSISTENCE_TEST_SUBPATH)
    ]
    
    monitor = RegistryMonitor(paths_to_monitor, window_size=5, poll_interval=1.0)
    monitor.start()
    
    time.sleep(2) # Baseline cache built
    
    try:
        simulate_safe_activity()
        logging.info("[TEST] Activity generation complete. Waiting for final feature window flush...")
        time.sleep(6)
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop()
        
        # Cleanup
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, TEST_SUBPATH)
        except:
            pass
            
        try:
            run_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, PERSISTENCE_TEST_SUBPATH, 0, winreg.KEY_WRITE)
            winreg.DeleteValue(run_key, "RansomGuardDummySafeTest")
            winreg.CloseKey(run_key)
        except:
            pass
            
        logging.info("\n[TEST] Cleaned up test registry keys. Test finished.")

if __name__ == "__main__":
    run_test()
