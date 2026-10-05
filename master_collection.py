import subprocess
import time
import os

sessions = [
    {'name': 'Idle', 'duration': 30, 'ps1': None},
    {'name': 'Browsing', 'duration': 30, 'ps1': 'sim_browsing.ps1'},
    {'name': 'VSCode', 'duration': 30, 'ps1': 'sim_vscode.ps1'},
    {'name': 'Documents', 'duration': 30, 'ps1': 'sim_docs.ps1'},
    {'name': 'Files', 'duration': 30, 'ps1': 'sim_files.ps1'},
    {'name': 'Mixed', 'duration': 30, 'ps1': 'sim_mixed.ps1'}
]

print('Starting Master Collection')

for s in sessions:
    print(f"--- Starting Session: {s['name']} for {s['duration']} seconds ---")
    
    ps_proc = None
    if s['ps1']:
        ps_proc = subprocess.Popen(['powershell', '-ExecutionPolicy', 'Bypass', '-File', s['ps1']])
        
    subprocess.run(['python', '-c', f"import phase5a_collector; phase5a_collector.run_collector({s['duration']})"])
    
    if ps_proc:
        ps_proc.terminate()
        try:
            ps_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            ps_proc.kill()
            
    print(f"--- Finished Session: {s['name']} ---")
    time.sleep(2)

print('Master Collection Complete.')
