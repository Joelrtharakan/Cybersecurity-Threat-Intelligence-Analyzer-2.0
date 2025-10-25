#!/usr/bin/env python3
"""
main.py
Runs the entire Cybersecurity Threat Intelligence Analyzer pipeline with one command.
"""

import os
import subprocess
import sys

def run_command(cmd, desc):
    print(f"Running: {desc}")
    full_cmd = f"./venv/bin/{cmd}"
    result = subprocess.run(full_cmd, shell=True, cwd=os.getcwd())
    if result.returncode != 0:
        print(f"Error in {desc}")
        sys.exit(1)
    print(f"Completed: {desc}\n")

def main():
    # Check if data exists
    if not os.path.exists('malicious_phish.csv'):
        print("Error: malicious_phish.csv not found. Download from Kaggle and place in root.")
        sys.exit(1)

    # Run pipeline
    run_command("python src/preprocess.py", "Preprocessing data")
    run_command("python src/ingest.py", "Ingesting into MongoDB")
    run_command("python src/mapreduce_queries.py", "Running aggregations")
    run_command("python src/visualize.py", "Generating visualizations")
    run_command("python src/ml_predict.py", "Training ML model")
    run_command("python src/anomaly_detect.py", "Detecting anomalies")

    print("\nPipeline completed! Starting web services...")
    
    # Kill any existing processes on the ports
    os.system("pkill -f 'python.*dashboard.py'")
    os.system("pkill -f 'python.*mongodb_viewer.py'")
    
    try:
        # Start the main dashboard
        dashboard_process = subprocess.Popen(
            ["./venv/bin/python", "src/dashboard.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
            universal_newlines=True
        )
        
        # Start the MongoDB viewer
        mongodb_viewer_process = subprocess.Popen(
            ["./venv/bin/python", "src/mongodb_viewer.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
            universal_newlines=True
        )
        
        print("\nStarting services...")
        print("Please wait a moment while both servers initialize...")
        
        import time
        time.sleep(3)  # Give servers time to start
        
        print("\n=== Services Started ===")
        print("1. Main Dashboard: http://localhost:5001")
        print("2. MongoDB Viewer: http://localhost:5002")
        print("\nKeep this terminal running to maintain the servers.")
        print("Press Ctrl+C to stop all services.")
        
        # Keep the script running and monitor the processes
        while True:
            # Check if processes are still running
            if dashboard_process.poll() is not None:
                print("Dashboard server stopped unexpectedly. Restarting...")
                dashboard_process = subprocess.Popen(
                    ["./venv/bin/python", "src/dashboard.py"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    bufsize=1,
                    universal_newlines=True
                )
            
            if mongodb_viewer_process.poll() is not None:
                print("MongoDB viewer stopped unexpectedly. Restarting...")
                mongodb_viewer_process = subprocess.Popen(
                    ["./venv/bin/python", "src/mongodb_viewer.py"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    bufsize=1,
                    universal_newlines=True
                )
            
            # Print any output from the processes
            dashboard_out = dashboard_process.stdout.readline()
            if dashboard_out:
                print("Dashboard:", dashboard_out.strip())
            
            mongodb_out = mongodb_viewer_process.stdout.readline()
            if mongodb_out:
                print("MongoDB Viewer:", mongodb_out.strip())
            
            time.sleep(1)  # Prevent high CPU usage
            
    except KeyboardInterrupt:
        print("\nShutting down services...")
        dashboard_process.terminate()
        mongodb_viewer_process.terminate()
        print("Services stopped successfully.")
        sys.exit(0)
    except Exception as e:
        print(f"Error running services: {e}")
        dashboard_process.terminate()
        mongodb_viewer_process.terminate()
        sys.exit(1)

if __name__ == '__main__':
    main()