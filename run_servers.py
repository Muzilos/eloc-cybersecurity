import os
import sys
import glob
import subprocess
import multiprocessing
import signal
import time

class FlaskServerManager:
    def __init__(self, base_directory='.'):
        self.base_directory = base_directory
        self.processes = []
        self.setup_signal_handlers()

    def setup_signal_handlers(self):
        signal.signal(signal.SIGINT, self.handle_shutdown)
        signal.signal(signal.SIGTERM, self.handle_shutdown)

    def find_server_files(self):
        """Find all server.py files in subdirectories."""
        pattern = os.path.join(self.base_directory, '*/server.py')
        return sorted(glob.glob(pattern))

    def run_flask_server(self, server_path):
        """Run a single Flask server in its own process."""
        try:
            directory = os.path.dirname(server_path)
            # Change to the server's directory
            os.chdir(directory)
            
            # Use python -u for unbuffered output
            process = subprocess.Popen(
                [sys.executable, '-u', 'server.py'],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            # Log server start
            print(f"Started Flask server in {directory}")
            
            # Monitor the process output
            while True:
                output = process.stdout.readline()
                if output:
                    print(f"[{os.path.basename(directory)}] {output.strip()}")
                if process.poll() is not None:
                    break
                
        except Exception as e:
            print(f"Error running server in {directory}: {e}")
            
        finally:
            os.chdir(self.base_directory)

    def start_all_servers(self):
        """Start all Flask servers in parallel."""
        server_files = self.find_server_files()
        if not server_files:
            print("No server.py files found in subdirectories!")
            return

        print(f"Found {len(server_files)} server files")
        
        # Start each server in a separate process
        for server_path in server_files:
            process = multiprocessing.Process(
                target=self.run_flask_server,
                args=(server_path,)
            )
            process.start()
            self.processes.append(process)

    def handle_shutdown(self, signum, frame):
        """Handle graceful shutdown of all servers."""
        print("\nShutting down all Flask servers...")
        for process in self.processes:
            if process.is_alive():
                process.terminate()
        
        # Wait for all processes to finish
        for process in self.processes:
            process.join()
        
        print("All servers stopped")
        sys.exit(0)

    def monitor_servers(self):
        """Monitor server processes and restart if needed."""
        while True:
            for i, process in enumerate(self.processes):
                if not process.is_alive():
                    print(f"Server process {i} died, restarting...")
                    server_files = self.find_server_files()
                    new_process = multiprocessing.Process(
                        target=self.run_flask_server,
                        args=(server_files[i],)
                    )
                    new_process.start()
                    self.processes[i] = new_process
            time.sleep(5)

if __name__ == "__main__":
    # Get base directory from command line argument or use current directory
    base_dir = sys.argv[1] if len(sys.argv) > 1 else '.'
    
    manager = FlaskServerManager(base_dir)
    manager.start_all_servers()
    
    try:
        manager.monitor_servers()
    except KeyboardInterrupt:
        manager.handle_shutdown(None, None)