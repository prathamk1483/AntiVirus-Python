import json
import time
import threading
import psutil  # Ensure you have installed psutil (pip install psutil)
from channels.generic.websocket import WebsocketConsumer
from . engine import Engine  # Adjust the import if necessary

class DashBoardConsumer(WebsocketConsumer):
    def connect(self):
        self.accept()
        self.running = True

        # Start a thread to send system stats periodically
        def send_stats():
            while self.running:
                stats = {
                    'cpu': psutil.cpu_percent(interval=1),
                    'ram': psutil.virtual_memory().percent,
                    'storage': psutil.disk_usage('/').percent
                }
                self.send(text_data=json.dumps(stats))
                time.sleep(1)
                
        threading.Thread(target=send_stats, daemon=True).start()

    def receive(self, text_data):
        data = json.loads(text_data)
        if 'path' in data:
            folder_path = data['path']
            if folder_path == "":
                folder_path = "D:/4k WALLPAPERS"
            def scan_callback(file_path):
                # Send a progress update for each file scanned
                progress_update = {
                    'type': 'scan_progress',
                    'current_file': file_path
                }
                self.send(text_data=json.dumps(progress_update))
            def run_scan():
                try:
                    # Instantiate your engine with SHA256 (or "md5" if preferred)
                    engine = Engine("sha256")

                    virusHashes, virusPaths = engine.virusScannerSha256(folder_path, scan_callback=scan_callback)
                    result = {
                        'type': 'scan_result',
                        'virusHashes': virusHashes,
                        'virusPaths': virusPaths,
                    }
                    self.send(text_data=json.dumps(result))
                except Exception as e:
                    error = {
                        'type': 'error',
                        'message': str(e)
                    }
                    self.send(text_data=json.dumps(error))
            # Run the scanning in a separate thread to avoid blocking the WebSocket
            threading.Thread(target=run_scan, daemon=True).start()
        elif 'action' in data:
            action = data['action']
            if action == 'clearJunk':
                def run_cleanup():
                    engine = Engine("sha256")

                    def cleanup_callback(message):
                        self.send(text_data=json.dumps({
                            'type': 'junk_progress',
                            'message': message
                        }))

                    engine.CacheFileRemover(callback=cleanup_callback)

                threading.Thread(target=run_cleanup, daemon=True).start()

    def disconnect(self, close_code):
        self.running = False
