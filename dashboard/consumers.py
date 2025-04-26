import json
import time
import threading
import psutil
import requests
from channels.generic.websocket import WebsocketConsumer
from .engine import Engine

class DashBoardConsumer(WebsocketConsumer):
    def connect(self):
        self.accept()
        self.running = True

        def send_stats():
            while self.running:
                stats = {
                    "client": "PC2",
                    "type": "malware",
                    "subType" : "system usage",
                    "data": {
                        'cpu': psutil.cpu_percent(interval=1),
                        'ram': psutil.virtual_memory().percent,
                        'storage': psutil.disk_usage('/').percent
                    }
                }
                self.send(text_data=json.dumps(stats))
                send_to_dashboard_api(stats)
                time.sleep(10)

        threading.Thread(target=send_stats, daemon=True).start()

    def receive(self, text_data):
        data = json.loads(text_data)

        if 'path' in data:
            folder_path = data['path'] or "D:/4k WALLPAPERS"

            def scan_callback(file_path):
                progress_data = {
                    "client": "PC2",
                    "type": "malware",
                    "subType" : "malware scan",
                    "data": {
                        'type': 'scan_progress',
                        'current_file': file_path
                    }
                }
                self.send(text_data=json.dumps(progress_data['data']))
                send_to_dashboard_api(progress_data)

            def run_scan():
                try:
                    engine = Engine("sha256")
                    virusHashes, virusPaths = engine.virusScannerSha256(folder_path, scan_callback=scan_callback)

                    result_data = {
                        "client": "PC2",
                        "type": "malware",
                        "data": {
                            'type': 'scan_result',
                            'virusHashes': virusHashes,
                            'virusPaths': virusPaths
                        }
                    }
                    self.send(text_data=json.dumps(result_data['data']))
                    send_to_dashboard_api(result_data)
                except Exception as e:
                    error_data = {
                        "client": "PC2",
                        "type": "malware",
                        "data": {
                            'type': 'error',
                            'message': str(e)
                        }
                    }
                    self.send(text_data=json.dumps(error_data['data']))
                    send_to_dashboard_api(error_data)

            threading.Thread(target=run_scan, daemon=True).start()

        elif 'action' in data and data['action'] == 'clearJunk':
            def run_cleanup():
                engine = Engine("sha256")

                def cleanup_callback(message):
                    cleanup_data = {
                        "client": "PC2",
                        "type": "malware",
                        "subType" : "junk cleanup",
                        "data": {
                            'type': 'junk_progress',
                            'message': message
                        }
                    }
                    self.send(text_data=json.dumps(cleanup_data['data']))
                    send_to_dashboard_api(cleanup_data)

                engine.CacheFileRemover(callback=cleanup_callback)

            threading.Thread(target=run_cleanup, daemon=True).start()

    def disconnect(self, close_code):
        self.running = False

def send_to_dashboard_api(data):
    try:
        response = requests.post(
            "https://centraldashboard.onrender.com/api/receiveLogs/",
            data=json.dumps(data),
            headers={"Content-Type": "application/json"},
        )
    except Exception as e:
        print(f"[API Error] Failed to POST data:")
