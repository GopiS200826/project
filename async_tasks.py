import threading
import queue
import time
from datetime import datetime

class AsyncTaskManager:
    def __init__(self):
        self.task_queue = queue.Queue()
        self.results = {}
        self.worker_thread = threading.Thread(target=self._worker, daemon=True)
        self.worker_thread.start()
    
    def _worker(self):
        """Background worker for async tasks"""
        while True:
            try:
                task_id, task_type, data = self.task_queue.get(timeout=1)
                
                if task_type == 'send_email':
                    self._send_email_async(data)
                elif task_type == 'create_notification':
                    self._create_notification_async(data)
                elif task_type == 'update_cache':
                    self._update_cache_async(data)
                
                self.task_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Async task error: {e}")
    
    def _send_email_async(self, data):
        """Send email in background"""
        # Import here to avoid circular imports
        from your_main_file import send_email  # You'll need to refactor this
        
        try:
            send_email(
                data['to_email'],
                data['subject'],
                data['html_content']
            )
        except Exception as e:
            print(f"Async email error: {e}")
    
    def _create_notification_async(self, data):
        """Create notification in background"""
        # Import here to avoid circular imports
        from your_main_file import create_notification  # You'll need to refactor this
        
        try:
            create_notification(
                user_id=data['user_id'],
                title=data['title'],
                message=data['message'],
                type=data.get('type', 'info'),
                link=data.get('link')
            )
            # Invalidate cache
            cache.delete(CacheKeys.notifications(data['user_id']))
            cache.delete(CacheKeys.unread_count(data['user_id']))
        except Exception as e:
            print(f"Async notification error: {e}")
    
    def _update_cache_async(self, data):
        """Update cache in background"""
        cache.delete(data['key'])
    
    def add_task(self, task_type, data):
        """Add task to queue"""
        task_id = f"{task_type}_{int(time.time())}"
        self.task_queue.put((task_id, task_type, data))
        return task_id

# Global async task manager
async_manager = AsyncTaskManager()
