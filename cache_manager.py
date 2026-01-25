import threading
import time
from collections import OrderedDict
import json

class CacheManager:
    def __init__(self, max_size=1000, ttl=300):
        self.cache = OrderedDict()
        self.max_size = max_size
        self.ttl = ttl  # Time to live in seconds
        self.lock = threading.Lock()
    
    def get(self, key):
        """Get value from cache"""
        with self.lock:
            if key in self.cache:
                value, timestamp = self.cache[key]
                if time.time() - timestamp < self.ttl:
                    # Move to end (most recently used)
                    self.cache.move_to_end(key)
                    return value
                else:
                    # Expired, delete it
                    del self.cache[key]
        return None
    
    def set(self, key, value):
        """Set value in cache"""
        with self.lock:
            if key in self.cache:
                del self.cache[key]
            elif len(self.cache) >= self.max_size:
                # Remove oldest item
                self.cache.popitem(last=False)
            
            self.cache[key] = (value, time.time())
    
    def delete(self, key):
        """Delete key from cache"""
        with self.lock:
            if key in self.cache:
                del self.cache[key]
                return True
        return False
    
    def clear(self):
        """Clear all cache"""
        with self.lock:
            self.cache.clear()
    
    def get_or_set(self, key, func, *args, **kwargs):
        """Get from cache or set using function"""
        value = self.get(key)
        if value is None:
            value = func(*args, **kwargs)
            if value is not None:
                self.set(key, value)
        return value

# Cache keys
class CacheKeys:
    @staticmethod
    def user(user_id):
        return f"user:{user_id}"
    
    @staticmethod
    def form(form_id):
        return f"form:{form_id}"
    
    @staticmethod
    def user_forms(user_id):
        return f"user_forms:{user_id}"
    
    @staticmethod
    def notifications(user_id):
        return f"notifications:{user_id}"
    
    @staticmethod
    def unread_count(user_id):
        return f"unread_count:{user_id}"

# Global cache instance
cache = CacheManager(max_size=2000, ttl=60)  # Cache for 1 minute
