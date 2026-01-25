import pymysql
import pymysql.cursors
from contextlib import contextmanager
import threading
from functools import lru_cache
import time

class DatabaseManager:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._init_pool()
        return cls._instance
    
    def _init_pool(self):
        self.connection_pool = []
        self.max_pool_size = 10
        self.min_pool_size = 3
        self.connection_config = {
            'host': 'mysql--bgr.railway.internal',
            'user': 'root',
            'password': 'obqlFmxezajMwLfOusStXlHkPHtzQQGL',
            'database': 'railway',
            'charset': 'utf8mb4',
            'cursorclass': pymysql.cursors.DictCursor,
            'autocommit': False
        }
        # Initialize minimum connections
        for _ in range(self.min_pool_size):
            conn = pymysql.connect(**self.connection_config)
            self.connection_pool.append(conn)
    
    @contextmanager
    def get_connection(self):
        """Get a database connection from pool"""
        conn = None
        try:
            if self.connection_pool:
                conn = self.connection_pool.pop()
            else:
                conn = pymysql.connect(**self.connection_config)
            
            yield conn
        finally:
            if conn:
                if len(self.connection_pool) < self.max_pool_size:
                    self.connection_pool.append(conn)
                else:
                    conn.close()
    
    @contextmanager
    def get_cursor(self, connection=None):
        """Get a cursor for database operations"""
        if connection:
            with connection.cursor() as cursor:
                yield cursor
        else:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    yield cursor
    
    def execute_query(self, query, params=None, fetchone=False, fetchall=True):
        """Execute a query and return results"""
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(query, params or ())
                if fetchone:
                    result = cursor.fetchone()
                elif fetchall:
                    result = cursor.fetchall()
                else:
                    result = cursor.lastrowid
                conn.commit()
                return result
    
    # Cached queries for frequently accessed data
    @lru_cache(maxsize=128)
    def get_user_by_id(self, user_id):
        return self.execute_query(
            "SELECT * FROM users WHERE id = %s",
            (user_id,),
            fetchone=True
        )
    
    @lru_cache(maxsize=128)
    def get_form_by_id(self, form_id):
        return self.execute_query(
            "SELECT * FROM forms WHERE id = %s",
            (form_id,),
            fetchone=True
        )
    
    def close_all(self):
        """Close all connections in pool"""
        for conn in self.connection_pool:
            try:
                conn.close()
            except:
                pass
        self.connection_pool.clear()

# Global database manager instance
db_manager = DatabaseManager()
