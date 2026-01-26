#!/usr/bin/env python3
"""
Initialize secure configuration
Run this once: python init_config.py
"""

print("Initializing secure configuration...")

try:
    from secure_config import setup_secure_config
    setup_secure_config()
except ImportError:
    print("Creating secure_config.py first...")
    
    # Create the secure_config.py file
    secure_config_code = '''
import os
import json
import base64
from cryptography.fernet import Fernet

class SecureConfig:
    def __init__(self, key_file='secret.key', config_file='config.enc'):
        self.key_file = key_file
        self.config_file = config_file
        self.key = self._load_or_create_key()
        self.cipher = Fernet(self.key)
    
    def _load_or_create_key(self):
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            os.chmod(self.key_file, 0o400)
            print(f"✅ New encryption key created: {self.key_file}")
            return key
    
    def save_config(self, config_dict):
        try:
            config_json = json.dumps(config_dict)
            encrypted_data = self.cipher.encrypt(config_json.encode())
            
            with open(self.config_file, 'wb') as f:
                f.write(encrypted_data)
            
            os.chmod(self.config_file, 0o400)
            print(f"✅ Configuration saved to: {self.config_file}")
            return True
        except Exception as e:
            print(f"❌ Error saving config: {e}")
            return False
    
    def load_config(self):
        if not os.path.exists(self.config_file):
            print("⚠️  No config file found")
            return {}
        
        try:
            with open(self.config_file, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self.cipher.decrypt(encrypted_data)
            config_dict = json.loads(decrypted_data.decode())
            
            print(f"✅ Configuration loaded from: {self.config_file}")
            return config_dict
        except Exception as e:
            print(f"❌ Error loading config: {e}")
            return {}

secure_config = SecureConfig()
'''
    
    with open('secure_config.py', 'w') as f:
        f.write(secure_config_code)
    
    print("✅ Created secure_config.py")
    print("Please run this script again to setup configuration.")
