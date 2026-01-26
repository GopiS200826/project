"""
Secure Configuration Manager
Store sensitive data in encrypted format
"""

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
        """Load existing key or create new one"""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                return f.read()
        else:
            # Generate new key
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            # Make it read-only
            os.chmod(self.key_file, 0o400)
            print(f"✅ New encryption key created: {self.key_file}")
            return key
    
    def save_config(self, config_dict):
        """Encrypt and save configuration"""
        try:
            # Convert to JSON and encrypt
            config_json = json.dumps(config_dict)
            encrypted_data = self.cipher.encrypt(config_json.encode())
            
            # Save encrypted file
            with open(self.config_file, 'wb') as f:
                f.write(encrypted_data)
            
            # Make it read-only
            os.chmod(self.config_file, 0o400)
            print(f"✅ Configuration saved to: {self.config_file}")
            return True
        except Exception as e:
            print(f"❌ Error saving config: {e}")
            return False
    
    def load_config(self):
        """Decrypt and load configuration"""
        if not os.path.exists(self.config_file):
            print("⚠️  No config file found")
            return {}
        
        try:
            with open(self.config_file, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt
            decrypted_data = self.cipher.decrypt(encrypted_data)
            config_dict = json.loads(decrypted_data.decode())
            
            print(f"✅ Configuration loaded from: {self.config_file}")
            return config_dict
        except Exception as e:
            print(f"❌ Error loading config: {e}")
            return {}
    
    def get(self, key, default=None):
        """Get a specific configuration value"""
        config = self.load_config()
        return config.get(key, default)

# Create global instance
secure_config = SecureConfig()

# Helper function to setup config for first time
def setup_secure_config():
    """Interactive setup for first-time configuration"""
    print("🔐 Secure Configuration Setup")
    print("=" * 40)
    
    config = {}
    
    config['MYSQL_HOST'] = input("MySQL Host [mysql-vdry.railway.internal]: ") or "mysql-vdry.railway.internal"
    config['MYSQL_USER'] = input("MySQL User [root]: ") or "root"
    config['MYSQL_PASSWORD'] = input("MySQL Password [kyzpHUHOJbBcdufVHeqRgYwjSVbgxiDs]: ") or "kyzpHUHOJbBcdufVHeqRgYwjSVbgxiDs"
    config['MYSQL_DB'] = input("MySQL Database [railway]: ") or "railway"
    
    config['ADMIN_PASSWORD'] = input("Admin Password: ")
    config['SUPER_ADMIN_PASSWORD'] = input("Super Admin Password: ")
    
    # Optional email config
    use_email = input("Configure email? (y/n): ").lower() == 'y'
    if use_email:
        config['EMAIL_USER'] = input("Email: ")
        config['EMAIL_PASSWORD'] = input("Email App Password: ")
    
    config['FLASK_SECRET_KEY'] = input("Flask Secret Key [auto-generate]: ") or base64.urlsafe_b64encode(os.urandom(32)).decode()
    
    # Save
    if secure_config.save_config(config):
        print("\n✅ Configuration saved successfully!")
        print(f"🔑 Key file: {secure_config.key_file}")
        print(f"📁 Config file: {secure_config.config_file}")
        print("\n⚠️  IMPORTANT: Add these files to .gitignore!")
        return True
    return False

if __name__ == "__main__":
    setup_secure_config()
