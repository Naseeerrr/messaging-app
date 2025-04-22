import base64
import os
import hashlib

class Encryptor:
    def __init__(self, key=None):
        # Use provided key or generate a default one
        if key is None:
            # Default key - in a real application, this would be securely shared
            self.key = b'IS370_SECURE_MESSAGING_KEY'
        else:
            self.key = key.encode() if isinstance(key, str) else key
        
        # Create a fixed-length key using SHA-256
        self.key_hash = hashlib.sha256(self.key).digest()
    
    def encrypt(self, message):
        """Encrypt a message using XOR with the key"""
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        # XOR each byte of the message with the corresponding byte of the key
        encrypted = bytearray()
        for i in range(len(message)):
            encrypted.append(message[i] ^ self.key_hash[i % len(self.key_hash)])
        
        # Encode as base64 for safe transmission
        return base64.b64encode(encrypted).decode('utf-8')
    
    def decrypt(self, encrypted_message):
        """Decrypt a message using XOR with the key"""
        try:
            # Decode from base64
            encrypted = base64.b64decode(encrypted_message)
            
            # XOR each byte with the key to get the original message
            decrypted = bytearray()
            for i in range(len(encrypted)):
                decrypted.append(encrypted[i] ^ self.key_hash[i % len(self.key_hash)])
            
            return decrypted.decode('utf-8')
        except:
            # If decryption fails, return the original message
            # This handles the case of receiving unencrypted messages
            return encrypted_message
