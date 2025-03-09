"""
Utility module for common functions such as logging configuration.
"""

import queue
import threading
import hashlib
import base64
import socket
import os
import logging
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class ThreadSafeQueue:
    """Thread-safe task queue implementation."""
    def __init__(self):
        self.queue = queue.Queue()
        self.workers = []
        self.shutdown_flag = threading.Event()
    
    def start(self, num_workers=1):
        """Start worker threads to process the queue."""
        self.shutdown_flag.clear()
        for _ in range(num_workers):
            worker = threading.Thread(target=self._worker_thread, daemon=True)
            worker.start()
            self.workers.append(worker)
    
    def stop(self):
        """Stop all worker threads."""
        self.shutdown_flag.set()
        for worker in self.workers:
            if worker.is_alive():
                worker.join(timeout=1.0)
        self.workers = []
    
    def _worker_thread(self):
        """Worker thread that processes tasks from the queue."""
        while not self.shutdown_flag.is_set():
            try:
                task, args, kwargs = self.queue.get(timeout=0.5)
                try:
                    task(*args, **kwargs)
                except Exception as e:
                    logging.error(f"Error in worker thread: {e}")
                finally:
                    self.queue.task_done()
            except queue.Empty:
                continue
    
    def add_task(self, task, *args, **kwargs):
        """Add a task to the queue."""
        self.queue.put((task, args, kwargs))



class SecureStorage:
    """Secure storage for sensitive data using Fernet encryption."""
    
    @staticmethod
    def _derive_key(password=None):
        """Derive a key from a password or machine-specific data.
        
        Args:
            password: Optional password bytes. If None, uses machine-specific info
            
        Returns:
            bytes: URL-safe base64 encoded key for Fernet
        """
        if password is None:
            # Use machine-specific information as password
            machine_info = os.name + socket.gethostname() + os.path.expanduser("~")
            password = machine_info.encode()
        
        # Create a salt (ideally this would be stored securely)
        salt = hashlib.sha256(password).digest()[:16]
        
        # Generate a key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    @staticmethod
    def encrypt(data, password=None):
        """Encrypt data using Fernet symmetric encryption.
        
        Args:
            data: String or bytes to encrypt
            password: Optional password for encryption (machine-specific by default)
            
        Returns:
            str: Base64 encoded encrypted data
        """
        # Convert data to bytes if it's a string
        if isinstance(data, str):
            data = data.encode()
            
        # Generate a key
        key = SecureStorage._derive_key(password)
        
        # Create a Fernet instance and encrypt
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(data)
        
        return base64.urlsafe_b64encode(encrypted_data).decode()
    
    @staticmethod
    def decrypt(encrypted_data, password=None):
        """Decrypt data encrypted with the encrypt method.
        
        Args:
            encrypted_data: Base64 encoded encrypted data
            password: Same password used for encryption (machine-specific by default)
            
        Returns:
            str: Decrypted data as a string
        """
        # Generate the same key used for encryption
        key = SecureStorage._derive_key(password)
        
        # Decode the base64 data
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data)
        
        # Create a Fernet instance and decrypt
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_bytes)
        
        return decrypted_data.decode()


def setup_logging(verbose: bool, log_level: Optional[int] = None) -> None:
    """
    Configure logging for the application.

    Args:
        verbose (bool): Enables DEBUG level logging if True; otherwise INFO.
        log_level (Optional[int]): Specific log level to set. Overrides verbose if provided.
    """
    if log_level is None:
        log_level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.StreamHandler()
        ]
    )
    logging.getLogger().setLevel(log_level)

# Retry decorator
import time
from functools import wraps

def retry_with_backoff(max_retries=3, initial_backoff=1, backoff_factor=2):
    """Retry a function with exponential backoff."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            current_backoff = initial_backoff
            
            while True:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    retries += 1
                    if retries > max_retries:
                        raise
                    
                    logging.warning(
                        f"Attempt {retries} failed: {str(e)}. Retrying in {current_backoff} seconds..."
                    )
                    time.sleep(current_backoff)
                    current_backoff *= backoff_factor
        return wrapper
    return decorator

