"""
Utility module for common functions such as logging configuration.
"""

import logging


def setup_logging(verbose: bool) -> None:
    """
    Configure logging for the application.

    Args:
        verbose (bool): Enables DEBUG level logging if True; otherwise INFO.
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

# Add retry decorator in utils.py
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

