"""Pytest configuration.

The application is now fail-closed: it refuses to start without a strong
SECRET_KEY. Tests only need *a* key, so we provide a deterministic one here
before any test module imports the app.
"""
import os

os.environ.setdefault("SECRET_KEY", "test-only-secret-key-not-for-production-0123456789")
