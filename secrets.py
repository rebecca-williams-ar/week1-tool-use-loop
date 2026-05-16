"""
secrets.py — Centralized secret retrieval
==========================================
All credential access goes through this module.
To migrate from .env to a real secrets manager (GCP Secret Manager,
AWS Secrets Manager, HashiCorp Vault), update only this file.
No other module needs to change.

Current backend: environment variables via python-dotenv
Production backend: replace get_secret() body with SDK calls to your
                    chosen secrets manager.
"""

import os


def get_secret(key: str) -> str:
    """
    Retrieve a required secret by name.
    Raises EnvironmentError immediately if the secret is missing —
    fail loudly, never fall back to a default.
    """
    value = os.environ.get(key)
    if not value:
        raise EnvironmentError(
            f"Required secret '{key}' is not set. "
            f"Copy .env.example to .env and add your credentials."
        )
    return value
