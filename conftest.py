"""Pytest root configuration: project-root importability + test-safe env.

Environment overrides are applied BEFORE any backend import so that
get_settings() (cached) sees them:
- RATE_LIMIT_PER_MINUTE raised: integration tests issue many fast requests
  from one client IP and must not trip the (real) API rate limiter.
- ALLOW_LOCAL_TARGETS=false stays the safe default; tests that need localhost
  pass allow_local explicitly at the SafetyController level only.
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("RATE_LIMIT_PER_MINUTE", "10000")
os.environ.setdefault("AUTH_REQUIRED", "false")  # backend/tests/test_auth.py turns it on explicitly
os.environ.setdefault("DB_DIR", str(ROOT / "data" / "db"))
