import os
import sys

# Scripts need a config file; tests use the shipped example.
os.environ.setdefault("CEDAR_DEMO_CONFIG", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.env.example"))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for sub in ("interceptor", os.path.join("tools", "claims_tool")):
    p = os.path.join(ROOT, sub)
    if p not in sys.path:
        sys.path.insert(0, p)
