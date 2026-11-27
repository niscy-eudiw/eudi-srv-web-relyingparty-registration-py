import os
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# app/__init__.py loads the trusted CAs from TRUSTED_CAS_PATH at import time and
# fails when that directory does not exist: point it to an empty one.
os.environ["TRUSTED_CAS_PATH"] = tempfile.mkdtemp(prefix="trusted-cas-")

# The app writes its log (app\logs) and sessions (flask_session) relative to the
# working directory: keep the tests' output out of the repository.
os.chdir(tempfile.mkdtemp(prefix="rpr-tests-"))


def pytest_unconfigure(config):
    # app/data_management.py starts a self-rescheduling, non-daemon
    # threading.Timer on import, which would keep the process alive forever.
    for thread in threading.enumerate():
        if isinstance(thread, threading.Timer):
            thread.cancel()
