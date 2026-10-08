#!/usr/bin/env python3
import subprocess
import sys

result = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests"])
sys.exit(result.returncode)
