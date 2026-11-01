#!/usr/bin/env python3
"""Fixed systemd entrypoint; no command-line policy or executable arguments."""
import os
from pathlib import Path
import sys

probe = sys.argv[1:] == ["--probe"]
if sys.argv[1:] not in ([], ["--probe"]):
    raise SystemExit("Fixed local observer entrypoint")
sys.path.insert(0, str(Path(__file__).resolve().parent))
import local_alerts

credentials = Path(os.environ["CREDENTIALS_DIRECTORY"])
suffix = "-probe" if probe else ""
sys.argv = [sys.argv[0], "--config", str(credentials / "checks.json"),
            "--state-dir", "/var/lib/homelab-local-alerts" + suffix,
            "--status-dir", "/var/lib/homelab-local-alerts-status" + suffix]
if not probe:
    sys.argv += ["--credentials", str(credentials)]
raise SystemExit(local_alerts.main())
