"""Seed settings.json for a prototype-mode PiFire container.

Writes a settings.json with hardware-touching modules set to prototype/none
and real_hw=False, so the app can start on a non-Pi host without crashing.
Bluetooth probe modules are left untouched and can be configured from the UI.
"""
import json
import os
import sys

sys.path.insert(0, "/app")

from common.common import default_settings

SETTINGS_PATH = "/app/settings.json"

if os.path.exists(SETTINGS_PATH):
    print(f"{SETTINGS_PATH} already exists, leaving it alone")
    sys.exit(0)

s = default_settings()
s["platform"]["real_hw"] = False
s["platform"]["system_type"] = "prototype"
s["modules"]["grillplat"] = "prototype"
s["modules"]["display"] = "none"
s["modules"]["dist"] = "none"
s["globals"]["first_time_setup"] = False
s["globals"]["venv"] = False
s["globals"]["uv"] = False
s["globals"]["python_exec"] = "python3"

with open(SETTINGS_PATH, "w") as f:
    json.dump(s, f, indent=2, sort_keys=True)

print(f"Seeded {SETTINGS_PATH} in prototype mode")
