"""Check that splunkd can discover the bridge's modular input and restart its daemon.

splunkd only discovers a modular input whose spec declares at least one parameter (comments don't count).
The spec must not declare interval: for a single-instance input splunkd then ignores the scheme default
interval and never restarts the daemon after it exits. Usage: check_modinput_spec.py APP_DIR
"""

import configparser
import sys
from pathlib import Path

SPEC_STANZA = "[mtls_bridge_daemon://<name>]"
SCHEME = "mtls_bridge_daemon"
INSTANCE = "mtls_bridge_daemon://bridge"
RESTART_SECONDS = "30"


def _spec_parameters(text):
    """The parameter names the daemon's spec stanza declares."""
    names, inside = [], False
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("["):
            inside = line == SPEC_STANZA
        elif inside and line and line[0] not in "*#" and "=" in line:
            names.append(line.split("=", 1)[0].strip())
    return names


def problems(app):
    """What would stop splunkd discovering or restarting the daemon in the app at ``app``."""
    app = Path(app)
    found = []
    names = _spec_parameters((app / "README" / "inputs.conf.spec").read_text())
    stanza = SPEC_STANZA[1:-1]
    if not names:
        found.append(f"README/inputs.conf.spec declares no parameter for {stanza}; splunkd won't discover it")
    if "disabled" not in names:
        found.append(f"README/inputs.conf.spec must declare disabled for {stanza}")
    if "interval" in names:
        found.append(f"README/inputs.conf.spec must not declare interval for {stanza}")
    inputs = configparser.ConfigParser(interpolation=None, strict=False)
    inputs.optionxform = str
    inputs.read(app / "default" / "inputs.conf")
    if inputs.get(SCHEME, "interval", fallback=None) != RESTART_SECONDS:
        found.append(f"default/inputs.conf [{SCHEME}] must set interval = {RESTART_SECONDS}")
    if inputs.has_option(INSTANCE, "interval"):
        found.append(f"default/inputs.conf [{INSTANCE}] must not override interval")
    return found


if __name__ == "__main__":
    found = problems(sys.argv[1])
    for problem in found:
        print(problem, file=sys.stderr)
    sys.exit(1 if found else 0)
