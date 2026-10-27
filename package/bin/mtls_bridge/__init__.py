"""mTLS-to-bearer-token bridge for the Splunk MCP Server app.

The daemon must import only the Python standard library.
"""

import json
import os


def _app_version():
    """The version in the app's app.manifest, which the release build stamps from the git tag."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, os.pardir, "app.manifest")
    try:
        with open(path) as handle:
            return json.load(handle)["info"]["id"]["version"]
    except (OSError, ValueError, KeyError, TypeError):
        return "unknown"


__version__ = _app_version()
