"""Run the bridge outside Splunk from a JSON config file (development and testing)."""

import argparse
import json
import logging
import signal
import sys

from .config import Config, Mapping
from .server import BridgeServer


def load_config(path):
    with open(path) as handle:
        values = json.load(handle)
    values["mappings"] = [Mapping(**m) for m in values.get("mappings", [])]
    return Config(**values)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="mtls_bridge", description=__doc__)
    parser.add_argument("config", help="path to a JSON file holding Config fields")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    bridge = BridgeServer(load_config(args.config))
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    logging.getLogger("mtls_bridge").info("listening on %s:%s", *bridge.address)
    try:
        bridge.serve_forever()
    finally:
        bridge.stop()


if __name__ == "__main__":
    main()
