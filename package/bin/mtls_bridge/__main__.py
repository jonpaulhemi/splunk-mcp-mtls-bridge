"""Run the bridge outside Splunk from a JSON config file (development and testing)."""

import argparse
import datetime
import json
import logging
import signal
import threading

from .config import Config, Mapping, RoleAccount, UserRule
from .server import BridgeServer

_TOKEN_CHECK_SECONDS = 30


def load_config(path):
    with open(path) as handle:
        values = json.load(handle)
    values["mappings"] = [Mapping(**_dated(m)) for m in values.get("mappings", [])]
    values["role_accounts"] = [RoleAccount(**_dated(a)) for a in values.get("role_accounts", [])]
    values["user_rules"] = [UserRule(**r) for r in values.get("user_rules", [])]
    return Config(**values)


def _dated(fields):
    """``fields`` with its token_expiry, written as YYYY-MM-DD, as a date."""
    expiry = fields.get("token_expiry")
    return dict(fields, token_expiry=datetime.date.fromisoformat(expiry) if expiry else None)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="mtls_bridge", description=__doc__)
    parser.add_argument("config", help="path to a JSON file holding Config fields")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    stopping = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopping.set())
    signal.signal(signal.SIGINT, lambda *_: stopping.set())
    bridge = BridgeServer(load_config(args.config)).start()
    logging.getLogger("mtls_bridge").info("listening on %s:%s", *bridge.address)
    # No config polls here, but expiry warnings still repeat daily and unreachable checks retry.
    while True:
        bridge.check_tokens()
        if stopping.wait(_TOKEN_CHECK_SECONDS):
            break
    bridge.stop()


if __name__ == "__main__":
    main()
