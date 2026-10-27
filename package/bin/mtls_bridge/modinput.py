"""The bridge's life as a splunkd modular input.

splunkd starts this script once (a single-instance scheme with one fixed stanza) and passes its URI
and a session key on stdin. The script reads the app's config with that key, runs the bridge, re-reads
the config every poll and applies changes live, and exits on SIGTERM, when splunkd itself goes away,
or when splunkd stops accepting the key. splunkd restarts it after the stanza's interval.
"""

import fcntl
import logging
import logging.handlers
import os
import signal
import threading
import time
import xml.etree.ElementTree as ElementTree

from . import splunk_config
from .server import ApplyError, BridgeServer

log = logging.getLogger("mtls_bridge")

SCHEME = """<scheme>
    <title>mTLS Bridge for Splunk MCP</title>
    <description>Runs the mTLS listener that forwards MCP calls to the Splunk MCP Server app.</description>
    <use_external_validation>false</use_external_validation>
    <use_single_instance>true</use_single_instance>
    <streaming_mode>simple</streaming_mode>
    <endpoint>
        <args/>
    </endpoint>
</scheme>
"""

_LOG_FILE = "ta_mtls_bridge.log"
_PARENT_CHECK_SECONDS = 1.0
_POLL_SECONDS = 30.0
# Tests shorten the config poll with this environment variable.
_POLL_ENV = "TA_MTLS_BRIDGE_POLL_SECONDS"


def main(argv, stdin):
    parent = os.getppid()  # splunkd; read first, before anything can outlive it
    if argv[:1] == ["--scheme"]:
        print(SCHEME)
        return 0
    if argv[:1] == ["--validate-arguments"]:
        return 0

    stopping = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopping.set())
    signal.signal(signal.SIGINT, lambda *_: stopping.set())
    splunk_home = os.environ.get("SPLUNK_HOME", "")
    _configure_logging(splunk_home)
    inputs = _parse_input(stdin.read())

    lock = _acquire_lock(inputs["checkpoint_dir"])
    if lock is None:
        log.info("another bridge instance is already running; exiting")
        return 0
    try:
        return _run(inputs, splunk_home, parent, stopping)
    finally:
        lock.close()


def _run(inputs, splunk_home, parent, stopping):
    try:
        config = splunk_config.load(inputs["server_uri"], inputs["session_key"], splunk_home)
    except splunk_config.NotConfigured as exc:
        log.warning("bridge not configured: %s", exc)
        return 0
    except splunk_config.SessionExpired as exc:
        _session_key_rejected(exc)
        return 1
    except splunk_config.ConfigError as exc:
        log.error("bridge configuration error: %s", exc)
        return 1
    if not _sync_audit_input(inputs):
        return 1

    if stopping.is_set():
        return 0
    try:
        bridge = BridgeServer(config).start()
    except OSError as exc:
        log.error("cannot start listener on %s:%s: %s", config.listen_host, config.listen_port, exc)
        return 1
    log.info("bridge listening on %s:%s with %d mappings", *bridge.address, len(config.mappings))

    poll = _poll_seconds()
    next_poll = time.monotonic() + poll
    status = 0
    while not stopping.wait(min(_PARENT_CHECK_SECONDS, poll)):
        if os.getppid() != parent:
            log.info("parent process exited; stopping")
            break
        if time.monotonic() >= next_poll:
            next_poll = time.monotonic() + poll
            if not _reload(bridge, inputs, splunk_home):
                status = 1
                break
    bridge.stop()
    log.info("bridge stopped")
    return status


def _poll_seconds():
    try:
        return max(0.1, float(os.environ.get(_POLL_ENV) or _POLL_SECONDS))
    except ValueError:
        return _POLL_SECONDS


def _session_key_rejected(exc):
    log.error("splunkd rejected the session key; exiting so splunkd restarts the bridge: %s", exc)


def _reload(bridge, inputs, splunk_home):
    """Re-read the config and apply it. Returns False if the daemon must exit for a fresh session key."""
    try:
        config = splunk_config.load(inputs["server_uri"], inputs["session_key"], splunk_home)
    except splunk_config.SessionExpired as exc:
        _session_key_rejected(exc)
        return False
    except splunk_config.ConfigError as exc:
        log.error("cannot reload the configuration (%s); keeping the last good configuration", exc)
        return True
    if not _sync_audit_input(inputs):
        return False
    changed = config != bridge.config
    try:
        # Applied even when unchanged, to pick up a CA bundle or cert replaced at the same path.
        bridge.apply(config)
    except ApplyError as exc:
        log.error("applied the new mappings; keeping the last good configuration for the %s", exc)
        return True
    if changed:
        log.info("configuration reloaded: listening on %s:%s with %d mappings", *bridge.address, len(config.mappings))
    return True


def _sync_audit_input(inputs):
    """Bring the audit monitor input in line with the Audit page. Returns False on a rejected session key."""
    try:
        splunk_config.sync_audit_input(inputs["server_uri"], inputs["session_key"])
    except splunk_config.SessionExpired as exc:
        _session_key_rejected(exc)
        return False
    except splunk_config.ConfigError as exc:
        # The bridge still writes the audit file; only where Splunk indexes it is stale.
        log.error("cannot update the audit input: %s", exc)
    return True


def _parse_input(text):
    root = ElementTree.fromstring(text)
    return {name: (root.findtext(name) or "").strip() for name in ("server_uri", "session_key", "checkpoint_dir")}


def _acquire_lock(directory):
    """Hold an exclusive lock for this process's lifetime, or return None if another instance has it."""
    os.makedirs(directory, exist_ok=True)
    handle = open(os.path.join(directory, "mtls_bridge.lock"), "w")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        return None
    return handle


def _configure_logging(splunk_home):
    log_dir = os.path.join(splunk_home, "var", "log", "splunk")
    if splunk_home and os.path.isdir(log_dir):
        handler = logging.handlers.RotatingFileHandler(
            os.path.join(log_dir, _LOG_FILE), maxBytes=25 * 1024 * 1024, backupCount=5
        )
    else:
        handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s pid=%(process)d %(name)s - %(message)s"))
    log.addHandler(handler)
    log.setLevel(logging.INFO)
