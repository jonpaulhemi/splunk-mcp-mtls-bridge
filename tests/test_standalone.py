"""The daemon runs on Splunk's bundled Python with nothing but the standard library."""

import json
import subprocess
import sys
import time
from dataclasses import asdict

from conftest import ROOT, Client, make_config

BIN = ROOT / "package" / "bin"


def test_daemon_imports_only_the_standard_library():
    # -S drops site-packages, so any third-party import fails.
    code = (
        f"import pkgutil, importlib, sys; sys.path.insert(0, {str(BIN)!r}); import mtls_bridge; "
        "[importlib.import_module('mtls_bridge.' + m.name) for m in pkgutil.iter_modules(mtls_bridge.__path__)]"
    )
    result = subprocess.run([sys.executable, "-I", "-S", "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_bridge_runs_as_a_standalone_process(test_pki, upstream, tmp_path, unused_port):
    config = asdict(make_config(test_pki, upstream, listen_port=unused_port))
    config_path = tmp_path / "bridge.json"
    config_path.write_text(json.dumps(config))
    process = subprocess.Popen(
        [sys.executable, "-m", "mtls_bridge", str(config_path)],
        cwd=str(BIN),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        client = Client(("127.0.0.1", unused_port), test_pki.ca.cert_path, test_pki.mapped.cert, test_pki.mapped.key)
        deadline = time.monotonic() + 10
        while True:
            try:
                status, _, body = client.rpc("tools/list")
                break
            except ConnectionRefusedError:
                if time.monotonic() > deadline or process.poll() is not None:
                    raise
                time.sleep(0.1)
        assert status == 200
        assert body["result"]["tools"][0]["name"] == "splunk_run_query"
    finally:
        process.terminate()
        process.wait(timeout=10)
