"""The README's openssl example makes a CA and client cert that the bridge accepts."""

import re
import subprocess
import types

import pytest

from mtls_bridge.config import Mapping

from harness import ROOT, Client, make_config, running_bridge

ISSUER = "CN=Example MCP Client CA,O=Example Corp"
IDENTITY = "spiffe://example.com/agents/report-bot"


def _example():
    """The README's pki.cnf and openssl commands."""
    readme = (ROOT / "README.md").read_text()
    section = readme.split("### Example: a test CA with openssl", 1)[1].split("\n## ", 1)[0]
    config, commands = re.findall(r"```(?:ini|sh)\n(.*?)```", section, re.S)
    return config, commands.replace("\\\n", " ")


@pytest.mark.parametrize("key", ["ec", "rsa"])
def test_readme_openssl_example_makes_certs_the_bridge_accepts(test_pki, upstream, tmp_path, key):
    config, commands = _example()
    if key == "rsa":
        commands = commands.replace("-newkey ec -pkeyopt ec_paramgen_curve:P-256", "-newkey rsa:2048")
    (tmp_path / "pki.cnf").write_text(config)
    for command in filter(None, commands.splitlines()):
        subprocess.run(command, shell=True, cwd=str(tmp_path), check=True, capture_output=True)

    mapping = Mapping(issuer=ISSUER, identity_type="URI", identity_value=IDENTITY, account="svc_report_bot", token="t")
    bridge_config = make_config(test_pki, upstream, ca_bundle=str(tmp_path / "ca.pem"), mappings=[mapping])
    client_cert = types.SimpleNamespace(cert=tmp_path / "client.pem", key=tmp_path / "client.key")
    with running_bridge(bridge_config) as bridge:
        status, _, body = Client(bridge.address, test_pki.ca.cert_path, client_cert).rpc("tools/list")

    assert status == 200, body
    assert upstream.received[-1].headers["Authorization"] == "Bearer t"
