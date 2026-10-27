"""The README's openssl example makes a CA and client cert that the bridge accepts, mapped as it says."""

import re
import subprocess

import pytest

from mtls_bridge.config import Mapping

from harness import MAPPED_TOKEN, ROOT, Client, make_config, running_bridge
from pki import Issued

EC_KEY = "-newkey ec -pkeyopt ec_paramgen_curve:P-256"
RSA_KEY = "-newkey rsa:2048"


def _example():
    """The README's pki.cnf, its openssl commands, and the issuer and identity it says to map."""
    readme = (ROOT / "README.md").read_text()
    section = readme.split("### Example: a test CA with openssl", 1)[1].split("\n## ", 1)[0]
    config, commands = re.findall(r"```(?:ini|sh)\n(.*?)```", section, re.S)
    issuer, identity = re.search(r"map issuer `([^`]+)`, identity type `URI` and identity `([^`]+)`", section).groups()
    return config, commands.replace("\\\n", " "), issuer, identity


@pytest.mark.parametrize("key", ["ec", "rsa"])
def test_readme_openssl_example_makes_certs_the_bridge_accepts(test_pki, upstream, tmp_path, key):
    config, commands, issuer, identity = _example()
    if key == "rsa":
        assert EC_KEY in commands
        commands = commands.replace(EC_KEY, RSA_KEY)
    (tmp_path / "pki.cnf").write_text(config)
    for command in filter(None, commands.splitlines()):
        subprocess.run(command, shell=True, cwd=str(tmp_path), check=True, capture_output=True)

    mapping = Mapping(issuer=issuer, identity_type="URI", identity_value=identity, account="svc", token=MAPPED_TOKEN)
    bridge_config = make_config(test_pki, upstream, ca_bundle=str(tmp_path / "ca.pem"), mappings=[mapping])
    client = Issued(cert=tmp_path / "client.pem", key=tmp_path / "client.key")
    with running_bridge(bridge_config) as bridge:
        status, _, body = Client(bridge.address, test_pki.ca.cert_path, client).rpc("tools/list")

    assert status == 200, body
