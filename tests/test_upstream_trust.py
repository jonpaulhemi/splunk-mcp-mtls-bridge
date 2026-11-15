"""A remote MCP Server needs trust no other Splunk install can satisfy, as the bridge sends it every token."""

import pytest

from mtls_bridge.server import ApplyError
from mtls_bridge.upstream import Upstream

import pki
from harness import make_config, running_bridge

REMOTE_URL = "https://mcp.example.com:8089/services/mcp"


@pytest.fixture
def splunk_default_ca(tmp_path):
    """A CA bundle shaped like Splunk's default cacert.pem: SplunkCommonCA, after another CA."""
    other = pki.make_ca(tmp_path, "Some Other CA")
    ca = pki.make_ca(tmp_path, "SplunkCommonCA", org="Splunk")
    bundle = tmp_path / "cacert.pem"
    bundle.write_bytes(other.cert_path.read_bytes() + ca.cert_path.read_bytes())
    return bundle


def test_remote_upstream_without_the_hostname_check_is_refused(test_pki, upstream):
    config = make_config(test_pki, upstream, upstream_url=REMOTE_URL, upstream_verify_hostname=False)

    with pytest.raises(ValueError, match="hostname check"):
        Upstream(config)


def test_remote_upstream_trusting_splunks_default_ca_is_refused(test_pki, upstream, splunk_default_ca):
    config = make_config(test_pki, upstream, upstream_url=REMOTE_URL, upstream_ca_bundle=str(splunk_default_ca))

    with pytest.raises(ValueError, match="SplunkCommonCA"):
        Upstream(config)


def test_remote_upstream_with_its_own_ca_and_the_hostname_check_is_accepted(test_pki, upstream):
    Upstream(make_config(test_pki, upstream, upstream_url=REMOTE_URL, upstream_verify_hostname=True))


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.2", "[::1]", "localhost"])
def test_loopback_upstream_keeps_the_defaults(test_pki, upstream, splunk_default_ca, host):
    config = make_config(
        test_pki,
        upstream,
        upstream_url=f"https://{host}:8089/services/mcp",
        upstream_ca_bundle=str(splunk_default_ca),
        upstream_verify_hostname=False,
    )

    Upstream(config)


def test_a_change_to_an_unsafe_remote_upstream_keeps_the_last_good_one(test_pki, upstream):
    config = make_config(test_pki, upstream)
    with running_bridge(config) as bridge:
        with pytest.raises(ApplyError, match="hostname check"):
            bridge.apply(make_config(test_pki, upstream, upstream_url=REMOTE_URL, upstream_verify_hostname=False))

        assert bridge.config.upstream_url == config.upstream_url
