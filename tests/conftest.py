import socket
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS.parent / "package" / "bin"))
sys.path.insert(0, str(TESTS))

import pki  # noqa: E402
from fake_splunkd import FakeSplunkd  # noqa: E402
from fake_upstream import FakeUpstream  # noqa: E402
from harness import SESSION_KEY, Client, make_config, running_bridge  # noqa: E402


@pytest.fixture(scope="session")
def test_pki(tmp_path_factory):
    return pki.build(tmp_path_factory.mktemp("pki"))


@pytest.fixture
def upstream(test_pki):
    fake = FakeUpstream(test_pki.server).start()
    yield fake
    fake.stop()


@pytest.fixture
def bridge(test_pki, upstream):
    with running_bridge(make_config(test_pki, upstream)) as server:
        yield server


@pytest.fixture
def client_for(test_pki, bridge):
    def make(issued):
        return Client(bridge.address, test_pki.ca.cert_path, issued)

    return make


@pytest.fixture
def unused_port():
    """A port nothing is listening on (briefly bound, then released)."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def splunk_home(tmp_path):
    """An empty $SPLUNK_HOME with the directories the bridge reads and writes."""
    home = tmp_path / "splunk"
    (home / "etc" / "auth").mkdir(parents=True)
    (home / "var" / "log" / "splunk").mkdir(parents=True)
    return home


@pytest.fixture
def splunkd(test_pki):
    fake = FakeSplunkd(test_pki.server, SESSION_KEY, {"{PKI}": str(test_pki.ca.cert_path.parent)}).start()
    yield fake
    fake.stop()
