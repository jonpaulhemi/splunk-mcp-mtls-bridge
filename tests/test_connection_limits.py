"""Connections are capped before the TLS handshake, in total and per source address."""

import json
import socket

import pytest

from harness import client_of, make_config, running_bridge, wait_for


def _idle(bridge):
    """A TCP connection that never starts TLS, as a scanner's would."""
    return socket.create_connection(bridge.address, timeout=5)


def _closed_at_once(sock):
    """True if the bridge closed ``sock`` without waiting for a handshake."""
    try:
        return sock.recv(1) == b""
    except ConnectionResetError:
        return True
    except socket.timeout:
        return False


def _audit(tmp_path):
    return [json.loads(line) for line in (tmp_path / "audit.log").read_text().splitlines()]


@pytest.mark.parametrize(
    ("limits", "reason"),
    [
        ({"max_connections_per_ip": 2}, "too many connections from this address (limit 2)"),
        ({"max_connections": 2}, "too many connections to the bridge (limit 2)"),
    ],
)
def test_connections_beyond_a_limit_are_closed_before_the_handshake(test_pki, upstream, tmp_path, limits, reason):
    config = make_config(test_pki, upstream, audit_log=str(tmp_path / "audit.log"), handshake_timeout=5, **limits)
    with running_bridge(config) as bridge:
        held = [_idle(bridge), _idle(bridge)]
        try:
            refused = _idle(bridge)
            assert _closed_at_once(refused)
            refused.close()
        finally:
            for sock in held:
                sock.close()

    failure = next(e for e in _audit(tmp_path) if e["event"] == "handshake_failure")
    assert failure["reason"] == reason


def test_a_closed_connection_frees_its_slot(test_pki, upstream):
    config = make_config(test_pki, upstream, max_connections_per_ip=1, handshake_timeout=5)
    with running_bridge(config) as bridge:
        held = _idle(bridge)
        held.close()
        # The worker sees the peer go away during the handshake and releases the slot.
        wait_for(lambda: not bridge._listener._open)

        assert client_of(bridge, test_pki, test_pki.mapped).rpc("tools/list")[0] == 200


def test_connections_within_the_limits_are_served(test_pki, upstream):
    config = make_config(test_pki, upstream, max_connections_per_ip=2, handshake_timeout=5)
    with running_bridge(config) as bridge:
        held = _idle(bridge)
        try:
            assert client_of(bridge, test_pki, test_pki.mapped).rpc("tools/list")[0] == 200
        finally:
            held.close()
