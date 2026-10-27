"""Applying a new config to a running bridge: in-flight requests finish on the old one."""

import socket
import threading

import pytest

from mtls_bridge.config import Mapping
from mtls_bridge.server import ApplyError

import pki
from harness import Client, client_of, make_config, running_bridge, wait_for


def test_request_in_flight_finishes_on_the_config_it_started_with(test_pki, upstream):
    with running_bridge(make_config(test_pki, upstream)) as bridge:
        upstream.gate = threading.Event()
        results = []
        worker = threading.Thread(
            target=lambda: results.append(client_of(bridge, test_pki, test_pki.mapped).rpc("tools/list")[0])
        )
        worker.start()
        wait_for(lambda: upstream.received)

        bridge.apply(make_config(test_pki, upstream, mappings=[]))
        upstream.gate.set()
        worker.join(10)

        assert results == [200]
        assert upstream.received[0].headers["Authorization"] == "Bearer mapped-account-token"
        assert client_of(bridge, test_pki, test_pki.mapped).rpc("tools/list")[0] == 403


def test_new_token_is_used_by_the_next_request(test_pki, upstream):
    with running_bridge(make_config(test_pki, upstream)) as bridge:
        mapping = Mapping(test_pki.ca.issuer_dn, "URI", pki.MAPPED_URI, "svc_agent_a", token="rotated")
        bridge.apply(make_config(test_pki, upstream, mappings=[mapping]))

        assert client_of(bridge, test_pki, test_pki.mapped).rpc("tools/list")[0] == 200
        assert upstream.received[-1].headers["Authorization"] == "Bearer rotated"


def test_changed_port_moves_the_listener(test_pki, upstream, unused_port):
    with running_bridge(make_config(test_pki, upstream)) as bridge:
        old_address = bridge.address
        bridge.apply(make_config(test_pki, upstream, listen_port=unused_port))

        assert bridge.address == ("127.0.0.1", unused_port)
        assert Client(bridge.address, test_pki.ca.cert_path, test_pki.mapped).rpc("tools/list")[0] == 200
        try:
            Client(old_address, test_pki.ca.cert_path, test_pki.mapped).rpc("tools/list")
            raise AssertionError("old port still serving")
        except ConnectionRefusedError:
            pass


def test_mapping_deletion_applies_even_when_the_listener_cannot_move(test_pki, upstream):
    with running_bridge(make_config(test_pki, upstream)) as bridge, socket.socket() as squatter:
        squatter.bind(("127.0.0.1", 0))
        squatter.listen()
        taken_port = squatter.getsockname()[1]
        old_address = bridge.address

        with pytest.raises(ApplyError, match="cannot listen"):
            bridge.apply(make_config(test_pki, upstream, listen_port=taken_port, mappings=[]))

        assert bridge.address == old_address
        assert client_of(bridge, test_pki, test_pki.mapped).rpc("tools/list")[0] == 403


def test_host_change_on_the_same_port_rebinds(test_pki, upstream, unused_port):
    config = make_config(test_pki, upstream, listen_host="0.0.0.0", listen_port=unused_port)
    with running_bridge(config) as bridge:
        bridge.apply(make_config(test_pki, upstream, listen_host="127.0.0.1", listen_port=unused_port))

        assert bridge.address == ("127.0.0.1", unused_port)
        assert Client(bridge.address, test_pki.ca.cert_path, test_pki.mapped).rpc("tools/list")[0] == 200
