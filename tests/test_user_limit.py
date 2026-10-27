"""Each user behind a proxying client has their own cap on concurrent calls, on top of the client's."""

import threading
import time

from harness import JOHN, client_of, make_proxy_config, running_bridge, wait_for

HEADER = "X-ProxiedEntitiesChain"
JANE = "CN=Jane Doe,OU=Users,O=Org,C=US"


def _hold(client, user, results):
    """Start a call for ``user`` that the gated upstream holds open."""
    thread = threading.Thread(target=lambda: results.append(client.rpc("tools/list", headers={HEADER: user})[0]))
    thread.start()
    return thread


def _run(test_pki, upstream, held_users, then_user, **limits):
    """Hold a call for each of ``held_users``, then return the status and error message of one more
    for ``then_user``, and the statuses of the held calls once released."""
    upstream.gate = threading.Event()
    with running_bridge(make_proxy_config(test_pki, upstream, **limits)) as bridge:
        client = client_of(bridge, test_pki, test_pki.unmapped)
        results = []
        threads = [_hold(client, user, results) for user in held_users]
        wait_for(lambda: len(upstream.received) == len(held_users))
        # If the extra call gets through, release everything once it reaches the upstream.
        release = threading.Thread(target=_release_after, args=(upstream, len(held_users) + 1))
        release.start()
        status, _, body = client.rpc("tools/list", headers={HEADER: then_user})
        upstream.gate.set()
        for thread in threads:
            thread.join(10)
    message = body["error"]["message"] if status != 200 else None
    return status, message, results


def _release_after(upstream, count):
    deadline = time.monotonic() + 5
    while len(upstream.received) < count and not upstream.gate.is_set() and time.monotonic() < deadline:
        time.sleep(0.02)
    upstream.gate.set()


def test_a_users_third_concurrent_call_gets_429(test_pki, upstream):
    status, message, held = _run(test_pki, upstream, [JOHN, JOHN], JOHN)
    assert status == 429
    assert "user" in message
    assert held == [200, 200]


def test_a_busy_user_does_not_block_another(test_pki, upstream):
    upstream.gate = threading.Event()
    with running_bridge(make_proxy_config(test_pki, upstream)) as bridge:
        client = client_of(bridge, test_pki, test_pki.unmapped)
        results = []
        threads = [_hold(client, JOHN, results) for _ in range(2)]
        wait_for(lambda: len(upstream.received) == 2)
        upstream.gate.set()  # let Jane's call through as soon as it arrives
        assert client.rpc("tools/list", headers={HEADER: JANE})[0] == 200
        for thread in threads:
            thread.join(10)


def test_the_user_limit_is_keyed_by_canonical_dn(test_pki, upstream):
    status, message, _ = _run(test_pki, upstream, [JOHN, JOHN], f"<{JOHN.lower()}>")
    assert status == 429
    assert "user" in message


def test_the_client_limit_still_applies_to_proxied_calls(test_pki, upstream):
    status, message, held = _run(test_pki, upstream, [JOHN, JANE], JOHN, max_concurrent_per_identity=2)
    assert status == 429
    assert "client" in message
    assert held == [200, 200]


def test_the_user_limit_can_be_raised(test_pki, upstream):
    status, _, _ = _run(test_pki, upstream, [JOHN, JOHN], JOHN, max_concurrent_per_user=3)
    assert status == 200
