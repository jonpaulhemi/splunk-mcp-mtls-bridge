"""Picks the one mapping a peer identity belongs to, or says why there isn't one."""

from . import certificate, identity


class Rejection(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def peer_of(der):
    """The identity of a verified peer cert, or Rejection if the bridge can't read it."""
    try:
        return identity.from_der(der)
    except (certificate.CertificateError, ValueError):
        raise Rejection("unreadable") from None


def resolve(mappings, peer):
    matches = [m for m in mappings if m.key in peer.keys]
    if not matches:
        raise Rejection("unmapped")
    if len(matches) > 1:
        raise Rejection("ambiguous")
    return matches[0]
