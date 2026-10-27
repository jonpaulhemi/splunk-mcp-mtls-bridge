"""Picks the one mapping a peer identity belongs to, or says why there isn't one."""


class Rejection(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def resolve(mappings, peer):
    matches = [
        m
        for m in mappings
        if m.issuer.lower() == peer.issuer.lower() and (m.identity_type.upper(), m.identity_value) in peer.identities
    ]
    if not matches:
        raise Rejection("unmapped")
    if len(matches) > 1:
        raise Rejection("ambiguous")
    return matches[0]
