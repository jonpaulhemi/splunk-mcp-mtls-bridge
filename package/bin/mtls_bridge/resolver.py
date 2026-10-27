"""Picks the one mapping a peer identity belongs to, or says why there isn't one."""


class Rejection(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def resolve(mappings, peer):
    keys = peer.keys
    matches = [m for m in mappings if m.key in keys]
    if not matches:
        raise Rejection("unmapped")
    if len(matches) > 1:
        raise Rejection("ambiguous")
    return matches[0]
