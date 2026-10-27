"""Works out which role account a call from a client that proxies users runs as.

Such a client names the call's user in X-ProxiedEntitiesChain: one DN, bare or in angle brackets.
The user rule matching that DN names the role account whose token the call is forwarded with.
"""

import collections

from . import identity

HEADER = "X-ProxiedEntitiesChain"
# User rule match types.
EXACT_DN = "dn"
# Longer headers are refused, and audit events carry at most this much of what was received.
MAX_HEADER_CHARS = 4096

# Why a proxied call was refused: audit reasons, and what the client is told.
MISSING = "proxied_user_missing"
MALFORMED = "proxied_user_malformed"
NOT_ALLOWED = "proxied_user_not_allowed"
UNMATCHED = "user_unmatched"
_MESSAGES = {
    MISSING: f"this client proxies users; name the user in {HEADER}",
    MALFORMED: f"{HEADER} must hold one distinguished name, optionally in angle brackets",
    NOT_ALLOWED: f"this client is not allowed to name a user in {HEADER}",
    UNMATCHED: "no user rule matches the named user",
}

ProxiedUser = collections.namedtuple("ProxiedUser", "dn rule role_account")


class UserRejection(Exception):
    def __init__(self, reason, received=None):
        super().__init__(reason)
        self.reason = reason
        # The header as received, cut to MAX_HEADER_CHARS; None if there was none.
        self.received = received

    @property
    def message(self):
        return _MESSAGES[self.reason]


def rule_key(match, value):
    """The canonical form of what a user rule matches. Raises ValueError if it can never match a user."""
    if match != EXACT_DN:
        raise ValueError(f"unknown user rule match type {match!r}")
    return identity.dn_key(value, "user DN")


def resolve(mapping, header_values, config):
    """The ProxiedUser a call from ``mapping``'s client is for, or None if the client doesn't proxy users.

    ``header_values`` are the request's X-ProxiedEntitiesChain values, or None if it has none.
    Raises UserRejection if the call must be refused.
    """
    received = None if header_values is None else ", ".join(header_values)[:MAX_HEADER_CHARS]
    if not mapping.proxies_users:
        if header_values is not None:
            raise UserRejection(NOT_ALLOWED, received)
        return None
    if header_values is None:
        raise UserRejection(MISSING)
    dn = _user_dn(header_values)
    if dn is None:
        raise UserRejection(MALFORMED, received)
    accounts = {account.name: account for account in config.role_accounts}
    for rule in config.user_rules:
        if rule.key == dn and rule.role_account in accounts:
            return ProxiedUser(dn, rule.name, accounts[rule.role_account])
    raise UserRejection(UNMATCHED, received)


def _user_dn(header_values):
    """The canonical DN the header names, or None if it doesn't name exactly one."""
    if len(header_values) != 1 or len(header_values[0]) > MAX_HEADER_CHARS:
        return None
    text = header_values[0].strip()
    if text.startswith("<") and text.endswith(">"):
        text = text[1:-1]
    # Any angle bracket left is a chain of several DNs, or an unbalanced one.
    if _has_unescaped(text, "<>"):
        return None
    try:
        return identity.dn_key(text, "user DN")
    except ValueError:
        return None


def _has_unescaped(text, chars):
    i = 0
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] in chars:
            return True
        i += 1
    return False
