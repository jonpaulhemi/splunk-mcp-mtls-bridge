"""Works out which role account a call from a client that proxies users runs as.

Such a client names the call's user in X-ProxiedEntitiesChain: one DN, bare or in angle brackets.
The user rule matching that DN names the role account whose token the call is forwarded with.
"""

import collections
import itertools

from . import identity

HEADER = "X-ProxiedEntitiesChain"
# User rule match types.
EXACT_DN = "dn"
ATTRIBUTES = "attributes"  # every attribute=value pair of the rule's value is in the user's DN
# Longer headers are refused, and audit events carry at most this much of what was received.
MAX_HEADER_CHARS = 4096

# Why a proxied call was refused: audit reasons, and what the client is told.
MISSING = "proxied_user_missing"
MALFORMED = "proxied_user_malformed"
NOT_ALLOWED = "proxied_user_not_allowed"
UNMATCHED = "user_unmatched"
AMBIGUOUS = "user_ambiguous"
_MESSAGES = {
    MISSING: f"this client proxies users; name the user in {HEADER}",
    MALFORMED: f"{HEADER} must hold one distinguished name, optionally in angle brackets",
    NOT_ALLOWED: f"this client is not allowed to name a user in {HEADER}",
    UNMATCHED: "no user rule matches the named user",
    AMBIGUOUS: "more than one user rule matches the named user",
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
    """The canonical form of what a user rule matches: the DN for an exact rule, or the sorted
    attribute=value pairs for an attribute rule. Raises ValueError if it can never match a user."""
    if match == EXACT_DN:
        return identity.dn_key(value, "user DN")
    if match == ATTRIBUTES:
        return tuple(sorted(_pairs(identity.dn_rdns(value, "attribute set"))))
    raise ValueError(f"unknown user rule match type {match!r}")


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
    rdns = _user_rdns(header_values)
    if rdns is None:
        raise UserRejection(MALFORMED, received)
    dn = identity.dn_key_of(rdns)
    held = collections.Counter(_pairs(rdns))
    accounts = {account.name: account for account in config.role_accounts}
    usable = [rule for rule in config.user_rules if rule.role_account in accounts]
    # An exact rule wins; otherwise exactly one attribute rule may match.
    exact = [rule for rule in usable if rule.match == EXACT_DN and rule.key == dn]
    matches = exact or [
        rule for rule in usable if rule.match == ATTRIBUTES and not collections.Counter(rule.key) - held
    ]
    if not matches:
        raise UserRejection(UNMATCHED, received)
    if len(matches) > 1:
        raise UserRejection(AMBIGUOUS, received)
    return ProxiedUser(dn, matches[0].name, accounts[matches[0].role_account])


def _pairs(rdns):
    """Every attribute=value pair of a DN, whichever RDN it's in."""
    return list(itertools.chain.from_iterable(rdns))


def _user_rdns(header_values):
    """The canonical RDNs of the DN the header names, or None if it doesn't name exactly one."""
    if len(header_values) != 1 or len(header_values[0]) > MAX_HEADER_CHARS:
        return None
    text = header_values[0].strip()
    if text.startswith("<") and text.endswith(">"):
        text = text[1:-1]
    # Any angle bracket left is a chain of several DNs, or an unbalanced one.
    if _has_unescaped(text, "<>"):
        return None
    try:
        return identity.dn_rdns(text, "user DN")
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
