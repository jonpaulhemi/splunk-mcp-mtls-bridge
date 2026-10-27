"""Reads another configuration page's rows, for REST handlers that check one page against another."""

import json

import splunk
from splunk import rest

APP = "TA-mtls-bridge"
ROLE_ACCOUNTS = "ta_mtls_bridge_role_accounts"
USER_RULES = "ta_mtls_bridge_user_rules"


def rows(session_key, conf):
    """{name: content} of each row the page stores in ``conf``; empty if none was ever saved."""
    try:
        _, content = rest.simpleRequest(
            f"/servicesNS/nobody/{APP}/configs/conf-{conf}",
            sessionKey=session_key,
            getargs={"output_mode": "json", "count": "0"},
            raiseAllErrors=True,
        )
    except splunk.ResourceNotFound:
        return {}
    return {entry["name"]: entry["content"] for entry in json.loads(content)["entry"] if entry["name"] != "default"}
