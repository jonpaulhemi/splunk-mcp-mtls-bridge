"""Modular input that runs the mTLS bridge under splunkd. See mtls_bridge.modinput."""

import sys

from mtls_bridge import modinput

if __name__ == "__main__":
    sys.exit(modinput.main(sys.argv[1:], sys.stdin))
