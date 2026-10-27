"""Fail the build if an AppInspect JSON report holds failures or errors; list everything else."""

import json
import sys

BLOCKING = {"failure", "error"}
SHOWN = BLOCKING | {"future_failure", "warning"}


def main(path):
    with open(path) as handle:
        report = json.load(handle)["reports"][0]
    blocking = 0
    for group in report["groups"]:
        for check in group["checks"]:
            if check["result"] not in SHOWN:
                continue
            if check["result"] in BLOCKING:
                blocking += 1
            print(f"{check['result'].upper()}: {check['name']}")
            for message in check.get("messages", [])[:5]:
                print(f"    {message.get('message', '')[:300]}")
    print(f"{blocking} blocking AppInspect result(s)")
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
