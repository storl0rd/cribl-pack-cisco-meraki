#!/usr/bin/env python3
"""Push the pack's Sources, Collectors (and, for group scope, breakers + vars) via the Cribl API.

Use when:
  * Stream < 4.14 (no Collectors inside Packs) -> --scope group
  * the pack import did not create the Sources/Collectors -> --scope pack

Dry run by default; add --apply to write. Commit & Deploy afterwards in the UI (or /version/commit).

  export CRIBL_URL=https://leader.example:9000      # or https://<org>.cribl.cloud
  export CRIBL_TOKEN=...                            # bearer token (Cribl.Cloud API credential or /auth/login)
  python3 tools/deploy_sources.py --group default --scope group --apply
"""
import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACK = os.path.join(ROOT, "pack", "cisco_meraki")


def load(*p):
    return yaml.safe_load(open(os.path.join(PACK, *p)))


def call(method, url, token, body=None, insecure=False):
    req = urllib.request.Request(url, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    ctx = ssl._create_unverified_context() if insecure else None
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def upsert(base, kind, obj_id, body, token, apply, insecure):
    url = "%s/%s" % (base, kind)
    if not apply:
        print("  would upsert %-10s %s" % (kind.split("/")[-1], obj_id))
        return True
    status, text = call("POST", url, token, dict(body, id=obj_id), insecure)
    if status in (200, 201):
        print("  created  %s" % obj_id)
        return True
    status, text = call("PATCH", "%s/%s" % (url, obj_id), token, dict(body, id=obj_id), insecure)
    if status in (200, 201):
        print("  updated  %s" % obj_id)
        return True
    print("  FAILED   %s  HTTP %s  %s" % (obj_id, status, text[:300]))
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--group", default="default", help="Worker Group (use 'default' on single-instance)")
    ap.add_argument("--scope", choices=["pack", "group"], default="pack")
    ap.add_argument("--only", choices=["inputs", "jobs", "all"], default="all")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (lab only)")
    a = ap.parse_args()

    url, token = os.environ.get("CRIBL_URL", "").rstrip("/"), os.environ.get("CRIBL_TOKEN", "")
    if a.apply and (not url or not token):
        sys.exit("CRIBL_URL and CRIBL_TOKEN must be set for --apply")
    base = "%s/api/v1/m/%s" % (url or "<CRIBL_URL>", a.group)
    if a.scope == "pack":
        base += "/p/cisco_meraki"

    ok = True
    if a.scope == "group":
        print("knowledge (group scope needs breakers + vars outside the pack):")
        for bid, b in load("default", "breakers.yml").items():
            ok &= upsert(base, "lib/breakers", bid, b, token, a.apply, a.insecure)
        for vid, v in load("default", "vars.yml").items():
            ok &= upsert(base, "lib/vars", vid, v, token, a.apply, a.insecure)
    if a.only in ("inputs", "all"):
        print("sources (created disabled):")
        for iid, i in load("default", "inputs.yml")["inputs"].items():
            ok &= upsert(base, "system/inputs", iid, i, token, a.apply, a.insecure)
    if a.only in ("jobs", "all"):
        print("collectors (schedules disabled):")
        for jid, j in load("default", "jobs.yml").items():
            ok &= upsert(base, "lib/jobs", jid, j, token, a.apply, a.insecure)
    if a.scope == "group":
        print("\nNOTE: group-scoped Sources send to global Routes. Add a Route with filter "
              "`__meraki_kind` or `sourcetype.startsWith('meraki:')` -> Pack cisco_meraki.")
    print("\nDone (%s). Commit & Deploy the Worker Group to activate." % ("applied" if a.apply else "dry run"))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
