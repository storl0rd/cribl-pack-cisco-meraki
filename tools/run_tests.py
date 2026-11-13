#!/usr/bin/env python3
"""Offline tests: execute the pack's routes + pipelines (eval/code/unroll/lookup/drop)
against the bundled samples in Node, emulating Cribl function semantics.

What this proves: the JS logic, regexes, lookups, route filters and function wiring.
What it cannot prove: Cribl-side schema acceptance of inputs.yml/jobs.yml and live
API/collector behaviour -- verify those on a 4.14+ worker (see README).
"""
import csv
import json
import os
import subprocess
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACK = os.path.join(ROOT, "pack", "cisco_meraki")


def y(*p):
    return yaml.safe_load(open(os.path.join(PACK, *p)))


bundle = {
    "routes": y("default", "pipelines", "route.yml")["routes"],
    "pipelines": {n: y("default", "pipelines", n, "conf.yml")
                  for n in os.listdir(os.path.join(PACK, "default", "pipelines"))
                  if os.path.isdir(os.path.join(PACK, "default", "pipelines", n))},
    "vars": {k: v["value"] for k, v in y("default", "vars.yml").items()},
    "lookups": {f: list(csv.DictReader(open(os.path.join(PACK, "data", "lookups", f))))
                for f in os.listdir(os.path.join(PACK, "data", "lookups"))},
    "samples": {f[:-5]: json.load(open(os.path.join(PACK, "data", "samples", f)))
                for f in os.listdir(os.path.join(PACK, "data", "samples"))},
    "jobs": y("default", "jobs.yml"),
}
r = subprocess.run(["node", os.path.join(ROOT, "tools", "harness.mjs")], input=json.dumps(bundle),
                   text=True, capture_output=True)
sys.stdout.write(r.stdout)
sys.stderr.write(r.stderr)
sys.exit(r.returncode)
