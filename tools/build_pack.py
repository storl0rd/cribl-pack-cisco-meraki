#!/usr/bin/env python3
"""Generate the Cisco Meraki Cribl Pack from a single endpoint table.

The table below was reverse engineered from Splunk_TA_cisco_meraki 3.5.0:
  bin/cisco_meraki_connect.py      -> SDK method, query params, lookback limits
  bin/meraki_custom_endpoints.json -> REST path, pagination, perPage max
  default/inputs.conf              -> default polling interval
  default/props.conf               -> sourcetype + timestamp field
  default/tags.conf                -> CIM tags

Usage:  python3 tools/build_pack.py            (writes pack/cisco_meraki + dist/*.crbl)
"""
import csv
import io
import json
import os
import shutil
import tarfile
import time

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(ROOT, "tools")
PACK_ID = "cisco_meraki"
PACK_VERSION = "2.0.0"
PACK_DIR = os.path.join(ROOT, "pack", PACK_ID)
DIST = os.path.join(ROOT, "dist")

# --------------------------------------------------------------------------------------
# Schedules.  Event-log style endpoints poll a closed window that ends 5 minutes ago,
# because Meraki event logs land with a few minutes of latency (gap-free, no overlap).
# --------------------------------------------------------------------------------------
S5 = dict(cron="*/5 * * * *", earliest="-10m@m", latest="-5m@m")
S15 = dict(cron="*/15 * * * *", earliest="-20m@m", latest="-5m@m")
H1 = dict(cron="7 * * * *", earliest="-1h@h", latest="@h")
D1 = dict(cron="17 0 * * *", earliest="-1d@d", latest="@d")
SNAP_H = dict(cron="7 * * * *", earliest="-1h", latest="now")    # snapshot: window unused
SNAP_D = dict(cron="17 1 * * *", earliest="-1h", latest="now")

# time modes -> query params
#   t0t1   : t0/t1 ISO-8601 window
#   ts     : tsStart/tsEnd window (assurance alerts)
#   events : /networks/{id}/events cursor (startingAfter/endingBefore)
#   t0     : t0 only (air marshal)
#   None   : snapshot / inventory
E = []


def ep(st, path, ta_input, time_mode, sched, scope="org", product=None, per_page=None,
       params=None, time_field=None, tags=None, desc=""):
    E.append(dict(st=st, path=path, ta_input=ta_input, time_mode=time_mode, sched=sched,
                  scope=scope, product=product, per_page=per_page, params=params or {},
                  time_field=time_field, tags=tags or [], desc=desc))


# ---- network event logs (per network, filtered by productType) ------------------------
ep("meraki:securityappliances", "/networks/{networkId}/events", "cisco_meraki_securityappliances", "events", S5,
   scope="network", product="appliance", per_page=1000, time_field="occurredAt",
   desc="MX/Z event log (DHCP, IDS, VPN, content filtering)")
ep("meraki:accesspoints", "/networks/{networkId}/events", "cisco_meraki_accesspoints", "events", S15,
   scope="network", product="wireless", per_page=1000, time_field="occurredAt",
   desc="MR event log (802.1X/WPA/splash auth, RF changes, wireless attacks)")
ep("meraki:switches", "/networks/{networkId}/events", "cisco_meraki_switches", "events", S15,
   scope="network", product="switch", per_page=1000, time_field="occurredAt",
   desc="MS event log (port status, STP, PoE, PSU)")
ep("meraki:cameras", "/networks/{networkId}/events", "cisco_meraki_cameras", "events", H1,
   scope="network", product="camera", per_page=1000, time_field="occurredAt",
   desc="MV event log (schedules, night mode, exports)")
ep("meraki:airmarshal", "/networks/{networkId}/wireless/airMarshal", "cisco_meraki_airmarshal", "t0", H1,
   scope="network", product="wireless", time_field="lastSeen", tags=[],
   desc="Rogue / neighbouring SSIDs seen by MR radios")

# ---- organisation security / audit -----------------------------------------------------
ep("meraki:organizationsecurity", "/organizations/{organizationId}/appliance/security/events",
   "cisco_meraki_organizationsecurity", "t0t1", S5, per_page=1000, params={"sortOrder": "ascending"},
   time_field="ts", desc="MX IDS/IPS alerts and AMP file scans")
ep("meraki:audit", "/organizations/{organizationId}/configurationChanges", "cisco_meraki_audit", "t0t1", S15,
   per_page=5000, time_field="ts", tags=["change"], desc="Dashboard configuration change log")
ep("meraki:apirequestshistory", "/organizations/{organizationId}/apiRequests", "cisco_meraki_api_request_history",
   "t0t1", H1, per_page=1000, time_field="ts", tags=["web"], desc="Dashboard API request audit log")
ep("meraki:webhooklogs:api", "/organizations/{organizationId}/webhooks/logs", "cisco_meraki_webhook_logs",
   "t0t1", H1, per_page=1000, time_field="loggedAt", desc="Webhook delivery log")
ep("meraki:assurancealerts", "/organizations/{organizationId}/assurance/alerts", "cisco_meraki_assurance_alerts",
   "ts", H1, per_page=300, time_field="startedAt", tags=["alert"], desc="Assurance (health) alerts")

# ---- device state / availability -------------------------------------------------------
ep("meraki:devices", "/organizations/{organizationId}/devices", "cisco_meraki_devices", None, SNAP_D,
   per_page=1000, tags=["inventory"], desc="Device inventory")
ep("meraki:devicesavailabilities", "/organizations/{organizationId}/devices/availabilities",
   "cisco_meraki_devices_availabilities", None, SNAP_H, per_page=1000, tags=["inventory"],
   desc="Current online/offline/alerting state per device")
ep("meraki:devicesavailabilitieschangehistory", "/organizations/{organizationId}/devices/availabilities/changeHistory",
   "cisco_meraki_device_availabilities_change_history", "t0t1", S15, per_page=1000, time_field="ts",
   tags=["change"], desc="Device availability transitions")
ep("meraki:devicesuplinksaddressesbydevice", "/organizations/{organizationId}/devices/uplinks/addresses/byDevice",
   "cisco_meraki_device_uplink_addresses_by_device", None, SNAP_D, per_page=1000, tags=["inventory"],
   desc="Uplink IP addressing per device")
ep("meraki:devicesuplinkslossandlatency", "/organizations/{organizationId}/devices/uplinksLossAndLatency",
   "cisco_meraki_devices_uplinks_loss_and_latency", "t0t1", S5,
   desc="MX/MG uplink loss + latency (API caps t1-t0 at 5 minutes)")
ep("meraki:powermodulesstatusesbydevice", "/organizations/{organizationId}/devices/powerModules/statuses/byDevice",
   "cisco_meraki_power_modules_statuses_by_device", None, SNAP_H, per_page=1000, tags=["inventory"],
   desc="PSU status for MS/MX with modular power")
ep("meraki:firmwareupgrades", "/organizations/{organizationId}/firmware/upgrades", "cisco_meraki_firmware_upgrades",
   None, SNAP_D, per_page=1000, time_field="time", tags=["change"], desc="Firmware upgrade history")
ep("meraki:organizationsnetworks", "/organizations/{organizationId}/networks", "cisco_meraki_organization_networks",
   None, SNAP_D, per_page=100000, desc="Network inventory")
ep("meraki:organizations", "/organizations", "cisco_meraki_organizations", None, SNAP_D, scope="global",
   per_page=9000, desc="Organisations visible to the API key")

# ---- wireless ---------------------------------------------------------------------------
ep("meraki:wirelessdevicesethernetstatuses", "/organizations/{organizationId}/wireless/devices/ethernet/statuses",
   "cisco_meraki_wireless_devices_ethernet_statuses", None, SNAP_D, per_page=1000,
   desc="MR ethernet / power status")
ep("meraki:wirelessdevicespacketlossbydevice", "/organizations/{organizationId}/wireless/devices/packetLoss/byDevice",
   "cisco_meraki_wireless_packet_loss_by_device", "t0t1", H1, per_page=1000, tags=["performance"],
   desc="MR packet loss")
ep("meraki:wirelessdeviceswirelesscontrollersbydevice",
   "/organizations/{organizationId}/wireless/devices/wirelessControllers/byDevice",
   "cisco_meraki_wireless_devices_by_wlc", None, SNAP_D, per_page=1000, desc="APs managed by Catalyst WLCs")
ep("meraki:wirelesscontrolleravailabilitieschangehistory",
   "/organizations/{organizationId}/wirelessController/availabilities/changeHistory",
   "cisco_meraki_wlc_avail_change_history", "t0t1", H1, per_page=1000, time_field="ts", tags=["inventory"],
   desc="Catalyst WLC availability changes")
ep("meraki:wirelesscontrollerdevicesinterfacesusagehistorybyinterval",
   "/organizations/{organizationId}/wirelessController/devices/interfaces/usage/history/byInterval",
   "cisco_meraki_wlc_iface_usage_history", "t0t1", D1, per_page=1000, tags=["network"],
   desc="Catalyst WLC interface usage")
ep("meraki:wirelesscontrollerdevicesinterfacespacketsoverviewbydevice",
   "/organizations/{organizationId}/wirelessController/devices/interfaces/packets/overview/byDevice",
   "cisco_meraki_wlc_iface_pkts_overview", "t0t1", D1, per_page=1000, tags=["network"],
   desc="Catalyst WLC interface packet counters")

# ---- switching --------------------------------------------------------------------------
ep("meraki:switchportsbyswitch", "/organizations/{organizationId}/switch/ports/bySwitch",
   "cisco_meraki_switch_ports_by_switch", None, SNAP_D, per_page=50, tags=["inventory"],
   desc="Switch port configuration")
ep("meraki:switchportsoverview", "/organizations/{organizationId}/switch/ports/overview",
   "cisco_meraki_switch_port_overview", "t0t1", D1, desc="Switch port counts by status/speed")
ep("meraki:portstransceiversreadingshistorybyswitch",
   "/organizations/{organizationId}/switch/ports/transceivers/readings/history/bySwitch",
   "cisco_meraki_switch_xcvr_readings_history", None, SNAP_D, per_page=100,
   desc="SFP DOM readings")
ep("meraki:summaryswitchpowerhistory", "/organizations/{organizationId}/summary/switch/power/history",
   "cisco_meraki_summary_switch_power_history", "t0t1", D1, desc="Switch power draw history")

# ---- summaries ------------------------------------------------------------------------------
for st, path, ta in [
    ("meraki:summarytopappliancesbyutilization", "/summary/top/appliances/byUtilization",
     "cisco_meraki_summary_appliances_top_by_utilization"),
    ("meraki:summarytopclientsbyusage", "/summary/top/clients/byUsage", "cisco_meraki_summary_top_clients_by_usage"),
    ("meraki:summarytopdevicesbyusage", "/summary/top/devices/byUsage", "cisco_meraki_summary_top_devices_by_usage"),
    ("meraki:summarytopswitchesbyenergyusage", "/summary/top/switches/byEnergyUsage",
     "cisco_meraki_summary_top_switches_by_energy_usage"),
]:
    ep(st, "/organizations/{organizationId}" + path, ta, "t0t1", D1, params={"quantity": "10"},
       desc="Daily top-10 summary")

# ---- API usage ----------------------------------------------------------------------------------
ep("meraki:apirequestsoverview", "/organizations/{organizationId}/apiRequests/overview",
   "cisco_meraki_api_request_overview", "t0t1", D1, desc="API response code totals")
ep("meraki:apirequestsresponsecodes", "/organizations/{organizationId}/apiRequests/overview/responseCodes/byInterval",
   "cisco_meraki_api_request_response_code", "t0t1", D1, params={"interval": "3600"},
   desc="API response codes per hour")

# ---- SD-WAN -------------------------------------------------------------------------------------
ep("meraki:appliancesdwanstatistics", "/organizations/{organizationId}/appliance/vpn/stats",
   "cisco_meraki_appliance_vpn_stats", "t0t1", D1, per_page=300, desc="AutoVPN peer statistics")
ep("meraki:appliancesdwanstatuses", "/organizations/{organizationId}/appliance/vpn/statuses",
   "cisco_meraki_appliance_vpn_statuses", None, SNAP_H, per_page=300, desc="AutoVPN peer status")

# ---- licensing ----------------------------------------------------------------------------------
ep("meraki:licensesoverview", "/organizations/{organizationId}/licenses/overview", "cisco_meraki_licenses_overview",
   None, SNAP_D, desc="Co-term / per-device licence overview")
ep("meraki:licensescotermlicenses", "/organizations/{organizationId}/licensing/coterm/licenses",
   "cisco_meraki_licenses_coterm_licenses", None, SNAP_D, per_page=1000, desc="Co-term licences")
ep("meraki:licensessubscriptions", "/administered/licensing/subscription/subscriptions",
   "cisco_meraki_licenses_subscriptions", None, SNAP_D, scope="administered", per_page=1000,
   desc="Subscription licences")
ep("meraki:licensessubscriptionentitlements", "/administered/licensing/subscription/entitlements",
   "cisco_meraki_licenses_subscription_entitlements", None, SNAP_D, scope="global",
   desc="Subscription entitlements (SKU catalogue)")

# ---- sensors ------------------------------------------------------------------------------------
ep("meraki:sensorreadingshistory", "/organizations/{organizationId}/sensor/readings/history",
   "cisco_meraki_sensor_readings_history", "t0t1", S15, per_page=1000, time_field="ts",
   desc="MT sensor readings")

assert len({e["st"] for e in E}) == len(E), "duplicate sourcetype"

# Value tier per sourcetype -> drives which destination profiles receive it.
#   security    : detections / investigations (SIEM, SecOps)
#   operational : health + telemetry (observability tools, metrics)
#   inventory   : slowly-changing asset context
SECURITY = {"meraki:securityappliances", "meraki:accesspoints", "meraki:switches", "meraki:cameras",
            "meraki:airmarshal", "meraki:organizationsecurity", "meraki:audit", "meraki:apirequestshistory"}
INVENTORY = {"meraki:devices", "meraki:devicesavailabilities", "meraki:devicesuplinksaddressesbydevice",
             "meraki:powermodulesstatusesbydevice", "meraki:organizationsnetworks", "meraki:organizations",
             "meraki:switchportsbyswitch", "meraki:wirelessdeviceswirelesscontrollersbydevice",
             "meraki:licensesoverview", "meraki:licensescotermlicenses", "meraki:licensessubscriptions",
             "meraki:licensessubscriptionentitlements"}
for _e in E:
    _e["tier"] = "security" if _e["st"] in SECURITY else ("inventory" if _e["st"] in INVENTORY else "operational")
assert SECURITY | INVENTORY <= {e["st"] for e in E}, "tier set names unknown sourcetype"

DESTS = ["splunk", "secops", "archive", "structured"]
REDUCTIONS = ["strip_nulls", "inventory_changes_only", "dedupe_airmarshal", "dedupe_urls",
              "drop_ip_flow_start", "drop_wireless_assoc", "drop_known_good_flows", "flow_summary"]

# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------
API_HOST = "${C.vars.meraki_api_host}"
ORG = "${C.vars.meraki_org_id}"
ISO_E = "new Date((earliest ? earliest : Date.now() / 1000 - 3600) * 1000).toISOString()"
ISO_L = "new Date((latest ? latest : Date.now() / 1000) * 1000).toISOString()"


def q(s):
    """JS string literal expression."""
    return "'" + str(s).replace("\\", "\\\\").replace("'", "\\'") + "'"


def collector_id(e):
    return "meraki_" + e["st"].split(":", 1)[1].replace(":", "_")


def url_for(e):
    path = e["path"].replace("{organizationId}", ORG).replace("{networkId}", "${id}")
    return "`https://" + API_HOST + "/api/v1" + path + "`"


def collect_params(e):
    p = []
    if e["per_page"]:
        p.append({"name": "perPage", "value": q(e["per_page"])})
    tm = e["time_mode"]
    if tm == "t0t1":
        p += [{"name": "t0", "value": ISO_E}, {"name": "t1", "value": ISO_L}]
    elif tm == "ts":
        p += [{"name": "tsStart", "value": ISO_E}, {"name": "tsEnd", "value": ISO_L}]
    elif tm == "events":
        p += [{"name": "productType", "value": q(e["product"])},
              {"name": "startingAfter", "value": ISO_E},
              {"name": "endingBefore", "value": ISO_L}]
    elif tm == "t0":
        p += [{"name": "t0", "value": ISO_E}]
    if e["scope"] == "administered":
        p.append({"name": "organizationIds[]", "value": "C.vars.meraki_org_id"})
    for k, v in e["params"].items():
        p.append({"name": k, "value": q(v)})
    return p


def collector(e):
    sched = e["sched"]
    conf = {
        "discovery": {"discoverType": "none"},
        "collectMethod": "get",
        "collectUrl": url_for(e),
        "collectRequestParams": collect_params(e),
        "collectRequestHeaders": [{"name": "Accept", "value": "'application/json'"}],
        "authentication": "tokenSecret",
        "tokenSecret": "meraki_api_key",
        "pagination": {"type": "response_header_link", "nextRelationAttribute": "next", "maxPages": 0},
        "timeout": 120,
        "useRoundRobinDns": False,
        "disableTimeFilter": True,
        "decodeUrl": True,
        "rejectUnauthorized": True,
        "captureHeaders": False,
        "stopOnEmptyResults": True,
        "safeHeaders": [],
        "retryRules": {
            "type": "backoff", "interval": 1000, "limit": 6, "multiplier": 2,
            "codes": [429, 502, 503, 504], "enableHeader": True,
            "retryConnectTimeout": True, "retryConnectReset": True,
        },
    }
    if e["scope"] == "network":
        conf["discovery"] = {
            "discoverType": "http",
            "discoverMethod": "get",
            "discoverUrl": "`https://" + API_HOST + "/api/v1/organizations/" + ORG + "/networks`",
            "discoverRequestParams": [
                {"name": "perPage", "value": "'100000'"},
                {"name": "productTypes[]", "value": q(e["product"])},
            ],
            "discoverRequestHeaders": [{"name": "Accept", "value": "'application/json'"}],
            "discoverDataField": "",
        }
    return {
        "type": "collection",
        "ttl": "4h",
        "ignoreGroupJobsLimit": False,
        "removeFields": [],
        "resumeOnBoot": False,
        "description": "%s - %s (TA input: %s)" % (e["st"], e["desc"], e["ta_input"]),
        "schedule": {
            "enabled": False,
            "cronSchedule": sched["cron"],
            "maxConcurrentRuns": 1,
            "skippable": True,
            "resumeMissed": False,
            "run": {
                "rescheduleDroppedTasks": True,
                "maxTaskReschedule": 1,
                "logLevel": "info",
                "jobTimeout": "0",
                "mode": "run",
                "timeRangeType": "relative",
                "earliest": sched["earliest"],
                "latest": sched["latest"],
                "timestampTimezone": "UTC",
                "timeWarning": {},
                "expression": "true",
                "minTaskSize": "1MB",
                "maxTaskSize": "10MB",
            },
        },
        "streamtags": ["meraki"],
        "workerAffinity": False,
        "collector": {"type": "rest", "conf": conf, "destructive": False},
        "input": {
            "type": "collection",
            "staleChannelFlushMs": 10000,
            "sendToRoutes": True,
            "preprocess": {"disabled": True},
            "throttleRatePerSec": "0",
            "breakerRulesets": ["meraki_json_document"],
            "metadata": [
                {"name": "sourcetype", "value": q(e["st"])},
                {"name": "__meraki_kind", "value": "'api'"},
            ],
        },
    }


def fn_eval_cfg(extra=()):
    fields = [
        ("__cfg_index", "C.vars.meraki_index || ''"),
        ("__cfg_org_id", "C.vars.meraki_org_id || ''"),
        ("__cfg_api_host", "C.vars.meraki_api_host || 'api.meraki.com'"),
    ] + list(extra)
    return {
        "id": "eval", "filter": "true", "disabled": False,
        "description": "Load pack variables into internal fields (Code functions read __cfg_*).",
        "conf": {"add": [{"name": n, "value": v} for n, v in fields]},
    }


def fn_code(path, desc, replacements=None, iterations=20000):
    src = open(os.path.join(TOOLS, "js", path)).read()
    for k, v in (replacements or {}).items():
        src = src.replace(k, v)
    return {"id": "code", "filter": "true", "disabled": False, "description": desc,
            "conf": {"code": src, "maxNumOfIterations": iterations, "activityLogSampleRate": 1}}


def fn_drop(flt, desc):
    return {"id": "drop", "filter": flt, "disabled": False, "description": desc, "conf": {}}


def tail_functions():
    """Shared fan-out -> reduce -> shape stages appended to every source pipeline."""
    dest_cfg = "({" + ", ".join(
        "%s: {enabled: C.vars.meraki_dest_%s_enabled, tiers: C.vars.meraki_dest_%s_tiers, reduce: %s}" % (
            d, d, d, "''" if d == "archive" else "C.vars.meraki_reduce_%s" % d) for d in DESTS) + "})"
    cfg = [
        ("__cfg_dest", dest_cfg),
        ("__cfg_index", "C.vars.meraki_index || ''"),
        ("__cfg_known_good", "C.vars.meraki_known_good_destinations || ''"),
        ("__cfg_secops_log_type", "C.vars.meraki_secops_log_type || 'CISCO_MERAKI'"),
        ("__cfg_secops_namespace", "C.vars.meraki_secops_namespace || ''"),
    ]
    ev = lambda flt, desc: {"id": "eval", "filter": flt, "disabled": False, "description": desc,
                            "conf": {"add": [{"name": n, "value": v} for n, v in cfg]}}
    sup = lambda kind, period, desc: {
        "id": "suppress", "filter": "__meraki_suppress === '%s'" % kind, "disabled": False, "description": desc,
        "conf": {"keyExpr": "C.Mask.md5(__meraki_suppress_key)", "allow": 1, "suppressPeriodSec": period,
                 "dropEventsMode": True, "maxCacheSize": 50000, "cacheIdleTimeoutPeriods": 2,
                 "numEventsIdleTimeoutTrigger": 10000}}
    return [
        ev("true", "Destination profiles, reduction toggles and SecOps settings."),
        fn_code("dest_select.js", "Pick destination profiles by enablement + tier."),
        {"id": "unroll", "filter": "Array.isArray(__meraki_dests)", "disabled": False,
         "description": "One copy per destination profile (none wanted = dropped).",
         "conf": {"srcExpr": "__meraki_dests", "dstField": "__meraki_dest"}},
        fn_code("reduce.js", "Per-destination opt-in reduction (archive is never reduced)."),
        fn_drop("__meraki_reduce_drop !== undefined", "Apply drop_* reductions."),
        sup("url", 60, "dedupe_urls: one urls event per client+domain per 60s."),
        sup("airmarshal", 3600, "dedupe_airmarshal: one event per rogue BSSID/SSID per hour."),
        sup("inventory", 86400, "inventory_changes_only: identical inventory record at most once per 24h."),
        {"id": "aggregation", "filter": "meraki_agg_dest !== undefined", "disabled": False,
         "description": "flow_summary: allowed flows -> 5-minute summaries per device/src/dst/port/proto.",
         "conf": {"passthrough": False, "preserveGroupBys": True, "sufficientStatsOnly": False, "metricsMode": False,
                  "timeWindow": "300s", "cumulative": False, "flushOnInputClose": True,
                  "lagTolerance": "30s", "idleTimeLimit": "60s",
                  "aggregations": ["count().as(flow_count)", "min(_time).as(first_seen)", "max(_time).as(last_seen)"],
                  "groupbys": ["meraki_agg_dest", "meraki_agg_device", "meraki_agg_category", "meraki_agg_src_ip",
                               "meraki_agg_dest_ip", "meraki_agg_dest_port", "meraki_agg_transport", "meraki_agg_action"]}},
        ev("__cfg_dest === undefined", "Re-load settings on aggregation output (aggregates carry no internal fields)."),
        fn_code("shape.js", "Shape each copy for its destination profile."),
    ]


def pipeline(functions, desc):
    return {"output": "default", "streamtags": ["meraki"], "groups": {}, "asyncFuncTimeout": 1000,
            "description": desc, "functions": functions}


# --------------------------------------------------------------------------------------
# write pack
# --------------------------------------------------------------------------------------
def dump(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        yaml.safe_dump(obj, f, sort_keys=False, width=1000, allow_unicode=True)


def write_text(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def build():
    if os.path.isdir(PACK_DIR):
        shutil.rmtree(PACK_DIR)
    d = lambda *p: os.path.join(PACK_DIR, *p)

    # package.json ------------------------------------------------------------------
    write_text(d("package.json"), json.dumps({
        "name": PACK_ID,
        "version": PACK_VERSION,
        "author": "Aether8 AI Consulting Inc.",
        "description": "Cisco Meraki ingestion: Dashboard API REST collectors (parity with Splunk TA 3.5.0), "
                       "alert webhooks and MX/MS/MR syslog, with Splunk-TA-compatible sourcetypes and optional CIM enrichment.",
        "displayName": "Cisco Meraki",
        "exports": [],
        "minLogStreamVersion": "4.14.0",
        "tags": {
            "dataType": ["logs", "metrics"],
            "domain": ["security", "observability", "network"],
            "technology": ["cisco", "meraki"],
            "streamtags": ["meraki"],
        },
    }, indent=2) + "\n")

    # vars --------------------------------------------------------------------------
    var = lambda v, desc: {"type": "string", "lib": "custom", "value": v, "description": desc, "tags": "meraki"}
    vars_ = {
        "meraki_api_host": var("api.meraki.com", "Dashboard API host. Canada: api.meraki.ca, China: api.meraki.cn, India: api.meraki.in, US FedRAMP: api.gov-meraki.com"),
        "meraki_org_id": var("", "Meraki organization ID collected by the REST collectors (GET /api/v1/organizations)."),
        "meraki_index": var("", "splunk profile only: value written to `index`. Empty = leave to the Destination."),
        "meraki_webhook_shared_secret": var("", "Webhook shared secret configured on the Meraki HTTP server. When set, webhooks without a matching sharedSecret are dropped."),
        "meraki_syslog_drop_categories": var("", "Comma-separated Meraki syslog roles dropped for ALL destinations (incl. archive), e.g. flows,urls."),
        "meraki_known_good_destinations": var("", "drop_known_good_flows: comma list of IPv4[/cidr][:port], e.g. 10.0.0.53:53,10.0.0.0/8:123"),
        "meraki_secops_log_type": var("CISCO_MERAKI", "secops profile: Google SecOps ingestion label (__logType)."),
        "meraki_secops_namespace": var("", "secops profile: optional Google SecOps namespace (__namespace)."),
    }
    defaults = {
        "splunk": ("true", "security,operational,inventory", ""),
        "secops": ("false", "security", ""),
        "archive": ("false", "*", None),
        "structured": ("false", "security,operational,inventory", ""),
    }
    for dname in DESTS:
        en, tiers, red = defaults[dname]
        vars_["meraki_dest_%s_enabled" % dname] = var(en, "%s profile on/off (true|false)." % dname)
        vars_["meraki_dest_%s_tiers" % dname] = var(tiers, "%s profile: tiers to receive (security,operational,inventory or *)." % dname)
        if red is not None:
            vars_["meraki_reduce_%s" % dname] = var(red, "%s profile: comma list of reductions: %s" % (dname, ", ".join(REDUCTIONS)))
    dump(d("default", "vars.yml"), vars_)

    # breakers ------------------------------------------------------------------------
    dump(d("default", "breakers.yml"), {
        "meraki_json_document": {
            "lib": "custom",
            "description": "One event per Meraki JSON document (an API response page or a webhook body). "
                           "Breaks only before a top-level { or [ at the start of a line, so pretty-printed bodies stay whole.",
            "tags": "meraki",
            "minRawLength": 256,
            "rules": [{
                "name": "Meraki JSON document",
                "condition": "true",
                "type": "regex",
                "timestampAnchorRegex": "/^/",
                "timestamp": {"type": "current", "length": 150},
                "timestampTimezone": "utc",
                "timestampEarliest": "-420weeks",
                "timestampLatest": "+1week",
                "maxEventBytes": 33554432,
                "disabled": False,
                "parserEnabled": False,
                "shouldUseDataRaw": False,
                "eventBreakerRegex": "/[\\r\\n]+(?=[\\[{])/",
            }],
        }
    })

    # lookups -------------------------------------------------------------------------
    os.makedirs(d("data", "lookups"), exist_ok=True)
    shutil.copy(os.path.join(TOOLS, "meraki_event_cim.csv"), d("data", "lookups", "meraki_event_cim.csv"))
    write_text(d("data", "lookups", "meraki_ids_priority.csv"),
               "priority,severity\n1,high\n2,medium\n3,low\n4,informational\n")

    # pipelines -------------------------------------------------------------------------
    time_fields = {e["st"]: e["time_field"] for e in E if e["time_field"]}
    static_tags = {e["st"]: e["tags"] for e in E if e["tags"]}
    lookup_filter = "__meraki_event_type !== undefined"
    api_fns = [
        fn_eval_cfg(),
        fn_code("api_unwrap.js", "Normalise the page shape ([...], {items}, {events}, {...}) to an array in _raw."),
        {"id": "unroll", "filter": "Array.isArray(_raw)", "disabled": False,
         "description": "One event per Meraki record.", "conf": {"srcExpr": "_raw", "dstField": "_raw"}},
        fn_code("api_prep.js", "Parse the record and expose lookup keys."),
        {"id": "lookup", "filter": lookup_filter, "disabled": False,
         "description": "TA LOOKUP-* (accesspoints/securityappliances/switches/cameras), OUTPUTNEW semantics.",
         "conf": {"file": "meraki_event_cim.csv", "matchMode": "exact", "reloadPeriodSec": -1, "addToEvent": False,
                  "ignoreCase": False,
                  "inFields": [{"eventField": "__meraki_product", "lookupField": "product"},
                               {"eventField": "__meraki_event_type", "lookupField": "meraki_event_type"}],
                  "outFields": [{"lookupField": k, "eventField": "__lk_" + k} for k in
                                ["action", "change_type", "object", "object_category", "result", "object_attrs"]]}},
        {"id": "lookup", "filter": "sourcetype === 'meraki:organizationsecurity' && __meraki_priority !== undefined",
         "disabled": False, "description": "IDS priority -> severity (TA cisco_meraki_organizationsecurity_lookup).",
         "conf": {"file": "meraki_ids_priority.csv", "matchMode": "exact", "reloadPeriodSec": -1, "addToEvent": False,
                  "ignoreCase": False,
                  "inFields": [{"eventField": "__meraki_priority", "lookupField": "priority"}],
                  "outFields": [{"lookupField": "severity", "eventField": "__lk_severity"}]}},
        fn_code("api_normalize.js", "_time, host, organizationId, source/index and CIM (props.conf port).",
                {"/*TIME_FIELDS*/{}": json.dumps(time_fields, sort_keys=True),
                 "/*TAGS*/{}": json.dumps(static_tags, sort_keys=True),
                 "/*TIERS*/{}": json.dumps({e["st"]: e["tier"] for e in E}, sort_keys=True)}, iterations=100000),
    ] + tail_functions()
    dump(d("default", "pipelines", "meraki_api", "conf.yml"),
         pipeline(api_fns, "Meraki Dashboard API records from the pack REST collectors (all meraki:* API sourcetypes)."))

    dump(d("default", "pipelines", "meraki_webhook", "conf.yml"), pipeline([
        fn_eval_cfg([("__cfg_webhook_secret", "C.vars.meraki_webhook_shared_secret || ''")]),
        fn_code("webhook.js", "Unwrap, authenticate, strip secret, timestamp, CIM."),
        fn_drop("__meraki_drop !== undefined", "Drop webhooks that failed shared-secret validation."),
    ] + tail_functions(), "Meraki Dashboard alert webhooks (default Meraki template or Splunk TA HEC template)."))

    dump(d("default", "pipelines", "meraki_syslog", "conf.yml"), pipeline([
        fn_eval_cfg([("__cfg_syslog_drop", "C.vars.meraki_syslog_drop_categories || ''")]),
        fn_code("syslog.js", "Parse Meraki syslog header, role, key=value body and tails; CIM normalise."),
        fn_drop("__meraki_drop !== undefined", "Drop roles listed in meraki_syslog_drop_categories."),
    ] + tail_functions(), "Meraki syslog: flows, firewall, vpn_firewall, cellular_firewall, urls, ids-alerts, security_event, events, airmarshal_events, ip_flow_*."))

    # routes -------------------------------------------------------------------------------
    syslog_re = ("/^(?:<\\d{1,3}>)?[\\s\\S]{0,80}?\\b\\d{10}\\.\\d+\\s+\\S+\\s+(?:flows|urls|firewall|vpn_firewall|"
                 "cellular_firewall|bridge_anyconnect_client_vpn_firewall|l7_firewall|ids-alerts|security_event|events|"
                 "airmarshal_events|ip_flow_start|ip_flow_end|anyconnect_vpn_\\w+)\\b/")
    api_sts = sorted(e["st"] for e in E)
    dump(d("default", "pipelines", "route.yml"), {
        "id": "default",
        "groups": {},
        "comments": [],
        "routes": [
            {"id": "meraki_webhook", "name": "Meraki webhook", "final": True, "disabled": False,
             "pipeline": "meraki_webhook", "output": "default", "enableOutputExpression": False, "clones": [],
             "description": "Pack webhook Source, or any HTTP/HEC Source carrying Meraki alert JSON.",
             "filter": "__meraki_kind === 'webhook' || sourcetype === 'meraki:webhook' || "
                       "(!__meraki_kind && typeof _raw === 'string' && _raw.indexOf('\"alertType\"') !== -1 && _raw.indexOf('\"occurredAt\"') !== -1)"},
            {"id": "meraki_api", "name": "Meraki Dashboard API", "final": True, "disabled": False,
             "pipeline": "meraki_api", "output": "default", "enableOutputExpression": False, "clones": [],
             "description": "Pack REST collectors (tagged with a meraki:* sourcetype).",
             "filter": "__meraki_kind === 'api' || " + json.dumps(api_sts) + ".includes(sourcetype)"},
            {"id": "meraki_syslog", "name": "Meraki syslog", "final": True, "disabled": False,
             "pipeline": "meraki_syslog", "output": "default", "enableOutputExpression": False, "clones": [],
             "description": "Pack syslog Source, or any Source receiving Meraki-format syslog.",
             "filter": "__meraki_kind === 'syslog' || (typeof _raw === 'string' && " + syslog_re + ".test(_raw))"},
            {"id": "meraki_unmatched", "name": "Unmatched", "final": True, "disabled": False,
             "pipeline": "passthru", "output": "default", "enableOutputExpression": False, "clones": [],
             "description": "Not recognised as Meraki data; passed through unchanged.", "filter": "true"},
        ],
    })

    # sources ------------------------------------------------------------------------------
    dump(d("default", "inputs.yml"), {"inputs": {
        "meraki_syslog": {
            "type": "syslog", "disabled": True, "description": "Meraki syslog (Dashboard > Network-wide > General > Syslog servers). UDP is what Meraki sends.",
            "host": "0.0.0.0", "udpPort": 5514, "tcpPort": 5514,
            "maxBufferSize": 1000, "ipWhitelistRegex": "/.*/", "timestampTimezone": "UTC",
            "singleMsgUdpPackets": True, "enableProxyHeader": False, "keepFieldsList": [],
            "octetCounting": False, "inferFraming": True, "strictlyInferOctetCounting": True,
            "allowNonStandardAppName": True, "maxActiveCxn": 1000, "socketIdleTimeout": 0,
            "socketEndingMaxWait": 30, "socketMaxLifespan": 0, "tls": {"disabled": True},
            "sendToRoutes": True, "pqEnabled": False, "streamtags": ["meraki"],
            "metadata": [{"name": "__meraki_kind", "value": "'syslog'"}],
        },
        "meraki_webhook": {
            "type": "http_raw", "disabled": True,
            "description": "Meraki alert webhooks. Meraki only delivers to HTTPS URLs with a publicly trusted certificate: enable TLS here or terminate TLS on a load balancer.",
            "host": "0.0.0.0", "port": 10443,
            "authTokens": [],
            "tls": {"disabled": True},
            "maxActiveReq": 256, "maxRequestsPerSocket": 0, "enableProxyHeader": False,
            "captureHeaders": False, "activityLogSampleRate": 100, "requestTimeout": 0,
            "socketTimeout": 0, "keepAliveTimeout": 5, "enableHealthCheck": False,
            "ipAllowlistRegex": "/.*/", "ipDenylistRegex": "/^$/",
            "breakerRulesets": ["meraki_json_document"], "staleChannelFlushMs": 10000,
            "allowedPaths": ["/meraki/webhook"], "allowedMethods": ["POST"],
            "sendToRoutes": True, "pqEnabled": False, "streamtags": ["meraki"],
            "metadata": [{"name": "__meraki_kind", "value": "'webhook'"},
                         {"name": "sourcetype", "value": "'meraki:webhook'"}],
        },
    }})

    # collectors ---------------------------------------------------------------------------
    dump(d("default", "jobs.yml"), {collector_id(e): collector(e) for e in E})

    # samples ------------------------------------------------------------------------------
    samples_meta = {}
    for fn in sorted(os.listdir(os.path.join(TOOLS, "samples"))):
        if not fn.endswith(".json"):
            continue
        events = json.load(open(os.path.join(TOOLS, "samples", fn)))
        sid = fn[:-5]
        body = json.dumps(events, indent=2)
        write_text(d("data", "samples", sid + ".json"), body + "\n")
        samples_meta[sid] = {"sampleName": sid + ".json", "created": 1763020800000,
                             "size": len(body), "numEvents": len(events), "tags": "meraki"}
    dump(d("default", "samples.yml"), samples_meta)

    shutil.copy(os.path.join(ROOT, "README.md"), d("README.md"))

    # mapping doc -------------------------------------------------------------------------
    rows = ["| Collector | Sourcetype | Tier | Meraki API path | Time params | Schedule (window) | TA input |",
            "|---|---|---|---|---|---|---|"]
    for e in E:
        s = e["sched"]
        win = "snapshot" if e["time_mode"] is None else "%s → %s" % (s["earliest"], s["latest"])
        rows.append("| `%s` | `%s` | %s | `%s` | %s | `%s` (%s) | `%s` |" % (
            collector_id(e), e["st"], e["tier"], e["path"] + ("?productType=" + e["product"] if e["time_mode"] == "events" else ""),
            e["time_mode"] or "-", s["cron"], win, e["ta_input"]))
    write_text(os.path.join(ROOT, "docs", "endpoint-mapping.md"),
               "# Endpoint mapping (generated by tools/build_pack.py)\n\n%d REST collectors, all disabled until "
               "`meraki_org_id` and the `meraki_api_key` secret exist.\n\n%s\n" % (len(E), "\n".join(rows)))

    # .crbl ----------------------------------------------------------------------------------
    os.makedirs(DIST, exist_ok=True)
    out = os.path.join(DIST, "%s_%s.crbl" % (PACK_ID, PACK_VERSION))
    with tarfile.open(out, "w:gz") as tar:
        for base, _, files in os.walk(PACK_DIR):
            for f in sorted(files):
                full = os.path.join(base, f)
                tar.add(full, arcname=os.path.relpath(full, PACK_DIR))
    print("collectors: %d" % len(E))
    print("pack:       %s" % PACK_DIR)
    print("crbl:       %s" % out)


if __name__ == "__main__":
    build()
