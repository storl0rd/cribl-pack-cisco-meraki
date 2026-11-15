# Cisco Meraki Pack for Cribl Stream

Collects Cisco Meraki data three ways and normalises it into the same sourcetypes as the
**Splunk Add-on for Cisco Meraki 3.5.0** (`Splunk_TA_cisco_meraki`). That means existing Splunk
searches, dashboards and CIM data models keep working when Cribl replaces the TA's modular inputs.

Each event is parsed once, then copied to one or more **destination profiles**: `splunk`,
`secops` (Google SecOps), `archive` and `structured` (any other tool). Each copy is shaped for its
destination and can be reduced independently.

| Path | Pack object | Sourcetype(s) |
|---|---|---|
| Dashboard API (pull) | 42 REST Collectors `meraki_*` → pipeline `meraki_api` | `meraki:*` (same names as the TA) |
| Alert webhooks (push) | Source `meraki_webhook` (Raw HTTP) → pipeline `meraki_webhook` | `meraki:webhook` |
| Syslog (push) | Source `meraki_syslog` (UDP/TCP 5514) → pipeline `meraki_syslog` | `meraki:syslog` (`source=meraki:syslog:<role>`) |

Requires **Cribl Stream 4.14+**, the first version that supports Collectors inside Packs. On older
versions, import the Sources and Collectors at Worker Group level with `tools/deploy_sources.py`.
The Routes, Pipelines and Lookups work on 4.x.

## How this pack was derived from the Splunk TA

| TA artifact | What it gave us |
|---|---|
| `bin/cisco_meraki_connect.py` | SDK method per input, query parameters (`t0/t1`, `startingAfter`, `tsStart`), `perPage`, network/productType fan-out, host selection (`get_event_host`), `organizationId` injection |
| `bin/meraki_custom_endpoints.json` | REST path, pagination and `perPage` maximum for each input |
| `default/inputs.conf` | Default polling intervals |
| `default/props.conf` | Timestamp field per sourcetype, ~60 `EVAL-*` and `FIELDALIAS-*` CIM mappings |
| `lookups/*.csv` (10 files) | Merged into `meraki_event_cim.csv` (keyed on product + event type) and `meraki_ids_priority.csv` |
| `default/tags.conf` | CIM `tag` values per sourcetype and event type |
| `bin/cisco_meraki_const.py` | Webhook payload template (HEC envelope with `Authorization: Splunk <secret>`) |

**The TA does not handle syslog.** The syslog pipeline follows Meraki's published syslog formats
(MX 18/19 firmware, MR, MS). See `docs/endpoint-mapping.md` for every collector, its API path,
schedule and the TA input it replaces.

## Setup

1. **Import the pack** (`dist/cisco_meraki_2.0.0.crbl`): *Processing > Packs > Add Pack > Import from file*.
2. **Create a secret**: *Group Settings > Security > Secrets*. Name it `meraki_api_key`, type *Text*, value
   is a Dashboard API key. A read-only org admin is enough.
3. **Set pack variables**: *Pack > Knowledge > Global Variables*.

   | Variable | Default | Notes |
   |---|---|---|
   | `meraki_org_id` | *(empty)* | **Required for collectors.** `GET /api/v1/organizations` |
   | `meraki_api_host` | `api.meraki.com` | Canada: `api.meraki.ca`, China: `api.meraki.cn`, India: `api.meraki.in`, FedRAMP: `api.gov-meraki.com` |
   | `meraki_webhook_shared_secret` | *(empty)* | When set, webhooks with a missing or wrong `sharedSecret` are dropped |
   | `meraki_syslog_drop_categories` | *(empty)* | Syslog roles dropped for **every** destination, archive included. Prefer per-destination reductions instead. |
   | `meraki_dest_*`, `meraki_reduce_*`, `meraki_secops_*`, `meraki_index`, `meraki_known_good_destinations` | | See [Destination profiles](#destination-profiles) and [Data reduction](#data-reduction). |

4. **Enable the Sources you need.** Everything ships disabled so the import doesn't bind ports or call the API.
5. **Enable collector schedules.** Every collector ships with `schedule.enabled: false`. Run one
   manually first (*Run > Preview*) to validate the key and org ID.
6. **Wire the pack** into a Route whose destination is an **Output Router** (see below), or use the Pack
   Sources directly.

## Destination profiles

Every Meraki event has a value **tier**: `security`, `operational` or `inventory`. Syslog and webhooks are
always `security`. The tier of each API sourcetype is listed in `docs/endpoint-mapping.md`. A profile
receives one copy of each event whose tier is in its list. The copy is tagged `__meraki_dest` (an internal
field, never sent to a destination). An event that no profile wants is dropped.

| Profile | Default | Tiers (default) | `_raw` | Metadata |
|---|---|---|---|---|
| `splunk` | **on** | `security,operational,inventory` | Exactly what the TA writes (TA search-time CIM keeps working) | `sourcetype`, `source`, `host`, `index` = `meraki_index` |
| `secops` | off | `security` | As received, in native format, so Google's `CISCO_MERAKI` parser can read it | `__logType` = `meraki_secops_log_type`, `__namespace` = `meraki_secops_namespace` |
| `archive` | off | `*` | Canonical event, **never reduced** | as parsed |
| `structured` | off | `security,operational,inventory` | Record JSON plus a `cim` object | for Sentinel, Elastic, Dynatrace, OTel and similar |

Variables per profile: `meraki_dest_<profile>_enabled` (`true` / `false`), `meraki_dest_<profile>_tiers`,
and `meraki_reduce_<profile>` (not available for archive).

### Routing the copies (Output Router)

Create one Output Router and point the Route that uses this pack at it:

```yaml
# Destinations > Output Router > meraki_router
rules:
  - filter: "__meraki_dest === 'splunk'"
    output: splunk_hec_prod
    final: true
  - filter: "__meraki_dest === 'secops'"
    output: google_secops_ca
    final: true
  - filter: "__meraki_dest === 'archive'"
    output: s3_meraki_archive        # or GCS / Cribl Lake; this is your replay source
    final: true
  - filter: "__meraki_dest === 'structured'"
    output: sentinel_or_elastic
    final: true
```

### Google SecOps

Destination: **Google SecOps**.
- Send events as **Unstructured**, API version **V2**.
- Default log type `CISCO_MERAKI`. The pack also sets `__logType` on each event.
- Use the regional endpoint of your SecOps instance (data residency).
- Data RBAC labels go in the destination's custom labels.

Google's `CISCO_MERAKI` parser accepts Meraki syslog and JSON. Which API record shapes it maps
to UDM isn't documented. Before go-live:
1. Run `data/samples/*.json` through *SIEM Settings > Parsers* to validate them.
2. Fill gaps (likely webhooks and some API sourcetypes) with **parser extensions** rather than mapping
   to UDM in Cribl. That way Google keeps maintaining the base parser.

To keep sending a sourcetype whose JSON doesn't parse, remove it from the secops tiers or override
`__logType` for it.

## Data reduction

Reduction is **opt-in per profile** (`meraki_reduce_<profile>`, a comma list) and never applies to `archive`.

| Toggle | Applies to | Typical saving | Loss |
|---|---|---|---|
| `strip_nulls` | API and webhook JSON: removes `null`, `""`, `[]`, `{}` | 10–30% of API bytes | none |
| `inventory_changes_only` | inventory tier: an identical record is sent at most once per 24h | 90–99% of inventory | none (daily heartbeat) |
| `dedupe_airmarshal` | one event per rogue BSSID/SSID per hour | 70–95% of Air Marshal | repeat sightings |
| `dedupe_urls` | one `urls` event per client and domain per 60s | 50–80% of URL logs | per-request detail |
| `drop_ip_flow_start` | keeps `ip_flow_end` | ~50% of ip_flow | flow start events |
| `drop_wireless_assoc` | MR association/disassociation events (syslog and API) | 40–70% of wireless events | association noise |
| `drop_known_good_flows` | **allowed** flows to `meraki_known_good_destinations` (`ip[/cidr][:port]`) | 30–60% of flows | flows to allowlisted destinations |
| `flow_summary` | **allowed** flows become 5-minute summaries (`flow_count` per device, src, dst, port, proto); sourcetype `meraki:syslog:flowsummary` | 90–99% of allowed flows | per-connection fidelity. Use with `archive`. |

Never reduced by any toggle: denied flows, IDS and `security_event`, auth failures, config changes, API audit,
webhooks.

How a full set of toggles affects volume:
- **Lossless set** (`strip_nulls`, `inventory_changes_only`, `dedupe_airmarshal`): typically 30–50% less into
  the SIEM. Add a metrics or observability tool for operational data to save more.
- **Add the lossy flow and URL toggles**: 50–75%.
- **Add `flow_summary`, with archive enabled**: 80–95%.

Measure on your own traffic with Cribl's per-function in/out stats before committing to a number.

Notes:
- `flow_summary` is ignored for `secops`, because Google's parser needs native syslog lines. Use
  `drop_known_good_flows` or `dedupe_urls` there instead.
- Suppression state lives in each worker process and resets on restart. When it does, it re-sends rather
  than drops.

### Webhook

Meraki only delivers to **HTTPS** URLs with a publicly trusted certificate. Enable TLS on the
`meraki_webhook` Source (port 10443, path `/meraki/webhook`) or terminate TLS on a load balancer.

| Option | Meraki config | Auth |
|---|---|---|
| A. Default template | *Network-wide > Alerts > Webhooks*: URL `https://<lb>/meraki/webhook`, shared secret `X`, payload template **Meraki (included)** | Set `meraki_webhook_shared_secret = X`. The pipeline validates it and always removes `sharedSecret` before forwarding. |
| B. Header token (recommended) | Custom payload template with header `Authorization: <token>` | Add `<token>` to the Source's *Auth tokens*. Cribl rejects bad requests before parsing. |
| C. Existing TA template | Point the TA-created HTTP server at a Cribl **Splunk HEC** Source | HEC token. The `meraki_webhook` route matches on `sourcetype=meraki:webhook` from the envelope. |

### Syslog

*Network-wide > General > Reporting > Syslog servers*: Cribl worker or LB IP, UDP 5514, then pick the roles
(Flows, URLs, Security events, Appliance/Switch/Wireless event log, Air Marshal). The route also detects
Meraki syslog arriving on any other Syslog Source by its header. Relay-prefixed lines
(`<pri>Mon dd hh:mm:ss relay 1 <epoch> ...`) parse correctly.

Parsed roles: `flows`, `firewall`, `vpn_firewall`, `cellular_firewall`, `bridge_anyconnect_client_vpn_firewall`,
`l7_firewall`, `ip_flow_start`, `ip_flow_end`, `urls`, `ids-alerts`, `security_event` (`ids_alerted`,
`security_filtering_file_scanned`, `security_filtering_disposition_change`), `events` (key=value and the
common free-text DHCP / port / VPN forms), `airmarshal_events`, `anyconnect_vpn_*`.

## Collector design

- **Pagination**: Meraki `Link: <...>; rel=next` headers (`response_header_link`).
- **Rate limiting**: Meraki allows 10 requests/s per org. Collectors retry 429/502/503/504 with exponential
  backoff and honour `Retry-After`.
- **Windows**: Event logs poll a closed window ending 5 minutes ago (`-10m@m → -5m@m` every 5 min), because
  Meraki event logs arrive late. Windows tile with no gaps and no overlap, so there's no checkpoint state to lose.
  If a run fails, re-run it for that window (*Monitoring > Job Inspector*).
- **Network fan-out**: The 4 event-log collectors and Air Marshal discover networks via
  `GET /organizations/{id}/networks?productTypes[]=<type>`, then make one task per network.
- **Page shape independence**: Every collector emits one event per page. The `meraki_api` pipeline unwraps
  `[...]`, `{items:[...]}`, `{events:[...]}` and single objects, then unrolls to one event per record.

### API budget (plan before enabling everything)

Calls per run ≈ pages. Network event collectors cost `networks × pages` per run. Example: an org with
300 appliance networks polled every 5 min makes ≥ 1 call/s on that collector alone. Raise intervals
(the TA default is daily for wireless, switch and camera) or split orgs across API keys if 429 retries
appear in job logs.

## Output contract

| Field | API | Webhook | Syslog |
|---|---|---|---|
| `_time` | TA timestamp field (`occurredAt`, `ts`, `lastSeen`...), else collection time | `occurredAt` → `sentAt` | header epoch |
| `host` | TA `get_event_host` order, lowercased; fallback `meraki_api_host` | `deviceName` → `deviceSerial` → `networkName` | device name, lowercased |
| `sourcetype` | TA sourcetype | `meraki:webhook` | `meraki:syslog` |
| `source` | `meraki:api:<name>` | `meraki:webhook` | `meraki:syslog:<role>` |
| `__meraki` (internal) | tier, parsed record and CIM, for routing and post-processing filters. Never sent to destinations. | ✓ | ✓ |
| `__meraki_dest` (internal) | destination profile of this copy | ✓ | ✓ |

Intentional differences from the TA (all opt-out by editing one line):
- Assurance alerts, webhook logs, firmware upgrades and webhooks use their event timestamp. The TA
  uses index time (`DATETIME_CONFIG = NONE`).
- IDS `severity` uses Meraki priority (1 high … 4 informational) instead of the TA's hard-coded `high`.
- `organizationId` isn't injected into `meraki:organizations` records. The TA stamps the configured org
  onto every listed org, which is wrong.
- Webhook `sharedSecret` is always removed.

## Rebuilding / testing

```bash
python3 tools/build_pack.py          # regenerate pack/cisco_meraki and dist/*.crbl from the endpoint table
python3 tools/run_tests.py           # run every pipeline against data/samples with assertions
```
