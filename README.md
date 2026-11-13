# Cisco Meraki Pack for Cribl Stream

Collects Cisco Meraki data three ways and normalises it into the same sourcetypes as the
**Splunk Add-on for Cisco Meraki 3.5.0** (`Splunk_TA_cisco_meraki`). That means existing Splunk
searches, dashboards and CIM data models keep working when Cribl replaces the TA's modular inputs.

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

1. **Import the pack** (`dist/cisco_meraki_1.0.0.crbl`): *Processing > Packs > Add Pack > Import from file*.
2. **Create a secret**: *Group Settings > Security > Secrets*. Name it `meraki_api_key`, type *Text*, value
   is a Dashboard API key. A read-only org admin is enough.
3. **Set pack variables**: *Pack > Knowledge > Global Variables*.

   | Variable | Default | Notes |
   |---|---|---|
   | `meraki_org_id` | *(empty)* | **Required for collectors.** `GET /api/v1/organizations` |
   | `meraki_api_host` | `api.meraki.com` | Canada: `api.meraki.ca`, China: `api.meraki.cn`, India: `api.meraki.in`, FedRAMP: `api.gov-meraki.com` |
   | `meraki_output_mode` | `raw` | `raw`: `_raw` matches the TA byte for byte, and CIM happens at search time in Splunk. `structured`: adds a `cim` object to the `_raw` JSON, for Sentinel, Elastic, S3, OTel and similar destinations. |
   | `meraki_index` | *(empty)* | Sets `index` when non-empty |
   | `meraki_webhook_shared_secret` | *(empty)* | When set, webhooks with a missing or wrong `sharedSecret` are dropped |
   | `meraki_syslog_drop_categories` | *(empty)* | e.g. `flows,urls`. These are the biggest syslog roles, so dropping them at the edge saves the most. |

4. **Enable the Sources you need.** Everything ships disabled so the import doesn't bind ports or call the API.
5. **Enable collector schedules.** Every collector ships with `schedule.enabled: false`. Run one
   manually first (*Run > Preview*) to validate the key and org ID.
6. **Wire the pack** into a Route, or use the Pack Sources directly. Pick Destinations in the Route.

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
| `__meraki` (internal) | parsed metadata + CIM, for post-processing filters and routing. Never sent to destinations. | ✓ | ✓ |

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
