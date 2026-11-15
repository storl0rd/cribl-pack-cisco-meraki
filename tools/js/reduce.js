// tail / reduction: per-destination, opt-in data reduction.
// Toggles come from meraki_reduce_<dest> (comma list). The `archive` profile is never
// reduced -- it is the full-fidelity copy that makes reduction elsewhere defensible.
//
//   strip_nulls            API/webhook JSON: remove null / "" / [] / {} values           (lossless)
//   inventory_changes_only inventory tier: emit a record only when it changed (24h)      (lossless*)
//   dedupe_airmarshal      one event per rogue BSSID/SSID per hour                       (lossless*)
//   dedupe_urls            one urls event per client+domain per 60s                       (lossy)
//   drop_ip_flow_start     drop ip_flow_start, keep ip_flow_end                           (lossy)
//   drop_wireless_assoc    drop MR association/disassociation events                     (lossy)
//   drop_known_good_flows  drop ALLOWED flows to meraki_known_good_destinations          (lossy)
//   flow_summary           ALLOWED flows -> 5-min summaries (not applied to secops)       (lossy)
//   * suppression state is per worker process and resets on restart (fails open: re-emits)
const d = __e.__meraki_dest;
const m = __e.__meraki || {};
const prof = (__e.__cfg_dest || {})[d] || {};
const R = {};
String(prof.reduce || '').split(',').forEach(function (s) { s = s.trim(); if (s) R[s] = true; });

const FW = { flows: 1, firewall: 1, vpn_firewall: 1, cellular_firewall: 1, bridge_anyconnect_client_vpn_firewall: 1, l7_firewall: 1, ip_flow_start: 1, ip_flow_end: 1 };

function ip2n(ip) {
  const p = String(ip).split('.');
  if (p.length !== 4) return null;
  let n = 0;
  for (let i = 0; i < 4; i++) {
    if (!/^\d{1,3}$/.test(p[i])) return null;
    const o = Number(p[i]);
    if (o > 255) return null;
    n = n * 256 + o;
  }
  return n;
}
// entries: "10.0.0.53", "10.0.0.53:53", "10.0.0.0/8", "10.0.0.0/8:123"
function knownGood(ip, port) {
  const n = ip2n(ip);
  if (n === null) return false;
  const list = String(__e.__cfg_known_good || '').split(',');
  for (let i = 0; i < list.length; i++) {
    const mm = list[i].trim().match(/^(\d+\.\d+\.\d+\.\d+)(?:\/(\d{1,2}))?(?::(\d+))?$/);
    if (!mm) continue;
    const base = ip2n(mm[1]);
    const bits = mm[2] === undefined ? 32 : Number(mm[2]);
    if (base === null || bits > 32) continue;
    const size = Math.pow(2, 32 - bits);
    if (Math.floor(n / size) === Math.floor(base / size) && (mm[3] === undefined || String(port) === mm[3])) return true;
  }
  return false;
}
function strip(v) {
  if (Array.isArray(v)) {
    const a = [];
    for (let i = 0; i < v.length; i++) { const x = strip(v[i]); if (x !== undefined) a.push(x); }
    return a.length ? a : undefined;
  }
  if (v !== null && typeof v === 'object') {
    const o = {};
    let any = false;
    const ks = Object.keys(v);
    for (let i = 0; i < ks.length; i++) { const x = strip(v[ks[i]]); if (x !== undefined) { o[ks[i]] = x; any = true; } }
    return any ? o : undefined;
  }
  return v === null || v === '' ? undefined : v;
}

if (d && d !== 'archive') {
  const kind = m.kind;
  const cat = m.category;
  const et = m.event_type;
  const cim = m.cim || {};
  const allowedFlow = kind === 'syslog' && FW[cat] && cim.action === 'allowed';

  if (R.drop_ip_flow_start && kind === 'syslog' && cat === 'ip_flow_start') __e.__meraki_reduce_drop = 'drop_ip_flow_start';
  if (R.drop_wireless_assoc && (et === 'association' || et === 'disassociation') &&
      ((kind === 'syslog' && cat === 'events') || m.sourcetype === 'meraki:accesspoints')) __e.__meraki_reduce_drop = 'drop_wireless_assoc';
  if (R.drop_known_good_flows && allowedFlow && knownGood(cim.dest_ip, cim.dest_port)) __e.__meraki_reduce_drop = 'drop_known_good_flows';

  if (!__e.__meraki_reduce_drop) {
    if (R.strip_nulls && (kind === 'api' || kind === 'webhook') && m.record) {
      const s = strip(m.record) || {};
      __e.__meraki_record_out = s;
      __e._raw = JSON.stringify(s);
    }
    if (R.flow_summary && d !== 'secops' && allowedFlow) {
      // consumed by the Aggregations function; group-by fields must be top-level
      __e.meraki_agg_dest = d;
      __e.meraki_agg_device = String(__e.host || '');
      __e.meraki_agg_category = String(cat);
      __e.meraki_agg_src_ip = String(cim.src_ip || '');
      __e.meraki_agg_dest_ip = String(cim.dest_ip || '');
      __e.meraki_agg_dest_port = String(cim.dest_port || '');
      __e.meraki_agg_transport = String(cim.transport || '');
      __e.meraki_agg_action = String(cim.action || '');
    } else if (R.dedupe_urls && kind === 'syslog' && cat === 'urls') {
      const hm = typeof cim.url === 'string' ? cim.url.match(/^[a-z][a-z0-9+.-]*:\/\/([^\/:?#]+)/i) : null;
      __e.__meraki_suppress = 'url';
      __e.__meraki_suppress_key = [d, __e.host, cim.src_ip, hm ? hm[1].toLowerCase() : cim.url].join('|');
    } else if (R.dedupe_airmarshal && (cat === 'airmarshal_events' || m.sourcetype === 'meraki:airmarshal')) {
      const r = m.record || {};
      __e.__meraki_suppress = 'airmarshal';
      __e.__meraki_suppress_key = [d, __e.host, cim.bssid || r.ssid || cim.ssid].join('|');
    } else if (R.inventory_changes_only && m.tier === 'inventory') {
      __e.__meraki_suppress = 'inventory';
      __e.__meraki_suppress_key = [d, m.sourcetype, __e._raw].join('|');
    }
  }
}
