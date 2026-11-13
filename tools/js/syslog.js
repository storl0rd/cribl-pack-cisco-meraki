// meraki_syslog: Meraki MX/MS/MR/MV/MG syslog (Dashboard > Network-wide > General > Reporting).
// The Splunk TA 3.5.0 does not handle syslog; formats follow Meraki's
// "Syslog Event Types and Log Samples" documentation.
//
//   <134>1 1700000000.123456789 MX84_HQ flows src=10.0.0.5 dst=8.8.8.8 mac=AA:.. protocol=udp sport=5353 dport=53 pattern: allow all
//   ^PRI ^v ^epoch               ^device ^category ^body
const raw = (typeof __e._raw === 'string' ? __e._raw : String(__e._raw)).replace(/[\r\n]+$/, '');
const HDR = /^(?:<(\d{1,3})>)?(?:[\s\S]*?\s)??(?:1\s+)?(\d{10}(?:\.\d+)?)\s+(\S+)\s+([A-Za-z][\w-]*)(?:\s+([\s\S]*))?$/;
const TAIL_CATS = { flows: 1, firewall: 1, vpn_firewall: 1, cellular_firewall: 1, bridge_anyconnect_client_vpn_firewall: 1, l7_firewall: 1, urls: 1, 'ids-alerts': 1, security_event: 1 };
const FIREWALL_CATS = { flows: 1, firewall: 1, vpn_firewall: 1, cellular_firewall: 1, bridge_anyconnect_client_vpn_firewall: 1, l7_firewall: 1, ip_flow_start: 1, ip_flow_end: 1 };
const PRIORITY = { '1': 'high', '2': 'medium', '3': 'low', '4': 'informational' };
const KV_RE = /([A-Za-z_][\w.\-]*)=('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|\S*)/g;

function parseKV(s, out) {
  KV_RE.lastIndex = 0;
  let m;
  while ((m = KV_RE.exec(s)) !== null) {
    let v = m[2];
    if (v.length >= 2 && (v[0] === "'" || v[0] === '"') && v[v.length - 1] === v[0]) v = v.slice(1, -1);
    out[m[1]] = v;
    if (m[0].length === 0) KV_RE.lastIndex++;
  }
}
function splitHostPort(v) {
  if (typeof v !== 'string' || !v) return [undefined, undefined];
  let m = v.match(/^\[([^\]]+)\]:(\d+)$/);
  if (m) return [m[1], m[2]];
  m = v.match(/^([^:]+):(\d+)$/);
  if (m) return [m[1], m[2]];
  return [v, undefined];
}
function normAction(v) {
  if (v === undefined || v === null) return undefined;
  const s = String(v).toLowerCase();
  if (s === '1' || s === 'allow' || s === 'allowed' || s === 'pass') return 'allowed';
  if (s === '0' || s === 'deny' || s === 'denied' || s === 'block' || s === 'blocked' || s === 'drop' || s === 'rst') return 'blocked';
  return s;
}

const m = raw.match(HDR);
const p = {};
const c = {};
const tags = [];
if (!m) {
  __e.sourcetype = 'meraki:syslog';
  __e.source = 'meraki:syslog:unparsed';
  __e.__meraki = { kind: 'syslog', parse_error: 'header did not match Meraki syslog format' };
} else {
  if (m[1] !== undefined) p.syslog_pri = Number(m[1]);
  p.meraki_epoch = m[2];
  p.meraki_device = m[3];
  p.meraki_category = m[4];
  let body = m[5] || '';
  const cat = p.meraki_category;

  // first-token variants: "flows allow src=..", "security_event ids_alerted signature=.."
  if (cat === 'security_event') {
    const s = body.match(/^(\S+)\s*([\s\S]*)$/);
    if (s) { p.meraki_subtype = s[1]; body = s[2]; }
  } else if (FIREWALL_CATS[cat]) {
    const s = body.match(/^(allow|deny|block)\s+([\s\S]*)$/i);
    if (s) { p.decision = s[1].toLowerCase(); body = s[2]; }
  }

  if (TAIL_CATS[cat]) {
    const t = body.match(/^([\s\S]*?)\s*\b(pattern|request|message):\s*([\s\S]*)$/);
    if (t) {
      body = t[1];
      if (t[2] === 'pattern') {
        const pm = t[3].match(/^(\S+)\s*([\s\S]*)$/);
        if (pm) { p.pattern_decision = pm[1]; if (pm[2]) p.rule = pm[2]; }
      } else if (t[2] === 'request') {
        const rm = t[3].match(/^(\S+)\s+(\S+)/);
        if (rm) { p.request_method = rm[1]; p.request_url = rm[2]; } else { p.request = t[3]; }
      } else {
        p.message = t[3];
      }
    }
    parseKV(body, p);
  } else if (cat === 'events') {
    let em;
    if (/^type=/.test(body)) {
      parseKV(body, p);
      p.meraki_event_type = p.type;
    } else if ((em = body.match(/^dhcp lease of ip (\S+) from server mac (\S+) for client mac (\S+)(?: from router (\S+))?(?: on subnet (\S+))?(?: with dns (.+))?$/i))) {
      p.meraki_event_type = 'dhcp_lease';
      p.client_ip = em[1]; p.server_mac = em[2]; p.client_mac = em[3];
      if (em[4]) p.router = em[4]; if (em[5]) p.subnet = em[5]; if (em[6]) p.dns = em[6];
    } else if ((em = body.match(/^dhcp no offers for mac (\S+)/i))) {
      p.meraki_event_type = 'dhcp_no_offers'; p.client_mac = em[1];
    } else if ((em = body.match(/^port (\S+) status changed from (\S+) to (\S+)/i))) {
      p.meraki_event_type = 'port_status'; p.port = em[1]; p.old = em[2]; p['new'] = em[3];
    } else if ((em = body.match(/^Site-to-site VPN:\s*([\s\S]*)$/i))) {
      p.meraki_event_type = 'site_to_site_vpn'; p.message = em[1];
    } else if ((em = body.match(/^([a-z][a-z0-9_]+)\s+([A-Za-z_][\w.\-]*=[\s\S]*)$/))) {
      p.meraki_event_type = em[1];
      parseKV(em[2], p);
    } else {
      p.message = body;
    }
  } else if (cat === 'airmarshal_events' || cat === 'ip_flow_start' || cat === 'ip_flow_end') {
    parseKV(body, p);
    if (p.type !== undefined) p.meraki_event_type = p.type;
  } else {
    // anyconnect_vpn_*, client_vpn, unknown roles: keep text, still lift k=v pairs
    p.message = body;
    const kv = {};
    parseKV(body, kv);
    const ks = Object.keys(kv);
    for (let i = 0; i < ks.length; i++) { if (p[ks[i]] === undefined) p[ks[i]] = kv[ks[i]]; }
  }

  // ---- CIM normalisation ---------------------------------------------------------
  const src = splitHostPort(p.src);
  const dst = splitHostPort(p.dst);
  if (src[0] !== undefined) c.src_ip = src[0];
  if (dst[0] !== undefined) c.dest_ip = dst[0];
  c.src_port = p.sport !== undefined ? p.sport : src[1];
  c.dest_port = p.dport !== undefined ? p.dport : dst[1];
  if (p.mac) c.src_mac = String(p.mac).toLowerCase();
  if (p.client_mac) c.src_mac = String(p.client_mac).toLowerCase();
  if (p.client_ip) c.src_ip = p.client_ip;
  if (p.protocol) { c.transport = String(p.protocol).toLowerCase().replace(/\/ip$/, ''); c.protocol = 'ip'; }
  if (p.translated_src_ip) c.src_translated_ip = p.translated_src_ip;
  if (p.translated_port) c.src_translated_port = p.translated_port;
  if (p.sent_bytes !== undefined) c.bytes_out = p.sent_bytes;
  if (p.received_bytes !== undefined) c.bytes_in = p.received_bytes;
  c.dvc = p.meraki_device;
  c.vendor_product = 'Cisco Meraki';
  c.vendor = 'Cisco';
  c.product = 'Meraki';

  if (FIREWALL_CATS[cat]) {
    c.action = normAction(p.decision !== undefined ? p.decision : p.pattern_decision);
    if (cat === 'ip_flow_start' || cat === 'ip_flow_end') c.action = c.action || 'allowed';
    if (p.rule) c.rule = p.rule;
    tags.push('network', 'communicate');
  } else if (cat === 'urls') {
    c.url = p.request_url; c.http_method = p.request_method; c.http_user_agent = p.agent;
    c.action = 'allowed';
    tags.push('web', 'proxy');
  } else if (cat === 'ids-alerts' || (cat === 'security_event' && p.meraki_subtype === 'ids_alerted')) {
    c.signature_id = p.signature; c.signature = p.message;
    c.severity = PRIORITY[p.priority] || 'high';
    c.action = normAction(p.decision);
    if (p.direction) c.direction = p.direction;
    if (p.dhost) c.dest_mac = String(p.dhost).toLowerCase();
    tags.push('ids', 'attack');
  } else if (cat === 'security_event') {
    // security_filtering_file_scanned / security_filtering_disposition_change
    c.url = p.url; c.file_hash = p.sha256; c.file_name = p.name; c.signature = p.disposition;
    c.action = normAction(p.action);
    tags.push('malware', 'attack');
  } else if (cat === 'airmarshal_events') {
    c.signature = p.type; c.ssid = p.ssid; c.bssid = p.bssid; c.signal_strength = p.rssi; c.channel = p.channel;
    c.src_mac = p.src ? String(p.src).toLowerCase() : undefined;
    c.src_ip = undefined;
    tags.push('alert');
  } else if (cat === 'events') {
    const et = p.meraki_event_type || '';
    if (/^(8021x_|wpa_|splash_)/.test(et) || et === 'association' || et === 'disassociation') {
      c.user = p.identity; c.action = /failure|fail|deauth|disassociation/.test(et) ? 'failure' : 'success';
      c.app = 'Cisco Meraki';
      tags.push('authentication');
    } else if (et === 'dhcp_lease') {
      c.dest_mac = p.server_mac ? String(p.server_mac).toLowerCase() : undefined; c.lease_scope = p.subnet; c.action = 'added';
      tags.push('network', 'session');
    } else if (et === 'content_filtering_block') {
      c.url = p.url; c.category = p.category0; c.action = 'blocked';
      tags.push('web', 'proxy');
    } else {
      tags.push('change');
    }
    if (et) c.meraki_event_type = et;
  }
  if (tags.length) c.tag = tags;
  const ck = Object.keys(c);
  for (let i = 0; i < ck.length; i++) { if (c[ck[i]] === undefined || c[ck[i]] === null || c[ck[i]] === '') delete c[ck[i]]; }

  // ---- metadata ---------------------------------------------------------------------
  __e._time = Number(p.meraki_epoch);
  __e.host = String(p.meraki_device).toLowerCase();
  __e.sourcetype = 'meraki:syslog';
  __e.source = 'meraki:syslog:' + cat;
  if (__e.__cfg_index) __e.index = __e.__cfg_index;

  const drop = String(__e.__cfg_syslog_drop || '').split(',').map(function (x) { return x.trim(); }).filter(function (x) { return x; });
  if (drop.indexOf(cat) !== -1) __e.__meraki_drop = 'category_filtered';

  __e.__meraki = { kind: 'syslog', category: cat, subtype: p.meraki_subtype, event_type: p.meraki_event_type, fields: p, cim: c };
  if (__e.__cfg_output_mode === 'structured') {
    const out = {};
    const pk = Object.keys(p);
    for (let i = 0; i < pk.length; i++) out[pk[i]] = p[pk[i]];
    out.cim = c;
    out.original_message = raw;
    __e._raw = JSON.stringify(out);
  }
}
