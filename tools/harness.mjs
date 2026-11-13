// Minimal Cribl function emulator + assertions. Input: JSON bundle on stdin (see run_tests.py).
import { readFileSync } from 'node:fs';

const B = JSON.parse(readFileSync(0, 'utf8'));
let failures = 0, passes = 0;
const ok = (cond, msg) => { if (cond) { passes++; } else { failures++; console.log('  FAIL: ' + msg); } };
const eq = (a, b, msg) => ok(JSON.stringify(a) === JSON.stringify(b), `${msg} -> expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);

const mkC = (vars) => ({ vars });
// Cribl semantics: an unknown field name evaluates to undefined (no ReferenceError);
// JS globals (JSON, Date, Array...) still resolve normally.
const scope = (e) => new Proxy(e, { has: (t, k) => typeof k === 'string' && k !== 'C' && (k in t || !(k in globalThis)) });
const expr = (src) => { const f = new Function('C', '__s', `with (__s) { return (${src}); }`); return (C, e) => f(C, scope(e)); };
const truthy = (src, e, C) => { try { return !!expr(src)(C, e); } catch (err) { return false; } };

function runFn(fn, events, C) {
  if (fn.disabled) return events;
  const out = [];
  for (const e of events) {
    if (!truthy(fn.filter ?? 'true', e, C)) { out.push(e); continue; }
    switch (fn.id) {
      case 'eval':
        for (const f of fn.conf.add || []) e[f.name] = expr(f.value)(C, e);
        out.push(e); break;
      case 'code':
        new Function('__e', fn.conf.code)(e); out.push(e); break;
      case 'unroll': {
        const arr = expr(fn.conf.srcExpr)(C, e);
        if (!Array.isArray(arr)) { out.push(e); break; }
        for (const item of arr) out.push({ ...e, [fn.conf.dstField]: item });
        break;
      }
      case 'lookup': {
        const rows = B.lookups[fn.conf.file];
        if (!rows) throw new Error('missing lookup ' + fn.conf.file);
        const hit = rows.find(r => fn.conf.inFields.every(f => e[f.eventField] !== undefined && String(e[f.eventField]) === r[f.lookupField]));
        if (hit) for (const o of fn.conf.outFields) { if (e[o.eventField] === undefined && hit[o.lookupField] !== '') e[o.eventField] = hit[o.lookupField]; }
        out.push(e); break;
      }
      case 'drop': break;
      default: throw new Error('harness does not emulate function ' + fn.id);
    }
  }
  return out;
}

function runPack(events, varOverrides = {}) {
  const C = mkC({ ...B.vars, ...varOverrides });
  const results = [];
  for (const ev of events) {
    const e = JSON.parse(JSON.stringify(ev));
    const route = B.routes.find(r => !r.disabled && truthy(r.filter, e, C));
    if (route.pipeline === 'passthru') { e.__route = route.id; results.push(e); continue; }
    let evs = [e];
    for (const fn of B.pipelines[route.pipeline].functions) evs = runFn(fn, evs, C);
    for (const x of evs) { x.__route = route.id; results.push(x); }
  }
  return results;
}
const J = (e) => JSON.parse(e._raw);

// ============================================================================ syslog
console.log('syslog');
{
  const out = runPack(B.samples.meraki_syslog, { meraki_output_mode: 'structured', meraki_org_id: '123456' });
  const by = (src) => out.filter(e => e.source === src);
  eq(out.filter(e => e.__route === 'meraki_syslog').length, 18, 'all lines from the pack syslog Source routed to meraki_syslog');
  const junk = out.find(e => e._raw === 'this line is not meraki syslog at all');
  eq([junk.source, junk.__meraki.parse_error], ['meraki:syslog:unparsed', 'header did not match Meraki syslog format'], 'unparseable line kept + flagged');
  // header detection when data arrives on a non-pack Source (no __meraki_kind)
  const untagged = runPack(B.samples.meraki_syslog.map(e => ({ _raw: e._raw, _time: e._time })));
  eq(untagged.filter(e => e.__route === 'meraki_syslog').length, 17, 'untagged: Meraki lines detected by header regex');
  eq(untagged.find(e => e._raw.startsWith('this line')).__route, 'meraki_unmatched', 'untagged: non-Meraki line falls through');

  const f = by('meraki:syslog:flows');
  eq(f.length, 2, 'two flows lines');
  eq(f[0]._time, 1763020801.1234567, 'flows _time from epoch');
  eq(f[0].host, 'mx84_hq', 'host lowercased device');
  eq(f[0].sourcetype, 'meraki:syslog', 'sourcetype');
  eq(J(f[0]).cim.action, 'allowed', 'flows pattern allow -> allowed');
  eq(J(f[0]).cim.dest_port, '53', 'flows dport');
  eq(J(f[0]).cim.src_mac, 'aa:bb:cc:11:22:33', 'flows mac lowercased');
  eq(J(f[1]).decision, 'deny', 'flows leading decision token');
  eq(J(f[1]).cim.action, 'blocked', 'flows deny -> blocked');
  eq(J(f[1]).cim.rule, '(dst 203.0.113.0/24)', 'flows rule text');
  eq(J(by('meraki:syslog:firewall')[0]).cim.action, 'blocked', 'firewall pattern 0 -> blocked');
  eq(J(by('meraki:syslog:vpn_firewall')[0]).cim.transport, 'icmp', 'vpn_firewall transport');

  const u = J(by('meraki:syslog:urls')[0]);
  eq(u.cim.url, 'https://www.example.com/index.html?q=a=b', 'urls request url (with = inside)');
  eq(u.cim.http_method, 'GET', 'urls method');
  eq(u.cim.http_user_agent, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'urls quoted agent');
  eq([u.cim.src_ip, u.cim.src_port], ['10.10.1.25', '52133'], 'urls src ip:port split');

  const ids = J(by('meraki:syslog:ids-alerts')[0]);
  eq(ids.cim.signature_id, '1:28423:1', 'ids signature id');
  eq(ids.cim.signature, 'EXPLOIT-KIT Multiple exploit kit single digit exe detection', 'ids message tail');
  eq(ids.cim.severity, 'high', 'ids priority 1 -> high');
  eq(ids.cim.action, 'blocked', 'ids decision');
  eq(ids.cim.transport, 'tcp', 'ids tcp/ip -> tcp');
  eq([ids.cim.dest_ip, ids.cim.dest_port], ['10.10.1.25', '51200'], 'ids dst split');

  const se = by('meraki:syslog:security_event').map(J);
  eq(se[0].meraki_subtype, 'ids_alerted', 'security_event subtype');
  eq(se[0].cim.severity, 'medium', 'security_event priority 2 -> medium');
  eq(se[0].cim.action, 'allowed', 'security_event ids decision allowed');
  eq(se[1].meraki_subtype, 'security_filtering_file_scanned', 'file scanned subtype');
  eq(se[1].cim.file_name, 'Win.Trojan.Agent', 'file scanned name');
  eq(se[1].cim.action, 'blocked', 'file scanned action=block -> blocked');
  eq(se[1].cim.tag, ['malware', 'attack'], 'file scanned tags');

  const ev = by('meraki:syslog:events').map(J);
  eq(ev[0].meraki_event_type, '8021x_eap_success', 'events type= kv');
  eq([ev[0].cim.user, ev[0].cim.src_ip, ev[0].cim.action], ['jdoe@corp.example', '10.40.2.15', 'success'], '802.1X CIM');
  eq(ev[0].cim.tag, ['authentication'], '802.1X tag');
  eq(ev[2].meraki_event_type, 'dhcp_lease', 'free-text dhcp lease');
  eq([ev[2].client_ip, ev[2].dns], ['10.10.1.88', '10.0.0.53, 10.0.0.54'], 'dhcp lease fields');
  eq([ev[3].meraki_event_type, ev[3].port, ev[3]['new']], ['port_status', '12', 'down'], 'port status free text');
  eq([ev[4].meraki_event_type, ev[4].cim.category, ev[4].cim.action], ['content_filtering_block', 'Gambling', 'blocked'], 'content filter block');
  eq(ev[5].meraki_event_type, 'site_to_site_vpn', 's2s vpn free text');

  const am = J(by('meraki:syslog:airmarshal_events')[0]);
  eq([am.cim.signature, am.cim.ssid, am.cim.channel], ['rogue_ssid_detected', 'FreeWiFi', '157'], 'air marshal');
  const fe = J(by('meraki:syslog:ip_flow_end')[0]);
  eq([fe.cim.src_translated_ip, fe.cim.action], ['203.0.113.1', 'allowed'], 'ip_flow_end NAT');
  const ac = by('meraki:syslog:anyconnect_vpn_auth_success');
  eq(ac.length, 1, 'relay-prefixed line parsed');
  eq(ac[0]._time, 1763020817.000000001, 'relay-prefixed uses Meraki epoch, not relay date');
  ok(J(ac[0]).original_message.startsWith('<134>Nov 13'), 'structured keeps original_message');

  // raw mode keeps _raw byte-identical and only sets metadata
  const raw = runPack(B.samples.meraki_syslog.slice(0, 1));
  eq(raw[0]._raw, B.samples.meraki_syslog[0]._raw, 'raw mode: _raw untouched');
  eq(raw[0].__meraki.cim.action, 'allowed', 'raw mode: __meraki internal still populated');

  // drop list
  const dropped = runPack(B.samples.meraki_syslog, { meraki_syslog_drop_categories: 'flows, urls' });
  eq(dropped.filter(e => /:(flows|urls)$/.test(e.source || '')).length, 0, 'drop list removes flows+urls');
  eq(dropped.length, out.length - 3, 'drop list removes exactly 3 events');
}

// ============================================================================ webhook
console.log('webhook');
{
  const s = B.samples.meraki_webhook;
  const noSecret = runPack(s);
  eq(noSecret.length, 4, 'no secret configured: all 4 accepted');
  ok(noSecret.every(e => !('sharedSecret' in J(e))), 'sharedSecret always stripped');
  eq(noSecret[0]._time, Date.parse('2025-11-13T08:00:59Z') / 1000, '_time from occurredAt');
  eq([noSecret[0].host, noSecret[0].sourcetype], ['mx84_hq', 'meraki:webhook'], 'host/sourcetype');
  eq(J(noSecret[1]).alertType, 'Uplink status changed', 'HEC envelope unwrapped');
  eq(J(noSecret[3]).alertId, '643451796765', 'pretty-printed body parsed');

  const withSecret = runPack(s, { meraki_webhook_shared_secret: 's3cr3t', meraki_output_mode: 'structured' });
  eq(withSecret.length, 3, 'secret configured: wrong secret dropped, HEC envelope kept');
  eq(J(withSecret[0]).cim, { id: '643451796765', type: 'Uplink status changed', signature: 'Uplink status changed', dest: 'e0:cb:bc:00:00:01', dvc: 'MX84_HQ', severity: 'critical', vendor_product: 'Cisco Meraki', vendor: 'Cisco', product: 'Meraki', tag: ['alert'] }, 'webhook CIM (TA aliases)');
  const r = runPack([{ _raw: 'not json', __meraki_kind: 'webhook' }]);
  eq([r.length, r[0].__meraki.parse_error], [1, 'webhook body is not a JSON object'], 'bad body kept + flagged');
}

// ============================================================================ API
console.log('api');
{
  const out = runPack(B.samples.meraki_api_pages, { meraki_output_mode: 'structured', meraki_org_id: '123456' });
  const st = (s) => out.filter(e => e.sourcetype === s);
  ok(out.every(e => e.__route === 'meraki_api'), 'all API pages routed to meraki_api');

  const sa = st('meraki:securityappliances');
  eq(sa.length, 4, '{events:[...]} page unrolled to 4 records');
  eq(sa[0]._time, Date.parse('2025-11-13T07:51:10.123Z') / 1000, '_time from occurredAt');
  eq(sa[0].host, 'mx84_hq', 'host from deviceName');
  eq(sa[0].source, 'meraki:api:securityappliances', 'source');
  const lease = J(sa[0]);
  eq(lease.organizationId, '123456', 'organizationId injected');
  eq([lease.cim.src_ip, lease.cim.dest_mac, lease.cim.lease_scope, lease.cim.action], ['10.10.1.88', 'e0:cb:bc:00:00:01', '10.10.1.0/24', 'added'], 'dhcp_lease EVAL + lookup action');
  eq(lease.cim.tag, ['network', 'session'], 'dhcp_lease tags');
  const vpn = J(sa[1]);
  eq(sa[1].host, 'q2xx-aaaa-bbbb', 'empty deviceName -> serial host');
  eq([vpn.cim.action, vpn.cim.change_type, vpn.cim.object, vpn.cim.object_category], ['stopped', 'stop', 'securityappliance', 'site_to_site_vpn'], 'vpn_registry_change EVAL wins, lookup fills object');
  const cf = J(sa[2]);
  eq([cf.cim.dest, cf.cim.signature_id, cf.cim.type], ['k2', 'Gambling', 'alert'], 'cf_block');
  eq(cf.cim.description, '"category":"Gambling","server":"198.51.100.44:80","url":"http://casino.example.com/"', 'cf_block printf description');
  eq(cf.type, 'cf_block', 'original Meraki `type` preserved (cim is namespaced)');
  const idsu = J(sa[3]);
  eq([idsu.cim.action, idsu.cim.object, idsu.cim.object_category, idsu.cim.object_id], ['modified', 'intrusion detection', 'policy', 'snort-2025-11-12'], 'ids_update lookup+EVAL');

  const ap = st('meraki:accesspoints').map(J);
  eq([ap[0].cim.action, ap[0].cim.user, ap[0].cim.src_mac, ap[0].cim.src_ip], ['failure', 'jdoe@corp.example', 'f0:18:98:aa:bb:cc', '10.40.2.15'], '8021x_eap_failure');
  eq([ap[1].cim.object, ap[1].cim.object_category, ap[1].cim.change_type, ap[1].cim.object_id], ['channel', 'accesspoint', 'update', 'Q3XX-CCCC-DDDD'], 'auto_rf_channel_change');
  const sw = J(st('meraki:switches')[0]);
  eq([sw.cim.action, sw.cim.status, sw.cim.object, sw.cim.change_type], ['started', 'designated', 'port', 'start'], 'stp_port_role_change');
  eq(st('meraki:cameras').length, 0, 'empty events page -> zero events');

  const sec = st('meraki:organizationsecurity').map(J);
  eq([sec[0].cim.action, sec[0].cim.src_ip, sec[0].cim.dest_ip, sec[0].cim.severity, sec[0].cim.date], ['blocked', '203.0.113.50', '10.10.1.25', 'high', '2025-11-13'], 'IDS Alert');
  eq([sec[1].cim.action, sec[1].cim.file_name, sec[1].cim.bytes_in, sec[1].cim.user], ['blocked', 'payload.exe', 193020, 'laptop-02'], 'File Scanned');
  eq(st('meraki:organizationsecurity')[0]._time, Date.parse('2025-11-13T07:51:30Z') / 1000, 'security _time from ts');

  const au = J(st('meraki:audit')[0]);
  eq([au.cim.user, au.cim.dest, au.cim.object, au.cim.action, au.cim.tag], ['jane.admin', 'L_111', 'HQ', 'modified', ['change']], 'audit CIM');

  const dv = st('meraki:devices');
  eq(dv.length, 2, 'top-level array unrolled');
  eq([dv[0].host, dv[1].host], ['mx84_hq', 'q3xx-cccc-dddd'], 'inventory host: name if present else serial');
  eq(dv[0]._time, 1763020800, 'snapshot keeps collection _time');

  const h = J(st('meraki:devicesavailabilitieschangehistory')[0]);
  eq([h.cim.device_name, h.cim.status, h.cim.product_type], ['MR46_Floor2', 'offline', 'wireless'], 'availability change history aliases');
  eq(st('meraki:devicesavailabilitieschangehistory')[0].host, 'mr46_floor2', 'host from device.name');

  const w = J(st('meraki:wirelesscontrollerdevicesinterfacesusagehistorybyinterval')[0]);
  eq([w.cim.bytes, w.cim.bytes_in, w.cim.dvc], [[1000, 2000], [600, 1500], 'WLC-9800-1'], '{items} page + multivalue pluck');

  const lic = st('meraki:licensesoverview');
  eq([lic.length, J(lic[0]).licensedDeviceCounts.MR], [1, 40], 'single-object page kept whole');
  eq(st('meraki:airmarshal')[0]._time, 1763020000, 'airmarshal _time from lastSeen epoch');
  const orgs = st('meraki:organizations').map(J);
  eq([orgs[0].organizationId, orgs[1].organizationId], [undefined, undefined], 'organizationId not stamped on org listing');

  const raw = runPack(B.samples.meraki_api_pages.slice(6, 7), { meraki_org_id: '123456' });
  ok(!('cim' in J(raw[0])), 'raw mode: no cim object');
  eq(J(raw[0]).serial, 'Q2XX-AAAA-BBBB', 'raw mode: record intact');
}

// ============================================================================ collector expressions
console.log('collectors');
{
  const vars = { meraki_api_host: 'api.meraki.ca', meraki_org_id: '123456' };
  const C = { vars };
  const earliest = 1763020200, latest = 1763020500;
  const ev = (src, scope) => new Function('C', 'earliest', 'latest', 'id', `return (${src});`)(C, earliest, latest, scope.id);
  let n = 0;
  for (const [id, job] of Object.entries(B.jobs)) {
    const conf = job.collector.conf;
    const url = ev(conf.collectUrl, { id: 'L_111' });
    ok(/^https:\/\/api\.meraki\.ca\/api\/v1\/(organizations|networks|administered)/.test(url) && !url.includes('${'), `${id}: url ${url}`);
    for (const p of conf.collectRequestParams) {
      const v = ev(p.value, {});
      ok(v !== undefined && v !== '', `${id}: param ${p.name} evaluates`);
      if (['t0', 't1', 'tsStart', 'tsEnd', 'startingAfter', 'endingBefore'].includes(p.name)) ok(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(v), `${id}: ${p.name} ISO8601 (${v})`);
    }
    if (conf.discovery.discoverType === 'http') ok(ev(conf.discovery.discoverUrl, {}) === 'https://api.meraki.ca/api/v1/organizations/123456/networks', `${id}: discover url`);
    ok(job.schedule.enabled === false, `${id}: ships disabled`);
    ok(job.input.metadata.find(m => m.name === 'sourcetype'), `${id}: sourcetype metadata`);
    n++;
  }
  const t0 = ev(B.jobs.meraki_audit.collector.conf.collectRequestParams.find(p => p.name === 't0').value, {});
  eq(t0, '2025-11-13T07:50:00.000Z', 'earliest epoch -> t0 ISO');
  eq(n, 42, 'collector count');
}

console.log(`\n${passes} passed, ${failures} failed`);
process.exit(failures ? 1 : 0);
