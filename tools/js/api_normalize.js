// meraki_api / step 4: timestamp, host, metadata and (optionally) CIM enrichment.
// CIM logic is a 1:1 port of Splunk_TA_cisco_meraki 3.5.0 default/props.conf
// (EVAL-*, FIELDALIAS-*, LOOKUP-*) and tags.conf. In "structured" output mode the
// result is written to a `cim` object inside _raw so it can never collide with
// Meraki's own keys (the TA overwrites e.g. `type` at search time).
const TIME_FIELDS = /*TIME_FIELDS*/{};
const STATIC_TAGS = /*TAGS*/{};

const j = __e.__json || {};
const st = typeof __e.sourcetype === 'string' ? __e.sourcetype : 'meraki:unknown';
const structured = __e.__cfg_output_mode === 'structured';

function toEpoch(v) {
  if (v === undefined || v === null || v === '') return null;
  if (typeof v === 'number') return v > 1e12 ? v / 1000 : v;
  if (typeof v === 'string' && /^\d+(\.\d+)?$/.test(v)) {
    const n = Number(v);
    return n > 1e12 ? n / 1000 : n;
  }
  const ms = Date.parse(v);
  return isNaN(ms) ? null : ms / 1000;
}
function lc(v) { return typeof v === 'string' ? v.toLowerCase() : v; }
function get(o, path) {
  let cur = o;
  const parts = path.split('.');
  for (let i = 0; i < parts.length; i++) {
    if (cur === null || cur === undefined || typeof cur !== 'object') return undefined;
    cur = cur[parts[i]];
  }
  return cur;
}
// Splunk-style multivalue path: "intervals{}.overall.usage.total"
function pluck(o, path) {
  let vals = [o];
  const segs = path.split('.');
  for (let s = 0; s < segs.length; s++) {
    const seg = segs[s];
    const isArr = seg.endsWith('{}');
    const key = isArr ? seg.slice(0, -2) : seg;
    const next = [];
    for (let i = 0; i < vals.length; i++) {
      const v = vals[i] === null || vals[i] === undefined ? undefined : vals[i][key];
      if (v === undefined || v === null) continue;
      if (isArr) { if (Array.isArray(v)) { for (let k = 0; k < v.length; k++) next.push(v[k]); } }
      else next.push(v);
    }
    vals = next;
  }
  if (vals.length === 0) return undefined;
  return vals.length === 1 ? vals[0] : vals;
}
// "10.1.1.1:443" -> 10.1.1.1, "[2001:db8::1]:443" -> 2001:db8::1, bare IPv6 unchanged
function hostPart(v) {
  if (typeof v !== 'string') return v;
  const b = v.match(/^\[([^\]]+)\](?::\d+)?$/);
  if (b) return b[1];
  const p = v.split(':');
  return p.length === 2 ? p[0] : v;
}
// Port of MerakiConnect.get_event_host()
function pickHost(r) {
  const c = [r.deviceName];
  if (r.device && typeof r.device === 'object') c.push(r.device.name, r.device.serial);
  if (r.serial || r.deviceSerial) c.push(r.name);
  c.push(r.deviceSerial, r.serial);
  for (let i = 0; i < c.length; i++) {
    if (typeof c[i] === 'string' && c[i].trim()) return c[i].trim().toLowerCase();
  }
  return null;
}

// ---- _time ------------------------------------------------------------------
const tf = TIME_FIELDS[st];
if (tf) {
  const t = toEpoch(get(j, tf));
  if (t !== null) __e._time = t;
}

// ---- organizationId (TA: event.setdefault("organizationId", org_id)) ---------
if (__e.__cfg_org_id && st !== 'meraki:organizations' && j.organizationId === undefined) {
  j.organizationId = String(__e.__cfg_org_id);
}

// ---- CIM --------------------------------------------------------------------
const c = {};
if (structured) {
  const t = j.type;
  const ed = j.eventData && typeof j.eventData === 'object' ? j.eventData : {};
  const dn = j.deviceName ? j.deviceName : j.deviceSerial;
  const is = function () { for (let i = 0; i < arguments.length; i++) { if (arguments[i] === t) return true; } return false; };
  const tags = [];

  switch (st) {
    case 'meraki:accesspoints': {
      const attacks = is('bcast_deauth_attack', 'mac_spoofing_attack');
      const change4 = is('auto_rf_channel_change', 'auto_tx_power_change', 'dfs_event', 'wpa_deauth');
      const auth5 = is('wpa_auth', 'splash_auth', '8021x_auth', '8021x_eap_success', '8021x_eap_failure');
      const x8021 = is('8021x_auth', '8021x_eap_success', '8021x_eap_failure');
      if (attacks || auth5) c.app = 'Cisco Meraki';
      if (attacks) { c.description = j.description; c.severity = 'unknown'; c.type = 'warning'; c.src = lc(ed.src); c.dest = dn; }
      if (change4) { c.dest = dn; c.dvc = dn; c.src = dn; c.status = 'success'; c.vendor_product = 'Cisco Meraki'; }
      if (is('auto_rf_channel_change', 'auto_tx_power_change', 'dfs_event')) c.object_id = j.deviceSerial;
      if (auth5) c.src = j.clientDescription;
      if (t === '8021x_auth') c.src_ip = ed.last_known_client_ip;
      if (is('8021x_eap_success', '8021x_eap_failure')) c.src_ip = ed.client_ip;
      if (x8021) { c.src_mac = lc(ed.client_mac); c.user = ed.identity; }
      if (is('wpa_auth', 'wpa_deauth', 'splash_auth')) c.user = j.clientDescription;
      if (attacks) tags.push('alert');
      if (auth5) tags.push('authentication');
      if (change4) tags.push('change');
      break;
    }
    case 'meraki:securityappliances': {
      const vpnUp = String(ed.connectivity) === 'true';
      if (t === 'vpn_registry_change') { c.action = vpnUp ? 'started' : 'stopped'; c.change_type = vpnUp ? 'start' : 'stop'; c.result = vpnUp ? 'started' : 'stopped'; }
      if (is('dhcp_problem', 'dhcp_blocked', 'martian_vlan', 'cf_block', 'events_dropped2', 'splash_auth')) c.app = 'Cisco Meraki';
      if (t === 'dhcp_problem') c.description = '"extra":"' + ed.extra + '","vap":"' + ed.vap + '","vlan":"' + ed.vlan + '"';
      if (t === 'events_dropped2') c.description = '"n":"' + ed.n + '","type":"' + ed.type + '"';
      if (t === 'martian_vlan') c.description = '"all_total_illegal_packets":"' + ed.all_total_illegal_packets + '","client_total_illegal_packets":"' + ed.client_total_illegal_packets + '","last_illegal_ip_mapped_vlan_id":"' + ed.last_illegal_ip_mapped_vlan_id + '","last_reported_total":"' + ed.last_reported_total + '","source_client_assigned_vlan":"' + ed.source_client_assigned_vlan + '","source_client_ip":"' + ed.source_client_ip + '","source_client_mac":"' + ed.source_client_mac + '"';
      if (t === 'cf_block') c.description = '"category":"' + ed.category + '","server":"' + ed.server + '","url":"' + ed.url + '"';
      if (is('dhcp_problem', 'dhcp_blocked', 'ids_start', 'ids_update', 'martian_vlan', 'web_cache_started', 'web_cache_stopped', 'vpn_registry_change', 'events_dropped2')) c.dest = dn;
      if (t === 'cf_block') c.dest = j.clientId;
      if (t === 'dhcp_lease') { c.dest_ip = lc(ed.server_ip); c.dest_mac = lc(ed.server_mac); c.duration = ed.duration; c.lease_duration = ed.duration; c.lease_scope = ed.subnet; c.src_ip = ed.ip; }
      const svc = is('ids_start', 'ids_update', 'web_cache_started', 'web_cache_stopped', 'vpn_registry_change');
      if (svc) { c.dvc = dn; c.status = 'success'; }
      if (is('ids_start', 'ids_update')) { c.object_attrs = 'intrusion_detection_rules'; c.object_id = ed.rules; }
      if (t === 'web_cache_started') c.object_attrs = ed.cache_size_mb;
      if (t === 'martian_vlan') c.severity = 'unknown';
      if (is('dhcp_lease', 'dhcp_problem', 'dhcp_blocked', 'martian_vlan', 'cf_block', 'events_dropped2')) c.signature = j.description;
      if (t === 'cf_block') c.signature_id = ed.category;
      if (t === 'dhcp_problem') c.src = ed.vlan;
      if (t === 'dhcp_blocked') c.src = lc(ed.mac);
      if (svc || is('cf_block', 'events_dropped2')) c.src = dn;
      if (t === 'martian_vlan') c.src = ed.source_client_ip;
      if (t === 'splash_auth') { c.src = j.clientDescription; c.user = j.clientDescription; }
      if (is('dhcp_problem', 'dhcp_blocked', 'martian_vlan')) c.type = 'warning';
      if (is('cf_block', 'events_dropped2')) c.type = 'alert';
      if (svc || t === 'dhcp_lease') c.vendor_product = 'Cisco Meraki';
      if (is('dhcp_problem', 'dhcp_blocked', 'martian_vlan', 'cf_block', 'events_dropped2')) tags.push('alert');
      if (t === 'splash_auth') tags.push('authentication');
      if (svc) tags.push('change');
      if (t === 'dhcp_lease') tags.push('network', 'session');
      break;
    }
    case 'meraki:switches': {
      const sw5 = is('port_status', 'stp_port_role_change', 'port_bounce', 'poe_budget_change', 'psu_insert');
      const designated = ed.new_state === 'designated';
      if (t === 'stp_port_role_change') { c.action = designated ? 'started' : 'stopped'; c.result = c.action; c.object_attrs = ed.new_state; c.object_id = ed.port; c.status = ed.new_state; }
      if (sw5) { c.dest = dn; c.dvc = dn; c.src = dn; c.object_category = 'switch'; c.vendor_product = 'Cisco Meraki'; tags.push('change'); }
      if (t === 'port_status') { c.object_attrs = ed['new']; c.object_id = ed.port; c.result = ed['new']; c.status = 'success'; }
      if (t === 'port_bounce') { c.object_attrs = 'bounce'; c.object_id = ed.ports; c.status = 'bounce'; }
      if (t === 'psu_insert') { c.object_id = ed.slot; c.status = 'success'; }
      if (t === 'poe_budget_change') c.status = 'success';
      break;
    }
    case 'meraki:cameras': {
      const cam7 = is('update_user_settings', 'night_mode', 'motion_alert_schedule_applied', 'motion_alert_schedule_removed', 'video_export_delete', 'schedule_applied', 'schedule_edited');
      if (t === 'night_mode') {
        c.action = ed.new_state === 'on' ? 'started' : (ed.new_state === 'off' ? 'stopped' : undefined);
        c.result = c.action;
        c.change_type = 'system configuration';
        c.object_attrs = '"lux":"' + ed.lux + '","new_state":"' + ed.new_state + '"';
        c.object_category = 'night_mode';
      }
      if (cam7) { c.dest = dn; c.dvc = dn; c.src = dn; c.object = 'camera'; c.status = 'success'; c.vendor_product = 'Cisco Meraki'; tags.push('change'); }
      if (is('motion_alert_schedule_applied', 'motion_alert_schedule_removed', 'schedule_applied', 'schedule_edited')) c.object_attrs = 'schedule';
      if (t === 'update_user_settings') c.object_attrs = 'motion_based_retention';
      if (is('update_user_settings', 'motion_alert_schedule_applied', 'motion_alert_schedule_removed', 'schedule_applied', 'schedule_edited')) c.user = ed.user;
      break;
    }
    case 'meraki:organizationsecurity': {
      const ids = j.eventType === 'IDS Alert';
      const fs = j.eventType === 'File Scanned';
      if (ids) {
        c.action = String(j.blocked) === 'true' ? 'blocked' : 'allowed';
        c.category = j.message;
        c.dest = hostPart(j.destIp); c.dest_ip = c.dest;
        c.src = hostPart(j.srcIp); c.src_ip = c.src;
        c.signature_id = j.signature;
        c.signature = j.message;
      }
      if (fs) {
        c.action = lc(j.action);
        c.bytes_in = j.fileSizeBytes;
        c.category = j.fileType;
        c.dest = j.clientName; c.dest_ip = j.srcIp;
        c.file_hash = j.fileHash;
        c.file_path = j.uri;
        if (typeof j.uri === 'string') c.file_name = j.uri.split('/').pop().split('?')[0];
        c.signature = j.canonicalName;
        c.user = j.clientName;
      }
      if (typeof j.ts === 'string') c.date = j.ts.substring(0, 10);
      // TA hard-codes severity="high"; Meraki IDS priority (1-4) is used when present.
      c.severity = __e.__lk_severity || 'high';
      tags.push(fs ? 'malware' : 'ids', 'attack');
      break;
    }
    case 'meraki:audit': {
      c.dest = j.networkId; c.object = j.networkName; c.object_attrs = j.label;
      c.vendor_account = j.adminEmail;
      c.user = typeof j.adminEmail === 'string' ? j.adminEmail.split('@')[0] : undefined;
      c.action = 'modified'; c.change_type = 'system configuration'; c.object_category = 'system configuration';
      c.result = '"' + j.label + '","Old value":"' + j.oldValue + '","New value":"' + j.newValue + '"';
      c.status = 'success';
      break;
    }
    case 'meraki:apirequestshistory': {
      c.dest = j.host; c.user = j.adminId; c.http_method = j.method; c.status = j.responseCode;
      c.src = j.sourceIp; c.uri_path = j.path; c.uri_query = j.queryString; c.http_user_agent = j.userAgent;
      break;
    }
    case 'meraki:assurancealerts': {
      c.alert_description = j.description; c.alert_severity = j.severity; c.alert_id = j.id; c.signature = j.title;
      break;
    }
    case 'meraki:devicesavailabilitieschangehistory': {
      c.object = get(j, 'device.name'); c.device_name = c.object;
      c.object_id = get(j, 'device.serial'); c.device_serial = c.object_id;
      c.product_type = get(j, 'device.productType');
      c.status = pluck(j, 'details.new{}.value'); c.device_status = c.status;
      c.action = 'updated';
      break;
    }
    case 'meraki:devicesuplinksaddressesbydevice':
    case 'meraki:devicesavailabilities': {
      c.device_name = j.name; c.device_serial = j.serial; c.device_mac = j.mac;
      if (st === 'meraki:devicesavailabilities') c.device_status = j.status;
      break;
    }
    case 'meraki:wirelessdevicespacketlossbydevice': {
      c.dest_name = get(j, 'network.name'); c.destination_network = c.dest_name;
      c.downstream_total = get(j, 'downstream.total'); c.upstream_total = get(j, 'upstream.total');
      if (typeof c.downstream_total === 'number' && typeof c.upstream_total === 'number') c.thruput = c.downstream_total + c.upstream_total;
      break;
    }
    case 'meraki:devices': { c.ip = j.lanIp; break; }
    case 'meraki:wirelesscontrolleravailabilitieschangehistory': { c.status = pluck(j, 'changes{}.status'); break; }
    case 'meraki:wirelesscontrollerdevicesinterfacesusagehistorybyinterval': {
      c.bytes = pluck(j, 'intervals{}.overall.usage.total'); c.bytes_in = pluck(j, 'intervals{}.overall.usage.recv');
      c.bytes_out = pluck(j, 'intervals{}.overall.usage.send'); c.dvc = j.serial;
      break;
    }
    case 'meraki:wirelesscontrollerdevicesinterfacespacketsoverviewbydevice': {
      c.bytes = pluck(j, 'interfaces{}.readings{}.total'); c.bytes_in = pluck(j, 'interfaces{}.readings{}.recv');
      c.bytes_out = pluck(j, 'interfaces{}.readings{}.send'); c.dvc = j.serial;
      break;
    }
    case 'meraki:firmwareupgrades': {
      c.upgrade_status = j.status; c.object_id = j.upgradeId; c.change_type = j.productTypes;
      c.src = get(j, 'fromVersion.id'); c.current_update = c.src;
      c.dest = get(j, 'toVersion.id'); c.lastest_update = c.dest;
      c.action = 'updated';
      break;
    }
    default: break;
  }

  // LOOKUP-* with OUTPUTNEW: EVAL results win, lookup only fills gaps.
  const LK = ['action', 'change_type', 'object', 'object_category', 'result', 'object_attrs'];
  for (let i = 0; i < LK.length; i++) {
    const v = __e['__lk_' + LK[i]];
    if (c[LK[i]] === undefined && v !== undefined && v !== null && v !== '') c[LK[i]] = v;
  }
  if (c.vendor_product === undefined) c.vendor_product = 'Cisco Meraki';
  c.vendor = 'Cisco';
  c.product = 'Meraki';
  if (__e.__meraki_event_type !== undefined) c.meraki_event_type = __e.__meraki_event_type;
  const st_tags = STATIC_TAGS[st] || [];
  for (let i = 0; i < st_tags.length; i++) { if (tags.indexOf(st_tags[i]) === -1) tags.push(st_tags[i]); }
  if (tags.length) c.tag = tags;
  const keys = Object.keys(c);
  for (let i = 0; i < keys.length; i++) { if (c[keys[i]] === undefined || c[keys[i]] === null) delete c[keys[i]]; }
  j.cim = c;
}

// ---- metadata + output --------------------------------------------------------
__e.host = pickHost(j) || __e.__cfg_api_host || 'api.meraki.com';
__e.source = 'meraki:api:' + st.replace(/^meraki:/, '');
if (__e.__cfg_index) __e.index = __e.__cfg_index;
__e.__meraki = { kind: 'api', sourcetype: st, event_type: __e.__meraki_event_type, cim: structured ? c : undefined };
__e._raw = JSON.stringify(j);
