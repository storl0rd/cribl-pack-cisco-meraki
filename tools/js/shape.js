// tail / shape: make each copy right for its destination profile.
//   splunk      _raw as the TA would write it; sourcetype/source/host; index from meraki_index
//   secops      _raw as received (Google's CISCO_MERAKI parser needs the native format);
//               __logType + optional __namespace for the Google SecOps destination
//   archive     canonical event, untouched, full fidelity (object store / Cribl Lake / replay)
//   structured  _raw = record JSON + `cim` object (Sentinel, Elastic, Dynatrace, OTel, ...)
// Route the copies with an Output Router keyed on __meraki_dest (see README).

// ---- flow summaries emitted by the Aggregations function ---------------------------
if (__e.meraki_agg_dest !== undefined && __e.__meraki === undefined) {
  const s = {
    summary_type: 'meraki_flow_summary',
    window_start: __e.first_seen,
    window_end: __e.last_seen,
    meraki_device: __e.meraki_agg_device,
    meraki_category: __e.meraki_agg_category,
    src_ip: __e.meraki_agg_src_ip,
    dest_ip: __e.meraki_agg_dest_ip,
    dest_port: __e.meraki_agg_dest_port,
    transport: __e.meraki_agg_transport,
    action: __e.meraki_agg_action,
    flow_count: __e.flow_count
  };
  const cim = {
    src_ip: s.src_ip || undefined, dest_ip: s.dest_ip || undefined, dest_port: s.dest_port || undefined,
    transport: s.transport || undefined, action: s.action || undefined, count: s.flow_count,
    dvc: s.meraki_device, vendor_product: 'Cisco Meraki', vendor: 'Cisco', product: 'Meraki', tag: ['network', 'communicate']
  };
  __e.__meraki_dest = __e.meraki_agg_dest;
  __e.__meraki = { kind: 'syslog_summary', tier: 'security', category: 'flowsummary', record: s, cim: cim };
  __e._time = typeof __e.first_seen === 'number' ? __e.first_seen : __e._time;
  __e.host = s.meraki_device;
  __e.sourcetype = 'meraki:syslog:flowsummary';
  __e.source = 'meraki:syslog:flowsummary';
  __e._raw = JSON.stringify(s);
  const ks = Object.keys(__e);
  for (let i = 0; i < ks.length; i++) {
    if (/^meraki_agg_/.test(ks[i]) || ks[i] === 'flow_count' || ks[i] === 'first_seen' || ks[i] === 'last_seen' || ks[i] === 'endtime' || ks[i] === 'starttime') delete __e[ks[i]];
  }
}

// ---- Suppress bookkeeping: never let it become an indexed field --------------------
if (__e.suppressCount !== undefined) {
  __e.__meraki_suppressed = __e.suppressCount;
  delete __e.suppressCount;
}

const dest = __e.__meraki_dest;
const mm = __e.__meraki || {};
const rec = __e.__meraki_record_out || mm.record;

if (dest === 'splunk') {
  if (__e.__cfg_index) __e.index = __e.__cfg_index;
} else if (dest === 'secops') {
  __e.__logType = __e.__cfg_secops_log_type || 'CISCO_MERAKI';
  if (__e.__cfg_secops_namespace) __e.__namespace = __e.__cfg_secops_namespace;
  delete __e.index;
} else if (dest === 'structured') {
  if (rec && typeof rec === 'object') {
    const out = {};
    const rk = Object.keys(rec);
    for (let i = 0; i < rk.length; i++) out[rk[i]] = rec[rk[i]];
    if (mm.cim) out.cim = mm.cim;
    if (__e.__meraki_suppressed !== undefined) out.meraki_suppressed_count = __e.__meraki_suppressed;
    __e._raw = JSON.stringify(out);
  }
  delete __e.index;
} else if (dest === 'archive') {
  // full fidelity: leave _raw and metadata exactly as parsed
}
