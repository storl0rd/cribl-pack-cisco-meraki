// meraki_webhook: Meraki Dashboard alert webhooks.
// Accepts both payload shapes seen in the field:
//   1. Meraki default template ("Meraki (included)")  -> flat JSON incl. sharedSecret
//   2. Splunk TA template (HEC envelope)               -> {"sourcetype":"meraki:webhook","event":{...}}
// The shared secret is validated (when meraki_webhook_shared_secret is set) and is
// ALWAYS stripped before the event leaves Cribl.
const original = __e._raw;
let j = null;
if (typeof original === 'string') {
  try { j = JSON.parse(original); } catch (err) { j = null; }
} else if (original && typeof original === 'object') {
  j = original;
}

if (!j || typeof j !== 'object' || Array.isArray(j)) {
  __e.sourcetype = 'meraki:webhook';
  __e.source = 'meraki:webhook';
  __e.__meraki = { kind: 'webhook', tier: 'security', parse_error: 'webhook body is not a JSON object' };
} else {
  let enveloped = false;
  if (j.event && typeof j.event === 'object' && j.alertType === undefined) { j = j.event; enveloped = true; }

  // ---- authentication ---------------------------------------------------------
  const expected = __e.__cfg_webhook_secret;
  if (expected) {
    if (j.sharedSecret === undefined) {
      // HEC-envelope deliveries are authenticated by the HEC token at the Source.
      if (!enveloped) __e.__meraki_drop = 'shared_secret_missing';
    } else if (String(j.sharedSecret) !== String(expected)) {
      __e.__meraki_drop = 'shared_secret_mismatch';
    }
  }
  delete j.sharedSecret;

  // ---- time / host --------------------------------------------------------------
  const ts = Date.parse(j.occurredAt || j.sentAt || '');
  if (!isNaN(ts)) __e._time = ts / 1000;
  const h = j.deviceName || j.deviceSerial || j.networkName;
  if (typeof h === 'string' && h.trim()) __e.host = h.trim().toLowerCase();
  __e.sourcetype = 'meraki:webhook';
  __e.source = 'meraki:webhook';

  // ---- CIM (TA FIELDALIAS: alertId->id, alertType->type, deviceMac->dest, alertLevel->severity)
  const c = {
    id: j.alertId,
    type: j.alertType,
    signature: j.alertType,
    dest: j.deviceMac ? String(j.deviceMac).toLowerCase() : undefined,
    dvc: j.deviceName || j.deviceSerial,
    severity: j.alertLevel,
    vendor_product: 'Cisco Meraki',
    vendor: 'Cisco',
    product: 'Meraki',
    tag: ['alert']
  };
  const keys = Object.keys(c);
  for (let i = 0; i < keys.length; i++) { if (c[keys[i]] === undefined || c[keys[i]] === null || c[keys[i]] === '') delete c[keys[i]]; }
  __e.__meraki = { kind: 'webhook', tier: 'security', alert_type: j.alertType, record: j, cim: c };
  __e._raw = JSON.stringify(j);
}
