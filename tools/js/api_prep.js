// meraki_api / step 2: parse one record and expose the lookup keys.
let rec = __e._raw;
if (typeof rec === 'string') {
  try { rec = JSON.parse(rec); } catch (err) { __e.__meraki_parse_error = 'record is not valid JSON'; rec = { value: rec }; }
}
if (rec === null || typeof rec !== 'object' || Array.isArray(rec)) {
  rec = { value: rec };
}
__e.__json = rec;

// Network event logs: sourcetype -> Meraki productType (TA SOURCETYPE_PRODUCT_TYPE_MAPPING)
const PRODUCT = {
  'meraki:accesspoints': 'wireless',
  'meraki:securityappliances': 'appliance',
  'meraki:switches': 'switch',
  'meraki:cameras': 'camera'
};
__e.__meraki_product = PRODUCT[__e.sourcetype];
__e.__meraki_event_type = __e.__meraki_product && rec.type !== undefined ? String(rec.type) : undefined;
__e.__meraki_priority = rec.priority !== undefined && rec.priority !== null ? String(rec.priority) : undefined;
