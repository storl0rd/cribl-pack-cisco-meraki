// tail / fan-out: decide which destination profiles get a copy of this event.
// A profile gets the event when it is enabled and its tier list contains the event's
// tier (security | operational | inventory, or *). The Unroll that follows creates one
// copy per profile, tagged __meraki_dest; an event no profile wants is dropped here.
const PROFILES = ['splunk', 'secops', 'archive', 'structured'];
const m = __e.__meraki || {};
const tier = m.tier || 'operational';
const cfg = __e.__cfg_dest || {};
const dests = [];
for (let i = 0; i < PROFILES.length; i++) {
  const p = cfg[PROFILES[i]];
  if (!p || String(p.enabled).toLowerCase() !== 'true') continue;
  const tiers = String(p.tiers || '').split(',').map(function (s) { return s.trim(); });
  if (tiers.indexOf('*') !== -1 || tiers.indexOf(tier) !== -1) dests.push(PROFILES[i]);
}
__e.__meraki_dests = dests;
