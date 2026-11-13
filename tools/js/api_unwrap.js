// meraki_api / step 1: turn one API response page into an array of records.
// The REST collectors emit one event per HTTP page (breaker: meraki_json_document).
// Meraki returns three page shapes; all are normalised here so the collectors
// never depend on a per-endpoint "data field" being right:
//   [ {...}, {...} ]                      -> top-level array (most org endpoints)
//   { items: [...], meta: {...} }         -> newer byDevice / wirelessController endpoints
//   { message, pageStartAt, events: [] }  -> /networks/{id}/events
//   { ... }                               -> single-object overview endpoints
// The array is written back to _raw so the Unroll function that follows creates
// one event per record without copying the full page into every record.
let page = null;
if (typeof __e._raw === 'string') {
  try { page = JSON.parse(__e._raw); } catch (err) { page = undefined; }
} else {
  page = __e._raw;
}
if (page === undefined) {
  __e.__meraki_parse_error = 'API page is not valid JSON';
  __e._raw = [__e._raw];
} else if (Array.isArray(page)) {
  __e._raw = page;
} else if (page && typeof page === 'object' && Array.isArray(page.items)) {
  __e.__meraki_page_meta = page.meta;
  __e._raw = page.items;
} else if (page && typeof page === 'object' && Array.isArray(page.events)) {
  __e.__meraki_page_meta = { pageStartAt: page.pageStartAt, pageEndAt: page.pageEndAt };
  __e._raw = page.events;
} else {
  __e._raw = [page];
}
