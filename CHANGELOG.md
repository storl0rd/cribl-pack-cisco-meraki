# Changelog

## 2.0.0
- **Breaking:** removed `meraki_output_mode`. Use the destination profiles instead: `splunk` replaces
  `raw`, and `structured` replaces `structured`.
- Each event is parsed once and fanned out to `splunk`, `secops` (Google SecOps: `__logType`
  `CISCO_MERAKI`, `__namespace`), `archive` (never reduced) and `structured` profiles, with
  per-profile tier filters (`security`, `operational`, `inventory`).
- Per-profile opt-in reductions: `strip_nulls`, `inventory_changes_only`, `dedupe_airmarshal`,
  `dedupe_urls`, `drop_ip_flow_start`, `drop_wireless_assoc`, `drop_known_good_flows`, `flow_summary`.
- `meraki_index` now applies to the splunk profile only.
- CIM is always computed into the internal `__meraki.cim` field.

## 1.0.0
- Initial release: 42 REST collectors (Splunk TA 3.5.0 parity), webhook and syslog sources,
  TA-compatible sourcetypes, CIM enrichment.
