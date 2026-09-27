## Browser Gamma Fix v0.7.2 — Edge 154.0.4258.37 support

This maintenance release adds support for Microsoft Edge `154.0.4258.37`.

### What changed

- Edge 154 moved the SDR/WCG/HDR output loop into a compact cold function
  fragment, so the earlier structured and semantic loop analyzers intentionally
  rejected it.
- v0.7.2 adds a fail-closed verifier for this layout. It requires one exact HDR
  output helper, exactly two nearby calls to it (planes 0 and 1), the shared
  indexed `01 02 00` usage table, the table byte flowing into both calls, and
  the original `cmp index, 2` loop limit.
- The verifier rejects zero, multiple or incomplete candidates. Existing gamma
  initializer, constant-block, singleton-store and helper checks remain active.

### Validation

- All 49 automated tests pass.
- Read-only analysis of Edge `154.0.4258.37` produced a complete plan with 98
  GPU gamma writes and two browser output writes.
- The author confirmed the live runtime correction. The on-disk `msedge.dll`
  SHA-256 remained `E14B3D725FEF3EB23EF28D01D6D5707BCB6FFC3AE59CE2E42997AC72BF0674F0`.

Native HDR, PQ/HLG and Display-P3 paths are unchanged. Browser files on disk
are never modified. Browser Gamma Fix remains free, MIT-licensed and open source.

### Upgrade

Download `BrowserGammaFix-win64.zip`, extract the complete package and run
`Gamma22Tray.exe` beside `_internal`. Do not run as administrator.
