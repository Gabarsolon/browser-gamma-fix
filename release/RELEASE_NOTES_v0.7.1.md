## Browser Gamma Fix v0.7.1 — Edge 153.0.4234.48 support

This maintenance release adds support for Microsoft Edge `153.0.4234.48`.

### What changed

- Edge `153.0.4234.48` has 99 strict sRGB singleton constructors, compared
  with the 97 and 98 counts recognized previously.
- v0.7.1 accepts 99 only with the existing complete structural validation:
  exactly one contiguous BT.709/sRGB/gamma 2.2 constant block, one common
  factory/pointer tuple, every load of the sRGB constant, every store to its
  singleton, and one verified SDR/WCG/HDR output path.
- Unknown counts, partial layouts and ambiguous output paths remain rejected.

### Validation

- All 49 automated tests pass, including an explicit 99-initializer fixture;
  unverified count 100 remains rejected.
- Read-only analysis of the original Edge `153.0.4234.48` DLL produced a
  complete plan with 99 GPU gamma writes and two browser output writes.
- The author confirmed the live runtime correction. The DLL SHA-256 remained
  `603DD1CA73B8F6DC0D61C5160F665784990BB26458F2819F53D08CA2BB69F582`.

Native HDR, PQ/HLG and Display-P3 paths are unchanged. Browser files on disk
are never modified. This project remains free, MIT-licensed and open source.

### Upgrade

Download `BrowserGammaFix-win64.zip`, extract the complete package and run
`Gamma22Tray.exe` beside `_internal`. Existing v0.7.0 installations can use
the in-app update option when it becomes available; manual replacement also
works. Do not run as administrator.
