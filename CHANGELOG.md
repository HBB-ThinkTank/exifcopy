# Changelog

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](https://semver.org/).

---
## [0.9.1] – 2025-06-29
### Changed
- Deutlich verbesserte JPEG-Parserlogik in `parse_jpeg_segments()`:
  - SOI (Start of Image), SOS (Start of Scan) und EOI (End of Image) werden nun korrekt erkannt und als Segmente gespeichert.
  - APP- und COM-Segmente nach SOS werden nicht mehr übersprungen, sondern verarbeitet – dies verbessert die Kompatibilität mit nicht standardkonformen JPEG-Dateien.
- Verwendung von `PathBuf` anstelle einfacher Strings für Dateioperationen (Konfig- und Funktionsargumente).

### Fixed
- Endlosschleife bei fehlerhaftem JPEG-Marker-Handling zu Beginn der Datei wurde behoben.


---

## [0.9.0] – 2025-06-23
### Added
- Initial metadata transfer functionality (EXIF, XMP, IPTC)
- File time preservation for NTFS (Windows only)
- JPEG format validation (SOI marker check)
- Basic CLI interface with error handling

### Notes
- This is a functional MVP release.
- Source and target JPEG files must exist and be valid.
- Requires Rust 2021+ and Windows APIs.

---

## [Unreleased]
- Improved error diagnostics
- Verbose/debug mode
- Extended format support (e.g. JPEG2000?)
- Cross-platform file time preservation
