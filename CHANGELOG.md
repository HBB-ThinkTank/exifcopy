# Changelog

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](https://semver.org/).

---
## [0.9.2] – 2025-07-06
### Changed
- Added XMP, EXIF and IPTC parsers for creation and modification times; all parsing is handled internally.
- Enhanced debug output: creation and modification times are now also displayed in human-readable `YYYY.MM.DDTHH:MM:SS` format.
- Prepared project for public release: revised project metadata and licensing files (`README.md`, `LICENSE`).

### Fixed
- Eliminated compiler warnings caused by deprecated methods in the `chrono` crate.

---

## [0.9.1] – 2025-06-29
### Changed
- Significantly improved JPEG segment parser in `parse_jpeg_segments()`:
  - SOI (Start of Image), SOS (Start of Scan), and EOI (End of Image) are now correctly identified and preserved as segments.
  - APP and COM segments located after the SOS marker are no longer skipped, improving compatibility with non-standard JPEG files.
- Replaced plain strings with `PathBuf` for file operations (in configuration and function arguments).

### Fixed
- Resolved infinite loop triggered by faulty JPEG marker handling at the beginning of certain files.

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
