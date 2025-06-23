# Changelog

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](https://semver.org/).

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
