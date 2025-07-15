# Changelog

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](https://semver.org/).

---

## [Unreleased] - 2025-07-15

- Improved error handling in `parse_jpeg_segments()`: now validates input file path and returns descriptive errors if the file is missing or unreadable.

## [Unreleased] - 2025-07-08

### Internal Changes
- Refactored module structure: split into `library`, `shared`, and local `config`
- Preparing library usage
- Removed unused static `CONFIG`
- Eliminated dead code (`get_log_mode`, unused `pub use`)
- Replaced unnecessary `.clone()` and `&` references (Clippy suggestions)
- Confirmed clean state with `cargo fmt` and `cargo clippy`

## [0.9.3] – 2025-07-06

### Changed
- Full implementation of `--keepdate=3`: extracts timestamps from EXIF, XMP, and IPTC metadata when available (#1)
- Refactored codebase into fully modular structure:
  - Separated modules for `config`, `jpeg`, `write`, `log`, and `lib.rs`
- Improved debug output and CLI option parsing
- Enhanced `print_help()` to display version, build date, authors, license and repository link
- Updated `README.md` to reflect the current project structure, purpose and usage

### Added
- Automatic build date and year injection via `build.rs`
- `BUILD_DATE` and `BUILD_YEAR` now displayed dynamically during `--help`
- New reusable config structure with global `CONFIG` (via `once_cell::Lazy`)

### Fixed
- Resolved all `clippy` warnings (e.g. regex in loop, collapsible if, needless borrow)

---

## [0.9.2] – 2025-07-06
### Changed
- Added XMP, EXIF and IPTC parsers for creation and modification times to allow setting file timestamps; all parsing is handled internally.
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
