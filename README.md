# Exifcopy

**Exifcopy** is a cross-platform command-line tool and Rust library for copying JPEG metadata with precision and integrity.\
It preserves EXIF, XMP, IPTC and other embedded segments 1:1 from a source file to a target file — including multiple segments of the same type.

Originally developed to restore metadata after lossy image compression, Exifcopy is now a robust utility for workflows requiring exact metadata preservation.

## Features

- Copies all recognised metadata types (EXIF, XMP, IPTC, ICC, etc.)
- Handles multiple segments of the same type (e.g. multiple APP1/XMP)
- Clean, modular architecture — usable as CLI or as Rust library
- Optional preservation of filesystem timestamps (CreateDate, ModifyDate)
- Special support for NTFS creation timestamps (Windows only)

## Usage

```bash
exifcopy [options] <source.jpg> <target.jpg>
```

To view all available options, run:

```bash
exifcopy --help
```

The help screen includes version, build date, license, author and repository information.

### Options

- `--help` / `-h`\
  Show help screen with usage and all available parameters

- `--log` / `-l`\
  Enable debug logging for verbose output (writes a `.log` file)

- `--keepdate=<n>` / `-kd <n>`\
  Preserve filesystem timestamps:

| Value | Behaviour                         |
|-------|------------------------------------|
| 0     | No change                          |
| 1     | Copy from target file (default)    |
| 2     | Copy from source file              |
| 3     | Extract from metadata if available |

## Build & Development

Exifcopy uses a `build.rs` script to embed the current UTC build date and year into the binary.\
These values are automatically shown in the `--help` screen to track builds precisely.

The codebase is fully modular and can be reused as a library in other Rust tools.\
To include Exifcopy as a local dependency:

```toml
[dependencies]
exifcopy = { path = "../exifcopy" }
```

## License

This project is licensed under the **GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)**.

If you would like to use `exifcopy` under different licensing terms (e.g. for proprietary or commercial purposes),\
please get in touch via the GitHub project page:

🫠 [https://github.com/HBB-ThinkTank/exifcopy](https://github.com/HBB-ThinkTank/exifcopy)

Requests for dual-licensing or custom agreements are generally welcome.

