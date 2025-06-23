# Exifcopy

`exifcopy` is a command-line tool for transferring metadata (EXIF, XMP, IPTC) from one JPEG file to another.
It is primarily intended for use cases where image optimizers (e.g. Guetzli) discard metadata during compression.

## Features
- Preserves most known metadata fields from the source JPEG
- Minimal dependencies and clean command-line usage
- Windows support (with NTFS file time preservation)

## Usage
```bash
exifcopy <source.jpg> <target.jpg>
```

## License
This project is licensed under the **GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)**.

If you would like to use `exifcopy` under different licensing terms (e.g. for proprietary or commercial purposes),
please get in touch via the GitHub project page:

➡️ https://github.com/HBB-ThinkTank/exifcopy

Requests for dual-licensing or custom agreements are generally welcome.
