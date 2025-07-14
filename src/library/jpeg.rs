use filetime::FileTime;
use std::collections::HashMap;
use std::fs::{File, metadata};
use std::io::{BufReader, Error, ErrorKind, Read};
use std::path::Path;

// PARSING THE SOURCE JPEG //

#[derive(Clone)]
pub struct JpegSegment {
    pub marker: u8,
    pub data: Vec<u8>,
    pub marker_name: String,
    #[allow(dead_code)]
    pub segment_type: String,
    #[allow(dead_code)]
    pub description: String,
    pub metadata_type: Option<String>,
}

pub struct ParsedJpeg {
    pub segments: Vec<JpegSegment>,
    pub scan_data: Vec<u8>,
    pub creation_time: Option<FileTime>,
    pub modification_time: Option<FileTime>,
}

pub struct MarkerInfo {
    pub name: &'static str,
    pub segment_type: &'static str,
    pub description: &'static str,
}

pub fn parse_jpeg_segments<P: AsRef<Path>>(
    path: P,
    include_scan_data: bool,
) -> std::io::Result<ParsedJpeg> {
    let file = File::open(&path)?;
    let mut reader = BufReader::new(file);
    let mut buf = Vec::new();

    let mut soi = [0; 2];
    reader.read_exact(&mut soi)?;

    if soi != [0xFF, 0xD8] {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Not a valid JPEG file (missing SOI marker)",
        ));
    }

    buf.extend_from_slice(&soi); // fügt 0xFF, 0xD8 an den Anfang von buf
    reader.read_to_end(&mut buf)?;

    let marker_map = build_marker_map();
    let mut segments = Vec::new();
    let mut scan_data = Vec::new();
    let mut i = 0;

    #[allow(unused_assignments)]
    let mut saw_sos = false;

    while i + 1 < buf.len() {
        if buf[i] == 0xFF {
            if buf[i + 1] == 0x00 {
                i += 2;
                continue;
            }
            if saw_sos {
                if i + 1 >= buf.len() {
                    break;
                }
                let marker_byte = buf[i + 1];
                if !(marker_byte == 0xD9
                    || marker_byte == 0xFE
                    || (0xE0..=0xEF).contains(&marker_byte))
                {
                    i += 1;
                    continue;
                }
            }
            let marker = buf[i + 1];
            if marker == 0xD8 || marker == 0xD9 {
                segments.push(JpegSegment {
                    marker,
                    data: Vec::new(),
                    marker_name: marker_map
                        .get(&marker)
                        .map(|m| m.name.to_string())
                        .unwrap_or("Unbekannt".into()),
                    segment_type: marker_map
                        .get(&marker)
                        .map(|m| m.segment_type.to_string())
                        .unwrap_or("Unbekannt".into()),
                    description: marker_map
                        .get(&marker)
                        .map(|m| m.description.to_string())
                        .unwrap_or("".into()),
                    metadata_type: None,
                });
                i += 2;
                continue;
            }
            i += 2;
            if i + 2 > buf.len() {
                break;
            }
            let length = ((buf[i] as usize) << 8) + (buf[i + 1] as usize);
            i += 2;
            if i + length - 2 > buf.len() {
                break;
            }
            let data = buf[i..i + length - 2].to_vec();

            let temp_segment = JpegSegment {
                marker,
                data: data.clone(),
                marker_name: marker_map
                    .get(&marker)
                    .map(|m| m.name.to_string())
                    .unwrap_or("Unbekannt".into()),
                segment_type: marker_map
                    .get(&marker)
                    .map(|m| m.segment_type.to_string())
                    .unwrap_or("Unbekannt".into()),
                description: marker_map
                    .get(&marker)
                    .map(|m| m.description.to_string())
                    .unwrap_or("".into()),
                metadata_type: identify_metadata_type(&JpegSegment {
                    marker,
                    data: data.clone(),
                    marker_name: "".into(),
                    segment_type: "".into(),
                    description: "".into(),
                    metadata_type: None,
                })
                .map(|s| s.to_string()),
            };

            if !saw_sos || temp_segment.metadata_type.is_some() {
                segments.push(temp_segment);
            }

            i += length - 2;

            if marker == 0xDA {
                if !saw_sos {
                    saw_sos = true;
                    if include_scan_data {
                        scan_data = buf[i..].to_vec();
                    }
                }
                continue;
            }
        } else {
            i += 1;
        }
    }

    // Dateisystem Zeitstempel anrufen
    let meta = metadata(path.as_ref()).ok();
    let (ctime, mtime) = meta
        .as_ref()
        .map(|m| {
            (
                FileTime::from_creation_time(m).unwrap_or_else(FileTime::now),
                FileTime::from_last_modification_time(m),
            )
        })
        .unwrap_or_else(|| (FileTime::now(), FileTime::now()));

    Ok(ParsedJpeg {
        segments,
        scan_data,
        creation_time: Some(ctime),
        modification_time: Some(mtime),
    })
}

pub fn parse_jpeg_segments_default<P: AsRef<Path>>(path: P) -> std::io::Result<ParsedJpeg> {
    parse_jpeg_segments(path, true)
}

pub fn build_marker_map() -> HashMap<u8, MarkerInfo> {
    let mut markers = HashMap::new();
    markers.insert(
        0xD8,
        MarkerInfo {
            name: "SOI",
            segment_type: "Start",
            description: "Start of Image",
        },
    );
    markers.insert(
        0xD9,
        MarkerInfo {
            name: "EOI",
            segment_type: "End",
            description: "End of Image",
        },
    );
    markers.insert(
        0xDA,
        MarkerInfo {
            name: "SOS",
            segment_type: "Scan",
            description: "Start of Scan",
        },
    );
    markers.insert(
        0xC0,
        MarkerInfo {
            name: "SOF0",
            segment_type: "Frame",
            description: "Baseline DCT",
        },
    );
    markers.insert(
        0xC1,
        MarkerInfo {
            name: "SOF1",
            segment_type: "Frame",
            description: "Extended Sequential DCT",
        },
    );
    markers.insert(
        0xC2,
        MarkerInfo {
            name: "SOF2",
            segment_type: "Frame",
            description: "Progressive DCT",
        },
    );
    markers.insert(
        0xC3,
        MarkerInfo {
            name: "SOF3",
            segment_type: "Frame",
            description: "Lossless (sequential)",
        },
    );
    markers.insert(
        0xC4,
        MarkerInfo {
            name: "DHT",
            segment_type: "Table",
            description: "Huffman Table",
        },
    );
    markers.insert(
        0xC5,
        MarkerInfo {
            name: "SOF5",
            segment_type: "Frame",
            description: "Differential Sequential",
        },
    );
    markers.insert(
        0xC6,
        MarkerInfo {
            name: "SOF6",
            segment_type: "Frame",
            description: "Differential Progressive",
        },
    );
    markers.insert(
        0xC7,
        MarkerInfo {
            name: "SOF7",
            segment_type: "Frame",
            description: "Differential Lossless",
        },
    );
    markers.insert(
        0xC8,
        MarkerInfo {
            name: "SOF8",
            segment_type: "Frame",
            description: "Reserved (JPEG Extension)",
        },
    );
    markers.insert(
        0xC9,
        MarkerInfo {
            name: "SOF9",
            segment_type: "Frame",
            description: "Extended Sequential DCT, Differential",
        },
    );
    markers.insert(
        0xCA,
        MarkerInfo {
            name: "SOF10",
            segment_type: "Frame",
            description: "Progressive DCT, Differential",
        },
    );
    markers.insert(
        0xCB,
        MarkerInfo {
            name: "SOF11",
            segment_type: "Frame",
            description: "Lossless (Sequential), Differential",
        },
    );
    markers.insert(
        0xCC,
        MarkerInfo {
            name: "SOF12",
            segment_type: "Frame",
            description: "JPEG-LS",
        },
    );
    markers.insert(
        0xCD,
        MarkerInfo {
            name: "SOF13",
            segment_type: "Frame",
            description: "Reserved (JPEG Extension)",
        },
    );
    markers.insert(
        0xCE,
        MarkerInfo {
            name: "SOF14",
            segment_type: "Frame",
            description: "Reserved (JPEG Extension)",
        },
    );
    markers.insert(
        0xCF,
        MarkerInfo {
            name: "SOF15",
            segment_type: "Frame",
            description: "Reserved (JPEG Extension)",
        },
    );
    markers.insert(
        0xDB,
        MarkerInfo {
            name: "DQT",
            segment_type: "Table",
            description: "Quantization Table",
        },
    );
    markers.insert(
        0xDD,
        MarkerInfo {
            name: "DRI",
            segment_type: "Restart",
            description: "Restart Interval",
        },
    );
    markers.insert(
        0xFE,
        MarkerInfo {
            name: "COM",
            segment_type: "Comment",
            description: "Comment",
        },
    );
    for i in 0xE0..=0xEF {
        markers.insert(
            i,
            MarkerInfo {
                name: Box::leak(format!("APP{}", i - 0xE0).into_boxed_str()),
                segment_type: "APP",
                description: "Application Segment",
            },
        );
    }
    markers
}

/// Identifies the type of metadata contained in a given JPEG segment.
///
/// This function inspects the beginning of the segment's binary data
/// and returns a short identifier for known metadata formats.
///
/// # Supported Identifiers
/// - `"EXIF"` – Exchangeable Image File Format
/// - `"XMP"` – Adobe's Extensible Metadata Platform
/// - `"ICC"` – ICC colour profiles
/// - `"IPTC"` – IPTC metadata inside Photoshop IRB (Image Resource Blocks)
/// - `"IRB"` – Photoshop IRB container without IPTC
/// - `"Adobe"`, `"JFIF"`, `"JFXX"`, `"MPF"`, `"CIFF"`, `"FLIR"`, `"GDepth"`, `"MetaInfo"`
///
/// # Parameters
/// * `segment` – Reference to the JPEG segment to inspect
///
/// # Returns
/// * `Some("...")` if the type could be identified
/// * `None` if no known pattern was matched
pub fn identify_metadata_type(segment: &JpegSegment) -> Option<&'static str> {
    if segment.data.len() < 12 {
        return None;
    }

    let d = &segment.data;

    // Photoshop-specific logic: may contain IPTC or generic IRB
    if d.starts_with(b"Photoshop 3.0\0") {
        if d.len() > 18 && d[14..].starts_with(b"8BIM") {
            return Some("IPTC");
        } else {
            return Some("IRB");
        }
    }

    // Match against known metadata segment headers
    match d {
        d if d.starts_with(b"Exif\0\0") => Some("EXIF"),
        d if d.starts_with(b"http://ns.adobe.com/xap/1.0/") => Some("XMP"),
        d if d.starts_with(b"ICC_PROFILE\0") => Some("ICC"),
        d if d.starts_with(b"Adobe") => Some("Adobe"),
        d if d.starts_with(b"JFIF\0") => Some("JFIF"),
        d if d.starts_with(b"JFXX\0") => Some("JFXX"),
        d if d.starts_with(b"MPF\0") => Some("MPF"),
        d if d.starts_with(b"CIFF") => Some("CIFF"),
        d if d.starts_with(b"FLIR") => Some("FLIR"),
        d if d.starts_with(b"GDepth") => Some("GDepth"),
        d if d.starts_with(b"MetaInfo") => Some("MetaInfo"),
        _ => None,
    }
}
