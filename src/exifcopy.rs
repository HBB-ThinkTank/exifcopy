// Neue Version mit eingebundener MarkerInfo-Map und Signaturerkennung Stand 2025-06-20 22:09:58.867 UTC

use std::clone::Clone;
use std::collections::HashMap;
use std::env;
use std::fs::{File, metadata, OpenOptions};
use std::io::{Read, Write, BufReader, Error, ErrorKind};
use std::path::{Path};
use std::sync::Mutex;
use filetime::{FileTime, set_file_mtime};
use once_cell::sync::Lazy;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Foundation::FILETIME;
use windows::Win32::Storage::FileSystem::{SetFileTime, CreateFileW, FILE_WRITE_ATTRIBUTES, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL};
use windows::Win32::Storage::FileSystem::{FILE_SHARE_READ};
use windows::Win32::Foundation::CloseHandle;
use windows::core::PCWSTR;


#[derive(Debug, Clone)]
struct Config {
    keep_date_mode: u8,
    debug: bool,
    source_path: String,
    target_path: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            keep_date_mode: 1,
            debug: false,
            source_path: String::new(),
            target_path: String::new(),
        }
    }
}

static CONFIG: Lazy<Mutex<Config>> = Lazy::new(|| {
    Mutex::new(Config::default())
});

struct ArgumentDefinition {
    name: &'static str,
    alias: &'static str,
    takes_value: bool,
    description: &'static str,
}

const ARG_DEFINITIONS: &[ArgumentDefinition] = &[
    ArgumentDefinition {
        name: "--debug",
        alias: "-d",
        takes_value: false,
        description: "Enable debug output",
    },
    ArgumentDefinition {
        name: "--help",
        alias: "-h",
        takes_value: false,
        description: "Show help information",
    },
    ArgumentDefinition {
        name: "--keepdate",
        alias: "-kd",
        takes_value: true,
        description: "Preserve file timestamps: 0 = none, 1 = target (default), 2 = source, 3 = metadata/source",
    },
];

fn parse_arguments() -> Result<Config, String> {
    let args: Vec<String> = env::args().collect();
    let mut config = Config::default();
    let mut positional_args: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];

        if let Some(def) = ARG_DEFINITIONS.iter().find(|d| d.name == arg || d.alias == arg) {
            if def.name == "--help" {
                print_help();
                std::process::exit(0);
            }

            if def.name == "--debug" {
                config.debug = true;
            }

            if def.name == "--keepdate" {
                if i + 1 >= args.len() {
                    return Err("Missing value for --keepdate".into());
                }
                i += 1;
                config.keep_date_mode = args[i].parse::<u8>().map_err(|_| "Invalid value for --keepdate (expected 0, 1, 2, 3)".to_string())?;
                if config.keep_date_mode > 3 {
                    return Err("Invalid value for --keepdate (expected 0, 1, 2, 3)".to_string());
                }
            }

            if def.takes_value {
                i += 1; // Skip next as it's the value
            }
        } else if arg.starts_with("-") {
            return Err(format!("Unknown option: {}", arg));
        } else {
            positional_args.push(arg.clone());
        }

        i += 1;
    }

    if positional_args.len() < 2 {
        return Err("Missing required <source.jpg> and <target.jpg> arguments".to_string());
    }

	config.source_path = positional_args[positional_args.len() - 2].clone();
	config.target_path = positional_args[positional_args.len() - 1].clone();

    *CONFIG.lock().unwrap() = config.clone();

    Ok(config)
}

fn print_help() {
    println!("Usage: exifcopy [options] <source.jpg> <target.jpg>\n");
    println!("Options:");
    for def in ARG_DEFINITIONS {
        println!("  {:<10} {:<4}  {}", def.name, def.alias, def.description);
    }
}

struct MarkerInfo {
    name: &'static str,
    segment_type: &'static str,
    description: &'static str,
}

struct JpegSegment {
    marker: u8,
    data: Vec<u8>,
    marker_name: String,
	#[allow(dead_code)]
    segment_type: String,
	#[allow(dead_code)]
    description: String,
    metadata_type: Option<String>,
}

struct ParsedJpeg {
    segments: Vec<JpegSegment>,
    scan_data: Vec<u8>,
    creation_time: Option<FileTime>,
    modification_time: Option<FileTime>,
}

fn build_marker_map() -> HashMap<u8, MarkerInfo> {
    let mut markers = HashMap::new();
    markers.insert(0xD8, MarkerInfo { name: "SOI", segment_type: "Start", description: "Start of Image" });
    markers.insert(0xD9, MarkerInfo { name: "EOI", segment_type: "End", description: "End of Image" });
    markers.insert(0xDA, MarkerInfo { name: "SOS", segment_type: "Scan", description: "Start of Scan" });
    markers.insert(0xC0, MarkerInfo { name: "SOF0", segment_type: "Frame", description: "Baseline DCT" });
    markers.insert(0xC1, MarkerInfo { name: "SOF1", segment_type: "Frame", description: "Extended Sequential DCT" });
    markers.insert(0xC2, MarkerInfo { name: "SOF2", segment_type: "Frame", description: "Progressive DCT" });
    markers.insert(0xC3, MarkerInfo { name: "SOF3", segment_type: "Frame", description: "Lossless (sequential)" });
    markers.insert(0xC4, MarkerInfo { name: "DHT", segment_type: "Table", description: "Huffman Table" });
    markers.insert(0xC5, MarkerInfo { name: "SOF5", segment_type: "Frame", description: "Differential Sequential" });
    markers.insert(0xC6, MarkerInfo { name: "SOF6", segment_type: "Frame", description: "Differential Progressive" });
    markers.insert(0xC7, MarkerInfo { name: "SOF7", segment_type: "Frame", description: "Differential Lossless" });
    markers.insert(0xC8, MarkerInfo { name: "SOF8", segment_type: "Frame", description: "Reserved (JPEG Extension)" });
    markers.insert(0xC9, MarkerInfo { name: "SOF9", segment_type: "Frame", description: "Extended Sequential DCT, Differential" });
    markers.insert(0xCA, MarkerInfo { name: "SOF10", segment_type: "Frame", description: "Progressive DCT, Differential" });
    markers.insert(0xCB, MarkerInfo { name: "SOF11", segment_type: "Frame", description: "Lossless (Sequential), Differential" });
    markers.insert(0xCC, MarkerInfo { name: "SOF12", segment_type: "Frame", description: "JPEG-LS" });
    markers.insert(0xCD, MarkerInfo { name: "SOF13", segment_type: "Frame", description: "Reserved (JPEG Extension)" });
    markers.insert(0xCE, MarkerInfo { name: "SOF14", segment_type: "Frame", description: "Reserved (JPEG Extension)" });
    markers.insert(0xCF, MarkerInfo { name: "SOF15", segment_type: "Frame", description: "Reserved (JPEG Extension)" });
    markers.insert(0xDB, MarkerInfo { name: "DQT", segment_type: "Table", description: "Quantization Table" });
    markers.insert(0xDD, MarkerInfo { name: "DRI", segment_type: "Restart", description: "Restart Interval" });
    markers.insert(0xFE, MarkerInfo { name: "COM", segment_type: "Comment", description: "Comment" });
    for i in 0xE0..=0xEF {
        markers.insert(i, MarkerInfo { name: Box::leak(format!("APP{}", i - 0xE0).into_boxed_str()), segment_type: "APP", description: "Application Segment" });
    }
    markers
}

fn identify_metadata_type(segment: &JpegSegment) -> Option<&'static str> {
    if segment.data.len() < 12 {
        return None;
    }
    match &segment.data[..] {
        d if d.starts_with(b"Exif\0\0") => Some("EXIF"),
        d if d.starts_with(b"http://ns.adobe.com/xap/1.0/") => Some("XMP"),
        d if d.starts_with(b"ICC_PROFILE\0") => Some("ICC"),
        d if d.starts_with(b"Photoshop 3.0\0") && d[13..].starts_with(b"8BIM") => Some("IPTC"),
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

fn parse_jpeg_segments<P: AsRef<Path>>(path: P, include_scan_data: bool) -> std::io::Result<ParsedJpeg> {
    let file = File::open(&path)?;
    let mut reader = BufReader::new(file);
    let mut buf = Vec::new();

    let mut soi = [0; 2];
    reader.read_exact(&mut soi)?;

    if soi != [0xFF, 0xD8] {
        return Err(Error::new(ErrorKind::InvalidData, "Not a valid JPEG file (missing SOI marker)"));
    }
	
    reader.read_to_end(&mut buf)?;

    let meta = metadata(path.as_ref()).ok();
    let (ctime, mtime) = meta
        .as_ref()
        .map(|m| (
            FileTime::from_creation_time(m).unwrap_or_else(FileTime::now),
            FileTime::from_last_modification_time(m),
        ))
        .unwrap_or_else(|| (FileTime::now(), FileTime::now()));

    let marker_map = build_marker_map();
    let mut segments = Vec::new();
    let mut scan_data = Vec::new();
    let mut i = 0;
	
	#[allow(unused_assignments)]
    let mut saw_sos = false;
	
    while i + 3 < buf.len() {
        if buf[i] == 0xFF {
            if buf[i + 1] == 0x00 {
                i += 2;
                continue;
            }
            let marker = buf[i + 1];
            i += 2;
            if marker == 0xD8 || marker == 0xD9 {
                segments.push(JpegSegment {
                    marker,
                    data: Vec::new(),
                    marker_name: marker_map.get(&marker).map(|m| m.name.to_string()).unwrap_or("Unbekannt".into()),
                    segment_type: marker_map.get(&marker).map(|m| m.segment_type.to_string()).unwrap_or("Unbekannt".into()),
                    description: marker_map.get(&marker).map(|m| m.description.to_string()).unwrap_or("".into()),
                    metadata_type: None,
                });
                continue;
            }
            if i + 2 > buf.len() { break; }
            let length = ((buf[i] as usize) << 8) + (buf[i + 1] as usize);
            i += 2;
            if i + length - 2 > buf.len() { break; }
            let data = buf[i..i + length - 2].to_vec();

            let temp_segment = JpegSegment {
                marker,
                data: data.clone(),
                marker_name: marker_map.get(&marker).map(|m| m.name.to_string()).unwrap_or("Unbekannt".into()),
                segment_type: marker_map.get(&marker).map(|m| m.segment_type.to_string()).unwrap_or("Unbekannt".into()),
                description: marker_map.get(&marker).map(|m| m.description.to_string()).unwrap_or("".into()),
                metadata_type: identify_metadata_type(&JpegSegment { marker, data: data.clone(), marker_name: "".into(), segment_type: "".into(), description: "".into(), metadata_type: None }).map(|s| s.to_string()),
            };

            if !saw_sos || temp_segment.metadata_type.is_some() {
                segments.push(temp_segment);
            }

            i += length - 2;

            if marker == 0xDA {
                saw_sos = true;
                if include_scan_data {
                    scan_data = buf[i..].to_vec();
                }
                break;
            }
        } else {
            i += 1;
        }
    }
    Ok(ParsedJpeg {
        segments,
        scan_data,
        creation_time: Some(ctime),
        modification_time: Some(mtime),
    })
}

fn parse_jpeg_segments_default<P: AsRef<Path>>(path: P) -> std::io::Result<ParsedJpeg> {
    parse_jpeg_segments(path, true)
}

fn write_log(path: &Path, content: &str) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{}", content)?;
    Ok(())
}

fn log_parsed_segments(target_path: &Path, source: &ParsedJpeg) -> std::io::Result<()> {
    let mut log_path = target_path.to_path_buf();
    log_path.set_extension("log");

    let mut log_output = String::new();
    log_output.push_str("Marker  | Name     | Beschreibung                         | Länge\n");
    log_output.push_str("--------|----------|--------------------------------------|------\n");

    for segment in &source.segments {
        if let Some(info) = build_marker_map().get(&segment.marker) {
            log_output.push_str(&format!(
                "0xFF{:02X} | {:<8} | {:<36} | {}\n",
                segment.marker,
                info.name,
                info.description,
                segment.data.len()
            ));
        } else {
            log_output.push_str(&format!(
                "0xFF{:02X} | {:<8} | {:<36} | {}\n",
                segment.marker,
                "UNKNOWN",
                "Unbekanntes Segment",
                segment.data.len()
            ));
        }
    }

    write_log(&log_path, &log_output)
}

trait WindowsFileTime {
    fn as_windows_file_time(&self) -> u64;
}

impl WindowsFileTime for FileTime {
    fn as_windows_file_time(&self) -> u64 {
        self.unix_seconds() as u64 * 10_000_000 + self.nanoseconds() as u64 / 100 + 116444736000000000
    }
}

fn set_creation_time_windows(path: &Path, ctime: FileTime) {
    use std::os::windows::ffi::OsStrExt;
    use std::ffi::OsStr;

    let wide_path: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(Some(0))
        .collect();

    unsafe {
        match CreateFileW(
            PCWSTR(wide_path.as_ptr()),
            FILE_WRITE_ATTRIBUTES.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE(0),
        ) {
            Ok(handle) if handle.0 != -1 => {
                let windows_ticks = ctime.as_windows_file_time();
                let ft = FILETIME {
                    dwLowDateTime: windows_ticks as u32,
                    dwHighDateTime: (windows_ticks >> 32) as u32,
                };
                let result = SetFileTime(handle, Some(&ft), None, None);
                match result {
                    Ok(_) => println!("✅ SetFileTime erfolgreich"),
                    Err(_) => println!("❌ SetFileTime fehlgeschlagen"),
                }
                let _ = CloseHandle(handle);
            }
            Ok(_) => {
                eprintln!("⚠️ CreateFileW lieferte ungültigen Handle für Pfad: {:?}", path);
            }
            Err(e) => {
                eprintln!("⚠️ Fehler beim Setzen von CreationTime: {e}");
            }
        }
    }
}

fn restore_file_times(target_path: &Path, target_meta: &ParsedJpeg, source_meta: &ParsedJpeg) {
	let mode = {
		let config = CONFIG.lock().unwrap();
		config.keep_date_mode
	};

    if mode == 0 { return; }

    let (ctime, mtime) = match mode {
        // FileCreate, FileModify, FileAccess werden von der Zieldatei vor dem Bearbeiten übernommen
        1 => (
            target_meta.creation_time.unwrap_or_else(FileTime::now),
            target_meta.modification_time.unwrap_or_else(FileTime::now),
        ),
        // FileCreate, FileModify, FileAccess werden von der Quelldatei übernommen
        2 => (
            source_meta.creation_time.unwrap_or_else(FileTime::now),
            source_meta.modification_time.unwrap_or_else(FileTime::now),
        ),
        // FileCreate, FileModify kommen aus den Metadaten (EXIF/XMP/IPTC etc.) - aber noch nicht umgesetzt
        3 => (
            source_meta.creation_time.unwrap_or_else(FileTime::now),
            source_meta.modification_time.unwrap_or_else(FileTime::now),
        ),
        _ => return,
    };

    let _ = set_file_mtime(target_path, mtime);
    #[cfg(target_family = "windows")]
    set_creation_time_windows(target_path, ctime);
}

fn inject_metadata_segments<P: AsRef<Path>>(target_path: P, source: &ParsedJpeg) -> std::io::Result<()> {
	let debug_mode = {
		let config = CONFIG.lock().unwrap();
		config.debug
	};
    let parsed_target = parse_jpeg_segments_default(&target_path)?;

	let target_path_ref = target_path.as_ref();
	let mut output = OpenOptions::new().write(true).truncate(true).create(true).open(target_path_ref)?;

	if debug_mode {
		log_parsed_segments(target_path_ref, &source)?;
		log_parsed_segments(target_path_ref, &parsed_target)?;
	}

    // Schreibe SOI Marker
    output.write_all(&[0xFF, 0xD8])?;

    // Schreibe alle APP- und COM-Segmente aus der Quelldatei und nur diese
    for segment in &source.segments {
        if segment.marker_name.starts_with("APP") || segment.marker_name == "COM" {
            let len = segment.data.len() + 2;
            output.write_all(&[0xFF, segment.marker])?;
            output.write_all(&(len as u16).to_be_bytes())?;
            output.write_all(&segment.data)?;
        }
    }

    // Schreibe alle Segmente aus der Zieldatei, aber nicht APP/COM/SOI/SOS/EOI
    for segment in &parsed_target.segments {
        if segment.marker_name.starts_with("APP") || segment.marker_name == "COM" || segment.marker_name == "SOI" || segment.marker_name == "SOS" || segment.marker_name == "EOI" {
            continue;
        }
        let len = segment.data.len() + 2;
        output.write_all(&[0xFF, segment.marker])?;
        output.write_all(&(len as u16).to_be_bytes())?;
        output.write_all(&segment.data)?;
    }

    for segment in &parsed_target.segments {
        if segment.marker_name == "SOS" {
            let len = segment.data.len() + 2;
            output.write_all(&[0xFF, segment.marker])?;
            output.write_all(&(len as u16).to_be_bytes())?;
            output.write_all(&segment.data)?;
        }
    }
  
  // Schreibe den Scan-Daten-Marker (SOS)
    output.write_all(&parsed_target.scan_data)?;

    // Falls kein End-Marker in den Scan-Daten enthalten ist, explizit EOI schreiben
    if !parsed_target.scan_data.ends_with(&[0xFF, 0xD9]) {
        output.write_all(&[0xFF, 0xD9])?;
    }

	restore_file_times(target_path_ref, &parsed_target, &source);
	println!("Fertig! Alle Operationen abgeschlossen.");

    Ok(())
}

pub fn main() {
    match parse_arguments() {
        Ok(config) => {
            if config.debug {
                println!("[DEBUG] Configuration: {:?}", config);
            }

			let source_path = &config.source_path;
			let target_path = &config.target_path;

            match parse_jpeg_segments(source_path, false) {
                Ok(parsed_source) => {
					if config.debug {
						if let Err(e) = log_parsed_segments(Path::new(target_path), &parsed_source) {
							eprintln!("[ERROR] Log failed: {}", e);
						}
					}

                    if let Err(e) = inject_metadata_segments(target_path, &parsed_source) {
                        eprintln!("[ERROR] {}", e);
                        std::process::exit(1);
                    }
                    println!("[INFO] Metadata-preserving copy complete.");
                }
                Err(e) => {
                    eprintln!("[ERROR] {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            print_help();
            std::process::exit(1);
        }
    }
}
