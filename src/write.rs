use chrono::{DateTime, NaiveDateTime};
use filetime::{FileTime, set_file_mtime};
use regex::Regex;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Foundation::FILETIME;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::FILE_SHARE_READ;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_WRITE_ATTRIBUTES, OPEN_EXISTING, SetFileTime,
};
use windows::core::PCWSTR;

use crate::CONFIG;
use crate::ParsedJpeg;
use crate::log_parsed_segments;
use crate::parse_jpeg_segments_default;
use crate::write_log;

// COPYING THE DATA FROM SOURCE AND WRITING THE TARGET //

trait WindowsFileTime {
    fn as_windows_file_time(&self) -> u64;
}

impl WindowsFileTime for FileTime {
    fn as_windows_file_time(&self) -> u64 {
        self.unix_seconds() as u64 * 10_000_000
            + self.nanoseconds() as u64 / 100
            + 116444736000000000
    }
}

pub fn inject_metadata_segments<P: AsRef<Path>>(
    target_path: P,
    source: &ParsedJpeg,
) -> std::io::Result<()> {
    let debug_mode = {
        let config = CONFIG.lock().unwrap();
        config.debug
    };
    let parsed_target = parse_jpeg_segments_default(&target_path)?;

    let target_path_ref = target_path.as_ref();
    let mut output = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(target_path_ref)?;

    if debug_mode {
        let _ = write_log("Segmente der ursprünglichen Zieldatei:");
        if let Err(e) = log_parsed_segments(&parsed_target) {
            eprintln!("[ERROR] Log failed: {}", e);
        }
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
        if segment.marker_name.starts_with("APP")
            || segment.marker_name == "COM"
            || segment.marker_name == "SOI"
            || segment.marker_name == "SOS"
            || segment.marker_name == "EOI"
        {
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

    if debug_mode {
        // ▲❗ Logging nach finalem Schreiben der Datei
        let parsed_target_final = parse_jpeg_segments_default(&target_path)?;
        let _ = write_log("Segmente der fertig geschriebenen Zieldatei:");
        if let Err(e) = log_parsed_segments(&parsed_target_final) {
            eprintln!("[ERROR] Log failed: {}", e);
        }
    }

    if let Err(e) = restore_file_times(target_path_ref, &parsed_target, source) {
        eprintln!(
            "[WARN] Datei-Zeitstempel konnten nicht gesetzt werden: {}",
            e
        );
    }
    println!("[INFO] Alle Operationen abgeschlossen.");

    Ok(())
}

fn restore_file_times(
    target_path: &Path,
    target_meta: &ParsedJpeg,
    source_meta: &ParsedJpeg,
) -> std::io::Result<()> {
    let mode = {
        let config = CONFIG.lock().unwrap();
        config.keep_date_mode
    };

    if mode == 0 {
        return Ok(());
    }

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
        3 => {
            // ▲❗ Metadatenbasierte Zeitübernahme (keepdate = 3)
            let (meta_ctime, meta_mtime) = extract_metadata_dates(source_meta);

            if CONFIG.lock().unwrap().debug {
                let _ = write_log("[DEBUG] Ausgewertete Metadaten-Zeitstempel (keepdate=3):");
                let _ = write_log(&format!(
                    "  Create: {:?} ({})
					  Modify: {:?} ({})
					",
                    meta_ctime,
                    meta_ctime
                        .map(|ft| fmt_filetime(&ft))
                        .unwrap_or_else(|| "-".into()),
                    meta_mtime,
                    meta_mtime
                        .map(|ft| fmt_filetime(&ft))
                        .unwrap_or_else(|| "-".into())
                ));
            }

            match (meta_ctime, meta_mtime) {
                (Some(c), Some(m)) => (c, m),
                (Some(c), None) => (c, c),
                (None, Some(m)) => (m, m),
                (None, None) => {
                    if CONFIG.lock().unwrap().debug {
                        let _ = write_log(
                            "[WARN] Keine gültigen Metadaten-Zeitstempel gefunden, Fallback auf keepdate=2",
                        );
                    }
                    (
                        source_meta.creation_time.unwrap_or_else(FileTime::now),
                        source_meta.modification_time.unwrap_or_else(FileTime::now),
                    )
                }
            }
        }
        _ => return Ok(()),
    };

    let _ = set_file_mtime(target_path, mtime);
    #[cfg(target_family = "windows")]
    set_creation_time_windows(target_path, ctime);

    Ok(())
}

fn extract_metadata_dates(jpeg: &ParsedJpeg) -> (Option<FileTime>, Option<FileTime>) {
    // ▲❗ Neue Version: basiert auf Segmenten mit metadata_type
    let mut create = None;
    let mut modify = None;

    let re_xmp_any = Regex::new(
        r#"([a-zA-Z0-9]+:)?(CreateDate|DateCreated|ModifyDate|DateModified)\s*=\s*"([^"]+)""#,
    )
    .unwrap();

    for segment in &jpeg.segments {
        if CONFIG.lock().unwrap().debug
            && (segment.marker_name == "APP1" || segment.marker_name == "APP13")
        {
            if let Some(ref mtype) = segment.metadata_type {
                if mtype == "XMP" || mtype == "EXIF" || mtype == "IPTC" {
                    let header = format!(
                        "--- SEGMENT {:?} / type {:?} ---",
                        segment.marker_name, segment.metadata_type
                    );
                    let preview = if segment.data.len() > 400 {
                        &segment.data[..400]
                    } else {
                        &segment.data
                    };

                    let as_text = String::from_utf8_lossy(preview)
                        .replace('\n', "⏎")
                        .replace('\r', "")
                        .replace('\t', "⇥");

                    let _ = write_log(&header);
                    let _ = write_log(&format!("{}\n", as_text));
                }
            }
        }

        if let Some(ref mtype) = segment.metadata_type {
            // XMP-Parser
            if mtype == "XMP" {
                if let Ok(xml) = std::str::from_utf8(&segment.data) {
                    if CONFIG.lock().unwrap().debug {
                        let _ = write_log("[DEBUG] XMP full segment content:");
                        let _ = write_log(xml);
                    }

                    for cap in re_xmp_any.captures_iter(xml) {
                        let ns = cap.get(1).map_or("", |m| m.as_str()); // z. B. "xmp:" oder ""
                        let tag = &cap[2]; // z. B. "CreateDate"
                        let value = &cap[3];
                        if CONFIG.lock().unwrap().debug {
                            let _ =
                                write_log(&format!("[DEBUG] Matched {}:{} = {}", ns, tag, value));
                            let _ = write_log(&format!(
                                "[DEBUG] Parsing value for {}{} → raw = {:?}",
                                ns, tag, value
                            ));
                        }
                        let mut parsed_dt = DateTime::parse_from_rfc3339(value)
                            .or_else(|_| DateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S%.f"))
                            .or_else(|_| DateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S"));

                        if parsed_dt.is_err() {
                            // Versuche: value + "+00:00"
                            let fallback = format!("{}+00:00", value);
                            parsed_dt = DateTime::parse_from_rfc3339(&fallback);
                        }
                        if let Ok(dt) = parsed_dt {
                            let ft = FileTime::from_unix_time(dt.timestamp(), 0);
                            if CONFIG.lock().unwrap().debug {
                                let _ = write_log(&format!(
                                    "[DEBUG] Umgewandelt zu DateTime = {:?}",
                                    dt
                                ));
                                let _ = write_log(&format!(
                                    "[DEBUG] Umgewandelt zu FileTime = {:?}",
                                    ft
                                ));
                            }
                            let tag_lc = tag.to_ascii_lowercase();
                            match tag_lc.as_str() {
                                // ▲❗ xmp:-Präfix wird bevorzugt behandelt
                                "createdate" | "datecreated" => {
                                    let _ =
                                        write_log(&format!("[DEBUG] Create Namespace: '{}'", ns));
                                    if ns == "xmp:" || create.is_none() {
                                        create = Some(ft);
                                        let _ = write_log(&format!(
                                            "[DEBUG] Setze create = {:?}",
                                            create
                                        ));
                                    } else {
                                        let _ = write_log(&format!(
                                            "[DEBUG] Verwerfe {}:{} (create bereits gesetzt)",
                                            ns, tag
                                        ));
                                    }
                                }
                                "modifydate" | "datemodified" => {
                                    let _ =
                                        write_log(&format!("[DEBUG] Modify Namespace: '{}'", ns));
                                    if ns == "xmp:" || modify.is_none() {
                                        modify = Some(ft);
                                        if CONFIG.lock().unwrap().debug {
                                            let _ = write_log(&format!(
                                                "[DEBUG] Setze modify = {:?}",
                                                modify
                                            ));
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }

            // EXIF-Parser
            if mtype == "EXIF" {
                if CONFIG.lock().unwrap().debug {
                    let _ = write_log("[DEBUG] EXIF-Segment erkannt, beginne Analyse...");
                }
                let (createdate_opt, modifydate_opt) =
                    parse_exif_segment_for_timestamps(&segment.data);

                if create.is_none() {
                    if let Some(createdate_val) = createdate_opt {
                        create = Some(createdate_val);
                        if CONFIG.lock().unwrap().debug {
                            let _ = write_log("[DEBUG] Create aus Direktparser übernommen");
                        }
                    }
                }

                if modify.is_none() {
                    if let Some(modifydate_val) = modifydate_opt {
                        modify = Some(modifydate_val);
                        if CONFIG.lock().unwrap().debug {
                            let _ = write_log("[DEBUG] Modify aus Direktparser übernommen");
                        }
                    }
                }
            }

            // IPTC
            if mtype == "IPTC" {
                if CONFIG.lock().unwrap().debug {
                    let _ = write_log("[DEBUG] IPTC-Segment erkannt, beginne Analyse...");

                    /*/ Schreibe IPTC-Daten in Datei
                    let mut file = match File::create("iptc_segment_dump.bin") {
                        Ok(f) => f,
                        Err(e) => {
                            let _ = write_log(&format!("[DEBUG] Fehler beim Erstellen von iptc_segment_dump.bin: {}", e));
                            return (create, modify);
                        }
                    };

                    if let Err(e) = file.write_all(&segment.data) {
                        let _ = write_log(&format!("[DEBUG] Fehler beim Schreiben von iptc_segment_dump.bin: {}", e));
                    } else {
                        let _ = write_log("[DEBUG] IPTC-Segment wurde in iptc_segment_dump.bin gespeichert.");
                    }*/
                }

                let (iptc_create, iptc_modify) = parse_iptc_segment_for_timestamps(&segment.data);

                if create.is_none() {
                    create = iptc_create;
                    if CONFIG.lock().unwrap().debug {
                        let _ = write_log("[DEBUG] Create aus IPTC übernommen");
                    }
                }

                if modify.is_none() {
                    modify = iptc_modify;
                    if CONFIG.lock().unwrap().debug {
                        let _ = write_log("[DEBUG] Modify aus IPTC übernommen");
                    }
                }
            }
        }
    }

    (create, modify)
}

fn fmt_filetime(ft: &FileTime) -> String {
    match DateTime::from_timestamp(ft.unix_seconds(), ft.nanoseconds()) {
        Some(dt) => dt.format("%Y.%m.%dT%H:%M:%S").to_string(),
        None => "-".to_string(),
    }
}

fn set_creation_time_windows(path: &Path, ctime: FileTime) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let wide_path: Vec<u16> = OsStr::new(path).encode_wide().chain(Some(0)).collect();

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
                eprintln!(
                    "⚠️ CreateFileW lieferte ungültigen Handle für Pfad: {:?}",
                    path
                );
            }
            Err(e) => {
                eprintln!("⚠️ Fehler beim Setzen von CreationTime: {e}");
            }
        }
    }
}

/// Parsed EXIF-Timestamps from EXIF segment (raw EXIF data, without 6-byte header)
fn parse_exif_segment_for_timestamps(data: &[u8]) -> (Option<FileTime>, Option<FileTime>) {
    let debug_mode = {
        let config = CONFIG.lock().unwrap();
        config.debug
    };

    let exif = &data[6..];
    if exif.len() < 10 {
        if debug_mode {
            let _ = write_log("[DEBUG] Segment zu kurz für EXIF-Auswertung.");
        }
        return (None, None);
    }

    if debug_mode {
        let _ = write_log(&format!("[DEBUG] Length of Exif-Segment: {}", exif.len()));
    }

    let is_le = match &exif[0..2] {
        b"II" => {
            if debug_mode {
                let _ = write_log("[DEBUG] Byte Order: Little Endian");
            }
            true
        }
        b"MM" => {
            if debug_mode {
                let _ = write_log("[DEBUG] Byte Order: Big Endian");
            }
            false
        }
        _ => {
            if debug_mode {
                let _ = write_log("[DEBUG] Unbekannte Byte Order");
            }
            return (None, None);
        }
    };

    fn read_u16(data: &[u8], offset: usize, le: bool) -> Option<u16> {
        data.get(offset..offset + 2).map(|b| {
            if le {
                u16::from_le_bytes([b[0], b[1]])
            } else {
                u16::from_be_bytes([b[0], b[1]])
            }
        })
    }

    fn read_u32(data: &[u8], offset: usize, le: bool) -> Option<u32> {
        data.get(offset..offset + 4).map(|b| {
            if le {
                u32::from_le_bytes([b[0], b[1], b[2], b[3]])
            } else {
                u32::from_be_bytes([b[0], b[1], b[2], b[3]])
            }
        })
    }

    if let Some(tiff_tag) = read_u16(exif, 2, is_le) {
        if tiff_tag != 0x002A && debug_mode {
            let _ = write_log("[DEBUG] Kein TIFF-Tag (0x002A), versuche trotzdem zu parsen.");
        }
    } else {
        let _ = write_log("[DEBUG] TIFF-Tag konnte nicht gelesen werden.");
        return (None, None);
    }

    let ifd0_offset = match read_u32(exif, 4, is_le) {
        Some(v) => v as usize,
        None => {
            if debug_mode {
                let _ = write_log("[DEBUG] IFD0-Offset konnte nicht gelesen werden.");
            }
            return (None, None);
        }
    };

    let ifd0_count = match read_u16(exif, ifd0_offset, is_le) {
        Some(v) => v as usize,
        None => {
            if debug_mode {
                let _ = write_log("[DEBUG] Anzahl der IFD0-Tags konnte nicht gelesen werden.");
            }
            return (None, None);
        }
    };

    if debug_mode {
        let _ = write_log(&format!("[DEBUG] Anzahl der IFD0-Tags: {}", ifd0_count));
    }

    let mut tag_map: HashMap<u16, String> = HashMap::new();
    let target_tags = [0x0132, 0x9003, 0x9004, 0x9010, 0x9011, 0x9012];
    let mut exif_ifd_offset: Option<usize> = None;

    for i in 0..ifd0_count {
        let base = ifd0_offset + 2 + i * 12;
        let tag = match read_u16(exif, base, is_le) {
            Some(t) => t,
            None => continue,
        };

        if debug_mode {
            let offset_raw = read_u32(exif, base + 8, is_le).unwrap_or(0);
            let _ = write_log(&format!(
                "[DEBUG] IFD0-Tag-ID {:04X} at offset {} → offset/value field: {}",
                tag, base, offset_raw
            ));
        }

        if tag == 0x8769 {
            if let Some(offset) = read_u32(exif, base + 8, is_le) {
                exif_ifd_offset = Some(offset as usize);
                if debug_mode {
                    let _ = write_log(&format!("[DEBUG] EXIF-IFD Offset gefunden: {}", offset));
                }
            }
            continue;
        }

        if target_tags.contains(&tag) {
            let datatype = match read_u16(exif, base + 2, is_le) {
                Some(t) => t,
                None => continue,
            };
            let count = match read_u32(exif, base + 4, is_le) {
                Some(c) => c as usize,
                None => continue,
            };
            let offset_or_value = exif.get(base + 8..base + 12).unwrap_or(&[]);

            if datatype == 2 && count > 0 {
                let string_bytes = if count <= 4 {
                    &offset_or_value[..count.min(4)]
                } else {
                    let offset = match read_u32(offset_or_value, 0, is_le) {
                        Some(o) => o as usize,
                        None => continue,
                    };
                    match exif.get(offset..offset + count) {
                        Some(b) => b,
                        None => continue,
                    }
                };
                if let Ok(s) = str::from_utf8(string_bytes) {
                    if debug_mode {
                        let _ = write_log(&format!(
                            "[DEBUG] IFD0-Tag {:04X} = '{}'",
                            tag,
                            s.trim_end_matches('\0')
                        ));
                    }
                    tag_map.insert(tag, s.trim_end_matches('\0').to_string());
                }
            }
        }
    }

    if let Some(eoff) = exif_ifd_offset {
        let exif_count = match read_u16(exif, eoff, is_le) {
            Some(v) => v as usize,
            None => {
                if debug_mode {
                    let _ = write_log("[DEBUG] Anzahl der EXIF-Tags konnte nicht gelesen werden.");
                }
                return (None, None);
            }
        };

        if debug_mode {
            let _ = write_log(&format!("[DEBUG] Anzahl der EXIF-Tags: {}", exif_count));
        }

        for i in 0..exif_count {
            let base = eoff + 2 + i * 12;
            let tag = match read_u16(exif, base, is_le) {
                Some(t) => t,
                None => continue,
            };

            if debug_mode {
                let offset_raw = read_u32(exif, base + 8, is_le).unwrap_or(0);
                let _ = write_log(&format!(
                    "[DEBUG] ExifIFD-Tag-ID {:04X} at offset {} → offset/value field: {}",
                    tag, base, offset_raw
                ));
            }

            if target_tags.contains(&tag) {
                let datatype = match read_u16(exif, base + 2, is_le) {
                    Some(t) => t,
                    None => continue,
                };
                let count = match read_u32(exif, base + 4, is_le) {
                    Some(c) => c as usize,
                    None => continue,
                };
                let offset_or_value = exif.get(base + 8..base + 12).unwrap_or(&[]);

                if datatype == 2 && count > 0 {
                    let string_bytes = if count <= 4 {
                        &offset_or_value[..count.min(4)]
                    } else {
                        let offset = match read_u32(offset_or_value, 0, is_le) {
                            Some(o) => o as usize,
                            None => continue,
                        };
                        match exif.get(offset..offset + count) {
                            Some(b) => b,
                            None => continue,
                        }
                    };
                    if let Ok(s) = str::from_utf8(string_bytes) {
                        if debug_mode {
                            let _ = write_log(&format!(
                                "[DEBUG] EXIF-Tag {:04X} = '{}'",
                                tag,
                                s.trim_end_matches('\0')
                            ));
                        }
                        tag_map.insert(tag, s.trim_end_matches('\0').to_string());
                    }
                }
            }
        }
    }

    let datetimeoriginal = tag_map.get(&0x9003);
    let datetimedigitized = tag_map.get(&0x9004);
    let modifydate = tag_map.get(&0x0132);
    let offsettimeoriginal = tag_map.get(&0x9011);
    let offsettimedigitized = tag_map.get(&0x9012);
    let offsetmodifydate = tag_map.get(&0x9010);

    if debug_mode {
        if let Some(s) = datetimeoriginal {
            let _ = write_log(&format!("[DEBUG] Tag 9003 DateTimeOriginal = '{}'", s));
        }
        if let Some(s) = datetimedigitized {
            let _ = write_log(&format!("[DEBUG] Tag 9004 DateTimeDigitized = '{}'", s));
        }
        if let Some(s) = modifydate {
            let _ = write_log(&format!("[DEBUG] Tag 0132 ModifyDate = '{}'", s));
        }
        if let Some(s) = offsettimeoriginal {
            let _ = write_log(&format!("[DEBUG] Tag 9011 OffsetTimeOriginal = '{}'", s));
        }
        if let Some(s) = offsettimedigitized {
            let _ = write_log(&format!("[DEBUG] Tag 9012 OffsetTimeDigitized = '{}'", s));
        }
        if let Some(s) = offsetmodifydate {
            let _ = write_log(&format!("[DEBUG] Tag 9010 OffsetTime = '{}'", s));
        }
    }

    let raw_createdate = datetimeoriginal.or(datetimedigitized);
    let raw_offset_create = offsettimeoriginal.or(offsettimedigitized);
    let raw_modifydate = modifydate;
    let raw_offset_modify = offsetmodifydate;

    let createdate_str = match raw_createdate {
        Some(s) => s,
        None => {
            if debug_mode {
                let _ = write_log("[DEBUG] Kein CreateDate gefunden.");
            }
            "<none>"
        }
    };
    let modifydate_str = match raw_modifydate {
        Some(s) => s,
        None => {
            if debug_mode {
                let _ = write_log("[DEBUG] Kein ModifyDate gefunden.");
            }
            "<none>"
        }
    };

    let final_offset_create = raw_offset_create
        .or_else(|| {
            if Some(createdate_str) == Some(modifydate_str) {
                raw_offset_modify
            } else {
                None
            }
        })
        .map_or("+00:00", |v| v.as_str());

    let final_offset_modify = raw_offset_modify
        .or_else(|| {
            if Some(createdate_str) == Some(modifydate_str) {
                raw_offset_create
            } else {
                None
            }
        })
        .map_or("+00:00", |v| v.as_str());

    if debug_mode {
        let _ = write_log(&format!(
            "[DEBUG] Raw Create: {}{}",
            createdate_str, final_offset_create
        ));

        let _ = write_log(&format!(
            "[DEBUG] Raw Modify: {}{}",
            modifydate_str, final_offset_modify
        ));
    }

    fn parse_datetime_with_offset(dt: &str, offset: &str) -> Option<FileTime> {
        let combined = format!("{}{}", dt, offset);
        DateTime::parse_from_str(&combined, "%Y:%m:%d %H:%M:%S%z")
            .ok()
            .map(|dt| FileTime::from_unix_time(dt.timestamp(), 0))
    }

    let createdate = parse_datetime_with_offset(createdate_str, final_offset_create);
    let modifydate = parse_datetime_with_offset(modifydate_str, final_offset_modify);

    (createdate, modifydate)
}

fn parse_iptc_segment_for_timestamps(data: &[u8]) -> (Option<FileTime>, Option<FileTime>) {
    let mut create_date: Option<String> = None;
    let mut create_time: Option<String> = None;
    let mut digital_date: Option<String> = None;
    let mut digital_time: Option<String> = None;
    let mut modify_date: Option<String> = None;
    let mut modify_time: Option<String> = None;

    let mut i = 0;
    while i + 5 <= data.len() {
        if data[i] == 0x1C && data[i + 1] == 0x02 {
            let dataset = data[i + 2];
            let len = u16::from_be_bytes([data[i + 3], data[i + 4]]) as usize;
            i += 5;

            if i + len > data.len() {
                break;
            }

            let content_bytes = &data[i..i + len];
            let content = String::from_utf8_lossy(content_bytes).to_string();

            if CONFIG.lock().unwrap().debug {
                let _ = write_log(&format!(
                    "[DEBUG] IPTC Dataset {:02X} = {:?}",
                    dataset, content
                ));
            }

            match dataset {
                0x1E => create_date = Some(content),  // Date Created
                0x23 => create_time = Some(content),  // Time Created
                0x37 => digital_date = Some(content), // Digital Creation Date
                0x3C => digital_time = Some(content), // Digital Creation Time
                0x3E => modify_date = Some(content),  // Modify Date (aka Date Sent)
                0x3F => modify_time = Some(content),  // Modify Time
                _ => {}
            }

            i += len;
        } else {
            i += 1;
        }
    }

    // Erstelle Hilfsfunktion zur Umwandlung
    fn make_filetime(date: Option<String>, time: Option<String>) -> Option<FileTime> {
        let date = date?;
        let time = time.unwrap_or_else(|| "000000".to_string());

        if date.len() != 8 || time.len() < 6 {
            return None;
        }

        let datetime_str = format!("{}T{}", date, &time[..6]); // ohne Offset
        if let Ok(ndt) = NaiveDateTime::parse_from_str(&datetime_str, "%Y%m%dT%H%M%S") {
            Some(FileTime::from_unix_time(ndt.and_utc().timestamp(), 0))
        //            Some(FileTime::from_unix_time(ndt.timestamp(), 0))
        } else {
            None
        }
    }

    let created = make_filetime(create_date.or(digital_date), create_time.or(digital_time));

    let modified = make_filetime(modify_date, modify_time);

    if CONFIG.lock().unwrap().debug {
        let _ = write_log(&format!("[DEBUG] IPTC final Create: {:?}", created));
        let _ = write_log(&format!("[DEBUG] IPTC final Modify: {:?}", modified));
    }

    (created, modified)
}
