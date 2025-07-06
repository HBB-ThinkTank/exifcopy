use std::fs::OpenOptions;
use std::io::Write;

use crate::build_marker_map;
use crate::CONFIG;
use crate::ParsedJpeg;

// LOGGING //

pub fn write_log(content: &str) -> std::io::Result<()> {
    let path = CONFIG.lock().unwrap().log_path.clone();

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{}", content)?;
    Ok(())
}

pub fn log_parsed_segments(source: &ParsedJpeg) -> std::io::Result<()> {
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

    write_log(&log_output)
}