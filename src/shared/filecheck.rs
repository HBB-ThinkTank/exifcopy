use crate::library::jpeg::parse_jpeg_segments_default;
use std::path::Path;

/// Validates a JPEG file by checking existence and parseability.
///
/// Returns Ok(()) if the file exists and is a valid JPEG.
/// Otherwise returns an Err with a description of the problem.
pub fn checkfile(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Err(format!("File does not exist: {}", path.display()));
    }

    match parse_jpeg_segments_default(path) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!(
            "File is not a valid JPEG: {} - {}",
            path.display(),
            e
        )),
    }
}
