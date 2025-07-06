// CONFIGURATION //
use exifcopy::{CONFIG, parse_arguments, print_help};

// // PARSING THE SOURCE JPEG // //
use exifcopy::parse_jpeg_segments;

// LOGGING //

use exifcopy::{log_parsed_segments, write_log};

// COPYING THE DATA FROM SOURCE AND WRITING THE TARGET //

use exifcopy::inject_metadata_segments;

use std::clone::Clone;

pub fn main() {
    match parse_arguments() {
        Ok(config) => {
            if config.debug {
                println!("[DEBUG] Configuration: {:?}", config);
            }

            *CONFIG.lock().unwrap() = config.clone(); // ▲❗ Konfiguration global speichern

            let source_path = &config.source_path;
            let target_path = &config.target_path;

            match parse_jpeg_segments(source_path, false) {
                Ok(parsed_source) => {
                    // Nur im Debug-Modus: Schreiben der gefundenen Segmente der Quelldatei
                    let _ = write_log("Segmente der Quelldatei:");
                    if CONFIG.lock().unwrap().debug {
                        if let Err(e) = log_parsed_segments(&parsed_source) {
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
