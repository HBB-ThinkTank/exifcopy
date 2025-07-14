mod config;

// CONFIGURATION //
use config::{parse_arguments, print_help};

// // PARSING THE SOURCE JPEG // //
use exifcopy::parse_jpeg_segments;

// LOGGING //

//use exifcopy::library::log::LogMode;
//use exifcopy::library::log::init_logging;
use exifcopy::{LogMode, init_logging, write_log};

// COPYING THE DATA FROM SOURCE AND WRITING THE TARGET //

use exifcopy::{InjectionMode, inject_metadata_segments, log_parsed_segments};

pub fn main() {
    match parse_arguments() {
        Ok(config) => {
            let write_settings = config.to_write_settings();

            init_logging(write_settings.log_mode, Some(&write_settings.log_path));

            if write_settings.log_mode == LogMode::FileOnly {
                println!("[DEBUG] Configuration: {:?}", config);
            }

            let source_path = &config.source_path;
            let target_path = &config.target_path;

            match parse_jpeg_segments(source_path, false) {
                Ok(parsed_source) => {
                    // Nur im Debug-Modus: Schreiben der gefundenen Segmente der Quelldatei
                    let _ = write_log(&write_settings, "Segmente der Quelldatei:");
                    if write_settings.log_mode == LogMode::FileOnly {
                        if let Err(e) = log_parsed_segments(&write_settings, &parsed_source) {
                            eprintln!("[ERROR] Log failed: {}", e);
                        }
                    }

                    // always use InjectionMode::CopyMetadata in Exifcopy
                    if let Err(e) = inject_metadata_segments(
                        &write_settings,
                        target_path,
                        InjectionMode::CopyMetadata,
                        &parsed_source,
                    ) {
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
