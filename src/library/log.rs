use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::WriteSettings;
use log::{LevelFilter, info};
use simplelog::{ColorChoice, CombinedLogger, Config, TermLogger, TerminalMode, WriteLogger};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogMode {
    None,
    Console,
    FileOnly,
    Both,
}

/// Initializes logging: console, file, or both.
/// Uses CONFIG.log_path unless overridden.
pub fn init_logging(mode: LogMode, log_override: Option<&Path>) {
    let mut loggers: Vec<Box<dyn simplelog::SharedLogger>> = Vec::new();

    match mode {
        LogMode::Console | LogMode::Both => {
            loggers.push(TermLogger::new(
                LevelFilter::Info,
                Config::default(),
                TerminalMode::Mixed,
                ColorChoice::Auto,
            ));
        }
        _ => {}
    }

    if matches!(mode, LogMode::FileOnly | LogMode::Both) {
        if let Some(p) = log_override {
            if let Ok(file) = File::create(p) {
                loggers.push(WriteLogger::new(LevelFilter::Info, Config::default(), file));
            } else {
                eprintln!("Failed to create log file at {:?}", p);
            }
        }
    }

    if let Err(e) = CombinedLogger::init(loggers) {
        eprintln!("Failed to initialize logger: {}", e);
    }
}

/// Appends a log line to the logfile, independent of log macros
pub fn write_log(settings: &WriteSettings, msg: &str) -> std::io::Result<()> {
    match settings.log_mode {
        LogMode::None => return Ok(()),
        LogMode::Console => println!("{}", msg),
        LogMode::FileOnly | LogMode::Both => {
            //use std::fs::OpenOptions;
            //use std::io::Write;

            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&settings.log_path)?;
            writeln!(file, "{}", msg)?;

            if matches!(settings.log_mode, LogMode::Both) {
                println!("{}", msg);
            }
        }
    }

    Ok(())
}

/// Logs to both: console (log crate) + file (manual)
pub fn log_both(settings: &WriteSettings, message: &str) {
    info!("{}", message);
    let _ = write_log(settings, message);
}
