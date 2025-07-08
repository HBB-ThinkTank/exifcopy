use crate::library::log::LogMode;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct WriteSettings {
    pub keepdate: u8,
    pub debug: bool,
    pub log_mode: LogMode,
    pub log_path: PathBuf,
}
