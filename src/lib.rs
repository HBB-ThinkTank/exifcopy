// SHARED //

pub mod shared;
pub use shared::settings::WriteSettings;

pub mod library {
    pub mod jpeg;
    pub mod log;
    pub mod write;
}

// PARSING THE SOURCE JPEG //

pub use library::jpeg::{JpegSegment, MarkerInfo, ParsedJpeg};
pub use library::jpeg::{
    build_marker_map, identify_metadata_type, parse_jpeg_segments, parse_jpeg_segments_default,
};

// LOGGING //

pub use library::log::{init_logging, LogMode, write_log};

// COPYING THE DATA FROM SOURCE AND WRITING THE TARGET //

pub use library::write::{inject_metadata_segments, InjectionMode, log_parsed_segments};
