
// CONFIGURATION //

pub mod config;
pub use config::{CONFIG, parse_arguments, print_help};

// PARSING THE SOURCE JPEG //

pub mod jpeg;
pub use jpeg::{build_marker_map, identify_metadata_type, parse_jpeg_segments, parse_jpeg_segments_default};
pub use jpeg::{MarkerInfo, JpegSegment, ParsedJpeg};

// LOGGING //

pub mod log;
pub use log::{log_parsed_segments, write_log};

// COPYING THE DATA FROM SOURCE AND WRITING THE TARGET //

pub mod write;
pub use write::inject_metadata_segments;