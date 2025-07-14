// shared/segmentmanipulator.rs

//! Segment manipulation utilities for combining and selecting segments
//! from ParsedJpeg structures. Used in both Exifcopy and JPT.

use crate::library::jpeg::{JpegSegment, ParsedJpeg};
use filetime::FileTime;

/// Extracts segments from a ParsedJpeg using a custom filter function.
///
/// # Arguments
///
/// * `jpeg` - Reference to the ParsedJpeg structure
/// * `predicate` - A closure that receives a segment and returns true if it should be included
///
/// # Returns
///
/// A vector of references to segments that match the filter condition.
pub fn extract_segments(
    jpeg: &ParsedJpeg,
    predicate: impl Fn(&JpegSegment) -> bool,
) -> Vec<&JpegSegment> {
    jpeg.segments.iter().filter(|seg| predicate(seg)).collect()
}

/// Merges a list of segments and metadata into a new ParsedJpeg.
///
/// # Arguments
///
/// * `segments` - The list of segments to be used in the new JPEG
/// * `scan_data` - The scan data section (typically unchanged)
/// * `creation_time` - Optional creation timestamp
/// * `modification_time` - Optional modification timestamp
///
/// # Returns
///
/// A new ParsedJpeg with the given components.
pub fn merge_segments(
    segments: Vec<JpegSegment>,
    scan_data: Vec<u8>,
    creation_time: Option<FileTime>,
    modification_time: Option<FileTime>,
) -> ParsedJpeg {
    ParsedJpeg {
        segments,
        scan_data,
        creation_time,
        modification_time,
    }
}
