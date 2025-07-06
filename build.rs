use std::env;
use std::fs::File;
use std::io::Write;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let mut f = File::create(format!("{}/build_info.rs", out_dir)).unwrap();

    let now = chrono::Utc::now();
    let build_date = now.format("%Y-%m-%d").to_string();
    let build_year = now.format("%Y").to_string();

    writeln!(f, "pub const BUILD_DATE: &str = \"{}\";", build_date).unwrap();
    writeln!(f, "pub const BUILD_YEAR: &str = \"{}\";", build_year).unwrap();
}
