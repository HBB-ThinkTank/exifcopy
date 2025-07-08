use std::env;
use std::path::PathBuf;

use exifcopy::library::log::LogMode;
use exifcopy::shared::settings::WriteSettings;

include!(concat!(env!("OUT_DIR"), "/build_info.rs"));

// CONFIGURATION //

#[derive(Debug, Clone)]
pub struct Config {
    pub keep_date_mode: u8,
    pub source_path: PathBuf,
    pub target_path: PathBuf,
    pub log_path: PathBuf,
    pub log_mode: LogMode,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            keep_date_mode: 1,
            source_path: PathBuf::new(),
            target_path: PathBuf::new(),
            log_path: PathBuf::new(),
            log_mode: LogMode::FileOnly,
        }
    }
}

//pub static CONFIG: Lazy<Mutex<Config>> = Lazy::new(|| Mutex::new(Config::default()));

pub struct ArgumentDefinition {
    pub name: &'static str,
    pub alias: &'static str,
    pub takes_value: bool,
    pub description: &'static str,
}

const ARG_DEFINITIONS: &[ArgumentDefinition] = &[
    ArgumentDefinition {
        name: "--log",
        alias: "-l",
        takes_value: true,
        description: "Log output: none, file, console, both (default: file)",
    },
    ArgumentDefinition {
        name: "--help",
        alias: "-h",
        takes_value: false,
        description: "Show help information",
    },
    ArgumentDefinition {
        name: "--keepdate",
        alias: "-kd",
        takes_value: true,
        description: "Preserve file timestamps: 0 = none, 1 = target (default), 2 = source, 3 = metadata/source",
    },
];

pub fn parse_arguments() -> Result<Config, String> {
    let args: Vec<String> = env::args().collect();
    let mut config = Config::default();
    let mut positional_args: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];

        let arg_key = if let Some(eq_pos) = arg.find('=') {
            &arg[..eq_pos]
        } else {
            arg
        };

        if let Some(def) = ARG_DEFINITIONS
            .iter()
            .find(|d| d.name == arg_key || d.alias == arg_key)
        {
            if def.name == "--help" {
                if args.len() == 2 {
                    print_help();
                    std::process::exit(0);
                } else {
                    print_help();
                }
            }

            if def.name == "--keepdate" {
                let val = if let Some(eq_pos) = arg.find('=') {
                    &arg[eq_pos + 1..]
                } else if i + 1 < args.len() {
                    i += 1;
                    &args[i]
                } else {
                    return Err("Missing value for --keepdate".into());
                };
                config.keep_date_mode = val.parse::<u8>().map_err(|_| {
                    "Invalid value for --keepdate (expected 0, 1, 2, 3)".to_string()
                })?;
                if config.keep_date_mode > 3 {
                    return Err("Invalid value for --keepdate (expected 0, 1, 2, 3)".to_string());
                }
            }

            if def.name == "--log" {
                let val = if let Some(eq_pos) = arg.find('=') {
                    &arg[eq_pos + 1..]
                } else if i + 1 < args.len() {
                    i += 1;
                    &args[i]
                } else {
                    return Err("Missing value for --log".into());
                };
                config.log_mode = match val.to_lowercase().as_str() {
                    "none" => LogMode::None,
                    "console" => LogMode::Console,
                    "both" => LogMode::Both,
                    "file" => LogMode::FileOnly,
                    _ => {
                        return Err(
                            "Invalid value for --log (use: none, file, console, both)".into()
                        );
                    }
                };
            }

            if def.takes_value
                && !arg.contains('=')
                && def.name != "--keepdate"
                && def.name != "--log"
            {
                i += 1;
            }
        } else if arg.starts_with("-") {
            return Err(format!("Unknown option: {}", arg));
        } else {
            positional_args.push(arg.clone());
        }

        i += 1;
    }

    if positional_args.len() < 2 {
        return Err("Missing required <source.jpg> and <target.jpg> arguments".to_string());
    }

    config.source_path = PathBuf::from(&positional_args[positional_args.len() - 2]);
    config.target_path = PathBuf::from(&positional_args[positional_args.len() - 1]);
    config.log_path = {
        let mut path = config.target_path.clone();
        path.set_extension("log");
        path
    };

    Ok(config)
}

pub fn print_help() {
    println!(
        "{} v{} ({})",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        BUILD_DATE,
    );
    println!(
        "© {} {} - Licensed under {}\n",
        BUILD_YEAR,
        env!("CARGO_PKG_AUTHORS"),
        env!("CARGO_PKG_LICENSE")
    );
    println!("{}", env!("CARGO_PKG_REPOSITORY"));

    println!("Usage:");
    println!("  exifcopy [options] <source.jpg> <target.jpg>\n");

    println!("Options:");
    for def in ARG_DEFINITIONS {
        println!("  {:<12} {:<4}  {}", def.name, def.alias, def.description);
    }
}

impl Config {
    pub fn to_write_settings(&self) -> WriteSettings {
        WriteSettings {
            keepdate: self.keep_date_mode,
            debug: matches!(self.log_mode, LogMode::FileOnly),
            log_mode: self.log_mode,
            log_path: self.log_path.clone(),
        }
    }
}
