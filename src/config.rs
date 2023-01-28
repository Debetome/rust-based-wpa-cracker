use std::str::{FromStr, Chars};
use std::collections::HashMap;
use itertools::structs::{Permutations, Unique};

use crate::errors::{ConfigError, ConfigErrorType};

#[derive(Debug)]
pub struct Config {
    pub ssid: String,
    pub charset: Vec<CharSet>,
    pub max: usize,
    pub min: usize,
    pub iterator: Option<Unique<Permutations<Chars<'static>>>>,
    pub eapols: Vec<String>
}

impl TryFrom<Vec<String>> for Config {
    type Error = Box<Vec<ConfigError>>;

    fn try_from(args: Vec<String>) -> Result<Self, Self::Error> {
        let args = &args[1..];
        let mut errors: Vec<ConfigError> = Vec::new();
        
        let charset = args
            .iter()
            .filter_map(|arg| CharSet::from_str(arg.as_str()).ok())
            .collect::<Vec<CharSet>>();

        let mut str_args = args
            .windows(2)
            .filter_map(|args| {
                match args[0].as_str() {
                    "--ssid" => Some((args[0].to_owned(), args[1].to_owned())),
                    "--eapol1" => Some((args[0].to_owned(), args[1].to_owned())),
                    "--eapol2" => Some((args[0].to_owned(), args[1].to_owned())),
                    _ => None
                }
            })
            .collect::<HashMap<String, String>>();

        let mut digit_args = args
            .windows(2)
            .filter_map(|args| {
                let mut parse_arg = |key: &str, value: &str| {
                    match value.to_string().parse::<usize>() {
                        Ok(num) => Some((key.to_owned(), num)),
                        Err(_) => {
                            errors.push(ConfigError {
                                desc: "Arguments '--min' and '--max' can only receive numeric values",
                                code: ConfigErrorType::InvalidValue,
                                detail: Some(format!("Value '{}' NOT valid for argument '{}'", value, key))
                            });
                            None
                        }
                    }
                };
                match args[0].as_str() {
                    "--max" => parse_arg(&args[0], &args[1]),
                    "--min" => parse_arg(&args[0], &args[1]),
                    _ => None
                }
            })
            .collect::<HashMap<String, usize>>();


        if str_args.is_empty() || str_args.len() < 3 {
            for arg in ["--ssid", "--eapol1", "--eapol2"] {
                if str_args.get(arg).is_some() { continue; }
                errors.push(ConfigError {
                    desc: "Undefined arguments",
                    code: ConfigErrorType::MissingArgument,
                    detail: Some(format!("Argument '{}' not included", arg))
                });
            }
        }

        if digit_args.is_empty() || digit_args.len() < 2 {
            for arg in ["--min", "--max"] {
                if digit_args.get(arg).is_some() { continue; }
                errors.push(ConfigError {
                    desc: "Undefined arguments",
                    code: ConfigErrorType::MissingArgument,
                    detail: Some(format!("Argument '{}' not included", arg))
                });
            }
        }

        if digit_args.len() == 2 && digit_args.get("--min").unwrap() > digit_args.get("--max").unwrap() { 
            errors.push(ConfigError {
                desc: "'--min' value can't be greater than '--max'",
                code: ConfigErrorType::IncorrectValue,
                detail: None
            });
        }

        if charset.is_empty() { 
            errors.push(ConfigError {
                desc: "No charsets specified ...",
                code: ConfigErrorType::MissingArgument,
                detail: None
            });
        }

        if !errors.is_empty() { return Err(Box::new(errors)); }

        let ssid = str_args.remove("--ssid").unwrap();
        let eapol1 = str_args.remove("--eapol1").unwrap();
        let eapol2 = str_args.remove("--eapol2").unwrap();
        let max = digit_args.remove("--max").unwrap();
        let min = digit_args.remove("--min").unwrap();
        let iterator = None;

        Ok(Self { ssid, charset, max, min, iterator, eapols: vec![eapol1, eapol2] })
    }
}

#[derive(Debug)]
pub enum CharSet {
    LowerCase(String),
    UpperCase(String),
    Digits(String)
}

impl FromStr for CharSet {
    type Err = String;

    fn from_str(arg: &str) -> Result<Self, Self::Err> {
        match arg {
            "--lowercase" => Ok(CharSet::LowerCase(String::from("abcdefghijklmnopqrstuvwxyz"))),
            "--uppercase" => Ok(CharSet::UpperCase(String::from("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))),
            "--digits" => Ok(CharSet::Digits(String::from("1234567890"))),
            _ => Err(String::from("Invalid charset argument"))
        }
    }
}