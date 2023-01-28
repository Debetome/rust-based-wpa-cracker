use std::error::Error;
use std::fmt;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ConfigErrorType {
    InvalidValue,
    IncorrectValue,
    MissingArgument
}

impl fmt::Display for ConfigErrorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidValue => write!(f, "Invalid Value"),
            Self::IncorrectValue => write!(f, "Incorrect Value"),
            Self::MissingArgument => write!(f, "Missing Argument")
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ConfigError {
    pub desc: &'static str,
    pub code: ConfigErrorType,
    pub detail: Option<String>
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.detail {
            Some(ref detail) => f.write_fmt(
                format_args!("{} - {} ({})", self.desc, detail, self.code)),
            None => f.write_fmt(format_args!("{} ({})", self.desc, self.code))
        }
    }
}

impl Error for ConfigError {
    fn description(&self) -> &'static str {
        self.desc
    }
}