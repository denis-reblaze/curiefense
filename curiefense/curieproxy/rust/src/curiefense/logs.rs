use serde::Serialize;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct Logs {
    pub level: LogLevel,
    pub start: Instant,
    pub logs: Vec<Log>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Log {
    pub elapsed_micros: u64,
    pub level: LogLevel,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
}

impl LogLevel {
    fn short(&self) -> char {
        match self {
            LogLevel::Debug => 'D',
            LogLevel::Info => 'I',
            LogLevel::Warning => 'W',
            LogLevel::Error => 'E',
        }
    }
}

impl Log {
    pub fn to_string(&self) -> String {
        format!(
            "{} {}µs {}",
            self.level.short(),
            self.elapsed_micros,
            self.message
        )
    }
}

impl Logs {
    pub fn new() -> Self {
        Logs {
            start: Instant::now(),
            level: LogLevel::Debug,
            logs: Vec::new(),
        }
    }

    pub fn log(&mut self, level: LogLevel, message: String) {
        let now = Instant::now();
        self.logs.push(Log {
            elapsed_micros: now.duration_since(self.start).as_micros() as u64,
            level: level,
            message,
        })
    }

    pub fn debug(&mut self, message: String) {
        self.log(LogLevel::Debug, message);
    }
    pub fn info(&mut self, message: String) {
        self.log(LogLevel::Info, message);
    }
    pub fn warning(&mut self, message: String) {
        self.log(LogLevel::Warning, message);
    }
    pub fn error(&mut self, message: String) {
        self.log(LogLevel::Error, message);
    }
    pub fn aerror(&mut self, message: anyhow::Error) {
        self.log(LogLevel::Error, format!("{}", message));
    }

    pub fn to_stringvec(&self) -> Vec<String> {
        self.logs.iter().map(|l| l.to_string()).collect()
    }
}
