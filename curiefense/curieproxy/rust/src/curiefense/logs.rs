use serde::Serialize;

#[derive(Debug, Clone)]
pub struct Logs(pub Vec<Log>);

#[derive(Debug, Clone, Serialize)]
pub struct Log {
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

impl Logs {
  pub fn new() -> Self {
    Logs(Vec::new())
  }
  pub fn debug(&mut self, message: String) {
    self.0.push(Log {
      level: LogLevel::Debug,
      message,
    })
  }
  pub fn info(&mut self, message: String) {
    self.0.push(Log {
      level: LogLevel::Info,
      message,
    })
  }
  pub fn warning(&mut self, message: String) {
    self.0.push(Log {
      level: LogLevel::Warning,
      message,
    })
  }
  pub fn error(&mut self, message: String) {
    self.0.push(Log {
      level: LogLevel::Error,
      message,
    })
  }
  pub fn aerror(&mut self, message: anyhow::Error) {
    self.0.push(Log {
      level: LogLevel::Error,
      message: format!("{}", message),
    })
  }

  pub fn to_stringvec(&self) -> Vec<String> {
    self.0.iter().map(|l| format!("{:?}", l)).collect()
  }
}
