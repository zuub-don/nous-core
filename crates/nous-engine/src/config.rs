//! CLI argument parsing and configuration for nous-engine.

/// Engine configuration parsed from CLI arguments.
#[derive(Debug, Clone)]
pub struct Config {
    /// Input source: file path or "-" for stdin.
    pub input: String,
    /// gRPC listen port.
    pub grpc_port: u16,
    /// Maximum number of recent events to buffer.
    pub buffer_size: usize,
    /// Adapter name: "suricata", "zeek", "syslog", "journald", or "auto".
    pub adapter: String,
    /// Correlation engine sliding window duration in seconds.
    pub correlation_window_secs: u64,
    /// PostgreSQL database URL (optional, requires `persistence` feature).
    pub db_url: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            input: "-".into(),
            grpc_port: 50051,
            buffer_size: 1000,
            adapter: "auto".into(),
            correlation_window_secs: 300,
            db_url: None,
        }
    }
}

impl Config {
    /// Parse configuration from CLI arguments.
    ///
    /// Supported flags:
    /// - `--input <path|->`: event source (default: stdin)
    /// - `--grpc-port <port>`: gRPC listen port (default: 50051)
    /// - `--buffer-size <n>`: event ring buffer capacity (default: 1000)
    /// - `--adapter <name>`: adapter to use (default: auto)
    /// - `--correlation-window <secs>`: correlation window duration (default: 300)
    /// - `--db-url <url>`: PostgreSQL connection URL
    pub fn from_args(args: &[String]) -> Result<Self, String> {
        let mut config = Config::default();
        let mut i = 0;

        while i < args.len() {
            match args[i].as_str() {
                "--input" => {
                    i += 1;
                    config.input = args.get(i).ok_or("--input requires a value")?.clone();
                }
                "--grpc-port" => {
                    i += 1;
                    let val = args.get(i).ok_or("--grpc-port requires a value")?;
                    config.grpc_port = val.parse().map_err(|_| format!("invalid port: {val}"))?;
                }
                "--buffer-size" => {
                    i += 1;
                    let val = args.get(i).ok_or("--buffer-size requires a value")?;
                    config.buffer_size = val
                        .parse()
                        .map_err(|_| format!("invalid buffer size: {val}"))?;
                }
                "--adapter" => {
                    i += 1;
                    config.adapter = args.get(i).ok_or("--adapter requires a value")?.clone();
                }
                "--correlation-window" => {
                    i += 1;
                    let val = args.get(i).ok_or("--correlation-window requires a value")?;
                    config.correlation_window_secs = val
                        .parse()
                        .map_err(|_| format!("invalid correlation window: {val}"))?;
                }
                "--db-url" => {
                    i += 1;
                    config.db_url = Some(args.get(i).ok_or("--db-url requires a value")?.clone());
                }
                other => {
                    return Err(format!("unknown argument: {other}"));
                }
            }
            i += 1;
        }

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = Config::default();
        assert_eq!(config.input, "-");
        assert_eq!(config.grpc_port, 50051);
        assert_eq!(config.buffer_size, 1000);
        assert_eq!(config.adapter, "auto");
        assert_eq!(config.correlation_window_secs, 300);
        assert!(config.db_url.is_none());
    }

    #[test]
    fn parse_all_args() {
        let args: Vec<String> = vec![
            "--input",
            "/var/log/suricata/eve.json",
            "--grpc-port",
            "9090",
            "--buffer-size",
            "5000",
            "--adapter",
            "suricata",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let config = Config::from_args(&args).unwrap();
        assert_eq!(config.input, "/var/log/suricata/eve.json");
        assert_eq!(config.grpc_port, 9090);
        assert_eq!(config.buffer_size, 5000);
        assert_eq!(config.adapter, "suricata");
    }

    #[test]
    fn parse_stdin_input() {
        let args: Vec<String> = vec!["--input", "-"].into_iter().map(String::from).collect();
        let config = Config::from_args(&args).unwrap();
        assert_eq!(config.input, "-");
    }

    #[test]
    fn invalid_port_returns_error() {
        let args: Vec<String> = vec!["--grpc-port", "not_a_number"]
            .into_iter()
            .map(String::from)
            .collect();
        assert!(Config::from_args(&args).is_err());
    }

    #[test]
    fn unknown_arg_returns_error() {
        let args: Vec<String> = vec!["--unknown"].into_iter().map(String::from).collect();
        assert!(Config::from_args(&args).is_err());
    }

    #[test]
    fn missing_value_returns_error() {
        let args: Vec<String> = vec!["--input"].into_iter().map(String::from).collect();
        assert!(Config::from_args(&args).is_err());
    }

    #[test]
    fn parse_adapter_flag() {
        let args: Vec<String> = vec!["--adapter", "zeek"]
            .into_iter()
            .map(String::from)
            .collect();
        let config = Config::from_args(&args).unwrap();
        assert_eq!(config.adapter, "zeek");
    }

    #[test]
    fn parse_db_url_flag() {
        let args: Vec<String> = vec!["--db-url", "postgres://localhost/nous"]
            .into_iter()
            .map(String::from)
            .collect();
        let config = Config::from_args(&args).unwrap();
        assert_eq!(config.db_url.as_deref(), Some("postgres://localhost/nous"));
    }
}
