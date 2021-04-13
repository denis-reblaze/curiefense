use core::time::Duration;

/// creates a connection to a redis server
pub fn redis_conn() -> anyhow::Result<redis::Connection> {
    let server = std::env::var("REDIS_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let client = redis::Client::open(format!("redis://{}:6379/", server))?;
    let max_timeout = Duration::from_millis(100);
    let cnx = client.get_connection_with_timeout(max_timeout)?;
    cnx.set_read_timeout(Some(max_timeout))?;
    cnx.set_write_timeout(Some(max_timeout))?;
    Ok(cnx)
}
