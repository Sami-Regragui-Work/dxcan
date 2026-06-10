use std::net::IpAddr;

pub async fn resolve_host(host: &str) -> Result<IpAddr, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    tokio::net::lookup_host(format!("{host}:0"))
        .await
        .map_err(|e| format!("DNS resolution failed for '{host}': {e}"))?
        .next()
        .map(|a| a.ip())
        .ok_or_else(|| format!("No addresses found for '{host}'"))
}