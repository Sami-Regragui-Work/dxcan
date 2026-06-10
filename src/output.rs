use serde::Serialize;

#[derive(Serialize)]
pub struct PortResult {
    pub port: u16,
    pub state: String,
    pub latency_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct ScanOutput {
    pub tool: String,
    pub host: String,
    pub ip: String,
    pub elapsed_s: f64,
    pub scanned: usize,
    pub shown: usize,
    pub results: Vec<PortResult>,
}