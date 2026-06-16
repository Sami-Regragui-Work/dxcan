use serde::Serialize;

#[derive(Serialize)]
pub struct PortEntry {
    pub port:       u16,
    pub protocol:   String,
    pub state:      String,
    pub latency_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service:    Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version:    Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner_raw: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error:      Option<String>,
}

#[derive(Serialize)]
pub struct ScanOutput {
    pub tool:       String,
    pub host:       String,
    pub ip:         String,
    pub elapsed_ms: f64,
    pub scanned:    usize,
    pub shown:      usize,
    pub results:    Vec<PortEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_guess:   Option<String>,
}