#[derive(Debug, Clone, PartialEq)]
pub enum Confidence {
    Confirmed,
    Heuristic,
    PortGuess,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confidence::Confirmed => write!(f, "confirmed"),
            Confidence::Heuristic => write!(f, "heuristic"),
            Confidence::PortGuess => write!(f, "port-guess"),
        }
    }
}

impl serde::Serialize for Confidence {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ServiceResult {
    pub port: u16,
    pub service: String,
    pub version: Option<String>,
    pub banner_raw: Option<String>,
    pub confidence: Confidence,
    pub detection_ms: f64,
}
