use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct TestBlock {
    pub fields: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct OsEntry {
    pub name: String,
    pub classes: Vec<OsClass>,
    pub cpes: Vec<String>,
    pub tests: HashMap<String, TestBlock>,
}

#[derive(Debug, Clone)]
pub struct OsClass {
    pub vendor: String,
    pub os_family: String,
    pub os_gen: String,
    pub device_type: String,
}

impl OsClass {
    pub fn has_data(&self) -> bool {
        !self.vendor.is_empty()
            || !self.os_family.is_empty()
            || !self.os_gen.is_empty()
            || !self.device_type.is_empty()
    }
}

impl OsEntry {
    pub fn primary_class(&self) -> Option<&OsClass> {
        self.classes.iter().find(|c| c.has_data())
    }

    pub fn running_line(&self) -> Option<String> {
        let c = self.primary_class()?;
        if c.os_family.is_empty() && c.os_gen.is_empty() {
            return None;
        }
        if c.os_gen.is_empty() {
            Some(c.os_family.clone())
        } else {
            Some(format!("{} {}", c.os_family, c.os_gen))
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct MatchPoints {
    pub weights: HashMap<String, HashMap<String, u32>>,
}

pub struct OsDatabase {
    pub match_points: MatchPoints,
    pub entries: Vec<OsEntry>,
}

pub const TEST_NAMES: &[&str] = &[
    "SEQ", "OPS", "WIN", "ECN", "T1", "T2", "T3", "T4", "T5", "T6", "T7", "U1", "IE",
];

pub const NMAP_OS_DB: &str = "/usr/share/nmap/nmap-os-db";

static DB: OnceLock<Result<OsDatabase, String>> = OnceLock::new();

const EMBEDDED_OS_DB: &str = include_str!(concat!(env!("OUT_DIR"), "/nmap-os-db"));

pub fn database() -> Result<&'static OsDatabase, String> {
    DB.get_or_init(load_default).as_ref().map_err(|e| e.clone())
}

fn parse_fields(s: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for part in s.split('%') {
        if let Some(eq) = part.find('=') {
            let key = part[..eq].trim().to_string();
            let val = part[eq + 1..].to_string();
            map.insert(key, val);
        }
    }
    map
}

fn parse_test_line(line: &str) -> Option<(String, TestBlock)> {
    let paren = line.find('(')?;
    let close = line.rfind(')')?;
    if close <= paren {
        return None;
    }
    let name = line[..paren].trim().to_string();
    let inner = &line[paren + 1..close];
    Some((
        name,
        TestBlock {
            fields: parse_fields(inner),
        },
    ))
}

fn parse_class_line(line: &str) -> Option<OsClass> {
    let rest = line.strip_prefix("Class ")?;
    let parts: Vec<&str> = rest.splitn(4, '|').map(|s| s.trim()).collect();
    Some(OsClass {
        vendor: parts.first().unwrap_or(&"").to_string(),
        os_family: parts.get(1).unwrap_or(&"").to_string(),
        os_gen: parts.get(2).unwrap_or(&"").to_string(),
        device_type: parts.get(3).unwrap_or(&"").to_string(),
    })
}

fn is_test_line(line: &str) -> bool {
    TEST_NAMES
        .iter()
        .any(|&name| line.starts_with(name) && line[name.len()..].starts_with('('))
}

fn parse_match_points(lines: &[&str]) -> MatchPoints {
    let mut mp = MatchPoints::default();
    for &line in lines {
        if is_test_line(line) {
            if let Some((name, block)) = parse_test_line(line) {
                let field_weights: HashMap<String, u32> = block
                    .fields
                    .into_iter()
                    .filter_map(|(k, v)| v.parse::<u32>().ok().map(|n| (k, n)))
                    .collect();
                mp.weights.insert(name, field_weights);
            }
        }
    }
    mp
}

pub fn resolve_db_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("DXCAN_OS_DB") {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Some(path);
        }
    }
    for candidate in [
        PathBuf::from(NMAP_OS_DB),
        PathBuf::from("/usr/local/share/nmap/nmap-os-db"),
    ] {
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sidecar = dir.join("nmap-os-db");
            if sidecar.is_file() {
                return Some(sidecar);
            }
        }
    }
    None
}

pub fn load_os_db(path: &Path) -> Result<OsDatabase, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    parse_os_db(&content)
}

pub fn parse_os_db(content: &str) -> Result<OsDatabase, String> {
    let mut entries: Vec<OsEntry> = Vec::new();
    let mut current: Option<OsEntry> = None;
    let mut in_match_points = false;
    let mut mp_lines: Vec<&str> = Vec::new();
    let mut match_points = MatchPoints::default();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            if in_match_points {
                in_match_points = false;
                match_points = parse_match_points(&mp_lines);
            }
            continue;
        }
        if line.starts_with('#') || line.starts_with("This nmap-os-db") {
            continue;
        }
        if line == "MatchPoints" {
            in_match_points = true;
            continue;
        }
        if in_match_points {
            mp_lines.push(line);
            continue;
        }
        if let Some(name) = line.strip_prefix("Fingerprint ") {
            if let Some(entry) = current.take() {
                entries.push(entry);
            }
            current = Some(OsEntry {
                name: name.trim().to_string(),
                classes: Vec::new(),
                cpes: Vec::new(),
                tests: HashMap::new(),
            });
            continue;
        }
        if let Some(entry) = current.as_mut() {
            if line.starts_with("Class ") {
                if let Some(class) = parse_class_line(line) {
                    entry.classes.push(class);
                }
            } else if line.starts_with("CPE ") {
                let cpe = line[4..]
                    .trim()
                    .trim_end_matches(" auto")
                    .trim()
                    .to_string();
                if !cpe.is_empty() {
                    entry.cpes.push(cpe);
                }
            } else if is_test_line(line) {
                if let Some((name, block)) = parse_test_line(line) {
                    entry.tests.insert(name, block);
                }
            }
        }
    }
    if let Some(entry) = current.take() {
        entries.push(entry);
    }

    Ok(OsDatabase {
        match_points,
        entries,
    })
}

fn load_default() -> Result<OsDatabase, String> {
    if let Some(path) = resolve_db_path() {
        return load_os_db(&path);
    }
    parse_os_db(EMBEDDED_OS_DB).map_err(|e| {
        format!(
            "nmap-os-db not found (install nmap or set DXCAN_OS_DB); build-time embed failed: {e}"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_nmap_os_db_from_disk() {
        let path = resolve_db_path().expect("nmap-os-db not found; install nmap or set DXCAN_OS_DB");
        let db = load_os_db(&path).expect("load");
        assert_db(&db);
    }

    #[test]
    fn loads_build_time_embedded_os_db() {
        let db = parse_os_db(EMBEDDED_OS_DB).expect("embedded load");
        assert_db(&db);
    }

    fn assert_db(db: &OsDatabase) {
        assert!(!db.entries.is_empty());
        assert!(!db.match_points.weights.is_empty());
        let missing_seq = db
            .entries
            .iter()
            .filter(|e| !e.tests.contains_key("SEQ"))
            .count();
        assert_eq!(missing_seq, 0);
        let linux = db
            .entries
            .iter()
            .find(|e| e.name == "Linux 5.0 - 5.4")
            .or_else(|| db.entries.iter().find(|e| e.name.contains("Linux 5.0")))
            .expect("linux fingerprint");
        let class = linux.primary_class().expect("class");
        assert_eq!(class.os_family, "Linux");
        assert!(linux.running_line().unwrap().contains("Linux"));
        assert!(!linux.cpes.is_empty() || !linux.classes.is_empty());
    }
}
