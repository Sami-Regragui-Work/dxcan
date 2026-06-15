//! Nmap XML output parser.
//!
//! Parses the XML produced by `nmap -oX -` into dxcan's internal types.
//! Handles the most common fields: ports, states, service/version, OS guess.
//! Non-fatal: missing or unexpected fields are silently skipped — we never
//! panic on malformed Nmap output.

use quick_xml::events::Event;
use quick_xml::reader::Reader;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
pub struct NmapPort {
    pub port:      u16,
    pub protocol:  String,
    pub state:     String,
    /// Reason for state (syn-ack, reset, no-response, etc.)
    pub reason:    Option<String>,
    pub service:   Option<String>,
    pub product:   Option<String>,
    pub version:   Option<String>,
    pub extra_info: Option<String>,
    /// Combined "product version extrainfo" string, trimmed
    pub version_string: Option<String>,
    /// RTT in ms extracted from <times> or srtt attribute when available
    pub rtt_ms:    Option<f64>,
}

#[derive(Debug, Default)]
pub struct NmapHost {
    pub ip:       String,
    pub hostname: Option<String>,
    pub ports:    Vec<NmapPort>,
    pub os_guess: Option<String>,
    pub os_accuracy: Option<u8>,
}

#[derive(Debug, Default)]
pub struct NmapResult {
    pub hosts:       Vec<NmapHost>,
    /// Wall-clock elapsed seconds reported by Nmap in <runstats>
    pub elapsed_secs: Option<f64>,
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

pub fn parse(xml: &str) -> Result<NmapResult, String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut result   = NmapResult::default();
    let mut cur_host: Option<NmapHost>  = None;
    let mut cur_port: Option<NmapPort>  = None;

    // Simple stack: track element nesting relevant to our parsing
    let mut in_host   = false;
    let mut in_ports  = false;
    let mut in_port   = false;
    let mut in_os     = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                match e.name().as_ref() {
                    b"host" => {
                        in_host = true;
                        cur_host = Some(NmapHost::default());
                    }
                    b"address" if in_host => {
                        let host = cur_host.as_mut().unwrap();
                        let mut addrtype = String::new();
                        let mut addr     = String::new();
                        for attr in e.attributes().flatten() {
                            match attr.key.as_ref() {
                                b"addrtype" => addrtype = attr_val(&attr),
                                b"addr"     => addr     = attr_val(&attr),
                                _ => {}
                            }
                        }
                        if addrtype == "ipv4" || addrtype == "ipv6" {
                            host.ip = addr;
                        }
                    }
                    b"hostname" if in_host => {
                        let host = cur_host.as_mut().unwrap();
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"name" {
                                host.hostname = Some(attr_val(&attr));
                                break;
                            }
                        }
                    }
                    b"ports" if in_host => {
                        in_ports = true;
                    }
                    b"port" if in_ports => {
                        in_port = true;
                        let mut p = NmapPort::default();
                        for attr in e.attributes().flatten() {
                            match attr.key.as_ref() {
                                b"portid"   => {
                                    p.port = attr_val(&attr).parse().unwrap_or(0);
                                }
                                b"protocol" => p.protocol = attr_val(&attr),
                                _ => {}
                            }
                        }
                        cur_port = Some(p);
                    }
                    b"state" if in_port => {
                        let port = cur_port.as_mut().unwrap();
                        for attr in e.attributes().flatten() {
                            match attr.key.as_ref() {
                                b"state"  => port.state  = attr_val(&attr),
                                b"reason" => port.reason = Some(attr_val(&attr)),
                                _ => {}
                            }
                        }
                    }
                    b"service" if in_port => {
                        let port = cur_port.as_mut().unwrap();
                        let mut product    = String::new();
                        let mut version    = String::new();
                        let mut extra_info = String::new();
                        for attr in e.attributes().flatten() {
                            match attr.key.as_ref() {
                                b"name"      => port.service = Some(attr_val(&attr)),
                                b"product"   => product    = attr_val(&attr),
                                b"version"   => version    = attr_val(&attr),
                                b"extrainfo" => extra_info = attr_val(&attr),
                                _ => {}
                            }
                        }
                        // Build a clean version string like Nmap's plain output
                        let parts: Vec<&str> = [&product, &version, &extra_info]
                            .iter()
                            .map(|s| s.as_str())
                            .filter(|s| !s.is_empty())
                            .collect();
                        if !parts.is_empty() {
                            port.version_string = Some(parts.join(" "));
                        }
                        if !product.is_empty()    { port.product    = Some(product);    }
                        if !version.is_empty()    { port.version    = Some(version);    }
                        if !extra_info.is_empty() { port.extra_info = Some(extra_info); }
                    }
                    b"times" if in_port => {
                        // srtt is in microseconds in Nmap XML
                        let port = cur_port.as_mut().unwrap();
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"srtt" {
                                if let Ok(us) = attr_val(&attr).parse::<f64>() {
                                    port.rtt_ms = Some(us / 1000.0);
                                }
                                break;
                            }
                        }
                    }
                    b"os" if in_host => {
                        in_os = true;
                    }
                    b"osmatch" if in_os => {
                        let host = cur_host.as_mut().unwrap();
                        // Only take the first (best) match — Nmap sorts descending by accuracy
                        if host.os_guess.is_none() {
                            let mut name     = String::new();
                            let mut accuracy = 0u8;
                            for attr in e.attributes().flatten() {
                                match attr.key.as_ref() {
                                    b"name"     => name     = attr_val(&attr),
                                    b"accuracy" => accuracy = attr_val(&attr).parse().unwrap_or(0),
                                    _ => {}
                                }
                            }
                            if !name.is_empty() {
                                host.os_guess    = Some(name);
                                host.os_accuracy = Some(accuracy);
                            }
                        }
                    }
                    b"finished" => {
                        // <finished elapsed="3.21" .../>  in <runstats>
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"elapsed" {
                                result.elapsed_secs = attr_val(&attr).parse().ok();
                                break;
                            }
                        }
                    }
                    _ => {}
                }
            }

            Ok(Event::End(e)) => {
                match e.name().as_ref() {
                    b"port" if in_port => {
                        in_port = false;
                        if let (Some(p), Some(h)) = (cur_port.take(), cur_host.as_mut()) {
                            h.ports.push(p);
                        }
                    }
                    b"ports" => {
                        in_ports = false;
                    }
                    b"os" => {
                        in_os = false;
                    }
                    b"host" => {
                        in_host = false;
                        if let Some(h) = cur_host.take() {
                            result.hosts.push(h);
                        }
                    }
                    _ => {}
                }
            }

            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error: {e}")),
            _ => {}
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn attr_val(attr: &quick_xml::events::attributes::Attribute) -> String {
    String::from_utf8_lossy(&attr.value).into_owned()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_port() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun>
<host>
  <address addr="127.0.0.1" addrtype="ipv4"/>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open" reason="syn-ack"/>
      <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu Linux"/>
      <times srtt="500" rttvar="100" to="100000"/>
    </port>
    <port protocol="tcp" portid="80">
      <state state="closed" reason="reset"/>
      <service name="http"/>
    </port>
  </ports>
</host>
<runstats><finished elapsed="1.23"/></runstats>
</nmaprun>"#;

        let r = parse(xml).unwrap();
        assert_eq!(r.hosts.len(), 1);
        let h = &r.hosts[0];
        assert_eq!(h.ip, "127.0.0.1");
        assert_eq!(h.ports.len(), 2);

        let ssh = &h.ports[0];
        assert_eq!(ssh.port, 22);
        assert_eq!(ssh.state, "open");
        assert_eq!(ssh.service.as_deref(), Some("ssh"));
        assert_eq!(ssh.version_string.as_deref(), Some("OpenSSH 8.9p1 Ubuntu Linux"));
        assert!((ssh.rtt_ms.unwrap() - 0.5).abs() < 0.001);

        assert!((r.elapsed_secs.unwrap() - 1.23).abs() < 0.001);
    }

    #[test]
    fn handles_os_match() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun>
<host>
  <address addr="10.0.0.1" addrtype="ipv4"/>
  <ports/>
  <os>
    <osmatch name="Linux 5.4" accuracy="97"/>
    <osmatch name="Linux 4.15" accuracy="85"/>
  </os>
</host>
</nmaprun>"#;
        let r = parse(xml).unwrap();
        let h = &r.hosts[0];
        assert_eq!(h.os_guess.as_deref(), Some("Linux 5.4"));
        assert_eq!(h.os_accuracy, Some(97));
    }
}