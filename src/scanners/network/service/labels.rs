pub fn product_hint_from_banner(port: u16, text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_lowercase();
    if lower.contains("ubuntu") {
        return Some(format!("{port}/tcp Ubuntu ({trimmed})"));
    }
    if lower.contains("debian") {
        return Some(format!("{port}/tcp Debian ({trimmed})"));
    }
    if lower.contains("centos") || lower.contains("red hat") || lower.contains("rhel") {
        return Some(format!("{port}/tcp Linux ({trimmed})"));
    }
    if lower.starts_with("ssh-") {
        return Some(format!("{port}/tcp {trimmed}"));
    }
    if lower.starts_with("server:") || lower.contains("apache") || lower.contains("nginx") {
        return Some(format!("{port}/tcp {trimmed}"));
    }
    None
}

pub fn service_role_label(service: &str) -> Option<&'static str> {
    match service {
        "ssh" => Some("An ssh server is running on this port"),
        "http" | "https" | "http-alt" | "https-alt" => {
            Some("A web server is running on this port")
        }
        "ftp" => Some("An ftp server is running on this port"),
        "smtp" | "smtp-submission" | "smtps" => Some("An smtp server is running on this port"),
        "pop3" | "pop3s" | "imap" | "imaps" => Some("A mail server is running on this port"),
        "mysql" | "postgresql" | "mssql" | "mongodb" | "redis" => {
            Some("A database server is running on this port")
        }
        _ => None,
    }
}

pub fn port_label(port: u16) -> Option<&'static str> {
    match port {
        21 => Some("ftp"),
        22 => Some("ssh"),
        23 => Some("telnet"),
        25 => Some("smtp"),
        53 => Some("dns"),
        80 => Some("http"),
        110 => Some("pop3"),
        111 => Some("rpcbind"),
        143 => Some("imap"),
        389 => Some("ldap"),
        443 => Some("https"),
        445 => Some("smb"),
        465 => Some("smtps"),
        587 => Some("smtp-submission"),
        631 => Some("ipp"),
        636 => Some("ldaps"),
        993 => Some("imaps"),
        995 => Some("pop3s"),
        1433 => Some("mssql"),
        1521 => Some("oracle"),
        2375 => Some("docker"),
        2376 => Some("docker-tls"),
        2379 => Some("etcd"),
        2181 => Some("zookeeper"),
        3000 => Some("http-alt"),
        3306 => Some("mysql"),
        3389 => Some("rdp"),
        4369 => Some("epmd"),
        5432 => Some("postgresql"),
        5672 => Some("amqp"),
        5900 => Some("vnc"),
        6379 => Some("redis"),
        6443 => Some("kubernetes-api"),
        8080 => Some("http-alt"),
        8443 => Some("https-alt"),
        8888 => Some("http-alt"),
        9000 => Some("http-alt"),
        9090 => Some("prometheus"),
        9092 => Some("kafka"),
        9200 => Some("elasticsearch"),
        9300 => Some("elasticsearch-cluster"),
        10250 => Some("kubelet"),
        11211 => Some("memcached"),
        15672 => Some("rabbitmq-mgmt"),
        27017 => Some("mongodb"),
        50000 => Some("db2"),
        _ => None,
    }
}
