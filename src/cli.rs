use clap::{Parser, ValueEnum};

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum ScanMethod {
    Auto,
    Connect,
    Syn,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ScanMode {
    OpenOnly,
    Full,
}

#[derive(Parser)]
#[command(
    name = "dxcan",
    about = "Lightweight TCP port scanner — part of the DXC platform.",
    version
)]
pub struct Args {
    #[arg(short = 'H', long)]
    pub host: String,

    #[arg(short, long)]
    pub ports: String,

    #[arg(short, long, default_value_t = 0.5)]
    pub timeout: f64,

    #[arg(short, long, default_value_t = 500)]
    pub workers: usize,

    #[arg(long = "scan-method", value_enum, default_value_t = ScanMethod::Auto)]
    pub scan_method: ScanMethod,

    #[arg(long)]
    pub verify: bool,

    #[arg(long = "service-version", short = 's', alias = "sv")]
    pub service_version: bool,

    #[arg(long = "reverse-dns")]
    pub reverse_dns: bool,

    #[arg(long = "role-labels")]
    pub role_labels: bool,

    #[arg(long = "os", short = 'O')]
    pub os_detect: bool,

    #[arg(long = "product-hints")]
    pub product_hints: bool,

    #[arg(long = "os-rich")]
    pub os_rich: bool,

    #[arg(long = "sv-rich")]
    pub sv_rich: bool,

    #[arg(short, long)]
    pub json: bool,

    #[arg(long)]
    pub precise: bool,

    #[arg(long)]
    pub all: bool,

    #[arg(long)]
    pub debug: bool,
}
