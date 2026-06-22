use clap::Parser;

#[derive(Parser)]
#[command(
    name = "dxcan-rustscan",
    about = "dxcan RustScan-backed scanner — fast port discovery then Nmap service detection.",
    version
)]
pub struct Args {
    /// Target host (IP address or hostname)
    #[arg(short = 'H', long)]
    pub host: String,

    /// Ports: single (22,80), range (1-1024), or - for all 65535
    #[arg(short, long, default_value = "1-65535")]
    pub ports: String,

    /// Enable OS detection (requires root / CAP_NET_RAW)
    #[arg(long)]
    pub os: bool,

    /// Enable service version detection (-sV) — produces VERSION column
    #[arg(long = "service-version", short = 's', alias = "sv")]
    pub service_version: bool,

    /// RustScan batch size — sockets opened per cycle (default: 5000)
    #[arg(long, default_value_t = 5000)]
    pub batch_size: u16,

    /// RustScan timeout per port in ms (default: 1500)
    #[arg(long, default_value_t = 1500)]
    pub rs_timeout: u32,

    /// Nmap timing template T0–T5 for the service scan phase (default: 4)
    #[arg(long, default_value_t = 4)]
    pub timing: u8,

    /// Service version detection intensity 0–9 (default: 5, only used with --service-version)
    #[arg(long, default_value_t = 5)]
    pub intensity: u8,

    /// Overall scan timeout in seconds (default: 300)
    #[arg(long, default_value_t = 300)]
    pub scan_timeout: u64,

    /// Output structured JSON
    #[arg(short, long)]
    pub json: bool,

    /// Show full latency precision in plain text output
    #[arg(long)]
    pub precise: bool,

    /// Show debug timing summary
    #[arg(long)]
    pub debug: bool,

    /// Print the commands that would be run, then exit
    #[arg(long)]
    pub dry_run: bool,

    /// Pass extra args verbatim to Nmap (after --)
    #[arg(last = true)]
    pub extra: Vec<String>,
}
