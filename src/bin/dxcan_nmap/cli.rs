use clap::Parser;

#[derive(Parser)]
#[command(
    name = "dxcan-nmap",
    about = "dxcan Nmap-backed scanner — wraps Nmap, emits dxcan JSON/text output.",
    version
)]
pub struct Args {
    /// Target host (IP address or hostname)
    #[arg(short = 'H', long)]
    pub host: String,

    /// Ports: single (22,80), range (1-1024), mixed (22,8000-9000), or - for all
    #[arg(short, long, default_value = "1-65535")]
    pub ports: String,

    /// Enable OS detection (requires root / CAP_NET_RAW)
    #[arg(long)]
    pub os: bool,

    /// Enable service version detection (-sV) — produces VERSION and CONFIDENCE columns
    #[arg(long = "service-version", short = 's', alias = "sv")]
    pub service_version: bool,

    /// Nmap timing template T0–T5 (default: 4)
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

    /// Show closed and filtered ports too (default: open only)
    #[arg(long)]
    pub all: bool,

    /// Show debug timing summary
    #[arg(long)]
    pub debug: bool,

    /// Print the Nmap command that would be run, then exit
    #[arg(long)]
    pub dry_run: bool,

    /// Pass extra args verbatim to Nmap (after --)
    #[arg(last = true)]
    pub extra: Vec<String>,
}
