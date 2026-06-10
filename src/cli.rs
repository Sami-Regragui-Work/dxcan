use clap::Parser;

#[derive(Parser)]
#[command(
    name = "dxcan",
    about = "Lightweight TCP port scanner — part of the DXC platform.",
    version
)]
pub struct Args {
    /// Target host (IP address or hostname)
    #[arg(short = 'H', long)]
    pub host: String,

    /// Ports: single (22,80), range (1-1024), mixed (22,8000-9000)
    #[arg(short, long)]
    pub ports: String,

    /// Initial per-port TCP timeout in seconds (adapts downward at runtime)
    #[arg(short, long, default_value_t = 0.5)]
    pub timeout: f64,

    /// Maximum concurrent connections
    #[arg(short, long, default_value_t = 500)]
    pub workers: usize,

    /// Output structured JSON
    #[arg(short, long)]
    pub json: bool,

    /// Show full latency precision in plain text output
    #[arg(long)]
    pub precise: bool,

    /// Show closed and filtered ports (default: open only)
    #[arg(long)]
    pub all: bool,
}