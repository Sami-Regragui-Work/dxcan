use clap::Parser;

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

    #[arg(long = "service-version", short = 's', alias = "sv")]
    pub service_version: bool,

    #[arg(long = "reverse-dns")]
    pub reverse_dns: bool,

    #[arg(long = "role-labels")]
    pub role_labels: bool,

    #[arg(long)]
    pub rich: bool,

    #[arg(short, long)]
    pub json: bool,

    #[arg(long)]
    pub precise: bool,

    #[arg(long)]
    pub all: bool,

    #[arg(long)]
    pub debug: bool,
}
