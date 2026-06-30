use std::path::Path;

use crate::scanners::network::vhost::wordlist::{
    load_wordlist as load_vhost_wordlist, parse_wordlist_lines,
};

const DEV_WORDLIST: &str = include_str!("domain-smoke.txt");

pub use crate::scanners::network::vhost::wordlist::expand_hostname;

pub fn load_wordlist(path: Option<&Path>, dev: bool) -> Result<Vec<String>, String> {
    if dev && path.is_none() {
        return Ok(parse_wordlist_lines(DEV_WORDLIST));
    }
    load_vhost_wordlist(path, dev)
}
