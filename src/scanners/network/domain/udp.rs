use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, UdpSocket as StdUdpSocket};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_resolver::proto::rr::{Name, RData, RecordType};
use hickory_resolver::proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex, Semaphore};
use tokio::time;

use super::DnsAnswer;

const SOCKET_BUF_BYTES: i32 = 4 * 1024 * 1024;
const SHARD_COUNT: usize = 32;
const READER_TASKS: usize = 4;

type PendingMap = HashMap<u16, oneshot::Sender<Vec<u8>>>;

pub struct UdpDnsClient {
    socket: Arc<UdpSocket>,
    resolvers: Vec<SocketAddr>,
    next_resolver: AtomicUsize,
    next_id: AtomicU16,
    timeout: Duration,
    inflight: Arc<Semaphore>,
    pending: Arc<[Mutex<PendingMap>; SHARD_COUNT]>,
}

fn shard_index(id: u16) -> usize {
    id as usize % SHARD_COUNT
}

fn bind_udp_socket() -> Result<StdUdpSocket, String> {
    let socket = StdUdpSocket::bind("0.0.0.0:0").map_err(|e| format!("udp bind: {e}"))?;
    let fd = socket.as_raw_fd();
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &SOCKET_BUF_BYTES as *const _ as *const _,
            std::mem::size_of_val(&SOCKET_BUF_BYTES) as _,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &SOCKET_BUF_BYTES as *const _ as *const _,
            std::mem::size_of_val(&SOCKET_BUF_BYTES) as _,
        );
    }
    socket
        .set_nonblocking(true)
        .map_err(|e| format!("udp nonblocking: {e}"))?;
    Ok(socket)
}

pub async fn build_udp_client(
    ips: &[IpAddr],
    timeout: Duration,
) -> Result<Arc<UdpDnsClient>, String> {
    if ips.is_empty() {
        return Err("no DNS resolvers configured".into());
    }
    let resolvers: Vec<SocketAddr> = ips.iter().map(|ip| SocketAddr::new(*ip, 53)).collect();
    let std_socket = bind_udp_socket()?;
    let socket = UdpSocket::from_std(std_socket).map_err(|e| format!("udp tokio: {e}"))?;
    let pending: Arc<[Mutex<PendingMap>; SHARD_COUNT]> =
        Arc::new(std::array::from_fn(|_| Mutex::new(PendingMap::new())));
    let client = Arc::new(UdpDnsClient {
        socket: Arc::new(socket),
        resolvers,
        next_resolver: AtomicUsize::new(0),
        next_id: AtomicU16::new(1),
        timeout,
        inflight: Arc::new(Semaphore::new(100)),
        pending,
    });
    for _ in 0..READER_TASKS {
        spawn_reader(client.clone());
    }
    Ok(client)
}

fn spawn_reader(client: Arc<UdpDnsClient>) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 512];
        loop {
            let Ok((n, _)) = client.socket.recv_from(&mut buf).await else {
                continue;
            };
            let Ok(msg) = Message::from_bytes(&buf[..n]) else {
                continue;
            };
            let id = msg.metadata.id;
            let shard = shard_index(id);
            let mut pending = client.pending[shard].lock().await;
            if let Some(tx) = pending.remove(&id) {
                let _ = tx.send(buf[..n].to_vec());
            }
        }
    });
}

impl UdpDnsClient {
    fn pick_resolver(&self) -> SocketAddr {
        let idx = self.next_resolver.fetch_add(1, Ordering::Relaxed);
        self.resolvers[idx % self.resolvers.len()]
    }

    fn next_query_id(&self) -> u16 {
        loop {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return id;
            }
        }
    }

    fn encode_query(fqdn: &str, id: u16) -> Result<Vec<u8>, String> {
        let trimmed = fqdn.trim().trim_end_matches('.');
        let name = Name::from_ascii(trimmed).map_err(|e| format!("{fqdn}: {e}"))?;
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(name, RecordType::A));
        msg.to_bytes().map_err(|e| format!("{fqdn}: encode: {e}"))
    }

    async fn send_and_wait(
        &self,
        fqdn: &str,
        id: u16,
        resolver: SocketAddr,
    ) -> Result<Vec<u8>, String> {
        let bytes = Self::encode_query(fqdn, id)?;
        let shard = shard_index(id);
        let (tx, rx) = oneshot::channel();
        self.pending[shard].lock().await.insert(id, tx);
        if self.socket.send_to(&bytes, resolver).await.is_err() {
            self.pending[shard].lock().await.remove(&id);
            return Err(format!("{fqdn}: send"));
        }
        match time::timeout(self.timeout, rx).await {
            Ok(Ok(payload)) => Ok(payload),
            Ok(Err(_)) => Err(format!("{fqdn}: dropped")),
            Err(_) => {
                self.pending[shard].lock().await.remove(&id);
                Err(format!("{fqdn}: timeout"))
            }
        }
    }

    pub async fn lookup_a(&self, fqdn: &str) -> Result<DnsAnswer, String> {
        let _permit = self
            .inflight
            .acquire()
            .await
            .map_err(|_| format!("{fqdn}: closed"))?;
        let id = self.next_query_id();
        let resolver = self.pick_resolver();
        match self.send_and_wait(fqdn, id, resolver).await {
            Ok(payload) => parse_a_response(&payload, fqdn),
            Err(first) if first.ends_with(": timeout") => {
                let id = self.next_query_id();
                let resolver = self.pick_resolver();
                match self.send_and_wait(fqdn, id, resolver).await {
                    Ok(payload) => parse_a_response(&payload, fqdn),
                    Err(_) => Err(first),
                }
            }
            Err(other) => Err(other),
        }
    }
}

fn parse_a_response(bytes: &[u8], fqdn: &str) -> Result<DnsAnswer, String> {
    let msg = Message::from_bytes(bytes).map_err(|e| format!("{fqdn}: decode: {e}"))?;
    match msg.metadata.response_code {
        ResponseCode::NoError => {}
        ResponseCode::NXDomain => return Err(format!("{fqdn}: nxdomain")),
        code => return Err(format!("{fqdn}: rcode {code}")),
    }
    let mut answer = DnsAnswer::default();
    for record in &msg.answers {
        match &record.data {
            RData::A(ip) => answer.a.push(IpAddr::V4(ip.0)),
            RData::CNAME(cname) => {
                if answer.cname.is_none() {
                    answer.cname = Some(cname.to_utf8());
                }
            }
            _ => {}
        }
        if answer.ttl.is_none() {
            answer.ttl = Some(record.ttl);
        }
    }
    if answer.has_records() {
        Ok(answer)
    } else {
        Err(format!("{fqdn}: no data"))
    }
}
