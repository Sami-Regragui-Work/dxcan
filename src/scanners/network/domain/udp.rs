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
const MIN_LANES: usize = 4;
const MAX_LANES: usize = 8;

type PendingMap = HashMap<u16, oneshot::Sender<Vec<u8>>>;

struct UdpLane {
    socket: Arc<UdpSocket>,
    pending: Arc<Mutex<PendingMap>>,
}

pub struct UdpDnsClient {
    lanes: Arc<Vec<UdpLane>>,
    resolvers: Vec<SocketAddr>,
    next_resolver: AtomicUsize,
    next_lane: AtomicUsize,
    next_id: AtomicU16,
    timeout: Duration,
    max_retries: u8,
    inflight: Arc<Semaphore>,
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

async fn build_lane() -> Result<UdpLane, String> {
    let std_socket = bind_udp_socket()?;
    let socket = Arc::new(UdpSocket::from_std(std_socket).map_err(|e| format!("udp tokio: {e}"))?);
    Ok(UdpLane {
        socket: socket.clone(),
        pending: Arc::new(Mutex::new(PendingMap::new())),
    })
}

fn lane_count_for(resolver_count: usize) -> usize {
    resolver_count.clamp(MIN_LANES, MAX_LANES)
}

pub async fn build_udp_client(
    ips: &[IpAddr],
    timeout: Duration,
    max_inflight: usize,
    max_retries: u8,
) -> Result<Arc<UdpDnsClient>, String> {
    if ips.is_empty() {
        return Err("no DNS resolvers configured".into());
    }
    let resolvers: Vec<SocketAddr> = ips.iter().map(|ip| SocketAddr::new(*ip, 53)).collect();
    let lane_count = lane_count_for(resolvers.len());
    let mut lanes = Vec::with_capacity(lane_count);
    for _ in 0..lane_count {
        lanes.push(build_lane().await?);
    }
    let lanes = Arc::new(lanes);
    for lane in lanes.iter() {
        spawn_reader(lane.socket.clone(), lane.pending.clone());
    }
    Ok(Arc::new(UdpDnsClient {
        lanes,
        resolvers,
        next_resolver: AtomicUsize::new(0),
        next_lane: AtomicUsize::new(0),
        next_id: AtomicU16::new(1),
        timeout,
        max_retries: max_retries.max(1),
        inflight: Arc::new(Semaphore::new(max_inflight.max(1))),
    }))
}

fn spawn_reader(socket: Arc<UdpSocket>, pending: Arc<Mutex<PendingMap>>) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 512];
        loop {
            let Ok((n, _)) = socket.recv_from(&mut buf).await else {
                continue;
            };
            let Ok(msg) = Message::from_bytes(&buf[..n]) else {
                continue;
            };
            let id = msg.metadata.id;
            let mut map = pending.lock().await;
            if let Some(tx) = map.remove(&id) {
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

    fn pick_lane(&self) -> usize {
        let lane_count = self.lanes.len().max(1);
        self.next_lane.fetch_add(1, Ordering::Relaxed) % lane_count
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
        lane_idx: usize,
    ) -> Result<Vec<u8>, String> {
        let lane = &self.lanes[lane_idx];
        let bytes = Self::encode_query(fqdn, id)?;
        let (tx, rx) = oneshot::channel();
        lane.pending.lock().await.insert(id, tx);
        if lane.socket.send_to(&bytes, resolver).await.is_err() {
            lane.pending.lock().await.remove(&id);
            return Err(format!("{fqdn}: send"));
        }
        match time::timeout(self.timeout, rx).await {
            Ok(Ok(payload)) => Ok(payload),
            Ok(Err(_)) => Err(format!("{fqdn}: dropped")),
            Err(_) => {
                lane.pending.lock().await.remove(&id);
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
        let attempts = self.max_retries.max(1);
        let mut last_err = String::new();
        for attempt in 0..attempts {
            let lane_idx = self.pick_lane();
            let id = self.next_query_id();
            let resolver = self.pick_resolver();
            let timeout = if attempt == 0 {
                self.timeout
            } else {
                Duration::from_secs_f64(self.timeout.as_secs_f64() / 2.0)
                    .max(Duration::from_millis(200))
            };
            match time::timeout(
                timeout,
                self.send_and_wait(fqdn, id, resolver, lane_idx),
            )
            .await
            {
                Ok(Ok(payload)) => return parse_a_response(&payload, fqdn),
                Ok(Err(err)) => last_err = err,
                Err(_) => last_err = format!("{fqdn}: timeout"),
            }
        }
        Err(if last_err.is_empty() {
            format!("{fqdn}: failed")
        } else {
            last_err
        })
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
