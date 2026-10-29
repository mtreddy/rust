//! Talking to nodes in other programs, over UDP.
//!
//! Two problems have to be solved: *finding* the other side, and *sending* to
//! it.
//!
//! **Finding** — every program shouts a short line of text, once every half
//! second, to a small range of well known ports on every host it has been told
//! about. The line says where to reach it and which topics it publishes and
//! listens to. Everyone who hears it writes the sender down in a peer table
//! and forgets about it again if it goes quiet. Real ROS2 does a much more
//! elaborate version of exactly this.
//!
//! We use a *range* of ports rather than one shared port because two programs
//! on one machine cannot bind the same port. Each program takes the first free
//! one and beacons are sent to all of them. DDS, underneath real ROS2, solves
//! it the same way.
//!
//! **Sending** — a message goes straight to the address of every peer that
//! said it was listening to that topic. One message, one datagram. If it is
//! lost, it is lost: that matches ROS2's default for sensor data. Messages for
//! nodes inside this same program never touch the network at all.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::bus::{Bus, Envelope};
use crate::msg::{put_string, take_string};

/// Where the discovery ports start. Domain 0 uses 7400..7410, domain 1 uses
/// 7420..7430, and so on, so two domains never hear each other.
const DISCOVERY_PORT_BASE: u16 = 7400;
const PORTS_PER_DOMAIN: u16 = 20;
/// How many programs can run in one domain on one machine.
const DISCOVERY_SLOTS: u16 = 10;

const BEACON_EVERY: Duration = Duration::from_millis(500);
const FORGET_PEER_AFTER: Duration = Duration::from_secs(3);
/// How long a receiving thread waits before checking whether to stop.
const RECEIVE_TIMEOUT: Duration = Duration::from_millis(200);

/// One message has to fit in one datagram.
pub const BIGGEST_MESSAGE: usize = 60_000;

/// Marks our datagrams so stray traffic on the port is ignored.
const FRAME_MAGIC: &[u8; 4] = b"TROS";
const BEACON_MAGIC: &str = "tinyros/1";

/// Another program we have heard from.
struct Peer {
    data_addr: SocketAddr,
    /// Topics it listens to. This is what decides where we send.
    subscribes_to: HashSet<String>,
    /// Topics it publishes. Not needed to deliver anything, but useful when
    /// you want to see what the graph looks like.
    publishes: Vec<(String, String)>,
    last_seen: Instant,
}

struct UdpInner {
    /// Messages go out of, and come in to, this socket.
    data_socket: UdpSocket,
    /// The address we tell other programs to send to.
    data_addr: SocketAddr,
    /// Beacons go out of, and come in to, this one.
    discovery_socket: UdpSocket,
    /// Every discovery port in this domain, ours included.
    discovery_ports: Vec<u16>,
    /// Machines to send beacons to. Localhost unless told otherwise.
    peer_hosts: Vec<IpAddr>,

    /// Hands messages to subscribers inside this program, exactly as the
    /// in-process transport does.
    bus: Bus,

    publishers: Mutex<Vec<(String, String)>>,
    subscriptions: Mutex<Vec<(String, String)>>,
    peers: Mutex<HashMap<SocketAddr, Peer>>,

    stopped: AtomicBool,
}

#[derive(Clone)]
pub struct UdpTransport {
    inner: Arc<UdpInner>,
}

impl UdpTransport {
    /// Open the sockets and start the three background threads: one listening
    /// for messages, one listening for beacons, one sending beacons.
    pub fn start(domain: u16, peer_hosts: Vec<IpAddr>) -> UdpTransport {
        let data_socket = UdpSocket::bind("0.0.0.0:0").expect("could not open a socket for messages");
        data_socket.set_read_timeout(Some(RECEIVE_TIMEOUT)).unwrap();
        let data_port = data_socket.local_addr().unwrap().port();

        let (discovery_socket, discovery_ports) = open_discovery_socket(domain);
        discovery_socket.set_read_timeout(Some(RECEIVE_TIMEOUT)).unwrap();
        // So that a broadcast address such as 192.168.1.255 can be used.
        let _ = discovery_socket.set_broadcast(true);

        let inner = Arc::new(UdpInner {
            data_socket,
            data_addr: address_others_can_reach(data_port),
            discovery_socket,
            discovery_ports,
            peer_hosts,
            bus: Bus::new(),
            publishers: Mutex::new(Vec::new()),
            subscriptions: Mutex::new(Vec::new()),
            peers: Mutex::new(HashMap::new()),
            stopped: AtomicBool::new(false),
        });

        for job in [receive_messages, receive_beacons, send_beacons] {
            let inner = Arc::clone(&inner);
            thread::spawn(move || job(inner));
        }

        UdpTransport { inner }
    }

    /// Send to every peer listening to this topic, and to any node in this
    /// same program.
    pub fn publish(&self, envelope: &Envelope) {
        self.inner.bus.publish(envelope);

        let frame = encode_frame(envelope);
        if frame.len() > BIGGEST_MESSAGE {
            eprintln!(
                "message on {} is {} bytes, too big to send (the limit is {BIGGEST_MESSAGE})",
                envelope.topic,
                frame.len()
            );
            return;
        }

        let peers = self.inner.peers.lock().unwrap();
        for peer in peers.values() {
            if peer.data_addr == self.inner.data_addr {
                continue; // that is us; local nodes were handled above
            }
            if !peer.subscribes_to.contains(&envelope.topic) {
                continue;
            }
            let _ = self.inner.data_socket.send_to(&frame, peer.data_addr);
        }
    }

    pub fn subscribe(&self, topic: &str, type_name: &str, inbox: Sender<Envelope>) {
        self.inner.bus.subscribe(topic, inbox);
        remember(&self.inner.subscriptions, topic, type_name);
        // Tell everyone straight away rather than making them wait for the
        // next beacon.
        send_beacon_now(&self.inner);
    }

    pub fn announce_publisher(&self, topic: &str, type_name: &str) {
        remember(&self.inner.publishers, topic, type_name);
        send_beacon_now(&self.inner);
    }

    pub fn stop(&self) {
        self.inner.stopped.store(true, Ordering::Relaxed);
    }

    /// Every topic somebody out there is publishing or listening to. The
    /// beginnings of `ros2 topic list`.
    pub fn known_topics(&self) -> Vec<String> {
        let mut names: HashSet<String> = HashSet::new();
        for (topic, _) in self.inner.publishers.lock().unwrap().iter() {
            names.insert(topic.clone());
        }
        for peer in self.inner.peers.lock().unwrap().values() {
            names.extend(peer.subscribes_to.iter().cloned());
            names.extend(peer.publishes.iter().map(|(topic, _)| topic.clone()));
        }
        let mut names: Vec<String> = names.into_iter().collect();
        names.sort();
        names
    }
}

// ---------------------------------------------------------------------------
// The three background threads
// ---------------------------------------------------------------------------

/// Messages arriving from other programs go into the same bus that local
/// messages use, so a node cannot tell the difference.
fn receive_messages(inner: Arc<UdpInner>) {
    let mut buffer = vec![0u8; BIGGEST_MESSAGE + 1024];
    while !inner.stopped.load(Ordering::Relaxed) {
        let size = match inner.data_socket.recv_from(&mut buffer) {
            Ok((size, _from)) => size,
            Err(_) => continue, // timed out, or something we cannot help
        };
        if let Some(envelope) = decode_frame(&buffer[..size]) {
            inner.bus.publish(&envelope);
        }
    }
}

fn receive_beacons(inner: Arc<UdpInner>) {
    let mut buffer = vec![0u8; 8192];
    while !inner.stopped.load(Ordering::Relaxed) {
        let (size, from) = match inner.discovery_socket.recv_from(&mut buffer) {
            Ok(result) => result,
            Err(_) => continue,
        };

        let text = match std::str::from_utf8(&buffer[..size]) {
            Ok(text) => text,
            Err(_) => continue,
        };
        let peer = match parse_beacon(text) {
            Some(peer) => peer,
            None => continue,
        };
        if peer.data_addr == inner.data_addr {
            continue; // our own beacon coming back to us
        }

        let is_new = {
            let mut peers = inner.peers.lock().unwrap();
            peers.insert(peer.data_addr, peer).is_none()
        };

        // Somebody just appeared: answer at once so they learn about us
        // without waiting for our next beacon.
        if is_new {
            let _ = inner
                .discovery_socket
                .send_to(beacon_text(&inner).as_bytes(), from);
        }
    }
}

fn send_beacons(inner: Arc<UdpInner>) {
    while !inner.stopped.load(Ordering::Relaxed) {
        forget_quiet_peers(&inner);
        send_beacon_now(&inner);
        thread::sleep(BEACON_EVERY);
    }
}

fn send_beacon_now(inner: &UdpInner) {
    let text = beacon_text(inner);
    for host in &inner.peer_hosts {
        for port in &inner.discovery_ports {
            let _ = inner
                .discovery_socket
                .send_to(text.as_bytes(), SocketAddr::new(*host, *port));
        }
    }
}

fn forget_quiet_peers(inner: &UdpInner) {
    let now = Instant::now();
    inner
        .peers
        .lock()
        .unwrap()
        .retain(|_, peer| now.duration_since(peer.last_seen) < FORGET_PEER_AFTER);
}

// ---------------------------------------------------------------------------
// The beacon: plain text on purpose, so you can watch it with `nc -ul 7400`
// ---------------------------------------------------------------------------

fn beacon_text(inner: &UdpInner) -> String {
    let mut text = format!("{BEACON_MAGIC} {}\n", inner.data_addr);
    for (topic, type_name) in inner.publishers.lock().unwrap().iter() {
        text.push_str(&format!("PUB {topic} {type_name}\n"));
    }
    for (topic, type_name) in inner.subscriptions.lock().unwrap().iter() {
        text.push_str(&format!("SUB {topic} {type_name}\n"));
    }
    text
}

fn parse_beacon(text: &str) -> Option<Peer> {
    let mut lines = text.lines();

    let mut header = lines.next()?.split_whitespace();
    if header.next()? != BEACON_MAGIC {
        return None;
    }
    let data_addr: SocketAddr = header.next()?.parse().ok()?;

    let mut peer = Peer {
        data_addr,
        subscribes_to: HashSet::new(),
        publishes: Vec::new(),
        last_seen: Instant::now(),
    };

    for line in lines {
        let mut words = line.split_whitespace();
        match (words.next(), words.next(), words.next()) {
            (Some("SUB"), Some(topic), Some(_type_name)) => {
                peer.subscribes_to.insert(topic.to_string());
            }
            (Some("PUB"), Some(topic), Some(type_name)) => {
                peer.publishes.push((topic.to_string(), type_name.to_string()));
            }
            _ => {}
        }
    }

    Some(peer)
}

// ---------------------------------------------------------------------------
// The message frame: magic, topic, type, then the message itself
// ---------------------------------------------------------------------------

fn encode_frame(envelope: &Envelope) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(FRAME_MAGIC);
    put_string(&mut out, &envelope.topic);
    put_string(&mut out, &envelope.type_name);
    out.extend_from_slice(&envelope.bytes);
    out
}

fn decode_frame(bytes: &[u8]) -> Option<Envelope> {
    if bytes.len() < FRAME_MAGIC.len() || &bytes[..FRAME_MAGIC.len()] != FRAME_MAGIC {
        return None;
    }
    let mut pos = FRAME_MAGIC.len();
    let topic = take_string(bytes, &mut pos)?;
    let type_name = take_string(bytes, &mut pos)?;
    Some(Envelope {
        topic,
        type_name,
        bytes: bytes[pos..].to_vec(),
    })
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn remember(list: &Mutex<Vec<(String, String)>>, topic: &str, type_name: &str) {
    let mut list = list.lock().unwrap();
    let entry = (topic.to_string(), type_name.to_string());
    if !list.contains(&entry) {
        list.push(entry);
    }
}

/// Take the first free discovery port in this domain, and work out the full
/// list so beacons can be sent to all of them.
fn open_discovery_socket(domain: u16) -> (UdpSocket, Vec<u16>) {
    let base = DISCOVERY_PORT_BASE + domain * PORTS_PER_DOMAIN;
    let ports: Vec<u16> = (0..DISCOVERY_SLOTS).map(|slot| base + slot).collect();

    for port in &ports {
        if let Ok(socket) = UdpSocket::bind(("0.0.0.0", *port)) {
            return (socket, ports);
        }
    }

    panic!(
        "all {DISCOVERY_SLOTS} discovery ports for domain {domain} are taken \
         ({base}..{}); use a different TINYROS_DOMAIN",
        base + DISCOVERY_SLOTS
    );
}

/// Which of our own addresses other machines should send to.
fn address_others_can_reach(port: u16) -> SocketAddr {
    // Connecting a UDP socket sends nothing at all. It only asks the operating
    // system which of our addresses it would use to reach the outside world.
    if let Ok(probe) = UdpSocket::bind("0.0.0.0:0") {
        if probe.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = probe.local_addr() {
                return SocketAddr::new(addr.ip(), port);
            }
        }
    }
    SocketAddr::from(([127, 0, 0, 1], port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_survives_the_round_trip() {
        let before = Envelope {
            topic: "/chatter".to_string(),
            type_name: "std_msgs/String".to_string(),
            bytes: vec![1, 2, 3, 4],
        };
        let after = decode_frame(&encode_frame(&before)).unwrap();
        assert_eq!(after.topic, before.topic);
        assert_eq!(after.type_name, before.type_name);
        assert_eq!(after.bytes, before.bytes);
    }

    #[test]
    fn rubbish_on_the_port_is_ignored() {
        assert!(decode_frame(b"").is_none());
        assert!(decode_frame(b"hello").is_none());
        // Right magic, but then it stops short.
        assert!(decode_frame(b"TROS\xff\xff\xff\xff").is_none());
    }

    #[test]
    fn a_beacon_says_who_is_listening_to_what() {
        let text = "tinyros/1 192.168.1.20:45001\n\
                    PUB /chatter std_msgs/String\n\
                    SUB /numbers std_msgs/Int32\n";
        let peer = parse_beacon(text).unwrap();

        assert_eq!(peer.data_addr.port(), 45001);
        assert!(peer.subscribes_to.contains("/numbers"));
        assert!(!peer.subscribes_to.contains("/chatter"));
        assert_eq!(peer.publishes.len(), 1);
    }

    #[test]
    fn a_beacon_from_something_else_is_ignored() {
        assert!(parse_beacon("").is_none());
        assert!(parse_beacon("hello there\n").is_none());
        assert!(parse_beacon("tinyros/1 not-an-address\n").is_none());
    }

    #[test]
    fn a_beacon_with_no_topics_is_still_a_peer() {
        let peer = parse_beacon("tinyros/1 127.0.0.1:9000\n").unwrap();
        assert!(peer.subscribes_to.is_empty());
    }
}
