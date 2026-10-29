//! Nodes: the things that publish and subscribe.
//!
//! The whole design rests on one idea: **a node owns a single channel, its
//! inbox.** Subscribing to a topic means handing a copy of the inbox's sending
//! end to the transport and remembering which function to run for that topic.
//! Everything that arrives — from a thread next door or from a socket — lands
//! in that one inbox, which is why the spin loop in `executor.rs` is so short.

use std::collections::HashSet;
use std::marker::PhantomData;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::bus::{Bus, Envelope};
use crate::msg::Message;
use crate::transport::Transport;
use crate::udp::UdpTransport;

/// Never sleep longer than this in one go, even when there is nothing to do.
/// Waking up now and then is how a node notices that it has been asked to stop.
pub(crate) const LONGEST_NAP: Duration = Duration::from_millis(100);

/// The shared setup every node is made from: the way messages travel, and one
/// "please stop" flag that all of them watch.
#[derive(Clone)]
pub struct Context {
    transport: Transport,
    stop: Arc<AtomicBool>,
}

impl Context {
    /// Start up, reading three settings from the environment. In ROS2 this is
    /// `rclpy.init()`.
    ///
    /// * `TINYROS_TRANSPORT` — `local` (the default) or `udp`
    /// * `TINYROS_DOMAIN` — a number, so two groups can share a machine
    ///   without hearing each other. The same idea as `ROS_DOMAIN_ID`.
    /// * `TINYROS_PEERS` — machines to look for nodes on, comma separated.
    ///   Localhost is always included.
    pub fn init() -> Context {
        let transport = match std::env::var("TINYROS_TRANSPORT").as_deref() {
            Ok("udp") => Transport::Udp(UdpTransport::start(domain_from_env(), peers_from_env())),
            _ => Transport::Local(Arc::new(Bus::new())),
        };
        Context::with_transport(transport)
    }

    /// Start up with the transport chosen in code rather than by environment
    /// variable. Useful in tests.
    pub fn with_transport(transport: Transport) -> Context {
        Context {
            transport,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn create_node(&self, name: &str) -> Node {
        if name.is_empty() || name.contains('/') || name.contains(' ') {
            panic!("node name {name:?} should be a plain word, such as \"talker\"");
        }

        let (inbox_tx, inbox_rx) = mpsc::channel();
        Node {
            name: name.to_string(),
            transport: self.transport.clone(),
            inbox_tx,
            inbox_rx,
            subscriptions: Vec::new(),
            timers: Vec::new(),
            complained_about: HashSet::new(),
            stop: Arc::clone(&self.stop),
        }
    }

    /// Ask every node made from this context to stop spinning, and shut the
    /// transport's background threads down with them.
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::Relaxed);
        self.transport.stop();
    }

    pub fn is_running(&self) -> bool {
        !self.stop.load(Ordering::Relaxed)
    }
}

/// One participant in the graph.
pub struct Node {
    name: String,
    transport: Transport,
    /// Handed out to the transport, once per topic we listen to.
    inbox_tx: Sender<Envelope>,
    pub(crate) inbox_rx: Receiver<Envelope>,
    subscriptions: Vec<Subscription>,
    timers: Vec<Timer>,
    /// Topics we have already complained about, so a mismatch is reported once
    /// rather than for every message.
    complained_about: HashSet<String>,
    stop: Arc<AtomicBool>,
}

struct Subscription {
    topic: String,
    type_name: &'static str,
    /// Takes raw bytes, because by this point the message type has been dealt
    /// with. See `create_subscription`.
    callback: Box<dyn FnMut(&[u8]) + Send>,
}

struct Timer {
    period: Duration,
    next_fire: Instant,
    callback: Box<dyn FnMut() + Send>,
}

impl Node {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Start sending messages of type `T` on a topic.
    pub fn create_publisher<T: Message>(&self, topic: &str) -> Publisher<T> {
        let topic = resolve_topic(topic);
        self.transport.announce_publisher(&topic, T::type_name());
        Publisher {
            topic,
            transport: self.transport.clone(),
            message_type: PhantomData,
        }
    }

    /// Run `callback` every time a message of type `T` arrives on a topic.
    pub fn create_subscription<T, F>(&mut self, topic: &str, mut callback: F)
    where
        T: Message,
        F: FnMut(T) + Send + 'static,
    {
        let topic = resolve_topic(topic);

        // Only ask the transport once per topic, otherwise it would put two
        // copies of every message into our inbox.
        let already_listening = self.subscriptions.iter().any(|s| s.topic == topic);
        if !already_listening {
            self.transport
                .subscribe(&topic, T::type_name(), self.inbox_tx.clone());
        }

        // The inbox carries raw bytes, but the caller's function wants a real
        // message. Wrap it once, here. After this point nothing else in the
        // node has to know what type this topic carries.
        let node_name = self.name.clone();
        let topic_for_message = topic.clone();
        let wrapped = move |bytes: &[u8]| match T::from_bytes(bytes) {
            Some(message) => callback(message),
            None => eprintln!(
                "[{node_name}] could not read a message on {topic_for_message}, ignoring it"
            ),
        };

        self.subscriptions.push(Subscription {
            topic,
            type_name: T::type_name(),
            callback: Box::new(wrapped),
        });
    }

    /// Run `callback` every `period`.
    pub fn create_timer<F>(&mut self, period: Duration, callback: F)
    where
        F: FnMut() + Send + 'static,
    {
        self.timers.push(Timer {
            period,
            next_fire: Instant::now() + period,
            callback: Box::new(callback),
        });
    }

    /// Ask this node to stop spinning. Unlike `Context::shutdown` this affects
    /// only this node.
    pub fn request_stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    pub fn should_stop(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    /// How long we can afford to sleep before a timer needs us.
    pub(crate) fn time_until_next_timer(&self) -> Duration {
        let now = Instant::now();
        self.timers
            .iter()
            .map(|timer| timer.next_fire.saturating_duration_since(now))
            .min()
            .unwrap_or(LONGEST_NAP)
            .min(LONGEST_NAP)
    }

    pub(crate) fn fire_due_timers(&mut self) {
        let now = Instant::now();
        for timer in self.timers.iter_mut() {
            if now < timer.next_fire {
                continue;
            }
            (timer.callback)();

            // Normally the next time is simply one period later. If we fell so
            // far behind that it has already passed, start counting from now
            // instead of firing again and again trying to catch up.
            timer.next_fire += timer.period;
            if timer.next_fire <= now {
                timer.next_fire = now + timer.period;
            }
        }
    }

    /// Hand one delivered message to whoever asked for that topic.
    pub(crate) fn deliver(&mut self, envelope: &Envelope) {
        let node_name = &self.name;
        let complained_about = &mut self.complained_about;

        for subscription in self.subscriptions.iter_mut() {
            if subscription.topic != envelope.topic {
                continue;
            }

            // Both sides have to agree on what the topic carries. Real ROS2
            // refuses to connect the two ends at all; we notice here instead,
            // and say so once.
            if subscription.type_name != envelope.type_name {
                if complained_about.insert(envelope.topic.clone()) {
                    eprintln!(
                        "[{}] ignoring messages on {}: they are {}, but this node is expecting {}",
                        node_name, envelope.topic, envelope.type_name, subscription.type_name
                    );
                }
                continue;
            }

            (subscription.callback)(&envelope.bytes);
        }
    }
}

/// The sending end of a topic.
pub struct Publisher<T: Message> {
    topic: String,
    transport: Transport,
    /// Remembers the message type for the compiler; holds nothing at runtime.
    message_type: PhantomData<T>,
}

impl<T: Message> Publisher<T> {
    pub fn publish(&self, message: &T) {
        self.transport.publish(&Envelope {
            topic: self.topic.clone(),
            type_name: T::type_name().to_string(),
            bytes: message.to_bytes(),
        });
    }

    pub fn topic(&self) -> &str {
        &self.topic
    }
}

impl<T: Message> Clone for Publisher<T> {
    fn clone(&self) -> Self {
        Publisher {
            topic: self.topic.clone(),
            transport: self.transport.clone(),
            message_type: PhantomData,
        }
    }
}

/// Topics are written starting with a slash, so "chatter" and "/chatter" mean
/// the same thing.
fn resolve_topic(topic: &str) -> String {
    if topic.starts_with('/') {
        topic.to_string()
    } else {
        format!("/{topic}")
    }
}

/// Which domain to use, from `TINYROS_DOMAIN`.
fn domain_from_env() -> u16 {
    std::env::var("TINYROS_DOMAIN")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

/// Which machines to look for nodes on, from `TINYROS_PEERS`. Localhost is
/// always included, so a demo on one machine needs no setting at all.
fn peers_from_env() -> Vec<IpAddr> {
    let mut hosts = vec![IpAddr::from([127, 0, 0, 1])];
    if let Ok(value) = std::env::var("TINYROS_PEERS") {
        for host in value.split(',') {
            match host.trim().parse::<IpAddr>() {
                Ok(host) if !hosts.contains(&host) => hosts.push(host),
                Ok(_) => {}
                Err(_) => eprintln!("TINYROS_PEERS: {host:?} is not an address, skipping it"),
            }
        }
    }
    hosts
}
