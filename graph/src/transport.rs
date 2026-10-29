//! Where messages actually travel.
//!
//! A node does not care whether the other side is a thread in this process or
//! a program on another machine, so both ways live behind this one enum.
//! Adding a third way to move bytes means adding a variant and one arm to each
//! `match` below.

use std::sync::mpsc::Sender;
use std::sync::Arc;

use crate::bus::{Bus, Envelope};
use crate::udp::UdpTransport;

#[derive(Clone)]
pub enum Transport {
    /// Between nodes in this program.
    Local(Arc<Bus>),
    /// Between programs, over the network.
    Udp(UdpTransport),
}

impl Transport {
    pub fn publish(&self, envelope: &Envelope) {
        match self {
            Transport::Local(bus) => bus.publish(envelope),
            Transport::Udp(udp) => udp.publish(envelope),
        }
    }

    pub fn subscribe(&self, topic: &str, type_name: &str, inbox: Sender<Envelope>) {
        match self {
            Transport::Local(bus) => bus.subscribe(topic, inbox),
            Transport::Udp(udp) => udp.subscribe(topic, type_name, inbox),
        }
    }

    /// Say that we are about to publish on a topic. Nobody needs telling
    /// inside one program; over the network it is how others learn to expect
    /// us.
    pub fn announce_publisher(&self, topic: &str, type_name: &str) {
        match self {
            Transport::Local(_) => {}
            Transport::Udp(udp) => udp.announce_publisher(topic, type_name),
        }
    }

    pub fn stop(&self) {
        match self {
            Transport::Local(_) => {}
            Transport::Udp(udp) => udp.stop(),
        }
    }
}
