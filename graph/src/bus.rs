//! Delivering messages between nodes in the same process.
//!
//! The bus is a post office. Every node hands it the sending end of its inbox
//! and says which topics it cares about; publishing then means dropping a copy
//! of the message into every inbox signed up for that topic.

use std::collections::HashMap;
use std::sync::mpsc::Sender;
use std::sync::Mutex;

/// One message on its way somewhere, with enough on the outside of it to be
/// delivered and understood.
#[derive(Debug, Clone)]
pub struct Envelope {
    pub topic: String,
    /// The type the sender believes it is sending, e.g. "std_msgs/String".
    pub type_name: String,
    pub bytes: Vec<u8>,
}

#[derive(Default)]
pub struct Bus {
    /// topic name -> the inbox of every node listening to it
    topics: Mutex<HashMap<String, Vec<Sender<Envelope>>>>,
}

impl Bus {
    pub fn new() -> Bus {
        Bus::default()
    }

    /// Start delivering messages on `topic` to this inbox.
    pub fn subscribe(&self, topic: &str, inbox: Sender<Envelope>) {
        let mut topics = self.topics.lock().unwrap();
        topics.entry(topic.to_string()).or_default().push(inbox);
    }

    /// Drop a copy of the message into every inbox listening to its topic.
    pub fn publish(&self, envelope: &Envelope) {
        let mut topics = self.topics.lock().unwrap();
        let listeners = match topics.get_mut(&envelope.topic) {
            Some(listeners) => listeners,
            // Nobody is listening. In ROS2 this is normal and not an error:
            // messages are not kept for someone who might arrive later.
            None => return,
        };

        // A send only fails when that node is gone, so forget about it.
        listeners.retain(|inbox| inbox.send(envelope.clone()).is_ok());
    }

    /// Every topic anybody is listening to. Handy for tests and for seeing
    /// what the graph looks like.
    pub fn topic_names(&self) -> Vec<String> {
        let topics = self.topics.lock().unwrap();
        let mut names: Vec<String> = topics.keys().cloned().collect();
        names.sort();
        names
    }
}
