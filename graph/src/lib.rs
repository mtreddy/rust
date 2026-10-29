//! A tiny version of ROS2, using nothing but the standard library.
//!
//! The names here follow real ROS2 (`Context`, `Node`, publishers,
//! subscriptions, `spin`) so that what you learn carries over.
//!
//! ```no_run
//! use std::time::Duration;
//! use tinyros::{spin, Context, StringMsg};
//!
//! let ctx = Context::init();
//! let mut node = ctx.create_node("talker");
//!
//! let chatter = node.create_publisher::<StringMsg>("/chatter");
//! node.create_timer(Duration::from_millis(500), move || {
//!     chatter.publish(&StringMsg::new("hello graph"));
//! });
//!
//! spin(&mut node);
//! ```

pub mod bus;
pub mod executor;
pub mod msg;
pub mod node;
pub mod transport;
pub mod udp;

pub use bus::{Bus, Envelope};
pub use executor::{spin, spin_once};
pub use msg::{Int32, Message, Point, StringMsg};
pub use node::{Context, Node, Publisher};
pub use transport::Transport;
pub use udp::UdpTransport;
