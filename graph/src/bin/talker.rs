//! Publishes a line of text on /chatter twice a second.
//!
//!     cargo run --bin talker                              (on its own)
//!     TINYROS_TRANSPORT=udp cargo run --bin talker        (talks to other programs)

use std::time::Duration;

use tinyros::{spin, Context, StringMsg};

fn main() {
    let ctx = Context::init();
    let mut node = ctx.create_node("talker");

    let chatter = node.create_publisher::<StringMsg>("/chatter");
    let mut count = 0;

    node.create_timer(Duration::from_millis(500), move || {
        count += 1;
        let message = StringMsg::new(&format!("hello graph {count}"));
        println!("Publishing: {}", message.data);
        chatter.publish(&message);
    });

    println!("talker running, press Ctrl-C to stop");
    spin(&mut node);
}
