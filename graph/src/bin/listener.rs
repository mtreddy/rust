//! Prints whatever turns up on /chatter.
//!
//!     TINYROS_TRANSPORT=udp cargo run --bin listener

use tinyros::{spin, Context, StringMsg};

fn main() {
    let ctx = Context::init();
    let mut node = ctx.create_node("listener");

    node.create_subscription::<StringMsg, _>("/chatter", |message| {
        println!("I heard: {}", message.data);
    });

    println!("listener running, press Ctrl-C to stop");
    spin(&mut node);
}
