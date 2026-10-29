//! Two nodes in one program, each spinning on its own thread.
//!
//!     cargo run --example demo

use std::thread;
use std::time::Duration;

use tinyros::{spin, Context, StringMsg};

fn main() {
    let ctx = Context::init();

    // The listener gets its own thread and just waits for messages.
    let mut listener = ctx.create_node("listener");
    listener.create_subscription::<StringMsg, _>("/chatter", |message| {
        println!("I heard: {}", message.data);
    });
    let listener_thread = thread::spawn(move || spin(&mut listener));

    // The talker publishes ten messages, then asks everyone to stop.
    let mut talker = ctx.create_node("talker");
    let chatter = talker.create_publisher::<StringMsg>("/chatter");
    let stopper = ctx.clone();
    let mut count = 0;

    talker.create_timer(Duration::from_millis(200), move || {
        count += 1;
        let message = StringMsg::new(&format!("hello graph {count}"));
        println!("Publishing: {}", message.data);
        chatter.publish(&message);

        if count == 10 {
            stopper.shutdown();
        }
    });

    spin(&mut talker);
    listener_thread.join().unwrap();
    println!("done");
}
