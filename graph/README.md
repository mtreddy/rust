# tinyros

A tiny version of ROS2, built with nothing but the Rust standard library.

Nodes, topics, publishers, subscriptions, callbacks, timers and a spin loop —
first between threads in one program, then between programs over UDP. The
names follow real ROS2 (`Context`, `create_publisher`, `spin`) so the ideas
carry over.

## Try it

Two nodes in one program, on two threads:

```
cargo run --example demo
```

Two separate programs finding each other over the network. Run each in its own
terminal:

```
TINYROS_TRANSPORT=udp cargo run --bin listener
TINYROS_TRANSPORT=udp cargo run --bin talker
```

Across two machines on the same network, tell each side where to look:

```
TINYROS_TRANSPORT=udp TINYROS_PEERS=192.168.1.20 cargo run --bin listener
```

Run the tests, including one that starts both programs and checks they find
each other:

```
cargo test
```

## Settings

| Variable | Meaning |
| --- | --- |
| `TINYROS_TRANSPORT` | `local` (default) or `udp` |
| `TINYROS_DOMAIN` | a number; two domains never hear each other, like `ROS_DOMAIN_ID` |
| `TINYROS_PEERS` | machines to look for nodes on, comma separated; localhost is always included |

## Writing a node

```rust
use std::time::Duration;
use tinyros::{spin, Context, StringMsg};

let ctx = Context::init();
let mut node = ctx.create_node("talker");

let chatter = node.create_publisher::<StringMsg>("/chatter");
node.create_timer(Duration::from_millis(500), move || {
    chatter.publish(&StringMsg::new("hello graph"));
});

node.create_subscription::<StringMsg, _>("/replies", |message| {
    println!("I heard: {}", message.data);
});

spin(&mut node);
```

## How it fits together

| File | What it does |
| --- | --- |
| `src/msg.rs` | turning messages into bytes and back |
| `src/bus.rs` | delivering messages between nodes in one program |
| `src/udp.rs` | finding other programs, and sending to them |
| `src/transport.rs` | the one enum that picks between those two |
| `src/node.rs` | `Context`, `Node`, publishers, subscriptions, timers |
| `src/executor.rs` | the spin loop |

The idea holding it together: **a node owns one channel, its inbox.**
Subscribing hands a copy of the sending end to the transport; publishing drops
a message into every inbox signed up for that topic; spinning is a loop that
waits on the inbox and runs the function for whatever arrives. Messages from a
socket are pushed into that same inbox by a background thread, which is why
the spin loop is identical whether the other node is a thread next door or a
program on another machine.

## Not done yet

Services (request and reply), parameters, logging to `/rosout`, quality of
service settings such as queue depth and guaranteed delivery, and a
`ros2`-style command line tool.
