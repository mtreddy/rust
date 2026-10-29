//! Nodes talking to each other inside one process.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tinyros::{spin, spin_once, Context, Int32, StringMsg};

/// A place for a callback to write down what it heard.
type Heard = Arc<Mutex<Vec<String>>>;

fn new_heard() -> Heard {
    Arc::new(Mutex::new(Vec::new()))
}

#[test]
fn a_published_message_reaches_the_subscriber() {
    let ctx = Context::init();

    let heard = new_heard();
    let mut listener = ctx.create_node("listener");
    let writer = Arc::clone(&heard);
    listener.create_subscription::<StringMsg, _>("/chatter", move |message| {
        writer.lock().unwrap().push(message.data);
    });

    let talker = ctx.create_node("talker");
    let chatter = talker.create_publisher::<StringMsg>("/chatter");
    chatter.publish(&StringMsg::new("hello"));

    spin_once(&mut listener);

    assert_eq!(*heard.lock().unwrap(), vec!["hello".to_string()]);
}

#[test]
fn two_listeners_both_get_the_message() {
    let ctx = Context::init();

    let heard_one = new_heard();
    let mut first = ctx.create_node("first");
    let writer = Arc::clone(&heard_one);
    first.create_subscription::<StringMsg, _>("/chatter", move |m| {
        writer.lock().unwrap().push(m.data);
    });

    let heard_two = new_heard();
    let mut second = ctx.create_node("second");
    let writer = Arc::clone(&heard_two);
    second.create_subscription::<StringMsg, _>("/chatter", move |m| {
        writer.lock().unwrap().push(m.data);
    });

    let talker = ctx.create_node("talker");
    talker
        .create_publisher::<StringMsg>("/chatter")
        .publish(&StringMsg::new("to everyone"));

    spin_once(&mut first);
    spin_once(&mut second);

    assert_eq!(*heard_one.lock().unwrap(), vec!["to everyone".to_string()]);
    assert_eq!(*heard_two.lock().unwrap(), vec!["to everyone".to_string()]);
}

#[test]
fn a_topic_name_without_a_slash_means_the_same_topic() {
    let ctx = Context::init();

    let heard = new_heard();
    let mut listener = ctx.create_node("listener");
    let writer = Arc::clone(&heard);
    listener.create_subscription::<StringMsg, _>("chatter", move |m| {
        writer.lock().unwrap().push(m.data);
    });

    let talker = ctx.create_node("talker");
    talker
        .create_publisher::<StringMsg>("/chatter")
        .publish(&StringMsg::new("slash or not"));

    spin_once(&mut listener);

    assert_eq!(*heard.lock().unwrap(), vec!["slash or not".to_string()]);
}

#[test]
fn nothing_arrives_when_the_two_sides_disagree_about_the_type() {
    let ctx = Context::init();

    let heard = new_heard();
    let mut listener = ctx.create_node("listener");
    let writer = Arc::clone(&heard);
    listener.create_subscription::<StringMsg, _>("/chatter", move |m| {
        writer.lock().unwrap().push(m.data);
    });

    // The listener wants text, but this node is sending numbers.
    let talker = ctx.create_node("talker");
    talker
        .create_publisher::<Int32>("/chatter")
        .publish(&Int32 { data: 42 });

    spin_once(&mut listener);

    assert!(heard.lock().unwrap().is_empty());
}

#[test]
fn a_message_on_another_topic_is_not_delivered() {
    let ctx = Context::init();

    let heard = new_heard();
    let mut listener = ctx.create_node("listener");
    let writer = Arc::clone(&heard);
    listener.create_subscription::<StringMsg, _>("/chatter", move |m| {
        writer.lock().unwrap().push(m.data);
    });

    let talker = ctx.create_node("talker");
    talker
        .create_publisher::<StringMsg>("/somewhere_else")
        .publish(&StringMsg::new("not for you"));

    spin_once(&mut listener);

    assert!(heard.lock().unwrap().is_empty());
}

#[test]
fn a_timer_fires_about_as_often_as_asked() {
    let ctx = Context::init();
    let mut node = ctx.create_node("ticker");

    let ticks = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&ticks);
    node.create_timer(Duration::from_millis(50), move || {
        counter.fetch_add(1, Ordering::Relaxed);
    });

    let started = Instant::now();
    while started.elapsed() < Duration::from_millis(500) {
        spin_once(&mut node);
    }

    // Ten are due in half a second. Machines are busy, so allow some slack.
    let count = ticks.load(Ordering::Relaxed);
    assert!((7..=11).contains(&count), "timer fired {count} times, expected about 10");
}

#[test]
fn shutdown_makes_spin_return() {
    let ctx = Context::init();
    let mut node = ctx.create_node("quitter");

    let stopper = ctx.clone();
    node.create_timer(Duration::from_millis(20), move || stopper.shutdown());

    let started = Instant::now();
    spin(&mut node);

    assert!(!ctx.is_running());
    assert!(started.elapsed() < Duration::from_secs(1), "spin took too long to return");
}

#[test]
fn a_node_hears_the_messages_it_publishes_itself() {
    let ctx = Context::init();
    let mut node = ctx.create_node("both_ends");

    let heard = new_heard();
    let writer = Arc::clone(&heard);
    node.create_subscription::<StringMsg, _>("/loop", move |m| {
        writer.lock().unwrap().push(m.data);
    });

    node.create_publisher::<StringMsg>("/loop")
        .publish(&StringMsg::new("talking to myself"));

    spin_once(&mut node);

    assert_eq!(*heard.lock().unwrap(), vec!["talking to myself".to_string()]);
}
