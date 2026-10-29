//! The real test of the UDP transport: two separate programs, started knowing
//! nothing about each other, finding each other and talking.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// A domain of its own, so a demo running on the same machine cannot
/// interfere with the test.
const TEST_DOMAIN: &str = "7";
const PATIENCE: Duration = Duration::from_secs(10);

fn start(program: &str) -> Child {
    Command::new(program)
        .env("TINYROS_TRANSPORT", "udp")
        .env("TINYROS_DOMAIN", TEST_DOMAIN)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("could not start {program}: {e}"))
}

#[test]
fn two_programs_find_each_other_and_talk() {
    let mut listener = start(env!("CARGO_BIN_EXE_listener"));
    let mut talker = start(env!("CARGO_BIN_EXE_talker"));

    // Read the listener's output on another thread, so waiting for it can time
    // out instead of hanging for ever.
    let stdout = listener.stdout.take().unwrap();
    let (lines_tx, lines_rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if lines_tx.send(line).is_err() {
                return;
            }
        }
    });

    let mut heard = None;
    while let Ok(line) = lines_rx.recv_timeout(PATIENCE) {
        if line.starts_with("I heard:") {
            heard = Some(line);
            break;
        }
    }

    let _ = talker.kill();
    let _ = listener.kill();
    let _ = talker.wait();
    let _ = listener.wait();

    let heard = heard.expect("the listener never heard the talker");
    assert!(heard.contains("hello graph"), "unexpected line: {heard}");
}
