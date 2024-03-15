use std::thread;
use std::time::Duration;
use std::sync::mpsc;

fn thread_wait() {
    let handle = thread::spawn(||{   
        for i in 0..10 {
            println!("hi thr num{}", i);
            thread::sleep(Duration::from_millis(1));
        }
    });

    for i in 1..5 {
        println!("Hi from main thread {}", i);
        thread::sleep(Duration::from_millis(1));
    }
    handle.join().unwrap();
}

fn thread_msg() {
    let(tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let val = String::from("Hi");
        tx.send(val).unwrap();
        //println!(" sent {}", val);
    });

    let rcvd = rx.recv().unwrap();
    println!("Receved {}", rcvd);
}
fn main() {
    thread_msg();
}
