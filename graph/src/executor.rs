//! The spin loop.
//!
//! This is the part people usually imagine is complicated. It is not: wait for
//! something to arrive in the node's inbox, run the function for that topic,
//! then run any timer that has come due. That is an executor.

use std::sync::mpsc::RecvTimeoutError;

use crate::node::Node;

/// Keep handling messages and timers until the node is asked to stop.
/// The same as `rclpy.spin(node)`.
pub fn spin(node: &mut Node) {
    while !node.should_stop() {
        spin_once(node);
    }
}

/// One pass: handle at most one message, then any timers that are due.
pub fn spin_once(node: &mut Node) {
    // Sleeping exactly until the next timer is what makes timers work without
    // any machinery of their own.
    let nap = node.time_until_next_timer();

    match node.inbox_rx.recv_timeout(nap) {
        Ok(envelope) => node.deliver(&envelope),
        // Nothing arrived in time, which is fine: a timer is probably due.
        Err(RecvTimeoutError::Timeout) => {}
        // Every sender is gone, so no message can ever arrive again.
        Err(RecvTimeoutError::Disconnected) => node.request_stop(),
    }

    node.fire_due_timers();
}
