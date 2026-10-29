//! Every message must survive the trip to bytes and back, and must refuse
//! bytes that do not make sense.

use tinyros::msg::{take_string, take_u32};
use tinyros::{Int32, Message, Point, StringMsg};

#[test]
fn string_survives_the_round_trip() {
    let before = StringMsg::new("hello graph");
    let after = StringMsg::from_bytes(&before.to_bytes()).unwrap();
    assert_eq!(before, after);
}

#[test]
fn empty_string_is_fine() {
    let before = StringMsg::new("");
    let after = StringMsg::from_bytes(&before.to_bytes()).unwrap();
    assert_eq!(before, after);
}

#[test]
fn int_survives_the_round_trip() {
    for value in [0, 1, -1, i32::MAX, i32::MIN] {
        let before = Int32 { data: value };
        let after = Int32::from_bytes(&before.to_bytes()).unwrap();
        assert_eq!(before, after);
    }
}

#[test]
fn a_message_with_several_fields_survives_the_round_trip() {
    let before = Point { x: 1.5, y: -2.25, z: 0.0 };
    let after = Point::from_bytes(&before.to_bytes()).unwrap();
    assert_eq!(before, after);
}

#[test]
fn type_names_are_what_we_expect() {
    assert_eq!(StringMsg::type_name(), "std_msgs/String");
    assert_eq!(Int32::type_name(), "std_msgs/Int32");
}

#[test]
fn cut_short_bytes_give_none_instead_of_panicking() {
    let full = StringMsg::new("hello graph").to_bytes();
    for length in 0..full.len() {
        assert!(
            StringMsg::from_bytes(&full[..length]).is_none(),
            "{length} bytes should not be enough for this message"
        );
    }
    assert!(Int32::from_bytes(&[1, 2]).is_none());
    assert!(Point::from_bytes(&[]).is_none());
}

#[test]
fn a_lie_about_the_length_gives_none() {
    // Claims the text is 1000 bytes long, but only 2 follow.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&1000u32.to_le_bytes());
    bytes.extend_from_slice(b"hi");
    assert!(StringMsg::from_bytes(&bytes).is_none());
}

#[test]
fn reading_moves_the_position_along() {
    let mut bytes = Vec::new();
    tinyros::msg::put_u32(&mut bytes, 7);
    tinyros::msg::put_string(&mut bytes, "two");

    let mut pos = 0;
    assert_eq!(take_u32(&bytes, &mut pos), Some(7));
    assert_eq!(pos, 4);
    assert_eq!(take_string(&bytes, &mut pos), Some("two".to_string()));
    assert_eq!(pos, bytes.len());
    assert_eq!(take_u32(&bytes, &mut pos), None);
}
