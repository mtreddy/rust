//! Turning messages into bytes, and back again.
//!
//! Before a message can travel to another node it has to become a plain row of
//! bytes. Real ROS2 uses a format called CDR; this is a simpler version of the
//! same idea:
//!
//! * numbers are written smallest byte first (little-endian)
//! * a string is written as its length (4 bytes), then the text itself
//! * a struct is written one field at a time, in the order it was declared
//!
//! Reading is the mirror image, and every read checks the length first, so a
//! short or damaged message gives back `None` instead of panicking.

/// Anything that can be sent on a topic.
pub trait Message: Sized + Send + 'static {
    /// The name of this type, e.g. "std_msgs/String".
    ///
    /// It travels with the message so a node can notice when two sides of a
    /// topic disagree about what is being sent.
    fn type_name() -> &'static str;

    /// Write this message into bytes.
    fn to_bytes(&self) -> Vec<u8>;

    /// Read a message back out of bytes. `None` means the bytes were not a
    /// valid message of this type.
    fn from_bytes(bytes: &[u8]) -> Option<Self>;
}

// ---------------------------------------------------------------------------
// Writing helpers
// ---------------------------------------------------------------------------

pub fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn put_i32(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn put_f64(out: &mut Vec<u8>, value: f64) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Write the length, then the text.
pub fn put_string(out: &mut Vec<u8>, text: &str) {
    put_u32(out, text.len() as u32);
    out.extend_from_slice(text.as_bytes());
}

// ---------------------------------------------------------------------------
// Reading helpers
// ---------------------------------------------------------------------------
//
// Each one takes the bytes and a `pos` (how far we have read so far). On
// success it moves `pos` past what it read, so calls can simply be chained one
// after another in field order.

pub fn take_u32(bytes: &[u8], pos: &mut usize) -> Option<u32> {
    let end = *pos + 4;
    if end > bytes.len() {
        return None;
    }
    let mut four = [0u8; 4];
    four.copy_from_slice(&bytes[*pos..end]);
    *pos = end;
    Some(u32::from_le_bytes(four))
}

pub fn take_i32(bytes: &[u8], pos: &mut usize) -> Option<i32> {
    let end = *pos + 4;
    if end > bytes.len() {
        return None;
    }
    let mut four = [0u8; 4];
    four.copy_from_slice(&bytes[*pos..end]);
    *pos = end;
    Some(i32::from_le_bytes(four))
}

pub fn take_f64(bytes: &[u8], pos: &mut usize) -> Option<f64> {
    let end = *pos + 8;
    if end > bytes.len() {
        return None;
    }
    let mut eight = [0u8; 8];
    eight.copy_from_slice(&bytes[*pos..end]);
    *pos = end;
    Some(f64::from_le_bytes(eight))
}

pub fn take_string(bytes: &[u8], pos: &mut usize) -> Option<String> {
    let length = take_u32(bytes, pos)? as usize;
    let end = *pos + length;
    if end > bytes.len() {
        return None;
    }
    let text = String::from_utf8(bytes[*pos..end].to_vec()).ok()?;
    *pos = end;
    Some(text)
}

// ---------------------------------------------------------------------------
// A few message types to get started
// ---------------------------------------------------------------------------
//
// These are written out by hand on purpose: the pattern is short enough to copy
// for any new message type you want to add.

/// A line of text. The same shape as ROS2's `std_msgs/String`.
#[derive(Debug, Clone, PartialEq)]
pub struct StringMsg {
    pub data: String,
}

impl StringMsg {
    pub fn new(data: &str) -> Self {
        StringMsg { data: data.to_string() }
    }
}

impl Message for StringMsg {
    fn type_name() -> &'static str {
        "std_msgs/String"
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_string(&mut out, &self.data);
        out
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut pos = 0;
        let data = take_string(bytes, &mut pos)?;
        Some(StringMsg { data })
    }
}

/// A whole number.
#[derive(Debug, Clone, PartialEq)]
pub struct Int32 {
    pub data: i32,
}

impl Message for Int32 {
    fn type_name() -> &'static str {
        "std_msgs/Int32"
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_i32(&mut out, self.data);
        out
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut pos = 0;
        let data = take_i32(bytes, &mut pos)?;
        Some(Int32 { data })
    }
}

/// A point in space. An example of a message with more than one field, so you
/// can see that fields are simply written one after another.
#[derive(Debug, Clone, PartialEq)]
pub struct Point {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl Message for Point {
    fn type_name() -> &'static str {
        "geometry_msgs/Point"
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_f64(&mut out, self.x);
        put_f64(&mut out, self.y);
        put_f64(&mut out, self.z);
        out
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut pos = 0;
        let x = take_f64(bytes, &mut pos)?;
        let y = take_f64(bytes, &mut pos)?;
        let z = take_f64(bytes, &mut pos)?;
        Some(Point { x, y, z })
    }
}
