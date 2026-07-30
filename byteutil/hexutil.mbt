/// Shared hex encoding / decoding helpers, reused by the `sm2`, `sm3`,
/// `sm4` packages and the command-line demos to avoid duplicating the same
/// pure functions in each.

///|
pub fn nibble_to_char(n : Int) -> Char {
  if n < 10 {
    Int::unsafe_to_char(n + '0'.to_int())
  } else {
    Int::unsafe_to_char(n - 10 + 'a'.to_int())
  }
}

///|
pub fn byte_to_hex(b : Byte) -> String {
  let hi = (b.to_int() >> 4) & 0xF
  let lo = b.to_int() & 0xF
  nibble_to_char(hi).to_string() + nibble_to_char(lo).to_string()
}

///|
pub fn bytes_to_hex(b : Bytes) -> String {
  let buf = StringBuilder::new()
  for i = 0; i < b.length(); i = i + 1 {
    buf.write_string(byte_to_hex(b[i]))
  }
  buf.to_string()
}

///|
pub fn hex_nibble(c : UInt16) -> Int {
  if c >= 48 && c <= 57 {
    (c - 48).to_int()
  } else if c >= 65 && c <= 70 {
    (c - 65).to_int() + 10
  } else if c >= 97 && c <= 102 {
    (c - 97).to_int() + 10
  } else {
    abort("invalid hex char")
  }
}

///|
pub fn hex_to_bytes(s : String) -> Bytes {
  let len = s.length()
  if len % 2 != 0 {
    abort("hex string must have even length")
  }
  let n = len / 2
  Bytes::makei(n, fn(i) {
    let hi = hex_nibble(s[i * 2])
    let lo = hex_nibble(s[i * 2 + 1])
    ((hi << 4) | lo).to_byte()
  })
}
