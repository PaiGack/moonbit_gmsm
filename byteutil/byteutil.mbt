/// Shared low-level bit/byte helpers and hex / byte utilities, reused by the
/// `sm2`, `sm3`, `sm4` packages and the command-line demos to avoid
/// duplicating the same pure functions in each.

///|
/// 32-bit left rotation.
pub fn rotl(x : UInt, n : Int) -> UInt {
  let n = n % 32
  (x << n) | (x >> (32 - n))
}

///|
/// Read a 32-bit unsigned integer from `buf` at `offset` in big-endian byte
/// order.
pub fn get_u32_be(buf : Bytes, offset : Int) -> UInt {
  (buf[offset].to_uint().land(0xffU) << 24) |
  (buf[offset + 1].to_uint().land(0xffU) << 16) |
  (buf[offset + 2].to_uint().land(0xffU) << 8) |
  buf[offset + 3].to_uint().land(0xffU)
}

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
pub fn bytes_eq(a : Bytes, b : Bytes) -> Bool {
  if a.length() != b.length() {
    return false
  }
  for i = 0; i < a.length(); i = i + 1 {
    if a[i] != b[i] {
      return false
    }
  }
  true
}

///|
pub fn bstr(b : Bool) -> String {
  if b {
    "true"
  } else {
    "false"
  }
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
