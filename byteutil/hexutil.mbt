/// Shared hex encoding / decoding helpers, reused by the `sm2`, `sm3`,
/// `sm4` packages and the command-line demos to avoid duplicating the same
/// pure functions in each.

///|
pub fn nibble_to_char(n : Int32) -> Char {
  if n < 10 {
    Int32::unsafe_to_char(n + '0'.to_int())
  } else {
    Int32::unsafe_to_char(n - 10 + 'a'.to_int())
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
  let buf = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    buf.write_string(byte_to_hex(b[i]))
  }
  buf.to_string()
}

///|
pub fn hex_nibble(c : UInt16) -> Int32 {
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
/// Decode a hex string (upper- or lower-case digits, no `0x` prefix).
///
/// Raises `ByteUtilError::InvalidHex` for an odd length or a non-hex
/// character. It deliberately does **not** abort: hex usually comes from
/// configuration files or the command line, where a single typo must not
/// take the process down. Use `hex_to_bytes_unchecked` only for literals
/// that are known good at compile time.
pub fn hex_to_bytes(s : String) -> Bytes raise ByteUtilError {
  let len = s.length()
  if len % 2 != 0 {
    raise ByteUtilError::InvalidHex
  }
  let n = len / 2
  Bytes::makei(n, fn(i) raise ByteUtilError {
    // `hex_nibble` yields Int32; shift as Int so high nibbles (>= 8) do not
    // sign-extend, and mask to a byte.
    let hi = hex_nibble_value(s[i * 2])
    let lo = hex_nibble_value(s[i * 2 + 1])
    if hi < 0 || lo < 0 {
      raise ByteUtilError::InvalidHex
    }
    // Use UInt to build the byte value: signed Int shifts/sign-extension have
    // been unreliable in some backends for values above 0x7f.
    ((hi.reinterpret_as_uint() << 4) | lo.reinterpret_as_uint()).to_byte()
  })
}

///|
/// Non-raising counterpart of `hex_to_bytes` for compile-time-known literals
/// and tests: an invalid input aborts. Keep it away from any input that comes
/// from outside the program.
pub fn hex_to_bytes_unchecked(s : String) -> Bytes {
  hex_to_bytes(s) catch {
    _ => abort("hex_to_bytes_unchecked: invalid hex string")
  }
}

///|
/// Value of one hex digit, or `-1` when `c` is not `0-9a-fA-F`.
fn hex_nibble_value(c : UInt16) -> Int32 {
  if c >= 48 && c <= 57 {
    (c - 48).to_int()
  } else if c >= 65 && c <= 70 {
    (c - 65).to_int() + 10
  } else if c >= 97 && c <= 102 {
    (c - 97).to_int() + 10
  } else {
    -1
  }
}
