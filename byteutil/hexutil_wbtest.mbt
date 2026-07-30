//| Whitebox tests for the hex encoding / decoding helpers in `hexutil.mbt`.

///|
test "nibble_to_char_boundaries" {
  // decimal digits
  assert_eq(nibble_to_char(0), '0')
  assert_eq(nibble_to_char(9), '9')
  // first / last hex letter
  assert_eq(nibble_to_char(10), 'a')
  assert_eq(nibble_to_char(15), 'f')
}

///|
test "byte_to_hex_all_byte_boundaries" {
  assert_eq(byte_to_hex(b'\x00'), "00")
  assert_eq(byte_to_hex(b'\x01'), "01")
  assert_eq(byte_to_hex(b'\x09'), "09")
  assert_eq(byte_to_hex(b'\x0a'), "0a")
  assert_eq(byte_to_hex(b'\x0f'), "0f")
  assert_eq(byte_to_hex(b'\x10'), "10")
  assert_eq(byte_to_hex(b'\x7f'), "7f")
  assert_eq(byte_to_hex(b'\x80'), "80")
  assert_eq(byte_to_hex(b'\xa0'), "a0")
  assert_eq(byte_to_hex(b'\xff'), "ff")
}

///|
test "bytes_to_hex_empty" {
  assert_eq(bytes_to_hex(b""), "")
}

///|
test "bytes_to_hex_single_byte" {
  assert_eq(bytes_to_hex(b"\x42"), "42")
}

///|
test "bytes_to_hex_large_buffer" {
  let buf = Bytes::makei(256, fn(i) { i.to_byte() })
  let hex = bytes_to_hex(buf)
  assert_eq(hex.length(), 512)
  // 0x00 -> "00", 0x0a -> "0a", 0xff -> "ff"
  assert_eq(hex[0:4].to_owned(), "0001")
  assert_eq(hex[20:24].to_owned(), "0a0b")
  assert_eq(hex[508:512].to_owned(), "feff")
}

///|
test "hex_nibble_digit_branches" {
  assert_eq(hex_nibble(48), 0)
  assert_eq(hex_nibble(57), 9)
}

///|
test "hex_nibble_uppercase_branches" {
  assert_eq(hex_nibble(65), 10) // 'A'
  assert_eq(hex_nibble(70), 15) // 'F'
}

///|
test "hex_nibble_lowercase_branches" {
  assert_eq(hex_nibble(97), 10) // 'a'
  assert_eq(hex_nibble(102), 15) // 'f'
}

///|
/// Expecting panic: `hex_nibble` on non-hex characters must abort. Mirrors
/// the existing `panic_hex_nibble_invalid_char` in `byteutil_wbtest.mbt` but
/// sweeps four boundary cases ('G', 'Z', '`', '{') instead of one.
test "panic_hex_nibble_invalid_chars" {
  // 'G' (71), 'Z' (90), '`' (96, just below 'a'), '{' (123, just above 'f').
  let invalid : Array[UInt16] = [71, 90, 96, 123]
  for c in invalid {
    ignore(hex_nibble(c))
  }
}

///|
test "hex_to_bytes_single_byte" {
  assert_eq(hex_to_bytes("ab"), b"\xab")
  assert_eq(hex_to_bytes("AB"), b"\xab")
  assert_eq(hex_to_bytes("0f"), b"\x0f")
}

///|
test "hex_to_bytes_full_byte_range" {
  let hex = "000102030405060708090a0b0c0d0e0f" +
    "101112131415161718191a1b1c1d1e1f" +
    "202122232425262728292a2b2c2d2e2f" +
    "303132333435363738393a3b3c3d3e3f" +
    "404142434445464748494a4b4c4d4e4f" +
    "505152535455565758595a5b5c5d5e5f" +
    "606162636465666768696a6b6c6d6e6f" +
    "707172737475767778797a7b7c7d7e7f" +
    "808182838485868788898a8b8c8d8e8f" +
    "909192939495969798999a9b9c9d9e9f" +
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf" +
    "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
    "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
    "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
    "e0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
    "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
  let b = hex_to_bytes(hex)
  assert_eq(b.length(), 256)
  for i in 0..<256 {
    assert_eq(b[i], i.to_byte())
  }
}

///|
test "hex_to_bytes_empty" {
  assert_eq(hex_to_bytes(""), b"")
  assert_eq(hex_to_bytes("").length(), 0)
}

///|
test "hex_to_bytes_mixed_case" {
  // Both upper- and lower-case hex digits are accepted; round-trip back
  // to hex always uses lowercase.
  let b = hex_to_bytes("01aBcD")
  assert_eq(b, Bytes::from_array([b'\x01', b'\xAB', b'\xCD']))
  assert_eq(bytes_to_hex(b), "01abcd")
}

///|
/// Expecting panic: `hex_to_bytes` with an odd-length string -> abort.
test "panic_hex_to_bytes_odd_length" {
  ignore(hex_to_bytes("abc"))
}

///|
test "hex_roundtrip_random" {
  // Deterministic pseudo-random bytes; verify encoding -> decoding is identity.
  let b = Bytes::makei(64, fn(i) { ((i * 31 + 17) & 0xFF).to_byte() })
  assert_eq(hex_to_bytes(bytes_to_hex(b)), b)
}
