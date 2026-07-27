//| Whitebox tests for the shared hex / byte helpers.

///|
test "nibble_to_char_branches" {
  assert_eq(nibble_to_char(0).to_string(), "0")
  assert_eq(nibble_to_char(9).to_string(), "9")
  assert_eq(nibble_to_char(10).to_string(), "a")
  assert_eq(nibble_to_char(15).to_string(), "f")
}

///|
test "byte_to_hex_branches" {
  assert_eq(byte_to_hex(b'\x00'), "00")
  assert_eq(byte_to_hex(b'\xff'), "ff")
  assert_eq(byte_to_hex(b'\x0a'), "0a")
  assert_eq(byte_to_hex(b'\xa0'), "a0")
}

///|
test "bytes_to_hex_loop" {
  assert_eq(bytes_to_hex(b""), "")
  assert_eq(bytes_to_hex(b"\x01\x02\xab"), "0102ab")
}

///|
test "bytes_eq_branches" {
  assert_true(bytes_eq(b"abc", b"abc"))
  assert_false(bytes_eq(b"ab", b"abc"))
  assert_false(bytes_eq(b"abd", b"abc"))
}

///|
test "bstr_branches" {
  assert_eq(bstr(true), "true")
  assert_eq(bstr(false), "false")
}

///|
test "hex_nibble_branches" {
  // digit
  assert_eq(hex_nibble(48), 0)
  assert_eq(hex_nibble(57), 9)
  // uppercase
  assert_eq(hex_nibble(65), 10)
  assert_eq(hex_nibble(70), 15)
  // lowercase
  assert_eq(hex_nibble(97), 10)
  assert_eq(hex_nibble(102), 15)
}

///|
test "hex_to_bytes_roundtrip" {
  let b = hex_to_bytes("0123456789abcdef")
  assert_eq(
    b,
    Bytes::from_array([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]),
  )
  assert_eq(bytes_to_hex(b), "0123456789abcdef")
}
