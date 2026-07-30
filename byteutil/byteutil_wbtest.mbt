//| Whitebox tests for the shared byte / hex helpers.

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

///|
/// Expecting panic: `hex_nibble` with a non-hex character -> abort (line 59).
test "panic_hex_nibble_invalid_char" {
  ignore(hex_nibble(71)) // 'G' is not a hex digit
}

///|
/// Expecting panic: `hex_to_bytes` with an odd-length string -> abort (line 67).
test "panic_hex_to_bytes_odd_length" {
  ignore(hex_to_bytes("abc"))
}

///|
test "get_u64_be_branches" {
  let b = b"\x00\x01\x02\x03\x04\x05\x06\x07"
  assert_eq(get_u64_be(b, 0), 0x0001020304050607UL)
}

///|
test "get_u32_be_fa_branches" {
  let buf = FixedArray::make(4, b'\x00')
  buf[0] = b'\x12'
  buf[1] = b'\x34'
  buf[2] = b'\x56'
  buf[3] = b'\x78'
  assert_eq(get_u32_be_fa(buf, 0), 0x12345678U)
}

///|
test "bn_from_to_bytes_roundtrip" {
  let b = b"\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x04"
  let r = FixedArray::make(4, 0UL)
  bn_from_bytes(r, b, 0)
  assert_eq(r[3], 1UL)
  assert_eq(r[2], 2UL)
  assert_eq(r[1], 3UL)
  assert_eq(r[0], 4UL)
  assert_eq(bn_to_bytes(r), b)
}

///|
test "block_words_roundtrip" {
  let blk = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
  let w = block_to_words(blk)
  assert_eq(w[0], 0x00010203U)
  assert_eq(w[1], 0x04050607U)
  assert_eq(w[2], 0x08090a0bU)
  assert_eq(w[3], 0x0c0d0e0fU)
  assert_eq(words_to_block(w), blk)
}
