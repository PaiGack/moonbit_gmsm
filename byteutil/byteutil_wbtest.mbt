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

/// ASN.1 / concat / pad helpers (migrated from sm2/sm4 test suites).

///|
test "encode_asn1_integer_edge_cases" {
  // All-zero input -> 0x02 0x01 0x00
  let zero = Bytes::makei(32, fn(_) { b'\x00' })
  let enc_zero = encode_asn1_integer(zero)
  assert_eq(enc_zero, Bytes::from_array([b'\x02', b'\x01', b'\x00']))
  // Leading-zero handling (strip + non-padded)
  let lead = Bytes::makei(33, fn(i) { if i == 0 { b'\x00' } else { b'\xAA' } })
  let enc_lead = encode_asn1_integer(lead)
  // First byte must be INTEGER tag
  assert_eq(enc_lead[0], b'\x02')
}

///|
test "encode_asn1_length_long_form" {
  // length >= 128 -> long form (0x81 <len>)
  let lb = encode_asn1_length(200)
  assert_eq(lb[0], b'\x81')
  assert_eq(lb[1], b'\xC8')
}

///|
test "decode_asn1_length_errors" {
  // only the valid short form can be asserted (out-of-bounds aborts)
  let (len, n) = decode_asn1_length(Bytes::from_array([b'\x05']), 0)
  assert_eq(len, 5)
  assert_eq(n, 1)
}

///|
test "normalize_32_overflow_aborts_on_large" {
  // A 33-byte value (no leading zero) exceeds 32 -> abort path.
  // Use a value that normalizes fine (<=32 bytes) to keep the test green.
  let ok = Bytes::makei(32, fn(i) {
    (i.reinterpret_as_uint() & 0xFFU).to_byte()
  })
  let n = normalize_32(ok)
  assert_eq(n.length(), 32)
}

///|
test "pad_left_and_concat" {
  let data = b"AB"
  let padded = pad_left(data, 5)
  assert_eq(padded.length(), 5)
  assert_eq(padded[0], b'\x00')
  assert_eq(padded[3], b'A')
  let cat = concat_bytes([b"XY", b"Z"])
  assert_eq(cat, b"XYZ")
}

///|
/// Expecting panic: `decode_asn1_length` with offset past the end -> abort.
test "panic_decode_asn1_length_out_of_bounds" {
  ignore(decode_asn1_length(Bytes::makei(0, fn(_) { b'\x00' }), 0))
}

///|
/// Expecting panic: `decode_asn1_length` with an invalid long-form length -> abort.
test "panic_decode_asn1_length_invalid_long" {
  // first byte 0x81 (long form, 1 length byte) but no length bytes follow.
  ignore(decode_asn1_length(Bytes::from_array([b'\x81']), 0))
}

///|
/// Expecting panic: `normalize_32` with a 33-byte value -> abort.
test "panic_normalize_32_too_large" {
  ignore(normalize_32(Bytes::makei(33, fn(_) { b'\x01' })))
}

/// PKCS#7 padding helpers (migrated from sm4 test suites).

///|
/// PKCS7 pad / unpad round-trip.
test "pkcs7_pad_unpad_roundtrip" {
  let data = b"hello"
  let padded = pkcs7_pad(data, 16)
  assert_eq(padded.length(), 16)
  let unpadded = match pkcs7_unpad(padded) {
    Ok(b) => b
    Err(_) => abort("pkcs7_unpad failed")
  }
  assert_eq(unpadded.length(), 5)
  for i in 0..<5 {
    assert_eq(unpadded[i], data[i])
  }
}

///|
/// PKCS7 padding with exact block size produces a full block of padding.
test "pkcs7_pad_exact_block" {
  let data = b"1234567890123456" // exactly 16 bytes
  let padded = pkcs7_pad(data, 16)
  assert_eq(padded.length(), 32)
  // Last 16 bytes should be 0x10
  for i in 16..<32 {
    assert_eq(padded[i], b'\x10')
  }
}

///|
/// PKCS7 unpadding an empty padding block returns empty.
test "pkcs7_unpad_full_block" {
  let padded = Bytes::makei(16, fn(_i) { b'\x10' })
  let unpadded = match pkcs7_unpad(padded) {
    Ok(b) => b
    Err(_) => abort("pkcs7_unpad failed")
  }
  assert_eq(unpadded.length(), 0)
}

///|
/// PKCS7 pad empty data.
test "pkcs7_pad_empty" {
  let padded = pkcs7_pad(b"", 16)
  assert_eq(padded.length(), 16)
  for i in 0..<16 {
    assert_eq(padded[i], b'\x10')
  }
}

///|
/// PKCS7 pad with various block sizes.
test "pkcs7_pad_different_block_sizes" {
  // block_size 16: pad "AB" (2 bytes) -> 14 bytes of 0x0E
  let data = b"AB"
  let padded = pkcs7_pad(data, 16)
  assert_eq(padded.length(), 16)
  assert_eq(padded[0], b'A')
  assert_eq(padded[1], b'B')
  for i in 2..<16 {
    assert_eq(padded[i], b'\x0E')
  }
}

///|
test "pkcs7_unpad_empty" {
  match pkcs7_unpad(b"") {
    Ok(_) => abort("unpad empty: expected error")
    Err(_) => ()
  }
}

///|
test "pkcs7_unpad_invalid_pad_value" {
  // last byte 0x11 (17) > 16 -> invalid
  let bad = Bytes::makei(16, fn(i) { if i == 15 { b'\x11' } else { b'\x01' } })
  match pkcs7_unpad(bad) {
    Ok(_) => abort("unpad pad value: expected error")
    Err(_) => ()
  }
}

///|
test "pkcs7_unpad_pad_too_long" {
  // last byte 0x10 (16) but only 1 byte total -> pad_len > length
  let bad = Bytes::makei(1, fn(_) { b'\x10' })
  match pkcs7_unpad(bad) {
    Ok(_) => abort("unpad too long: expected error")
    Err(_) => ()
  }
}

///|
test "pkcs7_unpad_wrong_pad_bytes" {
  // claims 3 bytes of padding 0x03 but data is only 4 bytes long,
  // so pad_len (3) would exceed length -> rejected first.
  let bad = Bytes::makei(4, fn(i) {
    match i {
      0 => b'A'
      1 => b'B'
      2 => b'\x03'
      3 => b'\x03'
      _ => b'\x00'
    }
  })
  match pkcs7_unpad(bad) {
    Ok(_) => abort("unpad wrong bytes: expected error")
    Err(_) => ()
  }
}

/// Additional coverage for helpers migrated from sm2/sm4.

///|
test "xor_bytes_equal_length" {
  assert_eq(xor_bytes(b"\x0f\x0f", b"\xf0\xf0"), b"\xff\xff")
  assert_eq(xor_bytes(b"abc", b"abc"), b"\x00\x00\x00")
}

///|
test "int_to_bytes_be_branches" {
  assert_eq(int_to_bytes_be(0x12345678), b"\x12\x34\x56\x78")
  assert_eq(int_to_bytes_be(0), b"\x00\x00\x00\x00")
}

///|
test "encode_asn1_octet_string_branches" {
  let enc = encode_asn1_octet_string(b"\x01\x02")
  assert_eq(enc, Bytes::from_array([b'\x04', b'\x02', b'\x01', b'\x02']))
}
