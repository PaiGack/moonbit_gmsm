//| Whitebox tests for the ASN.1 DER encoding helpers in `asn1.mbt`.

// ----------------------------------------------------------------------------
// Length field encoding / decoding
// ----------------------------------------------------------------------------

///|
test "encode_asn1_length_short_form" {
  assert_eq(encode_asn1_length(0), Bytes::from_array([b'\x00']))
  assert_eq(encode_asn1_length(1), Bytes::from_array([b'\x01']))
  assert_eq(encode_asn1_length(127), Bytes::from_array([b'\x7F']))
}

///|
test "encode_asn1_length_short_long_boundary" {
  // 127 -> short form; 128 -> long form (0x81 <len>)
  let b127 = encode_asn1_length(127)
  let b128 = encode_asn1_length(128)
  assert_eq(b127.length(), 1)
  assert_eq(b128.length(), 2)
  assert_eq(b128[0], b'\x81')
  assert_eq(b128[1], b'\x80')
}

///|
test "encode_asn1_length_long_form_single_byte" {
  // length >= 128 -> long form (0x81 <len>)
  let lb = encode_asn1_length(200)
  assert_eq(lb[0], b'\x81')
  assert_eq(lb[1], b'\xC8')
}

///|
test "encode_asn1_length_long_form_multi_byte" {
  assert_eq(encode_asn1_length(200), Bytes::from_array([b'\x81', b'\xC8']))
  assert_eq(
    encode_asn1_length(256),
    Bytes::from_array([b'\x82', b'\x01', b'\x00']),
  )
  assert_eq(
    encode_asn1_length(65536),
    Bytes::from_array([b'\x83', b'\x01', b'\x00', b'\x00']),
  )
}

///|
test "decode_asn1_length_short_form" {
  // only the valid short form can be asserted (out-of-bounds aborts)
  let (len, n) = decode_asn1_length(Bytes::from_array([b'\x05']), 0)
  assert_eq(len, 5)
  assert_eq(n, 1)
}

///|
test "decode_asn1_length_long_form" {
  let (l, n) = decode_asn1_length(Bytes::from_array([b'\x81', b'\xC8']), 0)
  assert_eq(l, 200)
  assert_eq(n, 2)
  let (l, n) = decode_asn1_length(
    Bytes::from_array([b'\xFF', b'\x82', b'\x01', b'\x00']),
    1,
  )
  assert_eq(l, 256)
  assert_eq(n, 3)
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

// ----------------------------------------------------------------------------
// pad_left
// ----------------------------------------------------------------------------

///|
test "pad_left_basic" {
  // Pin the original "AB" -> 5-byte padded behaviour that used to live in
  // the combined `pad_left_and_concat` test.
  let data = b"AB"
  let padded = pad_left(data, 5)
  assert_eq(padded.length(), 5)
  assert_eq(padded[0], b'\x00')
  assert_eq(padded[3], b'A')
}

///|
test "pad_left_already_long_enough" {
  let b = b"\x01\x02\x03\x04\x05"
  // Implementation early-returns the input when data.length() >= target.
  assert_eq(pad_left(b, 3), b)
}

///|
test "pad_left_exact_length" {
  let b = b"\x01\x02\x03"
  assert_eq(pad_left(b, 3), b)
}

///|
test "pad_left_zero_target" {
  assert_eq(pad_left(b"", 0).length(), 0)
}

// ----------------------------------------------------------------------------
// normalize_32
// ----------------------------------------------------------------------------

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
test "normalize_32_shorter_pads_left" {
  let n = normalize_32(b"\x01\x02\x03")
  assert_eq(n.length(), 32)
  for i in 0..<29 {
    assert_eq(n[i], b'\x00')
  }
  assert_eq(n[29], b'\x01')
  assert_eq(n[30], b'\x02')
  assert_eq(n[31], b'\x03')
}

///|
test "normalize_32_strip_one_leading_zero" {
  // 33 bytes: b[0] = 0x00, b[1..32] = 0x01..0x20
  let b = Bytes::makei(33, fn(i) { if i == 0 { b'\x00' } else { i.to_byte() } })
  let n = normalize_32(b)
  assert_eq(n.length(), 32)
  // After stripping exactly one leading zero, the remaining 32 bytes are
  // copied verbatim (no padding needed because data.length() == target).
  assert_eq(n[0], b'\x01')
  assert_eq(n[1], b'\x02')
  assert_eq(n[31], b'\x20')
}

///|
test "normalize_32_strip_many_leading_zeros" {
  // 40 bytes, the first 9 are 0x00; remaining bytes are 0..30.
  let b = Bytes::makei(40, fn(i) {
    if i < 9 {
      b'\x00'
    } else {
      (i - 9).to_byte()
    }
  })
  let n = normalize_32(b)
  assert_eq(n.length(), 32)
  // After stripping 9 leading zeros we have 31 bytes left; pad_left adds one
  // leading 0x00, so n[0] = 0x00 and the last byte is still 30 = 0x1e.
  assert_eq(n[0], b'\x00')
  assert_eq(n[31], b'\x1E')
}

///|
test "normalize_32_already_32" {
  let b = Bytes::makei(32, fn(i) { (i.reinterpret_as_uint() & 0xFFU).to_byte() })
  let n = normalize_32(b)
  assert_eq(n.length(), 32)
  for i in 0..<32 {
    assert_eq(n[i], b[i])
  }
}

///|
/// Expecting panic: `normalize_32` with a 33-byte value -> abort.
test "panic_normalize_32_too_large" {
  ignore(normalize_32(Bytes::makei(33, fn(_) { b'\x01' })))
}

// ----------------------------------------------------------------------------
// encode_asn1_integer
// ----------------------------------------------------------------------------

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
test "encode_asn1_integer_single_byte" {
  assert_eq(
    encode_asn1_integer(b"\x05"),
    Bytes::from_array([b'\x02', b'\x01', b'\x05']),
  )
}

///|
test "encode_asn1_integer_no_pad_low" {
  // First byte < 0x80 -> no prepended zero.
  assert_eq(
    encode_asn1_integer(b"\x7F\xFF\xFF\xFF"),
    Bytes::from_array([b'\x02', b'\x04', b'\x7F', b'\xFF', b'\xFF', b'\xFF']),
  )
}

///|
test "encode_asn1_integer_high_bit_pad" {
  // High bit of the first non-zero byte is set -> prepend a 0x00 so the value
  // is not misread as a negative INTEGER.
  let hi = Bytes::makei(32, fn(i) { if i == 0 { b'\x80' } else { b'\x00' } })
  let enc = encode_asn1_integer(hi)
  assert_eq(enc[0], b'\x02')
  assert_eq(enc[1], b'\x21') // length 33
  assert_eq(enc[2], b'\x00') // prepended zero
  assert_eq(enc[3], b'\x80')
  for i in 4..<35 {
    assert_eq(enc[i], b'\x00')
  }
}

// ----------------------------------------------------------------------------
// encode_asn1_octet_string
// ----------------------------------------------------------------------------

///|
test "encode_asn1_octet_string_branches" {
  let enc = encode_asn1_octet_string(b"\x01\x02")
  assert_eq(enc, Bytes::from_array([b'\x04', b'\x02', b'\x01', b'\x02']))
}

///|
test "encode_asn1_octet_string_empty" {
  assert_eq(
    encode_asn1_octet_string(b""),
    Bytes::from_array([b'\x04', b'\x00']),
  )
}

///|
test "encode_asn1_octet_string_long_form" {
  let data = Bytes::makei(200, fn(i) { (i & 0xFF).to_byte() })
  let enc = encode_asn1_octet_string(data)
  assert_eq(enc[0], b'\x04')
  assert_eq(enc[1], b'\x81') // long form, 1 length byte
  assert_eq(enc[2], b'\xC8') // length = 200
  for i in 0..<200 {
    assert_eq(enc[3 + i], data[i])
  }
}
