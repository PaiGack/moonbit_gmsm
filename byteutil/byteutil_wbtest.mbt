//| Whitebox tests for the shared bit/byte helpers in `byteutil.mbt`.
//
// Tests for hex encoding / decoding live in `hexutil_wbtest.mbt`,
// ASN.1 DER helpers in `asn1_wbtest.mbt`, and PKCS#7 padding in
// `pkcs7_wbtest.mbt`.

// ----------------------------------------------------------------------------
// Generic helpers
// ----------------------------------------------------------------------------

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
test "xor_bytes_equal_length" {
  assert_eq(xor_bytes(b"\x0f\x0f", b"\xf0\xf0"), b"\xff\xff")
  assert_eq(xor_bytes(b"abc", b"abc"), b"\x00\x00\x00")
}

///|
/// Expecting panic: `xor_bytes` with mismatched lengths -> abort.
test "panic_xor_bytes_length_mismatch" {
  ignore(xor_bytes(b"ab", b"abc"))
}

///|
test "int_to_bytes_be_branches" {
  assert_eq(int_to_bytes_be(0x12345678), b"\x12\x34\x56\x78")
  assert_eq(int_to_bytes_be(0), b"\x00\x00\x00\x00")
}

///|
test "int_to_bytes_be_boundaries" {
  assert_eq(int_to_bytes_be(1), b"\x00\x00\x00\x01")
  assert_eq(int_to_bytes_be(0xFF), b"\x00\x00\x00\xFF")
  assert_eq(int_to_bytes_be(0x100), b"\x00\x00\x01\x00")
  assert_eq(int_to_bytes_be(0x00FFFFFF), b"\x00\xFF\xFF\xFF")
  assert_eq(int_to_bytes_be(0x7FFFFFFF), b"\x7F\xFF\xFF\xFF")
  // `Int` is signed; the implementation masks to the low 32 bits with `& 0xFF`,
  // so -1 maps to 0xFFFFFFFF, mirroring how a C-style `(uint8_t*)&n` cast would.
  assert_eq(int_to_bytes_be(-1), b"\xFF\xFF\xFF\xFF")
}

///|
test "concat_bytes_basic" {
  // The concat branch of the former `pad_left_and_concat` test.
  assert_eq(concat_bytes([b"XY", b"Z"]), b"XYZ")
}

///|
test "concat_bytes_many_segments" {
  let r = concat_bytes([b"a", b"", b"bc", b"", b"def"])
  assert_eq(r, b"abcdef")
}

///|
test "concat_bytes_only_empty_segments" {
  let r = concat_bytes([b"", b""])
  assert_eq(r, b"")
  assert_eq(r.length(), 0)
}

// ----------------------------------------------------------------------------
// Bit / byte readers
// ----------------------------------------------------------------------------

///|
test "rotl_basic" {
  // identity
  assert_eq(rotl(0x12345678U, 0), 0x12345678U)
  // 4-bit rotate-left within a word
  assert_eq(rotl(0x12345678U, 4), 0x23456781U)
  // bit 31 -> bit 0 (the cross-word carry)
  assert_eq(rotl(0x80000000U, 1), 0x00000001U)
  // bit 0 -> bit 31
  assert_eq(rotl(0x00000001U, 31), 0x80000000U)
  // n == 32 wraps back to the identity (the implementation does n % 32)
  assert_eq(rotl(0x12345678U, 32), 0x12345678U)
  assert_eq(rotl(0x12345678U, 36), rotl(0x12345678U, 4))
}

///|
test "get_u32_be_branches" {
  let b = b"\xde\xad\xbe\xef\x00\x00\x00\x00"
  assert_eq(get_u32_be(b, 0), 0xDEADBEEFU)
  assert_eq(get_u32_be(b, 4), 0x00000000U)
  assert_eq(get_u32_be(b"\xff\xff\xff\xff", 0), 0xFFFFFFFFU)
}

///|
test "get_u64_be_branches" {
  let b = b"\x00\x01\x02\x03\x04\x05\x06\x07"
  assert_eq(get_u64_be(b, 0), 0x0001020304050607UL)
}

///|
test "get_u64_be_with_offset" {
  let b = b"\x00\x00\x00\x00\x00\x00\x00\x00\xde\xad\xbe\xef\xca\xfe\xba\xbe"
  assert_eq(get_u64_be(b, 8), 0xDEADBEEFCAFEBABEUL)
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

// ----------------------------------------------------------------------------
// 256-bit Bn <-> 32 bytes
// ----------------------------------------------------------------------------

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
test "bn_from_bytes_with_offset" {
  // 40-byte buffer; bn_from_bytes reads 32 bytes from offset 8, so the
  // trailing 32 bytes contain the actual 256-bit value.
  let b = Bytes::makei(40, fn(i) {
    if i < 8 {
      b'\xFF'
    } else if i == 39 {
      b'\x01'
    } else {
      b'\x00'
    }
  })
  let r = FixedArray::make(4, 0UL)
  bn_from_bytes(r, b, 8)
  // Bytes 8..39 are 0x00..0x01, which is the 32-byte big-endian
  // representation of 1, so r[0] (the least significant limb) is 1.
  assert_eq(r[0], 1UL)
  assert_eq(r[1], 0UL)
  assert_eq(r[2], 0UL)
  assert_eq(r[3], 0UL)
}

///|
test "bn_to_bytes_high_limb_first" {
  // Use full 64-bit limb values so the high 32 bits contribute to the
  // emitted bytes (a 32-bit literal lives in the low half of the limb).
  let r = FixedArray::make(4, 0UL)
  r[3] = 0xDEADBEEFDEADBEEFUL
  r[2] = 0xCAFEBABECAFEBABEUL
  let out = bn_to_bytes(r)
  // bn_to_bytes emits the high limb (r[3]) first, then r[2], r[1], r[0].
  assert_eq(out[0], b'\xDE')
  assert_eq(out[1], b'\xAD')
  assert_eq(out[2], b'\xBE')
  assert_eq(out[3], b'\xEF')
  assert_eq(out[4], b'\xDE')
  assert_eq(out[5], b'\xAD')
  assert_eq(out[6], b'\xBE')
  assert_eq(out[7], b'\xEF')
  assert_eq(out[8], b'\xCA')
  assert_eq(out[9], b'\xFE')
  assert_eq(out[10], b'\xBA')
  assert_eq(out[11], b'\xBE')
  assert_eq(out[12], b'\xCA')
  assert_eq(out[13], b'\xFE')
  assert_eq(out[14], b'\xBA')
  assert_eq(out[15], b'\xBE')
  for i in 16..<32 {
    assert_eq(out[i], b'\x00')
  }
}

// ----------------------------------------------------------------------------
// 16-byte block <-> 4 x UInt32
// ----------------------------------------------------------------------------

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

///|
test "block_to_words_high_bit_no_sign_extend" {
  // All four words have the high bit set; the implementation must keep them
  // unsigned (otherwise the round-trip back to bytes would lose information).
  let blk = Bytes::from_array([
    b'\xFF', b'\x00', b'\x00', b'\x00', b'\x00', b'\xFF', b'\x00', b'\x00', b'\x00',
    b'\x00', b'\xFF', b'\x00', b'\x00', b'\x00', b'\x00', b'\xFF',
  ])
  let w = block_to_words(blk)
  assert_eq(w[0], 0xFF000000U)
  assert_eq(w[1], 0x00FF0000U)
  assert_eq(w[2], 0x0000FF00U)
  assert_eq(w[3], 0x000000FFU)
  assert_eq(words_to_block(w), blk)
}
