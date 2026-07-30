//| Whitebox tests for the PKCS#7 padding helpers in `pkcs7.mbt`.

// ----------------------------------------------------------------------------
// pkcs7_pad
// ----------------------------------------------------------------------------

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

// ----------------------------------------------------------------------------
// pkcs7_unpad
// ----------------------------------------------------------------------------

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

///|
/// `pkcs7_unpad` must reject padding whose declared length is OK but whose
/// padding bytes do not all equal that length. The pre-existing
/// `pkcs7_unpad_wrong_pad_bytes` test actually exercises `pad_too_long`, not
/// the byte-value mismatch; this test pins down the latter branch.
test "pkcs7_unpad_wrong_pad_bytes_value" {
  // 6 bytes, last byte = 0x03 -> pad_len = 3, but the two preceding padding
  // bytes are 0x01 0x02 instead of 0x03 -> value mismatch.
  let bad = Bytes::from_array([b'A', b'B', b'C', b'\x01', b'\x02', b'\x03'])
  match pkcs7_unpad(bad) {
    Ok(_) => abort("unpad wrong bytes (value): expected error")
    Err(_) => ()
  }
}
