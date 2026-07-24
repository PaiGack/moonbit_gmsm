///| SM2 + SM3 whitebox tests

///|

///| Whitebox tests run within the package scope, so functions

///| from sm3.mbt and sm2.mbt are directly callable.

///|
/// Test: SM3 hash of "abc" (standard test vector)
test "sm3_abc" {
  let input : Bytes = b"abc"
  let hash = sm3_sum(input)
  // SM3("abc") = 66c7f0f4...
  let expected = Bytes::from_array([
    b'\x66', b'\xc7', b'\xf0', b'\xf4', b'\x62', b'\xee', b'\xed', b'\xd9', b'\xd1',
    b'\xf2', b'\xd4', b'\x6b', b'\xdc', b'\x10', b'\xe4', b'\xe2', b'\x41', b'\x67',
    b'\xc4', b'\x87', b'\x5c', b'\xf2', b'\xf7', b'\xa2', b'\x29', b'\x7d', b'\xa0',
    b'\x2b', b'\x8f', b'\x4b', b'\xa8', b'\xe0',
  ])
  assert_eq(hash, expected)
}

///|
/// Test: SM3 hash of empty string
test "sm3_empty" {
  let input : Bytes = b""
  let hash = sm3_sum(input)
  assert_eq(hash.length(), 32)
}

///|
/// Test: SM3 hash of 64 bytes (exact block boundary)
test "sm3_64bytes" {
  let input : Bytes = b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
  let hash = sm3_sum(input)
  assert_eq(hash.length(), 32)
}

///|
/// Test: SM3 hash of 256 bytes
test "sm3_256bytes" {
  let buf = Buffer(size_hint=256)
  for i = 0; i < 256; i = i + 1 {
    buf.write_byte((i & 0xFF).to_byte())
  }
  let input = buf.to_bytes()
  let hash = sm3_sum(input)
  assert_eq(hash.length(), 32)
}

///|
/// Test: SM3 hash of single byte "a"
test "sm3_single_byte" {
  let input : Bytes = b"a"
  let hash = sm3_sum(input)
  assert_eq(hash.length(), 32)
}

///|
/// Test: SM2 curve initialization
test "sm2_p256_init" {
  let curve = sm2_p256()
  // p[5] is 0 (part of the prime field), but other words are non-zero
  // n[4..7] contains the order's lower words
  assert_eq(curve.p.length(), 8)
  assert_eq(curve.n.length(), 8)
}

///|
/// Test: is_on_curve with base point
test "sm2_is_on_curve_base_point" {
  let curve = sm2_p256()
  let x = Bytes::from_array([
    b'\x32', b'\xC4', b'\xAE', b'\x2C', b'\x1F', b'\x19', b'\x81', b'\x19', b'\x5F',
    b'\x99', b'\x04', b'\x46', b'\x6A', b'\x39', b'\xC9', b'\x94', b'\x8F', b'\xE3',
    b'\x0B', b'\xBF', b'\xF2', b'\x66', b'\x0B', b'\xE1', b'\x71', b'\x5A', b'\x45',
    b'\x89', b'\x33', b'\x4C', b'\x74', b'\xC7',
  ])
  let y = Bytes::from_array([
    b'\xBC', b'\x37', b'\x36', b'\xA2', b'\xF4', b'\xF6', b'\x77', b'\x9C', b'\x59',
    b'\xBD', b'\xCE', b'\xE3', b'\x6B', b'\x69', b'\x21', b'\x53', b'\xD0', b'\xA9',
    b'\x87', b'\x7C', b'\xC6', b'\x2A', b'\x47', b'\x40', b'\x02', b'\xDF', b'\x32',
    b'\xE5', b'\x21', b'\x39', b'\xF0', b'\xA0',
  ])
  assert_true(is_on_curve(curve, x, y))
}

///|
/// Test: key generation
test "sm2_generate_key" {
  let curve = sm2_p256()
  let (private_key, _public_key) = generate_key(curve)
  assert_eq(private_key.length(), 32)
}

///|
/// Test: encryption/decryption round-trip (C1C3C2)
test "sm2_encrypt_decrypt_c1c3c2" {
  let curve = sm2_p256()
  let (private_key, public_key) = generate_key(curve)
  let plaintext : Bytes = b"Hello SM2!"
  let cipher = sm2_encrypt(curve, public_key, plaintext, C1C3C2)
  let decrypted = sm2_decrypt(curve, private_key, cipher, C1C3C2)
  assert_eq(decrypted, plaintext)
}

///|
/// Test: encryption/decryption round-trip (C1C2C3)
test "sm2_encrypt_decrypt_c1c2c3" {
  let curve = sm2_p256()
  let (private_key, public_key) = generate_key(curve)
  let plaintext : Bytes = b"Test C1C2C3 mode"
  let cipher = sm2_encrypt(curve, public_key, plaintext, C1C2C3)
  let decrypted = sm2_decrypt(curve, private_key, cipher, C1C2C3)
  assert_eq(decrypted, plaintext)
}

///|
/// Test: empty message encryption/decryption
test "sm2_encrypt_decrypt_empty" {
  let curve = sm2_p256()
  let (private_key, public_key) = generate_key(curve)
  let plaintext : Bytes = b""
  let cipher = sm2_encrypt(curve, public_key, plaintext, C1C3C2)
  let decrypted = sm2_decrypt(curve, private_key, cipher, C1C3C2)
  assert_eq(decrypted, plaintext)
}

///|
/// Test: long message encryption/decryption
test "sm2_encrypt_decrypt_long" {
  let curve = sm2_p256()
  let (private_key, public_key) = generate_key(curve)
  let buf = Buffer(size_hint=256)
  for i = 0; i < 256; i = i + 1 {
    buf.write_byte((i & 0xFF).to_byte())
  }
  let plaintext = buf.to_bytes()
  let cipher = sm2_encrypt(curve, public_key, plaintext, C1C3C2)
  let decrypted = sm2_decrypt(curve, private_key, cipher, C1C3C2)
  assert_eq(decrypted, plaintext)
}

///|
/// Test: sign returns 32-byte r and s
test "sm2_sign_verify" {
  let curve = sm2_p256()
  let (private_key, _public_key) = generate_key(curve)
  let msg : Bytes = b"test message"
  let uid : Bytes = b"1234567812345678"
  let (r, s) = sm2_sign(curve, private_key, msg, uid)
  assert_eq(r.length(), 32)
  assert_eq(s.length(), 32)
}

///|
/// Test: decrypt with correct key works
test "sm2_decrypt_correct_key" {
  let curve = sm2_p256()
  let (key1, pk1) = generate_key(curve)
  let (_key2, _pk2) = generate_key(curve)
  let plaintext : Bytes = b"secret"
  let cipher = sm2_encrypt(curve, pk1, plaintext, C1C3C2)
  let result = sm2_decrypt(curve, key1, cipher, C1C3C2)
  assert_eq(result, plaintext)
}

///|
/// Test: SM3 determinism - same input, same hash
test "sm3_deterministic" {
  let input : Bytes = b"deterministic test"
  let h1 = sm3_sum(input)
  let h2 = sm3_sum(input)
  assert_eq(h1, h2)
}

///|
/// Test: SM3 different inputs produce different hashes
test "sm3_different_inputs" {
  let h1 = sm3_sum(b"hello")
  let h2 = sm3_sum(b"world")
  assert_true(h1 != h2)
}
