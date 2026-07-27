/// SM4 whitebox tests (package-internal).

///|
/// S-Box boundary values.
test "sbox_boundary" {
  assert_eq(sbox[0x00], b'\xd6')
  assert_eq(sbox[0xFF], b'\x48')
}

///|
/// S-Box known values from standard.
test "sbox_known_values" {
  assert_eq(sbox[0x01], b'\x90')
  assert_eq(sbox[0x10], b'\x2b')
  assert_eq(sbox[0x20], b'\x9c')
  assert_eq(sbox[0x6F], b'\x87')
  assert_eq(sbox[0x7F], b'\x9e')
  assert_eq(sbox[0x80], b'\xea')
}

///|
/// τ transformation: substitute each byte via S-Box.
test "tau_transform" {
  let input = 0x01234567U
  let a0 = sbox[0x01].to_uint()
  let a1 = sbox[0x23].to_uint()
  let a2 = sbox[0x45].to_uint()
  let a3 = sbox[0x67].to_uint()
  let expected = (a0 << 24) | (a1 << 16) | (a2 << 8) | a3
  assert_eq(sm4_tau(input), expected)
}

///|
/// L transformation: verify formula.
test "L_transform" {
  let input = 0x01234567U
  let expected = input ^
    rotl(input, 2) ^
    rotl(input, 10) ^
    rotl(input, 18) ^
    rotl(input, 24)
  assert_eq(sm4_L(input), expected)
}

///|
/// L' transformation: verify formula.
test "L_prime_transform" {
  let input = 0x01234567U
  let expected = input ^ rotl(input, 13) ^ rotl(input, 23)
  assert_eq(sm4_L_prime(input), expected)
}

///|
/// Key expansion: verify round key count is correct.
test "key_expansion_count" {
  let key = Bytes::makei(16, fn(i) { (i & 0xFF).to_byte() })
  let rk = sm4_expand_key(key)
  // Just verify we get 32 round keys (don't check specific values here,
  // the correctness is verified via the block encrypt/decrypt KAT test)
  for i = 0; i < 32; i = i + 1 {
    // Each round key should be non-trivial (not all zero, though it could be)
    // Just verify the function runs without error
    let _ = rk[i]
  }
}

///|
/// Block process encrypt then decrypt with reversed keys returns original.
test "process_block_encrypt_decrypt" {
  let key = Bytes::from_array([
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76,
    0x54, 0x32, 0x10,
  ])
  let data = Bytes::from_array([
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76,
    0x54, 0x32, 0x10,
  ])

  let rk = sm4_expand_key(key)
  let rk_rev : FixedArray[UInt] = FixedArray::makei(32, fn(i) { rk[31 - i] })

  let x : FixedArray[UInt] = FixedArray::makei(4, fn(i) {
    get_u32_be(data, i * 4)
  })
  let cipher = sm4_process_block(x, rk)
  let plain = sm4_process_block(cipher, rk_rev)

  for i = 0; i < 4; i = i + 1 {
    assert_eq(plain[i], x[i])
  }
}

///|
/// Key expansion: invalid key length must raise SM4Error::InvalidKey.
test "key_expansion_invalid_key" {
  let bad_key = Bytes::makei(15, fn(i) { i.to_byte() }) // wrong length
  let r : Result[FixedArray[UInt], SM4Error] = try {
    let rk = sm4_expand_key(bad_key)
    Ok(rk)
  } catch {
    e => Err(e)
  }
  match r {
    Ok(_) => abort("expected SM4Error::InvalidKey from sm4_expand_key")
    Err(SM4Error::InvalidKey) => ()
    Err(_) => abort("expected SM4Error::InvalidKey")
  }
}

///|
test "sm4_error_variants_constructible" {
  // Ensure all SM4Error variants are constructed (suppresses unused_constructor warning)
  let e0 = SM4Error::InvalidKey
  let e1 = SM4Error::InvalidData
  let e2 = SM4Error::InvalidIV
  let e3 = SM4Error::InvalidPadding
  let e4 = SM4Error::DecryptFailed
  ignore(e0)
  ignore(e1)
  ignore(e2)
  ignore(e3)
  ignore(e4)
}
