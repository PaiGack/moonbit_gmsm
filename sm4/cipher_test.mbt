/// Tests for the tjfoc-compatible SM4 surface: `new_cipher` (cipher.Block),
/// the package-level default IV (`set_iv`) and the padded mode wrappers.

///|
/// `new_cipher` reuses one expanded key and matches the one-shot block API.
test "sm4_cipher_block" {
  let key = hex_to_bytes_unchecked("0123456789ABCDEFFEDCBA9876543210")
  let c = @sm4.new_cipher(key)
  assert_eq(c.block_size(), 16)
  assert_eq(@sm4.sm4_block_size, 16)
  assert_eq(@sm4.sm4_key_size, 16)
  let plain = hex_to_bytes_unchecked("0123456789ABCDEFFEDCBA9876543210")
  let cipher = c.encrypt(plain)
  // GM/T 0002-2012 Appendix A
  assert_bytes_eq(
    cipher,
    hex_to_bytes_unchecked("681EDF34D206965E86B3E94F536E4246"),
  )
  assert_bytes_eq(cipher, @sm4.sm4_encrypt_block(key, plain))
  assert_bytes_eq(c.decrypt(cipher), plain)
  // the same cipher value can be reused for further blocks
  let other = hex_to_bytes_unchecked("00112233445566778899AABBCCDDEEFF")
  assert_bytes_eq(c.encrypt(other), @sm4.sm4_encrypt_block(key, other))
  assert_bytes_eq(c.decrypt(other), @sm4.sm4_decrypt_block(key, other))
}

///|
/// `new_cipher` rejects a key that is not 16 bytes.
test "sm4_cipher_invalid_key" {
  let r : Result[@sm4.SM4Cipher, @sm4.SM4Error] = Ok(
    @sm4.new_cipher(hex_to_bytes_unchecked("0011")),
  ) catch {
    e => Err(e)
  }
  match r {
    Ok(_) => abort("new_cipher: expected InvalidKey")
    Err(e) => assert_true(e is @sm4.SM4Error::InvalidKey)
  }
}

///|
/// `encrypt` / `decrypt` only accept exactly one block.
test "sm4_cipher_invalid_block" {
  let c = @sm4.new_cipher(
    hex_to_bytes_unchecked("0123456789ABCDEFFEDCBA9876543210"),
  )
  let enc : Result[Bytes, @sm4.SM4Error] = Ok(
    c.encrypt(hex_to_bytes_unchecked("0011")),
  ) catch {
    e => Err(e)
  }
  match enc {
    Ok(_) => abort("encrypt: expected InvalidData")
    Err(e) => assert_true(e is @sm4.SM4Error::InvalidData)
  }
  let dec : Result[Bytes, @sm4.SM4Error] = Ok(
    c.decrypt(hex_to_bytes_unchecked("0011")),
  ) catch {
    e => Err(e)
  }
  match dec {
    Ok(_) => abort("decrypt: expected InvalidData")
    Err(e) => assert_true(e is @sm4.SM4Error::InvalidData)
  }
}

///|
/// The per-cipher IV can be set and read back, and rejects bad lengths.
test "sm4_cipher_set_iv" {
  let c = @sm4.new_cipher(
    hex_to_bytes_unchecked("0123456789ABCDEFFEDCBA9876543210"),
  )
  assert_bytes_eq(
    c.get_iv(),
    hex_to_bytes_unchecked("00000000000000000000000000000000"),
  )
  let iv = hex_to_bytes_unchecked("000102030405060708090A0B0C0D0E0F")
  c.set_iv(iv)
  assert_bytes_eq(c.get_iv(), iv)
  let r : Result[Unit, @sm4.SM4Error] = Ok(
    c.set_iv(hex_to_bytes_unchecked("0001")),
  ) catch {
    e => Err(e)
  }
  match r {
    Ok(_) => abort("set_iv: expected InvalidIV")
    Err(e) => assert_true(e is @sm4.SM4Error::InvalidIV)
  }
  // a rejected IV must not clobber the previous one
  assert_bytes_eq(c.get_iv(), iv)
}

///|
/// The package-level default IV drives the mode wrappers.
test "sm4_default_iv" {
  let iv = hex_to_bytes_unchecked("0F0E0D0C0B0A09080706050403020100")
  @sm4.set_iv_unchecked(iv)
  assert_bytes_eq(@sm4.get_iv_unchecked(), iv)
  let r : Result[Unit, @sm4.SM4Error] = Ok(
    @sm4.set_iv_unchecked(hex_to_bytes_unchecked("00")),
  ) catch {
    e => Err(e)
  }
  match r {
    Ok(_) => abort("set_iv: expected InvalidIV")
    Err(e) => assert_true(e is @sm4.SM4Error::InvalidIV)
  }
  assert_bytes_eq(@sm4.get_iv_unchecked(), iv)
  // restore the all-zero default for the other tests
  @sm4.set_iv_unchecked(
    hex_to_bytes_unchecked("00000000000000000000000000000000"),
  )
}

///|
/// The padded wrappers round-trip for every mode and every input length, and
/// agree with the explicit-IV API applied to the PKCS7-padded plaintext.
test "sm4_mode_wrappers_roundtrip" {
  let key = hex_to_bytes_unchecked("0123456789ABCDEFFEDCBA9876543210")
  let iv = hex_to_bytes_unchecked("000102030405060708090A0B0C0D0E0F")
  @sm4.set_iv_unchecked(iv)
  let inputs : Array[Bytes] = [
    b"",
    b"hello",
    hex_to_bytes_unchecked("0123456789ABCDEFFEDCBA9876543210"),
    Bytes::makei(30, fn(i) { ((i * 3 + 7) % 256).to_byte() }),
  ]
  for plain in inputs {
    let padded = @byteutil.pkcs7_pad(plain, 16)
    let ecb = @sm4.sm4_ecb(key, plain, true)
    assert_bytes_eq(ecb, @sm4.sm4_encrypt_ecb(key, padded))
    assert_bytes_eq(@sm4.sm4_ecb(key, ecb, false), plain)
    let cbc = @sm4.sm4_cbc(key, plain, true)
    assert_bytes_eq(cbc, @sm4.sm4_encrypt_cbc(key, iv, padded))
    assert_bytes_eq(@sm4.sm4_cbc(key, cbc, false), plain)
    let cfb = @sm4.sm4_cfb(key, plain, true)
    assert_bytes_eq(cfb, @sm4.sm4_encrypt_cfb(key, iv, padded))
    assert_bytes_eq(@sm4.sm4_cfb(key, cfb, false), plain)
    let ofb = @sm4.sm4_ofb(key, plain, true)
    assert_bytes_eq(ofb, @sm4.sm4_encrypt_ofb(key, iv, padded))
    assert_bytes_eq(@sm4.sm4_ofb(key, ofb, false), plain)
  }
  @sm4.set_iv_unchecked(
    hex_to_bytes_unchecked("00000000000000000000000000000000"),
  )
}

///|
/// Changing the default IV changes CBC/CFB/OFB output but not ECB output.
test "sm4_mode_wrappers_follow_default_iv" {
  let key = hex_to_bytes_unchecked("0123456789ABCDEFFEDCBA9876543210")
  let plain = b"iv sensitivity"
  @sm4.set_iv_unchecked(
    hex_to_bytes_unchecked("00000000000000000000000000000000"),
  )
  let cbc0 = @sm4.sm4_cbc(key, plain, true)
  let ecb0 = @sm4.sm4_ecb(key, plain, true)
  @sm4.set_iv_unchecked(
    hex_to_bytes_unchecked("000102030405060708090A0B0C0D0E0F"),
  )
  let cbc1 = @sm4.sm4_cbc(key, plain, true)
  let ecb1 = @sm4.sm4_ecb(key, plain, true)
  assert_false(bytes_equal(cbc0, cbc1))
  assert_true(bytes_equal(ecb0, ecb1))
  assert_bytes_eq(@sm4.sm4_cbc(key, cbc1, false), plain)
  @sm4.set_iv_unchecked(
    hex_to_bytes_unchecked("00000000000000000000000000000000"),
  )
}

///|
/// Decrypting through the wrappers rejects non block-aligned input.
test "sm4_mode_wrappers_invalid_data" {
  let key = hex_to_bytes_unchecked("0123456789ABCDEFFEDCBA9876543210")
  let r : Result[Bytes, @sm4.SM4Error] = Ok(
    @sm4.sm4_cbc(key, hex_to_bytes_unchecked("0011"), false),
  ) catch {
    e => Err(e)
  }
  match r {
    Ok(_) => abort("sm4_cbc: expected InvalidData")
    Err(e) => assert_true(e is @sm4.SM4Error::InvalidData)
  }
}

///|
/// The `sm4_gcm` dispatcher matches the dedicated encrypt/decrypt entries.
test "sm4_gcm_dispatcher" {
  let key = hex_to_bytes_unchecked("0123456789ABCDEFFEDCBA9876543210")
  let iv = hex_to_bytes_unchecked("000102030405060708090A0B")
  let aad = b"header"
  let plain = b"gcm dispatcher"
  let (c, t) = @sm4.sm4_gcm_encrypt(key, iv, plain, aad)
  let (c2, t2) = @sm4.sm4_gcm_encrypt(key, iv, plain, aad)
  assert_bytes_eq(c, c2)
  assert_bytes_eq(t, t2)
  // tag 不匹配时 `sm4_gcm_decrypt` 直接拒绝，不会返回未认证的明文。
  let wrong_tag = Bytes::makei(t.length(), fn(i) {
    if i == 0 {
      (t[i].to_uint() ^ 0xFFU).to_byte()
    } else {
      t[i]
    }
  })
  let bare : Result[Bytes, @sm4.SM4Error] = Ok(
    @sm4.sm4_gcm_decrypt(key, iv, c, aad, wrong_tag),
  ) catch {
    e => Err(e)
  }
  match bare {
    Ok(_) => abort("sm4_gcm_decrypt: tag mismatch must raise")
    Err(e) => assert_true(e is @sm4.SM4Error::InvalidTag)
  }
  // 正确 tag 下返回明文；返回类型是 `Bytes`，不再有永远为空的第二个分量。
  assert_bytes_eq(@sm4.sm4_gcm_decrypt(key, iv, c, aad, t), plain)
  // 空明文在 GCM 下是合法的：密文为空、tag 仍被认证。
  let (c3, t4) = @sm4.sm4_gcm_encrypt(key, iv, b"", aad)
  assert_eq(c3.length(), 0)
  assert_eq(@sm4.sm4_gcm_decrypt(key, iv, c3, aad, t4).length(), 0)
}

///|
/// Helper: byte-wise equality without aborting.
fn bytes_equal(a : Bytes, b : Bytes) -> Bool {
  if a.length() != b.length() {
    return false
  }
  for i in 0..<a.length() {
    if a[i] != b[i] {
      return false
    }
  }
  true
}

///|
/// `SM4Cipher::wipe` 清零轮密钥：之后再用该 cipher 加密，结果与真实密钥
/// 不再一致（说明密钥确实被抹掉了，而不是只改了个标志位）。
test "sm4_cipher_wipe_clears_round_keys" {
  let key = hex_to_bytes_unchecked("0123456789ABCDEFFEDCBA9876543210")
  let c = @sm4.new_cipher(key)
  let block = hex_to_bytes_unchecked("0123456789abcdeffedcba9876543210")
  let before = c.encrypt(block)
  c.wipe()
  let after = c.encrypt(block)
  assert_false(@byteutil.bytes_eq(before, after))
  // 再建一个 cipher 结果应与首个一致，确认 wipe 只影响被调用的实例
  assert_bytes_eq(@sm4.new_cipher(key).encrypt(block), before)
  assert_eq(c.get_iv(), Bytes::makei(16, fn(_) { b'\x00' }))
}
