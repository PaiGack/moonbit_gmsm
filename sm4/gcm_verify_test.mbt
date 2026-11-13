///|
/// GCM tag verification: `sm4_gcm_decrypt` releases plaintext only on
/// a matching tag, and `sm4_gcm(..., encrypt = false)` verifies when the tag
/// is appended.

///|
fn gcm_key() -> Bytes {
  @byteutil.hex_to_bytes_unchecked("0123456789ABCDEFFEDCBA9876543210")
}

///|
fn gcm_nonce() -> Bytes {
  @byteutil.hex_to_bytes_unchecked("000102030405060708090a0b")
}

///|
fn as_err(r : Result[Bytes, @sm4.SM4Error]) -> @sm4.SM4Error {
  match r {
    Ok(_) => abort("expected an error")
    Err(e) => e
  }
}

///|
/// Toggle the lowest bit of byte `i`, returning a new byte sequence.
fn flip_bit(b : Bytes, i : Int32) -> Bytes {
  let fa : FixedArray[Byte] = FixedArray::makei(b.length(), fn(k) {
    if k == i {
      (b[k].to_uint() ^ 1U).to_byte()
    } else {
      b[k]
    }
  })
  Bytes::from_array(fa)
}

///|
/// Replace byte `i` with `v`, returning a new byte sequence.
fn with_byte(b : Bytes, i : Int32, v : Byte) -> Bytes {
  let fa : FixedArray[Byte] = FixedArray::makei(b.length(), fn(k) {
    if k == i {
      v
    } else {
      b[k]
    }
  })
  Bytes::from_array(fa)
}

///|
/// A correct tag decrypts to the original plaintext.
test "sm4_gcm_decrypt_accepts_valid_tag" {
  let key = gcm_key()
  let (ct, tag) = @sm4.sm4_gcm_encrypt(key, gcm_nonce(), b"hello gcm", b"aad")
  assert_bytes_eq(
    @sm4.sm4_gcm_decrypt(key, gcm_nonce(), ct, b"aad", tag),
    b"hello gcm",
  )
}

///|
/// A flipped tag byte raises `InvalidTag`.
test "sm4_gcm_decrypt_rejects_bad_tag" {
  let key = gcm_key()
  let (ct, tag) = @sm4.sm4_gcm_encrypt(key, gcm_nonce(), b"hello gcm", b"aad")
  let bad_tag = flip_bit(tag, 0)
  let r : Result[Bytes, @sm4.SM4Error] = Ok(
    @sm4.sm4_gcm_decrypt(key, gcm_nonce(), ct, b"aad", bad_tag),
  ) catch {
    e => Err(e)
  }
  assert_true(as_err(r) is @sm4.SM4Error::InvalidTag)
}

///|
/// Tampered ciphertext or AAD also raises `InvalidTag`.
test "sm4_gcm_decrypt_rejects_tampered_input" {
  let key = gcm_key()
  let (ct, tag) = @sm4.sm4_gcm_encrypt(key, gcm_nonce(), b"hello gcm", b"aad")
  let bad_ct = flip_bit(ct, 3)
  let r1 : Result[Bytes, @sm4.SM4Error] = Ok(
    @sm4.sm4_gcm_decrypt(key, gcm_nonce(), bad_ct, b"aad", tag),
  ) catch {
    e => Err(e)
  }
  assert_true(as_err(r1) is @sm4.SM4Error::InvalidTag)
  let r2 : Result[Bytes, @sm4.SM4Error] = Ok(
    @sm4.sm4_gcm_decrypt(key, gcm_nonce(), ct, b"other", tag),
  ) catch {
    e => Err(e)
  }
  assert_true(as_err(r2) is @sm4.SM4Error::InvalidTag)
}

///|
/// A tag that is not 16 bytes is rejected.
test "sm4_gcm_decrypt_rejects_short_tag" {
  let key = gcm_key()
  let (ct, _tag) = @sm4.sm4_gcm_encrypt(key, gcm_nonce(), b"hello gcm", b"aad")
  let r : Result[Bytes, @sm4.SM4Error] = Ok(
    @sm4.sm4_gcm_decrypt(key, gcm_nonce(), ct, b"aad", b"0"),
  ) catch {
    e => Err(e)
  }
  assert_true(as_err(r) is @sm4.SM4Error::InvalidTag)
}

///|
/// `sm4_gcm_decrypt` 用独立 tag 校验，返回的只有明文。
test "sm4_gcm_decrypt_verifies_appended_tag" {
  let key = gcm_key()
  let (ct, tag) = @sm4.sm4_gcm_encrypt(key, gcm_nonce(), b"hello gcm", b"aad")
  assert_bytes_eq(
    @sm4.sm4_gcm_decrypt(key, gcm_nonce(), ct, b"aad", tag),
    b"hello gcm",
  )
  let bad_ct = with_byte(ct, 0, (ct[0].to_uint() ^ 0xFFU).to_byte())
  let r : Result[Bytes, @sm4.SM4Error] = Ok(
    @sm4.sm4_gcm_decrypt(key, gcm_nonce(), bad_ct, b"aad", tag),
  ) catch {
    e => Err(e)
  }
  assert_true(r is Err(@sm4.SM4Error::InvalidTag))
}

///|
/// tag 长度不是 16 字节时直接拒绝（不做截断比较）。
test "sm4_gcm_decrypt_rejects_bad_tag_length" {
  let key = gcm_key()
  let pt = Bytes::makei(32, fn(i) { (i * 3).to_byte() })
  let (ct, tag) = @sm4.sm4_gcm_encrypt(key, gcm_nonce(), pt, b"aad")
  for bad in [b"", tag[0:15].to_owned(), @byteutil.concat_bytes([tag, b"\x00"])] {
    let r : Result[Bytes, @sm4.SM4Error] = Ok(
      @sm4.sm4_gcm_decrypt(key, gcm_nonce(), ct, b"aad", bad),
    ) catch {
      e => Err(e)
    }
    assert_true(r is Err(@sm4.SM4Error::InvalidTag))
  }
  // 空明文 + 正确 tag 依然合法
  let (c0, t0) = @sm4.sm4_gcm_encrypt(key, gcm_nonce(), b"", b"aad")
  assert_eq(@sm4.sm4_gcm_decrypt(key, gcm_nonce(), c0, b"aad", t0).length(), 0)
}
