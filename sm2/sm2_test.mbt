/// SM2 blackbox tests.

///|
test "sm2_generate_key" {
  let key = sm2_generate_key()
  assert_true(sm2_check_pubkey(key.pubkey), msg="key should be valid")
}

///|
test "sm2_sign_verify" {
  let key = sm2_generate_key()
  let msg : Bytes = b"hello sm2"
  let (r, s) = sm2_sign(key, msg, Bytes::make(0, b'\x00'), true)
  assert_true(r > 0, msg="r should be positive")
  assert_true(s > 0, msg="s should be positive")
  assert_true(
    sm2_verify(key.pubkey, msg, Bytes::make(0, b'\x00'), r, s),
    msg="signature should verify",
  )
}

///|
test "sm2_sign_verify_with_uid" {
  let key = sm2_generate_key()
  let msg : Bytes = b"hello sm2"
  let uid : Bytes = b"1234567812345678"
  let (r, s) = sm2_sign(key, msg, uid, true)
  assert_true(
    sm2_verify(key.pubkey, msg, uid, r, s),
    msg="signature should verify",
  )
}

///|
test "sm2_encrypt_decrypt" {
  let key = sm2_generate_key()
  let msg : Bytes = b"Hello SM2!"
  let enc = sm2_encrypt(key.pubkey, msg, 0)
  match enc {
    Some(c) => {
      let dec = sm2_decrypt(key, c, 0)
      match dec {
        Some(p) => assert_eq(p, msg)
        None => assert_true(false, msg="decrypt failed")
      }
    }
    None => assert_true(false, msg="encrypt failed")
  }
}

///|
test "sm2_encrypt_decrypt_c1c2c3" {
  let key = sm2_generate_key()
  let msg : Bytes = b"Hello SM2 C1C2C3!"
  let enc = sm2_encrypt(key.pubkey, msg, 1)
  match enc {
    Some(c) => {
      let dec = sm2_decrypt(key, c, 1)
      match dec {
        Some(p) => assert_eq(p, msg)
        None => assert_true(false, msg="decrypt failed")
      }
    }
    None => assert_true(false, msg="encrypt failed")
  }
}

///|
test "sm2_encrypt_decrypt_long" {
  let key = sm2_generate_key()
  let arr : Array[Byte] = Array::make(200, b'\x00')
  for i in 0..<200 {
    arr[i] = (i % 256).to_byte()
  }
  let msg = Bytes::from_array(arr)
  let enc = sm2_encrypt(key.pubkey, msg, 0)
  match enc {
    Some(c) => {
      let dec = sm2_decrypt(key, c, 0)
      match dec {
        Some(p) => assert_eq(p, msg)
        None => assert_true(false, msg="decrypt failed")
      }
    }
    None => assert_true(false, msg="encrypt failed")
  }
}

///|
test "sm2_sign_different_message" {
  let key = sm2_generate_key()
  let msg1 : Bytes = b"msg one"
  let msg2 : Bytes = b"msg two"
  let (r, s) = sm2_sign(key, msg1, Bytes::make(0, b'\x00'), true)
  assert_true(
    sm2_verify(key.pubkey, msg1, Bytes::make(0, b'\x00'), r, s),
    msg="should verify msg1",
  )
  assert_false(
    sm2_verify(key.pubkey, msg2, Bytes::make(0, b'\x00'), r, s),
    msg="should NOT verify msg2",
  )
}

///|
test "sm2_wrong_key" {
  let key1 = sm2_generate_key()
  let key2 = sm2_generate_key()
  let msg : Bytes = b"test"
  let (r, s) = sm2_sign(key1, msg, Bytes::make(0, b'\x00'), true)
  assert_false(
    sm2_verify(key2.pubkey, msg, Bytes::make(0, b'\x00'), r, s),
    msg="wrong key should fail",
  )
}

///|
test "sm2_key_exchange" {
  let ida : Bytes = b"1234567812345678"
  let idb : Bytes = b"1234567812345678"
  let key_a = sm2_generate_key()
  let key_b = sm2_generate_key()
  let rkey_a = sm2_generate_key()
  let rkey_b = sm2_generate_key()

  let ra = sm2_key_exchange(
    16,
    ida,
    idb,
    key_a,
    key_b.pubkey,
    rkey_a,
    rkey_b.pubkey,
    true,
  )
  let rb = sm2_key_exchange(
    16,
    ida,
    idb,
    key_b,
    key_a.pubkey,
    rkey_b,
    rkey_a.pubkey,
    false,
  )

  match ra {
    Some((k1, s1, sa)) =>
      match rb {
        Some((k2, sb, s2)) => {
          assert_eq(k1, k2, msg="shared key should match")
          assert_eq(s1, sb, msg="S1 should equal Sb")
          assert_eq(sa, s2, msg="Sa should equal S2")
        }
        None => assert_true(false, msg="key exchange B failed")
      }
    None => assert_true(false, msg="key exchange A failed")
  }
}
