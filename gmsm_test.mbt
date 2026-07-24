/// Integration tests for SM2/SM3 algorithms.
/// These tests verify the public API through the top-level package.

///|
test "gmsm_sm2_keygen_and_sign_verify" {
  let key = sm2_generate_key()
  assert_true(sm2_check_pubkey(key.pubkey), msg="key should be valid")

  let msg : Bytes = b"hello world"
  let (r, s) = sm2_sign(key, msg, Bytes::make(0, b'\x00'), true)
  assert_true(
    sm2_verify(key.pubkey, msg, Bytes::make(0, b'\x00'), r, s),
    msg="sign-verify",
  )
}

///|
test "gmsm_sm2_encrypt_decrypt" {
  let key = sm2_generate_key()
  let msg : Bytes = b"Hello, GMSM!"

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
test "gmsm_sm3" {
  let hash = sm3_sum(b"abc")
  assert_eq(hash.length(), 32)
}
