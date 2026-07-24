/// Integration tests for SM2/SM3 algorithms.
/// These tests verify the public API through the top-level package.

///|
test "gmsm_sm2_keygen_and_verify" {
  let curve = sm2_p256()
  let (private_key, pubkey) = sm2_generate_key(curve)
  assert_true(
    sm2_is_on_curve(curve, pubkey.x, pubkey.y),
    msg="public key should be on curve",
  )

  let msg : Bytes = b"hello world"
  let uid : Bytes = b"\x31\x32\x33\x34\x35\x36\x37\x38\x31\x32\x33\x34\x35\x36\x37\x38"
  let (r, s) = sm2_sign(curve, private_key, msg, uid)
  assert_true(
    sm2_verify(curve, pubkey, msg, uid, r, s),
    msg="sign-verify",
  )
}

///|
test "gmsm_sm2_encrypt_decrypt" {
  let curve = sm2_p256()
  let (private_key, pubkey) = sm2_generate_key(curve)
  let msg : Bytes = b"Hello, GMSM!"

  let enc = sm2_encrypt(curve, pubkey, msg, C1C3C2)
  let dec = sm2_decrypt(curve, private_key, enc, C1C3C2)
  assert_eq(dec, msg)
}

///|
test "gmsm_sm3" {
  let hash = sm3_sum(b"abc")
  assert_eq(hash.length(), 32)
}
