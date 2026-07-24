/// SM2 public API re-exported from sm2 package.

///|
/// SM2 public key type.
pub type PubKey = @paigack/gmsm/sm2.PubKey

///|
/// SM2 private key type.
pub type PriKey = @paigack/gmsm/sm2.PriKey

///|
/// Generate a new SM2 key pair.
pub fn sm2_generate_key() -> PriKey {
  @paigack/gmsm/sm2.sm2_generate_key()
}

///|
/// Check if a public key is valid.
pub fn sm2_check_pubkey(pubkey : PubKey) -> Bool {
  @paigack/gmsm/sm2.sm2_check_pubkey(pubkey)
}

///|
/// SM2 signature. Returns (r, s).
pub fn sm2_sign(
  prikey : PriKey,
  msg : Bytes,
  uid : Bytes,
  random : Bool,
) -> (BigInt, BigInt) {
  @paigack/gmsm/sm2.sm2_sign(prikey, msg, uid, random)
}

///|
/// SM2 signature verification.
pub fn sm2_verify(
  pubkey : PubKey,
  msg : Bytes,
  uid : Bytes,
  r : BigInt,
  s : BigInt,
) -> Bool {
  @paigack/gmsm/sm2.sm2_verify(pubkey, msg, uid, r, s)
}

///|
/// SM2 encryption.
pub fn sm2_encrypt(pubkey : PubKey, data : Bytes, mode : Int) -> Bytes? {
  @paigack/gmsm/sm2.sm2_encrypt(pubkey, data, mode)
}

///|
/// SM2 decryption.
pub fn sm2_decrypt(prikey : PriKey, data : Bytes, mode : Int) -> Bytes? {
  @paigack/gmsm/sm2.sm2_decrypt(prikey, data, mode)
}

///|
/// SM2 key exchange.
pub fn sm2_key_exchange(
  klen : Int,
  ida : Bytes,
  idb : Bytes,
  pri : PriKey,
  pub_other : PubKey,
  rpri : PriKey,
  rpub_other : PubKey,
  this_is_a : Bool,
) -> (Bytes, Bytes, Bytes)? {
  @paigack/gmsm/sm2.sm2_key_exchange(
    klen, ida, idb, pri, pub_other, rpri, rpub_other, this_is_a,
  )
}

///|
/// SM3 hash.
pub fn sm3_sum(data : Bytes) -> Bytes {
  @paigack/gmsm/sm3.sm3_sum(data)
}

///|
/// SM3 hash of multiple data segments.
pub fn sm3_sum_multi(data : Array[Bytes]) -> Bytes {
  @paigack/gmsm/sm3.sm3_sum_multi(data)
}
