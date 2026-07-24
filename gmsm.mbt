/// SM2/SM3 public API re-exported from sm2 and sm3 packages.

///|
/// SM2 curve type.
pub type SM2Curve = @paigack/gmsm/sm2.SM2Curve

///|
/// SM2 public key type.
pub type SM2PublicKey = @paigack/gmsm/sm2.SM2PublicKey

///|
/// SM2 cipher mode.
pub type CipherMode = @paigack/gmsm/sm2.CipherMode

///|
/// SM2 recommended curve parameters (P-256).
pub fn sm2_p256() -> SM2Curve {
  @paigack/gmsm/sm2.sm2_p256()
}

///|
/// Generate an SM2 key pair.
pub fn sm2_generate_key(curve : SM2Curve) -> (Bytes, SM2PublicKey) {
  @paigack/gmsm/sm2.generate_key(curve)
}

///|
/// Derive public key from private key.
pub fn sm2_derive_public_key(curve : SM2Curve, private_key : Bytes) -> SM2PublicKey {
  @paigack/gmsm/sm2.derive_public_key(curve, private_key)
}

///|
/// Check if a point is on the SM2 curve.
pub fn sm2_is_on_curve(curve : SM2Curve, x : Bytes, y : Bytes) -> Bool {
  @paigack/gmsm/sm2.is_on_curve(curve, x, y)
}

///|
/// SM2 signature. Returns (r, s).
pub fn sm2_sign(
  curve : SM2Curve,
  private_key : Bytes,
  msg : Bytes,
  uid : Bytes,
) -> (Bytes, Bytes) {
  @paigack/gmsm/sm2.sm2_sign(curve, private_key, msg, uid)
}

///|
/// SM2 signature verification.
pub fn sm2_verify(
  curve : SM2Curve,
  public_key : SM2PublicKey,
  msg : Bytes,
  uid : Bytes,
  r : Bytes,
  s : Bytes,
) -> Bool {
  @paigack/gmsm/sm2.sm2_verify(curve, public_key, msg, uid, r, s)
}

///|
/// SM2 encryption.
pub fn sm2_encrypt(
  curve : SM2Curve,
  public_key : SM2PublicKey,
  msg : Bytes,
  mode : CipherMode,
) -> Bytes {
  @paigack/gmsm/sm2.sm2_encrypt(curve, public_key, msg, mode)
}

///|
/// SM2 decryption.
pub fn sm2_decrypt(
  curve : SM2Curve,
  private_key : Bytes,
  cipher : Bytes,
  mode : CipherMode,
) -> Bytes {
  @paigack/gmsm/sm2.sm2_decrypt(curve, private_key, cipher, mode)
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
