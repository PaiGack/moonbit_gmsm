///| Compatibility / API-completeness wrappers. These only construct existing
/// variants and are kept here per the project's deprecation convention.

///|
/// Returns the C1C2C3 cipher mode (constructs the variant for API completeness).
pub fn cipher_mode_c1c2c3() -> CipherMode {
  C1C2C3
}

///|
/// Returns the default C1C3C2 cipher mode (the layout produced by gmsm's
/// `Encrypt` with `mode = C1C3C2`).
pub fn cipher_mode_c1c3c2() -> CipherMode {
  C1C3C2
}

///|
/// Returns the ZeroRandom error (constructs the variant for API completeness).
pub fn sm2_error_zero_random() -> Sm2Error {
  ZeroRandom
}
