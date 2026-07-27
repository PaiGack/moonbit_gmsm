/// SM2 public key cryptography (GM/T 0003-2012)

///|
/// 256-bit big number: 4 × 64-bit limbs (little-endian)
pub type Bn = FixedArray[UInt64]

///|
pub(all) struct SM2Curve {
  p : Bn; a : Bn; b : Bn; n : Bn; gx : Bn; gy : Bn
}

///|
pub struct SM2PublicKey {
  curve : SM2Curve; x : Bn; y : Bn
}

///|
pub struct SM2PrivateKey {
  curve : SM2Curve; d : Bn
}

///|
pub enum CipherMode { C1C3C2; C1C2C3 }

///|
pub suberror Sm2Error {
  ZeroParam; NotOnCurve; InvalidCipher; InvalidSignature; InvalidPoint
  InvalidParameter; ZeroRandom; KdfZeroKey
} derive(Debug, Eq)

///|
pub fn sm2_p256() -> SM2Curve {
  SM2Curve::{
    p:  FixedArray::makei(4, fn(i) { match i { 0 => 0xFFFFFFFFFFFFFFFFUL; 1 => 0xFFFFFFFF00000000UL; 2 => 0xFFFFFFFFFFFFFFFFUL; 3 => 0xFFFFFFFEFFFFFFFFUL; _ => abort("unreachable") } }),
    a:  FixedArray::makei(4, fn(i) { match i { 0 => 0xFFFFFFFFFFFFFFFCUL; 1 => 0xFFFFFFFF00000000UL; 2 => 0xFFFFFFFFFFFFFFFFUL; 3 => 0xFFFFFFFEFFFFFFFFUL; _ => abort("unreachable") } }),
    b:  FixedArray::makei(4, fn(i) { match i { 0 => 0xDDBCBD414D940E93UL; 1 => 0xF39789F515AB8F92UL; 2 => 0x4D5A9E4BCF6509A7UL; 3 => 0x28E9FA9E9D9F5E34UL; _ => abort("unreachable") } }),
    n:  FixedArray::makei(4, fn(i) { match i { 0 => 0x53BBF40939D54123UL; 1 => 0x7203DF6B21C6052BUL; 2 => 0xFFFFFFFFFFFFFFFFUL; 3 => 0xFFFFFFFEFFFFFFFFUL; _ => abort("unreachable") } }),
    gx: FixedArray::makei(4, fn(i) { match i { 0 => 0x715A4589334C74C7UL; 1 => 0x8FE30BBFF2660BE1UL; 2 => 0x5F9904466A39C994UL; 3 => 0x32C4AE2C1F198119UL; _ => abort("unreachable") } }),
    gy: FixedArray::makei(4, fn(i) { match i { 0 => 0x02DF32E52139F0A0UL; 1 => 0xD0A9877CC62A4740UL; 2 => 0x59BDCEE36B692153UL; 3 => 0xBC3736A2F4F6779CUL; _ => abort("unreachable") } }),
  }
}

///|
pub fn private_key_from_bytes(curve : SM2Curve, d : Bytes) -> SM2PrivateKey raise Sm2Error {
  if d.length() != 32 { raise Sm2Error::InvalidParameter }
  let dv : Bn = FixedArray::makei(4, fn(_) { 0UL })
  bn_from_bytes(dv, d, 0)
  if bn_is_zero(dv) || !bn_lt(dv, curve.n) { raise Sm2Error::ZeroParam }
  SM2PrivateKey::{ curve, d: dv }
}

///|
pub fn public_key_from_xy(curve : SM2Curve, x : Bytes, y : Bytes) -> SM2PublicKey raise Sm2Error {
  if x.length() != 32 || y.length() != 32 { raise Sm2Error::InvalidParameter }
  let xv : Bn = FixedArray::makei(4, fn(_) { 0UL })
  let yv : Bn = FixedArray::makei(4, fn(_) { 0UL })
  bn_from_bytes(xv, x, 0)
  bn_from_bytes(yv, y, 0)
  if !point_is_on_curve_affine(xv, yv) { raise Sm2Error::NotOnCurve }
  SM2PublicKey::{ curve, x: xv, y: yv }
}

///|
pub fn generate_key(random : @random.Rand?) -> SM2PrivateKey {
  let curve = sm2_p256()
  let r = match random { Some(rr) => rr; None => @random.Rand::chacha8() }
  let d : Bn = FixedArray::makei(4, fn(_) { 0UL })
  while true {
    let buf = Bytes::makei(32, fn(_) { (r.int(limit=256) & 0xFF).to_byte() })
    bn_from_bytes(d, buf, 0)
    if !bn_is_zero(d) && bn_lt(d, curve.n) { break }
  }
  SM2PrivateKey::{ curve, d }
}

///|
pub fn derive_public_key(private_key : SM2PrivateKey) -> SM2PublicKey {
  let p : SM2Point = point_infinity()
  scalar_base_mult(p, private_key.d)
  let (x, y) = point_to_affine(p)
  SM2PublicKey::{ curve: private_key.curve, x, y }
}

///|
pub fn is_on_curve(public_key : SM2PublicKey) -> Bool {
  point_is_on_curve_affine(public_key.x, public_key.y)
}

///|
pub fn default_uid() -> Bytes { default_uid_impl() }

///|
/// Returns the C1C2C3 cipher mode (constructs the variant for API completeness).
pub fn cipher_mode_c1c2c3() -> CipherMode { C1C2C3 }

///|
/// Returns the ZeroRandom error (constructs the variant for API completeness).
pub fn sm2_error_zero_random() -> Sm2Error { ZeroRandom }

// --- helpers ---

fn add_to_8(r : FixedArray[UInt64], a : Bn) -> Unit {
  let mut carry : UInt64 = 0UL
  for i = 0; i < 4; i = i + 1 {
    let s1 = r[i] + a[i]
    let c1 : UInt64 = if s1 < r[i] { 1UL } else { 0UL }
    let s2 = s1 + carry
    let c2 : UInt64 = if s2 < s1 { 1UL } else { 0UL }
    r[i] = s2
    carry = c1 + c2
  }
  r[4] = r[4] + carry
}

fn bn_modinv_n(r : Bn, a : Bn, n : Bn) -> Unit {
  let n_minus_2 = FixedArray::makei(4, fn(i) { if i == 0 { n[0] - 2UL } else { n[i] } })
  r[0] = 1UL; r[1] = 0UL; r[2] = 0UL; r[3] = 0UL
  let base : Bn = FixedArray::makei(4, fn(_) { 0UL })
  bn_copy(base, a)
  for limb_idx = 3; limb_idx >= 0; limb_idx = limb_idx - 1 {
    let mut e = n_minus_2[limb_idx]
    for _bit = 0; _bit < 64; _bit = _bit + 1 {
      let bit_val = (e >> 63) & 1UL; e = e << 1
      bn_modsqr_n(r, r, n)
      if bit_val == 1UL { bn_modmul_n(r, r, base, n) }
    }
  }
}

fn bn_modmul_n(r : Bn, a : Bn, b : Bn, _n : Bn) -> Unit {
  let s8 : FixedArray[UInt64] = FixedArray::makei(8, fn(_) { 0UL })
  bn_mul(s8, a, b)
  bn_mod_n(r, s8)
}

fn bn_modsqr_n(r : Bn, a : Bn, n : Bn) -> Unit { bn_modmul_n(r, a, a, n) }

///|
pub fn sm2_sign(private_key : SM2PrivateKey, msg : Bytes, uid : Bytes, _random : @random.Rand?) -> (Bytes, Bytes) {
  let curve = private_key.curve
  let pubkey = derive_public_key(SM2PrivateKey::{ curve, d: private_key.d })
  let za_val = za(pubkey.x, pubkey.y, uid)
  let e = msg_hash(za_val, msg)
  let n = curve.n
  let one : Bn = FixedArray::makei(4, fn(i) { if i == 0 { 1UL } else { 0UL } })

  let one_plus_d : Bn = FixedArray::makei(4, fn(_) { 0UL })
  let da8 : FixedArray[UInt64] = FixedArray::makei(8, fn(i) { if i < 4 { one[i] } else { 0UL } })
  add_to_8(da8, private_key.d)
  bn_mod_n(one_plus_d, da8)

  let inv : Bn = FixedArray::makei(4, fn(_) { 0UL })
  bn_modinv_n(inv, one_plus_d, n)

  while true {
    let k = bn_rand_k(None)
    let p : SM2Point = point_infinity()
    scalar_base_mult(p, k)
    let (x1, _) = point_to_affine(p)

    let r8 : FixedArray[UInt64] = FixedArray::makei(8, fn(i) { if i < 4 { e[i] } else { 0UL } })
    add_to_8(r8, x1)
    let r : Bn = FixedArray::makei(4, fn(_) { 0UL })
    bn_mod_n(r, r8)
    if bn_is_zero(r) { continue }

    let rpk8 : FixedArray[UInt64] = FixedArray::makei(8, fn(i) { if i < 4 { r[i] } else { 0UL } })
    add_to_8(rpk8, k)
    let rpk : Bn = FixedArray::makei(4, fn(_) { 0UL })
    bn_mod_n(rpk, rpk8)
    let zero : Bn = FixedArray::makei(4, fn(_) { 0UL })
    if bn_eq(rpk, zero) || bn_eq(rpk, n) { continue }

    let rd8 : FixedArray[UInt64] = FixedArray::makei(8, fn(_) { 0UL })
    bn_mul(rd8, r, private_key.d)
    let rd : Bn = FixedArray::makei(4, fn(_) { 0UL })
    bn_mod_n(rd, rd8)

    // t = (k - r*d) mod n; k < n and rd < n, so on borrow add n back.
    let t : Bn = FixedArray::makei(4, fn(_) { 0UL })
    let borrow = bn_sub(t, k, rd)
    if borrow != 0U {
      bn_add(t, t, n) |> ignore
    }
    let s : Bn = FixedArray::makei(4, fn(_) { 0UL })
    bn_modmul_n(s, inv, t, n)
    if bn_is_zero(s) { continue }
    return (bn_to_bytes(r), bn_to_bytes(s))
  }
  abort("unreachable")
}

///|
pub fn sm2_verify(public_key : SM2PublicKey, msg : Bytes, uid : Bytes, r : Bytes, s : Bytes) -> Bool raise Sm2Error {
  let curve = public_key.curve; let n = curve.n
  if r.length() != 32 || s.length() != 32 { raise Sm2Error::InvalidSignature }
  let rv : Bn = FixedArray::makei(4, fn(_) { 0UL })
  let sv : Bn = FixedArray::makei(4, fn(_) { 0UL })
  bn_from_bytes(rv, r, 0); bn_from_bytes(sv, s, 0)
  if bn_is_zero(rv) || !bn_lt(rv, n) { raise Sm2Error::InvalidSignature }
  if bn_is_zero(sv) || !bn_lt(sv, n) { raise Sm2Error::InvalidSignature }

  let rps8 : FixedArray[UInt64] = FixedArray::makei(8, fn(i) { if i < 4 { rv[i] } else { 0UL } })
  add_to_8(rps8, sv)
  let t : Bn = FixedArray::makei(4, fn(_) { 0UL })
  bn_mod_n(t, rps8)
  if bn_is_zero(t) { return false }

  let za_val = za(public_key.x, public_key.y, uid)
  let e = msg_hash(za_val, msg)

  let sg : SM2Point = point_infinity(); scalar_base_mult(sg, sv)
  let tp : SM2Point = point_infinity()
  let p_pt = SM2Point::{ x: public_key.x, y: public_key.y, z: FixedArray::makei(4, fn(i) { if i == 0 { 1UL } else { 0UL } }) }
  scalar_mult(tp, t, p_pt); point_add(sg, tp)
  let (x1, _) = point_to_affine(sg)

  let e8 : FixedArray[UInt64] = FixedArray::makei(8, fn(i) { if i < 4 { e[i] } else { 0UL } })
  add_to_8(e8, x1)
  let r_res : Bn = FixedArray::makei(4, fn(_) { 0UL })
  bn_mod_n(r_res, e8)
  bn_eq(r_res, rv)
}

// --- ASN.1 DER ---

fn encode_asn1_length(len : Int) -> Bytes {
  if len < 128 { return Bytes::from_array([len.to_byte()]) }
  let mut temp = len; let mut byte_count = 0
  while temp > 0 { byte_count = byte_count + 1; temp = temp >> 8 }
  Bytes::makei(1 + byte_count, fn(i) {
    if i == 0 { (0x80 | byte_count).to_byte() }
    else { ((len >> ((byte_count - i) * 8)) & 0xFF).to_byte() }
  })
}

fn decode_asn1_length(data : Bytes, off : Int) -> (Int, Int) {
  if off >= data.length() { abort("ASN.1: out of bounds") }
  let first = data[off].to_uint()
  if first < 0x80U { return (first.reinterpret_as_int(), 1) }
  let num_bytes = first.reinterpret_as_int() & 0x7F
  if num_bytes == 0 || off + 1 + num_bytes > data.length() { abort("ASN.1: invalid long length") }
  let mut len : Int = 0
  for i = 0; i < num_bytes; i = i + 1 { len = (len << 8) | data[off + 1 + i].to_int() }
  (len, 1 + num_bytes)
}

fn pad_left(data : Bytes, target : Int) -> Bytes {
  if data.length() >= target { return data }
  Bytes::makei(target, fn(i) { let o = target - data.length(); if i < o { b'\x00' } else { data[i - o] } })
}

/// Normalize an ASN.1 INTEGER content to exactly 32 bytes:
/// strip leading zero bytes (sign padding), then left-pad with zeros.
fn normalize_32(data : Bytes) -> Bytes {
  let mut start = 0
  while start < data.length() - 1 && data[start] == b'\x00' && data.length() - start > 32 {
    start = start + 1
  }
  if data.length() - start > 32 { abort("integer too large") }
  pad_left(data[start:].to_owned(), 32)
}

fn encode_asn1_integer(bytes : Bytes) -> Bytes {
  let mut start = 0
  while start < bytes.length() && bytes[start] == b'\x00' { start = start + 1 }
  let remaining = bytes.length() - start
  if remaining == 0 { return Bytes::from_array([b'\x02', b'\x01', b'\x00']) }
  let pad = (bytes[start].to_uint() & 0x80U) != 0U
  let content_len = if pad { remaining + 1 } else { remaining }
  let lb = encode_asn1_length(content_len)
  let total = 1 + lb.length() + content_len
  Bytes::makei(total, fn(i) {
    if i == 0 { b'\x02' }
    else if i < 1 + lb.length() { lb[i - 1] }
    else {
      let vi = i - 1 - lb.length()
      if pad { if vi == 0 { b'\x00' } else { bytes[start + vi - 1] } }
      else { bytes[start + vi] }
    }
  })
}

fn encode_asn1_octet_string(data : Bytes) -> Bytes {
  let lb = encode_asn1_length(data.length())
  Bytes::makei(1 + lb.length() + data.length(), fn(i) {
    if i == 0 { b'\x04' } else if i < 1 + lb.length() { lb[i - 1] } else { data[i - 1 - lb.length()] }
  })
}

fn concat_bytes_array(segments : Array[Bytes]) -> Bytes {
  let mut total : Int = 0
  for j = 0; j < segments.length(); j = j + 1 { total = total + segments[j].length() }
  Bytes::makei(total, fn(idx) {
    let mut pos = idx
    for j = 0; j < segments.length(); j = j + 1 {
      let seg = segments[j]; let sl = seg.length()
      if pos < sl { return seg[pos] }
      pos = pos - sl
    }
    abort("unreachable")
  })
}

fn sign_data_to_sign_digit(r : Bytes, s : Bytes) -> Bytes {
  let rd = encode_asn1_integer(r); let sd = encode_asn1_integer(s)
  let cl = rd.length() + sd.length(); let sl = encode_asn1_length(cl)
  concat_bytes_array([Bytes::from_array([b'\x30']), sl, rd, sd])
}

fn sign_digit_to_sign_data(der : Bytes) -> Result[(Bytes, Bytes), String] {
  if der.length() < 4 { return Err("too short") }
  if der[0] != b'\x30' { return Err("not SEQUENCE") }
  let (_, sl1) = decode_asn1_length(der, 1)
  let mut off = 1 + sl1
  if der[off] != b'\x02' { return Err("expected INTEGER") }
  off = off + 1
  let (rl, rls) = decode_asn1_length(der, off); off = off + rls
  let rv = normalize_32(der[off:off + rl].to_owned()); off = off + rl
  if der[off] != b'\x02' { return Err("expected INTEGER") }
  off = off + 1
  let (sl2, sls) = decode_asn1_length(der, off); off = off + sls
  let sv = normalize_32(der[off:off + sl2].to_owned())
  Ok((rv, sv))
}

pub fn sm2_sign_der(pk : SM2PrivateKey, msg : Bytes, uid : Bytes, r : @random.Rand?) -> Bytes {
  let (rv, sv) = sm2_sign(pk, msg, uid, r)
  sign_data_to_sign_digit(rv, sv)
}

pub fn sm2_verify_der(pubk : SM2PublicKey, msg : Bytes, uid : Bytes, der : Bytes) -> Bool raise Sm2Error {
  match sign_digit_to_sign_data(der) {
    Ok((rv, sv)) => sm2_verify(pubk, msg, uid, rv, sv)
    Err(_) => false
  }
}

// --- Encrypt/Decrypt ---

pub fn sm2_encrypt(pubk : SM2PublicKey, msg : Bytes, random : @random.Rand?, mode : CipherMode) -> Bytes raise Sm2Error {
  let r = match random { Some(rr) => rr; None => @random.Rand::chacha8() }
  let k = bn_rand_k(Some(r))
  let c1_p : SM2Point = point_infinity(); scalar_base_mult(c1_p, k)
  let (c1x, c1y) = point_to_affine(c1_p)

  let kp_pt = SM2Point::{ x: pubk.x, y: pubk.y, z: FixedArray::makei(4, fn(i) { if i == 0 { 1UL } else { 0UL } }) }
  let kp : SM2Point = point_infinity(); scalar_mult(kp, k, kp_pt)
  let (x2, y2) = point_to_affine(kp)

  let x2b = bn_to_bytes(x2); let y2b = bn_to_bytes(y2)
  let (t, ok) = kdf(msg.length(), [x2b, y2b])
  if !ok { raise Sm2Error::KdfZeroKey }

  let c2 = Bytes::makei(msg.length(), fn(i) { (msg[i].to_int() ^ t[i].to_int()).to_byte() })
  let c3_input = concat_bytes_array([x2b, msg, y2b]); let c3 = @sm3.sm3_sum(c3_input)
  let c1x_b = bn_to_bytes(c1x); let c1y_b = bn_to_bytes(c1y)
  let c1 = Bytes::makei(65, fn(i) { if i == 0 { b'\x04' } else if i <= 32 { c1x_b[i - 1] } else { c1y_b[i - 33] } })

  match mode {
    C1C3C2 => Bytes::makei(65 + 32 + c2.length(), fn(i) {
      if i < 65 { c1[i] } else if i < 97 { c3[i - 65] } else { c2[i - 97] }
    })
    C1C2C3 => Bytes::makei(65 + c2.length() + 32, fn(i) {
      if i < 65 { c1[i] } else if i < 65 + c2.length() { c2[i - 65] } else { c3[i - 65 - c2.length()] }
    })
  }
}

pub fn sm2_decrypt(pk : SM2PrivateKey, cipher : Bytes, mode : CipherMode) -> Bytes raise Sm2Error {
  if cipher.length() < 97 || cipher[0] != b'\x04' { raise Sm2Error::InvalidCipher }
  let (c2, c3) = match mode {
    C1C3C2 => (cipher[97:].to_owned(), cipher[65:97].to_owned())
    C1C2C3 => { let cl = cipher.length() - 97; (cipher[65:65 + cl].to_owned(), cipher[65 + cl:].to_owned()) }
  }
  let c1x_b : Bn = FixedArray::makei(4, fn(_) { 0UL }); bn_from_bytes(c1x_b, cipher, 1)
  let c1y_b : Bn = FixedArray::makei(4, fn(_) { 0UL }); bn_from_bytes(c1y_b, cipher, 33)
  if !point_is_on_curve_affine(c1x_b, c1y_b) { raise Sm2Error::InvalidCipher }

  let c1_pt = SM2Point::{ x: c1x_b, y: c1y_b, z: FixedArray::makei(4, fn(i) { if i == 0 { 1UL } else { 0UL } }) }
  let kp2 : SM2Point = point_infinity(); scalar_mult(kp2, pk.d, c1_pt)
  let (x2, y2) = point_to_affine(kp2)

  let x2b = bn_to_bytes(x2); let y2b = bn_to_bytes(y2)
  let (t, ok) = kdf(c2.length(), [x2b, y2b])
  if !ok { raise Sm2Error::KdfZeroKey }

  let dec = Bytes::makei(c2.length(), fn(i) { (c2[i].to_int() ^ t[i].to_int()).to_byte() })
  let u_input = concat_bytes_array([x2b, dec, y2b]); let u = @sm3.sm3_sum(u_input)
  if u.length() != c3.length() { raise Sm2Error::InvalidCipher }
  for i = 0; i < u.length(); i = i + 1 { if u[i] != c3[i] { raise Sm2Error::InvalidCipher } }
  dec
}

pub fn sm2_encrypt_asn1(pubk : SM2PublicKey, msg : Bytes, r : @random.Rand?) -> Bytes raise Sm2Error {
  cipher_marshal(sm2_encrypt(pubk, msg, r, C1C3C2))
}

pub fn sm2_decrypt_asn1(pk : SM2PrivateKey, der : Bytes) -> Bytes raise Sm2Error {
  sm2_decrypt(pk, cipher_unmarshal(der), C1C3C2)
}

pub fn cipher_marshal(cipher : Bytes) -> Bytes {
  if cipher.length() < 97 || cipher[0] != b'\x04' { abort("invalid cipher") }
  let x = cipher[1:33].to_owned(); let y = cipher[33:65].to_owned()
  let c3 = cipher[65:97].to_owned(); let c2 = cipher[97:].to_owned()
  concat_bytes_array([Bytes::from_array([b'\x30']),
    encode_asn1_length(encode_asn1_integer(x).length() + encode_asn1_integer(y).length() + encode_asn1_octet_string(c3).length() + encode_asn1_octet_string(c2).length()),
    encode_asn1_integer(x), encode_asn1_integer(y), encode_asn1_octet_string(c3), encode_asn1_octet_string(c2)])
}

pub fn cipher_unmarshal(der : Bytes) -> Bytes {
  if der.length() < 4 || der[0] != b'\x30' { abort("invalid DER") }
  let (_, sl1) = decode_asn1_length(der, 1); let mut off = 1 + sl1

  if der[off] != b'\x02' { abort("expected INTEGER") }; off = off + 1
  let (xl, xls) = decode_asn1_length(der, off); off = off + xls
  let xv = normalize_32(der[off:off + xl].to_owned()); off = off + xl

  if der[off] != b'\x02' { abort("expected INTEGER") }; off = off + 1
  let (yl, yls) = decode_asn1_length(der, off); off = off + yls
  let yv = normalize_32(der[off:off + yl].to_owned()); off = off + yl

  if der[off] != b'\x04' { abort("expected OCTET STRING") }; off = off + 1
  let (c3l, c3ls) = decode_asn1_length(der, off); off = off + c3ls
  let c3v = der[off:off + c3l].to_owned(); off = off + c3l

  if der[off] != b'\x04' { abort("expected OCTET STRING") }; off = off + 1
  let (c2l, c2ls) = decode_asn1_length(der, off); off = off + c2ls
  let c2v = der[off:off + c2l].to_owned()

  Bytes::makei(1 + 64 + c3v.length() + c2v.length(), fn(i) {
    if i == 0 { b'\x04' } else if i <= 32 { xv[i - 1] } else if i <= 64 { yv[i - 33] }
    else if i <= 64 + c3v.length() { c3v[i - 65] } else { c2v[i - 65 - c3v.length()] }
  })
}

// --- Key Exchange ---

fn point_from_pubkey(pk : SM2PublicKey) -> SM2Point {
  SM2Point::{ x: pk.x, y: pk.y, z: FixedArray::makei(4, fn(i) { if i == 0 { 1UL } else { 0UL } }) }
}

pub fn key_exchange_a(klen : Int, ida : Bytes, idb : Bytes, priA : SM2PrivateKey, pubB : SM2PublicKey,
  rpriA : SM2PrivateKey, rpubB : SM2PublicKey) -> (Bytes, Bytes, Bytes) {
  let _curve = priA.curve
  let pubA = derive_public_key(priA)
  let rpubA = derive_public_key(rpriA)

  let x_hat = ke_x_hat(rpubB.x)
  let xhr_8 : FixedArray[UInt64] = FixedArray::makei(8, fn(_) { 0UL }); bn_mul(xhr_8, x_hat, rpriA.d)
  let xhr : Bn = FixedArray::makei(4, fn(_) { 0UL }); bn_mod_n(xhr, xhr_8)
  let ta8 : FixedArray[UInt64] = FixedArray::makei(8, fn(i) { if i < 4 { priA.d[i] } else { 0UL } }); add_to_8(ta8, xhr)
  let ta : Bn = FixedArray::makei(4, fn(_) { 0UL }); bn_mod_n(ta, ta8)

  let xrb : SM2Point = point_infinity(); scalar_mult(xrb, x_hat, point_from_pubkey(rpubB))
  point_add(xrb, point_from_pubkey(pubB))
  let v_pt : SM2Point = point_infinity(); scalar_mult(v_pt, ta, xrb)
  let (x2, y2) = point_to_affine(v_pt)

  let za_a = za(pubA.x, pubA.y, ida); let zb_b = za(pubB.x, pubB.y, idb)
  let x2b = bn_to_bytes(x2); let y2b = bn_to_bytes(y2)
  let (k, ok) = kdf(klen, [x2b, y2b, za_a, zb_b])
  if !ok { abort("KDF all-zero key") }

  let inner = compute_ke_inner(x2b, za_a, zb_b, rpubA.x, rpubA.y, x2, y2)
  let s1 = compute_ke_s(Bytes::from_array([b'\x02']), y2b, inner)
  let s2 = compute_ke_s(Bytes::from_array([b'\x03']), y2b, inner)
  (k, s1, s2)
}

pub fn key_exchange_b(klen : Int, ida : Bytes, idb : Bytes, priB : SM2PrivateKey, pubA : SM2PublicKey,
  rpriB : SM2PrivateKey, rpubA : SM2PublicKey) -> (Bytes, Bytes, Bytes) {
  let _curve = priB.curve
  let pubB = derive_public_key(priB)
  let rpubB = derive_public_key(rpriB)

  let x_hat = ke_x_hat(rpubA.x)
  let xhr_8 : FixedArray[UInt64] = FixedArray::makei(8, fn(_) { 0UL }); bn_mul(xhr_8, x_hat, rpriB.d)
  let xhr : Bn = FixedArray::makei(4, fn(_) { 0UL }); bn_mod_n(xhr, xhr_8)
  let tb8 : FixedArray[UInt64] = FixedArray::makei(8, fn(i) { if i < 4 { priB.d[i] } else { 0UL } }); add_to_8(tb8, xhr)
  let tb : Bn = FixedArray::makei(4, fn(_) { 0UL }); bn_mod_n(tb, tb8)

  let xra : SM2Point = point_infinity(); scalar_mult(xra, x_hat, point_from_pubkey(rpubA))
  point_add(xra, point_from_pubkey(pubA))
  let v2_pt : SM2Point = point_infinity(); scalar_mult(v2_pt, tb, xra)
  let (x2, y2) = point_to_affine(v2_pt)

  let za_a = za(pubA.x, pubA.y, ida); let zb_b = za(pubB.x, pubB.y, idb)
  let x2b = bn_to_bytes(x2); let y2b = bn_to_bytes(y2)
  let (k, ok) = kdf(klen, [x2b, y2b, za_a, zb_b])
  if !ok { abort("KDF all-zero key") }

  let inner = compute_ke_inner(x2b, za_a, zb_b, rpubB.x, rpubB.y, x2, y2)
  let s1 = compute_ke_s(Bytes::from_array([b'\x02']), y2b, inner)
  let s2 = compute_ke_s(Bytes::from_array([b'\x03']), y2b, inner)
  (k, s1, s2)
}

fn compute_ke_inner(x2b : Bytes, za : Bytes, zb : Bytes, x1 : Bn, y1 : Bn, x2 : Bn, y2 : Bn) -> Bytes {
  @sm3.sm3_sum(concat_bytes_array([x2b, za, zb, bn_to_bytes(x1), bn_to_bytes(y1), bn_to_bytes(x2), bn_to_bytes(y2)]))
}

fn compute_ke_s(prefix : Bytes, y2 : Bytes, inner : Bytes) -> Bytes {
  @sm3.sm3_sum(concat_bytes_array([prefix, y2, inner]))
}

// --- Compression ---

pub fn compress_point(p : SM2PublicKey) -> Bytes {
  let xb = bn_to_bytes(p.x)
  Bytes::makei(33, fn(i) { if i == 0 { if (p.y[0] & 1UL) == 0UL { b'\x02' } else { b'\x03' } } else { xb[i - 1] } })
}

pub fn decompress_point(b : Bytes) -> SM2PublicKey raise Sm2Error {
  if b.length() != 33 || (b[0] != b'\x02' && b[0] != b'\x03') { raise Sm2Error::InvalidPoint }
  let curve = sm2_p256()
  let x : Bn = FixedArray::makei(4, fn(_) { 0UL }); bn_from_bytes(x, b, 1)

  let x2 : Bn = FixedArray::makei(4, fn(_) { 0UL }); bn_modsqr_p(x2, x)
  let x3 : Bn = FixedArray::makei(4, fn(_) { 0UL }); bn_modmul_p(x3, x2, x)

  let three_x : Bn = FixedArray::makei(4, fn(_) { 0UL })
  bn_addmod_p(three_x, x, x)
  bn_addmod_p(three_x, three_x, x)
  let ax : Bn = FixedArray::makei(4, fn(_) { 0UL })
  if bn_is_zero(three_x) { bn_zero(ax) } else { bn_sub(ax, curve.p, three_x) |> ignore }

  let y2 : Bn = FixedArray::makei(4, fn(_) { 0UL }); bn_addmod_p(y2, x3, ax); bn_addmod_p(y2, y2, curve.b)
  // exp = (p+1)/4, used to compute the modular square root y = (y^2)^((p+1)/4)
  let exp : Bn = FixedArray::makei(4, fn(i) { match i { 0 => 0x4000000000000000UL; 1 => 0xFFFFFFFFC0000000UL; 2 => 0xFFFFFFFFFFFFFFFFUL; 3 => 0x3FFFFFFFBFFFFFFFUL; _ => abort("unreachable") } })
  let y : Bn = FixedArray::makei(4, fn(_) { 0UL }); bn_exp_mod_p(y, y2, exp)

  let exp_par = if b[0] == b'\x02' { 0UL } else { 1UL }
  if (y[0] & 1UL) != exp_par { bn_sub(y, curve.p, y) |> ignore }
  public_key_from_xy(curve, bn_to_bytes(x), bn_to_bytes(y))
}
