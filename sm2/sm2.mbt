/// SM2 cryptographic algorithm (GB/T 32918-2016).
/// Implements SM2 digital signature, encryption/decryption, key exchange and key generation.
/// Uses SM3 hash for message digestion.

///|
/// SM2 public key.
pub(all) struct PubKey {
  x : BigInt
  y : BigInt
}

///|
/// SM2 private key containing the public key and secret d.
pub(all) struct PriKey {
  pubkey : PubKey
  d : BigInt
}

///|
/// Default SM2 user ID for signing/verification (16 bytes of "1234567812345678")
let default_uid : Bytes = b"\x31\x32\x33\x34\x35\x36\x37\x38\x31\x32\x33\x34\x35\x36\x37\x38"

///|
/// SM2 curve parameters (sm2p256v1).
priv struct Sm2Curve {
  p : BigInt
  n : BigInt
  a : BigInt
  b : BigInt
  gx : BigInt
  gy : BigInt
}

///|
fn sm2_curve() -> Sm2Curve {
  {
    p: BigInt::from_string(
      "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
      radix=16,
    ),
    n: BigInt::from_string(
      "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
      radix=16,
    ),
    a: BigInt::from_string(
      "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
      radix=16,
    ),
    b: BigInt::from_string(
      "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
      radix=16,
    ),
    gx: BigInt::from_string(
      "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
      radix=16,
    ),
    gy: BigInt::from_string(
      "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
      radix=16,
    ),
  }
}

///|
/// Check if a point is on the SM2 curve: y^2 = x^3 + ax + b (mod p)
fn is_on_curve(x : BigInt, y : BigInt, c : Sm2Curve) -> Bool {
  let lhs = y * y % c.p
  let x3 = x * x % c.p * x % c.p
  let ax = c.a * x % c.p
  let rhs = (x3 + ax + c.b) % c.p
  lhs == rhs
}

///|
/// Point addition on the SM2 curve in affine coordinates.
fn point_add(
  x1 : BigInt,
  y1 : BigInt,
  x2 : BigInt,
  y2 : BigInt,
  c : Sm2Curve,
) -> (BigInt, BigInt) {
  if x1 == 0 && y1 == 0 {
    return (x2, y2)
  }
  if x2 == 0 && y2 == 0 {
    return (x1, y1)
  }
  if x1 == x2 {
    if y1 == y2 {
      return point_double(x1, y1, c)
    } else {
      return (0, 0)
    }
  }
  let dx = _mod_abs(x2 - x1, c.p)
  let dy = _mod_abs(y2 - y1, c.p)
  let lambda = dy * _mod_inv(dx, c.p) % c.p
  let x3 = _mod_abs(lambda * lambda - x1 - x2, c.p)
  let y3 = _mod_abs(lambda * (x1 - x3) - y1, c.p)
  (x3, y3)
}

///|
/// Point doubling on the SM2 curve in affine coordinates.
fn point_double(x : BigInt, y : BigInt, c : Sm2Curve) -> (BigInt, BigInt) {
  if y == 0 {
    return (0, 0)
  }
  let x2 = x * x % c.p
  let num = _mod_abs(3 * x2 + c.a, c.p)
  let den = _mod_abs(2 * y, c.p)
  let lambda = num * _mod_inv(den, c.p) % c.p
  let x3 = _mod_abs(lambda * lambda - 2 * x, c.p)
  let y3 = _mod_abs(lambda * (x - x3) - y, c.p)
  (x3, y3)
}

///|
/// Reduce a BigInt to non-negative modulo m.
fn _mod_abs(x : BigInt, m : BigInt) -> BigInt {
  let mut r = x % m
  if r < 0 {
    r = r + m
  }
  r
}

///|
/// Modular inverse using extended Euclidean algorithm.
fn _mod_inv(a : BigInt, m : BigInt) -> BigInt {
  let a_norm = _mod_abs(a, m)
  let mut t : BigInt = 0
  let mut newt : BigInt = 1
  let mut r : BigInt = m
  let mut newr : BigInt = a_norm
  while newr != 0 {
    let quotient = r / newr
    let tmp = t - quotient * newt
    t = newt
    newt = tmp
    let tmp2 = r - quotient * newr
    r = newr
    newr = tmp2
  }
  if r > 1 {
    0
  } else if t < 0 {
    t + m
  } else {
    t
  }
}

///|
/// Scalar multiplication using double-and-add.
fn scalar_mult(
  x : BigInt,
  y : BigInt,
  k : BigInt,
  c : Sm2Curve,
) -> (BigInt, BigInt) {
  let mut rx : BigInt = 0
  let mut ry : BigInt = 0
  let mut px : BigInt = x
  let mut py : BigInt = y
  let mut kk : BigInt = k
  while kk > 0 {
    if (kk & 1) == 1 {
      let (nx, ny) = point_add(rx, ry, px, py, c)
      rx = nx
      ry = ny
    }
    let (nx, ny) = point_double(px, py, c)
    px = nx
    py = ny
    kk = kk >> 1
  }
  (rx, ry)
}

///|
/// Scalar multiplication with base point G.
fn scalar_base_mult(k : BigInt, c : Sm2Curve) -> (BigInt, BigInt) {
  scalar_mult(c.gx, c.gy, k, c)
}

///|
/// Generate a random BigInt in [1, n-1].
fn rand_field_element(n : BigInt) -> BigInt {
  let bitlen = n.bit_length()
  let bytelen = (bitlen + 7) / 8 + 8
  let mut retries : Int = 0
  let nm1 : BigInt = n - 1
  let one : BigInt = 1
  while retries < 100 {
    let buf : Bytes = _random_bytes(bytelen)
    let mut k : BigInt = BigInt::from_octets(buf, signum=1)
    k = k % nm1 + one
    if k > 0 {
      return k
    }
    retries = retries + 1
  }
  1
}

///|
/// Simple PRNG for testing purposes.
fn _random_bytes(n : Int) -> Bytes {
  let arr : Array[Byte] = Array::make(n, b'\x00')
  for i in 0..<n {
    arr[i] = (_simple_rand() & 0xFF).to_byte()
  }
  Bytes::from_array(arr)
}

///|
/// Simple PRNG using Ref.
fn _simple_rand() -> Int {
  let rs = _rand_ref()
  rs.val = (rs.val * 1103515245 + 12345).land(0x7FFFFFFF)
  rs.val
}

///|
fn _rand_ref() -> @ref.Ref[Int] {
  _rand_ref_state
}

///|
let _rand_ref_state : @ref.Ref[Int] = @ref.new(0x0DEADBEEF)

///|
/// Compute Z_A = H_256(ENTL_A || ID_A || a || b || x_G || y_G || x_A || y_A)
fn za(pubkey : PubKey, uid : Bytes) -> Bytes {
  let uid_len = uid.length()
  let entla : Int = 8 * uid_len
  let curve = sm2_curve()

  let h = @paigack/gmsm/sm3.SM3::new()
  h.write(
    Bytes::from_array([
      ((entla >> 8) & 0xFF).to_byte(),
      (entla & 0xFF).to_byte(),
    ]),
  )
  if uid_len > 0 {
    h.write(uid)
  }
  h.write(_bigint_to_32bytes(curve.a))
  h.write(_bigint_to_32bytes(curve.b))
  h.write(_bigint_to_32bytes(curve.gx))
  h.write(_bigint_to_32bytes(curve.gy))
  h.write(_bigint_to_32bytes(pubkey.x))
  h.write(_bigint_to_32bytes(pubkey.y))
  h.sum()
}

///|
/// Convert a BigInt to 32-byte big-endian representation.
fn _bigint_to_32bytes(n : BigInt) -> Bytes {
  let octets = n.to_octets()
  let len = octets.length()
  if len < 32 {
    let arr : Array[Byte] = Array::make(32 - len, b'\x00')
    for i in 0..<len {
      arr.push(octets[i])
    }
    Bytes::from_array(arr)
  } else if len > 32 {
    let arr : Array[Byte] = Array::make(32, b'\x00')
    for i in 0..<32 {
      arr[i] = octets[len - 32 + i]
    }
    Bytes::from_array(arr)
  } else {
    octets
  }
}

///|
/// Compute message hash: H_256(Z_A || M)
fn _msg_hash(za_val : Bytes, msg : Bytes) -> Bytes {
  @paigack/gmsm/sm3.sm3_sum_multi([za_val, msg])
}

///|
/// SM2 signature. Returns (r, s) as BigInt.
pub fn sm2_sign(
  prikey : PriKey,
  msg : Bytes,
  uid : Bytes,
  _random : Bool,
) -> (BigInt, BigInt) {
  let curve = sm2_curve()
  let uid_actual : Bytes = if uid.length() == 0 { default_uid } else { uid }
  let za_val = za(prikey.pubkey, uid_actual)
  let digest = _msg_hash(za_val, msg)
  let e : BigInt = BigInt::from_octets(digest, signum=1)
  let n = curve.n

  let mut attempt : Int = 0
  let mut result : (BigInt, BigInt)? = _try_sign(prikey.d, e, n, curve)
  while result is None && attempt < 1000 {
    result = _try_sign(prikey.d, e, n, curve)
    attempt = attempt + 1
  }
  match result {
    Some(pair) => pair
    None => (0, 0)
  }
}

///|
fn _try_sign(
  d : BigInt,
  e : BigInt,
  n : BigInt,
  curve : Sm2Curve,
) -> (BigInt, BigInt)? {
  let one : BigInt = 1
  let k = rand_field_element(n)
  let (x1, _y1) = scalar_base_mult(k, curve)
  let r = _mod_abs(x1 + e, n)
  if r == 0 || r + k == n {
    return None
  }
  let rd = _mod_abs(d * r, n)
  let s_val = _mod_abs(k - rd, n)
  let d1 = _mod_abs(d + one, n)
  let d1_inv = _mod_inv(d1, n)
  let s_val2 = _mod_abs(s_val * d1_inv, n)
  if s_val2 == 0 {
    return None
  }
  Some((r, s_val2))
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
  let curve = sm2_curve()
  let n = curve.n
  let one : BigInt = 1

  if r < one || s < one || r >= n || s >= n {
    return false
  }

  let uid_actual : Bytes = if uid.length() == 0 { default_uid } else { uid }
  let za_val = za(pubkey, uid_actual)
  let digest = _msg_hash(za_val, msg)
  let e : BigInt = BigInt::from_octets(digest, signum=1)

  let t = _mod_abs(r + s, n)
  if t == 0 {
    return false
  }

  let (x1, y1) = scalar_base_mult(s, curve)
  let (x2, y2) = scalar_mult(pubkey.x, pubkey.y, t, curve)
  let (x, _y) = point_add(x1, y1, x2, y2, curve)

  let x_val = _mod_abs(x + e, n)
  x_val == r
}

///|
/// SM2 encryption. Returns encrypted bytes.
pub fn sm2_encrypt(pubkey : PubKey, data : Bytes, mode : Int) -> Bytes? {
  let curve = sm2_curve()

  let mut attempt : Int = 0
  let mut result : Bytes? = None
  while result is None && attempt < 1000 {
    result = _try_encrypt(pubkey, data, mode, curve)
    attempt = attempt + 1
  }
  result
}

///|
fn _try_encrypt(
  pubkey : PubKey,
  data : Bytes,
  mode : Int,
  curve : Sm2Curve,
) -> Bytes? {
  let length = data.length()
  let k = rand_field_element(curve.n)
  let (x1, y1) = scalar_base_mult(k, curve)
  let (x2, y2) = scalar_mult(pubkey.x, pubkey.y, k, curve)

  let x1_buf = _bigint_to_32bytes(x1)
  let y1_buf = _bigint_to_32bytes(y1)
  let x2_buf = _bigint_to_32bytes(x2)
  let y2_buf = _bigint_to_32bytes(y2)

  let c1 = _bytes_concat(x1_buf, y1_buf)

  let tm : Array[Byte] = x2_buf.to_array()
  for i in 0..<length {
    tm.push(data[i])
  }
  for bi in y2_buf {
    tm.push(bi)
  }
  let hash = @paigack/gmsm/sm3.sm3_sum(Bytes::from_array(tm))

  let kdf_result = _kdf(length, x2_buf, y2_buf)
  match kdf_result {
    Some(ct) => {
      let c2 : Array[Byte] = Array::make(length, b'\x00')
      for i in 0..<length {
        c2[i] = ct[i] ^ data[i]
      }
      let c2_bytes = Bytes::from_array(c2)
      if mode == 0 {
        Some(
          _bytes_cat3(
            Bytes::from_array([b'\x04']),
            c1,
            _bytes_concat(hash, c2_bytes),
          ),
        )
      } else {
        Some(
          _bytes_cat3(
            Bytes::from_array([b'\x04']),
            c1,
            _bytes_concat(c2_bytes, hash),
          ),
        )
      }
    }
    None => None
  }
}

///|
/// SM2 decryption. Returns decrypted bytes.
pub fn sm2_decrypt(prikey : PriKey, data : Bytes, mode : Int) -> Bytes? {
  let curve = sm2_curve()
  let data_len = data.length()

  let start_idx : Int = if data_len > 0 && data[0] == b'\x04' { 1 } else { 0 }
  let buf_len = data_len - start_idx
  if buf_len < 96 {
    return None
  }

  let x1_buf : Bytes = _sub_bytes(data, start_idx, start_idx + 32)
  let y1_buf : Bytes = _sub_bytes(data, start_idx + 32, start_idx + 64)

  let (c3_buf, c2_buf) : (Bytes, Bytes) = if mode == 0 {
    (
      _sub_bytes(data, start_idx + 64, start_idx + 96),
      _sub_bytes(data, start_idx + 96, data_len),
    )
  } else {
    (
      _sub_bytes(data, data_len - 32, data_len),
      _sub_bytes(data, start_idx + 64, data_len - 32),
    )
  }

  let x = BigInt::from_octets(x1_buf, signum=1)
  let y = BigInt::from_octets(y1_buf, signum=1)

  let (x2, y2) = scalar_mult(x, y, prikey.d, curve)
  let x2_buf = _bigint_to_32bytes(x2)
  let y2_buf = _bigint_to_32bytes(y2)

  let c2_len = c2_buf.length()
  let kdf_result = _kdf(c2_len, x2_buf, y2_buf)
  match kdf_result {
    Some(c_val) => {
      let plaintext : Array[Byte] = Array::make(c2_len, b'\x00')
      for i in 0..<c2_len {
        plaintext[i] = c_val[i] ^ c2_buf[i]
      }
      let tm : Array[Byte] = x2_buf.to_array()
      for i in 0..<c2_len {
        tm.push(plaintext[i])
      }
      for bi in y2_buf {
        tm.push(bi)
      }
      let h2 = @paigack/gmsm/sm3.sm3_sum(Bytes::from_array(tm))
      if h2 != c3_buf {
        return None
      }
      Some(Bytes::from_array(plaintext))
    }
    None => None
  }
}

///|
fn _sub_bytes(data : Bytes, start : Int, end : Int) -> Bytes {
  let len = end - start
  let arr : Array[Byte] = Array::make(len, b'\x00')
  for i in 0..<len {
    arr[i] = data[start + i]
  }
  Bytes::from_array(arr)
}

///|
fn _bytes_concat(a : Bytes, b : Bytes) -> Bytes {
  Bytes::from_array(a.to_array() + b.to_array())
}

///|
fn _bytes_cat3(a : Bytes, b : Bytes, c : Bytes) -> Bytes {
  _bytes_concat(a, _bytes_concat(b, c))
}

///|
/// SM2 key exchange. Returns (k, s1, s2).
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
  let curve = sm2_curve()
  let n = curve.n
  let one : BigInt = 1

  let w128 : BigInt = one << 128
  let w128_mask : BigInt = w128 - one

  let x2_low = rpri.pubkey.x & w128_mask
  let x2_hat : BigInt = w128 + x2_low

  let x2rb = x2_hat * rpri.d % n
  let tb = _mod_abs(pri.d + x2rb, n)

  if !is_on_curve(rpub_other.x, rpub_other.y, curve) {
    return None
  }

  let x1_hat : BigInt = w128 + (rpub_other.x & w128_mask)
  let (ramx1, ramy1) = scalar_mult(rpub_other.x, rpub_other.y, x1_hat, curve)
  let (vxt, vyt) = point_add(pub_other.x, pub_other.y, ramx1, ramy1, curve)
  let (vx, vy) = scalar_mult(vxt, vyt, tb, curve)

  if vx == 0 && vy == 0 {
    return None
  }

  let pza : PubKey = if this_is_a { pri.pubkey } else { pub_other }
  let pzb : PubKey = if this_is_a { pub_other } else { pri.pubkey }

  let za_val = za(pza, ida)
  let zb_val = za(pzb, idb)

  let kdf_result = _kdf2(klen, vx, vy, za_val, zb_val)
  match kdf_result {
    Some(k) => {
      let vx_octets = vx.to_octets()
      let rpub_x = rpub_other.x.to_octets()
      let rpub_y = rpub_other.y.to_octets()
      let rpri_x = rpri.pubkey.x.to_octets()
      let rpri_y = rpri.pubkey.y.to_octets()

      let h1 : Bytes = if this_is_a {
        _cat_arr([vx_octets, za_val, zb_val, rpub_x, rpub_y, rpri_x, rpri_y])
      } else {
        _cat_arr([vx_octets, za_val, zb_val, rpri_x, rpri_y, rpub_x, rpub_y])
      }
      let h = @paigack/gmsm/sm3.sm3_sum(h1)
      let vy_octets = vy.to_octets()
      let h2_input = _cat_arr([Bytes::from_array([b'\x02']), vy_octets, h])
      let s1 = @paigack/gmsm/sm3.sm3_sum(h2_input)
      let h3_input = _cat_arr([Bytes::from_array([b'\x03']), vy_octets, h])
      let s2 = @paigack/gmsm/sm3.sm3_sum(h3_input)
      Some((k, s1, s2))
    }
    None => None
  }
}

///|
fn _cat_arr(arr : Array[Bytes]) -> Bytes {
  let out : Array[Byte] = Array::make(0, b'\x00')
  for item in arr {
    for bi in item {
      out.push(bi)
    }
  }
  Bytes::from_array(out)
}

///|
/// Generate a new SM2 key pair.
pub fn sm2_generate_key() -> PriKey {
  let curve = sm2_curve()
  let two : BigInt = 2
  let nm1 : BigInt = curve.n - two
  let d : BigInt = if nm1 > 1 { rand_field_element(nm1 + 1) } else { 1 }
  let (px, py) = scalar_base_mult(d, curve)
  { pubkey: { x: px, y: py }, d }
}

///|
/// Check if a public key is valid.
pub fn sm2_check_pubkey(pubkey : PubKey) -> Bool {
  if pubkey.x == 0 && pubkey.y == 0 {
    return false
  }
  is_on_curve(pubkey.x, pubkey.y, sm2_curve())
}

// =============== Internal KDF helpers ===============

///|
fn _kdf(length : Int, x : Bytes, y : Bytes) -> Bytes? {
  let mut ct : Int = 1
  let result_arr : Array[Byte] = Array::make(0, b'\x00')
  let steps = (length + 31) / 32
  for i in 0..<steps {
    let h = @paigack/gmsm/sm3.SM3::new()
    h.write(x)
    h.write(y)
    h.write(
      Bytes::from_array([
        ((ct >> 24) & 0xFF).to_byte(),
        ((ct >> 16) & 0xFF).to_byte(),
        ((ct >> 8) & 0xFF).to_byte(),
        (ct & 0xFF).to_byte(),
      ]),
    )
    let hash = h.sum()
    if i + 1 == steps && length % 32 != 0 {
      for j in 0..<(length % 32) {
        result_arr.push(hash[j])
      }
    } else {
      for bi in hash {
        result_arr.push(bi)
      }
    }
    ct = ct + 1
  }
  let result = Bytes::from_array(result_arr)
  let mut all_zero : Bool = true
  for i in 0..<result.length() {
    if result[i] != b'\x00' {
      all_zero = false
    }
  }
  if all_zero {
    None
  } else {
    Some(result)
  }
}

///|
fn _kdf2(
  klen : Int,
  vx : BigInt,
  vy : BigInt,
  za_val : Bytes,
  zb_val : Bytes,
) -> Bytes? {
  let vx_buf = _bigint_to_32bytes(vx)
  let vy_buf = _bigint_to_32bytes(vy)
  let mut ct : Int = 1
  let result_arr : Array[Byte] = Array::make(0, b'\x00')
  let steps = (klen + 31) / 32
  for i in 0..<steps {
    let h = @paigack/gmsm/sm3.SM3::new()
    h.write(vx_buf)
    h.write(vy_buf)
    h.write(za_val)
    h.write(zb_val)
    h.write(
      Bytes::from_array([
        ((ct >> 24) & 0xFF).to_byte(),
        ((ct >> 16) & 0xFF).to_byte(),
        ((ct >> 8) & 0xFF).to_byte(),
        (ct & 0xFF).to_byte(),
      ]),
    )
    let hash = h.sum()
    if i + 1 == steps && klen % 32 != 0 {
      for j in 0..<(klen % 32) {
        result_arr.push(hash[j])
      }
    } else {
      for bi in hash {
        result_arr.push(bi)
      }
    }
    ct = ct + 1
  }
  let result = Bytes::from_array(result_arr)
  let mut all_zero : Bool = true
  for i in 0..<result.length() {
    if result[i] != b'\x00' {
      all_zero = false
    }
  }
  if all_zero {
    None
  } else {
    Some(result)
  }
}
