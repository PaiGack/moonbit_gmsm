package gmsm_oracle_test

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tjfoc/gmsm/sm4"
)

// ---- Vector records (all binary fields stored as hex strings) ----

type Sm3Vector struct {
	Name   string `json:"name"`
	Msg    string `json:"msg"`    // hex
	Digest string `json:"digest"` // hex
}
type Sm4BlockVector struct {
	Name   string `json:"name"`
	Key    string `json:"key"`
	Block  string `json:"block"`
	Cipher string `json:"cipher"`
}
type Sm4EcbVector struct {
	Name   string `json:"name"`
	Key    string `json:"key"`
	Plain  string `json:"plain"`
	Cipher string `json:"cipher"`
}
type Sm4CbcVector struct {
	Name   string `json:"name"`
	Key    string `json:"key"`
	IV     string `json:"iv"`
	Plain  string `json:"plain"`
	Cipher string `json:"cipher"`
}
type Sm2EncVector struct {
	Name   string `json:"name"`
	PubX   string `json:"pub_x"`
	PubY   string `json:"pub_y"`
	PrivD  string `json:"priv_d"`
	Msg    string `json:"msg"`
	Cipher string `json:"cipher"` // ASN.1 (C1C3C2) ciphertext
}
type Sm2SigVector struct {
	Name string `json:"name"`
	PubX string `json:"pub_x"`
	PubY string `json:"pub_y"`
	UID  string `json:"uid"`
	Msg  string `json:"msg"`
	R    string `json:"r"`
	S    string `json:"s"`
	Der  string `json:"der"` // ASN.1 DER signature
}
type Sm3MultiVector struct {
	Name   string   `json:"name"`
	Chunks []string `json:"chunks"` // hex, hashed in order
	Digest string   `json:"digest"` // hex
}
type Sm4ModeVector struct {
	Name   string `json:"name"`
	Mode   string `json:"mode"` // ecb | cbc | cfb | ofb
	Key    string `json:"key"`
	IV     string `json:"iv"` // package-level IV set through SetIV
	Plain  string `json:"plain"`
	Cipher string `json:"cipher"` // PKCS7-padded ciphertext
}
type Sm2CompressVector struct {
	Name       string `json:"name"`
	PrivD      string `json:"priv_d"`
	PubX       string `json:"pub_x"`
	PubY       string `json:"pub_y"`
	Compressed string `json:"compressed"` // tjfoc form: 0x00/0x01 prefix
}
type Sm2RawVector struct {
	Name   string `json:"name"`
	PrivD  string `json:"priv_d"`
	PubX   string `json:"pub_x"`
	PubY   string `json:"pub_y"`
	Msg    string `json:"msg"`
	C1C3C2 string `json:"c1c3c2"` // raw ciphertext, 0x04 prefixed
	C1C2C3 string `json:"c1c2c3"` // raw ciphertext, 0x04 prefixed
	Asn1   string `json:"asn1"`   // CipherMarshal(C1C3C2)
}
type Sm2KexVector struct {
	Name   string `json:"name"`
	Klen   int    `json:"klen"`
	IDA    string `json:"ida"`
	IDB    string `json:"idb"`
	PrivA  string `json:"priv_a"`
	PubAX  string `json:"pub_a_x"`
	PubAY  string `json:"pub_a_y"`
	PrivB  string `json:"priv_b"`
	PubBX  string `json:"pub_b_x"`
	PubBY  string `json:"pub_b_y"`
	RPrivA string `json:"rpriv_a"`
	RPubAX string `json:"rpub_a_x"`
	RPubAY string `json:"rpub_a_y"`
	RPrivB string `json:"rpriv_b"`
	RPubBX string `json:"rpub_b_x"`
	RPubBY string `json:"rpub_b_y"`
	K      string `json:"k"`
	S1     string `json:"s1"`
	S2     string `json:"s2"`
}
type Vectors struct {
	Sm3      []Sm3Vector         `json:"sm3"`
	Sm3Multi []Sm3MultiVector    `json:"sm3_multi"`
	Sm4Blk   []Sm4BlockVector    `json:"sm4_block"`
	Sm4Ecb   []Sm4EcbVector      `json:"sm4_ecb"`
	Sm4Cbc   []Sm4CbcVector      `json:"sm4_cbc"`
	Sm4Mode  []Sm4ModeVector     `json:"sm4_mode"`
	Sm2Enc   []Sm2EncVector      `json:"sm2_encrypt"`
	Sm2Sig   []Sm2SigVector      `json:"sm2_sign"`
	Sm2Cmp   []Sm2CompressVector `json:"sm2_compress"`
	Sm2Raw   []Sm2RawVector      `json:"sm2_raw_cipher"`
	Sm2Kex   []Sm2KexVector      `json:"sm2_key_exchange"`
}

// V accumulates the oracle vectors; populated by the gen* functions and written
// to disk by TestMain after all tests have run.
var V Vectors

// root returns the workspace root (parent of this go/ directory).
func root() string {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return filepath.Dir(wd)
}

func hexb(b []byte) string { return hex.EncodeToString(b) }

// pad32 left-pads a hex string to 32 bytes. gmsm serializes scalars with
// big.Int.Bytes() (no leading zeros) while MoonBit uses fixed 32-byte
// big-endian scalars.
func pad32(h string) string {
	for len(h) < 64 {
		h = "0" + h
	}
	return h
}

// ---- raw (unpadded) SM4 helpers, so MoonBit's non-padding ECB/CBC match ----

func rawSm4Ecb(key, plain []byte) []byte {
	c, err := sm4.NewCipher(key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(plain))
	for i := 0; i < len(plain); i += 16 {
		c.Encrypt(out[i:i+16], plain[i:i+16])
	}
	return out
}

func rawSm4Cbc(key, iv, plain []byte) []byte {
	c, err := sm4.NewCipher(key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(plain))
	prev := make([]byte, 16)
	copy(prev, iv)
	for i := 0; i < len(plain); i += 16 {
		blk := make([]byte, 16)
		for j := 0; j < 16; j++ {
			blk[j] = plain[i+j] ^ prev[j]
		}
		c.Encrypt(blk, blk)
		copy(out[i:], blk)
		copy(prev, blk)
	}
	return out
}

// ---- TestMain: generate vectors, run tests, then emit docs + MoonBit tests ----

func TestMain(m *testing.M) {
	// gmsm's randFieldElement ignores the reader passed to GenerateKey/Sm2Sign/
	// EncryptAsn1 and always reads from the global crypto/rand.Reader. Override it
	// with a deterministic reader so the oracle produces STABLE vectors and does
	// not block on the (unavailable) OS randomness source.
	rand.Reader = newDetReader()

	genSm3()
	genSm4()
	genSm2()
	// The generators below are appended last on purpose: only genSm2Extra
	// consumes randomness, so the vectors produced above stay stable.
	genSm3Multi()
	genSm4Modes()
	genSm2Extra()
	code := m.Run()
	if code == 0 {
		if err := writeDocs(); err != nil {
			fmt.Fprintln(os.Stderr, "writeDocs:", err)
			code = 1
		}
		if err := writeMoonbit(); err != nil {
			fmt.Fprintln(os.Stderr, "writeMoonbit:", err)
			code = 1
		}
	}
	os.Exit(code)
}

// ---- Documentation (human readable + machine readable) ----

func writeDocs() error {
	r := root()
	if err := os.MkdirAll(filepath.Join(r, "docs"), 0o755); err != nil {
		return err
	}

	j, err := json.MarshalIndent(V, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(r, "docs", "sm_vectors.json"), j, 0o644); err != nil {
		return err
	}

	var b strings.Builder
	b.WriteString("# SM Algorithm Test Vectors\n\n")
	b.WriteString("Auto-generated by the Go `gmsm` oracle in `go/` (`go test`).\n\n")
	b.WriteString("These vectors are the **reference inputs and outputs** for the MoonBit\n")
	b.WriteString("cross-language tests:\n")
	b.WriteString("- `sm3/go_vectors_test.mbt`\n")
	b.WriteString("- `sm4/go_vectors_test.mbt`\n")
	b.WriteString("- `sm2/go_vectors_test.mbt`\n\n")
	b.WriteString("The MoonBit tests load these values (via generated `_test.mbt` files) and\n")
	b.WriteString("assert that MoonBit's SM2/SM3/SM4 implementations reproduce the Go outputs.\n\n")

	b.WriteString("## SM3 (hash)\n\n")
	b.WriteString("| name | msg (hex) | digest (hex) |\n|---|---|---|\n")
	for _, v := range V.Sm3 {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", v.Name, v.Msg, v.Digest)
	}
	b.WriteString("\n### multi-chunk (streaming) hashing\n\n")
	b.WriteString("| name | chunks (hex) | digest (hex) |\n|---|---|---|\n")
	for _, v := range V.Sm3Multi {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", v.Name, strings.Join(v.Chunks, ", "), v.Digest)
	}
	b.WriteString("\n")

	b.WriteString("## SM4 (block cipher)\n\n")
	b.WriteString("### single block\n\n")
	b.WriteString("| name | key (hex) | block (hex) | cipher (hex) |\n|---|---|---|---|\n")
	for _, v := range V.Sm4Blk {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", v.Name, v.Key, v.Block, v.Cipher)
	}
	b.WriteString("\n### ECB (raw, no padding)\n\n")
	b.WriteString("| name | key (hex) | plain (hex) | cipher (hex) |\n|---|---|---|---|\n")
	for _, v := range V.Sm4Ecb {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", v.Name, v.Key, v.Plain, v.Cipher)
	}
	b.WriteString("\n### CBC (raw, no padding)\n\n")
	b.WriteString("| name | key (hex) | iv (hex) | plain (hex) | cipher (hex) |\n|---|---|---|---|---|\n")
	for _, v := range V.Sm4Cbc {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", v.Name, v.Key, v.IV, v.Plain, v.Cipher)
	}
	b.WriteString("\n### mode wrappers with PKCS7 padding (Sm4Ecb / Sm4Cbc / Sm4CFB / Sm4OFB)\n\n")
	b.WriteString("| name | mode | key (hex) | iv (hex) | plain (hex) | cipher (hex) |\n|---|---|---|---|---|---|\n")
	for _, v := range V.Sm4Mode {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", v.Name, v.Mode, v.Key, v.IV, v.Plain, v.Cipher)
	}
	b.WriteString("\n")

	b.WriteString("## SM2 (public key cryptography)\n\n")
	b.WriteString("### encryption (ASN.1 C1C3C2 ciphertext; MoonBit decrypts it)\n\n")
	b.WriteString("| name | pub_x (hex) | pub_y (hex) | priv_d (hex) | msg (hex) | cipher (hex) |\n|---|---|---|---|---|---|\n")
	for _, v := range V.Sm2Enc {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", v.Name, v.PubX, v.PubY, v.PrivD, v.Msg, v.Cipher)
	}
	b.WriteString("\n### signature (DER; MoonBit verifies it)\n\n")
	b.WriteString("| name | pub_x (hex) | pub_y (hex) | uid (hex) | msg (hex) | r (hex) | s (hex) | der (hex) |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|\n")
	for _, v := range V.Sm2Sig {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s | %s |\n", v.Name, v.PubX, v.PubY, v.UID, v.Msg, v.R, v.S, v.Der)
	}
	b.WriteString("\n### point compression\n\n")
	b.WriteString("`gmsm`'s `Compress` prefixes the x coordinate with the raw parity bit\n")
	b.WriteString("(`0x00`/`0x01`) instead of the standard `0x02`/`0x03`; MoonBit emits the\n")
	b.WriteString("standard form, so the cross-check compares `prefix - 2` and the 32 x bytes.\n\n")
	b.WriteString("| name | pub_x (hex) | pub_y (hex) | compressed (hex, gmsm form) |\n|---|---|---|---|\n")
	for _, v := range V.Sm2Cmp {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", v.Name, v.PubX, v.PubY, v.Compressed)
	}
	b.WriteString("\n### raw ciphertext layouts and ASN.1 conversion\n\n")
	b.WriteString("| name | priv_d (hex) | msg (hex) | C1C3C2 (hex) | C1C2C3 (hex) | asn1 (hex) |\n|---|---|---|---|---|---|\n")
	for _, v := range V.Sm2Raw {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", v.Name, v.PrivD, v.Msg, v.C1C3C2, v.C1C2C3, v.Asn1)
	}
	b.WriteString("\n### key exchange (KeyExchangeA / KeyExchangeB)\n\n")
	b.WriteString("| name | klen | priv_a | priv_b | rpriv_a | rpriv_b | k (hex) | s1 (hex) | s2 (hex) |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|\n")
	for _, v := range V.Sm2Kex {
		fmt.Fprintf(&b, "| %s | %d | %s | %s | %s | %s | %s | %s | %s |\n",
			v.Name, v.Klen, v.PrivA, v.PrivB, v.RPrivA, v.RPrivB, v.K, v.S1, v.S2)
	}
	b.WriteString("\n")

	return os.WriteFile(filepath.Join(r, "docs", "sm_vectors.md"), []byte(b.String()), 0o644)
}

// ---- MoonBit test file generation ----

const mbHelpers = `///|
/// Auto-generated by the Go gmsm oracle (go/). DO NOT EDIT BY HAND.
/// The vectors are loaded from docs/sm_vectors.json (and documented in
/// docs/sm_vectors.md). Each test asserts that MoonBit's SM implementation
/// reproduces the Go reference output.

///|
fn go_hex_nibble(c : UInt16) -> Int {
  if c >= 48 && c <= 57 {
    (c - 48).to_int()
  } else if c >= 65 && c <= 70 {
    (c - 65).to_int() + 10
  } else if c >= 97 && c <= 102 {
    (c - 97).to_int() + 10
  } else {
    abort("go: invalid hex char")
  }
}

///|
fn go_hex_to_bytes(s : String) -> Bytes {
  let n = s.length() / 2
  Bytes::makei(n, fn(i) {
    let hi = go_hex_nibble(s[i * 2])
    let lo = go_hex_nibble(s[i * 2 + 1])
    ((hi << 4) | lo).to_byte()
  })
}

///|
fn go_nibble_to_char(n : Int) -> Char {
  if n < 10 {
    Int::unsafe_to_char(n + '0'.to_int())
  } else {
    Int::unsafe_to_char(n - 10 + 'a'.to_int())
  }
}

///|
fn go_byte_to_hex(b : Byte) -> String {
  let hi = (b.to_int() >> 4) & 0xF
  let lo = b.to_int() & 0xF
  let buf = StringBuilder::new()
  buf.write_char(go_nibble_to_char(hi))
  buf.write_char(go_nibble_to_char(lo))
  buf.to_string()
}

///|
fn go_bytes_to_hex(b : Bytes) -> String {
  let buf = StringBuilder::new()
  for i = 0; i < b.length(); i = i + 1 {
    buf.write_string(go_byte_to_hex(b[i]))
  }
  buf.to_string()
}
`

func writeMoonbit() error {
	r := root()

	// SM3
	{
		var b strings.Builder
		b.WriteString(mbHelpers)
		for _, v := range V.Sm3 {
			fmt.Fprintf(&b, "\n///|\ntest %q {\n  let h = @sm3.sm3_sum(go_hex_to_bytes(%q))\n  assert_eq(go_bytes_to_hex(h), %q)\n}\n",
				"go_sm3_"+v.Name, v.Msg, v.Digest)
		}
		for _, v := range V.Sm3Multi {
			quoted := make([]string, len(v.Chunks))
			for i, c := range v.Chunks {
				quoted[i] = fmt.Sprintf("go_hex_to_bytes(%q)", c)
			}
			list := "[" + strings.Join(quoted, ", ") + "]"
			// sm3_sum_multi must match Go's chunked hash.Hash usage, and the
			// streaming write/sum API must agree with it.
			fmt.Fprintf(&b, "\n///|\ntest %q {\n  let chunks : Array[Bytes] = %s\n  assert_eq(go_bytes_to_hex(@sm3.sm3_sum_multi(chunks)), %q)\n  let mut ctx = @sm3.new()\n  for c in chunks {\n    ctx = ctx.write(c)\n  }\n  assert_eq(go_bytes_to_hex(ctx.sum()), %q)\n  assert_eq(ctx.size(), 32)\n  assert_eq(ctx.block_size(), 64)\n}\n",
				"go_sm3_multi_"+v.Name, list, v.Digest, v.Digest)
		}
		if err := os.WriteFile(filepath.Join(r, "sm3", "go_vectors_test.mbt"), []byte(b.String()), 0o644); err != nil {
			return err
		}
	}

	// SM4
	{
		var b strings.Builder
		b.WriteString(mbHelpers)
		for _, v := range V.Sm4Blk {
			fmt.Fprintf(&b, "\n///|\ntest %q {\n  let key = go_hex_to_bytes(%q)\n  let block = go_hex_to_bytes(%q)\n  let cipher = @sm4.sm4_encrypt_block(key, block)\n  assert_eq(go_bytes_to_hex(cipher), %q)\n}\n",
				"go_sm4_block_"+v.Name, v.Key, v.Block, v.Cipher)
		}
		for _, v := range V.Sm4Ecb {
			fmt.Fprintf(&b, "\n///|\ntest %q {\n  let key = go_hex_to_bytes(%q)\n  let plain = go_hex_to_bytes(%q)\n  let cipher = @sm4.sm4_encrypt_ecb(key, plain)\n  assert_eq(go_bytes_to_hex(cipher), %q)\n}\n",
				"go_sm4_ecb_"+v.Name, v.Key, v.Plain, v.Cipher)
		}
		for _, v := range V.Sm4Cbc {
			fmt.Fprintf(&b, "\n///|\ntest %q {\n  let key = go_hex_to_bytes(%q)\n  let iv = go_hex_to_bytes(%q)\n  let plain = go_hex_to_bytes(%q)\n  let cipher = @sm4.sm4_encrypt_cbc(key, iv, plain)\n  assert_eq(go_bytes_to_hex(cipher), %q)\n}\n",
				"go_sm4_cbc_"+v.Name, v.Key, v.IV, v.Plain, v.Cipher)
		}
		for _, v := range V.Sm4Mode {
			fn := map[string]string{
				"ecb": "@sm4.sm4_ecb", "cbc": "@sm4.sm4_cbc",
				"cfb": "@sm4.sm4_cfb", "ofb": "@sm4.sm4_ofb",
			}[v.Mode]
			// The padded wrappers read the package-level IV, exactly like
			// gmsm's Sm4Cbc / Sm4CFB / Sm4OFB after SetIV.
			fmt.Fprintf(&b, "\n///|\ntest %q {\n  let key = go_hex_to_bytes(%q)\n  @sm4.set_iv(go_hex_to_bytes(%q))\n  let plain = go_hex_to_bytes(%q)\n  let cipher = %s(key, plain, true)\n  assert_eq(go_bytes_to_hex(cipher), %q)\n  let back = %s(key, cipher, false)\n  assert_eq(go_bytes_to_hex(back), %q)\n}\n",
				"go_sm4_"+v.Name, v.Key, v.IV, v.Plain, fn, v.Cipher, fn, v.Plain)
		}
		if err := os.WriteFile(filepath.Join(r, "sm4", "go_vectors_test.mbt"), []byte(b.String()), 0o644); err != nil {
			return err
		}
	}

	// SM2
	{
		var b strings.Builder
		b.WriteString(mbHelpers)
		b.WriteString(`
///|
fn go_load_priv(d : Bytes) -> @sm2.SM2PrivateKey {
  try {
    @sm2.private_key_from_bytes(@sm2.sm2_p256(), d)
  } catch {
    _ => abort("go: bad private key")
  }
}

///|
fn go_load_pub(x : Bytes, y : Bytes) -> @sm2.SM2PublicKey {
  try {
    @sm2.public_key_from_xy(@sm2.sm2_p256(), x, y)
  } catch {
    _ => abort("go: bad public key")
  }
}
`)
		for _, v := range V.Sm2Enc {
			name := "go_sm2_dec_" + v.Name
			fmt.Fprintf(&b, "\n///|\ntest %q {\n  let privkey = go_load_priv(go_hex_to_bytes(%q))\n  let cipher = go_hex_to_bytes(%q)\n  let plain = try {\n    @sm2.sm2_decrypt_asn1(privkey, cipher)\n  } catch {\n    _ => abort(%q)\n  }\n  assert_eq(go_bytes_to_hex(plain), %q)\n}\n",
				name, v.PrivD, v.Cipher, name+": decrypt failed", v.Msg)
		}
		for _, v := range V.Sm2Sig {
			name := "go_sm2_verify_" + v.Name
			fmt.Fprintf(&b, "\n///|\ntest %q {\n  let pubkey = go_load_pub(go_hex_to_bytes(%q), go_hex_to_bytes(%q))\n  let msg = go_hex_to_bytes(%q)\n  let uid = go_hex_to_bytes(%q)\n  let der = go_hex_to_bytes(%q)\n  assert_true(@sm2.sm2_verify_der(pubkey, msg, uid, der))\n}\n",
				name, v.PubX, v.PubY, v.Msg, v.UID, v.Der)
		}
		// ASN.1 signature conversion helpers (SignDigitToSignData /
		// SignDataToSignDigit) against the same reference signatures.
		for _, v := range V.Sm2Sig {
			name := "go_sm2_signdata_" + v.Name
			fmt.Fprintf(&b, "\n///|\ntest %q {\n  let r = go_hex_to_bytes(%q)\n  let s = go_hex_to_bytes(%q)\n  let der = @sm2.sign_digit_to_sign_data(r, s)\n  assert_eq(go_bytes_to_hex(der), %q)\n  let (r2, s2) = @sm2.sign_data_to_sign_digit(go_hex_to_bytes(%q))\n  assert_eq(go_bytes_to_hex(r2), %q)\n  assert_eq(go_bytes_to_hex(s2), %q)\n}\n",
				name, pad32(v.R), pad32(v.S), v.Der, v.Der, pad32(v.R), pad32(v.S))
		}
		for _, v := range V.Sm2Cmp {
			name := "go_sm2_compress_" + v.Name
			// gmsm's Compress uses a raw parity prefix (0x00/0x01); MoonBit
			// emits the standard 0x02/0x03, so the prefixes differ by 2 while
			// the 32 x bytes must match exactly.
			fmt.Fprintf(&b, "\n///|\ntest %q {\n  let privkey = go_load_priv(go_hex_to_bytes(%q))\n  let pubkey = @sm2.derive_public_key(privkey)\n  let comp = @sm2.compress_point(pubkey)\n  let go_comp = go_hex_to_bytes(%q)\n  assert_eq(comp.length(), 33)\n  assert_eq(comp[0].to_int(), go_comp[0].to_int() + 2)\n  for i = 1; i < 33; i = i + 1 {\n    assert_eq(comp[i], go_comp[i])\n  }\n  let back = @sm2.decompress_point(comp)\n  assert_true(@sm2.is_on_curve(back))\n  assert_eq(go_bytes_to_hex(@sm2.compress_point(back)), go_bytes_to_hex(comp))\n  // the recovered y must be the real one: verify a signature with it\n  let msg = b\"decompressed key check\"\n  let uid = @sm2.default_uid()\n  let der = @sm2.sm2_sign_der(privkey, msg, uid, None)\n  assert_true(@sm2.sm2_verify_der(back, msg, uid, der))\n}\n",
				name, v.PrivD, v.Compressed)
		}
		for _, v := range V.Sm2Raw {
			name := "go_sm2_raw_" + v.Name
			fmt.Fprintf(&b, "\n///|\ntest %q {\n  let privkey = go_load_priv(go_hex_to_bytes(%q))\n  let c132 = go_hex_to_bytes(%q)\n  let c123 = go_hex_to_bytes(%q)\n  let asn1c = go_hex_to_bytes(%q)\n  assert_eq(go_bytes_to_hex(@sm2.sm2_decrypt(privkey, c132, @sm2.C1C3C2)), %q)\n  assert_eq(go_bytes_to_hex(@sm2.sm2_decrypt(privkey, c123, @sm2.C1C2C3)), %q)\n  assert_eq(go_bytes_to_hex(@sm2.cipher_marshal(c132)), %q)\n  assert_eq(go_bytes_to_hex(@sm2.cipher_unmarshal(asn1c)), %q)\n  assert_eq(go_bytes_to_hex(@sm2.sm2_decrypt_asn1(privkey, asn1c)), %q)\n}\n",
				name, v.PrivD, v.C1C3C2, v.C1C2C3, v.Asn1, v.Msg, v.Msg, v.Asn1, v.C1C3C2, v.Msg)
		}
		for _, v := range V.Sm2Kex {
			name := "go_sm2_kex_" + v.Name
			fmt.Fprintf(&b, "\n///|\ntest %q {\n  let ida = go_hex_to_bytes(%q)\n  let idb = go_hex_to_bytes(%q)\n  let pri_a = go_load_priv(go_hex_to_bytes(%q))\n  let pri_b = go_load_priv(go_hex_to_bytes(%q))\n  let pub_a = go_load_pub(go_hex_to_bytes(%q), go_hex_to_bytes(%q))\n  let pub_b = go_load_pub(go_hex_to_bytes(%q), go_hex_to_bytes(%q))\n  let rpri_a = go_load_priv(go_hex_to_bytes(%q))\n  let rpri_b = go_load_priv(go_hex_to_bytes(%q))\n  let rpub_a = go_load_pub(go_hex_to_bytes(%q), go_hex_to_bytes(%q))\n  let rpub_b = go_load_pub(go_hex_to_bytes(%q), go_hex_to_bytes(%q))\n  let (ka, s1a, s2a) = @sm2.key_exchange_a(%d, ida, idb, pri_a, pub_b, rpri_a, rpub_b)\n  assert_eq(go_bytes_to_hex(ka), %q)\n  assert_eq(go_bytes_to_hex(s1a), %q)\n  assert_eq(go_bytes_to_hex(s2a), %q)\n  let (kb, s1b, s2b) = @sm2.key_exchange_b(%d, ida, idb, pri_b, pub_a, rpri_b, rpub_a)\n  assert_eq(go_bytes_to_hex(kb), %q)\n  assert_eq(go_bytes_to_hex(s1b), %q)\n  assert_eq(go_bytes_to_hex(s2b), %q)\n}\n",
				name, v.IDA, v.IDB, v.PrivA, v.PrivB, v.PubAX, v.PubAY, v.PubBX, v.PubBY,
				v.RPrivA, v.RPrivB, v.RPubAX, v.RPubAY, v.RPubBX, v.RPubBY,
				v.Klen, v.K, v.S1, v.S2, v.Klen, v.K, v.S1, v.S2)
		}
		if err := os.WriteFile(filepath.Join(r, "sm2", "go_vectors_test.mbt"), []byte(b.String()), 0o644); err != nil {
			return err
		}
	}

	return nil
}
