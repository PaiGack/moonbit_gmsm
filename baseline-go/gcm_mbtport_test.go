package gmsm_oracle_test

import (
	"encoding/hex"
	"testing"

	"github.com/tjfoc/gmsm/sm4"
)

// Port of the CURRENT MoonBit GCM (right-shift GF mult, full 128-bit inc,
// BYTE-length GHASH length block) to Go, to compare against real tjfoc.
func mbtMult(x, y []byte) []byte {
	R := make([]byte, 16)
	R[0] = 0xe1
	Z := make([]byte, 16)
	V := make([]byte, 16)
	copy(V, x)
	for i := 0; i < 128; i++ {
		yi := (y[i/8] >> uint(7-i%8)) & 1
		if yi == 1 {
			for k := 0; k < 16; k++ {
				Z[k] ^= V[k]
			}
		}
		lsb := V[15] & 1
		for k := 15; k >= 0; k-- {
			shifted := V[k] >> 1
			if k > 0 {
				carry := (V[k-1] & 1) << 7
				V[k] = shifted ^ carry
			} else {
				V[k] = shifted
			}
		}
		if lsb == 1 {
			for k := 0; k < 16; k++ {
				V[k] ^= R[k]
			}
		}
	}
	return Z
}

func mbtGhash(h, a, c []byte) []byte {
	X := make([]byte, 16)
	aBlocks := (len(a) + 15) / 16
	for i := 0; i < aBlocks; i++ {
		for k := 0; k < 16; k++ {
			idx := i*16 + k
			var bk byte
			if idx < len(a) {
				bk = a[idx]
			}
			X[k] ^= bk
		}
		X = mbtMult(X, h)
	}
	cBlocks := (len(c) + 15) / 16
	for i := 0; i < cBlocks; i++ {
		for k := 0; k < 16; k++ {
			idx := i*16 + k
			var bk byte
			if idx < len(c) {
				bk = c[idx]
			}
			X[k] ^= bk
		}
		X = mbtMult(X, h)
	}
	aLen := uint64(len(a))
	cLen := uint64(len(c))
	for k := 0; k < 8; k++ {
		X[k] ^= byte((aLen >> uint(56-k*8)) & 0xFF)
	}
	for k := 0; k < 8; k++ {
		X[8+k] ^= byte((cLen >> uint(56-k*8)) & 0xFF)
	}
	X = mbtMult(X, h)
	return X
}

func mbtInc(y []byte) []byte {
	out := make([]byte, 16)
	copy(out, y)
	rc := byte(0)
	for i := 15; i >= 0; i-- {
		if i == 15 {
			if out[i] < 0xff {
				out[i] = out[i] + 1
				rc = 0
			} else {
				out[i] = 0
				rc = 1
			}
		} else {
			if out[i]+rc < 0xff {
				out[i] = out[i] + rc
				rc = 0
			} else {
				out[i] = 0
				rc = 1
			}
		}
	}
	return out
}

func mbtGCMEncrypt(key, iv, pt, aad []byte) ([]byte, []byte) {
	c, _ := sm4.NewCipher(key)
	zero := make([]byte, 16)
	h := make([]byte, 16)
	c.Encrypt(h, zero)
	var y0 []byte
	if len(iv)*8 == 96 {
		y0 = append(append([]byte{}, iv...), 0, 0, 0, 1)
	} else {
		y0 = mbtGhash(h, nil, iv)
	}
	l := len(pt)
	n := 1
	if l != 0 {
		n = (l + 15) / 16
	}
	yblocks := make([][]byte, n+1)
	yblocks[0] = y0
	for i := 1; i <= n; i++ {
		yblocks[i] = mbtInc(yblocks[i-1])
	}
	cipher := make([]byte, l)
	for i := 1; i <= n-1; i++ {
		ek := make([]byte, 16)
		c.Encrypt(ek, yblocks[i])
		base := (i - 1) * 16
		for j := 0; j < 16; j++ {
			cipher[base+j] = ek[j] ^ pt[base+j]
		}
	}
	ek := make([]byte, 16)
	c.Encrypt(ek, yblocks[n])
	nb := 0
	if l != 0 {
		nb = l - (n-1)*16
	}
	base := (n - 1) * 16
	for j := 0; j < nb; j++ {
		cipher[base+j] = ek[j] ^ pt[base+j]
	}
	ey0 := make([]byte, 16)
	c.Encrypt(ey0, y0)
	s := mbtGhash(h, aad, cipher)
	tag := make([]byte, 16)
	for i := 0; i < 16; i++ {
		tag[i] = ey0[i] ^ s[i]
	}
	return cipher, tag
}

func TestGcmMbtPort(t *testing.T) {
	key, _ := hex.DecodeString("31323334353637383930616263646566")
	iv, _ := hex.DecodeString("00000000000000000000000000000000")
	cases := [][]string{
		{"0123456789abcdeffedcba9876543210", ""},
		{"0123456789abcdeffedcba9876543210", "0123456789ab"},
		{"0123456789abcdeffedcba9876543210", "0123456789abcdeffedcba9876543210"},
		{"070a0d101316191c1f2225282b2e3134373a3d40", ""},
		{"070a0d101316191c1f2225282b2e3134373a3d40", "0123456789ab"},
		{"070a0d101316191c1f2225282b2e3134373a3d40", "0123456789abcdeffedcba9876543210"},
		{"010c17222d38434e59646f7a85909ba6b1bcc7d2dde8f3fe09141f2a35404b56", ""},
		{"010c17222d38434e59646f7a85909ba6b1bcc7d2dde8f3fe09141f2a35404b56", "0123456789ab"},
		{"010c17222d38434e59646f7a85909ba6b1bcc7d2dde8f3fe09141f2a35404b56", "0123456789abcdeffedcba9876543210"},
	}
	for i, c := range cases {
		pt, _ := hex.DecodeString(c[0])
		aad, _ := hex.DecodeString(c[1])
		MC, MT := mbtGCMEncrypt(key, iv, pt, aad)
		RC, RT, _ := sm4.Sm4GCM(key, iv, pt, aad, true)
		okC := hex.EncodeToString(MC) == hex.EncodeToString(RC)
		okT := hex.EncodeToString(MT) == hex.EncodeToString(RT)
		t.Logf("CASE %d C=%v T=%v  MC=%s RT=%s", i, okC, okT, hex.EncodeToString(MC), hex.EncodeToString(RT))
		if !okC || !okT {
			t.Errorf("CASE %d mismatch: MC=%s MT=%s RC=%s RT=%s", i, hex.EncodeToString(MC), hex.EncodeToString(MT), hex.EncodeToString(RC), hex.EncodeToString(RT))
		}
	}
}
