package gmsm_oracle_test

import (
	"encoding/hex"
	"testing"

	"github.com/tjfoc/gmsm/sm4"
)

// Verbatim copy of tjfoc/gmsm sm4_gcm.go functions to confirm behavior.
func tjAddition(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func tjRightshift(V []byte) {
	n := len(V)
	for i := n - 1; i >= 0; i-- {
		V[i] = V[i] >> 1
		if i != 0 {
			V[i] = ((V[i-1] & 0x01) << 7) | V[i]
		}
	}
}

func tjFindYi(Y []byte, index int) int {
	i := uint(index)
	temp := Y[i/8]
	temp = temp >> (7 - i%8)
	if temp&0x01 == 1 {
		return 1
	}
	return 0
}

func tjMultiplication(X, Y []byte) []byte {
	R := make([]byte, 16)
	R[0] = 0xe1
	Z := make([]byte, 16)
	V := make([]byte, 16)
	copy(V, X)
	for i := 0; i <= 127; i++ {
		if tjFindYi(Y, i) == 1 {
			Z = tjAddition(Z, V)
		}
		if V[15]&0x01 == 0 {
			tjRightshift(V)
		} else {
			tjRightshift(V)
			V = tjAddition(V, R)
		}
	}
	return Z
}

func tjGHASH(H, A, C []byte) []byte {
	calculm_v := func(m, v int) (int, int) {
		if m == 0 && v != 0 {
			m = 1
			v = v * 8
		} else if m != 0 && v == 0 {
			v = 16 * 8
		} else if m != 0 && v != 0 {
			m = m + 1
			v = v * 8
		} else {
			m = 1
			v = 0
		}
		return m, v
	}
	m := len(A) / 16
	v := len(A) % 16
	m, v = calculm_v(m, v)
	n := len(C) / 16
	u := len(C) % 16
	n, u = calculm_v(n, u)
	X := make([]byte, 16*(m+n+2))
	for i := 0; i < 16; i++ {
		X[i] = 0x00
	}
	for i := 1; i <= m-1; i++ {
		copy(X[i*16:i*16+16], tjMultiplication(tjAddition(X[(i-1)*16:(i-1)*16+16], A[(i-1)*16:(i-1)*16+16]), H))
	}
	zeros := make([]byte, (128-v)/8)
	Am := make([]byte, v/8)
	copy(Am[:], A[(m-1)*16:])
	Am = append(Am, zeros...)
	copy(X[m*16:m*16+16], tjMultiplication(tjAddition(X[(m-1)*16:(m-1)*16+16], Am), H))
	for i := m + 1; i <= m+n-1; i++ {
		copy(X[i*16:i*16+16], tjMultiplication(tjAddition(X[(i-1)*16:(i-1)*16+16], C[(i-m-1)*16:(i-m-1)*16+16]), H))
	}
	zeros = make([]byte, (128-u)/8)
	Cn := make([]byte, u/8)
	copy(Cn[:], C[(n-1)*16:])
	Cn = append(Cn, zeros...)
	copy(X[(m+n)*16:(m+n)*16+16], tjMultiplication(tjAddition(X[(m+n-1)*16:(m+n-1)*16+16], Cn), H))
	var lenAB []byte
	calculateLenToBytes := func(l int) []byte {
		data := make([]byte, 8)
		data[0] = byte((l >> 56) & 0xff)
		data[1] = byte((l >> 48) & 0xff)
		data[2] = byte((l >> 40) & 0xff)
		data[3] = byte((l >> 32) & 0xff)
		data[4] = byte((l >> 24) & 0xff)
		data[5] = byte((l >> 16) & 0xff)
		data[6] = byte((l >> 8) & 0xff)
		data[7] = byte((l >> 0) & 0xff)
		return data
	}
	lenAB = append(lenAB, calculateLenToBytes(len(A))...)
	lenAB = append(lenAB, calculateLenToBytes(len(C))...)
	copy(X[(m+n+1)*16:(m+n+1)*16+16], tjMultiplication(tjAddition(X[(m+n)*16:(m+n)*16+16], lenAB), H))
	return X[(m+n+1)*16 : (m+n+1)*16+16]
}

func tjGetY0(H, IV []byte) []byte {
	if len(IV)*8 == 96 {
		zero31one1 := []byte{0x00, 0x00, 0x00, 0x01}
		IV = append(IV, zero31one1...)
		return IV
	}
	return tjGHASH(H, []byte{}, IV)
}

func tjIncr(n int, Y_i []byte) []byte {
	Y_ii := make([]byte, 16*n)
	copy(Y_ii, Y_i)
	addYone := func(yi, yii []byte) {
		copy(yii[:], yi[:])
		Len := len(yi)
		var rc byte = 0x00
		for i := Len - 1; i >= 0; i-- {
			if i == Len-1 {
				if yii[i] < 0xff {
					yii[i] = yii[i] + 0x01
					rc = 0x00
				} else {
					yii[i] = 0x00
					rc = 0x01
				}
			} else {
				if yii[i]+rc < 0xff {
					yii[i] = yii[i] + rc
					rc = 0x00
				} else {
					yii[i] = 0x00
					rc = 0x01
				}
			}
		}
	}
	for i := 1; i < n; i++ {
		addYone(Y_ii[(i-1)*16:(i-1)*16+16], Y_ii[i*16:i*16+16])
	}
	return Y_ii
}

func tjMSB(l int, S []byte) []byte {
	return S[:l/8]
}

func tjGCMEncrypt(K, IV, P, A []byte) ([]byte, []byte) {
	calculm_v := func(m, v int) (int, int) {
		if m == 0 && v != 0 {
			m = 1
			v = v * 8
		} else if m != 0 && v == 0 {
			v = 16 * 8
		} else if m != 0 && v != 0 {
			m = m + 1
			v = v * 8
		} else {
			m = 1
			v = 0
		}
		return m, v
	}
	n := len(P) / 16
	u := len(P) % 16
	n, u = calculm_v(n, u)
	c, _ := sm4.NewCipher(K)
	H := make([]byte, 16)
	c.Encrypt(H, make([]byte, 16))
	Y0 := tjGetY0(H, IV)
	Y := make([]byte, 16*(n+1))
	Y = tjIncr(n+1, Y0)
	Enc := make([]byte, 16)
	C := make([]byte, len(P))
	for i := 1; i <= n-1; i++ {
		c.Encrypt(Enc, Y[i*16:i*16+16])
		copy(C[(i-1)*16:(i-1)*16+16], tjAddition(P[(i-1)*16:(i-1)*16+16], Enc))
	}
	c.Encrypt(Enc, Y[n*16:n*16+16])
	out := tjMSB(u, Enc)
	copy(C[(n-1)*16:], tjAddition(P[(n-1)*16:], out))
	c.Encrypt(Enc, Y0)
	T := tjMSB(128, tjAddition(Enc, tjGHASH(H, A, C)))
	return C, T
}

func TestGcmTjVerb(t *testing.T) {
	key, _ := hex.DecodeString("31323334353637383930616263646566")
	iv, _ := hex.DecodeString("00000000000000000000000000000000")
	pt, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	aad, _ := hex.DecodeString("")
	// compare mult
	c2, _ := sm4.NewCipher(key)
	H := make([]byte, 16)
	c2.Encrypt(H, make([]byte, 16))
	multX := make([]byte, 16)
	multX[15] = 0x10
	mb := mbtMult(multX, H)
	tj := tjMultiplication(multX, H)
	t.Logf("mbtMult(0x10,H)=%s", hex.EncodeToString(mb))
	t.Logf("tjMult (0x10,H)=%s", hex.EncodeToString(tj))
	VC, VT := tjGCMEncrypt(key, iv, pt, aad)
	RC, RT, _ := sm4.Sm4GCM(key, iv, pt, aad, true)
	Y0 := tjGetY0(H, iv)
	mbtC, _ := mbtGCMEncrypt(key, iv, pt, aad)
	// verbatim Y[1]
	Yv := tjIncr(2, Y0)
	ev := make([]byte, 16)
	c2.Encrypt(ev, Yv[16:32])
	// mbt Y[1]
	Ym := mbtInc(Y0)
	em := make([]byte, 16)
	c2.Encrypt(em, Ym)
	t.Logf("TJ Y0   =%s", hex.EncodeToString(Y0))
	t.Logf("VERB Y[1]=%s  E=%s", hex.EncodeToString(Yv[16:32]), hex.EncodeToString(ev))
	t.Logf("MBT  Y[1]=%s  E=%s", hex.EncodeToString(Ym), hex.EncodeToString(em))
	t.Logf("VERBATIM C=%s T=%s", hex.EncodeToString(VC), hex.EncodeToString(VT))
	t.Logf("MBT-PORT C=%s", hex.EncodeToString(mbtC))
	t.Logf("REAL    C=%s T=%s", hex.EncodeToString(RC), hex.EncodeToString(RT))
}
