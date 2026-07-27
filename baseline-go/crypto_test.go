package gmsm_oracle_test

import "io"

// detReader is a deterministic pseudo-random reader. We use it (instead of
// crypto/rand) so that the Go oracle produces STABLE SM2 key / signature /
// ciphertext vectors across runs. gmsm accepts an explicit io.Reader for every
// randomized operation (key generation, signing, encryption).
type detReader struct{ x uint64 }

func newDetReader() *detReader { return &detReader{x: 0x1234567890ABCDEF} }

func (r *detReader) Read(p []byte) (int, error) {
	for i := range p {
		// xorshift64*
		r.x ^= r.x << 13
		r.x ^= r.x >> 7
		r.x ^= r.x << 17
		p[i] = byte(r.x >> ((i & 7) * 8))
	}
	return len(p), nil
}

var _ io.Reader = (*detReader)(nil)
