# Go SM oracle (cross-language test harness)

This directory is a **reference oracle** for the MoonBit 国密 (SM2/SM3/SM4)
implementation in the parent workspace. It uses the well-tested Go library
[`github.com/tjfoc/gmsm`](https://github.com/tjfoc/gmsm) as the source of truth.

## What it does

Running `go test` here:

1. Computes SM3 digests, SM4 (block / ECB / CBC) ciphertexts, and SM2
   (encrypt + sign) vectors from a fixed set of inputs.
2. Writes the **inputs and outputs** to documentation under `../docs/`:
   - `docs/sm_vectors.json` — machine-readable vectors.
   - `docs/sm_vectors.md` — human-readable tables.
3. Generates the MoonBit cross-language test files that *load* those vectors
   and assert MoonBit reproduces the Go outputs:
   - `../sm3/go_vectors_test.mbt`
   - `../sm4/go_vectors_test.mbt`
   - `../sm2/go_vectors_test.mbt`

## Determinism

`github.com/tjfoc/gmsm` ignores the `io.Reader` argument passed to
`GenerateKey` / `Sm2Sign` / `EncryptAsn1` and always reads from the global
`crypto/rand.Reader`. `TestMain` therefore overrides `crypto/rand.Reader` with
a deterministic xorshift reader, so the generated vectors (especially the SM2
key, signature and ciphertext) are **stable across runs**.

> Note: gmsm's `Encrypt` infinite-loops on an empty plaintext (its KDF returns
> `!ok` for length 0), so the SM2 encryption vectors use non-empty messages.
> MoonBit's own `sm2` whitebox tests already cover the empty-plaintext case.

## Workflow

```sh
# 1. (re)generate vectors + MoonBit tests from the Go oracle
cd go && go test

# 2. validate the MoonBit implementation against the generated vectors
cd .. && moon test
```

`go test` must be run before the first `moon test`, and re-run whenever you
want to refresh the reference vectors.
