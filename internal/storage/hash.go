package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
)

// HashingReader wraps an io.Reader, computing a sha256 of every byte
// that flows through. Use it to compute a hash WHILE doing something
// else with the data — typically streaming through a compressor and
// then through an HTTP upload.
//
// Callers should Read until io.EOF (or io.Copy), then call Sum() to
// retrieve the lowercase-hex digest.
type HashingReader struct {
	src io.Reader
	h   hash.Hash
	n   int64
}

func NewHashingReader(r io.Reader) *HashingReader {
	return &HashingReader{src: r, h: sha256.New()}
}

func (hr *HashingReader) Read(p []byte) (int, error) {
	n, err := hr.src.Read(p)
	if n > 0 {
		hr.h.Write(p[:n])
		hr.n += int64(n)
	}
	return n, err
}

// Sum returns the lowercase-hex sha256 of all bytes Read so far.
func (hr *HashingReader) Sum() string {
	return hex.EncodeToString(hr.h.Sum(nil))
}

// BytesRead returns the running byte count.
func (hr *HashingReader) BytesRead() int64 { return hr.n }

// HashFile is a convenience: open + sha256 + close. Used by the
// startup scan that verifies on-disk locality cache files match the
// row's manifest.
func HashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	hr := NewHashingReader(f)
	n, err := io.Copy(io.Discard, hr)
	if err != nil {
		return "", 0, fmt.Errorf("hash %s: %w", path, err)
	}
	return hr.Sum(), n, nil
}
