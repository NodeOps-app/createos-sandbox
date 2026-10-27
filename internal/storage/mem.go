package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
)

// MemStorage is an in-memory Storage for tests. Concurrent-safe.
type MemStorage struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func NewMemStorage() *MemStorage {
	return &MemStorage{objects: make(map[string][]byte)}
}

func (m *MemStorage) Put(ctx context.Context, key string, body io.Reader, size int64, sha256Hex string) error {
	data, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	m.objects[key] = cp
	return nil
}

func (m *MemStorage) Get(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.objects[key]
	if !ok {
		return nil, 0, ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(data)), int64(len(data)), nil
}

func (m *MemStorage) GetRange(ctx context.Context, key string, offset int64) (io.ReadCloser, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.objects[key]
	if !ok {
		return nil, 0, ErrNotFound
	}
	if offset < 0 || offset > int64(len(data)) {
		return nil, 0, errors.New("invalid range offset")
	}
	return io.NopCloser(bytes.NewReader(data[offset:])), int64(len(data)), nil
}

func (m *MemStorage) Copy(ctx context.Context, srcKey, dstKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	src, ok := m.objects[srcKey]
	if !ok {
		return ErrNotFound
	}
	cp := make([]byte, len(src))
	copy(cp, src)
	m.objects[dstKey] = cp
	return nil
}

func (m *MemStorage) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objects, key)
	return nil
}

func (m *MemStorage) Exists(ctx context.Context, key string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.objects[key]
	return ok, nil
}

// Keys returns a snapshot of the keys currently stored. For tests.
func (m *MemStorage) Keys() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.objects))
	for k := range m.objects {
		out = append(out, k)
	}
	return out
}
