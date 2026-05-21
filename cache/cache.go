// Package cache provides a generic key-value cache interface and a default
// in-memory LRU implementation for CAR files, metadata, and other SDK data.
package cache

import (
	"container/list"
	"fmt"
	"io"
	"sync"
)

// Cache defines a generic key-value cache for CAR files and metadata.
// Implementations can be memory-backed, disk-backed, or hybrid.
type Cache interface {
	// Get retrieves data for the given key.
	Get(key string) (data []byte, ok bool, err error)

	// Put stores data for the given key.
	Put(key string, data []byte) error

	// Has returns true if the key exists in cache.
	Has(key string) (bool, error)

	// Delete removes the key from cache.
	Delete(key string) error

	// Clear removes all entries.
	Clear() error

	// Close cleans up resources.
	Close() error

	// Stats returns cache statistics.
	Stats() CacheStats
}

// CacheStats holds cache usage information.
type CacheStats struct {
	Entries   int   // Number of entries currently in cache
	Size      int64 // Current total size of cached data in bytes
	MaxSize   int64 // Configured maximum size
	Hits      uint64
	Misses    uint64
	Evictions uint64
}

// MemoryCache is a simple in-memory LRU cache.
// It is safe for concurrent use.
type MemoryCache struct {
	mu       sync.RWMutex
	maxSize  int64
	size     int64
	items    map[string]*list.Element
	lru      *list.List // front = most recently used, back = least recently used
	hits     uint64
	misses   uint64
	evictions uint64

	closed bool
}

// entry holds a single cache entry in the LRU list.
type entry struct {
	key   string
	data  []byte
	size  int64
}

// NewMemoryCache creates an in-memory cache with the given max size (in bytes).
// A maxSize ≤ 0 means no limit (use with caution).
func NewMemoryCache(maxSize int64) *MemoryCache {
	if maxSize <= 0 {
		maxSize = 256 * 1024 * 1024 // 256 MiB default
	}
	return &MemoryCache{
		maxSize: maxSize,
		items:   make(map[string]*list.Element),
		lru:     list.New(),
	}
}

// Get retrieves data for the given key. It returns the data, a boolean
// indicating whether the key was found, and any error encountered.
func (mc *MemoryCache) Get(key string) ([]byte, bool, error) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if mc.closed {
		return nil, false, fmt.Errorf("cache is closed")
	}

	el, ok := mc.items[key]
	if !ok {
		mc.misses++
		return nil, false, nil
	}

	mc.hits++
	mc.lru.MoveToFront(el)

	e := el.Value.(*entry)
	data := make([]byte, len(e.data))
	copy(data, e.data)
	return data, true, nil
}

// Put stores data for the given key. If the key already exists, the value
// is replaced and the entry moves to the front of the LRU.
//
// If adding the entry would exceed maxSize, the least recently used entries
// are evicted until there is enough room (or the new entry is larger than
// maxSize, in which case it is still stored).
func (mc *MemoryCache) Put(key string, data []byte) error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if mc.closed {
		return fmt.Errorf("cache is closed")
	}

	// If key already exists, remove it first so we can recalculate size.
	if el, ok := mc.items[key]; ok {
		e := el.Value.(*entry)
		mc.size -= e.size
		mc.lru.Remove(el)
		delete(mc.items, key)
	}

	newSize := int64(len(data))

	// Evict LRU entries until we have room (if maxSize > 0).
	if mc.maxSize > 0 {
		for mc.size+newSize > mc.maxSize && mc.lru.Len() > 0 {
			back := mc.lru.Back()
			if back == nil {
				break
			}
			e := back.Value.(*entry)
			mc.size -= e.size
			mc.lru.Remove(back)
			delete(mc.items, e.key)
			mc.evictions++
		}
	}

	e := &entry{key: key, data: data, size: newSize}
	el := mc.lru.PushFront(e)
	mc.items[key] = el
	mc.size += newSize

	return nil
}

// Has returns true if the key exists in cache.
func (mc *MemoryCache) Has(key string) (bool, error) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	if mc.closed {
		return false, fmt.Errorf("cache is closed")
	}

	_, ok := mc.items[key]
	return ok, nil
}

// Delete removes the key from cache. It is a no-op if the key does not exist.
func (mc *MemoryCache) Delete(key string) error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if mc.closed {
		return fmt.Errorf("cache is closed")
	}

	if el, ok := mc.items[key]; ok {
		e := el.Value.(*entry)
		mc.size -= e.size
		mc.lru.Remove(el)
		delete(mc.items, key)
	}
	return nil
}

// Clear removes all entries.
func (mc *MemoryCache) Clear() error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if mc.closed {
		return fmt.Errorf("cache is closed")
	}

	mc.items = make(map[string]*list.Element)
	mc.lru.Init()
	mc.size = 0
	return nil
}

// Close cleans up resources and prevents further operations.
func (mc *MemoryCache) Close() error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if mc.closed {
		return nil
	}

	_ = mc.Clear()
	mc.closed = true
	return nil
}

// Stats returns cache statistics.
func (mc *MemoryCache) Stats() CacheStats {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	return CacheStats{
		Entries:   len(mc.items),
		Size:      mc.size,
		MaxSize:   mc.maxSize,
		Hits:      mc.hits,
		Misses:    mc.misses,
		Evictions: mc.evictions,
	}
}

// Compile-time interface check.
var _ Cache = (*MemoryCache)(nil)

// Ensure io.Closer is satisfied too.
var _ io.Closer = (*MemoryCache)(nil)
