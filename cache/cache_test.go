package cache_test

import (
	"sync"
	"testing"

	"github.com/LWDJD/ipfar-sdk/cache"
)

func TestPutGet(t *testing.T) {
	c := cache.NewMemoryCache(1024)
	defer c.Close()

	err := c.Put("key1", []byte("hello"))
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	data, ok, err := c.Get("key1")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if !ok {
		t.Fatal("Get returned ok=false for existing key")
	}
	if string(data) != "hello" {
		t.Fatalf("Get returned %q, want %q", string(data), "hello")
	}
}

func TestGetMiss(t *testing.T) {
	c := cache.NewMemoryCache(1024)
	defer c.Close()

	_, ok, err := c.Get("nonexistent")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if ok {
		t.Fatal("Get returned ok=true for nonexistent key")
	}
}

func TestHas(t *testing.T) {
	c := cache.NewMemoryCache(1024)
	defer c.Close()

	// Key should not exist yet.
	ok, err := c.Has("key1")
	if err != nil {
		t.Fatalf("Has failed: %v", err)
	}
	if ok {
		t.Fatal("Has returned true for nonexistent key")
	}

	// Put and check again.
	err = c.Put("key1", []byte("data"))
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	ok, err = c.Has("key1")
	if err != nil {
		t.Fatalf("Has failed: %v", err)
	}
	if !ok {
		t.Fatal("Has returned false for existing key")
	}
}

func TestDelete(t *testing.T) {
	c := cache.NewMemoryCache(1024)
	defer c.Close()

	err := c.Put("key1", []byte("data"))
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	err = c.Delete("key1")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	ok, err := c.Has("key1")
	if err != nil {
		t.Fatalf("Has failed: %v", err)
	}
	if ok {
		t.Fatal("Has returned true after Delete")
	}
}

func TestDelete_NoOp(t *testing.T) {
	c := cache.NewMemoryCache(1024)
	defer c.Close()

	// Deleting a non-existent key should not error.
	err := c.Delete("nonexistent")
	if err != nil {
		t.Fatalf("Delete of nonexistent key failed: %v", err)
	}
}

func TestClear(t *testing.T) {
	c := cache.NewMemoryCache(1024)
	defer c.Close()

	c.Put("key1", []byte("data1"))
	c.Put("key2", []byte("data2"))

	err := c.Clear()
	if err != nil {
		t.Fatalf("Clear failed: %v", err)
	}

	_, ok, _ := c.Get("key1")
	if ok {
		t.Fatal("Get returned ok=true after Clear")
	}

	_, ok, _ = c.Get("key2")
	if ok {
		t.Fatal("Get returned ok=true after Clear")
	}

	stats := c.Stats()
	if stats.Entries != 0 {
		t.Errorf("Entries after Clear = %d, want 0", stats.Entries)
	}
	if stats.Size != 0 {
		t.Errorf("Size after Clear = %d, want 0", stats.Size)
	}
}

func TestLRUEviction(t *testing.T) {
	// MaxSize = 20 bytes. Each entry: key1=5 bytes, key2=5 bytes, key3=5 bytes.
	// Total would be 15, so all fit. But key4=10 bytes pushes us over.
	// With LRU, key1 should be evicted (least recently used).
	c := cache.NewMemoryCache(20)
	defer c.Close()

	c.Put("key1", []byte("12345")) // 5 bytes
	c.Put("key2", []byte("67890")) // 5 bytes
	c.Put("key3", []byte("abcde")) // 5 bytes — now 15 bytes

	// Access key1 to make it recently used.
	c.Get("key1")
	// Access key2 as well.
	c.Get("key2")
	// Now LRU order: key3 is least recently used.

	// Put key4 (10 bytes) → total would be 25, need to evict 5+ bytes.
	// key3 should be evicted (LRU).
	c.Put("key4", []byte("1234567890")) // 10 bytes

	// key1 and key2 should still exist, key3 evicted.
	_, ok, _ := c.Get("key1")
	if !ok {
		t.Error("key1 should still exist after eviction")
	}
	_, ok, _ = c.Get("key2")
	if !ok {
		t.Error("key2 should still exist after eviction")
	}
	_, ok, _ = c.Get("key3")
	if ok {
		t.Error("key3 should have been evicted (LRU)")
	}
	_, ok, _ = c.Get("key4")
	if !ok {
		t.Error("key4 should exist")
	}

	stats := c.Stats()
	if stats.Evictions < 1 {
		t.Errorf("expected at least 1 eviction, got %d", stats.Evictions)
	}
}

func TestLRUEviction_AccessUpdatesOrder(t *testing.T) {
	c := cache.NewMemoryCache(20)
	defer c.Close()

	c.Put("a", []byte("12345")) // 5
	c.Put("b", []byte("67890")) // 5
	c.Put("c", []byte("abcde")) // 5 — 15 bytes

	// Access "a" so it's not LRU.
	c.Get("a")
	c.Get("a")

	// Now LRU is "b".
	c.Put("d", []byte("1234567890")) // 10 bytes, total would be 25

	// "b" should be evicted.
	_, ok, _ := c.Get("a")
	if !ok {
		t.Error("a should exist")
	}
	_, ok, _ = c.Get("b")
	if ok {
		t.Error("b should be evicted")
	}
	_, ok, _ = c.Get("c")
	if !ok {
		t.Error("c should exist")
	}
	_, ok, _ = c.Get("d")
	if !ok {
		t.Error("d should exist")
	}
}

func TestLRU_UpdateExistingKey(t *testing.T) {
	c := cache.NewMemoryCache(100)
	defer c.Close()

	c.Put("key1", []byte("hello"))
	c.Put("key1", []byte("world")) // update

	data, ok, _ := c.Get("key1")
	if !ok {
		t.Fatal("key1 should exist")
	}
	if string(data) != "world" {
		t.Fatalf("got %q, want %q", string(data), "world")
	}

	stats := c.Stats()
	if stats.Entries != 1 {
		t.Errorf("expected 1 entry, got %d", stats.Entries)
	}
}

func TestConcurrency(t *testing.T) {
	c := cache.NewMemoryCache(1024 * 1024) // 1 MiB
	defer c.Close()

	var wg sync.WaitGroup
	n := 100

	// Concurrent Put.
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			key := "key" + string(rune('0'+idx%10))
			c.Put(key, []byte{byte(idx)})
		}(i)
	}

	// Concurrent Get.
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			key := "key" + string(rune('0'+idx%10))
			c.Get(key)
		}(i)
	}

	// Concurrent Has.
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			key := "key" + string(rune('0'+idx%10))
			c.Has(key)
		}(i)
	}

	// Concurrent Delete.
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			key := "key" + string(rune('0'+idx%10))
			c.Delete(key)
		}(i)
	}

	// Concurrent Stats.
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = c.Stats()
		}()
	}

	wg.Wait()
	// No panic = pass.
}

func TestStats(t *testing.T) {
	c := cache.NewMemoryCache(1024)
	defer c.Close()

	// Initial stats.
	stats := c.Stats()
	if stats.Entries != 0 || stats.Hits != 0 || stats.Misses != 0 || stats.Evictions != 0 {
		t.Errorf("initial stats not zero: %+v", stats)
	}

	// Miss.
	c.Get("nokey")
	stats = c.Stats()
	if stats.Misses != 1 {
		t.Errorf("Misses = %d, want 1", stats.Misses)
	}

	// Put and hit.
	c.Put("key1", []byte("data"))
	c.Get("key1")
	c.Get("key1") // second hit

	stats = c.Stats()
	if stats.Hits != 2 {
		t.Errorf("Hits = %d, want 2", stats.Hits)
	}
	if stats.Entries != 1 {
		t.Errorf("Entries = %d, want 1", stats.Entries)
	}
	if stats.Size != 4 {
		t.Errorf("Size = %d, want 4", stats.Size)
	}
}

func TestMaxSizeDefaults(t *testing.T) {
	// maxSize <= 0 should default to 256 MiB.
	c := cache.NewMemoryCache(0)
	defer c.Close()

	stats := c.Stats()
	if stats.MaxSize != 256*1024*1024 {
		t.Errorf("default MaxSize = %d, want %d", stats.MaxSize, 256*1024*1024)
	}
}

func TestClose(t *testing.T) {
	c := cache.NewMemoryCache(1024)

	c.Put("key", []byte("data"))

	err := c.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Operations after close should fail.
	_, _, err = c.Get("key")
	if err == nil {
		t.Error("Get after Close should return error")
	}

	err = c.Put("key2", []byte("data"))
	if err == nil {
		t.Error("Put after Close should return error")
	}

	_, err = c.Has("key")
	if err == nil {
		t.Error("Has after Close should return error")
	}

	err = c.Delete("key")
	if err == nil {
		t.Error("Delete after Close should return error")
	}

	err = c.Clear()
	if err == nil {
		t.Error("Clear after Close should return error")
	}

	// Double close should be safe.
	err = c.Close()
	if err != nil {
		t.Errorf("second Close should be no-op, got: %v", err)
	}
}

func TestCacheStats_Fields(t *testing.T) {
	stats := cache.CacheStats{
		Entries:   10,
		Size:      500,
		MaxSize:   1024,
		Hits:      100,
		Misses:    20,
		Evictions: 5,
	}

	if stats.Entries != 10 {
		t.Errorf("Entries = %d, want 10", stats.Entries)
	}
	if stats.Size != 500 {
		t.Errorf("Size = %d, want 500", stats.Size)
	}
	if stats.MaxSize != 1024 {
		t.Errorf("MaxSize = %d, want 1024", stats.MaxSize)
	}
	if stats.Hits != 100 {
		t.Errorf("Hits = %d, want 100", stats.Hits)
	}
	if stats.Misses != 20 {
		t.Errorf("Misses = %d, want 20", stats.Misses)
	}
	if stats.Evictions != 5 {
		t.Errorf("Evictions = %d, want 5", stats.Evictions)
	}
}

func TestMemoryCache_ImplementsCache(t *testing.T) {
	var c cache.Cache = cache.NewMemoryCache(1024)
	if c == nil {
		t.Error("NewMemoryCache returned nil")
	}
	c.Close()
}
