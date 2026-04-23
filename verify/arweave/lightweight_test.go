package arweave

import (
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// TrafficTracker 跟踪网络流量的 HTTP Transport
type TrafficTracker struct {
	bytesRead int64
	requests  int64
	transport http.RoundTripper
}

// NewTrafficTracker 创建流量跟踪器
func NewTrafficTracker() *TrafficTracker {
	return &TrafficTracker{
		transport: http.DefaultTransport,
	}
}

// RoundTrip 实现 http.RoundTripper 接口
func (t *TrafficTracker) RoundTrip(req *http.Request) (*http.Response, error) {
	atomic.AddInt64(&t.requests, 1)

	resp, err := t.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if resp.Body != nil {
		resp.Body = &trackingReader{
			ReadCloser: resp.Body,
			bytesRead:  &t.bytesRead,
		}
	}

	return resp, nil
}

// GetBytesRead 获取已读取的字节数
func (t *TrafficTracker) GetBytesRead() int64 {
	return atomic.LoadInt64(&t.bytesRead)
}

// GetRequestCount 获取请求次数
func (t *TrafficTracker) GetRequestCount() int64 {
	return atomic.LoadInt64(&t.requests)
}

// trackingReader 包装 io.ReadCloser 以跟踪读取的字节数
type trackingReader struct {
	io.ReadCloser
	bytesRead *int64
}

func (r *trackingReader) Read(p []byte) (n int, err error) {
	n, err = r.ReadCloser.Read(p)
	if n > 0 {
		atomic.AddInt64(r.bytesRead, int64(n))
	}
	return n, err
}

// TestLightweightBlockVerification 测试区块轻量验证
func TestLightweightBlockVerification(t *testing.T) {
	t.Run("VerifyBlock100", func(t *testing.T) {
		tracker := NewTrafficTracker()
		client := &http.Client{
			Transport: tracker,
			Timeout:   30 * time.Second,
		}

		// 临时替换默认客户端
		oldClient := http.DefaultClient
		http.DefaultClient = client
		defer func() { http.DefaultClient = oldClient }()

		result, err := VerifyBlockLight("https://arweave.net", 100)
		if err != nil {
			t.Fatalf("Light block verification failed: %v", err)
		}

		if !result.IsValid {
			t.Errorf("Expected block to be valid, got errors: %v", result.Errors)
		}

		fmt.Printf("✓ 区块轻量验证成功 (height=%d)\n", result.Height)
		fmt.Printf("  HTTP 请求次数: %d\n", tracker.GetRequestCount())
		fmt.Printf("  网络流量: %d bytes (%.2f KB)\n", tracker.GetBytesRead(), float64(tracker.GetBytesRead())/1024)
	})
}

// TestLightweightBundleHeader 测试捆绑包头部解析
func TestLightweightBundleHeader(t *testing.T) {
	t.Run("ParseBundleHeader", func(t *testing.T) {
		txID := "jXN3mTRx5oLuOkfbGxy6DTqw1CS_X25cEJ-ASyrE8is"
		url := fmt.Sprintf("https://arweave.net/raw/%s", txID)

		tracker := NewTrafficTracker()
		client := &http.Client{
			Transport: tracker,
			Timeout:   30 * time.Second,
		}

		// 第一次请求：获取前 32 字节（数据项数量）
		req1, _ := http.NewRequest("GET", url, nil)
		req1.Header.Set("Range", "bytes=0-31")

		resp1, err := client.Do(req1)
		if err != nil {
			t.Fatalf("第一次请求失败（获取数据项数量）: %v", err)
		}

		data1 := make([]byte, 32)
		n1, err := io.ReadFull(resp1.Body, data1)
		resp1.Body.Close()
		if err != nil && n1 < 32 {
			t.Fatalf("读取前 32 字节失败: %v", err)
		}

		itemsNum := byteArrayToLong(data1)
		firstTraffic := tracker.GetBytesRead()
		fmt.Printf("✓ 第一次请求成功\n")
		fmt.Printf("  数据项数量: %d\n", itemsNum)
		fmt.Printf("  预期获取: 32 bytes, 实际流量: %d bytes\n", firstTraffic)

		// 第二次请求：获取完整头部
		headerSize := 32 + itemsNum*64
		req2, _ := http.NewRequest("GET", url, nil)
		req2.Header.Set("Range", fmt.Sprintf("bytes=0-%d", headerSize-1))

		resp2, err := client.Do(req2)
		if err != nil {
			t.Fatalf("第二次请求失败（获取完整头部）: %v", err)
		}

		headerData := make([]byte, headerSize)
		n2, err := io.ReadFull(resp2.Body, headerData)
		resp2.Body.Close()
		if err != nil && n2 < int(headerSize) {
			t.Fatalf("读取头部数据失败: %v", err)
		}

		totalTraffic := tracker.GetBytesRead()
		secondTraffic := totalTraffic - firstTraffic

		fmt.Printf("✓ 第二次请求成功\n")
		fmt.Printf("  预期获取: %d bytes, 实际流量: %d bytes\n", headerSize, secondTraffic)
		fmt.Printf("\n📊 流量统计:\n")
		fmt.Printf("  总请求次数: %d\n", tracker.GetRequestCount())
		fmt.Printf("  总网络流量: %d bytes (%.2f KB)\n", totalTraffic, float64(totalTraffic)/1024)
		fmt.Printf("  头部大小: %d bytes\n", headerSize)
		fmt.Printf("  流量效率: %.2f%%\n", float64(headerSize)/float64(totalTraffic)*100)

		// 验证解析器
		reader := NewBytesReader(headerData)
		parser := NewBundleParser(reader)
		if err := parser.ParseHeader(); err != nil {
			t.Fatalf("解析头部失败: %v", err)
		}

		if parser == nil {
			t.Fatal("解析器不应为 nil")
		}

		fmt.Printf("✓ 捆绑包头部解析成功\n")

		// 验证流量效率（实际流量不应超过预期数据的 2 倍）
		if totalTraffic > int64(headerSize)*2 {
			t.Errorf("流量过高: %d bytes (预期 ~%d bytes)", totalTraffic, headerSize)
		}
	})
}

// TestLightweightTransactionTags 测试交易标签获取
func TestLightweightTransactionTags(t *testing.T) {
	t.Run("FetchTransactionTags", func(t *testing.T) {
		txID := "jXN3mTRx5oLuOkfbGxy6DTqw1CS_X25cEJ-ASyrE8is"

		tracker := NewTrafficTracker()
		client := &http.Client{
			Transport: tracker,
			Timeout:   30 * time.Second,
		}

		oldClient := http.DefaultClient
		http.DefaultClient = client
		defer func() { http.DefaultClient = oldClient }()

		tags, err := FetchTransactionTags("https://arweave.net", txID)
		if err != nil {
			t.Fatalf("获取交易标签失败: %v", err)
		}

		fmt.Printf("✓ 交易标签获取成功\n")
		fmt.Printf("  交易 ID: %s\n", txID)
		fmt.Printf("  标签数量: %d\n", len(tags))
		fmt.Printf("  HTTP 请求次数: %d\n", tracker.GetRequestCount())
		fmt.Printf("  网络流量: %d bytes (%.2f KB)\n", tracker.GetBytesRead(), float64(tracker.GetBytesRead())/1024)

		// 打印标签详情
		if len(tags) > 0 {
			fmt.Printf("\n📋 标签详情:\n")
			for i, tag := range tags {
				fmt.Printf("  [%d] %s = %s\n", i+1, tag.Name, tag.Value)
			}
		}
	})
}

// TestOfflineScenario 测试断网场景（应该失败）
func TestOfflineScenario(t *testing.T) {
	t.Run("ShouldFailWithoutNetwork", func(t *testing.T) {
		// 使用无效网关测试断网情况
		_, err := VerifyBlockLight("https://invalid-gateway-that-does-not-exist.test", 100)
		if err == nil {
			t.Fatal("断网情况下应该返回错误，但成功了")
		}

		fmt.Printf("✓ 断网测试通过（正确返回错误）: %v\n", err)
	})
}
