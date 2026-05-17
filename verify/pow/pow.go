// Package pow 提供 IPFAR 工作量证明（PoW）验证功能
// 基于 Argon2id 内存硬函数，用于防止垃圾数据攻击
// 规范参考: ipfar-specs/V1/项目规划.md §2.1
package pow

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"sync"

	"golang.org/x/crypto/argon2"
)

// PoW 算法常量，与 ipfar-specs/V1/项目规划.md §2.1 保持一致
const (
	// Algorithm 算法标识符
	Algorithm = "argon2id-light-v1"

	// Argon2id 参数（全档位统一）
	argon2Memory  = 20 * 1024 // 20 MB（单位：KB）
	argon2Time    = 1         // 迭代次数
	argon2Threads = 1         // 并行度
	argon2KeyLen  = 32        // 输出密钥长度（字节）

	// MinLeadingZeroBytes PoW 难度：前导零字节数
	// 2 字节 = 16 位前导零，平均需要 ~65,536 次计算
	MinLeadingZeroBytes = 2

	// PoWThreshold 100 MiB 阈值：大于等于此大小的文件免 PoW
	PoWThreshold = 100 * 1024 * 1024

	// maxSaltSafety 安全上限，防止无限循环
	maxSaltSafety = 10_000_000
)

// 错误定义
var (
	ErrMissingPoW            = errors.New("PoW is required for files smaller than 100 MiB")
	ErrInvalidPoWFormat      = errors.New("invalid PoW format: must be a decimal string representing a 64-bit unsigned integer")
	ErrPoWVerificationFailed = errors.New("PoW verification failed: insufficient leading zeros")
	ErrAlgorithmMismatch     = errors.New("PoW algorithm mismatch")
	ErrMissingAlgorithm      = errors.New("PoW algorithm identifier is required")
	ErrPoWCancelled          = errors.New("PoW computation cancelled")
)

// defaultWorkers returns the recommended number of parallel PoW workers.
// Caps at 4 to stay within reasonable memory limits.
func defaultWorkers() int {
	n := runtime.NumCPU()
	if n > 4 {
		n = 4
	}
	if n < 1 {
		n = 1
	}
	return n
}

// NeedsPoW 判断给定大小的文件是否需要 PoW 验证
// 规则：< 100 MiB 需要 PoW，≥ 100 MiB 免 PoW
// 规范参考: 项目规划.md §2.1 难度曲线
func NeedsPoW(dataSize int64) bool {
	return dataSize < PoWThreshold
}

// Verify 验证 PoW 是否满足难度要求
//
// 参数:
//   - pow: pow 字段值（满足难度要求的 salt，十进制字符串）
//   - powAlg: 算法标识符，必须为 "argon2id-light-v1"
//   - rootCID: 根 CID（Base32 字符串）
//   - dataTXID: Arweave 数据交易 ID
//   - dataSize: 原始数据大小（字节），用于判断是否需要 PoW
//
// 验证流程（规范 §2.1）:
//  1. 如果 dataSize >= 100 MiB，跳过验证（免 PoW）
//  2. 检查 pow_alg 是否匹配
//  3. 解析 pow 为 uint64 salt
//  4. 计算 Argon2id(rootCID+dataTXID, salt, 20MB/1/1)
//  5. 检查输出前导零 ≥ 2 字节
//
// 规范参考: 项目规划.md §2.1 验证
func Verify(pow, powAlg, rootCID, dataTXID string, dataSize int64) error {
	// 1. 大于等于 100 MiB 免 PoW（规范 §2.1 难度曲线）
	// 注意：此检查优先于算法标识检查，大文件即使提供无效 pow 也应跳过
	if dataSize >= PoWThreshold {
		return nil
	}

	// 2. 检查算法标识（规范 §2.1 验证步骤 1）
	if powAlg == "" {
		return ErrMissingAlgorithm
	}
	if powAlg != Algorithm {
		return fmt.Errorf("%w: expected %s, got %s", ErrAlgorithmMismatch, Algorithm, powAlg)
	}

	// 3. 小于 100 MiB 的文件必须提供 PoW
	if pow == "" {
		return ErrMissingPoW
	}

	// 4. 解析 salt（规范：pow 字段值为十进制字符串表示的 64 位无符号整数）
	salt, err := strconv.ParseUint(pow, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPoWFormat, err)
	}

	// 5. 构造 password = root_cid + data_txid（规范 §2.1 算法）
	password := []byte(rootCID + dataTXID)

	// 6. 将 salt 转换为 8 字节小端字节序
	saltBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(saltBytes, salt)

	// 7. 计算 Argon2id（20MB/1/1）
	hash := argon2.IDKey(password, saltBytes, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	// 8. 检查前导零（规范：前导零 ≥ 2 字节）
	if !hasLeadingZeroBytes(hash, MinLeadingZeroBytes) {
		return ErrPoWVerificationFailed
	}

	return nil
}

// hasLeadingZeroBytes 检查字节切片的前 n 个字节是否全为零
func hasLeadingZeroBytes(data []byte, n int) bool {
	if len(data) < n {
		return false
	}
	for i := 0; i < n; i++ {
		if data[i] != 0 {
			return false
		}
	}
	return true
}

// ComputePoW 计算满足难度要求的 PoW salt（单线程兼容包装）
//
// 警告：此函数执行 PoW 计算，可能消耗大量 CPU 和内存资源。
// 平均需要 ~65,536 次 Argon2id 计算（20MB/次）。
//
// 内部调用 ComputePoWParallel，使用默认 worker 数量。
// 仅用于离线生成测试向量，生产环境不应调用此函数。
//
// 参数:
//   - rootCID: 根 CID
//   - dataTXID: 数据交易 ID
//
// 返回: 满足难度要求的 salt 值（十进制字符串）
func ComputePoW(rootCID, dataTXID string) (string, error) {
	return ComputePoWParallel(context.Background(), rootCID, dataTXID, 0)
}

// ComputePoWParallel 使用多 goroutine 并行搜索不同 salt 范围，计算满足难度要求的 PoW salt。
//
// 规范参考: ipfar-specs/V1/项目规划.md §2.1 — 搜索并行度不限制。
//
// 每个 worker 搜索互不重叠的 salt 子空间（stride = numWorkers），
// 任一 worker 找到合法 salt 后立即通过 context 取消其余 worker。
//
// 参数:
//   - ctx: 上下文，用于取消正在进行的搜索
//   - rootCID: 根 CID
//   - dataTXID: 数据交易 ID
//   - numWorkers: 并行 worker 数量。传入 0 或负数则使用默认值 min(NumCPU, 4)
//
// 返回满足难度要求的 salt 值（十进制字符串）。
func ComputePoWParallel(ctx context.Context, rootCID, dataTXID string, numWorkers int) (string, error) {
	if numWorkers <= 0 {
		numWorkers = defaultWorkers()
	}

	password := []byte(rootCID + dataTXID)

	// Create a cancellable context so the first worker to find a solution
	// can signal all others to stop.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	resultCh := make(chan string, 1)
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(startSalt uint64) {
			defer wg.Done()
			salt := startSalt
			for {
				// Check cancellation before each hash computation.
				select {
				case <-ctx.Done():
					return
				default:
				}

				saltBytes := make([]byte, 8)
				binary.LittleEndian.PutUint64(saltBytes, salt)
				hash := argon2.IDKey(password, saltBytes, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

				if hasLeadingZeroBytes(hash, MinLeadingZeroBytes) {
					select {
					case resultCh <- strconv.FormatUint(salt, 10):
					case <-ctx.Done():
					default:
					}
					return
				}

				salt += uint64(numWorkers)

				if salt > maxSaltSafety {
					return
				}
			}
		}(uint64(i))
	}

	// Close resultCh when all workers have exited.
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Wait for the first result, cancellation, or all workers exhausted.
	select {
	case result, ok := <-resultCh:
		if ok && result != "" {
			return result, nil
		}
		return "", errors.New("PoW computation exceeded safety limit")
	case <-ctx.Done():
		return "", ErrPoWCancelled
	}
}
