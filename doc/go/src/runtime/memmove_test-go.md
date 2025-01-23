Response:
Let's break down the thought process to analyze the provided Go code snippet.

1. **Identify the Core Purpose:** The file path `go/src/runtime/memmove_test.go` immediately suggests that this code is testing the `memmove` functionality within the Go runtime. The `_test.go` suffix confirms it's a testing file.

2. **Scan for Key Functions and Structures:**  Quickly look for function definitions. The names like `TestMemmove`, `TestMemmoveAlias`, `TestMemmoveLarge`, `TestMemmoveOverlapLarge`, `TestMemclr`, and various `Benchmark` functions are strong indicators of the file's functionality.

3. **Analyze `TestMemmove` and `TestMemmoveAlias`:** These are the foundational tests.
    * **`TestMemmove`:**  It sets up two separate byte slices (`src` and `dst`), populates `src` with data, and then uses `copy(dst[y:y+n], src[x:x+n])` in nested loops. This strongly suggests it's testing the basic functionality of copying memory from one location to another. The nested loops iterate through different sizes and offsets, indicating thorough testing of various scenarios. The assertions (`t.Fatalf`) check if the copy was successful.
    * **`TestMemmoveAlias`:** This is very similar to `TestMemmove`, but it uses a single byte slice (`buf`) as both source and destination. This highlights that it's specifically testing the behavior of `memmove` when the source and destination memory regions *overlap*. This is a crucial aspect of `memmove` compared to a simple memory copy.

4. **Analyze Large Memory Tests:** `TestMemmoveLarge` and `TestMemmoveOverlapLarge` are self-explanatory. They test `memmove` with larger data sizes and in overlapping scenarios. The `race.Enabled` check suggests they are skipped under the race detector, likely due to performance overhead or potential false positives in race detection for memory operations.

5. **Analyze `testSize` and `testOverlap`:** These appear to be helper functions used by the large memory tests. `testSize` performs a straightforward copy and compares the result with a reference. `testOverlap` specifically handles the overlapping case, using `copyref` (forward copy) and `copybw` (backward copy) to create the expected result. This reinforces the understanding that `memmove` needs to handle both forward and backward overlapping copies correctly.

6. **Analyze `TestMemmoveAtomicity`:**  This test is different. It's focused on *atomicity*. It uses pointers and `sync/atomic`. The core idea is to test if, during a `Memmove` operation involving pointers, the garbage collector can ever observe a partially copied pointer. The goroutine repeatedly calls `Memmove` while the main goroutine checks for intermediate states.

7. **Analyze Benchmark Functions:** The `Benchmark` functions are for performance testing. They measure how long `copy` (which uses `memmove` under the hood) and `MemclrBytes` take for different sizes and alignment scenarios. The sheer number of benchmark functions indicates a focus on optimizing performance across various conditions.

8. **Analyze `TestMemclr` and `BenchmarkMemclr`:** These sections are about memory clearing. `TestMemclr` verifies that `MemclrBytes` correctly sets memory to zero. The benchmarks measure the performance of `MemclrBytes` for various sizes and alignments. The `BenchmarkGoMemclr` compares this with the built-in `clear` function.

9. **Analyze `BenchmarkClearFat*` and `BenchmarkCopyFat*`:** These benchmarks are specifically testing the performance of clearing and copying arrays of different sizes. The "Fat" in the name likely refers to the size of the array being cleared or copied. The division by 4 in some cases (e.g., `[8 / 4]uint32`) suggests they might be looking at word-level operations.

10. **Analyze `BenchmarkIssue18740`:** This benchmark is tied to a specific issue, suggesting it's a regression test or a test for a specific optimization. It focuses on how `memmove` handles copying 2, 4, and 8 bytes, likely to ensure efficient use of load/store instructions.

11. **Analyze `BenchmarkMemclrKnownSize*`:** These benchmarks test the performance of clearing small, fixed-size arrays by iterating through their elements and setting them to zero. This provides a baseline for comparison with `MemclrBytes`.

12. **Identify Key Go Features:** The code makes extensive use of:
    * **Slices:**  `[]byte` is the primary data structure being manipulated.
    * **`copy()`:** This is the higher-level Go function that relies on `memmove`.
    * **`unsafe.Pointer`:** Used in the atomicity test for direct memory manipulation.
    * **`sync/atomic`:**  Used for atomic operations in the atomicity test.
    * **`testing` package:** For writing unit tests and benchmarks.
    * **`crypto/rand`:** For generating random data in some tests.
    * **`internal/race`:** For checking if the race detector is enabled.
    * **`internal/testenv`:** For checking the build environment (e.g., on the builder).

13. **Infer `memmove` Functionality:** Based on the tests, it's clear that `memmove` is the underlying function responsible for efficiently copying blocks of memory, especially handling overlapping source and destination regions correctly. `MemclrBytes` is responsible for efficiently setting memory to zero.

14. **Consider Potential Errors:** The overlapping memory tests (`TestMemmoveAlias`, `testOverlap`) highlight a common point of confusion:  If you're manually copying memory and the source and destination overlap, you need to be careful about the direction of the copy (forward or backward) to avoid overwriting data prematurely. `memmove` handles this automatically.

This detailed analysis, going from the overall purpose to the specifics of each function and benchmark, allows for a comprehensive understanding of the code's functionality. The process involves recognizing patterns, interpreting function names, and understanding the context of a testing file within the Go runtime.
这个 Go 语言代码文件 `memmove_test.go` 的主要功能是**测试 Go 语言运行时（runtime）中 `memmove` 和 `memclr` 函数的正确性和性能。**

具体来说，它包含了以下几个方面的测试：

**1. `memmove` 功能测试:**

* **`TestMemmove`:**  这个函数测试 `memmove` 的基本拷贝功能。它创建两个独立的 byte 切片 `src` 和 `dst`，并将 `src` 的一部分内容拷贝到 `dst` 的不同位置。通过三重循环遍历所有可能的拷贝长度和源/目标偏移量，并断言拷贝后的 `dst` 切片的内容是否符合预期。
    * **功能:**  验证在源地址和目标地址不重叠的情况下，`memmove` 能否正确地将指定长度的数据从源地址拷贝到目标地址。
    * **代码示例:**
    ```go
    package main

    import "fmt"

    func main() {
        src := []byte{1, 2, 3, 4, 5}
        dst := make([]byte, 5)

        // 假设我们要将 src 的前 3 个字节拷贝到 dst 的后 3 个字节
        copy(dst[2:5], src[0:3])

        fmt.Println("Source:", src)    // 输出: Source: [1 2 3 4 5]
        fmt.Println("Destination:", dst) // 输出: Destination: [0 0 1 2 3]
    }
    ```
    * **假设的输入与输出:** 在 `TestMemmove` 的循环中，`src` 和 `dst` 会被初始化，然后会尝试各种不同的 `n` (拷贝长度), `x` (源偏移), `y` (目标偏移)。 例如，假设 `size` 为 5, `n` 为 3, `x` 为 1, `y` 为 2。
        * **输入:** `src` 为 `[128 129 130 131 132]`, `dst` 为 `[0 1 2 3 4]`, `n`=3, `x`=1, `y`=2
        * **执行:** `copy(dst[2:5], src[1:4])`  相当于 `Memmove(unsafe.Pointer(&dst[2]), unsafe.Pointer(&src[1]), 3)`
        * **预期输出:** `dst` 变为 `[0 1 129 130 131]`

* **`TestMemmoveAlias`:** 这个函数测试 `memmove` 在源地址和目标地址重叠的情况下的拷贝功能。它使用同一个 byte 切片 `buf` 作为源和目标，并进行拷贝操作。同样通过三重循环遍历不同的拷贝长度和偏移量，并断言拷贝后的 `buf` 切片的内容是否正确。
    * **功能:** 验证在源地址和目标地址重叠的情况下，`memmove` 能否正确地处理拷贝，避免数据被覆盖。
    * **代码示例:**
    ```go
    package main

    import "fmt"

    func main() {
        buf := []byte{1, 2, 3, 4, 5}

        // 假设我们要将 buf 的前 3 个字节拷贝到 buf 的后 3 个字节 (重叠)
        copy(buf[2:5], buf[0:3])

        fmt.Println("Buffer:", buf) // 输出: Buffer: [1 2 1 2 3]
    }
    ```
    * **假设的输入与输出:** 假设 `size` 为 5, `n` 为 3, `x` 为 0, `y` 为 2。
        * **输入:** `buf` 为 `[0 1 2 3 4]`, `n`=3, `x`=0, `y`=2
        * **执行:** `copy(buf[2:5], buf[0:3])` 相当于 `Memmove(unsafe.Pointer(&buf[2]), unsafe.Pointer(&buf[0]), 3)`
        * **预期输出:** `buf` 变为 `[0 1 0 1 2]`

* **`TestMemmoveLarge0x180000` 和 `TestMemmoveOverlapLarge0x120000`:** 这两个函数测试 `memmove` 在处理较大内存块时的性能和正确性，分别测试非重叠和重叠的情况。
    * **功能:** 验证 `memmove` 在处理大块内存时的效率和稳定性。

* **`testSize` 和 `testOverlap`:** 这两个是辅助函数，被用于 `TestMemmoveLarge0x180000` 和 `TestMemmoveOverlapLarge0x120000`，用于执行实际的拷贝和比较操作。

* **`TestMemmoveAtomicity`:** 这个函数测试 `memmove` 在拷贝指针时的原子性。它创建包含指针的切片，并启动一个 goroutine 不断地使用 `Memmove` 拷贝这些指针。同时，主 goroutine 检查目标切片中的指针是否被部分更新，以此来验证 `Memmove` 操作的原子性。
    * **功能:** 验证 `memmove` 在拷贝指针类型数据时，能够保证操作的原子性，避免垃圾回收器观察到不一致的状态。
    * **代码示例:**  虽然这个测试比较复杂，但其核心思想是验证在并发环境下，`Memmove` 对指针的写入要么完全完成，要么完全没有完成，不会出现中间状态。

**2. `memclr` 功能测试:**

* **`TestMemclr`:** 这个函数测试 `MemclrBytes` 函数，用于将指定内存区域清零。它创建一个 byte 切片，并使用 `MemclrBytes` 清零不同的区域，然后断言清零操作是否成功，以及周围的内存是否未被影响。
    * **功能:** 验证 `MemclrBytes` 能否正确地将指定内存区域的所有字节设置为 0。
    * **代码示例:**
    ```go
    package main

    import (
        "fmt"
        "runtime"
        "unsafe"
    )

    func main() {
        mem := []byte{1, 2, 3, 4, 5}

        // 清零 mem 的中间 3 个字节
        runtime.MemclrBytes(mem[1:4])

        fmt.Println("Memory:", mem) // 输出: Memory: [1 0 0 0 5]
    }
    ```
    * **假设的输入与输出:** 假设 `size` 为 5, `n` 为 3, `x` 为 1。
        * **输入:** `mem` 为 `[238 238 238 238 238]`, `n`=3, `x`=1
        * **执行:** `MemclrBytes(mem[1:4])` 相当于 `runtime.memclr(unsafe.Pointer(&mem[1]), 3)`
        * **预期输出:** `mem` 变为 `[238 0 0 0 238]`

**3. 性能基准测试 (Benchmarks):**

文件中包含大量的 `Benchmark` 函数，用于测试 `memmove` 和 `memclr` 在不同场景下的性能，包括：

* 不同大小的内存块拷贝和清零。
* 源地址和目标地址是否对齐的影响。
* 源地址和目标地址重叠的影响。
* 与 Go 语言内置的 `clear` 函数的性能比较。
* 特定大小的数组拷贝和清零的性能测试 (例如 `BenchmarkClearFat7`, `BenchmarkCopyFat8` 等)。
* 针对特定 Issue (例如 `BenchmarkIssue18740`) 的性能测试。
* 使用循环逐个字节清零与使用 `MemclrBytes` 的性能对比 (例如 `BenchmarkMemclrKnownSize*`)。

**关于 `memmove` 和 `memclr` 的 Go 语言功能实现:**

`memmove` 和 `memclr` 是 Go 语言运行时提供的底层内存操作函数。在 Go 的高级代码中，我们通常使用内置的 `copy` 函数进行内存拷贝，或者直接使用赋值操作或 `clear` 函数进行清零操作。`copy` 函数在底层会根据情况选择使用 `memmove` (当源地址和目标地址可能重叠时) 或更快的 `memcpy` (当源地址和目标地址保证不重叠时)。`MemclrBytes` 是 `memclr` 的 Go 语言封装。

**命令行参数处理:**

这个代码文件本身是一个测试文件，它依赖于 `go test` 命令来运行。`go test` 命令有一些常用的 flag，例如：

* `-v`:  显示更详细的测试输出。
* `-run <regexp>`:  只运行匹配正则表达式的测试函数。
* `-bench <regexp>`: 只运行匹配正则表达式的基准测试函数。
* `-count n`:  运行每个测试或基准测试 n 次。
* `-cpuprofile <file>`: 将 CPU profile 写入指定文件。
* `-memprofile <file>`: 将内存 profile 写入指定文件。
* `-race`: 启用 race condition 检测器。
* `-short`: 运行时间较短的测试。

在代码中，可以看到 `if *flagQuick { t.Skip("-quick") }`，这表明该测试会检查是否设置了 `-quick` 这个内部的 flag。这个 flag 通常用于跳过一些耗时的测试。

**使用者易犯错的点:**

虽然开发者通常不会直接调用 `runtime.Memmove` 或 `runtime.MemclrBytes`，但理解它们的工作原理对于理解 Go 的内存操作至关重要。

* **内存重叠时的错误假设:** 如果手动进行内存拷贝，没有考虑源地址和目标地址重叠的情况，可能会导致数据损坏。`memmove` 能够正确处理这种情况，而简单的 `memcpy` 则不能保证。Go 的 `copy` 函数已经处理了这个问题，开发者无需担心。
* **不了解 `clear` 和 `MemclrBytes` 的区别:** `clear` 是 Go 1.14 引入的泛型函数，可以用于清零各种类型的切片和数组，包括包含指针的类型。`MemclrBytes` 只能用于清零 byte 切片，并且它是一个运行时函数，可能在某些底层优化上有所不同。在大多数情况下，使用 `clear` 更方便且类型安全。
* **性能优化过度:**  除非在对性能有极致要求的底层库开发中，否则开发者通常不需要直接操作 `memmove` 或 `memclr`。过度关注这些底层细节可能会导致代码复杂性增加，而收益不明显。

总而言之，`go/src/runtime/memmove_test.go` 是 Go 语言运行时中用于测试核心内存操作功能的重要组成部分，它确保了 `memmove` 和 `memclr` 在各种场景下的正确性和性能。开发者通过使用 Go 的高级特性（如 `copy` 和 `clear`），可以间接地受益于这些底层优化的成果。

### 提示词
```
这是路径为go/src/runtime/memmove_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime_test

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"internal/race"
	"internal/testenv"
	. "runtime"
	"sync/atomic"
	"testing"
	"unsafe"
)

func TestMemmove(t *testing.T) {
	if *flagQuick {
		t.Skip("-quick")
	}
	t.Parallel()
	size := 256
	if testing.Short() {
		size = 128 + 16
	}
	src := make([]byte, size)
	dst := make([]byte, size)
	for i := 0; i < size; i++ {
		src[i] = byte(128 + (i & 127))
	}
	for i := 0; i < size; i++ {
		dst[i] = byte(i & 127)
	}
	for n := 0; n <= size; n++ {
		for x := 0; x <= size-n; x++ { // offset in src
			for y := 0; y <= size-n; y++ { // offset in dst
				copy(dst[y:y+n], src[x:x+n])
				for i := 0; i < y; i++ {
					if dst[i] != byte(i&127) {
						t.Fatalf("prefix dst[%d] = %d", i, dst[i])
					}
				}
				for i := y; i < y+n; i++ {
					if dst[i] != byte(128+((i-y+x)&127)) {
						t.Fatalf("copied dst[%d] = %d", i, dst[i])
					}
					dst[i] = byte(i & 127) // reset dst
				}
				for i := y + n; i < size; i++ {
					if dst[i] != byte(i&127) {
						t.Fatalf("suffix dst[%d] = %d", i, dst[i])
					}
				}
			}
		}
	}
}

func TestMemmoveAlias(t *testing.T) {
	if *flagQuick {
		t.Skip("-quick")
	}
	t.Parallel()
	size := 256
	if testing.Short() {
		size = 128 + 16
	}
	buf := make([]byte, size)
	for i := 0; i < size; i++ {
		buf[i] = byte(i)
	}
	for n := 0; n <= size; n++ {
		for x := 0; x <= size-n; x++ { // src offset
			for y := 0; y <= size-n; y++ { // dst offset
				copy(buf[y:y+n], buf[x:x+n])
				for i := 0; i < y; i++ {
					if buf[i] != byte(i) {
						t.Fatalf("prefix buf[%d] = %d", i, buf[i])
					}
				}
				for i := y; i < y+n; i++ {
					if buf[i] != byte(i-y+x) {
						t.Fatalf("copied buf[%d] = %d", i, buf[i])
					}
					buf[i] = byte(i) // reset buf
				}
				for i := y + n; i < size; i++ {
					if buf[i] != byte(i) {
						t.Fatalf("suffix buf[%d] = %d", i, buf[i])
					}
				}
			}
		}
	}
}

func TestMemmoveLarge0x180000(t *testing.T) {
	if testing.Short() && testenv.Builder() == "" {
		t.Skip("-short")
	}

	t.Parallel()
	if race.Enabled {
		t.Skip("skipping large memmove test under race detector")
	}
	testSize(t, 0x180000)
}

func TestMemmoveOverlapLarge0x120000(t *testing.T) {
	if testing.Short() && testenv.Builder() == "" {
		t.Skip("-short")
	}

	t.Parallel()
	if race.Enabled {
		t.Skip("skipping large memmove test under race detector")
	}
	testOverlap(t, 0x120000)
}

func testSize(t *testing.T, size int) {
	src := make([]byte, size)
	dst := make([]byte, size)
	_, _ = rand.Read(src)
	_, _ = rand.Read(dst)

	ref := make([]byte, size)
	copyref(ref, dst)

	for n := size - 50; n > 1; n >>= 1 {
		for x := 0; x <= size-n; x = x*7 + 1 { // offset in src
			for y := 0; y <= size-n; y = y*9 + 1 { // offset in dst
				copy(dst[y:y+n], src[x:x+n])
				copyref(ref[y:y+n], src[x:x+n])
				p := cmpb(dst, ref)
				if p >= 0 {
					t.Fatalf("Copy failed, copying from src[%d:%d] to dst[%d:%d].\nOffset %d is different, %v != %v", x, x+n, y, y+n, p, dst[p], ref[p])
				}
			}
		}
	}
}

func testOverlap(t *testing.T, size int) {
	src := make([]byte, size)
	test := make([]byte, size)
	ref := make([]byte, size)
	_, _ = rand.Read(src)

	for n := size - 50; n > 1; n >>= 1 {
		for x := 0; x <= size-n; x = x*7 + 1 { // offset in src
			for y := 0; y <= size-n; y = y*9 + 1 { // offset in dst
				// Reset input
				copyref(test, src)
				copyref(ref, src)
				copy(test[y:y+n], test[x:x+n])
				if y <= x {
					copyref(ref[y:y+n], ref[x:x+n])
				} else {
					copybw(ref[y:y+n], ref[x:x+n])
				}
				p := cmpb(test, ref)
				if p >= 0 {
					t.Fatalf("Copy failed, copying from src[%d:%d] to dst[%d:%d].\nOffset %d is different, %v != %v", x, x+n, y, y+n, p, test[p], ref[p])
				}
			}
		}
	}

}

// Forward copy.
func copyref(dst, src []byte) {
	for i, v := range src {
		dst[i] = v
	}
}

// Backwards copy
func copybw(dst, src []byte) {
	if len(src) == 0 {
		return
	}
	for i := len(src) - 1; i >= 0; i-- {
		dst[i] = src[i]
	}
}

// Returns offset of difference
func matchLen(a, b []byte, max int) int {
	a = a[:max]
	b = b[:max]
	for i, av := range a {
		if b[i] != av {
			return i
		}
	}
	return max
}

func cmpb(a, b []byte) int {
	l := matchLen(a, b, len(a))
	if l == len(a) {
		return -1
	}
	return l
}

// Ensure that memmove writes pointers atomically, so the GC won't
// observe a partially updated pointer.
func TestMemmoveAtomicity(t *testing.T) {
	if race.Enabled {
		t.Skip("skip under the race detector -- this test is intentionally racy")
	}

	var x int

	for _, backward := range []bool{true, false} {
		for _, n := range []int{3, 4, 5, 6, 7, 8, 9, 10, 15, 25, 49} {
			n := n

			// test copying [N]*int.
			sz := uintptr(n * PtrSize)
			name := fmt.Sprint(sz)
			if backward {
				name += "-backward"
			} else {
				name += "-forward"
			}
			t.Run(name, func(t *testing.T) {
				// Use overlapping src and dst to force forward/backward copy.
				var s [100]*int
				src := s[n-1 : 2*n-1]
				dst := s[:n]
				if backward {
					src, dst = dst, src
				}
				for i := range src {
					src[i] = &x
				}
				clear(dst)

				var ready atomic.Uint32
				go func() {
					sp := unsafe.Pointer(&src[0])
					dp := unsafe.Pointer(&dst[0])
					ready.Store(1)
					for i := 0; i < 10000; i++ {
						Memmove(dp, sp, sz)
						MemclrNoHeapPointers(dp, sz)
					}
					ready.Store(2)
				}()

				for ready.Load() == 0 {
					Gosched()
				}

				for ready.Load() != 2 {
					for i := range dst {
						p := dst[i]
						if p != nil && p != &x {
							t.Fatalf("got partially updated pointer %p at dst[%d], want either nil or %p", p, i, &x)
						}
					}
				}
			})
		}
	}
}

func benchmarkSizes(b *testing.B, sizes []int, fn func(b *testing.B, n int)) {
	for _, n := range sizes {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			b.SetBytes(int64(n))
			fn(b, n)
		})
	}
}

var bufSizes = []int{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	32, 64, 128, 256, 512, 1024, 2048, 4096,
}
var bufSizesOverlap = []int{
	32, 64, 128, 256, 512, 1024, 2048, 4096,
}

func BenchmarkMemmove(b *testing.B) {
	benchmarkSizes(b, bufSizes, func(b *testing.B, n int) {
		x := make([]byte, n)
		y := make([]byte, n)
		for i := 0; i < b.N; i++ {
			copy(x, y)
		}
	})
}

func BenchmarkMemmoveOverlap(b *testing.B) {
	benchmarkSizes(b, bufSizesOverlap, func(b *testing.B, n int) {
		x := make([]byte, n+16)
		for i := 0; i < b.N; i++ {
			copy(x[16:n+16], x[:n])
		}
	})
}

func BenchmarkMemmoveUnalignedDst(b *testing.B) {
	benchmarkSizes(b, bufSizes, func(b *testing.B, n int) {
		x := make([]byte, n+1)
		y := make([]byte, n)
		for i := 0; i < b.N; i++ {
			copy(x[1:], y)
		}
	})
}

func BenchmarkMemmoveUnalignedDstOverlap(b *testing.B) {
	benchmarkSizes(b, bufSizesOverlap, func(b *testing.B, n int) {
		x := make([]byte, n+16)
		for i := 0; i < b.N; i++ {
			copy(x[16:n+16], x[1:n+1])
		}
	})
}

func BenchmarkMemmoveUnalignedSrc(b *testing.B) {
	benchmarkSizes(b, bufSizes, func(b *testing.B, n int) {
		x := make([]byte, n)
		y := make([]byte, n+1)
		for i := 0; i < b.N; i++ {
			copy(x, y[1:])
		}
	})
}

func BenchmarkMemmoveUnalignedSrcDst(b *testing.B) {
	for _, n := range []int{16, 64, 256, 4096, 65536} {
		buf := make([]byte, (n+8)*2)
		x := buf[:len(buf)/2]
		y := buf[len(buf)/2:]
		for _, off := range []int{0, 1, 4, 7} {
			b.Run(fmt.Sprint("f_", n, off), func(b *testing.B) {
				b.SetBytes(int64(n))
				for i := 0; i < b.N; i++ {
					copy(x[off:n+off], y[off:n+off])
				}
			})

			b.Run(fmt.Sprint("b_", n, off), func(b *testing.B) {
				b.SetBytes(int64(n))
				for i := 0; i < b.N; i++ {
					copy(y[off:n+off], x[off:n+off])
				}
			})
		}
	}
}

func BenchmarkMemmoveUnalignedSrcOverlap(b *testing.B) {
	benchmarkSizes(b, bufSizesOverlap, func(b *testing.B, n int) {
		x := make([]byte, n+1)
		for i := 0; i < b.N; i++ {
			copy(x[1:n+1], x[:n])
		}
	})
}

func TestMemclr(t *testing.T) {
	size := 512
	if testing.Short() {
		size = 128 + 16
	}
	mem := make([]byte, size)
	for i := 0; i < size; i++ {
		mem[i] = 0xee
	}
	for n := 0; n < size; n++ {
		for x := 0; x <= size-n; x++ { // offset in mem
			MemclrBytes(mem[x : x+n])
			for i := 0; i < x; i++ {
				if mem[i] != 0xee {
					t.Fatalf("overwrite prefix mem[%d] = %d", i, mem[i])
				}
			}
			for i := x; i < x+n; i++ {
				if mem[i] != 0 {
					t.Fatalf("failed clear mem[%d] = %d", i, mem[i])
				}
				mem[i] = 0xee
			}
			for i := x + n; i < size; i++ {
				if mem[i] != 0xee {
					t.Fatalf("overwrite suffix mem[%d] = %d", i, mem[i])
				}
			}
		}
	}
}

func BenchmarkMemclr(b *testing.B) {
	for _, n := range []int{5, 16, 64, 256, 4096, 65536} {
		x := make([]byte, n)
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			b.SetBytes(int64(n))
			for i := 0; i < b.N; i++ {
				MemclrBytes(x)
			}
		})
	}
	for _, m := range []int{1, 4, 8, 16, 64} {
		x := make([]byte, m<<20)
		b.Run(fmt.Sprint(m, "M"), func(b *testing.B) {
			b.SetBytes(int64(m << 20))
			for i := 0; i < b.N; i++ {
				MemclrBytes(x)
			}
		})
	}
}

func BenchmarkMemclrUnaligned(b *testing.B) {
	for _, off := range []int{0, 1, 4, 7} {
		for _, n := range []int{5, 16, 64, 256, 4096, 65536} {
			x := make([]byte, n+off)
			b.Run(fmt.Sprint(off, n), func(b *testing.B) {
				b.SetBytes(int64(n))
				for i := 0; i < b.N; i++ {
					MemclrBytes(x[off:])
				}
			})
		}
	}

	for _, off := range []int{0, 1, 4, 7} {
		for _, m := range []int{1, 4, 8, 16, 64} {
			x := make([]byte, (m<<20)+off)
			b.Run(fmt.Sprint(off, m, "M"), func(b *testing.B) {
				b.SetBytes(int64(m << 20))
				for i := 0; i < b.N; i++ {
					MemclrBytes(x[off:])
				}
			})
		}
	}
}

func BenchmarkGoMemclr(b *testing.B) {
	benchmarkSizes(b, []int{5, 16, 64, 256}, func(b *testing.B, n int) {
		x := make([]byte, n)
		for i := 0; i < b.N; i++ {
			clear(x)
		}
	})
}

func BenchmarkMemclrRange(b *testing.B) {
	type RunData struct {
		data []int
	}

	benchSizes := []RunData{
		{[]int{1043, 1078, 1894, 1582, 1044, 1165, 1467, 1100, 1919, 1562, 1932, 1645,
			1412, 1038, 1576, 1200, 1029, 1336, 1095, 1494, 1350, 1025, 1502, 1548, 1316, 1296,
			1868, 1639, 1546, 1626, 1642, 1308, 1726, 1665, 1678, 1187, 1515, 1598, 1353, 1237,
			1977, 1452, 2012, 1914, 1514, 1136, 1975, 1618, 1536, 1695, 1600, 1733, 1392, 1099,
			1358, 1996, 1224, 1783, 1197, 1838, 1460, 1556, 1554, 2020}}, // 1kb-2kb
		{[]int{3964, 5139, 6573, 7775, 6553, 2413, 3466, 5394, 2469, 7336, 7091, 6745,
			4028, 5643, 6164, 3475, 4138, 6908, 7559, 3335, 5660, 4122, 3945, 2082, 7564, 6584,
			5111, 2288, 6789, 2797, 4928, 7986, 5163, 5447, 2999, 4968, 3174, 3202, 7908, 8137,
			4735, 6161, 4646, 7592, 3083, 5329, 3687, 2754, 3599, 7231, 6455, 2549, 8063, 2189,
			7121, 5048, 4277, 6626, 6306, 2815, 7473, 3963, 7549, 7255}}, // 2kb-8kb
		{[]int{16304, 15936, 15760, 4736, 9136, 11184, 10160, 5952, 14560, 15744,
			6624, 5872, 13088, 14656, 14192, 10304, 4112, 10384, 9344, 4496, 11392, 7024,
			5200, 10064, 14784, 5808, 13504, 10480, 8512, 4896, 13264, 5600}}, // 4kb-16kb
		{[]int{164576, 233136, 220224, 183280, 214112, 217248, 228560, 201728}}, // 128kb-256kb
	}

	for _, t := range benchSizes {
		total := 0
		minLen := 0
		maxLen := 0

		for _, clrLen := range t.data {
			maxLen = max(maxLen, clrLen)
			if clrLen < minLen || minLen == 0 {
				minLen = clrLen
			}
			total += clrLen
		}
		buffer := make([]byte, maxLen)

		text := ""
		if minLen >= (1 << 20) {
			text = fmt.Sprint(minLen>>20, "M ", (maxLen+(1<<20-1))>>20, "M")
		} else if minLen >= (1 << 10) {
			text = fmt.Sprint(minLen>>10, "K ", (maxLen+(1<<10-1))>>10, "K")
		} else {
			text = fmt.Sprint(minLen, " ", maxLen)
		}
		b.Run(text, func(b *testing.B) {
			b.SetBytes(int64(total))
			for i := 0; i < b.N; i++ {
				for _, clrLen := range t.data {
					MemclrBytes(buffer[:clrLen])
				}
			}
		})
	}
}

func BenchmarkClearFat7(b *testing.B) {
	p := new([7]byte)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = [7]byte{}
	}
}

func BenchmarkClearFat8(b *testing.B) {
	p := new([8 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = [8 / 4]uint32{}
	}
}

func BenchmarkClearFat11(b *testing.B) {
	p := new([11]byte)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = [11]byte{}
	}
}

func BenchmarkClearFat12(b *testing.B) {
	p := new([12 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = [12 / 4]uint32{}
	}
}

func BenchmarkClearFat13(b *testing.B) {
	p := new([13]byte)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = [13]byte{}
	}
}

func BenchmarkClearFat14(b *testing.B) {
	p := new([14]byte)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = [14]byte{}
	}
}

func BenchmarkClearFat15(b *testing.B) {
	p := new([15]byte)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = [15]byte{}
	}
}

func BenchmarkClearFat16(b *testing.B) {
	p := new([16 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = [16 / 4]uint32{}
	}
}

func BenchmarkClearFat24(b *testing.B) {
	p := new([24 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = [24 / 4]uint32{}
	}
}

func BenchmarkClearFat32(b *testing.B) {
	p := new([32 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = [32 / 4]uint32{}
	}
}

func BenchmarkClearFat40(b *testing.B) {
	p := new([40 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = [40 / 4]uint32{}
	}
}

func BenchmarkClearFat48(b *testing.B) {
	p := new([48 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = [48 / 4]uint32{}
	}
}

func BenchmarkClearFat56(b *testing.B) {
	p := new([56 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = [56 / 4]uint32{}
	}
}

func BenchmarkClearFat64(b *testing.B) {
	p := new([64 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = [64 / 4]uint32{}
	}
}

func BenchmarkClearFat72(b *testing.B) {
	p := new([72 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = [72 / 4]uint32{}
	}
}

func BenchmarkClearFat128(b *testing.B) {
	p := new([128 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = [128 / 4]uint32{}
	}
}

func BenchmarkClearFat256(b *testing.B) {
	p := new([256 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = [256 / 4]uint32{}
	}
}

func BenchmarkClearFat512(b *testing.B) {
	p := new([512 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = [512 / 4]uint32{}
	}
}

func BenchmarkClearFat1024(b *testing.B) {
	p := new([1024 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = [1024 / 4]uint32{}
	}
}

func BenchmarkClearFat1032(b *testing.B) {
	p := new([1032 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = [1032 / 4]uint32{}
	}
}

func BenchmarkClearFat1040(b *testing.B) {
	p := new([1040 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = [1040 / 4]uint32{}
	}
}

func BenchmarkCopyFat7(b *testing.B) {
	var x [7]byte
	p := new([7]byte)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = x
	}
}

func BenchmarkCopyFat8(b *testing.B) {
	var x [8 / 4]uint32
	p := new([8 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = x
	}
}

func BenchmarkCopyFat11(b *testing.B) {
	var x [11]byte
	p := new([11]byte)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = x
	}
}

func BenchmarkCopyFat12(b *testing.B) {
	var x [12 / 4]uint32
	p := new([12 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = x
	}
}

func BenchmarkCopyFat13(b *testing.B) {
	var x [13]byte
	p := new([13]byte)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = x
	}
}

func BenchmarkCopyFat14(b *testing.B) {
	var x [14]byte
	p := new([14]byte)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = x
	}
}

func BenchmarkCopyFat15(b *testing.B) {
	var x [15]byte
	p := new([15]byte)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = x
	}
}

func BenchmarkCopyFat16(b *testing.B) {
	var x [16 / 4]uint32
	p := new([16 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = x
	}
}

func BenchmarkCopyFat24(b *testing.B) {
	var x [24 / 4]uint32
	p := new([24 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = x
	}
}

func BenchmarkCopyFat32(b *testing.B) {
	var x [32 / 4]uint32
	p := new([32 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = x
	}
}

func BenchmarkCopyFat64(b *testing.B) {
	var x [64 / 4]uint32
	p := new([64 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = x
	}
}

func BenchmarkCopyFat72(b *testing.B) {
	var x [72 / 4]uint32
	p := new([72 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = x
	}
}

func BenchmarkCopyFat128(b *testing.B) {
	var x [128 / 4]uint32
	p := new([128 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = x
	}
}

func BenchmarkCopyFat256(b *testing.B) {
	var x [256 / 4]uint32
	p := new([256 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = x
	}
}

func BenchmarkCopyFat512(b *testing.B) {
	var x [512 / 4]uint32
	p := new([512 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = x
	}
}

func BenchmarkCopyFat520(b *testing.B) {
	var x [520 / 4]uint32
	p := new([520 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = x
	}
}

func BenchmarkCopyFat1024(b *testing.B) {
	var x [1024 / 4]uint32
	p := new([1024 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = x
	}
}

func BenchmarkCopyFat1032(b *testing.B) {
	var x [1032 / 4]uint32
	p := new([1032 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = x
	}
}

func BenchmarkCopyFat1040(b *testing.B) {
	var x [1040 / 4]uint32
	p := new([1040 / 4]uint32)
	Escape(p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		*p = x
	}
}

// BenchmarkIssue18740 ensures that memmove uses 4 and 8 byte load/store to move 4 and 8 bytes.
// It used to do 2 2-byte load/stores, which leads to a pipeline stall
// when we try to read the result with one 4-byte load.
func BenchmarkIssue18740(b *testing.B) {
	benchmarks := []struct {
		name  string
		nbyte int
		f     func([]byte) uint64
	}{
		{"2byte", 2, func(buf []byte) uint64 { return uint64(binary.LittleEndian.Uint16(buf)) }},
		{"4byte", 4, func(buf []byte) uint64 { return uint64(binary.LittleEndian.Uint32(buf)) }},
		{"8byte", 8, func(buf []byte) uint64 { return binary.LittleEndian.Uint64(buf) }},
	}

	var g [4096]byte
	for _, bm := range benchmarks {
		buf := make([]byte, bm.nbyte)
		b.Run(bm.name, func(b *testing.B) {
			for j := 0; j < b.N; j++ {
				for i := 0; i < 4096; i += bm.nbyte {
					copy(buf[:], g[i:])
					sink += bm.f(buf[:])
				}
			}
		})
	}
}

var memclrSink []int8

func BenchmarkMemclrKnownSize1(b *testing.B) {
	var x [1]int8

	b.SetBytes(1)
	for i := 0; i < b.N; i++ {
		for a := range x {
			x[a] = 0
		}
	}

	memclrSink = x[:]
}
func BenchmarkMemclrKnownSize2(b *testing.B) {
	var x [2]int8

	b.SetBytes(2)
	for i := 0; i < b.N; i++ {
		for a := range x {
			x[a] = 0
		}
	}

	memclrSink = x[:]
}
func BenchmarkMemclrKnownSize4(b *testing.B) {
	var x [4]int8

	b.SetBytes(4)
	for i := 0; i < b.N; i++ {
		for a := range x {
			x[a] = 0
		}
	}

	memclrSink = x[:]
}
func BenchmarkMemclrKnownSize8(b *testing.B) {
	var x [8]int8

	b.SetBytes(8)
	for i := 0; i < b.N; i++ {
		for a := range x {
			x[a] = 0
		}
	}

	memclrSink = x[:]
}
func BenchmarkMemclrKnownSize16(b *testing.B) {
	var x [16]int8

	b.SetBytes(16)
	for i := 0; i < b.N; i++ {
		for a := range x {
			x[a] = 0
		}
	}

	memclrSink = x[:]
}
func BenchmarkMemclrKnownSize32(b *testing.B) {
	var x [32]int8

	b.SetBytes(32)
	for i := 0; i < b.N; i++ {
		for a := range x {
			x[a] = 0
		}
	}

	memclrSink = x[:]
}
func BenchmarkMemclrKnownSize64(b *testing.B) {
	var x [64]int8

	b.SetBytes(64)
	for i := 0; i < b.N; i++ {
		for a := range x {
			x[a] = 0
		}
	}

	memclrSink = x[:]
}
func BenchmarkMemclrKnownSize112(b *testing.B) {
	var x [112]int8

	b.SetBytes(112)
	for i := 0; i < b.N; i++ {
		for a := range x {
			x[a] = 0
		}
	}

	memclrSink = x[:]
}

func BenchmarkMemclrKnownSize128(b *testing.B) {
	var x [128]int8

	b.SetBytes(128)
	for i := 0; i < b.N; i++ {
		for a := range x {
			x[a] = 0
		}
	}

	memclrSink = x[:]
}

func BenchmarkMemclrKnownSize192(b *testing.B) {
	var x [192]int8

	b.SetBytes(192)
	for i := 0; i < b.N; i++ {
		for a := range x {
			x[a] = 0
		}
	}

	memclrSink = x[:]
}

func BenchmarkMemclrKnownSize248(b *testing.B) {
	var x [248]int8

	b.SetBytes(248)
	for i := 0; i < b.N; i++ {
		for a := range x {
			x[a] = 0
		}
	}

	memclrSink = x[:]
}

func BenchmarkMemclrKnownSize256(b *testing.B) {
	var x [256]int8

	b.SetBytes(256)
	for i := 0; i < b.N; i++ {
		for a := range x {
			x[a] = 0
		}
	}

	memclrSink = x[:]
}
func BenchmarkMemclrKnownSize512(b *testing.B) {
	var x [512]int8

	b.SetBytes(512)
	for i := 0; i < b.N; i++ {
		for a := range x {
			x[a] = 0
		}
	}

	memclrSink = x[:]
}
func BenchmarkMemclrKnownSize1024(b *testing.B) {
	var x [1024]int8

	b.SetBytes(1024)
	for i := 0; i < b.N; i++ {
		for a := range x {
			x[a] = 0
		}
	}

	memclrSink = x[:]
}
func BenchmarkMemclrKnownSize4096(b *testing.B) {
	var x [4096]int8

	b.SetBytes(4096)
	for i := 0; i < b.N; i++ {
		for a := range x {
			x[a] = 0
		}
	}

	memclrSink = x[:]
}
func BenchmarkMemclrKnownSize512KiB(b *testing.B) {
	var x [524288]int8

	b.SetBytes(524288)
	for i := 0; i < b.N; i++ {
		for a := range x {
			x[a] = 0
		}
	}

	memclrSink = x[:]
}
```