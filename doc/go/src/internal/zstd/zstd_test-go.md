Response:
Let's break down the thought process for analyzing the Go code.

1. **Understand the Goal:** The request asks for the functionality of a Go test file (`zstd_test.go`) and how it tests the Zstandard decompression implementation.

2. **Initial Scan for Keywords:** Quickly look for keywords like `test`, `benchmark`, `import`, and function names. This gives a high-level overview. We see `testing`, `io`, `os`, which suggests file operations and standard testing procedures. The package name `zstd` and the function `NewReader` strongly indicate this is about Zstandard decompression.

3. **Analyze the `import` statements:**
    * `bytes`:  Likely used for in-memory byte buffers.
    * `crypto/sha256`: For checksum verification.
    * `fmt`: For formatted output (like `t.Errorf`).
    * `internal/race`: For detecting data races in concurrent code (likely skipped for performance tests).
    * `internal/testenv`: For checking the test environment (like optimization levels).
    * `io`: For input/output operations.
    * `os`: For operating system interactions (like file operations).
    * `os/exec`: For running external commands (like the `zstd` command-line tool).
    * `path/filepath`: For manipulating file paths.
    * `strings`: For string manipulation.
    * `sync`: For synchronization primitives (like `sync.Once`).
    * `testing`: The core Go testing package.

4. **Examine Global Variables:**
    * `tests`: A slice of structs, each containing a `name`, `uncompressed`, and `compressed` string. This is a clear indicator of test cases where the expected uncompressed output is known for a given compressed input.
    * `bigDataOnce`, `bigDataBytes`, `bigDataErr`:  Suggests loading a large file (`Isaac.Newton-Opticks.txt`) only once and reusing it. This is for performance testing with large datasets.
    * `zstdBigOnce`, `zstdBigBytes`, `zstdBigErr`:  Indicates compressing the large data using an external `zstd` command and storing the result. This allows testing decompression against data compressed by the standard `zstd` tool.

5. **Analyze Test Functions:** Look for functions starting with `Test`.
    * `TestSamples`: Iterates through the `tests` slice and checks if `NewReader` correctly decompresses the `compressed` string to the `uncompressed` string.
    * `TestReset`: Tests the `Reset` method of the `NewReader`. This is important for reusing the reader and avoiding allocations in performance-sensitive scenarios.
    * `TestLarge`:  Focuses on decompressing a large file. It uses the externally compressed data (`zstdBigData`). It also includes `showDiffs` to debug differences between expected and actual output.
    * `TestAlloc`: Measures memory allocations during decompression. It uses `testenv.SkipIfOptimizationOff` and skips under the race detector, indicating it's a performance-focused test.
    * `TestFileSamples`:  Reads files from the `testdata` directory (ending with `.zst`), decompresses them, calculates a SHA256 hash, and compares it to the filename prefix. This verifies decompression against real-world compressed files.
    * `TestReaderBad`: Iterates through a slice `badStrings` (not shown but implied) and checks that `NewReader` correctly returns an error for invalid compressed data.

6. **Analyze Helper Functions:** Look for functions that aren't tests but support the tests.
    * `bigData`: Loads and potentially repeats the contents of a large file.
    * `findZstd`: Locates the `zstd` executable on the system.
    * `zstdBigData`: Compresses the `bigData` using the external `zstd` command.
    * `showDiffs`:  A debugging utility to display differences between byte slices.

7. **Analyze Benchmark Functions:** Look for functions starting with `Benchmark`.
    * `BenchmarkLarge`: Measures the performance of decompressing the large compressed data. It uses `b.StopTimer`, `b.StartTimer`, and `b.ReportAllocs` for accurate benchmarking.

8. **Infer Functionality:** Based on the analysis, it's clear the file tests the `zstd` package's decompression functionality. It covers:
    * Basic decompression with predefined small examples.
    * Reusing the reader with the `Reset` method.
    * Decompressing large files.
    * Checking for errors with invalid compressed data.
    * Measuring memory allocations during decompression.
    * Verifying decompression against real-world compressed files.
    * Benchmarking the decompression performance.

9. **Construct Examples:** Based on the identified functionality, create code snippets to illustrate how the tested functions (`NewReader`, `Reset`) are used. Include expected inputs and outputs.

10. **Consider Command-line Arguments:** Notice the use of `exec.Command` and the `zstd` command-line tool. Explain how this is used for generating test data.

11. **Identify Potential Pitfalls:** Think about common mistakes users might make when using a decompression library. For example, forgetting to handle errors or trying to reuse a reader without resetting it.

12. **Structure the Answer:** Organize the findings into the requested categories: functionality, Go feature implementation, code examples, command-line arguments, and common mistakes. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this just tests basic decompression.
* **Correction:** Oh, the `TestAlloc` and `BenchmarkLarge` functions show it's also concerned with performance and memory usage.
* **Initial thought:** The `zstdBigData` function seems unnecessary.
* **Correction:** It's used to generate realistic compressed data using the standard `zstd` tool, which is important for testing compatibility.
* **Initial thought:**  Just list the test function names.
* **Refinement:** Describe *what* each test function is actually testing.

By following these steps and iteratively refining the understanding, a comprehensive analysis of the Go test file can be achieved.
这是一个 Go 语言的测试文件，路径为 `go/src/internal/zstd/zstd_test.go`。它的主要功能是**测试 `internal/zstd` 包中的 Zstandard 解压缩功能的实现是否正确**。

让我来详细列举一下它的功能：

1. **提供基础的压缩和解压缩测试用例 (`tests` 变量):**
   - `tests` 变量是一个结构体切片，包含了多个测试用例。
   - 每个测试用例都有一个 `name` (测试名称), `uncompressed` (未压缩的字符串) 和 `compressed` (对应的压缩字符串)。
   - `TestSamples` 函数会遍历这些测试用例，使用 `NewReader` 创建一个 Zstandard 解压缩器，并将压缩字符串作为输入。
   - 它会读取解压缩后的内容，并与预期的 `uncompressed` 字符串进行比较，以验证解压缩是否正确。

2. **测试 `Reset` 方法的正确性 (`TestReset` 函数):**
   - 该函数测试了 `NewReader` 返回的 Reader 接口的 `Reset` 方法。
   - `Reset` 方法允许重复使用同一个 Reader 实例来解压缩不同的压缩数据，而无需重新创建 Reader。这对于提高性能很有帮助。
   - 它遍历 `tests` 中的用例，使用不同的压缩数据重置 Reader，并验证解压缩结果。

3. **测试大型文件的解压缩 (`TestLarge` 函数):**
   - 该函数旨在测试处理大型压缩文件的能力。
   - 它依赖于一个名为 `bigData` 的函数来获取一个较大的未压缩数据块（从 `../../testdata/Isaac.Newton-Opticks.txt` 文件中读取并重复）。
   - 它还依赖于 `zstdBigData` 函数来获取该大型数据块的 Zstandard 压缩版本（通过调用外部的 `zstd` 命令行工具）。
   - 然后，它使用 `NewReader` 解压缩该大型压缩数据，并将解压缩后的数据与原始的未压缩数据进行比较。

4. **测试内存分配情况 (`TestAlloc` 函数):**
   - 该函数用于检查在解压缩过程中是否发生了不必要的内存分配。
   - 它使用了 `testing.AllocsPerRun` 函数来测量在多次运行解压缩操作期间的平均内存分配次数。
   - 目标是确保解压缩实现尽可能高效，避免不必要的堆分配。
   - 这个测试会跳过优化未开启的情况以及在 race 检测器开启时运行，因为 race 检测器会引入额外的分配。

5. **测试文件中的压缩数据 (`TestFileSamples` 函数):**
   - 该函数会读取 `testdata` 目录下的所有文件。
   - 对于以 `.zst` 结尾的文件，它会打开文件，创建一个 `NewReader` 来解压缩文件内容。
   - 它计算解压缩后内容的 SHA256 哈希值，并将其与文件名（去除 `.zst` 后缀）进行比较。
   - 这表明 `testdata` 目录下存放了一些压缩文件，文件名本身就是其解压后内容的哈希值的前缀。

6. **测试处理错误的压缩数据 (`TestReaderBad` 函数):**
   - 该函数遍历一个名为 `badStrings` 的切片（代码片段中未显示其内容，但可以推断出它包含了各种格式错误的 Zstandard 压缩数据）。
   - 对于每个错误的压缩数据，它尝试使用 `NewReader` 进行解压缩，并期望会返回一个错误。
   - 这确保了解压缩器能够正确地处理无效的输入，而不会崩溃或产生意外行为。

7. **性能基准测试 (`BenchmarkLarge` 函数):**
   - 该函数用于衡量解压缩大型压缩数据的性能。
   - 它使用 `testing.B` 提供的基准测试工具来运行解压缩操作多次，并报告每次操作的耗时和内存分配情况。
   - 这有助于评估解压缩实现的效率。

**它可以推理出这是 Zstandard 解压缩功能的实现。**

**Go 代码举例说明 Zstandard 解压缩功能的实现：**

```go
package main

import (
	"fmt"
	"internal/zstd"
	"io"
	"strings"
)

func main() {
	compressedData := "\x28\xb5\x2f\xfd\x24\x0d\x69\x00\x00\x68\x65\x6c\x6c\x6f\x2c\x20\x77\x6f\x72\x6c\x64\x0a\x4c\x1f\xf9\xf1"
	reader := zstd.NewReader(strings.NewReader(compressedData))
	defer reader.Close() // 记得关闭 Reader

	decompressedData, err := io.ReadAll(reader)
	if err != nil {
		fmt.Println("解压缩失败:", err)
		return
	}

	fmt.Println("解压缩后的数据:", string(decompressedData))

	// 假设的输入 (与 tests 变量中的 "hello" 用例相同)
	// 输入：压缩后的 "hello, world\n"

	// 预期输出：
	// 解压缩后的数据: hello, world
}
```

**代码推理的例子:**

假设 `compressedData` 是 `"\x28\xb5\x2f\xfd\x24\x0d\x69\x00\x00\x68\x65\x6c\x6c\x6f\x2c\x20\x77\x6f\x72\x6c\x64\x0a\x4c\x1f\xf9\xf1"`。

1. `zstd.NewReader(strings.NewReader(compressedData))` 会创建一个 Zstandard 解压缩器，读取 `compressedData` 中的字节流。
2. `io.ReadAll(reader)` 会从解压缩器中读取所有解压缩后的字节。
3. 根据 `tests` 变量中的定义，这个压缩数据对应于未压缩的字符串 `"hello, world\n"`。
4. 因此，`decompressedData` 的值将会是 `[]byte{'h', 'e', 'l', 'l', 'o', ',', ' ', 'w', 'o', 'r', 'l', 'd', '\n'}`。
5. `fmt.Println("解压缩后的数据:", string(decompressedData))` 将会输出 `解压缩后的数据: hello, world`。

**命令行参数的具体处理:**

在这个测试文件中，涉及到命令行参数的地方主要是 `zstdBigData` 函数中调用外部 `zstd` 命令：

```go
cmd := exec.Command(zstd, "-z")
cmd.Stdin = bytes.NewReader(input)
var compressed bytes.Buffer
cmd.Stdout = &compressed
cmd.Stderr = os.Stderr
if err := cmd.Run(); err != nil {
    zstdBigErr = fmt.Errorf("running zstd failed: %v", err)
    return
}
```

- `exec.Command(zstd, "-z")`:  这行代码创建了一个将要执行的命令。
    - `zstd` 是通过 `findZstd` 函数找到的 `zstd` 命令行工具的路径。
    - `"-z"` 是 `zstd` 命令的一个参数，表示进行压缩操作。
- `cmd.Stdin = bytes.NewReader(input)`:  这行代码将 `bigData` 函数返回的未压缩数据设置为 `zstd` 命令的标准输入。
- `var compressed bytes.Buffer`:  创建一个 `bytes.Buffer` 用于接收 `zstd` 命令的标准输出，也就是压缩后的数据。
- `cmd.Stdout = &compressed`: 将 `zstd` 命令的标准输出连接到 `compressed` 缓冲区。
- `cmd.Stderr = os.Stderr`: 将 `zstd` 命令的标准错误输出连接到当前进程的标准错误输出，方便查看错误信息。
- `cmd.Run()`:  执行 `zstd` 命令。

**总结：** `zstdBigData` 函数利用外部的 `zstd` 命令行工具来预先压缩一个大的测试文件。它使用了 `zstd -z` 命令，该命令会从标准输入读取数据并将其压缩后输出到标准输出。

**使用者易犯错的点:**

在直接使用 `internal/zstd` 包时，一个潜在的易错点是**忘记关闭 `NewReader` 返回的 `io.ReadCloser`**。虽然在大部分测试用例中，由于读取到结尾会自动处理，但在生产环境中，显式调用 `Close()` 可以释放底层资源，特别是当 Reader 被重复使用时。

**例子：**

```go
package main

import (
	"fmt"
	"internal/zstd"
	"io"
	"strings"
)

func main() {
	compressedData := "\x28\xb5\x2f\xfd\x24\x0d\x69\x00\x00\x68\x65\x6c\x6c\x6f\x2c\x20\x77\x6f\x72\x6c\x64\x0a\x4c\x1f\xf9\xf1"
	reader := zstd.NewReader(strings.NewReader(compressedData))
	// 忘记调用 reader.Close()，可能导致资源泄漏

	decompressedData, err := io.ReadAll(reader)
	if err != nil {
		fmt.Println("解压缩失败:", err)
		return
	}

	fmt.Println("解压缩后的数据:", string(decompressedData))
}
```

更好的做法是使用 `defer` 语句来确保 `Close()` 方法总是被调用：

```go
package main

import (
	"fmt"
	"internal/zstd"
	"io"
	"strings"
)

func main() {
	compressedData := "\x28\xb5\x2f\xfd\x24\x0d\x69\x00\x00\x68\x65\x6c\x6c\x6f\x2c\x20\x77\x6f\x72\x6c\x64\x0a\x4c\x1f\xf9\xf1"
	reader := zstd.NewReader(strings.NewReader(compressedData))
	defer reader.Close() // 确保 reader 在函数退出时被关闭

	decompressedData, err := io.ReadAll(reader)
	if err != nil {
		fmt.Println("解压缩失败:", err)
		return
	}

	fmt.Println("解压缩后的数据:", string(decompressedData))
}
```

### 提示词
```
这是路径为go/src/internal/zstd/zstd_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package zstd

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"internal/race"
	"internal/testenv"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// tests holds some simple test cases, including some found by fuzzing.
var tests = []struct {
	name, uncompressed, compressed string
}{
	{
		"hello",
		"hello, world\n",
		"\x28\xb5\x2f\xfd\x24\x0d\x69\x00\x00\x68\x65\x6c\x6c\x6f\x2c\x20\x77\x6f\x72\x6c\x64\x0a\x4c\x1f\xf9\xf1",
	},
	{
		// a small compressed .debug_ranges section.
		"ranges",
		"\xcc\x11\x00\x00\x00\x00\x00\x00\xd5\x13\x00\x00\x00\x00\x00\x00" +
			"\x1c\x14\x00\x00\x00\x00\x00\x00\x72\x14\x00\x00\x00\x00\x00\x00" +
			"\x9d\x14\x00\x00\x00\x00\x00\x00\xd5\x14\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\xfb\x12\x00\x00\x00\x00\x00\x00\x09\x13\x00\x00\x00\x00\x00\x00" +
			"\x0c\x13\x00\x00\x00\x00\x00\x00\xcb\x13\x00\x00\x00\x00\x00\x00" +
			"\x29\x14\x00\x00\x00\x00\x00\x00\x4e\x14\x00\x00\x00\x00\x00\x00" +
			"\x9d\x14\x00\x00\x00\x00\x00\x00\xd5\x14\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\xfb\x12\x00\x00\x00\x00\x00\x00\x09\x13\x00\x00\x00\x00\x00\x00" +
			"\x67\x13\x00\x00\x00\x00\x00\x00\xcb\x13\x00\x00\x00\x00\x00\x00" +
			"\x9d\x14\x00\x00\x00\x00\x00\x00\xd5\x14\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x5f\x0b\x00\x00\x00\x00\x00\x00\x6c\x0b\x00\x00\x00\x00\x00\x00" +
			"\x7d\x0b\x00\x00\x00\x00\x00\x00\x7e\x0c\x00\x00\x00\x00\x00\x00" +
			"\x38\x0f\x00\x00\x00\x00\x00\x00\x5c\x0f\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x83\x0c\x00\x00\x00\x00\x00\x00\xfa\x0c\x00\x00\x00\x00\x00\x00" +
			"\xfd\x0d\x00\x00\x00\x00\x00\x00\xef\x0e\x00\x00\x00\x00\x00\x00" +
			"\x14\x0f\x00\x00\x00\x00\x00\x00\x38\x0f\x00\x00\x00\x00\x00\x00" +
			"\x9f\x0f\x00\x00\x00\x00\x00\x00\xac\x0f\x00\x00\x00\x00\x00\x00" +
			"\xdb\x0f\x00\x00\x00\x00\x00\x00\xff\x0f\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\xfd\x0d\x00\x00\x00\x00\x00\x00\xd8\x0e\x00\x00\x00\x00\x00\x00" +
			"\x9f\x0f\x00\x00\x00\x00\x00\x00\xac\x0f\x00\x00\x00\x00\x00\x00" +
			"\xdb\x0f\x00\x00\x00\x00\x00\x00\xff\x0f\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\xfa\x0c\x00\x00\x00\x00\x00\x00\xea\x0d\x00\x00\x00\x00\x00\x00" +
			"\xef\x0e\x00\x00\x00\x00\x00\x00\x14\x0f\x00\x00\x00\x00\x00\x00" +
			"\x5c\x0f\x00\x00\x00\x00\x00\x00\x9f\x0f\x00\x00\x00\x00\x00\x00" +
			"\xac\x0f\x00\x00\x00\x00\x00\x00\xdb\x0f\x00\x00\x00\x00\x00\x00" +
			"\xff\x0f\x00\x00\x00\x00\x00\x00\x2c\x10\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x60\x11\x00\x00\x00\x00\x00\x00\xd1\x16\x00\x00\x00\x00\x00\x00" +
			"\x40\x0b\x00\x00\x00\x00\x00\x00\x2c\x10\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x7a\x00\x00\x00\x00\x00\x00\x00\xb6\x00\x00\x00\x00\x00\x00\x00" +
			"\x9f\x01\x00\x00\x00\x00\x00\x00\xa7\x01\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x7a\x00\x00\x00\x00\x00\x00\x00\xa9\x00\x00\x00\x00\x00\x00\x00" +
			"\x9f\x01\x00\x00\x00\x00\x00\x00\xa7\x01\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",

		"\x28\xb5\x2f\xfd\x64\xa0\x01\x2d\x05\x00\xc4\x04\xcc\x11\x00\xd5" +
			"\x13\x00\x1c\x14\x00\x72\x9d\xd5\xfb\x12\x00\x09\x0c\x13\xcb\x13" +
			"\x29\x4e\x67\x5f\x0b\x6c\x0b\x7d\x0b\x7e\x0c\x38\x0f\x5c\x0f\x83" +
			"\x0c\xfa\x0c\xfd\x0d\xef\x0e\x14\x38\x9f\x0f\xac\x0f\xdb\x0f\xff" +
			"\x0f\xd8\x9f\xac\xdb\xff\xea\x5c\x2c\x10\x60\xd1\x16\x40\x0b\x7a" +
			"\x00\xb6\x00\x9f\x01\xa7\x01\xa9\x36\x20\xa0\x83\x14\x34\x63\x4a" +
			"\x21\x70\x8c\x07\x46\x03\x4e\x10\x62\x3c\x06\x4e\xc8\x8c\xb0\x32" +
			"\x2a\x59\xad\xb2\xf1\x02\x82\x7c\x33\xcb\x92\x6f\x32\x4f\x9b\xb0" +
			"\xa2\x30\xf0\xc0\x06\x1e\x98\x99\x2c\x06\x1e\xd8\xc0\x03\x56\xd8" +
			"\xc0\x03\x0f\x6c\xe0\x01\xf1\xf0\xee\x9a\xc6\xc8\x97\x99\xd1\x6c" +
			"\xb4\x21\x45\x3b\x10\xe4\x7b\x99\x4d\x8a\x36\x64\x5c\x77\x08\x02" +
			"\xcb\xe0\xce",
	},
	{
		"fuzz1",
		"0\x00\x00\x00\x00\x000\x00\x00\x00\x00\x001\x00\x00\x00\x00\x000000",
		"(\xb5/\xfd\x04X\x8d\x00\x00P0\x000\x001\x000000\x03T\x02\x00\x01\x01m\xf9\xb7G",
	},
	{
		"empty block",
		"",
		"\x28\xb5\x2f\xfd\x00\x00\x15\x00\x00\x00\x00",
	},
	{
		"single skippable frame",
		"",
		"\x50\x2a\x4d\x18\x00\x00\x00\x00",
	},
	{
		"two skippable frames",
		"",
		"\x50\x2a\x4d\x18\x00\x00\x00\x00" +
			"\x50\x2a\x4d\x18\x00\x00\x00\x00",
	},
}

func TestSamples(t *testing.T) {
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			r := NewReader(strings.NewReader(test.compressed))
			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			gotstr := string(got)
			if gotstr != test.uncompressed {
				t.Errorf("got %q want %q", gotstr, test.uncompressed)
			}
		})
	}
}

func TestReset(t *testing.T) {
	input := strings.NewReader("")
	r := NewReader(input)
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			input.Reset(test.compressed)
			r.Reset(input)
			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			gotstr := string(got)
			if gotstr != test.uncompressed {
				t.Errorf("got %q want %q", gotstr, test.uncompressed)
			}
		})
	}
}

var (
	bigDataOnce  sync.Once
	bigDataBytes []byte
	bigDataErr   error
)

// bigData returns the contents of our large test file repeated multiple times.
func bigData(t testing.TB) []byte {
	bigDataOnce.Do(func() {
		bigDataBytes, bigDataErr = os.ReadFile("../../testdata/Isaac.Newton-Opticks.txt")
		if bigDataErr == nil {
			bigDataBytes = bytes.Repeat(bigDataBytes, 20)
		}
	})
	if bigDataErr != nil {
		t.Fatal(bigDataErr)
	}
	return bigDataBytes
}

func findZstd(t testing.TB) string {
	zstd, err := exec.LookPath("zstd")
	if err != nil {
		t.Skip("skipping because zstd not found")
	}
	return zstd
}

var (
	zstdBigOnce  sync.Once
	zstdBigBytes []byte
	zstdBigErr   error
)

// zstdBigData returns the compressed contents of our large test file.
// This will only run on Unix systems with zstd installed.
// That's OK as the package is GOOS-independent.
func zstdBigData(t testing.TB) []byte {
	input := bigData(t)

	zstd := findZstd(t)

	zstdBigOnce.Do(func() {
		cmd := exec.Command(zstd, "-z")
		cmd.Stdin = bytes.NewReader(input)
		var compressed bytes.Buffer
		cmd.Stdout = &compressed
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			zstdBigErr = fmt.Errorf("running zstd failed: %v", err)
			return
		}

		zstdBigBytes = compressed.Bytes()
	})
	if zstdBigErr != nil {
		t.Fatal(zstdBigErr)
	}
	return zstdBigBytes
}

// Test decompressing a large file. We don't have a compressor,
// so this test only runs on systems with zstd installed.
func TestLarge(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping expensive test in short mode")
	}

	data := bigData(t)
	compressed := zstdBigData(t)

	t.Logf("zstd compressed %d bytes to %d", len(data), len(compressed))

	r := NewReader(bytes.NewReader(compressed))
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, data) {
		showDiffs(t, got, data)
	}
}

// showDiffs reports the first few differences in two []byte.
func showDiffs(t *testing.T, got, want []byte) {
	t.Error("data mismatch")
	if len(got) != len(want) {
		t.Errorf("got data length %d, want %d", len(got), len(want))
	}
	diffs := 0
	for i, b := range got {
		if i >= len(want) {
			break
		}
		if b != want[i] {
			diffs++
			if diffs > 20 {
				break
			}
			t.Logf("%d: %#x != %#x", i, b, want[i])
		}
	}
}

func TestAlloc(t *testing.T) {
	testenv.SkipIfOptimizationOff(t)
	if race.Enabled {
		t.Skip("skipping allocation test under race detector")
	}

	compressed := zstdBigData(t)
	input := bytes.NewReader(compressed)
	r := NewReader(input)
	c := testing.AllocsPerRun(10, func() {
		input.Reset(compressed)
		r.Reset(input)
		io.Copy(io.Discard, r)
	})
	if c != 0 {
		t.Errorf("got %v allocs, want 0", c)
	}
}

func TestFileSamples(t *testing.T) {
	samples, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatal(err)
	}

	for _, sample := range samples {
		name := sample.Name()
		if !strings.HasSuffix(name, ".zst") {
			continue
		}

		t.Run(name, func(t *testing.T) {
			f, err := os.Open(filepath.Join("testdata", name))
			if err != nil {
				t.Fatal(err)
			}

			r := NewReader(f)
			h := sha256.New()
			if _, err := io.Copy(h, r); err != nil {
				t.Fatal(err)
			}
			got := fmt.Sprintf("%x", h.Sum(nil))[:8]

			want, _, _ := strings.Cut(name, ".")
			if got != want {
				t.Errorf("Wrong uncompressed content hash: got %s, want %s", got, want)
			}
		})
	}
}

func TestReaderBad(t *testing.T) {
	for i, s := range badStrings {
		t.Run(fmt.Sprintf("badStrings#%d", i), func(t *testing.T) {
			_, err := io.Copy(io.Discard, NewReader(strings.NewReader(s)))
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

func BenchmarkLarge(b *testing.B) {
	b.StopTimer()
	b.ReportAllocs()

	compressed := zstdBigData(b)

	b.SetBytes(int64(len(compressed)))

	input := bytes.NewReader(compressed)
	r := NewReader(input)

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		input.Reset(compressed)
		r.Reset(input)
		io.Copy(io.Discard, r)
	}
}
```