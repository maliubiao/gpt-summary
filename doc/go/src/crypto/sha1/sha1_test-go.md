Response:
Let's break down the thought process to analyze the provided Go code snippet.

**1. Initial Understanding of the Request:**

The request asks for an analysis of a Go test file (`sha1_test.go`). It specifically requests:

* **Functionality listing:** What does this code *do*?
* **Inferred Go feature:** What aspect of Go is being tested? Provide code examples.
* **Code inference (with examples):**  If I can deduce how specific parts work, show with input and output.
* **Command-line argument handling:**  Are there any command-line arguments involved?
* **Common mistakes:** Are there any pitfalls for users?
* **Chinese answers.**

**2. High-Level Analysis of the Code:**

I see `package sha1` and several imports related to testing, crypto, encoding, and I/O. The filename `sha1_test.go` strongly suggests this is a test suite for the SHA-1 hashing algorithm implementation in Go's standard library.

**3. Deeper Dive and Functionality Identification:**

* **`golden` variable:** This looks like a collection of test cases. Each `sha1Test` struct contains an expected output hash (`out`), an input string (`in`), and an intermediate state (`halfState`). This immediately tells me the tests verify the correctness of the SHA-1 calculation for various inputs.
* **`TestGolden` function:** This function iterates through the `golden` test cases. It calculates the SHA-1 hash of the input (`g.in`) using the `Sum` function and compares it to the expected output (`g.out`). It also tests the incremental hashing using `io.WriteString` and `c.Sum(nil)`, confirming that hashing in chunks works correctly. The `boring.Enabled` check suggests conditional testing based on a build tag or environment variable. The `ConstantTimeSum` call hints at a potential security-focused implementation.
* **`TestGoldenMarshal` function:** This function tests the `MarshalBinary` and `UnmarshalBinary` methods. This indicates the `sha1` implementation likely supports serialization and deserialization of its internal state. The `halfState` in the `golden` data is used to verify the marshaled state at a specific point.
* **`TestSize` and `TestBlockSize`:** These are straightforward tests to verify that the `Size()` and `BlockSize()` methods return the expected values for SHA-1.
* **`TestBlockGeneric`:** This test compares the output of `blockGeneric` (likely a pure Go implementation) and `block` (potentially an assembly-optimized version) for the core SHA-1 processing logic. This is a common practice to ensure consistency between different implementations.
* **`unmarshalTest` and `largeUnmarshalTests`, `TestLargeHashes`:** These sections focus on testing the unmarshaling of SHA-1 states after processing a very large amount of data. This is designed to catch potential issues with integer overflow or incorrect handling of large input lengths during state serialization.
* **`TestAllocations`:** This benchmark measures the number of memory allocations during a SHA-1 hashing operation. The goal is to minimize allocations for performance.
* **`TestSHA1Hash`:**  This calls `cryptotest.TestHash`, indicating the use of a generic test framework within the `crypto` package for testing hash functions.
* **`BenchmarkHash...` functions:** These are standard Go benchmarks to measure the performance of the SHA-1 implementation for different input sizes.

**4. Inferring Go Features:**

Based on the identified functionalities, the main Go features being tested are:

* **`hash.Hash` interface:** The code clearly uses the `hash.Hash` interface, as evidenced by calls to `New()`, `Write()`, `Sum()`, and `Reset()`.
* **`encoding.BinaryMarshaler` and `encoding.BinaryUnmarshaler` interfaces:** The `TestGoldenMarshal` function directly tests these interfaces, which allow for custom serialization and deserialization.
* **Testing framework:** The presence of `testing.T` and functions like `t.Fatalf`, `t.Errorf`, and `t.Skip` confirms the use of Go's built-in testing framework.
* **Benchmarking framework:** The `testing.B` type and functions like `b.N`, `b.ReportAllocs`, and `b.SetBytes` indicate the use of Go's benchmarking capabilities.

**5. Providing Code Examples (as requested):**

I can create examples demonstrating the usage of `hash.Hash` and the marshaling interfaces based on the test code.

**6. Code Inference and Examples (as requested):**

The `golden` variable provides input/output pairs. I can use these to demonstrate the `Sum` function. The `TestGoldenMarshal` function implicitly demonstrates the marshaling/unmarshaling process, and I can replicate that in an example.

**7. Command-Line Arguments:**

I see no direct parsing of command-line arguments in the code. However, the `boring.Enabled` check suggests the possibility of a build tag or environment variable influencing the test execution, which can be set via command-line tools.

**8. Common Mistakes:**

The `TestLargeHashes` section highlights a potential mistake related to handling very large input sizes when unmarshaling. Users might assume that a serialized state can always be restored without considering potential integer overflow issues.

**9. Structuring the Answer (in Chinese):**

Finally, I need to organize the findings into a clear and concise Chinese answer, addressing each point in the request. This involves translating the technical terms and concepts accurately.

This systematic approach allows me to thoroughly analyze the code snippet and address all the requirements of the request. The key is to start with a high-level understanding, then progressively drill down into the details, focusing on the purpose and functionality of each part of the code. The presence of test cases provides valuable clues about the intended behavior and the Go features being utilized.
这段代码是 Go 语言标准库中 `crypto/sha1` 包的测试文件 `sha1_test.go` 的一部分。它的主要功能是测试 SHA-1 哈希算法的实现是否正确。

**以下是代码的功能列表：**

1. **黄金标准测试 (`TestGolden`)**:
   - 定义了一组预先计算好的 SHA-1 哈希值 (`golden` 变量) 以及对应的输入字符串。
   - 针对每个测试用例，使用 `sha1.Sum()` 函数计算输入字符串的 SHA-1 哈希值，并与预期的哈希值进行比较，验证 `Sum` 函数的正确性。
   - 进一步测试了通过 `io.WriteString` 逐步写入数据并调用 `Sum` 方法计算哈希值的过程，确保增量计算的正确性。
   - 针对非 BoringSSL 构建，测试了 `ConstantTimeSum` 方法，这可能是为了防止侧信道攻击而实现的常量时间计算的哈希方法。

2. **状态序列化/反序列化测试 (`TestGoldenMarshal`)**:
   - 测试了 SHA-1 哈希状态的序列化和反序列化功能。
   - 对于每个测试用例，将输入字符串的前半部分写入哈希对象，然后使用 `MarshalBinary` (或 `AppendBinary`) 方法将哈希的中间状态序列化。
   - 将序列化后的状态与预期的中间状态 (`halfState`) 进行比较，验证序列化结果的正确性。
   - 使用 `UnmarshalBinary` 方法将序列化后的状态反序列化到另一个哈希对象中。
   - 将完整输入字符串的后半部分写入原始哈希对象和反序列化后的哈希对象。
   - 比较两个哈希对象最终计算出的哈希值，验证序列化和反序列化后哈希计算的正确性。

3. **大小和块大小测试 (`TestSize`, `TestBlockSize`)**:
   - 验证 `sha1.New()` 创建的哈希对象返回的 `Size()` 方法是否返回预期的哈希值长度（SHA-1 为 20 字节）。
   - 验证 `BlockSize()` 方法是否返回预期的块大小（SHA-1 为 64 字节）。

4. **通用块处理测试 (`TestBlockGeneric`)**:
   -  (仅在非 BoringSSL 构建下) 比较 `blockGeneric` 函数（纯 Go 实现的块处理逻辑）和 `block` 函数（可能是汇编优化的块处理逻辑）对相同输入的处理结果。
   -  确保在不同的底层实现下，哈希计算的结果一致。

5. **大数据哈希状态反序列化测试 (`TestLargeHashes`)**:
   -  测试反序列化处理过大量数据的 SHA-1 哈希状态的功能，解决 GitHub issue #29543 中描述的问题。
   -  定义了一些预先生成的、处理过大数据量的哈希状态和对应的最终哈希值。
   -  将这些状态反序列化到哈希对象中，并计算最终的哈希值，与预期的哈希值进行比较，验证在大数据量情况下反序列化的正确性。
   -  使用 `safeSum` 函数捕获 `Sum` 方法可能发生的 panic。

6. **内存分配测试 (`TestAllocations`)**:
   -  测试在执行 SHA-1 哈希计算时是否产生了不必要的内存分配。
   -  使用 `testing.AllocsPerRun` 函数测量在多次运行哈希计算过程中分配的内存次数，期望分配次数为 0。

7. **通用的哈希接口测试 (`TestSHA1Hash`)**:
   -  使用 `cryptotest.TestHash` 函数来运行通用的哈希接口测试，确保 `sha1.New()` 创建的对象满足 `hash.Hash` 接口的约定。

8. **性能基准测试 (`BenchmarkHash...`)**:
   -  定义了不同大小输入数据的性能基准测试 (`BenchmarkHash8Bytes`, `BenchmarkHash320Bytes`, `BenchmarkHash1K`, `BenchmarkHash8K`)。
   -  分别测试了使用 `sha1.New()` 创建哈希对象并计算哈希以及直接使用 `sha1.Sum()` 函数计算哈希的性能。

**推理出的 Go 语言功能实现：SHA-1 哈希算法**

这段代码是用来测试 Go 语言 `crypto/sha1` 包中 SHA-1 哈希算法的实现的。SHA-1 是一种将任意长度的数据映射为固定长度（20 字节）哈希值的算法。

**Go 代码举例说明 SHA-1 的使用：**

```go
package main

import (
	"crypto/sha1"
	"fmt"
)

func main() {
	data := []byte("hello world")

	// 使用 sha1.Sum() 函数计算哈希值
	hashBytes := sha1.Sum(data)
	fmt.Printf("SHA-1 hash of '%s': %x\n", data, hashBytes)

	// 使用 sha1.New() 创建哈希对象并逐步写入数据
	h := sha1.New()
	h.Write(data)
	hashBytes2 := h.Sum(nil)
	fmt.Printf("SHA-1 hash of '%s' (using New): %x\n", data, hashBytes2)
}
```

**假设的输入与输出（基于 `golden` 变量）：**

**输入：** `[]byte("abc")`

**输出：** `a9993e364706816aba3e25717850c26c9cd0d89d`

**输入：** `[]byte("")` (空字符串)

**输出：** `da39a3ee5e6b4b0d3255bfef95601890afd80709`

**命令行参数的具体处理：**

这段代码本身是测试代码，并不直接处理命令行参数。但是，Go 的测试框架 `go test` 接收各种命令行参数来控制测试的执行，例如：

- `-v`:  显示详细的测试输出。
- `-run <regexp>`:  只运行名称匹配正则表达式的测试函数。
- `-bench <regexp>`: 只运行名称匹配正则表达式的性能基准测试。
- `-count n`: 运行每个测试或基准测试 n 次。
- `-cpuprofile <file>`: 将 CPU 分析数据写入指定文件。
- `-memprofile <file>`: 将内存分析数据写入指定文件。

例如，要运行 `sha1_test.go` 文件中的所有测试，可以在命令行中执行：

```bash
go test go/src/crypto/sha1/sha1_test.go
```

要只运行 `TestGolden` 测试函数，可以执行：

```bash
go test -run TestGolden go/src/crypto/sha1/sha1_test.go
```

要运行所有的性能基准测试，可以执行：

```bash
go test -bench=. go/src/crypto/sha1/sha1_test.go
```

**使用者易犯错的点：**

一个潜在的易错点是在使用 `h.Sum(nil)` 方法时，如果传入的切片不是 `nil`，则会将当前的哈希值追加到该切片中，而不是创建一个新的切片。这可能会导致意想不到的结果，尤其是在循环中重复使用同一个切片时。

**错误示例：**

```go
package main

import (
	"crypto/sha1"
	"fmt"
)

func main() {
	dataList := [][]byte{
		[]byte("hello"),
		[]byte("world"),
	}

	var hashResult []byte
	h := sha1.New()

	for _, data := range dataList {
		h.Reset() // 每次循环前重置哈希对象
		h.Write(data)
		hashResult = h.Sum(hashResult) // 错误：hashResult 会不断追加
		fmt.Printf("Hash of '%s': %x\n", data, hashResult)
	}
}
```

在这个例子中，`hashResult` 会不断累积哈希值，而不是每次都只包含当前数据的哈希。

**正确用法：**

应该使用 `h.Sum(nil)` 来创建一个新的切片，或者在调用 `Sum` 之前将 `hashResult` 设置为空切片。

```go
package main

import (
	"crypto/sha1"
	"fmt"
)

func main() {
	dataList := [][]byte{
		[]byte("hello"),
		[]byte("world"),
	}

	h := sha1.New()

	for _, data := range dataList {
		h.Reset()
		h.Write(data)
		hashResult := h.Sum(nil) // 正确：创建新的切片
		fmt.Printf("Hash of '%s': %x\n", data, hashResult)
	}
}
```

或者：

```go
package main

import (
	"crypto/sha1"
	"fmt"
)

func main() {
	dataList := [][]byte{
		[]byte("hello"),
		[]byte("world"),
	}

	var hashResult []byte
	h := sha1.New()

	for _, data := range dataList {
		h.Reset()
		h.Write(data)
		hashResult = hashResult[:0] // 正确：将切片长度设为 0
		hashResult = h.Sum(hashResult)
		fmt.Printf("Hash of '%s': %x\n", data, hashResult)
	}
}
```

### 提示词
```
这是路径为go/src/crypto/sha1/sha1_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// SHA-1 hash algorithm. See RFC 3174.

package sha1

import (
	"bytes"
	"crypto/internal/boring"
	"crypto/internal/cryptotest"
	"crypto/rand"
	"encoding"
	"fmt"
	"hash"
	"io"
	"testing"
)

type sha1Test struct {
	out       string
	in        string
	halfState string // marshaled hash state after first half of in written, used by TestGoldenMarshal
}

var golden = []sha1Test{
	{"76245dbf96f661bd221046197ab8b9f063f11bad", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", "sha\x01\v\xa0)I\xdeq(8h\x9ev\xe5\x88[\xf8\x81\x17\xba4Daaaaaaaaaaaaaaaaaaaaaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x96"},
	{"da39a3ee5e6b4b0d3255bfef95601890afd80709", "", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
	{"86f7e437faa5a7fce15d1ddcb9eaeaea377667b8", "a", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
	{"da23614e02469a0d7c7bd1bdab5c9c474b1904dc", "ab", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"},
	{"a9993e364706816aba3e25717850c26c9cd0d89d", "abc", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"},
	{"81fe8bfe87576c3ecb22426f8e57847382917acf", "abcd", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0ab\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"},
	{"03de6c570bfe24bfc328ccd7ca46b76eadaf4334", "abcde", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0ab\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"},
	{"1f8ac10f23c5b5bc1167bda84b833e5c057a77d2", "abcdef", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0abc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03"},
	{"2fb5e13419fc89246865e7a324f476ec624e8740", "abcdefg", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0abc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03"},
	{"425af12a0743502b322e93a015bcf868e324d56a", "abcdefgh", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0abcd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04"},
	{"c63b19f1e4c8b5f76b25c49b8b87f57d8e4872a1", "abcdefghi", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0abcd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04"},
	{"d68c19a0a345b7eab78d5e11e991c026ec60db63", "abcdefghij", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0abcde\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05"},
	{"ebf81ddcbe5bf13aaabdc4d65354fdf2044f38a7", "Discard medicine more than two years old.", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0Discard medicine mor\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14"},
	{"e5dea09392dd886ca63531aaa00571dc07554bb6", "He who has a shady past knows that nice guys finish last.", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0He who has a shady past know\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c"},
	{"45988f7234467b94e3e9494434c96ee3609d8f8f", "I wouldn't marry him with a ten foot pole.", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0I wouldn't marry him \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x15"},
	{"55dee037eb7460d5a692d1ce11330b260e40c988", "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0Free! Free!/A trip/to Mars/f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c"},
	{"b7bc5fb91080c7de6b582ea281f8a396d7c0aee8", "The days of the digital watch are numbered.  -Tom Stoppard", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0The days of the digital watch\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1d"},
	{"c3aed9358f7c77f523afe86135f06b95b3999797", "Nepal premier won't resign.", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0Nepal premier\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\r"},
	{"6e29d302bf6e3a5e4305ff318d983197d6906bb9", "For every action there is an equal and opposite government program.", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0For every action there is an equa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!"},
	{"597f6a540010f94c15d71806a99a2c8710e747bd", "His money is twice tainted: 'taint yours and 'taint mine.", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0His money is twice tainted: \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c"},
	{"6859733b2590a8a091cecf50086febc5ceef1e80", "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0There is no reason for any individual to hav\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00,"},
	{"514b2630ec089b8aee18795fc0cf1f4860cdacad", "It's a tiny change to the code and not completely disgusting. - Bob Manchek", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0It's a tiny change to the code and no\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00%"},
	{"c5ca0d4a7b6676fc7aa72caa41cc3d5df567ed69", "size:  a.out:  bad magic", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0size:  a.out\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\f"},
	{"74c51fa9a04eadc8c1bbeaa7fc442f834b90a00a", "The major problem is with sendmail.  -Mark Horton", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0The major problem is wit\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18"},
	{"0b4c4ce5f52c3ad2821852a8dc00217fa18b8b66", "Give me a rock, paper and scissors and I will move the world.  CCFestoon", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0Give me a rock, paper and scissors a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$"},
	{"3ae7937dd790315beb0f48330e8642237c61550a", "If the enemy is within range, then so are you.", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0If the enemy is within \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x17"},
	{"410a2b296df92b9a47412b13281df8f830a9f44b", "It's well we cannot hear the screams/That we create in others' dreams.", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0It's well we cannot hear the scream\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00#"},
	{"841e7c85ca1adcddbdd0187f1289acb5c642f7f5", "You remind me of a TV show, but that's all right: I watch it anyway.", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0You remind me of a TV show, but th\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\""},
	{"163173b825d03b952601376b25212df66763e1db", "C is as portable as Stonehedge!!", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0C is as portable\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10"},
	{"32b0377f2687eb88e22106f133c586ab314d5279", "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0Even if I could be Shakespeare, I think I sh\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00,"},
	{"0885aaf99b569542fd165fa44e322718f4a984e0", "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule", "sha\x01x}\xf4\r\xeb\xf2\x10\x87\xe8[\xb2JA$D\xb7\u063ax8em\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00B"},
	{"6627d6904d71420b0bf3886ab629623538689f45", "How can you write a big system without C++?  -Paul Glick", "sha\x01gE#\x01\xef\u036b\x89\x98\xba\xdc\xfe\x102Tv\xc3\xd2\xe1\xf0How can you write a big syst\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c"},
}

func TestGolden(t *testing.T) {
	for i := 0; i < len(golden); i++ {
		g := golden[i]
		s := fmt.Sprintf("%x", Sum([]byte(g.in)))
		if s != g.out {
			t.Fatalf("Sum function: sha1(%s) = %s want %s", g.in, s, g.out)
		}
		c := New()
		for j := 0; j < 4; j++ {
			var sum []byte
			switch j {
			case 0, 1:
				io.WriteString(c, g.in)
				sum = c.Sum(nil)
			case 2:
				io.WriteString(c, g.in[:len(g.in)/2])
				c.Sum(nil)
				io.WriteString(c, g.in[len(g.in)/2:])
				sum = c.Sum(nil)
			case 3:
				if boring.Enabled {
					continue
				}
				io.WriteString(c, g.in[:len(g.in)/2])
				c.(*digest).ConstantTimeSum(nil)
				io.WriteString(c, g.in[len(g.in)/2:])
				sum = c.(*digest).ConstantTimeSum(nil)
			}
			s := fmt.Sprintf("%x", sum)
			if s != g.out {
				t.Fatalf("sha1[%d](%s) = %s want %s", j, g.in, s, g.out)
			}
			c.Reset()
		}
	}
}

func TestGoldenMarshal(t *testing.T) {
	h := New()
	h2 := New()
	for _, g := range golden {
		h.Reset()
		h2.Reset()

		io.WriteString(h, g.in[:len(g.in)/2])

		state, err := h.(encoding.BinaryMarshaler).MarshalBinary()
		if err != nil {
			t.Errorf("could not marshal: %v", err)
			continue
		}

		stateAppend, err := h.(encoding.BinaryAppender).AppendBinary(make([]byte, 4, 32))
		if err != nil {
			t.Errorf("could not marshal: %v", err)
			continue
		}
		stateAppend = stateAppend[4:]

		if string(state) != g.halfState {
			t.Errorf("sha1(%q) state = %+q, want %+q", g.in, state, g.halfState)
			continue
		}

		if string(stateAppend) != g.halfState {
			t.Errorf("sha1(%q) stateAppend = %+q, want %+q", g.in, stateAppend, g.halfState)
			continue
		}

		if err := h2.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
			t.Errorf("could not unmarshal: %v", err)
			continue
		}

		io.WriteString(h, g.in[len(g.in)/2:])
		io.WriteString(h2, g.in[len(g.in)/2:])

		if actual, actual2 := h.Sum(nil), h2.Sum(nil); !bytes.Equal(actual, actual2) {
			t.Errorf("sha1(%q) = 0x%x != marshaled 0x%x", g.in, actual, actual2)
		}
	}
}

func TestSize(t *testing.T) {
	c := New()
	if got := c.Size(); got != Size {
		t.Errorf("Size = %d; want %d", got, Size)
	}
}

func TestBlockSize(t *testing.T) {
	c := New()
	if got := c.BlockSize(); got != BlockSize {
		t.Errorf("BlockSize = %d; want %d", got, BlockSize)
	}
}

// Tests that blockGeneric (pure Go) and block (in assembly for some architectures) match.
func TestBlockGeneric(t *testing.T) {
	if boring.Enabled {
		t.Skip("BoringCrypto doesn't expose digest")
	}
	for i := 1; i < 30; i++ { // arbitrary factor
		gen, asm := New().(*digest), New().(*digest)
		buf := make([]byte, BlockSize*i)
		rand.Read(buf)
		blockGeneric(gen, buf)
		block(asm, buf)
		if *gen != *asm {
			t.Errorf("For %#v block and blockGeneric resulted in different states", buf)
		}
	}
}

// Tests for unmarshaling hashes that have hashed a large amount of data
// The initial hash generation is omitted from the test, because it takes a long time.
// The test contains some already-generated states, and their expected sums
// Tests a problem that is outlined in GitHub issue #29543
// The problem is triggered when an amount of data has been hashed for which
// the data length has a 1 in the 32nd bit. When casted to int, this changes
// the sign of the value, and causes the modulus operation to return a
// different result.
type unmarshalTest struct {
	state string
	sum   string
}

var largeUnmarshalTests = []unmarshalTest{
	// Data length: 7_102_415_735
	{
		state: "sha\x01\x13\xbc\xfe\x83\x8c\xbd\xdfP\x1f\xd8ڿ<\x9eji8t\xe1\xa5@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuv\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xa7VCw",
		sum:   "bc6245c9959cc33e1c2592e5c9ea9b5d0431246c",
	},
	// Data length: 6_565_544_823
	{
		state: "sha\x01m;\x16\xa6R\xbe@\xa9nĈ\xf9S\x03\x00B\xc2\xdcv\xcf@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuv\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x87VCw",
		sum:   "8f2d1c0e4271768f35feb918bfe21ea1387a2072",
	},
}

func safeSum(h hash.Hash) (sum []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("sum panic: %v", r)
		}
	}()

	return h.Sum(nil), nil
}

func TestLargeHashes(t *testing.T) {
	for i, test := range largeUnmarshalTests {

		h := New()
		if err := h.(encoding.BinaryUnmarshaler).UnmarshalBinary([]byte(test.state)); err != nil {
			t.Errorf("test %d could not unmarshal: %v", i, err)
			continue
		}

		sum, err := safeSum(h)
		if err != nil {
			t.Errorf("test %d could not sum: %v", i, err)
			continue
		}

		if fmt.Sprintf("%x", sum) != test.sum {
			t.Errorf("test %d sum mismatch: expect %s got %x", i, test.sum, sum)
		}
	}
}

func TestAllocations(t *testing.T) {
	cryptotest.SkipTestAllocations(t)
	in := []byte("hello, world!")
	out := make([]byte, 0, Size)
	h := New()
	n := int(testing.AllocsPerRun(10, func() {
		h.Reset()
		h.Write(in)
		out = h.Sum(out[:0])
	}))
	if n > 0 {
		t.Errorf("allocs = %d, want 0", n)
	}
}

func TestSHA1Hash(t *testing.T) {
	cryptotest.TestHash(t, New)
}

var bench = New()
var buf = make([]byte, 8192)

func benchmarkSize(b *testing.B, size int) {
	sum := make([]byte, bench.Size())
	b.Run("New", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(size))
		for i := 0; i < b.N; i++ {
			bench.Reset()
			bench.Write(buf[:size])
			bench.Sum(sum[:0])
		}
	})
	b.Run("Sum", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(size))
		for i := 0; i < b.N; i++ {
			Sum(buf[:size])
		}
	})
}

func BenchmarkHash8Bytes(b *testing.B) {
	benchmarkSize(b, 8)
}

func BenchmarkHash320Bytes(b *testing.B) {
	benchmarkSize(b, 320)
}

func BenchmarkHash1K(b *testing.B) {
	benchmarkSize(b, 1024)
}

func BenchmarkHash8K(b *testing.B) {
	benchmarkSize(b, 8192)
}
```