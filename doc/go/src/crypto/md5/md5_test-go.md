Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Identify the Core Purpose:** The file path `go/src/crypto/md5/md5_test.go` immediately suggests this is a test file for the `md5` package in Go's standard library. Test files in Go typically have the suffix `_test.go`.

2. **Scan Imports:** Look at the `import` statements. These give clues about the functionalities being tested:
    * `"bytes"`: Likely used for comparing byte slices, common in hashing.
    * `"crypto/internal/cryptotest"`: Indicates internal testing utilities for cryptographic functions.
    * `"crypto/rand"`: Suggests testing with random data.
    * `"encoding"`: Points to testing encoding/decoding, specifically `BinaryMarshaler` and `BinaryUnmarshaler`.
    * `"fmt"`:  Used for formatting output, particularly with `%x` for hexadecimal representation of hashes.
    * `"hash"`:  Confirms that `md5` implements the `hash.Hash` interface.
    * `"io"`:  Implies testing input/output operations with the hash function (like `WriteString`).
    * `"testing"`: The standard Go testing package, crucial for writing unit tests and benchmarks.
    * `"unsafe"`:  Hints at low-level operations, possibly for performance testing or memory manipulation.

3. **Analyze Top-Level Declarations:** Examine the global variables and types:
    * `md5Test` struct:  Clearly a structure for defining test cases. It holds the expected MD5 hash (`out`), the input string (`in`), and an intermediate state (`halfState`). This suggests testing the state persistence of the hash.
    * `golden` slice: A slice of `md5Test` structs. This is a common pattern for "golden tests" – comparing the output of the function against known correct outputs for various inputs.

4. **Dissect Individual Test Functions:** Go through each function starting with `Test...` and `Benchmark...`:
    * `TestGolden`:  This function iterates through the `golden` test cases. It uses `Sum` (a convenience function for computing the MD5 of a byte slice) and the `New()` constructor to create a `hash.Hash`. It tests `WriteString` and `Write` methods, including writing in chunks and handling potential unaligned writes. The core idea is to verify that the MD5 implementation produces the correct output for a set of known inputs.
    * `TestGoldenMarshal`:  This function focuses on the `encoding.BinaryMarshaler` and `encoding.BinaryUnmarshaler` interfaces. It tests the ability to serialize and deserialize the internal state of the MD5 hash. This is important for scenarios where you need to pause and resume hash computations.
    * `TestLarge`: This test aims to evaluate the performance and correctness of the MD5 implementation with large inputs. It writes a large block of data and calculates the MD5. The multiple loops with varying `blockSize` indicate stress testing with different chunk sizes. The `offset` loop suggests testing the handling of data that isn't aligned to block boundaries.
    * `TestBlockGeneric`: This test seems to be comparing the performance or correctness of a generic Go implementation (`blockGeneric`) against an architecture-specific (likely assembly-optimized) implementation (`block`).
    * `TestLargeHashes`: This test addresses a specific issue related to handling very large input sizes where the length overflows a signed 32-bit integer. It checks if unmarshaling a state after hashing very large data still leads to the correct final hash. The `safeSum` function is a defensive measure against potential panics during `Sum`.
    * `TestAllocations`: Uses `cryptotest.SkipTestAllocations` and `testing.AllocsPerRun` to check if the MD5 hashing process allocates any memory during its execution. This is a performance-oriented test.
    * `TestMD5Hash`:  This leverages the `cryptotest` package to run a suite of standard hash function tests against the `md5.New` constructor.
    * `BenchmarkHash...`: These functions are benchmarks for measuring the performance of the MD5 hash function for various input sizes. The `Unaligned` versions likely test performance when the input buffer isn't memory-aligned.

5. **Synthesize Functionality and Purpose:** Based on the analysis of individual components, formulate a concise description of the file's functionality. It tests the core MD5 hashing algorithm, its ability to handle various input sizes and alignments, its state serialization/deserialization, and its performance.

6. **Identify Key Go Features:** Connect the test code to specific Go language features being tested. This involves looking for patterns like:
    * Implementing interfaces (`hash.Hash`, `encoding.BinaryMarshaler`, `encoding.BinaryUnmarshaler`).
    * Using structs to represent data and test cases.
    * Using slices for test data and buffers.
    * Using the `testing` package for unit tests and benchmarks.
    * Using `fmt.Sprintf` for output formatting.
    * Using `io.WriteString` and `hash.Write` for data input.
    * Using `bytes.Equal` for comparing results.

7. **Develop Code Examples:** Create illustrative code snippets demonstrating the key functionalities being tested, like basic hashing, state serialization, and handling large inputs. Choose simple, clear examples.

8. **Infer Command-Line Arguments (If Applicable):**  In this specific case, the code doesn't directly process command-line arguments. However, because it's a test file, explain how Go tests are typically run (using `go test`).

9. **Identify Potential Pitfalls:**  Think about common mistakes developers might make when using the MD5 package based on the tests being performed. For example, forgetting to `Reset()` the hash, assuming the output is always a string without formatting, or misunderstanding how to serialize/deserialize the hash state.

10. **Structure the Answer:** Organize the findings into a clear and logical structure, addressing each part of the original prompt. Use headings and bullet points for better readability. Ensure the language is clear and concise.
这段代码是 Go 语言标准库中 `crypto/md5` 包的测试文件 `md5_test.go` 的一部分。它的主要功能是：

**1. 测试 MD5 哈希算法的正确性:**

   - **Golden Tests:**  通过 `golden` 变量定义了一系列预设的输入字符串 (`in`) 和其对应的 MD5 哈希值 (`out`)。`TestGolden` 函数会针对这些预设的输入，计算 MD5 哈希值，并与预设值进行比较，以验证 `Sum` 函数和 `hash.Hash` 接口的实现是否正确。
   - **分段写入测试:** `TestGolden` 中，除了直接使用 `Sum` 计算完整输入的哈希外，还测试了分段写入数据到 `hash.Hash` 对象 (`c`) 的情况，包括写入两次完整输入、写入前半部分和后半部分、以及测试非对齐写入。这验证了 MD5 算法在处理不同写入方式时的正确性。

   **Go 代码示例:**

   ```go
   package main

   import (
       "crypto/md5"
       "fmt"
   )

   func main() {
       input := "hello"
       expectedHash := "5d41402abc4b2a76b9719d911017c592"

       // 使用 Sum 函数计算 MD5
       hashBytes := md5.Sum([]byte(input))
       hashString := fmt.Sprintf("%x", hashBytes)
       fmt.Printf("Input: %s, MD5 Hash (Sum): %s\n", input, hashString)

       // 使用 hash.Hash 接口计算 MD5
       h := md5.New()
       h.Write([]byte(input))
       hashBytes2 := h.Sum(nil)
       hashString2 := fmt.Sprintf("%x", hashBytes2)
       fmt.Printf("Input: %s, MD5 Hash (Hash interface): %s\n", input, hashString2)

       // 假设的输入与输出
       // Input: hello, MD5 Hash (Sum): 5d41402abc4b2a76b9719d911017c592
       // Input: hello, MD5 Hash (Hash interface): 5d41402abc4b2a76b9719d911017c592

       if hashString == expectedHash && hashString2 == expectedHash {
           fmt.Println("MD5 calculation is correct!")
       } else {
           fmt.Println("MD5 calculation is incorrect!")
       }
   }
   ```

**2. 测试 MD5 哈希状态的序列化和反序列化:**

   - **`TestGoldenMarshal` 函数:**  这个函数测试了 `md5.digest` 类型（MD5 哈希的内部实现）是否正确实现了 `encoding.BinaryMarshaler` 和 `encoding.BinaryUnmarshaler` 接口。这意味着可以把一个计算到一半的 MD5 哈希的状态保存下来（序列化），然后在稍后恢复这个状态继续计算（反序列化）。
   - **`halfState` 字段:** `golden` 结构体中的 `halfState` 字段存储了在写入输入字符串的前半部分后，MD5 哈希对象的内部状态序列化后的结果。`TestGoldenMarshal` 会验证序列化和反序列化的过程是否正确。

   **Go 代码示例:**

   ```go
   package main

   import (
       "bytes"
       "crypto/md5"
       "encoding/hex"
       "fmt"
       "io"
       "log"
   )

   func main() {
       input := "abcdefg"
       halfInput := input[:len(input)/2]
       restInput := input[len(input)/2:]

       // 创建一个 MD5 hash 对象并写入前半部分数据
       h1 := md5.New()
       io.WriteString(h1, halfInput)

       // 序列化当前状态
       marshaler, ok := h1.(interface{ MarshalBinary() ([]byte, error) })
       if !ok {
           log.Fatal("MD5 does not implement BinaryMarshaler")
       }
       state, err := marshaler.MarshalBinary()
       if err != nil {
           log.Fatalf("Error marshaling state: %v", err)
       }
       fmt.Printf("Serialized state: %s\n", hex.EncodeToString(state))

       // 创建一个新的 MD5 hash 对象并反序列化之前的状态
       h2 := md5.New()
       unmarshaler, ok := h2.(interface{ UnmarshalBinary([]byte) error })
       if !ok {
           log.Fatal("MD5 does not implement BinaryUnmarshaler")
       }
       err = unmarshaler.UnmarshalBinary(state)
       if err != nil {
           log.Fatalf("Error unmarshaling state: %v", err)
       }

       // 分别写入剩余部分数据并计算最终哈希
       io.WriteString(h1, restInput)
       hash1 := h1.Sum(nil)

       io.WriteString(h2, restInput)
       hash2 := h2.Sum(nil)

       fmt.Printf("Hash 1: %s\n", hex.EncodeToString(hash1))
       fmt.Printf("Hash 2: %s\n", hex.EncodeToString(hash2))

       // 假设的输入与输出 (基于 "abcdefg" 这个 golden 测试用例)
       // Serialized state: 6d64350167452301efcbab8998badcfe103254766162630000000000000000000000000000000000000000000000000000000000000000000000000000000003
       // Hash 1: 7ac66c0f148de9519b8bd264312c4d64
       // Hash 2: 7ac66c0f148de9519b8bd264312c4d64

       if bytes.Equal(hash1, hash2) {
           fmt.Println("Serialization and deserialization work correctly!")
       } else {
           fmt.Println("Serialization and deserialization do not work correctly!")
       }
   }
   ```

**3. 测试处理大数据量的能力:**

   - **`TestLarge` 函数:** 这个函数测试了当输入数据量很大时，MD5 哈希算法是否还能正常工作并产生正确的哈希值。它循环写入不同大小的数据块，并与预期的哈希值进行比较。

   **Go 代码示例 (简化版):**

   ```go
   package main

   import (
       "crypto/md5"
       "fmt"
   )

   func main() {
       largeInput := make([]byte, 10000)
       for i := 0; i < len(largeInput); i++ {
           largeInput[i] = byte('0' + i%10)
       }

       expectedHash := "2bb571599a4180e1d542f76904adc3df" // 预先计算好的哈希值

       h := md5.New()
       h.Write(largeInput)
       hashBytes := h.Sum(nil)
       hashString := fmt.Sprintf("%x", hashBytes)

       fmt.Printf("MD5 Hash of large input: %s\n", hashString)

       // 假设的输出
       // MD5 Hash of large input: 2bb571599a4180e1d542f76904adc3df

       if hashString == expectedHash {
           fmt.Println("Handling large input works correctly!")
       } else {
           fmt.Println("Error handling large input!")
       }
   }
   ```

**4. 比较 Go 语言实现和汇编实现的性能 (和正确性):**

   - **`TestBlockGeneric` 函数:** 这个函数比较了 `blockGeneric` 函数（纯 Go 语言实现的 MD5 核心处理逻辑）和 `block` 函数（可能是针对特定架构优化的汇编实现）在处理同一块数据后产生的内部状态是否一致。这可以用来验证汇编实现的正确性，并间接比较两者的性能。

**5. 测试处理超大数据量的哈希状态反序列化:**

   - **`TestLargeHashes` 函数:**  这个函数特别测试了当已经哈希了非常大的数据量（以至于数据长度的某些位会溢出）后，能否正确地反序列化 MD5 哈希的状态。这主要是为了解决一个特定的 bug (GitHub issue #29541)。

**6. 测试内存分配情况:**

   - **`TestAllocations` 函数:** 使用 `testing.AllocsPerRun` 来检查在进行 MD5 哈希计算时是否发生了不必要的内存分配。这通常用于性能优化，确保哈希计算尽可能高效。

**7. 基准测试 (Benchmark):**

   - **`BenchmarkHash...` 函数:** 这些函数用于测量 MD5 哈希算法在处理不同大小的数据时的性能。`benchmarkSize` 函数是一个通用的基准测试函数，可以测试不同大小的输入，并且可以模拟非对齐的内存访问 (`unaligned` 参数)。

**关于命令行参数的具体处理:**

这段代码本身是测试代码，并不直接处理命令行参数。但是，你可以使用 Go 的测试工具 `go test` 来运行这些测试。

* **运行所有测试:**  在 `go/src/crypto/md5/` 目录下执行 `go test` 命令。
* **运行特定的测试函数:** 例如，运行 `TestGolden` 函数，可以执行 `go test -run TestGolden`。
* **运行基准测试:** 例如，运行所有的基准测试，可以执行 `go test -bench=.`。 运行特定的基准测试，例如 `BenchmarkHash8Bytes`，可以执行 `go test -bench=BenchmarkHash8Bytes`。

**使用者易犯错的点 (可以从测试代码中推断出来):**

1. **忘记 `Reset()` 哈希对象:** 在多次使用同一个 `hash.Hash` 对象进行哈希计算时，必须在每次新的计算开始前调用 `Reset()` 方法，否则会继续之前的状态进行计算，导致结果错误。`TestGolden` 函数中的循环就体现了这一点。

   ```go
   h := md5.New()
   h.Write([]byte("hello"))
   hash1 := fmt.Sprintf("%x", h.Sum(nil))

   // 错误的做法：没有 Reset
   h.Write([]byte("world"))
   hash2_wrong := fmt.Sprintf("%x", h.Sum(nil)) // 结果会是 "helloworld" 的哈希

   // 正确的做法：使用 Reset
   h.Reset()
   h.Write([]byte("world"))
   hash2_correct := fmt.Sprintf("%x", h.Sum(nil))

   fmt.Println(hash1)
   fmt.Println(hash2_wrong)
   fmt.Println(hash2_correct)
   ```

2. **不理解哈希状态的序列化和反序列化:**  不理解 `MarshalBinary` 和 `UnmarshalBinary` 的作用，可能导致在需要保存和恢复哈希计算状态的场景下出现问题。

3. **对大数据量的处理不当:**  虽然 MD5 算法可以处理大数据量，但如果一次性将所有数据加载到内存中进行哈希，可能会导致内存消耗过高。应该使用 `Write` 方法分块处理数据，就像 `TestLarge` 函数所演示的那样。

总而言之，这段测试代码覆盖了 `crypto/md5` 包的核心功能，并通过各种测试用例确保了 MD5 哈希算法在不同场景下的正确性和性能。它可以帮助我们理解如何正确地使用 `crypto/md5` 包，并避免一些常见的错误。

### 提示词
```
这是路径为go/src/crypto/md5/md5_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package md5

import (
	"bytes"
	"crypto/internal/cryptotest"
	"crypto/rand"
	"encoding"
	"fmt"
	"hash"
	"io"
	"testing"
	"unsafe"
)

type md5Test struct {
	out       string
	in        string
	halfState string // marshaled hash state after first half of in written, used by TestGoldenMarshal
}

var golden = []md5Test{
	{"d41d8cd98f00b204e9800998ecf8427e", "", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102Tv\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
	{"0cc175b9c0f1b6a831c399e269772661", "a", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102Tv\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"},
	{"187ef4436122d1cc2f40dc2b92f0eba0", "ab", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102Tva\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"},
	{"900150983cd24fb0d6963f7d28e17f72", "abc", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102Tva\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"},
	{"e2fc714c4727ee9395f324cd2e7f331f", "abcd", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102Tvab\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"},
	{"ab56b4d92b40713acc5af89985d4b786", "abcde", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102Tvab\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"},
	{"e80b5017098950fc58aad83c8c14978e", "abcdef", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102Tvabc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03"},
	{"7ac66c0f148de9519b8bd264312c4d64", "abcdefg", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102Tvabc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03"},
	{"e8dc4081b13434b45189a720b77b6818", "abcdefgh", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102Tvabcd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04"},
	{"8aa99b1f439ff71293e95357bac6fd94", "abcdefghi", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102Tvabcd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04"},
	{"a925576942e94b2ef57a066101b48876", "abcdefghij", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102Tvabcde\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05"},
	{"d747fc1719c7eacb84058196cfe56d57", "Discard medicine more than two years old.", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102TvDiscard medicine mor\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14"},
	{"bff2dcb37ef3a44ba43ab144768ca837", "He who has a shady past knows that nice guys finish last.", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102TvHe who has a shady past know\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c"},
	{"0441015ecb54a7342d017ed1bcfdbea5", "I wouldn't marry him with a ten foot pole.", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102TvI wouldn't marry him \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x15"},
	{"9e3cac8e9e9757a60c3ea391130d3689", "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102TvFree! Free!/A trip/to Mars/f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c"},
	{"a0f04459b031f916a59a35cc482dc039", "The days of the digital watch are numbered.  -Tom Stoppard", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102TvThe days of the digital watch\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1d"},
	{"e7a48e0fe884faf31475d2a04b1362cc", "Nepal premier won't resign.", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102TvNepal premier\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\r"},
	{"637d2fe925c07c113800509964fb0e06", "For every action there is an equal and opposite government program.", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102TvFor every action there is an equa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!"},
	{"834a8d18d5c6562119cf4c7f5086cb71", "His money is twice tainted: 'taint yours and 'taint mine.", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102TvHis money is twice tainted: \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c"},
	{"de3a4d2fd6c73ec2db2abad23b444281", "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102TvThere is no reason for any individual to hav\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00,"},
	{"acf203f997e2cf74ea3aff86985aefaf", "It's a tiny change to the code and not completely disgusting. - Bob Manchek", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102TvIt's a tiny change to the code and no\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00%"},
	{"e1c1384cb4d2221dfdd7c795a4222c9a", "size:  a.out:  bad magic", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102Tvsize:  a.out\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\f"},
	{"c90f3ddecc54f34228c063d7525bf644", "The major problem is with sendmail.  -Mark Horton", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102TvThe major problem is wit\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18"},
	{"cdf7ab6c1fd49bd9933c43f3ea5af185", "Give me a rock, paper and scissors and I will move the world.  CCFestoon", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102TvGive me a rock, paper and scissors a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$"},
	{"83bc85234942fc883c063cbd7f0ad5d0", "If the enemy is within range, then so are you.", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102TvIf the enemy is within \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x17"},
	{"277cbe255686b48dd7e8f389394d9299", "It's well we cannot hear the screams/That we create in others' dreams.", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102TvIt's well we cannot hear the scream\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00#"},
	{"fd3fb0a7ffb8af16603f3d3af98f8e1f", "You remind me of a TV show, but that's all right: I watch it anyway.", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102TvYou remind me of a TV show, but th\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\""},
	{"469b13a78ebf297ecda64d4723655154", "C is as portable as Stonehedge!!", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102TvC is as portable\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10"},
	{"63eb3a2f466410104731c4b037600110", "Even if I could be Shakespeare, I think I should still choose to be Faraday. - A. Huxley", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102TvEven if I could be Shakespeare, I think I sh\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00,"},
	{"72c2ed7592debca1c90fc0100f931a2f", "The fugacity of a constituent in a mixture of gases at a given temperature is proportional to its mole fraction.  Lewis-Randall Rule", "md5\x01\xa7\xc9\x18\x9b\xc3E\x18\xf2\x82\xfd\xf3$\x9d_\v\nem\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00B"},
	{"132f7619d33b523b1d9e5bd8e0928355", "How can you write a big system without C++?  -Paul Glick", "md5\x01gE#\x01\xefͫ\x89\x98\xba\xdc\xfe\x102TvHow can you write a big syst\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c"},
}

func TestGolden(t *testing.T) {
	for i := 0; i < len(golden); i++ {
		g := golden[i]
		s := fmt.Sprintf("%x", Sum([]byte(g.in)))
		if s != g.out {
			t.Fatalf("Sum function: md5(%s) = %s want %s", g.in, s, g.out)
		}
		c := New()
		buf := make([]byte, len(g.in)+4)
		for j := 0; j < 3+4; j++ {
			if j < 2 {
				io.WriteString(c, g.in)
			} else if j == 2 {
				io.WriteString(c, g.in[:len(g.in)/2])
				c.Sum(nil)
				io.WriteString(c, g.in[len(g.in)/2:])
			} else if j > 2 {
				// test unaligned write
				buf = buf[1:]
				copy(buf, g.in)
				c.Write(buf[:len(g.in)])
			}
			s := fmt.Sprintf("%x", c.Sum(nil))
			if s != g.out {
				t.Fatalf("md5[%d](%s) = %s want %s", j, g.in, s, g.out)
			}
			c.Reset()
		}
	}
}

func TestGoldenMarshal(t *testing.T) {
	for _, g := range golden {
		h := New()
		h2 := New()

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
			t.Errorf("md5(%q) state = %q, want %q", g.in, state, g.halfState)
			continue
		}

		if string(stateAppend) != g.halfState {
			t.Errorf("md5(%q) stateAppend = %q, want %q", g.in, stateAppend, g.halfState)
			continue
		}

		if err := h2.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
			t.Errorf("could not unmarshal: %v", err)
			continue
		}

		io.WriteString(h, g.in[len(g.in)/2:])
		io.WriteString(h2, g.in[len(g.in)/2:])

		if actual, actual2 := h.Sum(nil), h2.Sum(nil); !bytes.Equal(actual, actual2) {
			t.Errorf("md5(%q) = 0x%x != marshaled 0x%x", g.in, actual, actual2)
		}
	}
}

func TestLarge(t *testing.T) {
	const N = 10000
	ok := "2bb571599a4180e1d542f76904adc3df" // md5sum of "0123456789" * 1000
	block := make([]byte, 10004)
	c := New()
	for offset := 0; offset < 4; offset++ {
		for i := 0; i < N; i++ {
			block[offset+i] = '0' + byte(i%10)
		}
		for blockSize := 10; blockSize <= N; blockSize *= 10 {
			blocks := N / blockSize
			b := block[offset : offset+blockSize]
			c.Reset()
			for i := 0; i < blocks; i++ {
				c.Write(b)
			}
			s := fmt.Sprintf("%x", c.Sum(nil))
			if s != ok {
				t.Fatalf("md5 TestLarge offset=%d, blockSize=%d = %s want %s", offset, blockSize, s, ok)
			}
		}
	}
}

// Tests that blockGeneric (pure Go) and block (in assembly for amd64, 386, arm) match.
func TestBlockGeneric(t *testing.T) {
	gen, asm := New().(*digest), New().(*digest)
	buf := make([]byte, BlockSize*20) // arbitrary factor
	rand.Read(buf)
	blockGeneric(gen, buf)
	block(asm, buf)
	if *gen != *asm {
		t.Error("block and blockGeneric resulted in different states")
	}
}

// Tests for unmarshaling hashes that have hashed a large amount of data
// The initial hash generation is omitted from the test, because it takes a long time.
// The test contains some already-generated states, and their expected sums
// Tests a problem that is outlined in GitHub issue #29541
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
		state: "md5\x01\xa5\xf7\xf0=\xd6S\x85\xd9M\n}\xc3\u0601\x89\xe7@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuv\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xa7VCw",
		sum:   "cddefcf74ffec709a0b45a6a987564d5",
	},
	// Data length: 6_565_544_823
	{
		state: "md5\x01{\xda\x1a\xc7\xc9'?\x83EX\xe0\x88q\xfeG\x18@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuv\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x87VCw",
		sum:   "fd9f41874ab240698e7bc9c3ae70c8e4",
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

func TestMD5Hash(t *testing.T) {
	cryptotest.TestHash(t, New)
}

var bench = New()
var buf = make([]byte, 1024*1024*8+1)
var sum = make([]byte, bench.Size())

func benchmarkSize(b *testing.B, size int, unaligned bool) {
	b.SetBytes(int64(size))
	buf := buf
	if unaligned {
		if uintptr(unsafe.Pointer(&buf[0]))&(unsafe.Alignof(uint32(0))-1) == 0 {
			buf = buf[1:]
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bench.Reset()
		bench.Write(buf[:size])
		bench.Sum(sum[:0])
	}
}

func BenchmarkHash8Bytes(b *testing.B) {
	benchmarkSize(b, 8, false)
}

func BenchmarkHash64(b *testing.B) {
	benchmarkSize(b, 64, false)
}

func BenchmarkHash128(b *testing.B) {
	benchmarkSize(b, 128, false)
}

func BenchmarkHash256(b *testing.B) {
	benchmarkSize(b, 256, false)
}

func BenchmarkHash512(b *testing.B) {
	benchmarkSize(b, 512, false)
}

func BenchmarkHash1K(b *testing.B) {
	benchmarkSize(b, 1024, false)
}

func BenchmarkHash8K(b *testing.B) {
	benchmarkSize(b, 8192, false)
}

func BenchmarkHash1M(b *testing.B) {
	benchmarkSize(b, 1024*1024, false)
}

func BenchmarkHash8M(b *testing.B) {
	benchmarkSize(b, 8*1024*1024, false)
}

func BenchmarkHash8BytesUnaligned(b *testing.B) {
	benchmarkSize(b, 8, true)
}

func BenchmarkHash1KUnaligned(b *testing.B) {
	benchmarkSize(b, 1024, true)
}

func BenchmarkHash8KUnaligned(b *testing.B) {
	benchmarkSize(b, 8192, true)
}
```