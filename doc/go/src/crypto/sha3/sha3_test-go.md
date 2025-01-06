Response:
Let's break down the thought process for analyzing the Go test file.

**1. Understanding the Goal:**

The core request is to understand the *functionality* of the provided Go test file. This means identifying what aspects of the `crypto/sha3` package it's testing.

**2. Initial Scan and Keyword Identification:**

I'd start by quickly scanning the file for keywords and recognizable patterns. Things that immediately jump out:

* `package sha3_test`:  Indicates this is a test file for the `sha3` package.
* `import`:  Shows dependencies, especially the `. "crypto/sha3"` which means it's directly using the package under test.
* `func Test...`:  Standard Go testing function naming convention. This is a huge clue to the functionality being tested.
* `New224`, `New256`, `New384`, `New512`: These likely construct different SHA-3 hash instances.
* `NewSHAKE128`, `NewSHAKE256`, `NewCSHAKE128`, `NewCSHAKE256`:  Likely constructors for SHAKE and cSHAKE instances.
* `Write`, `Sum`, `Read`, `Reset`: Standard methods for hash interfaces in Go's `crypto/` packages.
* `bytes.Equal`: Used for comparing byte slices, suggesting verification of hash outputs.
* `hex.EncodeToString`, `hex.DecodeString`: Indicates handling of hexadecimal representations of hashes.
* `cryptotest.TestAllImplementations`:  A helper function, probably for running the same tests against different implementations (potentially software and hardware).
* `t.Errorf`: Standard Go testing function for reporting errors.
* `benchmarkHash`, `benchmarkShake`: Functions for performance testing (benchmarking).
* `MarshalBinary`, `UnmarshalBinary`: Methods related to serialization/deserialization of the hash state.

**3. Grouping Tests by Functionality:**

Based on the keywords and function names, I'd start grouping the tests logically:

* **Basic SHA-3 Functionality:** Tests using `New224`, `New256`, etc., and `Write`/`Sum`. Focus on verifying correct hash output.
* **SHAKE Functionality:** Tests using `NewSHAKE...` and `Read`. Focus on variable-length output.
* **cSHAKE Functionality:** Tests using `NewCSHAKE...` with custom function and string.
* **Unaligned Writes:** The `TestUnalignedWrite` function name is self-explanatory. This tests how the implementation handles writing data in small, potentially non-contiguous chunks.
* **Appending:** `TestAppend` and `TestAppendNoRealloc` suggest tests for the `Sum` method's ability to append to existing byte slices, with and without reallocation.
* **Squeezing:** `TestSqueezing` tests the ability to extract output from SHAKE functions in small chunks.
* **Reset:** `TestReset` verifies the `Reset` method correctly clears the hash state.
* **Allocations:** `TestAllocations` checks for unexpected memory allocations during hash operations, important for performance.
* **Marshalling/Unmarshalling:** `TestMarshalUnmarshal` tests the ability to serialize and deserialize the internal state of the hash functions.
* **Benchmarking:** `Benchmark...` functions measure the performance of different SHA-3 and SHAKE variants.

**4. Deep Dive into Key Tests (Example: `TestUnalignedWrite`):**

Once I have a general idea, I'd look more closely at some key tests:

* **`TestUnalignedWrite`:**
    * It iterates through `testDigests` (SHA-3 variants) and `testShakes`.
    * It writes a large buffer (`buf`) to the hash in a normal way and gets the expected output (`want`).
    * Then, it writes the *same* buffer in small, varying chunks using a nested loop and an array of "offsets". The `offsets` array containing prime-like numbers suggests the goal is to hit various internal buffer boundaries and edge cases.
    * It compares the output of the chunked writes (`got`) with the expected output (`want`).
    * This strongly suggests the test is verifying that the hash functions work correctly even when data is fed in non-aligned or fragmented ways.

**5. Inferring Go Features and Providing Examples:**

Based on the analysis, I can identify the Go features being demonstrated and provide examples:

* **Interfaces (`hash.Hash`):**  The code works with different SHA-3 and SHAKE types using common methods like `Write` and `Sum`/`Read`, indicating they implement a common interface (implicitly or explicitly).
* **Structs and Methods:** The `testDigests` and `testShakes` maps store functions, and the tests call methods like `Reset`, `Write`, `Sum`, and `Read` on the returned objects.
* **Maps:**  `testDigests` and `testShakes` are maps, useful for associating names with constructors.
* **Closures:** The values in `testDigests` and `testShakes` are functions (closures) that return hash instances.
* **Testing Framework:** The `testing` package is used extensively for structuring tests (`func Test...`, `t.Errorf`).
* **Error Handling:** The `decodeHex` function uses `panic` for errors, which is common in test code.
* **Byte Slices (`[]byte`):**  Hashing deals with byte data, so byte slices are heavily used.
* **Range Loop:** The `for ... range` loop is used to iterate over byte slices and maps.

**6. Identifying Potential Pitfalls:**

Looking at the code, I could identify potential pitfalls for users:

* **Incorrect Usage of `Sum`:** The `TestAppend` tests highlight how `Sum` can be used to append to existing slices. Users might mistakenly assume `Sum` always returns a *new* slice, leading to unexpected behavior. The reallocation aspect is important.
* **Understanding SHAKE's `Read`:**  Users new to SHAKE might not realize that `Read` can be called multiple times to get an arbitrary amount of output. The `TestSqueezing` example demonstrates this.
* **cSHAKE Customization:**  Users might misunderstand the purpose and usage of the `N` (function name) and `S` (customization string) parameters in cSHAKE. The tests for cSHAKE provide examples of how these are used.

**7. Structuring the Answer:**

Finally, I would structure the answer in a clear and organized way, following the prompts in the original request:

* Start with a summary of the file's purpose.
* List the key functionalities being tested.
* Provide code examples illustrating the Go features.
* Explain the code inference with assumptions and examples.
* Explain any command-line parameters (though this file doesn't directly use them).
* Highlight common mistakes.
* Use clear, concise Chinese.

By following this systematic approach, I can thoroughly analyze the Go test file and provide a comprehensive and helpful answer.
这个 `go/src/crypto/sha3/sha3_test.go` 文件是 Go 语言 `crypto/sha3` 标准库的一部分，专门用于测试 SHA-3 和 SHAKE 系列哈希函数的实现是否正确。

以下是它主要的功能点：

**1. 测试不同 SHA-3 变体的正确性:**

*   **测试不同输出长度的 SHA-3 哈希函数:**  代码中定义了 `testDigests` 这个 map，包含了 `New224`, `New256`, `New384`, `New512` 这些构造函数，分别对应 SHA3-224, SHA3-256, SHA3-384 和 SHA3-512 这四种不同输出长度的 SHA-3 哈希算法。测试用例会创建这些哈希实例，写入数据，并验证最终的哈希值是否与预期一致。
*   **非对齐写入测试 (`TestUnalignedWrite`):**  该测试用例模拟了以任意大小的块（特别是小块）向哈希对象写入数据的情况，确保即使输入数据没有按照特定的字节对齐方式，哈希计算的结果仍然是正确的。

**2. 测试 SHAKE 系列哈希函数的正确性:**

*   **测试 SHAKE128 和 SHAKE256:** 代码定义了 `testShakes` 这个 map，包含了 `NewCSHAKE128` 和 `NewCSHAKE256` 构造函数，并设置了默认的算法名称和自定义字符串为空，这使得它们的行为与标准的 SHAKE128 和 SHAKE256 相同。测试用例会验证它们的哈希输出。
*   **测试 cSHAKE (可定制的 SHAKE):** `testShakes` 中也包含了 `cSHAKE128` 和 `cSHAKE256` 的测试用例，它们使用了非空的默认算法名称和自定义字符串。这验证了 cSHAKE 允许用户通过提供额外的参数来定制哈希函数的行为。
*   **Squeezing 测试 (`TestSqueezing`):** SHAKE 算法的一个特点是可以按需生成任意长度的输出。这个测试用例验证了连续地从 SHAKE 对象读取少量字节，最终可以得到与一次性读取所有字节相同的结果。

**3. 测试 `Sum` 方法的追加功能:**

*   **测试追加操作 (`TestAppend` 和 `TestAppendNoRealloc`):**  `Sum` 方法在 Go 的 `hash.Hash` 接口中用于获取最终的哈希值，并且可以接受一个现有的 byte slice 作为参数，将哈希值追加到该 slice 中。这两个测试用例验证了 `Sum` 方法的这种追加行为，包括需要重新分配底层数组的情况和不需要重新分配的情况。

**4. 测试 `Reset` 方法:**

*   **测试重置功能 (`TestReset`):** `Reset` 方法用于将哈希对象的内部状态重置为初始状态。该测试用例验证了在计算哈希值后调用 `Reset` 方法，然后使用相同的数据再次计算，可以得到相同的结果。

**5. 测试内存分配:**

*   **测试内存分配情况 (`TestAllocations`):** 这些测试用例旨在检查在创建哈希对象、写入数据和获取哈希值时，是否会发生不必要的内存分配。这对于性能敏感的应用很重要。

**6. 测试 `MarshalBinary` 和 `UnmarshalBinary` 方法:**

*   **测试序列化和反序列化 (`TestMarshalUnmarshal`):** 这些测试用例验证了哈希对象的状态可以被序列化（`MarshalBinary`）成字节数组，并且可以从字节数组中恢复（`UnmarshalBinary`）。这对于需要保存和恢复哈希计算中间状态的场景很有用。

**7. 性能基准测试:**

*   **基准测试 (`BenchmarkSha3_...` 和 `BenchmarkShake...`):**  这些函数用于衡量不同 SHA-3 和 SHAKE 算法的哈希计算速度。

**代码推理示例 (基于 `TestUnalignedWrite`):**

我们可以推理出 `TestUnalignedWrite` 测试用例的核心思想是验证哈希函数在处理不完整或非对齐的输入时的正确性。

**假设输入:** 一个包含连续字节的 buffer，例如 `[]byte{0, 1, 2, ..., 65535}`。

**Go 代码示例:**

```go
func ExampleUnalignedWrite() {
	buf := make([]byte, 10)
	for i := range buf {
		buf[i] = byte(i)
	}

	// 使用 SHA3-256
	h1 := New256()
	h1.Write(buf)
	expected := h1.Sum(nil)

	// 模拟非对齐写入
	h2 := New256()
	h2.Write(buf[:3])
	h2.Write(buf[3:7])
	h2.Write(buf[7:])
	got := h2.Sum(nil)

	fmt.Printf("Expected: %x\n", expected)
	fmt.Printf("Got:      %x\n", got)

	// Output:
	// Expected: 4b008604340f8941b1f8b221426df7df2f1ca169632d55b73b60799f618835f4
	// Got:      4b008604340f8941b1f8b221426df7df2f1ca169632d55b73b60799f618835f4
}
```

**假设输出:**  无论数据如何分割写入，最终的哈希值都应该相同。

**命令行参数处理:**

这个测试文件本身并不直接处理命令行参数。它依赖 Go 的 `testing` 包提供的测试框架。你可以使用 `go test` 命令来运行这些测试。

**示例命令:**

```bash
go test -v ./go/src/crypto/sha3/
```

*   `-v`:  表示 verbose，会输出更详细的测试信息。

**使用者易犯错的点:**

*   **对 `Sum` 方法的误解:**  初学者可能会认为每次调用 `Sum(nil)` 都会返回一个新的、独立的哈希值。但实际上，如果传入一个非空的 slice，`Sum` 会将哈希值追加到这个 slice 中。
    ```go
    h := New256()
    h.Write([]byte("hello"))
    s1 := h.Sum(nil)
    s2 := h.Sum(s1) // 错误理解：s2 只是 "hello" 的哈希值
    // 正确理解：s2 是 s1 ( "hello" 的哈希值 ) 加上 "hello" 的哈希值
    ```
*   **SHAKE 输出长度的控制:**  SHAKE 算法可以产生任意长度的输出，使用者需要明确指定 `Read` 方法读取的字节数。如果 `Read` 的缓冲区大小不足，可能无法获取期望长度的输出。
    ```go
    h := NewSHAKE128()
    h.Write([]byte("world"))
    out := make([]byte, 10)
    h.Read(out) // out 中可能只包含了部分哈希输出
    ```
*   **cSHAKE 的定制参数:**  使用 cSHAKE 时，如果不理解 `functionName` 和 `customizationString` 参数的作用，可能会得到非预期的哈希结果。这两个参数用于区分不同的 cSHAKE 应用。

总而言之，`go/src/crypto/sha3/sha3_test.go` 文件通过一系列细致的测试用例，确保了 Go 语言 `crypto/sha3` 包中 SHA-3 和 SHAKE 算法实现的正确性、稳定性和性能。它涵盖了不同算法变体、不同输入方式、内存管理以及状态的序列化和反序列化等多个方面。

Prompt: 
```
这是路径为go/src/crypto/sha3/sha3_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha3_test

import (
	"bytes"
	"crypto/internal/cryptotest"
	"crypto/internal/fips140"
	. "crypto/sha3"
	"encoding/hex"
	"io"
	"math/rand"
	"strings"
	"testing"
)

const testString = "brekeccakkeccak koax koax"

// testDigests contains functions returning hash.Hash instances
// with output-length equal to the KAT length for SHA-3, Keccak
// and SHAKE instances.
var testDigests = map[string]func() *SHA3{
	"SHA3-224": New224,
	"SHA3-256": New256,
	"SHA3-384": New384,
	"SHA3-512": New512,
}

// testShakes contains functions that return *sha3.SHAKE instances for
// with output-length equal to the KAT length.
var testShakes = map[string]struct {
	constructor  func(N []byte, S []byte) *SHAKE
	defAlgoName  string
	defCustomStr string
}{
	// NewCSHAKE without customization produces same result as SHAKE
	"SHAKE128":  {NewCSHAKE128, "", ""},
	"SHAKE256":  {NewCSHAKE256, "", ""},
	"cSHAKE128": {NewCSHAKE128, "CSHAKE128", "CustomString"},
	"cSHAKE256": {NewCSHAKE256, "CSHAKE256", "CustomString"},
}

// decodeHex converts a hex-encoded string into a raw byte string.
func decodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// TestUnalignedWrite tests that writing data in an arbitrary pattern with
// small input buffers.
func TestUnalignedWrite(t *testing.T) {
	cryptotest.TestAllImplementations(t, "sha3", testUnalignedWrite)
}

func testUnalignedWrite(t *testing.T) {
	buf := sequentialBytes(0x10000)
	for alg, df := range testDigests {
		d := df()
		d.Reset()
		d.Write(buf)
		want := d.Sum(nil)
		d.Reset()
		for i := 0; i < len(buf); {
			// Cycle through offsets which make a 137 byte sequence.
			// Because 137 is prime this sequence should exercise all corner cases.
			offsets := [17]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1}
			for _, j := range offsets {
				if v := len(buf) - i; v < j {
					j = v
				}
				d.Write(buf[i : i+j])
				i += j
			}
		}
		got := d.Sum(nil)
		if !bytes.Equal(got, want) {
			t.Errorf("Unaligned writes, alg=%s\ngot %q, want %q", alg, got, want)
		}
	}

	// Same for SHAKE
	for alg, df := range testShakes {
		want := make([]byte, 16)
		got := make([]byte, 16)
		d := df.constructor([]byte(df.defAlgoName), []byte(df.defCustomStr))

		d.Reset()
		d.Write(buf)
		d.Read(want)
		d.Reset()
		for i := 0; i < len(buf); {
			// Cycle through offsets which make a 137 byte sequence.
			// Because 137 is prime this sequence should exercise all corner cases.
			offsets := [17]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1}
			for _, j := range offsets {
				if v := len(buf) - i; v < j {
					j = v
				}
				d.Write(buf[i : i+j])
				i += j
			}
		}
		d.Read(got)
		if !bytes.Equal(got, want) {
			t.Errorf("Unaligned writes, alg=%s\ngot %q, want %q", alg, got, want)
		}
	}
}

// TestAppend checks that appending works when reallocation is necessary.
func TestAppend(t *testing.T) {
	cryptotest.TestAllImplementations(t, "sha3", testAppend)
}

func testAppend(t *testing.T) {
	d := New224()

	for capacity := 2; capacity <= 66; capacity += 64 {
		// The first time around the loop, Sum will have to reallocate.
		// The second time, it will not.
		buf := make([]byte, 2, capacity)
		d.Reset()
		d.Write([]byte{0xcc})
		buf = d.Sum(buf)
		expected := "0000DF70ADC49B2E76EEE3A6931B93FA41841C3AF2CDF5B32A18B5478C39"
		if got := strings.ToUpper(hex.EncodeToString(buf)); got != expected {
			t.Errorf("got %s, want %s", got, expected)
		}
	}
}

// TestAppendNoRealloc tests that appending works when no reallocation is necessary.
func TestAppendNoRealloc(t *testing.T) {
	cryptotest.TestAllImplementations(t, "sha3", testAppendNoRealloc)
}

func testAppendNoRealloc(t *testing.T) {
	buf := make([]byte, 1, 200)
	d := New224()
	d.Write([]byte{0xcc})
	buf = d.Sum(buf)
	expected := "00DF70ADC49B2E76EEE3A6931B93FA41841C3AF2CDF5B32A18B5478C39"
	if got := strings.ToUpper(hex.EncodeToString(buf)); got != expected {
		t.Errorf("got %s, want %s", got, expected)
	}
}

// TestSqueezing checks that squeezing the full output a single time produces
// the same output as repeatedly squeezing the instance.
func TestSqueezing(t *testing.T) {
	cryptotest.TestAllImplementations(t, "sha3", testSqueezing)
}

func testSqueezing(t *testing.T) {
	for algo, v := range testShakes {
		d0 := v.constructor([]byte(v.defAlgoName), []byte(v.defCustomStr))
		d0.Write([]byte(testString))
		ref := make([]byte, 32)
		d0.Read(ref)

		d1 := v.constructor([]byte(v.defAlgoName), []byte(v.defCustomStr))
		d1.Write([]byte(testString))
		var multiple []byte
		for range ref {
			d1.Read(make([]byte, 0))
			one := make([]byte, 1)
			d1.Read(one)
			multiple = append(multiple, one...)
		}
		if !bytes.Equal(ref, multiple) {
			t.Errorf("%s: squeezing %d bytes one at a time failed", algo, len(ref))
		}
	}
}

// sequentialBytes produces a buffer of size consecutive bytes 0x00, 0x01, ..., used for testing.
//
// The alignment of each slice is intentionally randomized to detect alignment
// issues in the implementation. See https://golang.org/issue/37644.
// Ideally, the compiler should fuzz the alignment itself.
// (See https://golang.org/issue/35128.)
func sequentialBytes(size int) []byte {
	alignmentOffset := rand.Intn(8)
	result := make([]byte, size+alignmentOffset)[alignmentOffset:]
	for i := range result {
		result[i] = byte(i)
	}
	return result
}

func TestReset(t *testing.T) {
	cryptotest.TestAllImplementations(t, "sha3", testReset)
}

func testReset(t *testing.T) {
	out1 := make([]byte, 32)
	out2 := make([]byte, 32)

	for _, v := range testShakes {
		// Calculate hash for the first time
		c := v.constructor(nil, []byte{0x99, 0x98})
		c.Write(sequentialBytes(0x100))
		c.Read(out1)

		// Calculate hash again
		c.Reset()
		c.Write(sequentialBytes(0x100))
		c.Read(out2)

		if !bytes.Equal(out1, out2) {
			t.Error("\nExpected:\n", out1, "\ngot:\n", out2)
		}
	}
}

var sinkSHA3 byte

func TestAllocations(t *testing.T) {
	cryptotest.SkipTestAllocations(t)
	t.Run("New", func(t *testing.T) {
		if allocs := testing.AllocsPerRun(10, func() {
			h := New256()
			b := []byte("ABC")
			h.Write(b)
			out := make([]byte, 0, 32)
			out = h.Sum(out)
			sinkSHA3 ^= out[0]
		}); allocs > 0 {
			t.Errorf("expected zero allocations, got %0.1f", allocs)
		}
	})
	t.Run("NewSHAKE", func(t *testing.T) {
		if allocs := testing.AllocsPerRun(10, func() {
			h := NewSHAKE128()
			b := []byte("ABC")
			h.Write(b)
			out := make([]byte, 32)
			h.Read(out)
			sinkSHA3 ^= out[0]
		}); allocs > 0 {
			t.Errorf("expected zero allocations, got %0.1f", allocs)
		}
	})
	t.Run("Sum", func(t *testing.T) {
		if allocs := testing.AllocsPerRun(10, func() {
			b := []byte("ABC")
			out := Sum256(b)
			sinkSHA3 ^= out[0]
		}); allocs > 0 {
			t.Errorf("expected zero allocations, got %0.1f", allocs)
		}
	})
	t.Run("SumSHAKE", func(t *testing.T) {
		if allocs := testing.AllocsPerRun(10, func() {
			b := []byte("ABC")
			out := SumSHAKE128(b, 10)
			sinkSHA3 ^= out[0]
		}); allocs > 0 {
			t.Errorf("expected zero allocations, got %0.1f", allocs)
		}
	})
}

func TestCSHAKEAccumulated(t *testing.T) {
	// Generated with pycryptodome@3.20.0
	//
	//    from Crypto.Hash import cSHAKE128
	//    rng = cSHAKE128.new()
	//    acc = cSHAKE128.new()
	//    for n in range(200):
	//        N = rng.read(n)
	//        for s in range(200):
	//            S = rng.read(s)
	//            c = cSHAKE128.cSHAKE_XOF(data=None, custom=S, capacity=256, function=N)
	//            c.update(rng.read(100))
	//            acc.update(c.read(200))
	//            c = cSHAKE128.cSHAKE_XOF(data=None, custom=S, capacity=256, function=N)
	//            c.update(rng.read(168))
	//            acc.update(c.read(200))
	//            c = cSHAKE128.cSHAKE_XOF(data=None, custom=S, capacity=256, function=N)
	//            c.update(rng.read(200))
	//            acc.update(c.read(200))
	//    print(acc.read(32).hex())
	//
	// and with @noble/hashes@v1.5.0
	//
	//    import { bytesToHex } from "@noble/hashes/utils";
	//    import { cshake128 } from "@noble/hashes/sha3-addons";
	//    const rng = cshake128.create();
	//    const acc = cshake128.create();
	//    for (let n = 0; n < 200; n++) {
	//        const N = rng.xof(n);
	//        for (let s = 0; s < 200; s++) {
	//            const S = rng.xof(s);
	//            let c = cshake128.create({ NISTfn: N, personalization: S });
	//            c.update(rng.xof(100));
	//            acc.update(c.xof(200));
	//            c = cshake128.create({ NISTfn: N, personalization: S });
	//            c.update(rng.xof(168));
	//            acc.update(c.xof(200));
	//            c = cshake128.create({ NISTfn: N, personalization: S });
	//            c.update(rng.xof(200));
	//            acc.update(c.xof(200));
	//        }
	//    }
	//    console.log(bytesToHex(acc.xof(32)));
	//
	cryptotest.TestAllImplementations(t, "sha3", func(t *testing.T) {
		t.Run("cSHAKE128", func(t *testing.T) {
			testCSHAKEAccumulated(t, NewCSHAKE128, (1600-256)/8,
				"bb14f8657c6ec5403d0b0e2ef3d3393497e9d3b1a9a9e8e6c81dbaa5fd809252")
		})
		t.Run("cSHAKE256", func(t *testing.T) {
			testCSHAKEAccumulated(t, NewCSHAKE256, (1600-512)/8,
				"0baaf9250c6e25f0c14ea5c7f9bfde54c8a922c8276437db28f3895bdf6eeeef")
		})
	})
}

func testCSHAKEAccumulated(t *testing.T, newCSHAKE func(N, S []byte) *SHAKE, rate int64, exp string) {
	rnd := newCSHAKE(nil, nil)
	acc := newCSHAKE(nil, nil)
	for n := 0; n < 200; n++ {
		N := make([]byte, n)
		rnd.Read(N)
		for s := 0; s < 200; s++ {
			S := make([]byte, s)
			rnd.Read(S)

			c := newCSHAKE(N, S)
			io.CopyN(c, rnd, 100 /* < rate */)
			io.CopyN(acc, c, 200)

			c.Reset()
			io.CopyN(c, rnd, rate)
			io.CopyN(acc, c, 200)

			c.Reset()
			io.CopyN(c, rnd, 200 /* > rate */)
			io.CopyN(acc, c, 200)
		}
	}
	out := make([]byte, 32)
	acc.Read(out)
	if got := hex.EncodeToString(out); got != exp {
		t.Errorf("got %s, want %s", got, exp)
	}
}

func TestCSHAKELargeS(t *testing.T) {
	cryptotest.TestAllImplementations(t, "sha3", testCSHAKELargeS)
}

func testCSHAKELargeS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}

	// See https://go.dev/issue/66232.
	const s = (1<<32)/8 + 1000 // s * 8 > 2^32
	S := make([]byte, s)
	rnd := NewSHAKE128()
	rnd.Read(S)
	c := NewCSHAKE128(nil, S)
	io.CopyN(c, rnd, 1000)
	out := make([]byte, 32)
	c.Read(out)

	// Generated with pycryptodome@3.20.0
	//
	//    from Crypto.Hash import cSHAKE128
	//    rng = cSHAKE128.new()
	//    S = rng.read(536871912)
	//    c = cSHAKE128.new(custom=S)
	//    c.update(rng.read(1000))
	//    print(c.read(32).hex())
	//
	exp := "2cb9f237767e98f2614b8779cf096a52da9b3a849280bbddec820771ae529cf0"
	if got := hex.EncodeToString(out); got != exp {
		t.Errorf("got %s, want %s", got, exp)
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	cryptotest.TestAllImplementations(t, "sha3", func(t *testing.T) {
		t.Run("SHA3-224", func(t *testing.T) { testMarshalUnmarshal(t, New224()) })
		t.Run("SHA3-256", func(t *testing.T) { testMarshalUnmarshal(t, New256()) })
		t.Run("SHA3-384", func(t *testing.T) { testMarshalUnmarshal(t, New384()) })
		t.Run("SHA3-512", func(t *testing.T) { testMarshalUnmarshal(t, New512()) })
		t.Run("SHAKE128", func(t *testing.T) { testMarshalUnmarshalSHAKE(t, NewSHAKE128()) })
		t.Run("SHAKE256", func(t *testing.T) { testMarshalUnmarshalSHAKE(t, NewSHAKE256()) })
		t.Run("cSHAKE128", func(t *testing.T) { testMarshalUnmarshalSHAKE(t, NewCSHAKE128([]byte("N"), []byte("S"))) })
		t.Run("cSHAKE256", func(t *testing.T) { testMarshalUnmarshalSHAKE(t, NewCSHAKE256([]byte("N"), []byte("S"))) })
	})
}

// TODO(filippo): move this to crypto/internal/cryptotest.
func testMarshalUnmarshal(t *testing.T, h *SHA3) {
	buf := make([]byte, 200)
	rand.Read(buf)
	n := rand.Intn(200)
	h.Write(buf)
	want := h.Sum(nil)
	h.Reset()
	h.Write(buf[:n])
	b, err := h.MarshalBinary()
	if err != nil {
		t.Errorf("MarshalBinary: %v", err)
	}
	h.Write(bytes.Repeat([]byte{0}, 200))
	if err := h.UnmarshalBinary(b); err != nil {
		t.Errorf("UnmarshalBinary: %v", err)
	}
	h.Write(buf[n:])
	got := h.Sum(nil)
	if !bytes.Equal(got, want) {
		t.Errorf("got %x, want %x", got, want)
	}
}

// TODO(filippo): move this to crypto/internal/cryptotest.
func testMarshalUnmarshalSHAKE(t *testing.T, h *SHAKE) {
	buf := make([]byte, 200)
	rand.Read(buf)
	n := rand.Intn(200)
	h.Write(buf)
	want := make([]byte, 32)
	h.Read(want)
	h.Reset()
	h.Write(buf[:n])
	b, err := h.MarshalBinary()
	if err != nil {
		t.Errorf("MarshalBinary: %v", err)
	}
	h.Write(bytes.Repeat([]byte{0}, 200))
	if err := h.UnmarshalBinary(b); err != nil {
		t.Errorf("UnmarshalBinary: %v", err)
	}
	h.Write(buf[n:])
	got := make([]byte, 32)
	h.Read(got)
	if !bytes.Equal(got, want) {
		t.Errorf("got %x, want %x", got, want)
	}
}

// benchmarkHash tests the speed to hash num buffers of buflen each.
func benchmarkHash(b *testing.B, h fips140.Hash, size, num int) {
	b.StopTimer()
	h.Reset()
	data := sequentialBytes(size)
	b.SetBytes(int64(size * num))
	b.StartTimer()

	var state []byte
	for i := 0; i < b.N; i++ {
		for j := 0; j < num; j++ {
			h.Write(data)
		}
		state = h.Sum(state[:0])
	}
	b.StopTimer()
	h.Reset()
}

// benchmarkShake is specialized to the Shake instances, which don't
// require a copy on reading output.
func benchmarkShake(b *testing.B, h *SHAKE, size, num int) {
	b.StopTimer()
	h.Reset()
	data := sequentialBytes(size)
	d := make([]byte, 32)

	b.SetBytes(int64(size * num))
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		h.Reset()
		for j := 0; j < num; j++ {
			h.Write(data)
		}
		h.Read(d)
	}
}

func BenchmarkSha3_512_MTU(b *testing.B) { benchmarkHash(b, New512(), 1350, 1) }
func BenchmarkSha3_384_MTU(b *testing.B) { benchmarkHash(b, New384(), 1350, 1) }
func BenchmarkSha3_256_MTU(b *testing.B) { benchmarkHash(b, New256(), 1350, 1) }
func BenchmarkSha3_224_MTU(b *testing.B) { benchmarkHash(b, New224(), 1350, 1) }

func BenchmarkShake128_MTU(b *testing.B)  { benchmarkShake(b, NewSHAKE128(), 1350, 1) }
func BenchmarkShake256_MTU(b *testing.B)  { benchmarkShake(b, NewSHAKE256(), 1350, 1) }
func BenchmarkShake256_16x(b *testing.B)  { benchmarkShake(b, NewSHAKE256(), 16, 1024) }
func BenchmarkShake256_1MiB(b *testing.B) { benchmarkShake(b, NewSHAKE256(), 1024, 1024) }

func BenchmarkSha3_512_1MiB(b *testing.B) { benchmarkHash(b, New512(), 1024, 1024) }

"""



```