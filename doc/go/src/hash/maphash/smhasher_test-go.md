Response:
Let's break down the thought process for analyzing the given Go code snippet.

**1. Initial Scan and Keyword Recognition:**

The first step is to quickly scan the code for familiar keywords and structures. I see:

* `package maphash`: This tells me it's part of the `maphash` standard library package, likely related to hashing functionalities, especially for maps.
* `import`:  Standard Go imports. `testing` is a strong indicator of test code. `math`, `rand`, `runtime`, `slices`, `strings`, `unsafe`, and `internal/testenv` provide clues about the types of tests being performed.
* `// Copyright`, `// Use of this source code`:  Standard license and copyright information.
* `//go:build !race`: This is a build constraint, meaning these tests are skipped when the `-race` flag is used during compilation. This hints that the tests might be performance-sensitive or rely on specific memory layouts.
* `// Smhasher is a torture test for hash functions`:  This is a crucial piece of information. It immediately tells me the purpose of this file: to rigorously test the quality of hash functions. The link to `code.google.com/p/smhasher/` confirms this is based on a known hashing benchmark suite.
* `func Test...`:  Standard Go testing function names.
* `t.Parallel()`:  Indicates these tests can run in parallel.
* `bytesHash`, `stringHash`:  Helper functions to calculate hashes of byte slices and strings.
* `hashSet`: A custom data structure for tracking hash collisions.
* Specific test names like `TestSmhasherSanity`, `TestSmhasherAppendedZeros`, `TestSmhasherSmallKeys`, etc. These names suggest the specific properties of the hash function being tested.

**2. Understanding the Core Objective:**

The comment `// Smhasher is a torture test for hash functions` is the key. This means the code aims to evaluate how well the `maphash` package's hash functions perform under various challenging conditions. The tests aim to identify potential weaknesses or biases in the hashing algorithm.

**3. Analyzing Individual Tests (Iterative Process):**

I start analyzing individual test functions to understand their specific focus:

* **`TestSmhasherSanity`:** Checks if the hash depends only on the input key and is independent of surrounding memory or alignment. This is a basic but important property.
* **`bytesHash`, `stringHash`:** These are simple wrappers around the `maphash.Hash` type, confirming that the tests are using the package's API.
* **`hashSet`:** This structure is used to detect collisions. The `check` method calculates the expected number of collisions and flags anomalies, a core part of evaluating hash function quality.
* **`TestSmhasherAppendedZeros`:** Tests if adding trailing zeros to a string changes its hash. Good hash functions should differentiate these.
* **`TestSmhasherSmallKeys`:** Tests the hash function's behavior with very short inputs.
* **`TestSmhasherZeros`:**  Tests different lengths of all-zero byte slices.
* **`TestSmhasherTwoNonzero`:** Checks if strings with at most two non-zero bytes have distinct hashes.
* **`TestSmhasherCyclic`:** Tests strings with repeating patterns. Some poor hash functions can produce many collisions with such patterns.
* **`TestSmhasherSparse`:** Tests strings with only a few bits set.
* **`TestSmhasherPermutation`:** Tests combinations of specific byte sequences.
* **`TestSmhasherAvalanche`:** This is a crucial test. It verifies the "avalanche effect," meaning a small change in the input (flipping a single bit) should cause a significant and seemingly random change in the output bits.
* **`TestSmhasherWindowed`:** Tests bit rotations of keys.
* **`TestSmhasherText`:** Tests strings with alphanumeric characters.
* **`TestSmhasherSeed`:**  Verifies that using different seeds produces different hash values. This is important for security and randomization.

**4. Inferring the Go Feature Being Tested:**

Based on the package name (`maphash`) and the types of tests, it's clear this code tests the hash function implementation provided by the `maphash` package in Go. This package provides a way to calculate hash values for byte slices and strings, often used internally by Go's `map` data structure.

**5. Generating Code Examples:**

To illustrate the functionality, I can create simple examples showing how to use `maphash.Hash` to calculate hashes with different seeds and for different data. The key is to demonstrate the `SetSeed`, `Write`/`WriteString`, and `Sum64` methods.

**6. Identifying Potential Mistakes:**

I consider common pitfalls when working with hash functions:

* **Assuming a fixed seed:**  For security-sensitive applications or when randomization is needed, hardcoding or reusing the same seed can lead to predictable behavior.
* **Ignoring the importance of avalanche effect:**  If a hash function doesn't have a good avalanche effect, small changes in input might not result in significant changes in the hash, potentially leading to security vulnerabilities or clustering in hash tables.

**7. Structuring the Answer:**

Finally, I organize the information into a clear and structured answer, covering:

* **Functionality:** Listing the individual tests and their purposes.
* **Go Feature:** Identifying the `maphash` package and its role.
* **Code Examples:** Providing illustrative Go code snippets.
* **Assumptions and Input/Output:**  Describing the logic of the code examples and the expected outcomes.
* **Command-line Parameters:** Noting the use of `-race` and its effect.
* **Common Mistakes:**  Pointing out potential errors users might make.

This iterative process of scanning, understanding the high-level goal, analyzing details, and synthesizing the information allows for a comprehensive and accurate understanding of the given Go code snippet.
这段Go语言代码是 `go/src/hash/maphash/smhasher_test.go` 文件的一部分，它主要用于对 Go 语言标准库 `maphash` 包中的哈希函数进行**严格的质量测试**， 模仿了著名的Smhasher测试套件的一些测试用例。

以下是代码中各个部分的功能：

**1. 总体目标：测试 `maphash` 包的哈希函数质量**

   - 该代码通过各种测试用例来检验 `maphash` 包提供的哈希函数是否具有良好的分布性、雪崩效应、以及抵抗特定模式输入的能力。
   - Smhasher 是一套被广泛认可的哈希函数测试工具，这段代码借鉴了其思想和部分测试方法。

**2. 核心概念和辅助函数：**

   - `fixedSeed`:  定义了一个固定的 `Seed` 值，用于在某些测试中保证结果的可重复性。
   - `bytesHash(b []byte) uint64`:  使用 `maphash.Hash` 计算字节切片的哈希值。
   - `stringHash(s string) uint64`:  使用 `maphash.Hash` 计算字符串的哈希值。
   - `randBytes(r *rand.Rand, b []byte)`:  生成随机字节填充给定的字节切片。
   - `hashSet`:  一个自定义的数据结构，用于跟踪已生成的哈希值，并检测哈希冲突的频率。
   - `newHashSet()`:  创建一个新的 `hashSet` 实例。
   - `hashSet.add(h uint64)`:  向 `hashSet` 中添加一个哈希值。
   - `hashSet.addS(x string)` 和 `hashSet.addB(x []byte)`:  分别添加字符串和字节切片的哈希值。
   - `hashSet.addS_seed(x string, seed Seed)`:  使用指定的 `Seed` 计算并添加字符串的哈希值。
   - `hashSet.check(t *testing.T)`:  检查 `hashSet` 中的哈希冲突频率是否在预期范围内。它会根据哈希值的数量和哈希空间的大小计算期望的冲突概率，并与实际冲突数进行比较，判断哈希函数的分布性是否良好。

**3. 主要测试用例的功能：**

   - **`TestSmhasherSanity`**:  进行一些基本的健全性检查：
      - 验证哈希值是否只依赖于输入的键，而不受键外部内存的影响。
      - 验证哈希值是否不受内存对齐的影响。
   - **`TestSmhasherAppendedZeros`**:  测试在字符串末尾添加零字节是否会产生不同的哈希值。好的哈希函数应该能区分这些情况。
   - **`TestSmhasherSmallKeys`**:  测试所有 0 到 3 字节长度的字符串是否具有不同的哈希值。
   - **`TestSmhasherZeros`**:  测试不同长度的全零字节切片是否具有不同的哈希值。
   - **`TestSmhasherTwoNonzero`**:  测试最多包含两个非零字节的字符串是否具有不同的哈希值。
   - **`TestSmhasherCyclic`**:  测试具有重复模式的字符串（例如 "abcdabcdabcd..."）的哈希值分布。
   - **`TestSmhasherSparse`**:  测试只有少数几个比特被设置的字符串的哈希值分布。
   - **`TestSmhasherPermutation`**:  测试由一组给定的块进行排列组合形成的字符串的哈希值分布。
   - **`TestSmhasherAvalanche`**:  测试哈希函数的雪崩效应。它通过翻转输入键的每一位，观察输出哈希值的变化，来判断即使输入发生微小变化，输出是否也会有明显的、不可预测的变化。
   - **`TestSmhasherWindowed`**:  测试对一组不同的键进行位旋转后的哈希值分布。
   - **`TestSmhasherText`**:  测试由前缀、中间的字母数字字符组合以及后缀组成的字符串的哈希值分布。
   - **`TestSmhasherSeed`**:  测试使用不同的 `Seed` 值是否会生成不同的哈希值。这是 `maphash` 包的一个重要特性，允许用户为哈希函数提供随机性。

**4. 推理 `maphash` 的 Go 语言功能实现：**

这段代码主要测试的是 Go 语言标准库 `hash/maphash` 包提供的**可配置种子（seeded）的哈希函数**。`maphash` 包旨在提供高性能的哈希功能，特别适用于实现哈希表（例如 Go 的 `map` 类型）。

**Go 代码示例：**

```go
package main

import (
	"fmt"
	"hash/maphash"
)

func main() {
	var h maphash.Hash
	seed := maphash.MakeSeed() // 生成一个随机的 Seed
	h.SetSeed(seed)

	data1 := []byte("hello")
	h.Write(data1)
	hash1 := h.Sum64()
	fmt.Printf("Hash of '%s' with seed %v: %x\n", data1, seed, hash1)

	// 使用相同的 Seed，相同的输入，哈希值应该相同
	var h2 maphash.Hash
	h2.SetSeed(seed)
	h2.Write(data1)
	hash2 := h2.Sum64()
	fmt.Printf("Hash of '%s' with same seed: %x\n", data1, hash2)

	// 使用不同的 Seed，相同的输入，哈希值应该不同
	seed2 := maphash.MakeSeed()
	var h3 maphash.Hash
	h3.SetSeed(seed2)
	h3.Write(data1)
	hash3 := h3.Sum64()
	fmt.Printf("Hash of '%s' with different seed %v: %x\n", data1, seed2, hash3)

	strData := "world"
	var h4 maphash.Hash
	h4.SetSeed(seed)
	h4.WriteString(strData)
	hash4 := h4.Sum64()
	fmt.Printf("Hash of string '%s' with seed %v: %x\n", strData, seed, hash4)
}
```

**假设的输入与输出：**

由于 `maphash.MakeSeed()` 会生成随机的种子，因此每次运行的输出哈希值会不同。但基本原则是：

- 对于相同的输入和相同的种子，哈希值应该相同。
- 对于相同的输入和不同的种子，哈希值应该大概率不同。

**示例输出：**

```
Hash of 'hello' with seed {s:0xc9a3b6f8d1e2075a}: 968b970c17a8a5e7
Hash of 'hello' with same seed: 968b970c17a8a5e7
Hash of 'hello' with different seed {s:0x4b2e7c9d3f1a5b8c}: 3d4e6f1b8c9a205f
Hash of string 'world' with seed {s:0xc9a3b6f8d1e2075a}: 8e5a6f7b2d1c3a49
```

**5. 命令行参数的具体处理：**

这段代码中使用了 `//go:build !race` 这个构建约束。这意味着这些测试用例在运行带有 `-race` 标志的测试时会被跳过。

- **`-race` 标志** 是 Go 语言测试工具 `go test` 提供的一个选项，用于启用竞态检测器。竞态检测器可以帮助发现并发程序中潜在的数据竞争问题。

**为什么在 `-race` 模式下禁用这些测试？**

Smhasher 类型的测试通常非常耗时，并且会进行大量的内存操作。竞态检测器会增加程序的运行负担，使得这些测试在 `-race` 模式下运行时间过长，或者由于额外的开销而产生一些误报。因此，为了保证在非竞态检测模式下的性能测试效率，这些测试被选择性地禁用。

**运行测试的命令示例：**

- 运行所有非竞态测试： `go test ./...` (在 `go/src/hash/maphash/` 目录下执行)
- 运行所有测试（包括竞态测试，但这些会被跳过）： `go test -race ./...`

**6. 使用者易犯错的点：**

使用者在使用 `maphash` 包时，一个常见的错误是**混淆或错误地使用 `Seed`**。

**示例：**

```go
package main

import (
	"fmt"
	"hash/maphash"
)

func main() {
	var h1 maphash.Hash
	var h2 maphash.Hash

	data := []byte("test")

	// 错误示例：忘记设置 Seed，或者使用默认的零值 Seed
	h1.Write(data)
	hash1 := h1.Sum64()
	fmt.Printf("Hash 1 (no seed): %x\n", hash1)

	h2.Write(data) // 错误的假设：h2 会使用和 h1 相同的“默认” Seed
	hash2 := h2.Sum64()
	fmt.Printf("Hash 2 (no seed): %x\n", hash2)

	// 正确示例：显式设置 Seed
	seed := maphash.MakeSeed()
	var h3 maphash.Hash
	h3.SetSeed(seed)
	h3.Write(data)
	hash3 := h3.Sum64()
	fmt.Printf("Hash 3 (with seed %v): %x\n", seed, hash3)

	var h4 maphash.Hash
	h4.SetSeed(seed) // 使用相同的 Seed
	h4.Write(data)
	hash4 := h4.Sum64()
	fmt.Printf("Hash 4 (with same seed): %x\n", hash4)
}
```

**可能出现的错误现象：**

- 如果不设置 `Seed`，`maphash.Hash` 会使用一个内部的、可能固定的或容易预测的默认值，这可能导致在某些场景下哈希碰撞的概率增加，或者降低安全性。
- 错误地认为多个 `maphash.Hash` 实例在不显式设置 `Seed` 的情况下会使用相同的“默认” `Seed`。实际上，每个 `maphash.Hash` 实例都需要单独设置 `Seed`。

**总结：**

这段代码是 `maphash` 包的重要组成部分，它通过一系列严谨的测试确保了该包提供的哈希函数具有高质量的特性，例如良好的分布性、雪崩效应以及对不同模式输入的鲁棒性。理解这段代码有助于深入理解 `maphash` 包的设计和使用方法。

Prompt: 
```
这是路径为go/src/hash/maphash/smhasher_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !race

package maphash

import (
	"fmt"
	"internal/testenv"
	"math"
	"math/rand"
	"runtime"
	"slices"
	"strings"
	"testing"
	"unsafe"
)

// Smhasher is a torture test for hash functions.
// https://code.google.com/p/smhasher/
// This code is a port of some of the Smhasher tests to Go.

// Note: due to the long running time of these tests, they are
// currently disabled in -race mode.

var fixedSeed = MakeSeed()

// Sanity checks.
// hash should not depend on values outside key.
// hash should not depend on alignment.
func TestSmhasherSanity(t *testing.T) {
	t.Parallel()
	r := rand.New(rand.NewSource(1234))
	const REP = 10
	const KEYMAX = 128
	const PAD = 16
	const OFFMAX = 16
	for k := 0; k < REP; k++ {
		for n := 0; n < KEYMAX; n++ {
			for i := 0; i < OFFMAX; i++ {
				var b [KEYMAX + OFFMAX + 2*PAD]byte
				var c [KEYMAX + OFFMAX + 2*PAD]byte
				randBytes(r, b[:])
				randBytes(r, c[:])
				copy(c[PAD+i:PAD+i+n], b[PAD:PAD+n])
				if bytesHash(b[PAD:PAD+n]) != bytesHash(c[PAD+i:PAD+i+n]) {
					t.Errorf("hash depends on bytes outside key")
				}
			}
		}
	}
}

func bytesHash(b []byte) uint64 {
	var h Hash
	h.SetSeed(fixedSeed)
	h.Write(b)
	return h.Sum64()
}
func stringHash(s string) uint64 {
	var h Hash
	h.SetSeed(fixedSeed)
	h.WriteString(s)
	return h.Sum64()
}

const hashSize = 64

func randBytes(r *rand.Rand, b []byte) {
	r.Read(b) // can't fail
}

// A hashSet measures the frequency of hash collisions.
type hashSet struct {
	list []uint64 // list of hashes added
}

func newHashSet() *hashSet {
	return &hashSet{list: make([]uint64, 0, 1024)}
}
func (s *hashSet) add(h uint64) {
	s.list = append(s.list, h)
}
func (s *hashSet) addS(x string) {
	s.add(stringHash(x))
}
func (s *hashSet) addB(x []byte) {
	s.add(bytesHash(x))
}
func (s *hashSet) addS_seed(x string, seed Seed) {
	var h Hash
	h.SetSeed(seed)
	h.WriteString(x)
	s.add(h.Sum64())
}
func (s *hashSet) check(t *testing.T) {
	t.Helper()
	list := s.list
	slices.Sort(list)

	collisions := 0
	for i := 1; i < len(list); i++ {
		if list[i] == list[i-1] {
			collisions++
		}
	}
	n := len(list)

	const SLOP = 10.0
	pairs := int64(n) * int64(n-1) / 2
	expected := float64(pairs) / math.Pow(2.0, float64(hashSize))
	stddev := math.Sqrt(expected)
	if float64(collisions) > expected+SLOP*(3*stddev+1) {
		t.Errorf("unexpected number of collisions: got=%d mean=%f stddev=%f", collisions, expected, stddev)
	}
	// Reset for reuse
	s.list = s.list[:0]
}

// a string plus adding zeros must make distinct hashes
func TestSmhasherAppendedZeros(t *testing.T) {
	t.Parallel()
	s := "hello" + strings.Repeat("\x00", 256)
	h := newHashSet()
	for i := 0; i <= len(s); i++ {
		h.addS(s[:i])
	}
	h.check(t)
}

// All 0-3 byte strings have distinct hashes.
func TestSmhasherSmallKeys(t *testing.T) {
	testenv.ParallelOn64Bit(t)
	h := newHashSet()
	var b [3]byte
	for i := 0; i < 256; i++ {
		b[0] = byte(i)
		h.addB(b[:1])
		for j := 0; j < 256; j++ {
			b[1] = byte(j)
			h.addB(b[:2])
			if !testing.Short() {
				for k := 0; k < 256; k++ {
					b[2] = byte(k)
					h.addB(b[:3])
				}
			}
		}
	}
	h.check(t)
}

// Different length strings of all zeros have distinct hashes.
func TestSmhasherZeros(t *testing.T) {
	t.Parallel()
	N := 256 * 1024
	if testing.Short() {
		N = 1024
	}
	h := newHashSet()
	b := make([]byte, N)
	for i := 0; i <= N; i++ {
		h.addB(b[:i])
	}
	h.check(t)
}

// Strings with up to two nonzero bytes all have distinct hashes.
func TestSmhasherTwoNonzero(t *testing.T) {
	if runtime.GOARCH == "wasm" {
		t.Skip("Too slow on wasm")
	}
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}
	testenv.ParallelOn64Bit(t)
	h := newHashSet()
	for n := 2; n <= 16; n++ {
		twoNonZero(h, n)
	}
	h.check(t)
}
func twoNonZero(h *hashSet, n int) {
	b := make([]byte, n)

	// all zero
	h.addB(b)

	// one non-zero byte
	for i := 0; i < n; i++ {
		for x := 1; x < 256; x++ {
			b[i] = byte(x)
			h.addB(b)
			b[i] = 0
		}
	}

	// two non-zero bytes
	for i := 0; i < n; i++ {
		for x := 1; x < 256; x++ {
			b[i] = byte(x)
			for j := i + 1; j < n; j++ {
				for y := 1; y < 256; y++ {
					b[j] = byte(y)
					h.addB(b)
					b[j] = 0
				}
			}
			b[i] = 0
		}
	}
}

// Test strings with repeats, like "abcdabcdabcdabcd..."
func TestSmhasherCyclic(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}
	t.Parallel()
	r := rand.New(rand.NewSource(1234))
	const REPEAT = 8
	const N = 1000000
	h := newHashSet()
	for n := 4; n <= 12; n++ {
		b := make([]byte, REPEAT*n)
		for i := 0; i < N; i++ {
			b[0] = byte(i * 79 % 97)
			b[1] = byte(i * 43 % 137)
			b[2] = byte(i * 151 % 197)
			b[3] = byte(i * 199 % 251)
			randBytes(r, b[4:n])
			for j := n; j < n*REPEAT; j++ {
				b[j] = b[j-n]
			}
			h.addB(b)
		}
		h.check(t)
	}
}

// Test strings with only a few bits set
func TestSmhasherSparse(t *testing.T) {
	if runtime.GOARCH == "wasm" {
		t.Skip("Too slow on wasm")
	}
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}
	t.Parallel()
	h := newHashSet()
	sparse(t, h, 32, 6)
	sparse(t, h, 40, 6)
	sparse(t, h, 48, 5)
	sparse(t, h, 56, 5)
	sparse(t, h, 64, 5)
	sparse(t, h, 96, 4)
	sparse(t, h, 256, 3)
	sparse(t, h, 2048, 2)
}
func sparse(t *testing.T, h *hashSet, n int, k int) {
	t.Helper()
	b := make([]byte, n/8)
	setbits(h, b, 0, k)
	h.check(t)
}

// set up to k bits at index i and greater
func setbits(h *hashSet, b []byte, i int, k int) {
	h.addB(b)
	if k == 0 {
		return
	}
	for j := i; j < len(b)*8; j++ {
		b[j/8] |= byte(1 << uint(j&7))
		setbits(h, b, j+1, k-1)
		b[j/8] &= byte(^(1 << uint(j&7)))
	}
}

// Test all possible combinations of n blocks from the set s.
// "permutation" is a bad name here, but it is what Smhasher uses.
func TestSmhasherPermutation(t *testing.T) {
	if runtime.GOARCH == "wasm" {
		t.Skip("Too slow on wasm")
	}
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}
	testenv.ParallelOn64Bit(t)
	h := newHashSet()
	permutation(t, h, []uint32{0, 1, 2, 3, 4, 5, 6, 7}, 8)
	permutation(t, h, []uint32{0, 1 << 29, 2 << 29, 3 << 29, 4 << 29, 5 << 29, 6 << 29, 7 << 29}, 8)
	permutation(t, h, []uint32{0, 1}, 20)
	permutation(t, h, []uint32{0, 1 << 31}, 20)
	permutation(t, h, []uint32{0, 1, 2, 3, 4, 5, 6, 7, 1 << 29, 2 << 29, 3 << 29, 4 << 29, 5 << 29, 6 << 29, 7 << 29}, 6)
}
func permutation(t *testing.T, h *hashSet, s []uint32, n int) {
	t.Helper()
	b := make([]byte, n*4)
	genPerm(h, b, s, 0)
	h.check(t)
}
func genPerm(h *hashSet, b []byte, s []uint32, n int) {
	h.addB(b[:n])
	if n == len(b) {
		return
	}
	for _, v := range s {
		b[n] = byte(v)
		b[n+1] = byte(v >> 8)
		b[n+2] = byte(v >> 16)
		b[n+3] = byte(v >> 24)
		genPerm(h, b, s, n+4)
	}
}

type key interface {
	clear()              // set bits all to 0
	random(r *rand.Rand) // set key to something random
	bits() int           // how many bits key has
	flipBit(i int)       // flip bit i of the key
	hash() uint64        // hash the key
	name() string        // for error reporting
}

type bytesKey struct {
	b []byte
}

func (k *bytesKey) clear() {
	clear(k.b)
}
func (k *bytesKey) random(r *rand.Rand) {
	randBytes(r, k.b)
}
func (k *bytesKey) bits() int {
	return len(k.b) * 8
}
func (k *bytesKey) flipBit(i int) {
	k.b[i>>3] ^= byte(1 << uint(i&7))
}
func (k *bytesKey) hash() uint64 {
	return bytesHash(k.b)
}
func (k *bytesKey) name() string {
	return fmt.Sprintf("bytes%d", len(k.b))
}

// Flipping a single bit of a key should flip each output bit with 50% probability.
func TestSmhasherAvalanche(t *testing.T) {
	if runtime.GOARCH == "wasm" {
		t.Skip("Too slow on wasm")
	}
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}
	t.Parallel()
	avalancheTest1(t, &bytesKey{make([]byte, 2)})
	avalancheTest1(t, &bytesKey{make([]byte, 4)})
	avalancheTest1(t, &bytesKey{make([]byte, 8)})
	avalancheTest1(t, &bytesKey{make([]byte, 16)})
	avalancheTest1(t, &bytesKey{make([]byte, 32)})
	avalancheTest1(t, &bytesKey{make([]byte, 200)})
}
func avalancheTest1(t *testing.T, k key) {
	t.Helper()
	const REP = 100000
	r := rand.New(rand.NewSource(1234))
	n := k.bits()

	// grid[i][j] is a count of whether flipping
	// input bit i affects output bit j.
	grid := make([][hashSize]int, n)

	for z := 0; z < REP; z++ {
		// pick a random key, hash it
		k.random(r)
		h := k.hash()

		// flip each bit, hash & compare the results
		for i := 0; i < n; i++ {
			k.flipBit(i)
			d := h ^ k.hash()
			k.flipBit(i)

			// record the effects of that bit flip
			g := &grid[i]
			for j := 0; j < hashSize; j++ {
				g[j] += int(d & 1)
				d >>= 1
			}
		}
	}

	// Each entry in the grid should be about REP/2.
	// More precisely, we did N = k.bits() * hashSize experiments where
	// each is the sum of REP coin flips. We want to find bounds on the
	// sum of coin flips such that a truly random experiment would have
	// all sums inside those bounds with 99% probability.
	N := n * hashSize
	var c float64
	// find c such that Prob(mean-c*stddev < x < mean+c*stddev)^N > .9999
	for c = 0.0; math.Pow(math.Erf(c/math.Sqrt(2)), float64(N)) < .9999; c += .1 {
	}
	c *= 11.0 // allowed slack: 40% to 60% - we don't need to be perfectly random
	mean := .5 * REP
	stddev := .5 * math.Sqrt(REP)
	low := int(mean - c*stddev)
	high := int(mean + c*stddev)
	for i := 0; i < n; i++ {
		for j := 0; j < hashSize; j++ {
			x := grid[i][j]
			if x < low || x > high {
				t.Errorf("bad bias for %s bit %d -> bit %d: %d/%d\n", k.name(), i, j, x, REP)
			}
		}
	}
}

// All bit rotations of a set of distinct keys
func TestSmhasherWindowed(t *testing.T) {
	t.Parallel()
	windowed(t, &bytesKey{make([]byte, 128)})
}
func windowed(t *testing.T, k key) {
	if runtime.GOARCH == "wasm" {
		t.Skip("Too slow on wasm")
	}
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}
	const BITS = 16

	h := newHashSet()
	for r := 0; r < k.bits(); r++ {
		for i := 0; i < 1<<BITS; i++ {
			k.clear()
			for j := 0; j < BITS; j++ {
				if i>>uint(j)&1 != 0 {
					k.flipBit((j + r) % k.bits())
				}
			}
			h.add(k.hash())
		}
		h.check(t)
	}
}

// All keys of the form prefix + [A-Za-z0-9]*N + suffix.
func TestSmhasherText(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}
	t.Parallel()
	h := newHashSet()
	text(t, h, "Foo", "Bar")
	text(t, h, "FooBar", "")
	text(t, h, "", "FooBar")
}
func text(t *testing.T, h *hashSet, prefix, suffix string) {
	t.Helper()
	const N = 4
	const S = "ABCDEFGHIJKLMNOPQRSTabcdefghijklmnopqrst0123456789"
	const L = len(S)
	b := make([]byte, len(prefix)+N+len(suffix))
	copy(b, prefix)
	copy(b[len(prefix)+N:], suffix)
	c := b[len(prefix):]
	for i := 0; i < L; i++ {
		c[0] = S[i]
		for j := 0; j < L; j++ {
			c[1] = S[j]
			for k := 0; k < L; k++ {
				c[2] = S[k]
				for x := 0; x < L; x++ {
					c[3] = S[x]
					h.addB(b)
				}
			}
		}
	}
	h.check(t)
}

// Make sure different seed values generate different hashes.
func TestSmhasherSeed(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) == 4 {
		t.Skip("32-bit platforms don't have ideal seed-input distributions (see issue 33988)")
	}
	t.Parallel()
	h := newHashSet()
	const N = 100000
	s := "hello"
	for i := 0; i < N; i++ {
		h.addS_seed(s, Seed{s: uint64(i + 1)})
		h.addS_seed(s, Seed{s: uint64(i+1) << 32}) // make sure high bits are used
	}
	h.check(t)
}

"""



```