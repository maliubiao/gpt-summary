Response:
这是关于 Go 语言中 `crypto/sha512` 包的测试代码片段。我的目标是分析这段代码的功能，并尽可能深入地理解其背后的 Go 语言特性和测试方法。

**1. 功能列表:**

*   **黄金标准测试 (Golden Tests):**  代码中定义了多个 `golden` 变量，例如 `golden224`, `golden256` 等。这些变量存储了预先计算好的输入和对应的 SHA-512 系列哈希值的十六进制表示。`TestGolden` 和 `testGolden` 函数会遍历这些黄金标准数据，使用不同的 SHA-512 变体（SHA-512/224, SHA-512/256, SHA-384, SHA-512）对输入进行哈希计算，并将计算结果与预期的哈希值进行比较，以验证哈希算法的正确性。
*   **分段写入测试:** `testHash` 函数中的 `for pass := 0; pass < 3; pass++` 循环模拟了不同的写入方式。前两次循环是完整写入，第三次循环将输入分成两部分写入，确保哈希算法在处理分段输入时也能得到正确的结果。
*   **状态序列化与反序列化测试 (Marshal/Unmarshal Tests):** `TestGoldenMarshal` 和 `testGoldenMarshal` 函数测试了哈希对象的状态序列化和反序列化功能。这允许保存哈希计算的中间状态，并在之后恢复并继续计算。这通过实现 `encoding.BinaryMarshaler` 和 `encoding.BinaryUnmarshaler` 接口来实现。
*   **状态序列化不匹配测试:** `TestMarshalMismatch` 函数用于测试不同 SHA-512 变体之间状态序列化的兼容性。预期不同变体的状态序列化数据是不能互相反序列化的，以防止错误的使用。
*   **大小和块大小测试:** `TestSize` 和 `TestBlockSize` 函数分别测试了不同 SHA-512 变体的哈希值大小和块大小是否符合预期。
*   **处理大数据量的哈希测试:** `TestLargeHashes` 函数测试了对于大数据量输入进行哈希计算后，其状态能否正确地反序列化，并能得到正确的最终哈希值。这主要是为了解决在处理非常大的数据时可能出现的整数溢出等问题。
*   **内存分配测试:** `TestAllocations` 函数使用 `testing.AllocsPerRun` 来检查在进行哈希计算时是否产生了不必要的内存分配。目标是确保哈希算法的实现是高效的，没有额外的内存开销。
*   **与其他实现的兼容性测试:** `TestHash` 函数使用了 `cryptotest.TestAllImplementations`，这表明代码旨在测试当前的 SHA-512 实现是否与其他可能的实现（例如，基于 C 语言的实现）产生相同的哈希结果。
*   **性能基准测试 (Benchmarks):** `BenchmarkHash8Bytes`, `BenchmarkHash1K`, 和 `BenchmarkHash8K` 函数用于衡量不同输入大小下 SHA-512 算法的性能，包括 `New` 方法创建哈希对象并计算哈希值以及使用 `Sum384` 和 `Sum512` 函数直接计算哈希值的性能。

**2. Go 语言功能实现推理:**

这段代码主要测试了 Go 语言 `crypto/sha512` 包中 SHA-512 系列哈希算法的实现。它使用了以下 Go 语言特性：

*   **`testing` 包:** 用于编写和运行测试。例如，`t.Errorf` 用于报告错误，`t.Run` 用于组织子测试。
*   **`hash` 包:**  `crypto/sha512` 包实现了 `hash.Hash` 接口，该接口定义了哈希算法的基本操作，如 `Write`, `Sum`, `Reset`, `Size`, `BlockSize`。
*   **`encoding/hex` 包:** 用于将字节数组编码为十六进制字符串，方便比较哈希值。
*   **`io` 包:**  `io.WriteString` 用于向哈希对象写入数据。
*   **`bytes` 包:** `bytes.Equal` 用于比较两个字节数组是否相等。
*   **`encoding` 包:** `encoding.BinaryMarshaler` 和 `encoding.BinaryUnmarshaler` 接口用于实现状态的序列化和反序列化。
*   **匿名函数:**  在 `TestGolden` 和 `TestHash` 中使用了匿名函数作为参数传递给 `cryptotest.TestAllImplementations`。
*   **变长参数 (Variadic Functions):** 虽然这段代码中没有直接体现，但 `t.Errorf` 可以接受变长参数。

**Go 代码举例 (状态序列化与反序列化):**

假设我们想测试 SHA-512 的状态序列化和反序列化功能。

```go
package main

import (
	"bytes"
	"crypto/sha512"
	"encoding"
	"fmt"
	"io"
	"log"
)

func main() {
	h1 := sha512.New()
	io.WriteString(h1, "一部分数据")

	// 序列化哈希对象的状态
	marshaler, ok := h1.(encoding.BinaryMarshaler)
	if !ok {
		log.Fatal("SHA-512 不支持 BinaryMarshaler")
	}
	state, err := marshaler.MarshalBinary()
	if err != nil {
		log.Fatalf("序列化失败: %v", err)
	}
	fmt.Printf("序列化后的状态: %x\n", state)

	// 创建一个新的哈希对象
	h2 := sha512.New()
	unmarshaler, ok := h2.(encoding.BinaryUnmarshaler)
	if !ok {
		log.Fatal("SHA-512 不支持 BinaryUnmarshaler")
	}

	// 反序列化状态到新的哈希对象
	err = unmarshaler.UnmarshalBinary(state)
	if err != nil {
		log.Fatalf("反序列化失败: %v", err)
	}

	// 继续向两个哈希对象写入剩余的数据
	io.WriteString(h1, "另一部分数据")
	io.WriteString(h2, "另一部分数据")

	// 计算最终的哈希值
	sum1 := h1.Sum(nil)
	sum2 := h2.Sum(nil)

	// 比较两个哈希值是否相等
	if bytes.Equal(sum1, sum2) {
		fmt.Println("状态序列化和反序列化成功，哈希值一致")
		fmt.Printf("哈希值: %x\n", sum1)
	} else {
		fmt.Println("状态序列化和反序列化失败，哈希值不一致")
		fmt.Printf("哈希值1: %x\n", sum1)
		fmt.Printf("哈希值2: %x\n", sum2)
	}
}
```

**假设的输入与输出 (基于黄金标准测试):**

假设 `golden512` 中有以下测试用例：

```go
{
    out: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    in:  "test",
}
```

`testGolden` 函数会执行以下操作：

1. 调用 `sha512.New()` 创建一个 SHA-512 哈希对象。
2. 将输入字符串 "test" 转换为字节数组。
3. 调用哈希对象的 `Write` 方法写入数据。
4. 调用哈希对象的 `Sum(nil)` 方法计算哈希值。
5. 将计算出的哈希值转换为十六进制字符串。
6. 将计算出的十六进制字符串与预期的输出 "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" 进行比较。

**3. 命令行参数处理:**

这段代码是测试代码，不涉及命令行参数的具体处理。Go 语言的测试通常使用 `go test` 命令运行，可以通过一些 flag 来控制测试行为，例如 `-v` (显示详细输出), `-run` (运行特定的测试函数)。 这些参数由 `go test` 命令本身处理，而不是由这段代码直接处理。

**4. 使用者易犯错的点:**

*   **混淆不同的 SHA-512 变体:** 使用者可能会错误地使用 `sha512.New()` 创建 SHA-512 哈希对象，但期望得到 SHA-512/256 的哈希值。应该根据需要选择正确的构造函数，例如 `sha512.New512_256()`, `sha512.New384()` 等。
    ```go
    // 错误示例：期望得到 SHA-512/256 的哈希值，但使用了 sha512.New()
    h := sha512.New()
    h.Write([]byte("hello"))
    hashValue := h.Sum(nil) // 这将是 SHA-512 的哈希值，而不是 SHA-512/256
    ```
    ```go
    // 正确示例：使用 sha512.New512_256() 获取 SHA-512/256 的哈希值
    h := sha512.New512_256()
    h.Write([]byte("hello"))
    hashValue := h.Sum(nil)
    ```
*   **忘记 `Reset()` 哈希对象:**  在多次使用同一个哈希对象进行哈希计算时，必须在每次计算前调用 `Reset()` 方法，以清除之前的状态。否则，后续的哈希计算会包含之前的数据。
    ```go
    h := sha512.New()
    h.Write([]byte("数据1"))
    hash1 := h.Sum(nil)

    // 忘记 Reset，hash2 将是 "数据1数据2" 的哈希值，而不是 "数据2" 的哈希值
    h.Write([]byte("数据2"))
    hash2 := h.Sum(nil)

    h.Reset() // 正确的做法
    h.Write([]byte("数据2"))
    hash3 := h.Sum(nil) // hash3 才是 "数据2" 的哈希值
    ```
*   **不正确地处理哈希值的输出格式:** 哈希值的 `Sum()` 方法返回的是 `[]byte`。使用者可能需要将其转换为十六进制字符串或其他格式进行展示或存储，需要使用 `encoding/hex` 或其他编码方式。

**5. 功能归纳 (针对第 4 部分):**

这是测试代码的最后一部分，主要包含了以下功能：

*   **内存分配测试 (`TestAllocations`):**  验证在进行 SHA-512 系列哈希运算时，是否产生了不必要的内存分配，确保代码的高效性。
*   **与其他实现的兼容性测试 (`TestHash`):**  通过 `cryptotest.TestAllImplementations` 框架，确保当前 Go 语言实现的 SHA-512 算法与其他可能的实现（例如，使用不同的库或语言实现）产生相同的哈希结果，保证了跨平台的兼容性。
*   **性能基准测试 (`BenchmarkHash...`):**  衡量了不同输入大小下 SHA-512 和 SHA-384 算法的性能，为性能优化提供数据支持。这些基准测试分别针对使用 `New()` 创建哈希对象并逐步写入数据的方式，以及直接使用 `Sum384()` 和 `Sum512()` 函数进行计算的方式进行了评估。

总的来说，这部分测试代码专注于**性能**、**内存使用**以及**与其他实现的兼容性**，是确保 `crypto/sha512` 包稳定可靠的重要组成部分。它覆盖了从基本的正确性验证到性能评估和跨平台兼容性检查的多个方面。

好的，让我们归纳一下你提供的这段 `go/src/crypto/sha512/sha512_test.go` 代码片段的功能，这是第 4 部分，也是最后一部分。

这部分代码主要集中在以下几个方面，以确保 `crypto/sha512` 包的质量和性能：

1. **内存分配测试 (TestAllocations):**
    *   该测试旨在验证在进行 SHA-512 系列哈希运算时，代码是否会产生不必要的内存分配。
    *   它使用 `testing.AllocsPerRun` 函数来统计在执行哈希操作期间的内存分配次数。
    *   测试了 `New`, `New512_224`, `New512_256`, `New384` 创建哈希对象，并通过 `Write` 和 `Sum` 方法计算哈希值的情况。
    *   同时测试了使用 `Sum512`, `Sum384`, `Sum512_224`, `Sum512_256` 等单次计算哈希值的函数的内存分配情况。
    *   期望的分配次数为 0，这表明哈希算法的实现应该是高效的，避免了不必要的内存开销。

2. **与其他实现的兼容性测试 (TestHash):**
    *   这部分测试利用了 `cryptotest.TestAllImplementations` 函数，这是一个用于测试密码学原语的标准框架。
    *   它会针对 SHA-384, SHA-512/224, SHA-512/256 和 SHA-512 这四个变体，调用 `cryptotest.TestHash` 函数。
    *   `cryptotest.TestHash` 的目的是验证当前的 SHA-512 实现是否与其他已知的正确实现（通常是基于 C 语言或其他语言的实现）产生相同的哈希结果。
    *   这确保了 Go 语言的 SHA-512 实现与其他系统和库的互操作性。

3. **性能基准测试 (Benchmarks):**
    *   这部分包含了基准测试函数，用于衡量 SHA-512 系列算法的性能。
    *   `benchmarkSize` 函数是一个辅助函数，用于在不同的输入大小下执行基准测试。
    *   它分别测试了使用 `New()` 创建哈希对象，然后通过 `Write` 方法写入数据并用 `Sum` 方法计算哈希值的情况，以及直接使用 `Sum384` 和 `Sum512` 函数计算哈希值的情况。
    *   `BenchmarkHash8Bytes`, `BenchmarkHash1K`, `BenchmarkHash8K` 等具体的基准测试函数会调用 `benchmarkSize` 函数，并传入不同的输入大小（8 字节，1KB，8KB）。
    *   这些基准测试可以帮助开发者了解在不同场景下 SHA-512 算法的性能表现，并为性能优化提供依据。

**总结:**

这最后一部分的测试代码主要关注 `crypto/sha512` 包的 **资源效率**（通过内存分配测试）、**正确性**（通过与其他实现的兼容性测试）以及 **性能**（通过基准测试）。它确保了该包不仅能够正确地计算哈希值，还具有良好的性能，并且可以与其他系统的 SHA-512 实现无缝集成。 这些测试是保证 Go 语言标准库中密码学组件质量的重要组成部分。

Prompt: 
```
这是路径为go/src/crypto/sha512/sha512_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第4部分，共4部分，请归纳一下它的功能

"""
e is proportional to its mole fraction.  Lewis-Randall Rule",
		"sha\aj\t\xe6g\xf3\xbc\xc9\b\xbbg\xae\x85\x84ʧ;<n\xf3r\xfe\x94\xf8+\xa5O\xf5:_\x1d6\xf1Q\x0eR\u007f\xad\xe6\x82ћ\x05h\x8c+>l\x1f\x1f\x83٫\xfbA\xbdk[\xe0\xcd\x19\x13~!yThe fugacity of a constituent in a mixture of gases at a given tem\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00B",
	},
	{
		"833f9248ab4a3b9e5131f745fda1ffd2dd435b30e965957e78291c7ab73605fd1912b0794e5c233ab0a12d205a39778d19b83515d6a47003f19cdee51d98c7e0",
		"How can you write a big system without C++?  -Paul Glick",
		"sha\aj\t\xe6g\xf3\xbc\xc9\b\xbbg\xae\x85\x84ʧ;<n\xf3r\xfe\x94\xf8+\xa5O\xf5:_\x1d6\xf1Q\x0eR\u007f\xad\xe6\x82ћ\x05h\x8c+>l\x1f\x1f\x83٫\xfbA\xbdk[\xe0\xcd\x19\x13~!yHow can you write a big syst\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c",
	},
}

func testHash(t *testing.T, name, in, outHex string, oneShotResult []byte, digestFunc hash.Hash) {
	if calculated := hex.EncodeToString(oneShotResult); calculated != outHex {
		t.Errorf("one-shot result for %s(%q) = %q, but expected %q", name, in, calculated, outHex)
		return
	}

	for pass := 0; pass < 3; pass++ {
		if pass < 2 {
			io.WriteString(digestFunc, in)
		} else {
			io.WriteString(digestFunc, in[:len(in)/2])
			digestFunc.Sum(nil)
			io.WriteString(digestFunc, in[len(in)/2:])
		}

		if calculated := hex.EncodeToString(digestFunc.Sum(nil)); calculated != outHex {
			t.Errorf("%s(%q) = %q (in pass #%d), but expected %q", name, in, calculated, pass, outHex)
		}
		digestFunc.Reset()
	}
}

func TestGolden(t *testing.T) {
	cryptotest.TestAllImplementations(t, "sha512", func(t *testing.T) {
		testGolden(t)
	})
}

func testGolden(t *testing.T) {
	tests := []struct {
		name        string
		oneShotHash func(in []byte) []byte
		digest      hash.Hash
		golden      []sha512Test
	}{
		{
			"SHA512/224",
			func(in []byte) []byte { a := Sum512_224(in); return a[:] },
			New512_224(),
			golden224,
		},
		{
			"SHA512/256",
			func(in []byte) []byte { a := Sum512_256(in); return a[:] },
			New512_256(),
			golden256,
		},
		{
			"SHA384",
			func(in []byte) []byte { a := Sum384(in); return a[:] },
			New384(),
			golden384,
		},
		{
			"SHA512",
			func(in []byte) []byte { a := Sum512(in); return a[:] },
			New(),
			golden512,
		},
	}
	for _, tt := range tests {
		for _, test := range tt.golden {
			in := []byte(test.in)
			testHash(t, tt.name, test.in, test.out, tt.oneShotHash(in), tt.digest)
		}
	}
}

func TestGoldenMarshal(t *testing.T) {
	cryptotest.TestAllImplementations(t, "sha512", func(t *testing.T) {
		testGoldenMarshal(t)
	})
}

func testGoldenMarshal(t *testing.T) {
	tests := []struct {
		name    string
		newHash func() hash.Hash
		golden  []sha512Test
	}{
		{"512/224", New512_224, golden224},
		{"512/256", New512_256, golden256},
		{"384", New384, golden384},
		{"512", New, golden512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, test := range tt.golden {
				h := tt.newHash()
				h2 := tt.newHash()

				io.WriteString(h, test.in[:len(test.in)/2])

				state, err := h.(encoding.BinaryMarshaler).MarshalBinary()
				if err != nil {
					t.Errorf("could not marshal: %v", err)
					return
				}

				stateAppend, err := h.(encoding.BinaryAppender).AppendBinary(make([]byte, 4, 32))
				if err != nil {
					t.Errorf("could not marshal: %v", err)
					return
				}
				stateAppend = stateAppend[4:]

				if string(state) != test.halfState {
					t.Errorf("New%s(%q) state = %q, want %q", tt.name, test.in, state, test.halfState)
					continue
				}

				if string(stateAppend) != test.halfState {
					t.Errorf("New%s(%q) stateAppend = %q, want %q", tt.name, test.in, stateAppend, test.halfState)
					continue
				}

				if err := h2.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
					t.Errorf("could not unmarshal: %v", err)
					return
				}

				io.WriteString(h, test.in[len(test.in)/2:])
				io.WriteString(h2, test.in[len(test.in)/2:])

				if actual, actual2 := h.Sum(nil), h2.Sum(nil); !bytes.Equal(actual, actual2) {
					t.Errorf("New%s(%q) = 0x%x != marshaled 0x%x", tt.name, test.in, actual, actual2)
				}
			}
		})
	}
}

func TestMarshalMismatch(t *testing.T) {
	h := []func() hash.Hash{
		New,
		New384,
		New512_224,
		New512_256,
	}

	for i, fn1 := range h {
		for j, fn2 := range h {
			if i == j {
				continue
			}

			h1 := fn1()
			h2 := fn2()

			state, err := h1.(encoding.BinaryMarshaler).MarshalBinary()
			if err != nil {
				t.Errorf("i=%d: could not marshal: %v", i, err)
				continue
			}

			if err := h2.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err == nil {
				t.Errorf("i=%d, j=%d: got no error, expected one: %v", i, j, err)
			}
		}
	}
}

func TestSize(t *testing.T) {
	c := New()
	if got := c.Size(); got != Size {
		t.Errorf("Size = %d; want %d", got, Size)
	}
	c = New384()
	if got := c.Size(); got != Size384 {
		t.Errorf("New384.Size = %d; want %d", got, Size384)
	}
	c = New512_224()
	if got := c.Size(); got != Size224 {
		t.Errorf("New512224.Size = %d; want %d", got, Size224)
	}
	c = New512_256()
	if got := c.Size(); got != Size256 {
		t.Errorf("New512256.Size = %d; want %d", got, Size256)
	}
}

func TestBlockSize(t *testing.T) {
	c := New()
	if got := c.BlockSize(); got != BlockSize {
		t.Errorf("BlockSize = %d; want %d", got, BlockSize)
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
	// Data length: 6_565_544_823
	{
		state: "sha\aηe\x0f\x0f\xe1r]#\aoJ!.{5B\xe4\x140\x91\xdd\x00a\xe1\xb3E&\xb9\xbb\aJ\x9f^\x9f\x03ͺD\x96H\x80\xb0X\x9d\xdeʸ\f\xf7:\xd5\xe6'\xb9\x93f\xddA\xf0~\xe1\x02\x14\x00\x01\x02\x03\x04\x05\x06\a\b\t\n\v\f\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuv\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x87VCw",
		sum:   "12d612357a1dbc74a28883dff79b83e7d2b881ae40d7a67fd7305490bc8a641cd1ce9ece598192080d6e9ac7e75d5988567a58a9812991299eb99a04ecb69523",
	},
	{
		state: "sha\a2\xd2\xdc\xf5\xd7\xe2\xf9\x97\xaa\xe7}Fϱ\xbc\x8e\xbf\x12h\x83Z\xa1\xc7\xf5p>bfS T\xea\xee\x1e\xa6Z\x9c\xa4ڶ\u0086\bn\xe47\x8fsGs3\xe0\xda\\\x9dqZ\xa5\xf6\xd0kM\xa1\xf2\x00\x01\x02\x03\x04\x05\x06\a\b\t\n\v\f\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuv\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xa7VCw",
		sum:   "94a04b9a901254cd94ca0313557e4be3ab1ca86e920c1f3efdc22d361e9ae12be66bc6d6dc5db79a0a4aa6eca6f293c1e9095bbae127ae405f6c325478343299",
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
	if n := testing.AllocsPerRun(10, func() {
		in := []byte("hello, world!")
		out := make([]byte, 0, Size)

		{
			h := New()
			h.Reset()
			h.Write(in)
			out = h.Sum(out[:0])
		}
		{
			h := New512_224()
			h.Reset()
			h.Write(in)
			out = h.Sum(out[:0])
		}
		{
			h := New512_256()
			h.Reset()
			h.Write(in)
			out = h.Sum(out[:0])
		}
		{
			h := New384()
			h.Reset()
			h.Write(in)
			out = h.Sum(out[:0])
		}

		Sum512(in)
		Sum384(in)
		Sum512_224(in)
		Sum512_256(in)
	}); n > 0 {
		t.Errorf("allocs = %v, want 0", n)
	}
}

func TestHash(t *testing.T) {
	t.Run("SHA-384", func(t *testing.T) {
		cryptotest.TestAllImplementations(t, "sha512", func(t *testing.T) {
			cryptotest.TestHash(t, New384)
		})
	})
	t.Run("SHA-512/224", func(t *testing.T) {
		cryptotest.TestAllImplementations(t, "sha512", func(t *testing.T) {
			cryptotest.TestHash(t, New512_224)
		})
	})
	t.Run("SHA-512/256", func(t *testing.T) {
		cryptotest.TestAllImplementations(t, "sha512", func(t *testing.T) {
			cryptotest.TestHash(t, New512_256)
		})
	})
	t.Run("SHA-512", func(t *testing.T) {
		cryptotest.TestAllImplementations(t, "sha512", func(t *testing.T) {
			cryptotest.TestHash(t, New)
		})
	})
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
	b.Run("Sum384", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(size))
		for i := 0; i < b.N; i++ {
			Sum384(buf[:size])
		}
	})
	b.Run("Sum512", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(size))
		for i := 0; i < b.N; i++ {
			Sum512(buf[:size])
		}
	})
}

func BenchmarkHash8Bytes(b *testing.B) {
	benchmarkSize(b, 8)
}

func BenchmarkHash1K(b *testing.B) {
	benchmarkSize(b, 1024)
}

func BenchmarkHash8K(b *testing.B) {
	benchmarkSize(b, 8192)
}

"""




```