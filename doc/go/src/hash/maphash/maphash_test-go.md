Response:
我的目标是理解给定的 Go 代码并解释其功能，并提供代码示例和潜在的错误用法。

**1. 理解代码结构和测试函数命名:**

首先，我注意到代码位于 `go/src/hash/maphash/maphash_test.go`，这是一个 Go 测试文件。文件名中的 `_test` 表明它包含用于测试 `maphash` 包功能的测试用例。  测试函数的命名模式是 `TestXxx`，这很标准。

**2. 分析每个测试函数:**

*   `TestUnseededHash`: 测试在没有显式设置种子的情况下，`Hash` 的 `Sum64()` 方法是否产生足够随机的哈希值。
*   `TestSeededHash`: 测试当使用 `SetSeed()` 设置相同的种子时，`Sum64()` 方法是否总是产生相同的哈希值。
*   `TestHashGrouping`: 测试使用 `Write`、`WriteString` 和 `WriteByte` 等不同方法写入相同数据是否产生相同的哈希值。 这也测试了 `Bytes` 和 `String` 函数的等效性。
*   `TestHashBytesVsString`: 测试使用 `WriteString` 写入字符串和使用 `Write` 写入相同内容的字节切片是否产生相同的哈希值。
*   `TestHashHighBytes`:  测试即使只取哈希值的高 32 位，对于不同的输入，哈希值是否也具有一定的区分度。
*   `TestRepeat`: 测试 `Reset()` 方法是否正确地重置了哈希状态，以及使用相同的种子是否总是产生相同的哈希值。
*   `TestSeedFromSum64`, `TestSeedFromSeed`, `TestSeedFromFlush`, `TestSeedFromReset`: 这几个测试用例都验证了一个重要的概念：`Hash` 结构体在某些操作后会生成或更新内部的种子。这些测试确保在这些操作后，使用相同的种子（通过 `Seed()` 获取）产生的哈希值是一致的。
*   `TestComparable`: 测试 `Comparable` 函数对于各种可比较类型是否返回一致的结果。 它还测试了相同值的不同表示（例如，分配在堆上的字符串）是否产生相同的哈希。
*   `TestWriteComparable`: 类似于 `TestComparable`，但测试的是 `WriteComparable` 函数，它将可比较类型的值写入 `Hash` 实例。
*   `TestComparableShouldPanic`: 测试 `Comparable` 函数在处理不可哈希的类型时是否会发生 panic。
*   `TestWriteComparableNoncommute`: 测试 `WriteComparable` 和 `WriteString` 的操作顺序是否会影响最终的哈希值，即验证操作是否不可交换。
*   `TestComparableAllocations`: 测试 `Comparable` 函数在处理某些类型时是否会产生不必要的堆分配。
*   `BenchmarkHash`:  基准测试不同大小的输入在使用 `Write`、`Bytes` 和 `String` 方法时的性能。
*   `BenchmarkComparable`: 基准测试 `Comparable` 函数在处理不同类型时的性能。

**3. 推理 `maphash` 包的功能:**

基于这些测试，我可以推断出 `maphash` 包提供了一种高效且灵活的方式来计算哈希值。 它允许：

*   使用或不使用种子来生成哈希值。
*   通过不同的方法（`Write`、`WriteString`、`WriteByte`）向哈希对象写入数据。
*   直接基于字节切片或字符串计算哈希值（`Bytes` 和 `String` 函数）。
*   基于任何可比较的 Go 类型计算哈希值 (`Comparable` 和 `WriteComparable` 函数)。
*   重用哈希对象 (`Reset()` 方法)。
*   访问和设置内部种子。

**4. 构造代码示例:**

根据对测试用例的理解，我可以创建展示 `maphash` 功能的示例代码。

**5. 识别易犯错误点:**

我注意到一些测试用例强调了种子管理的重要性。 如果不小心使用了不同的种子，即使输入相同，也会得到不同的哈希值。  此外，尝试对不可比较的类型使用 `Comparable` 或 `WriteComparable` 会导致 panic。

**6. 组织答案并使用中文:**

最后，我将我的理解组织成结构化的中文答案，包括功能列表、代码示例、对 `maphash` 功能的推理以及易犯错误点的说明。

通过以上思考过程，我能够理解并解释给定的 Go 代码的功能，并提供相应的示例和注意事项。
这段 Go 语言代码是 `go/src/hash/maphash/maphash_test.go` 文件的一部分，它主要用于测试 `maphash` 包的功能。 `maphash` 包提供了一种用于计算哈希值的机制，特别是在 Go 语言的 `map` 实现中用于键的哈希。

**这个测试文件的主要功能包括：**

1. **测试无种子的哈希生成：** 验证在不显式设置种子的情况下，`Hash` 结构体生成的哈希值是否具有足够的随机性。
2. **测试有种子的哈希生成：** 验证使用相同的种子初始化 `Hash` 结构体后，对于相同的输入，是否总是生成相同的哈希值。
3. **测试不同写入方式的一致性：** 验证使用 `Write`、`WriteString` 和 `WriteByte` 等不同方法写入相同的数据，是否会生成相同的哈希值。同时也测试了 `Bytes` 和 `String` 函数直接计算哈希值的功能。
4. **测试字节切片和字符串哈希的一致性：** 验证对相同内容的字节切片和字符串计算哈希值，是否会得到相同的结果。
5. **测试哈希值的高位：** 确保生成的哈希值的高位也具有一定的随机性，避免哈希冲突。
6. **测试 `Reset()` 方法的功能：** 验证 `Reset()` 方法是否能正确地重置哈希状态，使得对相同数据的哈希结果保持一致。
7. **测试种子的获取和设置：** 验证通过 `Sum64()`、`Seed()`、`Write()` (写入足够的数据后)、`Reset()` 等操作生成的种子，可以被 `SetSeed()` 方法正确地设置，并且使用相同的种子进行哈希会得到相同的结果。
8. **测试 `Comparable` 函数：** 测试 `Comparable` 函数是否能为可比较的 Go 类型生成一致的哈希值。它还测试了对于相同值的不同表示（例如，分配在堆上的字符串），`Comparable` 是否产生相同的哈希。
9. **测试 `WriteComparable` 函数：** 测试 `WriteComparable` 函数是否能将可比较的 Go 类型的值写入 `Hash` 结构体并生成相应的哈希值。
10. **测试 `Comparable` 函数的 panic 行为：** 验证当 `Comparable` 函数接收到不可哈希的类型时，是否会触发 panic。
11. **测试 `WriteComparable` 和其他写入操作的非交换性：** 验证 `WriteComparable` 和 `WriteString` 等操作的顺序是否会影响最终的哈希值。
12. **测试 `Comparable` 函数的内存分配：** 验证 `Comparable` 函数在处理某些类型时是否会产生不必要的堆分配。
13. **性能基准测试：**  测试不同大小的输入在使用 `Write`、`Bytes` 和 `String` 方法时的性能。同时也测试了 `Comparable` 函数在处理不同类型时的性能。
14. **接口实现检查：**  确保 `Hash` 结构体实现了 `hash.Hash` 和 `hash.Hash64` 接口。

**推理出它是什么 Go 语言功能的实现，并用 Go 代码举例说明:**

这段代码测试的是 `hash/maphash` 包，这个包提供了一种专门用于哈希映射（`map`）键的哈希函数。它旨在提供比标准库 `hash` 包更适合 `map` 场景的哈希算法。

**代码示例：**

```go
package main

import (
	"fmt"
	"hash/maphash"
)

func main() {
	var h maphash.Hash

	// 未设置种子，每次运行生成的哈希值可能不同
	fmt.Printf("Unseeded Hash for 'hello': %x\n", h.Sum64())

	h.WriteString("hello")
	hash1 := h.Sum64()
	fmt.Printf("Hash for 'hello': %x\n", hash1)

	h.Reset() // 重置哈希状态
	h.WriteString("world")
	hash2 := h.Sum64()
	fmt.Printf("Hash for 'world': %x\n", hash2)

	// 使用种子，相同的种子和输入会生成相同的哈希值
	var seed maphash.Seed = maphash.MakeSeed()
	h.SetSeed(seed)
	h.Reset()
	h.WriteString("hello")
	hash3 := h.Sum64()
	fmt.Printf("Seeded Hash for 'hello': %x\n", hash3)

	var h2 maphash.Hash
	h2.SetSeed(seed)
	h2.WriteString("hello")
	hash4 := h2.Sum64()
	fmt.Printf("Seeded Hash (same seed) for 'hello': %x\n", hash4)

	if hash3 == hash4 {
		fmt.Println("Hashes with the same seed are identical.")
	}

	// 使用 Bytes 函数直接计算字节切片的哈希
	data := []byte("example")
	hashBytes := maphash.Bytes(seed, data)
	fmt.Printf("Hash for []byte{'example'}: %x\n", hashBytes)

	// 使用 String 函数直接计算字符串的哈希
	str := "another"
	hashString := maphash.String(seed, str)
	fmt.Printf("Hash for 'another': %x\n", hashString)

	// 使用 Comparable 函数计算可比较类型的哈希
	number := 123
	hashComparable := maphash.Comparable(seed, number)
	fmt.Printf("Hash for int 123: %x\n", hashComparable)
}
```

**假设的输入与输出：**

由于未设置种子时哈希值是随机的，所以每次运行的结果可能不同。但使用相同种子时，结果会一致。

```
Unseeded Hash for 'hello': aabbccddeeff0011  // 每次运行可能不同
Hash for 'hello': 1234567890abcdef
Hash for 'world': fedcba0987654321
Seeded Hash for 'hello': 9876543210fedcba
Seeded Hash (same seed) for 'hello': 9876543210fedcba
Hashes with the same seed are identical.
Hash for []byte{'example'}: 5566778899aabbcc
Hash for 'another': ccbb4433221100ff
Hash for int 123: ddeeffaabbcc1122
```

**涉及命令行参数的具体处理：**

这段测试代码本身不涉及命令行参数的处理。它是一个 Go 测试文件，通常使用 `go test` 命令来运行。`go test` 命令有一些标准参数，例如 `-v` (显示详细输出), `-bench` (运行基准测试) 等，但这些参数是 `go test` 命令自身的，而不是被这段代码处理的。

**使用者易犯错的点：**

1. **忘记设置种子或使用不同的种子：**  如果期望对于相同的输入得到相同的哈希值，务必使用 `SetSeed()` 方法设置相同的种子。如果不设置种子，`Hash` 结构体内部会生成一个随机种子，导致每次运行的结果都可能不同。

    ```go
    package main

    import (
    	"fmt"
    	"hash/maphash"
    )

    func main() {
    	var h1 maphash.Hash
    	h1.WriteString("test")
    	hash1 := h1.Sum64()
    	fmt.Printf("Hash 1: %x\n", hash1)

    	var h2 maphash.Hash
    	h2.WriteString("test")
    	hash2 := h2.Sum64()
    	fmt.Printf("Hash 2: %x\n", hash2)

    	if hash1 == hash2 {
    		fmt.Println("意外：未设置种子时哈希值相同 (可能发生，但不保证).")
    	} else {
    		fmt.Println("正常：未设置种子时哈希值不同.")
    	}

    	seed := maphash.MakeSeed()
    	var h3 maphash.Hash
    	h3.SetSeed(seed)
    	h3.WriteString("test")
    	hash3 := h3.Sum64()
    	fmt.Printf("Hash 3 (with seed): %x\n", hash3)

    	var h4 maphash.Hash
    	h4.SetSeed(seed)
    	h4.WriteString("test")
    	hash4 := h4.Sum64()
    	fmt.Printf("Hash 4 (with same seed): %x\n", hash4)

    	if hash3 == hash4 {
    		fmt.Println("正确：使用相同种子时哈希值相同.")
    	}
    }
    ```

2. **对不可比较的类型使用 `Comparable` 或 `WriteComparable`：**  `Comparable` 和 `WriteComparable` 只能用于 Go 语言中可比较的类型（例如，基本类型、字符串、指针、数组、结构体等，但不包括切片、映射、函数）。对不可比较的类型使用这些函数会导致 panic。

    ```go
    package main

    import (
    	"fmt"
    	"hash/maphash"
    )

    func main() {
    	seed := maphash.MakeSeed()
    	slice := []int{1, 2, 3}

    	// 使用 Comparable 对切片进行哈希会导致 panic
    	defer func() {
    		if r := recover(); r != nil {
    			fmt.Println("捕获到 panic:", r)
    		}
    	}()

    	hash := maphash.Comparable(seed, slice) // 这里会发生 panic
    	fmt.Println("哈希值:", hash) // 不会被执行
    }
    ```

这段测试代码非常全面地覆盖了 `hash/maphash` 包的各种功能和边界情况，确保了这个包的正确性和健壮性。

### 提示词
```
这是路径为go/src/hash/maphash/maphash_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package maphash

import (
	"bytes"
	"fmt"
	"hash"
	"internal/asan"
	"math"
	"reflect"
	"strings"
	"testing"
	"unsafe"
)

func TestUnseededHash(t *testing.T) {
	m := map[uint64]struct{}{}
	for i := 0; i < 1000; i++ {
		h := new(Hash)
		m[h.Sum64()] = struct{}{}
	}
	if len(m) < 900 {
		t.Errorf("empty hash not sufficiently random: got %d, want 1000", len(m))
	}
}

func TestSeededHash(t *testing.T) {
	s := MakeSeed()
	m := map[uint64]struct{}{}
	for i := 0; i < 1000; i++ {
		h := new(Hash)
		h.SetSeed(s)
		m[h.Sum64()] = struct{}{}
	}
	if len(m) != 1 {
		t.Errorf("seeded hash is random: got %d, want 1", len(m))
	}
}

func TestHashGrouping(t *testing.T) {
	b := bytes.Repeat([]byte("foo"), 100)
	hh := make([]*Hash, 7)
	for i := range hh {
		hh[i] = new(Hash)
	}
	for _, h := range hh[1:] {
		h.SetSeed(hh[0].Seed())
	}
	hh[0].Write(b)
	hh[1].WriteString(string(b))

	writeByte := func(h *Hash, b byte) {
		err := h.WriteByte(b)
		if err != nil {
			t.Fatalf("WriteByte: %v", err)
		}
	}
	writeSingleByte := func(h *Hash, b byte) {
		_, err := h.Write([]byte{b})
		if err != nil {
			t.Fatalf("Write single byte: %v", err)
		}
	}
	writeStringSingleByte := func(h *Hash, b byte) {
		_, err := h.WriteString(string([]byte{b}))
		if err != nil {
			t.Fatalf("WriteString single byte: %v", err)
		}
	}

	for i, x := range b {
		writeByte(hh[2], x)
		writeSingleByte(hh[3], x)
		if i == 0 {
			writeByte(hh[4], x)
		} else {
			writeSingleByte(hh[4], x)
		}
		writeStringSingleByte(hh[5], x)
		if i == 0 {
			writeByte(hh[6], x)
		} else {
			writeStringSingleByte(hh[6], x)
		}
	}

	sum := hh[0].Sum64()
	for i, h := range hh {
		if sum != h.Sum64() {
			t.Errorf("hash %d not identical to a single Write", i)
		}
	}

	if sum1 := Bytes(hh[0].Seed(), b); sum1 != hh[0].Sum64() {
		t.Errorf("hash using Bytes not identical to a single Write")
	}

	if sum1 := String(hh[0].Seed(), string(b)); sum1 != hh[0].Sum64() {
		t.Errorf("hash using String not identical to a single Write")
	}
}

func TestHashBytesVsString(t *testing.T) {
	s := "foo"
	b := []byte(s)
	h1 := new(Hash)
	h2 := new(Hash)
	h2.SetSeed(h1.Seed())
	n1, err1 := h1.WriteString(s)
	if n1 != len(s) || err1 != nil {
		t.Fatalf("WriteString(s) = %d, %v, want %d, nil", n1, err1, len(s))
	}
	n2, err2 := h2.Write(b)
	if n2 != len(b) || err2 != nil {
		t.Fatalf("Write(b) = %d, %v, want %d, nil", n2, err2, len(b))
	}
	if h1.Sum64() != h2.Sum64() {
		t.Errorf("hash of string and bytes not identical")
	}
}

func TestHashHighBytes(t *testing.T) {
	// See issue 34925.
	const N = 10
	m := map[uint64]struct{}{}
	for i := 0; i < N; i++ {
		h := new(Hash)
		h.WriteString("foo")
		m[h.Sum64()>>32] = struct{}{}
	}
	if len(m) < N/2 {
		t.Errorf("from %d seeds, wanted at least %d different hashes; got %d", N, N/2, len(m))
	}
}

func TestRepeat(t *testing.T) {
	h1 := new(Hash)
	h1.WriteString("testing")
	sum1 := h1.Sum64()

	h1.Reset()
	h1.WriteString("testing")
	sum2 := h1.Sum64()

	if sum1 != sum2 {
		t.Errorf("different sum after resetting: %#x != %#x", sum1, sum2)
	}

	h2 := new(Hash)
	h2.SetSeed(h1.Seed())
	h2.WriteString("testing")
	sum3 := h2.Sum64()

	if sum1 != sum3 {
		t.Errorf("different sum on the same seed: %#x != %#x", sum1, sum3)
	}
}

func TestSeedFromSum64(t *testing.T) {
	h1 := new(Hash)
	h1.WriteString("foo")
	x := h1.Sum64() // seed generated here
	h2 := new(Hash)
	h2.SetSeed(h1.Seed())
	h2.WriteString("foo")
	y := h2.Sum64()
	if x != y {
		t.Errorf("hashes don't match: want %x, got %x", x, y)
	}
}

func TestSeedFromSeed(t *testing.T) {
	h1 := new(Hash)
	h1.WriteString("foo")
	_ = h1.Seed() // seed generated here
	x := h1.Sum64()
	h2 := new(Hash)
	h2.SetSeed(h1.Seed())
	h2.WriteString("foo")
	y := h2.Sum64()
	if x != y {
		t.Errorf("hashes don't match: want %x, got %x", x, y)
	}
}

func TestSeedFromFlush(t *testing.T) {
	b := make([]byte, 65)
	h1 := new(Hash)
	h1.Write(b) // seed generated here
	x := h1.Sum64()
	h2 := new(Hash)
	h2.SetSeed(h1.Seed())
	h2.Write(b)
	y := h2.Sum64()
	if x != y {
		t.Errorf("hashes don't match: want %x, got %x", x, y)
	}
}

func TestSeedFromReset(t *testing.T) {
	h1 := new(Hash)
	h1.WriteString("foo")
	h1.Reset() // seed generated here
	h1.WriteString("foo")
	x := h1.Sum64()
	h2 := new(Hash)
	h2.SetSeed(h1.Seed())
	h2.WriteString("foo")
	y := h2.Sum64()
	if x != y {
		t.Errorf("hashes don't match: want %x, got %x", x, y)
	}
}

func negativeZero[T float32 | float64]() T {
	var f T
	f = -f
	return f
}

func TestComparable(t *testing.T) {
	testComparable(t, int64(2))
	testComparable(t, uint64(8))
	testComparable(t, uintptr(12))
	testComparable(t, any("s"))
	testComparable(t, "s")
	testComparable(t, true)
	testComparable(t, new(float64))
	testComparable(t, float64(9))
	testComparable(t, complex128(9i+1))
	testComparable(t, struct{}{})
	testComparable(t, struct {
		i int
		u uint
		b bool
		f float64
		p *int
		a any
	}{i: 9, u: 1, b: true, f: 9.9, p: new(int), a: 1})
	type S struct {
		s string
	}
	s1 := S{s: heapStr(t)}
	s2 := S{s: heapStr(t)}
	if unsafe.StringData(s1.s) == unsafe.StringData(s2.s) {
		t.Fatalf("unexpected two heapStr ptr equal")
	}
	if s1.s != s2.s {
		t.Fatalf("unexpected two heapStr value not equal")
	}
	testComparable(t, s1, s2)
	testComparable(t, s1.s, s2.s)
	testComparable(t, float32(0), negativeZero[float32]())
	testComparable(t, float64(0), negativeZero[float64]())
	testComparableNoEqual(t, math.NaN(), math.NaN())
	testComparableNoEqual(t, [2]string{"a", ""}, [2]string{"", "a"})
	testComparableNoEqual(t, struct{ a, b string }{"foo", ""}, struct{ a, b string }{"", "foo"})
	testComparableNoEqual(t, struct{ a, b any }{int(0), struct{}{}}, struct{ a, b any }{struct{}{}, int(0)})
}

func testComparableNoEqual[T comparable](t *testing.T, v1, v2 T) {
	seed := MakeSeed()
	if Comparable(seed, v1) == Comparable(seed, v2) {
		t.Fatalf("Comparable(seed, %v) == Comparable(seed, %v)", v1, v2)
	}
}

var heapStrValue = []byte("aTestString")

func heapStr(t *testing.T) string {
	return string(heapStrValue)
}

func testComparable[T comparable](t *testing.T, v T, v2 ...T) {
	t.Run(reflect.TypeFor[T]().String(), func(t *testing.T) {
		var a, b T = v, v
		if len(v2) != 0 {
			b = v2[0]
		}
		var pa *T = &a
		seed := MakeSeed()
		if Comparable(seed, a) != Comparable(seed, b) {
			t.Fatalf("Comparable(seed, %v) != Comparable(seed, %v)", a, b)
		}
		old := Comparable(seed, pa)
		stackGrow(8192)
		new := Comparable(seed, pa)
		if old != new {
			t.Fatal("Comparable(seed, ptr) != Comparable(seed, ptr)")
		}
	})
}

var use byte

//go:noinline
func stackGrow(dep int) {
	if dep == 0 {
		return
	}
	var local [1024]byte
	// make sure local is allocated on the stack.
	local[randUint64()%1024] = byte(randUint64())
	use = local[randUint64()%1024]
	stackGrow(dep - 1)
}

func TestWriteComparable(t *testing.T) {
	testWriteComparable(t, int64(2))
	testWriteComparable(t, uint64(8))
	testWriteComparable(t, uintptr(12))
	testWriteComparable(t, any("s"))
	testWriteComparable(t, "s")
	testComparable(t, true)
	testWriteComparable(t, new(float64))
	testWriteComparable(t, float64(9))
	testWriteComparable(t, complex128(9i+1))
	testWriteComparable(t, struct{}{})
	testWriteComparable(t, struct {
		i int
		u uint
		b bool
		f float64
		p *int
		a any
	}{i: 9, u: 1, b: true, f: 9.9, p: new(int), a: 1})
	type S struct {
		s string
	}
	s1 := S{s: heapStr(t)}
	s2 := S{s: heapStr(t)}
	if unsafe.StringData(s1.s) == unsafe.StringData(s2.s) {
		t.Fatalf("unexpected two heapStr ptr equal")
	}
	if s1.s != s2.s {
		t.Fatalf("unexpected two heapStr value not equal")
	}
	testWriteComparable(t, s1, s2)
	testWriteComparable(t, s1.s, s2.s)
	testWriteComparable(t, float32(0), negativeZero[float32]())
	testWriteComparable(t, float64(0), negativeZero[float64]())
	testWriteComparableNoEqual(t, math.NaN(), math.NaN())
	testWriteComparableNoEqual(t, [2]string{"a", ""}, [2]string{"", "a"})
	testWriteComparableNoEqual(t, struct{ a, b string }{"foo", ""}, struct{ a, b string }{"", "foo"})
	testWriteComparableNoEqual(t, struct{ a, b any }{int(0), struct{}{}}, struct{ a, b any }{struct{}{}, int(0)})
}

func testWriteComparableNoEqual[T comparable](t *testing.T, v1, v2 T) {
	seed := MakeSeed()
	h1 := Hash{}
	h2 := Hash{}
	h1.seed, h2.seed = seed, seed
	WriteComparable(&h1, v1)
	WriteComparable(&h2, v2)
	if h1.Sum64() == h2.Sum64() {
		t.Fatalf("WriteComparable(seed, %v) == WriteComparable(seed, %v)", v1, v2)
	}

}

func testWriteComparable[T comparable](t *testing.T, v T, v2 ...T) {
	t.Run(reflect.TypeFor[T]().String(), func(t *testing.T) {
		var a, b T = v, v
		if len(v2) != 0 {
			b = v2[0]
		}
		var pa *T = &a
		h1 := Hash{}
		h2 := Hash{}
		h1.seed = MakeSeed()
		h2.seed = h1.seed
		WriteComparable(&h1, a)
		WriteComparable(&h2, b)
		if h1.Sum64() != h2.Sum64() {
			t.Fatalf("WriteComparable(h, %v) != WriteComparable(h, %v)", a, b)
		}
		WriteComparable(&h1, pa)
		old := h1.Sum64()
		stackGrow(8192)
		WriteComparable(&h2, pa)
		new := h2.Sum64()
		if old != new {
			t.Fatal("WriteComparable(seed, ptr) != WriteComparable(seed, ptr)")
		}
	})
}

func TestComparableShouldPanic(t *testing.T) {
	s := []byte("s")
	a := any(s)
	defer func() {
		e := recover()
		err, ok := e.(error)
		if !ok {
			t.Fatalf("Comaparable(any([]byte)) should panic")
		}
		want := "hash of unhashable type []uint8"
		if s := err.Error(); !strings.Contains(s, want) {
			t.Fatalf("want %s, got %s", want, s)
		}
	}()
	Comparable(MakeSeed(), a)
}

func TestWriteComparableNoncommute(t *testing.T) {
	seed := MakeSeed()
	var h1, h2 Hash
	h1.SetSeed(seed)
	h2.SetSeed(seed)

	h1.WriteString("abc")
	WriteComparable(&h1, 123)
	WriteComparable(&h2, 123)
	h2.WriteString("abc")

	if h1.Sum64() == h2.Sum64() {
		t.Errorf("WriteComparable and WriteString unexpectedly commute")
	}
}

func TestComparableAllocations(t *testing.T) {
	if purego {
		t.Skip("skip allocation test in purego mode - reflect-based implementation allocates more")
	}
	if asan.Enabled {
		t.Skip("skip allocation test under -asan")
	}
	seed := MakeSeed()
	x := heapStr(t)
	allocs := testing.AllocsPerRun(10, func() {
		s := "s" + x
		Comparable(seed, s)
	})
	if allocs > 0 {
		t.Errorf("got %v allocs, want 0", allocs)
	}

	type S struct {
		a int
		b string
	}
	allocs = testing.AllocsPerRun(10, func() {
		s := S{123, "s" + x}
		Comparable(seed, s)
	})
	if allocs > 0 {
		t.Errorf("got %v allocs, want 0", allocs)
	}
}

// Make sure a Hash implements the hash.Hash and hash.Hash64 interfaces.
var _ hash.Hash = &Hash{}
var _ hash.Hash64 = &Hash{}

func benchmarkSize(b *testing.B, size int) {
	h := &Hash{}
	buf := make([]byte, size)
	s := string(buf)

	b.Run("Write", func(b *testing.B) {
		b.SetBytes(int64(size))
		for i := 0; i < b.N; i++ {
			h.Reset()
			h.Write(buf)
			h.Sum64()
		}
	})

	b.Run("Bytes", func(b *testing.B) {
		b.SetBytes(int64(size))
		seed := h.Seed()
		for i := 0; i < b.N; i++ {
			Bytes(seed, buf)
		}
	})

	b.Run("String", func(b *testing.B) {
		b.SetBytes(int64(size))
		seed := h.Seed()
		for i := 0; i < b.N; i++ {
			String(seed, s)
		}
	})
}

func BenchmarkHash(b *testing.B) {
	sizes := []int{4, 8, 16, 32, 64, 256, 320, 1024, 4096, 16384}
	for _, size := range sizes {
		b.Run(fmt.Sprint("n=", size), func(b *testing.B) {
			benchmarkSize(b, size)
		})
	}
}

func benchmarkComparable[T comparable](b *testing.B, v T) {
	b.Run(reflect.TypeFor[T]().String(), func(b *testing.B) {
		seed := MakeSeed()
		for i := 0; i < b.N; i++ {
			Comparable(seed, v)
		}
	})
}

func BenchmarkComparable(b *testing.B) {
	type testStruct struct {
		i int
		u uint
		b bool
		f float64
		p *int
		a any
	}
	benchmarkComparable(b, int64(2))
	benchmarkComparable(b, uint64(8))
	benchmarkComparable(b, uintptr(12))
	benchmarkComparable(b, any("s"))
	benchmarkComparable(b, "s")
	benchmarkComparable(b, true)
	benchmarkComparable(b, new(float64))
	benchmarkComparable(b, float64(9))
	benchmarkComparable(b, complex128(9i+1))
	benchmarkComparable(b, struct{}{})
	benchmarkComparable(b, testStruct{i: 9, u: 1, b: true, f: 9.9, p: new(int), a: 1})
}
```