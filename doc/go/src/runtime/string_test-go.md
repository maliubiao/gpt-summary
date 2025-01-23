Response:
Let's break down the thought process to analyze the provided Go code snippet.

1. **Understand the Goal:** The request asks for an analysis of a Go test file (`string_test.go`). The core tasks are to identify the file's functionalities, infer the underlying Go features being tested, provide code examples, discuss command-line arguments (if any), and highlight common pitfalls.

2. **Initial Scan for Keywords:** Look for keywords that indicate the file's purpose. `Benchmark`, `Test`, and import statements like `runtime`, `strconv`, `strings`, `testing`, and `unicode/utf8` are strong clues. This immediately tells us it's a testing file focusing on string and related functionalities within the `runtime` package.

3. **Categorize the Tests and Benchmarks:** Go through each function and try to categorize its purpose:

    * **Benchmarks:** Functions starting with `Benchmark` are performance tests. Notice patterns like `BenchmarkCompareString...`, `BenchmarkRuneCount`, `BenchmarkSliceByteToString`, etc. These clearly aim to measure the efficiency of various string operations.

    * **Tests:** Functions starting with `Test` are unit tests verifying the correctness of specific functionalities. Examples are `TestStringW`, `TestLargeStringConcat`, `TestAtoi`, `TestParseByteCount`, etc.

4. **Analyze Benchmarks (Focus on Performance):**

    * **String Comparison:** `BenchmarkCompareStringEqual`, `BenchmarkCompareStringIdentical`, `BenchmarkCompareStringSameLength`, `BenchmarkCompareStringDifferentLength`, `BenchmarkCompareStringBigUnaligned`, `BenchmarkCompareStringBig`. These are clearly testing the performance of different scenarios for comparing strings. Think about the underlying mechanisms: pointer comparison for identical strings, byte-by-byte comparison for equal strings, and optimizations for length differences.

    * **String Concatenation:** `BenchmarkConcatStringAndBytes`. This targets the performance of concatenating a string and a byte slice. Consider how Go handles string immutability and potential optimizations.

    * **String/Byte Slice Conversion:** `BenchmarkSliceByteToString`. This measures the performance of converting a byte slice to a string.

    * **Rune Counting:** `BenchmarkRuneCount`, `BenchmarkRuneIterate`. These focus on how to count runes (Unicode code points) in strings efficiently, comparing different approaches like `len([]rune(s))`, `range` loops, and `utf8.RuneCountInString`.

    * **Array Comparison:** `BenchmarkArrayEqual`. While not strictly strings, this benchmark provides a comparison point to understand how Go handles array equality.

5. **Analyze Tests (Focus on Correctness):**

    * **`TestStringW`:**  The comment and the code itself suggest this tests the `runtime.GostringW` function, which converts a slice of `uint16` (representing UTF-16) to a Go string. The test iterates through strings, converts them to `uint16` slices, and then back using `GostringW`.

    * **`TestLargeStringConcat`:** This test appears to verify how Go handles the concatenation of very large strings, likely checking for panics or unexpected behavior. The `runTestProg` function hints at running a separate program to test this.

    * **Temporary String Optimizations:** `TestConcatTempString`, `TestCompareTempString`, `TestStringIndexHaystack`, `TestStringIndexNeedle`, `TestRangeStringCast`. These tests use `testing.AllocsPerRun` which is a strong indicator they are checking for *zero allocations* in specific scenarios involving temporary string creation and usage. This points to compiler optimizations that avoid unnecessary heap allocations.

    * **Stack Allocation:** `TestStringOnStack`. This test seems to verify that small strings can be allocated on the stack instead of the heap for performance.

    * **Integer to String Conversion:** `TestIntString`, `TestIntStringAllocs`. These test the efficiency of converting integers to strings, again looking for zero allocations in some cases.

    * **String to Slice Conversion (Zeroing):** `TestString2Slice`. This specifically checks that when converting a string to a byte or rune slice, the unused capacity of the slice is zeroed out, preventing potential information leaks.

    * **String to Integer Conversion:** `TestAtoi`, `TestAtoi32`. These test the `runtime.Atoi` and `runtime.Atoi32` functions, verifying their correctness for various valid and invalid integer string inputs, including edge cases like overflows and underflows.

    * **Parsing Byte Counts:** `TestParseByteCount`. This tests a function that parses human-readable byte counts (like "10KiB", "1GB") into integer values. It covers valid and invalid inputs, including different suffixes.

6. **Infer Go Features:** Based on the analysis of tests and benchmarks, we can infer the Go features being tested:

    * String representation and comparison
    * String concatenation
    * Byte slice to string conversion
    * Rune handling and iteration
    * UTF-16 to UTF-8 conversion (`runtime.GostringW`)
    * Compiler optimizations for temporary strings and stack allocation
    * Integer to string and string to integer conversions
    * Parsing human-readable byte counts

7. **Construct Code Examples:** For the inferred features, provide simple Go code examples to illustrate their usage. This makes the explanation more concrete.

8. **Command-Line Arguments:**  Carefully examine the code. There are no direct uses of `os.Args` or the `flag` package within this snippet, so conclude that it doesn't directly handle command-line arguments. However, mention that `go test` itself has command-line arguments.

9. **Common Pitfalls:** Think about common mistakes developers might make when working with strings in Go, based on the tests:

    * **Inefficient Rune Counting:** Using `len([]rune(s))` when `utf8.RuneCountInString(s)` is more efficient.
    * **Assuming String Mutability:**  Strings are immutable; concatenation creates new strings.
    * **Incorrectly Parsing Byte Counts:**  Not handling different suffixes or invalid inputs.

10. **Structure the Answer:** Organize the findings logically using clear headings and bullet points. Start with a general overview, then delve into specific functionalities, provide code examples, and finally address command-line arguments and potential pitfalls. Use clear and concise language.

11. **Review and Refine:**  Read through the entire analysis to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas that could be explained better. For example, explicitly mentioning that this is *part* of the file is important.

This systematic approach, moving from high-level understanding to detailed analysis and finally to synthesis and presentation, allows for a comprehensive and accurate explanation of the provided Go code.
这段代码是 Go 语言 `runtime` 包中 `string_test.go` 文件的一部分，它的主要功能是 **测试和基准测试 Go 语言中字符串相关的实现和性能**。

具体来说，它涵盖了以下几个方面的功能：

**1. 字符串比较的性能测试 (Benchmarks for String Comparison):**

* **`BenchmarkCompareStringEqual`**: 测试比较两个内容相同的字符串的性能。这两个字符串是通过将相同的字节切片转换为字符串创建的。
* **`BenchmarkCompareStringIdentical`**: 测试比较两个指向内存中同一位置的字符串（因为一个字符串赋值给另一个）的性能。
* **`BenchmarkCompareStringSameLength`**: 测试比较两个长度相同但内容不同的字符串的性能。
* **`BenchmarkCompareStringDifferentLength`**: 测试比较两个长度不同的字符串的性能。
* **`BenchmarkCompareStringBigUnaligned`**: 测试比较两个大型字符串的性能，其中一个字符串是另一个字符串的子串（未对齐）。
* **`BenchmarkCompareStringBig`**: 测试比较两个大型且内容相同的字符串的性能。

**2. 字符串拼接的性能测试 (Benchmarks for String Concatenation):**

* **`BenchmarkConcatStringAndBytes`**: 测试将字符串和字节切片拼接的性能。

**3. 字节切片转换为字符串的性能测试 (Benchmarks for Byte Slice to String Conversion):**

* **`BenchmarkSliceByteToString`**: 测试将不同长度的字节切片转换为字符串的性能。它使用 `testing.B.Run` 创建了多个子基准测试，分别针对不同长度的字节切片。

**4. 计算字符串中 Rune (Unicode 码点) 数量的性能测试 (Benchmarks for Rune Counting):**

* **`BenchmarkRuneCount`**: 比较了三种计算字符串中 Rune 数量的方法的性能：
    * 将字符串转换为 `[]rune` 并取长度 (`lenruneslice`).
    * 使用 `range` 循环遍历字符串 (`rangeloop`).
    * 使用 `utf8.RuneCountInString` 函数 (`utf8.RuneCountInString`).
* **`BenchmarkRuneIterate`**:  测试使用 `range` 循环遍历字符串的性能。

**5. 数组比较的性能测试 (Benchmark for Array Comparison):**

* **`BenchmarkArrayEqual`**:  测试比较两个内容相同的字节数组的性能。虽然不是直接关于字符串，但可以作为对比。

**6. `runtime.GostringW` 的功能测试 (Tests for `runtime.GostringW`):**

* **`TestStringW`**: 测试 `runtime.GostringW` 函数，该函数将一个 `uint16` 类型的切片转换为 Go 字符串。这通常用于处理 Windows 上的字符串（UTF-16 编码）。

**7. 大型字符串拼接的测试 (Tests for Large String Concatenation):**

* **`TestLargeStringConcat`**: 测试当拼接非常大的字符串时，Go 运行时是否能够正确处理，并检查是否会发生预期的 panic。它依赖于运行一个名为 "testprog" 的外部程序。

**8. 临时字符串优化的测试 (Tests for Temporary String Optimizations):**

* **`TestConcatTempString`**: 测试当拼接一个临时的由字节切片转换来的字符串时，是否会发生额外的内存分配。期望没有额外的分配，因为编译器可能会优化这种情况。
* **`TestCompareTempString`**: 测试当比较一个临时的由字节切片转换来的字符串时，是否会发生额外的内存分配。期望没有额外的分配。
* **`TestStringIndexHaystack` 和 `TestStringIndexNeedle`**: 测试 `strings.Index` 函数在 haystack 或 needle 是由字节切片临时转换来的字符串时，是否会发生额外的内存分配。

**9. 栈上字符串分配的测试 (Tests for String Allocation on Stack):**

* **`TestStringOnStack`**: 测试在某些情况下，Go 编译器是否会将小的字符串分配在栈上以提高性能。

**10. 整型转换为字符串的测试 (Tests for Integer to String Conversion):**

* **`TestIntString`**: 测试将整型转换为字符串的性能，并区分结果是否逃逸到堆上。
* **`TestIntStringAllocs`**: 测试将整型转换为字符串时是否会发生内存分配。

**11. 字符串到字节切片转换的测试 (Tests for String to Byte Slice Conversion):**

* **`TestRangeStringCast`**: 测试使用 `range` 循环遍历由字符串转换来的字节切片时，访问元素是否与直接访问字符串元素相同，并检查是否发生额外的内存分配。
* **`TestString2Slice`**:  测试将字符串转换为字节切片或 Rune 切片时，确保切片的容量大于长度的部分被零值填充，防止潜在的信息泄露。

**12. 字符串到整型转换的测试 (Tests for String to Integer Conversion):**

* **`TestAtoi` 和 `TestAtoi32`**: 测试 `runtime.Atoi` 和 `runtime.Atoi32` 函数，这两个函数将字符串转换为整型。测试用例包括各种有效和无效的输入，以及边界情况。

**13. 解析字节计数的测试 (Tests for Parsing Byte Counts):**

* **`TestParseByteCount`**: 测试 `runtime.ParseByteCount` 函数，该函数将包含单位 (如 "10K", "10MiB") 的字符串解析为字节数。测试用例涵盖了各种有效和无效的输入格式。

**推断的 Go 语言功能实现：**

这段代码主要测试和基准测试了 Go 语言中以下核心的字符串相关功能：

* **字符串的内部表示和比较:**  通过比较不同创建方式和大小的字符串，测试 Go 运行时比较字符串的效率。
* **字符串的拼接:** 测试字符串拼接操作的性能，以及编译器可能进行的优化。
* **字符串和字节切片的相互转换:** 测试这两种类型之间的转换效率和内存分配行为。
* **Unicode 支持 (Rune):** 测试 Go 如何处理 Unicode 字符，以及计算字符串中 Rune 数量的不同方法的性能。
* **平台特定的字符串处理 (`runtime.GostringW`):**  测试与操作系统相关的字符串处理，例如 Windows 上的 UTF-16 字符串。
* **编译器优化:**  通过 `testing.AllocsPerRun` 来验证编译器在处理临时字符串和栈上分配方面的优化。
* **字符串与整型之间的转换:** 测试 `strconv` 包中 `Atoi` 等函数的底层实现 (在 `runtime` 包中也有对应实现)。
* **解析人类可读的字节计数:** 测试解析包含单位的字符串为数字的功能。

**Go 代码示例：**

**字符串比较:**

```go
package main

import "fmt"

func main() {
	s1 := "hello"
	s2 := "hello"
	s3 := "world"

	fmt.Println(s1 == s2) // 输出: true
	fmt.Println(s1 == s3) // 输出: false
}
```

**假设的输入与输出 (基于 `TestAtoi`):**

假设调用 `runtime.Atoi` 函数：

* **输入:** `"123"`
* **输出:** `(123, true)`  // 返回整型 123 和表示转换成功的布尔值 true

* **输入:** `"abc"`
* **输出:** `(0, false)` // 返回整型 0 和表示转换失败的布尔值 false

* **输入:** `"9223372036854775808"` (超出 int64 最大值)
* **输出:** `(0, false)` // 返回整型 0 和表示转换失败的布尔值 false

**命令行参数：**

这段代码本身是一个测试文件，并不直接处理命令行参数。但是，当你运行 Go 测试时，可以使用 `go test` 命令，该命令有很多选项，例如：

* **`-bench`**:  运行基准测试。例如：`go test -bench=.`  会运行所有的基准测试。
* **`-run`**: 运行指定的测试函数。例如：`go test -run=TestAtoi` 只运行名为 `TestAtoi` 的测试函数。
* **`-v`**:  显示更详细的测试输出。

**使用者易犯错的点 (基于代码推理):**

* **不了解字符串比较的性能差异:** 开发者可能会认为所有字符串比较的性能都是相同的，但实际上，比较指向同一内存地址的字符串 (`BenchmarkCompareStringIdentical`) 比比较内容相同的字符串 (`BenchmarkCompareStringEqual`) 要快得多。理解这些差异可以帮助优化代码。

* **在性能敏感的场景下频繁进行字符串和字节切片的转换:**  虽然转换操作很方便，但在循环或高频调用的代码中，频繁地 `string(byteSlice)` 或 `[]byte(string)` 可能会导致不必要的内存分配。`TestConcatTempString` 等测试就旨在验证在某些情况下编译器是否能优化掉这些分配。

* **不了解计算 Rune 数量的不同方法及其性能影响:**  简单地使用 `len([]rune(s))` 来计算 Rune 数量在处理包含大量非 ASCII 字符的字符串时可能效率较低。`utf8.RuneCountInString(s)` 通常是更高效的选择。

* **假设字符串是可变的:** Go 中的字符串是不可变的。任何修改字符串的操作（例如拼接）都会创建一个新的字符串。这可能会导致意外的内存分配和性能问题，尤其是在大量拼接字符串时。

* **在需要高效处理 Unicode 字符时，不使用 `range` 循环或 `utf8` 包提供的函数:**  直接通过索引访问字符串的字节可能会导致处理多字节字符时出现错误。`range` 循环可以正确地迭代 Unicode 字符。

总而言之，这段代码是 Go 运行时中非常重要的组成部分，它确保了字符串相关功能的正确性、稳定性和性能。通过这些测试和基准测试，Go 语言的开发者可以不断优化字符串的实现，为用户提供更高效的编程体验。

### 提示词
```
这是路径为go/src/runtime/string_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime_test

import (
	"runtime"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// Strings and slices that don't escape and fit into tmpBuf are stack allocated,
// which defeats using AllocsPerRun to test other optimizations.
const sizeNoStack = 100

func BenchmarkCompareStringEqual(b *testing.B) {
	bytes := []byte("Hello Gophers!")
	s1, s2 := string(bytes), string(bytes)
	for i := 0; i < b.N; i++ {
		if s1 != s2 {
			b.Fatal("s1 != s2")
		}
	}
}

func BenchmarkCompareStringIdentical(b *testing.B) {
	s1 := "Hello Gophers!"
	s2 := s1
	for i := 0; i < b.N; i++ {
		if s1 != s2 {
			b.Fatal("s1 != s2")
		}
	}
}

func BenchmarkCompareStringSameLength(b *testing.B) {
	s1 := "Hello Gophers!"
	s2 := "Hello, Gophers"
	for i := 0; i < b.N; i++ {
		if s1 == s2 {
			b.Fatal("s1 == s2")
		}
	}
}

func BenchmarkCompareStringDifferentLength(b *testing.B) {
	s1 := "Hello Gophers!"
	s2 := "Hello, Gophers!"
	for i := 0; i < b.N; i++ {
		if s1 == s2 {
			b.Fatal("s1 == s2")
		}
	}
}

func BenchmarkCompareStringBigUnaligned(b *testing.B) {
	bytes := make([]byte, 0, 1<<20)
	for len(bytes) < 1<<20 {
		bytes = append(bytes, "Hello Gophers!"...)
	}
	s1, s2 := string(bytes), "hello"+string(bytes)
	for i := 0; i < b.N; i++ {
		if s1 != s2[len("hello"):] {
			b.Fatal("s1 != s2")
		}
	}
	b.SetBytes(int64(len(s1)))
}

func BenchmarkCompareStringBig(b *testing.B) {
	bytes := make([]byte, 0, 1<<20)
	for len(bytes) < 1<<20 {
		bytes = append(bytes, "Hello Gophers!"...)
	}
	s1, s2 := string(bytes), string(bytes)
	for i := 0; i < b.N; i++ {
		if s1 != s2 {
			b.Fatal("s1 != s2")
		}
	}
	b.SetBytes(int64(len(s1)))
}

func BenchmarkConcatStringAndBytes(b *testing.B) {
	s1 := []byte("Gophers!")
	for i := 0; i < b.N; i++ {
		_ = "Hello " + string(s1)
	}
}

var escapeString string

func BenchmarkSliceByteToString(b *testing.B) {
	buf := []byte{'!'}
	for n := 0; n < 8; n++ {
		b.Run(strconv.Itoa(len(buf)), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				escapeString = string(buf)
			}
		})
		buf = append(buf, buf...)
	}
}

var stringdata = []struct{ name, data string }{
	{"ASCII", "01234567890"},
	{"Japanese", "日本語日本語日本語"},
	{"MixedLength", "$Ѐࠀက퀀𐀀\U00040000\U0010FFFF"},
}

var sinkInt int

func BenchmarkRuneCount(b *testing.B) {
	// Each sub-benchmark counts the runes in a string in a different way.
	b.Run("lenruneslice", func(b *testing.B) {
		for _, sd := range stringdata {
			b.Run(sd.name, func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					sinkInt += len([]rune(sd.data))
				}
			})
		}
	})
	b.Run("rangeloop", func(b *testing.B) {
		for _, sd := range stringdata {
			b.Run(sd.name, func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					n := 0
					for range sd.data {
						n++
					}
					sinkInt += n
				}
			})
		}
	})
	b.Run("utf8.RuneCountInString", func(b *testing.B) {
		for _, sd := range stringdata {
			b.Run(sd.name, func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					sinkInt += utf8.RuneCountInString(sd.data)
				}
			})
		}
	})
}

func BenchmarkRuneIterate(b *testing.B) {
	b.Run("range", func(b *testing.B) {
		for _, sd := range stringdata {
			b.Run(sd.name, func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					for range sd.data {
					}
				}
			})
		}
	})
	b.Run("range1", func(b *testing.B) {
		for _, sd := range stringdata {
			b.Run(sd.name, func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					for range sd.data {
					}
				}
			})
		}
	})
	b.Run("range2", func(b *testing.B) {
		for _, sd := range stringdata {
			b.Run(sd.name, func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					for range sd.data {
					}
				}
			})
		}
	})
}

func BenchmarkArrayEqual(b *testing.B) {
	a1 := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	a2 := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if a1 != a2 {
			b.Fatal("not equal")
		}
	}
}

func TestStringW(t *testing.T) {
	strings := []string{
		"hello",
		"a\u5566\u7788b",
	}

	for _, s := range strings {
		var b []uint16
		for _, c := range s {
			b = append(b, uint16(c))
			if c != rune(uint16(c)) {
				t.Errorf("bad test: stringW can't handle >16 bit runes")
			}
		}
		b = append(b, 0)
		r := runtime.GostringW(b)
		if r != s {
			t.Errorf("gostringW(%v) = %s, want %s", b, r, s)
		}
	}
}

func TestLargeStringConcat(t *testing.T) {
	output := runTestProg(t, "testprog", "stringconcat")
	want := "panic: " + strings.Repeat("0", 1<<10) + strings.Repeat("1", 1<<10) +
		strings.Repeat("2", 1<<10) + strings.Repeat("3", 1<<10)
	if !strings.HasPrefix(output, want) {
		t.Fatalf("output does not start with %q:\n%s", want, output)
	}
}

func TestConcatTempString(t *testing.T) {
	s := "bytes"
	b := []byte(s)
	n := testing.AllocsPerRun(1000, func() {
		if "prefix "+string(b)+" suffix" != "prefix bytes suffix" {
			t.Fatalf("strings are not equal: '%v' and '%v'", "prefix "+string(b)+" suffix", "prefix bytes suffix")
		}
	})
	if n != 0 {
		t.Fatalf("want 0 allocs, got %v", n)
	}
}

func TestCompareTempString(t *testing.T) {
	s := strings.Repeat("x", sizeNoStack)
	b := []byte(s)
	n := testing.AllocsPerRun(1000, func() {
		if string(b) != s {
			t.Fatalf("strings are not equal: '%v' and '%v'", string(b), s)
		}
		if string(b) < s {
			t.Fatalf("strings are not equal: '%v' and '%v'", string(b), s)
		}
		if string(b) > s {
			t.Fatalf("strings are not equal: '%v' and '%v'", string(b), s)
		}
		if string(b) == s {
		} else {
			t.Fatalf("strings are not equal: '%v' and '%v'", string(b), s)
		}
		if string(b) <= s {
		} else {
			t.Fatalf("strings are not equal: '%v' and '%v'", string(b), s)
		}
		if string(b) >= s {
		} else {
			t.Fatalf("strings are not equal: '%v' and '%v'", string(b), s)
		}
	})
	if n != 0 {
		t.Fatalf("want 0 allocs, got %v", n)
	}
}

func TestStringIndexHaystack(t *testing.T) {
	// See issue 25864.
	haystack := []byte("hello")
	needle := "ll"
	n := testing.AllocsPerRun(1000, func() {
		if strings.Index(string(haystack), needle) != 2 {
			t.Fatalf("needle not found")
		}
	})
	if n != 0 {
		t.Fatalf("want 0 allocs, got %v", n)
	}
}

func TestStringIndexNeedle(t *testing.T) {
	// See issue 25864.
	haystack := "hello"
	needle := []byte("ll")
	n := testing.AllocsPerRun(1000, func() {
		if strings.Index(haystack, string(needle)) != 2 {
			t.Fatalf("needle not found")
		}
	})
	if n != 0 {
		t.Fatalf("want 0 allocs, got %v", n)
	}
}

func TestStringOnStack(t *testing.T) {
	s := ""
	for i := 0; i < 3; i++ {
		s = "a" + s + "b" + s + "c"
	}

	if want := "aaabcbabccbaabcbabccc"; s != want {
		t.Fatalf("want: '%v', got '%v'", want, s)
	}
}

func TestIntString(t *testing.T) {
	// Non-escaping result of intstring.
	s := ""
	for i := rune(0); i < 4; i++ {
		s += string(i+'0') + string(i+'0'+1)
	}
	if want := "01122334"; s != want {
		t.Fatalf("want '%v', got '%v'", want, s)
	}

	// Escaping result of intstring.
	var a [4]string
	for i := rune(0); i < 4; i++ {
		a[i] = string(i + '0')
	}
	s = a[0] + a[1] + a[2] + a[3]
	if want := "0123"; s != want {
		t.Fatalf("want '%v', got '%v'", want, s)
	}
}

func TestIntStringAllocs(t *testing.T) {
	unknown := '0'
	n := testing.AllocsPerRun(1000, func() {
		s1 := string(unknown)
		s2 := string(unknown + 1)
		if s1 == s2 {
			t.Fatalf("bad")
		}
	})
	if n != 0 {
		t.Fatalf("want 0 allocs, got %v", n)
	}
}

func TestRangeStringCast(t *testing.T) {
	s := strings.Repeat("x", sizeNoStack)
	n := testing.AllocsPerRun(1000, func() {
		for i, c := range []byte(s) {
			if c != s[i] {
				t.Fatalf("want '%c' at pos %v, got '%c'", s[i], i, c)
			}
		}
	})
	if n != 0 {
		t.Fatalf("want 0 allocs, got %v", n)
	}
}

func isZeroed(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func isZeroedR(r []rune) bool {
	for _, x := range r {
		if x != 0 {
			return false
		}
	}
	return true
}

func TestString2Slice(t *testing.T) {
	// Make sure we don't return slices that expose
	// an unzeroed section of stack-allocated temp buf
	// between len and cap. See issue 14232.
	s := "foož"
	b := ([]byte)(s)
	if !isZeroed(b[len(b):cap(b)]) {
		t.Errorf("extra bytes not zeroed")
	}
	r := ([]rune)(s)
	if !isZeroedR(r[len(r):cap(r)]) {
		t.Errorf("extra runes not zeroed")
	}
}

const intSize = 32 << (^uint(0) >> 63)

type atoi64Test struct {
	in  string
	out int64
	ok  bool
}

var atoi64tests = []atoi64Test{
	{"", 0, false},
	{"0", 0, true},
	{"-0", 0, true},
	{"1", 1, true},
	{"-1", -1, true},
	{"12345", 12345, true},
	{"-12345", -12345, true},
	{"012345", 12345, true},
	{"-012345", -12345, true},
	{"12345x", 0, false},
	{"-12345x", 0, false},
	{"98765432100", 98765432100, true},
	{"-98765432100", -98765432100, true},
	{"20496382327982653440", 0, false},
	{"-20496382327982653440", 0, false},
	{"9223372036854775807", 1<<63 - 1, true},
	{"-9223372036854775807", -(1<<63 - 1), true},
	{"9223372036854775808", 0, false},
	{"-9223372036854775808", -1 << 63, true},
	{"9223372036854775809", 0, false},
	{"-9223372036854775809", 0, false},
}

func TestAtoi(t *testing.T) {
	switch intSize {
	case 32:
		for i := range atoi32tests {
			test := &atoi32tests[i]
			out, ok := runtime.Atoi(test.in)
			if test.out != int32(out) || test.ok != ok {
				t.Errorf("atoi(%q) = (%v, %v) want (%v, %v)",
					test.in, out, ok, test.out, test.ok)
			}
		}
	case 64:
		for i := range atoi64tests {
			test := &atoi64tests[i]
			out, ok := runtime.Atoi(test.in)
			if test.out != int64(out) || test.ok != ok {
				t.Errorf("atoi(%q) = (%v, %v) want (%v, %v)",
					test.in, out, ok, test.out, test.ok)
			}
		}
	}
}

type atoi32Test struct {
	in  string
	out int32
	ok  bool
}

var atoi32tests = []atoi32Test{
	{"", 0, false},
	{"0", 0, true},
	{"-0", 0, true},
	{"1", 1, true},
	{"-1", -1, true},
	{"12345", 12345, true},
	{"-12345", -12345, true},
	{"012345", 12345, true},
	{"-012345", -12345, true},
	{"12345x", 0, false},
	{"-12345x", 0, false},
	{"987654321", 987654321, true},
	{"-987654321", -987654321, true},
	{"2147483647", 1<<31 - 1, true},
	{"-2147483647", -(1<<31 - 1), true},
	{"2147483648", 0, false},
	{"-2147483648", -1 << 31, true},
	{"2147483649", 0, false},
	{"-2147483649", 0, false},
}

func TestAtoi32(t *testing.T) {
	for i := range atoi32tests {
		test := &atoi32tests[i]
		out, ok := runtime.Atoi32(test.in)
		if test.out != out || test.ok != ok {
			t.Errorf("atoi32(%q) = (%v, %v) want (%v, %v)",
				test.in, out, ok, test.out, test.ok)
		}
	}
}

func TestParseByteCount(t *testing.T) {
	for _, test := range []struct {
		in  string
		out int64
		ok  bool
	}{
		// Good numeric inputs.
		{"1", 1, true},
		{"12345", 12345, true},
		{"012345", 12345, true},
		{"98765432100", 98765432100, true},
		{"9223372036854775807", 1<<63 - 1, true},

		// Good trivial suffix inputs.
		{"1B", 1, true},
		{"12345B", 12345, true},
		{"012345B", 12345, true},
		{"98765432100B", 98765432100, true},
		{"9223372036854775807B", 1<<63 - 1, true},

		// Good binary suffix inputs.
		{"1KiB", 1 << 10, true},
		{"05KiB", 5 << 10, true},
		{"1MiB", 1 << 20, true},
		{"10MiB", 10 << 20, true},
		{"1GiB", 1 << 30, true},
		{"100GiB", 100 << 30, true},
		{"1TiB", 1 << 40, true},
		{"99TiB", 99 << 40, true},

		// Good zero inputs.
		//
		// -0 is an edge case, but no harm in supporting it.
		{"-0", 0, true},
		{"0", 0, true},
		{"0B", 0, true},
		{"0KiB", 0, true},
		{"0MiB", 0, true},
		{"0GiB", 0, true},
		{"0TiB", 0, true},

		// Bad inputs.
		{"", 0, false},
		{"-1", 0, false},
		{"a12345", 0, false},
		{"a12345B", 0, false},
		{"12345x", 0, false},
		{"0x12345", 0, false},

		// Bad numeric inputs.
		{"9223372036854775808", 0, false},
		{"9223372036854775809", 0, false},
		{"18446744073709551615", 0, false},
		{"20496382327982653440", 0, false},
		{"18446744073709551616", 0, false},
		{"18446744073709551617", 0, false},
		{"9999999999999999999999", 0, false},

		// Bad trivial suffix inputs.
		{"9223372036854775808B", 0, false},
		{"9223372036854775809B", 0, false},
		{"18446744073709551615B", 0, false},
		{"20496382327982653440B", 0, false},
		{"18446744073709551616B", 0, false},
		{"18446744073709551617B", 0, false},
		{"9999999999999999999999B", 0, false},

		// Bad binary suffix inputs.
		{"1Ki", 0, false},
		{"05Ki", 0, false},
		{"10Mi", 0, false},
		{"100Gi", 0, false},
		{"99Ti", 0, false},
		{"22iB", 0, false},
		{"B", 0, false},
		{"iB", 0, false},
		{"KiB", 0, false},
		{"MiB", 0, false},
		{"GiB", 0, false},
		{"TiB", 0, false},
		{"-120KiB", 0, false},
		{"-891MiB", 0, false},
		{"-704GiB", 0, false},
		{"-42TiB", 0, false},
		{"99999999999999999999KiB", 0, false},
		{"99999999999999999MiB", 0, false},
		{"99999999999999GiB", 0, false},
		{"99999999999TiB", 0, false},
		{"555EiB", 0, false},

		// Mistaken SI suffix inputs.
		{"0KB", 0, false},
		{"0MB", 0, false},
		{"0GB", 0, false},
		{"0TB", 0, false},
		{"1KB", 0, false},
		{"05KB", 0, false},
		{"1MB", 0, false},
		{"10MB", 0, false},
		{"1GB", 0, false},
		{"100GB", 0, false},
		{"1TB", 0, false},
		{"99TB", 0, false},
		{"1K", 0, false},
		{"05K", 0, false},
		{"10M", 0, false},
		{"100G", 0, false},
		{"99T", 0, false},
		{"99999999999999999999KB", 0, false},
		{"99999999999999999MB", 0, false},
		{"99999999999999GB", 0, false},
		{"99999999999TB", 0, false},
		{"99999999999TiB", 0, false},
		{"555EB", 0, false},
	} {
		out, ok := runtime.ParseByteCount(test.in)
		if test.out != out || test.ok != ok {
			t.Errorf("parseByteCount(%q) = (%v, %v) want (%v, %v)",
				test.in, out, ok, test.out, test.ok)
		}
	}
}
```