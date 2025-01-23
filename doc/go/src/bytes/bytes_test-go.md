Response:
The user wants me to analyze a Go test file (`bytes_test.go`) and summarize its functionality.

Here's a breakdown of the thought process to achieve that:

1. **Understand the Context:** The filename `bytes_test.go` strongly suggests this file contains tests for the `bytes` package in Go's standard library. The `package bytes_test` declaration confirms this.

2. **Identify Core Functionality:**  Scan the import statements and the names of the test functions. The imports like `bytes`, `strings`, `unicode`, and function names like `TestEqual`, `TestIndex`, `TestSplit`, `TestFields`, `TestMap` give clues about the functionalities being tested. These functionalities likely correspond to functions within the `bytes` package.

3. **Group Tests by Functionality:** Organize the tests based on the apparent functions they are testing. For instance, tests related to equality (`TestEqual`, `TestEqualExhaustive`, `TestNotEqual`) are grouped together. Tests involving searching (`TestIndex`, `TestLastIndex`, `TestIndexAny`, `TestLastIndexAny`, `TestIndexByte`, `TestLastIndexByte`, `TestIndexRune`) form another group. String manipulation tests like `TestLines`, `TestSplit`, `TestSplitAfter`, `TestFields`, `TestFieldsFunc`, `TestMap`, `TestToUpper`, `TestToLower`, `TestTrimSpace` (though `TestToUpper` and `TestToLower` are not explicitly present in this part, the patterns suggest their existence in the full file) fall into another category. Benchmarks (`BenchmarkIndexByte`, `BenchmarkIndexRune`, `BenchmarkEqual`, `BenchmarkIndex`, `BenchmarkCount`) are distinct.

4. **Infer Functionality from Test Names and Structures:**
    * `TestLines`: Likely tests a function that splits a byte slice into lines. The `LinesTest` struct with `a` (input string) and `b` (expected slice of strings) supports this.
    * `TestEqual`:  Clearly tests a function that checks if two byte slices are equal.
    * `TestIndex`, `TestLastIndex`, etc.: These test functions with names like `Index`, `LastIndex`, `IndexAny`, `LastIndexAny`, `IndexByte`, `LastIndexByte`, `IndexRune` suggest functions that search for the index of substrings, characters, or runes within a byte slice. The `BinOpTest` struct reinforces this, holding input byte slices (`a`, `b`) and an expected index (`i`).
    * `TestSplit`, `TestSplitAfter`, `TestFields`, `TestFieldsFunc`:  These tests, along with the `SplitTest` and `FieldsTest` structs, indicate functions for splitting byte slices based on delimiters or whitespace.
    * `TestMap`: Suggests a function that applies a mapping function to each rune in a byte slice.
    * `runStringTests`: This utility function further implies the existence of functions like `ToUpper`, `ToLower`, and `TrimSpace` that operate on byte slices and return modified byte slices.
    * Benchmarks: The `Benchmark...` functions are for performance testing.

5. **Identify Utility Functions:** Notice functions like `sliceOfString` and `collect`. These are helper functions within the test file, not part of the `bytes` package itself. `sliceOfString` converts a `[][]byte` to `[]string`, and `collect` appears to be a helper for testing iterators.

6. **Focus on Part 1:** The prompt specifically states "This is part 1". Therefore, the summary should only reflect the functionality present in this code snippet. Avoid speculating about what might be in "part 2".

7. **Formulate the Summary:**  Based on the above analysis, construct a concise summary of the file's purpose, listing the major categories of functions being tested.

8. **Review and Refine:**  Check the summary for clarity and accuracy. Ensure it directly answers the user's question about the file's functionality. For example, explicitly mentioning that it tests functions within the `bytes` package is important context.
这个Go语言源文件 `bytes_test.go` 的第一部分主要用于测试 `bytes` 标准库中与字节切片操作相关的多个核心功能。它通过定义各种测试用例和辅助函数，来验证 `bytes` 包中函数的正确性。

具体来说，这部分代码主要测试了以下功能：

1. **`Lines` 函数**:  测试将字节切片分割成多行的功能。它定义了包含不同换行符（`\n`, `\r\n`）的字符串，并验证 `bytes.Lines` 函数是否能正确地将它们分割成预期的行切片。

2. **`Equal` 函数**:  测试判断两个字节切片是否完全相等的功能。它通过多种测试用例，包括相等和不相等的切片，以及通过穷举测试来确保在各种长度和偏移情况下 `Equal` 函数的正确性。

3. **`Index` 和 `LastIndex` 函数**: 测试在字节切片中查找子切片第一次出现和最后一次出现的位置的功能。它包含了各种边界情况和常见用例，例如空切片、子切片不存在、子切片位于开头、结尾或中间等。还包括了对性能敏感的、需要回退到特定算法的情况的测试。

4. **`IndexAny` 和 `LastIndexAny` 函数**: 测试在字节切片中查找任意指定字符集合中的字符第一次出现和最后一次出现的位置的功能。

5. **`IndexByte` 和 `LastIndexByte` 函数**: 测试在字节切片中查找指定字节第一次出现和最后一次出现的位置的功能。它还包含了对不同大小和对齐方式的字节切片的测试，以确保实现的健壮性。

6. **`IndexRune` 函数**: 测试在字节切片中查找指定 Unicode 字符第一次出现的位置的功能。它涵盖了 ASCII 字符、多字节 UTF-8 字符以及错误的 UTF-8 编码。

7. **`Count` 函数**: 测试计算字节切片中子切片出现的次数的功能。它通过在不同偏移和窗口大小的字节切片中查找特定字节来测试其正确性。

8. **性能基准测试 (Benchmarks)**: 这部分代码还包含了一些性能基准测试，用于衡量 `IndexByte`, `IndexRune`, `Equal`, `Index`, 和 `Count` 等函数的性能。这些基准测试使用不同大小的字节切片来模拟实际使用场景，并评估函数的执行效率。

9. **`Split` 和 `SplitAfter` 函数**: 测试将字节切片按照指定分隔符分割成多个子切片的功能。`Split` 不包含分隔符，而 `SplitAfter` 包含分隔符。它包含了指定分割数量和不指定分割数量的情况。

10. **`Fields` 和 `FieldsFunc` 函数**: 测试将字节切片按照空白字符或自定义函数分割成多个字段的功能。

11. **`ToUpper` 和 `ToLower` 函数**: 测试将字节切片中的字符转换为大写和小写的功能。

12. **`TrimSpace` 函数**: 测试去除字节切片开头和结尾空白字符的功能。

13. **`Map` 函数**: 测试将字节切片中的每个字符都映射到一个新的字符的功能。

**归纳一下它的功能：**

这部分 `bytes_test.go` 文件的主要功能是 **全面测试 Go 语言 `bytes` 标准库中提供的各种字节切片操作函数**。它通过定义丰富的测试用例，覆盖了各种输入情况、边界条件和性能场景，以确保这些函数的功能正确性和性能表现。这部分代码着重于测试字节切片的比较、查找、分割、转换等核心操作。

### 提示词
```
这是路径为go/src/bytes/bytes_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bytes_test

import (
	. "bytes"
	"fmt"
	"internal/testenv"
	"iter"
	"math"
	"math/rand"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
	"unsafe"
)

func sliceOfString(s [][]byte) []string {
	result := make([]string, len(s))
	for i, v := range s {
		result[i] = string(v)
	}
	return result
}

func collect(t *testing.T, seq iter.Seq[[]byte]) [][]byte {
	out := slices.Collect(seq)
	out1 := slices.Collect(seq)
	if !slices.Equal(sliceOfString(out), sliceOfString(out1)) {
		t.Fatalf("inconsistent seq:\n%s\n%s", out, out1)
	}
	return out
}

type LinesTest struct {
	a string
	b []string
}

var linesTests = []LinesTest{
	{a: "abc\nabc\n", b: []string{"abc\n", "abc\n"}},
	{a: "abc\r\nabc", b: []string{"abc\r\n", "abc"}},
	{a: "abc\r\n", b: []string{"abc\r\n"}},
	{a: "\nabc", b: []string{"\n", "abc"}},
	{a: "\nabc\n\n", b: []string{"\n", "abc\n", "\n"}},
}

func TestLines(t *testing.T) {
	for _, s := range linesTests {
		result := sliceOfString(slices.Collect(Lines([]byte(s.a))))
		if !slices.Equal(result, s.b) {
			t.Errorf(`slices.Collect(Lines(%q)) = %q; want %q`, s.a, result, s.b)
		}
	}
}

// For ease of reading, the test cases use strings that are converted to byte
// slices before invoking the functions.

var abcd = "abcd"
var faces = "☺☻☹"
var commas = "1,2,3,4"
var dots = "1....2....3....4"

type BinOpTest struct {
	a string
	b string
	i int
}

func TestEqual(t *testing.T) {
	// Run the tests and check for allocation at the same time.
	allocs := testing.AllocsPerRun(10, func() {
		for _, tt := range compareTests {
			eql := Equal(tt.a, tt.b)
			if eql != (tt.i == 0) {
				t.Errorf(`Equal(%q, %q) = %v`, tt.a, tt.b, eql)
			}
		}
	})
	if allocs > 0 {
		t.Errorf("Equal allocated %v times", allocs)
	}
}

func TestEqualExhaustive(t *testing.T) {
	var size = 128
	if testing.Short() {
		size = 32
	}
	a := make([]byte, size)
	b := make([]byte, size)
	b_init := make([]byte, size)
	// randomish but deterministic data
	for i := 0; i < size; i++ {
		a[i] = byte(17 * i)
		b_init[i] = byte(23*i + 100)
	}

	for len := 0; len <= size; len++ {
		for x := 0; x <= size-len; x++ {
			for y := 0; y <= size-len; y++ {
				copy(b, b_init)
				copy(b[y:y+len], a[x:x+len])
				if !Equal(a[x:x+len], b[y:y+len]) || !Equal(b[y:y+len], a[x:x+len]) {
					t.Errorf("Equal(%d, %d, %d) = false", len, x, y)
				}
			}
		}
	}
}

// make sure Equal returns false for minimally different strings. The data
// is all zeros except for a single one in one location.
func TestNotEqual(t *testing.T) {
	var size = 128
	if testing.Short() {
		size = 32
	}
	a := make([]byte, size)
	b := make([]byte, size)

	for len := 0; len <= size; len++ {
		for x := 0; x <= size-len; x++ {
			for y := 0; y <= size-len; y++ {
				for diffpos := x; diffpos < x+len; diffpos++ {
					a[diffpos] = 1
					if Equal(a[x:x+len], b[y:y+len]) || Equal(b[y:y+len], a[x:x+len]) {
						t.Errorf("NotEqual(%d, %d, %d, %d) = true", len, x, y, diffpos)
					}
					a[diffpos] = 0
				}
			}
		}
	}
}

var indexTests = []BinOpTest{
	{"", "", 0},
	{"", "a", -1},
	{"", "foo", -1},
	{"fo", "foo", -1},
	{"foo", "baz", -1},
	{"foo", "foo", 0},
	{"oofofoofooo", "f", 2},
	{"oofofoofooo", "foo", 4},
	{"barfoobarfoo", "foo", 3},
	{"foo", "", 0},
	{"foo", "o", 1},
	{"abcABCabc", "A", 3},
	// cases with one byte strings - test IndexByte and special case in Index()
	{"", "a", -1},
	{"x", "a", -1},
	{"x", "x", 0},
	{"abc", "a", 0},
	{"abc", "b", 1},
	{"abc", "c", 2},
	{"abc", "x", -1},
	{"barfoobarfooyyyzzzyyyzzzyyyzzzyyyxxxzzzyyy", "x", 33},
	{"fofofofooofoboo", "oo", 7},
	{"fofofofofofoboo", "ob", 11},
	{"fofofofofofoboo", "boo", 12},
	{"fofofofofofoboo", "oboo", 11},
	{"fofofofofoooboo", "fooo", 8},
	{"fofofofofofoboo", "foboo", 10},
	{"fofofofofofoboo", "fofob", 8},
	{"fofofofofofofoffofoobarfoo", "foffof", 12},
	{"fofofofofoofofoffofoobarfoo", "foffof", 13},
	{"fofofofofofofoffofoobarfoo", "foffofo", 12},
	{"fofofofofoofofoffofoobarfoo", "foffofo", 13},
	{"fofofofofoofofoffofoobarfoo", "foffofoo", 13},
	{"fofofofofofofoffofoobarfoo", "foffofoo", 12},
	{"fofofofofoofofoffofoobarfoo", "foffofoob", 13},
	{"fofofofofofofoffofoobarfoo", "foffofoob", 12},
	{"fofofofofoofofoffofoobarfoo", "foffofooba", 13},
	{"fofofofofofofoffofoobarfoo", "foffofooba", 12},
	{"fofofofofoofofoffofoobarfoo", "foffofoobar", 13},
	{"fofofofofofofoffofoobarfoo", "foffofoobar", 12},
	{"fofofofofoofofoffofoobarfoo", "foffofoobarf", 13},
	{"fofofofofofofoffofoobarfoo", "foffofoobarf", 12},
	{"fofofofofoofofoffofoobarfoo", "foffofoobarfo", 13},
	{"fofofofofofofoffofoobarfoo", "foffofoobarfo", 12},
	{"fofofofofoofofoffofoobarfoo", "foffofoobarfoo", 13},
	{"fofofofofofofoffofoobarfoo", "foffofoobarfoo", 12},
	{"fofofofofoofofoffofoobarfoo", "ofoffofoobarfoo", 12},
	{"fofofofofofofoffofoobarfoo", "ofoffofoobarfoo", 11},
	{"fofofofofoofofoffofoobarfoo", "fofoffofoobarfoo", 11},
	{"fofofofofofofoffofoobarfoo", "fofoffofoobarfoo", 10},
	{"fofofofofoofofoffofoobarfoo", "foobars", -1},
	{"foofyfoobarfoobar", "y", 4},
	{"oooooooooooooooooooooo", "r", -1},
	{"oxoxoxoxoxoxoxoxoxoxoxoy", "oy", 22},
	{"oxoxoxoxoxoxoxoxoxoxoxox", "oy", -1},
	// test fallback to Rabin-Karp.
	{"000000000000000000000000000000000000000000000000000000000000000000000001", "0000000000000000000000000000000000000000000000000000000000000000001", 5},
	// test fallback to IndexRune
	{"oxoxoxoxoxoxoxoxoxoxox☺", "☺", 22},
	// invalid UTF-8 byte sequence (must be longer than bytealg.MaxBruteForce to
	// test that we don't use IndexRune)
	{"xx0123456789012345678901234567890123456789012345678901234567890120123456789012345678901234567890123456xxx\xed\x9f\xc0", "\xed\x9f\xc0", 105},
}

var lastIndexTests = []BinOpTest{
	{"", "", 0},
	{"", "a", -1},
	{"", "foo", -1},
	{"fo", "foo", -1},
	{"foo", "foo", 0},
	{"foo", "f", 0},
	{"oofofoofooo", "f", 7},
	{"oofofoofooo", "foo", 7},
	{"barfoobarfoo", "foo", 9},
	{"foo", "", 3},
	{"foo", "o", 2},
	{"abcABCabc", "A", 3},
	{"abcABCabc", "a", 6},
}

var indexAnyTests = []BinOpTest{
	{"", "", -1},
	{"", "a", -1},
	{"", "abc", -1},
	{"a", "", -1},
	{"a", "a", 0},
	{"\x80", "\xffb", 0},
	{"aaa", "a", 0},
	{"abc", "xyz", -1},
	{"abc", "xcz", 2},
	{"ab☺c", "x☺yz", 2},
	{"a☺b☻c☹d", "cx", len("a☺b☻")},
	{"a☺b☻c☹d", "uvw☻xyz", len("a☺b")},
	{"aRegExp*", ".(|)*+?^$[]", 7},
	{dots + dots + dots, " ", -1},
	{"012abcba210", "\xffb", 4},
	{"012\x80bcb\x80210", "\xffb", 3},
	{"0123456\xcf\x80abc", "\xcfb\x80", 10},
}

var lastIndexAnyTests = []BinOpTest{
	{"", "", -1},
	{"", "a", -1},
	{"", "abc", -1},
	{"a", "", -1},
	{"a", "a", 0},
	{"\x80", "\xffb", 0},
	{"aaa", "a", 2},
	{"abc", "xyz", -1},
	{"abc", "ab", 1},
	{"ab☺c", "x☺yz", 2},
	{"a☺b☻c☹d", "cx", len("a☺b☻")},
	{"a☺b☻c☹d", "uvw☻xyz", len("a☺b")},
	{"a.RegExp*", ".(|)*+?^$[]", 8},
	{dots + dots + dots, " ", -1},
	{"012abcba210", "\xffb", 6},
	{"012\x80bcb\x80210", "\xffb", 7},
	{"0123456\xcf\x80abc", "\xcfb\x80", 10},
}

// Execute f on each test case.  funcName should be the name of f; it's used
// in failure reports.
func runIndexTests(t *testing.T, f func(s, sep []byte) int, funcName string, testCases []BinOpTest) {
	for _, test := range testCases {
		a := []byte(test.a)
		b := []byte(test.b)
		actual := f(a, b)
		if actual != test.i {
			t.Errorf("%s(%q,%q) = %v; want %v", funcName, a, b, actual, test.i)
		}
	}
	var allocTests = []struct {
		a []byte
		b []byte
		i int
	}{
		// case for function Index.
		{[]byte("000000000000000000000000000000000000000000000000000000000000000000000001"), []byte("0000000000000000000000000000000000000000000000000000000000000000001"), 5},
		// case for function LastIndex.
		{[]byte("000000000000000000000000000000000000000000000000000000000000000010000"), []byte("00000000000000000000000000000000000000000000000000000000000001"), 3},
	}
	allocs := testing.AllocsPerRun(100, func() {
		if i := Index(allocTests[1].a, allocTests[1].b); i != allocTests[1].i {
			t.Errorf("Index([]byte(%q), []byte(%q)) = %v; want %v", allocTests[1].a, allocTests[1].b, i, allocTests[1].i)
		}
		if i := LastIndex(allocTests[0].a, allocTests[0].b); i != allocTests[0].i {
			t.Errorf("LastIndex([]byte(%q), []byte(%q)) = %v; want %v", allocTests[0].a, allocTests[0].b, i, allocTests[0].i)
		}
	})
	if allocs != 0 {
		t.Errorf("expected no allocations, got %f", allocs)
	}
}

func runIndexAnyTests(t *testing.T, f func(s []byte, chars string) int, funcName string, testCases []BinOpTest) {
	for _, test := range testCases {
		a := []byte(test.a)
		actual := f(a, test.b)
		if actual != test.i {
			t.Errorf("%s(%q,%q) = %v; want %v", funcName, a, test.b, actual, test.i)
		}
	}
}

func TestIndex(t *testing.T)     { runIndexTests(t, Index, "Index", indexTests) }
func TestLastIndex(t *testing.T) { runIndexTests(t, LastIndex, "LastIndex", lastIndexTests) }
func TestIndexAny(t *testing.T)  { runIndexAnyTests(t, IndexAny, "IndexAny", indexAnyTests) }
func TestLastIndexAny(t *testing.T) {
	runIndexAnyTests(t, LastIndexAny, "LastIndexAny", lastIndexAnyTests)
}

func TestIndexByte(t *testing.T) {
	for _, tt := range indexTests {
		if len(tt.b) != 1 {
			continue
		}
		a := []byte(tt.a)
		b := tt.b[0]
		pos := IndexByte(a, b)
		if pos != tt.i {
			t.Errorf(`IndexByte(%q, '%c') = %v`, tt.a, b, pos)
		}
		posp := IndexBytePortable(a, b)
		if posp != tt.i {
			t.Errorf(`indexBytePortable(%q, '%c') = %v`, tt.a, b, posp)
		}
	}
}

func TestLastIndexByte(t *testing.T) {
	testCases := []BinOpTest{
		{"", "q", -1},
		{"abcdef", "q", -1},
		{"abcdefabcdef", "a", len("abcdef")},      // something in the middle
		{"abcdefabcdef", "f", len("abcdefabcde")}, // last byte
		{"zabcdefabcdef", "z", 0},                 // first byte
		{"a☺b☻c☹d", "b", len("a☺")},               // non-ascii
	}
	for _, test := range testCases {
		actual := LastIndexByte([]byte(test.a), test.b[0])
		if actual != test.i {
			t.Errorf("LastIndexByte(%q,%c) = %v; want %v", test.a, test.b[0], actual, test.i)
		}
	}
}

// test a larger buffer with different sizes and alignments
func TestIndexByteBig(t *testing.T) {
	var n = 1024
	if testing.Short() {
		n = 128
	}
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		// different start alignments
		b1 := b[i:]
		for j := 0; j < len(b1); j++ {
			b1[j] = 'x'
			pos := IndexByte(b1, 'x')
			if pos != j {
				t.Errorf("IndexByte(%q, 'x') = %v", b1, pos)
			}
			b1[j] = 0
			pos = IndexByte(b1, 'x')
			if pos != -1 {
				t.Errorf("IndexByte(%q, 'x') = %v", b1, pos)
			}
		}
		// different end alignments
		b1 = b[:i]
		for j := 0; j < len(b1); j++ {
			b1[j] = 'x'
			pos := IndexByte(b1, 'x')
			if pos != j {
				t.Errorf("IndexByte(%q, 'x') = %v", b1, pos)
			}
			b1[j] = 0
			pos = IndexByte(b1, 'x')
			if pos != -1 {
				t.Errorf("IndexByte(%q, 'x') = %v", b1, pos)
			}
		}
		// different start and end alignments
		b1 = b[i/2 : n-(i+1)/2]
		for j := 0; j < len(b1); j++ {
			b1[j] = 'x'
			pos := IndexByte(b1, 'x')
			if pos != j {
				t.Errorf("IndexByte(%q, 'x') = %v", b1, pos)
			}
			b1[j] = 0
			pos = IndexByte(b1, 'x')
			if pos != -1 {
				t.Errorf("IndexByte(%q, 'x') = %v", b1, pos)
			}
		}
	}
}

// test a small index across all page offsets
func TestIndexByteSmall(t *testing.T) {
	b := make([]byte, 5015) // bigger than a page
	// Make sure we find the correct byte even when straddling a page.
	for i := 0; i <= len(b)-15; i++ {
		for j := 0; j < 15; j++ {
			b[i+j] = byte(100 + j)
		}
		for j := 0; j < 15; j++ {
			p := IndexByte(b[i:i+15], byte(100+j))
			if p != j {
				t.Errorf("IndexByte(%q, %d) = %d", b[i:i+15], 100+j, p)
			}
		}
		for j := 0; j < 15; j++ {
			b[i+j] = 0
		}
	}
	// Make sure matches outside the slice never trigger.
	for i := 0; i <= len(b)-15; i++ {
		for j := 0; j < 15; j++ {
			b[i+j] = 1
		}
		for j := 0; j < 15; j++ {
			p := IndexByte(b[i:i+15], byte(0))
			if p != -1 {
				t.Errorf("IndexByte(%q, %d) = %d", b[i:i+15], 0, p)
			}
		}
		for j := 0; j < 15; j++ {
			b[i+j] = 0
		}
	}
}

func TestIndexRune(t *testing.T) {
	tests := []struct {
		in   string
		rune rune
		want int
	}{
		{"", 'a', -1},
		{"", '☺', -1},
		{"foo", '☹', -1},
		{"foo", 'o', 1},
		{"foo☺bar", '☺', 3},
		{"foo☺☻☹bar", '☹', 9},
		{"a A x", 'A', 2},
		{"some_text=some_value", '=', 9},
		{"☺a", 'a', 3},
		{"a☻☺b", '☺', 4},
		{"𠀳𠀗𠀾𠁄𠀧𠁆𠁂𠀫𠀖𠀪𠀲𠀴𠁀𠀨𠀿", '𠀿', 56},

		// 2 bytes
		{"ӆ", 'ӆ', 0},
		{"a", 'ӆ', -1},
		{"  ӆ", 'ӆ', 2},
		{"  a", 'ӆ', -1},
		{strings.Repeat("ц", 64) + "ӆ", 'ӆ', 128}, // test cutover
		{strings.Repeat("ц", 64), 'ӆ', -1},

		// 3 bytes
		{"Ꚁ", 'Ꚁ', 0},
		{"a", 'Ꚁ', -1},
		{"  Ꚁ", 'Ꚁ', 2},
		{"  a", 'Ꚁ', -1},
		{strings.Repeat("Ꙁ", 64) + "Ꚁ", 'Ꚁ', 192}, // test cutover
		{strings.Repeat("Ꙁ", 64) + "Ꚁ", '䚀', -1},  // 'Ꚁ' and '䚀' share the same last two bytes

		// 4 bytes
		{"𡌀", '𡌀', 0},
		{"a", '𡌀', -1},
		{"  𡌀", '𡌀', 2},
		{"  a", '𡌀', -1},
		{strings.Repeat("𡋀", 64) + "𡌀", '𡌀', 256}, // test cutover
		{strings.Repeat("𡋀", 64) + "𡌀", '𣌀', -1},  // '𡌀' and '𣌀' share the same last two bytes

		// RuneError should match any invalid UTF-8 byte sequence.
		{"�", '�', 0},
		{"\xff", '�', 0},
		{"☻x�", '�', len("☻x")},
		{"☻x\xe2\x98", '�', len("☻x")},
		{"☻x\xe2\x98�", '�', len("☻x")},
		{"☻x\xe2\x98x", '�', len("☻x")},

		// Invalid rune values should never match.
		{"a☺b☻c☹d\xe2\x98�\xff�\xed\xa0\x80", -1, -1},
		{"a☺b☻c☹d\xe2\x98�\xff�\xed\xa0\x80", 0xD800, -1}, // Surrogate pair
		{"a☺b☻c☹d\xe2\x98�\xff�\xed\xa0\x80", utf8.MaxRune + 1, -1},

		// Test the cutover to bytealg.Index when it is triggered in
		// the middle of rune that contains consecutive runs of equal bytes.
		{"aaaaaKKKK\U000bc104", '\U000bc104', 17}, // cutover: (n + 16) / 8
		{"aaaaaKKKK鄄", '鄄', 17},
		{"aaKKKKKa\U000bc104", '\U000bc104', 18}, // cutover: 4 + n>>4
		{"aaKKKKKa鄄", '鄄', 18},
	}
	for _, tt := range tests {
		if got := IndexRune([]byte(tt.in), tt.rune); got != tt.want {
			t.Errorf("IndexRune(%q, %d) = %v; want %v", tt.in, tt.rune, got, tt.want)
		}
	}

	haystack := []byte("test世界")
	allocs := testing.AllocsPerRun(1000, func() {
		if i := IndexRune(haystack, 's'); i != 2 {
			t.Fatalf("'s' at %d; want 2", i)
		}
		if i := IndexRune(haystack, '世'); i != 4 {
			t.Fatalf("'世' at %d; want 4", i)
		}
	})
	if allocs != 0 {
		t.Errorf("expected no allocations, got %f", allocs)
	}
}

// test count of a single byte across page offsets
func TestCountByte(t *testing.T) {
	b := make([]byte, 5015) // bigger than a page
	windows := []int{1, 2, 3, 4, 15, 16, 17, 31, 32, 33, 63, 64, 65, 128}
	testCountWindow := func(i, window int) {
		for j := 0; j < window; j++ {
			b[i+j] = byte(100)
			p := Count(b[i:i+window], []byte{100})
			if p != j+1 {
				t.Errorf("TestCountByte.Count(%q, 100) = %d", b[i:i+window], p)
			}
		}
	}

	maxWnd := windows[len(windows)-1]

	for i := 0; i <= 2*maxWnd; i++ {
		for _, window := range windows {
			if window > len(b[i:]) {
				window = len(b[i:])
			}
			testCountWindow(i, window)
			for j := 0; j < window; j++ {
				b[i+j] = byte(0)
			}
		}
	}
	for i := 4096 - (maxWnd + 1); i < len(b); i++ {
		for _, window := range windows {
			if window > len(b[i:]) {
				window = len(b[i:])
			}
			testCountWindow(i, window)
			for j := 0; j < window; j++ {
				b[i+j] = byte(0)
			}
		}
	}
}

// Make sure we don't count bytes outside our window
func TestCountByteNoMatch(t *testing.T) {
	b := make([]byte, 5015)
	windows := []int{1, 2, 3, 4, 15, 16, 17, 31, 32, 33, 63, 64, 65, 128}
	for i := 0; i <= len(b); i++ {
		for _, window := range windows {
			if window > len(b[i:]) {
				window = len(b[i:])
			}
			// Fill the window with non-match
			for j := 0; j < window; j++ {
				b[i+j] = byte(100)
			}
			// Try to find something that doesn't exist
			p := Count(b[i:i+window], []byte{0})
			if p != 0 {
				t.Errorf("TestCountByteNoMatch(%q, 0) = %d", b[i:i+window], p)
			}
			for j := 0; j < window; j++ {
				b[i+j] = byte(0)
			}
		}
	}
}

var bmbuf []byte

func valName(x int) string {
	if s := x >> 20; s<<20 == x {
		return fmt.Sprintf("%dM", s)
	}
	if s := x >> 10; s<<10 == x {
		return fmt.Sprintf("%dK", s)
	}
	return fmt.Sprint(x)
}

func benchBytes(b *testing.B, sizes []int, f func(b *testing.B, n int)) {
	for _, n := range sizes {
		if isRaceBuilder && n > 4<<10 {
			continue
		}
		b.Run(valName(n), func(b *testing.B) {
			if len(bmbuf) < n {
				bmbuf = make([]byte, n)
			}
			b.SetBytes(int64(n))
			f(b, n)
		})
	}
}

var indexSizes = []int{10, 32, 4 << 10, 4 << 20, 64 << 20}

var isRaceBuilder = strings.HasSuffix(testenv.Builder(), "-race")

func BenchmarkIndexByte(b *testing.B) {
	benchBytes(b, indexSizes, bmIndexByte(IndexByte))
}

func BenchmarkIndexBytePortable(b *testing.B) {
	benchBytes(b, indexSizes, bmIndexByte(IndexBytePortable))
}

func bmIndexByte(index func([]byte, byte) int) func(b *testing.B, n int) {
	return func(b *testing.B, n int) {
		buf := bmbuf[0:n]
		buf[n-1] = 'x'
		for i := 0; i < b.N; i++ {
			j := index(buf, 'x')
			if j != n-1 {
				b.Fatal("bad index", j)
			}
		}
		buf[n-1] = '\x00'
	}
}

func BenchmarkIndexRune(b *testing.B) {
	benchBytes(b, indexSizes, bmIndexRune(IndexRune))
}

func BenchmarkIndexRuneASCII(b *testing.B) {
	benchBytes(b, indexSizes, bmIndexRuneASCII(IndexRune))
}

func BenchmarkIndexRuneUnicode(b *testing.B) {
	b.Run("Latin", func(b *testing.B) {
		// Latin is mostly 1, 2, 3 byte runes.
		benchBytes(b, indexSizes, bmIndexRuneUnicode(unicode.Latin, 'é'))
	})
	b.Run("Cyrillic", func(b *testing.B) {
		// Cyrillic is mostly 2 and 3 byte runes.
		benchBytes(b, indexSizes, bmIndexRuneUnicode(unicode.Cyrillic, 'Ꙁ'))
	})
	b.Run("Han", func(b *testing.B) {
		// Han consists only of 3 and 4 byte runes.
		benchBytes(b, indexSizes, bmIndexRuneUnicode(unicode.Han, '𠀿'))
	})
}

func bmIndexRuneASCII(index func([]byte, rune) int) func(b *testing.B, n int) {
	return func(b *testing.B, n int) {
		buf := bmbuf[0:n]
		buf[n-1] = 'x'
		for i := 0; i < b.N; i++ {
			j := index(buf, 'x')
			if j != n-1 {
				b.Fatal("bad index", j)
			}
		}
		buf[n-1] = '\x00'
	}
}

func bmIndexRune(index func([]byte, rune) int) func(b *testing.B, n int) {
	return func(b *testing.B, n int) {
		buf := bmbuf[0:n]
		utf8.EncodeRune(buf[n-3:], '世')
		for i := 0; i < b.N; i++ {
			j := index(buf, '世')
			if j != n-3 {
				b.Fatal("bad index", j)
			}
		}
		buf[n-3] = '\x00'
		buf[n-2] = '\x00'
		buf[n-1] = '\x00'
	}
}

func bmIndexRuneUnicode(rt *unicode.RangeTable, needle rune) func(b *testing.B, n int) {
	var rs []rune
	for _, r16 := range rt.R16 {
		for r := rune(r16.Lo); r <= rune(r16.Hi); r += rune(r16.Stride) {
			if r != needle {
				rs = append(rs, rune(r))
			}
		}
	}
	for _, r32 := range rt.R32 {
		for r := rune(r32.Lo); r <= rune(r32.Hi); r += rune(r32.Stride) {
			if r != needle {
				rs = append(rs, rune(r))
			}
		}
	}
	// Shuffle the runes so that they are not in descending order.
	// The sort is deterministic since this is used for benchmarks,
	// which need to be repeatable.
	rr := rand.New(rand.NewSource(1))
	rr.Shuffle(len(rs), func(i, j int) {
		rs[i], rs[j] = rs[j], rs[i]
	})
	uchars := string(rs)

	return func(b *testing.B, n int) {
		buf := bmbuf[0:n]
		o := copy(buf, uchars)
		for o < len(buf) {
			o += copy(buf[o:], uchars)
		}

		// Make space for the needle rune at the end of buf.
		m := utf8.RuneLen(needle)
		for o := m; o > 0; {
			_, sz := utf8.DecodeLastRune(buf)
			copy(buf[len(buf)-sz:], "\x00\x00\x00\x00")
			buf = buf[:len(buf)-sz]
			o -= sz
		}
		buf = utf8.AppendRune(buf[:n-m], needle)

		n -= m // adjust for rune len
		for i := 0; i < b.N; i++ {
			j := IndexRune(buf, needle)
			if j != n {
				b.Fatal("bad index", j)
			}
		}
		for i := range buf {
			buf[i] = '\x00'
		}
	}
}

func BenchmarkEqual(b *testing.B) {
	b.Run("0", func(b *testing.B) {
		var buf [4]byte
		buf1 := buf[0:0]
		buf2 := buf[1:1]
		for i := 0; i < b.N; i++ {
			eq := Equal(buf1, buf2)
			if !eq {
				b.Fatal("bad equal")
			}
		}
	})

	sizes := []int{1, 6, 9, 15, 16, 20, 32, 4 << 10, 4 << 20, 64 << 20}

	b.Run("same", func(b *testing.B) {
		benchBytes(b, sizes, bmEqual(func(a, b []byte) bool { return Equal(a, a) }))
	})

	benchBytes(b, sizes, bmEqual(Equal))
}

func bmEqual(equal func([]byte, []byte) bool) func(b *testing.B, n int) {
	return func(b *testing.B, n int) {
		if len(bmbuf) < 2*n {
			bmbuf = make([]byte, 2*n)
		}
		buf1 := bmbuf[0:n]
		buf2 := bmbuf[n : 2*n]
		buf1[n-1] = 'x'
		buf2[n-1] = 'x'
		for i := 0; i < b.N; i++ {
			eq := equal(buf1, buf2)
			if !eq {
				b.Fatal("bad equal")
			}
		}
		buf1[n-1] = '\x00'
		buf2[n-1] = '\x00'
	}
}

func BenchmarkEqualBothUnaligned(b *testing.B) {
	sizes := []int{64, 4 << 10}
	if !isRaceBuilder {
		sizes = append(sizes, []int{4 << 20, 64 << 20}...)
	}
	maxSize := 2 * (sizes[len(sizes)-1] + 8)
	if len(bmbuf) < maxSize {
		bmbuf = make([]byte, maxSize)
	}

	for _, n := range sizes {
		for _, off := range []int{0, 1, 4, 7} {
			buf1 := bmbuf[off : off+n]
			buf2Start := (len(bmbuf) / 2) + off
			buf2 := bmbuf[buf2Start : buf2Start+n]
			buf1[n-1] = 'x'
			buf2[n-1] = 'x'
			b.Run(fmt.Sprint(n, off), func(b *testing.B) {
				b.SetBytes(int64(n))
				for i := 0; i < b.N; i++ {
					eq := Equal(buf1, buf2)
					if !eq {
						b.Fatal("bad equal")
					}
				}
			})
			buf1[n-1] = '\x00'
			buf2[n-1] = '\x00'
		}
	}
}

func BenchmarkIndex(b *testing.B) {
	benchBytes(b, indexSizes, func(b *testing.B, n int) {
		buf := bmbuf[0:n]
		buf[n-1] = 'x'
		for i := 0; i < b.N; i++ {
			j := Index(buf, buf[n-7:])
			if j != n-7 {
				b.Fatal("bad index", j)
			}
		}
		buf[n-1] = '\x00'
	})
}

func BenchmarkIndexEasy(b *testing.B) {
	benchBytes(b, indexSizes, func(b *testing.B, n int) {
		buf := bmbuf[0:n]
		buf[n-1] = 'x'
		buf[n-7] = 'x'
		for i := 0; i < b.N; i++ {
			j := Index(buf, buf[n-7:])
			if j != n-7 {
				b.Fatal("bad index", j)
			}
		}
		buf[n-1] = '\x00'
		buf[n-7] = '\x00'
	})
}

func BenchmarkCount(b *testing.B) {
	benchBytes(b, indexSizes, func(b *testing.B, n int) {
		buf := bmbuf[0:n]
		buf[n-1] = 'x'
		for i := 0; i < b.N; i++ {
			j := Count(buf, buf[n-7:])
			if j != 1 {
				b.Fatal("bad count", j)
			}
		}
		buf[n-1] = '\x00'
	})
}

func BenchmarkCountEasy(b *testing.B) {
	benchBytes(b, indexSizes, func(b *testing.B, n int) {
		buf := bmbuf[0:n]
		buf[n-1] = 'x'
		buf[n-7] = 'x'
		for i := 0; i < b.N; i++ {
			j := Count(buf, buf[n-7:])
			if j != 1 {
				b.Fatal("bad count", j)
			}
		}
		buf[n-1] = '\x00'
		buf[n-7] = '\x00'
	})
}

func BenchmarkCountSingle(b *testing.B) {
	benchBytes(b, indexSizes, func(b *testing.B, n int) {
		buf := bmbuf[0:n]
		step := 8
		for i := 0; i < len(buf); i += step {
			buf[i] = 1
		}
		expect := (len(buf) + (step - 1)) / step
		for i := 0; i < b.N; i++ {
			j := Count(buf, []byte{1})
			if j != expect {
				b.Fatal("bad count", j, expect)
			}
		}
		for i := 0; i < len(buf); i++ {
			buf[i] = 0
		}
	})
}

type SplitTest struct {
	s   string
	sep string
	n   int
	a   []string
}

var splittests = []SplitTest{
	{"", "", -1, []string{}},
	{abcd, "a", 0, nil},
	{abcd, "", 2, []string{"a", "bcd"}},
	{abcd, "a", -1, []string{"", "bcd"}},
	{abcd, "z", -1, []string{"abcd"}},
	{abcd, "", -1, []string{"a", "b", "c", "d"}},
	{commas, ",", -1, []string{"1", "2", "3", "4"}},
	{dots, "...", -1, []string{"1", ".2", ".3", ".4"}},
	{faces, "☹", -1, []string{"☺☻", ""}},
	{faces, "~", -1, []string{faces}},
	{faces, "", -1, []string{"☺", "☻", "☹"}},
	{"1 2 3 4", " ", 3, []string{"1", "2", "3 4"}},
	{"1 2", " ", 3, []string{"1", "2"}},
	{"123", "", 2, []string{"1", "23"}},
	{"123", "", 17, []string{"1", "2", "3"}},
	{"bT", "T", math.MaxInt / 4, []string{"b", ""}},
	{"\xff-\xff", "", -1, []string{"\xff", "-", "\xff"}},
	{"\xff-\xff", "-", -1, []string{"\xff", "\xff"}},
}

func TestSplit(t *testing.T) {
	for _, tt := range splittests {
		a := SplitN([]byte(tt.s), []byte(tt.sep), tt.n)

		// Appending to the results should not change future results.
		var x []byte
		for _, v := range a {
			x = append(v, 'z')
		}

		result := sliceOfString(a)
		if !slices.Equal(result, tt.a) {
			t.Errorf(`Split(%q, %q, %d) = %v; want %v`, tt.s, tt.sep, tt.n, result, tt.a)
			continue
		}

		if tt.n < 0 {
			b := sliceOfString(slices.Collect(SplitSeq([]byte(tt.s), []byte(tt.sep))))
			if !slices.Equal(b, tt.a) {
				t.Errorf(`collect(SplitSeq(%q, %q)) = %v; want %v`, tt.s, tt.sep, b, tt.a)
			}
		}

		if tt.n == 0 || len(a) == 0 {
			continue
		}

		if want := tt.a[len(tt.a)-1] + "z"; string(x) != want {
			t.Errorf("last appended result was %s; want %s", x, want)
		}

		s := Join(a, []byte(tt.sep))
		if string(s) != tt.s {
			t.Errorf(`Join(Split(%q, %q, %d), %q) = %q`, tt.s, tt.sep, tt.n, tt.sep, s)
		}
		if tt.n < 0 {
			b := sliceOfString(Split([]byte(tt.s), []byte(tt.sep)))
			if !slices.Equal(result, b) {
				t.Errorf("Split disagrees withSplitN(%q, %q, %d) = %v; want %v", tt.s, tt.sep, tt.n, b, a)
			}
		}
		if len(a) > 0 {
			in, out := a[0], s
			if cap(in) == cap(out) && &in[:1][0] == &out[:1][0] {
				t.Errorf("Join(%#v, %q) didn't copy", a, tt.sep)
			}
		}
	}
}

var splitaftertests = []SplitTest{
	{abcd, "a", -1, []string{"a", "bcd"}},
	{abcd, "z", -1, []string{"abcd"}},
	{abcd, "", -1, []string{"a", "b", "c", "d"}},
	{commas, ",", -1, []string{"1,", "2,", "3,", "4"}},
	{dots, "...", -1, []string{"1...", ".2...", ".3...", ".4"}},
	{faces, "☹", -1, []string{"☺☻☹", ""}},
	{faces, "~", -1, []string{faces}},
	{faces, "", -1, []string{"☺", "☻", "☹"}},
	{"1 2 3 4", " ", 3, []string{"1 ", "2 ", "3 4"}},
	{"1 2 3", " ", 3, []string{"1 ", "2 ", "3"}},
	{"1 2", " ", 3, []string{"1 ", "2"}},
	{"123", "", 2, []string{"1", "23"}},
	{"123", "", 17, []string{"1", "2", "3"}},
}

func TestSplitAfter(t *testing.T) {
	for _, tt := range splitaftertests {
		a := SplitAfterN([]byte(tt.s), []byte(tt.sep), tt.n)

		// Appending to the results should not change future results.
		var x []byte
		for _, v := range a {
			x = append(v, 'z')
		}

		result := sliceOfString(a)
		if !slices.Equal(result, tt.a) {
			t.Errorf(`Split(%q, %q, %d) = %v; want %v`, tt.s, tt.sep, tt.n, result, tt.a)
			continue
		}

		if tt.n < 0 {
			b := sliceOfString(slices.Collect(SplitAfterSeq([]byte(tt.s), []byte(tt.sep))))
			if !slices.Equal(b, tt.a) {
				t.Errorf(`collect(SplitAfterSeq(%q, %q)) = %v; want %v`, tt.s, tt.sep, b, tt.a)
			}
		}

		if want := tt.a[len(tt.a)-1] + "z"; string(x) != want {
			t.Errorf("last appended result was %s; want %s", x, want)
		}

		s := Join(a, nil)
		if string(s) != tt.s {
			t.Errorf(`Join(Split(%q, %q, %d), %q) = %q`, tt.s, tt.sep, tt.n, tt.sep, s)
		}
		if tt.n < 0 {
			b := sliceOfString(SplitAfter([]byte(tt.s), []byte(tt.sep)))
			if !slices.Equal(result, b) {
				t.Errorf("SplitAfter disagrees withSplitAfterN(%q, %q, %d) = %v; want %v", tt.s, tt.sep, tt.n, b, a)
			}
		}
	}
}

type FieldsTest struct {
	s string
	a []string
}

var fieldstests = []FieldsTest{
	{"", []string{}},
	{" ", []string{}},
	{" \t ", []string{}},
	{"  abc  ", []string{"abc"}},
	{"1 2 3 4", []string{"1", "2", "3", "4"}},
	{"1  2  3  4", []string{"1", "2", "3", "4"}},
	{"1\t\t2\t\t3\t4", []string{"1", "2", "3", "4"}},
	{"1\u20002\u20013\u20024", []string{"1", "2", "3", "4"}},
	{"\u2000\u2001\u2002", []string{}},
	{"\n™\t™\n", []string{"™", "™"}},
	{faces, []string{faces}},
}

func TestFields(t *testing.T) {
	for _, tt := range fieldstests {
		b := []byte(tt.s)
		a := Fields(b)

		// Appending to the results should not change future results.
		var x []byte
		for _, v := range a {
			x = append(v, 'z')
		}

		result := sliceOfString(a)
		if !slices.Equal(result, tt.a) {
			t.Errorf("Fields(%q) = %v; want %v", tt.s, a, tt.a)
			continue
		}

		result2 := sliceOfString(collect(t, FieldsSeq([]byte(tt.s))))
		if !slices.Equal(result2, tt.a) {
			t.Errorf(`collect(FieldsSeq(%q)) = %v; want %v`, tt.s, result2, tt.a)
		}

		if string(b) != tt.s {
			t.Errorf("slice changed to %s; want %s", string(b), tt.s)
		}
		if len(tt.a) > 0 {
			if want := tt.a[len(tt.a)-1] + "z"; string(x) != want {
				t.Errorf("last appended result was %s; want %s", x, want)
			}
		}
	}
}

func TestFieldsFunc(t *testing.T) {
	for _, tt := range fieldstests {
		a := FieldsFunc([]byte(tt.s), unicode.IsSpace)
		result := sliceOfString(a)
		if !slices.Equal(result, tt.a) {
			t.Errorf("FieldsFunc(%q, unicode.IsSpace) = %v; want %v", tt.s, a, tt.a)
			continue
		}
	}
	pred := func(c rune) bool { return c == 'X' }
	var fieldsFuncTests = []FieldsTest{
		{"", []string{}},
		{"XX", []string{}},
		{"XXhiXXX", []string{"hi"}},
		{"aXXbXXXcX", []string{"a", "b", "c"}},
	}
	for _, tt := range fieldsFuncTests {
		b := []byte(tt.s)
		a := FieldsFunc(b, pred)

		// Appending to the results should not change future results.
		var x []byte
		for _, v := range a {
			x = append(v, 'z')
		}

		result := sliceOfString(a)
		if !slices.Equal(result, tt.a) {
			t.Errorf("FieldsFunc(%q) = %v, want %v", tt.s, a, tt.a)
		}

		result2 := sliceOfString(collect(t, FieldsFuncSeq([]byte(tt.s), pred)))
		if !slices.Equal(result2, tt.a) {
			t.Errorf(`collect(FieldsFuncSeq(%q)) = %v; want %v`, tt.s, result2, tt.a)
		}

		if string(b) != tt.s {
			t.Errorf("slice changed to %s; want %s", b, tt.s)
		}
		if len(tt.a) > 0 {
			if want := tt.a[len(tt.a)-1] + "z"; string(x) != want {
				t.Errorf("last appended result was %s; want %s", x, want)
			}
		}
	}
}

// Test case for any function which accepts and returns a byte slice.
// For ease of creation, we write the input byte slice as a string.
type StringTest struct {
	in  string
	out []byte
}

var upperTests = []StringTest{
	{"", []byte("")},
	{"ONLYUPPER", []byte("ONLYUPPER")},
	{"abc", []byte("ABC")},
	{"AbC123", []byte("ABC123")},
	{"azAZ09_", []byte("AZAZ09_")},
	{"longStrinGwitHmixofsmaLLandcAps", []byte("LONGSTRINGWITHMIXOFSMALLANDCAPS")},
	{"long\u0250string\u0250with\u0250nonascii\u2C6Fchars", []byte("LONG\u2C6FSTRING\u2C6FWITH\u2C6FNONASCII\u2C6FCHARS")},
	{"\u0250\u0250\u0250\u0250\u0250", []byte("\u2C6F\u2C6F\u2C6F\u2C6F\u2C6F")}, // grows one byte per char
	{"a\u0080\U0010FFFF", []byte("A\u0080\U0010FFFF")},                           // test utf8.RuneSelf and utf8.MaxRune
}

var lowerTests = []StringTest{
	{"", []byte("")},
	{"abc", []byte("abc")},
	{"AbC123", []byte("abc123")},
	{"azAZ09_", []byte("azaz09_")},
	{"longStrinGwitHmixofsmaLLandcAps", []byte("longstringwithmixofsmallandcaps")},
	{"LONG\u2C6FSTRING\u2C6FWITH\u2C6FNONASCII\u2C6FCHARS", []byte("long\u0250string\u0250with\u0250nonascii\u0250chars")},
	{"\u2C6D\u2C6D\u2C6D\u2C6D\u2C6D", []byte("\u0251\u0251\u0251\u0251\u0251")}, // shrinks one byte per char
	{"A\u0080\U0010FFFF", []byte("a\u0080\U0010FFFF")},                           // test utf8.RuneSelf and utf8.MaxRune
}

const space = "\t\v\r\f\n\u0085\u00a0\u2000\u3000"

var trimSpaceTests = []StringTest{
	{"", nil},
	{"  a", []byte("a")},
	{"b  ", []byte("b")},
	{"abc", []byte("abc")},
	{space + "abc" + space, []byte("abc")},
	{" ", nil},
	{"\u3000 ", nil},
	{" \u3000", nil},
	{" \t\r\n \t\t\r\r\n\n ", nil},
	{" \t\r\n x\t\t\r\r\n\n ", []byte("x")},
	{" \u2000\t\r\n x\t\t\r\r\ny\n \u3000", []byte("x\t\t\r\r\ny")},
	{"1 \t\r\n2", []byte("1 \t\r\n2")},
	{" x\x80", []byte("x\x80")},
	{" x\xc0", []byte("x\xc0")},
	{"x \xc0\xc0 ", []byte("x \xc0\xc0")},
	{"x \xc0", []byte("x \xc0")},
	{"x \xc0 ", []byte("x \xc0")},
	{"x \xc0\xc0 ", []byte("x \xc0\xc0")},
	{"x ☺\xc0\xc0 ", []byte("x ☺\xc0\xc0")},
	{"x ☺ ", []byte("x ☺")},
}

// Execute f on each test case.  funcName should be the name of f; it's used
// in failure reports.
func runStringTests(t *testing.T, f func([]byte) []byte, funcName string, testCases []StringTest) {
	for _, tc := range testCases {
		actual := f([]byte(tc.in))
		if actual == nil && tc.out != nil {
			t.Errorf("%s(%q) = nil; want %q", funcName, tc.in, tc.out)
		}
		if actual != nil && tc.out == nil {
			t.Errorf("%s(%q) = %q; want nil", funcName, tc.in, actual)
		}
		if !Equal(actual, tc.out) {
			t.Errorf("%s(%q) = %q; want %q", funcName, tc.in, actual, tc.out)
		}
	}
}

func tenRunes(r rune) string {
	runes := make([]rune, 10)
	for i := range runes {
		runes[i] = r
	}
	return string(runes)
}

// User-defined self-inverse mapping function
func rot13(r rune) rune {
	const step = 13
	if r >= 'a' && r <= 'z' {
		return ((r - 'a' + step) % 26) + 'a'
	}
	if r >= 'A' && r <= 'Z' {
		return ((r - 'A' + step) % 26) + 'A'
	}
	return r
}

func TestMap(t *testing.T) {
	// Run a couple of awful growth/shrinkage tests
	a := tenRunes('a')

	// 1.  Grow. This triggers two reallocations in Map.
	maxRune := func(r rune) rune { return unicode.MaxRune }
	m := Map(maxRune, []byte(a))
	expect := tenRunes(unicode.MaxRune)
	if string(m) != expect {
		t.Errorf("growing: expected %q got %q", expect, m)
	}

	// 2. Shrink
	minRune := func(r rune) rune { return 'a' }
	m = Map(minRune, []byte(tenRunes(unicode.MaxRune)))
```