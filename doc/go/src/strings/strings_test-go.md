Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The user wants to know the functionality of the provided Go code snippet, which is a part of the `strings_test.go` file. The request asks for a summary of its functions, potential code implementation examples (if deducible), explanations of command-line argument handling (if any), common mistakes users might make, and a final summary of its functionality.

2. **Initial Scan and Identify Key Components:** I quickly scan the code, looking for function declarations, test structures, and variable names. This gives me a high-level overview of what the code is doing. I see a lot of `Test...` functions, which strongly indicates this is a testing file. The presence of `linesTests`, `indexTests`, `splittests`, etc., suggests these are test cases for various string manipulation functions. The imports like `testing`, `strings`, `unicode`, and `utf8` confirm this.

3. **Analyze Test Functions and Their Associated Data Structures:**  I examine each `Test...` function and the corresponding data structures (like `linesTests`, `indexTests`, etc.). This is where the core functionality is revealed.

    * **`TestLines` and `linesTests`:**  The structure `LinesTest` has an input string `a` and an expected output slice of strings `b`. The `TestLines` function iterates through these cases and checks if the `strings.Lines` function (which we can infer exists) produces the expected output when given the input string. This strongly suggests `strings.Lines` splits a string into lines.

    * **`TestIndex`, `TestLastIndex`, `TestIndexAny`, `TestLastIndexAny`, `TestIndexByte`, `TestLastIndexByte` and their respective `indexTests` and similar:**  The `IndexTest` structure has input strings `s` and `sep` (separator) and an expected integer `out`. The test functions call functions like `strings.Index`, `strings.LastIndex`, etc., passing the input strings and comparing the returned integer with the expected output. This clearly points to functionality related to finding the index of substrings or characters within a string.

    * **`TestSplit`, `TestSplitAfter`, `TestFields`, `TestFieldsFunc` and their associated data:** Similar patterns emerge. `SplitTest` contains input string, separator, a limit `n`, and expected output slice of strings. The test functions call `strings.SplitN`, `strings.Split`, `strings.SplitAfterN`, `strings.SplitAfter`, `strings.Fields`, and `strings.FieldsFunc`, suggesting these functions are about splitting strings based on delimiters or conditions.

    * **`TestToUpper`, `TestToLower`, `TestTrimSpace`, `TestTrim`, `TestTrimFunc`, `TestMap`, `TestToValidUTF8`, `TestIndexFunc`, `TestCaseConsistency` and their data:** These tests demonstrate functions for case conversion (`ToUpper`, `ToLower`), trimming whitespace or specified characters (`TrimSpace`, `Trim`, `TrimFunc`), applying a mapping function to runes (`Map`), validating UTF-8 encoding (`ToValidUTF8`), and finding indices based on functions (`IndexFunc`, `LastIndexFunc`). `TestCaseConsistency` likely performs broader checks on the case conversion functions.

4. **Infer Function Signatures and Examples (Instruction #2):** Based on the test cases and function calls, I can infer the signatures of the `strings` package functions being tested. For example:

    * `strings.Lines(s string) iter.Seq[string]`
    * `strings.Index(s, substr string) int`
    * `strings.LastIndex(s, substr string) int`
    * `strings.SplitN(s, sep string, n int) []string`
    * `strings.Split(s, sep string) []string`
    * `strings.TrimSpace(s string) string`
    * `strings.ToUpper(s string) string`

    I can then construct simple Go code examples to demonstrate their usage based on the test cases.

5. **Command-Line Arguments (Instruction #4):** I carefully review the code for any use of `os.Args` or similar mechanisms for handling command-line arguments. Since this is a test file, it's highly unlikely to process command-line arguments directly. The `testing` package handles the test execution. Thus, I conclude that this specific snippet doesn't handle command-line arguments.

6. **Common Mistakes (Instruction #5):** I think about common errors users might make when using string manipulation functions, particularly those demonstrated in the tests.

    * **Incorrect understanding of `SplitN`'s `n` parameter:**  Users might not grasp how the limit affects the number of substrings returned.
    * **Confusion between `Split` and `SplitAfter`:** The difference between including or excluding the separator in the resulting substrings can be a source of errors.
    * **Misunderstanding how `TrimFunc` works:** Users need to provide a function that correctly identifies the characters to trim.

7. **Synthesize the Functionality Summary (Instructions #1 and #6):**  I combine my understanding from the previous steps to summarize the functionality of the code. I group the test functions based on the `strings` package functions they are testing.

8. **Refine and Organize the Answer:** I structure the answer clearly, addressing each part of the user's request. I use headings and bullet points to improve readability and ensure all aspects are covered. I provide the requested Go code examples and input/output scenarios. I explicitly state that command-line argument handling is not present.

This systematic approach allows me to thoroughly analyze the code snippet and provide a comprehensive answer to the user's request.
## 功能归纳：go/src/strings/strings_test.go 第 1 部分

这部分代码是 Go 语言标准库 `strings` 包的**测试代码**，主要用于测试 `strings` 包中一系列字符串操作相关的功能。

具体来说，它涵盖了以下功能的测试：

1. **行分割 (Line Splitting):**  测试 `strings` 包中将字符串分割成多行的功能，能够处理不同的换行符（`\n`, `\r\n`）。
2. **子串查找 (Substring Searching):** 测试 `strings` 包中查找子串在字符串中首次出现和最后一次出现的位置，包括查找特定子串、查找任意字符、以及查找特定字节。
3. **字符串分割 (String Splitting):** 测试 `strings` 包中根据分隔符将字符串分割成多个子串的功能，包括指定分割次数和不指定分割次数的情况，以及在分隔符之后进行分割。
4. **空白符分割 (Whitespace Splitting):** 测试 `strings` 包中根据空白符（空格、制表符、换行符等）将字符串分割成多个子串的功能。
5. **函数式分割 (Functional Splitting):** 测试 `strings` 包中根据自定义的函数来判断是否分割字符串的功能。
6. **大小写转换 (Case Conversion):** 测试 `strings` 包中将字符串转换为大写和小写的功能，包括处理非 ASCII 字符的情况。
7. **空白符去除 (Whitespace Trimming):** 测试 `strings` 包中去除字符串开头和结尾空白符的功能。
8. **字符去除 (Character Trimming):** 测试 `strings` 包中去除字符串开头和结尾指定字符的功能。
9. **前缀和后缀去除 (Prefix and Suffix Trimming):** 测试 `strings` 包中去除字符串指定前缀和后缀的功能。
10. **UTF-8 校验和替换 (UTF-8 Validation and Replacement):** 测试 `strings` 包中将字符串中无效的 UTF-8 字符替换为指定字符的功能。
11. **字符映射 (Character Mapping):** 测试 `strings` 包中根据指定的映射函数修改字符串中每个字符的功能。
12. **函数式查找 (Functional Searching):** 测试 `strings` 包中根据自定义的函数来查找字符串中第一个和最后一个满足条件的字符的功能。

**简单来说，这部分测试代码覆盖了 `strings` 包中关于查找、分割、转换和修剪字符串的基础功能。**

虽然代码本身是测试代码，但我们可以从中推断出被测试的 Go 语言功能的实现。以下是一些用 Go 代码举例说明的示例：

**1. 行分割 (对应 `TestLines`)**

```go
package main

import (
	"fmt"
	"strings"
)

func main() {
	text := "abc\nabc\n"
	lines := strings.SplitAfter(text, "\n") // 推测 strings.Lines 内部可能使用了类似 SplitAfter 的方法

	fmt.Println(lines) // 输出: [abc
	//  abc
	//  ]
}
```

**假设输入:**  `"abc\nabc\n"`
**推测输出:** `["abc\n", "abc\n"]`

**2. 子串查找 (对应 `TestIndex`)**

```go
package main

import (
	"fmt"
	"strings"
)

func main() {
	text := "hello world"
	index := strings.Index(text, "world")

	fmt.Println(index) // 输出: 6
}
```

**假设输入:** `text = "hello world"`, `sep = "world"`
**推测输出:** `6`

**3. 字符串分割 (对应 `TestSplit`)**

```go
package main

import (
	"fmt"
	"strings"
)

func main() {
	text := "apple,banana,orange"
	parts := strings.Split(text, ",")

	fmt.Println(parts) // 输出: [apple banana orange]
}
```

**假设输入:** `s = "apple,banana,orange"`, `sep = ","`
**推测输出:** `["apple", "banana", "orange"]`

**4. 大小写转换 (对应 `TestToUpper`, `TestToLower`)**

```go
package main

import (
	"fmt"
	"strings"
)

func main() {
	text := "Hello World"
	upper := strings.ToUpper(text)
	lower := strings.ToLower(text)

	fmt.Println("Upper:", upper) // 输出: Upper: HELLO WORLD
	fmt.Println("Lower:", lower) // 输出: Lower: hello world
}
```

**假设输入:** `in = "Hello World"`
**推测 `strings.ToUpper` 输出:** `"HELLO WORLD"`
**推测 `strings.ToLower` 输出:** `"hello world"`

**命令行参数处理：**

这部分代码主要是测试代码，它本身 **不涉及** 命令行参数的具体处理。Go 语言的测试工具 `go test` 负责运行这些测试，可以通过命令行参数来控制测试的范围、详细程度等，但这部分代码本身并没有直接处理这些参数。

**使用者易犯错的点：**

在理解和使用 `strings` 包中的功能时，使用者可能会犯以下错误（虽然这部分代码本身没有直接展示用户代码，但可以从测试用例中推断）：

* **`SplitN` 的第二个参数 `n` 的理解:**  `n` 参数指定了分割的次数，可能不总是返回所有子串，需要理解其作用。
* **`Split` 和 `SplitAfter` 的区别:** 容易混淆是否包含分隔符在结果中的区别。
* **`Trim` 和 `TrimSpace` 的区别:** `Trim` 需要指定要去除的字符集合，而 `TrimSpace` 专门去除空白符。
* **字符编码问题:**  在处理包含 Unicode 字符的字符串时，可能会因为不了解 UTF-8 编码而导致意想不到的结果。例如，使用字节索引而不是 rune 索引。
* **自定义 `FieldsFunc` 的判断逻辑:**  提供的函数需要准确地判断哪些字符应该作为分隔符。

**总结：**

这部分 `go/src/strings/strings_test.go` 代码是 `strings` 包的核心功能测试集的一部分，它详细测试了字符串的分割、查找、转换和修剪等基础操作，确保了这些功能的正确性和健壮性。通过分析这些测试用例，可以深入了解 `strings` 包中各个函数的使用方法和边界情况。

Prompt: 
```
这是路径为go/src/strings/strings_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package strings_test

import (
	"bytes"
	"fmt"
	"io"
	"iter"
	"math"
	"math/rand"
	"slices"
	"strconv"
	. "strings"
	"testing"
	"unicode"
	"unicode/utf8"
	"unsafe"
)

func collect(t *testing.T, seq iter.Seq[string]) []string {
	out := slices.Collect(seq)
	out1 := slices.Collect(seq)
	if !slices.Equal(out, out1) {
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
		result := slices.Collect(Lines(s.a))
		if !slices.Equal(result, s.b) {
			t.Errorf(`slices.Collect(Lines(%q)) = %q; want %q`, s.a, result, s.b)
		}
	}
}

var abcd = "abcd"
var faces = "☺☻☹"
var commas = "1,2,3,4"
var dots = "1....2....3....4"

type IndexTest struct {
	s   string
	sep string
	out int
}

var indexTests = []IndexTest{
	{"", "", 0},
	{"", "a", -1},
	{"", "foo", -1},
	{"fo", "foo", -1},
	{"foo", "foo", 0},
	{"oofofoofooo", "f", 2},
	{"oofofoofooo", "foo", 4},
	{"barfoobarfoo", "foo", 3},
	{"foo", "", 0},
	{"foo", "o", 1},
	{"abcABCabc", "A", 3},
	{"jrzm6jjhorimglljrea4w3rlgosts0w2gia17hno2td4qd1jz", "jz", 47},
	{"ekkuk5oft4eq0ocpacknhwouic1uua46unx12l37nioq9wbpnocqks6", "ks6", 52},
	{"999f2xmimunbuyew5vrkla9cpwhmxan8o98ec", "98ec", 33},
	{"9lpt9r98i04k8bz6c6dsrthb96bhi", "96bhi", 24},
	{"55u558eqfaod2r2gu42xxsu631xf0zobs5840vl", "5840vl", 33},
	// cases with one byte strings - test special case in Index()
	{"", "a", -1},
	{"x", "a", -1},
	{"x", "x", 0},
	{"abc", "a", 0},
	{"abc", "b", 1},
	{"abc", "c", 2},
	{"abc", "x", -1},
	// test special cases in Index() for short strings
	{"", "ab", -1},
	{"bc", "ab", -1},
	{"ab", "ab", 0},
	{"xab", "ab", 1},
	{"xab"[:2], "ab", -1},
	{"", "abc", -1},
	{"xbc", "abc", -1},
	{"abc", "abc", 0},
	{"xabc", "abc", 1},
	{"xabc"[:3], "abc", -1},
	{"xabxc", "abc", -1},
	{"", "abcd", -1},
	{"xbcd", "abcd", -1},
	{"abcd", "abcd", 0},
	{"xabcd", "abcd", 1},
	{"xyabcd"[:5], "abcd", -1},
	{"xbcqq", "abcqq", -1},
	{"abcqq", "abcqq", 0},
	{"xabcqq", "abcqq", 1},
	{"xyabcqq"[:6], "abcqq", -1},
	{"xabxcqq", "abcqq", -1},
	{"xabcqxq", "abcqq", -1},
	{"", "01234567", -1},
	{"32145678", "01234567", -1},
	{"01234567", "01234567", 0},
	{"x01234567", "01234567", 1},
	{"x0123456x01234567", "01234567", 9},
	{"xx01234567"[:9], "01234567", -1},
	{"", "0123456789", -1},
	{"3214567844", "0123456789", -1},
	{"0123456789", "0123456789", 0},
	{"x0123456789", "0123456789", 1},
	{"x012345678x0123456789", "0123456789", 11},
	{"xyz0123456789"[:12], "0123456789", -1},
	{"x01234567x89", "0123456789", -1},
	{"", "0123456789012345", -1},
	{"3214567889012345", "0123456789012345", -1},
	{"0123456789012345", "0123456789012345", 0},
	{"x0123456789012345", "0123456789012345", 1},
	{"x012345678901234x0123456789012345", "0123456789012345", 17},
	{"", "01234567890123456789", -1},
	{"32145678890123456789", "01234567890123456789", -1},
	{"01234567890123456789", "01234567890123456789", 0},
	{"x01234567890123456789", "01234567890123456789", 1},
	{"x0123456789012345678x01234567890123456789", "01234567890123456789", 21},
	{"xyz01234567890123456789"[:22], "01234567890123456789", -1},
	{"", "0123456789012345678901234567890", -1},
	{"321456788901234567890123456789012345678911", "0123456789012345678901234567890", -1},
	{"0123456789012345678901234567890", "0123456789012345678901234567890", 0},
	{"x0123456789012345678901234567890", "0123456789012345678901234567890", 1},
	{"x012345678901234567890123456789x0123456789012345678901234567890", "0123456789012345678901234567890", 32},
	{"xyz0123456789012345678901234567890"[:33], "0123456789012345678901234567890", -1},
	{"", "01234567890123456789012345678901", -1},
	{"32145678890123456789012345678901234567890211", "01234567890123456789012345678901", -1},
	{"01234567890123456789012345678901", "01234567890123456789012345678901", 0},
	{"x01234567890123456789012345678901", "01234567890123456789012345678901", 1},
	{"x0123456789012345678901234567890x01234567890123456789012345678901", "01234567890123456789012345678901", 33},
	{"xyz01234567890123456789012345678901"[:34], "01234567890123456789012345678901", -1},
	{"xxxxxx012345678901234567890123456789012345678901234567890123456789012", "012345678901234567890123456789012345678901234567890123456789012", 6},
	{"", "0123456789012345678901234567890123456789", -1},
	{"xx012345678901234567890123456789012345678901234567890123456789012", "0123456789012345678901234567890123456789", 2},
	{"xx012345678901234567890123456789012345678901234567890123456789012"[:41], "0123456789012345678901234567890123456789", -1},
	{"xx012345678901234567890123456789012345678901234567890123456789012", "0123456789012345678901234567890123456xxx", -1},
	{"xx0123456789012345678901234567890123456789012345678901234567890120123456789012345678901234567890123456xxx", "0123456789012345678901234567890123456xxx", 65},
	// test fallback to Rabin-Karp.
	{"oxoxoxoxoxoxoxoxoxoxoxoy", "oy", 22},
	{"oxoxoxoxoxoxoxoxoxoxoxox", "oy", -1},
	// test fallback to IndexRune
	{"oxoxoxoxoxoxoxoxoxoxox☺", "☺", 22},
	// invalid UTF-8 byte sequence (must be longer than bytealg.MaxBruteForce to
	// test that we don't use IndexRune)
	{"xx0123456789012345678901234567890123456789012345678901234567890120123456789012345678901234567890123456xxx\xed\x9f\xc0", "\xed\x9f\xc0", 105},
}

var lastIndexTests = []IndexTest{
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

var indexAnyTests = []IndexTest{
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

var lastIndexAnyTests = []IndexTest{
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
func runIndexTests(t *testing.T, f func(s, sep string) int, funcName string, testCases []IndexTest) {
	for _, test := range testCases {
		actual := f(test.s, test.sep)
		if actual != test.out {
			t.Errorf("%s(%q,%q) = %v; want %v", funcName, test.s, test.sep, actual, test.out)
		}
	}
}

func TestIndex(t *testing.T)     { runIndexTests(t, Index, "Index", indexTests) }
func TestLastIndex(t *testing.T) { runIndexTests(t, LastIndex, "LastIndex", lastIndexTests) }
func TestIndexAny(t *testing.T)  { runIndexTests(t, IndexAny, "IndexAny", indexAnyTests) }
func TestLastIndexAny(t *testing.T) {
	runIndexTests(t, LastIndexAny, "LastIndexAny", lastIndexAnyTests)
}

func TestIndexByte(t *testing.T) {
	for _, tt := range indexTests {
		if len(tt.sep) != 1 {
			continue
		}
		pos := IndexByte(tt.s, tt.sep[0])
		if pos != tt.out {
			t.Errorf(`IndexByte(%q, %q) = %v; want %v`, tt.s, tt.sep[0], pos, tt.out)
		}
	}
}

func TestLastIndexByte(t *testing.T) {
	testCases := []IndexTest{
		{"", "q", -1},
		{"abcdef", "q", -1},
		{"abcdefabcdef", "a", len("abcdef")},      // something in the middle
		{"abcdefabcdef", "f", len("abcdefabcde")}, // last byte
		{"zabcdefabcdef", "z", 0},                 // first byte
		{"a☺b☻c☹d", "b", len("a☺")},               // non-ascii
	}
	for _, test := range testCases {
		actual := LastIndexByte(test.s, test.sep[0])
		if actual != test.out {
			t.Errorf("LastIndexByte(%q,%c) = %v; want %v", test.s, test.sep[0], actual, test.out)
		}
	}
}

func simpleIndex(s, sep string) int {
	n := len(sep)
	for i := n; i <= len(s); i++ {
		if s[i-n:i] == sep {
			return i - n
		}
	}
	return -1
}

func TestIndexRandom(t *testing.T) {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	for times := 0; times < 10; times++ {
		for strLen := 5 + rand.Intn(5); strLen < 140; strLen += 10 { // Arbitrary
			s1 := make([]byte, strLen)
			for i := range s1 {
				s1[i] = chars[rand.Intn(len(chars))]
			}
			s := string(s1)
			for i := 0; i < 50; i++ {
				begin := rand.Intn(len(s) + 1)
				end := begin + rand.Intn(len(s)+1-begin)
				sep := s[begin:end]
				if i%4 == 0 {
					pos := rand.Intn(len(sep) + 1)
					sep = sep[:pos] + "A" + sep[pos:]
				}
				want := simpleIndex(s, sep)
				res := Index(s, sep)
				if res != want {
					t.Errorf("Index(%s,%s) = %d; want %d", s, sep, res, want)
				}
			}
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

		// 2 bytes
		{"ӆ", 'ӆ', 0},
		{"a", 'ӆ', -1},
		{"  ӆ", 'ӆ', 2},
		{"  a", 'ӆ', -1},
		{Repeat("ц", 64) + "ӆ", 'ӆ', 128}, // test cutover
		{Repeat("Ꙁ", 64) + "Ꚁ", '䚀', -1},  // 'Ꚁ' and '䚀' share the same last two bytes

		// 3 bytes
		{"Ꚁ", 'Ꚁ', 0},
		{"a", 'Ꚁ', -1},
		{"  Ꚁ", 'Ꚁ', 2},
		{"  a", 'Ꚁ', -1},
		{Repeat("Ꙁ", 64) + "Ꚁ", 'Ꚁ', 192}, // test cutover
		{Repeat("𡋀", 64) + "𡌀", '𣌀', -1},  // '𡌀' and '𣌀' share the same last two bytes

		// 4 bytes
		{"𡌀", '𡌀', 0},
		{"a", '𡌀', -1},
		{"  𡌀", '𡌀', 2},
		{"  a", '𡌀', -1},
		{Repeat("𡋀", 64) + "𡌀", '𡌀', 256}, // test cutover
		{Repeat("𡋀", 64), '𡌀', -1},

		// Test the cutover to bytealg.IndexString when it is triggered in
		// the middle of rune that contains consecutive runs of equal bytes.
		{"aaaaaKKKK\U000bc104", '\U000bc104', 17}, // cutover: (n + 16) / 8
		{"aaaaaKKKK鄄", '鄄', 17},
		{"aaKKKKKa\U000bc104", '\U000bc104', 18}, // cutover: 4 + n>>4
		{"aaKKKKKa鄄", '鄄', 18},
	}
	for _, tt := range tests {
		if got := IndexRune(tt.in, tt.rune); got != tt.want {
			t.Errorf("IndexRune(%q, %d) = %v; want %v", tt.in, tt.rune, got, tt.want)
		}
	}

	// Make sure we trigger the cutover and string(rune) conversion.
	haystack := "test" + Repeat("𡋀", 32) + "𡌀"
	allocs := testing.AllocsPerRun(1000, func() {
		if i := IndexRune(haystack, 's'); i != 2 {
			t.Fatalf("'s' at %d; want 2", i)
		}
		if i := IndexRune(haystack, '𡌀'); i != 132 {
			t.Fatalf("'𡌀' at %d; want 4", i)
		}
	})
	if allocs != 0 && testing.CoverMode() == "" {
		t.Errorf("expected no allocations, got %f", allocs)
	}
}

const benchmarkString = "some_text=some☺value"

func BenchmarkIndexRune(b *testing.B) {
	if got := IndexRune(benchmarkString, '☺'); got != 14 {
		b.Fatalf("wrong index: expected 14, got=%d", got)
	}
	for i := 0; i < b.N; i++ {
		IndexRune(benchmarkString, '☺')
	}
}

var benchmarkLongString = Repeat(" ", 100) + benchmarkString

func BenchmarkIndexRuneLongString(b *testing.B) {
	if got := IndexRune(benchmarkLongString, '☺'); got != 114 {
		b.Fatalf("wrong index: expected 114, got=%d", got)
	}
	for i := 0; i < b.N; i++ {
		IndexRune(benchmarkLongString, '☺')
	}
}

func BenchmarkIndexRuneFastPath(b *testing.B) {
	if got := IndexRune(benchmarkString, 'v'); got != 17 {
		b.Fatalf("wrong index: expected 17, got=%d", got)
	}
	for i := 0; i < b.N; i++ {
		IndexRune(benchmarkString, 'v')
	}
}

func BenchmarkIndex(b *testing.B) {
	if got := Index(benchmarkString, "v"); got != 17 {
		b.Fatalf("wrong index: expected 17, got=%d", got)
	}
	for i := 0; i < b.N; i++ {
		Index(benchmarkString, "v")
	}
}

func BenchmarkLastIndex(b *testing.B) {
	if got := Index(benchmarkString, "v"); got != 17 {
		b.Fatalf("wrong index: expected 17, got=%d", got)
	}
	for i := 0; i < b.N; i++ {
		LastIndex(benchmarkString, "v")
	}
}

func BenchmarkIndexByte(b *testing.B) {
	if got := IndexByte(benchmarkString, 'v'); got != 17 {
		b.Fatalf("wrong index: expected 17, got=%d", got)
	}
	for i := 0; i < b.N; i++ {
		IndexByte(benchmarkString, 'v')
	}
}

type SplitTest struct {
	s   string
	sep string
	n   int
	a   []string
}

var splittests = []SplitTest{
	{"", "", -1, []string{}},
	{abcd, "", 2, []string{"a", "bcd"}},
	{abcd, "", 4, []string{"a", "b", "c", "d"}},
	{abcd, "", -1, []string{"a", "b", "c", "d"}},
	{faces, "", -1, []string{"☺", "☻", "☹"}},
	{faces, "", 3, []string{"☺", "☻", "☹"}},
	{faces, "", 17, []string{"☺", "☻", "☹"}},
	{"☺�☹", "", -1, []string{"☺", "�", "☹"}},
	{abcd, "a", 0, nil},
	{abcd, "a", -1, []string{"", "bcd"}},
	{abcd, "z", -1, []string{"abcd"}},
	{commas, ",", -1, []string{"1", "2", "3", "4"}},
	{dots, "...", -1, []string{"1", ".2", ".3", ".4"}},
	{faces, "☹", -1, []string{"☺☻", ""}},
	{faces, "~", -1, []string{faces}},
	{"1 2 3 4", " ", 3, []string{"1", "2", "3 4"}},
	{"1 2", " ", 3, []string{"1", "2"}},
	{"", "T", math.MaxInt / 4, []string{""}},
	{"\xff-\xff", "", -1, []string{"\xff", "-", "\xff"}},
	{"\xff-\xff", "-", -1, []string{"\xff", "\xff"}},
}

func TestSplit(t *testing.T) {
	for _, tt := range splittests {
		a := SplitN(tt.s, tt.sep, tt.n)
		if !slices.Equal(a, tt.a) {
			t.Errorf("Split(%q, %q, %d) = %v; want %v", tt.s, tt.sep, tt.n, a, tt.a)
			continue
		}
		if tt.n < 0 {
			a2 := slices.Collect(SplitSeq(tt.s, tt.sep))
			if !slices.Equal(a2, tt.a) {
				t.Errorf(`collect(SplitSeq(%q, %q)) = %v; want %v`, tt.s, tt.sep, a2, tt.a)
			}
		}
		if tt.n == 0 {
			continue
		}
		s := Join(a, tt.sep)
		if s != tt.s {
			t.Errorf("Join(Split(%q, %q, %d), %q) = %q", tt.s, tt.sep, tt.n, tt.sep, s)
		}
		if tt.n < 0 {
			b := Split(tt.s, tt.sep)
			if !slices.Equal(a, b) {
				t.Errorf("Split disagrees with SplitN(%q, %q, %d) = %v; want %v", tt.s, tt.sep, tt.n, b, a)
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
		a := SplitAfterN(tt.s, tt.sep, tt.n)
		if !slices.Equal(a, tt.a) {
			t.Errorf(`Split(%q, %q, %d) = %v; want %v`, tt.s, tt.sep, tt.n, a, tt.a)
			continue
		}
		if tt.n < 0 {
			a2 := slices.Collect(SplitAfterSeq(tt.s, tt.sep))
			if !slices.Equal(a2, tt.a) {
				t.Errorf(`collect(SplitAfterSeq(%q, %q)) = %v; want %v`, tt.s, tt.sep, a2, tt.a)
			}
		}
		s := Join(a, "")
		if s != tt.s {
			t.Errorf(`Join(Split(%q, %q, %d), %q) = %q`, tt.s, tt.sep, tt.n, tt.sep, s)
		}
		if tt.n < 0 {
			b := SplitAfter(tt.s, tt.sep)
			if !slices.Equal(a, b) {
				t.Errorf("SplitAfter disagrees with SplitAfterN(%q, %q, %d) = %v; want %v", tt.s, tt.sep, tt.n, b, a)
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
	{"\u2000", []string{}},
	{"  abc  ", []string{"abc"}},
	{"1 2 3 4", []string{"1", "2", "3", "4"}},
	{"1  2  3  4", []string{"1", "2", "3", "4"}},
	{"1\t\t2\t\t3\t4", []string{"1", "2", "3", "4"}},
	{"1\u20002\u20013\u20024", []string{"1", "2", "3", "4"}},
	{"\u2000\u2001\u2002", []string{}},
	{"\n™\t™\n", []string{"™", "™"}},
	{"\n\u20001™2\u2000 \u2001 ™", []string{"1™2", "™"}},
	{"\n1\uFFFD \uFFFD2\u20003\uFFFD4", []string{"1\uFFFD", "\uFFFD2", "3\uFFFD4"}},
	{"1\xFF\u2000\xFF2\xFF \xFF", []string{"1\xFF", "\xFF2\xFF", "\xFF"}},
	{faces, []string{faces}},
}

func TestFields(t *testing.T) {
	for _, tt := range fieldstests {
		a := Fields(tt.s)
		if !slices.Equal(a, tt.a) {
			t.Errorf("Fields(%q) = %v; want %v", tt.s, a, tt.a)
			continue
		}
		a2 := collect(t, FieldsSeq(tt.s))
		if !slices.Equal(a2, tt.a) {
			t.Errorf(`collect(FieldsSeq(%q)) = %v; want %v`, tt.s, a2, tt.a)
		}
	}
}

var FieldsFuncTests = []FieldsTest{
	{"", []string{}},
	{"XX", []string{}},
	{"XXhiXXX", []string{"hi"}},
	{"aXXbXXXcX", []string{"a", "b", "c"}},
}

func TestFieldsFunc(t *testing.T) {
	for _, tt := range fieldstests {
		a := FieldsFunc(tt.s, unicode.IsSpace)
		if !slices.Equal(a, tt.a) {
			t.Errorf("FieldsFunc(%q, unicode.IsSpace) = %v; want %v", tt.s, a, tt.a)
			continue
		}
	}
	pred := func(c rune) bool { return c == 'X' }
	for _, tt := range FieldsFuncTests {
		a := FieldsFunc(tt.s, pred)
		if !slices.Equal(a, tt.a) {
			t.Errorf("FieldsFunc(%q) = %v, want %v", tt.s, a, tt.a)
		}
		a2 := collect(t, FieldsFuncSeq(tt.s, pred))
		if !slices.Equal(a2, tt.a) {
			t.Errorf(`collect(FieldsFuncSeq(%q)) = %v; want %v`, tt.s, a2, tt.a)
		}
	}
}

// Test case for any function which accepts and returns a single string.
type StringTest struct {
	in, out string
}

// Execute f on each test case.  funcName should be the name of f; it's used
// in failure reports.
func runStringTests(t *testing.T, f func(string) string, funcName string, testCases []StringTest) {
	for _, tc := range testCases {
		actual := f(tc.in)
		if actual != tc.out {
			t.Errorf("%s(%q) = %q; want %q", funcName, tc.in, actual, tc.out)
		}
	}
}

var upperTests = []StringTest{
	{"", ""},
	{"ONLYUPPER", "ONLYUPPER"},
	{"abc", "ABC"},
	{"AbC123", "ABC123"},
	{"azAZ09_", "AZAZ09_"},
	{"longStrinGwitHmixofsmaLLandcAps", "LONGSTRINGWITHMIXOFSMALLANDCAPS"},
	{"RENAN BASTOS 93 AOSDAJDJAIDJAIDAJIaidsjjaidijadsjiadjiOOKKO", "RENAN BASTOS 93 AOSDAJDJAIDJAIDAJIAIDSJJAIDIJADSJIADJIOOKKO"},
	{"long\u0250string\u0250with\u0250nonascii\u2C6Fchars", "LONG\u2C6FSTRING\u2C6FWITH\u2C6FNONASCII\u2C6FCHARS"},
	{"\u0250\u0250\u0250\u0250\u0250", "\u2C6F\u2C6F\u2C6F\u2C6F\u2C6F"}, // grows one byte per char
	{"a\u0080\U0010FFFF", "A\u0080\U0010FFFF"},                           // test utf8.RuneSelf and utf8.MaxRune
}

var lowerTests = []StringTest{
	{"", ""},
	{"abc", "abc"},
	{"AbC123", "abc123"},
	{"azAZ09_", "azaz09_"},
	{"longStrinGwitHmixofsmaLLandcAps", "longstringwithmixofsmallandcaps"},
	{"renan bastos 93 AOSDAJDJAIDJAIDAJIaidsjjaidijadsjiadjiOOKKO", "renan bastos 93 aosdajdjaidjaidajiaidsjjaidijadsjiadjiookko"},
	{"LONG\u2C6FSTRING\u2C6FWITH\u2C6FNONASCII\u2C6FCHARS", "long\u0250string\u0250with\u0250nonascii\u0250chars"},
	{"\u2C6D\u2C6D\u2C6D\u2C6D\u2C6D", "\u0251\u0251\u0251\u0251\u0251"}, // shrinks one byte per char
	{"A\u0080\U0010FFFF", "a\u0080\U0010FFFF"},                           // test utf8.RuneSelf and utf8.MaxRune
}

const space = "\t\v\r\f\n\u0085\u00a0\u2000\u3000"

var trimSpaceTests = []StringTest{
	{"", ""},
	{"abc", "abc"},
	{space + "abc" + space, "abc"},
	{" ", ""},
	{" \t\r\n \t\t\r\r\n\n ", ""},
	{" \t\r\n x\t\t\r\r\n\n ", "x"},
	{" \u2000\t\r\n x\t\t\r\r\ny\n \u3000", "x\t\t\r\r\ny"},
	{"1 \t\r\n2", "1 \t\r\n2"},
	{" x\x80", "x\x80"},
	{" x\xc0", "x\xc0"},
	{"x \xc0\xc0 ", "x \xc0\xc0"},
	{"x \xc0", "x \xc0"},
	{"x \xc0 ", "x \xc0"},
	{"x \xc0\xc0 ", "x \xc0\xc0"},
	{"x ☺\xc0\xc0 ", "x ☺\xc0\xc0"},
	{"x ☺ ", "x ☺"},
}

func tenRunes(ch rune) string {
	r := make([]rune, 10)
	for i := range r {
		r[i] = ch
	}
	return string(r)
}

// User-defined self-inverse mapping function
func rot13(r rune) rune {
	step := rune(13)
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
	maxRune := func(rune) rune { return unicode.MaxRune }
	m := Map(maxRune, a)
	expect := tenRunes(unicode.MaxRune)
	if m != expect {
		t.Errorf("growing: expected %q got %q", expect, m)
	}

	// 2. Shrink
	minRune := func(rune) rune { return 'a' }
	m = Map(minRune, tenRunes(unicode.MaxRune))
	expect = a
	if m != expect {
		t.Errorf("shrinking: expected %q got %q", expect, m)
	}

	// 3. Rot13
	m = Map(rot13, "a to zed")
	expect = "n gb mrq"
	if m != expect {
		t.Errorf("rot13: expected %q got %q", expect, m)
	}

	// 4. Rot13^2
	m = Map(rot13, Map(rot13, "a to zed"))
	expect = "a to zed"
	if m != expect {
		t.Errorf("rot13: expected %q got %q", expect, m)
	}

	// 5. Drop
	dropNotLatin := func(r rune) rune {
		if unicode.Is(unicode.Latin, r) {
			return r
		}
		return -1
	}
	m = Map(dropNotLatin, "Hello, 세계")
	expect = "Hello"
	if m != expect {
		t.Errorf("drop: expected %q got %q", expect, m)
	}

	// 6. Identity
	identity := func(r rune) rune {
		return r
	}
	orig := "Input string that we expect not to be copied."
	m = Map(identity, orig)
	if unsafe.StringData(orig) != unsafe.StringData(m) {
		t.Error("unexpected copy during identity map")
	}

	// 7. Handle invalid UTF-8 sequence
	replaceNotLatin := func(r rune) rune {
		if unicode.Is(unicode.Latin, r) {
			return r
		}
		return utf8.RuneError
	}
	m = Map(replaceNotLatin, "Hello\255World")
	expect = "Hello\uFFFDWorld"
	if m != expect {
		t.Errorf("replace invalid sequence: expected %q got %q", expect, m)
	}

	// 8. Check utf8.RuneSelf and utf8.MaxRune encoding
	encode := func(r rune) rune {
		switch r {
		case utf8.RuneSelf:
			return unicode.MaxRune
		case unicode.MaxRune:
			return utf8.RuneSelf
		}
		return r
	}
	s := string(rune(utf8.RuneSelf)) + string(utf8.MaxRune)
	r := string(utf8.MaxRune) + string(rune(utf8.RuneSelf)) // reverse of s
	m = Map(encode, s)
	if m != r {
		t.Errorf("encoding not handled correctly: expected %q got %q", r, m)
	}
	m = Map(encode, r)
	if m != s {
		t.Errorf("encoding not handled correctly: expected %q got %q", s, m)
	}

	// 9. Check mapping occurs in the front, middle and back
	trimSpaces := func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}
	m = Map(trimSpaces, "   abc    123   ")
	expect = "abc123"
	if m != expect {
		t.Errorf("trimSpaces: expected %q got %q", expect, m)
	}
}

func TestToUpper(t *testing.T) { runStringTests(t, ToUpper, "ToUpper", upperTests) }

func TestToLower(t *testing.T) { runStringTests(t, ToLower, "ToLower", lowerTests) }

var toValidUTF8Tests = []struct {
	in   string
	repl string
	out  string
}{
	{"", "\uFFFD", ""},
	{"abc", "\uFFFD", "abc"},
	{"\uFDDD", "\uFFFD", "\uFDDD"},
	{"a\xffb", "\uFFFD", "a\uFFFDb"},
	{"a\xffb\uFFFD", "X", "aXb\uFFFD"},
	{"a☺\xffb☺\xC0\xAFc☺\xff", "", "a☺b☺c☺"},
	{"a☺\xffb☺\xC0\xAFc☺\xff", "日本語", "a☺日本語b☺日本語c☺日本語"},
	{"\xC0\xAF", "\uFFFD", "\uFFFD"},
	{"\xE0\x80\xAF", "\uFFFD", "\uFFFD"},
	{"\xed\xa0\x80", "abc", "abc"},
	{"\xed\xbf\xbf", "\uFFFD", "\uFFFD"},
	{"\xF0\x80\x80\xaf", "☺", "☺"},
	{"\xF8\x80\x80\x80\xAF", "\uFFFD", "\uFFFD"},
	{"\xFC\x80\x80\x80\x80\xAF", "\uFFFD", "\uFFFD"},
}

func TestToValidUTF8(t *testing.T) {
	for _, tc := range toValidUTF8Tests {
		got := ToValidUTF8(tc.in, tc.repl)
		if got != tc.out {
			t.Errorf("ToValidUTF8(%q, %q) = %q; want %q", tc.in, tc.repl, got, tc.out)
		}
	}
}

func BenchmarkToUpper(b *testing.B) {
	for _, tc := range upperTests {
		b.Run(tc.in, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				actual := ToUpper(tc.in)
				if actual != tc.out {
					b.Errorf("ToUpper(%q) = %q; want %q", tc.in, actual, tc.out)
				}
			}
		})
	}
}

func BenchmarkToLower(b *testing.B) {
	for _, tc := range lowerTests {
		b.Run(tc.in, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				actual := ToLower(tc.in)
				if actual != tc.out {
					b.Errorf("ToLower(%q) = %q; want %q", tc.in, actual, tc.out)
				}
			}
		})
	}
}

func BenchmarkMapNoChanges(b *testing.B) {
	identity := func(r rune) rune {
		return r
	}
	for i := 0; i < b.N; i++ {
		Map(identity, "Some string that won't be modified.")
	}
}

func TestSpecialCase(t *testing.T) {
	lower := "abcçdefgğhıijklmnoöprsştuüvyz"
	upper := "ABCÇDEFGĞHIİJKLMNOÖPRSŞTUÜVYZ"
	u := ToUpperSpecial(unicode.TurkishCase, upper)
	if u != upper {
		t.Errorf("Upper(upper) is %s not %s", u, upper)
	}
	u = ToUpperSpecial(unicode.TurkishCase, lower)
	if u != upper {
		t.Errorf("Upper(lower) is %s not %s", u, upper)
	}
	l := ToLowerSpecial(unicode.TurkishCase, lower)
	if l != lower {
		t.Errorf("Lower(lower) is %s not %s", l, lower)
	}
	l = ToLowerSpecial(unicode.TurkishCase, upper)
	if l != lower {
		t.Errorf("Lower(upper) is %s not %s", l, lower)
	}
}

func TestTrimSpace(t *testing.T) { runStringTests(t, TrimSpace, "TrimSpace", trimSpaceTests) }

var trimTests = []struct {
	f            string
	in, arg, out string
}{
	{"Trim", "abba", "a", "bb"},
	{"Trim", "abba", "ab", ""},
	{"TrimLeft", "abba", "ab", ""},
	{"TrimRight", "abba", "ab", ""},
	{"TrimLeft", "abba", "a", "bba"},
	{"TrimLeft", "abba", "b", "abba"},
	{"TrimRight", "abba", "a", "abb"},
	{"TrimRight", "abba", "b", "abba"},
	{"Trim", "<tag>", "<>", "tag"},
	{"Trim", "* listitem", " *", "listitem"},
	{"Trim", `"quote"`, `"`, "quote"},
	{"Trim", "\u2C6F\u2C6F\u0250\u0250\u2C6F\u2C6F", "\u2C6F", "\u0250\u0250"},
	{"Trim", "\x80test\xff", "\xff", "test"},
	{"Trim", " Ġ ", " ", "Ġ"},
	{"Trim", " Ġİ0", "0 ", "Ġİ"},
	//empty string tests
	{"Trim", "abba", "", "abba"},
	{"Trim", "", "123", ""},
	{"Trim", "", "", ""},
	{"TrimLeft", "abba", "", "abba"},
	{"TrimLeft", "", "123", ""},
	{"TrimLeft", "", "", ""},
	{"TrimRight", "abba", "", "abba"},
	{"TrimRight", "", "123", ""},
	{"TrimRight", "", "", ""},
	{"TrimRight", "☺\xc0", "☺", "☺\xc0"},
	{"TrimPrefix", "aabb", "a", "abb"},
	{"TrimPrefix", "aabb", "b", "aabb"},
	{"TrimSuffix", "aabb", "a", "aabb"},
	{"TrimSuffix", "aabb", "b", "aab"},
}

func TestTrim(t *testing.T) {
	for _, tc := range trimTests {
		name := tc.f
		var f func(string, string) string
		switch name {
		case "Trim":
			f = Trim
		case "TrimLeft":
			f = TrimLeft
		case "TrimRight":
			f = TrimRight
		case "TrimPrefix":
			f = TrimPrefix
		case "TrimSuffix":
			f = TrimSuffix
		default:
			t.Errorf("Undefined trim function %s", name)
		}
		actual := f(tc.in, tc.arg)
		if actual != tc.out {
			t.Errorf("%s(%q, %q) = %q; want %q", name, tc.in, tc.arg, actual, tc.out)
		}
	}
}

func BenchmarkTrim(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, tc := range trimTests {
			name := tc.f
			var f func(string, string) string
			switch name {
			case "Trim":
				f = Trim
			case "TrimLeft":
				f = TrimLeft
			case "TrimRight":
				f = TrimRight
			case "TrimPrefix":
				f = TrimPrefix
			case "TrimSuffix":
				f = TrimSuffix
			default:
				b.Errorf("Undefined trim function %s", name)
			}
			actual := f(tc.in, tc.arg)
			if actual != tc.out {
				b.Errorf("%s(%q, %q) = %q; want %q", name, tc.in, tc.arg, actual, tc.out)
			}
		}
	}
}

func BenchmarkToValidUTF8(b *testing.B) {
	tests := []struct {
		name  string
		input string
	}{
		{"Valid", "typical"},
		{"InvalidASCII", "foo\xffbar"},
		{"InvalidNonASCII", "日本語\xff日本語"},
	}
	replacement := "\uFFFD"
	b.ResetTimer()
	for _, test := range tests {
		b.Run(test.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				ToValidUTF8(test.input, replacement)
			}
		})
	}
}

type predicate struct {
	f    func(rune) bool
	name string
}

var isSpace = predicate{unicode.IsSpace, "IsSpace"}
var isDigit = predicate{unicode.IsDigit, "IsDigit"}
var isUpper = predicate{unicode.IsUpper, "IsUpper"}
var isValidRune = predicate{
	func(r rune) bool {
		return r != utf8.RuneError
	},
	"IsValidRune",
}

func not(p predicate) predicate {
	return predicate{
		func(r rune) bool {
			return !p.f(r)
		},
		"not " + p.name,
	}
}

var trimFuncTests = []struct {
	f        predicate
	in       string
	trimOut  string
	leftOut  string
	rightOut string
}{
	{isSpace, space + " hello " + space,
		"hello",
		"hello " + space,
		space + " hello"},
	{isDigit, "\u0e50\u0e5212hello34\u0e50\u0e51",
		"hello",
		"hello34\u0e50\u0e51",
		"\u0e50\u0e5212hello"},
	{isUpper, "\u2C6F\u2C6F\u2C6F\u2C6FABCDhelloEF\u2C6F\u2C6FGH\u2C6F\u2C6F",
		"hello",
		"helloEF\u2C6F\u2C6FGH\u2C6F\u2C6F",
		"\u2C6F\u2C6F\u2C6F\u2C6FABCDhello"},
	{not(isSpace), "hello" + space + "hello",
		space,
		space + "hello",
		"hello" + space},
	{not(isDigit), "hello\u0e50\u0e521234\u0e50\u0e51helo",
		"\u0e50\u0e521234\u0e50\u0e51",
		"\u0e50\u0e521234\u0e50\u0e51helo",
		"hello\u0e50\u0e521234\u0e50\u0e51"},
	{isValidRune, "ab\xc0a\xc0cd",
		"\xc0a\xc0",
		"\xc0a\xc0cd",
		"ab\xc0a\xc0"},
	{not(isValidRune), "\xc0a\xc0",
		"a",
		"a\xc0",
		"\xc0a"},
	{isSpace, "",
		"",
		"",
		""},
	{isSpace, " ",
		"",
		"",
		""},
}

func TestTrimFunc(t *testing.T) {
	for _, tc := range trimFuncTests {
		trimmers := []struct {
			name string
			trim func(s string, f func(r rune) bool) string
			out  string
		}{
			{"TrimFunc", TrimFunc, tc.trimOut},
			{"TrimLeftFunc", TrimLeftFunc, tc.leftOut},
			{"TrimRightFunc", TrimRightFunc, tc.rightOut},
		}
		for _, trimmer := range trimmers {
			actual := trimmer.trim(tc.in, tc.f.f)
			if actual != trimmer.out {
				t.Errorf("%s(%q, %q) = %q; want %q", trimmer.name, tc.in, tc.f.name, actual, trimmer.out)
			}
		}
	}
}

var indexFuncTests = []struct {
	in          string
	f           predicate
	first, last int
}{
	{"", isValidRune, -1, -1},
	{"abc", isDigit, -1, -1},
	{"0123", isDigit, 0, 3},
	{"a1b", isDigit, 1, 1},
	{space, isSpace, 0, len(space) - 3}, // last rune in space is 3 bytes
	{"\u0e50\u0e5212hello34\u0e50\u0e51", isDigit, 0, 18},
	{"\u2C6F\u2C6F\u2C6F\u2C6FABCDhelloEF\u2C6F\u2C6FGH\u2C6F\u2C6F", isUpper, 0, 34},
	{"12\u0e50\u0e52hello34\u0e50\u0e51", not(isDigit), 8, 12},

	// tests of invalid UTF-8
	{"\x801", isDigit, 1, 1},
	{"\x80abc", isDigit, -1, -1},
	{"\xc0a\xc0", isValidRune, 1, 1},
	{"\xc0a\xc0", not(isValidRune), 0, 2},
	{"\xc0☺\xc0", not(isValidRune), 0, 4},
	{"\xc0☺\xc0\xc0", not(isValidRune), 0, 5},
	{"ab\xc0a\xc0cd", not(isValidRune), 2, 4},
	{"a\xe0\x80cd", not(isValidRune), 1, 2},
	{"\x80\x80\x80\x80", not(isValidRune), 0, 3},
}

func TestIndexFunc(t *testing.T) {
	for _, tc := range indexFuncTests {
		first := IndexFunc(tc.in, tc.f.f)
		if first != tc.first {
			t.Errorf("IndexFunc(%q, %s) = %d; want %d", tc.in, tc.f.name, first, tc.first)
		}
		last := LastIndexFunc(tc.in, tc.f.f)
		if last != tc.last {
			t.Errorf("LastIndexFunc(%q, %s) = %d; want %d", tc.in, tc.f.name, last, tc.last)
		}
	}
}

func equal(m string, s1, s2 string, t *testing.T) bool {
	if s1 == s2 {
		return true
	}
	e1 := Split(s1, "")
	e2 := Split(s2, "")
	for i, c1 := range e1 {
		if i >= len(e2) {
			break
		}
		r1, _ := utf8.DecodeRuneInString(c1)
		r2, _ := utf8.DecodeRuneInString(e2[i])
		if r1 != r2 {
			t.Errorf("%s diff at %d: U+%04X U+%04X", m, i, r1, r2)
		}
	}
	return false
}

func TestCaseConsistency(t *testing.T) {
	// Make a string of all the runes.
	numRunes := int(unicode.MaxRune + 1)
	if testing.Short() {
		numRunes = 1000
	}
	a := make([]rune, numRunes)
	for i := range a {
		a[i] = rune(i)
	}
	s := string(a)
	// convert the cases.
	upper := ToUpper(s)
	lower := ToLower(s)

	// Consistency checks
	if n := utf8.RuneCountInString(upper); n != numRunes {
		t.Error("rune count wrong in upper:", n)
	}
	if n := utf8.RuneCountInString(lower); n != numRunes {
		t.Error("rune count wrong in lower:", n)
	}
	if !equal("ToUpper(upper)", ToUpper(upper), upper, t) {
		t.Error("ToUpper(upper) consistency fail")
	}
	if !equal("ToLower(lower)", ToLower(lower), lower, t) {
		t.Error("ToLower(lower) consistency fail")
	}
	/*
		  These fail because of non-one-to-oneness of the data, such as multiple
		  upper case 'I' mapping to 'i'.  We comment them out but keep them for
		  interest.
		  For instance: CAPITAL LETTER I WITH DOT ABOVE:
			unicode.ToUpper(unicode.ToLower('\u0130')) != '\u0130'

		if !equal("ToUpper(lower)", ToUpper(lower), 
"""




```