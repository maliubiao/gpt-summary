Response:
Let's break down the thought process for analyzing this Go test file snippet.

**1. Understanding the Goal:**

The primary goal is to understand the functionality being tested in this `bytes_test.go` snippet. This involves identifying the core functions being tested and what aspects of their behavior are being verified. Since this is part 2 of a larger analysis, the immediate goal is to *summarize* the functionalities demonstrated in this specific part.

**2. Initial Scan and Keyword Identification:**

Quickly scan the code for keywords and function names. This gives a high-level overview. Keywords like `Test...`, `Benchmark...`, `var ...Tests`, function calls like `Map`, `ToUpper`, `ToLower`, `TrimSpace`, `Repeat`, `Runes`, `Trim`, `IndexFunc`, `Replace`, `Title`, `EqualFold`, `Cut`, `Contains`, `Fields`, `Split`, and `Clone` stand out.

**3. Grouping by Functionality:**

Based on the identified keywords, start grouping the tests logically. For instance, all the `TestToUpper`, `TestToLower`, `BenchmarkToUpper`, `BenchmarkToLower` clearly relate to case conversion. The various `TestTrim...` tests are related to string trimming. The `TestRepeat` and `BenchmarkRepeat` relate to string repetition.

**4. Analyzing Individual Test Functions:**

For each group of tests, examine the individual test functions and the data structures they use (like the `...Tests` variables).

* **`TestMap`:** This function tests a generic `Map` function (likely from the `bytes` package, although not shown directly). The tests demonstrate different mapping functions: identity, shrinking, rot13, rot13 applied twice, dropping non-Latin characters, and handling invalid runes.

* **`TestToUpper` and `TestToLower`:** These are straightforward tests for converting strings to uppercase and lowercase, respectively. They rely on `runStringTests` and predefined `upperTests` and `lowerTests` (likely defined in the omitted part 1).

* **`BenchmarkToUpper` and `BenchmarkToLower`:** These benchmark the performance of the `ToUpper` and `ToLower` functions using the same test cases as their corresponding unit tests.

* **`TestToValidUTF8`:** This tests the `ToValidUTF8` function, which replaces invalid UTF-8 sequences with a specified replacement string. The `toValidUTF8Tests` variable provides various input strings and expected outputs.

* **`TestTrimSpace`:** Tests the `TrimSpace` function, which removes leading and trailing whitespace. It also uses `runStringTests` and likely a `trimSpaceTests` variable from part 1.

* **`TestRepeat`:** Tests the `Repeat` function, which repeats a byte slice a given number of times. It includes test cases for various input strings and counts, including cases that could lead to overflow.

* **`TestRepeatCatchesOverflow`:**  Specifically tests the error handling of `Repeat` when given inputs that could cause integer overflow.

* **`TestRunes`:** Tests the `Runes` function, which converts a byte slice to a slice of runes. It checks both the conversion and the reassembly back into a string (if lossless).

* **`TestTrim`:** Tests various `Trim` functions (e.g., `Trim`, `TrimLeft`, `TrimRight`, `TrimPrefix`, `TrimSuffix`) using the `trimTests` data. It also handles cases with nil input.

* **`TestTrimFunc`:** Tests `TrimFunc`, `TrimLeftFunc`, and `TrimRightFunc`, which trim based on a provided function that determines whether a rune should be trimmed.

* **`TestIndexFunc`:** Tests `IndexFunc` and `LastIndexFunc`, which find the first and last index of a rune that satisfies a given function.

* **`TestReplace`:** Tests the `Replace` and `ReplaceAll` functions for replacing substrings.

* **`TestTitle` and `TestToTitle`:** Test functions for converting strings to title case.

* **`TestEqualFold`:** Tests the `EqualFold` function for case-insensitive comparison.

* **`TestCut`, `TestCutPrefix`, `TestCutSuffix`:** Test the functions for splitting a byte slice based on a separator.

* **`TestBufferGrowNegative`, `TestBufferTruncateNegative`, `TestBufferTruncateOutOfRange`:** These test the error handling of the `Buffer` type when `Grow` or `Truncate` are called with invalid arguments.

* **`TestContains`, `TestContainsAny`, `TestContainsRune`, `TestContainsFunc`:** Test various functions for checking if a byte slice contains a specific substring, any character from a string, a specific rune, or a rune satisfying a given function.

* **`BenchmarkFields`, `BenchmarkFieldsFunc`, `BenchmarkTrimSpace`, `BenchmarkToValidUTF8`:** These benchmark the performance of functions related to splitting and validating byte slices.

* **`BenchmarkIndexHard`, `BenchmarkLastIndexHard`, `BenchmarkCountHard`, `BenchmarkSplit...`, `BenchmarkRepeat`, `BenchmarkRepeatLarge`, `BenchmarkBytesCompare`, `BenchmarkIndexAny...`, `BenchmarkLastIndexAny...`, `BenchmarkTrimASCII`, `BenchmarkTrimByte`, `BenchmarkIndexPeriodic`:** These are more complex benchmarks testing performance under various conditions.

* **`TestClone`:** Tests the `Clone` function for creating a copy of a byte slice.

**5. Identifying Implemented Functionality:**

Based on the tests, we can infer that the `bytes` package (or the code being tested) implements functions for:

* Mapping byte slices using a rune-to-rune function.
* Converting byte slices to uppercase and lowercase.
* Converting byte slices to valid UTF-8, replacing invalid sequences.
* Trimming leading and trailing whitespace.
* Repeating byte slices.
* Converting byte slices to slices of runes.
* Trimming leading and trailing characters based on a set of characters or a function.
* Finding the first and last index of a substring or a rune satisfying a condition.
* Replacing substrings.
* Converting byte slices to title case.
* Performing case-insensitive comparisons.
* Cutting byte slices based on separators (prefix, suffix, or general).
* Growing and truncating `Buffer` objects.
* Checking if a byte slice contains another byte slice, any character from a string, a specific rune, or a rune satisfying a function.
* Splitting byte slices into fields.
* Cloning byte slices.

**6. Code Examples (Illustrative):**

Based on the understanding of the tested functions, create concise Go code examples demonstrating their usage. This helps solidify the understanding and provides concrete illustrations.

**7. Identifying Potential Mistakes:**

Review the tests for any hints of common errors users might make. For example, the `TestRepeatCatchesOverflow` test highlights that providing negative counts to `Repeat` is an error.

**8. Summarization:**

Finally, synthesize the information gathered into a concise summary of the functionalities demonstrated in the provided code snippet. Emphasize the key areas covered. Since this was part 2, focus on the functions covered in *this* specific section.

**Self-Correction/Refinement during the process:**

* **Initial Overlap:** Realize that some tests seem to be testing similar things (e.g., various `Trim` functions). Group them logically.
* **Function Inference:** If a test uses a function not explicitly defined in the snippet (like `Map` or `runStringTests`), acknowledge that it's likely part of the broader `bytes` package or the other part of the file.
* **Clarity of Examples:** Ensure the code examples are clear, concise, and directly illustrate the function's purpose.
* **Focus on the Snippet:**  Constantly remind yourself to focus only on the functionality *demonstrated* in the given code snippet. Avoid making assumptions about the entire `bytes` package.

By following this systematic approach, we can effectively analyze the Go test code and understand the functionality it verifies.
## 对go/src/bytes/bytes_test.go 代码片段的功能归纳 (第2部分)

这是 `go/src/bytes/bytes_test.go` 文件的一部分，专注于测试 `bytes` 包中字符串处理和操作的相关功能。  基于提供的代码片段，我们可以归纳出以下功能测试：

**核心功能测试:**

1. **`Map` 函数测试:**
   - 验证 `Map` 函数能够正确地将一个 rune 到 rune 的映射函数应用到 byte slice 的每一个 rune 上。
   - 测试了多种映射函数的应用场景，包括：
     - **恒等映射:** 输入输出一致。
     - **缩小映射:** 将所有 rune 映射到同一个值。
     - **Rot13 加密:** 将字母进行 Rot13 替换。
     - **Rot13 解密 (两次 Rot13):** 验证两次 Rot13 操作可以还原原始字符串。
     - **丢弃非拉丁字符:**  删除 byte slice 中的非拉丁字符。
     - **处理无效 rune:** 将所有 rune 映射到一个无效的 rune 值，并期望输出 `\uFFFD` (Unicode 替换字符)。

2. **大小写转换 (`ToUpper`, `ToLower`) 测试和性能基准:**
   - 验证 `ToUpper` 函数能够正确地将 byte slice 转换为大写。
   - 验证 `ToLower` 函数能够正确地将 byte slice 转换为小写。
   - 提供了性能基准测试 (`BenchmarkToUpper`, `BenchmarkToLower`) 来衡量这两个函数的执行效率。

3. **`ToValidUTF8` 函数测试:**
   - 验证 `ToValidUTF8` 函数能够将 byte slice 中无效的 UTF-8 编码替换为指定的替换字符串。
   - 测试了各种包含无效 UTF-8 编码的输入，并验证了替换后的输出是否符合预期。

4. **`TrimSpace` 函数测试:**
   - 验证 `TrimSpace` 函数能够移除 byte slice 首尾的空白字符。

5. **`Repeat` 函数测试和溢出处理:**
   - 验证 `Repeat` 函数能够将 byte slice 重复指定的次数。
   - 测试了各种重复次数，包括 0、1、较大的值。
   - **重点测试了 `Repeat` 函数对潜在的整数溢出的处理，确保在重复次数过大时能够正确地抛出错误。**

6. **`Runes` 函数测试:**
   - 验证 `Runes` 函数能够将 byte slice 转换为 rune slice。
   - 同时也测试了无损转换的情况，即从 rune slice 转换回字符串后是否与原始输入一致。

7. **`Trim` 系列函数测试 (`Trim`, `TrimLeft`, `TrimRight`, `TrimPrefix`, `TrimSuffix`):**
   - 验证 `Trim` 函数能够移除 byte slice 首尾指定的字符。
   - 验证 `TrimLeft` 函数能够移除 byte slice 开头指定的字符。
   - 验证 `TrimRight` 函数能够移除 byte slice 结尾指定的字符。
   - 验证 `TrimPrefix` 函数能够移除 byte slice 的指定前缀。
   - 验证 `TrimSuffix` 函数能够移除 byte slice 的指定后缀。
   - 这些测试覆盖了各种需要移除的字符和边界情况，包括空字符串和 nil 输入。

8. **`TrimFunc` 系列函数测试 (`TrimFunc`, `TrimLeftFunc`, `TrimRightFunc`):**
   - 验证 `TrimFunc` 函数能够移除 byte slice 首尾满足指定函数的 rune。
   - 验证 `TrimLeftFunc` 函数能够移除 byte slice 开头满足指定函数的 rune。
   - 验证 `TrimRightFunc` 函数能够移除 byte slice 结尾满足指定函数的 rune。
   - 使用了不同的谓词函数 (`unicode.IsSpace`, `unicode.IsDigit` 等) 来测试不同的移除条件。

9. **`IndexFunc` 和 `LastIndexFunc` 函数测试:**
   - 验证 `IndexFunc` 函数能够找到 byte slice 中第一个满足指定函数的 rune 的索引。
   - 验证 `LastIndexFunc` 函数能够找到 byte slice 中最后一个满足指定函数的 rune 的索引。
   - 同样使用了不同的谓词函数，并测试了包含无效 UTF-8 编码的情况。

10. **`Replace` 和 `ReplaceAll` 函数测试:**
    - 验证 `Replace` 函数能够将 byte slice 中前 n 个出现的 old 子串替换为 new 子串。
    - 验证 `ReplaceAll` 函数能够将 byte slice 中所有出现的 old 子串替换为 new 子串。
    - 测试了各种替换场景，包括空字符串、替换次数限制等。

11. **`Title` 和 `ToTitle` 函数测试:**
    - 验证 `Title` 函数能够将 byte slice 转换为标题格式（每个单词首字母大写）。
    - 验证 `ToTitle` 函数能够将 byte slice 转换为 Title Case (所有可大写的字符都大写)。

12. **`EqualFold` 函数测试:**
    - 验证 `EqualFold` 函数能够进行忽略大小写的 byte slice 比较。

13. **`Cut`, `CutPrefix`, `CutSuffix` 函数测试:**
    - 验证 `Cut` 函数能够根据分隔符将 byte slice 分割成两部分。
    - 验证 `CutPrefix` 函数能够检查并移除 byte slice 的指定前缀。
    - 验证 `CutSuffix` 函数能够检查并移除 byte slice 的指定后缀。

14. **`Buffer` 类型的错误处理测试 (`Grow`, `Truncate`):**
    - 测试了 `Buffer` 类型的 `Grow` 和 `Truncate` 方法在接收到负数或超出范围的参数时是否会 panic。

15. **`Contains`, `ContainsAny`, `ContainsRune`, `ContainsFunc` 函数测试:**
    - 验证 `Contains` 函数能够判断一个 byte slice 是否包含另一个 byte slice 作为子串。
    - 验证 `ContainsAny` 函数能够判断一个 byte slice 是否包含指定字符串中的任意字符。
    - 验证 `ContainsRune` 函数能够判断一个 byte slice 是否包含指定的 rune。
    - 验证 `ContainsFunc` 函数能够判断一个 byte slice 是否包含满足指定函数的 rune。

16. **性能基准测试 (续):**
    - 提供了大量更细致的性能基准测试，例如 `BenchmarkFields`, `BenchmarkFieldsFunc`, `BenchmarkTrimSpace`, `BenchmarkToValidUTF8`, `BenchmarkIndexHard` 等，用于衡量不同场景下函数的性能表现。
    - 这些基准测试涵盖了不同大小的输入和不同的操作类型，例如查找、分割、替换等。

17. **`Clone` 函数测试:**
    - 验证 `Clone` 函数能够创建一个 byte slice 的副本，并且副本与原始 byte slice 拥有不同的底层数组。

**总结:**

这部分代码主要集中在测试 `bytes` 包中用于处理和操作 byte slice 的各种函数，涵盖了字符串的映射、大小写转换、UTF-8 校验、空白符处理、重复、rune 转换、裁剪、查找、替换、标题化、比较、分割、包含性判断以及内存操作等多个方面。  同时，也包含了对 `Buffer` 类型部分方法的错误处理测试和大量的性能基准测试，以确保功能的正确性和效率。

Prompt: 
```
这是路径为go/src/bytes/bytes_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""

	expect = a
	if string(m) != expect {
		t.Errorf("shrinking: expected %q got %q", expect, m)
	}

	// 3. Rot13
	m = Map(rot13, []byte("a to zed"))
	expect = "n gb mrq"
	if string(m) != expect {
		t.Errorf("rot13: expected %q got %q", expect, m)
	}

	// 4. Rot13^2
	m = Map(rot13, Map(rot13, []byte("a to zed")))
	expect = "a to zed"
	if string(m) != expect {
		t.Errorf("rot13: expected %q got %q", expect, m)
	}

	// 5. Drop
	dropNotLatin := func(r rune) rune {
		if unicode.Is(unicode.Latin, r) {
			return r
		}
		return -1
	}
	m = Map(dropNotLatin, []byte("Hello, 세계"))
	expect = "Hello"
	if string(m) != expect {
		t.Errorf("drop: expected %q got %q", expect, m)
	}

	// 6. Invalid rune
	invalidRune := func(r rune) rune {
		return utf8.MaxRune + 1
	}
	m = Map(invalidRune, []byte("x"))
	expect = "\uFFFD"
	if string(m) != expect {
		t.Errorf("invalidRune: expected %q got %q", expect, m)
	}
}

func TestToUpper(t *testing.T) { runStringTests(t, ToUpper, "ToUpper", upperTests) }

func TestToLower(t *testing.T) { runStringTests(t, ToLower, "ToLower", lowerTests) }

func BenchmarkToUpper(b *testing.B) {
	for _, tc := range upperTests {
		tin := []byte(tc.in)
		b.Run(tc.in, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				actual := ToUpper(tin)
				if !Equal(actual, tc.out) {
					b.Errorf("ToUpper(%q) = %q; want %q", tc.in, actual, tc.out)
				}
			}
		})
	}
}

func BenchmarkToLower(b *testing.B) {
	for _, tc := range lowerTests {
		tin := []byte(tc.in)
		b.Run(tc.in, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				actual := ToLower(tin)
				if !Equal(actual, tc.out) {
					b.Errorf("ToLower(%q) = %q; want %q", tc.in, actual, tc.out)
				}
			}
		})
	}
}

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
		got := ToValidUTF8([]byte(tc.in), []byte(tc.repl))
		if !Equal(got, []byte(tc.out)) {
			t.Errorf("ToValidUTF8(%q, %q) = %q; want %q", tc.in, tc.repl, got, tc.out)
		}
	}
}

func TestTrimSpace(t *testing.T) { runStringTests(t, TrimSpace, "TrimSpace", trimSpaceTests) }

type RepeatTest struct {
	in, out string
	count   int
}

var longString = "a" + string(make([]byte, 1<<16)) + "z"

var RepeatTests = []RepeatTest{
	{"", "", 0},
	{"", "", 1},
	{"", "", 2},
	{"-", "", 0},
	{"-", "-", 1},
	{"-", "----------", 10},
	{"abc ", "abc abc abc ", 3},
	// Tests for results over the chunkLimit
	{string(rune(0)), string(make([]byte, 1<<16)), 1 << 16},
	{longString, longString + longString, 2},
}

func TestRepeat(t *testing.T) {
	for _, tt := range RepeatTests {
		tin := []byte(tt.in)
		tout := []byte(tt.out)
		a := Repeat(tin, tt.count)
		if !Equal(a, tout) {
			t.Errorf("Repeat(%q, %d) = %q; want %q", tin, tt.count, a, tout)
			continue
		}
	}
}

func repeat(b []byte, count int) (err error) {
	defer func() {
		if r := recover(); r != nil {
			switch v := r.(type) {
			case error:
				err = v
			default:
				err = fmt.Errorf("%s", v)
			}
		}
	}()

	Repeat(b, count)

	return
}

// See Issue golang.org/issue/16237
func TestRepeatCatchesOverflow(t *testing.T) {
	type testCase struct {
		s      string
		count  int
		errStr string
	}

	runTestCases := func(prefix string, tests []testCase) {
		for i, tt := range tests {
			err := repeat([]byte(tt.s), tt.count)
			if tt.errStr == "" {
				if err != nil {
					t.Errorf("#%d panicked %v", i, err)
				}
				continue
			}

			if err == nil || !strings.Contains(err.Error(), tt.errStr) {
				t.Errorf("%s#%d got %q want %q", prefix, i, err, tt.errStr)
			}
		}
	}

	const maxInt = int(^uint(0) >> 1)

	runTestCases("", []testCase{
		0: {"--", -2147483647, "negative"},
		1: {"", maxInt, ""},
		2: {"-", 10, ""},
		3: {"gopher", 0, ""},
		4: {"-", -1, "negative"},
		5: {"--", -102, "negative"},
		6: {string(make([]byte, 255)), int((^uint(0))/255 + 1), "overflow"},
	})

	const is64Bit = 1<<(^uintptr(0)>>63)/2 != 0
	if !is64Bit {
		return
	}

	runTestCases("64-bit", []testCase{
		0: {"-", maxInt, "out of range"},
	})
}

type RunesTest struct {
	in    string
	out   []rune
	lossy bool
}

var RunesTests = []RunesTest{
	{"", []rune{}, false},
	{" ", []rune{32}, false},
	{"ABC", []rune{65, 66, 67}, false},
	{"abc", []rune{97, 98, 99}, false},
	{"\u65e5\u672c\u8a9e", []rune{26085, 26412, 35486}, false},
	{"ab\x80c", []rune{97, 98, 0xFFFD, 99}, true},
	{"ab\xc0c", []rune{97, 98, 0xFFFD, 99}, true},
}

func TestRunes(t *testing.T) {
	for _, tt := range RunesTests {
		tin := []byte(tt.in)
		a := Runes(tin)
		if !slices.Equal(a, tt.out) {
			t.Errorf("Runes(%q) = %v; want %v", tin, a, tt.out)
			continue
		}
		if !tt.lossy {
			// can only test reassembly if we didn't lose information
			s := string(a)
			if s != tt.in {
				t.Errorf("string(Runes(%q)) = %x; want %x", tin, s, tin)
			}
		}
	}
}

type TrimTest struct {
	f            string
	in, arg, out string
}

var trimTests = []TrimTest{
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

type TrimNilTest struct {
	f   string
	in  []byte
	arg string
	out []byte
}

var trimNilTests = []TrimNilTest{
	{"Trim", nil, "", nil},
	{"Trim", []byte{}, "", nil},
	{"Trim", []byte{'a'}, "a", nil},
	{"Trim", []byte{'a', 'a'}, "a", nil},
	{"Trim", []byte{'a'}, "ab", nil},
	{"Trim", []byte{'a', 'b'}, "ab", nil},
	{"Trim", []byte("☺"), "☺", nil},
	{"TrimLeft", nil, "", nil},
	{"TrimLeft", []byte{}, "", nil},
	{"TrimLeft", []byte{'a'}, "a", nil},
	{"TrimLeft", []byte{'a', 'a'}, "a", nil},
	{"TrimLeft", []byte{'a'}, "ab", nil},
	{"TrimLeft", []byte{'a', 'b'}, "ab", nil},
	{"TrimLeft", []byte("☺"), "☺", nil},
	{"TrimRight", nil, "", nil},
	{"TrimRight", []byte{}, "", []byte{}},
	{"TrimRight", []byte{'a'}, "a", []byte{}},
	{"TrimRight", []byte{'a', 'a'}, "a", []byte{}},
	{"TrimRight", []byte{'a'}, "ab", []byte{}},
	{"TrimRight", []byte{'a', 'b'}, "ab", []byte{}},
	{"TrimRight", []byte("☺"), "☺", []byte{}},
	{"TrimPrefix", nil, "", nil},
	{"TrimPrefix", []byte{}, "", []byte{}},
	{"TrimPrefix", []byte{'a'}, "a", []byte{}},
	{"TrimPrefix", []byte("☺"), "☺", []byte{}},
	{"TrimSuffix", nil, "", nil},
	{"TrimSuffix", []byte{}, "", []byte{}},
	{"TrimSuffix", []byte{'a'}, "a", []byte{}},
	{"TrimSuffix", []byte("☺"), "☺", []byte{}},
}

func TestTrim(t *testing.T) {
	toFn := func(name string) (func([]byte, string) []byte, func([]byte, []byte) []byte) {
		switch name {
		case "Trim":
			return Trim, nil
		case "TrimLeft":
			return TrimLeft, nil
		case "TrimRight":
			return TrimRight, nil
		case "TrimPrefix":
			return nil, TrimPrefix
		case "TrimSuffix":
			return nil, TrimSuffix
		default:
			t.Errorf("Undefined trim function %s", name)
			return nil, nil
		}
	}

	for _, tc := range trimTests {
		name := tc.f
		f, fb := toFn(name)
		if f == nil && fb == nil {
			continue
		}
		var actual string
		if f != nil {
			actual = string(f([]byte(tc.in), tc.arg))
		} else {
			actual = string(fb([]byte(tc.in), []byte(tc.arg)))
		}
		if actual != tc.out {
			t.Errorf("%s(%q, %q) = %q; want %q", name, tc.in, tc.arg, actual, tc.out)
		}
	}

	for _, tc := range trimNilTests {
		name := tc.f
		f, fb := toFn(name)
		if f == nil && fb == nil {
			continue
		}
		var actual []byte
		if f != nil {
			actual = f(tc.in, tc.arg)
		} else {
			actual = fb(tc.in, []byte(tc.arg))
		}
		report := func(s []byte) string {
			if s == nil {
				return "nil"
			} else {
				return fmt.Sprintf("%q", s)
			}
		}
		if len(actual) != 0 {
			t.Errorf("%s(%s, %q) returned non-empty value", name, report(tc.in), tc.arg)
		} else {
			actualNil := actual == nil
			outNil := tc.out == nil
			if actualNil != outNil {
				t.Errorf("%s(%s, %q) got nil %t; want nil %t", name, report(tc.in), tc.arg, actualNil, outNil)
			}
		}
	}
}

type predicate struct {
	f    func(r rune) bool
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

type TrimFuncTest struct {
	f        predicate
	in       string
	trimOut  []byte
	leftOut  []byte
	rightOut []byte
}

func not(p predicate) predicate {
	return predicate{
		func(r rune) bool {
			return !p.f(r)
		},
		"not " + p.name,
	}
}

var trimFuncTests = []TrimFuncTest{
	{isSpace, space + " hello " + space,
		[]byte("hello"),
		[]byte("hello " + space),
		[]byte(space + " hello")},
	{isDigit, "\u0e50\u0e5212hello34\u0e50\u0e51",
		[]byte("hello"),
		[]byte("hello34\u0e50\u0e51"),
		[]byte("\u0e50\u0e5212hello")},
	{isUpper, "\u2C6F\u2C6F\u2C6F\u2C6FABCDhelloEF\u2C6F\u2C6FGH\u2C6F\u2C6F",
		[]byte("hello"),
		[]byte("helloEF\u2C6F\u2C6FGH\u2C6F\u2C6F"),
		[]byte("\u2C6F\u2C6F\u2C6F\u2C6FABCDhello")},
	{not(isSpace), "hello" + space + "hello",
		[]byte(space),
		[]byte(space + "hello"),
		[]byte("hello" + space)},
	{not(isDigit), "hello\u0e50\u0e521234\u0e50\u0e51helo",
		[]byte("\u0e50\u0e521234\u0e50\u0e51"),
		[]byte("\u0e50\u0e521234\u0e50\u0e51helo"),
		[]byte("hello\u0e50\u0e521234\u0e50\u0e51")},
	{isValidRune, "ab\xc0a\xc0cd",
		[]byte("\xc0a\xc0"),
		[]byte("\xc0a\xc0cd"),
		[]byte("ab\xc0a\xc0")},
	{not(isValidRune), "\xc0a\xc0",
		[]byte("a"),
		[]byte("a\xc0"),
		[]byte("\xc0a")},
	// The nils returned by TrimLeftFunc are odd behavior, but we need
	// to preserve backwards compatibility.
	{isSpace, "",
		nil,
		nil,
		[]byte("")},
	{isSpace, " ",
		nil,
		nil,
		[]byte("")},
}

func TestTrimFunc(t *testing.T) {
	for _, tc := range trimFuncTests {
		trimmers := []struct {
			name string
			trim func(s []byte, f func(r rune) bool) []byte
			out  []byte
		}{
			{"TrimFunc", TrimFunc, tc.trimOut},
			{"TrimLeftFunc", TrimLeftFunc, tc.leftOut},
			{"TrimRightFunc", TrimRightFunc, tc.rightOut},
		}
		for _, trimmer := range trimmers {
			actual := trimmer.trim([]byte(tc.in), tc.f.f)
			if actual == nil && trimmer.out != nil {
				t.Errorf("%s(%q, %q) = nil; want %q", trimmer.name, tc.in, tc.f.name, trimmer.out)
			}
			if actual != nil && trimmer.out == nil {
				t.Errorf("%s(%q, %q) = %q; want nil", trimmer.name, tc.in, tc.f.name, actual)
			}
			if !Equal(actual, trimmer.out) {
				t.Errorf("%s(%q, %q) = %q; want %q", trimmer.name, tc.in, tc.f.name, actual, trimmer.out)
			}
		}
	}
}

type IndexFuncTest struct {
	in          string
	f           predicate
	first, last int
}

var indexFuncTests = []IndexFuncTest{
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
}

func TestIndexFunc(t *testing.T) {
	for _, tc := range indexFuncTests {
		first := IndexFunc([]byte(tc.in), tc.f.f)
		if first != tc.first {
			t.Errorf("IndexFunc(%q, %s) = %d; want %d", tc.in, tc.f.name, first, tc.first)
		}
		last := LastIndexFunc([]byte(tc.in), tc.f.f)
		if last != tc.last {
			t.Errorf("LastIndexFunc(%q, %s) = %d; want %d", tc.in, tc.f.name, last, tc.last)
		}
	}
}

type ReplaceTest struct {
	in       string
	old, new string
	n        int
	out      string
}

var ReplaceTests = []ReplaceTest{
	{"hello", "l", "L", 0, "hello"},
	{"hello", "l", "L", -1, "heLLo"},
	{"hello", "x", "X", -1, "hello"},
	{"", "x", "X", -1, ""},
	{"radar", "r", "<r>", -1, "<r>ada<r>"},
	{"", "", "<>", -1, "<>"},
	{"banana", "a", "<>", -1, "b<>n<>n<>"},
	{"banana", "a", "<>", 1, "b<>nana"},
	{"banana", "a", "<>", 1000, "b<>n<>n<>"},
	{"banana", "an", "<>", -1, "b<><>a"},
	{"banana", "ana", "<>", -1, "b<>na"},
	{"banana", "", "<>", -1, "<>b<>a<>n<>a<>n<>a<>"},
	{"banana", "", "<>", 10, "<>b<>a<>n<>a<>n<>a<>"},
	{"banana", "", "<>", 6, "<>b<>a<>n<>a<>n<>a"},
	{"banana", "", "<>", 5, "<>b<>a<>n<>a<>na"},
	{"banana", "", "<>", 1, "<>banana"},
	{"banana", "a", "a", -1, "banana"},
	{"banana", "a", "a", 1, "banana"},
	{"☺☻☹", "", "<>", -1, "<>☺<>☻<>☹<>"},
}

func TestReplace(t *testing.T) {
	for _, tt := range ReplaceTests {
		in := append([]byte(tt.in), "<spare>"...)
		in = in[:len(tt.in)]
		out := Replace(in, []byte(tt.old), []byte(tt.new), tt.n)
		if s := string(out); s != tt.out {
			t.Errorf("Replace(%q, %q, %q, %d) = %q, want %q", tt.in, tt.old, tt.new, tt.n, s, tt.out)
		}
		if cap(in) == cap(out) && &in[:1][0] == &out[:1][0] {
			t.Errorf("Replace(%q, %q, %q, %d) didn't copy", tt.in, tt.old, tt.new, tt.n)
		}
		if tt.n == -1 {
			out := ReplaceAll(in, []byte(tt.old), []byte(tt.new))
			if s := string(out); s != tt.out {
				t.Errorf("ReplaceAll(%q, %q, %q) = %q, want %q", tt.in, tt.old, tt.new, s, tt.out)
			}
		}
	}
}

type TitleTest struct {
	in, out string
}

var TitleTests = []TitleTest{
	{"", ""},
	{"a", "A"},
	{" aaa aaa aaa ", " Aaa Aaa Aaa "},
	{" Aaa Aaa Aaa ", " Aaa Aaa Aaa "},
	{"123a456", "123a456"},
	{"double-blind", "Double-Blind"},
	{"ÿøû", "Ÿøû"},
	{"with_underscore", "With_underscore"},
	{"unicode \xe2\x80\xa8 line separator", "Unicode \xe2\x80\xa8 Line Separator"},
}

func TestTitle(t *testing.T) {
	for _, tt := range TitleTests {
		if s := string(Title([]byte(tt.in))); s != tt.out {
			t.Errorf("Title(%q) = %q, want %q", tt.in, s, tt.out)
		}
	}
}

var ToTitleTests = []TitleTest{
	{"", ""},
	{"a", "A"},
	{" aaa aaa aaa ", " AAA AAA AAA "},
	{" Aaa Aaa Aaa ", " AAA AAA AAA "},
	{"123a456", "123A456"},
	{"double-blind", "DOUBLE-BLIND"},
	{"ÿøû", "ŸØÛ"},
}

func TestToTitle(t *testing.T) {
	for _, tt := range ToTitleTests {
		if s := string(ToTitle([]byte(tt.in))); s != tt.out {
			t.Errorf("ToTitle(%q) = %q, want %q", tt.in, s, tt.out)
		}
	}
}

var EqualFoldTests = []struct {
	s, t string
	out  bool
}{
	{"abc", "abc", true},
	{"ABcd", "ABcd", true},
	{"123abc", "123ABC", true},
	{"αβδ", "ΑΒΔ", true},
	{"abc", "xyz", false},
	{"abc", "XYZ", false},
	{"abcdefghijk", "abcdefghijX", false},
	{"abcdefghijk", "abcdefghij\u212A", true},
	{"abcdefghijK", "abcdefghij\u212A", true},
	{"abcdefghijkz", "abcdefghij\u212Ay", false},
	{"abcdefghijKz", "abcdefghij\u212Ay", false},
}

func TestEqualFold(t *testing.T) {
	for _, tt := range EqualFoldTests {
		if out := EqualFold([]byte(tt.s), []byte(tt.t)); out != tt.out {
			t.Errorf("EqualFold(%#q, %#q) = %v, want %v", tt.s, tt.t, out, tt.out)
		}
		if out := EqualFold([]byte(tt.t), []byte(tt.s)); out != tt.out {
			t.Errorf("EqualFold(%#q, %#q) = %v, want %v", tt.t, tt.s, out, tt.out)
		}
	}
}

var cutTests = []struct {
	s, sep        string
	before, after string
	found         bool
}{
	{"abc", "b", "a", "c", true},
	{"abc", "a", "", "bc", true},
	{"abc", "c", "ab", "", true},
	{"abc", "abc", "", "", true},
	{"abc", "", "", "abc", true},
	{"abc", "d", "abc", "", false},
	{"", "d", "", "", false},
	{"", "", "", "", true},
}

func TestCut(t *testing.T) {
	for _, tt := range cutTests {
		if before, after, found := Cut([]byte(tt.s), []byte(tt.sep)); string(before) != tt.before || string(after) != tt.after || found != tt.found {
			t.Errorf("Cut(%q, %q) = %q, %q, %v, want %q, %q, %v", tt.s, tt.sep, before, after, found, tt.before, tt.after, tt.found)
		}
	}
}

var cutPrefixTests = []struct {
	s, sep string
	after  string
	found  bool
}{
	{"abc", "a", "bc", true},
	{"abc", "abc", "", true},
	{"abc", "", "abc", true},
	{"abc", "d", "abc", false},
	{"", "d", "", false},
	{"", "", "", true},
}

func TestCutPrefix(t *testing.T) {
	for _, tt := range cutPrefixTests {
		if after, found := CutPrefix([]byte(tt.s), []byte(tt.sep)); string(after) != tt.after || found != tt.found {
			t.Errorf("CutPrefix(%q, %q) = %q, %v, want %q, %v", tt.s, tt.sep, after, found, tt.after, tt.found)
		}
	}
}

var cutSuffixTests = []struct {
	s, sep string
	before string
	found  bool
}{
	{"abc", "bc", "a", true},
	{"abc", "abc", "", true},
	{"abc", "", "abc", true},
	{"abc", "d", "abc", false},
	{"", "d", "", false},
	{"", "", "", true},
}

func TestCutSuffix(t *testing.T) {
	for _, tt := range cutSuffixTests {
		if before, found := CutSuffix([]byte(tt.s), []byte(tt.sep)); string(before) != tt.before || found != tt.found {
			t.Errorf("CutSuffix(%q, %q) = %q, %v, want %q, %v", tt.s, tt.sep, before, found, tt.before, tt.found)
		}
	}
}

func TestBufferGrowNegative(t *testing.T) {
	defer func() {
		if err := recover(); err == nil {
			t.Fatal("Grow(-1) should have panicked")
		}
	}()
	var b Buffer
	b.Grow(-1)
}

func TestBufferTruncateNegative(t *testing.T) {
	defer func() {
		if err := recover(); err == nil {
			t.Fatal("Truncate(-1) should have panicked")
		}
	}()
	var b Buffer
	b.Truncate(-1)
}

func TestBufferTruncateOutOfRange(t *testing.T) {
	defer func() {
		if err := recover(); err == nil {
			t.Fatal("Truncate(20) should have panicked")
		}
	}()
	var b Buffer
	b.Write(make([]byte, 10))
	b.Truncate(20)
}

var containsTests = []struct {
	b, subslice []byte
	want        bool
}{
	{[]byte("hello"), []byte("hel"), true},
	{[]byte("日本語"), []byte("日本"), true},
	{[]byte("hello"), []byte("Hello, world"), false},
	{[]byte("東京"), []byte("京東"), false},
}

func TestContains(t *testing.T) {
	for _, tt := range containsTests {
		if got := Contains(tt.b, tt.subslice); got != tt.want {
			t.Errorf("Contains(%q, %q) = %v, want %v", tt.b, tt.subslice, got, tt.want)
		}
	}
}

var ContainsAnyTests = []struct {
	b        []byte
	substr   string
	expected bool
}{
	{[]byte(""), "", false},
	{[]byte(""), "a", false},
	{[]byte(""), "abc", false},
	{[]byte("a"), "", false},
	{[]byte("a"), "a", true},
	{[]byte("aaa"), "a", true},
	{[]byte("abc"), "xyz", false},
	{[]byte("abc"), "xcz", true},
	{[]byte("a☺b☻c☹d"), "uvw☻xyz", true},
	{[]byte("aRegExp*"), ".(|)*+?^$[]", true},
	{[]byte(dots + dots + dots), " ", false},
}

func TestContainsAny(t *testing.T) {
	for _, ct := range ContainsAnyTests {
		if ContainsAny(ct.b, ct.substr) != ct.expected {
			t.Errorf("ContainsAny(%s, %s) = %v, want %v",
				ct.b, ct.substr, !ct.expected, ct.expected)
		}
	}
}

var ContainsRuneTests = []struct {
	b        []byte
	r        rune
	expected bool
}{
	{[]byte(""), 'a', false},
	{[]byte("a"), 'a', true},
	{[]byte("aaa"), 'a', true},
	{[]byte("abc"), 'y', false},
	{[]byte("abc"), 'c', true},
	{[]byte("a☺b☻c☹d"), 'x', false},
	{[]byte("a☺b☻c☹d"), '☻', true},
	{[]byte("aRegExp*"), '*', true},
}

func TestContainsRune(t *testing.T) {
	for _, ct := range ContainsRuneTests {
		if ContainsRune(ct.b, ct.r) != ct.expected {
			t.Errorf("ContainsRune(%q, %q) = %v, want %v",
				ct.b, ct.r, !ct.expected, ct.expected)
		}
	}
}

func TestContainsFunc(t *testing.T) {
	for _, ct := range ContainsRuneTests {
		if ContainsFunc(ct.b, func(r rune) bool {
			return ct.r == r
		}) != ct.expected {
			t.Errorf("ContainsFunc(%q, func(%q)) = %v, want %v",
				ct.b, ct.r, !ct.expected, ct.expected)
		}
	}
}

var makeFieldsInput = func() []byte {
	x := make([]byte, 1<<20)
	// Input is ~10% space, ~10% 2-byte UTF-8, rest ASCII non-space.
	for i := range x {
		switch rand.Intn(10) {
		case 0:
			x[i] = ' '
		case 1:
			if i > 0 && x[i-1] == 'x' {
				copy(x[i-1:], "χ")
				break
			}
			fallthrough
		default:
			x[i] = 'x'
		}
	}
	return x
}

var makeFieldsInputASCII = func() []byte {
	x := make([]byte, 1<<20)
	// Input is ~10% space, rest ASCII non-space.
	for i := range x {
		if rand.Intn(10) == 0 {
			x[i] = ' '
		} else {
			x[i] = 'x'
		}
	}
	return x
}

var bytesdata = []struct {
	name string
	data []byte
}{
	{"ASCII", makeFieldsInputASCII()},
	{"Mixed", makeFieldsInput()},
}

func BenchmarkFields(b *testing.B) {
	for _, sd := range bytesdata {
		b.Run(sd.name, func(b *testing.B) {
			for j := 1 << 4; j <= 1<<20; j <<= 4 {
				b.Run(fmt.Sprintf("%d", j), func(b *testing.B) {
					b.ReportAllocs()
					b.SetBytes(int64(j))
					data := sd.data[:j]
					for i := 0; i < b.N; i++ {
						Fields(data)
					}
				})
			}
		})
	}
}

func BenchmarkFieldsFunc(b *testing.B) {
	for _, sd := range bytesdata {
		b.Run(sd.name, func(b *testing.B) {
			for j := 1 << 4; j <= 1<<20; j <<= 4 {
				b.Run(fmt.Sprintf("%d", j), func(b *testing.B) {
					b.ReportAllocs()
					b.SetBytes(int64(j))
					data := sd.data[:j]
					for i := 0; i < b.N; i++ {
						FieldsFunc(data, unicode.IsSpace)
					}
				})
			}
		})
	}
}

func BenchmarkTrimSpace(b *testing.B) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"NoTrim", []byte("typical")},
		{"ASCII", []byte("  foo bar  ")},
		{"SomeNonASCII", []byte("    \u2000\t\r\n x\t\t\r\r\ny\n \u3000    ")},
		{"JustNonASCII", []byte("\u2000\u2000\u2000☺☺☺☺\u3000\u3000\u3000")},
	}
	for _, test := range tests {
		b.Run(test.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				TrimSpace(test.input)
			}
		})
	}
}

func BenchmarkToValidUTF8(b *testing.B) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"Valid", []byte("typical")},
		{"InvalidASCII", []byte("foo\xffbar")},
		{"InvalidNonASCII", []byte("日本語\xff日本語")},
	}
	replacement := []byte("\uFFFD")
	b.ResetTimer()
	for _, test := range tests {
		b.Run(test.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				ToValidUTF8(test.input, replacement)
			}
		})
	}
}

func makeBenchInputHard() []byte {
	tokens := [...]string{
		"<a>", "<p>", "<b>", "<strong>",
		"</a>", "</p>", "</b>", "</strong>",
		"hello", "world",
	}
	x := make([]byte, 0, 1<<20)
	for {
		i := rand.Intn(len(tokens))
		if len(x)+len(tokens[i]) >= 1<<20 {
			break
		}
		x = append(x, tokens[i]...)
	}
	return x
}

var benchInputHard = makeBenchInputHard()

func benchmarkIndexHard(b *testing.B, sep []byte) {
	n := Index(benchInputHard, sep)
	if n < 0 {
		n = len(benchInputHard)
	}
	b.SetBytes(int64(n))
	for i := 0; i < b.N; i++ {
		Index(benchInputHard, sep)
	}
}

func benchmarkLastIndexHard(b *testing.B, sep []byte) {
	for i := 0; i < b.N; i++ {
		LastIndex(benchInputHard, sep)
	}
}

func benchmarkCountHard(b *testing.B, sep []byte) {
	for i := 0; i < b.N; i++ {
		Count(benchInputHard, sep)
	}
}

func BenchmarkIndexHard1(b *testing.B) { benchmarkIndexHard(b, []byte("<>")) }
func BenchmarkIndexHard2(b *testing.B) { benchmarkIndexHard(b, []byte("</pre>")) }
func BenchmarkIndexHard3(b *testing.B) { benchmarkIndexHard(b, []byte("<b>hello world</b>")) }
func BenchmarkIndexHard4(b *testing.B) {
	benchmarkIndexHard(b, []byte("<pre><b>hello</b><strong>world</strong></pre>"))
}

func BenchmarkLastIndexHard1(b *testing.B) { benchmarkLastIndexHard(b, []byte("<>")) }
func BenchmarkLastIndexHard2(b *testing.B) { benchmarkLastIndexHard(b, []byte("</pre>")) }
func BenchmarkLastIndexHard3(b *testing.B) { benchmarkLastIndexHard(b, []byte("<b>hello world</b>")) }

func BenchmarkCountHard1(b *testing.B) { benchmarkCountHard(b, []byte("<>")) }
func BenchmarkCountHard2(b *testing.B) { benchmarkCountHard(b, []byte("</pre>")) }
func BenchmarkCountHard3(b *testing.B) { benchmarkCountHard(b, []byte("<b>hello world</b>")) }

func BenchmarkSplitEmptySeparator(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Split(benchInputHard, nil)
	}
}

func BenchmarkSplitSingleByteSeparator(b *testing.B) {
	sep := []byte("/")
	for i := 0; i < b.N; i++ {
		Split(benchInputHard, sep)
	}
}

func BenchmarkSplitMultiByteSeparator(b *testing.B) {
	sep := []byte("hello")
	for i := 0; i < b.N; i++ {
		Split(benchInputHard, sep)
	}
}

func BenchmarkSplitNSingleByteSeparator(b *testing.B) {
	sep := []byte("/")
	for i := 0; i < b.N; i++ {
		SplitN(benchInputHard, sep, 10)
	}
}

func BenchmarkSplitNMultiByteSeparator(b *testing.B) {
	sep := []byte("hello")
	for i := 0; i < b.N; i++ {
		SplitN(benchInputHard, sep, 10)
	}
}

func BenchmarkRepeat(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Repeat([]byte("-"), 80)
	}
}

func BenchmarkRepeatLarge(b *testing.B) {
	s := Repeat([]byte("@"), 8*1024)
	for j := 8; j <= 30; j++ {
		for _, k := range []int{1, 16, 4097} {
			s := s[:k]
			n := (1 << j) / k
			if n == 0 {
				continue
			}
			b.Run(fmt.Sprintf("%d/%d", 1<<j, k), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					Repeat(s, n)
				}
				b.SetBytes(int64(n * len(s)))
			})
		}
	}
}

func BenchmarkBytesCompare(b *testing.B) {
	for n := 1; n <= 2048; n <<= 1 {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			var x = make([]byte, n)
			var y = make([]byte, n)

			for i := 0; i < n; i++ {
				x[i] = 'a'
			}

			for i := 0; i < n; i++ {
				y[i] = 'a'
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				Compare(x, y)
			}
		})
	}
}

func BenchmarkIndexAnyASCII(b *testing.B) {
	x := Repeat([]byte{'#'}, 2048) // Never matches set
	cs := "0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz"
	for k := 1; k <= 2048; k <<= 4 {
		for j := 1; j <= 64; j <<= 1 {
			b.Run(fmt.Sprintf("%d:%d", k, j), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					IndexAny(x[:k], cs[:j])
				}
			})
		}
	}
}

func BenchmarkIndexAnyUTF8(b *testing.B) {
	x := Repeat([]byte{'#'}, 2048) // Never matches set
	cs := "你好世界, hello world. 你好世界, hello world. 你好世界, hello world."
	for k := 1; k <= 2048; k <<= 4 {
		for j := 1; j <= 64; j <<= 1 {
			b.Run(fmt.Sprintf("%d:%d", k, j), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					IndexAny(x[:k], cs[:j])
				}
			})
		}
	}
}

func BenchmarkLastIndexAnyASCII(b *testing.B) {
	x := Repeat([]byte{'#'}, 2048) // Never matches set
	cs := "0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz"
	for k := 1; k <= 2048; k <<= 4 {
		for j := 1; j <= 64; j <<= 1 {
			b.Run(fmt.Sprintf("%d:%d", k, j), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					LastIndexAny(x[:k], cs[:j])
				}
			})
		}
	}
}

func BenchmarkLastIndexAnyUTF8(b *testing.B) {
	x := Repeat([]byte{'#'}, 2048) // Never matches set
	cs := "你好世界, hello world. 你好世界, hello world. 你好世界, hello world."
	for k := 1; k <= 2048; k <<= 4 {
		for j := 1; j <= 64; j <<= 1 {
			b.Run(fmt.Sprintf("%d:%d", k, j), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					LastIndexAny(x[:k], cs[:j])
				}
			})
		}
	}
}

func BenchmarkTrimASCII(b *testing.B) {
	cs := "0123456789abcdef"
	for k := 1; k <= 4096; k <<= 4 {
		for j := 1; j <= 16; j <<= 1 {
			b.Run(fmt.Sprintf("%d:%d", k, j), func(b *testing.B) {
				x := Repeat([]byte(cs[:j]), k) // Always matches set
				for i := 0; i < b.N; i++ {
					Trim(x[:k], cs[:j])
				}
			})
		}
	}
}

func BenchmarkTrimByte(b *testing.B) {
	x := []byte("  the quick brown fox   ")
	for i := 0; i < b.N; i++ {
		Trim(x, " ")
	}
}

func BenchmarkIndexPeriodic(b *testing.B) {
	key := []byte{1, 1}
	for _, skip := range [...]int{2, 4, 8, 16, 32, 64} {
		b.Run(fmt.Sprintf("IndexPeriodic%d", skip), func(b *testing.B) {
			buf := make([]byte, 1<<16)
			for i := 0; i < len(buf); i += skip {
				buf[i] = 1
			}
			for i := 0; i < b.N; i++ {
				Index(buf, key)
			}
		})
	}
}

func TestClone(t *testing.T) {
	var cloneTests = [][]byte{
		[]byte(nil),
		[]byte{},
		Clone([]byte{}),
		[]byte(strings.Repeat("a", 42))[:0],
		[]byte(strings.Repeat("a", 42))[:0:0],
		[]byte("short"),
		[]byte(strings.Repeat("a", 42)),
	}
	for _, input := range cloneTests {
		clone := Clone(input)
		if !Equal(clone, input) {
			t.Errorf("Clone(%q) = %q; want %q", input, clone, input)
		}

		if input == nil && clone != nil {
			t.Errorf("Clone(%#v) return value should be equal to nil slice.", input)
		}

		if input != nil && clone == nil {
			t.Errorf("Clone(%#v) return value should not be equal to nil slice.", input)
		}

		if cap(input) != 0 && unsafe.SliceData(input) == unsafe.SliceData(clone) {
			t.Errorf("Clone(%q) return value should not reference inputs backing memory.", input)
		}
	}
}

"""




```