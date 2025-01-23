Response:
Let's break down the thought process for analyzing this Go code snippet for `replace_test.go`.

**1. Initial Scan and Purpose Identification:**

* **File Path:** `go/src/strings/replace_test.go`. The `_test.go` suffix immediately tells me this is a testing file. The `strings` directory indicates it's testing functionality within the `strings` package. Specifically, `replace_test.go` suggests it's testing string replacement operations.
* **Package Declaration:** `package strings_test`. This confirms it's an external test package for `strings`.
* **Imports:**  `bytes`, `fmt`, `. "strings"`, `testing`. These imports give clues about the functionalities being tested:
    * `bytes`: Likely involves `bytes.Buffer` for building strings, especially in the context of `WriteString`.
    * `fmt`:  Used for formatting output (e.g., `fmt.Sprintf`, `fmt.Errorf`).
    * `. "strings"`: This is a crucial import. The dot means it's importing the `strings` package directly into the current namespace. This allows direct use of `strings` functions and types like `Replacer`.
    * `testing`: The standard Go testing library.

**2. Identifying Key Components:**

* **`htmlEscaper` and `htmlUnescaper`:** These are defined using `NewReplacer`. The string pairs strongly suggest they are for escaping and unescaping HTML entities. This is a concrete example of the `Replacer` in action.
* **`oldHTMLEscape`:** This function provides a comparison point. It shows the older way of doing HTML escaping using multiple `Replace` calls. This is useful for understanding the motivation behind `Replacer`.
* **`capitalLetters`:** Another `NewReplacer` example, simpler than the HTML one, mapping lowercase to uppercase.
* **`TestReplacer` function:** This is the core test function. Its structure (`type testCase`, `var testCases []testCase`, loop through `testCases`) is a common Go testing pattern. It's designed to test the `Replacer.Replace` and `Replacer.WriteString` methods.
* **Various `NewReplacer` calls within `TestReplacer`:** These are different configurations of the `Replacer` with various input and output string pairs. Analyzing these reveals different scenarios being tested (single character replacements, multi-character replacements, empty strings, etc.). The comments within the test cases also provide hints about the intended behavior.
* **`TestPickAlgorithm`:** This function suggests that the `NewReplacer` function might choose different underlying implementations based on the input. The `algorithmTestCases` and the use of `fmt.Sprintf("%T", tc.r.Replacer())` confirm this.
* **`TestWriteStringError`:** This specifically tests the error handling of `WriteString`.
* **`TestGenericTrieBuilding`:**  The structure of the test cases (`in`, `out` with the visual trie representation) and the use of `PrintTrie()` strongly imply that a trie data structure is used internally for efficient replacement, especially for multiple potential replacements.
* **Benchmark functions:**  Functions starting with `Benchmark` are performance tests. They compare the speed of different approaches or scenarios.

**3. Inferring Functionality and Implementation:**

* **`NewReplacer(pairs...)`:**  This function likely creates a `Replacer` object. The variable number of arguments suggests it takes pairs of old and new strings. The tests confirm this.
* **`Replacer.Replace(s string) string`:** This method performs the string replacement. The tests cover various input strings and expected outputs.
* **`Replacer.WriteString(w io.Writer, s string) (n int, err error)`:** This method writes the result of the replacement to an `io.Writer`. The tests verify the written string and the returned byte count and error.
* **Internal implementation details:**  The `TestPickAlgorithm` and `TestGenericTrieBuilding` functions provide insight into the internal workings. The existence of `*strings.byteReplacer`, `*strings.byteStringReplacer`, `*strings.singleStringReplacer`, and `*strings.genericReplacer` suggests different optimized implementations are used based on the types of replacements. The trie structure indicates an optimization for multiple potential replacements.

**4. Considering Potential Errors and Edge Cases:**

* **Overlapping replacements:**  The test cases like `NewReplacer("a", "1", "aa", "2", "aaa", "3")` and `NewReplacer("aaa", "3", "aa", "2", "a", "1")` highlight how overlapping replacements are handled (likely longest match first).
* **Empty old string:** The `blankToX1`, `blankToX2`, etc., test cases specifically address the behavior when replacing an empty string. This is a common edge case in string manipulation.
* **No replacements:** The `nop` test case checks the behavior when no replacements are defined.

**5. Structuring the Answer:**

Based on the above analysis, I'd structure the answer as follows:

* **Purpose:** Start with the high-level goal: testing the string replacement functionality of the `strings` package.
* **Key Components:** List and explain the main elements of the code: `htmlEscaper`, `htmlUnescaper`, `TestReplacer`, etc.
* **Functionality of `NewReplacer` and `Replacer` methods:** Explain what these functions do based on the test cases.
* **Implementation Details (Inferred):** Discuss the likely internal implementations based on `TestPickAlgorithm` and `TestGenericTrieBuilding`. Mention the optimization strategies.
* **Code Examples:** Provide clear examples demonstrating the usage of `NewReplacer` and its methods, drawing from the test cases and adding simple usage scenarios. Include expected inputs and outputs.
* **Command-Line Parameters:**  Note that this test file itself doesn't directly process command-line arguments but might be run as part of a larger testing suite.
* **Common Mistakes:** Highlight potential pitfalls, like understanding the order of replacements or the behavior with empty strings, using the test cases as illustrations.

By following this methodical approach, I can effectively analyze the Go code snippet and provide a comprehensive and accurate explanation of its functionality.
这段代码是 Go 语言标准库 `strings` 包中 `replace_test.go` 文件的一部分，它的主要功能是**测试 `strings` 包中用于字符串替换功能的 `Replacer` 类型及其相关方法**。

具体来说，它测试了以下功能：

1. **`NewReplacer(oldnew ...string)` 函数:**  这个函数用于创建一个 `Replacer` 对象，它接受一系列的旧字符串和新字符串的配对。测试用例通过各种不同的旧/新字符串组合来验证 `NewReplacer` 的行为，包括：
    * 简单的字符替换 (例如 `capitalLetters`)
    * HTML 实体转义和反转义 (例如 `htmlEscaper` 和 `htmlUnescaper`)
    * 不同长度的旧字符串和新字符串
    * 重复的旧字符串
    * 包含空字符串的替换
    * 没有替换规则的情况
    * 包含大量替换规则的情况
    * 替换规则之间存在前缀的情况

2. **`Replacer.Replace(s string) string` 方法:**  这个方法使用 `Replacer` 对象中定义的替换规则，对输入的字符串 `s` 进行替换，并返回替换后的新字符串。测试用例覆盖了各种输入字符串，包括：
    * 没有需要替换的字符
    * 只有一个需要替换的字符
    * 有多个需要替换的字符
    * 需要替换的字符重复出现
    * 空字符串

3. **`Replacer.WriteString(w io.Writer, s string) (n int, err error)` 方法:** 这个方法将替换后的字符串写入到 `io.Writer` 接口，并返回写入的字节数和可能发生的错误。测试用例验证了写入操作的正确性，包括写入的字符串内容和返回的字节数。 同时还测试了写入错误的情况。

4. **`Replacer.Replacer() interface{ Replace(string) string }` 方法:**  这是一个内部方法，用于返回 `Replacer` 接口的实际实现。 `TestPickAlgorithm` 测试函数验证了 `NewReplacer` 函数会根据传入的替换规则选择不同的内部实现算法，以优化性能。

5. **内部 trie 结构的构建 (`PrintTrie`)**: `TestGenericTrieBuilding` 测试函数通过 `PrintTrie()` 方法，验证了当 `Replacer` 包含多个可能存在前缀的旧字符串时，内部构建的 trie 树的结构是否正确。这是一种用于高效匹配和替换的算法。

**以下是用 Go 代码举例说明 `Replacer` 功能的实现:**

```go
package main

import (
	"fmt"
	"strings"
)

func main() {
	// 创建一个 Replacer 对象，将 "apple" 替换为 "orange"，将 "banana" 替换为 "grape"
	replacer := strings.NewReplacer("apple", "orange", "banana", "grape")

	// 使用 Replace 方法进行替换
	text := "I like apple and banana."
	replacedText := replacer.Replace(text)
	fmt.Println(replacedText) // 输出: I like orange and grape.

	// 使用 WriteString 方法将替换后的内容写入到字符串构建器
	var builder strings.Builder
	_, err := replacer.WriteString(&builder, text)
	if err != nil {
		fmt.Println("WriteString error:", err)
	}
	fmt.Println(builder.String()) // 输出: I like orange and grape.
}
```

**假设的输入与输出:**

* **输入 (给 `replacer.Replace()`):** `"I have a big apple."`
* **输出:** `"I have a big orange."`

* **输入 (给 `replacer.WriteString()`):** `"Do you like banana?"`
* **输出 (写入到 `io.Writer`):** `"Do you like grape?"`

**命令行参数的具体处理:**

这段代码本身是一个测试文件，不涉及命令行参数的处理。 它的目的是测试 `strings` 包的功能，通常会通过 `go test` 命令来运行。 `go test` 命令会执行该文件中的所有以 `Test` 开头的函数。

**使用者易犯错的点:**

1. **替换顺序和重叠问题:** 当多个旧字符串存在重叠时，`Replacer` 的替换行为是贪婪的，它会匹配最长的旧字符串。  这可能导致意想不到的结果。

   **例子:**

   ```go
   replacer := strings.NewReplacer("aa", "X", "aaa", "Y")
   text := "aaaa"
   result := replacer.Replace(text)
   fmt.Println(result) // 输出: Xaa
   ```
   在这个例子中，虽然 "aaa" 也能匹配，但由于 `Replacer` 内部可能先检查 "aa"，所以前两个 "a" 被替换成了 "X"，剩下的 "aa" 没有被 "aaa" 匹配到。如果希望 "aaa" 优先匹配，需要调整 `NewReplacer` 中字符串的顺序，但这并不是一个可靠的解决办法，因为内部实现可能会进行优化。 更可靠的方式是仔细设计替换规则，避免重叠歧义。

2. **性能考虑:** 对于大量的替换规则或者很长的输入字符串，`Replacer` 内部使用的算法效率至关重要。虽然 Go 语言的 `Replacer` 做了优化，但仍然需要根据实际情况选择合适的替换策略。例如，如果只是进行单个字符串的替换，直接使用 `strings.Replace` 可能更简单高效。

3. **理解 `NewReplacer` 的参数:** `NewReplacer` 接收的是旧字符串和新字符串的配对，必须是成对出现。如果传入奇数个字符串，会导致 `panic`。

   **例子:**

   ```go
   // 错误用法，会导致 panic
   replacer := strings.NewReplacer("a", "b", "c")
   ```

总而言之，`go/src/strings/replace_test.go` 这部分代码全面地测试了 Go 语言 `strings` 包中 `Replacer` 类型的各种功能和边界情况，确保了这个字符串替换工具的正确性和可靠性。通过阅读这些测试用例，开发者可以更深入地理解 `Replacer` 的工作原理和使用方法。

### 提示词
```
这是路径为go/src/strings/replace_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package strings_test

import (
	"bytes"
	"fmt"
	. "strings"
	"testing"
)

var htmlEscaper = NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	`"`, "&quot;",
	"'", "&apos;",
)

var htmlUnescaper = NewReplacer(
	"&amp;", "&",
	"&lt;", "<",
	"&gt;", ">",
	"&quot;", `"`,
	"&apos;", "'",
)

// The http package's old HTML escaping function.
func oldHTMLEscape(s string) string {
	s = Replace(s, "&", "&amp;", -1)
	s = Replace(s, "<", "&lt;", -1)
	s = Replace(s, ">", "&gt;", -1)
	s = Replace(s, `"`, "&quot;", -1)
	s = Replace(s, "'", "&apos;", -1)
	return s
}

var capitalLetters = NewReplacer("a", "A", "b", "B")

// TestReplacer tests the replacer implementations.
func TestReplacer(t *testing.T) {
	type testCase struct {
		r       *Replacer
		in, out string
	}
	var testCases []testCase

	// str converts 0xff to "\xff". This isn't just string(b) since that converts to UTF-8.
	str := func(b byte) string {
		return string([]byte{b})
	}
	var s []string

	// inc maps "\x00"->"\x01", ..., "a"->"b", "b"->"c", ..., "\xff"->"\x00".
	s = nil
	for i := 0; i < 256; i++ {
		s = append(s, str(byte(i)), str(byte(i+1)))
	}
	inc := NewReplacer(s...)

	// Test cases with 1-byte old strings, 1-byte new strings.
	testCases = append(testCases,
		testCase{capitalLetters, "brad", "BrAd"},
		testCase{capitalLetters, Repeat("a", (32<<10)+123), Repeat("A", (32<<10)+123)},
		testCase{capitalLetters, "", ""},

		testCase{inc, "brad", "csbe"},
		testCase{inc, "\x00\xff", "\x01\x00"},
		testCase{inc, "", ""},

		testCase{NewReplacer("a", "1", "a", "2"), "brad", "br1d"},
	)

	// repeat maps "a"->"a", "b"->"bb", "c"->"ccc", ...
	s = nil
	for i := 0; i < 256; i++ {
		n := i + 1 - 'a'
		if n < 1 {
			n = 1
		}
		s = append(s, str(byte(i)), Repeat(str(byte(i)), n))
	}
	repeat := NewReplacer(s...)

	// Test cases with 1-byte old strings, variable length new strings.
	testCases = append(testCases,
		testCase{htmlEscaper, "No changes", "No changes"},
		testCase{htmlEscaper, "I <3 escaping & stuff", "I &lt;3 escaping &amp; stuff"},
		testCase{htmlEscaper, "&&&", "&amp;&amp;&amp;"},
		testCase{htmlEscaper, "", ""},

		testCase{repeat, "brad", "bbrrrrrrrrrrrrrrrrrradddd"},
		testCase{repeat, "abba", "abbbba"},
		testCase{repeat, "", ""},

		testCase{NewReplacer("a", "11", "a", "22"), "brad", "br11d"},
	)

	// The remaining test cases have variable length old strings.

	testCases = append(testCases,
		testCase{htmlUnescaper, "&amp;amp;", "&amp;"},
		testCase{htmlUnescaper, "&lt;b&gt;HTML&apos;s neat&lt;/b&gt;", "<b>HTML's neat</b>"},
		testCase{htmlUnescaper, "", ""},

		testCase{NewReplacer("a", "1", "a", "2", "xxx", "xxx"), "brad", "br1d"},

		testCase{NewReplacer("a", "1", "aa", "2", "aaa", "3"), "aaaa", "1111"},

		testCase{NewReplacer("aaa", "3", "aa", "2", "a", "1"), "aaaa", "31"},
	)

	// gen1 has multiple old strings of variable length. There is no
	// overall non-empty common prefix, but some pairwise common prefixes.
	gen1 := NewReplacer(
		"aaa", "3[aaa]",
		"aa", "2[aa]",
		"a", "1[a]",
		"i", "i",
		"longerst", "most long",
		"longer", "medium",
		"long", "short",
		"xx", "xx",
		"x", "X",
		"X", "Y",
		"Y", "Z",
	)
	testCases = append(testCases,
		testCase{gen1, "fooaaabar", "foo3[aaa]b1[a]r"},
		testCase{gen1, "long, longerst, longer", "short, most long, medium"},
		testCase{gen1, "xxxxx", "xxxxX"},
		testCase{gen1, "XiX", "YiY"},
		testCase{gen1, "", ""},
	)

	// gen2 has multiple old strings with no pairwise common prefix.
	gen2 := NewReplacer(
		"roses", "red",
		"violets", "blue",
		"sugar", "sweet",
	)
	testCases = append(testCases,
		testCase{gen2, "roses are red, violets are blue...", "red are red, blue are blue..."},
		testCase{gen2, "", ""},
	)

	// gen3 has multiple old strings with an overall common prefix.
	gen3 := NewReplacer(
		"abracadabra", "poof",
		"abracadabrakazam", "splat",
		"abraham", "lincoln",
		"abrasion", "scrape",
		"abraham", "isaac",
	)
	testCases = append(testCases,
		testCase{gen3, "abracadabrakazam abraham", "poofkazam lincoln"},
		testCase{gen3, "abrasion abracad", "scrape abracad"},
		testCase{gen3, "abba abram abrasive", "abba abram abrasive"},
		testCase{gen3, "", ""},
	)

	// foo{1,2,3,4} have multiple old strings with an overall common prefix
	// and 1- or 2- byte extensions from the common prefix.
	foo1 := NewReplacer(
		"foo1", "A",
		"foo2", "B",
		"foo3", "C",
	)
	foo2 := NewReplacer(
		"foo1", "A",
		"foo2", "B",
		"foo31", "C",
		"foo32", "D",
	)
	foo3 := NewReplacer(
		"foo11", "A",
		"foo12", "B",
		"foo31", "C",
		"foo32", "D",
	)
	foo4 := NewReplacer(
		"foo12", "B",
		"foo32", "D",
	)
	testCases = append(testCases,
		testCase{foo1, "fofoofoo12foo32oo", "fofooA2C2oo"},
		testCase{foo1, "", ""},

		testCase{foo2, "fofoofoo12foo32oo", "fofooA2Doo"},
		testCase{foo2, "", ""},

		testCase{foo3, "fofoofoo12foo32oo", "fofooBDoo"},
		testCase{foo3, "", ""},

		testCase{foo4, "fofoofoo12foo32oo", "fofooBDoo"},
		testCase{foo4, "", ""},
	)

	// genAll maps "\x00\x01\x02...\xfe\xff" to "[all]", amongst other things.
	allBytes := make([]byte, 256)
	for i := range allBytes {
		allBytes[i] = byte(i)
	}
	allString := string(allBytes)
	genAll := NewReplacer(
		allString, "[all]",
		"\xff", "[ff]",
		"\x00", "[00]",
	)
	testCases = append(testCases,
		testCase{genAll, allString, "[all]"},
		testCase{genAll, "a\xff" + allString + "\x00", "a[ff][all][00]"},
		testCase{genAll, "", ""},
	)

	// Test cases with empty old strings.

	blankToX1 := NewReplacer("", "X")
	blankToX2 := NewReplacer("", "X", "", "")
	blankHighPriority := NewReplacer("", "X", "o", "O")
	blankLowPriority := NewReplacer("o", "O", "", "X")
	blankNoOp1 := NewReplacer("", "")
	blankNoOp2 := NewReplacer("", "", "", "A")
	blankFoo := NewReplacer("", "X", "foobar", "R", "foobaz", "Z")
	testCases = append(testCases,
		testCase{blankToX1, "foo", "XfXoXoX"},
		testCase{blankToX1, "", "X"},

		testCase{blankToX2, "foo", "XfXoXoX"},
		testCase{blankToX2, "", "X"},

		testCase{blankHighPriority, "oo", "XOXOX"},
		testCase{blankHighPriority, "ii", "XiXiX"},
		testCase{blankHighPriority, "oiio", "XOXiXiXOX"},
		testCase{blankHighPriority, "iooi", "XiXOXOXiX"},
		testCase{blankHighPriority, "", "X"},

		testCase{blankLowPriority, "oo", "OOX"},
		testCase{blankLowPriority, "ii", "XiXiX"},
		testCase{blankLowPriority, "oiio", "OXiXiOX"},
		testCase{blankLowPriority, "iooi", "XiOOXiX"},
		testCase{blankLowPriority, "", "X"},

		testCase{blankNoOp1, "foo", "foo"},
		testCase{blankNoOp1, "", ""},

		testCase{blankNoOp2, "foo", "foo"},
		testCase{blankNoOp2, "", ""},

		testCase{blankFoo, "foobarfoobaz", "XRXZX"},
		testCase{blankFoo, "foobar-foobaz", "XRX-XZX"},
		testCase{blankFoo, "", "X"},
	)

	// single string replacer

	abcMatcher := NewReplacer("abc", "[match]")

	testCases = append(testCases,
		testCase{abcMatcher, "", ""},
		testCase{abcMatcher, "ab", "ab"},
		testCase{abcMatcher, "abc", "[match]"},
		testCase{abcMatcher, "abcd", "[match]d"},
		testCase{abcMatcher, "cabcabcdabca", "c[match][match]d[match]a"},
	)

	// Issue 6659 cases (more single string replacer)

	noHello := NewReplacer("Hello", "")
	testCases = append(testCases,
		testCase{noHello, "Hello", ""},
		testCase{noHello, "Hellox", "x"},
		testCase{noHello, "xHello", "x"},
		testCase{noHello, "xHellox", "xx"},
	)

	// No-arg test cases.

	nop := NewReplacer()
	testCases = append(testCases,
		testCase{nop, "abc", "abc"},
		testCase{nop, "", ""},
	)

	// Run the test cases.

	for i, tc := range testCases {
		if s := tc.r.Replace(tc.in); s != tc.out {
			t.Errorf("%d. Replace(%q) = %q, want %q", i, tc.in, s, tc.out)
		}
		var buf bytes.Buffer
		n, err := tc.r.WriteString(&buf, tc.in)
		if err != nil {
			t.Errorf("%d. WriteString: %v", i, err)
			continue
		}
		got := buf.String()
		if got != tc.out {
			t.Errorf("%d. WriteString(%q) wrote %q, want %q", i, tc.in, got, tc.out)
			continue
		}
		if n != len(tc.out) {
			t.Errorf("%d. WriteString(%q) wrote correct string but reported %d bytes; want %d (%q)",
				i, tc.in, n, len(tc.out), tc.out)
		}
	}
}

var algorithmTestCases = []struct {
	r    *Replacer
	want string
}{
	{capitalLetters, "*strings.byteReplacer"},
	{htmlEscaper, "*strings.byteStringReplacer"},
	{NewReplacer("12", "123"), "*strings.singleStringReplacer"},
	{NewReplacer("1", "12"), "*strings.byteStringReplacer"},
	{NewReplacer("", "X"), "*strings.genericReplacer"},
	{NewReplacer("a", "1", "b", "12", "cde", "123"), "*strings.genericReplacer"},
}

// TestPickAlgorithm tests that NewReplacer picks the correct algorithm.
func TestPickAlgorithm(t *testing.T) {
	for i, tc := range algorithmTestCases {
		got := fmt.Sprintf("%T", tc.r.Replacer())
		if got != tc.want {
			t.Errorf("%d. algorithm = %s, want %s", i, got, tc.want)
		}
	}
}

type errWriter struct{}

func (errWriter) Write(p []byte) (n int, err error) {
	return 0, fmt.Errorf("unwritable")
}

// TestWriteStringError tests that WriteString returns an error
// received from the underlying io.Writer.
func TestWriteStringError(t *testing.T) {
	for i, tc := range algorithmTestCases {
		n, err := tc.r.WriteString(errWriter{}, "abc")
		if n != 0 || err == nil || err.Error() != "unwritable" {
			t.Errorf("%d. WriteStringError = %d, %v, want 0, unwritable", i, n, err)
		}
	}
}

// TestGenericTrieBuilding verifies the structure of the generated trie. There
// is one node per line, and the key ending with the current line is in the
// trie if it ends with a "+".
func TestGenericTrieBuilding(t *testing.T) {
	testCases := []struct{ in, out string }{
		{"abc;abdef;abdefgh;xx;xy;z", `-
			a-
			.b-
			..c+
			..d-
			...ef+
			.....gh+
			x-
			.x+
			.y+
			z+
			`},
		{"abracadabra;abracadabrakazam;abraham;abrasion", `-
			a-
			.bra-
			....c-
			.....adabra+
			...........kazam+
			....h-
			.....am+
			....s-
			.....ion+
			`},
		{"aaa;aa;a;i;longerst;longer;long;xx;x;X;Y", `-
			X+
			Y+
			a+
			.a+
			..a+
			i+
			l-
			.ong+
			....er+
			......st+
			x+
			.x+
			`},
		{"foo;;foo;foo1", `+
			f-
			.oo+
			...1+
			`},
	}

	for _, tc := range testCases {
		keys := Split(tc.in, ";")
		args := make([]string, len(keys)*2)
		for i, key := range keys {
			args[i*2] = key
		}

		got := NewReplacer(args...).PrintTrie()
		// Remove tabs from tc.out
		wantbuf := make([]byte, 0, len(tc.out))
		for i := 0; i < len(tc.out); i++ {
			if tc.out[i] != '\t' {
				wantbuf = append(wantbuf, tc.out[i])
			}
		}
		want := string(wantbuf)

		if got != want {
			t.Errorf("PrintTrie(%q)\ngot\n%swant\n%s", tc.in, got, want)
		}
	}
}

func BenchmarkGenericNoMatch(b *testing.B) {
	str := Repeat("A", 100) + Repeat("B", 100)
	generic := NewReplacer("a", "A", "b", "B", "12", "123") // varying lengths forces generic
	for i := 0; i < b.N; i++ {
		generic.Replace(str)
	}
}

func BenchmarkGenericMatch1(b *testing.B) {
	str := Repeat("a", 100) + Repeat("b", 100)
	generic := NewReplacer("a", "A", "b", "B", "12", "123")
	for i := 0; i < b.N; i++ {
		generic.Replace(str)
	}
}

func BenchmarkGenericMatch2(b *testing.B) {
	str := Repeat("It&apos;s &lt;b&gt;HTML&lt;/b&gt;!", 100)
	for i := 0; i < b.N; i++ {
		htmlUnescaper.Replace(str)
	}
}

func benchmarkSingleString(b *testing.B, pattern, text string) {
	r := NewReplacer(pattern, "[match]")
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Replace(text)
	}
}

func BenchmarkSingleMaxSkipping(b *testing.B) {
	benchmarkSingleString(b, Repeat("b", 25), Repeat("a", 10000))
}

func BenchmarkSingleLongSuffixFail(b *testing.B) {
	benchmarkSingleString(b, "b"+Repeat("a", 500), Repeat("a", 1002))
}

func BenchmarkSingleMatch(b *testing.B) {
	benchmarkSingleString(b, "abcdef", Repeat("abcdefghijklmno", 1000))
}

func BenchmarkByteByteNoMatch(b *testing.B) {
	str := Repeat("A", 100) + Repeat("B", 100)
	for i := 0; i < b.N; i++ {
		capitalLetters.Replace(str)
	}
}

func BenchmarkByteByteMatch(b *testing.B) {
	str := Repeat("a", 100) + Repeat("b", 100)
	for i := 0; i < b.N; i++ {
		capitalLetters.Replace(str)
	}
}

func BenchmarkByteStringMatch(b *testing.B) {
	str := "<" + Repeat("a", 99) + Repeat("b", 99) + ">"
	for i := 0; i < b.N; i++ {
		htmlEscaper.Replace(str)
	}
}

func BenchmarkHTMLEscapeNew(b *testing.B) {
	str := "I <3 to escape HTML & other text too."
	for i := 0; i < b.N; i++ {
		htmlEscaper.Replace(str)
	}
}

func BenchmarkHTMLEscapeOld(b *testing.B) {
	str := "I <3 to escape HTML & other text too."
	for i := 0; i < b.N; i++ {
		oldHTMLEscape(str)
	}
}

func BenchmarkByteStringReplacerWriteString(b *testing.B) {
	str := Repeat("I <3 to escape HTML & other text too.", 100)
	buf := new(bytes.Buffer)
	for i := 0; i < b.N; i++ {
		htmlEscaper.WriteString(buf, str)
		buf.Reset()
	}
}

func BenchmarkByteReplacerWriteString(b *testing.B) {
	str := Repeat("abcdefghijklmnopqrstuvwxyz", 100)
	buf := new(bytes.Buffer)
	for i := 0; i < b.N; i++ {
		capitalLetters.WriteString(buf, str)
		buf.Reset()
	}
}

// BenchmarkByteByteReplaces compares byteByteImpl against multiple Replaces.
func BenchmarkByteByteReplaces(b *testing.B) {
	str := Repeat("a", 100) + Repeat("b", 100)
	for i := 0; i < b.N; i++ {
		Replace(Replace(str, "a", "A", -1), "b", "B", -1)
	}
}

// BenchmarkByteByteMap compares byteByteImpl against Map.
func BenchmarkByteByteMap(b *testing.B) {
	str := Repeat("a", 100) + Repeat("b", 100)
	fn := func(r rune) rune {
		switch r {
		case 'a':
			return 'A'
		case 'b':
			return 'B'
		}
		return r
	}
	for i := 0; i < b.N; i++ {
		Map(fn, str)
	}
}

var mapdata = []struct{ name, data string }{
	{"ASCII", "a b c d e f g h i j k l m n o p q r s t u v w x y z"},
	{"Greek", "α β γ δ ε ζ η θ ι κ λ μ ν ξ ο π ρ ς σ τ υ φ χ ψ ω"},
}

func BenchmarkMap(b *testing.B) {
	mapidentity := func(r rune) rune {
		return r
	}

	b.Run("identity", func(b *testing.B) {
		for _, md := range mapdata {
			b.Run(md.name, func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					Map(mapidentity, md.data)
				}
			})
		}
	})

	mapchange := func(r rune) rune {
		if 'a' <= r && r <= 'z' {
			return r + 'A' - 'a'
		}
		if 'α' <= r && r <= 'ω' {
			return r + 'Α' - 'α'
		}
		return r
	}

	b.Run("change", func(b *testing.B) {
		for _, md := range mapdata {
			b.Run(md.name, func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					Map(mapchange, md.data)
				}
			})
		}
	})
}
```