Response:
The user wants to understand the functionality of the provided Go code snippet from `go/src/regexp/all_test.go`. I need to analyze the code and identify its purpose, which is to test the `regexp` package in Go.

Here's a breakdown of the testing categories I can infer from the code:

1. **Compilation Tests:** Testing successful and failed regular expression compilations.
2. **Matching Tests:** Testing if a regular expression matches a given string.
3. **Replacement Tests:** Testing string replacement using regular expressions.
4. **Quoting Tests:** Testing the `QuoteMeta` function.
5. **Literal Prefix Tests:** Testing the `LiteralPrefix` function.
6. **Subexpression Tests:** Testing the identification and indexing of subexpressions.
7. **Splitting Tests:** Testing string splitting based on regular expressions.
8. **Parsing and Compilation Tests:**  Testing the combination of parsing and compilation with different flags.
9. **Performance Benchmarks:**  Measuring the performance of various `regexp` operations.
10. **Deep Equal Tests:**  Testing the `DeepEqual` function for `Regexp` objects.
11. **Minimum Input Length Tests:** Testing the calculation of the minimum input length required for a match.
12. **Marshal/Unmarshal Tests:** Testing the serialization and deserialization of `Regexp` objects.

For each category, I will try to provide a concise explanation and a Go code example if applicable. I will also address potential pitfalls for users.这段代码是 Go 语言标准库 `regexp` 包的一部分，具体来说，它是 `go/src/regexp/all_test.go` 文件的一部分，用于对 `regexp` 包的功能进行全面的单元测试和基准测试。

以下是代码中涵盖的主要功能和测试点：

**1. 正则表达式编译 (Compilation)**

* **功能:** 测试 `regexp.Compile` 函数，验证它可以正确地编译有效的正则表达式，并能识别无效的正则表达式并返回相应的错误。
* **Go 代码示例:**
```go
package main

import (
	"fmt"
	"regexp"
)

func main() {
	// 有效的正则表达式
	reValid, errValid := regexp.Compile("a*b")
	if errValid != nil {
		fmt.Println("编译有效正则时发生错误:", errValid)
	} else {
		fmt.Println("成功编译有效正则:", reValid.String())
	}

	// 无效的正则表达式
	reInvalid, errInvalid := regexp.Compile("*ab")
	if errInvalid != nil {
		fmt.Println("编译无效正则时发生预期错误:", errInvalid)
	} else {
		fmt.Println("编译无效正则时没有发生错误，这是一个错误！")
	}
}

// 假设的输入与输出：
// 假设运行上述代码，输出可能如下：
// 成功编译有效正则: a*b
// 编译无效正则时发生预期错误: missing argument to repetition operator: `*`
```

* **测试用例:** 代码中定义了 `goodRe` 和 `badRe` 两个变量，分别包含了有效的和无效的正则表达式字符串，用于测试编译功能。

**2. 字符串匹配 (Matching)**

* **功能:** 测试 `regexp.MatchString` 和 `regexp.Regexp.MatchString` 方法，验证正则表达式是否匹配给定的字符串。
* **Go 代码示例:**
```go
package main

import (
	"fmt"
	"regexp"
)

func main() {
	matched, _ := regexp.MatchString("a[0-9]+b", "a123b")
	fmt.Println("是否匹配:", matched) // 输出: 是否匹配: true

	re, _ := regexp.Compile("go")
	matchedByRegexp := re.MatchString("golang")
	fmt.Println("是否匹配:", matchedByRegexp) // 输出: 是否匹配: true
}
```
* **测试用例:** 通过 `findTests` 数据结构（在提供的代码片段中未完整显示，但可以推断出其结构），包含了需要进行匹配测试的模式和文本。

**3. 字符串替换 (Replacement)**

* **功能:** 测试 `regexp.Regexp.ReplaceAllString`， `regexp.Regexp.ReplaceAllLiteralString` 和 `regexp.Regexp.ReplaceAllStringFunc` 方法，验证使用正则表达式进行字符串替换的功能。
* **Go 代码示例:**
```go
package main

import (
	"fmt"
	"regexp"
)

func main() {
	re := regexp.MustCompile("apple")
	result := re.ReplaceAllString("I have an apple and another apple.", "orange")
	fmt.Println(result) // 输出: I have an orange and another orange.

	reLiteral := regexp.MustCompile("a+")
	resultLiteral := reLiteral.ReplaceAllLiteralString("banana", "($0)")
	fmt.Println(resultLiteral) // 输出: b($0)n($0)n($0)

	reFunc := regexp.MustCompile("[aeiou]")
	resultFunc := reFunc.ReplaceAllStringFunc("hello", func(s string) string {
		switch s {
		case "a":
			return "1"
		case "e":
			return "2"
		case "i":
			return "3"
		case "o":
			return "4"
		case "u":
			return "5"
		default:
			return s
		}
	})
	fmt.Println(resultFunc) // 输出: h2ll4
}
```
* **测试用例:**  `replaceTests`， `replaceLiteralTests` 和 `replaceFuncTests` 变量包含了各种替换场景的测试数据，包括带捕获组的替换，字面量替换和使用函数的替换。

**4. 元字符引用 (Quoting Meta Characters)**

* **功能:** 测试 `regexp.QuoteMeta` 函数，验证它可以正确地将字符串中的正则表达式元字符进行转义，使其被视为普通字符。
* **Go 代码示例:**
```go
package main

import (
	"fmt"
	"regexp"
)

func main() {
	metaString := "a+b*c?"
	quoted := regexp.QuoteMeta(metaString)
	fmt.Println(quoted) // 输出: a\+b\*c\?

	// 使用引用后的字符串进行匹配，会匹配字面量 "a+b*c?"
	re := regexp.MustCompile(quoted)
	fmt.Println(re.MatchString("a+b*c?")) // 输出: true
	fmt.Println(re.MatchString("aaabbc")) // 输出: false
}
```
* **测试用例:** `metaTests` 变量包含了需要进行元字符引用测试的字符串及其预期输出。

**5. 字面量前缀 (Literal Prefix)**

* **功能:** 测试 `regexp.Regexp.LiteralPrefix` 方法，验证它可以提取正则表达式的字面量前缀。
* **Go 代码示例:**
```go
package main

import (
	"fmt"
	"regexp"
)

func main() {
	re := regexp.MustCompile("abc[0-9]+")
	prefix, complete := re.LiteralPrefix()
	fmt.Println("字面量前缀:", prefix)     // 输出: 字面量前缀: abc
	fmt.Println("是否是完整的字面量:", complete) // 输出: 是否是完整的字面量: false

	reComplete := regexp.MustCompile("hello")
	prefixComplete, completeComplete := reComplete.LiteralPrefix()
	fmt.Println("字面量前缀:", prefixComplete)       // 输出: 字面量前缀: hello
	fmt.Println("是否是完整的字面量:", completeComplete) // 输出: 是否是完整的字面量: true
}
```
* **测试用例:** `metaTests` 和 `literalPrefixTests` 变量用于测试字面量前缀的提取。

**6. 子表达式 (Subexpressions)**

* **功能:** 测试 `regexp.Regexp.NumSubexp` 和 `regexp.Regexp.SubexpNames` 以及 `regexp.Regexp.SubexpIndex` 方法，验证它可以正确地识别和索引正则表达式中的捕获组。
* **Go 代码示例:**
```go
package main

import (
	"fmt"
	"regexp"
)

func main() {
	re := regexp.MustCompile(`(ab)(cd)(ef)`)
	fmt.Println("子表达式数量:", re.NumSubexp())        // 输出: 子表达式数量: 3
	fmt.Println("子表达式名称:", re.SubexpNames())     // 输出: 子表达式名称: [ (ab)(cd)(ef)]

	reNamed := regexp.MustCompile(`(?P<first>ab)(?P<second>cd)`)
	fmt.Println("子表达式数量:", reNamed.NumSubexp())    // 输出: 子表达式数量: 2
	fmt.Println("子表达式名称:", reNamed.SubexpNames()) // 输出: 子表达式名称: [ (?P<first>ab)(?P<second>cd) first second]
	fmt.Println("子表达式 'first' 的索引:", reNamed.SubexpIndex("first")) // 输出: 子表达式 'first' 的索引: 1
}
```
* **测试用例:** `subexpCases` 变量包含了各种带有捕获组的正则表达式及其预期的子表达式数量、名称和索引。

**7. 字符串分割 (Splitting)**

* **功能:** 测试 `regexp.Regexp.Split` 方法，验证它可以根据正则表达式将字符串分割成多个子字符串。
* **Go 代码示例:**
```go
package main

import (
	"fmt"
	"regexp"
	"strings"
)

func main() {
	re := regexp.MustCompile(":")
	parts := re.Split("foo:and:bar", -1)
	fmt.Println(strings.Join(parts, ",")) // 输出: foo,and,bar
}
```
* **测试用例:** `splitTests` 变量包含了各种需要进行分割测试的字符串、分隔符（正则表达式）以及预期的分割结果。

**8. 解析和编译 (Parsing and Compiling)**

* **功能:** 测试在不同标志下解析和编译正则表达式，特别是涉及到多行匹配的情况。
* **Go 代码示例:**  这段代码主要在测试框架内部进行，用户一般直接使用 `regexp.Compile`。其目的是验证底层的解析和编译逻辑在不同配置下的正确性。

**9. 性能基准测试 (Benchmarks)**

* **功能:** 代码中包含了一系列的 `Benchmark` 函数，用于衡量 `regexp` 包中不同操作的性能，例如匹配、查找、替换等。这些基准测试可以帮助开发者了解不同正则表达式和输入对性能的影响。

**10. 深层相等性测试 (Deep Equal Test)**

* **功能:** 测试 `reflect.DeepEqual` 函数是否能正确比较两个 `regexp.Regexp` 对象。

**11. 最小输入长度测试 (Minimum Input Length Test)**

* **功能:** 测试 `minInputLen` 函数（该函数在 `regexp` 包内部），用于确定一个正则表达式匹配成功所需的最小输入长度。

**12. 文本序列化和反序列化 (Marshal/Unmarshal Text)**

* **功能:** 测试 `regexp.Regexp` 类型的 `MarshalText` 和 `UnmarshalText` 方法，用于将正则表达式序列化为文本格式和从文本格式反序列化。这对于存储和加载正则表达式非常有用。
* **Go 代码示例:**
```go
package main

import (
	"fmt"
	"regexp"
)

func main() {
	re := regexp.MustCompile("a[0-9]+b")
	marshaled, _ := re.MarshalText()
	fmt.Println("序列化后的文本:", string(marshaled))

	unmarshaled := new(regexp.Regexp)
	err := unmarshaled.UnmarshalText(marshaled)
	if err != nil {
		fmt.Println("反序列化失败:", err)
	} else {
		fmt.Println("反序列化后的正则:", unmarshaled.String())
	}
}
```

**使用者易犯错的点 (Potential Pitfalls for Users):**

* **转义字符的使用:**  在正则表达式字符串中，特殊字符需要使用反斜杠 `\` 进行转义。用户容易忘记或错误地使用转义字符，导致正则表达式的行为与预期不符。
    * **示例:**  如果要匹配字面量点号 `.`，需要写成 `\.`，而不是 `.` (它匹配任意字符)。
* **贪婪匹配与非贪婪匹配:** 默认情况下，正则表达式的量词（如 `*`, `+`, `?`）是贪婪的，会尽可能多地匹配字符。用户可能希望进行非贪婪匹配（尽可能少地匹配），需要在量词后面加上 `?`，例如 `*?`, `+?`, `??`。
    * **示例:** 对于字符串 `"abbbc"` 和正则表达式 `"ab+"`，会匹配 `"abbb"` (贪婪)。如果使用 `"ab+?"`，则会匹配 `"ab"` (非贪婪)。
* **字符类的使用:**  字符类 `[]` 中表示一组字符，`-` 用于表示范围， `^` 在开头表示否定。用户容易混淆字符类内部和外部的特殊字符含义。
    * **示例:** `[a-z]` 匹配小写字母， `[^0-9]` 匹配非数字字符。要在字符类中匹配字面量 `]` 或 `-`，需要进行转义，例如 `[a-z\-]` 匹配小写字母和 `-`。
* **捕获组的使用:**  括号 `()` 用于创建捕获组，方便提取匹配的子串。用户需要理解捕获组的编号和命名方式，以便在替换等操作中引用它们。
* **边界匹配符的使用:** `^` 匹配字符串的开头， `$` 匹配字符串的结尾。用户需要注意多行模式下这些符号的行为。

这段测试代码覆盖了 `regexp` 包的核心功能，通过大量的测试用例确保了该包的稳定性和可靠性。对于学习和使用 Go 语言的正则表达式功能来说，理解这些测试用例是非常有帮助的。

### 提示词
```
这是路径为go/src/regexp/all_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package regexp

import (
	"reflect"
	"regexp/syntax"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

var goodRe = []string{
	``,
	`.`,
	`^.$`,
	`a`,
	`a*`,
	`a+`,
	`a?`,
	`a|b`,
	`a*|b*`,
	`(a*|b)(c*|d)`,
	`[a-z]`,
	`[a-abc-c\-\]\[]`,
	`[a-z]+`,
	`[abc]`,
	`[^1234]`,
	`[^\n]`,
	`\!\\`,
}

type stringError struct {
	re  string
	err string
}

var badRe = []stringError{
	{`*`, "missing argument to repetition operator: `*`"},
	{`+`, "missing argument to repetition operator: `+`"},
	{`?`, "missing argument to repetition operator: `?`"},
	{`(abc`, "missing closing ): `(abc`"},
	{`abc)`, "unexpected ): `abc)`"},
	{`x[a-z`, "missing closing ]: `[a-z`"},
	{`[z-a]`, "invalid character class range: `z-a`"},
	{`abc\`, "trailing backslash at end of expression"},
	{`a**`, "invalid nested repetition operator: `**`"},
	{`a*+`, "invalid nested repetition operator: `*+`"},
	{`\x`, "invalid escape sequence: `\\x`"},
	{strings.Repeat(`\pL`, 27000), "expression too large"},
}

func compileTest(t *testing.T, expr string, error string) *Regexp {
	re, err := Compile(expr)
	if error == "" && err != nil {
		t.Error("compiling `", expr, "`; unexpected error: ", err.Error())
	}
	if error != "" && err == nil {
		t.Error("compiling `", expr, "`; missing error")
	} else if error != "" && !strings.Contains(err.Error(), error) {
		t.Error("compiling `", expr, "`; wrong error: ", err.Error(), "; want ", error)
	}
	return re
}

func TestGoodCompile(t *testing.T) {
	for i := 0; i < len(goodRe); i++ {
		compileTest(t, goodRe[i], "")
	}
}

func TestBadCompile(t *testing.T) {
	for i := 0; i < len(badRe); i++ {
		compileTest(t, badRe[i].re, badRe[i].err)
	}
}

func matchTest(t *testing.T, test *FindTest) {
	re := compileTest(t, test.pat, "")
	if re == nil {
		return
	}
	m := re.MatchString(test.text)
	if m != (len(test.matches) > 0) {
		t.Errorf("MatchString failure on %s: %t should be %t", test, m, len(test.matches) > 0)
	}
	// now try bytes
	m = re.Match([]byte(test.text))
	if m != (len(test.matches) > 0) {
		t.Errorf("Match failure on %s: %t should be %t", test, m, len(test.matches) > 0)
	}
}

func TestMatch(t *testing.T) {
	for _, test := range findTests {
		matchTest(t, &test)
	}
}

func matchFunctionTest(t *testing.T, test *FindTest) {
	m, err := MatchString(test.pat, test.text)
	if err == nil {
		return
	}
	if m != (len(test.matches) > 0) {
		t.Errorf("Match failure on %s: %t should be %t", test, m, len(test.matches) > 0)
	}
}

func TestMatchFunction(t *testing.T) {
	for _, test := range findTests {
		matchFunctionTest(t, &test)
	}
}

func copyMatchTest(t *testing.T, test *FindTest) {
	re := compileTest(t, test.pat, "")
	if re == nil {
		return
	}
	m1 := re.MatchString(test.text)
	m2 := re.Copy().MatchString(test.text)
	if m1 != m2 {
		t.Errorf("Copied Regexp match failure on %s: original gave %t; copy gave %t; should be %t",
			test, m1, m2, len(test.matches) > 0)
	}
}

func TestCopyMatch(t *testing.T) {
	for _, test := range findTests {
		copyMatchTest(t, &test)
	}
}

type ReplaceTest struct {
	pattern, replacement, input, output string
}

var replaceTests = []ReplaceTest{
	// Test empty input and/or replacement, with pattern that matches the empty string.
	{"", "", "", ""},
	{"", "x", "", "x"},
	{"", "", "abc", "abc"},
	{"", "x", "abc", "xaxbxcx"},

	// Test empty input and/or replacement, with pattern that does not match the empty string.
	{"b", "", "", ""},
	{"b", "x", "", ""},
	{"b", "", "abc", "ac"},
	{"b", "x", "abc", "axc"},
	{"y", "", "", ""},
	{"y", "x", "", ""},
	{"y", "", "abc", "abc"},
	{"y", "x", "abc", "abc"},

	// Multibyte characters -- verify that we don't try to match in the middle
	// of a character.
	{"[a-c]*", "x", "\u65e5", "x\u65e5x"},
	{"[^\u65e5]", "x", "abc\u65e5def", "xxx\u65e5xxx"},

	// Start and end of a string.
	{"^[a-c]*", "x", "abcdabc", "xdabc"},
	{"[a-c]*$", "x", "abcdabc", "abcdx"},
	{"^[a-c]*$", "x", "abcdabc", "abcdabc"},
	{"^[a-c]*", "x", "abc", "x"},
	{"[a-c]*$", "x", "abc", "x"},
	{"^[a-c]*$", "x", "abc", "x"},
	{"^[a-c]*", "x", "dabce", "xdabce"},
	{"[a-c]*$", "x", "dabce", "dabcex"},
	{"^[a-c]*$", "x", "dabce", "dabce"},
	{"^[a-c]*", "x", "", "x"},
	{"[a-c]*$", "x", "", "x"},
	{"^[a-c]*$", "x", "", "x"},

	{"^[a-c]+", "x", "abcdabc", "xdabc"},
	{"[a-c]+$", "x", "abcdabc", "abcdx"},
	{"^[a-c]+$", "x", "abcdabc", "abcdabc"},
	{"^[a-c]+", "x", "abc", "x"},
	{"[a-c]+$", "x", "abc", "x"},
	{"^[a-c]+$", "x", "abc", "x"},
	{"^[a-c]+", "x", "dabce", "dabce"},
	{"[a-c]+$", "x", "dabce", "dabce"},
	{"^[a-c]+$", "x", "dabce", "dabce"},
	{"^[a-c]+", "x", "", ""},
	{"[a-c]+$", "x", "", ""},
	{"^[a-c]+$", "x", "", ""},

	// Other cases.
	{"abc", "def", "abcdefg", "defdefg"},
	{"bc", "BC", "abcbcdcdedef", "aBCBCdcdedef"},
	{"abc", "", "abcdabc", "d"},
	{"x", "xXx", "xxxXxxx", "xXxxXxxXxXxXxxXxxXx"},
	{"abc", "d", "", ""},
	{"abc", "d", "abc", "d"},
	{".+", "x", "abc", "x"},
	{"[a-c]*", "x", "def", "xdxexfx"},
	{"[a-c]+", "x", "abcbcdcdedef", "xdxdedef"},
	{"[a-c]*", "x", "abcbcdcdedef", "xdxdxexdxexfx"},

	// Substitutions
	{"a+", "($0)", "banana", "b(a)n(a)n(a)"},
	{"a+", "(${0})", "banana", "b(a)n(a)n(a)"},
	{"a+", "(${0})$0", "banana", "b(a)an(a)an(a)a"},
	{"a+", "(${0})$0", "banana", "b(a)an(a)an(a)a"},
	{"hello, (.+)", "goodbye, ${1}", "hello, world", "goodbye, world"},
	{"hello, (.+)", "goodbye, $1x", "hello, world", "goodbye, "},
	{"hello, (.+)", "goodbye, ${1}x", "hello, world", "goodbye, worldx"},
	{"hello, (.+)", "<$0><$1><$2><$3>", "hello, world", "<hello, world><world><><>"},
	{"hello, (?P<noun>.+)", "goodbye, $noun!", "hello, world", "goodbye, world!"},
	{"hello, (?P<noun>.+)", "goodbye, ${noun}", "hello, world", "goodbye, world"},
	{"(?P<x>hi)|(?P<x>bye)", "$x$x$x", "hi", "hihihi"},
	{"(?P<x>hi)|(?P<x>bye)", "$x$x$x", "bye", "byebyebye"},
	{"(?P<x>hi)|(?P<x>bye)", "$xyz", "hi", ""},
	{"(?P<x>hi)|(?P<x>bye)", "${x}yz", "hi", "hiyz"},
	{"(?P<x>hi)|(?P<x>bye)", "hello $$x", "hi", "hello $x"},
	{"a+", "${oops", "aaa", "${oops"},
	{"a+", "$$", "aaa", "$"},
	{"a+", "$", "aaa", "$"},

	// Substitution when subexpression isn't found
	{"(x)?", "$1", "123", "123"},
	{"abc", "$1", "123", "123"},

	// Substitutions involving a (x){0}
	{"(a)(b){0}(c)", ".$1|$3.", "xacxacx", "x.a|c.x.a|c.x"},
	{"(a)(((b))){0}c", ".$1.", "xacxacx", "x.a.x.a.x"},
	{"((a(b){0}){3}){5}(h)", "y caramb$2", "say aaaaaaaaaaaaaaaah", "say ay caramba"},
	{"((a(b){0}){3}){5}h", "y caramb$2", "say aaaaaaaaaaaaaaaah", "say ay caramba"},
}

var replaceLiteralTests = []ReplaceTest{
	// Substitutions
	{"a+", "($0)", "banana", "b($0)n($0)n($0)"},
	{"a+", "(${0})", "banana", "b(${0})n(${0})n(${0})"},
	{"a+", "(${0})$0", "banana", "b(${0})$0n(${0})$0n(${0})$0"},
	{"a+", "(${0})$0", "banana", "b(${0})$0n(${0})$0n(${0})$0"},
	{"hello, (.+)", "goodbye, ${1}", "hello, world", "goodbye, ${1}"},
	{"hello, (?P<noun>.+)", "goodbye, $noun!", "hello, world", "goodbye, $noun!"},
	{"hello, (?P<noun>.+)", "goodbye, ${noun}", "hello, world", "goodbye, ${noun}"},
	{"(?P<x>hi)|(?P<x>bye)", "$x$x$x", "hi", "$x$x$x"},
	{"(?P<x>hi)|(?P<x>bye)", "$x$x$x", "bye", "$x$x$x"},
	{"(?P<x>hi)|(?P<x>bye)", "$xyz", "hi", "$xyz"},
	{"(?P<x>hi)|(?P<x>bye)", "${x}yz", "hi", "${x}yz"},
	{"(?P<x>hi)|(?P<x>bye)", "hello $$x", "hi", "hello $$x"},
	{"a+", "${oops", "aaa", "${oops"},
	{"a+", "$$", "aaa", "$$"},
	{"a+", "$", "aaa", "$"},
}

type ReplaceFuncTest struct {
	pattern       string
	replacement   func(string) string
	input, output string
}

var replaceFuncTests = []ReplaceFuncTest{
	{"[a-c]", func(s string) string { return "x" + s + "y" }, "defabcdef", "defxayxbyxcydef"},
	{"[a-c]+", func(s string) string { return "x" + s + "y" }, "defabcdef", "defxabcydef"},
	{"[a-c]*", func(s string) string { return "x" + s + "y" }, "defabcdef", "xydxyexyfxabcydxyexyfxy"},
}

func TestReplaceAll(t *testing.T) {
	for _, tc := range replaceTests {
		re, err := Compile(tc.pattern)
		if err != nil {
			t.Errorf("Unexpected error compiling %q: %v", tc.pattern, err)
			continue
		}
		actual := re.ReplaceAllString(tc.input, tc.replacement)
		if actual != tc.output {
			t.Errorf("%q.ReplaceAllString(%q,%q) = %q; want %q",
				tc.pattern, tc.input, tc.replacement, actual, tc.output)
		}
		// now try bytes
		actual = string(re.ReplaceAll([]byte(tc.input), []byte(tc.replacement)))
		if actual != tc.output {
			t.Errorf("%q.ReplaceAll(%q,%q) = %q; want %q",
				tc.pattern, tc.input, tc.replacement, actual, tc.output)
		}
	}
}

func TestReplaceAllLiteral(t *testing.T) {
	// Run ReplaceAll tests that do not have $ expansions.
	for _, tc := range replaceTests {
		if strings.Contains(tc.replacement, "$") {
			continue
		}
		re, err := Compile(tc.pattern)
		if err != nil {
			t.Errorf("Unexpected error compiling %q: %v", tc.pattern, err)
			continue
		}
		actual := re.ReplaceAllLiteralString(tc.input, tc.replacement)
		if actual != tc.output {
			t.Errorf("%q.ReplaceAllLiteralString(%q,%q) = %q; want %q",
				tc.pattern, tc.input, tc.replacement, actual, tc.output)
		}
		// now try bytes
		actual = string(re.ReplaceAllLiteral([]byte(tc.input), []byte(tc.replacement)))
		if actual != tc.output {
			t.Errorf("%q.ReplaceAllLiteral(%q,%q) = %q; want %q",
				tc.pattern, tc.input, tc.replacement, actual, tc.output)
		}
	}

	// Run literal-specific tests.
	for _, tc := range replaceLiteralTests {
		re, err := Compile(tc.pattern)
		if err != nil {
			t.Errorf("Unexpected error compiling %q: %v", tc.pattern, err)
			continue
		}
		actual := re.ReplaceAllLiteralString(tc.input, tc.replacement)
		if actual != tc.output {
			t.Errorf("%q.ReplaceAllLiteralString(%q,%q) = %q; want %q",
				tc.pattern, tc.input, tc.replacement, actual, tc.output)
		}
		// now try bytes
		actual = string(re.ReplaceAllLiteral([]byte(tc.input), []byte(tc.replacement)))
		if actual != tc.output {
			t.Errorf("%q.ReplaceAllLiteral(%q,%q) = %q; want %q",
				tc.pattern, tc.input, tc.replacement, actual, tc.output)
		}
	}
}

func TestReplaceAllFunc(t *testing.T) {
	for _, tc := range replaceFuncTests {
		re, err := Compile(tc.pattern)
		if err != nil {
			t.Errorf("Unexpected error compiling %q: %v", tc.pattern, err)
			continue
		}
		actual := re.ReplaceAllStringFunc(tc.input, tc.replacement)
		if actual != tc.output {
			t.Errorf("%q.ReplaceFunc(%q,fn) = %q; want %q",
				tc.pattern, tc.input, actual, tc.output)
		}
		// now try bytes
		actual = string(re.ReplaceAllFunc([]byte(tc.input), func(s []byte) []byte { return []byte(tc.replacement(string(s))) }))
		if actual != tc.output {
			t.Errorf("%q.ReplaceFunc(%q,fn) = %q; want %q",
				tc.pattern, tc.input, actual, tc.output)
		}
	}
}

type MetaTest struct {
	pattern, output, literal string
	isLiteral                bool
}

var metaTests = []MetaTest{
	{``, ``, ``, true},
	{`foo`, `foo`, `foo`, true},
	{`日本語+`, `日本語\+`, `日本語`, false},
	{`foo\.\$`, `foo\\\.\\\$`, `foo.$`, true}, // has meta but no operator
	{`foo.\$`, `foo\.\\\$`, `foo`, false},     // has escaped operators and real operators
	{`!@#$%^&*()_+-=[{]}\|,<.>/?~`, `!@#\$%\^&\*\(\)_\+-=\[\{\]\}\\\|,<\.>/\?~`, `!@#`, false},
}

var literalPrefixTests = []MetaTest{
	// See golang.org/issue/11175.
	// output is unused.
	{`^0^0$`, ``, `0`, false},
	{`^0^`, ``, ``, false},
	{`^0$`, ``, `0`, true},
	{`$0^`, ``, ``, false},
	{`$0$`, ``, ``, false},
	{`^^0$$`, ``, ``, false},
	{`^$^$`, ``, ``, false},
	{`$$0^^`, ``, ``, false},
	{`a\x{fffd}b`, ``, `a`, false},
	{`\x{fffd}b`, ``, ``, false},
	{"\ufffd", ``, ``, false},
}

func TestQuoteMeta(t *testing.T) {
	for _, tc := range metaTests {
		// Verify that QuoteMeta returns the expected string.
		quoted := QuoteMeta(tc.pattern)
		if quoted != tc.output {
			t.Errorf("QuoteMeta(`%s`) = `%s`; want `%s`",
				tc.pattern, quoted, tc.output)
			continue
		}

		// Verify that the quoted string is in fact treated as expected
		// by Compile -- i.e. that it matches the original, unquoted string.
		if tc.pattern != "" {
			re, err := Compile(quoted)
			if err != nil {
				t.Errorf("Unexpected error compiling QuoteMeta(`%s`): %v", tc.pattern, err)
				continue
			}
			src := "abc" + tc.pattern + "def"
			repl := "xyz"
			replaced := re.ReplaceAllString(src, repl)
			expected := "abcxyzdef"
			if replaced != expected {
				t.Errorf("QuoteMeta(`%s`).Replace(`%s`,`%s`) = `%s`; want `%s`",
					tc.pattern, src, repl, replaced, expected)
			}
		}
	}
}

func TestLiteralPrefix(t *testing.T) {
	for _, tc := range append(metaTests, literalPrefixTests...) {
		// Literal method needs to scan the pattern.
		re := MustCompile(tc.pattern)
		str, complete := re.LiteralPrefix()
		if complete != tc.isLiteral {
			t.Errorf("LiteralPrefix(`%s`) = %t; want %t", tc.pattern, complete, tc.isLiteral)
		}
		if str != tc.literal {
			t.Errorf("LiteralPrefix(`%s`) = `%s`; want `%s`", tc.pattern, str, tc.literal)
		}
	}
}

type subexpIndex struct {
	name  string
	index int
}

type subexpCase struct {
	input   string
	num     int
	names   []string
	indices []subexpIndex
}

var emptySubexpIndices = []subexpIndex{{"", -1}, {"missing", -1}}

var subexpCases = []subexpCase{
	{``, 0, nil, emptySubexpIndices},
	{`.*`, 0, nil, emptySubexpIndices},
	{`abba`, 0, nil, emptySubexpIndices},
	{`ab(b)a`, 1, []string{"", ""}, emptySubexpIndices},
	{`ab(.*)a`, 1, []string{"", ""}, emptySubexpIndices},
	{`(.*)ab(.*)a`, 2, []string{"", "", ""}, emptySubexpIndices},
	{`(.*)(ab)(.*)a`, 3, []string{"", "", "", ""}, emptySubexpIndices},
	{`(.*)((a)b)(.*)a`, 4, []string{"", "", "", "", ""}, emptySubexpIndices},
	{`(.*)(\(ab)(.*)a`, 3, []string{"", "", "", ""}, emptySubexpIndices},
	{`(.*)(\(a\)b)(.*)a`, 3, []string{"", "", "", ""}, emptySubexpIndices},
	{`(?P<foo>.*)(?P<bar>(a)b)(?P<foo>.*)a`, 4, []string{"", "foo", "bar", "", "foo"}, []subexpIndex{{"", -1}, {"missing", -1}, {"foo", 1}, {"bar", 2}}},
}

func TestSubexp(t *testing.T) {
	for _, c := range subexpCases {
		re := MustCompile(c.input)
		n := re.NumSubexp()
		if n != c.num {
			t.Errorf("%q: NumSubexp = %d, want %d", c.input, n, c.num)
			continue
		}
		names := re.SubexpNames()
		if len(names) != 1+n {
			t.Errorf("%q: len(SubexpNames) = %d, want %d", c.input, len(names), n)
			continue
		}
		if c.names != nil {
			for i := 0; i < 1+n; i++ {
				if names[i] != c.names[i] {
					t.Errorf("%q: SubexpNames[%d] = %q, want %q", c.input, i, names[i], c.names[i])
				}
			}
		}
		for _, subexp := range c.indices {
			index := re.SubexpIndex(subexp.name)
			if index != subexp.index {
				t.Errorf("%q: SubexpIndex(%q) = %d, want %d", c.input, subexp.name, index, subexp.index)
			}
		}
	}
}

var splitTests = []struct {
	s   string
	r   string
	n   int
	out []string
}{
	{"foo:and:bar", ":", -1, []string{"foo", "and", "bar"}},
	{"foo:and:bar", ":", 1, []string{"foo:and:bar"}},
	{"foo:and:bar", ":", 2, []string{"foo", "and:bar"}},
	{"foo:and:bar", "foo", -1, []string{"", ":and:bar"}},
	{"foo:and:bar", "bar", -1, []string{"foo:and:", ""}},
	{"foo:and:bar", "baz", -1, []string{"foo:and:bar"}},
	{"baabaab", "a", -1, []string{"b", "", "b", "", "b"}},
	{"baabaab", "a*", -1, []string{"b", "b", "b"}},
	{"baabaab", "ba*", -1, []string{"", "", "", ""}},
	{"foobar", "f*b*", -1, []string{"", "o", "o", "a", "r"}},
	{"foobar", "f+.*b+", -1, []string{"", "ar"}},
	{"foobooboar", "o{2}", -1, []string{"f", "b", "boar"}},
	{"a,b,c,d,e,f", ",", 3, []string{"a", "b", "c,d,e,f"}},
	{"a,b,c,d,e,f", ",", 0, nil},
	{",", ",", -1, []string{"", ""}},
	{",,,", ",", -1, []string{"", "", "", ""}},
	{"", ",", -1, []string{""}},
	{"", ".*", -1, []string{""}},
	{"", ".+", -1, []string{""}},
	{"", "", -1, []string{}},
	{"foobar", "", -1, []string{"f", "o", "o", "b", "a", "r"}},
	{"abaabaccadaaae", "a*", 5, []string{"", "b", "b", "c", "cadaaae"}},
	{":x:y:z:", ":", -1, []string{"", "x", "y", "z", ""}},
}

func TestSplit(t *testing.T) {
	for i, test := range splitTests {
		re, err := Compile(test.r)
		if err != nil {
			t.Errorf("#%d: %q: compile error: %s", i, test.r, err.Error())
			continue
		}

		split := re.Split(test.s, test.n)
		if !slices.Equal(split, test.out) {
			t.Errorf("#%d: %q: got %q; want %q", i, test.r, split, test.out)
		}

		if QuoteMeta(test.r) == test.r {
			strsplit := strings.SplitN(test.s, test.r, test.n)
			if !slices.Equal(split, strsplit) {
				t.Errorf("#%d: Split(%q, %q, %d): regexp vs strings mismatch\nregexp=%q\nstrings=%q", i, test.s, test.r, test.n, split, strsplit)
			}
		}
	}
}

// The following sequence of Match calls used to panic. See issue #12980.
func TestParseAndCompile(t *testing.T) {
	expr := "a$"
	s := "a\nb"

	for i, tc := range []struct {
		reFlags  syntax.Flags
		expMatch bool
	}{
		{syntax.Perl | syntax.OneLine, false},
		{syntax.Perl &^ syntax.OneLine, true},
	} {
		parsed, err := syntax.Parse(expr, tc.reFlags)
		if err != nil {
			t.Fatalf("%d: parse: %v", i, err)
		}
		re, err := Compile(parsed.String())
		if err != nil {
			t.Fatalf("%d: compile: %v", i, err)
		}
		if match := re.MatchString(s); match != tc.expMatch {
			t.Errorf("%d: %q.MatchString(%q)=%t; expected=%t", i, re, s, match, tc.expMatch)
		}
	}
}

// Check that one-pass cutoff does trigger.
func TestOnePassCutoff(t *testing.T) {
	re, err := syntax.Parse(`^x{1,1000}y{1,1000}$`, syntax.Perl)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	p, err := syntax.Compile(re.Simplify())
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if compileOnePass(p) != nil {
		t.Fatalf("makeOnePass succeeded; wanted nil")
	}
}

// Check that the same machine can be used with the standard matcher
// and then the backtracker when there are no captures.
func TestSwitchBacktrack(t *testing.T) {
	re := MustCompile(`a|b`)
	long := make([]byte, maxBacktrackVector+1)

	// The following sequence of Match calls used to panic. See issue #10319.
	re.Match(long)     // triggers standard matcher
	re.Match(long[:1]) // triggers backtracker
}

func BenchmarkFind(b *testing.B) {
	b.StopTimer()
	re := MustCompile("a+b+")
	wantSubs := "aaabb"
	s := []byte("acbb" + wantSubs + "dd")
	b.StartTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		subs := re.Find(s)
		if string(subs) != wantSubs {
			b.Fatalf("Find(%q) = %q; want %q", s, subs, wantSubs)
		}
	}
}

func BenchmarkFindAllNoMatches(b *testing.B) {
	re := MustCompile("a+b+")
	s := []byte("acddee")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		all := re.FindAll(s, -1)
		if all != nil {
			b.Fatalf("FindAll(%q) = %q; want nil", s, all)
		}
	}
}

func BenchmarkFindString(b *testing.B) {
	b.StopTimer()
	re := MustCompile("a+b+")
	wantSubs := "aaabb"
	s := "acbb" + wantSubs + "dd"
	b.StartTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		subs := re.FindString(s)
		if subs != wantSubs {
			b.Fatalf("FindString(%q) = %q; want %q", s, subs, wantSubs)
		}
	}
}

func BenchmarkFindSubmatch(b *testing.B) {
	b.StopTimer()
	re := MustCompile("a(a+b+)b")
	wantSubs := "aaabb"
	s := []byte("acbb" + wantSubs + "dd")
	b.StartTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		subs := re.FindSubmatch(s)
		if string(subs[0]) != wantSubs {
			b.Fatalf("FindSubmatch(%q)[0] = %q; want %q", s, subs[0], wantSubs)
		}
		if string(subs[1]) != "aab" {
			b.Fatalf("FindSubmatch(%q)[1] = %q; want %q", s, subs[1], "aab")
		}
	}
}

func BenchmarkFindStringSubmatch(b *testing.B) {
	b.StopTimer()
	re := MustCompile("a(a+b+)b")
	wantSubs := "aaabb"
	s := "acbb" + wantSubs + "dd"
	b.StartTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		subs := re.FindStringSubmatch(s)
		if subs[0] != wantSubs {
			b.Fatalf("FindStringSubmatch(%q)[0] = %q; want %q", s, subs[0], wantSubs)
		}
		if subs[1] != "aab" {
			b.Fatalf("FindStringSubmatch(%q)[1] = %q; want %q", s, subs[1], "aab")
		}
	}
}

func BenchmarkLiteral(b *testing.B) {
	x := strings.Repeat("x", 50) + "y"
	b.StopTimer()
	re := MustCompile("y")
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if !re.MatchString(x) {
			b.Fatalf("no match!")
		}
	}
}

func BenchmarkNotLiteral(b *testing.B) {
	x := strings.Repeat("x", 50) + "y"
	b.StopTimer()
	re := MustCompile(".y")
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if !re.MatchString(x) {
			b.Fatalf("no match!")
		}
	}
}

func BenchmarkMatchClass(b *testing.B) {
	b.StopTimer()
	x := strings.Repeat("xxxx", 20) + "w"
	re := MustCompile("[abcdw]")
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if !re.MatchString(x) {
			b.Fatalf("no match!")
		}
	}
}

func BenchmarkMatchClass_InRange(b *testing.B) {
	b.StopTimer()
	// 'b' is between 'a' and 'c', so the charclass
	// range checking is no help here.
	x := strings.Repeat("bbbb", 20) + "c"
	re := MustCompile("[ac]")
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		if !re.MatchString(x) {
			b.Fatalf("no match!")
		}
	}
}

func BenchmarkReplaceAll(b *testing.B) {
	x := "abcdefghijklmnopqrstuvwxyz"
	b.StopTimer()
	re := MustCompile("[cjrw]")
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		re.ReplaceAllString(x, "")
	}
}

func BenchmarkAnchoredLiteralShortNonMatch(b *testing.B) {
	b.StopTimer()
	x := []byte("abcdefghijklmnopqrstuvwxyz")
	re := MustCompile("^zbc(d|e)")
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		re.Match(x)
	}
}

func BenchmarkAnchoredLiteralLongNonMatch(b *testing.B) {
	b.StopTimer()
	x := []byte("abcdefghijklmnopqrstuvwxyz")
	for i := 0; i < 15; i++ {
		x = append(x, x...)
	}
	re := MustCompile("^zbc(d|e)")
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		re.Match(x)
	}
}

func BenchmarkAnchoredShortMatch(b *testing.B) {
	b.StopTimer()
	x := []byte("abcdefghijklmnopqrstuvwxyz")
	re := MustCompile("^.bc(d|e)")
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		re.Match(x)
	}
}

func BenchmarkAnchoredLongMatch(b *testing.B) {
	b.StopTimer()
	x := []byte("abcdefghijklmnopqrstuvwxyz")
	for i := 0; i < 15; i++ {
		x = append(x, x...)
	}
	re := MustCompile("^.bc(d|e)")
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		re.Match(x)
	}
}

func BenchmarkOnePassShortA(b *testing.B) {
	b.StopTimer()
	x := []byte("abcddddddeeeededd")
	re := MustCompile("^.bc(d|e)*$")
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		re.Match(x)
	}
}

func BenchmarkNotOnePassShortA(b *testing.B) {
	b.StopTimer()
	x := []byte("abcddddddeeeededd")
	re := MustCompile(".bc(d|e)*$")
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		re.Match(x)
	}
}

func BenchmarkOnePassShortB(b *testing.B) {
	b.StopTimer()
	x := []byte("abcddddddeeeededd")
	re := MustCompile("^.bc(?:d|e)*$")
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		re.Match(x)
	}
}

func BenchmarkNotOnePassShortB(b *testing.B) {
	b.StopTimer()
	x := []byte("abcddddddeeeededd")
	re := MustCompile(".bc(?:d|e)*$")
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		re.Match(x)
	}
}

func BenchmarkOnePassLongPrefix(b *testing.B) {
	b.StopTimer()
	x := []byte("abcdefghijklmnopqrstuvwxyz")
	re := MustCompile("^abcdefghijklmnopqrstuvwxyz.*$")
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		re.Match(x)
	}
}

func BenchmarkOnePassLongNotPrefix(b *testing.B) {
	b.StopTimer()
	x := []byte("abcdefghijklmnopqrstuvwxyz")
	re := MustCompile("^.bcdefghijklmnopqrstuvwxyz.*$")
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		re.Match(x)
	}
}

func BenchmarkMatchParallelShared(b *testing.B) {
	x := []byte("this is a long line that contains foo bar baz")
	re := MustCompile("foo (ba+r)? baz")
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			re.Match(x)
		}
	})
}

func BenchmarkMatchParallelCopied(b *testing.B) {
	x := []byte("this is a long line that contains foo bar baz")
	re := MustCompile("foo (ba+r)? baz")
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		re := re.Copy()
		for pb.Next() {
			re.Match(x)
		}
	})
}

var sink string

func BenchmarkQuoteMetaAll(b *testing.B) {
	specials := make([]byte, 0)
	for i := byte(0); i < utf8.RuneSelf; i++ {
		if special(i) {
			specials = append(specials, i)
		}
	}
	s := string(specials)
	b.SetBytes(int64(len(s)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sink = QuoteMeta(s)
	}
}

func BenchmarkQuoteMetaNone(b *testing.B) {
	s := "abcdefghijklmnopqrstuvwxyz"
	b.SetBytes(int64(len(s)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sink = QuoteMeta(s)
	}
}

var compileBenchData = []struct{ name, re string }{
	{"Onepass", `^a.[l-nA-Cg-j]?e$`},
	{"Medium", `^((a|b|[d-z0-9])*(日){4,5}.)+$`},
	{"Hard", strings.Repeat(`((abc)*|`, 50) + strings.Repeat(`)`, 50)},
}

func BenchmarkCompile(b *testing.B) {
	for _, data := range compileBenchData {
		b.Run(data.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := Compile(data.re); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestDeepEqual(t *testing.T) {
	re1 := MustCompile("a.*b.*c.*d")
	re2 := MustCompile("a.*b.*c.*d")
	if !reflect.DeepEqual(re1, re2) { // has always been true, since Go 1.
		t.Errorf("DeepEqual(re1, re2) = false, want true")
	}

	re1.MatchString("abcdefghijklmn")
	if !reflect.DeepEqual(re1, re2) {
		t.Errorf("DeepEqual(re1, re2) = false, want true")
	}

	re2.MatchString("abcdefghijklmn")
	if !reflect.DeepEqual(re1, re2) {
		t.Errorf("DeepEqual(re1, re2) = false, want true")
	}

	re2.MatchString(strings.Repeat("abcdefghijklmn", 100))
	if !reflect.DeepEqual(re1, re2) {
		t.Errorf("DeepEqual(re1, re2) = false, want true")
	}
}

var minInputLenTests = []struct {
	Regexp string
	min    int
}{
	{``, 0},
	{`a`, 1},
	{`aa`, 2},
	{`(aa)a`, 3},
	{`(?:aa)a`, 3},
	{`a?a`, 1},
	{`(aaa)|(aa)`, 2},
	{`(aa)+a`, 3},
	{`(aa)*a`, 1},
	{`(aa){3,5}`, 6},
	{`[a-z]`, 1},
	{`日`, 3},
}

func TestMinInputLen(t *testing.T) {
	for _, tt := range minInputLenTests {
		re, _ := syntax.Parse(tt.Regexp, syntax.Perl)
		m := minInputLen(re)
		if m != tt.min {
			t.Errorf("regexp %#q has minInputLen %d, should be %d", tt.Regexp, m, tt.min)
		}
	}
}

func TestUnmarshalText(t *testing.T) {
	unmarshaled := new(Regexp)
	for i := range goodRe {
		re := compileTest(t, goodRe[i], "")
		marshaled, err := re.MarshalText()
		if err != nil {
			t.Errorf("regexp %#q failed to marshal: %s", re, err)
			continue
		}
		if err := unmarshaled.UnmarshalText(marshaled); err != nil {
			t.Errorf("regexp %#q failed to unmarshal: %s", re, err)
			continue
		}
		if unmarshaled.String() != goodRe[i] {
			t.Errorf("UnmarshalText returned unexpected value: %s", unmarshaled.String())
		}

		buf := make([]byte, 4, 32)
		marshalAppend, err := re.AppendText(buf)
		if err != nil {
			t.Errorf("regexp %#q failed to marshal: %s", re, err)
			continue
		}
		marshalAppend = marshalAppend[4:]
		if err := unmarshaled.UnmarshalText(marshalAppend); err != nil {
			t.Errorf("regexp %#q failed to unmarshal: %s", re, err)
			continue
		}
		if unmarshaled.String() != goodRe[i] {
			t.Errorf("UnmarshalText returned unexpected value: %s", unmarshaled.String())
		}
	}
	t.Run("invalid pattern", func(t *testing.T) {
		re := new(Regexp)
		err := re.UnmarshalText([]byte(`\`))
		if err == nil {
			t.Error("unexpected success")
		}
	})
}
```