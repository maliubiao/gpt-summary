Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding - The File Path:**

The first thing to notice is the file path: `go/src/html/template/js_test.go`. This immediately tells us:

* **Language:** Go.
* **Context:**  It's a test file within the `html/template` package. This strongly suggests it's testing functionality related to handling JavaScript within HTML templates. The `_test.go` suffix confirms it's a testing file.

**2. Core Functionality Identification - Reading the Test Functions:**

The most direct way to understand the functionality is to look at the test functions:

* `TestNextJsCtx(t *testing.T)`: The name suggests it's testing something related to a "JavaScript Context" (`JsCtx`). The loop iterates through various string inputs (`s`) and expected `jsCtx` values. The `nextJSCtx` function is being tested. The comments within the test provide hints about what `jsCtxRegexp` and `jsCtxDivOp` represent (contexts where a regular expression or a division operator is expected).

* `TestJSValEscaper(t *testing.T)`: This test clearly focuses on a function called `jsValEscaper`. The test cases involve various Go data types (integers, floats, strings, structs, slices, nil) and their expected JavaScript string representations. The comments like "// ulp(1 << 53) > 1 so this loses precision in JS" indicate edge cases and JavaScript-specific considerations. The `skipNest` field suggests testing how the escaping behaves when nested.

* `TestJSStrEscaper(t *testing.T)`: Similar to the previous test, this focuses on `jsStrEscaper`. The test cases involve strings with special characters and their escaped versions in JavaScript string literals. The comments explain why certain characters are escaped (e.g., `</script>`, `<!--`, `"`, `'`).

* `TestJSRegexpEscaper(t *testing.T)`: This test focuses on `jsRegexpEscaper`. The test cases demonstrate escaping of characters that have special meaning in regular expressions.

* `TestEscapersOnLower7AndSelectHighCodepoints(t *testing.T)`: This test tests `jsStrEscaper` and `jsRegexpEscaper` specifically with a broad range of characters, including control characters, common symbols, and Unicode characters. This is important for ensuring comprehensive escaping.

* `TestIsJsMimeType(t *testing.T)`: This test focuses on `isJSType` and checks if various MIME types are correctly identified as JavaScript types.

* `Benchmark...`: The `Benchmark` functions are for performance testing. They measure how long the different escaping functions take to execute with various inputs.

**3. Inferring the Purpose - Connecting the Dots:**

By looking at the test functions and their names, we can infer the broader purpose:

* **Security:** The escaping functions (`jsValEscaper`, `jsStrEscaper`, `jsRegexpEscaper`) are clearly designed to prevent cross-site scripting (XSS) vulnerabilities. They escape characters that could be interpreted as HTML or JavaScript code when embedded in a web page. The escaping of sequences like `</script>`, `<!--`, and the handling of quotes are strong indicators of this.
* **Correct JavaScript Generation:** The `nextJSCtx` function likely plays a role in determining the correct context within JavaScript to ensure proper parsing. The differentiation between contexts where a division operator or regular expression is expected is important for generating valid JavaScript.
* **Data Type Handling:** `jsValEscaper` handles different Go data types and converts them to their JavaScript equivalents, ensuring type safety when embedding data in JavaScript.

**4. Go Language Features Illustrated:**

The code demonstrates several Go language features:

* **Testing:** The `testing` package is used extensively for unit testing.
* **Structs:** Structs are used to define test cases (`tests := []struct{...}`).
* **Slices:** Slices are used to hold the test cases.
* **String Manipulation:** Functions like `strings.TrimSpace` and `strings.Builder` are used.
* **Interfaces:** The `jsonErrType` and its `MarshalJSON` method demonstrate interfaces.
* **Error Handling:** The `errors` package is used.
* **Benchmarking:** The `testing` package's benchmarking capabilities are used.

**5. Code Example (Illustrating `jsValEscaper`):**

To provide a concrete example, consider the `TestJSValEscaper`. We can see that a Go integer `42` is converted to the JavaScript string `" 42 "`. A Go string `"foo"` is converted to `"\"foo\""`. More complex structures like structs and slices are also handled.

**6. Command Line Arguments:**

This specific test file doesn't directly process command-line arguments. However, the `go test` command is used to run these tests. Common command-line arguments for `go test` include `-v` (verbose output) and specifying specific test files or functions to run.

**7. Common Mistakes (Based on the Code):**

The comments in the `TestNextJsCtx` function provide insights into potential mistakes. Developers might incorrectly assume that a `/` will always be treated as a division operator. The context matters. The test cases highlight scenarios where a `/` can start a regular expression literal.

**Self-Correction/Refinement during the thought process:**

* Initially, I might focus too much on the individual escaping functions without seeing the bigger picture of XSS prevention. Stepping back and considering the context of the `html/template` package helps solidify this understanding.
* I might initially overlook the nuances in `TestNextJsCtx` regarding the division operator vs. regular expression context. Reading the comments carefully and understanding the examples helps clarify this.
* I might forget to explicitly mention the Go language features demonstrated in the code. Reviewing the code after understanding its functionality helps identify these.

By following this structured approach, we can effectively analyze the Go code snippet and understand its purpose, functionality, and relevant details.
这个 `js_test.go` 文件是 Go 语言 `html/template` 标准库的一部分，专门用于测试与在 HTML 模板中安全地生成 JavaScript 相关的代码。  它的主要功能可以归纳如下：

**主要功能:**

1. **测试 JavaScript 上下文判断 (`TestNextJsCtx`)**:
   - 测试 `nextJSCtx` 函数，该函数用于判断在给定的 JavaScript 代码片段之后，下一个 JavaScript 语法结构是期望一个正则表达式的开始，还是一个除法运算符。
   - 这是为了在模板生成 JavaScript 代码时，能够正确地进行转义，避免将除法运算符 `/` 误解析为正则表达式的开始，或者反之。

2. **测试 JavaScript 值转义 (`TestJSValEscaper`)**:
   - 测试 `jsValEscaper` 函数，该函数负责将 Go 语言的各种数据类型（如整数、浮点数、字符串、结构体、切片等）安全地转义为可以在 JavaScript 中直接使用的字面量。
   - 重点在于防止 XSS 攻击，例如，它会转义 `<script>` 标签等敏感字符。
   - 还会处理一些 JavaScript 特有的数值表示，例如 `NaN` 和 `Infinity`。

3. **测试 JavaScript 字符串转义 (`TestJSStrEscaper`)**:
   - 测试 `jsStrEscaper` 函数，该函数负责将 Go 字符串转义为可以在 JavaScript 字符串字面量中安全使用的形式。
   - 这包括转义特殊字符（如换行符、制表符、引号等）和防止 HTML 注入攻击的字符（如 `<`、`>` 等）。

4. **测试 JavaScript 正则表达式转义 (`TestJSRegexpEscaper`)**:
   - 测试 `jsRegexpEscaper` 函数，该函数负责将 Go 字符串转义为可以在 JavaScript 正则表达式字面量中安全使用的形式。
   - 这包括转义正则表达式中的特殊字符，以避免意外的正则表达式行为。

5. **测试各种字符的转义 (`TestEscapersOnLower7AndSelectHighCodepoints`)**:
   - 测试 `jsStrEscaper` 和 `jsRegexpEscaper` 对于各种 ASCII 控制字符、常用符号以及 Unicode 字符的转义是否正确。

6. **测试 JavaScript MIME 类型判断 (`TestIsJsMimeType`)**:
   - 测试 `isJSType` 函数，该函数用于判断给定的 MIME 类型字符串是否是 JavaScript 相关的类型。

7. **性能基准测试 (`Benchmark...`)**:
   - 提供了一系列的性能基准测试，用于衡量不同转义函数的性能。

**它是什么 Go 语言功能的实现？**

这个文件主要实现了 `html/template` 包中用于在 JavaScript 上下文中进行安全输出的功能。  `html/template` 包允许开发者创建包含动态内容的 HTML 模板。为了防止安全漏洞（特别是跨站脚本攻击 XSS），在将动态数据插入到 HTML 中的不同上下文中时，需要进行适当的转义。  这个 `js_test.go` 文件测试的就是针对 JavaScript 上下文的转义逻辑。

**Go 代码举例说明:**

假设我们有一个 HTML 模板，需要在 JavaScript 代码
### 提示词
```
这是路径为go/src/html/template/js_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package template

import (
	"errors"
	"math"
	"strings"
	"testing"
)

func TestNextJsCtx(t *testing.T) {
	tests := []struct {
		jsCtx jsCtx
		s     string
	}{
		// Statement terminators precede regexps.
		{jsCtxRegexp, ";"},
		// This is not airtight.
		//     ({ valueOf: function () { return 1 } } / 2)
		// is valid JavaScript but in practice, devs do not do this.
		// A block followed by a statement starting with a RegExp is
		// much more common:
		//     while (x) {...} /foo/.test(x) || panic()
		{jsCtxRegexp, "}"},
		// But member, call, grouping, and array expression terminators
		// precede div ops.
		{jsCtxDivOp, ")"},
		{jsCtxDivOp, "]"},
		// At the start of a primary expression, array, or expression
		// statement, expect a regexp.
		{jsCtxRegexp, "("},
		{jsCtxRegexp, "["},
		{jsCtxRegexp, "{"},
		// Assignment operators precede regexps as do all exclusively
		// prefix and binary operators.
		{jsCtxRegexp, "="},
		{jsCtxRegexp, "+="},
		{jsCtxRegexp, "*="},
		{jsCtxRegexp, "*"},
		{jsCtxRegexp, "!"},
		// Whether the + or - is infix or prefix, it cannot precede a
		// div op.
		{jsCtxRegexp, "+"},
		{jsCtxRegexp, "-"},
		// An incr/decr op precedes a div operator.
		// This is not airtight. In (g = ++/h/i) a regexp follows a
		// pre-increment operator, but in practice devs do not try to
		// increment or decrement regular expressions.
		// (g++/h/i) where ++ is a postfix operator on g is much more
		// common.
		{jsCtxDivOp, "--"},
		{jsCtxDivOp, "++"},
		{jsCtxDivOp, "x--"},
		// When we have many dashes or pluses, then they are grouped
		// left to right.
		{jsCtxRegexp, "x---"}, // A postfix -- then a -.
		// return followed by a slash returns the regexp literal or the
		// slash starts a regexp literal in an expression statement that
		// is dead code.
		{jsCtxRegexp, "return"},
		{jsCtxRegexp, "return "},
		{jsCtxRegexp, "return\t"},
		{jsCtxRegexp, "return\n"},
		{jsCtxRegexp, "return\u2028"},
		// Identifiers can be divided and cannot validly be preceded by
		// a regular expressions. Semicolon insertion cannot happen
		// between an identifier and a regular expression on a new line
		// because the one token lookahead for semicolon insertion has
		// to conclude that it could be a div binary op and treat it as
		// such.
		{jsCtxDivOp, "x"},
		{jsCtxDivOp, "x "},
		{jsCtxDivOp, "x\t"},
		{jsCtxDivOp, "x\n"},
		{jsCtxDivOp, "x\u2028"},
		{jsCtxDivOp, "preturn"},
		// Numbers precede div ops.
		{jsCtxDivOp, "0"},
		// Dots that are part of a number are div preceders.
		{jsCtxDivOp, "0."},
		// Some JS interpreters treat NBSP as a normal space, so
		// we must too in order to properly escape things.
		{jsCtxRegexp, "=\u00A0"},
	}

	for _, test := range tests {
		if ctx := nextJSCtx([]byte(test.s), jsCtxRegexp); ctx != test.jsCtx {
			t.Errorf("%q: want %s got %s", test.s, test.jsCtx, ctx)
		}
		if ctx := nextJSCtx([]byte(test.s), jsCtxDivOp); ctx != test.jsCtx {
			t.Errorf("%q: want %s got %s", test.s, test.jsCtx, ctx)
		}
	}

	if nextJSCtx([]byte("   "), jsCtxRegexp) != jsCtxRegexp {
		t.Error("Blank tokens")
	}

	if nextJSCtx([]byte("   "), jsCtxDivOp) != jsCtxDivOp {
		t.Error("Blank tokens")
	}
}

type jsonErrType struct{}

func (e *jsonErrType) MarshalJSON() ([]byte, error) {
	return nil, errors.New("a */ b <script c </script d <!-- e <sCrIpT f </sCrIpT")
}

func TestJSValEscaper(t *testing.T) {
	tests := []struct {
		x        any
		js       string
		skipNest bool
	}{
		{int(42), " 42 ", false},
		{uint(42), " 42 ", false},
		{int16(42), " 42 ", false},
		{uint16(42), " 42 ", false},
		{int32(-42), " -42 ", false},
		{uint32(42), " 42 ", false},
		{int16(-42), " -42 ", false},
		{uint16(42), " 42 ", false},
		{int64(-42), " -42 ", false},
		{uint64(42), " 42 ", false},
		{uint64(1) << 53, " 9007199254740992 ", false},
		// ulp(1 << 53) > 1 so this loses precision in JS
		// but it is still a representable integer literal.
		{uint64(1)<<53 + 1, " 9007199254740993 ", false},
		{float32(1.0), " 1 ", false},
		{float32(-1.0), " -1 ", false},
		{float32(0.5), " 0.5 ", false},
		{float32(-0.5), " -0.5 ", false},
		{float32(1.0) / float32(256), " 0.00390625 ", false},
		{float32(0), " 0 ", false},
		{math.Copysign(0, -1), " -0 ", false},
		{float64(1.0), " 1 ", false},
		{float64(-1.0), " -1 ", false},
		{float64(0.5), " 0.5 ", false},
		{float64(-0.5), " -0.5 ", false},
		{float64(0), " 0 ", false},
		{math.Copysign(0, -1), " -0 ", false},
		{"", `""`, false},
		{"foo", `"foo"`, false},
		// Newlines.
		{"\r\n\u2028\u2029", `"\r\n\u2028\u2029"`, false},
		// "\v" == "v" on IE 6 so use "\u000b" instead.
		{"\t\x0b", `"\t\u000b"`, false},
		{struct{ X, Y int }{1, 2}, `{"X":1,"Y":2}`, false},
		{[]any{}, "[]", false},
		{[]any{42, "foo", nil}, `[42,"foo",null]`, false},
		{[]string{"<!--", "</script>", "-->"}, `["\u003c!--","\u003c/script\u003e","--\u003e"]`, false},
		{"<!--", `"\u003c!--"`, false},
		{"-->", `"--\u003e"`, false},
		{"<![CDATA[", `"\u003c![CDATA["`, false},
		{"]]>", `"]]\u003e"`, false},
		{"</script", `"\u003c/script"`, false},
		{"\U0001D11E", "\"\U0001D11E\"", false}, // or "\uD834\uDD1E"
		{nil, " null ", false},
		{&jsonErrType{}, " /* json: error calling MarshalJSON for type *template.jsonErrType: a * / b \\x3Cscript c \\x3C/script d \\x3C!-- e \\x3Cscript f \\x3C/script */null ", true},
	}

	for _, test := range tests {
		if js := jsValEscaper(test.x); js != test.js {
			t.Errorf("%+v: want\n\t%q\ngot\n\t%q", test.x, test.js, js)
		}
		if test.skipNest {
			continue
		}
		// Make sure that escaping corner cases are not broken
		// by nesting.
		a := []any{test.x}
		want := "[" + strings.TrimSpace(test.js) + "]"
		if js := jsValEscaper(a); js != want {
			t.Errorf("%+v: want\n\t%q\ngot\n\t%q", a, want, js)
		}
	}
}

func TestJSStrEscaper(t *testing.T) {
	tests := []struct {
		x   any
		esc string
	}{
		{"", ``},
		{"foo", `foo`},
		{"\u0000", `\u0000`},
		{"\t", `\t`},
		{"\n", `\n`},
		{"\r", `\r`},
		{"\u2028", `\u2028`},
		{"\u2029", `\u2029`},
		{"\\", `\\`},
		{"\\n", `\\n`},
		{"foo\r\nbar", `foo\r\nbar`},
		// Preserve attribute boundaries.
		{`"`, `\u0022`},
		{`'`, `\u0027`},
		// Allow embedding in HTML without further escaping.
		{`&amp;`, `\u0026amp;`},
		// Prevent breaking out of text node and element boundaries.
		{"</script>", `\u003c\/script\u003e`},
		{"<![CDATA[", `\u003c![CDATA[`},
		{"]]>", `]]\u003e`},
		// https://dev.w3.org/html5/markup/aria/syntax.html#escaping-text-span
		//   "The text in style, script, title, and textarea elements
		//   must not have an escaping text span start that is not
		//   followed by an escaping text span end."
		// Furthermore, spoofing an escaping text span end could lead
		// to different interpretation of a </script> sequence otherwise
		// masked by the escaping text span, and spoofing a start could
		// allow regular text content to be interpreted as script
		// allowing script execution via a combination of a JS string
		// injection followed by an HTML text injection.
		{"<!--", `\u003c!--`},
		{"-->", `--\u003e`},
		// From https://code.google.com/p/doctype/wiki/ArticleUtf7
		{"+ADw-script+AD4-alert(1)+ADw-/script+AD4-",
			`\u002bADw-script\u002bAD4-alert(1)\u002bADw-\/script\u002bAD4-`,
		},
		// Invalid UTF-8 sequence
		{"foo\xA0bar", "foo\xA0bar"},
		// Invalid unicode scalar value.
		{"foo\xed\xa0\x80bar", "foo\xed\xa0\x80bar"},
	}

	for _, test := range tests {
		esc := jsStrEscaper(test.x)
		if esc != test.esc {
			t.Errorf("%q: want %q got %q", test.x, test.esc, esc)
		}
	}
}

func TestJSRegexpEscaper(t *testing.T) {
	tests := []struct {
		x   any
		esc string
	}{
		{"", `(?:)`},
		{"foo", `foo`},
		{"\u0000", `\u0000`},
		{"\t", `\t`},
		{"\n", `\n`},
		{"\r", `\r`},
		{"\u2028", `\u2028`},
		{"\u2029", `\u2029`},
		{"\\", `\\`},
		{"\\n", `\\n`},
		{"foo\r\nbar", `foo\r\nbar`},
		// Preserve attribute boundaries.
		{`"`, `\u0022`},
		{`'`, `\u0027`},
		// Allow embedding in HTML without further escaping.
		{`&amp;`, `\u0026amp;`},
		// Prevent breaking out of text node and element boundaries.
		{"</script>", `\u003c\/script\u003e`},
		{"<![CDATA[", `\u003c!\[CDATA\[`},
		{"]]>", `\]\]\u003e`},
		// Escaping text spans.
		{"<!--", `\u003c!\-\-`},
		{"-->", `\-\-\u003e`},
		{"*", `\*`},
		{"+", `\u002b`},
		{"?", `\?`},
		{"[](){}", `\[\]\(\)\{\}`},
		{"$foo|x.y", `\$foo\|x\.y`},
		{"x^y", `x\^y`},
	}

	for _, test := range tests {
		esc := jsRegexpEscaper(test.x)
		if esc != test.esc {
			t.Errorf("%q: want %q got %q", test.x, test.esc, esc)
		}
	}
}

func TestEscapersOnLower7AndSelectHighCodepoints(t *testing.T) {
	input := ("\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f" +
		"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f" +
		` !"#$%&'()*+,-./` +
		`0123456789:;<=>?` +
		`@ABCDEFGHIJKLMNO` +
		`PQRSTUVWXYZ[\]^_` +
		"`abcdefghijklmno" +
		"pqrstuvwxyz{|}~\x7f" +
		"\u00A0\u0100\u2028\u2029\ufeff\U0001D11E")

	tests := []struct {
		name    string
		escaper func(...any) string
		escaped string
	}{
		{
			"jsStrEscaper",
			jsStrEscaper,
			`\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007` +
				`\u0008\t\n\u000b\f\r\u000e\u000f` +
				`\u0010\u0011\u0012\u0013\u0014\u0015\u0016\u0017` +
				`\u0018\u0019\u001a\u001b\u001c\u001d\u001e\u001f` +
				` !\u0022#$%\u0026\u0027()*\u002b,-.\/` +
				`0123456789:;\u003c=\u003e?` +
				`@ABCDEFGHIJKLMNO` +
				`PQRSTUVWXYZ[\\]^_` +
				"\\u0060abcdefghijklmno" +
				"pqrstuvwxyz{|}~\u007f" +
				"\u00A0\u0100\\u2028\\u2029\ufeff\U0001D11E",
		},
		{
			"jsRegexpEscaper",
			jsRegexpEscaper,
			`\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007` +
				`\u0008\t\n\u000b\f\r\u000e\u000f` +
				`\u0010\u0011\u0012\u0013\u0014\u0015\u0016\u0017` +
				`\u0018\u0019\u001a\u001b\u001c\u001d\u001e\u001f` +
				` !\u0022#\$%\u0026\u0027\(\)\*\u002b,\-\.\/` +
				`0123456789:;\u003c=\u003e\?` +
				`@ABCDEFGHIJKLMNO` +
				`PQRSTUVWXYZ\[\\\]\^_` +
				"`abcdefghijklmno" +
				`pqrstuvwxyz\{\|\}~` + "\u007f" +
				"\u00A0\u0100\\u2028\\u2029\ufeff\U0001D11E",
		},
	}

	for _, test := range tests {
		if s := test.escaper(input); s != test.escaped {
			t.Errorf("%s once: want\n\t%q\ngot\n\t%q", test.name, test.escaped, s)
			continue
		}

		// Escape it rune by rune to make sure that any
		// fast-path checking does not break escaping.
		var buf strings.Builder
		for _, c := range input {
			buf.WriteString(test.escaper(string(c)))
		}

		if s := buf.String(); s != test.escaped {
			t.Errorf("%s rune-wise: want\n\t%q\ngot\n\t%q", test.name, test.escaped, s)
			continue
		}
	}
}

func TestIsJsMimeType(t *testing.T) {
	tests := []struct {
		in  string
		out bool
	}{
		{"application/javascript;version=1.8", true},
		{"application/javascript;version=1.8;foo=bar", true},
		{"application/javascript/version=1.8", false},
		{"text/javascript", true},
		{"application/json", true},
		{"application/ld+json", true},
		{"module", true},
	}

	for _, test := range tests {
		if isJSType(test.in) != test.out {
			t.Errorf("isJSType(%q) = %v, want %v", test.in, !test.out, test.out)
		}
	}
}

func BenchmarkJSValEscaperWithNum(b *testing.B) {
	for i := 0; i < b.N; i++ {
		jsValEscaper(3.141592654)
	}
}

func BenchmarkJSValEscaperWithStr(b *testing.B) {
	for i := 0; i < b.N; i++ {
		jsValEscaper("The <i>quick</i>,\r\n<span style='color:brown'>brown</span> fox jumps\u2028over the <canine class=\"lazy\">dog</canine>")
	}
}

func BenchmarkJSValEscaperWithStrNoSpecials(b *testing.B) {
	for i := 0; i < b.N; i++ {
		jsValEscaper("The quick, brown fox jumps over the lazy dog")
	}
}

func BenchmarkJSValEscaperWithObj(b *testing.B) {
	o := struct {
		S string
		N int
	}{
		"The <i>quick</i>,\r\n<span style='color:brown'>brown</span> fox jumps\u2028over the <canine class=\"lazy\">dog</canine>\u2028",
		42,
	}
	for i := 0; i < b.N; i++ {
		jsValEscaper(o)
	}
}

func BenchmarkJSValEscaperWithObjNoSpecials(b *testing.B) {
	o := struct {
		S string
		N int
	}{
		"The quick, brown fox jumps over the lazy dog",
		42,
	}
	for i := 0; i < b.N; i++ {
		jsValEscaper(o)
	}
}

func BenchmarkJSStrEscaperNoSpecials(b *testing.B) {
	for i := 0; i < b.N; i++ {
		jsStrEscaper("The quick, brown fox jumps over the lazy dog.")
	}
}

func BenchmarkJSStrEscaper(b *testing.B) {
	for i := 0; i < b.N; i++ {
		jsStrEscaper("The <i>quick</i>,\r\n<span style='color:brown'>brown</span> fox jumps\u2028over the <canine class=\"lazy\">dog</canine>")
	}
}

func BenchmarkJSRegexpEscaperNoSpecials(b *testing.B) {
	for i := 0; i < b.N; i++ {
		jsRegexpEscaper("The quick, brown fox jumps over the lazy dog")
	}
}

func BenchmarkJSRegexpEscaper(b *testing.B) {
	for i := 0; i < b.N; i++ {
		jsRegexpEscaper("The <i>quick</i>,\r\n<span style='color:brown'>brown</span> fox jumps\u2028over the <canine class=\"lazy\">dog</canine>")
	}
}
```