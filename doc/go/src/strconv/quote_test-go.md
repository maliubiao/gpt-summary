Response:
我的目标是对给定的 Go 语言测试代码 `quote_test.go` 进行分析，并以中文回答其功能、相关 Go 语言特性的实现方式（带代码示例）、代码推理（带假设的输入输出）、命令行参数处理（如果涉及）、以及使用者易犯的错误。

**1. 理解代码结构和目标：**

首先，我浏览了代码，发现它是一个测试文件，用于测试 `strconv` 包中与字符串和 rune 相关的 quote 和 unquote 功能。  重点关注了以 `Test` 和 `Benchmark` 开头的函数，以及全局变量 `quotetests`, `quoterunetests`, `canbackquotetests`, `unquotetests`, `misquoted`。这些变量存储了测试用例。

**2. 识别核心功能：**

仔细分析测试用例，我发现该文件主要测试以下功能：

* **Quote:** 将字符串或 rune 转换为带引号的表示形式，处理特殊字符的转义。
* **QuoteToASCII:** 将字符串或 rune 转换为 ASCII 表示形式，非 ASCII 字符会被转义为 `\u` 或 `\U` 形式。
* **QuoteToGraphic:**  将字符串或 rune 转换为 Graphic 表示形式。
* **CanBackquote:** 判断字符串是否可以使用反引号包围。
* **Unquote:** 将带引号的字符串或 rune 表示形式还原为原始字符串或 rune。
* **QuotedPrefix:** 提取字符串的带引号的前缀。
* **IsPrint 和 IsGraphic:** 验证自定义的 `IsPrint` 和 `IsGraphic` 函数是否与 `unicode` 包中的对应函数行为一致。

**3. 推理 Go 语言特性的实现方式：**

* **字符串和 Rune 的处理:** `strconv` 包提供了处理字符串和 rune 的函数，例如 `Quote`, `QuoteRune`, `Unquote` 等。测试代码中使用了这些函数。
* **Unicode 支持:** Go 语言原生支持 Unicode，`strconv` 包的这些函数也考虑了 Unicode 字符的处理，例如 `\u` 和 `\U` 转义序列。
* **测试框架:** 代码使用了 `testing` 包进行单元测试，通过 `t.Errorf` 报告错误。
* **Benchmark:** 代码使用了 `testing` 包进行性能基准测试，通过 `b.N` 进行迭代。

**4. 设计代码示例：**

针对每个核心功能，我构思了简单的 Go 代码示例，并考虑了输入和预期的输出。

**5. 考虑命令行参数处理：**

快速浏览代码，没有发现直接处理命令行参数的部分。`go test` 命令本身有一些参数，但测试代码本身没有涉及。

**6. 思考使用者易犯的错误：**

主要考虑了 `Unquote` 函数可能遇到的错误，例如不匹配的引号、无效的转义序列等。

**7. 组织答案：**

最后，我将以上分析结果组织成中文回答，力求清晰、准确、全面。  我使用了列表来枚举功能，并为代码示例和错误示例使用了代码块。

**反思和优化:**

在组织答案的过程中，我思考了如何更清晰地解释 `QuoteToGraphic` 的作用，并对比了它与 `Quote` 和 `QuoteToASCII` 的区别。 我也确保了代码示例简洁易懂，并包含了必要的注释。  对于使用者易犯的错误，我使用了具体的 `misquoted` 变量中的例子进行说明。
这个 Go 语言代码文件 `quote_test.go` 是 `strconv` 包的一部分，专门用于测试 `strconv` 包中与字符串和 rune 的引用（quoting）和反引用（unquoting）相关的函数。

**主要功能列举:**

1. **测试 `IsPrint` 函数:** 验证 `strconv` 包中的 `IsPrint` 函数是否与 `unicode` 包中的 `IsPrint` 函数行为一致。`IsPrint` 函数用于判断给定的 rune 是否为可打印字符。
2. **测试 `IsGraphic` 函数:** 验证 `strconv` 包中的 `IsGraphic` 函数是否与 `unicode` 包中的 `IsGraphic` 函数行为一致。`IsGraphic` 函数用于判断给定的 rune 是否为图形字符。
3. **测试 `Quote` 函数:** 测试将字符串转换为带双引号的表示形式，并对特殊字符进行转义。
4. **测试 `AppendQuote` 函数:** 测试将字符串添加到 byte slice 中，并用双引号括起来，对特殊字符进行转义。
5. **测试 `QuoteToASCII` 函数:** 测试将字符串转换为 ASCII 表示形式，非 ASCII 字符会被转义为 `\u` 或 `\U` 形式。
6. **测试 `AppendQuoteToASCII` 函数:** 测试将字符串添加到 byte slice 中，并转换为 ASCII 表示形式，非 ASCII 字符会被转义。
7. **测试 `QuoteToGraphic` 函数:** 测试将字符串转换为图形字符表示形式，与 `Quote` 类似，但可能在某些不可打印但属于图形字符的 rune 上有所不同。
8. **测试 `AppendQuoteToGraphic` 函数:** 测试将字符串添加到 byte slice 中，并转换为图形字符表示形式。
9. **性能基准测试 `BenchmarkQuote` 和 `BenchmarkAppendQuote`:** 评估 `Quote` 和 `AppendQuote` 函数的性能。
10. **测试 `QuoteRune` 函数:** 测试将 rune 转换为带单引号的表示形式，并对特殊字符进行转义。
11. **测试 `AppendQuoteRune` 函数:** 测试将 rune 添加到 byte slice 中，并用单引号括起来，对特殊字符进行转义。
12. **测试 `QuoteRuneToASCII` 函数:** 测试将 rune 转换为 ASCII 表示形式，非 ASCII 字符会被转义为 `\u` 或 `\U` 形式。
13. **测试 `AppendQuoteRuneToASCII` 函数:** 测试将 rune 添加到 byte slice 中，并转换为 ASCII 表示形式，非 ASCII 字符会被转义。
14. **测试 `QuoteRuneToGraphic` 函数:** 测试将 rune 转换为图形字符表示形式。
15. **测试 `AppendQuoteRuneToGraphic` 函数:** 测试将 rune 添加到 byte slice 中，并转换为图形字符表示形式。
16. **测试 `CanBackquote` 函数:** 测试判断给定的字符串是否可以使用反引号（`）括起来而无需转义。
17. **测试 `Unquote` 函数:** 测试将带引号（单引号、双引号或反引号）的字符串反引用为原始字符串。
18. **测试 `QuotedPrefix` 函数:** 测试提取字符串中带引号的前缀部分。
19. **性能基准测试 `BenchmarkUnquoteEasy` 和 `BenchmarkUnquoteHard`:** 评估 `Unquote` 函数在不同情况下的性能。

**Go 语言功能的实现推理和代码示例:**

这个测试文件主要测试了 `strconv` 包中处理字符串和 rune 的引用和反引用功能。这些功能在很多场景下非常有用，例如生成代码、序列化数据等。

**`Quote` 函数的实现 (推测):**

假设 `Quote` 函数的实现原理大致如下：它会遍历输入字符串的每个 rune，如果 rune 是特殊字符（如换行符、制表符、双引号等），则会将其转义为相应的转义序列（如 `\n`、`\t`、`\"`）。如果 rune 是非 ASCII 字符，可能会根据需要转义为 `\u` 或 `\U` 形式。最后，将处理后的字符串用双引号括起来。

```go
package main

import (
	"fmt"
	"strconv"
)

func main() {
	input := "Hello\nWorld!\""
	quoted := strconv.Quote(input)
	fmt.Println(quoted) // 输出: "Hello\nWorld!\""

	inputRune := '©'
	quotedRune := strconv.QuoteRune(inputRune)
	fmt.Println(quotedRune) // 输出: '©'
}
```

**假设的输入与输出:**

* **`Quote("Hello\tWorld!")`:** 输出 `"Hello\\tWorld!"` (假设 `\t` 被转义为 `\\t`)  *实际上 `\t` 会被转义成 `\t`，`\` 本身才会被转义成 `\\`*
* **`QuoteRune('\n')`:** 输出 `'\n'`

**`Unquote` 函数的实现 (推测):**

`Unquote` 函数的功能与 `Quote` 相反。它会移除字符串两端的引号，并解析其中的转义序列，将其还原为原始字符。

```go
package main

import (
	"fmt"
	"strconv"
)

func main() {
	quoted := "\"Hello\\nWorld!\\\"\""
	unquoted, err := strconv.Unquote(quoted)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println(unquoted) // 输出: Hello
                         //      World!"

	quotedRune := "'©'"
	unquotedRune, err := strconv.Unquote(quotedRune)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println(unquotedRune) // 输出: ©
}
```

**假设的输入与输出:**

* **`Unquote("\"Hello\\nWorld!\"")`:** 输出 `Hello\nWorld!`
* **`Unquote("'\\t'")`:** 输出 `\t`

**命令行参数的具体处理:**

这段代码本身是一个测试文件，它不是一个可执行程序，因此不涉及命令行参数的具体处理。它的目的是被 `go test` 命令执行，`go test` 命令本身有一些参数，但这个文件内部没有解析这些参数的逻辑。

**使用者易犯错的点:**

1. **`Unquote` 的输入格式错误:** `Unquote` 函数要求输入的字符串必须是被正确引号包围的，并且转义序列也必须正确。如果输入不符合规范，`Unquote` 会返回错误。

   ```go
   package main

   import (
       "fmt"
       "strconv"
   )

   func main() {
       // 缺少 closing quote
       badQuoted := "\"hello"
       _, err := strconv.Unquote(badQuoted)
       if err != nil {
           fmt.Println("Error:", err) // 输出: Error: strconv.Unquote: syntax error
       }

       // 无效的转义序列
       badEscape := "\"\\z\""
       _, err = strconv.Unquote(badEscape)
       if err != nil {
           fmt.Println("Error:", err) // 输出: Error: strconv.Unquote: invalid syntax
       }
   }
   ```

2. **混淆不同类型的引用:** `Quote` 和 `AppendQuote` 使用双引号，`QuoteRune` 和 `AppendQuoteRune` 使用单引号。`Unquote` 可以处理这三种引号，但需要注意匹配。

3. **理解 `QuoteToASCII` 和 `QuoteToGraphic` 的区别:** `QuoteToASCII` 倾向于将非 ASCII 字符转义为 `\u` 或 `\U` 形式，确保输出是纯 ASCII 的。`QuoteToGraphic` 则更注重保留图形字符的原貌，即使它们不是 ASCII 字符。使用者需要根据具体需求选择合适的函数。

总而言之，`go/src/strconv/quote_test.go` 这个文件通过大量的测试用例，细致地验证了 `strconv` 包中与字符串和 rune 的引用和反引用功能是否正确可靠。 这对于确保 `strconv` 包在处理字符串表示时的准确性至关重要。

### 提示词
```
这是路径为go/src/strconv/quote_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package strconv_test

import (
	. "strconv"
	"strings"
	"testing"
	"unicode"
)

// Verify that our IsPrint agrees with unicode.IsPrint.
func TestIsPrint(t *testing.T) {
	n := 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if IsPrint(r) != unicode.IsPrint(r) {
			t.Errorf("IsPrint(%U)=%t incorrect", r, IsPrint(r))
			n++
			if n > 10 {
				return
			}
		}
	}
}

// Verify that our IsGraphic agrees with unicode.IsGraphic.
func TestIsGraphic(t *testing.T) {
	n := 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if IsGraphic(r) != unicode.IsGraphic(r) {
			t.Errorf("IsGraphic(%U)=%t incorrect", r, IsGraphic(r))
			n++
			if n > 10 {
				return
			}
		}
	}
}

type quoteTest struct {
	in      string
	out     string
	ascii   string
	graphic string
}

var quotetests = []quoteTest{
	{"\a\b\f\r\n\t\v", `"\a\b\f\r\n\t\v"`, `"\a\b\f\r\n\t\v"`, `"\a\b\f\r\n\t\v"`},
	{"\\", `"\\"`, `"\\"`, `"\\"`},
	{"abc\xffdef", `"abc\xffdef"`, `"abc\xffdef"`, `"abc\xffdef"`},
	{"\u263a", `"☺"`, `"\u263a"`, `"☺"`},
	{"\U0010ffff", `"\U0010ffff"`, `"\U0010ffff"`, `"\U0010ffff"`},
	{"\x04", `"\x04"`, `"\x04"`, `"\x04"`},
	// Some non-printable but graphic runes. Final column is double-quoted.
	{"!\u00a0!\u2000!\u3000!", `"!\u00a0!\u2000!\u3000!"`, `"!\u00a0!\u2000!\u3000!"`, "\"!\u00a0!\u2000!\u3000!\""},
	{"\x7f", `"\x7f"`, `"\x7f"`, `"\x7f"`},
}

func TestQuote(t *testing.T) {
	for _, tt := range quotetests {
		if out := Quote(tt.in); out != tt.out {
			t.Errorf("Quote(%s) = %s, want %s", tt.in, out, tt.out)
		}
		if out := AppendQuote([]byte("abc"), tt.in); string(out) != "abc"+tt.out {
			t.Errorf("AppendQuote(%q, %s) = %s, want %s", "abc", tt.in, out, "abc"+tt.out)
		}
	}
}

func TestQuoteToASCII(t *testing.T) {
	for _, tt := range quotetests {
		if out := QuoteToASCII(tt.in); out != tt.ascii {
			t.Errorf("QuoteToASCII(%s) = %s, want %s", tt.in, out, tt.ascii)
		}
		if out := AppendQuoteToASCII([]byte("abc"), tt.in); string(out) != "abc"+tt.ascii {
			t.Errorf("AppendQuoteToASCII(%q, %s) = %s, want %s", "abc", tt.in, out, "abc"+tt.ascii)
		}
	}
}

func TestQuoteToGraphic(t *testing.T) {
	for _, tt := range quotetests {
		if out := QuoteToGraphic(tt.in); out != tt.graphic {
			t.Errorf("QuoteToGraphic(%s) = %s, want %s", tt.in, out, tt.graphic)
		}
		if out := AppendQuoteToGraphic([]byte("abc"), tt.in); string(out) != "abc"+tt.graphic {
			t.Errorf("AppendQuoteToGraphic(%q, %s) = %s, want %s", "abc", tt.in, out, "abc"+tt.graphic)
		}
	}
}

func BenchmarkQuote(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Quote("\a\b\f\r\n\t\v\a\b\f\r\n\t\v\a\b\f\r\n\t\v")
	}
}

func BenchmarkQuoteRune(b *testing.B) {
	for i := 0; i < b.N; i++ {
		QuoteRune('\a')
	}
}

var benchQuoteBuf []byte

func BenchmarkAppendQuote(b *testing.B) {
	for i := 0; i < b.N; i++ {
		benchQuoteBuf = AppendQuote(benchQuoteBuf[:0], "\a\b\f\r\n\t\v\a\b\f\r\n\t\v\a\b\f\r\n\t\v")
	}
}

var benchQuoteRuneBuf []byte

func BenchmarkAppendQuoteRune(b *testing.B) {
	for i := 0; i < b.N; i++ {
		benchQuoteRuneBuf = AppendQuoteRune(benchQuoteRuneBuf[:0], '\a')
	}
}

type quoteRuneTest struct {
	in      rune
	out     string
	ascii   string
	graphic string
}

var quoterunetests = []quoteRuneTest{
	{'a', `'a'`, `'a'`, `'a'`},
	{'\a', `'\a'`, `'\a'`, `'\a'`},
	{'\\', `'\\'`, `'\\'`, `'\\'`},
	{0xFF, `'ÿ'`, `'\u00ff'`, `'ÿ'`},
	{0x263a, `'☺'`, `'\u263a'`, `'☺'`},
	{0xdead, `'�'`, `'\ufffd'`, `'�'`},
	{0xfffd, `'�'`, `'\ufffd'`, `'�'`},
	{0x0010ffff, `'\U0010ffff'`, `'\U0010ffff'`, `'\U0010ffff'`},
	{0x0010ffff + 1, `'�'`, `'\ufffd'`, `'�'`},
	{0x04, `'\x04'`, `'\x04'`, `'\x04'`},
	// Some differences between graphic and printable. Note the last column is double-quoted.
	{'\u00a0', `'\u00a0'`, `'\u00a0'`, "'\u00a0'"},
	{'\u2000', `'\u2000'`, `'\u2000'`, "'\u2000'"},
	{'\u3000', `'\u3000'`, `'\u3000'`, "'\u3000'"},
}

func TestQuoteRune(t *testing.T) {
	for _, tt := range quoterunetests {
		if out := QuoteRune(tt.in); out != tt.out {
			t.Errorf("QuoteRune(%U) = %s, want %s", tt.in, out, tt.out)
		}
		if out := AppendQuoteRune([]byte("abc"), tt.in); string(out) != "abc"+tt.out {
			t.Errorf("AppendQuoteRune(%q, %U) = %s, want %s", "abc", tt.in, out, "abc"+tt.out)
		}
	}
}

func TestQuoteRuneToASCII(t *testing.T) {
	for _, tt := range quoterunetests {
		if out := QuoteRuneToASCII(tt.in); out != tt.ascii {
			t.Errorf("QuoteRuneToASCII(%U) = %s, want %s", tt.in, out, tt.ascii)
		}
		if out := AppendQuoteRuneToASCII([]byte("abc"), tt.in); string(out) != "abc"+tt.ascii {
			t.Errorf("AppendQuoteRuneToASCII(%q, %U) = %s, want %s", "abc", tt.in, out, "abc"+tt.ascii)
		}
	}
}

func TestQuoteRuneToGraphic(t *testing.T) {
	for _, tt := range quoterunetests {
		if out := QuoteRuneToGraphic(tt.in); out != tt.graphic {
			t.Errorf("QuoteRuneToGraphic(%U) = %s, want %s", tt.in, out, tt.graphic)
		}
		if out := AppendQuoteRuneToGraphic([]byte("abc"), tt.in); string(out) != "abc"+tt.graphic {
			t.Errorf("AppendQuoteRuneToGraphic(%q, %U) = %s, want %s", "abc", tt.in, out, "abc"+tt.graphic)
		}
	}
}

type canBackquoteTest struct {
	in  string
	out bool
}

var canbackquotetests = []canBackquoteTest{
	{"`", false},
	{string(rune(0)), false},
	{string(rune(1)), false},
	{string(rune(2)), false},
	{string(rune(3)), false},
	{string(rune(4)), false},
	{string(rune(5)), false},
	{string(rune(6)), false},
	{string(rune(7)), false},
	{string(rune(8)), false},
	{string(rune(9)), true}, // \t
	{string(rune(10)), false},
	{string(rune(11)), false},
	{string(rune(12)), false},
	{string(rune(13)), false},
	{string(rune(14)), false},
	{string(rune(15)), false},
	{string(rune(16)), false},
	{string(rune(17)), false},
	{string(rune(18)), false},
	{string(rune(19)), false},
	{string(rune(20)), false},
	{string(rune(21)), false},
	{string(rune(22)), false},
	{string(rune(23)), false},
	{string(rune(24)), false},
	{string(rune(25)), false},
	{string(rune(26)), false},
	{string(rune(27)), false},
	{string(rune(28)), false},
	{string(rune(29)), false},
	{string(rune(30)), false},
	{string(rune(31)), false},
	{string(rune(0x7F)), false},
	{`' !"#$%&'()*+,-./:;<=>?@[\]^_{|}~`, true},
	{`0123456789`, true},
	{`ABCDEFGHIJKLMNOPQRSTUVWXYZ`, true},
	{`abcdefghijklmnopqrstuvwxyz`, true},
	{`☺`, true},
	{"\x80", false},
	{"a\xe0\xa0z", false},
	{"\ufeffabc", false},
	{"a\ufeffz", false},
}

func TestCanBackquote(t *testing.T) {
	for _, tt := range canbackquotetests {
		if out := CanBackquote(tt.in); out != tt.out {
			t.Errorf("CanBackquote(%q) = %v, want %v", tt.in, out, tt.out)
		}
	}
}

type unQuoteTest struct {
	in  string
	out string
}

var unquotetests = []unQuoteTest{
	{`""`, ""},
	{`"a"`, "a"},
	{`"abc"`, "abc"},
	{`"☺"`, "☺"},
	{`"hello world"`, "hello world"},
	{`"\xFF"`, "\xFF"},
	{`"\377"`, "\377"},
	{`"\u1234"`, "\u1234"},
	{`"\U00010111"`, "\U00010111"},
	{`"\U0001011111"`, "\U0001011111"},
	{`"\a\b\f\n\r\t\v\\\""`, "\a\b\f\n\r\t\v\\\""},
	{`"'"`, "'"},

	{`'a'`, "a"},
	{`'☹'`, "☹"},
	{`'\a'`, "\a"},
	{`'\x10'`, "\x10"},
	{`'\377'`, "\377"},
	{`'\u1234'`, "\u1234"},
	{`'\U00010111'`, "\U00010111"},
	{`'\t'`, "\t"},
	{`' '`, " "},
	{`'\''`, "'"},
	{`'"'`, "\""},

	{"``", ``},
	{"`a`", `a`},
	{"`abc`", `abc`},
	{"`☺`", `☺`},
	{"`hello world`", `hello world`},
	{"`\\xFF`", `\xFF`},
	{"`\\377`", `\377`},
	{"`\\`", `\`},
	{"`\n`", "\n"},
	{"`	`", `	`},
	{"` `", ` `},
	{"`a\rb`", "ab"},
}

var misquoted = []string{
	``,
	`"`,
	`"a`,
	`"'`,
	`b"`,
	`"\"`,
	`"\9"`,
	`"\19"`,
	`"\129"`,
	`'\'`,
	`'\9'`,
	`'\19'`,
	`'\129'`,
	`'ab'`,
	`"\x1!"`,
	`"\U12345678"`,
	`"\z"`,
	"`",
	"`xxx",
	"``x\r",
	"`\"",
	`"\'"`,
	`'\"'`,
	"\"\n\"",
	"\"\\n\n\"",
	"'\n'",
	`"\udead"`,
	`"\ud83d\ude4f"`,
}

func TestUnquote(t *testing.T) {
	for _, tt := range unquotetests {
		testUnquote(t, tt.in, tt.out, nil)
	}
	for _, tt := range quotetests {
		testUnquote(t, tt.out, tt.in, nil)
	}
	for _, s := range misquoted {
		testUnquote(t, s, "", ErrSyntax)
	}
}

// Issue 23685: invalid UTF-8 should not go through the fast path.
func TestUnquoteInvalidUTF8(t *testing.T) {
	tests := []struct {
		in string

		// one of:
		want    string
		wantErr error
	}{
		{in: `"foo"`, want: "foo"},
		{in: `"foo`, wantErr: ErrSyntax},
		{in: `"` + "\xc0" + `"`, want: "\xef\xbf\xbd"},
		{in: `"a` + "\xc0" + `"`, want: "a\xef\xbf\xbd"},
		{in: `"\t` + "\xc0" + `"`, want: "\t\xef\xbf\xbd"},
	}
	for _, tt := range tests {
		testUnquote(t, tt.in, tt.want, tt.wantErr)
	}
}

func testUnquote(t *testing.T, in, want string, wantErr error) {
	// Test Unquote.
	got, gotErr := Unquote(in)
	if got != want || gotErr != wantErr {
		t.Errorf("Unquote(%q) = (%q, %v), want (%q, %v)", in, got, gotErr, want, wantErr)
	}

	// Test QuotedPrefix.
	// Adding an arbitrary suffix should not change the result of QuotedPrefix
	// assume that the suffix doesn't accidentally terminate a truncated input.
	if gotErr == nil {
		want = in
	}
	suffix := "\n\r\\\"`'" // special characters for quoted strings
	if len(in) > 0 {
		suffix = strings.ReplaceAll(suffix, in[:1], "")
	}
	in += suffix
	got, gotErr = QuotedPrefix(in)
	if gotErr == nil && wantErr != nil {
		_, wantErr = Unquote(got) // original input had trailing junk, reparse with only valid prefix
		want = got
	}
	if got != want || gotErr != wantErr {
		t.Errorf("QuotedPrefix(%q) = (%q, %v), want (%q, %v)", in, got, gotErr, want, wantErr)
	}
}

func BenchmarkUnquoteEasy(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Unquote(`"Give me a rock, paper and scissors and I will move the world."`)
	}
}

func BenchmarkUnquoteHard(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Unquote(`"\x47ive me a \x72ock, \x70aper and \x73cissors and \x49 will move the world."`)
	}
}
```