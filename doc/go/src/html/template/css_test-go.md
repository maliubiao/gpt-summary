Response:
Let's break down the thought process for analyzing this Go code and generating the detailed Chinese response.

**1. Understanding the Goal:**

The core request is to analyze a Go test file (`css_test.go`) and describe its functionalities, explain the underlying Go features it tests, provide examples, and highlight potential pitfalls. The target audience is assumed to be someone familiar with basic Go syntax but potentially less so with the specifics of the `html/template` package and CSS escaping/filtering.

**2. Initial Code Scan and Functional Breakdown:**

My first step is to quickly read through the code and identify the main testing functions. I see several `Test...` functions, which immediately tells me this is a unit test file. I then look at the names of these functions:

* `TestEndsWithCSSKeyword`:  This suggests it's testing a function that checks if a string ends with a specific CSS keyword.
* `TestIsCSSNmchar`: This likely tests a function that determines if a rune (Go's representation of a character) is a valid CSS name character.
* `TestDecodeCSS`:  This tests a function that decodes CSS escape sequences.
* `TestHexDecode`:  This tests a function that decodes hexadecimal representations.
* `TestSkipCSSSpace`: This tests a function that skips whitespace in a CSS string.
* `TestCSSEscaper`:  This tests a function that escapes characters in a string for use in CSS.
* `TestCSSValueFilter`: This tests a function that filters potentially unsafe CSS values.

I also notice `Benchmark...` functions, which indicate performance testing (benchmarking) of some of these functions.

**3. Deeper Dive into Each Test Function:**

For each `Test...` function, I examine the test cases defined within the `tests` slice. This gives me concrete examples of the input and expected output, which is crucial for understanding the function's behavior.

* **`TestEndsWithCSSKeyword`:** The test cases clearly show it's checking if a CSS string ends with a given keyword, case-insensitively, and considers word boundaries (e.g., "image url" ending with "url" but not "imageurl").

* **`TestIsCSSNmchar`:** The test cases demonstrate the rules for valid CSS name characters, including letters, digits, '-', '_', and certain Unicode ranges.

* **`TestDecodeCSS`:**  The test cases showcase various CSS escape sequences and their decoded equivalents, including hexadecimal escapes, special character escapes, and edge cases. The self-consistency check (`recoded := cssEscaper(got1); ...`) is also important, indicating a test for the reversibility of escaping and decoding.

* **`TestHexDecode`:** This test iterates through a large range of numbers, converts them to hex, and verifies the `hexDecode` function can correctly convert them back.

* **`TestSkipCSSSpace`:** This tests the skipping of various whitespace characters.

* **`TestCSSEscaper`:**  This test uses a long input string with various special characters and checks if the `cssEscaper` function produces the correct escaped output. It also tests the decoding of the escaped output to ensure reversibility.

* **`TestCSSValueFilter`:** This test covers a wide range of CSS values, including valid ones and potentially dangerous ones (like `expression(...)`). The expected output `ZgotmplZ` strongly suggests a sanitization or replacement mechanism for unsafe values.

**4. Identifying Go Language Features:**

Based on the code and my understanding of Go, I can identify the following features being utilized:

* **`testing` package:**  The foundation of the test file.
* **Structs:** Used to define the test cases.
* **Slices:** Used to hold the test cases.
* **`for...range` loop:** Used to iterate through the test cases.
* **`t.Errorf()`:** Used for reporting test failures.
* **String and byte slice conversions:** Frequent conversions between `string` and `[]byte`.
* **String manipulation functions:**  Likely used within the tested functions (though not directly visible in the test code).
* **Runes:**  Used to represent individual Unicode characters.
* **Hexadecimal number conversion (`strconv.FormatInt`)**:  Used in `TestHexDecode`.

**5. Inferring the Purpose and Providing Examples:**

By understanding what each test function is doing, I can infer the purpose of the underlying Go functions. For example, `TestDecodeCSS` suggests there's a function to handle CSS unescaping. I then create Go code examples to demonstrate the usage of these inferred functions, making sure to include sample inputs and expected outputs.

**6. Addressing Command-Line Arguments and Common Mistakes:**

Since the provided code is a test file, it doesn't directly process command-line arguments. Therefore, I state that explicitly.

For common mistakes, I focus on the potential misunderstandings related to the CSS escaping and filtering functions, specifically highlighting the difference between escaping for syntax correctness and filtering for security.

**7. Structuring the Output (Chinese):**

Finally, I organize the information logically in Chinese, using clear headings and bullet points for readability. I translate technical terms accurately and explain concepts in a way that is easy to understand. I ensure all parts of the original request are addressed.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe `cssValueFilter` just escapes characters.
* **Correction:** The presence of `ZgotmplZ` strongly suggests *filtering* or *sanitization*, replacing dangerous parts rather than just escaping them. This realization is key to correctly explaining its purpose.

* **Initial thought:**  Focus heavily on the `template` package itself.
* **Refinement:**  While the file is in the `template` package, the core functionality being tested is more about CSS manipulation (escaping, decoding, filtering). It's important to emphasize these CSS-related aspects.

By following these steps, combining code analysis with knowledge of Go and web technologies, I arrive at the comprehensive Chinese explanation provided in the example answer.
这段代码是 Go 语言 `html/template` 包的一部分，专门用于测试与 CSS 相关的实用工具函数。它包含了多个测试函数，每个函数都针对一个特定的 CSS 处理功能进行测试。

以下是它包含的主要功能以及对应的 Go 语言特性示例：

**1. 测试 `endsWithCSSKeyword` 函数:**

   - **功能:**  判断一个字节切片表示的 CSS 字符串是否以指定的 CSS 关键字结尾（忽略大小写）。
   - **Go 语言特性:**  使用了 `testing` 包进行单元测试，定义了包含测试用例的结构体切片，并使用 `t.Errorf` 报告测试失败。
   - **代码推理与示例:**
     ```go
     package main

     import (
         "fmt"
         "strings"
     )

     // 假设这是 template 包中的 endsWithCSSKeyword 函数的简化版本
     func endsWithCSSKeyword(css []byte, kw string) bool {
         lowerCSS := strings.ToLower(string(css))
         lowerKW := strings.ToLower(kw)
         return strings.HasSuffix(lowerCSS, lowerKW)
     }

     func main() {
         fmt.Println(endsWithCSSKeyword([]byte("background-image: url(image.png)"), "url")) // 输出: true
         fmt.Println(endsWithCSSKeyword([]byte("BACKGROUND-IMAGE: URL(image.png)"), "url")) // 输出: true
         fmt.Println(endsWithCSSKeyword([]byte("background-image: url"), "important"))  // 输出: false
         fmt.Println(endsWithCSSKeyword([]byte("background-imageurl(image.png)"), "url")) // 输出: false
     }
     ```
   - **假设输入与输出:**
     - 输入: `css = []byte("background-image: url(image.png)")`, `kw = "url"`
     - 输出: `true`
     - 输入: `css = []byte("background-image: none")`, `kw = "url"`
     - 输出: `false`

**2. 测试 `isCSSNmchar` 函数:**

   - **功能:** 判断一个 Unicode 字符（rune）是否是合法的 CSS 标识符字符（name character）。这包括字母、数字、连字符、下划线以及某些 Unicode 字符。
   - **Go 语言特性:**  使用了 `rune` 类型来表示 Unicode 字符。
   - **代码推理与示例:**
     ```go
     package main

     import "fmt"

     // 假设这是 template 包中的 isCSSNmchar 函数的简化版本
     func isCSSNmchar(r rune) bool {
         return (r >= 'a' && r <= 'z') ||
                (r >= 'A' && r <= 'Z') ||
                (r >= '0' && r <= '9') ||
                r == '-' || r == '_' ||
                (r >= 0x80 && r <= 0x10FFFF) // 简化了 Unicode 范围
     }

     func main() {
         fmt.Println(isCSSNmchar('a'))  // 输出: true
         fmt.Println(isCSSNmchar('9'))  // 输出: true
         fmt.Println(isCSSNmchar('-'))  // 输出: true
         fmt.Println(isCSSNmchar(' '))  // 输出: false
         fmt.Println(isCSSNmchar(0x00A0)) // 输出: true (假设在简化的 Unicode 范围内)
     }
     ```
   - **假设输入与输出:**
     - 输入: `rune = 'a'`
     - 输出: `true`
     - 输入: `rune = ' '`
     - 输出: `false`

**3. 测试 `decodeCSS` 函数:**

   - **功能:** 解码 CSS 字符串中的转义字符，例如将 `\A` 解码为换行符，将 `\20` 解码为空格，将 `\1234` 解码为对应的 Unicode 字符。
   - **Go 语言特性:**  涉及到字节切片的处理和 Unicode 字符的转换。
   - **代码推理与示例:**
     ```go
     package main

     import (
         "fmt"
         "strconv"
         "strings"
         "unicode/utf8"
     )

     // 假设这是 template 包中的 decodeCSS 函数的简化版本
     func decodeCSS(css []byte) []byte {
         var buf strings.Builder
         for i := 0; i < len(css); i++ {
             if css[i] == '\\' {
                 if i+1 < len(css) {
                     if isHexDigit(rune(css[i+1])) {
                         // 处理十六进制转义
                         j := i + 1
                         for j < len(css) && isHexDigit(rune(css[j])) && j-i-1 < 6 {
                             j++
                         }
                         hexStr := string(css[i+1:j])
                         code, err := strconv.ParseInt(hexStr, 16, 32)
                         if err == nil {
                             buf.WriteRune(rune(code))
                         }
                         i = j - 1
                     } else {
                         // 处理其他转义字符
                         switch css[i+1] {
                         case 'a':
                             buf.WriteByte('\n')
                         case 'b':
                             buf.WriteByte('\b')
                         case 'f':
                             buf.WriteByte('\f')
                         case 'n':
                             buf.WriteByte('\n')
                         case 'r':
                             buf.WriteByte('\r')
                         case 't':
                             buf.WriteByte('\t')
                         case 'v':
                             // ... (省略其他转义字符)
                         default:
                             buf.WriteByte(css[i+1]) // 如果是不认识的转义，保留
                         }
                         i++
                     }
                 } else {
                     // 如果 \ 是最后一个字符，则忽略
                 }
             } else {
                 buf.WriteByte(css[i])
             }
         }
         return []byte(buf.String())
     }

     func isHexDigit(r rune) bool {
         return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
     }

     func main() {
         fmt.Println(string(decodeCSS([]byte(`foo\bar`))))    // 输出: foobar
         fmt.Println(string(decodeCSS([]byte(`foo\Abar`))))   // 输出: foo
                                                               //       bar
         fmt.Println(string(decodeCSS([]byte(`foo\20bar`))))  // 输出: foo bar
         fmt.Println(string(decodeCSS([]byte(`foo\1234bar`)))) // 输出: fooሴbar (这里假设终端支持显示该 Unicode 字符)
     }
     ```
   - **假设输入与输出:**
     - 输入: `css = []byte("\\A")`
     - 输出: `"\n"` (换行符)
     - 输入: `css = []byte("\\20")`
     - 输出: `" "` (空格)
     - 输入: `css = []byte("\\1234")`
     - 输出:  对应的 Unicode 字符 (例如 `ሴ`)

**4. 测试 `hexDecode` 函数:**

   - **功能:** 将一个字节切片表示的十六进制字符串解码为整数。
   - **Go 语言特性:**  使用了 `strconv` 包进行字符串到整数的转换。
   - **代码推理与示例:**
     ```go
     package main

     import (
         "fmt"
         "strconv"
     )

     // 假设这是 template 包中的 hexDecode 函数的简化版本
     func hexDecode(s []byte) int {
         n, _ := strconv.ParseInt(string(s), 16, 64)
         return int(n)
     }

     func main() {
         fmt.Println(hexDecode([]byte("10")))   // 输出: 16
         fmt.Println(hexDecode([]byte("a")))    // 输出: 10
         fmt.Println(hexDecode([]byte("F")))    // 输出: 15
         fmt.Println(hexDecode([]byte("1A2B"))) // 输出: 6707
     }
     ```
   - **假设输入与输出:**
     - 输入: `hex = []byte("10")`
     - 输出: `16`
     - 输入: `hex = []byte("FF")`
     - 输出: `255`

**5. 测试 `skipCSSSpace` 函数:**

   - **功能:** 跳过 CSS 字符串开头的空白字符（空格、制表符、换行符等）。
   - **Go 语言特性:**  涉及到对字节切片的遍历和判断。
   - **代码推理与示例:**
     ```go
     package main

     import (
         "bytes"
         "fmt"
     )

     // 假设这是 template 包中的 skipCSSSpace 函数的简化版本
     func skipCSSSpace(css []byte) []byte {
         for len(css) > 0 && isCSSSpace(css[0]) {
             css = css[1:]
         }
         return css
     }

     func isCSSSpace(b byte) bool {
         return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f'
     }

     func main() {
         fmt.Println(string(skipCSSSpace([]byte("  \t\n foo")))) // 输出: foo
         fmt.Println(string(skipCSSSpace([]byte("bar"))))    // 输出: bar
     }
     ```
   - **假设输入与输出:**
     - 输入: `css = []byte("  \n  content")`
     - 输出: `"content"`
     - 输入: `css = []byte("no space")`
     - 输出: `"no space"`

**6. 测试 `cssEscaper` 函数:**

   - **功能:** 对 CSS 字符串中的特殊字符进行转义，使其可以在 HTML 模板中安全地使用。这通常用于防止 XSS 攻击。
   - **Go 语言特性:**  涉及到字符串的遍历和根据字符类型进行不同的转义处理。
   - **代码推理:**  `cssEscaper` 的具体实现会根据 CSS 规范对需要转义的字符进行处理，例如将 `<` 转义为 `\3c`，将 `"` 转义为 `\22` 等。由于这个函数较为复杂，简化的示例可能无法完全覆盖其功能。

**7. 测试 `cssValueFilter` 函数:**

   - **功能:**  过滤 CSS 属性值，移除或替换潜在的危险内容，例如 JavaScript 代码或 HTML 标签。这是一种安全措施，防止用户提供的 CSS 值导致安全漏洞。
   - **Go 语言特性:**  涉及到字符串的模式匹配和替换。
   - **代码推理:** `cssValueFilter` 会检查 CSS 值中是否包含敏感的字符串或模式，例如 `javascript:`、`expression(`、`<script` 等，并将其替换为安全的值，例如 `ZgotmplZ`。
   - **假设输入与输出:**
     - 输入: `css = "expression(alert('XSS'))"`
     - 输出: `"ZgotmplZ"`
     - 输入: `css = "color: red"`
     - 输出: `"color: red"`

**涉及的 Go 语言功能:**

- **`testing` 包:** 用于编写和运行单元测试。
- **结构体 (struct):** 用于组织测试用例的数据。
- **切片 (slice):** 用于存储测试用例。
- **`for...range` 循环:** 用于遍历测试用例。
- **`t.Errorf`:** 用于报告测试失败。
- **字符串和字节切片 (`string`, `[]byte`):**  用于处理 CSS 文本数据。
- **Unicode 字符 (`rune`):** 用于处理 Unicode 字符。
- **字符串处理函数 (`strings` 包):** 例如 `strings.ToLower`, `strings.HasSuffix`。
- **数字类型转换 (`strconv` 包):** 例如 `strconv.ParseInt`。
- **`bytes` 包:** 用于字节切片的操作。

**命令行参数的具体处理:**

这段代码是测试代码，本身不处理命令行参数。Go 语言的测试工具 `go test` 接收一些命令行参数，例如指定要运行的测试文件、运行特定的测试函数等，但这些参数是由 `go test` 工具处理的，而不是这段代码本身。

**使用者易犯错的点:**

虽然这段代码是测试代码，但可以推断出使用 `html/template` 包中 CSS 相关功能时可能犯的错误：

1. **混淆 `cssEscaper` 和 `cssValueFilter` 的用途:**
   - `cssEscaper` 主要用于确保 CSS 语法上的正确性，转义特殊字符，防止解析错误。
   - `cssValueFilter` 则更侧重于安全性，移除或替换潜在的危险 CSS 值。
   - **错误示例:** 错误地认为 `cssEscaper` 可以完全防止 XSS，而忽略了使用 `cssValueFilter` 对用户提供的 CSS 值进行过滤。

2. **不理解 CSS 转义规则:**
   - 可能会错误地手动进行 CSS 转义，导致双重转义或转义不足。应该依赖 `cssEscaper` 来完成。

3. **在不应该使用 CSS 上下文的地方使用 CSS 相关函数:**
   - 例如，在 HTML 属性的 URL 中错误地使用了 CSS 转义函数，可能会导致 URL 解析错误。

总而言之，这段代码通过一系列测试用例，验证了 `html/template` 包中用于处理 CSS 字符串的实用工具函数的正确性，包括判断关键字结尾、识别标识符字符、解码转义字符、十六进制解码、跳过空白以及进行转义和过滤等功能。这些功能对于在 Go 模板中安全地处理和渲染 CSS 代码至关重要。

Prompt: 
```
这是路径为go/src/html/template/css_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package template

import (
	"strconv"
	"strings"
	"testing"
)

func TestEndsWithCSSKeyword(t *testing.T) {
	tests := []struct {
		css, kw string
		want    bool
	}{
		{"", "url", false},
		{"url", "url", true},
		{"URL", "url", true},
		{"Url", "url", true},
		{"url", "important", false},
		{"important", "important", true},
		{"image-url", "url", false},
		{"imageurl", "url", false},
		{"image url", "url", true},
	}
	for _, test := range tests {
		got := endsWithCSSKeyword([]byte(test.css), test.kw)
		if got != test.want {
			t.Errorf("want %t but got %t for css=%v, kw=%v", test.want, got, test.css, test.kw)
		}
	}
}

func TestIsCSSNmchar(t *testing.T) {
	tests := []struct {
		rune rune
		want bool
	}{
		{0, false},
		{'0', true},
		{'9', true},
		{'A', true},
		{'Z', true},
		{'a', true},
		{'z', true},
		{'_', true},
		{'-', true},
		{':', false},
		{';', false},
		{' ', false},
		{0x7f, false},
		{0x80, true},
		{0x1234, true},
		{0xd800, false},
		{0xdc00, false},
		{0xfffe, false},
		{0x10000, true},
		{0x110000, false},
	}
	for _, test := range tests {
		got := isCSSNmchar(test.rune)
		if got != test.want {
			t.Errorf("%q: want %t but got %t", string(test.rune), test.want, got)
		}
	}
}

func TestDecodeCSS(t *testing.T) {
	tests := []struct {
		css, want string
	}{
		{``, ``},
		{`foo`, `foo`},
		{`foo\`, `foo`},
		{`foo\\`, `foo\`},
		{`\`, ``},
		{`\A`, "\n"},
		{`\a`, "\n"},
		{`\0a`, "\n"},
		{`\00000a`, "\n"},
		{`\000000a`, "\u0000a"},
		{`\1234 5`, "\u1234" + "5"},
		{`\1234\20 5`, "\u1234" + " 5"},
		{`\1234\A 5`, "\u1234" + "\n5"},
		{"\\1234\t5", "\u1234" + "5"},
		{"\\1234\n5", "\u1234" + "5"},
		{"\\1234\r\n5", "\u1234" + "5"},
		{`\12345`, "\U00012345"},
		{`\\`, `\`},
		{`\\ `, `\ `},
		{`\"`, `"`},
		{`\'`, `'`},
		{`\.`, `.`},
		{`\. .`, `. .`},
		{
			`The \3c i\3equick\3c/i\3e,\d\A\3cspan style=\27 color:brown\27\3e brown\3c/span\3e  fox jumps\2028over the \3c canine class=\22lazy\22 \3e dog\3c/canine\3e`,
			"The <i>quick</i>,\r\n<span style='color:brown'>brown</span> fox jumps\u2028over the <canine class=\"lazy\">dog</canine>",
		},
	}
	for _, test := range tests {
		got1 := string(decodeCSS([]byte(test.css)))
		if got1 != test.want {
			t.Errorf("%q: want\n\t%q\nbut got\n\t%q", test.css, test.want, got1)
		}
		recoded := cssEscaper(got1)
		if got2 := string(decodeCSS([]byte(recoded))); got2 != test.want {
			t.Errorf("%q: escape & decode not dual for %q", test.css, recoded)
		}
	}
}

func TestHexDecode(t *testing.T) {
	for i := 0; i < 0x200000; i += 101 /* coprime with 16 */ {
		s := strconv.FormatInt(int64(i), 16)
		if got := int(hexDecode([]byte(s))); got != i {
			t.Errorf("%s: want %d but got %d", s, i, got)
		}
		s = strings.ToUpper(s)
		if got := int(hexDecode([]byte(s))); got != i {
			t.Errorf("%s: want %d but got %d", s, i, got)
		}
	}
}

func TestSkipCSSSpace(t *testing.T) {
	tests := []struct {
		css, want string
	}{
		{"", ""},
		{"foo", "foo"},
		{"\n", ""},
		{"\r\n", ""},
		{"\r", ""},
		{"\t", ""},
		{" ", ""},
		{"\f", ""},
		{" foo", "foo"},
		{"  foo", " foo"},
		{`\20`, `\20`},
	}
	for _, test := range tests {
		got := string(skipCSSSpace([]byte(test.css)))
		if got != test.want {
			t.Errorf("%q: want %q but got %q", test.css, test.want, got)
		}
	}
}

func TestCSSEscaper(t *testing.T) {
	input := ("\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f" +
		"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f" +
		` !"#$%&'()*+,-./` +
		`0123456789:;<=>?` +
		`@ABCDEFGHIJKLMNO` +
		`PQRSTUVWXYZ[\]^_` +
		"`abcdefghijklmno" +
		"pqrstuvwxyz{|}~\x7f" +
		"\u00A0\u0100\u2028\u2029\ufeff\U0001D11E")

	want := ("\\0\x01\x02\x03\x04\x05\x06\x07" +
		"\x08\\9 \\a\x0b\\c \\d\x0E\x0F" +
		"\x10\x11\x12\x13\x14\x15\x16\x17" +
		"\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f" +
		` !\22#$%\26\27\28\29*\2b,-.\2f ` +
		`0123456789\3a\3b\3c=\3e?` +
		`@ABCDEFGHIJKLMNO` +
		`PQRSTUVWXYZ[\\]^_` +
		"`abcdefghijklmno" +
		`pqrstuvwxyz\7b|\7d~` + "\u007f" +
		"\u00A0\u0100\u2028\u2029\ufeff\U0001D11E")

	got := cssEscaper(input)
	if got != want {
		t.Errorf("encode: want\n\t%q\nbut got\n\t%q", want, got)
	}

	got = string(decodeCSS([]byte(got)))
	if input != got {
		t.Errorf("decode: want\n\t%q\nbut got\n\t%q", input, got)
	}
}

func TestCSSValueFilter(t *testing.T) {
	tests := []struct {
		css, want string
	}{
		{"", ""},
		{"foo", "foo"},
		{"0", "0"},
		{"0px", "0px"},
		{"-5px", "-5px"},
		{"1.25in", "1.25in"},
		{"+.33em", "+.33em"},
		{"100%", "100%"},
		{"12.5%", "12.5%"},
		{".foo", ".foo"},
		{"#bar", "#bar"},
		{"corner-radius", "corner-radius"},
		{"-moz-corner-radius", "-moz-corner-radius"},
		{"#000", "#000"},
		{"#48f", "#48f"},
		{"#123456", "#123456"},
		{"U+00-FF, U+980-9FF", "U+00-FF, U+980-9FF"},
		{"color: red", "color: red"},
		{"<!--", "ZgotmplZ"},
		{"-->", "ZgotmplZ"},
		{"<![CDATA[", "ZgotmplZ"},
		{"]]>", "ZgotmplZ"},
		{"</style", "ZgotmplZ"},
		{`"`, "ZgotmplZ"},
		{`'`, "ZgotmplZ"},
		{"`", "ZgotmplZ"},
		{"\x00", "ZgotmplZ"},
		{"/* foo */", "ZgotmplZ"},
		{"//", "ZgotmplZ"},
		{"[href=~", "ZgotmplZ"},
		{"expression(alert(1337))", "ZgotmplZ"},
		{"-expression(alert(1337))", "ZgotmplZ"},
		{"expression", "ZgotmplZ"},
		{"Expression", "ZgotmplZ"},
		{"EXPRESSION", "ZgotmplZ"},
		{"-moz-binding", "ZgotmplZ"},
		{"-expr\x00ession(alert(1337))", "ZgotmplZ"},
		{`-expr\0ession(alert(1337))`, "ZgotmplZ"},
		{`-express\69on(alert(1337))`, "ZgotmplZ"},
		{`-express\69 on(alert(1337))`, "ZgotmplZ"},
		{`-exp\72 ession(alert(1337))`, "ZgotmplZ"},
		{`-exp\52 ession(alert(1337))`, "ZgotmplZ"},
		{`-exp\000052 ession(alert(1337))`, "ZgotmplZ"},
		{`-expre\0000073sion`, "-expre\x073sion"},
		{`@import url evil.css`, "ZgotmplZ"},
		{"<", "ZgotmplZ"},
		{">", "ZgotmplZ"},
	}
	for _, test := range tests {
		got := cssValueFilter(test.css)
		if got != test.want {
			t.Errorf("%q: want %q but got %q", test.css, test.want, got)
		}
	}
}

func BenchmarkCSSEscaper(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cssEscaper("The <i>quick</i>,\r\n<span style='color:brown'>brown</span> fox jumps\u2028over the <canine class=\"lazy\">dog</canine>")
	}
}

func BenchmarkCSSEscaperNoSpecials(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cssEscaper("The quick, brown fox jumps over the lazy dog.")
	}
}

func BenchmarkDecodeCSS(b *testing.B) {
	s := []byte(`The \3c i\3equick\3c/i\3e,\d\A\3cspan style=\27 color:brown\27\3e brown\3c/span\3e fox jumps\2028over the \3c canine class=\22lazy\22 \3edog\3c/canine\3e`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decodeCSS(s)
	}
}

func BenchmarkDecodeCSSNoSpecials(b *testing.B) {
	s := []byte("The quick, brown fox jumps over the lazy dog.")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decodeCSS(s)
	}
}

func BenchmarkCSSValueFilter(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cssValueFilter(`  e\78preS\0Sio/**/n(alert(1337))`)
	}
}

func BenchmarkCSSValueFilterOk(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cssValueFilter(`Times New Roman`)
	}
}

"""



```