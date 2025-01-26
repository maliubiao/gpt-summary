Response:
Let's break down the thought process for analyzing the Go scanner test code.

1. **Identify the Core Purpose:** The filename `scanner_test.go` immediately suggests this is a test suite for a `scanner` package. The `package scanner` declaration confirms this. The content will likely involve creating various input scenarios and verifying the scanner's output.

2. **Understand the Setup:** Look for common testing patterns in Go. The `import "testing"` is a key indicator. Functions starting with `Test` (like `TestNext`, `TestScan`, etc.) are standard test functions.

3. **Examine Key Data Structures:** Scan the code for important data structures.
    * `StringReader`:  This custom reader allows feeding the scanner input in segments, useful for testing how the scanner handles chunked input.
    * `token`: This struct clearly represents a token recognized by the scanner, containing its type (`rune`) and its textual representation (`string`).
    * `tokenList`:  This is a crucial array of `token` structs. It serves as the ground truth for many tests, defining expected token types and values for various input strings.

4. **Analyze Individual Test Functions:**  Go through each `Test...` function and understand its specific focus:
    * `TestNext`:  Focuses on the `Next()` method, which reads single runes. It uses `StringReader` to test segmented input.
    * `TestScan`:  Tests the main `Scan()` method, which identifies and returns complete tokens. It uses `tokenList` to compare against expected outputs. It also checks scenarios with and without comment skipping.
    * `TestInvalidExponent`: Specifically tests how the scanner handles invalid exponent formats in floating-point numbers, including the error reporting mechanism.
    * `TestPosition`:  Verifies that the scanner correctly tracks the position (offset, line, column) of tokens in the input.
    * `TestScanZeroMode`: Tests the behavior when the scanner is configured with no specific token recognition modes.
    * `TestScanSelectedMask`:  Tests the effect of setting specific scanner modes (e.g., `ScanIdents`, `ScanInts`).
    * `TestScanCustomIdent`:  Demonstrates how to customize the definition of what constitutes an identifier using `IsIdentRune`.
    * `TestScanNext`:  Tests the interaction between `Scan()` and `Next()` and how the scanner handles Byte Order Marks (BOM).
    * `TestScanWhitespace`: Checks how the scanner handles whitespace characters based on the `Whitespace` setting.
    * `TestError`:  Extensively tests various error conditions the scanner might encounter (invalid characters, unterminated literals, etc.) and verifies the error reporting mechanism.
    * `TestIOError`:  Checks how the scanner handles non-EOF I/O errors.
    * `TestPos`:  Focuses on meticulously testing the position tracking of the scanner in various scenarios (empty input, newlines, multi-byte characters).
    * `TestNextEOFHandling` and `TestScanEOFHandling`:  Test the behavior of `Next()` and `Scan()` when the end of the input is reached.
    * `TestIssue29723`:  Addresses a specific bug report related to calling `TokenText()` in an error handler.
    * `TestNumbers`:  Performs comprehensive testing of different number formats (binary, octal, decimal, hexadecimal, with and without separators), including valid and invalid cases and associated error messages.
    * `TestIssue30320`:  Tests how specific scanner modes extract certain types of tokens from a string.
    * `TestIssue50909`: Tests the interaction between a custom `IsIdentRune` function and how the scanner identifies tokens across newlines.

5. **Identify Key Functionality:** Based on the tests, deduce the core functionalities of the `scanner` package:
    * **Tokenization:**  Breaking down input into meaningful units (tokens).
    * **Token Type Recognition:** Identifying the type of each token (identifier, integer, float, string, comment, etc.).
    * **Position Tracking:**  Maintaining accurate location information for each token.
    * **Error Reporting:**  Detecting and reporting syntax errors in the input.
    * **Customizable Identifier Recognition:**  Allowing users to define what constitutes an identifier.
    * **Whitespace Handling:**  Providing options for how whitespace is treated (skipped or as tokens).
    * **Comment Handling:**  Providing options for skipping or recognizing comments.
    * **Handling Different Number Bases:** Supporting binary, octal, decimal, and hexadecimal number formats.

6. **Construct Examples:** Create Go code snippets to illustrate how the `scanner` package might be used, focusing on the identified functionalities. Think about simple and clear examples that demonstrate core concepts.

7. **Consider Error-Prone Areas:** Based on the test cases, identify common mistakes users might make. For instance, forgetting to handle errors, misunderstanding scanner modes, or incorrect customization of identifier recognition.

8. **Structure the Response:** Organize the information logically with clear headings. Start with the overall functionality, then provide code examples, explanations of command-line arguments (if applicable – in this case, not really), and finally, common pitfalls. Use clear and concise language.

9. **Review and Refine:**  Read through the generated response to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For instance, ensure the code examples are correct and the explanations are easy to understand. For example, initially, I might not have explicitly mentioned the different number base support, but reviewing the `TestNumbers` function would remind me to include that.
这个Go语言代码文件 `scanner_test.go` 是对 `text/scanner` 包中的 `Scanner` 类型进行单元测试的集合。它的主要功能是验证 `Scanner` 的各种行为是否符合预期。

以下是该测试文件的详细功能分解：

**1. 基本输入读取测试 (`TestNext`)：**

   -   测试 `Scanner` 的 `Next()` 方法，该方法用于逐个读取输入源的 Rune (Unicode 字符)。
   -   `StringReader` 类型是一个自定义的 `io.Reader`，可以将字符串分段提供给 `Scanner`，用于模拟不同的输入方式。
   -   `readRuneSegments` 函数接受一个字符串切片，并使用 `StringReader` 将其作为输入源初始化 `Scanner`。然后，它循环调用 `Next()` 读取 Rune，并将读取到的字符拼接起来，最后与预期的完整字符串进行比较。
   -   `segmentList` 变量定义了一系列用于测试的不同字符串分段组合，包括空字符串、多字节字符（如日语）、Unicode 字符和 ASCII 字符等。

   **Go 代码示例：**

   ```go
   package main

   import (
       "fmt"
       "strings"
       "text/scanner"
   )

   func main() {
       input := "Hello, 日本語!"
       var s scanner.Scanner
       s.Init(strings.NewReader(input))

       for tok := s.Next(); tok != scanner.EOF; tok = s.Next() {
           fmt.Printf("%c ", tok)
       }
       // 输出: H e l l o ,   日 本 語 !
   }
   ```

   **假设输入与输出：**

   -   **假设输入：** 字符串 "你好，世界！"
   -   **预期输出：** 逐个打印出每个字符：`你 好 ， 世 界 ！ `

**2. Token 扫描测试 (`TestScan`)：**

   -   测试 `Scanner` 的 `Scan()` 方法，该方法用于扫描输入源并返回下一个 token（词法单元）。
   -   `token` 结构体定义了一个 token 的类型 (`rune`) 和文本内容 (`string`)。
   -   `tokenList` 变量包含了各种类型的 token 及其预期的文本表示，包括注释、标识符、整数（十进制、八进制、十六进制）、浮点数、字符和字符串（普通字符串和原始字符串）。
   -   `makeSource` 函数用于根据 `tokenList` 中的 token 生成测试用的输入源。
   -   `checkTok` 函数用于断言 `Scan()` 方法返回的 token 类型和文本内容是否与预期一致，并检查行号是否正确。
   -   `testScan` 函数使用不同的扫描模式（`GoTokens`，即 Go 语言的 token 识别规则，以及不跳过注释的模式）来测试 `Scan()` 方法。

   **Go 代码示例：**

   ```go
   package main

   import (
       "fmt"
       "strings"
       "text/scanner"
   )

   func main() {
       input := "package main // This is a comment\nimport \"fmt\""
       var s scanner.Scanner
       s.Init(strings.NewReader(input))

       for tok := s.Scan(); tok != scanner.EOF; tok = s.Scan() {
           fmt.Printf("Token: %s, Text: %q\n", scanner.TokenString(tok), s.TokenText())
       }
       // 可能的输出 (取决于 scanner 内部的 token 类型定义):
       // Token: identifier, Text: "package"
       // Token: identifier, Text: "main"
       // Token: comment, Text: "// This is a comment"
       // Token: identifier, Text: "import"
       // Token: string, Text: "\"fmt\""
   }
   ```

   **假设输入与输出：**

   -   **假设输入：** 字符串 "x := 10 + 3.14"
   -   **预期输出：**
     ```
     Token: identifier, Text: "x"
     Token: :=, Text: ":="
     Token: int, Text: "10"
     Token: +, Text: "+"
     Token: float, Text: "3.14"
     ```

**3. 错误处理测试 (`TestInvalidExponent`, `TestError`, `TestIOError`)：**

   -   测试 `Scanner` 在遇到语法错误或 I/O 错误时的处理方式。
   -   `TestInvalidExponent` 测试浮点数指数部分格式错误的情况，并验证错误处理函数是否被调用。
   -   `TestError` 包含了各种各样的错误输入，例如无效字符、未终止的字符串/字符/注释、非法的数字字面量等，并验证 `Scanner` 是否能正确检测到这些错误并调用错误处理函数。
   -   `TestIOError` 测试当 `io.Reader` 返回非 `io.EOF` 错误时，`Scanner` 的行为。
   -   测试中使用了 `s.Error` 字段来设置自定义的错误处理函数，用于检查错误信息和位置是否正确。

   **Go 代码示例 (错误处理)：**

   ```go
   package main

   import (
       "fmt"
       "strings"
       "text/scanner"
   )

   func main() {
       input := "0xG" // 非法的十六进制数
       var s scanner.Scanner
       s.Init(strings.NewReader(input))
       s.Error = func(s *scanner.Scanner, msg string) {
           fmt.Printf("Error at position %s: %s\n", s.Position, msg)
       }

       s.Scan()
       // 预期输出: Error at position 1:3: hexadecimal literal has no digits
   }
   ```

   **假设输入与输出：**

   -   **假设输入：** 字符串 "'abc" (未闭合的字符字面量)
   -   **预期输出：** `Error at position <input>:1:5: literal not terminated` (具体的行列号可能略有不同)

**4. 位置信息测试 (`TestPosition`, `TestPos`)：**

   -   测试 `Scanner` 是否能正确跟踪输入源中的位置信息（偏移量、行号、列号）。
   -   `TestPosition` 使用制表符作为分隔符，验证每个 token 的位置信息是否正确计算。
   -   `TestPos` 包含更细致的测试，涵盖了空输入、仅包含换行符的输入、多字节字符等情况，并测试 `Next()` 和 `Scan()` 方法对位置信息的影响。

   **Go 代码示例 (位置信息)：**

   ```go
   package main

   import (
       "fmt"
       "strings"
       "text/scanner"
   )

   func main() {
       input := "line1\n  line2"
       var s scanner.Scanner
       s.Init(strings.NewReader(input))

       s.Scan()
       fmt.Printf("Token: %q, Position: %s\n", s.TokenText(), s.Position) // 输出: Token: "line1", Position: <input>:1:1
       s.Scan()
       fmt.Printf("Token: %q, Position: %s\n", s.TokenText(), s.Position) // 输出: Token: "\n", Position: <input>:1:6
       s.Scan()
       fmt.Printf("Token: %q, Position: %s\n", s.TokenText(), s.Position) // 输出: Token: "  ", Position: <input>:2:1
       s.Scan()
       fmt.Printf("Token: %q, Position: %s\n", s.TokenText(), s.Position) // 输出: Token: "line2", Position: <input>:2:3
   }
   ```

   **假设输入与输出：**

   -   **假设输入：** 字符串 "a\n bbb"
   -   **预期输出：**
     ```
     Token: "a", Position: <input>:1:1
     Token: "\n", Position: <input>:1:2
     Token: " ", Position: <input>:2:1
     Token: "bbb", Position: <input>:2:2
     ```

**5. 自定义标识符测试 (`TestScanCustomIdent`)：**

   -   测试如何使用 `Scanner` 的 `IsIdentRune` 字段来自定义标识符的识别规则。
   -   该测试定义了一个只包含 'a' 或 'b' 开头，后续为最多 3 个数字的标识符规则。

   **Go 代码示例 (自定义标识符)：**

   ```go
   package main

   import (
       "fmt"
       "strings"
       "text/scanner"
   )

   func main() {
       input := "a12 b3 c45"
       var s scanner.Scanner
       s.Init(strings.NewReader(input))
       s.IsIdentRune = func(ch rune, i int) bool {
           return (i == 0 && (ch == 'a' || ch == 'b')) || (i > 0 && ch >= '0' && ch <= '9' && i < 4)
       }

       for tok := s.Scan(); tok != scanner.EOF; tok = s.Scan() {
           fmt.Printf("Token: %s, Text: %q\n", scanner.TokenString(tok), s.TokenText())
       }
       // 预期输出:
       // Token: identifier, Text: "a12"
       // Token: identifier, Text: "b3"
       // Token: identifier, Text: "c"
       // Token: int, Text: "45"
   }
   ```

   **假设输入与输出：**

   -   **假设输入：** 字符串 "myVar1 my_var2 abc99"，并且自定义标识符规则只允许字母开头和数字结尾。
   -   **预期输出：** 取决于 `IsIdentRune` 的具体实现，可能 "myVar1" 和 "abc99" 被识别为标识符，而 "my_var2" 不会被识别为单个标识符。

**6. 空格处理测试 (`TestScanWhitespace`)：**

   -   测试如何通过 `Scanner` 的 `Whitespace` 字段控制对空格字符的处理。
   -   可以设置 `Whitespace` 位掩码来指定哪些字符应该被视为空格跳过。

   **Go 代码示例 (空格处理)：**

   ```go
   package main

   import (
       "fmt"
       "strings"
       "text/scanner"
   )

   func main() {
       input := "a\tb\nc"
       var s scanner.Scanner
       s.Init(strings.NewReader(input))
       s.Mode = scanner.ScanIdents // 只扫描标识符

       fmt.Println("默认行为:")
       for tok := s.Scan(); tok != scanner.EOF; tok = s.Scan() {
           fmt.Printf("Token: %s, Text: %q\n", scanner.TokenString(tok), s.TokenText())
       }

       s.Init(strings.NewReader(input))
       s.Mode = scanner.ScanIdents
       s.Whitespace = 0 // 不跳过任何空格
       fmt.Println("\n不跳过空格:")
       for tok := s.Scan(); tok != scanner.EOF; tok = s.Scan() {
           fmt.Printf("Token: %s, Text: %q\n", scanner.TokenString(tok), s.TokenText())
       }
   }
   ```

   **假设输入与输出：**

   -   **假设输入：** 字符串 "  hello  world  "
   -   **预期输出：** 取决于 `Whitespace` 的设置。如果跳过空格，则会识别 "hello" 和 "world" 两个标识符。如果不跳过，则空格也会作为 token 被识别。

**7. EOF 处理测试 (`TestNextEOFHandling`, `TestScanEOFHandling`)：**

   -   测试当输入源到达末尾 (EOF) 时，`Next()` 和 `Scan()` 方法的行为。
   -   验证它们是否返回 `scanner.EOF`。

**8. 特定 Issue 的测试 (`TestIssue29723`, `TestIssue30320`, `TestIssue50909`)：**

   -   这些测试针对先前报告的 bug 或特定场景进行验证，确保 `Scanner` 在这些情况下也能正常工作。例如，`TestIssue29723` 检查在错误处理函数中调用 `TokenText()` 是否会 panic。

**9. 数字字面量测试 (`TestNumbers`)：**

   -   非常详细地测试各种格式的数字字面量，包括二进制、八进制、十进制、十六进制整数和浮点数，以及带有分隔符的数字。
   -   验证 `Scanner` 能正确识别这些数字，并能检测到非法的数字格式。

**10. 选择性扫描模式测试 (`TestScanSelectedMask`)：**

    - 测试通过设置 `Scanner` 的 `Mode` 字段来选择性地扫描特定类型的 token，例如只扫描标识符、字符或字符串。

**总结 `scanner_test.go` 的功能：**

-   **全面测试 `Scanner` 的核心功能：**  涵盖了 Rune 的读取 (`Next`) 和 Token 的扫描 (`Scan`)。
-   **测试不同类型的输入：**  包括各种字符集、字符串分段、以及包含各种 token 的 Go 语言代码片段。
-   **详尽的错误处理测试：**  验证 `Scanner` 在遇到各种语法错误时的检测和报告能力。
-   **位置信息跟踪验证：**  确保 `Scanner` 能准确地报告 token 在输入源中的位置。
-   **可定制性测试：**  验证 `IsIdentRune` 和 `Whitespace` 等字段的自定义功能。
-   **回归测试：**  包含针对已知 bug 的测试用例，防止代码修改后引入新的问题。
-   **数字字面量解析测试：**  专门测试各种格式的整数和浮点数解析是否正确。
-   **选择性扫描能力测试：**  验证根据模式只扫描特定类型 token 的功能。

**涉及的 Go 语言功能实现：**

这个测试文件主要测试的是 `text/scanner` 包中的 `Scanner` 类型。`Scanner` 的核心功能是 **词法分析 (Lexical Analysis)** 或 **扫描 (Scanning)**。它将输入的文本流分解成一系列有意义的单元，称为 **token**。

**使用者易犯错的点：**

-   **未正确处理 `Scan()` 返回的 `EOF`：**  `Scan()` 方法在到达输入结尾时会返回 `EOF`，使用者需要检查这个返回值来判断是否还有更多的 token。
    ```go
    package main

    import (
        "fmt"
        "strings"
        "text/scanner"
    )

    func main() {
        input := "hello world"
        var s scanner.Scanner
        s.Init(strings.NewReader(input))

        for tok := s.Scan(); tok != scanner.EOF; tok = s.Scan() { // 正确的循环条件
            fmt.Printf("Token: %s, Text: %q\n", scanner.TokenString(tok), s.TokenText())
        }
    }
    ```
    如果循环条件写错，可能会导致无限循环或遗漏最后的 token。

-   **混淆 `Next()` 和 `Scan()` 的使用场景：** `Next()` 用于逐字符读取，而 `Scan()` 用于读取 token。根据需求选择合适的方法。

-   **错误地设置 `Mode` 和 `Whitespace`：**  不理解 `Mode` 的各种选项（例如 `ScanIdents`、`ScanStrings`、`SkipComments`）和 `Whitespace` 的位掩码，可能导致扫描结果不符合预期。

-   **忽略错误处理：**  `Scanner` 通过 `Error` 字段报告错误。如果未设置或正确处理错误函数，可能会忽略输入中的语法错误。

-   **不了解自定义标识符的规则：** 如果使用了 `IsIdentRune` 来自定义标识符，需要确保定义的规则正确且符合预期。

总而言之，`scanner_test.go` 是 `text/scanner` 包的重要组成部分，它通过大量的测试用例确保了 `Scanner` 类型的稳定性和正确性，同时也展示了 `Scanner` 的各种功能和使用方法。

Prompt: 
```
这是路径为go/src/text/scanner/scanner_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scanner

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"unicode/utf8"
)

// A StringReader delivers its data one string segment at a time via Read.
type StringReader struct {
	data []string
	step int
}

func (r *StringReader) Read(p []byte) (n int, err error) {
	if r.step < len(r.data) {
		s := r.data[r.step]
		n = copy(p, s)
		r.step++
	} else {
		err = io.EOF
	}
	return
}

func readRuneSegments(t *testing.T, segments []string) {
	got := ""
	want := strings.Join(segments, "")
	s := new(Scanner).Init(&StringReader{data: segments})
	for {
		ch := s.Next()
		if ch == EOF {
			break
		}
		got += string(ch)
	}
	if got != want {
		t.Errorf("segments=%v got=%s want=%s", segments, got, want)
	}
}

var segmentList = [][]string{
	{},
	{""},
	{"日", "本語"},
	{"\u65e5", "\u672c", "\u8a9e"},
	{"\U000065e5", " ", "\U0000672c", "\U00008a9e"},
	{"\xe6", "\x97\xa5\xe6", "\x9c\xac\xe8\xaa\x9e"},
	{"Hello", ", ", "World", "!"},
	{"Hello", ", ", "", "World", "!"},
}

func TestNext(t *testing.T) {
	for _, s := range segmentList {
		readRuneSegments(t, s)
	}
}

type token struct {
	tok  rune
	text string
}

var f100 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

var tokenList = []token{
	{Comment, "// line comments"},
	{Comment, "//"},
	{Comment, "////"},
	{Comment, "// comment"},
	{Comment, "// /* comment */"},
	{Comment, "// // comment //"},
	{Comment, "//" + f100},

	{Comment, "// general comments"},
	{Comment, "/**/"},
	{Comment, "/***/"},
	{Comment, "/* comment */"},
	{Comment, "/* // comment */"},
	{Comment, "/* /* comment */"},
	{Comment, "/*\n comment\n*/"},
	{Comment, "/*" + f100 + "*/"},

	{Comment, "// identifiers"},
	{Ident, "a"},
	{Ident, "a0"},
	{Ident, "foobar"},
	{Ident, "abc123"},
	{Ident, "LGTM"},
	{Ident, "_"},
	{Ident, "_abc123"},
	{Ident, "abc123_"},
	{Ident, "_abc_123_"},
	{Ident, "_äöü"},
	{Ident, "_本"},
	{Ident, "äöü"},
	{Ident, "本"},
	{Ident, "a۰۱۸"},
	{Ident, "foo६४"},
	{Ident, "bar９８７６"},
	{Ident, f100},

	{Comment, "// decimal ints"},
	{Int, "0"},
	{Int, "1"},
	{Int, "9"},
	{Int, "42"},
	{Int, "1234567890"},

	{Comment, "// octal ints"},
	{Int, "00"},
	{Int, "01"},
	{Int, "07"},
	{Int, "042"},
	{Int, "01234567"},

	{Comment, "// hexadecimal ints"},
	{Int, "0x0"},
	{Int, "0x1"},
	{Int, "0xf"},
	{Int, "0x42"},
	{Int, "0x123456789abcDEF"},
	{Int, "0x" + f100},
	{Int, "0X0"},
	{Int, "0X1"},
	{Int, "0XF"},
	{Int, "0X42"},
	{Int, "0X123456789abcDEF"},
	{Int, "0X" + f100},

	{Comment, "// floats"},
	{Float, "0."},
	{Float, "1."},
	{Float, "42."},
	{Float, "01234567890."},
	{Float, ".0"},
	{Float, ".1"},
	{Float, ".42"},
	{Float, ".0123456789"},
	{Float, "0.0"},
	{Float, "1.0"},
	{Float, "42.0"},
	{Float, "01234567890.0"},
	{Float, "0e0"},
	{Float, "1e0"},
	{Float, "42e0"},
	{Float, "01234567890e0"},
	{Float, "0E0"},
	{Float, "1E0"},
	{Float, "42E0"},
	{Float, "01234567890E0"},
	{Float, "0e+10"},
	{Float, "1e-10"},
	{Float, "42e+10"},
	{Float, "01234567890e-10"},
	{Float, "0E+10"},
	{Float, "1E-10"},
	{Float, "42E+10"},
	{Float, "01234567890E-10"},

	{Comment, "// chars"},
	{Char, `' '`},
	{Char, `'a'`},
	{Char, `'本'`},
	{Char, `'\a'`},
	{Char, `'\b'`},
	{Char, `'\f'`},
	{Char, `'\n'`},
	{Char, `'\r'`},
	{Char, `'\t'`},
	{Char, `'\v'`},
	{Char, `'\''`},
	{Char, `'\000'`},
	{Char, `'\777'`},
	{Char, `'\x00'`},
	{Char, `'\xff'`},
	{Char, `'\u0000'`},
	{Char, `'\ufA16'`},
	{Char, `'\U00000000'`},
	{Char, `'\U0000ffAB'`},

	{Comment, "// strings"},
	{String, `" "`},
	{String, `"a"`},
	{String, `"本"`},
	{String, `"\a"`},
	{String, `"\b"`},
	{String, `"\f"`},
	{String, `"\n"`},
	{String, `"\r"`},
	{String, `"\t"`},
	{String, `"\v"`},
	{String, `"\""`},
	{String, `"\000"`},
	{String, `"\777"`},
	{String, `"\x00"`},
	{String, `"\xff"`},
	{String, `"\u0000"`},
	{String, `"\ufA16"`},
	{String, `"\U00000000"`},
	{String, `"\U0000ffAB"`},
	{String, `"` + f100 + `"`},

	{Comment, "// raw strings"},
	{RawString, "``"},
	{RawString, "`\\`"},
	{RawString, "`" + "\n\n/* foobar */\n\n" + "`"},
	{RawString, "`" + f100 + "`"},

	{Comment, "// individual characters"},
	// NUL character is not allowed
	{'\x01', "\x01"},
	{' ' - 1, string(' ' - 1)},
	{'+', "+"},
	{'/', "/"},
	{'.', "."},
	{'~', "~"},
	{'(', "("},
}

func makeSource(pattern string) *bytes.Buffer {
	var buf bytes.Buffer
	for _, k := range tokenList {
		fmt.Fprintf(&buf, pattern, k.text)
	}
	return &buf
}

func checkTok(t *testing.T, s *Scanner, line int, got, want rune, text string) {
	if got != want {
		t.Fatalf("tok = %s, want %s for %q", TokenString(got), TokenString(want), text)
	}
	if s.Line != line {
		t.Errorf("line = %d, want %d for %q", s.Line, line, text)
	}
	stext := s.TokenText()
	if stext != text {
		t.Errorf("text = %q, want %q", stext, text)
	} else {
		// check idempotency of TokenText() call
		stext = s.TokenText()
		if stext != text {
			t.Errorf("text = %q, want %q (idempotency check)", stext, text)
		}
	}
}

func checkTokErr(t *testing.T, s *Scanner, line int, want rune, text string) {
	prevCount := s.ErrorCount
	checkTok(t, s, line, s.Scan(), want, text)
	if s.ErrorCount != prevCount+1 {
		t.Fatalf("want error for %q", text)
	}
}

func countNewlines(s string) int {
	n := 0
	for _, ch := range s {
		if ch == '\n' {
			n++
		}
	}
	return n
}

func testScan(t *testing.T, mode uint) {
	s := new(Scanner).Init(makeSource(" \t%s\n"))
	s.Mode = mode
	tok := s.Scan()
	line := 1
	for _, k := range tokenList {
		if mode&SkipComments == 0 || k.tok != Comment {
			checkTok(t, s, line, tok, k.tok, k.text)
			tok = s.Scan()
		}
		line += countNewlines(k.text) + 1 // each token is on a new line
	}
	checkTok(t, s, line, tok, EOF, "")
}

func TestScan(t *testing.T) {
	testScan(t, GoTokens)
	testScan(t, GoTokens&^SkipComments)
}

func TestInvalidExponent(t *testing.T) {
	const src = "1.5e 1.5E 1e+ 1e- 1.5z"
	s := new(Scanner).Init(strings.NewReader(src))
	s.Error = func(s *Scanner, msg string) {
		const want = "exponent has no digits"
		if msg != want {
			t.Errorf("%s: got error %q; want %q", s.TokenText(), msg, want)
		}
	}
	checkTokErr(t, s, 1, Float, "1.5e")
	checkTokErr(t, s, 1, Float, "1.5E")
	checkTokErr(t, s, 1, Float, "1e+")
	checkTokErr(t, s, 1, Float, "1e-")
	checkTok(t, s, 1, s.Scan(), Float, "1.5")
	checkTok(t, s, 1, s.Scan(), Ident, "z")
	checkTok(t, s, 1, s.Scan(), EOF, "")
	if s.ErrorCount != 4 {
		t.Errorf("%d errors, want 4", s.ErrorCount)
	}
}

func TestPosition(t *testing.T) {
	src := makeSource("\t\t\t\t%s\n")
	s := new(Scanner).Init(src)
	s.Mode = GoTokens &^ SkipComments
	s.Scan()
	pos := Position{"", 4, 1, 5}
	for _, k := range tokenList {
		if s.Offset != pos.Offset {
			t.Errorf("offset = %d, want %d for %q", s.Offset, pos.Offset, k.text)
		}
		if s.Line != pos.Line {
			t.Errorf("line = %d, want %d for %q", s.Line, pos.Line, k.text)
		}
		if s.Column != pos.Column {
			t.Errorf("column = %d, want %d for %q", s.Column, pos.Column, k.text)
		}
		pos.Offset += 4 + len(k.text) + 1     // 4 tabs + token bytes + newline
		pos.Line += countNewlines(k.text) + 1 // each token is on a new line
		s.Scan()
	}
	// make sure there were no token-internal errors reported by scanner
	if s.ErrorCount != 0 {
		t.Errorf("%d errors", s.ErrorCount)
	}
}

func TestScanZeroMode(t *testing.T) {
	src := makeSource("%s\n")
	str := src.String()
	s := new(Scanner).Init(src)
	s.Mode = 0       // don't recognize any token classes
	s.Whitespace = 0 // don't skip any whitespace
	tok := s.Scan()
	for i, ch := range str {
		if tok != ch {
			t.Fatalf("%d. tok = %s, want %s", i, TokenString(tok), TokenString(ch))
		}
		tok = s.Scan()
	}
	if tok != EOF {
		t.Fatalf("tok = %s, want EOF", TokenString(tok))
	}
	if s.ErrorCount != 0 {
		t.Errorf("%d errors", s.ErrorCount)
	}
}

func testScanSelectedMode(t *testing.T, mode uint, class rune) {
	src := makeSource("%s\n")
	s := new(Scanner).Init(src)
	s.Mode = mode
	tok := s.Scan()
	for tok != EOF {
		if tok < 0 && tok != class {
			t.Fatalf("tok = %s, want %s", TokenString(tok), TokenString(class))
		}
		tok = s.Scan()
	}
	if s.ErrorCount != 0 {
		t.Errorf("%d errors", s.ErrorCount)
	}
}

func TestScanSelectedMask(t *testing.T) {
	testScanSelectedMode(t, 0, 0)
	testScanSelectedMode(t, ScanIdents, Ident)
	// Don't test ScanInts and ScanNumbers since some parts of
	// the floats in the source look like (invalid) octal ints
	// and ScanNumbers may return either Int or Float.
	testScanSelectedMode(t, ScanChars, Char)
	testScanSelectedMode(t, ScanStrings, String)
	testScanSelectedMode(t, SkipComments, 0)
	testScanSelectedMode(t, ScanComments, Comment)
}

func TestScanCustomIdent(t *testing.T) {
	const src = "faab12345 a12b123 a12 3b"
	s := new(Scanner).Init(strings.NewReader(src))
	// ident = ( 'a' | 'b' ) { digit } .
	// digit = '0' .. '3' .
	// with a maximum length of 4
	s.IsIdentRune = func(ch rune, i int) bool {
		return i == 0 && (ch == 'a' || ch == 'b') || 0 < i && i < 4 && '0' <= ch && ch <= '3'
	}
	checkTok(t, s, 1, s.Scan(), 'f', "f")
	checkTok(t, s, 1, s.Scan(), Ident, "a")
	checkTok(t, s, 1, s.Scan(), Ident, "a")
	checkTok(t, s, 1, s.Scan(), Ident, "b123")
	checkTok(t, s, 1, s.Scan(), Int, "45")
	checkTok(t, s, 1, s.Scan(), Ident, "a12")
	checkTok(t, s, 1, s.Scan(), Ident, "b123")
	checkTok(t, s, 1, s.Scan(), Ident, "a12")
	checkTok(t, s, 1, s.Scan(), Int, "3")
	checkTok(t, s, 1, s.Scan(), Ident, "b")
	checkTok(t, s, 1, s.Scan(), EOF, "")
}

func TestScanNext(t *testing.T) {
	const BOM = '\uFEFF'
	BOMs := string(BOM)
	s := new(Scanner).Init(strings.NewReader(BOMs + "if a == bcd /* com" + BOMs + "ment */ {\n\ta += c\n}" + BOMs + "// line comment ending in eof"))
	checkTok(t, s, 1, s.Scan(), Ident, "if") // the first BOM is ignored
	checkTok(t, s, 1, s.Scan(), Ident, "a")
	checkTok(t, s, 1, s.Scan(), '=', "=")
	checkTok(t, s, 0, s.Next(), '=', "")
	checkTok(t, s, 0, s.Next(), ' ', "")
	checkTok(t, s, 0, s.Next(), 'b', "")
	checkTok(t, s, 1, s.Scan(), Ident, "cd")
	checkTok(t, s, 1, s.Scan(), '{', "{")
	checkTok(t, s, 2, s.Scan(), Ident, "a")
	checkTok(t, s, 2, s.Scan(), '+', "+")
	checkTok(t, s, 0, s.Next(), '=', "")
	checkTok(t, s, 2, s.Scan(), Ident, "c")
	checkTok(t, s, 3, s.Scan(), '}', "}")
	checkTok(t, s, 3, s.Scan(), BOM, BOMs)
	checkTok(t, s, 3, s.Scan(), -1, "")
	if s.ErrorCount != 0 {
		t.Errorf("%d errors", s.ErrorCount)
	}
}

func TestScanWhitespace(t *testing.T) {
	var buf bytes.Buffer
	var ws uint64
	// start at 1, NUL character is not allowed
	for ch := byte(1); ch < ' '; ch++ {
		buf.WriteByte(ch)
		ws |= 1 << ch
	}
	const orig = 'x'
	buf.WriteByte(orig)

	s := new(Scanner).Init(&buf)
	s.Mode = 0
	s.Whitespace = ws
	tok := s.Scan()
	if tok != orig {
		t.Errorf("tok = %s, want %s", TokenString(tok), TokenString(orig))
	}
}

func testError(t *testing.T, src, pos, msg string, tok rune) {
	s := new(Scanner).Init(strings.NewReader(src))
	errorCalled := false
	s.Error = func(s *Scanner, m string) {
		if !errorCalled {
			// only look at first error
			if p := s.Pos().String(); p != pos {
				t.Errorf("pos = %q, want %q for %q", p, pos, src)
			}
			if m != msg {
				t.Errorf("msg = %q, want %q for %q", m, msg, src)
			}
			errorCalled = true
		}
	}
	tk := s.Scan()
	if tk != tok {
		t.Errorf("tok = %s, want %s for %q", TokenString(tk), TokenString(tok), src)
	}
	if !errorCalled {
		t.Errorf("error handler not called for %q", src)
	}
	if s.ErrorCount == 0 {
		t.Errorf("count = %d, want > 0 for %q", s.ErrorCount, src)
	}
}

func TestError(t *testing.T) {
	testError(t, "\x00", "<input>:1:1", "invalid character NUL", 0)
	testError(t, "\x80", "<input>:1:1", "invalid UTF-8 encoding", utf8.RuneError)
	testError(t, "\xff", "<input>:1:1", "invalid UTF-8 encoding", utf8.RuneError)

	testError(t, "a\x00", "<input>:1:2", "invalid character NUL", Ident)
	testError(t, "ab\x80", "<input>:1:3", "invalid UTF-8 encoding", Ident)
	testError(t, "abc\xff", "<input>:1:4", "invalid UTF-8 encoding", Ident)

	testError(t, `"a`+"\x00", "<input>:1:3", "invalid character NUL", String)
	testError(t, `"ab`+"\x80", "<input>:1:4", "invalid UTF-8 encoding", String)
	testError(t, `"abc`+"\xff", "<input>:1:5", "invalid UTF-8 encoding", String)

	testError(t, "`a"+"\x00", "<input>:1:3", "invalid character NUL", RawString)
	testError(t, "`ab"+"\x80", "<input>:1:4", "invalid UTF-8 encoding", RawString)
	testError(t, "`abc"+"\xff", "<input>:1:5", "invalid UTF-8 encoding", RawString)

	testError(t, `'\"'`, "<input>:1:3", "invalid char escape", Char)
	testError(t, `"\'"`, "<input>:1:3", "invalid char escape", String)

	testError(t, `01238`, "<input>:1:6", "invalid digit '8' in octal literal", Int)
	testError(t, `01238123`, "<input>:1:9", "invalid digit '8' in octal literal", Int)
	testError(t, `0x`, "<input>:1:3", "hexadecimal literal has no digits", Int)
	testError(t, `0xg`, "<input>:1:3", "hexadecimal literal has no digits", Int)
	testError(t, `'aa'`, "<input>:1:4", "invalid char literal", Char)
	testError(t, `1.5e`, "<input>:1:5", "exponent has no digits", Float)
	testError(t, `1.5E`, "<input>:1:5", "exponent has no digits", Float)
	testError(t, `1.5e+`, "<input>:1:6", "exponent has no digits", Float)
	testError(t, `1.5e-`, "<input>:1:6", "exponent has no digits", Float)

	testError(t, `'`, "<input>:1:2", "literal not terminated", Char)
	testError(t, `'`+"\n", "<input>:1:2", "literal not terminated", Char)
	testError(t, `"abc`, "<input>:1:5", "literal not terminated", String)
	testError(t, `"abc`+"\n", "<input>:1:5", "literal not terminated", String)
	testError(t, "`abc\n", "<input>:2:1", "literal not terminated", RawString)
	testError(t, `/*/`, "<input>:1:4", "comment not terminated", EOF)
}

// An errReader returns (0, err) where err is not io.EOF.
type errReader struct{}

func (errReader) Read(b []byte) (int, error) {
	return 0, io.ErrNoProgress // some error that is not io.EOF
}

func TestIOError(t *testing.T) {
	s := new(Scanner).Init(errReader{})
	errorCalled := false
	s.Error = func(s *Scanner, msg string) {
		if !errorCalled {
			if want := io.ErrNoProgress.Error(); msg != want {
				t.Errorf("msg = %q, want %q", msg, want)
			}
			errorCalled = true
		}
	}
	tok := s.Scan()
	if tok != EOF {
		t.Errorf("tok = %s, want EOF", TokenString(tok))
	}
	if !errorCalled {
		t.Errorf("error handler not called")
	}
}

func checkPos(t *testing.T, got, want Position) {
	if got.Offset != want.Offset || got.Line != want.Line || got.Column != want.Column {
		t.Errorf("got offset, line, column = %d, %d, %d; want %d, %d, %d",
			got.Offset, got.Line, got.Column, want.Offset, want.Line, want.Column)
	}
}

func checkNextPos(t *testing.T, s *Scanner, offset, line, column int, char rune) {
	if ch := s.Next(); ch != char {
		t.Errorf("ch = %s, want %s", TokenString(ch), TokenString(char))
	}
	want := Position{Offset: offset, Line: line, Column: column}
	checkPos(t, s.Pos(), want)
}

func checkScanPos(t *testing.T, s *Scanner, offset, line, column int, char rune) {
	want := Position{Offset: offset, Line: line, Column: column}
	checkPos(t, s.Pos(), want)
	if ch := s.Scan(); ch != char {
		t.Errorf("ch = %s, want %s", TokenString(ch), TokenString(char))
		if string(ch) != s.TokenText() {
			t.Errorf("tok = %q, want %q", s.TokenText(), string(ch))
		}
	}
	checkPos(t, s.Position, want)
}

func TestPos(t *testing.T) {
	// corner case: empty source
	s := new(Scanner).Init(strings.NewReader(""))
	checkPos(t, s.Pos(), Position{Offset: 0, Line: 1, Column: 1})
	s.Peek() // peek doesn't affect the position
	checkPos(t, s.Pos(), Position{Offset: 0, Line: 1, Column: 1})

	// corner case: source with only a newline
	s = new(Scanner).Init(strings.NewReader("\n"))
	checkPos(t, s.Pos(), Position{Offset: 0, Line: 1, Column: 1})
	checkNextPos(t, s, 1, 2, 1, '\n')
	// after EOF position doesn't change
	for i := 10; i > 0; i-- {
		checkScanPos(t, s, 1, 2, 1, EOF)
	}
	if s.ErrorCount != 0 {
		t.Errorf("%d errors", s.ErrorCount)
	}

	// corner case: source with only a single character
	s = new(Scanner).Init(strings.NewReader("本"))
	checkPos(t, s.Pos(), Position{Offset: 0, Line: 1, Column: 1})
	checkNextPos(t, s, 3, 1, 2, '本')
	// after EOF position doesn't change
	for i := 10; i > 0; i-- {
		checkScanPos(t, s, 3, 1, 2, EOF)
	}
	if s.ErrorCount != 0 {
		t.Errorf("%d errors", s.ErrorCount)
	}

	// positions after calling Next
	s = new(Scanner).Init(strings.NewReader("  foo६४  \n\n本語\n"))
	checkNextPos(t, s, 1, 1, 2, ' ')
	s.Peek() // peek doesn't affect the position
	checkNextPos(t, s, 2, 1, 3, ' ')
	checkNextPos(t, s, 3, 1, 4, 'f')
	checkNextPos(t, s, 4, 1, 5, 'o')
	checkNextPos(t, s, 5, 1, 6, 'o')
	checkNextPos(t, s, 8, 1, 7, '६')
	checkNextPos(t, s, 11, 1, 8, '४')
	checkNextPos(t, s, 12, 1, 9, ' ')
	checkNextPos(t, s, 13, 1, 10, ' ')
	checkNextPos(t, s, 14, 2, 1, '\n')
	checkNextPos(t, s, 15, 3, 1, '\n')
	checkNextPos(t, s, 18, 3, 2, '本')
	checkNextPos(t, s, 21, 3, 3, '語')
	checkNextPos(t, s, 22, 4, 1, '\n')
	// after EOF position doesn't change
	for i := 10; i > 0; i-- {
		checkScanPos(t, s, 22, 4, 1, EOF)
	}
	if s.ErrorCount != 0 {
		t.Errorf("%d errors", s.ErrorCount)
	}

	// positions after calling Scan
	s = new(Scanner).Init(strings.NewReader("abc\n本語\n\nx"))
	s.Mode = 0
	s.Whitespace = 0
	checkScanPos(t, s, 0, 1, 1, 'a')
	s.Peek() // peek doesn't affect the position
	checkScanPos(t, s, 1, 1, 2, 'b')
	checkScanPos(t, s, 2, 1, 3, 'c')
	checkScanPos(t, s, 3, 1, 4, '\n')
	checkScanPos(t, s, 4, 2, 1, '本')
	checkScanPos(t, s, 7, 2, 2, '語')
	checkScanPos(t, s, 10, 2, 3, '\n')
	checkScanPos(t, s, 11, 3, 1, '\n')
	checkScanPos(t, s, 12, 4, 1, 'x')
	// after EOF position doesn't change
	for i := 10; i > 0; i-- {
		checkScanPos(t, s, 13, 4, 2, EOF)
	}
	if s.ErrorCount != 0 {
		t.Errorf("%d errors", s.ErrorCount)
	}
}

type countReader int

func (r *countReader) Read([]byte) (int, error) {
	*r++
	return 0, io.EOF
}

func TestNextEOFHandling(t *testing.T) {
	var r countReader

	// corner case: empty source
	s := new(Scanner).Init(&r)

	tok := s.Next()
	if tok != EOF {
		t.Error("1) EOF not reported")
	}

	tok = s.Peek()
	if tok != EOF {
		t.Error("2) EOF not reported")
	}

	if r != 1 {
		t.Errorf("scanner called Read %d times, not once", r)
	}
}

func TestScanEOFHandling(t *testing.T) {
	var r countReader

	// corner case: empty source
	s := new(Scanner).Init(&r)

	tok := s.Scan()
	if tok != EOF {
		t.Error("1) EOF not reported")
	}

	tok = s.Peek()
	if tok != EOF {
		t.Error("2) EOF not reported")
	}

	if r != 1 {
		t.Errorf("scanner called Read %d times, not once", r)
	}
}

func TestIssue29723(t *testing.T) {
	s := new(Scanner).Init(strings.NewReader(`x "`))
	s.Error = func(s *Scanner, _ string) {
		got := s.TokenText() // this call shouldn't panic
		const want = `"`
		if got != want {
			t.Errorf("got %q; want %q", got, want)
		}
	}
	for r := s.Scan(); r != EOF; r = s.Scan() {
	}
}

func TestNumbers(t *testing.T) {
	for _, test := range []struct {
		tok              rune
		src, tokens, err string
	}{
		// binaries
		{Int, "0b0", "0b0", ""},
		{Int, "0b1010", "0b1010", ""},
		{Int, "0B1110", "0B1110", ""},

		{Int, "0b", "0b", "binary literal has no digits"},
		{Int, "0b0190", "0b0190", "invalid digit '9' in binary literal"},
		{Int, "0b01a0", "0b01 a0", ""}, // only accept 0-9

		// binary floats (invalid)
		{Float, "0b.", "0b.", "invalid radix point in binary literal"},
		{Float, "0b.1", "0b.1", "invalid radix point in binary literal"},
		{Float, "0b1.0", "0b1.0", "invalid radix point in binary literal"},
		{Float, "0b1e10", "0b1e10", "'e' exponent requires decimal mantissa"},
		{Float, "0b1P-1", "0b1P-1", "'P' exponent requires hexadecimal mantissa"},

		// octals
		{Int, "0o0", "0o0", ""},
		{Int, "0o1234", "0o1234", ""},
		{Int, "0O1234", "0O1234", ""},

		{Int, "0o", "0o", "octal literal has no digits"},
		{Int, "0o8123", "0o8123", "invalid digit '8' in octal literal"},
		{Int, "0o1293", "0o1293", "invalid digit '9' in octal literal"},
		{Int, "0o12a3", "0o12 a3", ""}, // only accept 0-9

		// octal floats (invalid)
		{Float, "0o.", "0o.", "invalid radix point in octal literal"},
		{Float, "0o.2", "0o.2", "invalid radix point in octal literal"},
		{Float, "0o1.2", "0o1.2", "invalid radix point in octal literal"},
		{Float, "0o1E+2", "0o1E+2", "'E' exponent requires decimal mantissa"},
		{Float, "0o1p10", "0o1p10", "'p' exponent requires hexadecimal mantissa"},

		// 0-octals
		{Int, "0", "0", ""},
		{Int, "0123", "0123", ""},

		{Int, "08123", "08123", "invalid digit '8' in octal literal"},
		{Int, "01293", "01293", "invalid digit '9' in octal literal"},
		{Int, "0F.", "0 F .", ""}, // only accept 0-9
		{Int, "0123F.", "0123 F .", ""},
		{Int, "0123456x", "0123456 x", ""},

		// decimals
		{Int, "1", "1", ""},
		{Int, "1234", "1234", ""},

		{Int, "1f", "1 f", ""}, // only accept 0-9

		// decimal floats
		{Float, "0.", "0.", ""},
		{Float, "123.", "123.", ""},
		{Float, "0123.", "0123.", ""},

		{Float, ".0", ".0", ""},
		{Float, ".123", ".123", ""},
		{Float, ".0123", ".0123", ""},

		{Float, "0.0", "0.0", ""},
		{Float, "123.123", "123.123", ""},
		{Float, "0123.0123", "0123.0123", ""},

		{Float, "0e0", "0e0", ""},
		{Float, "123e+0", "123e+0", ""},
		{Float, "0123E-1", "0123E-1", ""},

		{Float, "0.e+1", "0.e+1", ""},
		{Float, "123.E-10", "123.E-10", ""},
		{Float, "0123.e123", "0123.e123", ""},

		{Float, ".0e-1", ".0e-1", ""},
		{Float, ".123E+10", ".123E+10", ""},
		{Float, ".0123E123", ".0123E123", ""},

		{Float, "0.0e1", "0.0e1", ""},
		{Float, "123.123E-10", "123.123E-10", ""},
		{Float, "0123.0123e+456", "0123.0123e+456", ""},

		{Float, "0e", "0e", "exponent has no digits"},
		{Float, "0E+", "0E+", "exponent has no digits"},
		{Float, "1e+f", "1e+ f", "exponent has no digits"},
		{Float, "0p0", "0p0", "'p' exponent requires hexadecimal mantissa"},
		{Float, "1.0P-1", "1.0P-1", "'P' exponent requires hexadecimal mantissa"},

		// hexadecimals
		{Int, "0x0", "0x0", ""},
		{Int, "0x1234", "0x1234", ""},
		{Int, "0xcafef00d", "0xcafef00d", ""},
		{Int, "0XCAFEF00D", "0XCAFEF00D", ""},

		{Int, "0x", "0x", "hexadecimal literal has no digits"},
		{Int, "0x1g", "0x1 g", ""},

		// hexadecimal floats
		{Float, "0x0p0", "0x0p0", ""},
		{Float, "0x12efp-123", "0x12efp-123", ""},
		{Float, "0xABCD.p+0", "0xABCD.p+0", ""},
		{Float, "0x.0189P-0", "0x.0189P-0", ""},
		{Float, "0x1.ffffp+1023", "0x1.ffffp+1023", ""},

		{Float, "0x.", "0x.", "hexadecimal literal has no digits"},
		{Float, "0x0.", "0x0.", "hexadecimal mantissa requires a 'p' exponent"},
		{Float, "0x.0", "0x.0", "hexadecimal mantissa requires a 'p' exponent"},
		{Float, "0x1.1", "0x1.1", "hexadecimal mantissa requires a 'p' exponent"},
		{Float, "0x1.1e0", "0x1.1e0", "hexadecimal mantissa requires a 'p' exponent"},
		{Float, "0x1.2gp1a", "0x1.2 gp1a", "hexadecimal mantissa requires a 'p' exponent"},
		{Float, "0x0p", "0x0p", "exponent has no digits"},
		{Float, "0xeP-", "0xeP-", "exponent has no digits"},
		{Float, "0x1234PAB", "0x1234P AB", "exponent has no digits"},
		{Float, "0x1.2p1a", "0x1.2p1 a", ""},

		// separators
		{Int, "0b_1000_0001", "0b_1000_0001", ""},
		{Int, "0o_600", "0o_600", ""},
		{Int, "0_466", "0_466", ""},
		{Int, "1_000", "1_000", ""},
		{Float, "1_000.000_1", "1_000.000_1", ""},
		{Int, "0x_f00d", "0x_f00d", ""},
		{Float, "0x_f00d.0p1_2", "0x_f00d.0p1_2", ""},

		{Int, "0b__1000", "0b__1000", "'_' must separate successive digits"},
		{Int, "0o60___0", "0o60___0", "'_' must separate successive digits"},
		{Int, "0466_", "0466_", "'_' must separate successive digits"},
		{Float, "1_.", "1_.", "'_' must separate successive digits"},
		{Float, "0._1", "0._1", "'_' must separate successive digits"},
		{Float, "2.7_e0", "2.7_e0", "'_' must separate successive digits"},
		{Int, "0x___0", "0x___0", "'_' must separate successive digits"},
		{Float, "0x1.0_p0", "0x1.0_p0", "'_' must separate successive digits"},
	} {
		s := new(Scanner).Init(strings.NewReader(test.src))
		var err string
		s.Error = func(s *Scanner, msg string) {
			if err == "" {
				err = msg
			}
		}

		for i, want := range strings.Split(test.tokens, " ") {
			err = ""
			tok := s.Scan()
			lit := s.TokenText()
			if i == 0 {
				if tok != test.tok {
					t.Errorf("%q: got token %s; want %s", test.src, TokenString(tok), TokenString(test.tok))
				}
				if err != test.err {
					t.Errorf("%q: got error %q; want %q", test.src, err, test.err)
				}
			}
			if lit != want {
				t.Errorf("%q: got literal %q (%s); want %s", test.src, lit, TokenString(tok), want)
			}
		}

		// make sure we read all
		if tok := s.Scan(); tok != EOF {
			t.Errorf("%q: got %s; want EOF", test.src, TokenString(tok))
		}
	}
}

func TestIssue30320(t *testing.T) {
	for _, test := range []struct {
		in, want string
		mode     uint
	}{
		{"foo01.bar31.xx-0-1-1-0", "01 31 0 1 1 0", ScanInts},
		{"foo0/12/0/5.67", "0 12 0 5 67", ScanInts},
		{"xxx1e0yyy", "1 0", ScanInts},
		{"1_2", "1_2", ScanInts},
		{"xxx1.0yyy2e3ee", "1 0 2 3", ScanInts},
		{"xxx1.0yyy2e3ee", "1.0 2e3", ScanFloats},
	} {
		got := extractInts(test.in, test.mode)
		if got != test.want {
			t.Errorf("%q: got %q; want %q", test.in, got, test.want)
		}
	}
}

func extractInts(t string, mode uint) (res string) {
	var s Scanner
	s.Init(strings.NewReader(t))
	s.Mode = mode
	for {
		switch tok := s.Scan(); tok {
		case Int, Float:
			if len(res) > 0 {
				res += " "
			}
			res += s.TokenText()
		case EOF:
			return
		}
	}
}

func TestIssue50909(t *testing.T) {
	var s Scanner
	s.Init(strings.NewReader("hello \n\nworld\n!\n"))
	s.IsIdentRune = func(ch rune, _ int) bool { return ch != '\n' }

	r := ""
	n := 0
	for s.Scan() != EOF && n < 10 {
		r += s.TokenText()
		n++
	}

	const R = "hello world!"
	const N = 3
	if r != R || n != N {
		t.Errorf("got %q (n = %d); want %q (n = %d)", r, n, R, N)
	}
}

"""



```