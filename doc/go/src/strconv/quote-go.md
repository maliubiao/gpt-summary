Response:
我的目标是理解并解释给定的 Go 源代码文件 `quote.go` 的功能。我的思考过程如下：

1. **概览文件头部的注释：**  文件头部的版权声明和 `//go:generate go run makeisprint.go -output isprint.go` 注释提供了重要的上下文信息。`makeisprint.go` 的存在暗示了 `isprint.go` 文件是自动生成的，并且可能与字符的打印属性有关。

2. **识别核心数据结构和常量：** `lowerhex` 和 `upperhex` 字符串暗示了十六进制编码的功能。

3. **逐个分析函数的功能：**

    * **`contains(s string, c byte) bool`**: 这是一个简单的辅助函数，用于检查字符串是否包含特定的字节。
    * **`quoteWith(s string, quote byte, ASCIIonly, graphicOnly bool) string`**: 函数名暗示了它用指定的引号包裹字符串，并且可能基于 `ASCIIonly` 和 `graphicOnly` 参数进行不同的转义处理。  这可能是核心的“引用”功能。
    * **`quoteRuneWith(r rune, quote byte, ASCIIonly, graphicOnly bool) string`**:  类似 `quoteWith`，但处理的是单个 `rune`（Go 中的 Unicode 字符）。
    * **`appendQuotedWith(buf []byte, s string, quote byte, ASCIIonly, graphicOnly bool) []byte`**:  这是一个将引用后的字符串追加到字节切片的函数。以 "append" 开头的函数通常用于避免不必要的内存分配。
    * **`appendQuotedRuneWith(buf []byte, r rune, quote byte, ASCIIonly, graphicOnly bool) []byte`**: 类似 `appendQuotedWith`，但处理单个 `rune`。
    * **`appendEscapedRune(buf []byte, r rune, quote byte, ASCIIonly, graphicOnly bool) []byte`**: 这个函数负责实际的转义逻辑。它根据字符的值和传入的标志来决定如何将其表示为转义序列或直接添加到缓冲区。关键的判断条件是字符是否等于引号，是否是反斜杠，以及是否满足 `ASCIIonly` 或 `graphicOnly` 的条件。
    * **`Quote(s string) string`**: 使用双引号调用 `quoteWith`，并且 `ASCIIonly` 和 `graphicOnly` 都是 `false`。这暗示了这是最常用的字符串引用方式。
    * **`AppendQuote(dst []byte, s string) []byte`**:  使用双引号调用 `appendQuotedWith`，参数与 `Quote` 一致。
    * **`QuoteToASCII(s string) string`**: 类似 `Quote`，但 `ASCIIonly` 为 `true`，意味着非 ASCII 字符会被转义。
    * **`AppendQuoteToASCII(dst []byte, s string) []byte`**: 类似 `AppendQuote`, 但 `ASCIIonly` 为 `true`.
    * **`QuoteToGraphic(s string) string`**:  类似 `Quote`，但 `graphicOnly` 为 `true`，意味着非图形字符会被转义。
    * **`AppendQuoteToGraphic(dst []byte, s string) []byte`**: 类似 `AppendQuote`, 但 `graphicOnly` 为 `true`.
    * **`QuoteRune(r rune) string`**: 使用单引号调用 `quoteRuneWith`，参数与 `Quote` 一致。
    * **`AppendQuoteRune(dst []byte, r rune) []byte`**: 使用单引号调用 `appendQuotedRuneWith`，参数与 `Quote` 一致。
    * **`QuoteRuneToASCII(r rune) string`**: 类似 `QuoteRune`，但 `ASCIIonly` 为 `true`.
    * **`AppendQuoteRuneToASCII(dst []byte, r rune) []byte`**: 类似 `AppendQuoteRune`, 但 `ASCIIonly` 为 `true`.
    * **`QuoteRuneToGraphic(r rune) string`**: 类似 `QuoteRune`，但 `graphicOnly` 为 `true`.
    * **`AppendQuoteRuneToGraphic(dst []byte, r rune) []byte`**: 类似 `AppendQuoteRune`, 但 `graphicOnly` 为 `true`.
    * **`CanBackquote(s string) bool`**:  检查字符串是否可以使用反引号（raw string literal）表示。
    * **`unhex(b byte) (v rune, ok bool)`**: 将单个十六进制字符转换为数字。
    * **`UnquoteChar(s string, quote byte) (value rune, multibyte bool, tail string, err error)`**: 解码转义字符串中的第一个字符。
    * **`QuotedPrefix(s string) (string, error)`**: 提取字符串中带引号的前缀。
    * **`Unquote(s string) (string, error)`**:  核心的“反引用”功能，将带引号的字符串或字符字面量转换为其原始值。
    * **`unquote(in string, unescape bool) (out, rem string, err error)`**:  `Unquote` 的底层实现，可以选择是否进行转义。
    * **`bsearch[S ~[]E, E ~uint16 | ~uint32](s S, v E) (int, bool)`**:  一个私有的二分查找函数。
    * **`IsPrint(r rune) bool`**: 判断一个 rune 是否是可打印字符。
    * **`IsGraphic(r rune) bool`**: 判断一个 rune 是否是图形字符。
    * **`isInGraphicList(r rune) bool`**:  辅助 `IsGraphic` 判断的函数。

4. **推理 Go 语言功能实现：**  通过分析这些函数，可以推断出 `quote.go` 文件实现了 Go 语言中字符串和字符字面量的引用和反引用功能。这包括：
    * **普通双引号字符串的引用和反引用** (`Quote`, `AppendQuote`, `Unquote`).
    * **单引号字符字面量的引用和反引用** (`QuoteRune`, `AppendQuoteRune`, `Unquote`).
    * **反引号原始字符串的判断** (`CanBackquote`).
    * **控制字符和非打印字符的转义** (在 `appendEscapedRune` 中实现).
    * **根据 ASCII 或 Graphic 属性进行不同的引用方式** (`QuoteToASCII`, `QuoteToGraphic` 及其对应的 Append 函数).

5. **构建代码示例：**  基于推理出的功能，编写示例代码来演示 `Quote` 和 `Unquote` 的用法，并展示不同引用方式的区别。

6. **推断命令行参数处理：**  由于代码中没有直接涉及 `os.Args` 或其他命令行参数解析的代码，可以判断该文件主要处理字符串操作，而不是命令行参数。 `//go:generate` 指令是构建过程的一部分，但不是运行时接受的参数。

7. **考虑易犯错误点：**  思考使用这些函数时可能出现的错误，例如混淆不同类型的引号、不理解转义序列等。

8. **组织答案：** 将分析结果组织成清晰的中文描述，包括功能列表、Go 语言功能实现说明、代码示例、命令行参数说明以及易犯错误点。  尤其注意将代码示例的输入、函数调用和输出明确列出，方便理解。

通过以上思考过程，我能够理解 `quote.go` 文件的功能，并生成最终的答案。  关键在于理解每个函数的作用，将它们组合起来理解整体功能，并结合 Go 语言的特性进行推断。

这段 Go 语言代码文件 `go/src/strconv/quote.go` 的主要功能是**实现 Go 语言中字符串和字符字面量的引用（quoting）和反引用（unquoting）操作**。

具体来说，它提供了以下功能：

1. **字符串引用 (Quoting Strings):**
   - `Quote(s string) string`: 将字符串 `s` 转换为双引号包围的 Go 字符串字面量。非 ASCII 字符和控制字符会被转义。
   - `AppendQuote(dst []byte, s string) []byte`:  与 `Quote` 类似，但将结果追加到字节切片 `dst` 中。
   - `QuoteToASCII(s string) string`: 将字符串 `s` 转换为双引号包围的 Go 字符串字面量。所有非 ASCII 字符和控制字符都会被转义成 ASCII 转义序列（如 `\u0100`）。
   - `AppendQuoteToASCII(dst []byte, s string) []byte`: 与 `QuoteToASCII` 类似，但将结果追加到字节切片。
   - `QuoteToGraphic(s string) string`: 将字符串 `s` 转换为双引号包围的 Go 字符串字面量。只有非图形字符（由 `unicode.IsGraphic` 定义）才会被转义。
   - `AppendQuoteToGraphic(dst []byte, s string) []byte`: 与 `QuoteToGraphic` 类似，但将结果追加到字节切片。

2. **字符引用 (Quoting Runes):**
   - `QuoteRune(r rune) string`: 将 rune `r` 转换为单引号包围的 Go 字符字面量。非 ASCII 字符和控制字符会被转义。
   - `AppendQuoteRune(dst []byte, r rune) []byte`: 与 `QuoteRune` 类似，但将结果追加到字节切片 `dst` 中。
   - `QuoteRuneToASCII(r rune) string`: 将 rune `r` 转换为单引号包围的 Go 字符字面量。所有非 ASCII 字符和控制字符都会被转义成 ASCII 转义序列。
   - `AppendQuoteRuneToASCII(dst []byte, r rune) []byte`: 与 `QuoteRuneToASCII` 类似，但将结果追加到字节切片。
   - `QuoteRuneToGraphic(r rune) string`: 将 rune `r` 转换为单引号包围的 Go 字符字面量。只有非图形字符才会被转义。
   - `AppendQuoteRuneToGraphic(dst []byte, r rune) []byte`: 与 `QuoteRuneToGraphic` 类似，但将结果追加到字节切片。

3. **反引号字符串判断:**
   - `CanBackquote(s string) bool`: 判断字符串 `s` 是否可以使用反引号（`` ` ``）括起来，而无需任何转义。这通常用于包含多行或特殊字符的字符串。

4. **字符反引用 (Unquoting Characters):**
   - `UnquoteChar(s string, quote byte) (value rune, multibyte bool, tail string, err error)`:  解析一个被引号包围的字符或转义序列，返回其值、是否是多字节字符以及剩余的字符串。`quote` 参数指定了引号的类型（单引号或双引号）。

5. **字符串反引用 (Unquoting Strings):**
   - `Unquote(s string) (string, error)`:  解析一个被单引号、双引号或反引号包围的 Go 字符串字面量，返回其原始值。

**它是什么 Go 语言功能的实现：**

这段代码是 `strconv` 标准库中处理字符串和字符字面量表示形式的关键部分。它实现了 Go 语言规范中关于字符串和字符字面量的定义和解析规则，包括各种转义序列的处理。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"strconv"
)

func main() {
	// 字符串引用
	str := "Hello\nWorld!\t你好"
	quotedStr := strconv.Quote(str)
	fmt.Println("Quoted string:", quotedStr) // 输出: Quoted string: "Hello\nWorld!\t你好"

	asciiQuotedStr := strconv.QuoteToASCII(str)
	fmt.Println("ASCII quoted string:", asciiQuotedStr) // 输出: ASCII quoted string: "Hello\\nWorld!\\t\\xe4\\xbd\\xa0\\xe5\\xa5\\xbd"

	graphicQuotedStr := strconv.QuoteToGraphic(str)
	fmt.Println("Graphic quoted string:", graphicQuotedStr) // 输出: Graphic quoted string: "Hello\\nWorld!\\t你好"

	// 字符引用
	char := '你'
	quotedChar := strconv.QuoteRune(char)
	fmt.Println("Quoted rune:", quotedChar) // 输出: Quoted rune: '你'

	asciiQuotedChar := strconv.QuoteRuneToASCII(char)
	fmt.Println("ASCII quoted rune:", asciiQuotedChar) // 输出: ASCII quoted rune: '\xe4'

	// 字符串反引用
	unquotedStr, err := strconv.Unquote(quotedStr)
	if err != nil {
		fmt.Println("Unquote error:", err)
	} else {
		fmt.Println("Unquoted string:", unquotedStr) // 输出: Unquoted string: Hello
                                                     //                    World!	你好
	}

	// 反引号判断
	canBackquote := strconv.CanBackquote("This is a `raw` string.")
	fmt.Println("Can backquote:", canBackquote) // 输出: Can backquote: true
	canBackquote = strconv.CanBackquote("This has a newline.\n")
	fmt.Println("Can backquote:", canBackquote) // 输出: Can backquote: false
}
```

**假设的输入与输出：**

* **`Quote("你好\"世界")`**:
    * **输入:** `"你好\"世界"`
    * **输出:** `"\xe4\xbd\xa0\xe5\xa5\xbd\"世界"` （双引号会被转义）
* **`QuoteRune('\n')`**:
    * **输入:** `'\n'`
    * **输出:** `'\n'`
* **`Unquote("\"Hello\\nWorld\"")`**:
    * **输入:** `"Hello\\nWorld"`
    * **输出:** `"Hello\nWorld"`, `nil` (错误为 nil)
* **`Unquote("'A'")`**:
    * **输入:** `'A'`
    * **输出:** `"A"`, `nil`
* **`Unquote("`Raw string with\nnewline`")`**:
    * **输入:** `` `Raw string with\nnewline` ``
    * **输出:** `"Raw string with\nnewline"`, `nil`

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。它是一个提供字符串和字符引用/反引用功能的库。命令行参数的处理通常发生在 `main` 函数中，并使用 `os` 包或 `flag` 包等。

**使用者易犯错的点：**

1. **混淆不同类型的引号：**  容易混淆单引号（用于字符字面量）、双引号（用于普通字符串字面量）和反引号（用于原始字符串字面量）的用法和转义规则。例如，尝试用 `Unquote` 解析一个未转义的反引号字符串。

   ```go
   quoted := "`This is a raw string`"
   unquoted, err := strconv.Unquote(quoted)
   fmt.Println(unquoted, err) // 输出: This is a raw string <nil>

   quotedWrong := "This is a raw string" // 没有引号
   unquotedWrong, errWrong := strconv.Unquote(quotedWrong)
   fmt.Println(unquotedWrong, errWrong) // 输出:  strconv.ErrSyntax
   ```

2. **不理解转义序列：**  对 Go 语言中的转义序列不熟悉，可能导致在处理包含转义字符的字符串时出现错误。例如，忘记双引号字符串中的双引号需要转义 (`\"`)。

   ```go
   str := "This string has a \"quote\" inside."
   quoted := strconv.Quote(str)
   fmt.Println(quoted) // 输出: "This string has a \"quote\" inside."
   ```

3. **在应该使用 `QuoteToASCII` 的时候使用了 `Quote`：** 如果需要确保输出的字符串只包含 ASCII 字符，应该使用 `QuoteToASCII`，否则可能会出现非 ASCII 字符。

   ```go
   str := "你好"
   quoted := strconv.Quote(str)
   fmt.Println(quoted)        // 输出: "你好"
   asciiQuoted := strconv.QuoteToASCII(str)
   fmt.Println(asciiQuoted) // 输出: "\xe4\xbd\xa0\xe5\xa5\xbd"
   ```

总而言之，`go/src/strconv/quote.go` 文件提供了一组强大的工具，用于在 Go 语言中安全且正确地表示和解析字符串和字符字面量。理解其各种函数的功能和适用场景对于编写可靠的 Go 代码至关重要。

Prompt: 
```
这是路径为go/src/strconv/quote.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate go run makeisprint.go -output isprint.go

package strconv

import (
	"unicode/utf8"
)

const (
	lowerhex = "0123456789abcdef"
	upperhex = "0123456789ABCDEF"
)

// contains reports whether the string contains the byte c.
func contains(s string, c byte) bool {
	return index(s, c) != -1
}

func quoteWith(s string, quote byte, ASCIIonly, graphicOnly bool) string {
	return string(appendQuotedWith(make([]byte, 0, 3*len(s)/2), s, quote, ASCIIonly, graphicOnly))
}

func quoteRuneWith(r rune, quote byte, ASCIIonly, graphicOnly bool) string {
	return string(appendQuotedRuneWith(nil, r, quote, ASCIIonly, graphicOnly))
}

func appendQuotedWith(buf []byte, s string, quote byte, ASCIIonly, graphicOnly bool) []byte {
	// Often called with big strings, so preallocate. If there's quoting,
	// this is conservative but still helps a lot.
	if cap(buf)-len(buf) < len(s) {
		nBuf := make([]byte, len(buf), len(buf)+1+len(s)+1)
		copy(nBuf, buf)
		buf = nBuf
	}
	buf = append(buf, quote)
	for width := 0; len(s) > 0; s = s[width:] {
		r := rune(s[0])
		width = 1
		if r >= utf8.RuneSelf {
			r, width = utf8.DecodeRuneInString(s)
		}
		if width == 1 && r == utf8.RuneError {
			buf = append(buf, `\x`...)
			buf = append(buf, lowerhex[s[0]>>4])
			buf = append(buf, lowerhex[s[0]&0xF])
			continue
		}
		buf = appendEscapedRune(buf, r, quote, ASCIIonly, graphicOnly)
	}
	buf = append(buf, quote)
	return buf
}

func appendQuotedRuneWith(buf []byte, r rune, quote byte, ASCIIonly, graphicOnly bool) []byte {
	buf = append(buf, quote)
	if !utf8.ValidRune(r) {
		r = utf8.RuneError
	}
	buf = appendEscapedRune(buf, r, quote, ASCIIonly, graphicOnly)
	buf = append(buf, quote)
	return buf
}

func appendEscapedRune(buf []byte, r rune, quote byte, ASCIIonly, graphicOnly bool) []byte {
	if r == rune(quote) || r == '\\' { // always backslashed
		buf = append(buf, '\\')
		buf = append(buf, byte(r))
		return buf
	}
	if ASCIIonly {
		if r < utf8.RuneSelf && IsPrint(r) {
			buf = append(buf, byte(r))
			return buf
		}
	} else if IsPrint(r) || graphicOnly && isInGraphicList(r) {
		return utf8.AppendRune(buf, r)
	}
	switch r {
	case '\a':
		buf = append(buf, `\a`...)
	case '\b':
		buf = append(buf, `\b`...)
	case '\f':
		buf = append(buf, `\f`...)
	case '\n':
		buf = append(buf, `\n`...)
	case '\r':
		buf = append(buf, `\r`...)
	case '\t':
		buf = append(buf, `\t`...)
	case '\v':
		buf = append(buf, `\v`...)
	default:
		switch {
		case r < ' ' || r == 0x7f:
			buf = append(buf, `\x`...)
			buf = append(buf, lowerhex[byte(r)>>4])
			buf = append(buf, lowerhex[byte(r)&0xF])
		case !utf8.ValidRune(r):
			r = 0xFFFD
			fallthrough
		case r < 0x10000:
			buf = append(buf, `\u`...)
			for s := 12; s >= 0; s -= 4 {
				buf = append(buf, lowerhex[r>>uint(s)&0xF])
			}
		default:
			buf = append(buf, `\U`...)
			for s := 28; s >= 0; s -= 4 {
				buf = append(buf, lowerhex[r>>uint(s)&0xF])
			}
		}
	}
	return buf
}

// Quote returns a double-quoted Go string literal representing s. The
// returned string uses Go escape sequences (\t, \n, \xFF, \u0100) for
// control characters and non-printable characters as defined by
// [IsPrint].
func Quote(s string) string {
	return quoteWith(s, '"', false, false)
}

// AppendQuote appends a double-quoted Go string literal representing s,
// as generated by [Quote], to dst and returns the extended buffer.
func AppendQuote(dst []byte, s string) []byte {
	return appendQuotedWith(dst, s, '"', false, false)
}

// QuoteToASCII returns a double-quoted Go string literal representing s.
// The returned string uses Go escape sequences (\t, \n, \xFF, \u0100) for
// non-ASCII characters and non-printable characters as defined by [IsPrint].
func QuoteToASCII(s string) string {
	return quoteWith(s, '"', true, false)
}

// AppendQuoteToASCII appends a double-quoted Go string literal representing s,
// as generated by [QuoteToASCII], to dst and returns the extended buffer.
func AppendQuoteToASCII(dst []byte, s string) []byte {
	return appendQuotedWith(dst, s, '"', true, false)
}

// QuoteToGraphic returns a double-quoted Go string literal representing s.
// The returned string leaves Unicode graphic characters, as defined by
// [IsGraphic], unchanged and uses Go escape sequences (\t, \n, \xFF, \u0100)
// for non-graphic characters.
func QuoteToGraphic(s string) string {
	return quoteWith(s, '"', false, true)
}

// AppendQuoteToGraphic appends a double-quoted Go string literal representing s,
// as generated by [QuoteToGraphic], to dst and returns the extended buffer.
func AppendQuoteToGraphic(dst []byte, s string) []byte {
	return appendQuotedWith(dst, s, '"', false, true)
}

// QuoteRune returns a single-quoted Go character literal representing the
// rune. The returned string uses Go escape sequences (\t, \n, \xFF, \u0100)
// for control characters and non-printable characters as defined by [IsPrint].
// If r is not a valid Unicode code point, it is interpreted as the Unicode
// replacement character U+FFFD.
func QuoteRune(r rune) string {
	return quoteRuneWith(r, '\'', false, false)
}

// AppendQuoteRune appends a single-quoted Go character literal representing the rune,
// as generated by [QuoteRune], to dst and returns the extended buffer.
func AppendQuoteRune(dst []byte, r rune) []byte {
	return appendQuotedRuneWith(dst, r, '\'', false, false)
}

// QuoteRuneToASCII returns a single-quoted Go character literal representing
// the rune. The returned string uses Go escape sequences (\t, \n, \xFF,
// \u0100) for non-ASCII characters and non-printable characters as defined
// by [IsPrint].
// If r is not a valid Unicode code point, it is interpreted as the Unicode
// replacement character U+FFFD.
func QuoteRuneToASCII(r rune) string {
	return quoteRuneWith(r, '\'', true, false)
}

// AppendQuoteRuneToASCII appends a single-quoted Go character literal representing the rune,
// as generated by [QuoteRuneToASCII], to dst and returns the extended buffer.
func AppendQuoteRuneToASCII(dst []byte, r rune) []byte {
	return appendQuotedRuneWith(dst, r, '\'', true, false)
}

// QuoteRuneToGraphic returns a single-quoted Go character literal representing
// the rune. If the rune is not a Unicode graphic character,
// as defined by [IsGraphic], the returned string will use a Go escape sequence
// (\t, \n, \xFF, \u0100).
// If r is not a valid Unicode code point, it is interpreted as the Unicode
// replacement character U+FFFD.
func QuoteRuneToGraphic(r rune) string {
	return quoteRuneWith(r, '\'', false, true)
}

// AppendQuoteRuneToGraphic appends a single-quoted Go character literal representing the rune,
// as generated by [QuoteRuneToGraphic], to dst and returns the extended buffer.
func AppendQuoteRuneToGraphic(dst []byte, r rune) []byte {
	return appendQuotedRuneWith(dst, r, '\'', false, true)
}

// CanBackquote reports whether the string s can be represented
// unchanged as a single-line backquoted string without control
// characters other than tab.
func CanBackquote(s string) bool {
	for len(s) > 0 {
		r, wid := utf8.DecodeRuneInString(s)
		s = s[wid:]
		if wid > 1 {
			if r == '\ufeff' {
				return false // BOMs are invisible and should not be quoted.
			}
			continue // All other multibyte runes are correctly encoded and assumed printable.
		}
		if r == utf8.RuneError {
			return false
		}
		if (r < ' ' && r != '\t') || r == '`' || r == '\u007F' {
			return false
		}
	}
	return true
}

func unhex(b byte) (v rune, ok bool) {
	c := rune(b)
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return
}

// UnquoteChar decodes the first character or byte in the escaped string
// or character literal represented by the string s.
// It returns four values:
//
//  1. value, the decoded Unicode code point or byte value;
//  2. multibyte, a boolean indicating whether the decoded character requires a multibyte UTF-8 representation;
//  3. tail, the remainder of the string after the character; and
//  4. an error that will be nil if the character is syntactically valid.
//
// The second argument, quote, specifies the type of literal being parsed
// and therefore which escaped quote character is permitted.
// If set to a single quote, it permits the sequence \' and disallows unescaped '.
// If set to a double quote, it permits \" and disallows unescaped ".
// If set to zero, it does not permit either escape and allows both quote characters to appear unescaped.
func UnquoteChar(s string, quote byte) (value rune, multibyte bool, tail string, err error) {
	// easy cases
	if len(s) == 0 {
		err = ErrSyntax
		return
	}
	switch c := s[0]; {
	case c == quote && (quote == '\'' || quote == '"'):
		err = ErrSyntax
		return
	case c >= utf8.RuneSelf:
		r, size := utf8.DecodeRuneInString(s)
		return r, true, s[size:], nil
	case c != '\\':
		return rune(s[0]), false, s[1:], nil
	}

	// hard case: c is backslash
	if len(s) <= 1 {
		err = ErrSyntax
		return
	}
	c := s[1]
	s = s[2:]

	switch c {
	case 'a':
		value = '\a'
	case 'b':
		value = '\b'
	case 'f':
		value = '\f'
	case 'n':
		value = '\n'
	case 'r':
		value = '\r'
	case 't':
		value = '\t'
	case 'v':
		value = '\v'
	case 'x', 'u', 'U':
		n := 0
		switch c {
		case 'x':
			n = 2
		case 'u':
			n = 4
		case 'U':
			n = 8
		}
		var v rune
		if len(s) < n {
			err = ErrSyntax
			return
		}
		for j := 0; j < n; j++ {
			x, ok := unhex(s[j])
			if !ok {
				err = ErrSyntax
				return
			}
			v = v<<4 | x
		}
		s = s[n:]
		if c == 'x' {
			// single-byte string, possibly not UTF-8
			value = v
			break
		}
		if !utf8.ValidRune(v) {
			err = ErrSyntax
			return
		}
		value = v
		multibyte = true
	case '0', '1', '2', '3', '4', '5', '6', '7':
		v := rune(c) - '0'
		if len(s) < 2 {
			err = ErrSyntax
			return
		}
		for j := 0; j < 2; j++ { // one digit already; two more
			x := rune(s[j]) - '0'
			if x < 0 || x > 7 {
				err = ErrSyntax
				return
			}
			v = (v << 3) | x
		}
		s = s[2:]
		if v > 255 {
			err = ErrSyntax
			return
		}
		value = v
	case '\\':
		value = '\\'
	case '\'', '"':
		if c != quote {
			err = ErrSyntax
			return
		}
		value = rune(c)
	default:
		err = ErrSyntax
		return
	}
	tail = s
	return
}

// QuotedPrefix returns the quoted string (as understood by [Unquote]) at the prefix of s.
// If s does not start with a valid quoted string, QuotedPrefix returns an error.
func QuotedPrefix(s string) (string, error) {
	out, _, err := unquote(s, false)
	return out, err
}

// Unquote interprets s as a single-quoted, double-quoted,
// or backquoted Go string literal, returning the string value
// that s quotes.  (If s is single-quoted, it would be a Go
// character literal; Unquote returns the corresponding
// one-character string. For '' Unquote returns the empty string.)
func Unquote(s string) (string, error) {
	out, rem, err := unquote(s, true)
	if len(rem) > 0 {
		return "", ErrSyntax
	}
	return out, err
}

// unquote parses a quoted string at the start of the input,
// returning the parsed prefix, the remaining suffix, and any parse errors.
// If unescape is true, the parsed prefix is unescaped,
// otherwise the input prefix is provided verbatim.
func unquote(in string, unescape bool) (out, rem string, err error) {
	// Determine the quote form and optimistically find the terminating quote.
	if len(in) < 2 {
		return "", in, ErrSyntax
	}
	quote := in[0]
	end := index(in[1:], quote)
	if end < 0 {
		return "", in, ErrSyntax
	}
	end += 2 // position after terminating quote; may be wrong if escape sequences are present

	switch quote {
	case '`':
		switch {
		case !unescape:
			out = in[:end] // include quotes
		case !contains(in[:end], '\r'):
			out = in[len("`") : end-len("`")] // exclude quotes
		default:
			// Carriage return characters ('\r') inside raw string literals
			// are discarded from the raw string value.
			buf := make([]byte, 0, end-len("`")-len("\r")-len("`"))
			for i := len("`"); i < end-len("`"); i++ {
				if in[i] != '\r' {
					buf = append(buf, in[i])
				}
			}
			out = string(buf)
		}
		// NOTE: Prior implementations did not verify that raw strings consist
		// of valid UTF-8 characters and we continue to not verify it as such.
		// The Go specification does not explicitly require valid UTF-8,
		// but only mention that it is implicitly valid for Go source code
		// (which must be valid UTF-8).
		return out, in[end:], nil
	case '"', '\'':
		// Handle quoted strings without any escape sequences.
		if !contains(in[:end], '\\') && !contains(in[:end], '\n') {
			var valid bool
			switch quote {
			case '"':
				valid = utf8.ValidString(in[len(`"`) : end-len(`"`)])
			case '\'':
				r, n := utf8.DecodeRuneInString(in[len("'") : end-len("'")])
				valid = len("'")+n+len("'") == end && (r != utf8.RuneError || n != 1)
			}
			if valid {
				out = in[:end]
				if unescape {
					out = out[1 : end-1] // exclude quotes
				}
				return out, in[end:], nil
			}
		}

		// Handle quoted strings with escape sequences.
		var buf []byte
		in0 := in
		in = in[1:] // skip starting quote
		if unescape {
			buf = make([]byte, 0, 3*end/2) // try to avoid more allocations
		}
		for len(in) > 0 && in[0] != quote {
			// Process the next character,
			// rejecting any unescaped newline characters which are invalid.
			r, multibyte, rem, err := UnquoteChar(in, quote)
			if in[0] == '\n' || err != nil {
				return "", in0, ErrSyntax
			}
			in = rem

			// Append the character if unescaping the input.
			if unescape {
				if r < utf8.RuneSelf || !multibyte {
					buf = append(buf, byte(r))
				} else {
					buf = utf8.AppendRune(buf, r)
				}
			}

			// Single quoted strings must be a single character.
			if quote == '\'' {
				break
			}
		}

		// Verify that the string ends with a terminating quote.
		if !(len(in) > 0 && in[0] == quote) {
			return "", in0, ErrSyntax
		}
		in = in[1:] // skip terminating quote

		if unescape {
			return string(buf), in, nil
		}
		return in0[:len(in0)-len(in)], in, nil
	default:
		return "", in, ErrSyntax
	}
}

// bsearch is semantically the same as [slices.BinarySearch] (without NaN checks)
// We copied this function because we can not import "slices" here.
func bsearch[S ~[]E, E ~uint16 | ~uint32](s S, v E) (int, bool) {
	n := len(s)
	i, j := 0, n
	for i < j {
		h := i + (j-i)>>1
		if s[h] < v {
			i = h + 1
		} else {
			j = h
		}
	}
	return i, i < n && s[i] == v
}

// TODO: IsPrint is a local implementation of unicode.IsPrint, verified by the tests
// to give the same answer. It allows this package not to depend on unicode,
// and therefore not pull in all the Unicode tables. If the linker were better
// at tossing unused tables, we could get rid of this implementation.
// That would be nice.

// IsPrint reports whether the rune is defined as printable by Go, with
// the same definition as [unicode.IsPrint]: letters, numbers, punctuation,
// symbols and ASCII space.
func IsPrint(r rune) bool {
	// Fast check for Latin-1
	if r <= 0xFF {
		if 0x20 <= r && r <= 0x7E {
			// All the ASCII is printable from space through DEL-1.
			return true
		}
		if 0xA1 <= r && r <= 0xFF {
			// Similarly for ¡ through ÿ...
			return r != 0xAD // ...except for the bizarre soft hyphen.
		}
		return false
	}

	// Same algorithm, either on uint16 or uint32 value.
	// First, find first i such that isPrint[i] >= x.
	// This is the index of either the start or end of a pair that might span x.
	// The start is even (isPrint[i&^1]) and the end is odd (isPrint[i|1]).
	// If we find x in a range, make sure x is not in isNotPrint list.

	if 0 <= r && r < 1<<16 {
		rr, isPrint, isNotPrint := uint16(r), isPrint16, isNotPrint16
		i, _ := bsearch(isPrint, rr)
		if i >= len(isPrint) || rr < isPrint[i&^1] || isPrint[i|1] < rr {
			return false
		}
		_, found := bsearch(isNotPrint, rr)
		return !found
	}

	rr, isPrint, isNotPrint := uint32(r), isPrint32, isNotPrint32
	i, _ := bsearch(isPrint, rr)
	if i >= len(isPrint) || rr < isPrint[i&^1] || isPrint[i|1] < rr {
		return false
	}
	if r >= 0x20000 {
		return true
	}
	r -= 0x10000
	_, found := bsearch(isNotPrint, uint16(r))
	return !found
}

// IsGraphic reports whether the rune is defined as a Graphic by Unicode. Such
// characters include letters, marks, numbers, punctuation, symbols, and
// spaces, from categories L, M, N, P, S, and Zs.
func IsGraphic(r rune) bool {
	if IsPrint(r) {
		return true
	}
	return isInGraphicList(r)
}

// isInGraphicList reports whether the rune is in the isGraphic list. This separation
// from IsGraphic allows quoteWith to avoid two calls to IsPrint.
// Should be called only if IsPrint fails.
func isInGraphicList(r rune) bool {
	// We know r must fit in 16 bits - see makeisprint.go.
	if r > 0xFFFF {
		return false
	}
	_, found := bsearch(isGraphic, uint16(r))
	return found
}

"""



```