Response:
Let's break down the thought process for answering the request about the `utf8.go` file.

1. **Understanding the Core Request:** The request asks for a functional breakdown of the provided Go code snippet, focusing on its purpose, providing illustrative Go examples, and identifying potential pitfalls for users.

2. **Initial Skim and Keyword Identification:** I'd quickly scan the code looking for package names, function names, constants, and comments. This gives a high-level overview. Keywords like "UTF-8", "rune", "decode", "encode", "valid", and "count" stand out. The package comment explicitly states its purpose: "implements functions and constants to support text encoded in UTF-8. It includes functions to translate between runes and UTF-8 byte sequences." This is the most important piece of information.

3. **Categorizing Functionality:**  Based on the function names and package description, I'd start grouping the functions by their purpose:
    * **Decoding:**  `DecodeRune`, `DecodeRuneInString`, `DecodeLastRune`, `DecodeLastRuneInString` - These functions clearly deal with converting UTF-8 byte sequences back to runes.
    * **Encoding:** `EncodeRune`, `AppendRune` - These handle converting runes into UTF-8 byte sequences.
    * **Validation:** `Valid`, `ValidString`, `ValidRune`, `FullRune`, `FullRuneInString` -  These functions check the validity of UTF-8 sequences and individual runes.
    * **Counting:** `RuneCount`, `RuneCountInString` -  These count the number of runes in a UTF-8 sequence.
    * **Length/Size:** `RuneLen` - This determines the byte length of a rune's UTF-8 encoding.
    * **Start Byte Check:** `RuneStart` -  This identifies if a byte is the start of a UTF-8 rune.

4. **Explaining Each Category:** For each category, I'd formulate a concise explanation of its functionality. For example, for "Decoding," I'd explain that it converts UTF-8 encoded bytes into runes and provides the size of the encoding.

5. **Providing Go Code Examples:**  This is crucial for demonstrating how to use the functions. For each core functionality, I'd create a simple but illustrative example. The examples should:
    * Use clear variable names.
    * Demonstrate the input and output of the function.
    * Cover basic use cases.
    *  For decoding, show how to handle the returned `rune` and `size`.
    *  For encoding, show how to provide the byte slice and rune.
    *  For validation, demonstrate both valid and invalid cases.
    *  For counting, show the difference between byte length and rune count.

6. **Inferring the Overall Go Language Feature:**  The package name (`utf8`) and the types it manipulates (`rune`, `byte`) strongly suggest this is the standard library's implementation for UTF-8 encoding and decoding. It's essential for handling text in Go.

7. **Handling Assumptions and Outputs in Examples:**  For each code example, I need to clearly state the *input* and the expected *output*. This makes the examples verifiable and easy to understand.

8. **Identifying Potential Pitfalls (Common Mistakes):**  This requires thinking about how developers might misuse the library. Some common mistakes related to UTF-8 include:
    * **Incorrectly sized byte slices for encoding:**  Forgetting that a rune might take up to 4 bytes.
    * **Assuming byte length equals rune count:**  Not understanding variable-width encoding.
    * **Not checking for invalid UTF-8:**  Leading to unexpected behavior or errors when processing text.
    * **Confusing runes and bytes:**  Treating byte slices directly as strings of characters.

9. **Structuring the Answer:** Organize the information logically using headings and bullet points. This improves readability. Start with a general overview, then detail each function category, provide examples, explain the Go feature, and finally list common mistakes.

10. **Review and Refine:** After drafting the answer, review it for clarity, accuracy, and completeness. Ensure the code examples are correct and the explanations are easy to understand. Check for any redundant information or areas that could be more concise. For instance, ensure the explanations of `DecodeRune` and `DecodeRuneInString` are similar but highlight the difference in input type.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe focus on the constants first. **Correction:** The functions are the core functionality, so start there. The constants support the functions.
* **Initial example for `EncodeRune`:** Just show encoding a simple ASCII character. **Refinement:**  Add an example with a multi-byte rune to demonstrate the function's full capability.
* **Realization:** The prompt specifically asked for *reasoning* about the Go feature. Explicitly state that this is likely the standard library's UTF-8 implementation.
* **Considering command-line parameters:** Notice that the provided code *doesn't* handle command-line arguments directly. Acknowledge this explicitly and state that it's a library function meant to be used within Go programs.
* **Thinking about "assumptions":** Rephrase "assumptions" to "hypothesized input and output" for the code examples, making it clearer.

By following this structured thought process, combining code analysis with an understanding of UTF-8 and Go's text handling,  I can arrive at a comprehensive and accurate answer to the request.
这段代码是 Go 语言 `unicode/utf8` 包的一部分，专门用于处理 UTF-8 编码的文本。它提供了一系列函数和常量，用于在 `rune`（Go 语言中表示 Unicode 码点的数据类型）和 UTF-8 字节序列之间进行转换和操作。

**以下是它主要的功能：**

1. **编码和解码 Rune：**
   - **`EncodeRune(p []byte, r rune) int`**: 将一个 `rune` 编码成 UTF-8 字节序列并写入到字节切片 `p` 中。返回写入的字节数。
   - **`AppendRune(p []byte, r rune) []byte`**: 将一个 `rune` 编码成 UTF-8 字节序列并追加到字节切片 `p` 的末尾。返回扩展后的字节切片。
   - **`DecodeRune(p []byte) (r rune, size int)`**: 从字节切片 `p` 的开头解码第一个 UTF-8 编码的 `rune`。返回解码后的 `rune` 和占用的字节数。如果 `p` 为空，返回 `(RuneError, 0)`。如果编码无效，返回 `(RuneError, 1)`。
   - **`DecodeRuneInString(s string) (r rune, size int)`**: 功能与 `DecodeRune` 类似，但输入是字符串。
   - **`DecodeLastRune(p []byte) (r rune, size int)`**: 从字节切片 `p` 的末尾解码最后一个 UTF-8 编码的 `rune`。返回解码后的 `rune` 和占用的字节数。
   - **`DecodeLastRuneInString(s string) (r rune, size int)`**: 功能与 `DecodeLastRune` 类似，但输入是字符串。

2. **判断 UTF-8 序列的有效性：**
   - **`Valid(p []byte) bool`**: 判断字节切片 `p` 是否完全由有效的 UTF-8 编码的 `rune` 组成。
   - **`ValidString(s string) bool`**: 判断字符串 `s` 是否完全由有效的 UTF-8 编码的 `rune` 组成。
   - **`ValidRune(r rune) bool`**: 判断 `rune` 是否可以合法地编码为 UTF-8。代理区间的码点是非法的。
   - **`FullRune(p []byte) bool`**: 判断字节切片 `p` 的开头是否包含一个完整的 UTF-8 编码的 `rune`。
   - **`FullRuneInString(s string) bool`**: 功能与 `FullRune` 类似，但输入是字符串。

3. **获取 Rune 的长度：**
   - **`RuneLen(r rune) int`**: 返回 `rune` 的 UTF-8 编码所需的字节数。如果 `rune` 是无效的 UTF-8 值，则返回 -1。

4. **计算 Rune 的数量：**
   - **`RuneCount(p []byte) int`**: 计算字节切片 `p` 中包含的 `rune` 的数量。错误的编码也被视为一个宽度为 1 字节的 `rune`。
   - **`RuneCountInString(s string) int`**: 功能与 `RuneCount` 类似，但输入是字符串。

5. **判断字节是否是 Rune 的起始字节：**
   - **`RuneStart(b byte) bool`**: 判断字节 `b` 是否可能是一个 UTF-8 编码的 `rune` 的起始字节。非起始字节的高两位总是 `10`。

**推理：这是一个 Go 语言标准库中处理 UTF-8 编码的核心部分。**  Go 语言的字符串类型是 UTF-8 编码的，这个包提供了操作 UTF-8 字符串的基础工具。

**Go 代码示例：**

```go
package main

import (
	"fmt"
	"unicode/utf8"
)

func main() {
	// 编码 Rune
	runeValue := '你'
	buf := make([]byte, utf8.RuneLen(runeValue))
	size := utf8.EncodeRune(buf, runeValue)
	fmt.Printf("编码后的字节: %v, 长度: %d\n", buf, size) // 输出: 编码后的字节: [230 156 133], 长度: 3

	// 解码 Rune
	encodedBytes := []byte{230, 156, 133, 97} // "你a"
	r, size := utf8.DecodeRune(encodedBytes)
	fmt.Printf("解码后的 Rune: %c, 长度: %d\n", r, size) // 输出: 解码后的 Rune: 你, 长度: 3

	r2, size2 := utf8.DecodeRune(encodedBytes[size:])
	fmt.Printf("解码后的第二个 Rune: %c, 长度: %d\n", r2, size2) // 输出: 解码后的第二个 Rune: a, 长度: 1

	// 检查 UTF-8 字符串的有效性
	validUTF8 := "你好世界"
	invalidUTF8 := string([]byte{0xff, 0xfe, 'a'})
	fmt.Printf("'%s' 是否是有效的 UTF-8: %t\n", validUTF8, utf8.ValidString(validUTF8))   // 输出: '你好世界' 是否是有效的 UTF-8: true
	fmt.Printf("'%s' 是否是有效的 UTF-8: %t\n", invalidUTF8, utf8.ValidString(invalidUTF8)) // 输出: '��a' 是否是有效的 UTF-8: false

	// 计算 Rune 的数量
	text := "你好golang"
	runeCount := utf8.RuneCountInString(text)
	fmt.Printf("字符串 '%s' 的 Rune 数量: %d\n", text, runeCount) // 输出: 字符串 '你好golang' 的 Rune 数量: 7

	// 判断是否是 Rune 的起始字节
	fmt.Printf("0xE4 是否是 Rune 的起始字节: %t\n", utf8.RuneStart(0xE4)) // 输出: 0xE4 是否是 Rune 的起始字节: true (例如 '你' 的第一个字节)
	fmt.Printf("0x83 是否是 Rune 的起始字节: %t\n", utf8.RuneStart(0x83)) // 输出: 0x83 是否是 Rune 的起始字节: false (例如 '你' 的第二个或第三个字节)
}
```

**假设的输入与输出（与上面的代码示例相同，此处仅作强调）：**

* **输入 (EncodeRune):** `runeValue = '你'`
* **输出 (EncodeRune):** `buf = [230 156 133]`, `size = 3`

* **输入 (DecodeRune):** `encodedBytes = []byte{230, 156, 133, 97}`
* **输出 (DecodeRune):** `r = '你'`, `size = 3`
* **输出 (DecodeRune) 第二次调用:** `r2 = 'a'`, `size2 = 1`

* **输入 (ValidString):** `validUTF8 = "你好世界"`
* **输出 (ValidString):** `true`

* **输入 (ValidString):** `invalidUTF8 = string([]byte{0xff, 0xfe, 'a'})`
* **输出 (ValidString):** `false`

* **输入 (RuneCountInString):** `text = "你好golang"`
* **输出 (RuneCountInString):** `7`

* **输入 (RuneStart):** `0xE4`
* **输出 (RuneStart):** `true`

* **输入 (RuneStart):** `0x83`
* **输出 (RuneStart):** `false`

**命令行参数的具体处理：**

这段代码本身是一个库，不直接处理命令行参数。它提供的功能通常被其他 Go 程序调用，这些程序可能会使用 `flag` 包或其他方式来处理命令行参数，然后利用 `unicode/utf8` 包的功能来处理 UTF-8 编码的文本数据。

**使用者易犯错的点：**

1. **错误地假设字节长度等于 Rune 的数量：**  UTF-8 是变长编码，一个 Rune 可能由 1 到 4 个字节组成。直接使用 `len([]byte(str))` 获取的是字节数，而不是 Rune 的数量。应该使用 `utf8.RuneCountInString(str)` 来获取 Rune 的数量。

   ```go
   package main

   import (
       "fmt"
       "unicode/utf8"
   )

   func main() {
       text := "你好👋"
       byteLength := len([]byte(text))
       runeCount := utf8.RuneCountInString(text)
       fmt.Printf("字节长度: %d, Rune 数量: %d\n", byteLength, runeCount) // 输出: 字节长度: 7, Rune 数量: 3
   }
   ```

2. **在需要固定大小缓冲区时，没有考虑 UTF-8 的变长特性：** 例如，在处理网络协议或文件格式时，如果预先分配了固定大小的字节切片来存储字符，需要确保这个大小足够容纳可能出现的多字节 Rune。

3. **没有检查 UTF-8 字符串的有效性：**  如果处理来自外部源（如文件、网络）的字符串，应该使用 `utf8.ValidString` 或 `utf8.Valid` 来验证其是否是有效的 UTF-8 编码，以避免后续处理中出现意外错误。

4. **混淆 Rune 和字节：**  在需要操作单个字符时，应该使用 `rune` 类型，而不是 `byte`。例如，遍历字符串的字符应该使用 `for ... range` 循环，它会解码每个 Rune。

   ```go
   package main

   import "fmt"

   func main() {
       text := "你好"
       for i, r := range text {
           fmt.Printf("索引: %d, Rune: %c\n", i, r)
       }
       // 输出:
       // 索引: 0, Rune: 你
       // 索引: 3, Rune: 好
   }
   ```

理解 `unicode/utf8` 包的功能对于编写能够正确处理各种语言文本的 Go 程序至关重要。

Prompt: 
```
这是路径为go/src/unicode/utf8/utf8.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package utf8 implements functions and constants to support text encoded in
// UTF-8. It includes functions to translate between runes and UTF-8 byte sequences.
// See https://en.wikipedia.org/wiki/UTF-8
package utf8

// The conditions RuneError==unicode.ReplacementChar and
// MaxRune==unicode.MaxRune are verified in the tests.
// Defining them locally avoids this package depending on package unicode.

// Numbers fundamental to the encoding.
const (
	RuneError = '\uFFFD'     // the "error" Rune or "Unicode replacement character"
	RuneSelf  = 0x80         // characters below RuneSelf are represented as themselves in a single byte.
	MaxRune   = '\U0010FFFF' // Maximum valid Unicode code point.
	UTFMax    = 4            // maximum number of bytes of a UTF-8 encoded Unicode character.
)

// Code points in the surrogate range are not valid for UTF-8.
const (
	surrogateMin = 0xD800
	surrogateMax = 0xDFFF
)

const (
	t1 = 0b00000000
	tx = 0b10000000
	t2 = 0b11000000
	t3 = 0b11100000
	t4 = 0b11110000
	t5 = 0b11111000

	maskx = 0b00111111
	mask2 = 0b00011111
	mask3 = 0b00001111
	mask4 = 0b00000111

	rune1Max = 1<<7 - 1
	rune2Max = 1<<11 - 1
	rune3Max = 1<<16 - 1

	// The default lowest and highest continuation byte.
	locb = 0b10000000
	hicb = 0b10111111

	// These names of these constants are chosen to give nice alignment in the
	// table below. The first nibble is an index into acceptRanges or F for
	// special one-byte cases. The second nibble is the Rune length or the
	// Status for the special one-byte case.
	xx = 0xF1 // invalid: size 1
	as = 0xF0 // ASCII: size 1
	s1 = 0x02 // accept 0, size 2
	s2 = 0x13 // accept 1, size 3
	s3 = 0x03 // accept 0, size 3
	s4 = 0x23 // accept 2, size 3
	s5 = 0x34 // accept 3, size 4
	s6 = 0x04 // accept 0, size 4
	s7 = 0x44 // accept 4, size 4
)

const (
	runeErrorByte0 = t3 | (RuneError >> 12)
	runeErrorByte1 = tx | (RuneError>>6)&maskx
	runeErrorByte2 = tx | RuneError&maskx
)

// first is information about the first byte in a UTF-8 sequence.
var first = [256]uint8{
	//   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
	as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, // 0x00-0x0F
	as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, // 0x10-0x1F
	as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, // 0x20-0x2F
	as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, // 0x30-0x3F
	as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, // 0x40-0x4F
	as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, // 0x50-0x5F
	as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, // 0x60-0x6F
	as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, // 0x70-0x7F
	//   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0x80-0x8F
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0x90-0x9F
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0xA0-0xAF
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0xB0-0xBF
	xx, xx, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, // 0xC0-0xCF
	s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, // 0xD0-0xDF
	s2, s3, s3, s3, s3, s3, s3, s3, s3, s3, s3, s3, s3, s4, s3, s3, // 0xE0-0xEF
	s5, s6, s6, s6, s7, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0xF0-0xFF
}

// acceptRange gives the range of valid values for the second byte in a UTF-8
// sequence.
type acceptRange struct {
	lo uint8 // lowest value for second byte.
	hi uint8 // highest value for second byte.
}

// acceptRanges has size 16 to avoid bounds checks in the code that uses it.
var acceptRanges = [16]acceptRange{
	0: {locb, hicb},
	1: {0xA0, hicb},
	2: {locb, 0x9F},
	3: {0x90, hicb},
	4: {locb, 0x8F},
}

// FullRune reports whether the bytes in p begin with a full UTF-8 encoding of a rune.
// An invalid encoding is considered a full Rune since it will convert as a width-1 error rune.
func FullRune(p []byte) bool {
	n := len(p)
	if n == 0 {
		return false
	}
	x := first[p[0]]
	if n >= int(x&7) {
		return true // ASCII, invalid or valid.
	}
	// Must be short or invalid.
	accept := acceptRanges[x>>4]
	if n > 1 && (p[1] < accept.lo || accept.hi < p[1]) {
		return true
	} else if n > 2 && (p[2] < locb || hicb < p[2]) {
		return true
	}
	return false
}

// FullRuneInString is like FullRune but its input is a string.
func FullRuneInString(s string) bool {
	n := len(s)
	if n == 0 {
		return false
	}
	x := first[s[0]]
	if n >= int(x&7) {
		return true // ASCII, invalid, or valid.
	}
	// Must be short or invalid.
	accept := acceptRanges[x>>4]
	if n > 1 && (s[1] < accept.lo || accept.hi < s[1]) {
		return true
	} else if n > 2 && (s[2] < locb || hicb < s[2]) {
		return true
	}
	return false
}

// DecodeRune unpacks the first UTF-8 encoding in p and returns the rune and
// its width in bytes. If p is empty it returns ([RuneError], 0). Otherwise, if
// the encoding is invalid, it returns (RuneError, 1). Both are impossible
// results for correct, non-empty UTF-8.
//
// An encoding is invalid if it is incorrect UTF-8, encodes a rune that is
// out of range, or is not the shortest possible UTF-8 encoding for the
// value. No other validation is performed.
func DecodeRune(p []byte) (r rune, size int) {
	n := len(p)
	if n < 1 {
		return RuneError, 0
	}
	p0 := p[0]
	x := first[p0]
	if x >= as {
		// The following code simulates an additional check for x == xx and
		// handling the ASCII and invalid cases accordingly. This mask-and-or
		// approach prevents an additional branch.
		mask := rune(x) << 31 >> 31 // Create 0x0000 or 0xFFFF.
		return rune(p[0])&^mask | RuneError&mask, 1
	}
	sz := int(x & 7)
	accept := acceptRanges[x>>4]
	if n < sz {
		return RuneError, 1
	}
	b1 := p[1]
	if b1 < accept.lo || accept.hi < b1 {
		return RuneError, 1
	}
	if sz <= 2 { // <= instead of == to help the compiler eliminate some bounds checks
		return rune(p0&mask2)<<6 | rune(b1&maskx), 2
	}
	b2 := p[2]
	if b2 < locb || hicb < b2 {
		return RuneError, 1
	}
	if sz <= 3 {
		return rune(p0&mask3)<<12 | rune(b1&maskx)<<6 | rune(b2&maskx), 3
	}
	b3 := p[3]
	if b3 < locb || hicb < b3 {
		return RuneError, 1
	}
	return rune(p0&mask4)<<18 | rune(b1&maskx)<<12 | rune(b2&maskx)<<6 | rune(b3&maskx), 4
}

// DecodeRuneInString is like [DecodeRune] but its input is a string. If s is
// empty it returns ([RuneError], 0). Otherwise, if the encoding is invalid, it
// returns (RuneError, 1). Both are impossible results for correct, non-empty
// UTF-8.
//
// An encoding is invalid if it is incorrect UTF-8, encodes a rune that is
// out of range, or is not the shortest possible UTF-8 encoding for the
// value. No other validation is performed.
func DecodeRuneInString(s string) (r rune, size int) {
	n := len(s)
	if n < 1 {
		return RuneError, 0
	}
	s0 := s[0]
	x := first[s0]
	if x >= as {
		// The following code simulates an additional check for x == xx and
		// handling the ASCII and invalid cases accordingly. This mask-and-or
		// approach prevents an additional branch.
		mask := rune(x) << 31 >> 31 // Create 0x0000 or 0xFFFF.
		return rune(s[0])&^mask | RuneError&mask, 1
	}
	sz := int(x & 7)
	accept := acceptRanges[x>>4]
	if n < sz {
		return RuneError, 1
	}
	s1 := s[1]
	if s1 < accept.lo || accept.hi < s1 {
		return RuneError, 1
	}
	if sz <= 2 { // <= instead of == to help the compiler eliminate some bounds checks
		return rune(s0&mask2)<<6 | rune(s1&maskx), 2
	}
	s2 := s[2]
	if s2 < locb || hicb < s2 {
		return RuneError, 1
	}
	if sz <= 3 {
		return rune(s0&mask3)<<12 | rune(s1&maskx)<<6 | rune(s2&maskx), 3
	}
	s3 := s[3]
	if s3 < locb || hicb < s3 {
		return RuneError, 1
	}
	return rune(s0&mask4)<<18 | rune(s1&maskx)<<12 | rune(s2&maskx)<<6 | rune(s3&maskx), 4
}

// DecodeLastRune unpacks the last UTF-8 encoding in p and returns the rune and
// its width in bytes. If p is empty it returns ([RuneError], 0). Otherwise, if
// the encoding is invalid, it returns (RuneError, 1). Both are impossible
// results for correct, non-empty UTF-8.
//
// An encoding is invalid if it is incorrect UTF-8, encodes a rune that is
// out of range, or is not the shortest possible UTF-8 encoding for the
// value. No other validation is performed.
func DecodeLastRune(p []byte) (r rune, size int) {
	end := len(p)
	if end == 0 {
		return RuneError, 0
	}
	start := end - 1
	r = rune(p[start])
	if r < RuneSelf {
		return r, 1
	}
	// guard against O(n^2) behavior when traversing
	// backwards through strings with long sequences of
	// invalid UTF-8.
	lim := end - UTFMax
	if lim < 0 {
		lim = 0
	}
	for start--; start >= lim; start-- {
		if RuneStart(p[start]) {
			break
		}
	}
	if start < 0 {
		start = 0
	}
	r, size = DecodeRune(p[start:end])
	if start+size != end {
		return RuneError, 1
	}
	return r, size
}

// DecodeLastRuneInString is like [DecodeLastRune] but its input is a string. If
// s is empty it returns ([RuneError], 0). Otherwise, if the encoding is invalid,
// it returns (RuneError, 1). Both are impossible results for correct,
// non-empty UTF-8.
//
// An encoding is invalid if it is incorrect UTF-8, encodes a rune that is
// out of range, or is not the shortest possible UTF-8 encoding for the
// value. No other validation is performed.
func DecodeLastRuneInString(s string) (r rune, size int) {
	end := len(s)
	if end == 0 {
		return RuneError, 0
	}
	start := end - 1
	r = rune(s[start])
	if r < RuneSelf {
		return r, 1
	}
	// guard against O(n^2) behavior when traversing
	// backwards through strings with long sequences of
	// invalid UTF-8.
	lim := end - UTFMax
	if lim < 0 {
		lim = 0
	}
	for start--; start >= lim; start-- {
		if RuneStart(s[start]) {
			break
		}
	}
	if start < 0 {
		start = 0
	}
	r, size = DecodeRuneInString(s[start:end])
	if start+size != end {
		return RuneError, 1
	}
	return r, size
}

// RuneLen returns the number of bytes in the UTF-8 encoding of the rune.
// It returns -1 if the rune is not a valid value to encode in UTF-8.
func RuneLen(r rune) int {
	switch {
	case r < 0:
		return -1
	case r <= rune1Max:
		return 1
	case r <= rune2Max:
		return 2
	case surrogateMin <= r && r <= surrogateMax:
		return -1
	case r <= rune3Max:
		return 3
	case r <= MaxRune:
		return 4
	}
	return -1
}

// EncodeRune writes into p (which must be large enough) the UTF-8 encoding of the rune.
// If the rune is out of range, it writes the encoding of [RuneError].
// It returns the number of bytes written.
func EncodeRune(p []byte, r rune) int {
	// This function is inlineable for fast handling of ASCII.
	if uint32(r) <= rune1Max {
		p[0] = byte(r)
		return 1
	}
	return encodeRuneNonASCII(p, r)
}

func encodeRuneNonASCII(p []byte, r rune) int {
	// Negative values are erroneous. Making it unsigned addresses the problem.
	switch i := uint32(r); {
	case i <= rune2Max:
		_ = p[1] // eliminate bounds checks
		p[0] = t2 | byte(r>>6)
		p[1] = tx | byte(r)&maskx
		return 2
	case i < surrogateMin, surrogateMax < i && i <= rune3Max:
		_ = p[2] // eliminate bounds checks
		p[0] = t3 | byte(r>>12)
		p[1] = tx | byte(r>>6)&maskx
		p[2] = tx | byte(r)&maskx
		return 3
	case i > rune3Max && i <= MaxRune:
		_ = p[3] // eliminate bounds checks
		p[0] = t4 | byte(r>>18)
		p[1] = tx | byte(r>>12)&maskx
		p[2] = tx | byte(r>>6)&maskx
		p[3] = tx | byte(r)&maskx
		return 4
	default:
		_ = p[2] // eliminate bounds checks
		p[0] = runeErrorByte0
		p[1] = runeErrorByte1
		p[2] = runeErrorByte2
		return 3
	}
}

// AppendRune appends the UTF-8 encoding of r to the end of p and
// returns the extended buffer. If the rune is out of range,
// it appends the encoding of [RuneError].
func AppendRune(p []byte, r rune) []byte {
	// This function is inlineable for fast handling of ASCII.
	if uint32(r) <= rune1Max {
		return append(p, byte(r))
	}
	return appendRuneNonASCII(p, r)
}

func appendRuneNonASCII(p []byte, r rune) []byte {
	// Negative values are erroneous. Making it unsigned addresses the problem.
	switch i := uint32(r); {
	case i <= rune2Max:
		return append(p, t2|byte(r>>6), tx|byte(r)&maskx)
	case i < surrogateMin, surrogateMax < i && i <= rune3Max:
		return append(p, t3|byte(r>>12), tx|byte(r>>6)&maskx, tx|byte(r)&maskx)
	case i > rune3Max && i <= MaxRune:
		return append(p, t4|byte(r>>18), tx|byte(r>>12)&maskx, tx|byte(r>>6)&maskx, tx|byte(r)&maskx)
	default:
		return append(p, runeErrorByte0, runeErrorByte1, runeErrorByte2)
	}
}

// RuneCount returns the number of runes in p. Erroneous and short
// encodings are treated as single runes of width 1 byte.
func RuneCount(p []byte) int {
	np := len(p)
	var n int
	for ; n < np; n++ {
		if c := p[n]; c >= RuneSelf {
			// non-ASCII slow path
			return n + RuneCountInString(string(p[n:]))
		}
	}
	return n
}

// RuneCountInString is like [RuneCount] but its input is a string.
func RuneCountInString(s string) (n int) {
	for range s {
		n++
	}
	return n
}

// RuneStart reports whether the byte could be the first byte of an encoded,
// possibly invalid rune. Second and subsequent bytes always have the top two
// bits set to 10.
func RuneStart(b byte) bool { return b&0xC0 != 0x80 }

// Valid reports whether p consists entirely of valid UTF-8-encoded runes.
func Valid(p []byte) bool {
	// This optimization avoids the need to recompute the capacity
	// when generating code for p[8:], bringing it to parity with
	// ValidString, which was 20% faster on long ASCII strings.
	p = p[:len(p):len(p)]

	// Fast path. Check for and skip 8 bytes of ASCII characters per iteration.
	for len(p) >= 8 {
		// Combining two 32 bit loads allows the same code to be used
		// for 32 and 64 bit platforms.
		// The compiler can generate a 32bit load for first32 and second32
		// on many platforms. See test/codegen/memcombine.go.
		first32 := uint32(p[0]) | uint32(p[1])<<8 | uint32(p[2])<<16 | uint32(p[3])<<24
		second32 := uint32(p[4]) | uint32(p[5])<<8 | uint32(p[6])<<16 | uint32(p[7])<<24
		if (first32|second32)&0x80808080 != 0 {
			// Found a non ASCII byte (>= RuneSelf).
			break
		}
		p = p[8:]
	}
	n := len(p)
	for i := 0; i < n; {
		pi := p[i]
		if pi < RuneSelf {
			i++
			continue
		}
		x := first[pi]
		if x == xx {
			return false // Illegal starter byte.
		}
		size := int(x & 7)
		if i+size > n {
			return false // Short or invalid.
		}
		accept := acceptRanges[x>>4]
		if c := p[i+1]; c < accept.lo || accept.hi < c {
			return false
		} else if size == 2 {
		} else if c := p[i+2]; c < locb || hicb < c {
			return false
		} else if size == 3 {
		} else if c := p[i+3]; c < locb || hicb < c {
			return false
		}
		i += size
	}
	return true
}

// ValidString reports whether s consists entirely of valid UTF-8-encoded runes.
func ValidString(s string) bool {
	// Fast path. Check for and skip 8 bytes of ASCII characters per iteration.
	for len(s) >= 8 {
		// Combining two 32 bit loads allows the same code to be used
		// for 32 and 64 bit platforms.
		// The compiler can generate a 32bit load for first32 and second32
		// on many platforms. See test/codegen/memcombine.go.
		first32 := uint32(s[0]) | uint32(s[1])<<8 | uint32(s[2])<<16 | uint32(s[3])<<24
		second32 := uint32(s[4]) | uint32(s[5])<<8 | uint32(s[6])<<16 | uint32(s[7])<<24
		if (first32|second32)&0x80808080 != 0 {
			// Found a non ASCII byte (>= RuneSelf).
			break
		}
		s = s[8:]
	}
	n := len(s)
	for i := 0; i < n; {
		si := s[i]
		if si < RuneSelf {
			i++
			continue
		}
		x := first[si]
		if x == xx {
			return false // Illegal starter byte.
		}
		size := int(x & 7)
		if i+size > n {
			return false // Short or invalid.
		}
		accept := acceptRanges[x>>4]
		if c := s[i+1]; c < accept.lo || accept.hi < c {
			return false
		} else if size == 2 {
		} else if c := s[i+2]; c < locb || hicb < c {
			return false
		} else if size == 3 {
		} else if c := s[i+3]; c < locb || hicb < c {
			return false
		}
		i += size
	}
	return true
}

// ValidRune reports whether r can be legally encoded as UTF-8.
// Code points that are out of range or a surrogate half are illegal.
func ValidRune(r rune) bool {
	switch {
	case 0 <= r && r < surrogateMin:
		return true
	case surrogateMax < r && r <= MaxRune:
		return true
	}
	return false
}

"""



```