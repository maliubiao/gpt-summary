Response:
Let's break down the thought process for analyzing the provided Go test file.

1. **Understand the Goal:** The request asks for the functionality of the `utf8_test.go` file, its purpose in the broader Go context, example usage, and potential pitfalls. Essentially, it's about understanding what this test file *tests*.

2. **Identify the Core Package:** The import statement `unicode/utf8` is key. The `utf8_test` package is clearly designed to test the `unicode/utf8` package. This immediately tells us the domain: handling UTF-8 encoded text in Go.

3. **Examine the Test Functions:** Look for functions starting with `Test`. These are the primary units of functionality being tested. List them out:

    * `TestConstants`:  Suggests testing the correctness of constants defined in the `utf8` package.
    * `TestFullRune`:  Likely tests functions related to checking if a byte sequence represents a complete rune.
    * `TestEncodeRune`:  Probably tests the function for encoding a rune into its UTF-8 byte representation.
    * `TestAppendRune`:  Likely tests appending a rune to a byte slice.
    * `TestDecodeRune`:  Tests decoding a rune from a byte sequence.
    * `TestDecodeSurrogateRune`: Specifically tests how surrogate code points are handled during decoding.
    * `TestSequencing`:  Tests the consistency of forward and backward rune decoding.
    * `TestRuntimeConversion`:  Checks how Go's runtime handles runes. While not directly testing the `utf8` package's *functions*, it verifies assumptions used in the tests.
    * `TestDecodeInvalidSequence`: Focuses on testing the behavior when encountering invalid UTF-8 byte sequences.
    * `TestNegativeRune`: Tests how negative rune values are handled during encoding (expecting the replacement character).
    * `TestRuneCount`: Tests functions that count the number of runes in a string or byte slice.
    * `TestRuneCountNonASCIIAllocation`:  A performance-related test, checking for unexpected allocations.
    * `TestRuneLen`: Tests the function that determines the byte length of a rune.
    * `TestValid`: Tests functions that validate whether a byte sequence or string is valid UTF-8.
    * `TestValidRune`: Tests the function that checks if a given `rune` is a valid Unicode code point (not a surrogate).

4. **Analyze Helper Data Structures:** Look for global variables like `utf8map`, `surrogateMap`, `testStrings`, `invalidSequenceTests`, `runecounttests`, `runelentests`, `validTests`, and `validrunetests`. These provide the test cases for the various functions.

    * `utf8map`: Maps runes to their valid UTF-8 encodings. This is fundamental for testing encoding and decoding.
    * `surrogateMap`:  Contains surrogate code points and their (incorrect) UTF-8 representations. This helps test error handling.
    * `testStrings`:  A collection of valid UTF-8 strings, including edge cases like empty strings and long strings.
    * `invalidSequenceTests`:  Contains byte sequences that are *not* valid UTF-8, used for testing error handling during decoding.
    * The other `...tests` variables provide specific inputs and expected outputs for their respective test functions.

5. **Infer Functionality from Tests:** Based on the test names and the data they use, deduce the purpose of the functions in the `unicode/utf8` package. For example, `TestEncodeRune` with `utf8map` strongly suggests the existence of an `EncodeRune` function that takes a rune and returns its byte representation. Similarly, `TestRuneCount` implies `RuneCount` and `RuneCountInString` functions.

6. **Construct Example Code:**  Choose a few representative test functions and create simple Go code snippets demonstrating the likely usage of the corresponding `unicode/utf8` functions. Focus on clarity and showing basic input/output.

7. **Address Specific Questions:**

    * **Go Language Feature:**  The file tests the UTF-8 encoding and decoding functionality provided by the standard library.
    * **Command-line arguments:** Since this is a `_test.go` file, it's run using `go test`. There are standard `go test` flags, but this specific file doesn't seem to have custom command-line processing.
    * **Mistakes:**  Consider common errors when working with UTF-8, such as incorrect handling of invalid sequences or assumptions about fixed-width characters. The surrogate handling tests are a strong hint.

8. **Structure the Answer:** Organize the findings logically:

    * Start with a general summary of the file's purpose.
    * List the specific functionalities being tested.
    * Provide clear Go code examples.
    * Address command-line arguments (or lack thereof).
    * Discuss potential mistakes users might make.

9. **Refine and Review:**  Read through the answer to ensure accuracy, clarity, and completeness. Make sure the examples are correct and the explanations are easy to understand. For instance, initially, I might not have explicitly stated that surrogate code points are invalid UTF-8. Reviewing the `TestDecodeSurrogateRune` would remind me to include this important detail.

This iterative process of examining the code, understanding the test cases, and connecting them to the underlying functionality allows for a comprehensive analysis of the provided Go test file.
这个 `utf8_test.go` 文件是 Go 语言标准库 `unicode/utf8` 包的测试文件。它包含了多个测试函数，用于验证 `unicode/utf8` 包中提供的各种 UTF-8 编码和解码功能是否正确。

以下是该文件列举的功能及其 Go 代码示例：

**1. 常量验证:**

*   **功能:** 验证 `utf8` 包中定义的常量 `MaxRune` 和 `RuneError` 是否与 `unicode` 包中对应的值一致。
*   **Go 代码示例:**

```go
import (
	"fmt"
	"unicode"
	"unicode/utf8"
)

func main() {
	if utf8.MaxRune != unicode.MaxRune {
		fmt.Println("utf8.MaxRune 不正确")
	}
	if utf8.RuneError != unicode.ReplacementChar {
		fmt.Println("utf8.RuneError 不正确")
	}
}
```

**2. 判断是否为完整的 Rune (码点):**

*   **功能:** 测试 `FullRune` 和 `FullRuneInString` 函数，判断给定的字节切片或字符串是否以完整的 UTF-8 编码的 Rune 结尾。
*   **Go 代码示例:**

```go
import (
	"fmt"
	"unicode/utf8"
)

func main() {
	validUTF8 := []byte("你好")
	incompleteUTF8 := []byte("你")
	fmt.Println(utf8.FullRune(validUTF8))       // 输出: true
	fmt.Println(utf8.FullRune(incompleteUTF8))   // 输出: false
	fmt.Println(utf8.FullRuneInString("你好"))   // 输出: true
	fmt.Println(utf8.FullRuneInString("你"))     // 输出: false
}
```

**3. 编码 Rune 为 UTF-8 字节:**

*   **功能:** 测试 `EncodeRune` 函数，将一个 Rune (Unicode 码点) 编码为 UTF-8 字节序列。
*   **Go 代码示例:**

```go
import (
	"fmt"
	"unicode/utf8"
)

func main() {
	var buf [utf8.UTFMax]byte
	n := utf8.EncodeRune(buf[:], '你')
	fmt.Printf("%X\n", buf[:n]) // 输出: E4BDA0 (你的 UTF-8 编码)
}
```
*   **假设的输入与输出:**
    *   输入: Rune `'你'`
    *   输出: 字节切片 `[]byte{0xE4, 0xBda, 0x0}` (实际输出会是 `[228 189 160]`, 这里用十六进制表示)

**4. 追加 Rune 的 UTF-8 编码到字节切片:**

*   **功能:** 测试 `AppendRune` 函数，将一个 Rune 的 UTF-8 编码追加到给定的字节切片中。
*   **Go 代码示例:**

```go
import (
	"fmt"
	"unicode/utf8"
)

func main() {
	slice := []byte("hello, ")
	slice = utf8.AppendRune(slice, '世')
	slice = utf8.AppendRune(slice, '界')
	fmt.Println(string(slice)) // 输出: hello, 世界
}
```

**5. 解码 UTF-8 字节序列为 Rune:**

*   **功能:** 测试 `DecodeRune` 和 `DecodeRuneInString` 函数，将 UTF-8 编码的字节序列或字符串解码为一个 Rune。同时返回 Rune 的大小（字节数）。
*   **Go 代码示例:**

```go
import (
	"fmt"
	"unicode/utf8"
)

func main() {
	b := []byte("你好")
	r, size := utf8.DecodeRune(b)
	fmt.Printf("Rune: %c, Size: %d\n", r, size) // 输出: Rune: 你, Size: 3

	s := "世界"
	r2, size2 := utf8.DecodeRuneInString(s)
	fmt.Printf("Rune: %c, Size: %d\n", r2, size2) // 输出: Rune: 世, Size: 3
}
```
*   **假设的输入与输出:**
    *   输入: 字节切片 `[]byte{0xE4, 0xBda, 0xA0}`
    *   输出: Rune `'你'`, 大小 `3`

**6. 解码 UTF-8 字节序列的最后一个 Rune:**

*   **功能:** 测试 `DecodeLastRune` 和 `DecodeLastRuneInString` 函数，从字节切片或字符串的末尾开始解码最后一个 Rune。
*   **Go 代码示例:**

```go
import (
	"fmt"
	"unicode/utf8"
)

func main() {
	b := []byte("你好世界")
	r, size := utf8.DecodeLastRune(b)
	fmt.Printf("Last Rune: %c, Size: %d\n", r, size) // 输出: Last Rune: 界, Size: 3

	s := "你好世界"
	r2, size2 := utf8.DecodeLastRuneInString(s)
	fmt.Printf("Last Rune: %c, Size: %d\n", r2, size2) // 输出: Last Rune: 界, Size: 3
}
```
*   **假设的输入与输出:**
    *   输入: 字节切片 `[]byte{0xE4, 0xBda, 0xA0, 0xE4, 0xB8, 0x96}` (你好)
    *   输出: Rune `'好'`, 大小 `3`

**7. 处理无效的 UTF-8 序列:**

*   **功能:** 测试当输入包含无效的 UTF-8 字节序列时，`DecodeRune` 等函数是否返回 `utf8.RuneError` 和正确的错误字节数。
*   **Go 代码示例:**

```go
import (
	"fmt"
	"unicode/utf8"
)

func main() {
	invalidUTF8 := []byte{0xC0, 0x80} // 一个无效的两字节序列
	r, size := utf8.DecodeRune(invalidUTF8)
	fmt.Printf("Rune: %U, Size: %d\n", r, size) // 输出: Rune: U+FFFD, Size: 1 (RuneError 和 1 个字节)
}
```

**8. 计算字符串或字节切片中的 Rune 数量:**

*   **功能:** 测试 `RuneCountInString` 和 `RuneCount` 函数，计算字符串或字节切片中包含的 Rune 的数量。
*   **Go 代码示例:**

```go
import (
	"fmt"
	"unicode/utf8"
)

func main() {
	s := "你好世界"
	count := utf8.RuneCountInString(s)
	fmt.Println("Rune count:", count) // 输出: Rune count: 4

	b := []byte("你好世界")
	count2 := utf8.RuneCount(b)
	fmt.Println("Rune count:", count2) // 输出: Rune count: 4
}
```

**9. 获取 Rune 的 UTF-8 编码长度:**

*   **功能:** 测试 `RuneLen` 函数，返回给定 Rune 的 UTF-8 编码所需的字节数。
*   **Go 代码示例:**

```go
import (
	"fmt"
	"unicode/utf8"
)

func main() {
	fmt.Println(utf8.RuneLen('a'))   // 输出: 1
	fmt.Println(utf8.RuneLen('é'))   // 输出: 2
	fmt.Println(utf8.RuneLen('你'))   // 输出: 3
	fmt.Println(utf8.RuneLen(utf8.MaxRune)) // 输出: 4
}
```

**10. 验证字节切片或字符串是否为有效的 UTF-8 编码:**

*   **功能:** 测试 `Valid` 和 `ValidString` 函数，检查给定的字节切片或字符串是否包含有效的 UTF-8 编码序列。
*   **Go 代码示例:**

```go
import (
	"fmt"
	"unicode/utf8"
)

func main() {
	validUTF8 := "你好"
	invalidUTF8 := string([]byte{0xC0, 0x80})

	fmt.Println(utf8.ValidString(validUTF8))   // 输出: true
	fmt.Println(utf8.ValidString(invalidUTF8)) // 输出: false

	fmt.Println(utf8.Valid([]byte(validUTF8)))   // 输出: true
	fmt.Println(utf8.Valid([]byte(invalidUTF8))) // 输出: false
}
```

**11. 验证 Rune 是否是有效的 Unicode 码点:**

*   **功能:** 测试 `ValidRune` 函数，检查给定的 Rune 是否是有效的 Unicode 码点 (例如，排除 surrogate code points)。
*   **Go 代码示例:**

```go
import (
	"fmt"
	"unicode/utf8"
)

func main() {
	fmt.Println(utf8.ValidRune('a'))        // 输出: true
	fmt.Println(utf8.ValidRune(0xD800))   // 输出: false (Surrogate code point)
	fmt.Println(utf8.ValidRune(utf8.MaxRune)) // 输出: true
}
```

**代码推理:**

`utf8_test.go` 通过定义一系列的测试用例（例如 `utf8map`, `surrogateMap`, `testStrings`, `invalidSequenceTests` 等）来覆盖 `unicode/utf8` 包中各个函数的不同输入场景，包括正常情况、边界情况和错误情况。例如：

*   `utf8map` 定义了一系列 Rune 及其对应的 UTF-8 编码，用于测试编码和解码的正确性。
*   `surrogateMap` 定义了 surrogate code points 及其错误的 UTF-8 编码，用于测试解码函数如何处理这些无效的码点。
*   `invalidSequenceTests` 定义了各种无效的 UTF-8 字节序列，用于测试解码函数是否能够正确识别并返回 `RuneError`。

**命令行参数处理:**

这个测试文件本身并不直接处理命令行参数。它是通过 Go 的测试工具 `go test` 来运行的。 `go test` 命令有一些标准的参数，例如：

*   `-v`: 显示更详细的测试输出。
*   `-run <正则表达式>`: 只运行匹配正则表达式的测试函数。
*   `-bench <正则表达式>`: 运行性能测试函数。

例如，要运行 `utf8_test.go` 文件中的所有测试，可以在命令行中执行：

```bash
go test unicode/utf8
```

要运行特定的测试函数，例如 `TestEncodeRune`:

```bash
go test -run TestEncodeRune unicode/utf8
```

性能测试函数（以 `Benchmark` 开头）可以通过 `-bench` 参数运行：

```bash
go test -bench . unicode/utf8
```

**使用者易犯错的点:**

*   **假设字符是单字节的:**  初学者容易假设字符串中的每个 "字符" 都是一个字节，这在处理非 ASCII 字符时会导致错误。应该使用 `utf8.RuneCountInString` 来获取字符（Rune）的数量，而不是 `len()`。

    ```go
    package main

    import (
        "fmt"
        "unicode/utf8"
    )

    func main() {
        s := "你好"
        fmt.Println("错误的长度:", len(s))                     // 输出: 6 (字节数)
        fmt.Println("正确的 Rune 数量:", utf8.RuneCountInString(s)) // 输出: 2
    }
    ```

*   **不正确地处理无效的 UTF-8 序列:**  在处理来自外部数据源的字符串时，可能会遇到无效的 UTF-8 序列。直接使用可能会导致程序崩溃或产生不可预测的结果。应该使用 `utf8.ValidString` 或在解码时检查 `utf8.DecodeRune` 的返回值，以妥善处理这些情况。

    ```go
    package main

    import (
        "fmt"
        "unicode/utf8"
    )

    func main() {
        invalidUTF8 := string([]byte{0xC0, 0x80})
        if utf8.ValidString(invalidUTF8) {
            fmt.Println("这是一个有效的 UTF-8 字符串")
        } else {
            fmt.Println("这是一个无效的 UTF-8 字符串") // 输出
        }

        r, size := utf8.DecodeRune([]byte(invalidUTF8))
        if r == utf8.RuneError {
            fmt.Println("解码时遇到错误") // 输出
        }
        fmt.Println("解码的 Rune:", string(r)) // 输出: 解码的 Rune: �
    }
    ```

*   **混淆 byte 和 rune:**  需要理解 `byte` 是 `uint8` 的别名，代表一个字节，而 `rune` 是 `int32` 的别名，代表一个 Unicode 码点。在处理 UTF-8 字符串时，一个 Rune 可能由一个或多个字节组成。

总而言之，`utf8_test.go` 是 `unicode/utf8` 包功能实现的严格验证，确保了 Go 语言在处理 UTF-8 编码时的正确性和可靠性。理解这些测试用例可以帮助开发者更好地理解和使用 `unicode/utf8` 包。

Prompt: 
```
这是路径为go/src/unicode/utf8/utf8_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utf8_test

import (
	"bytes"
	"strings"
	"testing"
	"unicode"
	. "unicode/utf8"
)

// Validate the constants redefined from unicode.
func init() {
	if MaxRune != unicode.MaxRune {
		panic("utf8.MaxRune is wrong")
	}
	if RuneError != unicode.ReplacementChar {
		panic("utf8.RuneError is wrong")
	}
}

// Validate the constants redefined from unicode.
func TestConstants(t *testing.T) {
	if MaxRune != unicode.MaxRune {
		t.Errorf("utf8.MaxRune is wrong: %x should be %x", MaxRune, unicode.MaxRune)
	}
	if RuneError != unicode.ReplacementChar {
		t.Errorf("utf8.RuneError is wrong: %x should be %x", RuneError, unicode.ReplacementChar)
	}
}

type Utf8Map struct {
	r   rune
	str string
}

var utf8map = []Utf8Map{
	{0x0000, "\x00"},
	{0x0001, "\x01"},
	{0x007e, "\x7e"},
	{0x007f, "\x7f"},
	{0x0080, "\xc2\x80"},
	{0x0081, "\xc2\x81"},
	{0x00bf, "\xc2\xbf"},
	{0x00c0, "\xc3\x80"},
	{0x00c1, "\xc3\x81"},
	{0x00c8, "\xc3\x88"},
	{0x00d0, "\xc3\x90"},
	{0x00e0, "\xc3\xa0"},
	{0x00f0, "\xc3\xb0"},
	{0x00f8, "\xc3\xb8"},
	{0x00ff, "\xc3\xbf"},
	{0x0100, "\xc4\x80"},
	{0x07ff, "\xdf\xbf"},
	{0x0400, "\xd0\x80"},
	{0x0800, "\xe0\xa0\x80"},
	{0x0801, "\xe0\xa0\x81"},
	{0x1000, "\xe1\x80\x80"},
	{0xd000, "\xed\x80\x80"},
	{0xd7ff, "\xed\x9f\xbf"}, // last code point before surrogate half.
	{0xe000, "\xee\x80\x80"}, // first code point after surrogate half.
	{0xfffe, "\xef\xbf\xbe"},
	{0xffff, "\xef\xbf\xbf"},
	{0x10000, "\xf0\x90\x80\x80"},
	{0x10001, "\xf0\x90\x80\x81"},
	{0x40000, "\xf1\x80\x80\x80"},
	{0x10fffe, "\xf4\x8f\xbf\xbe"},
	{0x10ffff, "\xf4\x8f\xbf\xbf"},
	{0xFFFD, "\xef\xbf\xbd"},
}

var surrogateMap = []Utf8Map{
	{0xd800, "\xed\xa0\x80"}, // surrogate min decodes to (RuneError, 1)
	{0xdfff, "\xed\xbf\xbf"}, // surrogate max decodes to (RuneError, 1)
}

var testStrings = []string{
	"",
	"abcd",
	"☺☻☹",
	"日a本b語ç日ð本Ê語þ日¥本¼語i日©",
	"日a本b語ç日ð本Ê語þ日¥本¼語i日©日a本b語ç日ð本Ê語þ日¥本¼語i日©日a本b語ç日ð本Ê語þ日¥本¼語i日©",
	"\x80\x80\x80\x80",
}

func TestFullRune(t *testing.T) {
	for _, m := range utf8map {
		b := []byte(m.str)
		if !FullRune(b) {
			t.Errorf("FullRune(%q) (%U) = false, want true", b, m.r)
		}
		s := m.str
		if !FullRuneInString(s) {
			t.Errorf("FullRuneInString(%q) (%U) = false, want true", s, m.r)
		}
		b1 := b[0 : len(b)-1]
		if FullRune(b1) {
			t.Errorf("FullRune(%q) = true, want false", b1)
		}
		s1 := string(b1)
		if FullRuneInString(s1) {
			t.Errorf("FullRune(%q) = true, want false", s1)
		}
	}
	for _, s := range []string{"\xc0", "\xc1"} {
		b := []byte(s)
		if !FullRune(b) {
			t.Errorf("FullRune(%q) = false, want true", s)
		}
		if !FullRuneInString(s) {
			t.Errorf("FullRuneInString(%q) = false, want true", s)
		}
	}
}

func TestEncodeRune(t *testing.T) {
	for _, m := range utf8map {
		b := []byte(m.str)
		var buf [10]byte
		n := EncodeRune(buf[0:], m.r)
		b1 := buf[0:n]
		if !bytes.Equal(b, b1) {
			t.Errorf("EncodeRune(%#04x) = %q want %q", m.r, b1, b)
		}
	}
}

func TestAppendRune(t *testing.T) {
	for _, m := range utf8map {
		if buf := AppendRune(nil, m.r); string(buf) != m.str {
			t.Errorf("AppendRune(nil, %#04x) = %s, want %s", m.r, buf, m.str)
		}
		if buf := AppendRune([]byte("init"), m.r); string(buf) != "init"+m.str {
			t.Errorf("AppendRune(init, %#04x) = %s, want %s", m.r, buf, "init"+m.str)
		}
	}
}

func TestDecodeRune(t *testing.T) {
	for _, m := range utf8map {
		b := []byte(m.str)
		r, size := DecodeRune(b)
		if r != m.r || size != len(b) {
			t.Errorf("DecodeRune(%q) = %#04x, %d want %#04x, %d", b, r, size, m.r, len(b))
		}
		s := m.str
		r, size = DecodeRuneInString(s)
		if r != m.r || size != len(b) {
			t.Errorf("DecodeRuneInString(%q) = %#04x, %d want %#04x, %d", s, r, size, m.r, len(b))
		}

		// there's an extra byte that bytes left behind - make sure trailing byte works
		r, size = DecodeRune(b[0:cap(b)])
		if r != m.r || size != len(b) {
			t.Errorf("DecodeRune(%q) = %#04x, %d want %#04x, %d", b, r, size, m.r, len(b))
		}
		s = m.str + "\x00"
		r, size = DecodeRuneInString(s)
		if r != m.r || size != len(b) {
			t.Errorf("DecodeRuneInString(%q) = %#04x, %d want %#04x, %d", s, r, size, m.r, len(b))
		}

		// make sure missing bytes fail
		wantsize := 1
		if wantsize >= len(b) {
			wantsize = 0
		}
		r, size = DecodeRune(b[0 : len(b)-1])
		if r != RuneError || size != wantsize {
			t.Errorf("DecodeRune(%q) = %#04x, %d want %#04x, %d", b[:len(b)-1], r, size, RuneError, wantsize)
		}
		s = m.str[0 : len(m.str)-1]
		r, size = DecodeRuneInString(s)
		if r != RuneError || size != wantsize {
			t.Errorf("DecodeRuneInString(%q) = %#04x, %d want %#04x, %d", s, r, size, RuneError, wantsize)
		}

		// make sure bad sequences fail
		if len(b) == 1 {
			b[0] = 0x80
		} else {
			b[len(b)-1] = 0x7F
		}
		r, size = DecodeRune(b)
		if r != RuneError || size != 1 {
			t.Errorf("DecodeRune(%q) = %#04x, %d want %#04x, %d", b, r, size, RuneError, 1)
		}
		s = string(b)
		r, size = DecodeRuneInString(s)
		if r != RuneError || size != 1 {
			t.Errorf("DecodeRuneInString(%q) = %#04x, %d want %#04x, %d", s, r, size, RuneError, 1)
		}

	}
}

func TestDecodeSurrogateRune(t *testing.T) {
	for _, m := range surrogateMap {
		b := []byte(m.str)
		r, size := DecodeRune(b)
		if r != RuneError || size != 1 {
			t.Errorf("DecodeRune(%q) = %x, %d want %x, %d", b, r, size, RuneError, 1)
		}
		s := m.str
		r, size = DecodeRuneInString(s)
		if r != RuneError || size != 1 {
			t.Errorf("DecodeRuneInString(%q) = %x, %d want %x, %d", b, r, size, RuneError, 1)
		}
	}
}

// Check that DecodeRune and DecodeLastRune correspond to
// the equivalent range loop.
func TestSequencing(t *testing.T) {
	for _, ts := range testStrings {
		for _, m := range utf8map {
			for _, s := range []string{ts + m.str, m.str + ts, ts + m.str + ts} {
				testSequence(t, s)
			}
		}
	}
}

func runtimeRuneCount(s string) int {
	return len([]rune(s)) // Replaced by gc with call to runtime.countrunes(s).
}

// Check that a range loop, len([]rune(string)) optimization and
// []rune conversions visit the same runes.
// Not really a test of this package, but the assumption is used here and
// it's good to verify.
func TestRuntimeConversion(t *testing.T) {
	for _, ts := range testStrings {
		count := RuneCountInString(ts)
		if n := runtimeRuneCount(ts); n != count {
			t.Errorf("%q: len([]rune()) counted %d runes; got %d from RuneCountInString", ts, n, count)
			break
		}

		runes := []rune(ts)
		if n := len(runes); n != count {
			t.Errorf("%q: []rune() has length %d; got %d from RuneCountInString", ts, n, count)
			break
		}
		i := 0
		for _, r := range ts {
			if r != runes[i] {
				t.Errorf("%q[%d]: expected %c (%U); got %c (%U)", ts, i, runes[i], runes[i], r, r)
			}
			i++
		}
	}
}

var invalidSequenceTests = []string{
	"\xed\xa0\x80\x80", // surrogate min
	"\xed\xbf\xbf\x80", // surrogate max

	// xx
	"\x91\x80\x80\x80",

	// s1
	"\xC2\x7F\x80\x80",
	"\xC2\xC0\x80\x80",
	"\xDF\x7F\x80\x80",
	"\xDF\xC0\x80\x80",

	// s2
	"\xE0\x9F\xBF\x80",
	"\xE0\xA0\x7F\x80",
	"\xE0\xBF\xC0\x80",
	"\xE0\xC0\x80\x80",

	// s3
	"\xE1\x7F\xBF\x80",
	"\xE1\x80\x7F\x80",
	"\xE1\xBF\xC0\x80",
	"\xE1\xC0\x80\x80",

	//s4
	"\xED\x7F\xBF\x80",
	"\xED\x80\x7F\x80",
	"\xED\x9F\xC0\x80",
	"\xED\xA0\x80\x80",

	// s5
	"\xF0\x8F\xBF\xBF",
	"\xF0\x90\x7F\xBF",
	"\xF0\x90\x80\x7F",
	"\xF0\xBF\xBF\xC0",
	"\xF0\xBF\xC0\x80",
	"\xF0\xC0\x80\x80",

	// s6
	"\xF1\x7F\xBF\xBF",
	"\xF1\x80\x7F\xBF",
	"\xF1\x80\x80\x7F",
	"\xF1\xBF\xBF\xC0",
	"\xF1\xBF\xC0\x80",
	"\xF1\xC0\x80\x80",

	// s7
	"\xF4\x7F\xBF\xBF",
	"\xF4\x80\x7F\xBF",
	"\xF4\x80\x80\x7F",
	"\xF4\x8F\xBF\xC0",
	"\xF4\x8F\xC0\x80",
	"\xF4\x90\x80\x80",
}

func runtimeDecodeRune(s string) rune {
	for _, r := range s {
		return r
	}
	return -1
}

func TestDecodeInvalidSequence(t *testing.T) {
	for _, s := range invalidSequenceTests {
		r1, _ := DecodeRune([]byte(s))
		if want := RuneError; r1 != want {
			t.Errorf("DecodeRune(%#x) = %#04x, want %#04x", s, r1, want)
			return
		}
		r2, _ := DecodeRuneInString(s)
		if want := RuneError; r2 != want {
			t.Errorf("DecodeRuneInString(%q) = %#04x, want %#04x", s, r2, want)
			return
		}
		if r1 != r2 {
			t.Errorf("DecodeRune(%#x) = %#04x mismatch with DecodeRuneInString(%q) = %#04x", s, r1, s, r2)
			return
		}
		r3 := runtimeDecodeRune(s)
		if r2 != r3 {
			t.Errorf("DecodeRuneInString(%q) = %#04x mismatch with runtime.decoderune(%q) = %#04x", s, r2, s, r3)
			return
		}
	}
}

func testSequence(t *testing.T, s string) {
	type info struct {
		index int
		r     rune
	}
	index := make([]info, len(s))
	b := []byte(s)
	si := 0
	j := 0
	for i, r := range s {
		if si != i {
			t.Errorf("Sequence(%q) mismatched index %d, want %d", s, si, i)
			return
		}
		index[j] = info{i, r}
		j++
		r1, size1 := DecodeRune(b[i:])
		if r != r1 {
			t.Errorf("DecodeRune(%q) = %#04x, want %#04x", s[i:], r1, r)
			return
		}
		r2, size2 := DecodeRuneInString(s[i:])
		if r != r2 {
			t.Errorf("DecodeRuneInString(%q) = %#04x, want %#04x", s[i:], r2, r)
			return
		}
		if size1 != size2 {
			t.Errorf("DecodeRune/DecodeRuneInString(%q) size mismatch %d/%d", s[i:], size1, size2)
			return
		}
		si += size1
	}
	j--
	for si = len(s); si > 0; {
		r1, size1 := DecodeLastRune(b[0:si])
		r2, size2 := DecodeLastRuneInString(s[0:si])
		if size1 != size2 {
			t.Errorf("DecodeLastRune/DecodeLastRuneInString(%q, %d) size mismatch %d/%d", s, si, size1, size2)
			return
		}
		if r1 != index[j].r {
			t.Errorf("DecodeLastRune(%q, %d) = %#04x, want %#04x", s, si, r1, index[j].r)
			return
		}
		if r2 != index[j].r {
			t.Errorf("DecodeLastRuneInString(%q, %d) = %#04x, want %#04x", s, si, r2, index[j].r)
			return
		}
		si -= size1
		if si != index[j].index {
			t.Errorf("DecodeLastRune(%q) index mismatch at %d, want %d", s, si, index[j].index)
			return
		}
		j--
	}
	if si != 0 {
		t.Errorf("DecodeLastRune(%q) finished at %d, not 0", s, si)
	}
}

// Check that negative runes encode as U+FFFD.
func TestNegativeRune(t *testing.T) {
	errorbuf := make([]byte, UTFMax)
	errorbuf = errorbuf[0:EncodeRune(errorbuf, RuneError)]
	buf := make([]byte, UTFMax)
	buf = buf[0:EncodeRune(buf, -1)]
	if !bytes.Equal(buf, errorbuf) {
		t.Errorf("incorrect encoding [% x] for -1; expected [% x]", buf, errorbuf)
	}
}

type RuneCountTest struct {
	in  string
	out int
}

var runecounttests = []RuneCountTest{
	{"abcd", 4},
	{"☺☻☹", 3},
	{"1,2,3,4", 7},
	{"\xe2\x00", 2},
	{"\xe2\x80", 2},
	{"a\xe2\x80", 3},
}

func TestRuneCount(t *testing.T) {
	for _, tt := range runecounttests {
		if out := RuneCountInString(tt.in); out != tt.out {
			t.Errorf("RuneCountInString(%q) = %d, want %d", tt.in, out, tt.out)
		}
		if out := RuneCount([]byte(tt.in)); out != tt.out {
			t.Errorf("RuneCount(%q) = %d, want %d", tt.in, out, tt.out)
		}
	}
}

func TestRuneCountNonASCIIAllocation(t *testing.T) {
	if n := testing.AllocsPerRun(10, func() {
		s := []byte("日本語日本語日本語日")
		_ = RuneCount(s)
	}); n > 0 {
		t.Errorf("unexpected RuneCount allocation, got %v, want 0", n)
	}
}

type RuneLenTest struct {
	r    rune
	size int
}

var runelentests = []RuneLenTest{
	{0, 1},
	{'e', 1},
	{'é', 2},
	{'☺', 3},
	{RuneError, 3},
	{MaxRune, 4},
	{0xD800, -1},
	{0xDFFF, -1},
	{MaxRune + 1, -1},
	{-1, -1},
}

func TestRuneLen(t *testing.T) {
	for _, tt := range runelentests {
		if size := RuneLen(tt.r); size != tt.size {
			t.Errorf("RuneLen(%#U) = %d, want %d", tt.r, size, tt.size)
		}
	}
}

type ValidTest struct {
	in  string
	out bool
}

var validTests = []ValidTest{
	{"", true},
	{"a", true},
	{"abc", true},
	{"Ж", true},
	{"ЖЖ", true},
	{"брэд-ЛГТМ", true},
	{"☺☻☹", true},
	{"aa\xe2", false},
	{string([]byte{66, 250}), false},
	{string([]byte{66, 250, 67}), false},
	{"a\uFFFDb", true},
	{string("\xF4\x8F\xBF\xBF"), true},      // U+10FFFF
	{string("\xF4\x90\x80\x80"), false},     // U+10FFFF+1; out of range
	{string("\xF7\xBF\xBF\xBF"), false},     // 0x1FFFFF; out of range
	{string("\xFB\xBF\xBF\xBF\xBF"), false}, // 0x3FFFFFF; out of range
	{string("\xc0\x80"), false},             // U+0000 encoded in two bytes: incorrect
	{string("\xed\xa0\x80"), false},         // U+D800 high surrogate (sic)
	{string("\xed\xbf\xbf"), false},         // U+DFFF low surrogate (sic)
}

func TestValid(t *testing.T) {
	for _, tt := range validTests {
		if Valid([]byte(tt.in)) != tt.out {
			t.Errorf("Valid(%q) = %v; want %v", tt.in, !tt.out, tt.out)
		}
		if ValidString(tt.in) != tt.out {
			t.Errorf("ValidString(%q) = %v; want %v", tt.in, !tt.out, tt.out)
		}
	}
}

type ValidRuneTest struct {
	r  rune
	ok bool
}

var validrunetests = []ValidRuneTest{
	{0, true},
	{'e', true},
	{'é', true},
	{'☺', true},
	{RuneError, true},
	{MaxRune, true},
	{0xD7FF, true},
	{0xD800, false},
	{0xDFFF, false},
	{0xE000, true},
	{MaxRune + 1, false},
	{-1, false},
}

func TestValidRune(t *testing.T) {
	for _, tt := range validrunetests {
		if ok := ValidRune(tt.r); ok != tt.ok {
			t.Errorf("ValidRune(%#U) = %t, want %t", tt.r, ok, tt.ok)
		}
	}
}

func BenchmarkRuneCountTenASCIIChars(b *testing.B) {
	s := []byte("0123456789")
	for i := 0; i < b.N; i++ {
		RuneCount(s)
	}
}

func BenchmarkRuneCountTenJapaneseChars(b *testing.B) {
	s := []byte("日本語日本語日本語日")
	for i := 0; i < b.N; i++ {
		RuneCount(s)
	}
}

func BenchmarkRuneCountInStringTenASCIIChars(b *testing.B) {
	for i := 0; i < b.N; i++ {
		RuneCountInString("0123456789")
	}
}

func BenchmarkRuneCountInStringTenJapaneseChars(b *testing.B) {
	for i := 0; i < b.N; i++ {
		RuneCountInString("日本語日本語日本語日")
	}
}

var ascii100000 = strings.Repeat("0123456789", 10000)

func BenchmarkValidTenASCIIChars(b *testing.B) {
	s := []byte("0123456789")
	for i := 0; i < b.N; i++ {
		Valid(s)
	}
}

func BenchmarkValid100KASCIIChars(b *testing.B) {
	s := []byte(ascii100000)
	for i := 0; i < b.N; i++ {
		Valid(s)
	}
}

func BenchmarkValidTenJapaneseChars(b *testing.B) {
	s := []byte("日本語日本語日本語日")
	for i := 0; i < b.N; i++ {
		Valid(s)
	}
}
func BenchmarkValidLongMostlyASCII(b *testing.B) {
	longMostlyASCII := []byte(longStringMostlyASCII)
	for i := 0; i < b.N; i++ {
		Valid(longMostlyASCII)
	}
}

func BenchmarkValidLongJapanese(b *testing.B) {
	longJapanese := []byte(longStringJapanese)
	for i := 0; i < b.N; i++ {
		Valid(longJapanese)
	}
}

func BenchmarkValidStringTenASCIIChars(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ValidString("0123456789")
	}
}

func BenchmarkValidString100KASCIIChars(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ValidString(ascii100000)
	}
}

func BenchmarkValidStringTenJapaneseChars(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ValidString("日本語日本語日本語日")
	}
}

func BenchmarkValidStringLongMostlyASCII(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ValidString(longStringMostlyASCII)
	}
}

func BenchmarkValidStringLongJapanese(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ValidString(longStringJapanese)
	}
}

var longStringMostlyASCII string // ~100KB, ~97% ASCII
var longStringJapanese string    // ~100KB, non-ASCII

func init() {
	const japanese = "日本語日本語日本語日"
	var b strings.Builder
	for i := 0; b.Len() < 100_000; i++ {
		if i%100 == 0 {
			b.WriteString(japanese)
		} else {
			b.WriteString("0123456789")
		}
	}
	longStringMostlyASCII = b.String()
	longStringJapanese = strings.Repeat(japanese, 100_000/len(japanese))
}

func BenchmarkEncodeASCIIRune(b *testing.B) {
	buf := make([]byte, UTFMax)
	for i := 0; i < b.N; i++ {
		EncodeRune(buf, 'a') // 1 byte
	}
}

func BenchmarkEncodeSpanishRune(b *testing.B) {
	buf := make([]byte, UTFMax)
	for i := 0; i < b.N; i++ {
		EncodeRune(buf, 'Ñ') // 2 bytes
	}
}

func BenchmarkEncodeJapaneseRune(b *testing.B) {
	buf := make([]byte, UTFMax)
	for i := 0; i < b.N; i++ {
		EncodeRune(buf, '本') // 3 bytes
	}
}

func BenchmarkEncodeMaxRune(b *testing.B) {
	buf := make([]byte, UTFMax)
	for i := 0; i < b.N; i++ {
		EncodeRune(buf, MaxRune) // 4 bytes
	}
}

func BenchmarkEncodeInvalidRuneMaxPlusOne(b *testing.B) {
	buf := make([]byte, UTFMax)
	for i := 0; i < b.N; i++ {
		EncodeRune(buf, MaxRune+1) // 3 bytes: RuneError
	}
}

func BenchmarkEncodeInvalidRuneSurrogate(b *testing.B) {
	buf := make([]byte, UTFMax)
	for i := 0; i < b.N; i++ {
		EncodeRune(buf, 0xD800) // 3 bytes: RuneError
	}
}

func BenchmarkEncodeInvalidRuneNegative(b *testing.B) {
	buf := make([]byte, UTFMax)
	for i := 0; i < b.N; i++ {
		EncodeRune(buf, -1) // 3 bytes: RuneError
	}
}

func BenchmarkAppendASCIIRune(b *testing.B) {
	buf := make([]byte, UTFMax)
	for i := 0; i < b.N; i++ {
		AppendRune(buf[:0], 'a') // 1 byte
	}
}

func BenchmarkAppendSpanishRune(b *testing.B) {
	buf := make([]byte, UTFMax)
	for i := 0; i < b.N; i++ {
		AppendRune(buf[:0], 'Ñ') // 2 bytes
	}
}

func BenchmarkAppendJapaneseRune(b *testing.B) {
	buf := make([]byte, UTFMax)
	for i := 0; i < b.N; i++ {
		AppendRune(buf[:0], '本') // 3 bytes
	}
}

func BenchmarkAppendMaxRune(b *testing.B) {
	buf := make([]byte, UTFMax)
	for i := 0; i < b.N; i++ {
		AppendRune(buf[:0], MaxRune) // 4 bytes
	}
}

func BenchmarkAppendInvalidRuneMaxPlusOne(b *testing.B) {
	buf := make([]byte, UTFMax)
	for i := 0; i < b.N; i++ {
		AppendRune(buf[:0], MaxRune+1) // 3 bytes: RuneError
	}
}

func BenchmarkAppendInvalidRuneSurrogate(b *testing.B) {
	buf := make([]byte, UTFMax)
	for i := 0; i < b.N; i++ {
		AppendRune(buf[:0], 0xD800) // 3 bytes: RuneError
	}
}

func BenchmarkAppendInvalidRuneNegative(b *testing.B) {
	buf := make([]byte, UTFMax)
	for i := 0; i < b.N; i++ {
		AppendRune(buf[:0], -1) // 3 bytes: RuneError
	}
}

func BenchmarkDecodeASCIIRune(b *testing.B) {
	a := []byte{'a'}
	for i := 0; i < b.N; i++ {
		DecodeRune(a)
	}
}

func BenchmarkDecodeJapaneseRune(b *testing.B) {
	nihon := []byte("本")
	for i := 0; i < b.N; i++ {
		DecodeRune(nihon)
	}
}

// boolSink is used to reference the return value of benchmarked
// functions to avoid dead code elimination.
var boolSink bool

func BenchmarkFullRune(b *testing.B) {
	benchmarks := []struct {
		name string
		data []byte
	}{
		{"ASCII", []byte("a")},
		{"Incomplete", []byte("\xf0\x90\x80")},
		{"Japanese", []byte("本")},
	}
	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				boolSink = FullRune(bm.data)
			}
		})
	}
}

"""



```