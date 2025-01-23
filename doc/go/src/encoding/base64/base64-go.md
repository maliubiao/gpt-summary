Response:
我的思考过程如下：

1. **理解文件路径和目的:** 文件路径 `go/src/encoding/base64/base64.go` 明确指出这是 Go 语言标准库中用于实现 Base64 编码和解码功能的部分。

2. **概览代码结构:** 快速浏览代码，注意重要的类型定义（`Encoding`），常量定义（`StdPadding`, `NoPadding`），和导出的函数（以大写字母开头）。  这能帮助我快速了解代码的核心概念和对外接口。

3. **识别核心功能:**  从类型定义 `Encoding` 可以看出，其目的是定义一个 Base64 编码方案，包括编码字符集、解码映射、填充字符以及是否严格解码。导出的函数像 `NewEncoding`, `WithPadding`, `Strict`, `Encode`, `Decode`, `NewEncoder`, `NewDecoder` 等都直接指向编码和解码的核心功能。

4. **归纳功能点:** 基于以上的观察，我可以列出代码的主要功能：
    * 定义 Base64 编码方案。
    * 创建新的编码器和解码器。
    * 执行 Base64 编码。
    * 执行 Base64 解码。
    * 提供预定义的标准和 URL 安全的 Base64 编码。
    * 支持无填充的 Base64 编码。
    * 支持严格模式解码。

5. **推理 Go 语言功能实现:** 这是一个实现了 Base64 编码和解码功能的库。这是计算机科学中一个常见的概念，用于将二进制数据转换为 ASCII 字符串格式，以便在网络传输或存储时使用。

6. **编写代码示例:**  为了说明 Base64 的编码和解码功能，我需要提供一个简单的 Go 代码示例。这个示例应该演示如何使用 `StdEncoding` 进行编码和解码，并验证解码后的数据是否与原始数据一致。需要包含假设的输入和输出。

7. **考虑命令行参数处理:**  标准库的 `encoding/base64` 包本身不直接处理命令行参数。Base64 编码和解码通常是其他应用程序的组成部分，这些应用程序可能会通过命令行参数接收输入或指定输出。我需要解释这一点，并指出可以结合其他 Go 库（如 `flag` 包）来实现命令行工具。

8. **识别易犯错的点:**  在 Base64 使用中，常见的错误包括：
    * 使用错误的编码方案。
    * 处理填充字符不当。
    * 解码非法的 Base64 字符串。
    * 对大型数据流使用 `Encode` 和 `Decode` 函数，而不是使用 `NewEncoder` 和 `NewDecoder`。我需要举例说明这些错误。

9. **组织答案:** 最后，将以上所有信息组织成结构清晰、逻辑连贯的中文答案。确保每个功能点都得到解释，并提供相应的代码示例、命令行参数说明和易犯错误示例。  我需要使用清晰的标题和段落来组织信息。

10. **审查和完善:** 重新阅读答案，检查是否有遗漏、错误或不清楚的地方，并进行必要的修改和完善。例如，我最初可能只想到编码和解码，但后来意识到还需要解释 `Encoding` 类型的意义和各种预定义的编码。  对于命令行参数的处理，需要明确指出标准库本身不直接处理，而是需要结合其他库。

通过以上步骤，我能够系统地分析给定的 Go 代码，提取其功能，推理其实现的 Go 语言功能，提供代码示例，解释命令行参数处理，并识别潜在的错误。这个过程强调了从代码结构到具体功能，再到实际应用和潜在问题的全面理解。
这段代码是 Go 语言 `encoding/base64` 包的一部分，它实现了 **Base64 编码和解码** 的功能。

以下是它的功能列表：

1. **定义了 `Encoding` 类型:**  `Encoding` 结构体用于表示一个 Base64 编码方案，包含编码字符集 (`encode`)、解码映射 (`decodeMap`)、填充字符 (`padChar`) 和是否启用严格解码 (`strict`)。

2. **提供了创建 `Encoding` 的方法:**
   - `NewEncoding(encoder string)`:  允许用户使用自定义的 64 字符字母表创建一个新的 `Encoding` 实例。
   - `WithPadding(padding rune)`:  创建一个与现有 `Encoding` 实例相同的新实例，但可以指定不同的填充字符，或者禁用填充（使用 `NoPadding`）。
   - `Strict()`: 创建一个与现有 `Encoding` 实例相同的新实例，但启用了严格解码模式。

3. **提供了预定义的 `Encoding` 实例:**
   - `StdEncoding`: 标准的 Base64 编码，使用 "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" 字符集和 '=' 作为填充。
   - `URLEncoding`: URL 和文件名安全的 Base64 编码，使用 "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" 字符集，没有 '+' 和 '/'。
   - `RawStdEncoding`: 标准的无填充 Base64 编码。
   - `RawURLEncoding`: URL 和文件名安全的无填充 Base64 编码。

4. **提供了编码功能:**
   - `Encode(dst, src []byte)`: 将 `src` 中的字节数据使用指定的 `Encoding` 编码到 `dst` 中。输出会填充到 4 字节的倍数。
   - `AppendEncode(dst, src []byte) []byte`: 将 `src` 编码后的数据追加到 `dst` 中，并返回扩展后的切片。
   - `EncodeToString(src []byte) string`: 将 `src` 编码成 Base64 字符串并返回。
   - `NewEncoder(enc *Encoding, w io.Writer) io.WriteCloser`: 创建一个 Base64 流式编码器。写入该编码器的数据会被编码后写入到提供的 `io.Writer` 中。需要 `Close()` 来刷新任何未写入的块。
   - `EncodedLen(n int)`:  返回编码 `n` 个字节所需的字节数。

5. **提供了解码功能:**
   - `Decode(dst, src []byte)`: 将 `src` 中的 Base64 编码数据解码到 `dst` 中。如果 `src` 包含无效的 Base64 数据，会返回 `CorruptInputError`。
   - `AppendDecode(dst, src []byte) ([]byte, error)`: 将 `src` 解码后的数据追加到 `dst` 中，并返回扩展后的切片。如果输入格式错误，会返回部分解码的数据和一个错误。
   - `DecodeString(s string) ([]byte, error)`: 解码 Base64 字符串 `s` 并返回字节切片。
   - `NewDecoder(enc *Encoding, r io.Reader) io.Reader`: 创建一个 Base64 流式解码器。从该解码器读取数据会解码从提供的 `io.Reader` 读取的 Base64 编码数据。会忽略换行符。
   - `DecodedLen(n int)`: 返回解码 `n` 个字节的 Base64 编码数据后可能的最大字节数。

6. **定义了错误类型:**
   - `CorruptInputError`:  表示解码时遇到了非法的 Base64 数据。

**推理出的 Go 语言功能实现：Base64 编码和解码**

Base64 是一种将二进制数据转换为 ASCII 字符串的编码方式，常用于在不支持直接传输二进制数据的协议中传输数据，例如电子邮件的 MIME 协议。

**Go 代码示例：**

```go
package main

import (
	"encoding/base64"
	"fmt"
)

func main() {
	// 假设的输入数据
	data := []byte("Hello, World!")

	// 使用标准 Base64 编码
	encodedString := base64.StdEncoding.EncodeToString(data)
	fmt.Println("Encoded:", encodedString) // 输出: Encoded: SGVsbG8sIFdvcmxkIQ==

	// 解码 Base64 字符串
	decodedData, err := base64.StdEncoding.DecodeString(encodedString)
	if err != nil {
		fmt.Println("Decode error:", err)
		return
	}
	fmt.Println("Decoded:", string(decodedData)) // 输出: Decoded: Hello, World!

	// 使用 URL 安全的 Base64 编码
	urlEncodedString := base64.URLEncoding.EncodeToString(data)
	fmt.Println("URL Encoded:", urlEncodedString) // 输出: URL Encoded: SGVsbG8sIFdvcmxkIQ==

	// 解码 URL 安全的 Base64 字符串
	urlDecodedData, err := base64.URLEncoding.DecodeString(urlEncodedString)
	if err != nil {
		fmt.Println("URL Decode error:", err)
		return
	}
	fmt.Println("URL Decoded:", string(urlDecodedData)) // 输出: URL Decoded: Hello, World!
}
```

**假设的输入与输出：**

- **输入 (编码):** `[]byte("This is a test.")`
- **输出 (编码，使用 `StdEncoding`):** `"VGhpcyBpcyBhIHRlc3Qu"`
- **输入 (解码):** `"VGhpcyBpcyBhIHRlc3Qu"`
- **输出 (解码，使用 `StdEncoding`):** `[]byte("This is a test.")`

**命令行参数的具体处理：**

`encoding/base64` 包本身**不直接处理命令行参数**。它的主要功能是提供 Base64 编码和解码的 API。如果你想创建一个处理命令行参数的 Base64 编码/解码工具，你需要结合其他的 Go 语言库，例如 `flag` 包。

以下是一个简单的示例，演示如何使用 `flag` 包创建一个命令行工具来编码或解码 Base64 数据：

```go
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
)

func main() {
	encodeFlag := flag.Bool("encode", false, "Encode the input")
	decodeFlag := flag.Bool("decode", false, "Decode the input")
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Println("Usage: base64_tool [-encode|-decode] <input>")
		return
	}

	input := flag.Arg(0)

	if *encodeFlag {
		encoded := base64.StdEncoding.EncodeToString([]byte(input))
		fmt.Println(encoded)
	} else if *decodeFlag {
		decoded, err := base64.StdEncoding.DecodeString(input)
		if err != nil {
			fmt.Println("Error decoding:", err)
			os.Exit(1)
		}
		fmt.Println(string(decoded))
	} else {
		fmt.Println("Please specify either -encode or -decode flag.")
	}
}
```

**使用示例：**

```bash
go run your_tool.go -encode "Hello"
# 输出: SGVsbG8=

go run your_tool.go -decode SGVsbG8=
# 输出: Hello
```

**使用者易犯错的点：**

1. **混淆不同的编码方案：** 常见的错误是使用 URL 安全的编码来解码标准的 Base64 字符串，或者反之。这会导致解码失败或得到错误的结果。

   **例子：**

   ```go
   package main

   import (
   	"encoding/base64"
   	"fmt"
   )

   func main() {
   	standardEncoded := "SGVsbG8="
   	// 尝试使用 URLEncoding 解码标准编码的字符串
   	decoded, err := base64.URLEncoding.DecodeString(standardEncoded)
   	if err != nil {
   		fmt.Println("Error decoding:", err) // 输出: Error decoding: illegal base64 data at input byte 5
   		return
   	}
   	fmt.Println("Decoded:", string(decoded))
   }
   ```

2. **忘记处理填充字符：**  Base64 编码通常会使用 `=` 作为填充字符，以确保输出长度是 4 的倍数。在某些情况下（例如 URL 安全的编码或使用了 `RawStdEncoding`/`RawURLEncoding`），可能没有填充。尝试解码带有错误填充或缺少填充的字符串会导致错误。

   **例子：**

   ```go
   package main

   import (
   	"encoding/base64"
   	"fmt"
   )

   func main() {
   	// 缺少填充的标准 Base64 字符串（不完整的块）
   	incompleteEncoded := "SGVsbG"
   	decoded, err := base64.StdEncoding.DecodeString(incompleteEncoded)
   	if err != nil {
   		fmt.Println("Error decoding:", err) // 输出: Error decoding: illegal base64 data at input byte 6
   		return
   	}
   	fmt.Println("Decoded:", string(decoded))
   }
   ```

3. **在处理大数据流时直接使用 `Encode` 和 `Decode`：**  `Encode` 和 `Decode` 函数适用于处理完整的字节切片。对于大型数据流，应该使用 `NewEncoder` 和 `NewDecoder` 创建流式编码器和解码器，这样可以避免一次性加载整个数据到内存中。

理解这些功能和潜在的陷阱可以帮助你正确地使用 Go 语言的 `encoding/base64` 包进行 Base64 编码和解码操作。

### 提示词
```
这是路径为go/src/encoding/base64/base64.go的go语言实现的一部分， 请列举一下它的功能, 　
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

// Package base64 implements base64 encoding as specified by RFC 4648.
package base64

import (
	"encoding/binary"
	"io"
	"slices"
	"strconv"
)

/*
 * Encodings
 */

// An Encoding is a radix 64 encoding/decoding scheme, defined by a
// 64-character alphabet. The most common encoding is the "base64"
// encoding defined in RFC 4648 and used in MIME (RFC 2045) and PEM
// (RFC 1421).  RFC 4648 also defines an alternate encoding, which is
// the standard encoding with - and _ substituted for + and /.
type Encoding struct {
	encode    [64]byte   // mapping of symbol index to symbol byte value
	decodeMap [256]uint8 // mapping of symbol byte value to symbol index
	padChar   rune
	strict    bool
}

const (
	StdPadding rune = '=' // Standard padding character
	NoPadding  rune = -1  // No padding
)

const (
	decodeMapInitialize = "" +
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" +
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
	invalidIndex = '\xff'
)

// NewEncoding returns a new padded Encoding defined by the given alphabet,
// which must be a 64-byte string that contains unique byte values and
// does not contain the padding character or CR / LF ('\r', '\n').
// The alphabet is treated as a sequence of byte values
// without any special treatment for multi-byte UTF-8.
// The resulting Encoding uses the default padding character ('='),
// which may be changed or disabled via [Encoding.WithPadding].
func NewEncoding(encoder string) *Encoding {
	if len(encoder) != 64 {
		panic("encoding alphabet is not 64-bytes long")
	}

	e := new(Encoding)
	e.padChar = StdPadding
	copy(e.encode[:], encoder)
	copy(e.decodeMap[:], decodeMapInitialize)

	for i := 0; i < len(encoder); i++ {
		// Note: While we document that the alphabet cannot contain
		// the padding character, we do not enforce it since we do not know
		// if the caller intends to switch the padding from StdPadding later.
		switch {
		case encoder[i] == '\n' || encoder[i] == '\r':
			panic("encoding alphabet contains newline character")
		case e.decodeMap[encoder[i]] != invalidIndex:
			panic("encoding alphabet includes duplicate symbols")
		}
		e.decodeMap[encoder[i]] = uint8(i)
	}
	return e
}

// WithPadding creates a new encoding identical to enc except
// with a specified padding character, or [NoPadding] to disable padding.
// The padding character must not be '\r' or '\n',
// must not be contained in the encoding's alphabet,
// must not be negative, and must be a rune equal or below '\xff'.
// Padding characters above '\x7f' are encoded as their exact byte value
// rather than using the UTF-8 representation of the codepoint.
func (enc Encoding) WithPadding(padding rune) *Encoding {
	switch {
	case padding < NoPadding || padding == '\r' || padding == '\n' || padding > 0xff:
		panic("invalid padding")
	case padding != NoPadding && enc.decodeMap[byte(padding)] != invalidIndex:
		panic("padding contained in alphabet")
	}
	enc.padChar = padding
	return &enc
}

// Strict creates a new encoding identical to enc except with
// strict decoding enabled. In this mode, the decoder requires that
// trailing padding bits are zero, as described in RFC 4648 section 3.5.
//
// Note that the input is still malleable, as new line characters
// (CR and LF) are still ignored.
func (enc Encoding) Strict() *Encoding {
	enc.strict = true
	return &enc
}

// StdEncoding is the standard base64 encoding, as defined in RFC 4648.
var StdEncoding = NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

// URLEncoding is the alternate base64 encoding defined in RFC 4648.
// It is typically used in URLs and file names.
var URLEncoding = NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

// RawStdEncoding is the standard raw, unpadded base64 encoding,
// as defined in RFC 4648 section 3.2.
// This is the same as [StdEncoding] but omits padding characters.
var RawStdEncoding = StdEncoding.WithPadding(NoPadding)

// RawURLEncoding is the unpadded alternate base64 encoding defined in RFC 4648.
// It is typically used in URLs and file names.
// This is the same as [URLEncoding] but omits padding characters.
var RawURLEncoding = URLEncoding.WithPadding(NoPadding)

/*
 * Encoder
 */

// Encode encodes src using the encoding enc,
// writing [Encoding.EncodedLen](len(src)) bytes to dst.
//
// The encoding pads the output to a multiple of 4 bytes,
// so Encode is not appropriate for use on individual blocks
// of a large data stream. Use [NewEncoder] instead.
func (enc *Encoding) Encode(dst, src []byte) {
	if len(src) == 0 {
		return
	}
	// enc is a pointer receiver, so the use of enc.encode within the hot
	// loop below means a nil check at every operation. Lift that nil check
	// outside of the loop to speed up the encoder.
	_ = enc.encode

	di, si := 0, 0
	n := (len(src) / 3) * 3
	for si < n {
		// Convert 3x 8bit source bytes into 4 bytes
		val := uint(src[si+0])<<16 | uint(src[si+1])<<8 | uint(src[si+2])

		dst[di+0] = enc.encode[val>>18&0x3F]
		dst[di+1] = enc.encode[val>>12&0x3F]
		dst[di+2] = enc.encode[val>>6&0x3F]
		dst[di+3] = enc.encode[val&0x3F]

		si += 3
		di += 4
	}

	remain := len(src) - si
	if remain == 0 {
		return
	}
	// Add the remaining small block
	val := uint(src[si+0]) << 16
	if remain == 2 {
		val |= uint(src[si+1]) << 8
	}

	dst[di+0] = enc.encode[val>>18&0x3F]
	dst[di+1] = enc.encode[val>>12&0x3F]

	switch remain {
	case 2:
		dst[di+2] = enc.encode[val>>6&0x3F]
		if enc.padChar != NoPadding {
			dst[di+3] = byte(enc.padChar)
		}
	case 1:
		if enc.padChar != NoPadding {
			dst[di+2] = byte(enc.padChar)
			dst[di+3] = byte(enc.padChar)
		}
	}
}

// AppendEncode appends the base64 encoded src to dst
// and returns the extended buffer.
func (enc *Encoding) AppendEncode(dst, src []byte) []byte {
	n := enc.EncodedLen(len(src))
	dst = slices.Grow(dst, n)
	enc.Encode(dst[len(dst):][:n], src)
	return dst[:len(dst)+n]
}

// EncodeToString returns the base64 encoding of src.
func (enc *Encoding) EncodeToString(src []byte) string {
	buf := make([]byte, enc.EncodedLen(len(src)))
	enc.Encode(buf, src)
	return string(buf)
}

type encoder struct {
	err  error
	enc  *Encoding
	w    io.Writer
	buf  [3]byte    // buffered data waiting to be encoded
	nbuf int        // number of bytes in buf
	out  [1024]byte // output buffer
}

func (e *encoder) Write(p []byte) (n int, err error) {
	if e.err != nil {
		return 0, e.err
	}

	// Leading fringe.
	if e.nbuf > 0 {
		var i int
		for i = 0; i < len(p) && e.nbuf < 3; i++ {
			e.buf[e.nbuf] = p[i]
			e.nbuf++
		}
		n += i
		p = p[i:]
		if e.nbuf < 3 {
			return
		}
		e.enc.Encode(e.out[:], e.buf[:])
		if _, e.err = e.w.Write(e.out[:4]); e.err != nil {
			return n, e.err
		}
		e.nbuf = 0
	}

	// Large interior chunks.
	for len(p) >= 3 {
		nn := len(e.out) / 4 * 3
		if nn > len(p) {
			nn = len(p)
			nn -= nn % 3
		}
		e.enc.Encode(e.out[:], p[:nn])
		if _, e.err = e.w.Write(e.out[0 : nn/3*4]); e.err != nil {
			return n, e.err
		}
		n += nn
		p = p[nn:]
	}

	// Trailing fringe.
	copy(e.buf[:], p)
	e.nbuf = len(p)
	n += len(p)
	return
}

// Close flushes any pending output from the encoder.
// It is an error to call Write after calling Close.
func (e *encoder) Close() error {
	// If there's anything left in the buffer, flush it out
	if e.err == nil && e.nbuf > 0 {
		e.enc.Encode(e.out[:], e.buf[:e.nbuf])
		_, e.err = e.w.Write(e.out[:e.enc.EncodedLen(e.nbuf)])
		e.nbuf = 0
	}
	return e.err
}

// NewEncoder returns a new base64 stream encoder. Data written to
// the returned writer will be encoded using enc and then written to w.
// Base64 encodings operate in 4-byte blocks; when finished
// writing, the caller must Close the returned encoder to flush any
// partially written blocks.
func NewEncoder(enc *Encoding, w io.Writer) io.WriteCloser {
	return &encoder{enc: enc, w: w}
}

// EncodedLen returns the length in bytes of the base64 encoding
// of an input buffer of length n.
func (enc *Encoding) EncodedLen(n int) int {
	if enc.padChar == NoPadding {
		return n/3*4 + (n%3*8+5)/6 // minimum # chars at 6 bits per char
	}
	return (n + 2) / 3 * 4 // minimum # 4-char quanta, 3 bytes each
}

/*
 * Decoder
 */

type CorruptInputError int64

func (e CorruptInputError) Error() string {
	return "illegal base64 data at input byte " + strconv.FormatInt(int64(e), 10)
}

// decodeQuantum decodes up to 4 base64 bytes. The received parameters are
// the destination buffer dst, the source buffer src and an index in the
// source buffer si.
// It returns the number of bytes read from src, the number of bytes written
// to dst, and an error, if any.
func (enc *Encoding) decodeQuantum(dst, src []byte, si int) (nsi, n int, err error) {
	// Decode quantum using the base64 alphabet
	var dbuf [4]byte
	dlen := 4

	// Lift the nil check outside of the loop.
	_ = enc.decodeMap

	for j := 0; j < len(dbuf); j++ {
		if len(src) == si {
			switch {
			case j == 0:
				return si, 0, nil
			case j == 1, enc.padChar != NoPadding:
				return si, 0, CorruptInputError(si - j)
			}
			dlen = j
			break
		}
		in := src[si]
		si++

		out := enc.decodeMap[in]
		if out != 0xff {
			dbuf[j] = out
			continue
		}

		if in == '\n' || in == '\r' {
			j--
			continue
		}

		if rune(in) != enc.padChar {
			return si, 0, CorruptInputError(si - 1)
		}

		// We've reached the end and there's padding
		switch j {
		case 0, 1:
			// incorrect padding
			return si, 0, CorruptInputError(si - 1)
		case 2:
			// "==" is expected, the first "=" is already consumed.
			// skip over newlines
			for si < len(src) && (src[si] == '\n' || src[si] == '\r') {
				si++
			}
			if si == len(src) {
				// not enough padding
				return si, 0, CorruptInputError(len(src))
			}
			if rune(src[si]) != enc.padChar {
				// incorrect padding
				return si, 0, CorruptInputError(si - 1)
			}

			si++
		}

		// skip over newlines
		for si < len(src) && (src[si] == '\n' || src[si] == '\r') {
			si++
		}
		if si < len(src) {
			// trailing garbage
			err = CorruptInputError(si)
		}
		dlen = j
		break
	}

	// Convert 4x 6bit source bytes into 3 bytes
	val := uint(dbuf[0])<<18 | uint(dbuf[1])<<12 | uint(dbuf[2])<<6 | uint(dbuf[3])
	dbuf[2], dbuf[1], dbuf[0] = byte(val>>0), byte(val>>8), byte(val>>16)
	switch dlen {
	case 4:
		dst[2] = dbuf[2]
		dbuf[2] = 0
		fallthrough
	case 3:
		dst[1] = dbuf[1]
		if enc.strict && dbuf[2] != 0 {
			return si, 0, CorruptInputError(si - 1)
		}
		dbuf[1] = 0
		fallthrough
	case 2:
		dst[0] = dbuf[0]
		if enc.strict && (dbuf[1] != 0 || dbuf[2] != 0) {
			return si, 0, CorruptInputError(si - 2)
		}
	}

	return si, dlen - 1, err
}

// AppendDecode appends the base64 decoded src to dst
// and returns the extended buffer.
// If the input is malformed, it returns the partially decoded src and an error.
// New line characters (\r and \n) are ignored.
func (enc *Encoding) AppendDecode(dst, src []byte) ([]byte, error) {
	// Compute the output size without padding to avoid over allocating.
	n := len(src)
	for n > 0 && rune(src[n-1]) == enc.padChar {
		n--
	}
	n = decodedLen(n, NoPadding)

	dst = slices.Grow(dst, n)
	n, err := enc.Decode(dst[len(dst):][:n], src)
	return dst[:len(dst)+n], err
}

// DecodeString returns the bytes represented by the base64 string s.
// If the input is malformed, it returns the partially decoded data and
// [CorruptInputError]. New line characters (\r and \n) are ignored.
func (enc *Encoding) DecodeString(s string) ([]byte, error) {
	dbuf := make([]byte, enc.DecodedLen(len(s)))
	n, err := enc.Decode(dbuf, []byte(s))
	return dbuf[:n], err
}

type decoder struct {
	err     error
	readErr error // error from r.Read
	enc     *Encoding
	r       io.Reader
	buf     [1024]byte // leftover input
	nbuf    int
	out     []byte // leftover decoded output
	outbuf  [1024 / 4 * 3]byte
}

func (d *decoder) Read(p []byte) (n int, err error) {
	// Use leftover decoded output from last read.
	if len(d.out) > 0 {
		n = copy(p, d.out)
		d.out = d.out[n:]
		return n, nil
	}

	if d.err != nil {
		return 0, d.err
	}

	// This code assumes that d.r strips supported whitespace ('\r' and '\n').

	// Refill buffer.
	for d.nbuf < 4 && d.readErr == nil {
		nn := len(p) / 3 * 4
		if nn < 4 {
			nn = 4
		}
		if nn > len(d.buf) {
			nn = len(d.buf)
		}
		nn, d.readErr = d.r.Read(d.buf[d.nbuf:nn])
		d.nbuf += nn
	}

	if d.nbuf < 4 {
		if d.enc.padChar == NoPadding && d.nbuf > 0 {
			// Decode final fragment, without padding.
			var nw int
			nw, d.err = d.enc.Decode(d.outbuf[:], d.buf[:d.nbuf])
			d.nbuf = 0
			d.out = d.outbuf[:nw]
			n = copy(p, d.out)
			d.out = d.out[n:]
			if n > 0 || len(p) == 0 && len(d.out) > 0 {
				return n, nil
			}
			if d.err != nil {
				return 0, d.err
			}
		}
		d.err = d.readErr
		if d.err == io.EOF && d.nbuf > 0 {
			d.err = io.ErrUnexpectedEOF
		}
		return 0, d.err
	}

	// Decode chunk into p, or d.out and then p if p is too small.
	nr := d.nbuf / 4 * 4
	nw := d.nbuf / 4 * 3
	if nw > len(p) {
		nw, d.err = d.enc.Decode(d.outbuf[:], d.buf[:nr])
		d.out = d.outbuf[:nw]
		n = copy(p, d.out)
		d.out = d.out[n:]
	} else {
		n, d.err = d.enc.Decode(p, d.buf[:nr])
	}
	d.nbuf -= nr
	copy(d.buf[:d.nbuf], d.buf[nr:])
	return n, d.err
}

// Decode decodes src using the encoding enc. It writes at most
// [Encoding.DecodedLen](len(src)) bytes to dst and returns the number of bytes
// written. The caller must ensure that dst is large enough to hold all
// the decoded data. If src contains invalid base64 data, it will return the
// number of bytes successfully written and [CorruptInputError].
// New line characters (\r and \n) are ignored.
func (enc *Encoding) Decode(dst, src []byte) (n int, err error) {
	if len(src) == 0 {
		return 0, nil
	}

	// Lift the nil check outside of the loop. enc.decodeMap is directly
	// used later in this function, to let the compiler know that the
	// receiver can't be nil.
	_ = enc.decodeMap

	si := 0
	for strconv.IntSize >= 64 && len(src)-si >= 8 && len(dst)-n >= 8 {
		src2 := src[si : si+8]
		if dn, ok := assemble64(
			enc.decodeMap[src2[0]],
			enc.decodeMap[src2[1]],
			enc.decodeMap[src2[2]],
			enc.decodeMap[src2[3]],
			enc.decodeMap[src2[4]],
			enc.decodeMap[src2[5]],
			enc.decodeMap[src2[6]],
			enc.decodeMap[src2[7]],
		); ok {
			binary.BigEndian.PutUint64(dst[n:], dn)
			n += 6
			si += 8
		} else {
			var ninc int
			si, ninc, err = enc.decodeQuantum(dst[n:], src, si)
			n += ninc
			if err != nil {
				return n, err
			}
		}
	}

	for len(src)-si >= 4 && len(dst)-n >= 4 {
		src2 := src[si : si+4]
		if dn, ok := assemble32(
			enc.decodeMap[src2[0]],
			enc.decodeMap[src2[1]],
			enc.decodeMap[src2[2]],
			enc.decodeMap[src2[3]],
		); ok {
			binary.BigEndian.PutUint32(dst[n:], dn)
			n += 3
			si += 4
		} else {
			var ninc int
			si, ninc, err = enc.decodeQuantum(dst[n:], src, si)
			n += ninc
			if err != nil {
				return n, err
			}
		}
	}

	for si < len(src) {
		var ninc int
		si, ninc, err = enc.decodeQuantum(dst[n:], src, si)
		n += ninc
		if err != nil {
			return n, err
		}
	}
	return n, err
}

// assemble32 assembles 4 base64 digits into 3 bytes.
// Each digit comes from the decode map, and will be 0xff
// if it came from an invalid character.
func assemble32(n1, n2, n3, n4 byte) (dn uint32, ok bool) {
	// Check that all the digits are valid. If any of them was 0xff, their
	// bitwise OR will be 0xff.
	if n1|n2|n3|n4 == 0xff {
		return 0, false
	}
	return uint32(n1)<<26 |
			uint32(n2)<<20 |
			uint32(n3)<<14 |
			uint32(n4)<<8,
		true
}

// assemble64 assembles 8 base64 digits into 6 bytes.
// Each digit comes from the decode map, and will be 0xff
// if it came from an invalid character.
func assemble64(n1, n2, n3, n4, n5, n6, n7, n8 byte) (dn uint64, ok bool) {
	// Check that all the digits are valid. If any of them was 0xff, their
	// bitwise OR will be 0xff.
	if n1|n2|n3|n4|n5|n6|n7|n8 == 0xff {
		return 0, false
	}
	return uint64(n1)<<58 |
			uint64(n2)<<52 |
			uint64(n3)<<46 |
			uint64(n4)<<40 |
			uint64(n5)<<34 |
			uint64(n6)<<28 |
			uint64(n7)<<22 |
			uint64(n8)<<16,
		true
}

type newlineFilteringReader struct {
	wrapped io.Reader
}

func (r *newlineFilteringReader) Read(p []byte) (int, error) {
	n, err := r.wrapped.Read(p)
	for n > 0 {
		offset := 0
		for i, b := range p[:n] {
			if b != '\r' && b != '\n' {
				if i != offset {
					p[offset] = b
				}
				offset++
			}
		}
		if offset > 0 {
			return offset, err
		}
		// Previous buffer entirely whitespace, read again
		n, err = r.wrapped.Read(p)
	}
	return n, err
}

// NewDecoder constructs a new base64 stream decoder.
func NewDecoder(enc *Encoding, r io.Reader) io.Reader {
	return &decoder{enc: enc, r: &newlineFilteringReader{r}}
}

// DecodedLen returns the maximum length in bytes of the decoded data
// corresponding to n bytes of base64-encoded data.
func (enc *Encoding) DecodedLen(n int) int {
	return decodedLen(n, enc.padChar)
}

func decodedLen(n int, padChar rune) int {
	if padChar == NoPadding {
		// Unpadded data may end with partial block of 2-3 characters.
		return n/4*3 + n%4*6/8
	}
	// Padded base64 should always be a multiple of 4 characters in length.
	return n / 4 * 3
}
```