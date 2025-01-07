Response:
Let's break down the thought process for analyzing the provided Go code snippet for `encoding/base32`.

1. **Identify the Core Purpose:** The package name `base32` and the initial comment clearly indicate that this code implements base32 encoding and decoding as defined by RFC 4648. This is the fundamental understanding to build upon.

2. **Examine Key Data Structures:**  The `Encoding` struct is central. It contains:
    * `encode [32]byte`: The alphabet for encoding.
    * `decodeMap [256]uint8`: A lookup table for decoding.
    * `padChar rune`: The padding character.

   Understanding this struct is crucial because it defines how base32 is configured. The `StdEncoding` and `HexEncoding` constants show predefined standard and hexadecimal base32 alphabets.

3. **Analyze Functions Related to Encoding:** Look for functions whose names suggest encoding:
    * `NewEncoding(encoder string) *Encoding`:  Creates a new `Encoding` instance with a custom alphabet. Important for understanding flexibility.
    * `WithPadding(padding rune) *Encoding`: Modifies an existing `Encoding` to use a specific padding character or disable it. Highlights customizability.
    * `Encode(dst, src []byte)`:  The core encoding function. Note the in-place encoding and the mention of padding to multiples of 8 bytes.
    * `AppendEncode(dst, src []byte) []byte`:  Convenience function to append encoded data to a slice.
    * `EncodeToString(src []byte) string`:  Encodes to a string.
    * `NewEncoder(enc *Encoding, w io.Writer) io.WriteCloser`: Creates a streaming encoder. Important for handling large data.
    * `EncodedLen(n int) int`: Calculates the encoded length.

4. **Analyze Functions Related to Decoding:** Look for functions whose names suggest decoding:
    * `decode(dst, src []byte) (n int, end bool, err error)`: The core decoding function. Notice the `end` flag indicating padding and potential errors.
    * `Decode(dst, src []byte) (n int, err error)`:  Public decoding function, handling newline stripping.
    * `AppendDecode(dst, src []byte) ([]byte, error)`:  Appends decoded data.
    * `DecodeString(s string) ([]byte, error)`: Decodes from a string.
    * `NewDecoder(enc *Encoding, r io.Reader) io.Reader`: Creates a streaming decoder.
    * `DecodedLen(n int) int`: Calculates the decoded length.

5. **Identify Helper Functions and Constants:**
    * `StdPadding`, `NoPadding`: Constants for standard and no padding.
    * `decodeMapInitialize`, `invalidIndex`:  Internal constants for the decode map.
    * `CorruptInputError`: A custom error type for invalid base32 data.
    * `stripNewlines(dst, src []byte) int`:  Handles newline removal.
    * `newlineFilteringReader`: An `io.Reader` that filters out newlines.

6. **Infer Overall Functionality:** Based on the examined components, conclude that the package provides:
    * Creation of base32 encoders/decoders with standard or custom alphabets.
    * Support for standard padding or disabling padding.
    * Functions for encoding/decoding byte slices and strings.
    * Streaming encoding/decoding capabilities for larger datasets.
    * Error handling for invalid input.
    * Handling (ignoring) of newline characters in the input for decoding.

7. **Construct Examples (Code Inference):**  Think about typical use cases:
    * Basic encoding and decoding with the standard alphabet.
    * Encoding and decoding with a custom alphabet.
    * Encoding and decoding without padding.
    * Streaming encoding and decoding.

8. **Identify Potential Pitfalls (User Mistakes):**
    * Using the wrong encoding for decoding.
    * Incorrectly handling padding when using a non-standard encoding.
    * Not closing the encoder when using streaming encoding, leading to incomplete output.

9. **Address Specific Prompts:** Go back to the initial request and ensure all parts are addressed:
    * List functionalities.
    * Infer and demonstrate with code examples (with input/output assumptions).
    * Explain the Go language feature implemented (Base32 encoding/decoding).
    * Discuss command-line arguments (none in this code).
    * Point out common mistakes.
    * Format the answer in Chinese.

10. **Review and Refine:**  Read through the generated answer, ensuring clarity, accuracy, and completeness. Check for any inconsistencies or missing information. For instance, initially, I might forget to explicitly mention the handling of newlines, but upon closer inspection of the `Decode` function and the `newlineFilteringReader`, I would add that detail. Similarly, realizing the `Encoder` needs closing would be a refinement point.
这段代码是 Go 语言标准库 `encoding/base32` 包的一部分，它实现了 **Base32 编码**。Base32 是一种将任意二进制数据转换成由 32 个 ASCII 字符组成的文本格式的编码方案。

以下是该代码的主要功能：

1. **定义了 Base32 编码方案的结构体 `Encoding`:**  `Encoding` 结构体包含了编码和解码所需的字符映射表 (`encode` 和 `decodeMap`) 以及填充字符 (`padChar`)。这允许定义不同的 Base32 变体（例如标准 Base32 和 Base32Hex）。

2. **提供了创建新的 `Encoding` 实例的方法 `NewEncoding`:**  用户可以通过提供一个 32 字节的字符串作为字母表来创建自定义的 Base32 编码器。此方法会进行一些校验，例如字母表长度、唯一性以及是否包含换行符。

3. **提供了预定义的标准 Base32 编码器 `StdEncoding` 和 Base32Hex 编码器 `HexEncoding`:**  `StdEncoding` 使用 RFC 4648 中定义的标准字母表 "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"，而 `HexEncoding` 使用 "0123456789ABCDEFGHIJKLMNOPQRSTUV"，常用于 DNSSEC。

4. **提供了修改编码器填充字符的方法 `WithPadding`:**  用户可以修改现有编码器的填充字符，或者禁用填充。

5. **实现了编码功能：**
   - `Encode(dst, src []byte)`: 将 `src` 中的字节数据编码到 `dst` 中。编码后的数据长度是 `Encoding.EncodedLen(len(src))`。编码过程会将输入数据分成 5 字节一组，然后映射到 8 个 Base32 字符。如果最后一组不足 5 字节，会进行填充。
   - `AppendEncode(dst, src []byte) []byte`: 将 `src` 编码后的数据追加到 `dst` 中，并返回新的 `dst` 切片。
   - `EncodeToString(src []byte) string`: 将 `src` 编码成一个字符串。
   - `NewEncoder(enc *Encoding, w io.Writer) io.WriteCloser`:  返回一个实现了 `io.WriteCloser` 接口的编码器，可以将数据流式地写入到 `w` 中进行编码。这对于处理大量数据非常有用，因为它不需要将所有数据加载到内存中。
   - `EncodedLen(n int) int`: 计算给定长度的字节数组进行 Base32 编码后的长度。

6. **实现了解码功能：**
   - `decode(dst, src []byte) (n int, end bool, err error)`:  核心的解码函数，将 `src` 中的 Base32 编码数据解码到 `dst` 中。它还会返回是否遇到了填充字符以及任何错误。
   - `Decode(dst, src []byte) (n int, err error)`: 将 `src` 中的 Base32 编码数据解码到 `dst` 中。会忽略输入中的换行符。
   - `AppendDecode(dst, src []byte) ([]byte, error)`: 将 `src` 中的 Base32 编码数据解码后追加到 `dst` 中，并返回新的 `dst` 切片以及可能发生的错误。
   - `DecodeString(s string) ([]byte, error)`: 将 Base32 编码的字符串 `s` 解码成字节数组。
   - `NewDecoder(enc *Encoding, r io.Reader) io.Reader`: 返回一个实现了 `io.Reader` 接口的解码器，可以从 `r` 中流式地读取 Base32 编码的数据并进行解码。
   - `DecodedLen(n int) int`: 计算给定长度的 Base32 编码数据解码后的最大长度。

7. **定义了错误类型 `CorruptInputError`:**  用于表示解码过程中遇到非法 Base32 数据的情况。

8. **处理换行符:** 在解码过程中，会忽略输入数据中的换行符 (`\r` 和 `\n`)。

**Go 语言功能实现：**

这个包主要实现了 **数据编码与解码** 的功能，特别是 Base32 编码。它利用了 Go 语言的以下特性：

- **结构体 (Struct):**  `Encoding` 结构体用于组织 Base32 编码所需的数据。
- **方法 (Methods):**  与 `Encoding` 结构体关联的方法实现了编码和解码的具体逻辑。
- **接口 (Interfaces):**  `io.Writer` 和 `io.Reader` 接口用于实现流式编码和解码，使得可以处理大量数据而无需一次性加载到内存。`io.WriteCloser` 接口用于确保编码器在完成时可以被关闭以刷新任何未写入的数据。
- **切片 (Slices):**  用于存储和操作字节数据。
- **常量 (Constants):**  定义了标准的填充字符和预定义的编码器。
- **错误处理 (Error Handling):** 使用 `error` 接口和自定义的 `CorruptInputError` 来处理编码和解码过程中可能出现的错误。

**代码举例说明：**

假设我们要使用标准的 Base32 编码对字符串 "Hello, World!" 进行编码和解码。

```go
package main

import (
	"encoding/base32"
	"fmt"
)

func main() {
	data := []byte("Hello, World!")

	// 编码
	encodedString := base32.StdEncoding.EncodeToString(data)
	fmt.Println("编码后的字符串:", encodedString) // 输出: JBSWY3DPFQQHO33SNRSCC===

	// 解码
	decodedData, err := base32.StdEncoding.DecodeString(encodedString)
	if err != nil {
		fmt.Println("解码错误:", err)
		return
	}
	fmt.Println("解码后的字符串:", string(decodedData)) // 输出: Hello, World!
}
```

**假设的输入与输出：**

* **编码：**
    * 输入 ( `data` ): `[]byte("Hello, World!")`
    * 输出 ( `encodedString` ): `"JBSWY3DPFQQHO33SNRSCC==="`

* **解码：**
    * 输入 ( `encodedString` ): `"JBSWY3DPFQQHO33SNRSCC==="`
    * 输出 ( `decodedData` ): `[]byte("Hello, World!")`, `err`: `nil`

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。它是一个库，供其他 Go 程序调用。如果需要在命令行中使用 Base32 编码或解码，你需要编写一个使用了 `encoding/base32` 包的 Go 程序，并在该程序中处理命令行参数。例如，你可以使用 `flag` 包来解析命令行参数，并根据参数选择进行编码或解码操作。

**使用者易犯错的点：**

1. **使用了错误的编码器进行解码：**  如果使用 `StdEncoding` 编码的数据尝试用 `HexEncoding` 解码，或者反之，会导致解码失败并返回 `CorruptInputError`。

   ```go
   package main

   import (
   	"encoding/base32"
   	"fmt"
   )

   func main() {
   	data := []byte("example")
   	encoded := base32.StdEncoding.EncodeToString(data)
   	fmt.Println("使用 StdEncoding 编码:", encoded) // 输出: MZXW6YTBOI======

   	decoded, err := base32.HexEncoding.DecodeString(encoded)
   	if err != nil {
   		fmt.Println("使用 HexEncoding 解码错误:", err) // 输出: 使用 HexEncoding 解码错误: illegal base32 data at input byte 0
   	} else {
   		fmt.Println("使用 HexEncoding 解码:", string(decoded))
   	}
   }
   ```

2. **没有正确处理填充字符：**  虽然标准 Base32 使用 `=` 作为填充字符，但有些变体可能没有填充，或者使用不同的填充字符。在使用 `WithPadding` 自定义编码器时，需要确保编码和解码使用相同的设置。如果解码时期望有填充但实际没有，或者填充不正确，也会导致解码错误。

3. **在使用流式编码器后忘记调用 `Close()`：**  `NewEncoder` 返回的编码器需要调用 `Close()` 方法来刷新任何缓冲区中的数据。如果不调用 `Close()`，可能会导致部分数据丢失。

   ```go
   package main

   import (
   	"bytes"
   	"encoding/base32"
   	"fmt"
   	"io"
   	"os"
   )

   func main() {
   	data := []byte("This is a long string to demonstrate streaming.")
   	var buf bytes.Buffer
   	encoder := base32.NewEncoder(base32.StdEncoding, &buf)

   	_, err := encoder.Write(data)
   	if err != nil {
   		fmt.Println("写入编码器错误:", err)
   		return
   	}
   	// 注意：这里没有调用 encoder.Close()

   	fmt.Println("未关闭编码器，部分数据可能未刷新:", buf.String())

   	// 正确的做法是调用 Close()
   	var buf2 bytes.Buffer
   	encoder2 := base32.NewEncoder(base32.StdEncoding, &buf2)
   	_, err = encoder2.Write(data)
   	if err != nil {
   		fmt.Println("写入编码器2错误:", err)
   		return
   	}
   	err = encoder2.Close()
   	if err != nil {
   		fmt.Println("关闭编码器2错误:", err)
   		return
   	}
   	fmt.Println("正确关闭编码器后:", buf2.String())
   }
   ```

总而言之，`encoding/base32` 包提供了强大且灵活的 Base32 编码和解码功能，开发者可以根据需要选择标准的编码器或自定义编码器，并支持流式处理，使其适用于各种场景。 理解不同 Base32 变体的差异以及正确使用填充字符是避免错误的关键。

Prompt: 
```
这是路径为go/src/encoding/base32/base32.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package base32 implements base32 encoding as specified by RFC 4648.
package base32

import (
	"io"
	"slices"
	"strconv"
)

/*
 * Encodings
 */

// An Encoding is a radix 32 encoding/decoding scheme, defined by a
// 32-character alphabet. The most common is the "base32" encoding
// introduced for SASL GSSAPI and standardized in RFC 4648.
// The alternate "base32hex" encoding is used in DNSSEC.
type Encoding struct {
	encode    [32]byte   // mapping of symbol index to symbol byte value
	decodeMap [256]uint8 // mapping of symbol byte value to symbol index
	padChar   rune
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
// which must be a 32-byte string that contains unique byte values and
// does not contain the padding character or CR / LF ('\r', '\n').
// The alphabet is treated as a sequence of byte values
// without any special treatment for multi-byte UTF-8.
// The resulting Encoding uses the default padding character ('='),
// which may be changed or disabled via [Encoding.WithPadding].
func NewEncoding(encoder string) *Encoding {
	if len(encoder) != 32 {
		panic("encoding alphabet is not 32-bytes long")
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

// StdEncoding is the standard base32 encoding, as defined in RFC 4648.
var StdEncoding = NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

// HexEncoding is the “Extended Hex Alphabet” defined in RFC 4648.
// It is typically used in DNS.
var HexEncoding = NewEncoding("0123456789ABCDEFGHIJKLMNOPQRSTUV")

// WithPadding creates a new encoding identical to enc except
// with a specified padding character, or NoPadding to disable padding.
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

/*
 * Encoder
 */

// Encode encodes src using the encoding enc,
// writing [Encoding.EncodedLen](len(src)) bytes to dst.
//
// The encoding pads the output to a multiple of 8 bytes,
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
	n := (len(src) / 5) * 5
	for si < n {
		// Combining two 32 bit loads allows the same code to be used
		// for 32 and 64 bit platforms.
		hi := uint32(src[si+0])<<24 | uint32(src[si+1])<<16 | uint32(src[si+2])<<8 | uint32(src[si+3])
		lo := hi<<8 | uint32(src[si+4])

		dst[di+0] = enc.encode[(hi>>27)&0x1F]
		dst[di+1] = enc.encode[(hi>>22)&0x1F]
		dst[di+2] = enc.encode[(hi>>17)&0x1F]
		dst[di+3] = enc.encode[(hi>>12)&0x1F]
		dst[di+4] = enc.encode[(hi>>7)&0x1F]
		dst[di+5] = enc.encode[(hi>>2)&0x1F]
		dst[di+6] = enc.encode[(lo>>5)&0x1F]
		dst[di+7] = enc.encode[(lo)&0x1F]

		si += 5
		di += 8
	}

	// Add the remaining small block
	remain := len(src) - si
	if remain == 0 {
		return
	}

	// Encode the remaining bytes in reverse order.
	val := uint32(0)
	switch remain {
	case 4:
		val |= uint32(src[si+3])
		dst[di+6] = enc.encode[val<<3&0x1F]
		dst[di+5] = enc.encode[val>>2&0x1F]
		fallthrough
	case 3:
		val |= uint32(src[si+2]) << 8
		dst[di+4] = enc.encode[val>>7&0x1F]
		fallthrough
	case 2:
		val |= uint32(src[si+1]) << 16
		dst[di+3] = enc.encode[val>>12&0x1F]
		dst[di+2] = enc.encode[val>>17&0x1F]
		fallthrough
	case 1:
		val |= uint32(src[si+0]) << 24
		dst[di+1] = enc.encode[val>>22&0x1F]
		dst[di+0] = enc.encode[val>>27&0x1F]
	}

	// Pad the final quantum
	if enc.padChar != NoPadding {
		nPad := (remain * 8 / 5) + 1
		for i := nPad; i < 8; i++ {
			dst[di+i] = byte(enc.padChar)
		}
	}
}

// AppendEncode appends the base32 encoded src to dst
// and returns the extended buffer.
func (enc *Encoding) AppendEncode(dst, src []byte) []byte {
	n := enc.EncodedLen(len(src))
	dst = slices.Grow(dst, n)
	enc.Encode(dst[len(dst):][:n], src)
	return dst[:len(dst)+n]
}

// EncodeToString returns the base32 encoding of src.
func (enc *Encoding) EncodeToString(src []byte) string {
	buf := make([]byte, enc.EncodedLen(len(src)))
	enc.Encode(buf, src)
	return string(buf)
}

type encoder struct {
	err  error
	enc  *Encoding
	w    io.Writer
	buf  [5]byte    // buffered data waiting to be encoded
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
		for i = 0; i < len(p) && e.nbuf < 5; i++ {
			e.buf[e.nbuf] = p[i]
			e.nbuf++
		}
		n += i
		p = p[i:]
		if e.nbuf < 5 {
			return
		}
		e.enc.Encode(e.out[0:], e.buf[0:])
		if _, e.err = e.w.Write(e.out[0:8]); e.err != nil {
			return n, e.err
		}
		e.nbuf = 0
	}

	// Large interior chunks.
	for len(p) >= 5 {
		nn := len(e.out) / 8 * 5
		if nn > len(p) {
			nn = len(p)
			nn -= nn % 5
		}
		e.enc.Encode(e.out[0:], p[0:nn])
		if _, e.err = e.w.Write(e.out[0 : nn/5*8]); e.err != nil {
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
		e.enc.Encode(e.out[0:], e.buf[0:e.nbuf])
		encodedLen := e.enc.EncodedLen(e.nbuf)
		e.nbuf = 0
		_, e.err = e.w.Write(e.out[0:encodedLen])
	}
	return e.err
}

// NewEncoder returns a new base32 stream encoder. Data written to
// the returned writer will be encoded using enc and then written to w.
// Base32 encodings operate in 5-byte blocks; when finished
// writing, the caller must Close the returned encoder to flush any
// partially written blocks.
func NewEncoder(enc *Encoding, w io.Writer) io.WriteCloser {
	return &encoder{enc: enc, w: w}
}

// EncodedLen returns the length in bytes of the base32 encoding
// of an input buffer of length n.
func (enc *Encoding) EncodedLen(n int) int {
	if enc.padChar == NoPadding {
		return n/5*8 + (n%5*8+4)/5
	}
	return (n + 4) / 5 * 8
}

/*
 * Decoder
 */

type CorruptInputError int64

func (e CorruptInputError) Error() string {
	return "illegal base32 data at input byte " + strconv.FormatInt(int64(e), 10)
}

// decode is like Decode but returns an additional 'end' value, which
// indicates if end-of-message padding was encountered and thus any
// additional data is an error. This method assumes that src has been
// stripped of all supported whitespace ('\r' and '\n').
func (enc *Encoding) decode(dst, src []byte) (n int, end bool, err error) {
	// Lift the nil check outside of the loop.
	_ = enc.decodeMap

	dsti := 0
	olen := len(src)

	for len(src) > 0 && !end {
		// Decode quantum using the base32 alphabet
		var dbuf [8]byte
		dlen := 8

		for j := 0; j < 8; {

			if len(src) == 0 {
				if enc.padChar != NoPadding {
					// We have reached the end and are missing padding
					return n, false, CorruptInputError(olen - len(src) - j)
				}
				// We have reached the end and are not expecting any padding
				dlen, end = j, true
				break
			}
			in := src[0]
			src = src[1:]
			if in == byte(enc.padChar) && j >= 2 && len(src) < 8 {
				// We've reached the end and there's padding
				if len(src)+j < 8-1 {
					// not enough padding
					return n, false, CorruptInputError(olen)
				}
				for k := 0; k < 8-1-j; k++ {
					if len(src) > k && src[k] != byte(enc.padChar) {
						// incorrect padding
						return n, false, CorruptInputError(olen - len(src) + k - 1)
					}
				}
				dlen, end = j, true
				// 7, 5 and 2 are not valid padding lengths, and so 1, 3 and 6 are not
				// valid dlen values. See RFC 4648 Section 6 "Base 32 Encoding" listing
				// the five valid padding lengths, and Section 9 "Illustrations and
				// Examples" for an illustration for how the 1st, 3rd and 6th base32
				// src bytes do not yield enough information to decode a dst byte.
				if dlen == 1 || dlen == 3 || dlen == 6 {
					return n, false, CorruptInputError(olen - len(src) - 1)
				}
				break
			}
			dbuf[j] = enc.decodeMap[in]
			if dbuf[j] == 0xFF {
				return n, false, CorruptInputError(olen - len(src) - 1)
			}
			j++
		}

		// Pack 8x 5-bit source blocks into 5 byte destination
		// quantum
		switch dlen {
		case 8:
			dst[dsti+4] = dbuf[6]<<5 | dbuf[7]
			n++
			fallthrough
		case 7:
			dst[dsti+3] = dbuf[4]<<7 | dbuf[5]<<2 | dbuf[6]>>3
			n++
			fallthrough
		case 5:
			dst[dsti+2] = dbuf[3]<<4 | dbuf[4]>>1
			n++
			fallthrough
		case 4:
			dst[dsti+1] = dbuf[1]<<6 | dbuf[2]<<1 | dbuf[3]>>4
			n++
			fallthrough
		case 2:
			dst[dsti+0] = dbuf[0]<<3 | dbuf[1]>>2
			n++
		}
		dsti += 5
	}
	return n, end, nil
}

// Decode decodes src using the encoding enc. It writes at most
// [Encoding.DecodedLen](len(src)) bytes to dst and returns the number of bytes
// written. The caller must ensure that dst is large enough to hold all
// the decoded data. If src contains invalid base32 data, it will return the
// number of bytes successfully written and [CorruptInputError].
// Newline characters (\r and \n) are ignored.
func (enc *Encoding) Decode(dst, src []byte) (n int, err error) {
	buf := make([]byte, len(src))
	l := stripNewlines(buf, src)
	n, _, err = enc.decode(dst, buf[:l])
	return
}

// AppendDecode appends the base32 decoded src to dst
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

// DecodeString returns the bytes represented by the base32 string s.
// If the input is malformed, it returns the partially decoded data and
// [CorruptInputError]. New line characters (\r and \n) are ignored.
func (enc *Encoding) DecodeString(s string) ([]byte, error) {
	buf := []byte(s)
	l := stripNewlines(buf, buf)
	n, _, err := enc.decode(buf, buf[:l])
	return buf[:n], err
}

type decoder struct {
	err    error
	enc    *Encoding
	r      io.Reader
	end    bool       // saw end of message
	buf    [1024]byte // leftover input
	nbuf   int
	out    []byte // leftover decoded output
	outbuf [1024 / 8 * 5]byte
}

func readEncodedData(r io.Reader, buf []byte, min int, expectsPadding bool) (n int, err error) {
	for n < min && err == nil {
		var nn int
		nn, err = r.Read(buf[n:])
		n += nn
	}
	// data was read, less than min bytes could be read
	if n < min && n > 0 && err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	// no data was read, the buffer already contains some data
	// when padding is disabled this is not an error, as the message can be of
	// any length
	if expectsPadding && min < 8 && n == 0 && err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return
}

func (d *decoder) Read(p []byte) (n int, err error) {
	// Use leftover decoded output from last read.
	if len(d.out) > 0 {
		n = copy(p, d.out)
		d.out = d.out[n:]
		if len(d.out) == 0 {
			return n, d.err
		}
		return n, nil
	}

	if d.err != nil {
		return 0, d.err
	}

	// Read a chunk.
	nn := (len(p) + 4) / 5 * 8
	if nn < 8 {
		nn = 8
	}
	if nn > len(d.buf) {
		nn = len(d.buf)
	}

	// Minimum amount of bytes that needs to be read each cycle
	var min int
	var expectsPadding bool
	if d.enc.padChar == NoPadding {
		min = 1
		expectsPadding = false
	} else {
		min = 8 - d.nbuf
		expectsPadding = true
	}

	nn, d.err = readEncodedData(d.r, d.buf[d.nbuf:nn], min, expectsPadding)
	d.nbuf += nn
	if d.nbuf < min {
		return 0, d.err
	}
	if nn > 0 && d.end {
		return 0, CorruptInputError(0)
	}

	// Decode chunk into p, or d.out and then p if p is too small.
	var nr int
	if d.enc.padChar == NoPadding {
		nr = d.nbuf
	} else {
		nr = d.nbuf / 8 * 8
	}
	nw := d.enc.DecodedLen(d.nbuf)

	if nw > len(p) {
		nw, d.end, err = d.enc.decode(d.outbuf[0:], d.buf[0:nr])
		d.out = d.outbuf[0:nw]
		n = copy(p, d.out)
		d.out = d.out[n:]
	} else {
		n, d.end, err = d.enc.decode(p, d.buf[0:nr])
	}
	d.nbuf -= nr
	for i := 0; i < d.nbuf; i++ {
		d.buf[i] = d.buf[i+nr]
	}

	if err != nil && (d.err == nil || d.err == io.EOF) {
		d.err = err
	}

	if len(d.out) > 0 {
		// We cannot return all the decoded bytes to the caller in this
		// invocation of Read, so we return a nil error to ensure that Read
		// will be called again.  The error stored in d.err, if any, will be
		// returned with the last set of decoded bytes.
		return n, nil
	}

	return n, d.err
}

type newlineFilteringReader struct {
	wrapped io.Reader
}

// stripNewlines removes newline characters and returns the number
// of non-newline characters copied to dst.
func stripNewlines(dst, src []byte) int {
	offset := 0
	for _, b := range src {
		if b == '\r' || b == '\n' {
			continue
		}
		dst[offset] = b
		offset++
	}
	return offset
}

func (r *newlineFilteringReader) Read(p []byte) (int, error) {
	n, err := r.wrapped.Read(p)
	for n > 0 {
		s := p[0:n]
		offset := stripNewlines(s, s)
		if err != nil || offset > 0 {
			return offset, err
		}
		// Previous buffer entirely whitespace, read again
		n, err = r.wrapped.Read(p)
	}
	return n, err
}

// NewDecoder constructs a new base32 stream decoder.
func NewDecoder(enc *Encoding, r io.Reader) io.Reader {
	return &decoder{enc: enc, r: &newlineFilteringReader{r}}
}

// DecodedLen returns the maximum length in bytes of the decoded data
// corresponding to n bytes of base32-encoded data.
func (enc *Encoding) DecodedLen(n int) int {
	return decodedLen(n, enc.padChar)
}

func decodedLen(n int, padChar rune) int {
	if padChar == NoPadding {
		return n/8*5 + n%8*5/8
	}
	return n / 8 * 5
}

"""



```