Response:
Let's break down the thought process for analyzing the given Go code snippet.

**1. Understanding the Request:**

The core request is to understand the functionality of the provided Go code, specifically the `encoding/json/stream.go` part related to `Decoder` and `Encoder`. The prompt asks for:

* **Listing functionalities:** What can this code do?
* **Inferring the Go feature:** What broader Go capability is this part of?
* **Code examples:** Demonstrate the usage with input and output.
* **Command-line arguments:** Are there any command-line interactions?
* **Common mistakes:** What errors might users make?
* **Language:**  Answer in Chinese.

**2. Initial Code Scan and Identifying Key Structures:**

The first step is to quickly read through the code, looking for prominent types, methods, and comments. I immediately see `Decoder` and `Encoder` structs, along with `NewDecoder` and `NewEncoder` functions. This strongly suggests the code deals with reading and writing JSON streams.

**3. Analyzing the `Decoder`:**

* **`NewDecoder(r io.Reader)`:** This clearly creates a new decoder that reads from an `io.Reader`. This implies the decoder handles streaming input.
* **`Decode(v any)`:**  The name and the `any` type parameter strongly suggest this method decodes JSON from the input stream and populates the value pointed to by `v`. The comment refers to `Unmarshal`, reinforcing this.
* **`UseNumber()`:**  This method hints at different ways to handle JSON numbers (as `Number` or `float64`).
* **`DisallowUnknownFields()`:** This suggests a strict mode for decoding into structs, rejecting extra fields.
* **`Buffered() io.Reader`:**  This is interesting. It provides access to the remaining unread data in the decoder's internal buffer. This is useful for inspecting what hasn't been processed yet.
* **`Token()`:** This method stands out. The comments and the return type `Token` (which can be `Delim`, `bool`, `float64`, `Number`, `string`, `nil`) indicate a lower-level interface for processing JSON as a stream of tokens.
* **`More()`:**  This function, in conjunction with `Token()`, is a classic indicator of iterating through arrays or objects.
* **Internal methods like `readValue()`, `refill()`, `peek()`:** These are implementation details related to how the decoder manages its input buffer and scans for JSON values. They are important for understanding the inner workings but not directly exposed to the user.

**4. Analyzing the `Encoder`:**

* **`NewEncoder(w io.Writer)`:** Similar to the decoder, this creates an encoder that writes to an `io.Writer`, implying streaming output.
* **`Encode(v any)`:** This method takes a Go value and writes its JSON encoding to the output stream. The comment references `Marshal`.
* **`SetIndent(prefix, indent string)`:** This clearly controls the formatting of the JSON output with indentation.
* **`SetEscapeHTML(on bool)`:** This deals with escaping HTML characters in the output, a common security consideration when embedding JSON in HTML.

**5. Identifying the Core Go Feature:**

Based on the `Decoder` and `Encoder` interaction with `io.Reader` and `io.Writer`, and the methods for encoding and decoding, the core Go feature is clearly **JSON streaming**. This allows processing large JSON documents without loading the entire thing into memory at once.

**6. Crafting Code Examples:**

* **Decoding:**  I need a simple JSON input (string) and a Go data structure (struct and map) to demonstrate decoding. I'll show basic decoding and also demonstrate `UseNumber` and `DisallowUnknownFields`.
* **Encoding:**  Similarly, create a Go data structure and show how to encode it to JSON. Include an example of using `SetIndent`.
* **Token API:**  This requires a more manual approach. I'll demonstrate how to use `Token()` and `More()` to iterate through a JSON array.

**7. Command-Line Arguments:**

Scanning the code, there's no direct handling of command-line arguments. The code operates on `io.Reader` and `io.Writer` interfaces, which can be connected to files, network connections, or standard input/output, but the `stream.go` code itself doesn't parse command-line flags.

**8. Common Mistakes:**

Think about how users might misuse the `Decoder` and `Encoder`.

* **Forgetting to check errors after `Decode` or `Encode`.**
* **Mismatching the JSON structure with the Go data structure.** This is particularly relevant for `DisallowUnknownFields`.
* **Incorrectly using the `Token` API, especially with nesting.**  Forgetting to handle different token types or manage the stack can lead to errors.

**9. Structuring the Answer in Chinese:**

Translate the identified functionalities, explanations, and code examples into clear and understandable Chinese. Use appropriate technical terms and provide sufficient detail.

**Self-Correction/Refinement during the Process:**

* **Initial Thought:**  Perhaps this code handles more complex JSON transformations. **Correction:**  The focus is clearly on reading and writing streams, not in-place modification.
* **Initial Thought:** Maybe command-line arguments are implicitly handled through the `io.Reader` and `io.Writer`. **Correction:** While the input/output can *come from* command-line interactions, the code itself doesn't parse arguments. It's important to distinguish between the source of the stream and the code's function.
* **Example Clarity:** Ensure the code examples are concise and directly illustrate the feature being discussed. Add comments to explain the purpose of each part.

By following this structured approach, breaking down the problem into smaller parts, and iterating through the code's features, I can arrive at a comprehensive and accurate answer to the prompt.
这段代码是 Go 语言 `encoding/json` 标准库中处理 JSON 数据流的一部分，主要实现了 `Decoder` 和 `Encoder` 类型，用于从输入流中解码 JSON 数据以及将 Go 数据编码成 JSON 数据写入输出流。

**功能列举:**

1. **JSON 解码 (`Decoder`)**:
    *   **从 `io.Reader` 读取 JSON 数据流**: `NewDecoder(r io.Reader)` 函数创建一个新的解码器，它可以从任何实现了 `io.Reader` 接口的对象（例如文件、网络连接、字节缓冲区等）读取 JSON 数据。
    *   **将 JSON 解码到 Go 值**: `Decode(v any)` 方法从输入流中读取下一个 JSON 编码的值，并将其存储到 `v` 指向的 Go 变量中。`v` 可以是结构体、切片、映射或其他 Go 类型。
    *   **控制数字的解码方式**: `UseNumber()` 方法使解码器将 JSON 数字解码为 `json.Number` 类型而不是默认的 `float64` 类型。这在需要精确处理大整数或避免浮点数精度问题时很有用。
    *   **禁止未知的字段**: `DisallowUnknownFields()` 方法使解码器在目标是结构体时，如果输入的 JSON 对象包含目标结构体中不存在的、未被忽略的导出字段的键，则返回错误。这有助于提高数据校验的严格性。
    *   **访问剩余的缓冲数据**: `Buffered() io.Reader` 方法返回一个 `io.Reader`，可以读取解码器内部缓冲区中尚未被 `Decode` 处理的剩余数据。
    *   **Token 级别的解析**: `Token()` 方法允许逐个读取 JSON 数据流中的 Token（例如：`{`, `}`, `[`, `]`, 字符串, 数字, 布尔值, `null`）。这提供了更底层的 JSON 解析能力。
    *   **检查是否还有更多元素**: `More()` 方法用于在使用 `Token()` 方法解析数组或对象时，判断是否还有更多的元素需要读取。
    *   **获取当前输入偏移量**: `InputOffset()` 方法返回当前解码器在输入流中的字节偏移量。

2. **JSON 编码 (`Encoder`)**:
    *   **写入 JSON 数据流到 `io.Writer`**: `NewEncoder(w io.Writer)` 函数创建一个新的编码器，它可以将 JSON 数据写入任何实现了 `io.Writer` 接口的对象。
    *   **将 Go 值编码为 JSON**: `Encode(v any)` 方法将 Go 变量 `v` 编码为 JSON 格式，并写入到输出流。
    *   **设置缩进**: `SetIndent(prefix, indent string)` 方法允许设置 JSON 输出的缩进格式，使其更易于阅读。
    *   **控制 HTML 转义**: `SetEscapeHTML(on bool)` 方法允许控制是否对 JSON 字符串中的 HTML 特殊字符（如 `<`, `>`, `&`）进行转义。默认情况下会进行转义，以避免在 HTML 中嵌入 JSON 时出现安全问题。

3. **原始 JSON 消息 (`RawMessage`)**:
    *   `RawMessage` 类型表示一段原始的 JSON 编码值。
    *   它实现了 `Marshaler` 和 `Unmarshaler` 接口，可以用于延迟 JSON 解码或预先计算 JSON 编码。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言中 **JSON 数据流处理** 的核心实现。Go 的 `encoding/json` 包提供了将 Go 数据结构序列化为 JSON 格式以及将 JSON 数据反序列化为 Go 数据结构的功能。`stream.go` 文件中的 `Decoder` 和 `Encoder` 类型专注于处理可能非常大的 JSON 数据，避免一次性加载到内存中，从而提高效率和降低内存消耗。这对于处理网络请求、读取大型 JSON 文件等场景非常重要。

**Go 代码示例：**

**解码 (Decoder):**

```go
package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

func main() {
	jsonStream := `{"name": "Alice", "age": 30}
{"name": "Bob", "age": 25}`

	decoder := json.NewDecoder(strings.NewReader(jsonStream))

	for {
		var person map[string]interface{}
		err := decoder.Decode(&person)
		if err != nil {
			if err.Error() == "EOF" {
				break // 读取完毕
			}
			fmt.Println("解码错误:", err)
			return
		}
		fmt.Printf("解码结果: %+v\n", person)
	}
}

// 假设输入 jsonStream 为: `{"name": "Alice", "age": 30}\n{"name": "Bob", "age": 25}`
// 输出将会是:
// 解码结果: map[age:30 name:Alice]
// 解码结果: map[age:25 name:Bob]
```

**编码 (Encoder):**

```go
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type Person struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
}

func main() {
	people := []Person{
		{Name: "Alice", Age: 30},
		{Name: "Bob", Age: 25},
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ") // 设置缩进

	for _, p := range people {
		err := encoder.Encode(p)
		if err != nil {
			fmt.Println("编码错误:", err)
			return
		}
	}
}

// 假设运行上述代码，输出到标准输出将会是:
// {
//   "name": "Alice",
//   "age": 30
// }
// {
//   "name": "Bob",
//   "age": 25
// }
```

**Token 级别解析 (Decoder.Token()):**

```go
package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

func main() {
	jsonStream := `[true, "hello", 123, null, {"key": "value"}]`
	decoder := json.NewDecoder(strings.NewReader(jsonStream))

	for {
		token, err := decoder.Token()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			fmt.Println("Token 错误:", err)
			return
		}
		fmt.Printf("Token: %T - %+v\n", token, token)
	}
}

// 假设输入 jsonStream 为: `[true, "hello", 123, null, {"key": "value"}]`
// 输出将会是:
// Token: json.Delim - [
// Token: bool - true
// Token: string - hello
// Token: float64 - 123
// Token: <nil> - <nil>
// Token: json.Delim - {
// Token: string - key
// Token: json.Delim - :
// Token: string - value
// Token: json.Delim - }
// Token: json.Delim - ]
```

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。`Decoder` 和 `Encoder` 依赖于 `io.Reader` 和 `io.Writer` 接口，这意味着你可以将它们与处理命令行参数的逻辑结合使用。例如，你可以使用 `os.Open` 打开由命令行参数指定的文件，然后将返回的 `*os.File` 作为 `NewDecoder` 的参数。或者，你可以从 `os.Stdin` 创建一个 `Decoder` 来处理通过管道或重定向传入的 JSON 数据。

**使用者易犯错的点：**

1. **`Decoder.Decode` 的多次调用**:  `Decode` 方法每次调用都会尝试从输入流中读取并解码 *下一个* JSON 值。初学者可能会误以为一次 `Decode` 调用可以处理整个 JSON 文件，但实际上对于包含多个顶级 JSON 值的流，需要循环调用 `Decode`。

    ```go
    // 错误示例：只调用一次 Decode
    decoder := json.NewDecoder(reader)
    var data map[string]interface{}
    err := decoder.Decode(&data) // 可能只能读取到第一个 JSON 对象
    ```

    ```go
    // 正确示例：循环调用 Decode
    decoder := json.NewDecoder(reader)
    for {
        var data map[string]interface{}
        err := decoder.Decode(&data)
        if err != nil {
            if err == io.EOF {
                break // 读取完毕
            }
            // 处理错误
        }
        // 处理 data
    }
    ```

2. **结构体字段的导出**: `encoding/json` 包只能访问结构体中导出的字段（首字母大写）。如果结构体字段没有导出，`Decode` 和 `Encode` 将会忽略这些字段。

    ```go
    type Person struct {
        name string // 未导出
        Age  int    `json:"age"`
    }

    // 编码或解码时，name 字段会被忽略
    ```

3. **`DisallowUnknownFields` 的使用场景**: 只有当解码目标是结构体时，`DisallowUnknownFields` 才会生效。如果解码到 `map[string]interface{}`，即使 JSON 中包含未知的键，也不会报错。

4. **`Token` API 的复杂性**: `Token()` 方法提供了更底层的控制，但也更复杂。使用者需要理解 JSON 的结构和 Token 的顺序，并正确处理各种类型的 Token（`Delim`, `string`, `float64`, `bool`, `nil`）。错误地使用 `Token` API 容易导致解析错误或程序崩溃。

5. **忘记处理错误**: `Decode` 和 `Encode` 方法都可能返回错误，例如输入流格式不正确、写入失败等。使用者必须检查并妥善处理这些错误，以保证程序的健壮性。

这段代码是 `encoding/json` 包中非常重要的组成部分，为 Go 语言提供了高效且灵活的 JSON 数据流处理能力。理解其工作原理和使用方式对于编写处理 JSON 数据的 Go 程序至关重要。

### 提示词
```
这是路径为go/src/encoding/json/stream.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package json

import (
	"bytes"
	"errors"
	"io"
)

// A Decoder reads and decodes JSON values from an input stream.
type Decoder struct {
	r       io.Reader
	buf     []byte
	d       decodeState
	scanp   int   // start of unread data in buf
	scanned int64 // amount of data already scanned
	scan    scanner
	err     error

	tokenState int
	tokenStack []int
}

// NewDecoder returns a new decoder that reads from r.
//
// The decoder introduces its own buffering and may
// read data from r beyond the JSON values requested.
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{r: r}
}

// UseNumber causes the Decoder to unmarshal a number into an
// interface value as a [Number] instead of as a float64.
func (dec *Decoder) UseNumber() { dec.d.useNumber = true }

// DisallowUnknownFields causes the Decoder to return an error when the destination
// is a struct and the input contains object keys which do not match any
// non-ignored, exported fields in the destination.
func (dec *Decoder) DisallowUnknownFields() { dec.d.disallowUnknownFields = true }

// Decode reads the next JSON-encoded value from its
// input and stores it in the value pointed to by v.
//
// See the documentation for [Unmarshal] for details about
// the conversion of JSON into a Go value.
func (dec *Decoder) Decode(v any) error {
	if dec.err != nil {
		return dec.err
	}

	if err := dec.tokenPrepareForDecode(); err != nil {
		return err
	}

	if !dec.tokenValueAllowed() {
		return &SyntaxError{msg: "not at beginning of value", Offset: dec.InputOffset()}
	}

	// Read whole value into buffer.
	n, err := dec.readValue()
	if err != nil {
		return err
	}
	dec.d.init(dec.buf[dec.scanp : dec.scanp+n])
	dec.scanp += n

	// Don't save err from unmarshal into dec.err:
	// the connection is still usable since we read a complete JSON
	// object from it before the error happened.
	err = dec.d.unmarshal(v)

	// fixup token streaming state
	dec.tokenValueEnd()

	return err
}

// Buffered returns a reader of the data remaining in the Decoder's
// buffer. The reader is valid until the next call to [Decoder.Decode].
func (dec *Decoder) Buffered() io.Reader {
	return bytes.NewReader(dec.buf[dec.scanp:])
}

// readValue reads a JSON value into dec.buf.
// It returns the length of the encoding.
func (dec *Decoder) readValue() (int, error) {
	dec.scan.reset()

	scanp := dec.scanp
	var err error
Input:
	// help the compiler see that scanp is never negative, so it can remove
	// some bounds checks below.
	for scanp >= 0 {

		// Look in the buffer for a new value.
		for ; scanp < len(dec.buf); scanp++ {
			c := dec.buf[scanp]
			dec.scan.bytes++
			switch dec.scan.step(&dec.scan, c) {
			case scanEnd:
				// scanEnd is delayed one byte so we decrement
				// the scanner bytes count by 1 to ensure that
				// this value is correct in the next call of Decode.
				dec.scan.bytes--
				break Input
			case scanEndObject, scanEndArray:
				// scanEnd is delayed one byte.
				// We might block trying to get that byte from src,
				// so instead invent a space byte.
				if stateEndValue(&dec.scan, ' ') == scanEnd {
					scanp++
					break Input
				}
			case scanError:
				dec.err = dec.scan.err
				return 0, dec.scan.err
			}
		}

		// Did the last read have an error?
		// Delayed until now to allow buffer scan.
		if err != nil {
			if err == io.EOF {
				if dec.scan.step(&dec.scan, ' ') == scanEnd {
					break Input
				}
				if nonSpace(dec.buf) {
					err = io.ErrUnexpectedEOF
				}
			}
			dec.err = err
			return 0, err
		}

		n := scanp - dec.scanp
		err = dec.refill()
		scanp = dec.scanp + n
	}
	return scanp - dec.scanp, nil
}

func (dec *Decoder) refill() error {
	// Make room to read more into the buffer.
	// First slide down data already consumed.
	if dec.scanp > 0 {
		dec.scanned += int64(dec.scanp)
		n := copy(dec.buf, dec.buf[dec.scanp:])
		dec.buf = dec.buf[:n]
		dec.scanp = 0
	}

	// Grow buffer if not large enough.
	const minRead = 512
	if cap(dec.buf)-len(dec.buf) < minRead {
		newBuf := make([]byte, len(dec.buf), 2*cap(dec.buf)+minRead)
		copy(newBuf, dec.buf)
		dec.buf = newBuf
	}

	// Read. Delay error for next iteration (after scan).
	n, err := dec.r.Read(dec.buf[len(dec.buf):cap(dec.buf)])
	dec.buf = dec.buf[0 : len(dec.buf)+n]

	return err
}

func nonSpace(b []byte) bool {
	for _, c := range b {
		if !isSpace(c) {
			return true
		}
	}
	return false
}

// An Encoder writes JSON values to an output stream.
type Encoder struct {
	w          io.Writer
	err        error
	escapeHTML bool

	indentBuf    []byte
	indentPrefix string
	indentValue  string
}

// NewEncoder returns a new encoder that writes to w.
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w: w, escapeHTML: true}
}

// Encode writes the JSON encoding of v to the stream,
// with insignificant space characters elided,
// followed by a newline character.
//
// See the documentation for [Marshal] for details about the
// conversion of Go values to JSON.
func (enc *Encoder) Encode(v any) error {
	if enc.err != nil {
		return enc.err
	}

	e := newEncodeState()
	defer encodeStatePool.Put(e)

	err := e.marshal(v, encOpts{escapeHTML: enc.escapeHTML})
	if err != nil {
		return err
	}

	// Terminate each value with a newline.
	// This makes the output look a little nicer
	// when debugging, and some kind of space
	// is required if the encoded value was a number,
	// so that the reader knows there aren't more
	// digits coming.
	e.WriteByte('\n')

	b := e.Bytes()
	if enc.indentPrefix != "" || enc.indentValue != "" {
		enc.indentBuf, err = appendIndent(enc.indentBuf[:0], b, enc.indentPrefix, enc.indentValue)
		if err != nil {
			return err
		}
		b = enc.indentBuf
	}
	if _, err = enc.w.Write(b); err != nil {
		enc.err = err
	}
	return err
}

// SetIndent instructs the encoder to format each subsequent encoded
// value as if indented by the package-level function Indent(dst, src, prefix, indent).
// Calling SetIndent("", "") disables indentation.
func (enc *Encoder) SetIndent(prefix, indent string) {
	enc.indentPrefix = prefix
	enc.indentValue = indent
}

// SetEscapeHTML specifies whether problematic HTML characters
// should be escaped inside JSON quoted strings.
// The default behavior is to escape &, <, and > to \u0026, \u003c, and \u003e
// to avoid certain safety problems that can arise when embedding JSON in HTML.
//
// In non-HTML settings where the escaping interferes with the readability
// of the output, SetEscapeHTML(false) disables this behavior.
func (enc *Encoder) SetEscapeHTML(on bool) {
	enc.escapeHTML = on
}

// RawMessage is a raw encoded JSON value.
// It implements [Marshaler] and [Unmarshaler] and can
// be used to delay JSON decoding or precompute a JSON encoding.
type RawMessage []byte

// MarshalJSON returns m as the JSON encoding of m.
func (m RawMessage) MarshalJSON() ([]byte, error) {
	if m == nil {
		return []byte("null"), nil
	}
	return m, nil
}

// UnmarshalJSON sets *m to a copy of data.
func (m *RawMessage) UnmarshalJSON(data []byte) error {
	if m == nil {
		return errors.New("json.RawMessage: UnmarshalJSON on nil pointer")
	}
	*m = append((*m)[0:0], data...)
	return nil
}

var _ Marshaler = (*RawMessage)(nil)
var _ Unmarshaler = (*RawMessage)(nil)

// A Token holds a value of one of these types:
//
//   - [Delim], for the four JSON delimiters [ ] { }
//   - bool, for JSON booleans
//   - float64, for JSON numbers
//   - [Number], for JSON numbers
//   - string, for JSON string literals
//   - nil, for JSON null
type Token any

const (
	tokenTopValue = iota
	tokenArrayStart
	tokenArrayValue
	tokenArrayComma
	tokenObjectStart
	tokenObjectKey
	tokenObjectColon
	tokenObjectValue
	tokenObjectComma
)

// advance tokenstate from a separator state to a value state
func (dec *Decoder) tokenPrepareForDecode() error {
	// Note: Not calling peek before switch, to avoid
	// putting peek into the standard Decode path.
	// peek is only called when using the Token API.
	switch dec.tokenState {
	case tokenArrayComma:
		c, err := dec.peek()
		if err != nil {
			return err
		}
		if c != ',' {
			return &SyntaxError{"expected comma after array element", dec.InputOffset()}
		}
		dec.scanp++
		dec.tokenState = tokenArrayValue
	case tokenObjectColon:
		c, err := dec.peek()
		if err != nil {
			return err
		}
		if c != ':' {
			return &SyntaxError{"expected colon after object key", dec.InputOffset()}
		}
		dec.scanp++
		dec.tokenState = tokenObjectValue
	}
	return nil
}

func (dec *Decoder) tokenValueAllowed() bool {
	switch dec.tokenState {
	case tokenTopValue, tokenArrayStart, tokenArrayValue, tokenObjectValue:
		return true
	}
	return false
}

func (dec *Decoder) tokenValueEnd() {
	switch dec.tokenState {
	case tokenArrayStart, tokenArrayValue:
		dec.tokenState = tokenArrayComma
	case tokenObjectValue:
		dec.tokenState = tokenObjectComma
	}
}

// A Delim is a JSON array or object delimiter, one of [ ] { or }.
type Delim rune

func (d Delim) String() string {
	return string(d)
}

// Token returns the next JSON token in the input stream.
// At the end of the input stream, Token returns nil, [io.EOF].
//
// Token guarantees that the delimiters [ ] { } it returns are
// properly nested and matched: if Token encounters an unexpected
// delimiter in the input, it will return an error.
//
// The input stream consists of basic JSON values—bool, string,
// number, and null—along with delimiters [ ] { } of type [Delim]
// to mark the start and end of arrays and objects.
// Commas and colons are elided.
func (dec *Decoder) Token() (Token, error) {
	for {
		c, err := dec.peek()
		if err != nil {
			return nil, err
		}
		switch c {
		case '[':
			if !dec.tokenValueAllowed() {
				return dec.tokenError(c)
			}
			dec.scanp++
			dec.tokenStack = append(dec.tokenStack, dec.tokenState)
			dec.tokenState = tokenArrayStart
			return Delim('['), nil

		case ']':
			if dec.tokenState != tokenArrayStart && dec.tokenState != tokenArrayComma {
				return dec.tokenError(c)
			}
			dec.scanp++
			dec.tokenState = dec.tokenStack[len(dec.tokenStack)-1]
			dec.tokenStack = dec.tokenStack[:len(dec.tokenStack)-1]
			dec.tokenValueEnd()
			return Delim(']'), nil

		case '{':
			if !dec.tokenValueAllowed() {
				return dec.tokenError(c)
			}
			dec.scanp++
			dec.tokenStack = append(dec.tokenStack, dec.tokenState)
			dec.tokenState = tokenObjectStart
			return Delim('{'), nil

		case '}':
			if dec.tokenState != tokenObjectStart && dec.tokenState != tokenObjectComma {
				return dec.tokenError(c)
			}
			dec.scanp++
			dec.tokenState = dec.tokenStack[len(dec.tokenStack)-1]
			dec.tokenStack = dec.tokenStack[:len(dec.tokenStack)-1]
			dec.tokenValueEnd()
			return Delim('}'), nil

		case ':':
			if dec.tokenState != tokenObjectColon {
				return dec.tokenError(c)
			}
			dec.scanp++
			dec.tokenState = tokenObjectValue
			continue

		case ',':
			if dec.tokenState == tokenArrayComma {
				dec.scanp++
				dec.tokenState = tokenArrayValue
				continue
			}
			if dec.tokenState == tokenObjectComma {
				dec.scanp++
				dec.tokenState = tokenObjectKey
				continue
			}
			return dec.tokenError(c)

		case '"':
			if dec.tokenState == tokenObjectStart || dec.tokenState == tokenObjectKey {
				var x string
				old := dec.tokenState
				dec.tokenState = tokenTopValue
				err := dec.Decode(&x)
				dec.tokenState = old
				if err != nil {
					return nil, err
				}
				dec.tokenState = tokenObjectColon
				return x, nil
			}
			fallthrough

		default:
			if !dec.tokenValueAllowed() {
				return dec.tokenError(c)
			}
			var x any
			if err := dec.Decode(&x); err != nil {
				return nil, err
			}
			return x, nil
		}
	}
}

func (dec *Decoder) tokenError(c byte) (Token, error) {
	var context string
	switch dec.tokenState {
	case tokenTopValue:
		context = " looking for beginning of value"
	case tokenArrayStart, tokenArrayValue, tokenObjectValue:
		context = " looking for beginning of value"
	case tokenArrayComma:
		context = " after array element"
	case tokenObjectKey:
		context = " looking for beginning of object key string"
	case tokenObjectColon:
		context = " after object key"
	case tokenObjectComma:
		context = " after object key:value pair"
	}
	return nil, &SyntaxError{"invalid character " + quoteChar(c) + context, dec.InputOffset()}
}

// More reports whether there is another element in the
// current array or object being parsed.
func (dec *Decoder) More() bool {
	c, err := dec.peek()
	return err == nil && c != ']' && c != '}'
}

func (dec *Decoder) peek() (byte, error) {
	var err error
	for {
		for i := dec.scanp; i < len(dec.buf); i++ {
			c := dec.buf[i]
			if isSpace(c) {
				continue
			}
			dec.scanp = i
			return c, nil
		}
		// buffer has been scanned, now report any error
		if err != nil {
			return 0, err
		}
		err = dec.refill()
	}
}

// InputOffset returns the input stream byte offset of the current decoder position.
// The offset gives the location of the end of the most recently returned token
// and the beginning of the next token.
func (dec *Decoder) InputOffset() int64 {
	return dec.scanned + int64(dec.scanp)
}
```