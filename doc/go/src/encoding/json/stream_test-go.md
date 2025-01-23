Response:
Let's break down the thought process for analyzing the provided Go code.

**1. Initial Understanding of the File Path and Context:**

The filename `go/src/encoding/json/stream_test.go` immediately tells us this is a test file for the `encoding/json` package, specifically related to *streaming* JSON operations. This suggests functionalities for encoding and decoding JSON data in a sequential manner, rather than loading the entire JSON into memory at once.

**2. High-Level Overview of the Code:**

A quick scan reveals several test functions (starting with `Test...`), helper functions (like `Name`, `nlines`, `diff`), and some test data (`streamTest`, `streamEncoded`). This confirms it's primarily a testing file.

**3. Identifying Key Functionalities Based on Test Names and Logic:**

* **`TestEncoder` and `TestDecoder`:** These are the most obvious candidates for core streaming functionalities. They iterate through the `streamTest` data and compare the encoded/decoded output with the expected `streamEncoded`. This clearly points to testing the `Encoder` and `Decoder` types.

* **`TestEncoderIndent`:** The name suggests it tests the indentation feature of the encoder, further confirming the `Encoder`'s capabilities.

* **`TestEncoderSetEscapeHTML`:** This focuses on the `SetEscapeHTML` method of the encoder, which is about controlling the escaping of HTML characters.

* **`TestDecoderBuffered`:** This suggests the decoder has a way to access any remaining data in the input buffer after a successful decoding.

* **`TestRawMessage` and `TestNullRawMessage`:**  These tests deal with the `RawMessage` type, implying the code tests how to handle raw JSON blobs within a larger structure without immediate decoding.

* **`TestBlocking`:** This tests the behavior of the decoder when reading from a pipe, ensuring it doesn't block indefinitely if the input stream isn't complete. This is a critical aspect of streaming.

* **`TestDecodeInStream`:** This is a more in-depth test of the decoder, specifically looking at its ability to handle a stream of JSON tokens using the `Token()` method, and also how `Decode()` interacts within such a stream. The test cases include error scenarios, indicating robustness testing.

* **`TestHTTPDecoding`:** This demonstrates how the `Decoder` can be used with an `http.Response.Body`, showcasing a real-world use case of streaming JSON from a network source.

**4. Focusing on `Encoder` and `Decoder` Implementation (Inference):**

The tests for `Encoder` show usage of `NewEncoder(io.Writer)` and the `Encode(interface{})` method. The `SetIndent` and `SetEscapeHTML` methods are also evident. We can infer that `Encoder` likely holds an `io.Writer` and manages the internal state for encoding.

The tests for `Decoder` use `NewDecoder(io.Reader)` and `Decode(interface{})`. The `Buffered()` method is also used. This suggests `Decoder` holds an `io.Reader` and manages the state for decoding. The `Token()` method in `TestDecodeInStream` suggests a lower-level way to process the JSON structure.

**5. Constructing Go Code Examples:**

Based on the identified functionalities, the next step is to write illustrative Go code.

* **Encoding:**  Demonstrate `NewEncoder`, `Encode`, `SetIndent`, and `SetEscapeHTML`. Include a struct and basic data types to show encoding different JSON elements.
* **Decoding:** Show `NewDecoder`, `Decode`, and `Buffered`. Use the same struct as in the encoder example to illustrate the round trip. Also demonstrate decoding basic types.
* **Token Decoding:** Specifically illustrate the `Token()` method and how to handle `Delim` and other token types.
* **RawMessage:** Provide an example of using `RawMessage` to defer decoding a portion of the JSON.

**6. Identifying Potential User Errors:**

This requires thinking about common mistakes when working with streaming data.

* **Forgetting to check for errors after `Encode` or `Decode`:** Streaming operations can fail mid-stream.
* **Not understanding `Buffered()`:** Users might not realize that `Buffered()` returns unread data.
* **Misusing `Token()`:**  It's a lower-level API, so users might not correctly handle the different token types.
* **Incorrectly assuming the entire stream is in memory:** Streaming implies that data is processed incrementally.

**7. Review and Refinement:**

Finally, review the generated explanation and code examples for clarity, accuracy, and completeness. Ensure the language is accessible and the examples are easy to understand. For instance, the initial thought might not have included an example for `Token()`, but reviewing `TestDecodeInStream` would highlight its importance. Similarly, emphasizing the streaming nature and error handling are crucial for understanding the `encoding/json` package's stream capabilities.
这个 `go/src/encoding/json/stream_test.go` 文件是 Go 语言标准库 `encoding/json` 包的一部分，专门用于测试 JSON 编码器 (`Encoder`) 和解码器 (`Decoder`) 的流式处理功能。  它的主要功能可以归纳为以下几点：

1. **测试 `Encoder` 的基本流式编码功能:**
   - 验证 `Encoder` 能够将一系列 Go 语言的值（各种 JSON 数据类型，如数字、字符串、null、布尔值、数组、对象）逐个编码成 JSON 格式并写入 `io.Writer`。
   - 测试编码输出的正确性，对比实际编码结果和预期结果。
   - 涵盖了连续编码多个值的场景。

2. **测试 `Encoder` 的缩进功能:**
   - 验证 `Encoder` 的 `SetIndent` 方法能够控制 JSON 输出的缩进格式，使其更易读。
   - 测试不同缩进字符串的效果。
   - 验证可以通过 `SetIndent("", "")` 关闭缩进。

3. **测试 `Encoder` 的错误处理和状态重用:**
   - 测试当编码过程中遇到错误（例如，编码包含循环引用的数据结构）时，`Encoder` 能否正确返回错误。
   - 验证在遇到错误后，`Encoder` 的内部状态能够被重用，可以继续编码其他有效数据。

4. **测试 `Encoder` 的 HTML 转义功能:**
   - 验证 `Encoder` 的 `SetEscapeHTML` 方法能够控制是否对 HTML 特殊字符（如 `<`, `>`, `&`）进行转义。
   - 测试在不同转义设置下的编码输出结果。

5. **测试 `Decoder` 的基本流式解码功能:**
   - 验证 `Decoder` 能够从 `io.Reader` 中逐个解码 JSON 值，并将它们赋值给 Go 语言的变量。
   - 测试解码各种 JSON 数据类型到对应的 Go 类型。
   - 涵盖了连续解码多个值的场景，包括输入中不包含换行符的情况。

6. **测试 `Decoder` 的 `Buffered()` 方法:**
   - 验证 `Decoder` 的 `Buffered()` 方法能够返回解码器内部缓冲区中尚未被解码的剩余数据。

7. **测试 `RawMessage` 的处理:**
   - 验证 `Encoder` 和 `Decoder` 如何处理 `json.RawMessage` 类型，即允许将部分 JSON 数据作为原始字节流进行编码和解码，而不进行进一步的解析。
   - 测试 `RawMessage` 为 `null` 时的处理。

8. **测试 `Decoder` 的阻塞行为:**
   - 测试当 `Decoder` 从管道 (`net.Pipe`) 读取数据时，如果输入不完整，`Decode` 方法会阻塞等待，直到有更多数据到达。

9. **测试 `Decoder` 的 `Token()` 方法:**
   - 验证 `Decoder` 的 `Token()` 方法能够逐个返回 JSON 数据流中的 Token（例如，`{`, `}`, `[`, `]`, 字符串、数字等）。
   - 测试 `Token()` 方法在遇到错误的 JSON 格式时的处理。
   - 测试 `Decode()` 方法与 `Token()` 方法的混合使用。

10. **测试 `Decoder` 在 HTTP 场景下的应用:**
    - 演示如何使用 `Decoder` 来解码 HTTP 响应体中的 JSON 数据。
    - 验证在成功解码后再次调用 `Decode` 会返回 `io.EOF`。

**推理 Go 语言功能实现 (带有代码示例):**

通过分析测试用例，我们可以推断出 `encoding/json` 包实现了以下与流式处理相关的 Go 语言功能：

**`Encoder` 类型:**  用于将 Go 数据结构编码成 JSON 数据流并写入 `io.Writer`。

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
		{"Alice", 30},
		{"Bob", 25},
	}

	enc := json.NewEncoder(os.Stdout) // 创建一个写入标准输出的 Encoder

	fmt.Println("开始编码...")
	for _, p := range people {
		err := enc.Encode(p) // 逐个编码 Person 结构体
		if err != nil {
			fmt.Println("编码错误:", err)
			return
		}
	}
	fmt.Println("编码完成。")
}

// 假设输出:
// 开始编码...
// {"name":"Alice","age":30}
// {"name":"Bob","age":25}
// 编码完成。
```

**`Decoder` 类型:** 用于从 `io.Reader` 中读取 JSON 数据流并解码成 Go 数据结构。

```go
package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Person struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
}

func main() {
	jsonStream := `{"name":"Alice","age":30}
{"name":"Bob","age":25}
`
	reader := strings.NewReader(jsonStream)
	dec := json.NewDecoder(reader) // 创建一个从字符串读取的 Decoder

	fmt.Println("开始解码...")
	for {
		var p Person
		err := dec.Decode(&p) // 逐个解码 JSON 对象到 Person 结构体
		if err != nil {
			if err.Error() == "EOF" { // 读取到流的末尾
				fmt.Println("解码完成。")
				break
			}
			fmt.Println("解码错误:", err)
			return
		}
		fmt.Printf("解码得到: %+v\n", p)
	}
}

// 假设输出:
// 开始解码...
// 解码得到: {Name:Alice Age:30}
// 解码得到: {Name:Bob Age:25}
// 解码完成。
```

**`RawMessage` 类型:**  用于延迟解析 JSON 数据。

```go
package main

import (
	"encoding/json"
	"fmt"
)

type Event struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

type UserCreated struct {
	UserID   int    `json:"userId"`
	Username string `json:"username"`
}

func main() {
	jsonStr := `{"type":"user_created", "data":{"userId":123, "username":"john.doe"}}`

	var event Event
	err := json.Unmarshal([]byte(jsonStr), &event)
	if err != nil {
		fmt.Println("Unmarshal error:", err)
		return
	}

	fmt.Printf("Event Type: %s\n", event.Type)

	// 延迟解析 Data 字段
	if event.Type == "user_created" {
		var user UserCreated
		err = json.Unmarshal(event.Data, &user)
		if err != nil {
			fmt.Println("Unmarshal data error:", err)
			return
		}
		fmt.Printf("User ID: %d, Username: %s\n", user.UserID, user.Username)
	}
}

// 假设输出:
// Event Type: user_created
// User ID: 123, Username: john.doe
```

**`Decoder.Token()` 方法:**  用于逐个读取 JSON 数据流中的 Token。

```go
package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

func main() {
	jsonStream := `{"name": "Alice", "age": 30}`
	reader := strings.NewReader(jsonStream)
	decoder := json.NewDecoder(reader)

	fmt.Println("JSON Tokens:")
	for {
		token, err := decoder.Token()
		if err != nil {
			break // 通常是 io.EOF
		}
		fmt.Printf("Token: %v (Type: %T)\n", token, token)
	}
}

// 假设输出:
// JSON Tokens:
// Token: { (Type: json.Delim)
// Token: name (Type: string)
// Token: Alice (Type: string)
// Token: age (Type: string)
// Token: 30 (Type: float64)
// Token: } (Type: json.Delim)
```

**命令行参数处理:**

这段代码本身是测试代码，不涉及任何需要通过命令行传递的参数。它主要通过 Go 的 `testing` 包来运行，例如使用 `go test ./encoding/json` 命令。

**使用者易犯错的点:**

1. **解码时忘记传递指针:**  `Decoder.Decode()` 方法需要一个指向要填充的变量的指针。如果传递的是值，解码后的数据不会被保存。

   ```go
   // 错误示例
   var p Person
   err := dec.Decode(p) // 应该传递 &p
   ```

2. **假设一次 `Decode()` 调用能读取整个 JSON 文档:** 对于流式解码，`Decode()` 只会尝试读取并解码一个 JSON 值。如果输入包含多个 JSON 值，需要多次调用 `Decode()`。

   ```go
   // 正确的流式解码方式
   for dec.More() { // 或者检查 err 是否为 io.EOF
       var p Person
       err := dec.Decode(&p)
       // ...
   }
   ```

3. **混淆 `Unmarshal` 和 `Decode`:** `Unmarshal` 用于解码一个完整的 JSON 文档（通常是 `[]byte`），而 `Decode` 用于从 `io.Reader` 中流式解码。

4. **不处理 `Decoder.Token()` 返回的 `Delim`:** 使用 `Token()` 进行低级解析时，需要正确处理表示 JSON 结构开始和结束的 `Delim` 类型 (`{`, `}`, `[`, `]`)。

5. **在编码或解码复杂结构时未正确定义 JSON tag:**  结构体字段需要使用 `json:` tag 来指定 JSON 字段名，以及可能的其他选项（如 `omitempty`、`string` 等）。

希望以上解释能够帮助你理解这段 Go 测试代码的功能以及相关的 Go 语言特性。

### 提示词
```
这是路径为go/src/encoding/json/stream_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"path"
	"reflect"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

// TODO(https://go.dev/issue/52751): Replace with native testing support.

// CaseName is a case name annotated with a file and line.
type CaseName struct {
	Name  string
	Where CasePos
}

// Name annotates a case name with the file and line of the caller.
func Name(s string) (c CaseName) {
	c.Name = s
	runtime.Callers(2, c.Where.pc[:])
	return c
}

// CasePos represents a file and line number.
type CasePos struct{ pc [1]uintptr }

func (pos CasePos) String() string {
	frames := runtime.CallersFrames(pos.pc[:])
	frame, _ := frames.Next()
	return fmt.Sprintf("%s:%d", path.Base(frame.File), frame.Line)
}

// Test values for the stream test.
// One of each JSON kind.
var streamTest = []any{
	0.1,
	"hello",
	nil,
	true,
	false,
	[]any{"a", "b", "c"},
	map[string]any{"K": "Kelvin", "ß": "long s"},
	3.14, // another value to make sure something can follow map
}

var streamEncoded = `0.1
"hello"
null
true
false
["a","b","c"]
{"ß":"long s","K":"Kelvin"}
3.14
`

func TestEncoder(t *testing.T) {
	for i := 0; i <= len(streamTest); i++ {
		var buf strings.Builder
		enc := NewEncoder(&buf)
		// Check that enc.SetIndent("", "") turns off indentation.
		enc.SetIndent(">", ".")
		enc.SetIndent("", "")
		for j, v := range streamTest[0:i] {
			if err := enc.Encode(v); err != nil {
				t.Fatalf("#%d.%d Encode error: %v", i, j, err)
			}
		}
		if have, want := buf.String(), nlines(streamEncoded, i); have != want {
			t.Errorf("encoding %d items: mismatch:", i)
			diff(t, []byte(have), []byte(want))
			break
		}
	}
}

func TestEncoderErrorAndReuseEncodeState(t *testing.T) {
	// Disable the GC temporarily to prevent encodeState's in Pool being cleaned away during the test.
	percent := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(percent)

	// Trigger an error in Marshal with cyclic data.
	type Dummy struct {
		Name string
		Next *Dummy
	}
	dummy := Dummy{Name: "Dummy"}
	dummy.Next = &dummy

	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	if err := enc.Encode(dummy); err == nil {
		t.Errorf("Encode(dummy) error: got nil, want non-nil")
	}

	type Data struct {
		A string
		I int
	}
	want := Data{A: "a", I: 1}
	if err := enc.Encode(want); err != nil {
		t.Errorf("Marshal error: %v", err)
	}

	var got Data
	if err := Unmarshal(buf.Bytes(), &got); err != nil {
		t.Errorf("Unmarshal error: %v", err)
	}
	if got != want {
		t.Errorf("Marshal/Unmarshal roundtrip:\n\tgot:  %v\n\twant: %v", got, want)
	}
}

var streamEncodedIndent = `0.1
"hello"
null
true
false
[
>."a",
>."b",
>."c"
>]
{
>."ß": "long s",
>."K": "Kelvin"
>}
3.14
`

func TestEncoderIndent(t *testing.T) {
	var buf strings.Builder
	enc := NewEncoder(&buf)
	enc.SetIndent(">", ".")
	for _, v := range streamTest {
		enc.Encode(v)
	}
	if have, want := buf.String(), streamEncodedIndent; have != want {
		t.Error("Encode mismatch:")
		diff(t, []byte(have), []byte(want))
	}
}

type strMarshaler string

func (s strMarshaler) MarshalJSON() ([]byte, error) {
	return []byte(s), nil
}

type strPtrMarshaler string

func (s *strPtrMarshaler) MarshalJSON() ([]byte, error) {
	return []byte(*s), nil
}

func TestEncoderSetEscapeHTML(t *testing.T) {
	var c C
	var ct CText
	var tagStruct struct {
		Valid   int `json:"<>&#! "`
		Invalid int `json:"\\"`
	}

	// This case is particularly interesting, as we force the encoder to
	// take the address of the Ptr field to use its MarshalJSON method. This
	// is why the '&' is important.
	marshalerStruct := &struct {
		NonPtr strMarshaler
		Ptr    strPtrMarshaler
	}{`"<str>"`, `"<str>"`}

	// https://golang.org/issue/34154
	stringOption := struct {
		Bar string `json:"bar,string"`
	}{`<html>foobar</html>`}

	tests := []struct {
		CaseName
		v          any
		wantEscape string
		want       string
	}{
		{Name("c"), c, `"\u003c\u0026\u003e"`, `"<&>"`},
		{Name("ct"), ct, `"\"\u003c\u0026\u003e\""`, `"\"<&>\""`},
		{Name(`"<&>"`), "<&>", `"\u003c\u0026\u003e"`, `"<&>"`},
		{
			Name("tagStruct"), tagStruct,
			`{"\u003c\u003e\u0026#! ":0,"Invalid":0}`,
			`{"<>&#! ":0,"Invalid":0}`,
		},
		{
			Name(`"<str>"`), marshalerStruct,
			`{"NonPtr":"\u003cstr\u003e","Ptr":"\u003cstr\u003e"}`,
			`{"NonPtr":"<str>","Ptr":"<str>"}`,
		},
		{
			Name("stringOption"), stringOption,
			`{"bar":"\"\\u003chtml\\u003efoobar\\u003c/html\\u003e\""}`,
			`{"bar":"\"<html>foobar</html>\""}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			var buf strings.Builder
			enc := NewEncoder(&buf)
			if err := enc.Encode(tt.v); err != nil {
				t.Fatalf("%s: Encode(%s) error: %s", tt.Where, tt.Name, err)
			}
			if got := strings.TrimSpace(buf.String()); got != tt.wantEscape {
				t.Errorf("%s: Encode(%s):\n\tgot:  %s\n\twant: %s", tt.Where, tt.Name, got, tt.wantEscape)
			}
			buf.Reset()
			enc.SetEscapeHTML(false)
			if err := enc.Encode(tt.v); err != nil {
				t.Fatalf("%s: SetEscapeHTML(false) Encode(%s) error: %s", tt.Where, tt.Name, err)
			}
			if got := strings.TrimSpace(buf.String()); got != tt.want {
				t.Errorf("%s: SetEscapeHTML(false) Encode(%s):\n\tgot:  %s\n\twant: %s",
					tt.Where, tt.Name, got, tt.want)
			}
		})
	}
}

func TestDecoder(t *testing.T) {
	for i := 0; i <= len(streamTest); i++ {
		// Use stream without newlines as input,
		// just to stress the decoder even more.
		// Our test input does not include back-to-back numbers.
		// Otherwise stripping the newlines would
		// merge two adjacent JSON values.
		var buf bytes.Buffer
		for _, c := range nlines(streamEncoded, i) {
			if c != '\n' {
				buf.WriteRune(c)
			}
		}
		out := make([]any, i)
		dec := NewDecoder(&buf)
		for j := range out {
			if err := dec.Decode(&out[j]); err != nil {
				t.Fatalf("decode #%d/%d error: %v", j, i, err)
			}
		}
		if !reflect.DeepEqual(out, streamTest[0:i]) {
			t.Errorf("decoding %d items: mismatch:", i)
			for j := range out {
				if !reflect.DeepEqual(out[j], streamTest[j]) {
					t.Errorf("#%d:\n\tgot:  %v\n\twant: %v", j, out[j], streamTest[j])
				}
			}
			break
		}
	}
}

func TestDecoderBuffered(t *testing.T) {
	r := strings.NewReader(`{"Name": "Gopher"} extra `)
	var m struct {
		Name string
	}
	d := NewDecoder(r)
	err := d.Decode(&m)
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "Gopher" {
		t.Errorf("Name = %s, want Gopher", m.Name)
	}
	rest, err := io.ReadAll(d.Buffered())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(rest), " extra "; got != want {
		t.Errorf("Remaining = %s, want %s", got, want)
	}
}

func nlines(s string, n int) string {
	if n <= 0 {
		return ""
	}
	for i, c := range s {
		if c == '\n' {
			if n--; n == 0 {
				return s[0 : i+1]
			}
		}
	}
	return s
}

func TestRawMessage(t *testing.T) {
	var data struct {
		X  float64
		Id RawMessage
		Y  float32
	}
	const raw = `["\u0056",null]`
	const want = `{"X":0.1,"Id":["\u0056",null],"Y":0.2}`
	err := Unmarshal([]byte(want), &data)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if string([]byte(data.Id)) != raw {
		t.Fatalf("Unmarshal:\n\tgot:  %s\n\twant: %s", []byte(data.Id), raw)
	}
	got, err := Marshal(&data)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	if string(got) != want {
		t.Fatalf("Marshal:\n\tgot:  %s\n\twant: %s", got, want)
	}
}

func TestNullRawMessage(t *testing.T) {
	var data struct {
		X     float64
		Id    RawMessage
		IdPtr *RawMessage
		Y     float32
	}
	const want = `{"X":0.1,"Id":null,"IdPtr":null,"Y":0.2}`
	err := Unmarshal([]byte(want), &data)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if want, got := "null", string(data.Id); want != got {
		t.Fatalf("Unmarshal:\n\tgot:  %s\n\twant: %s", got, want)
	}
	if data.IdPtr != nil {
		t.Fatalf("pointer mismatch: got non-nil, want nil")
	}
	got, err := Marshal(&data)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	if string(got) != want {
		t.Fatalf("Marshal:\n\tgot:  %s\n\twant: %s", got, want)
	}
}

func TestBlocking(t *testing.T) {
	tests := []struct {
		CaseName
		in string
	}{
		{Name(""), `{"x": 1}`},
		{Name(""), `[1, 2, 3]`},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			r, w := net.Pipe()
			go w.Write([]byte(tt.in))
			var val any

			// If Decode reads beyond what w.Write writes above,
			// it will block, and the test will deadlock.
			if err := NewDecoder(r).Decode(&val); err != nil {
				t.Errorf("%s: NewDecoder(%s).Decode error: %v", tt.Where, tt.in, err)
			}
			r.Close()
			w.Close()
		})
	}
}

type decodeThis struct {
	v any
}

func TestDecodeInStream(t *testing.T) {
	tests := []struct {
		CaseName
		json      string
		expTokens []any
	}{
		// streaming token cases
		{CaseName: Name(""), json: `10`, expTokens: []any{float64(10)}},
		{CaseName: Name(""), json: ` [10] `, expTokens: []any{
			Delim('['), float64(10), Delim(']')}},
		{CaseName: Name(""), json: ` [false,10,"b"] `, expTokens: []any{
			Delim('['), false, float64(10), "b", Delim(']')}},
		{CaseName: Name(""), json: `{ "a": 1 }`, expTokens: []any{
			Delim('{'), "a", float64(1), Delim('}')}},
		{CaseName: Name(""), json: `{"a": 1, "b":"3"}`, expTokens: []any{
			Delim('{'), "a", float64(1), "b", "3", Delim('}')}},
		{CaseName: Name(""), json: ` [{"a": 1},{"a": 2}] `, expTokens: []any{
			Delim('['),
			Delim('{'), "a", float64(1), Delim('}'),
			Delim('{'), "a", float64(2), Delim('}'),
			Delim(']')}},
		{CaseName: Name(""), json: `{"obj": {"a": 1}}`, expTokens: []any{
			Delim('{'), "obj", Delim('{'), "a", float64(1), Delim('}'),
			Delim('}')}},
		{CaseName: Name(""), json: `{"obj": [{"a": 1}]}`, expTokens: []any{
			Delim('{'), "obj", Delim('['),
			Delim('{'), "a", float64(1), Delim('}'),
			Delim(']'), Delim('}')}},

		// streaming tokens with intermittent Decode()
		{CaseName: Name(""), json: `{ "a": 1 }`, expTokens: []any{
			Delim('{'), "a",
			decodeThis{float64(1)},
			Delim('}')}},
		{CaseName: Name(""), json: ` [ { "a" : 1 } ] `, expTokens: []any{
			Delim('['),
			decodeThis{map[string]any{"a": float64(1)}},
			Delim(']')}},
		{CaseName: Name(""), json: ` [{"a": 1},{"a": 2}] `, expTokens: []any{
			Delim('['),
			decodeThis{map[string]any{"a": float64(1)}},
			decodeThis{map[string]any{"a": float64(2)}},
			Delim(']')}},
		{CaseName: Name(""), json: `{ "obj" : [ { "a" : 1 } ] }`, expTokens: []any{
			Delim('{'), "obj", Delim('['),
			decodeThis{map[string]any{"a": float64(1)}},
			Delim(']'), Delim('}')}},

		{CaseName: Name(""), json: `{"obj": {"a": 1}}`, expTokens: []any{
			Delim('{'), "obj",
			decodeThis{map[string]any{"a": float64(1)}},
			Delim('}')}},
		{CaseName: Name(""), json: `{"obj": [{"a": 1}]}`, expTokens: []any{
			Delim('{'), "obj",
			decodeThis{[]any{
				map[string]any{"a": float64(1)},
			}},
			Delim('}')}},
		{CaseName: Name(""), json: ` [{"a": 1} {"a": 2}] `, expTokens: []any{
			Delim('['),
			decodeThis{map[string]any{"a": float64(1)}},
			decodeThis{&SyntaxError{"expected comma after array element", 11}},
		}},
		{CaseName: Name(""), json: `{ "` + strings.Repeat("a", 513) + `" 1 }`, expTokens: []any{
			Delim('{'), strings.Repeat("a", 513),
			decodeThis{&SyntaxError{"expected colon after object key", 518}},
		}},
		{CaseName: Name(""), json: `{ "\a" }`, expTokens: []any{
			Delim('{'),
			&SyntaxError{"invalid character 'a' in string escape code", 3},
		}},
		{CaseName: Name(""), json: ` \a`, expTokens: []any{
			&SyntaxError{"invalid character '\\\\' looking for beginning of value", 1},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			dec := NewDecoder(strings.NewReader(tt.json))
			for i, want := range tt.expTokens {
				var got any
				var err error

				if dt, ok := want.(decodeThis); ok {
					want = dt.v
					err = dec.Decode(&got)
				} else {
					got, err = dec.Token()
				}
				if errWant, ok := want.(error); ok {
					if err == nil || !reflect.DeepEqual(err, errWant) {
						t.Fatalf("%s:\n\tinput: %s\n\tgot error:  %v\n\twant error: %v", tt.Where, tt.json, err, errWant)
					}
					break
				} else if err != nil {
					t.Fatalf("%s:\n\tinput: %s\n\tgot error:  %v\n\twant error: nil", tt.Where, tt.json, err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("%s: token %d:\n\tinput: %s\n\tgot:  %T(%v)\n\twant: %T(%v)", tt.Where, i, tt.json, got, got, want, want)
				}
			}
		})
	}
}

// Test from golang.org/issue/11893
func TestHTTPDecoding(t *testing.T) {
	const raw = `{ "foo": "bar" }`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(raw))
	}))
	defer ts.Close()
	res, err := http.Get(ts.URL)
	if err != nil {
		log.Fatalf("http.Get error: %v", err)
	}
	defer res.Body.Close()

	foo := struct {
		Foo string
	}{}

	d := NewDecoder(res.Body)
	err = d.Decode(&foo)
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if foo.Foo != "bar" {
		t.Errorf(`Decode: got %q, want "bar"`, foo.Foo)
	}

	// make sure we get the EOF the second time
	err = d.Decode(&foo)
	if err != io.EOF {
		t.Errorf("Decode error:\n\tgot:  %v\n\twant: io.EOF", err)
	}
}
```