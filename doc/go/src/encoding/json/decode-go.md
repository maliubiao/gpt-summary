Response:
Let's break down the thought process for analyzing the provided Go code snippet and answering the request.

**1. Understanding the Goal:**

The core request is to understand the functionality of the `decode.go` file, specifically the provided section. The prompt asks for:

* **Core Functionality:** What does this code *do*?
* **Go Feature Implementation:** What Go features does it enable or relate to?
* **Code Examples:** How can this be used in practice (with input/output)?
* **Command-Line Arguments:** Does it involve any?
* **Common Mistakes:** What are potential pitfalls for users?
* **Summary:** A concise overview of the functionality.

**2. Initial Scan and Keyword Identification:**

I start by quickly scanning the code for prominent keywords and structures:

* `package json`:  Indicates this is part of the `encoding/json` package.
* `Unmarshal`:  A key function, likely responsible for converting JSON data *into* Go data structures.
* `Unmarshaler` interface:  Suggests a mechanism for custom decoding.
* `UnmarshalTypeError`, `InvalidUnmarshalError`:  Error types related to the unmarshaling process.
* `decodeState`: A struct, likely managing the state of the decoding process.
* `scanner`: Another struct, possibly involved in parsing the JSON.
* `reflect`:  The `reflect` package is heavily used, implying introspection and dynamic type handling.
* `strconv`:  Used for string conversions (like numbers).
* Comments mentioning `Marshal`: Suggests a paired encoding function.

**3. Focusing on Key Functions:**

The `Unmarshal` function is clearly central. I analyze its documentation:

* Takes `data []byte` and `v any` as input.
* `v` must be a pointer.
* Handles `null`.
* Uses `Unmarshaler` interface.
* Handles `encoding.TextUnmarshaler`.
* Matches object keys to struct fields (case-insensitive).
* Defines how JSON types are mapped to Go types for interfaces.
* Describes how arrays and objects are handled.
* Mentions error handling (`SyntaxError`, `UnmarshalTypeError`).

**4. Dissecting `decodeState` and Related Structures:**

The `decodeState` struct seems to hold the internal state of the decoder. I note its fields:

* `data`: The JSON input.
* `off`: Current reading position.
* `opcode`: Likely the result of the scanning process.
* `scan`: The scanner instance.
* `errorContext`: For tracking errors within nested structures.
* `savedError`: To store the first error encountered.
* `useNumber`, `disallowUnknownFields`:  Configuration options (though not directly exposed in this snippet).

The `scanner` is mentioned but its internals aren't in this snippet. I understand it's responsible for tokenizing the JSON.

**5. Understanding the Unmarshaling Logic:**

I examine the `d.unmarshal(v)` call within `Unmarshal`. This leads to the `decodeState.value` method, which seems to handle the decoding based on the JSON token (`opcode`). The switch statement in `value` is key:

* `scanBeginArray`: Calls `d.array`.
* `scanBeginObject`: Calls `d.object`.
* `scanBeginLiteral`: Calls `d.literalStore`.

These methods (`array`, `object`, `literalStore`) contain the core logic for decoding different JSON types into Go values. I pay attention to how they handle:

* **Pointers:** `indirect` function.
* **Interfaces:** Special handling in `array` and `object`.
* **Structs:** Matching fields by name and tags.
* **Maps:** Handling different key types.
* **Errors:** `UnmarshalTypeError`.

**6. Identifying Go Feature Implementations:**

Based on the analysis, I can now identify the key Go features being used:

* **Reflection:**  Crucial for inspecting types, creating new values, and setting fields dynamically. The `reflect` package is pervasive.
* **Interfaces:**  The `Unmarshaler` and `encoding.TextUnmarshaler` interfaces provide extensibility. Empty interfaces (`any`) are used for general JSON values.
* **Pointers:** Essential for modifying values passed to `Unmarshal`.
* **Struct Tags:**  The mention of "tag" points to the use of struct tags (like `json:"fieldName"`) for customizing the mapping between JSON keys and Go struct fields.
* **Error Handling:** The use of custom error types like `UnmarshalTypeError` provides specific information about decoding failures.

**7. Crafting the Code Examples (Mental Simulation and General Knowledge):**

To illustrate the functionality, I need simple examples. I think about common JSON structures and how they'd be unmarshaled into Go:

* **Basic Types:**  Boolean, number, string.
* **Arrays:**  Decoding into slices and arrays.
* **Objects:** Decoding into structs and maps.
* **Null:** How it's handled with pointers and other types.
* **Custom Unmarshaler:**  A basic example of implementing the interface.

I don't need to run the code in this phase, but I rely on my understanding of Go's type system and the `encoding/json` package. I focus on demonstrating the key aspects described in the documentation.

**8. Addressing Command-Line Arguments and Common Mistakes:**

This specific snippet doesn't handle command-line arguments. The `encoding/json` package itself doesn't directly interact with command-line arguments.

For common mistakes, I consider typical errors users make with JSON unmarshaling:

* **Non-pointer receiver:**  Forgetting to pass a pointer to `Unmarshal`.
* **Type mismatches:**  Trying to unmarshal a JSON string into an `int`, for example.
* **Case sensitivity (initially thought of this, but the code explicitly mentions case-insensitive matching as a default, so I revise my understanding).**
* **Ignoring errors:** Not checking the error returned by `Unmarshal`.

**9. Summarizing the Functionality:**

Finally, I synthesize the information gathered into a concise summary that captures the core purpose of the code. I focus on the "what" and "why."

**Self-Correction/Refinement During the Process:**

* **Initial thought about case sensitivity:**  I initially thought case sensitivity might be a common mistake, but upon closer reading of the `Unmarshal` documentation, it explicitly mentions case-insensitive matching. This requires adjusting my understanding and the "common mistakes" section.
* **Focus on the provided snippet:**  It's important to stick to the functionality present in *this specific part* of the `decode.go` file. While I have broader knowledge of the `encoding/json` package, I avoid discussing features not directly evident here. For instance, `Decoder` and its methods like `DisallowUnknownFields` are mentioned in the comments, but the provided code doesn't fully implement them, so I only touch upon them lightly.

By following this structured approach, combining code analysis with understanding of the Go language and the purpose of the `encoding/json` package, I can generate a comprehensive and accurate answer to the prompt.
这是 `go/src/encoding/json/decode.go` 文件的一部分，主要负责将 JSON 编码的数据 **反序列化 (unmarshal)** 成 Go 语言中的数据结构。

**功能归纳:**

这段代码的核心功能是实现了将 JSON 数据解码为 Go 语言值的逻辑。它包含了 `Unmarshal` 函数以及一些辅助类型和方法，用于处理不同类型的 JSON 值并将其转换为相应的 Go 类型。  关键的功能点包括：

* **主入口 `Unmarshal` 函数:**  接收 JSON 字节切片和指向 Go 变量的指针，并将 JSON 数据解析后存储到该变量中。
* **错误处理:**  定义了多种错误类型，如 `UnmarshalTypeError` (JSON 值与 Go 类型不匹配)、`InvalidUnmarshalError` (传递给 `Unmarshal` 的参数无效) 等，用于报告反序列化过程中遇到的问题。
* **类型转换和匹配:**  根据 JSON 数据的类型（布尔值、数字、字符串、数组、对象、null）将其转换为相应的 Go 类型，并处理类型不匹配的情况。
* **处理接口类型:**  当目标类型是接口时，会根据 JSON 值的类型存储 `bool`、`float64`、`string`、`[]any`、`map[string]any` 或 `nil`。
* **处理结构体:**  将 JSON 对象的键与结构体字段名或标签进行匹配，并将值赋给相应的字段。
* **处理数组和切片:**  将 JSON 数组解码到 Go 数组或切片中，并处理大小不一致的情况。
* **处理 Map:** 将 JSON 对象解码到 Go 的 map 中，支持字符串、整数和实现了 `encoding.TextUnmarshaler` 接口的类型作为键。
* **支持自定义反序列化:**  通过 `Unmarshaler` 接口，允许 Go 类型自定义其 JSON 反序列化的逻辑。
* **支持 `encoding.TextUnmarshaler` 接口:**  如果 Go 类型实现了 `encoding.TextUnmarshaler` 接口，且 JSON 输入是带引号的字符串，则会调用该接口的方法进行反序列化。
* **内部状态管理:**  使用 `decodeState` 结构体来维护解码过程中的状态，例如当前读取的位置、扫描器状态、错误上下文等。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言标准库中 `encoding/json` 包中 **JSON 反序列化** 功能的核心实现。它使得 Go 程序能够方便地处理从外部系统接收到的 JSON 数据，或者解析存储在文件或数据库中的 JSON 数据。

**Go 代码举例说明:**

```go
package main

import (
	"encoding/json"
	"fmt"
	"log"
)

// 定义一个结构体，用于存储 JSON 数据
type Person struct {
	Name    string `json:"name"`
	Age     int    `json:"age"`
	Hobbies []string `json:"hobbies"`
}

func main() {
	// 假设我们有以下 JSON 数据
	jsonData := []byte(`{
		"name": "Alice",
		"age": 30,
		"hobbies": ["reading", "coding"]
	}`)

	// 创建一个 Person 类型的变量用于存储反序列化的结果
	var person Person

	// 调用 json.Unmarshal 将 JSON 数据反序列化到 person 变量中
	err := json.Unmarshal(jsonData, &person)
	if err != nil {
		log.Fatal(err)
	}

	// 打印反序列化后的结果
	fmt.Printf("Name: %s\n", person.Name)
	fmt.Printf("Age: %d\n", person.Age)
	fmt.Printf("Hobbies: %v\n", person.Hobbies)

	// 示例 2: 反序列化到 map[string]any
	var genericData map[string]any
	jsonData2 := []byte(`{"city": "New York", "population": 8000000}`)
	err = json.Unmarshal(jsonData2, &genericData)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Generic Data: %v\n", genericData)

	// 示例 3: 反序列化到接口
	var i interface{}
	jsonData3 := []byte(`true`)
	err = json.Unmarshal(jsonData3, &i)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Interface value: %v, type: %T\n", i, i)
}
```

**假设的输入与输出:**

**示例 1 输入:**

```json
{
  "name": "Bob",
  "age": 25,
  "hobbies": ["swimming", "hiking"]
}
```

**示例 1 输出:**

```
Name: Bob
Age: 25
Hobbies: [swimming hiking]
```

**示例 2 输入:**

```json
{
  "country": "USA",
  "currency": "USD"
}
```

**示例 2 输出:**

```
Generic Data: map[currency:USD country:USA]
```

**示例 3 输入:**

```json
"hello"
```

**示例 3 输出:**

```
Interface value: hello, type: string
```

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。命令行参数的处理通常发生在应用程序的 `main` 函数中，可以使用 `os` 包的 `Args` 切片或者 `flag` 包来解析。  `encoding/json` 包负责处理 JSON 数据的编码和解码，与命令行参数处理是分离的。

**使用者易犯错的点:**

* **传递非指针变量给 `Unmarshal`:**  `Unmarshal` 函数的第二个参数必须是指向变量的指针。如果传递的是非指针变量，会返回 `InvalidUnmarshalError`。

   ```go
   var person Person
   // 错误：person 是值类型，需要传递其指针 &person
   err := json.Unmarshal(jsonData, person)
   ```

* **JSON 数据结构与 Go 类型不匹配:**  如果 JSON 数据的结构或类型与目标 Go 类型的定义不符，`Unmarshal` 会尽力进行转换，但可能会导致数据丢失或返回 `UnmarshalTypeError`。

   ```go
   // Person 结构体中 Age 是 int 类型
   invalidJSON := []byte(`{"name": "Charlie", "age": "thirty"}`)
   var person Person
   err := json.Unmarshal(invalidJSON, &person)
   // err 会是 *json.UnmarshalTypeError，因为 "thirty" 无法转换为 int
   ```

* **忽略 `Unmarshal` 返回的错误:**  `Unmarshal` 在反序列化过程中可能会遇到各种错误，例如 JSON 语法错误、类型不匹配等。应该始终检查并处理 `Unmarshal` 返回的错误。

   ```go
   err := json.Unmarshal(jsonData, &person)
   if err != nil {
       log.Println("反序列化失败:", err)
       // 进行错误处理
   }
   ```

* **结构体字段没有导出 (首字母小写):**  `Unmarshal` 默认只能将 JSON 键值映射到已导出的结构体字段。

   ```go
   type User struct {
       name string `json:"userName"` // name 未导出
   }
   userData := []byte(`{"userName": "David"}`)
   var user User
   err := json.Unmarshal(userData, &user)
   // user.name 仍然是其零值，因为 name 未导出，Unmarshal 无法设置
   ```

* **JSON 键名与结构体字段名或标签不一致:**  `Unmarshal` 默认会进行精确匹配，然后进行大小写不敏感的匹配。如果 JSON 键名与结构体字段名和标签都不匹配，则该字段会被忽略（除非使用了 `Decoder.DisallowUnknownFields`）。

   ```go
   type Product struct {
       ProductName string `json:"product_name"`
       Price       float64
   }
   productData := []byte(`{"ProductName": "Laptop", "price": 1200.00}`)
   var product Product
   err := json.Unmarshal(productData, &product)
   // product.Price 将是 0，因为 JSON 中的 "price" 与结构体字段名 "Price" 不匹配，且没有对应的标签
   ```

**这是第1部分，共2部分，请归纳一下它的功能**

总而言之，这段 `decode.go` 代码片段是 Go 语言 `encoding/json` 包中负责将 JSON 数据反序列化为 Go 语言数据结构的核心实现。它提供了 `Unmarshal` 函数，能够根据 JSON 数据的类型和结构，将其转换为相应的 Go 类型，并处理各种可能出现的错误情况。这段代码是 Go 语言处理 JSON 数据的基础，使得 Go 程序能够方便地与使用 JSON 数据格式的外部系统进行交互。

Prompt: 
```
这是路径为go/src/encoding/json/decode.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Represents JSON data structure using native Go types: booleans, floats,
// strings, arrays, and maps.

package json

import (
	"encoding"
	"encoding/base64"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
	_ "unsafe" // for linkname
)

// Unmarshal parses the JSON-encoded data and stores the result
// in the value pointed to by v. If v is nil or not a pointer,
// Unmarshal returns an [InvalidUnmarshalError].
//
// Unmarshal uses the inverse of the encodings that
// [Marshal] uses, allocating maps, slices, and pointers as necessary,
// with the following additional rules:
//
// To unmarshal JSON into a pointer, Unmarshal first handles the case of
// the JSON being the JSON literal null. In that case, Unmarshal sets
// the pointer to nil. Otherwise, Unmarshal unmarshals the JSON into
// the value pointed at by the pointer. If the pointer is nil, Unmarshal
// allocates a new value for it to point to.
//
// To unmarshal JSON into a value implementing [Unmarshaler],
// Unmarshal calls that value's [Unmarshaler.UnmarshalJSON] method, including
// when the input is a JSON null.
// Otherwise, if the value implements [encoding.TextUnmarshaler]
// and the input is a JSON quoted string, Unmarshal calls
// [encoding.TextUnmarshaler.UnmarshalText] with the unquoted form of the string.
//
// To unmarshal JSON into a struct, Unmarshal matches incoming object
// keys to the keys used by [Marshal] (either the struct field name or its tag),
// preferring an exact match but also accepting a case-insensitive match. By
// default, object keys which don't have a corresponding struct field are
// ignored (see [Decoder.DisallowUnknownFields] for an alternative).
//
// To unmarshal JSON into an interface value,
// Unmarshal stores one of these in the interface value:
//
//   - bool, for JSON booleans
//   - float64, for JSON numbers
//   - string, for JSON strings
//   - []any, for JSON arrays
//   - map[string]any, for JSON objects
//   - nil for JSON null
//
// To unmarshal a JSON array into a slice, Unmarshal resets the slice length
// to zero and then appends each element to the slice.
// As a special case, to unmarshal an empty JSON array into a slice,
// Unmarshal replaces the slice with a new empty slice.
//
// To unmarshal a JSON array into a Go array, Unmarshal decodes
// JSON array elements into corresponding Go array elements.
// If the Go array is smaller than the JSON array,
// the additional JSON array elements are discarded.
// If the JSON array is smaller than the Go array,
// the additional Go array elements are set to zero values.
//
// To unmarshal a JSON object into a map, Unmarshal first establishes a map to
// use. If the map is nil, Unmarshal allocates a new map. Otherwise Unmarshal
// reuses the existing map, keeping existing entries. Unmarshal then stores
// key-value pairs from the JSON object into the map. The map's key type must
// either be any string type, an integer, or implement [encoding.TextUnmarshaler].
//
// If the JSON-encoded data contain a syntax error, Unmarshal returns a [SyntaxError].
//
// If a JSON value is not appropriate for a given target type,
// or if a JSON number overflows the target type, Unmarshal
// skips that field and completes the unmarshaling as best it can.
// If no more serious errors are encountered, Unmarshal returns
// an [UnmarshalTypeError] describing the earliest such error. In any
// case, it's not guaranteed that all the remaining fields following
// the problematic one will be unmarshaled into the target object.
//
// The JSON null value unmarshals into an interface, map, pointer, or slice
// by setting that Go value to nil. Because null is often used in JSON to mean
// “not present,” unmarshaling a JSON null into any other Go type has no effect
// on the value and produces no error.
//
// When unmarshaling quoted strings, invalid UTF-8 or
// invalid UTF-16 surrogate pairs are not treated as an error.
// Instead, they are replaced by the Unicode replacement
// character U+FFFD.
func Unmarshal(data []byte, v any) error {
	// Check for well-formedness.
	// Avoids filling out half a data structure
	// before discovering a JSON syntax error.
	var d decodeState
	err := checkValid(data, &d.scan)
	if err != nil {
		return err
	}

	d.init(data)
	return d.unmarshal(v)
}

// Unmarshaler is the interface implemented by types
// that can unmarshal a JSON description of themselves.
// The input can be assumed to be a valid encoding of
// a JSON value. UnmarshalJSON must copy the JSON data
// if it wishes to retain the data after returning.
//
// By convention, to approximate the behavior of [Unmarshal] itself,
// Unmarshalers implement UnmarshalJSON([]byte("null")) as a no-op.
type Unmarshaler interface {
	UnmarshalJSON([]byte) error
}

// An UnmarshalTypeError describes a JSON value that was
// not appropriate for a value of a specific Go type.
type UnmarshalTypeError struct {
	Value  string       // description of JSON value - "bool", "array", "number -5"
	Type   reflect.Type // type of Go value it could not be assigned to
	Offset int64        // error occurred after reading Offset bytes
	Struct string       // name of the struct type containing the field
	Field  string       // the full path from root node to the field, include embedded struct
}

func (e *UnmarshalTypeError) Error() string {
	if e.Struct != "" || e.Field != "" {
		return "json: cannot unmarshal " + e.Value + " into Go struct field " + e.Struct + "." + e.Field + " of type " + e.Type.String()
	}
	return "json: cannot unmarshal " + e.Value + " into Go value of type " + e.Type.String()
}

// An UnmarshalFieldError describes a JSON object key that
// led to an unexported (and therefore unwritable) struct field.
//
// Deprecated: No longer used; kept for compatibility.
type UnmarshalFieldError struct {
	Key   string
	Type  reflect.Type
	Field reflect.StructField
}

func (e *UnmarshalFieldError) Error() string {
	return "json: cannot unmarshal object key " + strconv.Quote(e.Key) + " into unexported field " + e.Field.Name + " of type " + e.Type.String()
}

// An InvalidUnmarshalError describes an invalid argument passed to [Unmarshal].
// (The argument to [Unmarshal] must be a non-nil pointer.)
type InvalidUnmarshalError struct {
	Type reflect.Type
}

func (e *InvalidUnmarshalError) Error() string {
	if e.Type == nil {
		return "json: Unmarshal(nil)"
	}

	if e.Type.Kind() != reflect.Pointer {
		return "json: Unmarshal(non-pointer " + e.Type.String() + ")"
	}
	return "json: Unmarshal(nil " + e.Type.String() + ")"
}

func (d *decodeState) unmarshal(v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return &InvalidUnmarshalError{reflect.TypeOf(v)}
	}

	d.scan.reset()
	d.scanWhile(scanSkipSpace)
	// We decode rv not rv.Elem because the Unmarshaler interface
	// test must be applied at the top level of the value.
	err := d.value(rv)
	if err != nil {
		return d.addErrorContext(err)
	}
	return d.savedError
}

// A Number represents a JSON number literal.
type Number string

// String returns the literal text of the number.
func (n Number) String() string { return string(n) }

// Float64 returns the number as a float64.
func (n Number) Float64() (float64, error) {
	return strconv.ParseFloat(string(n), 64)
}

// Int64 returns the number as an int64.
func (n Number) Int64() (int64, error) {
	return strconv.ParseInt(string(n), 10, 64)
}

// An errorContext provides context for type errors during decoding.
type errorContext struct {
	Struct     reflect.Type
	FieldStack []string
}

// decodeState represents the state while decoding a JSON value.
type decodeState struct {
	data                  []byte
	off                   int // next read offset in data
	opcode                int // last read result
	scan                  scanner
	errorContext          *errorContext
	savedError            error
	useNumber             bool
	disallowUnknownFields bool
}

// readIndex returns the position of the last byte read.
func (d *decodeState) readIndex() int {
	return d.off - 1
}

// phasePanicMsg is used as a panic message when we end up with something that
// shouldn't happen. It can indicate a bug in the JSON decoder, or that
// something is editing the data slice while the decoder executes.
const phasePanicMsg = "JSON decoder out of sync - data changing underfoot?"

func (d *decodeState) init(data []byte) *decodeState {
	d.data = data
	d.off = 0
	d.savedError = nil
	if d.errorContext != nil {
		d.errorContext.Struct = nil
		// Reuse the allocated space for the FieldStack slice.
		d.errorContext.FieldStack = d.errorContext.FieldStack[:0]
	}
	return d
}

// saveError saves the first err it is called with,
// for reporting at the end of the unmarshal.
func (d *decodeState) saveError(err error) {
	if d.savedError == nil {
		d.savedError = d.addErrorContext(err)
	}
}

// addErrorContext returns a new error enhanced with information from d.errorContext
func (d *decodeState) addErrorContext(err error) error {
	if d.errorContext != nil && (d.errorContext.Struct != nil || len(d.errorContext.FieldStack) > 0) {
		switch err := err.(type) {
		case *UnmarshalTypeError:
			err.Struct = d.errorContext.Struct.Name()
			fieldStack := d.errorContext.FieldStack
			if err.Field != "" {
				fieldStack = append(fieldStack, err.Field)
			}
			err.Field = strings.Join(fieldStack, ".")
		}
	}
	return err
}

// skip scans to the end of what was started.
func (d *decodeState) skip() {
	s, data, i := &d.scan, d.data, d.off
	depth := len(s.parseState)
	for {
		op := s.step(s, data[i])
		i++
		if len(s.parseState) < depth {
			d.off = i
			d.opcode = op
			return
		}
	}
}

// scanNext processes the byte at d.data[d.off].
func (d *decodeState) scanNext() {
	if d.off < len(d.data) {
		d.opcode = d.scan.step(&d.scan, d.data[d.off])
		d.off++
	} else {
		d.opcode = d.scan.eof()
		d.off = len(d.data) + 1 // mark processed EOF with len+1
	}
}

// scanWhile processes bytes in d.data[d.off:] until it
// receives a scan code not equal to op.
func (d *decodeState) scanWhile(op int) {
	s, data, i := &d.scan, d.data, d.off
	for i < len(data) {
		newOp := s.step(s, data[i])
		i++
		if newOp != op {
			d.opcode = newOp
			d.off = i
			return
		}
	}

	d.off = len(data) + 1 // mark processed EOF with len+1
	d.opcode = d.scan.eof()
}

// rescanLiteral is similar to scanWhile(scanContinue), but it specialises the
// common case where we're decoding a literal. The decoder scans the input
// twice, once for syntax errors and to check the length of the value, and the
// second to perform the decoding.
//
// Only in the second step do we use decodeState to tokenize literals, so we
// know there aren't any syntax errors. We can take advantage of that knowledge,
// and scan a literal's bytes much more quickly.
func (d *decodeState) rescanLiteral() {
	data, i := d.data, d.off
Switch:
	switch data[i-1] {
	case '"': // string
		for ; i < len(data); i++ {
			switch data[i] {
			case '\\':
				i++ // escaped char
			case '"':
				i++ // tokenize the closing quote too
				break Switch
			}
		}
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-': // number
		for ; i < len(data); i++ {
			switch data[i] {
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
				'.', 'e', 'E', '+', '-':
			default:
				break Switch
			}
		}
	case 't': // true
		i += len("rue")
	case 'f': // false
		i += len("alse")
	case 'n': // null
		i += len("ull")
	}
	if i < len(data) {
		d.opcode = stateEndValue(&d.scan, data[i])
	} else {
		d.opcode = scanEnd
	}
	d.off = i + 1
}

// value consumes a JSON value from d.data[d.off-1:], decoding into v, and
// reads the following byte ahead. If v is invalid, the value is discarded.
// The first byte of the value has been read already.
func (d *decodeState) value(v reflect.Value) error {
	switch d.opcode {
	default:
		panic(phasePanicMsg)

	case scanBeginArray:
		if v.IsValid() {
			if err := d.array(v); err != nil {
				return err
			}
		} else {
			d.skip()
		}
		d.scanNext()

	case scanBeginObject:
		if v.IsValid() {
			if err := d.object(v); err != nil {
				return err
			}
		} else {
			d.skip()
		}
		d.scanNext()

	case scanBeginLiteral:
		// All bytes inside literal return scanContinue op code.
		start := d.readIndex()
		d.rescanLiteral()

		if v.IsValid() {
			if err := d.literalStore(d.data[start:d.readIndex()], v, false); err != nil {
				return err
			}
		}
	}
	return nil
}

type unquotedValue struct{}

// valueQuoted is like value but decodes a
// quoted string literal or literal null into an interface value.
// If it finds anything other than a quoted string literal or null,
// valueQuoted returns unquotedValue{}.
func (d *decodeState) valueQuoted() any {
	switch d.opcode {
	default:
		panic(phasePanicMsg)

	case scanBeginArray, scanBeginObject:
		d.skip()
		d.scanNext()

	case scanBeginLiteral:
		v := d.literalInterface()
		switch v.(type) {
		case nil, string:
			return v
		}
	}
	return unquotedValue{}
}

// indirect walks down v allocating pointers as needed,
// until it gets to a non-pointer.
// If it encounters an Unmarshaler, indirect stops and returns that.
// If decodingNull is true, indirect stops at the first settable pointer so it
// can be set to nil.
func indirect(v reflect.Value, decodingNull bool) (Unmarshaler, encoding.TextUnmarshaler, reflect.Value) {
	// Issue #24153 indicates that it is generally not a guaranteed property
	// that you may round-trip a reflect.Value by calling Value.Addr().Elem()
	// and expect the value to still be settable for values derived from
	// unexported embedded struct fields.
	//
	// The logic below effectively does this when it first addresses the value
	// (to satisfy possible pointer methods) and continues to dereference
	// subsequent pointers as necessary.
	//
	// After the first round-trip, we set v back to the original value to
	// preserve the original RW flags contained in reflect.Value.
	v0 := v
	haveAddr := false

	// If v is a named type and is addressable,
	// start with its address, so that if the type has pointer methods,
	// we find them.
	if v.Kind() != reflect.Pointer && v.Type().Name() != "" && v.CanAddr() {
		haveAddr = true
		v = v.Addr()
	}
	for {
		// Load value from interface, but only if the result will be
		// usefully addressable.
		if v.Kind() == reflect.Interface && !v.IsNil() {
			e := v.Elem()
			if e.Kind() == reflect.Pointer && !e.IsNil() && (!decodingNull || e.Elem().Kind() == reflect.Pointer) {
				haveAddr = false
				v = e
				continue
			}
		}

		if v.Kind() != reflect.Pointer {
			break
		}

		if decodingNull && v.CanSet() {
			break
		}

		// Prevent infinite loop if v is an interface pointing to its own address:
		//     var v any
		//     v = &v
		if v.Elem().Kind() == reflect.Interface && v.Elem().Elem().Equal(v) {
			v = v.Elem()
			break
		}
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		if v.Type().NumMethod() > 0 && v.CanInterface() {
			if u, ok := v.Interface().(Unmarshaler); ok {
				return u, nil, reflect.Value{}
			}
			if !decodingNull {
				if u, ok := v.Interface().(encoding.TextUnmarshaler); ok {
					return nil, u, reflect.Value{}
				}
			}
		}

		if haveAddr {
			v = v0 // restore original value after round-trip Value.Addr().Elem()
			haveAddr = false
		} else {
			v = v.Elem()
		}
	}
	return nil, nil, v
}

// array consumes an array from d.data[d.off-1:], decoding into v.
// The first byte of the array ('[') has been read already.
func (d *decodeState) array(v reflect.Value) error {
	// Check for unmarshaler.
	u, ut, pv := indirect(v, false)
	if u != nil {
		start := d.readIndex()
		d.skip()
		return u.UnmarshalJSON(d.data[start:d.off])
	}
	if ut != nil {
		d.saveError(&UnmarshalTypeError{Value: "array", Type: v.Type(), Offset: int64(d.off)})
		d.skip()
		return nil
	}
	v = pv

	// Check type of target.
	switch v.Kind() {
	case reflect.Interface:
		if v.NumMethod() == 0 {
			// Decoding into nil interface? Switch to non-reflect code.
			ai := d.arrayInterface()
			v.Set(reflect.ValueOf(ai))
			return nil
		}
		// Otherwise it's invalid.
		fallthrough
	default:
		d.saveError(&UnmarshalTypeError{Value: "array", Type: v.Type(), Offset: int64(d.off)})
		d.skip()
		return nil
	case reflect.Array, reflect.Slice:
		break
	}

	i := 0
	for {
		// Look ahead for ] - can only happen on first iteration.
		d.scanWhile(scanSkipSpace)
		if d.opcode == scanEndArray {
			break
		}

		// Expand slice length, growing the slice if necessary.
		if v.Kind() == reflect.Slice {
			if i >= v.Cap() {
				v.Grow(1)
			}
			if i >= v.Len() {
				v.SetLen(i + 1)
			}
		}

		if i < v.Len() {
			// Decode into element.
			if err := d.value(v.Index(i)); err != nil {
				return err
			}
		} else {
			// Ran out of fixed array: skip.
			if err := d.value(reflect.Value{}); err != nil {
				return err
			}
		}
		i++

		// Next token must be , or ].
		if d.opcode == scanSkipSpace {
			d.scanWhile(scanSkipSpace)
		}
		if d.opcode == scanEndArray {
			break
		}
		if d.opcode != scanArrayValue {
			panic(phasePanicMsg)
		}
	}

	if i < v.Len() {
		if v.Kind() == reflect.Array {
			for ; i < v.Len(); i++ {
				v.Index(i).SetZero() // zero remainder of array
			}
		} else {
			v.SetLen(i) // truncate the slice
		}
	}
	if i == 0 && v.Kind() == reflect.Slice {
		v.Set(reflect.MakeSlice(v.Type(), 0, 0))
	}
	return nil
}

var nullLiteral = []byte("null")
var textUnmarshalerType = reflect.TypeFor[encoding.TextUnmarshaler]()

// object consumes an object from d.data[d.off-1:], decoding into v.
// The first byte ('{') of the object has been read already.
func (d *decodeState) object(v reflect.Value) error {
	// Check for unmarshaler.
	u, ut, pv := indirect(v, false)
	if u != nil {
		start := d.readIndex()
		d.skip()
		return u.UnmarshalJSON(d.data[start:d.off])
	}
	if ut != nil {
		d.saveError(&UnmarshalTypeError{Value: "object", Type: v.Type(), Offset: int64(d.off)})
		d.skip()
		return nil
	}
	v = pv
	t := v.Type()

	// Decoding into nil interface? Switch to non-reflect code.
	if v.Kind() == reflect.Interface && v.NumMethod() == 0 {
		oi := d.objectInterface()
		v.Set(reflect.ValueOf(oi))
		return nil
	}

	var fields structFields

	// Check type of target:
	//   struct or
	//   map[T1]T2 where T1 is string, an integer type,
	//             or an encoding.TextUnmarshaler
	switch v.Kind() {
	case reflect.Map:
		// Map key must either have string kind, have an integer kind,
		// or be an encoding.TextUnmarshaler.
		switch t.Key().Kind() {
		case reflect.String,
			reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		default:
			if !reflect.PointerTo(t.Key()).Implements(textUnmarshalerType) {
				d.saveError(&UnmarshalTypeError{Value: "object", Type: t, Offset: int64(d.off)})
				d.skip()
				return nil
			}
		}
		if v.IsNil() {
			v.Set(reflect.MakeMap(t))
		}
	case reflect.Struct:
		fields = cachedTypeFields(t)
		// ok
	default:
		d.saveError(&UnmarshalTypeError{Value: "object", Type: t, Offset: int64(d.off)})
		d.skip()
		return nil
	}

	var mapElem reflect.Value
	var origErrorContext errorContext
	if d.errorContext != nil {
		origErrorContext = *d.errorContext
	}

	for {
		// Read opening " of string key or closing }.
		d.scanWhile(scanSkipSpace)
		if d.opcode == scanEndObject {
			// closing } - can only happen on first iteration.
			break
		}
		if d.opcode != scanBeginLiteral {
			panic(phasePanicMsg)
		}

		// Read key.
		start := d.readIndex()
		d.rescanLiteral()
		item := d.data[start:d.readIndex()]
		key, ok := unquoteBytes(item)
		if !ok {
			panic(phasePanicMsg)
		}

		// Figure out field corresponding to key.
		var subv reflect.Value
		destring := false // whether the value is wrapped in a string to be decoded first

		if v.Kind() == reflect.Map {
			elemType := t.Elem()
			if !mapElem.IsValid() {
				mapElem = reflect.New(elemType).Elem()
			} else {
				mapElem.SetZero()
			}
			subv = mapElem
		} else {
			f := fields.byExactName[string(key)]
			if f == nil {
				f = fields.byFoldedName[string(foldName(key))]
			}
			if f != nil {
				subv = v
				destring = f.quoted
				if d.errorContext == nil {
					d.errorContext = new(errorContext)
				}
				for i, ind := range f.index {
					if subv.Kind() == reflect.Pointer {
						if subv.IsNil() {
							// If a struct embeds a pointer to an unexported type,
							// it is not possible to set a newly allocated value
							// since the field is unexported.
							//
							// See https://golang.org/issue/21357
							if !subv.CanSet() {
								d.saveError(fmt.Errorf("json: cannot set embedded pointer to unexported struct: %v", subv.Type().Elem()))
								// Invalidate subv to ensure d.value(subv) skips over
								// the JSON value without assigning it to subv.
								subv = reflect.Value{}
								destring = false
								break
							}
							subv.Set(reflect.New(subv.Type().Elem()))
						}
						subv = subv.Elem()
					}
					if i < len(f.index)-1 {
						d.errorContext.FieldStack = append(
							d.errorContext.FieldStack,
							subv.Type().Field(ind).Name,
						)
					}
					subv = subv.Field(ind)
				}
				d.errorContext.Struct = t
				d.errorContext.FieldStack = append(d.errorContext.FieldStack, f.name)
			} else if d.disallowUnknownFields {
				d.saveError(fmt.Errorf("json: unknown field %q", key))
			}
		}

		// Read : before value.
		if d.opcode == scanSkipSpace {
			d.scanWhile(scanSkipSpace)
		}
		if d.opcode != scanObjectKey {
			panic(phasePanicMsg)
		}
		d.scanWhile(scanSkipSpace)

		if destring {
			switch qv := d.valueQuoted().(type) {
			case nil:
				if err := d.literalStore(nullLiteral, subv, false); err != nil {
					return err
				}
			case string:
				if err := d.literalStore([]byte(qv), subv, true); err != nil {
					return err
				}
			default:
				d.saveError(fmt.Errorf("json: invalid use of ,string struct tag, trying to unmarshal unquoted value into %v", subv.Type()))
			}
		} else {
			if err := d.value(subv); err != nil {
				return err
			}
		}

		// Write value back to map;
		// if using struct, subv points into struct already.
		if v.Kind() == reflect.Map {
			kt := t.Key()
			var kv reflect.Value
			if reflect.PointerTo(kt).Implements(textUnmarshalerType) {
				kv = reflect.New(kt)
				if err := d.literalStore(item, kv, true); err != nil {
					return err
				}
				kv = kv.Elem()
			} else {
				switch kt.Kind() {
				case reflect.String:
					kv = reflect.New(kt).Elem()
					kv.SetString(string(key))
				case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
					s := string(key)
					n, err := strconv.ParseInt(s, 10, 64)
					if err != nil || kt.OverflowInt(n) {
						d.saveError(&UnmarshalTypeError{Value: "number " + s, Type: kt, Offset: int64(start + 1)})
						break
					}
					kv = reflect.New(kt).Elem()
					kv.SetInt(n)
				case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
					s := string(key)
					n, err := strconv.ParseUint(s, 10, 64)
					if err != nil || kt.OverflowUint(n) {
						d.saveError(&UnmarshalTypeError{Value: "number " + s, Type: kt, Offset: int64(start + 1)})
						break
					}
					kv = reflect.New(kt).Elem()
					kv.SetUint(n)
				default:
					panic("json: Unexpected key type") // should never occur
				}
			}
			if kv.IsValid() {
				v.SetMapIndex(kv, subv)
			}
		}

		// Next token must be , or }.
		if d.opcode == scanSkipSpace {
			d.scanWhile(scanSkipSpace)
		}
		if d.errorContext != nil {
			// Reset errorContext to its original state.
			// Keep the same underlying array for FieldStack, to reuse the
			// space and avoid unnecessary allocs.
			d.errorContext.FieldStack = d.errorContext.FieldStack[:len(origErrorContext.FieldStack)]
			d.errorContext.Struct = origErrorContext.Struct
		}
		if d.opcode == scanEndObject {
			break
		}
		if d.opcode != scanObjectValue {
			panic(phasePanicMsg)
		}
	}
	return nil
}

// convertNumber converts the number literal s to a float64 or a Number
// depending on the setting of d.useNumber.
func (d *decodeState) convertNumber(s string) (any, error) {
	if d.useNumber {
		return Number(s), nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil, &UnmarshalTypeError{Value: "number " + s, Type: reflect.TypeFor[float64](), Offset: int64(d.off)}
	}
	return f, nil
}

var numberType = reflect.TypeFor[Number]()

// literalStore decodes a literal stored in item into v.
//
// fromQuoted indicates whether this literal came from unwrapping a
// string from the ",string" struct tag option. this is used only to
// produce more helpful error messages.
func (d *decodeState) literalStore(item []byte, v reflect.Value, fromQuoted bool) error {
	// Check for unmarshaler.
	if len(item) == 0 {
		// Empty string given.
		d.saveError(fmt.Errorf("json: invalid use of ,string struct tag, trying to unmarshal %q into %v", item, v.Type()))
		return nil
	}
	isNull := item[0] == 'n' // null
	u, ut, pv := indirect(v, isNull)
	if u != nil {
		return u.UnmarshalJSON(item)
	}
	if ut != nil {
		if item[0] != '"' {
			if fromQuoted {
				d.saveError(fmt.Errorf("json: invalid use of ,string struct tag, trying to unmarshal %q into %v", item, v.Type()))
				return nil
			}
			val := "number"
			switch item[0] {
			case 'n':
				val = "null"
			case 't', 'f':
				val = "bool"
			}
			d.saveError(&UnmarshalTypeError{Value: val, Type: v.Type(), Offset: int64(d.readIndex())})
			return nil
		}
		s, ok := unquoteBytes(item)
		if !ok {
			if fromQuoted {
				return fmt.Errorf("json: invalid use of ,string struct tag, trying to unmarshal %q into %v", item, v.Type())
			}
			panic(phasePanicMsg)
		}
		return ut.UnmarshalText(s)
	}

	v = pv

	switch c := item[0]; c {
	case 'n': // null
		// The main parser checks that only true and false can reach here,
		// but if this was a quoted string input, it could be anything.
		if fromQuoted && string(item) != "null" {
			d.saveError(fmt.Errorf("json: invalid use of ,string struct tag, trying to unmarshal %q into %v", item, v.Type()))
			break
		}
		switch v.Kind() {
		case reflect.Interface, reflect.Pointer, reflect.Map, reflect.Slice:
			v.SetZero()
			// otherwise, ignore null for primitives/string
		}
	case 't', 'f': // true, false
		value := item[0] == 't'
		// The main parser checks that only true and false can reach here,
		// but if this was a quoted string input, it could be anything.
		if fromQuoted && string(item) != "true" && string(item) != "false" {
			d.saveError(fmt.Errorf("json: invalid use of ,string struct tag, trying to unmarshal %q into %v", item, v.Type()))
			break
		}
		switch v.Kind() {
		default:
			if fromQuoted {
				d.saveError(fmt.Errorf("json: invalid use of ,string struct tag, trying to unmarshal %q into %v", item, v.Type()))
			} else {
				d.saveError(&UnmarshalTypeError{Value: "bool", Type: v.Type(), Offset: int64(d.readIndex())})
			}
		case reflect.Bool:
			v.SetBool(value)
		case reflect.Interface:
			if v.NumMethod() == 0 {
				v.Set(reflect.ValueOf(value))
			} else {
				d.saveError(&UnmarshalTypeError{Value: "bool", Type: v.Type(), Offset: int64(d.readIndex())})
			}
		}

	case '"': // string
		s, ok := unquoteBytes(item)
		if !ok {
			if fromQuoted {
				return fmt.Errorf("json: invalid use of ,string struct tag, trying to unmarshal %q into %v", item, v.Type())
			}
			panic(phasePanicMsg)
		}
		switch v.Kind() {
		default:
			d.saveError(&UnmarshalTypeError{Value: "string", Type: v.Type(), Offset: int64(d.readIndex())})
		case reflect.Slice:
			if v.Type().Elem().Kind() != reflect.Uint8 {
				d.saveError(&UnmarshalTypeError{Value: "string", Type: v.Type(), Offset: int64(d.readIndex())})
				break
			}
			b := make([]byte, base64.StdEncoding.DecodedLen(len(s)))
			n, err := base64.StdEncoding.Decode(b, s)
			if err != nil {
				d.saveError(err)
				break
			}
			v.SetBytes(b[:n])
		case reflect.String:
			t := string(s)
			if v.Type() == numberType && !isValidNumber(t) {
				return fmt.Errorf("json: invalid number literal, trying to unmarshal %q into Number", item)
			}
			v.SetString(t)
		case reflect.Interface:
			if v.NumMethod() == 0 {
				v.Set(reflect.ValueOf(string(s)))
			} else {
				d.saveError(&UnmarshalTypeError{Value: "string", Type: v.Type(), Offset: int64(d.readIndex())})
			}
		}

	default: // number
		if c != '-' && (c < '0' || c > '9') {
			if fromQuoted {
				return fmt.Errorf("json: invalid use of ,string struct tag, trying to unmarshal %q into %v", item, v.Type())
			}
			panic(phasePanicMsg)
		}
		switch v.Kind() {
		default:
			if v.Kind() == reflect.String && v.Type() == numberType {
				// s must be a valid number, because it's
				// already been tokenized.
				v.SetString(string(item))
				break
			}
			if fromQuoted {
				return fmt.Errorf("json: invalid use of ,string struct tag, trying to unmarshal %q into %v", item, v.Type())
			}
			d.saveError(&UnmarshalTypeError{Value: "number", Type: v.Type(), Offset: int64(d.readIndex())})
		case reflect.Interface:
			n, err := d.convertNumber(string(item))
			if err != nil {
				d.saveError(err)
				break
			}
			if v.NumMethod() != 0 {
				d.saveError(&UnmarshalTypeError{Value: "number", Type: v.Type(), Offset: int64(d.readIndex())})
				break
			}
			v.Set(reflect.ValueOf(n))

		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			n, err := strconv.ParseInt(string(item), 10, 64)
			if err != nil || v.OverflowInt(n) {
				d.saveError(&UnmarshalTypeError{Value: "number " + string(item), Type: v.Type(), Offset: int64(d.readIndex())})
				break
			}
			v.SetInt(n)

		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
			n, err := strconv.ParseUint(string(item), 10, 64)
			if err != nil || v.OverflowUint(n) {
				d.saveError(&UnmarshalTypeError{Value: "number " + string(item), Type: v.Type(), Offset: int64(d.readIndex())})
				break
			}
			v.SetUint(n)

		case reflect.Float32, reflect.Float64:
			n, err := strconv.ParseFloat(string(item), v.Type().Bits())
			if err != nil || v.OverflowFloat(n) {
				d.saveError(&UnmarshalTypeError{Value: "number " + string(item), Type: v.Type(), Offset: int64(d.readIndex())})
				break
			}
			v.SetFloat(n)
		}
	}
	return nil
}

// The xxxInterface routines build up a value to be stored
// in an empty interface. They are not strictly necessary,
// but they avoid the weight of reflection in this common case.

// valueInterface is like value but returns any.
func (d *decodeState) valueInterface() (val any) {
	switch d.opcode {
	default:
		panic(phasePanicMsg)
	case scanBeginArray:
		val = d.arrayInterface()
		d.scanNext()
	case scanBeginObject:
		val = d.objectInterface()
		d.scanNext()
	case scanBeginLiteral:
		val = d.literalInterface()
	}
	return
}

// arrayInterface is like array but returns []any.
func (d *decodeState) arrayInterface() []any {
	var v = make([]any, 0)
	for {
		// Look ahead for ] - can only happen on first iteration.
		d.scanWhile(scanSkipSpace)
		if d.opcode == scanEndArray {
			break
		}

		v = append(v, d.valueInterface())

		// Next token must be , or ].
		if d.opcode == scanSkipSpace {
			d.scanWhile(scanSkipSpace)
		}
		if d.opcode == scanEndArray {
			break
		}
		if d.opcode != scanArrayValue {
			panic(phasePanicMsg)
		}
	}
	return v
}

// objectInterface is like object but returns map[string]any.
func (d *decodeState) objectInterface() map[string]any {
	m := make(map[string]any)
	for {
		// Read opening " of string key or closing }.
		d.scanWhile(scanSkipSpace)
		if d.opcode == scanEndObject {
			// closing } - can only happen on first iteration.
			break
		}
		if d.opcode != scanBeginLiteral {
			panic(phasePanicMsg)
		}

		// Read string key.
		start := d.readIndex()
		d.rescanLiteral()
		item := d.data[start:d.readIndex()]
		key, ok := unquote(item)
		if !ok {
			panic(phasePanicMsg)
		}

		// Read : before value.
		if d.opcode == scanSkipSpace {
			d.scanWhile(scanSkipSpace)
		}
		if d.opcode != scanObjectKey {
			panic(phasePanicMsg)
		}
		d.scanWhile(scanSkipSpace)

		// Read value.
		m[key] = d.valueInterface()

		// Next token must be , or }.
		if d.opcode == scanSkipSpace {
			d.scanWhile(scanSkipSpace)
		}
		if d.opcode == scanEndObject {
			break
		}
		if d.opcode != scanObjectValue {
			panic(phasePanicMsg)
		}
	}
	return m
}

// literalInterface consumes and returns a literal from d.data[d.off-1:] and
// it reads the following byte ahead. The first byte of the literal has been
// read already (that's how the caller knows it's a literal).
func (d *decodeState)
"""




```