Response:
The user provided a segment of Go code from `go/src/encoding/json/encode.go` and asked for its functionality.

Here's a breakdown of the thought process to arrive at the answer:

1. **Identify the Core Purpose:** The package name `encoding/json` and the filename `encode.go` strongly suggest this code is responsible for *encoding* Go data structures into JSON format. The initial comments confirm this.

2. **Analyze Key Functions:**  The code immediately presents the `Marshal` and `MarshalIndent` functions. These are the primary entry points for users wanting to convert Go data to JSON.

3. **Examine `Marshal`'s Logic:** The comments and code within `Marshal` are crucial. They describe how different Go types are handled:
    * `Marshaler` interface: Custom JSON encoding.
    * `encoding.TextMarshaler`:  Custom text encoding as a JSON string.
    * Basic types (bool, numbers, strings): Standard JSON representation. Note the HTML escaping for strings.
    * Arrays and slices: JSON arrays (with special handling for `[]byte`).
    * Structs: JSON objects, respecting `json` tags for field names, `omitempty`, `omitzero`, and `string` options. Pay attention to the rules for embedded structs and field visibility.
    * Maps: JSON objects with sorted keys.
    * Pointers: Value pointed to (or `null` if nil).
    * Interfaces: Value contained (or `null` if nil).
    * Unsupported types (channels, complex, functions):  `UnsupportedTypeError`.
    * Cyclic data: Error.

4. **Analyze `MarshalIndent`:** This function clearly builds upon `Marshal` by adding indentation for better readability.

5. **Identify Helper Types and Functions:**  The code defines several helper types and functions that support the encoding process:
    * `Marshaler`, `UnsupportedTypeError`, `UnsupportedValueError`, `MarshalerError`: Error types related to the encoding process.
    * `encodeState`: Manages the encoding process, including a buffer and cycle detection.
    * `encoderFunc`:  A function type for encoding different Go types.
    * `valueEncoder`, `typeEncoder`, `newTypeEncoder`:  Functions for selecting the appropriate encoder based on the Go type.
    * Specific encoders (`boolEncoder`, `intEncoder`, `stringEncoder`, etc.): Implement the encoding logic for individual types.
    * `structEncoder`, `mapEncoder`, `sliceEncoder`, `arrayEncoder`, `ptrEncoder`:  Encoders for complex data structures.
    * `isEmptyValue`: Determines if a value is considered empty for `omitempty`.
    * `appendString`:  Handles string encoding with optional HTML escaping.
    * `isValidNumber`: Validates JSON number literals.
    * `typeFields`:  Extracts relevant struct fields for JSON encoding, respecting tags and visibility rules.

6. **Infer Overall Functionality:** Based on the analysis, the primary function of this code is to provide the core logic for converting Go values into their JSON representation, adhering to the JSON specification and providing options for customization via struct tags and interfaces.

7. **Illustrative Go Code Examples:**  Create simple Go structs and data structures and demonstrate how `Marshal` and `MarshalIndent` work, highlighting the effect of struct tags (renaming, `omitempty`, `string`). Include examples of custom Marshaler and TextMarshaler implementations.

8. **Code Reasoning with Input/Output:** For the struct tag examples, provide the input Go struct and the expected JSON output to illustrate the tag's effect.

9. **Identify Potential Pitfalls:** Think about common mistakes developers might make when using this package:
    * Forgetting about HTML escaping and its implications for web security.
    * Incorrectly using or misunderstanding the `omitempty` tag.
    * Being surprised by the handling of unexported fields.
    * Not knowing how to handle cyclic data structures.
    * Issues with custom `Marshaler` implementations.

10. **Summarize Functionality for Part 1:** Condense the analysis into a concise summary of the code's purpose.

**Self-Correction/Refinement during the process:**

* Initially, I might focus too much on individual functions. Realizing the overall goal is encoding helps to structure the analysis.
* While analyzing the struct tag handling, ensure to cover all the options (`omitempty`, `omitzero`, `string`, `-`, `-,`).
*  For the examples, choose data types and scenarios that clearly demonstrate the specific feature being explained.
* When discussing potential pitfalls, provide concrete examples to illustrate the issue. For instance, a struct with an unexported field and its JSON representation.
*  Ensure the language used in the explanation is clear and accurate. Refer to the Go documentation and JSON specification when necessary.
这是一个 Go 语言 `encoding/json` 包中 `encode.go` 文件的一部分，其核心功能是实现 **将 Go 语言的数据结构编码（序列化）成 JSON 格式的字符串**。

**具体功能归纳如下：**

1. **提供 `Marshal` 函数:**  这是将 Go 语言值转换为 JSON 格式字节切片的主要入口点。它会递归地遍历传入的值，并根据值的类型进行相应的 JSON 编码。

2. **提供 `MarshalIndent` 函数:**  与 `Marshal` 类似，但会格式化输出的 JSON 字符串，使其更易读。可以指定前缀和缩进字符串。

3. **支持 `Marshaler` 接口:** 如果 Go 语言的类型实现了 `Marshaler` 接口，`Marshal` 会调用该类型的 `MarshalJSON` 方法来获取其 JSON 表示。这允许自定义类型的编码方式。

4. **支持 `encoding.TextMarshaler` 接口:** 如果类型没有实现 `Marshaler`，但实现了 `encoding.TextMarshaler` 接口，`Marshal` 会调用其 `MarshalText` 方法，并将返回的文本编码为 JSON 字符串。

5. **处理基本数据类型:**  定义了如何将 Go 的基本数据类型（如布尔值、整数、浮点数、字符串）编码为对应的 JSON 类型。

6. **处理复合数据类型:**
    * **数组和切片:** 编码为 JSON 数组。`[]byte` 类型会被编码为 Base64 编码的字符串。nil 切片编码为 `null`。
    * **结构体:** 编码为 JSON 对象。结构体的字段名会作为 JSON 对象的键。可以通过 `json` 标签来自定义键名和编码行为（例如，忽略字段、omitempty 等）。
    * **Map:** 编码为 JSON 对象。Map 的键必须是字符串、整数类型或实现了 `encoding.TextMarshaler` 接口。键会被排序后作为 JSON 对象的键。
    * **指针:** 编码为指针指向的值。nil 指针编码为 `null`。
    * **接口:** 编码为接口包含的值。nil 接口编码为 `null`。

7. **错误处理:**
    * **`UnsupportedTypeError`:** 当尝试编码不支持的类型（如 channel, complex, function）时返回。
    * **`UnsupportedValueError`:** 当尝试编码不支持的值（如 NaN, +/-Inf）时返回。
    * **`MarshalerError`:**  当调用 `Marshaler` 或 `encoding.TextMarshaler` 的方法时发生错误时返回。

8. **HTML 转义:**  为了安全地将 JSON 嵌入到 HTML `<script>` 标签中，默认会对字符串中的 `<`, `>`, `&`, `\u2028`, `\u2029` 等字符进行转义。

9. **循环引用检测:**  为了防止栈溢出，会检测编码过程中是否存在循环引用的数据结构，如果发现会返回错误。

10. **使用 `sync.Pool` 复用 `encodeState`:**  为了提高性能，使用 `sync.Pool` 来复用 `encodeState` 结构体，减少内存分配和垃圾回收的开销。

**基于以上分析，可以推理出这段代码是 Go 语言中用于将数据结构序列化成 JSON 字符串的核心实现。**

**Go 代码举例说明：**

假设我们有以下 Go 结构体：

```go
package main

import (
	"encoding/json"
	"fmt"
)

type Person struct {
	Name    string `json:"name"`
	Age     int    `json:"age,omitempty"`
	Hobbies []string `json:"hobbies,omitempty"`
	Address *Address `json:"address"`
}

type Address struct {
	City    string `json:"city"`
	ZipCode string `json:"zip_code"`
}

func main() {
	address := &Address{City: "Beijing", ZipCode: "100000"}
	person := Person{Name: "Alice", Address: address}

	// 使用 Marshal 编码
	jsonBytes, err := json.Marshal(person)
	if err != nil {
		fmt.Println("编码错误:", err)
		return
	}
	fmt.Println("Marshal 编码结果:", string(jsonBytes))

	// 使用 MarshalIndent 编码
	jsonIndentBytes, err := json.MarshalIndent(person, "", "  ")
	if err != nil {
		fmt.Println("编码错误:", err)
		return
	}
	fmt.Println("MarshalIndent 编码结果:\n", string(jsonIndentBytes))
}
```

**假设的输入与输出：**

**输入 (Go 结构体 `person`)：**

```go
Person{
    Name: "Alice",
    Age: 0,
    Hobbies: nil,
    Address: &Address{City: "Beijing", ZipCode: "100000"},
}
```

**输出 (使用 `json.Marshal`)：**

```json
{"name":"Alice","address":{"city":"Beijing","zip_code":"100000"}}
```

**输出 (使用 `json.MarshalIndent`)：**

```json
{
  "name": "Alice",
  "address": {
    "city": "Beijing",
    "zip_code": "100000"
  }
}
```

**代码推理：**

* `person.Age` 的值为 0，由于 `json:"age,omitempty"` 标签，该字段被省略。
* `person.Hobbies` 的值为 nil，由于 `json:"hobbies,omitempty"` 标签，该字段也被省略。
* 结构体字段的名称会根据 `json` 标签进行映射，例如 `Name` 字段映射为 JSON 的 `name` 键。
* 嵌套的结构体 `Address` 会被递归编码为 JSON 对象。

**使用者易犯错的点：**

1. **忽略 HTML 转义导致安全问题：** 如果将用户输入的数据直接编码到 JSON 中并嵌入到网页中，可能会导致 XSS 攻击。

   ```go
   package main

   import (
       "encoding/json"
       "fmt"
   )

   type Message struct {
       Content string `json:"content"`
   }

   func main() {
       // 用户输入包含 HTML 标签
       userInput := "<script>alert('XSS')</script>"
       msg := Message{Content: userInput}

       jsonBytes, _ := json.Marshal(msg)
       fmt.Println(string(jsonBytes)) // 输出: {"content":"\u003cscript\u003ealert('XSS')\u003c/script\u003e"}
   }
   ```

   在上面的例子中，`Marshal` 默认转义了 `<` 和 `>`，防止了直接执行脚本。但是，如果使用 `Encoder` 并禁用了 HTML 转义，就会存在安全风险。

2. **误解 `omitempty` 的作用：**  认为所有类型的零值都会被忽略。实际上，`omitempty` 对不同类型的 "空值" 有不同的定义，例如，数值类型的 0 会被忽略，但指针类型的 nil 会被忽略，而空字符串、空切片、空 Map 也会被忽略。

   ```go
   package main

   import (
       "encoding/json"
       "fmt"
   )

   type Data struct {
       Count int      `json:"count,omitempty"`
       Items []string `json:"items,omitempty"`
       Name  string   `json:"name,omitempty"`
       Ptr   *int     `json:"ptr,omitempty"`
   }

   func main() {
       data := Data{Count: 0, Items: []string{}, Name: "", Ptr: nil}
       jsonBytes, _ := json.Marshal(data)
       fmt.Println(string(jsonBytes)) // 输出: {"count":0,"items":[],"name":""}
   }
   ```

   可以看到，虽然 `Count` 是 0，`Items` 是空切片，`Name` 是空字符串，但由于 `omitempty` 的定义，它们仍然出现在 JSON 输出中。只有 `Ptr` 是 nil，才被忽略了。

**总结 `encode.go` 的功能（第 1 部分）：**

这部分代码主要实现了将 Go 语言的各种数据类型编码成 JSON 格式字符串的核心功能，包括 `Marshal` 和 `MarshalIndent` 两个主要的入口函数，并支持通过 `Marshaler` 和 `encoding.TextMarshaler` 接口进行自定义编码。它处理了基本类型、复合类型以及错误情况，并默认进行了 HTML 转义以提高安全性。同时，使用了 `sync.Pool` 来优化性能。

### 提示词
```
这是路径为go/src/encoding/json/encode.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package json implements encoding and decoding of JSON as defined in
// RFC 7159. The mapping between JSON and Go values is described
// in the documentation for the Marshal and Unmarshal functions.
//
// See "JSON and Go" for an introduction to this package:
// https://golang.org/doc/articles/json_and_go.html
package json

import (
	"bytes"
	"cmp"
	"encoding"
	"encoding/base64"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
	_ "unsafe" // for linkname
)

// Marshal returns the JSON encoding of v.
//
// Marshal traverses the value v recursively.
// If an encountered value implements [Marshaler]
// and is not a nil pointer, Marshal calls [Marshaler.MarshalJSON]
// to produce JSON. If no [Marshaler.MarshalJSON] method is present but the
// value implements [encoding.TextMarshaler] instead, Marshal calls
// [encoding.TextMarshaler.MarshalText] and encodes the result as a JSON string.
// The nil pointer exception is not strictly necessary
// but mimics a similar, necessary exception in the behavior of
// [Unmarshaler.UnmarshalJSON].
//
// Otherwise, Marshal uses the following type-dependent default encodings:
//
// Boolean values encode as JSON booleans.
//
// Floating point, integer, and [Number] values encode as JSON numbers.
// NaN and +/-Inf values will return an [UnsupportedValueError].
//
// String values encode as JSON strings coerced to valid UTF-8,
// replacing invalid bytes with the Unicode replacement rune.
// So that the JSON will be safe to embed inside HTML <script> tags,
// the string is encoded using [HTMLEscape],
// which replaces "<", ">", "&", U+2028, and U+2029 are escaped
// to "\u003c","\u003e", "\u0026", "\u2028", and "\u2029".
// This replacement can be disabled when using an [Encoder],
// by calling [Encoder.SetEscapeHTML](false).
//
// Array and slice values encode as JSON arrays, except that
// []byte encodes as a base64-encoded string, and a nil slice
// encodes as the null JSON value.
//
// Struct values encode as JSON objects.
// Each exported struct field becomes a member of the object, using the
// field name as the object key, unless the field is omitted for one of the
// reasons given below.
//
// The encoding of each struct field can be customized by the format string
// stored under the "json" key in the struct field's tag.
// The format string gives the name of the field, possibly followed by a
// comma-separated list of options. The name may be empty in order to
// specify options without overriding the default field name.
//
// The "omitempty" option specifies that the field should be omitted
// from the encoding if the field has an empty value, defined as
// false, 0, a nil pointer, a nil interface value, and any array,
// slice, map, or string of length zero.
//
// As a special case, if the field tag is "-", the field is always omitted.
// Note that a field with name "-" can still be generated using the tag "-,".
//
// Examples of struct field tags and their meanings:
//
//	// Field appears in JSON as key "myName".
//	Field int `json:"myName"`
//
//	// Field appears in JSON as key "myName" and
//	// the field is omitted from the object if its value is empty,
//	// as defined above.
//	Field int `json:"myName,omitempty"`
//
//	// Field appears in JSON as key "Field" (the default), but
//	// the field is skipped if empty.
//	// Note the leading comma.
//	Field int `json:",omitempty"`
//
//	// Field is ignored by this package.
//	Field int `json:"-"`
//
//	// Field appears in JSON as key "-".
//	Field int `json:"-,"`
//
// The "omitzero" option specifies that the field should be omitted
// from the encoding if the field has a zero value, according to rules:
//
// 1) If the field type has an "IsZero() bool" method, that will be used to
// determine whether the value is zero.
//
// 2) Otherwise, the value is zero if it is the zero value for its type.
//
// If both "omitempty" and "omitzero" are specified, the field will be omitted
// if the value is either empty or zero (or both).
//
// The "string" option signals that a field is stored as JSON inside a
// JSON-encoded string. It applies only to fields of string, floating point,
// integer, or boolean types. This extra level of encoding is sometimes used
// when communicating with JavaScript programs:
//
//	Int64String int64 `json:",string"`
//
// The key name will be used if it's a non-empty string consisting of
// only Unicode letters, digits, and ASCII punctuation except quotation
// marks, backslash, and comma.
//
// Embedded struct fields are usually marshaled as if their inner exported fields
// were fields in the outer struct, subject to the usual Go visibility rules amended
// as described in the next paragraph.
// An anonymous struct field with a name given in its JSON tag is treated as
// having that name, rather than being anonymous.
// An anonymous struct field of interface type is treated the same as having
// that type as its name, rather than being anonymous.
//
// The Go visibility rules for struct fields are amended for JSON when
// deciding which field to marshal or unmarshal. If there are
// multiple fields at the same level, and that level is the least
// nested (and would therefore be the nesting level selected by the
// usual Go rules), the following extra rules apply:
//
// 1) Of those fields, if any are JSON-tagged, only tagged fields are considered,
// even if there are multiple untagged fields that would otherwise conflict.
//
// 2) If there is exactly one field (tagged or not according to the first rule), that is selected.
//
// 3) Otherwise there are multiple fields, and all are ignored; no error occurs.
//
// Handling of anonymous struct fields is new in Go 1.1.
// Prior to Go 1.1, anonymous struct fields were ignored. To force ignoring of
// an anonymous struct field in both current and earlier versions, give the field
// a JSON tag of "-".
//
// Map values encode as JSON objects. The map's key type must either be a
// string, an integer type, or implement [encoding.TextMarshaler]. The map keys
// are sorted and used as JSON object keys by applying the following rules,
// subject to the UTF-8 coercion described for string values above:
//   - keys of any string type are used directly
//   - keys that implement [encoding.TextMarshaler] are marshaled
//   - integer keys are converted to strings
//
// Pointer values encode as the value pointed to.
// A nil pointer encodes as the null JSON value.
//
// Interface values encode as the value contained in the interface.
// A nil interface value encodes as the null JSON value.
//
// Channel, complex, and function values cannot be encoded in JSON.
// Attempting to encode such a value causes Marshal to return
// an [UnsupportedTypeError].
//
// JSON cannot represent cyclic data structures and Marshal does not
// handle them. Passing cyclic structures to Marshal will result in
// an error.
func Marshal(v any) ([]byte, error) {
	e := newEncodeState()
	defer encodeStatePool.Put(e)

	err := e.marshal(v, encOpts{escapeHTML: true})
	if err != nil {
		return nil, err
	}
	buf := append([]byte(nil), e.Bytes()...)

	return buf, nil
}

// MarshalIndent is like [Marshal] but applies [Indent] to format the output.
// Each JSON element in the output will begin on a new line beginning with prefix
// followed by one or more copies of indent according to the indentation nesting.
func MarshalIndent(v any, prefix, indent string) ([]byte, error) {
	b, err := Marshal(v)
	if err != nil {
		return nil, err
	}
	b2 := make([]byte, 0, indentGrowthFactor*len(b))
	b2, err = appendIndent(b2, b, prefix, indent)
	if err != nil {
		return nil, err
	}
	return b2, nil
}

// Marshaler is the interface implemented by types that
// can marshal themselves into valid JSON.
type Marshaler interface {
	MarshalJSON() ([]byte, error)
}

// An UnsupportedTypeError is returned by [Marshal] when attempting
// to encode an unsupported value type.
type UnsupportedTypeError struct {
	Type reflect.Type
}

func (e *UnsupportedTypeError) Error() string {
	return "json: unsupported type: " + e.Type.String()
}

// An UnsupportedValueError is returned by [Marshal] when attempting
// to encode an unsupported value.
type UnsupportedValueError struct {
	Value reflect.Value
	Str   string
}

func (e *UnsupportedValueError) Error() string {
	return "json: unsupported value: " + e.Str
}

// Before Go 1.2, an InvalidUTF8Error was returned by [Marshal] when
// attempting to encode a string value with invalid UTF-8 sequences.
// As of Go 1.2, [Marshal] instead coerces the string to valid UTF-8 by
// replacing invalid bytes with the Unicode replacement rune U+FFFD.
//
// Deprecated: No longer used; kept for compatibility.
type InvalidUTF8Error struct {
	S string // the whole string value that caused the error
}

func (e *InvalidUTF8Error) Error() string {
	return "json: invalid UTF-8 in string: " + strconv.Quote(e.S)
}

// A MarshalerError represents an error from calling a
// [Marshaler.MarshalJSON] or [encoding.TextMarshaler.MarshalText] method.
type MarshalerError struct {
	Type       reflect.Type
	Err        error
	sourceFunc string
}

func (e *MarshalerError) Error() string {
	srcFunc := e.sourceFunc
	if srcFunc == "" {
		srcFunc = "MarshalJSON"
	}
	return "json: error calling " + srcFunc +
		" for type " + e.Type.String() +
		": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *MarshalerError) Unwrap() error { return e.Err }

const hex = "0123456789abcdef"

// An encodeState encodes JSON into a bytes.Buffer.
type encodeState struct {
	bytes.Buffer // accumulated output

	// Keep track of what pointers we've seen in the current recursive call
	// path, to avoid cycles that could lead to a stack overflow. Only do
	// the relatively expensive map operations if ptrLevel is larger than
	// startDetectingCyclesAfter, so that we skip the work if we're within a
	// reasonable amount of nested pointers deep.
	ptrLevel uint
	ptrSeen  map[any]struct{}
}

const startDetectingCyclesAfter = 1000

var encodeStatePool sync.Pool

func newEncodeState() *encodeState {
	if v := encodeStatePool.Get(); v != nil {
		e := v.(*encodeState)
		e.Reset()
		if len(e.ptrSeen) > 0 {
			panic("ptrEncoder.encode should have emptied ptrSeen via defers")
		}
		e.ptrLevel = 0
		return e
	}
	return &encodeState{ptrSeen: make(map[any]struct{})}
}

// jsonError is an error wrapper type for internal use only.
// Panics with errors are wrapped in jsonError so that the top-level recover
// can distinguish intentional panics from this package.
type jsonError struct{ error }

func (e *encodeState) marshal(v any, opts encOpts) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if je, ok := r.(jsonError); ok {
				err = je.error
			} else {
				panic(r)
			}
		}
	}()
	e.reflectValue(reflect.ValueOf(v), opts)
	return nil
}

// error aborts the encoding by panicking with err wrapped in jsonError.
func (e *encodeState) error(err error) {
	panic(jsonError{err})
}

func isEmptyValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64,
		reflect.Interface, reflect.Pointer:
		return v.IsZero()
	}
	return false
}

func (e *encodeState) reflectValue(v reflect.Value, opts encOpts) {
	valueEncoder(v)(e, v, opts)
}

type encOpts struct {
	// quoted causes primitive fields to be encoded inside JSON strings.
	quoted bool
	// escapeHTML causes '<', '>', and '&' to be escaped in JSON strings.
	escapeHTML bool
}

type encoderFunc func(e *encodeState, v reflect.Value, opts encOpts)

var encoderCache sync.Map // map[reflect.Type]encoderFunc

func valueEncoder(v reflect.Value) encoderFunc {
	if !v.IsValid() {
		return invalidValueEncoder
	}
	return typeEncoder(v.Type())
}

func typeEncoder(t reflect.Type) encoderFunc {
	if fi, ok := encoderCache.Load(t); ok {
		return fi.(encoderFunc)
	}

	// To deal with recursive types, populate the map with an
	// indirect func before we build it. This type waits on the
	// real func (f) to be ready and then calls it. This indirect
	// func is only used for recursive types.
	var (
		wg sync.WaitGroup
		f  encoderFunc
	)
	wg.Add(1)
	fi, loaded := encoderCache.LoadOrStore(t, encoderFunc(func(e *encodeState, v reflect.Value, opts encOpts) {
		wg.Wait()
		f(e, v, opts)
	}))
	if loaded {
		return fi.(encoderFunc)
	}

	// Compute the real encoder and replace the indirect func with it.
	f = newTypeEncoder(t, true)
	wg.Done()
	encoderCache.Store(t, f)
	return f
}

var (
	marshalerType     = reflect.TypeFor[Marshaler]()
	textMarshalerType = reflect.TypeFor[encoding.TextMarshaler]()
)

// newTypeEncoder constructs an encoderFunc for a type.
// The returned encoder only checks CanAddr when allowAddr is true.
func newTypeEncoder(t reflect.Type, allowAddr bool) encoderFunc {
	// If we have a non-pointer value whose type implements
	// Marshaler with a value receiver, then we're better off taking
	// the address of the value - otherwise we end up with an
	// allocation as we cast the value to an interface.
	if t.Kind() != reflect.Pointer && allowAddr && reflect.PointerTo(t).Implements(marshalerType) {
		return newCondAddrEncoder(addrMarshalerEncoder, newTypeEncoder(t, false))
	}
	if t.Implements(marshalerType) {
		return marshalerEncoder
	}
	if t.Kind() != reflect.Pointer && allowAddr && reflect.PointerTo(t).Implements(textMarshalerType) {
		return newCondAddrEncoder(addrTextMarshalerEncoder, newTypeEncoder(t, false))
	}
	if t.Implements(textMarshalerType) {
		return textMarshalerEncoder
	}

	switch t.Kind() {
	case reflect.Bool:
		return boolEncoder
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return intEncoder
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return uintEncoder
	case reflect.Float32:
		return float32Encoder
	case reflect.Float64:
		return float64Encoder
	case reflect.String:
		return stringEncoder
	case reflect.Interface:
		return interfaceEncoder
	case reflect.Struct:
		return newStructEncoder(t)
	case reflect.Map:
		return newMapEncoder(t)
	case reflect.Slice:
		return newSliceEncoder(t)
	case reflect.Array:
		return newArrayEncoder(t)
	case reflect.Pointer:
		return newPtrEncoder(t)
	default:
		return unsupportedTypeEncoder
	}
}

func invalidValueEncoder(e *encodeState, v reflect.Value, _ encOpts) {
	e.WriteString("null")
}

func marshalerEncoder(e *encodeState, v reflect.Value, opts encOpts) {
	if v.Kind() == reflect.Pointer && v.IsNil() {
		e.WriteString("null")
		return
	}
	m, ok := v.Interface().(Marshaler)
	if !ok {
		e.WriteString("null")
		return
	}
	b, err := m.MarshalJSON()
	if err == nil {
		e.Grow(len(b))
		out := e.AvailableBuffer()
		out, err = appendCompact(out, b, opts.escapeHTML)
		e.Buffer.Write(out)
	}
	if err != nil {
		e.error(&MarshalerError{v.Type(), err, "MarshalJSON"})
	}
}

func addrMarshalerEncoder(e *encodeState, v reflect.Value, opts encOpts) {
	va := v.Addr()
	if va.IsNil() {
		e.WriteString("null")
		return
	}
	m := va.Interface().(Marshaler)
	b, err := m.MarshalJSON()
	if err == nil {
		e.Grow(len(b))
		out := e.AvailableBuffer()
		out, err = appendCompact(out, b, opts.escapeHTML)
		e.Buffer.Write(out)
	}
	if err != nil {
		e.error(&MarshalerError{v.Type(), err, "MarshalJSON"})
	}
}

func textMarshalerEncoder(e *encodeState, v reflect.Value, opts encOpts) {
	if v.Kind() == reflect.Pointer && v.IsNil() {
		e.WriteString("null")
		return
	}
	m, ok := v.Interface().(encoding.TextMarshaler)
	if !ok {
		e.WriteString("null")
		return
	}
	b, err := m.MarshalText()
	if err != nil {
		e.error(&MarshalerError{v.Type(), err, "MarshalText"})
	}
	e.Write(appendString(e.AvailableBuffer(), b, opts.escapeHTML))
}

func addrTextMarshalerEncoder(e *encodeState, v reflect.Value, opts encOpts) {
	va := v.Addr()
	if va.IsNil() {
		e.WriteString("null")
		return
	}
	m := va.Interface().(encoding.TextMarshaler)
	b, err := m.MarshalText()
	if err != nil {
		e.error(&MarshalerError{v.Type(), err, "MarshalText"})
	}
	e.Write(appendString(e.AvailableBuffer(), b, opts.escapeHTML))
}

func boolEncoder(e *encodeState, v reflect.Value, opts encOpts) {
	b := e.AvailableBuffer()
	b = mayAppendQuote(b, opts.quoted)
	b = strconv.AppendBool(b, v.Bool())
	b = mayAppendQuote(b, opts.quoted)
	e.Write(b)
}

func intEncoder(e *encodeState, v reflect.Value, opts encOpts) {
	b := e.AvailableBuffer()
	b = mayAppendQuote(b, opts.quoted)
	b = strconv.AppendInt(b, v.Int(), 10)
	b = mayAppendQuote(b, opts.quoted)
	e.Write(b)
}

func uintEncoder(e *encodeState, v reflect.Value, opts encOpts) {
	b := e.AvailableBuffer()
	b = mayAppendQuote(b, opts.quoted)
	b = strconv.AppendUint(b, v.Uint(), 10)
	b = mayAppendQuote(b, opts.quoted)
	e.Write(b)
}

type floatEncoder int // number of bits

func (bits floatEncoder) encode(e *encodeState, v reflect.Value, opts encOpts) {
	f := v.Float()
	if math.IsInf(f, 0) || math.IsNaN(f) {
		e.error(&UnsupportedValueError{v, strconv.FormatFloat(f, 'g', -1, int(bits))})
	}

	// Convert as if by ES6 number to string conversion.
	// This matches most other JSON generators.
	// See golang.org/issue/6384 and golang.org/issue/14135.
	// Like fmt %g, but the exponent cutoffs are different
	// and exponents themselves are not padded to two digits.
	b := e.AvailableBuffer()
	b = mayAppendQuote(b, opts.quoted)
	abs := math.Abs(f)
	fmt := byte('f')
	// Note: Must use float32 comparisons for underlying float32 value to get precise cutoffs right.
	if abs != 0 {
		if bits == 64 && (abs < 1e-6 || abs >= 1e21) || bits == 32 && (float32(abs) < 1e-6 || float32(abs) >= 1e21) {
			fmt = 'e'
		}
	}
	b = strconv.AppendFloat(b, f, fmt, -1, int(bits))
	if fmt == 'e' {
		// clean up e-09 to e-9
		n := len(b)
		if n >= 4 && b[n-4] == 'e' && b[n-3] == '-' && b[n-2] == '0' {
			b[n-2] = b[n-1]
			b = b[:n-1]
		}
	}
	b = mayAppendQuote(b, opts.quoted)
	e.Write(b)
}

var (
	float32Encoder = (floatEncoder(32)).encode
	float64Encoder = (floatEncoder(64)).encode
)

func stringEncoder(e *encodeState, v reflect.Value, opts encOpts) {
	if v.Type() == numberType {
		numStr := v.String()
		// In Go1.5 the empty string encodes to "0", while this is not a valid number literal
		// we keep compatibility so check validity after this.
		if numStr == "" {
			numStr = "0" // Number's zero-val
		}
		if !isValidNumber(numStr) {
			e.error(fmt.Errorf("json: invalid number literal %q", numStr))
		}
		b := e.AvailableBuffer()
		b = mayAppendQuote(b, opts.quoted)
		b = append(b, numStr...)
		b = mayAppendQuote(b, opts.quoted)
		e.Write(b)
		return
	}
	if opts.quoted {
		b := appendString(nil, v.String(), opts.escapeHTML)
		e.Write(appendString(e.AvailableBuffer(), b, false)) // no need to escape again since it is already escaped
	} else {
		e.Write(appendString(e.AvailableBuffer(), v.String(), opts.escapeHTML))
	}
}

// isValidNumber reports whether s is a valid JSON number literal.
//
// isValidNumber should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/bytedance/sonic
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname isValidNumber
func isValidNumber(s string) bool {
	// This function implements the JSON numbers grammar.
	// See https://tools.ietf.org/html/rfc7159#section-6
	// and https://www.json.org/img/number.png

	if s == "" {
		return false
	}

	// Optional -
	if s[0] == '-' {
		s = s[1:]
		if s == "" {
			return false
		}
	}

	// Digits
	switch {
	default:
		return false

	case s[0] == '0':
		s = s[1:]

	case '1' <= s[0] && s[0] <= '9':
		s = s[1:]
		for len(s) > 0 && '0' <= s[0] && s[0] <= '9' {
			s = s[1:]
		}
	}

	// . followed by 1 or more digits.
	if len(s) >= 2 && s[0] == '.' && '0' <= s[1] && s[1] <= '9' {
		s = s[2:]
		for len(s) > 0 && '0' <= s[0] && s[0] <= '9' {
			s = s[1:]
		}
	}

	// e or E followed by an optional - or + and
	// 1 or more digits.
	if len(s) >= 2 && (s[0] == 'e' || s[0] == 'E') {
		s = s[1:]
		if s[0] == '+' || s[0] == '-' {
			s = s[1:]
			if s == "" {
				return false
			}
		}
		for len(s) > 0 && '0' <= s[0] && s[0] <= '9' {
			s = s[1:]
		}
	}

	// Make sure we are at the end.
	return s == ""
}

func interfaceEncoder(e *encodeState, v reflect.Value, opts encOpts) {
	if v.IsNil() {
		e.WriteString("null")
		return
	}
	e.reflectValue(v.Elem(), opts)
}

func unsupportedTypeEncoder(e *encodeState, v reflect.Value, _ encOpts) {
	e.error(&UnsupportedTypeError{v.Type()})
}

type structEncoder struct {
	fields structFields
}

type structFields struct {
	list         []field
	byExactName  map[string]*field
	byFoldedName map[string]*field
}

func (se structEncoder) encode(e *encodeState, v reflect.Value, opts encOpts) {
	next := byte('{')
FieldLoop:
	for i := range se.fields.list {
		f := &se.fields.list[i]

		// Find the nested struct field by following f.index.
		fv := v
		for _, i := range f.index {
			if fv.Kind() == reflect.Pointer {
				if fv.IsNil() {
					continue FieldLoop
				}
				fv = fv.Elem()
			}
			fv = fv.Field(i)
		}

		if (f.omitEmpty && isEmptyValue(fv)) ||
			(f.omitZero && (f.isZero == nil && fv.IsZero() || (f.isZero != nil && f.isZero(fv)))) {
			continue
		}
		e.WriteByte(next)
		next = ','
		if opts.escapeHTML {
			e.WriteString(f.nameEscHTML)
		} else {
			e.WriteString(f.nameNonEsc)
		}
		opts.quoted = f.quoted
		f.encoder(e, fv, opts)
	}
	if next == '{' {
		e.WriteString("{}")
	} else {
		e.WriteByte('}')
	}
}

func newStructEncoder(t reflect.Type) encoderFunc {
	se := structEncoder{fields: cachedTypeFields(t)}
	return se.encode
}

type mapEncoder struct {
	elemEnc encoderFunc
}

func (me mapEncoder) encode(e *encodeState, v reflect.Value, opts encOpts) {
	if v.IsNil() {
		e.WriteString("null")
		return
	}
	if e.ptrLevel++; e.ptrLevel > startDetectingCyclesAfter {
		// We're a large number of nested ptrEncoder.encode calls deep;
		// start checking if we've run into a pointer cycle.
		ptr := v.UnsafePointer()
		if _, ok := e.ptrSeen[ptr]; ok {
			e.error(&UnsupportedValueError{v, fmt.Sprintf("encountered a cycle via %s", v.Type())})
		}
		e.ptrSeen[ptr] = struct{}{}
		defer delete(e.ptrSeen, ptr)
	}
	e.WriteByte('{')

	// Extract and sort the keys.
	var (
		sv  = make([]reflectWithString, v.Len())
		mi  = v.MapRange()
		err error
	)
	for i := 0; mi.Next(); i++ {
		if sv[i].ks, err = resolveKeyName(mi.Key()); err != nil {
			e.error(fmt.Errorf("json: encoding error for type %q: %q", v.Type().String(), err.Error()))
		}
		sv[i].v = mi.Value()
	}
	slices.SortFunc(sv, func(i, j reflectWithString) int {
		return strings.Compare(i.ks, j.ks)
	})

	for i, kv := range sv {
		if i > 0 {
			e.WriteByte(',')
		}
		e.Write(appendString(e.AvailableBuffer(), kv.ks, opts.escapeHTML))
		e.WriteByte(':')
		me.elemEnc(e, kv.v, opts)
	}
	e.WriteByte('}')
	e.ptrLevel--
}

func newMapEncoder(t reflect.Type) encoderFunc {
	switch t.Key().Kind() {
	case reflect.String,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
	default:
		if !t.Key().Implements(textMarshalerType) {
			return unsupportedTypeEncoder
		}
	}
	me := mapEncoder{typeEncoder(t.Elem())}
	return me.encode
}

func encodeByteSlice(e *encodeState, v reflect.Value, _ encOpts) {
	if v.IsNil() {
		e.WriteString("null")
		return
	}

	s := v.Bytes()
	b := e.AvailableBuffer()
	b = append(b, '"')
	b = base64.StdEncoding.AppendEncode(b, s)
	b = append(b, '"')
	e.Write(b)
}

// sliceEncoder just wraps an arrayEncoder, checking to make sure the value isn't nil.
type sliceEncoder struct {
	arrayEnc encoderFunc
}

func (se sliceEncoder) encode(e *encodeState, v reflect.Value, opts encOpts) {
	if v.IsNil() {
		e.WriteString("null")
		return
	}
	if e.ptrLevel++; e.ptrLevel > startDetectingCyclesAfter {
		// We're a large number of nested ptrEncoder.encode calls deep;
		// start checking if we've run into a pointer cycle.
		// Here we use a struct to memorize the pointer to the first element of the slice
		// and its length.
		ptr := struct {
			ptr any // always an unsafe.Pointer, but avoids a dependency on package unsafe
			len int
		}{v.UnsafePointer(), v.Len()}
		if _, ok := e.ptrSeen[ptr]; ok {
			e.error(&UnsupportedValueError{v, fmt.Sprintf("encountered a cycle via %s", v.Type())})
		}
		e.ptrSeen[ptr] = struct{}{}
		defer delete(e.ptrSeen, ptr)
	}
	se.arrayEnc(e, v, opts)
	e.ptrLevel--
}

func newSliceEncoder(t reflect.Type) encoderFunc {
	// Byte slices get special treatment; arrays don't.
	if t.Elem().Kind() == reflect.Uint8 {
		p := reflect.PointerTo(t.Elem())
		if !p.Implements(marshalerType) && !p.Implements(textMarshalerType) {
			return encodeByteSlice
		}
	}
	enc := sliceEncoder{newArrayEncoder(t)}
	return enc.encode
}

type arrayEncoder struct {
	elemEnc encoderFunc
}

func (ae arrayEncoder) encode(e *encodeState, v reflect.Value, opts encOpts) {
	e.WriteByte('[')
	n := v.Len()
	for i := 0; i < n; i++ {
		if i > 0 {
			e.WriteByte(',')
		}
		ae.elemEnc(e, v.Index(i), opts)
	}
	e.WriteByte(']')
}

func newArrayEncoder(t reflect.Type) encoderFunc {
	enc := arrayEncoder{typeEncoder(t.Elem())}
	return enc.encode
}

type ptrEncoder struct {
	elemEnc encoderFunc
}

func (pe ptrEncoder) encode(e *encodeState, v reflect.Value, opts encOpts) {
	if v.IsNil() {
		e.WriteString("null")
		return
	}
	if e.ptrLevel++; e.ptrLevel > startDetectingCyclesAfter {
		// We're a large number of nested ptrEncoder.encode calls deep;
		// start checking if we've run into a pointer cycle.
		ptr := v.Interface()
		if _, ok := e.ptrSeen[ptr]; ok {
			e.error(&UnsupportedValueError{v, fmt.Sprintf("encountered a cycle via %s", v.Type())})
		}
		e.ptrSeen[ptr] = struct{}{}
		defer delete(e.ptrSeen, ptr)
	}
	pe.elemEnc(e, v.Elem(), opts)
	e.ptrLevel--
}

func newPtrEncoder(t reflect.Type) encoderFunc {
	enc := ptrEncoder{typeEncoder(t.Elem())}
	return enc.encode
}

type condAddrEncoder struct {
	canAddrEnc, elseEnc encoderFunc
}

func (ce condAddrEncoder) encode(e *encodeState, v reflect.Value, opts encOpts) {
	if v.CanAddr() {
		ce.canAddrEnc(e, v, opts)
	} else {
		ce.elseEnc(e, v, opts)
	}
}

// newCondAddrEncoder returns an encoder that checks whether its value
// CanAddr and delegates to canAddrEnc if so, else to elseEnc.
func newCondAddrEncoder(canAddrEnc, elseEnc encoderFunc) encoderFunc {
	enc := condAddrEncoder{canAddrEnc: canAddrEnc, elseEnc: elseEnc}
	return enc.encode
}

func isValidTag(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case strings.ContainsRune("!#$%&()*+-./:;<=>?@[]^_{|}~ ", c):
			// Backslash and quote chars are reserved, but
			// otherwise any punctuation chars are allowed
			// in a tag name.
		case !unicode.IsLetter(c) && !unicode.IsDigit(c):
			return false
		}
	}
	return true
}

func typeByIndex(t reflect.Type, index []int) reflect.Type {
	for _, i := range index {
		if t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		t = t.Field(i).Type
	}
	return t
}

type reflectWithString struct {
	v  reflect.Value
	ks string
}

func resolveKeyName(k reflect.Value) (string, error) {
	if k.Kind() == reflect.String {
		return k.String(), nil
	}
	if tm, ok := k.Interface().(encoding.TextMarshaler); ok {
		if k.Kind() == reflect.Pointer && k.IsNil() {
			return "", nil
		}
		buf, err := tm.MarshalText()
		return string(buf), err
	}
	switch k.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(k.Int(), 10), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return strconv.FormatUint(k.Uint(), 10), nil
	}
	panic("unexpected map key type")
}

func appendString[Bytes []byte | string](dst []byte, src Bytes, escapeHTML bool) []byte {
	dst = append(dst, '"')
	start := 0
	for i := 0; i < len(src); {
		if b := src[i]; b < utf8.RuneSelf {
			if htmlSafeSet[b] || (!escapeHTML && safeSet[b]) {
				i++
				continue
			}
			dst = append(dst, src[start:i]...)
			switch b {
			case '\\', '"':
				dst = append(dst, '\\', b)
			case '\b':
				dst = append(dst, '\\', 'b')
			case '\f':
				dst = append(dst, '\\', 'f')
			case '\n':
				dst = append(dst, '\\', 'n')
			case '\r':
				dst = append(dst, '\\', 'r')
			case '\t':
				dst = append(dst, '\\', 't')
			default:
				// This encodes bytes < 0x20 except for \b, \f, \n, \r and \t.
				// If escapeHTML is set, it also escapes <, >, and &
				// because they can lead to security holes when
				// user-controlled strings are rendered into JSON
				// and served to some browsers.
				dst = append(dst, '\\', 'u', '0', '0', hex[b>>4], hex[b&0xF])
			}
			i++
			start = i
			continue
		}
		// TODO(https://go.dev/issue/56948): Use generic utf8 functionality.
		// For now, cast only a small portion of byte slices to a string
		// so that it can be stack allocated. This slows down []byte slightly
		// due to the extra copy, but keeps string performance roughly the same.
		n := len(src) - i
		if n > utf8.UTFMax {
			n = utf8.UTFMax
		}
		c, size := utf8.DecodeRuneInString(string(src[i : i+n]))
		if c == utf8.RuneError && size == 1 {
			dst = append(dst, src[start:i]...)
			dst = append(dst, `\ufffd`...)
			i += size
			start = i
			continue
		}
		// U+2028 is LINE SEPARATOR.
		// U+2029 is PARAGRAPH SEPARATOR.
		// They are both technically valid characters in JSON strings,
		// but don't work in JSONP, which has to be evaluated as JavaScript,
		// and can lead to security holes there. It is valid JSON to
		// escape them, so we do so unconditionally.
		// See https://en.wikipedia.org/wiki/JSON#Safety.
		if c == '\u2028' || c == '\u2029' {
			dst = append(dst, src[start:i]...)
			dst = append(dst, '\\', 'u', '2', '0', '2', hex[c&0xF])
			i += size
			start = i
			continue
		}
		i += size
	}
	dst = append(dst, src[start:]...)
	dst = append(dst, '"')
	return dst
}

// A field represents a single field found in a struct.
type field struct {
	name      string
	nameBytes []byte // []byte(name)

	nameNonEsc  string // `"` + name + `":`
	nameEscHTML string // `"` + HTMLEscape(name) + `":`

	tag       bool
	index     []int
	typ       reflect.Type
	omitEmpty bool
	omitZero  bool
	isZero    func(reflect.Value) bool
	quoted    bool

	encoder encoderFunc
}

type isZeroer interface {
	IsZero() bool
}

var isZeroerType = reflect.TypeFor[isZeroer]()

// typeFields returns a list of fields that JSON should recognize for the given type.
// The algorithm is breadth-first search over the set of structs to include - the top struct
// and then any reachable anonymous structs.
//
// typeFields should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/bytedance/sonic
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname typeFields
func typeFields(t reflect.Type) structFields {
	// Anonymous fields to explore at the current level and the next.
	current := []field{}
	next := []field{{typ: t}}

	// Count of queued names for current level and the next.
	var count, nextCount map[reflect.Type]int

	// Types already visited at an earlier level.
	visited := map[reflect.Type]bool{}

	// Fields found.
	var fields []field

	// Buffer to run appendHTMLEscape on field names.
	var nameEscBuf []byte

	for len(next) > 0 {
		current, next = next, current[:0]
		count, nextCount = nextCount, map[reflect.Type]int{}

		for _, f := range current {
			if visited[f.typ] {
				continue
			}
			visited[f.typ] = true

			// Scan f.typ for fields to include.
			for i := 0; i < f.typ.NumField(); i++ {
				sf := f.typ.Field(i)
				if sf.Anonymous {
					t := sf.Type
					if t.Kind() == reflect.Pointer {
						t = t.Elem()
					}
					if !sf.IsExported() && t.Kind() != reflect.Struct {
						// Ignore embedded fields of unexported non-struct types.
						continue
					}
					// Do not ignore embedded fields of unexported struct types
					// since they may have exported fields.
				} else if !sf.IsExported() {
					// Ignore unexported non-embedded fields.
					continue
				}
				tag := sf.Tag.Get("json")
				if tag == "-" {
					continue
				}
				name, opts := parseTag(tag)
				if !isValidTag(name) {
					name = ""
				}
				index := make([]int, len(f.index)+1)
				copy(index, f
```