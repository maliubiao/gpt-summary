Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The request asks for the functionality of the provided Go code, which is a part of a TOML encoder. The prompt specifically asks for the purpose, usage examples, potential pitfalls, and code reasoning with examples.

2. **Initial Scan and Keywords:**  Quickly scan the code for important keywords and structures: `package toml`, `import`, `type Encoder struct`, `func NewEncoder`, `func Encode`, `func safeEncode`, `func encode`, `switch rv.Kind()`, error handling (`errors.New`, `panic`), and helper functions like `eElement`, `eTable`, etc. These immediately suggest this code is responsible for converting Go data structures into TOML format.

3. **Identify the Core Functionality:** The `Encoder` struct and its methods (`NewEncoder`, `Encode`) are clearly the central components. `NewEncoder` sets up the encoder, and `Encode` is the entry point for the encoding process.

4. **Trace the Encoding Flow:**  Follow the execution path of the `Encode` function.
    * It takes an `interface{}` as input, meaning it can handle various Go data types.
    * It uses `reflect.ValueOf` to get the runtime representation of the input.
    * `eindirect` is used to dereference pointers and interfaces.
    * `safeEncode` wraps the core encoding logic with a `recover` to handle panics gracefully.
    * The `encode` function is the workhorse. It uses a `switch` statement based on the `reflect.Kind()` of the input value to handle different Go types.

5. **Analyze Type Handling:** The `switch` statement in `encode` is crucial. For each `case`:
    * **Primitive Types:**  `int`, `float`, `string`, `bool` are handled by `keyEqElement`, which writes the key-value pair directly.
    * **Arrays and Slices:**  Distinction between regular arrays/slices and "arrays of tables" (slices of structs/maps) is made. Regular arrays/slices are handled by `keyEqElement`, while arrays of tables use `eArrayOfTables`.
    * **Maps:** Handled by `eTable` and then `eMap`. Note the sorting of keys for deterministic output.
    * **Structs:** Handled by `eTable` and then `eStruct`. Pay attention to how struct fields (including anonymous fields and tags) are processed.
    * **Time and TextMarshaler:**  Special handling to ensure correct TOML formatting.
    * **Pointers and Interfaces:** Recursively handled by calling `encode` on the underlying value.

6. **Examine Helper Functions:**  Understand the purpose of functions like:
    * `eElement`: Encodes individual array elements.
    * `eArrayOrSliceElement`: Handles arrays/slices within arrays.
    * `eArrayOfTables`: Encodes arrays of tables (`[[table]]`).
    * `eTable`: Encodes tables (`[table]`).
    * `eMapOrStruct`: Dispatches to `eMap` or `eStruct`.
    * `eMap`: Encodes map types.
    * `eStruct`: Encodes struct types, handling tags.
    * `tomlTypeOfGo`: Determines the TOML type of a Go value.
    * `tomlArrayType`: Determines the element type of a TOML array and checks for validity.
    * `getOptions`: Parses `toml` struct tags.
    * `isZero`, `isEmpty`: Helper functions for `omitempty` and `omitzero` tags.
    * `newline`, `keyEqElement`, `wf`, `indentStr`: Formatting and output helpers.

7. **Infer Functionality and Provide Examples:** Based on the code analysis, formulate a concise description of the code's functionality: converting Go data structures to TOML. Then, create illustrative Go code examples demonstrating how to use the `Encoder` to encode different Go types (structs, maps, slices). Include expected TOML output.

8. **Identify Potential Pitfalls:** Look for error conditions and constraints in the code:
    * Mixed-type arrays (`errArrayMixedElementTypes`).
    * Nil elements in arrays (`errArrayNilElement`).
    * Non-string map keys (`errNonString`).
    * Invalid TOML keys (empty keys).
    * Limitations on nested structures (e.g., nested arrays of tables).
    * The importance of struct tags for controlling encoding. Create examples of common mistakes, such as forgetting tags or using incorrect tag names.

9. **Address Command-Line Arguments (if applicable):** The code doesn't seem to directly handle command-line arguments. It operates on Go data structures and writes to an `io.Writer`. State this explicitly.

10. **Structure the Answer:** Organize the findings logically with clear headings and explanations. Use code blocks for Go examples and TOML output. Use clear and concise language.

11. **Review and Refine:**  Read through the answer to ensure accuracy, completeness, and clarity. Check if all parts of the prompt have been addressed. Ensure the examples are correct and easy to understand. Make sure the language is natural and fluent in Chinese as requested. For instance, instead of just saying "handles structs," explain *how* it handles them (field names, tags, etc.).

By following these steps, we can effectively analyze the Go code and provide a comprehensive answer that addresses all aspects of the user's request. The iterative process of scanning, tracing, analyzing, and then synthesizing information is key to understanding complex code.
这段代码是 Go 语言 `toml` 包中用于将 Go 数据结构编码为 TOML 格式的实现。它定义了一个 `Encoder` 类型，负责将 Go 的值写入到 `io.Writer` 中，生成符合 TOML 规范的文本。

**功能列表:**

1. **创建 Encoder:** `NewEncoder(w io.Writer)` 函数创建一个新的 `Encoder` 实例，它将输出写入到提供的 `io.Writer`。你可以通过 `Indent` 字段自定义缩进。
2. **TOML 编码:** `Encode(v interface{}) error` 方法是编码的入口点。它接收一个 Go 的值（可以是结构体、map 等），并将其转换为 TOML 格式的字符串写入到 `Encoder` 关联的 `io.Writer`。
3. **支持多种 Go 数据类型:**  代码中 `encode` 和 `eElement` 等函数处理了多种 Go 的基本类型（int, float, string, bool），以及复合类型（array, slice, map, struct）。
4. **处理 time.Time 和 TextMarshaler:** 特殊处理了 `time.Time` 类型，将其格式化为 ISO8601 格式。同时，如果 Go 类型实现了 `encoding.TextMarshaler` 接口，则会调用其 `MarshalText` 方法进行编码。
5. **处理数组和切片:** 可以编码 Go 的数组和切片。对于元素类型相同的数组，会将其编码为 TOML 的数组。对于元素类型为结构体或 map 的切片，会将其编码为 TOML 的数组表格（Array of Tables）。
6. **处理 Map:** 可以编码 Go 的 map 类型。Map 的键必须是字符串类型。编码时，会按照键的字母顺序进行排序，以保证输出的确定性。
7. **处理 Struct:** 可以编码 Go 的结构体类型。结构体的字段名会作为 TOML 的键。可以通过 `toml` 结构体标签来控制键名、是否忽略字段、以及在值为空或零值时是否忽略。
8. **处理嵌套结构:** 支持嵌套的结构体和 map，会生成相应的 TOML 表格和子表格。
9. **处理匿名结构体字段:** 可以处理匿名结构体字段，并将匿名结构体的字段提升到当前表格中。
10. **错误处理:** 定义了一些特定的错误类型，例如 `errArrayMixedElementTypes` (数组元素类型不一致), `errNonString` (map 的键不是字符串) 等，用于在编码过程中出现错误时返回。
11. **控制输出格式:** `Indent` 字段允许用户自定义缩进，默认是两个空格。

**它是什么 Go 语言功能的实现？**

这段代码实现了将 Go 数据结构序列化为 TOML (Tom's Obvious, Minimal Language) 格式的功能。TOML 是一种易于阅读和编写的配置文件格式。

**Go 代码示例:**

```go
package main

import (
	"bytes"
	"fmt"
	"time"

	"github.com/BurntSushi/toml"
)

type Server struct {
	IP   string
	Port int
}

type Database struct {
	Enabled bool
	Ports   []int
	Data    map[string]string
}

type Config struct {
	Title   string
	Owner   struct {
		Name string
		Dob  time.Time
	}
	Servers map[string]Server
	Database Database
}

func main() {
	cfg := Config{
		Title: "TOML Example",
		Owner: struct {
			Name string
			Dob  time.Time
		}{
			Name: "Tom Preston-Werner",
			Dob:  time.Date(1979, time.May, 27, 7, 32, 0, 0, time.UTC),
		},
		Servers: map[string]Server{
			"alpha": {IP: "10.0.0.1", Port: 8001},
			"beta":  {IP: "10.0.0.2", Port: 8001},
		},
		Database: Database{
			Enabled: true,
			Ports:   []int{8000, 8001, 8002},
			Data: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
		},
	}

	var buf bytes.Buffer
	encoder := toml.NewEncoder(&buf)
	err := encoder.Encode(cfg)
	if err != nil {
		fmt.Println("Error encoding TOML:", err)
		return
	}

	fmt.Println(buf.String())
}
```

**假设的输出:**

```toml
title = "TOML Example"

[owner]
name = "Tom Preston-Werner"
dob = 1979-05-27T07:32:00Z

[servers]

[servers.alpha]
ip = "10.0.0.1"
port = 8001

[servers.beta]
ip = "10.0.0.2"
port = 8001

[database]
enabled = true
ports = [ 8000, 8001, 8002 ]

[database.data]
key1 = "value1"
key2 = "value2"
```

**命令行参数处理:**

这段代码本身并不直接处理命令行参数。它是一个库，用于在 Go 程序中进行 TOML 编码。命令行参数的处理通常由调用这个库的应用程序来完成。应用程序可以使用 Go 的 `flag` 包或者其他命令行参数解析库来获取和处理命令行参数，然后根据这些参数来构建需要编码的 Go 数据结构。

**使用者易犯错的点:**

1. **Map 的键必须是字符串:**  尝试编码键不是字符串类型的 map 会导致错误。

   ```go
   package main

   import (
       "bytes"
       "fmt"
       "github.com/BurntSushi/toml"
   )

   func main() {
       data := map[int]string{1: "one", 2: "two"}
       var buf bytes.Buffer
       enc := toml.NewEncoder(&buf)
       err := enc.Encode(data)
       if err != nil {
           fmt.Println("Error:", err) // 输出: Error: toml: cannot encode a map with non-string key type
       }
   }
   ```

2. **数组元素类型不一致:** TOML 的数组要求元素类型一致。尝试编码元素类型不一致的 Go 切片或数组会导致错误。

   ```go
   package main

   import (
       "bytes"
       "fmt"
       "github.com/BurntSushi/toml"
   )

   func main() {
       data := []interface{}{1, "two"}
       var buf bytes.Buffer
       enc := toml.NewEncoder(&buf)
       err := enc.Encode(data)
       if err != nil {
           fmt.Println("Error:", err) // 输出: Error: toml: cannot encode array with mixed element types
       }
   }
   ```

3. **忽略结构体标签的使用:**  如果希望自定义 TOML 的键名，或者忽略某些字段，需要使用结构体标签。忘记使用标签或者标签使用不当会导致输出不符合预期。

   ```go
   package main

   import (
       "bytes"
       "fmt"
       "github.com/BurntSushi/toml"
   )

   type User struct {
       FirstName string `toml:"first_name"` // 使用标签定义键名
       Age       int    `toml:"-"`          // 使用标签忽略字段
       City      string
   }

   func main() {
       user := User{FirstName: "Alice", Age: 30, City: "New York"}
       var buf bytes.Buffer
       enc := toml.NewEncoder(&buf)
       err := enc.Encode(user)
       if err != nil {
           fmt.Println("Error:", err)
           return
       }
       fmt.Println(buf.String())
       // 输出:
       // first_name = "Alice"
       // city = "New York"  // Age 字段被忽略
   }
   ```

4. **对匿名非结构体字段的编码**: 匿名结构体字段如果不是结构体类型，则无法直接编码。

   ```go
   package main

   import (
       "bytes"
       "fmt"
       "github.com/BurntSushi/toml"
   )

   type Data struct {
       Info string
   }

   type Config struct {
       Data // 匿名结构体字段
   }

   func main() {
       cfg := Config{Data: Data{Info: "important"}}
       var buf bytes.Buffer
       enc := toml.NewEncoder(&buf)
       err := enc.Encode(cfg)
       if err != nil {
           fmt.Println("Error:", err)
           return
       }
       fmt.Println(buf.String())
       // 输出:
       // info = "important"
   }
   ```

   但如果匿名的是一个非结构体类型，则会报错：

   ```go
   package main

   import (
       "bytes"
       "fmt"
       "github.com/BurntSushi/toml"
   )

   type Config struct {
       string // 匿名非结构体字段
   }

   func main() {
       cfg := Config{"value"}
       var buf bytes.Buffer
       enc := toml.NewEncoder(&buf)
       err := enc.Encode(cfg)
       if err != nil {
           fmt.Println("Error:", err) // 输出: Error: toml: cannot encode an anonymous field that is not a struct
           return
       }
       fmt.Println(buf.String())
   }
   ```

了解这些细节可以帮助使用者避免在将 Go 数据结构编码为 TOML 时犯错。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/BurntSushi/toml/encode.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package toml

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

type tomlEncodeError struct{ error }

var (
	errArrayMixedElementTypes = errors.New(
		"toml: cannot encode array with mixed element types")
	errArrayNilElement = errors.New(
		"toml: cannot encode array with nil element")
	errNonString = errors.New(
		"toml: cannot encode a map with non-string key type")
	errAnonNonStruct = errors.New(
		"toml: cannot encode an anonymous field that is not a struct")
	errArrayNoTable = errors.New(
		"toml: TOML array element cannot contain a table")
	errNoKey = errors.New(
		"toml: top-level values must be Go maps or structs")
	errAnything = errors.New("") // used in testing
)

var quotedReplacer = strings.NewReplacer(
	"\t", "\\t",
	"\n", "\\n",
	"\r", "\\r",
	"\"", "\\\"",
	"\\", "\\\\",
)

// Encoder controls the encoding of Go values to a TOML document to some
// io.Writer.
//
// The indentation level can be controlled with the Indent field.
type Encoder struct {
	// A single indentation level. By default it is two spaces.
	Indent string

	// hasWritten is whether we have written any output to w yet.
	hasWritten bool
	w          *bufio.Writer
}

// NewEncoder returns a TOML encoder that encodes Go values to the io.Writer
// given. By default, a single indentation level is 2 spaces.
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{
		w:      bufio.NewWriter(w),
		Indent: "  ",
	}
}

// Encode writes a TOML representation of the Go value to the underlying
// io.Writer. If the value given cannot be encoded to a valid TOML document,
// then an error is returned.
//
// The mapping between Go values and TOML values should be precisely the same
// as for the Decode* functions. Similarly, the TextMarshaler interface is
// supported by encoding the resulting bytes as strings. (If you want to write
// arbitrary binary data then you will need to use something like base64 since
// TOML does not have any binary types.)
//
// When encoding TOML hashes (i.e., Go maps or structs), keys without any
// sub-hashes are encoded first.
//
// If a Go map is encoded, then its keys are sorted alphabetically for
// deterministic output. More control over this behavior may be provided if
// there is demand for it.
//
// Encoding Go values without a corresponding TOML representation---like map
// types with non-string keys---will cause an error to be returned. Similarly
// for mixed arrays/slices, arrays/slices with nil elements, embedded
// non-struct types and nested slices containing maps or structs.
// (e.g., [][]map[string]string is not allowed but []map[string]string is OK
// and so is []map[string][]string.)
func (enc *Encoder) Encode(v interface{}) error {
	rv := eindirect(reflect.ValueOf(v))
	if err := enc.safeEncode(Key([]string{}), rv); err != nil {
		return err
	}
	return enc.w.Flush()
}

func (enc *Encoder) safeEncode(key Key, rv reflect.Value) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if terr, ok := r.(tomlEncodeError); ok {
				err = terr.error
				return
			}
			panic(r)
		}
	}()
	enc.encode(key, rv)
	return nil
}

func (enc *Encoder) encode(key Key, rv reflect.Value) {
	// Special case. Time needs to be in ISO8601 format.
	// Special case. If we can marshal the type to text, then we used that.
	// Basically, this prevents the encoder for handling these types as
	// generic structs (or whatever the underlying type of a TextMarshaler is).
	switch rv.Interface().(type) {
	case time.Time, TextMarshaler:
		enc.keyEqElement(key, rv)
		return
	}

	k := rv.Kind()
	switch k {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32,
		reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32,
		reflect.Uint64,
		reflect.Float32, reflect.Float64, reflect.String, reflect.Bool:
		enc.keyEqElement(key, rv)
	case reflect.Array, reflect.Slice:
		if typeEqual(tomlArrayHash, tomlTypeOfGo(rv)) {
			enc.eArrayOfTables(key, rv)
		} else {
			enc.keyEqElement(key, rv)
		}
	case reflect.Interface:
		if rv.IsNil() {
			return
		}
		enc.encode(key, rv.Elem())
	case reflect.Map:
		if rv.IsNil() {
			return
		}
		enc.eTable(key, rv)
	case reflect.Ptr:
		if rv.IsNil() {
			return
		}
		enc.encode(key, rv.Elem())
	case reflect.Struct:
		enc.eTable(key, rv)
	default:
		panic(e("unsupported type for key '%s': %s", key, k))
	}
}

// eElement encodes any value that can be an array element (primitives and
// arrays).
func (enc *Encoder) eElement(rv reflect.Value) {
	switch v := rv.Interface().(type) {
	case time.Time:
		// Special case time.Time as a primitive. Has to come before
		// TextMarshaler below because time.Time implements
		// encoding.TextMarshaler, but we need to always use UTC.
		enc.wf(v.UTC().Format("2006-01-02T15:04:05Z"))
		return
	case TextMarshaler:
		// Special case. Use text marshaler if it's available for this value.
		if s, err := v.MarshalText(); err != nil {
			encPanic(err)
		} else {
			enc.writeQuoted(string(s))
		}
		return
	}
	switch rv.Kind() {
	case reflect.Bool:
		enc.wf(strconv.FormatBool(rv.Bool()))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32,
		reflect.Int64:
		enc.wf(strconv.FormatInt(rv.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16,
		reflect.Uint32, reflect.Uint64:
		enc.wf(strconv.FormatUint(rv.Uint(), 10))
	case reflect.Float32:
		enc.wf(floatAddDecimal(strconv.FormatFloat(rv.Float(), 'f', -1, 32)))
	case reflect.Float64:
		enc.wf(floatAddDecimal(strconv.FormatFloat(rv.Float(), 'f', -1, 64)))
	case reflect.Array, reflect.Slice:
		enc.eArrayOrSliceElement(rv)
	case reflect.Interface:
		enc.eElement(rv.Elem())
	case reflect.String:
		enc.writeQuoted(rv.String())
	default:
		panic(e("unexpected primitive type: %s", rv.Kind()))
	}
}

// By the TOML spec, all floats must have a decimal with at least one
// number on either side.
func floatAddDecimal(fstr string) string {
	if !strings.Contains(fstr, ".") {
		return fstr + ".0"
	}
	return fstr
}

func (enc *Encoder) writeQuoted(s string) {
	enc.wf("\"%s\"", quotedReplacer.Replace(s))
}

func (enc *Encoder) eArrayOrSliceElement(rv reflect.Value) {
	length := rv.Len()
	enc.wf("[")
	for i := 0; i < length; i++ {
		elem := rv.Index(i)
		enc.eElement(elem)
		if i != length-1 {
			enc.wf(", ")
		}
	}
	enc.wf("]")
}

func (enc *Encoder) eArrayOfTables(key Key, rv reflect.Value) {
	if len(key) == 0 {
		encPanic(errNoKey)
	}
	for i := 0; i < rv.Len(); i++ {
		trv := rv.Index(i)
		if isNil(trv) {
			continue
		}
		panicIfInvalidKey(key)
		enc.newline()
		enc.wf("%s[[%s]]", enc.indentStr(key), key.maybeQuotedAll())
		enc.newline()
		enc.eMapOrStruct(key, trv)
	}
}

func (enc *Encoder) eTable(key Key, rv reflect.Value) {
	panicIfInvalidKey(key)
	if len(key) == 1 {
		// Output an extra newline between top-level tables.
		// (The newline isn't written if nothing else has been written though.)
		enc.newline()
	}
	if len(key) > 0 {
		enc.wf("%s[%s]", enc.indentStr(key), key.maybeQuotedAll())
		enc.newline()
	}
	enc.eMapOrStruct(key, rv)
}

func (enc *Encoder) eMapOrStruct(key Key, rv reflect.Value) {
	switch rv := eindirect(rv); rv.Kind() {
	case reflect.Map:
		enc.eMap(key, rv)
	case reflect.Struct:
		enc.eStruct(key, rv)
	default:
		panic("eTable: unhandled reflect.Value Kind: " + rv.Kind().String())
	}
}

func (enc *Encoder) eMap(key Key, rv reflect.Value) {
	rt := rv.Type()
	if rt.Key().Kind() != reflect.String {
		encPanic(errNonString)
	}

	// Sort keys so that we have deterministic output. And write keys directly
	// underneath this key first, before writing sub-structs or sub-maps.
	var mapKeysDirect, mapKeysSub []string
	for _, mapKey := range rv.MapKeys() {
		k := mapKey.String()
		if typeIsHash(tomlTypeOfGo(rv.MapIndex(mapKey))) {
			mapKeysSub = append(mapKeysSub, k)
		} else {
			mapKeysDirect = append(mapKeysDirect, k)
		}
	}

	var writeMapKeys = func(mapKeys []string) {
		sort.Strings(mapKeys)
		for _, mapKey := range mapKeys {
			mrv := rv.MapIndex(reflect.ValueOf(mapKey))
			if isNil(mrv) {
				// Don't write anything for nil fields.
				continue
			}
			enc.encode(key.add(mapKey), mrv)
		}
	}
	writeMapKeys(mapKeysDirect)
	writeMapKeys(mapKeysSub)
}

func (enc *Encoder) eStruct(key Key, rv reflect.Value) {
	// Write keys for fields directly under this key first, because if we write
	// a field that creates a new table, then all keys under it will be in that
	// table (not the one we're writing here).
	rt := rv.Type()
	var fieldsDirect, fieldsSub [][]int
	var addFields func(rt reflect.Type, rv reflect.Value, start []int)
	addFields = func(rt reflect.Type, rv reflect.Value, start []int) {
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			// skip unexported fields
			if f.PkgPath != "" && !f.Anonymous {
				continue
			}
			frv := rv.Field(i)
			if f.Anonymous {
				t := f.Type
				switch t.Kind() {
				case reflect.Struct:
					// Treat anonymous struct fields with
					// tag names as though they are not
					// anonymous, like encoding/json does.
					if getOptions(f.Tag).name == "" {
						addFields(t, frv, f.Index)
						continue
					}
				case reflect.Ptr:
					if t.Elem().Kind() == reflect.Struct &&
						getOptions(f.Tag).name == "" {
						if !frv.IsNil() {
							addFields(t.Elem(), frv.Elem(), f.Index)
						}
						continue
					}
					// Fall through to the normal field encoding logic below
					// for non-struct anonymous fields.
				}
			}

			if typeIsHash(tomlTypeOfGo(frv)) {
				fieldsSub = append(fieldsSub, append(start, f.Index...))
			} else {
				fieldsDirect = append(fieldsDirect, append(start, f.Index...))
			}
		}
	}
	addFields(rt, rv, nil)

	var writeFields = func(fields [][]int) {
		for _, fieldIndex := range fields {
			sft := rt.FieldByIndex(fieldIndex)
			sf := rv.FieldByIndex(fieldIndex)
			if isNil(sf) {
				// Don't write anything for nil fields.
				continue
			}

			opts := getOptions(sft.Tag)
			if opts.skip {
				continue
			}
			keyName := sft.Name
			if opts.name != "" {
				keyName = opts.name
			}
			if opts.omitempty && isEmpty(sf) {
				continue
			}
			if opts.omitzero && isZero(sf) {
				continue
			}

			enc.encode(key.add(keyName), sf)
		}
	}
	writeFields(fieldsDirect)
	writeFields(fieldsSub)
}

// tomlTypeName returns the TOML type name of the Go value's type. It is
// used to determine whether the types of array elements are mixed (which is
// forbidden). If the Go value is nil, then it is illegal for it to be an array
// element, and valueIsNil is returned as true.

// Returns the TOML type of a Go value. The type may be `nil`, which means
// no concrete TOML type could be found.
func tomlTypeOfGo(rv reflect.Value) tomlType {
	if isNil(rv) || !rv.IsValid() {
		return nil
	}
	switch rv.Kind() {
	case reflect.Bool:
		return tomlBool
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32,
		reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32,
		reflect.Uint64:
		return tomlInteger
	case reflect.Float32, reflect.Float64:
		return tomlFloat
	case reflect.Array, reflect.Slice:
		if typeEqual(tomlHash, tomlArrayType(rv)) {
			return tomlArrayHash
		}
		return tomlArray
	case reflect.Ptr, reflect.Interface:
		return tomlTypeOfGo(rv.Elem())
	case reflect.String:
		return tomlString
	case reflect.Map:
		return tomlHash
	case reflect.Struct:
		switch rv.Interface().(type) {
		case time.Time:
			return tomlDatetime
		case TextMarshaler:
			return tomlString
		default:
			return tomlHash
		}
	default:
		panic("unexpected reflect.Kind: " + rv.Kind().String())
	}
}

// tomlArrayType returns the element type of a TOML array. The type returned
// may be nil if it cannot be determined (e.g., a nil slice or a zero length
// slize). This function may also panic if it finds a type that cannot be
// expressed in TOML (such as nil elements, heterogeneous arrays or directly
// nested arrays of tables).
func tomlArrayType(rv reflect.Value) tomlType {
	if isNil(rv) || !rv.IsValid() || rv.Len() == 0 {
		return nil
	}
	firstType := tomlTypeOfGo(rv.Index(0))
	if firstType == nil {
		encPanic(errArrayNilElement)
	}

	rvlen := rv.Len()
	for i := 1; i < rvlen; i++ {
		elem := rv.Index(i)
		switch elemType := tomlTypeOfGo(elem); {
		case elemType == nil:
			encPanic(errArrayNilElement)
		case !typeEqual(firstType, elemType):
			encPanic(errArrayMixedElementTypes)
		}
	}
	// If we have a nested array, then we must make sure that the nested
	// array contains ONLY primitives.
	// This checks arbitrarily nested arrays.
	if typeEqual(firstType, tomlArray) || typeEqual(firstType, tomlArrayHash) {
		nest := tomlArrayType(eindirect(rv.Index(0)))
		if typeEqual(nest, tomlHash) || typeEqual(nest, tomlArrayHash) {
			encPanic(errArrayNoTable)
		}
	}
	return firstType
}

type tagOptions struct {
	skip      bool // "-"
	name      string
	omitempty bool
	omitzero  bool
}

func getOptions(tag reflect.StructTag) tagOptions {
	t := tag.Get("toml")
	if t == "-" {
		return tagOptions{skip: true}
	}
	var opts tagOptions
	parts := strings.Split(t, ",")
	opts.name = parts[0]
	for _, s := range parts[1:] {
		switch s {
		case "omitempty":
			opts.omitempty = true
		case "omitzero":
			opts.omitzero = true
		}
	}
	return opts
}

func isZero(rv reflect.Value) bool {
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return rv.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return rv.Float() == 0.0
	}
	return false
}

func isEmpty(rv reflect.Value) bool {
	switch rv.Kind() {
	case reflect.Array, reflect.Slice, reflect.Map, reflect.String:
		return rv.Len() == 0
	case reflect.Bool:
		return !rv.Bool()
	}
	return false
}

func (enc *Encoder) newline() {
	if enc.hasWritten {
		enc.wf("\n")
	}
}

func (enc *Encoder) keyEqElement(key Key, val reflect.Value) {
	if len(key) == 0 {
		encPanic(errNoKey)
	}
	panicIfInvalidKey(key)
	enc.wf("%s%s = ", enc.indentStr(key), key.maybeQuoted(len(key)-1))
	enc.eElement(val)
	enc.newline()
}

func (enc *Encoder) wf(format string, v ...interface{}) {
	if _, err := fmt.Fprintf(enc.w, format, v...); err != nil {
		encPanic(err)
	}
	enc.hasWritten = true
}

func (enc *Encoder) indentStr(key Key) string {
	return strings.Repeat(enc.Indent, len(key)-1)
}

func encPanic(err error) {
	panic(tomlEncodeError{err})
}

func eindirect(v reflect.Value) reflect.Value {
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface:
		return eindirect(v.Elem())
	default:
		return v
	}
}

func isNil(rv reflect.Value) bool {
	switch rv.Kind() {
	case reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

func panicIfInvalidKey(key Key) {
	for _, k := range key {
		if len(k) == 0 {
			encPanic(e("Key '%s' is not a valid table name. Key names "+
				"cannot be empty.", key.maybeQuotedAll()))
		}
	}
}

func isValidKeyName(s string) bool {
	return len(s) != 0
}

"""



```