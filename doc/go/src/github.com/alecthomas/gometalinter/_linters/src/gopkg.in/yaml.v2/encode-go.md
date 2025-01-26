Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Functionality:** The package name `yaml` and the file name `encode.go` strongly suggest this code is responsible for encoding Go data structures into YAML format. The presence of `yaml_emitter_t` and functions like `yaml_emitter_emit` further reinforce this, indicating the use of a C library (likely `libyaml`) for the underlying YAML processing.

2. **Deconstruct the `encoder` struct:** This struct holds the state needed for the encoding process. The key fields are:
    * `emitter yaml_emitter_t`:  Interface to the C YAML library.
    * `event yaml_event_t`: Represents a YAML event to be emitted.
    * `out []byte`:  Likely used for in-memory encoding (though `io.Writer` suggests output can go elsewhere).
    * `flow bool`: Controls the YAML style (block or flow).
    * `doneInit bool`: Tracks initialization state.

3. **Analyze Key Functions (Top-Down Approach):**

    * **`newEncoder()` and `newEncoderWithWriter()`:** These are constructors. One writes to a byte slice, the other to a generic `io.Writer`. This immediately tells us there are two main ways to use the encoder.

    * **`init()`:**  Initializes the YAML stream. The `yaml_stream_start_event_initialize` is a giveaway.

    * **`finish()`:**  Terminates the YAML stream (`yaml_stream_end_event_initialize`).

    * **`destroy()`:**  Cleans up resources (`yaml_emitter_delete`). Important for proper resource management.

    * **`emit()`:**  The core function that sends the current `event` to the YAML emitter.

    * **`must()`:**  Error handling. Checks the return value of the C library and panics if there's an error.

    * **`marshalDoc()`:** Encodes a single YAML document. It calls `marshal()` for the actual data.

    * **`marshal()`:**  The workhorse function. It handles different Go types:
        * **Special Cases:** `time.Time`, `Marshaler`, `encoding.TextMarshaler`. This indicates flexibility in handling different data representations.
        * **Basic Types:**  `string`, `int`, `uint`, `float`, `bool`.
        * **Compound Types:** `map`, `slice`, `array`, `struct`.
        * **Pointers:** Recursively calls `marshal()` on the pointed-to value.
        * **Interfaces:**  Handles the underlying type.
        * **Nil:** Encodes as `null`.

    * **`mapv()`, `itemsv()`, `structv()`, `mappingv()`, `slicev()`:** These are helper functions for encoding specific compound types. Notice the `sort.Sort` in `mapv` and `structv` – this indicates the output order of map keys is deterministic. The handling of struct tags and inline fields in `structv` is also significant.

    * **`stringv()`:**  Handles string encoding, including UTF-8 validation and potential base64 encoding for invalid UTF-8. The `isBase60Float` check suggests backward compatibility considerations.

    * **`boolv()`, `intv()`, `uintv()`, `timev()`, `floatv()`, `nilv()`:** Encode the respective primitive types.

    * **`emitScalar()`:**  Emits a scalar YAML value.

4. **Inferring Go Features:**

    * **Reflection:** The extensive use of `reflect.Value` and `reflect.Kind()` clearly indicates the use of Go's reflection capabilities to inspect the structure and type of the input data at runtime.

    * **Interfaces:** The handling of `Marshaler` and `encoding.TextMarshaler` demonstrates the use of interfaces for custom serialization logic.

    * **Pointers:** The code explicitly handles pointers, including nil pointers.

    * **String Conversion:** Functions like `strconv.FormatInt`, `strconv.FormatUint`, `strconv.FormatFloat` are used for converting numeric types to strings for YAML output.

    * **Time Formatting:**  `time.RFC3339Nano` shows how time values are formatted for YAML.

5. **Considering Command-Line Arguments (Context is Key):**  The provided code snippet *itself* doesn't handle command-line arguments. It's a low-level encoding library. Higher-level tools that *use* this library might have command-line options to control aspects like indentation, output file, etc. Therefore, the thought here is to explain that this snippet is just a *part* of a larger process.

6. **Identifying Potential User Errors:**  Think about the assumptions and complexities in the code:

    * **Invalid UTF-8:** The code handles it, but users might be surprised by the base64 encoding.
    * **Custom Marshaler Logic:**  If a `Marshaler` implementation has bugs, it could lead to incorrect YAML.
    * **Struct Tag Errors:** Incorrect or conflicting struct tags can cause unexpected output. The code detects and panics on some conflicts related to inline maps.
    * **Time Zones:** The code uses `time.Time`, which by default includes time zone information. Users might need to be aware of how time zones are handled in YAML.
    * **Circular References:**  The code doesn't explicitly show handling of circular references, which could lead to infinite loops or stack overflows in a real-world encoder. *While the provided snippet doesn't directly illustrate the error, it's a common pitfall with serialization libraries.*

7. **Structuring the Answer:**  Organize the information logically:
    * Start with the main function: encoding to YAML.
    * Explain the core `encoder` struct.
    * Detail the key functions and their roles.
    * Provide illustrative Go code examples for important features.
    * Discuss command-line arguments in the broader context.
    * Highlight common user errors.
    * Use clear and concise language.

By following these steps, we can systematically analyze the code and provide a comprehensive and informative answer. The key is to understand the code's purpose, break it down into its components, and connect those components to relevant Go language features and potential usage scenarios.
这段代码是 Go 语言 `gopkg.in/yaml.v2` 库中负责将 Go 数据结构编码成 YAML 格式的一部分。它定义了一个 `encoder` 结构体以及一系列方法来实现这个编码过程。

**主要功能:**

1. **初始化编码器:**
   - `newEncoder()`: 创建一个新的 `encoder` 实例，并将输出目标设置为一个 byte slice (`e.out`)。
   - `newEncoderWithWriter(w io.Writer)`: 创建一个新的 `encoder` 实例，并将输出目标设置为一个 `io.Writer` 接口，允许将 YAML 输出到任何实现了 `io.Writer` 的地方，如文件或网络连接。

2. **管理 YAML 流:**
   - `init()`: 初始化 YAML 流，发送 `stream_start_event` 事件。这个方法确保在开始编码任何内容之前，YAML 流已经正确启动。
   - `finish()`: 结束 YAML 流，发送 `stream_end_event` 事件。
   - `destroy()`: 清理编码器使用的资源，例如释放 C 库 `libyaml` 中的 emitter。

3. **核心编码逻辑:**
   - `marshalDoc(tag string, in reflect.Value)`: 编码一个 YAML 文档。它首先发送 `document_start_event`，然后调用 `marshal` 方法来处理实际的数据编码，最后发送 `document_end_event`。
   - `marshal(tag string, in reflect.Value)`: 这是一个递归方法，负责将 Go 的各种数据类型编码成 YAML。它会根据 `reflect.Value` 的类型进行不同的处理，例如：
     - 处理 `Marshaler` 和 `encoding.TextMarshaler` 接口，允许自定义类型的 YAML 编码。
     - 处理 `time.Time` 类型，将其格式化为 YAML 的时间戳格式。
     - 递归处理 `interface` 类型，编码其底层的值。
     - 调用 `mapv`、`slicev`、`structv` 等方法来处理复杂类型。
     - 将基本类型（如 `string`、`int`、`bool` 等）转换为 YAML 的标量值。
   - `mapv(tag string, in reflect.Value)`: 编码 Go 的 `map` 类型为 YAML 的 mapping (键值对)。它会对 map 的键进行排序，以确保输出的稳定性。
   - `itemsv(tag string, in reflect.Value)`: 编码 `[]MapItem` 类型的 slice 为 YAML 的 mapping。
   - `structv(tag string, in reflect.Value)`: 编码 Go 的 `struct` 类型为 YAML 的 mapping。它会根据 struct 字段的 tag 来决定 YAML 的 key，并处理 `omitempty` 选项和内联字段。
   - `slicev(tag string, in reflect.Value)`: 编码 Go 的 `slice` 或 `array` 类型为 YAML 的 sequence (列表)。
   - `stringv(tag string, in reflect.Value)`: 编码 Go 的 `string` 类型为 YAML 的标量。它会处理 UTF-8 编码，并根据字符串内容选择合适的标量样式（plain, double-quoted, literal）。对于非 UTF-8 字符串，会将其编码为 base64 并添加 `!!binary` tag。
   - `boolv(tag string, in reflect.Value)`: 编码 Go 的 `bool` 类型为 YAML 的 `true` 或 `false`。
   - `intv(tag string, in reflect.Value)`: 编码 Go 的整数类型为 YAML 的数字。
   - `uintv(tag string, in reflect.Value)`: 编码 Go 的无符号整数类型为 YAML 的数字。
   - `timev(tag string, in reflect.Value)`: 编码 Go 的 `time.Time` 类型为 YAML 的时间戳，使用 RFC3339Nano 格式。
   - `floatv(tag string, in reflect.Value)`: 编码 Go 的浮点数类型为 YAML 的数字。它会处理 `+Inf`、`-Inf` 和 `NaN`。
   - `nilv()`: 编码 Go 的 `nil` 值为 YAML 的 `null`。

4. **底层事件处理:**
   - `emit()`: 将当前的 YAML 事件发送到 emitter。
   - `emitScalar(...)`: 发送一个 YAML 标量事件。
   - `mappingv(...)`: 发送 mapping 的开始和结束事件，并执行传入的函数来编码 mapping 的内容。

5. **错误处理:**
   - `must(ok bool)`: 检查操作是否成功，如果不成功则 panic 并显示错误信息。

**它是什么 Go 语言功能的实现？**

这个代码片段主要实现了 Go 语言的 **结构体序列化** 或更具体地说，**将 Go 的数据结构编码成 YAML 格式**。它利用了 Go 的以下特性：

* **反射 (Reflection):**  `reflect` 包被广泛用于检查变量的类型和值，这是实现通用序列化/反序列化的基础。`marshal` 方法通过反射来判断输入 `reflect.Value` 的类型，并采取相应的编码策略。
* **接口 (Interfaces):** 代码中检查了 `Marshaler` 和 `encoding.TextMarshaler` 接口，允许用户自定义类型的编码方式。这使得库具有很强的扩展性。
* **类型断言 (Type Assertion):** 在 `marshal` 方法中可以看到类型断言，例如 `iface.(type)`，用于处理实现了接口的类型。
* **函数作为参数 (First-class functions):** `mappingv` 方法接受一个 `func()` 作为参数，用于封装编码 mapping 内容的逻辑。
* **错误处理 (Error Handling):**  虽然这个片段中使用了 `panic` 进行错误处理，但在实际的 `yaml` 库中，更常见的做法是返回 `error` 值。

**Go 代码示例:**

假设我们有以下 Go 结构体：

```go
package main

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"time"
)

type Person struct {
	Name    string `yaml:"name"`
	Age     int    `yaml:"age"`
	Hobbies []string `yaml:"hobbies,omitempty"`
	Birthday time.Time `yaml:"birthday"`
}

func main() {
	p := Person{
		Name:    "Alice",
		Age:     30,
		Hobbies: []string{"reading", "coding"},
		Birthday: time.Date(1993, 10, 26, 0, 0, 0, 0, time.UTC),
	}

	out, err := yaml.Marshal(&p)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(out))
}
```

**假设的输出:**

```yaml
name: Alice
age: 30
hobbies:
- reading
- coding
birthday: 1993-10-26T00:00:00Z
```

**代码推理:**

在上面的例子中，当我们调用 `yaml.Marshal(&p)` 时，`encode.go` 中的 `newEncoder()` 会创建一个新的编码器，然后 `marshalDoc` 会被调用，最终 `marshal` 方法会遍历 `Person` 结构体的字段。

- 对于 `Name` 字段，`stringv` 方法会被调用，将其编码为 YAML 字符串。
- 对于 `Age` 字段，`intv` 方法会被调用，将其编码为 YAML 数字。
- 对于 `Hobbies` 字段，`slicev` 方法会被调用，将其编码为 YAML 列表。
- 对于 `Birthday` 字段，`timev` 方法会被调用，将其格式化为 YAML 时间戳。

**命令行参数的具体处理:**

这个代码片段本身并不处理命令行参数。它是一个底层的编码库。通常，使用这个库的更高级别的工具或应用程序可能会处理命令行参数，以控制 YAML 输出的格式，例如缩进、是否使用 flow 样式等。

例如，一个使用 `gopkg.in/yaml.v2` 的命令行工具可能会有如下参数：

```bash
mytool --indent 4 --flow input.json output.yaml
```

但这些参数的处理逻辑不会在这个 `encode.go` 文件中。

**使用者易犯错的点:**

1. **未导出字段的编码:** Go 的反射机制只能访问导出的字段（首字母大写）。如果结构体字段是未导出的，默认情况下不会被编码到 YAML 中。

   ```go
   type PrivateField struct {
       Name string
       age  int // 未导出，不会被编码
   }

   p := PrivateField{"Bob", 25}
   out, _ := yaml.Marshal(&p)
   fmt.Println(string(out)) // 输出: name: Bob
   ```

2. **循环引用的处理:** `gopkg.in/yaml.v2` 默认情况下不能处理循环引用的数据结构，会导致无限递归。使用者需要注意避免这种情况，或者使用支持循环引用处理的第三方库。

3. **时间类型的时区信息:**  `time.Time` 包含了时区信息。默认情况下，`gopkg.in/yaml.v2` 会将其编码为 UTC 时间。如果需要保留或以其他方式处理时区信息，可能需要自定义 `Marshaler` 或在编码前进行转换。

4. **结构体标签的使用错误:**  `yaml` 标签用于指定 YAML 字段的名称和一些选项（如 `omitempty`）。拼写错误或使用不当的标签会导致编码结果不符合预期。

   ```go
   type TagError struct {
       FieldName string `yamll:"field_name"` // 错误的标签拼写
   }

   t := TagError{"Value"}
   out, _ := yaml.Marshal(&t)
   fmt.Println(string(out)) // 输出: FieldName: Value (使用了 Go 字段名)
   ```

这段代码是 `gopkg.in/yaml.v2` 库的核心部分，负责将 Go 的数据结构转换为 YAML 格式的文本表示。它利用了 Go 的反射机制和接口来实现灵活且通用的编码功能。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/gopkg.in/yaml.v2/encode.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package yaml

import (
	"encoding"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type encoder struct {
	emitter yaml_emitter_t
	event   yaml_event_t
	out     []byte
	flow    bool
	// doneInit holds whether the initial stream_start_event has been
	// emitted.
	doneInit bool
}

func newEncoder() *encoder {
	e := &encoder{}
	yaml_emitter_initialize(&e.emitter)
	yaml_emitter_set_output_string(&e.emitter, &e.out)
	yaml_emitter_set_unicode(&e.emitter, true)
	return e
}

func newEncoderWithWriter(w io.Writer) *encoder {
	e := &encoder{}
	yaml_emitter_initialize(&e.emitter)
	yaml_emitter_set_output_writer(&e.emitter, w)
	yaml_emitter_set_unicode(&e.emitter, true)
	return e
}

func (e *encoder) init() {
	if e.doneInit {
		return
	}
	yaml_stream_start_event_initialize(&e.event, yaml_UTF8_ENCODING)
	e.emit()
	e.doneInit = true
}

func (e *encoder) finish() {
	e.emitter.open_ended = false
	yaml_stream_end_event_initialize(&e.event)
	e.emit()
}

func (e *encoder) destroy() {
	yaml_emitter_delete(&e.emitter)
}

func (e *encoder) emit() {
	// This will internally delete the e.event value.
	e.must(yaml_emitter_emit(&e.emitter, &e.event))
}

func (e *encoder) must(ok bool) {
	if !ok {
		msg := e.emitter.problem
		if msg == "" {
			msg = "unknown problem generating YAML content"
		}
		failf("%s", msg)
	}
}

func (e *encoder) marshalDoc(tag string, in reflect.Value) {
	e.init()
	yaml_document_start_event_initialize(&e.event, nil, nil, true)
	e.emit()
	e.marshal(tag, in)
	yaml_document_end_event_initialize(&e.event, true)
	e.emit()
}

func (e *encoder) marshal(tag string, in reflect.Value) {
	if !in.IsValid() || in.Kind() == reflect.Ptr && in.IsNil() {
		e.nilv()
		return
	}
	iface := in.Interface()
	switch m := iface.(type) {
	case time.Time, *time.Time:
		// Although time.Time implements TextMarshaler,
		// we don't want to treat it as a string for YAML
		// purposes because YAML has special support for
		// timestamps.
	case Marshaler:
		v, err := m.MarshalYAML()
		if err != nil {
			fail(err)
		}
		if v == nil {
			e.nilv()
			return
		}
		in = reflect.ValueOf(v)
	case encoding.TextMarshaler:
		text, err := m.MarshalText()
		if err != nil {
			fail(err)
		}
		in = reflect.ValueOf(string(text))
	case nil:
		e.nilv()
		return
	}
	switch in.Kind() {
	case reflect.Interface:
		e.marshal(tag, in.Elem())
	case reflect.Map:
		e.mapv(tag, in)
	case reflect.Ptr:
		if in.Type() == ptrTimeType {
			e.timev(tag, in.Elem())
		} else {
			e.marshal(tag, in.Elem())
		}
	case reflect.Struct:
		if in.Type() == timeType {
			e.timev(tag, in)
		} else {
			e.structv(tag, in)
		}
	case reflect.Slice, reflect.Array:
		if in.Type().Elem() == mapItemType {
			e.itemsv(tag, in)
		} else {
			e.slicev(tag, in)
		}
	case reflect.String:
		e.stringv(tag, in)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if in.Type() == durationType {
			e.stringv(tag, reflect.ValueOf(iface.(time.Duration).String()))
		} else {
			e.intv(tag, in)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		e.uintv(tag, in)
	case reflect.Float32, reflect.Float64:
		e.floatv(tag, in)
	case reflect.Bool:
		e.boolv(tag, in)
	default:
		panic("cannot marshal type: " + in.Type().String())
	}
}

func (e *encoder) mapv(tag string, in reflect.Value) {
	e.mappingv(tag, func() {
		keys := keyList(in.MapKeys())
		sort.Sort(keys)
		for _, k := range keys {
			e.marshal("", k)
			e.marshal("", in.MapIndex(k))
		}
	})
}

func (e *encoder) itemsv(tag string, in reflect.Value) {
	e.mappingv(tag, func() {
		slice := in.Convert(reflect.TypeOf([]MapItem{})).Interface().([]MapItem)
		for _, item := range slice {
			e.marshal("", reflect.ValueOf(item.Key))
			e.marshal("", reflect.ValueOf(item.Value))
		}
	})
}

func (e *encoder) structv(tag string, in reflect.Value) {
	sinfo, err := getStructInfo(in.Type())
	if err != nil {
		panic(err)
	}
	e.mappingv(tag, func() {
		for _, info := range sinfo.FieldsList {
			var value reflect.Value
			if info.Inline == nil {
				value = in.Field(info.Num)
			} else {
				value = in.FieldByIndex(info.Inline)
			}
			if info.OmitEmpty && isZero(value) {
				continue
			}
			e.marshal("", reflect.ValueOf(info.Key))
			e.flow = info.Flow
			e.marshal("", value)
		}
		if sinfo.InlineMap >= 0 {
			m := in.Field(sinfo.InlineMap)
			if m.Len() > 0 {
				e.flow = false
				keys := keyList(m.MapKeys())
				sort.Sort(keys)
				for _, k := range keys {
					if _, found := sinfo.FieldsMap[k.String()]; found {
						panic(fmt.Sprintf("Can't have key %q in inlined map; conflicts with struct field", k.String()))
					}
					e.marshal("", k)
					e.flow = false
					e.marshal("", m.MapIndex(k))
				}
			}
		}
	})
}

func (e *encoder) mappingv(tag string, f func()) {
	implicit := tag == ""
	style := yaml_BLOCK_MAPPING_STYLE
	if e.flow {
		e.flow = false
		style = yaml_FLOW_MAPPING_STYLE
	}
	yaml_mapping_start_event_initialize(&e.event, nil, []byte(tag), implicit, style)
	e.emit()
	f()
	yaml_mapping_end_event_initialize(&e.event)
	e.emit()
}

func (e *encoder) slicev(tag string, in reflect.Value) {
	implicit := tag == ""
	style := yaml_BLOCK_SEQUENCE_STYLE
	if e.flow {
		e.flow = false
		style = yaml_FLOW_SEQUENCE_STYLE
	}
	e.must(yaml_sequence_start_event_initialize(&e.event, nil, []byte(tag), implicit, style))
	e.emit()
	n := in.Len()
	for i := 0; i < n; i++ {
		e.marshal("", in.Index(i))
	}
	e.must(yaml_sequence_end_event_initialize(&e.event))
	e.emit()
}

// isBase60 returns whether s is in base 60 notation as defined in YAML 1.1.
//
// The base 60 float notation in YAML 1.1 is a terrible idea and is unsupported
// in YAML 1.2 and by this package, but these should be marshalled quoted for
// the time being for compatibility with other parsers.
func isBase60Float(s string) (result bool) {
	// Fast path.
	if s == "" {
		return false
	}
	c := s[0]
	if !(c == '+' || c == '-' || c >= '0' && c <= '9') || strings.IndexByte(s, ':') < 0 {
		return false
	}
	// Do the full match.
	return base60float.MatchString(s)
}

// From http://yaml.org/type/float.html, except the regular expression there
// is bogus. In practice parsers do not enforce the "\.[0-9_]*" suffix.
var base60float = regexp.MustCompile(`^[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+(?:\.[0-9_]*)?$`)

func (e *encoder) stringv(tag string, in reflect.Value) {
	var style yaml_scalar_style_t
	s := in.String()
	canUsePlain := true
	switch {
	case !utf8.ValidString(s):
		if tag == yaml_BINARY_TAG {
			failf("explicitly tagged !!binary data must be base64-encoded")
		}
		if tag != "" {
			failf("cannot marshal invalid UTF-8 data as %s", shortTag(tag))
		}
		// It can't be encoded directly as YAML so use a binary tag
		// and encode it as base64.
		tag = yaml_BINARY_TAG
		s = encodeBase64(s)
	case tag == "":
		// Check to see if it would resolve to a specific
		// tag when encoded unquoted. If it doesn't,
		// there's no need to quote it.
		rtag, _ := resolve("", s)
		canUsePlain = rtag == yaml_STR_TAG && !isBase60Float(s)
	}
	// Note: it's possible for user code to emit invalid YAML
	// if they explicitly specify a tag and a string containing
	// text that's incompatible with that tag.
	switch {
	case strings.Contains(s, "\n"):
		style = yaml_LITERAL_SCALAR_STYLE
	case canUsePlain:
		style = yaml_PLAIN_SCALAR_STYLE
	default:
		style = yaml_DOUBLE_QUOTED_SCALAR_STYLE
	}
	e.emitScalar(s, "", tag, style)
}

func (e *encoder) boolv(tag string, in reflect.Value) {
	var s string
	if in.Bool() {
		s = "true"
	} else {
		s = "false"
	}
	e.emitScalar(s, "", tag, yaml_PLAIN_SCALAR_STYLE)
}

func (e *encoder) intv(tag string, in reflect.Value) {
	s := strconv.FormatInt(in.Int(), 10)
	e.emitScalar(s, "", tag, yaml_PLAIN_SCALAR_STYLE)
}

func (e *encoder) uintv(tag string, in reflect.Value) {
	s := strconv.FormatUint(in.Uint(), 10)
	e.emitScalar(s, "", tag, yaml_PLAIN_SCALAR_STYLE)
}

func (e *encoder) timev(tag string, in reflect.Value) {
	t := in.Interface().(time.Time)
	s := t.Format(time.RFC3339Nano)
	e.emitScalar(s, "", tag, yaml_PLAIN_SCALAR_STYLE)
}

func (e *encoder) floatv(tag string, in reflect.Value) {
	// Issue #352: When formatting, use the precision of the underlying value
	precision := 64
	if in.Kind() == reflect.Float32 {
		precision = 32
	}

	s := strconv.FormatFloat(in.Float(), 'g', -1, precision)
	switch s {
	case "+Inf":
		s = ".inf"
	case "-Inf":
		s = "-.inf"
	case "NaN":
		s = ".nan"
	}
	e.emitScalar(s, "", tag, yaml_PLAIN_SCALAR_STYLE)
}

func (e *encoder) nilv() {
	e.emitScalar("null", "", "", yaml_PLAIN_SCALAR_STYLE)
}

func (e *encoder) emitScalar(value, anchor, tag string, style yaml_scalar_style_t) {
	implicit := tag == ""
	e.must(yaml_scalar_event_initialize(&e.event, []byte(anchor), []byte(tag), []byte(value), implicit, implicit, style))
	e.emit()
}

"""



```