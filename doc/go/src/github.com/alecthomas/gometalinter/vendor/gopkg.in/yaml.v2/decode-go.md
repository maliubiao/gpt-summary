Response:
Let's break down the thought process for analyzing the provided Go code.

1. **Understand the Goal:** The core request is to explain the functionality of the provided Go code snippet, which is part of a YAML decoding library. The prompt specifically asks for features, the Go feature it implements, examples, handling of command-line arguments (if any), and common mistakes.

2. **Initial Scan and Identify Key Structures:**  A quick skim reveals several important elements:
    * **Package `yaml`:**  Indicates this code is part of a YAML parsing and handling library.
    * **Constants (documentNode, mappingNode, etc.):** These look like flags representing different types of YAML nodes.
    * **`node` struct:**  This seems to be the internal representation of a YAML node, holding its kind, line/column, tag, value, children, and anchors.
    * **`parser` struct:**  This likely handles the raw parsing of the YAML input into the `node` tree.
    * **`decoder` struct:** This appears to be responsible for converting the `node` tree into Go data structures.
    * **Methods on `parser` (e.g., `newParser`, `parse`, `scalar`, `mapping`):** These suggest the steps involved in parsing the YAML.
    * **Methods on `decoder` (e.g., `unmarshal`, `scalar`, `mapping`, `sequence`):**  These suggest the steps involved in converting the parsed YAML into Go types.
    * **`Unmarshaler` interface:** This hints at custom handling of YAML decoding for specific Go types.

3. **Focus on the `parser`:**  The `parser` seems to be the entry point for processing the raw YAML input.
    * **`newParser(b []byte)`:**  Initializes the parser with the input byte slice. The `yaml_parser_*` functions suggest it's likely using a C library (like libyaml) under the hood.
    * **`parse()`:**  The central parsing function, deciding what to do based on the `event.typ`. This switch statement clearly maps YAML event types (scalar, alias, mapping, sequence, document) to corresponding handling methods. This strongly suggests a *state machine* or *event-driven parsing* approach.
    * **`scalar()`, `mapping()`, `sequence()`, `alias()`, `document()`:** These methods are responsible for building the `node` tree based on the specific YAML structure.

4. **Focus on the `decoder`:** The `decoder` takes the `node` tree and converts it to Go values.
    * **`unmarshal(n *node, out reflect.Value)`:** This is the core decoding function. It handles different `node` kinds and uses Go reflection (`reflect` package) to interact with the target Go value.
    * **`scalar()`, `mapping()`, `sequence()`:** Similar to the parser, these methods handle the conversion of different YAML node types to Go types. The use of `reflect` is key here for dynamically setting values based on the target Go type.
    * **`prepare()`:**  This method looks important for handling pointers and the `Unmarshaler` interface. It ensures the output value is ready to be populated.
    * **`callUnmarshaler()`:**  This method demonstrates the support for custom decoding logic, allowing users to define how their types are unmarshaled from YAML.
    * **Type Conversions (within `decoder.scalar`):**  The code explicitly handles conversions from YAML scalars (strings, numbers, booleans) to various Go types (string, int, uint, bool, float, time.Duration). This is a crucial part of the decoding process.

5. **Infer the Overall Functionality:** Based on the structures and methods, it's clear that this code implements the *decoding* or *unmarshaling* of YAML data into Go data structures. The `parser` builds an intermediate representation (`node` tree), and the `decoder` then traverses this tree, using reflection to populate the provided Go value.

6. **Identify Key Go Features:** The most prominent Go features used here are:
    * **Structs:** `node`, `parser`, `decoder` for organizing data.
    * **Methods:**  For defining behavior on these structs.
    * **Interfaces:** `Unmarshaler` and `encoding.TextUnmarshaler` for custom decoding.
    * **Reflection (`reflect` package):**  Essential for dynamically inspecting and setting Go values during decoding.
    * **Pointers:** Used extensively for passing and modifying data.
    * **Error Handling:**  Using `panic` and a custom `TypeError`.
    * **Constants and `iota`:** For defining node types.
    * **String Conversion (`strconv`):** For converting strings to numbers.

7. **Construct Examples:**  Create simple YAML examples and the corresponding Go structs to demonstrate the decoding process for scalars, sequences, and mappings. Think about how the YAML structure will map to the Go struct fields.

8. **Consider Command-Line Arguments:**  Review the code for any interaction with `os.Args` or similar mechanisms. In this snippet, there's no direct handling of command-line arguments. It's a library function.

9. **Identify Potential Pitfalls:** Think about common mistakes users might make when using a YAML decoding library. Focus on type mismatches, incorrect struct tags, and forgetting to handle errors. The provided code has error handling, but users might ignore the returned errors. Also, the handling of private fields is a common stumbling block in Go.

10. **Structure the Answer:** Organize the findings into clear sections: Functionality, Go Feature Implementation (with examples), Command-line Arguments, and Common Mistakes. Use clear and concise language, and provide code examples to illustrate the concepts.

This methodical approach, starting with a high-level overview and then drilling down into the details of the code, allows for a comprehensive understanding and the ability to address all aspects of the prompt. The key is to identify the core responsibilities of the different components and how they interact to achieve the overall goal of YAML decoding.
这段Go语言代码是 `go-yaml.v2` 库中负责将 YAML 文本解码（unmarshal）成 Go 语言数据结构的一部分。它主要实现了以下功能：

1. **YAML 解析 (Parsing):**
   - 代码中定义了一个 `parser` 结构体，它内部包含一个 `yaml_parser_t` (很可能来自 C 语言的 libyaml 库的结构体) 和一个 `yaml_event_t`。
   - `newParser(b []byte)` 函数创建了一个新的解析器，并使用 `yaml_parser_set_input_string` 将输入的 YAML 字节流传递给底层的 libyaml 解析器。
   - `parse()` 方法是核心的解析逻辑，它通过不断调用底层的 `yaml_parser_parse` 来获取 YAML 事件，并根据事件类型（`yaml_SCALAR_EVENT`, `yaml_MAPPING_START_EVENT` 等）构建一个代表 YAML 文档结构的 `node` 树。
   - `node` 结构体是用来表示 YAML 文档中的各种节点（例如：文档、映射、序列、标量和别名）。

2. **YAML 解码 (Decoding/Unmarshaling):**
   - 代码中定义了一个 `decoder` 结构体，它负责将解析器生成的 `node` 树转换为 Go 语言的值。
   - `newDecoder()` 函数创建一个新的解码器。
   - `unmarshal(n *node, out reflect.Value)` 方法是核心的解码逻辑。它递归地遍历 `node` 树，并使用 Go 语言的反射 (`reflect` 包) 将 YAML 数据填充到 `out` 参数指向的 Go 变量中。
   - `scalar()`, `sequence()`, `mapping()` 等方法分别处理不同类型的 YAML 节点，并将它们转换为相应的 Go 类型（例如，YAML 标量转换为字符串、数字、布尔值等，YAML 序列转换为切片，YAML 映射转换为结构体或 map）。
   - 代码支持通过 `Unmarshaler` 接口进行自定义解码，如果 Go 类型的指针实现了该接口，解码器会调用其 `UnmarshalYAML` 方法。
   - 代码还支持通过 `encoding.TextUnmarshaler` 接口将 YAML 标量解码为实现了该接口的 Go 类型。

3. **处理 YAML 特性:**
   - **锚点和别名 (`anchor` 和 `alias`):**  解析器会记录 YAML 中的锚点 (`&`)，解码器在遇到别名 (`*`) 时，会查找对应的锚点节点并复用其值，避免循环引用。
   - **标签 (`tag`):**  解析器会提取 YAML 节点上的标签（例如 `!!int`，`!!str`），解码器会根据标签进行类型转换。如果没有显式标签，则尝试进行隐式类型推断。
   - **合并 (`merge`):**  支持 YAML 的 `<<` 合并特性，可以将一个映射或多个映射的内容合并到当前的映射中。

**它是什么Go语言功能的实现：**

这段代码实现了一个 YAML **解码器** 或 **反序列化器**。它将 YAML 格式的文本数据转换成 Go 语言可以理解和操作的数据结构。

**Go 代码举例说明：**

假设我们有以下 YAML 字符串：

```yaml
name: Alice
age: 30
hobbies:
  - reading
  - coding
```

我们可以使用这段代码（结合 `go-yaml.v2` 库的其他部分）将其解码为 Go 结构体：

```go
package main

import (
	"fmt"
	"gopkg.in/yaml.v2"
)

type Person struct {
	Name    string   `yaml:"name"`
	Age     int      `yaml:"age"`
	Hobbies []string `yaml:"hobbies"`
}

func main() {
	yamlData := `
name: Alice
age: 30
hobbies:
  - reading
  - coding
`

	var person Person
	err := yaml.Unmarshal([]byte(yamlData), &person)
	if err != nil {
		fmt.Println("Error unmarshaling YAML:", err)
		return
	}

	fmt.Printf("Name: %s\n", person.Name)
	fmt.Printf("Age: %d\n", person.Age)
	fmt.Printf("Hobbies: %v\n", person.Hobbies)
}
```

**假设的输入与输出：**

**输入 (YAML 字符串):**

```yaml
key: value
items:
  - item1
  - item2
count: 123
is_active: true
```

**Go 结构体：**

```go
type Data struct {
	Key      string    `yaml:"key"`
	Items    []string  `yaml:"items"`
	Count    int       `yaml:"count"`
	IsActive bool      `yaml:"is_active"`
}
```

**输出 (Go 结构体 `Data` 的实例):**

```
Data{
	Key:      "value",
	Items:    []string{"item1", "item2"},
	Count:    123,
	IsActive: true,
}
```

**代码推理：**

- `yaml.Unmarshal([]byte(yamlData), &person)` 函数会调用 `newParser` 创建一个解析器，并将 `yamlData` 传递给它。
- 解析器会遍历 YAML 数据，生成一个 `node` 树，表示 YAML 的结构。
- `yaml.Unmarshal` 内部会创建一个 `decoder` 实例。
- 解码器会根据 `Person` 结构体的 `yaml` 标签，将 `node` 树中的值映射到 `person` 变量的相应字段。例如，YAML 中的 `name` 对应 `Person` 结构体的 `Name` 字段，`age` 对应 `Age` 字段，以此类推。
- 对于 `hobbies` 字段，解码器会识别出它是一个 YAML 序列，并将其转换为 Go 的字符串切片。

**命令行参数的具体处理：**

这段代码本身并没有直接处理命令行参数。`go-yaml.v2` 库主要是一个用于解析和生成 YAML 数据的库，它通常被其他应用程序或工具使用。如果需要从命令行读取 YAML 数据，你需要使用 Go 的 `os` 包或其他相关的库来获取命令行参数或读取文件内容，然后将这些数据传递给 `yaml.Unmarshal` 函数。

**使用者易犯错的点：**

1. **Go 结构体字段的 `yaml` 标签不正确或缺失：** 解码器依赖于 `yaml` 标签将 YAML 的键映射到 Go 结构体的字段。如果标签不正确或者字段没有标签，解码器可能无法正确地将 YAML 数据填充到结构体中。

   ```go
   type IncorrectPerson struct {
       FullName string `yaml:"name"` // 正确
       Years int // 缺失标签，YAML 中的 age 字段不会被解码到这里
   }

   yamlData := `
   name: Bob
   age: 40
   `

   var person IncorrectPerson
   yaml.Unmarshal([]byte(yamlData), &person)
   fmt.Println(person.FullName) // 输出: Bob
   fmt.Println(person.Years)    // 输出: 0 (未被赋值)
   ```

2. **YAML 数据类型与 Go 结构体字段类型不匹配：**  如果 YAML 中的数据类型与 Go 结构体字段的类型不兼容，解码器会尝试进行类型转换，但如果无法转换则会报错。

   ```go
   type Data struct {
       Count int `yaml:"count"`
   }

   yamlData := `
   count: "abc" # YAML 中是字符串，Go 中是 int
   `

   var data Data
   err := yaml.Unmarshal([]byte(yamlData), &data)
   if err != nil {
       fmt.Println("Error unmarshaling YAML:", err) // 会报错，无法将 "abc" 转换为 int
   }
   ```

3. **尝试解码到未导出的结构体字段：** Go 的反射机制无法访问未导出的结构体字段（字段名以小写字母开头），因此解码器也无法将 YAML 数据填充到这些字段中。

   ```go
   type PrivateData struct {
       value string `yaml:"value"` // 未导出的字段
   }

   yamlData := `
   value: secret
   `

   var data PrivateData
   yaml.Unmarshal([]byte(yamlData), &data)
   fmt.Println(data.value) // 输出: "" (未被赋值)
   ```

4. **忽略 `yaml.Unmarshal` 函数返回的错误：**  `yaml.Unmarshal` 在解码过程中如果遇到错误（例如，YAML 格式错误、类型不匹配等）会返回 `error`。开发者应该检查并处理这些错误，以确保程序的健壮性。

   ```go
   yamlData := `
   invalid yaml:
   - not a valid sequence
   `

   var data map[string]interface{}
   err := yaml.Unmarshal([]byte(yamlData), &data)
   if err != nil {
       fmt.Println("Error unmarshaling YAML:", err) // 应该处理这个错误
   }
   ```

总之，这段代码是 `go-yaml.v2` 库中 YAML 解码功能的核心实现，它负责将 YAML 文本转换为 Go 语言的数据结构，并支持 YAML 的多种特性。理解其工作原理有助于更好地使用该库并避免常见的错误。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/vendor/gopkg.in/yaml.v2/decode.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package yaml

import (
	"encoding"
	"encoding/base64"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"time"
)

const (
	documentNode = 1 << iota
	mappingNode
	sequenceNode
	scalarNode
	aliasNode
)

type node struct {
	kind         int
	line, column int
	tag          string
	value        string
	implicit     bool
	children     []*node
	anchors      map[string]*node
}

// ----------------------------------------------------------------------------
// Parser, produces a node tree out of a libyaml event stream.

type parser struct {
	parser yaml_parser_t
	event  yaml_event_t
	doc    *node
}

func newParser(b []byte) *parser {
	p := parser{}
	if !yaml_parser_initialize(&p.parser) {
		panic("failed to initialize YAML emitter")
	}

	if len(b) == 0 {
		b = []byte{'\n'}
	}

	yaml_parser_set_input_string(&p.parser, b)

	p.skip()
	if p.event.typ != yaml_STREAM_START_EVENT {
		panic("expected stream start event, got " + strconv.Itoa(int(p.event.typ)))
	}
	p.skip()
	return &p
}

func (p *parser) destroy() {
	if p.event.typ != yaml_NO_EVENT {
		yaml_event_delete(&p.event)
	}
	yaml_parser_delete(&p.parser)
}

func (p *parser) skip() {
	if p.event.typ != yaml_NO_EVENT {
		if p.event.typ == yaml_STREAM_END_EVENT {
			failf("attempted to go past the end of stream; corrupted value?")
		}
		yaml_event_delete(&p.event)
	}
	if !yaml_parser_parse(&p.parser, &p.event) {
		p.fail()
	}
}

func (p *parser) fail() {
	var where string
	var line int
	if p.parser.problem_mark.line != 0 {
		line = p.parser.problem_mark.line
	} else if p.parser.context_mark.line != 0 {
		line = p.parser.context_mark.line
	}
	if line != 0 {
		where = "line " + strconv.Itoa(line) + ": "
	}
	var msg string
	if len(p.parser.problem) > 0 {
		msg = p.parser.problem
	} else {
		msg = "unknown problem parsing YAML content"
	}
	failf("%s%s", where, msg)
}

func (p *parser) anchor(n *node, anchor []byte) {
	if anchor != nil {
		p.doc.anchors[string(anchor)] = n
	}
}

func (p *parser) parse() *node {
	switch p.event.typ {
	case yaml_SCALAR_EVENT:
		return p.scalar()
	case yaml_ALIAS_EVENT:
		return p.alias()
	case yaml_MAPPING_START_EVENT:
		return p.mapping()
	case yaml_SEQUENCE_START_EVENT:
		return p.sequence()
	case yaml_DOCUMENT_START_EVENT:
		return p.document()
	case yaml_STREAM_END_EVENT:
		// Happens when attempting to decode an empty buffer.
		return nil
	default:
		panic("attempted to parse unknown event: " + strconv.Itoa(int(p.event.typ)))
	}
	panic("unreachable")
}

func (p *parser) node(kind int) *node {
	return &node{
		kind:   kind,
		line:   p.event.start_mark.line,
		column: p.event.start_mark.column,
	}
}

func (p *parser) document() *node {
	n := p.node(documentNode)
	n.anchors = make(map[string]*node)
	p.doc = n
	p.skip()
	n.children = append(n.children, p.parse())
	if p.event.typ != yaml_DOCUMENT_END_EVENT {
		panic("expected end of document event but got " + strconv.Itoa(int(p.event.typ)))
	}
	p.skip()
	return n
}

func (p *parser) alias() *node {
	n := p.node(aliasNode)
	n.value = string(p.event.anchor)
	p.skip()
	return n
}

func (p *parser) scalar() *node {
	n := p.node(scalarNode)
	n.value = string(p.event.value)
	n.tag = string(p.event.tag)
	n.implicit = p.event.implicit
	p.anchor(n, p.event.anchor)
	p.skip()
	return n
}

func (p *parser) sequence() *node {
	n := p.node(sequenceNode)
	p.anchor(n, p.event.anchor)
	p.skip()
	for p.event.typ != yaml_SEQUENCE_END_EVENT {
		n.children = append(n.children, p.parse())
	}
	p.skip()
	return n
}

func (p *parser) mapping() *node {
	n := p.node(mappingNode)
	p.anchor(n, p.event.anchor)
	p.skip()
	for p.event.typ != yaml_MAPPING_END_EVENT {
		n.children = append(n.children, p.parse(), p.parse())
	}
	p.skip()
	return n
}

// ----------------------------------------------------------------------------
// Decoder, unmarshals a node into a provided value.

type decoder struct {
	doc     *node
	aliases map[string]bool
	mapType reflect.Type
	terrors []string
}

var (
	mapItemType    = reflect.TypeOf(MapItem{})
	durationType   = reflect.TypeOf(time.Duration(0))
	defaultMapType = reflect.TypeOf(map[interface{}]interface{}{})
	ifaceType      = defaultMapType.Elem()
)

func newDecoder() *decoder {
	d := &decoder{mapType: defaultMapType}
	d.aliases = make(map[string]bool)
	return d
}

func (d *decoder) terror(n *node, tag string, out reflect.Value) {
	if n.tag != "" {
		tag = n.tag
	}
	value := n.value
	if tag != yaml_SEQ_TAG && tag != yaml_MAP_TAG {
		if len(value) > 10 {
			value = " `" + value[:7] + "...`"
		} else {
			value = " `" + value + "`"
		}
	}
	d.terrors = append(d.terrors, fmt.Sprintf("line %d: cannot unmarshal %s%s into %s", n.line+1, shortTag(tag), value, out.Type()))
}

func (d *decoder) callUnmarshaler(n *node, u Unmarshaler) (good bool) {
	terrlen := len(d.terrors)
	err := u.UnmarshalYAML(func(v interface{}) (err error) {
		defer handleErr(&err)
		d.unmarshal(n, reflect.ValueOf(v))
		if len(d.terrors) > terrlen {
			issues := d.terrors[terrlen:]
			d.terrors = d.terrors[:terrlen]
			return &TypeError{issues}
		}
		return nil
	})
	if e, ok := err.(*TypeError); ok {
		d.terrors = append(d.terrors, e.Errors...)
		return false
	}
	if err != nil {
		fail(err)
	}
	return true
}

// d.prepare initializes and dereferences pointers and calls UnmarshalYAML
// if a value is found to implement it.
// It returns the initialized and dereferenced out value, whether
// unmarshalling was already done by UnmarshalYAML, and if so whether
// its types unmarshalled appropriately.
//
// If n holds a null value, prepare returns before doing anything.
func (d *decoder) prepare(n *node, out reflect.Value) (newout reflect.Value, unmarshaled, good bool) {
	if n.tag == yaml_NULL_TAG || n.kind == scalarNode && n.tag == "" && (n.value == "null" || n.value == "" && n.implicit) {
		return out, false, false
	}
	again := true
	for again {
		again = false
		if out.Kind() == reflect.Ptr {
			if out.IsNil() {
				out.Set(reflect.New(out.Type().Elem()))
			}
			out = out.Elem()
			again = true
		}
		if out.CanAddr() {
			if u, ok := out.Addr().Interface().(Unmarshaler); ok {
				good = d.callUnmarshaler(n, u)
				return out, true, good
			}
		}
	}
	return out, false, false
}

func (d *decoder) unmarshal(n *node, out reflect.Value) (good bool) {
	switch n.kind {
	case documentNode:
		return d.document(n, out)
	case aliasNode:
		return d.alias(n, out)
	}
	out, unmarshaled, good := d.prepare(n, out)
	if unmarshaled {
		return good
	}
	switch n.kind {
	case scalarNode:
		good = d.scalar(n, out)
	case mappingNode:
		good = d.mapping(n, out)
	case sequenceNode:
		good = d.sequence(n, out)
	default:
		panic("internal error: unknown node kind: " + strconv.Itoa(n.kind))
	}
	return good
}

func (d *decoder) document(n *node, out reflect.Value) (good bool) {
	if len(n.children) == 1 {
		d.doc = n
		d.unmarshal(n.children[0], out)
		return true
	}
	return false
}

func (d *decoder) alias(n *node, out reflect.Value) (good bool) {
	an, ok := d.doc.anchors[n.value]
	if !ok {
		failf("unknown anchor '%s' referenced", n.value)
	}
	if d.aliases[n.value] {
		failf("anchor '%s' value contains itself", n.value)
	}
	d.aliases[n.value] = true
	good = d.unmarshal(an, out)
	delete(d.aliases, n.value)
	return good
}

var zeroValue reflect.Value

func resetMap(out reflect.Value) {
	for _, k := range out.MapKeys() {
		out.SetMapIndex(k, zeroValue)
	}
}

func (d *decoder) scalar(n *node, out reflect.Value) (good bool) {
	var tag string
	var resolved interface{}
	if n.tag == "" && !n.implicit {
		tag = yaml_STR_TAG
		resolved = n.value
	} else {
		tag, resolved = resolve(n.tag, n.value)
		if tag == yaml_BINARY_TAG {
			data, err := base64.StdEncoding.DecodeString(resolved.(string))
			if err != nil {
				failf("!!binary value contains invalid base64 data")
			}
			resolved = string(data)
		}
	}
	if resolved == nil {
		if out.Kind() == reflect.Map && !out.CanAddr() {
			resetMap(out)
		} else {
			out.Set(reflect.Zero(out.Type()))
		}
		return true
	}
	if s, ok := resolved.(string); ok && out.CanAddr() {
		if u, ok := out.Addr().Interface().(encoding.TextUnmarshaler); ok {
			err := u.UnmarshalText([]byte(s))
			if err != nil {
				fail(err)
			}
			return true
		}
	}
	switch out.Kind() {
	case reflect.String:
		if tag == yaml_BINARY_TAG {
			out.SetString(resolved.(string))
			good = true
		} else if resolved != nil {
			out.SetString(n.value)
			good = true
		}
	case reflect.Interface:
		if resolved == nil {
			out.Set(reflect.Zero(out.Type()))
		} else {
			out.Set(reflect.ValueOf(resolved))
		}
		good = true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		switch resolved := resolved.(type) {
		case int:
			if !out.OverflowInt(int64(resolved)) {
				out.SetInt(int64(resolved))
				good = true
			}
		case int64:
			if !out.OverflowInt(resolved) {
				out.SetInt(resolved)
				good = true
			}
		case uint64:
			if resolved <= math.MaxInt64 && !out.OverflowInt(int64(resolved)) {
				out.SetInt(int64(resolved))
				good = true
			}
		case float64:
			if resolved <= math.MaxInt64 && !out.OverflowInt(int64(resolved)) {
				out.SetInt(int64(resolved))
				good = true
			}
		case string:
			if out.Type() == durationType {
				d, err := time.ParseDuration(resolved)
				if err == nil {
					out.SetInt(int64(d))
					good = true
				}
			}
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		switch resolved := resolved.(type) {
		case int:
			if resolved >= 0 && !out.OverflowUint(uint64(resolved)) {
				out.SetUint(uint64(resolved))
				good = true
			}
		case int64:
			if resolved >= 0 && !out.OverflowUint(uint64(resolved)) {
				out.SetUint(uint64(resolved))
				good = true
			}
		case uint64:
			if !out.OverflowUint(uint64(resolved)) {
				out.SetUint(uint64(resolved))
				good = true
			}
		case float64:
			if resolved <= math.MaxUint64 && !out.OverflowUint(uint64(resolved)) {
				out.SetUint(uint64(resolved))
				good = true
			}
		}
	case reflect.Bool:
		switch resolved := resolved.(type) {
		case bool:
			out.SetBool(resolved)
			good = true
		}
	case reflect.Float32, reflect.Float64:
		switch resolved := resolved.(type) {
		case int:
			out.SetFloat(float64(resolved))
			good = true
		case int64:
			out.SetFloat(float64(resolved))
			good = true
		case uint64:
			out.SetFloat(float64(resolved))
			good = true
		case float64:
			out.SetFloat(resolved)
			good = true
		}
	case reflect.Ptr:
		if out.Type().Elem() == reflect.TypeOf(resolved) {
			// TODO DOes this make sense? When is out a Ptr except when decoding a nil value?
			elem := reflect.New(out.Type().Elem())
			elem.Elem().Set(reflect.ValueOf(resolved))
			out.Set(elem)
			good = true
		}
	}
	if !good {
		d.terror(n, tag, out)
	}
	return good
}

func settableValueOf(i interface{}) reflect.Value {
	v := reflect.ValueOf(i)
	sv := reflect.New(v.Type()).Elem()
	sv.Set(v)
	return sv
}

func (d *decoder) sequence(n *node, out reflect.Value) (good bool) {
	l := len(n.children)

	var iface reflect.Value
	switch out.Kind() {
	case reflect.Slice:
		out.Set(reflect.MakeSlice(out.Type(), l, l))
	case reflect.Interface:
		// No type hints. Will have to use a generic sequence.
		iface = out
		out = settableValueOf(make([]interface{}, l))
	default:
		d.terror(n, yaml_SEQ_TAG, out)
		return false
	}
	et := out.Type().Elem()

	j := 0
	for i := 0; i < l; i++ {
		e := reflect.New(et).Elem()
		if ok := d.unmarshal(n.children[i], e); ok {
			out.Index(j).Set(e)
			j++
		}
	}
	out.Set(out.Slice(0, j))
	if iface.IsValid() {
		iface.Set(out)
	}
	return true
}

func (d *decoder) mapping(n *node, out reflect.Value) (good bool) {
	switch out.Kind() {
	case reflect.Struct:
		return d.mappingStruct(n, out)
	case reflect.Slice:
		return d.mappingSlice(n, out)
	case reflect.Map:
		// okay
	case reflect.Interface:
		if d.mapType.Kind() == reflect.Map {
			iface := out
			out = reflect.MakeMap(d.mapType)
			iface.Set(out)
		} else {
			slicev := reflect.New(d.mapType).Elem()
			if !d.mappingSlice(n, slicev) {
				return false
			}
			out.Set(slicev)
			return true
		}
	default:
		d.terror(n, yaml_MAP_TAG, out)
		return false
	}
	outt := out.Type()
	kt := outt.Key()
	et := outt.Elem()

	mapType := d.mapType
	if outt.Key() == ifaceType && outt.Elem() == ifaceType {
		d.mapType = outt
	}

	if out.IsNil() {
		out.Set(reflect.MakeMap(outt))
	}
	l := len(n.children)
	for i := 0; i < l; i += 2 {
		if isMerge(n.children[i]) {
			d.merge(n.children[i+1], out)
			continue
		}
		k := reflect.New(kt).Elem()
		if d.unmarshal(n.children[i], k) {
			kkind := k.Kind()
			if kkind == reflect.Interface {
				kkind = k.Elem().Kind()
			}
			if kkind == reflect.Map || kkind == reflect.Slice {
				failf("invalid map key: %#v", k.Interface())
			}
			e := reflect.New(et).Elem()
			if d.unmarshal(n.children[i+1], e) {
				out.SetMapIndex(k, e)
			}
		}
	}
	d.mapType = mapType
	return true
}

func (d *decoder) mappingSlice(n *node, out reflect.Value) (good bool) {
	outt := out.Type()
	if outt.Elem() != mapItemType {
		d.terror(n, yaml_MAP_TAG, out)
		return false
	}

	mapType := d.mapType
	d.mapType = outt

	var slice []MapItem
	var l = len(n.children)
	for i := 0; i < l; i += 2 {
		if isMerge(n.children[i]) {
			d.merge(n.children[i+1], out)
			continue
		}
		item := MapItem{}
		k := reflect.ValueOf(&item.Key).Elem()
		if d.unmarshal(n.children[i], k) {
			v := reflect.ValueOf(&item.Value).Elem()
			if d.unmarshal(n.children[i+1], v) {
				slice = append(slice, item)
			}
		}
	}
	out.Set(reflect.ValueOf(slice))
	d.mapType = mapType
	return true
}

func (d *decoder) mappingStruct(n *node, out reflect.Value) (good bool) {
	sinfo, err := getStructInfo(out.Type())
	if err != nil {
		panic(err)
	}
	name := settableValueOf("")
	l := len(n.children)

	var inlineMap reflect.Value
	var elemType reflect.Type
	if sinfo.InlineMap != -1 {
		inlineMap = out.Field(sinfo.InlineMap)
		inlineMap.Set(reflect.New(inlineMap.Type()).Elem())
		elemType = inlineMap.Type().Elem()
	}

	for i := 0; i < l; i += 2 {
		ni := n.children[i]
		if isMerge(ni) {
			d.merge(n.children[i+1], out)
			continue
		}
		if !d.unmarshal(ni, name) {
			continue
		}
		if info, ok := sinfo.FieldsMap[name.String()]; ok {
			var field reflect.Value
			if info.Inline == nil {
				field = out.Field(info.Num)
			} else {
				field = out.FieldByIndex(info.Inline)
			}
			d.unmarshal(n.children[i+1], field)
		} else if sinfo.InlineMap != -1 {
			if inlineMap.IsNil() {
				inlineMap.Set(reflect.MakeMap(inlineMap.Type()))
			}
			value := reflect.New(elemType).Elem()
			d.unmarshal(n.children[i+1], value)
			inlineMap.SetMapIndex(name, value)
		}
	}
	return true
}

func failWantMap() {
	failf("map merge requires map or sequence of maps as the value")
}

func (d *decoder) merge(n *node, out reflect.Value) {
	switch n.kind {
	case mappingNode:
		d.unmarshal(n, out)
	case aliasNode:
		an, ok := d.doc.anchors[n.value]
		if ok && an.kind != mappingNode {
			failWantMap()
		}
		d.unmarshal(n, out)
	case sequenceNode:
		// Step backwards as earlier nodes take precedence.
		for i := len(n.children) - 1; i >= 0; i-- {
			ni := n.children[i]
			if ni.kind == aliasNode {
				an, ok := d.doc.anchors[ni.value]
				if ok && an.kind != mappingNode {
					failWantMap()
				}
			} else if ni.kind != mappingNode {
				failWantMap()
			}
			d.unmarshal(ni, out)
		}
	default:
		failWantMap()
	}
}

func isMerge(n *node) bool {
	return n.kind == scalarNode && n.value == "<<" && (n.implicit == true || n.tag == yaml_MERGE_TAG)
}

"""



```