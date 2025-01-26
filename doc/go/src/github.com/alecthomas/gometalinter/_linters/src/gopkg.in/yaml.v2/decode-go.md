Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Purpose:**  The file path `go/src/github.com/alecthomas/gometalinter/_linters/src/gopkg.in/yaml.v2/decode.go` strongly suggests this code is responsible for *decoding* YAML data. The `decode.go` name is a clear indicator. The package name `yaml` reinforces this.

2. **High-Level Structure Scan:**  Quickly scan the code to identify major components:
    * **Constants:**  `documentNode`, `mappingNode`, etc. These look like enums representing different YAML node types.
    * **`node` struct:** This seems to be the fundamental data structure representing a YAML element. It holds the kind, line/column info, tag, value, and children. This likely forms a tree structure.
    * **`parser` struct:**  This looks like the component responsible for taking raw YAML input and building the `node` tree. It uses the `libyaml` C library.
    * **`decoder` struct:** This component seems to take the `node` tree and convert it into Go data structures.
    * **Functions starting with `new...`:**  These are constructors for the `parser` and `decoder`.
    * **Methods on `parser`:**  `init`, `destroy`, `expect`, `peek`, `fail`, `parse`, `scalar`, `mapping`, `sequence`, `document`, `alias`. These clearly relate to the parsing process. The names are very descriptive of YAML concepts.
    * **Methods on `decoder`:** `terror`, `callUnmarshaler`, `prepare`, `unmarshal`, `document`, `alias`, `scalar`, `sequence`, `mapping`, `mappingStruct`, `mappingSlice`, `merge`. These relate to taking the parsed `node` structure and turning it into Go types.

3. **Focus on Key Responsibilities (Parsing vs. Decoding):**  Recognize the separation of concerns between parsing (turning text into a structured representation) and decoding (turning the structured representation into Go types).

4. **Analyze the `parser`:**
    * **Input Handling:** `newParser(b []byte)` and `newParserFromReader(r io.Reader)` show it can handle both byte slices and `io.Reader` as input. This is standard practice for input handling in Go.
    * **Event-Driven:** The `expect` and `peek` methods, along with the `yaml_event_t` type, strongly suggest an event-driven parsing approach, likely based on the underlying `libyaml` library.
    * **Node Construction:** The `parse`, `scalar`, `mapping`, `sequence`, `document`, and `alias` methods build the `node` tree structure.
    * **Error Handling:** The `fail` method handles parsing errors.

5. **Analyze the `decoder`:**
    * **Input:** The `decoder` takes a `node` tree (`doc *node`).
    * **Output:** The `unmarshal` methods aim to populate the fields of Go structs or create Go maps/slices.
    * **Reflection:** The extensive use of `reflect` package functions (`reflect.ValueOf`, `reflect.TypeOf`, `out.Kind()`, `out.Set()`, etc.) is a clear indication that this is doing dynamic type conversion based on the structure of the YAML and the target Go type.
    * **`Unmarshaler` Interface:** The `callUnmarshaler` method shows support for custom unmarshaling logic via the `Unmarshaler` interface. This is a common pattern in Go serialization libraries.
    * **Type Conversions:** The `scalar` method has a large switch statement handling different Go types (string, int, bool, float, struct, etc.) and attempting to convert the YAML scalar value to those types.
    * **Mapping and Sequences:** The `mapping` and `sequence` methods handle YAML maps and lists, recursively calling `unmarshal` for their children.
    * **Anchors and Aliases:** The `alias` method deals with YAML anchors and references (`&` and `*`).
    * **Merge:** The `merge` method implements the YAML merge key (`<<`).

6. **Infer Go Feature Implementation:**  Based on the above analysis, it's clear this code implements YAML decoding in Go. Specifically:
    * **Parsing YAML:** The `parser` handles the lexical analysis and syntax tree construction.
    * **Unmarshaling YAML to Go Types:** The `decoder` takes the parsed tree and converts it into Go data structures.
    * **Support for Basic YAML Types:** Scalars (strings, numbers, booleans), sequences (lists/arrays), and mappings (dictionaries/objects).
    * **Advanced YAML Features:** Anchors/aliases and merge keys.
    * **Custom Unmarshaling:** The `Unmarshaler` interface allows users to provide custom decoding logic for their types.
    * **Reflection-Based Decoding:** The code uses reflection to dynamically match YAML structures to Go types.

7. **Code Example Construction (Think Simple to Complex):** Start with a simple YAML example and show how it would be decoded into a Go struct. Then, demonstrate more complex scenarios like nested structures, lists, and maps. Crucially, show the *Go code* that would trigger this decoding, i.e., the use of `yaml.Unmarshal`.

8. **Command-Line Argument Handling (Check for Obvious Signs):** Scan the code for any command-line flag parsing logic (e.g., using the `flag` package). In this snippet, there's no explicit command-line argument handling. Note this explicitly.

9. **Common Pitfalls (Think about YAML's Quirks and Go's Type System):**
    * **Indentation Sensitivity:** YAML relies on indentation. Incorrect indentation is a very common error.
    * **Type Mismatches:**  Trying to decode a YAML string into a Go integer, for example, will cause errors.
    * **YAML Tags:**  While the code handles tags, users might misunderstand or misuse them.
    * **Anchors and Aliases (Circular References):** The code has a check for circular references in aliases, but users might still create complex alias structures that are hard to understand.
    * **Null Values:**  Understanding how YAML nulls are mapped to Go zero values is important.

10. **Refine and Organize:**  Structure the answer logically with clear headings and bullet points. Use precise language. Ensure the code examples are clear and runnable (even if they are illustrative).

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Is this just a parser?"  Realization: The `decoder` section is substantial, indicating both parsing and decoding are happening.
* **Considering command-line arguments:**  Looking for `flag.Parse()` or similar. Finding none, concluding it's not handled in *this specific snippet*. Important to be precise.
* **Thinking about errors:**  The `terror` method and the `TypeError` suggest the decoding process can fail due to type mismatches.
* **Example complexity:**  Start with a very basic example, then add complexity gradually to illustrate different aspects.

By following these steps, we can systematically analyze the code and generate a comprehensive and accurate description of its functionality.
这段代码是Go语言中用于解析（decoding）YAML格式数据的一部分。它主要负责将YAML文本转换为Go语言的数据结构。

让我们分解一下它的功能：

**1. 定义了YAML节点的表示 (`node` 结构体):**

   - `kind`:  表示节点的类型，例如 `documentNode`（文档）、`mappingNode`（映射/字典）、`sequenceNode`（序列/列表）、`scalarNode`（标量/基本类型值）、`aliasNode`（别名）。
   - `line`, `column`: 记录节点在YAML文档中的起始行号和列号，用于错误报告。
   - `tag`:  YAML的标签，用于显式指定数据类型。
   - `alias`: 如果节点是别名，则指向它引用的实际节点。
   - `value`: 对于标量节点，存储其字符串值。
   - `implicit`:  指示标签是否是隐式的（根据内容推断出来的）。
   - `children`: 对于映射和序列节点，存储其子节点的列表。
   - `anchors`:  在文档节点中，存储所有定义的锚点及其对应的节点。

**2. 实现了YAML解析器 (`parser` 结构体):**

   - `parser`: 嵌入了 `libyaml` C库的解析器对象 (`yaml_parser_t`)，这是实际进行YAML语法分析的引擎。
   - `event`: 存储当前解析到的YAML事件 (`yaml_event_t`)。YAML解析是基于事件流的。
   - `doc`: 指向当前正在解析的YAML文档的根节点。
   - `doneInit`: 标记解析器是否已初始化。

   **`parser` 的主要功能:**

   - **初始化和销毁:** `newParser` 和 `newParserFromReader` 创建解析器，可以从字节切片或 `io.Reader` 读取YAML数据。 `destroy` 方法清理解析器资源。
   - **事件处理:**
     - `expect`:  从事件流中消费一个事件，并检查其类型是否符合预期。
     - `peek`:  查看下一个事件的类型，但不消费它。
   - **错误处理:** `fail` 方法处理解析过程中遇到的错误，并生成带有行号信息的错误消息。
   - **构建节点树:**  `parse` 方法是核心，根据当前事件类型调用相应的子方法（`scalar`, `alias`, `mapping`, `sequence`, `document`）来创建和连接 `node` 结构体，形成一个表示YAML文档结构的树。
   - **处理锚点:** `anchor` 方法将节点与锚点名称关联起来。

**3. 实现了YAML解码器 (`decoder` 结构体):**

   - `doc`: 指向要解码的YAML文档的根节点（由 `parser` 生成）。
   - `aliases`:  用于检测循环引用的别名节点。
   - `mapType`:  用于解码interface{}类型的映射时的默认映射类型。
   - `terrors`: 存储解码过程中遇到的类型错误。
   - `strict`:  一个布尔值，控制是否进行严格的类型检查（例如，禁止重复的键）。

   **`decoder` 的主要功能:**

   - **`unmarshal`:**  这是解码的核心方法，它根据 `node` 的类型，将YAML数据解码到提供的Go语言变量中。它会递归地处理子节点。
   - **类型转换:**  `scalar` 方法负责将YAML标量值转换为Go的各种基本类型（字符串、整数、浮点数、布尔值等）。它会尝试根据YAML标签或内容进行推断。
   - **处理映射:** `mapping` 方法将YAML映射解码到Go的结构体或map中。它会根据结构体字段名或map的键来匹配YAML的键值对。
   - **处理序列:** `sequence` 方法将YAML序列解码到Go的切片或数组中。
   - **处理别名:** `alias` 方法解析YAML别名，并使用其引用的节点的值。
   - **处理文档:** `document` 方法处理YAML文档的根节点。
   - **处理 `Unmarshaler` 接口:** `callUnmarshaler` 方法允许Go类型实现 `Unmarshaler` 接口来自定义YAML解码的行为。
   - **合并键 (`merge`):**  实现了YAML的合并键 (`<<`) 功能，可以将其他映射的内容合并到当前映射中。
   - **错误报告:** `terror` 方法记录解码过程中遇到的类型错误。

**可以推理出它是什么Go语言功能的实现:**

这个代码片段是 `gopkg.in/yaml.v2` 库中用于将 YAML 数据反序列化（Unmarshal）到 Go 语言数据结构的实现。它实现了以下核心功能：

- **将 YAML 文本解析成内部的树状结构:** `parser` 负责完成这一步。
- **将内部的树状结构映射到 Go 语言的类型:** `decoder` 负责完成这一步，它使用反射来动态地创建和设置 Go 语言变量的值。
- **支持 YAML 的基本数据类型:** 标量（字符串、数字、布尔值等）、序列（列表）、映射（字典）。
- **支持 YAML 的高级特性:** 锚点和别名 (`&` 和 `*`)，合并键 (`<<`)。
- **支持自定义的类型转换:** 通过 `Unmarshaler` 接口。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"gopkg.in/yaml.v2"
)

type Person struct {
	Name string `yaml:"name"`
	Age  int    `yaml:"age"`
}

func main() {
	yamlData := `
name: Alice
age: 30
`

	var person Person
	err := yaml.Unmarshal([]byte(yamlData), &person)
	if err != nil {
		fmt.Println("Error unmarshaling YAML:", err)
		return
	}

	fmt.Printf("Name: %s, Age: %d\n", person.Name, person.Age)
}
```

**假设的输入与输出:**

**输入 (yamlData):**

```yaml
name: Bob
age: 25
address:
  street: "123 Main St"
  city: "Anytown"
```

**输出 (解码后的 `person` 变量):**

```go
type Person struct {
	Name    string `yaml:"name"`
	Age     int    `yaml:"age"`
	Address struct {
		Street string `yaml:"street"`
		City   string `yaml:"city"`
	} `yaml:"address"`
}

// ... 在 main 函数中 unmarshal ...

fmt.Printf("Name: %s, Age: %d, Address: {Street: %s, City: %s}\n",
	person.Name, person.Age, person.Address.Street, person.Address.City)
```

**输出结果:**

```
Name: Bob, Age: 25, Address: {Street: 123 Main St, City: Anytown}
```

**命令行参数的具体处理:**

这段代码本身**没有**直接处理命令行参数。`gopkg.in/yaml.v2` 库主要是一个用于 YAML 数据编解码的库，它专注于处理 YAML 格式的数据。命令行参数的处理通常是由调用此库的应用程序来完成的。应用程序可能会使用 `flag` 包或其他库来解析命令行参数，然后将相关配置传递给 YAML 解码过程。

**使用者易犯错的点:**

1. **YAML 格式错误:**  这是最常见的错误。YAML 对缩进非常敏感。不正确的缩进会导致解析错误。

   ```yaml
   # 错误的缩进
   name: Carol
  age: 40 # 这里缩进错误
   ```

   **错误示例:** 使用 `yaml.Unmarshal` 解析上述 YAML 时，会返回解析错误，指出缩进问题。

2. **Go 结构体字段标签不匹配:**  `yaml.Unmarshal` 依赖于 Go 结构体字段的 `yaml` 标签来匹配 YAML 的键。如果标签不正确或缺失，解码器可能无法正确地将 YAML 数据映射到结构体字段。

   ```go
   type Product struct {
       ProductName string `yaml:"product_name"` // YAML 中是 "product-name"
       Price       float64 `yaml:"price"`
   }

   yamlData := `
product-name: Laptop
price: 1200.00
`

   var product Product
   yaml.Unmarshal([]byte(yamlData), &product)
   fmt.Println(product.ProductName) // 输出为空字符串，因为标签不匹配
   ```

3. **类型不匹配:** 尝试将 YAML 的字符串值解码到 Go 的数字类型，或者反之，可能会导致错误。虽然 `yaml.v2` 会尽力进行类型转换，但某些情况下会失败。

   ```yaml
   age: "thirty" # 字符串 "thirty" 无法直接转换为 int

   type Person struct {
       Age int `yaml:"age"`
   }

   var person Person
   err := yaml.Unmarshal([]byte(yamlData), &person)
   fmt.Println(err) // 会输出类型转换错误
   ```

4. **处理 `interface{}` 类型的映射:** 当将 YAML 映射解码到 `map[string]interface{}` 或 `interface{}` 时，需要注意类型断言。解码器会尽力推断类型，但最终的值可能需要进行类型断言才能使用。

   ```yaml
   data:
     count: 10
     message: hello

   var result map[string]interface{}
   yaml.Unmarshal([]byte(yamlData), &result)

   count, ok := result["count"].(int) // 需要进行类型断言
   if ok {
       fmt.Println("Count:", count)
   }
   ```

理解这些功能和潜在的陷阱可以帮助开发者更有效地使用 `gopkg.in/yaml.v2` 库来处理 YAML 数据。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/gopkg.in/yaml.v2/decode.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"io"
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
	// For an alias node, alias holds the resolved alias.
	alias    *node
	value    string
	implicit bool
	children []*node
	anchors  map[string]*node
}

// ----------------------------------------------------------------------------
// Parser, produces a node tree out of a libyaml event stream.

type parser struct {
	parser   yaml_parser_t
	event    yaml_event_t
	doc      *node
	doneInit bool
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
	return &p
}

func newParserFromReader(r io.Reader) *parser {
	p := parser{}
	if !yaml_parser_initialize(&p.parser) {
		panic("failed to initialize YAML emitter")
	}
	yaml_parser_set_input_reader(&p.parser, r)
	return &p
}

func (p *parser) init() {
	if p.doneInit {
		return
	}
	p.expect(yaml_STREAM_START_EVENT)
	p.doneInit = true
}

func (p *parser) destroy() {
	if p.event.typ != yaml_NO_EVENT {
		yaml_event_delete(&p.event)
	}
	yaml_parser_delete(&p.parser)
}

// expect consumes an event from the event stream and
// checks that it's of the expected type.
func (p *parser) expect(e yaml_event_type_t) {
	if p.event.typ == yaml_NO_EVENT {
		if !yaml_parser_parse(&p.parser, &p.event) {
			p.fail()
		}
	}
	if p.event.typ == yaml_STREAM_END_EVENT {
		failf("attempted to go past the end of stream; corrupted value?")
	}
	if p.event.typ != e {
		p.parser.problem = fmt.Sprintf("expected %s event but got %s", e, p.event.typ)
		p.fail()
	}
	yaml_event_delete(&p.event)
	p.event.typ = yaml_NO_EVENT
}

// peek peeks at the next event in the event stream,
// puts the results into p.event and returns the event type.
func (p *parser) peek() yaml_event_type_t {
	if p.event.typ != yaml_NO_EVENT {
		return p.event.typ
	}
	if !yaml_parser_parse(&p.parser, &p.event) {
		p.fail()
	}
	return p.event.typ
}

func (p *parser) fail() {
	var where string
	var line int
	if p.parser.problem_mark.line != 0 {
		line = p.parser.problem_mark.line
		// Scanner errors don't iterate line before returning error
		if p.parser.error == yaml_SCANNER_ERROR {
			line++
		}
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
	p.init()
	switch p.peek() {
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
		panic("attempted to parse unknown event: " + p.event.typ.String())
	}
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
	p.expect(yaml_DOCUMENT_START_EVENT)
	n.children = append(n.children, p.parse())
	p.expect(yaml_DOCUMENT_END_EVENT)
	return n
}

func (p *parser) alias() *node {
	n := p.node(aliasNode)
	n.value = string(p.event.anchor)
	n.alias = p.doc.anchors[n.value]
	if n.alias == nil {
		failf("unknown anchor '%s' referenced", n.value)
	}
	p.expect(yaml_ALIAS_EVENT)
	return n
}

func (p *parser) scalar() *node {
	n := p.node(scalarNode)
	n.value = string(p.event.value)
	n.tag = string(p.event.tag)
	n.implicit = p.event.implicit
	p.anchor(n, p.event.anchor)
	p.expect(yaml_SCALAR_EVENT)
	return n
}

func (p *parser) sequence() *node {
	n := p.node(sequenceNode)
	p.anchor(n, p.event.anchor)
	p.expect(yaml_SEQUENCE_START_EVENT)
	for p.peek() != yaml_SEQUENCE_END_EVENT {
		n.children = append(n.children, p.parse())
	}
	p.expect(yaml_SEQUENCE_END_EVENT)
	return n
}

func (p *parser) mapping() *node {
	n := p.node(mappingNode)
	p.anchor(n, p.event.anchor)
	p.expect(yaml_MAPPING_START_EVENT)
	for p.peek() != yaml_MAPPING_END_EVENT {
		n.children = append(n.children, p.parse(), p.parse())
	}
	p.expect(yaml_MAPPING_END_EVENT)
	return n
}

// ----------------------------------------------------------------------------
// Decoder, unmarshals a node into a provided value.

type decoder struct {
	doc     *node
	aliases map[*node]bool
	mapType reflect.Type
	terrors []string
	strict  bool
}

var (
	mapItemType    = reflect.TypeOf(MapItem{})
	durationType   = reflect.TypeOf(time.Duration(0))
	defaultMapType = reflect.TypeOf(map[interface{}]interface{}{})
	ifaceType      = defaultMapType.Elem()
	timeType       = reflect.TypeOf(time.Time{})
	ptrTimeType    = reflect.TypeOf(&time.Time{})
)

func newDecoder(strict bool) *decoder {
	d := &decoder{mapType: defaultMapType, strict: strict}
	d.aliases = make(map[*node]bool)
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
	if n.tag == yaml_NULL_TAG || n.kind == scalarNode && n.tag == "" && (n.value == "null" || n.value == "~" || n.value == "" && n.implicit) {
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
	if d.aliases[n] {
		// TODO this could actually be allowed in some circumstances.
		failf("anchor '%s' value contains itself", n.value)
	}
	d.aliases[n] = true
	good = d.unmarshal(n.alias, out)
	delete(d.aliases, n)
	return good
}

var zeroValue reflect.Value

func resetMap(out reflect.Value) {
	for _, k := range out.MapKeys() {
		out.SetMapIndex(k, zeroValue)
	}
}

func (d *decoder) scalar(n *node, out reflect.Value) bool {
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
	if resolvedv := reflect.ValueOf(resolved); out.Type() == resolvedv.Type() {
		// We've resolved to exactly the type we want, so use that.
		out.Set(resolvedv)
		return true
	}
	// Perhaps we can use the value as a TextUnmarshaler to
	// set its value.
	if out.CanAddr() {
		u, ok := out.Addr().Interface().(encoding.TextUnmarshaler)
		if ok {
			var text []byte
			if tag == yaml_BINARY_TAG {
				text = []byte(resolved.(string))
			} else {
				// We let any value be unmarshaled into TextUnmarshaler.
				// That might be more lax than we'd like, but the
				// TextUnmarshaler itself should bowl out any dubious values.
				text = []byte(n.value)
			}
			err := u.UnmarshalText(text)
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
			return true
		}
		if resolved != nil {
			out.SetString(n.value)
			return true
		}
	case reflect.Interface:
		if resolved == nil {
			out.Set(reflect.Zero(out.Type()))
		} else if tag == yaml_TIMESTAMP_TAG {
			// It looks like a timestamp but for backward compatibility
			// reasons we set it as a string, so that code that unmarshals
			// timestamp-like values into interface{} will continue to
			// see a string and not a time.Time.
			// TODO(v3) Drop this.
			out.Set(reflect.ValueOf(n.value))
		} else {
			out.Set(reflect.ValueOf(resolved))
		}
		return true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		switch resolved := resolved.(type) {
		case int:
			if !out.OverflowInt(int64(resolved)) {
				out.SetInt(int64(resolved))
				return true
			}
		case int64:
			if !out.OverflowInt(resolved) {
				out.SetInt(resolved)
				return true
			}
		case uint64:
			if resolved <= math.MaxInt64 && !out.OverflowInt(int64(resolved)) {
				out.SetInt(int64(resolved))
				return true
			}
		case float64:
			if resolved <= math.MaxInt64 && !out.OverflowInt(int64(resolved)) {
				out.SetInt(int64(resolved))
				return true
			}
		case string:
			if out.Type() == durationType {
				d, err := time.ParseDuration(resolved)
				if err == nil {
					out.SetInt(int64(d))
					return true
				}
			}
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		switch resolved := resolved.(type) {
		case int:
			if resolved >= 0 && !out.OverflowUint(uint64(resolved)) {
				out.SetUint(uint64(resolved))
				return true
			}
		case int64:
			if resolved >= 0 && !out.OverflowUint(uint64(resolved)) {
				out.SetUint(uint64(resolved))
				return true
			}
		case uint64:
			if !out.OverflowUint(uint64(resolved)) {
				out.SetUint(uint64(resolved))
				return true
			}
		case float64:
			if resolved <= math.MaxUint64 && !out.OverflowUint(uint64(resolved)) {
				out.SetUint(uint64(resolved))
				return true
			}
		}
	case reflect.Bool:
		switch resolved := resolved.(type) {
		case bool:
			out.SetBool(resolved)
			return true
		}
	case reflect.Float32, reflect.Float64:
		switch resolved := resolved.(type) {
		case int:
			out.SetFloat(float64(resolved))
			return true
		case int64:
			out.SetFloat(float64(resolved))
			return true
		case uint64:
			out.SetFloat(float64(resolved))
			return true
		case float64:
			out.SetFloat(resolved)
			return true
		}
	case reflect.Struct:
		if resolvedv := reflect.ValueOf(resolved); out.Type() == resolvedv.Type() {
			out.Set(resolvedv)
			return true
		}
	case reflect.Ptr:
		if out.Type().Elem() == reflect.TypeOf(resolved) {
			// TODO DOes this make sense? When is out a Ptr except when decoding a nil value?
			elem := reflect.New(out.Type().Elem())
			elem.Elem().Set(reflect.ValueOf(resolved))
			out.Set(elem)
			return true
		}
	}
	d.terror(n, tag, out)
	return false
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
	case reflect.Array:
		if l != out.Len() {
			failf("invalid array: want %d elements but got %d", out.Len(), l)
		}
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
	if out.Kind() != reflect.Array {
		out.Set(out.Slice(0, j))
	}
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
				d.setMapIndex(n.children[i+1], out, k, e)
			}
		}
	}
	d.mapType = mapType
	return true
}

func (d *decoder) setMapIndex(n *node, out, k, v reflect.Value) {
	if d.strict && out.MapIndex(k) != zeroValue {
		d.terrors = append(d.terrors, fmt.Sprintf("line %d: key %#v already set in map", n.line+1, k.Interface()))
		return
	}
	out.SetMapIndex(k, v)
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

	var doneFields []bool
	if d.strict {
		doneFields = make([]bool, len(sinfo.FieldsList))
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
			if d.strict {
				if doneFields[info.Id] {
					d.terrors = append(d.terrors, fmt.Sprintf("line %d: field %s already set in type %s", ni.line+1, name.String(), out.Type()))
					continue
				}
				doneFields[info.Id] = true
			}
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
			d.setMapIndex(n.children[i+1], inlineMap, name, value)
		} else if d.strict {
			d.terrors = append(d.terrors, fmt.Sprintf("line %d: field %s not found in type %s", ni.line+1, name.String(), out.Type()))
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