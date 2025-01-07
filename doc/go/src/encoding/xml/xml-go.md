Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding - The Basics**

* **Language:** The code starts with `// Package xml`, immediately telling us this is the definition of the `xml` package in Go's standard library. This is crucial context.
* **Purpose:** The package comment explains its core function: "implements a simple XML 1.0 parser that understands XML name spaces." This is the most important takeaway.
* **Copyright & License:**  Standard boilerplate, not directly related to functionality but good to note.
* **Imports:**  A quick scan of the imports (`bufio`, `bytes`, `errors`, `fmt`, `io`, `strconv`, `strings`, `unicode`, `unicode/utf8`) gives hints about the operations the package performs (buffering, byte manipulation, error handling, string formatting, input/output, string conversions, character handling).

**2. Data Structures - Representing XML Concepts**

* **`SyntaxError`:**  Clearly for reporting parsing errors, including the line number. This is essential for debugging.
* **`Name`:** Represents an XML name, importantly including `Space` for namespaces and `Local` for the actual name. This is a core XML concept the package handles.
* **`Attr`:**  Represents an attribute within an XML element, linking a `Name` to a `Value`.
* **`Token`:**  A crucial interface. It's an empty interface (`any`), meaning it can hold any of the specific token types. This suggests a token-based parsing approach.
* **`StartElement`, `EndElement`, `CharData`, `Comment`, `ProcInst`, `Directive`:**  These concrete types implement the `Token` interface and represent the fundamental building blocks of an XML document. The comments for each clearly describe their XML counterparts. The `Copy()` methods hint at the internal buffer management strategy (avoiding data corruption).
* **`TokenReader`:** An interface defining something that can provide a stream of `Token`s. This is a good abstraction, as a `Decoder` itself implements this.
* **`Decoder`:** The central struct. It holds the state of the XML parser. The comments within the `Decoder` struct are extremely informative, explaining its fields and their purpose:
    * `Strict`:  Controls the level of XML conformance. This immediately signals a key configurability aspect.
    * `AutoClose`, `Entity`, `CharsetReader`, `DefaultSpace`: These are all configuration options that allow for customization of the parsing behavior. They indicate the flexibility of the parser.
    * Internal fields (`r`, `t`, `buf`, `saved`, `stk`, `free`, `needClose`, `toClose`, `nextToken`, `nextByte`, `ns`, `err`, `line`, `linestart`, `offset`, `unmarshalDepth`): These are implementation details, but their names provide some insight into the parsing process (buffering, stacks for element and namespace tracking, error handling, line counting, etc.).

**3. Key Functions - The Parsing Process**

* **`NewDecoder(r io.Reader)`:** The primary entry point for creating a decoder, taking an `io.Reader` as input.
* **`NewTokenDecoder(t TokenReader)`:**  Allows using a pre-existing `TokenReader`, showing flexibility.
* **`Token() (Token, error)`:**  The core parsing function. It returns the next `Token` from the input stream, along with a potential error. The detailed comment about EOF handling is important.
* **`CopyToken(t Token)`:**  Provides a way to get a copy of a `Token`, addressing the internal buffer sharing.
* **Helper functions within `Decoder`:**  Many private methods (like `rawToken`, `getc`, `ungetc`, `text`, `nsname`, `pushElement`, `popElement`, etc.) are responsible for the low-level parsing logic. Even without diving deep into their implementation, their names strongly suggest their roles.

**4. Inferring Functionality & Example (High-Level Reasoning)**

Based on the data structures and key functions, we can infer that the package provides functionality for:

* **Parsing XML:**  The core purpose, broken down into individual tokens.
* **Handling Namespaces:** The `Name` struct and the comments in `Decoder.Token` explicitly mention namespace handling.
* **Error Reporting:** The `SyntaxError` struct and the error returns from `Token()`.
* **Configuration:** The `Strict`, `AutoClose`, `Entity`, `CharsetReader`, and `DefaultSpace` fields in `Decoder` allow customization.

**5. Example Construction (Iterative Refinement)**

When creating the example, the thought process might go something like this:

* **Basic Parsing:** Start with the simplest case: reading a simple XML snippet. Use `NewDecoder` and a loop calling `Token()`. Print the type of each token.
* **Namespaces:** Add an element with a namespace prefix and a corresponding `xmlns` attribute. Check that the `Name.Space` is populated correctly in the `StartElement`.
* **Attributes:** Add attributes to an element and verify they are parsed into the `StartElement.Attr` slice.
* **Character Data:** Include text content within elements and verify it's parsed as `CharData`.
* **Error Handling (Conceptual):**  While not explicitly coded in this *simple* example, mentally consider how to trigger `SyntaxError` (e.g., mismatched tags).

**6. Identifying Potential Pitfalls**

Consider common mistakes when working with XML parsers:

* **Modifying Token Data:**  The "Slices of bytes...remain valid only until the next call to Token" warning is a huge clue. This leads to the example of incorrect modification and the advice to use `Copy()`.
* **Assuming String Data is Always Safe:** The byte slice nature of `CharData` and `Comment` needs emphasis. Converting to strings without considering encoding could lead to issues.
* **Forgetting to Handle Errors:** A classic programming mistake. Emphasize the importance of checking the error return from `Token()`.

**7. Structure and Language**

Organize the findings logically (Functionality, Core Feature, Code Example, Potential Issues). Use clear and concise language, avoiding overly technical jargon where possible. Keep the target audience in mind (someone who needs to understand the basic capabilities of this Go XML package).

**Self-Correction/Refinement During Analysis:**

* **Initial Thought:** "It just parses XML."  **Correction:**  "It parses XML *and handles namespaces* as a key feature."
* **Initial Thought:** "The internal fields of `Decoder` are just implementation details." **Refinement:** "While implementation details, their names *hint* at the underlying parsing mechanisms (stack, buffer)."
* **Initial Thought:** "Just show a basic parsing example." **Refinement:** "The example should demonstrate *key* features like namespaces and attributes to be more informative."

By following these steps, focusing on understanding the code's purpose, data structures, and core functions, we can arrive at a comprehensive and informative summary like the example provided.
这是对Go语言标准库 `encoding/xml` 包中 `xml.go` 文件的一部分代码的分析。这部分代码主要定义了 XML 解析过程中使用的数据结构和一些辅助方法，为后续的 XML 解析逻辑奠定了基础。

**功能归纳:**

这部分代码的主要功能是 **定义了用于表示 XML 文档结构的各种数据类型**。这些类型包括：

* **错误类型 (`SyntaxError`)**:  用于表示 XML 语法错误。
* **XML 命名实体 (`Name`)**:  用于表示 XML 元素或属性的名称，包含命名空间信息。
* **XML 属性 (`Attr`)**:  用于表示 XML 元素的属性，包含属性名和属性值。
* **XML 令牌 (`Token`)**:  一个接口，表示 XML 文档中的各种基本组成部分，如起始标签、结束标签、字符数据、注释、处理指令和指令。
* **具体的 XML 令牌类型**:
    * **起始标签 (`StartElement`)**: 表示 XML 的起始标签，包含标签名和属性列表。
    * **结束标签 (`EndElement`)**: 表示 XML 的结束标签，包含标签名。
    * **字符数据 (`CharData`)**: 表示 XML 中的文本内容。
    * **注释 (`Comment`)**: 表示 XML 注释。
    * **处理指令 (`ProcInst`)**: 表示 XML 处理指令。
    * **指令 (`Directive`)**: 表示 XML 指令 (例如 `<!DOCTYPE>`)。
* **令牌读取器接口 (`TokenReader`)**: 定义了从 XML 流中读取令牌的方法。
* **XML 解码器 (`Decoder`)**:  核心结构体，用于解析 XML 输入流。它包含了解析状态和配置信息。

**核心功能：定义 XML 数据结构**

这部分代码的核心在于定义了 Go 语言中表示 XML 文档组成部分的数据结构。这些结构体和接口使得 Go 程序可以方便地表示和操作 XML 文档的各个部分。例如，`StartElement` 结构体清晰地表示了一个起始标签及其包含的属性，而 `CharData` 则表示了文本内容。`Token` 接口则提供了一种统一的方式来处理不同类型的 XML 组成部分。

**Go 代码举例说明 (推理 `Decoder` 的基本用法):**

虽然这部分代码没有包含具体的解析逻辑，但我们可以根据已有的类型定义来推断 `Decoder` 的基本用法。假设我们有一个简单的 XML 字符串：

```xml
<bookstore>
  <book category="cooking">
    <title lang="en">Everyday Italian</title>
    <author>Giada De Laurentiis</author>
  </book>
</bookstore>
```

我们可以推断出 `Decoder` 的使用方式大致如下：

```go
package main

import (
	"encoding/xml"
	"fmt"
	"strings"
)

func main() {
	xmlData := `<bookstore><book category="cooking"><title lang="en">Everyday Italian</title><author>Giada De Laurentiis</author></book></bookstore>`
	decoder := xml.NewDecoder(strings.NewReader(xmlData))

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch se := token.(type) {
		case xml.StartElement:
			fmt.Printf("Start Element: Name=%+v, Attr=%+v\n", se.Name, se.Attr)
		case xml.EndElement:
			fmt.Printf("End Element: Name=%+v\n", se.Name)
		case xml.CharData:
			data := strings.TrimSpace(string(se))
			if data != "" {
				fmt.Printf("Char Data: [%s]\n", data)
			}
		case xml.Comment:
			fmt.Printf("Comment: [%s]\n", se)
		case xml.ProcInst:
			fmt.Printf("ProcInst: Target=%s, Inst=%s\n", se.Target, se.Inst)
		case xml.Directive:
			fmt.Printf("Directive: [%s]\n", se)
		}
	}
}
```

**假设的输入与输出:**

对于上述 XML 输入，假设 `Decoder.Token()` 方法能够逐个返回 XML 的组成部分，那么输出可能如下：

```
Start Element: Name={Space: Local:bookstore}, Attr:[]
Start Element: Name={Space: Local:book}, Attr:[{Name:{Space: Local:category} Value:cooking}]
Start Element: Name={Space: Local:title}, Attr:[{Name:{Space: Local:lang} Value:en}]
Char Data: [Everyday Italian]
End Element: Name={Space: Local:title}
Start Element: Name={Space: Local:author}, Attr:[]
Char Data: [Giada De Laurentiis]
End Element: Name={Space: Local:author}
End Element: Name={Space: Local:book}
End Element: Name={Space: Local:bookstore}
```

**命令行参数处理:**

这段代码本身并没有直接处理命令行参数。`encoding/xml` 包主要关注 XML 的解析和编码，通常与其他包（例如 `os` 或第三方库）结合来处理文件读取等操作，而文件路径可能会通过命令行参数传递。

**使用者易犯错的点:**

根据这部分代码，一个潜在的易错点是 **直接修改 `Token` 中返回的切片数据**。例如，`CharData` 是一个 `[]byte`。由于 `Decoder` 为了效率可能会重用内部缓冲区，直接修改返回的 `CharData` 的内容可能会导致后续解析出现意想不到的问题。

**例子：错误的修改 `CharData`:**

```go
package main

import (
	"encoding/xml"
	"fmt"
	"strings"
)

func main() {
	xmlData := `<data>text</data>`
	decoder := xml.NewDecoder(strings.NewReader(xmlData))

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch cd := token.(type) {
		case xml.CharData:
			// 错误的做法：直接修改 CharData 的内容
			if string(cd) == "text" {
				cd[0] = 'T'
			}
			fmt.Printf("Char Data: [%s]\n", cd)
		}
	}
}
```

在这个例子中，直接修改 `cd[0]` 可能会导致未定义的行为，因为 `cd` 可能指向 `Decoder` 内部的缓冲区。 正确的做法是使用 `Copy()` 方法创建副本后再进行修改。

**总结一下它的功能 (第1部分):**

这部分代码定义了 Go 语言中用于表示 XML 文档结构的关键数据类型，为 XML 解析器的实现提供了基础的数据模型。它包括了表示 XML 元素、属性、命名空间、不同类型的 XML 内容（如文本、注释、指令等）的结构体和接口。 核心目标是提供一种在 Go 程序中方便且类型安全地表示 XML 文档的方式。 这为后续实现 XML 解析和编码逻辑奠定了坚实的基础。

Prompt: 
```
这是路径为go/src/encoding/xml/xml.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package xml implements a simple XML 1.0 parser that
// understands XML name spaces.
package xml

// References:
//    Annotated XML spec: https://www.xml.com/axml/testaxml.htm
//    XML name spaces: https://www.w3.org/TR/REC-xml-names/

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// A SyntaxError represents a syntax error in the XML input stream.
type SyntaxError struct {
	Msg  string
	Line int
}

func (e *SyntaxError) Error() string {
	return "XML syntax error on line " + strconv.Itoa(e.Line) + ": " + e.Msg
}

// A Name represents an XML name (Local) annotated
// with a name space identifier (Space).
// In tokens returned by [Decoder.Token], the Space identifier
// is given as a canonical URL, not the short prefix used
// in the document being parsed.
type Name struct {
	Space, Local string
}

// An Attr represents an attribute in an XML element (Name=Value).
type Attr struct {
	Name  Name
	Value string
}

// A Token is an interface holding one of the token types:
// [StartElement], [EndElement], [CharData], [Comment], [ProcInst], or [Directive].
type Token any

// A StartElement represents an XML start element.
type StartElement struct {
	Name Name
	Attr []Attr
}

// Copy creates a new copy of StartElement.
func (e StartElement) Copy() StartElement {
	attrs := make([]Attr, len(e.Attr))
	copy(attrs, e.Attr)
	e.Attr = attrs
	return e
}

// End returns the corresponding XML end element.
func (e StartElement) End() EndElement {
	return EndElement{e.Name}
}

// An EndElement represents an XML end element.
type EndElement struct {
	Name Name
}

// A CharData represents XML character data (raw text),
// in which XML escape sequences have been replaced by
// the characters they represent.
type CharData []byte

// Copy creates a new copy of CharData.
func (c CharData) Copy() CharData { return CharData(bytes.Clone(c)) }

// A Comment represents an XML comment of the form <!--comment-->.
// The bytes do not include the <!-- and --> comment markers.
type Comment []byte

// Copy creates a new copy of Comment.
func (c Comment) Copy() Comment { return Comment(bytes.Clone(c)) }

// A ProcInst represents an XML processing instruction of the form <?target inst?>
type ProcInst struct {
	Target string
	Inst   []byte
}

// Copy creates a new copy of ProcInst.
func (p ProcInst) Copy() ProcInst {
	p.Inst = bytes.Clone(p.Inst)
	return p
}

// A Directive represents an XML directive of the form <!text>.
// The bytes do not include the <! and > markers.
type Directive []byte

// Copy creates a new copy of Directive.
func (d Directive) Copy() Directive { return Directive(bytes.Clone(d)) }

// CopyToken returns a copy of a Token.
func CopyToken(t Token) Token {
	switch v := t.(type) {
	case CharData:
		return v.Copy()
	case Comment:
		return v.Copy()
	case Directive:
		return v.Copy()
	case ProcInst:
		return v.Copy()
	case StartElement:
		return v.Copy()
	}
	return t
}

// A TokenReader is anything that can decode a stream of XML tokens, including a
// [Decoder].
//
// When Token encounters an error or end-of-file condition after successfully
// reading a token, it returns the token. It may return the (non-nil) error from
// the same call or return the error (and a nil token) from a subsequent call.
// An instance of this general case is that a TokenReader returning a non-nil
// token at the end of the token stream may return either io.EOF or a nil error.
// The next Read should return nil, [io.EOF].
//
// Implementations of Token are discouraged from returning a nil token with a
// nil error. Callers should treat a return of nil, nil as indicating that
// nothing happened; in particular it does not indicate EOF.
type TokenReader interface {
	Token() (Token, error)
}

// A Decoder represents an XML parser reading a particular input stream.
// The parser assumes that its input is encoded in UTF-8.
type Decoder struct {
	// Strict defaults to true, enforcing the requirements
	// of the XML specification.
	// If set to false, the parser allows input containing common
	// mistakes:
	//	* If an element is missing an end tag, the parser invents
	//	  end tags as necessary to keep the return values from Token
	//	  properly balanced.
	//	* In attribute values and character data, unknown or malformed
	//	  character entities (sequences beginning with &) are left alone.
	//
	// Setting:
	//
	//	d.Strict = false
	//	d.AutoClose = xml.HTMLAutoClose
	//	d.Entity = xml.HTMLEntity
	//
	// creates a parser that can handle typical HTML.
	//
	// Strict mode does not enforce the requirements of the XML name spaces TR.
	// In particular it does not reject name space tags using undefined prefixes.
	// Such tags are recorded with the unknown prefix as the name space URL.
	Strict bool

	// When Strict == false, AutoClose indicates a set of elements to
	// consider closed immediately after they are opened, regardless
	// of whether an end element is present.
	AutoClose []string

	// Entity can be used to map non-standard entity names to string replacements.
	// The parser behaves as if these standard mappings are present in the map,
	// regardless of the actual map content:
	//
	//	"lt": "<",
	//	"gt": ">",
	//	"amp": "&",
	//	"apos": "'",
	//	"quot": `"`,
	Entity map[string]string

	// CharsetReader, if non-nil, defines a function to generate
	// charset-conversion readers, converting from the provided
	// non-UTF-8 charset into UTF-8. If CharsetReader is nil or
	// returns an error, parsing stops with an error. One of the
	// CharsetReader's result values must be non-nil.
	CharsetReader func(charset string, input io.Reader) (io.Reader, error)

	// DefaultSpace sets the default name space used for unadorned tags,
	// as if the entire XML stream were wrapped in an element containing
	// the attribute xmlns="DefaultSpace".
	DefaultSpace string

	r              io.ByteReader
	t              TokenReader
	buf            bytes.Buffer
	saved          *bytes.Buffer
	stk            *stack
	free           *stack
	needClose      bool
	toClose        Name
	nextToken      Token
	nextByte       int
	ns             map[string]string
	err            error
	line           int
	linestart      int64
	offset         int64
	unmarshalDepth int
}

// NewDecoder creates a new XML parser reading from r.
// If r does not implement [io.ByteReader], NewDecoder will
// do its own buffering.
func NewDecoder(r io.Reader) *Decoder {
	d := &Decoder{
		ns:       make(map[string]string),
		nextByte: -1,
		line:     1,
		Strict:   true,
	}
	d.switchToReader(r)
	return d
}

// NewTokenDecoder creates a new XML parser using an underlying token stream.
func NewTokenDecoder(t TokenReader) *Decoder {
	// Is it already a Decoder?
	if d, ok := t.(*Decoder); ok {
		return d
	}
	d := &Decoder{
		ns:       make(map[string]string),
		t:        t,
		nextByte: -1,
		line:     1,
		Strict:   true,
	}
	return d
}

// Token returns the next XML token in the input stream.
// At the end of the input stream, Token returns nil, [io.EOF].
//
// Slices of bytes in the returned token data refer to the
// parser's internal buffer and remain valid only until the next
// call to Token. To acquire a copy of the bytes, call [CopyToken]
// or the token's Copy method.
//
// Token expands self-closing elements such as <br>
// into separate start and end elements returned by successive calls.
//
// Token guarantees that the [StartElement] and [EndElement]
// tokens it returns are properly nested and matched:
// if Token encounters an unexpected end element
// or EOF before all expected end elements,
// it will return an error.
//
// If [Decoder.CharsetReader] is called and returns an error,
// the error is wrapped and returned.
//
// Token implements XML name spaces as described by
// https://www.w3.org/TR/REC-xml-names/. Each of the
// [Name] structures contained in the Token has the Space
// set to the URL identifying its name space when known.
// If Token encounters an unrecognized name space prefix,
// it uses the prefix as the Space rather than report an error.
func (d *Decoder) Token() (Token, error) {
	var t Token
	var err error
	if d.stk != nil && d.stk.kind == stkEOF {
		return nil, io.EOF
	}
	if d.nextToken != nil {
		t = d.nextToken
		d.nextToken = nil
	} else {
		if t, err = d.rawToken(); t == nil && err != nil {
			if err == io.EOF && d.stk != nil && d.stk.kind != stkEOF {
				err = d.syntaxError("unexpected EOF")
			}
			return nil, err
		}
		// We still have a token to process, so clear any
		// errors (e.g. EOF) and proceed.
		err = nil
	}
	if !d.Strict {
		if t1, ok := d.autoClose(t); ok {
			d.nextToken = t
			t = t1
		}
	}
	switch t1 := t.(type) {
	case StartElement:
		// In XML name spaces, the translations listed in the
		// attributes apply to the element name and
		// to the other attribute names, so process
		// the translations first.
		for _, a := range t1.Attr {
			if a.Name.Space == xmlnsPrefix {
				v, ok := d.ns[a.Name.Local]
				d.pushNs(a.Name.Local, v, ok)
				d.ns[a.Name.Local] = a.Value
			}
			if a.Name.Space == "" && a.Name.Local == xmlnsPrefix {
				// Default space for untagged names
				v, ok := d.ns[""]
				d.pushNs("", v, ok)
				d.ns[""] = a.Value
			}
		}

		d.pushElement(t1.Name)
		d.translate(&t1.Name, true)
		for i := range t1.Attr {
			d.translate(&t1.Attr[i].Name, false)
		}
		t = t1

	case EndElement:
		if !d.popElement(&t1) {
			return nil, d.err
		}
		t = t1
	}
	return t, err
}

const (
	xmlURL      = "http://www.w3.org/XML/1998/namespace"
	xmlnsPrefix = "xmlns"
	xmlPrefix   = "xml"
)

// Apply name space translation to name n.
// The default name space (for Space=="")
// applies only to element names, not to attribute names.
func (d *Decoder) translate(n *Name, isElementName bool) {
	switch {
	case n.Space == xmlnsPrefix:
		return
	case n.Space == "" && !isElementName:
		return
	case n.Space == xmlPrefix:
		n.Space = xmlURL
	case n.Space == "" && n.Local == xmlnsPrefix:
		return
	}
	if v, ok := d.ns[n.Space]; ok {
		n.Space = v
	} else if n.Space == "" {
		n.Space = d.DefaultSpace
	}
}

func (d *Decoder) switchToReader(r io.Reader) {
	// Get efficient byte at a time reader.
	// Assume that if reader has its own
	// ReadByte, it's efficient enough.
	// Otherwise, use bufio.
	if rb, ok := r.(io.ByteReader); ok {
		d.r = rb
	} else {
		d.r = bufio.NewReader(r)
	}
}

// Parsing state - stack holds old name space translations
// and the current set of open elements. The translations to pop when
// ending a given tag are *below* it on the stack, which is
// more work but forced on us by XML.
type stack struct {
	next *stack
	kind int
	name Name
	ok   bool
}

const (
	stkStart = iota
	stkNs
	stkEOF
)

func (d *Decoder) push(kind int) *stack {
	s := d.free
	if s != nil {
		d.free = s.next
	} else {
		s = new(stack)
	}
	s.next = d.stk
	s.kind = kind
	d.stk = s
	return s
}

func (d *Decoder) pop() *stack {
	s := d.stk
	if s != nil {
		d.stk = s.next
		s.next = d.free
		d.free = s
	}
	return s
}

// Record that after the current element is finished
// (that element is already pushed on the stack)
// Token should return EOF until popEOF is called.
func (d *Decoder) pushEOF() {
	// Walk down stack to find Start.
	// It might not be the top, because there might be stkNs
	// entries above it.
	start := d.stk
	for start.kind != stkStart {
		start = start.next
	}
	// The stkNs entries below a start are associated with that
	// element too; skip over them.
	for start.next != nil && start.next.kind == stkNs {
		start = start.next
	}
	s := d.free
	if s != nil {
		d.free = s.next
	} else {
		s = new(stack)
	}
	s.kind = stkEOF
	s.next = start.next
	start.next = s
}

// Undo a pushEOF.
// The element must have been finished, so the EOF should be at the top of the stack.
func (d *Decoder) popEOF() bool {
	if d.stk == nil || d.stk.kind != stkEOF {
		return false
	}
	d.pop()
	return true
}

// Record that we are starting an element with the given name.
func (d *Decoder) pushElement(name Name) {
	s := d.push(stkStart)
	s.name = name
}

// Record that we are changing the value of ns[local].
// The old value is url, ok.
func (d *Decoder) pushNs(local string, url string, ok bool) {
	s := d.push(stkNs)
	s.name.Local = local
	s.name.Space = url
	s.ok = ok
}

// Creates a SyntaxError with the current line number.
func (d *Decoder) syntaxError(msg string) error {
	return &SyntaxError{Msg: msg, Line: d.line}
}

// Record that we are ending an element with the given name.
// The name must match the record at the top of the stack,
// which must be a pushElement record.
// After popping the element, apply any undo records from
// the stack to restore the name translations that existed
// before we saw this element.
func (d *Decoder) popElement(t *EndElement) bool {
	s := d.pop()
	name := t.Name
	switch {
	case s == nil || s.kind != stkStart:
		d.err = d.syntaxError("unexpected end element </" + name.Local + ">")
		return false
	case s.name.Local != name.Local:
		if !d.Strict {
			d.needClose = true
			d.toClose = t.Name
			t.Name = s.name
			return true
		}
		d.err = d.syntaxError("element <" + s.name.Local + "> closed by </" + name.Local + ">")
		return false
	case s.name.Space != name.Space:
		ns := name.Space
		if name.Space == "" {
			ns = `""`
		}
		d.err = d.syntaxError("element <" + s.name.Local + "> in space " + s.name.Space +
			" closed by </" + name.Local + "> in space " + ns)
		return false
	}

	d.translate(&t.Name, true)

	// Pop stack until a Start or EOF is on the top, undoing the
	// translations that were associated with the element we just closed.
	for d.stk != nil && d.stk.kind != stkStart && d.stk.kind != stkEOF {
		s := d.pop()
		if s.ok {
			d.ns[s.name.Local] = s.name.Space
		} else {
			delete(d.ns, s.name.Local)
		}
	}

	return true
}

// If the top element on the stack is autoclosing and
// t is not the end tag, invent the end tag.
func (d *Decoder) autoClose(t Token) (Token, bool) {
	if d.stk == nil || d.stk.kind != stkStart {
		return nil, false
	}
	for _, s := range d.AutoClose {
		if strings.EqualFold(s, d.stk.name.Local) {
			// This one should be auto closed if t doesn't close it.
			et, ok := t.(EndElement)
			if !ok || !strings.EqualFold(et.Name.Local, d.stk.name.Local) {
				return EndElement{d.stk.name}, true
			}
			break
		}
	}
	return nil, false
}

var errRawToken = errors.New("xml: cannot use RawToken from UnmarshalXML method")

// RawToken is like [Decoder.Token] but does not verify that
// start and end elements match and does not translate
// name space prefixes to their corresponding URLs.
func (d *Decoder) RawToken() (Token, error) {
	if d.unmarshalDepth > 0 {
		return nil, errRawToken
	}
	return d.rawToken()
}

func (d *Decoder) rawToken() (Token, error) {
	if d.t != nil {
		return d.t.Token()
	}
	if d.err != nil {
		return nil, d.err
	}
	if d.needClose {
		// The last element we read was self-closing and
		// we returned just the StartElement half.
		// Return the EndElement half now.
		d.needClose = false
		return EndElement{d.toClose}, nil
	}

	b, ok := d.getc()
	if !ok {
		return nil, d.err
	}

	if b != '<' {
		// Text section.
		d.ungetc(b)
		data := d.text(-1, false)
		if data == nil {
			return nil, d.err
		}
		return CharData(data), nil
	}

	if b, ok = d.mustgetc(); !ok {
		return nil, d.err
	}
	switch b {
	case '/':
		// </: End element
		var name Name
		if name, ok = d.nsname(); !ok {
			if d.err == nil {
				d.err = d.syntaxError("expected element name after </")
			}
			return nil, d.err
		}
		d.space()
		if b, ok = d.mustgetc(); !ok {
			return nil, d.err
		}
		if b != '>' {
			d.err = d.syntaxError("invalid characters between </" + name.Local + " and >")
			return nil, d.err
		}
		return EndElement{name}, nil

	case '?':
		// <?: Processing instruction.
		var target string
		if target, ok = d.name(); !ok {
			if d.err == nil {
				d.err = d.syntaxError("expected target name after <?")
			}
			return nil, d.err
		}
		d.space()
		d.buf.Reset()
		var b0 byte
		for {
			if b, ok = d.mustgetc(); !ok {
				return nil, d.err
			}
			d.buf.WriteByte(b)
			if b0 == '?' && b == '>' {
				break
			}
			b0 = b
		}
		data := d.buf.Bytes()
		data = data[0 : len(data)-2] // chop ?>

		if target == "xml" {
			content := string(data)
			ver := procInst("version", content)
			if ver != "" && ver != "1.0" {
				d.err = fmt.Errorf("xml: unsupported version %q; only version 1.0 is supported", ver)
				return nil, d.err
			}
			enc := procInst("encoding", content)
			if enc != "" && enc != "utf-8" && enc != "UTF-8" && !strings.EqualFold(enc, "utf-8") {
				if d.CharsetReader == nil {
					d.err = fmt.Errorf("xml: encoding %q declared but Decoder.CharsetReader is nil", enc)
					return nil, d.err
				}
				newr, err := d.CharsetReader(enc, d.r.(io.Reader))
				if err != nil {
					d.err = fmt.Errorf("xml: opening charset %q: %w", enc, err)
					return nil, d.err
				}
				if newr == nil {
					panic("CharsetReader returned a nil Reader for charset " + enc)
				}
				d.switchToReader(newr)
			}
		}
		return ProcInst{target, data}, nil

	case '!':
		// <!: Maybe comment, maybe CDATA.
		if b, ok = d.mustgetc(); !ok {
			return nil, d.err
		}
		switch b {
		case '-': // <!-
			// Probably <!-- for a comment.
			if b, ok = d.mustgetc(); !ok {
				return nil, d.err
			}
			if b != '-' {
				d.err = d.syntaxError("invalid sequence <!- not part of <!--")
				return nil, d.err
			}
			// Look for terminator.
			d.buf.Reset()
			var b0, b1 byte
			for {
				if b, ok = d.mustgetc(); !ok {
					return nil, d.err
				}
				d.buf.WriteByte(b)
				if b0 == '-' && b1 == '-' {
					if b != '>' {
						d.err = d.syntaxError(
							`invalid sequence "--" not allowed in comments`)
						return nil, d.err
					}
					break
				}
				b0, b1 = b1, b
			}
			data := d.buf.Bytes()
			data = data[0 : len(data)-3] // chop -->
			return Comment(data), nil

		case '[': // <![
			// Probably <![CDATA[.
			for i := 0; i < 6; i++ {
				if b, ok = d.mustgetc(); !ok {
					return nil, d.err
				}
				if b != "CDATA["[i] {
					d.err = d.syntaxError("invalid <![ sequence")
					return nil, d.err
				}
			}
			// Have <![CDATA[.  Read text until ]]>.
			data := d.text(-1, true)
			if data == nil {
				return nil, d.err
			}
			return CharData(data), nil
		}

		// Probably a directive: <!DOCTYPE ...>, <!ENTITY ...>, etc.
		// We don't care, but accumulate for caller. Quoted angle
		// brackets do not count for nesting.
		d.buf.Reset()
		d.buf.WriteByte(b)
		inquote := uint8(0)
		depth := 0
		for {
			if b, ok = d.mustgetc(); !ok {
				return nil, d.err
			}
			if inquote == 0 && b == '>' && depth == 0 {
				break
			}
		HandleB:
			d.buf.WriteByte(b)
			switch {
			case b == inquote:
				inquote = 0

			case inquote != 0:
				// in quotes, no special action

			case b == '\'' || b == '"':
				inquote = b

			case b == '>' && inquote == 0:
				depth--

			case b == '<' && inquote == 0:
				// Look for <!-- to begin comment.
				s := "!--"
				for i := 0; i < len(s); i++ {
					if b, ok = d.mustgetc(); !ok {
						return nil, d.err
					}
					if b != s[i] {
						for j := 0; j < i; j++ {
							d.buf.WriteByte(s[j])
						}
						depth++
						goto HandleB
					}
				}

				// Remove < that was written above.
				d.buf.Truncate(d.buf.Len() - 1)

				// Look for terminator.
				var b0, b1 byte
				for {
					if b, ok = d.mustgetc(); !ok {
						return nil, d.err
					}
					if b0 == '-' && b1 == '-' && b == '>' {
						break
					}
					b0, b1 = b1, b
				}

				// Replace the comment with a space in the returned Directive
				// body, so that markup parts that were separated by the comment
				// (like a "<" and a "!") don't get joined when re-encoding the
				// Directive, taking new semantic meaning.
				d.buf.WriteByte(' ')
			}
		}
		return Directive(d.buf.Bytes()), nil
	}

	// Must be an open element like <a href="foo">
	d.ungetc(b)

	var (
		name  Name
		empty bool
		attr  []Attr
	)
	if name, ok = d.nsname(); !ok {
		if d.err == nil {
			d.err = d.syntaxError("expected element name after <")
		}
		return nil, d.err
	}

	attr = []Attr{}
	for {
		d.space()
		if b, ok = d.mustgetc(); !ok {
			return nil, d.err
		}
		if b == '/' {
			empty = true
			if b, ok = d.mustgetc(); !ok {
				return nil, d.err
			}
			if b != '>' {
				d.err = d.syntaxError("expected /> in element")
				return nil, d.err
			}
			break
		}
		if b == '>' {
			break
		}
		d.ungetc(b)

		a := Attr{}
		if a.Name, ok = d.nsname(); !ok {
			if d.err == nil {
				d.err = d.syntaxError("expected attribute name in element")
			}
			return nil, d.err
		}
		d.space()
		if b, ok = d.mustgetc(); !ok {
			return nil, d.err
		}
		if b != '=' {
			if d.Strict {
				d.err = d.syntaxError("attribute name without = in element")
				return nil, d.err
			}
			d.ungetc(b)
			a.Value = a.Name.Local
		} else {
			d.space()
			data := d.attrval()
			if data == nil {
				return nil, d.err
			}
			a.Value = string(data)
		}
		attr = append(attr, a)
	}
	if empty {
		d.needClose = true
		d.toClose = name
	}
	return StartElement{name, attr}, nil
}

func (d *Decoder) attrval() []byte {
	b, ok := d.mustgetc()
	if !ok {
		return nil
	}
	// Handle quoted attribute values
	if b == '"' || b == '\'' {
		return d.text(int(b), false)
	}
	// Handle unquoted attribute values for strict parsers
	if d.Strict {
		d.err = d.syntaxError("unquoted or missing attribute value in element")
		return nil
	}
	// Handle unquoted attribute values for unstrict parsers
	d.ungetc(b)
	d.buf.Reset()
	for {
		b, ok = d.mustgetc()
		if !ok {
			return nil
		}
		// https://www.w3.org/TR/REC-html40/intro/sgmltut.html#h-3.2.2
		if 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' ||
			'0' <= b && b <= '9' || b == '_' || b == ':' || b == '-' {
			d.buf.WriteByte(b)
		} else {
			d.ungetc(b)
			break
		}
	}
	return d.buf.Bytes()
}

// Skip spaces if any
func (d *Decoder) space() {
	for {
		b, ok := d.getc()
		if !ok {
			return
		}
		switch b {
		case ' ', '\r', '\n', '\t':
		default:
			d.ungetc(b)
			return
		}
	}
}

// Read a single byte.
// If there is no byte to read, return ok==false
// and leave the error in d.err.
// Maintain line number.
func (d *Decoder) getc() (b byte, ok bool) {
	if d.err != nil {
		return 0, false
	}
	if d.nextByte >= 0 {
		b = byte(d.nextByte)
		d.nextByte = -1
	} else {
		b, d.err = d.r.ReadByte()
		if d.err != nil {
			return 0, false
		}
		if d.saved != nil {
			d.saved.WriteByte(b)
		}
	}
	if b == '\n' {
		d.line++
		d.linestart = d.offset + 1
	}
	d.offset++
	return b, true
}

// InputOffset returns the input stream byte offset of the current decoder position.
// The offset gives the location of the end of the most recently returned token
// and the beginning of the next token.
func (d *Decoder) InputOffset() int64 {
	return d.offset
}

// InputPos returns the line of the current decoder position and the 1 based
// input position of the line. The position gives the location of the end of the
// most recently returned token.
func (d *Decoder) InputPos() (line, column int) {
	return d.line, int(d.offset-d.linestart) + 1
}

// Return saved offset.
// If we did ungetc (nextByte >= 0), have to back up one.
func (d *Decoder) savedOffset() int {
	n := d.saved.Len()
	if d.nextByte >= 0 {
		n--
	}
	return n
}

// Must read a single byte.
// If there is no byte to read,
// set d.err to SyntaxError("unexpected EOF")
// and return ok==false
func (d *Decoder) mustgetc() (b byte, ok bool) {
	if b, ok = d.getc(); !ok {
		if d.err == io.EOF {
			d.err = d.syntaxError("unexpected EOF")
		}
	}
	return
}

// Unread a single byte.
func (d *Decoder) ungetc(b byte) {
	if b == '\n' {
		d.line--
	}
	d.nextByte = int(b)
	d.offset--
}

var entity = map[string]rune{
	"lt":   '<',
	"gt":   '>',
	"amp":  '&',
	"apos": '\'',
	"quot": '"',
}

// Read plain text section (XML calls it character data).
// If quote >= 0, we are in a quoted string and need to find the matching quote.
// If cdata == true, we are in a <![CDATA[ section and need to find ]]>.
// On failure return nil and leave the error in d.err.
func (d *Decoder) text(quote int, cdata bool) []byte {
	var b0, b1 byte
	var trunc int
	d.buf.Reset()
Input:
	for {
		b, ok := d.getc()
		if !ok {
			if cdata {
				if d.err == io.EOF {
					d.err = d.syntaxError("unexpected EOF in CDATA section")
				}
				return nil
			}
			break Input
		}

		// <![CDATA[ section ends with ]]>.
		// It is an error for ]]> to appear in ordinary text,
		// but it is allowed in quoted strings.
		if quote < 0 && b0 == ']' && b1 == ']' && b == '>' {
			if cdata {
				trunc = 2
				break Input
			}
			d.err = d.syntaxError("unescaped ]]> not in CDATA section")
			return nil
		}

		// Stop reading text if we see a <.
		if b == '<' && !cdata {
			if quote >= 0 {
				d.err = d.syntaxError("unescaped < inside quoted string")
				return nil
			}
			d.ungetc('<')
			break Input
		}
		if quote >= 0 && b == byte(quote) {
			break Input
		}
		if b == '&' && !cdata {
			// Read escaped character expression up to semicolon.
			// XML in all its glory allows a document to define and use
			// its own character names with <!ENTITY ...> directives.
			// Parsers are required to recognize lt, gt, amp, apos, and quot
			// even if they have not been declared.
			before := d.buf.Len()
			d.buf.WriteByte('&')
			var ok bool
			var text string
			var haveText bool
			if b, ok = d.mustgetc(); !ok {
				return nil
			}
			if b == '#' {
				d.buf.WriteByte(b)
				if b, ok = d.mustgetc(); !ok {
					return nil
				}
				base := 10
				if b == 'x' {
					base = 16
					d.buf.WriteByte(b)
					if b, ok = d.mustgetc(); !ok {
						return nil
					}
				}
				start := d.buf.Len()
				for '0' <= b && b <= '9' ||
					base == 16 && 'a' <= b && b <= 'f' ||
					base == 16 && 'A' <= b && b <= 'F' {
					d.buf.WriteByte(b)
					if b, ok = d.mustgetc(); !ok {
						return nil
					}
				}
				if b != ';' {
					d.ungetc(b)
				} else {
					s := string(d.buf.Bytes()[start:])
					d.buf.WriteByte(';')
					n, err := strconv.ParseUint(s, base, 64)
					if err == nil && n <= unicode.MaxRune {
						text = string(rune(n))
						haveText = true
					}
				}
			} else {
				d.ungetc(b)
				if !d.readName() {
					if d.err != nil {
						return nil
					}
				}
				if b, ok = d.mustgetc(); !ok {
					return nil
				}
				if b != ';' {
					d.ungetc(b)
				} else {
					name := d.buf.Bytes()[before+1:]
					d.buf.WriteByte(';')
					if isName(name) {
						s := string(name)
						if r, ok := entity[s]; ok {
							text = string(r)
							haveText = true
						} else if d.Entity != nil {
							text, haveText = d.Entity[s]
						}
					}
				}
			}

			if haveText {
				d.buf.Truncate(before)
				d.buf.WriteString(text)
				b0, b1 = 0, 0
				continue Input
			}
			if !d.Strict {
				b0, b1 = 0, 0
				continue Input
			}
			ent := string(d.buf.Bytes()[before:])
			if ent[len(ent)-1] != ';' {
				ent += " (no semicolon)"
			}
			d.err = d.syntaxError("invalid character entity " + ent)
			return nil
		}

		// We must rewrite unescaped \r and \r\n into \n.
		if b == '\r' {
			d.buf.WriteByte('\n')
		} else if b1 == '\r' && b == '\n' {
			// Skip \r\n--we already wrote \n.
		} else {
			d.buf.WriteByte(b)
		}

		b0, b1 = b1, b
	}
	data := d.buf.Bytes()
	data = data[0 : len(data)-trunc]

	// Inspect each rune for being a disallowed character.
	buf := data
	for len(buf) > 0 {
		r, size := utf8.DecodeRune(buf)
		if r == utf8.RuneError && size == 1 {
			d.err = d.syntaxError("invalid UTF-8")
			return nil
		}
		buf = buf[size:]
		if !isInCharacterRange(r) {
			d.err = d.syntaxError(fmt.Sprintf("illegal character code %U", r))
			return nil
		}
	}

	return data
}

// Decide whether the given rune is in the XML Character Range, per
// the Char production of https://www.xml.com/axml/testaxml.htm,
// Section 2.2 Characters.
func isInCharacterRange(r rune) (inrange bool) {
	return r == 0x09 ||
		r == 0x0A ||
		r == 0x0D ||
		r >= 0x20 && r <= 0xD7FF ||
		r >= 0xE000 && r <= 0xFFFD ||
		r >= 0x10000 && r <= 0x10FFFF
}

// Get name space name: name with a : stuck in the middle.
// The part before the : is the name space identifier.
func (d *Decoder) nsname() (name Name, ok bool) {
	s, ok := d.name()
	if !ok {
		return
	}
	if strings.Count(s, ":") > 1 {
		return name, false
	} else if space, local, ok := strings.Cut(s, ":"); !ok || space == "" || local == "" {
		name.Local = s
	} else {
		name.Space = space
		name.Local = local
	}
	return name, true
}

// Get name: /first(first|second)*/
// Do not set d.err if the name is missing (unless unexpected EOF is received):
// let the caller provide better context.
func (d *Decoder) name() (s string, ok bool) {
	d.buf.Reset()
	if !d.readName() {
		return "", false
	}

	// Now we check the characters.
	b := d.buf.Bytes()
	if !isName(b) {
		d.err = d.syntaxError("invalid XML name: " + string(b))
		return "", false
	}
	return string(b), true
}

// Read a name and append its bytes to d.buf.
// The name is delimited by any single-byte character not valid in names.
// All multi-byte characters are accepted; the caller must check their validity.
func (d *Decoder) readName() (ok bool) {
	var b byte
	if b, ok = d.mustgetc(); !ok {
		return
	}
	if b < utf8.RuneSelf && !isNameByte(b) {
		d.ungetc(b)
		return false
	}
	d.buf.WriteByte(b)

	for {
		if b, ok = d.mustgetc(); !ok {
			return
		}
		if b < utf8.RuneSelf && !isNameByte(b) {
			d.ungetc(b)
			break
		}
		d.buf.WriteByte(b)
	}
	return true
}

func isNameByte(c byte) bool {
	return 'A' <= c && c <= 'Z' ||
		'a' <= c && c <= 'z' ||
		'0' <= c && c <= '9' ||
		c == '_' || c == ':' || c == '.' || c == '-'
}

func isName(s []byte) bool {
	if len(s) == 0 {
		return false
	}
	c, n := utf8.DecodeRune(s)
	if c == utf8.RuneError && n == 1 {
		return false
	}
	if !unicode.Is(first, c) {
		return false
	}
	for n < len(s) {
		s = s[n:]
		c, n = utf8.DecodeRune(s)
		if c == utf8.RuneError && n == 1 {
			return false
		}
		if !unicode.Is(first, c) && !unicode.Is(second, c) {
			return false
		}
	}
	return true
}

func isNameString(s string) bool {
	if len(s) == 0 {
		return false
	}
	c, n := utf8.DecodeRuneInString(s)
	if c == utf8.RuneError && n == 1 {
		return false
	}
	if !unicode.Is(first, c) {
		return false
	}
	for n < len(s) {
		s = s[n:]
		c, n = utf8.DecodeRuneInString(s)
		if c == utf8.RuneError && n == 1 {
			return false
		}
		if !unicode.Is(first, c) && !unicode.Is(second, c) {
			return false
		}
	}
	return true
}

// These tables were generated by cut and paste from Appendix B of
// the XML spec at https://www.xml.com/axml/testaxml.htm
// and then reformatting. First corresponds to (Letter | '_' | ':')
// and second corresponds to NameChar.

var first = &unicode.RangeTable{
	R16: []unicode.Range16{
		{0x003A, 0x003A, 1},
		{0x0041, 0x005A, 1},
		{0x005F, 0x005F, 1},
		{0x0061, 0x007A, 1},
		{0x00C0, 0x00D6, 1},
		{0x00D8, 0x00F6, 1},
		{0x00F8, 0x00FF, 1},
		{0x0100, 0x0131, 1},
		{0x0134, 0x013E, 1},
		{0x0141, 0x0148, 1},
		{0x014A, 0x017E, 1},
		{0x0180, 0x01C3, 1},
		{0x01CD, 0x01F0, 1},
		{0x01F4, 0x01F5, 1},
		{0x01FA, 0x0217, 1},
		{0x0250, 0x02A8, 1},
		{0x02BB, 0x02C1, 1},
		{0x0386, 0x0386, 1},
		{0x0388, 0x038A, 1},
		{0x038C, 0x038C, 1},
		{0x038E, 0x03A1, 1},
		{0x03A3, 0x03CE, 1},
		{0x03D0, 0x03D6, 1},
		{0x03DA, 0x03E0, 2},
		{0x03E2, 0x03F3, 1},
		{0x0401, 0x040C, 1},
		{0x040E, 0x044F, 1},
		{0x0451, 0x045C, 1},
		{0x045E, 0x0481, 1},
		{0x0490, 0x04C4, 1},
		{0x04C7, 0x04C8, 1},
		{0x04CB, 0x04CC, 1},
		{0x04D0, 0x04EB, 1},
		{0x04EE, 0x04F5, 1},
		{0x04F8, 0x04F9, 1},
		{0x0531, 0x0556, 1},
		{0x0559, 0x0559, 1},
		{0x0561, 0x0586, 1},
		{0x05D0, 0x05EA, 1},
		{0x05F0, 0x05F2, 1},
		{0x0621, 0x063A, 1},
		{0x0641, 0x064A, 1},
		{0x0671, 0x06B7, 1},
		{0x06BA, 0x06BE, 1},
		{0x06C0, 0x06CE, 1},
		{0x06D0, 0x06D3, 1},
		{0x06D5, 0x06D5, 1},
		{0x06E5, 0x06E6, 1},
		{0x0905, 0x0939, 1},
		{0x093D, 0x093D, 1},
		{0x0958, 0x0961, 1},
		{0x0985, 0x098C, 1},
		{0x098F, 0x0990, 1},
		{0x0993, 0x09A8, 1},
		{0x09AA, 0x09B0, 1},
		{0x09B2, 0x09B2, 1},
		{0x09B6, 0x09B9, 1},
		{0x09DC, 0x09DD, 1},
		{0x09DF, 0x09E1, 1},
		{0x09F0, 0x09F1, 1},
		{0x0A05, 0x0A0A, 1},
		{0x0A0F, 0x0A10, 1},
		{0x0A13, 0x0A28, 1},
		{0x0A2A, 0x0A30, 1},
		{0x0A32, 0x0A33, 1},
		{0x0A35, 0x0A36, 1},
		{0x0A38, 0x0A39, 1},
		{0x0A59, 0x0A5C, 1},
		{0x0A5E, 0x0A5E, 1},
		{0x0A72, 0x0A74, 1},
		{0x0A85, 0x0A8B, 1},
		{0x0A8D, 0x0A8D, 1},
		{0x0A8F, 0x0A91, 1},
		{0x0A93, 0x0AA8, 1},
		{0x0AAA, 0x0AB0, 1},
		{0x0AB2, 0x0AB3, 1},
		{0x0AB5, 0x0AB9, 1},
		{0x0ABD, 0x0AE0, 0x23},
		{0x0B05, 0x0B0C, 1},
		{0x0B0F, 0x0B10, 1},
		{0x0B13, 0x0B28, 1},
		{0x0B2A, 0x0
"""




```