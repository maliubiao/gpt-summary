Response:
The user wants to understand the functionality of the provided Go code snippet, which is part of the `marshal_test.go` file in the `encoding/xml` package. This file likely contains tests for the XML marshaling functionality in Go.

To fulfill the request, I need to:

1. **Identify the primary purpose of the code**: Based on the file name and the presence of struct definitions, it's clear this code defines various Go structs and data structures used for testing XML marshaling.

2. **List the functionalities demonstrated by the code**: The code defines numerous structs with different XML tags and options. This suggests the tests cover a wide range of marshaling scenarios, such as:
    - Basic data type marshaling (integers, floats, booleans, strings)
    - Struct field tagging (`xml:"tagName"`, `xml:"tagName,attr"`, etc.)
    - Handling of attributes (`attr`)
    - Handling of inner XML (`innerxml`)
    - Handling of character data (`chardata`)
    - Handling of comments (`comment`)
    - Handling of CDATA (`cdata`)
    - Handling of namespaces
    - Handling ofomitempty option
    - Handling of anonymous fields and struct embedding
    - Handling of slices and arrays
    - Handling of custom marshaling

3. **Provide a Go code example**: To illustrate the marshaling process, I can choose a simple struct and demonstrate how it would be marshaled to XML.

4. **Infer the related Go language feature**: The code clearly relates to the `encoding/xml` package and its ability to convert Go data structures into XML format.

5. **Explain potential pitfalls**:  Common mistakes might involve incorrect struct tags, misunderstanding the behavior of `omitempty`, or issues with namespaces.

6. **Summarize the functionality of this part**: This specific part focuses on defining the Go data structures that will be used in the subsequent test cases to verify the correctness of the XML marshaling logic.

**Plan:**

1. Start with a concise summary of the code's function.
2. Elaborate on the specific functionalities observed in the code, categorizing them.
3. Provide a simple Go code example demonstrating marshaling.
4. Briefly mention the related Go language feature.
5. List potential pitfalls for users.
这是 `go/src/encoding/xml/marshal_test.go` 文件的一部分，它主要定义了一系列 Go 语言的结构体（struct）和常量，这些结构体被设计用来测试 `encoding/xml` 包中将 Go 数据结构序列化（marshal）成 XML 格式的功能。

**功能归纳:**

这部分代码的主要功能是 **定义了各种用于 XML 序列化测试的 Go 数据结构**。 这些结构体使用了不同的 `xml` tag 语法，旨在覆盖 `encoding/xml` 包在序列化过程中可能遇到的各种情况，例如：

* **基本数据类型的序列化**:  如 `string`, `int`, `float32`, `bool` 等。
* **结构体字段的 tag 定义**:  通过 `xml:"tagName"` 指定 XML 元素的名称，通过 `xml:"tagName,attr"` 指定 XML 属性，通过 `,chardata`, `,comment`, `,innerxml`, `,cdata` 等特殊 tag 控制序列化的方式。
* **嵌套结构体的序列化**:  测试结构体内部包含其他结构体的情况。
* **切片和数组的序列化**:  测试如何序列化 Go 的切片和数组类型。
* **属性的序列化**:  测试使用 `xml:",attr"` tag 将字段序列化为 XML 属性。
* **`omitempty` 选项**:  测试使用 `omitempty` tag 在字段值为零值或空值时省略该字段的序列化。
* **匿名结构体字段**:  测试匿名结构体字段的序列化行为。
* **自定义类型的序列化**:  例如 `DriveType`, `NamedType`, `MyBytes`, `MyInt` 等。
* **`any` tag**:  测试使用 `xml:",any"` tag 接收任意 XML 内容。
* **忽略字段**:  测试使用 `xml:"-"` tag 忽略特定字段的序列化。
* **命名空间**:  通过 `xml:"namespace tagName"` 的形式测试命名空间的处理。
* **自定义 Marshaler 接口**:  测试实现了 `Marshaler` 和 `MarshalerAttr` 接口的类型的序列化。

**Go 语言功能实现推断与代码示例:**

这部分代码主要是在为 `encoding/xml` 包的 **XML 序列化（marshaling）** 功能提供测试用例的数据结构。 `encoding/xml` 包允许你将 Go 的数据结构转换成符合 XML 规范的文本格式。

**代码示例:**

```go
package main

import (
	"encoding/xml"
	"fmt"
)

type Person struct {
	XMLName xml.Name `xml:"person"`
	Name    string   `xml:"name"`
	Age     int      `xml:"age,attr"`
	Address Address  `xml:"address"`
}

type Address struct {
	City    string `xml:"city"`
	Country string `xml:"country"`
}

func main() {
	p := Person{
		Name: "Alice",
		Age:  30,
		Address: Address{
			City:    "New York",
			Country: "USA",
		},
	}

	output, err := xml.MarshalIndent(p, "", "  ")
	if err != nil {
		fmt.Println("Error marshaling:", err)
		return
	}
	fmt.Println(string(output))
}
```

**假设的输入与输出:**

**输入 (Go 结构体 `p`):**

```go
Person{
	Name: "Alice",
	Age:  30,
	Address: Address{
		City:    "New York",
		Country: "USA",
	},
}
```

**输出 (XML):**

```xml
<person age="30">
  <name>Alice</name>
  <address>
    <city>New York</city>
    <country>USA</country>
  </address>
</person>
```

**代码推理:**

* `xml.MarshalIndent(p, "", "  ")` 函数会将 `Person` 类型的变量 `p` 序列化成 XML 格式的字节切片。
* `xml:"person"` tag 指定了根元素的名称为 `person`。
* `xml:"name"` tag 指定了 `Name` 字段会生成一个名为 `name` 的 XML 元素。
* `xml:"age,attr"` tag 指定了 `Age` 字段会生成一个名为 `age` 的 XML 属性。
* 嵌套的 `Address` 结构体会被序列化为 `person` 元素下的 `address` 子元素。

**命令行参数处理:**

这段代码本身并不涉及命令行参数的处理。 命令行参数的处理通常发生在调用 `encoding/xml` 包进行实际序列化或反序列化的程序中，而不是在测试代码中。  测试代码的主要目的是验证 `encoding/xml` 包在不同输入和配置下的行为是否符合预期。

**使用者易犯错的点:**

* **Tag 语法的错误使用**:  例如，忘记使用逗号分隔标签名和选项（如 `,attr`，`,omitempty`），或者拼写错误。
    ```go
    type Example struct {
        Name string `xml:namenode` // 错误：缺少逗号
        Value string `xml:"value, omitempty"` // 错误：omitempty 前面有空格
    }
    ```
* **对 `omitempty` 的误解**:  `omitempty` 只会忽略字段的零值或空值。对于指针类型，如果指针为 `nil`，则会忽略该字段，但如果指针指向一个零值或空值的变量，则仍然会生成对应的 XML 元素。
    ```go
    type OptionalValue struct {
        Value *string `xml:"value,omitempty"`
    }

    // 假设 str 为 ""
    str := ""
    optional := OptionalValue{Value: &str}
    // 序列化后会生成 <value></value> 而不是被忽略
    ```
* **命名空间的使用不当**:  如果 XML 结构中涉及到命名空间，需要在 Go 结构体的 tag 中正确指定命名空间。
    ```go
    type NamespacedElement struct {
        Data string `xml:"http://example.org data"`
    }
    ```
* **对 `chardata`, `comment`, `innerxml`, `cdata` 的混淆**:  这些 tag 有不同的用途，需要根据实际需求选择正确的 tag。
    * `chardata`: 表示元素的内容是纯文本数据。
    * `comment`: 表示生成 XML 注释。
    * `innerxml`: 表示字段的内容是原始的 XML 片段，不会进行转义。
    * `cdata`:  表示将字段的内容包裹在 `<![CDATA[]]>` 中。

这部分代码定义了测试 `encoding/xml` 包序列化功能的各种数据结构，是构建和验证 XML 序列化功能的重要组成部分。在实际使用 `encoding/xml` 包时，理解这些 tag 的含义和作用至关重要，可以避免很多常见的错误。

### 提示词
```
这是路径为go/src/encoding/xml/marshal_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xml

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type DriveType int

const (
	HyperDrive DriveType = iota
	ImprobabilityDrive
)

type Passenger struct {
	Name   []string `xml:"name"`
	Weight float32  `xml:"weight"`
}

type Ship struct {
	XMLName struct{} `xml:"spaceship"`

	Name      string       `xml:"name,attr"`
	Pilot     string       `xml:"pilot,attr"`
	Drive     DriveType    `xml:"drive"`
	Age       uint         `xml:"age"`
	Passenger []*Passenger `xml:"passenger"`
	secret    string
}

type NamedType string

type Port struct {
	XMLName struct{} `xml:"port"`
	Type    string   `xml:"type,attr,omitempty"`
	Comment string   `xml:",comment"`
	Number  string   `xml:",chardata"`
}

type Domain struct {
	XMLName struct{} `xml:"domain"`
	Country string   `xml:",attr,omitempty"`
	Name    []byte   `xml:",chardata"`
	Comment []byte   `xml:",comment"`
}

type Book struct {
	XMLName struct{} `xml:"book"`
	Title   string   `xml:",chardata"`
}

type Event struct {
	XMLName struct{} `xml:"event"`
	Year    int      `xml:",chardata"`
}

type Movie struct {
	XMLName struct{} `xml:"movie"`
	Length  uint     `xml:",chardata"`
}

type Pi struct {
	XMLName       struct{} `xml:"pi"`
	Approximation float32  `xml:",chardata"`
}

type Universe struct {
	XMLName struct{} `xml:"universe"`
	Visible float64  `xml:",chardata"`
}

type Particle struct {
	XMLName struct{} `xml:"particle"`
	HasMass bool     `xml:",chardata"`
}

type Departure struct {
	XMLName struct{}  `xml:"departure"`
	When    time.Time `xml:",chardata"`
}

type SecretAgent struct {
	XMLName   struct{} `xml:"agent"`
	Handle    string   `xml:"handle,attr"`
	Identity  string
	Obfuscate string `xml:",innerxml"`
}

type NestedItems struct {
	XMLName struct{} `xml:"result"`
	Items   []string `xml:">item"`
	Item1   []string `xml:"Items>item1"`
}

type NestedOrder struct {
	XMLName struct{} `xml:"result"`
	Field1  string   `xml:"parent>c"`
	Field2  string   `xml:"parent>b"`
	Field3  string   `xml:"parent>a"`
}

type MixedNested struct {
	XMLName struct{} `xml:"result"`
	A       string   `xml:"parent1>a"`
	B       string   `xml:"b"`
	C       string   `xml:"parent1>parent2>c"`
	D       string   `xml:"parent1>d"`
}

type NilTest struct {
	A any `xml:"parent1>parent2>a"`
	B any `xml:"parent1>b"`
	C any `xml:"parent1>parent2>c"`
}

type Service struct {
	XMLName struct{} `xml:"service"`
	Domain  *Domain  `xml:"host>domain"`
	Port    *Port    `xml:"host>port"`
	Extra1  any
	Extra2  any `xml:"host>extra2"`
}

var nilStruct *Ship

type EmbedA struct {
	EmbedC
	EmbedB EmbedB
	FieldA string
	embedD
}

type EmbedB struct {
	FieldB string
	*EmbedC
}

type EmbedC struct {
	FieldA1 string `xml:"FieldA>A1"`
	FieldA2 string `xml:"FieldA>A2"`
	FieldB  string
	FieldC  string
}

type embedD struct {
	fieldD string
	FieldE string // Promoted and visible when embedD is embedded.
}

type NameCasing struct {
	XMLName struct{} `xml:"casing"`
	Xy      string
	XY      string
	XyA     string `xml:"Xy,attr"`
	XYA     string `xml:"XY,attr"`
}

type NamePrecedence struct {
	XMLName     Name              `xml:"Parent"`
	FromTag     XMLNameWithoutTag `xml:"InTag"`
	FromNameVal XMLNameWithoutTag
	FromNameTag XMLNameWithTag
	InFieldName string
}

type XMLNameWithTag struct {
	XMLName Name   `xml:"InXMLNameTag"`
	Value   string `xml:",chardata"`
}

type XMLNameWithoutTag struct {
	XMLName Name
	Value   string `xml:",chardata"`
}

type NameInField struct {
	Foo Name `xml:"ns foo"`
}

type AttrTest struct {
	Int   int     `xml:",attr"`
	Named int     `xml:"int,attr"`
	Float float64 `xml:",attr"`
	Uint8 uint8   `xml:",attr"`
	Bool  bool    `xml:",attr"`
	Str   string  `xml:",attr"`
	Bytes []byte  `xml:",attr"`
}

type AttrsTest struct {
	Attrs []Attr  `xml:",any,attr"`
	Int   int     `xml:",attr"`
	Named int     `xml:"int,attr"`
	Float float64 `xml:",attr"`
	Uint8 uint8   `xml:",attr"`
	Bool  bool    `xml:",attr"`
	Str   string  `xml:",attr"`
	Bytes []byte  `xml:",attr"`
}

type OmitAttrTest struct {
	Int   int     `xml:",attr,omitempty"`
	Named int     `xml:"int,attr,omitempty"`
	Float float64 `xml:",attr,omitempty"`
	Uint8 uint8   `xml:",attr,omitempty"`
	Bool  bool    `xml:",attr,omitempty"`
	Str   string  `xml:",attr,omitempty"`
	Bytes []byte  `xml:",attr,omitempty"`
	PStr  *string `xml:",attr,omitempty"`
}

type OmitFieldTest struct {
	Int   int           `xml:",omitempty"`
	Named int           `xml:"int,omitempty"`
	Float float64       `xml:",omitempty"`
	Uint8 uint8         `xml:",omitempty"`
	Bool  bool          `xml:",omitempty"`
	Str   string        `xml:",omitempty"`
	Bytes []byte        `xml:",omitempty"`
	PStr  *string       `xml:",omitempty"`
	Ptr   *PresenceTest `xml:",omitempty"`
}

type AnyTest struct {
	XMLName  struct{}  `xml:"a"`
	Nested   string    `xml:"nested>value"`
	AnyField AnyHolder `xml:",any"`
}

type AnyOmitTest struct {
	XMLName  struct{}   `xml:"a"`
	Nested   string     `xml:"nested>value"`
	AnyField *AnyHolder `xml:",any,omitempty"`
}

type AnySliceTest struct {
	XMLName  struct{}    `xml:"a"`
	Nested   string      `xml:"nested>value"`
	AnyField []AnyHolder `xml:",any"`
}

type AnyHolder struct {
	XMLName Name
	XML     string `xml:",innerxml"`
}

type RecurseA struct {
	A string
	B *RecurseB
}

type RecurseB struct {
	A *RecurseA
	B string
}

type PresenceTest struct {
	Exists *struct{}
}

type IgnoreTest struct {
	PublicSecret string `xml:"-"`
}

type MyBytes []byte

type Data struct {
	Bytes  []byte
	Attr   []byte `xml:",attr"`
	Custom MyBytes
}

type Plain struct {
	V any
}

type MyInt int

type EmbedInt struct {
	MyInt
}

type Strings struct {
	X []string `xml:"A>B,omitempty"`
}

type PointerFieldsTest struct {
	XMLName  Name    `xml:"dummy"`
	Name     *string `xml:"name,attr"`
	Age      *uint   `xml:"age,attr"`
	Empty    *string `xml:"empty,attr"`
	Contents *string `xml:",chardata"`
}

type ChardataEmptyTest struct {
	XMLName  Name    `xml:"test"`
	Contents *string `xml:",chardata"`
}

type PointerAnonFields struct {
	*MyInt
	*NamedType
}

type MyMarshalerTest struct {
}

var _ Marshaler = (*MyMarshalerTest)(nil)

func (m *MyMarshalerTest) MarshalXML(e *Encoder, start StartElement) error {
	e.EncodeToken(start)
	e.EncodeToken(CharData([]byte("hello world")))
	e.EncodeToken(EndElement{start.Name})
	return nil
}

type MyMarshalerAttrTest struct {
}

var _ MarshalerAttr = (*MyMarshalerAttrTest)(nil)

func (m *MyMarshalerAttrTest) MarshalXMLAttr(name Name) (Attr, error) {
	return Attr{name, "hello world"}, nil
}

func (m *MyMarshalerAttrTest) UnmarshalXMLAttr(attr Attr) error {
	return nil
}

type MarshalerStruct struct {
	Foo MyMarshalerAttrTest `xml:",attr"`
}

type InnerStruct struct {
	XMLName Name `xml:"testns outer"`
}

type OuterStruct struct {
	InnerStruct
	IntAttr int `xml:"int,attr"`
}

type OuterNamedStruct struct {
	InnerStruct
	XMLName Name `xml:"outerns test"`
	IntAttr int  `xml:"int,attr"`
}

type OuterNamedOrderedStruct struct {
	XMLName Name `xml:"outerns test"`
	InnerStruct
	IntAttr int `xml:"int,attr"`
}

type OuterOuterStruct struct {
	OuterStruct
}

type NestedAndChardata struct {
	AB       []string `xml:"A>B"`
	Chardata string   `xml:",chardata"`
}

type NestedAndComment struct {
	AB      []string `xml:"A>B"`
	Comment string   `xml:",comment"`
}

type CDataTest struct {
	Chardata string `xml:",cdata"`
}

type NestedAndCData struct {
	AB    []string `xml:"A>B"`
	CDATA string   `xml:",cdata"`
}

func ifaceptr(x any) any {
	return &x
}

func stringptr(x string) *string {
	return &x
}

type T1 struct{}
type T2 struct{}

type IndirComment struct {
	T1      T1
	Comment *string `xml:",comment"`
	T2      T2
}

type DirectComment struct {
	T1      T1
	Comment string `xml:",comment"`
	T2      T2
}

type IfaceComment struct {
	T1      T1
	Comment any `xml:",comment"`
	T2      T2
}

type IndirChardata struct {
	T1       T1
	Chardata *string `xml:",chardata"`
	T2       T2
}

type DirectChardata struct {
	T1       T1
	Chardata string `xml:",chardata"`
	T2       T2
}

type IfaceChardata struct {
	T1       T1
	Chardata any `xml:",chardata"`
	T2       T2
}

type IndirCDATA struct {
	T1    T1
	CDATA *string `xml:",cdata"`
	T2    T2
}

type DirectCDATA struct {
	T1    T1
	CDATA string `xml:",cdata"`
	T2    T2
}

type IfaceCDATA struct {
	T1    T1
	CDATA any `xml:",cdata"`
	T2    T2
}

type IndirInnerXML struct {
	T1       T1
	InnerXML *string `xml:",innerxml"`
	T2       T2
}

type DirectInnerXML struct {
	T1       T1
	InnerXML string `xml:",innerxml"`
	T2       T2
}

type IfaceInnerXML struct {
	T1       T1
	InnerXML any `xml:",innerxml"`
	T2       T2
}

type IndirElement struct {
	T1      T1
	Element *string
	T2      T2
}

type DirectElement struct {
	T1      T1
	Element string
	T2      T2
}

type IfaceElement struct {
	T1      T1
	Element any
	T2      T2
}

type IndirOmitEmpty struct {
	T1        T1
	OmitEmpty *string `xml:",omitempty"`
	T2        T2
}

type DirectOmitEmpty struct {
	T1        T1
	OmitEmpty string `xml:",omitempty"`
	T2        T2
}

type IfaceOmitEmpty struct {
	T1        T1
	OmitEmpty any `xml:",omitempty"`
	T2        T2
}

type IndirAny struct {
	T1  T1
	Any *string `xml:",any"`
	T2  T2
}

type DirectAny struct {
	T1  T1
	Any string `xml:",any"`
	T2  T2
}

type IfaceAny struct {
	T1  T1
	Any any `xml:",any"`
	T2  T2
}

type Generic[T any] struct {
	X T
}

var (
	nameAttr     = "Sarah"
	ageAttr      = uint(12)
	contentsAttr = "lorem ipsum"
	empty        = ""
)

// Unless explicitly stated as such (or *Plain), all of the
// tests below are two-way tests. When introducing new tests,
// please try to make them two-way as well to ensure that
// marshaling and unmarshaling are as symmetrical as feasible.
var marshalTests = []struct {
	Value          any
	ExpectXML      string
	MarshalOnly    bool
	MarshalError   string
	UnmarshalOnly  bool
	UnmarshalError string
}{
	// Test nil marshals to nothing
	{Value: nil, ExpectXML: ``, MarshalOnly: true},
	{Value: nilStruct, ExpectXML: ``, MarshalOnly: true},

	// Test value types
	{Value: &Plain{true}, ExpectXML: `<Plain><V>true</V></Plain>`},
	{Value: &Plain{false}, ExpectXML: `<Plain><V>false</V></Plain>`},
	{Value: &Plain{int(42)}, ExpectXML: `<Plain><V>42</V></Plain>`},
	{Value: &Plain{int8(42)}, ExpectXML: `<Plain><V>42</V></Plain>`},
	{Value: &Plain{int16(42)}, ExpectXML: `<Plain><V>42</V></Plain>`},
	{Value: &Plain{int32(42)}, ExpectXML: `<Plain><V>42</V></Plain>`},
	{Value: &Plain{uint(42)}, ExpectXML: `<Plain><V>42</V></Plain>`},
	{Value: &Plain{uint8(42)}, ExpectXML: `<Plain><V>42</V></Plain>`},
	{Value: &Plain{uint16(42)}, ExpectXML: `<Plain><V>42</V></Plain>`},
	{Value: &Plain{uint32(42)}, ExpectXML: `<Plain><V>42</V></Plain>`},
	{Value: &Plain{float32(1.25)}, ExpectXML: `<Plain><V>1.25</V></Plain>`},
	{Value: &Plain{float64(1.25)}, ExpectXML: `<Plain><V>1.25</V></Plain>`},
	{Value: &Plain{uintptr(0xFFDD)}, ExpectXML: `<Plain><V>65501</V></Plain>`},
	{Value: &Plain{"gopher"}, ExpectXML: `<Plain><V>gopher</V></Plain>`},
	{Value: &Plain{[]byte("gopher")}, ExpectXML: `<Plain><V>gopher</V></Plain>`},
	{Value: &Plain{"</>"}, ExpectXML: `<Plain><V>&lt;/&gt;</V></Plain>`},
	{Value: &Plain{[]byte("</>")}, ExpectXML: `<Plain><V>&lt;/&gt;</V></Plain>`},
	{Value: &Plain{[3]byte{'<', '/', '>'}}, ExpectXML: `<Plain><V>&lt;/&gt;</V></Plain>`},
	{Value: &Plain{NamedType("potato")}, ExpectXML: `<Plain><V>potato</V></Plain>`},
	{Value: &Plain{[]int{1, 2, 3}}, ExpectXML: `<Plain><V>1</V><V>2</V><V>3</V></Plain>`},
	{Value: &Plain{[3]int{1, 2, 3}}, ExpectXML: `<Plain><V>1</V><V>2</V><V>3</V></Plain>`},
	{Value: ifaceptr(true), MarshalOnly: true, ExpectXML: `<bool>true</bool>`},

	// Test time.
	{
		Value:     &Plain{time.Unix(1e9, 123456789).UTC()},
		ExpectXML: `<Plain><V>2001-09-09T01:46:40.123456789Z</V></Plain>`,
	},

	// A pointer to struct{} may be used to test for an element's presence.
	{
		Value:     &PresenceTest{new(struct{})},
		ExpectXML: `<PresenceTest><Exists></Exists></PresenceTest>`,
	},
	{
		Value:     &PresenceTest{},
		ExpectXML: `<PresenceTest></PresenceTest>`,
	},

	// A []byte field is only nil if the element was not found.
	{
		Value:         &Data{},
		ExpectXML:     `<Data></Data>`,
		UnmarshalOnly: true,
	},
	{
		Value:         &Data{Bytes: []byte{}, Custom: MyBytes{}, Attr: []byte{}},
		ExpectXML:     `<Data Attr=""><Bytes></Bytes><Custom></Custom></Data>`,
		UnmarshalOnly: true,
	},

	// Check that []byte works, including named []byte types.
	{
		Value:     &Data{Bytes: []byte("ab"), Custom: MyBytes("cd"), Attr: []byte{'v'}},
		ExpectXML: `<Data Attr="v"><Bytes>ab</Bytes><Custom>cd</Custom></Data>`,
	},

	// Test innerxml
	{
		Value: &SecretAgent{
			Handle:    "007",
			Identity:  "James Bond",
			Obfuscate: "<redacted/>",
		},
		ExpectXML:   `<agent handle="007"><Identity>James Bond</Identity><redacted/></agent>`,
		MarshalOnly: true,
	},
	{
		Value: &SecretAgent{
			Handle:    "007",
			Identity:  "James Bond",
			Obfuscate: "<Identity>James Bond</Identity><redacted/>",
		},
		ExpectXML:     `<agent handle="007"><Identity>James Bond</Identity><redacted/></agent>`,
		UnmarshalOnly: true,
	},

	// Test structs
	{Value: &Port{Type: "ssl", Number: "443"}, ExpectXML: `<port type="ssl">443</port>`},
	{Value: &Port{Number: "443"}, ExpectXML: `<port>443</port>`},
	{Value: &Port{Type: "<unix>"}, ExpectXML: `<port type="&lt;unix&gt;"></port>`},
	{Value: &Port{Number: "443", Comment: "https"}, ExpectXML: `<port><!--https-->443</port>`},
	{Value: &Port{Number: "443", Comment: "add space-"}, ExpectXML: `<port><!--add space- -->443</port>`, MarshalOnly: true},
	{Value: &Domain{Name: []byte("google.com&friends")}, ExpectXML: `<domain>google.com&amp;friends</domain>`},
	{Value: &Domain{Name: []byte("google.com"), Comment: []byte(" &friends ")}, ExpectXML: `<domain>google.com<!-- &friends --></domain>`},
	{Value: &Book{Title: "Pride & Prejudice"}, ExpectXML: `<book>Pride &amp; Prejudice</book>`},
	{Value: &Event{Year: -3114}, ExpectXML: `<event>-3114</event>`},
	{Value: &Movie{Length: 13440}, ExpectXML: `<movie>13440</movie>`},
	{Value: &Pi{Approximation: 3.14159265}, ExpectXML: `<pi>3.1415927</pi>`},
	{Value: &Universe{Visible: 9.3e13}, ExpectXML: `<universe>9.3e+13</universe>`},
	{Value: &Particle{HasMass: true}, ExpectXML: `<particle>true</particle>`},
	{Value: &Departure{When: ParseTime("2013-01-09T00:15:00-09:00")}, ExpectXML: `<departure>2013-01-09T00:15:00-09:00</departure>`},
	{Value: atomValue, ExpectXML: atomXML},
	{Value: &Generic[int]{1}, ExpectXML: `<Generic><X>1</X></Generic>`},
	{
		Value: &Ship{
			Name:  "Heart of Gold",
			Pilot: "Computer",
			Age:   1,
			Drive: ImprobabilityDrive,
			Passenger: []*Passenger{
				{
					Name:   []string{"Zaphod", "Beeblebrox"},
					Weight: 7.25,
				},
				{
					Name:   []string{"Trisha", "McMillen"},
					Weight: 5.5,
				},
				{
					Name:   []string{"Ford", "Prefect"},
					Weight: 7,
				},
				{
					Name:   []string{"Arthur", "Dent"},
					Weight: 6.75,
				},
			},
		},
		ExpectXML: `<spaceship name="Heart of Gold" pilot="Computer">` +
			`<drive>` + strconv.Itoa(int(ImprobabilityDrive)) + `</drive>` +
			`<age>1</age>` +
			`<passenger>` +
			`<name>Zaphod</name>` +
			`<name>Beeblebrox</name>` +
			`<weight>7.25</weight>` +
			`</passenger>` +
			`<passenger>` +
			`<name>Trisha</name>` +
			`<name>McMillen</name>` +
			`<weight>5.5</weight>` +
			`</passenger>` +
			`<passenger>` +
			`<name>Ford</name>` +
			`<name>Prefect</name>` +
			`<weight>7</weight>` +
			`</passenger>` +
			`<passenger>` +
			`<name>Arthur</name>` +
			`<name>Dent</name>` +
			`<weight>6.75</weight>` +
			`</passenger>` +
			`</spaceship>`,
	},

	// Test a>b
	{
		Value: &NestedItems{Items: nil, Item1: nil},
		ExpectXML: `<result>` +
			`<Items>` +
			`</Items>` +
			`</result>`,
	},
	{
		Value: &NestedItems{Items: []string{}, Item1: []string{}},
		ExpectXML: `<result>` +
			`<Items>` +
			`</Items>` +
			`</result>`,
		MarshalOnly: true,
	},
	{
		Value: &NestedItems{Items: nil, Item1: []string{"A"}},
		ExpectXML: `<result>` +
			`<Items>` +
			`<item1>A</item1>` +
			`</Items>` +
			`</result>`,
	},
	{
		Value: &NestedItems{Items: []string{"A", "B"}, Item1: nil},
		ExpectXML: `<result>` +
			`<Items>` +
			`<item>A</item>` +
			`<item>B</item>` +
			`</Items>` +
			`</result>`,
	},
	{
		Value: &NestedItems{Items: []string{"A", "B"}, Item1: []string{"C"}},
		ExpectXML: `<result>` +
			`<Items>` +
			`<item>A</item>` +
			`<item>B</item>` +
			`<item1>C</item1>` +
			`</Items>` +
			`</result>`,
	},
	{
		Value: &NestedOrder{Field1: "C", Field2: "B", Field3: "A"},
		ExpectXML: `<result>` +
			`<parent>` +
			`<c>C</c>` +
			`<b>B</b>` +
			`<a>A</a>` +
			`</parent>` +
			`</result>`,
	},
	{
		Value: &NilTest{A: "A", B: nil, C: "C"},
		ExpectXML: `<NilTest>` +
			`<parent1>` +
			`<parent2><a>A</a></parent2>` +
			`<parent2><c>C</c></parent2>` +
			`</parent1>` +
			`</NilTest>`,
		MarshalOnly: true, // Uses interface{}
	},
	{
		Value: &MixedNested{A: "A", B: "B", C: "C", D: "D"},
		ExpectXML: `<result>` +
			`<parent1><a>A</a></parent1>` +
			`<b>B</b>` +
			`<parent1>` +
			`<parent2><c>C</c></parent2>` +
			`<d>D</d>` +
			`</parent1>` +
			`</result>`,
	},
	{
		Value:     &Service{Port: &Port{Number: "80"}},
		ExpectXML: `<service><host><port>80</port></host></service>`,
	},
	{
		Value:     &Service{},
		ExpectXML: `<service></service>`,
	},
	{
		Value: &Service{Port: &Port{Number: "80"}, Extra1: "A", Extra2: "B"},
		ExpectXML: `<service>` +
			`<host><port>80</port></host>` +
			`<Extra1>A</Extra1>` +
			`<host><extra2>B</extra2></host>` +
			`</service>`,
		MarshalOnly: true,
	},
	{
		Value: &Service{Port: &Port{Number: "80"}, Extra2: "example"},
		ExpectXML: `<service>` +
			`<host><port>80</port></host>` +
			`<host><extra2>example</extra2></host>` +
			`</service>`,
		MarshalOnly: true,
	},
	{
		Value: &struct {
			XMLName struct{} `xml:"space top"`
			A       string   `xml:"x>a"`
			B       string   `xml:"x>b"`
			C       string   `xml:"space x>c"`
			C1      string   `xml:"space1 x>c"`
			D1      string   `xml:"space1 x>d"`
		}{
			A:  "a",
			B:  "b",
			C:  "c",
			C1: "c1",
			D1: "d1",
		},
		ExpectXML: `<top xmlns="space">` +
			`<x><a>a</a><b>b</b><c xmlns="space">c</c>` +
			`<c xmlns="space1">c1</c>` +
			`<d xmlns="space1">d1</d>` +
			`</x>` +
			`</top>`,
	},
	{
		Value: &struct {
			XMLName Name
			A       string `xml:"x>a"`
			B       string `xml:"x>b"`
			C       string `xml:"space x>c"`
			C1      string `xml:"space1 x>c"`
			D1      string `xml:"space1 x>d"`
		}{
			XMLName: Name{
				Space: "space0",
				Local: "top",
			},
			A:  "a",
			B:  "b",
			C:  "c",
			C1: "c1",
			D1: "d1",
		},
		ExpectXML: `<top xmlns="space0">` +
			`<x><a>a</a><b>b</b>` +
			`<c xmlns="space">c</c>` +
			`<c xmlns="space1">c1</c>` +
			`<d xmlns="space1">d1</d>` +
			`</x>` +
			`</top>`,
	},
	{
		Value: &struct {
			XMLName struct{} `xml:"top"`
			B       string   `xml:"space x>b"`
			B1      string   `xml:"space1 x>b"`
		}{
			B:  "b",
			B1: "b1",
		},
		ExpectXML: `<top>` +
			`<x><b xmlns="space">b</b>` +
			`<b xmlns="space1">b1</b></x>` +
			`</top>`,
	},

	// Test struct embedding
	{
		Value: &EmbedA{
			EmbedC: EmbedC{
				FieldA1: "", // Shadowed by A.A
				FieldA2: "", // Shadowed by A.A
				FieldB:  "A.C.B",
				FieldC:  "A.C.C",
			},
			EmbedB: EmbedB{
				FieldB: "A.B.B",
				EmbedC: &EmbedC{
					FieldA1: "A.B.C.A1",
					FieldA2: "A.B.C.A2",
					FieldB:  "", // Shadowed by A.B.B
					FieldC:  "A.B.C.C",
				},
			},
			FieldA: "A.A",
			embedD: embedD{
				FieldE: "A.D.E",
			},
		},
		ExpectXML: `<EmbedA>` +
			`<FieldB>A.C.B</FieldB>` +
			`<FieldC>A.C.C</FieldC>` +
			`<EmbedB>` +
			`<FieldB>A.B.B</FieldB>` +
			`<FieldA>` +
			`<A1>A.B.C.A1</A1>` +
			`<A2>A.B.C.A2</A2>` +
			`</FieldA>` +
			`<FieldC>A.B.C.C</FieldC>` +
			`</EmbedB>` +
			`<FieldA>A.A</FieldA>` +
			`<FieldE>A.D.E</FieldE>` +
			`</EmbedA>`,
	},

	// Anonymous struct pointer field which is nil
	{
		Value:     &EmbedB{},
		ExpectXML: `<EmbedB><FieldB></FieldB></EmbedB>`,
	},

	// Other kinds of nil anonymous fields
	{
		Value:     &PointerAnonFields{},
		ExpectXML: `<PointerAnonFields></PointerAnonFields>`,
	},

	// Test that name casing matters
	{
		Value:     &NameCasing{Xy: "mixed", XY: "upper", XyA: "mixedA", XYA: "upperA"},
		ExpectXML: `<casing Xy="mixedA" XY="upperA"><Xy>mixed</Xy><XY>upper</XY></casing>`,
	},

	// Test the order in which the XML element name is chosen
	{
		Value: &NamePrecedence{
			FromTag:     XMLNameWithoutTag{Value: "A"},
			FromNameVal: XMLNameWithoutTag{XMLName: Name{Local: "InXMLName"}, Value: "B"},
			FromNameTag: XMLNameWithTag{Value: "C"},
			InFieldName: "D",
		},
		ExpectXML: `<Parent>` +
			`<InTag>A</InTag>` +
			`<InXMLName>B</InXMLName>` +
			`<InXMLNameTag>C</InXMLNameTag>` +
			`<InFieldName>D</InFieldName>` +
			`</Parent>`,
		MarshalOnly: true,
	},
	{
		Value: &NamePrecedence{
			XMLName:     Name{Local: "Parent"},
			FromTag:     XMLNameWithoutTag{XMLName: Name{Local: "InTag"}, Value: "A"},
			FromNameVal: XMLNameWithoutTag{XMLName: Name{Local: "FromNameVal"}, Value: "B"},
			FromNameTag: XMLNameWithTag{XMLName: Name{Local: "InXMLNameTag"}, Value: "C"},
			InFieldName: "D",
		},
		ExpectXML: `<Parent>` +
			`<InTag>A</InTag>` +
			`<FromNameVal>B</FromNameVal>` +
			`<InXMLNameTag>C</InXMLNameTag>` +
			`<InFieldName>D</InFieldName>` +
			`</Parent>`,
		UnmarshalOnly: true,
	},

	// xml.Name works in a plain field as well.
	{
		Value:     &NameInField{Name{Space: "ns", Local: "foo"}},
		ExpectXML: `<NameInField><foo xmlns="ns"></foo></NameInField>`,
	},
	{
		Value:         &NameInField{Name{Space: "ns", Local: "foo"}},
		ExpectXML:     `<NameInField><foo xmlns="ns"><ignore></ignore></foo></NameInField>`,
		UnmarshalOnly: true,
	},

	// Marshaling zero xml.Name uses the tag or field name.
	{
		Value:       &NameInField{},
		ExpectXML:   `<NameInField><foo xmlns="ns"></foo></NameInField>`,
		MarshalOnly: true,
	},

	// Test attributes
	{
		Value: &AttrTest{
			Int:   8,
			Named: 9,
			Float: 23.5,
			Uint8: 255,
			Bool:  true,
			Str:   "str",
			Bytes: []byte("byt"),
		},
		ExpectXML: `<AttrTest Int="8" int="9" Float="23.5" Uint8="255"` +
			` Bool="true" Str="str" Bytes="byt"></AttrTest>`,
	},
	{
		Value: &AttrTest{Bytes: []byte{}},
		ExpectXML: `<AttrTest Int="0" int="0" Float="0" Uint8="0"` +
			` Bool="false" Str="" Bytes=""></AttrTest>`,
	},
	{
		Value: &AttrsTest{
			Attrs: []Attr{
				{Name: Name{Local: "Answer"}, Value: "42"},
				{Name: Name{Local: "Int"}, Value: "8"},
				{Name: Name{Local: "int"}, Value: "9"},
				{Name: Name{Local: "Float"}, Value: "23.5"},
				{Name: Name{Local: "Uint8"}, Value: "255"},
				{Name: Name{Local: "Bool"}, Value: "true"},
				{Name: Name{Local: "Str"}, Value: "str"},
				{Name: Name{Local: "Bytes"}, Value: "byt"},
			},
		},
		ExpectXML:   `<AttrsTest Answer="42" Int="8" int="9" Float="23.5" Uint8="255" Bool="true" Str="str" Bytes="byt" Int="0" int="0" Float="0" Uint8="0" Bool="false" Str="" Bytes=""></AttrsTest>`,
		MarshalOnly: true,
	},
	{
		Value: &AttrsTest{
			Attrs: []Attr{
				{Name: Name{Local: "Answer"}, Value: "42"},
			},
			Int:   8,
			Named: 9,
			Float: 23.5,
			Uint8: 255,
			Bool:  true,
			Str:   "str",
			Bytes: []byte("byt"),
		},
		ExpectXML: `<AttrsTest Answer="42" Int="8" int="9" Float="23.5" Uint8="255" Bool="true" Str="str" Bytes="byt"></AttrsTest>`,
	},
	{
		Value: &AttrsTest{
			Attrs: []Attr{
				{Name: Name{Local: "Int"}, Value: "0"},
				{Name: Name{Local: "int"}, Value: "0"},
				{Name: Name{Local: "Float"}, Value: "0"},
				{Name: Name{Local: "Uint8"}, Value: "0"},
				{Name: Name{Local: "Bool"}, Value: "false"},
				{Name: Name{Local: "Str"}},
				{Name: Name{Local: "Bytes"}},
			},
			Bytes: []byte{},
		},
		ExpectXML:   `<AttrsTest Int="0" int="0" Float="0" Uint8="0" Bool="false" Str="" Bytes="" Int="0" int="0" Float="0" Uint8="0" Bool="false" Str="" Bytes=""></AttrsTest>`,
		MarshalOnly: true,
	},
	{
		Value: &OmitAttrTest{
			Int:   8,
			Named: 9,
			Float: 23.5,
			Uint8: 255,
			Bool:  true,
			Str:   "str",
			Bytes: []byte("byt"),
			PStr:  &empty,
		},
		ExpectXML: `<OmitAttrTest Int="8" int="9" Float="23.5" Uint8="255"` +
			` Bool="true" Str="str" Bytes="byt" PStr=""></OmitAttrTest>`,
	},
	{
		Value:     &OmitAttrTest{},
		ExpectXML: `<OmitAttrTest></OmitAttrTest>`,
	},

	// pointer fields
	{
		Value:       &PointerFieldsTest{Name: &nameAttr, Age: &ageAttr, Contents: &contentsAttr},
		ExpectXML:   `<dummy name="Sarah" age="12">lorem ipsum</dummy>`,
		MarshalOnly: true,
	},

	// empty chardata pointer field
	{
		Value:       &ChardataEmptyTest{},
		ExpectXML:   `<test></test>`,
		MarshalOnly: true,
	},

	// omitempty on fields
	{
		Value: &OmitFieldTest{
			Int:   8,
			Named: 9,
			Float: 23.5,
			Uint8: 255,
			Bool:  true,
			Str:   "str",
			Bytes: []byte("byt"),
			PStr:  &empty,
			Ptr:   &PresenceTest{},
		},
		ExpectXML: `<OmitFieldTest>` +
			`<Int>8</Int>` +
			`<int>9</int>` +
			`<Float>23.5</Float>` +
			`<Uint8>255</Uint8>` +
			`<Bool>true</Bool>` +
			`<Str>str</Str>` +
			`<Bytes>byt</Bytes>` +
			`<PStr></PStr>` +
			`<Ptr></Ptr>` +
			`</OmitFieldTest>`,
	},
	{
		Value:     &OmitFieldTest{},
		ExpectXML: `<OmitFieldTest></OmitFieldTest>`,
	},

	// Test ",any"
	{
		ExpectXML: `<a><nested><value>known</value></nested><other><sub>unknown</sub></other></a>`,
		Value: &AnyTest{
			Nested: "known",
			AnyField: AnyHolder{
				XMLName: Name{Local: "other"},
				XML:     "<sub>unknown</sub>",
			},
		},
	},
	{
		Value: &AnyTest{Nested: "known",
			AnyField: AnyHolder{
				XML:     "<unknown/>",
				XMLName: Name{Local: "AnyField"},
			},
		},
		ExpectXML: `<a><nested><value>known</value></nested><AnyField><unknown/></AnyField></a>`,
	},
	{
		ExpectXML: `<a><nested><value>b</value></nested></a>`,
		Value: &AnyOmitTest{
			Nested: "b",
		},
	},
	{
		ExpectXML: `<a><nested><value>b</value></nested><c><d>e</d></c><g xmlns="f"><h>i</h></g></a>`,
		Value: &AnySliceTest{
			Nested: "b",
			AnyField: []AnyHolder{
				{
					XMLName: Name{Local: "c"},
					XML:     "<d>e</d>",
				},
				{
					XMLName: Name{Space: "f", Local: "g"},
					XML:     "<h>i</h>",
				},
			},
		},
	},
	{
		ExpectXML: `<a><nested><value>b</value></nested></a>`,
		Value: &AnySliceTest{
			Nested: "b",
		},
	},

	// Test recursive types.
	{
		Value: &RecurseA{
			A: "a1",
			B: &RecurseB{
				A: &RecurseA{"a2", nil},
				B: "b1",
			},
		},
		ExpectXML: `<RecurseA><A>a1</A><B><A><A>a2</A></A><B>b1</B></B></RecurseA>`,
	},

	// Test ignoring fields via "-" tag
	{
		ExpectXML: `<IgnoreTest></IgnoreTest>`,
		Value:     &IgnoreTest{},
	},
	{
		ExpectXML:   `<IgnoreTest></IgnoreTest>`,
		Value:       &IgnoreTest{PublicSecret: "can't tell"},
		MarshalOnly: true,
	},
	{
		ExpectXML:     `<IgnoreTest><PublicSecret>ignore me</PublicSecret></IgnoreTest>`,
		Value:         &IgnoreTest{},
		UnmarshalOnly: true,
	},

	// Test escaping.
	{
		ExpectXML: `<a><nested><value>dquote: &#34;; squote: &#39;; ampersand: &amp;; less: &lt;; greater: &gt;;</value></nested><empty></empty></a>`,
		Value: &AnyTest{
			Nested:   `dquote: "; squote: '; ampersand: &; less: <; greater: >;`,
			AnyField: AnyHolder{XMLName: Name{Local: "empty"}},
		},
	},
	{
		ExpectXML: `<a><nested><value>newline: &#xA;; cr: &#xD;; tab: &#x9;;</value></nested><AnyField></AnyField></a>`,
		Value: &AnyTest{
			Nested:   "newline: \n; cr: \r; tab: \t;",
			AnyField: AnyHolder{XMLName: Name{Local: "AnyField"}},
		},
	},
	{
		ExpectXML: "<a><nested><value>1\r2\r\n3\n\r4\n5</value></nested></a>",
		Value: &AnyTest{
			Nested: "1\n2\n3\n\n4\n5",
		},
		UnmarshalOnly: true,
	},
	{
		ExpectXML: `<EmbedInt><MyInt>42</MyInt></EmbedInt>`,
		Value: &EmbedInt{
			MyInt: 42,
		},
	},
	// Test outputting CDATA-wrapped text.
	{
		ExpectXML: `<CDataTest></CDataTest>`,
		Value:     &CDataTest{},
	},
	{
		ExpectXML: `<CDataTest><![CDATA[http://example.com/tests/1?foo=1&bar=baz]]></CDataTest>`,
		Value: &CDataTest{
			Chardata: "http://example.com/tests/1?foo=1&bar=baz",
		},
	},
	{
		ExpectXML: `<CDataTest><![CDATA[Literal <![CDATA[Nested]]]]><![CDATA[>!]]></CDataTest>`,
		Value: &CDataTest{
			Chardata: "Literal <![CDATA[Nested]]>!",
		},
	},
	{
		ExpectXML: `<CDataTest><![CDATA[<![CDATA[Nested]]]]><![CDATA[> Literal!]]></CDataTest>`,
		Value: &CDataTest{
			Chardata: "<![CDATA[Nested]]> Literal!",
		},
	},
	{
		ExpectXML: `<CDataTest><![CDATA[<![CDATA[Nested]]]]><![CDATA[> Literal! <![CDATA[Nested]]]]><![CDATA[> Literal!]]></CDataTest>`,
		Value: &CDataTest{
			Chardata: "<![CDATA[Nested]]> Literal! <![CDATA[Nested]]> Literal!",
		},
	},
	{
		ExpectXML: `<CDataTest><![CDATA[<![CDATA[<![CDATA[Nested]]]]><![CDATA[>]]]]><![CDATA[>]]></CDataTest>`,
		Value: &CDataTest{
			Chardata: "<![CDATA[<![CDATA[Nested]]>]]>",
		},
	},

	// Test omitempty with parent chain; see golang.org/issue/4168.
	{
		ExpectXML: `<Strings><A></A></Strings>`,
		Value:     &Strings{},
	},
	// Custom marshalers.
	{
		ExpectXML: `<MyMarshalerTest>hello world</MyMarshalerTest>`,
		Value:     &MyMarshalerTest{},
	},
	{
		ExpectXML: `<MarshalerStruct Foo="hello world"></MarshalerStruct>`,
		Value:     &MarshalerStruct{},
	},
	{
		ExpectXML: `<outer xmlns="testns" int="10"></outer>`,
		Value:     &OuterStruct{IntAttr: 10},
	},
	{
		ExpectXML: `<test xmlns="outerns" int="10"></test>`,
		Value:     &OuterNamedStruct{XMLName: Name{Space: "outerns", Local: "test"}, IntAttr: 10},
	},
	{
		ExpectXML: `<test xmlns="outerns" int="10"></test>`,
		Value:     &OuterNamedOrderedStruct{XMLName: Name{Space: "outerns", Local: "test"}, IntAttr: 10},
	},
	{
		ExpectXML: `<outer xmlns="testns" int="10"></outer>`,
		Value:     &OuterOuterStruct{OuterStruct{IntAttr: 10}},
	},
	{
		ExpectXML: `<NestedAndChardata><A><B></B><B></B></A>test</NestedAndChardata>`,
		Value:     &NestedAndChardata{AB: make([]string, 2), Chardata: "test"},
	},
	{
		ExpectXML: `<NestedAndComment><A><B></B><B></B></A><!--test--></NestedAndComment>`,
		Value:     &NestedAndComment{AB: make([]string, 2), Comment: "test"},
	},
	{
		ExpectXML: `<NestedAndCData><A><B></B><B></B></A><![CDATA[test]]></NestedAndCData>`,
		Value:     &NestedAndCData{AB: make([]string, 2), CDATA: "test"},
	},
	// Test pointer indirection in various kinds of fields.
	// https://golang.org/issue/19063
	{
		ExpectXML:   `<IndirComment><T1></T1><!--hi--><T2></T2></IndirComment>`,
		Value:       &IndirComment{Comment: stringptr("hi")},
		MarshalOnly: true,
	},
	{
		ExpectXML:   `<IndirComment><T1></T1><T2></T2></IndirComment>`,
		Value:       &IndirComment{Comment: stringptr("")},
		MarshalOnly: true,
	},
	{
		ExpectXML:    `<IndirComment><T1></T1><T2></T2></IndirComment>`,
		Value:        &IndirComment{Comment: nil},
		MarshalError: "xml: bad type for comment field of xml.IndirComment",
	},
	{
		ExpectXML:     `<IndirComment><T1></T1><!--hi--><T2></T2></IndirComment>`,
		Value:         &IndirComment{Comment: nil},
		UnmarshalOnly: true,
	},
	{
		ExpectXML:   `<IfaceComment><T1></T1><!--hi--><T2></T2></IfaceComment>`,
		Value:       &IfaceComment{Comment: "hi"},
		MarshalOnly: true,
	},
	{
		ExpectXML:     `<IfaceComment><T1></T1><!--hi--><T2></T2></IfaceComment>`,
		Value:         &IfaceComment{Comment: nil},
		UnmarshalOnly: true,
	},
	{
		ExpectXML:    `<IfaceComment><T1></T1><T2></T2></IfaceComment>`,
		Value:        &IfaceComment{Comment: nil},
		MarshalError: "xml: bad type for comment field of xml.IfaceComment",
	},
	{
		ExpectXML:     `<IfaceComment><T1></T1><T2></T2></IfaceComment>`,
		Value:         &IfaceComment{Comment: nil},
		UnmarshalOnly: true,
	},
	{
		ExpectXML: `<DirectComment><T1></T1><!--hi--><T2></T2></DirectComment>`,
		Value:     &DirectComment{Comment: string("hi")},
	},
	{
		ExpectXML: `<DirectComment><T1></T1><T2></T2></DirectComment>`,
		Value:     &DirectComment{Comment: string("")},
	},
	{
		ExpectXML: `<IndirChardata><T1></T1>hi<T2></T2></IndirChardata>`,
		Value:     &IndirChardata{Chardata: stringptr("hi")},
	},
	{
		ExpectXML:     `<IndirChardata><T1></T1><![CDATA[hi]]><T2></T2></IndirChardata>`,
		Value:         &IndirChardata{Chardata: stringptr("hi")},
		UnmarshalOnly: true, // marshals without CDATA
	},
	{
		ExpectXML: `<IndirChardata><T1></T1><T2></T2></IndirChardata>`,
		Value:     &IndirChardata{Chardata: stringptr("")},
	},
	{
		ExpectXML:   `<IndirChardata><T1></T1><T2></T2></IndirChardata>`,
		Value:       &IndirChardata{Chardata: nil},
		MarshalOnly: true, // unmarshal leaves Chardata=stringptr("")
	},
	{
		ExpectXML:      `<IfaceChardata><T1></T1>hi<T2></T2></IfaceChardata>`,
		Value:          &IfaceChar
```