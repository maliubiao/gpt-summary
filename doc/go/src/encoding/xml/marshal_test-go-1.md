Response:
The user wants a summary of the functionality of the provided Go code snippet. This code is part of the `encoding/xml` package in Go, specifically the `marshal_test.go` file.

Based on the variable names and structure of the code, it seems to be focused on testing the `Marshal` and `Unmarshal` functions of the `encoding/xml` package. It covers various scenarios, including:

1. **Handling of different data types:** Strings, pointers to strings, interfaces, etc.
2. **Handling of XML elements and attributes.**
3. **Handling of CDATA sections.**
4. **Handling of InnerXML.**
5. **Handling of `omitempty` tags.**
6. **Error handling during marshaling and unmarshaling.**
7. **Testing `MarshalIndent` for formatted XML output.**
8. **Testing `EncodeToken` for manual XML token encoding.**
9. **Testing error conditions during writing to the output.**

Therefore, the main function of this code is to **test the XML marshaling and unmarshaling capabilities of the `encoding/xml` package in Go.**
这是go语言标准库 `encoding/xml` 包中 `marshal_test.go` 文件的一部分，它主要的功能是**测试 `encoding/xml` 包中将 Go 数据结构序列化（Marshal）成 XML 和从 XML 反序列化（Unmarshal）回 Go 数据结构的功能。**

具体来说，这部分代码定义了一系列的测试用例，每个用例包含以下信息：

* `ExpectXML`: 期望的 XML 输出字符串。
* `Value`: 要进行序列化或反序列化的 Go 数据结构实例。
* `UnmarshalOnly`: 一个布尔值，表示这个用例只用于反序列化测试，不进行序列化测试。
* `MarshalOnly`: 一个布尔值，表示这个用例只用于序列化测试，不进行反序列化测试。
* `UnmarshalError`:  期望的反序列化错误信息，如果反序列化应该成功，则为空字符串。
* `MarshalError`: 期望的序列化错误信息，如果序列化应该成功，则为空字符串。

通过这些测试用例，`encoding/xml` 包的开发者可以验证：

1. **基础的序列化和反序列化是否正常工作。**
2. **不同类型的 Go 数据结构（如字符串、指针、接口等）是否能正确地序列化和反序列化成对应的 XML 结构。**
3. **是否正确处理了 XML 中的特殊结构，例如 CDATA、InnerXML、属性等。**
4. **在遇到错误情况时，是否能产生预期的错误。**

**代码功能举例说明 (基于代码推理):**

以下是一个基于代码片段的简单例子，展示了 `Marshal` 和 `Unmarshal` 的使用，并附带了假设的输入和输出：

```go
package main

import (
	"encoding/xml"
	"fmt"
	"log"
)

// 定义一个简单的 Go 结构体
type Person struct {
	Name string `xml:"name"`
	Age  int    `xml:"age"`
}

func main() {
	// 假设的输入：一个 Person 结构体
	input := Person{Name: "张三", Age: 30}

	// 序列化为 XML
	output, err := xml.Marshal(input)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("序列化后的 XML: %s\n", output)

	// 假设的输出 (与 ExpectXML 类似):
	// <Person><name>张三</name><age>30</age></Person>

	// 反序列化回 Go 结构体
	var p Person
	err = xml.Unmarshal(output, &p)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("反序列化后的 Go 结构体: %+v\n", p)

	// 假设的输出:
	// {Name:张三 Age:30}
}
```

**代码推理与假设输入输出的例子 (基于提供的测试用例):**

提供的代码片段中包含很多测试用例，我们以 `DirectChardata` 这个结构体为例进行推理。

假设我们有以下 Go 结构体定义：

```go
type DirectChardata struct {
	T1       string `xml:"T1"`
	Chardata string `xml:",chardata"`
	T2       string `xml:"T2"`
}
```

以及一个测试用例：

```go
{
	ExpectXML: `<DirectChardata><T1></T1>hi<T2></T2></DirectChardata>`,
	Value:     &DirectChardata{Chardata: string("hi")},
},
```

**推理:**

这个测试用例旨在测试 `encoding/xml` 如何处理 `chardata` 标签。当 `Chardata` 字段被赋值为 "hi" 时，序列化后的 XML 中，"hi" 会直接出现在 `<T1>` 和 `<T2>` 标签之间，而不是被包含在子标签中。

**假设输入:**

```go
input := &DirectChardata{Chardata: "hi"}
```

**预期输出 (Marshal):**

```xml
<DirectChardata><T1></T1>hi<T2></T2></DirectChardata>
```

**反过来，假设输入 (Unmarshal):**

```xml
<DirectChardata><T1></T1>hello<T2></T2></DirectChardata>
```

**预期输出 (Unmarshal 后的 Go 结构体):**

```go
&DirectChardata{Chardata: "hello"}
```

**命令行参数的具体处理:**

这段代码本身是测试代码，通常不会直接涉及命令行参数的处理。 `go test` 命令会执行这些测试用例。 `go test` 命令本身有一些参数，例如指定要测试的包、运行特定的测试用例等，但这些参数是 `go test` 命令的参数，而不是这段代码自身的参数。

**使用者易犯错的点:**

基于这段测试代码，可以推断出一些使用 `encoding/xml` 包时容易犯错的点：

1. **将接口类型用于带有 `chardata` 或 XML 子元素的结构体字段。**  从测试用例中可以看到很多 `UnmarshalError: "cannot unmarshal into interface {}"`，这暗示了直接将 XML 内容反序列化到接口类型可能存在问题，尤其是在处理文本内容或子元素时。

   **错误示例:**

   ```go
   type IfaceChardata struct {
       T1       string      `xml:"T1"`
       Chardata interface{} `xml:",chardata"` // 容易出错
       T2       string      `xml:"T2"`
   }
   ```

2. **混淆使用 `chardata` 和子元素。**  如果一个字段被标记为 `chardata`，那么 XML 中的文本内容会直接映射到该字段，不能同时包含子元素。

3. **不理解 `InnerXML` 的作用。**  `InnerXML` 允许将 XML 片段原样嵌入到 Go 结构体中，但需要小心处理，因为它不会被进一步解析。

4. **在 `omitempty` 的使用上存在误解。**  例如，对于指针类型，即使指针不为 `nil` 但指向的值是零值或空值，在 Go 1.8 之后，仍然可能会输出对应的 XML 标签。

**归纳一下它的功能（针对第2部分）:**

这部分代码主要测试了 `encoding/xml` 包对于 **XML 文本内容 (Character Data, CDATA) 和内部 XML (InnerXML)** 的序列化和反序列化处理。它涵盖了以下几种情况：

* **直接将字符串作为文本内容 (`chardata`) 嵌入到 XML 元素中。**
* **使用 CDATA 块包裹文本内容。**
* **将 XML 片段作为字符串嵌入到元素中 (`InnerXML`)。**
* **各种类型的 Go 字段（指针、接口、直接类型）在处理这些 XML 结构时的行为。**
* **针对只进行序列化或只进行反序列化的特定场景进行测试。**
* **预期在某些情况下反序列化会失败，并验证了预期的错误信息。**

通过这些测试用例，开发者可以确保 `encoding/xml` 包能够正确地处理 XML 文档中的文本内容和内部结构，并且在遇到不支持的情况时能够给出合理的错误提示。

### 提示词
```
这是路径为go/src/encoding/xml/marshal_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```go
data{Chardata: string("hi")},
		UnmarshalError: "cannot unmarshal into interface {}",
	},
	{
		ExpectXML:      `<IfaceChardata><T1></T1><![CDATA[hi]]><T2></T2></IfaceChardata>`,
		Value:          &IfaceChardata{Chardata: string("hi")},
		UnmarshalOnly:  true, // marshals without CDATA
		UnmarshalError: "cannot unmarshal into interface {}",
	},
	{
		ExpectXML:      `<IfaceChardata><T1></T1><T2></T2></IfaceChardata>`,
		Value:          &IfaceChardata{Chardata: string("")},
		UnmarshalError: "cannot unmarshal into interface {}",
	},
	{
		ExpectXML:      `<IfaceChardata><T1></T1><T2></T2></IfaceChardata>`,
		Value:          &IfaceChardata{Chardata: nil},
		UnmarshalError: "cannot unmarshal into interface {}",
	},
	{
		ExpectXML: `<DirectChardata><T1></T1>hi<T2></T2></DirectChardata>`,
		Value:     &DirectChardata{Chardata: string("hi")},
	},
	{
		ExpectXML:     `<DirectChardata><T1></T1><![CDATA[hi]]><T2></T2></DirectChardata>`,
		Value:         &DirectChardata{Chardata: string("hi")},
		UnmarshalOnly: true, // marshals without CDATA
	},
	{
		ExpectXML: `<DirectChardata><T1></T1><T2></T2></DirectChardata>`,
		Value:     &DirectChardata{Chardata: string("")},
	},
	{
		ExpectXML: `<IndirCDATA><T1></T1><![CDATA[hi]]><T2></T2></IndirCDATA>`,
		Value:     &IndirCDATA{CDATA: stringptr("hi")},
	},
	{
		ExpectXML:     `<IndirCDATA><T1></T1>hi<T2></T2></IndirCDATA>`,
		Value:         &IndirCDATA{CDATA: stringptr("hi")},
		UnmarshalOnly: true, // marshals with CDATA
	},
	{
		ExpectXML: `<IndirCDATA><T1></T1><T2></T2></IndirCDATA>`,
		Value:     &IndirCDATA{CDATA: stringptr("")},
	},
	{
		ExpectXML:   `<IndirCDATA><T1></T1><T2></T2></IndirCDATA>`,
		Value:       &IndirCDATA{CDATA: nil},
		MarshalOnly: true, // unmarshal leaves CDATA=stringptr("")
	},
	{
		ExpectXML:      `<IfaceCDATA><T1></T1><![CDATA[hi]]><T2></T2></IfaceCDATA>`,
		Value:          &IfaceCDATA{CDATA: string("hi")},
		UnmarshalError: "cannot unmarshal into interface {}",
	},
	{
		ExpectXML:      `<IfaceCDATA><T1></T1>hi<T2></T2></IfaceCDATA>`,
		Value:          &IfaceCDATA{CDATA: string("hi")},
		UnmarshalOnly:  true, // marshals with CDATA
		UnmarshalError: "cannot unmarshal into interface {}",
	},
	{
		ExpectXML:      `<IfaceCDATA><T1></T1><T2></T2></IfaceCDATA>`,
		Value:          &IfaceCDATA{CDATA: string("")},
		UnmarshalError: "cannot unmarshal into interface {}",
	},
	{
		ExpectXML:      `<IfaceCDATA><T1></T1><T2></T2></IfaceCDATA>`,
		Value:          &IfaceCDATA{CDATA: nil},
		UnmarshalError: "cannot unmarshal into interface {}",
	},
	{
		ExpectXML: `<DirectCDATA><T1></T1><![CDATA[hi]]><T2></T2></DirectCDATA>`,
		Value:     &DirectCDATA{CDATA: string("hi")},
	},
	{
		ExpectXML:     `<DirectCDATA><T1></T1>hi<T2></T2></DirectCDATA>`,
		Value:         &DirectCDATA{CDATA: string("hi")},
		UnmarshalOnly: true, // marshals with CDATA
	},
	{
		ExpectXML: `<DirectCDATA><T1></T1><T2></T2></DirectCDATA>`,
		Value:     &DirectCDATA{CDATA: string("")},
	},
	{
		ExpectXML:   `<IndirInnerXML><T1></T1><hi/><T2></T2></IndirInnerXML>`,
		Value:       &IndirInnerXML{InnerXML: stringptr("<hi/>")},
		MarshalOnly: true,
	},
	{
		ExpectXML:   `<IndirInnerXML><T1></T1><T2></T2></IndirInnerXML>`,
		Value:       &IndirInnerXML{InnerXML: stringptr("")},
		MarshalOnly: true,
	},
	{
		ExpectXML: `<IndirInnerXML><T1></T1><T2></T2></IndirInnerXML>`,
		Value:     &IndirInnerXML{InnerXML: nil},
	},
	{
		ExpectXML:     `<IndirInnerXML><T1></T1><hi/><T2></T2></IndirInnerXML>`,
		Value:         &IndirInnerXML{InnerXML: nil},
		UnmarshalOnly: true,
	},
	{
		ExpectXML:   `<IfaceInnerXML><T1></T1><hi/><T2></T2></IfaceInnerXML>`,
		Value:       &IfaceInnerXML{InnerXML: "<hi/>"},
		MarshalOnly: true,
	},
	{
		ExpectXML:     `<IfaceInnerXML><T1></T1><hi/><T2></T2></IfaceInnerXML>`,
		Value:         &IfaceInnerXML{InnerXML: nil},
		UnmarshalOnly: true,
	},
	{
		ExpectXML: `<IfaceInnerXML><T1></T1><T2></T2></IfaceInnerXML>`,
		Value:     &IfaceInnerXML{InnerXML: nil},
	},
	{
		ExpectXML:     `<IfaceInnerXML><T1></T1><T2></T2></IfaceInnerXML>`,
		Value:         &IfaceInnerXML{InnerXML: nil},
		UnmarshalOnly: true,
	},
	{
		ExpectXML:   `<DirectInnerXML><T1></T1><hi/><T2></T2></DirectInnerXML>`,
		Value:       &DirectInnerXML{InnerXML: string("<hi/>")},
		MarshalOnly: true,
	},
	{
		ExpectXML:     `<DirectInnerXML><T1></T1><hi/><T2></T2></DirectInnerXML>`,
		Value:         &DirectInnerXML{InnerXML: string("<T1></T1><hi/><T2></T2>")},
		UnmarshalOnly: true,
	},
	{
		ExpectXML:   `<DirectInnerXML><T1></T1><T2></T2></DirectInnerXML>`,
		Value:       &DirectInnerXML{InnerXML: string("")},
		MarshalOnly: true,
	},
	{
		ExpectXML:     `<DirectInnerXML><T1></T1><T2></T2></DirectInnerXML>`,
		Value:         &DirectInnerXML{InnerXML: string("<T1></T1><T2></T2>")},
		UnmarshalOnly: true,
	},
	{
		ExpectXML: `<IndirElement><T1></T1><Element>hi</Element><T2></T2></IndirElement>`,
		Value:     &IndirElement{Element: stringptr("hi")},
	},
	{
		ExpectXML: `<IndirElement><T1></T1><Element></Element><T2></T2></IndirElement>`,
		Value:     &IndirElement{Element: stringptr("")},
	},
	{
		ExpectXML: `<IndirElement><T1></T1><T2></T2></IndirElement>`,
		Value:     &IndirElement{Element: nil},
	},
	{
		ExpectXML:   `<IfaceElement><T1></T1><Element>hi</Element><T2></T2></IfaceElement>`,
		Value:       &IfaceElement{Element: "hi"},
		MarshalOnly: true,
	},
	{
		ExpectXML:     `<IfaceElement><T1></T1><Element>hi</Element><T2></T2></IfaceElement>`,
		Value:         &IfaceElement{Element: nil},
		UnmarshalOnly: true,
	},
	{
		ExpectXML: `<IfaceElement><T1></T1><T2></T2></IfaceElement>`,
		Value:     &IfaceElement{Element: nil},
	},
	{
		ExpectXML:     `<IfaceElement><T1></T1><T2></T2></IfaceElement>`,
		Value:         &IfaceElement{Element: nil},
		UnmarshalOnly: true,
	},
	{
		ExpectXML: `<DirectElement><T1></T1><Element>hi</Element><T2></T2></DirectElement>`,
		Value:     &DirectElement{Element: string("hi")},
	},
	{
		ExpectXML: `<DirectElement><T1></T1><Element></Element><T2></T2></DirectElement>`,
		Value:     &DirectElement{Element: string("")},
	},
	{
		ExpectXML: `<IndirOmitEmpty><T1></T1><OmitEmpty>hi</OmitEmpty><T2></T2></IndirOmitEmpty>`,
		Value:     &IndirOmitEmpty{OmitEmpty: stringptr("hi")},
	},
	{
		// Note: Changed in Go 1.8 to include <OmitEmpty> element (because x.OmitEmpty != nil).
		ExpectXML:   `<IndirOmitEmpty><T1></T1><OmitEmpty></OmitEmpty><T2></T2></IndirOmitEmpty>`,
		Value:       &IndirOmitEmpty{OmitEmpty: stringptr("")},
		MarshalOnly: true,
	},
	{
		ExpectXML:     `<IndirOmitEmpty><T1></T1><OmitEmpty></OmitEmpty><T2></T2></IndirOmitEmpty>`,
		Value:         &IndirOmitEmpty{OmitEmpty: stringptr("")},
		UnmarshalOnly: true,
	},
	{
		ExpectXML: `<IndirOmitEmpty><T1></T1><T2></T2></IndirOmitEmpty>`,
		Value:     &IndirOmitEmpty{OmitEmpty: nil},
	},
	{
		ExpectXML:   `<IfaceOmitEmpty><T1></T1><OmitEmpty>hi</OmitEmpty><T2></T2></IfaceOmitEmpty>`,
		Value:       &IfaceOmitEmpty{OmitEmpty: "hi"},
		MarshalOnly: true,
	},
	{
		ExpectXML:     `<IfaceOmitEmpty><T1></T1><OmitEmpty>hi</OmitEmpty><T2></T2></IfaceOmitEmpty>`,
		Value:         &IfaceOmitEmpty{OmitEmpty: nil},
		UnmarshalOnly: true,
	},
	{
		ExpectXML: `<IfaceOmitEmpty><T1></T1><T2></T2></IfaceOmitEmpty>`,
		Value:     &IfaceOmitEmpty{OmitEmpty: nil},
	},
	{
		ExpectXML:     `<IfaceOmitEmpty><T1></T1><T2></T2></IfaceOmitEmpty>`,
		Value:         &IfaceOmitEmpty{OmitEmpty: nil},
		UnmarshalOnly: true,
	},
	{
		ExpectXML: `<DirectOmitEmpty><T1></T1><OmitEmpty>hi</OmitEmpty><T2></T2></DirectOmitEmpty>`,
		Value:     &DirectOmitEmpty{OmitEmpty: string("hi")},
	},
	{
		ExpectXML: `<DirectOmitEmpty><T1></T1><T2></T2></DirectOmitEmpty>`,
		Value:     &DirectOmitEmpty{OmitEmpty: string("")},
	},
	{
		ExpectXML: `<IndirAny><T1></T1><Any>hi</Any><T2></T2></IndirAny>`,
		Value:     &IndirAny{Any: stringptr("hi")},
	},
	{
		ExpectXML: `<IndirAny><T1></T1><Any></Any><T2></T2></IndirAny>`,
		Value:     &IndirAny{Any: stringptr("")},
	},
	{
		ExpectXML: `<IndirAny><T1></T1><T2></T2></IndirAny>`,
		Value:     &IndirAny{Any: nil},
	},
	{
		ExpectXML:   `<IfaceAny><T1></T1><Any>hi</Any><T2></T2></IfaceAny>`,
		Value:       &IfaceAny{Any: "hi"},
		MarshalOnly: true,
	},
	{
		ExpectXML:     `<IfaceAny><T1></T1><Any>hi</Any><T2></T2></IfaceAny>`,
		Value:         &IfaceAny{Any: nil},
		UnmarshalOnly: true,
	},
	{
		ExpectXML: `<IfaceAny><T1></T1><T2></T2></IfaceAny>`,
		Value:     &IfaceAny{Any: nil},
	},
	{
		ExpectXML:     `<IfaceAny><T1></T1><T2></T2></IfaceAny>`,
		Value:         &IfaceAny{Any: nil},
		UnmarshalOnly: true,
	},
	{
		ExpectXML: `<DirectAny><T1></T1><Any>hi</Any><T2></T2></DirectAny>`,
		Value:     &DirectAny{Any: string("hi")},
	},
	{
		ExpectXML: `<DirectAny><T1></T1><Any></Any><T2></T2></DirectAny>`,
		Value:     &DirectAny{Any: string("")},
	},
	{
		ExpectXML:     `<IndirFoo><T1></T1><Foo>hi</Foo><T2></T2></IndirFoo>`,
		Value:         &IndirAny{Any: stringptr("hi")},
		UnmarshalOnly: true,
	},
	{
		ExpectXML:     `<IndirFoo><T1></T1><Foo></Foo><T2></T2></IndirFoo>`,
		Value:         &IndirAny{Any: stringptr("")},
		UnmarshalOnly: true,
	},
	{
		ExpectXML:     `<IndirFoo><T1></T1><T2></T2></IndirFoo>`,
		Value:         &IndirAny{Any: nil},
		UnmarshalOnly: true,
	},
	{
		ExpectXML:     `<IfaceFoo><T1></T1><Foo>hi</Foo><T2></T2></IfaceFoo>`,
		Value:         &IfaceAny{Any: nil},
		UnmarshalOnly: true,
	},
	{
		ExpectXML:     `<IfaceFoo><T1></T1><T2></T2></IfaceFoo>`,
		Value:         &IfaceAny{Any: nil},
		UnmarshalOnly: true,
	},
	{
		ExpectXML:     `<IfaceFoo><T1></T1><T2></T2></IfaceFoo>`,
		Value:         &IfaceAny{Any: nil},
		UnmarshalOnly: true,
	},
	{
		ExpectXML:     `<DirectFoo><T1></T1><Foo>hi</Foo><T2></T2></DirectFoo>`,
		Value:         &DirectAny{Any: string("hi")},
		UnmarshalOnly: true,
	},
	{
		ExpectXML:     `<DirectFoo><T1></T1><Foo></Foo><T2></T2></DirectFoo>`,
		Value:         &DirectAny{Any: string("")},
		UnmarshalOnly: true,
	},
}

func TestMarshal(t *testing.T) {
	for idx, test := range marshalTests {
		if test.UnmarshalOnly {
			continue
		}

		t.Run(fmt.Sprintf("%d", idx), func(t *testing.T) {
			data, err := Marshal(test.Value)
			if err != nil {
				if test.MarshalError == "" {
					t.Errorf("marshal(%#v): %s", test.Value, err)
					return
				}
				if !strings.Contains(err.Error(), test.MarshalError) {
					t.Errorf("marshal(%#v): %s, want %q", test.Value, err, test.MarshalError)
				}
				return
			}
			if test.MarshalError != "" {
				t.Errorf("Marshal succeeded, want error %q", test.MarshalError)
				return
			}
			if got, want := string(data), test.ExpectXML; got != want {
				if strings.Contains(want, "\n") {
					t.Errorf("marshal(%#v):\nHAVE:\n%s\nWANT:\n%s", test.Value, got, want)
				} else {
					t.Errorf("marshal(%#v):\nhave %#q\nwant %#q", test.Value, got, want)
				}
			}
		})
	}
}

type AttrParent struct {
	X string `xml:"X>Y,attr"`
}

type BadAttr struct {
	Name map[string]string `xml:"name,attr"`
}

var marshalErrorTests = []struct {
	Value any
	Err   string
	Kind  reflect.Kind
}{
	{
		Value: make(chan bool),
		Err:   "xml: unsupported type: chan bool",
		Kind:  reflect.Chan,
	},
	{
		Value: map[string]string{
			"question": "What do you get when you multiply six by nine?",
			"answer":   "42",
		},
		Err:  "xml: unsupported type: map[string]string",
		Kind: reflect.Map,
	},
	{
		Value: map[*Ship]bool{nil: false},
		Err:   "xml: unsupported type: map[*xml.Ship]bool",
		Kind:  reflect.Map,
	},
	{
		Value: &Domain{Comment: []byte("f--bar")},
		Err:   `xml: comments must not contain "--"`,
	},
	// Reject parent chain with attr, never worked; see golang.org/issue/5033.
	{
		Value: &AttrParent{},
		Err:   `xml: X>Y chain not valid with attr flag`,
	},
	{
		Value: BadAttr{map[string]string{"X": "Y"}},
		Err:   `xml: unsupported type: map[string]string`,
	},
}

var marshalIndentTests = []struct {
	Value     any
	Prefix    string
	Indent    string
	ExpectXML string
}{
	{
		Value: &SecretAgent{
			Handle:    "007",
			Identity:  "James Bond",
			Obfuscate: "<redacted/>",
		},
		Prefix:    "",
		Indent:    "\t",
		ExpectXML: "<agent handle=\"007\">\n\t<Identity>James Bond</Identity><redacted/>\n</agent>",
	},
}

func TestMarshalErrors(t *testing.T) {
	for idx, test := range marshalErrorTests {
		data, err := Marshal(test.Value)
		if err == nil {
			t.Errorf("#%d: marshal(%#v) = [success] %q, want error %v", idx, test.Value, data, test.Err)
			continue
		}
		if err.Error() != test.Err {
			t.Errorf("#%d: marshal(%#v) = [error] %v, want %v", idx, test.Value, err, test.Err)
		}
		if test.Kind != reflect.Invalid {
			if kind := err.(*UnsupportedTypeError).Type.Kind(); kind != test.Kind {
				t.Errorf("#%d: marshal(%#v) = [error kind] %s, want %s", idx, test.Value, kind, test.Kind)
			}
		}
	}
}

// Do invertibility testing on the various structures that we test
func TestUnmarshal(t *testing.T) {
	for i, test := range marshalTests {
		if test.MarshalOnly {
			continue
		}
		if _, ok := test.Value.(*Plain); ok {
			continue
		}
		if test.ExpectXML == `<top>`+
			`<x><b xmlns="space">b</b>`+
			`<b xmlns="space1">b1</b></x>`+
			`</top>` {
			// TODO(rogpeppe): re-enable this test in
			// https://go-review.googlesource.com/#/c/5910/
			continue
		}

		vt := reflect.TypeOf(test.Value)
		dest := reflect.New(vt.Elem()).Interface()
		err := Unmarshal([]byte(test.ExpectXML), dest)

		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			switch fix := dest.(type) {
			case *Feed:
				fix.Author.InnerXML = ""
				for i := range fix.Entry {
					fix.Entry[i].Author.InnerXML = ""
				}
			}

			if err != nil {
				if test.UnmarshalError == "" {
					t.Errorf("unmarshal(%#v): %s", test.ExpectXML, err)
					return
				}
				if !strings.Contains(err.Error(), test.UnmarshalError) {
					t.Errorf("unmarshal(%#v): %s, want %q", test.ExpectXML, err, test.UnmarshalError)
				}
				return
			}
			if got, want := dest, test.Value; !reflect.DeepEqual(got, want) {
				t.Errorf("unmarshal(%q):\nhave %#v\nwant %#v", test.ExpectXML, got, want)
			}
		})
	}
}

func TestMarshalIndent(t *testing.T) {
	for i, test := range marshalIndentTests {
		data, err := MarshalIndent(test.Value, test.Prefix, test.Indent)
		if err != nil {
			t.Errorf("#%d: Error: %s", i, err)
			continue
		}
		if got, want := string(data), test.ExpectXML; got != want {
			t.Errorf("#%d: MarshalIndent:\nGot:%s\nWant:\n%s", i, got, want)
		}
	}
}

type limitedBytesWriter struct {
	w      io.Writer
	remain int // until writes fail
}

func (lw *limitedBytesWriter) Write(p []byte) (n int, err error) {
	if lw.remain <= 0 {
		println("error")
		return 0, errors.New("write limit hit")
	}
	if len(p) > lw.remain {
		p = p[:lw.remain]
		n, _ = lw.w.Write(p)
		lw.remain = 0
		return n, errors.New("write limit hit")
	}
	n, err = lw.w.Write(p)
	lw.remain -= n
	return n, err
}

func TestMarshalWriteErrors(t *testing.T) {
	var buf bytes.Buffer
	const writeCap = 1024
	w := &limitedBytesWriter{&buf, writeCap}
	enc := NewEncoder(w)
	var err error
	var i int
	const n = 4000
	for i = 1; i <= n; i++ {
		err = enc.Encode(&Passenger{
			Name:   []string{"Alice", "Bob"},
			Weight: 5,
		})
		if err != nil {
			break
		}
	}
	if err == nil {
		t.Error("expected an error")
	}
	if i == n {
		t.Errorf("expected to fail before the end")
	}
	if buf.Len() != writeCap {
		t.Errorf("buf.Len() = %d; want %d", buf.Len(), writeCap)
	}
}

func TestMarshalWriteIOErrors(t *testing.T) {
	enc := NewEncoder(errWriter{})

	expectErr := "unwritable"
	err := enc.Encode(&Passenger{})
	if err == nil || err.Error() != expectErr {
		t.Errorf("EscapeTest = [error] %v, want %v", err, expectErr)
	}
}

func TestMarshalFlush(t *testing.T) {
	var buf strings.Builder
	enc := NewEncoder(&buf)
	if err := enc.EncodeToken(CharData("hello world")); err != nil {
		t.Fatalf("enc.EncodeToken: %v", err)
	}
	if buf.Len() > 0 {
		t.Fatalf("enc.EncodeToken caused actual write: %q", buf.String())
	}
	if err := enc.Flush(); err != nil {
		t.Fatalf("enc.Flush: %v", err)
	}
	if buf.String() != "hello world" {
		t.Fatalf("after enc.Flush, buf.String() = %q, want %q", buf.String(), "hello world")
	}
}

func BenchmarkMarshal(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			Marshal(atomValue)
		}
	})
}

func BenchmarkUnmarshal(b *testing.B) {
	b.ReportAllocs()
	xml := []byte(atomXML)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			Unmarshal(xml, &Feed{})
		}
	})
}

// golang.org/issue/6556
func TestStructPointerMarshal(t *testing.T) {
	type A struct {
		XMLName string `xml:"a"`
		B       []any
	}
	type C struct {
		XMLName Name
		Value   string `xml:"value"`
	}

	a := new(A)
	a.B = append(a.B, &C{
		XMLName: Name{Local: "c"},
		Value:   "x",
	})

	b, err := Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if x := string(b); x != "<a><c><value>x</value></c></a>" {
		t.Fatal(x)
	}
	var v A
	err = Unmarshal(b, &v)
	if err != nil {
		t.Fatal(err)
	}
}

var encodeTokenTests = []struct {
	desc string
	toks []Token
	want string
	err  string
}{{
	desc: "start element with name space",
	toks: []Token{
		StartElement{Name{"space", "local"}, nil},
	},
	want: `<local xmlns="space">`,
}, {
	desc: "start element with no name",
	toks: []Token{
		StartElement{Name{"space", ""}, nil},
	},
	err: "xml: start tag with no name",
}, {
	desc: "end element with no name",
	toks: []Token{
		EndElement{Name{"space", ""}},
	},
	err: "xml: end tag with no name",
}, {
	desc: "char data",
	toks: []Token{
		CharData("foo"),
	},
	want: `foo`,
}, {
	desc: "char data with escaped chars",
	toks: []Token{
		CharData(" \t\n"),
	},
	want: " &#x9;\n",
}, {
	desc: "comment",
	toks: []Token{
		Comment("foo"),
	},
	want: `<!--foo-->`,
}, {
	desc: "comment with invalid content",
	toks: []Token{
		Comment("foo-->"),
	},
	err: "xml: EncodeToken of Comment containing --> marker",
}, {
	desc: "proc instruction",
	toks: []Token{
		ProcInst{"Target", []byte("Instruction")},
	},
	want: `<?Target Instruction?>`,
}, {
	desc: "proc instruction with empty target",
	toks: []Token{
		ProcInst{"", []byte("Instruction")},
	},
	err: "xml: EncodeToken of ProcInst with invalid Target",
}, {
	desc: "proc instruction with bad content",
	toks: []Token{
		ProcInst{"", []byte("Instruction?>")},
	},
	err: "xml: EncodeToken of ProcInst with invalid Target",
}, {
	desc: "directive",
	toks: []Token{
		Directive("foo"),
	},
	want: `<!foo>`,
}, {
	desc: "more complex directive",
	toks: []Token{
		Directive("DOCTYPE doc [ <!ELEMENT doc '>'> <!-- com>ment --> ]"),
	},
	want: `<!DOCTYPE doc [ <!ELEMENT doc '>'> <!-- com>ment --> ]>`,
}, {
	desc: "directive instruction with bad name",
	toks: []Token{
		Directive("foo>"),
	},
	err: "xml: EncodeToken of Directive containing wrong < or > markers",
}, {
	desc: "end tag without start tag",
	toks: []Token{
		EndElement{Name{"foo", "bar"}},
	},
	err: "xml: end tag </bar> without start tag",
}, {
	desc: "mismatching end tag local name",
	toks: []Token{
		StartElement{Name{"", "foo"}, nil},
		EndElement{Name{"", "bar"}},
	},
	err:  "xml: end tag </bar> does not match start tag <foo>",
	want: `<foo>`,
}, {
	desc: "mismatching end tag namespace",
	toks: []Token{
		StartElement{Name{"space", "foo"}, nil},
		EndElement{Name{"another", "foo"}},
	},
	err:  "xml: end tag </foo> in namespace another does not match start tag <foo> in namespace space",
	want: `<foo xmlns="space">`,
}, {
	desc: "start element with explicit namespace",
	toks: []Token{
		StartElement{Name{"space", "local"}, []Attr{
			{Name{"xmlns", "x"}, "space"},
			{Name{"space", "foo"}, "value"},
		}},
	},
	want: `<local xmlns="space" xmlns:_xmlns="xmlns" _xmlns:x="space" xmlns:space="space" space:foo="value">`,
}, {
	desc: "start element with explicit namespace and colliding prefix",
	toks: []Token{
		StartElement{Name{"space", "local"}, []Attr{
			{Name{"xmlns", "x"}, "space"},
			{Name{"space", "foo"}, "value"},
			{Name{"x", "bar"}, "other"},
		}},
	},
	want: `<local xmlns="space" xmlns:_xmlns="xmlns" _xmlns:x="space" xmlns:space="space" space:foo="value" xmlns:x="x" x:bar="other">`,
}, {
	desc: "start element using previously defined namespace",
	toks: []Token{
		StartElement{Name{"", "local"}, []Attr{
			{Name{"xmlns", "x"}, "space"},
		}},
		StartElement{Name{"space", "foo"}, []Attr{
			{Name{"space", "x"}, "y"},
		}},
	},
	want: `<local xmlns:_xmlns="xmlns" _xmlns:x="space"><foo xmlns="space" xmlns:space="space" space:x="y">`,
}, {
	desc: "nested name space with same prefix",
	toks: []Token{
		StartElement{Name{"", "foo"}, []Attr{
			{Name{"xmlns", "x"}, "space1"},
		}},
		StartElement{Name{"", "foo"}, []Attr{
			{Name{"xmlns", "x"}, "space2"},
		}},
		StartElement{Name{"", "foo"}, []Attr{
			{Name{"space1", "a"}, "space1 value"},
			{Name{"space2", "b"}, "space2 value"},
		}},
		EndElement{Name{"", "foo"}},
		EndElement{Name{"", "foo"}},
		StartElement{Name{"", "foo"}, []Attr{
			{Name{"space1", "a"}, "space1 value"},
			{Name{"space2", "b"}, "space2 value"},
		}},
	},
	want: `<foo xmlns:_xmlns="xmlns" _xmlns:x="space1"><foo _xmlns:x="space2"><foo xmlns:space1="space1" space1:a="space1 value" xmlns:space2="space2" space2:b="space2 value"></foo></foo><foo xmlns:space1="space1" space1:a="space1 value" xmlns:space2="space2" space2:b="space2 value">`,
}, {
	desc: "start element defining several prefixes for the same name space",
	toks: []Token{
		StartElement{Name{"space", "foo"}, []Attr{
			{Name{"xmlns", "a"}, "space"},
			{Name{"xmlns", "b"}, "space"},
			{Name{"space", "x"}, "value"},
		}},
	},
	want: `<foo xmlns="space" xmlns:_xmlns="xmlns" _xmlns:a="space" _xmlns:b="space" xmlns:space="space" space:x="value">`,
}, {
	desc: "nested element redefines name space",
	toks: []Token{
		StartElement{Name{"", "foo"}, []Attr{
			{Name{"xmlns", "x"}, "space"},
		}},
		StartElement{Name{"space", "foo"}, []Attr{
			{Name{"xmlns", "y"}, "space"},
			{Name{"space", "a"}, "value"},
		}},
	},
	want: `<foo xmlns:_xmlns="xmlns" _xmlns:x="space"><foo xmlns="space" _xmlns:y="space" xmlns:space="space" space:a="value">`,
}, {
	desc: "nested element creates alias for default name space",
	toks: []Token{
		StartElement{Name{"space", "foo"}, []Attr{
			{Name{"", "xmlns"}, "space"},
		}},
		StartElement{Name{"space", "foo"}, []Attr{
			{Name{"xmlns", "y"}, "space"},
			{Name{"space", "a"}, "value"},
		}},
	},
	want: `<foo xmlns="space" xmlns="space"><foo xmlns="space" xmlns:_xmlns="xmlns" _xmlns:y="space" xmlns:space="space" space:a="value">`,
}, {
	desc: "nested element defines default name space with existing prefix",
	toks: []Token{
		StartElement{Name{"", "foo"}, []Attr{
			{Name{"xmlns", "x"}, "space"},
		}},
		StartElement{Name{"space", "foo"}, []Attr{
			{Name{"", "xmlns"}, "space"},
			{Name{"space", "a"}, "value"},
		}},
	},
	want: `<foo xmlns:_xmlns="xmlns" _xmlns:x="space"><foo xmlns="space" xmlns="space" xmlns:space="space" space:a="value">`,
}, {
	desc: "nested element uses empty attribute name space when default ns defined",
	toks: []Token{
		StartElement{Name{"space", "foo"}, []Attr{
			{Name{"", "xmlns"}, "space"},
		}},
		StartElement{Name{"space", "foo"}, []Attr{
			{Name{"", "attr"}, "value"},
		}},
	},
	want: `<foo xmlns="space" xmlns="space"><foo xmlns="space" attr="value">`,
}, {
	desc: "redefine xmlns",
	toks: []Token{
		StartElement{Name{"", "foo"}, []Attr{
			{Name{"foo", "xmlns"}, "space"},
		}},
	},
	want: `<foo xmlns:foo="foo" foo:xmlns="space">`,
}, {
	desc: "xmlns with explicit name space #1",
	toks: []Token{
		StartElement{Name{"space", "foo"}, []Attr{
			{Name{"xml", "xmlns"}, "space"},
		}},
	},
	want: `<foo xmlns="space" xmlns:_xml="xml" _xml:xmlns="space">`,
}, {
	desc: "xmlns with explicit name space #2",
	toks: []Token{
		StartElement{Name{"space", "foo"}, []Attr{
			{Name{xmlURL, "xmlns"}, "space"},
		}},
	},
	want: `<foo xmlns="space" xml:xmlns="space">`,
}, {
	desc: "empty name space declaration is ignored",
	toks: []Token{
		StartElement{Name{"", "foo"}, []Attr{
			{Name{"xmlns", "foo"}, ""},
		}},
	},
	want: `<foo xmlns:_xmlns="xmlns" _xmlns:foo="">`,
}, {
	desc: "attribute with no name is ignored",
	toks: []Token{
		StartElement{Name{"", "foo"}, []Attr{
			{Name{"", ""}, "value"},
		}},
	},
	want: `<foo>`,
}, {
	desc: "namespace URL with non-valid name",
	toks: []Token{
		StartElement{Name{"/34", "foo"}, []Attr{
			{Name{"/34", "x"}, "value"},
		}},
	},
	want: `<foo xmlns="/34" xmlns:_="/34" _:x="value">`,
}, {
	desc: "nested element resets default namespace to empty",
	toks: []Token{
		StartElement{Name{"space", "foo"}, []Attr{
			{Name{"", "xmlns"}, "space"},
		}},
		StartElement{Name{"", "foo"}, []Attr{
			{Name{"", "xmlns"}, ""},
			{Name{"", "x"}, "value"},
			{Name{"space", "x"}, "value"},
		}},
	},
	want: `<foo xmlns="space" xmlns="space"><foo xmlns="" x="value" xmlns:space="space" space:x="value">`,
}, {
	desc: "nested element requires empty default name space",
	toks: []Token{
		StartElement{Name{"space", "foo"}, []Attr{
			{Name{"", "xmlns"}, "space"},
		}},
		StartElement{Name{"", "foo"}, nil},
	},
	want: `<foo xmlns="space" xmlns="space"><foo>`,
}, {
	desc: "attribute uses name space from xmlns",
	toks: []Token{
		StartElement{Name{"some/space", "foo"}, []Attr{
			{Name{"", "attr"}, "value"},
			{Name{"some/space", "other"}, "other value"},
		}},
	},
	want: `<foo xmlns="some/space" attr="value" xmlns:space="some/space" space:other="other value">`,
}, {
	desc: "default name space should not be used by attributes",
	toks: []Token{
		StartElement{Name{"space", "foo"}, []Attr{
			{Name{"", "xmlns"}, "space"},
			{Name{"xmlns", "bar"}, "space"},
			{Name{"space", "baz"}, "foo"},
		}},
		StartElement{Name{"space", "baz"}, nil},
		EndElement{Name{"space", "baz"}},
		EndElement{Name{"space", "foo"}},
	},
	want: `<foo xmlns="space" xmlns="space" xmlns:_xmlns="xmlns" _xmlns:bar="space" xmlns:space="space" space:baz="foo"><baz xmlns="space"></baz></foo>`,
}, {
	desc: "default name space not used by attributes, not explicitly defined",
	toks: []Token{
		StartElement{Name{"space", "foo"}, []Attr{
			{Name{"", "xmlns"}, "space"},
			{Name{"space", "baz"}, "foo"},
		}},
		StartElement{Name{"space", "baz"}, nil},
		EndElement{Name{"space", "baz"}},
		EndElement{Name{"space", "foo"}},
	},
	want: `<foo xmlns="space" xmlns="space" xmlns:space="space" space:baz="foo"><baz xmlns="space"></baz></foo>`,
}, {
	desc: "impossible xmlns declaration",
	toks: []Token{
		StartElement{Name{"", "foo"}, []Attr{
			{Name{"", "xmlns"}, "space"},
		}},
		StartElement{Name{"space", "bar"}, []Attr{
			{Name{"space", "attr"}, "value"},
		}},
	},
	want: `<foo xmlns="space"><bar xmlns="space" xmlns:space="space" space:attr="value">`,
}, {
	desc: "reserved namespace prefix -- all lower case",
	toks: []Token{
		StartElement{Name{"", "foo"}, []Attr{
			{Name{"http://www.w3.org/2001/xmlSchema-instance", "nil"}, "true"},
		}},
	},
	want: `<foo xmlns:_xmlSchema-instance="http://www.w3.org/2001/xmlSchema-instance" _xmlSchema-instance:nil="true">`,
}, {
	desc: "reserved namespace prefix -- all upper case",
	toks: []Token{
		StartElement{Name{"", "foo"}, []Attr{
			{Name{"http://www.w3.org/2001/XMLSchema-instance", "nil"}, "true"},
		}},
	},
	want: `<foo xmlns:_XMLSchema-instance="http://www.w3.org/2001/XMLSchema-instance" _XMLSchema-instance:nil="true">`,
}, {
	desc: "reserved namespace prefix -- all mixed case",
	toks: []Token{
		StartElement{Name{"", "foo"}, []Attr{
			{Name{"http://www.w3.org/2001/XmLSchema-instance", "nil"}, "true"},
		}},
	},
	want: `<foo xmlns:_XmLSchema-instance="http://www.w3.org/2001/XmLSchema-instance" _XmLSchema-instance:nil="true">`,
}}

func TestEncodeToken(t *testing.T) {
loop:
	for i, tt := range encodeTokenTests {
		var buf strings.Builder
		enc := NewEncoder(&buf)
		var err error
		for j, tok := range tt.toks {
			err = enc.EncodeToken(tok)
			if err != nil && j < len(tt.toks)-1 {
				t.Errorf("#%d %s token #%d: %v", i, tt.desc, j, err)
				continue loop
			}
		}
		errorf := func(f string, a ...any) {
			t.Errorf("#%d %s token #%d:%s", i, tt.desc, len(tt.toks)-1, fmt.Sprintf(f, a...))
		}
		switch {
		case tt.err != "" && err == nil:
			errorf(" expected error; got none")
			continue
		case tt.err == "" && err != nil:
			errorf(" got error: %v", err)
			continue
		case tt.err != "" && err != nil && tt.err != err.Error():
			errorf(" error mismatch; got %v, want %v", err, tt.err)
			continue
		}
		if err := enc.Flush(); err != nil {
			errorf(" %v", err)
			continue
		}
		if got := buf.String(); got != tt.want {
			errorf("\ngot  %v\nwant %v", got, tt.want)
			continue
		}
	}
}

func TestProcInstEncodeToken(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)

	if err := enc.EncodeToken(ProcInst{"xml", []byte("Instruction")}); err != nil {
		t.Fatalf("enc.EncodeToken: expected to be able to encode xml target ProcInst as first token, %s", err)
	}

	if err := enc.EncodeToken(ProcInst{"Target", []byte("Instruction")}); err != nil {
		t.Fatalf("enc.EncodeToken: expected to be able to add non-xml target ProcInst")
	}

	if err := enc.EncodeToken(ProcInst{"xml", []byte("Instruction")}); err == nil {
		t.Fatalf("enc.EncodeToken: expected to not be allowed to encode xml target ProcInst when not first token")
	}
}

func TestDecodeEncode(t *testing.T) {
	var in, out bytes.Buffer
	in.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<?Target Instruction?>
<root>
</root>
`)
	dec := NewDecoder(&in)
	enc := NewEncoder(&out)
	for tok, err := dec.Token(); err == nil; tok, err = dec.Token() {
		err = enc.EncodeToken(tok)
		if err != nil {
			t.Fatalf("enc.EncodeToken: Unable to encode token (%#v), %v", tok, err)
		}
	}
}

// Issue 9796. Used to fail with GORACE="halt_on_error=1" -race.
func TestRace9796(t *testing.T) {
	type A struct{}
	type B struct {
		C []A `xml:"X>Y"`
	}
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			Marshal(B{[]A{{}}})
			wg.Done()
		}()
	}
	wg.Wait()
}

func TestIsValidDirective(t *testing.T) {
	testOK := []string{
		"<>",
		"< < > >",
		"<!DOCTYPE '<' '>' '>' <!--nothing-->>",
		"<!DOCTYPE doc [ <!ELEMENT doc ANY> <!ELEMENT doc ANY> ]>",
		"<!DOCTYPE doc [ <!ELEMENT doc \"ANY> '<' <!E\" LEMENT '>' doc ANY> ]>",
		"<!DOCTYPE doc <!-- just>>>> a < comment --> [ <!ITEM anything> ] >",
	}
	testKO := []string{
		"<",
		">",
		"<!--",
		"-->",
		"< > > < < >",
		"<!dummy <!-- > -->",
		"<!DOCTYPE doc '>",
		"<!DOCTYPE doc '>'",
		"<!DOCTYPE doc <!--comment>",
	}
	for _, s := range testOK {
		if !isValidDirective(Directive(s)) {
			t.Errorf("Directive %q is expected to be valid", s)
		}
	}
	for _, s := range testKO {
		if isValidDirective(Directive(s)) {
			t.Errorf("Directive %q is expected to be invalid", s)
		}
	}
}

// Issue 11719. EncodeToken used to silently eat tokens with an invalid type.
func TestSimpleUseOfEncodeToken(t *testing.T) {
	var buf strings.Builder
	enc := NewEncoder(&buf)
	if err := enc.EncodeToken(&StartElement{Name: Name{"", "object1"}}); err == nil {
		t.Errorf("enc.EncodeToken: pointer type should be rejected")
	}
	if err := enc.EncodeToken(&EndElement{Name: Name{"", "object1"}}); err == nil {
		t.Errorf("enc.EncodeToken: pointer type should be rejected")
	}
	if err := enc.EncodeToken(StartElement{Name: Name{"", "object2"}}); err != nil {
		t.Errorf("enc.EncodeToken: StartElement %s", err)
	}
	if err := enc.EncodeToken(EndElement{Name: Name{"", "object2"}}); err != nil {
		t.Errorf("enc.EncodeToken: EndElement %s", err)
	}
	if err := enc.EncodeToken(Universe{}); err == nil {
		t.Errorf("enc.EncodeToken: invalid type not caught")
	}
	if err := enc.Flush(); err != nil {
		t.Errorf("enc.Flush: %s", err)
	}
	if buf.Len() == 0 {
		t.Errorf("enc.EncodeToken: empty buffer")
	}
	want := "<object2></object2>"
	if buf.String() != want {
		t.Errorf("enc.EncodeToken: expected %q; got %q", want, buf.String())
	}
}

// Issue 16158. Decoder.unmarshalAttr ignores the return value of copyValue.
func TestIssue16158(t *testing.T) {
	const data = `<foo b="HELLOWORLD"></foo>`
	err := Unmarshal([]byte(data), &struct {
		B byte `xml:"b,attr,omitempty"`
	}{})
	if err == nil {
		t.Errorf("Unmarshal: expected error, got nil")
	}
}

// Issue 20953. Crash on invalid XMLName attribute.

type InvalidXMLName struct {
	XMLName Name `xml:"error"`
	Type    struct {
		XMLName Name `xml:"type,attr"`
	}
}

func TestInvalidXMLName(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	if err := enc.Encode(InvalidXMLName{}); err == nil {
		t.Error("unexpected success")
	} else if want := "invalid tag"; !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not contain %q", err, want)
	}
}

// Issue 50164. Crash on zero value XML attribute.
type LayerOne struct {
	XMLName Name `xml:"l1"`

	Value     *float64 `xml:"value,omitempty"`
	*LayerTwo `xml:",omitempty"`
}

type LayerTwo struct {
	ValueTwo *int `xml:"value_two,attr,om
```