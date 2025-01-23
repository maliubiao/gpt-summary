Response:
Let's break down the thought process to analyze the Go XML test file.

1. **Identify the Core Purpose:** The file name `read_test.go` and the import of the `testing` package immediately suggest this is a test file for the `encoding/xml` package, specifically focused on the *reading* or *unmarshaling* functionality.

2. **Scan for Test Functions:**  Look for functions starting with `Test`. This provides a list of specific test cases. We see:
    * `TestUnmarshalFeed`
    * `TestUnmarshalPaths`
    * `TestUnmarshalBadPaths`
    * `TestUnmarshalWithoutNameType`
    * `TestUnmarshalAttr`
    * `TestUnmarshalNS`
    * `TestMarshalNS` (Aha!  A slight detour - also tests marshaling related to namespaces)
    * `TestUnmarshalNSAttr`
    * `TestMarshalNSAttr` (Another marshaling test related to attributes and namespaces)
    * `TestUnmarshaler`
    * `TestUnmarshalIntoInterface`
    * `TestMalformedComment`
    * `TestInvalidInnerXMLType`
    * `TestUnmarshalEmptyValues`
    * `TestUnmarshalWhitespaceValues`
    * `TestUnmarshalWhitespaceAttrs`
    * `TestUnmarshalIntoNil`
    * `TestCVE202228131`
    * `TestCVE202230633`

3. **Analyze Each Test Function:**  For each test function, understand its goal:

    * **`TestUnmarshalFeed`**:  Clearly tests unmarshaling a standard Atom feed. The presence of `atomFeedString` and `atomFeed` variables confirms this. It checks if unmarshaling the string produces the expected data structure.

    * **`TestUnmarshalPaths`**: This test uses the `xml:"path>to>element"` syntax for unmarshaling. The `pathTestString` and `pathTests` array are key here. It verifies that elements can be targeted using paths.

    * **`TestUnmarshalBadPaths`**:  This is the negative counterpart to `TestUnmarshalPaths`. It verifies that invalid path specifications during unmarshaling result in the expected `TagPathError`.

    * **`TestUnmarshalWithoutNameType`**: Checks if unmarshaling works correctly when the struct field doesn't explicitly specify an XML name, but relies on the default. The `TestThree` struct is the focus.

    * **`TestUnmarshalAttr`**:  Focuses on unmarshaling XML attributes into struct fields. It covers different field types like `int`, `*int`, and `*string`.

    * **`TestUnmarshalNS`**: Tests unmarshaling XML with namespaces. The `Tables` struct and the `tables` array of test cases illustrate how namespaces are handled during unmarshaling of elements. The use of `NewDecoder` and `DefaultSpace` is noteworthy.

    * **`TestMarshalNS`**:  Tests the *marshaling* of structs with namespace information. This is a slight departure but related to namespace handling.

    * **`TestUnmarshalNSAttr`**: Tests unmarshaling XML attributes that have namespace prefixes.

    * **`TestMarshalNSAttr`**: Tests the *marshaling* of attributes with namespace information.

    * **`TestUnmarshaler`**: Examines the use of the `UnmarshalXML` interface for custom unmarshaling logic, both for element content and attributes. The `MyCharData` and `MyAttr` types are crucial.

    * **`TestUnmarshalIntoInterface`**:  Verifies that unmarshaling XML into an interface field works correctly, preserving the underlying concrete type.

    * **`TestMalformedComment`**:  Tests the parser's ability to reject invalid XML comments.

    * **`TestInvalidInnerXMLType`**: Checks the behavior when `",innerxml"` is used on a field type that cannot hold arbitrary XML content (like `[]string`).

    * **`TestUnmarshalEmptyValues`**:  Focuses on how empty XML elements are unmarshaled into various Go types (int, string, bool, slices, pointers). It tests both zero-valued and pre-populated destination structs.

    * **`TestUnmarshalWhitespaceValues`**: Verifies that leading and trailing whitespace around XML element values are trimmed during unmarshaling for various numeric and boolean types.

    * **`TestUnmarshalWhitespaceAttrs`**: Similar to the previous test, but for XML attributes.

    * **`TestUnmarshalIntoNil`**: Checks the error handling when attempting to unmarshal into a nil pointer.

    * **`TestCVE202228131`**: This test name strongly suggests a test for a security vulnerability related to excessive nesting depth. It checks if unmarshaling deeply nested XML fails with the expected error (`errUnmarshalDepth`).

    * **`TestCVE202230633`**: Another security-related test, likely checking for vulnerabilities related to large input sizes that could cause excessive memory allocation or panics.

4. **Group Functionality:**  Based on the analysis of individual tests, categorize the functionalities being tested:
    * Basic Unmarshaling
    * Unmarshaling with Path Selectors
    * Handling Invalid Paths
    * Unmarshaling without Explicit Name Tags
    * Unmarshaling Attributes
    * Unmarshaling with Namespaces (Elements and Attributes)
    * Custom Unmarshaling (`UnmarshalXML` interface)
    * Unmarshaling into Interfaces
    * Handling XML Comments (Valid and Invalid)
    * Handling `",innerxml"`
    * Unmarshaling Empty Elements
    * Handling Whitespace in Element Values and Attributes
    * Error Handling (Unmarshaling into Nil)
    * Security (Depth Limit, Large Input Handling)

5. **Code Examples and Assumptions:** When providing Go code examples, base them on the structures and data used in the test file itself. Make explicit assumptions about the input XML and the expected output Go structs.

6. **Command Line Arguments:** Since this is a test file, focus on how *tests* are run (using `go test`). Mention relevant flags like `-v` for verbose output.

7. **Common Mistakes:** Think about typical errors developers might make when working with XML unmarshaling, drawing inspiration from the test cases themselves (e.g., incorrect struct tags, namespace issues, expecting unmarshaling into nil to work).

8. **Structure the Answer:** Organize the information logically, starting with a summary of the file's purpose, then detailing each functionality with code examples, assumptions, and potential pitfalls. Use clear headings and formatting for readability.
这个`go/src/encoding/xml/read_test.go` 文件是 Go 语言 `encoding/xml` 标准库中负责 XML **反序列化 (unmarshaling)** 功能的测试文件。它包含了一系列测试用例，用于验证 `encoding/xml` 包在将 XML 数据解析并填充到 Go 结构体中的各种场景下的正确性。

**主要功能列表:**

1. **基本反序列化测试:** 测试将简单的 XML 结构反序列化为对应的 Go 结构体。
2. **带有 XML 路径的反序列化:** 测试使用 XML 路径表达式 (`xml:"path>to>element"`) 来定位和反序列化嵌套的 XML 元素。
3. **处理错误的 XML 路径:** 测试当提供的 XML 路径无效时，反序列化是否能正确报告错误。
4. **不指定 XML 标签名称的反序列化:** 测试当 Go 结构体字段没有明确指定 XML 标签名称时，反序列化是否能根据字段名进行匹配。
5. **反序列化 XML 属性:** 测试将 XML 元素的属性值反序列化到 Go 结构体的字段中。
6. **反序列化带命名空间的 XML:** 测试处理带有 XML 命名空间的元素和属性的反序列化。
7. **自定义反序列化:** 测试使用 `UnmarshalXML` 接口来实现自定义的反序列化逻辑。
8. **反序列化到接口:** 测试将 XML 数据反序列化到接口类型的字段中。
9. **处理错误的 XML 注释:** 测试反序列化器是否能正确拒绝格式错误的 XML 注释。
10. **处理错误的 `innerxml` 类型:** 测试当 `",innerxml"` 标签应用于无法存储 XML 内容的字段类型时，反序列化器的行为。
11. **反序列化空值:** 测试如何将空的 XML 元素反序列化为 Go 的各种基本类型（如 `int`, `string`, `bool` 等）及其指针类型和切片类型。
12. **处理带有空白字符的值:** 测试反序列化器如何处理 XML 元素和属性值周围的空白字符。
13. **尝试反序列化到 `nil` 指针:** 测试尝试将 XML 反序列化到 `nil` 指针时是否会产生错误。
14. **防止 XML 炸弹 (CVE-2022-28131):** 测试反序列化器是否能防止由于过深的 XML 嵌套导致的拒绝服务攻击。
15. **防止大量重复标签导致的内存消耗 (CVE-2022-30633):** 测试反序列化器是否能防止由于大量重复标签导致的过高内存消耗。

**Go 语言功能实现推理与代码示例:**

这个测试文件主要测试 `encoding/xml` 包中的 `Unmarshal` 函数和 `NewDecoder` 类型及其 `Decode` 方法。这两个功能用于将 XML 数据反序列化为 Go 的结构体。

**1. 基本反序列化:**

```go
package main

import (
	"encoding/xml"
	"fmt"
)

type Person struct {
	XMLName xml.Name `xml:"person"` // 指定根元素名称
	Name    string   `xml:"name"`
	Age     int      `xml:"age"`
}

func main() {
	xmlData := []byte(`
		<person>
			<name>Alice</name>
			<age>30</age>
		</person>
	`)

	var p Person
	err := xml.Unmarshal(xmlData, &p)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("%+v\n", p) // 输出: {XMLName:{Space: Local:} Name:Alice Age:30}
}
```

**假设输入:** 上面的 `xmlData` 变量。

**输出:**  `{XMLName:{Space: Local:} Name:Alice Age:30}`

**2. 带有 XML 路径的反序列化:**

```go
package main

import (
	"encoding/xml"
	"fmt"
)

type Result struct {
	Before string `xml:"Info>Metadata>Before"`
	Value  string `xml:"Data>Value"`
	After  string `xml:"Info>Metadata>After"`
}

func main() {
	xmlData := []byte(`
		<Root>
			<Info>
				<Metadata>
					<Before>Start</Before>
					<After>End</After>
				</Metadata>
			</Info>
			<Data>
				<Value>Important Data</Value>
			</Data>
		</Root>
	`)

	var r Result
	err := xml.Unmarshal(xmlData, &r)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("%+v\n", r) // 输出: {Before:Start Value:Important Data After:End}
}
```

**假设输入:** 上面的 `xmlData` 变量。

**输出:** `{Before:Start Value:Important Data After:End}`

**3. 反序列化 XML 属性:**

```go
package main

import (
	"encoding/xml"
	"fmt"
)

type Config struct {
	XMLName xml.Name `xml:"config"`
	Version string   `xml:"version,attr"`
	Timeout int      `xml:"timeout,attr"`
}

func main() {
	xmlData := []byte(`
		<config version="1.0" timeout="60">
		</config>
	`)

	var cfg Config
	err := xml.Unmarshal(xmlData, &cfg)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("%+v\n", cfg) // 输出: {XMLName:{Space: Local:} Version:1.0 Timeout:60}
}
```

**假设输入:** 上面的 `xmlData` 变量。

**输出:** `{XMLName:{Space: Local:} Version:1.0 Timeout:60}`

**命令行参数:**

这个测试文件本身并不直接处理命令行参数。 它是通过 `go test` 命令来运行的。 `go test` 命令有一些常用的参数，例如：

* `-v`:  显示更详细的测试输出，包括每个测试用例的名称和结果。
* `-run <正则表达式>`:  只运行名称匹配指定正则表达式的测试用例。例如，`go test -run UnmarshalFeed` 只会运行 `TestUnmarshalFeed` 这个测试函数。
* `-bench <正则表达式>`: 运行性能测试。这个文件里没有性能测试，所以这个参数不适用。
* `-coverprofile <文件名>`:  生成代码覆盖率报告。

**使用者易犯错的点:**

1. **结构体标签不正确:**  `encoding/xml` 依赖于结构体字段的标签 (`xml:"..."`) 来进行 XML 元素和字段的映射。如果标签写错，反序列化会失败或者将数据填充到错误的字段。

   ```go
   type WrongPerson struct {
       Name string `xml:"wrongName"` // XML 中是 <name>
       Age  int    `xml:"Age"`       // XML 中是 <age> (小写)
   }

   xmlData := []byte(`<person><name>Alice</name><age>30</age></person>`)
   var wp WrongPerson
   xml.Unmarshal(xmlData, &wp)
   fmt.Printf("%+v\n", wp) // 输出: {Name: Age:0} (字段没有正确填充)
   ```

2. **命名空间处理不当:**  当处理带有命名空间的 XML 时，需要在结构体标签中明确指定命名空间 URI。如果忽略或者指定错误，反序列化可能会失败或者无法找到对应的元素。

   ```go
   type Book struct {
       Title string `xml:"http://example.org/ns book-title"` // 正确指定命名空间
   }

   xmlData := []byte(`<bk:book-title xmlns:bk="http://example.org/ns">The Great Book</bk:book-title>`)
   var b Book
   xml.Unmarshal(xmlData, &b)
   fmt.Printf("%+v\n", b) // 输出: {Title:The Great Book}

   type WrongBook struct {
       Title string `xml:"book-title"` // 缺少命名空间
   }
   var wb WrongBook
   xml.Unmarshal(xmlData, &wb)
   fmt.Printf("%+v\n", wb) // 输出: {Title:} (没有找到对应的元素)
   ```

3. **大小写敏感:** XML 标签名是大小写敏感的。确保结构体标签中的名称与 XML 中的元素名称大小写一致。

4. **期望反序列化到 `nil` 指针:**  如测试用例所示，尝试将 XML 反序列化到 `nil` 指针会导致错误。必须提供一个指向有效内存的指针。

总而言之，`go/src/encoding/xml/read_test.go` 是 `encoding/xml` 包中至关重要的测试文件，它覆盖了 XML 反序列化的各种核心功能和边界情况，确保了该功能的稳定性和正确性。 理解这个测试文件的内容可以帮助开发者更好地理解和使用 Go 语言的 XML 处理能力，并避免一些常见的错误。

### 提示词
```
这是路径为go/src/encoding/xml/read_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xml

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Stripped down Atom feed data structures.

func TestUnmarshalFeed(t *testing.T) {
	var f Feed
	if err := Unmarshal([]byte(atomFeedString), &f); err != nil {
		t.Fatalf("Unmarshal: %s", err)
	}
	if !reflect.DeepEqual(f, atomFeed) {
		t.Fatalf("have %#v\nwant %#v", f, atomFeed)
	}
}

// hget http://codereview.appspot.com/rss/mine/rsc
const atomFeedString = `
<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom" xml:lang="en-us" updated="2009-10-04T01:35:58+00:00"><title>Code Review - My issues</title><link href="http://codereview.appspot.com/" rel="alternate"></link><link href="http://codereview.appspot.com/rss/mine/rsc" rel="self"></link><id>http://codereview.appspot.com/</id><author><name>rietveld&lt;&gt;</name></author><entry><title>rietveld: an attempt at pubsubhubbub
</title><link href="http://codereview.appspot.com/126085" rel="alternate"></link><updated>2009-10-04T01:35:58+00:00</updated><author><name>email-address-removed</name></author><id>urn:md5:134d9179c41f806be79b3a5f7877d19a</id><summary type="html">
  An attempt at adding pubsubhubbub support to Rietveld.
http://code.google.com/p/pubsubhubbub
http://code.google.com/p/rietveld/issues/detail?id=155

The server side of the protocol is trivial:
  1. add a &amp;lt;link rel=&amp;quot;hub&amp;quot; href=&amp;quot;hub-server&amp;quot;&amp;gt; tag to all
     feeds that will be pubsubhubbubbed.
  2. every time one of those feeds changes, tell the hub
     with a simple POST request.

I have tested this by adding debug prints to a local hub
server and checking that the server got the right publish
requests.

I can&amp;#39;t quite get the server to work, but I think the bug
is not in my code.  I think that the server expects to be
able to grab the feed and see the feed&amp;#39;s actual URL in
the link rel=&amp;quot;self&amp;quot;, but the default value for that drops
the :port from the URL, and I cannot for the life of me
figure out how to get the Atom generator deep inside
django not to do that, or even where it is doing that,
or even what code is running to generate the Atom feed.
(I thought I knew but I added some assert False statements
and it kept running!)

Ignoring that particular problem, I would appreciate
feedback on the right way to get the two values at
the top of feeds.py marked NOTE(rsc).


</summary></entry><entry><title>rietveld: correct tab handling
</title><link href="http://codereview.appspot.com/124106" rel="alternate"></link><updated>2009-10-03T23:02:17+00:00</updated><author><name>email-address-removed</name></author><id>urn:md5:0a2a4f19bb815101f0ba2904aed7c35a</id><summary type="html">
  This fixes the buggy tab rendering that can be seen at
http://codereview.appspot.com/116075/diff/1/2

The fundamental problem was that the tab code was
not being told what column the text began in, so it
didn&amp;#39;t know where to put the tab stops.  Another problem
was that some of the code assumed that string byte
offsets were the same as column offsets, which is only
true if there are no tabs.

In the process of fixing this, I cleaned up the arguments
to Fold and ExpandTabs and renamed them Break and
_ExpandTabs so that I could be sure that I found all the
call sites.  I also wanted to verify that ExpandTabs was
not being used from outside intra_region_diff.py.


</summary></entry></feed> 	   `

type Feed struct {
	XMLName Name      `xml:"http://www.w3.org/2005/Atom feed"`
	Title   string    `xml:"title"`
	ID      string    `xml:"id"`
	Link    []Link    `xml:"link"`
	Updated time.Time `xml:"updated,attr"`
	Author  Person    `xml:"author"`
	Entry   []Entry   `xml:"entry"`
}

type Entry struct {
	Title   string    `xml:"title"`
	ID      string    `xml:"id"`
	Link    []Link    `xml:"link"`
	Updated time.Time `xml:"updated"`
	Author  Person    `xml:"author"`
	Summary Text      `xml:"summary"`
}

type Link struct {
	Rel  string `xml:"rel,attr,omitempty"`
	Href string `xml:"href,attr"`
}

type Person struct {
	Name     string `xml:"name"`
	URI      string `xml:"uri"`
	Email    string `xml:"email"`
	InnerXML string `xml:",innerxml"`
}

type Text struct {
	Type string `xml:"type,attr,omitempty"`
	Body string `xml:",chardata"`
}

var atomFeed = Feed{
	XMLName: Name{"http://www.w3.org/2005/Atom", "feed"},
	Title:   "Code Review - My issues",
	Link: []Link{
		{Rel: "alternate", Href: "http://codereview.appspot.com/"},
		{Rel: "self", Href: "http://codereview.appspot.com/rss/mine/rsc"},
	},
	ID:      "http://codereview.appspot.com/",
	Updated: ParseTime("2009-10-04T01:35:58+00:00"),
	Author: Person{
		Name:     "rietveld<>",
		InnerXML: "<name>rietveld&lt;&gt;</name>",
	},
	Entry: []Entry{
		{
			Title: "rietveld: an attempt at pubsubhubbub\n",
			Link: []Link{
				{Rel: "alternate", Href: "http://codereview.appspot.com/126085"},
			},
			Updated: ParseTime("2009-10-04T01:35:58+00:00"),
			Author: Person{
				Name:     "email-address-removed",
				InnerXML: "<name>email-address-removed</name>",
			},
			ID: "urn:md5:134d9179c41f806be79b3a5f7877d19a",
			Summary: Text{
				Type: "html",
				Body: `
  An attempt at adding pubsubhubbub support to Rietveld.
http://code.google.com/p/pubsubhubbub
http://code.google.com/p/rietveld/issues/detail?id=155

The server side of the protocol is trivial:
  1. add a &lt;link rel=&quot;hub&quot; href=&quot;hub-server&quot;&gt; tag to all
     feeds that will be pubsubhubbubbed.
  2. every time one of those feeds changes, tell the hub
     with a simple POST request.

I have tested this by adding debug prints to a local hub
server and checking that the server got the right publish
requests.

I can&#39;t quite get the server to work, but I think the bug
is not in my code.  I think that the server expects to be
able to grab the feed and see the feed&#39;s actual URL in
the link rel=&quot;self&quot;, but the default value for that drops
the :port from the URL, and I cannot for the life of me
figure out how to get the Atom generator deep inside
django not to do that, or even where it is doing that,
or even what code is running to generate the Atom feed.
(I thought I knew but I added some assert False statements
and it kept running!)

Ignoring that particular problem, I would appreciate
feedback on the right way to get the two values at
the top of feeds.py marked NOTE(rsc).


`,
			},
		},
		{
			Title: "rietveld: correct tab handling\n",
			Link: []Link{
				{Rel: "alternate", Href: "http://codereview.appspot.com/124106"},
			},
			Updated: ParseTime("2009-10-03T23:02:17+00:00"),
			Author: Person{
				Name:     "email-address-removed",
				InnerXML: "<name>email-address-removed</name>",
			},
			ID: "urn:md5:0a2a4f19bb815101f0ba2904aed7c35a",
			Summary: Text{
				Type: "html",
				Body: `
  This fixes the buggy tab rendering that can be seen at
http://codereview.appspot.com/116075/diff/1/2

The fundamental problem was that the tab code was
not being told what column the text began in, so it
didn&#39;t know where to put the tab stops.  Another problem
was that some of the code assumed that string byte
offsets were the same as column offsets, which is only
true if there are no tabs.

In the process of fixing this, I cleaned up the arguments
to Fold and ExpandTabs and renamed them Break and
_ExpandTabs so that I could be sure that I found all the
call sites.  I also wanted to verify that ExpandTabs was
not being used from outside intra_region_diff.py.


`,
			},
		},
	},
}

const pathTestString = `
<Result>
    <Before>1</Before>
    <Items>
        <Item1>
            <Value>A</Value>
        </Item1>
        <Item2>
            <Value>B</Value>
        </Item2>
        <Item1>
            <Value>C</Value>
            <Value>D</Value>
        </Item1>
        <_>
            <Value>E</Value>
        </_>
    </Items>
    <After>2</After>
</Result>
`

type PathTestItem struct {
	Value string
}

type PathTestA struct {
	Items         []PathTestItem `xml:">Item1"`
	Before, After string
}

type PathTestB struct {
	Other         []PathTestItem `xml:"Items>Item1"`
	Before, After string
}

type PathTestC struct {
	Values1       []string `xml:"Items>Item1>Value"`
	Values2       []string `xml:"Items>Item2>Value"`
	Before, After string
}

type PathTestSet struct {
	Item1 []PathTestItem
}

type PathTestD struct {
	Other         PathTestSet `xml:"Items"`
	Before, After string
}

type PathTestE struct {
	Underline     string `xml:"Items>_>Value"`
	Before, After string
}

var pathTests = []any{
	&PathTestA{Items: []PathTestItem{{"A"}, {"D"}}, Before: "1", After: "2"},
	&PathTestB{Other: []PathTestItem{{"A"}, {"D"}}, Before: "1", After: "2"},
	&PathTestC{Values1: []string{"A", "C", "D"}, Values2: []string{"B"}, Before: "1", After: "2"},
	&PathTestD{Other: PathTestSet{Item1: []PathTestItem{{"A"}, {"D"}}}, Before: "1", After: "2"},
	&PathTestE{Underline: "E", Before: "1", After: "2"},
}

func TestUnmarshalPaths(t *testing.T) {
	for _, pt := range pathTests {
		v := reflect.New(reflect.TypeOf(pt).Elem()).Interface()
		if err := Unmarshal([]byte(pathTestString), v); err != nil {
			t.Fatalf("Unmarshal: %s", err)
		}
		if !reflect.DeepEqual(v, pt) {
			t.Fatalf("have %#v\nwant %#v", v, pt)
		}
	}
}

type BadPathTestA struct {
	First  string `xml:"items>item1"`
	Other  string `xml:"items>item2"`
	Second string `xml:"items"`
}

type BadPathTestB struct {
	Other  string `xml:"items>item2>value"`
	First  string `xml:"items>item1"`
	Second string `xml:"items>item1>value"`
}

type BadPathTestC struct {
	First  string
	Second string `xml:"First"`
}

type BadPathTestD struct {
	BadPathEmbeddedA
	BadPathEmbeddedB
}

type BadPathEmbeddedA struct {
	First string
}

type BadPathEmbeddedB struct {
	Second string `xml:"First"`
}

var badPathTests = []struct {
	v, e any
}{
	{&BadPathTestA{}, &TagPathError{reflect.TypeFor[BadPathTestA](), "First", "items>item1", "Second", "items"}},
	{&BadPathTestB{}, &TagPathError{reflect.TypeFor[BadPathTestB](), "First", "items>item1", "Second", "items>item1>value"}},
	{&BadPathTestC{}, &TagPathError{reflect.TypeFor[BadPathTestC](), "First", "", "Second", "First"}},
	{&BadPathTestD{}, &TagPathError{reflect.TypeFor[BadPathTestD](), "First", "", "Second", "First"}},
}

func TestUnmarshalBadPaths(t *testing.T) {
	for _, tt := range badPathTests {
		err := Unmarshal([]byte(pathTestString), tt.v)
		if !reflect.DeepEqual(err, tt.e) {
			t.Fatalf("Unmarshal with %#v didn't fail properly:\nhave %#v,\nwant %#v", tt.v, err, tt.e)
		}
	}
}

const OK = "OK"
const withoutNameTypeData = `
<?xml version="1.0" charset="utf-8"?>
<Test3 Attr="OK" />`

type TestThree struct {
	XMLName Name   `xml:"Test3"`
	Attr    string `xml:",attr"`
}

func TestUnmarshalWithoutNameType(t *testing.T) {
	var x TestThree
	if err := Unmarshal([]byte(withoutNameTypeData), &x); err != nil {
		t.Fatalf("Unmarshal: %s", err)
	}
	if x.Attr != OK {
		t.Fatalf("have %v\nwant %v", x.Attr, OK)
	}
}

func TestUnmarshalAttr(t *testing.T) {
	type ParamVal struct {
		Int int `xml:"int,attr"`
	}

	type ParamPtr struct {
		Int *int `xml:"int,attr"`
	}

	type ParamStringPtr struct {
		Int *string `xml:"int,attr"`
	}

	x := []byte(`<Param int="1" />`)

	p1 := &ParamPtr{}
	if err := Unmarshal(x, p1); err != nil {
		t.Fatalf("Unmarshal: %s", err)
	}
	if p1.Int == nil {
		t.Fatalf("Unmarshal failed in to *int field")
	} else if *p1.Int != 1 {
		t.Fatalf("Unmarshal with %s failed:\nhave %#v,\n want %#v", x, p1.Int, 1)
	}

	p2 := &ParamVal{}
	if err := Unmarshal(x, p2); err != nil {
		t.Fatalf("Unmarshal: %s", err)
	}
	if p2.Int != 1 {
		t.Fatalf("Unmarshal with %s failed:\nhave %#v,\n want %#v", x, p2.Int, 1)
	}

	p3 := &ParamStringPtr{}
	if err := Unmarshal(x, p3); err != nil {
		t.Fatalf("Unmarshal: %s", err)
	}
	if p3.Int == nil {
		t.Fatalf("Unmarshal failed in to *string field")
	} else if *p3.Int != "1" {
		t.Fatalf("Unmarshal with %s failed:\nhave %#v,\n want %#v", x, p3.Int, 1)
	}
}

type Tables struct {
	HTable string `xml:"http://www.w3.org/TR/html4/ table"`
	FTable string `xml:"http://www.w3schools.com/furniture table"`
}

var tables = []struct {
	xml string
	tab Tables
	ns  string
}{
	{
		xml: `<Tables>` +
			`<table xmlns="http://www.w3.org/TR/html4/">hello</table>` +
			`<table xmlns="http://www.w3schools.com/furniture">world</table>` +
			`</Tables>`,
		tab: Tables{"hello", "world"},
	},
	{
		xml: `<Tables>` +
			`<table xmlns="http://www.w3schools.com/furniture">world</table>` +
			`<table xmlns="http://www.w3.org/TR/html4/">hello</table>` +
			`</Tables>`,
		tab: Tables{"hello", "world"},
	},
	{
		xml: `<Tables xmlns:f="http://www.w3schools.com/furniture" xmlns:h="http://www.w3.org/TR/html4/">` +
			`<f:table>world</f:table>` +
			`<h:table>hello</h:table>` +
			`</Tables>`,
		tab: Tables{"hello", "world"},
	},
	{
		xml: `<Tables>` +
			`<table>bogus</table>` +
			`</Tables>`,
		tab: Tables{},
	},
	{
		xml: `<Tables>` +
			`<table>only</table>` +
			`</Tables>`,
		tab: Tables{HTable: "only"},
		ns:  "http://www.w3.org/TR/html4/",
	},
	{
		xml: `<Tables>` +
			`<table>only</table>` +
			`</Tables>`,
		tab: Tables{FTable: "only"},
		ns:  "http://www.w3schools.com/furniture",
	},
	{
		xml: `<Tables>` +
			`<table>only</table>` +
			`</Tables>`,
		tab: Tables{},
		ns:  "something else entirely",
	},
}

func TestUnmarshalNS(t *testing.T) {
	for i, tt := range tables {
		var dst Tables
		var err error
		if tt.ns != "" {
			d := NewDecoder(strings.NewReader(tt.xml))
			d.DefaultSpace = tt.ns
			err = d.Decode(&dst)
		} else {
			err = Unmarshal([]byte(tt.xml), &dst)
		}
		if err != nil {
			t.Errorf("#%d: Unmarshal: %v", i, err)
			continue
		}
		want := tt.tab
		if dst != want {
			t.Errorf("#%d: dst=%+v, want %+v", i, dst, want)
		}
	}
}

func TestMarshalNS(t *testing.T) {
	dst := Tables{"hello", "world"}
	data, err := Marshal(&dst)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `<Tables><table xmlns="http://www.w3.org/TR/html4/">hello</table><table xmlns="http://www.w3schools.com/furniture">world</table></Tables>`
	str := string(data)
	if str != want {
		t.Errorf("have: %q\nwant: %q\n", str, want)
	}
}

type TableAttrs struct {
	TAttr TAttr
}

type TAttr struct {
	HTable string `xml:"http://www.w3.org/TR/html4/ table,attr"`
	FTable string `xml:"http://www.w3schools.com/furniture table,attr"`
	Lang   string `xml:"http://www.w3.org/XML/1998/namespace lang,attr,omitempty"`
	Other1 string `xml:"http://golang.org/xml/ other,attr,omitempty"`
	Other2 string `xml:"http://golang.org/xmlfoo/ other,attr,omitempty"`
	Other3 string `xml:"http://golang.org/json/ other,attr,omitempty"`
	Other4 string `xml:"http://golang.org/2/json/ other,attr,omitempty"`
}

var tableAttrs = []struct {
	xml string
	tab TableAttrs
	ns  string
}{
	{
		xml: `<TableAttrs xmlns:f="http://www.w3schools.com/furniture" xmlns:h="http://www.w3.org/TR/html4/"><TAttr ` +
			`h:table="hello" f:table="world" ` +
			`/></TableAttrs>`,
		tab: TableAttrs{TAttr{HTable: "hello", FTable: "world"}},
	},
	{
		xml: `<TableAttrs><TAttr xmlns:f="http://www.w3schools.com/furniture" xmlns:h="http://www.w3.org/TR/html4/" ` +
			`h:table="hello" f:table="world" ` +
			`/></TableAttrs>`,
		tab: TableAttrs{TAttr{HTable: "hello", FTable: "world"}},
	},
	{
		xml: `<TableAttrs><TAttr ` +
			`h:table="hello" f:table="world" xmlns:f="http://www.w3schools.com/furniture" xmlns:h="http://www.w3.org/TR/html4/" ` +
			`/></TableAttrs>`,
		tab: TableAttrs{TAttr{HTable: "hello", FTable: "world"}},
	},
	{
		// Default space does not apply to attribute names.
		xml: `<TableAttrs xmlns="http://www.w3schools.com/furniture" xmlns:h="http://www.w3.org/TR/html4/"><TAttr ` +
			`h:table="hello" table="world" ` +
			`/></TableAttrs>`,
		tab: TableAttrs{TAttr{HTable: "hello", FTable: ""}},
	},
	{
		// Default space does not apply to attribute names.
		xml: `<TableAttrs xmlns:f="http://www.w3schools.com/furniture"><TAttr xmlns="http://www.w3.org/TR/html4/" ` +
			`table="hello" f:table="world" ` +
			`/></TableAttrs>`,
		tab: TableAttrs{TAttr{HTable: "", FTable: "world"}},
	},
	{
		xml: `<TableAttrs><TAttr ` +
			`table="bogus" ` +
			`/></TableAttrs>`,
		tab: TableAttrs{},
	},
	{
		// Default space does not apply to attribute names.
		xml: `<TableAttrs xmlns:h="http://www.w3.org/TR/html4/"><TAttr ` +
			`h:table="hello" table="world" ` +
			`/></TableAttrs>`,
		tab: TableAttrs{TAttr{HTable: "hello", FTable: ""}},
		ns:  "http://www.w3schools.com/furniture",
	},
	{
		// Default space does not apply to attribute names.
		xml: `<TableAttrs xmlns:f="http://www.w3schools.com/furniture"><TAttr ` +
			`table="hello" f:table="world" ` +
			`/></TableAttrs>`,
		tab: TableAttrs{TAttr{HTable: "", FTable: "world"}},
		ns:  "http://www.w3.org/TR/html4/",
	},
	{
		xml: `<TableAttrs><TAttr ` +
			`table="bogus" ` +
			`/></TableAttrs>`,
		tab: TableAttrs{},
		ns:  "something else entirely",
	},
}

func TestUnmarshalNSAttr(t *testing.T) {
	for i, tt := range tableAttrs {
		var dst TableAttrs
		var err error
		if tt.ns != "" {
			d := NewDecoder(strings.NewReader(tt.xml))
			d.DefaultSpace = tt.ns
			err = d.Decode(&dst)
		} else {
			err = Unmarshal([]byte(tt.xml), &dst)
		}
		if err != nil {
			t.Errorf("#%d: Unmarshal: %v", i, err)
			continue
		}
		want := tt.tab
		if dst != want {
			t.Errorf("#%d: dst=%+v, want %+v", i, dst, want)
		}
	}
}

func TestMarshalNSAttr(t *testing.T) {
	src := TableAttrs{TAttr{"hello", "world", "en_US", "other1", "other2", "other3", "other4"}}
	data, err := Marshal(&src)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `<TableAttrs><TAttr xmlns:html4="http://www.w3.org/TR/html4/" html4:table="hello" xmlns:furniture="http://www.w3schools.com/furniture" furniture:table="world" xml:lang="en_US" xmlns:_xml="http://golang.org/xml/" _xml:other="other1" xmlns:_xmlfoo="http://golang.org/xmlfoo/" _xmlfoo:other="other2" xmlns:json="http://golang.org/json/" json:other="other3" xmlns:json_1="http://golang.org/2/json/" json_1:other="other4"></TAttr></TableAttrs>`
	str := string(data)
	if str != want {
		t.Errorf("Marshal:\nhave: %#q\nwant: %#q\n", str, want)
	}

	var dst TableAttrs
	if err := Unmarshal(data, &dst); err != nil {
		t.Errorf("Unmarshal: %v", err)
	}

	if dst != src {
		t.Errorf("Unmarshal = %q, want %q", dst, src)
	}
}

type MyCharData struct {
	body string
}

func (m *MyCharData) UnmarshalXML(d *Decoder, start StartElement) error {
	for {
		t, err := d.Token()
		if err == io.EOF { // found end of element
			break
		}
		if err != nil {
			return err
		}
		if char, ok := t.(CharData); ok {
			m.body += string(char)
		}
	}
	return nil
}

var _ Unmarshaler = (*MyCharData)(nil)

func (m *MyCharData) UnmarshalXMLAttr(attr Attr) error {
	panic("must not call")
}

type MyAttr struct {
	attr string
}

func (m *MyAttr) UnmarshalXMLAttr(attr Attr) error {
	m.attr = attr.Value
	return nil
}

var _ UnmarshalerAttr = (*MyAttr)(nil)

type MyStruct struct {
	Data *MyCharData
	Attr *MyAttr `xml:",attr"`

	Data2 MyCharData
	Attr2 MyAttr `xml:",attr"`
}

func TestUnmarshaler(t *testing.T) {
	xml := `<?xml version="1.0" encoding="utf-8"?>
		<MyStruct Attr="attr1" Attr2="attr2">
		<Data>hello <!-- comment -->world</Data>
		<Data2>howdy <!-- comment -->world</Data2>
		</MyStruct>
	`

	var m MyStruct
	if err := Unmarshal([]byte(xml), &m); err != nil {
		t.Fatal(err)
	}

	if m.Data == nil || m.Attr == nil || m.Data.body != "hello world" || m.Attr.attr != "attr1" || m.Data2.body != "howdy world" || m.Attr2.attr != "attr2" {
		t.Errorf("m=%#+v\n", m)
	}
}

type Pea struct {
	Cotelydon string
}

type Pod struct {
	Pea any `xml:"Pea"`
}

// https://golang.org/issue/6836
func TestUnmarshalIntoInterface(t *testing.T) {
	pod := new(Pod)
	pod.Pea = new(Pea)
	xml := `<Pod><Pea><Cotelydon>Green stuff</Cotelydon></Pea></Pod>`
	err := Unmarshal([]byte(xml), pod)
	if err != nil {
		t.Fatalf("failed to unmarshal %q: %v", xml, err)
	}
	pea, ok := pod.Pea.(*Pea)
	if !ok {
		t.Fatalf("unmarshaled into wrong type: have %T want *Pea", pod.Pea)
	}
	have, want := pea.Cotelydon, "Green stuff"
	if have != want {
		t.Errorf("failed to unmarshal into interface, have %q want %q", have, want)
	}
}

type X struct {
	D string `xml:",comment"`
}

// Issue 11112. Unmarshal must reject invalid comments.
func TestMalformedComment(t *testing.T) {
	testData := []string{
		"<X><!-- a---></X>",
		"<X><!-- -- --></X>",
		"<X><!-- a--b --></X>",
		"<X><!------></X>",
	}
	for i, test := range testData {
		data := []byte(test)
		v := new(X)
		if err := Unmarshal(data, v); err == nil {
			t.Errorf("%d: unmarshal should reject invalid comments", i)
		}
	}
}

type IXField struct {
	Five        int      `xml:"five"`
	NotInnerXML []string `xml:",innerxml"`
}

// Issue 15600. ",innerxml" on a field that can't hold it.
func TestInvalidInnerXMLType(t *testing.T) {
	v := new(IXField)
	if err := Unmarshal([]byte(`<tag><five>5</five><innertag/></tag>`), v); err != nil {
		t.Errorf("Unmarshal failed: got %v", err)
	}
	if v.Five != 5 {
		t.Errorf("Five = %v, want 5", v.Five)
	}
	if v.NotInnerXML != nil {
		t.Errorf("NotInnerXML = %v, want nil", v.NotInnerXML)
	}
}

type Child struct {
	G struct {
		I int
	}
}

type ChildToEmbed struct {
	X bool
}

type Parent struct {
	I        int
	IPtr     *int
	Is       []int
	IPtrs    []*int
	F        float32
	FPtr     *float32
	Fs       []float32
	FPtrs    []*float32
	B        bool
	BPtr     *bool
	Bs       []bool
	BPtrs    []*bool
	Bytes    []byte
	BytesPtr *[]byte
	S        string
	SPtr     *string
	Ss       []string
	SPtrs    []*string
	MyI      MyInt
	Child    Child
	Children []Child
	ChildPtr *Child
	ChildToEmbed
}

const (
	emptyXML = `
<Parent>
    <I></I>
    <IPtr></IPtr>
    <Is></Is>
    <IPtrs></IPtrs>
    <F></F>
    <FPtr></FPtr>
    <Fs></Fs>
    <FPtrs></FPtrs>
    <B></B>
    <BPtr></BPtr>
    <Bs></Bs>
    <BPtrs></BPtrs>
    <Bytes></Bytes>
    <BytesPtr></BytesPtr>
    <S></S>
    <SPtr></SPtr>
    <Ss></Ss>
    <SPtrs></SPtrs>
    <MyI></MyI>
    <Child></Child>
    <Children></Children>
    <ChildPtr></ChildPtr>
    <X></X>
</Parent>
`
)

// golang.org/issues/13417
func TestUnmarshalEmptyValues(t *testing.T) {
	// Test first with a zero-valued dst.
	v := new(Parent)
	if err := Unmarshal([]byte(emptyXML), v); err != nil {
		t.Fatalf("zero: Unmarshal failed: got %v", err)
	}

	zBytes, zInt, zStr, zFloat, zBool := []byte{}, 0, "", float32(0), false
	want := &Parent{
		IPtr:         &zInt,
		Is:           []int{zInt},
		IPtrs:        []*int{&zInt},
		FPtr:         &zFloat,
		Fs:           []float32{zFloat},
		FPtrs:        []*float32{&zFloat},
		BPtr:         &zBool,
		Bs:           []bool{zBool},
		BPtrs:        []*bool{&zBool},
		Bytes:        []byte{},
		BytesPtr:     &zBytes,
		SPtr:         &zStr,
		Ss:           []string{zStr},
		SPtrs:        []*string{&zStr},
		Children:     []Child{{}},
		ChildPtr:     new(Child),
		ChildToEmbed: ChildToEmbed{},
	}
	if !reflect.DeepEqual(v, want) {
		t.Fatalf("zero: Unmarshal:\nhave:  %#+v\nwant: %#+v", v, want)
	}

	// Test with a pre-populated dst.
	// Multiple addressable copies, as pointer-to fields will replace value during unmarshal.
	vBytes0, vInt0, vStr0, vFloat0, vBool0 := []byte("x"), 1, "x", float32(1), true
	vBytes1, vInt1, vStr1, vFloat1, vBool1 := []byte("x"), 1, "x", float32(1), true
	vInt2, vStr2, vFloat2, vBool2 := 1, "x", float32(1), true
	v = &Parent{
		I:            vInt0,
		IPtr:         &vInt1,
		Is:           []int{vInt0},
		IPtrs:        []*int{&vInt2},
		F:            vFloat0,
		FPtr:         &vFloat1,
		Fs:           []float32{vFloat0},
		FPtrs:        []*float32{&vFloat2},
		B:            vBool0,
		BPtr:         &vBool1,
		Bs:           []bool{vBool0},
		BPtrs:        []*bool{&vBool2},
		Bytes:        vBytes0,
		BytesPtr:     &vBytes1,
		S:            vStr0,
		SPtr:         &vStr1,
		Ss:           []string{vStr0},
		SPtrs:        []*string{&vStr2},
		MyI:          MyInt(vInt0),
		Child:        Child{G: struct{ I int }{I: vInt0}},
		Children:     []Child{{G: struct{ I int }{I: vInt0}}},
		ChildPtr:     &Child{G: struct{ I int }{I: vInt0}},
		ChildToEmbed: ChildToEmbed{X: vBool0},
	}
	if err := Unmarshal([]byte(emptyXML), v); err != nil {
		t.Fatalf("populated: Unmarshal failed: got %v", err)
	}

	want = &Parent{
		IPtr:     &zInt,
		Is:       []int{vInt0, zInt},
		IPtrs:    []*int{&vInt0, &zInt},
		FPtr:     &zFloat,
		Fs:       []float32{vFloat0, zFloat},
		FPtrs:    []*float32{&vFloat0, &zFloat},
		BPtr:     &zBool,
		Bs:       []bool{vBool0, zBool},
		BPtrs:    []*bool{&vBool0, &zBool},
		Bytes:    []byte{},
		BytesPtr: &zBytes,
		SPtr:     &zStr,
		Ss:       []string{vStr0, zStr},
		SPtrs:    []*string{&vStr0, &zStr},
		Child:    Child{G: struct{ I int }{I: vInt0}}, // I should == zInt0? (zero value)
		Children: []Child{{G: struct{ I int }{I: vInt0}}, {}},
		ChildPtr: &Child{G: struct{ I int }{I: vInt0}}, // I should == zInt0? (zero value)
	}
	if !reflect.DeepEqual(v, want) {
		t.Fatalf("populated: Unmarshal:\nhave:  %#+v\nwant: %#+v", v, want)
	}
}

type WhitespaceValuesParent struct {
	BFalse bool
	BTrue  bool
	I      int
	INeg   int
	I8     int8
	I8Neg  int8
	I16    int16
	I16Neg int16
	I32    int32
	I32Neg int32
	I64    int64
	I64Neg int64
	UI     uint
	UI8    uint8
	UI16   uint16
	UI32   uint32
	UI64   uint64
	F32    float32
	F32Neg float32
	F64    float64
	F64Neg float64
}

const whitespaceValuesXML = `
<WhitespaceValuesParent>
    <BFalse>   false   </BFalse>
    <BTrue>   true   </BTrue>
    <I>   266703   </I>
    <INeg>   -266703   </INeg>
    <I8>  112  </I8>
    <I8Neg>  -112  </I8Neg>
    <I16>  6703  </I16>
    <I16Neg>  -6703  </I16Neg>
    <I32>  266703  </I32>
    <I32Neg>  -266703  </I32Neg>
    <I64>  266703  </I64>
    <I64Neg>  -266703  </I64Neg>
    <UI>   266703   </UI>
    <UI8>  112  </UI8>
    <UI16>  6703  </UI16>
    <UI32>  266703  </UI32>
    <UI64>  266703  </UI64>
    <F32>  266.703  </F32>
    <F32Neg>  -266.703  </F32Neg>
    <F64>  266.703  </F64>
    <F64Neg>  -266.703  </F64Neg>
</WhitespaceValuesParent>
`

// golang.org/issues/22146
func TestUnmarshalWhitespaceValues(t *testing.T) {
	v := WhitespaceValuesParent{}
	if err := Unmarshal([]byte(whitespaceValuesXML), &v); err != nil {
		t.Fatalf("whitespace values: Unmarshal failed: got %v", err)
	}

	want := WhitespaceValuesParent{
		BFalse: false,
		BTrue:  true,
		I:      266703,
		INeg:   -266703,
		I8:     112,
		I8Neg:  -112,
		I16:    6703,
		I16Neg: -6703,
		I32:    266703,
		I32Neg: -266703,
		I64:    266703,
		I64Neg: -266703,
		UI:     266703,
		UI8:    112,
		UI16:   6703,
		UI32:   266703,
		UI64:   266703,
		F32:    266.703,
		F32Neg: -266.703,
		F64:    266.703,
		F64Neg: -266.703,
	}
	if v != want {
		t.Fatalf("whitespace values: Unmarshal:\nhave: %#+v\nwant: %#+v", v, want)
	}
}

type WhitespaceAttrsParent struct {
	BFalse bool    `xml:",attr"`
	BTrue  bool    `xml:",attr"`
	I      int     `xml:",attr"`
	INeg   int     `xml:",attr"`
	I8     int8    `xml:",attr"`
	I8Neg  int8    `xml:",attr"`
	I16    int16   `xml:",attr"`
	I16Neg int16   `xml:",attr"`
	I32    int32   `xml:",attr"`
	I32Neg int32   `xml:",attr"`
	I64    int64   `xml:",attr"`
	I64Neg int64   `xml:",attr"`
	UI     uint    `xml:",attr"`
	UI8    uint8   `xml:",attr"`
	UI16   uint16  `xml:",attr"`
	UI32   uint32  `xml:",attr"`
	UI64   uint64  `xml:",attr"`
	F32    float32 `xml:",attr"`
	F32Neg float32 `xml:",attr"`
	F64    float64 `xml:",attr"`
	F64Neg float64 `xml:",attr"`
}

const whitespaceAttrsXML = `
<WhitespaceAttrsParent
    BFalse="  false  "
    BTrue="  true  "
    I="  266703  "
    INeg="  -266703  "
    I8="  112  "
    I8Neg="  -112  "
    I16="  6703  "
    I16Neg="  -6703  "
    I32="  266703  "
    I32Neg="  -266703  "
    I64="  266703  "
    I64Neg="  -266703  "
    UI="  266703  "
    UI8="  112  "
    UI16="  6703  "
    UI32="  266703  "
    UI64="  266703  "
    F32="  266.703  "
    F32Neg="  -266.703  "
    F64="  266.703  "
    F64Neg="  -266.703  "
>
</WhitespaceAttrsParent>
`

// golang.org/issues/22146
func TestUnmarshalWhitespaceAttrs(t *testing.T) {
	v := WhitespaceAttrsParent{}
	if err := Unmarshal([]byte(whitespaceAttrsXML), &v); err != nil {
		t.Fatalf("whitespace attrs: Unmarshal failed: got %v", err)
	}

	want := WhitespaceAttrsParent{
		BFalse: false,
		BTrue:  true,
		I:      266703,
		INeg:   -266703,
		I8:     112,
		I8Neg:  -112,
		I16:    6703,
		I16Neg: -6703,
		I32:    266703,
		I32Neg: -266703,
		I64:    266703,
		I64Neg: -266703,
		UI:     266703,
		UI8:    112,
		UI16:   6703,
		UI32:   266703,
		UI64:   266703,
		F32:    266.703,
		F32Neg: -266.703,
		F64:    266.703,
		F64Neg: -266.703,
	}
	if v != want {
		t.Fatalf("whitespace attrs: Unmarshal:\nhave: %#+v\nwant: %#+v", v, want)
	}
}

// golang.org/issues/53350
func TestUnmarshalIntoNil(t *testing.T) {
	type T struct {
		A int `xml:"A"`
	}

	var nilPointer *T
	err := Unmarshal([]byte("<T><A>1</A></T>"), nilPointer)

	if err == nil {
		t.Fatalf("no error in unmarshaling")
	}

}

func TestCVE202228131(t *testing.T) {
	type nested struct {
		Parent *nested `xml:",any"`
	}
	var n nested
	err := Unmarshal(bytes.Repeat([]byte("<a>"), maxUnmarshalDepth+1), &n)
	if err == nil {
		t.Fatal("Unmarshal did not fail")
	} else if !errors.Is(err, errUnmarshalDepth) {
		t.Fatalf("Unmarshal unexpected error: got %q, want %q", err, errUnmarshalDepth)
	}
}

func TestCVE202230633(t *testing.T) {
	if testing.Short() || runtime.GOARCH == "wasm" {
		t.Skip("test requires significant memory")
	}
	defer func() {
		p := recover()
		if p != nil {
			t.Fatal("Unmarshal panicked")
		}
	}()
	var example struct {
		Things []string
	}
	Unmarshal(bytes.Repeat([]byte("<a>"), 17_000_000), &example)
}
```