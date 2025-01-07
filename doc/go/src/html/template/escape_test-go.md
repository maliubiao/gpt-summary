Response:
My thought process for analyzing the Go code and generating the response involved several steps:

1. **Understanding the Goal:** The primary request is to analyze a Go file (`escape_test.go`) and explain its functionality, focusing on its role in testing HTML template escaping.

2. **Initial Code Scan:** I quickly scanned the code to identify key components:
    * **Package Declaration:** `package template` - This indicates it's part of the `html/template` package.
    * **Imports:**  Standard testing libraries (`testing`), string manipulation (`strings`), and specific `html/template` and `text/template` packages. This confirms it's a test file for HTML templating.
    * **`struct` definitions:** `badMarshaler`, `goodMarshaler`. These seem related to testing how data is marshaled (likely to JSON) within templates.
    * **`TestEscape` function:** This is the core testing function. It contains a large slice of `struct`s defining test cases.
    * **Test case structure:** Each test case has `name`, `input` (template string), and `output` (expected escaped output).
    * **Template execution within tests:** The tests parse the `input` template and execute it with some test data.
    * **Assertions:** The tests compare the actual output with the expected `output`.
    * **Other `Test...` functions:** `TestEscapeMap`, `TestEscapeSet`, `TestErrors`, `TestEscapeText` - these suggest different aspects of escaping being tested.

3. **Focusing on `TestEscape`:** This function appears to be the most comprehensive and indicative of the file's core purpose.

4. **Analyzing Test Cases in `TestEscape`:** I examined the different test cases and categorized them by what they seem to be testing:
    * **Basic HTML escaping:** Cases involving `<`, `>`, `&`.
    * **Contextual escaping:** How escaping changes within different HTML contexts (e.g., within `<script>` tags, within attributes, within `<style>` tags).
    * **URL escaping:** Handling of URLs in `href` attributes.
    * **JavaScript escaping:** Escaping within `onclick` attributes and `<script>` tags.
    * **CSS escaping:** Escaping within `<style>` tags and `style` attributes.
    * **JSON marshaling:**  Testing how `json.Marshaler` interfaces interact with templates.
    * **Comments:** How HTML, JavaScript, and CSS comments are handled.
    * **Special HTML elements:**  `<textarea>`, doctype.
    * **Dynamic attributes and elements:** Testing template logic within tag and attribute names.
    * **Error conditions:** Cases that are expected to produce errors.

5. **Inferring Functionality:** Based on the test cases, I reasoned that the primary function of the code is to test the **context-aware escaping** capabilities of Go's `html/template` package. This means the template engine intelligently escapes content based on where it's placed in the HTML structure to prevent cross-site scripting (XSS) vulnerabilities.

6. **Constructing the Explanation (Part 1):** I summarized the findings concisely for the first part of the request: "归纳一下它的功能". This involved highlighting the core purpose of testing HTML escaping and mentioning the different contexts covered.

7. **Preparing for Part 2 (Anticipating the Request):** Knowing there was a "Part 2," I anticipated it would ask for more details on specific Go language features and examples. I kept the specific details observed in step 4 in mind.

8. **Generating Go Code Examples (Mental Preparation):**  I mentally drafted examples to illustrate:
    * Basic HTML escaping.
    * JavaScript context escaping.
    * CSS context escaping.
    * URL escaping.
    * How to use `| html`, `| js`, `| css`, `| urlquery`.

9. **Thinking about Error Scenarios:** I reviewed the `TestErrors` function to identify common mistakes users might make, such as:
    * Incorrectly using template logic within HTML tags.
    * Expecting non-final pipeline commands to perform escaping.
    * Issues with unclosed or mismatched quotes.

10. **Considering Command-Line Arguments:** I noted that the provided code was a test file and didn't directly involve command-line arguments. However, I knew that the `go test` command is used to run these tests, so I prepared to mention that.

11. **Review and Refinement:** I reviewed my understanding and planned answers to ensure they were accurate, clear, and addressed all parts of the prompt. I paid attention to using proper Chinese terminology.

Essentially, I started with a broad overview and then drilled down into the specific details of the test cases to infer the underlying functionality being tested. I then structured the explanation to match the request's format, anticipating the likely content of the subsequent part.
这是 `go/src/html/template/escape_test.go` 文件的一部分，它主要的功能是**测试 Go 语言 `html/template` 包的 HTML 转义功能**。

更具体地说，这段代码测试了 `html/template` 包在不同 HTML 上下文（例如，普通文本、HTML 标签属性、`<script>` 标签、`<style>` 标签等）中，对模板中插入的数据进行正确的转义，以防止跨站脚本攻击 (XSS)。

**以下是更详细的功能列表:**

1. **测试基本的 HTML 实体转义:**  例如，将 `<` 转义为 `&lt;`，将 `>` 转义为 `&gt;`，将 `&` 转义为 `&amp;`，将双引号 `"` 转义为 `&#34;`，将单引号 `'` 转义为 `&#39;`。

2. **测试上下文相关的转义:** `html/template` 的一个关键特性是能够根据内容插入的 HTML 上下文进行不同的转义。这段代码测试了在以下上下文中的转义行为：
    * **普通文本:**  最基本的 HTML 转义。
    * **HTML 标签属性:**  例如 `href`，`title`，`class` 等属性中的值，需要进行 URL 编码或 HTML 实体编码。
    * **`<script>` 标签:**  JavaScript 代码中的字符串需要进行 JavaScript 特殊字符的转义，例如将 `<` 转义为 `\u003c`，将双引号转义为 `\"`。
    * **`<style>` 标签:** CSS 代码中的字符串和 URL 需要进行 CSS 特殊字符的转义和 URL 编码。
    * **URL:**  测试 `href` 等 URL 属性中的 URL 编码，以及对危险 URL (例如 `javascript:`) 的处理。
    * **JavaScript 字符串字面量和正则表达式:**  测试在 `<script>` 标签内的 JavaScript 字符串和正则表达式字面量中的转义。
    * **CSS 字符串和 URL:** 测试在 `<style>` 标签和 `style` 属性内的 CSS 字符串和 URL 的转义和编码。

3. **测试模板控制结构中的转义:** 例如 `{{if}}`, `{{else}}`, `{{range}}`, `{{with}}` 等，确保在这些结构中插入的内容也能正确转义。

4. **测试管道操作符 (`|`) 和预定义的转义函数:**  例如 `html`, `js`, `css`, `urlquery`。代码验证了这些函数在不同上下文中的行为。

5. **测试 `json.Marshaler` 接口:** 代码测试了当模板数据实现了 `json.Marshaler` 接口时，`html/template` 如何处理其输出。

6. **测试 HTML 注释、JavaScript 注释和 CSS 注释的处理:** 验证模板引擎是否正确识别和处理这些注释，以及它们是否会影响转义行为。

7. **测试自定义模板的功能 (`{{define}}` 和 `{{template}}`)**:  验证在不同的模板上下文中调用其他模板时，转义是否正确。

8. **测试错误处理:**  代码包含了一些预期会产生错误的模板输入，用于验证 `html/template` 包的错误处理机制。

**用 Go 代码举例说明 (HTML 标签属性转义):**

假设输入的模板字符串是：

```go
tmplStr := `<a href="/search?q={{.Query}}">Search</a>`
```

假设输入的数据是：

```go
data := struct {
    Query string
}{
    Query: "go <language>",
}
```

执行模板：

```go
package main

import (
	"html/template"
	"os"
)

func main() {
	tmplStr := `<a href="/search?q={{.Query}}">Search</a>`
	data := struct {
		Query string
	}{
		Query: "go <language>",
	}

	tmpl, err := template.New("test").Parse(tmplStr)
	if err != nil {
		panic(err)
	}
	err = tmpl.Execute(os.Stdout, data)
	if err != nil {
		panic(err)
	}
}
```

**假设的输出:**

```html
<a href="/search?q=go%20%3clanguage%3e">Search</a>
```

**解释:**  在 `href` 属性中，空格被 URL 编码为 `%20`，`<` 被编码为 `%3c`。这是因为 `html/template` 知道 `href` 是一个 URL 属性，需要进行 URL 编码。

**用 Go 代码举例说明 (JavaScript 上下文转义):**

假设输入的模板字符串是：

```go
tmplStr := `<button onclick="alert('Hello, {{.Name}}!')">Click Me</button>`
```

假设输入的数据是：

```go
data := struct {
    Name string
}{
    Name: "O'Reilly with '",
}
```

执行模板：

```go
package main

import (
	"html/template"
	"os"
)

func main() {
	tmplStr := `<button onclick="alert('Hello, {{.Name}}!')">Click Me</button>`
	data := struct {
		Name string
	}{
		Name: "O'Reilly with '",
	}

	tmpl, err := template.New("test").Parse(tmplStr)
	if err != nil {
		panic(err)
	}
	err = tmpl.Execute(os.Stdout, data)
	if err != nil {
		panic(err)
	}
}
```

**假设的输出:**

```html
<button onclick="alert('Hello, O\'Reilly with \'!')">Click Me</button>
```

**解释:** 在 `onclick` 属性的 JavaScript 字符串中，单引号 `'` 被转义为 `\'`，以避免 JavaScript 语法错误，并防止 XSS 攻击。

**涉及代码推理，需要带上假设的输入与输出:**  上面的两个例子已经包含了。

**如果涉及命令行参数的具体处理，请详细介绍一下:**

这段代码本身是一个测试文件，它不直接处理命令行参数。 它的目的是通过 `go test` 命令来运行。 `go test` 命令会编译并执行该文件中的测试函数（以 `Test` 开头的函数）。

虽然这段代码本身不涉及命令行参数，但运行它的 `go test` 命令可以接受一些参数，例如：

* `-v`:  显示更详细的测试输出，包括每个测试用例的名称。
* `-run <regexp>`:  只运行名称匹配正则表达式的测试用例。
* `-coverprofile <file>`:  生成代码覆盖率报告。

**如果有哪些使用者易犯错的点，请举例说明:**

1. **在不应该使用的地方使用管道操作符和预定义的转义函数:**  例如，在 HTML 标签内部直接使用 `{{. | html}}` 可能不是预期的行为。 `html/template` 通常会根据上下文自动进行转义。

   ```go
   // 错误示例
   tmplStr := `<div class="{{.ClassName | html}}">...</div>`
   data := struct {
       ClassName string
   }{
       ClassName: "<script>alert('evil')</script>",
   }
   ```
   虽然 `html` 函数会转义尖括号，但这可能不是最佳实践，因为 `html/template` 通常会根据 `class` 属性的上下文进行适当的转义。

2. **在 JavaScript 或 CSS 上下文中使用错误的转义函数:**  例如，在 `<script>` 标签内使用 `{{. | html}}` 进行转义，这会导致 JavaScript 代码中的 HTML 实体，而不是正确的 JavaScript 字符串转义。应该使用 `{{. | js}}`。

   ```go
   // 错误示例
   tmplStr := `<script>var msg = '{{.Message | html}}';</script>`
   data := struct {
       Message string
   }{
       Message: "O'Reilly's",
   }
   // 输出会是 <script>var msg = 'O&#39;Reilly&#39;s';</script>，这可能不是预期的 JavaScript 代码。
   ```

3. **期望在所有情况下都进行相同的转义:**  `html/template` 的强大之处在于其上下文感知能力。用户需要理解不同上下文下的转义规则是不同的。

4. **过度转义:** 有时用户可能会手动转义一些数据，然后在模板中再次使用预定义的转义函数，导致过度转义。

**归纳一下它的功能 (第1部分):**

这段代码的主要功能是**全面测试 Go 语言 `html/template` 包的 HTML 上下文感知转义能力，以确保其能够有效地防止跨站脚本攻击。** 它通过大量的测试用例，覆盖了各种 HTML 上下文、模板控制结构、预定义的转义函数以及错误处理情况，来验证模板引擎的正确性。

Prompt: 
```
这是路径为go/src/html/template/escape_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package template

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"text/template"
	"text/template/parse"
)

type badMarshaler struct{}

func (x *badMarshaler) MarshalJSON() ([]byte, error) {
	// Keys in valid JSON must be double quoted as must all strings.
	return []byte("{ foo: 'not quite valid JSON' }"), nil
}

type goodMarshaler struct{}

func (x *goodMarshaler) MarshalJSON() ([]byte, error) {
	return []byte(`{ "<foo>": "O'Reilly" }`), nil
}

func TestEscape(t *testing.T) {
	data := struct {
		F, T       bool
		C, G, H, I string
		A, E       []string
		B, M       json.Marshaler
		N          int
		U          any  // untyped nil
		Z          *int // typed nil
		W          HTML
	}{
		F: false,
		T: true,
		C: "<Cincinnati>",
		G: "<Goodbye>",
		H: "<Hello>",
		A: []string{"<a>", "<b>"},
		E: []string{},
		N: 42,
		B: &badMarshaler{},
		M: &goodMarshaler{},
		U: nil,
		Z: nil,
		W: HTML(`&iexcl;<b class="foo">Hello</b>, <textarea>O'World</textarea>!`),
		I: "${ asd `` }",
	}
	pdata := &data

	tests := []struct {
		name   string
		input  string
		output string
	}{
		{
			"if",
			"{{if .T}}Hello{{end}}, {{.C}}!",
			"Hello, &lt;Cincinnati&gt;!",
		},
		{
			"else",
			"{{if .F}}{{.H}}{{else}}{{.G}}{{end}}!",
			"&lt;Goodbye&gt;!",
		},
		{
			"overescaping1",
			"Hello, {{.C | html}}!",
			"Hello, &lt;Cincinnati&gt;!",
		},
		{
			"overescaping2",
			"Hello, {{html .C}}!",
			"Hello, &lt;Cincinnati&gt;!",
		},
		{
			"overescaping3",
			"{{with .C}}{{$msg := .}}Hello, {{$msg}}!{{end}}",
			"Hello, &lt;Cincinnati&gt;!",
		},
		{
			"assignment",
			"{{if $x := .H}}{{$x}}{{end}}",
			"&lt;Hello&gt;",
		},
		{
			"withBody",
			"{{with .H}}{{.}}{{end}}",
			"&lt;Hello&gt;",
		},
		{
			"withElse",
			"{{with .E}}{{.}}{{else}}{{.H}}{{end}}",
			"&lt;Hello&gt;",
		},
		{
			"rangeBody",
			"{{range .A}}{{.}}{{end}}",
			"&lt;a&gt;&lt;b&gt;",
		},
		{
			"rangeElse",
			"{{range .E}}{{.}}{{else}}{{.H}}{{end}}",
			"&lt;Hello&gt;",
		},
		{
			"nonStringValue",
			"{{.T}}",
			"true",
		},
		{
			"untypedNilValue",
			"{{.U}}",
			"",
		},
		{
			"typedNilValue",
			"{{.Z}}",
			"&lt;nil&gt;",
		},
		{
			"constant",
			`<a href="/search?q={{"'a<b'"}}">`,
			`<a href="/search?q=%27a%3cb%27">`,
		},
		{
			"multipleAttrs",
			"<a b=1 c={{.H}}>",
			"<a b=1 c=&lt;Hello&gt;>",
		},
		{
			"urlStartRel",
			`<a href='{{"/foo/bar?a=b&c=d"}}'>`,
			`<a href='/foo/bar?a=b&amp;c=d'>`,
		},
		{
			"urlStartAbsOk",
			`<a href='{{"http://example.com/foo/bar?a=b&c=d"}}'>`,
			`<a href='http://example.com/foo/bar?a=b&amp;c=d'>`,
		},
		{
			"protocolRelativeURLStart",
			`<a href='{{"//example.com:8000/foo/bar?a=b&c=d"}}'>`,
			`<a href='//example.com:8000/foo/bar?a=b&amp;c=d'>`,
		},
		{
			"pathRelativeURLStart",
			`<a href="{{"/javascript:80/foo/bar"}}">`,
			`<a href="/javascript:80/foo/bar">`,
		},
		{
			"dangerousURLStart",
			`<a href='{{"javascript:alert(%22pwned%22)"}}'>`,
			`<a href='#ZgotmplZ'>`,
		},
		{
			"dangerousURLStart2",
			`<a href='  {{"javascript:alert(%22pwned%22)"}}'>`,
			`<a href='  #ZgotmplZ'>`,
		},
		{
			"nonHierURL",
			`<a href={{"mailto:Muhammed \"The Greatest\" Ali <m.ali@example.com>"}}>`,
			`<a href=mailto:Muhammed%20%22The%20Greatest%22%20Ali%20%3cm.ali@example.com%3e>`,
		},
		{
			"urlPath",
			`<a href='http://{{"javascript:80"}}/foo'>`,
			`<a href='http://javascript:80/foo'>`,
		},
		{
			"urlQuery",
			`<a href='/search?q={{.H}}'>`,
			`<a href='/search?q=%3cHello%3e'>`,
		},
		{
			"urlFragment",
			`<a href='/faq#{{.H}}'>`,
			`<a href='/faq#%3cHello%3e'>`,
		},
		{
			"urlBranch",
			`<a href="{{if .F}}/foo?a=b{{else}}/bar{{end}}">`,
			`<a href="/bar">`,
		},
		{
			"urlBranchConflictMoot",
			`<a href="{{if .T}}/foo?a={{else}}/bar#{{end}}{{.C}}">`,
			`<a href="/foo?a=%3cCincinnati%3e">`,
		},
		{
			"jsStrValue",
			"<button onclick='alert({{.H}})'>",
			`<button onclick='alert(&#34;\u003cHello\u003e&#34;)'>`,
		},
		{
			"jsNumericValue",
			"<button onclick='alert({{.N}})'>",
			`<button onclick='alert( 42 )'>`,
		},
		{
			"jsBoolValue",
			"<button onclick='alert({{.T}})'>",
			`<button onclick='alert( true )'>`,
		},
		{
			"jsNilValueTyped",
			"<button onclick='alert(typeof{{.Z}})'>",
			`<button onclick='alert(typeof null )'>`,
		},
		{
			"jsNilValueUntyped",
			"<button onclick='alert(typeof{{.U}})'>",
			`<button onclick='alert(typeof null )'>`,
		},
		{
			"jsObjValue",
			"<button onclick='alert({{.A}})'>",
			`<button onclick='alert([&#34;\u003ca\u003e&#34;,&#34;\u003cb\u003e&#34;])'>`,
		},
		{
			"jsObjValueScript",
			"<script>alert({{.A}})</script>",
			`<script>alert(["\u003ca\u003e","\u003cb\u003e"])</script>`,
		},
		{
			"jsObjValueNotOverEscaped",
			"<button onclick='alert({{.A | html}})'>",
			`<button onclick='alert([&#34;\u003ca\u003e&#34;,&#34;\u003cb\u003e&#34;])'>`,
		},
		{
			"jsStr",
			"<button onclick='alert(&quot;{{.H}}&quot;)'>",
			`<button onclick='alert(&quot;\u003cHello\u003e&quot;)'>`,
		},
		{
			"badMarshaler",
			`<button onclick='alert(1/{{.B}}in numbers)'>`,
			`<button onclick='alert(1/ /* json: error calling MarshalJSON for type *template.badMarshaler: invalid character &#39;f&#39; looking for beginning of object key string */null in numbers)'>`,
		},
		{
			"jsMarshaler",
			`<button onclick='alert({{.M}})'>`,
			`<button onclick='alert({&#34;\u003cfoo\u003e&#34;:&#34;O&#39;Reilly&#34;})'>`,
		},
		{
			"jsStrNotUnderEscaped",
			"<button onclick='alert({{.C | urlquery}})'>",
			// URL escaped, then quoted for JS.
			`<button onclick='alert(&#34;%3CCincinnati%3E&#34;)'>`,
		},
		{
			"jsRe",
			`<button onclick='alert(/{{"foo+bar"}}/.test(""))'>`,
			`<button onclick='alert(/foo\u002bbar/.test(""))'>`,
		},
		{
			"jsReBlank",
			`<script>alert(/{{""}}/.test(""));</script>`,
			`<script>alert(/(?:)/.test(""));</script>`,
		},
		{
			"jsReAmbigOk",
			`<script>{{if true}}var x = 1{{end}}</script>`,
			// The {if} ends in an ambiguous jsCtx but there is
			// no slash following so we shouldn't care.
			`<script>var x = 1</script>`,
		},
		{
			"styleBidiKeywordPassed",
			`<p style="dir: {{"ltr"}}">`,
			`<p style="dir: ltr">`,
		},
		{
			"styleBidiPropNamePassed",
			`<p style="border-{{"left"}}: 0; border-{{"right"}}: 1in">`,
			`<p style="border-left: 0; border-right: 1in">`,
		},
		{
			"styleExpressionBlocked",
			`<p style="width: {{"expression(alert(1337))"}}">`,
			`<p style="width: ZgotmplZ">`,
		},
		{
			"styleTagSelectorPassed",
			`<style>{{"p"}} { color: pink }</style>`,
			`<style>p { color: pink }</style>`,
		},
		{
			"styleIDPassed",
			`<style>p{{"#my-ID"}} { font: Arial }</style>`,
			`<style>p#my-ID { font: Arial }</style>`,
		},
		{
			"styleClassPassed",
			`<style>p{{".my_class"}} { font: Arial }</style>`,
			`<style>p.my_class { font: Arial }</style>`,
		},
		{
			"styleQuantityPassed",
			`<a style="left: {{"2em"}}; top: {{0}}">`,
			`<a style="left: 2em; top: 0">`,
		},
		{
			"stylePctPassed",
			`<table style=width:{{"100%"}}>`,
			`<table style=width:100%>`,
		},
		{
			"styleColorPassed",
			`<p style="color: {{"#8ff"}}; background: {{"#000"}}">`,
			`<p style="color: #8ff; background: #000">`,
		},
		{
			"styleObfuscatedExpressionBlocked",
			`<p style="width: {{"  e\\78preS\x00Sio/**/n(alert(1337))"}}">`,
			`<p style="width: ZgotmplZ">`,
		},
		{
			"styleMozBindingBlocked",
			`<p style="{{"-moz-binding(alert(1337))"}}: ...">`,
			`<p style="ZgotmplZ: ...">`,
		},
		{
			"styleObfuscatedMozBindingBlocked",
			`<p style="{{"  -mo\\7a-B\x00I/**/nding(alert(1337))"}}: ...">`,
			`<p style="ZgotmplZ: ...">`,
		},
		{
			"styleFontNameString",
			`<p style='font-family: "{{"Times New Roman"}}"'>`,
			`<p style='font-family: "Times New Roman"'>`,
		},
		{
			"styleFontNameString",
			`<p style='font-family: "{{"Times New Roman"}}", "{{"sans-serif"}}"'>`,
			`<p style='font-family: "Times New Roman", "sans-serif"'>`,
		},
		{
			"styleFontNameUnquoted",
			`<p style='font-family: {{"Times New Roman"}}'>`,
			`<p style='font-family: Times New Roman'>`,
		},
		{
			"styleURLQueryEncoded",
			`<p style="background: url(/img?name={{"O'Reilly Animal(1)<2>.png"}})">`,
			`<p style="background: url(/img?name=O%27Reilly%20Animal%281%29%3c2%3e.png)">`,
		},
		{
			"styleQuotedURLQueryEncoded",
			`<p style="background: url('/img?name={{"O'Reilly Animal(1)<2>.png"}}')">`,
			`<p style="background: url('/img?name=O%27Reilly%20Animal%281%29%3c2%3e.png')">`,
		},
		{
			"styleStrQueryEncoded",
			`<p style="background: '/img?name={{"O'Reilly Animal(1)<2>.png"}}'">`,
			`<p style="background: '/img?name=O%27Reilly%20Animal%281%29%3c2%3e.png'">`,
		},
		{
			"styleURLBadProtocolBlocked",
			`<a style="background: url('{{"javascript:alert(1337)"}}')">`,
			`<a style="background: url('#ZgotmplZ')">`,
		},
		{
			"styleStrBadProtocolBlocked",
			`<a style="background: '{{"vbscript:alert(1337)"}}'">`,
			`<a style="background: '#ZgotmplZ'">`,
		},
		{
			"styleStrEncodedProtocolEncoded",
			`<a style="background: '{{"javascript\\3a alert(1337)"}}'">`,
			// The CSS string 'javascript\\3a alert(1337)' does not contain a colon.
			`<a style="background: 'javascript\\3a alert\28 1337\29 '">`,
		},
		{
			"styleURLGoodProtocolPassed",
			`<a style="background: url('{{"http://oreilly.com/O'Reilly Animals(1)<2>;{}.html"}}')">`,
			`<a style="background: url('http://oreilly.com/O%27Reilly%20Animals%281%29%3c2%3e;%7b%7d.html')">`,
		},
		{
			"styleStrGoodProtocolPassed",
			`<a style="background: '{{"http://oreilly.com/O'Reilly Animals(1)<2>;{}.html"}}'">`,
			`<a style="background: 'http\3a\2f\2foreilly.com\2fO\27Reilly Animals\28 1\29\3c 2\3e\3b\7b\7d.html'">`,
		},
		{
			"styleURLEncodedForHTMLInAttr",
			`<a style="background: url('{{"/search?img=foo&size=icon"}}')">`,
			`<a style="background: url('/search?img=foo&amp;size=icon')">`,
		},
		{
			"styleURLNotEncodedForHTMLInCdata",
			`<style>body { background: url('{{"/search?img=foo&size=icon"}}') }</style>`,
			`<style>body { background: url('/search?img=foo&size=icon') }</style>`,
		},
		{
			"styleURLMixedCase",
			`<p style="background: URL(#{{.H}})">`,
			`<p style="background: URL(#%3cHello%3e)">`,
		},
		{
			"stylePropertyPairPassed",
			`<a style='{{"color: red"}}'>`,
			`<a style='color: red'>`,
		},
		{
			"styleStrSpecialsEncoded",
			`<a style="font-family: '{{"/**/'\";:// \\"}}', &quot;{{"/**/'\";:// \\"}}&quot;">`,
			`<a style="font-family: '\2f**\2f\27\22\3b\3a\2f\2f  \\', &quot;\2f**\2f\27\22\3b\3a\2f\2f  \\&quot;">`,
		},
		{
			"styleURLSpecialsEncoded",
			`<a style="border-image: url({{"/**/'\";:// \\"}}), url(&quot;{{"/**/'\";:// \\"}}&quot;), url('{{"/**/'\";:// \\"}}'), 'http://www.example.com/?q={{"/**/'\";:// \\"}}''">`,
			`<a style="border-image: url(/**/%27%22;://%20%5c), url(&quot;/**/%27%22;://%20%5c&quot;), url('/**/%27%22;://%20%5c'), 'http://www.example.com/?q=%2f%2a%2a%2f%27%22%3b%3a%2f%2f%20%5c''">`,
		},
		{
			"HTML comment",
			"<b>Hello, <!-- name of world -->{{.C}}</b>",
			"<b>Hello, &lt;Cincinnati&gt;</b>",
		},
		{
			"HTML comment not first < in text node.",
			"<<!-- -->!--",
			"&lt;!--",
		},
		{
			"HTML normalization 1",
			"a < b",
			"a &lt; b",
		},
		{
			"HTML normalization 2",
			"a << b",
			"a &lt;&lt; b",
		},
		{
			"HTML normalization 3",
			"a<<!-- --><!-- -->b",
			"a&lt;b",
		},
		{
			"HTML doctype not normalized",
			"<!DOCTYPE html>Hello, World!",
			"<!DOCTYPE html>Hello, World!",
		},
		{
			"HTML doctype not case-insensitive",
			"<!doCtYPE htMl>Hello, World!",
			"<!doCtYPE htMl>Hello, World!",
		},
		{
			"No doctype injection",
			`<!{{"DOCTYPE"}}`,
			"&lt;!DOCTYPE",
		},
		{
			"Split HTML comment",
			"<b>Hello, <!-- name of {{if .T}}city -->{{.C}}{{else}}world -->{{.W}}{{end}}</b>",
			"<b>Hello, &lt;Cincinnati&gt;</b>",
		},
		{
			"JS line comment",
			"<script>for (;;) { if (c()) break// foo not a label\n" +
				"foo({{.T}});}</script>",
			"<script>for (;;) { if (c()) break\n" +
				"foo( true );}</script>",
		},
		{
			"JS multiline block comment",
			"<script>for (;;) { if (c()) break/* foo not a label\n" +
				" */foo({{.T}});}</script>",
			// Newline separates break from call. If newline
			// removed, then break will consume label leaving
			// code invalid.
			"<script>for (;;) { if (c()) break\n" +
				"foo( true );}</script>",
		},
		{
			"JS single-line block comment",
			"<script>for (;;) {\n" +
				"if (c()) break/* foo a label */foo;" +
				"x({{.T}});}</script>",
			// Newline separates break from call. If newline
			// removed, then break will consume label leaving
			// code invalid.
			"<script>for (;;) {\n" +
				"if (c()) break foo;" +
				"x( true );}</script>",
		},
		{
			"JS block comment flush with mathematical division",
			"<script>var a/*b*//c\nd</script>",
			"<script>var a /c\nd</script>",
		},
		{
			"JS mixed comments",
			"<script>var a/*b*///c\nd</script>",
			"<script>var a \nd</script>",
		},
		{
			"JS HTML-like comments",
			"<script>before <!-- beep\nbetween\nbefore-->boop\n</script>",
			"<script>before \nbetween\nbefore\n</script>",
		},
		{
			"JS hashbang comment",
			"<script>#! beep\n</script>",
			"<script>\n</script>",
		},
		{
			"Special tags in <script> string literals",
			`<script>var a = "asd < 123 <!-- 456 < fgh <script jkl < 789 </script"</script>`,
			`<script>var a = "asd < 123 \x3C!-- 456 < fgh \x3Cscript jkl < 789 \x3C/script"</script>`,
		},
		{
			"Special tags in <script> string literals (mixed case)",
			`<script>var a = "<!-- <ScripT </ScripT"</script>`,
			`<script>var a = "\x3C!-- \x3CScripT \x3C/ScripT"</script>`,
		},
		{
			"Special tags in <script> regex literals (mixed case)",
			`<script>var a = /<!-- <ScripT </ScripT/</script>`,
			`<script>var a = /\x3C!-- \x3CScripT \x3C/ScripT/</script>`,
		},
		{
			"CSS comments",
			"<style>p// paragraph\n" +
				`{border: 1px/* color */{{"#00f"}}}</style>`,
			"<style>p\n" +
				"{border: 1px #00f}</style>",
		},
		{
			"JS attr block comment",
			`<a onclick="f(&quot;&quot;); /* alert({{.H}}) */">`,
			// Attribute comment tests should pass if the comments
			// are successfully elided.
			`<a onclick="f(&quot;&quot;); /* alert() */">`,
		},
		{
			"JS attr line comment",
			`<a onclick="// alert({{.G}})">`,
			`<a onclick="// alert()">`,
		},
		{
			"CSS attr block comment",
			`<a style="/* color: {{.H}} */">`,
			`<a style="/* color:  */">`,
		},
		{
			"CSS attr line comment",
			`<a style="// color: {{.G}}">`,
			`<a style="// color: ">`,
		},
		{
			"HTML substitution commented out",
			"<p><!-- {{.H}} --></p>",
			"<p></p>",
		},
		{
			"Comment ends flush with start",
			"<!--{{.}}--><script>/*{{.}}*///{{.}}\n</script><style>/*{{.}}*///{{.}}\n</style><a onclick='/*{{.}}*///{{.}}' style='/*{{.}}*///{{.}}'>",
			"<script> \n</script><style> \n</style><a onclick='/**///' style='/**///'>",
		},
		{
			"typed HTML in text",
			`{{.W}}`,
			`&iexcl;<b class="foo">Hello</b>, <textarea>O'World</textarea>!`,
		},
		{
			"typed HTML in attribute",
			`<div title="{{.W}}">`,
			`<div title="&iexcl;Hello, O&#39;World!">`,
		},
		{
			"typed HTML in script",
			`<button onclick="alert({{.W}})">`,
			`<button onclick="alert(&#34;\u0026iexcl;\u003cb class=\&#34;foo\&#34;\u003eHello\u003c/b\u003e, \u003ctextarea\u003eO&#39;World\u003c/textarea\u003e!&#34;)">`,
		},
		{
			"typed HTML in RCDATA",
			`<textarea>{{.W}}</textarea>`,
			`<textarea>&iexcl;&lt;b class=&#34;foo&#34;&gt;Hello&lt;/b&gt;, &lt;textarea&gt;O&#39;World&lt;/textarea&gt;!</textarea>`,
		},
		{
			"range in textarea",
			"<textarea>{{range .A}}{{.}}{{end}}</textarea>",
			"<textarea>&lt;a&gt;&lt;b&gt;</textarea>",
		},
		{
			"No tag injection",
			`{{"10$"}}<{{"script src,evil.org/pwnd.js"}}...`,
			`10$&lt;script src,evil.org/pwnd.js...`,
		},
		{
			"No comment injection",
			`<{{"!--"}}`,
			`&lt;!--`,
		},
		{
			"No RCDATA end tag injection",
			`<textarea><{{"/textarea "}}...</textarea>`,
			`<textarea>&lt;/textarea ...</textarea>`,
		},
		{
			"optional attrs",
			`<img class="{{"iconClass"}}"` +
				`{{if .T}} id="{{"<iconId>"}}"{{end}}` +
				// Double quotes inside if/else.
				` src=` +
				`{{if .T}}"?{{"<iconPath>"}}"` +
				`{{else}}"images/cleardot.gif"{{end}}` +
				// Missing space before title, but it is not a
				// part of the src attribute.
				`{{if .T}}title="{{"<title>"}}"{{end}}` +
				// Quotes outside if/else.
				` alt="` +
				`{{if .T}}{{"<alt>"}}` +
				`{{else}}{{if .F}}{{"<title>"}}{{end}}` +
				`{{end}}"` +
				`>`,
			`<img class="iconClass" id="&lt;iconId&gt;" src="?%3ciconPath%3e"title="&lt;title&gt;" alt="&lt;alt&gt;">`,
		},
		{
			"conditional valueless attr name",
			`<input{{if .T}} checked{{end}} name=n>`,
			`<input checked name=n>`,
		},
		{
			"conditional dynamic valueless attr name 1",
			`<input{{if .T}} {{"checked"}}{{end}} name=n>`,
			`<input checked name=n>`,
		},
		{
			"conditional dynamic valueless attr name 2",
			`<input {{if .T}}{{"checked"}} {{end}}name=n>`,
			`<input checked name=n>`,
		},
		{
			"dynamic attribute name",
			`<img on{{"load"}}="alert({{"loaded"}})">`,
			// Treated as JS since quotes are inserted.
			`<img onload="alert(&#34;loaded&#34;)">`,
		},
		{
			"bad dynamic attribute name 1",
			// Allow checked, selected, disabled, but not JS or
			// CSS attributes.
			`<input {{"onchange"}}="{{"doEvil()"}}">`,
			`<input ZgotmplZ="doEvil()">`,
		},
		{
			"bad dynamic attribute name 2",
			`<div {{"sTyle"}}="{{"color: expression(alert(1337))"}}">`,
			`<div ZgotmplZ="color: expression(alert(1337))">`,
		},
		{
			"bad dynamic attribute name 3",
			// Allow title or alt, but not a URL.
			`<img {{"src"}}="{{"javascript:doEvil()"}}">`,
			`<img ZgotmplZ="javascript:doEvil()">`,
		},
		{
			"bad dynamic attribute name 4",
			// Structure preservation requires values to associate
			// with a consistent attribute.
			`<input checked {{""}}="Whose value am I?">`,
			`<input checked ZgotmplZ="Whose value am I?">`,
		},
		{
			"dynamic element name",
			`<h{{3}}><table><t{{"head"}}>...</h{{3}}>`,
			`<h3><table><thead>...</h3>`,
		},
		{
			"bad dynamic element name",
			// Dynamic element names are typically used to switch
			// between (thead, tfoot, tbody), (ul, ol), (th, td),
			// and other replaceable sets.
			// We do not currently easily support (ul, ol).
			// If we do change to support that, this test should
			// catch failures to filter out special tag names which
			// would violate the structure preservation property --
			// if any special tag name could be substituted, then
			// the content could be raw text/RCDATA for some inputs
			// and regular HTML content for others.
			`<{{"script"}}>{{"doEvil()"}}</{{"script"}}>`,
			`&lt;script>doEvil()&lt;/script>`,
		},
		{
			"srcset bad URL in second position",
			`<img srcset="{{"/not-an-image#,javascript:alert(1)"}}">`,
			// The second URL is also filtered.
			`<img srcset="/not-an-image#,#ZgotmplZ">`,
		},
		{
			"srcset buffer growth",
			`<img srcset={{",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,"}}>`,
			`<img srcset=,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,>`,
		},
		{
			"unquoted empty attribute value (plaintext)",
			"<p name={{.U}}>",
			"<p name=ZgotmplZ>",
		},
		{
			"unquoted empty attribute value (url)",
			"<p href={{.U}}>",
			"<p href=ZgotmplZ>",
		},
		{
			"quoted empty attribute value",
			"<p name=\"{{.U}}\">",
			"<p name=\"\">",
		},
		{
			"JS template lit special characters",
			"<script>var a = `{{.I}}`</script>",
			"<script>var a = `\\u0024\\u007b asd \\u0060\\u0060 \\u007d`</script>",
		},
		{
			"JS template lit special characters, nested lit",
			"<script>var a = `${ `{{.I}}` }`</script>",
			"<script>var a = `${ `\\u0024\\u007b asd \\u0060\\u0060 \\u007d` }`</script>",
		},
		{
			"JS template lit, nested JS",
			"<script>var a = `${ var a = \"{{\"a \\\" d\"}}\" }`</script>",
			"<script>var a = `${ var a = \"a \\u0022 d\" }`</script>",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tmpl := New(test.name)
			tmpl = Must(tmpl.Parse(test.input))
			// Check for bug 6459: Tree field was not set in Parse.
			if tmpl.Tree != tmpl.text.Tree {
				t.Fatalf("%s: tree not set properly", test.name)
			}
			b := new(strings.Builder)
			if err := tmpl.Execute(b, data); err != nil {
				t.Fatalf("%s: template execution failed: %s", test.name, err)
			}
			if w, g := test.output, b.String(); w != g {
				t.Fatalf("%s: escaped output: want\n\t%q\ngot\n\t%q", test.name, w, g)
			}
			b.Reset()
			if err := tmpl.Execute(b, pdata); err != nil {
				t.Fatalf("%s: template execution failed for pointer: %s", test.name, err)
			}
			if w, g := test.output, b.String(); w != g {
				t.Fatalf("%s: escaped output for pointer: want\n\t%q\ngot\n\t%q", test.name, w, g)
			}
			if tmpl.Tree != tmpl.text.Tree {
				t.Fatalf("%s: tree mismatch", test.name)
			}
		})
	}
}

func TestEscapeMap(t *testing.T) {
	data := map[string]string{
		"html":     `<h1>Hi!</h1>`,
		"urlquery": `http://www.foo.com/index.html?title=main`,
	}
	for _, test := range [...]struct {
		desc, input, output string
	}{
		// covering issue 20323
		{
			"field with predefined escaper name 1",
			`{{.html | print}}`,
			`&lt;h1&gt;Hi!&lt;/h1&gt;`,
		},
		// covering issue 20323
		{
			"field with predefined escaper name 2",
			`{{.urlquery | print}}`,
			`http://www.foo.com/index.html?title=main`,
		},
	} {
		tmpl := Must(New("").Parse(test.input))
		b := new(strings.Builder)
		if err := tmpl.Execute(b, data); err != nil {
			t.Errorf("%s: template execution failed: %s", test.desc, err)
			continue
		}
		if w, g := test.output, b.String(); w != g {
			t.Errorf("%s: escaped output: want\n\t%q\ngot\n\t%q", test.desc, w, g)
			continue
		}
	}
}

func TestEscapeSet(t *testing.T) {
	type dataItem struct {
		Children []*dataItem
		X        string
	}

	data := dataItem{
		Children: []*dataItem{
			{X: "foo"},
			{X: "<bar>"},
			{
				Children: []*dataItem{
					{X: "baz"},
				},
			},
		},
	}

	tests := []struct {
		inputs map[string]string
		want   string
	}{
		// The trivial set.
		{
			map[string]string{
				"main": ``,
			},
			``,
		},
		// A template called in the start context.
		{
			map[string]string{
				"main": `Hello, {{template "helper"}}!`,
				// Not a valid top level HTML template.
				// "<b" is not a full tag.
				"helper": `{{"<World>"}}`,
			},
			`Hello, &lt;World&gt;!`,
		},
		// A template called in a context other than the start.
		{
			map[string]string{
				"main": `<a onclick='a = {{template "helper"}};'>`,
				// Not a valid top level HTML template.
				// "<b" is not a full tag.
				"helper": `{{"<a>"}}<b`,
			},
			`<a onclick='a = &#34;\u003ca\u003e&#34;<b;'>`,
		},
		// A recursive template that ends in its start context.
		{
			map[string]string{
				"main": `{{range .Children}}{{template "main" .}}{{else}}{{.X}} {{end}}`,
			},
			`foo &lt;bar&gt; baz `,
		},
		// A recursive helper template that ends in its start context.
		{
			map[string]string{
				"main":   `{{template "helper" .}}`,
				"helper": `{{if .Children}}<ul>{{range .Children}}<li>{{template "main" .}}</li>{{end}}</ul>{{else}}{{.X}}{{end}}`,
			},
			`<ul><li>foo</li><li>&lt;bar&gt;</li><li><ul><li>baz</li></ul></li></ul>`,
		},
		// Co-recursive templates that end in its start context.
		{
			map[string]string{
				"main":   `<blockquote>{{range .Children}}{{template "helper" .}}{{end}}</blockquote>`,
				"helper": `{{if .Children}}{{template "main" .}}{{else}}{{.X}}<br>{{end}}`,
			},
			`<blockquote>foo<br>&lt;bar&gt;<br><blockquote>baz<br></blockquote></blockquote>`,
		},
		// A template that is called in two different contexts.
		{
			map[string]string{
				"main":   `<button onclick="title='{{template "helper"}}'; ...">{{template "helper"}}</button>`,
				"helper": `{{11}} of {{"<100>"}}`,
			},
			`<button onclick="title='11 of \u003c100\u003e'; ...">11 of &lt;100&gt;</button>`,
		},
		// A non-recursive template that ends in a different context.
		// helper starts in jsCtxRegexp and ends in jsCtxDivOp.
		{
			map[string]string{
				"main":   `<script>var x={{template "helper"}}/{{"42"}};</script>`,
				"helper": "{{126}}",
			},
			`<script>var x= 126 /"42";</script>`,
		},
		// A recursive template that ends in a similar context.
		{
			map[string]string{
				"main":      `<script>var x=[{{template "countdown" 4}}];</script>`,
				"countdown": `{{.}}{{if .}},{{template "countdown" . | pred}}{{end}}`,
			},
			`<script>var x=[ 4 , 3 , 2 , 1 , 0 ];</script>`,
		},
		// A recursive template that ends in a different context.
		/*
			{
				map[string]string{
					"main":   `<a href="/foo{{template "helper" .}}">`,
					"helper": `{{if .Children}}{{range .Children}}{{template "helper" .}}{{end}}{{else}}?x={{.X}}{{end}}`,
				},
				`<a href="/foo?x=foo?x=%3cbar%3e?x=baz">`,
			},
		*/
	}

	// pred is a template function that returns the predecessor of a
	// natural number for testing recursive templates.
	fns := FuncMap{"pred": func(a ...any) (any, error) {
		if len(a) == 1 {
			if i, _ := a[0].(int); i > 0 {
				return i - 1, nil
			}
		}
		return nil, fmt.Errorf("undefined pred(%v)", a)
	}}

	for _, test := range tests {
		source := ""
		for name, body := range test.inputs {
			source += fmt.Sprintf("{{define %q}}%s{{end}} ", name, body)
		}
		tmpl, err := New("root").Funcs(fns).Parse(source)
		if err != nil {
			t.Errorf("error parsing %q: %v", source, err)
			continue
		}
		var b strings.Builder

		if err := tmpl.ExecuteTemplate(&b, "main", data); err != nil {
			t.Errorf("%q executing %v", err.Error(), tmpl.Lookup("main"))
			continue
		}
		if got := b.String(); test.want != got {
			t.Errorf("want\n\t%q\ngot\n\t%q", test.want, got)
		}
	}

}

func TestErrors(t *testing.T) {
	tests := []struct {
		input string
		err   string
	}{
		// Non-error cases.
		{
			"{{if .Cond}}<a>{{else}}<b>{{end}}",
			"",
		},
		{
			"{{if .Cond}}<a>{{end}}",
			"",
		},
		{
			"{{if .Cond}}{{else}}<b>{{end}}",
			"",
		},
		{
			"{{with .Cond}}<div>{{end}}",
			"",
		},
		{
			"{{range .Items}}<a>{{end}}",
			"",
		},
		{
			"<a href='/foo?{{range .Items}}&{{.K}}={{.V}}{{end}}'>",
			"",
		},
		{
			"{{range .Items}}<a{{if .X}}{{end}}>{{end}}",
			"",
		},
		{
			"{{range .Items}}<a{{if .X}}{{end}}>{{continue}}{{end}}",
			"",
		},
		{
			"{{range .Items}}<a{{if .X}}{{end}}>{{break}}{{end}}",
			"",
		},
		{
			"{{range .Items}}<a{{if .X}}{{end}}>{{if .X}}{{break}}{{end}}{{end}}",
			"",
		},
		{
			"<script>var a = `${a+b}`</script>`",
			"",
		},
		{
			"<script>var tmpl = `asd`;</script>",
			``,
		},
		{
			"<script>var tmpl = `${1}`;</script>",
			``,
		},
		{
			"<script>var tmpl = `${return ``}`;</script>",
			``,
		},
		{
			"<script>var tmpl = `${return {{.}} }`;</script>",
			``,
		},
		{
			"<script>var tmpl = `${ let a = {1:1} {{.}} }`;</script>",
			``,
		},
		{
			"<script>var tmpl = `asd ${return \"{\"}`;</script>",
			``,
		},

		// Error cases.
		{
			"{{if .Cond}}<a{{end}}",
			"z:1:5: {{if}} branches",
		},
		{
			"{{if .Cond}}\n{{else}}\n<a{{end}}",
			"z:1:5: {{if}} branches",
		},
		{
			// Missing quote in the else branch.
			`{{if .Cond}}<a href="foo">{{else}}<a href="bar>{{end}}`,
			"z:1:5: {{if}} branches",
		},
		{
			// Different kind of attribute: href implies a URL.
			"<a {{if .Cond}}href='{{else}}title='{{end}}{{.X}}'>",
			"z:1:8: {{if}} branches",
		},
		{
			"\n{{with .X}}<a{{end}}",
			"z:2:7: {{with}} branches",
		},
		{
			"\n{{with .X}}<a>{{else}}<a{{end}}",
			"z:2:7: {{with}} branches",
		},
		{
			"{{range .Items}}<a{{end}}",
			`z:1: on range loop re-entry: "<" in attribute name: "<a"`,
		},
		{
			"\n{{range .Items}} x='<a{{end}}",
			"z:2:8: on range loop re-entry: {{range}} branches",
		},
		{
			"{{range .Items}}<a{{if .X}}{{break}}{{end}}>{{end}}",
			"z:1:29: at range loop break: {{range}} branches end in different contexts",
		},
		{
			"{{range .Items}}<a{{if .X}}{{continue}}{{end}}>{{end}}",
			"z:1:29: at range loop continue: {{range}} branches end in different contexts",
		},
		{
			"{{range .Items}}{{if .X}}{{break}}{{end}}<a{{if .Y}}{{continue}}{{end}}>{{if .Z}}{{continue}}{{end}}{{end}}",
			"z:1:54: at range loop continue: {{range}} branches end in different contexts",
		},
		{
			"<a b=1 c={{.H}}",
			"z: ends in a non-text context: {stateAttr delimSpaceOrTagEnd",
		},
		{
			"<script>foo();",
			"z: ends in a non-text context: {stateJS",
		},
		{
			`<a href="{{if .F}}/foo?a={{else}}/bar/{{end}}{{.H}}">`,
			"z:1:47: {{.H}} appears in an ambiguous context within a URL",
		},
		{
			`<a onclick="alert('Hello \`,
			`unfinished escape sequence in JS string: "Hello \\"`,
		},
		{
			`<a onclick='alert("Hello\, World\`,
			`unfinished escape sequence in JS string: "Hello\\, World\\"`,
		},
		{
			`<a onclick='alert(/x+\`,
			`unfinished escape sequence in JS string: "x+\\"`,
		},
		{
			`<a onclick="/foo[\]/`,
			`unfinished JS regexp charset: "foo[\\]/"`,
		},
		{
			// It is ambiguous whether 1.5 should be 1\.5 or 1.5.
			// Either `var x = 1/- 1.5 /i.test(x)`
			// where `i.test(x)` is a method call of reference i,
			// or `/-1\.5/i.test(x)` which is a method call on a
			// case insensitive regular expression.
			`<script>{{if false}}var x = 1{{end}}/-{{"1.5"}}/i.test(x)</script>`,
			`'/' could start a division or regexp: "/-"`,
		},
		{
			`{{template "foo"}}`,
			"z:1:11: no such template \"foo\"",
		},
		{
			`<div{{template "y"}}>` +
				// Illegal starting in stateTag but not in stateText.
				`{{define "y"}} foo<b{{end}}`,
			`"<" in attribute name: " foo<b"`,
		},
		{
			`<script>reverseList = [{{template "t"}}]</script>` +
				// Missing " after recursive call.
				`{{define "t"}}{{if .Tail}}{{template "t" .Tail}}{{end}}{{.Head}}",{{end}}`,
			`: cannot compute output context for template t$htmltemplate_stateJS_elementScript`,
		},
		{
			`<input type=button value=onclick=>`,
			`html/template:z: "=" in unquoted attr: "onclick="`,
		},
		{
			`<input type=button value= onclick=>`,
			`html/template:z: "=" in unquoted attr: "onclick="`,
		},
		{
			`<input type=button value= 1+1=2>`,
			`html/template:z: "=" in unquoted attr: "1+1=2"`,
		},
		{
			"<a class=`foo>",
			"html/template:z: \"`\" in unquoted attr: \"`foo\"",
		},
		{
			`<a style=font:'Arial'>`,
			`html/template:z: "'" in unquoted attr: "font:'Arial'"`,
		},
		{
			`<a=foo>`,
			`: expected space, attr name, or end of tag, but got "=foo>"`,
		},
		{
			`Hello, {{. | urlquery | print}}!`,
			// urlquery is disallowed if it is not the last command in the pipeline.
			`predefined escaper "urlquery" disallowed in template`,
		},
		{
			`Hello, {{. | html | print}}!`,
			// html is disallowed if it is not the last command in the pipeline.
			`predefined escaper "html" disallowed in template`,
		},
		{
			`Hello, {{html . | print}}!`,
			// A direct call to html is disallowed if it is not the last command in the pipeline.
			`predefined escaper "html" disallowed in template`,
		},
		{
			`<div class={{. | html}}>Hello<div>`,
			// html is disallowed in a pipeline that is in an unquoted attribute context,
			// even if it is the last command in the pipeline.
			`predefined escaper "html" disallowed in template`,
		},
		{
			`Hello, {{. | urlquery | html}}!`,
			// html is allowed since it is the last command in the pipeline, but urlquery is not.
			`predefined escaper "urlquery" disallowed in template`,
		},
	}
	for _, test := range tests {
		buf := new(bytes.Buffer)
		tmpl, err := New("z").Parse(test.input)
		if err != nil {
			t.Errorf("input=%q: unexpected parse error %s\n", test.input, err)
			continue
		}
		err = tmpl.Execute(buf, nil)
		var got string
		if err != nil {
			got = err.Error()
		}
		if test.err == "" {
			if got != "" {
				t.Errorf("input=%q: unexpected error %q", test.input, got)
			}
			continue
		}
		if !strings.Contains(got, test.err) {
			t.Errorf("input=%q: error\n\t%q\ndoes not contain expected string\n\t%q", test.input, got, test.err)
			continue
		}
		// Check that we get the same error if we call Execute again.
		if err := tmpl.Execute(buf, nil); err == nil || err.Error() != got {
			t.Errorf("input=%q: unexpected error on second call %q", test.input, err)

		}
	}
}

func TestEscapeText(t *testing.T) {
	tests := []struct {
		input  string
		output context
	}{
		{
			``,
			context{},
		},
		{
			`Hello, World!`,
			context{},
		},
		{
			// An orphaned "<" is OK.
			`I <3 Ponies!`,
			context{},
		},
		{
			`<a`,
			context{state: stateTag},
		},
		{
			`<a `,
			context{state: stateTag},
		},
		{
			`<a>`,
			context{state: stateText},
		},
		{
			`<a href`,
			context{state: 
"""




```