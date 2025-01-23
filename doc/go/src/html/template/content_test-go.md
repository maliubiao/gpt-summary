Response:
Let's break down the thought process for analyzing the provided Go code snippet `content_test.go`.

**1. Initial Understanding of the Goal:**

The file name `content_test.go` strongly suggests this code is for testing something related to "content" within the `html/template` package. Specifically, the test function names like `TestTypedContent` and the presence of types like `CSS`, `HTML`, `JS`, `URL` etc., point towards testing how different content types are handled during template execution.

**2. Analyzing `TestTypedContent`:**

* **Data Structures:** The code starts by defining `data`, a slice of `any`. This slice contains various string-like values, but importantly, some are wrapped in custom types like `CSS`, `HTML`, `JS`, etc. This immediately signals that the test is about how the template engine treats these different typed values.

* **`tests` Slice:** The `tests` slice of structs is the core of this test function. Each struct has an `input` string (a template) and a `want` slice of strings (the expected output). The template always contains `{{.}}`, indicating the test is focused on how the *single* input value is rendered within different template contexts.

* **Template Contexts:** The `input` strings in `tests` represent different HTML contexts where the data might be inserted (e.g., `<style>`, `<div style="...">`, plain text, `<a title="...">`, `<script>`, `<a href="...">`, `<img srcset="...">`). The variety of contexts suggests the test is verifying context-aware escaping.

* **Expected Outputs:** The `want` slice in each test case contains the expected output for each data point when inserted into the corresponding template context. Observing these expected outputs reveals the escaping/sanitization behavior for different content types in different contexts. For example:
    * In `<style>`, raw CSS is allowed.
    * In `<div style="...">`, CSS is HTML-escaped.
    * In plain text, HTML entities are escaped.
    * In `<script>`, JavaScript escaping is applied.
    * In `<a href="...">`, URL escaping is applied.
    * The presence of `ZgotmplZ` suggests a deliberate "safe" or default output when a type isn't appropriate for the context.

* **Looping and Execution:** The code iterates through the `tests`, parses the template, and then iterates through the `data`, executing the template with each data point. It compares the actual output with the expected output.

**3. Inferring the Go Feature:**

Based on the analysis of `TestTypedContent`, it becomes clear that this code is testing the **context-aware escaping** feature of Go's `html/template` package. The custom types (`CSS`, `HTML`, `JS`, etc.) are used to signal the *intended* content type, allowing the template engine to apply the appropriate escaping rules based on where the value is being inserted in the HTML. This is a security feature to prevent cross-site scripting (XSS) vulnerabilities.

**4. Developing the Go Code Example:**

To demonstrate the feature, we need a simple template and examples of the different content types. The example should show how the output changes based on the context. The provided example in the initial prompt is a good starting point.

**5. Analyzing `TestStringer`:**

This test is simpler. It tests how the template engine handles types that implement the `String()` and `Error()` interfaces. The output confirms that `String()` is used for general string representation, while `Error()` is also used, indicating it's treated similarly. This implies that if a value has a `String()` method, it will be called for rendering in the template.

**6. Analyzing `TestEscapingNilNonemptyInterfaces`:**

This test addresses a specific edge case related to nil interfaces. It checks if a nil value of a non-empty interface type (like `error`) is handled correctly and produces the same output as a nil value of an empty interface type (`any`). This is important for consistency and avoiding unexpected behavior.

**7. Identifying Potential Pitfalls:**

Based on the tests, a key pitfall is **incorrectly assuming automatic escaping**. Developers might forget to use the specific content types (like `HTML`, `JS`, `URL`) or might place data in a context where the default escaping is insufficient or incorrect. The `ZgotmplZ` output is a clear indicator of a potential mismatch.

**8. Command-Line Arguments:**

The provided code does not directly process command-line arguments. It's a unit test file. Command-line arguments for Go tests are handled by the `go test` command and its flags (e.g., `-v` for verbose output, `-run` to specify tests to run).

**Self-Correction/Refinement During the Process:**

* Initially, I might have just thought it was about HTML escaping. However, the presence of `CSS`, `JS`, `URL`, and `Srcset` types quickly expanded the scope to context-aware escaping.
*  Seeing `ZgotmplZ` required understanding its significance. It's a placeholder indicating a type mismatch or a context where the provided type isn't inherently safe.
*  Realizing the core concept is "context" prompted thinking about different HTML tags and attributes.
* The `TestStringer` and `TestEscapingNilNonemptyInterfaces` tests provided additional insights into how the template engine handles different Go types and edge cases.

By following this step-by-step analysis, focusing on the code's structure, data, and expected behavior, we can effectively understand the purpose and functionality of the `content_test.go` file.
这个`content_test.go` 文件是 Go 语言 `html/template` 标准库的一部分，它的主要功能是**测试模板引擎在处理不同类型的安全内容时的行为，特别是针对跨站脚本攻击（XSS）的防御机制。**

更具体地说，它测试了模板引擎如何根据上下文正确地转义或不转义不同类型的数据，以确保输出的 HTML 是安全的。

**以下是它的主要功能点：**

1. **测试不同类型的安全内容类型:**  该文件测试了 `html/template` 包中定义的几种安全内容类型，例如 `HTML`、`CSS`、`JS`、`URL`、`HTMLAttr` 和 `Srcset`。这些类型本质上是字符串的包装器，它们向模板引擎表明了字符串的预期用途，从而指导引擎进行适当的转义。

2. **测试上下文相关的转义:**  模板引擎会根据内容被插入的 HTML 上下文（例如，在 `<style>` 标签内，在 `href` 属性中，在 `<script>` 标签内等）应用不同的转义规则。此文件通过一系列测试用例来验证这种上下文相关的转义是否正确。

3. **验证预期的输出:**  每个测试用例都定义了一个包含 `{{.}}` 的模板字符串，以及一个期望的输出字符串。`{{.}}` 是模板语法，表示将传入的数据插入到这里。测试会用不同类型的安全内容数据执行模板，并将实际输出与期望输出进行比较，以确保转义逻辑正确。

**推理 `html/template` 的安全内容处理功能并用 Go 代码举例说明:**

`html/template` 包的核心功能之一就是提供了一种安全的方式来生成 HTML，防止 XSS 攻击。它通过引入预定义的“安全上下文”类型来实现这一点。当你将一个字符串包装成这些类型之一时，你实际上是在告诉模板引擎这个字符串已经包含了特定类型的安全内容，或者应该被视为这种类型的安全内容。

**Go 代码示例:**

```go

### 提示词
```
这是路径为go/src/html/template/content_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package template

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestTypedContent(t *testing.T) {
	data := []any{
		`<b> "foo%" O'Reilly &bar;`,
		CSS(`a[href =~ "//example.com"]#foo`),
		HTML(`Hello, <b>World</b> &amp;tc!`),
		HTMLAttr(` dir="ltr"`),
		JS(`c && alert("Hello, World!");`),
		JSStr(`Hello, World & O'Reilly\u0021`),
		URL(`greeting=H%69,&addressee=(World)`),
		Srcset(`greeting=H%69,&addressee=(World) 2x, https://golang.org/favicon.ico 500.5w`),
		URL(`,foo/,`),
	}

	// For each content sensitive escaper, see how it does on
	// each of the typed strings above.
	tests := []struct {
		// A template containing a single {{.}}.
		input string
		want  []string
	}{
		{
			`<style>{{.}} { color: blue }</style>`,
			[]string{
				`ZgotmplZ`,
				// Allowed but not escaped.
				`a[href =~ "//example.com"]#foo`,
				`ZgotmplZ`,
				`ZgotmplZ`,
				`ZgotmplZ`,
				`ZgotmplZ`,
				`ZgotmplZ`,
				`ZgotmplZ`,
				`ZgotmplZ`,
			},
		},
		{
			`<div style="{{.}}">`,
			[]string{
				`ZgotmplZ`,
				// Allowed and HTML escaped.
				`a[href =~ &#34;//example.com&#34;]#foo`,
				`ZgotmplZ`,
				`ZgotmplZ`,
				`ZgotmplZ`,
				`ZgotmplZ`,
				`ZgotmplZ`,
				`ZgotmplZ`,
				`ZgotmplZ`,
			},
		},
		{
			`{{.}}`,
			[]string{
				`&lt;b&gt; &#34;foo%&#34; O&#39;Reilly &amp;bar;`,
				`a[href =~ &#34;//example.com&#34;]#foo`,
				// Not escaped.
				`Hello, <b>World</b> &amp;tc!`,
				` dir=&#34;ltr&#34;`,
				`c &amp;&amp; alert(&#34;Hello, World!&#34;);`,
				`Hello, World &amp; O&#39;Reilly\u0021`,
				`greeting=H%69,&amp;addressee=(World)`,
				`greeting=H%69,&amp;addressee=(World) 2x, https://golang.org/favicon.ico 500.5w`,
				`,foo/,`,
			},
		},
		{
			`<a{{.}}>`,
			[]string{
				`ZgotmplZ`,
				`ZgotmplZ`,
				`ZgotmplZ`,
				// Allowed and HTML escaped.
				` dir="ltr"`,
				`ZgotmplZ`,
				`ZgotmplZ`,
				`ZgotmplZ`,
				`ZgotmplZ`,
				`ZgotmplZ`,
			},
		},
		{
			`<a title={{.}}>`,
			[]string{
				`&lt;b&gt;&#32;&#34;foo%&#34;&#32;O&#39;Reilly&#32;&amp;bar;`,
				`a[href&#32;&#61;~&#32;&#34;//example.com&#34;]#foo`,
				// Tags stripped, spaces escaped, entity not re-escaped.
				`Hello,&#32;World&#32;&amp;tc!`,
				`&#32;dir&#61;&#34;ltr&#34;`,
				`c&#32;&amp;&amp;&#32;alert(&#34;Hello,&#32;World!&#34;);`,
				`Hello,&#32;World&#32;&amp;&#32;O&#39;Reilly\u0021`,
				`greeting&#61;H%69,&amp;addressee&#61;(World)`,
				`greeting&#61;H%69,&amp;addressee&#61;(World)&#32;2x,&#32;https://golang.org/favicon.ico&#32;500.5w`,
				`,foo/,`,
			},
		},
		{
			`<a title='{{.}}'>`,
			[]string{
				`&lt;b&gt; &#34;foo%&#34; O&#39;Reilly &amp;bar;`,
				`a[href =~ &#34;//example.com&#34;]#foo`,
				// Tags stripped, entity not re-escaped.
				`Hello, World &amp;tc!`,
				` dir=&#34;ltr&#34;`,
				`c &amp;&amp; alert(&#34;Hello, World!&#34;);`,
				`Hello, World &amp; O&#39;Reilly\u0021`,
				`greeting=H%69,&amp;addressee=(World)`,
				`greeting=H%69,&amp;addressee=(World) 2x, https://golang.org/favicon.ico 500.5w`,
				`,foo/,`,
			},
		},
		{
			`<textarea>{{.}}</textarea>`,
			[]string{
				`&lt;b&gt; &#34;foo%&#34; O&#39;Reilly &amp;bar;`,
				`a[href =~ &#34;//example.com&#34;]#foo`,
				// Angle brackets escaped to prevent injection of close tags, entity not re-escaped.
				`Hello, &lt;b&gt;World&lt;/b&gt; &amp;tc!`,
				` dir=&#34;ltr&#34;`,
				`c &amp;&amp; alert(&#34;Hello, World!&#34;);`,
				`Hello, World &amp; O&#39;Reilly\u0021`,
				`greeting=H%69,&amp;addressee=(World)`,
				`greeting=H%69,&amp;addressee=(World) 2x, https://golang.org/favicon.ico 500.5w`,
				`,foo/,`,
			},
		},
		{
			`<script>alert({{.}})</script>`,
			[]string{
				`"\u003cb\u003e \"foo%\" O'Reilly \u0026bar;"`,
				`"a[href =~ \"//example.com\"]#foo"`,
				`"Hello, \u003cb\u003eWorld\u003c/b\u003e \u0026amp;tc!"`,
				`" dir=\"ltr\""`,
				// Not escaped.
				`c && alert("Hello, World!");`,
				// Escape sequence not over-escaped.
				`"Hello, World & O'Reilly\u0021"`,
				`"greeting=H%69,\u0026addressee=(World)"`,
				`"greeting=H%69,\u0026addressee=(World) 2x, https://golang.org/favicon.ico 500.5w"`,
				`",foo/,"`,
			},
		},
		{
			`<button onclick="alert({{.}})">`,
			[]string{
				`&#34;\u003cb\u003e \&#34;foo%\&#34; O&#39;Reilly \u0026bar;&#34;`,
				`&#34;a[href =~ \&#34;//example.com\&#34;]#foo&#34;`,
				`&#34;Hello, \u003cb\u003eWorld\u003c/b\u003e \u0026amp;tc!&#34;`,
				`&#34; dir=\&#34;ltr\&#34;&#34;`,
				// Not JS escaped but HTML escaped.
				`c &amp;&amp; alert(&#34;Hello, World!&#34;);`,
				// Escape sequence not over-escaped.
				`&#34;Hello, World &amp; O&#39;Reilly\u0021&#34;`,
				`&#34;greeting=H%69,\u0026addressee=(World)&#34;`,
				`&#34;greeting=H%69,\u0026addressee=(World) 2x, https://golang.org/favicon.ico 500.5w&#34;`,
				`&#34;,foo/,&#34;`,
			},
		},
		{
			`<script>alert("{{.}}")</script>`,
			[]string{
				`\u003cb\u003e \u0022foo%\u0022 O\u0027Reilly \u0026bar;`,
				`a[href =~ \u0022\/\/example.com\u0022]#foo`,
				`Hello, \u003cb\u003eWorld\u003c\/b\u003e \u0026amp;tc!`,
				` dir=\u0022ltr\u0022`,
				`c \u0026\u0026 alert(\u0022Hello, World!\u0022);`,
				// Escape sequence not over-escaped.
				`Hello, World \u0026 O\u0027Reilly\u0021`,
				`greeting=H%69,\u0026addressee=(World)`,
				`greeting=H%69,\u0026addressee=(World) 2x, https:\/\/golang.org\/favicon.ico 500.5w`,
				`,foo\/,`,
			},
		},
		{
			`<script type="text/javascript">alert("{{.}}")</script>`,
			[]string{
				`\u003cb\u003e \u0022foo%\u0022 O\u0027Reilly \u0026bar;`,
				`a[href =~ \u0022\/\/example.com\u0022]#foo`,
				`Hello, \u003cb\u003eWorld\u003c\/b\u003e \u0026amp;tc!`,
				` dir=\u0022ltr\u0022`,
				`c \u0026\u0026 alert(\u0022Hello, World!\u0022);`,
				// Escape sequence not over-escaped.
				`Hello, World \u0026 O\u0027Reilly\u0021`,
				`greeting=H%69,\u0026addressee=(World)`,
				`greeting=H%69,\u0026addressee=(World) 2x, https:\/\/golang.org\/favicon.ico 500.5w`,
				`,foo\/,`,
			},
		},
		{
			`<script type="text/javascript">alert({{.}})</script>`,
			[]string{
				`"\u003cb\u003e \"foo%\" O'Reilly \u0026bar;"`,
				`"a[href =~ \"//example.com\"]#foo"`,
				`"Hello, \u003cb\u003eWorld\u003c/b\u003e \u0026amp;tc!"`,
				`" dir=\"ltr\""`,
				// Not escaped.
				`c && alert("Hello, World!");`,
				// Escape sequence not over-escaped.
				`"Hello, World & O'Reilly\u0021"`,
				`"greeting=H%69,\u0026addressee=(World)"`,
				`"greeting=H%69,\u0026addressee=(World) 2x, https://golang.org/favicon.ico 500.5w"`,
				`",foo/,"`,
			},
		},
		{
			// Not treated as JS. The output is same as for <div>{{.}}</div>
			`<script type="text/template">{{.}}</script>`,
			[]string{
				`&lt;b&gt; &#34;foo%&#34; O&#39;Reilly &amp;bar;`,
				`a[href =~ &#34;//example.com&#34;]#foo`,
				// Not escaped.
				`Hello, <b>World</b> &amp;tc!`,
				` dir=&#34;ltr&#34;`,
				`c &amp;&amp; alert(&#34;Hello, World!&#34;);`,
				`Hello, World &amp; O&#39;Reilly\u0021`,
				`greeting=H%69,&amp;addressee=(World)`,
				`greeting=H%69,&amp;addressee=(World) 2x, https://golang.org/favicon.ico 500.5w`,
				`,foo/,`,
			},
		},
		{
			`<button onclick='alert("{{.}}")'>`,
			[]string{
				`\u003cb\u003e \u0022foo%\u0022 O\u0027Reilly \u0026bar;`,
				`a[href =~ \u0022\/\/example.com\u0022]#foo`,
				`Hello, \u003cb\u003eWorld\u003c\/b\u003e \u0026amp;tc!`,
				` dir=\u0022ltr\u0022`,
				`c \u0026\u0026 alert(\u0022Hello, World!\u0022);`,
				// Escape sequence not over-escaped.
				`Hello, World \u0026 O\u0027Reilly\u0021`,
				`greeting=H%69,\u0026addressee=(World)`,
				`greeting=H%69,\u0026addressee=(World) 2x, https:\/\/golang.org\/favicon.ico 500.5w`,
				`,foo\/,`,
			},
		},
		{
			`<a href="?q={{.}}">`,
			[]string{
				`%3cb%3e%20%22foo%25%22%20O%27Reilly%20%26bar%3b`,
				`a%5bhref%20%3d~%20%22%2f%2fexample.com%22%5d%23foo`,
				`Hello%2c%20%3cb%3eWorld%3c%2fb%3e%20%26amp%3btc%21`,
				`%20dir%3d%22ltr%22`,
				`c%20%26%26%20alert%28%22Hello%2c%20World%21%22%29%3b`,
				`Hello%2c%20World%20%26%20O%27Reilly%5cu0021`,
				// Quotes and parens are escaped but %69 is not over-escaped. HTML escaping is done.
				`greeting=H%69,&amp;addressee=%28World%29`,
				`greeting%3dH%2569%2c%26addressee%3d%28World%29%202x%2c%20https%3a%2f%2fgolang.org%2ffavicon.ico%20500.5w`,
				`,foo/,`,
			},
		},
		{
			`<style>body { background: url('?img={{.}}') }</style>`,
			[]string{
				`%3cb%3e%20%22foo%25%22%20O%27Reilly%20%26bar%3b`,
				`a%5bhref%20%3d~%20%22%2f%2fexample.com%22%5d%23foo`,
				`Hello%2c%20%3cb%3eWorld%3c%2fb%3e%20%26amp%3btc%21`,
				`%20dir%3d%22ltr%22`,
				`c%20%26%26%20alert%28%22Hello%2c%20World%21%22%29%3b`,
				`Hello%2c%20World%20%26%20O%27Reilly%5cu0021`,
				// Quotes and parens are escaped but %69 is not over-escaped. HTML escaping is not done.
				`greeting=H%69,&addressee=%28World%29`,
				`greeting%3dH%2569%2c%26addressee%3d%28World%29%202x%2c%20https%3a%2f%2fgolang.org%2ffavicon.ico%20500.5w`,
				`,foo/,`,
			},
		},
		{
			`<img srcset="{{.}}">`,
			[]string{
				`#ZgotmplZ`,
				`#ZgotmplZ`,
				// Commas are not escaped.
				`Hello,#ZgotmplZ`,
				// Leading spaces are not percent escapes.
				` dir=%22ltr%22`,
				// Spaces after commas are not percent escaped.
				`#ZgotmplZ, World!%22%29;`,
				`Hello,#ZgotmplZ`,
				`greeting=H%69%2c&amp;addressee=%28World%29`,
				// Metadata is not escaped.
				`greeting=H%69,&amp;addressee=(World) 2x, https://golang.org/favicon.ico 500.5w`,
				`%2cfoo/%2c`,
			},
		},
		{
			`<img srcset={{.}}>`,
			[]string{
				`#ZgotmplZ`,
				`#ZgotmplZ`,
				`Hello,#ZgotmplZ`,
				// Spaces are HTML escaped not %-escaped
				`&#32;dir&#61;%22ltr%22`,
				`#ZgotmplZ,&#32;World!%22%29;`,
				`Hello,#ZgotmplZ`,
				`greeting&#61;H%69%2c&amp;addressee&#61;%28World%29`,
				`greeting&#61;H%69,&amp;addressee&#61;(World)&#32;2x,&#32;https://golang.org/favicon.ico&#32;500.5w`,
				// Commas are escaped.
				`%2cfoo/%2c`,
			},
		},
		{
			`<img srcset="{{.}} 2x, https://golang.org/ 500.5w">`,
			[]string{
				`#ZgotmplZ`,
				`#ZgotmplZ`,
				`Hello,#ZgotmplZ`,
				` dir=%22ltr%22`,
				`#ZgotmplZ, World!%22%29;`,
				`Hello,#ZgotmplZ`,
				`greeting=H%69%2c&amp;addressee=%28World%29`,
				`greeting=H%69,&amp;addressee=(World) 2x, https://golang.org/favicon.ico 500.5w`,
				`%2cfoo/%2c`,
			},
		},
		{
			`<img srcset="http://godoc.org/ {{.}}, https://golang.org/ 500.5w">`,
			[]string{
				`#ZgotmplZ`,
				`#ZgotmplZ`,
				`Hello,#ZgotmplZ`,
				` dir=%22ltr%22`,
				`#ZgotmplZ, World!%22%29;`,
				`Hello,#ZgotmplZ`,
				`greeting=H%69%2c&amp;addressee=%28World%29`,
				`greeting=H%69,&amp;addressee=(World) 2x, https://golang.org/favicon.ico 500.5w`,
				`%2cfoo/%2c`,
			},
		},
		{
			`<img srcset="http://godoc.org/?q={{.}} 2x, https://golang.org/ 500.5w">`,
			[]string{
				`#ZgotmplZ`,
				`#ZgotmplZ`,
				`Hello,#ZgotmplZ`,
				` dir=%22ltr%22`,
				`#ZgotmplZ, World!%22%29;`,
				`Hello,#ZgotmplZ`,
				`greeting=H%69%2c&amp;addressee=%28World%29`,
				`greeting=H%69,&amp;addressee=(World) 2x, https://golang.org/favicon.ico 500.5w`,
				`%2cfoo/%2c`,
			},
		},
		{
			`<img srcset="http://godoc.org/ 2x, {{.}} 500.5w">`,
			[]string{
				`#ZgotmplZ`,
				`#ZgotmplZ`,
				`Hello,#ZgotmplZ`,
				` dir=%22ltr%22`,
				`#ZgotmplZ, World!%22%29;`,
				`Hello,#ZgotmplZ`,
				`greeting=H%69%2c&amp;addressee=%28World%29`,
				`greeting=H%69,&amp;addressee=(World) 2x, https://golang.org/favicon.ico 500.5w`,
				`%2cfoo/%2c`,
			},
		},
		{
			`<img srcset="http://godoc.org/ 2x, https://golang.org/ {{.}}">`,
			[]string{
				`#ZgotmplZ`,
				`#ZgotmplZ`,
				`Hello,#ZgotmplZ`,
				` dir=%22ltr%22`,
				`#ZgotmplZ, World!%22%29;`,
				`Hello,#ZgotmplZ`,
				`greeting=H%69%2c&amp;addressee=%28World%29`,
				`greeting=H%69,&amp;addressee=(World) 2x, https://golang.org/favicon.ico 500.5w`,
				`%2cfoo/%2c`,
			},
		},
	}

	for _, test := range tests {
		tmpl := Must(New("x").Parse(test.input))
		pre := strings.Index(test.input, "{{.}}")
		post := len(test.input) - (pre + 5)
		var b strings.Builder
		for i, x := range data {
			b.Reset()
			if err := tmpl.Execute(&b, x); err != nil {
				t.Errorf("%q with %v: %s", test.input, x, err)
				continue
			}
			if want, got := test.want[i], b.String()[pre:b.Len()-post]; want != got {
				t.Errorf("%q with %v:\nwant\n\t%q,\ngot\n\t%q\n", test.input, x, want, got)
				continue
			}
		}
	}
}

// Test that we print using the String method. Was issue 3073.
type myStringer struct {
	v int
}

func (s *myStringer) String() string {
	return fmt.Sprintf("string=%d", s.v)
}

type errorer struct {
	v int
}

func (s *errorer) Error() string {
	return fmt.Sprintf("error=%d", s.v)
}

func TestStringer(t *testing.T) {
	s := &myStringer{3}
	b := new(strings.Builder)
	tmpl := Must(New("x").Parse("{{.}}"))
	if err := tmpl.Execute(b, s); err != nil {
		t.Fatal(err)
	}
	var expect = "string=3"
	if b.String() != expect {
		t.Errorf("expected %q got %q", expect, b.String())
	}
	e := &errorer{7}
	b.Reset()
	if err := tmpl.Execute(b, e); err != nil {
		t.Fatal(err)
	}
	expect = "error=7"
	if b.String() != expect {
		t.Errorf("expected %q got %q", expect, b.String())
	}
}

// https://golang.org/issue/5982
func TestEscapingNilNonemptyInterfaces(t *testing.T) {
	tmpl := Must(New("x").Parse("{{.E}}"))

	got := new(bytes.Buffer)
	testData := struct{ E error }{} // any non-empty interface here will do; error is just ready at hand
	tmpl.Execute(got, testData)

	// A non-empty interface should print like an empty interface.
	want := new(bytes.Buffer)
	data := struct{ E any }{}
	tmpl.Execute(want, data)

	if !bytes.Equal(want.Bytes(), got.Bytes()) {
		t.Errorf("expected %q got %q", string(want.Bytes()), string(got.Bytes()))
	}
}
```