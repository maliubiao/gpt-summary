Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The primary goal is to explain the functionality of the `html/template` package in Go, based on the provided `doc.go` content. The request also asks for examples, error handling insights, common pitfalls, and a focus on security.

2. **Identify Key Themes:**  Reading through the documentation, several central themes emerge:
    * **HTML Safety:** The package's primary purpose is to generate HTML that's safe from code injection.
    * **Contextual Auto-Escaping:**  It intelligently escapes data based on where it's placed in the HTML structure (HTML tags, attributes, JavaScript, CSS, URLs).
    * **`text/template` Foundation:**  It's built upon the `text/template` package, sharing its basic templating syntax.
    * **Trusted Templates, Untrusted Data:** The security model assumes template authors are trustworthy, but the data passed to the template is not.
    * **Typed Strings:**  The ability to mark data as already safe (e.g., `template.HTML`).
    * **Namespaced and `data-` Attributes:** Special handling for these attributes.
    * **Security Properties:**  Mention of "Structure Preservation," "Code Effect," and "Least Surprise."

3. **Structure the Answer:** I decide to organize the answer logically, following the structure of the request:
    * **Functionality Listing:** A bulleted list of the main capabilities.
    * **Go Code Examples:** Illustrate the key concepts with practical code.
    * **Code Reasoning (with Assumptions):** Explain the *why* behind the examples, including hypothetical inputs and expected outputs.
    * **Command-Line Arguments:**  Note that the provided documentation *doesn't* discuss command-line arguments, so explicitly state this.
    * **Common Mistakes:**  Identify a typical error based on the "Typed Strings" section.

4. **Elaborate on Functionality:**  I go through the documentation and extract the core functionalities:
    * HTML safety via auto-escaping.
    * Contextual awareness.
    * Reusing `text/template`'s API.
    * Handling different content types (HTML, JavaScript, URLs).
    * Support for namespaced and `data-` attributes.
    * Error reporting (though details are in `ErrorCode`).
    * The concept of typed strings for pre-safe content.

5. **Create Go Code Examples:** I focus on demonstrating the core difference between `text/template` and `html/template` in terms of escaping:

    * **Example 1 (Basic Escaping):** Show how `html/template` escapes HTML tags. Provide input and the expected safe output.
    * **Example 2 (Contextual Escaping - URL):** Illustrate how the escaping changes based on the context (within an `href` attribute).
    * **Example 3 (Typed String):** Demonstrate how `template.HTML` bypasses escaping.

6. **Reason About the Code:** For each example, I explain:
    * The *assumption* about the input data.
    * The *expected output* based on `html/template`'s behavior.
    * *Why* the output is the way it is (referencing contextual escaping and typed strings).

7. **Address Command-Line Arguments:**  I carefully check the provided documentation. Since it doesn't mention any command-line arguments for the `html/template` package itself, I explicitly state that. This demonstrates attention to detail and avoids making assumptions.

8. **Identify Common Mistakes:** The "Typed Strings" section directly suggests a common error: forgetting to use `template.HTML` when you want to include pre-safe HTML. I create an example demonstrating this.

9. **Review and Refine:** I read through my answer to ensure:
    * **Accuracy:** The information aligns with the documentation.
    * **Clarity:** The explanations are easy to understand.
    * **Completeness:** All parts of the request are addressed.
    * **Conciseness:**  Avoiding unnecessary jargon or overly verbose explanations.
    * **Language:** Ensuring the language is natural and grammatically correct.

This systematic approach, focusing on understanding the core concepts, structuring the answer logically, and providing concrete examples, helps generate a comprehensive and accurate response to the prompt. The process also involves careful reading of the source material and paying attention to what is *not* mentioned (like command-line arguments).
这段Go语言代码是 `html/template` 包的文档，它解释了这个包的功能和使用方法。以下是它所列举的功能以及相关的解释和示例：

**主要功能:**

1. **安全地生成 HTML 输出:** 这是 `html/template` 的核心功能。它通过自动转义（escaping）来防止代码注入攻击，确保动态生成的内容不会被浏览器错误地解释为 HTML 标签或 JavaScript 代码。

2. **数据驱动的模板:**  它使用与 `text/template` 包相同的接口，允许你定义包含占位符的模板，并将数据传递给模板来生成最终的 HTML 输出。

3. **上下文感知转义:**  `html/template` 能够理解 HTML、CSS、JavaScript 和 URI 的上下文，并根据不同的上下文应用不同的转义规则。这意味着它可以根据数据在 HTML 结构中的位置（例如，在标签内部、属性值中、JavaScript 代码中等）进行适当的转义。

4. **与 `text/template` 包兼容:**  `html/template` 是对 `text/template` 的包装，因此你可以使用相同的 API 来解析和执行模板。这意味着你可以轻松地将现有的 `text/template` 模板迁移到 `html/template` 以获得安全性。

5. **处理命名空间和 `data-` 属性:**  它能够正确处理带有命名空间（例如 `my:href`）和 `data-` 前缀的属性，确保在这些属性中插入的数据也被安全地转义。

6. **支持安全内容标记:**  你可以使用 `template.HTML`, `template.JS`, `template.URL` 等类型来标记已知安全的字符串，从而避免不必要的重复转义。

**它是什么 Go 语言功能的实现:**

`html/template` 包是对 Go 语言标准库中 `text/template` 包的扩展和增强。它利用了 `text/template` 的模板解析和执行引擎，并在解析过程中添加了额外的安全处理步骤，即上下文感知的自动转义。

**Go 代码示例:**

以下代码示例展示了 `html/template` 如何防止跨站脚本攻击 (XSS)。

```go
package main

import (
	"html/template"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	// 使用 html/template
	t_html, err_html := template.New("webpage").Parse(`
		<h1>Hello, {{.Name}}!</h1>
		<p>You searched for: <a href="/search?q={{.Query}}">{{.Query}}</a></p>
		<script>console.log('{{.Evil}}');</script>
	`)
	if err_html != nil {
		http.Error(w, err_html.Error(), http.StatusInternalServerError)
		return
	}

	data := struct {
		Name  string
		Query string
		Evil  string
	}{
		Name:  "User",
		Query: "<script>alert('Search Result')</script>",
		Evil:  "<script>alert('Evil Code')</script>",
	}

	err_exec_html := t_html.Execute(w, data)
	if err_exec_html != nil {
		http.Error(w, err_exec_html.Error(), http.StatusInternalServerError)
		return
	}

	// 使用 text/template 进行对比
	t_text, err_text := text_template.New("webpage").Parse(`
		<h1>Hello, {{.Name}}!</h1>
		<p>You searched for: <a href="/search?q={{.Query}}">{{.Query}}</a></p>
		<script>console.log('{{.Evil}}');</script>
	`)
	if err_text != nil {
		http.Error(w, err_text.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte("\n\n--- text/template Output ---\n\n")) // 分隔符

	err_exec_text := t_text.Execute(w, data)
	if err_exec_text != nil {
		http.Error(w, err_exec_text.Error(), http.StatusInternalServerError)
		return
	}
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8080", nil)
}
```

**假设的输入与输出:**

当用户访问 `http://localhost:8080/` 时，`handler` 函数会被调用。

**使用 `html/template` 的输出 (安全):**

```html
<h1>Hello, User!</h1>
<p>You searched for: <a href="/search?q=%3cscript%3ealert('Search&#43;Result')%3c/script%3e">&lt;script&gt;alert('Search Result')&lt;/script&gt;</a></p>
<script>console.log('&lt;script&gt;alert(\'Evil Code\')&lt;/script&gt;');</script>

--- text/template Output ---

<h1>Hello, User!</h1>
<p>You searched for: <a href="/search?q=<script>alert('Search Result')</script>"><script>alert('Search Result')</script></a></p>
<script>console.log('<script>alert('Evil Code')</script>');</script>
```

**解释:**

* **`.Query` 的转义:** 在 `html/template` 的输出中，`<script>alert('Search Result')</script>` 被转义为 `%3cscript%3ealert('Search&#43;Result')%3c/script%3e`（在 `href` 属性中进行了 URL 编码） 和 `&lt;script&gt;alert('Search Result')&lt;/script&gt;`（在标签文本内容中进行了 HTML 实体编码）。 这使得这段脚本不会被浏览器执行。
* **`.Evil` 的转义:**  同样，`<script>alert('Evil Code')</script>` 被转义为 `&lt;script&gt;alert(\'Evil Code\')&lt;/script&gt;`，防止 JavaScript 代码注入。
* **`text/template` 的输出 (不安全):**  `text/template` 不进行自动的 HTML 转义，因此恶意脚本会被直接输出到 HTML 中，可能会导致安全问题。

**命令行参数的具体处理:**

这段文档并没有直接涉及 `html/template` 包的命令行参数处理。`html/template` 主要是在 Go 代码中作为库来使用，用于处理 HTML 模板的解析和执行。如果涉及到命令行参数，通常是在调用模板执行的外部程序中处理，而不是 `html/template` 包本身的功能。

**使用者易犯错的点:**

1. **混淆 `html/template` 和 `text/template`:**  开发者可能会错误地使用 `text/template` 来处理 HTML 输出，导致安全漏洞。记住，只要输出是 HTML，就应该使用 `html/template`。

   ```go
   // 错误的做法
   import "text/template"

   func renderUnsafe(w http.ResponseWriter, data string) {
       tmpl, _ := text_template.New("unsafe").Parse(`<div>{{.}}</div>`)
       tmpl.Execute(w, data) // 如果 data 包含恶意脚本，就会存在安全风险
   }

   // 正确的做法
   import "html/template"

   func renderSafe(w http.ResponseWriter, data string) {
       tmpl, _ := html_template.New("safe").Parse(`<div>{{.}}</div>`)
       tmpl.Execute(w, data) // data 中的特殊字符会被转义
   }
   ```

   **假设输入:** `data = "<script>alert('XSS')</script>"`

   **`renderUnsafe` 的输出:** `<div><script>alert('XSS')</script></div>` (可能执行恶意脚本)

   **`renderSafe` 的输出:** `<div>&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;</div>` (安全，脚本被转义)

2. **错误地使用安全类型:**  开发者可能会误解 `template.HTML` 等安全类型的作用，并随意地将不受信任的数据标记为安全，从而绕过转义机制，引入安全风险。

   ```go
   import "html/template"

   func renderPotentiallyUnsafe(w http.ResponseWriter, data string) {
       // 错误地假设 data 是安全的
       safeData := template.HTML(data)
       tmpl, _ := html_template.New("potentiallyUnsafe").Parse(`<div>{{.}}</div>`)
       tmpl.Execute(w, safeData) // 如果 data 不安全，这里就存在风险
   }
   ```

   **假设输入:** `data = "<script>alert('XSS')</script>"`

   **`renderPotentiallyUnsafe` 的输出:** `<div><script>alert('XSS')</script></div>` (因为数据被强制标记为安全，跳过了转义)

总而言之，`html/template` 包的核心价值在于其自动的、上下文感知的 HTML 转义功能，这大大降低了在 Go Web 应用中引入 XSS 漏洞的风险。理解其工作原理以及避免常见的错误用法对于开发安全的 Web 应用至关重要。

### 提示词
```
这是路径为go/src/html/template/doc.go的go语言实现的一部分， 请列举一下它的功能, 　
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

/*
Package template (html/template) implements data-driven templates for
generating HTML output safe against code injection. It provides the
same interface as [text/template] and should be used instead of
[text/template] whenever the output is HTML.

The documentation here focuses on the security features of the package.
For information about how to program the templates themselves, see the
documentation for [text/template].

# Introduction

This package wraps [text/template] so you can share its template API
to parse and execute HTML templates safely.

	tmpl, err := template.New("name").Parse(...)
	// Error checking elided
	err = tmpl.Execute(out, data)

If successful, tmpl will now be injection-safe. Otherwise, err is an error
defined in the docs for ErrorCode.

HTML templates treat data values as plain text which should be encoded so they
can be safely embedded in an HTML document. The escaping is contextual, so
actions can appear within JavaScript, CSS, and URI contexts.

The security model used by this package assumes that template authors are
trusted, while Execute's data parameter is not. More details are
provided below.

Example

	import "text/template"
	...
	t, err := template.New("foo").Parse(`{{define "T"}}Hello, {{.}}!{{end}}`)
	err = t.ExecuteTemplate(out, "T", "<script>alert('you have been pwned')</script>")

produces

	Hello, <script>alert('you have been pwned')</script>!

but the contextual autoescaping in html/template

	import "html/template"
	...
	t, err := template.New("foo").Parse(`{{define "T"}}Hello, {{.}}!{{end}}`)
	err = t.ExecuteTemplate(out, "T", "<script>alert('you have been pwned')</script>")

produces safe, escaped HTML output

	Hello, &lt;script&gt;alert(&#39;you have been pwned&#39;)&lt;/script&gt;!

# Contexts

This package understands HTML, CSS, JavaScript, and URIs. It adds sanitizing
functions to each simple action pipeline, so given the excerpt

	<a href="/search?q={{.}}">{{.}}</a>

At parse time each {{.}} is overwritten to add escaping functions as necessary.
In this case it becomes

	<a href="/search?q={{. | urlescaper | attrescaper}}">{{. | htmlescaper}}</a>

where urlescaper, attrescaper, and htmlescaper are aliases for internal escaping
functions.

For these internal escaping functions, if an action pipeline evaluates to
a nil interface value, it is treated as though it were an empty string.

# Namespaced and data- attributes

Attributes with a namespace are treated as if they had no namespace.
Given the excerpt

	<a my:href="{{.}}"></a>

At parse time the attribute will be treated as if it were just "href".
So at parse time the template becomes:

	<a my:href="{{. | urlescaper | attrescaper}}"></a>

Similarly to attributes with namespaces, attributes with a "data-" prefix are
treated as if they had no "data-" prefix. So given

	<a data-href="{{.}}"></a>

At parse time this becomes

	<a data-href="{{. | urlescaper | attrescaper}}"></a>

If an attribute has both a namespace and a "data-" prefix, only the namespace
will be removed when determining the context. For example

	<a my:data-href="{{.}}"></a>

This is handled as if "my:data-href" was just "data-href" and not "href" as
it would be if the "data-" prefix were to be ignored too. Thus at parse
time this becomes just

	<a my:data-href="{{. | attrescaper}}"></a>

As a special case, attributes with the namespace "xmlns" are always treated
as containing URLs. Given the excerpts

	<a xmlns:title="{{.}}"></a>
	<a xmlns:href="{{.}}"></a>
	<a xmlns:onclick="{{.}}"></a>

At parse time they become:

	<a xmlns:title="{{. | urlescaper | attrescaper}}"></a>
	<a xmlns:href="{{. | urlescaper | attrescaper}}"></a>
	<a xmlns:onclick="{{. | urlescaper | attrescaper}}"></a>

# Errors

See the documentation of ErrorCode for details.

# A fuller picture

The rest of this package comment may be skipped on first reading; it includes
details necessary to understand escaping contexts and error messages. Most users
will not need to understand these details.

# Contexts

Assuming {{.}} is `O'Reilly: How are <i>you</i>?`, the table below shows
how {{.}} appears when used in the context to the left.

	Context                          {{.}} After
	{{.}}                            O'Reilly: How are &lt;i&gt;you&lt;/i&gt;?
	<a title='{{.}}'>                O&#39;Reilly: How are you?
	<a href="/{{.}}">                O&#39;Reilly: How are %3ci%3eyou%3c/i%3e?
	<a href="?q={{.}}">              O&#39;Reilly%3a%20How%20are%3ci%3e...%3f
	<a onx='f("{{.}}")'>             O\x27Reilly: How are \x3ci\x3eyou...?
	<a onx='f({{.}})'>               "O\x27Reilly: How are \x3ci\x3eyou...?"
	<a onx='pattern = /{{.}}/;'>     O\x27Reilly: How are \x3ci\x3eyou...\x3f

If used in an unsafe context, then the value might be filtered out:

	Context                          {{.}} After
	<a href="{{.}}">                 #ZgotmplZ

since "O'Reilly:" is not an allowed protocol like "http:".

If {{.}} is the innocuous word, `left`, then it can appear more widely,

	Context                              {{.}} After
	{{.}}                                left
	<a title='{{.}}'>                    left
	<a href='{{.}}'>                     left
	<a href='/{{.}}'>                    left
	<a href='?dir={{.}}'>                left
	<a style="border-{{.}}: 4px">        left
	<a style="align: {{.}}">             left
	<a style="background: '{{.}}'>       left
	<a style="background: url('{{.}}')>  left
	<style>p.{{.}} {color:red}</style>   left

Non-string values can be used in JavaScript contexts.
If {{.}} is

	struct{A,B string}{ "foo", "bar" }

in the escaped template

	<script>var pair = {{.}};</script>

then the template output is

	<script>var pair = {"A": "foo", "B": "bar"};</script>

See package json to understand how non-string content is marshaled for
embedding in JavaScript contexts.

# Typed Strings

By default, this package assumes that all pipelines produce a plain text string.
It adds escaping pipeline stages necessary to correctly and safely embed that
plain text string in the appropriate context.

When a data value is not plain text, you can make sure it is not over-escaped
by marking it with its type.

Types HTML, JS, URL, and others from content.go can carry safe content that is
exempted from escaping.

The template

	Hello, {{.}}!

can be invoked with

	tmpl.Execute(out, template.HTML(`<b>World</b>`))

to produce

	Hello, <b>World</b>!

instead of the

	Hello, &lt;b&gt;World&lt;b&gt;!

that would have been produced if {{.}} was a regular string.

# Security Model

https://rawgit.com/mikesamuel/sanitized-jquery-templates/trunk/safetemplate.html#problem_definition defines "safe" as used by this package.

This package assumes that template authors are trusted, that Execute's data
parameter is not, and seeks to preserve the properties below in the face
of untrusted data:

Structure Preservation Property:
"... when a template author writes an HTML tag in a safe templating language,
the browser will interpret the corresponding portion of the output as a tag
regardless of the values of untrusted data, and similarly for other structures
such as attribute boundaries and JS and CSS string boundaries."

Code Effect Property:
"... only code specified by the template author should run as a result of
injecting the template output into a page and all code specified by the
template author should run as a result of the same."

Least Surprise Property:
"A developer (or code reviewer) familiar with HTML, CSS, and JavaScript, who
knows that contextual autoescaping happens should be able to look at a {{.}}
and correctly infer what sanitization happens."

Previously, ECMAScript 6 template literal were disabled by default, and could be
enabled with the GODEBUG=jstmpllitinterp=1 environment variable. Template
literals are now supported by default, and setting jstmpllitinterp has no
effect.
*/
package template
```