Response:
Let's break down the thought process for analyzing the provided Go code snippet for `html/template`.

1. **Understand the Goal:** The primary goal is to understand the functionality of the `html/template/template.go` file. This means identifying its core purpose, key methods, data structures, and how it relates to web development.

2. **Initial Scan and Keyword Spotting:**  Quickly read through the code, looking for familiar keywords and patterns. Things that jump out are:
    * `package template`:  Clearly indicates the package name.
    * `import`:  Lists dependencies, including `text/template`. This is a crucial clue – it builds *on top of* the `text/template` package.
    * `Template struct`:  The central data structure. Its fields (`escapeErr`, `text`, `Tree`, `nameSpace`) hint at its responsibilities.
    * Methods like `Execute`, `Parse`, `New`, `Lookup`, `Clone`, `ParseFiles`, `ParseGlob`, `ParseFS`: These are the main actions users can perform.
    * Comments containing "HTML", "safe", "escaping": These suggest the core purpose is related to generating secure HTML.
    * `nameSpace`:  Indicates a mechanism for managing multiple templates.

3. **Identify the Core Functionality:** Based on the initial scan, the main purpose seems to be creating and executing HTML templates while ensuring safety (preventing cross-site scripting, or XSS). The `text/template` import suggests it's an extension of the standard text templating engine, adding HTML-specific safety features.

4. **Analyze Key Structures:**
    * **`Template` struct:**  The `text` field being a `text/template.Template` confirms the inheritance/extension relationship. The `escapeErr` suggests a state related to security checks. The `Tree` likely holds the parsed template structure. `nameSpace` is for managing related templates.
    * **`nameSpace` struct:** The `set` field (a map) clearly manages a collection of `Template` instances, likely by name. The `escaped` flag and `esc` field strongly indicate the management of HTML escaping.

5. **Analyze Key Methods:** Go through the important methods, understanding their purpose and how they interact:
    * **`New`:** Creates a new `Template`. The package-level `New` and the method `New` on an existing `Template` differ slightly in terms of namespacing.
    * **`Parse`:**  Parses template text. It handles named templates (`{{define}}`). Crucially, it needs to happen *before* execution.
    * **`Execute`:** Renders the template with data. The call to `t.escape()` before `t.text.Execute()` highlights the security step.
    * **`ExecuteTemplate`:** Executes a named sub-template.
    * **`Lookup`:** Retrieves a template by name.
    * **`Clone`:** Creates a copy of a template and its associated templates. The error condition about execution is important.
    * **`ParseFiles`, `ParseGlob`, `ParseFS`:**  Methods for loading templates from files. They offer different ways to specify the files.

6. **Infer Go Feature Implementation:** The code clearly implements a **template engine** specifically for HTML. It builds upon the standard `text/template` package, adding features for **automatic HTML escaping** to prevent XSS vulnerabilities. The `nameSpace` implements a way to manage **associated templates** (nested templates, partials, etc.).

7. **Develop Go Code Examples:**  Based on the identified functionality, create simple, illustrative examples. Focus on demonstrating core features like:
    * Basic template parsing and execution.
    * Using variables in templates.
    * Defining and using named templates.
    * Demonstrating HTML escaping.

8. **Consider Input/Output:** For the code examples, specify the input template strings and the expected output. This makes the behavior concrete and easier to understand.

9. **Address Command-Line Parameters:**  While the code itself doesn't directly handle command-line arguments, the methods `ParseFiles` and `ParseGlob` inherently deal with file paths, which are often provided as command-line arguments in larger applications. Explain this connection.

10. **Identify Common Mistakes:** Think about how a developer might misuse the library. Common mistakes related to templating engines include:
    * Executing before parsing.
    * Incorrectly assuming data will be escaped when using `text/template` directly (as opposed to `html/template`).
    * Forgetting about the implications of parsing multiple files with the same name.

11. **Structure the Answer:** Organize the findings logically. Start with a high-level summary of the functionality, then delve into specifics like methods, examples, and common mistakes. Use clear headings and formatting to improve readability.

12. **Review and Refine:**  Read through the drafted answer to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that could be explained better. For instance, initially, I might forget to explicitly mention the prevention of XSS as a key feature. Reviewing would remind me to add that.

This iterative process of scanning, identifying, analyzing, inferring, and exemplifying helps in understanding the purpose and functionality of the given Go code. The key is to leverage the provided code structure, comments, and naming conventions to build a comprehensive understanding.
这段 Go 语言代码是 `html/template` 包的核心部分，它实现了用于生成安全的 HTML 文档片段的模板引擎。它基于 `text/template` 包，并在其基础上增加了 HTML 语境感知转义的功能，以防止跨站脚本攻击 (XSS)。

以下是它的主要功能：

1. **创建和管理 HTML 模板:**
    *   `New(name string) *Template`: 创建一个新的 HTML 模板，可以指定模板的名称。
    *   `(t *Template) New(name string) *Template`:  基于现有模板 `t` 创建一个新的关联模板，新模板会继承 `t` 的分隔符等设置。
    *   `Templates() []*Template`: 返回与模板 `t` 关联的所有模板的切片。
    *   `Lookup(name string) *Template`: 查找与模板 `t` 关联的具有给定名称的模板。
    *   `DefinedTemplates() string`: 返回一个字符串，列出已定义的模板。

2. **解析模板内容:**
    *   `Parse(text string) (*Template, error)`: 将字符串 `text` 解析为模板 `t` 的主体。它可以识别 `{{define ...}}` 或 `{{block ...}}` 语句来定义额外的关联模板。
    *   `ParseFiles(filenames ...string) (*Template, error)` 和 `(t *Template) ParseFiles(filenames ...string) (*Template, error)`: 从指定的文件中解析模板定义。前者创建一个新的模板，后者将解析结果关联到已有的模板 `t`。
    *   `ParseGlob(pattern string) (*Template, error)` 和 `(t *Template) ParseGlob(pattern string) *Template, error)`: 使用 glob 模式匹配文件，并解析其中的模板定义。前者创建一个新的模板，后者将解析结果关联到已有的模板 `t`。
    *   `ParseFS(fsys fs.FS, patterns ...string) (*Template, error)` 和 `(t *Template) ParseFS(fsys fs.FS, patterns ...string) (*Template, error)`:  与 `ParseFiles` 和 `ParseGlob` 类似，但从 `io/fs` 文件系统中读取模板文件。
    *   `AddParseTree(name string, tree *parse.Tree) (*Template, error)`:  使用已解析的语法树创建一个新的模板并将其与 `t` 关联。

3. **执行模板并生成 HTML 输出:**
    *   `Execute(wr io.Writer, data any) error`: 将解析后的模板应用于给定的数据对象 `data`，并将输出写入 `io.Writer` `wr`。在执行前，会进行 HTML 安全转义。
    *   `ExecuteTemplate(wr io.Writer, name string, data any) error`: 执行与 `t` 关联的具有给定名称的模板，并将输出写入 `io.Writer` `wr`。

4. **模板选项配置:**
    *   `Option(opt ...string) *Template`: 设置模板的选项。目前支持 `missingkey` 选项，用于控制当映射中不存在键时的行为。

5. **克隆模板:**
    *   `Clone() (*Template, error)`: 返回模板的副本，包括所有关联的模板。克隆的模板可以独立进行解析，而不会影响原始模板。

6. **函数映射:**
    *   `Funcs(funcMap FuncMap) *Template`: 将函数映射添加到模板的函数映射中，允许在模板中使用自定义函数。

7. **分隔符设置:**
    *   `Delims(left, right string) *Template`: 设置模板动作的左右分隔符。

8. **HTML 安全转义:**
    *   这是 `html/template` 最核心的功能。在执行模板时，它会自动对 HTML 上下文敏感的内容进行转义，例如将 `<` 转义为 `&lt;`，以防止 XSS 攻击。

9. **错误处理:**
    *   许多方法返回 `error`，用于指示解析、执行或其他操作期间发生的错误。
    *   `Must(t *Template, err error) *Template`: 一个辅助函数，用于包装返回 `(*Template, error)` 的函数调用，并在错误不为 `nil` 时 `panic`。

**它是什么 go 语言功能的实现？**

`html/template` 包实现了**模板引擎**，这是一种常见的软件开发模式，用于将数据与预定义的格式（模板）结合起来生成输出。它利用了 Go 语言的以下特性：

*   **结构体 (struct):**  `Template` 和 `nameSpace` 是核心数据结构，用于组织和管理模板信息。
*   **方法 (method):**  `Template` 类型定义了许多方法，用于操作和管理模板。
*   **接口 (interface):**  `io.Writer` 接口用于指定输出目标。`fs.FS` 接口用于抽象文件系统操作。
*   **并发 (concurrency):** 使用 `sync.Mutex` 来保护共享的 `nameSpace` 数据，使模板可以安全地并行执行。
*   **错误处理:** 使用 `error` 类型来表示操作失败。
*   **变参函数 (variadic functions):** 例如 `ParseFiles(filenames ...string)`，可以接受不定数量的参数。
*   **匿名函数 (anonymous functions) 和闭包 (closures):**  在 `readFileFS` 中使用了匿名函数作为闭包。

**Go 代码举例说明:**

```go
package main

import (
	"html/template"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	// 创建一个新的模板
	tmpl := template.Must(template.New("index").Parse(`
		<!DOCTYPE html>
		<html>
		<head>
			<title>{{.Title}}</title>
		</head>
		<body>
			<h1>{{.Greeting}}</h1>
			<p>User input: {{.UserInput}}</p>
		</body>
		</html>
	`))

	data := struct {
		Title     string
		Greeting  string
		UserInput string
	}{
		Title:     "My Webpage",
		Greeting:  "Hello, World!",
		UserInput: "<script>alert('XSS')</script>", // 潜在的 XSS 攻击
	}

	// 执行模板并将结果写入 HTTP 响应
	err := tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8080", nil)
}
```

**假设的输入与输出:**

在这个例子中，当用户访问 `http://localhost:8080/` 时，`handler` 函数会被调用。

**输入 (data 变量):**

```go
data := struct {
	Title     string
	Greeting  string
	UserInput string
}{
	Title:     "My Webpage",
	Greeting:  "Hello, World!",
	UserInput: "<script>alert('XSS')</script>",
}
```

**输出 (写入 http.ResponseWriter):**

```html
<!DOCTYPE html>
<html>
<head>
	<title>My Webpage</title>
</head>
<body>
	<h1>Hello, World!</h1>
	<p>User input: &lt;script&gt;alert('XSS')&lt;/script&gt;</p>
</body>
</html>
```

**代码推理:**

`html/template` 包会自动将 `UserInput` 字段中的 `<script>` 标签转义为 `&lt;script&gt;` 和 `</script>` 转义为 `&lt;/script&gt;`，从而阻止了浏览器执行这段 JavaScript 代码，防止了潜在的 XSS 攻击。  如果使用 `text/template` 包，则不会进行这样的转义，将会直接输出 `<script>alert('XSS')</script>`，导致安全问题。

**命令行参数的具体处理:**

`html/template` 包本身不直接处理命令行参数。但是，它的 `ParseFiles` 和 `ParseGlob` 函数接受文件路径或模式作为参数，这些路径或模式通常可以通过命令行参数传递给程序。

例如，一个使用 `ParseFiles` 的程序可能会这样处理命令行参数：

```go
package main

import (
	"html/template"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		println("Usage: go run main.go <template_file1> [<template_file2> ...]")
		return
	}

	tmpl, err := template.ParseFiles(os.Args[1:]...)
	if err != nil {
		panic(err)
	}

	// ... 使用 tmpl 进行后续操作 ...
}
```

在这个例子中，命令行参数（模板文件名）被传递给 `template.ParseFiles` 函数。

**使用者易犯错的点:**

*   **混淆 `html/template` 和 `text/template`:**  初学者容易混淆这两个包。`text/template` 不会进行 HTML 安全转义，如果用于生成 HTML 内容，可能导致 XSS 漏洞。应该始终使用 `html/template` 来生成 HTML。

    **错误示例 (使用 `text/template`):**

    ```go
    package main

    import (
    	"net/http"
    	"text/template"
    )

    func handler(w http.ResponseWriter, r *http.Request) {
    	tmpl := template.Must(template.New("index").Parse("User input: {{.}}"))
    	userInput := "<script>alert('XSS')</script>"
    	tmpl.Execute(w, userInput) // 潜在的 XSS 漏洞
    }

    func main() {
    	http.HandleFunc("/", handler)
    	http.ListenAndServe(":8080", nil)
    }
    ```

    在这个错误的例子中，使用了 `text/template`，`userInput` 中的 `<script>` 标签不会被转义，会导致 XSS 漏洞。

*   **在执行后尝试解析模板:**  一旦模板被执行 (`Execute` 方法被调用)，就不能再对其进行解析 (`Parse`, `ParseFiles`, `ParseGlob` 等)。这样做会导致错误。

    **错误示例:**

    ```go
    package main

    import (
    	"html/template"
    	"net/http"
    )

    func handler(w http.ResponseWriter, r *http.Request) {
    	tmpl := template.New("index")
    	tmpl, err := tmpl.Parse("<h1>Initial Template</h1>")
    	if err != nil {
    		http.Error(w, err.Error(), http.StatusInternalServerError)
    		return
    	}
    	tmpl.Execute(w, nil) // 首次执行

    	// 错误：尝试在执行后解析
    	_, err = tmpl.Parse("<h1>Updated Template</h1>")
    	if err != nil {
    		http.Error(w, err.Error(), http.StatusInternalServerError)
    		return
    	}
    }

    func main() {
    	http.HandleFunc("/", handler)
    	http.ListenAndServe(":8080", nil)
    }
    ```

*   **忘记处理错误:**  模板的解析和执行操作都可能返回错误，应该始终检查并处理这些错误，以避免程序崩溃或产生意外行为。

*   **在模板中使用不信任的数据而未进行适当的上下文转义:**  虽然 `html/template` 提供了自动转义，但在某些特定场景下（例如，在 `<script>` 标签内部输出 JavaScript 代码，或者在 CSS 样式中输出数据），简单的 HTML 转义可能不够，需要使用特定的转义函数或机制。但是，`html/template` 已经尽力在 HTML 上下文中进行安全的转义。

总而言之，`go/src/html/template/template.go` 实现了 Go 语言中用于生成安全 HTML 内容的模板引擎，它继承了 `text/template` 的基本功能，并添加了关键的 HTML 上下文感知转义机制，以帮助开发者避免 XSS 攻击。

Prompt: 
```
这是路径为go/src/html/template/template.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package template

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sync"
	"text/template"
	"text/template/parse"
)

// Template is a specialized Template from "text/template" that produces a safe
// HTML document fragment.
type Template struct {
	// Sticky error if escaping fails, or escapeOK if succeeded.
	escapeErr error
	// We could embed the text/template field, but it's safer not to because
	// we need to keep our version of the name space and the underlying
	// template's in sync.
	text *template.Template
	// The underlying template's parse tree, updated to be HTML-safe.
	Tree       *parse.Tree
	*nameSpace // common to all associated templates
}

// escapeOK is a sentinel value used to indicate valid escaping.
var escapeOK = fmt.Errorf("template escaped correctly")

// nameSpace is the data structure shared by all templates in an association.
type nameSpace struct {
	mu      sync.Mutex
	set     map[string]*Template
	escaped bool
	esc     escaper
}

// Templates returns a slice of the templates associated with t, including t
// itself.
func (t *Template) Templates() []*Template {
	ns := t.nameSpace
	ns.mu.Lock()
	defer ns.mu.Unlock()
	// Return a slice so we don't expose the map.
	m := make([]*Template, 0, len(ns.set))
	for _, v := range ns.set {
		m = append(m, v)
	}
	return m
}

// Option sets options for the template. Options are described by
// strings, either a simple string or "key=value". There can be at
// most one equals sign in an option string. If the option string
// is unrecognized or otherwise invalid, Option panics.
//
// Known options:
//
// missingkey: Control the behavior during execution if a map is
// indexed with a key that is not present in the map.
//
//	"missingkey=default" or "missingkey=invalid"
//		The default behavior: Do nothing and continue execution.
//		If printed, the result of the index operation is the string
//		"<no value>".
//	"missingkey=zero"
//		The operation returns the zero value for the map type's element.
//	"missingkey=error"
//		Execution stops immediately with an error.
func (t *Template) Option(opt ...string) *Template {
	t.text.Option(opt...)
	return t
}

// checkCanParse checks whether it is OK to parse templates.
// If not, it returns an error.
func (t *Template) checkCanParse() error {
	if t == nil {
		return nil
	}
	t.nameSpace.mu.Lock()
	defer t.nameSpace.mu.Unlock()
	if t.nameSpace.escaped {
		return fmt.Errorf("html/template: cannot Parse after Execute")
	}
	return nil
}

// escape escapes all associated templates.
func (t *Template) escape() error {
	t.nameSpace.mu.Lock()
	defer t.nameSpace.mu.Unlock()
	t.nameSpace.escaped = true
	if t.escapeErr == nil {
		if t.Tree == nil {
			return fmt.Errorf("template: %q is an incomplete or empty template", t.Name())
		}
		if err := escapeTemplate(t, t.text.Root, t.Name()); err != nil {
			return err
		}
	} else if t.escapeErr != escapeOK {
		return t.escapeErr
	}
	return nil
}

// Execute applies a parsed template to the specified data object,
// writing the output to wr.
// If an error occurs executing the template or writing its output,
// execution stops, but partial results may already have been written to
// the output writer.
// A template may be executed safely in parallel, although if parallel
// executions share a Writer the output may be interleaved.
func (t *Template) Execute(wr io.Writer, data any) error {
	if err := t.escape(); err != nil {
		return err
	}
	return t.text.Execute(wr, data)
}

// ExecuteTemplate applies the template associated with t that has the given
// name to the specified data object and writes the output to wr.
// If an error occurs executing the template or writing its output,
// execution stops, but partial results may already have been written to
// the output writer.
// A template may be executed safely in parallel, although if parallel
// executions share a Writer the output may be interleaved.
func (t *Template) ExecuteTemplate(wr io.Writer, name string, data any) error {
	tmpl, err := t.lookupAndEscapeTemplate(name)
	if err != nil {
		return err
	}
	return tmpl.text.Execute(wr, data)
}

// lookupAndEscapeTemplate guarantees that the template with the given name
// is escaped, or returns an error if it cannot be. It returns the named
// template.
func (t *Template) lookupAndEscapeTemplate(name string) (tmpl *Template, err error) {
	t.nameSpace.mu.Lock()
	defer t.nameSpace.mu.Unlock()
	t.nameSpace.escaped = true
	tmpl = t.set[name]
	if tmpl == nil {
		return nil, fmt.Errorf("html/template: %q is undefined", name)
	}
	if tmpl.escapeErr != nil && tmpl.escapeErr != escapeOK {
		return nil, tmpl.escapeErr
	}
	if tmpl.text.Tree == nil || tmpl.text.Root == nil {
		return nil, fmt.Errorf("html/template: %q is an incomplete template", name)
	}
	if t.text.Lookup(name) == nil {
		panic("html/template internal error: template escaping out of sync")
	}
	if tmpl.escapeErr == nil {
		err = escapeTemplate(tmpl, tmpl.text.Root, name)
	}
	return tmpl, err
}

// DefinedTemplates returns a string listing the defined templates,
// prefixed by the string "; defined templates are: ". If there are none,
// it returns the empty string. Used to generate an error message.
func (t *Template) DefinedTemplates() string {
	return t.text.DefinedTemplates()
}

// Parse parses text as a template body for t.
// Named template definitions ({{define ...}} or {{block ...}} statements) in text
// define additional templates associated with t and are removed from the
// definition of t itself.
//
// Templates can be redefined in successive calls to Parse,
// before the first use of [Template.Execute] on t or any associated template.
// A template definition with a body containing only white space and comments
// is considered empty and will not replace an existing template's body.
// This allows using Parse to add new named template definitions without
// overwriting the main template body.
func (t *Template) Parse(text string) (*Template, error) {
	if err := t.checkCanParse(); err != nil {
		return nil, err
	}

	ret, err := t.text.Parse(text)
	if err != nil {
		return nil, err
	}

	// In general, all the named templates might have changed underfoot.
	// Regardless, some new ones may have been defined.
	// The template.Template set has been updated; update ours.
	t.nameSpace.mu.Lock()
	defer t.nameSpace.mu.Unlock()
	for _, v := range ret.Templates() {
		name := v.Name()
		tmpl := t.set[name]
		if tmpl == nil {
			tmpl = t.new(name)
		}
		tmpl.text = v
		tmpl.Tree = v.Tree
	}
	return t, nil
}

// AddParseTree creates a new template with the name and parse tree
// and associates it with t.
//
// It returns an error if t or any associated template has already been executed.
func (t *Template) AddParseTree(name string, tree *parse.Tree) (*Template, error) {
	if err := t.checkCanParse(); err != nil {
		return nil, err
	}

	t.nameSpace.mu.Lock()
	defer t.nameSpace.mu.Unlock()
	text, err := t.text.AddParseTree(name, tree)
	if err != nil {
		return nil, err
	}
	ret := &Template{
		nil,
		text,
		text.Tree,
		t.nameSpace,
	}
	t.set[name] = ret
	return ret, nil
}

// Clone returns a duplicate of the template, including all associated
// templates. The actual representation is not copied, but the name space of
// associated templates is, so further calls to [Template.Parse] in the copy will add
// templates to the copy but not to the original. [Template.Clone] can be used to prepare
// common templates and use them with variant definitions for other templates
// by adding the variants after the clone is made.
//
// It returns an error if t has already been executed.
func (t *Template) Clone() (*Template, error) {
	t.nameSpace.mu.Lock()
	defer t.nameSpace.mu.Unlock()
	if t.escapeErr != nil {
		return nil, fmt.Errorf("html/template: cannot Clone %q after it has executed", t.Name())
	}
	textClone, err := t.text.Clone()
	if err != nil {
		return nil, err
	}
	ns := &nameSpace{set: make(map[string]*Template)}
	ns.esc = makeEscaper(ns)
	ret := &Template{
		nil,
		textClone,
		textClone.Tree,
		ns,
	}
	ret.set[ret.Name()] = ret
	for _, x := range textClone.Templates() {
		name := x.Name()
		src := t.set[name]
		if src == nil || src.escapeErr != nil {
			return nil, fmt.Errorf("html/template: cannot Clone %q after it has executed", t.Name())
		}
		x.Tree = x.Tree.Copy()
		ret.set[name] = &Template{
			nil,
			x,
			x.Tree,
			ret.nameSpace,
		}
	}
	// Return the template associated with the name of this template.
	return ret.set[ret.Name()], nil
}

// New allocates a new HTML template with the given name.
func New(name string) *Template {
	ns := &nameSpace{set: make(map[string]*Template)}
	ns.esc = makeEscaper(ns)
	tmpl := &Template{
		nil,
		template.New(name),
		nil,
		ns,
	}
	tmpl.set[name] = tmpl
	return tmpl
}

// New allocates a new HTML template associated with the given one
// and with the same delimiters. The association, which is transitive,
// allows one template to invoke another with a {{template}} action.
//
// If a template with the given name already exists, the new HTML template
// will replace it. The existing template will be reset and disassociated with
// t.
func (t *Template) New(name string) *Template {
	t.nameSpace.mu.Lock()
	defer t.nameSpace.mu.Unlock()
	return t.new(name)
}

// new is the implementation of New, without the lock.
func (t *Template) new(name string) *Template {
	tmpl := &Template{
		nil,
		t.text.New(name),
		nil,
		t.nameSpace,
	}
	if existing, ok := tmpl.set[name]; ok {
		emptyTmpl := New(existing.Name())
		*existing = *emptyTmpl
	}
	tmpl.set[name] = tmpl
	return tmpl
}

// Name returns the name of the template.
func (t *Template) Name() string {
	return t.text.Name()
}

type FuncMap = template.FuncMap

// Funcs adds the elements of the argument map to the template's function map.
// It must be called before the template is parsed.
// It panics if a value in the map is not a function with appropriate return
// type. However, it is legal to overwrite elements of the map. The return
// value is the template, so calls can be chained.
func (t *Template) Funcs(funcMap FuncMap) *Template {
	t.text.Funcs(template.FuncMap(funcMap))
	return t
}

// Delims sets the action delimiters to the specified strings, to be used in
// subsequent calls to [Template.Parse], [ParseFiles], or [ParseGlob]. Nested template
// definitions will inherit the settings. An empty delimiter stands for the
// corresponding default: {{ or }}.
// The return value is the template, so calls can be chained.
func (t *Template) Delims(left, right string) *Template {
	t.text.Delims(left, right)
	return t
}

// Lookup returns the template with the given name that is associated with t,
// or nil if there is no such template.
func (t *Template) Lookup(name string) *Template {
	t.nameSpace.mu.Lock()
	defer t.nameSpace.mu.Unlock()
	return t.set[name]
}

// Must is a helper that wraps a call to a function returning ([*Template], error)
// and panics if the error is non-nil. It is intended for use in variable initializations
// such as
//
//	var t = template.Must(template.New("name").Parse("html"))
func Must(t *Template, err error) *Template {
	if err != nil {
		panic(err)
	}
	return t
}

// ParseFiles creates a new [Template] and parses the template definitions from
// the named files. The returned template's name will have the (base) name and
// (parsed) contents of the first file. There must be at least one file.
// If an error occurs, parsing stops and the returned [*Template] is nil.
//
// When parsing multiple files with the same name in different directories,
// the last one mentioned will be the one that results.
// For instance, ParseFiles("a/foo", "b/foo") stores "b/foo" as the template
// named "foo", while "a/foo" is unavailable.
func ParseFiles(filenames ...string) (*Template, error) {
	return parseFiles(nil, readFileOS, filenames...)
}

// ParseFiles parses the named files and associates the resulting templates with
// t. If an error occurs, parsing stops and the returned template is nil;
// otherwise it is t. There must be at least one file.
//
// When parsing multiple files with the same name in different directories,
// the last one mentioned will be the one that results.
//
// ParseFiles returns an error if t or any associated template has already been executed.
func (t *Template) ParseFiles(filenames ...string) (*Template, error) {
	return parseFiles(t, readFileOS, filenames...)
}

// parseFiles is the helper for the method and function. If the argument
// template is nil, it is created from the first file.
func parseFiles(t *Template, readFile func(string) (string, []byte, error), filenames ...string) (*Template, error) {
	if err := t.checkCanParse(); err != nil {
		return nil, err
	}

	if len(filenames) == 0 {
		// Not really a problem, but be consistent.
		return nil, fmt.Errorf("html/template: no files named in call to ParseFiles")
	}
	for _, filename := range filenames {
		name, b, err := readFile(filename)
		if err != nil {
			return nil, err
		}
		s := string(b)
		// First template becomes return value if not already defined,
		// and we use that one for subsequent New calls to associate
		// all the templates together. Also, if this file has the same name
		// as t, this file becomes the contents of t, so
		//  t, err := New(name).Funcs(xxx).ParseFiles(name)
		// works. Otherwise we create a new template associated with t.
		var tmpl *Template
		if t == nil {
			t = New(name)
		}
		if name == t.Name() {
			tmpl = t
		} else {
			tmpl = t.New(name)
		}
		_, err = tmpl.Parse(s)
		if err != nil {
			return nil, err
		}
	}
	return t, nil
}

// ParseGlob creates a new [Template] and parses the template definitions from
// the files identified by the pattern. The files are matched according to the
// semantics of filepath.Match, and the pattern must match at least one file.
// The returned template will have the (base) name and (parsed) contents of the
// first file matched by the pattern. ParseGlob is equivalent to calling
// [ParseFiles] with the list of files matched by the pattern.
//
// When parsing multiple files with the same name in different directories,
// the last one mentioned will be the one that results.
func ParseGlob(pattern string) (*Template, error) {
	return parseGlob(nil, pattern)
}

// ParseGlob parses the template definitions in the files identified by the
// pattern and associates the resulting templates with t. The files are matched
// according to the semantics of filepath.Match, and the pattern must match at
// least one file. ParseGlob is equivalent to calling t.ParseFiles with the
// list of files matched by the pattern.
//
// When parsing multiple files with the same name in different directories,
// the last one mentioned will be the one that results.
//
// ParseGlob returns an error if t or any associated template has already been executed.
func (t *Template) ParseGlob(pattern string) (*Template, error) {
	return parseGlob(t, pattern)
}

// parseGlob is the implementation of the function and method ParseGlob.
func parseGlob(t *Template, pattern string) (*Template, error) {
	if err := t.checkCanParse(); err != nil {
		return nil, err
	}
	filenames, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	if len(filenames) == 0 {
		return nil, fmt.Errorf("html/template: pattern matches no files: %#q", pattern)
	}
	return parseFiles(t, readFileOS, filenames...)
}

// IsTrue reports whether the value is 'true', in the sense of not the zero of its type,
// and whether the value has a meaningful truth value. This is the definition of
// truth used by if and other such actions.
func IsTrue(val any) (truth, ok bool) {
	return template.IsTrue(val)
}

// ParseFS is like [ParseFiles] or [ParseGlob] but reads from the file system fs
// instead of the host operating system's file system.
// It accepts a list of glob patterns.
// (Note that most file names serve as glob patterns matching only themselves.)
func ParseFS(fs fs.FS, patterns ...string) (*Template, error) {
	return parseFS(nil, fs, patterns)
}

// ParseFS is like [Template.ParseFiles] or [Template.ParseGlob] but reads from the file system fs
// instead of the host operating system's file system.
// It accepts a list of glob patterns.
// (Note that most file names serve as glob patterns matching only themselves.)
func (t *Template) ParseFS(fs fs.FS, patterns ...string) (*Template, error) {
	return parseFS(t, fs, patterns)
}

func parseFS(t *Template, fsys fs.FS, patterns []string) (*Template, error) {
	var filenames []string
	for _, pattern := range patterns {
		list, err := fs.Glob(fsys, pattern)
		if err != nil {
			return nil, err
		}
		if len(list) == 0 {
			return nil, fmt.Errorf("template: pattern matches no files: %#q", pattern)
		}
		filenames = append(filenames, list...)
	}
	return parseFiles(t, readFileFS(fsys), filenames...)
}

func readFileOS(file string) (name string, b []byte, err error) {
	name = filepath.Base(file)
	b, err = os.ReadFile(file)
	return
}

func readFileFS(fsys fs.FS) func(string) (string, []byte, error) {
	return func(file string) (name string, b []byte, err error) {
		name = path.Base(file)
		b, err = fs.ReadFile(fsys, file)
		return
	}
}

"""



```