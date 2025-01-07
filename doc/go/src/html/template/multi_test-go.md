Response:
Let's break down the thought process for analyzing the provided Go code snippet for `multi_test.go`.

**1. Initial Understanding: The Purpose of `multi_test.go`**

The package declaration `package template` and the import of `"testing"` immediately tell us this is a test file for the `template` package in Go's standard library. The name `multi_test` strongly suggests it's focused on testing scenarios involving multiple templates. The comment "// Tests for multiple-template execution, copied from text/template." confirms this. The "copied from text/template" hints at a shared underlying concept between `html/template` and `text/template`.

**2. Examining the `multiExecTests` Variable:**

This slice of `execTest` structs is crucial. Each struct represents a test case. Looking at the fields of `execTest` (deduced from how they're used):

* `"empty"`, `"text"`, `"invoke x"`, etc. are likely test case *names*.
* `""`, `"some text"`, `{{template "x" .SI}}`, etc. are the *template strings* to be parsed and executed.
* `"some text"`, `"TEXT"`, etc. are the *expected output* after execution.
* `nil`, `tVal`, etc. are likely the *data* passed to the template for execution.
* `true` seems to indicate whether the test is expected to *succeed*.

The content of these test cases gives us insights into the functionalities being tested:

* **Basic text rendering:** `"empty"`, `"text"`
* **Template invocation:** `"invoke x"`, `"invoke x no args"`, `"invoke dot int"`, etc. This confirms the "multiple-template" aspect. It shows how one template can call another.
* **Passing data:**  `.SI`, `.I`, `.U` suggest accessing fields of the input data.
* **Variable declaration within a template:** `"variable declared by template"`

**3. Analyzing the `multiText1` and `multiText2` Constants:**

These string constants clearly define named templates using `{{define "name"}}...{{end}}`. This reinforces the idea of testing multi-template scenarios where templates can be defined separately and then invoked.

**4. Dissecting the `TestMultiExecute` Function:**

This function is the core test for basic multi-template execution.

* It creates a new root template: `template, err := New("root").Parse(multiText1)`.
* It parses the first set of template definitions.
* It parses the second set of template definitions into the *same* root template: `_, err = template.Parse(multiText2)`. This is key – it shows how to add multiple template definitions to a single template set.
* It calls `testExecute(multiExecTests, template, t)`. This suggests a helper function (likely defined elsewhere in the package) that runs the test cases defined in `multiExecTests` against the parsed template.

**5. Investigating `TestParseFiles`, `TestParseGlob`, and `TestParseFS`:**

These functions highlight different ways to load templates from external sources:

* **`ParseFiles`:** Parses templates from specific named files.
* **`ParseGlob`:** Parses templates from files matching a given glob pattern.
* **`ParseFS`:** Parses templates from an `os.FS` interface, providing a way to load templates from various sources like directories or zip archives. The use of `os.DirFS("testdata")` is a concrete example.

The error handling in these functions (checking for errors when files don't exist or the pattern is invalid) is standard good testing practice.

**6. Examining `templateFileExecTests` and the associated `TestParseFilesWithData`, `TestParseGlobWithData`, and `TestParseZipFS`:**

These sections demonstrate parsing templates from files *that contain both template definitions and content to be rendered*. This contrasts with `multiText1` and `multiText2`, which only contained definitions. The `templateFileExecTests` variable and the test functions show how the content within those files gets processed. The `TestParseZipFS` function is particularly interesting as it demonstrates loading templates from a zip archive.

**7. Analyzing the Remaining Test Functions (`TestAddParseTreeToUnparsedTemplate`, `TestRedefinition`, `TestEmptyTemplateCloneCrash`, `TestTemplateLookUp`, `TestParse`, `TestEmptyTemplate`, `TestIssue19294`):**

These test cases focus on more specific edge cases and error conditions:

* **`TestAddParseTreeToUnparsedTemplate`:** Checks that adding a pre-parsed template tree to an existing template doesn't cause a panic.
* **`TestRedefinition`:** Tests how the template engine handles redefinitions of templates with the same name. It suggests that subsequent parses overwrite existing definitions within the same template.
* **`TestEmptyTemplateCloneCrash`:**  Ensures that cloning an empty template doesn't crash the program.
* **`TestTemplateLookUp`:** (Skipped in the provided code, but the intent is clear) Tests the `Lookup` method for finding defined templates.
* **`TestParse`:**  Highlights a crucial restriction:  only one `Parse` call on the same template can contain non-definition text.
* **`TestEmptyTemplate`:** Explores how empty templates are handled during execution.
* **`TestIssue19294`:** Addresses a specific bug related to the order of template processing and empty blocks.

**8. Inferring Go Features and Providing Examples:**

Based on the analysis, the key Go `html/template` features being tested are:

* **Defining named templates:** Using `{{define "name"}}...{{end}}`.
* **Invoking templates:** Using `{{template "name" .}}` or `{{template "name"}}`.
* **Passing data to templates:** Accessing data using `.` and fields like `.SI`, `.I`, etc.
* **Parsing templates from strings:** Using `template.New("name").Parse(string)`.
* **Parsing templates from files:** Using `template.ParseFiles("file1", "file2")`.
* **Parsing templates using glob patterns:** Using `template.ParseGlob("pattern")`.
* **Parsing templates from `fs.FS`:** Using `template.ParseFS(fs, "files...")`.
* **Cloning templates:** Using `template.Clone()`.
* **Looking up templates:** Using `template.Lookup("name")`.
* **Block definitions and inheritance (implicitly tested in `TestIssue19294`):** Using `{{block "name" .}}...{{end}}`.

The Go code examples were constructed by taking the core concepts demonstrated in the test functions and expressing them in simpler, illustrative snippets.

**9. Identifying Potential Pitfalls:**

By carefully examining the tests and the descriptions, potential pitfalls were identified:

* **Redefining templates:** The behavior of `Parse` when redefining templates might not be immediately obvious.
* **Mixing content and definitions in multiple `Parse` calls:**  The restriction on having non-definition text in only one `Parse` call on the same receiver is a crucial point.
* **Understanding the context (`.`) inside templates:**  Knowing how data is passed and accessed is essential.

**Self-Correction/Refinement During the Process:**

* Initially, I might have focused too much on the individual test cases without fully grasping the overall purpose of testing multi-template functionality. Stepping back and looking at the larger structure (the different `TestParse*` functions) helped solidify the understanding.
*  The purpose of `execTest` wasn't immediately clear. By observing its usage within `testExecute`, I could infer its structure and the meaning of its fields.
* The "copied from text/template" comment prompted me to consider the similarities and potential differences between `html/template` and `text/template`. While not explicitly detailed in the provided snippet, it's a useful piece of background information.
*  The skipped `TestTemplateLookUp` highlighted that even within a test file, some tests might be under development or have known issues.

By following this systematic approach, combining code analysis with an understanding of testing principles, and considering the context of the Go `html/template` package, I could arrive at a comprehensive explanation of the provided code snippet.
这段 `multi_test.go` 文件是 Go 语言 `html/template` 标准库的一部分，专门用于测试和验证在处理**多个模板**时的各种功能。它主要关注以下几个方面：

**1. 定义和执行多个模板:**

这个文件测试了如何在同一个 `template.Template` 对象中定义多个命名模板，并通过 `{{template "name" .}}` 语法来调用和执行这些子模板。

**Go 代码示例:**

```go
package main

import (
	"html/template"
	"os"
)

func main() {
	tmpl := template.New("root") // 创建一个根模板

	// 定义名为 "header" 的模板
	tmpl, err := tmpl.Parse(`{{define "header"}}<h1>网站标题</h1>{{end}}`)
	if err != nil {
		panic(err)
	}

	// 定义名为 "content" 的模板
	tmpl, err = tmpl.Parse(`{{define "content"}}<p>这是网站内容。</p>{{end}}`)
	if err != nil {
		panic(err)
	}

	// 定义名为 "main" 的主模板，并调用其他模板
	tmpl, err = tmpl.Parse(`
		<!DOCTYPE html>
		<html>
		<head><title>我的网站</title></head>
		<body>
			{{template "header"}}
			{{template "content"}}
		</body>
		</html>
	`)
	if err != nil {
		panic(err)
	}

	err = tmpl.Execute(os.Stdout, nil) // 执行主模板
	if err != nil {
		panic(err)
	}
}
```

**假设的输入与输出:**

在这个例子中，输入数据为 `nil`，因为模板内容是固定的。

**输出:**

```html
<!DOCTYPE html>
<html>
<head><title>我的网站</title></head>
<body>
<h1>网站标题</h1>
<p>这是网站内容。</p>
</body>
</html>
```

**2. 通过 `ParseFiles` 和 `ParseGlob` 加载多个模板文件:**

测试了 `ParseFiles` 函数用于从指定路径的文件中加载模板定义，以及 `ParseGlob` 函数用于根据通配符模式加载多个模板文件。

**Go 代码示例 (使用 `ParseFiles`):**

假设有 `header.tmpl` 和 `content.tmpl` 两个文件：

**header.tmpl:**
```html
<h1>网站标题</h1>
```

**content.tmpl:**
```html
<p>这是网站内容。</p>
```

**main.go:**

```go
package main

import (
	"html/template"
	"os"
)

func main() {
	tmpl := template.New("root")

	// 从多个文件中加载模板定义
	tmpl, err := tmpl.ParseFiles("header.tmpl", "content.tmpl", "main.tmpl")
	if err != nil {
		panic(err)
	}

	err = tmpl.ExecuteTemplate(os.Stdout, "main.tmpl", nil)
	if err != nil {
		panic(err)
	}
}
```

**main.tmpl:**
```html
<!DOCTYPE html>
<html>
<head><title>我的网站</title></head>
<body>
	{{template "header.tmpl"}}
	{{template "content.tmpl"}}
</body>
</html>
```

**假设的输入与输出:**

输入数据为 `nil`。

**输出:**

```html
<!DOCTYPE html>
<html>
<head><title>我的网站</title></head>
<body>
<h1>网站标题</h1>
<p>这是网站内容。</p>
</body>
</html>
```

**Go 代码示例 (使用 `ParseGlob`):**

假设 `templates` 目录下有 `header.tmpl` 和 `content.tmpl`。

```go
package main

import (
	"html/template"
	"os"
)

func main() {
	tmpl := template.New("root")

	// 使用通配符加载 templates 目录下的所有 .tmpl 文件
	tmpl, err := tmpl.ParseGlob("templates/*.tmpl")
	if err != nil {
		panic(err)
	}

	err = tmpl.ExecuteTemplate(os.Stdout, "main.tmpl", nil)
	if err != nil {
		panic(err)
	}
}
```

**假设的输入与输出:**

与 `ParseFiles` 示例类似，输入数据为 `nil`，输出也相同。

**3. 通过 `ParseFS` 从文件系统加载模板:**

测试了 `ParseFS` 函数，它可以从一个 `os.FS` 接口表示的文件系统中加载模板。这使得从嵌入式文件系统、zip 文件或其他自定义文件源加载模板成为可能。

**Go 代码示例:**

```go
package main

import (
	"embed"
	"html/template"
	"os"
)

//go:embed templates/*
var templates embed.FS

func main() {
	tmpl := template.New("root")

	// 从嵌入式文件系统中加载模板
	tmpl, err := tmpl.ParseFS(templates, "templates/header.tmpl", "templates/content.tmpl", "templates/main.tmpl")
	if err != nil {
		panic(err)
	}

	err = tmpl.ExecuteTemplate(os.Stdout, "templates/main.tmpl", nil)
	if err != nil {
		panic(err)
	}
}
```

**假设的输入与输出:**

输入数据为 `nil`，输出与之前的示例相同。

**4. 模板的重新定义 (`TestRedefinition`):**

测试了在同一个模板集合中重新定义同名模板的行为。Go 的 `html/template` 允许重新定义模板，后定义的会覆盖先定义的。

**Go 代码示例:**

```go
package main

import (
	"html/template"
	"os"
)

func main() {
	tmpl := template.New("myTemplate")

	// 定义名为 "myTemplate" 的模板
	tmpl, err := tmpl.Parse(`{{define "myTemplate"}}原始版本{{end}}`)
	if err != nil {
		panic(err)
	}

	// 重新定义名为 "myTemplate" 的模板
	tmpl, err = tmpl.Parse(`{{define "myTemplate"}}覆盖版本{{end}}`)
	if err != nil {
		panic(err)
	}

	err = tmpl.ExecuteTemplate(os.Stdout, "myTemplate", nil)
	if err != nil {
		panic(err)
	}
}
```

**假设的输入与输出:**

输入数据为 `nil`。

**输出:**

```
覆盖版本
```

**5. 空模板的处理 (`TestEmptyTemplate` 和 `TestIssue19294`):**

测试了如何处理空模板定义以及在模板调用链中可能出现的空模板的情况。

**6. 模板克隆 (`TestEmptyTemplateCloneCrash`):**

测试了克隆一个空模板是否会引起崩溃。

**7. 模板查找 (`TestTemplateLookUp`):**

测试了 `Lookup` 方法，用于在模板集合中查找已定义的模板。

**命令行参数处理:**

这个文件本身是一个测试文件，不直接处理命令行参数。但是，`ParseFiles` 和 `ParseGlob` 函数会涉及到文件路径和通配符模式的处理，这些可以被认为是间接的命令行参数处理，因为文件路径通常可以通过命令行传递给程序。

* **`ParseFiles(filenames ...string)`:** 接受一个或多个文件名作为参数。
* **`ParseGlob(pattern string)`:** 接受一个通配符模式作为参数，例如 `"templates/*.html"`。

**使用者易犯错的点:**

1. **模板名称冲突:**  如果在同一个 `template.Template` 对象中定义了多个同名的模板，后定义的会覆盖先定义的，这可能导致意外的结果。

   **示例:**

   ```go
   package main

   import (
   	"html/template"
   	"os"
   )

   func main() {
   	tmpl := template.New("root")
   	tmpl, _ = tmpl.Parse(`{{define "header"}}<h1>版本一</h1>{{end}}`)
   	tmpl, _ = tmpl.Parse(`{{define "header"}}<h1>版本二</h1>{{end}}`)

   	err := tmpl.ExecuteTemplate(os.Stdout, "header", nil) // 执行的是版本二
   	if err != nil {
   		panic(err)
   	}
   }
   ```

2. **在多次 `Parse` 调用中混合定义和内容:**  如果对同一个 `Template` 对象多次调用 `Parse`，只有其中一个调用可以包含非定义文本（即实际要渲染的内容）。其他调用应该只包含 `{{define}}` 块。

   **示例 (错误的做法):**

   ```go
   package main

   import (
   	"html/template"
   	"os"
   )

   func main() {
   	tmpl := template.New("page")
   	tmpl, _ = tmpl.Parse("<h1>欢迎</h1>") // 包含内容
   	tmpl, _ = tmpl.Parse(`{{define "footer"}}<p>版权所有</p>{{end}}`) // 定义

   	err := tmpl.Execute(os.Stdout, nil) // 可能出现意外结果或错误
   	if err != nil {
   		panic(err)
   	}
   }
   ```

   **正确的做法:**

   ```go
   package main

   import (
   	"html/template"
   	"os"
   )

   func main() {
   	tmpl := template.New("page")
   	tmpl, _ = tmpl.Parse(`
   		<h1>欢迎</h1>
   		{{define "footer"}}<p>版权所有</p>{{end}}
   	`)

   	err := tmpl.Execute(os.Stdout, nil)
   	if err != nil {
   		panic(err)
   	}
   }
   ```

3. **忘记在 `ParseFiles` 或 `ParseGlob` 后执行特定的模板:** 当使用 `ParseFiles` 或 `ParseGlob` 加载多个文件时，需要使用 `ExecuteTemplate` 方法并指定要执行的模板名称。

   **示例:**

   ```go
   package main

   import (
   	"html/template"
   	"os"
   )

   func main() {
   	tmpl, err := template.ParseFiles("header.tmpl", "content.tmpl")
   	if err != nil {
   		panic(err)
   	}

   	// 必须指定要执行的模板
   	err = tmpl.ExecuteTemplate(os.Stdout, "content.tmpl", nil)
   	if err != nil {
   		panic(err)
   	}
   }
   ```

总而言之，`multi_test.go` 文件全面地测试了 `html/template` 包在处理多个模板定义、加载、执行以及一些边界情况下的行为，确保了该功能的稳定性和可靠性。通过阅读和理解这些测试用例，开发者可以更深入地了解 `html/template` 的工作原理和最佳实践。

Prompt: 
```
这是路径为go/src/html/template/multi_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Tests for multiple-template execution, copied from text/template.

package template

import (
	"archive/zip"
	"os"
	"strings"
	"testing"
	"text/template/parse"
)

var multiExecTests = []execTest{
	{"empty", "", "", nil, true},
	{"text", "some text", "some text", nil, true},
	{"invoke x", `{{template "x" .SI}}`, "TEXT", tVal, true},
	{"invoke x no args", `{{template "x"}}`, "TEXT", tVal, true},
	{"invoke dot int", `{{template "dot" .I}}`, "17", tVal, true},
	{"invoke dot []int", `{{template "dot" .SI}}`, "[3 4 5]", tVal, true},
	{"invoke dotV", `{{template "dotV" .U}}`, "v", tVal, true},
	{"invoke nested int", `{{template "nested" .I}}`, "17", tVal, true},
	{"variable declared by template", `{{template "nested" $x:=.SI}},{{index $x 1}}`, "[3 4 5],4", tVal, true},

	// User-defined function: test argument evaluator.
	{"testFunc literal", `{{oneArg "joe"}}`, "oneArg=joe", tVal, true},
	{"testFunc .", `{{oneArg .}}`, "oneArg=joe", "joe", true},
}

// These strings are also in testdata/*.
const multiText1 = `
	{{define "x"}}TEXT{{end}}
	{{define "dotV"}}{{.V}}{{end}}
`

const multiText2 = `
	{{define "dot"}}{{.}}{{end}}
	{{define "nested"}}{{template "dot" .}}{{end}}
`

func TestMultiExecute(t *testing.T) {
	// Declare a couple of templates first.
	template, err := New("root").Parse(multiText1)
	if err != nil {
		t.Fatalf("parse error for 1: %s", err)
	}
	_, err = template.Parse(multiText2)
	if err != nil {
		t.Fatalf("parse error for 2: %s", err)
	}
	testExecute(multiExecTests, template, t)
}

func TestParseFiles(t *testing.T) {
	_, err := ParseFiles("DOES NOT EXIST")
	if err == nil {
		t.Error("expected error for non-existent file; got none")
	}
	template := New("root")
	_, err = template.ParseFiles("testdata/file1.tmpl", "testdata/file2.tmpl")
	if err != nil {
		t.Fatalf("error parsing files: %v", err)
	}
	testExecute(multiExecTests, template, t)
}

func TestParseGlob(t *testing.T) {
	_, err := ParseGlob("DOES NOT EXIST")
	if err == nil {
		t.Error("expected error for non-existent file; got none")
	}
	_, err = New("error").ParseGlob("[x")
	if err == nil {
		t.Error("expected error for bad pattern; got none")
	}
	template := New("root")
	_, err = template.ParseGlob("testdata/file*.tmpl")
	if err != nil {
		t.Fatalf("error parsing files: %v", err)
	}
	testExecute(multiExecTests, template, t)
}

func TestParseFS(t *testing.T) {
	fs := os.DirFS("testdata")

	{
		_, err := ParseFS(fs, "DOES NOT EXIST")
		if err == nil {
			t.Error("expected error for non-existent file; got none")
		}
	}

	{
		template := New("root")
		_, err := template.ParseFS(fs, "file1.tmpl", "file2.tmpl")
		if err != nil {
			t.Fatalf("error parsing files: %v", err)
		}
		testExecute(multiExecTests, template, t)
	}

	{
		template := New("root")
		_, err := template.ParseFS(fs, "file*.tmpl")
		if err != nil {
			t.Fatalf("error parsing files: %v", err)
		}
		testExecute(multiExecTests, template, t)
	}
}

// In these tests, actual content (not just template definitions) comes from the parsed files.

var templateFileExecTests = []execTest{
	{"test", `{{template "tmpl1.tmpl"}}{{template "tmpl2.tmpl"}}`, "template1\n\ny\ntemplate2\n\nx\n", 0, true},
}

func TestParseFilesWithData(t *testing.T) {
	template, err := New("root").ParseFiles("testdata/tmpl1.tmpl", "testdata/tmpl2.tmpl")
	if err != nil {
		t.Fatalf("error parsing files: %v", err)
	}
	testExecute(templateFileExecTests, template, t)
}

func TestParseGlobWithData(t *testing.T) {
	template, err := New("root").ParseGlob("testdata/tmpl*.tmpl")
	if err != nil {
		t.Fatalf("error parsing files: %v", err)
	}
	testExecute(templateFileExecTests, template, t)
}

func TestParseZipFS(t *testing.T) {
	z, err := zip.OpenReader("testdata/fs.zip")
	if err != nil {
		t.Fatalf("error parsing zip: %v", err)
	}
	template, err := New("root").ParseFS(z, "tmpl*.tmpl")
	if err != nil {
		t.Fatalf("error parsing files: %v", err)
	}
	testExecute(templateFileExecTests, template, t)
}

const (
	cloneText1 = `{{define "a"}}{{template "b"}}{{template "c"}}{{end}}`
	cloneText2 = `{{define "b"}}b{{end}}`
	cloneText3 = `{{define "c"}}root{{end}}`
	cloneText4 = `{{define "c"}}clone{{end}}`
)

// Issue 7032
func TestAddParseTreeToUnparsedTemplate(t *testing.T) {
	master := "{{define \"master\"}}{{end}}"
	tmpl := New("master")
	tree, err := parse.Parse("master", master, "", "", nil)
	if err != nil {
		t.Fatalf("unexpected parse err: %v", err)
	}
	masterTree := tree["master"]
	tmpl.AddParseTree("master", masterTree) // used to panic
}

func TestRedefinition(t *testing.T) {
	var tmpl *Template
	var err error
	if tmpl, err = New("tmpl1").Parse(`{{define "test"}}foo{{end}}`); err != nil {
		t.Fatalf("parse 1: %v", err)
	}
	if _, err = tmpl.Parse(`{{define "test"}}bar{{end}}`); err != nil {
		t.Fatalf("got error %v, expected nil", err)
	}
	if _, err = tmpl.New("tmpl2").Parse(`{{define "test"}}bar{{end}}`); err != nil {
		t.Fatalf("got error %v, expected nil", err)
	}
}

// Issue 10879
func TestEmptyTemplateCloneCrash(t *testing.T) {
	t1 := New("base")
	t1.Clone() // used to panic
}

// Issue 10910, 10926
func TestTemplateLookUp(t *testing.T) {
	t.Skip("broken on html/template") // TODO
	t1 := New("foo")
	if t1.Lookup("foo") != nil {
		t.Error("Lookup returned non-nil value for undefined template foo")
	}
	t1.New("bar")
	if t1.Lookup("bar") != nil {
		t.Error("Lookup returned non-nil value for undefined template bar")
	}
	t1.Parse(`{{define "foo"}}test{{end}}`)
	if t1.Lookup("foo") == nil {
		t.Error("Lookup returned nil value for defined template")
	}
}

func TestParse(t *testing.T) {
	// In multiple calls to Parse with the same receiver template, only one call
	// can contain text other than space, comments, and template definitions
	t1 := New("test")
	if _, err := t1.Parse(`{{define "test"}}{{end}}`); err != nil {
		t.Fatalf("parsing test: %s", err)
	}
	if _, err := t1.Parse(`{{define "test"}}{{/* this is a comment */}}{{end}}`); err != nil {
		t.Fatalf("parsing test: %s", err)
	}
	if _, err := t1.Parse(`{{define "test"}}foo{{end}}`); err != nil {
		t.Fatalf("parsing test: %s", err)
	}
}

func TestEmptyTemplate(t *testing.T) {
	cases := []struct {
		defn []string
		in   string
		want string
	}{
		{[]string{"x", "y"}, "", "y"},
		{[]string{""}, "once", ""},
		{[]string{"", ""}, "twice", ""},
		{[]string{"{{.}}", "{{.}}"}, "twice", "twice"},
		{[]string{"{{/* a comment */}}", "{{/* a comment */}}"}, "comment", ""},
		{[]string{"{{.}}", ""}, "twice", "twice"}, // TODO: should want "" not "twice"
	}

	for i, c := range cases {
		root := New("root")

		var (
			m   *Template
			err error
		)
		for _, d := range c.defn {
			m, err = root.New(c.in).Parse(d)
			if err != nil {
				t.Fatal(err)
			}
		}
		buf := &strings.Builder{}
		if err := m.Execute(buf, c.in); err != nil {
			t.Error(i, err)
			continue
		}
		if buf.String() != c.want {
			t.Errorf("expected string %q: got %q", c.want, buf.String())
		}
	}
}

// Issue 19249 was a regression in 1.8 caused by the handling of empty
// templates added in that release, which got different answers depending
// on the order templates appeared in the internal map.
func TestIssue19294(t *testing.T) {
	// The empty block in "xhtml" should be replaced during execution
	// by the contents of "stylesheet", but if the internal map associating
	// names with templates is built in the wrong order, the empty block
	// looks non-empty and this doesn't happen.
	var inlined = map[string]string{
		"stylesheet": `{{define "stylesheet"}}stylesheet{{end}}`,
		"xhtml":      `{{block "stylesheet" .}}{{end}}`,
	}
	all := []string{"stylesheet", "xhtml"}
	for i := 0; i < 100; i++ {
		res, err := New("title.xhtml").Parse(`{{template "xhtml" .}}`)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range all {
			_, err := res.New(name).Parse(inlined[name])
			if err != nil {
				t.Fatal(err)
			}
		}
		var buf strings.Builder
		res.Execute(&buf, 0)
		if buf.String() != "stylesheet" {
			t.Fatalf("iteration %d: got %q; expected %q", i, buf.String(), "stylesheet")
		}
	}
}

"""



```