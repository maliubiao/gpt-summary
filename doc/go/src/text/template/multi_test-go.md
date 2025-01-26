Response:
Let's break down the thought process for analyzing the provided Go code.

1. **Identify the Core Functionality:** The first step is to quickly scan the code for keywords and structures that reveal its purpose. Keywords like `test`, `parse`, `execute`, `define`, `template`, `files`, `glob`, `clone`, `AddParseTree` immediately jump out. The presence of `multiParseTest` and `multiExecTests` strongly suggests this code tests functionalities related to handling multiple templates.

2. **Categorize the Tests:**  Observing the distinct test functions like `TestMultiParse`, `TestMultiExecute`, `TestParseFiles`, `TestParseGlob`, `TestParseFS`, `TestClone`, and `TestAddParseTree` indicates different aspects of the `text/template` package being tested. This helps in organizing the analysis.

3. **Analyze Individual Test Functions:**

   * **`TestMultiParse`:** This test iterates through `multiParseTests`, which contain input strings, expected parse results (or errors), and names of defined templates. The core of the test is the `New("root").Parse(test.input)` call. This clearly tests the ability to parse multiple `{{define}}` blocks within a single input string. The assertions check for correct parsing and the presence of the defined templates.

   * **`TestMultiExecute`:** This test uses pre-parsed templates (`multiText1`, `multiText2`) and the `testExecute` helper function (not shown but assumed to handle execution and comparison). The `multiExecTests` array contains input templates, expected output, and data to pass to the template. This section focuses on testing how defined templates can be invoked within other templates using `{{template "name" .}}`. It demonstrates passing data (`.`, `.SI`, `.I`, `.U`) to the invoked templates.

   * **`TestParseFiles`, `TestParseGlob`, `TestParseFS`:** These tests clearly focus on parsing templates from external files. They test error handling for non-existent files and successful parsing from individual files or using glob patterns. The use of `testdata/file1.tmpl` and `testdata/file2.tmpl` is a strong indicator of this. The `os.DirFS` part in `TestParseFS` specifically highlights the testing of parsing from a file system abstraction.

   * **`TestClone`:**  This test demonstrates the `Clone()` method of the `Template` type. It creates a base template, adds definitions, clones it, adds more definitions to both the original and the clone, and then verifies that the original and the clone have their own separate sets of definitions.

   * **`TestAddParseTree`:** This test shows how to manually create a parse tree using `parse.Parse` and then add it to an existing `Template` using `AddParseTree`. This is a lower-level way to construct templates compared to parsing from strings or files.

   * **Other Tests (`TestRedefinition`, `TestEmptyTemplateCloneCrash`, `TestTemplateLookUp`, `TestNew`, `TestParse`, `TestEmptyTemplate`, `TestIssue19294`, `TestAddToZeroTemplate`):** These tests address specific edge cases, bug fixes, or more nuanced aspects of the `Template` API. They often involve setting up specific conditions and verifying expected behavior (or the absence of panics).

4. **Identify Go Language Features:** Based on the test functions, the key Go features being tested are:

   * **`text/template` package:**  The core focus.
   * **Template definition and invocation:**  Using `{{define}}` and `{{template}}`.
   * **Parsing templates from strings:**  Using `New().Parse()`.
   * **Parsing templates from files:** Using `ParseFiles()`, `ParseGlob()`, `ParseFS()`.
   * **Passing data to templates:** The dot `.` and field access.
   * **Cloning templates:** Using `Clone()`.
   * **Adding pre-parsed trees:** Using `AddParseTree()`.
   * **Error handling:** Checking for `error` returns.

5. **Illustrate with Go Code Examples:**  For each identified feature, create concise Go code examples that demonstrate its usage. This involves showing how to create templates, define them, execute them, and use the related functions like `ParseFiles` and `Clone`.

6. **Infer Functionality:** Based on the tests and examples, summarize the overall functionality of the code. This should include parsing multiple templates, executing named templates, handling template definitions from different sources, and the ability to clone and manipulate templates.

7. **Identify Command Line Arguments (If Applicable):** Carefully look for code that processes command-line arguments using packages like `flag`. In this specific code, the `*debug` flag is present. Explain its purpose and usage.

8. **Highlight Common Mistakes:** Analyze the test cases that check for errors. These often reveal common pitfalls for users. For example, the "missing end" and "malformed name" tests in `TestMultiParse` indicate potential syntax errors when defining templates. The discussion around `TestParse` highlights the limitation of having non-definition text in subsequent `Parse` calls on the same template.

9. **Structure the Answer:** Organize the findings logically, using clear headings and bullet points for readability. Start with the core functionality, then delve into specific features, code examples, command-line arguments, and common mistakes. Use clear and concise language.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This is just about parsing templates."
* **Correction:**  Realized that execution, cloning, and adding pre-parsed trees are also significant aspects being tested.
* **Initial thought:** "The command-line arguments are complex."
* **Correction:** Noticed only the `debug` flag is present and its usage is straightforward (for printing debug output).
* **Initial thought:** "The error handling tests are just boilerplate."
* **Correction:** Recognized that these tests point to common syntax errors users might encounter.

By following this structured thought process, combining code analysis with an understanding of the underlying concepts of the `text/template` package, a comprehensive and accurate explanation can be generated.这段代码是 Go 语言 `text/template` 标准库中 `multi_test.go` 文件的一部分，它专门用于测试 `text/template` 包中关于**多模板处理**的功能。

具体来说，它测试了以下几个核心功能：

1. **解析多个模板定义:** 代码测试了在同一个输入字符串中解析多个使用 `{{define "name"}}...{{end}}` 定义的模板。
2. **执行指定的模板:** 代码测试了如何通过 `{{template "name" .}}` 语法在一个模板中调用另一个已定义的模板。
3. **从文件中解析模板:** 代码测试了如何使用 `ParseFiles` 和 `ParseGlob` 函数从一个或多个文件中解析模板定义。
4. **从 `fs.FS` 解析模板:** 代码测试了如何使用 `ParseFS` 函数从一个 `fs.FS` 接口指定的虚拟文件系统中解析模板。
5. **克隆模板:** 代码测试了 `Clone()` 方法，用于创建一个现有模板的副本，并且副本可以独立修改和执行。
6. **添加已解析的语法树:** 代码测试了 `AddParseTree()` 方法，允许将预先解析好的模板语法树添加到现有模板中。
7. **模板重定义:** 代码测试了在同一个模板集合中重新定义模板的行为。
8. **查找模板:** 代码测试了 `Lookup()` 方法，用于查找已定义的模板。
9. **创建新模板:** 代码测试了 `New()` 方法在创建新模板时的行为，特别是与已存在同名模板的关系。
10. **多次解析:** 代码测试了对同一个模板实例多次调用 `Parse` 方法的行为，以及对非模板定义内容的限制。
11. **空模板处理:** 代码测试了如何处理和执行内容为空的模板定义。

**以下是一些功能的 Go 代码示例说明：**

**1. 解析多个模板定义和执行指定模板:**

```go
package main

import (
	"fmt"
	"os"
	"text/template"
)

func main() {
	// 定义包含多个模板的字符串
	const multiTemplateString = `
		{{define "header"}}
		<h1>Welcome</h1>
		{{end}}

		{{define "content"}}
		<p>{{.}}</p>
		{{end}}

		{{define "footer"}}
		<p>Copyright 2023</p>
		{{end}}

		{{template "header"}}
		{{template "content" "This is the main content."}}
		{{template "footer"}}
	`

	// 创建一个新的模板
	tmpl := template.New("webpage")

	// 解析模板字符串
	_, err := tmpl.Parse(multiTemplateString)
	if err != nil {
		panic(err)
	}

	// 执行根模板（实际上执行了嵌套的模板）
	err = tmpl.Execute(os.Stdout, nil)
	if err != nil {
		panic(err)
	}
}

// 假设的输出：
//
//		<h1>Welcome</h1>
//		<p>This is the main content.</p>
//		<p>Copyright 2023</p>
```

**2. 从文件中解析模板:**

假设 `testdata` 目录下有两个文件 `header.tmpl` 和 `content.tmpl`：

* **testdata/header.tmpl:**
  ```html
  <h1>Header from file</h1>
  ```
* **testdata/content.tmpl:**
  ```html
  <p>Content from file: {{.}}</p>
  ```

```go
package main

import (
	"fmt"
	"os"
	"text/template"
)

func main() {
	// 创建一个新的模板
	tmpl := template.New("page")

	// 解析多个模板文件
	tmpl, err := tmpl.ParseFiles("testdata/header.tmpl", "testdata/content.tmpl")
	if err != nil {
		panic(err)
	}

	// 执行名为 "content.tmpl" 的模板，传递数据 "Hello from file!"
	err = tmpl.ExecuteTemplate(os.Stdout, "content.tmpl", "Hello from file!")
	if err != nil {
		panic(err)
	}
}

// 假设的输出：
//
//		<p>Content from file: Hello from file!</p>
```

**3. 克隆模板:**

```go
package main

import (
	"fmt"
	"os"
	"strings"
	"text/template"
)

func main() {
	// 创建一个基础模板
	baseTmpl, err := template.New("base").Parse(`{{define "greeting"}}Hello, {{.Name}}!{{end}}`)
	if err != nil {
		panic(err)
	}

	// 克隆基础模板
	clonedTmpl, err := baseTmpl.Clone()
	if err != nil {
		panic(err)
	}

	// 在克隆的模板中添加新的定义
	_, err = clonedTmpl.Parse(`{{define "farewell"}}Goodbye, {{.Name}}!{{end}}`)
	if err != nil {
		panic(err)
	}

	data := map[string]string{"Name": "World"}
	var buf strings.Builder

	// 执行基础模板
	err = baseTmpl.ExecuteTemplate(&buf, "greeting", data)
	if err != nil {
		panic(err)
	}
	fmt.Println("Base Template:", buf.String()) // 输出: Base Template: Hello, World!
	buf.Reset()

	// 执行克隆的模板（包含新的定义）
	err = clonedTmpl.ExecuteTemplate(&buf, "farewell", data)
	if err != nil {
		panic(err)
	}
	fmt.Println("Cloned Template:", buf.String()) // 输出: Cloned Template: Goodbye, World!
}
```

**命令行参数的具体处理:**

这段代码本身是一个测试文件，并不直接处理命令行参数。但是，它引入了一个全局变量 `*debug`，这通常是通过构建标签或测试标志来控制的。在实际的 `text/template` 包中，并没有直接暴露用户可配置的命令行参数。

**使用者易犯错的点:**

1. **模板定义名称冲突:** 如果在同一个模板集合中定义了同名的模板，后续的定义会覆盖之前的定义，但不会报错。这可能会导致意外的行为。

   ```go
   package main

   import (
   	"fmt"
   	"os"
   	"text/template"
   )

   func main() {
   	tmpl := template.New("mytemplate")
   	_, err := tmpl.Parse(`{{define "myblock"}}Version 1{{end}}`)
   	if err != nil {
   		panic(err)
   	}
   	_, err = tmpl.Parse(`{{define "myblock"}}Version 2{{end}}`)
   	if err != nil {
   		panic(err)
   	}

   	err = tmpl.ExecuteTemplate(os.Stdout, "myblock", nil)
   	if err != nil {
   		panic(err)
   	}
   }

   // 输出： Version 2
   ```

2. **在 `Parse` 方法中混合定义和非定义内容:**  对于同一个模板实例多次调用 `Parse` 方法时，只有第一次调用可以包含非模板定义的内容（例如普通的文本）。后续的 `Parse` 调用应该只包含模板定义。

   ```go
   package main

   import (
   	"fmt"
   	"os"
   	"text/template"
   )

   func main() {
   	tmpl := template.New("mytemplate")
   	_, err := tmpl.Parse("This is some initial text. {{define \"myblock\"}}My Block{{end}}")
   	if err != nil {
   		panic(err)
   	}
   	_, err = tmpl.Parse("{{define \"anotherblock\"}}Another Block{{end}} More text.")
   	if err != nil {
   		fmt.Println("Error:", err) // 这里会报错，因为第二次 Parse 包含了非定义文本
   	}

   	err = tmpl.Execute(os.Stdout, nil)
   	if err != nil {
   		panic(err)
   	}
   }
   ```

总的来说，`multi_test.go` 这部分代码全面地测试了 `text/template` 包处理多个模板定义和组合使用的能力，确保了该库在复杂场景下的稳定性和正确性。

Prompt: 
```
这是路径为go/src/text/template/multi_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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

// Tests for multiple-template parsing and execution.

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"text/template/parse"
)

const (
	noError  = true
	hasError = false
)

type multiParseTest struct {
	name    string
	input   string
	ok      bool
	names   []string
	results []string
}

var multiParseTests = []multiParseTest{
	{"empty", "", noError,
		nil,
		nil},
	{"one", `{{define "foo"}} FOO {{end}}`, noError,
		[]string{"foo"},
		[]string{" FOO "}},
	{"two", `{{define "foo"}} FOO {{end}}{{define "bar"}} BAR {{end}}`, noError,
		[]string{"foo", "bar"},
		[]string{" FOO ", " BAR "}},
	// errors
	{"missing end", `{{define "foo"}} FOO `, hasError,
		nil,
		nil},
	{"malformed name", `{{define "foo}} FOO `, hasError,
		nil,
		nil},
}

func TestMultiParse(t *testing.T) {
	for _, test := range multiParseTests {
		template, err := New("root").Parse(test.input)
		switch {
		case err == nil && !test.ok:
			t.Errorf("%q: expected error; got none", test.name)
			continue
		case err != nil && test.ok:
			t.Errorf("%q: unexpected error: %v", test.name, err)
			continue
		case err != nil && !test.ok:
			// expected error, got one
			if *debug {
				fmt.Printf("%s: %s\n\t%s\n", test.name, test.input, err)
			}
			continue
		}
		if template == nil {
			continue
		}
		if len(template.tmpl) != len(test.names)+1 { // +1 for root
			t.Errorf("%s: wrong number of templates; wanted %d got %d", test.name, len(test.names), len(template.tmpl))
			continue
		}
		for i, name := range test.names {
			tmpl, ok := template.tmpl[name]
			if !ok {
				t.Errorf("%s: can't find template %q", test.name, name)
				continue
			}
			result := tmpl.Root.String()
			if result != test.results[i] {
				t.Errorf("%s=(%q): got\n\t%v\nexpected\n\t%v", test.name, test.input, result, test.results[i])
			}
		}
	}
}

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

const (
	cloneText1 = `{{define "a"}}{{template "b"}}{{template "c"}}{{end}}`
	cloneText2 = `{{define "b"}}b{{end}}`
	cloneText3 = `{{define "c"}}root{{end}}`
	cloneText4 = `{{define "c"}}clone{{end}}`
)

func TestClone(t *testing.T) {
	// Create some templates and clone the root.
	root, err := New("root").Parse(cloneText1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = root.Parse(cloneText2)
	if err != nil {
		t.Fatal(err)
	}
	clone := Must(root.Clone())
	// Add variants to both.
	_, err = root.Parse(cloneText3)
	if err != nil {
		t.Fatal(err)
	}
	_, err = clone.Parse(cloneText4)
	if err != nil {
		t.Fatal(err)
	}
	// Verify that the clone is self-consistent.
	for k, v := range clone.tmpl {
		if k == clone.name && v.tmpl[k] != clone {
			t.Error("clone does not contain root")
		}
		if v != v.tmpl[v.name] {
			t.Errorf("clone does not contain self for %q", k)
		}
	}
	// Execute root.
	var b strings.Builder
	err = root.ExecuteTemplate(&b, "a", 0)
	if err != nil {
		t.Fatal(err)
	}
	if b.String() != "broot" {
		t.Errorf("expected %q got %q", "broot", b.String())
	}
	// Execute copy.
	b.Reset()
	err = clone.ExecuteTemplate(&b, "a", 0)
	if err != nil {
		t.Fatal(err)
	}
	if b.String() != "bclone" {
		t.Errorf("expected %q got %q", "bclone", b.String())
	}
}

func TestAddParseTree(t *testing.T) {
	// Create some templates.
	root, err := New("root").Parse(cloneText1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = root.Parse(cloneText2)
	if err != nil {
		t.Fatal(err)
	}
	// Add a new parse tree.
	tree, err := parse.Parse("cloneText3", cloneText3, "", "", nil, builtins())
	if err != nil {
		t.Fatal(err)
	}
	added, err := root.AddParseTree("c", tree["c"])
	if err != nil {
		t.Fatal(err)
	}
	// Execute.
	var b strings.Builder
	err = added.ExecuteTemplate(&b, "a", 0)
	if err != nil {
		t.Fatal(err)
	}
	if b.String() != "broot" {
		t.Errorf("expected %q got %q", "broot", b.String())
	}
}

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

func TestNew(t *testing.T) {
	// template with same name already exists
	t1, _ := New("test").Parse(`{{define "test"}}foo{{end}}`)
	t2 := t1.New("test")

	if t1.common != t2.common {
		t.Errorf("t1 & t2 didn't share common struct; got %v != %v", t1.common, t2.common)
	}
	if t1.Tree == nil {
		t.Error("defined template got nil Tree")
	}
	if t2.Tree != nil {
		t.Error("undefined template got non-nil Tree")
	}

	containsT1 := false
	for _, tmpl := range t1.Templates() {
		if tmpl == t2 {
			t.Error("Templates included undefined template")
		}
		if tmpl == t1 {
			containsT1 = true
		}
	}
	if !containsT1 {
		t.Error("Templates didn't include defined template")
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
		{[]string{"{{.}}", ""}, "twice", ""},
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

// Issue 48436
func TestAddToZeroTemplate(t *testing.T) {
	tree, err := parse.Parse("c", cloneText3, "", "", nil, builtins())
	if err != nil {
		t.Fatal(err)
	}
	var tmpl Template
	tmpl.AddParseTree("x", tree["c"])
}

"""



```