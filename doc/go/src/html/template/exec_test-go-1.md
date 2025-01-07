Response:
The user wants a summary of the functionalities present in the provided Go code snippet. This code is part of the `exec_test.go` file within the `html/template` package in the Go standard library. It seems to be testing the execution logic of HTML templates.

Here's a breakdown of the code's functions:

1. **Basic Execution:** Tests the core `Execute` functionality of templates.
2. **Custom Delimiters:** Checks if the template engine can handle different delimiters for actions.
3. **Error Handling:** Tests how errors during template execution are propagated and formatted, including nested template errors.
4. **JavaScript Escaping:**  Verifies the `JSEscapeString` function for correct escaping of strings for use in JavaScript.
5. **Template with Data Structures:** Demonstrates the use of templates with complex data structures like trees and how to iterate or access their members.
6. **Template Definition and Lookup:** Tests defining and looking up templates by name.
7. **Handling Empty Templates:** Checks the error messages produced when trying to execute empty or incomplete templates.
8. **`printf` Function:** Verifies the functionality of the `printf` built-in function within templates.
9. **Comparison Operators:**  Extensively tests the behavior of comparison operators (eq, ne, lt, le, gt, ge) in templates with various data types, including signed/unsigned integers and potential error conditions.
10. **Handling Missing Map Keys:**  Tests different strategies for handling missing keys in maps during template execution, including default value, zero value, and error reporting.
11. **Error Reporting for Unterminated Strings:**  Confirms that the error message for unterminated strings in templates points to the correct line number.
12. **Differentiating Execution Errors:** Tests the difference between general errors and `ExecError` during template execution.
13. **Validating Function Names:** Checks the rules for valid function names within template `FuncMap`.
14. **Template Blocks:** Tests the functionality of `block` and `define` actions for template inheritance and overriding.
15. **Handling Field Evaluation Errors:** Tests the error messages generated when trying to access missing or invalid fields on different types (nil pointers, non-nil pointers, maps).
16. **Maximum Execution Depth:** Tests the mechanism to prevent infinite recursion in templates by setting a maximum execution depth.
17. **Addressability in Indexing:**  Verifies that the `index` function works correctly with addressable values.
18. **Interface Handling:** Tests how template execution handles interface values, including nil interfaces and function calls on interfaces.
19. **Panic Recovery in Function Calls:**  Ensures that panics occurring within functions called from templates are caught and returned as errors.
20. **Parenthesized Arguments (Issue 31810):** Tests the behavior of parenthesized expressions as arguments in template actions. (Note: This is marked as skipped in `html/template`).
21. **Concurrency Safety (Issue 39807):** Checks for race conditions when applying template escaping in a concurrent environment.
22. **Recursive Template Execution:** Tests scenarios involving templates calling themselves recursively, both directly and via methods.
23. **`Funcs` after `Clone` (Issue 43295):** Verifies that function maps added to a template are correctly retained after cloning the template.
这是 `go/src/html/template/exec_test.go` 文件的一部分，主要集中在测试 `html/template` 包中模板的**执行（Execute）**功能。以下是对其功能的归纳：

**核心功能：测试 HTML 模板的执行逻辑**

这部分代码通过编写各种测试用例，验证 `html/template` 包在执行模板时的行为是否符合预期。它涵盖了模板执行过程中的各种情况，包括：

* **基本执行：** 验证简单的模板和数据的渲染结果。
* **自定义分隔符：** 测试使用非默认分隔符 (`{{` 和 `}}`) 的模板。
* **错误处理：** 测试在模板执行过程中发生的各种错误，例如访问不存在的字段、索引越界、调用错误函数等，并验证错误信息的准确性。
* **JavaScript 转义：** 测试 `JSEscapeString` 函数是否正确转义字符串，以防止在 JavaScript 代码中出现安全漏洞。
* **复杂数据结构：** 测试模板如何处理和渲染复杂的数据结构，例如结构体和树。
* **模板定义和查找：** 测试在模板中定义和引用其他模板的功能。
* **空模板处理：** 测试执行空模板或不完整模板时的错误信息。
* **内置函数：** 测试内置函数，例如 `printf` 的功能。
* **比较运算符：**  详细测试了各种比较运算符（`eq`、`ne`、`lt`、`le`、`gt`、`ge`）在模板中的行为，包括不同数据类型之间的比较和错误情况。
* **缺失的 Map 键：** 测试当模板尝试访问 Map 中不存在的键时，不同的处理策略（默认值、零值、错误）。
* **未结束的字符串：** 测试模板解析器在遇到未结束的字符串时的错误报告，并验证错误信息是否包含正确的行号。
* **执行错误与解析错误：** 区分模板解析时发生的错误和模板执行时发生的错误。
* **函数名称验证：** 测试 `FuncMap` 中函数名称的有效性规则。
* **模板块（Block）：** 测试 `block` 和 `define` 动作，用于创建可覆盖的模板区域。
* **字段访问错误：** 测试访问不存在的字段或在 `nil` 指针上访问字段时的错误信息。
* **最大执行深度：** 测试模板执行的最大递归深度限制，防止无限循环。
* **`index` 函数的地址：** 测试 `index` 函数在处理可寻址值时的行为。
* **接口值的处理：** 测试模板如何处理接口类型的值，包括 `nil` 接口。
* **函数调用中的 Panic 恢复：** 测试当模板调用的 Go 函数发生 `panic` 时，模板引擎是否能够捕获并返回错误。
* **带括号的参数（Issue 31810）：**  测试模板中带括号的参数的解析和执行（在 `html/template` 中被跳过）。
* **并发安全（Issue 39807）：** 测试在并发执行模板时，转义操作的线程安全性。
* **递归执行：** 测试模板的递归调用。
* **克隆后添加函数（Issue 43295）：** 测试克隆模板后添加的函数是否仍然可用。

**代码示例与推理**

虽然这部分代码主要是测试，但我们可以从测试用例中推断出一些 `html/template` 的功能。

**1. 自定义分隔符 (`Delims`)**

假设我们想使用 `|` 作为模板动作的起始和结束符。

```go
package main

import (
	"fmt"
	"html/template"
	"os"
)

func main() {
	text := "|.Name|"
	tmpl, err := template.New("test").Delims("|", "|").Parse(text)
	if err != nil {
		panic(err)
	}

	data := struct {
		Name string
	}{
		Name: "World",
	}

	err = tmpl.Execute(os.Stdout, data)
	if err != nil {
		panic(err)
	}
}
```

**假设的输入：** 上述 Go 代码
**输出：** `World`

**2. 错误处理 (`ExecuteError`)**

假设我们的数据结构中有一个会返回错误的函数。

```go
package main

import (
	"bytes"
	"errors"
	"html/template"
	"os"
)

type MyData struct{}

func (MyData) MyError(shouldError bool) (string, error) {
	if shouldError {
		return "", errors.New("something went wrong")
	}
	return "No error", nil
}

func main() {
	tmpl, err := template.New("errorTest").Parse("{{.MyError true}}")
	if err != nil {
		panic(err)
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, MyData{})
	if err != nil {
		fmt.Println("Execution error:", err)
	}
}
```

**假设的输入：** 上述 Go 代码
**输出（包含 `something went wrong`）：** `Execution error: template: errorTest:1:3: executing "errorTest" at <.MyError true>: error calling method MyError: something went wrong`

**3. 嵌套模板错误 (`ExecError`)**

假设我们有多个嵌套的模板，并且最内层的模板访问了一个超出范围的索引。

```go
package main

import (
	"bytes"
	"html/template"
	"os"
)

func main() {
	const execErrorText = `{{template "one" .}}
{{define "one"}}{{template "two" .}}{{end}}
{{define "two"}}{{template "three" .}}{{end}}
{{define "three"}}{{index "hi" .}}{{end}}`

	tmpl, err := template.New("top").Parse(execErrorText)
	if err != nil {
		panic(err)
	}

	var b bytes.Buffer
	err = tmpl.Execute(&b, 5) // 索引 "hi" 的长度为 2，索引 5 超出范围
	if err != nil {
		fmt.Println(err)
	}
}
```

**假设的输入：** 上述 Go 代码
**输出（包含索引越界信息）：** `template: top:4:20: executing "three" at <index "hi" .>: error calling index: index out of range: 5`

**4. JavaScript 转义 (`JSEscaping`)**

```go
package main

import (
	"fmt"
	"html/template"
)

func main() {
	input := `'foo`
	escaped := template.JSEscapeString(input)
	fmt.Println(escaped)
}
```

**假设的输入：** 上述 Go 代码
**输出：** `\'foo`

**5. 处理缺失的 Map 键 (`MissingMapKey`)**

```go
package main

import (
	"bytes"
	"html/template"
	"log"
)

func main() {
	data := map[string]int{
		"x": 99,
	}
	tmpl, err := template.New("t1").Parse("{{.x}} {{.y}}")
	if err != nil {
		log.Fatal(err)
	}
	var b bytes.Buffer
	err = tmpl.Execute(&b, data)
	if err != nil {
		log.Fatal(err)
	}
	println(b.String()) // 输出 "99 "，因为 .y 缺失，默认输出 "<no value>" 在 html/template 中为空字符串
}
```

**假设的输入：** 上述 Go 代码
**输出：** `99 `

如果设置 `missingkey=zero` 选项：

```go
// ... (前面部分相同)
	tmpl.Option("missingkey=zero")
	b.Reset()
	err = tmpl.Execute(&b, data)
	if err != nil {
		log.Fatal(err)
	}
	println(b.String())
```

**假设的输入：** 上述 Go 代码
**输出：** `99 0`

如果设置 `missingkey=error` 选项：

```go
// ... (前面部分相同)
	tmpl.Option("missingkey=error")
	err = tmpl.Execute(&b, data)
	if err != nil {
		println(err.Error()) // 输出错误信息
	}
```

**假设的输入：** 上述 Go 代码
**输出（包含 "y" 键不存在的信息）：** `template: t1:1:4: executing "t1" at <.y>: map has no entry for key "y"`

**命令行参数处理：**

这段代码本身并没有直接处理命令行参数。它是单元测试代码，通常通过 `go test` 命令来运行。`go test` 命令有一些标准的命令行参数，例如 `-v` (显示详细输出), `-run` (运行指定的测试用例) 等。这些参数由 `go test` 工具处理，而不是由这段代码本身处理。

**使用者易犯错的点：**

* **忘记处理模板执行错误：**  执行 `tmpl.Execute` 方法会返回一个 `error`，使用者需要检查并处理这个错误，否则可能会导致程序异常。
* **混淆模板语法：**  模板语法有一定的规则，例如变量的访问、函数的调用等，初学者容易混淆。
* **不注意 HTML 转义：**  `html/template` 会自动进行 HTML 转义，但在某些场景下可能需要禁用或进行特定的转义，使用者需要了解其行为。
* **自定义分隔符的使用场景：**  虽然可以自定义分隔符，但需要确保模板内容和代码中的设置一致，否则会导致解析错误。
* **对 `missingkey` 选项理解不足：**  不清楚不同 `missingkey` 选项的含义，可能导致输出不符合预期或程序崩溃。

总而言之，这段测试代码全面地验证了 `html/template` 包在执行模板时的各种功能和边界情况，为开发者提供了信心，确保模板引擎的稳定性和可靠性。

Prompt: 
```
这是路径为go/src/html/template/exec_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
c TestExecute(t *testing.T) {
	testExecute(execTests, nil, t)
}

var delimPairs = []string{
	"", "", // default
	"{{", "}}", // same as default
	"|", "|", // same
	"(日)", "(本)", // peculiar
}

func TestDelims(t *testing.T) {
	const hello = "Hello, world"
	var value = struct{ Str string }{hello}
	for i := 0; i < len(delimPairs); i += 2 {
		text := ".Str"
		left := delimPairs[i+0]
		trueLeft := left
		right := delimPairs[i+1]
		trueRight := right
		if left == "" { // default case
			trueLeft = "{{"
		}
		if right == "" { // default case
			trueRight = "}}"
		}
		text = trueLeft + text + trueRight
		// Now add a comment
		text += trueLeft + "/*comment*/" + trueRight
		// Now add  an action containing a string.
		text += trueLeft + `"` + trueLeft + `"` + trueRight
		// At this point text looks like `{{.Str}}{{/*comment*/}}{{"{{"}}`.
		tmpl, err := New("delims").Delims(left, right).Parse(text)
		if err != nil {
			t.Fatalf("delim %q text %q parse err %s", left, text, err)
		}
		var b = new(strings.Builder)
		err = tmpl.Execute(b, value)
		if err != nil {
			t.Fatalf("delim %q exec err %s", left, err)
		}
		if b.String() != hello+trueLeft {
			t.Errorf("expected %q got %q", hello+trueLeft, b.String())
		}
	}
}

// Check that an error from a method flows back to the top.
func TestExecuteError(t *testing.T) {
	b := new(bytes.Buffer)
	tmpl := New("error")
	_, err := tmpl.Parse("{{.MyError true}}")
	if err != nil {
		t.Fatalf("parse error: %s", err)
	}
	err = tmpl.Execute(b, tVal)
	if err == nil {
		t.Errorf("expected error; got none")
	} else if !strings.Contains(err.Error(), myError.Error()) {
		if *debug {
			fmt.Printf("test execute error: %s\n", err)
		}
		t.Errorf("expected myError; got %s", err)
	}
}

const execErrorText = `line 1
line 2
line 3
{{template "one" .}}
{{define "one"}}{{template "two" .}}{{end}}
{{define "two"}}{{template "three" .}}{{end}}
{{define "three"}}{{index "hi" $}}{{end}}`

// Check that an error from a nested template contains all the relevant information.
func TestExecError(t *testing.T) {
	tmpl, err := New("top").Parse(execErrorText)
	if err != nil {
		t.Fatal("parse error:", err)
	}
	var b bytes.Buffer
	err = tmpl.Execute(&b, 5) // 5 is out of range indexing "hi"
	if err == nil {
		t.Fatal("expected error")
	}
	const want = `template: top:7:20: executing "three" at <index "hi" $>: error calling index: index out of range: 5`
	got := err.Error()
	if got != want {
		t.Errorf("expected\n%q\ngot\n%q", want, got)
	}
}

func TestJSEscaping(t *testing.T) {
	testCases := []struct {
		in, exp string
	}{
		{`a`, `a`},
		{`'foo`, `\'foo`},
		{`Go "jump" \`, `Go \"jump\" \\`},
		{`Yukihiro says "今日は世界"`, `Yukihiro says \"今日は世界\"`},
		{"unprintable \uFFFE", `unprintable \uFFFE`},
		{`<html>`, `\u003Chtml\u003E`},
		{`no = in attributes`, `no \u003D in attributes`},
		{`&#x27; does not become HTML entity`, `\u0026#x27; does not become HTML entity`},
	}
	for _, tc := range testCases {
		s := JSEscapeString(tc.in)
		if s != tc.exp {
			t.Errorf("JS escaping [%s] got [%s] want [%s]", tc.in, s, tc.exp)
		}
	}
}

// A nice example: walk a binary tree.

type Tree struct {
	Val         int
	Left, Right *Tree
}

// Use different delimiters to test Set.Delims.
// Also test the trimming of leading and trailing spaces.
const treeTemplate = `
	(- define "tree" -)
	[
		(- .Val -)
		(- with .Left -)
			(template "tree" . -)
		(- end -)
		(- with .Right -)
			(- template "tree" . -)
		(- end -)
	]
	(- end -)
`

func TestTree(t *testing.T) {
	var tree = &Tree{
		1,
		&Tree{
			2, &Tree{
				3,
				&Tree{
					4, nil, nil,
				},
				nil,
			},
			&Tree{
				5,
				&Tree{
					6, nil, nil,
				},
				nil,
			},
		},
		&Tree{
			7,
			&Tree{
				8,
				&Tree{
					9, nil, nil,
				},
				nil,
			},
			&Tree{
				10,
				&Tree{
					11, nil, nil,
				},
				nil,
			},
		},
	}
	tmpl, err := New("root").Delims("(", ")").Parse(treeTemplate)
	if err != nil {
		t.Fatal("parse error:", err)
	}
	var b strings.Builder
	const expect = "[1[2[3[4]][5[6]]][7[8[9]][10[11]]]]"
	// First by looking up the template.
	err = tmpl.Lookup("tree").Execute(&b, tree)
	if err != nil {
		t.Fatal("exec error:", err)
	}
	result := b.String()
	if result != expect {
		t.Errorf("expected %q got %q", expect, result)
	}
	// Then direct to execution.
	b.Reset()
	err = tmpl.ExecuteTemplate(&b, "tree", tree)
	if err != nil {
		t.Fatal("exec error:", err)
	}
	result = b.String()
	if result != expect {
		t.Errorf("expected %q got %q", expect, result)
	}
}

func TestExecuteOnNewTemplate(t *testing.T) {
	// This is issue 3872.
	New("Name").Templates()
	// This is issue 11379.
	// new(Template).Templates() // TODO: crashes
	// new(Template).Parse("") // TODO: crashes
	// new(Template).New("abc").Parse("") // TODO: crashes
	// new(Template).Execute(nil, nil)                // TODO: crashes; returns an error (but does not crash)
	// new(Template).ExecuteTemplate(nil, "XXX", nil) // TODO: crashes; returns an error (but does not crash)
}

const testTemplates = `{{define "one"}}one{{end}}{{define "two"}}two{{end}}`

func TestMessageForExecuteEmpty(t *testing.T) {
	// Test a truly empty template.
	tmpl := New("empty")
	var b bytes.Buffer
	err := tmpl.Execute(&b, 0)
	if err == nil {
		t.Fatal("expected initial error")
	}
	got := err.Error()
	want := `template: "empty" is an incomplete or empty template` // NOTE: text/template has extra "empty: " in message
	if got != want {
		t.Errorf("expected error %s got %s", want, got)
	}

	// Add a non-empty template to check that the error is helpful.
	tmpl = New("empty")
	tests, err := New("").Parse(testTemplates)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.AddParseTree("secondary", tests.Tree)
	err = tmpl.Execute(&b, 0)
	if err == nil {
		t.Fatal("expected second error")
	}
	got = err.Error()
	if got != want {
		t.Errorf("expected error %s got %s", want, got)
	}
	// Make sure we can execute the secondary.
	err = tmpl.ExecuteTemplate(&b, "secondary", 0)
	if err != nil {
		t.Fatal(err)
	}
}

func TestFinalForPrintf(t *testing.T) {
	tmpl, err := New("").Parse(`{{"x" | printf}}`)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	err = tmpl.Execute(&b, 0)
	if err != nil {
		t.Fatal(err)
	}
}

type cmpTest struct {
	expr  string
	truth string
	ok    bool
}

var cmpTests = []cmpTest{
	{"eq true true", "true", true},
	{"eq true false", "false", true},
	{"eq 1+2i 1+2i", "true", true},
	{"eq 1+2i 1+3i", "false", true},
	{"eq 1.5 1.5", "true", true},
	{"eq 1.5 2.5", "false", true},
	{"eq 1 1", "true", true},
	{"eq 1 2", "false", true},
	{"eq `xy` `xy`", "true", true},
	{"eq `xy` `xyz`", "false", true},
	{"eq .Uthree .Uthree", "true", true},
	{"eq .Uthree .Ufour", "false", true},
	{"eq 3 4 5 6 3", "true", true},
	{"eq 3 4 5 6 7", "false", true},
	{"ne true true", "false", true},
	{"ne true false", "true", true},
	{"ne 1+2i 1+2i", "false", true},
	{"ne 1+2i 1+3i", "true", true},
	{"ne 1.5 1.5", "false", true},
	{"ne 1.5 2.5", "true", true},
	{"ne 1 1", "false", true},
	{"ne 1 2", "true", true},
	{"ne `xy` `xy`", "false", true},
	{"ne `xy` `xyz`", "true", true},
	{"ne .Uthree .Uthree", "false", true},
	{"ne .Uthree .Ufour", "true", true},
	{"lt 1.5 1.5", "false", true},
	{"lt 1.5 2.5", "true", true},
	{"lt 1 1", "false", true},
	{"lt 1 2", "true", true},
	{"lt `xy` `xy`", "false", true},
	{"lt `xy` `xyz`", "true", true},
	{"lt .Uthree .Uthree", "false", true},
	{"lt .Uthree .Ufour", "true", true},
	{"le 1.5 1.5", "true", true},
	{"le 1.5 2.5", "true", true},
	{"le 2.5 1.5", "false", true},
	{"le 1 1", "true", true},
	{"le 1 2", "true", true},
	{"le 2 1", "false", true},
	{"le `xy` `xy`", "true", true},
	{"le `xy` `xyz`", "true", true},
	{"le `xyz` `xy`", "false", true},
	{"le .Uthree .Uthree", "true", true},
	{"le .Uthree .Ufour", "true", true},
	{"le .Ufour .Uthree", "false", true},
	{"gt 1.5 1.5", "false", true},
	{"gt 1.5 2.5", "false", true},
	{"gt 1 1", "false", true},
	{"gt 2 1", "true", true},
	{"gt 1 2", "false", true},
	{"gt `xy` `xy`", "false", true},
	{"gt `xy` `xyz`", "false", true},
	{"gt .Uthree .Uthree", "false", true},
	{"gt .Uthree .Ufour", "false", true},
	{"gt .Ufour .Uthree", "true", true},
	{"ge 1.5 1.5", "true", true},
	{"ge 1.5 2.5", "false", true},
	{"ge 2.5 1.5", "true", true},
	{"ge 1 1", "true", true},
	{"ge 1 2", "false", true},
	{"ge 2 1", "true", true},
	{"ge `xy` `xy`", "true", true},
	{"ge `xy` `xyz`", "false", true},
	{"ge `xyz` `xy`", "true", true},
	{"ge .Uthree .Uthree", "true", true},
	{"ge .Uthree .Ufour", "false", true},
	{"ge .Ufour .Uthree", "true", true},
	// Mixing signed and unsigned integers.
	{"eq .Uthree .Three", "true", true},
	{"eq .Three .Uthree", "true", true},
	{"le .Uthree .Three", "true", true},
	{"le .Three .Uthree", "true", true},
	{"ge .Uthree .Three", "true", true},
	{"ge .Three .Uthree", "true", true},
	{"lt .Uthree .Three", "false", true},
	{"lt .Three .Uthree", "false", true},
	{"gt .Uthree .Three", "false", true},
	{"gt .Three .Uthree", "false", true},
	{"eq .Ufour .Three", "false", true},
	{"lt .Ufour .Three", "false", true},
	{"gt .Ufour .Three", "true", true},
	{"eq .NegOne .Uthree", "false", true},
	{"eq .Uthree .NegOne", "false", true},
	{"ne .NegOne .Uthree", "true", true},
	{"ne .Uthree .NegOne", "true", true},
	{"lt .NegOne .Uthree", "true", true},
	{"lt .Uthree .NegOne", "false", true},
	{"le .NegOne .Uthree", "true", true},
	{"le .Uthree .NegOne", "false", true},
	{"gt .NegOne .Uthree", "false", true},
	{"gt .Uthree .NegOne", "true", true},
	{"ge .NegOne .Uthree", "false", true},
	{"ge .Uthree .NegOne", "true", true},
	{"eq (index `x` 0) 'x'", "true", true}, // The example that triggered this rule.
	{"eq (index `x` 0) 'y'", "false", true},
	{"eq .V1 .V2", "true", true},
	{"eq .Ptr .Ptr", "true", true},
	{"eq .Ptr .NilPtr", "false", true},
	{"eq .NilPtr .NilPtr", "true", true},
	{"eq .Iface1 .Iface1", "true", true},
	{"eq .Iface1 .Iface2", "false", true},
	{"eq .Iface2 .Iface2", "true", true},
	{"eq .Map .Map", "true", true},        // Uncomparable types but nil is OK.
	{"eq .Map nil", "true", true},         // Uncomparable types but nil is OK.
	{"eq nil .Map", "true", true},         // Uncomparable types but nil is OK.
	{"eq .Map .NonNilMap", "false", true}, // Uncomparable types but nil is OK.
	// Errors
	{"eq `xy` 1", "", false},                // Different types.
	{"eq 2 2.0", "", false},                 // Different types.
	{"lt true true", "", false},             // Unordered types.
	{"lt 1+0i 1+0i", "", false},             // Unordered types.
	{"eq .Ptr 1", "", false},                // Incompatible types.
	{"eq .Ptr .NegOne", "", false},          // Incompatible types.
	{"eq .Map .V1", "", false},              // Uncomparable types.
	{"eq .NonNilMap .NonNilMap", "", false}, // Uncomparable types.
}

func TestComparison(t *testing.T) {
	b := new(strings.Builder)
	var cmpStruct = struct {
		Uthree, Ufour  uint
		NegOne, Three  int
		Ptr, NilPtr    *int
		NonNilMap      map[int]int
		Map            map[int]int
		V1, V2         V
		Iface1, Iface2 fmt.Stringer
	}{
		Uthree:    3,
		Ufour:     4,
		NegOne:    -1,
		Three:     3,
		Ptr:       new(int),
		NonNilMap: make(map[int]int),
		Iface1:    b,
	}
	for _, test := range cmpTests {
		text := fmt.Sprintf("{{if %s}}true{{else}}false{{end}}", test.expr)
		tmpl, err := New("empty").Parse(text)
		if err != nil {
			t.Fatalf("%q: %s", test.expr, err)
		}
		b.Reset()
		err = tmpl.Execute(b, &cmpStruct)
		if test.ok && err != nil {
			t.Errorf("%s errored incorrectly: %s", test.expr, err)
			continue
		}
		if !test.ok && err == nil {
			t.Errorf("%s did not error", test.expr)
			continue
		}
		if b.String() != test.truth {
			t.Errorf("%s: want %s; got %s", test.expr, test.truth, b.String())
		}
	}
}

func TestMissingMapKey(t *testing.T) {
	data := map[string]int{
		"x": 99,
	}
	tmpl, err := New("t1").Parse("{{.x}} {{.y}}")
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	// By default, just get "<no value>" // NOTE: not in html/template, get empty string
	err = tmpl.Execute(&b, data)
	if err != nil {
		t.Fatal(err)
	}
	want := "99 "
	got := b.String()
	if got != want {
		t.Errorf("got %q; expected %q", got, want)
	}
	// Same if we set the option explicitly to the default.
	tmpl.Option("missingkey=default")
	b.Reset()
	err = tmpl.Execute(&b, data)
	if err != nil {
		t.Fatal("default:", err)
	}
	got = b.String()
	if got != want {
		t.Errorf("got %q; expected %q", got, want)
	}
	// Next we ask for a zero value
	tmpl.Option("missingkey=zero")
	b.Reset()
	err = tmpl.Execute(&b, data)
	if err != nil {
		t.Fatal("zero:", err)
	}
	want = "99 0"
	got = b.String()
	if got != want {
		t.Errorf("got %q; expected %q", got, want)
	}
	// Now we ask for an error.
	tmpl.Option("missingkey=error")
	err = tmpl.Execute(&b, data)
	if err == nil {
		t.Errorf("expected error; got none")
	}
	// same Option, but now a nil interface: ask for an error
	err = tmpl.Execute(&b, nil)
	t.Log(err)
	if err == nil {
		t.Errorf("expected error for nil-interface; got none")
	}
}

// Test that the error message for multiline unterminated string
// refers to the line number of the opening quote.
func TestUnterminatedStringError(t *testing.T) {
	_, err := New("X").Parse("hello\n\n{{`unterminated\n\n\n\n}}\n some more\n\n")
	if err == nil {
		t.Fatal("expected error")
	}
	str := err.Error()
	if !strings.Contains(str, "X:3: unterminated raw quoted string") {
		t.Fatalf("unexpected error: %s", str)
	}
}

const alwaysErrorText = "always be failing"

var alwaysError = errors.New(alwaysErrorText)

type ErrorWriter int

func (e ErrorWriter) Write(p []byte) (int, error) {
	return 0, alwaysError
}

func TestExecuteGivesExecError(t *testing.T) {
	// First, a non-execution error shouldn't be an ExecError.
	tmpl, err := New("X").Parse("hello")
	if err != nil {
		t.Fatal(err)
	}
	err = tmpl.Execute(ErrorWriter(0), 0)
	if err == nil {
		t.Fatal("expected error; got none")
	}
	if err.Error() != alwaysErrorText {
		t.Errorf("expected %q error; got %q", alwaysErrorText, err)
	}
	// This one should be an ExecError.
	tmpl, err = New("X").Parse("hello, {{.X.Y}}")
	if err != nil {
		t.Fatal(err)
	}
	err = tmpl.Execute(io.Discard, 0)
	if err == nil {
		t.Fatal("expected error; got none")
	}
	eerr, ok := err.(template.ExecError)
	if !ok {
		t.Fatalf("did not expect ExecError %s", eerr)
	}
	expect := "field X in type int"
	if !strings.Contains(err.Error(), expect) {
		t.Errorf("expected %q; got %q", expect, err)
	}
}

func funcNameTestFunc() int {
	return 0
}

func TestGoodFuncNames(t *testing.T) {
	names := []string{
		"_",
		"a",
		"a1",
		"a1",
		"Ӵ",
	}
	for _, name := range names {
		tmpl := New("X").Funcs(
			FuncMap{
				name: funcNameTestFunc,
			},
		)
		if tmpl == nil {
			t.Fatalf("nil result for %q", name)
		}
	}
}

func TestBadFuncNames(t *testing.T) {
	names := []string{
		"",
		"2",
		"a-b",
	}
	for _, name := range names {
		testBadFuncName(name, t)
	}
}

func testBadFuncName(name string, t *testing.T) {
	t.Helper()
	defer func() {
		recover()
	}()
	New("X").Funcs(
		FuncMap{
			name: funcNameTestFunc,
		},
	)
	// If we get here, the name did not cause a panic, which is how Funcs
	// reports an error.
	t.Errorf("%q succeeded incorrectly as function name", name)
}

func TestBlock(t *testing.T) {
	const (
		input   = `a({{block "inner" .}}bar({{.}})baz{{end}})b`
		want    = `a(bar(hello)baz)b`
		overlay = `{{define "inner"}}foo({{.}})bar{{end}}`
		want2   = `a(foo(goodbye)bar)b`
	)
	tmpl, err := New("outer").Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	tmpl2, err := Must(tmpl.Clone()).Parse(overlay)
	if err != nil {
		t.Fatal(err)
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, "hello"); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}

	buf.Reset()
	if err := tmpl2.Execute(&buf, "goodbye"); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != want2 {
		t.Errorf("got %q, want %q", got, want2)
	}
}

func TestEvalFieldErrors(t *testing.T) {
	tests := []struct {
		name, src string
		value     any
		want      string
	}{
		{
			// Check that calling an invalid field on nil pointer
			// prints a field error instead of a distracting nil
			// pointer error. https://golang.org/issue/15125
			"MissingFieldOnNil",
			"{{.MissingField}}",
			(*T)(nil),
			"can't evaluate field MissingField in type *template.T",
		},
		{
			"MissingFieldOnNonNil",
			"{{.MissingField}}",
			&T{},
			"can't evaluate field MissingField in type *template.T",
		},
		{
			"ExistingFieldOnNil",
			"{{.X}}",
			(*T)(nil),
			"nil pointer evaluating *template.T.X",
		},
		{
			"MissingKeyOnNilMap",
			"{{.MissingKey}}",
			(*map[string]string)(nil),
			"nil pointer evaluating *map[string]string.MissingKey",
		},
		{
			"MissingKeyOnNilMapPtr",
			"{{.MissingKey}}",
			(*map[string]string)(nil),
			"nil pointer evaluating *map[string]string.MissingKey",
		},
		{
			"MissingKeyOnMapPtrToNil",
			"{{.MissingKey}}",
			&map[string]string{},
			"<nil>",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmpl := Must(New("tmpl").Parse(tc.src))
			err := tmpl.Execute(io.Discard, tc.value)
			got := "<nil>"
			if err != nil {
				got = err.Error()
			}
			if !strings.HasSuffix(got, tc.want) {
				t.Fatalf("got error %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMaxExecDepth(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short mode")
	}
	tmpl := Must(New("tmpl").Parse(`{{template "tmpl" .}}`))
	err := tmpl.Execute(io.Discard, nil)
	got := "<nil>"
	if err != nil {
		got = err.Error()
	}
	const want = "exceeded maximum template depth"
	if !strings.Contains(got, want) {
		t.Errorf("got error %q; want %q", got, want)
	}
}

func TestAddrOfIndex(t *testing.T) {
	// golang.org/issue/14916.
	// Before index worked on reflect.Values, the .String could not be
	// found on the (incorrectly unaddressable) V value,
	// in contrast to range, which worked fine.
	// Also testing that passing a reflect.Value to tmpl.Execute works.
	texts := []string{
		`{{range .}}{{.String}}{{end}}`,
		`{{with index . 0}}{{.String}}{{end}}`,
	}
	for _, text := range texts {
		tmpl := Must(New("tmpl").Parse(text))
		var buf strings.Builder
		err := tmpl.Execute(&buf, reflect.ValueOf([]V{{1}}))
		if err != nil {
			t.Fatalf("%s: Execute: %v", text, err)
		}
		if buf.String() != "&lt;1&gt;" {
			t.Fatalf("%s: template output = %q, want %q", text, &buf, "&lt;1&gt;")
		}
	}
}

func TestInterfaceValues(t *testing.T) {
	// golang.org/issue/17714.
	// Before index worked on reflect.Values, interface values
	// were always implicitly promoted to the underlying value,
	// except that nil interfaces were promoted to the zero reflect.Value.
	// Eliminating a round trip to interface{} and back to reflect.Value
	// eliminated this promotion, breaking these cases.
	tests := []struct {
		text string
		out  string
	}{
		{`{{index .Nil 1}}`, "ERROR: index of untyped nil"},
		{`{{index .Slice 2}}`, "2"},
		{`{{index .Slice .Two}}`, "2"},
		{`{{call .Nil 1}}`, "ERROR: call of nil"},
		{`{{call .PlusOne 1}}`, "2"},
		{`{{call .PlusOne .One}}`, "2"},
		{`{{and (index .Slice 0) true}}`, "0"},
		{`{{and .Zero true}}`, "0"},
		{`{{and (index .Slice 1) false}}`, "false"},
		{`{{and .One false}}`, "false"},
		{`{{or (index .Slice 0) false}}`, "false"},
		{`{{or .Zero false}}`, "false"},
		{`{{or (index .Slice 1) true}}`, "1"},
		{`{{or .One true}}`, "1"},
		{`{{not (index .Slice 0)}}`, "true"},
		{`{{not .Zero}}`, "true"},
		{`{{not (index .Slice 1)}}`, "false"},
		{`{{not .One}}`, "false"},
		{`{{eq (index .Slice 0) .Zero}}`, "true"},
		{`{{eq (index .Slice 1) .One}}`, "true"},
		{`{{ne (index .Slice 0) .Zero}}`, "false"},
		{`{{ne (index .Slice 1) .One}}`, "false"},
		{`{{ge (index .Slice 0) .One}}`, "false"},
		{`{{ge (index .Slice 1) .Zero}}`, "true"},
		{`{{gt (index .Slice 0) .One}}`, "false"},
		{`{{gt (index .Slice 1) .Zero}}`, "true"},
		{`{{le (index .Slice 0) .One}}`, "true"},
		{`{{le (index .Slice 1) .Zero}}`, "false"},
		{`{{lt (index .Slice 0) .One}}`, "true"},
		{`{{lt (index .Slice 1) .Zero}}`, "false"},
	}

	for _, tt := range tests {
		tmpl := Must(New("tmpl").Parse(tt.text))
		var buf strings.Builder
		err := tmpl.Execute(&buf, map[string]any{
			"PlusOne": func(n int) int {
				return n + 1
			},
			"Slice": []int{0, 1, 2, 3},
			"One":   1,
			"Two":   2,
			"Nil":   nil,
			"Zero":  0,
		})
		if strings.HasPrefix(tt.out, "ERROR:") {
			e := strings.TrimSpace(strings.TrimPrefix(tt.out, "ERROR:"))
			if err == nil || !strings.Contains(err.Error(), e) {
				t.Errorf("%s: Execute: %v, want error %q", tt.text, err, e)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: Execute: %v", tt.text, err)
			continue
		}
		if buf.String() != tt.out {
			t.Errorf("%s: template output = %q, want %q", tt.text, &buf, tt.out)
		}
	}
}

// Check that panics during calls are recovered and returned as errors.
func TestExecutePanicDuringCall(t *testing.T) {
	funcs := map[string]any{
		"doPanic": func() string {
			panic("custom panic string")
		},
	}
	tests := []struct {
		name    string
		input   string
		data    any
		wantErr string
	}{
		{
			"direct func call panics",
			"{{doPanic}}", (*T)(nil),
			`template: t:1:2: executing "t" at <doPanic>: error calling doPanic: custom panic string`,
		},
		{
			"indirect func call panics",
			"{{call doPanic}}", (*T)(nil),
			`template: t:1:7: executing "t" at <doPanic>: error calling doPanic: custom panic string`,
		},
		{
			"direct method call panics",
			"{{.GetU}}", (*T)(nil),
			`template: t:1:2: executing "t" at <.GetU>: error calling GetU: runtime error: invalid memory address or nil pointer dereference`,
		},
		{
			"indirect method call panics",
			"{{call .GetU}}", (*T)(nil),
			`template: t:1:7: executing "t" at <.GetU>: error calling GetU: runtime error: invalid memory address or nil pointer dereference`,
		},
		{
			"func field call panics",
			"{{call .PanicFunc}}", tVal,
			`template: t:1:2: executing "t" at <call .PanicFunc>: error calling call: test panic`,
		},
		{
			"method call on nil interface",
			"{{.NonEmptyInterfaceNil.Method0}}", tVal,
			`template: t:1:23: executing "t" at <.NonEmptyInterfaceNil.Method0>: nil pointer evaluating template.I.Method0`,
		},
	}
	for _, tc := range tests {
		b := new(bytes.Buffer)
		tmpl, err := New("t").Funcs(funcs).Parse(tc.input)
		if err != nil {
			t.Fatalf("parse error: %s", err)
		}
		err = tmpl.Execute(b, tc.data)
		if err == nil {
			t.Errorf("%s: expected error; got none", tc.name)
		} else if !strings.Contains(err.Error(), tc.wantErr) {
			if *debug {
				fmt.Printf("%s: test execute error: %s\n", tc.name, err)
			}
			t.Errorf("%s: expected error:\n%s\ngot:\n%s", tc.name, tc.wantErr, err)
		}
	}
}

// Issue 31810. Check that a parenthesized first argument behaves properly.
func TestIssue31810(t *testing.T) {
	t.Skip("broken in html/template")

	// A simple value with no arguments is fine.
	var b strings.Builder
	const text = "{{ (.)  }}"
	tmpl, err := New("").Parse(text)
	if err != nil {
		t.Error(err)
	}
	err = tmpl.Execute(&b, "result")
	if err != nil {
		t.Error(err)
	}
	if b.String() != "result" {
		t.Errorf("%s got %q, expected %q", text, b.String(), "result")
	}

	// Even a plain function fails - need to use call.
	f := func() string { return "result" }
	b.Reset()
	err = tmpl.Execute(&b, f)
	if err == nil {
		t.Error("expected error with no call, got none")
	}

	// Works if the function is explicitly called.
	const textCall = "{{ (call .)  }}"
	tmpl, err = New("").Parse(textCall)
	b.Reset()
	err = tmpl.Execute(&b, f)
	if err != nil {
		t.Error(err)
	}
	if b.String() != "result" {
		t.Errorf("%s got %q, expected %q", textCall, b.String(), "result")
	}
}

// Issue 39807. There was a race applying escapeTemplate.

const raceText = `
{{- define "jstempl" -}}
var v = "v";
{{- end -}}
<script type="application/javascript">
{{ template "jstempl" $ }}
</script>
`

func TestEscapeRace(t *testing.T) {
	tmpl := New("")
	_, err := tmpl.New("templ.html").Parse(raceText)
	if err != nil {
		t.Fatal(err)
	}
	const count = 20
	for i := 0; i < count; i++ {
		_, err := tmpl.New(fmt.Sprintf("x%d.html", i)).Parse(`{{ template "templ.html" .}}`)
		if err != nil {
			t.Fatal(err)
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < count; j++ {
				sub := tmpl.Lookup(fmt.Sprintf("x%d.html", j))
				if err := sub.Execute(io.Discard, nil); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
}

func TestRecursiveExecute(t *testing.T) {
	tmpl := New("")

	recur := func() (HTML, error) {
		var sb strings.Builder
		if err := tmpl.ExecuteTemplate(&sb, "subroutine", nil); err != nil {
			t.Fatal(err)
		}
		return HTML(sb.String()), nil
	}

	m := FuncMap{
		"recur": recur,
	}

	top, err := tmpl.New("x.html").Funcs(m).Parse(`{{recur}}`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tmpl.New("subroutine").Parse(`<a href="/x?p={{"'a<b'"}}">`)
	if err != nil {
		t.Fatal(err)
	}
	if err := top.Execute(io.Discard, nil); err != nil {
		t.Fatal(err)
	}
}

// recursiveInvoker is for TestRecursiveExecuteViaMethod.
type recursiveInvoker struct {
	t    *testing.T
	tmpl *Template
}

func (r *recursiveInvoker) Recur() (string, error) {
	var sb strings.Builder
	if err := r.tmpl.ExecuteTemplate(&sb, "subroutine", nil); err != nil {
		r.t.Fatal(err)
	}
	return sb.String(), nil
}

func TestRecursiveExecuteViaMethod(t *testing.T) {
	tmpl := New("")
	top, err := tmpl.New("x.html").Parse(`{{.Recur}}`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tmpl.New("subroutine").Parse(`<a href="/x?p={{"'a<b'"}}">`)
	if err != nil {
		t.Fatal(err)
	}
	r := &recursiveInvoker{
		t:    t,
		tmpl: tmpl,
	}
	if err := top.Execute(io.Discard, r); err != nil {
		t.Fatal(err)
	}
}

// Issue 43295.
func TestTemplateFuncsAfterClone(t *testing.T) {
	s := `{{ f . }}`
	want := "test"
	orig := New("orig").Funcs(map[string]any{
		"f": func(in string) string {
			return in
		},
	}).New("child")

	overviewTmpl := Must(Must(orig.Clone()).Parse(s))
	var out strings.Builder
	if err := overviewTmpl.Execute(&out, want); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != want {
		t.Fatalf("got %q; want %q", got, want)
	}
}

"""




```