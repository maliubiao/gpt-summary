Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The overarching goal is to analyze a Go test file (`exec_test.go`) and describe its purpose and functionality, focusing on the core Go features it tests.

2. **Identify the Core Package:** The path `go/src/text/template/exec_test.go` immediately tells us this is testing the `text/template` package's execution functionality.

3. **Scan for Key Structures and Functions:** Look for prominent data structures and functions. The `execTest` struct is immediately apparent and seems central to the testing strategy. The `TestExecute` function and other functions starting with `Test` are also clearly important as they define the test cases.

4. **Analyze `execTest`:**  This structure holds the test name, the template input, the expected output, the input data, and a boolean indicating whether the test is expected to succeed. This reveals the fundamental pattern: run a template with some data and compare the result.

5. **Examine `TestExecute`:** This function iterates through the `execTests` slice. Inside the loop, it parses the template input, executes it with the provided data, and then compares the output against the expected output. This confirms the basic testing methodology. The `FuncMap` is also defined here, indicating the testing of custom functions within templates.

6. **Identify Specific Test Cases:**  Start examining the individual test cases in `execTests`. Notice categories like `bug...`, `issue...`, and tests focused on specific operators like `eq`. This suggests the file tests various edge cases, bug fixes, and the correctness of template language features.

7. **Look for Helper Functions:** Functions like `fVal1`, `fVal2`, `zeroArgs`, `oneArg`, etc., are helper functions used as data or as functions within the templates. Their names and signatures provide clues about what aspects of template execution are being tested (e.g., function calls with different argument counts and types).

8. **Focus on Go Language Features:** As you analyze the test cases, connect them to specific Go features being tested *within the context of templates*. For example:
    * **Function Calls:** The `zeroArgs`, `oneArg`, `twoArgs`, `dddArg` functions demonstrate testing function calls within templates, including variadic arguments.
    * **Data Structures:**  The tests involving `tVal` and its fields (like `AI`) show how templates interact with different Go data types (structs, slices).
    * **Control Flow:** The `range` keyword in the template examples and the `rangeTestData` function show testing iteration within templates.
    * **Comparison Operators:** The `cmpTests` array and the `TestComparison` function specifically target the comparison operators (`eq`, `ne`, `lt`, etc.) within the template language.
    * **Error Handling:**  The tests like `TestExecuteError` and `TestExecError` explicitly check how template execution handles errors, including those from function calls and nested templates.
    * **Custom Delimiters:** `TestDelims` specifically targets the ability to change the template delimiters.
    * **String Escaping:** `TestJSEscaping` verifies the correct escaping of strings for JavaScript contexts.
    * **Template Definitions and Blocks:** `TestTree` and `TestBlock` demonstrate testing template definitions (`define`) and block inheritance.
    * **`index` Function:**  Several tests use the `index` function to access elements of slices or maps.
    * **`call` Function:** Tests involving `call` verify the invocation of functions and methods within templates.
    * **Panic Handling:** `TestExecutePanicDuringCall` checks how panics within template functions are handled.
    * **Channel Iteration:** `TestIssue43065` addresses ranging over channels.
    * **Nil Pointers and Missing Fields:** `TestEvalFieldErrors` and `TestIssue48215` cover how the template engine handles nil pointers and missing fields during evaluation.

9. **Infer Functionality from Test Cases:** If you see a pattern in the tests, you can infer the broader functionality being tested. For instance, the numerous comparison tests strongly indicate that the template engine supports a full suite of comparison operators.

10. **Consider Potential User Errors:** Think about common mistakes users might make when working with Go templates. The "易犯错的点" section should cover areas like:
    * Incorrectly using comparison operators (e.g., comparing different types).
    * Forgetting to use `call` for function invocation within pipelines.
    * Issues with nil pointers or accessing missing fields in data.
    * Errors in template syntax (though this file primarily tests execution).

11. **Structure the Answer:** Organize the findings into clear sections:
    * **功能列举:** List the specific functionalities tested.
    * **Go 语言功能实现举例:**  Provide concise code examples that demonstrate the use of the template features, including assumptions for input and output.
    * **代码推理:** Explain the logic of specific test cases, again with assumptions and outputs if relevant.
    * **命令行参数:**  If the code handled command-line arguments (it doesn't in this snippet), describe their usage.
    * **易犯错的点:** Detail common pitfalls.
    * **功能归纳:** Summarize the overall purpose of the code.

12. **Refine and Verify:** Review the answer for accuracy and completeness. Ensure the code examples are correct and the explanations are clear. Double-check if the analysis aligns with the code's behavior. For instance, the presence of `FuncMap` strongly suggests testing custom functions. The numerous `Test...` functions directly correspond to specific tests.

By following these steps, you can systematically analyze the Go test file and generate a comprehensive and informative response.
好的，让我们来归纳一下 `go/src/text/template/exec_test.go` 这部分代码的功能。

**功能归纳 (第 2 部分):**

这部分代码主要集中在 `text/template` 包的 **模板执行阶段** 的各种功能测试，特别是以下几个方面：

1. **比较操作符的测试:**  详细测试了模板语言中的比较操作符 (`eq`, `ne`, `lt`, `le`, `gt`, `ge`) 在不同数据类型之间的行为，包括基本类型、复数、字符串、自定义类型以及有符号和无符号整数的比较。还覆盖了比较操作符处理 `nil` 值的情况。

2. **`missingkey` 选项测试:** 测试了当模板尝试访问 map 中不存在的 key 时，`missingkey` 选项的不同设置 (`default`, `zero`, `error`) 对输出和错误处理的影响。

3. **错误处理测试:**  测试了模板执行过程中可能出现的各种错误情况，例如：
    * 未终止的字符串字面量导致的解析错误。
    * `io.Writer` 写入错误。
    * 尝试访问不存在的字段或方法导致的执行错误 (包括在 `nil` 指针上的访问)。
    * 模板调用深度超过限制。
    * 函数调用时参数或返回值类型不匹配。
    * 函数调用时发生 `panic` 的处理。

4. **函数调用测试 (`call`):** 详细测试了 `call` 动作在模板中的使用，包括：
    * 调用不同参数数量和类型的函数。
    * 调用 variadic 函数。
    * 调用返回不同数量和类型的函数 (特别是返回 `error`)。
    * 调用管道命令的结果。

5. **块 (Block) 模板测试:**  测试了 `block` 动作的定义和继承机制，允许在不同的模板中覆盖块的内容。

6. **对 `reflect.Value` 的处理:** 测试了模板引擎如何处理 `reflect.Value` 类型的数据，特别是在 `index` 和 `range` 动作中的应用。

7. **接口类型值的处理:**  测试了模板引擎如何处理接口类型的值，以及在 `index`、`call` 和逻辑运算中的行为。

8. **协程安全测试 (Issue 39807):**  通过并发地添加解析树和执行模板来测试模板引擎的协程安全性。

9. **嵌入式 `nil` 指针处理 (Issue 48215):** 测试了当结构体包含嵌入式 `nil` 指针时，模板引擎的错误处理，避免发生 `panic`。

**结合第 1 部分，`go/src/text/template/exec_test.go` 的总体功能是:**

全面测试 `text/template` 包的 **模板执行阶段** 的各项功能。它涵盖了模板语法中各种动作的执行，包括变量访问、函数调用、控制流 (if, range)、模板定义和包含，以及错误处理机制。这些测试用例旨在验证模板引擎在处理各种输入数据和模板结构时的正确性和鲁棒性。

**更具体地列举一下这部分代码的功能：**

* **测试比较函数的行为:** 验证 `eq`, `ne`, `lt`, `le`, `gt`, `ge` 在不同类型和值上的结果。
* **测试 `missingkey` 选项:** 确保在访问不存在的 map key 时，根据选项设置产生预期的输出或错误。
* **测试模板执行过程中发生的错误:** 确保各种执行错误能够被正确捕获并报告。
* **测试 `call` 动作的正确性:** 验证 `call` 能够正确调用函数并处理参数和返回值。
* **测试 `block` 动作的继承机制:** 确保块模板能够被正确定义和覆盖。
* **测试模板对 `reflect.Value` 的处理能力:** 验证模板可以处理通过反射传递的值。
* **测试模板对接口类型值的处理:** 验证模板可以正确处理接口类型的值。
* **测试模板引擎的协程安全性:** 验证在高并发场景下模板引擎的稳定性。
* **测试模板引擎对嵌入式 `nil` 指针的处理:** 验证模板引擎不会因嵌入式 `nil` 指针而崩溃。

总而言之，这部分 `exec_test.go` 是对 `text/template` 包执行逻辑的细致而全面的单元测试。

Prompt: 
```
这是路径为go/src/text/template/exec_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
aluated
	// as constant floats instead of ints. Issue 34483.
	{"bug18a", "{{eq . '.'}}", "true", '.', true},
	{"bug18b", "{{eq . 'e'}}", "true", 'e', true},
	{"bug18c", "{{eq . 'P'}}", "true", 'P', true},

	{"issue56490", "{{$i := 0}}{{$x := 0}}{{range $i = .AI}}{{end}}{{$i}}", "5", tVal, true},
	{"issue60801", "{{$k := 0}}{{$v := 0}}{{range $k, $v = .AI}}{{$k}}={{$v}} {{end}}", "0=3 1=4 2=5 ", tVal, true},
}

func fVal1(i int) iter.Seq[int] {
	return func(yield func(int) bool) {
		for v := range i {
			if !yield(v) {
				break
			}
		}
	}
}

func fVal2(i int) iter.Seq2[int, int] {
	return func(yield func(int, int) bool) {
		for v := range i {
			if !yield(v, v+1) {
				break
			}
		}
	}
}

const rangeTestInt = `{{range $v := .}}{{printf "%T%d" $v $v}}{{end}}`

func rangeTestData[T int | int8 | int16 | int32 | int64 | uint | uint8 | uint16 | uint32 | uint64 | uintptr]() string {
	I := T(5)
	var buf strings.Builder
	for i := T(0); i < I; i++ {
		fmt.Fprintf(&buf, "%T%d", i, i)
	}
	return buf.String()
}

func zeroArgs() string {
	return "zeroArgs"
}

func oneArg(a string) string {
	return "oneArg=" + a
}

func twoArgs(a, b string) string {
	return "twoArgs=" + a + b
}

func dddArg(a int, b ...string) string {
	return fmt.Sprintln(a, b)
}

// count returns a channel that will deliver n sequential 1-letter strings starting at "a"
func count(n int) chan string {
	if n == 0 {
		return nil
	}
	c := make(chan string)
	go func() {
		for i := 0; i < n; i++ {
			c <- "abcdefghijklmnop"[i : i+1]
		}
		close(c)
	}()
	return c
}

// vfunc takes a *V and a V
func vfunc(V, *V) string {
	return "vfunc"
}

// valueString takes a string, not a pointer.
func valueString(v string) string {
	return "value is ignored"
}

// returnInt returns an int
func returnInt() int {
	return 7
}

func add(args ...int) int {
	sum := 0
	for _, x := range args {
		sum += x
	}
	return sum
}

func echo(arg any) any {
	return arg
}

func makemap(arg ...string) map[string]string {
	if len(arg)%2 != 0 {
		panic("bad makemap")
	}
	m := make(map[string]string)
	for i := 0; i < len(arg); i += 2 {
		m[arg[i]] = arg[i+1]
	}
	return m
}

func stringer(s fmt.Stringer) string {
	return s.String()
}

func mapOfThree() any {
	return map[string]int{"three": 3}
}

func testExecute(execTests []execTest, template *Template, t *testing.T) {
	b := new(strings.Builder)
	funcs := FuncMap{
		"add":         add,
		"count":       count,
		"dddArg":      dddArg,
		"die":         func() bool { panic("die") },
		"echo":        echo,
		"makemap":     makemap,
		"mapOfThree":  mapOfThree,
		"oneArg":      oneArg,
		"returnInt":   returnInt,
		"stringer":    stringer,
		"twoArgs":     twoArgs,
		"typeOf":      typeOf,
		"valueString": valueString,
		"vfunc":       vfunc,
		"zeroArgs":    zeroArgs,
	}
	for _, test := range execTests {
		var tmpl *Template
		var err error
		if template == nil {
			tmpl, err = New(test.name).Funcs(funcs).Parse(test.input)
		} else {
			tmpl, err = template.New(test.name).Funcs(funcs).Parse(test.input)
		}
		if err != nil {
			t.Errorf("%s: parse error: %s", test.name, err)
			continue
		}
		b.Reset()
		err = tmpl.Execute(b, test.data)
		switch {
		case !test.ok && err == nil:
			t.Errorf("%s: expected error; got none", test.name)
			continue
		case test.ok && err != nil:
			t.Errorf("%s: unexpected execute error: %s", test.name, err)
			continue
		case !test.ok && err != nil:
			// expected error, got one
			if *debug {
				fmt.Printf("%s: %s\n\t%s\n", test.name, test.input, err)
			}
		}
		result := b.String()
		if result != test.output {
			t.Errorf("%s: expected\n\t%q\ngot\n\t%q", test.name, test.output, result)
		}
	}
}

func TestExecute(t *testing.T) {
	testExecute(execTests, nil, t)
}

var delimPairs = []string{
	"", "", // default
	"{{", "}}", // same as default
	"<<", ">>", // distinct
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

type CustomError struct{}

func (*CustomError) Error() string { return "heyo !" }

// Check that a custom error can be returned.
func TestExecError_CustomError(t *testing.T) {
	failingFunc := func() (string, error) {
		return "", &CustomError{}
	}
	tmpl := Must(New("top").Funcs(FuncMap{
		"err": failingFunc,
	}).Parse("{{ err }}"))

	var b bytes.Buffer
	err := tmpl.Execute(&b, nil)

	var e *CustomError
	if !errors.As(err, &e) {
		t.Fatalf("expected custom error; got %s", err)
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
	new(Template).Templates()
	new(Template).Parse("")
	new(Template).New("abc").Parse("")
	new(Template).Execute(nil, nil)                // returns an error (but does not crash)
	new(Template).ExecuteTemplate(nil, "XXX", nil) // returns an error (but does not crash)
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
	want := `template: empty: "empty" is an incomplete or empty template`
	if got != want {
		t.Errorf("expected error %s got %s", want, got)
	}
	// Add a non-empty template to check that the error is helpful.
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
	want = `template: empty: "empty" is an incomplete or empty template`
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
	{"eq .Iface1 .NilIface", "false", true},
	{"eq .NilIface .NilIface", "true", true},
	{"eq .NilIface .Iface1", "false", true},
	{"eq .NilIface 0", "false", true},
	{"eq 0 .NilIface", "false", true},
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
		Uthree, Ufour    uint
		NegOne, Three    int
		Ptr, NilPtr      *int
		NonNilMap        map[int]int
		Map              map[int]int
		V1, V2           V
		Iface1, NilIface fmt.Stringer
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
	// By default, just get "<no value>"
	err = tmpl.Execute(&b, data)
	if err != nil {
		t.Fatal(err)
	}
	want := "99 <no value>"
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
	want = "99 <no value>"
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
	eerr, ok := err.(ExecError)
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
		if buf.String() != "<1>" {
			t.Fatalf("%s: template output = %q, want %q", text, &buf, "<1>")
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

func TestFunctionCheckDuringCall(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		data    any
		wantErr string
	}{{
		name:    "call nothing",
		input:   `{{call}}`,
		data:    tVal,
		wantErr: "wrong number of args for call: want at least 1 got 0",
	},
		{
			name:    "call non-function",
			input:   "{{call .True}}",
			data:    tVal,
			wantErr: "error calling call: non-function .True of type bool",
		},
		{
			name:    "call func with wrong argument",
			input:   "{{call .BinaryFunc 1}}",
			data:    tVal,
			wantErr: "error calling call: wrong number of args for .BinaryFunc: got 1 want 2",
		},
		{
			name:    "call variadic func with wrong argument",
			input:   `{{call .VariadicFuncInt}}`,
			data:    tVal,
			wantErr: "error calling call: wrong number of args for .VariadicFuncInt: got 0 want at least 1",
		},
		{
			name:    "call too few return number func",
			input:   `{{call .TooFewReturnCountFunc}}`,
			data:    tVal,
			wantErr: "error calling call: function .TooFewReturnCountFunc has 0 return values; should be 1 or 2",
		},
		{
			name:    "call too many return number func",
			input:   `{{call .TooManyReturnCountFunc}}`,
			data:    tVal,
			wantErr: "error calling call: function .TooManyReturnCountFunc has 3 return values; should be 1 or 2",
		},
		{
			name:    "call invalid return type func",
			input:   `{{call .InvalidReturnTypeFunc}}`,
			data:    tVal,
			wantErr: "error calling call: invalid function signature for .InvalidReturnTypeFunc: second return value should be error; is bool",
		},
		{
			name:    "call pipeline",
			input:   `{{call (len "test")}}`,
			data:    nil,
			wantErr: "error calling call: non-function len \"test\" of type int",
		},
	}

	for _, tc := range tests {
		b := new(bytes.Buffer)
		tmpl, err := New("t").Parse(tc.input)
		if err != nil {
			t.Fatalf("parse error: %s", err)
		}
		err = tmpl.Execute(b, tc.data)
		if err == nil {
			t.Errorf("%s: expected error; got none", tc.name)
		} else if tc.wantErr == "" || !strings.Contains(err.Error(), tc.wantErr) {
			if *debug {
				fmt.Printf("%s: test execute error: %s\n", tc.name, err)
			}
			t.Errorf("%s: expected error:\n%s\ngot:\n%s", tc.name, tc.wantErr, err)
		}
	}
}

// Issue 31810. Check that a parenthesized first argument behaves properly.
func TestIssue31810(t *testing.T) {
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

// Issue 43065, range over send only channel
func TestIssue43065(t *testing.T) {
	var b bytes.Buffer
	tmp := Must(New("").Parse(`{{range .}}{{end}}`))
	ch := make(chan<- int)
	err := tmp.Execute(&b, ch)
	if err == nil {
		t.Error("expected err got nil")
	} else if !strings.Contains(err.Error(), "range over send-only channel") {
		t.Errorf("%s", err)
	}
}

// Issue 39807: data race in html/template & text/template
func TestIssue39807(t *testing.T) {
	var wg sync.WaitGroup

	tplFoo, err := New("foo").Parse(`{{ template "bar" . }}`)
	if err != nil {
		t.Error(err)
	}

	tplBar, err := New("bar").Parse("bar")
	if err != nil {
		t.Error(err)
	}

	gofuncs := 10
	numTemplates := 10

	for i := 1; i <= gofuncs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numTemplates; j++ {
				_, err := tplFoo.AddParseTree(tplBar.Name(), tplBar.Tree)
				if err != nil {
					t.Error(err)
				}
				err = tplFoo.Execute(io.Discard, nil)
				if err != nil {
					t.Error(err)
				}
			}
		}()
	}

	wg.Wait()
}

// Issue 48215: embedded nil pointer causes panic.
// Fixed by adding FieldByIndexErr to the reflect package.
func TestIssue48215(t *testing.T) {
	type A struct {
		S string
	}
	type B struct {
		*A
	}
	tmpl, err := New("").Parse(`{{ .S }}`)
	if err != nil {
		t.Fatal(err)
	}
	err = tmpl.Execute(io.Discard, B{})
	// We expect an error, not a panic.
	if err == nil {
		t.Fatal("did not get error for nil embedded struct")
	}
	if !strings.Contains(err.Error(), "reflect: indirection through nil pointer to embedded struct field A") {
		t.Fatal(err)
	}
}

"""




```