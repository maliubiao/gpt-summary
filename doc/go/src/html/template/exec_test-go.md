Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The request asks for the functionality of the given Go code, which is a test file (`exec_test.go`) for the `html/template` package. The core task is to figure out what aspects of template execution this test file is verifying.

2. **Identify Key Components:** Scan the code for important elements:
    * **Package Declaration:** `package template` immediately tells us this is part of the `html/template` package's internal testing.
    * **Imports:**  The imports (`bytes`, `errors`, `flag`, `fmt`, `io`, `reflect`, `strings`, `sync`, `testing`, `text/template`) indicate the areas the tests touch upon. Notably, the presence of `text/template` suggests that the `html/template` builds upon or shares concepts with the `text/template` package.
    * **Global Variables:**  Variables like `debug`, `tVal`, `tSliceOfNil`, and `execTests` are crucial. `execTests` looks like the core test data.
    * **Structs:**  The definitions of `T`, `S`, `U`, `V`, `W`, and `execTest` reveal the types of data used in the tests. The methods associated with `T`, `U`, `V`, and `W` are also important as they are likely called from within the templates.
    * **Test Functions:** The presence of `testExecute` strongly suggests this file contains integration or black-box tests.

3. **Analyze `T` Struct:**  The `T` struct is a data structure designed to represent various Go types and features that templates might interact with. Note the diverse fields:
    * Basic types (bool, int, string, float, complex)
    * Nested structs
    * Structs with `String()` and `Error()` methods (important for template rendering)
    * Slices, arrays, maps (different ways to represent collections)
    * Empty and non-empty interfaces (testing interface handling)
    * Pointers
    * Functions (both regular and variadic)
    * Another template (`Tmpl`)
    * An unexported field (to check accessibility)

4. **Analyze `execTests` Slice:** This slice of `execTest` structs is the heart of the test suite. Each `execTest` defines:
    * `name`: A descriptive name for the test case.
    * `input`: The template string to be executed.
    * `output`: The expected output of the template execution.
    * `data`: The data passed to the template during execution (often an instance of `T`).
    * `ok`: A boolean indicating whether the template execution is expected to succeed.

5. **Infer Functionality from `execTests`:** By examining the `input` strings in `execTests`, we can deduce the features being tested. Look for patterns and template syntax:
    * Accessing struct fields (`.X`, `.U.V`)
    * Accessing map elements (`.MSI.one`)
    * Using the dot (`.`) for the current context
    * Declaring and using variables (`$x := ...`)
    * Calling methods (`.Method0`, `.Method1 1234`)
    * Calling functions (including built-in functions like `print`, `printf`, `html`, `js`, `urlquery`, `len`, `index`, `slice`, `not`, `and`, `or`)
    * Using control flow structures (`if`, `with`, `range`)
    * Handling errors
    * Working with different data types (integers, floats, booleans, strings, slices, maps, interfaces)
    * Using pipelines (`.Method0 | .Method2 .U16`)
    * Handling nil values
    * Edge cases and bug fixes (the "bug" prefixed tests)

6. **Analyze `testExecute` Function:** This function performs the actual execution of the tests. Key steps:
    * Iterates through the `execTests`.
    * Parses the template string (`New(test.name).Funcs(funcs).Parse(test.input)`). The `Funcs` part indicates custom functions can be added to templates.
    * Executes the template with the provided data (`tmpl.Execute(b, test.data)`).
    * Compares the actual output with the expected output.
    * Handles expected errors.

7. **Identify the Purpose of Flags:** The `debug` flag is used to control whether error messages are printed during test execution. This is a common practice in testing.

8. **Synthesize the Functionality Summary:** Based on the above analysis, we can summarize the functionality of the test file. The core purpose is to rigorously test various aspects of `html/template` execution, ensuring it correctly handles different data types, template syntax, function calls, control flow, error conditions, and edge cases.

9. **Address Specific Questions:** Now, address the specific points raised in the prompt:
    * **List of Functionalities:**  Extract the functionalities identified in step 5 and organize them.
    * **Go Language Feature:**  Choose a prominent feature being tested, like function calls, and provide a Go code example demonstrating its usage within a template.
    * **Code Reasoning (with Input/Output):** For the chosen feature, create a simple test case (similar to those in `execTests`) with a specific input template and data, along with the expected output.
    * **Command-line Arguments:** Explain the purpose of the `debug` flag.
    * **Common Mistakes:** Think about potential pitfalls when using templates, such as incorrect syntax or type mismatches. Provide an example.
    * **Overall Functionality (for Part 1):** Summarize the purpose of the code snippet as a test suite for `html/template` execution.

This systematic approach, breaking down the code into its components and then analyzing their interactions, allows for a comprehensive understanding of the test file's functionality.
## 对 go/src/html/template/exec_test.go (第1部分) 功能的归纳

这个 Go 语言源文件 `go/src/html/template/exec_test.go` 的主要功能是 **对 `html/template` 包的模板执行引擎进行全面的单元测试。**

它通过定义一系列的测试用例 (`execTests`)，每个用例都包含一个模板字符串、输入数据以及期望的输出结果，来验证模板引擎在处理各种语法、数据类型和控制流时的正确性。

**具体来说，这个测试文件旨在测试以下 `html/template` 的功能：**

1. **基础文本渲染:**  验证模板引擎能否正确渲染静态文本。
2. **数据访问:** 测试模板能否正确访问不同数据结构（结构体、map、切片、数组等）的字段和元素。
3. **点号 (`.`) 的使用:**  测试点号在不同上下文中的含义，包括访问当前对象、迭代元素等。
4. **变量的使用:**  验证模板中变量的声明、赋值和使用。
5. **方法调用:**  测试模板能否调用数据对象的方法，包括带参数和不带参数的方法。
6. **函数调用:**  验证模板能否调用预定义的函数（内置函数和自定义函数）。
7. **管道 (`|`) 的使用:** 测试管道操作符在模板中的作用，将前一个操作的结果传递给后一个操作。
8. **控制流语句:**  测试 `if`、`with` 和 `range` 等控制流语句的执行逻辑。
9. **内置函数:**  测试 `print`、`printf`、`html`、`js`、`urlquery`、`len`、`index`、`slice`、`not`、`and`、`or` 等内置函数的行为。
10. **HTML 转义:**  验证 `html` 函数能否正确转义 HTML 特殊字符。
11. **JavaScript 转义:** 验证 `js` 函数能否正确转义 JavaScript 特殊字符。
12. **URL 查询转义:** 验证 `urlquery` 函数能否正确转义 URL 查询参数。
13. **布尔运算:**  测试 `not`、`and`、`or` 等布尔运算符的逻辑。
14. **索引操作:**  测试 `index` 函数对切片、数组和 map 的索引操作。
15. **切片操作:**  测试 `slice` 函数对切片、数组和字符串的切片操作。
16. **长度获取:**  测试 `len` 函数获取切片、数组和 map 长度的功能。
17. **作用域控制:**  验证 `with` 语句改变作用域的功能。
18. **循环迭代:**  测试 `range` 语句对切片、数组和 map 的迭代功能。
19. **错误处理:**  测试模板引擎在遇到错误时的处理方式。
20. **数字字面量解析:** 测试模板引擎对不同进制数字字面量的解析。
21. **解决已知 Bug:** 文件中包含一些以 "bug" 开头的测试用例，用于验证之前发现的并已修复的 bug 不会再次出现。

**总而言之，`exec_test.go` (第1部分) 是一个功能丰富的测试文件，旨在确保 `html/template` 包的模板执行引擎能够按照预期工作，并处理各种复杂的模板场景。**

在后续的第 2 部分中，可能会包含更多的测试用例，或者涉及更深入的模板引擎内部机制的测试。

### 提示词
```
这是路径为go/src/html/template/exec_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Tests for template execution, copied from text/template.

package template

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
	"text/template"
)

var debug = flag.Bool("debug", false, "show the errors produced by the tests")

// T has lots of interesting pieces to use to test execution.
type T struct {
	// Basics
	True        bool
	I           int
	U16         uint16
	X, S        string
	FloatZero   float64
	ComplexZero complex128
	// Nested structs.
	U *U
	// Struct with String method.
	V0     V
	V1, V2 *V
	// Struct with Error method.
	W0     W
	W1, W2 *W
	// Slices
	SI      []int
	SICap   []int
	SIEmpty []int
	SB      []bool
	// Arrays
	AI [3]int
	// Maps
	MSI      map[string]int
	MSIone   map[string]int // one element, for deterministic output
	MSIEmpty map[string]int
	MXI      map[any]int
	MII      map[int]int
	MI32S    map[int32]string
	MI64S    map[int64]string
	MUI32S   map[uint32]string
	MUI64S   map[uint64]string
	MI8S     map[int8]string
	MUI8S    map[uint8]string
	SMSI     []map[string]int
	// Empty interfaces; used to see if we can dig inside one.
	Empty0 any // nil
	Empty1 any
	Empty2 any
	Empty3 any
	Empty4 any
	// Non-empty interfaces.
	NonEmptyInterface         I
	NonEmptyInterfacePtS      *I
	NonEmptyInterfaceNil      I
	NonEmptyInterfaceTypedNil I
	// Stringer.
	Str fmt.Stringer
	Err error
	// Pointers
	PI  *int
	PS  *string
	PSI *[]int
	NIL *int
	// Function (not method)
	BinaryFunc      func(string, string) string
	VariadicFunc    func(...string) string
	VariadicFuncInt func(int, ...string) string
	NilOKFunc       func(*int) bool
	ErrFunc         func() (string, error)
	PanicFunc       func() string
	// Template to test evaluation of templates.
	Tmpl *Template
	// Unexported field; cannot be accessed by template.
	unexported int
}

type S []string

func (S) Method0() string {
	return "M0"
}

type U struct {
	V string
}

type V struct {
	j int
}

func (v *V) String() string {
	if v == nil {
		return "nilV"
	}
	return fmt.Sprintf("<%d>", v.j)
}

type W struct {
	k int
}

func (w *W) Error() string {
	if w == nil {
		return "nilW"
	}
	return fmt.Sprintf("[%d]", w.k)
}

var siVal = I(S{"a", "b"})

var tVal = &T{
	True:   true,
	I:      17,
	U16:    16,
	X:      "x",
	S:      "xyz",
	U:      &U{"v"},
	V0:     V{6666},
	V1:     &V{7777}, // leave V2 as nil
	W0:     W{888},
	W1:     &W{999}, // leave W2 as nil
	SI:     []int{3, 4, 5},
	SICap:  make([]int, 5, 10),
	AI:     [3]int{3, 4, 5},
	SB:     []bool{true, false},
	MSI:    map[string]int{"one": 1, "two": 2, "three": 3},
	MSIone: map[string]int{"one": 1},
	MXI:    map[any]int{"one": 1},
	MII:    map[int]int{1: 1},
	MI32S:  map[int32]string{1: "one", 2: "two"},
	MI64S:  map[int64]string{2: "i642", 3: "i643"},
	MUI32S: map[uint32]string{2: "u322", 3: "u323"},
	MUI64S: map[uint64]string{2: "ui642", 3: "ui643"},
	MI8S:   map[int8]string{2: "i82", 3: "i83"},
	MUI8S:  map[uint8]string{2: "u82", 3: "u83"},
	SMSI: []map[string]int{
		{"one": 1, "two": 2},
		{"eleven": 11, "twelve": 12},
	},
	Empty1:                    3,
	Empty2:                    "empty2",
	Empty3:                    []int{7, 8},
	Empty4:                    &U{"UinEmpty"},
	NonEmptyInterface:         &T{X: "x"},
	NonEmptyInterfacePtS:      &siVal,
	NonEmptyInterfaceTypedNil: (*T)(nil),
	Str:                       bytes.NewBuffer([]byte("foozle")),
	Err:                       errors.New("erroozle"),
	PI:                        newInt(23),
	PS:                        newString("a string"),
	PSI:                       newIntSlice(21, 22, 23),
	BinaryFunc:                func(a, b string) string { return fmt.Sprintf("[%s=%s]", a, b) },
	VariadicFunc:              func(s ...string) string { return fmt.Sprint("<", strings.Join(s, "+"), ">") },
	VariadicFuncInt:           func(a int, s ...string) string { return fmt.Sprint(a, "=<", strings.Join(s, "+"), ">") },
	NilOKFunc:                 func(s *int) bool { return s == nil },
	ErrFunc:                   func() (string, error) { return "bla", nil },
	PanicFunc:                 func() string { panic("test panic") },
	Tmpl:                      Must(New("x").Parse("test template")), // "x" is the value of .X
}

var tSliceOfNil = []*T{nil}

// A non-empty interface.
type I interface {
	Method0() string
}

var iVal I = tVal

// Helpers for creation.
func newInt(n int) *int {
	return &n
}

func newString(s string) *string {
	return &s
}

func newIntSlice(n ...int) *[]int {
	p := new([]int)
	*p = make([]int, len(n))
	copy(*p, n)
	return p
}

// Simple methods with and without arguments.
func (t *T) Method0() string {
	return "M0"
}

func (t *T) Method1(a int) int {
	return a
}

func (t *T) Method2(a uint16, b string) string {
	return fmt.Sprintf("Method2: %d %s", a, b)
}

func (t *T) Method3(v any) string {
	return fmt.Sprintf("Method3: %v", v)
}

func (t *T) Copy() *T {
	n := new(T)
	*n = *t
	return n
}

func (t *T) MAdd(a int, b []int) []int {
	v := make([]int, len(b))
	for i, x := range b {
		v[i] = x + a
	}
	return v
}

var myError = errors.New("my error")

// MyError returns a value and an error according to its argument.
func (t *T) MyError(error bool) (bool, error) {
	if error {
		return true, myError
	}
	return false, nil
}

// A few methods to test chaining.
func (t *T) GetU() *U {
	return t.U
}

func (u *U) TrueFalse(b bool) string {
	if b {
		return "true"
	}
	return ""
}

func typeOf(arg any) string {
	return fmt.Sprintf("%T", arg)
}

type execTest struct {
	name   string
	input  string
	output string
	data   any
	ok     bool
}

// bigInt and bigUint are hex string representing numbers either side
// of the max int boundary.
// We do it this way so the test doesn't depend on ints being 32 bits.
var (
	bigInt  = fmt.Sprintf("0x%x", int(1<<uint(reflect.TypeFor[int]().Bits()-1)-1))
	bigUint = fmt.Sprintf("0x%x", uint(1<<uint(reflect.TypeFor[int]().Bits()-1)))
)

var execTests = []execTest{
	// Trivial cases.
	{"empty", "", "", nil, true},
	{"text", "some text", "some text", nil, true},
	{"nil action", "{{nil}}", "", nil, false},

	// Ideal constants.
	{"ideal int", "{{typeOf 3}}", "int", 0, true},
	{"ideal float", "{{typeOf 1.0}}", "float64", 0, true},
	{"ideal exp float", "{{typeOf 1e1}}", "float64", 0, true},
	{"ideal complex", "{{typeOf 1i}}", "complex128", 0, true},
	{"ideal int", "{{typeOf " + bigInt + "}}", "int", 0, true},
	{"ideal too big", "{{typeOf " + bigUint + "}}", "", 0, false},
	{"ideal nil without type", "{{nil}}", "", 0, false},

	// Fields of structs.
	{".X", "-{{.X}}-", "-x-", tVal, true},
	{".U.V", "-{{.U.V}}-", "-v-", tVal, true},
	{".unexported", "{{.unexported}}", "", tVal, false},

	// Fields on maps.
	{"map .one", "{{.MSI.one}}", "1", tVal, true},
	{"map .two", "{{.MSI.two}}", "2", tVal, true},
	{"map .NO", "{{.MSI.NO}}", "", tVal, true}, // NOTE: <no value> in text/template
	{"map .one interface", "{{.MXI.one}}", "1", tVal, true},
	{"map .WRONG args", "{{.MSI.one 1}}", "", tVal, false},
	{"map .WRONG type", "{{.MII.one}}", "", tVal, false},

	// Dots of all kinds to test basic evaluation.
	{"dot int", "<{{.}}>", "&lt;13>", 13, true},
	{"dot uint", "<{{.}}>", "&lt;14>", uint(14), true},
	{"dot float", "<{{.}}>", "&lt;15.1>", 15.1, true},
	{"dot bool", "<{{.}}>", "&lt;true>", true, true},
	{"dot complex", "<{{.}}>", "&lt;(16.2-17i)>", 16.2 - 17i, true},
	{"dot string", "<{{.}}>", "&lt;hello>", "hello", true},
	{"dot slice", "<{{.}}>", "&lt;[-1 -2 -3]>", []int{-1, -2, -3}, true},
	{"dot map", "<{{.}}>", "&lt;map[two:22]>", map[string]int{"two": 22}, true},
	{"dot struct", "<{{.}}>", "&lt;{7 seven}>", struct {
		a int
		b string
	}{7, "seven"}, true},

	// Variables.
	{"$ int", "{{$}}", "123", 123, true},
	{"$.I", "{{$.I}}", "17", tVal, true},
	{"$.U.V", "{{$.U.V}}", "v", tVal, true},
	{"declare in action", "{{$x := $.U.V}}{{$x}}", "v", tVal, true},
	{"simple assignment", "{{$x := 2}}{{$x = 3}}{{$x}}", "3", tVal, true},
	{"nested assignment",
		"{{$x := 2}}{{if true}}{{$x = 3}}{{end}}{{$x}}",
		"3", tVal, true},
	{"nested assignment changes the last declaration",
		"{{$x := 1}}{{if true}}{{$x := 2}}{{if true}}{{$x = 3}}{{end}}{{end}}{{$x}}",
		"1", tVal, true},

	// Type with String method.
	{"V{6666}.String()", "-{{.V0}}-", "-{6666}-", tVal, true}, //  NOTE: -<6666>- in text/template
	{"&V{7777}.String()", "-{{.V1}}-", "-&lt;7777&gt;-", tVal, true},
	{"(*V)(nil).String()", "-{{.V2}}-", "-nilV-", tVal, true},

	// Type with Error method.
	{"W{888}.Error()", "-{{.W0}}-", "-{888}-", tVal, true}, // NOTE: -[888] in text/template
	{"&W{999}.Error()", "-{{.W1}}-", "-[999]-", tVal, true},
	{"(*W)(nil).Error()", "-{{.W2}}-", "-nilW-", tVal, true},

	// Pointers.
	{"*int", "{{.PI}}", "23", tVal, true},
	{"*string", "{{.PS}}", "a string", tVal, true},
	{"*[]int", "{{.PSI}}", "[21 22 23]", tVal, true},
	{"*[]int[1]", "{{index .PSI 1}}", "22", tVal, true},
	{"NIL", "{{.NIL}}", "&lt;nil&gt;", tVal, true},

	// Empty interfaces holding values.
	{"empty nil", "{{.Empty0}}", "", tVal, true}, // NOTE: <no value> in text/template
	{"empty with int", "{{.Empty1}}", "3", tVal, true},
	{"empty with string", "{{.Empty2}}", "empty2", tVal, true},
	{"empty with slice", "{{.Empty3}}", "[7 8]", tVal, true},
	{"empty with struct", "{{.Empty4}}", "{UinEmpty}", tVal, true},
	{"empty with struct, field", "{{.Empty4.V}}", "UinEmpty", tVal, true},

	// Edge cases with <no value> with an interface value
	{"field on interface", "{{.foo}}", "", nil, true},                  // NOTE: <no value> in text/template
	{"field on parenthesized interface", "{{(.).foo}}", "", nil, true}, // NOTE: <no value> in text/template

	// Issue 31810: Parenthesized first element of pipeline with arguments.
	// See also TestIssue31810.
	{"unparenthesized non-function", "{{1 2}}", "", nil, false},
	{"parenthesized non-function", "{{(1) 2}}", "", nil, false},
	{"parenthesized non-function with no args", "{{(1)}}", "1", nil, true}, // This is fine.

	// Method calls.
	{".Method0", "-{{.Method0}}-", "-M0-", tVal, true},
	{".Method1(1234)", "-{{.Method1 1234}}-", "-1234-", tVal, true},
	{".Method1(.I)", "-{{.Method1 .I}}-", "-17-", tVal, true},
	{".Method2(3, .X)", "-{{.Method2 3 .X}}-", "-Method2: 3 x-", tVal, true},
	{".Method2(.U16, `str`)", "-{{.Method2 .U16 `str`}}-", "-Method2: 16 str-", tVal, true},
	{".Method2(.U16, $x)", "{{if $x := .X}}-{{.Method2 .U16 $x}}{{end}}-", "-Method2: 16 x-", tVal, true},
	{".Method3(nil constant)", "-{{.Method3 nil}}-", "-Method3: &lt;nil&gt;-", tVal, true},
	{".Method3(nil value)", "-{{.Method3 .MXI.unset}}-", "-Method3: &lt;nil&gt;-", tVal, true},
	{"method on var", "{{if $x := .}}-{{$x.Method2 .U16 $x.X}}{{end}}-", "-Method2: 16 x-", tVal, true},
	{"method on chained var",
		"{{range .MSIone}}{{if $.U.TrueFalse $.True}}{{$.U.TrueFalse $.True}}{{else}}WRONG{{end}}{{end}}",
		"true", tVal, true},
	{"chained method",
		"{{range .MSIone}}{{if $.GetU.TrueFalse $.True}}{{$.U.TrueFalse $.True}}{{else}}WRONG{{end}}{{end}}",
		"true", tVal, true},
	{"chained method on variable",
		"{{with $x := .}}{{with .SI}}{{$.GetU.TrueFalse $.True}}{{end}}{{end}}",
		"true", tVal, true},
	{".NilOKFunc not nil", "{{call .NilOKFunc .PI}}", "false", tVal, true},
	{".NilOKFunc nil", "{{call .NilOKFunc nil}}", "true", tVal, true},
	{"method on nil value from slice", "-{{range .}}{{.Method1 1234}}{{end}}-", "-1234-", tSliceOfNil, true},
	{"method on typed nil interface value", "{{.NonEmptyInterfaceTypedNil.Method0}}", "M0", tVal, true},

	// Function call builtin.
	{".BinaryFunc", "{{call .BinaryFunc `1` `2`}}", "[1=2]", tVal, true},
	{".VariadicFunc0", "{{call .VariadicFunc}}", "&lt;&gt;", tVal, true},
	{".VariadicFunc2", "{{call .VariadicFunc `he` `llo`}}", "&lt;he&#43;llo&gt;", tVal, true},
	{".VariadicFuncInt", "{{call .VariadicFuncInt 33 `he` `llo`}}", "33=&lt;he&#43;llo&gt;", tVal, true},
	{"if .BinaryFunc call", "{{ if .BinaryFunc}}{{call .BinaryFunc `1` `2`}}{{end}}", "[1=2]", tVal, true},
	{"if not .BinaryFunc call", "{{ if not .BinaryFunc}}{{call .BinaryFunc `1` `2`}}{{else}}No{{end}}", "No", tVal, true},
	{"Interface Call", `{{stringer .S}}`, "foozle", map[string]any{"S": bytes.NewBufferString("foozle")}, true},
	{".ErrFunc", "{{call .ErrFunc}}", "bla", tVal, true},
	{"call nil", "{{call nil}}", "", tVal, false},

	// Erroneous function calls (check args).
	{".BinaryFuncTooFew", "{{call .BinaryFunc `1`}}", "", tVal, false},
	{".BinaryFuncTooMany", "{{call .BinaryFunc `1` `2` `3`}}", "", tVal, false},
	{".BinaryFuncBad0", "{{call .BinaryFunc 1 3}}", "", tVal, false},
	{".BinaryFuncBad1", "{{call .BinaryFunc `1` 3}}", "", tVal, false},
	{".VariadicFuncBad0", "{{call .VariadicFunc 3}}", "", tVal, false},
	{".VariadicFuncIntBad0", "{{call .VariadicFuncInt}}", "", tVal, false},
	{".VariadicFuncIntBad`", "{{call .VariadicFuncInt `x`}}", "", tVal, false},
	{".VariadicFuncNilBad", "{{call .VariadicFunc nil}}", "", tVal, false},

	// Pipelines.
	{"pipeline", "-{{.Method0 | .Method2 .U16}}-", "-Method2: 16 M0-", tVal, true},
	{"pipeline func", "-{{call .VariadicFunc `llo` | call .VariadicFunc `he` }}-", "-&lt;he&#43;&lt;llo&gt;&gt;-", tVal, true},

	// Nil values aren't missing arguments.
	{"nil pipeline", "{{ .Empty0 | call .NilOKFunc }}", "true", tVal, true},
	{"nil call arg", "{{ call .NilOKFunc .Empty0 }}", "true", tVal, true},
	{"bad nil pipeline", "{{ .Empty0 | .VariadicFunc }}", "", tVal, false},

	// Parenthesized expressions
	{"parens in pipeline", "{{printf `%d %d %d` (1) (2 | add 3) (add 4 (add 5 6))}}", "1 5 15", tVal, true},

	// Parenthesized expressions with field accesses
	{"parens: $ in paren", "{{($).X}}", "x", tVal, true},
	{"parens: $.GetU in paren", "{{($.GetU).V}}", "v", tVal, true},
	{"parens: $ in paren in pipe", "{{($ | echo).X}}", "x", tVal, true},
	{"parens: spaces and args", `{{(makemap "up" "down" "left" "right").left}}`, "right", tVal, true},

	// If.
	{"if true", "{{if true}}TRUE{{end}}", "TRUE", tVal, true},
	{"if false", "{{if false}}TRUE{{else}}FALSE{{end}}", "FALSE", tVal, true},
	{"if nil", "{{if nil}}TRUE{{end}}", "", tVal, false},
	{"if on typed nil interface value", "{{if .NonEmptyInterfaceTypedNil}}TRUE{{ end }}", "", tVal, true},
	{"if 1", "{{if 1}}NON-ZERO{{else}}ZERO{{end}}", "NON-ZERO", tVal, true},
	{"if 0", "{{if 0}}NON-ZERO{{else}}ZERO{{end}}", "ZERO", tVal, true},
	{"if 1.5", "{{if 1.5}}NON-ZERO{{else}}ZERO{{end}}", "NON-ZERO", tVal, true},
	{"if 0.0", "{{if .FloatZero}}NON-ZERO{{else}}ZERO{{end}}", "ZERO", tVal, true},
	{"if 1.5i", "{{if 1.5i}}NON-ZERO{{else}}ZERO{{end}}", "NON-ZERO", tVal, true},
	{"if 0.0i", "{{if .ComplexZero}}NON-ZERO{{else}}ZERO{{end}}", "ZERO", tVal, true},
	{"if emptystring", "{{if ``}}NON-EMPTY{{else}}EMPTY{{end}}", "EMPTY", tVal, true},
	{"if string", "{{if `notempty`}}NON-EMPTY{{else}}EMPTY{{end}}", "NON-EMPTY", tVal, true},
	{"if emptyslice", "{{if .SIEmpty}}NON-EMPTY{{else}}EMPTY{{end}}", "EMPTY", tVal, true},
	{"if slice", "{{if .SI}}NON-EMPTY{{else}}EMPTY{{end}}", "NON-EMPTY", tVal, true},
	{"if emptymap", "{{if .MSIEmpty}}NON-EMPTY{{else}}EMPTY{{end}}", "EMPTY", tVal, true},
	{"if map", "{{if .MSI}}NON-EMPTY{{else}}EMPTY{{end}}", "NON-EMPTY", tVal, true},
	{"if map unset", "{{if .MXI.none}}NON-ZERO{{else}}ZERO{{end}}", "ZERO", tVal, true},
	{"if map not unset", "{{if not .MXI.none}}ZERO{{else}}NON-ZERO{{end}}", "ZERO", tVal, true},
	{"if $x with $y int", "{{if $x := true}}{{with $y := .I}}{{$x}},{{$y}}{{end}}{{end}}", "true,17", tVal, true},
	{"if $x with $x int", "{{if $x := true}}{{with $x := .I}}{{$x}},{{end}}{{$x}}{{end}}", "17,true", tVal, true},
	{"if else if", "{{if false}}FALSE{{else if true}}TRUE{{end}}", "TRUE", tVal, true},
	{"if else chain", "{{if eq 1 3}}1{{else if eq 2 3}}2{{else if eq 3 3}}3{{end}}", "3", tVal, true},

	// Print etc.
	{"print", `{{print "hello, print"}}`, "hello, print", tVal, true},
	{"print 123", `{{print 1 2 3}}`, "1 2 3", tVal, true},
	{"print nil", `{{print nil}}`, "&lt;nil&gt;", tVal, true},
	{"println", `{{println 1 2 3}}`, "1 2 3\n", tVal, true},
	{"printf int", `{{printf "%04x" 127}}`, "007f", tVal, true},
	{"printf float", `{{printf "%g" 3.5}}`, "3.5", tVal, true},
	{"printf complex", `{{printf "%g" 1+7i}}`, "(1&#43;7i)", tVal, true},
	{"printf string", `{{printf "%s" "hello"}}`, "hello", tVal, true},
	{"printf function", `{{printf "%#q" zeroArgs}}`, "`zeroArgs`", tVal, true},
	{"printf field", `{{printf "%s" .U.V}}`, "v", tVal, true},
	{"printf method", `{{printf "%s" .Method0}}`, "M0", tVal, true},
	{"printf dot", `{{with .I}}{{printf "%d" .}}{{end}}`, "17", tVal, true},
	{"printf var", `{{with $x := .I}}{{printf "%d" $x}}{{end}}`, "17", tVal, true},
	{"printf lots", `{{printf "%d %s %g %s" 127 "hello" 7-3i .Method0}}`, "127 hello (7-3i) M0", tVal, true},

	// HTML.
	{"html", `{{html "<script>alert(\"XSS\");</script>"}}`,
		"&lt;script&gt;alert(&#34;XSS&#34;);&lt;/script&gt;", nil, true},
	{"html pipeline", `{{printf "<script>alert(\"XSS\");</script>" | html}}`,
		"&lt;script&gt;alert(&#34;XSS&#34;);&lt;/script&gt;", nil, true},
	{"html", `{{html .PS}}`, "a string", tVal, true},
	{"html typed nil", `{{html .NIL}}`, "&lt;nil&gt;", tVal, true},
	{"html untyped nil", `{{html .Empty0}}`, "&lt;nil&gt;", tVal, true}, // NOTE: "&lt;no value&gt;" in text/template

	// JavaScript.
	{"js", `{{js .}}`, `It\&#39;d be nice.`, `It'd be nice.`, true},

	// URL query.
	{"urlquery", `{{"http://www.example.org/"|urlquery}}`, "http%3A%2F%2Fwww.example.org%2F", nil, true},

	// Booleans
	{"not", "{{not true}} {{not false}}", "false true", nil, true},
	{"and", "{{and false 0}} {{and 1 0}} {{and 0 true}} {{and 1 1}}", "false 0 0 1", nil, true},
	{"or", "{{or 0 0}} {{or 1 0}} {{or 0 true}} {{or 1 1}}", "0 1 true 1", nil, true},
	{"boolean if", "{{if and true 1 `hi`}}TRUE{{else}}FALSE{{end}}", "TRUE", tVal, true},
	{"boolean if not", "{{if and true 1 `hi` | not}}TRUE{{else}}FALSE{{end}}", "FALSE", nil, true},

	// Indexing.
	{"slice[0]", "{{index .SI 0}}", "3", tVal, true},
	{"slice[1]", "{{index .SI 1}}", "4", tVal, true},
	{"slice[HUGE]", "{{index .SI 10}}", "", tVal, false},
	{"slice[WRONG]", "{{index .SI `hello`}}", "", tVal, false},
	{"slice[nil]", "{{index .SI nil}}", "", tVal, false},
	{"map[one]", "{{index .MSI `one`}}", "1", tVal, true},
	{"map[two]", "{{index .MSI `two`}}", "2", tVal, true},
	{"map[NO]", "{{index .MSI `XXX`}}", "0", tVal, true},
	{"map[nil]", "{{index .MSI nil}}", "", tVal, false},
	{"map[``]", "{{index .MSI ``}}", "0", tVal, true},
	{"map[WRONG]", "{{index .MSI 10}}", "", tVal, false},
	{"double index", "{{index .SMSI 1 `eleven`}}", "11", tVal, true},
	{"nil[1]", "{{index nil 1}}", "", tVal, false},
	{"map MI64S", "{{index .MI64S 2}}", "i642", tVal, true},
	{"map MI32S", "{{index .MI32S 2}}", "two", tVal, true},
	{"map MUI64S", "{{index .MUI64S 3}}", "ui643", tVal, true},
	{"map MI8S", "{{index .MI8S 3}}", "i83", tVal, true},
	{"map MUI8S", "{{index .MUI8S 2}}", "u82", tVal, true},
	{"index of an interface field", "{{index .Empty3 0}}", "7", tVal, true},

	// Slicing.
	{"slice[:]", "{{slice .SI}}", "[3 4 5]", tVal, true},
	{"slice[1:]", "{{slice .SI 1}}", "[4 5]", tVal, true},
	{"slice[1:2]", "{{slice .SI 1 2}}", "[4]", tVal, true},
	{"slice[-1:]", "{{slice .SI -1}}", "", tVal, false},
	{"slice[1:-2]", "{{slice .SI 1 -2}}", "", tVal, false},
	{"slice[1:2:-1]", "{{slice .SI 1 2 -1}}", "", tVal, false},
	{"slice[2:1]", "{{slice .SI 2 1}}", "", tVal, false},
	{"slice[2:2:1]", "{{slice .SI 2 2 1}}", "", tVal, false},
	{"out of range", "{{slice .SI 4 5}}", "", tVal, false},
	{"out of range", "{{slice .SI 2 2 5}}", "", tVal, false},
	{"len(s) < indexes < cap(s)", "{{slice .SICap 6 10}}", "[0 0 0 0]", tVal, true},
	{"len(s) < indexes < cap(s)", "{{slice .SICap 6 10 10}}", "[0 0 0 0]", tVal, true},
	{"indexes > cap(s)", "{{slice .SICap 10 11}}", "", tVal, false},
	{"indexes > cap(s)", "{{slice .SICap 6 10 11}}", "", tVal, false},
	{"array[:]", "{{slice .AI}}", "[3 4 5]", tVal, true},
	{"array[1:]", "{{slice .AI 1}}", "[4 5]", tVal, true},
	{"array[1:2]", "{{slice .AI 1 2}}", "[4]", tVal, true},
	{"string[:]", "{{slice .S}}", "xyz", tVal, true},
	{"string[0:1]", "{{slice .S 0 1}}", "x", tVal, true},
	{"string[1:]", "{{slice .S 1}}", "yz", tVal, true},
	{"string[1:2]", "{{slice .S 1 2}}", "y", tVal, true},
	{"out of range", "{{slice .S 1 5}}", "", tVal, false},
	{"3-index slice of string", "{{slice .S 1 2 2}}", "", tVal, false},
	{"slice of an interface field", "{{slice .Empty3 0 1}}", "[7]", tVal, true},

	// Len.
	{"slice", "{{len .SI}}", "3", tVal, true},
	{"map", "{{len .MSI }}", "3", tVal, true},
	{"len of int", "{{len 3}}", "", tVal, false},
	{"len of nothing", "{{len .Empty0}}", "", tVal, false},
	{"len of an interface field", "{{len .Empty3}}", "2", tVal, true},

	// With.
	{"with true", "{{with true}}{{.}}{{end}}", "true", tVal, true},
	{"with false", "{{with false}}{{.}}{{else}}FALSE{{end}}", "FALSE", tVal, true},
	{"with 1", "{{with 1}}{{.}}{{else}}ZERO{{end}}", "1", tVal, true},
	{"with 0", "{{with 0}}{{.}}{{else}}ZERO{{end}}", "ZERO", tVal, true},
	{"with 1.5", "{{with 1.5}}{{.}}{{else}}ZERO{{end}}", "1.5", tVal, true},
	{"with 0.0", "{{with .FloatZero}}{{.}}{{else}}ZERO{{end}}", "ZERO", tVal, true},
	{"with 1.5i", "{{with 1.5i}}{{.}}{{else}}ZERO{{end}}", "(0&#43;1.5i)", tVal, true},
	{"with 0.0i", "{{with .ComplexZero}}{{.}}{{else}}ZERO{{end}}", "ZERO", tVal, true},
	{"with emptystring", "{{with ``}}{{.}}{{else}}EMPTY{{end}}", "EMPTY", tVal, true},
	{"with string", "{{with `notempty`}}{{.}}{{else}}EMPTY{{end}}", "notempty", tVal, true},
	{"with emptyslice", "{{with .SIEmpty}}{{.}}{{else}}EMPTY{{end}}", "EMPTY", tVal, true},
	{"with slice", "{{with .SI}}{{.}}{{else}}EMPTY{{end}}", "[3 4 5]", tVal, true},
	{"with emptymap", "{{with .MSIEmpty}}{{.}}{{else}}EMPTY{{end}}", "EMPTY", tVal, true},
	{"with map", "{{with .MSIone}}{{.}}{{else}}EMPTY{{end}}", "map[one:1]", tVal, true},
	{"with empty interface, struct field", "{{with .Empty4}}{{.V}}{{end}}", "UinEmpty", tVal, true},
	{"with $x int", "{{with $x := .I}}{{$x}}{{end}}", "17", tVal, true},
	{"with $x struct.U.V", "{{with $x := $}}{{$x.U.V}}{{end}}", "v", tVal, true},
	{"with variable and action", "{{with $x := $}}{{$y := $.U.V}}{{$y}}{{end}}", "v", tVal, true},
	{"with on typed nil interface value", "{{with .NonEmptyInterfaceTypedNil}}TRUE{{ end }}", "", tVal, true},
	{"with else with", "{{with 0}}{{.}}{{else with true}}{{.}}{{end}}", "true", tVal, true},
	{"with else with chain", "{{with 0}}{{.}}{{else with false}}{{.}}{{else with `notempty`}}{{.}}{{end}}", "notempty", tVal, true},

	// Range.
	{"range []int", "{{range .SI}}-{{.}}-{{end}}", "-3--4--5-", tVal, true},
	{"range empty no else", "{{range .SIEmpty}}-{{.}}-{{end}}", "", tVal, true},
	{"range []int else", "{{range .SI}}-{{.}}-{{else}}EMPTY{{end}}", "-3--4--5-", tVal, true},
	{"range empty else", "{{range .SIEmpty}}-{{.}}-{{else}}EMPTY{{end}}", "EMPTY", tVal, true},
	{"range []int break else", "{{range .SI}}-{{.}}-{{break}}NOTREACHED{{else}}EMPTY{{end}}", "-3-", tVal, true},
	{"range []int continue else", "{{range .SI}}-{{.}}-{{continue}}NOTREACHED{{else}}EMPTY{{end}}", "-3--4--5-", tVal, true},
	{"range []bool", "{{range .SB}}-{{.}}-{{end}}", "-true--false-", tVal, true},
	{"range []int method", "{{range .SI | .MAdd .I}}-{{.}}-{{end}}", "-20--21--22-", tVal, true},
	{"range map", "{{range .MSI}}-{{.}}-{{end}}", "-1--3--2-", tVal, true},
	{"range empty map no else", "{{range .MSIEmpty}}-{{.}}-{{end}}", "", tVal, true},
	{"range map else", "{{range .MSI}}-{{.}}-{{else}}EMPTY{{end}}", "-1--3--2-", tVal, true},
	{"range empty map else", "{{range .MSIEmpty}}-{{.}}-{{else}}EMPTY{{end}}", "EMPTY", tVal, true},
	{"range empty interface", "{{range .Empty3}}-{{.}}-{{else}}EMPTY{{end}}", "-7--8-", tVal, true},
	{"range empty nil", "{{range .Empty0}}-{{.}}-{{end}}", "", tVal, true},
	{"range $x SI", "{{range $x := .SI}}<{{$x}}>{{end}}", "&lt;3>&lt;4>&lt;5>", tVal, true},
	{"range $x $y SI", "{{range $x, $y := .SI}}<{{$x}}={{$y}}>{{end}}", "&lt;0=3>&lt;1=4>&lt;2=5>", tVal, true},
	{"range $x MSIone", "{{range $x := .MSIone}}<{{$x}}>{{end}}", "&lt;1>", tVal, true},
	{"range $x $y MSIone", "{{range $x, $y := .MSIone}}<{{$x}}={{$y}}>{{end}}", "&lt;one=1>", tVal, true},
	{"range $x PSI", "{{range $x := .PSI}}<{{$x}}>{{end}}", "&lt;21>&lt;22>&lt;23>", tVal, true},
	{"declare in range", "{{range $x := .PSI}}<{{$foo:=$x}}{{$x}}>{{end}}", "&lt;21>&lt;22>&lt;23>", tVal, true},
	{"range count", `{{range $i, $x := count 5}}[{{$i}}]{{$x}}{{end}}`, "[0]a[1]b[2]c[3]d[4]e", tVal, true},
	{"range nil count", `{{range $i, $x := count 0}}{{else}}empty{{end}}`, "empty", tVal, true},

	// Cute examples.
	{"or as if true", `{{or .SI "slice is empty"}}`, "[3 4 5]", tVal, true},
	{"or as if false", `{{or .SIEmpty "slice is empty"}}`, "slice is empty", tVal, true},

	// Error handling.
	{"error method, error", "{{.MyError true}}", "", tVal, false},
	{"error method, no error", "{{.MyError false}}", "false", tVal, true},

	// Numbers
	{"decimal", "{{print 1234}}", "1234", tVal, true},
	{"decimal _", "{{print 12_34}}", "1234", tVal, true},
	{"binary", "{{print 0b101}}", "5", tVal, true},
	{"binary _", "{{print 0b_1_0_1}}", "5", tVal, true},
	{"BINARY", "{{print 0B101}}", "5", tVal, true},
	{"octal0", "{{print 0377}}", "255", tVal, true},
	{"octal", "{{print 0o377}}", "255", tVal, true},
	{"octal _", "{{print 0o_3_7_7}}", "255", tVal, true},
	{"OCTAL", "{{print 0O377}}", "255", tVal, true},
	{"hex", "{{print 0x123}}", "291", tVal, true},
	{"hex _", "{{print 0x1_23}}", "291", tVal, true},
	{"HEX", "{{print 0X123ABC}}", "1194684", tVal, true},
	{"float", "{{print 123.4}}", "123.4", tVal, true},
	{"float _", "{{print 0_0_1_2_3.4}}", "123.4", tVal, true},
	{"hex float", "{{print +0x1.ep+2}}", "7.5", tVal, true},
	{"hex float _", "{{print +0x_1.e_0p+0_2}}", "7.5", tVal, true},
	{"HEX float", "{{print +0X1.EP+2}}", "7.5", tVal, true},
	{"print multi", "{{print 1_2_3_4 7.5_00_00_00}}", "1234 7.5", tVal, true},
	{"print multi2", "{{print 1234 0x0_1.e_0p+02}}", "1234 7.5", tVal, true},

	// Fixed bugs.
	// Must separate dot and receiver; otherwise args are evaluated with dot set to variable.
	{"bug0", "{{range .MSIone}}{{if $.Method1 .}}X{{end}}{{end}}", "X", tVal, true},
	// Do not loop endlessly in indirect for non-empty interfaces.
	// The bug appears with *interface only; looped forever.
	{"bug1", "{{.Method0}}", "M0", &iVal, true},
	// Was taking address of interface field, so method set was empty.
	{"bug2", "{{$.NonEmptyInterface.Method0}}", "M0", tVal, true},
	// Struct values were not legal in with - mere oversight.
	{"bug3", "{{with $}}{{.Method0}}{{end}}", "M0", tVal, true},
	// Nil interface values in if.
	{"bug4", "{{if .Empty0}}non-nil{{else}}nil{{end}}", "nil", tVal, true},
	// Stringer.
	{"bug5", "{{.Str}}", "foozle", tVal, true},
	{"bug5a", "{{.Err}}", "erroozle", tVal, true},
	// Args need to be indirected and dereferenced sometimes.
	{"bug6a", "{{vfunc .V0 .V1}}", "vfunc", tVal, true},
	{"bug6b", "{{vfunc .V0 .V0}}", "vfunc", tVal, true},
	{"bug6c", "{{vfunc .V1 .V0}}", "vfunc", tVal, true},
	{"bug6d", "{{vfunc .V1 .V1}}", "vfunc", tVal, true},
	// Legal parse but illegal execution: non-function should have no arguments.
	{"bug7a", "{{3 2}}", "", tVal, false},
	{"bug7b", "{{$x := 1}}{{$x 2}}", "", tVal, false},
	{"bug7c", "{{$x := 1}}{{3 | $x}}", "", tVal, false},
	// Pipelined arg was not being type-checked.
	{"bug8a", "{{3|oneArg}}", "", tVal, false},
	{"bug8b", "{{4|dddArg 3}}", "", tVal, false},
	// A bug was introduced that broke map lookups for lower-case names.
	{"bug9", "{{.cause}}", "neglect", map[string]string{"cause": "neglect"}, true},
	// Field chain starting with function did not work.
	{"bug10", "{{mapOfThree.three}}-{{(mapOfThree).three}}", "3-3", 0, true},
	// Dereferencing nil pointer while evaluating function arguments should not panic. Issue 7333.
	{"bug11", "{{valueString .PS}}", "", T{}, false},
	// 0xef gave constant type float64. Issue 8622.
	{"bug12xe", "{{printf `%T` 0xef}}", "int", T{}, true},
	{"bug12xE", "{{printf `%T` 0xEE}}", "int", T{}, true},
	{"bug12Xe", "{{printf `%T` 0Xef}}", "int", T{}, true},
	{"bug12XE", "{{printf `%T` 0XEE}}", "int", T{}, true},
	// Chained nodes did not work as arguments. Issue 8473.
	{"bug13", "{{print (.Copy).I}}", "17", tVal, true},
	// Didn't protect against nil or literal values in field chains.
	{"bug14a", "{{(nil).True}}", "", tVal, false},
	{"bug14b", "{{$x := nil}}{{$x.anything}}", "", tVal, false},
	{"bug14c", `{{$x := (1.0)}}{{$y := ("hello")}}{{$x.anything}}{{$y.true}}`, "", tVal, false},
	// Didn't call validateType on function results. Issue 10800.
	{"bug15", "{{valueString returnInt}}", "", tVal, false},
	// Variadic function corner cases. Issue 10946.
	{"bug16a", "{{true|printf}}", "", tVal, false},
	{"bug16b", "{{1|printf}}", "", tVal, false},
	{"bug16c", "{{1.1|printf}}", "", tVal, false},
	{"bug16d", "{{'x'|printf}}", "", tVal, false},
	{"bug16e", "{{0i|printf}}", "", tVal, false},
	{"bug16f", "{{true|twoArgs \"xxx\"}}", "", tVal, false},
	{"bug16g", "{{\"aaa\" |twoArgs \"bbb\"}}", "twoArgs=bbbaaa", tVal, true},
	{"bug16h", "{{1|oneArg}}", "", tVal, false},
	{"bug16i", "{{\"aaa\"|oneArg}}", "oneArg=aaa", tVal, true},
	{"bug16j", "{{1+2i|printf \"%v\"}}", "(1&#43;2i)", tVal, true},
	{"bug16k", "{{\"aaa\"|printf }}", "aaa", tVal, true},
	{"bug17a", "{{.NonEmptyInterface.X}}", "x", tVal, true},
	{"bug17b", "-{{.NonEmptyInterface.Method1 1234}}-", "-1234-", tVal, true},
	{"bug17c", "{{len .NonEmptyInterfacePtS}}", "2", tVal, true},
	{"bug17d", "{{index .NonEmptyInterfacePtS 0}}", "a", tVal, true},
	{"bug17e", "{{range .NonEmptyInterfacePtS}}-{{.}}-{{end}}", "-a--b-", tVal, true},

	// More variadic function corner cases. Some runes would get evaluated
	// as constant floats instead of ints. Issue 34483.
	{"bug18a", "{{eq . '.'}}", "true", '.', true},
	{"bug18b", "{{eq . 'e'}}", "true", 'e', true},
	{"bug18c", "{{eq . 'P'}}", "true", 'P', true},
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
			tmpl, err = template.Clone()
			if err != nil {
				t.Errorf("%s: clone error: %s", test.name, err)
				continue
			}
			tmpl, err = tmpl.New(test.name).Funcs(funcs).Parse(test.input)
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

fun
```