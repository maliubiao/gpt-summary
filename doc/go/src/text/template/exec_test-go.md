Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The request asks for an analysis of a specific Go file (`exec_test.go`) within the `text/template` package. The focus is on its functionality, particularly in the context of testing the `text/template` package.

2. **Identify the Core Purpose:**  The file name itself, `exec_test.go`, strongly suggests that this file contains *tests* for the *execution* phase of the `text/template` package. This is a crucial starting point.

3. **Examine the Imports:** The `import` statements provide valuable clues about the functionalities being tested:
    * `"bytes"`: Likely used for working with byte buffers, potentially for capturing template output.
    * `"errors"`:  Used for creating and handling errors, suggesting tests involving error conditions in template execution.
    * `"flag"`: Indicates the presence of command-line flags that might control test behavior (like the `debug` flag).
    * `"fmt"`:  For formatted I/O, used for printing and string formatting within tests.
    * `"io"`:  Basic input/output interfaces, might be used if templates interact with streams.
    * `"iter"`:  Suggests testing of iteration features within templates (e.g., `range`).
    * `"reflect"`: Essential for inspecting the types and values of Go objects at runtime, vital for template execution.
    * `"strings"`: For string manipulation, likely used in constructing or comparing template outputs.
    * `"sync"`: Might be relevant if there are tests involving concurrent template execution (less likely for basic execution tests).
    * `"testing"`:  The core Go testing package, confirming the file's purpose as a test suite.

4. **Analyze the Global Variables and Types:**
    * `debug`: A boolean flag controlled by the command line, likely used to enable more verbose output during test runs.
    * `T`: A struct with a wide variety of fields (basic types, nested structs, slices, maps, interfaces, functions, templates). This is clearly the primary data structure used to feed data into the templates during testing. The diversity of fields is a strong indication that the tests aim to cover many different scenarios of data access within templates.
    * `S`, `U`, `V`, `W`: Helper structs and types, often with methods like `String()` or `Error()`, used to test how templates interact with custom types.
    * `tVal`: An instance of `T` populated with sample data. This is a key input for many tests.
    * `tSliceOfNil`:  A slice containing a nil pointer of type `T`, likely used to test how templates handle nil values.
    * `I`: An interface, used to test interface handling within templates.
    * `iVal`: An instance of the interface `I`.
    * `execTest`: A struct that defines the structure of individual test cases. Each test has a `name`, `input` (the template string), `output` (the expected output), `data` (the input data for the template), and `ok` (whether the test is expected to succeed or fail).
    * `execTests`: A slice of `execTest` structs – the actual test suite. The numerous test cases demonstrate the extensive nature of the testing. The names of the tests often hint at the specific feature being tested (e.g., "`.X`", "`.U.V`", `"if true`", `"range []int"`).

5. **Infer Functionality Based on Test Cases:** By skimming through the `execTests` array, you can start to understand the specific Go language features that the `text/template` package implements and that this test suite is verifying:
    * Accessing struct fields (`.X`, `.U.V`).
    * Accessing map elements (`.MSI.one`).
    * Basic data type handling (int, float, bool, string).
    * Variable declaration and assignment (`$x := ...`).
    * Calling methods on structs (`.Method0`, `.Method1`).
    * Calling functions (both regular and variadic) using the `call` keyword.
    * Pipelines (`{{.Method0 | .Method2 .U16}}`).
    * Conditional statements (`if`, `else`, `else if`).
    * Built-in functions like `print`, `println`, `printf`, `html`, `js`, `urlquery`, `not`, `and`, `or`, `index`, `slice`, `len`.
    * Looping (`range`).
    * The `with` action for changing the context.
    * Handling of `nil` values.
    * Error handling from methods.

6. **Focus on the Request's Questions:**

    * **List of Functions:**  The primary function is to test the *execution* of templates. It doesn't implement new Go language features, but rather tests the *template language's* features.
    * **Go Language Feature Implementation:** The `text/template` package implements a template language. This test suite verifies the correct interpretation and execution of that language.
    * **Code Examples:** To provide examples, select some of the test cases and demonstrate how they would work in a real `text/template` scenario. Explain the input template, the data, and the expected output.
    * **Input/Output and Assumptions:**  For code examples, explicitly state the input data and the expected output.
    * **Command-Line Arguments:** Describe the `debug` flag and its likely effect.
    * **Common Mistakes:**  Think about potential pitfalls for users of the `text/template` package, based on the tests. Examples include incorrect syntax, type mismatches, accessing non-existent fields, or misunderstanding the context (`.`).
    * **Functionality Summary:**  Synthesize the findings into a concise summary.

7. **Structure the Answer:** Organize the analysis into clear sections based on the request's prompts. Use headings and bullet points for readability. Provide code examples in code blocks with explanations.

8. **Refine and Review:** After drafting the answer, reread it to ensure accuracy, clarity, and completeness. Check that all aspects of the request have been addressed. For instance, ensure the explanation of the `debug` flag is clear and that the code examples are correct and well-explained.

By following this process of examining the file's name, imports, data structures, and test cases, you can effectively deduce the functionality of this Go testing file and provide a comprehensive analysis.
这是 `go/src/text/template/exec_test.go` 文件的第一部分，它主要用于**测试 `text/template` 包中模板的执行（execution）过程**。

**功能归纳:**

* **定义了用于测试的数据结构和测试用例:**  文件中定义了 `T` 结构体，包含了各种类型的数据（基本类型、结构体、切片、映射、接口、函数等），用于作为模板执行时的数据输入。同时，`execTests` 切片包含了大量的 `execTest` 结构体，每个 `execTest` 定义了一个具体的测试用例，包括模板字符串、预期输出、输入数据以及是否期望测试通过。
* **覆盖了模板语法的各种特性:**  通过 `execTests` 中的众多测试用例，该文件旨在测试 `text/template` 包对各种模板语法的支持和执行情况，例如：
    * 访问结构体字段和方法。
    * 访问映射的元素。
    * 使用变量。
    * 调用函数（包括自定义函数和内置函数）。
    * 使用管道。
    * 使用条件语句 (`if`, `else`)。
    * 使用循环语句 (`range`)。
    * 使用 `with` 语句改变上下文。
    * 内置函数的使用（如 `print`, `println`, `printf`, `html`, `js`, `urlquery`, `len`, `index`, `slice`, `not`, `and`, `or` 等）。
    * 处理 `nil` 值。
    * 处理错误。
    * 进行算术运算和比较操作（虽然这部分在提供的代码中没有直接体现，但通常与模板执行相关）。
* **测试了不同数据类型的处理:**  `T` 结构体和 `execTests` 覆盖了各种 Go 语言的数据类型，确保模板引擎能够正确处理不同类型的数据。
* **测试了接口的处理:**  文件中包含了对空接口和非空接口的处理测试，验证模板引擎能否正确访问接口的值和方法。
* **测试了函数调用，包括普通函数和变参函数:**  通过 `BinaryFunc`, `VariadicFunc` 等字段，测试了模板中调用不同类型 Go 函数的能力。
* **使用了命令行 flag 控制测试行为:**  `debug` 变量通过 `flag` 包进行定义，允许用户在运行测试时通过命令行参数控制是否显示错误信息。

**它是什么 go 语言功能的实现？**

这部分代码本身 **不是** 某个 Go 语言功能的具体实现，而是 `text/template` 包执行功能的 **测试代码**。`text/template` 包实现了 **文本模板引擎**，允许开发者将数据渲染到预定义的文本模板中，生成最终的文本输出。

**Go 代码举例说明:**

假设我们要测试模板如何访问 `T` 结构体中的 `I` 字段：

```go
package main

import (
	"fmt"
	"os"
	"text/template"
)

// 假设这是从 exec_test.go 中提取的 T 结构体定义
type T struct {
	I int
}

func main() {
	tmplStr := "{{.I}}" // 模板字符串，访问 T 结构体的 I 字段
	t := T{I: 123}      // 创建 T 结构体的实例

	tmpl, err := template.New("test").Parse(tmplStr)
	if err != nil {
		panic(err)
	}

	err = tmpl.Execute(os.Stdout, t)
	if err != nil {
		panic(err)
	}
}
```

**假设的输入与输出:**

**输入:**  运行上述 `main.go` 程序。

**输出:** `123`

**代码推理:**

1. 我们定义了一个简单的模板字符串 `{{.I}}`，它指示模板引擎访问输入数据（类型为 `T`）的 `I` 字段。
2. 我们创建了一个 `T` 类型的实例 `t`，并将 `I` 字段设置为 `123`。
3. `tmpl.Execute(os.Stdout, t)`  会执行模板，并将 `t` 作为数据传入。
4. 模板引擎会找到 `t` 的 `I` 字段，其值为 `123`，并将其渲染到输出（标准输出）。

**命令行参数的具体处理:**

文件中定义了一个名为 `debug` 的布尔类型的命令行 flag：

```go
var debug = flag.Bool("debug", false, "show the errors produced by the tests")
```

在运行测试时，可以使用 `-debug` 命令行参数来控制其值：

* **不使用 `-debug` 参数或使用 `-debug=false`:** `debug` 的值为 `false`，测试过程中产生的错误信息可能不会被详细显示。
* **使用 `-debug=true`:** `debug` 的值为 `true`，测试框架可能会打印更详细的错误信息，方便开发者调试测试失败的用例。

具体的错误显示逻辑应该在测试框架的其他部分实现，例如在执行每个 `execTest` 时，如果模板执行出错，会根据 `debug` 的值决定是否打印错误详情。

**使用者易犯错的点（根据测试用例推断）:**

* **访问不存在的字段或映射键:**  例如 `{{.NO}}` 访问 `MSI` 中不存在的键，会导致输出 `<no value>`。使用者可能会忘记处理这种情况。
* **类型不匹配:**  例如在映射访问中使用错误的键类型 `{{.MII.one}}`（`MII` 的键是 `int`，而 `one` 是字符串）。
* **函数调用参数不匹配:**  例如 `{{call .BinaryFunc `1`}}` 传递给需要两个参数的函数只传递了一个。
* **在 `if` 或 `with` 等语句中使用不符合预期求值结果的值:**  例如认为空字符串或空切片在 `if` 语句中会认为是真。
* **不理解作用域和变量的生命周期:**  例如在嵌套的 `if` 语句中重新声明同名变量，可能会导致外部作用域的变量值没有改变。

**总结:**

`go/src/text/template/exec_test.go` 的第一部分定义了用于测试 `text/template` 包模板执行功能的数据结构和大量的测试用例，覆盖了模板语法的各种特性、不同数据类型的处理、接口和函数调用等。它通过命令行 flag 提供了一种控制测试行为的方式，并通过丰富的测试用例揭示了使用者在使用模板时可能遇到的常见错误。该文件的核心目标是确保 `text/template` 包的模板执行功能能够按照预期工作。

Prompt: 
```
这是路径为go/src/text/template/exec_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"errors"
	"flag"
	"fmt"
	"io"
	"iter"
	"reflect"
	"strings"
	"sync"
	"testing"
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
	BinaryFunc             func(string, string) string
	VariadicFunc           func(...string) string
	VariadicFuncInt        func(int, ...string) string
	NilOKFunc              func(*int) bool
	ErrFunc                func() (string, error)
	PanicFunc              func() string
	TooFewReturnCountFunc  func()
	TooManyReturnCountFunc func() (string, error, int)
	InvalidReturnTypeFunc  func() (string, bool)
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
	TooFewReturnCountFunc:     func() {},
	TooManyReturnCountFunc:    func() (string, error, int) { return "", nil, 0 },
	InvalidReturnTypeFunc:     func() (string, bool) { return "", false },
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
	{"map .NO", "{{.MSI.NO}}", "<no value>", tVal, true},
	{"map .one interface", "{{.MXI.one}}", "1", tVal, true},
	{"map .WRONG args", "{{.MSI.one 1}}", "", tVal, false},
	{"map .WRONG type", "{{.MII.one}}", "", tVal, false},

	// Dots of all kinds to test basic evaluation.
	{"dot int", "<{{.}}>", "<13>", 13, true},
	{"dot uint", "<{{.}}>", "<14>", uint(14), true},
	{"dot float", "<{{.}}>", "<15.1>", 15.1, true},
	{"dot bool", "<{{.}}>", "<true>", true, true},
	{"dot complex", "<{{.}}>", "<(16.2-17i)>", 16.2 - 17i, true},
	{"dot string", "<{{.}}>", "<hello>", "hello", true},
	{"dot slice", "<{{.}}>", "<[-1 -2 -3]>", []int{-1, -2, -3}, true},
	{"dot map", "<{{.}}>", "<map[two:22]>", map[string]int{"two": 22}, true},
	{"dot struct", "<{{.}}>", "<{7 seven}>", struct {
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
	{"V{6666}.String()", "-{{.V0}}-", "-<6666>-", tVal, true},
	{"&V{7777}.String()", "-{{.V1}}-", "-<7777>-", tVal, true},
	{"(*V)(nil).String()", "-{{.V2}}-", "-nilV-", tVal, true},

	// Type with Error method.
	{"W{888}.Error()", "-{{.W0}}-", "-[888]-", tVal, true},
	{"&W{999}.Error()", "-{{.W1}}-", "-[999]-", tVal, true},
	{"(*W)(nil).Error()", "-{{.W2}}-", "-nilW-", tVal, true},

	// Pointers.
	{"*int", "{{.PI}}", "23", tVal, true},
	{"*string", "{{.PS}}", "a string", tVal, true},
	{"*[]int", "{{.PSI}}", "[21 22 23]", tVal, true},
	{"*[]int[1]", "{{index .PSI 1}}", "22", tVal, true},
	{"NIL", "{{.NIL}}", "<nil>", tVal, true},

	// Empty interfaces holding values.
	{"empty nil", "{{.Empty0}}", "<no value>", tVal, true},
	{"empty with int", "{{.Empty1}}", "3", tVal, true},
	{"empty with string", "{{.Empty2}}", "empty2", tVal, true},
	{"empty with slice", "{{.Empty3}}", "[7 8]", tVal, true},
	{"empty with struct", "{{.Empty4}}", "{UinEmpty}", tVal, true},
	{"empty with struct, field", "{{.Empty4.V}}", "UinEmpty", tVal, true},

	// Edge cases with <no value> with an interface value
	{"field on interface", "{{.foo}}", "<no value>", nil, true},
	{"field on parenthesized interface", "{{(.).foo}}", "<no value>", nil, true},

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
	{".Method3(nil constant)", "-{{.Method3 nil}}-", "-Method3: <nil>-", tVal, true},
	{".Method3(nil value)", "-{{.Method3 .MXI.unset}}-", "-Method3: <nil>-", tVal, true},
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
	{".VariadicFunc0", "{{call .VariadicFunc}}", "<>", tVal, true},
	{".VariadicFunc2", "{{call .VariadicFunc `he` `llo`}}", "<he+llo>", tVal, true},
	{".VariadicFuncInt", "{{call .VariadicFuncInt 33 `he` `llo`}}", "33=<he+llo>", tVal, true},
	{"if .BinaryFunc call", "{{ if .BinaryFunc}}{{call .BinaryFunc `1` `2`}}{{end}}", "[1=2]", tVal, true},
	{"if not .BinaryFunc call", "{{ if not .BinaryFunc}}{{call .BinaryFunc `1` `2`}}{{else}}No{{end}}", "No", tVal, true},
	{"Interface Call", `{{stringer .S}}`, "foozle", map[string]any{"S": bytes.NewBufferString("foozle")}, true},
	{".ErrFunc", "{{call .ErrFunc}}", "bla", tVal, true},
	{"call nil", "{{call nil}}", "", tVal, false},
	{"empty call", "{{call}}", "", tVal, false},
	{"empty call after pipe valid", "{{.ErrFunc | call}}", "bla", tVal, true},
	{"empty call after pipe invalid", "{{1 | call}}", "", tVal, false},

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
	{"pipeline func", "-{{call .VariadicFunc `llo` | call .VariadicFunc `he` }}-", "-<he+<llo>>-", tVal, true},

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
	{"print nil", `{{print nil}}`, "<nil>", tVal, true},
	{"println", `{{println 1 2 3}}`, "1 2 3\n", tVal, true},
	{"printf int", `{{printf "%04x" 127}}`, "007f", tVal, true},
	{"printf float", `{{printf "%g" 3.5}}`, "3.5", tVal, true},
	{"printf complex", `{{printf "%g" 1+7i}}`, "(1+7i)", tVal, true},
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
	{"html untyped nil", `{{html .Empty0}}`, "&lt;no value&gt;", tVal, true},

	// JavaScript.
	{"js", `{{js .}}`, `It\'d be nice.`, `It'd be nice.`, true},

	// URL query.
	{"urlquery", `{{"http://www.example.org/"|urlquery}}`, "http%3A%2F%2Fwww.example.org%2F", nil, true},

	// Booleans
	{"not", "{{not true}} {{not false}}", "false true", nil, true},
	{"and", "{{and false 0}} {{and 1 0}} {{and 0 true}} {{and 1 1}}", "false 0 0 1", nil, true},
	{"or", "{{or 0 0}} {{or 1 0}} {{or 0 true}} {{or 1 1}}", "0 1 true 1", nil, true},
	{"or short-circuit", "{{or 0 1 (die)}}", "1", nil, true},
	{"and short-circuit", "{{and 1 0 (die)}}", "0", nil, true},
	{"or short-circuit2", "{{or 0 0 (die)}}", "", nil, false},
	{"and short-circuit2", "{{and 1 1 (die)}}", "", nil, false},
	{"and pipe-true", "{{1 | and 1}}", "1", nil, true},
	{"and pipe-false", "{{0 | and 1}}", "0", nil, true},
	{"or pipe-true", "{{1 | or 0}}", "1", nil, true},
	{"or pipe-false", "{{0 | or 0}}", "0", nil, true},
	{"and undef", "{{and 1 .Unknown}}", "<no value>", nil, true},
	{"or undef", "{{or 0 .Unknown}}", "<no value>", nil, true},
	{"boolean if", "{{if and true 1 `hi`}}TRUE{{else}}FALSE{{end}}", "TRUE", tVal, true},
	{"boolean if not", "{{if and true 1 `hi` | not}}TRUE{{else}}FALSE{{end}}", "FALSE", nil, true},
	{"boolean if pipe", "{{if true | not | and 1}}TRUE{{else}}FALSE{{end}}", "FALSE", nil, true},

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
	{"with 1.5i", "{{with 1.5i}}{{.}}{{else}}ZERO{{end}}", "(0+1.5i)", tVal, true},
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
	{"range $x SI", "{{range $x := .SI}}<{{$x}}>{{end}}", "<3><4><5>", tVal, true},
	{"range $x $y SI", "{{range $x, $y := .SI}}<{{$x}}={{$y}}>{{end}}", "<0=3><1=4><2=5>", tVal, true},
	{"range $x MSIone", "{{range $x := .MSIone}}<{{$x}}>{{end}}", "<1>", tVal, true},
	{"range $x $y MSIone", "{{range $x, $y := .MSIone}}<{{$x}}={{$y}}>{{end}}", "<one=1>", tVal, true},
	{"range $x PSI", "{{range $x := .PSI}}<{{$x}}>{{end}}", "<21><22><23>", tVal, true},
	{"declare in range", "{{range $x := .PSI}}<{{$foo:=$x}}{{$x}}>{{end}}", "<21><22><23>", tVal, true},
	{"range count", `{{range $i, $x := count 5}}[{{$i}}]{{$x}}{{end}}`, "[0]a[1]b[2]c[3]d[4]e", tVal, true},
	{"range nil count", `{{range $i, $x := count 0}}{{else}}empty{{end}}`, "empty", tVal, true},
	{"range iter.Seq[int]", `{{range $i := .}}{{$i}}{{end}}`, "01", fVal1(2), true},
	{"i = range iter.Seq[int]", `{{$i := 0}}{{range $i = .}}{{$i}}{{end}}`, "01", fVal1(2), true},
	{"range iter.Seq[int] over two var", `{{range $i, $c := .}}{{$c}}{{end}}`, "", fVal1(2), false},
	{"i, c := range iter.Seq2[int,int]", `{{range $i, $c := .}}{{$i}}{{$c}}{{end}}`, "0112", fVal2(2), true},
	{"i, c = range iter.Seq2[int,int]", `{{$i := 0}}{{$c := 0}}{{range $i, $c = .}}{{$i}}{{$c}}{{end}}`, "0112", fVal2(2), true},
	{"i = range iter.Seq2[int,int]", `{{$i := 0}}{{range $i = .}}{{$i}}{{end}}`, "01", fVal2(2), true},
	{"i := range iter.Seq2[int,int]", `{{range $i := .}}{{$i}}{{end}}`, "01", fVal2(2), true},
	{"i,c,x range iter.Seq2[int,int]", `{{$i := 0}}{{$c := 0}}{{$x := 0}}{{range $i, $c = .}}{{$i}}{{$c}}{{end}}`, "0112", fVal2(2), true},
	{"i,x range iter.Seq[int]", `{{$i := 0}}{{$x := 0}}{{range $i = .}}{{$i}}{{end}}`, "01", fVal1(2), true},
	{"range iter.Seq[int] else", `{{range $i := .}}{{$i}}{{else}}empty{{end}}`, "empty", fVal1(0), true},
	{"range iter.Seq2[int,int] else", `{{range $i := .}}{{$i}}{{else}}empty{{end}}`, "empty", fVal2(0), true},
	{"range int8", rangeTestInt, rangeTestData[int8](), int8(5), true},
	{"range int16", rangeTestInt, rangeTestData[int16](), int16(5), true},
	{"range int32", rangeTestInt, rangeTestData[int32](), int32(5), true},
	{"range int64", rangeTestInt, rangeTestData[int64](), int64(5), true},
	{"range int", rangeTestInt, rangeTestData[int](), int(5), true},
	{"range uint8", rangeTestInt, rangeTestData[uint8](), uint8(5), true},
	{"range uint16", rangeTestInt, rangeTestData[uint16](), uint16(5), true},
	{"range uint32", rangeTestInt, rangeTestData[uint32](), uint32(5), true},
	{"range uint64", rangeTestInt, rangeTestData[uint64](), uint64(5), true},
	{"range uint", rangeTestInt, rangeTestData[uint](), uint(5), true},
	{"range uintptr", rangeTestInt, rangeTestData[uintptr](), uintptr(5), true},
	{"range uintptr(0)", `{{range $v := .}}{{print $v}}{{else}}empty{{end}}`, "empty", uintptr(0), true},
	{"range 5", `{{range $v := 5}}{{printf "%T%d" $v $v}}{{end}}`, rangeTestData[int](), nil, true},

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
	{"bug16j", "{{1+2i|printf \"%v\"}}", "(1+2i)", tVal, true},
	{"bug16k", "{{\"aaa\"|printf }}", "aaa", tVal, true},
	{"bug17a", "{{.NonEmptyInterface.X}}", "x", tVal, true},
	{"bug17b", "-{{.NonEmptyInterface.Method1 1234}}-", "-1234-", tVal, true},
	{"bug17c", "{{len .NonEmptyInterfacePtS}}", "2", tVal, true},
	{"bug17d", "{{index .NonEmptyInterfacePtS 0}}", "a", tVal, true},
	{"bug17e", "{{range .NonEmptyInterfacePtS}}-{{.}}-{{end}}", "-a--b-", tVal, true},

	// More variadic function corner cases. Some runes would get ev
"""




```