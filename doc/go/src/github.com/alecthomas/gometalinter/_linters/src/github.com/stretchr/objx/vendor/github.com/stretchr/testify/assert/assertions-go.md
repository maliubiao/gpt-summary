Response:
My thought process for analyzing the provided Go code snippet and generating the summary goes like this:

1. **Understand the Goal:** The request asks for a functional summary of the provided Go code, focusing on its purpose and capabilities within the context of testing. It also asks for specific examples and handling of potential errors.

2. **Identify the Core Package:** The `package assert` declaration immediately tells me this code is part of an assertion library. The import path (`github.com/stretchr/testify/assert`) confirms this is likely a component of the popular `testify` assertion library.

3. **Scan for Key Data Structures and Interfaces:** I look for defined types and interfaces. The `TestingT` interface is crucial – it represents the testing context (like `*testing.T`). The `ComparisonAssertionFunc`, `ValueAssertionFunc`, `BoolAssertionFunc`, and `ErrorAssertionFunc` type definitions signal the presence of functions for performing different types of assertions. The `Comparison` type indicates a way to define custom assertion logic.

4. **Identify Helper Functions:**  Functions like `ObjectsAreEqual`, `ObjectsAreEqualValues`, `CallerInfo`, `isTest`, `messageFromMsgAndArgs`, `indentMessageLines`, `Fail`, and `FailNow` are clearly utility functions used internally by the assertion logic. `CallerInfo` is particularly interesting as it addresses the common problem of assertion failures pointing to the assertion library code instead of the test code.

5. **Analyze Assertion Functions:** I scan for functions that start with a capital letter and take `TestingT` as their first argument. These are likely the core assertion functions. I look for patterns in their names (e.g., `Equal`, `NotEqual`, `True`, `False`, `Nil`, `NotNil`, `Contains`, `Len`, `Panics`, `WithinDuration`, `InDelta`, `NoError`, `Error`). The names are usually quite descriptive of the assertion they perform.

6. **Categorize Functionality:**  Based on the identified assertion functions, I start grouping them by the type of assertion they perform:
    * **Equality:** `Equal`, `EqualValues`, `Exactly`, `NotEqual`
    * **Nil/Empty:** `Nil`, `NotNil`, `Empty`, `NotEmpty`
    * **Length:** `Len`
    * **Boolean:** `True`, `False`
    * **Containment:** `Contains`, `NotContains`, `Subset`, `NotSubset`, `ElementsMatch`
    * **Panics:** `Panics`, `PanicsWithValue`, `NotPanics`
    * **Time:** `WithinDuration`
    * **Numerical Comparisons (with tolerance):** `InDelta`, `InDeltaSlice`, `InDeltaMapValues`, `InEpsilon`, `InEpsilonSlice`
    * **Errors:** `NoError`, `Error`
    * **Type Assertions:** `Implements`, `IsType`
    * **Custom Conditions:** `Condition`

7. **Infer Purpose of Helper Functions:** I consider how the helper functions support the assertion functions. `ObjectsAreEqual` and `ObjectsAreEqualValues` are clearly used for the underlying comparison logic. `Fail` and `FailNow` handle reporting assertion failures. `CallerInfo` helps provide context for failures.

8. **Address Specific Requests:** I go back to the prompt and ensure I address all points:
    * **List Functionality:** This is the main goal and is covered by the categorization above.
    * **Infer Go Language Feature:** The code heavily utilizes reflection (`reflect` package) to compare objects of arbitrary types. This is a key Go feature being used.
    * **Code Examples (Part 2):**  I know I need to provide examples in the next part, illustrating how to use the different assertion functions.
    * **Code Reasoning with Assumptions:** When explaining the functionality, I make implicit assumptions about how the functions are used within a test context.
    * **Command-line Arguments:**  Based on the code, there's no explicit handling of command-line arguments *within this specific file*. The `//go:generate` line suggests code generation, which *might* involve command-line tools, but that's outside the scope of the provided snippet. Therefore, I'll state that no command-line arguments are handled *in this part*.
    * **Common Mistakes (Part 2):** I anticipate needing to address common mistakes in the next part, like using the wrong assertion for the intended comparison.
    * **Chinese Answer:** I ensure the response is in Chinese.
    * **Part 1 Summary:** I need to provide a concise summary of the overall functionality.

9. **Structure the Output:** I organize the information logically, starting with a general overview, then detailing the different categories of assertion functions, and finally summarizing the overall purpose. I use clear headings and bullet points for readability.

10. **Refine and Review:** I reread the prompt and my generated response to ensure accuracy, completeness, and clarity. I check for any inconsistencies or areas where more explanation might be needed.

By following this process, I can systematically analyze the Go code snippet and generate a comprehensive and accurate summary of its functionality, addressing all the requirements of the prompt.
这是 `go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/stretchr/objx/vendor/github.com/stretchr/testify/assert/assertions.go` 文件的第一部分，它实现了 `testify` 库中用于编写单元测试的断言功能。

**功能归纳：**

这部分代码定义了 `assert` 包，提供了一系列用于在 Go 语言测试中进行断言的函数。这些断言函数可以帮助开发者验证代码的行为是否符合预期。  它涵盖了多种类型的断言，例如：

* **基本比较：** 判断两个值是否相等、不等、为 `nil` 或非 `nil`。
* **类型判断：** 判断对象的类型是否符合预期，或者是否实现了某个接口。
* **容器类型断言：** 判断切片、数组或 map 的长度、是否包含某个元素或子集。
* **布尔值断言：** 判断一个布尔值是 `true` 还是 `false`。
* **Panic 断言：** 判断代码是否会触发 `panic`，以及 `panic` 的值是否符合预期。
* **时间断言：** 判断两个时间是否在一定的误差范围内。
* **数值精度断言：**  判断两个数值是否在一定的误差范围内（绝对误差或相对误差）。
* **错误断言：** 判断函数是否返回了错误，以及错误的具体内容。
* **自定义断言：** 允许用户使用自定义的比较函数进行断言。

**它是什么go语言功能的实现？**

这部分代码主要利用了 Go 语言的以下特性来实现断言功能：

* **接口 (Interfaces):**  `TestingT` 接口抽象了 Go 语言标准库 `testing` 包中的 `*testing.T` 类型，使得断言函数可以接收不同的测试上下文。
* **反射 (Reflection):**  `reflect` 包被广泛用于比较任意类型的对象，例如 `ObjectsAreEqual` 和 `ObjectsAreEqualValues` 函数。这使得断言函数可以处理各种数据类型，而不仅仅是预定义的类型。
* **变参函数 (Variadic functions):**  断言函数通常接收 `msgAndArgs ...interface{}` 作为最后一个参数，允许用户自定义断言失败时的消息。
* **错误处理 (Error handling):**  断言失败时，会调用 `t.Errorf` 来报告错误，并将调用栈信息打印出来，方便调试。
* **匿名函数和闭包 (Anonymous functions and closures):**  `Panics` 和 `NotPanics` 函数使用了匿名函数来捕获可能发生的 `panic`。
* **类型断言 (Type assertion):** 在 `FailNow` 函数中使用了类型断言 `t.(failNower)` 来判断 `TestingT` 是否实现了 `FailNow` 方法。

**Go代码举例说明:**

假设我们要测试一个计算两个整数和的函数 `Add(a, b int) int`。我们可以使用 `assert` 包中的断言函数来编写测试用例：

```go
package mypackage

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func Add(a, b int) int {
	return a + b
}

func TestAdd(t *testing.T) {
	// 测试正常情况
	result := Add(2, 3)
	assert.Equal(t, 5, result, "正常情况下，2 + 3 应该等于 5")

	// 测试负数
	result = Add(-1, 5)
	assert.Equal(t, 4, result, "负数相加的情况")

	// 测试零
	result = Add(0, 0)
	assert.Zero(t, result, "零加零应该等于零")
}
```

**假设的输入与输出：**

在上面的 `TestAdd` 函数中：

* **输入：**  `t` 是 `*testing.T` 类型的测试上下文对象，以及 `Add` 函数的不同输入参数 (例如 `2, 3`, `-1, 5`, `0, 0`)。
* **输出：**  如果断言成功，测试用例会继续执行。如果断言失败，`assert.Equal` 和 `assert.Zero` 函数会调用 `t.Errorf`，输出包含错误信息和调用栈的报告，导致测试失败。例如，如果我们将 `assert.Equal(t, 6, result, ...)` 写错为期望结果是 6，那么输出会类似于：

```
--- FAIL: TestAdd (0.00s)
    assertions_test.go:10:
        	Error Trace:	assertions_test.go:10
        			assertions_test.go:18
        	Error:      	正常情况下，2 + 3 应该等于 5
        	            	Not equal:
        	            	expected: 6
        	            	actual  : 5
        	Test:       	TestAdd
```

**命令行参数的具体处理：**

这段代码本身并没有直接处理命令行参数。命令行参数的处理通常由 `go test` 命令本身负责。 `testify` 库是在测试代码中使用的，它依赖于 `go test` 提供的测试框架。

**使用者易犯错的点：**

* **使用错误的断言函数：**  例如，想要判断两个浮点数是否在误差范围内，却使用了 `assert.Equal`，这会导致即使两个浮点数非常接近但由于精度问题而不相等，测试也会失败。应该使用 `assert.InDelta` 或 `assert.InEpsilon`。
* **忽略断言的返回值：**  断言函数返回一个布尔值，表示断言是否成功。虽然通常不需要显式地检查返回值，但在某些情况下，可以利用返回值进行链式调用或者提前返回。
* **自定义错误消息不清晰：**  虽然可以自定义错误消息，但如果消息不够清晰，当测试失败时，难以快速定位问题。建议提供有意义的错误消息，说明期望的行为和实际的行为。
* **对 `nil` 值的判断不当：**  需要区分 `nil` 接口和 `nil` 的具体类型值。 `assert.Nil` 可以处理这两种情况，但理解其工作原理很重要。
* **在不需要 `FailNow` 的情况下使用它：** `FailNow` 会立即终止当前测试用例的执行。如果只想标记测试失败，并继续执行后续的断言，应该使用 `Fail` 或普通的断言函数。

总而言之，这段代码是 `testify` 库中 `assert` 包的核心部分，提供了丰富的断言函数，帮助 Go 开发者编写更可靠和易于维护的单元测试。它利用了 Go 语言的多种特性来实现其功能，并为开发者提供了灵活的断言方式。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/stretchr/objx/vendor/github.com/stretchr/testify/assert/assertions.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
package assert

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/davecgh/go-spew/spew"
	"github.com/pmezard/go-difflib/difflib"
)

//go:generate go run ../_codegen/main.go -output-package=assert -template=assertion_format.go.tmpl

// TestingT is an interface wrapper around *testing.T
type TestingT interface {
	Errorf(format string, args ...interface{})
}

// ComparisonAssertionFunc is a common function prototype when comparing two values.  Can be useful
// for table driven tests.
type ComparisonAssertionFunc func(TestingT, interface{}, interface{}, ...interface{}) bool

// ValueAssertionFunc is a common function prototype when validating a single value.  Can be useful
// for table driven tests.
type ValueAssertionFunc func(TestingT, interface{}, ...interface{}) bool

// BoolAssertionFunc is a common function prototype when validating a bool value.  Can be useful
// for table driven tests.
type BoolAssertionFunc func(TestingT, bool, ...interface{}) bool

// ValuesAssertionFunc is a common function prototype when validating an error value.  Can be useful
// for table driven tests.
type ErrorAssertionFunc func(TestingT, error, ...interface{}) bool

// Comparison a custom function that returns true on success and false on failure
type Comparison func() (success bool)

/*
	Helper functions
*/

// ObjectsAreEqual determines if two objects are considered equal.
//
// This function does no assertion of any kind.
func ObjectsAreEqual(expected, actual interface{}) bool {
	if expected == nil || actual == nil {
		return expected == actual
	}

	exp, ok := expected.([]byte)
	if !ok {
		return reflect.DeepEqual(expected, actual)
	}

	act, ok := actual.([]byte)
	if !ok {
		return false
	}
	if exp == nil || act == nil {
		return exp == nil && act == nil
	}
	return bytes.Equal(exp, act)
}

// ObjectsAreEqualValues gets whether two objects are equal, or if their
// values are equal.
func ObjectsAreEqualValues(expected, actual interface{}) bool {
	if ObjectsAreEqual(expected, actual) {
		return true
	}

	actualType := reflect.TypeOf(actual)
	if actualType == nil {
		return false
	}
	expectedValue := reflect.ValueOf(expected)
	if expectedValue.IsValid() && expectedValue.Type().ConvertibleTo(actualType) {
		// Attempt comparison after type conversion
		return reflect.DeepEqual(expectedValue.Convert(actualType).Interface(), actual)
	}

	return false
}

/* CallerInfo is necessary because the assert functions use the testing object
internally, causing it to print the file:line of the assert method, rather than where
the problem actually occurred in calling code.*/

// CallerInfo returns an array of strings containing the file and line number
// of each stack frame leading from the current test to the assert call that
// failed.
func CallerInfo() []string {

	pc := uintptr(0)
	file := ""
	line := 0
	ok := false
	name := ""

	callers := []string{}
	for i := 0; ; i++ {
		pc, file, line, ok = runtime.Caller(i)
		if !ok {
			// The breaks below failed to terminate the loop, and we ran off the
			// end of the call stack.
			break
		}

		// This is a huge edge case, but it will panic if this is the case, see #180
		if file == "<autogenerated>" {
			break
		}

		f := runtime.FuncForPC(pc)
		if f == nil {
			break
		}
		name = f.Name()

		// testing.tRunner is the standard library function that calls
		// tests. Subtests are called directly by tRunner, without going through
		// the Test/Benchmark/Example function that contains the t.Run calls, so
		// with subtests we should break when we hit tRunner, without adding it
		// to the list of callers.
		if name == "testing.tRunner" {
			break
		}

		parts := strings.Split(file, "/")
		file = parts[len(parts)-1]
		if len(parts) > 1 {
			dir := parts[len(parts)-2]
			if (dir != "assert" && dir != "mock" && dir != "require") || file == "mock_test.go" {
				callers = append(callers, fmt.Sprintf("%s:%d", file, line))
			}
		}

		// Drop the package
		segments := strings.Split(name, ".")
		name = segments[len(segments)-1]
		if isTest(name, "Test") ||
			isTest(name, "Benchmark") ||
			isTest(name, "Example") {
			break
		}
	}

	return callers
}

// Stolen from the `go test` tool.
// isTest tells whether name looks like a test (or benchmark, according to prefix).
// It is a Test (say) if there is a character after Test that is not a lower-case letter.
// We don't want TesticularCancer.
func isTest(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	if len(name) == len(prefix) { // "Test" is ok
		return true
	}
	rune, _ := utf8.DecodeRuneInString(name[len(prefix):])
	return !unicode.IsLower(rune)
}

func messageFromMsgAndArgs(msgAndArgs ...interface{}) string {
	if len(msgAndArgs) == 0 || msgAndArgs == nil {
		return ""
	}
	if len(msgAndArgs) == 1 {
		return msgAndArgs[0].(string)
	}
	if len(msgAndArgs) > 1 {
		return fmt.Sprintf(msgAndArgs[0].(string), msgAndArgs[1:]...)
	}
	return ""
}

// Aligns the provided message so that all lines after the first line start at the same location as the first line.
// Assumes that the first line starts at the correct location (after carriage return, tab, label, spacer and tab).
// The longestLabelLen parameter specifies the length of the longest label in the output (required becaues this is the
// basis on which the alignment occurs).
func indentMessageLines(message string, longestLabelLen int) string {
	outBuf := new(bytes.Buffer)

	for i, scanner := 0, bufio.NewScanner(strings.NewReader(message)); scanner.Scan(); i++ {
		// no need to align first line because it starts at the correct location (after the label)
		if i != 0 {
			// append alignLen+1 spaces to align with "{{longestLabel}}:" before adding tab
			outBuf.WriteString("\n\t" + strings.Repeat(" ", longestLabelLen+1) + "\t")
		}
		outBuf.WriteString(scanner.Text())
	}

	return outBuf.String()
}

type failNower interface {
	FailNow()
}

// FailNow fails test
func FailNow(t TestingT, failureMessage string, msgAndArgs ...interface{}) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	Fail(t, failureMessage, msgAndArgs...)

	// We cannot extend TestingT with FailNow() and
	// maintain backwards compatibility, so we fallback
	// to panicking when FailNow is not available in
	// TestingT.
	// See issue #263

	if t, ok := t.(failNower); ok {
		t.FailNow()
	} else {
		panic("test failed and t is missing `FailNow()`")
	}
	return false
}

// Fail reports a failure through
func Fail(t TestingT, failureMessage string, msgAndArgs ...interface{}) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	content := []labeledContent{
		{"Error Trace", strings.Join(CallerInfo(), "\n\t\t\t")},
		{"Error", failureMessage},
	}

	// Add test name if the Go version supports it
	if n, ok := t.(interface {
		Name() string
	}); ok {
		content = append(content, labeledContent{"Test", n.Name()})
	}

	message := messageFromMsgAndArgs(msgAndArgs...)
	if len(message) > 0 {
		content = append(content, labeledContent{"Messages", message})
	}

	t.Errorf("\n%s", ""+labeledOutput(content...))

	return false
}

type labeledContent struct {
	label   string
	content string
}

// labeledOutput returns a string consisting of the provided labeledContent. Each labeled output is appended in the following manner:
//
//   \t{{label}}:{{align_spaces}}\t{{content}}\n
//
// The initial carriage return is required to undo/erase any padding added by testing.T.Errorf. The "\t{{label}}:" is for the label.
// If a label is shorter than the longest label provided, padding spaces are added to make all the labels match in length. Once this
// alignment is achieved, "\t{{content}}\n" is added for the output.
//
// If the content of the labeledOutput contains line breaks, the subsequent lines are aligned so that they start at the same location as the first line.
func labeledOutput(content ...labeledContent) string {
	longestLabel := 0
	for _, v := range content {
		if len(v.label) > longestLabel {
			longestLabel = len(v.label)
		}
	}
	var output string
	for _, v := range content {
		output += "\t" + v.label + ":" + strings.Repeat(" ", longestLabel-len(v.label)) + "\t" + indentMessageLines(v.content, longestLabel) + "\n"
	}
	return output
}

// Implements asserts that an object is implemented by the specified interface.
//
//    assert.Implements(t, (*MyInterface)(nil), new(MyObject))
func Implements(t TestingT, interfaceObject interface{}, object interface{}, msgAndArgs ...interface{}) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	interfaceType := reflect.TypeOf(interfaceObject).Elem()

	if object == nil {
		return Fail(t, fmt.Sprintf("Cannot check if nil implements %v", interfaceType), msgAndArgs...)
	}
	if !reflect.TypeOf(object).Implements(interfaceType) {
		return Fail(t, fmt.Sprintf("%T must implement %v", object, interfaceType), msgAndArgs...)
	}

	return true
}

// IsType asserts that the specified objects are of the same type.
func IsType(t TestingT, expectedType interface{}, object interface{}, msgAndArgs ...interface{}) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	if !ObjectsAreEqual(reflect.TypeOf(object), reflect.TypeOf(expectedType)) {
		return Fail(t, fmt.Sprintf("Object expected to be of type %v, but was %v", reflect.TypeOf(expectedType), reflect.TypeOf(object)), msgAndArgs...)
	}

	return true
}

// Equal asserts that two objects are equal.
//
//    assert.Equal(t, 123, 123)
//
// Pointer variable equality is determined based on the equality of the
// referenced values (as opposed to the memory addresses). Function equality
// cannot be determined and will always fail.
func Equal(t TestingT, expected, actual interface{}, msgAndArgs ...interface{}) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	if err := validateEqualArgs(expected, actual); err != nil {
		return Fail(t, fmt.Sprintf("Invalid operation: %#v == %#v (%s)",
			expected, actual, err), msgAndArgs...)
	}

	if !ObjectsAreEqual(expected, actual) {
		diff := diff(expected, actual)
		expected, actual = formatUnequalValues(expected, actual)
		return Fail(t, fmt.Sprintf("Not equal: \n"+
			"expected: %s\n"+
			"actual  : %s%s", expected, actual, diff), msgAndArgs...)
	}

	return true

}

// formatUnequalValues takes two values of arbitrary types and returns string
// representations appropriate to be presented to the user.
//
// If the values are not of like type, the returned strings will be prefixed
// with the type name, and the value will be enclosed in parenthesis similar
// to a type conversion in the Go grammar.
func formatUnequalValues(expected, actual interface{}) (e string, a string) {
	if reflect.TypeOf(expected) != reflect.TypeOf(actual) {
		return fmt.Sprintf("%T(%#v)", expected, expected),
			fmt.Sprintf("%T(%#v)", actual, actual)
	}

	return fmt.Sprintf("%#v", expected),
		fmt.Sprintf("%#v", actual)
}

// EqualValues asserts that two objects are equal or convertable to the same types
// and equal.
//
//    assert.EqualValues(t, uint32(123), int32(123))
func EqualValues(t TestingT, expected, actual interface{}, msgAndArgs ...interface{}) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	if !ObjectsAreEqualValues(expected, actual) {
		diff := diff(expected, actual)
		expected, actual = formatUnequalValues(expected, actual)
		return Fail(t, fmt.Sprintf("Not equal: \n"+
			"expected: %s\n"+
			"actual  : %s%s", expected, actual, diff), msgAndArgs...)
	}

	return true

}

// Exactly asserts that two objects are equal in value and type.
//
//    assert.Exactly(t, int32(123), int64(123))
func Exactly(t TestingT, expected, actual interface{}, msgAndArgs ...interface{}) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	aType := reflect.TypeOf(expected)
	bType := reflect.TypeOf(actual)

	if aType != bType {
		return Fail(t, fmt.Sprintf("Types expected to match exactly\n\t%v != %v", aType, bType), msgAndArgs...)
	}

	return Equal(t, expected, actual, msgAndArgs...)

}

// NotNil asserts that the specified object is not nil.
//
//    assert.NotNil(t, err)
func NotNil(t TestingT, object interface{}, msgAndArgs ...interface{}) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	if !isNil(object) {
		return true
	}
	return Fail(t, "Expected value not to be nil.", msgAndArgs...)
}

// isNil checks if a specified object is nil or not, without Failing.
func isNil(object interface{}) bool {
	if object == nil {
		return true
	}

	value := reflect.ValueOf(object)
	kind := value.Kind()
	if kind >= reflect.Chan && kind <= reflect.Slice && value.IsNil() {
		return true
	}

	return false
}

// Nil asserts that the specified object is nil.
//
//    assert.Nil(t, err)
func Nil(t TestingT, object interface{}, msgAndArgs ...interface{}) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	if isNil(object) {
		return true
	}
	return Fail(t, fmt.Sprintf("Expected nil, but got: %#v", object), msgAndArgs...)
}

// isEmpty gets whether the specified object is considered empty or not.
func isEmpty(object interface{}) bool {

	// get nil case out of the way
	if object == nil {
		return true
	}

	objValue := reflect.ValueOf(object)

	switch objValue.Kind() {
	// collection types are empty when they have no element
	case reflect.Array, reflect.Chan, reflect.Map, reflect.Slice:
		return objValue.Len() == 0
	// pointers are empty if nil or if the value they point to is empty
	case reflect.Ptr:
		if objValue.IsNil() {
			return true
		}
		deref := objValue.Elem().Interface()
		return isEmpty(deref)
	// for all other types, compare against the zero value
	default:
		zero := reflect.Zero(objValue.Type())
		return reflect.DeepEqual(object, zero.Interface())
	}
}

// Empty asserts that the specified object is empty.  I.e. nil, "", false, 0 or either
// a slice or a channel with len == 0.
//
//  assert.Empty(t, obj)
func Empty(t TestingT, object interface{}, msgAndArgs ...interface{}) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	pass := isEmpty(object)
	if !pass {
		Fail(t, fmt.Sprintf("Should be empty, but was %v", object), msgAndArgs...)
	}

	return pass

}

// NotEmpty asserts that the specified object is NOT empty.  I.e. not nil, "", false, 0 or either
// a slice or a channel with len == 0.
//
//  if assert.NotEmpty(t, obj) {
//    assert.Equal(t, "two", obj[1])
//  }
func NotEmpty(t TestingT, object interface{}, msgAndArgs ...interface{}) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	pass := !isEmpty(object)
	if !pass {
		Fail(t, fmt.Sprintf("Should NOT be empty, but was %v", object), msgAndArgs...)
	}

	return pass

}

// getLen try to get length of object.
// return (false, 0) if impossible.
func getLen(x interface{}) (ok bool, length int) {
	v := reflect.ValueOf(x)
	defer func() {
		if e := recover(); e != nil {
			ok = false
		}
	}()
	return true, v.Len()
}

// Len asserts that the specified object has specific length.
// Len also fails if the object has a type that len() not accept.
//
//    assert.Len(t, mySlice, 3)
func Len(t TestingT, object interface{}, length int, msgAndArgs ...interface{}) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	ok, l := getLen(object)
	if !ok {
		return Fail(t, fmt.Sprintf("\"%s\" could not be applied builtin len()", object), msgAndArgs...)
	}

	if l != length {
		return Fail(t, fmt.Sprintf("\"%s\" should have %d item(s), but has %d", object, length, l), msgAndArgs...)
	}
	return true
}

// True asserts that the specified value is true.
//
//    assert.True(t, myBool)
func True(t TestingT, value bool, msgAndArgs ...interface{}) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	if h, ok := t.(interface {
		Helper()
	}); ok {
		h.Helper()
	}

	if value != true {
		return Fail(t, "Should be true", msgAndArgs...)
	}

	return true

}

// False asserts that the specified value is false.
//
//    assert.False(t, myBool)
func False(t TestingT, value bool, msgAndArgs ...interface{}) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	if value != false {
		return Fail(t, "Should be false", msgAndArgs...)
	}

	return true

}

// NotEqual asserts that the specified values are NOT equal.
//
//    assert.NotEqual(t, obj1, obj2)
//
// Pointer variable equality is determined based on the equality of the
// referenced values (as opposed to the memory addresses).
func NotEqual(t TestingT, expected, actual interface{}, msgAndArgs ...interface{}) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	if err := validateEqualArgs(expected, actual); err != nil {
		return Fail(t, fmt.Sprintf("Invalid operation: %#v != %#v (%s)",
			expected, actual, err), msgAndArgs...)
	}

	if ObjectsAreEqual(expected, actual) {
		return Fail(t, fmt.Sprintf("Should not be: %#v\n", actual), msgAndArgs...)
	}

	return true

}

// containsElement try loop over the list check if the list includes the element.
// return (false, false) if impossible.
// return (true, false) if element was not found.
// return (true, true) if element was found.
func includeElement(list interface{}, element interface{}) (ok, found bool) {

	listValue := reflect.ValueOf(list)
	elementValue := reflect.ValueOf(element)
	defer func() {
		if e := recover(); e != nil {
			ok = false
			found = false
		}
	}()

	if reflect.TypeOf(list).Kind() == reflect.String {
		return true, strings.Contains(listValue.String(), elementValue.String())
	}

	if reflect.TypeOf(list).Kind() == reflect.Map {
		mapKeys := listValue.MapKeys()
		for i := 0; i < len(mapKeys); i++ {
			if ObjectsAreEqual(mapKeys[i].Interface(), element) {
				return true, true
			}
		}
		return true, false
	}

	for i := 0; i < listValue.Len(); i++ {
		if ObjectsAreEqual(listValue.Index(i).Interface(), element) {
			return true, true
		}
	}
	return true, false

}

// Contains asserts that the specified string, list(array, slice...) or map contains the
// specified substring or element.
//
//    assert.Contains(t, "Hello World", "World")
//    assert.Contains(t, ["Hello", "World"], "World")
//    assert.Contains(t, {"Hello": "World"}, "Hello")
func Contains(t TestingT, s, contains interface{}, msgAndArgs ...interface{}) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	ok, found := includeElement(s, contains)
	if !ok {
		return Fail(t, fmt.Sprintf("\"%s\" could not be applied builtin len()", s), msgAndArgs...)
	}
	if !found {
		return Fail(t, fmt.Sprintf("\"%s\" does not contain \"%s\"", s, contains), msgAndArgs...)
	}

	return true

}

// NotContains asserts that the specified string, list(array, slice...) or map does NOT contain the
// specified substring or element.
//
//    assert.NotContains(t, "Hello World", "Earth")
//    assert.NotContains(t, ["Hello", "World"], "Earth")
//    assert.NotContains(t, {"Hello": "World"}, "Earth")
func NotContains(t TestingT, s, contains interface{}, msgAndArgs ...interface{}) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	ok, found := includeElement(s, contains)
	if !ok {
		return Fail(t, fmt.Sprintf("\"%s\" could not be applied builtin len()", s), msgAndArgs...)
	}
	if found {
		return Fail(t, fmt.Sprintf("\"%s\" should not contain \"%s\"", s, contains), msgAndArgs...)
	}

	return true

}

// Subset asserts that the specified list(array, slice...) contains all
// elements given in the specified subset(array, slice...).
//
//    assert.Subset(t, [1, 2, 3], [1, 2], "But [1, 2, 3] does contain [1, 2]")
func Subset(t TestingT, list, subset interface{}, msgAndArgs ...interface{}) (ok bool) {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	if subset == nil {
		return true // we consider nil to be equal to the nil set
	}

	subsetValue := reflect.ValueOf(subset)
	defer func() {
		if e := recover(); e != nil {
			ok = false
		}
	}()

	listKind := reflect.TypeOf(list).Kind()
	subsetKind := reflect.TypeOf(subset).Kind()

	if listKind != reflect.Array && listKind != reflect.Slice {
		return Fail(t, fmt.Sprintf("%q has an unsupported type %s", list, listKind), msgAndArgs...)
	}

	if subsetKind != reflect.Array && subsetKind != reflect.Slice {
		return Fail(t, fmt.Sprintf("%q has an unsupported type %s", subset, subsetKind), msgAndArgs...)
	}

	for i := 0; i < subsetValue.Len(); i++ {
		element := subsetValue.Index(i).Interface()
		ok, found := includeElement(list, element)
		if !ok {
			return Fail(t, fmt.Sprintf("\"%s\" could not be applied builtin len()", list), msgAndArgs...)
		}
		if !found {
			return Fail(t, fmt.Sprintf("\"%s\" does not contain \"%s\"", list, element), msgAndArgs...)
		}
	}

	return true
}

// NotSubset asserts that the specified list(array, slice...) contains not all
// elements given in the specified subset(array, slice...).
//
//    assert.NotSubset(t, [1, 3, 4], [1, 2], "But [1, 3, 4] does not contain [1, 2]")
func NotSubset(t TestingT, list, subset interface{}, msgAndArgs ...interface{}) (ok bool) {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	if subset == nil {
		return Fail(t, fmt.Sprintf("nil is the empty set which is a subset of every set"), msgAndArgs...)
	}

	subsetValue := reflect.ValueOf(subset)
	defer func() {
		if e := recover(); e != nil {
			ok = false
		}
	}()

	listKind := reflect.TypeOf(list).Kind()
	subsetKind := reflect.TypeOf(subset).Kind()

	if listKind != reflect.Array && listKind != reflect.Slice {
		return Fail(t, fmt.Sprintf("%q has an unsupported type %s", list, listKind), msgAndArgs...)
	}

	if subsetKind != reflect.Array && subsetKind != reflect.Slice {
		return Fail(t, fmt.Sprintf("%q has an unsupported type %s", subset, subsetKind), msgAndArgs...)
	}

	for i := 0; i < subsetValue.Len(); i++ {
		element := subsetValue.Index(i).Interface()
		ok, found := includeElement(list, element)
		if !ok {
			return Fail(t, fmt.Sprintf("\"%s\" could not be applied builtin len()", list), msgAndArgs...)
		}
		if !found {
			return true
		}
	}

	return Fail(t, fmt.Sprintf("%q is a subset of %q", subset, list), msgAndArgs...)
}

// ElementsMatch asserts that the specified listA(array, slice...) is equal to specified
// listB(array, slice...) ignoring the order of the elements. If there are duplicate elements,
// the number of appearances of each of them in both lists should match.
//
// assert.ElementsMatch(t, [1, 3, 2, 3], [1, 3, 3, 2])
func ElementsMatch(t TestingT, listA, listB interface{}, msgAndArgs ...interface{}) (ok bool) {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	if isEmpty(listA) && isEmpty(listB) {
		return true
	}

	aKind := reflect.TypeOf(listA).Kind()
	bKind := reflect.TypeOf(listB).Kind()

	if aKind != reflect.Array && aKind != reflect.Slice {
		return Fail(t, fmt.Sprintf("%q has an unsupported type %s", listA, aKind), msgAndArgs...)
	}

	if bKind != reflect.Array && bKind != reflect.Slice {
		return Fail(t, fmt.Sprintf("%q has an unsupported type %s", listB, bKind), msgAndArgs...)
	}

	aValue := reflect.ValueOf(listA)
	bValue := reflect.ValueOf(listB)

	aLen := aValue.Len()
	bLen := bValue.Len()

	if aLen != bLen {
		return Fail(t, fmt.Sprintf("lengths don't match: %d != %d", aLen, bLen), msgAndArgs...)
	}

	// Mark indexes in bValue that we already used
	visited := make([]bool, bLen)
	for i := 0; i < aLen; i++ {
		element := aValue.Index(i).Interface()
		found := false
		for j := 0; j < bLen; j++ {
			if visited[j] {
				continue
			}
			if ObjectsAreEqual(bValue.Index(j).Interface(), element) {
				visited[j] = true
				found = true
				break
			}
		}
		if !found {
			return Fail(t, fmt.Sprintf("element %s appears more times in %s than in %s", element, aValue, bValue), msgAndArgs...)
		}
	}

	return true
}

// Condition uses a Comparison to assert a complex condition.
func Condition(t TestingT, comp Comparison, msgAndArgs ...interface{}) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	result := comp()
	if !result {
		Fail(t, "Condition failed!", msgAndArgs...)
	}
	return result
}

// PanicTestFunc defines a func that should be passed to the assert.Panics and assert.NotPanics
// methods, and represents a simple func that takes no arguments, and returns nothing.
type PanicTestFunc func()

// didPanic returns true if the function passed to it panics. Otherwise, it returns false.
func didPanic(f PanicTestFunc) (bool, interface{}) {

	didPanic := false
	var message interface{}
	func() {

		defer func() {
			if message = recover(); message != nil {
				didPanic = true
			}
		}()

		// call the target function
		f()

	}()

	return didPanic, message

}

// Panics asserts that the code inside the specified PanicTestFunc panics.
//
//   assert.Panics(t, func(){ GoCrazy() })
func Panics(t TestingT, f PanicTestFunc, msgAndArgs ...interface{}) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	if funcDidPanic, panicValue := didPanic(f); !funcDidPanic {
		return Fail(t, fmt.Sprintf("func %#v should panic\n\tPanic value:\t%#v", f, panicValue), msgAndArgs...)
	}

	return true
}

// PanicsWithValue asserts that the code inside the specified PanicTestFunc panics, and that
// the recovered panic value equals the expected panic value.
//
//   assert.PanicsWithValue(t, "crazy error", func(){ GoCrazy() })
func PanicsWithValue(t TestingT, expected interface{}, f PanicTestFunc, msgAndArgs ...interface{}) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	funcDidPanic, panicValue := didPanic(f)
	if !funcDidPanic {
		return Fail(t, fmt.Sprintf("func %#v should panic\n\tPanic value:\t%#v", f, panicValue), msgAndArgs...)
	}
	if panicValue != expected {
		return Fail(t, fmt.Sprintf("func %#v should panic with value:\t%#v\n\tPanic value:\t%#v", f, expected, panicValue), msgAndArgs...)
	}

	return true
}

// NotPanics asserts that the code inside the specified PanicTestFunc does NOT panic.
//
//   assert.NotPanics(t, func(){ RemainCalm() })
func NotPanics(t TestingT, f PanicTestFunc, msgAndArgs ...interface{}) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	if funcDidPanic, panicValue := didPanic(f); funcDidPanic {
		return Fail(t, fmt.Sprintf("func %#v should not panic\n\tPanic value:\t%v", f, panicValue), msgAndArgs...)
	}

	return true
}

// WithinDuration asserts that the two times are within duration delta of each other.
//
//   assert.WithinDuration(t, time.Now(), time.Now(), 10*time.Second)
func WithinDuration(t TestingT, expected, actual time.Time, delta time.Duration, msgAndArgs ...interface{}) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	dt := expected.Sub(actual)
	if dt < -delta || dt > delta {
		return Fail(t, fmt.Sprintf("Max difference between %v and %v allowed is %v, but difference was %v", expected, actual, delta, dt), msgAndArgs...)
	}

	return true
}

func toFloat(x interface{}) (float64, bool) {
	var xf float64
	xok := true

	switch xn := x.(type) {
	case uint8:
		xf = float64(xn)
	case uint16:
		xf = float64(xn)
	case uint32:
		xf = float64(xn)
	case uint64:
		xf = float64(xn)
	case int:
		xf = float64(xn)
	case int8:
		xf = float64(xn)
	case int16:
		xf = float64(xn)
	case int32:
		xf = float64(xn)
	case int64:
		xf = float64(xn)
	case float32:
		xf = float64(xn)
	case float64:
		xf = float64(xn)
	case time.Duration:
		xf = float64(xn)
	default:
		xok = false
	}

	return xf, xok
}

// InDelta asserts that the two numerals are within delta of each other.
//
// 	 assert.InDelta(t, math.Pi, (22 / 7.0), 0.01)
func InDelta(t TestingT, expected, actual interface{}, delta float64, msgAndArgs ...interface{}) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	af, aok := toFloat(expected)
	bf, bok := toFloat(actual)

	if !aok || !bok {
		return Fail(t, fmt.Sprintf("Parameters must be numerical"), msgAndArgs...)
	}

	if math.IsNaN(af) {
		return Fail(t, fmt.Sprintf("Expected must not be NaN"), msgAndArgs...)
	}

	if math.IsNaN(bf) {
		return Fail(t, fmt.Sprintf("Expected %v with delta %v, but was NaN", expected, delta), msgAndArgs...)
	}

	dt := af - bf
	if dt < -delta || dt > delta {
		return Fail(t, fmt.Sprintf("Max difference between %v and %v allowed is %v, but difference was %v", expected, actual, delta, dt), msgAndArgs...)
	}

	return true
}

// InDeltaSlice is the same as InDelta, except it compares two slices.
func InDeltaSlice(t TestingT, expected, actual interface{}, delta float64, msgAndArgs ...interface{}) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	if expected == nil || actual == nil ||
		reflect.TypeOf(actual).Kind() != reflect.Slice ||
		reflect.TypeOf(expected).Kind() != reflect.Slice {
		return Fail(t, fmt.Sprintf("Parameters must be slice"), msgAndArgs...)
	}

	actualSlice := reflect.ValueOf(actual)
	expectedSlice := reflect.ValueOf(expected)

	for i := 0; i < actualSlice.Len(); i++ {
		result := InDelta(t, actualSlice.Index(i).Interface(), expectedSlice.Index(i).Interface(), delta, msgAndArgs...)
		if !result {
			return result
		}
	}

	return true
}

// InDeltaMapValues is the same as InDelta, but it compares all values between two maps. Both maps must have exactly the same keys.
func InDeltaMapValues(t TestingT, expected, actual interface{}, delta float64, msgAndArgs ...interface{}) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	if expected == nil || actual == nil ||
		reflect.TypeOf(actual).Kind() != reflect.Map ||
		reflect.TypeOf(expected).Kind() != reflect.Map {
		return Fail(t, "Arguments must be maps", msgAndArgs...)
	}

	expectedMap := reflect.ValueOf(expected)
	actualMap := reflect.ValueOf(actual)

	if expectedMap.Len() != actualMap.Len() {
		return Fail(t, "Arguments must have the same number of keys", msgAndArgs...)
	}

	for _, k := range expectedMap.MapKeys() {
		ev := expectedMap.MapIndex(k)
		av := actualMap.MapIndex(k)

		if !ev.IsValid() {
			return Fail(t, fmt.Sprintf("missing key %q in expected map", k), msgAndArgs...)
		}

		if !av.IsValid() {
			return Fail(t, fmt.Sprintf("missing key %q in actual map", k), msgAndArgs...)
		}

		if !InDelta(
			t,
			ev.Interface(),
			av.Interface(),
			delta,
			msgAndArgs...,
		) {
			return false
		}
	}

	return true
}

func calcRelativeError(expected, actual interface{}) (float64, error) {
	af, aok := toFloat(expected)
	if !aok {
		return 0, fmt.Errorf("expected value %q cannot be converted to float", expected)
	}
	if af == 0 {
		return 0, fmt.Errorf("expected value must have a value other than zero to calculate the relative error")
	}
	bf, bok := toFloat(actual)
	if !bok {
		return 0, fmt.Errorf("actual value %q cannot be converted to float", actual)
	}

	return math.Abs(af-bf) / math.Abs(af), nil
}

// InEpsilon asserts that expected and actual have a relative error less than epsilon
func InEpsilon(t TestingT, expected, actual interface{}, epsilon float64, msgAndArgs ...interface{}) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	actualEpsilon, err := calcRelativeError(expected, actual)
	if err != nil {
		return Fail(t, err.Error(), msgAndArgs...)
	}
	if actualEpsilon > epsilon {
		return Fail(t, fmt.Sprintf("Relative error is too high: %#v (expected)\n"+
			"        < %#v (actual)", epsilon, actualEpsilon), msgAndArgs...)
	}

	return true
}

// InEpsilonSlice is the same as InEpsilon, except it compares each value from two slices.
func InEpsilonSlice(t TestingT, expected, actual interface{}, epsilon float64, msgAndArgs ...interface{}) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	if expected == nil || actual == nil ||
		reflect.TypeOf(actual).Kind() != reflect.Slice ||
		reflect.TypeOf(expected).Kind() != reflect.Slice {
		return Fail(t, fmt.Sprintf("Parameters must be slice"), msgAndArgs...)
	}

	actualSlice := reflect.ValueOf(actual)
	expectedSlice := reflect.ValueOf(expected)

	for i := 0; i < actualSlice.Len(); i++ {
		result := InEpsilon(t, actualSlice.Index(i).Interface(), expectedSlice.Index(i).Interface(), epsilon)
		if !result {
			return result
		}
	}

	return true
}

/*
	Errors
*/

// NoError asserts that a function returned no error (i.e. `nil`).
//
//   actualObj, err := SomeFunction()
//   if assert.NoError(t, err) {
//	   assert.Equal(t, expectedObj, actualObj)
//   }
func NoError(t TestingT, err error, msgAndArgs ...interface{}) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	if err != nil {
		return Fail(t, fmt.Sprintf("Received unexpected error:\n%+v", err), msgAndArgs...)
	}

	return true
}

// Error asserts that a function returned an error (i.e. not `nil`).
//
//   actualObj, err := SomeFunction()
//   if assert.Error(t, err) {
//	   assert.Equal(t, expectedError, err)
//   }
func Error(t TestingT, err error, msgAndArgs ...interface{}) bool {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	if err == nil {
		return Fail(t, "An error is expected but got nil.", msgAndArgs...)
	}

	return true
}

// EqualError asserts that a function returned an error (i.e. not `nil`)
// and that it is equal to the provided error.
//
//   actualObj, err := SomeFunction()
//   assert.EqualError(t, err,  expectedErrorString)
func EqualError(t T
"""




```