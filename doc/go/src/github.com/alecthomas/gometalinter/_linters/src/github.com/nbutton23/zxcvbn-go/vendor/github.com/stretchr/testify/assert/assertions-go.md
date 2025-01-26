Response:
The user wants to understand the functionality of the provided Go code snippet. This code is part of the `assert` package in the `stretchr/testify` library, a popular testing utility in Go.

Here's a breakdown of the thought process:

1. **Identify the Core Purpose:** The package name `assert` and the numerous functions with names like `Equal`, `NotNil`, `True`, etc., strongly suggest that this code provides assertion functions for writing tests in Go.

2. **Categorize the Functions:**  Group the functions based on the type of assertion they perform. Common categories would include:
    * Equality checks (`Equal`, `EqualValues`, `Exactly`, `NotEqual`, `JSONEq`)
    * Nil checks (`Nil`, `NotNil`)
    * Boolean checks (`True`, `False`)
    * Length checks (`Len`)
    * Empty/NotEmpty checks (`Empty`, `NotEmpty`)
    * Containment checks (`Contains`, `NotContains`)
    * Error checks (`NoError`, `Error`, `EqualError`)
    * Panic checks (`Panics`, `NotPanics`)
    * Type checks (`IsType`, `Implements`)
    * Numeric comparisons with tolerance (`InDelta`, `InDeltaSlice`, `InEpsilon`, `InEpsilonSlice`)
    * Regular expression matching (`Regexp`, `NotRegexp`)
    * Zero value checks (`Zero`, `NotZero`)
    * Custom conditions (`Condition`)

3. **Explain Key Concepts:**  Identify and explain core concepts within the code, such as:
    * The `TestingT` interface: This highlights how the assertions interact with Go's testing framework.
    * The `CallerInfo` function: This explains how the library provides more informative error messages.
    * The `ObjectsAreEqual` and `ObjectsAreEqualValues` functions: These are fundamental to many equality assertions and need explanation.
    * The use of reflection (`reflect` package): This is a core mechanism used for comparing different types and inspecting values.

4. **Provide Code Examples:**  For each category of functions, create simple, illustrative Go code examples demonstrating their usage. Include:
    * Basic test setup using `testing.T`.
    * Calls to the assertion functions with typical inputs.
    * Expected outcomes (success or failure) and the reason.

5. **Address Code Reasoning:**  For functions that involve more complex logic or decision-making, explain the reasoning behind the code. For example, the `isEmpty` function checks for various "empty" states.

6. **Consider Command-Line Arguments:** Review the code for any handling of command-line arguments. In this case, there isn't any direct handling of command-line arguments within the provided snippet. However, mention that the underlying `go test` command will handle test execution.

7. **Identify Potential Pitfalls:** Think about common mistakes users might make when using these assertion functions. Examples include:
    * Confusing `Equal` and `Exactly`.
    * Misunderstanding the behavior of `EqualValues` with type conversions.
    * Incorrectly using `Contains` with different data types.

8. **Structure the Answer:** Organize the information logically using headings and bullet points for clarity.

9. **Refine and Review:**  Read through the entire answer to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For instance, ensure the examples have clear inputs and the expected outcome is understandable. Ensure the language is precise and avoids jargon where possible.

**(Self-Correction Example during the thought process):** Initially, I might have just listed the functions without grouping them. However, categorizing them makes the explanation much clearer and easier to understand. Similarly, initially, I might have forgotten to explain the purpose of `CallerInfo`, which is a crucial feature of `testify/assert`. Reviewing the code and thinking about the user experience helps identify these missing pieces.
这段代码是Go语言测试库 `stretchr/testify` 中 `assert` 包的一部分，专门用于提供各种断言功能，帮助开发者在编写测试代码时验证程序的行为是否符合预期。

以下是其主要功能列表：

**核心断言功能：**

* **`ObjectsAreEqual(expected, actual interface{}) bool`**:  判断两个对象是否深度相等。这是其他很多断言的基础。
* **`ObjectsAreEqualValues(expected, actual interface{}) bool`**: 判断两个对象是否相等，或者它们的值在类型转换后相等。
* **`Equal(t TestingT, expected, actual interface{}, msgAndArgs ...interface{}) bool`**: 断言两个对象深度相等。如果不等，会输出详细的差异信息。
* **`EqualValues(t TestingT, expected, actual interface{}, msgAndArgs ...interface{}) bool`**: 断言两个对象相等或可转换为相同类型后相等。
* **`Exactly(t TestingT, expected, actual interface{}, msgAndArgs ...interface{}) bool`**: 断言两个对象的值和类型都完全一致。
* **`NotNil(t TestingT, object interface{}, msgAndArgs ...interface{}) bool`**: 断言对象不是 `nil`。
* **`Nil(t TestingT, object interface{}, msgAndArgs ...interface{}) bool`**: 断言对象是 `nil`。
* **`Empty(t TestingT, object interface{}, msgAndArgs ...interface{}) bool`**: 断言对象是空的，例如 `nil`、`""`、`false`、`0` 或长度为 0 的切片/通道/Map。
* **`NotEmpty(t TestingT, object interface{}, msgAndArgs ...interface{}) bool`**: 断言对象不是空的。
* **`Len(t TestingT, object interface{}, length int, msgAndArgs ...interface{}) bool`**: 断言对象的长度是指定的 `length`。
* **`True(t TestingT, value bool, msgAndArgs ...interface{}) bool`**: 断言布尔值为 `true`。
* **`False(t TestingT, value bool, msgAndArgs ...interface{}) bool`**: 断言布尔值为 `false`。
* **`NotEqual(t TestingT, expected, actual interface{}, msgAndArgs ...interface{}) bool`**: 断言两个对象不相等。
* **`Contains(t TestingT, s, contains interface{}, msgAndArgs ...interface{}) bool`**: 断言字符串、切片、数组或 Map 包含指定的子串或元素。
* **`NotContains(t TestingT, s, contains interface{}, msgAndArgs ...interface{}) bool`**: 断言字符串、切片、数组或 Map 不包含指定的子串或元素。
* **`Condition(t TestingT, comp Comparison, msgAndArgs ...interface{}) bool`**: 使用自定义的比较函数 `Comparison` 进行断言。
* **`Panics(t TestingT, f PanicTestFunc, msgAndArgs ...interface{}) bool`**: 断言执行指定的函数 `f` 会引发 panic。
* **`NotPanics(t TestingT, f PanicTestFunc, msgAndArgs ...interface{}) bool`**: 断言执行指定的函数 `f` 不会引发 panic。
* **`WithinDuration(t TestingT, expected, actual time.Time, delta time.Duration, msgAndArgs ...interface{}) bool`**: 断言两个 `time.Time` 对象在指定的 `delta` 时间范围内。
* **`InDelta(t TestingT, expected, actual interface{}, delta float64, msgAndArgs ...interface{}) bool`**: 断言两个数值在指定的 `delta` 误差范围内。
* **`InDeltaSlice(t TestingT, expected, actual interface{}, delta float64, msgAndArgs ...interface{}) bool`**:  与 `InDelta` 类似，用于比较两个数值切片。
* **`InEpsilon(t TestingT, expected, actual interface{}, epsilon float64, msgAndArgs ...interface{}) bool`**: 断言两个数值的相对误差小于指定的 `epsilon` 值。
* **`InEpsilonSlice(t TestingT, expected, actual interface{}, epsilon float64, msgAndArgs ...interface{}) bool`**: 与 `InEpsilon` 类似，用于比较两个数值切片。
* **`NoError(t TestingT, err error, msgAndArgs ...interface{}) bool`**: 断言 `error` 对象为 `nil`。
* **`Error(t TestingT, err error, msgAndArgs ...interface{}) bool`**: 断言 `error` 对象不为 `nil`。
* **`EqualError(t TestingT, theError error, errString string, msgAndArgs ...interface{}) bool`**: 断言 `error` 对象不为 `nil` 且其错误信息与指定的字符串 `errString` 相等。
* **`Regexp(t TestingT, rx interface{}, str interface{}, msgAndArgs ...interface{}) bool`**: 断言字符串匹配指定的正则表达式。
* **`NotRegexp(t TestingT, rx interface{}, str interface{}, msgAndArgs ...interface{}) bool`**: 断言字符串不匹配指定的正则表达式。
* **`Zero(t TestingT, i interface{}, msgAndArgs ...interface{}) bool`**: 断言对象是其类型的零值。
* **`NotZero(t TestingT, i interface{}, msgAndArgs ...interface{}) bool`**: 断言对象不是其类型的零值。
* **`JSONEq(t TestingT, expected string, actual string, msgAndArgs ...interface{}) bool`**: 断言两个 JSON 字符串在语义上是等价的，忽略键的顺序。
* **`Implements(t TestingT, interfaceObject interface{}, object interface{}, msgAndArgs ...interface{}) bool`**: 断言一个对象实现了指定的接口。
* **`IsType(t TestingT, expectedType interface{}, object interface{}, msgAndArgs ...interface{}) bool`**: 断言两个对象是相同的类型。

**辅助功能：**

* **`TestingT` interface**: 定义了一个测试接口，通常由 `testing.T` 实现。
* **`Comparison` type**:  定义了一个自定义的比较函数类型。
* **`CallerInfo() []string`**:  获取调用栈信息，用于提供更精确的错误报告，指向实际的测试代码行。
* **`messageFromMsgAndArgs(msgAndArgs ...interface{}) string`**:  处理断言函数的可变参数，生成自定义的错误消息。
* **`indentMessageLines(message string, tabs int) string`**:  缩进错误消息的行，使其更易读。
* **`FailNow(t TestingT, failureMessage string, msgAndArgs ...interface{}) bool`**: 报告失败并立即停止当前测试。
* **`Fail(t TestingT, failureMessage string, msgAndArgs ...interface{}) bool`**: 报告失败。
* **`PanicTestFunc` type**: 定义了用于 `Panics` 和 `NotPanics` 断言的无参数函数类型。
* **`didPanic(f PanicTestFunc) (bool, interface{})`**:  辅助函数，用于判断执行给定的函数是否会 panic。
* **`toFloat(x interface{}) (float64, bool)`**: 尝试将任意类型转换为 `float64`。
* **`calcRelativeError(expected, actual interface{}) (float64, error)`**: 计算两个数值的相对误差。
* **`matchRegexp(rx interface{}, str interface{}) bool`**: 判断字符串是否匹配正则表达式。
* **`typeAndKind(v interface{}) (reflect.Type, reflect.Kind)`**: 获取对象的类型和 Kind。
* **`diff(expected interface{}, actual interface{}) string`**:  生成两个对象之间的差异，用于 `Equal` 断言失败时的详细输出。

**它是什么Go语言功能的实现：**

这个代码片段主要实现了 **测试断言库** 的核心功能。它利用了 Go 语言的以下特性：

* **接口 (Interfaces):**  `TestingT` 接口抽象了 Go 语言标准库 `testing` 包中的 `*testing.T` 类型，使得断言函数可以与不同的测试框架或模拟对象一起使用。
* **反射 (Reflection):**  `reflect` 包被广泛用于比较不同类型的值，检查对象的类型、Kind 和零值，以及判断对象是否实现了某个接口。例如，`ObjectsAreEqual` 和 `isEmpty` 等函数都使用了反射。
* **可变参数 (Variadic Functions):**  断言函数使用 `msgAndArgs ...interface{}` 来接收可选的自定义错误消息参数，提高了测试的可读性。
* **Panic 和 Recover:** `Panics` 和 `NotPanics` 函数使用了 `defer` 和 `recover` 来捕获函数执行过程中可能发生的 panic。
* **闭包 (Closures):**  `Panics` 和 `NotPanics` 函数接受一个 `PanicTestFunc` 类型的函数作为参数，这可以是一个匿名函数（闭包）。

**Go代码举例说明：**

```go
package mypackage_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAddition(t *testing.T) {
	result := 2 + 3
	assert.Equal(t, 5, result, "The sum should be 5")
}

func TestStringContains(t *testing.T) {
	str := "hello world"
	assert.Contains(t, str, "world", "The string should contain 'world'")
}

func TestErrorIsNil(t *testing.T) {
	err := someFunctionThatMightReturnError()
	assert.NoError(t, err, "No error should have been returned")
}

func someFunctionThatMightReturnError() error {
	return nil // Or return an actual error
}

func TestPanicOccurs(t *testing.T) {
	assert.Panics(t, func() {
		panic("Something went wrong")
	}, "The function should panic")
}

func TestTimeWithinRange(t *testing.T) {
	now := time.Now()
	later := now.Add(5 * time.Second)
	assert.WithinDuration(t, now, later, 10*time.Second, "The times should be within 10 seconds")
}
```

**假设的输入与输出：**

以 `assert.Equal(t, 5, result, "The sum should be 5")` 为例：

* **假设输入:** `result` 的值为 `5`。
* **输出:**  断言成功，测试继续执行。

* **假设输入:** `result` 的值为 `4`。
* **输出:**  断言失败，`testing.T.Errorf` 会被调用，输出类似以下的错误信息：

```
--- FAIL: TestAddition (0.00s)
    assertions.go:160:
                Error Trace:    path/to/your/test_file.go:10
                Error:          Not equal: 5 (expected)
                                != 4 (actual)
                Messages:       The sum should be 5
```

**命令行参数的具体处理：**

这段代码本身**不直接处理**命令行参数。 `stretchr/testify/assert` 包是作为一个库被使用的，它依赖 Go 语言自带的 `testing` 包来执行测试。

命令行参数的处理是由 `go test` 命令完成的。  常见的 `go test` 参数包括：

* **`-v` (verbose):**  输出更详细的测试信息，包括每个测试用例的执行结果。
* **`-run <regexp>`:**  只运行匹配指定正则表达式的测试用例。
* **`-cover`:**  生成代码覆盖率报告。
* **`-bench <regexp>`:**  运行 benchmark 测试。
* **`-timeout <duration>`:** 设置测试用例的超时时间。

当运行 `go test` 命令时，`testing` 包会解析这些参数，并根据参数执行相应的测试用例。`assert` 包提供的断言函数会与 `testing.T` 实例进行交互，报告测试结果。

**使用者易犯错的点：**

1. **混淆 `Equal` 和 `Exactly`:**
   * `Equal` 只比较值是否深度相等。
   * `Exactly` 要求值和类型都必须完全一致。

   ```go
   var a int32 = 5
   var b int64 = 5
   assert.Equal(t, a, b)   // 通过，因为值相等
   assert.Exactly(t, a, b) // 失败，因为类型不同
   ```

2. **不理解 `EqualValues` 的类型转换:**
   `EqualValues` 会尝试进行类型转换后再比较。这在某些情况下很方便，但也可能导致意想不到的结果。

   ```go
   var a uint32 = 10
   var b int32 = 10
   assert.EqualValues(t, a, b) // 通过，因为值可以互相转换
   ```

3. **在 `Contains` 中使用错误的类型:**
   `Contains` 用于检查字符串是否包含子串，以及切片、数组或 Map 是否包含特定元素。如果类型不匹配，可能会导致断言失败。

   ```go
   numbers := []int{1, 2, 3}
   assert.Contains(t, numbers, "2") // 失败，因为 "2" 是字符串，而切片元素是 int
   assert.Contains(t, numbers, 2)   // 通过
   ```

4. **忘记添加自定义错误消息:**
   虽然断言库会提供默认的错误消息，但在复杂的测试场景中，添加清晰的自定义错误消息可以更容易地定位问题。

   ```go
   assert.Equal(t, expectedValue, actualValue, "The user ID should match the expected value for user: %s", userName)
   ```

5. **过度依赖断言而忽略了测试的结构和可读性:**  应该编写清晰、有组织的测试用例，而不是仅仅堆砌断言。

总而言之，这段代码是 `stretchr/testify` 库中用于进行各种类型断言的核心组件，它极大地简化了 Go 语言的测试编写过程，并提供了丰富的断言函数来验证代码的正确性。使用者需要理解每种断言的语义和适用场景，才能有效地利用这个库。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/nbutton23/zxcvbn-go/vendor/github.com/stretchr/testify/assert/assertions.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package assert

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"math"
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

func init() {
	spew.Config.SortKeys = true
}

// TestingT is an interface wrapper around *testing.T
type TestingT interface {
	Errorf(format string, args ...interface{})
}

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

	return reflect.DeepEqual(expected, actual)

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
		dir := parts[len(parts)-2]
		file = parts[len(parts)-1]
		if (dir != "assert" && dir != "mock" && dir != "require") || file == "mock_test.go" {
			callers = append(callers, fmt.Sprintf("%s:%d", file, line))
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

// getWhitespaceString returns a string that is long enough to overwrite the default
// output from the go testing framework.
func getWhitespaceString() string {

	_, file, line, ok := runtime.Caller(1)
	if !ok {
		return ""
	}
	parts := strings.Split(file, "/")
	file = parts[len(parts)-1]

	return strings.Repeat(" ", len(fmt.Sprintf("%s:%d:      ", file, line)))

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

// Indents all lines of the message by appending a number of tabs to each line, in an output format compatible with Go's
// test printing (see inner comment for specifics)
func indentMessageLines(message string, tabs int) string {
	outBuf := new(bytes.Buffer)

	for i, scanner := 0, bufio.NewScanner(strings.NewReader(message)); scanner.Scan(); i++ {
		if i != 0 {
			outBuf.WriteRune('\n')
		}
		for ii := 0; ii < tabs; ii++ {
			outBuf.WriteRune('\t')
			// Bizarrely, all lines except the first need one fewer tabs prepended, so deliberately advance the counter
			// by 1 prematurely.
			if ii == 0 && i > 0 {
				ii++
			}
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

	message := messageFromMsgAndArgs(msgAndArgs...)

	errorTrace := strings.Join(CallerInfo(), "\n\r\t\t\t")
	if len(message) > 0 {
		t.Errorf("\r%s\r\tError Trace:\t%s\n"+
			"\r\tError:%s\n"+
			"\r\tMessages:\t%s\n\r",
			getWhitespaceString(),
			errorTrace,
			indentMessageLines(failureMessage, 2),
			message)
	} else {
		t.Errorf("\r%s\r\tError Trace:\t%s\n"+
			"\r\tError:%s\n\r",
			getWhitespaceString(),
			errorTrace,
			indentMessageLines(failureMessage, 2))
	}

	return false
}

// Implements asserts that an object is implemented by the specified interface.
//
//    assert.Implements(t, (*MyInterface)(nil), new(MyObject), "MyObject")
func Implements(t TestingT, interfaceObject interface{}, object interface{}, msgAndArgs ...interface{}) bool {

	interfaceType := reflect.TypeOf(interfaceObject).Elem()

	if !reflect.TypeOf(object).Implements(interfaceType) {
		return Fail(t, fmt.Sprintf("%T must implement %v", object, interfaceType), msgAndArgs...)
	}

	return true

}

// IsType asserts that the specified objects are of the same type.
func IsType(t TestingT, expectedType interface{}, object interface{}, msgAndArgs ...interface{}) bool {

	if !ObjectsAreEqual(reflect.TypeOf(object), reflect.TypeOf(expectedType)) {
		return Fail(t, fmt.Sprintf("Object expected to be of type %v, but was %v", reflect.TypeOf(expectedType), reflect.TypeOf(object)), msgAndArgs...)
	}

	return true
}

// Equal asserts that two objects are equal.
//
//    assert.Equal(t, 123, 123, "123 and 123 should be equal")
//
// Returns whether the assertion was successful (true) or not (false).
func Equal(t TestingT, expected, actual interface{}, msgAndArgs ...interface{}) bool {

	if !ObjectsAreEqual(expected, actual) {
		diff := diff(expected, actual)
		expected, actual = formatUnequalValues(expected, actual)
		return Fail(t, fmt.Sprintf("Not equal: %s (expected)\n"+
			"        != %s (actual)%s", expected, actual, diff), msgAndArgs...)
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
	aType := reflect.TypeOf(expected)
	bType := reflect.TypeOf(actual)

	if aType != bType && isNumericType(aType) && isNumericType(bType) {
		return fmt.Sprintf("%v(%#v)", aType, expected),
			fmt.Sprintf("%v(%#v)", bType, actual)
	}

	return fmt.Sprintf("%#v", expected),
		fmt.Sprintf("%#v", actual)
}

func isNumericType(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return true
	case reflect.Float32, reflect.Float64:
		return true
	}

	return false
}

// EqualValues asserts that two objects are equal or convertable to the same types
// and equal.
//
//    assert.EqualValues(t, uint32(123), int32(123), "123 and 123 should be equal")
//
// Returns whether the assertion was successful (true) or not (false).
func EqualValues(t TestingT, expected, actual interface{}, msgAndArgs ...interface{}) bool {

	if !ObjectsAreEqualValues(expected, actual) {
		return Fail(t, fmt.Sprintf("Not equal: %#v (expected)\n"+
			"        != %#v (actual)", expected, actual), msgAndArgs...)
	}

	return true

}

// Exactly asserts that two objects are equal is value and type.
//
//    assert.Exactly(t, int32(123), int64(123), "123 and 123 should NOT be equal")
//
// Returns whether the assertion was successful (true) or not (false).
func Exactly(t TestingT, expected, actual interface{}, msgAndArgs ...interface{}) bool {

	aType := reflect.TypeOf(expected)
	bType := reflect.TypeOf(actual)

	if aType != bType {
		return Fail(t, fmt.Sprintf("Types expected to match exactly\n\r\t%v != %v", aType, bType), msgAndArgs...)
	}

	return Equal(t, expected, actual, msgAndArgs...)

}

// NotNil asserts that the specified object is not nil.
//
//    assert.NotNil(t, err, "err should be something")
//
// Returns whether the assertion was successful (true) or not (false).
func NotNil(t TestingT, object interface{}, msgAndArgs ...interface{}) bool {
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
//    assert.Nil(t, err, "err should be nothing")
//
// Returns whether the assertion was successful (true) or not (false).
func Nil(t TestingT, object interface{}, msgAndArgs ...interface{}) bool {
	if isNil(object) {
		return true
	}
	return Fail(t, fmt.Sprintf("Expected nil, but got: %#v", object), msgAndArgs...)
}

var numericZeros = []interface{}{
	int(0),
	int8(0),
	int16(0),
	int32(0),
	int64(0),
	uint(0),
	uint8(0),
	uint16(0),
	uint32(0),
	uint64(0),
	float32(0),
	float64(0),
}

// isEmpty gets whether the specified object is considered empty or not.
func isEmpty(object interface{}) bool {

	if object == nil {
		return true
	} else if object == "" {
		return true
	} else if object == false {
		return true
	}

	for _, v := range numericZeros {
		if object == v {
			return true
		}
	}

	objValue := reflect.ValueOf(object)

	switch objValue.Kind() {
	case reflect.Map:
		fallthrough
	case reflect.Slice, reflect.Chan:
		{
			return (objValue.Len() == 0)
		}
	case reflect.Struct:
		switch object.(type) {
		case time.Time:
			return object.(time.Time).IsZero()
		}
	case reflect.Ptr:
		{
			if objValue.IsNil() {
				return true
			}
			switch object.(type) {
			case *time.Time:
				return object.(*time.Time).IsZero()
			default:
				return false
			}
		}
	}
	return false
}

// Empty asserts that the specified object is empty.  I.e. nil, "", false, 0 or either
// a slice or a channel with len == 0.
//
//  assert.Empty(t, obj)
//
// Returns whether the assertion was successful (true) or not (false).
func Empty(t TestingT, object interface{}, msgAndArgs ...interface{}) bool {

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
//
// Returns whether the assertion was successful (true) or not (false).
func NotEmpty(t TestingT, object interface{}, msgAndArgs ...interface{}) bool {

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
//    assert.Len(t, mySlice, 3, "The size of slice is not 3")
//
// Returns whether the assertion was successful (true) or not (false).
func Len(t TestingT, object interface{}, length int, msgAndArgs ...interface{}) bool {
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
//    assert.True(t, myBool, "myBool should be true")
//
// Returns whether the assertion was successful (true) or not (false).
func True(t TestingT, value bool, msgAndArgs ...interface{}) bool {

	if value != true {
		return Fail(t, "Should be true", msgAndArgs...)
	}

	return true

}

// False asserts that the specified value is false.
//
//    assert.False(t, myBool, "myBool should be false")
//
// Returns whether the assertion was successful (true) or not (false).
func False(t TestingT, value bool, msgAndArgs ...interface{}) bool {

	if value != false {
		return Fail(t, "Should be false", msgAndArgs...)
	}

	return true

}

// NotEqual asserts that the specified values are NOT equal.
//
//    assert.NotEqual(t, obj1, obj2, "two objects shouldn't be equal")
//
// Returns whether the assertion was successful (true) or not (false).
func NotEqual(t TestingT, expected, actual interface{}, msgAndArgs ...interface{}) bool {

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
//    assert.Contains(t, "Hello World", "World", "But 'Hello World' does contain 'World'")
//    assert.Contains(t, ["Hello", "World"], "World", "But ["Hello", "World"] does contain 'World'")
//    assert.Contains(t, {"Hello": "World"}, "Hello", "But {'Hello': 'World'} does contain 'Hello'")
//
// Returns whether the assertion was successful (true) or not (false).
func Contains(t TestingT, s, contains interface{}, msgAndArgs ...interface{}) bool {

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
//    assert.NotContains(t, "Hello World", "Earth", "But 'Hello World' does NOT contain 'Earth'")
//    assert.NotContains(t, ["Hello", "World"], "Earth", "But ['Hello', 'World'] does NOT contain 'Earth'")
//    assert.NotContains(t, {"Hello": "World"}, "Earth", "But {'Hello': 'World'} does NOT contain 'Earth'")
//
// Returns whether the assertion was successful (true) or not (false).
func NotContains(t TestingT, s, contains interface{}, msgAndArgs ...interface{}) bool {

	ok, found := includeElement(s, contains)
	if !ok {
		return Fail(t, fmt.Sprintf("\"%s\" could not be applied builtin len()", s), msgAndArgs...)
	}
	if found {
		return Fail(t, fmt.Sprintf("\"%s\" should not contain \"%s\"", s, contains), msgAndArgs...)
	}

	return true

}

// Condition uses a Comparison to assert a complex condition.
func Condition(t TestingT, comp Comparison, msgAndArgs ...interface{}) bool {
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
//   assert.Panics(t, func(){
//     GoCrazy()
//   }, "Calling GoCrazy() should panic")
//
// Returns whether the assertion was successful (true) or not (false).
func Panics(t TestingT, f PanicTestFunc, msgAndArgs ...interface{}) bool {

	if funcDidPanic, panicValue := didPanic(f); !funcDidPanic {
		return Fail(t, fmt.Sprintf("func %#v should panic\n\r\tPanic value:\t%v", f, panicValue), msgAndArgs...)
	}

	return true
}

// NotPanics asserts that the code inside the specified PanicTestFunc does NOT panic.
//
//   assert.NotPanics(t, func(){
//     RemainCalm()
//   }, "Calling RemainCalm() should NOT panic")
//
// Returns whether the assertion was successful (true) or not (false).
func NotPanics(t TestingT, f PanicTestFunc, msgAndArgs ...interface{}) bool {

	if funcDidPanic, panicValue := didPanic(f); funcDidPanic {
		return Fail(t, fmt.Sprintf("func %#v should not panic\n\r\tPanic value:\t%v", f, panicValue), msgAndArgs...)
	}

	return true
}

// WithinDuration asserts that the two times are within duration delta of each other.
//
//   assert.WithinDuration(t, time.Now(), time.Now(), 10*time.Second, "The difference should not be more than 10s")
//
// Returns whether the assertion was successful (true) or not (false).
func WithinDuration(t TestingT, expected, actual time.Time, delta time.Duration, msgAndArgs ...interface{}) bool {

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
	default:
		xok = false
	}

	return xf, xok
}

// InDelta asserts that the two numerals are within delta of each other.
//
// 	 assert.InDelta(t, math.Pi, (22 / 7.0), 0.01)
//
// Returns whether the assertion was successful (true) or not (false).
func InDelta(t TestingT, expected, actual interface{}, delta float64, msgAndArgs ...interface{}) bool {

	af, aok := toFloat(expected)
	bf, bok := toFloat(actual)

	if !aok || !bok {
		return Fail(t, fmt.Sprintf("Parameters must be numerical"), msgAndArgs...)
	}

	if math.IsNaN(af) {
		return Fail(t, fmt.Sprintf("Actual must not be NaN"), msgAndArgs...)
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
	if expected == nil || actual == nil ||
		reflect.TypeOf(actual).Kind() != reflect.Slice ||
		reflect.TypeOf(expected).Kind() != reflect.Slice {
		return Fail(t, fmt.Sprintf("Parameters must be slice"), msgAndArgs...)
	}

	actualSlice := reflect.ValueOf(actual)
	expectedSlice := reflect.ValueOf(expected)

	for i := 0; i < actualSlice.Len(); i++ {
		result := InDelta(t, actualSlice.Index(i).Interface(), expectedSlice.Index(i).Interface(), delta)
		if !result {
			return result
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
		return 0, fmt.Errorf("expected value %q cannot be converted to float", actual)
	}

	return math.Abs(af-bf) / math.Abs(af), nil
}

// InEpsilon asserts that expected and actual have a relative error less than epsilon
//
// Returns whether the assertion was successful (true) or not (false).
func InEpsilon(t TestingT, expected, actual interface{}, epsilon float64, msgAndArgs ...interface{}) bool {
	actualEpsilon, err := calcRelativeError(expected, actual)
	if err != nil {
		return Fail(t, err.Error(), msgAndArgs...)
	}
	if actualEpsilon > epsilon {
		return Fail(t, fmt.Sprintf("Relative error is too high: %#v (expected)\n"+
			"        < %#v (actual)", actualEpsilon, epsilon), msgAndArgs...)
	}

	return true
}

// InEpsilonSlice is the same as InEpsilon, except it compares each value from two slices.
func InEpsilonSlice(t TestingT, expected, actual interface{}, epsilon float64, msgAndArgs ...interface{}) bool {
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
//	   assert.Equal(t, actualObj, expectedObj)
//   }
//
// Returns whether the assertion was successful (true) or not (false).
func NoError(t TestingT, err error, msgAndArgs ...interface{}) bool {
	if err != nil {
		return Fail(t, fmt.Sprintf("Received unexpected error %+v", err), msgAndArgs...)
	}

	return true
}

// Error asserts that a function returned an error (i.e. not `nil`).
//
//   actualObj, err := SomeFunction()
//   if assert.Error(t, err, "An error was expected") {
//	   assert.Equal(t, err, expectedError)
//   }
//
// Returns whether the assertion was successful (true) or not (false).
func Error(t TestingT, err error, msgAndArgs ...interface{}) bool {

	if err == nil {
		return Fail(t, "An error is expected but got nil.", msgAndArgs...)
	}

	return true
}

// EqualError asserts that a function returned an error (i.e. not `nil`)
// and that it is equal to the provided error.
//
//   actualObj, err := SomeFunction()
//   assert.EqualError(t, err,  expectedErrorString, "An error was expected")
//
// Returns whether the assertion was successful (true) or not (false).
func EqualError(t TestingT, theError error, errString string, msgAndArgs ...interface{}) bool {

	message := messageFromMsgAndArgs(msgAndArgs...)
	if !NotNil(t, theError, "An error is expected but got nil. %s", message) {
		return false
	}
	s := "An error with value \"%s\" is expected but got \"%s\". %s"
	return Equal(t, errString, theError.Error(),
		s, errString, theError.Error(), message)
}

// matchRegexp return true if a specified regexp matches a string.
func matchRegexp(rx interface{}, str interface{}) bool {

	var r *regexp.Regexp
	if rr, ok := rx.(*regexp.Regexp); ok {
		r = rr
	} else {
		r = regexp.MustCompile(fmt.Sprint(rx))
	}

	return (r.FindStringIndex(fmt.Sprint(str)) != nil)

}

// Regexp asserts that a specified regexp matches a string.
//
//  assert.Regexp(t, regexp.MustCompile("start"), "it's starting")
//  assert.Regexp(t, "start...$", "it's not starting")
//
// Returns whether the assertion was successful (true) or not (false).
func Regexp(t TestingT, rx interface{}, str interface{}, msgAndArgs ...interface{}) bool {

	match := matchRegexp(rx, str)

	if !match {
		Fail(t, fmt.Sprintf("Expect \"%v\" to match \"%v\"", str, rx), msgAndArgs...)
	}

	return match
}

// NotRegexp asserts that a specified regexp does not match a string.
//
//  assert.NotRegexp(t, regexp.MustCompile("starts"), "it's starting")
//  assert.NotRegexp(t, "^start", "it's not starting")
//
// Returns whether the assertion was successful (true) or not (false).
func NotRegexp(t TestingT, rx interface{}, str interface{}, msgAndArgs ...interface{}) bool {
	match := matchRegexp(rx, str)

	if match {
		Fail(t, fmt.Sprintf("Expect \"%v\" to NOT match \"%v\"", str, rx), msgAndArgs...)
	}

	return !match

}

// Zero asserts that i is the zero value for its type and returns the truth.
func Zero(t TestingT, i interface{}, msgAndArgs ...interface{}) bool {
	if i != nil && !reflect.DeepEqual(i, reflect.Zero(reflect.TypeOf(i)).Interface()) {
		return Fail(t, fmt.Sprintf("Should be zero, but was %v", i), msgAndArgs...)
	}
	return true
}

// NotZero asserts that i is not the zero value for its type and returns the truth.
func NotZero(t TestingT, i interface{}, msgAndArgs ...interface{}) bool {
	if i == nil || reflect.DeepEqual(i, reflect.Zero(reflect.TypeOf(i)).Interface()) {
		return Fail(t, fmt.Sprintf("Should not be zero, but was %v", i), msgAndArgs...)
	}
	return true
}

// JSONEq asserts that two JSON strings are equivalent.
//
//  assert.JSONEq(t, `{"hello": "world", "foo": "bar"}`, `{"foo": "bar", "hello": "world"}`)
//
// Returns whether the assertion was successful (true) or not (false).
func JSONEq(t TestingT, expected string, actual string, msgAndArgs ...interface{}) bool {
	var expectedJSONAsInterface, actualJSONAsInterface interface{}

	if err := json.Unmarshal([]byte(expected), &expectedJSONAsInterface); err != nil {
		return Fail(t, fmt.Sprintf("Expected value ('%s') is not valid json.\nJSON parsing error: '%s'", expected, err.Error()), msgAndArgs...)
	}

	if err := json.Unmarshal([]byte(actual), &actualJSONAsInterface); err != nil {
		return Fail(t, fmt.Sprintf("Input ('%s') needs to be valid json.\nJSON parsing error: '%s'", actual, err.Error()), msgAndArgs...)
	}

	return Equal(t, expectedJSONAsInterface, actualJSONAsInterface, msgAndArgs...)
}

func typeAndKind(v interface{}) (reflect.Type, reflect.Kind) {
	t := reflect.TypeOf(v)
	k := t.Kind()

	if k == reflect.Ptr {
		t = t.Elem()
		k = t.Kind()
	}
	return t, k
}

// diff returns a diff of both values as long as both are of the same type and
// are a struct, map, slice or array. Otherwise it returns an empty string.
func diff(expected interface{}, actual interface{}) string {
	if expected == nil || actual == nil {
		return ""
	}

	et, ek := typeAndKind(expected)
	at, _ := typeAndKind(actual)

	if et != at {
		return ""
	}

	if ek != reflect.Struct && ek != reflect.Map && ek != reflect.Slice && ek != reflect.Array {
		return ""
	}

	e := spew.Sdump(expected)
	a := spew.Sdump(actual)

	diff, _ := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A:        difflib.SplitLines(e),
		B:        difflib.SplitLines(a),
		FromFile: "Expected",
		FromDate: "",
		ToFile:   "Actual",
		ToDate:   "",
		Context:  1,
	})

	return "\n\nDiff:\n" + diff
}

"""



```