Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Understanding the Context:**

The very first line `/* * CODE GENERATED AUTOMATICALLY WITH github.com/stretchr/testify/_codegen * THIS FILE MUST NOT BE EDITED BY HAND */` is crucial. It immediately tells us this isn't manually written code. It's generated. This has several implications:

* **Purpose:**  The code's primary purpose is likely to automate a task. In this case, it's bridging the gap between two different styles of using the `testify/assert` library.
* **Structure:** The code will likely follow a predictable pattern, as code generators tend to be consistent.
* **Maintainability:** Directly editing this file is discouraged. Changes should be made in the generation process.

The path `go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/nbutton23/zxcvbn-go/vendor/github.com/stretchr/testify/assert/assertion_forward.go` tells us:

* **Library:**  It's part of the `stretchr/testify` library, specifically the `assert` package.
* **Location:** It's within a `vendor` directory, indicating it's a dependency. The `gometalinter` part suggests this might be used for code quality checks.
* **Filename:** `assertion_forward.go` hints at forwarding or delegating functionality.

**2. Analyzing the Code Structure:**

The code defines a type `Assertions` and then provides numerous methods on this type. Each method has a similar structure:

```go
// Doc comment explaining the function
func (a *Assertions) FunctionName(arg1 type1, arg2 type2, ...interface{}) bool {
	return FunctionName(a.t, arg1, arg2, ...)
}
```

This pattern is extremely consistent. The core logic of each assertion function is *not* implemented here. Instead, it's calling a function with the *same name* but without the receiver `(a *Assertions)`. The `a.t` is being passed as the first argument.

**3. Identifying the Core Functionality:**

Based on the repeated pattern, the primary function of this code is **forwarding method calls**. The `Assertions` type seems to be a convenience struct that holds a `testing.T` instance (likely represented by `a.t`). This allows for a more object-oriented style of using the `assert` library.

**4. Deducing the "Why":**

Why have two ways of doing the same thing?  The `testify/assert` library likely provides two main ways to perform assertions:

* **Function-based:** Directly calling functions like `assert.Equal(t, 1, 1)`. This requires passing the `testing.T` instance explicitly.
* **Method-based:** Creating an `Assertions` instance and calling methods on it like `assert.New(t).Equal(1, 1)`. This avoids repeatedly passing `t`.

This `assertion_forward.go` file bridges the gap by providing the method-based interface, which then internally calls the function-based implementation. This provides flexibility for developers.

**5. Generating Examples:**

To illustrate the forwarding, we can create simple examples demonstrating both usage patterns:

* **Function-based:**  Show calling `assert.Equal(t, ...)` directly.
* **Method-based:** Show creating an `Assertions` object and calling `a.Equal(...)`. Highlight how `a.t` gets passed internally.

**6. Considering Command-Line Arguments and Error-Prone Aspects:**

Since this code is generated and primarily about forwarding, it doesn't directly handle command-line arguments. The underlying `testify` library handles those.

Regarding common mistakes, the most likely issue is trying to *modify* this generated file. The comment at the top explicitly warns against this. Users might be tempted to customize assertion behavior here, but their changes would be overwritten. The correct way to extend or customize `testify` is through its intended extension mechanisms (if any) or by contributing to the main library.

**7. Structuring the Answer:**

Finally, organize the findings into a clear and logical answer, addressing each part of the prompt:

* **Functions:** List each method and briefly explain its assertion purpose.
* **Go Language Feature:** Identify the forwarding/delegation pattern.
* **Code Example:** Provide both function-based and method-based examples to illustrate the forwarding.
* **Command-Line Arguments:** State that this file doesn't handle them directly.
* **Common Mistakes:**  Point out the danger of editing the generated file.

This methodical approach, starting with understanding the context and then dissecting the code structure, allows for a comprehensive and accurate analysis of the provided Go code snippet.
这段代码是 Go 语言 `testify` 测试库中 `assert` 包的一部分，它定义了一个名为 `Assertions` 的结构体，并为该结构体实现了一系列方法。这些方法是对 `assert` 包中同名函数的简单封装，其主要功能是**将针对 `Assertions` 实例的方法调用转发到 `assert` 包的顶层函数**。

**功能列表:**

这个文件中的每个方法都对应了 `assert` 包中的一个断言函数。以下是这些方法及其对应的断言功能：

* **`Condition(comp Comparison, msgAndArgs ...interface{}) bool`**: 使用一个自定义的比较函数 `Comparison` 来断言一个复杂的条件。
* **`Contains(s interface{}, contains interface{}, msgAndArgs ...interface{}) bool`**: 断言一个字符串、列表（数组、切片...）或映射包含指定的子字符串或元素。
* **`Empty(object interface{}, msgAndArgs ...interface{}) bool`**: 断言指定的对象是空的。例如：`nil`，`""`，`false`，`0`，或者长度为 0 的切片或通道。
* **`Equal(expected interface{}, actual interface{}, msgAndArgs ...interface{}) bool`**: 断言两个对象相等。
* **`EqualError(theError error, errString string, msgAndArgs ...interface{}) bool`**: 断言一个函数返回了一个错误（非 `nil`）并且该错误与提供的字符串相等。
* **`EqualValues(expected interface{}, actual interface{}, msgAndArgs ...interface{}) bool`**: 断言两个对象相等或者可以转换为相同的类型并相等。
* **`Error(err error, msgAndArgs ...interface{}) bool`**: 断言一个函数返回了一个错误（非 `nil`）。
* **`Exactly(expected interface{}, actual interface{}, msgAndArgs ...interface{}) bool`**: 断言两个对象的值和类型都完全相同。
* **`Fail(failureMessage string, msgAndArgs ...interface{}) bool`**: 报告一个失败。
* **`FailNow(failureMessage string, msgAndArgs ...interface{}) bool`**: 报告一个失败并立即停止测试。
* **`False(value bool, msgAndArgs ...interface{}) bool`**: 断言指定的值为 `false`。
* **`HTTPBodyContains(handler http.HandlerFunc, method string, url string, values url.Values, str interface{}) bool`**: 断言指定的处理器返回的响应体包含某个字符串。
* **`HTTPBodyNotContains(handler http.HandlerFunc, method string, url string, values url.Values, str interface{}) bool`**: 断言指定的处理器返回的响应体不包含某个字符串。
* **`HTTPError(handler http.HandlerFunc, method string, url string, values url.Values) bool`**: 断言指定的处理器返回一个错误状态码。
* **`HTTPRedirect(handler http.HandlerFunc, method string, url string, values url.Values) bool`**: 断言指定的处理器返回一个重定向状态码。
* **`HTTPSuccess(handler http.HandlerFunc, method string, url string, values url.Values) bool`**: 断言指定的处理器返回一个成功的状态码。
* **`Implements(interfaceObject interface{}, object interface{}, msgAndArgs ...interface{}) bool`**: 断言一个对象实现了指定的接口。
* **`InDelta(expected interface{}, actual interface{}, delta float64, msgAndArgs ...interface{}) bool`**: 断言两个数字在给定的 `delta` 范围内。
* **`InDeltaSlice(expected interface{}, actual interface{}, delta float64, msgAndArgs ...interface{}) bool`**: 与 `InDelta` 相同，但用于比较两个切片。
* **`InEpsilon(expected interface{}, actual interface{}, epsilon float64, msgAndArgs ...interface{}) bool`**: 断言 `expected` 和 `actual` 的相对误差小于 `epsilon`。
* **`InEpsilonSlice(expected interface{}, actual interface{}, delta float64, msgAndArgs ...interface{}) bool`**: 与 `InEpsilon` 相同，但用于比较两个切片。
* **`IsType(expectedType interface{}, object interface{}, msgAndArgs ...interface{}) bool`**: 断言指定的两个对象具有相同的类型。
* **`JSONEq(expected string, actual string, msgAndArgs ...interface{}) bool`**: 断言两个 JSON 字符串在语义上是相等的（忽略顺序和空格）。
* **`Len(object interface{}, length int, msgAndArgs ...interface{}) bool`**: 断言指定对象的长度为特定的值。如果对象的类型不能用于 `len()` 函数，则会断言失败。
* **`Nil(object interface{}, msgAndArgs ...interface{}) bool`**: 断言指定的对象为 `nil`。
* **`NoError(err error, msgAndArgs ...interface{}) bool`**: 断言一个函数没有返回错误（即返回 `nil`）。
* **`NotContains(s interface{}, contains interface{}, msgAndArgs ...interface{}) bool`**: 断言一个字符串、列表（数组、切片...）或映射不包含指定的子字符串或元素。
* **`NotEmpty(object interface{}, msgAndArgs ...interface{}) bool`**: 断言指定的对象不是空的。
* **`NotEqual(expected interface{}, actual interface{}, msgAndArgs ...interface{}) bool`**: 断言指定的值不相等。
* **`NotNil(object interface{}, msgAndArgs ...interface{}) bool`**: 断言指定的对象不为 `nil`。
* **`NotPanics(f PanicTestFunc, msgAndArgs ...interface{}) bool`**: 断言指定的函数执行时不会发生 panic。
* **`NotRegexp(rx interface{}, str interface{}, msgAndArgs ...interface{}) bool`**: 断言指定的正则表达式不匹配一个字符串。
* **`NotZero(i interface{}, msgAndArgs ...interface{}) bool`**: 断言 `i` 不是其类型的零值。
* **`Panics(f PanicTestFunc, msgAndArgs ...interface{}) bool`**: 断言指定的函数执行时会发生 panic。
* **`Regexp(rx interface{}, str interface{}, msgAndArgs ...interface{}) bool`**: 断言指定的正则表达式匹配一个字符串。
* **`True(value bool, msgAndArgs ...interface{}) bool`**: 断言指定的值为 `true`。
* **`WithinDuration(expected time.Time, actual time.Time, delta time.Duration, msgAndArgs ...interface{}) bool`**: 断言两个时间在给定的 `delta` 时间范围内。
* **`Zero(i interface{}, msgAndArgs ...interface{}) bool`**: 断言 `i` 是其类型的零值。

**Go 语言功能的实现：方法转发/委托**

这个文件实现的核心 Go 语言功能是**方法转发**或称为**委托**。`Assertions` 结构体本身并不实现断言的逻辑，而是将其方法调用转发到 `assert` 包中的独立函数。

**代码举例说明:**

```go
package main

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestExampleAssertion(t *testing.T) {
	// 使用 assert 包的顶层函数
	assert.Equal(t, 1, 1, "Should be equal")

	// 使用 Assertions 结构体的方法
	a := assert.New(t) // 创建 Assertions 实例
	a.Equal(1, 1, "Should also be equal")
}
```

**假设的输入与输出：**

在上面的例子中，`assert.Equal(t, 1, 1, "Should be equal")` 和 `a.Equal(1, 1, "Should also be equal")` 这两种方式都会执行相同的断言逻辑。

* **输入:** 两个整数 `1` 和 `1`，以及一个可选的消息字符串 `"Should be equal"`。
* **输出:** 如果两个整数相等，则断言通过，不会有输出。如果两个整数不相等，则断言失败，`testify` 会输出包含错误信息（包括提供的消息字符串）的测试失败报告。

**命令行参数的具体处理：**

这个代码文件本身不处理任何命令行参数。`testify` 库的命令行参数处理通常由 `go test` 命令及其相关标志来完成。例如，你可以使用 `go test -v` 来获取更详细的测试输出，或者使用 `-run` 标志来运行特定的测试用例。这些参数由 Go 的测试框架处理，而不是 `assertion_forward.go` 这个文件。

**使用者易犯错的点：**

* **尝试修改此文件:** 文件开头的注释 `THIS FILE MUST NOT BE EDITED BY HAND` 非常重要。这个文件是自动生成的，任何手动修改都会在下次生成时被覆盖。如果需要自定义断言或扩展功能，应该在 `assert` 包的其他地方进行，或者考虑创建自定义的断言函数。
* **混淆使用方式:** 虽然 `Assertions` 提供了更面向对象的使用方式，但它本质上是对顶层函数的封装。使用者可能会困惑何时使用 `assert.Equal(t, ...)`，何时使用 `a.Equal(...)`。理解 `Assertions` 只是一个方便的封装是关键。

总而言之，`assertion_forward.go` 文件的主要作用是为 `testify` 库的断言功能提供一种更方便的、面向对象的使用方式，通过 `Assertions` 结构体的方法调用来间接地调用 `assert` 包的顶层断言函数。这提高了代码的可读性和组织性，尤其是在需要进行多次断言的测试用例中。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/nbutton23/zxcvbn-go/vendor/github.com/stretchr/testify/assert/assertion_forward.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
/*
* CODE GENERATED AUTOMATICALLY WITH github.com/stretchr/testify/_codegen
* THIS FILE MUST NOT BE EDITED BY HAND
*/

package assert

import (

	http "net/http"
	url "net/url"
	time "time"
)


// Condition uses a Comparison to assert a complex condition.
func (a *Assertions) Condition(comp Comparison, msgAndArgs ...interface{}) bool {
	return Condition(a.t, comp, msgAndArgs...)
}


// Contains asserts that the specified string, list(array, slice...) or map contains the
// specified substring or element.
// 
//    a.Contains("Hello World", "World", "But 'Hello World' does contain 'World'")
//    a.Contains(["Hello", "World"], "World", "But ["Hello", "World"] does contain 'World'")
//    a.Contains({"Hello": "World"}, "Hello", "But {'Hello': 'World'} does contain 'Hello'")
// 
// Returns whether the assertion was successful (true) or not (false).
func (a *Assertions) Contains(s interface{}, contains interface{}, msgAndArgs ...interface{}) bool {
	return Contains(a.t, s, contains, msgAndArgs...)
}


// Empty asserts that the specified object is empty.  I.e. nil, "", false, 0 or either
// a slice or a channel with len == 0.
// 
//  a.Empty(obj)
// 
// Returns whether the assertion was successful (true) or not (false).
func (a *Assertions) Empty(object interface{}, msgAndArgs ...interface{}) bool {
	return Empty(a.t, object, msgAndArgs...)
}


// Equal asserts that two objects are equal.
// 
//    a.Equal(123, 123, "123 and 123 should be equal")
// 
// Returns whether the assertion was successful (true) or not (false).
func (a *Assertions) Equal(expected interface{}, actual interface{}, msgAndArgs ...interface{}) bool {
	return Equal(a.t, expected, actual, msgAndArgs...)
}


// EqualError asserts that a function returned an error (i.e. not `nil`)
// and that it is equal to the provided error.
// 
//   actualObj, err := SomeFunction()
//   if assert.Error(t, err, "An error was expected") {
// 	   assert.Equal(t, err, expectedError)
//   }
// 
// Returns whether the assertion was successful (true) or not (false).
func (a *Assertions) EqualError(theError error, errString string, msgAndArgs ...interface{}) bool {
	return EqualError(a.t, theError, errString, msgAndArgs...)
}


// EqualValues asserts that two objects are equal or convertable to the same types
// and equal.
// 
//    a.EqualValues(uint32(123), int32(123), "123 and 123 should be equal")
// 
// Returns whether the assertion was successful (true) or not (false).
func (a *Assertions) EqualValues(expected interface{}, actual interface{}, msgAndArgs ...interface{}) bool {
	return EqualValues(a.t, expected, actual, msgAndArgs...)
}


// Error asserts that a function returned an error (i.e. not `nil`).
// 
//   actualObj, err := SomeFunction()
//   if a.Error(err, "An error was expected") {
// 	   assert.Equal(t, err, expectedError)
//   }
// 
// Returns whether the assertion was successful (true) or not (false).
func (a *Assertions) Error(err error, msgAndArgs ...interface{}) bool {
	return Error(a.t, err, msgAndArgs...)
}


// Exactly asserts that two objects are equal is value and type.
// 
//    a.Exactly(int32(123), int64(123), "123 and 123 should NOT be equal")
// 
// Returns whether the assertion was successful (true) or not (false).
func (a *Assertions) Exactly(expected interface{}, actual interface{}, msgAndArgs ...interface{}) bool {
	return Exactly(a.t, expected, actual, msgAndArgs...)
}


// Fail reports a failure through
func (a *Assertions) Fail(failureMessage string, msgAndArgs ...interface{}) bool {
	return Fail(a.t, failureMessage, msgAndArgs...)
}


// FailNow fails test
func (a *Assertions) FailNow(failureMessage string, msgAndArgs ...interface{}) bool {
	return FailNow(a.t, failureMessage, msgAndArgs...)
}


// False asserts that the specified value is false.
// 
//    a.False(myBool, "myBool should be false")
// 
// Returns whether the assertion was successful (true) or not (false).
func (a *Assertions) False(value bool, msgAndArgs ...interface{}) bool {
	return False(a.t, value, msgAndArgs...)
}


// HTTPBodyContains asserts that a specified handler returns a
// body that contains a string.
// 
//  a.HTTPBodyContains(myHandler, "www.google.com", nil, "I'm Feeling Lucky")
// 
// Returns whether the assertion was successful (true) or not (false).
func (a *Assertions) HTTPBodyContains(handler http.HandlerFunc, method string, url string, values url.Values, str interface{}) bool {
	return HTTPBodyContains(a.t, handler, method, url, values, str)
}


// HTTPBodyNotContains asserts that a specified handler returns a
// body that does not contain a string.
// 
//  a.HTTPBodyNotContains(myHandler, "www.google.com", nil, "I'm Feeling Lucky")
// 
// Returns whether the assertion was successful (true) or not (false).
func (a *Assertions) HTTPBodyNotContains(handler http.HandlerFunc, method string, url string, values url.Values, str interface{}) bool {
	return HTTPBodyNotContains(a.t, handler, method, url, values, str)
}


// HTTPError asserts that a specified handler returns an error status code.
// 
//  a.HTTPError(myHandler, "POST", "/a/b/c", url.Values{"a": []string{"b", "c"}}
// 
// Returns whether the assertion was successful (true) or not (false).
func (a *Assertions) HTTPError(handler http.HandlerFunc, method string, url string, values url.Values) bool {
	return HTTPError(a.t, handler, method, url, values)
}


// HTTPRedirect asserts that a specified handler returns a redirect status code.
// 
//  a.HTTPRedirect(myHandler, "GET", "/a/b/c", url.Values{"a": []string{"b", "c"}}
// 
// Returns whether the assertion was successful (true) or not (false).
func (a *Assertions) HTTPRedirect(handler http.HandlerFunc, method string, url string, values url.Values) bool {
	return HTTPRedirect(a.t, handler, method, url, values)
}


// HTTPSuccess asserts that a specified handler returns a success status code.
// 
//  a.HTTPSuccess(myHandler, "POST", "http://www.google.com", nil)
// 
// Returns whether the assertion was successful (true) or not (false).
func (a *Assertions) HTTPSuccess(handler http.HandlerFunc, method string, url string, values url.Values) bool {
	return HTTPSuccess(a.t, handler, method, url, values)
}


// Implements asserts that an object is implemented by the specified interface.
// 
//    a.Implements((*MyInterface)(nil), new(MyObject), "MyObject")
func (a *Assertions) Implements(interfaceObject interface{}, object interface{}, msgAndArgs ...interface{}) bool {
	return Implements(a.t, interfaceObject, object, msgAndArgs...)
}


// InDelta asserts that the two numerals are within delta of each other.
// 
// 	 a.InDelta(math.Pi, (22 / 7.0), 0.01)
// 
// Returns whether the assertion was successful (true) or not (false).
func (a *Assertions) InDelta(expected interface{}, actual interface{}, delta float64, msgAndArgs ...interface{}) bool {
	return InDelta(a.t, expected, actual, delta, msgAndArgs...)
}


// InDeltaSlice is the same as InDelta, except it compares two slices.
func (a *Assertions) InDeltaSlice(expected interface{}, actual interface{}, delta float64, msgAndArgs ...interface{}) bool {
	return InDeltaSlice(a.t, expected, actual, delta, msgAndArgs...)
}


// InEpsilon asserts that expected and actual have a relative error less than epsilon
// 
// Returns whether the assertion was successful (true) or not (false).
func (a *Assertions) InEpsilon(expected interface{}, actual interface{}, epsilon float64, msgAndArgs ...interface{}) bool {
	return InEpsilon(a.t, expected, actual, epsilon, msgAndArgs...)
}


// InEpsilonSlice is the same as InEpsilon, except it compares two slices.
func (a *Assertions) InEpsilonSlice(expected interface{}, actual interface{}, delta float64, msgAndArgs ...interface{}) bool {
	return InEpsilonSlice(a.t, expected, actual, delta, msgAndArgs...)
}


// IsType asserts that the specified objects are of the same type.
func (a *Assertions) IsType(expectedType interface{}, object interface{}, msgAndArgs ...interface{}) bool {
	return IsType(a.t, expectedType, object, msgAndArgs...)
}


// JSONEq asserts that two JSON strings are equivalent.
// 
//  a.JSONEq(`{"hello": "world", "foo": "bar"}`, `{"foo": "bar", "hello": "world"}`)
// 
// Returns whether the assertion was successful (true) or not (false).
func (a *Assertions) JSONEq(expected string, actual string, msgAndArgs ...interface{}) bool {
	return JSONEq(a.t, expected, actual, msgAndArgs...)
}


// Len asserts that the specified object has specific length.
// Len also fails if the object has a type that len() not accept.
// 
//    a.Len(mySlice, 3, "The size of slice is not 3")
// 
// Returns whether the assertion was successful (true) or not (false).
func (a *Assertions) Len(object interface{}, length int, msgAndArgs ...interface{}) bool {
	return Len(a.t, object, length, msgAndArgs...)
}


// Nil asserts that the specified object is nil.
// 
//    a.Nil(err, "err should be nothing")
// 
// Returns whether the assertion was successful (true) or not (false).
func (a *Assertions) Nil(object interface{}, msgAndArgs ...interface{}) bool {
	return Nil(a.t, object, msgAndArgs...)
}


// NoError asserts that a function returned no error (i.e. `nil`).
// 
//   actualObj, err := SomeFunction()
//   if a.NoError(err) {
// 	   assert.Equal(t, actualObj, expectedObj)
//   }
// 
// Returns whether the assertion was successful (true) or not (false).
func (a *Assertions) NoError(err error, msgAndArgs ...interface{}) bool {
	return NoError(a.t, err, msgAndArgs...)
}


// NotContains asserts that the specified string, list(array, slice...) or map does NOT contain the
// specified substring or element.
// 
//    a.NotContains("Hello World", "Earth", "But 'Hello World' does NOT contain 'Earth'")
//    a.NotContains(["Hello", "World"], "Earth", "But ['Hello', 'World'] does NOT contain 'Earth'")
//    a.NotContains({"Hello": "World"}, "Earth", "But {'Hello': 'World'} does NOT contain 'Earth'")
// 
// Returns whether the assertion was successful (true) or not (false).
func (a *Assertions) NotContains(s interface{}, contains interface{}, msgAndArgs ...interface{}) bool {
	return NotContains(a.t, s, contains, msgAndArgs...)
}


// NotEmpty asserts that the specified object is NOT empty.  I.e. not nil, "", false, 0 or either
// a slice or a channel with len == 0.
// 
//  if a.NotEmpty(obj) {
//    assert.Equal(t, "two", obj[1])
//  }
// 
// Returns whether the assertion was successful (true) or not (false).
func (a *Assertions) NotEmpty(object interface{}, msgAndArgs ...interface{}) bool {
	return NotEmpty(a.t, object, msgAndArgs...)
}


// NotEqual asserts that the specified values are NOT equal.
// 
//    a.NotEqual(obj1, obj2, "two objects shouldn't be equal")
// 
// Returns whether the assertion was successful (true) or not (false).
func (a *Assertions) NotEqual(expected interface{}, actual interface{}, msgAndArgs ...interface{}) bool {
	return NotEqual(a.t, expected, actual, msgAndArgs...)
}


// NotNil asserts that the specified object is not nil.
// 
//    a.NotNil(err, "err should be something")
// 
// Returns whether the assertion was successful (true) or not (false).
func (a *Assertions) NotNil(object interface{}, msgAndArgs ...interface{}) bool {
	return NotNil(a.t, object, msgAndArgs...)
}


// NotPanics asserts that the code inside the specified PanicTestFunc does NOT panic.
// 
//   a.NotPanics(func(){
//     RemainCalm()
//   }, "Calling RemainCalm() should NOT panic")
// 
// Returns whether the assertion was successful (true) or not (false).
func (a *Assertions) NotPanics(f PanicTestFunc, msgAndArgs ...interface{}) bool {
	return NotPanics(a.t, f, msgAndArgs...)
}


// NotRegexp asserts that a specified regexp does not match a string.
// 
//  a.NotRegexp(regexp.MustCompile("starts"), "it's starting")
//  a.NotRegexp("^start", "it's not starting")
// 
// Returns whether the assertion was successful (true) or not (false).
func (a *Assertions) NotRegexp(rx interface{}, str interface{}, msgAndArgs ...interface{}) bool {
	return NotRegexp(a.t, rx, str, msgAndArgs...)
}


// NotZero asserts that i is not the zero value for its type and returns the truth.
func (a *Assertions) NotZero(i interface{}, msgAndArgs ...interface{}) bool {
	return NotZero(a.t, i, msgAndArgs...)
}


// Panics asserts that the code inside the specified PanicTestFunc panics.
// 
//   a.Panics(func(){
//     GoCrazy()
//   }, "Calling GoCrazy() should panic")
// 
// Returns whether the assertion was successful (true) or not (false).
func (a *Assertions) Panics(f PanicTestFunc, msgAndArgs ...interface{}) bool {
	return Panics(a.t, f, msgAndArgs...)
}


// Regexp asserts that a specified regexp matches a string.
// 
//  a.Regexp(regexp.MustCompile("start"), "it's starting")
//  a.Regexp("start...$", "it's not starting")
// 
// Returns whether the assertion was successful (true) or not (false).
func (a *Assertions) Regexp(rx interface{}, str interface{}, msgAndArgs ...interface{}) bool {
	return Regexp(a.t, rx, str, msgAndArgs...)
}


// True asserts that the specified value is true.
// 
//    a.True(myBool, "myBool should be true")
// 
// Returns whether the assertion was successful (true) or not (false).
func (a *Assertions) True(value bool, msgAndArgs ...interface{}) bool {
	return True(a.t, value, msgAndArgs...)
}


// WithinDuration asserts that the two times are within duration delta of each other.
// 
//   a.WithinDuration(time.Now(), time.Now(), 10*time.Second, "The difference should not be more than 10s")
// 
// Returns whether the assertion was successful (true) or not (false).
func (a *Assertions) WithinDuration(expected time.Time, actual time.Time, delta time.Duration, msgAndArgs ...interface{}) bool {
	return WithinDuration(a.t, expected, actual, delta, msgAndArgs...)
}


// Zero asserts that i is the zero value for its type and returns the truth.
func (a *Assertions) Zero(i interface{}, msgAndArgs ...interface{}) bool {
	return Zero(a.t, i, msgAndArgs...)
}

"""



```