Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding of the Context:**

The first and most crucial step is to understand *where* this code comes from. The path `go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/stretchr/objx/vendor/github.com/stretchr/testify/require/require.go` is incredibly informative. It tells us:

* **Go Source Code:** It's Go code.
* **Part of a Larger Project:**  It's within a complex dependency structure involving `gometalinter`, `objx`, and `testify`.
* **Test-Related:** The `testify` package is a strong indicator it's related to testing in Go. The `require` subdirectory further reinforces this.
* **Vendored Dependency:** The `vendor` directory suggests this is a specific version of the `testify` library included within `objx`.

Knowing this context immediately helps narrow down the possible functionality. It's almost certainly about assertions in tests.

**2. Examining the Imports:**

The import statements are the next key clue:

```go
import (
	assert "github.com/stretchr/testify/assert"
	http "net/http"
	url "net/url"
	time "time"
)
```

* `assert "github.com/stretchr/testify/assert"`: This is the core `testify/assert` package. The alias `assert` tells us that the code is using functions from this package.
* `net/http`, `net/url`, `time`:  These standard library packages suggest that some assertions might deal with HTTP requests, URLs, and time-related values.

**3. Analyzing the Function Signatures and Bodies (Pattern Recognition):**

Now, the real work begins – looking at the individual functions. A clear pattern emerges:

* **Function Pairs:**  Almost every assertion has two versions: one with `msgAndArgs ...interface{}` and one with `msg string, args ...interface{}`. This is a common pattern for providing optional error messages in testing libraries. The `f` suffix usually indicates the formatted version.
* **Delegation to `assert`:** Inside each function, there's a direct call to a corresponding function from the imported `assert` package. For example, `require.Contains` calls `assert.Contains`.
* **`t TestingT`:**  Every function takes a `TestingT` interface as its first argument. This is the standard interface for Go testing (`*testing.T`).
* **`tHelper` Interface:** The code checks if `t` implements `tHelper` and calls `h.Helper()`. This is related to Go 1.9's `t.Helper()` for improved error reporting.
* **`t.FailNow()`:**  If the underlying `assert` function returns `false` (meaning the assertion failed), `t.FailNow()` is called. This is a critical difference from `assert` – `require` stops the test immediately on failure.

**4. Inferring the Core Functionality:**

Based on the patterns, we can confidently infer that this `require` package provides a set of assertion functions. These functions:

* **Delegate to `assert`:**  They are essentially wrappers around the `testify/assert` package.
* **Fail Immediately:**  On assertion failure, they call `t.FailNow()`, stopping the current test function.
* **Offer Formatted Error Messages:** They provide options for adding custom error messages.

**5. Reasoning About "Require" vs. "Assert":**

The name "require" is significant. While `assert` functions indicate a condition that *should* be true, `require` functions indicate a condition that *must* be true for the rest of the test to be meaningful. If a `require` fails, there's often no point in continuing the test.

**6. Code Examples and Use Cases:**

To solidify understanding, it's helpful to think of concrete examples. The comments within the code itself provide excellent illustrations. Consider `require.Equal`:

* **Input:** Two values to compare, an optional message.
* **Output:** The test passes if the values are equal. If not, the test fails immediately with an error message (either default or custom).

**7. Command-Line Arguments (Not Applicable):**

This code is a library. It doesn't have its own command-line interface. The testing framework (like `go test`) handles running the tests.

**8. Common Mistakes (Focus on the "FailNow"):**

The key difference between `assert` and `require` is the immediate failure. A common mistake is using `require` when you want the test to continue even if the assertion fails (perhaps to check multiple things). Another mistake is not handling the "fail-fast" nature of `require` properly in test logic.

**9. Structuring the Answer:**

Finally, organize the findings into a clear and logical answer, addressing the specific points requested in the prompt (functionality, Go feature, code examples, etc.). Emphasize the core concept of "require" as a stricter form of assertion that halts the test on failure.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe it's just a copy of `assert`. **Correction:** The `t.FailNow()` makes it distinct.
* **Initial thought:**  Focus on individual assertion logic. **Correction:**  The overarching pattern of delegation and `FailNow()` is more important for the initial summary.
* **Realization:** The `tHelper` interface is a modern Go testing feature worth mentioning.

By following this structured approach, examining the code, and reasoning about its purpose and context, we can effectively analyze and explain the functionality of this Go testing utility.
这是路径为 `go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/stretchr/objx/vendor/github.com/stretchr/testify/require/require.go` 的Go语言实现的一部分，它是 `stretchr/testify` 库中 `require` 包的定义。

**它的主要功能是提供一组用于编写更严格的Go测试断言函数。**  与 `assert` 包中的断言函数不同，`require` 包中的断言函数在断言失败时会立即终止当前测试（调用 `t.FailNow()`），而不是继续执行后续的测试代码。这在某些情况下非常有用，特别是当一个断言的失败意味着后续的测试步骤没有意义或者会导致程序崩溃时。

**可以推理出它是什么go语言功能的实现：**

这部分代码主要利用了 Go 语言的 **测试框架 (`testing` 包)** 和 **接口 (`interface`)**。

* **测试框架 (`testing` 包):**  `require` 包的函数都接收一个类型为 `TestingT` 的参数 `t`。 `TestingT` 是一个接口，`*testing.T` 类型实现了这个接口。`*testing.T` 提供了诸如 `FailNow()` 等方法来控制测试的执行流程。

* **接口 (`interface`):**  `TestingT` 接口允许 `require` 包的函数与不同的测试 runner 进行交互，只要这些 runner 实现了 `TestingT` 接口。代码中还用到了 `tHelper` 接口，这是一个非公开的接口，用于标记辅助函数，帮助测试框架提供更准确的错误报告。

**Go 代码举例说明:**

假设我们有一个函数 `Add(a, b int) int`，我们想测试它的功能。

```go
package mypackage

import (
	"testing"
	"github.com/stretchr/testify/require"
)

func Add(a, b int) int {
	return a + b
}

func TestAdd(t *testing.T) {
	result := Add(2, 3)
	require.Equal(t, 5, result, "Expected 2 + 3 to be 5")

	// 如果上面的 require.Equal 失败，这里的代码不会被执行
	// 因为 require.Equal 会调用 t.FailNow()

	// 假设后续的测试依赖于 Add 函数的正确性
	// 如果 Add 函数有问题，后续的测试很可能也会失败或者产生误导
	// 使用 require 可以确保在关键步骤失败时立即停止测试
	result = Add(-1, 1)
	require.Equal(t, 0, result, "Expected -1 + 1 to be 0")
}
```

**假设的输入与输出：**

在上面的 `TestAdd` 函数中：

* **第一次调用 `require.Equal(t, 5, result, "Expected 2 + 3 to be 5")`:**
    * **输入:** `t` (测试上下文), `5` (期望值), `result` (实际值，此处为 `Add(2, 3)` 的返回值 `5`), `"Expected 2 + 3 to be 5"` (可选的消息)。
    * **输出:** 如果 `result` 等于 `5`，则测试继续执行。否则，测试会立即失败并输出错误信息 "Expected 2 + 3 to be 5"。

* **第二次调用 `require.Equal(t, 0, result, "Expected -1 + 1 to be 0")`:**
    * **输入:** `t` (测试上下文), `0` (期望值), `result` (实际值，此处为 `Add(-1, 1)` 的返回值 `0`), `"Expected -1 + 1 to be 0"` (可选的消息)。
    * **输出:** 如果 `result` 等于 `0`，则测试继续执行。否则，测试会立即失败并输出错误信息 "Expected -1 + 1 to be 0"。

**命令行参数的具体处理：**

这段代码本身是一个库，不直接处理命令行参数。 命令行参数的处理通常由 `go test` 命令负责。 `go test` 提供了各种参数来控制测试的执行，例如指定要运行的测试文件、运行特定的测试函数、输出详细信息等等。

**使用者易犯错的点：**

* **混淆 `require` 和 `assert` 的使用场景:**  初学者可能不清楚何时应该使用 `require`，何时应该使用 `assert`。 错误地在应该使用 `assert` 的地方使用了 `require`，可能会导致一些不重要的断言失败就终止了整个测试，掩盖了其他潜在的问题。反之，在关键步骤应该使用 `require` 的地方使用了 `assert`，可能会导致测试继续执行，产生错误的结论或者引发 panic。

    ```go
    func TestSomething(t *testing.T) {
        // 错误示例：不重要的检查使用了 require
        file, err := os.Open("some_file.txt")
        require.NoError(t, err, "Should be able to open the file")
        defer file.Close()

        // 如果文件不存在，上面的 require 会终止测试
        // 但也许我们只是想检查文件是否存在，即使不存在也不影响后续测试的进行
        // 这种情况下应该使用 assert.NoError

        // ... 后续的测试代码
    }
    ```

**功能归纳:**

总而言之，这段 `require.go` 文件的功能是定义了一系列用于Go测试的断言函数，这些函数在断言失败时会立即终止测试执行。它提供了一种更严格的断言方式，适用于那些断言的失败意味着后续测试没有意义或者可能导致问题的场景。 它依赖于 Go 的 `testing` 包和接口机制来实现其功能。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/stretchr/objx/vendor/github.com/stretchr/testify/require/require.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
* CODE GENERATED AUTOMATICALLY WITH github.com/stretchr/testify/_codegen
* THIS FILE MUST NOT BE EDITED BY HAND
 */

package require

import (
	assert "github.com/stretchr/testify/assert"
	http "net/http"
	url "net/url"
	time "time"
)

// Condition uses a Comparison to assert a complex condition.
func Condition(t TestingT, comp assert.Comparison, msgAndArgs ...interface{}) {
	if assert.Condition(t, comp, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// Conditionf uses a Comparison to assert a complex condition.
func Conditionf(t TestingT, comp assert.Comparison, msg string, args ...interface{}) {
	if assert.Conditionf(t, comp, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// Contains asserts that the specified string, list(array, slice...) or map contains the
// specified substring or element.
//
//    assert.Contains(t, "Hello World", "World")
//    assert.Contains(t, ["Hello", "World"], "World")
//    assert.Contains(t, {"Hello": "World"}, "Hello")
func Contains(t TestingT, s interface{}, contains interface{}, msgAndArgs ...interface{}) {
	if assert.Contains(t, s, contains, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// Containsf asserts that the specified string, list(array, slice...) or map contains the
// specified substring or element.
//
//    assert.Containsf(t, "Hello World", "World", "error message %s", "formatted")
//    assert.Containsf(t, ["Hello", "World"], "World", "error message %s", "formatted")
//    assert.Containsf(t, {"Hello": "World"}, "Hello", "error message %s", "formatted")
func Containsf(t TestingT, s interface{}, contains interface{}, msg string, args ...interface{}) {
	if assert.Containsf(t, s, contains, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// DirExists checks whether a directory exists in the given path. It also fails if the path is a file rather a directory or there is an error checking whether it exists.
func DirExists(t TestingT, path string, msgAndArgs ...interface{}) {
	if assert.DirExists(t, path, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// DirExistsf checks whether a directory exists in the given path. It also fails if the path is a file rather a directory or there is an error checking whether it exists.
func DirExistsf(t TestingT, path string, msg string, args ...interface{}) {
	if assert.DirExistsf(t, path, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// ElementsMatch asserts that the specified listA(array, slice...) is equal to specified
// listB(array, slice...) ignoring the order of the elements. If there are duplicate elements,
// the number of appearances of each of them in both lists should match.
//
// assert.ElementsMatch(t, [1, 3, 2, 3], [1, 3, 3, 2])
func ElementsMatch(t TestingT, listA interface{}, listB interface{}, msgAndArgs ...interface{}) {
	if assert.ElementsMatch(t, listA, listB, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// ElementsMatchf asserts that the specified listA(array, slice...) is equal to specified
// listB(array, slice...) ignoring the order of the elements. If there are duplicate elements,
// the number of appearances of each of them in both lists should match.
//
// assert.ElementsMatchf(t, [1, 3, 2, 3], [1, 3, 3, 2], "error message %s", "formatted")
func ElementsMatchf(t TestingT, listA interface{}, listB interface{}, msg string, args ...interface{}) {
	if assert.ElementsMatchf(t, listA, listB, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// Empty asserts that the specified object is empty.  I.e. nil, "", false, 0 or either
// a slice or a channel with len == 0.
//
//  assert.Empty(t, obj)
func Empty(t TestingT, object interface{}, msgAndArgs ...interface{}) {
	if assert.Empty(t, object, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// Emptyf asserts that the specified object is empty.  I.e. nil, "", false, 0 or either
// a slice or a channel with len == 0.
//
//  assert.Emptyf(t, obj, "error message %s", "formatted")
func Emptyf(t TestingT, object interface{}, msg string, args ...interface{}) {
	if assert.Emptyf(t, object, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// Equal asserts that two objects are equal.
//
//    assert.Equal(t, 123, 123)
//
// Pointer variable equality is determined based on the equality of the
// referenced values (as opposed to the memory addresses). Function equality
// cannot be determined and will always fail.
func Equal(t TestingT, expected interface{}, actual interface{}, msgAndArgs ...interface{}) {
	if assert.Equal(t, expected, actual, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// EqualError asserts that a function returned an error (i.e. not `nil`)
// and that it is equal to the provided error.
//
//   actualObj, err := SomeFunction()
//   assert.EqualError(t, err,  expectedErrorString)
func EqualError(t TestingT, theError error, errString string, msgAndArgs ...interface{}) {
	if assert.EqualError(t, theError, errString, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// EqualErrorf asserts that a function returned an error (i.e. not `nil`)
// and that it is equal to the provided error.
//
//   actualObj, err := SomeFunction()
//   assert.EqualErrorf(t, err,  expectedErrorString, "error message %s", "formatted")
func EqualErrorf(t TestingT, theError error, errString string, msg string, args ...interface{}) {
	if assert.EqualErrorf(t, theError, errString, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// EqualValues asserts that two objects are equal or convertable to the same types
// and equal.
//
//    assert.EqualValues(t, uint32(123), int32(123))
func EqualValues(t TestingT, expected interface{}, actual interface{}, msgAndArgs ...interface{}) {
	if assert.EqualValues(t, expected, actual, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// EqualValuesf asserts that two objects are equal or convertable to the same types
// and equal.
//
//    assert.EqualValuesf(t, uint32(123, "error message %s", "formatted"), int32(123))
func EqualValuesf(t TestingT, expected interface{}, actual interface{}, msg string, args ...interface{}) {
	if assert.EqualValuesf(t, expected, actual, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// Equalf asserts that two objects are equal.
//
//    assert.Equalf(t, 123, 123, "error message %s", "formatted")
//
// Pointer variable equality is determined based on the equality of the
// referenced values (as opposed to the memory addresses). Function equality
// cannot be determined and will always fail.
func Equalf(t TestingT, expected interface{}, actual interface{}, msg string, args ...interface{}) {
	if assert.Equalf(t, expected, actual, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// Error asserts that a function returned an error (i.e. not `nil`).
//
//   actualObj, err := SomeFunction()
//   if assert.Error(t, err) {
// 	   assert.Equal(t, expectedError, err)
//   }
func Error(t TestingT, err error, msgAndArgs ...interface{}) {
	if assert.Error(t, err, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// Errorf asserts that a function returned an error (i.e. not `nil`).
//
//   actualObj, err := SomeFunction()
//   if assert.Errorf(t, err, "error message %s", "formatted") {
// 	   assert.Equal(t, expectedErrorf, err)
//   }
func Errorf(t TestingT, err error, msg string, args ...interface{}) {
	if assert.Errorf(t, err, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// Exactly asserts that two objects are equal in value and type.
//
//    assert.Exactly(t, int32(123), int64(123))
func Exactly(t TestingT, expected interface{}, actual interface{}, msgAndArgs ...interface{}) {
	if assert.Exactly(t, expected, actual, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// Exactlyf asserts that two objects are equal in value and type.
//
//    assert.Exactlyf(t, int32(123, "error message %s", "formatted"), int64(123))
func Exactlyf(t TestingT, expected interface{}, actual interface{}, msg string, args ...interface{}) {
	if assert.Exactlyf(t, expected, actual, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// Fail reports a failure through
func Fail(t TestingT, failureMessage string, msgAndArgs ...interface{}) {
	if assert.Fail(t, failureMessage, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// FailNow fails test
func FailNow(t TestingT, failureMessage string, msgAndArgs ...interface{}) {
	if assert.FailNow(t, failureMessage, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// FailNowf fails test
func FailNowf(t TestingT, failureMessage string, msg string, args ...interface{}) {
	if assert.FailNowf(t, failureMessage, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// Failf reports a failure through
func Failf(t TestingT, failureMessage string, msg string, args ...interface{}) {
	if assert.Failf(t, failureMessage, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// False asserts that the specified value is false.
//
//    assert.False(t, myBool)
func False(t TestingT, value bool, msgAndArgs ...interface{}) {
	if assert.False(t, value, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// Falsef asserts that the specified value is false.
//
//    assert.Falsef(t, myBool, "error message %s", "formatted")
func Falsef(t TestingT, value bool, msg string, args ...interface{}) {
	if assert.Falsef(t, value, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// FileExists checks whether a file exists in the given path. It also fails if the path points to a directory or there is an error when trying to check the file.
func FileExists(t TestingT, path string, msgAndArgs ...interface{}) {
	if assert.FileExists(t, path, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// FileExistsf checks whether a file exists in the given path. It also fails if the path points to a directory or there is an error when trying to check the file.
func FileExistsf(t TestingT, path string, msg string, args ...interface{}) {
	if assert.FileExistsf(t, path, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// HTTPBodyContains asserts that a specified handler returns a
// body that contains a string.
//
//  assert.HTTPBodyContains(t, myHandler, "GET", "www.google.com", nil, "I'm Feeling Lucky")
//
// Returns whether the assertion was successful (true) or not (false).
func HTTPBodyContains(t TestingT, handler http.HandlerFunc, method string, url string, values url.Values, str interface{}, msgAndArgs ...interface{}) {
	if assert.HTTPBodyContains(t, handler, method, url, values, str, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// HTTPBodyContainsf asserts that a specified handler returns a
// body that contains a string.
//
//  assert.HTTPBodyContainsf(t, myHandler, "GET", "www.google.com", nil, "I'm Feeling Lucky", "error message %s", "formatted")
//
// Returns whether the assertion was successful (true) or not (false).
func HTTPBodyContainsf(t TestingT, handler http.HandlerFunc, method string, url string, values url.Values, str interface{}, msg string, args ...interface{}) {
	if assert.HTTPBodyContainsf(t, handler, method, url, values, str, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// HTTPBodyNotContains asserts that a specified handler returns a
// body that does not contain a string.
//
//  assert.HTTPBodyNotContains(t, myHandler, "GET", "www.google.com", nil, "I'm Feeling Lucky")
//
// Returns whether the assertion was successful (true) or not (false).
func HTTPBodyNotContains(t TestingT, handler http.HandlerFunc, method string, url string, values url.Values, str interface{}, msgAndArgs ...interface{}) {
	if assert.HTTPBodyNotContains(t, handler, method, url, values, str, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// HTTPBodyNotContainsf asserts that a specified handler returns a
// body that does not contain a string.
//
//  assert.HTTPBodyNotContainsf(t, myHandler, "GET", "www.google.com", nil, "I'm Feeling Lucky", "error message %s", "formatted")
//
// Returns whether the assertion was successful (true) or not (false).
func HTTPBodyNotContainsf(t TestingT, handler http.HandlerFunc, method string, url string, values url.Values, str interface{}, msg string, args ...interface{}) {
	if assert.HTTPBodyNotContainsf(t, handler, method, url, values, str, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// HTTPError asserts that a specified handler returns an error status code.
//
//  assert.HTTPError(t, myHandler, "POST", "/a/b/c", url.Values{"a": []string{"b", "c"}}
//
// Returns whether the assertion was successful (true) or not (false).
func HTTPError(t TestingT, handler http.HandlerFunc, method string, url string, values url.Values, msgAndArgs ...interface{}) {
	if assert.HTTPError(t, handler, method, url, values, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// HTTPErrorf asserts that a specified handler returns an error status code.
//
//  assert.HTTPErrorf(t, myHandler, "POST", "/a/b/c", url.Values{"a": []string{"b", "c"}}
//
// Returns whether the assertion was successful (true, "error message %s", "formatted") or not (false).
func HTTPErrorf(t TestingT, handler http.HandlerFunc, method string, url string, values url.Values, msg string, args ...interface{}) {
	if assert.HTTPErrorf(t, handler, method, url, values, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// HTTPRedirect asserts that a specified handler returns a redirect status code.
//
//  assert.HTTPRedirect(t, myHandler, "GET", "/a/b/c", url.Values{"a": []string{"b", "c"}}
//
// Returns whether the assertion was successful (true) or not (false).
func HTTPRedirect(t TestingT, handler http.HandlerFunc, method string, url string, values url.Values, msgAndArgs ...interface{}) {
	if assert.HTTPRedirect(t, handler, method, url, values, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// HTTPRedirectf asserts that a specified handler returns a redirect status code.
//
//  assert.HTTPRedirectf(t, myHandler, "GET", "/a/b/c", url.Values{"a": []string{"b", "c"}}
//
// Returns whether the assertion was successful (true, "error message %s", "formatted") or not (false).
func HTTPRedirectf(t TestingT, handler http.HandlerFunc, method string, url string, values url.Values, msg string, args ...interface{}) {
	if assert.HTTPRedirectf(t, handler, method, url, values, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// HTTPSuccess asserts that a specified handler returns a success status code.
//
//  assert.HTTPSuccess(t, myHandler, "POST", "http://www.google.com", nil)
//
// Returns whether the assertion was successful (true) or not (false).
func HTTPSuccess(t TestingT, handler http.HandlerFunc, method string, url string, values url.Values, msgAndArgs ...interface{}) {
	if assert.HTTPSuccess(t, handler, method, url, values, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// HTTPSuccessf asserts that a specified handler returns a success status code.
//
//  assert.HTTPSuccessf(t, myHandler, "POST", "http://www.google.com", nil, "error message %s", "formatted")
//
// Returns whether the assertion was successful (true) or not (false).
func HTTPSuccessf(t TestingT, handler http.HandlerFunc, method string, url string, values url.Values, msg string, args ...interface{}) {
	if assert.HTTPSuccessf(t, handler, method, url, values, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// Implements asserts that an object is implemented by the specified interface.
//
//    assert.Implements(t, (*MyInterface)(nil), new(MyObject))
func Implements(t TestingT, interfaceObject interface{}, object interface{}, msgAndArgs ...interface{}) {
	if assert.Implements(t, interfaceObject, object, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// Implementsf asserts that an object is implemented by the specified interface.
//
//    assert.Implementsf(t, (*MyInterface, "error message %s", "formatted")(nil), new(MyObject))
func Implementsf(t TestingT, interfaceObject interface{}, object interface{}, msg string, args ...interface{}) {
	if assert.Implementsf(t, interfaceObject, object, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// InDelta asserts that the two numerals are within delta of each other.
//
// 	 assert.InDelta(t, math.Pi, (22 / 7.0), 0.01)
func InDelta(t TestingT, expected interface{}, actual interface{}, delta float64, msgAndArgs ...interface{}) {
	if assert.InDelta(t, expected, actual, delta, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// InDeltaMapValues is the same as InDelta, but it compares all values between two maps. Both maps must have exactly the same keys.
func InDeltaMapValues(t TestingT, expected interface{}, actual interface{}, delta float64, msgAndArgs ...interface{}) {
	if assert.InDeltaMapValues(t, expected, actual, delta, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// InDeltaMapValuesf is the same as InDelta, but it compares all values between two maps. Both maps must have exactly the same keys.
func InDeltaMapValuesf(t TestingT, expected interface{}, actual interface{}, delta float64, msg string, args ...interface{}) {
	if assert.InDeltaMapValuesf(t, expected, actual, delta, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// InDeltaSlice is the same as InDelta, except it compares two slices.
func InDeltaSlice(t TestingT, expected interface{}, actual interface{}, delta float64, msgAndArgs ...interface{}) {
	if assert.InDeltaSlice(t, expected, actual, delta, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// InDeltaSlicef is the same as InDelta, except it compares two slices.
func InDeltaSlicef(t TestingT, expected interface{}, actual interface{}, delta float64, msg string, args ...interface{}) {
	if assert.InDeltaSlicef(t, expected, actual, delta, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// InDeltaf asserts that the two numerals are within delta of each other.
//
// 	 assert.InDeltaf(t, math.Pi, (22 / 7.0, "error message %s", "formatted"), 0.01)
func InDeltaf(t TestingT, expected interface{}, actual interface{}, delta float64, msg string, args ...interface{}) {
	if assert.InDeltaf(t, expected, actual, delta, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// InEpsilon asserts that expected and actual have a relative error less than epsilon
func InEpsilon(t TestingT, expected interface{}, actual interface{}, epsilon float64, msgAndArgs ...interface{}) {
	if assert.InEpsilon(t, expected, actual, epsilon, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// InEpsilonSlice is the same as InEpsilon, except it compares each value from two slices.
func InEpsilonSlice(t TestingT, expected interface{}, actual interface{}, epsilon float64, msgAndArgs ...interface{}) {
	if assert.InEpsilonSlice(t, expected, actual, epsilon, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// InEpsilonSlicef is the same as InEpsilon, except it compares each value from two slices.
func InEpsilonSlicef(t TestingT, expected interface{}, actual interface{}, epsilon float64, msg string, args ...interface{}) {
	if assert.InEpsilonSlicef(t, expected, actual, epsilon, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// InEpsilonf asserts that expected and actual have a relative error less than epsilon
func InEpsilonf(t TestingT, expected interface{}, actual interface{}, epsilon float64, msg string, args ...interface{}) {
	if assert.InEpsilonf(t, expected, actual, epsilon, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// IsType asserts that the specified objects are of the same type.
func IsType(t TestingT, expectedType interface{}, object interface{}, msgAndArgs ...interface{}) {
	if assert.IsType(t, expectedType, object, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// IsTypef asserts that the specified objects are of the same type.
func IsTypef(t TestingT, expectedType interface{}, object interface{}, msg string, args ...interface{}) {
	if assert.IsTypef(t, expectedType, object, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// JSONEq asserts that two JSON strings are equivalent.
//
//  assert.JSONEq(t, `{"hello": "world", "foo": "bar"}`, `{"foo": "bar", "hello": "world"}`)
func JSONEq(t TestingT, expected string, actual string, msgAndArgs ...interface{}) {
	if assert.JSONEq(t, expected, actual, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// JSONEqf asserts that two JSON strings are equivalent.
//
//  assert.JSONEqf(t, `{"hello": "world", "foo": "bar"}`, `{"foo": "bar", "hello": "world"}`, "error message %s", "formatted")
func JSONEqf(t TestingT, expected string, actual string, msg string, args ...interface{}) {
	if assert.JSONEqf(t, expected, actual, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// Len asserts that the specified object has specific length.
// Len also fails if the object has a type that len() not accept.
//
//    assert.Len(t, mySlice, 3)
func Len(t TestingT, object interface{}, length int, msgAndArgs ...interface{}) {
	if assert.Len(t, object, length, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// Lenf asserts that the specified object has specific length.
// Lenf also fails if the object has a type that len() not accept.
//
//    assert.Lenf(t, mySlice, 3, "error message %s", "formatted")
func Lenf(t TestingT, object interface{}, length int, msg string, args ...interface{}) {
	if assert.Lenf(t, object, length, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// Nil asserts that the specified object is nil.
//
//    assert.Nil(t, err)
func Nil(t TestingT, object interface{}, msgAndArgs ...interface{}) {
	if assert.Nil(t, object, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// Nilf asserts that the specified object is nil.
//
//    assert.Nilf(t, err, "error message %s", "formatted")
func Nilf(t TestingT, object interface{}, msg string, args ...interface{}) {
	if assert.Nilf(t, object, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// NoError asserts that a function returned no error (i.e. `nil`).
//
//   actualObj, err := SomeFunction()
//   if assert.NoError(t, err) {
// 	   assert.Equal(t, expectedObj, actualObj)
//   }
func NoError(t TestingT, err error, msgAndArgs ...interface{}) {
	if assert.NoError(t, err, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// NoErrorf asserts that a function returned no error (i.e. `nil`).
//
//   actualObj, err := SomeFunction()
//   if assert.NoErrorf(t, err, "error message %s", "formatted") {
// 	   assert.Equal(t, expectedObj, actualObj)
//   }
func NoErrorf(t TestingT, err error, msg string, args ...interface{}) {
	if assert.NoErrorf(t, err, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// NotContains asserts that the specified string, list(array, slice...) or map does NOT contain the
// specified substring or element.
//
//    assert.NotContains(t, "Hello World", "Earth")
//    assert.NotContains(t, ["Hello", "World"], "Earth")
//    assert.NotContains(t, {"Hello": "World"}, "Earth")
func NotContains(t TestingT, s interface{}, contains interface{}, msgAndArgs ...interface{}) {
	if assert.NotContains(t, s, contains, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// NotContainsf asserts that the specified string, list(array, slice...) or map does NOT contain the
// specified substring or element.
//
//    assert.NotContainsf(t, "Hello World", "Earth", "error message %s", "formatted")
//    assert.NotContainsf(t, ["Hello", "World"], "Earth", "error message %s", "formatted")
//    assert.NotContainsf(t, {"Hello": "World"}, "Earth", "error message %s", "formatted")
func NotContainsf(t TestingT, s interface{}, contains interface{}, msg string, args ...interface{}) {
	if assert.NotContainsf(t, s, contains, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// NotEmpty asserts that the specified object is NOT empty.  I.e. not nil, "", false, 0 or either
// a slice or a channel with len == 0.
//
//  if assert.NotEmpty(t, obj) {
//    assert.Equal(t, "two", obj[1])
//  }
func NotEmpty(t TestingT, object interface{}, msgAndArgs ...interface{}) {
	if assert.NotEmpty(t, object, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// NotEmptyf asserts that the specified object is NOT empty.  I.e. not nil, "", false, 0 or either
// a slice or a channel with len == 0.
//
//  if assert.NotEmptyf(t, obj, "error message %s", "formatted") {
//    assert.Equal(t, "two", obj[1])
//  }
func NotEmptyf(t TestingT, object interface{}, msg string, args ...interface{}) {
	if assert.NotEmptyf(t, object, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// NotEqual asserts that the specified values are NOT equal.
//
//    assert.NotEqual(t, obj1, obj2)
//
// Pointer variable equality is determined based on the equality of the
// referenced values (as opposed to the memory addresses).
func NotEqual(t TestingT, expected interface{}, actual interface{}, msgAndArgs ...interface{}) {
	if assert.NotEqual(t, expected, actual, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// NotEqualf asserts that the specified values are NOT equal.
//
//    assert.NotEqualf(t, obj1, obj2, "error message %s", "formatted")
//
// Pointer variable equality is determined based on the equality of the
// referenced values (as opposed to the memory addresses).
func NotEqualf(t TestingT, expected interface{}, actual interface{}, msg string, args ...interface{}) {
	if assert.NotEqualf(t, expected, actual, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// NotNil asserts that the specified object is not nil.
//
//    assert.NotNil(t, err)
func NotNil(t TestingT, object interface{}, msgAndArgs ...interface{}) {
	if assert.NotNil(t, object, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// NotNilf asserts that the specified object is not nil.
//
//    assert.NotNilf(t, err, "error message %s", "formatted")
func NotNilf(t TestingT, object interface{}, msg string, args ...interface{}) {
	if assert.NotNilf(t, object, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// NotPanics asserts that the code inside the specified PanicTestFunc does NOT panic.
//
//   assert.NotPanics(t, func(){ RemainCalm() })
func NotPanics(t TestingT, f assert.PanicTestFunc, msgAndArgs ...interface{}) {
	if assert.NotPanics(t, f, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// NotPanicsf asserts that the code inside the specified PanicTestFunc does NOT panic.
//
//   assert.NotPanicsf(t, func(){ RemainCalm() }, "error message %s", "formatted")
func NotPanicsf(t TestingT, f assert.PanicTestFunc, msg string, args ...interface{}) {
	if assert.NotPanicsf(t, f, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// NotRegexp asserts that a specified regexp does not match a string.
//
//  assert.NotRegexp(t, regexp.MustCompile("starts"), "it's starting")
//  assert.NotRegexp(t, "^start", "it's not starting")
func NotRegexp(t TestingT, rx interface{}, str interface{}, msgAndArgs ...interface{}) {
	if assert.NotRegexp(t, rx, str, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// NotRegexpf asserts that a specified regexp does not match a string.
//
//  assert.NotRegexpf(t, regexp.MustCompile("starts", "error message %s", "formatted"), "it's starting")
//  assert.NotRegexpf(t, "^start", "it's not starting", "error message %s", "formatted")
func NotRegexpf(t TestingT, rx interface{}, str interface{}, msg string, args ...interface{}) {
	if assert.NotRegexpf(t, rx, str, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// NotSubset asserts that the specified list(array, slice...) contains not all
// elements given in the specified subset(array, slice...).
//
//    assert.NotSubset(t, [1, 3, 4], [1, 2], "But [1, 3, 4] does not contain [1, 2]")
func NotSubset(t TestingT, list interface{}, subset interface{}, msgAndArgs ...interface{}) {
	if assert.NotSubset(t, list, subset, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// NotSubsetf asserts that the specified list(array, slice...) contains not all
// elements given in the specified subset(array, slice...).
//
//    assert.NotSubsetf(t, [1, 3, 4], [1, 2], "But [1, 3, 4] does not contain [1, 2]", "error message %s", "formatted")
func NotSubsetf(t TestingT, list interface{}, subset interface{}, msg string, args ...interface{}) {
	if assert.NotSubsetf(t, list, subset, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// NotZero asserts that i is not the zero value for its type.
func NotZero(t TestingT, i interface{}, msgAndArgs ...interface{}) {
	if assert.NotZero(t, i, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// NotZerof asserts that i is not the zero value for its type.
func NotZerof(t TestingT, i interface{}, msg string, args ...interface{}) {
	if assert.NotZerof(t, i, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// Panics asserts that the code inside the specified PanicTestFunc panics.
//
//   assert.Panics(t, func(){ GoCrazy() })
func Panics(t TestingT, f assert.PanicTestFunc, msgAndArgs ...interface{}) {
	if assert.Panics(t, f, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// PanicsWithValue asserts that the code inside the specified PanicTestFunc panics, and that
// the recovered panic value equals the expected panic value.
//
//   assert.PanicsWithValue(t, "crazy error", func(){ GoCrazy() })
func PanicsWithValue(t TestingT, expected interface{}, f assert.PanicTestFunc, msgAndArgs ...interface{}) {
	if assert.PanicsWithValue(t, expected, f, msgAndArgs...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// PanicsWithValuef asserts that the code inside the specified PanicTestFunc panics, and that
// the recovered panic value equals the expected panic value.
//
//   assert.PanicsWithValuef(t, "crazy error", func(){ GoCrazy() }, "error message %s", "formatted")
func PanicsWithValuef(t TestingT, expected interface{}, f assert.PanicTestFunc, msg string, args ...interface{}) {
	if assert.PanicsWithValuef(t, expected, f, msg, args...) {
		return
	}
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}
	t.FailNow()
}

// Panicsf asserts that
"""




```