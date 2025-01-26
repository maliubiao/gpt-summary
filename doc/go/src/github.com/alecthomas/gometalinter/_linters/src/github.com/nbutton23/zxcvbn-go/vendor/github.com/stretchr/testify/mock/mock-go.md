Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding of the Goal:**

The request asks for the functionality of the given Go code, which is located within a mock package. This immediately suggests the code is related to creating and managing mock objects for testing.

**2. High-Level Structure Recognition:**

I first scanned the code for major components:

* **`TestingT` interface:**  This clearly relates to the standard Go testing library (`testing.T`).
* **`Call` struct:**  The name "Call" strongly indicates it represents a function call, both for setting expectations and recording actual calls.
* **`Mock` struct:** This is the core of the mocking mechanism. It holds expectations and records the calls made to the mock object.
* **`Arguments` type:**  This seems to be a custom type for handling arguments passed to and returned from mocked methods.
* **Functions starting with `Assert`:**  These are clearly assertion functions for verifying the behavior of the mock.

**3. Deeper Dive into Key Components:**

* **`Call`:**
    * **Purpose:** Represents a single method call (expected or actual).
    * **Key fields:** `Method`, `Arguments`, `ReturnArguments`, `Repeatability`, `WaitFor`, `RunFn`. I considered what each of these likely does. `Repeatability` controls how many times a return value is used. `WaitFor` introduces asynchronous behavior. `RunFn` allows side effects during the mock call.
    * **Methods:** `Return`, `Once`, `Twice`, `Times`, `WaitUntil`, `After`, `Run`, `On`. These methods clearly define how to set up expectations for a call.

* **`Mock`:**
    * **Purpose:** Manages expectations and tracks actual calls.
    * **Key fields:** `ExpectedCalls`, `Calls`, `testData`, `mutex`. The `mutex` indicates thread safety is a concern. `testData` suggests a place for user-defined data.
    * **Methods:** `On`, `Called`, `AssertExpectations`, `AssertNumberOfCalls`, `AssertCalled`, `AssertNotCalled`. `On` sets expectations. `Called` records an actual call and returns the mocked value. The `Assert` functions verify the mock's behavior.

* **`Arguments`:**
    * **Purpose:**  Represents a list of arguments.
    * **Key constants:** `Anything`, `AnythingOfTypeArgument`. These are for flexible argument matching.
    * **Methods:** `Get`, `Is`, `Diff`, `Assert`, `String`, `Int`, `Error`, `Bool`. These provide ways to access, compare, and verify arguments. The `Diff` method is crucial for understanding how argument matching works. The type assertion methods (`String`, `Int`, etc.) suggest convenience for accessing specific argument types.

**4. Identifying Key Functionality and Go Features:**

Based on the structure and the names of the types and methods, I could deduce the following functionalities:

* **Defining Expectations:** Using `Mock.On()` to specify expected method calls and their arguments.
* **Returning Values:** Using `Call.Return()` to define the return values for expected calls.
* **Controlling Call Count:** Using `Call.Once()`, `Call.Twice()`, `Call.Times()` to specify how many times a method is expected to be called.
* **Asynchronous Behavior:** Using `Call.WaitUntil()` and `Call.After()` to simulate delays or synchronization points.
* **Side Effects:** Using `Call.Run()` to execute a custom function when a mocked method is called.
* **Recording Actual Calls:** The `Mock.Called()` method records that a method was called with specific arguments.
* **Argument Matching:** The `Arguments` type and its `Diff` method provide various ways to match arguments, including exact matching, ignoring arguments (`Anything`), type checking (`AnythingOfType`), and custom matching (`MatchedBy`).
* **Assertions:** The `Mock.AssertExpectations()` and other `Assert` methods are used to verify that the expected calls were made.

**5. Providing Go Code Examples:**

To illustrate the functionality, I created simple examples covering the common use cases:

* Basic expectation and return value.
* Matching arguments (including `Anything`).
* Using `Times()` for multiple calls.
* Using `Run()` for side effects.

**6. Inferring Go Language Features:**

I identified the following Go language features in use:

* **Interfaces:** `TestingT` is a clear example.
* **Structs:** `Call` and `Mock` are core data structures.
* **Variadic Functions:**  Used in `On`, `Return`, `Called`, and others.
* **Reflection:** Used extensively in argument matching (`reflect` package).
* **Concurrency:** The `sync.Mutex` in the `Mock` struct indicates thread safety.
* **Channels:** Used in `WaitFor` for asynchronous behavior.
* **Panic and Recover (Implicit):** The code uses `panic` for unexpected calls and argument mismatches. While no explicit `recover` is shown in this snippet, it's common in testing frameworks.

**7. Identifying Potential Mistakes:**

I considered common pitfalls when using mocking libraries:

* **Forgetting to set expectations:** This leads to panics.
* **Incorrect argument matching:**  Using the wrong matching strategy (e.g., expecting exact match when it's not needed).
* **Order of calls (although this library explicitly states order doesn't matter for `AssertExpectations`):** In other mocking libraries, call order can be significant. It's worth noting this difference.
* **Modifying arguments passed by reference without `RunFn`:** This can lead to unexpected behavior if the mocked method is expected to modify the arguments.

**8. Structuring the Answer:**

Finally, I organized the information into logical sections:

* **功能列举:**  A straightforward list of features.
* **实现的 Go 语言功能:**  Connecting the code to specific Go concepts with code examples.
* **代码推理:**  Illustrating how argument matching works with an example.
* **命令行参数:**  Not applicable in this code snippet.
* **使用者易犯错的点:**  Highlighting common mistakes.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the individual methods without seeing the bigger picture of the mocking workflow. Stepping back to understand the roles of `Call` and `Mock` helped.
* I initially overlooked the significance of the `RunFn` and its use case for mocking methods with side effects.
* I realized the need to explicitly mention that this specific mocking library *doesn't* enforce call order for `AssertExpectations`, as this is a common feature in other mocking frameworks and a potential source of confusion.

By following this structured analysis, I could generate a comprehensive and accurate answer to the request.
这段代码是 Go 语言 `testify` 库中 `mock` 包的一部分，用于实现 mock 对象的功能。它的核心作用是在单元测试中创建一个模拟对象，你可以预先设定这个模拟对象的行为（例如，当调用某个方法时返回特定的值），并在测试结束后验证这个模拟对象是否按照预期被调用。

以下是这段代码的主要功能：

1. **定义 Mock 对象 (`Mock` struct):**
   - `ExpectedCalls`: 存储着预期的方法调用及其对应的返回值的列表。
   - `Calls`: 记录着实际发生的方法调用的列表。
   - `testData`:  允许存储任意测试数据，`testify` 自身会忽略这部分数据。
   - `mutex`:  用于保证并发安全。

2. **定义 Call 对象 (`Call` struct):**
   - `Parent`: 指向所属的 `Mock` 对象。
   - `Method`:  被调用或期望被调用的方法名。
   - `Arguments`:  方法调用的参数。
   - `ReturnArguments`:  方法调用应该返回的值。
   - `Repeatability`:  指定返回 `ReturnArguments` 的次数。0 表示无限次。
   - `totalCalls`:  记录该调用实际发生的次数。
   - `WaitFor`:  一个通道，用于阻塞 `Return` 操作，直到通道关闭或接收到消息。
   - `RunFn`:  一个函数，在方法被调用时执行，可以用于修改引用传递的参数。

3. **设置期望 (`On` 方法):**
   - 允许你定义对 mock 对象方法调用的期望。
   - 你可以指定期望调用的方法名和参数。
   - 返回一个 `Call` 对象，你可以进一步设置该调用的返回行为。
   - 例如：`mockObj.On("MyMethod", 1, "hello").Return(true, nil)` 表示期望 `MyMethod` 方法被调用，参数为 `1` 和 `"hello"`，并返回 `true` 和 `nil`。

4. **设置返回值 (`Return` 方法):**
   - 用于指定期望方法调用时应该返回的值。
   - 只能在 `On` 方法之后调用。
   - 例如：`.Return(123, "world")` 设置返回值为 `123` 和 `"world"`。

5. **控制调用次数 (`Once`, `Twice`, `Times` 方法):**
   - 允许你指定某个期望的方法调用应该发生多少次。
   - `Once()`:  期望调用一次。
   - `Twice()`: 期望调用两次。
   - `Times(i int)`: 期望调用 `i` 次。

6. **设置延迟返回 (`WaitUntil`, `After` 方法):**
   - 允许你模拟方法调用时的延迟。
   - `WaitUntil(w <-chan time.Time)`:  阻塞直到通道 `w` 关闭或接收到消息。
   - `After(d time.Duration)`: 阻塞指定的时间 `d`。

7. **执行自定义函数 (`Run` 方法):**
   - 允许你在期望的方法被调用时执行一个自定义函数。
   - 这个函数可以访问传递给方法的参数，并进行一些操作，例如修改通过引用传递的参数。
   - 例如：`.Run(func(args Arguments) { arg := args.Get(0).(*string); *arg = "modified" })`

8. **记录方法调用 (`Called` 方法):**
   - 当你实际调用 mock 对象的方法时，需要在测试代码中调用 `Called` 方法来告知 mock 对象发生了调用。
   - `Called` 方法会记录这次调用，并查找是否有匹配的期望。
   - 如果找到匹配的期望，它会返回预先设定的返回值。
   - 如果没有找到匹配的期望，它会 panic，提示发生了意外的调用。

9. **断言 (`AssertExpectations`, `AssertNumberOfCalls`, `AssertCalled`, `AssertNotCalled` 方法):**
   - 在测试结束时，你可以使用这些方法来验证 mock 对象是否按照预期被调用。
   - `AssertExpectations(t TestingT)`: 验证所有通过 `On` 设置的期望是否都被满足。
   - `AssertNumberOfCalls(t TestingT, methodName string, expectedCalls int)`:  断言某个方法被调用的次数。
   - `AssertCalled(t TestingT, methodName string, arguments ...interface{})`: 断言某个方法是否使用指定的参数被调用过。
   - `AssertNotCalled(t TestingT, methodName string, arguments ...interface{})`: 断言某个方法没有使用指定的参数被调用过。

10. **参数匹配 (`Arguments` 类型和相关方法):**
    - `Arguments`:  表示方法参数或返回值的切片。
    - `Anything`:  一个常量，用于在设置期望时表示匹配任何参数。
    - `AnythingOfType(t string)`:  用于在设置期望时表示匹配任何指定类型的参数。
    - `MatchedBy(fn interface{})`: 允许使用自定义函数进行参数匹配。
    - `Diff`:  比较两个参数列表的差异。
    - `Assert`:  断言参数列表与期望的对象列表完全匹配。

**它是什么 Go 语言功能的实现：**

这段代码主要实现了 **Mocking** 功能。Mocking 是一种在单元测试中常用的技术，用于隔离被测试的代码单元与它的依赖项。通过使用 mock 对象，我们可以：

- **解耦依赖:** 避免测试环境对真实依赖项的依赖，例如数据库、外部服务等。
- **控制行为:** 精确控制依赖项在测试中的行为，例如模拟不同的返回值、抛出错误等。
- **验证交互:** 验证被测试的代码是否正确地与依赖项进行交互。

**Go 代码举例说明：**

假设我们有一个接口 `Calculator` 和一个依赖于它的服务 `MyService`：

```go
package mypackage

// Calculator 接口
type Calculator interface {
	Add(a, b int) int
	Subtract(a, b int) int
}

// MyService 依赖于 Calculator
type MyService struct {
	calculator Calculator
}

func NewMyService(calc Calculator) *MyService {
	return &MyService{calculator: calc}
}

func (s *MyService) PerformCalculation(x, y int) int {
	sum := s.calculator.Add(x, y)
	diff := s.calculator.Subtract(sum, 5)
	return diff
}
```

我们可以使用 `testify/mock` 来测试 `MyService`，而无需真正实现 `Calculator` 接口：

```go
package mypackage_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"your_module_path/mypackage" // 替换为你的模块路径
)

// 创建一个 MockCalculator 类型，嵌入 mock.Mock
type MockCalculator struct {
	mock.Mock
}

// 实现 Calculator 接口的 Add 方法，调用 mock 的 Call 方法
func (m *MockCalculator) Add(a, b int) int {
	args := m.Called(a, b)
	return args.Get(0).(int)
}

// 实现 Calculator 接口的 Subtract 方法，调用 mock 的 Call 方法
func (m *MockCalculator) Subtract(a, b int) int {
	args := m.Called(a, b)
	return args.Get(0).(int)
}

func TestMyService_PerformCalculation(t *testing.T) {
	// 创建一个 MockCalculator 实例
	mockCalc := new(MockCalculator)

	// 设置对 Add 方法的期望
	mockCalc.On("Add", 10, 5).Return(15)

	// 设置对 Subtract 方法的期望
	mockCalc.On("Subtract", 15, 5).Return(10)

	// 创建 MyService 实例，注入 MockCalculator
	service := mypackage.NewMyService(mockCalc)

	// 执行被测试的方法
	result := service.PerformCalculation(10, 5)

	// 断言结果
	assert.Equal(t, 10, result)

	// 断言 MockCalculator 的期望是否被满足
	mockCalc.AssertExpectations(t)
}

```

**假设的输入与输出：**

在上面的例子中，`TestMyService_PerformCalculation` 函数的输入是硬编码的 `10` 和 `5` 传递给 `PerformCalculation` 方法。

- **`mockCalc.On("Add", 10, 5).Return(15)`:**  假设 `MyService` 调用 `mockCalc.Add(10, 5)`，那么 `mockCalc.Called(10, 5)` 会被调用，它会找到匹配的期望，并返回预设的 `15`。
- **`mockCalc.On("Subtract", 15, 5).Return(10)`:** 假设 `MyService` 调用 `mockCalc.Subtract(15, 5)`（这里的 `15` 是 `Add` 方法的返回值），那么 `mockCalc.Called(15, 5)` 会被调用，找到匹配的期望，并返回预设的 `10`。

最终 `PerformCalculation` 方法会返回 `10`，这与 `assert.Equal(t, 10, result)` 的断言一致。

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。`testify` 库主要用于编写单元测试，而命令行参数通常在应用程序的主程序中处理。

**使用者易犯错的点：**

1. **忘记设置期望:**  如果在调用 mock 对象的方法之前没有使用 `On` 方法设置期望，`Called` 方法会 panic。

   ```go
   func TestMyService_WithoutExpectation(t *testing.T) {
       mockCalc := new(MockCalculator)
       service := mypackage.NewMyService(mockCalc)
       // 忘记设置对 Add 的期望
       // service.PerformCalculation(10, 5) // 这里会 panic
   }
   ```

2. **参数匹配不正确:**  `Called` 方法会严格匹配参数。如果设置期望时的参数与实际调用时的参数不一致，即使类型相同，也可能导致找不到匹配的期望。可以使用 `mock.Anything` 或 `mock.AnythingOfType` 来放宽参数匹配。

   ```go
   func TestMyService_IncorrectArgumentMatching(t *testing.T) {
       mockCalc := new(MockCalculator)
       mockCalc.On("Add", 10, 5).Return(15)
       service := mypackage.NewMyService(mockCalc)
       // 实际调用参数不同
       // service.PerformCalculation(10, 6) // 这里会 panic
   }
   ```

3. **断言方法使用错误:**  例如，使用了 `AssertCalled` 或 `AssertNotCalled` 但没有提供正确的参数，或者在测试结束时忘记调用 `AssertExpectations`。

   ```go
   func TestMyService_IncorrectAssertion(t *testing.T) {
       mockCalc := new(MockCalculator)
       mockCalc.On("Add", 10, 5).Return(15)
       service := mypackage.NewMyService(mockCalc)
       service.PerformCalculation(10, 5)
       // 断言时参数不匹配，会导致断言失败
       assert.True(t, mockCalc.AssertCalled(t, "Add", 10, 6))
   }
   ```

总而言之，这段代码是 `testify/mock` 库的核心，它提供了一种强大且灵活的方式来创建和管理 mock 对象，从而帮助开发者编写高质量的单元测试。理解其功能和使用方法对于进行有效的 Go 语言测试至关重要。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/nbutton23/zxcvbn-go/vendor/github.com/stretchr/testify/mock/mock.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package mock

import (
	"fmt"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/pmezard/go-difflib/difflib"
	"github.com/stretchr/objx"
	"github.com/stretchr/testify/assert"
)

func inin() {
	spew.Config.SortKeys = true
}

// TestingT is an interface wrapper around *testing.T
type TestingT interface {
	Logf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	FailNow()
}

/*
	Call
*/

// Call represents a method call and is used for setting expectations,
// as well as recording activity.
type Call struct {
	Parent *Mock

	// The name of the method that was or will be called.
	Method string

	// Holds the arguments of the method.
	Arguments Arguments

	// Holds the arguments that should be returned when
	// this method is called.
	ReturnArguments Arguments

	// The number of times to return the return arguments when setting
	// expectations. 0 means to always return the value.
	Repeatability int

	// Amount of times this call has been called
	totalCalls int

	// Holds a channel that will be used to block the Return until it either
	// receives a message or is closed. nil means it returns immediately.
	WaitFor <-chan time.Time

	// Holds a handler used to manipulate arguments content that are passed by
	// reference. It's useful when mocking methods such as unmarshalers or
	// decoders.
	RunFn func(Arguments)
}

func newCall(parent *Mock, methodName string, methodArguments ...interface{}) *Call {
	return &Call{
		Parent:          parent,
		Method:          methodName,
		Arguments:       methodArguments,
		ReturnArguments: make([]interface{}, 0),
		Repeatability:   0,
		WaitFor:         nil,
		RunFn:           nil,
	}
}

func (c *Call) lock() {
	c.Parent.mutex.Lock()
}

func (c *Call) unlock() {
	c.Parent.mutex.Unlock()
}

// Return specifies the return arguments for the expectation.
//
//    Mock.On("DoSomething").Return(errors.New("failed"))
func (c *Call) Return(returnArguments ...interface{}) *Call {
	c.lock()
	defer c.unlock()

	c.ReturnArguments = returnArguments

	return c
}

// Once indicates that that the mock should only return the value once.
//
//    Mock.On("MyMethod", arg1, arg2).Return(returnArg1, returnArg2).Once()
func (c *Call) Once() *Call {
	return c.Times(1)
}

// Twice indicates that that the mock should only return the value twice.
//
//    Mock.On("MyMethod", arg1, arg2).Return(returnArg1, returnArg2).Twice()
func (c *Call) Twice() *Call {
	return c.Times(2)
}

// Times indicates that that the mock should only return the indicated number
// of times.
//
//    Mock.On("MyMethod", arg1, arg2).Return(returnArg1, returnArg2).Times(5)
func (c *Call) Times(i int) *Call {
	c.lock()
	defer c.unlock()
	c.Repeatability = i
	return c
}

// WaitUntil sets the channel that will block the mock's return until its closed
// or a message is received.
//
//    Mock.On("MyMethod", arg1, arg2).WaitUntil(time.After(time.Second))
func (c *Call) WaitUntil(w <-chan time.Time) *Call {
	c.lock()
	defer c.unlock()
	c.WaitFor = w
	return c
}

// After sets how long to block until the call returns
//
//    Mock.On("MyMethod", arg1, arg2).After(time.Second)
func (c *Call) After(d time.Duration) *Call {
	return c.WaitUntil(time.After(d))
}

// Run sets a handler to be called before returning. It can be used when
// mocking a method such as unmarshalers that takes a pointer to a struct and
// sets properties in such struct
//
//    Mock.On("Unmarshal", AnythingOfType("*map[string]interface{}").Return().Run(func(args Arguments) {
//    	arg := args.Get(0).(*map[string]interface{})
//    	arg["foo"] = "bar"
//    })
func (c *Call) Run(fn func(Arguments)) *Call {
	c.lock()
	defer c.unlock()
	c.RunFn = fn
	return c
}

// On chains a new expectation description onto the mocked interface. This
// allows syntax like.
//
//    Mock.
//       On("MyMethod", 1).Return(nil).
//       On("MyOtherMethod", 'a', 'b', 'c').Return(errors.New("Some Error"))
func (c *Call) On(methodName string, arguments ...interface{}) *Call {
	return c.Parent.On(methodName, arguments...)
}

// Mock is the workhorse used to track activity on another object.
// For an example of its usage, refer to the "Example Usage" section at the top
// of this document.
type Mock struct {
	// Represents the calls that are expected of
	// an object.
	ExpectedCalls []*Call

	// Holds the calls that were made to this mocked object.
	Calls []Call

	// TestData holds any data that might be useful for testing.  Testify ignores
	// this data completely allowing you to do whatever you like with it.
	testData objx.Map

	mutex sync.Mutex
}

// TestData holds any data that might be useful for testing.  Testify ignores
// this data completely allowing you to do whatever you like with it.
func (m *Mock) TestData() objx.Map {

	if m.testData == nil {
		m.testData = make(objx.Map)
	}

	return m.testData
}

/*
	Setting expectations
*/

// On starts a description of an expectation of the specified method
// being called.
//
//     Mock.On("MyMethod", arg1, arg2)
func (m *Mock) On(methodName string, arguments ...interface{}) *Call {
	for _, arg := range arguments {
		if v := reflect.ValueOf(arg); v.Kind() == reflect.Func {
			panic(fmt.Sprintf("cannot use Func in expectations. Use mock.AnythingOfType(\"%T\")", arg))
		}
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()
	c := newCall(m, methodName, arguments...)
	m.ExpectedCalls = append(m.ExpectedCalls, c)
	return c
}

// /*
// 	Recording and responding to activity
// */

func (m *Mock) findExpectedCall(method string, arguments ...interface{}) (int, *Call) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	for i, call := range m.ExpectedCalls {
		if call.Method == method && call.Repeatability > -1 {

			_, diffCount := call.Arguments.Diff(arguments)
			if diffCount == 0 {
				return i, call
			}

		}
	}
	return -1, nil
}

func (m *Mock) findClosestCall(method string, arguments ...interface{}) (bool, *Call) {
	diffCount := 0
	var closestCall *Call

	for _, call := range m.expectedCalls() {
		if call.Method == method {

			_, tempDiffCount := call.Arguments.Diff(arguments)
			if tempDiffCount < diffCount || diffCount == 0 {
				diffCount = tempDiffCount
				closestCall = call
			}

		}
	}

	if closestCall == nil {
		return false, nil
	}

	return true, closestCall
}

func callString(method string, arguments Arguments, includeArgumentValues bool) string {

	var argValsString string
	if includeArgumentValues {
		var argVals []string
		for argIndex, arg := range arguments {
			argVals = append(argVals, fmt.Sprintf("%d: %#v", argIndex, arg))
		}
		argValsString = fmt.Sprintf("\n\t\t%s", strings.Join(argVals, "\n\t\t"))
	}

	return fmt.Sprintf("%s(%s)%s", method, arguments.String(), argValsString)
}

// Called tells the mock object that a method has been called, and gets an array
// of arguments to return.  Panics if the call is unexpected (i.e. not preceded by
// appropriate .On .Return() calls)
// If Call.WaitFor is set, blocks until the channel is closed or receives a message.
func (m *Mock) Called(arguments ...interface{}) Arguments {
	// get the calling function's name
	pc, _, _, ok := runtime.Caller(1)
	if !ok {
		panic("Couldn't get the caller information")
	}
	functionPath := runtime.FuncForPC(pc).Name()
	//Next four lines are required to use GCCGO function naming conventions.
	//For Ex:  github_com_docker_libkv_store_mock.WatchTree.pN39_github_com_docker_libkv_store_mock.Mock
	//uses inteface information unlike golang github.com/docker/libkv/store/mock.(*Mock).WatchTree
	//With GCCGO we need to remove interface information starting from pN<dd>.
	re := regexp.MustCompile("\\.pN\\d+_")
	if re.MatchString(functionPath) {
		functionPath = re.Split(functionPath, -1)[0]
	}
	parts := strings.Split(functionPath, ".")
	functionName := parts[len(parts)-1]

	found, call := m.findExpectedCall(functionName, arguments...)

	if found < 0 {
		// we have to fail here - because we don't know what to do
		// as the return arguments.  This is because:
		//
		//   a) this is a totally unexpected call to this method,
		//   b) the arguments are not what was expected, or
		//   c) the developer has forgotten to add an accompanying On...Return pair.

		closestFound, closestCall := m.findClosestCall(functionName, arguments...)

		if closestFound {
			panic(fmt.Sprintf("\n\nmock: Unexpected Method Call\n-----------------------------\n\n%s\n\nThe closest call I have is: \n\n%s\n\n%s\n", callString(functionName, arguments, true), callString(functionName, closestCall.Arguments, true), diffArguments(arguments, closestCall.Arguments)))
		} else {
			panic(fmt.Sprintf("\nassert: mock: I don't know what to return because the method call was unexpected.\n\tEither do Mock.On(\"%s\").Return(...) first, or remove the %s() call.\n\tThis method was unexpected:\n\t\t%s\n\tat: %s", functionName, functionName, callString(functionName, arguments, true), assert.CallerInfo()))
		}
	} else {
		m.mutex.Lock()
		switch {
		case call.Repeatability == 1:
			call.Repeatability = -1
			call.totalCalls++

		case call.Repeatability > 1:
			call.Repeatability--
			call.totalCalls++

		case call.Repeatability == 0:
			call.totalCalls++
		}
		m.mutex.Unlock()
	}

	// add the call
	m.mutex.Lock()
	m.Calls = append(m.Calls, *newCall(m, functionName, arguments...))
	m.mutex.Unlock()

	// block if specified
	if call.WaitFor != nil {
		<-call.WaitFor
	}

	if call.RunFn != nil {
		call.RunFn(arguments)
	}

	return call.ReturnArguments
}

/*
	Assertions
*/

type assertExpectationser interface {
	AssertExpectations(TestingT) bool
}

// AssertExpectationsForObjects asserts that everything specified with On and Return
// of the specified objects was in fact called as expected.
//
// Calls may have occurred in any order.
func AssertExpectationsForObjects(t TestingT, testObjects ...interface{}) bool {
	for _, obj := range testObjects {
		if m, ok := obj.(Mock); ok {
			t.Logf("Deprecated mock.AssertExpectationsForObjects(myMock.Mock) use mock.AssertExpectationsForObjects(myMock)")
			obj = &m
		}
		m := obj.(assertExpectationser)
		if !m.AssertExpectations(t) {
			return false
		}
	}
	return true
}

// AssertExpectations asserts that everything specified with On and Return was
// in fact called as expected.  Calls may have occurred in any order.
func (m *Mock) AssertExpectations(t TestingT) bool {
	var somethingMissing bool
	var failedExpectations int

	// iterate through each expectation
	expectedCalls := m.expectedCalls()
	for _, expectedCall := range expectedCalls {
		if !m.methodWasCalled(expectedCall.Method, expectedCall.Arguments) && expectedCall.totalCalls == 0 {
			somethingMissing = true
			failedExpectations++
			t.Logf("\u274C\t%s(%s)", expectedCall.Method, expectedCall.Arguments.String())
		} else {
			m.mutex.Lock()
			if expectedCall.Repeatability > 0 {
				somethingMissing = true
				failedExpectations++
			} else {
				t.Logf("\u2705\t%s(%s)", expectedCall.Method, expectedCall.Arguments.String())
			}
			m.mutex.Unlock()
		}
	}

	if somethingMissing {
		t.Errorf("FAIL: %d out of %d expectation(s) were met.\n\tThe code you are testing needs to make %d more call(s).\n\tat: %s", len(expectedCalls)-failedExpectations, len(expectedCalls), failedExpectations, assert.CallerInfo())
	}

	return !somethingMissing
}

// AssertNumberOfCalls asserts that the method was called expectedCalls times.
func (m *Mock) AssertNumberOfCalls(t TestingT, methodName string, expectedCalls int) bool {
	var actualCalls int
	for _, call := range m.calls() {
		if call.Method == methodName {
			actualCalls++
		}
	}
	return assert.Equal(t, expectedCalls, actualCalls, fmt.Sprintf("Expected number of calls (%d) does not match the actual number of calls (%d).", expectedCalls, actualCalls))
}

// AssertCalled asserts that the method was called.
// It can produce a false result when an argument is a pointer type and the underlying value changed after calling the mocked method.
func (m *Mock) AssertCalled(t TestingT, methodName string, arguments ...interface{}) bool {
	if !assert.True(t, m.methodWasCalled(methodName, arguments), fmt.Sprintf("The \"%s\" method should have been called with %d argument(s), but was not.", methodName, len(arguments))) {
		t.Logf("%v", m.expectedCalls())
		return false
	}
	return true
}

// AssertNotCalled asserts that the method was not called.
// It can produce a false result when an argument is a pointer type and the underlying value changed after calling the mocked method.
func (m *Mock) AssertNotCalled(t TestingT, methodName string, arguments ...interface{}) bool {
	if !assert.False(t, m.methodWasCalled(methodName, arguments), fmt.Sprintf("The \"%s\" method was called with %d argument(s), but should NOT have been.", methodName, len(arguments))) {
		t.Logf("%v", m.expectedCalls())
		return false
	}
	return true
}

func (m *Mock) methodWasCalled(methodName string, expected []interface{}) bool {
	for _, call := range m.calls() {
		if call.Method == methodName {

			_, differences := Arguments(expected).Diff(call.Arguments)

			if differences == 0 {
				// found the expected call
				return true
			}

		}
	}
	// we didn't find the expected call
	return false
}

func (m *Mock) expectedCalls() []*Call {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return append([]*Call{}, m.ExpectedCalls...)
}

func (m *Mock) calls() []Call {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return append([]Call{}, m.Calls...)
}

/*
	Arguments
*/

// Arguments holds an array of method arguments or return values.
type Arguments []interface{}

const (
	// Anything is used in Diff and Assert when the argument being tested
	// shouldn't be taken into consideration.
	Anything string = "mock.Anything"
)

// AnythingOfTypeArgument is a string that contains the type of an argument
// for use when type checking.  Used in Diff and Assert.
type AnythingOfTypeArgument string

// AnythingOfType returns an AnythingOfTypeArgument object containing the
// name of the type to check for.  Used in Diff and Assert.
//
// For example:
//	Assert(t, AnythingOfType("string"), AnythingOfType("int"))
func AnythingOfType(t string) AnythingOfTypeArgument {
	return AnythingOfTypeArgument(t)
}

// argumentMatcher performs custom argument matching, returning whether or
// not the argument is matched by the expectation fixture function.
type argumentMatcher struct {
	// fn is a function which accepts one argument, and returns a bool.
	fn reflect.Value
}

func (f argumentMatcher) Matches(argument interface{}) bool {
	expectType := f.fn.Type().In(0)

	if reflect.TypeOf(argument).AssignableTo(expectType) {
		result := f.fn.Call([]reflect.Value{reflect.ValueOf(argument)})
		return result[0].Bool()
	}
	return false
}

func (f argumentMatcher) String() string {
	return fmt.Sprintf("func(%s) bool", f.fn.Type().In(0).Name())
}

// MatchedBy can be used to match a mock call based on only certain properties
// from a complex struct or some calculation. It takes a function that will be
// evaluated with the called argument and will return true when there's a match
// and false otherwise.
//
// Example:
// m.On("Do", MatchedBy(func(req *http.Request) bool { return req.Host == "example.com" }))
//
// |fn|, must be a function accepting a single argument (of the expected type)
// which returns a bool. If |fn| doesn't match the required signature,
// MathedBy() panics.
func MatchedBy(fn interface{}) argumentMatcher {
	fnType := reflect.TypeOf(fn)

	if fnType.Kind() != reflect.Func {
		panic(fmt.Sprintf("assert: arguments: %s is not a func", fn))
	}
	if fnType.NumIn() != 1 {
		panic(fmt.Sprintf("assert: arguments: %s does not take exactly one argument", fn))
	}
	if fnType.NumOut() != 1 || fnType.Out(0).Kind() != reflect.Bool {
		panic(fmt.Sprintf("assert: arguments: %s does not return a bool", fn))
	}

	return argumentMatcher{fn: reflect.ValueOf(fn)}
}

// Get Returns the argument at the specified index.
func (args Arguments) Get(index int) interface{} {
	if index+1 > len(args) {
		panic(fmt.Sprintf("assert: arguments: Cannot call Get(%d) because there are %d argument(s).", index, len(args)))
	}
	return args[index]
}

// Is gets whether the objects match the arguments specified.
func (args Arguments) Is(objects ...interface{}) bool {
	for i, obj := range args {
		if obj != objects[i] {
			return false
		}
	}
	return true
}

// Diff gets a string describing the differences between the arguments
// and the specified objects.
//
// Returns the diff string and number of differences found.
func (args Arguments) Diff(objects []interface{}) (string, int) {

	var output = "\n"
	var differences int

	var maxArgCount = len(args)
	if len(objects) > maxArgCount {
		maxArgCount = len(objects)
	}

	for i := 0; i < maxArgCount; i++ {
		var actual, expected interface{}

		if len(objects) <= i {
			actual = "(Missing)"
		} else {
			actual = objects[i]
		}

		if len(args) <= i {
			expected = "(Missing)"
		} else {
			expected = args[i]
		}

		if matcher, ok := expected.(argumentMatcher); ok {
			if matcher.Matches(actual) {
				output = fmt.Sprintf("%s\t%d: \u2705  %s matched by %s\n", output, i, actual, matcher)
			} else {
				differences++
				output = fmt.Sprintf("%s\t%d: \u2705  %s not matched by %s\n", output, i, actual, matcher)
			}
		} else if reflect.TypeOf(expected) == reflect.TypeOf((*AnythingOfTypeArgument)(nil)).Elem() {

			// type checking
			if reflect.TypeOf(actual).Name() != string(expected.(AnythingOfTypeArgument)) && reflect.TypeOf(actual).String() != string(expected.(AnythingOfTypeArgument)) {
				// not match
				differences++
				output = fmt.Sprintf("%s\t%d: \u274C  type %s != type %s - %s\n", output, i, expected, reflect.TypeOf(actual).Name(), actual)
			}

		} else {

			// normal checking

			if assert.ObjectsAreEqual(expected, Anything) || assert.ObjectsAreEqual(actual, Anything) || assert.ObjectsAreEqual(actual, expected) {
				// match
				output = fmt.Sprintf("%s\t%d: \u2705  %s == %s\n", output, i, actual, expected)
			} else {
				// not match
				differences++
				output = fmt.Sprintf("%s\t%d: \u274C  %s != %s\n", output, i, actual, expected)
			}
		}

	}

	if differences == 0 {
		return "No differences.", differences
	}

	return output, differences

}

// Assert compares the arguments with the specified objects and fails if
// they do not exactly match.
func (args Arguments) Assert(t TestingT, objects ...interface{}) bool {

	// get the differences
	diff, diffCount := args.Diff(objects)

	if diffCount == 0 {
		return true
	}

	// there are differences... report them...
	t.Logf(diff)
	t.Errorf("%sArguments do not match.", assert.CallerInfo())

	return false

}

// String gets the argument at the specified index. Panics if there is no argument, or
// if the argument is of the wrong type.
//
// If no index is provided, String() returns a complete string representation
// of the arguments.
func (args Arguments) String(indexOrNil ...int) string {

	if len(indexOrNil) == 0 {
		// normal String() method - return a string representation of the args
		var argsStr []string
		for _, arg := range args {
			argsStr = append(argsStr, fmt.Sprintf("%s", reflect.TypeOf(arg)))
		}
		return strings.Join(argsStr, ",")
	} else if len(indexOrNil) == 1 {
		// Index has been specified - get the argument at that index
		var index = indexOrNil[0]
		var s string
		var ok bool
		if s, ok = args.Get(index).(string); !ok {
			panic(fmt.Sprintf("assert: arguments: String(%d) failed because object wasn't correct type: %s", index, args.Get(index)))
		}
		return s
	}

	panic(fmt.Sprintf("assert: arguments: Wrong number of arguments passed to String.  Must be 0 or 1, not %d", len(indexOrNil)))

}

// Int gets the argument at the specified index. Panics if there is no argument, or
// if the argument is of the wrong type.
func (args Arguments) Int(index int) int {
	var s int
	var ok bool
	if s, ok = args.Get(index).(int); !ok {
		panic(fmt.Sprintf("assert: arguments: Int(%d) failed because object wasn't correct type: %v", index, args.Get(index)))
	}
	return s
}

// Error gets the argument at the specified index. Panics if there is no argument, or
// if the argument is of the wrong type.
func (args Arguments) Error(index int) error {
	obj := args.Get(index)
	var s error
	var ok bool
	if obj == nil {
		return nil
	}
	if s, ok = obj.(error); !ok {
		panic(fmt.Sprintf("assert: arguments: Error(%d) failed because object wasn't correct type: %v", index, args.Get(index)))
	}
	return s
}

// Bool gets the argument at the specified index. Panics if there is no argument, or
// if the argument is of the wrong type.
func (args Arguments) Bool(index int) bool {
	var s bool
	var ok bool
	if s, ok = args.Get(index).(bool); !ok {
		panic(fmt.Sprintf("assert: arguments: Bool(%d) failed because object wasn't correct type: %v", index, args.Get(index)))
	}
	return s
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

func diffArguments(expected Arguments, actual Arguments) string {
	for x := range expected {
		if diffString := diff(expected[x], actual[x]); diffString != "" {
			return fmt.Sprintf("Difference found in argument %v:\n\n%s", x, diffString)
		}
	}

	return ""
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

	return diff
}

"""



```