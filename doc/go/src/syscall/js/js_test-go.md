Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understanding the Goal:** The core request is to analyze a Go test file (`js_test.go`) within the `syscall/js` package and explain its functionality. Specifically, the request asks for:
    * A summary of its functions.
    * Examples of the Go language features it demonstrates.
    * Details on any code inference, including assumptions, inputs, and outputs.
    * Information on command-line arguments (though this turns out to be minimal).
    * Identification of common mistakes users might make.

2. **Initial Scan and High-Level Overview:** I started by quickly reading through the code, paying attention to the `package` declaration (`js_test`), the `import` statements (`fmt`, `math`, `runtime`, `syscall/js`, `testing`), and the overall structure. The presence of `//go:build js && wasm` immediately signals that this code is specifically for the `js` operating system and the `wasm` architecture. The comments about running the tests with `GOOS=js GOARCH=wasm go test` confirm this. This suggests the code is testing Go's ability to interact with JavaScript in a WebAssembly environment.

3. **Identifying Key Components:**  I then looked for major blocks of code and their purpose:
    * **`dummys` variable:**  This immediately stood out as a central piece. It uses `js.Global().Call("eval", ...)` to create a JavaScript object. This suggests the tests will interact with this object to test value conversions and operations.
    * **`//go:wasmimport` and `//go:wasmexport`:** These are special Go compiler directives for WebAssembly. `wasmimport` indicates that a function is implemented in the host environment (JavaScript in this case), and `wasmexport` means a Go function is exposed to the host. This is crucial for understanding how Go and JavaScript communicate.
    * **`Test...` functions:**  These are standard Go testing functions. Each `Test...` function seems to focus on a specific aspect of the `syscall/js` package.
    * **Helper functions:** Functions like `growStack`, `testIntConversion`, `expectValueError`, and `expectPanic` are clearly for supporting the tests.
    * **`ExampleFuncOf`:** This demonstrates how to use `js.FuncOf` to create a Go function that can be called from JavaScript.
    * **`BenchmarkDOM`:**  This is a performance benchmark for DOM manipulation.

4. **Analyzing Individual Test Functions:**  I went through each `Test...` function, trying to understand what it was testing:
    * `TestWasmImport`: Checks calling a JavaScript function from Go.
    * `TestWasmExport`: Checks calling a Go function from JavaScript.
    * `TestBool`, `TestString`, `TestInt`, `TestFloat`, `TestObject`, etc.: These test how Go values are converted to and from JavaScript values and how basic operations (Get, Set, Equal, etc.) work.
    * `TestFuncOf`: Tests creating Go functions callable from JavaScript.
    * `TestCopyBytesToGo`, `TestCopyBytesToJS`:  Test efficient byte array transfers.
    * `TestGarbageCollection`: Checks if garbage collection is working correctly in the WASM environment.
    * `TestCallAllocations`, `TestInvokeAllocations`, `TestNewAllocations`: Examine the memory allocation behavior of different `js.Value` methods.
    * `TestGlobal`: Tests obtaining the global JavaScript object.

5. **Inferring Functionality:** Based on the test names and the operations performed within them, I could infer the functionality of various parts of the `syscall/js` package. For example, the `TestBool` function directly shows how to get and set boolean values in JavaScript from Go using `Value.Bool()` and `Value.Set()`. The `TestCall` function shows how to call JavaScript functions using `Value.Call()`.

6. **Providing Go Code Examples:**  Once I understood the purpose of a test function, I could construct simple Go code examples illustrating the corresponding `syscall/js` functionality. For instance, to show how `js.Global().Get()` works, I created an example of accessing `console.log`.

7. **Addressing Command-Line Arguments:** The code itself didn't process command-line arguments. The comments mentioned environment variables (`GOOS`, `GOARCH`) for building and running, which I included in the explanation.

8. **Identifying Potential Pitfalls:**  Based on the code and my understanding of the interaction between Go and JavaScript, I identified potential issues:
    * **Releasing `js.Func`:** Emphasizing the need to release functions created with `js.FuncOf` to prevent memory leaks.
    * **Type Mismatches:**  Highlighting potential errors when assuming JavaScript types are the same as Go types.

9. **Structuring the Answer:** I organized the information into logical sections as requested: functionality, Go feature implementation (with examples), code inference details, command-line arguments, and potential pitfalls. I used clear headings and formatting to make the information easy to read.

10. **Review and Refinement:**  Finally, I reread my analysis to ensure accuracy, clarity, and completeness, checking that I had addressed all aspects of the original request. For example, I made sure to explain the purpose of the initial `dummys` object and how it was used throughout the tests. I also reviewed the assumptions I made during code inference to ensure they were reasonable.
这个 Go 语言文件 `js_test.go` 是 `syscall/js` 包的一部分，专门用于测试 Go 在 `js` (JavaScript) 操作系统和 `wasm` (WebAssembly) 架构下的系统调用功能。它旨在验证 Go 代码与 JavaScript 代码的互操作性。

以下是该文件列举的功能以及更详细的解释：

**核心功能:**

1. **测试 Go 调用 JavaScript 代码:**
   - 它测试了 Go 代码如何调用 JavaScript 全局对象的方法和属性，例如 `eval`。
   - 它测试了如何获取和设置 JavaScript 对象的不同类型的值 (布尔值, 字符串, 整数, 浮点数, 数组, 日期等)。
   - 它测试了如何调用 JavaScript 对象的方法 (`Call`) 和如何作为方法调用 (`Invoke`)。
   - 它测试了如何创建新的 JavaScript 对象 (`New`)。
   - 它测试了如何判断一个 JavaScript 对象是否是某个构造函数的实例 (`InstanceOf`)。
   - 它测试了如何获取 JavaScript 值的类型 (`Type`)。
   - 它测试了 `js.ValueOf` 函数，用于将 Go 的值转换为 JavaScript 的值。
   - 它测试了如何创建可以从 JavaScript 调用的 Go 函数 (`js.FuncOf`)。
   - 它测试了 `js.CopyBytesToGo` 和 `js.CopyBytesToJS` 函数，用于在 Go 和 JavaScript 之间高效地复制字节数组。

2. **测试 JavaScript 调用 Go 代码:**
   - 它使用了 `//go:wasmimport` 指令来声明一个由 JavaScript 环境提供的函数 (`testAdd`, `testCallExport`)，并测试了从 Go 代码中调用这些导入的函数。
   - 它使用了 `//go:wasmexport` 指令来将 Go 函数 (`testExport`, `testExport0`) 导出到 JavaScript 环境，并测试了 JavaScript 代码调用这些导出的函数。

3. **测试 `js.Value` 类型的各种操作:**
   - 它测试了 `js.Value` 类型的 `Bool()`, `String()`, `Int()`, `Float()` 方法，用于将 JavaScript 值转换为 Go 的对应类型。
   - 它测试了 `js.Value` 类型的 `Get()`, `Set()`, `Delete()`, `Index()`, `SetIndex()` 方法，用于操作 JavaScript 对象和数组的属性和元素。
   - 它测试了 `js.Value` 类型的 `Equal()` 方法，用于比较 JavaScript 值是否相等。
   - 它测试了 `js.Value` 类型的 `IsNaN()`, `IsUndefined()`, `IsNull()` 方法，用于判断 JavaScript 值是否为 NaN, undefined 或 null。
   - 它测试了 `js.Value` 类型的 `Length()` 方法，用于获取 JavaScript 数组或字符串的长度。
   - 它测试了 `js.Value` 类型的 `Truthy()` 方法，用于判断 JavaScript 值是否为 truthy。

4. **测试错误处理:**
   - 它使用了 `expectValueError` 和 `expectPanic` 辅助函数来测试在执行无效的 JavaScript 操作时是否会抛出预期的错误。

5. **测试内存管理 (垃圾回收):**
   - 它测试了在 Go/Wasm 环境中垃圾回收机制是否正常工作，即当不再使用的 JavaScript 对象被 Go 侧释放后，JavaScript 引擎能够回收其内存。

6. **测试性能 (基准测试):**
   - 它包含了一个 `BenchmarkDOM` 基准测试，模拟了 Web 应用中常见的 DOM 操作，用于评估 Go/Wasm 在进行 JavaScript 操作时的性能。

7. **测试 `js.Global()`:**
   - 它测试了 `js.Global()` 函数是否正确返回全局 JavaScript 对象。

**Go 语言功能实现示例:**

**1. 调用 JavaScript 函数:**

```go
package main

import (
	"fmt"
	"syscall/js"
)

func main() {
	// 获取全局 JavaScript 对象
	global := js.Global()

	// 获取 JavaScript 的 console 对象
	console := global.Get("console")

	// 调用 console.log 方法
	console.Call("log", "Hello from Go/Wasm!")
}
```

**假设输入与输出:**

- **输入:**  运行上述 Go 代码。
- **输出:** 在浏览器的开发者控制台中会输出 "Hello from Go/Wasm!"。

**2. 将 Go 值传递给 JavaScript:**

```go
package main

import (
	"fmt"
	"syscall/js"
)

func main() {
	global := js.Global()

	// 将 Go 字符串传递给 JavaScript 的 alert 函数
	global.Call("alert", "This is a Go string!")

	// 将 Go 整数传递给 JavaScript 的 alert 函数
	global.Call("alert", 123)
}
```

**假设输入与输出:**

- **输入:** 运行上述 Go 代码。
- **输出:**  会弹出两个警告框，分别显示 "This is a Go string!" 和 "123"。

**3. 从 JavaScript 获取值:**

```go
package main

import (
	"fmt"
	"syscall/js"
)

func main() {
	global := js.Global()

	// 获取 JavaScript 的全局变量 myVar (假设已在 JavaScript 中定义)
	myVar := global.Get("myVar")

	// 将 JavaScript 的值转换为 Go 的字符串
	if myVar.Type() == js.TypeString {
		goString := myVar.String()
		fmt.Println("Value of myVar:", goString)
	} else {
		fmt.Println("myVar is not a string")
	}
}
```

**假设输入与输出:**

- **假设输入:** 在 JavaScript 环境中定义了 `var myVar = "JavaScript Value";`。
- **输出:** 运行 Go 代码后，控制台会输出 "Value of myVar: JavaScript Value"。

**代码推理 (涉及 `//go:wasmimport` 和 `//go:wasmexport`)**

这段代码展示了 Go/Wasm 如何与宿主环境 (通常是 JavaScript) 交互。

- **`//go:wasmimport _gotest add`**: 这行代码声明了一个名为 `testAdd` 的 Go 函数，但它的实际实现是在 JavaScript 环境中。当 Go 代码调用 `testAdd(a, b)` 时，Wasm 运行时会查找名为 `_gotest.add` 的 JavaScript 函数并执行它。

   **假设输入与输出 (针对 `TestWasmImport`)**:
   - **假设 JavaScript 环境中存在以下代码:**
     ```javascript
     globalThis._gotest = {
       add: function(a, b) {
         return a + b;
       }
     };
     ```
   - **输入:** `TestWasmImport` 函数中调用 `testAdd(3, 5)`。
   - **输出:** `testAdd` 函数返回 `8`，Go 代码中的断言 `got != want` 将会失败，因为 `want` 也被计算为 `3 + 5 = 8`。

- **`//go:wasmexport testExport`**: 这行代码指示 Go 编译器生成必要的代码，使得 Go 函数 `testExport` 可以被 JavaScript 环境调用。当 JavaScript 调用名为 `testExport` 的函数时，实际上会执行 Go 的 `testExport` 函数。

   **假设输入与输出 (针对 `TestWasmExport`)**:
   - **假设 JavaScript 环境中存在以下代码:**
     ```javascript
     // wasm_exec.js (或其他类似的 Wasm 执行环境) 会处理导出函数的调用
     // 假设可以通过某种方式调用导出的 Go 函数 testExport
     // 例如： go.exports.testExport(123, 456);
     ```
   - **输入:** JavaScript 调用 `testExport(123, 456)`。
   - **输出:** Go 的 `testExport` 函数会被执行，`testExportCalled` 会被设置为 `true`，并且会进行一些内部操作 (堆栈增长，goroutine 切换)。最终，它会返回 `int64(123) + 456 = 579`。 `TestWasmExport` 会检查返回值是否正确以及 `testExportCalled` 是否为 `true`。

**命令行参数处理:**

该文件本身并没有直接处理命令行参数。然而，为了运行这些测试，你需要使用 `go test` 命令，并且需要设置环境变量 `GOOS` 和 `GOARCH`：

```bash
GOOS=js GOARCH=wasm go test
```

- `GOOS=js`:  指定目标操作系统为 JavaScript。
- `GOARCH=wasm`: 指定目标架构为 WebAssembly。
- `go test`:  运行当前目录下的测试文件。

这些环境变量告诉 Go 工具链，你需要构建和测试可以在 JavaScript/WebAssembly 环境中运行的代码。

**使用者易犯错的点:**

1. **忘记 Release `js.Func`:**  当使用 `js.FuncOf` 创建可以在 JavaScript 中调用的 Go 函数时，需要在使用完毕后调用 `Release()` 方法来释放相关的资源，防止内存泄漏。

   ```go
   func main() {
       cb := js.FuncOf(func(this js.Value, args []js.Value) any {
           // ... 一些操作 ...
           return nil
       })
       defer cb.Release() // 确保函数退出时释放资源

       // 将 cb 传递给 JavaScript
       js.Global().Get("someObject").Set("callback", cb)

       // ...
   }
   ```
   **易错情况:** 如果忘记 `cb.Release()`，每次创建 `js.FuncOf` 都会在 Go 侧保留一个对 JavaScript 函数的引用，导致内存占用持续增加。

2. **类型转换错误:**  从 JavaScript 获取值后，需要根据实际类型进行转换。如果类型不匹配，调用如 `Int()` 或 `String()` 等方法可能会导致意外的结果甚至 panic。

   ```go
   func main() {
       global := js.Global()
       value := global.Get("someValue") // 假设 JavaScript 中 someValue 是一个字符串 "123"

       // 错误的做法：假设它是整数
       intValue := value.Int() // 如果 value 不是数字，可能会得到 0 或 panic
       fmt.Println(intValue)

       // 正确的做法：先检查类型
       if value.Type() == js.TypeNumber {
           intValue := value.Int()
           fmt.Println(intValue)
       } else if value.Type() == js.TypeString {
           stringValue := value.String()
           fmt.Println(stringValue)
       }
   }
   ```

3. **在错误的上下文中操作 `js.Value`:** `js.Value` 对象与特定的 JavaScript 运行时环境关联。尝试在不同的 Goroutine 或回调中直接传递和操作 `js.Value` 可能导致问题，因为 JavaScript 的对象不是线程安全的。 通常需要在同一个 Goroutine 中创建和操作 `js.Value`，或者使用 channel 等机制进行同步。

总而言之，`js_test.go` 文件是一个全面的测试套件，用于验证 `syscall/js` 包在 Go/Wasm 环境下的正确性和功能，涵盖了 Go 与 JavaScript 交互的各种场景，包括值传递、函数调用、错误处理和内存管理等。

Prompt: 
```
这是路径为go/src/syscall/js/js_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build js && wasm

// To run these tests:
//
// - Install Node
// - Add /path/to/go/lib/wasm to your $PATH (so that "go test" can find
//   "go_js_wasm_exec").
// - GOOS=js GOARCH=wasm go test
//
// See -exec in "go help test", and "go help run" for details.

package js_test

import (
	"fmt"
	"math"
	"runtime"
	"syscall/js"
	"testing"
)

var dummys = js.Global().Call("eval", `({
	someBool: true,
	someString: "abc\u1234",
	someInt: 42,
	someFloat: 42.123,
	someArray: [41, 42, 43],
	someDate: new Date(),
	add: function(a, b) {
		return a + b;
	},
	zero: 0,
	stringZero: "0",
	NaN: NaN,
	emptyObj: {},
	emptyArray: [],
	Infinity: Infinity,
	NegInfinity: -Infinity,
	objNumber0: new Number(0),
	objBooleanFalse: new Boolean(false),
})`)

//go:wasmimport _gotest add
func testAdd(uint32, uint32) uint32

func TestWasmImport(t *testing.T) {
	a := uint32(3)
	b := uint32(5)
	want := a + b
	if got := testAdd(a, b); got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

// testCallExport is imported from host (wasm_exec.js), which calls testExport.
//
//go:wasmimport _gotest callExport
func testCallExport(a int32, b int64) int64

//go:wasmexport testExport
func testExport(a int32, b int64) int64 {
	testExportCalled = true
	// test stack growth
	growStack(1000)
	// force a goroutine switch
	ch := make(chan int64)
	go func() {
		ch <- int64(a)
		ch <- b
	}()
	return <-ch + <-ch
}

//go:wasmexport testExport0
func testExport0() { // no arg or result (see issue 69584)
	runtime.GC()
}

var testExportCalled bool

func growStack(n int64) {
	if n > 0 {
		growStack(n - 1)
	}
}

func TestWasmExport(t *testing.T) {
	testExportCalled = false
	a := int32(123)
	b := int64(456)
	want := int64(a) + b
	if got := testCallExport(a, b); got != want {
		t.Errorf("got %v, want %v", got, want)
	}
	if !testExportCalled {
		t.Error("testExport not called")
	}
}

func TestBool(t *testing.T) {
	want := true
	o := dummys.Get("someBool")
	if got := o.Bool(); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	dummys.Set("otherBool", want)
	if got := dummys.Get("otherBool").Bool(); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if !dummys.Get("someBool").Equal(dummys.Get("someBool")) {
		t.Errorf("same value not equal")
	}
}

func TestString(t *testing.T) {
	want := "abc\u1234"
	o := dummys.Get("someString")
	if got := o.String(); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	dummys.Set("otherString", want)
	if got := dummys.Get("otherString").String(); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if !dummys.Get("someString").Equal(dummys.Get("someString")) {
		t.Errorf("same value not equal")
	}

	if got, want := js.Undefined().String(), "<undefined>"; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := js.Null().String(), "<null>"; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := js.ValueOf(true).String(), "<boolean: true>"; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := js.ValueOf(42.5).String(), "<number: 42.5>"; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := js.Global().Call("Symbol").String(), "<symbol>"; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := js.Global().String(), "<object>"; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := js.Global().Get("setTimeout").String(), "<function>"; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestInt(t *testing.T) {
	want := 42
	o := dummys.Get("someInt")
	if got := o.Int(); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	dummys.Set("otherInt", want)
	if got := dummys.Get("otherInt").Int(); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if !dummys.Get("someInt").Equal(dummys.Get("someInt")) {
		t.Errorf("same value not equal")
	}
	if got := dummys.Get("zero").Int(); got != 0 {
		t.Errorf("got %#v, want %#v", got, 0)
	}
}

func TestIntConversion(t *testing.T) {
	testIntConversion(t, 0)
	testIntConversion(t, 1)
	testIntConversion(t, -1)
	testIntConversion(t, 1<<20)
	testIntConversion(t, -1<<20)
	testIntConversion(t, 1<<40)
	testIntConversion(t, -1<<40)
	testIntConversion(t, 1<<60)
	testIntConversion(t, -1<<60)
}

func testIntConversion(t *testing.T, want int) {
	if got := js.ValueOf(want).Int(); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestFloat(t *testing.T) {
	want := 42.123
	o := dummys.Get("someFloat")
	if got := o.Float(); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	dummys.Set("otherFloat", want)
	if got := dummys.Get("otherFloat").Float(); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if !dummys.Get("someFloat").Equal(dummys.Get("someFloat")) {
		t.Errorf("same value not equal")
	}
}

func TestObject(t *testing.T) {
	if !dummys.Get("someArray").Equal(dummys.Get("someArray")) {
		t.Errorf("same value not equal")
	}

	// An object and its prototype should not be equal.
	proto := js.Global().Get("Object").Get("prototype")
	o := js.Global().Call("eval", "new Object()")
	if proto.Equal(o) {
		t.Errorf("object equals to its prototype")
	}
}

func TestFrozenObject(t *testing.T) {
	o := js.Global().Call("eval", "(function () { let o = new Object(); o.field = 5; Object.freeze(o); return o; })()")
	want := 5
	if got := o.Get("field").Int(); want != got {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestEqual(t *testing.T) {
	if !dummys.Get("someFloat").Equal(dummys.Get("someFloat")) {
		t.Errorf("same float is not equal")
	}
	if !dummys.Get("emptyObj").Equal(dummys.Get("emptyObj")) {
		t.Errorf("same object is not equal")
	}
	if dummys.Get("someFloat").Equal(dummys.Get("someInt")) {
		t.Errorf("different values are not unequal")
	}
}

func TestNaN(t *testing.T) {
	if !dummys.Get("NaN").IsNaN() {
		t.Errorf("JS NaN is not NaN")
	}
	if !js.ValueOf(math.NaN()).IsNaN() {
		t.Errorf("Go NaN is not NaN")
	}
	if dummys.Get("NaN").Equal(dummys.Get("NaN")) {
		t.Errorf("NaN is equal to NaN")
	}
}

func TestUndefined(t *testing.T) {
	if !js.Undefined().IsUndefined() {
		t.Errorf("undefined is not undefined")
	}
	if !js.Undefined().Equal(js.Undefined()) {
		t.Errorf("undefined is not equal to undefined")
	}
	if dummys.IsUndefined() {
		t.Errorf("object is undefined")
	}
	if js.Undefined().IsNull() {
		t.Errorf("undefined is null")
	}
	if dummys.Set("test", js.Undefined()); !dummys.Get("test").IsUndefined() {
		t.Errorf("could not set undefined")
	}
}

func TestNull(t *testing.T) {
	if !js.Null().IsNull() {
		t.Errorf("null is not null")
	}
	if !js.Null().Equal(js.Null()) {
		t.Errorf("null is not equal to null")
	}
	if dummys.IsNull() {
		t.Errorf("object is null")
	}
	if js.Null().IsUndefined() {
		t.Errorf("null is undefined")
	}
	if dummys.Set("test", js.Null()); !dummys.Get("test").IsNull() {
		t.Errorf("could not set null")
	}
	if dummys.Set("test", nil); !dummys.Get("test").IsNull() {
		t.Errorf("could not set nil")
	}
}

func TestLength(t *testing.T) {
	if got := dummys.Get("someArray").Length(); got != 3 {
		t.Errorf("got %#v, want %#v", got, 3)
	}
}

func TestGet(t *testing.T) {
	// positive cases get tested per type

	expectValueError(t, func() {
		dummys.Get("zero").Get("badField")
	})
}

func TestSet(t *testing.T) {
	// positive cases get tested per type

	expectValueError(t, func() {
		dummys.Get("zero").Set("badField", 42)
	})
}

func TestDelete(t *testing.T) {
	dummys.Set("test", 42)
	dummys.Delete("test")
	if dummys.Call("hasOwnProperty", "test").Bool() {
		t.Errorf("property still exists")
	}

	expectValueError(t, func() {
		dummys.Get("zero").Delete("badField")
	})
}

func TestIndex(t *testing.T) {
	if got := dummys.Get("someArray").Index(1).Int(); got != 42 {
		t.Errorf("got %#v, want %#v", got, 42)
	}

	expectValueError(t, func() {
		dummys.Get("zero").Index(1)
	})
}

func TestSetIndex(t *testing.T) {
	dummys.Get("someArray").SetIndex(2, 99)
	if got := dummys.Get("someArray").Index(2).Int(); got != 99 {
		t.Errorf("got %#v, want %#v", got, 99)
	}

	expectValueError(t, func() {
		dummys.Get("zero").SetIndex(2, 99)
	})
}

func TestCall(t *testing.T) {
	var i int64 = 40
	if got := dummys.Call("add", i, 2).Int(); got != 42 {
		t.Errorf("got %#v, want %#v", got, 42)
	}
	if got := dummys.Call("add", js.Global().Call("eval", "40"), 2).Int(); got != 42 {
		t.Errorf("got %#v, want %#v", got, 42)
	}

	expectPanic(t, func() {
		dummys.Call("zero")
	})
	expectValueError(t, func() {
		dummys.Get("zero").Call("badMethod")
	})
}

func TestInvoke(t *testing.T) {
	var i int64 = 40
	if got := dummys.Get("add").Invoke(i, 2).Int(); got != 42 {
		t.Errorf("got %#v, want %#v", got, 42)
	}

	expectValueError(t, func() {
		dummys.Get("zero").Invoke()
	})
}

func TestNew(t *testing.T) {
	if got := js.Global().Get("Array").New(42).Length(); got != 42 {
		t.Errorf("got %#v, want %#v", got, 42)
	}

	expectValueError(t, func() {
		dummys.Get("zero").New()
	})
}

func TestInstanceOf(t *testing.T) {
	someArray := js.Global().Get("Array").New()
	if got, want := someArray.InstanceOf(js.Global().Get("Array")), true; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := someArray.InstanceOf(js.Global().Get("Function")), false; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestType(t *testing.T) {
	if got, want := js.Undefined().Type(), js.TypeUndefined; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
	if got, want := js.Null().Type(), js.TypeNull; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
	if got, want := js.ValueOf(true).Type(), js.TypeBoolean; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
	if got, want := js.ValueOf(0).Type(), js.TypeNumber; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
	if got, want := js.ValueOf(42).Type(), js.TypeNumber; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
	if got, want := js.ValueOf("test").Type(), js.TypeString; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
	if got, want := js.Global().Get("Symbol").Invoke("test").Type(), js.TypeSymbol; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
	if got, want := js.Global().Get("Array").New().Type(), js.TypeObject; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
	if got, want := js.Global().Get("Array").Type(), js.TypeFunction; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

type object = map[string]any
type array = []any

func TestValueOf(t *testing.T) {
	a := js.ValueOf(array{0, array{0, 42, 0}, 0})
	if got := a.Index(1).Index(1).Int(); got != 42 {
		t.Errorf("got %v, want %v", got, 42)
	}

	o := js.ValueOf(object{"x": object{"y": 42}})
	if got := o.Get("x").Get("y").Int(); got != 42 {
		t.Errorf("got %v, want %v", got, 42)
	}
}

func TestZeroValue(t *testing.T) {
	var v js.Value
	if !v.IsUndefined() {
		t.Error("zero js.Value is not js.Undefined()")
	}
}

func TestFuncOf(t *testing.T) {
	c := make(chan struct{})
	cb := js.FuncOf(func(this js.Value, args []js.Value) any {
		if got := args[0].Int(); got != 42 {
			t.Errorf("got %#v, want %#v", got, 42)
		}
		c <- struct{}{}
		return nil
	})
	defer cb.Release()
	js.Global().Call("setTimeout", cb, 0, 42)
	<-c
}

func TestInvokeFunction(t *testing.T) {
	called := false
	cb := js.FuncOf(func(this js.Value, args []js.Value) any {
		cb2 := js.FuncOf(func(this js.Value, args []js.Value) any {
			called = true
			return 42
		})
		defer cb2.Release()
		return cb2.Invoke()
	})
	defer cb.Release()
	if got := cb.Invoke().Int(); got != 42 {
		t.Errorf("got %#v, want %#v", got, 42)
	}
	if !called {
		t.Error("function not called")
	}
}

func TestInterleavedFunctions(t *testing.T) {
	c1 := make(chan struct{})
	c2 := make(chan struct{})

	js.Global().Get("setTimeout").Invoke(js.FuncOf(func(this js.Value, args []js.Value) any {
		c1 <- struct{}{}
		<-c2
		return nil
	}), 0)

	<-c1
	c2 <- struct{}{}
	// this goroutine is running, but the callback of setTimeout did not return yet, invoke another function now
	f := js.FuncOf(func(this js.Value, args []js.Value) any {
		return nil
	})
	f.Invoke()
}

func ExampleFuncOf() {
	var cb js.Func
	cb = js.FuncOf(func(this js.Value, args []js.Value) any {
		fmt.Println("button clicked")
		cb.Release() // release the function if the button will not be clicked again
		return nil
	})
	js.Global().Get("document").Call("getElementById", "myButton").Call("addEventListener", "click", cb)
}

// See
// - https://developer.mozilla.org/en-US/docs/Glossary/Truthy
// - https://stackoverflow.com/questions/19839952/all-falsey-values-in-javascript/19839953#19839953
// - http://www.ecma-international.org/ecma-262/5.1/#sec-9.2
func TestTruthy(t *testing.T) {
	want := true
	for _, key := range []string{
		"someBool", "someString", "someInt", "someFloat", "someArray", "someDate",
		"stringZero", // "0" is truthy
		"add",        // functions are truthy
		"emptyObj", "emptyArray", "Infinity", "NegInfinity",
		// All objects are truthy, even if they're Number(0) or Boolean(false).
		"objNumber0", "objBooleanFalse",
	} {
		if got := dummys.Get(key).Truthy(); got != want {
			t.Errorf("%s: got %#v, want %#v", key, got, want)
		}
	}

	want = false
	if got := dummys.Get("zero").Truthy(); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got := dummys.Get("NaN").Truthy(); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got := js.ValueOf("").Truthy(); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got := js.Null().Truthy(); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got := js.Undefined().Truthy(); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func expectValueError(t *testing.T, fn func()) {
	defer func() {
		err := recover()
		if _, ok := err.(*js.ValueError); !ok {
			t.Errorf("expected *js.ValueError, got %T", err)
		}
	}()
	fn()
}

func expectPanic(t *testing.T, fn func()) {
	defer func() {
		err := recover()
		if err == nil {
			t.Errorf("expected panic")
		}
	}()
	fn()
}

var copyTests = []struct {
	srcLen  int
	dstLen  int
	copyLen int
}{
	{5, 3, 3},
	{3, 5, 3},
	{0, 0, 0},
}

func TestCopyBytesToGo(t *testing.T) {
	for _, tt := range copyTests {
		t.Run(fmt.Sprintf("%d-to-%d", tt.srcLen, tt.dstLen), func(t *testing.T) {
			src := js.Global().Get("Uint8Array").New(tt.srcLen)
			if tt.srcLen >= 2 {
				src.SetIndex(1, 42)
			}
			dst := make([]byte, tt.dstLen)

			if got, want := js.CopyBytesToGo(dst, src), tt.copyLen; got != want {
				t.Errorf("copied %d, want %d", got, want)
			}
			if tt.dstLen >= 2 {
				if got, want := int(dst[1]), 42; got != want {
					t.Errorf("got %d, want %d", got, want)
				}
			}
		})
	}
}

func TestCopyBytesToJS(t *testing.T) {
	for _, tt := range copyTests {
		t.Run(fmt.Sprintf("%d-to-%d", tt.srcLen, tt.dstLen), func(t *testing.T) {
			src := make([]byte, tt.srcLen)
			if tt.srcLen >= 2 {
				src[1] = 42
			}
			dst := js.Global().Get("Uint8Array").New(tt.dstLen)

			if got, want := js.CopyBytesToJS(dst, src), tt.copyLen; got != want {
				t.Errorf("copied %d, want %d", got, want)
			}
			if tt.dstLen >= 2 {
				if got, want := dst.Index(1).Int(), 42; got != want {
					t.Errorf("got %d, want %d", got, want)
				}
			}
		})
	}
}

func TestGarbageCollection(t *testing.T) {
	before := js.JSGo.Get("_values").Length()
	for i := 0; i < 1000; i++ {
		_ = js.Global().Get("Object").New().Call("toString").String()
		runtime.GC()
	}
	after := js.JSGo.Get("_values").Length()
	if after-before > 500 {
		t.Errorf("garbage collection ineffective")
	}
}

// This table is used for allocation tests. We expect a specific allocation
// behavior to be seen, depending on the number of arguments applied to various
// JavaScript functions.
// Note: All JavaScript functions return a JavaScript array, which will cause
// one allocation to be created to track the Value.gcPtr for the Value finalizer.
var allocTests = []struct {
	argLen   int // The number of arguments to use for the syscall
	expected int // The expected number of allocations
}{
	// For less than or equal to 16 arguments, we expect 1 allocation:
	// - makeValue new(ref)
	{0, 1},
	{2, 1},
	{15, 1},
	{16, 1},
	// For greater than 16 arguments, we expect 3 allocation:
	// - makeValue: new(ref)
	// - makeArgSlices: argVals = make([]Value, size)
	// - makeArgSlices: argRefs = make([]ref, size)
	{17, 3},
	{32, 3},
	{42, 3},
}

// TestCallAllocations ensures the correct allocation profile for Value.Call
func TestCallAllocations(t *testing.T) {
	for _, test := range allocTests {
		args := make([]any, test.argLen)

		tmpArray := js.Global().Get("Array").New(0)
		numAllocs := testing.AllocsPerRun(100, func() {
			tmpArray.Call("concat", args...)
		})

		if numAllocs != float64(test.expected) {
			t.Errorf("got numAllocs %#v, want %#v", numAllocs, test.expected)
		}
	}
}

// TestInvokeAllocations ensures the correct allocation profile for Value.Invoke
func TestInvokeAllocations(t *testing.T) {
	for _, test := range allocTests {
		args := make([]any, test.argLen)

		tmpArray := js.Global().Get("Array").New(0)
		concatFunc := tmpArray.Get("concat").Call("bind", tmpArray)
		numAllocs := testing.AllocsPerRun(100, func() {
			concatFunc.Invoke(args...)
		})

		if numAllocs != float64(test.expected) {
			t.Errorf("got numAllocs %#v, want %#v", numAllocs, test.expected)
		}
	}
}

// TestNewAllocations ensures the correct allocation profile for Value.New
func TestNewAllocations(t *testing.T) {
	arrayConstructor := js.Global().Get("Array")

	for _, test := range allocTests {
		args := make([]any, test.argLen)

		numAllocs := testing.AllocsPerRun(100, func() {
			arrayConstructor.New(args...)
		})

		if numAllocs != float64(test.expected) {
			t.Errorf("got numAllocs %#v, want %#v", numAllocs, test.expected)
		}
	}
}

// BenchmarkDOM is a simple benchmark which emulates a webapp making DOM operations.
// It creates a div, and sets its id. Then searches by that id and sets some data.
// Finally it removes that div.
func BenchmarkDOM(b *testing.B) {
	document := js.Global().Get("document")
	if document.IsUndefined() {
		b.Skip("Not a browser environment. Skipping.")
	}
	const data = "someString"
	for i := 0; i < b.N; i++ {
		div := document.Call("createElement", "div")
		div.Call("setAttribute", "id", "myDiv")
		document.Get("body").Call("appendChild", div)
		myDiv := document.Call("getElementById", "myDiv")
		myDiv.Set("innerHTML", data)

		if got, want := myDiv.Get("innerHTML").String(), data; got != want {
			b.Errorf("got %s, want %s", got, want)
		}
		document.Get("body").Call("removeChild", div)
	}
}

func TestGlobal(t *testing.T) {
	ident := js.FuncOf(func(this js.Value, args []js.Value) any {
		return args[0]
	})
	defer ident.Release()

	if got := ident.Invoke(js.Global()); !got.Equal(js.Global()) {
		t.Errorf("got %#v, want %#v", got, js.Global())
	}
}

"""



```