Response:
Let's break down the thought process for analyzing the provided Go code and generating the Chinese response.

1. **Understanding the Goal:** The request asks for a description of the Go code's functionality, potential implementation details, examples, error-prone areas, and handling of command-line arguments. The core task is to explain what `runtime.Pinner` does and how the test file verifies its behavior.

2. **Initial Code Scan (Keywords and Structure):**
   -  Look for key terms: `runtime.Pinner`, `Pin`, `Unpin`, `IsPinned`, `GetPinCounter`, `CgoCheckPointer`, `SetFinalizer`, `GC`, `panic`.
   -  Notice the import of `runtime`, `testing`, `time`, and `unsafe`. This immediately suggests interaction with Go's runtime environment, unit testing, timing mechanisms, and unsafe memory operations.
   -  Observe the test function names, like `TestPinnerSimple`, `TestPinnerPinKeepsAliveAndReleases`, etc. These give strong hints about the tested functionalities.
   -  Identify the `obj` and `objWith` struct definitions. They seem to be used as sample objects for pinning.
   -  Recognize the global variables like `globalUintptr`, `globalPtrToObj`, etc. These are likely used to test pinning of global objects.

3. **Core Functionality Identification (`runtime.Pinner`):** Based on the method names (`Pin`, `Unpin`, `IsPinned`), the primary function of `runtime.Pinner` appears to be controlling whether a Go object's memory can be moved by the garbage collector (GC). "Pinning" likely means preventing the GC from relocating the object.

4. **Analyzing Individual Test Functions:**  Go through each test function and deduce its specific purpose:
   - `TestPinnerSimple`: Basic pinning and unpinning, checking `IsPinned`.
   - `TestPinnerPinKeepsAliveAndReleases`: Verifies that pinning prevents garbage collection and unpinning allows it. The `SetFinalizer` and `GC` calls are key here.
   - `TestPinnerMultiplePinsSame`: Checks the behavior of pinning the same object multiple times and the associated pin counter.
   - `TestPinnerTwoPinner`:  Explores the interaction of multiple `Pinner` instances on the same object.
   - `TestPinnerPinZerosizeObj`:  Tests pinning an empty struct.
   - `TestPinnerPinGlobalPtr`:  Confirms pinning of global variables.
   - `TestPinnerPinTinyObj`:  Tests pinning of small objects.
   - `TestPinnerInterface`:  Examines pinning interfaces and the underlying objects.
   - `TestPinnerPinNonPtrPanics`:  Checks that pinning non-pointer types causes a panic.
   - `TestPinnerReuse`:  Relates pinning to `CgoCheckPointer`. This is a significant clue about `Pinner`'s use case (interaction with C/C++ code).
   - `TestPinnerEmptyUnpin`:  Verifies that calling `Unpin` without prior `Pin` is safe.
   - `TestPinnerLeakPanics`:  Tests the behavior when a pinned object isn't unpinned, suggesting a mechanism for detecting such leaks.
   - Tests involving `CgoCheckPointer`:  These strongly indicate that `Pinner` is related to ensuring memory safety when Go code interacts with C/C++ via Cgo. Pinning prevents the GC from moving memory that C code might be accessing.
   - Benchmark functions: Measure the performance of pinning and unpinning operations under different scenarios.

5. **Inferring the Go Feature:** Based on the tests, especially those involving `CgoCheckPointer`, the most likely Go feature being implemented is **facilitating safe interaction between Go and C/C++ code via Cgo**. Pinning ensures that memory passed to C code remains at a fixed address, preventing issues if the Go GC moves it.

6. **Generating the Code Example:** Create a simple example demonstrating the core functionality: pinning an object, passing its address to a (hypothetical) C function, and then unpinning. This illustrates the main use case. Include comments explaining each step.

7. **Hypothesizing Input and Output (for Code Reasoning):**  For the `TestPinnerMultiplePinsSame` example, specify the input (pinning the same object 100 times) and the expected output (the pin counter being 99). This demonstrates the counter mechanism.

8. **Command-Line Arguments:** Review the code for any direct use of `os.Args` or `flag` package. Since none is present, state that no command-line arguments are directly processed in *this specific test file*. However, acknowledge that the `cgocheck=1` build tag is *required* for some tests to pass, as highlighted by the `assertCgoCheckPanics` function.

9. **Common Mistakes:**  Think about how a user might misuse the `Pinner`. Forgetting to call `Unpin` is a prime example, leading to memory leaks or unexpected behavior if the object is expected to be garbage collected. The leak panic test confirms this. Also, trying to pin non-pointer types would be an error.

10. **Structuring the Response:** Organize the information logically:
    - Start with the overall functionality.
    - Explain the inferred Go feature.
    - Provide a code example.
    - Detail code reasoning with input/output.
    - Discuss command-line arguments (and the relevant build tag).
    - List potential mistakes.
    - Use clear and concise Chinese.

11. **Refinement and Review:** Read through the generated response to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For instance, explicitly mentioning that `cgocheck=1` is crucial for the `CgoCheckPointer` tests is important.

By following these steps, we can systematically analyze the code and produce a comprehensive and informative answer to the original request. The key is to combine code inspection with an understanding of Go's runtime and Cgo interaction.
这段代码是 Go 语言运行时（`runtime` 包）中关于 `Pinner` 的测试代码。`Pinner` 的主要功能是**临时阻止 Go 语言的垃圾回收器（GC）移动某个对象的内存地址**，这通常用于与 C/C++ 代码（通过 Cgo）交互的场景，以确保传递给 C/C++ 的指针在 C/C++ 使用期间保持有效。

以下是代码中各个测试用例的功能列表：

* **`TestPinnerSimple`**: 测试基本的 Pin 和 Unpin 操作，验证对象在 Pin 后被标记为 pinned，Unpin 后不再被标记。
* **`TestPinnerPinKeepsAliveAndReleases`**: 测试 `Pin` 方法可以防止对象被过早地垃圾回收，而 `Unpin` 后对象可以被回收。使用了 `runtime.SetFinalizer` 来观察对象的回收时机。
* **`TestPinnerMultiplePinsSame`**: 测试多次 Pin 同一个对象，验证内部的引用计数机制是否正确。
* **`TestPinnerTwoPinner`**: 测试使用两个不同的 `Pinner` 实例 Pin 同一个对象，验证引用计数机制在多个 `Pinner` 之间的行为。
* **`TestPinnerPinZerosizeObj`**: 测试 Pin 一个零大小的对象是否正常工作。
* **`TestPinnerPinGlobalPtr`**: 测试 Pin 全局变量的指针是否正常工作。
* **`TestPinnerPinTinyObj`**: 测试 Pin 多个小对象，并验证其 Pin 计数器。
* **`TestPinnerInterface`**: 测试 Pin 接口类型以及接口指向的实际对象时的行为。
* **`TestPinnerPinNonPtrPanics`**: 测试尝试 Pin 非指针类型的值是否会触发 panic。
* **`TestPinnerReuse`**:  测试 Pin 和 Unpin 后，对象及其指针能否安全地用于 Cgo 调用（通过 `runtime.CgoCheckPointer` 检查）。
* **`TestPinnerEmptyUnpin`**: 测试在没有 Pin 的情况下调用 `Unpin` 是否安全。
* **`TestPinnerLeakPanics`**: 测试当一个对象被 Pin 但未被 Unpin 时，是否会触发 panic (如果配置了 `runtime.SetPinnerLeakPanic`)。
* **`TestPinnerCgoCheckPtr2Ptr`**, **`TestPinnerCgoCheckPtr2UnsafePtr`**, **`TestPinnerCgoCheckPtr2UnknownPtr`**, **`TestPinnerCgoCheckInterface`**, **`TestPinnerCgoCheckSlice`**, **`TestPinnerCgoCheckString`**, **`TestPinnerCgoCheckPinned2UnpinnedPanics`**, **`TestPinnerCgoCheckPtr2Pinned2Unpinned`**: 这些测试用例都专注于测试 `Pinner` 与 Cgo 的交互，验证在 Pin 对象后，指向该对象的指针（包括多级指针、unsafe.Pointer、接口、切片、字符串等）能否通过 `runtime.CgoCheckPointer` 的检查。`runtime.CgoCheckPointer` 用于在 Cgo 调用前后检查 Go 内存的安全性。
* **`BenchmarkPinner...`**:  这些是基准测试，用于衡量 `Pinner` 的 `Pin` 和 `Unpin` 操作的性能。

**`runtime.Pinner` 功能的 Go 代码示例：**

假设我们有一个需要传递给 C 代码的 Go 结构体：

```go
package main

/*
#include <stdlib.h>

typedef struct {
    long long x;
    long long y;
} c_obj;

void process_c_obj(c_obj* obj) {
    // 在 C 代码中使用 obj
    obj->x += 1;
    obj->y *= 2;
}
*/
import "C"
import "runtime"
import "unsafe"

type GoObj struct {
	X int64
	Y int64
}

func main() {
	goObj := &GoObj{X: 10, Y: 20}
	var pinner runtime.Pinner
	pinner.Pin(goObj) // Pin GoObj，防止 GC 移动其内存

	cObjPtr := (*C.c_obj)(unsafe.Pointer(goObj)) // 将 GoObj 的指针转换为 C 结构体指针
	C.process_c_obj(cObjPtr)                   // 调用 C 函数处理数据

	pinner.Unpin() // 取消 Pin，允许 GC 移动或回收 goObj

	println("GoObj.X:", goObj.X) // 输出: GoObj.X: 11
	println("GoObj.Y:", goObj.Y) // 输出: GoObj.Y: 40
}
```

**假设的输入与输出（以 `TestPinnerMultiplePinsSame` 为例）：**

**假设输入：**

1. 创建一个新的 `obj` 实例。
2. 使用同一个 `Pinner` 实例，对该 `obj` 实例调用 `Pin` 方法 100 次。

**预期输出：**

1. 在第一次 `Pin` 调用后，`runtime.IsPinned(addr)` 返回 `true`。
2. 在连续的 `Pin` 调用中，`runtime.IsPinned(addr)` 始终返回 `true`。
3. 调用 `runtime.GetPinCounter(addr)` 应该返回一个非 nil 的指针，并且该指针指向的值为 99（第一次 Pin 不会创建计数器，后续的 Pin 会增加计数）。
4. 调用 `pinner.Unpin()` 后，`runtime.IsPinned(addr)` 返回 `false`。
5. 调用 `runtime.GetPinCounter(addr)` 返回 `nil`，表示 Pin 计数器被删除。

**命令行参数的具体处理：**

这段代码本身是一个测试文件，不直接处理命令行参数。但是，它间接地依赖于 Go 的测试框架。

* 运行这些测试通常使用 `go test ./runtime` 命令。
* 其中一些测试（特别是涉及到 `runtime.CgoCheckPointer` 的测试）**强烈依赖于使用 `cgocheck=1` 构建标签**。这意味着在运行这些测试时，你需要使用如下命令：

  ```bash
  go test -tags=cgocheck=1 ./runtime
  ```

  或者，更常见的是，当你进行 Cgo 开发并希望启用 Cgo 的指针检查时，你会设置环境变量 `GODEBUG=cgocheck=1`。当 `cgocheck=1` 时，`runtime.CgoCheckPointer` 会执行更严格的检查，如果发现传递给 Cgo 的指针指向的 Go 内存可能存在问题（例如，指向了未 Pin 的可移动对象），则会触发 panic。

**使用者易犯错的点：**

1. **忘记调用 `Unpin`**: 这是最常见的错误。如果一个对象被 `Pin` 了但忘记 `Unpin`，那么这个对象将永远不会被垃圾回收器移动。在某些情况下，这可能导致内存泄漏（如果对象本身不再使用，但由于被 Pin 而无法回收）。在测试用例 `TestPinnerLeakPanics` 中就展示了当配置了 `runtime.SetPinnerLeakPanic` 时，忘记 `Unpin` 会导致 panic。

   ```go
   func main() {
       var pinner runtime.Pinner
       obj := new(struct{})
       pinner.Pin(obj)
       // ... 使用 obj 的指针传递给 C 代码 ...
       // 忘记调用 pinner.Unpin()
   }
   ```

2. **在错误的生命周期使用 `Pinner`**: `Pinner` 的设计是用于临时固定对象的内存。不应该在对象的整个生命周期都保持 Pin 状态，这会影响垃圾回收器的效率。

3. **不理解 `cgocheck` 的作用**:  开发者可能会忽略 `cgocheck=1` 构建标签的重要性。在与 Cgo 交互时，如果没有启用 `cgocheck`，一些潜在的内存安全问题可能不会被及时发现。`assertCgoCheckPanics` 函数的存在就说明了这些测试依赖于 `cgocheck` 来触发 panic。

   例如，以下代码在没有启用 `cgocheck` 的情况下可能不会 panic，但启用后会 panic：

   ```go
   package main

   /*
   #include <stdlib.h>
   */
   import "C"
   import "runtime"
   import "unsafe"

   type MyObject struct {
       data int
   }

   func main() {
       obj := &MyObject{data: 10}
       objPtr := unsafe.Pointer(obj)

       runtime.CgoCheckPointer(objPtr, nil) // 如果 obj 没有被 Pin 且 cgocheck=1，这里会 panic
   }
   ```

总而言之，`go/src/runtime/pinner_test.go` 详细测试了 `runtime.Pinner` 的各种功能和边界情况，特别是它在与 Cgo 交互时的内存安全保证。理解这些测试用例有助于开发者正确地使用 `Pinner`，避免常见的错误。

### 提示词
```
这是路径为go/src/runtime/pinner_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime_test

import (
	"runtime"
	"testing"
	"time"
	"unsafe"
)

type obj struct {
	x int64
	y int64
	z int64
}

type objWith[T any] struct {
	x int64
	y int64
	z int64
	o T
}

var (
	globalUintptr                uintptr
	globalPtrToObj               = &obj{}
	globalPtrToObjWithPtr        = &objWith[*uintptr]{}
	globalPtrToRuntimeObj        = func() *obj { return &obj{} }()
	globalPtrToRuntimeObjWithPtr = func() *objWith[*uintptr] { return &objWith[*uintptr]{} }()
)

func assertDidPanic(t *testing.T) {
	if recover() == nil {
		t.Fatal("did not panic")
	}
}

func assertCgoCheckPanics(t *testing.T, p any) {
	defer func() {
		if recover() == nil {
			t.Fatal("cgoCheckPointer() did not panic, make sure the tests run with cgocheck=1")
		}
	}()
	runtime.CgoCheckPointer(p, true)
}

func TestPinnerSimple(t *testing.T) {
	var pinner runtime.Pinner
	p := new(obj)
	addr := unsafe.Pointer(p)
	if runtime.IsPinned(addr) {
		t.Fatal("already marked as pinned")
	}
	pinner.Pin(p)
	if !runtime.IsPinned(addr) {
		t.Fatal("not marked as pinned")
	}
	if runtime.GetPinCounter(addr) != nil {
		t.Fatal("pin counter should not exist")
	}
	pinner.Unpin()
	if runtime.IsPinned(addr) {
		t.Fatal("still marked as pinned")
	}
}

func TestPinnerPinKeepsAliveAndReleases(t *testing.T) {
	var pinner runtime.Pinner
	p := new(obj)
	done := make(chan struct{})
	runtime.SetFinalizer(p, func(any) {
		done <- struct{}{}
	})
	pinner.Pin(p)
	p = nil
	runtime.GC()
	runtime.GC()
	select {
	case <-done:
		t.Fatal("Pin() didn't keep object alive")
	case <-time.After(time.Millisecond * 10):
		break
	}
	pinner.Unpin()
	runtime.GC()
	runtime.GC()
	select {
	case <-done:
		break
	case <-time.After(time.Second):
		t.Fatal("Unpin() didn't release object")
	}
}

func TestPinnerMultiplePinsSame(t *testing.T) {
	const N = 100
	var pinner runtime.Pinner
	p := new(obj)
	addr := unsafe.Pointer(p)
	if runtime.IsPinned(addr) {
		t.Fatal("already marked as pinned")
	}
	for i := 0; i < N; i++ {
		pinner.Pin(p)
	}
	if !runtime.IsPinned(addr) {
		t.Fatal("not marked as pinned")
	}
	if cnt := runtime.GetPinCounter(addr); cnt == nil || *cnt != N-1 {
		t.Fatalf("pin counter incorrect: %d", *cnt)
	}
	pinner.Unpin()
	if runtime.IsPinned(addr) {
		t.Fatal("still marked as pinned")
	}
	if runtime.GetPinCounter(addr) != nil {
		t.Fatal("pin counter was not deleted")
	}
}

func TestPinnerTwoPinner(t *testing.T) {
	var pinner1, pinner2 runtime.Pinner
	p := new(obj)
	addr := unsafe.Pointer(p)
	if runtime.IsPinned(addr) {
		t.Fatal("already marked as pinned")
	}
	pinner1.Pin(p)
	if !runtime.IsPinned(addr) {
		t.Fatal("not marked as pinned")
	}
	if runtime.GetPinCounter(addr) != nil {
		t.Fatal("pin counter should not exist")
	}
	pinner2.Pin(p)
	if !runtime.IsPinned(addr) {
		t.Fatal("not marked as pinned")
	}
	if cnt := runtime.GetPinCounter(addr); cnt == nil || *cnt != 1 {
		t.Fatalf("pin counter incorrect: %d", *cnt)
	}
	pinner1.Unpin()
	if !runtime.IsPinned(addr) {
		t.Fatal("not marked as pinned")
	}
	if runtime.GetPinCounter(addr) != nil {
		t.Fatal("pin counter should not exist")
	}
	pinner2.Unpin()
	if runtime.IsPinned(addr) {
		t.Fatal("still marked as pinned")
	}
	if runtime.GetPinCounter(addr) != nil {
		t.Fatal("pin counter was not deleted")
	}
}

func TestPinnerPinZerosizeObj(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	p := new(struct{})
	pinner.Pin(p)
	if !runtime.IsPinned(unsafe.Pointer(p)) {
		t.Fatal("not marked as pinned")
	}
}

func TestPinnerPinGlobalPtr(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	pinner.Pin(globalPtrToObj)
	pinner.Pin(globalPtrToObjWithPtr)
	pinner.Pin(globalPtrToRuntimeObj)
	pinner.Pin(globalPtrToRuntimeObjWithPtr)
}

func TestPinnerPinTinyObj(t *testing.T) {
	var pinner runtime.Pinner
	const N = 64
	var addr [N]unsafe.Pointer
	for i := 0; i < N; i++ {
		p := new(bool)
		addr[i] = unsafe.Pointer(p)
		pinner.Pin(p)
		pinner.Pin(p)
		if !runtime.IsPinned(addr[i]) {
			t.Fatalf("not marked as pinned: %d", i)
		}
		if cnt := runtime.GetPinCounter(addr[i]); cnt == nil || *cnt == 0 {
			t.Fatalf("pin counter incorrect: %d, %d", *cnt, i)
		}
	}
	pinner.Unpin()
	for i := 0; i < N; i++ {
		if runtime.IsPinned(addr[i]) {
			t.Fatal("still marked as pinned")
		}
		if runtime.GetPinCounter(addr[i]) != nil {
			t.Fatal("pin counter should not exist")
		}
	}
}

func TestPinnerInterface(t *testing.T) {
	var pinner runtime.Pinner
	o := new(obj)
	ifc := any(o)
	pinner.Pin(&ifc)
	if !runtime.IsPinned(unsafe.Pointer(&ifc)) {
		t.Fatal("not marked as pinned")
	}
	if runtime.IsPinned(unsafe.Pointer(o)) {
		t.Fatal("marked as pinned")
	}
	pinner.Unpin()
	pinner.Pin(ifc)
	if !runtime.IsPinned(unsafe.Pointer(o)) {
		t.Fatal("not marked as pinned")
	}
	if runtime.IsPinned(unsafe.Pointer(&ifc)) {
		t.Fatal("marked as pinned")
	}
	pinner.Unpin()
}

func TestPinnerPinNonPtrPanics(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	var i int
	defer assertDidPanic(t)
	pinner.Pin(i)
}

func TestPinnerReuse(t *testing.T) {
	var pinner runtime.Pinner
	p := new(obj)
	p2 := &p
	assertCgoCheckPanics(t, p2)
	pinner.Pin(p)
	runtime.CgoCheckPointer(p2, true)
	pinner.Unpin()
	assertCgoCheckPanics(t, p2)
	pinner.Pin(p)
	runtime.CgoCheckPointer(p2, true)
	pinner.Unpin()
}

func TestPinnerEmptyUnpin(t *testing.T) {
	var pinner runtime.Pinner
	pinner.Unpin()
	pinner.Unpin()
}

func TestPinnerLeakPanics(t *testing.T) {
	old := runtime.GetPinnerLeakPanic()
	func() {
		defer assertDidPanic(t)
		old()
	}()
	done := make(chan struct{})
	runtime.SetPinnerLeakPanic(func() {
		done <- struct{}{}
	})
	func() {
		var pinner runtime.Pinner
		p := new(obj)
		pinner.Pin(p)
	}()
	runtime.GC()
	runtime.GC()
	select {
	case <-done:
		break
	case <-time.After(time.Second):
		t.Fatal("leak didn't make GC to panic")
	}
	runtime.SetPinnerLeakPanic(old)
}

func TestPinnerCgoCheckPtr2Ptr(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	p := new(obj)
	p2 := &objWith[*obj]{o: p}
	assertCgoCheckPanics(t, p2)
	pinner.Pin(p)
	runtime.CgoCheckPointer(p2, true)
}

func TestPinnerCgoCheckPtr2UnsafePtr(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	p := unsafe.Pointer(new(obj))
	p2 := &objWith[unsafe.Pointer]{o: p}
	assertCgoCheckPanics(t, p2)
	pinner.Pin(p)
	runtime.CgoCheckPointer(p2, true)
}

func TestPinnerCgoCheckPtr2UnknownPtr(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	p := unsafe.Pointer(new(obj))
	p2 := &p
	func() {
		defer assertDidPanic(t)
		runtime.CgoCheckPointer(p2, nil)
	}()
	pinner.Pin(p)
	runtime.CgoCheckPointer(p2, nil)
}

func TestPinnerCgoCheckInterface(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	var ifc any
	var o obj
	ifc = &o
	p := &ifc
	assertCgoCheckPanics(t, p)
	pinner.Pin(&o)
	runtime.CgoCheckPointer(p, true)
}

func TestPinnerCgoCheckSlice(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	sl := []int{1, 2, 3}
	assertCgoCheckPanics(t, &sl)
	pinner.Pin(&sl[0])
	runtime.CgoCheckPointer(&sl, true)
}

func TestPinnerCgoCheckString(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	b := []byte("foobar")
	str := unsafe.String(&b[0], 6)
	assertCgoCheckPanics(t, &str)
	pinner.Pin(&b[0])
	runtime.CgoCheckPointer(&str, true)
}

func TestPinnerCgoCheckPinned2UnpinnedPanics(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	p := new(obj)
	p2 := &objWith[*obj]{o: p}
	assertCgoCheckPanics(t, p2)
	pinner.Pin(p2)
	assertCgoCheckPanics(t, p2)
}

func TestPinnerCgoCheckPtr2Pinned2Unpinned(t *testing.T) {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	p := new(obj)
	p2 := &objWith[*obj]{o: p}
	p3 := &objWith[*objWith[*obj]]{o: p2}
	assertCgoCheckPanics(t, p2)
	assertCgoCheckPanics(t, p3)
	pinner.Pin(p2)
	assertCgoCheckPanics(t, p2)
	assertCgoCheckPanics(t, p3)
	pinner.Pin(p)
	runtime.CgoCheckPointer(p2, true)
	runtime.CgoCheckPointer(p3, true)
}

func BenchmarkPinnerPinUnpinBatch(b *testing.B) {
	const Batch = 1000
	var data [Batch]*obj
	for i := 0; i < Batch; i++ {
		data[i] = new(obj)
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		var pinner runtime.Pinner
		for i := 0; i < Batch; i++ {
			pinner.Pin(data[i])
		}
		pinner.Unpin()
	}
}

func BenchmarkPinnerPinUnpinBatchDouble(b *testing.B) {
	const Batch = 1000
	var data [Batch]*obj
	for i := 0; i < Batch; i++ {
		data[i] = new(obj)
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		var pinner runtime.Pinner
		for i := 0; i < Batch; i++ {
			pinner.Pin(data[i])
			pinner.Pin(data[i])
		}
		pinner.Unpin()
	}
}

func BenchmarkPinnerPinUnpinBatchTiny(b *testing.B) {
	const Batch = 1000
	var data [Batch]*bool
	for i := 0; i < Batch; i++ {
		data[i] = new(bool)
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		var pinner runtime.Pinner
		for i := 0; i < Batch; i++ {
			pinner.Pin(data[i])
		}
		pinner.Unpin()
	}
}

func BenchmarkPinnerPinUnpin(b *testing.B) {
	p := new(obj)
	for n := 0; n < b.N; n++ {
		var pinner runtime.Pinner
		pinner.Pin(p)
		pinner.Unpin()
	}
}

func BenchmarkPinnerPinUnpinTiny(b *testing.B) {
	p := new(bool)
	for n := 0; n < b.N; n++ {
		var pinner runtime.Pinner
		pinner.Pin(p)
		pinner.Unpin()
	}
}

func BenchmarkPinnerPinUnpinDouble(b *testing.B) {
	p := new(obj)
	for n := 0; n < b.N; n++ {
		var pinner runtime.Pinner
		pinner.Pin(p)
		pinner.Pin(p)
		pinner.Unpin()
	}
}

func BenchmarkPinnerPinUnpinParallel(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		p := new(obj)
		for pb.Next() {
			var pinner runtime.Pinner
			pinner.Pin(p)
			pinner.Unpin()
		}
	})
}

func BenchmarkPinnerPinUnpinParallelTiny(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		p := new(bool)
		for pb.Next() {
			var pinner runtime.Pinner
			pinner.Pin(p)
			pinner.Unpin()
		}
	})
}

func BenchmarkPinnerPinUnpinParallelDouble(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		p := new(obj)
		for pb.Next() {
			var pinner runtime.Pinner
			pinner.Pin(p)
			pinner.Pin(p)
			pinner.Unpin()
		}
	})
}

func BenchmarkPinnerIsPinnedOnPinned(b *testing.B) {
	var pinner runtime.Pinner
	ptr := new(obj)
	pinner.Pin(ptr)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		runtime.IsPinned(unsafe.Pointer(ptr))
	}
	pinner.Unpin()
}

func BenchmarkPinnerIsPinnedOnUnpinned(b *testing.B) {
	ptr := new(obj)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		runtime.IsPinned(unsafe.Pointer(ptr))
	}
}

func BenchmarkPinnerIsPinnedOnPinnedParallel(b *testing.B) {
	var pinner runtime.Pinner
	ptr := new(obj)
	pinner.Pin(ptr)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			runtime.IsPinned(unsafe.Pointer(ptr))
		}
	})
	pinner.Unpin()
}

func BenchmarkPinnerIsPinnedOnUnpinnedParallel(b *testing.B) {
	ptr := new(obj)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			runtime.IsPinned(unsafe.Pointer(ptr))
		}
	})
}

// const string data is not in span.
func TestPinnerConstStringData(t *testing.T) {
	var pinner runtime.Pinner
	str := "test-const-string"
	p := unsafe.StringData(str)
	addr := unsafe.Pointer(p)
	if !runtime.IsPinned(addr) {
		t.Fatal("not marked as pinned")
	}
	pinner.Pin(p)
	pinner.Unpin()
	if !runtime.IsPinned(addr) {
		t.Fatal("not marked as pinned")
	}
}
```