Response:
Let's break down the thought process for summarizing the given Go code snippet.

1. **Understand the Goal:** The request asks for a summary of the functionality of the provided Go code, which is a part of `go/src/runtime/syscall_windows_test.go`. It's crucial to recognize this is a *test* file. Therefore, the primary function is to test the behavior of the `syscall` package on Windows.

2. **Initial Scan and Keyword Identification:** Quickly read through the code, looking for recurring keywords and patterns. Key terms that jump out are:
    * `Test...`: This strongly indicates the presence of unit tests.
    * `syscall`:  This confirms the code is interacting with the operating system's system calls.
    * `windows`: This specifies the target operating system.
    * `DLL`, `LoadDLL`, `FindProc`, `Call`: These suggest interaction with Dynamic Link Libraries (DLLs), a fundamental concept on Windows.
    * `Callback`, `NewCallback`, `NewCallbackCDecl`: These point to testing the ability to call Go functions from Windows APIs (callbacks).
    * Specific Windows API names like `UnionRect`, `wsprintfA`, `EnumWindows`, `VerifyVersionInfoW`, `RegisterClassExW`, `OutputDebugStringW`, `CreateThread`, etc. These reveal the specific Windows functionalities being tested.
    * Error handling (`t.Fatal`, `t.Error`, checking return values).
    * `unsafe.Pointer`:  Indicates low-level memory manipulation, often necessary when interacting with C-style APIs.
    * `runtime.LockOSThread`, `runtime.UnlockOSThread`, `runtime.GC`: Hints at testing interactions with the Go runtime, particularly in the context of callbacks.
    * `exec.Command`:  Shows the execution of external commands, likely for building DLLs for testing.
    * Data structures like `Rect`, `OSVersionInfoEx`: Represent Windows data structures used in the API calls.

3. **Categorization of Functionality (Implicit Grouping):** As I identify these keywords, I start mentally (or physically) grouping the tests by the type of syscall functionality they are exercising. This leads to categories like:
    * **DLL Loading and Procedure Calls:**  Tests `LoadDLL`, `FindProc`, and `Call` with different calling conventions (`stdcall`, `cdecl`).
    * **Callbacks:** Tests the ability to pass Go functions as callbacks to Windows APIs, including handling panics, GC, and thread safety.
    * **Specific Windows API Tests:** Tests individual APIs like `EnumWindows`, `VerifyVersionInfoW`, etc.
    * **Exception Handling:** Tests how Go handles exceptions raised from Windows code.
    * **Thread Creation:** Tests creating new threads from Go and interacting with them.
    * **Low-Level Syscall (`SyscallN`):** Tests direct invocation of system calls with varying numbers of arguments.
    * **Floating-Point Arguments and Returns:** Tests passing and receiving floating-point numbers to and from DLL functions.
    * **Process Affinity and CPU Information:** Tests functions related to CPU management.
    * **DLL Preloading Mitigation:** Tests security features related to DLL loading.
    * **Stack Management in Callbacks:** Tests how Go manages stack size when calling back and forth between Go and C code.

4. **Synthesize a High-Level Summary:** Based on these categories, I can formulate a concise summary of the overall purpose:  The code tests the `syscall` package's ability to interact with various Windows system functionalities.

5. **Elaborate with Key Details (for a more detailed explanation):**  For each category, I can provide a brief description of what it tests. For instance, for "DLL Loading and Procedure Calls," I would mention testing different calling conventions and parameter passing. For "Callbacks," I'd highlight the testing of Go functions being called from Windows, including error handling and interaction with the Go runtime.

6. **Address Specific Requirements of the Prompt:** The prompt asks for specific things:
    * **List of functionalities:** This is addressed by the categorization step.
    * **Reasoning about Go language features:**  I can infer that the code is testing the `syscall` package, the `unsafe` package (for pointer manipulation), the `runtime` package (for interacting with the Go runtime), and the ability to interoperate with C code (via DLLs).
    * **Go code examples (if inferable):** The prompt implies providing examples *if* the code demonstrates a particular Go feature. In this case, the core features are interacting with the `syscall` package and using callbacks. A simple example of loading a DLL and calling a function would be relevant.
    * **Assumptions, Inputs, and Outputs (for code reasoning):**  Since this is a test file, the "inputs" are essentially the parameters passed to the Windows API calls, and the "outputs" are the return values and any modifications to memory. The tests often make assertions about these outputs.
    * **Command-line argument handling:** I scanned for usage of `os.Args` but didn't find any explicit command-line argument parsing in *this snippet*. However, I did notice the `GO_WANT_HELPER_PROCESS` environment variable being used, which is a common pattern for testing child processes.
    * **Common mistakes:** I considered potential pitfalls, like incorrect use of `unsafe.Pointer`, mismanaging DLL handles, or errors in callback signatures, but decided not to include them since the prompt asked to only include them if readily apparent in *this specific snippet*.
    * **Summarize the function:** This is the core request and is addressed by the high-level summary.

7. **Refine and Organize:**  Review the summary for clarity, conciseness, and accuracy. Organize the information logically, possibly using bullet points or numbered lists. Ensure the language is clear and understandable.

By following these steps, I can systematically analyze the code and generate a comprehensive and accurate summary of its functionality, addressing all the specific requirements of the prompt.
这是 `go/src/runtime/syscall_windows_test.go` 文件的一部分，它主要用于测试 Go 语言在 Windows 平台上与系统调用相关的特性和功能。

**它的主要功能可以归纳为：**

1. **测试 DLL 的加载和函数调用:**
   - 测试如何使用 `syscall.LoadDLL` 加载 Windows 的动态链接库 (DLL)。
   - 测试如何使用 `DLL.FindProc` 查找 DLL 中的导出函数。
   - 测试如何使用 `Proc.Call` 调用 DLL 中的函数，包括 `stdcall` 和 `cdecl` 两种调用约定，以及处理不同的参数和返回值类型（包括 64 位返回值）。

2. **测试 Go 语言的回调机制:**
   - 测试如何使用 `syscall.NewCallback` 和 `syscall.NewCallbackCDecl` 将 Go 函数注册为 Windows API 的回调函数。
   - 测试回调函数中的参数传递和返回值处理。
   - 测试在回调函数中调用 Go 运行时功能，如 `runtime.GC`。
   - 测试在回调函数中发生 panic 的处理机制，包括在锁定 OS 线程时的 panic 情况。
   - 测试在不同线程中执行回调函数的情况。

3. **测试特定的 Windows API 功能:**
   - 针对一些特定的 Windows API 函数进行测试，例如：
     - `UnionRect`: 合并矩形。
     - `wsprintfA`: 格式化字符串。
     - `EnumWindows`: 枚举顶层窗口。
     - `VerifyVersionInfoW`: 校验操作系统版本。
     - `RegisterClassExW` 和 `UnregisterClassW`: 注册和取消注册窗口类。
     - `OutputDebugStringW`: 输出调试信息。
     - `CreateThread`: 创建线程。
     - `GetProcessAffinityMask` 和 `SetProcessAffinityMask`: 获取和设置进程的 CPU 亲和性掩码。

4. **测试异常处理:**
   - 测试 Go 程序如何捕获和处理 Windows 代码中抛出的异常。
   - 测试除零异常的处理。

5. **测试栈管理:**
   - 测试在回调函数中进行栈增长后的返回是否正常。
   - 测试系统调用的栈使用情况是否在限制范围内。

6. **测试浮点数参数和返回值:**
   - 测试向 DLL 函数传递和接收浮点数（float32 和 float64）的能力。

7. **测试 `SyscallN` 函数:**
   - 测试 `syscall.SyscallN` 函数，它允许调用具有可变数量参数的系统调用。

8. **测试 DLL 预加载缓解机制:**
   - 测试 Go 语言如何防止恶意 DLL 通过预加载漏洞注入。

**可以推理出它是什么 go 语言功能的实现:**

这部分代码主要测试了 Go 语言的 `syscall` 包在 Windows 平台上的实现。`syscall` 包提供了与操作系统底层系统调用接口交互的能力，使得 Go 程序可以调用 Windows API 函数，进行底层的系统操作。同时，它也测试了 Go 语言的 C 互操作性，特别是通过回调函数机制，让 Go 代码能够响应 Windows 事件。

**Go 代码举例说明 (测试 DLL 加载和函数调用):**

假设我们有一个简单的 C++ DLL (example.dll) 包含一个 `add` 函数：

```cpp
// example.cpp
#include <windows.h>

extern "C" __declspec(dllexport) int add(int a, int b) {
    return a + b;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    return TRUE;
}
```

在 Go 代码中，我们可以这样测试加载 DLL 并调用 `add` 函数：

```go
package main

import (
	"fmt"
	"syscall"
	"testing" // 虽然这段代码不是完整的测试用例，但为了演示结构
	"unsafe"
)

func ExampleCallDLL() {
	dll, err := syscall.LoadDLL("example.dll")
	if err != nil {
		panic(err)
	}
	defer dll.Release()

	addProc, err := dll.FindProc("add")
	if err != nil {
		panic(err)
	}

	r1, _, err := addProc.Call(uintptr(5), uintptr(3))
	if err != syscall.Errno(0) {
		panic(err)
	}

	fmt.Println("Result:", int(r1)) // Output: Result: 8
}

// 为了在测试文件中运行，可以添加一个 Test 函数
func TestCallDLL(t *testing.T) {
	ExampleCallDLL()
}
```

**假设的输入与输出:**

在上面的 `ExampleCallDLL` 中：

* **输入:** 加载名为 "example.dll" 的 DLL，并调用其 "add" 函数，传入参数 5 和 3。
* **输出:**  `addProc.Call` 的第一个返回值 `r1` 将是 8，表示 5 + 3 的结果。

**命令行参数的具体处理:**

在这部分代码中，没有看到直接处理命令行参数的逻辑。测试通常是通过 `go test` 命令运行，`testing` 包会处理测试用例的发现和执行。不过，可以看到 `TestWERDialogue` 函数中使用了环境变量 `TEST_WER_DIALOGUE` 和 `GOTRACEBACK` 来控制测试行为。

**使用者易犯错的点:**

1. **`unsafe.Pointer` 的使用:** 直接操作内存指针是非常危险的，容易导致程序崩溃或安全漏洞。例如，在传递结构体指针给 DLL 函数时，必须确保 Go 端的结构体内存布局与 C/C++ 端一致。如果结构体字段类型或顺序不匹配，会导致数据错乱。

   ```go
   type MyStruct struct {
       A int32
       B int64 // 假设 C++ 端是 long long
   }

   // 错误示例：如果 C++ 端 B 是 int，则会导致数据错乱
   s := MyStruct{A: 1, B: 2}
   dll := GetDLL(t, "mydll.dll")
   someProc := dll.Proc("SomeFunction")
   _, _, err := someProc.Call(uintptr(unsafe.Pointer(&s)))
   ```

2. **调用约定错误:**  `stdcall` 和 `cdecl` 是不同的函数调用约定，参数压栈顺序和栈清理方式不同。如果 Go 代码中 `NewCallback` 或 `NewCallbackCDecl` 的使用与 DLL 中函数的声明不符，会导致程序崩溃。

3. **DLL 句柄和进程句柄的管理:**  `syscall.LoadDLL` 返回的 DLL 句柄需要使用 `dll.Release()` 释放，`syscall.OpenProcess` 返回的进程句柄需要使用 `syscall.CloseHandle` 关闭，否则可能导致资源泄漏。

4. **回调函数的生命周期:**  使用 `syscall.NewCallback` 创建的回调函数，其底层的函数指针需要保持有效。如果回调函数对应的 Go 函数被垃圾回收，调用该指针会导致崩溃。通常，将回调函数保存在一个不会被回收的地方，或者确保在不再需要时释放回调。

**总结一下它的功能：**

这部分 `syscall_windows_test.go` 的代码主要用于全面测试 Go 语言在 Windows 平台上与操作系统底层交互的能力，特别是通过 `syscall` 包调用 Windows API 和处理回调函数的机制。它涵盖了 DLL 的加载、函数调用（包括不同调用约定）、Go 语言回调的各种场景、特定 Windows API 的功能测试、异常处理以及一些底层的内存和栈管理测试，确保 Go 语言在 Windows 环境下能够可靠地进行系统编程。

Prompt: 
```
这是路径为go/src/runtime/syscall_windows_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime_test

import (
	"fmt"
	"internal/abi"
	"internal/syscall/windows/sysdll"
	"internal/testenv"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

type DLL struct {
	*syscall.DLL
	t *testing.T
}

func GetDLL(t *testing.T, name string) *DLL {
	d, e := syscall.LoadDLL(name)
	if e != nil {
		t.Fatal(e)
	}
	return &DLL{DLL: d, t: t}
}

func (d *DLL) Proc(name string) *syscall.Proc {
	p, e := d.FindProc(name)
	if e != nil {
		d.t.Fatal(e)
	}
	return p
}

func TestStdCall(t *testing.T) {
	type Rect struct {
		left, top, right, bottom int32
	}
	res := Rect{}
	expected := Rect{1, 1, 40, 60}
	a, _, _ := GetDLL(t, "user32.dll").Proc("UnionRect").Call(
		uintptr(unsafe.Pointer(&res)),
		uintptr(unsafe.Pointer(&Rect{10, 1, 14, 60})),
		uintptr(unsafe.Pointer(&Rect{1, 2, 40, 50})))
	if a != 1 || res.left != expected.left ||
		res.top != expected.top ||
		res.right != expected.right ||
		res.bottom != expected.bottom {
		t.Error("stdcall USER32.UnionRect returns", a, "res=", res)
	}
}

func Test64BitReturnStdCall(t *testing.T) {

	const (
		VER_BUILDNUMBER      = 0x0000004
		VER_MAJORVERSION     = 0x0000002
		VER_MINORVERSION     = 0x0000001
		VER_PLATFORMID       = 0x0000008
		VER_PRODUCT_TYPE     = 0x0000080
		VER_SERVICEPACKMAJOR = 0x0000020
		VER_SERVICEPACKMINOR = 0x0000010
		VER_SUITENAME        = 0x0000040

		VER_EQUAL         = 1
		VER_GREATER       = 2
		VER_GREATER_EQUAL = 3
		VER_LESS          = 4
		VER_LESS_EQUAL    = 5

		ERROR_OLD_WIN_VERSION syscall.Errno = 1150
	)

	type OSVersionInfoEx struct {
		OSVersionInfoSize uint32
		MajorVersion      uint32
		MinorVersion      uint32
		BuildNumber       uint32
		PlatformId        uint32
		CSDVersion        [128]uint16
		ServicePackMajor  uint16
		ServicePackMinor  uint16
		SuiteMask         uint16
		ProductType       byte
		Reserve           byte
	}

	d := GetDLL(t, "kernel32.dll")

	var m1, m2 uintptr
	VerSetConditionMask := d.Proc("VerSetConditionMask")
	m1, m2, _ = VerSetConditionMask.Call(m1, m2, VER_MAJORVERSION, VER_GREATER_EQUAL)
	m1, m2, _ = VerSetConditionMask.Call(m1, m2, VER_MINORVERSION, VER_GREATER_EQUAL)
	m1, m2, _ = VerSetConditionMask.Call(m1, m2, VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL)
	m1, m2, _ = VerSetConditionMask.Call(m1, m2, VER_SERVICEPACKMINOR, VER_GREATER_EQUAL)

	vi := OSVersionInfoEx{
		MajorVersion:     5,
		MinorVersion:     1,
		ServicePackMajor: 2,
		ServicePackMinor: 0,
	}
	vi.OSVersionInfoSize = uint32(unsafe.Sizeof(vi))
	r, _, e2 := d.Proc("VerifyVersionInfoW").Call(
		uintptr(unsafe.Pointer(&vi)),
		VER_MAJORVERSION|VER_MINORVERSION|VER_SERVICEPACKMAJOR|VER_SERVICEPACKMINOR,
		m1, m2)
	if r == 0 && e2 != ERROR_OLD_WIN_VERSION {
		t.Errorf("VerifyVersionInfo failed: %s", e2)
	}
}

func TestCDecl(t *testing.T) {
	var buf [50]byte
	fmtp, _ := syscall.BytePtrFromString("%d %d %d")
	a, _, _ := GetDLL(t, "user32.dll").Proc("wsprintfA").Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(fmtp)),
		1000, 2000, 3000)
	if string(buf[:a]) != "1000 2000 3000" {
		t.Error("cdecl USER32.wsprintfA returns", a, "buf=", buf[:a])
	}
}

func TestEnumWindows(t *testing.T) {
	d := GetDLL(t, "user32.dll")
	isWindows := d.Proc("IsWindow")
	counter := 0
	cb := syscall.NewCallback(func(hwnd syscall.Handle, lparam uintptr) uintptr {
		if lparam != 888 {
			t.Error("lparam was not passed to callback")
		}
		b, _, _ := isWindows.Call(uintptr(hwnd))
		if b == 0 {
			t.Error("USER32.IsWindow returns FALSE")
		}
		counter++
		return 1 // continue enumeration
	})
	a, _, _ := d.Proc("EnumWindows").Call(cb, 888)
	if a == 0 {
		t.Error("USER32.EnumWindows returns FALSE")
	}
	if counter == 0 {
		t.Error("Callback has been never called or your have no windows")
	}
}

func callback(timeFormatString unsafe.Pointer, lparam uintptr) uintptr {
	(*(*func())(unsafe.Pointer(&lparam)))()
	return 0 // stop enumeration
}

// nestedCall calls into Windows, back into Go, and finally to f.
func nestedCall(t *testing.T, f func()) {
	c := syscall.NewCallback(callback)
	d := GetDLL(t, "kernel32.dll")
	defer d.Release()
	const LOCALE_NAME_USER_DEFAULT = 0
	d.Proc("EnumTimeFormatsEx").Call(c, LOCALE_NAME_USER_DEFAULT, 0, uintptr(*(*unsafe.Pointer)(unsafe.Pointer(&f))))
}

func TestCallback(t *testing.T) {
	var x = false
	nestedCall(t, func() { x = true })
	if !x {
		t.Fatal("nestedCall did not call func")
	}
}

func TestCallbackGC(t *testing.T) {
	nestedCall(t, runtime.GC)
}

func TestCallbackPanicLocked(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if !runtime.LockedOSThread() {
		t.Fatal("runtime.LockOSThread didn't")
	}
	defer func() {
		s := recover()
		if s == nil {
			t.Fatal("did not panic")
		}
		if s.(string) != "callback panic" {
			t.Fatal("wrong panic:", s)
		}
		if !runtime.LockedOSThread() {
			t.Fatal("lost lock on OS thread after panic")
		}
	}()
	nestedCall(t, func() { panic("callback panic") })
	panic("nestedCall returned")
}

func TestCallbackPanic(t *testing.T) {
	// Make sure panic during callback unwinds properly.
	if runtime.LockedOSThread() {
		t.Fatal("locked OS thread on entry to TestCallbackPanic")
	}
	defer func() {
		s := recover()
		if s == nil {
			t.Fatal("did not panic")
		}
		if s.(string) != "callback panic" {
			t.Fatal("wrong panic:", s)
		}
		if runtime.LockedOSThread() {
			t.Fatal("locked OS thread on exit from TestCallbackPanic")
		}
	}()
	nestedCall(t, func() { panic("callback panic") })
	panic("nestedCall returned")
}

func TestCallbackPanicLoop(t *testing.T) {
	// Make sure we don't blow out m->g0 stack.
	for i := 0; i < 100000; i++ {
		TestCallbackPanic(t)
	}
}

func TestBlockingCallback(t *testing.T) {
	c := make(chan int)
	go func() {
		for i := 0; i < 10; i++ {
			c <- <-c
		}
	}()
	nestedCall(t, func() {
		for i := 0; i < 10; i++ {
			c <- i
			if j := <-c; j != i {
				t.Errorf("out of sync %d != %d", j, i)
			}
		}
	})
}

func TestCallbackInAnotherThread(t *testing.T) {
	d := GetDLL(t, "kernel32.dll")

	f := func(p uintptr) uintptr {
		return p
	}
	r, _, err := d.Proc("CreateThread").Call(0, 0, syscall.NewCallback(f), 123, 0, 0)
	if r == 0 {
		t.Fatalf("CreateThread failed: %v", err)
	}
	h := syscall.Handle(r)
	defer syscall.CloseHandle(h)

	switch s, err := syscall.WaitForSingleObject(h, syscall.INFINITE); s {
	case syscall.WAIT_OBJECT_0:
		break
	case syscall.WAIT_FAILED:
		t.Fatalf("WaitForSingleObject failed: %v", err)
	default:
		t.Fatalf("WaitForSingleObject returns unexpected value %v", s)
	}

	var ec uint32
	r, _, err = d.Proc("GetExitCodeThread").Call(uintptr(h), uintptr(unsafe.Pointer(&ec)))
	if r == 0 {
		t.Fatalf("GetExitCodeThread failed: %v", err)
	}
	if ec != 123 {
		t.Fatalf("expected 123, but got %d", ec)
	}
}

type cbFunc struct {
	goFunc any
}

func (f cbFunc) cName(cdecl bool) string {
	name := "stdcall"
	if cdecl {
		name = "cdecl"
	}
	t := reflect.TypeOf(f.goFunc)
	for i := 0; i < t.NumIn(); i++ {
		name += "_" + t.In(i).Name()
	}
	return name
}

func (f cbFunc) cSrc(w io.Writer, cdecl bool) {
	// Construct a C function that takes a callback with
	// f.goFunc's signature, and calls it with integers 1..N.
	funcname := f.cName(cdecl)
	attr := "__stdcall"
	if cdecl {
		attr = "__cdecl"
	}
	typename := "t" + funcname
	t := reflect.TypeOf(f.goFunc)
	cTypes := make([]string, t.NumIn())
	cArgs := make([]string, t.NumIn())
	for i := range cTypes {
		// We included stdint.h, so this works for all sized
		// integer types, and uint8Pair_t.
		cTypes[i] = t.In(i).Name() + "_t"
		if t.In(i).Name() == "uint8Pair" {
			cArgs[i] = fmt.Sprintf("(uint8Pair_t){%d,1}", i)
		} else {
			cArgs[i] = fmt.Sprintf("%d", i+1)
		}
	}
	fmt.Fprintf(w, `
typedef uintptr_t %s (*%s)(%s);
uintptr_t %s(%s f) {
	return f(%s);
}
	`, attr, typename, strings.Join(cTypes, ","), funcname, typename, strings.Join(cArgs, ","))
}

func (f cbFunc) testOne(t *testing.T, dll *syscall.DLL, cdecl bool, cb uintptr) {
	r1, _, _ := dll.MustFindProc(f.cName(cdecl)).Call(cb)

	want := 0
	for i := 0; i < reflect.TypeOf(f.goFunc).NumIn(); i++ {
		want += i + 1
	}
	if int(r1) != want {
		t.Errorf("wanted result %d; got %d", want, r1)
	}
}

type uint8Pair struct{ x, y uint8 }

var cbFuncs = []cbFunc{
	{func(i1, i2 uintptr) uintptr {
		return i1 + i2
	}},
	{func(i1, i2, i3 uintptr) uintptr {
		return i1 + i2 + i3
	}},
	{func(i1, i2, i3, i4 uintptr) uintptr {
		return i1 + i2 + i3 + i4
	}},
	{func(i1, i2, i3, i4, i5 uintptr) uintptr {
		return i1 + i2 + i3 + i4 + i5
	}},
	{func(i1, i2, i3, i4, i5, i6 uintptr) uintptr {
		return i1 + i2 + i3 + i4 + i5 + i6
	}},
	{func(i1, i2, i3, i4, i5, i6, i7 uintptr) uintptr {
		return i1 + i2 + i3 + i4 + i5 + i6 + i7
	}},
	{func(i1, i2, i3, i4, i5, i6, i7, i8 uintptr) uintptr {
		return i1 + i2 + i3 + i4 + i5 + i6 + i7 + i8
	}},
	{func(i1, i2, i3, i4, i5, i6, i7, i8, i9 uintptr) uintptr {
		return i1 + i2 + i3 + i4 + i5 + i6 + i7 + i8 + i9
	}},

	// Non-uintptr parameters.
	{func(i1, i2, i3, i4, i5, i6, i7, i8, i9 uint8) uintptr {
		return uintptr(i1 + i2 + i3 + i4 + i5 + i6 + i7 + i8 + i9)
	}},
	{func(i1, i2, i3, i4, i5, i6, i7, i8, i9 uint16) uintptr {
		return uintptr(i1 + i2 + i3 + i4 + i5 + i6 + i7 + i8 + i9)
	}},
	{func(i1, i2, i3, i4, i5, i6, i7, i8, i9 int8) uintptr {
		return uintptr(i1 + i2 + i3 + i4 + i5 + i6 + i7 + i8 + i9)
	}},
	{func(i1 int8, i2 int16, i3 int32, i4, i5 uintptr) uintptr {
		return uintptr(i1) + uintptr(i2) + uintptr(i3) + i4 + i5
	}},
	{func(i1, i2, i3, i4, i5 uint8Pair) uintptr {
		return uintptr(i1.x + i1.y + i2.x + i2.y + i3.x + i3.y + i4.x + i4.y + i5.x + i5.y)
	}},
	{func(i1, i2, i3, i4, i5, i6, i7, i8, i9 uint32) uintptr {
		runtime.GC()
		return uintptr(i1 + i2 + i3 + i4 + i5 + i6 + i7 + i8 + i9)
	}},
}

//go:registerparams
func sum2(i1, i2 uintptr) uintptr {
	return i1 + i2
}

//go:registerparams
func sum3(i1, i2, i3 uintptr) uintptr {
	return i1 + i2 + i3
}

//go:registerparams
func sum4(i1, i2, i3, i4 uintptr) uintptr {
	return i1 + i2 + i3 + i4
}

//go:registerparams
func sum5(i1, i2, i3, i4, i5 uintptr) uintptr {
	return i1 + i2 + i3 + i4 + i5
}

//go:registerparams
func sum6(i1, i2, i3, i4, i5, i6 uintptr) uintptr {
	return i1 + i2 + i3 + i4 + i5 + i6
}

//go:registerparams
func sum7(i1, i2, i3, i4, i5, i6, i7 uintptr) uintptr {
	return i1 + i2 + i3 + i4 + i5 + i6 + i7
}

//go:registerparams
func sum8(i1, i2, i3, i4, i5, i6, i7, i8 uintptr) uintptr {
	return i1 + i2 + i3 + i4 + i5 + i6 + i7 + i8
}

//go:registerparams
func sum9(i1, i2, i3, i4, i5, i6, i7, i8, i9 uintptr) uintptr {
	return i1 + i2 + i3 + i4 + i5 + i6 + i7 + i8 + i9
}

//go:registerparams
func sum10(i1, i2, i3, i4, i5, i6, i7, i8, i9, i10 uintptr) uintptr {
	return i1 + i2 + i3 + i4 + i5 + i6 + i7 + i8 + i9 + i10
}

//go:registerparams
func sum9uint8(i1, i2, i3, i4, i5, i6, i7, i8, i9 uint8) uintptr {
	return uintptr(i1 + i2 + i3 + i4 + i5 + i6 + i7 + i8 + i9)
}

//go:registerparams
func sum9uint16(i1, i2, i3, i4, i5, i6, i7, i8, i9 uint16) uintptr {
	return uintptr(i1 + i2 + i3 + i4 + i5 + i6 + i7 + i8 + i9)
}

//go:registerparams
func sum9int8(i1, i2, i3, i4, i5, i6, i7, i8, i9 int8) uintptr {
	return uintptr(i1 + i2 + i3 + i4 + i5 + i6 + i7 + i8 + i9)
}

//go:registerparams
func sum5mix(i1 int8, i2 int16, i3 int32, i4, i5 uintptr) uintptr {
	return uintptr(i1) + uintptr(i2) + uintptr(i3) + i4 + i5
}

//go:registerparams
func sum5andPair(i1, i2, i3, i4, i5 uint8Pair) uintptr {
	return uintptr(i1.x + i1.y + i2.x + i2.y + i3.x + i3.y + i4.x + i4.y + i5.x + i5.y)
}

// This test forces a GC. The idea is to have enough arguments
// that insufficient spill slots allocated (according to the ABI)
// may cause compiler-generated spills to clobber the return PC.
// Then, the GC stack scanning will catch that.
//
//go:registerparams
func sum9andGC(i1, i2, i3, i4, i5, i6, i7, i8, i9 uint32) uintptr {
	runtime.GC()
	return uintptr(i1 + i2 + i3 + i4 + i5 + i6 + i7 + i8 + i9)
}

// TODO(register args): Remove this once we switch to using the register
// calling convention by default, since this is redundant with the existing
// tests.
var cbFuncsRegABI = []cbFunc{
	{sum2},
	{sum3},
	{sum4},
	{sum5},
	{sum6},
	{sum7},
	{sum8},
	{sum9},
	{sum10},
	{sum9uint8},
	{sum9uint16},
	{sum9int8},
	{sum5mix},
	{sum5andPair},
	{sum9andGC},
}

func getCallbackTestFuncs() []cbFunc {
	if regs := runtime.SetIntArgRegs(-1); regs > 0 {
		return cbFuncsRegABI
	}
	return cbFuncs
}

type cbDLL struct {
	name      string
	buildArgs func(out, src string) []string
}

func (d *cbDLL) makeSrc(t *testing.T, path string) {
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create source file: %v", err)
	}
	defer f.Close()

	fmt.Fprint(f, `
#include <stdint.h>
typedef struct { uint8_t x, y; } uint8Pair_t;
`)
	for _, cbf := range getCallbackTestFuncs() {
		cbf.cSrc(f, false)
		cbf.cSrc(f, true)
	}
}

func (d *cbDLL) build(t *testing.T, dir string) string {
	srcname := d.name + ".c"
	d.makeSrc(t, filepath.Join(dir, srcname))
	outname := d.name + ".dll"
	args := d.buildArgs(outname, srcname)
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build dll: %v - %v", err, string(out))
	}
	return filepath.Join(dir, outname)
}

var cbDLLs = []cbDLL{
	{
		"test",
		func(out, src string) []string {
			return []string{"gcc", "-shared", "-s", "-Werror", "-o", out, src}
		},
	},
	{
		"testO2",
		func(out, src string) []string {
			return []string{"gcc", "-shared", "-s", "-Werror", "-o", out, "-O2", src}
		},
	},
}

func TestStdcallAndCDeclCallbacks(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("skipping test: gcc is missing")
	}
	tmp := t.TempDir()

	oldRegs := runtime.SetIntArgRegs(abi.IntArgRegs)
	defer runtime.SetIntArgRegs(oldRegs)

	for _, dll := range cbDLLs {
		t.Run(dll.name, func(t *testing.T) {
			dllPath := dll.build(t, tmp)
			dll := syscall.MustLoadDLL(dllPath)
			defer dll.Release()
			for _, cbf := range getCallbackTestFuncs() {
				t.Run(cbf.cName(false), func(t *testing.T) {
					stdcall := syscall.NewCallback(cbf.goFunc)
					cbf.testOne(t, dll, false, stdcall)
				})
				t.Run(cbf.cName(true), func(t *testing.T) {
					cdecl := syscall.NewCallbackCDecl(cbf.goFunc)
					cbf.testOne(t, dll, true, cdecl)
				})
			}
		})
	}
}

func TestRegisterClass(t *testing.T) {
	kernel32 := GetDLL(t, "kernel32.dll")
	user32 := GetDLL(t, "user32.dll")
	mh, _, _ := kernel32.Proc("GetModuleHandleW").Call(0)
	cb := syscall.NewCallback(func(hwnd syscall.Handle, msg uint32, wparam, lparam uintptr) (rc uintptr) {
		t.Fatal("callback should never get called")
		return 0
	})
	type Wndclassex struct {
		Size       uint32
		Style      uint32
		WndProc    uintptr
		ClsExtra   int32
		WndExtra   int32
		Instance   syscall.Handle
		Icon       syscall.Handle
		Cursor     syscall.Handle
		Background syscall.Handle
		MenuName   *uint16
		ClassName  *uint16
		IconSm     syscall.Handle
	}
	name := syscall.StringToUTF16Ptr("test_window")
	wc := Wndclassex{
		WndProc:   cb,
		Instance:  syscall.Handle(mh),
		ClassName: name,
	}
	wc.Size = uint32(unsafe.Sizeof(wc))
	a, _, err := user32.Proc("RegisterClassExW").Call(uintptr(unsafe.Pointer(&wc)))
	if a == 0 {
		t.Fatalf("RegisterClassEx failed: %v", err)
	}
	r, _, err := user32.Proc("UnregisterClassW").Call(uintptr(unsafe.Pointer(name)), 0)
	if r == 0 {
		t.Fatalf("UnregisterClass failed: %v", err)
	}
}

func TestOutputDebugString(t *testing.T) {
	d := GetDLL(t, "kernel32.dll")
	p := syscall.StringToUTF16Ptr("testing OutputDebugString")
	d.Proc("OutputDebugStringW").Call(uintptr(unsafe.Pointer(p)))
}

func TestRaiseException(t *testing.T) {
	if strings.HasPrefix(testenv.Builder(), "windows-amd64-2012") {
		testenv.SkipFlaky(t, 49681)
	}
	o := runTestProg(t, "testprog", "RaiseException")
	if strings.Contains(o, "RaiseException should not return") {
		t.Fatalf("RaiseException did not crash program: %v", o)
	}
	if !strings.Contains(o, "Exception 0xbad") {
		t.Fatalf("No stack trace: %v", o)
	}
}

func TestZeroDivisionException(t *testing.T) {
	o := runTestProg(t, "testprog", "ZeroDivisionException")
	if !strings.Contains(o, "panic: runtime error: integer divide by zero") {
		t.Fatalf("No stack trace: %v", o)
	}
}

func TestWERDialogue(t *testing.T) {
	if os.Getenv("TEST_WER_DIALOGUE") == "1" {
		const EXCEPTION_NONCONTINUABLE = 1
		mod := syscall.MustLoadDLL("kernel32.dll")
		proc := mod.MustFindProc("RaiseException")
		proc.Call(0xbad, EXCEPTION_NONCONTINUABLE, 0, 0)
		t.Fatal("RaiseException should not return")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := testenv.CleanCmdEnv(testenv.Command(t, exe, "-test.run=TestWERDialogue"))
	cmd.Env = append(cmd.Env, "TEST_WER_DIALOGUE=1", "GOTRACEBACK=wer")
	// Child process should not open WER dialogue, but return immediately instead.
	// The exit code can't be reliably tested here because Windows can change it.
	_, err = cmd.CombinedOutput()
	if err == nil {
		t.Error("test program succeeded unexpectedly")
	}
}

func TestWindowsStackMemory(t *testing.T) {
	o := runTestProg(t, "testprog", "StackMemory")
	stackUsage, err := strconv.Atoi(o)
	if err != nil {
		t.Fatalf("Failed to read stack usage: %v", err)
	}
	if expected, got := 128<<10, stackUsage; got > expected {
		t.Fatalf("expected < %d bytes of memory per thread, got %d", expected, got)
	}
}

var used byte

func use(buf []byte) {
	for _, c := range buf {
		used += c
	}
}

func forceStackCopy() (r int) {
	var f func(int) int
	f = func(i int) int {
		var buf [256]byte
		use(buf[:])
		if i == 0 {
			return 0
		}
		return i + f(i-1)
	}
	r = f(128)
	return
}

func TestReturnAfterStackGrowInCallback(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("skipping test: gcc is missing")
	}

	const src = `
#include <stdint.h>
#include <windows.h>

typedef uintptr_t __stdcall (*callback)(uintptr_t);

uintptr_t cfunc(callback f, uintptr_t n) {
   uintptr_t r;
   r = f(n);
   SetLastError(333);
   return r;
}
`
	tmpdir := t.TempDir()

	srcname := "mydll.c"
	err := os.WriteFile(filepath.Join(tmpdir, srcname), []byte(src), 0)
	if err != nil {
		t.Fatal(err)
	}
	outname := "mydll.dll"
	cmd := exec.Command("gcc", "-shared", "-s", "-Werror", "-o", outname, srcname)
	cmd.Dir = tmpdir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build dll: %v - %v", err, string(out))
	}
	dllpath := filepath.Join(tmpdir, outname)

	dll := syscall.MustLoadDLL(dllpath)
	defer dll.Release()

	proc := dll.MustFindProc("cfunc")

	cb := syscall.NewCallback(func(n uintptr) uintptr {
		forceStackCopy()
		return n
	})

	// Use a new goroutine so that we get a small stack.
	type result struct {
		r   uintptr
		err syscall.Errno
	}
	want := result{
		// Make it large enough to test issue #29331.
		r:   (^uintptr(0)) >> 24,
		err: 333,
	}
	c := make(chan result)
	go func() {
		r, _, err := proc.Call(cb, want.r)
		c <- result{r, err.(syscall.Errno)}
	}()
	if got := <-c; got != want {
		t.Errorf("got %d want %d", got, want)
	}
}

func TestSyscallN(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("skipping test: gcc is missing")
	}
	if runtime.GOARCH != "amd64" {
		t.Skipf("skipping test: GOARCH=%s", runtime.GOARCH)
	}

	for arglen := 0; arglen <= runtime.MaxArgs; arglen++ {
		arglen := arglen
		t.Run(fmt.Sprintf("arg-%d", arglen), func(t *testing.T) {
			t.Parallel()
			args := make([]string, arglen)
			rets := make([]string, arglen+1)
			params := make([]uintptr, arglen)
			for i := range args {
				args[i] = fmt.Sprintf("int a%d", i)
				rets[i] = fmt.Sprintf("(a%d == %d)", i, i)
				params[i] = uintptr(i)
			}
			rets[arglen] = "1" // for arglen == 0

			src := fmt.Sprintf(`
		#include <stdint.h>
		#include <windows.h>
		int cfunc(%s) { return %s; }`, strings.Join(args, ", "), strings.Join(rets, " && "))

			tmpdir := t.TempDir()

			srcname := "mydll.c"
			err := os.WriteFile(filepath.Join(tmpdir, srcname), []byte(src), 0)
			if err != nil {
				t.Fatal(err)
			}
			outname := "mydll.dll"
			cmd := exec.Command("gcc", "-shared", "-s", "-Werror", "-o", outname, srcname)
			cmd.Dir = tmpdir
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("failed to build dll: %v\n%s", err, out)
			}
			dllpath := filepath.Join(tmpdir, outname)

			dll := syscall.MustLoadDLL(dllpath)
			defer dll.Release()

			proc := dll.MustFindProc("cfunc")

			// proc.Call() will call SyscallN() internally.
			r, _, err := proc.Call(params...)
			if r != 1 {
				t.Errorf("got %d want 1 (err=%v)", r, err)
			}
		})
	}
}

func TestFloatArgs(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("skipping test: gcc is missing")
	}
	if runtime.GOARCH != "amd64" {
		t.Skipf("skipping test: GOARCH=%s", runtime.GOARCH)
	}

	const src = `
#include <stdint.h>
#include <windows.h>

uintptr_t cfunc(uintptr_t a, double b, float c, double d) {
	if (a == 1 && b == 2.2 && c == 3.3f && d == 4.4e44) {
		return 1;
	}
	return 0;
}
`
	tmpdir := t.TempDir()

	srcname := "mydll.c"
	err := os.WriteFile(filepath.Join(tmpdir, srcname), []byte(src), 0)
	if err != nil {
		t.Fatal(err)
	}
	outname := "mydll.dll"
	cmd := exec.Command("gcc", "-shared", "-s", "-Werror", "-o", outname, srcname)
	cmd.Dir = tmpdir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build dll: %v - %v", err, string(out))
	}
	dllpath := filepath.Join(tmpdir, outname)

	dll := syscall.MustLoadDLL(dllpath)
	defer dll.Release()

	proc := dll.MustFindProc("cfunc")

	r, _, err := proc.Call(
		1,
		uintptr(math.Float64bits(2.2)),
		uintptr(math.Float32bits(3.3)),
		uintptr(math.Float64bits(4.4e44)),
	)
	if r != 1 {
		t.Errorf("got %d want 1 (err=%v)", r, err)
	}
}

func TestFloatReturn(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("skipping test: gcc is missing")
	}
	if runtime.GOARCH != "amd64" {
		t.Skipf("skipping test: GOARCH=%s", runtime.GOARCH)
	}

	const src = `
#include <stdint.h>
#include <windows.h>

float cfuncFloat(uintptr_t a, double b, float c, double d) {
	if (a == 1 && b == 2.2 && c == 3.3f && d == 4.4e44) {
		return 1.5f;
	}
	return 0;
}

double cfuncDouble(uintptr_t a, double b, float c, double d) {
	if (a == 1 && b == 2.2 && c == 3.3f && d == 4.4e44) {
		return 2.5;
	}
	return 0;
}
`
	tmpdir := t.TempDir()

	srcname := "mydll.c"
	err := os.WriteFile(filepath.Join(tmpdir, srcname), []byte(src), 0)
	if err != nil {
		t.Fatal(err)
	}
	outname := "mydll.dll"
	cmd := exec.Command("gcc", "-shared", "-s", "-Werror", "-o", outname, srcname)
	cmd.Dir = tmpdir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build dll: %v - %v", err, string(out))
	}
	dllpath := filepath.Join(tmpdir, outname)

	dll := syscall.MustLoadDLL(dllpath)
	defer dll.Release()

	proc := dll.MustFindProc("cfuncFloat")

	_, r, err := proc.Call(
		1,
		uintptr(math.Float64bits(2.2)),
		uintptr(math.Float32bits(3.3)),
		uintptr(math.Float64bits(4.4e44)),
	)
	fr := math.Float32frombits(uint32(r))
	if fr != 1.5 {
		t.Errorf("got %f want 1.5 (err=%v)", fr, err)
	}

	proc = dll.MustFindProc("cfuncDouble")

	_, r, err = proc.Call(
		1,
		uintptr(math.Float64bits(2.2)),
		uintptr(math.Float32bits(3.3)),
		uintptr(math.Float64bits(4.4e44)),
	)
	dr := math.Float64frombits(uint64(r))
	if dr != 2.5 {
		t.Errorf("got %f want 2.5 (err=%v)", dr, err)
	}
}

func TestTimeBeginPeriod(t *testing.T) {
	const TIMERR_NOERROR = 0
	if *runtime.TimeBeginPeriodRetValue != TIMERR_NOERROR {
		t.Fatalf("timeBeginPeriod failed: it returned %d", *runtime.TimeBeginPeriodRetValue)
	}
}

// removeOneCPU removes one (any) cpu from affinity mask.
// It returns new affinity mask.
func removeOneCPU(mask uintptr) (uintptr, error) {
	if mask == 0 {
		return 0, fmt.Errorf("cpu affinity mask is empty")
	}
	maskbits := int(unsafe.Sizeof(mask) * 8)
	for i := 0; i < maskbits; i++ {
		newmask := mask & ^(1 << uint(i))
		if newmask != mask {
			return newmask, nil
		}

	}
	panic("not reached")
}

func resumeChildThread(kernel32 *syscall.DLL, childpid int) error {
	_OpenThread := kernel32.MustFindProc("OpenThread")
	_ResumeThread := kernel32.MustFindProc("ResumeThread")
	_Thread32First := kernel32.MustFindProc("Thread32First")
	_Thread32Next := kernel32.MustFindProc("Thread32Next")

	snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(snapshot)

	const _THREAD_SUSPEND_RESUME = 0x0002

	type ThreadEntry32 struct {
		Size           uint32
		tUsage         uint32
		ThreadID       uint32
		OwnerProcessID uint32
		BasePri        int32
		DeltaPri       int32
		Flags          uint32
	}

	var te ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	ret, _, err := _Thread32First.Call(uintptr(snapshot), uintptr(unsafe.Pointer(&te)))
	if ret == 0 {
		return err
	}
	for te.OwnerProcessID != uint32(childpid) {
		ret, _, err = _Thread32Next.Call(uintptr(snapshot), uintptr(unsafe.Pointer(&te)))
		if ret == 0 {
			return err
		}
	}
	h, _, err := _OpenThread.Call(_THREAD_SUSPEND_RESUME, 1, uintptr(te.ThreadID))
	if h == 0 {
		return err
	}
	defer syscall.Close(syscall.Handle(h))

	ret, _, err = _ResumeThread.Call(h)
	if ret == 0xffffffff {
		return err
	}
	return nil
}

func TestNumCPU(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		// in child process
		fmt.Fprintf(os.Stderr, "%d", runtime.NumCPU())
		os.Exit(0)
	}

	switch n := runtime.NumberOfProcessors(); {
	case n < 1:
		t.Fatalf("system cannot have %d cpu(s)", n)
	case n == 1:
		if runtime.NumCPU() != 1 {
			t.Fatalf("runtime.NumCPU() returns %d on single cpu system", runtime.NumCPU())
		}
		return
	}

	const (
		_CREATE_SUSPENDED   = 0x00000004
		_PROCESS_ALL_ACCESS = syscall.STANDARD_RIGHTS_REQUIRED | syscall.SYNCHRONIZE | 0xfff
	)

	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	_GetProcessAffinityMask := kernel32.MustFindProc("GetProcessAffinityMask")
	_SetProcessAffinityMask := kernel32.MustFindProc("SetProcessAffinityMask")

	cmd := exec.Command(os.Args[0], "-test.run=TestNumCPU")
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1")
	var buf strings.Builder
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: _CREATE_SUSPENDED}
	err := cmd.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = cmd.Wait()
		childOutput := buf.String()
		if err != nil {
			t.Fatalf("child failed: %v: %v", err, childOutput)
		}
		// removeOneCPU should have decreased child cpu count by 1
		want := fmt.Sprintf("%d", runtime.NumCPU()-1)
		if childOutput != want {
			t.Fatalf("child output: want %q, got %q", want, childOutput)
		}
	}()

	defer func() {
		err = resumeChildThread(kernel32, cmd.Process.Pid)
		if err != nil {
			t.Fatal(err)
		}
	}()

	ph, err := syscall.OpenProcess(_PROCESS_ALL_ACCESS, false, uint32(cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(ph)

	var mask, sysmask uintptr
	ret, _, err := _GetProcessAffinityMask.Call(uintptr(ph), uintptr(unsafe.Pointer(&mask)), uintptr(unsafe.Pointer(&sysmask)))
	if ret == 0 {
		t.Fatal(err)
	}

	newmask, err := removeOneCPU(mask)
	if err != nil {
		t.Fatal(err)
	}

	ret, _, err = _SetProcessAffinityMask.Call(uintptr(ph), newmask)
	if ret == 0 {
		t.Fatal(err)
	}
	ret, _, err = _GetProcessAffinityMask.Call(uintptr(ph), uintptr(unsafe.Pointer(&mask)), uintptr(unsafe.Pointer(&sysmask)))
	if ret == 0 {
		t.Fatal(err)
	}
	if newmask != mask {
		t.Fatalf("SetProcessAffinityMask didn't set newmask of 0x%x. Current mask is 0x%x.", newmask, mask)
	}
}

// See Issue 14959
func TestDLLPreloadMitigation(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("skipping test: gcc is missing")
	}

	tmpdir := t.TempDir()

	const src = `
#include <stdint.h>
#include <windows.h>

uintptr_t cfunc(void) {
   SetLastError(123);
   return 0;
}
`
	srcname := "nojack.c"
	err := os.WriteFile(filepath.Join(tmpdir, srcname), []byte(src), 0)
	if err != nil {
		t.Fatal(err)
	}
	name := "nojack.dll"
	cmd := exec.Command("gcc", "-shared", "-s", "-Werror", "-o", name, srcname)
	cmd.Dir = tmpdir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build dll: %v - %v", err, string(out))
	}
	dllpath := filepath.Join(tmpdir, name)

	dll := syscall.MustLoadDLL(dllpath)
	dll.MustFindProc("cfunc")
	dll.Release()

	// Get into the directory with the DLL we'll load by base name
	// ("nojack.dll") Think of this as the user double-clicking an
	// installer from their Downloads directory where a browser
	// silently downloaded some malicious DLLs.
	t.Chdir(tmpdir)

	// First before we can load a DLL from the current directory,
	// loading it only as "nojack.dll", without an absolute path.
	delete(sysdll.IsSystemDLL, name) // in case test was run repeatedly
	dll, err = syscall.LoadDLL(name)
	if err != nil {
		t.Fatalf("failed to load %s by base name before sysdll registration: %v", name, err)
	}
	dll.Release()

	// And now verify that if we register it as a system32-only
	// DLL, the implicit loading from the current directory no
	// longer works.
	sysdll.IsSystemDLL[name] = true
	dll, err = syscall.LoadDLL(name)
	if err == nil {
		dll.Release()
		t.Fatalf("Bad: insecure load of DLL by base name %q before sysdll registration: %v", name, err)
	}
}

// Test that C code called via a DLL can use large Windows thread
// stacks and call back in to Go without crashing. See issue #20975.
//
// See also TestBigStackCallbackCgo.
func TestBigStackCallbackSyscall(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("skipping test: gcc is missing")
	}

	srcname, err := filepath.Abs("testdata/testprogcgo/bigstack_windows.c")
	if err != nil {
		t.Fatal("Abs failed: ", err)
	}

	tmpdir := t.TempDir()

	outname := "mydll.dll"
	cmd := exec.Command("gcc", "-shared", "-s", "-Werror", "-o", outname, srcname)
	cmd.Dir = tmpdir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build dll: %v - %v", err, string(out))
	}
	dllpath := filepath.Join(tmpdir, outname)

	dll := syscall.MustLoadDLL(dllpath)
	defer dll.Release()

	var ok bool
	proc := dll.MustFindProc("bigStack")
	cb := syscall.NewCallback(func() uintptr {
		// Do something interesting to force stack checks.
		forceStackCopy()
		ok = true
		return 0
	})
	proc.Call(cb)
	if !ok {
		t.Fatalf("callback not called")
	}
}

func TestSyscallStackUsage(t *testing.T) {
	// Test that the stack usage of a syscall doesn't exceed the limit.
	// See https://go.dev/issue/69813.
	syscall.Syscall15(procSetEvent.Addr(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	syscall.Syscall18(procSetEvent.Addr(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
}

var (
	modwinmm    = syscall.NewLazyDLL("winmm.dll")
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")

	procCreateEvent = modkernel32.NewProc("CreateEventW")
	procSetEvent    = modkernel32.NewProc("SetEvent")
)

func createEvent() (syscall.Handle, error) {
	r0, _, e0 := syscall.Syscall6(procCreateEvent.Addr(), 4, 0, 0, 0, 0, 0, 0)
	if r0 == 0 {
		return 0, syscall.Errno(e0)
	}
	return syscall.Handle(r0), nil
}

func setEvent(h syscall.Handle) error {
	r0, _, e0 := syscall.Syscall(procSetEvent.Addr(), 1, uintptr(h), 0, 0)
	if r0 == 0 {
		return syscall.Errno(e0)
	}
	return nil
}

func BenchmarkChanToSyscallPing(b *testing.B) {
	n := b.N
	ch := make(chan int)
	event, err := createEvent()
	if err != nil {
		b.Fatal(err)
	}
	go func() {
		for i := 0; i < n; i++ {
			syscall.WaitForSingleObject(event, syscall.INFINITE)
			ch <- 1
		}
	}()
	for i := 0; i < n; i++ {
		err := setEvent(event)
		if err != nil {
			b.Fatal(err)
		}
		<-ch
	}
}

func BenchmarkSyscallToSyscallPing(b *testing.B) {
	n := b.N
	event1, err := createEvent()
	if err != nil {
		b.Fatal(err)
	}
	event2, err := createEvent()
	if err != nil {
		b.Fatal(err)
	}
	go func() {
		for i := 0; i < n; i++ {
			syscall.WaitForSingleObject(event1, syscall.INFINITE)
			if err := setEvent(event2); err != nil {
				b.Errorf("Set event failed: %v", err)
				return
			}
		}
	}()
	for i := 0; i < n; i++ {
		if err := setEvent(event1); err != nil {
			b.Fatal(err)
		}
		if b.Failed() {
			break
		}
		syscall.WaitForSingleObject(event2, syscall.INFINITE)
	}
}

func BenchmarkChanToChanPing(b *testing.B) {
	n := b.N
	ch1 := make(chan int)
	ch2 := make(chan int)
	go func() {
		for i := 0; i < n; i++ {
			<-ch1
			ch2 <- 1
		}
	}()
	for i := 0; i < n; i++ {
		ch1 <- 1
		<-ch2
	}
}

func BenchmarkOsYield(b *testing.B) {
	for i := 0; i < b.N; i++ {
		runtime.OsYield()
	}
}

func BenchmarkRunningGoProgram(b *testing.B) {
	tmpdir := b.TempDir()

	src :=
"""




```