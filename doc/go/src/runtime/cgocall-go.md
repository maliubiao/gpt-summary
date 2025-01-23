Response:
Let's break down the thought process for analyzing this Go code snippet and generating the desired output.

**1. Understanding the Goal:**

The primary goal is to explain the functionality of the provided Go code (`go/src/runtime/cgocall.go`) and relate it to the concept of Cgo. The output needs to cover various aspects like the code's role, examples, potential errors, and command-line parameters (though this specific snippet doesn't directly handle command-line args).

**2. Initial Scan and Keyword Identification:**

The first step is to quickly read through the code and identify key terms and concepts. Words like "Cgo," "call," "callback," "frame," "stack," "syscall," "goroutine," `cgocall`, `asmcgocall`, `cgocallback`, `crosscall2`, `entersyscall`, `exitsyscall`, `lockOSThread`, `unlockOSThread`, and the accompanying comments immediately highlight the core purpose: managing interactions between Go and C code.

**3. Deciphering the Narrative Comments:**

The comments at the beginning are crucial. They provide a high-level explanation of the Cgo call and callback mechanisms. The comments describe the flow of execution when Go calls C and when C calls back into Go. This narrative becomes the foundation for understanding the individual functions' roles.

* **Go to C:**  Focus on `cgocall`, `asmcgocall`, the role of `m->g0` stack, and `entersyscall`/`exitsyscall`.
* **C to Go:** Focus on `GoF` (the C wrapper), `crosscall2`, `cgocallback`, `cgocallbackg`, the stack switching, and the `entersyscall`/`exitsyscall` pairing.

**4. Analyzing Key Functions:**

Now, examine the individual Go functions defined in the code:

* **`syscall_cgocaller`:**  Recognize it as a wrapper for making C library calls through Cgo. This is a good starting point for a simple example.
* **`cgocall`:**  This is the entry point for Go to C calls. Understand its responsibilities: checking Cgo availability, setting up the environment (like `entersyscall`), calling the assembly function (`asmcgocall`), and cleaning up (`exitsyscall`).
* **`callbackUpdateSystemStack`:**  Focus on its role in managing the `g0` stack for C callbacks, particularly the handling of `isextra` Ms and potentially inaccurate initial stack bounds.
* **`cgocallbackg`:** This is the core of the C to Go callback mechanism. Note the stack switching, locking the OS thread, calling `cgocallbackg1`, and the `reentersyscall` for returning to C.
* **`cgocallbackg1`:** This function performs the actual Go function invocation after the setup in `cgocallbackg`. Pay attention to the `defer unwindm` for panic handling.
* **`unwindm`:**  This function handles stack unwinding and resource cleanup during panics in C callbacks.
* **`badcgocallback` and `cgounimpl`:** These are error handlers indicating problems with Cgo execution.
* **`cgoCheckPointer`, `cgoCheckArg`, `cgoCheckUnknownPointer`, `cgoIsGoPointer`, `cgoInRange`, `cgoCheckResult`:**  These functions are related to Cgo pointer safety, ensuring that Go pointers passed to C do not point to movable Go memory.

**5. Constructing Examples:**

Based on the function analysis, create illustrative Go code examples:

* **Go calling C:**  Use the `syscall` package as a common example, demonstrating `syscall.Syscall` or a direct C function call through Cgo. Highlight the necessity of `import "C"`.
* **C calling Go:** Create a simple Go function and a corresponding C function signature. Show how the C code would call the generated Go function (the `GoF` mentioned in the comments). Include the necessary Cgo directives.

**6. Identifying Potential Pitfalls:**

Think about common mistakes developers might make when using Cgo:

* **Passing Go pointers to unpinned memory:** This is directly addressed by the `cgoCheckPointer` family of functions. Explain the issue and provide a concrete example.
* **Forgetting `import "C"`:** This is a fundamental requirement for Cgo.
* **Incorrect C function signatures:** Mismatched signatures will lead to runtime errors.

**7. Addressing Command-Line Parameters and Assumptions:**

In this specific snippet, there are no direct command-line parameter handling. However, the code relies on Cgo being enabled and configured correctly during the Go build process. Mentioning this implicit dependency is important. Also, the comments make assumptions about the target architecture and operating system (though the code includes checks for some specific OSes).

**8. Structuring the Output:**

Organize the information logically using headings and bullet points for clarity. Start with a general overview of the file's purpose, then detail the functionality of key functions, provide examples, discuss potential errors, and finally address command-line parameters and assumptions. Use clear and concise language.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focusing too much on the assembly language aspects. **Correction:** Shift focus to the high-level Go code and the purpose of the assembly calls.
* **Initial thought:** Providing very complex examples. **Correction:** Simplify examples to illustrate the core concepts without unnecessary complexity.
* **Missing key detail:**  Forgetting to explain the role of the `frame` structure. **Correction:**  Integrate the explanation of the `frame` in both Go-to-C and C-to-Go scenarios.
* **Overlooking error scenarios:**  Not initially highlighting the pointer safety issues. **Correction:**  Emphasize the role of the `cgoCheckPointer` functions and provide relevant examples of incorrect usage.

By following these steps and iteratively refining the understanding, the comprehensive and accurate explanation of the `cgocall.go` file can be constructed.
这段代码是Go语言运行时环境 `runtime` 包中 `cgocall.go` 文件的一部分，主要负责 **Go 语言与 C 语言代码之间的相互调用 (Cgo)**。它定义了 Go 代码调用 C 代码以及 C 代码回调 Go 代码的底层机制。

以下是该文件的主要功能：

1. **Go 调用 C (cgocall):**
   - 提供 `cgocall` 函数，这是 Go 代码调用 C 代码的入口点。
   - 负责在调用 C 代码前后进行必要的环境设置和清理工作，例如：
     - 使用 `entersyscall()` 通知调度器，即将进入系统调用，可能需要创建新的 M 来运行其他 Goroutine。
     - 调用汇编实现的 `asmcgocall`，该函数负责切换到专门用于执行 C 代码的 g0 栈。
     - 执行由 `cgo` 工具生成的 C 桥接函数（例如 `_cgo_Cfunc_f`），该函数实际调用目标 C 函数。
     - 使用 `exitsyscall()` 通知调度器，C 代码调用完成，可以继续运行 Go 代码。
     - 进行竞态检测相关的操作（如果启用了竞态检测）。
     - 使用 `KeepAlive` 确保传递给 C 代码的 Go 对象在 C 代码执行期间不会被垃圾回收。

2. **C 回调 Go (cgocallbackg, cgocallbackg1):**
   - 提供 `cgocallbackg` 和 `cgocallbackg1` 函数，用于处理 C 代码回调 Go 代码的情况。
   - 当 C 代码需要调用 Go 函数时，它会调用由 `cgo` 生成的 C 桥接函数（例如 `GoF`）。
   - 这个 C 桥接函数会调用 `crosscall2` (在汇编中定义)，它负责适配 C 和 Go 的调用约定。
   - `crosscall2` 会调用 `runtime.cgocallback` (也在汇编中定义)，它会切换到当前 Goroutine 的栈。
   - `runtime.cgocallback` 最终调用 `runtime.cgocallbackg`。
   - `cgocallbackg` 负责：
     - 使用 `exitsyscall()` 确保当前 M 可以运行 Go 代码。
     - 调用 `cgocallbackg1` 来执行实际的 Go 回调函数。
     - 在 `cgocallbackg1` 中，通过 `cgo` 生成的 Go 代码 (例如 `_cgoexp_GoF`) 将 C 传递的参数解包，并调用实际的 Go 函数。
     - 执行完毕后，进行清理工作，并使用 `reentersyscall` 返回到 C 代码的调用点。

3. **栈管理:**
   - 在 Go 调用 C 时，会切换到 M 的 g0 栈，这是一个由操作系统分配的栈，用于安全地执行 C 代码。
   - 在 C 回调 Go 时，会从 g0 栈切换回当前 Goroutine 的栈。
   - `callbackUpdateSystemStack` 函数用于更新 M 的 g0 栈的边界信息，特别是在处理 C 回调时，可能需要根据当前的栈指针来调整。

4. **Cgo 安全性检查 (cgoCheckPointer 系列函数):**
   - 提供一系列以 `cgoCheckPointer` 开头的函数，用于在 Go 代码传递指针给 C 代码时进行安全检查。
   - 这些检查旨在防止将指向未固定 (unpinned) 的 Go 堆内存的指针传递给 C 代码。如果 Go 的垃圾回收器移动了这些内存，C 代码持有的指针就会失效，导致程序崩溃或数据损坏。
   - `cgoCheckPointer` 会根据传递的参数类型，检查指针指向的内存是否包含其他 Go 指针，并决定是否需要检查整个数据结构。

5. **其他辅助功能:**
   - `unwindm`: 在 C 回调 Go 的过程中发生 panic 时，负责清理 M 的状态。
   - `badcgocallback`, `cgounimpl`:  用于处理错误的 Cgo 调用情况。
   - `racecgosync`:  用于竞态检测，表示 C 代码中可能存在的同步操作。

**可以推理出这是 Go 语言的 Cgo (C interoperation) 功能的实现。**

**Go 代码举例说明 (Go 调用 C):**

假设我们有一个 C 文件 `hello.c`:

```c
#include <stdio.h>

void say_hello(const char *name) {
    printf("Hello, %s from C!\n", name);
}
```

我们需要在 Go 代码中调用这个 C 函数。首先，创建一个 Go 文件 `main.go`:

```go
package main

// #cgo CFLAGS: -Wall -Werror
// #include "hello.h"
import "C"
import "fmt"

func main() {
	name := "Go"
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName)) // 记得释放 C 分配的内存

	C.say_hello(cName)
	fmt.Println("Back in Go!")
}
```

同时创建一个头文件 `hello.h`:

```c
#ifndef HELLO_H
#define HELLO_H

void say_hello(const char *name);

#endif
```

**假设的输入与输出:**

**输入:**  编译并运行 `main.go`

**输出:**

```
Hello, Go from C!
Back in Go!
```

**代码推理:**

1. `import "C"` 使得 Go 代码可以与 C 代码进行交互。
2. `// #include "hello.h"`  告诉 `cgo` 工具在编译时包含 `hello.h` 头文件。
3. `C.CString(name)` 将 Go 字符串转换为 C 风格的字符串。由于 C 使用 `malloc` 等函数分配内存，所以需要在 Go 中使用 `C.free` 释放。
4. `C.say_hello(cName)` 调用了 C 代码中的 `say_hello` 函数。
5. 当 `C.say_hello` 被调用时，`runtime.cgocall` (以及其调用的底层函数) 会负责切换到 g0 栈，调用 C 的桥接函数，最终执行 `say_hello`。
6. C 函数执行完毕后，控制权返回 Go 代码。

**Go 代码举例说明 (C 回调 Go):**

假设我们有一个 Go 函数，我们想让 C 代码能够调用它。修改 `main.go`:

```go
package main

// #cgo CFLAGS: -Wall -Werror

import "C"
import "fmt"
import "unsafe"

//export go_callback
func go_callback(name *C.char) {
	goName := C.GoString(name)
	fmt.Printf("Go callback received: Hello, %s from C!\n", goName)
}

func main() {
	fmt.Println("Go program started.")

	// 这里可以放一些让程序运行起来的代码，等待 C 代码的调用
	// 例如，使用 time.Sleep 模拟等待
	select {}
}
```

修改 `hello.c`，使其能够调用 Go 函数：

```c
#include <stdio.h>
#include <stdlib.h>

// 声明 Go 的回调函数 (由 cgo 生成)
extern void go_callback(const char *name);

void call_go_callback(const char *name) {
    printf("C code is calling Go callback...\n");
    go_callback(name);
    printf("C code finished calling Go callback.\n");
}

// 为了让 C 代码持续运行，等待 Go 程序的执行
int main() {
    call_go_callback("C");
    return 0;
}
```

**假设的输入与输出:**

**输入:**  先编译并运行 Go 程序，然后在另一个终端编译并运行 C 程序。

**Go 程序输出:**

```
Go program started.
Go callback received: Hello, C from C!
```

**C 程序输出:**

```
C code is calling Go callback...
C code finished calling Go callback.
```

**代码推理:**

1. `//export go_callback` 指令告诉 `cgo` 工具生成可以被 C 代码调用的 `go_callback` 函数的声明。
2. 在 C 代码中，我们使用 `extern void go_callback(const char *name);` 声明了 Go 的回调函数。
3. 当 C 代码调用 `go_callback("C")` 时，`runtime.cgocallbackg` (以及其调用的底层函数) 会负责切换到 Go 的 Goroutine 栈，执行 `go_callback` 函数。
4. `C.GoString(name)` 将 C 字符串转换回 Go 字符串。

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。命令行参数的处理通常发生在 `main` 包的 `main` 函数中，可以使用 `os.Args` 获取。但是，Cgo 的行为会受到一些构建时的环境变量的影响，例如 `CGO_ENABLED` 用于启用或禁用 Cgo。

**使用者易犯错的点:**

1. **内存管理:**
   - **错误示例:**  在 Go 中将一个 Go 字符串直接传递给 C 函数，而不进行转换。C 函数可能会尝试修改这块内存，导致 Go 程序的崩溃。
   ```go
   package main

   // #include <stdio.h>
   // void print_string(char* s) { printf("%s\n", s); }
   import "C"
   import "fmt"

   func main() {
       goStr := "Hello"
       C.print_string((*C.char)(unsafe.Pointer(&[]byte(goStr)[0]))) // 错误：直接传递 Go 字符串的指针
       fmt.Println("Done")
   }
   ```
   - **正确做法:** 使用 `C.CString` 将 Go 字符串转换为 C 字符串，并在使用完毕后使用 `C.free` 释放内存。

2. **Go 指针传递给 C:**
   - **错误示例:** 将指向 Go 堆内存的指针直接传递给 C 代码，并且没有确保这块内存不会被 Go 的垃圾回收器移动。
   ```go
   package main

   // #include <stdint.h>
   // typedef struct { int val; } MyStruct;
   // void process_struct(MyStruct* s) { s->val = 100; }
   import "C"
   import "fmt"

   type MyStruct struct {
       Val int
   }

   func main() {
       s := MyStruct{Val: 50}
       C.process_struct((*C.MyStruct)(unsafe.Pointer(&s))) // 潜在错误：s 可能被 GC 移动
       fmt.Println(s.Val)
   }
   ```
   - **正确做法:**  对于需要在 C 代码中长期使用的 Go 对象，需要考虑使用 `runtime.KeepAlive` 或者其他方式来确保对象不会被垃圾回收。通常，最佳实践是避免直接传递 Go 指针，而是传递数据的副本或者使用 C 分配的内存。

3. **C 回调 Go 的线程安全:**
   - 如果 C 代码在多个线程中同时回调 Go 代码，需要确保 Go 的回调函数是线程安全的，避免数据竞争。

4. **忘记 `import "C"`:**
   - 如果没有 `import "C"`，Cgo 的功能将无法使用。

5. **C 代码中的错误导致 Go 程序崩溃:**
   - C 代码中的错误（例如空指针解引用、内存泄漏）可能会导致整个 Go 程序崩溃，因为它们运行在同一个进程中。

总而言之，`go/src/runtime/cgocall.go` 是 Go 语言 Cgo 功能的核心实现，它定义了 Go 和 C 代码之间相互调用的底层机制，并提供了一些安全检查来降低 Cgo 使用中的风险。理解这段代码有助于深入了解 Go 语言的运行时原理以及 Cgo 的工作方式。

### 提示词
```
这是路径为go/src/runtime/cgocall.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Cgo call and callback support.
//
// To call into the C function f from Go, the cgo-generated code calls
// runtime.cgocall(_cgo_Cfunc_f, frame), where _cgo_Cfunc_f is a
// gcc-compiled function written by cgo.
//
// runtime.cgocall (below) calls entersyscall so as not to block
// other goroutines or the garbage collector, and then calls
// runtime.asmcgocall(_cgo_Cfunc_f, frame).
//
// runtime.asmcgocall (in asm_$GOARCH.s) switches to the m->g0 stack
// (assumed to be an operating system-allocated stack, so safe to run
// gcc-compiled code on) and calls _cgo_Cfunc_f(frame).
//
// _cgo_Cfunc_f invokes the actual C function f with arguments
// taken from the frame structure, records the results in the frame,
// and returns to runtime.asmcgocall.
//
// After it regains control, runtime.asmcgocall switches back to the
// original g (m->curg)'s stack and returns to runtime.cgocall.
//
// After it regains control, runtime.cgocall calls exitsyscall, which blocks
// until this m can run Go code without violating the $GOMAXPROCS limit,
// and then unlocks g from m.
//
// The above description skipped over the possibility of the gcc-compiled
// function f calling back into Go. If that happens, we continue down
// the rabbit hole during the execution of f.
//
// To make it possible for gcc-compiled C code to call a Go function p.GoF,
// cgo writes a gcc-compiled function named GoF (not p.GoF, since gcc doesn't
// know about packages).  The gcc-compiled C function f calls GoF.
//
// GoF initializes "frame", a structure containing all of its
// arguments and slots for p.GoF's results. It calls
// crosscall2(_cgoexp_GoF, frame, framesize, ctxt) using the gcc ABI.
//
// crosscall2 (in cgo/asm_$GOARCH.s) is a four-argument adapter from
// the gcc function call ABI to the gc function call ABI. At this
// point we're in the Go runtime, but we're still running on m.g0's
// stack and outside the $GOMAXPROCS limit. crosscall2 calls
// runtime.cgocallback(_cgoexp_GoF, frame, ctxt) using the gc ABI.
// (crosscall2's framesize argument is no longer used, but there's one
// case where SWIG calls crosscall2 directly and expects to pass this
// argument. See _cgo_panic.)
//
// runtime.cgocallback (in asm_$GOARCH.s) switches from m.g0's stack
// to the original g (m.curg)'s stack, on which it calls
// runtime.cgocallbackg(_cgoexp_GoF, frame, ctxt). As part of the
// stack switch, runtime.cgocallback saves the current SP as
// m.g0.sched.sp, so that any use of m.g0's stack during the execution
// of the callback will be done below the existing stack frames.
// Before overwriting m.g0.sched.sp, it pushes the old value on the
// m.g0 stack, so that it can be restored later.
//
// runtime.cgocallbackg (below) is now running on a real goroutine
// stack (not an m.g0 stack).  First it calls runtime.exitsyscall, which will
// block until the $GOMAXPROCS limit allows running this goroutine.
// Once exitsyscall has returned, it is safe to do things like call the memory
// allocator or invoke the Go callback function.  runtime.cgocallbackg
// first defers a function to unwind m.g0.sched.sp, so that if p.GoF
// panics, m.g0.sched.sp will be restored to its old value: the m.g0 stack
// and the m.curg stack will be unwound in lock step.
// Then it calls _cgoexp_GoF(frame).
//
// _cgoexp_GoF, which was generated by cmd/cgo, unpacks the arguments
// from frame, calls p.GoF, writes the results back to frame, and
// returns. Now we start unwinding this whole process.
//
// runtime.cgocallbackg pops but does not execute the deferred
// function to unwind m.g0.sched.sp, calls runtime.entersyscall, and
// returns to runtime.cgocallback.
//
// After it regains control, runtime.cgocallback switches back to
// m.g0's stack (the pointer is still in m.g0.sched.sp), restores the old
// m.g0.sched.sp value from the stack, and returns to crosscall2.
//
// crosscall2 restores the callee-save registers for gcc and returns
// to GoF, which unpacks any result values and returns to f.

package runtime

import (
	"internal/abi"
	"internal/goarch"
	"internal/goexperiment"
	"internal/runtime/sys"
	"unsafe"
)

// Addresses collected in a cgo backtrace when crashing.
// Length must match arg.Max in x_cgo_callers in runtime/cgo/gcc_traceback.c.
type cgoCallers [32]uintptr

// argset matches runtime/cgo/linux_syscall.c:argset_t
type argset struct {
	args   unsafe.Pointer
	retval uintptr
}

// wrapper for syscall package to call cgocall for libc (cgo) calls.
//
//go:linkname syscall_cgocaller syscall.cgocaller
//go:nosplit
//go:uintptrescapes
func syscall_cgocaller(fn unsafe.Pointer, args ...uintptr) uintptr {
	as := argset{args: unsafe.Pointer(&args[0])}
	cgocall(fn, unsafe.Pointer(&as))
	return as.retval
}

var ncgocall uint64 // number of cgo calls in total for dead m

// Call from Go to C.
//
// This must be nosplit because it's used for syscalls on some
// platforms. Syscalls may have untyped arguments on the stack, so
// it's not safe to grow or scan the stack.
//
// cgocall should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/ebitengine/purego
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname cgocall
//go:nosplit
func cgocall(fn, arg unsafe.Pointer) int32 {
	if !iscgo && GOOS != "solaris" && GOOS != "illumos" && GOOS != "windows" {
		throw("cgocall unavailable")
	}

	if fn == nil {
		throw("cgocall nil")
	}

	if raceenabled {
		racereleasemerge(unsafe.Pointer(&racecgosync))
	}

	mp := getg().m
	mp.ncgocall++

	// Reset traceback.
	mp.cgoCallers[0] = 0

	// Announce we are entering a system call
	// so that the scheduler knows to create another
	// M to run goroutines while we are in the
	// foreign code.
	//
	// The call to asmcgocall is guaranteed not to
	// grow the stack and does not allocate memory,
	// so it is safe to call while "in a system call", outside
	// the $GOMAXPROCS accounting.
	//
	// fn may call back into Go code, in which case we'll exit the
	// "system call", run the Go code (which may grow the stack),
	// and then re-enter the "system call" reusing the PC and SP
	// saved by entersyscall here.
	entersyscall()

	// Tell asynchronous preemption that we're entering external
	// code. We do this after entersyscall because this may block
	// and cause an async preemption to fail, but at this point a
	// sync preemption will succeed (though this is not a matter
	// of correctness).
	osPreemptExtEnter(mp)

	mp.incgo = true
	// We use ncgo as a check during execution tracing for whether there is
	// any C on the call stack, which there will be after this point. If
	// there isn't, we can use frame pointer unwinding to collect call
	// stacks efficiently. This will be the case for the first Go-to-C call
	// on a stack, so it's preferable to update it here, after we emit a
	// trace event in entersyscall above.
	mp.ncgo++

	errno := asmcgocall(fn, arg)

	// Update accounting before exitsyscall because exitsyscall may
	// reschedule us on to a different M.
	mp.incgo = false
	mp.ncgo--

	osPreemptExtExit(mp)

	// Save current syscall parameters, so m.winsyscall can be
	// used again if callback decide to make syscall.
	winsyscall := mp.winsyscall

	exitsyscall()

	getg().m.winsyscall = winsyscall

	// Note that raceacquire must be called only after exitsyscall has
	// wired this M to a P.
	if raceenabled {
		raceacquire(unsafe.Pointer(&racecgosync))
	}

	// From the garbage collector's perspective, time can move
	// backwards in the sequence above. If there's a callback into
	// Go code, GC will see this function at the call to
	// asmcgocall. When the Go call later returns to C, the
	// syscall PC/SP is rolled back and the GC sees this function
	// back at the call to entersyscall. Normally, fn and arg
	// would be live at entersyscall and dead at asmcgocall, so if
	// time moved backwards, GC would see these arguments as dead
	// and then live. Prevent these undead arguments from crashing
	// GC by forcing them to stay live across this time warp.
	KeepAlive(fn)
	KeepAlive(arg)
	KeepAlive(mp)

	return errno
}

// Set or reset the system stack bounds for a callback on sp.
//
// Must be nosplit because it is called by needm prior to fully initializing
// the M.
//
//go:nosplit
func callbackUpdateSystemStack(mp *m, sp uintptr, signal bool) {
	g0 := mp.g0

	if !mp.isextra {
		// We allocated the stack for standard Ms. Don't replace the
		// stack bounds with estimated ones when we already initialized
		// with the exact ones.
		return
	}

	inBound := sp > g0.stack.lo && sp <= g0.stack.hi
	if inBound && mp.g0StackAccurate {
		// This M has called into Go before and has the stack bounds
		// initialized. We have the accurate stack bounds, and the SP
		// is in bounds. We expect it continues to run within the same
		// bounds.
		return
	}

	// We don't have an accurate stack bounds (either it never calls
	// into Go before, or we couldn't get the accurate bounds), or the
	// current SP is not within the previous bounds (the stack may have
	// changed between calls). We need to update the stack bounds.
	//
	// N.B. we need to update the stack bounds even if SP appears to
	// already be in bounds, if our bounds are estimated dummy bounds
	// (below). We may be in a different region within the same actual
	// stack bounds, but our estimates were not accurate. Or the actual
	// stack bounds could have shifted but still have partial overlap with
	// our dummy bounds. If we failed to update in that case, we could find
	// ourselves seemingly called near the bottom of the stack bounds, where
	// we quickly run out of space.

	// Set the stack bounds to match the current stack. If we don't
	// actually know how big the stack is, like we don't know how big any
	// scheduling stack is, but we assume there's at least 32 kB. If we
	// can get a more accurate stack bound from pthread, use that, provided
	// it actually contains SP.
	g0.stack.hi = sp + 1024
	g0.stack.lo = sp - 32*1024
	mp.g0StackAccurate = false
	if !signal && _cgo_getstackbound != nil {
		// Don't adjust if called from the signal handler.
		// We are on the signal stack, not the pthread stack.
		// (We could get the stack bounds from sigaltstack, but
		// we're getting out of the signal handler very soon
		// anyway. Not worth it.)
		var bounds [2]uintptr
		asmcgocall(_cgo_getstackbound, unsafe.Pointer(&bounds))
		// getstackbound is an unsupported no-op on Windows.
		//
		// On Unix systems, if the API to get accurate stack bounds is
		// not available, it returns zeros.
		//
		// Don't use these bounds if they don't contain SP. Perhaps we
		// were called by something not using the standard thread
		// stack.
		if bounds[0] != 0 && sp > bounds[0] && sp <= bounds[1] {
			g0.stack.lo = bounds[0]
			g0.stack.hi = bounds[1]
			mp.g0StackAccurate = true
		}
	}
	g0.stackguard0 = g0.stack.lo + stackGuard
	g0.stackguard1 = g0.stackguard0
}

// Call from C back to Go. fn must point to an ABIInternal Go entry-point.
//
//go:nosplit
func cgocallbackg(fn, frame unsafe.Pointer, ctxt uintptr) {
	gp := getg()
	if gp != gp.m.curg {
		println("runtime: bad g in cgocallback")
		exit(2)
	}

	sp := gp.m.g0.sched.sp // system sp saved by cgocallback.
	oldStack := gp.m.g0.stack
	oldAccurate := gp.m.g0StackAccurate
	callbackUpdateSystemStack(gp.m, sp, false)

	// The call from C is on gp.m's g0 stack, so we must ensure
	// that we stay on that M. We have to do this before calling
	// exitsyscall, since it would otherwise be free to move us to
	// a different M. The call to unlockOSThread is in this function
	// after cgocallbackg1, or in the case of panicking, in unwindm.
	lockOSThread()

	checkm := gp.m

	// Save current syscall parameters, so m.winsyscall can be
	// used again if callback decide to make syscall.
	winsyscall := gp.m.winsyscall

	// entersyscall saves the caller's SP to allow the GC to trace the Go
	// stack. However, since we're returning to an earlier stack frame and
	// need to pair with the entersyscall() call made by cgocall, we must
	// save syscall* and let reentersyscall restore them.
	//
	// Note: savedsp and savedbp MUST be held in locals as an unsafe.Pointer.
	// When we call into Go, the stack is free to be moved. If these locals
	// aren't visible in the stack maps, they won't get updated properly,
	// and will end up being stale when restored by reentersyscall.
	savedsp := unsafe.Pointer(gp.syscallsp)
	savedpc := gp.syscallpc
	savedbp := unsafe.Pointer(gp.syscallbp)
	exitsyscall() // coming out of cgo call
	gp.m.incgo = false
	if gp.m.isextra {
		gp.m.isExtraInC = false
	}

	osPreemptExtExit(gp.m)

	if gp.nocgocallback {
		panic("runtime: function marked with #cgo nocallback called back into Go")
	}

	cgocallbackg1(fn, frame, ctxt)

	// At this point we're about to call unlockOSThread.
	// The following code must not change to a different m.
	// This is enforced by checking incgo in the schedule function.
	gp.m.incgo = true
	unlockOSThread()

	if gp.m.isextra {
		gp.m.isExtraInC = true
	}

	if gp.m != checkm {
		throw("m changed unexpectedly in cgocallbackg")
	}

	osPreemptExtEnter(gp.m)

	// going back to cgo call
	reentersyscall(savedpc, uintptr(savedsp), uintptr(savedbp))

	gp.m.winsyscall = winsyscall

	// Restore the old g0 stack bounds
	gp.m.g0.stack = oldStack
	gp.m.g0.stackguard0 = oldStack.lo + stackGuard
	gp.m.g0.stackguard1 = gp.m.g0.stackguard0
	gp.m.g0StackAccurate = oldAccurate
}

func cgocallbackg1(fn, frame unsafe.Pointer, ctxt uintptr) {
	gp := getg()

	if gp.m.needextram || extraMWaiters.Load() > 0 {
		gp.m.needextram = false
		systemstack(newextram)
	}

	if ctxt != 0 {
		s := append(gp.cgoCtxt, ctxt)

		// Now we need to set gp.cgoCtxt = s, but we could get
		// a SIGPROF signal while manipulating the slice, and
		// the SIGPROF handler could pick up gp.cgoCtxt while
		// tracing up the stack.  We need to ensure that the
		// handler always sees a valid slice, so set the
		// values in an order such that it always does.
		p := (*slice)(unsafe.Pointer(&gp.cgoCtxt))
		atomicstorep(unsafe.Pointer(&p.array), unsafe.Pointer(&s[0]))
		p.cap = cap(s)
		p.len = len(s)

		defer func(gp *g) {
			// Decrease the length of the slice by one, safely.
			p := (*slice)(unsafe.Pointer(&gp.cgoCtxt))
			p.len--
		}(gp)
	}

	if gp.m.ncgo == 0 {
		// The C call to Go came from a thread not currently running
		// any Go. In the case of -buildmode=c-archive or c-shared,
		// this call may be coming in before package initialization
		// is complete. Wait until it is.
		<-main_init_done
	}

	// Check whether the profiler needs to be turned on or off; this route to
	// run Go code does not use runtime.execute, so bypasses the check there.
	hz := sched.profilehz
	if gp.m.profilehz != hz {
		setThreadCPUProfiler(hz)
	}

	// Add entry to defer stack in case of panic.
	restore := true
	defer unwindm(&restore)

	var ditAlreadySet bool
	if debug.dataindependenttiming == 1 && gp.m.isextra {
		// We only need to enable DIT for threads that were created by C, as it
		// should already by enabled on threads that were created by Go.
		ditAlreadySet = sys.EnableDIT()
	}

	if raceenabled {
		raceacquire(unsafe.Pointer(&racecgosync))
	}

	// Invoke callback. This function is generated by cmd/cgo and
	// will unpack the argument frame and call the Go function.
	var cb func(frame unsafe.Pointer)
	cbFV := funcval{uintptr(fn)}
	*(*unsafe.Pointer)(unsafe.Pointer(&cb)) = noescape(unsafe.Pointer(&cbFV))
	cb(frame)

	if raceenabled {
		racereleasemerge(unsafe.Pointer(&racecgosync))
	}

	if debug.dataindependenttiming == 1 && !ditAlreadySet {
		// Only unset DIT if it wasn't already enabled when cgocallback was called.
		sys.DisableDIT()
	}

	// Do not unwind m->g0->sched.sp.
	// Our caller, cgocallback, will do that.
	restore = false
}

func unwindm(restore *bool) {
	if *restore {
		// Restore sp saved by cgocallback during
		// unwind of g's stack (see comment at top of file).
		mp := acquirem()
		sched := &mp.g0.sched
		sched.sp = *(*uintptr)(unsafe.Pointer(sched.sp + alignUp(sys.MinFrameSize, sys.StackAlign)))

		// Do the accounting that cgocall will not have a chance to do
		// during an unwind.
		//
		// In the case where a Go call originates from C, ncgo is 0
		// and there is no matching cgocall to end.
		if mp.ncgo > 0 {
			mp.incgo = false
			mp.ncgo--
			osPreemptExtExit(mp)
		}

		// Undo the call to lockOSThread in cgocallbackg, only on the
		// panicking path. In normal return case cgocallbackg will call
		// unlockOSThread, ensuring no preemption point after the unlock.
		// Here we don't need to worry about preemption, because we're
		// panicking out of the callback and unwinding the g0 stack,
		// instead of reentering cgo (which requires the same thread).
		unlockOSThread()

		releasem(mp)
	}
}

// called from assembly.
func badcgocallback() {
	throw("misaligned stack in cgocallback")
}

// called from (incomplete) assembly.
func cgounimpl() {
	throw("cgo not implemented")
}

var racecgosync uint64 // represents possible synchronization in C code

// Pointer checking for cgo code.

// We want to detect all cases where a program that does not use
// unsafe makes a cgo call passing a Go pointer to memory that
// contains an unpinned Go pointer. Here a Go pointer is defined as a
// pointer to memory allocated by the Go runtime. Programs that use
// unsafe can evade this restriction easily, so we don't try to catch
// them. The cgo program will rewrite all possibly bad pointer
// arguments to call cgoCheckPointer, where we can catch cases of a Go
// pointer pointing to an unpinned Go pointer.

// Complicating matters, taking the address of a slice or array
// element permits the C program to access all elements of the slice
// or array. In that case we will see a pointer to a single element,
// but we need to check the entire data structure.

// The cgoCheckPointer call takes additional arguments indicating that
// it was called on an address expression. An additional argument of
// true means that it only needs to check a single element. An
// additional argument of a slice or array means that it needs to
// check the entire slice/array, but nothing else. Otherwise, the
// pointer could be anything, and we check the entire heap object,
// which is conservative but safe.

// When and if we implement a moving garbage collector,
// cgoCheckPointer will pin the pointer for the duration of the cgo
// call.  (This is necessary but not sufficient; the cgo program will
// also have to change to pin Go pointers that cannot point to Go
// pointers.)

// cgoCheckPointer checks if the argument contains a Go pointer that
// points to an unpinned Go pointer, and panics if it does.
func cgoCheckPointer(ptr any, arg any) {
	if !goexperiment.CgoCheck2 && debug.cgocheck == 0 {
		return
	}

	ep := efaceOf(&ptr)
	t := ep._type

	top := true
	if arg != nil && (t.Kind_&abi.KindMask == abi.Pointer || t.Kind_&abi.KindMask == abi.UnsafePointer) {
		p := ep.data
		if t.Kind_&abi.KindDirectIface == 0 {
			p = *(*unsafe.Pointer)(p)
		}
		if p == nil || !cgoIsGoPointer(p) {
			return
		}
		aep := efaceOf(&arg)
		switch aep._type.Kind_ & abi.KindMask {
		case abi.Bool:
			if t.Kind_&abi.KindMask == abi.UnsafePointer {
				// We don't know the type of the element.
				break
			}
			pt := (*ptrtype)(unsafe.Pointer(t))
			cgoCheckArg(pt.Elem, p, true, false, cgoCheckPointerFail)
			return
		case abi.Slice:
			// Check the slice rather than the pointer.
			ep = aep
			t = ep._type
		case abi.Array:
			// Check the array rather than the pointer.
			// Pass top as false since we have a pointer
			// to the array.
			ep = aep
			t = ep._type
			top = false
		case abi.Pointer:
			// The Go code is indexing into a pointer to an array,
			// and we have been passed the pointer-to-array.
			// Check the array rather than the pointer.
			pt := (*abi.PtrType)(unsafe.Pointer(aep._type))
			t = pt.Elem
			if t.Kind_&abi.KindMask != abi.Array {
				throw("can't happen")
			}
			ep = aep
			top = false
		default:
			throw("can't happen")
		}
	}

	cgoCheckArg(t, ep.data, t.Kind_&abi.KindDirectIface == 0, top, cgoCheckPointerFail)
}

const cgoCheckPointerFail = "cgo argument has Go pointer to unpinned Go pointer"
const cgoResultFail = "cgo result is unpinned Go pointer or points to unpinned Go pointer"

// cgoCheckArg is the real work of cgoCheckPointer. The argument p
// is either a pointer to the value (of type t), or the value itself,
// depending on indir. The top parameter is whether we are at the top
// level, where Go pointers are allowed. Go pointers to pinned objects are
// allowed as long as they don't reference other unpinned pointers.
func cgoCheckArg(t *_type, p unsafe.Pointer, indir, top bool, msg string) {
	if !t.Pointers() || p == nil {
		// If the type has no pointers there is nothing to do.
		return
	}

	switch t.Kind_ & abi.KindMask {
	default:
		throw("can't happen")
	case abi.Array:
		at := (*arraytype)(unsafe.Pointer(t))
		if !indir {
			if at.Len != 1 {
				throw("can't happen")
			}
			cgoCheckArg(at.Elem, p, at.Elem.Kind_&abi.KindDirectIface == 0, top, msg)
			return
		}
		for i := uintptr(0); i < at.Len; i++ {
			cgoCheckArg(at.Elem, p, true, top, msg)
			p = add(p, at.Elem.Size_)
		}
	case abi.Chan, abi.Map:
		// These types contain internal pointers that will
		// always be allocated in the Go heap. It's never OK
		// to pass them to C.
		panic(errorString(msg))
	case abi.Func:
		if indir {
			p = *(*unsafe.Pointer)(p)
		}
		if !cgoIsGoPointer(p) {
			return
		}
		panic(errorString(msg))
	case abi.Interface:
		it := *(**_type)(p)
		if it == nil {
			return
		}
		// A type known at compile time is OK since it's
		// constant. A type not known at compile time will be
		// in the heap and will not be OK.
		if inheap(uintptr(unsafe.Pointer(it))) {
			panic(errorString(msg))
		}
		p = *(*unsafe.Pointer)(add(p, goarch.PtrSize))
		if !cgoIsGoPointer(p) {
			return
		}
		if !top && !isPinned(p) {
			panic(errorString(msg))
		}
		cgoCheckArg(it, p, it.Kind_&abi.KindDirectIface == 0, false, msg)
	case abi.Slice:
		st := (*slicetype)(unsafe.Pointer(t))
		s := (*slice)(p)
		p = s.array
		if p == nil || !cgoIsGoPointer(p) {
			return
		}
		if !top && !isPinned(p) {
			panic(errorString(msg))
		}
		if !st.Elem.Pointers() {
			return
		}
		for i := 0; i < s.cap; i++ {
			cgoCheckArg(st.Elem, p, true, false, msg)
			p = add(p, st.Elem.Size_)
		}
	case abi.String:
		ss := (*stringStruct)(p)
		if !cgoIsGoPointer(ss.str) {
			return
		}
		if !top && !isPinned(ss.str) {
			panic(errorString(msg))
		}
	case abi.Struct:
		st := (*structtype)(unsafe.Pointer(t))
		if !indir {
			if len(st.Fields) != 1 {
				throw("can't happen")
			}
			cgoCheckArg(st.Fields[0].Typ, p, st.Fields[0].Typ.Kind_&abi.KindDirectIface == 0, top, msg)
			return
		}
		for _, f := range st.Fields {
			if !f.Typ.Pointers() {
				continue
			}
			cgoCheckArg(f.Typ, add(p, f.Offset), true, top, msg)
		}
	case abi.Pointer, abi.UnsafePointer:
		if indir {
			p = *(*unsafe.Pointer)(p)
			if p == nil {
				return
			}
		}

		if !cgoIsGoPointer(p) {
			return
		}
		if !top && !isPinned(p) {
			panic(errorString(msg))
		}

		cgoCheckUnknownPointer(p, msg)
	}
}

// cgoCheckUnknownPointer is called for an arbitrary pointer into Go
// memory. It checks whether that Go memory contains any other
// pointer into unpinned Go memory. If it does, we panic.
// The return values are unused but useful to see in panic tracebacks.
func cgoCheckUnknownPointer(p unsafe.Pointer, msg string) (base, i uintptr) {
	if inheap(uintptr(p)) {
		b, span, _ := findObject(uintptr(p), 0, 0)
		base = b
		if base == 0 {
			return
		}
		tp := span.typePointersOfUnchecked(base)
		for {
			var addr uintptr
			if tp, addr = tp.next(base + span.elemsize); addr == 0 {
				break
			}
			pp := *(*unsafe.Pointer)(unsafe.Pointer(addr))
			if cgoIsGoPointer(pp) && !isPinned(pp) {
				panic(errorString(msg))
			}
		}
		return
	}

	for _, datap := range activeModules() {
		if cgoInRange(p, datap.data, datap.edata) || cgoInRange(p, datap.bss, datap.ebss) {
			// We have no way to know the size of the object.
			// We have to assume that it might contain a pointer.
			panic(errorString(msg))
		}
		// In the text or noptr sections, we know that the
		// pointer does not point to a Go pointer.
	}

	return
}

// cgoIsGoPointer reports whether the pointer is a Go pointer--a
// pointer to Go memory. We only care about Go memory that might
// contain pointers.
//
//go:nosplit
//go:nowritebarrierrec
func cgoIsGoPointer(p unsafe.Pointer) bool {
	if p == nil {
		return false
	}

	if inHeapOrStack(uintptr(p)) {
		return true
	}

	for _, datap := range activeModules() {
		if cgoInRange(p, datap.data, datap.edata) || cgoInRange(p, datap.bss, datap.ebss) {
			return true
		}
	}

	return false
}

// cgoInRange reports whether p is between start and end.
//
//go:nosplit
//go:nowritebarrierrec
func cgoInRange(p unsafe.Pointer, start, end uintptr) bool {
	return start <= uintptr(p) && uintptr(p) < end
}

// cgoCheckResult is called to check the result parameter of an
// exported Go function. It panics if the result is or contains any
// other pointer into unpinned Go memory.
func cgoCheckResult(val any) {
	if !goexperiment.CgoCheck2 && debug.cgocheck == 0 {
		return
	}

	ep := efaceOf(&val)
	t := ep._type
	cgoCheckArg(t, ep.data, t.Kind_&abi.KindDirectIface == 0, false, cgoResultFail)
}
```