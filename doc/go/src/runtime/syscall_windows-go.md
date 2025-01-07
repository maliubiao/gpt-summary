Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Scan and Keyword Spotting:**

The first step is a quick scan for recognizable keywords and structures. I see:

* `package runtime`:  Immediately tells me this is part of the Go runtime itself, dealing with low-level operations.
* `import`:  Shows dependencies on `internal/abi`, `internal/goarch`, and `unsafe`. These hints point towards ABI (Application Binary Interface) handling, architecture-specific details, and direct memory manipulation.
* `cbs struct`: A struct named `cbs` with fields like `lock`, `ctxt`, `index`, and `n`. The presence of a `lock` suggests concurrency control. The names `ctxt` and `index` could relate to storing and retrieving data, perhaps related to callbacks.
* `func cbsLock()`, `func cbsUnlock()`:  Explicit locking functions, reinforcing the concurrency theme.
* `winCallback struct`:  Clearly related to callbacks on Windows, containing `fn` (function), `retPop`, and `abiMap`.
* `abiPart`, `abiDesc`: These strongly suggest the code is dealing with different calling conventions or ABIs, and how to translate between them.
* `compileCallback`: A crucial function name, suggesting the process of turning a Go function into something callable from C.
* `callbackasm`, `callbackWrap`:  More callback-related names, hinting at the assembly-level interaction.
* `syscall_loadsystemlibrary`, `syscall_loadlibrary`, `syscall_getprocaddress`, `syscall_Syscall*`, `syscall_SyscallN`:  These are clearly related to making system calls on Windows.
* `go:linkname`: This directive links Go identifiers to external (often syscall) implementations.
* `go:nosplit`: This directive is important in the runtime and indicates that these functions should not be preempted.

**2. Deductive Reasoning (Focusing on Key Structures):**

* **`cbs` structure:** The `cbs` struct appears to be a central registry for Go callbacks that can be called from C/Windows. The `index` map likely stores the association between a Go function and its callback index. The `ctxt` array likely holds the details (`winCallback`) of each registered callback. The lock ensures thread safety.

* **`winCallback`, `abiPart`, `abiDesc`:**  These are clearly related to managing different calling conventions. The `abiDesc` seems to define how to translate data between the C calling convention and the Go calling convention. `abiPart` appears to be a smaller unit within this translation. The `retPop` field suggests handling stack cleanup for `cdecl`.

* **`compileCallback`:**  This function is likely the core of the callback mechanism. It takes a Go function and `cdecl` flag, analyzes its arguments, generates an `abiDesc`, registers the callback in the `cbs` structure, and returns an address that can be used as a C function pointer. The check for existing callbacks in `cbs.index` indicates it tries to reuse existing wrappers.

* **`callbackasm` and `callbackWrap`:** `callbackasm` is likely a small assembly stub that receives control from the C world. It probably uses the callback index to jump to the correct `callbackWrap` function. `callbackWrap` then uses the stored `abiDesc` to translate arguments from the C calling convention to the Go calling convention, calls the actual Go function, and then translates the result back.

* **`syscall_*` functions:**  These are wrappers around the Windows system call mechanism. They take the system call number and arguments and invoke the actual system call. The `go:linkname` directive connects these to the `syscall` package.

**3. Putting it Together and Inferring Functionality:**

Based on the identified components, I can infer the following overall functionality:

* **Callback Mechanism:** The primary goal of this code is to allow Go functions to be called from Windows APIs (which expect C-style function pointers). This involves:
    * Registering Go functions as callbacks.
    * Generating a thunk (small piece of code) that acts as an intermediary.
    * Handling the translation of arguments and return values between C and Go calling conventions.
    * Managing concurrency to ensure thread-safe access to the callback registry.

* **System Call Interface:** The code also provides low-level functions for making system calls directly to the Windows kernel. This is essential for interacting with the operating system.

**4. Generating Examples (Mental Walkthrough):**

* **Callback Example:** I can imagine a scenario where a Go program needs to register a function to be called when a Windows event occurs. The `compileCallback` function would be used to get a C-compatible function pointer for this Go function. I'd need to consider different calling conventions (`cdecl` vs. `stdcall`).

* **System Call Example:**  Calling `CreateFileW` or `ReadFile` are common examples of system calls. The `syscall_SyscallN` family of functions provides the interface for this.

**5. Identifying Potential Pitfalls:**

* **Incorrect Calling Convention:**  Mixing up `cdecl` and `stdcall` on x86 would lead to stack corruption.
* **Incorrect Argument Types:**  The `compileCallback` function performs checks on argument and return types. Passing functions with unsupported signatures would cause panics.
* **Too Many Callbacks:** The `cbs` struct has a fixed size, so registering too many callbacks would lead to an error.

**6. Structuring the Answer:**

Finally, I organize the findings into the requested format:

* List the functionalities clearly.
* Provide concrete Go code examples to illustrate the callback and system call mechanisms, including assumptions about inputs and outputs.
* Explain the handling of the `cdecl` parameter.
* Point out the common pitfalls with illustrative examples.

This systematic approach, combining keyword recognition, deductive reasoning, and mental examples, allows for a comprehensive understanding of the provided code snippet. The focus is on understanding *what* the code does and *why* it's structured the way it is.
这段代码是 Go 语言运行时环境（runtime）中用于支持在 Windows 平台上进行系统调用和回调函数处理的关键部分。它主要实现了以下功能：

**1. Go 函数到 C 函数指针的转换 (Callbacks):**

   - **功能:** 允许将 Go 语言函数转换为 C 语言风格的函数指针，以便可以将 Go 函数作为回调函数传递给 Windows API。Windows API 经常需要接收函数指针作为参数，以便在特定事件发生时调用这些函数。
   - **实现:** `compileCallback` 函数是实现这个功能的核心。它接收一个 Go 函数 (`eface`) 和一个 `cdecl` 布尔值作为输入，返回一个 `uintptr`，这个 `uintptr` 可以被解释为 C 函数指针。
   - **ABI 转换:**  由于 Go 和 C 的函数调用约定（Application Binary Interface, ABI）不同，`compileCallback` 还需要处理参数和返回值的转换。`abiDesc` 结构体及其相关方法 (`assignArg`, `tryRegAssignArg`, `assignReg`) 负责描述和执行这种 ABI 转换。
   - **回调注册:** `cbs` 结构体用于存储所有已注册的 Go 回调函数的信息。`compileCallback` 会将转换后的 Go 函数信息存储在 `cbs` 中，并返回一个指向 `callbackasm` 函数的地址，这个地址会根据注册的顺序进行调整。
   - **`callbackasm` 和 `callbackWrap`:** `callbackasm` 是一个汇编函数，它是 C 回调函数实际调用的入口点。它会根据传入的索引值调用 `callbackWrap`。`callbackWrap` 函数负责从 C 的调用约定转换为 Go 的调用约定，调用实际的 Go 函数，并将结果转换回 C 的调用约定。

   **Go 代码示例 (Callback):**

   ```go
   package main

   import (
       "fmt"
       "syscall"
       "unsafe"
   )

   //go:linkname compileCallback runtime.compileCallback

   func compileCallback(fn eface, cdecl bool) uintptr

   func goCallback(param uintptr) uintptr {
       fmt.Println("Go callback called with parameter:", param)
       return param * 2
   }

   type eface struct {
       _type *_type
       data  unsafe.Pointer
   }

   type _type struct {
       size       uintptr
       ptrdata    uintptr // number of bytes in the type that can contain pointers
       hash       uint32  // hash of type; avoids computation in hash tables
       tflag      uint8   // extra type information flags
       align      uint8   // alignment of variable with this type
       fieldAlign uint8   // alignment of struct field with this type
       kind       uint8   // enumeration for C
       // function for comparing objects of this type
       // (ptr to object A, ptr to object B) == 0
       equal func(unsafe.Pointer, unsafe.Pointer) bool
       // gcdata stores the GC type data for the garbage collector.
       // If the Kind is a Ptr this is the type that the pointer points to.
       gcdata    *byte
       str       int32 // string form
       ptrToThis int32 // type for pointer to this type, may be zero
   }

   func main() {
       // 将 Go 函数转换为 C 函数指针
       cb := compileCallback(eface{data: unsafe.Pointer(&goCallback)}, false)
       fmt.Printf("C callback address: 0x%x\n", cb)

       // 假设我们有一个 Windows API 函数需要一个回调函数
       // 这里只是一个模拟，实际的 Windows API 调用会更复杂
       type CallBackProc func(uintptr) uintptr
       callbackFn := *(*CallBackProc)(unsafe.Pointer(&cb))

       input := uintptr(10)
       result := callbackFn(input)
       fmt.Println("Result from callback:", result)
   }
   ```

   **假设的输入与输出:**

   - **输入:**  `compileCallback` 函数接收 `goCallback` 函数的 `eface` 结构体以及 `false` (表示使用默认的 Windows 调用约定，例如 `stdcall` 或 `fastcall`)。
   - **输出:** `compileCallback` 返回一个 `uintptr`，这个值是运行时环境生成的、可以作为 C 函数指针使用的地址。在上面的例子中，它被转换为 `CallBackProc` 类型并调用。`goCallback` 被调用，输出 "Go callback called with parameter: 10"，并返回 `20`。

**2. Windows 系统调用 (System Calls):**

   - **功能:** 提供了直接调用 Windows 系统调用的能力。系统调用是程序与操作系统内核交互的底层机制。
   - **实现:** `syscall_Syscall`, `syscall_Syscall6`, `syscall_Syscall9`, `syscall_Syscall12`, `syscall_Syscall15`, `syscall_Syscall18`, 和 `syscall_SyscallN` 等函数提供了不同参数数量的系统调用封装。
   - **`syscall_syscalln`:**  这是实际执行系统调用的底层函数。它将参数传递给 `cgocall`，后者会切换到执行系统调用的 goroutine 上下文。
   - **参数处理:**  这些函数接收系统调用号 (`fn`) 和系统调用所需的参数 (`a1`, `a2`, ... 或 `args ...uintptr`)。
   - **返回值处理:** 系统调用的结果（通常是两个返回值和一个错误码）会被返回。

   **Go 代码示例 (System Call):**

   ```go
   package main

   import (
       "fmt"
       "syscall"
       "unsafe"
   )

   //go:linkname syscall_SyscallN runtime.syscall_SyscallN

   func syscall_SyscallN(fn uintptr, args ...uintptr) (r1, r2, err uintptr)

   const (
       // 假设这是 GetCurrentProcessId 的系统调用号 (实际值需要查阅 Windows SDK)
       getcurrentProcessId = 0x0000004e
   )

   func main() {
       r1, _, err := syscall_SyscallN(getcurrentProcessId, 0, 0, 0)
       if err != 0 {
           fmt.Printf("System call failed with error: %d\n", err)
           return
       }
       fmt.Printf("Current process ID: %d\n", r1)
   }
   ```

   **假设的输入与输出:**

   - **输入:** `syscall_SyscallN` 函数接收 `getcurrentProcessId` (假设的系统调用号) 和零个参数。
   - **输出:**  `syscall_SyscallN` 返回当前进程的 ID (一个 `uintptr`)，错误码 `err` 为 0 表示成功。输出类似于 "Current process ID: 1234" (具体 ID 取决于运行时的进程)。

**3. 动态库加载和函数查找:**

   - **功能:** 提供了加载 Windows 动态链接库 (DLL) 和在已加载的 DLL 中查找函数地址的功能。
   - **实现:**
     - `syscall_loadsystemlibrary`:  加载系统目录下的 DLL。
     - `syscall_loadlibrary`: 加载指定的 DLL。
     - `syscall_getprocaddress`:  获取已加载 DLL 中指定函数的地址。
   - **与 `syscall` 包的关联:**  这些 `runtime` 包中的函数通过 `go:linkname` 指令与标准库 `syscall` 包中的 `LoadLibrary`, `GetProcAddress` 等函数关联起来。这意味着标准库中的 `syscall.LoadLibrary` 实际上会调用这里的 `syscall_loadlibrary`。

   **Go 代码示例 (Dynamic Library):**

   ```go
   package main

   import (
       "fmt"
       "syscall"
       "unsafe"
   )

   //go:linkname syscall_loadlibrary runtime.syscall_loadlibrary
   //go:linkname syscall_getprocaddress runtime.syscall_getprocaddress

   func syscall_loadlibrary(filename *uint16) (handle, err uintptr)
   func syscall_getprocaddress(handle uintptr, procname *byte) (outhandle, err uintptr)

   func main() {
       kernel32, err := syscall.LoadLibrary("kernel32.dll")
       if err != nil {
           fmt.Printf("LoadLibrary failed: %v\n", err)
           return
       }
       defer syscall.FreeLibrary(kernel32)

       proc, err := syscall.GetProcAddress(kernel32, syscall.StringToBytePtr("MessageBoxW"))
       if err != nil {
           fmt.Printf("GetProcAddress failed: %v\n", err)
           return
       }
       fmt.Printf("Address of MessageBoxW: 0x%x\n", proc)
   }
   ```

**4. 内部辅助功能:**

   - **`cbs` 结构体和相关锁:**  用于管理和同步对已注册回调函数的访问，确保线程安全。
   - **`abiPart` 和 `abiDesc`:**  用于描述 C 和 Go 函数调用约定之间的差异，以及如何进行参数和返回值的转换。
   - **`callbackMaxFrame`:** 定义了回调函数栈帧的最大大小，用于防止栈溢出。

**`cdecl` 参数的处理:**

- `cdecl` 参数在 `compileCallback` 函数中用于指定在 x86 架构上生成的回调函数是否使用 `cdecl` 调用约定。
- **x86 (386):**
    - 如果 `cdecl` 为 `true`，则生成使用 `cdecl` 调用约定的回调函数。在 `cdecl` 中，被调用者负责清理栈上的参数。`retPop` 字段会记录需要弹出的字节数。
    - 如果 `cdecl` 为 `false`（默认情况），则使用 `stdcall` 调用约定。在 `stdcall` 中，调用者负责清理栈上的参数。
- **其他架构 (amd64, arm, arm64):** `cdecl` 参数会被忽略，因为这些架构通常只有一种主要的调用约定 (例如，amd64 上是 fastcall，arm 上是 AAPCS)。

**使用者易犯错的点 (Callbacks):**

1. **不正确的函数签名:** 传递给 `compileCallback` 的 Go 函数必须具有与期望的 C 回调函数相匹配的签名，尤其是参数类型和返回值类型。如果签名不匹配，可能会导致运行时错误或数据损坏。例如，如果 C API 期望一个接受两个 `int` 参数的回调，但你传递了一个接受一个 `string` 参数的 Go 函数，就会出错。
2. **内存管理:**  如果 Go 回调函数捕获了 Go 对象的引用，需要确保这些对象在回调函数被调用时仍然有效。否则，可能会访问到已释放的内存。
3. **竞态条件:**  如果多个线程同时注册或调用回调函数，需要使用适当的同步机制（如 `cbs` 结构体中的锁）来避免竞态条件。
4. **栈溢出:**  如果 Go 回调函数的栈帧过大，超过 `callbackMaxFrame` 的限制，`compileCallback` 会 panic。这通常发生在回调函数有大量的局部变量或嵌套调用很深的情况下。

**使用者易犯错的点 (System Calls):**

1. **错误的系统调用号:** 使用错误的系统调用号会导致不可预测的行为，甚至可能导致系统崩溃。需要查阅 Windows SDK 或相关文档以获取正确的系统调用号。
2. **不正确的参数类型和数量:**  传递给系统调用的参数必须与系统调用期望的类型和数量完全匹配。类型不匹配可能导致数据被错误地解释，数量不匹配可能导致栈损坏或参数丢失。
3. **权限问题:**  某些系统调用需要特定的权限才能执行。如果程序没有足够的权限，系统调用可能会失败并返回错误。

总而言之，这段代码是 Go 运行时与 Windows 操作系统交互的核心，它提供了将 Go 代码集成到 Windows 环境的关键机制，包括调用 Windows API 和处理来自 Windows 的回调。理解这段代码对于进行底层的 Windows 系统编程至关重要。

Prompt: 
```
这是路径为go/src/runtime/syscall_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/abi"
	"internal/goarch"
	"unsafe"
)

// cbs stores all registered Go callbacks.
var cbs struct {
	lock  mutex // use cbsLock / cbsUnlock for race instrumentation.
	ctxt  [cb_max]winCallback
	index map[winCallbackKey]int
	n     int
}

func cbsLock() {
	lock(&cbs.lock)
	// compileCallback is used by goenvs prior to completion of schedinit.
	// raceacquire involves a racecallback to get the proc, which is not
	// safe prior to scheduler initialization. Thus avoid instrumentation
	// until then.
	if raceenabled && mainStarted {
		raceacquire(unsafe.Pointer(&cbs.lock))
	}
}

func cbsUnlock() {
	if raceenabled && mainStarted {
		racerelease(unsafe.Pointer(&cbs.lock))
	}
	unlock(&cbs.lock)
}

// winCallback records information about a registered Go callback.
type winCallback struct {
	fn     *funcval // Go function
	retPop uintptr  // For 386 cdecl, how many bytes to pop on return
	abiMap abiDesc
}

// abiPartKind is the action an abiPart should take.
type abiPartKind int

const (
	abiPartBad   abiPartKind = iota
	abiPartStack             // Move a value from memory to the stack.
	abiPartReg               // Move a value from memory to a register.
)

// abiPart encodes a step in translating between calling ABIs.
type abiPart struct {
	kind           abiPartKind
	srcStackOffset uintptr
	dstStackOffset uintptr // used if kind == abiPartStack
	dstRegister    int     // used if kind == abiPartReg
	len            uintptr
}

func (a *abiPart) tryMerge(b abiPart) bool {
	if a.kind != abiPartStack || b.kind != abiPartStack {
		return false
	}
	if a.srcStackOffset+a.len == b.srcStackOffset && a.dstStackOffset+a.len == b.dstStackOffset {
		a.len += b.len
		return true
	}
	return false
}

// abiDesc specifies how to translate from a C frame to a Go
// frame. This does not specify how to translate back because
// the result is always a uintptr. If the C ABI is fastcall,
// this assumes the four fastcall registers were first spilled
// to the shadow space.
type abiDesc struct {
	parts []abiPart

	srcStackSize uintptr // stdcall/fastcall stack space tracking
	dstStackSize uintptr // Go stack space used
	dstSpill     uintptr // Extra stack space for argument spill slots
	dstRegisters int     // Go ABI int argument registers used

	// retOffset is the offset of the uintptr-sized result in the Go
	// frame.
	retOffset uintptr
}

func (p *abiDesc) assignArg(t *_type) {
	if t.Size_ > goarch.PtrSize {
		// We don't support this right now. In
		// stdcall/cdecl, 64-bit ints and doubles are
		// passed as two words (little endian); and
		// structs are pushed on the stack. In
		// fastcall, arguments larger than the word
		// size are passed by reference. On arm,
		// 8-byte aligned arguments round up to the
		// next even register and can be split across
		// registers and the stack.
		panic("compileCallback: argument size is larger than uintptr")
	}
	if k := t.Kind_ & abi.KindMask; GOARCH != "386" && (k == abi.Float32 || k == abi.Float64) {
		// In fastcall, floating-point arguments in
		// the first four positions are passed in
		// floating-point registers, which we don't
		// currently spill. arm passes floating-point
		// arguments in VFP registers, which we also
		// don't support.
		// So basically we only support 386.
		panic("compileCallback: float arguments not supported")
	}

	if t.Size_ == 0 {
		// The Go ABI aligns for zero-sized types.
		p.dstStackSize = alignUp(p.dstStackSize, uintptr(t.Align_))
		return
	}

	// In the C ABI, we're already on a word boundary.
	// Also, sub-word-sized fastcall register arguments
	// are stored to the least-significant bytes of the
	// argument word and all supported Windows
	// architectures are little endian, so srcStackOffset
	// is already pointing to the right place for smaller
	// arguments. The same is true on arm.

	oldParts := p.parts
	if p.tryRegAssignArg(t, 0) {
		// Account for spill space.
		//
		// TODO(mknyszek): Remove this when we no longer have
		// caller reserved spill space.
		p.dstSpill = alignUp(p.dstSpill, uintptr(t.Align_))
		p.dstSpill += t.Size_
	} else {
		// Register assignment failed.
		// Undo the work and stack assign.
		p.parts = oldParts

		// The Go ABI aligns arguments.
		p.dstStackSize = alignUp(p.dstStackSize, uintptr(t.Align_))

		// Copy just the size of the argument. Note that this
		// could be a small by-value struct, but C and Go
		// struct layouts are compatible, so we can copy these
		// directly, too.
		part := abiPart{
			kind:           abiPartStack,
			srcStackOffset: p.srcStackSize,
			dstStackOffset: p.dstStackSize,
			len:            t.Size_,
		}
		// Add this step to the adapter.
		if len(p.parts) == 0 || !p.parts[len(p.parts)-1].tryMerge(part) {
			p.parts = append(p.parts, part)
		}
		// The Go ABI packs arguments.
		p.dstStackSize += t.Size_
	}

	// cdecl, stdcall, fastcall, and arm pad arguments to word size.
	// TODO(rsc): On arm and arm64 do we need to skip the caller's saved LR?
	p.srcStackSize += goarch.PtrSize
}

// tryRegAssignArg tries to register-assign a value of type t.
// If this type is nested in an aggregate type, then offset is the
// offset of this type within its parent type.
// Assumes t.size <= goarch.PtrSize and t.size != 0.
//
// Returns whether the assignment succeeded.
func (p *abiDesc) tryRegAssignArg(t *_type, offset uintptr) bool {
	switch k := t.Kind_ & abi.KindMask; k {
	case abi.Bool, abi.Int, abi.Int8, abi.Int16, abi.Int32, abi.Uint, abi.Uint8, abi.Uint16, abi.Uint32, abi.Uintptr, abi.Pointer, abi.UnsafePointer:
		// Assign a register for all these types.
		return p.assignReg(t.Size_, offset)
	case abi.Int64, abi.Uint64:
		// Only register-assign if the registers are big enough.
		if goarch.PtrSize == 8 {
			return p.assignReg(t.Size_, offset)
		}
	case abi.Array:
		at := (*arraytype)(unsafe.Pointer(t))
		if at.Len == 1 {
			return p.tryRegAssignArg(at.Elem, offset) // TODO fix when runtime is fully commoned up w/ abi.Type
		}
	case abi.Struct:
		st := (*structtype)(unsafe.Pointer(t))
		for i := range st.Fields {
			f := &st.Fields[i]
			if !p.tryRegAssignArg(f.Typ, offset+f.Offset) {
				return false
			}
		}
		return true
	}
	// Pointer-sized types such as maps and channels are currently
	// not supported.
	panic("compileCallback: type " + toRType(t).string() + " is currently not supported for use in system callbacks")
}

// assignReg attempts to assign a single register for an
// argument with the given size, at the given offset into the
// value in the C ABI space.
//
// Returns whether the assignment was successful.
func (p *abiDesc) assignReg(size, offset uintptr) bool {
	if p.dstRegisters >= intArgRegs {
		return false
	}
	p.parts = append(p.parts, abiPart{
		kind:           abiPartReg,
		srcStackOffset: p.srcStackSize + offset,
		dstRegister:    p.dstRegisters,
		len:            size,
	})
	p.dstRegisters++
	return true
}

type winCallbackKey struct {
	fn    *funcval
	cdecl bool
}

func callbackasm()

// callbackasmAddr returns address of runtime.callbackasm
// function adjusted by i.
// On x86 and amd64, runtime.callbackasm is a series of CALL instructions,
// and we want callback to arrive at
// correspondent call instruction instead of start of
// runtime.callbackasm.
// On ARM, runtime.callbackasm is a series of mov and branch instructions.
// R12 is loaded with the callback index. Each entry is two instructions,
// hence 8 bytes.
func callbackasmAddr(i int) uintptr {
	var entrySize int
	switch GOARCH {
	default:
		panic("unsupported architecture")
	case "386", "amd64":
		entrySize = 5
	case "arm", "arm64":
		// On ARM and ARM64, each entry is a MOV instruction
		// followed by a branch instruction
		entrySize = 8
	}
	return abi.FuncPCABI0(callbackasm) + uintptr(i*entrySize)
}

const callbackMaxFrame = 64 * goarch.PtrSize

// compileCallback converts a Go function fn into a C function pointer
// that can be passed to Windows APIs.
//
// On 386, if cdecl is true, the returned C function will use the
// cdecl calling convention; otherwise, it will use stdcall. On amd64,
// it always uses fastcall. On arm, it always uses the ARM convention.
//
//go:linkname compileCallback syscall.compileCallback
func compileCallback(fn eface, cdecl bool) (code uintptr) {
	if GOARCH != "386" {
		// cdecl is only meaningful on 386.
		cdecl = false
	}

	if fn._type == nil || (fn._type.Kind_&abi.KindMask) != abi.Func {
		panic("compileCallback: expected function with one uintptr-sized result")
	}
	ft := (*functype)(unsafe.Pointer(fn._type))

	// Check arguments and construct ABI translation.
	var abiMap abiDesc
	for _, t := range ft.InSlice() {
		abiMap.assignArg(t)
	}
	// The Go ABI aligns the result to the word size. src is
	// already aligned.
	abiMap.dstStackSize = alignUp(abiMap.dstStackSize, goarch.PtrSize)
	abiMap.retOffset = abiMap.dstStackSize

	if len(ft.OutSlice()) != 1 {
		panic("compileCallback: expected function with one uintptr-sized result")
	}
	if ft.OutSlice()[0].Size_ != goarch.PtrSize {
		panic("compileCallback: expected function with one uintptr-sized result")
	}
	if k := ft.OutSlice()[0].Kind_ & abi.KindMask; k == abi.Float32 || k == abi.Float64 {
		// In cdecl and stdcall, float results are returned in
		// ST(0). In fastcall, they're returned in XMM0.
		// Either way, it's not AX.
		panic("compileCallback: float results not supported")
	}
	if intArgRegs == 0 {
		// Make room for the uintptr-sized result.
		// If there are argument registers, the return value will
		// be passed in the first register.
		abiMap.dstStackSize += goarch.PtrSize
	}

	// TODO(mknyszek): Remove dstSpill from this calculation when we no longer have
	// caller reserved spill space.
	frameSize := alignUp(abiMap.dstStackSize, goarch.PtrSize)
	frameSize += abiMap.dstSpill
	if frameSize > callbackMaxFrame {
		panic("compileCallback: function argument frame too large")
	}

	// For cdecl, the callee is responsible for popping its
	// arguments from the C stack.
	var retPop uintptr
	if cdecl {
		retPop = abiMap.srcStackSize
	}

	key := winCallbackKey{(*funcval)(fn.data), cdecl}

	cbsLock()

	// Check if this callback is already registered.
	if n, ok := cbs.index[key]; ok {
		cbsUnlock()
		return callbackasmAddr(n)
	}

	// Register the callback.
	if cbs.index == nil {
		cbs.index = make(map[winCallbackKey]int)
	}
	n := cbs.n
	if n >= len(cbs.ctxt) {
		cbsUnlock()
		throw("too many callback functions")
	}
	c := winCallback{key.fn, retPop, abiMap}
	cbs.ctxt[n] = c
	cbs.index[key] = n
	cbs.n++

	cbsUnlock()
	return callbackasmAddr(n)
}

type callbackArgs struct {
	index uintptr
	// args points to the argument block.
	//
	// For cdecl and stdcall, all arguments are on the stack.
	//
	// For fastcall, the trampoline spills register arguments to
	// the reserved spill slots below the stack arguments,
	// resulting in a layout equivalent to stdcall.
	//
	// For arm, the trampoline stores the register arguments just
	// below the stack arguments, so again we can treat it as one
	// big stack arguments frame.
	args unsafe.Pointer
	// Below are out-args from callbackWrap
	result uintptr
	retPop uintptr // For 386 cdecl, how many bytes to pop on return
}

// callbackWrap is called by callbackasm to invoke a registered C callback.
func callbackWrap(a *callbackArgs) {
	c := cbs.ctxt[a.index]
	a.retPop = c.retPop

	// Convert from C to Go ABI.
	var regs abi.RegArgs
	var frame [callbackMaxFrame]byte
	goArgs := unsafe.Pointer(&frame)
	for _, part := range c.abiMap.parts {
		switch part.kind {
		case abiPartStack:
			memmove(add(goArgs, part.dstStackOffset), add(a.args, part.srcStackOffset), part.len)
		case abiPartReg:
			goReg := unsafe.Pointer(&regs.Ints[part.dstRegister])
			memmove(goReg, add(a.args, part.srcStackOffset), part.len)
		default:
			panic("bad ABI description")
		}
	}

	// TODO(mknyszek): Remove this when we no longer have
	// caller reserved spill space.
	frameSize := alignUp(c.abiMap.dstStackSize, goarch.PtrSize)
	frameSize += c.abiMap.dstSpill

	// Even though this is copying back results, we can pass a nil
	// type because those results must not require write barriers.
	reflectcall(nil, unsafe.Pointer(c.fn), noescape(goArgs), uint32(c.abiMap.dstStackSize), uint32(c.abiMap.retOffset), uint32(frameSize), &regs)

	// Extract the result.
	//
	// There's always exactly one return value, one pointer in size.
	// If it's on the stack, then we will have reserved space for it
	// at the end of the frame, otherwise it was passed in a register.
	if c.abiMap.dstStackSize != c.abiMap.retOffset {
		a.result = *(*uintptr)(unsafe.Pointer(&frame[c.abiMap.retOffset]))
	} else {
		var zero int
		// On architectures with no registers, Ints[0] would be a compile error,
		// so we use a dynamic index. These architectures will never take this
		// branch, so this won't cause a runtime panic.
		a.result = regs.Ints[zero]
	}
}

const _LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800

//go:linkname syscall_loadsystemlibrary syscall.loadsystemlibrary
func syscall_loadsystemlibrary(filename *uint16) (handle, err uintptr) {
	handle, _, err = syscall_SyscallN(uintptr(unsafe.Pointer(_LoadLibraryExW)), uintptr(unsafe.Pointer(filename)), 0, _LOAD_LIBRARY_SEARCH_SYSTEM32)
	KeepAlive(filename)
	if handle != 0 {
		err = 0
	}
	return
}

// golang.org/x/sys linknames syscall.loadlibrary
// (in addition to standard package syscall).
// Do not remove or change the type signature.
//
//go:linkname syscall_loadlibrary syscall.loadlibrary
func syscall_loadlibrary(filename *uint16) (handle, err uintptr) {
	handle, _, err = syscall_SyscallN(uintptr(unsafe.Pointer(_LoadLibraryW)), uintptr(unsafe.Pointer(filename)))
	KeepAlive(filename)
	if handle != 0 {
		err = 0
	}
	return
}

// golang.org/x/sys linknames syscall.getprocaddress
// (in addition to standard package syscall).
// Do not remove or change the type signature.
//
//go:linkname syscall_getprocaddress syscall.getprocaddress
func syscall_getprocaddress(handle uintptr, procname *byte) (outhandle, err uintptr) {
	outhandle, _, err = syscall_SyscallN(uintptr(unsafe.Pointer(_GetProcAddress)), handle, uintptr(unsafe.Pointer(procname)))
	KeepAlive(procname)
	if outhandle != 0 {
		err = 0
	}
	return
}

//go:linkname syscall_Syscall syscall.Syscall
//go:nosplit
func syscall_Syscall(fn, nargs, a1, a2, a3 uintptr) (r1, r2, err uintptr) {
	return syscall_syscalln(fn, nargs, a1, a2, a3)
}

//go:linkname syscall_Syscall6 syscall.Syscall6
//go:nosplit
func syscall_Syscall6(fn, nargs, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2, err uintptr) {
	return syscall_syscalln(fn, nargs, a1, a2, a3, a4, a5, a6)
}

//go:linkname syscall_Syscall9 syscall.Syscall9
//go:nosplit
func syscall_Syscall9(fn, nargs, a1, a2, a3, a4, a5, a6, a7, a8, a9 uintptr) (r1, r2, err uintptr) {
	return syscall_syscalln(fn, nargs, a1, a2, a3, a4, a5, a6, a7, a8, a9)
}

//go:linkname syscall_Syscall12 syscall.Syscall12
//go:nosplit
func syscall_Syscall12(fn, nargs, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12 uintptr) (r1, r2, err uintptr) {
	return syscall_syscalln(fn, nargs, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12)
}

//go:linkname syscall_Syscall15 syscall.Syscall15
//go:nosplit
func syscall_Syscall15(fn, nargs, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15 uintptr) (r1, r2, err uintptr) {
	return syscall_syscalln(fn, nargs, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15)
}

//go:linkname syscall_Syscall18 syscall.Syscall18
//go:nosplit
func syscall_Syscall18(fn, nargs, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18 uintptr) (r1, r2, err uintptr) {
	return syscall_syscalln(fn, nargs, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18)
}

// maxArgs should be divisible by 2, as Windows stack
// must be kept 16-byte aligned on syscall entry.
//
// Although it only permits maximum 42 parameters, it
// is arguably large enough.
const maxArgs = 42

//go:linkname syscall_SyscallN syscall.SyscallN
//go:nosplit
func syscall_SyscallN(fn uintptr, args ...uintptr) (r1, r2, err uintptr) {
	return syscall_syscalln(fn, uintptr(len(args)), args...)
}

//go:nosplit
func syscall_syscalln(fn, n uintptr, args ...uintptr) (r1, r2, err uintptr) {
	if n > uintptr(len(args)) {
		panic("syscall: n > len(args)") // should not be reachable from user code
	}
	if n > maxArgs {
		panic("runtime: SyscallN has too many arguments")
	}

	// The cgocall parameters are stored in m instead of in
	// the stack because the stack can move during fn if it
	// calls back into Go.
	c := &getg().m.winsyscall
	c.fn = fn
	c.n = n
	if c.n != 0 {
		c.args = uintptr(noescape(unsafe.Pointer(&args[0])))
	}
	cgocall(asmstdcallAddr, unsafe.Pointer(c))
	// cgocall may reschedule us on to a different M,
	// but it copies the return values into the new M's
	// so we can read them from there.
	c = &getg().m.winsyscall
	return c.r1, c.r2, c.err
}

"""



```