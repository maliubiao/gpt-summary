Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Skim and Identification of Core Concepts:**

The first step is to quickly read through the code to identify the main components and their purpose. Keywords like `DLL`, `Proc`, `LoadDLL`, `FindProc`, `Call`, `LazyDLL`, `LazyProc`, `LoadLibrary`, and `GetProcAddress` immediately jump out and suggest this code is about interacting with Dynamic Link Libraries (DLLs) on Windows.

**2. Dissecting Key Structures:**

Next, I'd examine the core data structures:

* **`DLL`:**  Represents a loaded DLL in memory. It has a `Name` and a `Handle`.
* **`Proc`:** Represents a specific function (procedure) within a DLL. It holds a pointer to the `DLL`, the function `Name`, and its memory `addr`.
* **`LazyDLL`:**  A wrapper around `DLL` that delays loading until needed. This is important for performance and initialization order. It adds a `System` flag for specifying loading from the system directory.
* **`LazyProc`:**  Similar to `LazyDLL`, it delays looking up the procedure address until it's first used.

**3. Understanding Core Functions:**

Now, let's focus on the functions and their roles:

* **`LoadDLL(name string)`:**  The primary function for loading a DLL. It uses `syscall_loadlibrary` (which is linked to the underlying Windows API `LoadLibrary`). The "Warning" comment about DLL preloading attacks is crucial.
* **`MustLoadDLL(name string)`:** A convenience function that panics on failure.
* **`FindProc(name string)`:**  Locates a procedure by name within a loaded `DLL`. It uses `syscall_getprocaddress` (linked to the Windows API `GetProcAddress`).
* **`MustFindProc(name string)`:**  Panics if `FindProc` fails.
* **`FindProcByOrdinal(ordinal uintptr)`:** Locates a procedure by its ordinal number.
* **`MustFindProcByOrdinal(ordinal uintptr)`:** Panics if `FindProcByOrdinal` fails.
* **`Release()`:** Unloads the DLL from memory (`FreeLibrary`).
* **`Proc.Call(a ...uintptr)`:**  The crucial function for calling a function within the DLL. It uses `syscall.Syscall` family of functions, handling different numbers of arguments. The comment about the non-nil error and needing to check the primary return value is important for correct usage.
* **`LazyDLL.Load()`:**  Handles the deferred loading of the DLL. It checks if already loaded and uses a mutex for thread safety. It has special handling for "kernel32.dll".
* **`LazyDLL.NewProc(name string)`:** Creates a `LazyProc` associated with this `LazyDLL`.
* **`LazyProc.Find()`:**  Handles the deferred lookup of the procedure's address. It ensures the `LazyDLL` is loaded first.
* **`LazyProc.Call(a ...uintptr)`:**  Calls the procedure, ensuring it's looked up first.

**4. Identifying Implicit Functionality and Relationships:**

* **Error Handling:**  The `DLLError` structure and the way errors are returned from functions like `LoadDLL` and `FindProc` is a key part of the functionality.
* **`go:linkname`:**  Understanding that `go:linkname` is used to connect Go functions to symbols in the runtime is important, even though it's not directly used by the caller.
* **Thread Safety:** The use of `sync.Mutex` in `LazyDLL` and `LazyProc` indicates awareness of concurrent access.
* **DLL Preloading Attacks:** The warning in `LoadDLL` highlights a security concern.
* **System DLL Loading:** The `LazyDLL.System` flag and the logic in `loadLibraryEx` to handle loading from the system directory are important nuances.

**5. Considering Examples and Edge Cases:**

* **Simple DLL loading and function call:**  A basic example with `LoadDLL` and `FindProc` is essential.
* **Using `LazyDLL`:** Demonstrating the delayed loading behavior is important.
* **Calling functions with different numbers of arguments:**  Highlighting the variadic `Call` method.
* **Potential Errors:**  Illustrating how errors are returned and should be handled.
* **DLL Preloading Attack:**  Explaining the security risk when using non-absolute paths.

**6. Structuring the Answer:**

Finally, I'd organize the findings into clear sections:

* **Core Functionality:** A high-level summary.
* **Detailed Functionality Breakdown:**  Explaining each key structure and function.
* **Go Language Feature Implementation:**  Focusing on the use of `syscall`, `unsafe`, `sync`, and `go:linkname`.
* **Code Examples:**  Providing practical illustrations of how to use the code.
* **Assumptions (if any):**  Explicitly stating any assumptions made during the analysis.
* **Command-line Arguments:**  Checking for any command-line parameter handling (in this case, none found).
* **Common Mistakes:** Identifying potential pitfalls for users.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Might have focused too much on individual functions without seeing the bigger picture of DLL interaction. Realization: The `DLL` and `Proc` structures are central.
* **Realization about `go:linkname`:**  Initially, I might have overlooked the significance. Correction: Recognize that it bridges the Go code with lower-level runtime functionality.
* **Emphasis on security:** The warning about DLL preloading attacks needs to be prominently mentioned.
* **Clarity in examples:** Ensuring the examples are concise and illustrate the intended functionality.

By following this structured approach, combining code reading with conceptual understanding and consideration of usage scenarios, we can effectively analyze and explain the purpose and functionality of the given Go code.
这段Go语言代码是 `golang.org/x/sys/windows` 包中用于加载和调用Windows动态链接库（DLL）的一部分。它提供了一种在Go程序中与Windows DLL进行交互的方式。

**主要功能:**

1. **加载DLL (`LoadDLL`, `MustLoadDLL`, `LazyDLL`, `NewLazyDLL`, `NewLazySystemDLL`):**
   - 允许Go程序将DLL文件加载到内存中。
   - `LoadDLL` 函数尝试加载指定的DLL文件，如果加载失败会返回错误。
   - `MustLoadDLL` 函数与 `LoadDLL` 类似，但在加载失败时会触发 `panic`。
   - `LazyDLL` 结构体提供了一种延迟加载DLL的机制。只有在首次需要DLL时才会加载，提高了程序启动性能。
   - `NewLazyDLL` 创建一个 `LazyDLL` 实例。
   - `NewLazySystemDLL` 创建一个 `LazyDLL` 实例，并指定只在Windows系统目录下搜索DLL（用于加载系统DLL，更安全）。

2. **查找DLL中的导出函数 (`FindProc`, `MustFindProc`, `FindProcByOrdinal`, `MustFindProcByOrdinal`, `LazyProc`, `NewProc`):**
   - 一旦DLL被加载，可以使用这些函数在DLL中查找特定的导出函数（过程）。
   - `FindProc` 函数根据函数名查找导出函数，返回一个 `Proc` 结构体，如果找不到会返回错误。
   - `MustFindProc` 函数与 `FindProc` 类似，但在查找失败时会触发 `panic`。
   - `FindProcByOrdinal` 函数根据导出函数的序号（Ordinal）查找。
   - `MustFindProcByOrdinal` 函数与 `FindProcByOrdinal` 类似，查找失败时触发 `panic`。
   - `LazyProc` 结构体提供了一种延迟查找导出函数的机制，只有在首次需要调用该函数时才会查找。
   - `LazyDLL.NewProc` 创建一个与 `LazyDLL` 关联的 `LazyProc` 实例。

3. **调用DLL中的导出函数 (`Proc.Call`, `LazyProc.Call`):**
   - `Proc.Call` 函数用于执行通过 `FindProc` 或 `FindProcByOrdinal` 找到的导出函数。它接受可变数量的 `uintptr` 参数作为传递给DLL函数的参数。
   - `LazyProc.Call` 函数与 `Proc.Call` 类似，但它会自动触发 `LazyProc` 查找导出函数（如果尚未查找）。

4. **卸载DLL (`DLL.Release`):**
   - `DLL.Release` 函数用于从内存中卸载已加载的DLL。

**它是什么Go语言功能的实现:**

这段代码是 Go 语言中与操作系统底层交互（特别是 Windows API）的功能实现的一部分。它利用了以下 Go 语言特性：

- **`syscall` 包:**  直接调用操作系统提供的系统调用。代码中使用了 `syscall.loadlibrary` 和 `syscall.getprocaddress` (通过 `go:linkname` 进行了重命名和关联)。`syscall.Syscall` 系列函数用于实际的函数调用。
- **`unsafe` 包:**  允许进行不安全的指针操作。在这里用于 `atomic.LoadPointer` 和 `atomic.StorePointer` 实现无锁的原子操作，确保在并发场景下 `LazyDLL` 和 `LazyProc` 的加载和查找操作是安全的。
- **`sync` 包:** 提供了同步原语，如 `sync.Mutex` 用于保护 `LazyDLL` 和 `LazyProc` 的内部状态，防止并发访问导致的数据竞争。`sync.Once` 用于确保某些初始化操作只执行一次。
- **`go:linkname` 编译指令:**  允许将本地 Go 函数链接到 runtime 包或其他包中的私有函数。这里将 `syscall_loadlibrary` 和 `syscall_getprocaddress` 链接到 `syscall` 包中对应的函数。

**Go 代码示例:**

```go
package main

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"
)

func main() {
	// 加载 user32.dll
	user32, err := windows.LoadDLL("user32.dll")
	if err != nil {
		fmt.Println("加载 user32.dll 失败:", err)
		return
	}
	defer user32.Release()

	// 查找 MessageBoxW 函数
	messageBoxW, err := user32.FindProc("MessageBoxW")
	if err != nil {
		fmt.Println("查找 MessageBoxW 失败:", err)
		return
	}

	// 定义 MessageBoxW 函数的参数
	var (
		caption   = syscall.StringToUTF16Ptr("你好")
		text      = syscall.StringToUTF16Ptr("这是一个来自 Go 的消息框！")
		nullHwnd  = uintptr(0)
		nullFlags = uintptr(0)
	)

	// 调用 MessageBoxW 函数
	ret, _, err := messageBoxW.Call(nullHwnd, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(caption)), nullFlags)
	if err != syscall.Errno(0) {
		fmt.Println("调用 MessageBoxW 失败:", err)
		return
	}

	fmt.Println("MessageBox 返回值:", ret)

	// 使用 LazyDLL 加载并调用
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getModuleHandleW := kernel32.NewProc("GetModuleHandleW")

	handle, _, err := getModuleHandleW.Call(uintptr(0))
	if err != syscall.Errno(0) {
		fmt.Println("调用 GetModuleHandleW 失败:", err)
		return
	}
	fmt.Printf("GetModuleHandleW 返回句柄: 0x%x\n", handle)

	if err := kernel32.Load(); err != nil {
		fmt.Println("LazyDLL 加载失败:", err)
	}
}
```

**假设的输入与输出:**

上面的代码示例中，假设 `user32.dll` 和 `kernel32.dll` 存在于系统的默认DLL搜索路径中。

- **加载 `user32.dll` 和查找 `MessageBoxW`:** 如果成功，不会有明显的输出，但会准备好调用 `MessageBoxW`。如果失败，会输出加载或查找失败的错误信息。
- **调用 `MessageBoxW`:** 会弹出一个标题为 "你好"，内容为 "这是一个来自 Go 的消息框！" 的消息框。用户点击消息框上的按钮后，终端会输出 `MessageBox 返回值: ` 加上相应的返回值（通常是点击的按钮的ID）。
- **使用 `LazyDLL` 加载 `kernel32.dll` 并调用 `GetModuleHandleW`:** 会输出 `GetModuleHandleW 返回句柄: ` 加上 `kernel32.dll` 的模块句柄的十六进制表示。

**命令行参数的具体处理:**

这段代码本身不处理任何命令行参数。它关注的是 DLL 的加载和函数调用。命令行参数的处理通常会在 `main` 函数中使用 `os.Args` 来完成，但这部分代码没有涉及到。

**使用者易犯错的点:**

1. **DLL 路径问题:**
   - 使用 `LoadDLL` 时，如果没有提供绝对路径，Windows 会按照一定的搜索顺序查找 DLL。这可能导致加载了错误的 DLL，或者由于 DLL 不在搜索路径中而加载失败。
   - **错误示例:** `windows.LoadDLL("mydll.dll")`，如果 `mydll.dll` 不在当前目录或系统路径中，则会加载失败。
   - **建议:**  尽可能使用绝对路径加载自定义 DLL，或者使用 `LazyDLL` 并配合 `System: true` 来加载系统 DLL。

2. **函数参数类型不匹配:**
   - 在调用 DLL 函数时，必须确保传递的参数类型和数量与 DLL 函数的定义完全一致。Go 的 `uintptr` 可以表示指针，但需要小心地将 Go 的数据类型转换为 DLL 函数期望的类型。
   - **错误示例:** 如果 `MessageBoxW` 的某个参数期望的是一个指向宽字符字符串的指针，但传递了一个指向 ASCII 字符串的指针，可能会导致程序崩溃或产生不可预测的结果。
   - **建议:**  仔细查阅 Windows API 文档，了解 DLL 函数的参数类型，并使用 `syscall` 包提供的辅助函数（如 `syscall.StringToUTF16Ptr`）进行转换。

3. **错误处理不当:**
   - 调用 `LoadDLL`、`FindProc` 或 `Call` 时可能会返回错误。忽略这些错误可能会导致程序行为异常。
   - **错误示例:**
     ```go
     dll, _ := windows.LoadDLL("nonexistent.dll") // 忽略了错误
     if dll != nil {
         // ... 使用 dll，但 dll 实际上是 nil
     }
     ```
   - **建议:**  始终检查这些函数的返回值中的错误，并进行适当的处理。

4. **DLL 预加载攻击 (DLL Preloading Attacks):**
   - `LoadDLL` 函数的注释中提到了这个问题。当使用相对路径加载 DLL 时，攻击者可能在应用程序启动前将恶意 DLL 放置在应用程序的搜索路径中，导致应用程序加载恶意的 DLL 而不是预期的 DLL。
   - **易错场景:**  使用 `LoadDLL("mydll.dll")` 而没有确保 `mydll.dll` 的来源是可信的。
   - **建议:**  对于系统 DLL，使用 `NewLazySystemDLL`；对于自定义 DLL，尽可能使用绝对路径加载，或者采取其他安全措施来验证 DLL 的来源。

5. **忘记释放 DLL:**
   - 使用 `LoadDLL` 加载的 DLL 应该在不再需要时使用 `DLL.Release()` 卸载，以释放资源。忘记释放 DLL 可能会导致资源泄漏。
   - **易错场景:**  在函数中加载 DLL，但函数返回后没有调用 `Release()`。
   - **建议:**  使用 `defer dll.Release()` 来确保在函数退出时释放 DLL。

总而言之，这段代码提供了一种在 Go 中与 Windows DLL 交互的基础机制。使用者需要理解 Windows DLL 的工作原理，以及 Go 语言中与系统调用相关的概念，才能安全有效地使用这些功能。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/windows/dll_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package windows

import (
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// We need to use LoadLibrary and GetProcAddress from the Go runtime, because
// the these symbols are loaded by the system linker and are required to
// dynamically load additional symbols. Note that in the Go runtime, these
// return syscall.Handle and syscall.Errno, but these are the same, in fact,
// as windows.Handle and windows.Errno, and we intend to keep these the same.

//go:linkname syscall_loadlibrary syscall.loadlibrary
func syscall_loadlibrary(filename *uint16) (handle Handle, err Errno)

//go:linkname syscall_getprocaddress syscall.getprocaddress
func syscall_getprocaddress(handle Handle, procname *uint8) (proc uintptr, err Errno)

// DLLError describes reasons for DLL load failures.
type DLLError struct {
	Err     error
	ObjName string
	Msg     string
}

func (e *DLLError) Error() string { return e.Msg }

func (e *DLLError) Unwrap() error { return e.Err }

// A DLL implements access to a single DLL.
type DLL struct {
	Name   string
	Handle Handle
}

// LoadDLL loads DLL file into memory.
//
// Warning: using LoadDLL without an absolute path name is subject to
// DLL preloading attacks. To safely load a system DLL, use LazyDLL
// with System set to true, or use LoadLibraryEx directly.
func LoadDLL(name string) (dll *DLL, err error) {
	namep, err := UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	h, e := syscall_loadlibrary(namep)
	if e != 0 {
		return nil, &DLLError{
			Err:     e,
			ObjName: name,
			Msg:     "Failed to load " + name + ": " + e.Error(),
		}
	}
	d := &DLL{
		Name:   name,
		Handle: h,
	}
	return d, nil
}

// MustLoadDLL is like LoadDLL but panics if load operation fails.
func MustLoadDLL(name string) *DLL {
	d, e := LoadDLL(name)
	if e != nil {
		panic(e)
	}
	return d
}

// FindProc searches DLL d for procedure named name and returns *Proc
// if found. It returns an error if search fails.
func (d *DLL) FindProc(name string) (proc *Proc, err error) {
	namep, err := BytePtrFromString(name)
	if err != nil {
		return nil, err
	}
	a, e := syscall_getprocaddress(d.Handle, namep)
	if e != 0 {
		return nil, &DLLError{
			Err:     e,
			ObjName: name,
			Msg:     "Failed to find " + name + " procedure in " + d.Name + ": " + e.Error(),
		}
	}
	p := &Proc{
		Dll:  d,
		Name: name,
		addr: a,
	}
	return p, nil
}

// MustFindProc is like FindProc but panics if search fails.
func (d *DLL) MustFindProc(name string) *Proc {
	p, e := d.FindProc(name)
	if e != nil {
		panic(e)
	}
	return p
}

// FindProcByOrdinal searches DLL d for procedure by ordinal and returns *Proc
// if found. It returns an error if search fails.
func (d *DLL) FindProcByOrdinal(ordinal uintptr) (proc *Proc, err error) {
	a, e := GetProcAddressByOrdinal(d.Handle, ordinal)
	name := "#" + itoa(int(ordinal))
	if e != nil {
		return nil, &DLLError{
			Err:     e,
			ObjName: name,
			Msg:     "Failed to find " + name + " procedure in " + d.Name + ": " + e.Error(),
		}
	}
	p := &Proc{
		Dll:  d,
		Name: name,
		addr: a,
	}
	return p, nil
}

// MustFindProcByOrdinal is like FindProcByOrdinal but panics if search fails.
func (d *DLL) MustFindProcByOrdinal(ordinal uintptr) *Proc {
	p, e := d.FindProcByOrdinal(ordinal)
	if e != nil {
		panic(e)
	}
	return p
}

// Release unloads DLL d from memory.
func (d *DLL) Release() (err error) {
	return FreeLibrary(d.Handle)
}

// A Proc implements access to a procedure inside a DLL.
type Proc struct {
	Dll  *DLL
	Name string
	addr uintptr
}

// Addr returns the address of the procedure represented by p.
// The return value can be passed to Syscall to run the procedure.
func (p *Proc) Addr() uintptr {
	return p.addr
}

//go:uintptrescapes

// Call executes procedure p with arguments a. It will panic, if more than 15 arguments
// are supplied.
//
// The returned error is always non-nil, constructed from the result of GetLastError.
// Callers must inspect the primary return value to decide whether an error occurred
// (according to the semantics of the specific function being called) before consulting
// the error. The error will be guaranteed to contain windows.Errno.
func (p *Proc) Call(a ...uintptr) (r1, r2 uintptr, lastErr error) {
	switch len(a) {
	case 0:
		return syscall.Syscall(p.Addr(), uintptr(len(a)), 0, 0, 0)
	case 1:
		return syscall.Syscall(p.Addr(), uintptr(len(a)), a[0], 0, 0)
	case 2:
		return syscall.Syscall(p.Addr(), uintptr(len(a)), a[0], a[1], 0)
	case 3:
		return syscall.Syscall(p.Addr(), uintptr(len(a)), a[0], a[1], a[2])
	case 4:
		return syscall.Syscall6(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], 0, 0)
	case 5:
		return syscall.Syscall6(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], 0)
	case 6:
		return syscall.Syscall6(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5])
	case 7:
		return syscall.Syscall9(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], 0, 0)
	case 8:
		return syscall.Syscall9(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], 0)
	case 9:
		return syscall.Syscall9(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8])
	case 10:
		return syscall.Syscall12(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], 0, 0)
	case 11:
		return syscall.Syscall12(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], 0)
	case 12:
		return syscall.Syscall12(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11])
	case 13:
		return syscall.Syscall15(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], 0, 0)
	case 14:
		return syscall.Syscall15(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], 0)
	case 15:
		return syscall.Syscall15(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14])
	default:
		panic("Call " + p.Name + " with too many arguments " + itoa(len(a)) + ".")
	}
}

// A LazyDLL implements access to a single DLL.
// It will delay the load of the DLL until the first
// call to its Handle method or to one of its
// LazyProc's Addr method.
type LazyDLL struct {
	Name string

	// System determines whether the DLL must be loaded from the
	// Windows System directory, bypassing the normal DLL search
	// path.
	System bool

	mu  sync.Mutex
	dll *DLL // non nil once DLL is loaded
}

// Load loads DLL file d.Name into memory. It returns an error if fails.
// Load will not try to load DLL, if it is already loaded into memory.
func (d *LazyDLL) Load() error {
	// Non-racy version of:
	// if d.dll != nil {
	if atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&d.dll))) != nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.dll != nil {
		return nil
	}

	// kernel32.dll is special, since it's where LoadLibraryEx comes from.
	// The kernel already special-cases its name, so it's always
	// loaded from system32.
	var dll *DLL
	var err error
	if d.Name == "kernel32.dll" {
		dll, err = LoadDLL(d.Name)
	} else {
		dll, err = loadLibraryEx(d.Name, d.System)
	}
	if err != nil {
		return err
	}

	// Non-racy version of:
	// d.dll = dll
	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&d.dll)), unsafe.Pointer(dll))
	return nil
}

// mustLoad is like Load but panics if search fails.
func (d *LazyDLL) mustLoad() {
	e := d.Load()
	if e != nil {
		panic(e)
	}
}

// Handle returns d's module handle.
func (d *LazyDLL) Handle() uintptr {
	d.mustLoad()
	return uintptr(d.dll.Handle)
}

// NewProc returns a LazyProc for accessing the named procedure in the DLL d.
func (d *LazyDLL) NewProc(name string) *LazyProc {
	return &LazyProc{l: d, Name: name}
}

// NewLazyDLL creates new LazyDLL associated with DLL file.
func NewLazyDLL(name string) *LazyDLL {
	return &LazyDLL{Name: name}
}

// NewLazySystemDLL is like NewLazyDLL, but will only
// search Windows System directory for the DLL if name is
// a base name (like "advapi32.dll").
func NewLazySystemDLL(name string) *LazyDLL {
	return &LazyDLL{Name: name, System: true}
}

// A LazyProc implements access to a procedure inside a LazyDLL.
// It delays the lookup until the Addr method is called.
type LazyProc struct {
	Name string

	mu   sync.Mutex
	l    *LazyDLL
	proc *Proc
}

// Find searches DLL for procedure named p.Name. It returns
// an error if search fails. Find will not search procedure,
// if it is already found and loaded into memory.
func (p *LazyProc) Find() error {
	// Non-racy version of:
	// if p.proc == nil {
	if atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&p.proc))) == nil {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.proc == nil {
			e := p.l.Load()
			if e != nil {
				return e
			}
			proc, e := p.l.dll.FindProc(p.Name)
			if e != nil {
				return e
			}
			// Non-racy version of:
			// p.proc = proc
			atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&p.proc)), unsafe.Pointer(proc))
		}
	}
	return nil
}

// mustFind is like Find but panics if search fails.
func (p *LazyProc) mustFind() {
	e := p.Find()
	if e != nil {
		panic(e)
	}
}

// Addr returns the address of the procedure represented by p.
// The return value can be passed to Syscall to run the procedure.
// It will panic if the procedure cannot be found.
func (p *LazyProc) Addr() uintptr {
	p.mustFind()
	return p.proc.Addr()
}

//go:uintptrescapes

// Call executes procedure p with arguments a. It will panic, if more than 15 arguments
// are supplied. It will also panic if the procedure cannot be found.
//
// The returned error is always non-nil, constructed from the result of GetLastError.
// Callers must inspect the primary return value to decide whether an error occurred
// (according to the semantics of the specific function being called) before consulting
// the error. The error will be guaranteed to contain windows.Errno.
func (p *LazyProc) Call(a ...uintptr) (r1, r2 uintptr, lastErr error) {
	p.mustFind()
	return p.proc.Call(a...)
}

var canDoSearchSystem32Once struct {
	sync.Once
	v bool
}

func initCanDoSearchSystem32() {
	// https://msdn.microsoft.com/en-us/library/ms684179(v=vs.85).aspx says:
	// "Windows 7, Windows Server 2008 R2, Windows Vista, and Windows
	// Server 2008: The LOAD_LIBRARY_SEARCH_* flags are available on
	// systems that have KB2533623 installed. To determine whether the
	// flags are available, use GetProcAddress to get the address of the
	// AddDllDirectory, RemoveDllDirectory, or SetDefaultDllDirectories
	// function. If GetProcAddress succeeds, the LOAD_LIBRARY_SEARCH_*
	// flags can be used with LoadLibraryEx."
	canDoSearchSystem32Once.v = (modkernel32.NewProc("AddDllDirectory").Find() == nil)
}

func canDoSearchSystem32() bool {
	canDoSearchSystem32Once.Do(initCanDoSearchSystem32)
	return canDoSearchSystem32Once.v
}

func isBaseName(name string) bool {
	for _, c := range name {
		if c == ':' || c == '/' || c == '\\' {
			return false
		}
	}
	return true
}

// loadLibraryEx wraps the Windows LoadLibraryEx function.
//
// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms684179(v=vs.85).aspx
//
// If name is not an absolute path, LoadLibraryEx searches for the DLL
// in a variety of automatic locations unless constrained by flags.
// See: https://msdn.microsoft.com/en-us/library/ff919712%28VS.85%29.aspx
func loadLibraryEx(name string, system bool) (*DLL, error) {
	loadDLL := name
	var flags uintptr
	if system {
		if canDoSearchSystem32() {
			flags = LOAD_LIBRARY_SEARCH_SYSTEM32
		} else if isBaseName(name) {
			// WindowsXP or unpatched Windows machine
			// trying to load "foo.dll" out of the system
			// folder, but LoadLibraryEx doesn't support
			// that yet on their system, so emulate it.
			systemdir, err := GetSystemDirectory()
			if err != nil {
				return nil, err
			}
			loadDLL = systemdir + "\\" + name
		}
	}
	h, err := LoadLibraryEx(loadDLL, 0, flags)
	if err != nil {
		return nil, err
	}
	return &DLL{Name: name, Handle: h}, nil
}

type errString string

func (s errString) Error() string { return string(s) }

"""



```