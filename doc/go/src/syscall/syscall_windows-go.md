Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Skim and Identification of Key Areas:**

The first step is a quick read-through to get a general sense of what the code is doing. Keywords like `syscall`, function names like `StringToUTF16`, `CreateFile`, `socket`, and constant names like `InvalidHandle` immediately jump out. The `package syscall` declaration confirms this is related to system calls. The comments mentioning Windows system calls are also a strong indicator.

**2. Categorization of Functionality:**

As I skim, I start mentally grouping related functions and types. I see:

* **String Conversion:**  Functions like `StringToUTF16`, `UTF16FromString`, `UTF16ToString`, `StringToUTF16Ptr`, `UTF16PtrFromString`. These clearly handle conversions between Go strings (UTF-8) and Windows-specific UTF-16 encoding.
* **Error Handling:** The `Errno` type and its methods (`Error`, `Is`, `Temporary`, `Timeout`) are central to Windows error handling. The `FormatMessage` function is also related.
* **Callbacks:** `NewCallback` and `NewCallbackCDecl` are clearly for creating function pointers for use in Windows callbacks.
* **System Call Wrappers:** A large block of functions starting with `//sys` followed by Windows API names (e.g., `LoadLibraryW`, `CreateFileW`, `ReadFile`, `WriteFile`, `CloseHandle`, `socket`, `bind`, etc.). These are direct wrappers around Windows system calls.
* **Higher-Level File Operations:** Functions like `Open`, `Read`, `Write`, `Seek`, `Close`, `Getwd`, `Chdir`, `Mkdir`, `Rmdir`, `Unlink`, `Rename`. These are Go-style abstractions built on top of the lower-level system call wrappers for common file system operations.
* **Networking:** Functions like `WSAStartup`, `WSACleanup`, `socket`, `bind`, `connect`, `listen`, `accept`, `send`, `recv`. These relate to network socket programming.
* **Other System Functions:**  Functions like `GetVersion`, `ExitProcess`, `GetComputerName`, `GetSystemTimeAsFileTime`, `CreateProcess`, `GetEnvironmentStrings`,  `GetTempPath`,  `CreatePipe`, etc. These cover various other system-level interactions.

**3. Analyzing Specific Function Groups in Detail:**

Once the broad categories are identified, I focus on the details of each group:

* **String Conversion:** I notice the deprecation of `StringToUTF16` and the suggestion to use `UTF16FromString`. The functions handle null termination and potential null bytes within the string. The mention of "WTF-8" for unpaired surrogates is a detail to note.
* **Error Handling:**  The `Errno` type implementing the `error` interface is standard Go practice. The `Is` method checks against common Go error types (like `os.ErrNotExist`). The use of `FormatMessageW` to get human-readable error messages from Windows is expected.
* **Callbacks:** The explanation of `stdcall` and `cdecl` calling conventions is important for understanding how these functions are used. The limitation on the number of callbacks and the lack of memory release are significant caveats.
* **System Call Wrappers:** I recognize the `//sys` directive as a special Go mechanism for generating system call wrappers. I note the `failretval` annotations, which indicate the values returned by the underlying Windows API to signal failure.
* **Higher-Level File Operations:** I see how these functions map to the lower-level `CreateFile`, `ReadFile`, `WriteFile`, etc. The `Open` function's handling of different flags (e.g., `O_RDONLY`, `O_CREAT`, `O_TRUNC`) is typical of OS file opening functions.
* **Networking:** The presence of `WSAStartup` and `WSACleanup` confirms this section deals with Winsock (Windows Sockets). The other functions (`socket`, `bind`, etc.) are standard socket programming primitives.

**4. Looking for Code Examples and Edge Cases (as requested):**

The prompt specifically asked for examples and potential pitfalls. While the provided snippet doesn't *execute* any complex logic on its own, I can infer examples based on the function signatures and what they represent:

* **String Conversion Example (Mental Simulation):**  I can imagine a scenario where a Go program needs to pass a filename to a Windows API. The `UTF16PtrFromString` function would be used.

```go
// Hypothetical usage within a larger program
filename := "C:\\MyFile.txt"
filenamePtr, err := syscall.UTF16PtrFromString(filename)
if err != nil {
    // Handle error
}
// Pass filenamePtr to a Windows API function
```

* **Error Handling Example:** I see the `errors.Is` usage in the `Errno.Is` method, which is a common pattern for checking error types.

* **Callback Example:** I can envision needing to pass a Go function to a Windows API that expects a callback. `NewCallback` would be used. However, demonstrating this fully requires knowing the specific Windows API.

* **Potential Pitfalls (based on my knowledge of Windows API and similar system call wrappers):**
    * **Incorrect String Encoding:**  Forgetting to convert strings to UTF-16 before passing them to Windows APIs is a classic mistake.
    * **Handle Management:** Not closing handles returned by functions like `CreateFile` or `socket` can lead to resource leaks.
    * **Error Handling:** Ignoring the `error` return values from system calls is a major problem.
    * **Callback Lifetime:** The "never released" memory for callbacks is a crucial point. Creating too many callbacks can cause issues.

**5. Synthesizing the Functionality Summary:**

Finally, I combine the categorized functionality into a concise summary. I focus on the core purpose of the code: providing access to Windows system calls from Go. I mention the key areas like file I/O, process management, networking, and string conversion.

**Self-Correction/Refinement During the Process:**

* **Initial Over-Simplification:**  My initial skim might categorize too broadly. I need to go back and refine the categories to be more specific (e.g., distinguish between low-level system call wrappers and higher-level file operations).
* **Considering Deprecation:**  I noted the deprecated functions and made sure to mention the preferred alternatives.
* **Addressing All Parts of the Prompt:** I constantly referred back to the prompt to ensure I was addressing all the requested points (functionality, examples, pitfalls, etc.).
* **Using Correct Terminology:** I made sure to use accurate terms like "Winsock," "UTF-16," "stdcall," and "cdecl."

By following these steps, I could systematically analyze the code snippet and generate the comprehensive summary provided in the initial example answer.
这个go语言实现文件 `go/src/syscall/syscall_windows.go` 的主要功能是**为Go程序提供与Windows操作系统进行底层交互的能力，封装了Windows系统调用 (system calls) 的接口**。

更具体地说，它做了以下几件事：

1. **定义了与Windows API相关的常量和类型:**  例如 `Handle`, `InvalidHandle`, `Errno` 以及各种Windows API中使用的结构体，如 `SecurityAttributes`, `Overlapped`, `Filetime` 等。这些定义是与Windows系统交互的基础。

2. **提供了UTF-8和UTF-16字符串之间的转换函数:** Windows API 广泛使用 UTF-16 编码的字符串。  `StringToUTF16`, `UTF16FromString`, `UTF16ToString`, `StringToUTF16Ptr`, `UTF16PtrFromString` 等函数用于在Go的UTF-8字符串和Windows的UTF-16字符串之间进行转换。

3. **实现了Windows错误码的处理:**  `Errno` 类型代表Windows的错误码，并提供了 `Error()` 方法将其转换为可读的字符串。  `Is()` 方法用于判断 `Errno` 是否属于特定的Go标准错误类型 (如 `os.ErrNotExist`)。`Temporary()` 和 `Timeout()` 方法判断错误是否是临时性的或超时相关的。

4. **提供了调用Windows API的Go函数包装器:** 文件中大量的 `//sys` 开头的注释定义了与实际Windows API函数对应的Go函数。例如，`//sys	CreateFile(name *uint16, access uint32, ...)`  会生成一个名为 `CreateFile` 的Go函数，该函数会调用底层的Windows `CreateFileW` API。  这些包装器负责将Go的数据类型转换为Windows API期望的类型，并处理返回值。

5. **实现了Go标准库中 `os` 包等使用的底层系统调用接口:**  例如，`Open`, `Read`, `Write`, `Close`, `Getwd`, `Chdir`, `Mkdir`, `Rmdir`, `Unlink`, `Rename` 等函数是Go程序进行文件操作的基础，这些函数在Windows平台上通过调用相应的Windows API实现。

6. **提供了创建Windows回调函数的机制:** `NewCallback` 和 `NewCallbackCDecl` 函数可以将Go函数转换为符合Windows `stdcall` 或 `cdecl` 调用约定的函数指针，这对于与需要回调函数的Windows API进行交互非常重要。

**它是什么go语言功能的实现：**

这个文件是Go语言 `syscall` 标准库的一部分，专门负责提供对Windows系统调用的访问。它是Go程序能够与Windows操作系统底层进行交互的关键组件，例如创建文件、读写文件、创建进程、进行网络通信等。

**Go代码举例说明:**

假设我们需要在Windows下创建一个文件并写入内容，可以使用 `syscall` 包中的函数：

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	filename := "test.txt"
	filenameUTF16, err := syscall.UTF16PtrFromString(filename)
	if err != nil {
		fmt.Println("Error converting filename:", err)
		return
	}

	// 创建文件
	handle, err := syscall.CreateFile(
		filenameUTF16,
		syscall.GENERIC_WRITE,
		0,
		nil,
		syscall.CREATE_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer syscall.CloseHandle(handle)

	// 写入内容
	content := "Hello, Windows from Go!"
	contentBytes := []byte(content)
	var bytesWritten uint32
	err = syscall.WriteFile(handle, contentBytes, &bytesWritten, nil)
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}

	fmt.Printf("Successfully wrote %d bytes to %s\n", bytesWritten, filename)
}
```

**假设的输入与输出:**

* **输入:**  程序执行时，`filename` 被设置为 "test.txt"，`content` 被设置为 "Hello, Windows from Go!"。
* **输出:**  如果执行成功，会在当前目录下创建一个名为 `test.txt` 的文件，文件内容为 "Hello, Windows from Go!"。程序的标准输出会显示 "Successfully wrote 23 bytes to test.txt" (假设UTF-8编码时该字符串长度为23)。如果执行失败，会打印相应的错误信息。

**归纳一下它的功能 (针对第1部分):**

这部分 `syscall_windows.go` 文件的主要功能是提供了基础的类型定义和实用工具函数，用于在Go语言中与Windows系统进行交互，特别是：

* **定义了与Windows API互操作所需的基本类型，例如句柄和错误码。**
* **提供了方便的UTF-8和UTF-16字符串转换功能，简化了与Windows API的字符串参数传递。**
* **实现了Windows错误码的封装和处理，使得Go程序能够更好地理解和处理Windows的错误。**

它为后续的系统调用包装器和更高级的文件/网络操作提供了基础支撑。

Prompt: 
```
这是路径为go/src/syscall/syscall_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Windows system calls.

package syscall

import (
	errorspkg "errors"
	"internal/asan"
	"internal/bytealg"
	"internal/itoa"
	"internal/msan"
	"internal/oserror"
	"internal/race"
	"runtime"
	"sync"
	"unsafe"
)

type Handle uintptr

const InvalidHandle = ^Handle(0)

// StringToUTF16 returns the UTF-16 encoding of the UTF-8 string s,
// with a terminating NUL added. If s contains a NUL byte this
// function panics instead of returning an error.
//
// Deprecated: Use [UTF16FromString] instead.
func StringToUTF16(s string) []uint16 {
	a, err := UTF16FromString(s)
	if err != nil {
		panic("syscall: string with NUL passed to StringToUTF16")
	}
	return a
}

// UTF16FromString returns the UTF-16 encoding of the UTF-8 string
// s, with a terminating NUL added. If s contains a NUL byte at any
// location, it returns (nil, [EINVAL]). Unpaired surrogates
// are encoded using WTF-8.
func UTF16FromString(s string) ([]uint16, error) {
	if bytealg.IndexByteString(s, 0) != -1 {
		return nil, EINVAL
	}
	// Valid UTF-8 characters between 1 and 3 bytes require one uint16.
	// Valid UTF-8 characters of 4 bytes require two uint16.
	// Bytes with invalid UTF-8 encoding require maximum one uint16 per byte.
	// So the number of UTF-8 code units (len(s)) is always greater or
	// equal than the number of UTF-16 code units.
	// Also account for the terminating NUL character.
	buf := make([]uint16, 0, len(s)+1)
	buf = encodeWTF16(s, buf)
	return append(buf, 0), nil
}

// UTF16ToString returns the UTF-8 encoding of the UTF-16 sequence s,
// with a terminating NUL removed. Unpaired surrogates are decoded
// using WTF-8 instead of UTF-8 encoding.
func UTF16ToString(s []uint16) string {
	maxLen := 0
	for i, v := range s {
		if v == 0 {
			s = s[0:i]
			break
		}
		switch {
		case v <= rune1Max:
			maxLen += 1
		case v <= rune2Max:
			maxLen += 2
		default:
			// r is a non-surrogate that decodes to 3 bytes,
			// or is an unpaired surrogate (also 3 bytes in WTF-8),
			// or is one half of a valid surrogate pair.
			// If it is half of a pair, we will add 3 for the second surrogate
			// (total of 6) and overestimate by 2 bytes for the pair,
			// since the resulting rune only requires 4 bytes.
			maxLen += 3
		}
	}
	buf := decodeWTF16(s, make([]byte, 0, maxLen))
	return unsafe.String(unsafe.SliceData(buf), len(buf))
}

// utf16PtrToString is like UTF16ToString, but takes *uint16
// as a parameter instead of []uint16.
func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	end := unsafe.Pointer(p)
	n := 0
	for *(*uint16)(end) != 0 {
		end = unsafe.Pointer(uintptr(end) + unsafe.Sizeof(*p))
		n++
	}
	return UTF16ToString(unsafe.Slice(p, n))
}

// StringToUTF16Ptr returns pointer to the UTF-16 encoding of
// the UTF-8 string s, with a terminating NUL added. If s
// contains a NUL byte this function panics instead of
// returning an error.
//
// Deprecated: Use [UTF16PtrFromString] instead.
func StringToUTF16Ptr(s string) *uint16 { return &StringToUTF16(s)[0] }

// UTF16PtrFromString returns pointer to the UTF-16 encoding of
// the UTF-8 string s, with a terminating NUL added. If s
// contains a NUL byte at any location, it returns (nil, EINVAL).
// Unpaired surrogates are encoded using WTF-8.
func UTF16PtrFromString(s string) (*uint16, error) {
	a, err := UTF16FromString(s)
	if err != nil {
		return nil, err
	}
	return &a[0], nil
}

// Errno is the Windows error number.
//
// Errno values can be tested against error values using [errors.Is].
// For example:
//
//	_, _, err := syscall.Syscall(...)
//	if errors.Is(err, fs.ErrNotExist) ...
type Errno uintptr

func langid(pri, sub uint16) uint32 { return uint32(sub)<<10 | uint32(pri) }

// FormatMessage is deprecated (msgsrc should be uintptr, not uint32, but can
// not be changed due to the Go 1 compatibility guarantee).
//
// Deprecated: Use FormatMessage from golang.org/x/sys/windows instead.
func FormatMessage(flags uint32, msgsrc uint32, msgid uint32, langid uint32, buf []uint16, args *byte) (n uint32, err error) {
	return formatMessage(flags, uintptr(msgsrc), msgid, langid, buf, args)
}

func (e Errno) Error() string {
	// deal with special go errors
	idx := int(e - APPLICATION_ERROR)
	if 0 <= idx && idx < len(errors) {
		return errors[idx]
	}
	// ask windows for the remaining errors
	var flags uint32 = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ARGUMENT_ARRAY | FORMAT_MESSAGE_IGNORE_INSERTS
	b := make([]uint16, 300)
	n, err := formatMessage(flags, 0, uint32(e), langid(LANG_ENGLISH, SUBLANG_ENGLISH_US), b, nil)
	if err != nil {
		n, err = formatMessage(flags, 0, uint32(e), 0, b, nil)
		if err != nil {
			return "winapi error #" + itoa.Itoa(int(e))
		}
	}
	// trim terminating \r and \n
	for ; n > 0 && (b[n-1] == '\n' || b[n-1] == '\r'); n-- {
	}
	return UTF16ToString(b[:n])
}

const (
	_ERROR_NOT_ENOUGH_MEMORY    = Errno(8)
	_ERROR_NOT_SUPPORTED        = Errno(50)
	_ERROR_BAD_NETPATH          = Errno(53)
	_ERROR_CALL_NOT_IMPLEMENTED = Errno(120)
)

func (e Errno) Is(target error) bool {
	switch target {
	case oserror.ErrPermission:
		return e == ERROR_ACCESS_DENIED ||
			e == EACCES ||
			e == EPERM
	case oserror.ErrExist:
		return e == ERROR_ALREADY_EXISTS ||
			e == ERROR_DIR_NOT_EMPTY ||
			e == ERROR_FILE_EXISTS ||
			e == EEXIST ||
			e == ENOTEMPTY
	case oserror.ErrNotExist:
		return e == ERROR_FILE_NOT_FOUND ||
			e == _ERROR_BAD_NETPATH ||
			e == ERROR_PATH_NOT_FOUND ||
			e == ENOENT
	case errorspkg.ErrUnsupported:
		return e == _ERROR_NOT_SUPPORTED ||
			e == _ERROR_CALL_NOT_IMPLEMENTED ||
			e == ENOSYS ||
			e == ENOTSUP ||
			e == EOPNOTSUPP ||
			e == EWINDOWS
	}
	return false
}

func (e Errno) Temporary() bool {
	return e == EINTR || e == EMFILE || e.Timeout()
}

func (e Errno) Timeout() bool {
	return e == EAGAIN || e == EWOULDBLOCK || e == ETIMEDOUT
}

// Implemented in runtime/syscall_windows.go.
func compileCallback(fn any, cleanstack bool) uintptr

// NewCallback converts a Go function to a function pointer conforming to the stdcall calling convention.
// This is useful when interoperating with Windows code requiring callbacks.
// The argument is expected to be a function with one uintptr-sized result. The function must not have arguments with size larger than the size of uintptr.
// Only a limited number of callbacks may be created in a single Go process, and any memory allocated
// for these callbacks is never released.
// Between NewCallback and NewCallbackCDecl, at least 1024 callbacks can always be created.
func NewCallback(fn any) uintptr {
	return compileCallback(fn, true)
}

// NewCallbackCDecl converts a Go function to a function pointer conforming to the cdecl calling convention.
// This is useful when interoperating with Windows code requiring callbacks.
// The argument is expected to be a function with one uintptr-sized result. The function must not have arguments with size larger than the size of uintptr.
// Only a limited number of callbacks may be created in a single Go process, and any memory allocated
// for these callbacks is never released.
// Between NewCallback and NewCallbackCDecl, at least 1024 callbacks can always be created.
func NewCallbackCDecl(fn any) uintptr {
	return compileCallback(fn, false)
}

// windows api calls

//sys	GetLastError() (lasterr error)
//sys	LoadLibrary(libname string) (handle Handle, err error) = LoadLibraryW
//sys	FreeLibrary(handle Handle) (err error)
//sys	GetProcAddress(module Handle, procname string) (proc uintptr, err error)
//sys	GetVersion() (ver uint32, err error)
//sys	formatMessage(flags uint32, msgsrc uintptr, msgid uint32, langid uint32, buf []uint16, args *byte) (n uint32, err error) = FormatMessageW
//sys	ExitProcess(exitcode uint32)
//sys	CreateFile(name *uint16, access uint32, mode uint32, sa *SecurityAttributes, createmode uint32, attrs uint32, templatefile int32) (handle Handle, err error) [failretval==InvalidHandle] = CreateFileW
//sys	readFile(handle Handle, buf []byte, done *uint32, overlapped *Overlapped) (err error) = ReadFile
//sys	writeFile(handle Handle, buf []byte, done *uint32, overlapped *Overlapped) (err error) = WriteFile
//sys	SetFilePointer(handle Handle, lowoffset int32, highoffsetptr *int32, whence uint32) (newlowoffset uint32, err error) [failretval==0xffffffff]
//sys	CloseHandle(handle Handle) (err error)
//sys	GetStdHandle(stdhandle int) (handle Handle, err error) [failretval==InvalidHandle]
//sys	findFirstFile1(name *uint16, data *win32finddata1) (handle Handle, err error) [failretval==InvalidHandle] = FindFirstFileW
//sys	findNextFile1(handle Handle, data *win32finddata1) (err error) = FindNextFileW
//sys	FindClose(handle Handle) (err error)
//sys	GetFileInformationByHandle(handle Handle, data *ByHandleFileInformation) (err error)
//sys	GetCurrentDirectory(buflen uint32, buf *uint16) (n uint32, err error) = GetCurrentDirectoryW
//sys	SetCurrentDirectory(path *uint16) (err error) = SetCurrentDirectoryW
//sys	CreateDirectory(path *uint16, sa *SecurityAttributes) (err error) = CreateDirectoryW
//sys	RemoveDirectory(path *uint16) (err error) = RemoveDirectoryW
//sys	DeleteFile(path *uint16) (err error) = DeleteFileW
//sys	MoveFile(from *uint16, to *uint16) (err error) = MoveFileW
//sys	GetComputerName(buf *uint16, n *uint32) (err error) = GetComputerNameW
//sys	SetEndOfFile(handle Handle) (err error)
//sys	GetSystemTimeAsFileTime(time *Filetime)
//sys	GetTimeZoneInformation(tzi *Timezoneinformation) (rc uint32, err error) [failretval==0xffffffff]
//sys	createIoCompletionPort(filehandle Handle, cphandle Handle, key uintptr, threadcnt uint32) (handle Handle, err error) = CreateIoCompletionPort
//sys	getQueuedCompletionStatus(cphandle Handle, qty *uint32, key *uintptr, overlapped **Overlapped, timeout uint32) (err error) = GetQueuedCompletionStatus
//sys	postQueuedCompletionStatus(cphandle Handle, qty uint32, key uintptr, overlapped *Overlapped) (err error) = PostQueuedCompletionStatus
//sys	CancelIo(s Handle) (err error)
//sys	CancelIoEx(s Handle, o *Overlapped) (err error)
//sys	CreateProcess(appName *uint16, commandLine *uint16, procSecurity *SecurityAttributes, threadSecurity *SecurityAttributes, inheritHandles bool, creationFlags uint32, env *uint16, currentDir *uint16, startupInfo *StartupInfo, outProcInfo *ProcessInformation) (err error) = CreateProcessW
//sys	CreateProcessAsUser(token Token, appName *uint16, commandLine *uint16, procSecurity *SecurityAttributes, threadSecurity *SecurityAttributes, inheritHandles bool, creationFlags uint32, env *uint16, currentDir *uint16, startupInfo *StartupInfo, outProcInfo *ProcessInformation) (err error) = advapi32.CreateProcessAsUserW
//sys	OpenProcess(da uint32, inheritHandle bool, pid uint32) (handle Handle, err error)
//sys	TerminateProcess(handle Handle, exitcode uint32) (err error)
//sys	GetExitCodeProcess(handle Handle, exitcode *uint32) (err error)
//sys	getStartupInfo(startupInfo *StartupInfo) = GetStartupInfoW
//sys	GetCurrentProcess() (pseudoHandle Handle, err error)
//sys	GetProcessTimes(handle Handle, creationTime *Filetime, exitTime *Filetime, kernelTime *Filetime, userTime *Filetime) (err error)
//sys	DuplicateHandle(hSourceProcessHandle Handle, hSourceHandle Handle, hTargetProcessHandle Handle, lpTargetHandle *Handle, dwDesiredAccess uint32, bInheritHandle bool, dwOptions uint32) (err error)
//sys	WaitForSingleObject(handle Handle, waitMilliseconds uint32) (event uint32, err error) [failretval==0xffffffff]
//sys	GetTempPath(buflen uint32, buf *uint16) (n uint32, err error) = GetTempPathW
//sys	CreatePipe(readhandle *Handle, writehandle *Handle, sa *SecurityAttributes, size uint32) (err error)
//sys	GetFileType(filehandle Handle) (n uint32, err error)
//sys	CryptAcquireContext(provhandle *Handle, container *uint16, provider *uint16, provtype uint32, flags uint32) (err error) = advapi32.CryptAcquireContextW
//sys	CryptReleaseContext(provhandle Handle, flags uint32) (err error) = advapi32.CryptReleaseContext
//sys	CryptGenRandom(provhandle Handle, buflen uint32, buf *byte) (err error) = advapi32.CryptGenRandom
//sys	GetEnvironmentStrings() (envs *uint16, err error) [failretval==nil] = kernel32.GetEnvironmentStringsW
//sys	FreeEnvironmentStrings(envs *uint16) (err error) = kernel32.FreeEnvironmentStringsW
//sys	GetEnvironmentVariable(name *uint16, buffer *uint16, size uint32) (n uint32, err error) = kernel32.GetEnvironmentVariableW
//sys	SetEnvironmentVariable(name *uint16, value *uint16) (err error) = kernel32.SetEnvironmentVariableW
//sys	SetFileTime(handle Handle, ctime *Filetime, atime *Filetime, wtime *Filetime) (err error)
//sys	GetFileAttributes(name *uint16) (attrs uint32, err error) [failretval==INVALID_FILE_ATTRIBUTES] = kernel32.GetFileAttributesW
//sys	SetFileAttributes(name *uint16, attrs uint32) (err error) = kernel32.SetFileAttributesW
//sys	GetFileAttributesEx(name *uint16, level uint32, info *byte) (err error) = kernel32.GetFileAttributesExW
//sys	GetCommandLine() (cmd *uint16) = kernel32.GetCommandLineW
//sys	CommandLineToArgv(cmd *uint16, argc *int32) (argv *[8192]*[8192]uint16, err error) [failretval==nil] = shell32.CommandLineToArgvW
//sys	LocalFree(hmem Handle) (handle Handle, err error) [failretval!=0]
//sys	SetHandleInformation(handle Handle, mask uint32, flags uint32) (err error)
//sys	FlushFileBuffers(handle Handle) (err error)
//sys	GetFullPathName(path *uint16, buflen uint32, buf *uint16, fname **uint16) (n uint32, err error) = kernel32.GetFullPathNameW
//sys	GetLongPathName(path *uint16, buf *uint16, buflen uint32) (n uint32, err error) = kernel32.GetLongPathNameW
//sys	GetShortPathName(longpath *uint16, shortpath *uint16, buflen uint32) (n uint32, err error) = kernel32.GetShortPathNameW
//sys	CreateFileMapping(fhandle Handle, sa *SecurityAttributes, prot uint32, maxSizeHigh uint32, maxSizeLow uint32, name *uint16) (handle Handle, err error) = kernel32.CreateFileMappingW
//sys	MapViewOfFile(handle Handle, access uint32, offsetHigh uint32, offsetLow uint32, length uintptr) (addr uintptr, err error)
//sys	UnmapViewOfFile(addr uintptr) (err error)
//sys	FlushViewOfFile(addr uintptr, length uintptr) (err error)
//sys	VirtualLock(addr uintptr, length uintptr) (err error)
//sys	VirtualUnlock(addr uintptr, length uintptr) (err error)
//sys	TransmitFile(s Handle, handle Handle, bytesToWrite uint32, bytsPerSend uint32, overlapped *Overlapped, transmitFileBuf *TransmitFileBuffers, flags uint32) (err error) = mswsock.TransmitFile
//sys	ReadDirectoryChanges(handle Handle, buf *byte, buflen uint32, watchSubTree bool, mask uint32, retlen *uint32, overlapped *Overlapped, completionRoutine uintptr) (err error) = kernel32.ReadDirectoryChangesW
//sys	CertOpenSystemStore(hprov Handle, name *uint16) (store Handle, err error) = crypt32.CertOpenSystemStoreW
//sys   CertOpenStore(storeProvider uintptr, msgAndCertEncodingType uint32, cryptProv uintptr, flags uint32, para uintptr) (handle Handle, err error) = crypt32.CertOpenStore
//sys	CertEnumCertificatesInStore(store Handle, prevContext *CertContext) (context *CertContext, err error) [failretval==nil] = crypt32.CertEnumCertificatesInStore
//sys   CertAddCertificateContextToStore(store Handle, certContext *CertContext, addDisposition uint32, storeContext **CertContext) (err error) = crypt32.CertAddCertificateContextToStore
//sys	CertCloseStore(store Handle, flags uint32) (err error) = crypt32.CertCloseStore
//sys   CertGetCertificateChain(engine Handle, leaf *CertContext, time *Filetime, additionalStore Handle, para *CertChainPara, flags uint32, reserved uintptr, chainCtx **CertChainContext) (err error) = crypt32.CertGetCertificateChain
//sys   CertFreeCertificateChain(ctx *CertChainContext) = crypt32.CertFreeCertificateChain
//sys   CertCreateCertificateContext(certEncodingType uint32, certEncoded *byte, encodedLen uint32) (context *CertContext, err error) [failretval==nil] = crypt32.CertCreateCertificateContext
//sys   CertFreeCertificateContext(ctx *CertContext) (err error) = crypt32.CertFreeCertificateContext
//sys   CertVerifyCertificateChainPolicy(policyOID uintptr, chain *CertChainContext, para *CertChainPolicyPara, status *CertChainPolicyStatus) (err error) = crypt32.CertVerifyCertificateChainPolicy
//sys	RegOpenKeyEx(key Handle, subkey *uint16, options uint32, desiredAccess uint32, result *Handle) (regerrno error) = advapi32.RegOpenKeyExW
//sys	RegCloseKey(key Handle) (regerrno error) = advapi32.RegCloseKey
//sys	RegQueryInfoKey(key Handle, class *uint16, classLen *uint32, reserved *uint32, subkeysLen *uint32, maxSubkeyLen *uint32, maxClassLen *uint32, valuesLen *uint32, maxValueNameLen *uint32, maxValueLen *uint32, saLen *uint32, lastWriteTime *Filetime) (regerrno error) = advapi32.RegQueryInfoKeyW
//sys	regEnumKeyEx(key Handle, index uint32, name *uint16, nameLen *uint32, reserved *uint32, class *uint16, classLen *uint32, lastWriteTime *Filetime) (regerrno error) = advapi32.RegEnumKeyExW
//sys	RegQueryValueEx(key Handle, name *uint16, reserved *uint32, valtype *uint32, buf *byte, buflen *uint32) (regerrno error) = advapi32.RegQueryValueExW
//sys	getCurrentProcessId() (pid uint32) = kernel32.GetCurrentProcessId
//sys	GetConsoleMode(console Handle, mode *uint32) (err error) = kernel32.GetConsoleMode
//sys	WriteConsole(console Handle, buf *uint16, towrite uint32, written *uint32, reserved *byte) (err error) = kernel32.WriteConsoleW
//sys	ReadConsole(console Handle, buf *uint16, toread uint32, read *uint32, inputControl *byte) (err error) = kernel32.ReadConsoleW
//sys	CreateToolhelp32Snapshot(flags uint32, processId uint32) (handle Handle, err error) [failretval==InvalidHandle] = kernel32.CreateToolhelp32Snapshot
//sys	Process32First(snapshot Handle, procEntry *ProcessEntry32) (err error) = kernel32.Process32FirstW
//sys	Process32Next(snapshot Handle, procEntry *ProcessEntry32) (err error) = kernel32.Process32NextW
//sys	DeviceIoControl(handle Handle, ioControlCode uint32, inBuffer *byte, inBufferSize uint32, outBuffer *byte, outBufferSize uint32, bytesReturned *uint32, overlapped *Overlapped) (err error)
//sys	setFileInformationByHandle(handle Handle, fileInformationClass uint32, buf unsafe.Pointer, bufsize uint32) (err error) = kernel32.SetFileInformationByHandle
// This function returns 1 byte BOOLEAN rather than the 4 byte BOOL.
//sys	CreateSymbolicLink(symlinkfilename *uint16, targetfilename *uint16, flags uint32) (err error) [failretval&0xff==0] = CreateSymbolicLinkW
//sys	CreateHardLink(filename *uint16, existingfilename *uint16, reserved uintptr) (err error) [failretval&0xff==0] = CreateHardLinkW
//sys	initializeProcThreadAttributeList(attrlist *_PROC_THREAD_ATTRIBUTE_LIST, attrcount uint32, flags uint32, size *uintptr) (err error) = InitializeProcThreadAttributeList
//sys	deleteProcThreadAttributeList(attrlist *_PROC_THREAD_ATTRIBUTE_LIST) = DeleteProcThreadAttributeList
//sys	updateProcThreadAttribute(attrlist *_PROC_THREAD_ATTRIBUTE_LIST, flags uint32, attr uintptr, value unsafe.Pointer, size uintptr, prevvalue unsafe.Pointer, returnedsize *uintptr) (err error) = UpdateProcThreadAttribute
//sys	getFinalPathNameByHandle(file Handle, filePath *uint16, filePathSize uint32, flags uint32) (n uint32, err error) [n == 0 || n >= filePathSize] = kernel32.GetFinalPathNameByHandleW

// syscall interface implementation for other packages

func makeInheritSa() *SecurityAttributes {
	var sa SecurityAttributes
	sa.Length = uint32(unsafe.Sizeof(sa))
	sa.InheritHandle = 1
	return &sa
}

func Open(name string, flag int, perm uint32) (fd Handle, err error) {
	if len(name) == 0 {
		return InvalidHandle, ERROR_FILE_NOT_FOUND
	}
	namep, err := UTF16PtrFromString(name)
	if err != nil {
		return InvalidHandle, err
	}
	var access uint32
	switch flag & (O_RDONLY | O_WRONLY | O_RDWR) {
	case O_RDONLY:
		access = GENERIC_READ
	case O_WRONLY:
		access = GENERIC_WRITE
	case O_RDWR:
		access = GENERIC_READ | GENERIC_WRITE
	}
	if flag&O_CREAT != 0 {
		access |= GENERIC_WRITE
	}
	if flag&O_APPEND != 0 {
		// Remove GENERIC_WRITE unless O_TRUNC is set, in which case we need it to truncate the file.
		// We can't just remove FILE_WRITE_DATA because GENERIC_WRITE without FILE_WRITE_DATA
		// starts appending at the beginning of the file rather than at the end.
		if flag&O_TRUNC == 0 {
			access &^= GENERIC_WRITE
		}
		// Set all access rights granted by GENERIC_WRITE except for FILE_WRITE_DATA.
		access |= FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | _FILE_WRITE_EA | STANDARD_RIGHTS_WRITE | SYNCHRONIZE
	}
	sharemode := uint32(FILE_SHARE_READ | FILE_SHARE_WRITE)
	var sa *SecurityAttributes
	if flag&O_CLOEXEC == 0 {
		sa = makeInheritSa()
	}
	// We don't use CREATE_ALWAYS, because when opening a file with
	// FILE_ATTRIBUTE_READONLY these will replace an existing file
	// with a new, read-only one. See https://go.dev/issue/38225.
	//
	// Instead, we ftruncate the file after opening when O_TRUNC is set.
	var createmode uint32
	switch {
	case flag&(O_CREAT|O_EXCL) == (O_CREAT | O_EXCL):
		createmode = CREATE_NEW
	case flag&O_CREAT == O_CREAT:
		createmode = OPEN_ALWAYS
	default:
		createmode = OPEN_EXISTING
	}
	var attrs uint32 = FILE_ATTRIBUTE_NORMAL
	if perm&S_IWRITE == 0 {
		attrs = FILE_ATTRIBUTE_READONLY
	}
	if flag&O_WRONLY == 0 && flag&O_RDWR == 0 {
		// We might be opening or creating a directory.
		// CreateFile requires FILE_FLAG_BACKUP_SEMANTICS
		// to work with directories.
		attrs |= FILE_FLAG_BACKUP_SEMANTICS
	}
	if flag&O_SYNC != 0 {
		const _FILE_FLAG_WRITE_THROUGH = 0x80000000
		attrs |= _FILE_FLAG_WRITE_THROUGH
	}
	h, err := CreateFile(namep, access, sharemode, sa, createmode, attrs, 0)
	if err != nil {
		if err == ERROR_ACCESS_DENIED && (flag&O_WRONLY != 0 || flag&O_RDWR != 0) {
			// We should return EISDIR when we are trying to open a directory with write access.
			fa, e1 := GetFileAttributes(namep)
			if e1 == nil && fa&FILE_ATTRIBUTE_DIRECTORY != 0 {
				err = EISDIR
			}
		}
		return InvalidHandle, err
	}
	if flag&O_TRUNC == O_TRUNC {
		err = Ftruncate(h, 0)
		if err != nil {
			CloseHandle(h)
			return InvalidHandle, err
		}
	}
	return h, nil
}

func Read(fd Handle, p []byte) (n int, err error) {
	var done uint32
	e := ReadFile(fd, p, &done, nil)
	if e != nil {
		if e == ERROR_BROKEN_PIPE {
			// NOTE(brainman): work around ERROR_BROKEN_PIPE is returned on reading EOF from stdin
			return 0, nil
		}
		return 0, e
	}
	return int(done), nil
}

func Write(fd Handle, p []byte) (n int, err error) {
	var done uint32
	e := WriteFile(fd, p, &done, nil)
	if e != nil {
		return 0, e
	}
	return int(done), nil
}

func ReadFile(fd Handle, p []byte, done *uint32, overlapped *Overlapped) error {
	err := readFile(fd, p, done, overlapped)
	if race.Enabled {
		if *done > 0 {
			race.WriteRange(unsafe.Pointer(&p[0]), int(*done))
		}
		race.Acquire(unsafe.Pointer(&ioSync))
	}
	if msan.Enabled && *done > 0 {
		msan.Write(unsafe.Pointer(&p[0]), uintptr(*done))
	}
	if asan.Enabled && *done > 0 {
		asan.Write(unsafe.Pointer(&p[0]), uintptr(*done))
	}
	return err
}

func WriteFile(fd Handle, p []byte, done *uint32, overlapped *Overlapped) error {
	if race.Enabled {
		race.ReleaseMerge(unsafe.Pointer(&ioSync))
	}
	err := writeFile(fd, p, done, overlapped)
	if race.Enabled && *done > 0 {
		race.ReadRange(unsafe.Pointer(&p[0]), int(*done))
	}
	if msan.Enabled && *done > 0 {
		msan.Read(unsafe.Pointer(&p[0]), uintptr(*done))
	}
	if asan.Enabled && *done > 0 {
		asan.Read(unsafe.Pointer(&p[0]), uintptr(*done))
	}
	return err
}

var ioSync int64

var procSetFilePointerEx = modkernel32.NewProc("SetFilePointerEx")

const ptrSize = unsafe.Sizeof(uintptr(0))

// setFilePointerEx calls SetFilePointerEx.
// See https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfilepointerex
func setFilePointerEx(handle Handle, distToMove int64, newFilePointer *int64, whence uint32) error {
	var e1 Errno
	if unsafe.Sizeof(uintptr(0)) == 8 {
		_, _, e1 = Syscall6(procSetFilePointerEx.Addr(), 4, uintptr(handle), uintptr(distToMove), uintptr(unsafe.Pointer(newFilePointer)), uintptr(whence), 0, 0)
	} else {
		// Different 32-bit systems disgaree about whether distToMove starts 8-byte aligned.
		switch runtime.GOARCH {
		default:
			panic("unsupported 32-bit architecture")
		case "386":
			// distToMove is a LARGE_INTEGER, which is 64 bits.
			_, _, e1 = Syscall6(procSetFilePointerEx.Addr(), 5, uintptr(handle), uintptr(distToMove), uintptr(distToMove>>32), uintptr(unsafe.Pointer(newFilePointer)), uintptr(whence), 0)
		case "arm":
			// distToMove must be 8-byte aligned per ARM calling convention
			// https://docs.microsoft.com/en-us/cpp/build/overview-of-arm-abi-conventions#stage-c-assignment-of-arguments-to-registers-and-stack
			_, _, e1 = Syscall6(procSetFilePointerEx.Addr(), 6, uintptr(handle), 0, uintptr(distToMove), uintptr(distToMove>>32), uintptr(unsafe.Pointer(newFilePointer)), uintptr(whence))
		}
	}
	if e1 != 0 {
		return errnoErr(e1)
	}
	return nil
}

func Seek(fd Handle, offset int64, whence int) (newoffset int64, err error) {
	var w uint32
	switch whence {
	case 0:
		w = FILE_BEGIN
	case 1:
		w = FILE_CURRENT
	case 2:
		w = FILE_END
	}
	err = setFilePointerEx(fd, offset, &newoffset, w)
	return
}

func Close(fd Handle) (err error) {
	return CloseHandle(fd)
}

var (
	Stdin  = getStdHandle(STD_INPUT_HANDLE)
	Stdout = getStdHandle(STD_OUTPUT_HANDLE)
	Stderr = getStdHandle(STD_ERROR_HANDLE)
)

func getStdHandle(h int) (fd Handle) {
	r, _ := GetStdHandle(h)
	return r
}

const ImplementsGetwd = true

func Getwd() (wd string, err error) {
	b := make([]uint16, 300)
	// The path of the current directory may not fit in the initial 300-word
	// buffer when long path support is enabled. The current directory may also
	// change between subsequent calls of GetCurrentDirectory. As a result, we
	// need to retry the call in a loop until the current directory fits, each
	// time with a bigger buffer.
	for {
		n, e := GetCurrentDirectory(uint32(len(b)), &b[0])
		if e != nil {
			return "", e
		}
		if int(n) <= len(b) {
			return UTF16ToString(b[:n]), nil
		}
		b = make([]uint16, n)
	}
}

func Chdir(path string) (err error) {
	pathp, err := UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return SetCurrentDirectory(pathp)
}

func Mkdir(path string, mode uint32) (err error) {
	pathp, err := UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return CreateDirectory(pathp, nil)
}

func Rmdir(path string) (err error) {
	pathp, err := UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return RemoveDirectory(pathp)
}

func Unlink(path string) (err error) {
	pathp, err := UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return DeleteFile(pathp)
}

func Rename(oldpath, newpath string) (err error) {
	from, err := UTF16PtrFromString(oldpath)
	if err != nil {
		return err
	}
	to, err := UTF16PtrFromString(newpath)
	if err != nil {
		return err
	}
	return MoveFile(from, to)
}

func ComputerName() (name string, err error) {
	var n uint32 = MAX_COMPUTERNAME_LENGTH + 1
	b := make([]uint16, n)
	e := GetComputerName(&b[0], &n)
	if e != nil {
		return "", e
	}
	return UTF16ToString(b[:n]), nil
}

func Ftruncate(fd Handle, length int64) (err error) {
	type _FILE_END_OF_FILE_INFO struct {
		EndOfFile int64
	}
	const FileEndOfFileInfo = 6
	var info _FILE_END_OF_FILE_INFO
	info.EndOfFile = length
	return setFileInformationByHandle(fd, FileEndOfFileInfo, unsafe.Pointer(&info), uint32(unsafe.Sizeof(info)))
}

func Gettimeofday(tv *Timeval) (err error) {
	var ft Filetime
	GetSystemTimeAsFileTime(&ft)
	*tv = NsecToTimeval(ft.Nanoseconds())
	return nil
}

func Pipe(p []Handle) (err error) {
	if len(p) != 2 {
		return EINVAL
	}
	var r, w Handle
	e := CreatePipe(&r, &w, makeInheritSa(), 0)
	if e != nil {
		return e
	}
	p[0] = r
	p[1] = w
	return nil
}

func Utimes(path string, tv []Timeval) (err error) {
	if len(tv) != 2 {
		return EINVAL
	}
	pathp, e := UTF16PtrFromString(path)
	if e != nil {
		return e
	}
	h, e := CreateFile(pathp,
		FILE_WRITE_ATTRIBUTES, FILE_SHARE_WRITE, nil,
		OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0)
	if e != nil {
		return e
	}
	defer Close(h)
	a := Filetime{}
	w := Filetime{}
	if tv[0].Nanoseconds() != 0 {
		a = NsecToFiletime(tv[0].Nanoseconds())
	}
	if tv[0].Nanoseconds() != 0 {
		w = NsecToFiletime(tv[1].Nanoseconds())
	}
	return SetFileTime(h, nil, &a, &w)
}

// This matches the value in os/file_windows.go.
const _UTIME_OMIT = -1

func UtimesNano(path string, ts []Timespec) (err error) {
	if len(ts) != 2 {
		return EINVAL
	}
	pathp, e := UTF16PtrFromString(path)
	if e != nil {
		return e
	}
	h, e := CreateFile(pathp,
		FILE_WRITE_ATTRIBUTES, FILE_SHARE_WRITE, nil,
		OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0)
	if e != nil {
		return e
	}
	defer Close(h)
	a := Filetime{}
	w := Filetime{}
	if ts[0].Nsec != _UTIME_OMIT {
		a = NsecToFiletime(TimespecToNsec(ts[0]))
	}
	if ts[1].Nsec != _UTIME_OMIT {
		w = NsecToFiletime(TimespecToNsec(ts[1]))
	}
	return SetFileTime(h, nil, &a, &w)
}

func Fsync(fd Handle) (err error) {
	return FlushFileBuffers(fd)
}

func Chmod(path string, mode uint32) (err error) {
	p, e := UTF16PtrFromString(path)
	if e != nil {
		return e
	}
	attrs, e := GetFileAttributes(p)
	if e != nil {
		return e
	}
	if mode&S_IWRITE != 0 {
		attrs &^= FILE_ATTRIBUTE_READONLY
	} else {
		attrs |= FILE_ATTRIBUTE_READONLY
	}
	return SetFileAttributes(p, attrs)
}

func LoadCancelIoEx() error {
	return procCancelIoEx.Find()
}

func LoadSetFileCompletionNotificationModes() error {
	return procSetFileCompletionNotificationModes.Find()
}

// net api calls

const socket_error = uintptr(^uint32(0))

//sys	WSAStartup(verreq uint32, data *WSAData) (sockerr error) = ws2_32.WSAStartup
//sys	WSACleanup() (err error) [failretval==socket_error] = ws2_32.WSACleanup
//sys	WSAIoctl(s Handle, iocc uint32, inbuf *byte, cbif uint32, outbuf *byte, cbob uint32, cbbr *uint32, overlapped *Overlapped, completionRoutine uintptr) (err error) [failretval==socket_error] = ws2_32.WSAIoctl
//sys	socket(af int32, typ int32, protocol int32) (handle Handle, err error) [failretval==InvalidHandle] = ws2_32.socket
//sys	Setsockopt(s Handle, level int32, optname int32, optval *byte, optlen int32) (err error) [failretval==socket_error] = ws2_32.setsockopt
//sys	Getsockopt(s Handle, level int32, optname int32, optval *byte, optlen *int32) (err error) [failretval==socket_error] = ws2_32.getsockopt
//sys	bind(s Handle, name unsafe.Pointer, namelen int32) (err error) [failretval==socket_error] = ws2_32.bind
//sys	connect(s Handle, name unsafe.Pointer, namelen int32) (err error) [failretval==socket_error] = ws2_32.connect
//sys	getsockname(s Handle, rsa *RawSockaddrAny, addrlen *int32) (err error) [failretval==socket_error] = ws2_32.getsockname
//sys	getpeername(s Handle, rsa *RawSockaddrAny, addrlen *int32) (err error) [failretval==socket_error] = ws2_32.getpeername
//sys	listen(s Handle, backlog int32) (err error) [failretval==socket_error] = ws2_32.listen
//sys	shutdown(s Handle, how int32) (err error) [failretval==socket_error] = ws2_32.shutdown
//sys	Closesocket(s Handle) (err error) [failretval==socket_error] = ws2_32.closesocket
//sys	AcceptEx(ls Handle, as Handle, buf *byte, rxdatalen uint32, laddrlen uint32, raddrlen uint32, recvd *uint32, overlapped *Overlapped) (err error) = mswsock.AcceptEx
//sys	GetAcceptExSockaddrs(buf *byte, rxdatalen uint32, laddrlen uint32, raddrlen uint32, lrsa **RawSockaddrAny, lrsalen *int32, rrsa **RawSockaddrAny, rrsalen *int32) = mswsock.GetAcceptExSockaddrs
//sys	WSARecv(s Handle, bufs *WSABuf, bufcnt uint32, recvd *uint32, flags *uint32, overlapped *Overlapped, croutine *byte) (err error) [failretval==socket_error] = ws2_32.WSARecv
//sys	WSASend(s Handle, bufs *WSABuf, bufcnt uint32, sent *uint32, flags uint32, overlapped *Overlapped, croutine *byte) (err error) [failretval==socket_error] = ws2_32.WSASend
//sys	WSARecvFrom(s Handle, bufs *WSABuf, bufcnt uint32, recvd *uint32, flags *uint32,  from *RawSockaddrAny, fromlen *int32, overlapped *Overlapped, croutine *byte) (err error) [failretval==socket_error] = ws2_32.WSARecvFrom
//sys	WSASendTo(s Handle, bufs *WSABuf, bufcnt uint32, sent *uint32, flags uint32, to *RawSockaddrAny, tolen int32,  overlapped *Overlapped, croutine *byte) (err error) [failretval==socket_error] = ws2_32.WSASendTo
//sys	GetHostByName(name string) (h *Hostent, err error) [failretval==nil] = ws2_32.gethostbyname
//sys	GetServByName(name string, proto string) (s *Servent, err error) [failretval==nil] = ws2_32.getservbyname
//sys	Ntohs(netshort uint16) (u uint16) = ws2_32.ntohs
//sys	GetProtoByName(name string) (p *Protoent, err error) [failretval==nil] = ws2_32.getprotobyname
//sys	DnsQuery(name str
"""




```