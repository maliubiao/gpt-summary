Response:
The user wants to understand the functionality of the provided Go code snippet. This code is part of the `zsyscall_windows.go` file in the `golang.org/x/sys/windows` package, which suggests it's related to low-level system calls on Windows.

The code consists of multiple Go functions that internally use `syscall.Syscall` or `syscall.Syscall6` to invoke Windows API functions. Each Go function seems to wrap a specific Windows API call.

To answer the user's request, I need to:
1. **List the functions:** Identify each Go function in the snippet.
2. **Describe the function of each:** Based on the function names and the Windows API they call (extracted from the `proc...Addr()` calls), explain what each function does.
3. **Provide Go code examples:** For some representative functions, demonstrate how they might be used in Go code, including hypothetical inputs and expected outputs.
4. **Address command-line parameters:** Check if any functions directly process command-line arguments. This seems unlikely given the nature of these system call wrappers.
5. **Identify potential pitfalls:** Think about common mistakes developers might make when using these functions, such as incorrect buffer sizes or handling of pointers.
6. **Summarize the overall functionality:** Based on the individual function descriptions, provide a high-level summary of what this part of the file accomplishes.

Let's go through each function:

- `timeBeginPeriod`: Calls `proctimeBeginPeriod`. This likely relates to increasing the resolution of the system timer.
- `timeEndPeriod`: Calls `proctimeEndPeriod`. This likely relates to decreasing the resolution of the system timer back to the default.
- `WinVerifyTrustEx`: Calls `procWinVerifyTrustEx`. This function seems to verify the trustworthiness of a digital signature.
- `FreeAddrInfoW`: Calls `procFreeAddrInfoW`. This function likely frees memory allocated for address information, possibly related to network operations.
- `GetAddrInfoW`: Calls `procGetAddrInfoW`. This function seems to retrieve address information for a host and service name, likely used for network programming.
- `WSACleanup`: Calls `procWSACleanup`. This is a function to clean up Winsock library usage, part of network programming.
- `WSAEnumProtocols`: Calls `procWSAEnumProtocolsW`. This function enumerates available network protocols.
- `WSAGetOverlappedResult`: Calls `procWSAGetOverlappedResult`. This function retrieves the results of an overlapped I/O operation on a socket.

Now, let's prepare the Go code examples and the overall summary.
这段Go语言代码文件 `zsyscall_windows.go` 的一部分，主要功能是**通过 Go 的 `syscall` 包直接调用 Windows API 函数**。 它为 Go 语言程序提供了访问底层 Windows 系统功能的桥梁。

**具体功能归纳：**

这部分代码主要包含以下几类功能的 Windows API 封装：

1. **时间管理:**
   - `timeBeginPeriod`:  提高系统时钟的分辨率。
   - `timeEndPeriod`:  降低系统时钟的分辨率。

2. **数字签名验证:**
   - `WinVerifyTrustEx`:  验证指定数据的可信度，通常用于验证数字签名。

3. **网络地址信息:**
   - `FreeAddrInfoW`:  释放由 `GetAddrInfoW` 函数分配的地址信息结构体内存。
   - `GetAddrInfoW`:  获取指定主机名和/或服务名的地址信息。

4. **Winsock (Windows Sockets) 网络编程:**
   - `WSACleanup`:  清理 Winsock 库的使用，释放相关资源。
   - `WSAEnumProtocols`:  枚举系统中可用的传输协议。
   - `WSAGetOverlappedResult`:  获取重叠 I/O 操作的结果。

**Go 语言功能实现示例：**

以下是一些基于这段代码功能的 Go 代码示例：

**示例 1: 调整系统时钟分辨率**

```go
package main

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func main() {
	// 假设要将系统时钟分辨率提高到 1 毫秒
	period := uint32(1)

	// 调用 timeBeginPeriod
	err := _timeBeginPeriod(period)
	if err != nil {
		fmt.Printf("Error calling timeBeginPeriod: %v\n", err)
		return
	}
	fmt.Println("System timer resolution increased.")

	// 模拟一些需要高精度定时的操作
	time.Sleep(5 * time.Millisecond)
	fmt.Println("Waited for 5 milliseconds.")

	// 恢复系统时钟分辨率
	err = _timeEndPeriod(period)
	if err != nil {
		fmt.Printf("Error calling timeEndPeriod: %v\n", err)
		return
	}
	fmt.Println("System timer resolution restored.")
}

// 内部调用的封装，假设已经在 zsyscall_windows.go 中定义
func _timeBeginPeriod(period uint32) (err error) {
	r1, _, e1 := syscall.Syscall(proctimeBeginPeriod.Addr(), 1, uintptr(period), 0, 0)
	if r1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func _timeEndPeriod(period uint32) (err error) {
	r1, _, e1 := syscall.Syscall(proctimeEndPeriod.Addr(), 1, uintptr(period), 0, 0)
	if r1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// 假设的输入与输出：
// 运行程序后，控制台输出类似于：
// System timer resolution increased.
// Waited for 5 milliseconds.
// System timer resolution restored.
```

**示例 2: 获取主机地址信息**

```go
package main

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func main() {
	// 假设要查询 "www.google.com" 的地址信息
	hostnamePtr, err := syscall.UTF16PtrFromString("www.google.com")
	if err != nil {
		fmt.Printf("Error creating hostname pointer: %v\n", err)
		return
	}
	var hints windows.AddrinfoW
	var resultPtr *windows.AddrinfoW

	// 调用 GetAddrInfoW
	err = _GetAddrInfoW(hostnamePtr, nil, &hints, &resultPtr)
	if err != nil {
		fmt.Printf("Error calling GetAddrInfoW: %v\n", err)
		return
	}
	defer _FreeAddrInfoW(resultPtr)

	// 遍历并打印地址信息
	for p := resultPtr; p != nil; p = p.Next {
		addr, err := net.ParseIP(p.Addr.String())
		if err == nil {
			fmt.Printf("Found address: %v\n", addr)
		}
	}
}

// 内部调用的封装，假设已经在 zsyscall_windows.go 中定义
func _GetAddrInfoW(nodename *uint16, servicename *uint16, hints *windows.AddrinfoW, result **windows.AddrinfoW) (sockerr error) {
	r0, _, _ := syscall.Syscall6(procGetAddrInfoW.Addr(), 4, uintptr(unsafe.Pointer(nodename)), uintptr(unsafe.Pointer(servicename)), uintptr(unsafe.Pointer(hints)), uintptr(unsafe.Pointer(result)), 0, 0)
	if r0 != 0 {
		sockerr = syscall.Errno(r0)
	}
	return
}

func _FreeAddrInfoW(addrinfo *windows.AddrinfoW) {
	syscall.Syscall(procFreeAddrInfoW.Addr(), 1, uintptr(unsafe.Pointer(addrinfo)), 0, 0)
	return
}

// 假设的输入与输出：
// 运行程序后，控制台输出类似于：
// Found address: <Google 的 IP 地址>
// (可能会有多个 IP 地址)
```

**命令行参数处理：**

这段代码本身并不直接处理命令行参数。它封装的是底层的 Windows API 函数，这些函数的行为通常由传递给它们的参数控制，而不是直接解析命令行。更上层的 Go 代码可能会使用这些函数来实现需要处理命令行参数的功能。

**使用者易犯错的点：**

* **结构体和指针的使用:** 这些函数经常涉及到 Windows 定义的结构体（例如 `AddrinfoW`, `WinTrustData`）和指向这些结构体的指针。 错误地分配或使用这些结构体和指针会导致程序崩溃或行为异常。
* **错误处理:**  Windows API 调用通常通过返回值指示成功或失败，并可能通过 `GetLastError` 提供更详细的错误信息。  这段代码通常会将 Windows 的错误码转换为 Go 的 `error` 类型，但开发者需要正确地检查和处理这些错误。
* **内存管理:**  某些函数（如 `GetAddrInfoW`) 会分配内存，需要使用相应的释放函数 (`FreeAddrInfoW`) 来避免内存泄漏。
* **字符串编码:** Windows API 通常使用 UTF-16 编码的字符串。 在 Go 中与这些 API 交互时，需要使用 `syscall.UTF16PtrFromString` 等函数进行编码转换。

**功能归纳：**

总而言之，这部分 `zsyscall_windows.go` 代码的功能是为 Go 语言程序提供了与 Windows 系统进行更底层交互的能力，具体包括：

* **精确的时间控制** (通过调整系统时钟分辨率)。
* **验证软件和数据的可信度** (通过数字签名验证)。
* **执行网络编程任务** (获取网络地址信息和使用 Winsock 功能)。

它属于 Go 语言中 `syscall` 包在 Windows 平台上的具体实现，使得 Go 程序能够利用 Windows 操作系统提供的丰富功能。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/windows/zsyscall_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```go
fe.Pointer(time)), 0, 0)
	return
}

func getSystemWindowsDirectory(dir *uint16, dirLen uint32) (len uint32, err error) {
	r0, _, e1 := syscall.Syscall(procGetSystemWindowsDirectoryW.Addr(), 2, uintptr(unsafe.Pointer(dir)), uintptr(dirLen), 0)
	len = uint32(r0)
	if len == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetTempPath(buflen uint32, buf *uint16) (n uint32, err error) {
	r0, _, e1 := syscall.Syscall(procGetTempPathW.Addr(), 2, uintptr(buflen), uintptr(unsafe.Pointer(buf)), 0)
	n = uint32(r0)
	if n == 0 {
		err = errnoErr(e1)
	}
	return
}

func getThreadPreferredUILanguages(flags uint32, numLanguages *uint32, buf *uint16, bufSize *uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procGetThreadPreferredUILanguages.Addr(), 4, uintptr(flags), uintptr(unsafe.Pointer(numLanguages)), uintptr(unsafe.Pointer(buf)), uintptr(unsafe.Pointer(bufSize)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func getTickCount64() (ms uint64) {
	r0, _, _ := syscall.Syscall(procGetTickCount64.Addr(), 0, 0, 0, 0)
	ms = uint64(r0)
	return
}

func GetTimeZoneInformation(tzi *Timezoneinformation) (rc uint32, err error) {
	r0, _, e1 := syscall.Syscall(procGetTimeZoneInformation.Addr(), 1, uintptr(unsafe.Pointer(tzi)), 0, 0)
	rc = uint32(r0)
	if rc == 0xffffffff {
		err = errnoErr(e1)
	}
	return
}

func getUserPreferredUILanguages(flags uint32, numLanguages *uint32, buf *uint16, bufSize *uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procGetUserPreferredUILanguages.Addr(), 4, uintptr(flags), uintptr(unsafe.Pointer(numLanguages)), uintptr(unsafe.Pointer(buf)), uintptr(unsafe.Pointer(bufSize)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetVersion() (ver uint32, err error) {
	r0, _, e1 := syscall.Syscall(procGetVersion.Addr(), 0, 0, 0, 0)
	ver = uint32(r0)
	if ver == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetVolumeInformationByHandle(file Handle, volumeNameBuffer *uint16, volumeNameSize uint32, volumeNameSerialNumber *uint32, maximumComponentLength *uint32, fileSystemFlags *uint32, fileSystemNameBuffer *uint16, fileSystemNameSize uint32) (err error) {
	r1, _, e1 := syscall.Syscall9(procGetVolumeInformationByHandleW.Addr(), 8, uintptr(file), uintptr(unsafe.Pointer(volumeNameBuffer)), uintptr(volumeNameSize), uintptr(unsafe.Pointer(volumeNameSerialNumber)), uintptr(unsafe.Pointer(maximumComponentLength)), uintptr(unsafe.Pointer(fileSystemFlags)), uintptr(unsafe.Pointer(fileSystemNameBuffer)), uintptr(fileSystemNameSize), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetVolumeInformation(rootPathName *uint16, volumeNameBuffer *uint16, volumeNameSize uint32, volumeNameSerialNumber *uint32, maximumComponentLength *uint32, fileSystemFlags *uint32, fileSystemNameBuffer *uint16, fileSystemNameSize uint32) (err error) {
	r1, _, e1 := syscall.Syscall9(procGetVolumeInformationW.Addr(), 8, uintptr(unsafe.Pointer(rootPathName)), uintptr(unsafe.Pointer(volumeNameBuffer)), uintptr(volumeNameSize), uintptr(unsafe.Pointer(volumeNameSerialNumber)), uintptr(unsafe.Pointer(maximumComponentLength)), uintptr(unsafe.Pointer(fileSystemFlags)), uintptr(unsafe.Pointer(fileSystemNameBuffer)), uintptr(fileSystemNameSize), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetVolumeNameForVolumeMountPoint(volumeMountPoint *uint16, volumeName *uint16, bufferlength uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procGetVolumeNameForVolumeMountPointW.Addr(), 3, uintptr(unsafe.Pointer(volumeMountPoint)), uintptr(unsafe.Pointer(volumeName)), uintptr(bufferlength))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetVolumePathName(fileName *uint16, volumePathName *uint16, bufferLength uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procGetVolumePathNameW.Addr(), 3, uintptr(unsafe.Pointer(fileName)), uintptr(unsafe.Pointer(volumePathName)), uintptr(bufferLength))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetVolumePathNamesForVolumeName(volumeName *uint16, volumePathNames *uint16, bufferLength uint32, returnLength *uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procGetVolumePathNamesForVolumeNameW.Addr(), 4, uintptr(unsafe.Pointer(volumeName)), uintptr(unsafe.Pointer(volumePathNames)), uintptr(bufferLength), uintptr(unsafe.Pointer(returnLength)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func getWindowsDirectory(dir *uint16, dirLen uint32) (len uint32, err error) {
	r0, _, e1 := syscall.Syscall(procGetWindowsDirectoryW.Addr(), 2, uintptr(unsafe.Pointer(dir)), uintptr(dirLen), 0)
	len = uint32(r0)
	if len == 0 {
		err = errnoErr(e1)
	}
	return
}

func initializeProcThreadAttributeList(attrlist *ProcThreadAttributeList, attrcount uint32, flags uint32, size *uintptr) (err error) {
	r1, _, e1 := syscall.Syscall6(procInitializeProcThreadAttributeList.Addr(), 4, uintptr(unsafe.Pointer(attrlist)), uintptr(attrcount), uintptr(flags), uintptr(unsafe.Pointer(size)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func IsWow64Process(handle Handle, isWow64 *bool) (err error) {
	var _p0 uint32
	if *isWow64 {
		_p0 = 1
	}
	r1, _, e1 := syscall.Syscall(procIsWow64Process.Addr(), 2, uintptr(handle), uintptr(unsafe.Pointer(&_p0)), 0)
	*isWow64 = _p0 != 0
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func IsWow64Process2(handle Handle, processMachine *uint16, nativeMachine *uint16) (err error) {
	err = procIsWow64Process2.Find()
	if err != nil {
		return
	}
	r1, _, e1 := syscall.Syscall(procIsWow64Process2.Addr(), 3, uintptr(handle), uintptr(unsafe.Pointer(processMachine)), uintptr(unsafe.Pointer(nativeMachine)))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func LoadLibraryEx(libname string, zero Handle, flags uintptr) (handle Handle, err error) {
	var _p0 *uint16
	_p0, err = syscall.UTF16PtrFromString(libname)
	if err != nil {
		return
	}
	return _LoadLibraryEx(_p0, zero, flags)
}

func _LoadLibraryEx(libname *uint16, zero Handle, flags uintptr) (handle Handle, err error) {
	r0, _, e1 := syscall.Syscall(procLoadLibraryExW.Addr(), 3, uintptr(unsafe.Pointer(libname)), uintptr(zero), uintptr(flags))
	handle = Handle(r0)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return
}

func LoadLibrary(libname string) (handle Handle, err error) {
	var _p0 *uint16
	_p0, err = syscall.UTF16PtrFromString(libname)
	if err != nil {
		return
	}
	return _LoadLibrary(_p0)
}

func _LoadLibrary(libname *uint16) (handle Handle, err error) {
	r0, _, e1 := syscall.Syscall(procLoadLibraryW.Addr(), 1, uintptr(unsafe.Pointer(libname)), 0, 0)
	handle = Handle(r0)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return
}

func LoadResource(module Handle, resInfo Handle) (resData Handle, err error) {
	r0, _, e1 := syscall.Syscall(procLoadResource.Addr(), 2, uintptr(module), uintptr(resInfo), 0)
	resData = Handle(r0)
	if resData == 0 {
		err = errnoErr(e1)
	}
	return
}

func LocalAlloc(flags uint32, length uint32) (ptr uintptr, err error) {
	r0, _, e1 := syscall.Syscall(procLocalAlloc.Addr(), 2, uintptr(flags), uintptr(length), 0)
	ptr = uintptr(r0)
	if ptr == 0 {
		err = errnoErr(e1)
	}
	return
}

func LocalFree(hmem Handle) (handle Handle, err error) {
	r0, _, e1 := syscall.Syscall(procLocalFree.Addr(), 1, uintptr(hmem), 0, 0)
	handle = Handle(r0)
	if handle != 0 {
		err = errnoErr(e1)
	}
	return
}

func LockFileEx(file Handle, flags uint32, reserved uint32, bytesLow uint32, bytesHigh uint32, overlapped *Overlapped) (err error) {
	r1, _, e1 := syscall.Syscall6(procLockFileEx.Addr(), 6, uintptr(file), uintptr(flags), uintptr(reserved), uintptr(bytesLow), uintptr(bytesHigh), uintptr(unsafe.Pointer(overlapped)))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func LockResource(resData Handle) (addr uintptr, err error) {
	r0, _, e1 := syscall.Syscall(procLockResource.Addr(), 1, uintptr(resData), 0, 0)
	addr = uintptr(r0)
	if addr == 0 {
		err = errnoErr(e1)
	}
	return
}

func MapViewOfFile(handle Handle, access uint32, offsetHigh uint32, offsetLow uint32, length uintptr) (addr uintptr, err error) {
	r0, _, e1 := syscall.Syscall6(procMapViewOfFile.Addr(), 5, uintptr(handle), uintptr(access), uintptr(offsetHigh), uintptr(offsetLow), uintptr(length), 0)
	addr = uintptr(r0)
	if addr == 0 {
		err = errnoErr(e1)
	}
	return
}

func Module32First(snapshot Handle, moduleEntry *ModuleEntry32) (err error) {
	r1, _, e1 := syscall.Syscall(procModule32FirstW.Addr(), 2, uintptr(snapshot), uintptr(unsafe.Pointer(moduleEntry)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func Module32Next(snapshot Handle, moduleEntry *ModuleEntry32) (err error) {
	r1, _, e1 := syscall.Syscall(procModule32NextW.Addr(), 2, uintptr(snapshot), uintptr(unsafe.Pointer(moduleEntry)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func MoveFileEx(from *uint16, to *uint16, flags uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procMoveFileExW.Addr(), 3, uintptr(unsafe.Pointer(from)), uintptr(unsafe.Pointer(to)), uintptr(flags))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func MoveFile(from *uint16, to *uint16) (err error) {
	r1, _, e1 := syscall.Syscall(procMoveFileW.Addr(), 2, uintptr(unsafe.Pointer(from)), uintptr(unsafe.Pointer(to)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func MultiByteToWideChar(codePage uint32, dwFlags uint32, str *byte, nstr int32, wchar *uint16, nwchar int32) (nwrite int32, err error) {
	r0, _, e1 := syscall.Syscall6(procMultiByteToWideChar.Addr(), 6, uintptr(codePage), uintptr(dwFlags), uintptr(unsafe.Pointer(str)), uintptr(nstr), uintptr(unsafe.Pointer(wchar)), uintptr(nwchar))
	nwrite = int32(r0)
	if nwrite == 0 {
		err = errnoErr(e1)
	}
	return
}

func OpenEvent(desiredAccess uint32, inheritHandle bool, name *uint16) (handle Handle, err error) {
	var _p0 uint32
	if inheritHandle {
		_p0 = 1
	}
	r0, _, e1 := syscall.Syscall(procOpenEventW.Addr(), 3, uintptr(desiredAccess), uintptr(_p0), uintptr(unsafe.Pointer(name)))
	handle = Handle(r0)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return
}

func OpenMutex(desiredAccess uint32, inheritHandle bool, name *uint16) (handle Handle, err error) {
	var _p0 uint32
	if inheritHandle {
		_p0 = 1
	}
	r0, _, e1 := syscall.Syscall(procOpenMutexW.Addr(), 3, uintptr(desiredAccess), uintptr(_p0), uintptr(unsafe.Pointer(name)))
	handle = Handle(r0)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return
}

func OpenProcess(desiredAccess uint32, inheritHandle bool, processId uint32) (handle Handle, err error) {
	var _p0 uint32
	if inheritHandle {
		_p0 = 1
	}
	r0, _, e1 := syscall.Syscall(procOpenProcess.Addr(), 3, uintptr(desiredAccess), uintptr(_p0), uintptr(processId))
	handle = Handle(r0)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return
}

func OpenThread(desiredAccess uint32, inheritHandle bool, threadId uint32) (handle Handle, err error) {
	var _p0 uint32
	if inheritHandle {
		_p0 = 1
	}
	r0, _, e1 := syscall.Syscall(procOpenThread.Addr(), 3, uintptr(desiredAccess), uintptr(_p0), uintptr(threadId))
	handle = Handle(r0)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return
}

func PostQueuedCompletionStatus(cphandle Handle, qty uint32, key uintptr, overlapped *Overlapped) (err error) {
	r1, _, e1 := syscall.Syscall6(procPostQueuedCompletionStatus.Addr(), 4, uintptr(cphandle), uintptr(qty), uintptr(key), uintptr(unsafe.Pointer(overlapped)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func Process32First(snapshot Handle, procEntry *ProcessEntry32) (err error) {
	r1, _, e1 := syscall.Syscall(procProcess32FirstW.Addr(), 2, uintptr(snapshot), uintptr(unsafe.Pointer(procEntry)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func Process32Next(snapshot Handle, procEntry *ProcessEntry32) (err error) {
	r1, _, e1 := syscall.Syscall(procProcess32NextW.Addr(), 2, uintptr(snapshot), uintptr(unsafe.Pointer(procEntry)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func ProcessIdToSessionId(pid uint32, sessionid *uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procProcessIdToSessionId.Addr(), 2, uintptr(pid), uintptr(unsafe.Pointer(sessionid)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func PulseEvent(event Handle) (err error) {
	r1, _, e1 := syscall.Syscall(procPulseEvent.Addr(), 1, uintptr(event), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func PurgeComm(handle Handle, dwFlags uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procPurgeComm.Addr(), 2, uintptr(handle), uintptr(dwFlags), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func QueryDosDevice(deviceName *uint16, targetPath *uint16, max uint32) (n uint32, err error) {
	r0, _, e1 := syscall.Syscall(procQueryDosDeviceW.Addr(), 3, uintptr(unsafe.Pointer(deviceName)), uintptr(unsafe.Pointer(targetPath)), uintptr(max))
	n = uint32(r0)
	if n == 0 {
		err = errnoErr(e1)
	}
	return
}

func QueryFullProcessImageName(proc Handle, flags uint32, exeName *uint16, size *uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procQueryFullProcessImageNameW.Addr(), 4, uintptr(proc), uintptr(flags), uintptr(unsafe.Pointer(exeName)), uintptr(unsafe.Pointer(size)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func QueryInformationJobObject(job Handle, JobObjectInformationClass int32, JobObjectInformation uintptr, JobObjectInformationLength uint32, retlen *uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procQueryInformationJobObject.Addr(), 5, uintptr(job), uintptr(JobObjectInformationClass), uintptr(JobObjectInformation), uintptr(JobObjectInformationLength), uintptr(unsafe.Pointer(retlen)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func ReadConsole(console Handle, buf *uint16, toread uint32, read *uint32, inputControl *byte) (err error) {
	r1, _, e1 := syscall.Syscall6(procReadConsoleW.Addr(), 5, uintptr(console), uintptr(unsafe.Pointer(buf)), uintptr(toread), uintptr(unsafe.Pointer(read)), uintptr(unsafe.Pointer(inputControl)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func ReadDirectoryChanges(handle Handle, buf *byte, buflen uint32, watchSubTree bool, mask uint32, retlen *uint32, overlapped *Overlapped, completionRoutine uintptr) (err error) {
	var _p0 uint32
	if watchSubTree {
		_p0 = 1
	}
	r1, _, e1 := syscall.Syscall9(procReadDirectoryChangesW.Addr(), 8, uintptr(handle), uintptr(unsafe.Pointer(buf)), uintptr(buflen), uintptr(_p0), uintptr(mask), uintptr(unsafe.Pointer(retlen)), uintptr(unsafe.Pointer(overlapped)), uintptr(completionRoutine), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func readFile(handle Handle, buf []byte, done *uint32, overlapped *Overlapped) (err error) {
	var _p0 *byte
	if len(buf) > 0 {
		_p0 = &buf[0]
	}
	r1, _, e1 := syscall.Syscall6(procReadFile.Addr(), 5, uintptr(handle), uintptr(unsafe.Pointer(_p0)), uintptr(len(buf)), uintptr(unsafe.Pointer(done)), uintptr(unsafe.Pointer(overlapped)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func ReadProcessMemory(process Handle, baseAddress uintptr, buffer *byte, size uintptr, numberOfBytesRead *uintptr) (err error) {
	r1, _, e1 := syscall.Syscall6(procReadProcessMemory.Addr(), 5, uintptr(process), uintptr(baseAddress), uintptr(unsafe.Pointer(buffer)), uintptr(size), uintptr(unsafe.Pointer(numberOfBytesRead)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func ReleaseMutex(mutex Handle) (err error) {
	r1, _, e1 := syscall.Syscall(procReleaseMutex.Addr(), 1, uintptr(mutex), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func RemoveDirectory(path *uint16) (err error) {
	r1, _, e1 := syscall.Syscall(procRemoveDirectoryW.Addr(), 1, uintptr(unsafe.Pointer(path)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func RemoveDllDirectory(cookie uintptr) (err error) {
	r1, _, e1 := syscall.Syscall(procRemoveDllDirectory.Addr(), 1, uintptr(cookie), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func ResetEvent(event Handle) (err error) {
	r1, _, e1 := syscall.Syscall(procResetEvent.Addr(), 1, uintptr(event), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func resizePseudoConsole(pconsole Handle, size uint32) (hr error) {
	r0, _, _ := syscall.Syscall(procResizePseudoConsole.Addr(), 2, uintptr(pconsole), uintptr(size), 0)
	if r0 != 0 {
		hr = syscall.Errno(r0)
	}
	return
}

func ResumeThread(thread Handle) (ret uint32, err error) {
	r0, _, e1 := syscall.Syscall(procResumeThread.Addr(), 1, uintptr(thread), 0, 0)
	ret = uint32(r0)
	if ret == 0xffffffff {
		err = errnoErr(e1)
	}
	return
}

func SetCommBreak(handle Handle) (err error) {
	r1, _, e1 := syscall.Syscall(procSetCommBreak.Addr(), 1, uintptr(handle), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetCommMask(handle Handle, dwEvtMask uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procSetCommMask.Addr(), 2, uintptr(handle), uintptr(dwEvtMask), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetCommState(handle Handle, lpDCB *DCB) (err error) {
	r1, _, e1 := syscall.Syscall(procSetCommState.Addr(), 2, uintptr(handle), uintptr(unsafe.Pointer(lpDCB)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetCommTimeouts(handle Handle, timeouts *CommTimeouts) (err error) {
	r1, _, e1 := syscall.Syscall(procSetCommTimeouts.Addr(), 2, uintptr(handle), uintptr(unsafe.Pointer(timeouts)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetConsoleCP(cp uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procSetConsoleCP.Addr(), 1, uintptr(cp), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func setConsoleCursorPosition(console Handle, position uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procSetConsoleCursorPosition.Addr(), 2, uintptr(console), uintptr(position), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetConsoleMode(console Handle, mode uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procSetConsoleMode.Addr(), 2, uintptr(console), uintptr(mode), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetConsoleOutputCP(cp uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procSetConsoleOutputCP.Addr(), 1, uintptr(cp), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetCurrentDirectory(path *uint16) (err error) {
	r1, _, e1 := syscall.Syscall(procSetCurrentDirectoryW.Addr(), 1, uintptr(unsafe.Pointer(path)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetDefaultDllDirectories(directoryFlags uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procSetDefaultDllDirectories.Addr(), 1, uintptr(directoryFlags), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetDllDirectory(path string) (err error) {
	var _p0 *uint16
	_p0, err = syscall.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	return _SetDllDirectory(_p0)
}

func _SetDllDirectory(path *uint16) (err error) {
	r1, _, e1 := syscall.Syscall(procSetDllDirectoryW.Addr(), 1, uintptr(unsafe.Pointer(path)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetEndOfFile(handle Handle) (err error) {
	r1, _, e1 := syscall.Syscall(procSetEndOfFile.Addr(), 1, uintptr(handle), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetEnvironmentVariable(name *uint16, value *uint16) (err error) {
	r1, _, e1 := syscall.Syscall(procSetEnvironmentVariableW.Addr(), 2, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(value)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetErrorMode(mode uint32) (ret uint32) {
	r0, _, _ := syscall.Syscall(procSetErrorMode.Addr(), 1, uintptr(mode), 0, 0)
	ret = uint32(r0)
	return
}

func SetEvent(event Handle) (err error) {
	r1, _, e1 := syscall.Syscall(procSetEvent.Addr(), 1, uintptr(event), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetFileAttributes(name *uint16, attrs uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procSetFileAttributesW.Addr(), 2, uintptr(unsafe.Pointer(name)), uintptr(attrs), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetFileCompletionNotificationModes(handle Handle, flags uint8) (err error) {
	r1, _, e1 := syscall.Syscall(procSetFileCompletionNotificationModes.Addr(), 2, uintptr(handle), uintptr(flags), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetFileInformationByHandle(handle Handle, class uint32, inBuffer *byte, inBufferLen uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procSetFileInformationByHandle.Addr(), 4, uintptr(handle), uintptr(class), uintptr(unsafe.Pointer(inBuffer)), uintptr(inBufferLen), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetFilePointer(handle Handle, lowoffset int32, highoffsetptr *int32, whence uint32) (newlowoffset uint32, err error) {
	r0, _, e1 := syscall.Syscall6(procSetFilePointer.Addr(), 4, uintptr(handle), uintptr(lowoffset), uintptr(unsafe.Pointer(highoffsetptr)), uintptr(whence), 0, 0)
	newlowoffset = uint32(r0)
	if newlowoffset == 0xffffffff {
		err = errnoErr(e1)
	}
	return
}

func SetFileTime(handle Handle, ctime *Filetime, atime *Filetime, wtime *Filetime) (err error) {
	r1, _, e1 := syscall.Syscall6(procSetFileTime.Addr(), 4, uintptr(handle), uintptr(unsafe.Pointer(ctime)), uintptr(unsafe.Pointer(atime)), uintptr(unsafe.Pointer(wtime)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetFileValidData(handle Handle, validDataLength int64) (err error) {
	r1, _, e1 := syscall.Syscall(procSetFileValidData.Addr(), 2, uintptr(handle), uintptr(validDataLength), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetHandleInformation(handle Handle, mask uint32, flags uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procSetHandleInformation.Addr(), 3, uintptr(handle), uintptr(mask), uintptr(flags))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetInformationJobObject(job Handle, JobObjectInformationClass uint32, JobObjectInformation uintptr, JobObjectInformationLength uint32) (ret int, err error) {
	r0, _, e1 := syscall.Syscall6(procSetInformationJobObject.Addr(), 4, uintptr(job), uintptr(JobObjectInformationClass), uintptr(JobObjectInformation), uintptr(JobObjectInformationLength), 0, 0)
	ret = int(r0)
	if ret == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetNamedPipeHandleState(pipe Handle, state *uint32, maxCollectionCount *uint32, collectDataTimeout *uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procSetNamedPipeHandleState.Addr(), 4, uintptr(pipe), uintptr(unsafe.Pointer(state)), uintptr(unsafe.Pointer(maxCollectionCount)), uintptr(unsafe.Pointer(collectDataTimeout)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetPriorityClass(process Handle, priorityClass uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procSetPriorityClass.Addr(), 2, uintptr(process), uintptr(priorityClass), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetProcessPriorityBoost(process Handle, disable bool) (err error) {
	var _p0 uint32
	if disable {
		_p0 = 1
	}
	r1, _, e1 := syscall.Syscall(procSetProcessPriorityBoost.Addr(), 2, uintptr(process), uintptr(_p0), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetProcessShutdownParameters(level uint32, flags uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procSetProcessShutdownParameters.Addr(), 2, uintptr(level), uintptr(flags), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetProcessWorkingSetSizeEx(hProcess Handle, dwMinimumWorkingSetSize uintptr, dwMaximumWorkingSetSize uintptr, flags uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procSetProcessWorkingSetSizeEx.Addr(), 4, uintptr(hProcess), uintptr(dwMinimumWorkingSetSize), uintptr(dwMaximumWorkingSetSize), uintptr(flags), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetStdHandle(stdhandle uint32, handle Handle) (err error) {
	r1, _, e1 := syscall.Syscall(procSetStdHandle.Addr(), 2, uintptr(stdhandle), uintptr(handle), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetVolumeLabel(rootPathName *uint16, volumeName *uint16) (err error) {
	r1, _, e1 := syscall.Syscall(procSetVolumeLabelW.Addr(), 2, uintptr(unsafe.Pointer(rootPathName)), uintptr(unsafe.Pointer(volumeName)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetVolumeMountPoint(volumeMountPoint *uint16, volumeName *uint16) (err error) {
	r1, _, e1 := syscall.Syscall(procSetVolumeMountPointW.Addr(), 2, uintptr(unsafe.Pointer(volumeMountPoint)), uintptr(unsafe.Pointer(volumeName)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetupComm(handle Handle, dwInQueue uint32, dwOutQueue uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procSetupComm.Addr(), 3, uintptr(handle), uintptr(dwInQueue), uintptr(dwOutQueue))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SizeofResource(module Handle, resInfo Handle) (size uint32, err error) {
	r0, _, e1 := syscall.Syscall(procSizeofResource.Addr(), 2, uintptr(module), uintptr(resInfo), 0)
	size = uint32(r0)
	if size == 0 {
		err = errnoErr(e1)
	}
	return
}

func SleepEx(milliseconds uint32, alertable bool) (ret uint32) {
	var _p0 uint32
	if alertable {
		_p0 = 1
	}
	r0, _, _ := syscall.Syscall(procSleepEx.Addr(), 2, uintptr(milliseconds), uintptr(_p0), 0)
	ret = uint32(r0)
	return
}

func TerminateJobObject(job Handle, exitCode uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procTerminateJobObject.Addr(), 2, uintptr(job), uintptr(exitCode), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func TerminateProcess(handle Handle, exitcode uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procTerminateProcess.Addr(), 2, uintptr(handle), uintptr(exitcode), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func Thread32First(snapshot Handle, threadEntry *ThreadEntry32) (err error) {
	r1, _, e1 := syscall.Syscall(procThread32First.Addr(), 2, uintptr(snapshot), uintptr(unsafe.Pointer(threadEntry)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func Thread32Next(snapshot Handle, threadEntry *ThreadEntry32) (err error) {
	r1, _, e1 := syscall.Syscall(procThread32Next.Addr(), 2, uintptr(snapshot), uintptr(unsafe.Pointer(threadEntry)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func UnlockFileEx(file Handle, reserved uint32, bytesLow uint32, bytesHigh uint32, overlapped *Overlapped) (err error) {
	r1, _, e1 := syscall.Syscall6(procUnlockFileEx.Addr(), 5, uintptr(file), uintptr(reserved), uintptr(bytesLow), uintptr(bytesHigh), uintptr(unsafe.Pointer(overlapped)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func UnmapViewOfFile(addr uintptr) (err error) {
	r1, _, e1 := syscall.Syscall(procUnmapViewOfFile.Addr(), 1, uintptr(addr), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func updateProcThreadAttribute(attrlist *ProcThreadAttributeList, flags uint32, attr uintptr, value unsafe.Pointer, size uintptr, prevvalue unsafe.Pointer, returnedsize *uintptr) (err error) {
	r1, _, e1 := syscall.Syscall9(procUpdateProcThreadAttribute.Addr(), 7, uintptr(unsafe.Pointer(attrlist)), uintptr(flags), uintptr(attr), uintptr(value), uintptr(size), uintptr(prevvalue), uintptr(unsafe.Pointer(returnedsize)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func VirtualAlloc(address uintptr, size uintptr, alloctype uint32, protect uint32) (value uintptr, err error) {
	r0, _, e1 := syscall.Syscall6(procVirtualAlloc.Addr(), 4, uintptr(address), uintptr(size), uintptr(alloctype), uintptr(protect), 0, 0)
	value = uintptr(r0)
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

func VirtualFree(address uintptr, size uintptr, freetype uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procVirtualFree.Addr(), 3, uintptr(address), uintptr(size), uintptr(freetype))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func VirtualLock(addr uintptr, length uintptr) (err error) {
	r1, _, e1 := syscall.Syscall(procVirtualLock.Addr(), 2, uintptr(addr), uintptr(length), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func VirtualProtect(address uintptr, size uintptr, newprotect uint32, oldprotect *uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procVirtualProtect.Addr(), 4, uintptr(address), uintptr(size), uintptr(newprotect), uintptr(unsafe.Pointer(oldprotect)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func VirtualProtectEx(process Handle, address uintptr, size uintptr, newProtect uint32, oldProtect *uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procVirtualProtectEx.Addr(), 5, uintptr(process), uintptr(address), uintptr(size), uintptr(newProtect), uintptr(unsafe.Pointer(oldProtect)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func VirtualQuery(address uintptr, buffer *MemoryBasicInformation, length uintptr) (err error) {
	r1, _, e1 := syscall.Syscall(procVirtualQuery.Addr(), 3, uintptr(address), uintptr(unsafe.Pointer(buffer)), uintptr(length))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func VirtualQueryEx(process Handle, address uintptr, buffer *MemoryBasicInformation, length uintptr) (err error) {
	r1, _, e1 := syscall.Syscall6(procVirtualQueryEx.Addr(), 4, uintptr(process), uintptr(address), uintptr(unsafe.Pointer(buffer)), uintptr(length), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func VirtualUnlock(addr uintptr, length uintptr) (err error) {
	r1, _, e1 := syscall.Syscall(procVirtualUnlock.Addr(), 2, uintptr(addr), uintptr(length), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func WTSGetActiveConsoleSessionId() (sessionID uint32) {
	r0, _, _ := syscall.Syscall(procWTSGetActiveConsoleSessionId.Addr(), 0, 0, 0, 0)
	sessionID = uint32(r0)
	return
}

func WaitCommEvent(handle Handle, lpEvtMask *uint32, lpOverlapped *Overlapped) (err error) {
	r1, _, e1 := syscall.Syscall(procWaitCommEvent.Addr(), 3, uintptr(handle), uintptr(unsafe.Pointer(lpEvtMask)), uintptr(unsafe.Pointer(lpOverlapped)))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func waitForMultipleObjects(count uint32, handles uintptr, waitAll bool, waitMilliseconds uint32) (event uint32, err error) {
	var _p0 uint32
	if waitAll {
		_p0 = 1
	}
	r0, _, e1 := syscall.Syscall6(procWaitForMultipleObjects.Addr(), 4, uintptr(count), uintptr(handles), uintptr(_p0), uintptr(waitMilliseconds), 0, 0)
	event = uint32(r0)
	if event == 0xffffffff {
		err = errnoErr(e1)
	}
	return
}

func WaitForSingleObject(handle Handle, waitMilliseconds uint32) (event uint32, err error) {
	r0, _, e1 := syscall.Syscall(procWaitForSingleObject.Addr(), 2, uintptr(handle), uintptr(waitMilliseconds), 0)
	event = uint32(r0)
	if event == 0xffffffff {
		err = errnoErr(e1)
	}
	return
}

func WriteConsole(console Handle, buf *uint16, towrite uint32, written *uint32, reserved *byte) (err error) {
	r1, _, e1 := syscall.Syscall6(procWriteConsoleW.Addr(), 5, uintptr(console), uintptr(unsafe.Pointer(buf)), uintptr(towrite), uintptr(unsafe.Pointer(written)), uintptr(unsafe.Pointer(reserved)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func writeFile(handle Handle, buf []byte, done *uint32, overlapped *Overlapped) (err error) {
	var _p0 *byte
	if len(buf) > 0 {
		_p0 = &buf[0]
	}
	r1, _, e1 := syscall.Syscall6(procWriteFile.Addr(), 5, uintptr(handle), uintptr(unsafe.Pointer(_p0)), uintptr(len(buf)), uintptr(unsafe.Pointer(done)), uintptr(unsafe.Pointer(overlapped)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func WriteProcessMemory(process Handle, baseAddress uintptr, buffer *byte, size uintptr, numberOfBytesWritten *uintptr) (err error) {
	r1, _, e1 := syscall.Syscall6(procWriteProcessMemory.Addr(), 5, uintptr(process), uintptr(baseAddress), uintptr(unsafe.Pointer(buffer)), uintptr(size), uintptr(unsafe.Pointer(numberOfBytesWritten)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func AcceptEx(ls Handle, as Handle, buf *byte, rxdatalen uint32, laddrlen uint32, raddrlen uint32, recvd *uint32, overlapped *Overlapped) (err error) {
	r1, _, e1 := syscall.Syscall9(procAcceptEx.Addr(), 8, uintptr(ls), uintptr(as), uintptr(unsafe.Pointer(buf)), uintptr(rxdatalen), uintptr(laddrlen), uintptr(raddrlen), uintptr(unsafe.Pointer(recvd)), uintptr(unsafe.Pointer(overlapped)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetAcceptExSockaddrs(buf *byte, rxdatalen uint32, laddrlen uint32, raddrlen uint32, lrsa **RawSockaddrAny, lrsalen *int32, rrsa **RawSockaddrAny, rrsalen *int32) {
	syscall.Syscall9(procGetAcceptExSockaddrs.Addr(), 8, uintptr(unsafe.Pointer(buf)), uintptr(rxdatalen), uintptr(laddrlen), uintptr(raddrlen), uintptr(unsafe.Pointer(lrsa)), uintptr(unsafe.Pointer(lrsalen)), uintptr(unsafe.Pointer(rrsa)), uintptr(unsafe.Pointer(rrsalen)), 0)
	return
}

func TransmitFile(s Handle, handle Handle, bytesToWrite uint32, bytsPerSend uint32, overlapped *Overlapped, transmitFileBuf *TransmitFileBuffers, flags uint32) (err error) {
	r1, _, e1 := syscall.Syscall9(procTransmitFile.Addr(), 7, uintptr(s), uintptr(handle), uintptr(bytesToWrite), uintptr(bytsPerSend), uintptr(unsafe.Pointer(overlapped)), uintptr(unsafe.Pointer(transmitFileBuf)), uintptr(flags), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func NetApiBufferFree(buf *byte) (neterr error) {
	r0, _, _ := syscall.Syscall(procNetApiBufferFree.Addr(), 1, uintptr(unsafe.Pointer(buf)), 0, 0)
	if r0 != 0 {
		neterr = syscall.Errno(r0)
	}
	return
}

func NetGetJoinInformation(server *uint16, name **uint16, bufType *uint32) (neterr error) {
	r0, _, _ := syscall.Syscall(procNetGetJoinInformation.Addr(), 3, uintptr(unsafe.Pointer(server)), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(bufType)))
	if r0 != 0 {
		neterr = syscall.Errno(r0)
	}
	return
}

func NetUserEnum(serverName *uint16, level uint32, filter uint32, buf **byte, prefMaxLen uint32, entriesRead *uint32, totalEntries *uint32, resumeHandle *uint32) (neterr error) {
	r0, _, _ := syscall.Syscall9(procNetUserEnum.Addr(), 8, uintptr(unsafe.Pointer(serverName)), uintptr(level), uintptr(filter), uintptr(unsafe.Pointer(buf)), uintptr(prefMaxLen), uintptr(unsafe.Pointer(entriesRead)), uintptr(unsafe.Pointer(totalEntries)), uintptr(unsafe.Pointer(resumeHandle)), 0)
	if r0 != 0 {
		neterr = syscall.Errno(r0)
	}
	return
}

func NetUserGetInfo(serverName *uint16, userName *uint16, level uint32, buf **byte) (neterr error) {
	r0, _, _ := syscall.Syscall6(procNetUserGetInfo.Addr(), 4, uintptr(unsafe.Pointer(serverName)), uintptr(unsafe.Pointer(userName)), uintptr(level), uintptr(unsafe.Pointer(buf)), 0, 0)
	if r0 != 0 {
		neterr = syscall.Errno(r0)
	}
	return
}

func NtCreateFile(handle *Handle, access uint32, oa *OBJECT_ATTRIBUTES, iosb *IO_STATUS_BLOCK, allocationSize *int64, attributes uint32, share uint32, disposition uint32, options uint32, eabuffer uintptr, ealength uint32) (ntstatus error) {
	r0, _, _ := syscall.Syscall12(procNtCreateFile.Addr(), 11, uintptr(unsafe.Pointer(handle)), uintptr(access), uintptr(unsafe.Pointer(oa)), uintptr(unsafe.Pointer(iosb)), uintptr(unsafe.Pointer(allocationSize)), uintptr(attributes), uintptr(share), uintptr(disposition), uintptr(options), uintptr(eabuffer), uintptr(ealength), 0)
	if r0 != 0 {
		ntstatus = NTStatus(r0)
	}
	return
}

func NtCreateNamedPipeFile(pipe *Handle, access uint32, oa *OBJECT_ATTRIBUTES, iosb *IO_STATUS_BLOCK, share uint32, disposition uint32, options uint32, typ uint32, readMode uint32, completionMode uint32, maxInstances uint32, inboundQuota uint32, outputQuota uint32, timeout *int64) (ntstatus error) {
	r0, _, _ := syscall.Syscall15(procNtCreateNamedPipeFile.Addr(), 14, uintptr(unsafe.Pointer(pipe)), uintptr(access), uintptr(unsafe.Pointer(oa)), uintptr(unsafe.Pointer(iosb)), uintptr(share), uintptr(disposition), uintptr(options), uintptr(typ), uintptr(readMode), uintptr(completionMode), uintptr(maxInstances), uintptr(inboundQuota), uintptr(outputQuota), uintptr(unsafe.Pointer(timeout)), 0)
	if r0 != 0 {
		ntstatus = NTStatus(r0)
	}
	return
}

func NtQueryInformationProcess(proc Handle, procInfoClass int32, procInfo unsafe.Pointer, procInfoLen uint32, retLen *uint32) (ntstatus error) {
	r0, _, _ := syscall.Syscall6(procNtQueryInformationProcess.Addr(), 5, uintptr(proc), uintptr(procInfoClass), uintptr(procInfo), uintptr(procInfoLen), uintptr(unsafe.Pointer(retLen)), 0)
	if r0 != 0 {
		ntstatus = NTStatus(r0)
	}
	return
}

func NtQuerySystemInformation(sysInfoClass int32, sysInfo unsafe.Pointer, sysInfoLen uint32, retLen *uint32) (ntstatus error) {
	r0, _, _ := syscall.Syscall6(procNtQuerySystemInformation.Addr(), 4, uintptr(sysInfoClass), uintptr(sysInfo), uintptr(sysInfoLen), uintptr(unsafe.Pointer(retLen)), 0, 0)
	if r0 != 0 {
		ntstatus = NTStatus(r0)
	}
	return
}

func NtSetInformationFile(handle Handle, iosb *IO_STATUS_BLOCK, inBuffer *byte, inBufferLen uint32, class uint32) (ntstatus error) {
	r0, _, _ := syscall.Syscall6(procNtSetInformationFile.Addr(), 5, uintptr(handle), uintptr(unsafe.Pointer(iosb)), uintptr(unsafe.Pointer(inBuffer)), uintptr(inBufferLen), uintptr(class), 0)
	if r0 != 0 {
		ntstatus = NTStatus(r0)
	}
	return
}

func NtSetInformationProcess(proc Handle, procInfoClass int32, procInfo unsafe.Pointer, procInfoLen uint32) (ntstatus error) {
	r0, _, _ := syscall.Syscall6(procNtSetInformationProcess.Addr(), 4, uintptr(proc), uintptr(procInfoClass), uintptr(procInfo), uintptr(procInfoLen), 0, 0)
	if r0 != 0 {
		ntstatus = NTStatus(r0)
	}
	return
}

func NtSetSystemInformation(sysInfoClass int32, sysInfo unsafe.Pointer, sysInfoLen uint32) (ntstatus error) {
	r0, _, _ := syscall.Syscall(procNtSetSystemInformation.Addr(), 3, uintptr(sysInfoClass), uintptr(sysInfo), uintptr(sysInfoLen))
	if r0 != 0 {
		ntstatus = NTStatus(r0)
	}
	return
}

func RtlAddFunctionTable(functionTable *RUNTIME_FUNCTION, entryCount uint32, baseAddress uintptr) (ret bool) {
	r0, _, _ := syscall.Syscall(procRtlAddFunctionTable.Addr(), 3, uintptr(unsafe.Pointer(functionTable)), uintptr(entryCount), uintptr(baseAddress))
	ret = r0 != 0
	return
}

func RtlDefaultNpAcl(acl **ACL) (ntstatus error) {
	r0, _, _ := syscall.Syscall(procRtlDefaultNpAcl.Addr(), 1, uintptr(unsafe.Pointer(acl)), 0, 0)
	if r0 != 0 {
		ntstatus = NTStatus(r0)
	}
	return
}

func RtlDeleteFunctionTable(functionTable *RUNTIME_FUNCTION) (ret bool) {
	r0, _, _ := syscall.Syscall(procRtlDeleteFunctionTable.Addr(), 1, uintptr(unsafe.Pointer(functionTable)), 0, 0)
	ret = r0 != 0
	return
}

func RtlDosPathNameToNtPathName(dosName *uint16, ntName *NTUnicodeString, ntFileNamePart *uint16, relativeName *RTL_RELATIVE_NAME) (ntstatus error) {
	r0, _, _ := syscall.Syscall6(procRtlDosPathNameToNtPathName_U_WithStatus.Addr(), 4, uintptr(unsafe.Pointer(dosName)), uintptr(unsafe.Pointer(ntName)), uintptr(unsafe.Pointer(ntFileNamePart)), uintptr(unsafe.Pointer(relativeName)), 0, 0)
	if r0 != 0 {
		ntstatus = NTStatus(r0)
	}
	return
}

func RtlDosPathNameToRelativeNtPathName(dosName *uint16, ntName *NTUnicodeString, ntFileNamePart *uint16, relativeName *RTL_RELATIVE_NAME) (ntstatus error) {
	r0, _, _ := syscall.Syscall6(procRtlDosPathNameToRelativeNtPathName_U_WithStatus.Addr(), 4, uintptr(unsafe.Pointer(dosName)), uintptr(unsafe.Pointer(ntName)), uintptr(unsafe.Pointer(ntFileNamePart)), uintptr(unsafe.Pointer(relativeName)), 0, 0)
	if r0 != 0 {
		ntstatus = NTStatus(r0)
	}
	return
}

func RtlGetCurrentPeb() (peb *PEB) {
	r0, _, _ := syscall.Syscall(procRtlGetCurrentPeb.Addr(), 0, 0, 0, 0)
	peb = (*PEB)(unsafe.Pointer(r0))
	return
}

func rtlGetNtVersionNumbers(majorVersion *uint32, minorVersion *uint32, buildNumber *uint32) {
	syscall.Syscall(procRtlGetNtVersionNumbers.Addr(), 3, uintptr(unsafe.Pointer(majorVersion)), uintptr(unsafe.Pointer(minorVersion)), uintptr(unsafe.Pointer(buildNumber)))
	return
}

func rtlGetVersion(info *OsVersionInfoEx) (ntstatus error) {
	r0, _, _ := syscall.Syscall(procRtlGetVersion.Addr(), 1, uintptr(unsafe.Pointer(info)), 0, 0)
	if r0 != 0 {
		ntstatus = NTStatus(r0)
	}
	return
}

func RtlInitString(destinationString *NTString, sourceString *byte) {
	syscall.Syscall(procRtlInitString.Addr(), 2, uintptr(unsafe.Pointer(destinationString)), uintptr(unsafe.Pointer(sourceString)), 0)
	return
}

func RtlInitUnicodeString(destinationString *NTUnicodeString, sourceString *uint16) {
	syscall.Syscall(procRtlInitUnicodeString.Addr(), 2, uintptr(unsafe.Pointer(destinationString)), uintptr(unsafe.Pointer(sourceString)), 0)
	return
}

func rtlNtStatusToDosErrorNoTeb(ntstatus NTStatus) (ret syscall.Errno) {
	r0, _, _ := syscall.Syscall(procRtlNtStatusToDosErrorNoTeb.Addr(), 1, uintptr(ntstatus), 0, 0)
	ret = syscall.Errno(r0)
	return
}

func clsidFromString(lpsz *uint16, pclsid *GUID) (ret error) {
	r0, _, _ := syscall.Syscall(procCLSIDFromString.Addr(), 2, uintptr(unsafe.Pointer(lpsz)), uintptr(unsafe.Pointer(pclsid)), 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func coCreateGuid(pguid *GUID) (ret error) {
	r0, _, _ := syscall.Syscall(procCoCreateGuid.Addr(), 1, uintptr(unsafe.Pointer(pguid)), 0, 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func CoGetObject(name *uint16, bindOpts *BIND_OPTS3, guid *GUID, functionTable **uintptr) (ret error) {
	r0, _, _ := syscall.Syscall6(procCoGetObject.Addr(), 4, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(bindOpts)), uintptr(unsafe.Pointer(guid)), uintptr(unsafe.Pointer(functionTable)), 0, 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func CoInitializeEx(reserved uintptr, coInit uint32) (ret error) {
	r0, _, _ := syscall.Syscall(procCoInitializeEx.Addr(), 2, uintptr(reserved), uintptr(coInit), 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func CoTaskMemFree(address unsafe.Pointer) {
	syscall.Syscall(procCoTaskMemFree.Addr(), 1, uintptr(address), 0, 0)
	return
}

func CoUninitialize() {
	syscall.Syscall(procCoUninitialize.Addr(), 0, 0, 0, 0)
	return
}

func stringFromGUID2(rguid *GUID, lpsz *uint16, cchMax int32) (chars int32) {
	r0, _, _ := syscall.Syscall(procStringFromGUID2.Addr(), 3, uintptr(unsafe.Pointer(rguid)), uintptr(unsafe.Pointer(lpsz)), uintptr(cchMax))
	chars = int32(r0)
	return
}

func EnumProcessModules(process Handle, module *Handle, cb uint32, cbNeeded *uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procEnumProcessModules.Addr(), 4, uintptr(process), uintptr(unsafe.Pointer(module)), uintptr(cb), uintptr(unsafe.Pointer(cbNeeded)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func EnumProcessModulesEx(process Handle, module *Handle, cb uint32, cbNeeded *uint32, filterFlag uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procEnumProcessModulesEx.Addr(), 5, uintptr(process), uintptr(unsafe.Pointer(module)), uintptr(cb), uintptr(unsafe.Pointer(cbNeeded)), uintptr(filterFlag), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func enumProcesses(processIds *uint32, nSize uint32, bytesReturned *uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procEnumProcesses.Addr(), 3, uintptr(unsafe.Pointer(processIds)), uintptr(nSize), uintptr(unsafe.Pointer(bytesReturned)))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetModuleBaseName(process Handle, module Handle, baseName *uint16, size uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procGetModuleBaseNameW.Addr(), 4, uintptr(process), uintptr(module), uintptr(unsafe.Pointer(baseName)), uintptr(size), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetModuleFileNameEx(process Handle, module Handle, filename *uint16, size uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procGetModuleFileNameExW.Addr(), 4, uintptr(process), uintptr(module), uintptr(unsafe.Pointer(filename)), uintptr(size), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetModuleInformation(process Handle, module Handle, modinfo *ModuleInfo, cb uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procGetModuleInformation.Addr(), 4, uintptr(process), uintptr(module), uintptr(unsafe.Pointer(modinfo)), uintptr(cb), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func QueryWorkingSetEx(process Handle, pv uintptr, cb uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procQueryWorkingSetEx.Addr(), 3, uintptr(process), uintptr(pv), uintptr(cb))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SubscribeServiceChangeNotifications(service Handle, eventType uint32, callback uintptr, callbackCtx uintptr, subscription *uintptr) (ret error) {
	ret = procSubscribeServiceChangeNotifications.Find()
	if ret != nil {
		return
	}
	r0, _, _ := syscall.Syscall6(procSubscribeServiceChangeNotifications.Addr(), 5, uintptr(service), uintptr(eventType), uintptr(callback), uintptr(callbackCtx), uintptr(unsafe.Pointer(subscription)), 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func UnsubscribeServiceChangeNotifications(subscription uintptr) (err error) {
	err = procUnsubscribeServiceChangeNotifications.Find()
	if err != nil {
		return
	}
	syscall.Syscall(procUnsubscribeServiceChangeNotifications.Addr(), 1, uintptr(subscription), 0, 0)
	return
}

func GetUserNameEx(nameFormat uint32, nameBuffre *uint16, nSize *uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procGetUserNameExW.Addr(), 3, uintptr(nameFormat), uintptr(unsafe.Pointer(nameBuffre)), uintptr(unsafe.Pointer(nSize)))
	if r1&0xff == 0 {
		err = errnoErr(e1)
	}
	return
}

func TranslateName(accName *uint16, accNameFormat uint32, desiredNameFormat uint32, translatedName *uint16, nSize *uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procTranslateNameW.Addr(), 5, uintptr(unsafe.Pointer(accName)), uintptr(accNameFormat), uintptr(desiredNameFormat), uintptr(unsafe.Pointer(translatedName)), uintptr(unsafe.Pointer(nSize)), 0)
	if r1&0xff == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetupDiBuildDriverInfoList(deviceInfoSet DevInfo, deviceInfoData *DevInfoData, driverType SPDIT) (err error) {
	r1, _, e1 := syscall.Syscall(procSetupDiBuildDriverInfoList.Addr(), 3, uintptr(deviceInfoSet), uintptr(unsafe.Pointer(deviceInfoData)), uintptr(driverType))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetupDiCallClassInstaller(installFunction DI_FUNCTION, deviceInfoSet DevInfo, deviceInfoData *DevInfoData) (err error) {
	r1, _, e1 := syscall.Syscall(procSetupDiCallClassInstaller.Addr(), 3, uintptr(installFunction), uintptr(deviceInfoSet), uintptr(unsafe.Pointer(deviceInfoData)))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetupDiCancelDriverInfoSearch(deviceInfoSet DevInfo) (err error) {
	r1, _, e1 := syscall.Syscall(procSetupDiCancelDriverInfoSearch.Addr(), 1, uintptr(deviceInfoSet), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func setupDiClassGuidsFromNameEx(className *uint16, classGuidList *GUID, classGuidListSize uint32, requiredSize *uint32, machineName *uint16, reserved uintptr) (err error) {
	r1, _, e1 := syscall.Syscall6(procSetupDiClassGuidsFromNameExW.Addr(), 6, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(classGuidList)), uintptr(classGuidListSize), uintptr(unsafe.Pointer(requiredSize)), uintptr(unsafe.Pointer(machineName)), uintptr(reserved))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func setupDiClassNameFromGuidEx(classGUID *GUID, className *uint16, classNameSize uint32, requiredSize *uint32, machineName *uint16, reserved uintptr) (err error) {
	r1, _, e1 := syscall.Syscall6(procSetupDiClassNameFromGuidExW.Addr(), 6, uintptr(unsafe.Pointer(classGUID)), uintptr(unsafe.Pointer(className)), uintptr(classNameSize), uintptr(unsafe.Pointer(requiredSize)), uintptr(unsafe.Pointer(machineName)), uintptr(reserved))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func setupDiCreateDeviceInfoListEx(classGUID *GUID, hwndParent uintptr, machineName *uint16, reserved uintptr) (handle DevInfo, err error) {
	r0, _, e1 := syscall.Syscall6(procSetupDiCreateDeviceInfoListExW.Addr(), 4, uintptr(unsafe.Pointer(classGUID)), uintptr(hwndParent), uintptr(unsafe.Pointer(machineName)), uintptr(reserved), 0, 0)
	handle = DevInfo(r0)
	if handle == DevInfo(InvalidHandle) {
		err = errnoErr(e1)
	}
	return
}

func setupDiCreateDeviceInfo(deviceInfoSet DevInfo, DeviceName *uint16, classGUID *GUID, DeviceDescription *uint16, hwndParent uintptr, CreationFlags DICD, deviceInfoData *DevInfoData) (err error) {
	r1, _, e1 := syscall.Syscall9(procSetupDiCreateDeviceInfoW.Addr(), 7, uintptr(deviceInfoSet), uintptr(unsafe.Pointer(DeviceName)), uintptr(unsafe.Pointer(classGUID)), uintptr(unsafe.Pointer(DeviceDescription)), uintptr(hwndParent), uintptr(CreationFlags), uintptr(unsafe.Pointer(deviceInfoData)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetupDiDestroyDeviceInfoList(deviceInfoSet DevInfo) (err error) {
	r1, _, e1 := syscall.Syscall(procSetupDiDestroyDeviceInfoList.Addr(), 1, uintptr(deviceInfoSet), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetupDiDestroyDriverInfoList(deviceInfoSet DevInfo, deviceInfoData *DevInfoData, driverType SPDIT) (err error) {
	r1, _, e1 := syscall.Syscall(procSetupDiDestroyDriverInfoList.Addr(), 3, uintptr(deviceInfoSet), uintptr(unsafe.Pointer(deviceInfoData)), uintptr(driverType))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func setupDiEnumDeviceInfo(deviceInfoSet DevInfo, memberIndex uint32, deviceInfoData *DevInfoData) (err error) {
	r1, _, e1 := syscall.Syscall(procSetupDiEnumDeviceInfo.Addr(), 3, uintptr(deviceInfoSet), uintptr(memberIndex), uintptr(unsafe.Pointer(deviceInfoData)))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func setupDiEnumDriverInfo(deviceInfoSet DevInfo, deviceInfoData *DevInfoData, driverType SPDIT, memberIndex uint32, driverInfoData *DrvInfoData) (err error) {
	r1, _, e1 := syscall.Syscall6(procSetupDiEnumDriverInfoW.Addr(), 5, uintptr(deviceInfoSet), uintptr(unsafe.Pointer(deviceInfoData)), uintptr(driverType), uintptr(memberIndex), uintptr(unsafe.Pointer(driverInfoData)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func setupDiGetClassDevsEx(classGUID *GUID, Enumerator *uint16, hwndParent uintptr, Flags DIGCF, deviceInfoSet DevInfo, machineName *uint16, reserved uintptr) (handle DevInfo, err error) {
	r0, _, e1 := syscall.Syscall9(procSetupDiGetClassDevsExW.Addr(), 7, uintptr(unsafe.Pointer(classGUID)), uintptr(unsafe.Pointer(Enumerator)), uintptr(hwndParent), uintptr(Flags), uintptr(deviceInfoSet), uintptr(unsafe.Pointer(machineName)), uintptr(reserved), 0, 0)
	handle = DevInfo(r0)
	if handle == DevInfo(InvalidHandle) {
		err = errnoErr(e1)
	}
	return
}

func SetupDiGetClassInstallParams(deviceInfoSet DevInfo, deviceInfoData *DevInfoData, classInstallParams *ClassInstallHeader, classInstallParamsSize uint32, requiredSize *uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procSetupDiGetClassInstallParamsW.Addr(), 5, uintptr(deviceInfoSet), uintptr(unsafe.Pointer(deviceInfoData)), uintptr(unsafe.Pointer(classInstallParams)), uintptr(classInstallParamsSize), uintptr(unsafe.Pointer(requiredSize)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func setupDiGetDeviceInfoListDetail(deviceInfoSet DevInfo, deviceInfoSetDetailData *DevInfoListDetailData) (err error) {
	r1, _, e1 := syscall.Syscall(procSetupDiGetDeviceInfoListDetailW.Addr(), 2, uintptr(deviceInfoSet), uintptr(unsafe.Pointer(deviceInfoSetDetailData)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func setupDiGetDeviceInstallParams(deviceInfoSet DevInfo, deviceInfoData *DevInfoData, deviceInstallParams *DevInstallParams) (err error) {
	r1, _, e1 := syscall.Syscall(procSetupDiGetDeviceInstallParamsW.Addr(), 3, uintptr(deviceInfoSet), uintptr(unsafe.Pointer(deviceInfoData)), uintptr(unsafe.Pointer(deviceInstallParams)))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func setupDiGetDeviceInstanceId(deviceInfoSet DevInfo, deviceInfoData *DevInfoData, instanceId *uint16, instanceIdSize uint32, instanceIdRequiredSize *uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procSetupDiGetDeviceInstanceIdW.Addr(), 5, uintptr(deviceInfoSet), uintptr(unsafe.Pointer(deviceInfoData)), uintptr(unsafe.Pointer(instanceId)), uintptr(instanceIdSize), uintptr(unsafe.Pointer(instanceIdRequiredSize)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func setupDiGetDeviceProperty(deviceInfoSet DevInfo, deviceInfoData *DevInfoData, propertyKey *DEVPROPKEY, propertyType *DEVPROPTYPE, propertyBuffer *byte, propertyBufferSize uint32, requiredSize *uint32, flags uint32) (err error) {
	r1, _, e1 := syscall.Syscall9(procSetupDiGetDevicePropertyW.Addr(), 8, uintptr(deviceInfoSet), uintptr(unsafe.Pointer(deviceInfoData)), uintptr(unsafe.Pointer(propertyKey)), uintptr(unsafe.Pointer(propertyType)), uintptr(unsafe.Pointer(propertyBuffer)), uintptr(propertyBufferSize), uintptr(unsafe.Pointer(requiredSize)), uintptr(flags), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func setupDiGetDeviceRegistryProperty(deviceInfoSet DevInfo, deviceInfoData *DevInfoData, property SPDRP, propertyRegDataType *uint32, propertyBuffer *byte, propertyBufferSize uint32, requiredSize *uint32) (err error) {
	r1, _, e1 := syscall.Syscall9(procSetupDiGetDeviceRegistryPropertyW.Addr(), 7, uintptr(deviceInfoSet), uintptr(unsafe.Pointer(deviceInfoData)), uintptr(property), uintptr(unsafe.Pointer(propertyRegDataType)), uintptr(unsafe.Pointer(propertyBuffer)), uintptr(propertyBufferSize), uintptr(unsafe.Pointer(requiredSize)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func setupDiGetDriverInfoDetail(deviceInfoSet DevInfo, deviceInfoData *DevInfoData, driverInfoData *DrvInfoData, driverInfoDetailData *DrvInfoDetailData, driverInfoDetailDataSize uint32, requiredSize *uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procSetupDiGetDriverInfoDetailW.Addr(), 6, uintptr(deviceInfoSet), uintptr(unsafe.Pointer(deviceInfoData)), uintptr(unsafe.Pointer(driverInfoData)), uintptr(unsafe.Pointer(driverInfoDetailData)), uintptr(driverInfoDetailDataSize), uintptr(unsafe.Pointer(requiredSize)))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func setupDiGetSelectedDevice(deviceInfoSet DevInfo, deviceInfoData *DevInfoData) (err error) {
	r1, _, e1 := syscall.Syscall(procSetupDiGetSelectedDevice.Addr(), 2, uintptr(deviceInfoSet), uintptr(unsafe.Pointer(deviceInfoData)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func setupDiGetSelectedDriver(deviceInfoSet DevInfo, deviceInfoData *DevInfoData, driverInfoData *DrvInfoData) (err error) {
	r1, _, e1 := syscall.Syscall(procSetupDiGetSelectedDriverW.Addr(), 3, uintptr(deviceInfoSet), uintptr(unsafe.Pointer(deviceInfoData)), uintptr(unsafe.Pointer(driverInfoData)))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetupDiOpenDevRegKey(deviceInfoSet DevInfo, deviceInfoData *DevInfoData, Scope DICS_FLAG, HwProfile uint32, KeyType DIREG, samDesired uint32) (key Handle, err error) {
	r0, _, e1 := syscall.Syscall6(procSetupDiOpenDevRegKey.Addr(), 6, uintptr(deviceInfoSet), uintptr(unsafe.Pointer(deviceInfoData)), uintptr(Scope), uintptr(HwProfile), uintptr(KeyType), uintptr(samDesired))
	key = Handle(r0)
	if key == InvalidHandle {
		err = errnoErr(e1)
	}
	return
}

func SetupDiSetClassInstallParams(deviceInfoSet DevInfo, deviceInfoData *DevInfoData, classInstallParams *ClassInstallHeader, classInstallParamsSize uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procSetupDiSetClassInstallParamsW.Addr(), 4, uintptr(deviceInfoSet), uintptr(unsafe.Pointer(deviceInfoData)), uintptr(unsafe.Pointer(classInstallParams)), uintptr(classInstallParamsSize), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetupDiSetDeviceInstallParams(deviceInfoSet DevInfo, deviceInfoData *DevInfoData, deviceInstallParams *DevInstallParams) (err error) {
	r1, _, e1 := syscall.Syscall(procSetupDiSetDeviceInstallParamsW.Addr(), 3, uintptr(deviceInfoSet), uintptr(unsafe.Pointer(deviceInfoData)), uintptr(unsafe.Pointer(deviceInstallParams)))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func setupDiSetDeviceRegistryProperty(deviceInfoSet DevInfo, deviceInfoData *DevInfoData, property SPDRP, propertyBuffer *byte, propertyBufferSize uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procSetupDiSetDeviceRegistryPropertyW.Addr(), 5, uintptr(deviceInfoSet), uintptr(unsafe.Pointer(deviceInfoData)), uintptr(property), uintptr(unsafe.Pointer(propertyBuffer)), uintptr(propertyBufferSize), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetupDiSetSelectedDevice(deviceInfoSet DevInfo, deviceInfoData *DevInfoData) (err error) {
	r1, _, e1 := syscall.Syscall(procSetupDiSetSelectedDevice.Addr(), 2, uintptr(deviceInfoSet), uintptr(unsafe.Pointer(deviceInfoData)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetupDiSetSelectedDriver(deviceInfoSet DevInfo, deviceInfoData *DevInfoData, driverInfoData *DrvInfoData) (err error) {
	r1, _, e1 := syscall.Syscall(procSetupDiSetSelectedDriverW.Addr(), 3, uintptr(deviceInfoSet), uintptr(unsafe.Pointer(deviceInfoData)), uintptr(unsafe.Pointer(driverInfoData)))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func setupUninstallOEMInf(infFileName *uint16, flags SUOI, reserved uintptr) (err error) {
	r1, _, e1 := syscall.Syscall(procSetupUninstallOEMInfW.Addr(), 3, uintptr(unsafe.Pointer(infFileName)), uintptr(flags), uintptr(reserved))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func commandLineToArgv(cmd *uint16, argc *int32) (argv **uint16, err error) {
	r0, _, e1 := syscall.Syscall(procCommandLineToArgvW.Addr(), 2, uintptr(unsafe.Pointer(cmd)), uintptr(unsafe.Pointer(argc)), 0)
	argv = (**uint16)(unsafe.Pointer(r0))
	if argv == nil {
		err = errnoErr(e1)
	}
	return
}

func shGetKnownFolderPath(id *KNOWNFOLDERID, flags uint32, token Token, path **uint16) (ret error) {
	r0, _, _ := syscall.Syscall6(procSHGetKnownFolderPath.Addr(), 4, uintptr(unsafe.Pointer(id)), uintptr(flags), uintptr(token), uintptr(unsafe.Pointer(path)), 0, 0)
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func ShellExecute(hwnd Handle, verb *uint16, file *uint16, args *uint16, cwd *uint16, showCmd int32) (err error) {
	r1, _, e1 := syscall.Syscall6(procShellExecuteW.Addr(), 6, uintptr(hwnd), uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)), uintptr(unsafe.Pointer(args)), uintptr(unsafe.Pointer(cwd)), uintptr(showCmd))
	if r1 <= 32 {
		err = errnoErr(e1)
	}
	return
}

func EnumChildWindows(hwnd HWND, enumFunc uintptr, param unsafe.Pointer) {
	syscall.Syscall(procEnumChildWindows.Addr(), 3, uintptr(hwnd), uintptr(enumFunc), uintptr(param))
	return
}

func EnumWindows(enumFunc uintptr, param unsafe.Pointer) (err error) {
	r1, _, e1 := syscall.Syscall(procEnumWindows.Addr(), 2, uintptr(enumFunc), uintptr(param), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func ExitWindowsEx(flags uint32, reason uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procExitWindowsEx.Addr(), 2, uintptr(flags), uintptr(reason), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetClassName(hwnd HWND, className *uint16, maxCount int32) (copied int32, err error) {
	r0, _, e1 := syscall.Syscall(procGetClassNameW.Addr(), 3, uintptr(hwnd), uintptr(unsafe.Pointer(className)), uintptr(maxCount))
	copied = int32(r0)
	if copied == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetDesktopWindow() (hwnd HWND) {
	r0, _, _ := syscall.Syscall(procGetDesktopWindow.Addr(), 0, 0, 0, 0)
	hwnd = HWND(r0)
	return
}

func GetForegroundWindow() (hwnd HWND) {
	r0, _, _ := syscall.Syscall(procGetForegroundWindow.Addr(), 0, 0, 0, 0)
	hwnd = HWND(r0)
	return
}

func GetGUIThreadInfo(thread uint32, info *GUIThreadInfo) (err error) {
	r1, _, e1 := syscall.Syscall(procGetGUIThreadInfo.Addr(), 2, uintptr(thread), uintptr(unsafe.Pointer(info)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetKeyboardLayout(tid uint32) (hkl Handle) {
	r0, _, _ := syscall.Syscall(procGetKeyboardLayout.Addr(), 1, uintptr(tid), 0, 0)
	hkl = Handle(r0)
	return
}

func GetShellWindow() (shellWindow HWND) {
	r0, _, _ := syscall.Syscall(procGetShellWindow.Addr(), 0, 0, 0, 0)
	shellWindow = HWND(r0)
	return
}

func GetWindowThreadProcessId(hwnd HWND, pid *uint32) (tid uint32, err error) {
	r0, _, e1 := syscall.Syscall(procGetWindowThreadProcessId.Addr(), 2, uintptr(hwnd), uintptr(unsafe.Pointer(pid)), 0)
	tid = uint32(r0)
	if tid == 0 {
		err = errnoErr(e1)
	}
	return
}

func IsWindow(hwnd HWND) (isWindow bool) {
	r0, _, _ := syscall.Syscall(procIsWindow.Addr(), 1, uintptr(hwnd), 0, 0)
	isWindow = r0 != 0
	return
}

func IsWindowUnicode(hwnd HWND) (isUnicode bool) {
	r0, _, _ := syscall.Syscall(procIsWindowUnicode.Addr(), 1, uintptr(hwnd), 0, 0)
	isUnicode = r0 != 0
	return
}

func IsWindowVisible(hwnd HWND) (isVisible bool) {
	r0, _, _ := syscall.Syscall(procIsWindowVisible.Addr(), 1, uintptr(hwnd), 0, 0)
	isVisible = r0 != 0
	return
}

func LoadKeyboardLayout(name *uint16, flags uint32) (hkl Handle, err error) {
	r0, _, e1 := syscall.Syscall(procLoadKeyboardLayoutW.Addr(), 2, uintptr(unsafe.Pointer(name)), uintptr(flags), 0)
	hkl = Handle(r0)
	if hkl == 0 {
		err = errnoErr(e1)
	}
	return
}

func MessageBox(hwnd HWND, text *uint16, caption *uint16, boxtype uint32) (ret int32, err error) {
	r0, _, e1 := syscall.Syscall6(procMessageBoxW.Addr(), 4, uintptr(hwnd), uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(caption)), uintptr(boxtype), 0, 0)
	ret = int32(r0)
	if ret == 0 {
		err = errnoErr(e1)
	}
	return
}

func ToUnicodeEx(vkey uint32, scancode uint32, keystate *byte, pwszBuff *uint16, cchBuff int32, flags uint32, hkl Handle) (ret int32) {
	r0, _, _ := syscall.Syscall9(procToUnicodeEx.Addr(), 7, uintptr(vkey), uintptr(scancode), uintptr(unsafe.Pointer(keystate)), uintptr(unsafe.Pointer(pwszBuff)), uintptr(cchBuff), uintptr(flags), uintptr(hkl), 0, 0)
	ret = int32(r0)
	return
}

func UnloadKeyboardLayout(hkl Handle) (err error) {
	r1, _, e1 := syscall.Syscall(procUnloadKeyboardLayout.Addr(), 1, uintptr(hkl), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func CreateEnvironmentBlock(block **uint16, token Token, inheritExisting bool) (err error) {
	var _p0 uint32
	if inheritExisting {
		_p0 = 1
	}
	r1, _, e1 := syscall.Syscall(procCreateEnvironmentBlock.Addr(), 3, uintptr(unsafe.Pointer(block)), uintptr(token), uintptr(_p0))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func DestroyEnvironmentBlock(block *uint16) (err error) {
	r1, _, e1 := syscall.Syscall(procDestroyEnvironmentBlock.Addr(), 1, uintptr(unsafe.Pointer(block)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetUserProfileDirectory(t Token, dir *uint16, dirLen *uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procGetUserProfileDirectoryW.Addr(), 3, uintptr(t), uintptr(unsafe.Pointer(dir)), uintptr(unsafe.Pointer(dirLen)))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetFileVersionInfoSize(filename string, zeroHandle *Handle) (bufSize uint32, err error) {
	var _p0 *uint16
	_p0, err = syscall.UTF16PtrFromString(filename)
	if err != nil {
		return
	}
	return _GetFileVersionInfoSize(_p0, zeroHandle)
}

func _GetFileVersionInfoSize(filename *uint16, zeroHandle *Handle) (bufSize uint32, err error) {
	r0, _, e1 := syscall.Syscall(procGetFileVersionInfoSizeW.Addr(), 2, uintptr(unsafe.Pointer(filename)), uintptr(unsafe.Pointer(zeroHandle)), 0)
	bufSize = uint32(r0)
	if bufSize == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetFileVersionInfo(filename string, handle uint32, bufSize uint32, buffer unsafe.Pointer) (err error) {
	var _p0 *uint16
	_p0, err = syscall.UTF16PtrFromString(filename)
	if err != nil {
		return
	}
	return _GetFileVersionInfo(_p0, handle, bufSize, buffer)
}

func _GetFileVersionInfo(filename *uint16, handle uint32, bufSize uint32, buffer unsafe.Pointer) (err error) {
	r1, _, e1 := syscall.Syscall6(procGetFileVersionInfoW.Addr(), 4, uintptr(unsafe.Pointer(filename)), uintptr(handle), uintptr(bufSize), uintptr(buffer), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func VerQueryValue(block unsafe.Pointer, subBlock string, pointerToBufferPointer unsafe.Pointer, bufSize *uint32) (err error) {
	var _p0 *uint16
	_p0, err = syscall.UTF16PtrFromString(subBlock)
	if err != nil {
		return
	}
	return _VerQueryValue(block, _p0, pointerToBufferPointer, bufSize)
}

func _VerQueryValue(block unsafe.Pointer, subBlock *uint16, pointerToBufferPointer unsafe.Pointer, bufSize *uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procVerQueryValueW.Addr(), 4, uintptr(block), uintptr(unsafe.Pointer(subBlock)), uintptr(pointerToBufferPointer), uintptr(unsafe.Pointer(bufSize)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func TimeBeginPeriod(period uint32) (err error) {
	r1, _, e1 := syscall.Syscall(proctimeBeginPeriod.Addr(), 1, uintptr(period), 0, 0)
	if r1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func TimeEndPeriod(period uint32) (err error) {
	r1, _, e1 := syscall.Syscall(proctimeEndPeriod.Addr(), 1, uintptr(period), 0, 0)
	if r1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func WinVerifyTrustEx(hwnd HWND, actionId *GUID, data *WinTrustData) (ret error) {
	r0, _, _ := syscall.Syscall(procWinVerifyTrustEx.Addr(), 3, uintptr(hwnd), uintptr(unsafe.Pointer(actionId)), uintptr(unsafe.Pointer(data)))
	if r0 != 0 {
		ret = syscall.Errno(r0)
	}
	return
}

func FreeAddrInfoW(addrinfo *AddrinfoW) {
	syscall.Syscall(procFreeAddrInfoW.Addr(), 1, uintptr(unsafe.Pointer(addrinfo)), 0, 0)
	return
}

func GetAddrInfoW(nodename *uint16, servicename *uint16, hints *AddrinfoW, result **AddrinfoW) (sockerr error) {
	r0, _, _ := syscall.Syscall6(procGetAddrInfoW.Addr(), 4, uintptr(unsafe.Pointer(nodename)), uintptr(unsafe.Pointer(servicename)), uintptr(unsafe.Pointer(hints)), uintptr(unsafe.Pointer(result)), 0, 0)
	if r0 != 0 {
		sockerr = syscall.Errno(r0)
	}
	return
}

func WSACleanup() (err error) {
	r1, _, e1 := syscall.Syscall(procWSACleanup.Addr(), 0, 0, 0, 0)
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func WSAEnumProtocols(protocols *int32, protocolBuffer *WSAProtocolInfo, bufferLength *uint32) (n int32, err error) {
	r0, _, e1 := syscall.Syscall(procWSAEnumProtocolsW.Addr(), 3, uintptr(unsafe.Pointer(protocols)), uintptr(unsafe.Pointer(protocolBuffer)), uintptr(unsafe.Pointer(bufferLength)))
	n = int32(r0)
	if n == -1 {
		err = errnoErr(e1)
	}
	return
}

func WSAGetOverlappedResult(h Handle, o *Overlapped, bytes *uint32, wait bool, flags *uint32) (err error) {
	var _p0 uin
```