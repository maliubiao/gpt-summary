Response:
The user wants to understand the functionality of the provided Go code snippet, which is a part of the `syscall_windows.go` file in the `golang.org/x/sys/windows` package.

To address this, I need to:

1. **List the functions and types defined in the snippet.**
2. **Infer the purpose of each function and type.**  Many of these are wrappers around Windows API calls or data structures.
3. **Identify potential Go language features implemented by this code.** Look for patterns related to system calls, networking, process management, file system interaction, etc.
4. **Provide Go code examples** to illustrate the usage of the inferred functionalities. These examples should include hypothetical inputs and expected outputs where applicable.
5. **Explain any command-line argument processing** if the code relates to command-line tools (which seems unlikely given the nature of the code, but I need to check).
6. **Highlight common pitfalls for users** based on the code. The comments in the code, like the one about the `Linger` struct, are good hints here.
7. **Summarize the overall functionality** of the code snippet.

**Detailed breakdown of the code:**

* **`WSASendMsg`, `WSARecvMsg`:**  These functions likely handle sending and receiving messages on sockets, potentially with more advanced options than the standard `Send` and `Recv`. The `WSA` prefix suggests they are related to Winsock.
* **`Rusage`, `WaitStatus`:**  These structs seem to represent process resource usage and termination status, respectively. They appear to be adaptations of Unix-like concepts for Windows.
* **Methods on `WaitStatus`:**  These methods (`Exited`, `ExitStatus`, etc.) provide a consistent interface for querying process exit information, aligning with the `os/exec` package's expectations.
* **`Timespec`:** This struct likely represents a time duration with seconds and nanoseconds, similar to the Unix `timespec` structure.
* **`TimespecToNsec`, `NsecToTimespec`:** These functions perform conversions between `Timespec` and nanoseconds, enabling time calculations.
* **Network functions (`Accept`, `Recvfrom`, `Sendto`, `SetsockoptTimeval`):** These are standard socket operations. The `syscall.EWINDOWS` return in `Accept` and `SetsockoptTimeval` suggests they are not fully implemented or rely on other lower-level functions.
* **Socket option structures (`Linger`, `sysLinger`, `IPMreq`, `IPv6Mreq`):** These structs define options that can be set on sockets. The comment about `Linger` being "wrong" is a key observation.
* **`GetsockoptInt`, `SetsockoptLinger`, `SetsockoptInet4Addr`, `SetsockoptIPMreq`, `SetsockoptIPv6Mreq`:**  These functions provide type-safe ways to get and set socket options.
* **`EnumProcesses`:** This function retrieves a list of running process IDs.
* **`Getpid`:** Returns the current process ID.
* **`FindFirstFile`, `FindNextFile`:** These functions are used to iterate through files in a directory. The comment about the `Win32finddata` struct discrepancy is important.
* **`getProcessEntry`, `Getppid`:**  These functions help retrieve process information, specifically the parent process ID.
* **OS-related functions (`Fchdir`, `Link`, `Symlink`, `Fchmod`, `Chown`, `Lchown`, `Fchown`):** These functions relate to file system operations, but are currently returning `syscall.EWINDOWS`, indicating they are not directly implemented.
* **User and group ID functions (`Getuid`, `Geteuid`, `Getgid`, `Getegid`, `Getgroups`):**  These functions, common in Unix-like systems, also return fixed values or errors on Windows, as user/group IDs are handled differently.
* **`Signal` type and methods:** This represents a signal, likely for inter-process communication.
* **`LoadCreateSymbolicLink`, `Readlink`:**  These functions handle symbolic links.
* **GUID functions (`GUIDFromString`, `GenerateGUID`, `String` method on `GUID`):** These functions deal with Globally Unique Identifiers (GUIDs).
* **Known folder path functions (`KnownFolderPath`):** These functions retrieve paths to special system folders.
* **OS Version functions (`RtlGetVersion`, `RtlGetNtVersionNumbers`):** These functions retrieve detailed operating system version information.
* **UI Language functions (`GetProcessPreferredUILanguages`, `GetThreadPreferredUILanguages`, `GetUserPreferredUILanguages`, `GetSystemPreferredUILanguages`, `getUILanguages`):** These functions retrieve the user's preferred UI languages.
* **Console functions (`SetConsoleCursorPosition`):** This function controls the console cursor position.
* **`GetStartupInfo`:** Retrieves information about how the current process was started.
* **`NTStatus` and related methods (`Errno`, `Error`):** This deals with NTSTATUS error codes, which are a lower-level error reporting mechanism in Windows.
* **`NTUnicodeString`, `NTString` and related functions/methods:** These structures and functions handle Windows-native string types.
* **Resource functions (`FindResource`, `LoadResourceData`):** These functions access embedded resources within a module (like an executable).
* **Working set functions (`PSAPI_WORKING_SET_EX_BLOCK`, `PSAPI_WORKING_SET_EX_INFORMATION`):** These functions retrieve detailed information about the memory pages used by a process.
* **Pseudo console functions (`CreatePseudoConsole`, `ResizePseudoConsole`):** These functions manage pseudo consoles, which are used for terminal emulation.
* **Serial communication constants:** The constants at the end (`CBR_...`, `DTR_CONTROL_...`, etc.) relate to serial port configuration.

Now I can generate the response based on this analysis.
这是 Go 语言 `syscall` 包在 Windows 平台实现的一部分，主要提供了对 Windows 系统 API 的底层访问，以支持 Go 标准库和其他扩展库的功能。由于这是第二部分，且没有前文，我将基于提供的代码片段进行归纳。

**归纳其功能：**

这部分代码主要提供了以下方面的功能，用于与 Windows 操作系统进行交互：

1. **高级 Socket 操作:** 提供了 `WSASendMsg` 和 `WSARecvMsg` 函数，允许进行更底层的 socket 发送和接收操作，可能用于处理更复杂的网络协议或需要精细控制的场景。

2. **进程和线程信息:**
   - 定义了 `Rusage` 结构体，用于存储进程的资源使用情况（虽然在 Windows 上其具体含义可能与 Unix 系统不同）。
   - 定义了 `WaitStatus` 结构体，用于表示进程的退出状态，并提供了一些方法来判断进程是否退出以及退出码。
   - 提供了 `EnumProcesses` 函数来枚举当前运行的进程。
   - 提供了 `Getpid` 和 `Getppid` 函数分别获取当前进程和父进程的 ID。
   - 提供了 `getProcessEntry` 函数来获取指定进程的详细信息（通过快照）。

3. **文件系统操作 (部分):**
   - 提供了 `FindFirstFile` 和 `FindNextFile` 函数，用于查找符合特定模式的文件。**注意代码中的注释提到了 `Win32finddata` 结构体可能存在问题，并使用了 `win32finddata1` 作为替代。**
   - 提供了 `Readlink` 函数来读取符号链接的目标路径。

4. **时间和日期:**
   - 定义了 `Timespec` 结构体，用于表示时间和纳秒。
   - 提供了 `TimespecToNsec` 和 `NsecToTimespec` 函数，用于 `Timespec` 和纳秒之间的转换。

5. **Socket 选项:**
   - 提供了 `SetsockoptLinger` 函数来设置 socket 的 `linger` 选项。
   - 提供了 `SetsockoptInet4Addr` 和 `SetsockoptIPMreq` 函数来设置 IPv4 相关的 socket 选项。
   - 提供了 `GetsockoptInt` 函数来获取整型的 socket 选项值。
   - 定义了 `Linger`, `sysLinger`, `IPMreq`, `IPv6Mreq` 等结构体，用于设置不同的 socket 选项。**注意代码中 `Linger` 结构体的注释，说明其定义可能不适合直接使用，推荐使用 `SetsockoptLinger`。**

6. **GUID (全局唯一标识符) 操作:**
   - 提供了 `GUIDFromString` 函数将字符串转换为 `GUID`。
   - 提供了 `GenerateGUID` 函数生成新的 `GUID`。
   - 为 `GUID` 类型提供了 `String` 方法，将其转换为字符串表示。

7. **已知文件夹路径:**
   - 提供了 `KnownFolderPath` 函数，用于获取 Windows 中预定义的特殊文件夹的路径（例如文档、程序数据等）。

8. **操作系统版本信息:**
   - 提供了 `RtlGetVersion` 和 `RtlGetNtVersionNumbers` 函数，用于获取更底层的操作系统版本信息。

9. **用户界面语言:**
   - 提供了 `GetProcessPreferredUILanguages`, `GetThreadPreferredUILanguages`, `GetUserPreferredUILanguages`, `GetSystemPreferredUILanguages` 等函数，用于获取不同级别的首选用户界面语言。

10. **控制台操作:**
    - 提供了 `SetConsoleCursorPosition` 函数来设置控制台光标的位置。
    - 提供了 `CreatePseudoConsole` 和 `ResizePseudoConsole` 函数，用于创建和调整伪控制台的大小。

11. **进程启动信息:**
    - 提供了 `GetStartupInfo` 函数来获取进程的启动信息。

12. **NTSTATUS 错误处理:**
    - 定义了 `NTStatus` 类型，用于表示 Windows NT 系统级的错误代码。
    - 提供了 `Errno` 和 `Error` 方法，用于将 `NTStatus` 转换为 `syscall.Errno` 和可读的错误字符串。

13. **Windows 字符串处理:**
    - 提供了 `NewNTUnicodeString` 和 `NewNTString` 函数，用于创建 Windows NT 风格的 Unicode 和 ANSI 字符串结构。
    - 为 `NTUnicodeString` 和 `NTString` 提供了 `Slice` 和 `String` 方法，方便访问和转换字符串数据。

14. **资源管理:**
    - 提供了 `FindResource` 和 `LoadResourceData` 函数，用于查找和加载模块（如 DLL 或 EXE 文件）中嵌入的资源。

15. **进程工作集信息:**
    - 定义了 `PSAPI_WORKING_SET_EX_BLOCK` 和 `PSAPI_WORKING_SET_EX_INFORMATION` 结构体，用于获取进程内存页的详细信息。

16. **串口通信常量:**
    - 定义了一些用于串口通信配置的常量，如波特率 (`CBR_...`)、数据终端就绪 (DTR) 控制 (`DTR_CONTROL_...`)、请求发送 (RTS) 控制 (`RTS_CONTROL_...`)、奇偶校验 (`NOPARITY`, `ODDPARITY`, ...)、停止位 (`ONESTOPBIT`, `TWOSTOPBITS`)，以及用于控制串口的转义函数 (`SETXOFF`, `SETXON`, ...) 和清除串口缓冲区 (`PURGE_TXABORT`, `PURGE_RXABORT`, ...) 的常量。

**Go 语言功能的实现示例 (代码推理):**

**假设要实现获取当前进程 ID 的功能:**

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

// 假设这是从提供的代码片段中获取的定义
// func GetCurrentProcessId() (pid uint32) // 实际实现可能在其他地方

func main() {
	pid := getCurrentProcessId() // 调用 syscall_windows.go 中实现的函数
	fmt.Printf("Current process ID: %d\n", pid)
}

// 模拟 syscall_windows.go 中 GetCurrentProcessId 的定义 (实际实现应该通过 syscall.Syscall0 调用 Windows API)
func getCurrentProcessId() uint32 {
	// 这里只是一个模拟，实际实现会调用 Windows API
	// 假设 Windows API 返回的值是 1234
	return 1234
}

// 假设的输出:
// Current process ID: 1234
```

**假设要实现枚举进程的功能:**

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

// 假设这是从提供的代码片段中获取的定义
// func EnumProcesses(processIds []uint32, bytesReturned *uint32) error // 实际实现可能在其他地方

func main() {
	processIds := make([]uint32, 1024) // 预分配一个较大的 slice
	var bytesReturned uint32
	err := enumProcesses(processIds, &bytesReturned)
	if err != nil {
		fmt.Println("Error enumerating processes:", err)
		return
	}

	numProcesses := bytesReturned / unsafe.Sizeof(processIds[0])
	fmt.Printf("Number of processes: %d\n", numProcesses)
	fmt.Println("Process IDs:")
	for i := 0; i < int(numProcesses); i++ {
		fmt.Println(processIds[i])
	}
}

// 模拟 syscall_windows.go 中 EnumProcesses 的定义
func enumProcesses(processIds []uint32, bytesReturned *uint32) error {
	// 模拟返回一些进程 ID
	if len(processIds) >= 3 {
		processIds[0] = 100
		processIds[1] = 200
		processIds[2] = 300
		*bytesReturned = uint32(3 * unsafe.Sizeof(processIds[0]))
	} else {
		*bytesReturned = 0
	}
	return nil
}

// 假设的输出:
// Number of processes: 3
// Process IDs:
// 100
// 200
// 300
```

**命令行参数处理:**

这段代码本身并没有直接处理命令行参数。它主要是提供底层系统调用的封装。命令行参数的处理通常发生在更上层的应用代码中，这些应用代码可能会使用 `os` 包或其他库来解析命令行参数，并基于这些参数调用 `syscall` 包提供的功能。

**使用者易犯错的点:**

1. **`Linger` 结构体的误用:**  代码中明确注释了 `Linger` 结构体的定义可能不适合直接用于 `Setsockopt` 和 `Getsockopt`，建议使用 `SetsockoptLinger`。直接使用 `Linger` 可能会导致数据结构不匹配，从而引发错误。

   ```go
   // 错误用法示例
   // var linger syscall.Linger{Onoff: 1, Linger: 1}
   // syscall.Setsockopt(socketFD, syscall.SOL_SOCKET, syscall.SO_LINGER, unsafe.Pointer(&linger), unsafe.Sizeof(linger))

   // 正确用法示例
   var linger syscall.Linger{Onoff: 1, Linger: 1}
   syscall.SetsockoptLinger(socketFD, syscall.SOL_SOCKET, syscall.SO_LINGER, &linger)
   ```

2. **`Win32finddata` 结构体的误用:**  `FindFirstFile` 和 `FindNextFile` 函数内部使用了 `win32finddata1` 结构体，而不是 `Win32finddata`。直接使用 `Win32finddata` 并假设其内存布局与 Windows API 完全一致可能会导致数据读取错误。

   ```go
   // 应该使用提供的封装函数，而不是直接操作底层的结构体
   namePtr, err := syscall.UTF16PtrFromString("*")
   if err != nil {
       // ...
   }
   var findData syscall.Win32finddata
   h, err := syscall.FindFirstFile(namePtr, &findData)
   if h != syscall.InvalidHandle {
       defer syscall.FindClose(h)
       for {
           // 使用 findData
           err = syscall.FindNextFile(h, &findData)
           if err != nil {
               break
           }
       }
   }
   ```

总而言之，这段代码是 Go 语言在 Windows 平台上实现底层系统调用的重要组成部分，它为 Go 语言程序提供了与 Windows 操作系统内核交互的能力，从而支持更高级的功能和抽象。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/windows/syscall_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
return err
}

func WSARecvMsg(fd Handle, msg *WSAMsg, bytesReceived *uint32, overlapped *Overlapped, croutine *byte) error {
	err := loadWSASendRecvMsg()
	if err != nil {
		return err
	}
	r1, _, e1 := syscall.Syscall6(sendRecvMsgFunc.recvAddr, 5, uintptr(fd), uintptr(unsafe.Pointer(msg)), uintptr(unsafe.Pointer(bytesReceived)), uintptr(unsafe.Pointer(overlapped)), uintptr(unsafe.Pointer(croutine)), 0)
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return err
}

// Invented structures to support what package os expects.
type Rusage struct {
	CreationTime Filetime
	ExitTime     Filetime
	KernelTime   Filetime
	UserTime     Filetime
}

type WaitStatus struct {
	ExitCode uint32
}

func (w WaitStatus) Exited() bool { return true }

func (w WaitStatus) ExitStatus() int { return int(w.ExitCode) }

func (w WaitStatus) Signal() Signal { return -1 }

func (w WaitStatus) CoreDump() bool { return false }

func (w WaitStatus) Stopped() bool { return false }

func (w WaitStatus) Continued() bool { return false }

func (w WaitStatus) StopSignal() Signal { return -1 }

func (w WaitStatus) Signaled() bool { return false }

func (w WaitStatus) TrapCause() int { return -1 }

// Timespec is an invented structure on Windows, but here for
// consistency with the corresponding package for other operating systems.
type Timespec struct {
	Sec  int64
	Nsec int64
}

func TimespecToNsec(ts Timespec) int64 { return int64(ts.Sec)*1e9 + int64(ts.Nsec) }

func NsecToTimespec(nsec int64) (ts Timespec) {
	ts.Sec = nsec / 1e9
	ts.Nsec = nsec % 1e9
	return
}

// TODO(brainman): fix all needed for net

func Accept(fd Handle) (nfd Handle, sa Sockaddr, err error) { return 0, nil, syscall.EWINDOWS }

func Recvfrom(fd Handle, p []byte, flags int) (n int, from Sockaddr, err error) {
	var rsa RawSockaddrAny
	l := int32(unsafe.Sizeof(rsa))
	n32, err := recvfrom(fd, p, int32(flags), &rsa, &l)
	n = int(n32)
	if err != nil {
		return
	}
	from, err = rsa.Sockaddr()
	return
}

func Sendto(fd Handle, p []byte, flags int, to Sockaddr) (err error) {
	ptr, l, err := to.sockaddr()
	if err != nil {
		return err
	}
	return sendto(fd, p, int32(flags), ptr, l)
}

func SetsockoptTimeval(fd Handle, level, opt int, tv *Timeval) (err error) { return syscall.EWINDOWS }

// The Linger struct is wrong but we only noticed after Go 1.
// sysLinger is the real system call structure.

// BUG(brainman): The definition of Linger is not appropriate for direct use
// with Setsockopt and Getsockopt.
// Use SetsockoptLinger instead.

type Linger struct {
	Onoff  int32
	Linger int32
}

type sysLinger struct {
	Onoff  uint16
	Linger uint16
}

type IPMreq struct {
	Multiaddr [4]byte /* in_addr */
	Interface [4]byte /* in_addr */
}

type IPv6Mreq struct {
	Multiaddr [16]byte /* in6_addr */
	Interface uint32
}

func GetsockoptInt(fd Handle, level, opt int) (int, error) {
	v := int32(0)
	l := int32(unsafe.Sizeof(v))
	err := Getsockopt(fd, int32(level), int32(opt), (*byte)(unsafe.Pointer(&v)), &l)
	return int(v), err
}

func SetsockoptLinger(fd Handle, level, opt int, l *Linger) (err error) {
	sys := sysLinger{Onoff: uint16(l.Onoff), Linger: uint16(l.Linger)}
	return Setsockopt(fd, int32(level), int32(opt), (*byte)(unsafe.Pointer(&sys)), int32(unsafe.Sizeof(sys)))
}

func SetsockoptInet4Addr(fd Handle, level, opt int, value [4]byte) (err error) {
	return Setsockopt(fd, int32(level), int32(opt), (*byte)(unsafe.Pointer(&value[0])), 4)
}

func SetsockoptIPMreq(fd Handle, level, opt int, mreq *IPMreq) (err error) {
	return Setsockopt(fd, int32(level), int32(opt), (*byte)(unsafe.Pointer(mreq)), int32(unsafe.Sizeof(*mreq)))
}

func SetsockoptIPv6Mreq(fd Handle, level, opt int, mreq *IPv6Mreq) (err error) {
	return syscall.EWINDOWS
}

func EnumProcesses(processIds []uint32, bytesReturned *uint32) error {
	// EnumProcesses syscall expects the size parameter to be in bytes, but the code generated with mksyscall uses
	// the length of the processIds slice instead. Hence, this wrapper function is added to fix the discrepancy.
	var p *uint32
	if len(processIds) > 0 {
		p = &processIds[0]
	}
	size := uint32(len(processIds) * 4)
	return enumProcesses(p, size, bytesReturned)
}

func Getpid() (pid int) { return int(GetCurrentProcessId()) }

func FindFirstFile(name *uint16, data *Win32finddata) (handle Handle, err error) {
	// NOTE(rsc): The Win32finddata struct is wrong for the system call:
	// the two paths are each one uint16 short. Use the correct struct,
	// a win32finddata1, and then copy the results out.
	// There is no loss of expressivity here, because the final
	// uint16, if it is used, is supposed to be a NUL, and Go doesn't need that.
	// For Go 1.1, we might avoid the allocation of win32finddata1 here
	// by adding a final Bug [2]uint16 field to the struct and then
	// adjusting the fields in the result directly.
	var data1 win32finddata1
	handle, err = findFirstFile1(name, &data1)
	if err == nil {
		copyFindData(data, &data1)
	}
	return
}

func FindNextFile(handle Handle, data *Win32finddata) (err error) {
	var data1 win32finddata1
	err = findNextFile1(handle, &data1)
	if err == nil {
		copyFindData(data, &data1)
	}
	return
}

func getProcessEntry(pid int) (*ProcessEntry32, error) {
	snapshot, err := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer CloseHandle(snapshot)
	var procEntry ProcessEntry32
	procEntry.Size = uint32(unsafe.Sizeof(procEntry))
	if err = Process32First(snapshot, &procEntry); err != nil {
		return nil, err
	}
	for {
		if procEntry.ProcessID == uint32(pid) {
			return &procEntry, nil
		}
		err = Process32Next(snapshot, &procEntry)
		if err != nil {
			return nil, err
		}
	}
}

func Getppid() (ppid int) {
	pe, err := getProcessEntry(Getpid())
	if err != nil {
		return -1
	}
	return int(pe.ParentProcessID)
}

// TODO(brainman): fix all needed for os
func Fchdir(fd Handle) (err error)             { return syscall.EWINDOWS }
func Link(oldpath, newpath string) (err error) { return syscall.EWINDOWS }
func Symlink(path, link string) (err error)    { return syscall.EWINDOWS }

func Fchmod(fd Handle, mode uint32) (err error)        { return syscall.EWINDOWS }
func Chown(path string, uid int, gid int) (err error)  { return syscall.EWINDOWS }
func Lchown(path string, uid int, gid int) (err error) { return syscall.EWINDOWS }
func Fchown(fd Handle, uid int, gid int) (err error)   { return syscall.EWINDOWS }

func Getuid() (uid int)                  { return -1 }
func Geteuid() (euid int)                { return -1 }
func Getgid() (gid int)                  { return -1 }
func Getegid() (egid int)                { return -1 }
func Getgroups() (gids []int, err error) { return nil, syscall.EWINDOWS }

type Signal int

func (s Signal) Signal() {}

func (s Signal) String() string {
	if 0 <= s && int(s) < len(signals) {
		str := signals[s]
		if str != "" {
			return str
		}
	}
	return "signal " + itoa(int(s))
}

func LoadCreateSymbolicLink() error {
	return procCreateSymbolicLinkW.Find()
}

// Readlink returns the destination of the named symbolic link.
func Readlink(path string, buf []byte) (n int, err error) {
	fd, err := CreateFile(StringToUTF16Ptr(path), GENERIC_READ, 0, nil, OPEN_EXISTING,
		FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return -1, err
	}
	defer CloseHandle(fd)

	rdbbuf := make([]byte, MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
	var bytesReturned uint32
	err = DeviceIoControl(fd, FSCTL_GET_REPARSE_POINT, nil, 0, &rdbbuf[0], uint32(len(rdbbuf)), &bytesReturned, nil)
	if err != nil {
		return -1, err
	}

	rdb := (*reparseDataBuffer)(unsafe.Pointer(&rdbbuf[0]))
	var s string
	switch rdb.ReparseTag {
	case IO_REPARSE_TAG_SYMLINK:
		data := (*symbolicLinkReparseBuffer)(unsafe.Pointer(&rdb.reparseBuffer))
		p := (*[0xffff]uint16)(unsafe.Pointer(&data.PathBuffer[0]))
		s = UTF16ToString(p[data.PrintNameOffset/2 : (data.PrintNameLength-data.PrintNameOffset)/2])
	case IO_REPARSE_TAG_MOUNT_POINT:
		data := (*mountPointReparseBuffer)(unsafe.Pointer(&rdb.reparseBuffer))
		p := (*[0xffff]uint16)(unsafe.Pointer(&data.PathBuffer[0]))
		s = UTF16ToString(p[data.PrintNameOffset/2 : (data.PrintNameLength-data.PrintNameOffset)/2])
	default:
		// the path is not a symlink or junction but another type of reparse
		// point
		return -1, syscall.ENOENT
	}
	n = copy(buf, []byte(s))

	return n, nil
}

// GUIDFromString parses a string in the form of
// "{XXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}" into a GUID.
func GUIDFromString(str string) (GUID, error) {
	guid := GUID{}
	str16, err := syscall.UTF16PtrFromString(str)
	if err != nil {
		return guid, err
	}
	err = clsidFromString(str16, &guid)
	if err != nil {
		return guid, err
	}
	return guid, nil
}

// GenerateGUID creates a new random GUID.
func GenerateGUID() (GUID, error) {
	guid := GUID{}
	err := coCreateGuid(&guid)
	if err != nil {
		return guid, err
	}
	return guid, nil
}

// String returns the canonical string form of the GUID,
// in the form of "{XXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}".
func (guid GUID) String() string {
	var str [100]uint16
	chars := stringFromGUID2(&guid, &str[0], int32(len(str)))
	if chars <= 1 {
		return ""
	}
	return string(utf16.Decode(str[:chars-1]))
}

// KnownFolderPath returns a well-known folder path for the current user, specified by one of
// the FOLDERID_ constants, and chosen and optionally created based on a KF_ flag.
func KnownFolderPath(folderID *KNOWNFOLDERID, flags uint32) (string, error) {
	return Token(0).KnownFolderPath(folderID, flags)
}

// KnownFolderPath returns a well-known folder path for the user token, specified by one of
// the FOLDERID_ constants, and chosen and optionally created based on a KF_ flag.
func (t Token) KnownFolderPath(folderID *KNOWNFOLDERID, flags uint32) (string, error) {
	var p *uint16
	err := shGetKnownFolderPath(folderID, flags, t, &p)
	if err != nil {
		return "", err
	}
	defer CoTaskMemFree(unsafe.Pointer(p))
	return UTF16PtrToString(p), nil
}

// RtlGetVersion returns the version of the underlying operating system, ignoring
// manifest semantics but is affected by the application compatibility layer.
func RtlGetVersion() *OsVersionInfoEx {
	info := &OsVersionInfoEx{}
	info.osVersionInfoSize = uint32(unsafe.Sizeof(*info))
	// According to documentation, this function always succeeds.
	// The function doesn't even check the validity of the
	// osVersionInfoSize member. Disassembling ntdll.dll indicates
	// that the documentation is indeed correct about that.
	_ = rtlGetVersion(info)
	return info
}

// RtlGetNtVersionNumbers returns the version of the underlying operating system,
// ignoring manifest semantics and the application compatibility layer.
func RtlGetNtVersionNumbers() (majorVersion, minorVersion, buildNumber uint32) {
	rtlGetNtVersionNumbers(&majorVersion, &minorVersion, &buildNumber)
	buildNumber &= 0xffff
	return
}

// GetProcessPreferredUILanguages retrieves the process preferred UI languages.
func GetProcessPreferredUILanguages(flags uint32) ([]string, error) {
	return getUILanguages(flags, getProcessPreferredUILanguages)
}

// GetThreadPreferredUILanguages retrieves the thread preferred UI languages for the current thread.
func GetThreadPreferredUILanguages(flags uint32) ([]string, error) {
	return getUILanguages(flags, getThreadPreferredUILanguages)
}

// GetUserPreferredUILanguages retrieves information about the user preferred UI languages.
func GetUserPreferredUILanguages(flags uint32) ([]string, error) {
	return getUILanguages(flags, getUserPreferredUILanguages)
}

// GetSystemPreferredUILanguages retrieves the system preferred UI languages.
func GetSystemPreferredUILanguages(flags uint32) ([]string, error) {
	return getUILanguages(flags, getSystemPreferredUILanguages)
}

func getUILanguages(flags uint32, f func(flags uint32, numLanguages *uint32, buf *uint16, bufSize *uint32) error) ([]string, error) {
	size := uint32(128)
	for {
		var numLanguages uint32
		buf := make([]uint16, size)
		err := f(flags, &numLanguages, &buf[0], &size)
		if err == ERROR_INSUFFICIENT_BUFFER {
			continue
		}
		if err != nil {
			return nil, err
		}
		buf = buf[:size]
		if numLanguages == 0 || len(buf) == 0 { // GetProcessPreferredUILanguages may return numLanguages==0 with "\0\0"
			return []string{}, nil
		}
		if buf[len(buf)-1] == 0 {
			buf = buf[:len(buf)-1] // remove terminating null
		}
		languages := make([]string, 0, numLanguages)
		from := 0
		for i, c := range buf {
			if c == 0 {
				languages = append(languages, string(utf16.Decode(buf[from:i])))
				from = i + 1
			}
		}
		return languages, nil
	}
}

func SetConsoleCursorPosition(console Handle, position Coord) error {
	return setConsoleCursorPosition(console, *((*uint32)(unsafe.Pointer(&position))))
}

func GetStartupInfo(startupInfo *StartupInfo) error {
	getStartupInfo(startupInfo)
	return nil
}

func (s NTStatus) Errno() syscall.Errno {
	return rtlNtStatusToDosErrorNoTeb(s)
}

func langID(pri, sub uint16) uint32 { return uint32(sub)<<10 | uint32(pri) }

func (s NTStatus) Error() string {
	b := make([]uint16, 300)
	n, err := FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_FROM_HMODULE|FORMAT_MESSAGE_ARGUMENT_ARRAY, modntdll.Handle(), uint32(s), langID(LANG_ENGLISH, SUBLANG_ENGLISH_US), b, nil)
	if err != nil {
		return fmt.Sprintf("NTSTATUS 0x%08x", uint32(s))
	}
	// trim terminating \r and \n
	for ; n > 0 && (b[n-1] == '\n' || b[n-1] == '\r'); n-- {
	}
	return string(utf16.Decode(b[:n]))
}

// NewNTUnicodeString returns a new NTUnicodeString structure for use with native
// NT APIs that work over the NTUnicodeString type. Note that most Windows APIs
// do not use NTUnicodeString, and instead UTF16PtrFromString should be used for
// the more common *uint16 string type.
func NewNTUnicodeString(s string) (*NTUnicodeString, error) {
	s16, err := UTF16FromString(s)
	if err != nil {
		return nil, err
	}
	n := uint16(len(s16) * 2)
	return &NTUnicodeString{
		Length:        n - 2, // subtract 2 bytes for the NULL terminator
		MaximumLength: n,
		Buffer:        &s16[0],
	}, nil
}

// Slice returns a uint16 slice that aliases the data in the NTUnicodeString.
func (s *NTUnicodeString) Slice() []uint16 {
	slice := unsafe.Slice(s.Buffer, s.MaximumLength)
	return slice[:s.Length]
}

func (s *NTUnicodeString) String() string {
	return UTF16ToString(s.Slice())
}

// NewNTString returns a new NTString structure for use with native
// NT APIs that work over the NTString type. Note that most Windows APIs
// do not use NTString, and instead UTF16PtrFromString should be used for
// the more common *uint16 string type.
func NewNTString(s string) (*NTString, error) {
	var nts NTString
	s8, err := BytePtrFromString(s)
	if err != nil {
		return nil, err
	}
	RtlInitString(&nts, s8)
	return &nts, nil
}

// Slice returns a byte slice that aliases the data in the NTString.
func (s *NTString) Slice() []byte {
	slice := unsafe.Slice(s.Buffer, s.MaximumLength)
	return slice[:s.Length]
}

func (s *NTString) String() string {
	return ByteSliceToString(s.Slice())
}

// FindResource resolves a resource of the given name and resource type.
func FindResource(module Handle, name, resType ResourceIDOrString) (Handle, error) {
	var namePtr, resTypePtr uintptr
	var name16, resType16 *uint16
	var err error
	resolvePtr := func(i interface{}, keep **uint16) (uintptr, error) {
		switch v := i.(type) {
		case string:
			*keep, err = UTF16PtrFromString(v)
			if err != nil {
				return 0, err
			}
			return uintptr(unsafe.Pointer(*keep)), nil
		case ResourceID:
			return uintptr(v), nil
		}
		return 0, errorspkg.New("parameter must be a ResourceID or a string")
	}
	namePtr, err = resolvePtr(name, &name16)
	if err != nil {
		return 0, err
	}
	resTypePtr, err = resolvePtr(resType, &resType16)
	if err != nil {
		return 0, err
	}
	resInfo, err := findResource(module, namePtr, resTypePtr)
	runtime.KeepAlive(name16)
	runtime.KeepAlive(resType16)
	return resInfo, err
}

func LoadResourceData(module, resInfo Handle) (data []byte, err error) {
	size, err := SizeofResource(module, resInfo)
	if err != nil {
		return
	}
	resData, err := LoadResource(module, resInfo)
	if err != nil {
		return
	}
	ptr, err := LockResource(resData)
	if err != nil {
		return
	}
	data = unsafe.Slice((*byte)(unsafe.Pointer(ptr)), size)
	return
}

// PSAPI_WORKING_SET_EX_BLOCK contains extended working set information for a page.
type PSAPI_WORKING_SET_EX_BLOCK uint64

// Valid returns the validity of this page.
// If this bit is 1, the subsequent members are valid; otherwise they should be ignored.
func (b PSAPI_WORKING_SET_EX_BLOCK) Valid() bool {
	return (b & 1) == 1
}

// ShareCount is the number of processes that share this page. The maximum value of this member is 7.
func (b PSAPI_WORKING_SET_EX_BLOCK) ShareCount() uint64 {
	return b.intField(1, 3)
}

// Win32Protection is the memory protection attributes of the page. For a list of values, see
// https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
func (b PSAPI_WORKING_SET_EX_BLOCK) Win32Protection() uint64 {
	return b.intField(4, 11)
}

// Shared returns the shared status of this page.
// If this bit is 1, the page can be shared.
func (b PSAPI_WORKING_SET_EX_BLOCK) Shared() bool {
	return (b & (1 << 15)) == 1
}

// Node is the NUMA node. The maximum value of this member is 63.
func (b PSAPI_WORKING_SET_EX_BLOCK) Node() uint64 {
	return b.intField(16, 6)
}

// Locked returns the locked status of this page.
// If this bit is 1, the virtual page is locked in physical memory.
func (b PSAPI_WORKING_SET_EX_BLOCK) Locked() bool {
	return (b & (1 << 22)) == 1
}

// LargePage returns the large page status of this page.
// If this bit is 1, the page is a large page.
func (b PSAPI_WORKING_SET_EX_BLOCK) LargePage() bool {
	return (b & (1 << 23)) == 1
}

// Bad returns the bad status of this page.
// If this bit is 1, the page is has been reported as bad.
func (b PSAPI_WORKING_SET_EX_BLOCK) Bad() bool {
	return (b & (1 << 31)) == 1
}

// intField extracts an integer field in the PSAPI_WORKING_SET_EX_BLOCK union.
func (b PSAPI_WORKING_SET_EX_BLOCK) intField(start, length int) uint64 {
	var mask PSAPI_WORKING_SET_EX_BLOCK
	for pos := start; pos < start+length; pos++ {
		mask |= (1 << pos)
	}

	masked := b & mask
	return uint64(masked >> start)
}

// PSAPI_WORKING_SET_EX_INFORMATION contains extended working set information for a process.
type PSAPI_WORKING_SET_EX_INFORMATION struct {
	// The virtual address.
	VirtualAddress Pointer
	// A PSAPI_WORKING_SET_EX_BLOCK union that indicates the attributes of the page at VirtualAddress.
	VirtualAttributes PSAPI_WORKING_SET_EX_BLOCK
}

// CreatePseudoConsole creates a windows pseudo console.
func CreatePseudoConsole(size Coord, in Handle, out Handle, flags uint32, pconsole *Handle) error {
	// We need this wrapper to manually cast Coord to uint32. The autogenerated wrappers only
	// accept arguments that can be casted to uintptr, and Coord can't.
	return createPseudoConsole(*((*uint32)(unsafe.Pointer(&size))), in, out, flags, pconsole)
}

// ResizePseudoConsole resizes the internal buffers of the pseudo console to the width and height specified in `size`.
func ResizePseudoConsole(pconsole Handle, size Coord) error {
	// We need this wrapper to manually cast Coord to uint32. The autogenerated wrappers only
	// accept arguments that can be casted to uintptr, and Coord can't.
	return resizePseudoConsole(pconsole, *((*uint32)(unsafe.Pointer(&size))))
}

// DCB constants. See https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-dcb.
const (
	CBR_110    = 110
	CBR_300    = 300
	CBR_600    = 600
	CBR_1200   = 1200
	CBR_2400   = 2400
	CBR_4800   = 4800
	CBR_9600   = 9600
	CBR_14400  = 14400
	CBR_19200  = 19200
	CBR_38400  = 38400
	CBR_57600  = 57600
	CBR_115200 = 115200
	CBR_128000 = 128000
	CBR_256000 = 256000

	DTR_CONTROL_DISABLE   = 0x00000000
	DTR_CONTROL_ENABLE    = 0x00000010
	DTR_CONTROL_HANDSHAKE = 0x00000020

	RTS_CONTROL_DISABLE   = 0x00000000
	RTS_CONTROL_ENABLE    = 0x00001000
	RTS_CONTROL_HANDSHAKE = 0x00002000
	RTS_CONTROL_TOGGLE    = 0x00003000

	NOPARITY    = 0
	ODDPARITY   = 1
	EVENPARITY  = 2
	MARKPARITY  = 3
	SPACEPARITY = 4

	ONESTOPBIT   = 0
	ONE5STOPBITS = 1
	TWOSTOPBITS  = 2
)

// EscapeCommFunction constants. See https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-escapecommfunction.
const (
	SETXOFF  = 1
	SETXON   = 2
	SETRTS   = 3
	CLRRTS   = 4
	SETDTR   = 5
	CLRDTR   = 6
	SETBREAK = 8
	CLRBREAK = 9
)

// PurgeComm constants. See https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-purgecomm.
const (
	PURGE_TXABORT = 0x0001
	PURGE_RXABORT = 0x0002
	PURGE_TXCLEAR = 0x0004
	PURGE_RXCLEAR = 0x0008
)

// SetCommMask constants. See https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setcommmask.
const (
	EV_RXCHAR  = 0x0001
	EV_RXFLAG  = 0x0002
	EV_TXEMPTY = 0x0004
	EV_CTS     = 0x0008
	EV_DSR     = 0x0010
	EV_RLSD    = 0x0020
	EV_BREAK   = 0x0040
	EV_ERR     = 0x0080
	EV_RING    = 0x0100
)
```