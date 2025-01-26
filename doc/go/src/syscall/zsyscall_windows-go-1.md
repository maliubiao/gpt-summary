Response:
The user wants a summary of the functionalities provided by the Go code snippet. This is the second part of a two-part code listing. I need to identify the main categories of operations performed by the functions in this part. Looking at the function names, they appear to be primarily interacting with the Windows operating system kernel through syscalls.

Here's a possible breakdown of functionalities:
1. **Process Management:** Getting process ID, exit code, process times, opening/terminating processes.
2. **Environment Variables:** Getting and setting environment variables and strings.
3. **File System Operations:** Getting file attributes, information, full/short/long paths, creating/removing directories, reading/writing files, moving files, setting file pointers and times, locking/unlocking files.
4. **Handles:**  Operations related to handles, like getting standard handles and setting handle information.
5. **Memory Management:** Mapping and unmapping views of files, allocating and freeing local memory.
6. **Synchronization:** Getting queued completion status, posting queued completion status, waiting for single objects.
7. **Console Operations:** Reading and writing to the console.
8. **Module/Library Loading:** Loading libraries and getting procedure addresses.
9. **Time and Date:** Getting system time and timezone information.
10. **User Information:** Getting user profile directory, username.
11. **Network related operations (Winsock):**  Functions for socket creation, binding, listening, connecting, sending/receiving data, getting host/protocol/service information, and other Winsock specific operations.
这是 `go/src/syscall/zsyscall_windows.go` 文件的一部分，它定义了 Go 语言在 Windows 操作系统上进行系统调用的底层接口。 这个第二部分主要包含以下功能：

1. **进程管理相关:**
    - `getCurrentProcessId()`: 获取当前进程的 ID。
    - `GetExitCodeProcess(handle Handle, exitcode *uint32)`: 获取指定进程的退出码。
    - `OpenProcess(da uint32, inheritHandle bool, pid uint32)`:  打开一个已存在的进程并返回其句柄。
    - `TerminateProcess(handle Handle, exitcode uint32)`: 终止指定的进程。
    - `GetProcessTimes(handle Handle, creationTime *Filetime, exitTime *Filetime, kernelTime *Filetime, userTime *Filetime)`: 获取指定进程的时间信息，包括创建时间、退出时间、内核时间和用户时间。
    - `Process32First(snapshot Handle, procEntry *ProcessEntry32)`: 获取系统快照中第一个进程的信息。
    - `Process32Next(snapshot Handle, procEntry *ProcessEntry32)`: 获取系统快照中下一个进程的信息。

2. **环境变量相关:**
    - `GetEnvironmentStrings()`: 获取当前进程的环境变量字符串。
    - `GetEnvironmentVariable(name *uint16, buffer *uint16, size uint32)`: 获取指定名称的环境变量的值。
    - `SetEnvironmentVariable(name *uint16, value *uint16)`: 设置指定名称的环境变量的值。

3. **文件系统相关:**
    - `GetFileAttributesEx(name *uint16, level uint32, info *byte)`: 获取文件的扩展属性信息。
    - `GetFileAttributes(name *uint16)`: 获取文件的属性。
    - `GetFileInformationByHandle(handle Handle, data *ByHandleFileInformation)`: 通过文件句柄获取文件的详细信息。
    - `GetFileType(filehandle Handle)`: 获取文件句柄指向的文件类型。
    - `getFinalPathNameByHandle(file Handle, filePath *uint16, filePathSize uint32, flags uint32)`: 通过文件句柄获取文件的最终路径名。
    - `GetFullPathName(path *uint16, buflen uint32, buf *uint16, fname **uint16)`: 获取指定路径的完整路径名。
    - `GetLongPathName(path *uint16, buf *uint16, buflen uint32)`: 获取指定路径的长路径名。
    - `GetShortPathName(longpath *uint16, shortpath *uint16, buflen uint32)`: 获取指定路径的短路径名。
    - `GetTempPath(buflen uint32, buf *uint16)`: 获取系统临时文件夹的路径。
    - `MoveFile(from *uint16, to *uint16)`: 移动文件或目录。
    - `RemoveDirectory(path *uint16)`: 删除一个空目录。
    - `SetCurrentDirectory(path *uint16)`: 设置当前进程的当前工作目录。
    - `SetEndOfFile(handle Handle)`: 将指定文件的文件指针设置为文件末尾，从而截断文件。
    - `SetFileAttributes(name *uint16, attrs uint32)`: 设置文件的属性。
    - `setFileInformationByHandle(handle Handle, fileInformationClass uint32, buf unsafe.Pointer, bufsize uint32)`: 通过文件句柄设置文件的信息。
    - `SetFilePointer(handle Handle, lowoffset int32, highoffsetptr *int32, whence uint32)`: 设置文件的读写指针。
    - `SetFileTime(handle Handle, ctime *Filetime, atime *Filetime, wtime *Filetime)`: 设置文件的创建时间、访问时间和写入时间。
    - `readFile(handle Handle, buf []byte, done *uint32, overlapped *Overlapped)`: 从文件中读取数据。
    - `writeFile(handle Handle, buf []byte, done *uint32, overlapped *Overlapped)`: 向文件中写入数据。
    - `ReadDirectoryChanges(handle Handle, buf *byte, buflen uint32, watchSubTree bool, mask uint32, retlen *uint32, overlapped *Overlapped, completionRoutine uintptr)`: 监视目录的更改。

4. **句柄操作相关:**
    - `GetStdHandle(stdhandle int)`: 获取标准输入、输出或错误流的句柄。
    - `SetHandleInformation(handle Handle, mask uint32, flags uint32)`: 设置句柄的特定属性。
    - `CloseHandle(handle Handle)`: 关闭一个打开的对象句柄。（虽然这里没有直接列出，但在第一部分中存在，属于相关的操作）

5. **内存管理相关:**
    - `MapViewOfFile(handle Handle, access uint32, offsetHigh uint32, offsetLow uint32, length uintptr)`: 将文件的一部分映射到进程的地址空间。
    - `UnmapViewOfFile(addr uintptr)`: 取消文件到进程地址空间的映射。
    - `LocalFree(hmem Handle)`: 释放本地分配的内存。
    - `VirtualLock(addr uintptr, length uintptr)`: 将指定内存区域锁定在物理内存中。
    - `VirtualUnlock(addr uintptr, length uintptr)`: 解锁之前锁定的内存区域。

6. **同步相关:**
    - `getQueuedCompletionStatus(cphandle Handle, qty *uint32, key *uintptr, overlapped **Overlapped, timeout uint32)`: 等待完成端口的 I/O 操作完成。
    - `postQueuedCompletionStatus(cphandle Handle, qty uint32, key uintptr, overlapped *Overlapped)`: 向完成端口投递一个完成包。
    - `WaitForSingleObject(handle Handle, waitMilliseconds uint32)`: 等待指定的内核对象变为 signaled 状态。

7. **控制台操作相关:**
    - `ReadConsole(console Handle, buf *uint16, toread uint32, read *uint32, inputControl *byte)`: 从控制台读取输入。
    - `WriteConsole(console Handle, buf *uint16, towrite uint32, written *uint32, reserved *byte)`: 向控制台写入输出。

8. **动态链接库 (DLL) 相关:**
    - `LoadLibrary(libname string)`: 加载指定的动态链接库到进程的地址空间。
    - `_LoadLibrary(libname *uint16)`: `LoadLibrary` 的底层实现，接受 UTF-16 编码的库名。
    - `GetProcAddress(module Handle, procname string)`: 获取指定 DLL 中导出函数的地址。
    - `_GetProcAddress(module Handle, procname *byte)`: `GetProcAddress` 的底层实现，接受 ANSI 编码的函数名。

9. **时间相关:**
    - `GetSystemTimeAsFileTime(time *Filetime)`: 获取当前系统时间，以 FILETIME 结构表示。
    - `GetTimeZoneInformation(tzi *Timezoneinformation)`: 获取当前时区信息。
    - `GetVersion()`: 获取当前操作系统的版本号。

10. **进程和线程属性相关:**
    - `initializeProcThreadAttributeList(attrlist *_PROC_THREAD_ATTRIBUTE_LIST, attrcount uint32, flags uint32, size *uintptr)`: 初始化进程或线程属性列表。
    - `updateProcThreadAttribute(attrlist *_PROC_THREAD_ATTRIBUTE_LIST, flags uint32, attr uintptr, value unsafe.Pointer, size uintptr, prevvalue unsafe.Pointer, returnedsize *uintptr)`: 更新进程或线程属性列表中的属性。

11. **网络相关 (Winsock):**
    - `AcceptEx(ls Handle, as Handle, buf *byte, rxdatalen uint32, laddrlen uint32, raddrlen uint32, recvd *uint32, overlapped *Overlapped)`:  接受传入的连接请求，并允许在接受操作中接收数据。
    - `GetAcceptExSockaddrs(buf *byte, rxdatalen uint32, laddrlen uint32, raddrlen uint32, lrsa **RawSockaddrAny, lrsalen *int32, rrsa **RawSockaddrAny, rrsalen *int32)`: 从 `AcceptEx` 函数接收缓冲区中获取本地和远程地址信息。
    - `TransmitFile(s Handle, handle Handle, bytesToWrite uint32, bytsPerSend uint32, overlapped *Overlapped, transmitFileBuf *TransmitFileBuffers, flags uint32)`: 通过套接字传输文件。
    - `NetApiBufferFree(buf *byte)`: 释放通过 Net API 函数分配的缓冲区。
    - `NetGetJoinInformation(server *uint16, name **uint16, bufType *uint32)`: 获取计算机加入域或工作组的信息。
    - `NetUserGetInfo(serverName *uint16, userName *uint16, level uint32, buf **byte)`: 获取指定用户的账户信息。
    - `GetUserNameEx(nameFormat uint32, nameBuffre *uint16, nSize *uint32)`: 获取各种格式的用户名。
    - `TranslateName(accName *uint16, accNameFormat uint32, desiredNameFormat uint32, translatedName *uint16, nSize *uint32)`: 将一种格式的帐户名转换为另一种格式。
    - `CommandLineToArgv(cmd *uint16, argc *int32)`: 将命令行字符串解析为参数数组。
    - `GetUserProfileDirectory(t Token, dir *uint16, dirLen *uint32)`: 获取指定用户的用户配置文件目录。
    - `FreeAddrInfoW(addrinfo *AddrinfoW)`: 释放 `GetAddrInfoW` 函数返回的地址信息结构。
    - `GetAddrInfoW(nodename *uint16, servicename *uint16, hints *AddrinfoW, result **AddrinfoW)`: 将主机名或服务名转换为套接字地址信息。
    - `WSACleanup()`: 清理 Winsock 库。
    - `WSAEnumProtocols(protocols *int32, protocolBuffer *WSAProtocolInfo, bufferLength *uint32)`: 枚举可用的 Winsock 协议。
    - `WSAIoctl(s Handle, iocc uint32, inbuf *byte, cbif uint32, outbuf *byte, cbob uint32, cbbr *uint32, overlapped *Overlapped, completionRoutine uintptr)`:  对套接字执行 I/O 控制命令。
    - `WSARecv(s Handle, bufs *WSABuf, bufcnt uint32, recvd *uint32, flags *uint32, overlapped *Overlapped, croutine *byte)`: 从套接字接收数据。
    - `WSARecvFrom(s Handle, bufs *WSABuf, bufcnt uint32, recvd *uint32, flags *uint32, from *RawSockaddrAny, fromlen *int32, overlapped *Overlapped, croutine *byte)`: 从套接字接收数据，并获取发送端的地址信息。
    - `WSASend(s Handle, bufs *WSABuf, bufcnt uint32, sent *uint32, flags uint32, overlapped *Overlapped, croutine *byte)`: 通过套接字发送数据。
    - `WSASendTo(s Handle, bufs *WSABuf, bufcnt uint32, sent *uint32, flags uint32, to *RawSockaddrAny, tolen int32, overlapped *Overlapped, croutine *byte)`: 通过套接字发送数据到指定的地址。
    - `WSAStartup(verreq uint32, data *WSAData)`: 初始化 Winsock 库。
    - `bind(s Handle, name unsafe.Pointer, namelen int32)`: 将本地地址与套接字关联。
    - `Closesocket(s Handle)`: 关闭一个套接字。
    - `connect(s Handle, name unsafe.Pointer, namelen int32)`: 与指定的地址建立连接。
    - `GetHostByName(name string)`: 根据主机名获取主机信息。
    - `_GetHostByName(name *byte)`: `GetHostByName` 的底层实现。
    - `getpeername(s Handle, rsa *RawSockaddrAny, addrlen *int32)`: 获取连接到套接字的对端的地址。
    - `GetProtoByName(name string)`: 根据协议名称获取协议信息。
    - `_GetProtoByName(name *byte)`: `GetProtoByName` 的底层实现。
    - `GetServByName(name string, proto string)`: 根据服务名称和协议获取服务信息。
    - `_GetServByName(name *byte, proto *byte)`: `GetServByName` 的底层实现。
    - `getsockname(s Handle, rsa *RawSockaddrAny, addrlen *int32)`: 获取与套接字关联的本地地址。
    - `Getsockopt(s Handle, level int32, optname int32, optval *byte, optlen *int32)`: 获取套接字的选项值。
    - `listen(s Handle, backlog int32)`: 监听传入的连接请求。
    - `Ntohs(netshort uint16)`: 将网络字节序的 short 类型转换为主机字节序。
    - `Setsockopt(s Handle, level int32, optname int32, optval *byte, optlen int32)`: 设置套接字的选项值。
    - `shutdown(s Handle, how int32)`: 关闭套接字的发送或接收操作。
    - `socket(af int32, typ int32, protocol int32)`: 创建一个套接字。

**归纳一下它的功能:**

这个代码片段是 Go 语言 `syscall` 包在 Windows 平台上的核心部分，它通过直接调用 Windows API 实现了与操作系统内核的交互。  其主要功能是为 Go 程序提供访问 Windows 系统底层功能的能力，包括进程管理、文件系统操作、内存管理、同步机制、控制台交互、动态库加载以及网络编程 (Winsock) 等等。  它扮演着 Go 运行时与 Windows 操作系统之间的桥梁角色。

Prompt: 
```
这是路径为go/src/syscall/zsyscall_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
 0)
	pseudoHandle = Handle(r0)
	if pseudoHandle == 0 {
		err = errnoErr(e1)
	}
	return
}

func getCurrentProcessId() (pid uint32) {
	r0, _, _ := Syscall(procGetCurrentProcessId.Addr(), 0, 0, 0, 0)
	pid = uint32(r0)
	return
}

func GetEnvironmentStrings() (envs *uint16, err error) {
	r0, _, e1 := Syscall(procGetEnvironmentStringsW.Addr(), 0, 0, 0, 0)
	envs = (*uint16)(unsafe.Pointer(r0))
	if envs == nil {
		err = errnoErr(e1)
	}
	return
}

func GetEnvironmentVariable(name *uint16, buffer *uint16, size uint32) (n uint32, err error) {
	r0, _, e1 := Syscall(procGetEnvironmentVariableW.Addr(), 3, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(buffer)), uintptr(size))
	n = uint32(r0)
	if n == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetExitCodeProcess(handle Handle, exitcode *uint32) (err error) {
	r1, _, e1 := Syscall(procGetExitCodeProcess.Addr(), 2, uintptr(handle), uintptr(unsafe.Pointer(exitcode)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetFileAttributesEx(name *uint16, level uint32, info *byte) (err error) {
	r1, _, e1 := Syscall(procGetFileAttributesExW.Addr(), 3, uintptr(unsafe.Pointer(name)), uintptr(level), uintptr(unsafe.Pointer(info)))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetFileAttributes(name *uint16) (attrs uint32, err error) {
	r0, _, e1 := Syscall(procGetFileAttributesW.Addr(), 1, uintptr(unsafe.Pointer(name)), 0, 0)
	attrs = uint32(r0)
	if attrs == INVALID_FILE_ATTRIBUTES {
		err = errnoErr(e1)
	}
	return
}

func GetFileInformationByHandle(handle Handle, data *ByHandleFileInformation) (err error) {
	r1, _, e1 := Syscall(procGetFileInformationByHandle.Addr(), 2, uintptr(handle), uintptr(unsafe.Pointer(data)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetFileType(filehandle Handle) (n uint32, err error) {
	r0, _, e1 := Syscall(procGetFileType.Addr(), 1, uintptr(filehandle), 0, 0)
	n = uint32(r0)
	if n == 0 {
		err = errnoErr(e1)
	}
	return
}

func getFinalPathNameByHandle(file Handle, filePath *uint16, filePathSize uint32, flags uint32) (n uint32, err error) {
	r0, _, e1 := Syscall6(procGetFinalPathNameByHandleW.Addr(), 4, uintptr(file), uintptr(unsafe.Pointer(filePath)), uintptr(filePathSize), uintptr(flags), 0, 0)
	n = uint32(r0)
	if n == 0 || n >= filePathSize {
		err = errnoErr(e1)
	}
	return
}

func GetFullPathName(path *uint16, buflen uint32, buf *uint16, fname **uint16) (n uint32, err error) {
	r0, _, e1 := Syscall6(procGetFullPathNameW.Addr(), 4, uintptr(unsafe.Pointer(path)), uintptr(buflen), uintptr(unsafe.Pointer(buf)), uintptr(unsafe.Pointer(fname)), 0, 0)
	n = uint32(r0)
	if n == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetLastError() (lasterr error) {
	r0, _, _ := Syscall(procGetLastError.Addr(), 0, 0, 0, 0)
	if r0 != 0 {
		lasterr = Errno(r0)
	}
	return
}

func GetLongPathName(path *uint16, buf *uint16, buflen uint32) (n uint32, err error) {
	r0, _, e1 := Syscall(procGetLongPathNameW.Addr(), 3, uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(buf)), uintptr(buflen))
	n = uint32(r0)
	if n == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetProcAddress(module Handle, procname string) (proc uintptr, err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(procname)
	if err != nil {
		return
	}
	return _GetProcAddress(module, _p0)
}

func _GetProcAddress(module Handle, procname *byte) (proc uintptr, err error) {
	r0, _, e1 := Syscall(procGetProcAddress.Addr(), 2, uintptr(module), uintptr(unsafe.Pointer(procname)), 0)
	proc = uintptr(r0)
	if proc == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetProcessTimes(handle Handle, creationTime *Filetime, exitTime *Filetime, kernelTime *Filetime, userTime *Filetime) (err error) {
	r1, _, e1 := Syscall6(procGetProcessTimes.Addr(), 5, uintptr(handle), uintptr(unsafe.Pointer(creationTime)), uintptr(unsafe.Pointer(exitTime)), uintptr(unsafe.Pointer(kernelTime)), uintptr(unsafe.Pointer(userTime)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func getQueuedCompletionStatus(cphandle Handle, qty *uint32, key *uintptr, overlapped **Overlapped, timeout uint32) (err error) {
	r1, _, e1 := Syscall6(procGetQueuedCompletionStatus.Addr(), 5, uintptr(cphandle), uintptr(unsafe.Pointer(qty)), uintptr(unsafe.Pointer(key)), uintptr(unsafe.Pointer(overlapped)), uintptr(timeout), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetShortPathName(longpath *uint16, shortpath *uint16, buflen uint32) (n uint32, err error) {
	r0, _, e1 := Syscall(procGetShortPathNameW.Addr(), 3, uintptr(unsafe.Pointer(longpath)), uintptr(unsafe.Pointer(shortpath)), uintptr(buflen))
	n = uint32(r0)
	if n == 0 {
		err = errnoErr(e1)
	}
	return
}

func getStartupInfo(startupInfo *StartupInfo) {
	Syscall(procGetStartupInfoW.Addr(), 1, uintptr(unsafe.Pointer(startupInfo)), 0, 0)
	return
}

func GetStdHandle(stdhandle int) (handle Handle, err error) {
	r0, _, e1 := Syscall(procGetStdHandle.Addr(), 1, uintptr(stdhandle), 0, 0)
	handle = Handle(r0)
	if handle == InvalidHandle {
		err = errnoErr(e1)
	}
	return
}

func GetSystemTimeAsFileTime(time *Filetime) {
	Syscall(procGetSystemTimeAsFileTime.Addr(), 1, uintptr(unsafe.Pointer(time)), 0, 0)
	return
}

func GetTempPath(buflen uint32, buf *uint16) (n uint32, err error) {
	r0, _, e1 := Syscall(procGetTempPathW.Addr(), 2, uintptr(buflen), uintptr(unsafe.Pointer(buf)), 0)
	n = uint32(r0)
	if n == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetTimeZoneInformation(tzi *Timezoneinformation) (rc uint32, err error) {
	r0, _, e1 := Syscall(procGetTimeZoneInformation.Addr(), 1, uintptr(unsafe.Pointer(tzi)), 0, 0)
	rc = uint32(r0)
	if rc == 0xffffffff {
		err = errnoErr(e1)
	}
	return
}

func GetVersion() (ver uint32, err error) {
	r0, _, e1 := Syscall(procGetVersion.Addr(), 0, 0, 0, 0)
	ver = uint32(r0)
	if ver == 0 {
		err = errnoErr(e1)
	}
	return
}

func initializeProcThreadAttributeList(attrlist *_PROC_THREAD_ATTRIBUTE_LIST, attrcount uint32, flags uint32, size *uintptr) (err error) {
	r1, _, e1 := Syscall6(procInitializeProcThreadAttributeList.Addr(), 4, uintptr(unsafe.Pointer(attrlist)), uintptr(attrcount), uintptr(flags), uintptr(unsafe.Pointer(size)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func LoadLibrary(libname string) (handle Handle, err error) {
	var _p0 *uint16
	_p0, err = UTF16PtrFromString(libname)
	if err != nil {
		return
	}
	return _LoadLibrary(_p0)
}

func _LoadLibrary(libname *uint16) (handle Handle, err error) {
	r0, _, e1 := Syscall(procLoadLibraryW.Addr(), 1, uintptr(unsafe.Pointer(libname)), 0, 0)
	handle = Handle(r0)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return
}

func LocalFree(hmem Handle) (handle Handle, err error) {
	r0, _, e1 := Syscall(procLocalFree.Addr(), 1, uintptr(hmem), 0, 0)
	handle = Handle(r0)
	if handle != 0 {
		err = errnoErr(e1)
	}
	return
}

func MapViewOfFile(handle Handle, access uint32, offsetHigh uint32, offsetLow uint32, length uintptr) (addr uintptr, err error) {
	r0, _, e1 := Syscall6(procMapViewOfFile.Addr(), 5, uintptr(handle), uintptr(access), uintptr(offsetHigh), uintptr(offsetLow), uintptr(length), 0)
	addr = uintptr(r0)
	if addr == 0 {
		err = errnoErr(e1)
	}
	return
}

func MoveFile(from *uint16, to *uint16) (err error) {
	r1, _, e1 := Syscall(procMoveFileW.Addr(), 2, uintptr(unsafe.Pointer(from)), uintptr(unsafe.Pointer(to)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func OpenProcess(da uint32, inheritHandle bool, pid uint32) (handle Handle, err error) {
	var _p0 uint32
	if inheritHandle {
		_p0 = 1
	}
	r0, _, e1 := Syscall(procOpenProcess.Addr(), 3, uintptr(da), uintptr(_p0), uintptr(pid))
	handle = Handle(r0)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return
}

func postQueuedCompletionStatus(cphandle Handle, qty uint32, key uintptr, overlapped *Overlapped) (err error) {
	r1, _, e1 := Syscall6(procPostQueuedCompletionStatus.Addr(), 4, uintptr(cphandle), uintptr(qty), uintptr(key), uintptr(unsafe.Pointer(overlapped)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func Process32First(snapshot Handle, procEntry *ProcessEntry32) (err error) {
	r1, _, e1 := Syscall(procProcess32FirstW.Addr(), 2, uintptr(snapshot), uintptr(unsafe.Pointer(procEntry)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func Process32Next(snapshot Handle, procEntry *ProcessEntry32) (err error) {
	r1, _, e1 := Syscall(procProcess32NextW.Addr(), 2, uintptr(snapshot), uintptr(unsafe.Pointer(procEntry)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func ReadConsole(console Handle, buf *uint16, toread uint32, read *uint32, inputControl *byte) (err error) {
	r1, _, e1 := Syscall6(procReadConsoleW.Addr(), 5, uintptr(console), uintptr(unsafe.Pointer(buf)), uintptr(toread), uintptr(unsafe.Pointer(read)), uintptr(unsafe.Pointer(inputControl)), 0)
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
	r1, _, e1 := Syscall9(procReadDirectoryChangesW.Addr(), 8, uintptr(handle), uintptr(unsafe.Pointer(buf)), uintptr(buflen), uintptr(_p0), uintptr(mask), uintptr(unsafe.Pointer(retlen)), uintptr(unsafe.Pointer(overlapped)), uintptr(completionRoutine), 0)
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
	r1, _, e1 := Syscall6(procReadFile.Addr(), 5, uintptr(handle), uintptr(unsafe.Pointer(_p0)), uintptr(len(buf)), uintptr(unsafe.Pointer(done)), uintptr(unsafe.Pointer(overlapped)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func RemoveDirectory(path *uint16) (err error) {
	r1, _, e1 := Syscall(procRemoveDirectoryW.Addr(), 1, uintptr(unsafe.Pointer(path)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetCurrentDirectory(path *uint16) (err error) {
	r1, _, e1 := Syscall(procSetCurrentDirectoryW.Addr(), 1, uintptr(unsafe.Pointer(path)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetEndOfFile(handle Handle) (err error) {
	r1, _, e1 := Syscall(procSetEndOfFile.Addr(), 1, uintptr(handle), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetEnvironmentVariable(name *uint16, value *uint16) (err error) {
	r1, _, e1 := Syscall(procSetEnvironmentVariableW.Addr(), 2, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(value)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetFileAttributes(name *uint16, attrs uint32) (err error) {
	r1, _, e1 := Syscall(procSetFileAttributesW.Addr(), 2, uintptr(unsafe.Pointer(name)), uintptr(attrs), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetFileCompletionNotificationModes(handle Handle, flags uint8) (err error) {
	r1, _, e1 := Syscall(procSetFileCompletionNotificationModes.Addr(), 2, uintptr(handle), uintptr(flags), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func setFileInformationByHandle(handle Handle, fileInformationClass uint32, buf unsafe.Pointer, bufsize uint32) (err error) {
	r1, _, e1 := Syscall6(procSetFileInformationByHandle.Addr(), 4, uintptr(handle), uintptr(fileInformationClass), uintptr(buf), uintptr(bufsize), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetFilePointer(handle Handle, lowoffset int32, highoffsetptr *int32, whence uint32) (newlowoffset uint32, err error) {
	r0, _, e1 := Syscall6(procSetFilePointer.Addr(), 4, uintptr(handle), uintptr(lowoffset), uintptr(unsafe.Pointer(highoffsetptr)), uintptr(whence), 0, 0)
	newlowoffset = uint32(r0)
	if newlowoffset == 0xffffffff {
		err = errnoErr(e1)
	}
	return
}

func SetFileTime(handle Handle, ctime *Filetime, atime *Filetime, wtime *Filetime) (err error) {
	r1, _, e1 := Syscall6(procSetFileTime.Addr(), 4, uintptr(handle), uintptr(unsafe.Pointer(ctime)), uintptr(unsafe.Pointer(atime)), uintptr(unsafe.Pointer(wtime)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetHandleInformation(handle Handle, mask uint32, flags uint32) (err error) {
	r1, _, e1 := Syscall(procSetHandleInformation.Addr(), 3, uintptr(handle), uintptr(mask), uintptr(flags))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func TerminateProcess(handle Handle, exitcode uint32) (err error) {
	r1, _, e1 := Syscall(procTerminateProcess.Addr(), 2, uintptr(handle), uintptr(exitcode), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func UnmapViewOfFile(addr uintptr) (err error) {
	r1, _, e1 := Syscall(procUnmapViewOfFile.Addr(), 1, uintptr(addr), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func updateProcThreadAttribute(attrlist *_PROC_THREAD_ATTRIBUTE_LIST, flags uint32, attr uintptr, value unsafe.Pointer, size uintptr, prevvalue unsafe.Pointer, returnedsize *uintptr) (err error) {
	r1, _, e1 := Syscall9(procUpdateProcThreadAttribute.Addr(), 7, uintptr(unsafe.Pointer(attrlist)), uintptr(flags), uintptr(attr), uintptr(value), uintptr(size), uintptr(prevvalue), uintptr(unsafe.Pointer(returnedsize)), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func VirtualLock(addr uintptr, length uintptr) (err error) {
	r1, _, e1 := Syscall(procVirtualLock.Addr(), 2, uintptr(addr), uintptr(length), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func VirtualUnlock(addr uintptr, length uintptr) (err error) {
	r1, _, e1 := Syscall(procVirtualUnlock.Addr(), 2, uintptr(addr), uintptr(length), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func WaitForSingleObject(handle Handle, waitMilliseconds uint32) (event uint32, err error) {
	r0, _, e1 := Syscall(procWaitForSingleObject.Addr(), 2, uintptr(handle), uintptr(waitMilliseconds), 0)
	event = uint32(r0)
	if event == 0xffffffff {
		err = errnoErr(e1)
	}
	return
}

func WriteConsole(console Handle, buf *uint16, towrite uint32, written *uint32, reserved *byte) (err error) {
	r1, _, e1 := Syscall6(procWriteConsoleW.Addr(), 5, uintptr(console), uintptr(unsafe.Pointer(buf)), uintptr(towrite), uintptr(unsafe.Pointer(written)), uintptr(unsafe.Pointer(reserved)), 0)
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
	r1, _, e1 := Syscall6(procWriteFile.Addr(), 5, uintptr(handle), uintptr(unsafe.Pointer(_p0)), uintptr(len(buf)), uintptr(unsafe.Pointer(done)), uintptr(unsafe.Pointer(overlapped)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func AcceptEx(ls Handle, as Handle, buf *byte, rxdatalen uint32, laddrlen uint32, raddrlen uint32, recvd *uint32, overlapped *Overlapped) (err error) {
	r1, _, e1 := Syscall9(procAcceptEx.Addr(), 8, uintptr(ls), uintptr(as), uintptr(unsafe.Pointer(buf)), uintptr(rxdatalen), uintptr(laddrlen), uintptr(raddrlen), uintptr(unsafe.Pointer(recvd)), uintptr(unsafe.Pointer(overlapped)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetAcceptExSockaddrs(buf *byte, rxdatalen uint32, laddrlen uint32, raddrlen uint32, lrsa **RawSockaddrAny, lrsalen *int32, rrsa **RawSockaddrAny, rrsalen *int32) {
	Syscall9(procGetAcceptExSockaddrs.Addr(), 8, uintptr(unsafe.Pointer(buf)), uintptr(rxdatalen), uintptr(laddrlen), uintptr(raddrlen), uintptr(unsafe.Pointer(lrsa)), uintptr(unsafe.Pointer(lrsalen)), uintptr(unsafe.Pointer(rrsa)), uintptr(unsafe.Pointer(rrsalen)), 0)
	return
}

func TransmitFile(s Handle, handle Handle, bytesToWrite uint32, bytsPerSend uint32, overlapped *Overlapped, transmitFileBuf *TransmitFileBuffers, flags uint32) (err error) {
	r1, _, e1 := Syscall9(procTransmitFile.Addr(), 7, uintptr(s), uintptr(handle), uintptr(bytesToWrite), uintptr(bytsPerSend), uintptr(unsafe.Pointer(overlapped)), uintptr(unsafe.Pointer(transmitFileBuf)), uintptr(flags), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func NetApiBufferFree(buf *byte) (neterr error) {
	r0, _, _ := Syscall(procNetApiBufferFree.Addr(), 1, uintptr(unsafe.Pointer(buf)), 0, 0)
	if r0 != 0 {
		neterr = Errno(r0)
	}
	return
}

func NetGetJoinInformation(server *uint16, name **uint16, bufType *uint32) (neterr error) {
	r0, _, _ := Syscall(procNetGetJoinInformation.Addr(), 3, uintptr(unsafe.Pointer(server)), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(bufType)))
	if r0 != 0 {
		neterr = Errno(r0)
	}
	return
}

func NetUserGetInfo(serverName *uint16, userName *uint16, level uint32, buf **byte) (neterr error) {
	r0, _, _ := Syscall6(procNetUserGetInfo.Addr(), 4, uintptr(unsafe.Pointer(serverName)), uintptr(unsafe.Pointer(userName)), uintptr(level), uintptr(unsafe.Pointer(buf)), 0, 0)
	if r0 != 0 {
		neterr = Errno(r0)
	}
	return
}

func GetUserNameEx(nameFormat uint32, nameBuffre *uint16, nSize *uint32) (err error) {
	r1, _, e1 := Syscall(procGetUserNameExW.Addr(), 3, uintptr(nameFormat), uintptr(unsafe.Pointer(nameBuffre)), uintptr(unsafe.Pointer(nSize)))
	if r1&0xff == 0 {
		err = errnoErr(e1)
	}
	return
}

func TranslateName(accName *uint16, accNameFormat uint32, desiredNameFormat uint32, translatedName *uint16, nSize *uint32) (err error) {
	r1, _, e1 := Syscall6(procTranslateNameW.Addr(), 5, uintptr(unsafe.Pointer(accName)), uintptr(accNameFormat), uintptr(desiredNameFormat), uintptr(unsafe.Pointer(translatedName)), uintptr(unsafe.Pointer(nSize)), 0)
	if r1&0xff == 0 {
		err = errnoErr(e1)
	}
	return
}

func CommandLineToArgv(cmd *uint16, argc *int32) (argv *[8192]*[8192]uint16, err error) {
	r0, _, e1 := Syscall(procCommandLineToArgvW.Addr(), 2, uintptr(unsafe.Pointer(cmd)), uintptr(unsafe.Pointer(argc)), 0)
	argv = (*[8192]*[8192]uint16)(unsafe.Pointer(r0))
	if argv == nil {
		err = errnoErr(e1)
	}
	return
}

func GetUserProfileDirectory(t Token, dir *uint16, dirLen *uint32) (err error) {
	r1, _, e1 := Syscall(procGetUserProfileDirectoryW.Addr(), 3, uintptr(t), uintptr(unsafe.Pointer(dir)), uintptr(unsafe.Pointer(dirLen)))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func FreeAddrInfoW(addrinfo *AddrinfoW) {
	Syscall(procFreeAddrInfoW.Addr(), 1, uintptr(unsafe.Pointer(addrinfo)), 0, 0)
	return
}

func GetAddrInfoW(nodename *uint16, servicename *uint16, hints *AddrinfoW, result **AddrinfoW) (sockerr error) {
	r0, _, _ := Syscall6(procGetAddrInfoW.Addr(), 4, uintptr(unsafe.Pointer(nodename)), uintptr(unsafe.Pointer(servicename)), uintptr(unsafe.Pointer(hints)), uintptr(unsafe.Pointer(result)), 0, 0)
	if r0 != 0 {
		sockerr = Errno(r0)
	}
	return
}

func WSACleanup() (err error) {
	r1, _, e1 := Syscall(procWSACleanup.Addr(), 0, 0, 0, 0)
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func WSAEnumProtocols(protocols *int32, protocolBuffer *WSAProtocolInfo, bufferLength *uint32) (n int32, err error) {
	r0, _, e1 := Syscall(procWSAEnumProtocolsW.Addr(), 3, uintptr(unsafe.Pointer(protocols)), uintptr(unsafe.Pointer(protocolBuffer)), uintptr(unsafe.Pointer(bufferLength)))
	n = int32(r0)
	if n == -1 {
		err = errnoErr(e1)
	}
	return
}

func WSAIoctl(s Handle, iocc uint32, inbuf *byte, cbif uint32, outbuf *byte, cbob uint32, cbbr *uint32, overlapped *Overlapped, completionRoutine uintptr) (err error) {
	r1, _, e1 := Syscall9(procWSAIoctl.Addr(), 9, uintptr(s), uintptr(iocc), uintptr(unsafe.Pointer(inbuf)), uintptr(cbif), uintptr(unsafe.Pointer(outbuf)), uintptr(cbob), uintptr(unsafe.Pointer(cbbr)), uintptr(unsafe.Pointer(overlapped)), uintptr(completionRoutine))
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func WSARecv(s Handle, bufs *WSABuf, bufcnt uint32, recvd *uint32, flags *uint32, overlapped *Overlapped, croutine *byte) (err error) {
	r1, _, e1 := Syscall9(procWSARecv.Addr(), 7, uintptr(s), uintptr(unsafe.Pointer(bufs)), uintptr(bufcnt), uintptr(unsafe.Pointer(recvd)), uintptr(unsafe.Pointer(flags)), uintptr(unsafe.Pointer(overlapped)), uintptr(unsafe.Pointer(croutine)), 0, 0)
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func WSARecvFrom(s Handle, bufs *WSABuf, bufcnt uint32, recvd *uint32, flags *uint32, from *RawSockaddrAny, fromlen *int32, overlapped *Overlapped, croutine *byte) (err error) {
	r1, _, e1 := Syscall9(procWSARecvFrom.Addr(), 9, uintptr(s), uintptr(unsafe.Pointer(bufs)), uintptr(bufcnt), uintptr(unsafe.Pointer(recvd)), uintptr(unsafe.Pointer(flags)), uintptr(unsafe.Pointer(from)), uintptr(unsafe.Pointer(fromlen)), uintptr(unsafe.Pointer(overlapped)), uintptr(unsafe.Pointer(croutine)))
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func WSASend(s Handle, bufs *WSABuf, bufcnt uint32, sent *uint32, flags uint32, overlapped *Overlapped, croutine *byte) (err error) {
	r1, _, e1 := Syscall9(procWSASend.Addr(), 7, uintptr(s), uintptr(unsafe.Pointer(bufs)), uintptr(bufcnt), uintptr(unsafe.Pointer(sent)), uintptr(flags), uintptr(unsafe.Pointer(overlapped)), uintptr(unsafe.Pointer(croutine)), 0, 0)
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func WSASendTo(s Handle, bufs *WSABuf, bufcnt uint32, sent *uint32, flags uint32, to *RawSockaddrAny, tolen int32, overlapped *Overlapped, croutine *byte) (err error) {
	r1, _, e1 := Syscall9(procWSASendTo.Addr(), 9, uintptr(s), uintptr(unsafe.Pointer(bufs)), uintptr(bufcnt), uintptr(unsafe.Pointer(sent)), uintptr(flags), uintptr(unsafe.Pointer(to)), uintptr(tolen), uintptr(unsafe.Pointer(overlapped)), uintptr(unsafe.Pointer(croutine)))
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func WSAStartup(verreq uint32, data *WSAData) (sockerr error) {
	r0, _, _ := Syscall(procWSAStartup.Addr(), 2, uintptr(verreq), uintptr(unsafe.Pointer(data)), 0)
	if r0 != 0 {
		sockerr = Errno(r0)
	}
	return
}

func bind(s Handle, name unsafe.Pointer, namelen int32) (err error) {
	r1, _, e1 := Syscall(procbind.Addr(), 3, uintptr(s), uintptr(name), uintptr(namelen))
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func Closesocket(s Handle) (err error) {
	r1, _, e1 := Syscall(procclosesocket.Addr(), 1, uintptr(s), 0, 0)
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func connect(s Handle, name unsafe.Pointer, namelen int32) (err error) {
	r1, _, e1 := Syscall(procconnect.Addr(), 3, uintptr(s), uintptr(name), uintptr(namelen))
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func GetHostByName(name string) (h *Hostent, err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(name)
	if err != nil {
		return
	}
	return _GetHostByName(_p0)
}

func _GetHostByName(name *byte) (h *Hostent, err error) {
	r0, _, e1 := Syscall(procgethostbyname.Addr(), 1, uintptr(unsafe.Pointer(name)), 0, 0)
	h = (*Hostent)(unsafe.Pointer(r0))
	if h == nil {
		err = errnoErr(e1)
	}
	return
}

func getpeername(s Handle, rsa *RawSockaddrAny, addrlen *int32) (err error) {
	r1, _, e1 := Syscall(procgetpeername.Addr(), 3, uintptr(s), uintptr(unsafe.Pointer(rsa)), uintptr(unsafe.Pointer(addrlen)))
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func GetProtoByName(name string) (p *Protoent, err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(name)
	if err != nil {
		return
	}
	return _GetProtoByName(_p0)
}

func _GetProtoByName(name *byte) (p *Protoent, err error) {
	r0, _, e1 := Syscall(procgetprotobyname.Addr(), 1, uintptr(unsafe.Pointer(name)), 0, 0)
	p = (*Protoent)(unsafe.Pointer(r0))
	if p == nil {
		err = errnoErr(e1)
	}
	return
}

func GetServByName(name string, proto string) (s *Servent, err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(name)
	if err != nil {
		return
	}
	var _p1 *byte
	_p1, err = BytePtrFromString(proto)
	if err != nil {
		return
	}
	return _GetServByName(_p0, _p1)
}

func _GetServByName(name *byte, proto *byte) (s *Servent, err error) {
	r0, _, e1 := Syscall(procgetservbyname.Addr(), 2, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(proto)), 0)
	s = (*Servent)(unsafe.Pointer(r0))
	if s == nil {
		err = errnoErr(e1)
	}
	return
}

func getsockname(s Handle, rsa *RawSockaddrAny, addrlen *int32) (err error) {
	r1, _, e1 := Syscall(procgetsockname.Addr(), 3, uintptr(s), uintptr(unsafe.Pointer(rsa)), uintptr(unsafe.Pointer(addrlen)))
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func Getsockopt(s Handle, level int32, optname int32, optval *byte, optlen *int32) (err error) {
	r1, _, e1 := Syscall6(procgetsockopt.Addr(), 5, uintptr(s), uintptr(level), uintptr(optname), uintptr(unsafe.Pointer(optval)), uintptr(unsafe.Pointer(optlen)), 0)
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func listen(s Handle, backlog int32) (err error) {
	r1, _, e1 := Syscall(proclisten.Addr(), 2, uintptr(s), uintptr(backlog), 0)
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func Ntohs(netshort uint16) (u uint16) {
	r0, _, _ := Syscall(procntohs.Addr(), 1, uintptr(netshort), 0, 0)
	u = uint16(r0)
	return
}

func Setsockopt(s Handle, level int32, optname int32, optval *byte, optlen int32) (err error) {
	r1, _, e1 := Syscall6(procsetsockopt.Addr(), 5, uintptr(s), uintptr(level), uintptr(optname), uintptr(unsafe.Pointer(optval)), uintptr(optlen), 0)
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func shutdown(s Handle, how int32) (err error) {
	r1, _, e1 := Syscall(procshutdown.Addr(), 2, uintptr(s), uintptr(how), 0)
	if r1 == socket_error {
		err = errnoErr(e1)
	}
	return
}

func socket(af int32, typ int32, protocol int32) (handle Handle, err error) {
	r0, _, e1 := Syscall(procsocket.Addr(), 3, uintptr(af), uintptr(typ), uintptr(protocol))
	handle = Handle(r0)
	if handle == InvalidHandle {
		err = errnoErr(e1)
	}
	return
}

"""




```