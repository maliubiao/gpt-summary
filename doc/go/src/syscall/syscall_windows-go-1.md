Response:
The user wants a summary of the functionalities present in the provided Go code snippet from `syscall_windows.go`. Since this is part 2 of the request, the summary should build upon the summary generated for part 1 (though I don't have access to part 1's content). The focus should be on the functions, data structures, and overall purpose as inferred from the code.

Here's a breakdown of the key elements to consider:

1. **Network Functions:**  Identify functions related to network operations like `Bind`, `Connect`, `Listen`, `Accept`, `Sendto`, `Recvfrom`, `Getsockname`, `Getpeername`, `Shutdown`, `Setsockopt`, `Getsockopt`, `GetAddrInfoW`, `FreeAddrInfoW`, `WSAEnumProtocols`, and Windows-specific `WSASendto`, `ConnectEx`, `LoadConnectEx`, `LoadGetAddrInfo`.

2. **Socket Address Structures:** Recognize the definitions of `Sockaddr`, `SockaddrInet4`, `SockaddrInet6`, `SockaddrUnix`, and their raw counterparts. Note their role in representing network addresses.

3. **File and Directory Operations:** Look for functions related to file system interactions such as `FindFirstFile`, `FindNextFile`, `fdpath`, `Fchdir`, `Link`, `Symlink`, `Readlink`.

4. **Process and Thread Management:** Identify functions like `Getpid`, `Getppid`, `getProcessEntry`, `CreateToolhelp32Snapshot`, `Process32First`, `Process32Next`, `newProcThreadAttributeList`, `GetStartupInfo`.

5. **Synchronization Primitives:**  Notice the use of `sync.Once` in `LoadConnectEx`.

6. **I/O Completion Ports:**  Identify functions like `CreateIoCompletionPort`, `GetQueuedCompletionStatus`, `PostQueuedCompletionStatus`. Recognize the deprecation warnings.

7. **Registry Operations:** See the `RegEnumKeyEx` function.

8. **Error Handling:** Observe the use of `error` as a return type and the handling of Windows-specific error codes.

9. **Constants and Data Structures:** Note definitions like `RawSockaddrInet4`, `RawSockaddrInet6`, `RawSockaddr`, `RawSockaddrAny`, `MibIfRow`, `IpAdapterInfo`, `Overlapped`, `WSABuf`, `Filetime`, `Rusage`, `WaitStatus`, `Timespec`, `Linger`, `IPMreq`, `IPv6Mreq`, `Win32finddata`, `ProcessEntry32`, `StartupInfo`, etc.

10. **Internal Helpers:** Identify functions that seem to be internal helpers or wrappers around Windows API calls (prefixed with lowercase names in some cases, or functions like the `sockaddr()` methods on the `Sockaddr` implementations).

**Synthesize the Summary:** Combine these observations into a concise summary of the code's capabilities, focusing on the main categories of functionality. Since this is part 2, avoid repeating what was likely covered in part 1 (e.g., the direct system call mechanism using `//sys`).
这段代码是 `go/src/syscall/syscall_windows.go` 文件的一部分，它主要负责提供 Go 语言在 Windows 平台进行底层系统调用的能力，特别是涉及到网络、文件系统和进程管理的方面。

结合前一部分的内容，我们可以归纳一下这部分代码的功能：

**核心功能归纳：**

1. **网络编程支持增强:**  在前面部分已经提供了基础的 socket 操作（如 `socket`, `bind`, `connect` 等）的基础上，这部分代码进一步提供了更高级和 Windows 特有的网络功能：
    *   **地址解析:**  `GetAddrInfoW` 和 `FreeAddrInfoW` 实现了将主机名和服务名解析为网络地址信息的功能，这对于建立网络连接至关重要。
    *   **发送数据到指定地址:**  `WSASendto` 及其针对 IPv4 和 IPv6 的特定版本 `wsaSendtoInet4` 和 `wsaSendtoInet6` 提供了向指定网络地址发送数据的能力，并且支持使用 `WSABuf` 结构进行 scatter-gather I/O。
    *   **扩展的连接功能:** `ConnectEx` 提供了一种允许在连接建立时发送数据的扩展连接方式，这在某些高性能网络应用中很有用。相关的 `LoadConnectEx` 函数负责动态加载 `ConnectEx` 函数的地址。
    *   **枚举网络协议:** `WSAEnumProtocols` 允许程序获取系统支持的网络协议信息。
    *   **获取网络接口信息:** `GetIfEntry` 和 `GetAdaptersInfo` 用于获取网络接口的详细配置信息。
    *   **设置 Socket 选项:** 提供了 `SetsockoptInt`, `SetsockoptLinger`, `SetsockoptInet4Addr`, `SetsockoptIPMreq` 等函数，用于设置 socket 的各种选项，例如超时、地址重用、IP 组播等。也提供了 `GetsockoptInt` 用于获取 socket 选项的值。
    *   **禁用 IPv6 (测试用):** 包含一个名为 `SocketDisableIPv6` 的变量，用于在测试时强制创建 IPv6 socket 失败。

2. **Socket 地址结构定义和处理:** 定义了多种 `Sockaddr` 接口的实现，用于表示不同类型的网络地址：
    *   `SockaddrInet4`: IPv4 地址
    *   `SockaddrInet6`: IPv6 地址
    *   `SockaddrUnix`: Unix 域 socket 地址
    *   同时定义了对应的原始结构 `RawSockaddrInet4`, `RawSockaddrInet6`, `RawSockaddrUnix` 和通用的 `RawSockaddr`, `RawSockaddrAny`。
    *   每个 `Sockaddr` 实现都有一个 `sockaddr()` 方法，用于将其转换为系统调用所需的指针和长度。
    *   `RawSockaddrAny` 的 `Sockaddr()` 方法则可以将原始的 socket 地址结构转换回对应的 Go `Sockaddr` 接口。

3. **文件系统操作:**  在前面部分提供基础文件操作的基础上，这部分代码提供了更高级的文件系统功能：
    *   **查找文件:** `FindFirstFile` 和 `FindNextFile` 用于查找符合特定模式的文件和目录。
    *   **获取文件路径:** `fdpath` 用于根据文件句柄获取文件的完整路径。
    *   **改变当前工作目录:** `Fchdir` 允许程序根据文件句柄改变当前工作目录。
    *   **创建硬链接和符号链接:** `Link` 和 `Symlink` 用于创建文件系统的链接（但代码中目前返回 `EWINDOWS`，表示未实现或不支持）。
    *   **读取符号链接目标:** `Readlink` 用于获取符号链接指向的实际路径。

4. **进程和线程管理:**  提供了用于获取进程和线程信息的函数：
    *   **获取进程 ID:** `Getpid` 获取当前进程的 ID。
    *   **获取父进程 ID:** `Getppid` 获取当前进程的父进程 ID。
    *   **获取进程信息:** `getProcessEntry` 通过遍历进程快照获取指定进程的详细信息。
    *   **创建进程线程属性列表:** `newProcThreadAttributeList` 用于为创建进程或线程分配属性列表。
    *   **获取进程启动信息:** `GetStartupInfo` 用于获取进程的启动信息。

5. **I/O 完成端口 (IOCP) 支持:** 提供了与 IOCP 相关的函数，用于异步 I/O 操作：
    *   `CreateIoCompletionPort`: 创建一个 I/O 完成端口。
    *   `GetQueuedCompletionStatus`: 从完成端口队列中获取已完成的 I/O 操作状态。
    *   `PostQueuedCompletionStatus`: 向完成端口队列投递一个自定义的完成状态。
    *   **注意：** 这些 `Deprecated` 注释表明这些函数的签名可能存在问题，建议使用 `x/sys/windows` 包中的对应函数。

6. **注册表操作:**  提供了访问 Windows 注册表的功能：
    *   `RegEnumKeyEx`: 枚举注册表键的子键。

7. **其他辅助结构和函数:**
    *   定义了 `Rusage`, `WaitStatus`, `Timespec`, `Linger`, `IPMreq`, `IPv6Mreq` 等结构体，用于与 Windows 系统调用交互。
    *   提供了 `TimespecToNsec` 和 `NsecToTimespec` 用于 `Timespec` 结构和纳秒之间的转换。
    *   定义了 `Signal` 类型及其相关方法，用于表示信号（但 Windows 上的信号处理机制与 Unix-like 系统不同）。
    *   `LoadCreateSymbolicLink` 用于动态加载 `CreateSymbolicLinkW` 函数的地址。
    *   `SetFileCompletionNotificationModes` 用于设置文件完成通知模式。
    *   `DnsQuery_W`, `DnsRecordListFree`, `DnsNameCompare_W` 等函数涉及到 DNS 查询操作。

**总结来说，这部分代码是 `syscall_windows.go` 中处理更高级网络操作、文件系统功能、进程管理以及 Windows 特有的机制（如 IOCP 和注册表访问）的关键组成部分，它构建在前面部分提供的基础系统调用之上，为 Go 语言在 Windows 平台上进行更复杂的系统级编程提供了必要的接口。**

Prompt: 
```
这是路径为go/src/syscall/syscall_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
ing, qtype uint16, options uint32, extra *byte, qrs **DNSRecord, pr *byte) (status error) = dnsapi.DnsQuery_W
//sys	DnsRecordListFree(rl *DNSRecord, freetype uint32) = dnsapi.DnsRecordListFree
//sys	DnsNameCompare(name1 *uint16, name2 *uint16) (same bool) = dnsapi.DnsNameCompare_W
//sys	GetAddrInfoW(nodename *uint16, servicename *uint16, hints *AddrinfoW, result **AddrinfoW) (sockerr error) = ws2_32.GetAddrInfoW
//sys	FreeAddrInfoW(addrinfo *AddrinfoW) = ws2_32.FreeAddrInfoW
//sys	GetIfEntry(pIfRow *MibIfRow) (errcode error) = iphlpapi.GetIfEntry
//sys	GetAdaptersInfo(ai *IpAdapterInfo, ol *uint32) (errcode error) = iphlpapi.GetAdaptersInfo
//sys	SetFileCompletionNotificationModes(handle Handle, flags uint8) (err error) = kernel32.SetFileCompletionNotificationModes
//sys	WSAEnumProtocols(protocols *int32, protocolBuffer *WSAProtocolInfo, bufferLength *uint32) (n int32, err error) [failretval==-1] = ws2_32.WSAEnumProtocolsW

// For testing: clients can set this flag to force
// creation of IPv6 sockets to return [EAFNOSUPPORT].
var SocketDisableIPv6 bool

type RawSockaddrInet4 struct {
	Family uint16
	Port   uint16
	Addr   [4]byte /* in_addr */
	Zero   [8]uint8
}

type RawSockaddrInet6 struct {
	Family   uint16
	Port     uint16
	Flowinfo uint32
	Addr     [16]byte /* in6_addr */
	Scope_id uint32
}

type RawSockaddr struct {
	Family uint16
	Data   [14]int8
}

type RawSockaddrAny struct {
	Addr RawSockaddr
	Pad  [100]int8
}

type Sockaddr interface {
	sockaddr() (ptr unsafe.Pointer, len int32, err error) // lowercase; only we can define Sockaddrs
}

type SockaddrInet4 struct {
	Port int
	Addr [4]byte
	raw  RawSockaddrInet4
}

func (sa *SockaddrInet4) sockaddr() (unsafe.Pointer, int32, error) {
	if sa.Port < 0 || sa.Port > 0xFFFF {
		return nil, 0, EINVAL
	}
	sa.raw.Family = AF_INET
	p := (*[2]byte)(unsafe.Pointer(&sa.raw.Port))
	p[0] = byte(sa.Port >> 8)
	p[1] = byte(sa.Port)
	sa.raw.Addr = sa.Addr
	return unsafe.Pointer(&sa.raw), int32(unsafe.Sizeof(sa.raw)), nil
}

type SockaddrInet6 struct {
	Port   int
	ZoneId uint32
	Addr   [16]byte
	raw    RawSockaddrInet6
}

func (sa *SockaddrInet6) sockaddr() (unsafe.Pointer, int32, error) {
	if sa.Port < 0 || sa.Port > 0xFFFF {
		return nil, 0, EINVAL
	}
	sa.raw.Family = AF_INET6
	p := (*[2]byte)(unsafe.Pointer(&sa.raw.Port))
	p[0] = byte(sa.Port >> 8)
	p[1] = byte(sa.Port)
	sa.raw.Scope_id = sa.ZoneId
	sa.raw.Addr = sa.Addr
	return unsafe.Pointer(&sa.raw), int32(unsafe.Sizeof(sa.raw)), nil
}

type RawSockaddrUnix struct {
	Family uint16
	Path   [UNIX_PATH_MAX]int8
}

type SockaddrUnix struct {
	Name string
	raw  RawSockaddrUnix
}

func (sa *SockaddrUnix) sockaddr() (unsafe.Pointer, int32, error) {
	name := sa.Name
	n := len(name)
	if n > len(sa.raw.Path) {
		return nil, 0, EINVAL
	}
	if n == len(sa.raw.Path) && name[0] != '@' {
		return nil, 0, EINVAL
	}
	sa.raw.Family = AF_UNIX
	for i := 0; i < n; i++ {
		sa.raw.Path[i] = int8(name[i])
	}
	// length is family (uint16), name, NUL.
	sl := int32(2)
	if n > 0 {
		sl += int32(n) + 1
	}
	if sa.raw.Path[0] == '@' || (sa.raw.Path[0] == 0 && sl > 3) {
		// Check sl > 3 so we don't change unnamed socket behavior.
		sa.raw.Path[0] = 0
		// Don't count trailing NUL for abstract address.
		sl--
	}

	return unsafe.Pointer(&sa.raw), sl, nil
}

func (rsa *RawSockaddrAny) Sockaddr() (Sockaddr, error) {
	switch rsa.Addr.Family {
	case AF_UNIX:
		pp := (*RawSockaddrUnix)(unsafe.Pointer(rsa))
		sa := new(SockaddrUnix)
		if pp.Path[0] == 0 {
			// "Abstract" Unix domain socket.
			// Rewrite leading NUL as @ for textual display.
			// (This is the standard convention.)
			// Not friendly to overwrite in place,
			// but the callers below don't care.
			pp.Path[0] = '@'
		}

		// Assume path ends at NUL.
		// This is not technically the Linux semantics for
		// abstract Unix domain sockets--they are supposed
		// to be uninterpreted fixed-size binary blobs--but
		// everyone uses this convention.
		n := 0
		for n < len(pp.Path) && pp.Path[n] != 0 {
			n++
		}
		sa.Name = string(unsafe.Slice((*byte)(unsafe.Pointer(&pp.Path[0])), n))
		return sa, nil

	case AF_INET:
		pp := (*RawSockaddrInet4)(unsafe.Pointer(rsa))
		sa := new(SockaddrInet4)
		p := (*[2]byte)(unsafe.Pointer(&pp.Port))
		sa.Port = int(p[0])<<8 + int(p[1])
		sa.Addr = pp.Addr
		return sa, nil

	case AF_INET6:
		pp := (*RawSockaddrInet6)(unsafe.Pointer(rsa))
		sa := new(SockaddrInet6)
		p := (*[2]byte)(unsafe.Pointer(&pp.Port))
		sa.Port = int(p[0])<<8 + int(p[1])
		sa.ZoneId = pp.Scope_id
		sa.Addr = pp.Addr
		return sa, nil
	}
	return nil, EAFNOSUPPORT
}

func Socket(domain, typ, proto int) (fd Handle, err error) {
	if domain == AF_INET6 && SocketDisableIPv6 {
		return InvalidHandle, EAFNOSUPPORT
	}
	return socket(int32(domain), int32(typ), int32(proto))
}

func SetsockoptInt(fd Handle, level, opt int, value int) (err error) {
	v := int32(value)
	return Setsockopt(fd, int32(level), int32(opt), (*byte)(unsafe.Pointer(&v)), int32(unsafe.Sizeof(v)))
}

func Bind(fd Handle, sa Sockaddr) (err error) {
	ptr, n, err := sa.sockaddr()
	if err != nil {
		return err
	}
	return bind(fd, ptr, n)
}

func Connect(fd Handle, sa Sockaddr) (err error) {
	ptr, n, err := sa.sockaddr()
	if err != nil {
		return err
	}
	return connect(fd, ptr, n)
}

func Getsockname(fd Handle) (sa Sockaddr, err error) {
	var rsa RawSockaddrAny
	l := int32(unsafe.Sizeof(rsa))
	if err = getsockname(fd, &rsa, &l); err != nil {
		return
	}
	return rsa.Sockaddr()
}

func Getpeername(fd Handle) (sa Sockaddr, err error) {
	var rsa RawSockaddrAny
	l := int32(unsafe.Sizeof(rsa))
	if err = getpeername(fd, &rsa, &l); err != nil {
		return
	}
	return rsa.Sockaddr()
}

func Listen(s Handle, n int) (err error) {
	return listen(s, int32(n))
}

func Shutdown(fd Handle, how int) (err error) {
	return shutdown(fd, int32(how))
}

func WSASendto(s Handle, bufs *WSABuf, bufcnt uint32, sent *uint32, flags uint32, to Sockaddr, overlapped *Overlapped, croutine *byte) (err error) {
	var rsa unsafe.Pointer
	var len int32
	if to != nil {
		rsa, len, err = to.sockaddr()
		if err != nil {
			return err
		}
	}
	r1, _, e1 := Syscall9(procWSASendTo.Addr(), 9, uintptr(s), uintptr(unsafe.Pointer(bufs)), uintptr(bufcnt), uintptr(unsafe.Pointer(sent)), uintptr(flags), uintptr(unsafe.Pointer(rsa)), uintptr(len), uintptr(unsafe.Pointer(overlapped)), uintptr(unsafe.Pointer(croutine)))
	if r1 == socket_error {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = EINVAL
		}
	}
	return err
}

func wsaSendtoInet4(s Handle, bufs *WSABuf, bufcnt uint32, sent *uint32, flags uint32, to *SockaddrInet4, overlapped *Overlapped, croutine *byte) (err error) {
	rsa, len, err := to.sockaddr()
	if err != nil {
		return err
	}
	r1, _, e1 := Syscall9(procWSASendTo.Addr(), 9, uintptr(s), uintptr(unsafe.Pointer(bufs)), uintptr(bufcnt), uintptr(unsafe.Pointer(sent)), uintptr(flags), uintptr(unsafe.Pointer(rsa)), uintptr(len), uintptr(unsafe.Pointer(overlapped)), uintptr(unsafe.Pointer(croutine)))
	if r1 == socket_error {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = EINVAL
		}
	}
	return err
}

func wsaSendtoInet6(s Handle, bufs *WSABuf, bufcnt uint32, sent *uint32, flags uint32, to *SockaddrInet6, overlapped *Overlapped, croutine *byte) (err error) {
	rsa, len, err := to.sockaddr()
	if err != nil {
		return err
	}
	r1, _, e1 := Syscall9(procWSASendTo.Addr(), 9, uintptr(s), uintptr(unsafe.Pointer(bufs)), uintptr(bufcnt), uintptr(unsafe.Pointer(sent)), uintptr(flags), uintptr(unsafe.Pointer(rsa)), uintptr(len), uintptr(unsafe.Pointer(overlapped)), uintptr(unsafe.Pointer(croutine)))
	if r1 == socket_error {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = EINVAL
		}
	}
	return err
}

func LoadGetAddrInfo() error {
	return procGetAddrInfoW.Find()
}

var connectExFunc struct {
	once sync.Once
	addr uintptr
	err  error
}

func LoadConnectEx() error {
	connectExFunc.once.Do(func() {
		var s Handle
		s, connectExFunc.err = Socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
		if connectExFunc.err != nil {
			return
		}
		defer CloseHandle(s)
		var n uint32
		connectExFunc.err = WSAIoctl(s,
			SIO_GET_EXTENSION_FUNCTION_POINTER,
			(*byte)(unsafe.Pointer(&WSAID_CONNECTEX)),
			uint32(unsafe.Sizeof(WSAID_CONNECTEX)),
			(*byte)(unsafe.Pointer(&connectExFunc.addr)),
			uint32(unsafe.Sizeof(connectExFunc.addr)),
			&n, nil, 0)
	})
	return connectExFunc.err
}

func connectEx(s Handle, name unsafe.Pointer, namelen int32, sendBuf *byte, sendDataLen uint32, bytesSent *uint32, overlapped *Overlapped) (err error) {
	r1, _, e1 := Syscall9(connectExFunc.addr, 7, uintptr(s), uintptr(name), uintptr(namelen), uintptr(unsafe.Pointer(sendBuf)), uintptr(sendDataLen), uintptr(unsafe.Pointer(bytesSent)), uintptr(unsafe.Pointer(overlapped)), 0, 0)
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = EINVAL
		}
	}
	return
}

func ConnectEx(fd Handle, sa Sockaddr, sendBuf *byte, sendDataLen uint32, bytesSent *uint32, overlapped *Overlapped) error {
	err := LoadConnectEx()
	if err != nil {
		return errorspkg.New("failed to find ConnectEx: " + err.Error())
	}
	ptr, n, err := sa.sockaddr()
	if err != nil {
		return err
	}
	return connectEx(fd, ptr, n, sendBuf, sendDataLen, bytesSent, overlapped)
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
// consistency with the syscall package for other operating systems.
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

func Accept(fd Handle) (nfd Handle, sa Sockaddr, err error) { return 0, nil, EWINDOWS }
func Recvfrom(fd Handle, p []byte, flags int) (n int, from Sockaddr, err error) {
	return 0, nil, EWINDOWS
}
func Sendto(fd Handle, p []byte, flags int, to Sockaddr) (err error)       { return EWINDOWS }
func SetsockoptTimeval(fd Handle, level, opt int, tv *Timeval) (err error) { return EWINDOWS }

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
	optval := int32(0)
	optlen := int32(unsafe.Sizeof(optval))
	err := Getsockopt(fd, int32(level), int32(opt), (*byte)(unsafe.Pointer(&optval)), &optlen)
	return int(optval), err
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
func SetsockoptIPv6Mreq(fd Handle, level, opt int, mreq *IPv6Mreq) (err error) { return EWINDOWS }

func Getpid() (pid int) { return int(getCurrentProcessId()) }

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

func fdpath(fd Handle, buf []uint16) ([]uint16, error) {
	const (
		FILE_NAME_NORMALIZED = 0
		VOLUME_NAME_DOS      = 0
	)
	for {
		n, err := getFinalPathNameByHandle(fd, &buf[0], uint32(len(buf)), FILE_NAME_NORMALIZED|VOLUME_NAME_DOS)
		if err == nil {
			buf = buf[:n]
			break
		}
		if err != _ERROR_NOT_ENOUGH_MEMORY {
			return nil, err
		}
		buf = append(buf, make([]uint16, n-uint32(len(buf)))...)
	}
	return buf, nil
}

func Fchdir(fd Handle) (err error) {
	var buf [MAX_PATH + 1]uint16
	path, err := fdpath(fd, buf[:])
	if err != nil {
		return err
	}
	// When using VOLUME_NAME_DOS, the path is always prefixed by "\\?\".
	// That prefix tells the Windows APIs to disable all string parsing and to send
	// the string that follows it straight to the file system.
	// Although SetCurrentDirectory and GetCurrentDirectory do support the "\\?\" prefix,
	// some other Windows APIs don't. If the prefix is not removed here, it will leak
	// to Getwd, and we don't want such a general-purpose function to always return a
	// path with the "\\?\" prefix after Fchdir is called.
	// The downside is that APIs that do support it will parse the path and try to normalize it,
	// when it's already normalized.
	if len(path) >= 4 && path[0] == '\\' && path[1] == '\\' && path[2] == '?' && path[3] == '\\' {
		path = path[4:]
	}
	return SetCurrentDirectory(&path[0])
}

// TODO(brainman): fix all needed for os
func Link(oldpath, newpath string) (err error) { return EWINDOWS }
func Symlink(path, link string) (err error)    { return EWINDOWS }

func Fchmod(fd Handle, mode uint32) (err error)        { return EWINDOWS }
func Chown(path string, uid int, gid int) (err error)  { return EWINDOWS }
func Lchown(path string, uid int, gid int) (err error) { return EWINDOWS }
func Fchown(fd Handle, uid int, gid int) (err error)   { return EWINDOWS }

func Getuid() (uid int)                  { return -1 }
func Geteuid() (euid int)                { return -1 }
func Getgid() (gid int)                  { return -1 }
func Getegid() (egid int)                { return -1 }
func Getgroups() (gids []int, err error) { return nil, EWINDOWS }

type Signal int

func (s Signal) Signal() {}

func (s Signal) String() string {
	if 0 <= s && int(s) < len(signals) {
		str := signals[s]
		if str != "" {
			return str
		}
	}
	return "signal " + itoa.Itoa(int(s))
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
		s = UTF16ToString(p[data.SubstituteNameOffset/2 : (data.SubstituteNameOffset+data.SubstituteNameLength)/2])
		if data.Flags&_SYMLINK_FLAG_RELATIVE == 0 {
			if len(s) >= 4 && s[:4] == `\??\` {
				s = s[4:]
				switch {
				case len(s) >= 2 && s[1] == ':': // \??\C:\foo\bar
					// do nothing
				case len(s) >= 4 && s[:4] == `UNC\`: // \??\UNC\foo\bar
					s = `\\` + s[4:]
				default:
					// unexpected; do nothing
				}
			} else {
				// unexpected; do nothing
			}
		}
	case _IO_REPARSE_TAG_MOUNT_POINT:
		data := (*mountPointReparseBuffer)(unsafe.Pointer(&rdb.reparseBuffer))
		p := (*[0xffff]uint16)(unsafe.Pointer(&data.PathBuffer[0]))
		s = UTF16ToString(p[data.SubstituteNameOffset/2 : (data.SubstituteNameOffset+data.SubstituteNameLength)/2])
		if len(s) >= 4 && s[:4] == `\??\` { // \??\C:\foo\bar
			s = s[4:]
		} else {
			// unexpected; do nothing
		}
	default:
		// the path is not a symlink or junction but another type of reparse
		// point
		return -1, ENOENT
	}
	n = copy(buf, []byte(s))

	return n, nil
}

// Deprecated: CreateIoCompletionPort has the wrong function signature. Use x/sys/windows.CreateIoCompletionPort.
func CreateIoCompletionPort(filehandle Handle, cphandle Handle, key uint32, threadcnt uint32) (Handle, error) {
	return createIoCompletionPort(filehandle, cphandle, uintptr(key), threadcnt)
}

// Deprecated: GetQueuedCompletionStatus has the wrong function signature. Use x/sys/windows.GetQueuedCompletionStatus.
func GetQueuedCompletionStatus(cphandle Handle, qty *uint32, key *uint32, overlapped **Overlapped, timeout uint32) error {
	var ukey uintptr
	var pukey *uintptr
	if key != nil {
		ukey = uintptr(*key)
		pukey = &ukey
	}
	err := getQueuedCompletionStatus(cphandle, qty, pukey, overlapped, timeout)
	if key != nil {
		*key = uint32(ukey)
		if uintptr(*key) != ukey && err == nil {
			err = errorspkg.New("GetQueuedCompletionStatus returned key overflow")
		}
	}
	return err
}

// Deprecated: PostQueuedCompletionStatus has the wrong function signature. Use x/sys/windows.PostQueuedCompletionStatus.
func PostQueuedCompletionStatus(cphandle Handle, qty uint32, key uint32, overlapped *Overlapped) error {
	return postQueuedCompletionStatus(cphandle, qty, uintptr(key), overlapped)
}

// newProcThreadAttributeList allocates new PROC_THREAD_ATTRIBUTE_LIST, with
// the requested maximum number of attributes, which must be cleaned up by
// deleteProcThreadAttributeList.
func newProcThreadAttributeList(maxAttrCount uint32) (*_PROC_THREAD_ATTRIBUTE_LIST, error) {
	var size uintptr
	err := initializeProcThreadAttributeList(nil, maxAttrCount, 0, &size)
	if err != ERROR_INSUFFICIENT_BUFFER {
		if err == nil {
			return nil, errorspkg.New("unable to query buffer size from InitializeProcThreadAttributeList")
		}
		return nil, err
	}
	// size is guaranteed to be ≥1 by initializeProcThreadAttributeList.
	al := (*_PROC_THREAD_ATTRIBUTE_LIST)(unsafe.Pointer(&make([]byte, size)[0]))
	err = initializeProcThreadAttributeList(al, maxAttrCount, 0, &size)
	if err != nil {
		return nil, err
	}
	return al, nil
}

// RegEnumKeyEx enumerates the subkeys of an open registry key.
// Each call retrieves information about one subkey. name is
// a buffer that should be large enough to hold the name of the
// subkey plus a null terminating character. nameLen is its
// length. On return, nameLen will contain the actual length of the
// subkey.
//
// Should name not be large enough to hold the subkey, this function
// will return ERROR_MORE_DATA, and must be called again with an
// appropriately sized buffer.
//
// reserved must be nil. class and classLen behave like name and nameLen
// but for the class of the subkey, except that they are optional.
// lastWriteTime, if not nil, will be populated with the time the subkey
// was last written.
//
// The caller must enumerate all subkeys in order. That is
// RegEnumKeyEx must be called with index starting at 0, incrementing
// the index until the function returns ERROR_NO_MORE_ITEMS, or with
// the index of the last subkey (obtainable from RegQueryInfoKey),
// decrementing until index 0 is enumerated.
//
// Successive calls to this API must happen on the same OS thread,
// so call [runtime.LockOSThread] before calling this function.
func RegEnumKeyEx(key Handle, index uint32, name *uint16, nameLen *uint32, reserved *uint32, class *uint16, classLen *uint32, lastWriteTime *Filetime) (regerrno error) {
	return regEnumKeyEx(key, index, name, nameLen, reserved, class, classLen, lastWriteTime)
}

func GetStartupInfo(startupInfo *StartupInfo) error {
	getStartupInfo(startupInfo)
	return nil
}

"""




```