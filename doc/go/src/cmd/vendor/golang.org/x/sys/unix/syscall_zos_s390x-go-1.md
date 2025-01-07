Response:
The user has provided a Go code snippet from the `syscall_zos_s390x.go` file and is asking for its functionality. This is the second part of a two-part request. I need to summarize the functionalities present in this second part of the code.

**Plan:**

1. Identify the key data structures and variables defined in the code.
2. Analyze the functions and their purpose.
3. Infer the high-level Go language features being implemented.
4. If possible, provide illustrative Go code examples with hypothetical inputs and outputs.
5. If there are command-line arguments involved, describe them.
6. Point out common mistakes users might make.
7. Finally, summarize the overall functionality of this code snippet.
这是`go/src/cmd/vendor/golang.org/x/sys/unix/syscall_zos_s390x.go` 文件第二部分的功能列表：

1. **定义了标准输入/输出/错误的文件描述符:**  `Stdin`, `Stdout`, `Stderr` 分别被赋值为 0, 1, 2。

2. **定义了预先分配的常见 `Errno` 值:**  `errEAGAIN`, `errEINVAL`, `errENOENT` 用于避免在运行时进行重复的内存分配。

3. **定义了用于控制和记录追踪信息的全局变量:** `ZosTraceLevel` 控制追踪级别，`ZosTracefile` 指定追踪信息输出的文件。

4. **定义了用于信号名称和信号值之间映射的变量:** `signalNameMapOnce` 用于确保映射只初始化一次，`signalNameMap` 是存储信号名称到信号值的映射。

5. **提供了根据 `Errno` 返回 `error` 的优化函数 `errnoErr`:**  对于常见的错误码，返回预先分配的 `error` 实例，减少内存分配。

6. **提供了增强的 `Errno` 处理函数 `errnoErr2`:**  除了基本的 `Errno` 处理，还允许在 z/OS 系统上获取额外的错误信息 `errno2`。它还包含了基于 `ZosTraceLevel` 的错误追踪功能，可以将错误信息（包括调用栈信息）输出到控制台或指定的文件。

7. **提供了根据 `Errno` 值获取错误名称的函数 `ErrnoName`:**  通过在 `errorList` 中查找，返回错误码对应的名称。

8. **提供了根据信号值获取信号名称的函数 `SignalName`:** 通过在 `signalList` 中查找，返回信号值对应的名称。

9. **提供了根据信号名称获取信号值的函数 `SignalNum`:**  通过 `signalNameMap` 查找，返回信号名称对应的 `syscall.Signal` 值。

10. **提供了计算以 NULL 结尾的字节数组实际长度的函数 `clen`。**

11. **实现了内存映射的管理结构 `mmapper`:**
    *   维护了活跃的内存映射 `active`。
    *   包含了进行内存映射和取消映射的函数指针 `mmap` 和 `munmap`，允许操作系统特定的实现。
    *   提供了 `Mmap` 方法用于创建内存映射，内部使用 `__MAP_64` 标志。
    *   提供了 `Munmap` 方法用于取消内存映射。

12. **重写了 `Read` 和 `Write` 函数:** 包装了底层的 `read` 和 `write` 系统调用，并加入了对 race condition 检测的支持（如果 `raceenabled` 为真）。

13. **定义了用于禁用 IPv6 socket 的全局变量 `SocketDisableIPv6`。**

14. **定义了 socket 地址的接口 `Sockaddr` 以及其不同类型的实现:** `SockaddrInet4`, `SockaddrInet6`, `SockaddrUnix` 分别对应 IPv4, IPv6 和 Unix 域 socket 地址。

15. **实现了 socket 相关的系统调用包装函数:**
    *   `Bind`: 绑定 socket 地址。
    *   `Connect`: 连接到指定 socket 地址。
    *   `Getpeername`: 获取连接的对端地址。
    *   `GetsockoptByte`, `GetsockoptInt`, `GetsockoptInet4Addr`, `GetsockoptIPMreq`, `GetsockoptIPv6Mreq`, `GetsockoptIPv6MTUInfo`, `GetsockoptICMPv6Filter`, `GetsockoptLinger`, `GetsockoptTimeval`, `GetsockoptUint64`: 获取 socket 选项。
    *   `Recvfrom`: 从 socket 接收数据，并获取发送方地址。
    *   `Sendto`: 向指定 socket 地址发送数据。
    *   `SetsockoptByte`, `SetsockoptInt`, `SetsockoptInet4Addr`, `SetsockoptIPMreq`, `SetsockoptIPv6Mreq`, `SetsockoptICMPv6Filter`, `SetsockoptLinger`, `SetsockoptString`, `SetsockoptTimeval`, `SetsockoptUint64`: 设置 socket 选项。
    *   `Socket`: 创建 socket，支持 `SocketDisableIPv6` 标志。
    *   `Socketpair`: 创建一对已连接的 socket。

16. **定义了用于 race condition 检测的全局变量 `ioSync`。**

17. **提供了设置 close-on-exec 标志的函数 `CloseOnExec`。**

18. **提供了设置非阻塞模式的函数 `SetNonblock`。**

19. **包装了 `syscall.Exec` 函数为 `Exec`。**

20. **提供了获取文件扩展属性的函数 `Getag`:**  用于获取文件的 CCSID 和标志。

21. **实现了 `Mount` 和 `Unmount` 系统调用的包装函数，包括对 z/OS 特定系统调用的支持以及回退到旧版本 `mount_LE` 和 `unmount_LE` 的逻辑。**

22. **提供了从 `dirent` 结构中读取 inode, 记录长度和名称长度的辅助函数 `direntIno`, `direntReclen`, `direntNamlen`。**

23. **提供了将 z/OS 的 `direntLE` 结构转换为 Unix 标准 `Dirent` 结构的函数 `direntLeToDirentUnix`。**

24. **实现了 `Getdirentries` 函数:**  模拟了从目录中读取多个目录项的功能，使用了底层的 `Opendir`, `Readdir_r`, `Closedir`, `Telldir`, `Lstat` 等函数。

25. **提供了获取指向 `errno2` 变量的指针的函数 `Err2ad`。**

26. **提供了向 z/OS 控制台输出格式化信息的函数 `ZosConsolePrintf`。**

27. **提供了在 ASCII 和 EBCDIC 编码之间转换字符串和字节数组的函数 `ZosStringToEbcdicBytes` 和 `ZosEbcdicBytesToString`。**

28. **提供了根据文件描述符获取文件路径的函数 `fdToPath`。**

29. **实现了 `Mkfifoat` 系统调用的包装函数，包括对 z/OS 特定系统调用的支持以及回退到旧版本 `Mkfifo` 的逻辑。**

30. **注释掉了一些函数，如 `Posix_openpt`, `Grantpt`, `Unlockpt`。**

31. **提供了更通用的 `Fcntl` 函数:**  根据传入的 `op` 类型，调用相应的 `Fcntl` 具体实现，包括对 `Flock_t`, `int`, `F_cnvrt`, `unsafe.Pointer` 的支持。

32. **实现了 `Sendfile` 系统调用的包装函数:**  如果底层系统调用未实现或不可用，则回退到使用 `Read` 和 `Write` 模拟 `sendfile` 的功能。

**推断的 Go 语言功能实现:**

这段代码是 `syscall` 包的一部分，主要负责与底层操作系统交互，尤其是 z/OS (s390x) 平台。它实现了以下 Go 语言功能：

*   **系统调用:** 包装了大量的 z/OS 系统调用，如 `read`, `write`, `bind`, `connect`, `socket`, `mount`, `unmount`, `mkfifoat`, `fcntl`, `sendfile` 等。
*   **错误处理:**  定义了 `Errno` 类型，并提供了将 `Errno` 转换为 Go `error` 的机制，还针对 z/OS 提供了更详细的错误信息处理（`errno2`）。
*   **文件 I/O:**  提供了 `Read` 和 `Write` 函数，以及内存映射相关的 `Mmap` 和 `Munmap`。
*   **网络编程:**  实现了 socket 相关的操作，如创建、绑定、连接、发送、接收数据等。
*   **进程控制:**  提供了 `Exec` 函数执行新的程序。
*   **目录操作:**  实现了 `Getdirentries` 函数读取目录项。
*   **扩展属性:**  提供了 `Getag` 函数获取文件扩展属性。
*   **字符编码转换:** 提供了 ASCII 和 EBCDIC 之间的转换函数。

**Go 代码示例：**

以下是一些基于代码推断的 Go 代码示例：

```go
package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	sys "golang.org/x/sys/unix"
)

func main() {
	// 使用 Read 和 Write
	file, err := os.Open("test.txt")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	buf := make([]byte, 100)
	n, err := sys.Read(int(file.Fd()), buf)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	fmt.Printf("Read %d bytes: %s\n", n, string(buf[:n]))

	// 使用 Socket 进行网络编程
	fd, err := sys.Socket(sys.AF_INET, sys.SOCK_STREAM, 0)
	if err != nil {
		fmt.Println("Error creating socket:", err)
		return
	}
	defer syscall.Close(fd)

	addr := sys.SockaddrInet4{
		Port: 8080,
		Addr: [4]byte{127, 0, 0, 1},
	}
	err = sys.Connect(fd, &addr)
	if err != nil {
		fmt.Println("Error connecting:", err)
		return
	}
	fmt.Println("Connected to server")

	// 使用 Mmap 进行内存映射 (假设存在文件 data.bin)
	dataFile, err := os.OpenFile("data.bin", os.O_RDWR, 0644)
	if err != nil {
		fmt.Println("Error opening data file:", err)
		return
	}
	defer dataFile.Close()

	fileInfo, _ := dataFile.Stat()
	length := int(fileInfo.Size())
	prot := syscall.PROT_READ | syscall.PROT_WRITE
	flags := syscall.MAP_SHARED
	data, err := sys.Mmap(int(dataFile.Fd()), 0, length, prot, flags)
	if err != nil {
		fmt.Println("Error mmapping file:", err)
		return
	}
	defer sys.Munmap(data)
	fmt.Printf("Mapped %d bytes of data file\n", len(data))

	// 使用 Getdirentries 读取目录
	dirFile, err := os.Open(".")
	if err != nil {
		fmt.Println("Error opening directory:", err)
		return
	}
	defer dirFile.Close()

	dirBuf := make([]byte, 4096)
	basep := uintptr(0)
	n, err = sys.Getdirentries(int(dirFile.Fd()), dirBuf, &basep)
	if err != nil {
		fmt.Println("Error reading directory entries:", err)
		return
	}
	fmt.Printf("Read %d bytes of directory entries\n", n)
}
```

**假设的输入与输出:**

*   **Read 示例:** 假设 `test.txt` 文件内容为 "Hello, world!"，输出可能为 "Read 13 bytes: Hello, world!"。
*   **Socket 示例:**  假设本地 8080 端口有一个监听的服务器，成功连接后输出 "Connected to server"。
*   **Mmap 示例:** 假设 `data.bin` 文件存在且大小为 1024 字节，输出可能为 "Mapped 1024 bytes of data file"。
*   **Getdirentries 示例:** 输出读取到的目录项字节数，具体内容取决于当前目录结构。

**命令行参数的具体处理:**

这段代码本身没有直接处理命令行参数的逻辑。但是，`ZosTraceLevel` 和 `ZosTracefile` 变量可以间接地被命令行参数影响，如果程序的其他部分读取环境变量或命令行参数来设置这些全局变量。例如，可以设置一个环境变量 `ZOS_TRACE_LEVEL` 来控制追踪级别。

**使用者易犯错的点:**

*   **不正确的类型转换:** 在调用系统调用时，参数类型必须正确匹配。例如，文件描述符是 `int` 类型。
*   **忽略错误返回值:** 系统调用通常会返回错误信息，必须检查并处理这些错误。
*   **内存管理:**  在使用 `Mmap` 时，需要确保在不再使用时调用 `Munmap` 释放内存，否则可能导致资源泄漏。
*   **字符编码问题:** 在 z/OS 上处理字符串时，需要注意 ASCII 和 EBCDIC 之间的转换，尤其是在与操作系统接口交互时。
*   **对 z/OS 特定概念不熟悉:**  例如，`errno2` 是 z/OS 特有的错误信息，理解其含义需要一定的 z/OS 背景知识。
*   **`Getdirentries` 的使用:** 需要理解 `Getdirentries` 的行为和 Darwin 模拟的局限性，以及如何处理 `basep` 参数（虽然在这个模拟实现中似乎没有被完全使用）。

**归纳一下它的功能:**

这段 Go 代码是 Go 语言 `syscall` 包在 z/OS (s390x) 平台上的底层实现。它提供了访问 z/OS 系统调用的接口，包括文件 I/O、网络编程、进程控制、目录操作等核心功能。此外，它还包含了一些 z/OS 特有的功能，如 `errno2` 处理和字符编码转换，以及为了在 z/OS 上更好地支持这些系统调用所做的特定实现和兼容性处理。 这部分代码是操作系统接口的关键组成部分，使得 Go 程序能够在 z/OS 环境下运行并利用底层的操作系统功能。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/syscall_zos_s390x.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共2部分，请归纳一下它的功能

"""

var (
	Stdin  = 0
	Stdout = 1
	Stderr = 2
)

// Do the interface allocations only once for common
// Errno values.
var (
	errEAGAIN error = syscall.EAGAIN
	errEINVAL error = syscall.EINVAL
	errENOENT error = syscall.ENOENT
)

var ZosTraceLevel int
var ZosTracefile *os.File

var (
	signalNameMapOnce sync.Once
	signalNameMap     map[string]syscall.Signal
)

// errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e Errno) error {
	switch e {
	case 0:
		return nil
	case EAGAIN:
		return errEAGAIN
	case EINVAL:
		return errEINVAL
	case ENOENT:
		return errENOENT
	}
	return e
}

var reg *regexp.Regexp

// enhanced with zos specific errno2
func errnoErr2(e Errno, e2 uintptr) error {
	switch e {
	case 0:
		return nil
	case EAGAIN:
		return errEAGAIN
		/*
			Allow the retrieval of errno2 for EINVAL and ENOENT on zos
				case EINVAL:
					return errEINVAL
				case ENOENT:
					return errENOENT
		*/
	}
	if ZosTraceLevel > 0 {
		var name string
		if reg == nil {
			reg = regexp.MustCompile("(^unix\\.[^/]+$|.*\\/unix\\.[^/]+$)")
		}
		i := 1
		pc, file, line, ok := runtime.Caller(i)
		if ok {
			name = runtime.FuncForPC(pc).Name()
		}
		for ok && reg.MatchString(runtime.FuncForPC(pc).Name()) {
			i += 1
			pc, file, line, ok = runtime.Caller(i)
		}
		if ok {
			if ZosTracefile == nil {
				ZosConsolePrintf("From %s:%d\n", file, line)
				ZosConsolePrintf("%s: %s (errno2=0x%x)\n", name, e.Error(), e2)
			} else {
				fmt.Fprintf(ZosTracefile, "From %s:%d\n", file, line)
				fmt.Fprintf(ZosTracefile, "%s: %s (errno2=0x%x)\n", name, e.Error(), e2)
			}
		} else {
			if ZosTracefile == nil {
				ZosConsolePrintf("%s (errno2=0x%x)\n", e.Error(), e2)
			} else {
				fmt.Fprintf(ZosTracefile, "%s (errno2=0x%x)\n", e.Error(), e2)
			}
		}
	}
	return e
}

// ErrnoName returns the error name for error number e.
func ErrnoName(e Errno) string {
	i := sort.Search(len(errorList), func(i int) bool {
		return errorList[i].num >= e
	})
	if i < len(errorList) && errorList[i].num == e {
		return errorList[i].name
	}
	return ""
}

// SignalName returns the signal name for signal number s.
func SignalName(s syscall.Signal) string {
	i := sort.Search(len(signalList), func(i int) bool {
		return signalList[i].num >= s
	})
	if i < len(signalList) && signalList[i].num == s {
		return signalList[i].name
	}
	return ""
}

// SignalNum returns the syscall.Signal for signal named s,
// or 0 if a signal with such name is not found.
// The signal name should start with "SIG".
func SignalNum(s string) syscall.Signal {
	signalNameMapOnce.Do(func() {
		signalNameMap = make(map[string]syscall.Signal, len(signalList))
		for _, signal := range signalList {
			signalNameMap[signal.name] = signal.num
		}
	})
	return signalNameMap[s]
}

// clen returns the index of the first NULL byte in n or len(n) if n contains no NULL byte.
func clen(n []byte) int {
	i := bytes.IndexByte(n, 0)
	if i == -1 {
		i = len(n)
	}
	return i
}

// Mmap manager, for use by operating system-specific implementations.

type mmapper struct {
	sync.Mutex
	active map[*byte][]byte // active mappings; key is last byte in mapping
	mmap   func(addr, length uintptr, prot, flags, fd int, offset int64) (uintptr, error)
	munmap func(addr uintptr, length uintptr) error
}

func (m *mmapper) Mmap(fd int, offset int64, length int, prot int, flags int) (data []byte, err error) {
	if length <= 0 {
		return nil, EINVAL
	}

	// Set __MAP_64 by default
	flags |= __MAP_64

	// Map the requested memory.
	addr, errno := m.mmap(0, uintptr(length), prot, flags, fd, offset)
	if errno != nil {
		return nil, errno
	}

	// Slice memory layout
	var sl = struct {
		addr uintptr
		len  int
		cap  int
	}{addr, length, length}

	// Use unsafe to turn sl into a []byte.
	b := *(*[]byte)(unsafe.Pointer(&sl))

	// Register mapping in m and return it.
	p := &b[cap(b)-1]
	m.Lock()
	defer m.Unlock()
	m.active[p] = b
	return b, nil
}

func (m *mmapper) Munmap(data []byte) (err error) {
	if len(data) == 0 || len(data) != cap(data) {
		return EINVAL
	}

	// Find the base of the mapping.
	p := &data[cap(data)-1]
	m.Lock()
	defer m.Unlock()
	b := m.active[p]
	if b == nil || &b[0] != &data[0] {
		return EINVAL
	}

	// Unmap the memory and update m.
	if errno := m.munmap(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b))); errno != nil {
		return errno
	}
	delete(m.active, p)
	return nil
}

func Read(fd int, p []byte) (n int, err error) {
	n, err = read(fd, p)
	if raceenabled {
		if n > 0 {
			raceWriteRange(unsafe.Pointer(&p[0]), n)
		}
		if err == nil {
			raceAcquire(unsafe.Pointer(&ioSync))
		}
	}
	return
}

func Write(fd int, p []byte) (n int, err error) {
	if raceenabled {
		raceReleaseMerge(unsafe.Pointer(&ioSync))
	}
	n, err = write(fd, p)
	if raceenabled && n > 0 {
		raceReadRange(unsafe.Pointer(&p[0]), n)
	}
	return
}

// For testing: clients can set this flag to force
// creation of IPv6 sockets to return EAFNOSUPPORT.
var SocketDisableIPv6 bool

// Sockaddr represents a socket address.
type Sockaddr interface {
	sockaddr() (ptr unsafe.Pointer, len _Socklen, err error) // lowercase; only we can define Sockaddrs
}

// SockaddrInet4 implements the Sockaddr interface for AF_INET type sockets.
type SockaddrInet4 struct {
	Port int
	Addr [4]byte
	raw  RawSockaddrInet4
}

// SockaddrInet6 implements the Sockaddr interface for AF_INET6 type sockets.
type SockaddrInet6 struct {
	Port   int
	ZoneId uint32
	Addr   [16]byte
	raw    RawSockaddrInet6
}

// SockaddrUnix implements the Sockaddr interface for AF_UNIX type sockets.
type SockaddrUnix struct {
	Name string
	raw  RawSockaddrUnix
}

func Bind(fd int, sa Sockaddr) (err error) {
	ptr, n, err := sa.sockaddr()
	if err != nil {
		return err
	}
	return bind(fd, ptr, n)
}

func Connect(fd int, sa Sockaddr) (err error) {
	ptr, n, err := sa.sockaddr()
	if err != nil {
		return err
	}
	return connect(fd, ptr, n)
}

func Getpeername(fd int) (sa Sockaddr, err error) {
	var rsa RawSockaddrAny
	var len _Socklen = SizeofSockaddrAny
	if err = getpeername(fd, &rsa, &len); err != nil {
		return
	}
	return anyToSockaddr(fd, &rsa)
}

func GetsockoptByte(fd, level, opt int) (value byte, err error) {
	var n byte
	vallen := _Socklen(1)
	err = getsockopt(fd, level, opt, unsafe.Pointer(&n), &vallen)
	return n, err
}

func GetsockoptInt(fd, level, opt int) (value int, err error) {
	var n int32
	vallen := _Socklen(4)
	err = getsockopt(fd, level, opt, unsafe.Pointer(&n), &vallen)
	return int(n), err
}

func GetsockoptInet4Addr(fd, level, opt int) (value [4]byte, err error) {
	vallen := _Socklen(4)
	err = getsockopt(fd, level, opt, unsafe.Pointer(&value[0]), &vallen)
	return value, err
}

func GetsockoptIPMreq(fd, level, opt int) (*IPMreq, error) {
	var value IPMreq
	vallen := _Socklen(SizeofIPMreq)
	err := getsockopt(fd, level, opt, unsafe.Pointer(&value), &vallen)
	return &value, err
}

func GetsockoptIPv6Mreq(fd, level, opt int) (*IPv6Mreq, error) {
	var value IPv6Mreq
	vallen := _Socklen(SizeofIPv6Mreq)
	err := getsockopt(fd, level, opt, unsafe.Pointer(&value), &vallen)
	return &value, err
}

func GetsockoptIPv6MTUInfo(fd, level, opt int) (*IPv6MTUInfo, error) {
	var value IPv6MTUInfo
	vallen := _Socklen(SizeofIPv6MTUInfo)
	err := getsockopt(fd, level, opt, unsafe.Pointer(&value), &vallen)
	return &value, err
}

func GetsockoptICMPv6Filter(fd, level, opt int) (*ICMPv6Filter, error) {
	var value ICMPv6Filter
	vallen := _Socklen(SizeofICMPv6Filter)
	err := getsockopt(fd, level, opt, unsafe.Pointer(&value), &vallen)
	return &value, err
}

func GetsockoptLinger(fd, level, opt int) (*Linger, error) {
	var linger Linger
	vallen := _Socklen(SizeofLinger)
	err := getsockopt(fd, level, opt, unsafe.Pointer(&linger), &vallen)
	return &linger, err
}

func GetsockoptTimeval(fd, level, opt int) (*Timeval, error) {
	var tv Timeval
	vallen := _Socklen(unsafe.Sizeof(tv))
	err := getsockopt(fd, level, opt, unsafe.Pointer(&tv), &vallen)
	return &tv, err
}

func GetsockoptUint64(fd, level, opt int) (value uint64, err error) {
	var n uint64
	vallen := _Socklen(8)
	err = getsockopt(fd, level, opt, unsafe.Pointer(&n), &vallen)
	return n, err
}

func Recvfrom(fd int, p []byte, flags int) (n int, from Sockaddr, err error) {
	var rsa RawSockaddrAny
	var len _Socklen = SizeofSockaddrAny
	if n, err = recvfrom(fd, p, flags, &rsa, &len); err != nil {
		return
	}
	if rsa.Addr.Family != AF_UNSPEC {
		from, err = anyToSockaddr(fd, &rsa)
	}
	return
}

func Sendto(fd int, p []byte, flags int, to Sockaddr) (err error) {
	ptr, n, err := to.sockaddr()
	if err != nil {
		return err
	}
	return sendto(fd, p, flags, ptr, n)
}

func SetsockoptByte(fd, level, opt int, value byte) (err error) {
	return setsockopt(fd, level, opt, unsafe.Pointer(&value), 1)
}

func SetsockoptInt(fd, level, opt int, value int) (err error) {
	var n = int32(value)
	return setsockopt(fd, level, opt, unsafe.Pointer(&n), 4)
}

func SetsockoptInet4Addr(fd, level, opt int, value [4]byte) (err error) {
	return setsockopt(fd, level, opt, unsafe.Pointer(&value[0]), 4)
}

func SetsockoptIPMreq(fd, level, opt int, mreq *IPMreq) (err error) {
	return setsockopt(fd, level, opt, unsafe.Pointer(mreq), SizeofIPMreq)
}

func SetsockoptIPv6Mreq(fd, level, opt int, mreq *IPv6Mreq) (err error) {
	return setsockopt(fd, level, opt, unsafe.Pointer(mreq), SizeofIPv6Mreq)
}

func SetsockoptICMPv6Filter(fd, level, opt int, filter *ICMPv6Filter) error {
	return setsockopt(fd, level, opt, unsafe.Pointer(filter), SizeofICMPv6Filter)
}

func SetsockoptLinger(fd, level, opt int, l *Linger) (err error) {
	return setsockopt(fd, level, opt, unsafe.Pointer(l), SizeofLinger)
}

func SetsockoptString(fd, level, opt int, s string) (err error) {
	var p unsafe.Pointer
	if len(s) > 0 {
		p = unsafe.Pointer(&[]byte(s)[0])
	}
	return setsockopt(fd, level, opt, p, uintptr(len(s)))
}

func SetsockoptTimeval(fd, level, opt int, tv *Timeval) (err error) {
	return setsockopt(fd, level, opt, unsafe.Pointer(tv), unsafe.Sizeof(*tv))
}

func SetsockoptUint64(fd, level, opt int, value uint64) (err error) {
	return setsockopt(fd, level, opt, unsafe.Pointer(&value), 8)
}

func Socket(domain, typ, proto int) (fd int, err error) {
	if domain == AF_INET6 && SocketDisableIPv6 {
		return -1, EAFNOSUPPORT
	}
	fd, err = socket(domain, typ, proto)
	return
}

func Socketpair(domain, typ, proto int) (fd [2]int, err error) {
	var fdx [2]int32
	err = socketpair(domain, typ, proto, &fdx)
	if err == nil {
		fd[0] = int(fdx[0])
		fd[1] = int(fdx[1])
	}
	return
}

var ioSync int64

func CloseOnExec(fd int) { fcntl(fd, F_SETFD, FD_CLOEXEC) }

func SetNonblock(fd int, nonblocking bool) (err error) {
	flag, err := fcntl(fd, F_GETFL, 0)
	if err != nil {
		return err
	}
	if nonblocking {
		flag |= O_NONBLOCK
	} else {
		flag &= ^O_NONBLOCK
	}
	_, err = fcntl(fd, F_SETFL, flag)
	return err
}

// Exec calls execve(2), which replaces the calling executable in the process
// tree. argv0 should be the full path to an executable ("/bin/ls") and the
// executable name should also be the first argument in argv (["ls", "-l"]).
// envv are the environment variables that should be passed to the new
// process (["USER=go", "PWD=/tmp"]).
func Exec(argv0 string, argv []string, envv []string) error {
	return syscall.Exec(argv0, argv, envv)
}

func Getag(path string) (ccsid uint16, flag uint16, err error) {
	var val [8]byte
	sz, err := Getxattr(path, "ccsid", val[:])
	if err != nil {
		return
	}
	ccsid = uint16(EncodeData(val[0:sz]))
	sz, err = Getxattr(path, "flags", val[:])
	if err != nil {
		return
	}
	flag = uint16(EncodeData(val[0:sz]) >> 15)
	return
}

// Mount begin
func impl_Mount(source string, target string, fstype string, flags uintptr, data string) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(source)
	if err != nil {
		return
	}
	var _p1 *byte
	_p1, err = BytePtrFromString(target)
	if err != nil {
		return
	}
	var _p2 *byte
	_p2, err = BytePtrFromString(fstype)
	if err != nil {
		return
	}
	var _p3 *byte
	_p3, err = BytePtrFromString(data)
	if err != nil {
		return
	}
	runtime.EnterSyscall()
	r0, e2, e1 := CallLeFuncWithErr(GetZosLibVec()+SYS___MOUNT1_A<<4, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(_p1)), uintptr(unsafe.Pointer(_p2)), uintptr(flags), uintptr(unsafe.Pointer(_p3)))
	runtime.ExitSyscall()
	if int64(r0) == -1 {
		err = errnoErr2(e1, e2)
	}
	return
}

//go:nosplit
func get_MountAddr() *(func(source string, target string, fstype string, flags uintptr, data string) (err error))

var Mount = enter_Mount

func enter_Mount(source string, target string, fstype string, flags uintptr, data string) (err error) {
	funcref := get_MountAddr()
	if validMount() {
		*funcref = impl_Mount
	} else {
		*funcref = legacyMount
	}
	return (*funcref)(source, target, fstype, flags, data)
}

func legacyMount(source string, target string, fstype string, flags uintptr, data string) (err error) {
	if needspace := 8 - len(fstype); needspace <= 0 {
		fstype = fstype[0:8]
	} else {
		fstype += "        "[0:needspace]
	}
	return mount_LE(target, source, fstype, uint32(flags), int32(len(data)), data)
}

func validMount() bool {
	if funcptrtest(GetZosLibVec()+SYS___MOUNT1_A<<4, "") == 0 {
		if name, err := getLeFuncName(GetZosLibVec() + SYS___MOUNT1_A<<4); err == nil {
			return name == "__mount1_a"
		}
	}
	return false
}

// Mount end

// Unmount begin
func impl_Unmount(target string, flags int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(target)
	if err != nil {
		return
	}
	runtime.EnterSyscall()
	r0, e2, e1 := CallLeFuncWithErr(GetZosLibVec()+SYS___UMOUNT2_A<<4, uintptr(unsafe.Pointer(_p0)), uintptr(flags))
	runtime.ExitSyscall()
	if int64(r0) == -1 {
		err = errnoErr2(e1, e2)
	}
	return
}

//go:nosplit
func get_UnmountAddr() *(func(target string, flags int) (err error))

var Unmount = enter_Unmount

func enter_Unmount(target string, flags int) (err error) {
	funcref := get_UnmountAddr()
	if funcptrtest(GetZosLibVec()+SYS___UMOUNT2_A<<4, "") == 0 {
		*funcref = impl_Unmount
	} else {
		*funcref = legacyUnmount
	}
	return (*funcref)(target, flags)
}

func legacyUnmount(name string, mtm int) (err error) {
	// mountpoint is always a full path and starts with a '/'
	// check if input string is not a mountpoint but a filesystem name
	if name[0] != '/' {
		return unmount_LE(name, mtm)
	}
	// treat name as mountpoint
	b2s := func(arr []byte) string {
		var str string
		for i := 0; i < len(arr); i++ {
			if arr[i] == 0 {
				str = string(arr[:i])
				break
			}
		}
		return str
	}
	var buffer struct {
		header W_Mnth
		fsinfo [64]W_Mntent
	}
	fs_count, err := W_Getmntent_A((*byte)(unsafe.Pointer(&buffer)), int(unsafe.Sizeof(buffer)))
	if err == nil {
		err = EINVAL
		for i := 0; i < fs_count; i++ {
			if b2s(buffer.fsinfo[i].Mountpoint[:]) == name {
				err = unmount_LE(b2s(buffer.fsinfo[i].Fsname[:]), mtm)
				break
			}
		}
	} else if fs_count == 0 {
		err = EINVAL
	}
	return err
}

// Unmount end

func direntIno(buf []byte) (uint64, bool) {
	return readInt(buf, unsafe.Offsetof(Dirent{}.Ino), unsafe.Sizeof(Dirent{}.Ino))
}

func direntReclen(buf []byte) (uint64, bool) {
	return readInt(buf, unsafe.Offsetof(Dirent{}.Reclen), unsafe.Sizeof(Dirent{}.Reclen))
}

func direntNamlen(buf []byte) (uint64, bool) {
	reclen, ok := direntReclen(buf)
	if !ok {
		return 0, false
	}
	return reclen - uint64(unsafe.Offsetof(Dirent{}.Name)), true
}

func direntLeToDirentUnix(dirent *direntLE, dir uintptr, path string) (Dirent, error) {
	var d Dirent

	d.Ino = uint64(dirent.Ino)
	offset, err := Telldir(dir)
	if err != nil {
		return d, err
	}

	d.Off = int64(offset)
	s := string(bytes.Split(dirent.Name[:], []byte{0})[0])
	copy(d.Name[:], s)

	d.Reclen = uint16(24 + len(d.NameString()))
	var st Stat_t
	path = path + "/" + s
	err = Lstat(path, &st)
	if err != nil {
		return d, err
	}

	d.Type = uint8(st.Mode >> 24)
	return d, err
}

func Getdirentries(fd int, buf []byte, basep *uintptr) (n int, err error) {
	// Simulation of Getdirentries port from the Darwin implementation.
	// COMMENTS FROM DARWIN:
	// It's not the full required semantics, but should handle the case
	// of calling Getdirentries or ReadDirent repeatedly.
	// It won't handle assigning the results of lseek to *basep, or handle
	// the directory being edited underfoot.

	skip, err := Seek(fd, 0, 1 /* SEEK_CUR */)
	if err != nil {
		return 0, err
	}

	// Get path from fd to avoid unavailable call (fdopendir)
	path, err := ZosFdToPath(fd)
	if err != nil {
		return 0, err
	}
	d, err := Opendir(path)
	if err != nil {
		return 0, err
	}
	defer Closedir(d)

	var cnt int64
	for {
		var entryLE direntLE
		var entrypLE *direntLE
		e := Readdir_r(d, &entryLE, &entrypLE)
		if e != nil {
			return n, e
		}
		if entrypLE == nil {
			break
		}
		if skip > 0 {
			skip--
			cnt++
			continue
		}

		// Dirent on zos has a different structure
		entry, e := direntLeToDirentUnix(&entryLE, d, path)
		if e != nil {
			return n, e
		}

		reclen := int(entry.Reclen)
		if reclen > len(buf) {
			// Not enough room. Return for now.
			// The counter will let us know where we should start up again.
			// Note: this strategy for suspending in the middle and
			// restarting is O(n^2) in the length of the directory. Oh well.
			break
		}

		// Copy entry into return buffer.
		s := unsafe.Slice((*byte)(unsafe.Pointer(&entry)), reclen)
		copy(buf, s)

		buf = buf[reclen:]
		n += reclen
		cnt++
	}
	// Set the seek offset of the input fd to record
	// how many files we've already returned.
	_, err = Seek(fd, cnt, 0 /* SEEK_SET */)
	if err != nil {
		return n, err
	}

	return n, nil
}

func Err2ad() (eadd *int) {
	r0, _, _ := CallLeFuncWithErr(GetZosLibVec() + SYS___ERR2AD<<4)
	eadd = (*int)(unsafe.Pointer(r0))
	return
}

func ZosConsolePrintf(format string, v ...interface{}) (int, error) {
	type __cmsg struct {
		_            uint16
		_            [2]uint8
		__msg_length uint32
		__msg        uintptr
		_            [4]uint8
	}
	msg := fmt.Sprintf(format, v...)
	strptr := unsafe.Pointer((*reflect.StringHeader)(unsafe.Pointer(&msg)).Data)
	len := (*reflect.StringHeader)(unsafe.Pointer(&msg)).Len
	cmsg := __cmsg{__msg_length: uint32(len), __msg: uintptr(strptr)}
	cmd := uint32(0)
	runtime.EnterSyscall()
	rc, err2, err1 := CallLeFuncWithErr(GetZosLibVec()+SYS_____CONSOLE_A<<4, uintptr(unsafe.Pointer(&cmsg)), 0, uintptr(unsafe.Pointer(&cmd)))
	runtime.ExitSyscall()
	if rc != 0 {
		return 0, fmt.Errorf("%s (errno2=0x%x)\n", err1.Error(), err2)
	}
	return 0, nil
}
func ZosStringToEbcdicBytes(str string, nullterm bool) (ebcdicBytes []byte) {
	if nullterm {
		ebcdicBytes = []byte(str + "\x00")
	} else {
		ebcdicBytes = []byte(str)
	}
	A2e(ebcdicBytes)
	return
}
func ZosEbcdicBytesToString(b []byte, trimRight bool) (str string) {
	res := make([]byte, len(b))
	copy(res, b)
	E2a(res)
	if trimRight {
		str = string(bytes.TrimRight(res, " \x00"))
	} else {
		str = string(res)
	}
	return
}

func fdToPath(dirfd int) (path string, err error) {
	var buffer [1024]byte
	// w_ctrl()
	ret := runtime.CallLeFuncByPtr(runtime.XplinkLibvec+SYS_W_IOCTL<<4,
		[]uintptr{uintptr(dirfd), 17, 1024, uintptr(unsafe.Pointer(&buffer[0]))})
	if ret == 0 {
		zb := bytes.IndexByte(buffer[:], 0)
		if zb == -1 {
			zb = len(buffer)
		}
		// __e2a_l()
		runtime.CallLeFuncByPtr(runtime.XplinkLibvec+SYS___E2A_L<<4,
			[]uintptr{uintptr(unsafe.Pointer(&buffer[0])), uintptr(zb)})
		return string(buffer[:zb]), nil
	}
	// __errno()
	errno := int(*(*int32)(unsafe.Pointer(runtime.CallLeFuncByPtr(runtime.XplinkLibvec+SYS___ERRNO<<4,
		[]uintptr{}))))
	// __errno2()
	errno2 := int(runtime.CallLeFuncByPtr(runtime.XplinkLibvec+SYS___ERRNO2<<4,
		[]uintptr{}))
	// strerror_r()
	ret = runtime.CallLeFuncByPtr(runtime.XplinkLibvec+SYS_STRERROR_R<<4,
		[]uintptr{uintptr(errno), uintptr(unsafe.Pointer(&buffer[0])), 1024})
	if ret == 0 {
		zb := bytes.IndexByte(buffer[:], 0)
		if zb == -1 {
			zb = len(buffer)
		}
		return "", fmt.Errorf("%s (errno2=0x%x)", buffer[:zb], errno2)
	} else {
		return "", fmt.Errorf("fdToPath errno %d (errno2=0x%x)", errno, errno2)
	}
}

func impl_Mkfifoat(dirfd int, path string, mode uint32) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	runtime.EnterSyscall()
	r0, e2, e1 := CallLeFuncWithErr(GetZosLibVec()+SYS___MKFIFOAT_A<<4, uintptr(dirfd), uintptr(unsafe.Pointer(_p0)), uintptr(mode))
	runtime.ExitSyscall()
	if int64(r0) == -1 {
		err = errnoErr2(e1, e2)
	}
	return
}

//go:nosplit
func get_MkfifoatAddr() *(func(dirfd int, path string, mode uint32) (err error))

var Mkfifoat = enter_Mkfifoat

func enter_Mkfifoat(dirfd int, path string, mode uint32) (err error) {
	funcref := get_MkfifoatAddr()
	if funcptrtest(GetZosLibVec()+SYS___MKFIFOAT_A<<4, "") == 0 {
		*funcref = impl_Mkfifoat
	} else {
		*funcref = legacy_Mkfifoat
	}
	return (*funcref)(dirfd, path, mode)
}

func legacy_Mkfifoat(dirfd int, path string, mode uint32) (err error) {
	dirname, err := ZosFdToPath(dirfd)
	if err != nil {
		return err
	}
	return Mkfifo(dirname+"/"+path, mode)
}

//sys	Posix_openpt(oflag int) (fd int, err error) = SYS_POSIX_OPENPT
//sys	Grantpt(fildes int) (rc int, err error) = SYS_GRANTPT
//sys	Unlockpt(fildes int) (rc int, err error) = SYS_UNLOCKPT

func fcntlAsIs(fd uintptr, cmd int, arg uintptr) (val int, err error) {
	runtime.EnterSyscall()
	r0, e2, e1 := CallLeFuncWithErr(GetZosLibVec()+SYS_FCNTL<<4, uintptr(fd), uintptr(cmd), arg)
	runtime.ExitSyscall()
	val = int(r0)
	if int64(r0) == -1 {
		err = errnoErr2(e1, e2)
	}
	return
}

func Fcntl(fd uintptr, cmd int, op interface{}) (ret int, err error) {
	switch op.(type) {
	case *Flock_t:
		err = FcntlFlock(fd, cmd, op.(*Flock_t))
		if err != nil {
			ret = -1
		}
		return
	case int:
		return FcntlInt(fd, cmd, op.(int))
	case *F_cnvrt:
		return fcntlAsIs(fd, cmd, uintptr(unsafe.Pointer(op.(*F_cnvrt))))
	case unsafe.Pointer:
		return fcntlAsIs(fd, cmd, uintptr(op.(unsafe.Pointer)))
	default:
		return -1, EINVAL
	}
	return
}

func Sendfile(outfd int, infd int, offset *int64, count int) (written int, err error) {
	if raceenabled {
		raceReleaseMerge(unsafe.Pointer(&ioSync))
	}
	return sendfile(outfd, infd, offset, count)
}

func sendfile(outfd int, infd int, offset *int64, count int) (written int, err error) {
	// TODO: use LE call instead if the call is implemented
	originalOffset, err := Seek(infd, 0, SEEK_CUR)
	if err != nil {
		return -1, err
	}
	//start reading data from in_fd
	if offset != nil {
		_, err := Seek(infd, *offset, SEEK_SET)
		if err != nil {
			return -1, err
		}
	}

	buf := make([]byte, count)
	readBuf := make([]byte, 0)
	var n int = 0
	for i := 0; i < count; i += n {
		n, err := Read(infd, buf)
		if n == 0 {
			if err != nil {
				return -1, err
			} else { // EOF
				break
			}
		}
		readBuf = append(readBuf, buf...)
		buf = buf[0:0]
	}

	n2, err := Write(outfd, readBuf)
	if err != nil {
		return -1, err
	}

	//When sendfile() returns, this variable will be set to the
	// offset of the byte following the last byte that was read.
	if offset != nil {
		*offset = *offset + int64(n)
		// If offset is not NULL, then sendfile() does not modify the file
		// offset of in_fd
		_, err := Seek(infd, originalOffset, SEEK_SET)
		if err != nil {
			return -1, err
		}
	}
	return n2, nil
}

"""




```