Response:
The user wants to understand the functionality of a Go file containing constants related to system calls on Darwin/AMD64.

**Plan:**

1. **Identify the core purpose:** The file defines numerical constants for various system-level entities like socket options, file modes, and error/signal codes.
2. **Categorize the constants:** Group the constants into logical categories (e.g., socket options, file modes, errors, signals).
3. **Explain the significance:** Briefly describe what each category of constants is used for in system programming.
4. **Provide a Go code example:** Demonstrate how some of these constants are used with the `syscall` package.
5. **Infer the Go feature:** Explain that this file helps bridge the gap between Go and the underlying operating system's API.
6. **Address potential mistakes:**  Highlight a common pitfall when using these constants.
7. **Summarize the functionality for Part 2:**  Concisely describe the overall purpose of the file.
这是 Go 语言 `syscall` 包的一部分，用于在 Darwin (macOS) 操作系统上进行系统调用。

**功能列举:**

这个文件定义了一系列常量，这些常量代表了在 Darwin/AMD64 架构上的系统调用中使用的各种标识符和选项。主要包括：

1. **ioctl 请求码 (SIOC 开头的常量):**  用于网络接口控制操作，例如获取/设置接口的各种属性（IP地址、MAC地址、MTU等）。
2. **Socket 相关的常量 (SOCK_、SOL_、SOMAXCONN、SO_ 开头的常量):**  定义了 socket 的类型 (DGRAM, STREAM, RAW 等)、socket 选项 (REUSEADDR, KEEPALIVE, SNDBUF, RCVBUF 等) 和 socket 协议族 (LOCAL, SOCKET)。
3. **文件模式相关的常量 (S_IF 开头的文件类型常量，S_I 开头的权限常量):**  用于表示文件的类型 (目录、普通文件、socket 等) 和访问权限 (读、写、执行)。
4. **终端控制相关的常量 (TAB_、TCIFLUSH 等，TIOCCBRK 等):** 用于配置和控制终端的行为，例如波特率、回显、流控制等。这些常量用于 `termios` 相关的系统调用。
5. **TCP 选项相关的常量 (TCPOPT_、TCP_ 开头的常量):** 定义了 TCP 协议的各种选项，例如最大报文段大小 (MSS)、延迟 ACK、拥塞控制算法等。
6. **信号相关的常量 (SIG 开头的常量):**  代表各种系统信号，例如中断、终止、段错误等。
7. **错误码常量 (E 开头的常量):** 定义了各种系统调用可能返回的错误代码，方便程序根据不同的错误类型进行处理。
8. **文件属性标志常量 (UF_ 开头的常量):** 用于表示文件系统的特定属性，例如是否允许追加、是否被压缩等。
9. **其他常量 (V 开头的一些常量，WCONTINUED 等，XATTR_ 等):**  包括用于终端特殊字符的定义 (VEOF, VINTR 等)、进程状态相关的常量 (WEXITED, WSTOPPED 等) 和扩展属性相关的常量 (XATTR_CREATE, XATTR_REPLACE 等)。

**Go 语言功能实现示例:**

这个文件定义的是常量，它们本身并不构成一个完整的功能实现。它们是 `syscall` 包中其他函数的基础，用于和操作系统内核进行交互。以下是一些使用这些常量的 Go 代码示例：

**示例 1: 获取网络接口的 IP 地址**

```go
package main

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

func main() {
	ifaceName := "en0" // 假设要查询的网络接口是 en0

	// 打开一个 socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		fmt.Println("Error creating socket:", err)
		return
	}
	defer syscall.Close(fd)

	// 构建 ifreq 结构体
	var ifreq struct {
		Name [16]byte
		Addr syscall.RawSockaddrAny
		Data [16]byte // 填充其他数据
	}
	copy(ifreq.Name[:], ifaceName)

	// 发送 SIOCGIFADDR ioctl 请求
	_, _, ep := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCGIFADDR, uintptr(unsafe.Pointer(&ifreq)))
	if ep != 0 {
		fmt.Println("Error getting interface address:", syscall.Errno(ep))
		return
	}

	// 解析 IP 地址
	var sockaddrInet *syscall.SockaddrInet4 = (*syscall.SockaddrInet4)(unsafe.Pointer(&ifreq.Addr))
	ip := net.IPv4(sockaddrInet.Addr[0], sockaddrInet.Addr[1], sockaddrInet.Addr[2], sockaddrInet.Addr[3])

	fmt.Printf("IP address of %s: %s\n", ifaceName, ip.String())
}
```

**假设输入与输出:**

假设网络接口 "en0" 的 IP 地址是 192.168.1.100。

**输出:**

```
IP address of en0: 192.168.1.100
```

**代码推理:**

这段代码使用了 `syscall.Socket` 创建了一个 socket，然后构造了一个 `ifreq` 结构体，并将接口名称填入。 接着，它使用了 `syscall.Syscall` 发起了 `SIOCGIFADDR` 的 ioctl 请求。`SIOCGIFADDR` 常量定义在这个文件中，它告诉内核我们要获取指定网络接口的地址信息。内核会将接口的地址信息填充到 `ifreq` 结构体中，最后我们解析出 IP 地址并打印。

**示例 2: 设置 socket 的 REUSEADDR 选项**

```go
package main

import (
	"fmt"
	"syscall"
)

func main() {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		fmt.Println("Error creating socket:", err)
		return
	}
	defer syscall.Close(fd)

	// 设置 SO_REUSEADDR 选项
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	if err != nil {
		fmt.Println("Error setting SO_REUSEADDR:", err)
		return
	}

	fmt.Println("SO_REUSEADDR option set successfully.")
}
```

**假设输入与输出:**

无特定的输入，这是一个设置 socket 选项的操作。

**输出:**

```
SO_REUSEADDR option set successfully.
```

**代码推理:**

这段代码创建了一个 TCP socket。然后，它使用 `syscall.SetsockoptInt` 函数来设置 `SO_REUSEADDR` 选项。`SOL_SOCKET` 和 `SO_REUSEADDR` 都是在这个文件中定义的常量。设置 `SO_REUSEADDR` 可以使服务器在关闭后立即重新绑定到相同的地址和端口，而无需等待操作系统释放资源。

**命令行参数的具体处理:**

这个文件本身不处理命令行参数。它只是定义常量。命令行参数的处理通常发生在 `main` 函数中，使用 `os.Args` 获取参数，并根据参数的值来决定调用哪些使用了这些常量的系统调用。

**易犯错的点:**

* **平台依赖性:** 这些常量是特定于 Darwin/AMD64 平台的。如果你的代码需要在其他操作系统或架构上运行，你需要使用相应的 `zerrors_*.go` 文件或者使用更高级、平台无关的网络和系统编程库（如 `net` 包）。直接使用这些常量可能会导致在其他平台上编译或运行时出现错误。

**示例 (错误用法):**

```go
package main

import (
	"fmt"
	"syscall"
)

func main() {
	// 假设在 Linux 系统上运行这段代码
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		fmt.Println("Error creating socket:", err)
		return
	}
	defer syscall.Close(fd)

	// 尝试使用 Darwin 特有的常量，可能导致错误或未定义的行为
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, 0xffff, 1) // 0xffff 是 Darwin 上 SOL_SOCKET 的值
	if err != nil {
		fmt.Println("Error setting socket option:", err)
		return
	}

	fmt.Println("Socket option set (potentially incorrectly on this platform).")
}
```

在 Linux 上，`syscall.SOL_SOCKET` 的值可能与 Darwin 上不同，直接使用 Darwin 的常量值会导致错误或者设置了错误的 socket 选项。

**功能归纳 (第 2 部分):**

总而言之，`go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_darwin_amd64.go` 这个文件定义了在 Darwin/AMD64 架构下进行底层系统编程时需要用到的各种常量，涵盖了网络接口控制、socket 编程、文件操作、终端控制、TCP 协议选项、信号处理和错误代码等多个方面。它是 Go 语言 `syscall` 包与 Darwin 操作系统内核交互的基础，使得 Go 程序能够执行底层的系统调用操作。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_darwin_amd64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
= 0x80206939
	SIOCSIFKPI                              = 0x80206986
	SIOCSIFLLADDR                           = 0x8020693c
	SIOCSIFMAC                              = 0x80206983
	SIOCSIFMEDIA                            = 0xc0206937
	SIOCSIFMETRIC                           = 0x80206918
	SIOCSIFMTU                              = 0x80206934
	SIOCSIFNETMASK                          = 0x80206916
	SIOCSIFPHYADDR                          = 0x8040693e
	SIOCSIFPHYS                             = 0x80206936
	SIOCSIFVLAN                             = 0x8020697e
	SIOCSLOWAT                              = 0x80047302
	SIOCSPGRP                               = 0x80047308
	SOCK_DGRAM                              = 0x2
	SOCK_MAXADDRLEN                         = 0xff
	SOCK_RAW                                = 0x3
	SOCK_RDM                                = 0x4
	SOCK_SEQPACKET                          = 0x5
	SOCK_STREAM                             = 0x1
	SOL_LOCAL                               = 0x0
	SOL_SOCKET                              = 0xffff
	SOMAXCONN                               = 0x80
	SO_ACCEPTCONN                           = 0x2
	SO_BROADCAST                            = 0x20
	SO_DEBUG                                = 0x1
	SO_DONTROUTE                            = 0x10
	SO_DONTTRUNC                            = 0x2000
	SO_ERROR                                = 0x1007
	SO_KEEPALIVE                            = 0x8
	SO_LABEL                                = 0x1010
	SO_LINGER                               = 0x80
	SO_LINGER_SEC                           = 0x1080
	SO_NETSVC_MARKING_LEVEL                 = 0x1119
	SO_NET_SERVICE_TYPE                     = 0x1116
	SO_NKE                                  = 0x1021
	SO_NOADDRERR                            = 0x1023
	SO_NOSIGPIPE                            = 0x1022
	SO_NOTIFYCONFLICT                       = 0x1026
	SO_NP_EXTENSIONS                        = 0x1083
	SO_NREAD                                = 0x1020
	SO_NUMRCVPKT                            = 0x1112
	SO_NWRITE                               = 0x1024
	SO_OOBINLINE                            = 0x100
	SO_PEERLABEL                            = 0x1011
	SO_RANDOMPORT                           = 0x1082
	SO_RCVBUF                               = 0x1002
	SO_RCVLOWAT                             = 0x1004
	SO_RCVTIMEO                             = 0x1006
	SO_REUSEADDR                            = 0x4
	SO_REUSEPORT                            = 0x200
	SO_REUSESHAREUID                        = 0x1025
	SO_SNDBUF                               = 0x1001
	SO_SNDLOWAT                             = 0x1003
	SO_SNDTIMEO                             = 0x1005
	SO_TIMESTAMP                            = 0x400
	SO_TIMESTAMP_MONOTONIC                  = 0x800
	SO_TRACKER_ATTRIBUTE_FLAGS_APP_APPROVED = 0x1
	SO_TRACKER_ATTRIBUTE_FLAGS_DOMAIN_SHORT = 0x4
	SO_TRACKER_ATTRIBUTE_FLAGS_TRACKER      = 0x2
	SO_TRACKER_TRANSPARENCY_VERSION         = 0x3
	SO_TYPE                                 = 0x1008
	SO_UPCALLCLOSEWAIT                      = 0x1027
	SO_USELOOPBACK                          = 0x40
	SO_WANTMORE                             = 0x4000
	SO_WANTOOBFLAG                          = 0x8000
	S_IEXEC                                 = 0x40
	S_IFBLK                                 = 0x6000
	S_IFCHR                                 = 0x2000
	S_IFDIR                                 = 0x4000
	S_IFIFO                                 = 0x1000
	S_IFLNK                                 = 0xa000
	S_IFMT                                  = 0xf000
	S_IFREG                                 = 0x8000
	S_IFSOCK                                = 0xc000
	S_IFWHT                                 = 0xe000
	S_IREAD                                 = 0x100
	S_IRGRP                                 = 0x20
	S_IROTH                                 = 0x4
	S_IRUSR                                 = 0x100
	S_IRWXG                                 = 0x38
	S_IRWXO                                 = 0x7
	S_IRWXU                                 = 0x1c0
	S_ISGID                                 = 0x400
	S_ISTXT                                 = 0x200
	S_ISUID                                 = 0x800
	S_ISVTX                                 = 0x200
	S_IWGRP                                 = 0x10
	S_IWOTH                                 = 0x2
	S_IWRITE                                = 0x80
	S_IWUSR                                 = 0x80
	S_IXGRP                                 = 0x8
	S_IXOTH                                 = 0x1
	S_IXUSR                                 = 0x40
	TAB0                                    = 0x0
	TAB1                                    = 0x400
	TAB2                                    = 0x800
	TAB3                                    = 0x4
	TABDLY                                  = 0xc04
	TCIFLUSH                                = 0x1
	TCIOFF                                  = 0x3
	TCIOFLUSH                               = 0x3
	TCION                                   = 0x4
	TCOFLUSH                                = 0x2
	TCOOFF                                  = 0x1
	TCOON                                   = 0x2
	TCPOPT_CC                               = 0xb
	TCPOPT_CCECHO                           = 0xd
	TCPOPT_CCNEW                            = 0xc
	TCPOPT_EOL                              = 0x0
	TCPOPT_FASTOPEN                         = 0x22
	TCPOPT_MAXSEG                           = 0x2
	TCPOPT_NOP                              = 0x1
	TCPOPT_SACK                             = 0x5
	TCPOPT_SACK_HDR                         = 0x1010500
	TCPOPT_SACK_PERMITTED                   = 0x4
	TCPOPT_SACK_PERMIT_HDR                  = 0x1010402
	TCPOPT_SIGNATURE                        = 0x13
	TCPOPT_TIMESTAMP                        = 0x8
	TCPOPT_TSTAMP_HDR                       = 0x101080a
	TCPOPT_WINDOW                           = 0x3
	TCP_CONNECTIONTIMEOUT                   = 0x20
	TCP_CONNECTION_INFO                     = 0x106
	TCP_ENABLE_ECN                          = 0x104
	TCP_FASTOPEN                            = 0x105
	TCP_KEEPALIVE                           = 0x10
	TCP_KEEPCNT                             = 0x102
	TCP_KEEPINTVL                           = 0x101
	TCP_MAXHLEN                             = 0x3c
	TCP_MAXOLEN                             = 0x28
	TCP_MAXSEG                              = 0x2
	TCP_MAXWIN                              = 0xffff
	TCP_MAX_SACK                            = 0x4
	TCP_MAX_WINSHIFT                        = 0xe
	TCP_MINMSS                              = 0xd8
	TCP_MSS                                 = 0x200
	TCP_NODELAY                             = 0x1
	TCP_NOOPT                               = 0x8
	TCP_NOPUSH                              = 0x4
	TCP_NOTSENT_LOWAT                       = 0x201
	TCP_RXT_CONNDROPTIME                    = 0x80
	TCP_RXT_FINDROP                         = 0x100
	TCP_SENDMOREACKS                        = 0x103
	TCSAFLUSH                               = 0x2
	TIOCCBRK                                = 0x2000747a
	TIOCCDTR                                = 0x20007478
	TIOCCONS                                = 0x80047462
	TIOCDCDTIMESTAMP                        = 0x40107458
	TIOCDRAIN                               = 0x2000745e
	TIOCDSIMICROCODE                        = 0x20007455
	TIOCEXCL                                = 0x2000740d
	TIOCEXT                                 = 0x80047460
	TIOCFLUSH                               = 0x80047410
	TIOCGDRAINWAIT                          = 0x40047456
	TIOCGETA                                = 0x40487413
	TIOCGETD                                = 0x4004741a
	TIOCGPGRP                               = 0x40047477
	TIOCGWINSZ                              = 0x40087468
	TIOCIXOFF                               = 0x20007480
	TIOCIXON                                = 0x20007481
	TIOCMBIC                                = 0x8004746b
	TIOCMBIS                                = 0x8004746c
	TIOCMGDTRWAIT                           = 0x4004745a
	TIOCMGET                                = 0x4004746a
	TIOCMODG                                = 0x40047403
	TIOCMODS                                = 0x80047404
	TIOCMSDTRWAIT                           = 0x8004745b
	TIOCMSET                                = 0x8004746d
	TIOCM_CAR                               = 0x40
	TIOCM_CD                                = 0x40
	TIOCM_CTS                               = 0x20
	TIOCM_DSR                               = 0x100
	TIOCM_DTR                               = 0x2
	TIOCM_LE                                = 0x1
	TIOCM_RI                                = 0x80
	TIOCM_RNG                               = 0x80
	TIOCM_RTS                               = 0x4
	TIOCM_SR                                = 0x10
	TIOCM_ST                                = 0x8
	TIOCNOTTY                               = 0x20007471
	TIOCNXCL                                = 0x2000740e
	TIOCOUTQ                                = 0x40047473
	TIOCPKT                                 = 0x80047470
	TIOCPKT_DATA                            = 0x0
	TIOCPKT_DOSTOP                          = 0x20
	TIOCPKT_FLUSHREAD                       = 0x1
	TIOCPKT_FLUSHWRITE                      = 0x2
	TIOCPKT_IOCTL                           = 0x40
	TIOCPKT_NOSTOP                          = 0x10
	TIOCPKT_START                           = 0x8
	TIOCPKT_STOP                            = 0x4
	TIOCPTYGNAME                            = 0x40807453
	TIOCPTYGRANT                            = 0x20007454
	TIOCPTYUNLK                             = 0x20007452
	TIOCREMOTE                              = 0x80047469
	TIOCSBRK                                = 0x2000747b
	TIOCSCONS                               = 0x20007463
	TIOCSCTTY                               = 0x20007461
	TIOCSDRAINWAIT                          = 0x80047457
	TIOCSDTR                                = 0x20007479
	TIOCSETA                                = 0x80487414
	TIOCSETAF                               = 0x80487416
	TIOCSETAW                               = 0x80487415
	TIOCSETD                                = 0x8004741b
	TIOCSIG                                 = 0x2000745f
	TIOCSPGRP                               = 0x80047476
	TIOCSTART                               = 0x2000746e
	TIOCSTAT                                = 0x20007465
	TIOCSTI                                 = 0x80017472
	TIOCSTOP                                = 0x2000746f
	TIOCSWINSZ                              = 0x80087467
	TIOCTIMESTAMP                           = 0x40107459
	TIOCUCNTL                               = 0x80047466
	TOSTOP                                  = 0x400000
	UF_APPEND                               = 0x4
	UF_COMPRESSED                           = 0x20
	UF_DATAVAULT                            = 0x80
	UF_HIDDEN                               = 0x8000
	UF_IMMUTABLE                            = 0x2
	UF_NODUMP                               = 0x1
	UF_OPAQUE                               = 0x8
	UF_SETTABLE                             = 0xffff
	UF_TRACKED                              = 0x40
	VDISCARD                                = 0xf
	VDSUSP                                  = 0xb
	VEOF                                    = 0x0
	VEOL                                    = 0x1
	VEOL2                                   = 0x2
	VERASE                                  = 0x3
	VINTR                                   = 0x8
	VKILL                                   = 0x5
	VLNEXT                                  = 0xe
	VMADDR_CID_ANY                          = 0xffffffff
	VMADDR_CID_HOST                         = 0x2
	VMADDR_CID_HYPERVISOR                   = 0x0
	VMADDR_CID_RESERVED                     = 0x1
	VMADDR_PORT_ANY                         = 0xffffffff
	VMIN                                    = 0x10
	VM_LOADAVG                              = 0x2
	VM_MACHFACTOR                           = 0x4
	VM_MAXID                                = 0x6
	VM_METER                                = 0x1
	VM_SWAPUSAGE                            = 0x5
	VQUIT                                   = 0x9
	VREPRINT                                = 0x6
	VSTART                                  = 0xc
	VSTATUS                                 = 0x12
	VSTOP                                   = 0xd
	VSUSP                                   = 0xa
	VT0                                     = 0x0
	VT1                                     = 0x10000
	VTDLY                                   = 0x10000
	VTIME                                   = 0x11
	VWERASE                                 = 0x4
	WCONTINUED                              = 0x10
	WCOREFLAG                               = 0x80
	WEXITED                                 = 0x4
	WNOHANG                                 = 0x1
	WNOWAIT                                 = 0x20
	WORDSIZE                                = 0x40
	WSTOPPED                                = 0x8
	WUNTRACED                               = 0x2
	XATTR_CREATE                            = 0x2
	XATTR_NODEFAULT                         = 0x10
	XATTR_NOFOLLOW                          = 0x1
	XATTR_NOSECURITY                        = 0x8
	XATTR_REPLACE                           = 0x4
	XATTR_SHOWCOMPRESSION                   = 0x20
)

// Errors
const (
	E2BIG           = syscall.Errno(0x7)
	EACCES          = syscall.Errno(0xd)
	EADDRINUSE      = syscall.Errno(0x30)
	EADDRNOTAVAIL   = syscall.Errno(0x31)
	EAFNOSUPPORT    = syscall.Errno(0x2f)
	EAGAIN          = syscall.Errno(0x23)
	EALREADY        = syscall.Errno(0x25)
	EAUTH           = syscall.Errno(0x50)
	EBADARCH        = syscall.Errno(0x56)
	EBADEXEC        = syscall.Errno(0x55)
	EBADF           = syscall.Errno(0x9)
	EBADMACHO       = syscall.Errno(0x58)
	EBADMSG         = syscall.Errno(0x5e)
	EBADRPC         = syscall.Errno(0x48)
	EBUSY           = syscall.Errno(0x10)
	ECANCELED       = syscall.Errno(0x59)
	ECHILD          = syscall.Errno(0xa)
	ECONNABORTED    = syscall.Errno(0x35)
	ECONNREFUSED    = syscall.Errno(0x3d)
	ECONNRESET      = syscall.Errno(0x36)
	EDEADLK         = syscall.Errno(0xb)
	EDESTADDRREQ    = syscall.Errno(0x27)
	EDEVERR         = syscall.Errno(0x53)
	EDOM            = syscall.Errno(0x21)
	EDQUOT          = syscall.Errno(0x45)
	EEXIST          = syscall.Errno(0x11)
	EFAULT          = syscall.Errno(0xe)
	EFBIG           = syscall.Errno(0x1b)
	EFTYPE          = syscall.Errno(0x4f)
	EHOSTDOWN       = syscall.Errno(0x40)
	EHOSTUNREACH    = syscall.Errno(0x41)
	EIDRM           = syscall.Errno(0x5a)
	EILSEQ          = syscall.Errno(0x5c)
	EINPROGRESS     = syscall.Errno(0x24)
	EINTR           = syscall.Errno(0x4)
	EINVAL          = syscall.Errno(0x16)
	EIO             = syscall.Errno(0x5)
	EISCONN         = syscall.Errno(0x38)
	EISDIR          = syscall.Errno(0x15)
	ELAST           = syscall.Errno(0x6a)
	ELOOP           = syscall.Errno(0x3e)
	EMFILE          = syscall.Errno(0x18)
	EMLINK          = syscall.Errno(0x1f)
	EMSGSIZE        = syscall.Errno(0x28)
	EMULTIHOP       = syscall.Errno(0x5f)
	ENAMETOOLONG    = syscall.Errno(0x3f)
	ENEEDAUTH       = syscall.Errno(0x51)
	ENETDOWN        = syscall.Errno(0x32)
	ENETRESET       = syscall.Errno(0x34)
	ENETUNREACH     = syscall.Errno(0x33)
	ENFILE          = syscall.Errno(0x17)
	ENOATTR         = syscall.Errno(0x5d)
	ENOBUFS         = syscall.Errno(0x37)
	ENODATA         = syscall.Errno(0x60)
	ENODEV          = syscall.Errno(0x13)
	ENOENT          = syscall.Errno(0x2)
	ENOEXEC         = syscall.Errno(0x8)
	ENOLCK          = syscall.Errno(0x4d)
	ENOLINK         = syscall.Errno(0x61)
	ENOMEM          = syscall.Errno(0xc)
	ENOMSG          = syscall.Errno(0x5b)
	ENOPOLICY       = syscall.Errno(0x67)
	ENOPROTOOPT     = syscall.Errno(0x2a)
	ENOSPC          = syscall.Errno(0x1c)
	ENOSR           = syscall.Errno(0x62)
	ENOSTR          = syscall.Errno(0x63)
	ENOSYS          = syscall.Errno(0x4e)
	ENOTBLK         = syscall.Errno(0xf)
	ENOTCONN        = syscall.Errno(0x39)
	ENOTDIR         = syscall.Errno(0x14)
	ENOTEMPTY       = syscall.Errno(0x42)
	ENOTRECOVERABLE = syscall.Errno(0x68)
	ENOTSOCK        = syscall.Errno(0x26)
	ENOTSUP         = syscall.Errno(0x2d)
	ENOTTY          = syscall.Errno(0x19)
	ENXIO           = syscall.Errno(0x6)
	EOPNOTSUPP      = syscall.Errno(0x66)
	EOVERFLOW       = syscall.Errno(0x54)
	EOWNERDEAD      = syscall.Errno(0x69)
	EPERM           = syscall.Errno(0x1)
	EPFNOSUPPORT    = syscall.Errno(0x2e)
	EPIPE           = syscall.Errno(0x20)
	EPROCLIM        = syscall.Errno(0x43)
	EPROCUNAVAIL    = syscall.Errno(0x4c)
	EPROGMISMATCH   = syscall.Errno(0x4b)
	EPROGUNAVAIL    = syscall.Errno(0x4a)
	EPROTO          = syscall.Errno(0x64)
	EPROTONOSUPPORT = syscall.Errno(0x2b)
	EPROTOTYPE      = syscall.Errno(0x29)
	EPWROFF         = syscall.Errno(0x52)
	EQFULL          = syscall.Errno(0x6a)
	ERANGE          = syscall.Errno(0x22)
	EREMOTE         = syscall.Errno(0x47)
	EROFS           = syscall.Errno(0x1e)
	ERPCMISMATCH    = syscall.Errno(0x49)
	ESHLIBVERS      = syscall.Errno(0x57)
	ESHUTDOWN       = syscall.Errno(0x3a)
	ESOCKTNOSUPPORT = syscall.Errno(0x2c)
	ESPIPE          = syscall.Errno(0x1d)
	ESRCH           = syscall.Errno(0x3)
	ESTALE          = syscall.Errno(0x46)
	ETIME           = syscall.Errno(0x65)
	ETIMEDOUT       = syscall.Errno(0x3c)
	ETOOMANYREFS    = syscall.Errno(0x3b)
	ETXTBSY         = syscall.Errno(0x1a)
	EUSERS          = syscall.Errno(0x44)
	EWOULDBLOCK     = syscall.Errno(0x23)
	EXDEV           = syscall.Errno(0x12)
)

// Signals
const (
	SIGABRT   = syscall.Signal(0x6)
	SIGALRM   = syscall.Signal(0xe)
	SIGBUS    = syscall.Signal(0xa)
	SIGCHLD   = syscall.Signal(0x14)
	SIGCONT   = syscall.Signal(0x13)
	SIGEMT    = syscall.Signal(0x7)
	SIGFPE    = syscall.Signal(0x8)
	SIGHUP    = syscall.Signal(0x1)
	SIGILL    = syscall.Signal(0x4)
	SIGINFO   = syscall.Signal(0x1d)
	SIGINT    = syscall.Signal(0x2)
	SIGIO     = syscall.Signal(0x17)
	SIGIOT    = syscall.Signal(0x6)
	SIGKILL   = syscall.Signal(0x9)
	SIGPIPE   = syscall.Signal(0xd)
	SIGPROF   = syscall.Signal(0x1b)
	SIGQUIT   = syscall.Signal(0x3)
	SIGSEGV   = syscall.Signal(0xb)
	SIGSTOP   = syscall.Signal(0x11)
	SIGSYS    = syscall.Signal(0xc)
	SIGTERM   = syscall.Signal(0xf)
	SIGTRAP   = syscall.Signal(0x5)
	SIGTSTP   = syscall.Signal(0x12)
	SIGTTIN   = syscall.Signal(0x15)
	SIGTTOU   = syscall.Signal(0x16)
	SIGURG    = syscall.Signal(0x10)
	SIGUSR1   = syscall.Signal(0x1e)
	SIGUSR2   = syscall.Signal(0x1f)
	SIGVTALRM = syscall.Signal(0x1a)
	SIGWINCH  = syscall.Signal(0x1c)
	SIGXCPU   = syscall.Signal(0x18)
	SIGXFSZ   = syscall.Signal(0x19)
)

// Error table
var errorList = [...]struct {
	num  syscall.Errno
	name string
	desc string
}{
	{1, "EPERM", "operation not permitted"},
	{2, "ENOENT", "no such file or directory"},
	{3, "ESRCH", "no such process"},
	{4, "EINTR", "interrupted system call"},
	{5, "EIO", "input/output error"},
	{6, "ENXIO", "device not configured"},
	{7, "E2BIG", "argument list too long"},
	{8, "ENOEXEC", "exec format error"},
	{9, "EBADF", "bad file descriptor"},
	{10, "ECHILD", "no child processes"},
	{11, "EDEADLK", "resource deadlock avoided"},
	{12, "ENOMEM", "cannot allocate memory"},
	{13, "EACCES", "permission denied"},
	{14, "EFAULT", "bad address"},
	{15, "ENOTBLK", "block device required"},
	{16, "EBUSY", "resource busy"},
	{17, "EEXIST", "file exists"},
	{18, "EXDEV", "cross-device link"},
	{19, "ENODEV", "operation not supported by device"},
	{20, "ENOTDIR", "not a directory"},
	{21, "EISDIR", "is a directory"},
	{22, "EINVAL", "invalid argument"},
	{23, "ENFILE", "too many open files in system"},
	{24, "EMFILE", "too many open files"},
	{25, "ENOTTY", "inappropriate ioctl for device"},
	{26, "ETXTBSY", "text file busy"},
	{27, "EFBIG", "file too large"},
	{28, "ENOSPC", "no space left on device"},
	{29, "ESPIPE", "illegal seek"},
	{30, "EROFS", "read-only file system"},
	{31, "EMLINK", "too many links"},
	{32, "EPIPE", "broken pipe"},
	{33, "EDOM", "numerical argument out of domain"},
	{34, "ERANGE", "result too large"},
	{35, "EAGAIN", "resource temporarily unavailable"},
	{36, "EINPROGRESS", "operation now in progress"},
	{37, "EALREADY", "operation already in progress"},
	{38, "ENOTSOCK", "socket operation on non-socket"},
	{39, "EDESTADDRREQ", "destination address required"},
	{40, "EMSGSIZE", "message too long"},
	{41, "EPROTOTYPE", "protocol wrong type for socket"},
	{42, "ENOPROTOOPT", "protocol not available"},
	{43, "EPROTONOSUPPORT", "protocol not supported"},
	{44, "ESOCKTNOSUPPORT", "socket type not supported"},
	{45, "ENOTSUP", "operation not supported"},
	{46, "EPFNOSUPPORT", "protocol family not supported"},
	{47, "EAFNOSUPPORT", "address family not supported by protocol family"},
	{48, "EADDRINUSE", "address already in use"},
	{49, "EADDRNOTAVAIL", "can't assign requested address"},
	{50, "ENETDOWN", "network is down"},
	{51, "ENETUNREACH", "network is unreachable"},
	{52, "ENETRESET", "network dropped connection on reset"},
	{53, "ECONNABORTED", "software caused connection abort"},
	{54, "ECONNRESET", "connection reset by peer"},
	{55, "ENOBUFS", "no buffer space available"},
	{56, "EISCONN", "socket is already connected"},
	{57, "ENOTCONN", "socket is not connected"},
	{58, "ESHUTDOWN", "can't send after socket shutdown"},
	{59, "ETOOMANYREFS", "too many references: can't splice"},
	{60, "ETIMEDOUT", "operation timed out"},
	{61, "ECONNREFUSED", "connection refused"},
	{62, "ELOOP", "too many levels of symbolic links"},
	{63, "ENAMETOOLONG", "file name too long"},
	{64, "EHOSTDOWN", "host is down"},
	{65, "EHOSTUNREACH", "no route to host"},
	{66, "ENOTEMPTY", "directory not empty"},
	{67, "EPROCLIM", "too many processes"},
	{68, "EUSERS", "too many users"},
	{69, "EDQUOT", "disc quota exceeded"},
	{70, "ESTALE", "stale NFS file handle"},
	{71, "EREMOTE", "too many levels of remote in path"},
	{72, "EBADRPC", "RPC struct is bad"},
	{73, "ERPCMISMATCH", "RPC version wrong"},
	{74, "EPROGUNAVAIL", "RPC prog. not avail"},
	{75, "EPROGMISMATCH", "program version wrong"},
	{76, "EPROCUNAVAIL", "bad procedure for program"},
	{77, "ENOLCK", "no locks available"},
	{78, "ENOSYS", "function not implemented"},
	{79, "EFTYPE", "inappropriate file type or format"},
	{80, "EAUTH", "authentication error"},
	{81, "ENEEDAUTH", "need authenticator"},
	{82, "EPWROFF", "device power is off"},
	{83, "EDEVERR", "device error"},
	{84, "EOVERFLOW", "value too large to be stored in data type"},
	{85, "EBADEXEC", "bad executable (or shared library)"},
	{86, "EBADARCH", "bad CPU type in executable"},
	{87, "ESHLIBVERS", "shared library version mismatch"},
	{88, "EBADMACHO", "malformed Mach-o file"},
	{89, "ECANCELED", "operation canceled"},
	{90, "EIDRM", "identifier removed"},
	{91, "ENOMSG", "no message of desired type"},
	{92, "EILSEQ", "illegal byte sequence"},
	{93, "ENOATTR", "attribute not found"},
	{94, "EBADMSG", "bad message"},
	{95, "EMULTIHOP", "EMULTIHOP (Reserved)"},
	{96, "ENODATA", "no message available on STREAM"},
	{97, "ENOLINK", "ENOLINK (Reserved)"},
	{98, "ENOSR", "no STREAM resources"},
	{99, "ENOSTR", "not a STREAM"},
	{100, "EPROTO", "protocol error"},
	{101, "ETIME", "STREAM ioctl timeout"},
	{102, "EOPNOTSUPP", "operation not supported on socket"},
	{103, "ENOPOLICY", "policy not found"},
	{104, "ENOTRECOVERABLE", "state not recoverable"},
	{105, "EOWNERDEAD", "previous owner died"},
	{106, "EQFULL", "interface output queue is full"},
}

// Signal table
var signalList = [...]struct {
	num  syscall.Signal
	name string
	desc string
}{
	{1, "SIGHUP", "hangup"},
	{2, "SIGINT", "interrupt"},
	{3, "SIGQUIT", "quit"},
	{4, "SIGILL", "illegal instruction"},
	{5, "SIGTRAP", "trace/BPT trap"},
	{6, "SIGABRT", "abort trap"},
	{7, "SIGEMT", "EMT trap"},
	{8, "SIGFPE", "floating point exception"},
	{9, "SIGKILL", "killed"},
	{10, "SIGBUS", "bus error"},
	{11, "SIGSEGV", "segmentation fault"},
	{12, "SIGSYS", "bad system call"},
	{13, "SIGPIPE", "broken pipe"},
	{14, "SIGALRM", "alarm clock"},
	{15, "SIGTERM", "terminated"},
	{16, "SIGURG", "urgent I/O condition"},
	{17, "SIGSTOP", "suspended (signal)"},
	{18, "SIGTSTP", "suspended"},
	{19, "SIGCONT", "continued"},
	{20, "SIGCHLD", "child exited"},
	{21, "SIGTTIN", "stopped (tty input)"},
	{22, "SIGTTOU", "stopped (tty output)"},
	{23, "SIGIO", "I/O possible"},
	{24, "SIGXCPU", "cputime limit exceeded"},
	{25, "SIGXFSZ", "filesize limit exceeded"},
	{26, "SIGVTALRM", "virtual timer expired"},
	{27, "SIGPROF", "profiling timer expired"},
	{28, "SIGWINCH", "window size changes"},
	{29, "SIGINFO", "information request"},
	{30, "SIGUSR1", "user defined signal 1"},
	{31, "SIGUSR2", "user defined signal 2"},
}
```