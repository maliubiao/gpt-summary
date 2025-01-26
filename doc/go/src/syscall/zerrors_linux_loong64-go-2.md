Response:
The user provided the third part of a Go source code file (`zerrors_linux_loong64.go`) which defines constants for system calls, errors, and signals specific to the Linux operating system on the LoongArch 64-bit architecture. The request asks for a summary of its functionality, assuming it's the final part of a three-part series.

Here's a breakdown of how to arrive at the answer:

1. **Identify the core components:**  The provided code snippet mainly defines three groups of constants:
    * Constants related to file permissions and terminal control (starting with `S_` and `TC`).
    * Constants related to TCP socket options (starting with `TCP_`).
    * Constants related to terminal I/O control (starting with `TIOC`).
    * Constants related to `TUN` (network tunnel) devices.
    * Constants related to terminal special characters (starting with `V`).
    * Constants related to process wait options (starting with `W`).
    * Error codes (starting with `E`).
    * Signal numbers (starting with `SIG`).
    * String representations for error codes (the `errors` array).
    * String representations for signal numbers (the `signals` array).

2. **Infer the purpose of each component:**
    * File permissions (`S_IRWXU`, etc.) are used to control access rights to files and directories.
    * Terminal control constants (`TCFLSH`, `TIOCCBRK`, etc.) are used to manipulate terminal settings, like flushing buffers, sending break signals, and getting/setting various terminal attributes.
    * TCP constants (`TCP_CORK`, `TCP_NODELAY`, etc.) are used to configure the behavior of TCP sockets, such as enabling Nagle's algorithm, setting timeouts, and managing connection state.
    * TUN constants (`TUNSETIFF`, `TUNGETIFF`, etc.) are used to configure virtual network interface tunnels.
    * Terminal special character constants (`VEOF`, `VINTR`, etc.) define specific characters that have special meaning in terminal input, like end-of-file or interrupt.
    * Process wait constants (`WEXITED`, `WNOHANG`, etc.) are used with system calls like `wait` or `waitpid` to specify the conditions under which a process should be considered to have terminated.
    * Error codes (`EACCES`, `ENOENT`, etc.) represent different types of errors that can occur during system calls.
    * Signal numbers (`SIGINT`, `SIGKILL`, etc.) represent different types of signals that can be sent to a process to notify it of an event or request an action.
    * The `errors` and `signals` arrays provide human-readable descriptions for the numeric error and signal codes.

3. **Connect to Go's `syscall` package:** Recognizing the file path `go/src/syscall/zerrors_linux_loong64.go`, it's clear this code is part of Go's standard library, specifically the `syscall` package. This package provides a low-level interface to the operating system's system calls.

4. **Consider the "part 3" context:** Knowing this is the final part suggests the earlier parts likely defined other system call-related constants. This part likely focuses on terminal control, network configuration (TCP), and providing string representations for errors and signals.

5. **Formulate the summary:** Based on the above analysis, the code's primary function is to define constants used for interacting with the Linux kernel on the LoongArch 64-bit architecture. This includes constants for file operations, network settings, terminal control, and error/signal handling. The `errors` and `signals` arrays provide a way to convert numeric error and signal codes into human-readable strings, which is crucial for debugging and error reporting.

6. **Refine the language:**  Ensure the summary is clear, concise, and uses appropriate technical terminology. Emphasize the low-level nature and the target architecture.
这是Go语言标准库 `syscall` 包的一部分，专门针对 Linux 操作系统在 LoongArch 64 位架构上的实现。这个文件的主要功能是定义了一系列常量，这些常量用于与底层的 Linux 系统调用进行交互。

具体来说，这部分代码定义了以下几类常量：

1. **文件和目录操作相关的常量:** 例如 `S_IRWXU`, `S_ISGID`, `S_ISUID` 等，这些常量用于表示文件的权限和属性。

2. **终端控制相关的常量:** 例如 `TCFLSH`, `TIOCCBRK`, `TIOCGWINSZ` 等，这些常量用于控制终端的行为，如刷新输入输出缓冲区，发送 BREAK 信号，获取窗口大小等。

3. **TCP 协议相关的常量:** 例如 `TCP_CORK`, `TCP_NODELAY`, `TCP_KEEPIDLE` 等，这些常量用于设置 TCP socket 的选项，如禁用 Nagle 算法，设置 keep-alive 时间等。

4. **TUN 设备相关的常量:** 例如 `TUNSETIFF`, `TUNGETIFF` 等，这些常量用于配置 TUN（网络隧道）设备。

5. **终端特殊字符相关的常量:** 例如 `VDISCARD`, `VEOF`, `VINTR` 等，这些常量定义了终端输入中具有特殊含义的字符。

6. **进程等待相关的常量:** 例如 `WEXITED`, `WNOHANG` 等，这些常量用于 `wait` 或 `waitpid` 等系统调用中，指定等待子进程退出的方式。

7. **错误码常量:** 例如 `E2BIG`, `EACCES`, `ENOENT` 等，这些常量对应了 Linux 系统调用可能返回的各种错误。

8. **信号常量:** 例如 `SIGABRT`, `SIGINT`, `SIGKILL` 等，这些常量代表了不同的信号，可以用于进程间通信或通知进程发生了特定事件。

9. **错误信息表 `errors`:**  这是一个字符串数组，用于将数字错误码转换为对应的文本描述。例如，错误码 `2` 对应 "no such file or directory"。

10. **信号信息表 `signals`:** 这是一个字符串数组，用于将数字信号转换为对应的文本描述。例如，信号 `2` (SIGINT) 对应 "interrupt"。

**归纳一下它的功能：**

作为 `syscall` 包的一部分，这个文件的核心功能是为 Go 程序提供与 Linux (LoongArch 64 位) 内核进行底层交互所需的常量定义。它涵盖了文件系统操作、终端控制、网络协议配置、进程管理以及错误和信号处理等多个方面。通过这些常量，Go 程序员可以直接使用操作系统的底层功能。

**它是什么Go语言功能的实现？**

这个文件是 Go 语言中 `syscall` 包针对特定操作系统和架构的底层实现部分。`syscall` 包允许 Go 程序直接调用操作系统的系统调用。 由于系统调用在不同的操作系统和硬件架构上有所不同，因此 `syscall` 包会针对不同的平台提供不同的实现文件。 `zerrors_linux_loong64.go` 就是针对 Linux 操作系统在 LoongArch 64 位架构上的具体实现，定义了该平台特有的系统调用相关的常量。

**代码举例说明:**

假设我们要使用 `TCP_NODELAY` 常量来禁用 TCP socket 的 Nagle 算法。

```go
package main

import (
	"fmt"
	"net"
	"syscall"
)

func main() {
	conn, err := net.Dial("tcp", "www.example.com:80")
	if err != nil {
		fmt.Println("Error connecting:", err)
		return
	}
	defer conn.Close()

	rawConn, err := conn.(syscall.Conn).SyscallConn()
	if err != nil {
		fmt.Println("Error getting raw connection:", err)
		return
	}

	err = rawConn.Control(func(fd uintptr) {
		err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
		if err != nil {
			fmt.Println("Error setting TCP_NODELAY:", err)
		} else {
			fmt.Println("TCP_NODELAY set successfully")
		}
	})

	if err != nil {
		fmt.Println("Error during raw connection control:", err)
	}
}
```

**假设的输入与输出：**

在这个例子中，输入是尝试连接 `www.example.com:80`。

输出可能如下：

```
TCP_NODELAY set successfully
```

或者，如果设置失败，则会输出错误信息，例如：

```
Error setting TCP_NODELAY: operation not permitted
```

**涉及命令行参数的具体处理：**

这个代码片段本身不涉及命令行参数的处理。它定义的是常量，这些常量在其他的 Go 代码中被使用，而那些使用这些常量的代码可能会处理命令行参数。

**使用者易犯错的点：**

由于 `syscall` 包是与操作系统底层交互，因此使用不当容易导致程序崩溃或出现不可预测的行为。

一个常见的错误是**错误地使用常量值**。例如，错误地将文件权限常量进行组合，可能导致权限设置不符合预期。

```go
package main

import (
	"fmt"
	"os"
	"syscall"
)

func main() {
	filename := "test.txt"
	// 错误地使用了或运算，本意是设置用户读写执行权限
	err := syscall.Creat(filename, syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	fmt.Println("File created successfully.")

	// 正确的做法是使用位或运算
	err = os.Chmod(filename, 0700) // 使用 os 包更安全方便
	if err != nil {
		fmt.Println("Error changing file mode:", err)
	}
}
```

在这个错误的例子中，使用了 `|` (位或) 来创建文件，但 `syscall.Creat` 的第二个参数期望的是一个模式值，而不是单独的权限位的组合。正确的方式是使用八进制字面量或者 `os.Chmod` 等更高级别的函数。

Prompt: 
```
这是路径为go/src/syscall/zerrors_linux_loong64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共3部分，请归纳一下它的功能

"""
                      = 0x7
	S_IRWXU                           = 0x1c0
	S_ISGID                           = 0x400
	S_ISUID                           = 0x800
	S_ISVTX                           = 0x200
	S_IWGRP                           = 0x10
	S_IWOTH                           = 0x2
	S_IWRITE                          = 0x80
	S_IWUSR                           = 0x80
	S_IXGRP                           = 0x8
	S_IXOTH                           = 0x1
	S_IXUSR                           = 0x40
	TCFLSH                            = 0x540b
	TCIFLUSH                          = 0x0
	TCIOFLUSH                         = 0x2
	TCOFLUSH                          = 0x1
	TCP_CC_INFO                       = 0x1a
	TCP_CM_INQ                        = 0x24
	TCP_CONGESTION                    = 0xd
	TCP_COOKIE_IN_ALWAYS              = 0x1
	TCP_COOKIE_MAX                    = 0x10
	TCP_COOKIE_MIN                    = 0x8
	TCP_COOKIE_OUT_NEVER              = 0x2
	TCP_COOKIE_PAIR_SIZE              = 0x20
	TCP_COOKIE_TRANSACTIONS           = 0xf
	TCP_CORK                          = 0x3
	TCP_DEFER_ACCEPT                  = 0x9
	TCP_FASTOPEN                      = 0x17
	TCP_FASTOPEN_CONNECT              = 0x1e
	TCP_FASTOPEN_KEY                  = 0x21
	TCP_FASTOPEN_NO_COOKIE            = 0x22
	TCP_INFO                          = 0xb
	TCP_INQ                           = 0x24
	TCP_KEEPCNT                       = 0x6
	TCP_KEEPIDLE                      = 0x4
	TCP_KEEPINTVL                     = 0x5
	TCP_LINGER2                       = 0x8
	TCP_MAXSEG                        = 0x2
	TCP_MAXWIN                        = 0xffff
	TCP_MAX_WINSHIFT                  = 0xe
	TCP_MD5SIG                        = 0xe
	TCP_MD5SIG_EXT                    = 0x20
	TCP_MD5SIG_FLAG_PREFIX            = 0x1
	TCP_MD5SIG_MAXKEYLEN              = 0x50
	TCP_MSS                           = 0x200
	TCP_MSS_DEFAULT                   = 0x218
	TCP_MSS_DESIRED                   = 0x4c4
	TCP_NODELAY                       = 0x1
	TCP_NOTSENT_LOWAT                 = 0x19
	TCP_QUEUE_SEQ                     = 0x15
	TCP_QUICKACK                      = 0xc
	TCP_REPAIR                        = 0x13
	TCP_REPAIR_OFF                    = 0x0
	TCP_REPAIR_OFF_NO_WP              = -0x1
	TCP_REPAIR_ON                     = 0x1
	TCP_REPAIR_OPTIONS                = 0x16
	TCP_REPAIR_QUEUE                  = 0x14
	TCP_REPAIR_WINDOW                 = 0x1d
	TCP_SAVED_SYN                     = 0x1c
	TCP_SAVE_SYN                      = 0x1b
	TCP_SYNCNT                        = 0x7
	TCP_S_DATA_IN                     = 0x4
	TCP_S_DATA_OUT                    = 0x8
	TCP_THIN_DUPACK                   = 0x11
	TCP_THIN_LINEAR_TIMEOUTS          = 0x10
	TCP_TIMESTAMP                     = 0x18
	TCP_TX_DELAY                      = 0x25
	TCP_ULP                           = 0x1f
	TCP_USER_TIMEOUT                  = 0x12
	TCP_WINDOW_CLAMP                  = 0xa
	TCP_ZEROCOPY_RECEIVE              = 0x23
	TCSAFLUSH                         = 0x2
	TIOCCBRK                          = 0x5428
	TIOCCONS                          = 0x541d
	TIOCEXCL                          = 0x540c
	TIOCGDEV                          = 0x80045432
	TIOCGETD                          = 0x5424
	TIOCGEXCL                         = 0x80045440
	TIOCGICOUNT                       = 0x545d
	TIOCGISO7816                      = 0x80285442
	TIOCGLCKTRMIOS                    = 0x5456
	TIOCGPGRP                         = 0x540f
	TIOCGPKT                          = 0x80045438
	TIOCGPTLCK                        = 0x80045439
	TIOCGPTN                          = 0x80045430
	TIOCGPTPEER                       = 0x5441
	TIOCGRS485                        = 0x542e
	TIOCGSERIAL                       = 0x541e
	TIOCGSID                          = 0x5429
	TIOCGSOFTCAR                      = 0x5419
	TIOCGWINSZ                        = 0x5413
	TIOCINQ                           = 0x541b
	TIOCLINUX                         = 0x541c
	TIOCMBIC                          = 0x5417
	TIOCMBIS                          = 0x5416
	TIOCMGET                          = 0x5415
	TIOCMIWAIT                        = 0x545c
	TIOCMSET                          = 0x5418
	TIOCM_CAR                         = 0x40
	TIOCM_CD                          = 0x40
	TIOCM_CTS                         = 0x20
	TIOCM_DSR                         = 0x100
	TIOCM_DTR                         = 0x2
	TIOCM_LE                          = 0x1
	TIOCM_RI                          = 0x80
	TIOCM_RNG                         = 0x80
	TIOCM_RTS                         = 0x4
	TIOCM_SR                          = 0x10
	TIOCM_ST                          = 0x8
	TIOCNOTTY                         = 0x5422
	TIOCNXCL                          = 0x540d
	TIOCOUTQ                          = 0x5411
	TIOCPKT                           = 0x5420
	TIOCPKT_DATA                      = 0x0
	TIOCPKT_DOSTOP                    = 0x20
	TIOCPKT_FLUSHREAD                 = 0x1
	TIOCPKT_FLUSHWRITE                = 0x2
	TIOCPKT_IOCTL                     = 0x40
	TIOCPKT_NOSTOP                    = 0x10
	TIOCPKT_START                     = 0x8
	TIOCPKT_STOP                      = 0x4
	TIOCSBRK                          = 0x5427
	TIOCSCTTY                         = 0x540e
	TIOCSERCONFIG                     = 0x5453
	TIOCSERGETLSR                     = 0x5459
	TIOCSERGETMULTI                   = 0x545a
	TIOCSERGSTRUCT                    = 0x5458
	TIOCSERGWILD                      = 0x5454
	TIOCSERSETMULTI                   = 0x545b
	TIOCSERSWILD                      = 0x5455
	TIOCSER_TEMT                      = 0x1
	TIOCSETD                          = 0x5423
	TIOCSIG                           = 0x40045436
	TIOCSISO7816                      = 0xc0285443
	TIOCSLCKTRMIOS                    = 0x5457
	TIOCSPGRP                         = 0x5410
	TIOCSPTLCK                        = 0x40045431
	TIOCSRS485                        = 0x542f
	TIOCSSERIAL                       = 0x541f
	TIOCSSOFTCAR                      = 0x541a
	TIOCSTI                           = 0x5412
	TIOCSWINSZ                        = 0x5414
	TIOCVHANGUP                       = 0x5437
	TOSTOP                            = 0x100
	TUNATTACHFILTER                   = 0x401054d5
	TUNDETACHFILTER                   = 0x401054d6
	TUNGETDEVNETNS                    = 0x54e3
	TUNGETFEATURES                    = 0x800454cf
	TUNGETFILTER                      = 0x801054db
	TUNGETIFF                         = 0x800454d2
	TUNGETSNDBUF                      = 0x800454d3
	TUNGETVNETBE                      = 0x800454df
	TUNGETVNETHDRSZ                   = 0x800454d7
	TUNGETVNETLE                      = 0x800454dd
	TUNSETCARRIER                     = 0x400454e2
	TUNSETDEBUG                       = 0x400454c9
	TUNSETFILTEREBPF                  = 0x800454e1
	TUNSETGROUP                       = 0x400454ce
	TUNSETIFF                         = 0x400454ca
	TUNSETIFINDEX                     = 0x400454da
	TUNSETLINK                        = 0x400454cd
	TUNSETNOCSUM                      = 0x400454c8
	TUNSETOFFLOAD                     = 0x400454d0
	TUNSETOWNER                       = 0x400454cc
	TUNSETPERSIST                     = 0x400454cb
	TUNSETQUEUE                       = 0x400454d9
	TUNSETSNDBUF                      = 0x400454d4
	TUNSETSTEERINGEBPF                = 0x800454e0
	TUNSETTXFILTER                    = 0x400454d1
	TUNSETVNETBE                      = 0x400454de
	TUNSETVNETHDRSZ                   = 0x400454d8
	TUNSETVNETLE                      = 0x400454dc
	VDISCARD                          = 0xd
	VEOF                              = 0x4
	VEOL                              = 0xb
	VEOL2                             = 0x10
	VERASE                            = 0x2
	VINTR                             = 0x0
	VKILL                             = 0x3
	VLNEXT                            = 0xf
	VMIN                              = 0x6
	VQUIT                             = 0x1
	VREPRINT                          = 0xc
	VSTART                            = 0x8
	VSTOP                             = 0x9
	VSUSP                             = 0xa
	VSWTC                             = 0x7
	VT0                               = 0x0
	VT1                               = 0x4000
	VTDLY                             = 0x4000
	VTIME                             = 0x5
	VWERASE                           = 0xe
	WALL                              = 0x40000000
	WCLONE                            = 0x80000000
	WCONTINUED                        = 0x8
	WEXITED                           = 0x4
	WNOHANG                           = 0x1
	WNOTHREAD                         = 0x20000000
	WNOWAIT                           = 0x1000000
	WORDSIZE                          = 0x40
	WSTOPPED                          = 0x2
	WUNTRACED                         = 0x2
)

// Errors
const (
	E2BIG           = Errno(0x7)
	EACCES          = Errno(0xd)
	EADDRINUSE      = Errno(0x62)
	EADDRNOTAVAIL   = Errno(0x63)
	EADV            = Errno(0x44)
	EAFNOSUPPORT    = Errno(0x61)
	EAGAIN          = Errno(0xb)
	EALREADY        = Errno(0x72)
	EBADE           = Errno(0x34)
	EBADF           = Errno(0x9)
	EBADFD          = Errno(0x4d)
	EBADMSG         = Errno(0x4a)
	EBADR           = Errno(0x35)
	EBADRQC         = Errno(0x38)
	EBADSLT         = Errno(0x39)
	EBFONT          = Errno(0x3b)
	EBUSY           = Errno(0x10)
	ECANCELED       = Errno(0x7d)
	ECHILD          = Errno(0xa)
	ECHRNG          = Errno(0x2c)
	ECOMM           = Errno(0x46)
	ECONNABORTED    = Errno(0x67)
	ECONNREFUSED    = Errno(0x6f)
	ECONNRESET      = Errno(0x68)
	EDEADLK         = Errno(0x23)
	EDEADLOCK       = Errno(0x23)
	EDESTADDRREQ    = Errno(0x59)
	EDOM            = Errno(0x21)
	EDOTDOT         = Errno(0x49)
	EDQUOT          = Errno(0x7a)
	EEXIST          = Errno(0x11)
	EFAULT          = Errno(0xe)
	EFBIG           = Errno(0x1b)
	EHOSTDOWN       = Errno(0x70)
	EHOSTUNREACH    = Errno(0x71)
	EHWPOISON       = Errno(0x85)
	EIDRM           = Errno(0x2b)
	EILSEQ          = Errno(0x54)
	EINPROGRESS     = Errno(0x73)
	EINTR           = Errno(0x4)
	EINVAL          = Errno(0x16)
	EIO             = Errno(0x5)
	EISCONN         = Errno(0x6a)
	EISDIR          = Errno(0x15)
	EISNAM          = Errno(0x78)
	EKEYEXPIRED     = Errno(0x7f)
	EKEYREJECTED    = Errno(0x81)
	EKEYREVOKED     = Errno(0x80)
	EL2HLT          = Errno(0x33)
	EL2NSYNC        = Errno(0x2d)
	EL3HLT          = Errno(0x2e)
	EL3RST          = Errno(0x2f)
	ELIBACC         = Errno(0x4f)
	ELIBBAD         = Errno(0x50)
	ELIBEXEC        = Errno(0x53)
	ELIBMAX         = Errno(0x52)
	ELIBSCN         = Errno(0x51)
	ELNRNG          = Errno(0x30)
	ELOOP           = Errno(0x28)
	EMEDIUMTYPE     = Errno(0x7c)
	EMFILE          = Errno(0x18)
	EMLINK          = Errno(0x1f)
	EMSGSIZE        = Errno(0x5a)
	EMULTIHOP       = Errno(0x48)
	ENAMETOOLONG    = Errno(0x24)
	ENAVAIL         = Errno(0x77)
	ENETDOWN        = Errno(0x64)
	ENETRESET       = Errno(0x66)
	ENETUNREACH     = Errno(0x65)
	ENFILE          = Errno(0x17)
	ENOANO          = Errno(0x37)
	ENOBUFS         = Errno(0x69)
	ENOCSI          = Errno(0x32)
	ENODATA         = Errno(0x3d)
	ENODEV          = Errno(0x13)
	ENOENT          = Errno(0x2)
	ENOEXEC         = Errno(0x8)
	ENOKEY          = Errno(0x7e)
	ENOLCK          = Errno(0x25)
	ENOLINK         = Errno(0x43)
	ENOMEDIUM       = Errno(0x7b)
	ENOMEM          = Errno(0xc)
	ENOMSG          = Errno(0x2a)
	ENONET          = Errno(0x40)
	ENOPKG          = Errno(0x41)
	ENOPROTOOPT     = Errno(0x5c)
	ENOSPC          = Errno(0x1c)
	ENOSR           = Errno(0x3f)
	ENOSTR          = Errno(0x3c)
	ENOSYS          = Errno(0x26)
	ENOTBLK         = Errno(0xf)
	ENOTCONN        = Errno(0x6b)
	ENOTDIR         = Errno(0x14)
	ENOTEMPTY       = Errno(0x27)
	ENOTNAM         = Errno(0x76)
	ENOTRECOVERABLE = Errno(0x83)
	ENOTSOCK        = Errno(0x58)
	ENOTSUP         = Errno(0x5f)
	ENOTTY          = Errno(0x19)
	ENOTUNIQ        = Errno(0x4c)
	ENXIO           = Errno(0x6)
	EOPNOTSUPP      = Errno(0x5f)
	EOVERFLOW       = Errno(0x4b)
	EOWNERDEAD      = Errno(0x82)
	EPERM           = Errno(0x1)
	EPFNOSUPPORT    = Errno(0x60)
	EPIPE           = Errno(0x20)
	EPROTO          = Errno(0x47)
	EPROTONOSUPPORT = Errno(0x5d)
	EPROTOTYPE      = Errno(0x5b)
	ERANGE          = Errno(0x22)
	EREMCHG         = Errno(0x4e)
	EREMOTE         = Errno(0x42)
	EREMOTEIO       = Errno(0x79)
	ERESTART        = Errno(0x55)
	ERFKILL         = Errno(0x84)
	EROFS           = Errno(0x1e)
	ESHUTDOWN       = Errno(0x6c)
	ESOCKTNOSUPPORT = Errno(0x5e)
	ESPIPE          = Errno(0x1d)
	ESRCH           = Errno(0x3)
	ESRMNT          = Errno(0x45)
	ESTALE          = Errno(0x74)
	ESTRPIPE        = Errno(0x56)
	ETIME           = Errno(0x3e)
	ETIMEDOUT       = Errno(0x6e)
	ETOOMANYREFS    = Errno(0x6d)
	ETXTBSY         = Errno(0x1a)
	EUCLEAN         = Errno(0x75)
	EUNATCH         = Errno(0x31)
	EUSERS          = Errno(0x57)
	EWOULDBLOCK     = Errno(0xb)
	EXDEV           = Errno(0x12)
	EXFULL          = Errno(0x36)
)

// Signals
const (
	SIGABRT   = Signal(0x6)
	SIGALRM   = Signal(0xe)
	SIGBUS    = Signal(0x7)
	SIGCHLD   = Signal(0x11)
	SIGCLD    = Signal(0x11)
	SIGCONT   = Signal(0x12)
	SIGFPE    = Signal(0x8)
	SIGHUP    = Signal(0x1)
	SIGILL    = Signal(0x4)
	SIGINT    = Signal(0x2)
	SIGIO     = Signal(0x1d)
	SIGIOT    = Signal(0x6)
	SIGKILL   = Signal(0x9)
	SIGPIPE   = Signal(0xd)
	SIGPOLL   = Signal(0x1d)
	SIGPROF   = Signal(0x1b)
	SIGPWR    = Signal(0x1e)
	SIGQUIT   = Signal(0x3)
	SIGSEGV   = Signal(0xb)
	SIGSTKFLT = Signal(0x10)
	SIGSTOP   = Signal(0x13)
	SIGSYS    = Signal(0x1f)
	SIGTERM   = Signal(0xf)
	SIGTRAP   = Signal(0x5)
	SIGTSTP   = Signal(0x14)
	SIGTTIN   = Signal(0x15)
	SIGTTOU   = Signal(0x16)
	SIGURG    = Signal(0x17)
	SIGUSR1   = Signal(0xa)
	SIGUSR2   = Signal(0xc)
	SIGVTALRM = Signal(0x1a)
	SIGWINCH  = Signal(0x1c)
	SIGXCPU   = Signal(0x18)
	SIGXFSZ   = Signal(0x19)
)

// Error table
var errors = [...]string{
	1:   "operation not permitted",
	2:   "no such file or directory",
	3:   "no such process",
	4:   "interrupted system call",
	5:   "input/output error",
	6:   "no such device or address",
	7:   "argument list too long",
	8:   "exec format error",
	9:   "bad file descriptor",
	10:  "no child processes",
	11:  "resource temporarily unavailable",
	12:  "cannot allocate memory",
	13:  "permission denied",
	14:  "bad address",
	15:  "block device required",
	16:  "device or resource busy",
	17:  "file exists",
	18:  "invalid cross-device link",
	19:  "no such device",
	20:  "not a directory",
	21:  "is a directory",
	22:  "invalid argument",
	23:  "too many open files in system",
	24:  "too many open files",
	25:  "inappropriate ioctl for device",
	26:  "text file busy",
	27:  "file too large",
	28:  "no space left on device",
	29:  "illegal seek",
	30:  "read-only file system",
	31:  "too many links",
	32:  "broken pipe",
	33:  "numerical argument out of domain",
	34:  "numerical result out of range",
	35:  "resource deadlock avoided",
	36:  "file name too long",
	37:  "no locks available",
	38:  "function not implemented",
	39:  "directory not empty",
	40:  "too many levels of symbolic links",
	42:  "no message of desired type",
	43:  "identifier removed",
	44:  "channel number out of range",
	45:  "level 2 not synchronized",
	46:  "level 3 halted",
	47:  "level 3 reset",
	48:  "link number out of range",
	49:  "protocol driver not attached",
	50:  "no CSI structure available",
	51:  "level 2 halted",
	52:  "invalid exchange",
	53:  "invalid request descriptor",
	54:  "exchange full",
	55:  "no anode",
	56:  "invalid request code",
	57:  "invalid slot",
	59:  "bad font file format",
	60:  "device not a stream",
	61:  "no data available",
	62:  "timer expired",
	63:  "out of streams resources",
	64:  "machine is not on the network",
	65:  "package not installed",
	66:  "object is remote",
	67:  "link has been severed",
	68:  "advertise error",
	69:  "srmount error",
	70:  "communication error on send",
	71:  "protocol error",
	72:  "multihop attempted",
	73:  "RFS specific error",
	74:  "bad message",
	75:  "value too large for defined data type",
	76:  "name not unique on network",
	77:  "file descriptor in bad state",
	78:  "remote address changed",
	79:  "can not access a needed shared library",
	80:  "accessing a corrupted shared library",
	81:  ".lib section in a.out corrupted",
	82:  "attempting to link in too many shared libraries",
	83:  "cannot exec a shared library directly",
	84:  "invalid or incomplete multibyte or wide character",
	85:  "interrupted system call should be restarted",
	86:  "streams pipe error",
	87:  "too many users",
	88:  "socket operation on non-socket",
	89:  "destination address required",
	90:  "message too long",
	91:  "protocol wrong type for socket",
	92:  "protocol not available",
	93:  "protocol not supported",
	94:  "socket type not supported",
	95:  "operation not supported",
	96:  "protocol family not supported",
	97:  "address family not supported by protocol",
	98:  "address already in use",
	99:  "cannot assign requested address",
	100: "network is down",
	101: "network is unreachable",
	102: "network dropped connection on reset",
	103: "software caused connection abort",
	104: "connection reset by peer",
	105: "no buffer space available",
	106: "transport endpoint is already connected",
	107: "transport endpoint is not connected",
	108: "cannot send after transport endpoint shutdown",
	109: "too many references: cannot splice",
	110: "connection timed out",
	111: "connection refused",
	112: "host is down",
	113: "no route to host",
	114: "operation already in progress",
	115: "operation now in progress",
	116: "stale file handle",
	117: "structure needs cleaning",
	118: "not a XENIX named type file",
	119: "no XENIX semaphores available",
	120: "is a named type file",
	121: "remote I/O error",
	122: "disk quota exceeded",
	123: "no medium found",
	124: "wrong medium type",
	125: "operation canceled",
	126: "required key not available",
	127: "key has expired",
	128: "key has been revoked",
	129: "key was rejected by service",
	130: "owner died",
	131: "state not recoverable",
	132: "operation not possible due to RF-kill",
	133: "memory page has hardware error",
}

// Signal table
var signals = [...]string{
	1:  "hangup",
	2:  "interrupt",
	3:  "quit",
	4:  "illegal instruction",
	5:  "trace/breakpoint trap",
	6:  "aborted",
	7:  "bus error",
	8:  "floating point exception",
	9:  "killed",
	10: "user defined signal 1",
	11: "segmentation fault",
	12: "user defined signal 2",
	13: "broken pipe",
	14: "alarm clock",
	15: "terminated",
	16: "stack fault",
	17: "child exited",
	18: "continued",
	19: "stopped (signal)",
	20: "stopped",
	21: "stopped (tty input)",
	22: "stopped (tty output)",
	23: "urgent I/O condition",
	24: "CPU time limit exceeded",
	25: "file size limit exceeded",
	26: "virtual timer expired",
	27: "profiling timer expired",
	28: "window changed",
	29: "I/O possible",
	30: "power failure",
	31: "bad system call",
}

"""




```