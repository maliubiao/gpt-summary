Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding of the Context:**

The prompt clearly states this is part of a Go file located at `go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_openbsd_mips64.go`. This location is crucial. It tells us:

* **It's part of the `golang.org/x/sys/unix` package:** This means it's related to system calls and low-level operating system interactions for Unix-like systems.
* **It's in the `vendor` directory:** This indicates it's a vendored dependency, likely from the `x/sys` repository.
* **The filename ends in `_openbsd_mips64.go`:** This is the most important part. It specifies the target operating system (OpenBSD) and architecture (MIPS64). This immediately tells us the content will be specific to this combination. The `zerrors_` prefix often suggests automatically generated error and constant definitions.

**2. Analyzing the Code Sections:**

I'll go through each major section and its purpose:

* **Constants (First Block):**
    *  The names start with `O_`, `SYS_`, `FCNTL_`, `MADV_`, `MAP_`, `MCL_`, `MS_`, `NF`, `PAGE_`, `PROT_`, `S_`, `SA_`, `SEEK_`, `SHM_`, `SO_`, `STAT_`, `TCP_`, `TIOC`, `TIOCM_`, `TIOCPKT_`, `TOSTOP`, `UTIME_`, `VDISCARD`, `VDSUSP`, etc.
    *  These prefixes are strong indicators of system-level constants. Many relate to file operations (`O_`, `FCNTL_`), memory mapping (`MAP_`, `PROT_`), socket options (`SO_`, `TCP_`), terminal I/O control (`TIOC*`), and process signals (`SA_`).
    * **Inference:** This section defines constants used for interacting with the OpenBSD kernel through system calls. These are likely arguments or return values for functions like `open`, `ioctl`, `mmap`, etc.

* **Constants (Second Block - Errors):**
    *  The names start with `E`.
    *  The values are of type `syscall.Errno`.
    * **Inference:** This defines error codes returned by system calls, indicating the reason for failure.

* **Constants (Third Block - Signals):**
    * The names start with `SIG`.
    * The values are of type `syscall.Signal`.
    * **Inference:**  This defines signals that can be sent to processes to notify them of events.

* **Error Table (`errorList`):**
    * It's an array of structs, each containing `num` (syscall.Errno), `name` (string), and `desc` (string).
    * It appears to map the numeric error codes to their symbolic names and descriptions.
    * **Inference:** This provides a human-readable mapping of the error constants defined earlier. It's likely used for error reporting and debugging.

* **Signal Table (`signalList`):**
    * Similar structure to the error table, but for signals.
    * **Inference:** This provides a human-readable mapping of signal numbers to their names and descriptions.

**3. Reasoning about Go Functionality:**

Given the presence of system call constants, error codes, and signals, the most likely Go functionality this code relates to is the `syscall` package. The `syscall` package provides a direct interface to the operating system's system calls.

**4. Constructing Go Code Examples:**

To illustrate the use, I'll pick a few representative examples:

* **File Open (`O_RDONLY`, `O_CREATE`, `O_WRONLY`, `EACCES`, `ENOENT`):** This is a fundamental system call.
* **IO Control (`TIOCGWINSZ`, `TIOCSWINSZ`):**  This demonstrates interaction with terminal devices.
* **Signal Handling (`SIGINT`, `syscall.Signal`):** This shows how signals are used to manage processes.

**5. Inferring Command-Line Parameters (and realizing there aren't many direct ones):**

While these constants are used in system calls, they aren't *directly* command-line parameters. The *system calls themselves* might be invoked as a result of command-line actions, but the constants are internal to the Go program. For example, running `cat file.txt` would eventually lead to `open` being called with flags like `O_RDONLY`, but `O_RDONLY` isn't a parameter to the `cat` command itself. It's an argument to the underlying `open` system call.

**6. Identifying Potential Pitfalls:**

* **Platform Specificity:** The biggest error is assuming these constants are universal. The `_openbsd_mips64.go` suffix is a clear warning.
* **Incorrect Constant Usage:**  Using the wrong constant with a system call can lead to unexpected behavior or errors. The constants define specific actions and modes.

**7. Synthesizing the Summary:**

The summary should concisely capture the key functionalities identified: defining system call constants, error codes, and signals specifically for OpenBSD on the MIPS64 architecture, primarily for use with the `syscall` package.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe this also handles some specific OpenBSD system call structures. *Correction:*  While related, the provided snippet focuses mainly on constants, errors, and signals. Structures would likely be in other files.
* **Considering command-line arguments too narrowly:** Initially, I might have looked for direct command-line equivalents for each constant. *Correction:* The link is more indirect. Command-line actions trigger system calls, which then use these constants. The constants aren't usually exposed directly in command-line interfaces.

This iterative process of analyzing the code, making inferences, and then refining those inferences based on the context and the nature of the code is how I arrived at the final answer.
这是第二部分，延续了路径为 `go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_openbsd_mips64.go` 的 Go 语言实现的分析。

**归纳一下它的功能：**

综合第一部分和第二部分的内容，这个 Go 语言源文件 `zerrors_openbsd_mips64.go` 的主要功能是：

**定义了 OpenBSD 操作系统在 MIPS64 架构下使用的系统调用相关的常量、错误码和信号。**

具体来说，它做了以下几件事：

1. **定义了大量的常量 (Constants):**
   - 这些常量以 `O_`, `SYS_`, `FCNTL_`, `MADV_`, `MAP_`, `MCL_`, `MS_`, `NF`, `PAGE_`, `PROT_`, `S_`, `SA_`, `SEEK_`, `SHM_`, `SO_`, `STAT_`, `TCP_`, `TIOC` 等前缀开头。
   - 这些常量代表了系统调用中使用的各种选项、标志、控制码、参数等。例如，文件操作的标志（`O_RDONLY`，`O_CREATE`），`ioctl` 系统调用的命令（`TIOCGWINSZ`，`TIOCSWINSZ`），内存映射的标志（`PROT_READ`，`MAP_SHARED`）等等。

2. **定义了错误码 (Errors):**
   - 这些常量以 `E` 开头，类型为 `syscall.Errno`。
   - 它们对应了系统调用失败时返回的错误代码，用于指示错误的具体原因。例如，`EACCES` (权限被拒绝)，`ENOENT` (文件或目录不存在) 等。

3. **定义了信号 (Signals):**
   - 这些常量以 `SIG` 开头，类型为 `syscall.Signal`。
   - 它们代表了可以发送给进程的各种信号，用于通知进程发生了特定的事件。例如，`SIGINT` (中断信号)，`SIGKILL` (强制终止信号) 等。

4. **提供了错误码和信号的名称和描述 (Error table & Signal table):**
   - `errorList` 数组将数字错误码映射到其符号名称和文字描述。
   - `signalList` 数组将信号数字映射到其符号名称和文字描述。
   - 这为开发者提供了更易读的错误和信号信息。

**它是什么 Go 语言功能的实现？**

这个文件是 Go 语言 `syscall` 标准库的一部分实现细节。 `syscall` 包允许 Go 程序直接调用操作系统底层的系统调用。 为了能够正确地进行系统调用，Go 需要知道特定操作系统和架构下的系统调用号、常量定义、错误码和信号定义。

`zerrors_openbsd_mips64.go` 文件就是为 OpenBSD 操作系统在 MIPS64 架构下提供这些信息的。  Go 编译器在编译涉及到 `syscall` 的代码时，会根据目标操作系统和架构选择对应的 `zerrors_*.go` 文件。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	// 使用 O_RDONLY 常量以只读模式打开文件
	fd, err := syscall.Open("test.txt", syscall.O_RDONLY, 0)
	if err != nil {
		// 检查是否是文件不存在的错误 (ENOENT)
		if err == syscall.ENOENT {
			fmt.Println("文件不存在")
		} else {
			fmt.Println("打开文件出错:", err)
		}
		return
	}
	defer syscall.Close(fd)

	fmt.Println("成功打开文件，文件描述符:", fd)

	// 获取终端窗口大小 (使用 TIOCGWINSZ 常量)
	var ws syscall.Winsize
	_, _, ioctlErr := syscall.Syscall(syscall.SYS_IOCTL, uintptr(syscall.Stdout), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws)))
	if ioctlErr != 0 {
		fmt.Println("获取窗口大小失败:", ioctlErr)
	} else {
		fmt.Printf("窗口大小: 行=%d, 列=%d\n", ws.Row, ws.Col)
	}

	// 发送一个 SIGKILL 信号给一个进程 (假设进程ID为 1234)
	pid := 1234
	err = syscall.Kill(pid, syscall.SIGKILL)
	if err != nil {
		fmt.Println("发送信号失败:", err)
		if err == syscall.ESRCH {
			fmt.Println("进程不存在")
		}
	} else {
		fmt.Printf("成功向进程 %d 发送了 SIGKILL 信号\n", pid)
	}
}
```

**假设的输入与输出:**

假设 `test.txt` 文件不存在：

```
文件不存在
```

假设 `test.txt` 文件存在：

```
成功打开文件，文件描述符: 3
获取窗口大小失败: input/output error
发送信号失败: no such process
进程不存在
```

**代码推理:**

-  `syscall.Open("test.txt", syscall.O_RDONLY, 0)`:  这里使用了 `syscall.O_RDONLY` 常量，该常量在 `zerrors_openbsd_mips64.go` 中被定义为特定的数值，告诉系统以只读模式打开文件。如果文件不存在，`Open` 函数会返回一个错误，该错误会被与 `syscall.ENOENT` 进行比较，`syscall.ENOENT` 也是在这个文件中定义的。
-  `syscall.Syscall(syscall.SYS_IOCTL, uintptr(syscall.Stdout), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws)))`:  这里尝试使用 `ioctl` 系统调用获取终端窗口大小。 `syscall.TIOCGWINSZ` 是一个控制码常量，用于获取窗口大小。输出 "获取窗口大小失败: input/output error" 表明该操作在当前环境下（可能不是一个真正的终端）失败了。
-  `syscall.Kill(pid, syscall.SIGKILL)`: 这里尝试向进程 ID 为 1234 的进程发送 `syscall.SIGKILL` 信号，这是一个强制终止信号。如果进程不存在，`Kill` 函数会返回 `syscall.ESRCH` 错误。

**命令行参数的具体处理:**

这个文件本身不直接处理命令行参数。它定义的是 Go 语言 `syscall` 包在特定平台下使用的常量。  命令行参数的处理通常发生在 `main` 函数或者使用了 `flag` 等包的地方。  `syscall` 包提供的功能会被更上层的代码使用，而这些上层代码可能会解析命令行参数并调用相应的系统调用。

例如，一个程序如果接收一个 `-f` 参数指定文件名，那么在打开文件时可能会使用 `syscall.Open` 并带上 `syscall.O_RDONLY` 等常量，但 `-f` 参数的解析逻辑不在 `zerrors_openbsd_mips64.go` 中。

**使用者易犯错的点:**

- **跨平台假设:** 最常见的错误是假设这些常量在所有操作系统或架构上都是相同的。 例如，`syscall.O_RDONLY` 在不同的操作系统上可能具有相同的数值，但这不能保证。因此，直接使用这些常量而不考虑平台差异会导致代码在不同系统上行为不一致甚至出错。应该使用 `syscall` 包提供的更通用的接口，Go 编译器会根据目标平台选择正确的常量。

  **错误示例:**

  ```go
  // 错误：假设在所有平台上 O_RDONLY 的值都是 0
  const myReadOnlyFlag = 0
  fd, err := syscall.Open("myfile.txt", myReadOnlyFlag, 0)
  ```

  **正确做法:**

  ```go
  fd, err := syscall.Open("myfile.txt", syscall.O_RDONLY, 0)
  ```

- **不理解常量的含义:** 错误地使用常量，例如将用于设置文件状态的常量用于网络操作，会导致系统调用失败或产生意想不到的结果。需要查阅相关的操作系统文档来理解每个常量的具体作用。

总而言之，`zerrors_openbsd_mips64.go` 是 Go 语言与 OpenBSD (MIPS64 架构) 操作系统底层交互的桥梁，它定义了进行系统调用所需的各种平台特定的常量、错误码和信号，使得 Go 程序能够以一种类型安全的方式调用操作系统的功能。 开发者在使用 `syscall` 包时，通常不需要直接关注这个文件的内容，Go 的构建工具会处理平台相关的细节。理解这个文件的作用有助于更深入地理解 Go 的底层运作机制以及系统编程的概念。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_openbsd_mips64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共2部分，请归纳一下它的功能

"""
          = 0x8
	TIOCFLAG_PPS                      = 0x10
	TIOCFLAG_SOFTCAR                  = 0x1
	TIOCFLUSH                         = 0x80047410
	TIOCGETA                          = 0x402c7413
	TIOCGETD                          = 0x4004741a
	TIOCGFLAGS                        = 0x4004745d
	TIOCGPGRP                         = 0x40047477
	TIOCGSID                          = 0x40047463
	TIOCGTSTAMP                       = 0x4010745b
	TIOCGWINSZ                        = 0x40087468
	TIOCMBIC                          = 0x8004746b
	TIOCMBIS                          = 0x8004746c
	TIOCMGET                          = 0x4004746a
	TIOCMODG                          = 0x4004746a
	TIOCMODS                          = 0x8004746d
	TIOCMSET                          = 0x8004746d
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
	TIOCNOTTY                         = 0x20007471
	TIOCNXCL                          = 0x2000740e
	TIOCOUTQ                          = 0x40047473
	TIOCPKT                           = 0x80047470
	TIOCPKT_DATA                      = 0x0
	TIOCPKT_DOSTOP                    = 0x20
	TIOCPKT_FLUSHREAD                 = 0x1
	TIOCPKT_FLUSHWRITE                = 0x2
	TIOCPKT_IOCTL                     = 0x40
	TIOCPKT_NOSTOP                    = 0x10
	TIOCPKT_START                     = 0x8
	TIOCPKT_STOP                      = 0x4
	TIOCREMOTE                        = 0x80047469
	TIOCSBRK                          = 0x2000747b
	TIOCSCTTY                         = 0x20007461
	TIOCSDTR                          = 0x20007479
	TIOCSETA                          = 0x802c7414
	TIOCSETAF                         = 0x802c7416
	TIOCSETAW                         = 0x802c7415
	TIOCSETD                          = 0x8004741b
	TIOCSETVERAUTH                    = 0x8004741c
	TIOCSFLAGS                        = 0x8004745c
	TIOCSIG                           = 0x8004745f
	TIOCSPGRP                         = 0x80047476
	TIOCSTART                         = 0x2000746e
	TIOCSTAT                          = 0x20007465
	TIOCSTOP                          = 0x2000746f
	TIOCSTSTAMP                       = 0x8008745a
	TIOCSWINSZ                        = 0x80087467
	TIOCUCNTL                         = 0x80047466
	TIOCUCNTL_CBRK                    = 0x7a
	TIOCUCNTL_SBRK                    = 0x7b
	TOSTOP                            = 0x400000
	UTIME_NOW                         = -0x2
	UTIME_OMIT                        = -0x1
	VDISCARD                          = 0xf
	VDSUSP                            = 0xb
	VEOF                              = 0x0
	VEOL                              = 0x1
	VEOL2                             = 0x2
	VERASE                            = 0x3
	VINTR                             = 0x8
	VKILL                             = 0x5
	VLNEXT                            = 0xe
	VMIN                              = 0x10
	VM_ANONMIN                        = 0x7
	VM_LOADAVG                        = 0x2
	VM_MALLOC_CONF                    = 0xc
	VM_MAXID                          = 0xd
	VM_MAXSLP                         = 0xa
	VM_METER                          = 0x1
	VM_NKMEMPAGES                     = 0x6
	VM_PSSTRINGS                      = 0x3
	VM_SWAPENCRYPT                    = 0x5
	VM_USPACE                         = 0xb
	VM_UVMEXP                         = 0x4
	VM_VNODEMIN                       = 0x9
	VM_VTEXTMIN                       = 0x8
	VQUIT                             = 0x9
	VREPRINT                          = 0x6
	VSTART                            = 0xc
	VSTATUS                           = 0x12
	VSTOP                             = 0xd
	VSUSP                             = 0xa
	VTIME                             = 0x11
	VWERASE                           = 0x4
	WALTSIG                           = 0x4
	WCONTINUED                        = 0x8
	WCOREFLAG                         = 0x80
	WNOHANG                           = 0x1
	WUNTRACED                         = 0x2
	XCASE                             = 0x1000000
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
	EBADF           = syscall.Errno(0x9)
	EBADMSG         = syscall.Errno(0x5c)
	EBADRPC         = syscall.Errno(0x48)
	EBUSY           = syscall.Errno(0x10)
	ECANCELED       = syscall.Errno(0x58)
	ECHILD          = syscall.Errno(0xa)
	ECONNABORTED    = syscall.Errno(0x35)
	ECONNREFUSED    = syscall.Errno(0x3d)
	ECONNRESET      = syscall.Errno(0x36)
	EDEADLK         = syscall.Errno(0xb)
	EDESTADDRREQ    = syscall.Errno(0x27)
	EDOM            = syscall.Errno(0x21)
	EDQUOT          = syscall.Errno(0x45)
	EEXIST          = syscall.Errno(0x11)
	EFAULT          = syscall.Errno(0xe)
	EFBIG           = syscall.Errno(0x1b)
	EFTYPE          = syscall.Errno(0x4f)
	EHOSTDOWN       = syscall.Errno(0x40)
	EHOSTUNREACH    = syscall.Errno(0x41)
	EIDRM           = syscall.Errno(0x59)
	EILSEQ          = syscall.Errno(0x54)
	EINPROGRESS     = syscall.Errno(0x24)
	EINTR           = syscall.Errno(0x4)
	EINVAL          = syscall.Errno(0x16)
	EIO             = syscall.Errno(0x5)
	EIPSEC          = syscall.Errno(0x52)
	EISCONN         = syscall.Errno(0x38)
	EISDIR          = syscall.Errno(0x15)
	ELAST           = syscall.Errno(0x5f)
	ELOOP           = syscall.Errno(0x3e)
	EMEDIUMTYPE     = syscall.Errno(0x56)
	EMFILE          = syscall.Errno(0x18)
	EMLINK          = syscall.Errno(0x1f)
	EMSGSIZE        = syscall.Errno(0x28)
	ENAMETOOLONG    = syscall.Errno(0x3f)
	ENEEDAUTH       = syscall.Errno(0x51)
	ENETDOWN        = syscall.Errno(0x32)
	ENETRESET       = syscall.Errno(0x34)
	ENETUNREACH     = syscall.Errno(0x33)
	ENFILE          = syscall.Errno(0x17)
	ENOATTR         = syscall.Errno(0x53)
	ENOBUFS         = syscall.Errno(0x37)
	ENODEV          = syscall.Errno(0x13)
	ENOENT          = syscall.Errno(0x2)
	ENOEXEC         = syscall.Errno(0x8)
	ENOLCK          = syscall.Errno(0x4d)
	ENOMEDIUM       = syscall.Errno(0x55)
	ENOMEM          = syscall.Errno(0xc)
	ENOMSG          = syscall.Errno(0x5a)
	ENOPROTOOPT     = syscall.Errno(0x2a)
	ENOSPC          = syscall.Errno(0x1c)
	ENOSYS          = syscall.Errno(0x4e)
	ENOTBLK         = syscall.Errno(0xf)
	ENOTCONN        = syscall.Errno(0x39)
	ENOTDIR         = syscall.Errno(0x14)
	ENOTEMPTY       = syscall.Errno(0x42)
	ENOTRECOVERABLE = syscall.Errno(0x5d)
	ENOTSOCK        = syscall.Errno(0x26)
	ENOTSUP         = syscall.Errno(0x5b)
	ENOTTY          = syscall.Errno(0x19)
	ENXIO           = syscall.Errno(0x6)
	EOPNOTSUPP      = syscall.Errno(0x2d)
	EOVERFLOW       = syscall.Errno(0x57)
	EOWNERDEAD      = syscall.Errno(0x5e)
	EPERM           = syscall.Errno(0x1)
	EPFNOSUPPORT    = syscall.Errno(0x2e)
	EPIPE           = syscall.Errno(0x20)
	EPROCLIM        = syscall.Errno(0x43)
	EPROCUNAVAIL    = syscall.Errno(0x4c)
	EPROGMISMATCH   = syscall.Errno(0x4b)
	EPROGUNAVAIL    = syscall.Errno(0x4a)
	EPROTO          = syscall.Errno(0x5f)
	EPROTONOSUPPORT = syscall.Errno(0x2b)
	EPROTOTYPE      = syscall.Errno(0x29)
	ERANGE          = syscall.Errno(0x22)
	EREMOTE         = syscall.Errno(0x47)
	EROFS           = syscall.Errno(0x1e)
	ERPCMISMATCH    = syscall.Errno(0x49)
	ESHUTDOWN       = syscall.Errno(0x3a)
	ESOCKTNOSUPPORT = syscall.Errno(0x2c)
	ESPIPE          = syscall.Errno(0x1d)
	ESRCH           = syscall.Errno(0x3)
	ESTALE          = syscall.Errno(0x46)
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
	SIGTHR    = syscall.Signal(0x20)
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
	{16, "EBUSY", "device busy"},
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
	{45, "EOPNOTSUPP", "operation not supported"},
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
	{69, "EDQUOT", "disk quota exceeded"},
	{70, "ESTALE", "stale NFS file handle"},
	{71, "EREMOTE", "too many levels of remote in path"},
	{72, "EBADRPC", "RPC struct is bad"},
	{73, "ERPCMISMATCH", "RPC version wrong"},
	{74, "EPROGUNAVAIL", "RPC program not available"},
	{75, "EPROGMISMATCH", "program version wrong"},
	{76, "EPROCUNAVAIL", "bad procedure for program"},
	{77, "ENOLCK", "no locks available"},
	{78, "ENOSYS", "function not implemented"},
	{79, "EFTYPE", "inappropriate file type or format"},
	{80, "EAUTH", "authentication error"},
	{81, "ENEEDAUTH", "need authenticator"},
	{82, "EIPSEC", "IPsec processing failure"},
	{83, "ENOATTR", "attribute not found"},
	{84, "EILSEQ", "illegal byte sequence"},
	{85, "ENOMEDIUM", "no medium found"},
	{86, "EMEDIUMTYPE", "wrong medium type"},
	{87, "EOVERFLOW", "value too large to be stored in data type"},
	{88, "ECANCELED", "operation canceled"},
	{89, "EIDRM", "identifier removed"},
	{90, "ENOMSG", "no message of desired type"},
	{91, "ENOTSUP", "not supported"},
	{92, "EBADMSG", "bad message"},
	{93, "ENOTRECOVERABLE", "state not recoverable"},
	{94, "EOWNERDEAD", "previous owner died"},
	{95, "ELAST", "protocol error"},
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
	{6, "SIGIOT", "abort trap"},
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
	{32, "SIGTHR", "thread AST"},
	{81920, "SIGSTKSZ", "unknown signal"},
}

"""




```