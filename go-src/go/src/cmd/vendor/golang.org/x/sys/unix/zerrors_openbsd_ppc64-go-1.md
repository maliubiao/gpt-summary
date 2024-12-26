Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding - What is the file about?**

The path `go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_openbsd_ppc64.go` provides a lot of information.

* **`go/src/cmd/vendor/`:**  This immediately signals that the code is likely a vendored dependency. This means it's a copy of external code included directly within the project, rather than being fetched as a standard package.
* **`golang.org/x/sys/unix/`:** This indicates it's part of the Go standard library's extensions for interacting with operating system-level system calls, specifically for Unix-like systems.
* **`zerrors_openbsd_ppc64.go`:** The `zerrors` prefix suggests this file likely contains automatically generated error and signal definitions. `openbsd` specifies the target operating system, and `ppc64` specifies the target architecture (PowerPC 64-bit).

Therefore, the primary function is to define system-level constants (errors and signals) specific to OpenBSD on the ppc64 architecture.

**2. Analyzing the Content - What specific things are defined?**

The code is structured into three main constant blocks and two variable blocks:

* **`const (...)` block with no explicit type:** This block contains a large number of constants, many starting with `TIO`, `VM`, `V`, `W`, and `XCASE`. The lack of an explicit type suggests these are likely integer constants. The prefixes hint at their meaning:
    * `TIO`:  Likely related to terminal I/O control (`ioctl`).
    * `VM`:  Likely related to virtual memory.
    * `V`:  Likely related to terminal special characters.
    * `W`:  Likely related to process status.
    * `XCASE`: Likely related to terminal settings.

* **`const (...)` block with `syscall.Errno` type:** This block defines constants representing error codes returned by system calls. The `syscall.Errno` type confirms this. Each constant corresponds to a specific error like `EACCES` (Permission denied), `ENOENT` (No such file or directory), etc.

* **`const (...)` block with `syscall.Signal` type:** This block defines constants representing signals that can be sent to processes. The `syscall.Signal` type confirms this. Each constant corresponds to a specific signal like `SIGINT` (Interrupt), `SIGKILL` (Kill), etc.

* **`var errorList = [...]struct {...}`:** This defines a slice (or array with a specified length in this case) of structs. Each struct contains an error number (`num`), its symbolic name (`name`), and a textual description (`desc`). This appears to be a mapping from the numerical error code to its human-readable representation.

* **`var signalList = [...]struct {...}`:**  Similar to `errorList`, this defines a slice of structs mapping signal numbers to their names and descriptions.

**3. Inferring Functionality and Purpose:**

Based on the content, the file's primary function is to provide Go programs running on OpenBSD/ppc64 with access to:

* **System call constants:**  Constants used as arguments or return values for system calls (especially `ioctl`).
* **Error numbers:**  Symbolic names for common error codes returned by system calls, allowing for more readable error handling.
* **Signal numbers:** Symbolic names for signals that can be used for process communication and control.
* **Human-readable descriptions:**  For both errors and signals, providing descriptive text for logging and debugging.

**4. Illustrative Go Code Example (Based on Inference):**

Since the file defines constants, the most common way to use it is by referencing these constants within Go code when interacting with the operating system.

* **Hypothesis:** The `TIOCGWINSZ` constant is likely used with the `unix.IoctlGetWinsize` function to get the terminal window size.

* **Go Code Example:**

```go
package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func main() {
	// Assume standard input is connected to a terminal
	fd := int(os.Stdin.Fd())

	var ws unix.Winsize
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(unix.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws)))
	if err != 0 {
		fmt.Println("Error getting window size:", err)
		return
	}

	fmt.Printf("Window size: Rows=%d, Cols=%d\n", ws.Row, ws.Col)
}
```

* **Assumptions:**  This code assumes that the `TIOCGWINSZ` constant defined in the `zerrors` file is the correct value to use with the `ioctl` system call for getting the window size on OpenBSD/ppc64.

* **Potential Output:** If run in a terminal with, say, 24 rows and 80 columns, the output would be:

```
Window size: Rows=24, Cols=80
```

**5. Reasoning about `errorList` and `signalList`:**

These lists are likely used internally within the `golang.org/x/sys/unix` package to provide functions that can convert raw error numbers and signal numbers into human-readable strings.

* **Hypothesis:** There might be functions like `unix.ErrnoName(errno syscall.Errno)` and `unix.SignalName(sig syscall.Signal)`.

* **Illustrative Usage (no code from the snippet itself can confirm this, but it's a reasonable inference):**

```go
package main

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

func main() {
	err := syscall.Errno(unix.EACCES)
	fmt.Println(unix.ErrnoName(err)) // Output: permission denied

	sig := syscall.Signal(unix.SIGINT)
	fmt.Println(unix.SignalName(sig)) // Output: interrupt
}
```

**6. Common Pitfalls (Based on General Knowledge):**

The most common mistake when dealing with system-level programming is using the wrong constant for a particular system call or operation. This file helps *prevent* that by providing the correct constants for the specific platform. However, a user might still:

* **Use constants from a different platform:**  If code isn't properly platform-aware, it might try to use constants defined for Linux on OpenBSD, leading to incorrect behavior.

**7. Final Summary:**

The code defines architecture-specific constants (terminal I/O controls, virtual memory settings, process status flags, error codes, and signals) for the OpenBSD operating system on the ppc64 architecture. It serves as a crucial bridge between Go programs and the underlying operating system, enabling low-level system interactions. The `errorList` and `signalList` provide mappings for converting numerical error and signal values to human-readable strings, likely used for error reporting and debugging.
这是 `go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_openbsd_ppc64.go` 文件的第二部分，与第一部分一起定义了在 OpenBSD 操作系统，powerpc64 架构下，Go 语言与底层操作系统交互时需要用到的一些常量、错误码和信号。

**归纳一下它的功能:**

这部分代码主要功能是 **定义了大量的常量，这些常量代表了 OpenBSD 操作系统在 powerpc64 架构下的错误码 (Errno) 和信号 (Signal)。**  它还包含了将这些错误码和信号值映射到其名称和描述的表格。

**具体功能分解:**

1. **定义错误码常量:**  使用 `const` 关键字定义了一系列以 `E` 开头的常量，例如 `E2BIG`, `EACCES`, `ENOENT` 等。 这些常量的值是 `syscall.Errno` 类型，对应了 OpenBSD 系统调用可能返回的各种错误代码。

2. **定义信号常量:** 使用 `const` 关键字定义了一系列以 `SIG` 开头的常量，例如 `SIGABRT`, `SIGALRM`, `SIGINT` 等。 这些常量的值是 `syscall.Signal` 类型，对应了 OpenBSD 系统中可以发送给进程的各种信号。

3. **定义错误码列表 `errorList`:**  定义了一个名为 `errorList` 的数组，其元素是结构体类型，包含三个字段：
    * `num`: `syscall.Errno` 类型，存储错误码的数值。
    * `name`: `string` 类型，存储错误码的名称（例如 "EPERM"）。
    * `desc`: `string` 类型，存储错误码的描述信息（例如 "operation not permitted"）。
    这个列表将数字错误码与其对应的名称和描述关联起来。

4. **定义信号列表 `signalList`:** 定义了一个名为 `signalList` 的数组，其元素也是结构体类型，包含三个字段：
    * `num`: `syscall.Signal` 类型，存储信号的数值。
    * `name`: `string` 类型，存储信号的名称（例如 "SIGHUP"）。
    * `desc`: `string` 类型，存储信号的描述信息（例如 "hangup"）。
    这个列表将数字信号与其对应的名称和描述关联起来。

**它是什么 Go 语言功能的实现：**

这部分代码是 `golang.org/x/sys/unix` 包的一部分，该包提供了对底层 Unix 系统调用的访问。 它通过定义这些常量和映射表，使得 Go 语言程序能够以更具可读性和可维护性的方式与 OpenBSD 操作系统进行交互，处理系统调用返回的错误和信号。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func main() {
	// 假设我们尝试打开一个不存在的文件
	fd, err := syscall.Open("/nonexistent_file", syscall.O_RDONLY, 0)
	if err != nil {
		// 检查错误是否是 ENOENT (No such file or directory)
		if err == syscall.ENOENT {
			fmt.Println("文件不存在:", err)
		} else {
			fmt.Println("打开文件时发生其他错误:", err)
		}
	}
	if fd != -1 {
		syscall.Close(fd)
	}

	// 发送 SIGKILL 信号给一个进程 (这里仅为演示，实际操作需谨慎)
	pid := syscall.Getpid()
	errSignal := syscall.Kill(pid, syscall.SIGKILL)
	if errSignal != nil {
		fmt.Println("发送信号时发生错误:", errSignal)
	}

	// 查找错误码对应的名称和描述
	var errorName, errorDesc string
	for _, errInfo := range unix.ErrorList { // 注意这里使用了 unix.ErrorList
		if errInfo.Errno == syscall.ENOENT {
			errorName = errInfo.Name
			errorDesc = errInfo.Description
			break
		}
	}
	fmt.Printf("错误码 %d 的名称是: %s, 描述是: %s\n", syscall.ENOENT, errorName, errorDesc)

	// 查找信号对应的名称和描述
	var signalName, signalDesc string
	for _, sigInfo := range unix.SignalList { // 注意这里使用了 unix.SignalList
		if sigInfo.Signal == syscall.SIGKILL {
			signalName = sigInfo.Name
			signalDesc = sigInfo.Description
			break
		}
	}
	fmt.Printf("信号 %d 的名称是: %s, 描述是: %s\n", syscall.SIGKILL, signalName, signalDesc)
}
```

**假设的输入与输出:**

在这个例子中，假设 `/nonexistent_file` 文件不存在。

**可能的输出:**

```
文件不存在: no such file or directory
发送信号时发生错误: operation not permitted  // 因为进程不能随意给自己发送 SIGKILL
错误码 2 的名称是: ENOENT, 描述是: no such file or directory
信号 9 的名称是: SIGKILL, 描述是: killed
```

**命令行参数的具体处理:**

这段代码本身不涉及命令行参数的处理。它只是定义了一些常量和数据结构，用于在 Go 语言程序中与操作系统进行交互。命令行参数的处理通常在程序的 `main` 函数中使用 `os.Args` 或 `flag` 包进行。

**使用者易犯错的点:**

* **平台差异:** 这些常量是特定于 OpenBSD 和 powerpc64 架构的。如果在其他操作系统或架构下运行相同的代码，这些常量的值可能不同，导致程序行为异常。使用者需要注意平台兼容性。
* **错误码和信号的理解:**  开发者需要理解每个错误码和信号的具体含义，才能正确地处理系统调用返回的错误和操作系统发送的信号。 错误地理解或处理这些值可能导致程序崩溃或行为不符合预期。
* **直接使用数值而非常量:**  虽然可以使用数字来表示错误码和信号，但这会降低代码的可读性和可维护性。 推荐使用这里定义的常量，例如 `syscall.ENOENT` 而不是直接使用数字 `2`。

**总结一下它的功能 (结合第 1 部分):**

这个 `zerrors_openbsd_ppc64.go` 文件及其第一部分共同定义了在 OpenBSD 操作系统，powerpc64 架构下，Go 语言进行系统编程时需要用到的各种常量。 这些常量包括：

* **系统调用相关的宏定义:** 例如 `O_RDONLY`, `S_IFREG` 等，用于传递给系统调用。
* **`ioctl` 系统调用相关的常量:** 例如 `TIOCGWINSZ`, `TIOCSETA` 等，用于控制终端设备。
* **虚拟内存相关的常量:** 例如 `VM_ANONMIN`, `VM_METER` 等。
* **错误码 (Errno) 常量:**  用于表示系统调用失败的原因。
* **信号 (Signal) 常量:** 用于进程间通信和操作系统通知。

此外，它还提供了将错误码和信号值映射到其名称和描述的列表，方便程序进行错误处理和日志记录。  总而言之，这个文件为 Go 语言在 OpenBSD/ppc64 平台上的系统编程提供了必要的底层定义。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_openbsd_ppc64.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	{32, "SIGTHR", "thread AST"},
}

"""




```