Response:
The user wants to understand the functionality of the provided Go code snippet. This is the second part of a two-part file.

**Part 1 Analysis (Implicit from instruction "This is part 2"):**

The previous part likely contained definitions for system calls and related constants specific to the `freebsd_arm64` architecture. This part seems to be defining error codes and signal codes along with their descriptions.

**Part 2 Analysis:**

1. **Constants related to TCP RACK (Reliable ACK):**  These constants (e.g., `TCP_RACK_IDLE_REDUCE_HIGH`, `TCP_RACK_MIN_PACE`) are likely used for fine-tuning the TCP RACK algorithm, which is an enhancement for TCP congestion control.

2. **Constants related to Terminal I/O Control (TTY):** Constants starting with `TIOC` (e.g., `TIOCCBRK`, `TIOCGDRAINWAIT`) represent various ioctl (input/output control) commands for manipulating terminal devices. These control things like break conditions, draining output queues, getting terminal attributes, etc.

3. **General Constants:**  Other constants like `TCP_VENDOR`, `TCSAFLUSH`, `TIMER_ABSTIME`, `TIMER_RELTIME`, `TOSTOP`, `UTIME_NOW`, `UTIME_OMIT`, `VDISCARD`, etc., represent various system-level flags and options.

4. **Error Constants:** The section starting with `// Errors` defines constants like `E2BIG`, `EACCES`, etc., which correspond to standard POSIX error numbers returned by system calls. Each is assigned a `syscall.Errno` value.

5. **Signal Constants:**  The section starting with `// Signals` defines constants like `SIGABRT`, `SIGALRM`, etc., which represent various signals that can be sent to a process. Each is assigned a `syscall.Signal` value.

6. **Error Table:** The `errorList` variable provides a mapping between the numeric error code, its symbolic name (e.g., "EPERM"), and a human-readable description.

7. **Signal Table:**  The `signalList` variable does the same for signals, mapping the numeric signal value, its symbolic name (e.g., "SIGHUP"), and a description.

**Overall Function:**

This file provides definitions for constants, error codes, and signal codes specific to the FreeBSD operating system on the ARM64 architecture. It's likely used by the `syscall` package or other low-level Go code to interact with the operating system kernel. The tables make it easier to translate between numeric error/signal values and their symbolic representations and descriptions.

**Go Code Examples:**

I'll focus on demonstrating the use of error and signal constants and tables, as these are the most directly usable parts in typical Go programs.

**Potential Pitfalls:**

The main pitfall is directly using the numerical values of these constants instead of the symbolic names. While the numbers might be consistent on a particular architecture and OS version, relying on them directly makes the code less portable and harder to understand.
Based on the provided Go code snippet, here's a breakdown of its functionality as the second part of the file `go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_freebsd_arm64.go`:

**Functionality:**

This Go code file defines constants related to the FreeBSD operating system specifically for the ARM64 architecture. It covers:

1. **TCP RACK (Reliable ACK) Constants:** It defines constants prefixed with `TCP_RACK_` which are likely related to the TCP RACK algorithm, a mechanism for improving TCP performance, especially in lossy networks. These constants control various aspects of RACK behavior, such as pacing, delay, and loss recovery.

2. **Terminal I/O Control (TTY) Constants:** It defines constants prefixed with `TIOC` (Terminal Input/Output Control). These constants represent various ioctl (input/output control) commands used to configure and interact with terminal devices. They control things like setting break conditions, flushing buffers, getting terminal attributes, managing modem lines, and controlling packet mode.

3. **General System Constants:** It defines other miscellaneous constants like `TCP_VENDOR`, `TCSAFLUSH` (to flush pending input and/or output), and `TIMER_ABSTIME`/`TIMER_RELTIME` (for specifying timer types). It also includes constants related to job control (`TOSTOP`) and time handling (`UTIME_NOW`, `UTIME_OMIT`). Constants starting with `V` are often related to terminal special characters (e.g., `VEOL` for end-of-line, `VINTR` for interrupt). Constants starting with `W` are related to wait status of child processes (e.g., `WCONTINUED`, `WEXITED`).

4. **Error Constants:** It defines a set of error constants, starting with `E` (e.g., `E2BIG`, `EACCES`). These constants represent standard POSIX error numbers returned by system calls to indicate various error conditions. Each error constant is assigned a value of type `syscall.Errno`.

5. **Signal Constants:** It defines a set of signal constants, starting with `SIG` (e.g., `SIGABRT`, `SIGKILL`). These constants represent signals that can be sent to a process to indicate various events. Each signal constant is assigned a value of type `syscall.Signal`.

6. **Error Table:** It defines a variable `errorList` which is an array of structs. Each struct maps a numeric error code (`num` of type `syscall.Errno`) to its symbolic name (`name` of type `string`) and a human-readable description (`desc` of type `string`). This table provides a way to easily look up the meaning of a given error number.

7. **Signal Table:** It defines a variable `signalList` which is an array of structs, similar to `errorList`. Each struct maps a numeric signal value (`num` of type `syscall.Signal`) to its symbolic name (`name` of type `string`) and a human-readable description (`desc` of type `string`). This table allows for easy lookup of signal meanings.

**Inferred Go Language Functionality:**

This file is part of the `syscall` package in Go's standard library (or an extended version of it). It provides a platform-specific (FreeBSD, ARM64) mapping of system-level constants, errors, and signals. The `syscall` package allows Go programs to make direct system calls to the operating system kernel.

**Go Code Example (Illustrating Error Handling):**

```go
package main

import (
	"fmt"
	"syscall"
	"golang.org/x/sys/unix" // Assuming this is where the file resides
)

func main() {
	_, _, err := unix.Syscall(unix.SYS_OPEN, uintptr(0), uintptr(unix.O_RDONLY), 0) // Try to open a non-existent file (fd 0 is usually stdin, but let's simulate an error)
	if err != nil {
		switch err {
		case unix.ENOENT:
			fmt.Println("Error: No such file or directory")
		case unix.EACCES:
			fmt.Println("Error: Permission denied")
		default:
			// Search the error table for a more detailed description
			for _, e := range unix.ErrorList {
				if e.Num == err {
					fmt.Printf("Error: %s - %s\n", e.Name, e.Desc)
					return
				}
			}
			fmt.Printf("Unknown error: %v\n", err)
		}
	}
}

// Assuming a hypothetical input that triggers an ENOENT error.
// Input: (No specific input needed for this error scenario)
// Output: Error: No such file or directory
```

**Go Code Example (Illustrating Signal Handling):**

```go
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
	"golang.org/x/sys/unix" // Assuming this is where the file resides
)

func main() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, unix.SIGUSR1) // Register for specific signals

	go func() {
		sig := <-sigs
		switch sig {
		case syscall.SIGINT:
			fmt.Println("Received SIGINT (Interrupt)")
			os.Exit(1)
		case syscall.SIGTERM:
			fmt.Println("Received SIGTERM (Termination)")
			os.Exit(1)
		case unix.SIGUSR1:
			fmt.Println("Received SIGUSR1 (User-defined signal 1)")
		default:
			fmt.Println("Received an unexpected signal:", sig)
		}
	}()

	fmt.Println("Waiting for signals...")
	time.Sleep(10 * time.Second) // Keep the program running to receive signals
	fmt.Println("Exiting.")
}

// Assuming an external process sends a SIGUSR1 signal to this program.
// Input:  (Sending signal via command line or another process: `kill -USR1 <pid>`)
// Output: Waiting for signals...
//         Received SIGUSR1 (User-defined signal 1)
//         Exiting. (after 10 seconds if no signal received)
```

**Code Reasoning:**

*   The error handling example demonstrates how to check the type of error returned by a system call and how to use the `errorList` to get a more descriptive error message if the specific error is not directly handled.
*   The signal handling example shows how to register a Go program to receive specific signals defined in the file and how to react to them.

**No Command-Line Argument Processing:**

This specific code file does not handle command-line arguments. It solely defines constants. Command-line argument processing would typically occur in the `main` function of an executable program.

**Common User Mistakes:**

*   **Using Magic Numbers:**  A common mistake is using the raw numerical values of the error or signal constants directly in code instead of using the symbolic names (e.g., using `13` instead of `unix.EACCES`). This makes the code harder to read and less portable. The symbolic names provided by this file improve code clarity.
*   **Incorrectly Interpreting Error/Signal Numbers:**  While the descriptions are provided, developers might misinterpret the specific meaning of an error or signal. It's crucial to consult the FreeBSD documentation for a comprehensive understanding.
*   **Assuming Consistency Across Platforms:**  Error and signal numbers can vary across different operating systems. Relying on specific numerical values defined in this file will make the code non-portable to other platforms (like Linux or macOS). The Go `syscall` package helps abstract some of these differences, but platform-specific constants are still necessary for finer control.

**归纳一下它的功能 (Summary of Functionality):**

This Go code file serves as a **platform-specific (FreeBSD ARM64) definition file for system-level constants, error codes, and signal codes**. It provides symbolic names and descriptions for:

*   **TCP RACK parameters:**  Allowing for configuration of the TCP RACK algorithm.
*   **Terminal I/O control commands:** Enabling manipulation of terminal device settings.
*   **General system flags and options.**
*   **POSIX error numbers:**  Representing various error conditions returned by system calls.
*   **System signal numbers:** Representing different signals that can be sent to processes.

It also includes **lookup tables (`errorList` and `signalList`)** to easily map numeric error and signal values to their symbolic names and human-readable descriptions. This file is a crucial part of the `syscall` package, enabling Go programs to interact directly with the FreeBSD kernel on ARM64 architectures.

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_freebsd_arm64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
CP_RACK_IDLE_REDUCE_HIGH      = 0x444
	TCP_RACK_MIN_PACE              = 0x445
	TCP_RACK_MIN_PACE_SEG          = 0x446
	TCP_RACK_MIN_TO                = 0x422
	TCP_RACK_PACE_ALWAYS           = 0x41f
	TCP_RACK_PACE_MAX_SEG          = 0x41e
	TCP_RACK_PACE_REDUCE           = 0x41d
	TCP_RACK_PKT_DELAY             = 0x428
	TCP_RACK_PROP                  = 0x41b
	TCP_RACK_PROP_RATE             = 0x420
	TCP_RACK_PRR_SENDALOT          = 0x421
	TCP_RACK_REORD_FADE            = 0x426
	TCP_RACK_REORD_THRESH          = 0x425
	TCP_RACK_TLP_INC_VAR           = 0x429
	TCP_RACK_TLP_REDUCE            = 0x41c
	TCP_RACK_TLP_THRESH            = 0x427
	TCP_RACK_TLP_USE               = 0x447
	TCP_VENDOR                     = 0x80000000
	TCSAFLUSH                      = 0x2
	TIMER_ABSTIME                  = 0x1
	TIMER_RELTIME                  = 0x0
	TIOCCBRK                       = 0x2000747a
	TIOCCDTR                       = 0x20007478
	TIOCCONS                       = 0x80047462
	TIOCDRAIN                      = 0x2000745e
	TIOCEXCL                       = 0x2000740d
	TIOCEXT                        = 0x80047460
	TIOCFLUSH                      = 0x80047410
	TIOCGDRAINWAIT                 = 0x40047456
	TIOCGETA                       = 0x402c7413
	TIOCGETD                       = 0x4004741a
	TIOCGPGRP                      = 0x40047477
	TIOCGPTN                       = 0x4004740f
	TIOCGSID                       = 0x40047463
	TIOCGWINSZ                     = 0x40087468
	TIOCMBIC                       = 0x8004746b
	TIOCMBIS                       = 0x8004746c
	TIOCMGDTRWAIT                  = 0x4004745a
	TIOCMGET                       = 0x4004746a
	TIOCMSDTRWAIT                  = 0x8004745b
	TIOCMSET                       = 0x8004746d
	TIOCM_CAR                      = 0x40
	TIOCM_CD                       = 0x40
	TIOCM_CTS                      = 0x20
	TIOCM_DCD                      = 0x40
	TIOCM_DSR                      = 0x100
	TIOCM_DTR                      = 0x2
	TIOCM_LE                       = 0x1
	TIOCM_RI                       = 0x80
	TIOCM_RNG                      = 0x80
	TIOCM_RTS                      = 0x4
	TIOCM_SR                       = 0x10
	TIOCM_ST                       = 0x8
	TIOCNOTTY                      = 0x20007471
	TIOCNXCL                       = 0x2000740e
	TIOCOUTQ                       = 0x40047473
	TIOCPKT                        = 0x80047470
	TIOCPKT_DATA                   = 0x0
	TIOCPKT_DOSTOP                 = 0x20
	TIOCPKT_FLUSHREAD              = 0x1
	TIOCPKT_FLUSHWRITE             = 0x2
	TIOCPKT_IOCTL                  = 0x40
	TIOCPKT_NOSTOP                 = 0x10
	TIOCPKT_START                  = 0x8
	TIOCPKT_STOP                   = 0x4
	TIOCPTMASTER                   = 0x2000741c
	TIOCSBRK                       = 0x2000747b
	TIOCSCTTY                      = 0x20007461
	TIOCSDRAINWAIT                 = 0x80047457
	TIOCSDTR                       = 0x20007479
	TIOCSETA                       = 0x802c7414
	TIOCSETAF                      = 0x802c7416
	TIOCSETAW                      = 0x802c7415
	TIOCSETD                       = 0x8004741b
	TIOCSIG                        = 0x2004745f
	TIOCSPGRP                      = 0x80047476
	TIOCSTART                      = 0x2000746e
	TIOCSTAT                       = 0x20007465
	TIOCSTI                        = 0x80017472
	TIOCSTOP                       = 0x2000746f
	TIOCSWINSZ                     = 0x80087467
	TIOCTIMESTAMP                  = 0x40107459
	TIOCUCNTL                      = 0x80047466
	TOSTOP                         = 0x400000
	UTIME_NOW                      = -0x1
	UTIME_OMIT                     = -0x2
	VDISCARD                       = 0xf
	VDSUSP                         = 0xb
	VEOF                           = 0x0
	VEOL                           = 0x1
	VEOL2                          = 0x2
	VERASE                         = 0x3
	VERASE2                        = 0x7
	VINTR                          = 0x8
	VKILL                          = 0x5
	VLNEXT                         = 0xe
	VMIN                           = 0x10
	VM_BCACHE_SIZE_MAX             = 0x19000000
	VQUIT                          = 0x9
	VREPRINT                       = 0x6
	VSTART                         = 0xc
	VSTATUS                        = 0x12
	VSTOP                          = 0xd
	VSUSP                          = 0xa
	VTIME                          = 0x11
	VWERASE                        = 0x4
	WCONTINUED                     = 0x4
	WCOREFLAG                      = 0x80
	WEXITED                        = 0x10
	WLINUXCLONE                    = 0x80000000
	WNOHANG                        = 0x1
	WNOWAIT                        = 0x8
	WSTOPPED                       = 0x2
	WTRAPPED                       = 0x20
	WUNTRACED                      = 0x2
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
	EBADMSG         = syscall.Errno(0x59)
	EBADRPC         = syscall.Errno(0x48)
	EBUSY           = syscall.Errno(0x10)
	ECANCELED       = syscall.Errno(0x55)
	ECAPMODE        = syscall.Errno(0x5e)
	ECHILD          = syscall.Errno(0xa)
	ECONNABORTED    = syscall.Errno(0x35)
	ECONNREFUSED    = syscall.Errno(0x3d)
	ECONNRESET      = syscall.Errno(0x36)
	EDEADLK         = syscall.Errno(0xb)
	EDESTADDRREQ    = syscall.Errno(0x27)
	EDOM            = syscall.Errno(0x21)
	EDOOFUS         = syscall.Errno(0x58)
	EDQUOT          = syscall.Errno(0x45)
	EEXIST          = syscall.Errno(0x11)
	EFAULT          = syscall.Errno(0xe)
	EFBIG           = syscall.Errno(0x1b)
	EFTYPE          = syscall.Errno(0x4f)
	EHOSTDOWN       = syscall.Errno(0x40)
	EHOSTUNREACH    = syscall.Errno(0x41)
	EIDRM           = syscall.Errno(0x52)
	EILSEQ          = syscall.Errno(0x56)
	EINPROGRESS     = syscall.Errno(0x24)
	EINTEGRITY      = syscall.Errno(0x61)
	EINTR           = syscall.Errno(0x4)
	EINVAL          = syscall.Errno(0x16)
	EIO             = syscall.Errno(0x5)
	EISCONN         = syscall.Errno(0x38)
	EISDIR          = syscall.Errno(0x15)
	ELAST           = syscall.Errno(0x61)
	ELOOP           = syscall.Errno(0x3e)
	EMFILE          = syscall.Errno(0x18)
	EMLINK          = syscall.Errno(0x1f)
	EMSGSIZE        = syscall.Errno(0x28)
	EMULTIHOP       = syscall.Errno(0x5a)
	ENAMETOOLONG    = syscall.Errno(0x3f)
	ENEEDAUTH       = syscall.Errno(0x51)
	ENETDOWN        = syscall.Errno(0x32)
	ENETRESET       = syscall.Errno(0x34)
	ENETUNREACH     = syscall.Errno(0x33)
	ENFILE          = syscall.Errno(0x17)
	ENOATTR         = syscall.Errno(0x57)
	ENOBUFS         = syscall.Errno(0x37)
	ENODEV          = syscall.Errno(0x13)
	ENOENT          = syscall.Errno(0x2)
	ENOEXEC         = syscall.Errno(0x8)
	ENOLCK          = syscall.Errno(0x4d)
	ENOLINK         = syscall.Errno(0x5b)
	ENOMEM          = syscall.Errno(0xc)
	ENOMSG          = syscall.Errno(0x53)
	ENOPROTOOPT     = syscall.Errno(0x2a)
	ENOSPC          = syscall.Errno(0x1c)
	ENOSYS          = syscall.Errno(0x4e)
	ENOTBLK         = syscall.Errno(0xf)
	ENOTCAPABLE     = syscall.Errno(0x5d)
	ENOTCONN        = syscall.Errno(0x39)
	ENOTDIR         = syscall.Errno(0x14)
	ENOTEMPTY       = syscall.Errno(0x42)
	ENOTRECOVERABLE = syscall.Errno(0x5f)
	ENOTSOCK        = syscall.Errno(0x26)
	ENOTSUP         = syscall.Errno(0x2d)
	ENOTTY          = syscall.Errno(0x19)
	ENXIO           = syscall.Errno(0x6)
	EOPNOTSUPP      = syscall.Errno(0x2d)
	EOVERFLOW       = syscall.Errno(0x54)
	EOWNERDEAD      = syscall.Errno(0x60)
	EPERM           = syscall.Errno(0x1)
	EPFNOSUPPORT    = syscall.Errno(0x2e)
	EPIPE           = syscall.Errno(0x20)
	EPROCLIM        = syscall.Errno(0x43)
	EPROCUNAVAIL    = syscall.Errno(0x4c)
	EPROGMISMATCH   = syscall.Errno(0x4b)
	EPROGUNAVAIL    = syscall.Errno(0x4a)
	EPROTO          = syscall.Errno(0x5c)
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
	SIGLIBRT  = syscall.Signal(0x21)
	SIGLWP    = syscall.Signal(0x20)
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
	{35, "EWOULDBLOCK", "resource temporarily unavailable"},
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
	{82, "EIDRM", "identifier removed"},
	{83, "ENOMSG", "no message of desired type"},
	{84, "EOVERFLOW", "value too large to be stored in data type"},
	{85, "ECANCELED", "operation canceled"},
	{86, "EILSEQ", "illegal byte sequence"},
	{87, "ENOATTR", "attribute not found"},
	{88, "EDOOFUS", "programming error"},
	{89, "EBADMSG", "bad message"},
	{90, "EMULTIHOP", "multihop attempted"},
	{91, "ENOLINK", "link has been severed"},
	{92, "EPROTO", "protocol error"},
	{93, "ENOTCAPABLE", "capabilities insufficient"},
	{94, "ECAPMODE", "not permitted in capability mode"},
	{95, "ENOTRECOVERABLE", "state not recoverable"},
	{96, "EOWNERDEAD", "previous owner died"},
	{97, "EINTEGRITY", "integrity check failed"},
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
	{32, "SIGTHR", "unknown signal"},
	{33, "SIGLIBRT", "unknown signal"},
}
```