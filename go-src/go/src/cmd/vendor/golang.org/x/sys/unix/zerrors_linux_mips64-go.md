Response:
Let's break down the thought process to analyze the provided Go code snippet.

**1. Initial Scan and Identification of Key Elements:**

The first thing I do is scan the code for structural elements and keywords. I notice:

* **Comments:**  The initial comments about `mkerrors.sh` and `cgo -godefs` are immediately important. They tell me this file isn't hand-written but generated. The `-I/tmp/mips64/include` hints at cross-compilation or a specific architecture target. The `go:build mips64 && linux` confirms the target architecture and OS.
* **Package Declaration:** `package unix` – This tells me it's part of the `unix` package, likely providing low-level OS interactions.
* **Imports:** `import "syscall"` –  This is a crucial import. The `syscall` package provides the fundamental interface to system calls.
* **Constants:**  A large block of `const` declarations. These constants have names that often correspond to POSIX or Linux kernel definitions (like `O_CREAT`, `BLKGETSIZE`, `SIGBUS`, `EADDRINUSE`). The hexadecimal values are also typical of system call related constants.
* **Error and Signal Tables:**  `errorList` and `signalList` are clearly defined as arrays of structs, mapping numerical error/signal codes to their names and descriptions.

**2. Deduction of Functionality:**

Based on the elements identified above, I can start to infer the file's purpose:

* **Platform-Specific Constants:** The `go:build` directive and the `mips64` in the file name and comments clearly indicate that this file provides constants specific to the Linux operating system running on the MIPS64 architecture. These constants are likely used to interact with the kernel.
* **System Call Definitions:** The nature of the constants (starting with `B`, `BLK`, `C`, `F`, `HIDIOC`, `PPPIOC`, `PTP`, `PTRACE`, `RLIMIT`, `RND`, `RTC`, `SCM`, `SECCOMP`, `SFD`, `SIOC`, `SOCK`, `SOL`, `SO`, `TAB`, `TC`, `TFD`, `TIOC`, `TOSTOP`, `TUN`, `UBI`, `V`, `WDIOC`) strongly suggests they are related to various system call interfaces, ioctls, and other low-level operations.
* **Error and Signal Mapping:** The `errorList` and `signalList` are clearly designed to provide a Go-friendly way to access and understand system errors and signals, mapping their numerical values to human-readable names and descriptions. This is important because system calls often return numerical error codes.

**3. Hypothesizing the Go Language Feature:**

Given the focus on constants and the `syscall` package, the most likely Go language feature being implemented is **providing a low-level interface to the operating system's system call API for the specific `mips64` and `linux` platform.**  This allows Go programs to interact directly with the kernel for tasks like file I/O, networking, process management, etc.

**4. Constructing Go Code Examples:**

Now I try to create concrete examples demonstrating how these constants might be used:

* **File I/O:**  Constants like `O_RDWR`, `O_CREAT`, `O_TRUNC` are commonly used with `os.OpenFile`. I create a simple example showing this.
* **Socket Programming:**  Constants like `SOCK_STREAM`, `AF_INET`, `SO_REUSEADDR` are fundamental in socket programming. I construct an example showcasing socket creation and option setting.
* **ioctl System Call:** The presence of many `TIOC`, `BLK`, etc., constants suggests usage with `syscall.Syscall` and `unix.Ioctl`. I create a basic example demonstrating how to use `unix.Ioctl` with a `BLKGETSIZE64` constant to get disk size. *Initially, I might forget the specific `unix.Ioctl` function and just think about `syscall.Syscall`. Then I would review the `unix` package documentation (or through trial and error) and realize `unix.Ioctl` is the more convenient wrapper.*
* **Signal Handling:**  Constants like `SIGINT`, `SIGTERM` are essential for signal handling. I create an example of catching `SIGINT`.

**5. Reasoning about Inputs and Outputs (for Code Examples):**

For each code example, I consider:

* **Inputs:** What are the values passed to the functions or system calls?  For the `OpenFile` example, it's the filename and the combination of `O_RDWR`, `O_CREAT`, and `O_TRUNC`. For `Ioctl`, it's the file descriptor and the ioctl request constant.
* **Outputs:** What is the expected result?  For `OpenFile`, it's a file descriptor or an error. For `Ioctl`, it's the size of the disk (or an error). For signals, it's the execution of the signal handling function.

**6. Considering Command-Line Arguments:**

I look for constants that might directly relate to command-line arguments. In this specific file, there aren't any *directly* representing command-line arguments. The constants are lower-level. However, I realize that tools built using these constants might *take* command-line arguments. For instance, a disk utility using `BLKGETSIZE64` might accept a device path as a command-line argument. So I explain this indirect relationship.

**7. Identifying Potential User Errors:**

I think about common mistakes developers make when working with low-level OS interfaces:

* **Incorrect Constant Usage:** Using a constant intended for a different architecture or OS. This is less likely with this generated file, but still a possibility if developers mix code from different platforms.
* **Incorrect ioctl Arguments:**  Passing the wrong data structures or sizes to `unix.Ioctl`. This is a common source of errors when working with ioctls. I emphasize the importance of correct usage and casting.
* **Signal Handling Issues:**  Not handling signals gracefully, leading to unexpected program termination. Forgetting to restore default signal handlers if needed.

**8. Review and Refinement:**

Finally, I review my analysis and examples for clarity, accuracy, and completeness. I make sure the explanation of the generated nature of the file is clear, and that the examples are practical and easy to understand. I also check that I've addressed all the prompts in the original request.

This iterative process of scanning, deducing, hypothesizing, exemplifying, and reviewing allows for a comprehensive understanding of the provided code snippet and its role within the Go ecosystem.
The Go code snippet you provided is an autogenerated file (`zerrors_linux_mips64.go`) that serves as a **machine-readable representation of system-level constants, error numbers, and signal numbers specific to the Linux operating system on the MIPS64 architecture.**

Here's a breakdown of its functionality:

**1. Defining System Constants:**

* The bulk of the file consists of `const` declarations. These constants represent values defined in the Linux kernel headers (likely those under `/tmp/mips64/include` during the generation process).
* These constants cover a wide range of kernel functionalities, including:
    * **Terminal I/O (TTY):** Constants starting with `B`, `C`, `TIO`, representing baud rates, control flags, and ioctl requests for terminal devices.
    * **Block Devices:** Constants starting with `BLK`, related to ioctl requests for block devices (disks, partitions), such as getting size, setting block size, discarding data, etc.
    * **File System Operations:** Constants starting with `FS_IOC`, `F_`, related to ioctl requests for file system operations like getting/setting flags, encryption policies, and file locking.
    * **Epoll:** Constants related to the `epoll` mechanism for I/O event notification (`EPOLL_CLOEXEC`).
    * **FUSE (Filesystem in Userspace):**  While not explicitly present in this snippet, similar constant files might include FUSE-related definitions.
    * **HID (Human Interface Devices):** Constants starting with `HIDIOC`, for ioctl requests related to HID devices.
    * **Memory Locking:** Constants like `MAP_LOCKED`, `MCL_CURRENT`, `MCL_FUTURE`.
    * **Memory Management:** Constants starting with `MEM`, for ioctl requests related to memory devices.
    * **Network Namespaces:** Constants starting with `NS_GET`, for operations related to network namespaces.
    * **Open Flags:** Constants starting with `O_`, used with the `open` system call (e.g., `O_RDWR`, `O_CREAT`).
    * **PPP (Point-to-Point Protocol):** Constants starting with `PPPIOC`, for ioctl requests related to PPP interfaces.
    * **PTP (Precision Time Protocol):** Constants starting with `PTP_CLOCK`, for ioctl requests related to PTP hardware clocks.
    * **Ptrace (Process Tracing):** Constants starting with `PTRACE_`, for operations related to process tracing and debugging.
    * **Resource Limits:** Constants starting with `RLIMIT_`, defining resource limits for processes.
    * **Random Number Generation:** Constants starting with `RND`, for ioctl requests related to the kernel's random number generator.
    * **Real-Time Clock (RTC):** Constants starting with `RTC_`, for ioctl requests related to the system's real-time clock.
    * **Socket Options:** Constants starting with `SO_`, used with `setsockopt` and `getsockopt` system calls to configure socket behavior.
    * **Signals:** Constants starting with `SIG`, representing various signals that can be sent to processes.
    * **Sockets:** Constants like `SOCK_STREAM`, `SOCK_DGRAM`, `SOL_SOCKET`.
    * **Syscalls:**  While not directly syscall numbers, many constants map to parameters used in syscalls.
    * **Timer File Descriptors:** Constants starting with `TFD_`.
    * **TUN/TAP Interfaces:** Constants starting with `TUN`, for ioctl requests related to virtual network interfaces.
    * **UBI (Unsorted Block Images):** Constants starting with `UBI_IOC`, for ioctl requests related to UBI devices.
    * **Watchdog Timer:** Constants starting with `WDIOC_`, for ioctl requests related to the watchdog timer.

**2. Defining System Errors:**

* The `Errors` section defines constants representing common error numbers returned by system calls.
* These constants are of type `syscall.Errno`, which is Go's representation of system error codes. Examples include `EADDRINUSE`, `ENOENT`, `EPERM`.

**3. Defining System Signals:**

* The `Signals` section defines constants representing signals that can be sent to processes.
* These constants are of type `syscall.Signal`. Examples include `SIGINT`, `SIGKILL`, `SIGTERM`.

**4. Providing Error and Signal Tables:**

* The `errorList` and `signalList` are arrays of structs.
* Each struct contains the numerical value, symbolic name, and a human-readable description of an error or signal, respectively. This is useful for converting raw error/signal numbers into more understandable information.

**In essence, this file acts as a bridge between the Go language and the underlying Linux kernel on the MIPS64 architecture, providing Go programs with the necessary symbolic names and numerical values to interact with the operating system at a low level.**

**What Go Language Feature Does This Implement?**

This file is a crucial part of the implementation of the `syscall` and `unix` packages in Go's standard library. Specifically, it provides the **platform-specific definitions** needed for these packages to interact with the Linux kernel on MIPS64.

**Go Code Example:**

Let's illustrate how some of these constants might be used with the `syscall` and `unix` packages.

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
	// Using O_RDWR and O_CREATE constants for opening a file
	fd, err := syscall.Open("myfile.txt", syscall.O_RDWR|syscall.O_CREATE, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	fmt.Println("File opened successfully with file descriptor:", fd)
	syscall.Close(fd)

	// Using BLKGETSIZE64 to get the size of a block device
	devPath := "/dev/sda" // Replace with an actual block device path
	devFd, err := syscall.Open(devPath, syscall.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		fmt.Println("Error opening device:", err)
		return
	}
	defer syscall.Close(devFd)

	var size int64
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(devFd), unix.BLKGETSIZE64, uintptr(unsafe.Pointer(&size)))
	if errno != 0 {
		fmt.Println("Error getting device size:", syscall.Errno(errno))
		return
	}
	fmt.Printf("Size of %s: %d bytes\n", devPath, size)

	// Handling SIGINT signal
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT)

	go func() {
		s := <-signalChan
		fmt.Println("\nReceived signal:", s)
		// Perform cleanup actions here
		os.Exit(0)
	}()

	fmt.Println("Waiting for SIGINT (Ctrl+C)...")
	// Keep the program running
	select {}
}
```

**Assumptions and Inputs/Outputs:**

* **For the `syscall.Open` example:**
    * **Input:** Filename "myfile.txt", flags `syscall.O_RDWR|syscall.O_CREATE`, permissions `0644`.
    * **Output:** If successful, a non-negative file descriptor (integer). If an error occurs (e.g., permission issues), a negative file descriptor and an error value.
* **For the `unix.BLKGETSIZE64` example:**
    * **Input:** Device path `/dev/sda` (you need to replace this with a valid block device on your system).
    * **Output:** If successful, the `size` variable will contain the size of the block device in bytes. If an error occurs (e.g., invalid device path, permission issues), an error message will be printed.
* **For the Signal Handling example:**
    * **Input:** The user pressing Ctrl+C in the terminal, which sends the `SIGINT` signal.
    * **Output:** The program will catch the `SIGINT` signal, print a message, and then exit gracefully.

**Command-Line Parameter Handling:**

This specific file doesn't handle command-line parameters directly. It defines constants that are *used* by other parts of the `syscall` and `unix` packages, which might be involved in handling command-line parameters.

For instance, if you were writing a command-line utility that uses block device operations, you might use constants like `unix.BLKGETSIZE64` along with the `syscall` package to interact with the specified block device path provided as a command-line argument.

**Example of Indirect Command-Line Usage:**

Imagine a simplified command-line tool to get the size of a block device:

```go
package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func main() {
	devicePtr := flag.String("device", "", "Path to the block device")
	flag.Parse()

	if *devicePtr == "" {
		fmt.Println("Please provide the path to the block device using the -device flag.")
		os.Exit(1)
	}

	devFd, err := syscall.Open(*devicePtr, syscall.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		fmt.Println("Error opening device:", err)
		os.Exit(1)
	}
	defer syscall.Close(devFd)

	var size int64
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(devFd), unix.BLKGETSIZE64, uintptr(unsafe.Pointer(&size)))
	if errno != 0 {
		fmt.Println("Error getting device size:", syscall.Errno(errno))
		os.Exit(1)
	}
	fmt.Printf("Size of %s: %d bytes\n", *devicePtr, size)
}
```

In this example:

* The `flag` package is used to define a command-line parameter `-device`.
* The `main` function retrieves the value of the `-device` flag.
* The code then uses `unix.BLKGETSIZE64` (from the file you provided) to get the size of the device specified by the command-line argument.

**User Mistakes (Potential):**

While users don't directly edit this autogenerated file, they can make mistakes when *using* the constants defined in it:

1. **Incorrectly assuming cross-platform compatibility:**  These constants are specific to Linux on the MIPS64 architecture. Using them on other operating systems or architectures will lead to errors or unexpected behavior. For truly cross-platform code, you need to use platform-agnostic abstractions or conditionally compile code for different platforms.

2. **Using the wrong constant for a specific ioctl:**  There are many similar-sounding constants. Referring to the correct kernel documentation or header files is crucial to use the right constant for the intended ioctl operation. For example, using `BLKGETSIZE` (which might return a 32-bit value) when the device requires `BLKGETSIZE64` could lead to incorrect results on large devices.

3. **Incorrectly using bitwise operations with flags:** Many constants are used as bit flags. Users might make mistakes when combining them using bitwise OR (`|`) or checking for their presence using bitwise AND (`&`).

4. **Not checking errors after system calls:**  System calls that use these constants can fail. It's essential to always check the error return value and handle potential errors appropriately.

This autogenerated file, though not directly manipulated by developers, is a fundamental building block for low-level system interaction in Go programs targeting Linux on the MIPS64 architecture. It provides the necessary vocabulary for Go code to "speak" to the kernel.

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/zerrors_linux_mips64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// mkerrors.sh -Wall -Werror -static -I/tmp/mips64/include
// Code generated by the command above; see README.md. DO NOT EDIT.

//go:build mips64 && linux

// Code generated by cmd/cgo -godefs; DO NOT EDIT.
// cgo -godefs -- -Wall -Werror -static -I/tmp/mips64/include _const.go

package unix

import "syscall"

const (
	B1000000                         = 0x1008
	B115200                          = 0x1002
	B1152000                         = 0x1009
	B1500000                         = 0x100a
	B2000000                         = 0x100b
	B230400                          = 0x1003
	B2500000                         = 0x100c
	B3000000                         = 0x100d
	B3500000                         = 0x100e
	B4000000                         = 0x100f
	B460800                          = 0x1004
	B500000                          = 0x1005
	B57600                           = 0x1001
	B576000                          = 0x1006
	B921600                          = 0x1007
	BLKALIGNOFF                      = 0x2000127a
	BLKBSZGET                        = 0x40081270
	BLKBSZSET                        = 0x80081271
	BLKDISCARD                       = 0x20001277
	BLKDISCARDZEROES                 = 0x2000127c
	BLKFLSBUF                        = 0x20001261
	BLKFRAGET                        = 0x20001265
	BLKFRASET                        = 0x20001264
	BLKGETDISKSEQ                    = 0x40081280
	BLKGETSIZE                       = 0x20001260
	BLKGETSIZE64                     = 0x40081272
	BLKIOMIN                         = 0x20001278
	BLKIOOPT                         = 0x20001279
	BLKPBSZGET                       = 0x2000127b
	BLKRAGET                         = 0x20001263
	BLKRASET                         = 0x20001262
	BLKROGET                         = 0x2000125e
	BLKROSET                         = 0x2000125d
	BLKROTATIONAL                    = 0x2000127e
	BLKRRPART                        = 0x2000125f
	BLKSECDISCARD                    = 0x2000127d
	BLKSECTGET                       = 0x20001267
	BLKSECTSET                       = 0x20001266
	BLKSSZGET                        = 0x20001268
	BLKZEROOUT                       = 0x2000127f
	BOTHER                           = 0x1000
	BS1                              = 0x2000
	BSDLY                            = 0x2000
	CBAUD                            = 0x100f
	CBAUDEX                          = 0x1000
	CIBAUD                           = 0x100f0000
	CLOCAL                           = 0x800
	CR1                              = 0x200
	CR2                              = 0x400
	CR3                              = 0x600
	CRDLY                            = 0x600
	CREAD                            = 0x80
	CS6                              = 0x10
	CS7                              = 0x20
	CS8                              = 0x30
	CSIZE                            = 0x30
	CSTOPB                           = 0x40
	ECCGETLAYOUT                     = 0x41484d11
	ECCGETSTATS                      = 0x40104d12
	ECHOCTL                          = 0x200
	ECHOE                            = 0x10
	ECHOK                            = 0x20
	ECHOKE                           = 0x800
	ECHONL                           = 0x40
	ECHOPRT                          = 0x400
	EFD_CLOEXEC                      = 0x80000
	EFD_NONBLOCK                     = 0x80
	EPIOCGPARAMS                     = 0x40088a02
	EPIOCSPARAMS                     = 0x80088a01
	EPOLL_CLOEXEC                    = 0x80000
	EXTPROC                          = 0x10000
	FF1                              = 0x8000
	FFDLY                            = 0x8000
	FICLONE                          = 0x80049409
	FICLONERANGE                     = 0x8020940d
	FLUSHO                           = 0x2000
	FS_IOC_ENABLE_VERITY             = 0x80806685
	FS_IOC_GETFLAGS                  = 0x40086601
	FS_IOC_GET_ENCRYPTION_NONCE      = 0x4010661b
	FS_IOC_GET_ENCRYPTION_POLICY     = 0x800c6615
	FS_IOC_GET_ENCRYPTION_PWSALT     = 0x80106614
	FS_IOC_SETFLAGS                  = 0x80086602
	FS_IOC_SET_ENCRYPTION_POLICY     = 0x400c6613
	F_GETLK                          = 0xe
	F_GETLK64                        = 0xe
	F_GETOWN                         = 0x17
	F_RDLCK                          = 0x0
	F_SETLK                          = 0x6
	F_SETLK64                        = 0x6
	F_SETLKW                         = 0x7
	F_SETLKW64                       = 0x7
	F_SETOWN                         = 0x18
	F_UNLCK                          = 0x2
	F_WRLCK                          = 0x1
	HIDIOCGRAWINFO                   = 0x40084803
	HIDIOCGRDESC                     = 0x50044802
	HIDIOCGRDESCSIZE                 = 0x40044801
	HIDIOCREVOKE                     = 0x8004480d
	HUPCL                            = 0x400
	ICANON                           = 0x2
	IEXTEN                           = 0x100
	IN_CLOEXEC                       = 0x80000
	IN_NONBLOCK                      = 0x80
	IOCTL_VM_SOCKETS_GET_LOCAL_CID   = 0x200007b9
	ISIG                             = 0x1
	IUCLC                            = 0x200
	IXOFF                            = 0x1000
	IXON                             = 0x400
	MAP_ANON                         = 0x800
	MAP_ANONYMOUS                    = 0x800
	MAP_DENYWRITE                    = 0x2000
	MAP_EXECUTABLE                   = 0x4000
	MAP_GROWSDOWN                    = 0x1000
	MAP_HUGETLB                      = 0x80000
	MAP_LOCKED                       = 0x8000
	MAP_NONBLOCK                     = 0x20000
	MAP_NORESERVE                    = 0x400
	MAP_POPULATE                     = 0x10000
	MAP_RENAME                       = 0x800
	MAP_STACK                        = 0x40000
	MCL_CURRENT                      = 0x1
	MCL_FUTURE                       = 0x2
	MCL_ONFAULT                      = 0x4
	MEMERASE                         = 0x80084d02
	MEMERASE64                       = 0x80104d14
	MEMGETBADBLOCK                   = 0x80084d0b
	MEMGETINFO                       = 0x40204d01
	MEMGETOOBSEL                     = 0x40c84d0a
	MEMGETREGIONCOUNT                = 0x40044d07
	MEMISLOCKED                      = 0x40084d17
	MEMLOCK                          = 0x80084d05
	MEMREAD                          = 0xc0404d1a
	MEMREADOOB                       = 0xc0104d04
	MEMSETBADBLOCK                   = 0x80084d0c
	MEMUNLOCK                        = 0x80084d06
	MEMWRITEOOB                      = 0xc0104d03
	MTDFILEMODE                      = 0x20004d13
	NFDBITS                          = 0x40
	NLDLY                            = 0x100
	NOFLSH                           = 0x80
	NS_GET_MNTNS_ID                  = 0x4008b705
	NS_GET_NSTYPE                    = 0x2000b703
	NS_GET_OWNER_UID                 = 0x2000b704
	NS_GET_PARENT                    = 0x2000b702
	NS_GET_PID_FROM_PIDNS            = 0x4004b706
	NS_GET_PID_IN_PIDNS              = 0x4004b708
	NS_GET_TGID_FROM_PIDNS           = 0x4004b707
	NS_GET_TGID_IN_PIDNS             = 0x4004b709
	NS_GET_USERNS                    = 0x2000b701
	OLCUC                            = 0x2
	ONLCR                            = 0x4
	OTPERASE                         = 0x800c4d19
	OTPGETREGIONCOUNT                = 0x80044d0e
	OTPGETREGIONINFO                 = 0x800c4d0f
	OTPLOCK                          = 0x400c4d10
	OTPSELECT                        = 0x40044d0d
	O_APPEND                         = 0x8
	O_ASYNC                          = 0x1000
	O_CLOEXEC                        = 0x80000
	O_CREAT                          = 0x100
	O_DIRECT                         = 0x8000
	O_DIRECTORY                      = 0x10000
	O_DSYNC                          = 0x10
	O_EXCL                           = 0x400
	O_FSYNC                          = 0x4010
	O_LARGEFILE                      = 0x0
	O_NDELAY                         = 0x80
	O_NOATIME                        = 0x40000
	O_NOCTTY                         = 0x800
	O_NOFOLLOW                       = 0x20000
	O_NONBLOCK                       = 0x80
	O_PATH                           = 0x200000
	O_RSYNC                          = 0x4010
	O_SYNC                           = 0x4010
	O_TMPFILE                        = 0x410000
	O_TRUNC                          = 0x200
	PARENB                           = 0x100
	PARODD                           = 0x200
	PENDIN                           = 0x4000
	PERF_EVENT_IOC_DISABLE           = 0x20002401
	PERF_EVENT_IOC_ENABLE            = 0x20002400
	PERF_EVENT_IOC_ID                = 0x40082407
	PERF_EVENT_IOC_MODIFY_ATTRIBUTES = 0x8008240b
	PERF_EVENT_IOC_PAUSE_OUTPUT      = 0x80042409
	PERF_EVENT_IOC_PERIOD            = 0x80082404
	PERF_EVENT_IOC_QUERY_BPF         = 0xc008240a
	PERF_EVENT_IOC_REFRESH           = 0x20002402
	PERF_EVENT_IOC_RESET             = 0x20002403
	PERF_EVENT_IOC_SET_BPF           = 0x80042408
	PERF_EVENT_IOC_SET_FILTER        = 0x80082406
	PERF_EVENT_IOC_SET_OUTPUT        = 0x20002405
	PPPIOCATTACH                     = 0x8004743d
	PPPIOCATTCHAN                    = 0x80047438
	PPPIOCBRIDGECHAN                 = 0x80047435
	PPPIOCCONNECT                    = 0x8004743a
	PPPIOCDETACH                     = 0x8004743c
	PPPIOCDISCONN                    = 0x20007439
	PPPIOCGASYNCMAP                  = 0x40047458
	PPPIOCGCHAN                      = 0x40047437
	PPPIOCGDEBUG                     = 0x40047441
	PPPIOCGFLAGS                     = 0x4004745a
	PPPIOCGIDLE                      = 0x4010743f
	PPPIOCGIDLE32                    = 0x4008743f
	PPPIOCGIDLE64                    = 0x4010743f
	PPPIOCGL2TPSTATS                 = 0x40487436
	PPPIOCGMRU                       = 0x40047453
	PPPIOCGRASYNCMAP                 = 0x40047455
	PPPIOCGUNIT                      = 0x40047456
	PPPIOCGXASYNCMAP                 = 0x40207450
	PPPIOCSACTIVE                    = 0x80107446
	PPPIOCSASYNCMAP                  = 0x80047457
	PPPIOCSCOMPRESS                  = 0x8010744d
	PPPIOCSDEBUG                     = 0x80047440
	PPPIOCSFLAGS                     = 0x80047459
	PPPIOCSMAXCID                    = 0x80047451
	PPPIOCSMRRU                      = 0x8004743b
	PPPIOCSMRU                       = 0x80047452
	PPPIOCSNPMODE                    = 0x8008744b
	PPPIOCSPASS                      = 0x80107447
	PPPIOCSRASYNCMAP                 = 0x80047454
	PPPIOCSXASYNCMAP                 = 0x8020744f
	PPPIOCUNBRIDGECHAN               = 0x20007434
	PPPIOCXFERUNIT                   = 0x2000744e
	PR_SET_PTRACER_ANY               = 0xffffffffffffffff
	PTP_CLOCK_GETCAPS                = 0x40503d01
	PTP_CLOCK_GETCAPS2               = 0x40503d0a
	PTP_ENABLE_PPS                   = 0x80043d04
	PTP_ENABLE_PPS2                  = 0x80043d0d
	PTP_EXTTS_REQUEST                = 0x80103d02
	PTP_EXTTS_REQUEST2               = 0x80103d0b
	PTP_MASK_CLEAR_ALL               = 0x20003d13
	PTP_MASK_EN_SINGLE               = 0x80043d14
	PTP_PEROUT_REQUEST               = 0x80383d03
	PTP_PEROUT_REQUEST2              = 0x80383d0c
	PTP_PIN_SETFUNC                  = 0x80603d07
	PTP_PIN_SETFUNC2                 = 0x80603d10
	PTP_SYS_OFFSET                   = 0x83403d05
	PTP_SYS_OFFSET2                  = 0x83403d0e
	PTRACE_GETFPREGS                 = 0xe
	PTRACE_GET_THREAD_AREA           = 0x19
	PTRACE_GET_THREAD_AREA_3264      = 0xc4
	PTRACE_GET_WATCH_REGS            = 0xd0
	PTRACE_OLDSETOPTIONS             = 0x15
	PTRACE_PEEKDATA_3264             = 0xc1
	PTRACE_PEEKTEXT_3264             = 0xc0
	PTRACE_POKEDATA_3264             = 0xc3
	PTRACE_POKETEXT_3264             = 0xc2
	PTRACE_SETFPREGS                 = 0xf
	PTRACE_SET_THREAD_AREA           = 0x1a
	PTRACE_SET_WATCH_REGS            = 0xd1
	RLIMIT_AS                        = 0x6
	RLIMIT_MEMLOCK                   = 0x9
	RLIMIT_NOFILE                    = 0x5
	RLIMIT_NPROC                     = 0x8
	RLIMIT_RSS                       = 0x7
	RNDADDENTROPY                    = 0x80085203
	RNDADDTOENTCNT                   = 0x80045201
	RNDCLEARPOOL                     = 0x20005206
	RNDGETENTCNT                     = 0x40045200
	RNDGETPOOL                       = 0x40085202
	RNDRESEEDCRNG                    = 0x20005207
	RNDZAPENTCNT                     = 0x20005204
	RTC_AIE_OFF                      = 0x20007002
	RTC_AIE_ON                       = 0x20007001
	RTC_ALM_READ                     = 0x40247008
	RTC_ALM_SET                      = 0x80247007
	RTC_EPOCH_READ                   = 0x4008700d
	RTC_EPOCH_SET                    = 0x8008700e
	RTC_IRQP_READ                    = 0x4008700b
	RTC_IRQP_SET                     = 0x8008700c
	RTC_PARAM_GET                    = 0x80187013
	RTC_PARAM_SET                    = 0x80187014
	RTC_PIE_OFF                      = 0x20007006
	RTC_PIE_ON                       = 0x20007005
	RTC_PLL_GET                      = 0x40207011
	RTC_PLL_SET                      = 0x80207012
	RTC_RD_TIME                      = 0x40247009
	RTC_SET_TIME                     = 0x8024700a
	RTC_UIE_OFF                      = 0x20007004
	RTC_UIE_ON                       = 0x20007003
	RTC_VL_CLR                       = 0x20007014
	RTC_VL_READ                      = 0x40047013
	RTC_WIE_OFF                      = 0x20007010
	RTC_WIE_ON                       = 0x2000700f
	RTC_WKALM_RD                     = 0x40287010
	RTC_WKALM_SET                    = 0x8028700f
	SCM_DEVMEM_DMABUF                = 0x4f
	SCM_DEVMEM_LINEAR                = 0x4e
	SCM_TIMESTAMPING                 = 0x25
	SCM_TIMESTAMPING_OPT_STATS       = 0x36
	SCM_TIMESTAMPING_PKTINFO         = 0x3a
	SCM_TIMESTAMPNS                  = 0x23
	SCM_TXTIME                       = 0x3d
	SCM_WIFI_STATUS                  = 0x29
	SECCOMP_IOCTL_NOTIF_ADDFD        = 0x80182103
	SECCOMP_IOCTL_NOTIF_ID_VALID     = 0x80082102
	SECCOMP_IOCTL_NOTIF_SET_FLAGS    = 0x80082104
	SFD_CLOEXEC                      = 0x80000
	SFD_NONBLOCK                     = 0x80
	SIOCATMARK                       = 0x40047307
	SIOCGPGRP                        = 0x40047309
	SIOCGSTAMPNS_NEW                 = 0x40108907
	SIOCGSTAMP_NEW                   = 0x40108906
	SIOCINQ                          = 0x467f
	SIOCOUTQ                         = 0x7472
	SIOCSPGRP                        = 0x80047308
	SOCK_CLOEXEC                     = 0x80000
	SOCK_DGRAM                       = 0x1
	SOCK_NONBLOCK                    = 0x80
	SOCK_STREAM                      = 0x2
	SOL_SOCKET                       = 0xffff
	SO_ACCEPTCONN                    = 0x1009
	SO_ATTACH_BPF                    = 0x32
	SO_ATTACH_REUSEPORT_CBPF         = 0x33
	SO_ATTACH_REUSEPORT_EBPF         = 0x34
	SO_BINDTODEVICE                  = 0x19
	SO_BINDTOIFINDEX                 = 0x3e
	SO_BPF_EXTENSIONS                = 0x30
	SO_BROADCAST                     = 0x20
	SO_BSDCOMPAT                     = 0xe
	SO_BUF_LOCK                      = 0x48
	SO_BUSY_POLL                     = 0x2e
	SO_BUSY_POLL_BUDGET              = 0x46
	SO_CNX_ADVICE                    = 0x35
	SO_COOKIE                        = 0x39
	SO_DETACH_REUSEPORT_BPF          = 0x44
	SO_DEVMEM_DMABUF                 = 0x4f
	SO_DEVMEM_DONTNEED               = 0x50
	SO_DEVMEM_LINEAR                 = 0x4e
	SO_DOMAIN                        = 0x1029
	SO_DONTROUTE                     = 0x10
	SO_ERROR                         = 0x1007
	SO_INCOMING_CPU                  = 0x31
	SO_INCOMING_NAPI_ID              = 0x38
	SO_KEEPALIVE                     = 0x8
	SO_LINGER                        = 0x80
	SO_LOCK_FILTER                   = 0x2c
	SO_MARK                          = 0x24
	SO_MAX_PACING_RATE               = 0x2f
	SO_MEMINFO                       = 0x37
	SO_NETNS_COOKIE                  = 0x47
	SO_NOFCS                         = 0x2b
	SO_OOBINLINE                     = 0x100
	SO_PASSCRED                      = 0x11
	SO_PASSPIDFD                     = 0x4c
	SO_PASSSEC                       = 0x22
	SO_PEEK_OFF                      = 0x2a
	SO_PEERCRED                      = 0x12
	SO_PEERGROUPS                    = 0x3b
	SO_PEERPIDFD                     = 0x4d
	SO_PEERSEC                       = 0x1e
	SO_PREFER_BUSY_POLL              = 0x45
	SO_PROTOCOL                      = 0x1028
	SO_RCVBUF                        = 0x1002
	SO_RCVBUFFORCE                   = 0x21
	SO_RCVLOWAT                      = 0x1004
	SO_RCVMARK                       = 0x4b
	SO_RCVTIMEO                      = 0x1006
	SO_RCVTIMEO_NEW                  = 0x42
	SO_RCVTIMEO_OLD                  = 0x1006
	SO_RESERVE_MEM                   = 0x49
	SO_REUSEADDR                     = 0x4
	SO_REUSEPORT                     = 0x200
	SO_RXQ_OVFL                      = 0x28
	SO_SECURITY_AUTHENTICATION       = 0x16
	SO_SECURITY_ENCRYPTION_NETWORK   = 0x18
	SO_SECURITY_ENCRYPTION_TRANSPORT = 0x17
	SO_SELECT_ERR_QUEUE              = 0x2d
	SO_SNDBUF                        = 0x1001
	SO_SNDBUFFORCE                   = 0x1f
	SO_SNDLOWAT                      = 0x1003
	SO_SNDTIMEO                      = 0x1005
	SO_SNDTIMEO_NEW                  = 0x43
	SO_SNDTIMEO_OLD                  = 0x1005
	SO_STYLE                         = 0x1008
	SO_TIMESTAMPING                  = 0x25
	SO_TIMESTAMPING_NEW              = 0x41
	SO_TIMESTAMPING_OLD              = 0x25
	SO_TIMESTAMPNS                   = 0x23
	SO_TIMESTAMPNS_NEW               = 0x40
	SO_TIMESTAMPNS_OLD               = 0x23
	SO_TIMESTAMP_NEW                 = 0x3f
	SO_TXREHASH                      = 0x4a
	SO_TXTIME                        = 0x3d
	SO_TYPE                          = 0x1008
	SO_WIFI_STATUS                   = 0x29
	SO_ZEROCOPY                      = 0x3c
	TAB1                             = 0x800
	TAB2                             = 0x1000
	TAB3                             = 0x1800
	TABDLY                           = 0x1800
	TCFLSH                           = 0x5407
	TCGETA                           = 0x5401
	TCGETS                           = 0x540d
	TCGETS2                          = 0x4030542a
	TCSAFLUSH                        = 0x5410
	TCSBRK                           = 0x5405
	TCSBRKP                          = 0x5486
	TCSETA                           = 0x5402
	TCSETAF                          = 0x5404
	TCSETAW                          = 0x5403
	TCSETS                           = 0x540e
	TCSETS2                          = 0x8030542b
	TCSETSF                          = 0x5410
	TCSETSF2                         = 0x8030542d
	TCSETSW                          = 0x540f
	TCSETSW2                         = 0x8030542c
	TCXONC                           = 0x5406
	TFD_CLOEXEC                      = 0x80000
	TFD_NONBLOCK                     = 0x80
	TIOCCBRK                         = 0x5428
	TIOCCONS                         = 0x80047478
	TIOCEXCL                         = 0x740d
	TIOCGDEV                         = 0x40045432
	TIOCGETD                         = 0x7400
	TIOCGETP                         = 0x7408
	TIOCGEXCL                        = 0x40045440
	TIOCGICOUNT                      = 0x5492
	TIOCGISO7816                     = 0x40285442
	TIOCGLCKTRMIOS                   = 0x548b
	TIOCGLTC                         = 0x7474
	TIOCGPGRP                        = 0x40047477
	TIOCGPKT                         = 0x40045438
	TIOCGPTLCK                       = 0x40045439
	TIOCGPTN                         = 0x40045430
	TIOCGPTPEER                      = 0x20005441
	TIOCGRS485                       = 0x4020542e
	TIOCGSERIAL                      = 0x5484
	TIOCGSID                         = 0x7416
	TIOCGSOFTCAR                     = 0x5481
	TIOCGWINSZ                       = 0x40087468
	TIOCINQ                          = 0x467f
	TIOCLINUX                        = 0x5483
	TIOCMBIC                         = 0x741c
	TIOCMBIS                         = 0x741b
	TIOCMGET                         = 0x741d
	TIOCMIWAIT                       = 0x5491
	TIOCMSET                         = 0x741a
	TIOCM_CAR                        = 0x100
	TIOCM_CD                         = 0x100
	TIOCM_CTS                        = 0x40
	TIOCM_DSR                        = 0x400
	TIOCM_RI                         = 0x200
	TIOCM_RNG                        = 0x200
	TIOCM_SR                         = 0x20
	TIOCM_ST                         = 0x10
	TIOCNOTTY                        = 0x5471
	TIOCNXCL                         = 0x740e
	TIOCOUTQ                         = 0x7472
	TIOCPKT                          = 0x5470
	TIOCSBRK                         = 0x5427
	TIOCSCTTY                        = 0x5480
	TIOCSERCONFIG                    = 0x5488
	TIOCSERGETLSR                    = 0x548e
	TIOCSERGETMULTI                  = 0x548f
	TIOCSERGSTRUCT                   = 0x548d
	TIOCSERGWILD                     = 0x5489
	TIOCSERSETMULTI                  = 0x5490
	TIOCSERSWILD                     = 0x548a
	TIOCSER_TEMT                     = 0x1
	TIOCSETD                         = 0x7401
	TIOCSETN                         = 0x740a
	TIOCSETP                         = 0x7409
	TIOCSIG                          = 0x80045436
	TIOCSISO7816                     = 0xc0285443
	TIOCSLCKTRMIOS                   = 0x548c
	TIOCSLTC                         = 0x7475
	TIOCSPGRP                        = 0x80047476
	TIOCSPTLCK                       = 0x80045431
	TIOCSRS485                       = 0xc020542f
	TIOCSSERIAL                      = 0x5485
	TIOCSSOFTCAR                     = 0x5482
	TIOCSTI                          = 0x5472
	TIOCSWINSZ                       = 0x80087467
	TIOCVHANGUP                      = 0x5437
	TOSTOP                           = 0x8000
	TUNATTACHFILTER                  = 0x801054d5
	TUNDETACHFILTER                  = 0x801054d6
	TUNGETDEVNETNS                   = 0x200054e3
	TUNGETFEATURES                   = 0x400454cf
	TUNGETFILTER                     = 0x401054db
	TUNGETIFF                        = 0x400454d2
	TUNGETSNDBUF                     = 0x400454d3
	TUNGETVNETBE                     = 0x400454df
	TUNGETVNETHDRSZ                  = 0x400454d7
	TUNGETVNETLE                     = 0x400454dd
	TUNSETCARRIER                    = 0x800454e2
	TUNSETDEBUG                      = 0x800454c9
	TUNSETFILTEREBPF                 = 0x400454e1
	TUNSETGROUP                      = 0x800454ce
	TUNSETIFF                        = 0x800454ca
	TUNSETIFINDEX                    = 0x800454da
	TUNSETLINK                       = 0x800454cd
	TUNSETNOCSUM                     = 0x800454c8
	TUNSETOFFLOAD                    = 0x800454d0
	TUNSETOWNER                      = 0x800454cc
	TUNSETPERSIST                    = 0x800454cb
	TUNSETQUEUE                      = 0x800454d9
	TUNSETSNDBUF                     = 0x800454d4
	TUNSETSTEERINGEBPF               = 0x400454e0
	TUNSETTXFILTER                   = 0x800454d1
	TUNSETVNETBE                     = 0x800454de
	TUNSETVNETHDRSZ                  = 0x800454d8
	TUNSETVNETLE                     = 0x800454dc
	UBI_IOCATT                       = 0x80186f40
	UBI_IOCDET                       = 0x80046f41
	UBI_IOCEBCH                      = 0x80044f02
	UBI_IOCEBER                      = 0x80044f01
	UBI_IOCEBISMAP                   = 0x40044f05
	UBI_IOCEBMAP                     = 0x80084f03
	UBI_IOCEBUNMAP                   = 0x80044f04
	UBI_IOCMKVOL                     = 0x80986f00
	UBI_IOCRMVOL                     = 0x80046f01
	UBI_IOCRNVOL                     = 0x91106f03
	UBI_IOCRPEB                      = 0x80046f04
	UBI_IOCRSVOL                     = 0x800c6f02
	UBI_IOCSETVOLPROP                = 0x80104f06
	UBI_IOCSPEB                      = 0x80046f05
	UBI_IOCVOLCRBLK                  = 0x80804f07
	UBI_IOCVOLRMBLK                  = 0x20004f08
	UBI_IOCVOLUP                     = 0x80084f00
	VDISCARD                         = 0xd
	VEOF                             = 0x10
	VEOL                             = 0x11
	VEOL2                            = 0x6
	VMIN                             = 0x4
	VREPRINT                         = 0xc
	VSTART                           = 0x8
	VSTOP                            = 0x9
	VSUSP                            = 0xa
	VSWTC                            = 0x7
	VSWTCH                           = 0x7
	VT1                              = 0x4000
	VTDLY                            = 0x4000
	VTIME                            = 0x5
	VWERASE                          = 0xe
	WDIOC_GETBOOTSTATUS              = 0x40045702
	WDIOC_GETPRETIMEOUT              = 0x40045709
	WDIOC_GETSTATUS                  = 0x40045701
	WDIOC_GETSUPPORT                 = 0x40285700
	WDIOC_GETTEMP                    = 0x40045703
	WDIOC_GETTIMELEFT                = 0x4004570a
	WDIOC_GETTIMEOUT                 = 0x40045707
	WDIOC_KEEPALIVE                  = 0x40045705
	WDIOC_SETOPTIONS                 = 0x40045704
	WORDSIZE                         = 0x40
	XCASE                            = 0x4
	XTABS                            = 0x1800
	_HIDIOCGRAWNAME                  = 0x40804804
	_HIDIOCGRAWPHYS                  = 0x40404805
	_HIDIOCGRAWUNIQ                  = 0x40404808
)

// Errors
const (
	EADDRINUSE      = syscall.Errno(0x7d)
	EADDRNOTAVAIL   = syscall.Errno(0x7e)
	EADV            = syscall.Errno(0x44)
	EAFNOSUPPORT    = syscall.Errno(0x7c)
	EALREADY        = syscall.Errno(0x95)
	EBADE           = syscall.Errno(0x32)
	EBADFD          = syscall.Errno(0x51)
	EBADMSG         = syscall.Errno(0x4d)
	EBADR           = syscall.Errno(0x33)
	EBADRQC         = syscall.Errno(0x36)
	EBADSLT         = syscall.Errno(0x37)
	EBFONT          = syscall.Errno(0x3b)
	ECANCELED       = syscall.Errno(0x9e)
	ECHRNG          = syscall.Errno(0x25)
	ECOMM           = syscall.Errno(0x46)
	ECONNABORTED    = syscall.Errno(0x82)
	ECONNREFUSED    = syscall.Errno(0x92)
	ECONNRESET      = syscall.Errno(0x83)
	EDEADLK         = syscall.Errno(0x2d)
	EDEADLOCK       = syscall.Errno(0x38)
	EDESTADDRREQ    = syscall.Errno(0x60)
	EDOTDOT         = syscall.Errno(0x49)
	EDQUOT          = syscall.Errno(0x46d)
	EHOSTDOWN       = syscall.Errno(0x93)
	EHOSTUNREACH    = syscall.Errno(0x94)
	EHWPOISON       = syscall.Errno(0xa8)
	EIDRM           = syscall.Errno(0x24)
	EILSEQ          = syscall.Errno(0x58)
	EINIT           = syscall.Errno(0x8d)
	EINPROGRESS     = syscall.Errno(0x96)
	EISCONN         = syscall.Errno(0x85)
	EISNAM          = syscall.Errno(0x8b)
	EKEYEXPIRED     = syscall.Errno(0xa2)
	EKEYREJECTED    = syscall.Errno(0xa4)
	EKEYREVOKED     = syscall.Errno(0xa3)
	EL2HLT          = syscall.Errno(0x2c)
	EL2NSYNC        = syscall.Errno(0x26)
	EL3HLT          = syscall.Errno(0x27)
	EL3RST          = syscall.Errno(0x28)
	ELIBACC         = syscall.Errno(0x53)
	ELIBBAD         = syscall.Errno(0x54)
	ELIBEXEC        = syscall.Errno(0x57)
	ELIBMAX         = syscall.Errno(0x56)
	ELIBSCN         = syscall.Errno(0x55)
	ELNRNG          = syscall.Errno(0x29)
	ELOOP           = syscall.Errno(0x5a)
	EMEDIUMTYPE     = syscall.Errno(0xa0)
	EMSGSIZE        = syscall.Errno(0x61)
	EMULTIHOP       = syscall.Errno(0x4a)
	ENAMETOOLONG    = syscall.Errno(0x4e)
	ENAVAIL         = syscall.Errno(0x8a)
	ENETDOWN        = syscall.Errno(0x7f)
	ENETRESET       = syscall.Errno(0x81)
	ENETUNREACH     = syscall.Errno(0x80)
	ENOANO          = syscall.Errno(0x35)
	ENOBUFS         = syscall.Errno(0x84)
	ENOCSI          = syscall.Errno(0x2b)
	ENODATA         = syscall.Errno(0x3d)
	ENOKEY          = syscall.Errno(0xa1)
	ENOLCK          = syscall.Errno(0x2e)
	ENOLINK         = syscall.Errno(0x43)
	ENOMEDIUM       = syscall.Errno(0x9f)
	ENOMSG          = syscall.Errno(0x23)
	ENONET          = syscall.Errno(0x40)
	ENOPKG          = syscall.Errno(0x41)
	ENOPROTOOPT     = syscall.Errno(0x63)
	ENOSR           = syscall.Errno(0x3f)
	ENOSTR          = syscall.Errno(0x3c)
	ENOSYS          = syscall.Errno(0x59)
	ENOTCONN        = syscall.Errno(0x86)
	ENOTEMPTY       = syscall.Errno(0x5d)
	ENOTNAM         = syscall.Errno(0x89)
	ENOTRECOVERABLE = syscall.Errno(0xa6)
	ENOTSOCK        = syscall.Errno(0x5f)
	ENOTSUP         = syscall.Errno(0x7a)
	ENOTUNIQ        = syscall.Errno(0x50)
	EOPNOTSUPP      = syscall.Errno(0x7a)
	EOVERFLOW       = syscall.Errno(0x4f)
	EOWNERDEAD      = syscall.Errno(0xa5)
	EPFNOSUPPORT    = syscall.Errno(0x7b)
	EPROTO          = syscall.Errno(0x47)
	EPROTONOSUPPORT = syscall.Errno(0x78)
	EPROTOTYPE      = syscall.Errno(0x62)
	EREMCHG         = syscall.Errno(0x52)
	EREMDEV         = syscall.Errno(0x8e)
	EREMOTE         = syscall.Errno(0x42)
	EREMOTEIO       = syscall.Errno(0x8c)
	ERESTART        = syscall.Errno(0x5b)
	ERFKILL         = syscall.Errno(0xa7)
	ESHUTDOWN       = syscall.Errno(0x8f)
	ESOCKTNOSUPPORT = syscall.Errno(0x79)
	ESRMNT          = syscall.Errno(0x45)
	ESTALE          = syscall.Errno(0x97)
	ESTRPIPE        = syscall.Errno(0x5c)
	ETIME           = syscall.Errno(0x3e)
	ETIMEDOUT       = syscall.Errno(0x91)
	ETOOMANYREFS    = syscall.Errno(0x90)
	EUCLEAN         = syscall.Errno(0x87)
	EUNATCH         = syscall.Errno(0x2a)
	EUSERS          = syscall.Errno(0x5e)
	EXFULL          = syscall.Errno(0x34)
)

// Signals
const (
	SIGBUS    = syscall.Signal(0xa)
	SIGCHLD   = syscall.Signal(0x12)
	SIGCLD    = syscall.Signal(0x12)
	SIGCONT   = syscall.Signal(0x19)
	SIGEMT    = syscall.Signal(0x7)
	SIGIO     = syscall.Signal(0x16)
	SIGPOLL   = syscall.Signal(0x16)
	SIGPROF   = syscall.Signal(0x1d)
	SIGPWR    = syscall.Signal(0x13)
	SIGSTOP   = syscall.Signal(0x17)
	SIGSYS    = syscall.Signal(0xc)
	SIGTSTP   = syscall.Signal(0x18)
	SIGTTIN   = syscall.Signal(0x1a)
	SIGTTOU   = syscall.Signal(0x1b)
	SIGURG    = syscall.Signal(0x15)
	SIGUSR1   = syscall.Signal(0x10)
	SIGUSR2   = syscall.Signal(0x11)
	SIGVTALRM = syscall.Signal(0x1c)
	SIGWINCH  = syscall.Signal(0x14)
	SIGXCPU   = syscall.Signal(0x1e)
	SIGXFSZ   = syscall.Signal(0x1f)
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
	{6, "ENXIO", "no such device or address"},
	{7, "E2BIG", "argument list too long"},
	{8, "ENOEXEC", "exec format error"},
	{9, "EBADF", "bad file descriptor"},
	{10, "ECHILD", "no child processes"},
	{11, "EAGAIN", "resource temporarily unavailable"},
	{12, "ENOMEM", "cannot allocate memory"},
	{13, "EACCES", "permission denied"},
	{14, "EFAULT", "bad address"},
	{15, "ENOTBLK", "block device required"},
	{16, "EBUSY", "device or resource busy"},
	{17, "EEXIST", "file exists"},
	{18, "EXDEV", "invalid cross-device link"},
	{19, "ENODEV", "no such device"},
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
	{34, "ERANGE", "numerical result out of range"},
	{35, "ENOMSG", "no message of desired type"},
	{36, "EIDRM", "identifier removed"},
	{37, "ECHRNG", "channel number out of range"},
	{38, "EL2NSYNC", "level 2 not synchronized"},
	{39, "EL3HLT", "level 3 halted"},
	{40, "EL3RST", "level 3 reset"},
	{41, "ELNRNG", "link number out of range"},
	{42, "EUNATCH", "protocol driver not attached"},
	{43, "ENOCSI", "no CSI structure available"},
	{44, "EL2HLT", "level 2 halted"},
	{45, "EDEADLK", "resource deadlock avoided"},
	{46, "ENOLCK", "no locks available"},
	{50, "EBADE", "invalid exchange"},
	{51, "EBADR", "invalid request descriptor"},
	{52, "EXFULL", "exchange full"},
	{53, "ENOANO", "no anode"},
	{54, "EBADRQC", "invalid request code"},
	{55, "EBADSLT", "invalid slot"},
	{56, "EDEADLOCK", "file locking deadlock error"},
	{59, "EBFONT", "bad font file format"},
	{60, "ENOSTR", "device not a stream"},
	{61, "ENODATA", "no data available"},
	{62, "ETIME", "timer expired"},
	{63, "ENOSR", "out of streams resources"},
	{64, "ENONET", "machine is not on the network"},
	{65, "ENOPKG", "package not installed"},
	{66, "EREMOTE", "object is remote"},
	{67, "ENOLINK", "link has been severed"},
	{68, "EADV", "advertise error"},
	{69, "ESRMNT", "srmount error"},
	{70, "ECOMM", "communication error on send"},
	{71, "EPROTO", "protocol error"},
	{73, "EDOTDOT", "RFS specific error"},
	{74, "EMULTIHOP", "multihop attempted"},
	{77, "EBADMSG", "bad message"},
	{78, "ENAMETOOLONG", "file name too long"},
	{79, "EOVERFLOW", "value too large for defined data type"},
	{80, "ENOTUNIQ", "name not unique on network"},
	{81, "EBADFD", "file descriptor in bad state"},
	{82, "EREMCHG", "remote address changed"},
	{83, "ELIBACC", "can not access a needed shared library"},
	{84, "ELIBBAD", "accessing a corrupted shared library"},
	{85, "ELIBSCN", ".lib section in a.out corrupted"},
	{86, "ELIBMAX", "attempting to link in too many shared libraries"},
	{87, "ELIBEXEC", "cannot exec a shared library directly"},
	{88, "EILSEQ", "invalid or incomplete multibyte or wide character"},
	{89, "ENOSYS", "function not implemented"},
	{90, "ELOOP", "too many levels of symbolic links"},
	{91, "ERESTART", "interrupted system call should be restarted"},
	{92, "ESTRPIPE", "streams pipe error"},
	{93, "ENOTEMPTY", "directory not empty"},
	{94, "EUSERS", "too many users"},
	{95, "ENOTSOCK", "socket operation on non-socket"},
	{96, "EDESTADDRREQ", "destination address required"},
	{97, "EMSGSIZE", "message too long"},
	{98, "EPROTOTYPE", "protocol wrong type for socket"},
	{99, "ENOPROTOOPT", "protocol not available"},
	{120, "EPROTONOSUPPORT", "protocol not supported"},
	{121, "ESOCKTNOSUPPORT", "socket type not supported"},
	{122, "ENOTSUP", "operation not supported"},
	{123, "EPFNOSUPPORT", "protocol family not supported"},
	{124, "EAFNOSUPPORT", "address family not supported by protocol"},
	{125, "EADDRINUSE", "address already in use"},
	{126, "EADDRNOTAVAIL", "cannot assign requested address"},
	{127, "ENETDOWN", "network is down"},
	{128, "ENETUNREACH", "network is unreachable"},
	{129, "ENETRESET", "network dropped connection on reset"},
	{130, "ECONNABORTED", "software caused connection abort"},
	{131, "ECONNRESET", "connection reset by peer"},
	{132, "ENOBUFS", "no buffer space available"},
	{133, "EISCONN", "transport endpoint is already connected"},
	{134, "ENOTCONN", "transport endpoint is not connected"},
	{135, "EUCLEAN", "structure needs cleaning"},
	{137, "ENOTNAM", "not a XENIX named type file"},
	{138, "ENAVAIL", "no XENIX semaphores available"},
	{139, "EISNAM", "is a named type file"},
	{140, "EREMOTEIO", "remote I/O error"},
	{141, "EINIT", "unknown error 141"},
	{142, "EREMDEV", "unknown error 142"},
	{143, "ESHUTDOWN", "cannot send after transport endpoint shutdown"},
	{144, "ETOOMANYREFS", "too many references: cannot splice"},
	{145, "ETIMEDOUT", "connection timed out"},
	{146, "ECONNREFUSED", "connection refused"},
	{147, "EHOSTDOWN", "host is down"},
	{148, "EHOSTUNREACH", "no route to host"},
	{149, "EALREADY", "operation already in progress"},
	{150, "EINPROGRESS", "operation now in progress"},
	{151, "ESTALE", "stale file handle"},
	{158, "ECANCELED", "operation canceled"},
	{159, "ENOMEDIUM", "no medium found"},
	{160, "EMEDIUMTYPE", "wrong medium type"},
	{161, "ENOKEY", "required key not available"},
	{162, "EKEYEXPIRED", "key has expired"},
	{163, "EKEYREVOKED", "key has been revoked"},
	{164, "EKEYREJECTED", "key was rejected by service"},
	{165, "EOWNERDEAD", "owner died"},
	{166, "ENOTRECOVERABLE", "state not recoverable"},
	{167, "ERFKILL", "operation not possible due to RF-kill"},
	{168, "EHWPOISON", "memory page has hardware error"},
	{1133, "EDQUOT", "disk quota exceeded"},
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
	{5, "SIGTRAP", "trace/breakpoint trap"},
	{6, "SIGABRT", "aborted"},
	{7, "SIGEMT", "EMT trap"},
	{8, "SIGFPE", "floating point exception"},
	{9, "SIGKILL", "killed"},
	{10, "SIGBUS", "bus error"},
	{11, "SIGSEGV", "segmentation fault"},
	{12, "SIGSYS", "bad system call"},
	{13, "SIGPIPE", "broken pipe"},
	{14, "SIGALRM", "alarm clock"},
	{15, "SIGTERM", "terminated"},
	{16, "SIGUSR1", "user defined signal 1"},
	{17, "SIGUSR2", "user defined signal 2"},
	{18, "SIGCHLD", "child exited"},
	{19, "SIGPWR", "power failure"},
	{20, "SIGWINCH", "window changed"},
	{21, "SIGURG", "urgent I/O condition"},
	{22, "SIGIO", "I/O possible"},
	{23, "SIGSTOP", "stopped (signal)"},
	{24, "SIGTSTP", "stopped"},
	{25, "SIGCONT", "continued"},
	{26, "SIGTTIN", "stopped (tty input)"},
	{27, "SIGTTOU", "stopped (tty output)"},
	{28, "SIGVTALRM", "virtual timer expired"},
	{29, "SIGPROF", "profiling timer expired"},
	{30, "SIGXCPU", "CPU time limit exceeded"},
	{31, "SIGXFSZ", "file size limit exceeded"},
}

"""



```