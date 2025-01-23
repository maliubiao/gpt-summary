Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Observation and Goal:**

The first thing I notice is the file path and the comment at the top. The path `go/src/cmd/vendor/golang.org/x/sys/unix/zsysnum_linux_ppc64le.go` strongly suggests this file defines system call numbers for a specific architecture (ppc64le) on Linux. The comment confirms this, showing the `go run` command used to generate it, which involves parsing a header file (`unistd.h`). The `// Code generated... DO NOT EDIT.` warning reinforces that this is an automatically created file. Therefore, the primary goal is to understand *what* these constants represent.

**2. Deconstructing the Code:**

The core of the file is a series of Go constants. Each constant has a name starting with `SYS_` and an integer value. This naming convention is a strong indicator that these represent system call numbers.

**3. Understanding System Call Numbers:**

I know that operating systems provide an interface for user-space programs to request kernel services. These requests are made through system calls, and each system call has a unique identifier (the system call number). The kernel uses this number to determine which function to execute.

**4. Connecting the Code to Go Functionality:**

How does this connect to Go?  The `golang.org/x/sys/unix` package is the key. This package provides low-level access to operating system primitives, including system calls. Functions within this package, like `syscall.Syscall`, `syscall.Open`, `syscall.Read`, etc., ultimately translate into these raw system calls.

**5. Forming a Hypothesis:**

My hypothesis is that this file provides a mapping between human-readable names (like `SYS_OPEN`) and the numerical system call codes that the Linux kernel on the `ppc64le` architecture expects. The `unix` package uses these constants internally when making system call requests.

**6. Generating Examples:**

To illustrate this, I'd think of common system calls and how they're used in Go.

* **`SYS_OPEN`:**  The `os.Open` function internally uses the `syscall.Open` function, which would rely on `unix.SYS_OPEN`. I'd construct a simple example opening a file.
* **`SYS_READ`:** Similarly, `os.File.Read` uses `syscall.Read`. I'd create an example reading from an opened file.
* **`SYS_EXIT`:**  `os.Exit` eventually calls the `exit` system call. A basic example is trivial.

For each example, I'd include the *expected output* to confirm the code's behavior. Since I can't *actually* see the raw system call numbers being used at runtime without more advanced debugging, the output focuses on the observable effect of the system call.

**7. Analyzing the Generation Command:**

The comment `// go run linux/mksysnum.go -Wall -Werror -static -I/tmp/ppc64le/include /tmp/ppc64le/include/asm/unistd.h` is crucial.

* `go run linux/mksysnum.go`: This indicates a Go program named `mksysnum.go` in the `linux` subdirectory is used to generate this file.
* `-Wall -Werror -static`: These are compiler flags likely passed to the C compiler when processing the header file. `-Wall` enables all warnings, `-Werror` treats warnings as errors, and `-static` might be relevant for how symbols are resolved (although less directly related to *this* generated file).
* `-I/tmp/ppc64le/include`: This specifies an include directory where the compiler will look for header files. This tells me the system call definitions are being pulled from a specific location.
* `/tmp/ppc64le/include/asm/unistd.h`: This is the *input* file. It's a standard Linux header file containing the system call number definitions for the `ppc64le` architecture.

This analysis explains *how* the file is created.

**8. Identifying Potential Pitfalls:**

The "DO NOT EDIT" warning is the biggest clue. Manually changing these numbers will lead to incorrect system calls, likely causing crashes or unexpected behavior. I'd create an example of *incorrect* usage by suggesting someone might try to change a value.

**9. Structuring the Answer:**

Finally, I'd organize my findings into logical sections:

* **Functionality:** What the code *is*.
* **Go Language Feature:** How it relates to Go's system call mechanism.
* **Code Examples:** Demonstrating usage.
* **Command-Line Parameters:** Explaining the generation process.
* **Potential Mistakes:** Highlighting the "DO NOT EDIT" aspect.

This systematic approach ensures a comprehensive and accurate answer. Even if I didn't know the exact details of the `mksysnum.go` program, I could still deduce its purpose based on the generated output and the standard Linux system call conventions.
这个Go语言文件 `zsysnum_linux_ppc64le.go` 的主要功能是**定义了一系列常量，这些常量代表了 Linux 系统在 `ppc64le` (PowerPC 64-bit Little Endian) 架构下的系统调用号 (syscall numbers)**。

**更详细的功能分解：**

1. **系统调用号映射:** 文件中的每个 `const` 定义都将一个有意义的系统调用名称（例如 `SYS_OPEN`，表示打开文件）映射到一个特定的数字（例如 `5`）。这个数字是内核用来识别用户程序请求执行哪个系统调用的唯一标识符。

2. **平台特定:**  文件名中的 `ppc64le` 表明这些系统调用号是针对特定的硬件架构。不同的 CPU 架构（如 x86, ARM 等）可能使用不同的系统调用号。Go 语言的 `syscall` 包会根据目标操作系统和架构选择相应的 `zsysnum_*.go` 文件。

3. **供 `syscall` 包使用:** 这个文件通常被 Go 语言标准库中的 `syscall` 包所使用。`syscall` 包提供了底层的操作系统接口，允许 Go 程序直接发起系统调用。当 `syscall` 包需要执行某个系统调用时，它会使用这里定义的常量作为参数传递给内核。

4. **自动生成:** 文件开头的注释 `// go run linux/mksysnum.go ...` 表明这个文件是通过一个名为 `mksysnum.go` 的 Go 程序自动生成的。这个生成程序会读取 Linux 内核的头文件 (`/tmp/ppc64le/include/asm/unistd.h`)，从中提取系统调用的定义并生成 Go 代码。

**它是什么Go语言功能的实现？**

这个文件是 Go 语言 `syscall` 包实现跨平台系统调用功能的基础部分。`syscall` 包的目标是提供一个相对统一的 API 来访问不同操作系统的底层功能。为了实现这一点，它需要针对每个操作系统和架构维护一份系统调用号的映射表。`zsysnum_linux_ppc64le.go` 就是 Linux 系统在 `ppc64le` 架构下的系统调用号映射表。

**Go 代码举例说明：**

假设我们要使用 `SYS_OPEN` 系统调用来打开一个文件。在 Go 语言中，我们通常会使用 `os` 包或者 `syscall` 包来实现：

```go
package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

func main() {
	filename := "test.txt"

	// 使用 os 包打开文件 (更推荐的方式)
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	fmt.Println("File opened successfully using os.Open:", file.Name())
	file.Close()

	// 使用 syscall 包直接调用 SYS_OPEN (更底层的方式，通常不直接使用)
	fd, err := syscall.Open(filename, syscall.O_RDONLY, 0)
	if err != nil {
		fmt.Println("Error opening file using syscall.Open:", err)
		return
	}
	fmt.Printf("File opened successfully using syscall.Open with file descriptor: %d\n", fd)
	syscall.Close(fd)

	// 你也可以直接访问常量 (但不推荐这样做，因为这是内部实现细节)
	fmt.Printf("SYS_OPEN constant value: %d\n", syscall.SYS_OPEN)

	// 假设我们想手动执行一个 read 系统调用 (演示目的)
	// 注意：这只是一个示例，实际使用中需要更严谨的错误处理和参数设置
	buf := make([]byte, 10)
	n, err := syscall.Read(fd, buf) // 这里的 fd 已经被上面的 close 关闭了，所以会出错
	if err != nil {
		fmt.Println("Error reading from file:", err)
	} else {
		fmt.Printf("Read %d bytes: %s\n", n, string(buf[:n]))
	}
}
```

**假设的输入与输出：**

假设当前目录下存在一个名为 `test.txt` 的文件。

**输出：**

```
File opened successfully using os.Open: test.txt
File opened successfully using syscall.Open with file descriptor: 3
SYS_OPEN constant value: 5
Error reading from file: bad file descriptor
```

**代码推理：**

* `os.Open(filename)`:  这是一个高层次的函数，它最终会调用底层的 `syscall.Open`。
* `syscall.Open(filename, syscall.O_RDONLY, 0)`:  这个函数直接使用了 `SYS_OPEN` 系统调用。`syscall.O_RDONLY` 是一个表示只读模式的常量，它会被传递给系统调用。`0` 是文件权限参数，在这个只读的场景下没有实际意义。
* `syscall.SYS_OPEN`:  这个常量的值就是文件 `zsysnum_linux_ppc64le.go` 中定义的 `5`。
* `syscall.Read(fd, buf)`:  这个函数调用了 `SYS_READ` 系统调用，尝试从文件描述符 `fd` 中读取数据到缓冲区 `buf` 中。由于上面的 `fd` 已经被关闭，所以会返回 "bad file descriptor" 错误。

**命令行参数的具体处理：**

文件开头的注释提供了生成此文件的命令：

```
go run linux/mksysnum.go -Wall -Werror -static -I/tmp/ppc64le/include /tmp/ppc64le/include/asm/unistd.h
```

* `go run linux/mksysnum.go`:  这会运行 `linux` 目录下的 `mksysnum.go` 程序。这个程序是用来生成 `zsysnum_linux_ppc64le.go` 文件的。
* `-Wall`:  这是 Go 编译器的一个选项，用于启用所有警告信息。虽然这个命令是在 `go run` 中使用的，但 `-Wall` 更像是传递给 `mksysnum.go` 内部可能调用的 C 编译器的选项，用于处理头文件。
* `-Werror`:  这也是一个编译器选项，用于将所有警告视为错误。同样，这很可能是传递给内部 C 编译器的。
* `-static`:  这可能是一个链接器选项，指示生成静态链接的可执行文件。在这个上下文中，它可能影响 `mksysnum.go` 如何处理头文件中的定义。
* `-I/tmp/ppc64le/include`:  这是一个编译器选项，用于指定额外的头文件搜索路径。这里指定了 `/tmp/ppc64le/include` 目录，表明系统调用号的定义是从这个目录下的头文件中读取的。
* `/tmp/ppc64le/include/asm/unistd.h`:  这是 `mksysnum.go` 程序需要解析的头文件。这个文件通常包含 Linux 系统在特定架构下的系统调用号定义。

**总结:**  `mksysnum.go` 程序会读取指定的 `unistd.h` 头文件，提取出系统调用的宏定义（例如 `#define __NR_open 5`），然后将其转换为 Go 语言的常量定义，并写入到 `zsysnum_linux_ppc64le.go` 文件中。

**使用者易犯错的点：**

* **手动修改文件:**  最容易犯的错误就是手动修改 `zsysnum_linux_ppc64le.go` 文件。由于这个文件是自动生成的，手动修改会被后续的重新生成覆盖。更重要的是，随意修改系统调用号会导致程序行为异常甚至崩溃，因为程序请求的系统调用与内核实际执行的系统调用不匹配。**文件开头的 `// Code generated by the command above; see README.md. DO NOT EDIT.` 注释已经明确指出了这一点。**

**举例说明错误：**

假设某个开发者错误地将 `SYS_OPEN` 的值从 `5` 改为了 `1000`。那么，当程序尝试调用 `syscall.Open` 时，实际上会向内核请求执行系统调用号为 `1000` 的操作，而这很可能不是打开文件的操作，会导致不可预测的结果。

总而言之，`zsysnum_linux_ppc64le.go` 是 Go 语言在特定架构下实现系统调用的关键组成部分，它提供了系统调用号的映射，并由自动化的工具生成，使用者不应该手动修改。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/zsysnum_linux_ppc64le.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// go run linux/mksysnum.go -Wall -Werror -static -I/tmp/ppc64le/include /tmp/ppc64le/include/asm/unistd.h
// Code generated by the command above; see README.md. DO NOT EDIT.

//go:build ppc64le && linux

package unix

const (
	SYS_RESTART_SYSCALL         = 0
	SYS_EXIT                    = 1
	SYS_FORK                    = 2
	SYS_READ                    = 3
	SYS_WRITE                   = 4
	SYS_OPEN                    = 5
	SYS_CLOSE                   = 6
	SYS_WAITPID                 = 7
	SYS_CREAT                   = 8
	SYS_LINK                    = 9
	SYS_UNLINK                  = 10
	SYS_EXECVE                  = 11
	SYS_CHDIR                   = 12
	SYS_TIME                    = 13
	SYS_MKNOD                   = 14
	SYS_CHMOD                   = 15
	SYS_LCHOWN                  = 16
	SYS_BREAK                   = 17
	SYS_OLDSTAT                 = 18
	SYS_LSEEK                   = 19
	SYS_GETPID                  = 20
	SYS_MOUNT                   = 21
	SYS_UMOUNT                  = 22
	SYS_SETUID                  = 23
	SYS_GETUID                  = 24
	SYS_STIME                   = 25
	SYS_PTRACE                  = 26
	SYS_ALARM                   = 27
	SYS_OLDFSTAT                = 28
	SYS_PAUSE                   = 29
	SYS_UTIME                   = 30
	SYS_STTY                    = 31
	SYS_GTTY                    = 32
	SYS_ACCESS                  = 33
	SYS_NICE                    = 34
	SYS_FTIME                   = 35
	SYS_SYNC                    = 36
	SYS_KILL                    = 37
	SYS_RENAME                  = 38
	SYS_MKDIR                   = 39
	SYS_RMDIR                   = 40
	SYS_DUP                     = 41
	SYS_PIPE                    = 42
	SYS_TIMES                   = 43
	SYS_PROF                    = 44
	SYS_BRK                     = 45
	SYS_SETGID                  = 46
	SYS_GETGID                  = 47
	SYS_SIGNAL                  = 48
	SYS_GETEUID                 = 49
	SYS_GETEGID                 = 50
	SYS_ACCT                    = 51
	SYS_UMOUNT2                 = 52
	SYS_LOCK                    = 53
	SYS_IOCTL                   = 54
	SYS_FCNTL                   = 55
	SYS_MPX                     = 56
	SYS_SETPGID                 = 57
	SYS_ULIMIT                  = 58
	SYS_OLDOLDUNAME             = 59
	SYS_UMASK                   = 60
	SYS_CHROOT                  = 61
	SYS_USTAT                   = 62
	SYS_DUP2                    = 63
	SYS_GETPPID                 = 64
	SYS_GETPGRP                 = 65
	SYS_SETSID                  = 66
	SYS_SIGACTION               = 67
	SYS_SGETMASK                = 68
	SYS_SSETMASK                = 69
	SYS_SETREUID                = 70
	SYS_SETREGID                = 71
	SYS_SIGSUSPEND              = 72
	SYS_SIGPENDING              = 73
	SYS_SETHOSTNAME             = 74
	SYS_SETRLIMIT               = 75
	SYS_GETRLIMIT               = 76
	SYS_GETRUSAGE               = 77
	SYS_GETTIMEOFDAY            = 78
	SYS_SETTIMEOFDAY            = 79
	SYS_GETGROUPS               = 80
	SYS_SETGROUPS               = 81
	SYS_SELECT                  = 82
	SYS_SYMLINK                 = 83
	SYS_OLDLSTAT                = 84
	SYS_READLINK                = 85
	SYS_USELIB                  = 86
	SYS_SWAPON                  = 87
	SYS_REBOOT                  = 88
	SYS_READDIR                 = 89
	SYS_MMAP                    = 90
	SYS_MUNMAP                  = 91
	SYS_TRUNCATE                = 92
	SYS_FTRUNCATE               = 93
	SYS_FCHMOD                  = 94
	SYS_FCHOWN                  = 95
	SYS_GETPRIORITY             = 96
	SYS_SETPRIORITY             = 97
	SYS_PROFIL                  = 98
	SYS_STATFS                  = 99
	SYS_FSTATFS                 = 100
	SYS_IOPERM                  = 101
	SYS_SOCKETCALL              = 102
	SYS_SYSLOG                  = 103
	SYS_SETITIMER               = 104
	SYS_GETITIMER               = 105
	SYS_STAT                    = 106
	SYS_LSTAT                   = 107
	SYS_FSTAT                   = 108
	SYS_OLDUNAME                = 109
	SYS_IOPL                    = 110
	SYS_VHANGUP                 = 111
	SYS_IDLE                    = 112
	SYS_VM86                    = 113
	SYS_WAIT4                   = 114
	SYS_SWAPOFF                 = 115
	SYS_SYSINFO                 = 116
	SYS_IPC                     = 117
	SYS_FSYNC                   = 118
	SYS_SIGRETURN               = 119
	SYS_CLONE                   = 120
	SYS_SETDOMAINNAME           = 121
	SYS_UNAME                   = 122
	SYS_MODIFY_LDT              = 123
	SYS_ADJTIMEX                = 124
	SYS_MPROTECT                = 125
	SYS_SIGPROCMASK             = 126
	SYS_CREATE_MODULE           = 127
	SYS_INIT_MODULE             = 128
	SYS_DELETE_MODULE           = 129
	SYS_GET_KERNEL_SYMS         = 130
	SYS_QUOTACTL                = 131
	SYS_GETPGID                 = 132
	SYS_FCHDIR                  = 133
	SYS_BDFLUSH                 = 134
	SYS_SYSFS                   = 135
	SYS_PERSONALITY             = 136
	SYS_AFS_SYSCALL             = 137
	SYS_SETFSUID                = 138
	SYS_SETFSGID                = 139
	SYS__LLSEEK                 = 140
	SYS_GETDENTS                = 141
	SYS__NEWSELECT              = 142
	SYS_FLOCK                   = 143
	SYS_MSYNC                   = 144
	SYS_READV                   = 145
	SYS_WRITEV                  = 146
	SYS_GETSID                  = 147
	SYS_FDATASYNC               = 148
	SYS__SYSCTL                 = 149
	SYS_MLOCK                   = 150
	SYS_MUNLOCK                 = 151
	SYS_MLOCKALL                = 152
	SYS_MUNLOCKALL              = 153
	SYS_SCHED_SETPARAM          = 154
	SYS_SCHED_GETPARAM          = 155
	SYS_SCHED_SETSCHEDULER      = 156
	SYS_SCHED_GETSCHEDULER      = 157
	SYS_SCHED_YIELD             = 158
	SYS_SCHED_GET_PRIORITY_MAX  = 159
	SYS_SCHED_GET_PRIORITY_MIN  = 160
	SYS_SCHED_RR_GET_INTERVAL   = 161
	SYS_NANOSLEEP               = 162
	SYS_MREMAP                  = 163
	SYS_SETRESUID               = 164
	SYS_GETRESUID               = 165
	SYS_QUERY_MODULE            = 166
	SYS_POLL                    = 167
	SYS_NFSSERVCTL              = 168
	SYS_SETRESGID               = 169
	SYS_GETRESGID               = 170
	SYS_PRCTL                   = 171
	SYS_RT_SIGRETURN            = 172
	SYS_RT_SIGACTION            = 173
	SYS_RT_SIGPROCMASK          = 174
	SYS_RT_SIGPENDING           = 175
	SYS_RT_SIGTIMEDWAIT         = 176
	SYS_RT_SIGQUEUEINFO         = 177
	SYS_RT_SIGSUSPEND           = 178
	SYS_PREAD64                 = 179
	SYS_PWRITE64                = 180
	SYS_CHOWN                   = 181
	SYS_GETCWD                  = 182
	SYS_CAPGET                  = 183
	SYS_CAPSET                  = 184
	SYS_SIGALTSTACK             = 185
	SYS_SENDFILE                = 186
	SYS_GETPMSG                 = 187
	SYS_PUTPMSG                 = 188
	SYS_VFORK                   = 189
	SYS_UGETRLIMIT              = 190
	SYS_READAHEAD               = 191
	SYS_PCICONFIG_READ          = 198
	SYS_PCICONFIG_WRITE         = 199
	SYS_PCICONFIG_IOBASE        = 200
	SYS_MULTIPLEXER             = 201
	SYS_GETDENTS64              = 202
	SYS_PIVOT_ROOT              = 203
	SYS_MADVISE                 = 205
	SYS_MINCORE                 = 206
	SYS_GETTID                  = 207
	SYS_TKILL                   = 208
	SYS_SETXATTR                = 209
	SYS_LSETXATTR               = 210
	SYS_FSETXATTR               = 211
	SYS_GETXATTR                = 212
	SYS_LGETXATTR               = 213
	SYS_FGETXATTR               = 214
	SYS_LISTXATTR               = 215
	SYS_LLISTXATTR              = 216
	SYS_FLISTXATTR              = 217
	SYS_REMOVEXATTR             = 218
	SYS_LREMOVEXATTR            = 219
	SYS_FREMOVEXATTR            = 220
	SYS_FUTEX                   = 221
	SYS_SCHED_SETAFFINITY       = 222
	SYS_SCHED_GETAFFINITY       = 223
	SYS_TUXCALL                 = 225
	SYS_IO_SETUP                = 227
	SYS_IO_DESTROY              = 228
	SYS_IO_GETEVENTS            = 229
	SYS_IO_SUBMIT               = 230
	SYS_IO_CANCEL               = 231
	SYS_SET_TID_ADDRESS         = 232
	SYS_FADVISE64               = 233
	SYS_EXIT_GROUP              = 234
	SYS_LOOKUP_DCOOKIE          = 235
	SYS_EPOLL_CREATE            = 236
	SYS_EPOLL_CTL               = 237
	SYS_EPOLL_WAIT              = 238
	SYS_REMAP_FILE_PAGES        = 239
	SYS_TIMER_CREATE            = 240
	SYS_TIMER_SETTIME           = 241
	SYS_TIMER_GETTIME           = 242
	SYS_TIMER_GETOVERRUN        = 243
	SYS_TIMER_DELETE            = 244
	SYS_CLOCK_SETTIME           = 245
	SYS_CLOCK_GETTIME           = 246
	SYS_CLOCK_GETRES            = 247
	SYS_CLOCK_NANOSLEEP         = 248
	SYS_SWAPCONTEXT             = 249
	SYS_TGKILL                  = 250
	SYS_UTIMES                  = 251
	SYS_STATFS64                = 252
	SYS_FSTATFS64               = 253
	SYS_RTAS                    = 255
	SYS_SYS_DEBUG_SETCONTEXT    = 256
	SYS_MIGRATE_PAGES           = 258
	SYS_MBIND                   = 259
	SYS_GET_MEMPOLICY           = 260
	SYS_SET_MEMPOLICY           = 261
	SYS_MQ_OPEN                 = 262
	SYS_MQ_UNLINK               = 263
	SYS_MQ_TIMEDSEND            = 264
	SYS_MQ_TIMEDRECEIVE         = 265
	SYS_MQ_NOTIFY               = 266
	SYS_MQ_GETSETATTR           = 267
	SYS_KEXEC_LOAD              = 268
	SYS_ADD_KEY                 = 269
	SYS_REQUEST_KEY             = 270
	SYS_KEYCTL                  = 271
	SYS_WAITID                  = 272
	SYS_IOPRIO_SET              = 273
	SYS_IOPRIO_GET              = 274
	SYS_INOTIFY_INIT            = 275
	SYS_INOTIFY_ADD_WATCH       = 276
	SYS_INOTIFY_RM_WATCH        = 277
	SYS_SPU_RUN                 = 278
	SYS_SPU_CREATE              = 279
	SYS_PSELECT6                = 280
	SYS_PPOLL                   = 281
	SYS_UNSHARE                 = 282
	SYS_SPLICE                  = 283
	SYS_TEE                     = 284
	SYS_VMSPLICE                = 285
	SYS_OPENAT                  = 286
	SYS_MKDIRAT                 = 287
	SYS_MKNODAT                 = 288
	SYS_FCHOWNAT                = 289
	SYS_FUTIMESAT               = 290
	SYS_NEWFSTATAT              = 291
	SYS_UNLINKAT                = 292
	SYS_RENAMEAT                = 293
	SYS_LINKAT                  = 294
	SYS_SYMLINKAT               = 295
	SYS_READLINKAT              = 296
	SYS_FCHMODAT                = 297
	SYS_FACCESSAT               = 298
	SYS_GET_ROBUST_LIST         = 299
	SYS_SET_ROBUST_LIST         = 300
	SYS_MOVE_PAGES              = 301
	SYS_GETCPU                  = 302
	SYS_EPOLL_PWAIT             = 303
	SYS_UTIMENSAT               = 304
	SYS_SIGNALFD                = 305
	SYS_TIMERFD_CREATE          = 306
	SYS_EVENTFD                 = 307
	SYS_SYNC_FILE_RANGE2        = 308
	SYS_FALLOCATE               = 309
	SYS_SUBPAGE_PROT            = 310
	SYS_TIMERFD_SETTIME         = 311
	SYS_TIMERFD_GETTIME         = 312
	SYS_SIGNALFD4               = 313
	SYS_EVENTFD2                = 314
	SYS_EPOLL_CREATE1           = 315
	SYS_DUP3                    = 316
	SYS_PIPE2                   = 317
	SYS_INOTIFY_INIT1           = 318
	SYS_PERF_EVENT_OPEN         = 319
	SYS_PREADV                  = 320
	SYS_PWRITEV                 = 321
	SYS_RT_TGSIGQUEUEINFO       = 322
	SYS_FANOTIFY_INIT           = 323
	SYS_FANOTIFY_MARK           = 324
	SYS_PRLIMIT64               = 325
	SYS_SOCKET                  = 326
	SYS_BIND                    = 327
	SYS_CONNECT                 = 328
	SYS_LISTEN                  = 329
	SYS_ACCEPT                  = 330
	SYS_GETSOCKNAME             = 331
	SYS_GETPEERNAME             = 332
	SYS_SOCKETPAIR              = 333
	SYS_SEND                    = 334
	SYS_SENDTO                  = 335
	SYS_RECV                    = 336
	SYS_RECVFROM                = 337
	SYS_SHUTDOWN                = 338
	SYS_SETSOCKOPT              = 339
	SYS_GETSOCKOPT              = 340
	SYS_SENDMSG                 = 341
	SYS_RECVMSG                 = 342
	SYS_RECVMMSG                = 343
	SYS_ACCEPT4                 = 344
	SYS_NAME_TO_HANDLE_AT       = 345
	SYS_OPEN_BY_HANDLE_AT       = 346
	SYS_CLOCK_ADJTIME           = 347
	SYS_SYNCFS                  = 348
	SYS_SENDMMSG                = 349
	SYS_SETNS                   = 350
	SYS_PROCESS_VM_READV        = 351
	SYS_PROCESS_VM_WRITEV       = 352
	SYS_FINIT_MODULE            = 353
	SYS_KCMP                    = 354
	SYS_SCHED_SETATTR           = 355
	SYS_SCHED_GETATTR           = 356
	SYS_RENAMEAT2               = 357
	SYS_SECCOMP                 = 358
	SYS_GETRANDOM               = 359
	SYS_MEMFD_CREATE            = 360
	SYS_BPF                     = 361
	SYS_EXECVEAT                = 362
	SYS_SWITCH_ENDIAN           = 363
	SYS_USERFAULTFD             = 364
	SYS_MEMBARRIER              = 365
	SYS_MLOCK2                  = 378
	SYS_COPY_FILE_RANGE         = 379
	SYS_PREADV2                 = 380
	SYS_PWRITEV2                = 381
	SYS_KEXEC_FILE_LOAD         = 382
	SYS_STATX                   = 383
	SYS_PKEY_ALLOC              = 384
	SYS_PKEY_FREE               = 385
	SYS_PKEY_MPROTECT           = 386
	SYS_RSEQ                    = 387
	SYS_IO_PGETEVENTS           = 388
	SYS_SEMTIMEDOP              = 392
	SYS_SEMGET                  = 393
	SYS_SEMCTL                  = 394
	SYS_SHMGET                  = 395
	SYS_SHMCTL                  = 396
	SYS_SHMAT                   = 397
	SYS_SHMDT                   = 398
	SYS_MSGGET                  = 399
	SYS_MSGSND                  = 400
	SYS_MSGRCV                  = 401
	SYS_MSGCTL                  = 402
	SYS_PIDFD_SEND_SIGNAL       = 424
	SYS_IO_URING_SETUP          = 425
	SYS_IO_URING_ENTER          = 426
	SYS_IO_URING_REGISTER       = 427
	SYS_OPEN_TREE               = 428
	SYS_MOVE_MOUNT              = 429
	SYS_FSOPEN                  = 430
	SYS_FSCONFIG                = 431
	SYS_FSMOUNT                 = 432
	SYS_FSPICK                  = 433
	SYS_PIDFD_OPEN              = 434
	SYS_CLONE3                  = 435
	SYS_CLOSE_RANGE             = 436
	SYS_OPENAT2                 = 437
	SYS_PIDFD_GETFD             = 438
	SYS_FACCESSAT2              = 439
	SYS_PROCESS_MADVISE         = 440
	SYS_EPOLL_PWAIT2            = 441
	SYS_MOUNT_SETATTR           = 442
	SYS_QUOTACTL_FD             = 443
	SYS_LANDLOCK_CREATE_RULESET = 444
	SYS_LANDLOCK_ADD_RULE       = 445
	SYS_LANDLOCK_RESTRICT_SELF  = 446
	SYS_PROCESS_MRELEASE        = 448
	SYS_FUTEX_WAITV             = 449
	SYS_SET_MEMPOLICY_HOME_NODE = 450
	SYS_CACHESTAT               = 451
	SYS_FCHMODAT2               = 452
	SYS_MAP_SHADOW_STACK        = 453
	SYS_FUTEX_WAKE              = 454
	SYS_FUTEX_WAIT              = 455
	SYS_FUTEX_REQUEUE           = 456
	SYS_STATMOUNT               = 457
	SYS_LISTMOUNT               = 458
	SYS_LSM_GET_SELF_ATTR       = 459
	SYS_LSM_SET_SELF_ATTR       = 460
	SYS_LSM_LIST_MODULES        = 461
	SYS_MSEAL                   = 462
)
```