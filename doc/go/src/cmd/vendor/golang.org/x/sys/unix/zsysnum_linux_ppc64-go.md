Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Initial Understanding:** The code is a Go file named `zsysnum_linux_ppc64.go` located within a specific path in the Go source tree. The comments at the top are crucial. They indicate this file is *generated* and shouldn't be manually edited. The `//go:build` line tells us this code is specifically for the `ppc64` architecture on Linux.

2. **Core Content Analysis:** The body of the file consists of a `package unix` declaration and a `const` block. This `const` block defines a series of constants that start with `SYS_`. Looking at the names (e.g., `SYS_READ`, `SYS_WRITE`, `SYS_OPEN`), it's immediately apparent these relate to system calls. The numbers assigned to them (0, 1, 2, etc.) likely correspond to the system call numbers for the Linux kernel on the `ppc64` architecture.

3. **Functionality Deduction:**  Based on the constant names and the `SYS_` prefix, the primary function of this file is to define the system call numbers for the Linux kernel when running on a PowerPC 64-bit architecture. These numbers are essential for a program to request services from the operating system kernel.

4. **Relating to Go Functionality:** How does Go use this?  Go's standard library provides a package called `syscall` (and, in more recent versions, `unix` in the `golang.org/x/sys` repository which this file is a part of). This package allows Go programs to interact with the operating system's system calls. This file provides the *mapping* between the symbolic names for system calls (like `SYS_READ`) and their numerical representation. When a Go program uses functions in the `syscall` or `unix` package that trigger a system call, Go needs to know the correct number to pass to the kernel. This file provides that information.

5. **Code Example Construction:**  To illustrate this, think about a simple operation like reading a file. In Go, you might use `os.Open`. Under the hood, `os.Open` will eventually make a system call. The `SYS_OPEN` constant defined in this file is the key.

   * **Conceptual Flow:** `os.Open("myfile.txt")` -> `syscall.Open("myfile.txt", ...)` (or similar within the `unix` package) -> Go runtime uses `SYS_OPEN` (which is 5 in this case) to make the actual system call.

   * **Go Code Example:** The example needs to show the use of a `unix` package function that directly interacts with a system call. `unix.Open` is a good choice. The example should demonstrate how the constant is implicitly used.

6. **Input and Output (for Code Example):** For the `unix.Open` example:
   * **Input:** The filename (`test.txt`). We'll assume the file exists for simplicity. The flags and permissions (`unix.O_RDONLY`, `0`).
   * **Output:** A file descriptor (an integer). If there's an error, we'll handle that.

7. **Command Line Arguments:** The comment at the top provides the command used to *generate* this file: `go run linux/mksysnum.go -Wall -Werror -static -I/tmp/ppc64/include /tmp/ppc64/include/asm/unistd.h`. Let's break this down:
   * `go run linux/mksysnum.go`: Executes a Go program likely responsible for parsing system call definitions.
   * `-Wall -Werror`: Standard compiler flags for more warnings and treating warnings as errors.
   * `-static`:  Likely instructs the generator to produce a static definition of the system call numbers.
   * `-I/tmp/ppc64/include`:  Specifies the include directory where the system call definitions are located.
   * `/tmp/ppc64/include/asm/unistd.h`: The specific header file containing the system call definitions for the `ppc64` architecture.

8. **Potential Pitfalls:**  The main pitfall for users is *incorrectly assuming or hardcoding* system call numbers. This file exists precisely to provide the correct, architecture-specific numbers. Manually using a number instead of the symbolic constant could lead to portability issues or incorrect behavior on different architectures. An example of this is trying to use `5` directly instead of `unix.SYS_OPEN`.

9. **Review and Refinement:**  Read through the generated explanation to ensure clarity, accuracy, and completeness. Make sure the code example is runnable and demonstrates the concept effectively. Check if any assumptions need to be explicitly stated. For example, assuming the existence of `test.txt` in the code example.

This systematic approach, starting from understanding the basic purpose of the file and gradually building up to code examples and potential pitfalls, is key to analyzing and explaining code effectively. The comments within the code itself are invaluable clues in this process.
这个Go语言源文件 `go/src/cmd/vendor/golang.org/x/sys/unix/zsysnum_linux_ppc64.go` 的主要功能是**定义了Linux操作系统在ppc64（PowerPC 64-bit）架构下的系统调用号常量**。

**具体功能拆解：**

1. **系统调用号定义:**  文件中使用 Go 语言的 `const` 关键字定义了一系列常量，这些常量以 `SYS_` 开头，后面跟着系统调用的名称，例如 `SYS_READ`， `SYS_WRITE`， `SYS_OPEN` 等。每个常量都被赋予一个整数值，这个整数值就是该系统调用在 ppc64 Linux 架构下的编号。

2. **平台特定:**  `//go:build ppc64 && linux` 这行 build tag 表明，这个文件只会在 `ppc64` 架构并且操作系统是 `linux` 的情况下被编译进程序。这保证了系统调用号的正确性，因为不同的架构和操作系统可能有不同的系统调用号分配。

3. **代码生成:** 文件开头的注释 `// go run linux/mksysnum.go -Wall -Werror -static -I/tmp/ppc64/include /tmp/ppc64/include/asm/unistd.h`  说明这个文件是**自动生成的**。  `mksysnum.go` 是一个 Go 工具，它会解析指定的头文件 (`/tmp/ppc64/include/asm/unistd.h`) 中定义的系统调用号，并生成这个 Go 源文件。这意味着开发者通常不需要手动修改这个文件。

**它是什么Go语言功能的实现？**

这个文件是 Go 语言的 `syscall` 或 `golang.org/x/sys/unix` 包实现其跨平台系统调用支持的关键部分。  Go 语言的标准库和扩展库提供了与操作系统底层交互的能力，例如文件操作、进程管理、网络编程等。这些操作在底层往往需要通过系统调用来完成。

`zsysnum_linux_ppc64.go` 提供了 ppc64 Linux 架构下系统调用的数字映射，使得 Go 程序可以使用符号化的常量（例如 `unix.SYS_READ`）来调用相应的系统调用，而无需关心底层的具体数字。  Go 运行时或者 `syscall`/`unix` 包会在需要的时候使用这些常量。

**Go 代码示例：**

假设你想在 ppc64 Linux 上打开一个文件并读取内容，Go 代码可能会像这样：

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	filename := "test.txt"

	// 假设 test.txt 文件存在并且有读取权限

	// 调用 unix.Open 系统调用，使用 zsysnum_linux_ppc64.go 中定义的 SYS_OPEN
	fd, err := syscall.Open(filename, syscall.O_RDONLY, 0)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer syscall.Close(fd)

	// 读取文件内容
	buf := make([]byte, 100)
	n, err := syscall.Read(fd, buf)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	fmt.Printf("Read %d bytes: %s\n", n, string(buf[:n]))
}
```

**假设的输入与输出：**

* **假设输入:**  在当前目录下存在一个名为 `test.txt` 的文件，内容为 "Hello, World!".
* **预期输出:**
  ```
  Read 13 bytes: Hello, World!
  ```

**代码推理：**

1. `syscall.Open(filename, syscall.O_RDONLY, 0)`:  这个函数调用会使用 `zsysnum_linux_ppc64.go` 中定义的 `SYS_OPEN` 常量（其值为 5）来执行底层的 `open` 系统调用。 `syscall.O_RDONLY` 是一个表示只读模式的常量。
2. `syscall.Read(fd, buf)`: 这个函数调用会使用 `zsysnum_linux_ppc64.go` 中定义的 `SYS_READ` 常量（其值为 3）来执行底层的 `read` 系统调用，从文件描述符 `fd` 中读取数据到缓冲区 `buf` 中。

**命令行参数的具体处理：**

生成 `zsysnum_linux_ppc64.go` 的命令行是：

```
go run linux/mksysnum.go -Wall -Werror -static -I/tmp/ppc64/include /tmp/ppc64/include/asm/unistd.h
```

* **`go run linux/mksysnum.go`**:  执行 `linux/mksysnum.go` 这个 Go 程序。这个程序是用来生成系统调用号文件的。
* **`-Wall`**:  传递给 Go 编译器，启用所有警告。
* **`-Werror`**: 传递给 Go 编译器，将所有警告视为错误。这意味着如果生成代码的过程中有任何警告，都会导致生成失败。
* **`-static`**:  这很可能是 `mksysnum.go` 程序自定义的参数，可能指示生成静态的系统调用号定义。
* **`-I/tmp/ppc64/include`**:  这是传递给 `mksysnum.go` 程序的参数，指定头文件的搜索路径。程序会去 `/tmp/ppc64/include` 目录下查找头文件。
* **`/tmp/ppc64/include/asm/unistd.h`**: 这是传递给 `mksysnum.go` 程序的参数，指定要解析的具体的头文件。这个头文件通常包含了 Linux 系统调用的宏定义，其中就包括了系统调用号。

总结来说，这个命令行的作用是运行一个代码生成工具，该工具读取指定路径下的系统调用头文件，并根据其中的定义生成 Go 语言的常量定义文件。

**使用者易犯错的点：**

对于一般的 Go 开发者来说，**直接使用或修改 `zsysnum_linux_ppc64.go` 的内容是极其不推荐的，也是不应该发生的**。

* **平台依赖性混淆:**  硬编码或假设某个系统调用的编号在所有平台上都一样是错误的。系统调用号是平台相关的。
* **版本兼容性问题:**  即使在同一个平台上，不同版本的操作系统内核也可能更改系统调用号。依赖硬编码的数字会导致程序在新版本上崩溃或行为异常。
* **破坏代码生成流程:** 手动修改此文件会被后续的代码生成过程覆盖，导致修改丢失。

**错误示例（不应该这样做）：**

```go
package main

import "fmt"
import "syscall"

func main() {
	// 错误的做法：直接使用系统调用号，而不是使用 unix 包提供的常量
	fd, err := syscall.RawSyscall(5, uintptr(0), uintptr(syscall.O_RDONLY), 0) // 假设 SYS_OPEN 是 5
	if err != 0 {
		fmt.Println("Error opening file:", err)
		return
	}
	syscall.Close(int(fd))
}
```

在这个错误的示例中，开发者直接使用了数字 `5` 来代表 `SYS_OPEN`，这是不安全且不推荐的做法。应该始终使用 `syscall` 或 `golang.org/x/sys/unix` 包中提供的常量，例如 `syscall.SYS_OPEN` 或 `unix.O_RDONLY`。  Go 语言的这些库会处理平台差异，确保你的代码在不同的操作系统和架构上能够正确地工作。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/zsysnum_linux_ppc64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// go run linux/mksysnum.go -Wall -Werror -static -I/tmp/ppc64/include /tmp/ppc64/include/asm/unistd.h
// Code generated by the command above; see README.md. DO NOT EDIT.

//go:build ppc64 && linux

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