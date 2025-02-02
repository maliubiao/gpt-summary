Response:
Let's break down the thought process for answering this request.

**1. Understanding the Core Request:**

The request asks for an analysis of a Go file containing constants. The key tasks are to identify its purpose, provide examples of its use, explain any associated command-line tools, and highlight potential pitfalls.

**2. Initial Analysis of the File Content:**

The first thing that jumps out is the `// Code generated by the command above; see README.md. DO NOT EDIT.` This immediately tells us:

* **Autogenerated:** This file isn't written by hand; a tool created it.
* **Tool-Driven:**  The comment points to `linux/mksysnum.go`. This is a crucial clue.
* **Configuration:** The command line `go run linux/mksysnum.go -Wall -Werror -static -I/tmp/ppc/include /tmp/ppc/include/asm/unistd.h` provides the configuration for the generation.
* **Platform-Specific:** The filename `zsysnum_linux_ppc.go` and the build constraint `//go:build ppc && linux` indicate this file is specific to the PowerPC architecture on Linux.

The rest of the file is a long list of constants starting with `SYS_`. This strongly suggests these are **system call numbers**.

**3. Inferring the Purpose:**

Knowing these are system call numbers, we can deduce the primary function of the file:

* **Mapping Names to Numbers:** It provides a mapping between human-readable names (e.g., `SYS_READ`) and their corresponding numerical identifiers used by the Linux kernel.

**4. Connecting to Go Functionality:**

The next step is to figure out *how* Go uses these constants. Go's `syscall` package comes to mind. This package provides a low-level interface to the operating system's system calls. It makes sense that this file would be used by the `syscall` package on `ppc` Linux.

**5. Constructing Go Examples:**

To demonstrate the use, we need examples that involve system calls. Good candidates are common operations like reading a file, getting the process ID, and exiting a program.

* **`syscall.Open`, `syscall.Read`, `syscall.Close`:** These demonstrate file operations, which directly correspond to `SYS_OPEN`, `SYS_READ`, and `SYS_CLOSE`.
* **`syscall.Getpid`:** This directly uses the `SYS_GETPID` constant internally.
* **`syscall.Exit`:** This maps to `SYS_EXIT`.

For each example:

* **Input:** Define the necessary input (e.g., filename, buffer).
* **Process:** Show the Go code using the `syscall` functions.
* **Output:**  Describe the expected output or effect.

**6. Analyzing the Command-Line Arguments:**

The comment at the top provides the exact command used to generate the file. We need to break down each argument:

* `go run linux/mksysnum.go`:  Executes the Go program responsible for generating the file.
* `-Wall -Werror`: These are common compiler flags for enabling all warnings and treating warnings as errors. They likely influence the code generation process.
* `-static`:  This might indicate that the generated numbers are statically linked or based on a static header.
* `-I/tmp/ppc/include`: Specifies the include directory where the `mksysnum.go` script looks for header files.
* `/tmp/ppc/include/asm/unistd.h`: The specific header file containing the system call definitions.

**7. Identifying Potential Pitfalls:**

Since this file is autogenerated and intended for internal use by the `syscall` package, direct manual manipulation is the biggest mistake a user could make.

* **Manual Editing:** Explain why this is wrong (overwritten on regeneration, potential inconsistencies).
* **Relying on Specific Numbers:** Emphasize that these numbers are platform-specific and shouldn't be hardcoded in general application code.

**8. Structuring the Answer:**

Organize the information logically:

* **Functionality:** Start with a high-level description of the file's purpose.
* **Go Feature Implementation:** Explain how it relates to the `syscall` package and provide illustrative Go code examples.
* **Code Reasoning (if applicable):**  In this case, the reasoning is primarily based on the constant names and the file's context within the Go source. No complex code tracing is required.
* **Command-Line Arguments:** Detail the purpose of each argument used in the generation command.
* **Potential Pitfalls:** Clearly outline common mistakes users might make.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this file is directly used by user-level programs.
* **Correction:** The `//go:build` constraint and the location within the `vendor` directory suggest it's for internal use within the Go standard library or related packages. The `syscall` package is the logical connection.
* **Initial thought:** Focus on the individual system calls.
* **Refinement:**  Focus on the *purpose* of the file – mapping names to numbers – and how that facilitates the `syscall` package. The individual system calls are details supporting this main purpose.

By following this systematic approach, we can generate a comprehensive and accurate answer to the request.
文件 `go/src/cmd/vendor/golang.org/x/sys/unix/zsysnum_linux_ppc.go` 的功能是定义了一系列常量，这些常量代表了 Linux 系统在 PowerPC (ppc) 架构上的系统调用号。

**它的主要功能：**

1. **提供系统调用号的符号常量：**  将底层的系统调用号 (例如 `0`, `1`, `2` 等) 关联到具有描述性意义的常量名 (例如 `SYS_RESTART_SYSCALL`, `SYS_EXIT`, `SYS_FORK` 等)。这使得在 Go 代码中引用系统调用时更易读和维护。

2. **特定于架构和操作系统：**  `//go:build ppc && linux` 这行构建约束表明，这个文件只会在 `ppc` 架构且操作系统为 `linux` 的情况下被编译。这意味着系统调用号在不同的架构和操作系统上可能会有不同的值，因此需要针对不同的平台定义不同的 `zsysnum_*.go` 文件。

3. **为 `syscall` 包提供基础：** Go 的 `syscall` 标准库包允许程序直接调用操作系统的系统调用。这个文件定义的常量正是 `syscall` 包在 PowerPC Linux 上进行系统调用时所使用的编号。

**它是什么 Go 语言功能的实现：**

这个文件是 Go 语言中 `syscall` 包为了实现跨平台系统调用而采用的一种机制的一部分。由于系统调用号是与操作系统和架构相关的，Go 语言通过为每个支持的平台维护一个类似的 `zsysnum_*.go` 文件来解决这个问题。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	// 假设我们要调用 write 系统调用

	// 文件描述符，假设是标准输出
	fd := uintptr(1)
	// 要写入的内容
	message := "Hello, syscall!\n"
	buffer := unsafe.Pointer(&[]byte(message)[0])
	// 写入的字节数
	count := uintptr(len(message))

	// 直接使用 syscall.Syscall 函数调用系统调用
	// 在 ppc linux 上，SYS_WRITE 的值是 4
	ret, _, err := syscall.Syscall(uintptr(syscall.SYS_WRITE), fd, buffer, count)

	if err != 0 {
		fmt.Printf("syscall failed: %v\n", err)
		return
	}

	fmt.Printf("syscall returned: %d\n", ret)
}
```

**假设的输入与输出：**

* **输入：**  程序执行。
* **输出：**  如果系统调用成功，标准输出会打印 "Hello, syscall!\n"，并且程序会打印 "syscall returned: 15" (假设 "Hello, syscall!\n" 占 15 个字节)。如果系统调用失败，会打印相应的错误信息。

**代码推理：**

1. **`syscall.SYS_WRITE`:**  在 `zsysnum_linux_ppc.go` 中，`SYS_WRITE` 常量的值是 `4`。
2. **`syscall.Syscall`:**  这个函数是 Go 中用于执行系统调用的底层函数。它的第一个参数是系统调用号。
3. **`uintptr(syscall.SYS_WRITE)`:**  将 `SYS_WRITE` 常量转换为 `uintptr` 类型，因为 `syscall.Syscall` 的第一个参数需要 `uintptr`。
4. **`fd`, `buffer`, `count`:** 这些参数对应于 `write` 系统调用的参数：文件描述符、缓冲区指针和要写入的字节数。

**命令行参数的具体处理：**

```
// go run linux/mksysnum.go -Wall -Werror -static -I/tmp/ppc/include /tmp/ppc/include/asm/unistd.h
```

这个注释说明了生成 `zsysnum_linux_ppc.go` 文件的命令：

* **`go run linux/mksysnum.go`:**  执行 `linux/mksysnum.go` 这个 Go 程序。这个程序的作用是从 C 头文件中解析系统调用号并生成 Go 代码。
* **`-Wall`:**  这是 Go 编译器的一个选项，表示启用所有可能的警告。在 `mksysnum.go` 中，它可能被用来在解析头文件时显示所有相关的警告信息。
* **`-Werror`:**  这也是 Go 编译器的一个选项，表示将所有警告视为错误。这意味着如果解析头文件时出现任何警告，程序将会终止。
* **`-static`:** 这个参数的具体含义可能取决于 `mksysnum.go` 程序的实现。一种可能的解释是，它指示程序生成静态的系统调用号列表，而不是尝试在运行时动态获取。
* **`-I/tmp/ppc/include`:**  这是指定头文件搜索路径的参数。`mksysnum.go` 程序会在这里查找指定的头文件。
* **`/tmp/ppc/include/asm/unistd.h`:**  这是指定要解析的 C 头文件。在 Linux 系统中，`asm/unistd.h` 文件通常包含了系统调用的定义和编号。对于 PowerPC 架构，这个文件路径会是特定于 PowerPC 的。

**总结:** `mksysnum.go` 脚本读取指定的 C 头文件 (`/tmp/ppc/include/asm/unistd.h`)，提取其中定义的系统调用号，并根据这些信息生成 `zsysnum_linux_ppc.go` 文件。 `-Wall` 和 `-Werror` 用于控制代码生成过程中的警告行为， `-static` 可能影响系统调用号的获取方式， `-I` 指定头文件路径。

**使用者易犯错的点：**

1. **手动修改此文件：**  最容易犯的错误就是直接编辑 `zsysnum_linux_ppc.go` 文件。由于文件头有 `// Code generated by the command above; see README.md. DO NOT EDIT.` 的注释，说明这个文件是自动生成的。任何手动修改都会在下次重新生成时被覆盖。如果需要修改系统调用号，应该修改生成脚本 `linux/mksysnum.go` 或者修改输入的头文件。

2. **在非 PowerPC Linux 系统上引用这些常量：**  这些常量是特定于 PowerPC 架构的 Linux 系统的。如果在其他架构或操作系统上直接使用这些常量，会导致系统调用号不匹配，从而导致程序崩溃或行为异常。应该使用 `syscall` 包提供的跨平台接口，而不是直接使用 `SYS_*` 常量。`syscall` 包会根据当前的操作系统和架构选择正确的 `zsysnum_*.go` 文件。

**例子说明手动修改的错误：**

假设开发者错误地认为 `SYS_READ` 的值应该是 `10`，并手动将 `zsysnum_linux_ppc.go` 文件中的 `SYS_READ = 3` 修改为 `SYS_READ = 10`。

```go
package main

import (
	"fmt"
	"syscall"
)

func main() {
	// 开发者错误地修改了 zsysnum_linux_ppc.go，认为 SYS_READ 是 10
	fd := 0 // 标准输入
	buf := make([]byte, 100)
	n, err := syscall.Read(fd, buf) // 实际上会调用系统调用号 3 (在内核中仍然是 read)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("Read %d bytes: %s\n", n, string(buf[:n]))
}
```

在这个例子中，即使开发者认为他们调用的是系统调用号 `10`，但由于 `syscall.Read` 最终会使用内核中正确的 `read` 系统调用号 (3)，程序仍然会尝试读取输入。然而，如果内核中系统调用号 `10` 对应的是其他操作，则可能会引发不可预测的行为。而且，下次重新生成 `zsysnum_linux_ppc.go` 时，手动修改会被覆盖。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/zsysnum_linux_ppc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// go run linux/mksysnum.go -Wall -Werror -static -I/tmp/ppc/include /tmp/ppc/include/asm/unistd.h
// Code generated by the command above; see README.md. DO NOT EDIT.

//go:build ppc && linux

package unix

const (
	SYS_RESTART_SYSCALL              = 0
	SYS_EXIT                         = 1
	SYS_FORK                         = 2
	SYS_READ                         = 3
	SYS_WRITE                        = 4
	SYS_OPEN                         = 5
	SYS_CLOSE                        = 6
	SYS_WAITPID                      = 7
	SYS_CREAT                        = 8
	SYS_LINK                         = 9
	SYS_UNLINK                       = 10
	SYS_EXECVE                       = 11
	SYS_CHDIR                        = 12
	SYS_TIME                         = 13
	SYS_MKNOD                        = 14
	SYS_CHMOD                        = 15
	SYS_LCHOWN                       = 16
	SYS_BREAK                        = 17
	SYS_OLDSTAT                      = 18
	SYS_LSEEK                        = 19
	SYS_GETPID                       = 20
	SYS_MOUNT                        = 21
	SYS_UMOUNT                       = 22
	SYS_SETUID                       = 23
	SYS_GETUID                       = 24
	SYS_STIME                        = 25
	SYS_PTRACE                       = 26
	SYS_ALARM                        = 27
	SYS_OLDFSTAT                     = 28
	SYS_PAUSE                        = 29
	SYS_UTIME                        = 30
	SYS_STTY                         = 31
	SYS_GTTY                         = 32
	SYS_ACCESS                       = 33
	SYS_NICE                         = 34
	SYS_FTIME                        = 35
	SYS_SYNC                         = 36
	SYS_KILL                         = 37
	SYS_RENAME                       = 38
	SYS_MKDIR                        = 39
	SYS_RMDIR                        = 40
	SYS_DUP                          = 41
	SYS_PIPE                         = 42
	SYS_TIMES                        = 43
	SYS_PROF                         = 44
	SYS_BRK                          = 45
	SYS_SETGID                       = 46
	SYS_GETGID                       = 47
	SYS_SIGNAL                       = 48
	SYS_GETEUID                      = 49
	SYS_GETEGID                      = 50
	SYS_ACCT                         = 51
	SYS_UMOUNT2                      = 52
	SYS_LOCK                         = 53
	SYS_IOCTL                        = 54
	SYS_FCNTL                        = 55
	SYS_MPX                          = 56
	SYS_SETPGID                      = 57
	SYS_ULIMIT                       = 58
	SYS_OLDOLDUNAME                  = 59
	SYS_UMASK                        = 60
	SYS_CHROOT                       = 61
	SYS_USTAT                        = 62
	SYS_DUP2                         = 63
	SYS_GETPPID                      = 64
	SYS_GETPGRP                      = 65
	SYS_SETSID                       = 66
	SYS_SIGACTION                    = 67
	SYS_SGETMASK                     = 68
	SYS_SSETMASK                     = 69
	SYS_SETREUID                     = 70
	SYS_SETREGID                     = 71
	SYS_SIGSUSPEND                   = 72
	SYS_SIGPENDING                   = 73
	SYS_SETHOSTNAME                  = 74
	SYS_SETRLIMIT                    = 75
	SYS_GETRLIMIT                    = 76
	SYS_GETRUSAGE                    = 77
	SYS_GETTIMEOFDAY                 = 78
	SYS_SETTIMEOFDAY                 = 79
	SYS_GETGROUPS                    = 80
	SYS_SETGROUPS                    = 81
	SYS_SELECT                       = 82
	SYS_SYMLINK                      = 83
	SYS_OLDLSTAT                     = 84
	SYS_READLINK                     = 85
	SYS_USELIB                       = 86
	SYS_SWAPON                       = 87
	SYS_REBOOT                       = 88
	SYS_READDIR                      = 89
	SYS_MMAP                         = 90
	SYS_MUNMAP                       = 91
	SYS_TRUNCATE                     = 92
	SYS_FTRUNCATE                    = 93
	SYS_FCHMOD                       = 94
	SYS_FCHOWN                       = 95
	SYS_GETPRIORITY                  = 96
	SYS_SETPRIORITY                  = 97
	SYS_PROFIL                       = 98
	SYS_STATFS                       = 99
	SYS_FSTATFS                      = 100
	SYS_IOPERM                       = 101
	SYS_SOCKETCALL                   = 102
	SYS_SYSLOG                       = 103
	SYS_SETITIMER                    = 104
	SYS_GETITIMER                    = 105
	SYS_STAT                         = 106
	SYS_LSTAT                        = 107
	SYS_FSTAT                        = 108
	SYS_OLDUNAME                     = 109
	SYS_IOPL                         = 110
	SYS_VHANGUP                      = 111
	SYS_IDLE                         = 112
	SYS_VM86                         = 113
	SYS_WAIT4                        = 114
	SYS_SWAPOFF                      = 115
	SYS_SYSINFO                      = 116
	SYS_IPC                          = 117
	SYS_FSYNC                        = 118
	SYS_SIGRETURN                    = 119
	SYS_CLONE                        = 120
	SYS_SETDOMAINNAME                = 121
	SYS_UNAME                        = 122
	SYS_MODIFY_LDT                   = 123
	SYS_ADJTIMEX                     = 124
	SYS_MPROTECT                     = 125
	SYS_SIGPROCMASK                  = 126
	SYS_CREATE_MODULE                = 127
	SYS_INIT_MODULE                  = 128
	SYS_DELETE_MODULE                = 129
	SYS_GET_KERNEL_SYMS              = 130
	SYS_QUOTACTL                     = 131
	SYS_GETPGID                      = 132
	SYS_FCHDIR                       = 133
	SYS_BDFLUSH                      = 134
	SYS_SYSFS                        = 135
	SYS_PERSONALITY                  = 136
	SYS_AFS_SYSCALL                  = 137
	SYS_SETFSUID                     = 138
	SYS_SETFSGID                     = 139
	SYS__LLSEEK                      = 140
	SYS_GETDENTS                     = 141
	SYS__NEWSELECT                   = 142
	SYS_FLOCK                        = 143
	SYS_MSYNC                        = 144
	SYS_READV                        = 145
	SYS_WRITEV                       = 146
	SYS_GETSID                       = 147
	SYS_FDATASYNC                    = 148
	SYS__SYSCTL                      = 149
	SYS_MLOCK                        = 150
	SYS_MUNLOCK                      = 151
	SYS_MLOCKALL                     = 152
	SYS_MUNLOCKALL                   = 153
	SYS_SCHED_SETPARAM               = 154
	SYS_SCHED_GETPARAM               = 155
	SYS_SCHED_SETSCHEDULER           = 156
	SYS_SCHED_GETSCHEDULER           = 157
	SYS_SCHED_YIELD                  = 158
	SYS_SCHED_GET_PRIORITY_MAX       = 159
	SYS_SCHED_GET_PRIORITY_MIN       = 160
	SYS_SCHED_RR_GET_INTERVAL        = 161
	SYS_NANOSLEEP                    = 162
	SYS_MREMAP                       = 163
	SYS_SETRESUID                    = 164
	SYS_GETRESUID                    = 165
	SYS_QUERY_MODULE                 = 166
	SYS_POLL                         = 167
	SYS_NFSSERVCTL                   = 168
	SYS_SETRESGID                    = 169
	SYS_GETRESGID                    = 170
	SYS_PRCTL                        = 171
	SYS_RT_SIGRETURN                 = 172
	SYS_RT_SIGACTION                 = 173
	SYS_RT_SIGPROCMASK               = 174
	SYS_RT_SIGPENDING                = 175
	SYS_RT_SIGTIMEDWAIT              = 176
	SYS_RT_SIGQUEUEINFO              = 177
	SYS_RT_SIGSUSPEND                = 178
	SYS_PREAD64                      = 179
	SYS_PWRITE64                     = 180
	SYS_CHOWN                        = 181
	SYS_GETCWD                       = 182
	SYS_CAPGET                       = 183
	SYS_CAPSET                       = 184
	SYS_SIGALTSTACK                  = 185
	SYS_SENDFILE                     = 186
	SYS_GETPMSG                      = 187
	SYS_PUTPMSG                      = 188
	SYS_VFORK                        = 189
	SYS_UGETRLIMIT                   = 190
	SYS_READAHEAD                    = 191
	SYS_MMAP2                        = 192
	SYS_TRUNCATE64                   = 193
	SYS_FTRUNCATE64                  = 194
	SYS_STAT64                       = 195
	SYS_LSTAT64                      = 196
	SYS_FSTAT64                      = 197
	SYS_PCICONFIG_READ               = 198
	SYS_PCICONFIG_WRITE              = 199
	SYS_PCICONFIG_IOBASE             = 200
	SYS_MULTIPLEXER                  = 201
	SYS_GETDENTS64                   = 202
	SYS_PIVOT_ROOT                   = 203
	SYS_FCNTL64                      = 204
	SYS_MADVISE                      = 205
	SYS_MINCORE                      = 206
	SYS_GETTID                       = 207
	SYS_TKILL                        = 208
	SYS_SETXATTR                     = 209
	SYS_LSETXATTR                    = 210
	SYS_FSETXATTR                    = 211
	SYS_GETXATTR                     = 212
	SYS_LGETXATTR                    = 213
	SYS_FGETXATTR                    = 214
	SYS_LISTXATTR                    = 215
	SYS_LLISTXATTR                   = 216
	SYS_FLISTXATTR                   = 217
	SYS_REMOVEXATTR                  = 218
	SYS_LREMOVEXATTR                 = 219
	SYS_FREMOVEXATTR                 = 220
	SYS_FUTEX                        = 221
	SYS_SCHED_SETAFFINITY            = 222
	SYS_SCHED_GETAFFINITY            = 223
	SYS_TUXCALL                      = 225
	SYS_SENDFILE64                   = 226
	SYS_IO_SETUP                     = 227
	SYS_IO_DESTROY                   = 228
	SYS_IO_GETEVENTS                 = 229
	SYS_IO_SUBMIT                    = 230
	SYS_IO_CANCEL                    = 231
	SYS_SET_TID_ADDRESS              = 232
	SYS_FADVISE64                    = 233
	SYS_EXIT_GROUP                   = 234
	SYS_LOOKUP_DCOOKIE               = 235
	SYS_EPOLL_CREATE                 = 236
	SYS_EPOLL_CTL                    = 237
	SYS_EPOLL_WAIT                   = 238
	SYS_REMAP_FILE_PAGES             = 239
	SYS_TIMER_CREATE                 = 240
	SYS_TIMER_SETTIME                = 241
	SYS_TIMER_GETTIME                = 242
	SYS_TIMER_GETOVERRUN             = 243
	SYS_TIMER_DELETE                 = 244
	SYS_CLOCK_SETTIME                = 245
	SYS_CLOCK_GETTIME                = 246
	SYS_CLOCK_GETRES                 = 247
	SYS_CLOCK_NANOSLEEP              = 248
	SYS_SWAPCONTEXT                  = 249
	SYS_TGKILL                       = 250
	SYS_UTIMES                       = 251
	SYS_STATFS64                     = 252
	SYS_FSTATFS64                    = 253
	SYS_FADVISE64_64                 = 254
	SYS_RTAS                         = 255
	SYS_SYS_DEBUG_SETCONTEXT         = 256
	SYS_MIGRATE_PAGES                = 258
	SYS_MBIND                        = 259
	SYS_GET_MEMPOLICY                = 260
	SYS_SET_MEMPOLICY                = 261
	SYS_MQ_OPEN                      = 262
	SYS_MQ_UNLINK                    = 263
	SYS_MQ_TIMEDSEND                 = 264
	SYS_MQ_TIMEDRECEIVE              = 265
	SYS_MQ_NOTIFY                    = 266
	SYS_MQ_GETSETATTR                = 267
	SYS_KEXEC_LOAD                   = 268
	SYS_ADD_KEY                      = 269
	SYS_REQUEST_KEY                  = 270
	SYS_KEYCTL                       = 271
	SYS_WAITID                       = 272
	SYS_IOPRIO_SET                   = 273
	SYS_IOPRIO_GET                   = 274
	SYS_INOTIFY_INIT                 = 275
	SYS_INOTIFY_ADD_WATCH            = 276
	SYS_INOTIFY_RM_WATCH             = 277
	SYS_SPU_RUN                      = 278
	SYS_SPU_CREATE                   = 279
	SYS_PSELECT6                     = 280
	SYS_PPOLL                        = 281
	SYS_UNSHARE                      = 282
	SYS_SPLICE                       = 283
	SYS_TEE                          = 284
	SYS_VMSPLICE                     = 285
	SYS_OPENAT                       = 286
	SYS_MKDIRAT                      = 287
	SYS_MKNODAT                      = 288
	SYS_FCHOWNAT                     = 289
	SYS_FUTIMESAT                    = 290
	SYS_FSTATAT64                    = 291
	SYS_UNLINKAT                     = 292
	SYS_RENAMEAT                     = 293
	SYS_LINKAT                       = 294
	SYS_SYMLINKAT                    = 295
	SYS_READLINKAT                   = 296
	SYS_FCHMODAT                     = 297
	SYS_FACCESSAT                    = 298
	SYS_GET_ROBUST_LIST              = 299
	SYS_SET_ROBUST_LIST              = 300
	SYS_MOVE_PAGES                   = 301
	SYS_GETCPU                       = 302
	SYS_EPOLL_PWAIT                  = 303
	SYS_UTIMENSAT                    = 304
	SYS_SIGNALFD                     = 305
	SYS_TIMERFD_CREATE               = 306
	SYS_EVENTFD                      = 307
	SYS_SYNC_FILE_RANGE2             = 308
	SYS_FALLOCATE                    = 309
	SYS_SUBPAGE_PROT                 = 310
	SYS_TIMERFD_SETTIME              = 311
	SYS_TIMERFD_GETTIME              = 312
	SYS_SIGNALFD4                    = 313
	SYS_EVENTFD2                     = 314
	SYS_EPOLL_CREATE1                = 315
	SYS_DUP3                         = 316
	SYS_PIPE2                        = 317
	SYS_INOTIFY_INIT1                = 318
	SYS_PERF_EVENT_OPEN              = 319
	SYS_PREADV                       = 320
	SYS_PWRITEV                      = 321
	SYS_RT_TGSIGQUEUEINFO            = 322
	SYS_FANOTIFY_INIT                = 323
	SYS_FANOTIFY_MARK                = 324
	SYS_PRLIMIT64                    = 325
	SYS_SOCKET                       = 326
	SYS_BIND                         = 327
	SYS_CONNECT                      = 328
	SYS_LISTEN                       = 329
	SYS_ACCEPT                       = 330
	SYS_GETSOCKNAME                  = 331
	SYS_GETPEERNAME                  = 332
	SYS_SOCKETPAIR                   = 333
	SYS_SEND                         = 334
	SYS_SENDTO                       = 335
	SYS_RECV                         = 336
	SYS_RECVFROM                     = 337
	SYS_SHUTDOWN                     = 338
	SYS_SETSOCKOPT                   = 339
	SYS_GETSOCKOPT                   = 340
	SYS_SENDMSG                      = 341
	SYS_RECVMSG                      = 342
	SYS_RECVMMSG                     = 343
	SYS_ACCEPT4                      = 344
	SYS_NAME_TO_HANDLE_AT            = 345
	SYS_OPEN_BY_HANDLE_AT            = 346
	SYS_CLOCK_ADJTIME                = 347
	SYS_SYNCFS                       = 348
	SYS_SENDMMSG                     = 349
	SYS_SETNS                        = 350
	SYS_PROCESS_VM_READV             = 351
	SYS_PROCESS_VM_WRITEV            = 352
	SYS_FINIT_MODULE                 = 353
	SYS_KCMP                         = 354
	SYS_SCHED_SETATTR                = 355
	SYS_SCHED_GETATTR                = 356
	SYS_RENAMEAT2                    = 357
	SYS_SECCOMP                      = 358
	SYS_GETRANDOM                    = 359
	SYS_MEMFD_CREATE                 = 360
	SYS_BPF                          = 361
	SYS_EXECVEAT                     = 362
	SYS_SWITCH_ENDIAN                = 363
	SYS_USERFAULTFD                  = 364
	SYS_MEMBARRIER                   = 365
	SYS_MLOCK2                       = 378
	SYS_COPY_FILE_RANGE              = 379
	SYS_PREADV2                      = 380
	SYS_PWRITEV2                     = 381
	SYS_KEXEC_FILE_LOAD              = 382
	SYS_STATX                        = 383
	SYS_PKEY_ALLOC                   = 384
	SYS_PKEY_FREE                    = 385
	SYS_PKEY_MPROTECT                = 386
	SYS_RSEQ                         = 387
	SYS_IO_PGETEVENTS                = 388
	SYS_SEMGET                       = 393
	SYS_SEMCTL                       = 394
	SYS_SHMGET                       = 395
	SYS_SHMCTL                       = 396
	SYS_SHMAT                        = 397
	SYS_SHMDT                        = 398
	SYS_MSGGET                       = 399
	SYS_MSGSND                       = 400
	SYS_MSGRCV                       = 401
	SYS_MSGCTL                       = 402
	SYS_CLOCK_GETTIME64              = 403
	SYS_CLOCK_SETTIME64              = 404
	SYS_CLOCK_ADJTIME64              = 405
	SYS_CLOCK_GETRES_TIME64          = 406
	SYS_CLOCK_NANOSLEEP_TIME64       = 407
	SYS_TIMER_GETTIME64              = 408
	SYS_TIMER_SETTIME64              = 409
	SYS_TIMERFD_GETTIME64            = 410
	SYS_TIMERFD_SETTIME64            = 411
	SYS_UTIMENSAT_TIME64             = 412
	SYS_PSELECT6_TIME64              = 413
	SYS_PPOLL_TIME64                 = 414
	SYS_IO_PGETEVENTS_TIME64         = 416
	SYS_RECVMMSG_TIME64              = 417
	SYS_MQ_TIMEDSEND_TIME64          = 418
	SYS_MQ_TIMEDRECEIVE_TIME64       = 419
	SYS_SEMTIMEDOP_TIME64            = 420
	SYS_RT_SIGTIMEDWAIT_TIME64       = 421
	SYS_FUTEX_TIME64                 = 422
	SYS_SCHED_RR_GET_INTERVAL_TIME64 = 423
	SYS_PIDFD_SEND_SIGNAL            = 424
	SYS_IO_URING_SETUP               = 425
	SYS_IO_URING_ENTER               = 426
	SYS_IO_URING_REGISTER            = 427
	SYS_OPEN_TREE                    = 428
	SYS_MOVE_MOUNT                   = 429
	SYS_FSOPEN                       = 430
	SYS_FSCONFIG                     = 431
	SYS_FSMOUNT                      = 432
	SYS_FSPICK                       = 433
	SYS_PIDFD_OPEN                   = 434
	SYS_CLONE3                       = 435
	SYS_CLOSE_RANGE                  = 436
	SYS_OPENAT2                      = 437
	SYS_PIDFD_GETFD                  = 438
	SYS_FACCESSAT2                   = 439
	SYS_PROCESS_MADVISE              = 440
	SYS_EPOLL_PWAIT2                 = 441
	SYS_MOUNT_SETATTR                = 442
	SYS_QUOTACTL_FD                  = 443
	SYS_LANDLOCK_CREATE_RULESET      = 444
	SYS_LANDLOCK_ADD_RULE            = 445
	SYS_LANDLOCK_RESTRICT_SELF       = 446
	SYS_PROCESS_MRELEASE             = 448
	SYS_FUTEX_WAITV                  = 449
	SYS_SET_MEMPOLICY_HOME_NODE      = 450
	SYS_CACHESTAT                    = 451
	SYS_FCHMODAT2                    = 452
	SYS_MAP_SHADOW_STACK             = 453
	SYS_FUTEX_WAKE                   = 454
	SYS_FUTEX_WAIT                   = 455
	SYS_FUTEX_REQUEUE                = 456
	SYS_STATMOUNT                    = 457
	SYS_LISTMOUNT                    = 458
	SYS_LSM_GET_SELF_ATTR            = 459
	SYS_LSM_SET_SELF_ATTR            = 460
	SYS_LSM_LIST_MODULES             = 461
	SYS_MSEAL                        = 462
)
```