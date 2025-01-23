Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Observation and Context:**

* **File Path:** `go/src/cmd/vendor/golang.org/x/sys/unix/zsysnum_linux_arm.go`  Immediately tells us a few things:
    * It's part of the `golang.org/x/sys` package, which is a low-level system interface library for Go.
    * It's within the `vendor` directory, indicating it's a dependency managed locally.
    * The `unix` subdirectory suggests it's specifically for Unix-like systems.
    * `zsysnum_linux_arm.go` strongly implies it deals with system call numbers (`sysnum`) for Linux on the ARM architecture. The `z` prefix might indicate auto-generation or a specific purpose within the build process.

* **Code Generation Comment:** The first lines `// go run linux/mksysnum.go ...` are crucial. They tell us this file is *generated* by another Go program (`mksysnum.go`). This means we should focus on the *output* of that generation process, not necessarily the direct functionality of *this* file in a running Go program.

* **`//go:build arm && linux`:** This is a Go build constraint (build tag). It means this file will *only* be included in builds targeting the `arm` architecture and the `linux` operating system. This confirms our earlier deduction from the filename.

* **`package unix`:**  This confirms the package name, consistent with the directory structure.

* **`const (...)` block:**  This defines a series of Go constants. The names of the constants (`SYS_EXIT`, `SYS_READ`, `SYS_OPEN`, etc.) strongly resemble standard Unix system call names. The values assigned to them (0, 1, 2, etc.) are likely the corresponding system call numbers for the Linux/ARM platform.

**2. Inferring Functionality:**

Based on the above observations, the primary function of this file is to:

* **Provide a mapping:**  It provides a mapping between symbolic names (e.g., `SYS_EXIT`) and their numerical representation (the system call number, e.g., `1`) for Linux systems running on ARM architecture.

**3. Reasoning about the "Why":**

Why is this necessary?

* **System Calls:**  Operating systems provide an interface for user-level programs to request services from the kernel. These requests are made via *system calls*. Each system call is identified by a unique number.
* **Platform Dependence:** System call numbers are not standardized across all operating systems or even across different architectures of the same operating system. What is `1` on Linux/ARM might be something else on Linux/x86 or macOS.
* **Abstraction:** Go's `syscall` package (or the lower-level parts of `golang.org/x/sys/unix`) needs a way to translate a generic system call request (like "exit the program") into the specific number the kernel expects on the current platform. This file provides that crucial platform-specific information.

**4. Illustrative Go Code Example:**

How would a Go program use these constants?

* The `syscall` package is the most likely consumer. We can demonstrate a simple example of making a system call. Since `SYS_EXIT` is present, a program exiting is a good example.

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	fmt.Println("About to exit...")
	syscall.Syscall(syscall.SYS_EXIT, 0, 0, 0) // Assuming SYS_EXIT is accessible
	fmt.Println("This should not be printed") // Because the program exited
}
```

* **Hypothetical Input/Output (for syscall):**  While this specific file doesn't have direct input/output, we can think about the `syscall.Syscall` function. The *input* would be the system call number (obtained from the constants in this file) and arguments. The *output* would be the return value of the system call, and potentially changes to system state (like the program exiting).

**5. Command Line and Generation Process:**

The comment `// go run linux/mksysnum.go ...` provides the key information.

* **`go run linux/mksysnum.go`:** This executes the `mksysnum.go` program.
* **`-Wall -Werror`:** These are likely flags passed to a C compiler (like gcc or clang) during the `mksysnum.go` execution. They enable more warnings and treat warnings as errors.
* **`-static`:**  Another C compiler flag, indicating static linking.
* **`-I/tmp/arm/include`:** Specifies an include directory where the C preprocessor should look for header files. This tells us the build environment has headers for the ARM architecture.
* **`/tmp/arm/include/asm/unistd.h`:** This is the crucial input file. `unistd.h` is a standard C header file that, on Linux, typically defines the system call numbers. The `asm/` subdirectory suggests it's the architecture-specific version.

**6. Potential User Errors:**

* **Direct Modification:**  The "DO NOT EDIT" comment is a strong warning. Users should *not* manually change this file. Any modifications will likely be overwritten the next time the `mksysnum.go` script is run.
* **Incorrect Assumptions:** Users might mistakenly assume these system call numbers are universally valid across all Linux architectures. This file is specific to `arm` and `linux`.

**7. Self-Correction/Refinement:**

* Initially, I might have focused too much on the *functionality of the constants within Go code*. While important, realizing the file is *generated* shifts the focus to the generation process and the *source of truth* (the `unistd.h` file).
* I considered whether to provide more complex examples of syscall usage, but decided to keep it simple with `SYS_EXIT` to illustrate the basic concept.
* I made sure to explicitly mention the build constraints, as they are a critical part of understanding when this file is relevant.

By following these steps, combining code analysis with an understanding of operating system concepts and Go's build process, we can arrive at a comprehensive explanation of the provided code snippet.
The Go code snippet you provided is a generated file (`zsysnum_linux_arm.go`) that defines a set of **constants representing system call numbers** for the Linux operating system running on the ARM architecture.

Here's a breakdown of its functionality:

**1. Mapping System Call Names to Numbers:**

The primary function of this file is to create a mapping between human-readable names for system calls (like `SYS_EXIT`, `SYS_READ`, `SYS_OPEN`) and their corresponding numerical identifiers. These numbers are used by the Linux kernel to identify which system service a user-space program is requesting.

**2. Platform Specificity:**

The file name `zsysnum_linux_arm.go` and the build constraint `//go:build arm && linux` clearly indicate that these system call numbers are specific to the **Linux operating system running on the ARM architecture**. System call numbers can vary between different operating systems and even different architectures of the same OS.

**3. Use by the `syscall` Package:**

This file is a crucial part of the `syscall` package (or the more modern `golang.org/x/sys/unix` package, where it resides). These packages provide a low-level interface for Go programs to interact directly with the operating system kernel. When you make a system call in Go using these packages, the symbolic names defined in this file are used internally to pass the correct numerical identifier to the kernel.

**4. Auto-Generation:**

The comments at the beginning:

```
// go run linux/mksysnum.go -Wall -Werror -static -I/tmp/arm/include /tmp/arm/include/asm/unistd.h
// Code generated by the command above; see README.md. DO NOT EDIT.
```

are extremely important. They tell us that this file is **automatically generated** by running the `mksysnum.go` program. This program likely reads the system call definitions from the C header file `/tmp/arm/include/asm/unistd.h` and generates the Go code to define the constants. This ensures that the Go code accurately reflects the system call numbers for the target platform.

**What Go Language Feature is This Implementing?**

This file directly supports the functionality of the `syscall` package (or `golang.org/x/sys/unix`). It allows Go programs to make **system calls**, which is a fundamental mechanism for interacting with the operating system kernel.

**Go Code Example:**

Here's an example of how these constants might be used within the `syscall` package (or by a sufficiently low-level Go program):

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	message := "Hello, system call!\n"
	fd := 1 // Standard output file descriptor

	// Assuming SYS_WRITE is defined in the unix package (which it is based on the provided snippet)
	_, _, err := syscall.Syscall(syscall.SYS_WRITE, uintptr(fd), uintptr(unsafe.Pointer(syscall.StringBytePtr(message))), uintptr(len(message)))
	if err != 0 {
		fmt.Println("Error writing:", err)
	}

	// Exit the program using the SYS_EXIT system call
	syscall.Exit(0) // Internally likely uses syscall.Syscall(syscall.SYS_EXIT, 0, 0, 0)
}
```

**Explanation of the Example:**

1. **`syscall.SYS_WRITE`:** We use the constant `syscall.SYS_WRITE` (which is defined in the provided snippet) to indicate we want to perform the `write` system call.
2. **`syscall.Syscall`:** This function is the core of making system calls in Go. It takes the system call number and its arguments as `uintptr` values.
3. **Arguments:**  We provide the file descriptor (`fd`), a pointer to the data to be written (`unsafe.Pointer(syscall.StringBytePtr(message))`), and the number of bytes to write (`len(message)`).
4. **`syscall.Exit(0)`:** This function uses the `SYS_EXIT` constant internally to terminate the program gracefully.

**Hypothetical Input and Output (for the example):**

* **Input:** The string "Hello, system call!\n" and the file descriptor `1`.
* **Output:** The string "Hello, system call!\n" will be printed to the standard output. The program will then exit.

**Command-Line Parameter Handling:**

The provided snippet itself **does not handle any command-line parameters**. The command at the beginning:

```
// go run linux/mksysnum.go -Wall -Werror -static -I/tmp/arm/include /tmp/arm/include/asm/unistd.h
```

shows the command used to *generate* this file. Let's break down those parameters:

* **`go run linux/mksysnum.go`:**  This executes the Go program `mksysnum.go` located in the `linux` subdirectory.
* **`-Wall`:** This is likely a flag passed to a C compiler (like `gcc` or `clang`) within the `mksysnum.go` program. It typically means "enable all warnings".
* **`-Werror`:**  Another C compiler flag, meaning "treat warnings as errors". This ensures strictness during the generation process.
* **`-static`:**  A C compiler flag indicating that the generated code (if any C code is involved in `mksysnum.go`) should be linked statically.
* **`-I/tmp/arm/include`:** This is a crucial flag for the C preprocessor. It tells the preprocessor to add `/tmp/arm/include` to the list of directories to search for header files (like `unistd.h`). This ensures that the correct architecture-specific header file is used.
* **`/tmp/arm/include/asm/unistd.h`:** This is the input file for the `mksysnum.go` program. It's the C header file that defines the system call numbers for the ARM architecture on Linux.

**In summary, the command-line parameters are used by the *generator* program (`mksysnum.go`) to locate and parse the correct system call definitions and then output the Go code.**

**User Errors:**

A common mistake users might make is **directly modifying this file**. The "DO NOT EDIT" comment is there for a reason. Any manual changes will likely be overwritten the next time the `mksysnum.go` script is run (e.g., during a Go SDK update or a rebuild of the `sys` package).

**Example of a Mistake:**

Let's say a user, for some misguided reason, decides that `SYS_EXIT` should be `999` instead of `1`. If they manually edit the file:

```go
const (
	// ... other constants ...
	SYS_EXIT                         = 999 // WRONG! DO NOT DO THIS
	// ... other constants ...
)
```

Then, if a Go program relies on `syscall.Exit(0)` (which internally uses `SYS_EXIT`), it will now try to execute system call number 999 for exiting, which is incorrect and will likely lead to a crash or unexpected behavior.

Therefore, the golden rule is: **Do not manually edit generated files like this.** If there's a discrepancy or a need for a different system call number (which is highly unlikely in standard scenarios), the issue lies with the generation process or the underlying operating system definitions, not this file itself.

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/zsysnum_linux_arm.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// go run linux/mksysnum.go -Wall -Werror -static -I/tmp/arm/include /tmp/arm/include/asm/unistd.h
// Code generated by the command above; see README.md. DO NOT EDIT.

//go:build arm && linux

package unix

const (
	SYS_SYSCALL_MASK                 = 0
	SYS_RESTART_SYSCALL              = 0
	SYS_EXIT                         = 1
	SYS_FORK                         = 2
	SYS_READ                         = 3
	SYS_WRITE                        = 4
	SYS_OPEN                         = 5
	SYS_CLOSE                        = 6
	SYS_CREAT                        = 8
	SYS_LINK                         = 9
	SYS_UNLINK                       = 10
	SYS_EXECVE                       = 11
	SYS_CHDIR                        = 12
	SYS_MKNOD                        = 14
	SYS_CHMOD                        = 15
	SYS_LCHOWN                       = 16
	SYS_LSEEK                        = 19
	SYS_GETPID                       = 20
	SYS_MOUNT                        = 21
	SYS_SETUID                       = 23
	SYS_GETUID                       = 24
	SYS_PTRACE                       = 26
	SYS_PAUSE                        = 29
	SYS_ACCESS                       = 33
	SYS_NICE                         = 34
	SYS_SYNC                         = 36
	SYS_KILL                         = 37
	SYS_RENAME                       = 38
	SYS_MKDIR                        = 39
	SYS_RMDIR                        = 40
	SYS_DUP                          = 41
	SYS_PIPE                         = 42
	SYS_TIMES                        = 43
	SYS_BRK                          = 45
	SYS_SETGID                       = 46
	SYS_GETGID                       = 47
	SYS_GETEUID                      = 49
	SYS_GETEGID                      = 50
	SYS_ACCT                         = 51
	SYS_UMOUNT2                      = 52
	SYS_IOCTL                        = 54
	SYS_FCNTL                        = 55
	SYS_SETPGID                      = 57
	SYS_UMASK                        = 60
	SYS_CHROOT                       = 61
	SYS_USTAT                        = 62
	SYS_DUP2                         = 63
	SYS_GETPPID                      = 64
	SYS_GETPGRP                      = 65
	SYS_SETSID                       = 66
	SYS_SIGACTION                    = 67
	SYS_SETREUID                     = 70
	SYS_SETREGID                     = 71
	SYS_SIGSUSPEND                   = 72
	SYS_SIGPENDING                   = 73
	SYS_SETHOSTNAME                  = 74
	SYS_SETRLIMIT                    = 75
	SYS_GETRUSAGE                    = 77
	SYS_GETTIMEOFDAY                 = 78
	SYS_SETTIMEOFDAY                 = 79
	SYS_GETGROUPS                    = 80
	SYS_SETGROUPS                    = 81
	SYS_SYMLINK                      = 83
	SYS_READLINK                     = 85
	SYS_USELIB                       = 86
	SYS_SWAPON                       = 87
	SYS_REBOOT                       = 88
	SYS_MUNMAP                       = 91
	SYS_TRUNCATE                     = 92
	SYS_FTRUNCATE                    = 93
	SYS_FCHMOD                       = 94
	SYS_FCHOWN                       = 95
	SYS_GETPRIORITY                  = 96
	SYS_SETPRIORITY                  = 97
	SYS_STATFS                       = 99
	SYS_FSTATFS                      = 100
	SYS_SYSLOG                       = 103
	SYS_SETITIMER                    = 104
	SYS_GETITIMER                    = 105
	SYS_STAT                         = 106
	SYS_LSTAT                        = 107
	SYS_FSTAT                        = 108
	SYS_VHANGUP                      = 111
	SYS_WAIT4                        = 114
	SYS_SWAPOFF                      = 115
	SYS_SYSINFO                      = 116
	SYS_FSYNC                        = 118
	SYS_SIGRETURN                    = 119
	SYS_CLONE                        = 120
	SYS_SETDOMAINNAME                = 121
	SYS_UNAME                        = 122
	SYS_ADJTIMEX                     = 124
	SYS_MPROTECT                     = 125
	SYS_SIGPROCMASK                  = 126
	SYS_INIT_MODULE                  = 128
	SYS_DELETE_MODULE                = 129
	SYS_QUOTACTL                     = 131
	SYS_GETPGID                      = 132
	SYS_FCHDIR                       = 133
	SYS_BDFLUSH                      = 134
	SYS_SYSFS                        = 135
	SYS_PERSONALITY                  = 136
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
	SYS_POLL                         = 168
	SYS_NFSSERVCTL                   = 169
	SYS_SETRESGID                    = 170
	SYS_GETRESGID                    = 171
	SYS_PRCTL                        = 172
	SYS_RT_SIGRETURN                 = 173
	SYS_RT_SIGACTION                 = 174
	SYS_RT_SIGPROCMASK               = 175
	SYS_RT_SIGPENDING                = 176
	SYS_RT_SIGTIMEDWAIT              = 177
	SYS_RT_SIGQUEUEINFO              = 178
	SYS_RT_SIGSUSPEND                = 179
	SYS_PREAD64                      = 180
	SYS_PWRITE64                     = 181
	SYS_CHOWN                        = 182
	SYS_GETCWD                       = 183
	SYS_CAPGET                       = 184
	SYS_CAPSET                       = 185
	SYS_SIGALTSTACK                  = 186
	SYS_SENDFILE                     = 187
	SYS_VFORK                        = 190
	SYS_UGETRLIMIT                   = 191
	SYS_MMAP2                        = 192
	SYS_TRUNCATE64                   = 193
	SYS_FTRUNCATE64                  = 194
	SYS_STAT64                       = 195
	SYS_LSTAT64                      = 196
	SYS_FSTAT64                      = 197
	SYS_LCHOWN32                     = 198
	SYS_GETUID32                     = 199
	SYS_GETGID32                     = 200
	SYS_GETEUID32                    = 201
	SYS_GETEGID32                    = 202
	SYS_SETREUID32                   = 203
	SYS_SETREGID32                   = 204
	SYS_GETGROUPS32                  = 205
	SYS_SETGROUPS32                  = 206
	SYS_FCHOWN32                     = 207
	SYS_SETRESUID32                  = 208
	SYS_GETRESUID32                  = 209
	SYS_SETRESGID32                  = 210
	SYS_GETRESGID32                  = 211
	SYS_CHOWN32                      = 212
	SYS_SETUID32                     = 213
	SYS_SETGID32                     = 214
	SYS_SETFSUID32                   = 215
	SYS_SETFSGID32                   = 216
	SYS_GETDENTS64                   = 217
	SYS_PIVOT_ROOT                   = 218
	SYS_MINCORE                      = 219
	SYS_MADVISE                      = 220
	SYS_FCNTL64                      = 221
	SYS_GETTID                       = 224
	SYS_READAHEAD                    = 225
	SYS_SETXATTR                     = 226
	SYS_LSETXATTR                    = 227
	SYS_FSETXATTR                    = 228
	SYS_GETXATTR                     = 229
	SYS_LGETXATTR                    = 230
	SYS_FGETXATTR                    = 231
	SYS_LISTXATTR                    = 232
	SYS_LLISTXATTR                   = 233
	SYS_FLISTXATTR                   = 234
	SYS_REMOVEXATTR                  = 235
	SYS_LREMOVEXATTR                 = 236
	SYS_FREMOVEXATTR                 = 237
	SYS_TKILL                        = 238
	SYS_SENDFILE64                   = 239
	SYS_FUTEX                        = 240
	SYS_SCHED_SETAFFINITY            = 241
	SYS_SCHED_GETAFFINITY            = 242
	SYS_IO_SETUP                     = 243
	SYS_IO_DESTROY                   = 244
	SYS_IO_GETEVENTS                 = 245
	SYS_IO_SUBMIT                    = 246
	SYS_IO_CANCEL                    = 247
	SYS_EXIT_GROUP                   = 248
	SYS_LOOKUP_DCOOKIE               = 249
	SYS_EPOLL_CREATE                 = 250
	SYS_EPOLL_CTL                    = 251
	SYS_EPOLL_WAIT                   = 252
	SYS_REMAP_FILE_PAGES             = 253
	SYS_SET_TID_ADDRESS              = 256
	SYS_TIMER_CREATE                 = 257
	SYS_TIMER_SETTIME                = 258
	SYS_TIMER_GETTIME                = 259
	SYS_TIMER_GETOVERRUN             = 260
	SYS_TIMER_DELETE                 = 261
	SYS_CLOCK_SETTIME                = 262
	SYS_CLOCK_GETTIME                = 263
	SYS_CLOCK_GETRES                 = 264
	SYS_CLOCK_NANOSLEEP              = 265
	SYS_STATFS64                     = 266
	SYS_FSTATFS64                    = 267
	SYS_TGKILL                       = 268
	SYS_UTIMES                       = 269
	SYS_ARM_FADVISE64_64             = 270
	SYS_PCICONFIG_IOBASE             = 271
	SYS_PCICONFIG_READ               = 272
	SYS_PCICONFIG_WRITE              = 273
	SYS_MQ_OPEN                      = 274
	SYS_MQ_UNLINK                    = 275
	SYS_MQ_TIMEDSEND                 = 276
	SYS_MQ_TIMEDRECEIVE              = 277
	SYS_MQ_NOTIFY                    = 278
	SYS_MQ_GETSETATTR                = 279
	SYS_WAITID                       = 280
	SYS_SOCKET                       = 281
	SYS_BIND                         = 282
	SYS_CONNECT                      = 283
	SYS_LISTEN                       = 284
	SYS_ACCEPT                       = 285
	SYS_GETSOCKNAME                  = 286
	SYS_GETPEERNAME                  = 287
	SYS_SOCKETPAIR                   = 288
	SYS_SEND                         = 289
	SYS_SENDTO                       = 290
	SYS_RECV                         = 291
	SYS_RECVFROM                     = 292
	SYS_SHUTDOWN                     = 293
	SYS_SETSOCKOPT                   = 294
	SYS_GETSOCKOPT                   = 295
	SYS_SENDMSG                      = 296
	SYS_RECVMSG                      = 297
	SYS_SEMOP                        = 298
	SYS_SEMGET                       = 299
	SYS_SEMCTL                       = 300
	SYS_MSGSND                       = 301
	SYS_MSGRCV                       = 302
	SYS_MSGGET                       = 303
	SYS_MSGCTL                       = 304
	SYS_SHMAT                        = 305
	SYS_SHMDT                        = 306
	SYS_SHMGET                       = 307
	SYS_SHMCTL                       = 308
	SYS_ADD_KEY                      = 309
	SYS_REQUEST_KEY                  = 310
	SYS_KEYCTL                       = 311
	SYS_SEMTIMEDOP                   = 312
	SYS_VSERVER                      = 313
	SYS_IOPRIO_SET                   = 314
	SYS_IOPRIO_GET                   = 315
	SYS_INOTIFY_INIT                 = 316
	SYS_INOTIFY_ADD_WATCH            = 317
	SYS_INOTIFY_RM_WATCH             = 318
	SYS_MBIND                        = 319
	SYS_GET_MEMPOLICY                = 320
	SYS_SET_MEMPOLICY                = 321
	SYS_OPENAT                       = 322
	SYS_MKDIRAT                      = 323
	SYS_MKNODAT                      = 324
	SYS_FCHOWNAT                     = 325
	SYS_FUTIMESAT                    = 326
	SYS_FSTATAT64                    = 327
	SYS_UNLINKAT                     = 328
	SYS_RENAMEAT                     = 329
	SYS_LINKAT                       = 330
	SYS_SYMLINKAT                    = 331
	SYS_READLINKAT                   = 332
	SYS_FCHMODAT                     = 333
	SYS_FACCESSAT                    = 334
	SYS_PSELECT6                     = 335
	SYS_PPOLL                        = 336
	SYS_UNSHARE                      = 337
	SYS_SET_ROBUST_LIST              = 338
	SYS_GET_ROBUST_LIST              = 339
	SYS_SPLICE                       = 340
	SYS_ARM_SYNC_FILE_RANGE          = 341
	SYS_TEE                          = 342
	SYS_VMSPLICE                     = 343
	SYS_MOVE_PAGES                   = 344
	SYS_GETCPU                       = 345
	SYS_EPOLL_PWAIT                  = 346
	SYS_KEXEC_LOAD                   = 347
	SYS_UTIMENSAT                    = 348
	SYS_SIGNALFD                     = 349
	SYS_TIMERFD_CREATE               = 350
	SYS_EVENTFD                      = 351
	SYS_FALLOCATE                    = 352
	SYS_TIMERFD_SETTIME              = 353
	SYS_TIMERFD_GETTIME              = 354
	SYS_SIGNALFD4                    = 355
	SYS_EVENTFD2                     = 356
	SYS_EPOLL_CREATE1                = 357
	SYS_DUP3                         = 358
	SYS_PIPE2                        = 359
	SYS_INOTIFY_INIT1                = 360
	SYS_PREADV                       = 361
	SYS_PWRITEV                      = 362
	SYS_RT_TGSIGQUEUEINFO            = 363
	SYS_PERF_EVENT_OPEN              = 364
	SYS_RECVMMSG                     = 365
	SYS_ACCEPT4                      = 366
	SYS_FANOTIFY_INIT                = 367
	SYS_FANOTIFY_MARK                = 368
	SYS_PRLIMIT64                    = 369
	SYS_NAME_TO_HANDLE_AT            = 370
	SYS_OPEN_BY_HANDLE_AT            = 371
	SYS_CLOCK_ADJTIME                = 372
	SYS_SYNCFS                       = 373
	SYS_SENDMMSG                     = 374
	SYS_SETNS                        = 375
	SYS_PROCESS_VM_READV             = 376
	SYS_PROCESS_VM_WRITEV            = 377
	SYS_KCMP                         = 378
	SYS_FINIT_MODULE                 = 379
	SYS_SCHED_SETATTR                = 380
	SYS_SCHED_GETATTR                = 381
	SYS_RENAMEAT2                    = 382
	SYS_SECCOMP                      = 383
	SYS_GETRANDOM                    = 384
	SYS_MEMFD_CREATE                 = 385
	SYS_BPF                          = 386
	SYS_EXECVEAT                     = 387
	SYS_USERFAULTFD                  = 388
	SYS_MEMBARRIER                   = 389
	SYS_MLOCK2                       = 390
	SYS_COPY_FILE_RANGE              = 391
	SYS_PREADV2                      = 392
	SYS_PWRITEV2                     = 393
	SYS_PKEY_MPROTECT                = 394
	SYS_PKEY_ALLOC                   = 395
	SYS_PKEY_FREE                    = 396
	SYS_STATX                        = 397
	SYS_RSEQ                         = 398
	SYS_IO_PGETEVENTS                = 399
	SYS_MIGRATE_PAGES                = 400
	SYS_KEXEC_FILE_LOAD              = 401
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