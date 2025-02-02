Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Identify the Core Purpose:** The first and most important step is to recognize what this file is doing. The comments at the top are a huge clue: `"// go run linux/mksysnum.go ..."` and `"// Code generated by the command above; see README.md. DO NOT EDIT."`. This immediately suggests that the file is *generated* and contains system call numbers. The `//go:build s390x && linux` line confirms it's specific to the s390x architecture on Linux.

2. **Analyze the Content:**  The file consists of a `package unix` declaration followed by a `const` block. Inside the `const` block, we see a long list of identifiers like `SYS_EXIT`, `SYS_FORK`, `SYS_READ`, etc., each assigned an integer value. These identifiers look very much like system call names.

3. **Connect the Dots:**  The combination of the generated nature, the architecture/OS constraint, and the system call-like constants strongly points to the conclusion that this file defines system call numbers for the s390x architecture on Linux.

4. **Formulate the Functionality Description:** Based on the above analysis, we can state the core functionality:  This file defines constants representing the system call numbers for the Linux operating system on the s390x architecture. These constants are used by the `syscall` package (or similar low-level interaction libraries) to make system calls.

5. **Infer the Go Language Feature:**  The use of `const` to define these values clearly points to the use of **constants** in Go. These constants provide a symbolic representation of the underlying numerical system call codes.

6. **Construct a Code Example:** To illustrate how these constants are used, we need a scenario involving system calls. A simple example is making a `write` system call. This requires the `SYS_WRITE` constant, a file descriptor, a buffer, and a length. The `syscall` package provides the necessary tools.

    * **Identify the relevant `syscall` functions:**  Look for functions in the `syscall` package that correspond to the system calls listed in the file. `syscall.Syscall` is the generic way to make system calls.
    * **Determine the arguments:** Each system call has specific arguments. For `write`, it's file descriptor, pointer to data, and length.
    * **Construct the Go code:** Put together the necessary imports (`syscall`), the constant usage, and the `syscall.Syscall` invocation.

7. **Develop the Input and Output:** For the code example, provide clear inputs (the file descriptor, the message) and describe the expected output (the number of bytes written, or an error).

8. **Address Command-Line Arguments:**  The comment at the top contains the command used to generate the file. Analyze this command (`go run linux/mksysnum.go -Wall -Werror -static -I/tmp/s390x/include -fsigned-char /tmp/s390x/include/asm/unistd.h`).

    * **Identify the Go command:** `go run` means it's executing a Go program.
    * **Identify the generator script:** `linux/mksysnum.go` is the script responsible for generating the file.
    * **Analyze the flags:** Explain what each flag likely does (linting, error handling, static linking hint, include path, signed char).
    * **Identify the input file:** `/tmp/s390x/include/asm/unistd.h` is the likely source of the system call definitions.

9. **Consider Potential Pitfalls:** Think about how developers might misuse this file or the concepts it represents.

    * **Direct modification:**  The "DO NOT EDIT" comment is a strong hint. Modifying the file directly would be incorrect because it's generated.
    * **Incorrect architecture:** Using these constants on a non-s390x Linux system would lead to errors because the system call numbers might be different.

10. **Structure the Response:** Organize the information logically, covering functionality, Go feature, code example, command-line arguments, and potential errors. Use clear headings and formatting for readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file contains function implementations for system calls.
* **Correction:** The "generated" comment and the `const` keyword quickly disprove this. It's just *definitions* of the numbers.
* **Initial thought (for the code example):** I should use a more complex system call.
* **Correction:**  A simple `write` example is more illustrative and easier to understand for demonstrating the use of the constants.
* **Initial thought (for pitfalls):**  Maybe there are issues with data types.
* **Correction:**  While data types are important in system calls, the most obvious pitfall with this *specific* file is incorrect modification or using it on the wrong architecture.

By following this structured thought process, including analyzing comments, code structure, and the surrounding context, we can arrive at a comprehensive and accurate understanding of the provided Go code snippet.
这段Go语言代码文件 `go/src/cmd/vendor/golang.org/x/sys/unix/zsysnum_linux_s390x.go` 的主要功能是：

**定义了Linux操作系统在s390x架构下的系统调用号常量。**

更具体地说，它创建了一个Go包 `unix`，并在其中声明了一系列常量（以 `SYS_` 开头）。每个常量都代表一个特定的Linux系统调用，并赋予了该系统调用在s390x架构上的唯一数字标识符。

**功能拆解：**

1. **系统调用号映射:**  将人类可读的系统调用名称（例如 `EXIT`, `FORK`, `READ`）映射到内核理解的数字编号（例如 `1`, `2`, `3`）。这是操作系统编程的基础，因为用户空间程序需要通过这些数字来请求内核执行特定的操作。
2. **平台特定:**  文件名中的 `s390x` 表明这些常量是专门为IBM System z架构（s390x）上的Linux系统定义的。不同的架构可能有不同的系统调用号分配。
3. **自动化生成:** 文件开头的注释 `// go run linux/mksysnum.go ...` 表明这个文件是自动生成的，而不是手动编写的。`mksysnum.go` 脚本很可能读取了Linux内核头文件（如 `unistd.h`），并从中提取了系统调用号的定义，然后生成了这个Go代码文件。
4. **`go:build` 指令:**  `//go:build s390x && linux`  是一个构建约束，它告诉Go编译器只有在目标操作系统是Linux并且目标架构是s390x时才编译这个文件。这保证了平台特定代码的正确使用。

**它是什么Go语言功能的实现？**

这个文件主要使用了Go语言的以下功能：

* **常量声明 (`const`):**  用于定义不可更改的系统调用号。
* **包 (`package`):**  将相关的常量组织到 `unix` 包中，方便其他Go代码引用。
* **构建约束 (`//go:build`):**  实现平台特定的编译。

**Go代码示例说明:**

这个文件本身不包含可执行的代码逻辑，它只是定义常量。这些常量通常被 `syscall` 标准库包或者更底层的系统编程库使用。

假设我们想使用 `SYS_WRITE` 系统调用向文件描述符为 `1`（标准输出）写入一段文本。

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	message := "Hello, syscall!\n"
	fd := uintptr(1) // 标准输出的文件描述符
	buf := unsafe.Pointer(&[]byte(message)[0])
	n, _, err := syscall.Syscall(syscall.SYS_WRITE, fd, uintptr(buf), uintptr(len(message)))
	if err != 0 {
		fmt.Println("syscall write error:", err)
		return
	}
	fmt.Printf("Wrote %d bytes\n", n)
}
```

**假设的输入与输出:**

* **输入:**  无直接的用户输入，代码中硬编码了要写入的消息 "Hello, syscall!\n"。
* **输出:**
   ```
   Hello, syscall!
   Wrote 16 bytes
   ```

**代码推理:**

* `syscall.Syscall` 函数是Go语言中执行系统调用的底层机制。
* 第一个参数是系统调用号，我们使用了 `syscall.SYS_WRITE`，它对应着文件中定义的常量 `SYS_WRITE = 4`。
* 第二个参数是要写入的文件描述符，这里是标准输出 `1`。
* 第三个参数是要写入数据的内存地址，我们通过 `unsafe.Pointer` 获取了字符串 "Hello, syscall!\n" 的底层字节数组的地址。
* 第四个参数是要写入的字节数，即字符串的长度。
* `syscall.Syscall` 返回三个值：
    * `n`:  实际写入的字节数。
    * `_`:  一些系统调用会返回第二个结果，这里我们忽略它。
    * `err`:  如果系统调用发生错误，则返回错误信息，否则为 `0`。

**命令行参数的具体处理:**

这段代码本身不是一个可执行程序，而是一个包含常量的文件。其生成过程依赖于 `go run linux/mksysnum.go ...` 命令。

`go run linux/mksysnum.go` 表示执行 `linux/mksysnum.go` 这个Go程序。后面的参数是传递给 `mksysnum.go` 程序的：

* `-Wall`:  启用所有警告。
* `-Werror`: 将警告视为错误，一旦有警告就停止编译。
* `-static`:  可能指示生成静态链接相关的代码或定义（在这个上下文中可能影响系统调用号的生成方式）。
* `-I/tmp/s390x/include`:  指定头文件搜索路径，`mksysnum.go` 会在这个路径下查找 Linux 内核的头文件。
* `-fsigned-char`:  指定 `char` 类型默认为有符号类型。
* `/tmp/s390x/include/asm/unistd.h`:  指定要解析的 Linux 内核头文件，这个文件通常包含了系统调用的定义。

总的来说，这些命令行参数控制了 `mksysnum.go` 程序的行为，使其能够正确地解析特定架构的内核头文件，并生成对应的Go系统调用号常量文件。

**使用者易犯错的点:**

1. **直接修改此文件:** 由于这个文件是自动生成的，开发者不应该手动修改它。任何手动修改都会在下次重新生成时被覆盖。如果需要添加或修改系统调用号，应该修改生成脚本 `mksysnum.go` 或者修改内核头文件。
2. **在错误的架构或操作系统上使用:** 这些常量是特定于 Linux 和 s390x 架构的。在其他操作系统或架构上使用这些常量会导致程序行为不正确，甚至崩溃。Go 的构建约束 `//go:build s390x && linux`  在编译时会防止这种情况发生，但如果开发者绕过构建系统或者在非Go环境中使用这些常量，就会出错。 例如，尝试在 x86_64 的 Linux 系统上运行使用了 `syscall.SYS_WRITE` 的代码，虽然常量名相同，但实际对应的系统调用号可能一致，但最好不要依赖这种巧合。在其他操作系统上，系统调用号肯定不同。

例如，如果在 x86_64 Linux 系统上执行上面提供的 Go 代码示例，虽然 `syscall.SYS_WRITE` 对应的数值很可能也是 1，但这是巧合，不应依赖。如果使用了其他系统调用，很可能就会出错。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/zsysnum_linux_s390x.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// go run linux/mksysnum.go -Wall -Werror -static -I/tmp/s390x/include -fsigned-char /tmp/s390x/include/asm/unistd.h
// Code generated by the command above; see README.md. DO NOT EDIT.

//go:build s390x && linux

package unix

const (
	SYS_EXIT                    = 1
	SYS_FORK                    = 2
	SYS_READ                    = 3
	SYS_WRITE                   = 4
	SYS_OPEN                    = 5
	SYS_CLOSE                   = 6
	SYS_RESTART_SYSCALL         = 7
	SYS_CREAT                   = 8
	SYS_LINK                    = 9
	SYS_UNLINK                  = 10
	SYS_EXECVE                  = 11
	SYS_CHDIR                   = 12
	SYS_MKNOD                   = 14
	SYS_CHMOD                   = 15
	SYS_LSEEK                   = 19
	SYS_GETPID                  = 20
	SYS_MOUNT                   = 21
	SYS_UMOUNT                  = 22
	SYS_PTRACE                  = 26
	SYS_ALARM                   = 27
	SYS_PAUSE                   = 29
	SYS_UTIME                   = 30
	SYS_ACCESS                  = 33
	SYS_NICE                    = 34
	SYS_SYNC                    = 36
	SYS_KILL                    = 37
	SYS_RENAME                  = 38
	SYS_MKDIR                   = 39
	SYS_RMDIR                   = 40
	SYS_DUP                     = 41
	SYS_PIPE                    = 42
	SYS_TIMES                   = 43
	SYS_BRK                     = 45
	SYS_SIGNAL                  = 48
	SYS_ACCT                    = 51
	SYS_UMOUNT2                 = 52
	SYS_IOCTL                   = 54
	SYS_FCNTL                   = 55
	SYS_SETPGID                 = 57
	SYS_UMASK                   = 60
	SYS_CHROOT                  = 61
	SYS_USTAT                   = 62
	SYS_DUP2                    = 63
	SYS_GETPPID                 = 64
	SYS_GETPGRP                 = 65
	SYS_SETSID                  = 66
	SYS_SIGACTION               = 67
	SYS_SIGSUSPEND              = 72
	SYS_SIGPENDING              = 73
	SYS_SETHOSTNAME             = 74
	SYS_SETRLIMIT               = 75
	SYS_GETRUSAGE               = 77
	SYS_GETTIMEOFDAY            = 78
	SYS_SETTIMEOFDAY            = 79
	SYS_SYMLINK                 = 83
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
	SYS_GETPRIORITY             = 96
	SYS_SETPRIORITY             = 97
	SYS_STATFS                  = 99
	SYS_FSTATFS                 = 100
	SYS_SOCKETCALL              = 102
	SYS_SYSLOG                  = 103
	SYS_SETITIMER               = 104
	SYS_GETITIMER               = 105
	SYS_STAT                    = 106
	SYS_LSTAT                   = 107
	SYS_FSTAT                   = 108
	SYS_LOOKUP_DCOOKIE          = 110
	SYS_VHANGUP                 = 111
	SYS_IDLE                    = 112
	SYS_WAIT4                   = 114
	SYS_SWAPOFF                 = 115
	SYS_SYSINFO                 = 116
	SYS_IPC                     = 117
	SYS_FSYNC                   = 118
	SYS_SIGRETURN               = 119
	SYS_CLONE                   = 120
	SYS_SETDOMAINNAME           = 121
	SYS_UNAME                   = 122
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
	SYS_GETDENTS                = 141
	SYS_SELECT                  = 142
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
	SYS_QUERY_MODULE            = 167
	SYS_POLL                    = 168
	SYS_NFSSERVCTL              = 169
	SYS_PRCTL                   = 172
	SYS_RT_SIGRETURN            = 173
	SYS_RT_SIGACTION            = 174
	SYS_RT_SIGPROCMASK          = 175
	SYS_RT_SIGPENDING           = 176
	SYS_RT_SIGTIMEDWAIT         = 177
	SYS_RT_SIGQUEUEINFO         = 178
	SYS_RT_SIGSUSPEND           = 179
	SYS_PREAD64                 = 180
	SYS_PWRITE64                = 181
	SYS_GETCWD                  = 183
	SYS_CAPGET                  = 184
	SYS_CAPSET                  = 185
	SYS_SIGALTSTACK             = 186
	SYS_SENDFILE                = 187
	SYS_GETPMSG                 = 188
	SYS_PUTPMSG                 = 189
	SYS_VFORK                   = 190
	SYS_GETRLIMIT               = 191
	SYS_LCHOWN                  = 198
	SYS_GETUID                  = 199
	SYS_GETGID                  = 200
	SYS_GETEUID                 = 201
	SYS_GETEGID                 = 202
	SYS_SETREUID                = 203
	SYS_SETREGID                = 204
	SYS_GETGROUPS               = 205
	SYS_SETGROUPS               = 206
	SYS_FCHOWN                  = 207
	SYS_SETRESUID               = 208
	SYS_GETRESUID               = 209
	SYS_SETRESGID               = 210
	SYS_GETRESGID               = 211
	SYS_CHOWN                   = 212
	SYS_SETUID                  = 213
	SYS_SETGID                  = 214
	SYS_SETFSUID                = 215
	SYS_SETFSGID                = 216
	SYS_PIVOT_ROOT              = 217
	SYS_MINCORE                 = 218
	SYS_MADVISE                 = 219
	SYS_GETDENTS64              = 220
	SYS_READAHEAD               = 222
	SYS_SETXATTR                = 224
	SYS_LSETXATTR               = 225
	SYS_FSETXATTR               = 226
	SYS_GETXATTR                = 227
	SYS_LGETXATTR               = 228
	SYS_FGETXATTR               = 229
	SYS_LISTXATTR               = 230
	SYS_LLISTXATTR              = 231
	SYS_FLISTXATTR              = 232
	SYS_REMOVEXATTR             = 233
	SYS_LREMOVEXATTR            = 234
	SYS_FREMOVEXATTR            = 235
	SYS_GETTID                  = 236
	SYS_TKILL                   = 237
	SYS_FUTEX                   = 238
	SYS_SCHED_SETAFFINITY       = 239
	SYS_SCHED_GETAFFINITY       = 240
	SYS_TGKILL                  = 241
	SYS_IO_SETUP                = 243
	SYS_IO_DESTROY              = 244
	SYS_IO_GETEVENTS            = 245
	SYS_IO_SUBMIT               = 246
	SYS_IO_CANCEL               = 247
	SYS_EXIT_GROUP              = 248
	SYS_EPOLL_CREATE            = 249
	SYS_EPOLL_CTL               = 250
	SYS_EPOLL_WAIT              = 251
	SYS_SET_TID_ADDRESS         = 252
	SYS_FADVISE64               = 253
	SYS_TIMER_CREATE            = 254
	SYS_TIMER_SETTIME           = 255
	SYS_TIMER_GETTIME           = 256
	SYS_TIMER_GETOVERRUN        = 257
	SYS_TIMER_DELETE            = 258
	SYS_CLOCK_SETTIME           = 259
	SYS_CLOCK_GETTIME           = 260
	SYS_CLOCK_GETRES            = 261
	SYS_CLOCK_NANOSLEEP         = 262
	SYS_STATFS64                = 265
	SYS_FSTATFS64               = 266
	SYS_REMAP_FILE_PAGES        = 267
	SYS_MBIND                   = 268
	SYS_GET_MEMPOLICY           = 269
	SYS_SET_MEMPOLICY           = 270
	SYS_MQ_OPEN                 = 271
	SYS_MQ_UNLINK               = 272
	SYS_MQ_TIMEDSEND            = 273
	SYS_MQ_TIMEDRECEIVE         = 274
	SYS_MQ_NOTIFY               = 275
	SYS_MQ_GETSETATTR           = 276
	SYS_KEXEC_LOAD              = 277
	SYS_ADD_KEY                 = 278
	SYS_REQUEST_KEY             = 279
	SYS_KEYCTL                  = 280
	SYS_WAITID                  = 281
	SYS_IOPRIO_SET              = 282
	SYS_IOPRIO_GET              = 283
	SYS_INOTIFY_INIT            = 284
	SYS_INOTIFY_ADD_WATCH       = 285
	SYS_INOTIFY_RM_WATCH        = 286
	SYS_MIGRATE_PAGES           = 287
	SYS_OPENAT                  = 288
	SYS_MKDIRAT                 = 289
	SYS_MKNODAT                 = 290
	SYS_FCHOWNAT                = 291
	SYS_FUTIMESAT               = 292
	SYS_NEWFSTATAT              = 293
	SYS_UNLINKAT                = 294
	SYS_RENAMEAT                = 295
	SYS_LINKAT                  = 296
	SYS_SYMLINKAT               = 297
	SYS_READLINKAT              = 298
	SYS_FCHMODAT                = 299
	SYS_FACCESSAT               = 300
	SYS_PSELECT6                = 301
	SYS_PPOLL                   = 302
	SYS_UNSHARE                 = 303
	SYS_SET_ROBUST_LIST         = 304
	SYS_GET_ROBUST_LIST         = 305
	SYS_SPLICE                  = 306
	SYS_SYNC_FILE_RANGE         = 307
	SYS_TEE                     = 308
	SYS_VMSPLICE                = 309
	SYS_MOVE_PAGES              = 310
	SYS_GETCPU                  = 311
	SYS_EPOLL_PWAIT             = 312
	SYS_UTIMES                  = 313
	SYS_FALLOCATE               = 314
	SYS_UTIMENSAT               = 315
	SYS_SIGNALFD                = 316
	SYS_TIMERFD                 = 317
	SYS_EVENTFD                 = 318
	SYS_TIMERFD_CREATE          = 319
	SYS_TIMERFD_SETTIME         = 320
	SYS_TIMERFD_GETTIME         = 321
	SYS_SIGNALFD4               = 322
	SYS_EVENTFD2                = 323
	SYS_INOTIFY_INIT1           = 324
	SYS_PIPE2                   = 325
	SYS_DUP3                    = 326
	SYS_EPOLL_CREATE1           = 327
	SYS_PREADV                  = 328
	SYS_PWRITEV                 = 329
	SYS_RT_TGSIGQUEUEINFO       = 330
	SYS_PERF_EVENT_OPEN         = 331
	SYS_FANOTIFY_INIT           = 332
	SYS_FANOTIFY_MARK           = 333
	SYS_PRLIMIT64               = 334
	SYS_NAME_TO_HANDLE_AT       = 335
	SYS_OPEN_BY_HANDLE_AT       = 336
	SYS_CLOCK_ADJTIME           = 337
	SYS_SYNCFS                  = 338
	SYS_SETNS                   = 339
	SYS_PROCESS_VM_READV        = 340
	SYS_PROCESS_VM_WRITEV       = 341
	SYS_S390_RUNTIME_INSTR      = 342
	SYS_KCMP                    = 343
	SYS_FINIT_MODULE            = 344
	SYS_SCHED_SETATTR           = 345
	SYS_SCHED_GETATTR           = 346
	SYS_RENAMEAT2               = 347
	SYS_SECCOMP                 = 348
	SYS_GETRANDOM               = 349
	SYS_MEMFD_CREATE            = 350
	SYS_BPF                     = 351
	SYS_S390_PCI_MMIO_WRITE     = 352
	SYS_S390_PCI_MMIO_READ      = 353
	SYS_EXECVEAT                = 354
	SYS_USERFAULTFD             = 355
	SYS_MEMBARRIER              = 356
	SYS_RECVMMSG                = 357
	SYS_SENDMMSG                = 358
	SYS_SOCKET                  = 359
	SYS_SOCKETPAIR              = 360
	SYS_BIND                    = 361
	SYS_CONNECT                 = 362
	SYS_LISTEN                  = 363
	SYS_ACCEPT4                 = 364
	SYS_GETSOCKOPT              = 365
	SYS_SETSOCKOPT              = 366
	SYS_GETSOCKNAME             = 367
	SYS_GETPEERNAME             = 368
	SYS_SENDTO                  = 369
	SYS_SENDMSG                 = 370
	SYS_RECVFROM                = 371
	SYS_RECVMSG                 = 372
	SYS_SHUTDOWN                = 373
	SYS_MLOCK2                  = 374
	SYS_COPY_FILE_RANGE         = 375
	SYS_PREADV2                 = 376
	SYS_PWRITEV2                = 377
	SYS_S390_GUARDED_STORAGE    = 378
	SYS_STATX                   = 379
	SYS_S390_STHYI              = 380
	SYS_KEXEC_FILE_LOAD         = 381
	SYS_IO_PGETEVENTS           = 382
	SYS_RSEQ                    = 383
	SYS_PKEY_MPROTECT           = 384
	SYS_PKEY_ALLOC              = 385
	SYS_PKEY_FREE               = 386
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
	SYS_MEMFD_SECRET            = 447
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