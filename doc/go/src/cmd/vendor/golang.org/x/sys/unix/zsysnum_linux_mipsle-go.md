Response:
Let's break down the thought process for answering the request about `zsysnum_linux_mipsle.go`.

**1. Understanding the File's Purpose:**

The very first lines of the file are crucial:

```go
// go run linux/mksysnum.go -Wall -Werror -static -I/tmp/mipsle/include /tmp/mipsle/include/asm/unistd.h
// Code generated by the command above; see README.md. DO NOT EDIT.

//go:build mipsle && linux
```

This tells us several important things:

* **Code Generation:** The file is *generated* by the `linux/mksysnum.go` tool. This means we're looking at the *output* of a process, not hand-written code in the traditional sense.
* **Syscall Numbers:** The presence of `-I/tmp/mipsle/include /tmp/mipsle/include/asm/unistd.h` strongly suggests that this file maps Go constants to system call numbers defined in the C header file `unistd.h`.
* **Target Architecture:** The `//go:build mipsle && linux` line confirms this file is specifically for the `mipsle` (MIPS little-endian) architecture on Linux.
* **Don't Edit:** The "DO NOT EDIT" warning reinforces that this is generated and manual changes will be overwritten.

**2. Identifying the Core Functionality:**

Scanning the rest of the file reveals a series of Go constants defined:

```go
const (
	SYS_SYSCALL                      = 4000
	SYS_EXIT                         = 4001
	SYS_FORK                         = 4002
	// ... and so on
)
```

The pattern is clear: each constant `SYS_...` represents a Linux system call, and the associated number is the system call number for the `mipsle` architecture.

**3. Answering the "Functionality" Question:**

Based on the analysis so far, the primary function is clear:

* **Mapping System Calls:** It provides a mapping between symbolic names for Linux system calls (like `SYS_EXIT`, `SYS_READ`) and their corresponding numerical identifiers (like `4001`, `4003`) on the `mipsle` Linux architecture. This is essential for the Go runtime to make system calls.

**4. Inferring the Go Language Feature:**

The question asks what Go language feature this implements. The constants themselves aren't a specific "feature."  However, their purpose is to *enable* the `syscall` package. The `syscall` package in Go allows programs to directly interact with the operating system's kernel by invoking system calls. This file provides the necessary numerical mappings for that interaction to happen correctly on the target architecture.

**5. Providing a Go Code Example:**

To illustrate the connection to the `syscall` package, a simple example of making a system call is needed. The `syscall.Syscall()` function is the core mechanism. We need to show how one of the constants from the file would be used:

```go
package main

import (
	"fmt"
	"syscall"
)

func main() {
	// Using the SYS_GETPID constant defined in zsysnum_linux_mipsle.go
	pid, _, err := syscall.Syscall(syscall.SYS_GETPID, 0, 0, 0)
	if err != 0 {
		fmt.Println("Error getting PID:", err)
		return
	}
	fmt.Println("Process ID:", pid)
}
```

* **Input/Output (Implicit):**  The input is the `syscall.SYS_GETPID` constant. The output (if successful) is the process ID printed to the console.

**6. Addressing Command-Line Arguments:**

The initial comment in the file shows the command used to generate it:

```
// go run linux/mksysnum.go -Wall -Werror -static -I/tmp/mipsle/include /tmp/mipsle/include/asm/unistd.h
```

We need to explain what these arguments mean in the context of generating this file:

* `go run linux/mksysnum.go`: Executes the Go program `mksysnum.go`.
* `-Wall -Werror`:  Compiler flags for `mksysnum.go`, likely to enforce good coding practices.
* `-static`:  Likely a flag specific to `mksysnum.go` for how it generates the output.
* `-I/tmp/mipsle/include`: Tells the compiler (used by `mksysnum.go` to parse headers) where to find include files.
* `/tmp/mipsle/include/asm/unistd.h`: The specific header file containing the system call definitions for the target architecture.

**7. Identifying Potential Errors:**

The key error a user might make is *manually editing* this file. The "DO NOT EDIT" comment is crucial. Explain why this is wrong (changes will be overwritten).

**8. Structuring the Answer:**

Finally, organize the information logically according to the prompts in the original request:

* Functionality
* Go Language Feature
* Go Code Example (with Input/Output)
* Command-Line Arguments
* Common Mistakes

This structured approach ensures all aspects of the request are addressed clearly and comprehensively.
这个 `go/src/cmd/vendor/golang.org/x/sys/unix/zsysnum_linux_mipsle.go` 文件是 Go 语言标准库中 `syscall` 包的一部分，专门为 Linux 操作系统上的 MIPS 小端（mipsle）架构定义了系统调用号。

**它的主要功能是:**

1. **定义系统调用常量:** 它定义了一系列 Go 语言常量，每个常量都对应一个 Linux 系统调用，并赋予了该系统调用在 MIPS 小端架构上的编号。例如，`SYS_EXIT` 常量被定义为 `4001`，这意味着在 MIPS 小端 Linux 上调用 `exit()` 系统调用时，需要使用编号 `4001`。

2. **为 `syscall` 包提供架构特定的系统调用映射:**  Go 的 `syscall` 包提供了一种与操作系统内核进行交互的方式，允许 Go 程序直接调用系统调用。这个文件为 `syscall` 包提供了在 MIPS 小端 Linux 上正确调用系统调用所需的数字映射。

**它是什么 Go 语言功能的实现:**

这个文件是 Go 语言 `syscall` 包实现的一部分。`syscall` 包允许 Go 程序直接调用底层的操作系统系统调用。为了实现跨平台兼容性，`syscall` 包需要为不同的操作系统和架构提供不同的系统调用号映射。`zsysnum_linux_mipsle.go` 就是针对 Linux 和 MIPS 小端架构的特定实现。

**Go 代码示例:**

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	// 调用 exit 系统调用，参数为 0 (表示正常退出)
	_, _, err := syscall.Syscall(syscall.SYS_EXIT, 0, 0, 0)
	if err != 0 {
		fmt.Println("Error calling exit:", err)
	}
	// 注意：如果 syscall.Syscall 成功执行了 exit，则后面的代码不会被执行。
	fmt.Println("This should not be printed if exit was successful.")
}
```

**代码推理（假设）：**

* **假设输入：** 上述 Go 代码在 MIPS 小端 Linux 系统上运行。
* **推理过程：**
    1. `syscall.SYS_EXIT` 在 `zsysnum_linux_mipsle.go` 中被定义为 `4001`。
    2. `syscall.Syscall(syscall.SYS_EXIT, 0, 0, 0)` 会发起一个系统调用，其系统调用号为 `4001`，对应于 Linux 的 `exit()` 系统调用。
    3. 传递给 `exit()` 的参数为 `0`，表示程序正常退出。
* **预期输出：** 程序正常退出，不会打印 "This should not be printed if exit was successful."。如果系统调用失败（通常不会发生在这种简单的例子中），可能会打印 "Error calling exit: ..."。

**命令行参数的具体处理:**

文件开头的注释提供了生成此文件的命令：

```
// go run linux/mksysnum.go -Wall -Werror -static -I/tmp/mipsle/include /tmp/mipsle/include/asm/unistd.h
```

这个命令使用了 `go run` 来执行 `linux/mksysnum.go` 这个 Go 程序。该程序负责读取系统头文件（通常是 `unistd.h`），解析其中的系统调用定义，并生成 `zsysnum_linux_mipsle.go` 文件。

* **`linux/mksysnum.go`:**  这是生成系统调用号映射文件的 Go 程序。
* **`-Wall -Werror`:** 这些是 Go 编译器的标志，用于启用所有警告并将警告视为错误，有助于确保生成的代码质量。
* **`-static`:**  这个标志的具体含义可能取决于 `mksysnum.go` 程序的实现。通常，`static` 可能意味着生成静态的常量定义。
* **`-I/tmp/mipsle/include`:** 这个标志告诉 `mksysnum.go` 程序在哪里查找头文件。在这里，它指定了 `/tmp/mipsle/include` 目录作为头文件搜索路径。这表明在生成此文件时，使用了针对 MIPS 小端架构的特定头文件。
* **`/tmp/mipsle/include/asm/unistd.h`:** 这是实际包含 MIPS 小端 Linux 系统调用定义的头文件。`mksysnum.go` 程序会解析这个文件来提取系统调用号和名称。

**使用者易犯错的点:**

最容易犯的错误是 **手动修改此文件**。

* **原因:**  此文件是通过脚本自动生成的，任何手动修改都会在下次运行生成脚本时被覆盖。
* **后果:**  如果手动修改了系统调用号，可能会导致程序在运行时调用错误的系统调用，产生不可预测的行为，甚至导致程序崩溃或系统不稳定。

**示例:**

假设开发者错误地将 `SYS_EXIT` 的值从 `4001` 修改为 `9999`，并重新编译了程序。当程序尝试调用 `syscall.Syscall(syscall.SYS_EXIT, 0, 0, 0)` 时，实际上会调用系统调用号为 `9999` 的系统调用（如果存在），而不是预期的 `exit` 系统调用，导致程序行为异常。

**总结:**

`go/src/cmd/vendor/golang.org/x/sys/unix/zsysnum_linux_mipsle.go` 文件是 Go 语言 `syscall` 包中至关重要的一部分，它定义了 Linux MIPS 小端架构下的系统调用号，使得 Go 程序能够在该平台上正确地与操作系统内核进行交互。 开发者应该理解此文件的作用，并避免手动修改它。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/zsysnum_linux_mipsle.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// go run linux/mksysnum.go -Wall -Werror -static -I/tmp/mipsle/include /tmp/mipsle/include/asm/unistd.h
// Code generated by the command above; see README.md. DO NOT EDIT.

//go:build mipsle && linux

package unix

const (
	SYS_SYSCALL                      = 4000
	SYS_EXIT                         = 4001
	SYS_FORK                         = 4002
	SYS_READ                         = 4003
	SYS_WRITE                        = 4004
	SYS_OPEN                         = 4005
	SYS_CLOSE                        = 4006
	SYS_WAITPID                      = 4007
	SYS_CREAT                        = 4008
	SYS_LINK                         = 4009
	SYS_UNLINK                       = 4010
	SYS_EXECVE                       = 4011
	SYS_CHDIR                        = 4012
	SYS_TIME                         = 4013
	SYS_MKNOD                        = 4014
	SYS_CHMOD                        = 4015
	SYS_LCHOWN                       = 4016
	SYS_BREAK                        = 4017
	SYS_UNUSED18                     = 4018
	SYS_LSEEK                        = 4019
	SYS_GETPID                       = 4020
	SYS_MOUNT                        = 4021
	SYS_UMOUNT                       = 4022
	SYS_SETUID                       = 4023
	SYS_GETUID                       = 4024
	SYS_STIME                        = 4025
	SYS_PTRACE                       = 4026
	SYS_ALARM                        = 4027
	SYS_UNUSED28                     = 4028
	SYS_PAUSE                        = 4029
	SYS_UTIME                        = 4030
	SYS_STTY                         = 4031
	SYS_GTTY                         = 4032
	SYS_ACCESS                       = 4033
	SYS_NICE                         = 4034
	SYS_FTIME                        = 4035
	SYS_SYNC                         = 4036
	SYS_KILL                         = 4037
	SYS_RENAME                       = 4038
	SYS_MKDIR                        = 4039
	SYS_RMDIR                        = 4040
	SYS_DUP                          = 4041
	SYS_PIPE                         = 4042
	SYS_TIMES                        = 4043
	SYS_PROF                         = 4044
	SYS_BRK                          = 4045
	SYS_SETGID                       = 4046
	SYS_GETGID                       = 4047
	SYS_SIGNAL                       = 4048
	SYS_GETEUID                      = 4049
	SYS_GETEGID                      = 4050
	SYS_ACCT                         = 4051
	SYS_UMOUNT2                      = 4052
	SYS_LOCK                         = 4053
	SYS_IOCTL                        = 4054
	SYS_FCNTL                        = 4055
	SYS_MPX                          = 4056
	SYS_SETPGID                      = 4057
	SYS_ULIMIT                       = 4058
	SYS_UNUSED59                     = 4059
	SYS_UMASK                        = 4060
	SYS_CHROOT                       = 4061
	SYS_USTAT                        = 4062
	SYS_DUP2                         = 4063
	SYS_GETPPID                      = 4064
	SYS_GETPGRP                      = 4065
	SYS_SETSID                       = 4066
	SYS_SIGACTION                    = 4067
	SYS_SGETMASK                     = 4068
	SYS_SSETMASK                     = 4069
	SYS_SETREUID                     = 4070
	SYS_SETREGID                     = 4071
	SYS_SIGSUSPEND                   = 4072
	SYS_SIGPENDING                   = 4073
	SYS_SETHOSTNAME                  = 4074
	SYS_SETRLIMIT                    = 4075
	SYS_GETRLIMIT                    = 4076
	SYS_GETRUSAGE                    = 4077
	SYS_GETTIMEOFDAY                 = 4078
	SYS_SETTIMEOFDAY                 = 4079
	SYS_GETGROUPS                    = 4080
	SYS_SETGROUPS                    = 4081
	SYS_RESERVED82                   = 4082
	SYS_SYMLINK                      = 4083
	SYS_UNUSED84                     = 4084
	SYS_READLINK                     = 4085
	SYS_USELIB                       = 4086
	SYS_SWAPON                       = 4087
	SYS_REBOOT                       = 4088
	SYS_READDIR                      = 4089
	SYS_MMAP                         = 4090
	SYS_MUNMAP                       = 4091
	SYS_TRUNCATE                     = 4092
	SYS_FTRUNCATE                    = 4093
	SYS_FCHMOD                       = 4094
	SYS_FCHOWN                       = 4095
	SYS_GETPRIORITY                  = 4096
	SYS_SETPRIORITY                  = 4097
	SYS_PROFIL                       = 4098
	SYS_STATFS                       = 4099
	SYS_FSTATFS                      = 4100
	SYS_IOPERM                       = 4101
	SYS_SOCKETCALL                   = 4102
	SYS_SYSLOG                       = 4103
	SYS_SETITIMER                    = 4104
	SYS_GETITIMER                    = 4105
	SYS_STAT                         = 4106
	SYS_LSTAT                        = 4107
	SYS_FSTAT                        = 4108
	SYS_UNUSED109                    = 4109
	SYS_IOPL                         = 4110
	SYS_VHANGUP                      = 4111
	SYS_IDLE                         = 4112
	SYS_VM86                         = 4113
	SYS_WAIT4                        = 4114
	SYS_SWAPOFF                      = 4115
	SYS_SYSINFO                      = 4116
	SYS_IPC                          = 4117
	SYS_FSYNC                        = 4118
	SYS_SIGRETURN                    = 4119
	SYS_CLONE                        = 4120
	SYS_SETDOMAINNAME                = 4121
	SYS_UNAME                        = 4122
	SYS_MODIFY_LDT                   = 4123
	SYS_ADJTIMEX                     = 4124
	SYS_MPROTECT                     = 4125
	SYS_SIGPROCMASK                  = 4126
	SYS_CREATE_MODULE                = 4127
	SYS_INIT_MODULE                  = 4128
	SYS_DELETE_MODULE                = 4129
	SYS_GET_KERNEL_SYMS              = 4130
	SYS_QUOTACTL                     = 4131
	SYS_GETPGID                      = 4132
	SYS_FCHDIR                       = 4133
	SYS_BDFLUSH                      = 4134
	SYS_SYSFS                        = 4135
	SYS_PERSONALITY                  = 4136
	SYS_AFS_SYSCALL                  = 4137
	SYS_SETFSUID                     = 4138
	SYS_SETFSGID                     = 4139
	SYS__LLSEEK                      = 4140
	SYS_GETDENTS                     = 4141
	SYS__NEWSELECT                   = 4142
	SYS_FLOCK                        = 4143
	SYS_MSYNC                        = 4144
	SYS_READV                        = 4145
	SYS_WRITEV                       = 4146
	SYS_CACHEFLUSH                   = 4147
	SYS_CACHECTL                     = 4148
	SYS_SYSMIPS                      = 4149
	SYS_UNUSED150                    = 4150
	SYS_GETSID                       = 4151
	SYS_FDATASYNC                    = 4152
	SYS__SYSCTL                      = 4153
	SYS_MLOCK                        = 4154
	SYS_MUNLOCK                      = 4155
	SYS_MLOCKALL                     = 4156
	SYS_MUNLOCKALL                   = 4157
	SYS_SCHED_SETPARAM               = 4158
	SYS_SCHED_GETPARAM               = 4159
	SYS_SCHED_SETSCHEDULER           = 4160
	SYS_SCHED_GETSCHEDULER           = 4161
	SYS_SCHED_YIELD                  = 4162
	SYS_SCHED_GET_PRIORITY_MAX       = 4163
	SYS_SCHED_GET_PRIORITY_MIN       = 4164
	SYS_SCHED_RR_GET_INTERVAL        = 4165
	SYS_NANOSLEEP                    = 4166
	SYS_MREMAP                       = 4167
	SYS_ACCEPT                       = 4168
	SYS_BIND                         = 4169
	SYS_CONNECT                      = 4170
	SYS_GETPEERNAME                  = 4171
	SYS_GETSOCKNAME                  = 4172
	SYS_GETSOCKOPT                   = 4173
	SYS_LISTEN                       = 4174
	SYS_RECV                         = 4175
	SYS_RECVFROM                     = 4176
	SYS_RECVMSG                      = 4177
	SYS_SEND                         = 4178
	SYS_SENDMSG                      = 4179
	SYS_SENDTO                       = 4180
	SYS_SETSOCKOPT                   = 4181
	SYS_SHUTDOWN                     = 4182
	SYS_SOCKET                       = 4183
	SYS_SOCKETPAIR                   = 4184
	SYS_SETRESUID                    = 4185
	SYS_GETRESUID                    = 4186
	SYS_QUERY_MODULE                 = 4187
	SYS_POLL                         = 4188
	SYS_NFSSERVCTL                   = 4189
	SYS_SETRESGID                    = 4190
	SYS_GETRESGID                    = 4191
	SYS_PRCTL                        = 4192
	SYS_RT_SIGRETURN                 = 4193
	SYS_RT_SIGACTION                 = 4194
	SYS_RT_SIGPROCMASK               = 4195
	SYS_RT_SIGPENDING                = 4196
	SYS_RT_SIGTIMEDWAIT              = 4197
	SYS_RT_SIGQUEUEINFO              = 4198
	SYS_RT_SIGSUSPEND                = 4199
	SYS_PREAD64                      = 4200
	SYS_PWRITE64                     = 4201
	SYS_CHOWN                        = 4202
	SYS_GETCWD                       = 4203
	SYS_CAPGET                       = 4204
	SYS_CAPSET                       = 4205
	SYS_SIGALTSTACK                  = 4206
	SYS_SENDFILE                     = 4207
	SYS_GETPMSG                      = 4208
	SYS_PUTPMSG                      = 4209
	SYS_MMAP2                        = 4210
	SYS_TRUNCATE64                   = 4211
	SYS_FTRUNCATE64                  = 4212
	SYS_STAT64                       = 4213
	SYS_LSTAT64                      = 4214
	SYS_FSTAT64                      = 4215
	SYS_PIVOT_ROOT                   = 4216
	SYS_MINCORE                      = 4217
	SYS_MADVISE                      = 4218
	SYS_GETDENTS64                   = 4219
	SYS_FCNTL64                      = 4220
	SYS_RESERVED221                  = 4221
	SYS_GETTID                       = 4222
	SYS_READAHEAD                    = 4223
	SYS_SETXATTR                     = 4224
	SYS_LSETXATTR                    = 4225
	SYS_FSETXATTR                    = 4226
	SYS_GETXATTR                     = 4227
	SYS_LGETXATTR                    = 4228
	SYS_FGETXATTR                    = 4229
	SYS_LISTXATTR                    = 4230
	SYS_LLISTXATTR                   = 4231
	SYS_FLISTXATTR                   = 4232
	SYS_REMOVEXATTR                  = 4233
	SYS_LREMOVEXATTR                 = 4234
	SYS_FREMOVEXATTR                 = 4235
	SYS_TKILL                        = 4236
	SYS_SENDFILE64                   = 4237
	SYS_FUTEX                        = 4238
	SYS_SCHED_SETAFFINITY            = 4239
	SYS_SCHED_GETAFFINITY            = 4240
	SYS_IO_SETUP                     = 4241
	SYS_IO_DESTROY                   = 4242
	SYS_IO_GETEVENTS                 = 4243
	SYS_IO_SUBMIT                    = 4244
	SYS_IO_CANCEL                    = 4245
	SYS_EXIT_GROUP                   = 4246
	SYS_LOOKUP_DCOOKIE               = 4247
	SYS_EPOLL_CREATE                 = 4248
	SYS_EPOLL_CTL                    = 4249
	SYS_EPOLL_WAIT                   = 4250
	SYS_REMAP_FILE_PAGES             = 4251
	SYS_SET_TID_ADDRESS              = 4252
	SYS_RESTART_SYSCALL              = 4253
	SYS_FADVISE64                    = 4254
	SYS_STATFS64                     = 4255
	SYS_FSTATFS64                    = 4256
	SYS_TIMER_CREATE                 = 4257
	SYS_TIMER_SETTIME                = 4258
	SYS_TIMER_GETTIME                = 4259
	SYS_TIMER_GETOVERRUN             = 4260
	SYS_TIMER_DELETE                 = 4261
	SYS_CLOCK_SETTIME                = 4262
	SYS_CLOCK_GETTIME                = 4263
	SYS_CLOCK_GETRES                 = 4264
	SYS_CLOCK_NANOSLEEP              = 4265
	SYS_TGKILL                       = 4266
	SYS_UTIMES                       = 4267
	SYS_MBIND                        = 4268
	SYS_GET_MEMPOLICY                = 4269
	SYS_SET_MEMPOLICY                = 4270
	SYS_MQ_OPEN                      = 4271
	SYS_MQ_UNLINK                    = 4272
	SYS_MQ_TIMEDSEND                 = 4273
	SYS_MQ_TIMEDRECEIVE              = 4274
	SYS_MQ_NOTIFY                    = 4275
	SYS_MQ_GETSETATTR                = 4276
	SYS_VSERVER                      = 4277
	SYS_WAITID                       = 4278
	SYS_ADD_KEY                      = 4280
	SYS_REQUEST_KEY                  = 4281
	SYS_KEYCTL                       = 4282
	SYS_SET_THREAD_AREA              = 4283
	SYS_INOTIFY_INIT                 = 4284
	SYS_INOTIFY_ADD_WATCH            = 4285
	SYS_INOTIFY_RM_WATCH             = 4286
	SYS_MIGRATE_PAGES                = 4287
	SYS_OPENAT                       = 4288
	SYS_MKDIRAT                      = 4289
	SYS_MKNODAT                      = 4290
	SYS_FCHOWNAT                     = 4291
	SYS_FUTIMESAT                    = 4292
	SYS_FSTATAT64                    = 4293
	SYS_UNLINKAT                     = 4294
	SYS_RENAMEAT                     = 4295
	SYS_LINKAT                       = 4296
	SYS_SYMLINKAT                    = 4297
	SYS_READLINKAT                   = 4298
	SYS_FCHMODAT                     = 4299
	SYS_FACCESSAT                    = 4300
	SYS_PSELECT6                     = 4301
	SYS_PPOLL                        = 4302
	SYS_UNSHARE                      = 4303
	SYS_SPLICE                       = 4304
	SYS_SYNC_FILE_RANGE              = 4305
	SYS_TEE                          = 4306
	SYS_VMSPLICE                     = 4307
	SYS_MOVE_PAGES                   = 4308
	SYS_SET_ROBUST_LIST              = 4309
	SYS_GET_ROBUST_LIST              = 4310
	SYS_KEXEC_LOAD                   = 4311
	SYS_GETCPU                       = 4312
	SYS_EPOLL_PWAIT                  = 4313
	SYS_IOPRIO_SET                   = 4314
	SYS_IOPRIO_GET                   = 4315
	SYS_UTIMENSAT                    = 4316
	SYS_SIGNALFD                     = 4317
	SYS_TIMERFD                      = 4318
	SYS_EVENTFD                      = 4319
	SYS_FALLOCATE                    = 4320
	SYS_TIMERFD_CREATE               = 4321
	SYS_TIMERFD_GETTIME              = 4322
	SYS_TIMERFD_SETTIME              = 4323
	SYS_SIGNALFD4                    = 4324
	SYS_EVENTFD2                     = 4325
	SYS_EPOLL_CREATE1                = 4326
	SYS_DUP3                         = 4327
	SYS_PIPE2                        = 4328
	SYS_INOTIFY_INIT1                = 4329
	SYS_PREADV                       = 4330
	SYS_PWRITEV                      = 4331
	SYS_RT_TGSIGQUEUEINFO            = 4332
	SYS_PERF_EVENT_OPEN              = 4333
	SYS_ACCEPT4                      = 4334
	SYS_RECVMMSG                     = 4335
	SYS_FANOTIFY_INIT                = 4336
	SYS_FANOTIFY_MARK                = 4337
	SYS_PRLIMIT64                    = 4338
	SYS_NAME_TO_HANDLE_AT            = 4339
	SYS_OPEN_BY_HANDLE_AT            = 4340
	SYS_CLOCK_ADJTIME                = 4341
	SYS_SYNCFS                       = 4342
	SYS_SENDMMSG                     = 4343
	SYS_SETNS                        = 4344
	SYS_PROCESS_VM_READV             = 4345
	SYS_PROCESS_VM_WRITEV            = 4346
	SYS_KCMP                         = 4347
	SYS_FINIT_MODULE                 = 4348
	SYS_SCHED_SETATTR                = 4349
	SYS_SCHED_GETATTR                = 4350
	SYS_RENAMEAT2                    = 4351
	SYS_SECCOMP                      = 4352
	SYS_GETRANDOM                    = 4353
	SYS_MEMFD_CREATE                 = 4354
	SYS_BPF                          = 4355
	SYS_EXECVEAT                     = 4356
	SYS_USERFAULTFD                  = 4357
	SYS_MEMBARRIER                   = 4358
	SYS_MLOCK2                       = 4359
	SYS_COPY_FILE_RANGE              = 4360
	SYS_PREADV2                      = 4361
	SYS_PWRITEV2                     = 4362
	SYS_PKEY_MPROTECT                = 4363
	SYS_PKEY_ALLOC                   = 4364
	SYS_PKEY_FREE                    = 4365
	SYS_STATX                        = 4366
	SYS_RSEQ                         = 4367
	SYS_IO_PGETEVENTS                = 4368
	SYS_SEMGET                       = 4393
	SYS_SEMCTL                       = 4394
	SYS_SHMGET                       = 4395
	SYS_SHMCTL                       = 4396
	SYS_SHMAT                        = 4397
	SYS_SHMDT                        = 4398
	SYS_MSGGET                       = 4399
	SYS_MSGSND                       = 4400
	SYS_MSGRCV                       = 4401
	SYS_MSGCTL                       = 4402
	SYS_CLOCK_GETTIME64              = 4403
	SYS_CLOCK_SETTIME64              = 4404
	SYS_CLOCK_ADJTIME64              = 4405
	SYS_CLOCK_GETRES_TIME64          = 4406
	SYS_CLOCK_NANOSLEEP_TIME64       = 4407
	SYS_TIMER_GETTIME64              = 4408
	SYS_TIMER_SETTIME64              = 4409
	SYS_TIMERFD_GETTIME64            = 4410
	SYS_TIMERFD_SETTIME64            = 4411
	SYS_UTIMENSAT_TIME64             = 4412
	SYS_PSELECT6_TIME64              = 4413
	SYS_PPOLL_TIME64                 = 4414
	SYS_IO_PGETEVENTS_TIME64         = 4416
	SYS_RECVMMSG_TIME64              = 4417
	SYS_MQ_TIMEDSEND_TIME64          = 4418
	SYS_MQ_TIMEDRECEIVE_TIME64       = 4419
	SYS_SEMTIMEDOP_TIME64            = 4420
	SYS_RT_SIGTIMEDWAIT_TIME64       = 4421
	SYS_FUTEX_TIME64                 = 4422
	SYS_SCHED_RR_GET_INTERVAL_TIME64 = 4423
	SYS_PIDFD_SEND_SIGNAL            = 4424
	SYS_IO_URING_SETUP               = 4425
	SYS_IO_URING_ENTER               = 4426
	SYS_IO_URING_REGISTER            = 4427
	SYS_OPEN_TREE                    = 4428
	SYS_MOVE_MOUNT                   = 4429
	SYS_FSOPEN                       = 4430
	SYS_FSCONFIG                     = 4431
	SYS_FSMOUNT                      = 4432
	SYS_FSPICK                       = 4433
	SYS_PIDFD_OPEN                   = 4434
	SYS_CLONE3                       = 4435
	SYS_CLOSE_RANGE                  = 4436
	SYS_OPENAT2                      = 4437
	SYS_PIDFD_GETFD                  = 4438
	SYS_FACCESSAT2                   = 4439
	SYS_PROCESS_MADVISE              = 4440
	SYS_EPOLL_PWAIT2                 = 4441
	SYS_MOUNT_SETATTR                = 4442
	SYS_QUOTACTL_FD                  = 4443
	SYS_LANDLOCK_CREATE_RULESET      = 4444
	SYS_LANDLOCK_ADD_RULE            = 4445
	SYS_LANDLOCK_RESTRICT_SELF       = 4446
	SYS_PROCESS_MRELEASE             = 4448
	SYS_FUTEX_WAITV                  = 4449
	SYS_SET_MEMPOLICY_HOME_NODE      = 4450
	SYS_CACHESTAT                    = 4451
	SYS_FCHMODAT2                    = 4452
	SYS_MAP_SHADOW_STACK             = 4453
	SYS_FUTEX_WAKE                   = 4454
	SYS_FUTEX_WAIT                   = 4455
	SYS_FUTEX_REQUEUE                = 4456
	SYS_STATMOUNT                    = 4457
	SYS_LISTMOUNT                    = 4458
	SYS_LSM_GET_SELF_ATTR            = 4459
	SYS_LSM_SET_SELF_ATTR            = 4460
	SYS_LSM_LIST_MODULES             = 4461
	SYS_MSEAL                        = 4462
)
```