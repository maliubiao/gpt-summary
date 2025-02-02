Response:
Let's break down the thought process for answering the user's request.

**1. Understanding the Core Request:**

The user provided a Go source code snippet and asked for several things:

* **Functionality:** What does this code do?
* **Go Feature:** What Go feature does it implement?
* **Example:** Show how it's used in Go code.
* **Reasoning (if needed):** Explain the connection between the code and the Go feature.
* **Command-Line Args:** Any command-line interaction?
* **Common Mistakes:**  Potential pitfalls for users.

**2. Initial Analysis of the Code:**

The code snippet consists of:

* A comment indicating the file path and a generation command. This is a crucial clue.
* A `package syscall` declaration, indicating interaction with the operating system.
* A series of `const` declarations. Each constant starts with `SYS_` followed by a name (e.g., `SYS_EXIT`) and is assigned an integer value.

**3. Deduction of Functionality:**

The `SYS_` prefix and the names of the constants (like `EXIT`, `READ`, `WRITE`, `OPEN`) strongly suggest these are system call numbers. The comment mentioning `asm/unistd.h` reinforces this, as `unistd.h` typically defines system call numbers in Unix-like systems. Therefore, the file's primary function is to define the system call numbers for the Linux operating system on the MIPS Little-Endian (mipsle) architecture.

**4. Identifying the Go Feature:**

Go's `syscall` package provides a way to directly interact with the operating system's system calls. This file is clearly a part of that mechanism. It acts as a mapping between symbolic names (like `SYS_READ`) and their corresponding numerical values, making it easier for Go programmers to invoke system calls without needing to remember the raw numbers.

**5. Constructing a Go Example:**

To demonstrate the usage, we need to show how a system call is invoked using these constants. A simple example is calling the `exit` system call.

* **Import:**  We need `syscall`.
* **Using the Constant:** Access the `SYS_EXIT` constant.
* **Invoking the Syscall:**  Use `syscall.Syscall()` or a similar function. `syscall.Exit()` is a higher-level wrapper, but using `syscall.Syscall()` directly better illustrates the role of the constant.
* **Arguments:**  The `exit` system call takes an exit code.
* **Output:**  Since `exit` terminates the program, there's no standard output in the traditional sense. However, the *effect* is program termination.

This leads to the example provided in the final answer.

**6. Reasoning (Connecting Code to Feature):**

The explanation needs to clearly link the constants in the file to their usage in the `syscall` package. Emphasize that Go uses these constants to translate the programmer's intent (e.g., "exit the program") into the numeric code the kernel understands.

**7. Command-Line Arguments:**

Reviewing the code, there's no direct handling of command-line arguments within this file itself. The `mksysnum_linux.pl` script mentioned in the comment likely *generates* this file, potentially taking command-line arguments to specify the architecture or header file location. However, the *generated* file doesn't directly process command-line input.

**8. Common Mistakes:**

Consider potential errors users might make when working with system calls:

* **Incorrect System Call Numbers:** If this file were manually edited incorrectly, using the wrong constant would lead to the wrong system call being invoked.
* **Incorrect Arguments:** Even with the correct system call number, providing the wrong number or types of arguments to `syscall.Syscall()` would cause errors.
* **Architecture Mismatch:** Using this file (specifically for `mipsle`) on a different architecture would result in incorrect system call numbers and unpredictable behavior.

**9. Structuring the Answer:**

Organize the information logically, following the user's request:

* Start with the main function of the file.
* Explain the connection to the Go `syscall` package.
* Provide a clear and simple Go code example.
* Explain the example, including assumed inputs and outputs.
* Address command-line arguments (and note their absence in this specific file).
* Discuss potential common mistakes.

**Self-Correction/Refinement During Thought Process:**

* Initially, I might have just said "it defines system call numbers." While true, it's better to be more specific about *why* and *how* in the context of Go.
* I considered using a simpler system call like `getpid` for the example. However, `exit` clearly demonstrates the termination effect, making the connection to the system call more obvious, despite not having a typical "output."
* I initially overlooked the comment about the generation script. Realizing its significance helps explain the "DO NOT EDIT" warning and the purpose of the file's content.

By following this structured thought process, we arrive at the comprehensive and accurate answer provided earlier.
这段代码是 Go 语言标准库 `syscall` 包中，针对 **Linux 操作系统** 并且运行在 **MIPS Little-Endian (mipsle) 架构** 上的系统调用号定义。

**功能:**

它的主要功能是定义了一系列常量，每个常量代表一个 Linux 系统调用，并赋予了该系统调用在 MIPS Little-Endian 架构上的编号。

* **提供系统调用号:**  它为 Go 语言程序在 MIPS Little-Endian Linux 上执行底层操作系统交互提供了必要的系统调用号。
* **简化系统调用:**  通过使用这些常量，Go 开发者可以使用具有语义的名称（例如 `SYS_READ`）来指代特定的系统调用，而不是直接使用难以记忆的数字 (例如 `4003`)。这提高了代码的可读性和可维护性。
* **平台特定:** 这个文件是平台特定的，因为不同的操作系统和 CPU 架构可能使用不同的系统调用号。`zsysnum_linux_mipsle.go` 明确针对 Linux 和 MIPS Little-Endian。

**它是什么 Go 语言功能的实现:**

这个文件是 Go 语言 `syscall` 包实现的一部分。`syscall` 包允许 Go 程序直接调用操作系统提供的系统调用接口。这对于需要进行底层操作，例如文件 I/O、网络编程、进程管理等的 Go 程序来说至关重要。

**Go 代码示例:**

以下是一个简单的 Go 代码示例，演示了如何使用 `syscall` 包和这个文件中定义的常量来执行系统调用：

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	message := "Hello, syscall!\n"
	fd := 1 // 标准输出文件描述符

	// 将字符串转换为字节切片
	buf := unsafe.Pointer(&[]byte(message)[0])
	len := uintptr(len(message))
	off := uintptr(0)

	// 调用 write 系统调用
	// 假设输入： message 字符串 "Hello, syscall!\n"
	// 假设输出： 在标准输出上打印 "Hello, syscall!\n"
	_, _, err := syscall.Syscall(syscall.SYS_WRITE, uintptr(fd), uintptr(buf), len)
	if err != 0 {
		fmt.Println("syscall write error:", err)
	}

	// 调用 exit 系统调用退出程序
	exitCode := 0
	// 假设输入： exitCode 为 0
	// 假设输出： 程序正常退出
	syscall.Exit(exitCode)
}
```

**代码推理:**

在上面的例子中：

1. **`syscall.SYS_WRITE`:**  我们使用了 `zsysnum_linux_mipsle.go` 中定义的 `SYS_WRITE` 常量（其值为 `4004`）来指明要调用的系统调用是 `write`。
2. **`syscall.Syscall`:**  `syscall.Syscall` 函数是 Go 中用于执行系统调用的底层函数。它接受系统调用号以及系统调用所需的参数。
3. **参数:** `write` 系统调用需要三个参数：文件描述符、指向要写入数据的缓冲区的指针和要写入的字节数。
4. **`syscall.Exit`:** 我们使用了 `syscall.Exit` 函数，它实际上是对 `SYS_EXIT` 系统调用的一个封装，用于正常退出程序。

**假设的输入与输出:**

* **`syscall.Syscall(syscall.SYS_WRITE, uintptr(fd), uintptr(buf), len)`:**
    * **假设输入:**
        * `fd`: 1 (标准输出)
        * `buf`: 指向字符串 "Hello, syscall!\n" 的内存地址
        * `len`:  16 (字符串的长度)
    * **假设输出:**  会在标准输出 (通常是终端) 上打印出 "Hello, syscall!\n"。该函数会返回写入的字节数，错误码等信息。
* **`syscall.Exit(exitCode)`:**
    * **假设输入:** `exitCode`: 0
    * **假设输出:** 程序会以退出码 0 正常终止。

**命令行参数的具体处理:**

这个代码文件本身并不直接处理命令行参数。命令行参数的处理通常发生在 `main` 函数中，通过 `os.Args` 切片来获取。  `syscall` 包提供的系统调用可以用于执行与进程和文件系统相关的操作，这些操作可能会受到命令行参数的影响，但 `zsysnum_linux_mipsle.go` 文件本身只负责提供系统调用号的映射。

**使用者易犯错的点:**

使用 `syscall` 包直接进行系统调用是比较底层的操作，容易出错。以下是一些常见的错误点：

* **错误的系统调用号:**  如果在调用 `syscall.Syscall` 时使用了错误的系统调用号，会导致程序行为异常，甚至崩溃。这个文件虽然提供了正确的系统调用号，但在其他地方使用时仍然可能出错。
* **错误的参数类型或数量:**  每个系统调用都有特定的参数类型和数量要求。如果传递了错误的参数，会导致系统调用失败。例如，`write` 系统调用需要一个指向缓冲区的指针，如果传递了其他类型的参数就会出错。
* **内存安全问题:**  在传递指针给系统调用时，需要确保指针指向有效的内存区域，并且在系统调用执行期间该内存区域不会被释放或修改。否则可能导致程序崩溃或安全漏洞。
* **平台依赖性:**  直接使用系统调用会使代码具有平台依赖性。在其他操作系统或架构上运行时，相同的系统调用号可能对应不同的操作，或者根本不存在。因此，直接使用 `syscall` 的代码通常需要进行平台适配。
* **错误处理不当:** 系统调用可能会失败，开发者需要仔细检查 `syscall.Syscall` 的返回值，特别是错误信息，并进行适当的错误处理。

**示例说明易犯错的点:**

假设开发者错误地使用了 `SYS_OPEN` 的系统调用号，但实际上想调用 `SYS_CREATE`：

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	filename := "test.txt"
	var mode int = syscall.O_RDWR | syscall.O_CREATE // 期望创建文件并读写
	var perm uint32 = 0644

	// 错误地使用 SYS_OPEN，但本意是创建文件
	// 在 MIPS Little-Endian Linux 上，SYS_OPEN 的值是 4005
	// 如果传入 O_CREATE 标志，行为可能与预期不符，可能尝试打开已存在的文件
	fd, _, err := syscall.Syscall(syscall.SYS_OPEN, uintptr(unsafe.Pointer(syscall.StringBytePtr(filename))), uintptr(mode), uintptr(perm))
	if err != 0 {
		fmt.Println("syscall open error:", err)
		return
	}
	defer syscall.Close(int(fd))

	fmt.Println("File opened/created successfully with fd:", fd)
}
```

在这个错误的例子中，开发者可能想创建文件，但错误地使用了 `SYS_OPEN` 系统调用号。虽然 `SYS_OPEN` 也能创建文件，但其行为和参数可能与开发者预期的 `SYS_CREATE` 或带有 `O_CREAT` 标志的 `SYS_OPEN` 调用有所不同，导致潜在的错误或不可预测的行为。 正确的做法是如果想创建文件，应该使用带有 `syscall.O_CREAT` 标志的 `SYS_OPEN` 或者直接使用 `SYS_CREAT` (尽管 `SYS_OPEN` 更常用且灵活)。

总而言之，`go/src/syscall/zsysnum_linux_mipsle.go` 这个文件在 Go 语言的系统调用机制中扮演着关键的角色，它定义了特定平台下的系统调用号，使得 Go 程序能够与操作系统进行底层的交互。 然而，直接使用系统调用需要谨慎，并注意潜在的错误。

Prompt: 
```
这是路径为go/src/syscall/zsysnum_linux_mipsle.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// mksysnum_linux.pl /usr/include/mips-linux-gnu/asm/unistd.h
// Code generated by the command above; DO NOT EDIT.

package syscall

const (
	SYS_SYSCALL                = 4000
	SYS_EXIT                   = 4001
	SYS_FORK                   = 4002
	SYS_READ                   = 4003
	SYS_WRITE                  = 4004
	SYS_OPEN                   = 4005
	SYS_CLOSE                  = 4006
	SYS_WAITPID                = 4007
	SYS_CREAT                  = 4008
	SYS_LINK                   = 4009
	SYS_UNLINK                 = 4010
	SYS_EXECVE                 = 4011
	SYS_CHDIR                  = 4012
	SYS_TIME                   = 4013
	SYS_MKNOD                  = 4014
	SYS_CHMOD                  = 4015
	SYS_LCHOWN                 = 4016
	SYS_BREAK                  = 4017
	SYS_UNUSED18               = 4018
	SYS_LSEEK                  = 4019
	SYS_GETPID                 = 4020
	SYS_MOUNT                  = 4021
	SYS_UMOUNT                 = 4022
	SYS_SETUID                 = 4023
	SYS_GETUID                 = 4024
	SYS_STIME                  = 4025
	SYS_PTRACE                 = 4026
	SYS_ALARM                  = 4027
	SYS_UNUSED28               = 4028
	SYS_PAUSE                  = 4029
	SYS_UTIME                  = 4030
	SYS_STTY                   = 4031
	SYS_GTTY                   = 4032
	SYS_ACCESS                 = 4033
	SYS_NICE                   = 4034
	SYS_FTIME                  = 4035
	SYS_SYNC                   = 4036
	SYS_KILL                   = 4037
	SYS_RENAME                 = 4038
	SYS_MKDIR                  = 4039
	SYS_RMDIR                  = 4040
	SYS_DUP                    = 4041
	SYS_PIPE                   = 4042
	SYS_TIMES                  = 4043
	SYS_PROF                   = 4044
	SYS_BRK                    = 4045
	SYS_SETGID                 = 4046
	SYS_GETGID                 = 4047
	SYS_SIGNAL                 = 4048
	SYS_GETEUID                = 4049
	SYS_GETEGID                = 4050
	SYS_ACCT                   = 4051
	SYS_UMOUNT2                = 4052
	SYS_LOCK                   = 4053
	SYS_IOCTL                  = 4054
	SYS_FCNTL                  = 4055
	SYS_MPX                    = 4056
	SYS_SETPGID                = 4057
	SYS_ULIMIT                 = 4058
	SYS_UNUSED59               = 4059
	SYS_UMASK                  = 4060
	SYS_CHROOT                 = 4061
	SYS_USTAT                  = 4062
	SYS_DUP2                   = 4063
	SYS_GETPPID                = 4064
	SYS_GETPGRP                = 4065
	SYS_SETSID                 = 4066
	SYS_SIGACTION              = 4067
	SYS_SGETMASK               = 4068
	SYS_SSETMASK               = 4069
	SYS_SETREUID               = 4070
	SYS_SETREGID               = 4071
	SYS_SIGSUSPEND             = 4072
	SYS_SIGPENDING             = 4073
	SYS_SETHOSTNAME            = 4074
	SYS_SETRLIMIT              = 4075
	SYS_GETRLIMIT              = 4076
	SYS_GETRUSAGE              = 4077
	SYS_GETTIMEOFDAY           = 4078
	SYS_SETTIMEOFDAY           = 4079
	SYS_GETGROUPS              = 4080
	SYS_SETGROUPS              = 4081
	SYS_RESERVED82             = 4082
	SYS_SYMLINK                = 4083
	SYS_UNUSED84               = 4084
	SYS_READLINK               = 4085
	SYS_USELIB                 = 4086
	SYS_SWAPON                 = 4087
	SYS_REBOOT                 = 4088
	SYS_READDIR                = 4089
	SYS_MMAP                   = 4090
	SYS_MUNMAP                 = 4091
	SYS_TRUNCATE               = 4092
	SYS_FTRUNCATE              = 4093
	SYS_FCHMOD                 = 4094
	SYS_FCHOWN                 = 4095
	SYS_GETPRIORITY            = 4096
	SYS_SETPRIORITY            = 4097
	SYS_PROFIL                 = 4098
	SYS_STATFS                 = 4099
	SYS_FSTATFS                = 4100
	SYS_IOPERM                 = 4101
	SYS_SOCKETCALL             = 4102
	SYS_SYSLOG                 = 4103
	SYS_SETITIMER              = 4104
	SYS_GETITIMER              = 4105
	SYS_STAT                   = 4106
	SYS_LSTAT                  = 4107
	SYS_FSTAT                  = 4108
	SYS_UNUSED109              = 4109
	SYS_IOPL                   = 4110
	SYS_VHANGUP                = 4111
	SYS_IDLE                   = 4112
	SYS_VM86                   = 4113
	SYS_WAIT4                  = 4114
	SYS_SWAPOFF                = 4115
	SYS_SYSINFO                = 4116
	SYS_IPC                    = 4117
	SYS_FSYNC                  = 4118
	SYS_SIGRETURN              = 4119
	SYS_CLONE                  = 4120
	SYS_SETDOMAINNAME          = 4121
	SYS_UNAME                  = 4122
	SYS_MODIFY_LDT             = 4123
	SYS_ADJTIMEX               = 4124
	SYS_MPROTECT               = 4125
	SYS_SIGPROCMASK            = 4126
	SYS_CREATE_MODULE          = 4127
	SYS_INIT_MODULE            = 4128
	SYS_DELETE_MODULE          = 4129
	SYS_GET_KERNEL_SYMS        = 4130
	SYS_QUOTACTL               = 4131
	SYS_GETPGID                = 4132
	SYS_FCHDIR                 = 4133
	SYS_BDFLUSH                = 4134
	SYS_SYSFS                  = 4135
	SYS_PERSONALITY            = 4136
	SYS_AFS_SYSCALL            = 4137
	SYS_SETFSUID               = 4138
	SYS_SETFSGID               = 4139
	SYS__LLSEEK                = 4140
	SYS_GETDENTS               = 4141
	SYS__NEWSELECT             = 4142
	SYS_FLOCK                  = 4143
	SYS_MSYNC                  = 4144
	SYS_READV                  = 4145
	SYS_WRITEV                 = 4146
	SYS_CACHEFLUSH             = 4147
	SYS_CACHECTL               = 4148
	SYS_SYSMIPS                = 4149
	SYS_UNUSED150              = 4150
	SYS_GETSID                 = 4151
	SYS_FDATASYNC              = 4152
	SYS__SYSCTL                = 4153
	SYS_MLOCK                  = 4154
	SYS_MUNLOCK                = 4155
	SYS_MLOCKALL               = 4156
	SYS_MUNLOCKALL             = 4157
	SYS_SCHED_SETPARAM         = 4158
	SYS_SCHED_GETPARAM         = 4159
	SYS_SCHED_SETSCHEDULER     = 4160
	SYS_SCHED_GETSCHEDULER     = 4161
	SYS_SCHED_YIELD            = 4162
	SYS_SCHED_GET_PRIORITY_MAX = 4163
	SYS_SCHED_GET_PRIORITY_MIN = 4164
	SYS_SCHED_RR_GET_INTERVAL  = 4165
	SYS_NANOSLEEP              = 4166
	SYS_MREMAP                 = 4167
	SYS_ACCEPT                 = 4168
	SYS_BIND                   = 4169
	SYS_CONNECT                = 4170
	SYS_GETPEERNAME            = 4171
	SYS_GETSOCKNAME            = 4172
	SYS_GETSOCKOPT             = 4173
	SYS_LISTEN                 = 4174
	SYS_RECV                   = 4175
	SYS_RECVFROM               = 4176
	SYS_RECVMSG                = 4177
	SYS_SEND                   = 4178
	SYS_SENDMSG                = 4179
	SYS_SENDTO                 = 4180
	SYS_SETSOCKOPT             = 4181
	SYS_SHUTDOWN               = 4182
	SYS_SOCKET                 = 4183
	SYS_SOCKETPAIR             = 4184
	SYS_SETRESUID              = 4185
	SYS_GETRESUID              = 4186
	SYS_QUERY_MODULE           = 4187
	SYS_POLL                   = 4188
	SYS_NFSSERVCTL             = 4189
	SYS_SETRESGID              = 4190
	SYS_GETRESGID              = 4191
	SYS_PRCTL                  = 4192
	SYS_RT_SIGRETURN           = 4193
	SYS_RT_SIGACTION           = 4194
	SYS_RT_SIGPROCMASK         = 4195
	SYS_RT_SIGPENDING          = 4196
	SYS_RT_SIGTIMEDWAIT        = 4197
	SYS_RT_SIGQUEUEINFO        = 4198
	SYS_RT_SIGSUSPEND          = 4199
	SYS_PREAD64                = 4200
	SYS_PWRITE64               = 4201
	SYS_CHOWN                  = 4202
	SYS_GETCWD                 = 4203
	SYS_CAPGET                 = 4204
	SYS_CAPSET                 = 4205
	SYS_SIGALTSTACK            = 4206
	SYS_SENDFILE               = 4207
	SYS_GETPMSG                = 4208
	SYS_PUTPMSG                = 4209
	SYS_MMAP2                  = 4210
	SYS_TRUNCATE64             = 4211
	SYS_FTRUNCATE64            = 4212
	SYS_STAT64                 = 4213
	SYS_LSTAT64                = 4214
	SYS_FSTAT64                = 4215
	SYS_PIVOT_ROOT             = 4216
	SYS_MINCORE                = 4217
	SYS_MADVISE                = 4218
	SYS_GETDENTS64             = 4219
	SYS_FCNTL64                = 4220
	SYS_RESERVED221            = 4221
	SYS_GETTID                 = 4222
	SYS_READAHEAD              = 4223
	SYS_SETXATTR               = 4224
	SYS_LSETXATTR              = 4225
	SYS_FSETXATTR              = 4226
	SYS_GETXATTR               = 4227
	SYS_LGETXATTR              = 4228
	SYS_FGETXATTR              = 4229
	SYS_LISTXATTR              = 4230
	SYS_LLISTXATTR             = 4231
	SYS_FLISTXATTR             = 4232
	SYS_REMOVEXATTR            = 4233
	SYS_LREMOVEXATTR           = 4234
	SYS_FREMOVEXATTR           = 4235
	SYS_TKILL                  = 4236
	SYS_SENDFILE64             = 4237
	SYS_FUTEX                  = 4238
	SYS_SCHED_SETAFFINITY      = 4239
	SYS_SCHED_GETAFFINITY      = 4240
	SYS_IO_SETUP               = 4241
	SYS_IO_DESTROY             = 4242
	SYS_IO_GETEVENTS           = 4243
	SYS_IO_SUBMIT              = 4244
	SYS_IO_CANCEL              = 4245
	SYS_EXIT_GROUP             = 4246
	SYS_LOOKUP_DCOOKIE         = 4247
	SYS_EPOLL_CREATE           = 4248
	SYS_EPOLL_CTL              = 4249
	SYS_EPOLL_WAIT             = 4250
	SYS_REMAP_FILE_PAGES       = 4251
	SYS_SET_TID_ADDRESS        = 4252
	SYS_RESTART_SYSCALL        = 4253
	SYS_FADVISE64              = 4254
	SYS_STATFS64               = 4255
	SYS_FSTATFS64              = 4256
	SYS_TIMER_CREATE           = 4257
	SYS_TIMER_SETTIME          = 4258
	SYS_TIMER_GETTIME          = 4259
	SYS_TIMER_GETOVERRUN       = 4260
	SYS_TIMER_DELETE           = 4261
	SYS_CLOCK_SETTIME          = 4262
	SYS_CLOCK_GETTIME          = 4263
	SYS_CLOCK_GETRES           = 4264
	SYS_CLOCK_NANOSLEEP        = 4265
	SYS_TGKILL                 = 4266
	SYS_UTIMES                 = 4267
	SYS_MBIND                  = 4268
	SYS_GET_MEMPOLICY          = 4269
	SYS_SET_MEMPOLICY          = 4270
	SYS_MQ_OPEN                = 4271
	SYS_MQ_UNLINK              = 4272
	SYS_MQ_TIMEDSEND           = 4273
	SYS_MQ_TIMEDRECEIVE        = 4274
	SYS_MQ_NOTIFY              = 4275
	SYS_MQ_GETSETATTR          = 4276
	SYS_VSERVER                = 4277
	SYS_WAITID                 = 4278
	SYS_ADD_KEY                = 4280
	SYS_REQUEST_KEY            = 4281
	SYS_KEYCTL                 = 4282
	SYS_SET_THREAD_AREA        = 4283
	SYS_INOTIFY_INIT           = 4284
	SYS_INOTIFY_ADD_WATCH      = 4285
	SYS_INOTIFY_RM_WATCH       = 4286
	SYS_MIGRATE_PAGES          = 4287
	SYS_OPENAT                 = 4288
	SYS_MKDIRAT                = 4289
	SYS_MKNODAT                = 4290
	SYS_FCHOWNAT               = 4291
	SYS_FUTIMESAT              = 4292
	SYS_FSTATAT64              = 4293
	SYS_UNLINKAT               = 4294
	SYS_RENAMEAT               = 4295
	SYS_LINKAT                 = 4296
	SYS_SYMLINKAT              = 4297
	SYS_READLINKAT             = 4298
	SYS_FCHMODAT               = 4299
	SYS_FACCESSAT              = 4300
	SYS_PSELECT6               = 4301
	SYS_PPOLL                  = 4302
	SYS_UNSHARE                = 4303
	SYS_SPLICE                 = 4304
	SYS_SYNC_FILE_RANGE        = 4305
	SYS_TEE                    = 4306
	SYS_VMSPLICE               = 4307
	SYS_MOVE_PAGES             = 4308
	SYS_SET_ROBUST_LIST        = 4309
	SYS_GET_ROBUST_LIST        = 4310
	SYS_KEXEC_LOAD             = 4311
	SYS_GETCPU                 = 4312
	SYS_EPOLL_PWAIT            = 4313
	SYS_IOPRIO_SET             = 4314
	SYS_IOPRIO_GET             = 4315
	SYS_UTIMENSAT              = 4316
	SYS_SIGNALFD               = 4317
	SYS_TIMERFD                = 4318
	SYS_EVENTFD                = 4319
	SYS_FALLOCATE              = 4320
	SYS_TIMERFD_CREATE         = 4321
	SYS_TIMERFD_GETTIME        = 4322
	SYS_TIMERFD_SETTIME        = 4323
	SYS_SIGNALFD4              = 4324
	SYS_EVENTFD2               = 4325
	SYS_EPOLL_CREATE1          = 4326
	SYS_DUP3                   = 4327
	SYS_PIPE2                  = 4328
	SYS_INOTIFY_INIT1          = 4329
	SYS_PREADV                 = 4330
	SYS_PWRITEV                = 4331
	SYS_RT_TGSIGQUEUEINFO      = 4332
	SYS_PERF_EVENT_OPEN        = 4333
	SYS_ACCEPT4                = 4334
	SYS_RECVMMSG               = 4335
	SYS_FANOTIFY_INIT          = 4336
	SYS_FANOTIFY_MARK          = 4337
	SYS_PRLIMIT64              = 4338
	SYS_NAME_TO_HANDLE_AT      = 4339
	SYS_OPEN_BY_HANDLE_AT      = 4340
	SYS_CLOCK_ADJTIME          = 4341
	SYS_SYNCFS                 = 4342
	SYS_SENDMMSG               = 4343
	SYS_SETNS                  = 4344
	SYS_PROCESS_VM_READV       = 4345
	SYS_PROCESS_VM_WRITEV      = 4346
	SYS_LINUX_SYSCALLS         = 4346
	SYS_O32_LINUX_SYSCALLS     = 4346
	SYS_64_LINUX_SYSCALLS      = 4305
	SYS_N32_LINUX_SYSCALLS     = 4310
)

"""



```