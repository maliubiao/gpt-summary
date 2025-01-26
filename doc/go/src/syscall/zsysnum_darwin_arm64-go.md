Response:
Let's break down the thought process for answering this request.

1. **Understanding the Core Request:** The primary goal is to explain the functionality of the provided Go code snippet and relate it to Go's features. The snippet is a series of constants defining system call numbers on Darwin ARM64.

2. **Initial Interpretation of the Code:** The code clearly defines constants. Each constant starts with `SYS_` and is followed by the name of a common system call (e.g., `SYS_READ`, `SYS_WRITE`). The values assigned to these constants are integer numbers. The comment at the top points out the code is generated from `/usr/include/sys/syscall.h`. This strongly suggests these constants map Go-friendly names to the underlying operating system's system call numbers.

3. **Identifying the Go Feature:**  Knowing that Go interacts with the OS through system calls, and seeing these constants, the connection to the `syscall` package becomes clear. The `syscall` package in Go provides low-level access to operating system primitives, and these constants are exactly what's needed to invoke those primitives.

4. **Formulating the Functionality:** Based on the above, the core function of this code is to define the mapping between human-readable system call names and their numerical identifiers on the Darwin ARM64 architecture. This allows Go programs to make system calls without needing to remember or hardcode these magic numbers.

5. **Providing a Go Code Example:** To illustrate this, a simple example that uses a system call is needed. `syscall.Open`, `syscall.Read`, and `syscall.Write` are good choices as they are fundamental file operations. The example should:
    * Import the `syscall` package.
    * Demonstrate how to use one of the defined constants (indirectly through the `syscall` package functions).
    * Include basic error handling for robustness.
    * Provide a clear input (filename) and expected output (content of the file).

6. **Explaining the Code Example:**  The explanation needs to clarify:
    * How the `syscall` package uses these constants internally.
    * The role of the system call itself (e.g., `open` opens a file).
    * The connection between the Go code and the underlying OS interaction.

7. **Addressing Code Reasoning (Input/Output):**  The Go code example already incorporates this. The "input" is the filename passed to `syscall.Open`, and the "output" is the content read from the file (or an error message).

8. **Addressing Command-Line Parameters:** This specific code snippet doesn't directly handle command-line parameters. It's a data file (constants). Therefore, the answer should state this explicitly. It's important *not* to invent command-line usage where none exists.

9. **Identifying Common Mistakes:**  Since this file defines constants, direct manipulation of these constants is generally not recommended and could lead to errors. Users should rely on the higher-level functions in the `syscall` package. The most likely mistake is a misunderstanding of the purpose of these constants – they are for internal use by the `syscall` package, not direct manipulation by end-users. An example of incorrect usage would be attempting to directly pass `syscall.SYS_READ` as a file descriptor.

10. **Structuring the Answer:**  The answer should be structured logically, following the order of the questions in the prompt:
    * List the functionalities.
    * Provide a Go code example.
    * Explain the code example with input/output.
    * Discuss command-line parameters (or lack thereof).
    * Highlight common mistakes.

11. **Language and Tone:**  The answer should be in Chinese, as requested, and maintain a clear and informative tone. Using code blocks for the Go example enhances readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Could this relate to assembly code generation?  While system calls are low-level, this file doesn't contain assembly. It's primarily about defining numerical identifiers. So, focus shifts to the `syscall` package.
* **Considering other Go features:** Could this be related to cgo?  While cgo also deals with external code, this file doesn't directly involve C code. It's more about mapping to OS-level system calls, which the `syscall` package handles directly.
* **Ensuring the Go example is simple:**  Avoid overly complex examples. The goal is to illustrate the basic concept of system calls, not to demonstrate advanced usage of the `syscall` package.
* **Double-checking the mistake section:** Make sure the "common mistake" is realistic and something a user might actually do. Simply stating "using the wrong constant number" isn't very helpful. Focusing on misuse due to misunderstanding is better.
这段代码是 Go 语言标准库 `syscall` 包中，针对 Darwin 操作系统（macOS 等）并且运行在 ARM64 架构上的一个源文件 `zsysnum_darwin_arm64.go` 的一部分。

**它的主要功能是:**

1. **定义系统调用号常量:**  这个文件定义了一系列以 `SYS_` 开头的常量，例如 `SYS_READ`, `SYS_WRITE`, `SYS_OPEN` 等。每个常量都代表一个特定的系统调用，并且被赋予了一个唯一的数字。这个数字是操作系统内核用来识别和执行相应系统调用的标识符。

**可以推理出它是什么 Go 语言功能的实现:**

这个文件是 Go 语言中 **系统调用 (syscall)** 功能的底层实现之一。Go 语言的 `syscall` 包提供了与操作系统内核进行交互的低级接口。这些常量定义了在 Darwin ARM64 架构上可用的系统调用及其对应的编号。当 Go 程序需要执行某些操作系统级别的操作时，例如读写文件、创建进程等，它会使用 `syscall` 包中提供的函数。这些函数在底层会使用这里定义的系统调用号来调用相应的内核功能。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"os"
	"syscall"
)

func main() {
	filename := "test.txt"

	// 创建一个文件
	fd, err := syscall.Open(filename, syscall.O_RDWR|syscall.O_CREATE|syscall.O_TRUNC, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer syscall.Close(fd) // 确保文件描述符被关闭

	message := []byte("Hello, syscall!\n")

	// 写入数据到文件
	n, err := syscall.Write(fd, message)
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}
	fmt.Printf("Wrote %d bytes to file\n", n)

	// 将文件指针移动到开始位置
	_, err = syscall.Lseek(fd, 0, 0)
	if err != nil {
		fmt.Println("Error seeking in file:", err)
		return
	}

	readBuf := make([]byte, 100)

	// 从文件读取数据
	rn, err := syscall.Read(fd, readBuf)
	if err != nil {
		fmt.Println("Error reading from file:", err)
		return
	}
	fmt.Printf("Read %d bytes from file: %s\n", rn, string(readBuf[:rn]))

	// 获取当前进程的 PID
	pid := syscall.Getpid()
	fmt.Println("Process ID:", pid)

	// 退出程序
	syscall.Exit(0)
}
```

**代码推理：**

* **假设输入:** 上面的代码会尝试创建一个名为 `test.txt` 的文件（如果不存在），并向其中写入 "Hello, syscall!\n" 字符串，然后读取该字符串并打印出来。
* **假设输出:**
  ```
  Wrote 16 bytes to file
  Read 16 bytes from file: Hello, syscall!

  Process ID: <当前进程的PID>
  ```

**解释:**

1. `syscall.Open(filename, syscall.O_RDWR|syscall.O_CREATE|syscall.O_TRUNC, 0644)`:  这个函数调用了底层的 `open` 系统调用（对应 `SYS_OPEN` 常量）。它会打开或创建一个文件，并返回一个文件描述符 `fd`。
2. `syscall.Write(fd, message)`: 这个函数调用了底层的 `write` 系统调用（对应 `SYS_WRITE` 常量），将 `message` 中的数据写入到文件描述符 `fd` 指向的文件中。
3. `syscall.Lseek(fd, 0, 0)`: 这个函数调用了底层的 `lseek` 系统调用（对应 `SYS_LSEEK` 常量），将文件读写指针移动到文件的开头。
4. `syscall.Read(fd, readBuf)`: 这个函数调用了底层的 `read` 系统调用（对应 `SYS_READ` 常量），从文件描述符 `fd` 指向的文件中读取数据到 `readBuf` 中。
5. `syscall.Getpid()`: 这个函数调用了底层的 `getpid` 系统调用（对应 `SYS_GETPID` 常量），获取当前进程的进程 ID。
6. `syscall.Exit(0)`: 这个函数调用了底层的 `exit` 系统调用（对应 `SYS_EXIT` 常量），正常终止程序的执行。

**命令行参数的具体处理:**

这个文件本身不处理命令行参数。它只是定义了一些常量。`syscall` 包中的其他函数可能会接受参数，例如 `syscall.Open` 接受文件名、打开模式和权限作为参数。这些参数会被传递给底层的系统调用。

**使用者易犯错的点:**

1. **直接使用系统调用号:**  虽然这些常量是公开的，但通常不建议直接使用这些数字。应该使用 `syscall` 包中提供的封装好的函数，例如 `syscall.Open`, `syscall.Read` 等。直接使用数字容易出错且可移植性差。

   **错误示例:**

   ```go
   package main

   import (
       "fmt"
       "syscall"
   )

   func main() {
       // 尝试直接使用系统调用号进行写操作 (这通常不会按预期工作)
       fd := 1 // 标准输出的文件描述符
       message := []byte("Hello, direct syscall!\n")
       _, _, err := syscall.Syscall(syscall.SYS_WRITE, uintptr(fd), uintptr(unsafe.Pointer(&message[0])), uintptr(len(message)))
       if err != 0 {
           fmt.Println("Error using syscall:", err)
       }
   }
   ```

   **解释:**  直接使用 `syscall.Syscall` 需要非常小心地处理参数类型和返回值，容易出错。更推荐使用 `syscall.Write` 等高级函数。

2. **错误的文件描述符:** 在使用文件操作相关的系统调用时，传递无效或错误的文件描述符会导致程序崩溃或产生不可预测的结果。

   **错误示例:**

   ```go
   package main

   import (
       "fmt"
       "syscall"
   )

   func main() {
       fd := -1 // 无效的文件描述符
       message := []byte("Trying to write to an invalid fd\n")
       _, err := syscall.Write(fd, message)
       if err != nil {
           fmt.Println("Error writing:", err) // 通常会返回一个错误
       }
   }
   ```

3. **忽略错误处理:**  系统调用可能会失败，例如文件不存在、权限不足等。必须检查系统调用的返回值（通常是 error 类型）并进行适当的错误处理。

   **错误示例:**

   ```go
   package main

   import (
       "fmt"
       "syscall"
   )

   func main() {
       _, _ = syscall.Open("nonexistent_file.txt", syscall.O_RDONLY, 0) // 没有检查错误
       // ... 后续操作可能会因为文件未打开而失败
   }
   ```

总而言之，`go/src/syscall/zsysnum_darwin_arm64.go` 这个文件是 Go 语言 `syscall` 包在 Darwin ARM64 架构上的核心组成部分，它定义了操作系统提供的各种系统调用的编号，使得 Go 程序能够通过 `syscall` 包提供的函数来与操作系统内核进行交互。 使用者应该优先使用 `syscall` 包中封装好的函数，并始终注意错误处理。

Prompt: 
```
这是路径为go/src/syscall/zsysnum_darwin_arm64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// mksysnum_darwin.pl /usr/include/sys/syscall.h
// Code generated by the command above; DO NOT EDIT.

package syscall

const (
	SYS_SYSCALL                        = 0
	SYS_EXIT                           = 1
	SYS_FORK                           = 2
	SYS_READ                           = 3
	SYS_WRITE                          = 4
	SYS_OPEN                           = 5
	SYS_CLOSE                          = 6
	SYS_WAIT4                          = 7
	SYS_LINK                           = 9
	SYS_UNLINK                         = 10
	SYS_CHDIR                          = 12
	SYS_FCHDIR                         = 13
	SYS_MKNOD                          = 14
	SYS_CHMOD                          = 15
	SYS_CHOWN                          = 16
	SYS_GETFSSTAT                      = 18
	SYS_GETPID                         = 20
	SYS_SETUID                         = 23
	SYS_GETUID                         = 24
	SYS_GETEUID                        = 25
	SYS_PTRACE                         = 26
	SYS_RECVMSG                        = 27
	SYS_SENDMSG                        = 28
	SYS_RECVFROM                       = 29
	SYS_ACCEPT                         = 30
	SYS_GETPEERNAME                    = 31
	SYS_GETSOCKNAME                    = 32
	SYS_ACCESS                         = 33
	SYS_CHFLAGS                        = 34
	SYS_FCHFLAGS                       = 35
	SYS_SYNC                           = 36
	SYS_KILL                           = 37
	SYS_GETPPID                        = 39
	SYS_DUP                            = 41
	SYS_PIPE                           = 42
	SYS_GETEGID                        = 43
	SYS_SIGACTION                      = 46
	SYS_GETGID                         = 47
	SYS_SIGPROCMASK                    = 48
	SYS_GETLOGIN                       = 49
	SYS_SETLOGIN                       = 50
	SYS_ACCT                           = 51
	SYS_SIGPENDING                     = 52
	SYS_SIGALTSTACK                    = 53
	SYS_IOCTL                          = 54
	SYS_REBOOT                         = 55
	SYS_REVOKE                         = 56
	SYS_SYMLINK                        = 57
	SYS_READLINK                       = 58
	SYS_EXECVE                         = 59
	SYS_UMASK                          = 60
	SYS_CHROOT                         = 61
	SYS_MSYNC                          = 65
	SYS_VFORK                          = 66
	SYS_MUNMAP                         = 73
	SYS_MPROTECT                       = 74
	SYS_MADVISE                        = 75
	SYS_MINCORE                        = 78
	SYS_GETGROUPS                      = 79
	SYS_SETGROUPS                      = 80
	SYS_GETPGRP                        = 81
	SYS_SETPGID                        = 82
	SYS_SETITIMER                      = 83
	SYS_SWAPON                         = 85
	SYS_GETITIMER                      = 86
	SYS_GETDTABLESIZE                  = 89
	SYS_DUP2                           = 90
	SYS_FCNTL                          = 92
	SYS_SELECT                         = 93
	SYS_FSYNC                          = 95
	SYS_SETPRIORITY                    = 96
	SYS_SOCKET                         = 97
	SYS_CONNECT                        = 98
	SYS_GETPRIORITY                    = 100
	SYS_BIND                           = 104
	SYS_SETSOCKOPT                     = 105
	SYS_LISTEN                         = 106
	SYS_SIGSUSPEND                     = 111
	SYS_GETTIMEOFDAY                   = 116
	SYS_GETRUSAGE                      = 117
	SYS_GETSOCKOPT                     = 118
	SYS_READV                          = 120
	SYS_WRITEV                         = 121
	SYS_SETTIMEOFDAY                   = 122
	SYS_FCHOWN                         = 123
	SYS_FCHMOD                         = 124
	SYS_SETREUID                       = 126
	SYS_SETREGID                       = 127
	SYS_RENAME                         = 128
	SYS_FLOCK                          = 131
	SYS_MKFIFO                         = 132
	SYS_SENDTO                         = 133
	SYS_SHUTDOWN                       = 134
	SYS_SOCKETPAIR                     = 135
	SYS_MKDIR                          = 136
	SYS_RMDIR                          = 137
	SYS_UTIMES                         = 138
	SYS_FUTIMES                        = 139
	SYS_ADJTIME                        = 140
	SYS_GETHOSTUUID                    = 142
	SYS_SETSID                         = 147
	SYS_GETPGID                        = 151
	SYS_SETPRIVEXEC                    = 152
	SYS_PREAD                          = 153
	SYS_PWRITE                         = 154
	SYS_NFSSVC                         = 155
	SYS_STATFS                         = 157
	SYS_FSTATFS                        = 158
	SYS_UNMOUNT                        = 159
	SYS_GETFH                          = 161
	SYS_QUOTACTL                       = 165
	SYS_MOUNT                          = 167
	SYS_CSOPS                          = 169
	SYS_CSOPS_AUDITTOKEN               = 170
	SYS_WAITID                         = 173
	SYS_KDEBUG_TRACE                   = 180
	SYS_SETGID                         = 181
	SYS_SETEGID                        = 182
	SYS_SETEUID                        = 183
	SYS_SIGRETURN                      = 184
	SYS_CHUD                           = 185
	SYS_FDATASYNC                      = 187
	SYS_STAT                           = 188
	SYS_FSTAT                          = 189
	SYS_LSTAT                          = 190
	SYS_PATHCONF                       = 191
	SYS_FPATHCONF                      = 192
	SYS_GETRLIMIT                      = 194
	SYS_SETRLIMIT                      = 195
	SYS_GETDIRENTRIES                  = 196
	SYS_MMAP                           = 197
	SYS_LSEEK                          = 199
	SYS_TRUNCATE                       = 200
	SYS_FTRUNCATE                      = 201
	SYS___SYSCTL                       = 202
	SYS_MLOCK                          = 203
	SYS_MUNLOCK                        = 204
	SYS_UNDELETE                       = 205
	SYS_ATSOCKET                       = 206
	SYS_ATGETMSG                       = 207
	SYS_ATPUTMSG                       = 208
	SYS_ATPSNDREQ                      = 209
	SYS_ATPSNDRSP                      = 210
	SYS_ATPGETREQ                      = 211
	SYS_ATPGETRSP                      = 212
	SYS_OPEN_DPROTECTED_NP             = 216
	SYS_GETATTRLIST                    = 220
	SYS_SETATTRLIST                    = 221
	SYS_GETDIRENTRIESATTR              = 222
	SYS_EXCHANGEDATA                   = 223
	SYS_SEARCHFS                       = 225
	SYS_DELETE                         = 226
	SYS_COPYFILE                       = 227
	SYS_FGETATTRLIST                   = 228
	SYS_FSETATTRLIST                   = 229
	SYS_POLL                           = 230
	SYS_WATCHEVENT                     = 231
	SYS_WAITEVENT                      = 232
	SYS_MODWATCH                       = 233
	SYS_GETXATTR                       = 234
	SYS_FGETXATTR                      = 235
	SYS_SETXATTR                       = 236
	SYS_FSETXATTR                      = 237
	SYS_REMOVEXATTR                    = 238
	SYS_FREMOVEXATTR                   = 239
	SYS_LISTXATTR                      = 240
	SYS_FLISTXATTR                     = 241
	SYS_FSCTL                          = 242
	SYS_INITGROUPS                     = 243
	SYS_POSIX_SPAWN                    = 244
	SYS_FFSCTL                         = 245
	SYS_NFSCLNT                        = 247
	SYS_FHOPEN                         = 248
	SYS_MINHERIT                       = 250
	SYS_SEMSYS                         = 251
	SYS_MSGSYS                         = 252
	SYS_SHMSYS                         = 253
	SYS_SEMCTL                         = 254
	SYS_SEMGET                         = 255
	SYS_SEMOP                          = 256
	SYS_MSGCTL                         = 258
	SYS_MSGGET                         = 259
	SYS_MSGSND                         = 260
	SYS_MSGRCV                         = 261
	SYS_SHMAT                          = 262
	SYS_SHMCTL                         = 263
	SYS_SHMDT                          = 264
	SYS_SHMGET                         = 265
	SYS_SHM_OPEN                       = 266
	SYS_SHM_UNLINK                     = 267
	SYS_SEM_OPEN                       = 268
	SYS_SEM_CLOSE                      = 269
	SYS_SEM_UNLINK                     = 270
	SYS_SEM_WAIT                       = 271
	SYS_SEM_TRYWAIT                    = 272
	SYS_SEM_POST                       = 273
	SYS_SEM_GETVALUE                   = 274
	SYS_SEM_INIT                       = 275
	SYS_SEM_DESTROY                    = 276
	SYS_OPEN_EXTENDED                  = 277
	SYS_UMASK_EXTENDED                 = 278
	SYS_STAT_EXTENDED                  = 279
	SYS_LSTAT_EXTENDED                 = 280
	SYS_FSTAT_EXTENDED                 = 281
	SYS_CHMOD_EXTENDED                 = 282
	SYS_FCHMOD_EXTENDED                = 283
	SYS_ACCESS_EXTENDED                = 284
	SYS_SETTID                         = 285
	SYS_GETTID                         = 286
	SYS_SETSGROUPS                     = 287
	SYS_GETSGROUPS                     = 288
	SYS_SETWGROUPS                     = 289
	SYS_GETWGROUPS                     = 290
	SYS_MKFIFO_EXTENDED                = 291
	SYS_MKDIR_EXTENDED                 = 292
	SYS_IDENTITYSVC                    = 293
	SYS_SHARED_REGION_CHECK_NP         = 294
	SYS_VM_PRESSURE_MONITOR            = 296
	SYS_PSYNCH_RW_LONGRDLOCK           = 297
	SYS_PSYNCH_RW_YIELDWRLOCK          = 298
	SYS_PSYNCH_RW_DOWNGRADE            = 299
	SYS_PSYNCH_RW_UPGRADE              = 300
	SYS_PSYNCH_MUTEXWAIT               = 301
	SYS_PSYNCH_MUTEXDROP               = 302
	SYS_PSYNCH_CVBROAD                 = 303
	SYS_PSYNCH_CVSIGNAL                = 304
	SYS_PSYNCH_CVWAIT                  = 305
	SYS_PSYNCH_RW_RDLOCK               = 306
	SYS_PSYNCH_RW_WRLOCK               = 307
	SYS_PSYNCH_RW_UNLOCK               = 308
	SYS_PSYNCH_RW_UNLOCK2              = 309
	SYS_GETSID                         = 310
	SYS_SETTID_WITH_PID                = 311
	SYS_PSYNCH_CVCLRPREPOST            = 312
	SYS_AIO_FSYNC                      = 313
	SYS_AIO_RETURN                     = 314
	SYS_AIO_SUSPEND                    = 315
	SYS_AIO_CANCEL                     = 316
	SYS_AIO_ERROR                      = 317
	SYS_AIO_READ                       = 318
	SYS_AIO_WRITE                      = 319
	SYS_LIO_LISTIO                     = 320
	SYS_IOPOLICYSYS                    = 322
	SYS_PROCESS_POLICY                 = 323
	SYS_MLOCKALL                       = 324
	SYS_MUNLOCKALL                     = 325
	SYS_ISSETUGID                      = 327
	SYS___PTHREAD_KILL                 = 328
	SYS___PTHREAD_SIGMASK              = 329
	SYS___SIGWAIT                      = 330
	SYS___DISABLE_THREADSIGNAL         = 331
	SYS___PTHREAD_MARKCANCEL           = 332
	SYS___PTHREAD_CANCELED             = 333
	SYS___SEMWAIT_SIGNAL               = 334
	SYS_PROC_INFO                      = 336
	SYS_SENDFILE                       = 337
	SYS_STAT64                         = 338
	SYS_FSTAT64                        = 339
	SYS_LSTAT64                        = 340
	SYS_STAT64_EXTENDED                = 341
	SYS_LSTAT64_EXTENDED               = 342
	SYS_FSTAT64_EXTENDED               = 343
	SYS_GETDIRENTRIES64                = 344
	SYS_STATFS64                       = 345
	SYS_FSTATFS64                      = 346
	SYS_GETFSSTAT64                    = 347
	SYS___PTHREAD_CHDIR                = 348
	SYS___PTHREAD_FCHDIR               = 349
	SYS_AUDIT                          = 350
	SYS_AUDITON                        = 351
	SYS_GETAUID                        = 353
	SYS_SETAUID                        = 354
	SYS_GETAUDIT_ADDR                  = 357
	SYS_SETAUDIT_ADDR                  = 358
	SYS_AUDITCTL                       = 359
	SYS_BSDTHREAD_CREATE               = 360
	SYS_BSDTHREAD_TERMINATE            = 361
	SYS_KQUEUE                         = 362
	SYS_KEVENT                         = 363
	SYS_LCHOWN                         = 364
	SYS_STACK_SNAPSHOT                 = 365
	SYS_BSDTHREAD_REGISTER             = 366
	SYS_WORKQ_OPEN                     = 367
	SYS_WORKQ_KERNRETURN               = 368
	SYS_KEVENT64                       = 369
	SYS___OLD_SEMWAIT_SIGNAL           = 370
	SYS___OLD_SEMWAIT_SIGNAL_NOCANCEL  = 371
	SYS_THREAD_SELFID                  = 372
	SYS_LEDGER                         = 373
	SYS___MAC_EXECVE                   = 380
	SYS___MAC_SYSCALL                  = 381
	SYS___MAC_GET_FILE                 = 382
	SYS___MAC_SET_FILE                 = 383
	SYS___MAC_GET_LINK                 = 384
	SYS___MAC_SET_LINK                 = 385
	SYS___MAC_GET_PROC                 = 386
	SYS___MAC_SET_PROC                 = 387
	SYS___MAC_GET_FD                   = 388
	SYS___MAC_SET_FD                   = 389
	SYS___MAC_GET_PID                  = 390
	SYS___MAC_GET_LCID                 = 391
	SYS___MAC_GET_LCTX                 = 392
	SYS___MAC_SET_LCTX                 = 393
	SYS_SETLCID                        = 394
	SYS_GETLCID                        = 395
	SYS_READ_NOCANCEL                  = 396
	SYS_WRITE_NOCANCEL                 = 397
	SYS_OPEN_NOCANCEL                  = 398
	SYS_CLOSE_NOCANCEL                 = 399
	SYS_WAIT4_NOCANCEL                 = 400
	SYS_RECVMSG_NOCANCEL               = 401
	SYS_SENDMSG_NOCANCEL               = 402
	SYS_RECVFROM_NOCANCEL              = 403
	SYS_ACCEPT_NOCANCEL                = 404
	SYS_MSYNC_NOCANCEL                 = 405
	SYS_FCNTL_NOCANCEL                 = 406
	SYS_SELECT_NOCANCEL                = 407
	SYS_FSYNC_NOCANCEL                 = 408
	SYS_CONNECT_NOCANCEL               = 409
	SYS_SIGSUSPEND_NOCANCEL            = 410
	SYS_READV_NOCANCEL                 = 411
	SYS_WRITEV_NOCANCEL                = 412
	SYS_SENDTO_NOCANCEL                = 413
	SYS_PREAD_NOCANCEL                 = 414
	SYS_PWRITE_NOCANCEL                = 415
	SYS_WAITID_NOCANCEL                = 416
	SYS_POLL_NOCANCEL                  = 417
	SYS_MSGSND_NOCANCEL                = 418
	SYS_MSGRCV_NOCANCEL                = 419
	SYS_SEM_WAIT_NOCANCEL              = 420
	SYS_AIO_SUSPEND_NOCANCEL           = 421
	SYS___SIGWAIT_NOCANCEL             = 422
	SYS___SEMWAIT_SIGNAL_NOCANCEL      = 423
	SYS___MAC_MOUNT                    = 424
	SYS___MAC_GET_MOUNT                = 425
	SYS___MAC_GETFSSTAT                = 426
	SYS_FSGETPATH                      = 427
	SYS_AUDIT_SESSION_SELF             = 428
	SYS_AUDIT_SESSION_JOIN             = 429
	SYS_FILEPORT_MAKEPORT              = 430
	SYS_FILEPORT_MAKEFD                = 431
	SYS_AUDIT_SESSION_PORT             = 432
	SYS_PID_SUSPEND                    = 433
	SYS_PID_RESUME                     = 434
	SYS_PID_HIBERNATE                  = 435
	SYS_PID_SHUTDOWN_SOCKETS           = 436
	SYS_SHARED_REGION_MAP_AND_SLIDE_NP = 438
	SYS_KAS_INFO                       = 439
	SYS_MAXSYSCALL                     = 440
)

"""



```