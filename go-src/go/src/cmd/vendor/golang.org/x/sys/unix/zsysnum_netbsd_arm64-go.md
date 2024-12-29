Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding - What is this?**

The first lines are crucial:

```go
// go run mksysnum.go http://cvsweb.netbsd.org/bsdweb.cgi/~checkout~/src/sys/kern/syscalls.master
// Code generated by the command above; DO NOT EDIT.

//go:build arm64 && netbsd

package unix
```

This tells us several key things:

* **Automatic Generation:**  The file is automatically generated by the `mksysnum.go` script, likely pulling data from the specified NetBSD syscall definition file. This means its content directly reflects the syscalls available on that operating system and architecture.
* **Target Platform:** The `//go:build arm64 && netbsd` directive specifies that this file is only included in builds for the `arm64` architecture on the `netbsd` operating system.
* **Package:**  It belongs to the `unix` package. This strongly suggests it's part of Go's standard library for interacting with operating system primitives.

**2. Core Content - What does it contain?**

The rest of the file is a series of constant declarations:

```go
const (
	SYS_EXIT                 = 1   // { void|sys||exit(int rval); }
	SYS_FORK                 = 2   // { int|sys||fork(void); }
	// ... and so on
)
```

Each constant follows a pattern:

* `SYS_`: A prefix indicating it's a system call.
* `NAME`: A descriptive name of the system call (e.g., `EXIT`, `FORK`, `READ`).
* `=`: Assignment.
* `NUMBER`: An integer value.
* `//`: A comment.

The comments are very informative, providing what looks like the C-style signature of the corresponding system call.

**3. Functionality - What does this code *do*?**

Given the structure and the context, the primary function of this code is to define **numerical identifiers for system calls** on the `arm64` architecture of the `netbsd` operating system.

**4. Connecting to Go Functionality - How is this used?**

This is the crucial step where we infer the purpose within the larger Go ecosystem. The `unix` package is the key. Go's `syscall` package (often used via the `os` package) provides a way to make raw system calls. However, Go doesn't hardcode syscall numbers directly in the `syscall` package itself. Instead, it uses architecture and OS-specific files like this one to provide the mapping between symbolic names (like `SYS_READ`) and their numerical values.

Therefore, this file enables Go programs running on `arm64` NetBSD to invoke specific operating system functions by using the defined constants.

**5. Code Examples - Illustrating the Usage**

Now we can create concrete Go examples. The `os` package provides higher-level abstractions, but under the hood, it often uses the `syscall` package.

* **Example 1 (Simple Syscall):**  Demonstrates using `syscall.Syscall` directly with one of the constants. We choose `SYS_GETPID` as it requires no arguments.

* **Example 2 (File I/O):** Shows how higher-level functions in the `os` package (like `os.Open`) internally rely on system calls, and indirectly, these constants.

* **Example 3 (Socket):** Illustrates networking and the `net` package's interaction with syscalls.

**6. Assumptions and Inputs/Outputs**

For the code examples, we need to make assumptions about the environment. For example, when opening a file, we assume the file exists. The output will depend on the system's state. We provide examples of *possible* outputs.

**7. Command-Line Parameters**

The first line of the file mentions a command: `go run mksysnum.go http://...`. This immediately suggests a command-line parameter: the URL. We need to explain that the `mksysnum.go` tool uses this URL to fetch the syscall definitions.

**8. Common Mistakes**

Thinking about potential errors users might make is essential.

* **Directly Using Numbers:**  A key mistake would be to hardcode syscall numbers instead of using the provided constants. This is bad for portability and readability.
* **Incorrect OS/Architecture:** Using this file on a different OS or architecture would lead to incorrect syscall numbers and likely program crashes. The `//go:build` directive helps prevent this, but developers could still make mistakes during build processes.

**Self-Correction/Refinement During the Process:**

* Initially, I might focus too much on the individual syscalls. It's important to zoom out and realize the file's overarching purpose is to provide a *mapping*.
* I might initially forget to explain the `//go:build` directive's significance.
* I need to ensure the Go code examples are clear and demonstrate the connection to the constants. Starting with simple examples and then moving to more complex ones is a good strategy.
*  It's important to explicitly state the assumptions made for the example code.

By following this structured approach, I can systematically analyze the provided code snippet and generate a comprehensive explanation covering its functionality, purpose, usage, and potential pitfalls.
这个Go语言实现文件 `zsysnum_netbsd_arm64.go` 的主要功能是：

**核心功能：定义了 NetBSD 操作系统在 ARM64 架构下的系统调用号常量。**

简单来说，操作系统提供了一系列内核级别的函数供用户程序调用，这些函数被称为系统调用。每个系统调用在内核中都有一个唯一的数字标识，这个文件就定义了这些数字标识的 Go 语言常量。

**更详细的解释：**

1. **系统调用号映射:**  它将 NetBSD ARM64 架构下的每个系统调用与一个唯一的整数常量关联起来。例如，`SYS_EXIT` 常量被赋值为 `1`，表示 `exit` 系统调用的编号是 1。

2. **供 Go 语言 `syscall` 包使用:** 这个文件是 Go 语言标准库 `syscall` 包的一部分。`syscall` 包提供了低级别的接口，允许 Go 程序直接调用操作系统的系统调用。`syscall` 包会使用这些常量来构造和发起系统调用。

3. **平台特定:**  文件名中的 `netbsd` 和 `arm64` 表明这是一个平台特定的文件。不同的操作系统和处理器架构可能有不同的系统调用号。Go 会根据构建的目标平台选择对应的 `zsysnum_*.go` 文件。

4. **自动生成:** 文件头部的注释 `// go run mksysnum.go ...` 说明这个文件是由 `mksysnum.go` 工具自动生成的。这个工具很可能从 NetBSD 的内核源代码中提取了系统调用号的信息。这保证了 Go 语言使用的系统调用号与操作系统内核保持一致。

**它是什么 Go 语言功能的实现？**

这个文件是 Go 语言中 **`syscall` 包实现系统调用功能的底层基础**。它为 `syscall` 包提供了特定平台下系统调用的编号信息。

**Go 代码举例说明：**

假设我们想在 Go 程序中调用 `exit` 系统调用来终止程序。我们可以使用 `syscall` 包：

```go
package main

import (
	"fmt"
	"syscall"
)

func main() {
	fmt.Println("程序即将退出")
	// 使用 SYS_EXIT 常量调用 exit 系统调用，退出码为 0
	_, _, err := syscall.Syscall(syscall.SYS_EXIT, 0, 0, 0)
	if err != nil {
		fmt.Println("调用 exit 失败:", err)
	}
	// 这行代码不会被执行，因为程序已经在上面退出了
	fmt.Println("程序已退出")
}
```

**假设的输入与输出：**

* **输入:**  运行上述 Go 程序。
* **输出:**
   ```
   程序即将退出
   ```
   程序会立即终止，不会输出 "程序已退出"。

**代码推理：**

1. `import "syscall"` 导入了 `syscall` 包。
2. `syscall.SYS_EXIT`  引用了在 `zsysnum_netbsd_arm64.go` 中定义的常量 `SYS_EXIT`，其值为 `1`。
3. `syscall.Syscall(syscall.SYS_EXIT, 0, 0, 0)`  调用了 `syscall.Syscall` 函数，该函数是 Go 中进行原始系统调用的接口。
   * 第一个参数 `syscall.SYS_EXIT` 指定了要调用的系统调用号。
   * 后面的三个 `0` 是传递给 `exit` 系统调用的参数，在 `exit` 系统调用中，第一个参数是退出状态码。
4. 当 `syscall.Syscall` 被调用时，Go 的运行时系统会根据 `syscall.SYS_EXIT` 的值（即 `1`）来执行 NetBSD ARM64 平台的 `exit` 系统调用，并传递退出状态码 `0`。

**涉及命令行参数的具体处理：**

这个文件本身不直接处理命令行参数。它只是定义了一些常量。

但是，文件头部的注释 `// go run mksysnum.go http://cvsweb.netbsd.org/bsdweb.cgi/~checkout~/src/sys/kern/syscalls.master`  揭示了生成这个文件的过程。

* **`go run mksysnum.go`**:  这是一个 Go 命令，用于运行名为 `mksysnum.go` 的 Go 程序。
* **`http://cvsweb.netbsd.org/bsdweb.cgi/~checkout~/src/sys/kern/syscalls.master`**:  这是一个 URL，很可能是 `mksysnum.go` 程序的命令行参数。这个 URL 指向 NetBSD 操作系统内核源代码中定义系统调用的文件。

**`mksysnum.go` 程序的推测功能：**

1. **下载:**  `mksysnum.go` 程序很可能通过给定的 URL 下载 NetBSD 的 `syscalls.master` 文件。
2. **解析:**  程序会解析下载的文件，提取出系统调用的名称和对应的编号。
3. **生成 Go 代码:**  程序会将提取出的信息转换成 Go 语言的常量定义，并生成类似 `zsysnum_netbsd_arm64.go` 这样的文件。

**使用者易犯错的点：**

1. **直接使用系统调用号：**  初学者可能会尝试直接使用数字（例如 `1` 代表 `exit`）来调用系统调用，而不是使用 `syscall.SYS_EXIT` 这样的常量。这样做是不可取的，因为：
   * **可读性差：**  使用常量可以清晰地表达意图。
   * **平台不兼容：**  系统调用号在不同的操作系统和架构上可能不同，直接使用数字会导致代码在不同平台上的移植性很差。
   * **维护困难：**  如果系统调用号发生变化，所有直接使用数字的地方都需要修改，而使用常量只需要修改 `zsysnum_*.go` 文件。

   **错误示例：**
   ```go
   // 错误的示例，不应该直接使用数字 1
   _, _, err := syscall.Syscall(1, 0, 0, 0)
   ```

2. **混淆不同平台的系统调用号：**  开发者可能会错误地假设所有平台上的系统调用号都是相同的。例如，在 Linux 上 `SYS_EXIT` 的值可能是不同的。因此，在编写跨平台代码时，需要特别注意使用 `syscall` 包提供的平台相关的常量。

总结来说，`zsysnum_netbsd_arm64.go` 是 Go 语言 `syscall` 包在 NetBSD ARM64 平台上的核心组成部分，它定义了系统调用号常量，使得 Go 程序能够方便且正确地调用操作系统的底层功能。使用者应该始终使用这些常量，而不是直接使用数字，以保证代码的可读性和跨平台兼容性。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/zsysnum_netbsd_arm64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// go run mksysnum.go http://cvsweb.netbsd.org/bsdweb.cgi/~checkout~/src/sys/kern/syscalls.master
// Code generated by the command above; DO NOT EDIT.

//go:build arm64 && netbsd

package unix

const (
	SYS_EXIT                 = 1   // { void|sys||exit(int rval); }
	SYS_FORK                 = 2   // { int|sys||fork(void); }
	SYS_READ                 = 3   // { ssize_t|sys||read(int fd, void *buf, size_t nbyte); }
	SYS_WRITE                = 4   // { ssize_t|sys||write(int fd, const void *buf, size_t nbyte); }
	SYS_OPEN                 = 5   // { int|sys||open(const char *path, int flags, ... mode_t mode); }
	SYS_CLOSE                = 6   // { int|sys||close(int fd); }
	SYS_LINK                 = 9   // { int|sys||link(const char *path, const char *link); }
	SYS_UNLINK               = 10  // { int|sys||unlink(const char *path); }
	SYS_CHDIR                = 12  // { int|sys||chdir(const char *path); }
	SYS_FCHDIR               = 13  // { int|sys||fchdir(int fd); }
	SYS_CHMOD                = 15  // { int|sys||chmod(const char *path, mode_t mode); }
	SYS_CHOWN                = 16  // { int|sys||chown(const char *path, uid_t uid, gid_t gid); }
	SYS_BREAK                = 17  // { int|sys||obreak(char *nsize); }
	SYS_GETPID               = 20  // { pid_t|sys||getpid_with_ppid(void); }
	SYS_UNMOUNT              = 22  // { int|sys||unmount(const char *path, int flags); }
	SYS_SETUID               = 23  // { int|sys||setuid(uid_t uid); }
	SYS_GETUID               = 24  // { uid_t|sys||getuid_with_euid(void); }
	SYS_GETEUID              = 25  // { uid_t|sys||geteuid(void); }
	SYS_PTRACE               = 26  // { int|sys||ptrace(int req, pid_t pid, void *addr, int data); }
	SYS_RECVMSG              = 27  // { ssize_t|sys||recvmsg(int s, struct msghdr *msg, int flags); }
	SYS_SENDMSG              = 28  // { ssize_t|sys||sendmsg(int s, const struct msghdr *msg, int flags); }
	SYS_RECVFROM             = 29  // { ssize_t|sys||recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlenaddr); }
	SYS_ACCEPT               = 30  // { int|sys||accept(int s, struct sockaddr *name, socklen_t *anamelen); }
	SYS_GETPEERNAME          = 31  // { int|sys||getpeername(int fdes, struct sockaddr *asa, socklen_t *alen); }
	SYS_GETSOCKNAME          = 32  // { int|sys||getsockname(int fdes, struct sockaddr *asa, socklen_t *alen); }
	SYS_ACCESS               = 33  // { int|sys||access(const char *path, int flags); }
	SYS_CHFLAGS              = 34  // { int|sys||chflags(const char *path, u_long flags); }
	SYS_FCHFLAGS             = 35  // { int|sys||fchflags(int fd, u_long flags); }
	SYS_SYNC                 = 36  // { void|sys||sync(void); }
	SYS_KILL                 = 37  // { int|sys||kill(pid_t pid, int signum); }
	SYS_GETPPID              = 39  // { pid_t|sys||getppid(void); }
	SYS_DUP                  = 41  // { int|sys||dup(int fd); }
	SYS_PIPE                 = 42  // { int|sys||pipe(void); }
	SYS_GETEGID              = 43  // { gid_t|sys||getegid(void); }
	SYS_PROFIL               = 44  // { int|sys||profil(char *samples, size_t size, u_long offset, u_int scale); }
	SYS_KTRACE               = 45  // { int|sys||ktrace(const char *fname, int ops, int facs, pid_t pid); }
	SYS_GETGID               = 47  // { gid_t|sys||getgid_with_egid(void); }
	SYS___GETLOGIN           = 49  // { int|sys||__getlogin(char *namebuf, size_t namelen); }
	SYS___SETLOGIN           = 50  // { int|sys||__setlogin(const char *namebuf); }
	SYS_ACCT                 = 51  // { int|sys||acct(const char *path); }
	SYS_IOCTL                = 54  // { int|sys||ioctl(int fd, u_long com, ... void *data); }
	SYS_REVOKE               = 56  // { int|sys||revoke(const char *path); }
	SYS_SYMLINK              = 57  // { int|sys||symlink(const char *path, const char *link); }
	SYS_READLINK             = 58  // { ssize_t|sys||readlink(const char *path, char *buf, size_t count); }
	SYS_EXECVE               = 59  // { int|sys||execve(const char *path, char * const *argp, char * const *envp); }
	SYS_UMASK                = 60  // { mode_t|sys||umask(mode_t newmask); }
	SYS_CHROOT               = 61  // { int|sys||chroot(const char *path); }
	SYS_VFORK                = 66  // { int|sys||vfork(void); }
	SYS_SBRK                 = 69  // { int|sys||sbrk(intptr_t incr); }
	SYS_SSTK                 = 70  // { int|sys||sstk(int incr); }
	SYS_VADVISE              = 72  // { int|sys||ovadvise(int anom); }
	SYS_MUNMAP               = 73  // { int|sys||munmap(void *addr, size_t len); }
	SYS_MPROTECT             = 74  // { int|sys||mprotect(void *addr, size_t len, int prot); }
	SYS_MADVISE              = 75  // { int|sys||madvise(void *addr, size_t len, int behav); }
	SYS_MINCORE              = 78  // { int|sys||mincore(void *addr, size_t len, char *vec); }
	SYS_GETGROUPS            = 79  // { int|sys||getgroups(int gidsetsize, gid_t *gidset); }
	SYS_SETGROUPS            = 80  // { int|sys||setgroups(int gidsetsize, const gid_t *gidset); }
	SYS_GETPGRP              = 81  // { int|sys||getpgrp(void); }
	SYS_SETPGID              = 82  // { int|sys||setpgid(pid_t pid, pid_t pgid); }
	SYS_DUP2                 = 90  // { int|sys||dup2(int from, int to); }
	SYS_FCNTL                = 92  // { int|sys||fcntl(int fd, int cmd, ... void *arg); }
	SYS_FSYNC                = 95  // { int|sys||fsync(int fd); }
	SYS_SETPRIORITY          = 96  // { int|sys||setpriority(int which, id_t who, int prio); }
	SYS_CONNECT              = 98  // { int|sys||connect(int s, const struct sockaddr *name, socklen_t namelen); }
	SYS_GETPRIORITY          = 100 // { int|sys||getpriority(int which, id_t who); }
	SYS_BIND                 = 104 // { int|sys||bind(int s, const struct sockaddr *name, socklen_t namelen); }
	SYS_SETSOCKOPT           = 105 // { int|sys||setsockopt(int s, int level, int name, const void *val, socklen_t valsize); }
	SYS_LISTEN               = 106 // { int|sys||listen(int s, int backlog); }
	SYS_GETSOCKOPT           = 118 // { int|sys||getsockopt(int s, int level, int name, void *val, socklen_t *avalsize); }
	SYS_READV                = 120 // { ssize_t|sys||readv(int fd, const struct iovec *iovp, int iovcnt); }
	SYS_WRITEV               = 121 // { ssize_t|sys||writev(int fd, const struct iovec *iovp, int iovcnt); }
	SYS_FCHOWN               = 123 // { int|sys||fchown(int fd, uid_t uid, gid_t gid); }
	SYS_FCHMOD               = 124 // { int|sys||fchmod(int fd, mode_t mode); }
	SYS_SETREUID             = 126 // { int|sys||setreuid(uid_t ruid, uid_t euid); }
	SYS_SETREGID             = 127 // { int|sys||setregid(gid_t rgid, gid_t egid); }
	SYS_RENAME               = 128 // { int|sys||rename(const char *from, const char *to); }
	SYS_FLOCK                = 131 // { int|sys||flock(int fd, int how); }
	SYS_MKFIFO               = 132 // { int|sys||mkfifo(const char *path, mode_t mode); }
	SYS_SENDTO               = 133 // { ssize_t|sys||sendto(int s, const void *buf, size_t len, int flags, const struct sockaddr *to, socklen_t tolen); }
	SYS_SHUTDOWN             = 134 // { int|sys||shutdown(int s, int how); }
	SYS_SOCKETPAIR           = 135 // { int|sys||socketpair(int domain, int type, int protocol, int *rsv); }
	SYS_MKDIR                = 136 // { int|sys||mkdir(const char *path, mode_t mode); }
	SYS_RMDIR                = 137 // { int|sys||rmdir(const char *path); }
	SYS_SETSID               = 147 // { int|sys||setsid(void); }
	SYS_SYSARCH              = 165 // { int|sys||sysarch(int op, void *parms); }
	SYS_PREAD                = 173 // { ssize_t|sys||pread(int fd, void *buf, size_t nbyte, int PAD, off_t offset); }
	SYS_PWRITE               = 174 // { ssize_t|sys||pwrite(int fd, const void *buf, size_t nbyte, int PAD, off_t offset); }
	SYS_NTP_ADJTIME          = 176 // { int|sys||ntp_adjtime(struct timex *tp); }
	SYS_SETGID               = 181 // { int|sys||setgid(gid_t gid); }
	SYS_SETEGID              = 182 // { int|sys||setegid(gid_t egid); }
	SYS_SETEUID              = 183 // { int|sys||seteuid(uid_t euid); }
	SYS_PATHCONF             = 191 // { long|sys||pathconf(const char *path, int name); }
	SYS_FPATHCONF            = 192 // { long|sys||fpathconf(int fd, int name); }
	SYS_GETRLIMIT            = 194 // { int|sys||getrlimit(int which, struct rlimit *rlp); }
	SYS_SETRLIMIT            = 195 // { int|sys||setrlimit(int which, const struct rlimit *rlp); }
	SYS_MMAP                 = 197 // { void *|sys||mmap(void *addr, size_t len, int prot, int flags, int fd, long PAD, off_t pos); }
	SYS_LSEEK                = 199 // { off_t|sys||lseek(int fd, int PAD, off_t offset, int whence); }
	SYS_TRUNCATE             = 200 // { int|sys||truncate(const char *path, int PAD, off_t length); }
	SYS_FTRUNCATE            = 201 // { int|sys||ftruncate(int fd, int PAD, off_t length); }
	SYS___SYSCTL             = 202 // { int|sys||__sysctl(const int *name, u_int namelen, void *old, size_t *oldlenp, const void *new, size_t newlen); }
	SYS_MLOCK                = 203 // { int|sys||mlock(const void *addr, size_t len); }
	SYS_MUNLOCK              = 204 // { int|sys||munlock(const void *addr, size_t len); }
	SYS_UNDELETE             = 205 // { int|sys||undelete(const char *path); }
	SYS_GETPGID              = 207 // { pid_t|sys||getpgid(pid_t pid); }
	SYS_REBOOT               = 208 // { int|sys||reboot(int opt, char *bootstr); }
	SYS_POLL                 = 209 // { int|sys||poll(struct pollfd *fds, u_int nfds, int timeout); }
	SYS_SEMGET               = 221 // { int|sys||semget(key_t key, int nsems, int semflg); }
	SYS_SEMOP                = 222 // { int|sys||semop(int semid, struct sembuf *sops, size_t nsops); }
	SYS_SEMCONFIG            = 223 // { int|sys||semconfig(int flag); }
	SYS_MSGGET               = 225 // { int|sys||msgget(key_t key, int msgflg); }
	SYS_MSGSND               = 226 // { int|sys||msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg); }
	SYS_MSGRCV               = 227 // { ssize_t|sys||msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg); }
	SYS_SHMAT                = 228 // { void *|sys||shmat(int shmid, const void *shmaddr, int shmflg); }
	SYS_SHMDT                = 230 // { int|sys||shmdt(const void *shmaddr); }
	SYS_SHMGET               = 231 // { int|sys||shmget(key_t key, size_t size, int shmflg); }
	SYS_TIMER_CREATE         = 235 // { int|sys||timer_create(clockid_t clock_id, struct sigevent *evp, timer_t *timerid); }
	SYS_TIMER_DELETE         = 236 // { int|sys||timer_delete(timer_t timerid); }
	SYS_TIMER_GETOVERRUN     = 239 // { int|sys||timer_getoverrun(timer_t timerid); }
	SYS_FDATASYNC            = 241 // { int|sys||fdatasync(int fd); }
	SYS_MLOCKALL             = 242 // { int|sys||mlockall(int flags); }
	SYS_MUNLOCKALL           = 243 // { int|sys||munlockall(void); }
	SYS_SIGQUEUEINFO         = 245 // { int|sys||sigqueueinfo(pid_t pid, const siginfo_t *info); }
	SYS_MODCTL               = 246 // { int|sys||modctl(int cmd, void *arg); }
	SYS___POSIX_RENAME       = 270 // { int|sys||__posix_rename(const char *from, const char *to); }
	SYS_SWAPCTL              = 271 // { int|sys||swapctl(int cmd, void *arg, int misc); }
	SYS_MINHERIT             = 273 // { int|sys||minherit(void *addr, size_t len, int inherit); }
	SYS_LCHMOD               = 274 // { int|sys||lchmod(const char *path, mode_t mode); }
	SYS_LCHOWN               = 275 // { int|sys||lchown(const char *path, uid_t uid, gid_t gid); }
	SYS_MSYNC                = 277 // { int|sys|13|msync(void *addr, size_t len, int flags); }
	SYS___POSIX_CHOWN        = 283 // { int|sys||__posix_chown(const char *path, uid_t uid, gid_t gid); }
	SYS___POSIX_FCHOWN       = 284 // { int|sys||__posix_fchown(int fd, uid_t uid, gid_t gid); }
	SYS___POSIX_LCHOWN       = 285 // { int|sys||__posix_lchown(const char *path, uid_t uid, gid_t gid); }
	SYS_GETSID               = 286 // { pid_t|sys||getsid(pid_t pid); }
	SYS___CLONE              = 287 // { pid_t|sys||__clone(int flags, void *stack); }
	SYS_FKTRACE              = 288 // { int|sys||fktrace(int fd, int ops, int facs, pid_t pid); }
	SYS_PREADV               = 289 // { ssize_t|sys||preadv(int fd, const struct iovec *iovp, int iovcnt, int PAD, off_t offset); }
	SYS_PWRITEV              = 290 // { ssize_t|sys||pwritev(int fd, const struct iovec *iovp, int iovcnt, int PAD, off_t offset); }
	SYS___GETCWD             = 296 // { int|sys||__getcwd(char *bufp, size_t length); }
	SYS_FCHROOT              = 297 // { int|sys||fchroot(int fd); }
	SYS_LCHFLAGS             = 304 // { int|sys||lchflags(const char *path, u_long flags); }
	SYS_ISSETUGID            = 305 // { int|sys||issetugid(void); }
	SYS_UTRACE               = 306 // { int|sys||utrace(const char *label, void *addr, size_t len); }
	SYS_GETCONTEXT           = 307 // { int|sys||getcontext(struct __ucontext *ucp); }
	SYS_SETCONTEXT           = 308 // { int|sys||setcontext(const struct __ucontext *ucp); }
	SYS__LWP_CREATE          = 309 // { int|sys||_lwp_create(const struct __ucontext *ucp, u_long flags, lwpid_t *new_lwp); }
	SYS__LWP_EXIT            = 310 // { int|sys||_lwp_exit(void); }
	SYS__LWP_SELF            = 311 // { lwpid_t|sys||_lwp_self(void); }
	SYS__LWP_WAIT            = 312 // { int|sys||_lwp_wait(lwpid_t wait_for, lwpid_t *departed); }
	SYS__LWP_SUSPEND         = 313 // { int|sys||_lwp_suspend(lwpid_t target); }
	SYS__LWP_CONTINUE        = 314 // { int|sys||_lwp_continue(lwpid_t target); }
	SYS__LWP_WAKEUP          = 315 // { int|sys||_lwp_wakeup(lwpid_t target); }
	SYS__LWP_GETPRIVATE      = 316 // { void *|sys||_lwp_getprivate(void); }
	SYS__LWP_SETPRIVATE      = 317 // { void|sys||_lwp_setprivate(void *ptr); }
	SYS__LWP_KILL            = 318 // { int|sys||_lwp_kill(lwpid_t target, int signo); }
	SYS__LWP_DETACH          = 319 // { int|sys||_lwp_detach(lwpid_t target); }
	SYS__LWP_UNPARK          = 321 // { int|sys||_lwp_unpark(lwpid_t target, const void *hint); }
	SYS__LWP_UNPARK_ALL      = 322 // { ssize_t|sys||_lwp_unpark_all(const lwpid_t *targets, size_t ntargets, const void *hint); }
	SYS__LWP_SETNAME         = 323 // { int|sys||_lwp_setname(lwpid_t target, const char *name); }
	SYS__LWP_GETNAME         = 324 // { int|sys||_lwp_getname(lwpid_t target, char *name, size_t len); }
	SYS__LWP_CTL             = 325 // { int|sys||_lwp_ctl(int features, struct lwpctl **address); }
	SYS___SIGACTION_SIGTRAMP = 340 // { int|sys||__sigaction_sigtramp(int signum, const struct sigaction *nsa, struct sigaction *osa, const void *tramp, int vers); }
	SYS_PMC_GET_INFO         = 341 // { int|sys||pmc_get_info(int ctr, int op, void *args); }
	SYS_PMC_CONTROL          = 342 // { int|sys||pmc_control(int ctr, int op, void *args); }
	SYS_RASCTL               = 343 // { int|sys||rasctl(void *addr, size_t len, int op); }
	SYS_KQUEUE               = 344 // { int|sys||kqueue(void); }
	SYS__SCHED_SETPARAM      = 346 // { int|sys||_sched_setparam(pid_t pid, lwpid_t lid, int policy, const struct sched_param *params); }
	SYS__SCHED_GETPARAM      = 347 // { int|sys||_sched_getparam(pid_t pid, lwpid_t lid, int *policy, struct sched_param *params); }
	SYS__SCHED_SETAFFINITY   = 348 // { int|sys||_sched_setaffinity(pid_t pid, lwpid_t lid, size_t size, const cpuset_t *cpuset); }
	SYS__SCHED_GETAFFINITY   = 349 // { int|sys||_sched_getaffinity(pid_t pid, lwpid_t lid, size_t size, cpuset_t *cpuset); }
	SYS_SCHED_YIELD          = 350 // { int|sys||sched_yield(void); }
	SYS_FSYNC_RANGE          = 354 // { int|sys||fsync_range(int fd, int flags, off_t start, off_t length); }
	SYS_UUIDGEN              = 355 // { int|sys||uuidgen(struct uuid *store, int count); }
	SYS_GETVFSSTAT           = 356 // { int|sys||getvfsstat(struct statvfs *buf, size_t bufsize, int flags); }
	SYS_STATVFS1             = 357 // { int|sys||statvfs1(const char *path, struct statvfs *buf, int flags); }
	SYS_FSTATVFS1            = 358 // { int|sys||fstatvfs1(int fd, struct statvfs *buf, int flags); }
	SYS_EXTATTRCTL           = 360 // { int|sys||extattrctl(const char *path, int cmd, const char *filename, int attrnamespace, const char *attrname); }
	SYS_EXTATTR_SET_FILE     = 361 // { int|sys||extattr_set_file(const char *path, int attrnamespace, const char *attrname, const void *data, size_t nbytes); }
	SYS_EXTATTR_GET_FILE     = 362 // { ssize_t|sys||extattr_get_file(const char *path, int attrnamespace, const char *attrname, void *data, size_t nbytes); }
	SYS_EXTATTR_DELETE_FILE  = 363 // { int|sys||extattr_delete_file(const char *path, int attrnamespace, const char *attrname); }
	SYS_EXTATTR_SET_FD       = 364 // { int|sys||extattr_set_fd(int fd, int attrnamespace, const char *attrname, const void *data, size_t nbytes); }
	SYS_EXTATTR_GET_FD       = 365 // { ssize_t|sys||extattr_get_fd(int fd, int attrnamespace, const char *attrname, void *data, size_t nbytes); }
	SYS_EXTATTR_DELETE_FD    = 366 // { int|sys||extattr_delete_fd(int fd, int attrnamespace, const char *attrname); }
	SYS_EXTATTR_SET_LINK     = 367 // { int|sys||extattr_set_link(const char *path, int attrnamespace, const char *attrname, const void *data, size_t nbytes); }
	SYS_EXTATTR_GET_LINK     = 368 // { ssize_t|sys||extattr_get_link(const char *path, int attrnamespace, const char *attrname, void *data, size_t nbytes); }
	SYS_EXTATTR_DELETE_LINK  = 369 // { int|sys||extattr_delete_link(const char *path, int attrnamespace, const char *attrname); }
	SYS_EXTATTR_LIST_FD      = 370 // { ssize_t|sys||extattr_list_fd(int fd, int attrnamespace, void *data, size_t nbytes); }
	SYS_EXTATTR_LIST_FILE    = 371 // { ssize_t|sys||extattr_list_file(const char *path, int attrnamespace, void *data, size_t nbytes); }
	SYS_EXTATTR_LIST_LINK    = 372 // { ssize_t|sys||extattr_list_link(const char *path, int attrnamespace, void *data, size_t nbytes); }
	SYS_SETXATTR             = 375 // { int|sys||setxattr(const char *path, const char *name, const void *value, size_t size, int flags); }
	SYS_LSETXATTR            = 376 // { int|sys||lsetxattr(const char *path, const char *name, const void *value, size_t size, int flags); }
	SYS_FSETXATTR            = 377 // { int|sys||fsetxattr(int fd, const char *name, const void *value, size_t size, int flags); }
	SYS_GETXATTR             = 378 // { int|sys||getxattr(const char *path, const char *name, void *value, size_t size); }
	SYS_LGETXATTR            = 379 // { int|sys||lgetxattr(const char *path, const char *name, void *value, size_t size); }
	SYS_FGETXATTR            = 380 // { int|sys||fgetxattr(int fd, const char *name, void *value, size_t size); }
	SYS_LISTXATTR            = 381 // { int|sys||listxattr(const char *path, char *list, size_t size); }
	SYS_LLISTXATTR           = 382 // { int|sys||llistxattr(const char *path, char *list, size_t size); }
	SYS_FLISTXATTR           = 383 // { int|sys||flistxattr(int fd, char *list, size_t size); }
	SYS_REMOVEXATTR          = 384 // { int|sys||removexattr(const char *path, const char *name); }
	SYS_LREMOVEXATTR         = 385 // { int|sys||lremovexattr(const char *path, const char *name); }
	SYS_FREMOVEXATTR         = 386 // { int|sys||fremovexattr(int fd, const char *name); }
	SYS_GETDENTS             = 390 // { int|sys|30|getdents(int fd, char *buf, size_t count); }
	SYS_SOCKET               = 394 // { int|sys|30|socket(int domain, int type, int protocol); }
	SYS_GETFH                = 395 // { int|sys|30|getfh(const char *fname, void *fhp, size_t *fh_size); }
	SYS_MOUNT                = 410 // { int|sys|50|mount(const char *type, const char *path, int flags, void *data, size_t data_len); }
	SYS_MREMAP               = 411 // { void *|sys||mremap(void *old_address, size_t old_size, void *new_address, size_t new_size, int flags); }
	SYS_PSET_CREATE          = 412 // { int|sys||pset_create(psetid_t *psid); }
	SYS_PSET_DESTROY         = 413 // { int|sys||pset_destroy(psetid_t psid); }
	SYS_PSET_ASSIGN          = 414 // { int|sys||pset_assign(psetid_t psid, cpuid_t cpuid, psetid_t *opsid); }
	SYS__PSET_BIND           = 415 // { int|sys||_pset_bind(idtype_t idtype, id_t first_id, id_t second_id, psetid_t psid, psetid_t *opsid); }
	SYS_POSIX_FADVISE        = 416 // { int|sys|50|posix_fadvise(int fd, int PAD, off_t offset, off_t len, int advice); }
	SYS_SELECT               = 417 // { int|sys|50|select(int nd, fd_set *in, fd_set *ou, fd_set *ex, struct timeval *tv); }
	SYS_GETTIMEOFDAY         = 418 // { int|sys|50|gettimeofday(struct timeval *tp, void *tzp); }
	SYS_SETTIMEOFDAY         = 419 // { int|sys|50|settimeofday(const struct timeval *tv, const void *tzp); }
	SYS_UTIMES               = 420 // { int|sys|50|utimes(const char *path, const struct timeval *tptr); }
	SYS_ADJTIME              = 421 // { int|sys|50|adjtime(const struct timeval *delta, struct timeval *olddelta); }
	SYS_FUTIMES              = 423 // { int|sys|50|futimes(int fd, const struct timeval *tptr); }
	SYS_LUTIMES              = 424 // { int|sys|50|lutimes(const char *path, const struct timeval *tptr); }
	SYS_SETITIMER            = 425 // { int|sys|50|setitimer(int which, const struct itimerval *itv, struct itimerval *oitv); }
	SYS_GETITIMER            = 426 // { int|sys|50|getitimer(int which, struct itimerval *itv); }
	SYS_CLOCK_GETTIME        = 427 // { int|sys|50|clock_gettime(clockid_t clock_id, struct timespec *tp); }
	SYS_CLOCK_SETTIME        = 428 // { int|sys|50|clock_settime(clockid_t clock_id, const struct timespec *tp); }
	SYS_CLOCK_GETRES         = 429 // { int|sys|50|clock_getres(clockid_t clock_id, struct timespec *tp); }
	SYS_NANOSLEEP            = 430 // { int|sys|50|nanosleep(const struct timespec *rqtp, struct timespec *rmtp); }
	SYS___SIGTIMEDWAIT       = 431 // { int|sys|50|__sigtimedwait(const sigset_t *set, siginfo_t *info, struct timespec *timeout); }
	SYS__LWP_PARK            = 434 // { int|sys|50|_lwp_park(const struct timespec *ts, lwpid_t unpark, const void *hint, const void *unparkhint); }
	SYS_KEVENT               = 435 // { int|sys|50|kevent(int fd, const struct kevent *changelist, size_t nchanges, struct kevent *eventlist, size_t nevents, const struct timespec *timeout); }
	SYS_PSELECT              = 436 // { int|sys|50|pselect(int nd, fd_set *in, fd_set *ou, fd_set *ex, const struct timespec *ts, const sigset_t *mask); }
	SYS_POLLTS               = 437 // { int|sys|50|pollts(struct pollfd *fds, u_int nfds, const struct timespec *ts, const sigset_t *mask); }
	SYS_STAT                 = 439 // { int|sys|50|stat(const char *path, struct stat *ub); }
	SYS_FSTAT                = 440 // { int|sys|50|fstat(int fd, struct stat *sb); }
	SYS_LSTAT                = 441 // { int|sys|50|lstat(const char *path, struct stat *ub); }
	SYS___SEMCTL             = 442 // { int|sys|50|__semctl(int semid, int semnum, int cmd, ... union __semun *arg); }
	SYS_SHMCTL               = 443 // { int|sys|50|shmctl(int shmid, int cmd, struct shmid_ds *buf); }
	SYS_MSGCTL               = 444 // { int|sys|50|msgctl(int msqid, int cmd, struct msqid_ds *buf); }
	SYS_GETRUSAGE            = 445 // { int|sys|50|getrusage(int who, struct rusage *rusage); }
	SYS_TIMER_SETTIME        = 446 // { int|sys|50|timer_settime(timer_t timerid, int flags, const struct itimerspec *value, struct itimerspec *ovalue); }
	SYS_TIMER_GETTIME        = 447 // { int|sys|50|timer_gettime(timer_t timerid, struct itimerspec *value); }
	SYS_NTP_GETTIME          = 448 // { int|sys|50|ntp_gettime(struct ntptimeval *ntvp); }
	SYS_WAIT4                = 449 // { int|sys|50|wait4(pid_t pid, int *status, int options, struct rusage *rusage); }
	SYS_MKNOD                = 450 // { int|sys|50|mknod(const char *path, mode_t mode, dev_t dev); }
	SYS_FHSTAT               = 451 // { int|sys|50|fhstat(const void *fhp, size_t fh_size, struct stat *sb); }
	SYS_PIPE2                = 453 // { int|sys||pipe2(int *fildes, int flags); }
	SYS_DUP3                 = 454 // { int|sys||dup3(int from, int to, int flags); }
	SYS_KQUEUE1              = 455 // { int|sys||kqueue1(int flags); }
	SYS_PACCEPT              = 456 // { int|sys||paccept(int s, struct sockaddr *name, socklen_t *anamelen, const sigset_t *mask, int flags); }
	SYS_LINKAT               = 457 // { int|sys||linkat(int fd1, const char *name1, int fd2, const char *name2, int flags); }
	SYS_RENAMEAT             = 458 // { int|sys||renameat(int fromfd, const char *from, int tofd, const char *to); }
	SYS_MKFIFOAT             = 459 // { int|sys||mkfifoat(int fd, const char *path, mode_t mode); }
	SYS_MKNODAT              = 460 // { int|sys||mknodat(int fd, const char *path, mode_t mode, uint32_t dev); }
	SYS_MKDIRAT              = 461 // { int|sys||mkdirat(int fd, const char *path, mode_t mode); }
	SYS_FACCESSAT            = 462 // { int|sys||faccessat(int fd, const char *path, int amode, int flag); }
	SYS_FCHMODAT             = 463 // { int|sys||fchmodat(int fd, const char *path, mode_t mode, int flag); }
	SYS_FCHOWNAT             = 464 // { int|sys||fchownat(int fd, const char *path, uid_t owner, gid_t group, int flag); }
	SYS_FEXECVE              = 465 // { int|sys||fexecve(int fd, char * const *argp, char * const *envp); }
	SYS_FSTATAT              = 466 // { int|sys||fstatat(int fd, const char *path, struct stat *buf, int flag); }
	SYS_UTIMENSAT            = 467 // { int|sys||utimensat(int fd, const char *path, const struct timespec *tptr, int flag); }
	SYS_OPENAT               = 468 // { int|sys||openat(int fd, const char *path, int oflags, ... mode_t mode); }
	SYS_READLINKAT           = 469 // { int|sys||readlinkat(int fd, const char *path, char *buf, size_t bufsize); }
	SYS_SYMLINKAT            = 470 // { int|sys||symlinkat(const char *path1, int fd, const char *path2); }
	SYS_UNLINKAT             = 471 // { int|sys||unlinkat(int fd, const char *path, int flag); }
	SYS_FUTIMENS             = 472 // { int|sys||futimens(int fd, const struct timespec *tptr); }
	SYS___QUOTACTL           = 473 // { int|sys||__quotactl(const char *path, struct quotactl_args *args); }
	SYS_POSIX_SPAWN          = 474 // { int|sys||posix_spawn(pid_t *pid, const char *path, const struct posix_spawn_file_actions *file_actions, const struct posix_spawnattr *attrp, char *const *argv, char *const *envp); }
	SYS_RECVMMSG             = 475 // { int|sys||recvmmsg(int s, struct mmsghdr *mmsg, unsigned int vlen, unsigned int flags, struct timespec *timeout); }
	SYS_SENDMMSG             = 476 // { int|sys||sendmmsg(int s, struct mmsghdr *mmsg, unsigned int vlen, unsigned int flags); }
)

"""



```