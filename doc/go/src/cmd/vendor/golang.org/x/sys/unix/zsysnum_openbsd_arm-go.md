Response:
Let's break down the thought process to analyze the given Go code snippet.

1. **Identify the Core Purpose:** The first thing that jumps out is the `// Code generated by the command above; see README.md. DO NOT EDIT.`  This immediately tells us this isn't hand-written code, but rather machine-generated. The command itself `go run mksysnum.go ...` gives a hint: it's likely mapping system call numbers.

2. **Examine the File Path:** The path `go/src/cmd/vendor/golang.org/x/sys/unix/zsysnum_openbsd_arm.go` is very informative:
    * `go/src`:  Indicates this is part of the Go standard library or an extended package.
    * `cmd/vendor`:  Suggests this code might be vendored (copied) from an external source.
    * `golang.org/x/sys`: This is the `sys` package, which provides lower-level system interfaces.
    * `unix`:  Specifically targets Unix-like operating systems.
    * `zsysnum_openbsd_arm.go`:  The `zsysnum` prefix and the `openbsd_arm` suffix are key. `z` often indicates generated code. `openbsd` specifies the operating system, and `arm` the architecture. Putting it together, it looks like a file mapping system call numbers for OpenBSD on ARM.

3. **Analyze the Code Structure:** The code consists of:
    * A comment indicating it's generated.
    * A `//go:build arm && openbsd` directive: This is a build constraint, meaning this file will *only* be compiled when the target operating system is OpenBSD and the architecture is ARM. This confirms the filepath's implication.
    * A `package unix` declaration: It belongs to the `unix` package.
    * `// Deprecated: Use libc wrappers instead of direct syscalls.`: This is a crucial hint. It explains *why* this file exists but also advises against using it directly. It suggests Go prefers using standard C library functions for system calls.
    * A `const` block defining a series of constants starting with `SYS_`: These look like system call numbers. The comments next to each constant provide the C signature of the corresponding system call.

4. **Infer Functionality:** Based on the above observations, the core functionality is clear: **This file defines constants representing the system call numbers for the OpenBSD operating system on the ARM architecture.**  It's essentially a lookup table that maps symbolic names (e.g., `SYS_READ`) to their numerical values (e.g., `3`).

5. **Reason about Go Language Feature:**  This code snippet is directly related to Go's ability to perform **system calls**. While Go prefers using higher-level abstractions, sometimes direct interaction with the kernel is necessary. This file provides the low-level mapping required for that.

6. **Construct a Go Code Example (and Anticipate the "Deprecated" Warning):**  Since the code is deprecated, any direct usage would likely involve the `syscall` package. A simple example of making a system call would involve `syscall.Syscall`. It's important to include the warning about deprecation when providing this example.

7. **Consider Command-Line Arguments:** The comment `// go run mksysnum.go ...` indicates that the file itself is generated by a script (`mksysnum.go`). The URL points to the OpenBSD syscall definition file. Therefore, the command-line argument to `mksysnum.go` is the URL of the `syscalls.master` file.

8. **Think about Potential Mistakes:** The "Deprecated" comment is the biggest clue here. Users might be tempted to directly use these `SYS_` constants with `syscall.Syscall`, which is discouraged. The preferred way is to use the functions in the standard library (e.g., `os.Open`, `os.Read`, etc.) which handle the system call invocation internally in a more portable and maintainable way.

9. **Structure the Output:** Finally, organize the findings into clear sections: Functions, Go Language Feature, Code Example, Command-Line Arguments, and Common Mistakes. Use clear and concise language. Highlight important information (like the deprecation warning).

**Self-Correction/Refinement during the process:**

* **Initial Thought:** Maybe this is involved in implementing some low-level I/O.
* **Correction:** While related to I/O, its primary purpose is the *mapping* of system call numbers, not the I/O operations themselves. The higher-level I/O functions would *use* these constants.
* **Initial Thought:**  Focus on how `syscall.Syscall` works.
* **Refinement:** While relevant, emphasize the *deprecation* and the preferred alternative (using standard library functions). The existence of this file is about the *possibility* of direct syscalls, but the recommendation is against it.

By following these steps of identification, analysis, inference, and refinement, we can arrive at a comprehensive understanding of the provided Go code snippet.
这是路径为 `go/src/cmd/vendor/golang.org/x/sys/unix/zsysnum_openbsd_arm.go` 的 Go 语言实现的一部分，它定义了一系列常量，这些常量代表了 **OpenBSD 操作系统在 ARM 架构下的系统调用号 (syscall numbers)**。

**功能列举：**

1. **定义系统调用号常量:**  该文件定义了大量的常量，每个常量都以 `SYS_` 开头，例如 `SYS_EXIT`, `SYS_READ`, `SYS_OPEN` 等。这些常量的值是与 OpenBSD 内核中对应的系统调用关联的数字。

2. **为 `syscall` 包提供底层支持:**  Go 语言的 `syscall` 包允许程序直接进行系统调用。这个文件提供的常量是 `syscall` 包在 OpenBSD/ARM 架构下构建系统调用时所必需的。

3. **作为 `mksysnum.go` 脚本的输出:** 文件开头的注释表明，这个文件是由 `mksysnum.go` 脚本生成的。该脚本从 OpenBSD 的源代码仓库中抓取系统调用定义，并将其转换为 Go 代码。

**Go 语言功能的实现：直接系统调用 (Direct System Calls)**

这个文件是 Go 语言中进行**直接系统调用**的一种底层实现方式的一部分。虽然 Go 官方更推荐使用标准库中封装好的函数 (例如 `os` 包, `io` 包等)，但在某些特殊情况下，可能需要直接调用系统调用以获得更底层的控制或访问特定功能。

**Go 代码举例：**

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	// 假设我们要直接调用 OpenBSD 的 SYS_GETPID 系统调用
	// 注意：直接使用 syscall 包进行系统调用通常不是推荐的做法，
	// 除非你有充分的理由并且了解其风险。

	pid, _, err := syscall.Syscall(syscall.SYS_GETPID, 0, 0, 0)
	if err != 0 {
		fmt.Printf("系统调用失败: %v\n", err)
		return
	}
	fmt.Printf("进程 PID: %d\n", pid)

	// 尝试直接打开一个文件 (不推荐，应该使用 os.Open)
	path := "/etc/passwd"
	pathPtr, _ := syscall.BytePtrFromString(path)
	fd, _, err := syscall.Syscall(syscall.SYS_OPEN, uintptr(unsafe.Pointer(pathPtr)), uintptr(syscall.O_RDONLY), 0)
	if err != 0 {
		fmt.Printf("打开文件失败: %v\n", err)
	} else {
		fmt.Printf("文件描述符: %d\n", fd)
		syscall.Close(int(fd)) // 记得关闭文件描述符
	}
}
```

**假设的输入与输出：**

在这个例子中，没有直接的“输入”。系统调用本身的行为依赖于操作系统状态。

**输出：**

```
进程 PID: <当前进程的PID>
文件描述符: <成功打开文件后的文件描述符，例如 3>
```

如果打开文件失败，输出可能是：

```
进程 PID: <当前进程的PID>
打开文件失败: no such file or directory
```

**命令行参数的具体处理：**

该文件本身不处理命令行参数。它是 `mksysnum.go` 脚本的输出结果。`mksysnum.go` 脚本的命令行参数是 OpenBSD 系统调用定义的 URL，如文件开头的注释所示：

```
// go run mksysnum.go https://cvsweb.openbsd.org/cgi-bin/cvsweb/~checkout~/src/sys/kern/syscalls.master
```

这个命令会：

1. 使用 `go run` 运行 `mksysnum.go` 脚本。
2. 将 `https://cvsweb.openbsd.org/cgi-bin/cvsweb/~checkout~/src/sys/kern/syscalls.master` 作为参数传递给 `mksysnum.go`。
3. `mksysnum.go` 脚本会下载该 URL 指向的 OpenBSD 系统调用定义文件。
4. 解析该文件，提取系统调用名称和对应的编号。
5. 生成类似 `zsysnum_openbsd_arm.go` 这样的 Go 代码文件，其中包含了系统调用号的常量定义。

**使用者易犯错的点：**

1. **直接使用 `syscall` 包进行系统调用:** 这是最常见的错误。Go 官方强烈建议使用标准库提供的更高级别的抽象，例如 `os` 包用于文件操作，`net` 包用于网络操作等。直接使用 `syscall` 会使代码更难维护、更不具备平台移植性，并且容易出错。

   **错误示例：**

   ```go
   package main

   import (
       "fmt"
       "syscall"
       "unsafe"
   )

   func main() {
       path := "/tmp/test.txt"
       pathPtr, _ := syscall.BytePtrFromString(path)
       // 直接使用 syscall.SYS_OPEN，而没有正确处理标志和权限
       fd, _, err := syscall.Syscall(syscall.SYS_OPEN, uintptr(unsafe.Pointer(pathPtr)), syscall.O_RDWR|syscall.O_CREAT, 0644)
       if err != 0 {
           fmt.Printf("打开文件失败: %v\n", err)
           return
       }
       fmt.Println("文件打开成功")
       syscall.Close(int(fd))
   }
   ```

   **正确做法：**

   ```go
   package main

   import (
       "fmt"
       "os"
   )

   func main() {
       path := "/tmp/test.txt"
       file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
       if err != nil {
           fmt.Printf("打开文件失败: %v\n", err)
           return
       }
       fmt.Println("文件打开成功")
       file.Close()
   }
   ```

2. **不理解系统调用的参数和返回值:** 系统调用的参数和返回值与 Go 语言的类型系统不同。直接使用 `syscall.Syscall` 需要对底层的 C 接口有深刻的理解，包括指针、大小、错误码等等。不正确的参数传递会导致程序崩溃或产生不可预测的行为。

3. **忽略错误处理:** 系统调用可能会失败，并且通常通过返回值或全局的 `errno` 变量来指示错误。在使用 `syscall.Syscall` 时，必须仔细检查返回值中的错误信息，并进行适当的处理。

4. **平台依赖性:**  `zsysnum_openbsd_arm.go` 中定义的常量只适用于 OpenBSD 操作系统在 ARM 架构下。直接使用这些常量编写的代码将无法在其他操作系统或架构上运行。这就是为什么 Go 鼓励使用更高级别的、平台无关的抽象。

总之，`zsysnum_openbsd_arm.go` 是 Go 语言在 OpenBSD/ARM 平台上进行底层系统调用的基础设施之一。虽然它为直接操作提供了可能，但除非有特殊需求且具备充分的专业知识，否则应优先使用 Go 标准库中提供的更安全、更易用、更具移植性的接口。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/zsysnum_openbsd_arm.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// go run mksysnum.go https://cvsweb.openbsd.org/cgi-bin/cvsweb/~checkout~/src/sys/kern/syscalls.master
// Code generated by the command above; see README.md. DO NOT EDIT.

//go:build arm && openbsd

package unix

// Deprecated: Use libc wrappers instead of direct syscalls.
const (
	SYS_EXIT           = 1   // { void sys_exit(int rval); }
	SYS_FORK           = 2   // { int sys_fork(void); }
	SYS_READ           = 3   // { ssize_t sys_read(int fd, void *buf, size_t nbyte); }
	SYS_WRITE          = 4   // { ssize_t sys_write(int fd, const void *buf, size_t nbyte); }
	SYS_OPEN           = 5   // { int sys_open(const char *path, int flags, ... mode_t mode); }
	SYS_CLOSE          = 6   // { int sys_close(int fd); }
	SYS_GETENTROPY     = 7   // { int sys_getentropy(void *buf, size_t nbyte); }
	SYS___TFORK        = 8   // { int sys___tfork(const struct __tfork *param, size_t psize); }
	SYS_LINK           = 9   // { int sys_link(const char *path, const char *link); }
	SYS_UNLINK         = 10  // { int sys_unlink(const char *path); }
	SYS_WAIT4          = 11  // { pid_t sys_wait4(pid_t pid, int *status, int options, struct rusage *rusage); }
	SYS_CHDIR          = 12  // { int sys_chdir(const char *path); }
	SYS_FCHDIR         = 13  // { int sys_fchdir(int fd); }
	SYS_MKNOD          = 14  // { int sys_mknod(const char *path, mode_t mode, dev_t dev); }
	SYS_CHMOD          = 15  // { int sys_chmod(const char *path, mode_t mode); }
	SYS_CHOWN          = 16  // { int sys_chown(const char *path, uid_t uid, gid_t gid); }
	SYS_OBREAK         = 17  // { int sys_obreak(char *nsize); } break
	SYS_GETDTABLECOUNT = 18  // { int sys_getdtablecount(void); }
	SYS_GETRUSAGE      = 19  // { int sys_getrusage(int who, struct rusage *rusage); }
	SYS_GETPID         = 20  // { pid_t sys_getpid(void); }
	SYS_MOUNT          = 21  // { int sys_mount(const char *type, const char *path, int flags, void *data); }
	SYS_UNMOUNT        = 22  // { int sys_unmount(const char *path, int flags); }
	SYS_SETUID         = 23  // { int sys_setuid(uid_t uid); }
	SYS_GETUID         = 24  // { uid_t sys_getuid(void); }
	SYS_GETEUID        = 25  // { uid_t sys_geteuid(void); }
	SYS_PTRACE         = 26  // { int sys_ptrace(int req, pid_t pid, caddr_t addr, int data); }
	SYS_RECVMSG        = 27  // { ssize_t sys_recvmsg(int s, struct msghdr *msg, int flags); }
	SYS_SENDMSG        = 28  // { ssize_t sys_sendmsg(int s, const struct msghdr *msg, int flags); }
	SYS_RECVFROM       = 29  // { ssize_t sys_recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlenaddr); }
	SYS_ACCEPT         = 30  // { int sys_accept(int s, struct sockaddr *name, socklen_t *anamelen); }
	SYS_GETPEERNAME    = 31  // { int sys_getpeername(int fdes, struct sockaddr *asa, socklen_t *alen); }
	SYS_GETSOCKNAME    = 32  // { int sys_getsockname(int fdes, struct sockaddr *asa, socklen_t *alen); }
	SYS_ACCESS         = 33  // { int sys_access(const char *path, int amode); }
	SYS_CHFLAGS        = 34  // { int sys_chflags(const char *path, u_int flags); }
	SYS_FCHFLAGS       = 35  // { int sys_fchflags(int fd, u_int flags); }
	SYS_SYNC           = 36  // { void sys_sync(void); }
	SYS_STAT           = 38  // { int sys_stat(const char *path, struct stat *ub); }
	SYS_GETPPID        = 39  // { pid_t sys_getppid(void); }
	SYS_LSTAT          = 40  // { int sys_lstat(const char *path, struct stat *ub); }
	SYS_DUP            = 41  // { int sys_dup(int fd); }
	SYS_FSTATAT        = 42  // { int sys_fstatat(int fd, const char *path, struct stat *buf, int flag); }
	SYS_GETEGID        = 43  // { gid_t sys_getegid(void); }
	SYS_PROFIL         = 44  // { int sys_profil(caddr_t samples, size_t size, u_long offset, u_int scale); }
	SYS_KTRACE         = 45  // { int sys_ktrace(const char *fname, int ops, int facs, pid_t pid); }
	SYS_SIGACTION      = 46  // { int sys_sigaction(int signum, const struct sigaction *nsa, struct sigaction *osa); }
	SYS_GETGID         = 47  // { gid_t sys_getgid(void); }
	SYS_SIGPROCMASK    = 48  // { int sys_sigprocmask(int how, sigset_t mask); }
	SYS_SETLOGIN       = 50  // { int sys_setlogin(const char *namebuf); }
	SYS_ACCT           = 51  // { int sys_acct(const char *path); }
	SYS_SIGPENDING     = 52  // { int sys_sigpending(void); }
	SYS_FSTAT          = 53  // { int sys_fstat(int fd, struct stat *sb); }
	SYS_IOCTL          = 54  // { int sys_ioctl(int fd, u_long com, ... void *data); }
	SYS_REBOOT         = 55  // { int sys_reboot(int opt); }
	SYS_REVOKE         = 56  // { int sys_revoke(const char *path); }
	SYS_SYMLINK        = 57  // { int sys_symlink(const char *path, const char *link); }
	SYS_READLINK       = 58  // { ssize_t sys_readlink(const char *path, char *buf, size_t count); }
	SYS_EXECVE         = 59  // { int sys_execve(const char *path, char * const *argp, char * const *envp); }
	SYS_UMASK          = 60  // { mode_t sys_umask(mode_t newmask); }
	SYS_CHROOT         = 61  // { int sys_chroot(const char *path); }
	SYS_GETFSSTAT      = 62  // { int sys_getfsstat(struct statfs *buf, size_t bufsize, int flags); }
	SYS_STATFS         = 63  // { int sys_statfs(const char *path, struct statfs *buf); }
	SYS_FSTATFS        = 64  // { int sys_fstatfs(int fd, struct statfs *buf); }
	SYS_FHSTATFS       = 65  // { int sys_fhstatfs(const fhandle_t *fhp, struct statfs *buf); }
	SYS_VFORK          = 66  // { int sys_vfork(void); }
	SYS_GETTIMEOFDAY   = 67  // { int sys_gettimeofday(struct timeval *tp, struct timezone *tzp); }
	SYS_SETTIMEOFDAY   = 68  // { int sys_settimeofday(const struct timeval *tv, const struct timezone *tzp); }
	SYS_SETITIMER      = 69  // { int sys_setitimer(int which, const struct itimerval *itv, struct itimerval *oitv); }
	SYS_GETITIMER      = 70  // { int sys_getitimer(int which, struct itimerval *itv); }
	SYS_SELECT         = 71  // { int sys_select(int nd, fd_set *in, fd_set *ou, fd_set *ex, struct timeval *tv); }
	SYS_KEVENT         = 72  // { int sys_kevent(int fd, const struct kevent *changelist, int nchanges, struct kevent *eventlist, int nevents, const struct timespec *timeout); }
	SYS_MUNMAP         = 73  // { int sys_munmap(void *addr, size_t len); }
	SYS_MPROTECT       = 74  // { int sys_mprotect(void *addr, size_t len, int prot); }
	SYS_MADVISE        = 75  // { int sys_madvise(void *addr, size_t len, int behav); }
	SYS_UTIMES         = 76  // { int sys_utimes(const char *path, const struct timeval *tptr); }
	SYS_FUTIMES        = 77  // { int sys_futimes(int fd, const struct timeval *tptr); }
	SYS_MINCORE        = 78  // { int sys_mincore(void *addr, size_t len, char *vec); }
	SYS_GETGROUPS      = 79  // { int sys_getgroups(int gidsetsize, gid_t *gidset); }
	SYS_SETGROUPS      = 80  // { int sys_setgroups(int gidsetsize, const gid_t *gidset); }
	SYS_GETPGRP        = 81  // { int sys_getpgrp(void); }
	SYS_SETPGID        = 82  // { int sys_setpgid(pid_t pid, pid_t pgid); }
	SYS_FUTEX          = 83  // { int sys_futex(uint32_t *f, int op, int val, const struct timespec *timeout, uint32_t *g); }
	SYS_UTIMENSAT      = 84  // { int sys_utimensat(int fd, const char *path, const struct timespec *times, int flag); }
	SYS_FUTIMENS       = 85  // { int sys_futimens(int fd, const struct timespec *times); }
	SYS_KBIND          = 86  // { int sys_kbind(const struct __kbind *param, size_t psize, int64_t proc_cookie); }
	SYS_CLOCK_GETTIME  = 87  // { int sys_clock_gettime(clockid_t clock_id, struct timespec *tp); }
	SYS_CLOCK_SETTIME  = 88  // { int sys_clock_settime(clockid_t clock_id, const struct timespec *tp); }
	SYS_CLOCK_GETRES   = 89  // { int sys_clock_getres(clockid_t clock_id, struct timespec *tp); }
	SYS_DUP2           = 90  // { int sys_dup2(int from, int to); }
	SYS_NANOSLEEP      = 91  // { int sys_nanosleep(const struct timespec *rqtp, struct timespec *rmtp); }
	SYS_FCNTL          = 92  // { int sys_fcntl(int fd, int cmd, ... void *arg); }
	SYS_ACCEPT4        = 93  // { int sys_accept4(int s, struct sockaddr *name, socklen_t *anamelen, int flags); }
	SYS___THRSLEEP     = 94  // { int sys___thrsleep(const volatile void *ident, clockid_t clock_id, const struct timespec *tp, void *lock, const int *abort); }
	SYS_FSYNC          = 95  // { int sys_fsync(int fd); }
	SYS_SETPRIORITY    = 96  // { int sys_setpriority(int which, id_t who, int prio); }
	SYS_SOCKET         = 97  // { int sys_socket(int domain, int type, int protocol); }
	SYS_CONNECT        = 98  // { int sys_connect(int s, const struct sockaddr *name, socklen_t namelen); }
	SYS_GETDENTS       = 99  // { int sys_getdents(int fd, void *buf, size_t buflen); }
	SYS_GETPRIORITY    = 100 // { int sys_getpriority(int which, id_t who); }
	SYS_PIPE2          = 101 // { int sys_pipe2(int *fdp, int flags); }
	SYS_DUP3           = 102 // { int sys_dup3(int from, int to, int flags); }
	SYS_SIGRETURN      = 103 // { int sys_sigreturn(struct sigcontext *sigcntxp); }
	SYS_BIND           = 104 // { int sys_bind(int s, const struct sockaddr *name, socklen_t namelen); }
	SYS_SETSOCKOPT     = 105 // { int sys_setsockopt(int s, int level, int name, const void *val, socklen_t valsize); }
	SYS_LISTEN         = 106 // { int sys_listen(int s, int backlog); }
	SYS_CHFLAGSAT      = 107 // { int sys_chflagsat(int fd, const char *path, u_int flags, int atflags); }
	SYS_PLEDGE         = 108 // { int sys_pledge(const char *promises, const char *execpromises); }
	SYS_PPOLL          = 109 // { int sys_ppoll(struct pollfd *fds, u_int nfds, const struct timespec *ts, const sigset_t *mask); }
	SYS_PSELECT        = 110 // { int sys_pselect(int nd, fd_set *in, fd_set *ou, fd_set *ex, const struct timespec *ts, const sigset_t *mask); }
	SYS_SIGSUSPEND     = 111 // { int sys_sigsuspend(int mask); }
	SYS_SENDSYSLOG     = 112 // { int sys_sendsyslog(const char *buf, size_t nbyte, int flags); }
	SYS_UNVEIL         = 114 // { int sys_unveil(const char *path, const char *permissions); }
	SYS_GETSOCKOPT     = 118 // { int sys_getsockopt(int s, int level, int name, void *val, socklen_t *avalsize); }
	SYS_THRKILL        = 119 // { int sys_thrkill(pid_t tid, int signum, void *tcb); }
	SYS_READV          = 120 // { ssize_t sys_readv(int fd, const struct iovec *iovp, int iovcnt); }
	SYS_WRITEV         = 121 // { ssize_t sys_writev(int fd, const struct iovec *iovp, int iovcnt); }
	SYS_KILL           = 122 // { int sys_kill(int pid, int signum); }
	SYS_FCHOWN         = 123 // { int sys_fchown(int fd, uid_t uid, gid_t gid); }
	SYS_FCHMOD         = 124 // { int sys_fchmod(int fd, mode_t mode); }
	SYS_SETREUID       = 126 // { int sys_setreuid(uid_t ruid, uid_t euid); }
	SYS_SETREGID       = 127 // { int sys_setregid(gid_t rgid, gid_t egid); }
	SYS_RENAME         = 128 // { int sys_rename(const char *from, const char *to); }
	SYS_FLOCK          = 131 // { int sys_flock(int fd, int how); }
	SYS_MKFIFO         = 132 // { int sys_mkfifo(const char *path, mode_t mode); }
	SYS_SENDTO         = 133 // { ssize_t sys_sendto(int s, const void *buf, size_t len, int flags, const struct sockaddr *to, socklen_t tolen); }
	SYS_SHUTDOWN       = 134 // { int sys_shutdown(int s, int how); }
	SYS_SOCKETPAIR     = 135 // { int sys_socketpair(int domain, int type, int protocol, int *rsv); }
	SYS_MKDIR          = 136 // { int sys_mkdir(const char *path, mode_t mode); }
	SYS_RMDIR          = 137 // { int sys_rmdir(const char *path); }
	SYS_ADJTIME        = 140 // { int sys_adjtime(const struct timeval *delta, struct timeval *olddelta); }
	SYS_GETLOGIN_R     = 141 // { int sys_getlogin_r(char *namebuf, u_int namelen); }
	SYS_SETSID         = 147 // { int sys_setsid(void); }
	SYS_QUOTACTL       = 148 // { int sys_quotactl(const char *path, int cmd, int uid, char *arg); }
	SYS_NFSSVC         = 155 // { int sys_nfssvc(int flag, void *argp); }
	SYS_GETFH          = 161 // { int sys_getfh(const char *fname, fhandle_t *fhp); }
	SYS_SYSARCH        = 165 // { int sys_sysarch(int op, void *parms); }
	SYS_PREAD          = 173 // { ssize_t sys_pread(int fd, void *buf, size_t nbyte, int pad, off_t offset); }
	SYS_PWRITE         = 174 // { ssize_t sys_pwrite(int fd, const void *buf, size_t nbyte, int pad, off_t offset); }
	SYS_SETGID         = 181 // { int sys_setgid(gid_t gid); }
	SYS_SETEGID        = 182 // { int sys_setegid(gid_t egid); }
	SYS_SETEUID        = 183 // { int sys_seteuid(uid_t euid); }
	SYS_PATHCONF       = 191 // { long sys_pathconf(const char *path, int name); }
	SYS_FPATHCONF      = 192 // { long sys_fpathconf(int fd, int name); }
	SYS_SWAPCTL        = 193 // { int sys_swapctl(int cmd, const void *arg, int misc); }
	SYS_GETRLIMIT      = 194 // { int sys_getrlimit(int which, struct rlimit *rlp); }
	SYS_SETRLIMIT      = 195 // { int sys_setrlimit(int which, const struct rlimit *rlp); }
	SYS_MMAP           = 197 // { void *sys_mmap(void *addr, size_t len, int prot, int flags, int fd, long pad, off_t pos); }
	SYS_LSEEK          = 199 // { off_t sys_lseek(int fd, int pad, off_t offset, int whence); }
	SYS_TRUNCATE       = 200 // { int sys_truncate(const char *path, int pad, off_t length); }
	SYS_FTRUNCATE      = 201 // { int sys_ftruncate(int fd, int pad, off_t length); }
	SYS_SYSCTL         = 202 // { int sys_sysctl(const int *name, u_int namelen, void *old, size_t *oldlenp, void *new, size_t newlen); }
	SYS_MLOCK          = 203 // { int sys_mlock(const void *addr, size_t len); }
	SYS_MUNLOCK        = 204 // { int sys_munlock(const void *addr, size_t len); }
	SYS_GETPGID        = 207 // { pid_t sys_getpgid(pid_t pid); }
	SYS_UTRACE         = 209 // { int sys_utrace(const char *label, const void *addr, size_t len); }
	SYS_SEMGET         = 221 // { int sys_semget(key_t key, int nsems, int semflg); }
	SYS_MSGGET         = 225 // { int sys_msgget(key_t key, int msgflg); }
	SYS_MSGSND         = 226 // { int sys_msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg); }
	SYS_MSGRCV         = 227 // { int sys_msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg); }
	SYS_SHMAT          = 228 // { void *sys_shmat(int shmid, const void *shmaddr, int shmflg); }
	SYS_SHMDT          = 230 // { int sys_shmdt(const void *shmaddr); }
	SYS_MINHERIT       = 250 // { int sys_minherit(void *addr, size_t len, int inherit); }
	SYS_POLL           = 252 // { int sys_poll(struct pollfd *fds, u_int nfds, int timeout); }
	SYS_ISSETUGID      = 253 // { int sys_issetugid(void); }
	SYS_LCHOWN         = 254 // { int sys_lchown(const char *path, uid_t uid, gid_t gid); }
	SYS_GETSID         = 255 // { pid_t sys_getsid(pid_t pid); }
	SYS_MSYNC          = 256 // { int sys_msync(void *addr, size_t len, int flags); }
	SYS_PIPE           = 263 // { int sys_pipe(int *fdp); }
	SYS_FHOPEN         = 264 // { int sys_fhopen(const fhandle_t *fhp, int flags); }
	SYS_PREADV         = 267 // { ssize_t sys_preadv(int fd, const struct iovec *iovp, int iovcnt, int pad, off_t offset); }
	SYS_PWRITEV        = 268 // { ssize_t sys_pwritev(int fd, const struct iovec *iovp, int iovcnt, int pad, off_t offset); }
	SYS_KQUEUE         = 269 // { int sys_kqueue(void); }
	SYS_MLOCKALL       = 271 // { int sys_mlockall(int flags); }
	SYS_MUNLOCKALL     = 272 // { int sys_munlockall(void); }
	SYS_GETRESUID      = 281 // { int sys_getresuid(uid_t *ruid, uid_t *euid, uid_t *suid); }
	SYS_SETRESUID      = 282 // { int sys_setresuid(uid_t ruid, uid_t euid, uid_t suid); }
	SYS_GETRESGID      = 283 // { int sys_getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid); }
	SYS_SETRESGID      = 284 // { int sys_setresgid(gid_t rgid, gid_t egid, gid_t sgid); }
	SYS_MQUERY         = 286 // { void *sys_mquery(void *addr, size_t len, int prot, int flags, int fd, long pad, off_t pos); }
	SYS_CLOSEFROM      = 287 // { int sys_closefrom(int fd); }
	SYS_SIGALTSTACK    = 288 // { int sys_sigaltstack(const struct sigaltstack *nss, struct sigaltstack *oss); }
	SYS_SHMGET         = 289 // { int sys_shmget(key_t key, size_t size, int shmflg); }
	SYS_SEMOP          = 290 // { int sys_semop(int semid, struct sembuf *sops, size_t nsops); }
	SYS_FHSTAT         = 294 // { int sys_fhstat(const fhandle_t *fhp, struct stat *sb); }
	SYS___SEMCTL       = 295 // { int sys___semctl(int semid, int semnum, int cmd, union semun *arg); }
	SYS_SHMCTL         = 296 // { int sys_shmctl(int shmid, int cmd, struct shmid_ds *buf); }
	SYS_MSGCTL         = 297 // { int sys_msgctl(int msqid, int cmd, struct msqid_ds *buf); }
	SYS_SCHED_YIELD    = 298 // { int sys_sched_yield(void); }
	SYS_GETTHRID       = 299 // { pid_t sys_getthrid(void); }
	SYS___THRWAKEUP    = 301 // { int sys___thrwakeup(const volatile void *ident, int n); }
	SYS___THREXIT      = 302 // { void sys___threxit(pid_t *notdead); }
	SYS___THRSIGDIVERT = 303 // { int sys___thrsigdivert(sigset_t sigmask, siginfo_t *info, const struct timespec *timeout); }
	SYS___GETCWD       = 304 // { int sys___getcwd(char *buf, size_t len); }
	SYS_ADJFREQ        = 305 // { int sys_adjfreq(const int64_t *freq, int64_t *oldfreq); }
	SYS_SETRTABLE      = 310 // { int sys_setrtable(int rtableid); }
	SYS_GETRTABLE      = 311 // { int sys_getrtable(void); }
	SYS_FACCESSAT      = 313 // { int sys_faccessat(int fd, const char *path, int amode, int flag); }
	SYS_FCHMODAT       = 314 // { int sys_fchmodat(int fd, const char *path, mode_t mode, int flag); }
	SYS_FCHOWNAT       = 315 // { int sys_fchownat(int fd, const char *path, uid_t uid, gid_t gid, int flag); }
	SYS_LINKAT         = 317 // { int sys_linkat(int fd1, const char *path1, int fd2, const char *path2, int flag); }
	SYS_MKDIRAT        = 318 // { int sys_mkdirat(int fd, const char *path, mode_t mode); }
	SYS_MKFIFOAT       = 319 // { int sys_mkfifoat(int fd, const char *path, mode_t mode); }
	SYS_MKNODAT        = 320 // { int sys_mknodat(int fd, const char *path, mode_t mode, dev_t dev); }
	SYS_OPENAT         = 321 // { int sys_openat(int fd, const char *path, int flags, ... mode_t mode); }
	SYS_READLINKAT     = 322 // { ssize_t sys_readlinkat(int fd, const char *path, char *buf, size_t count); }
	SYS_RENAMEAT       = 323 // { int sys_renameat(int fromfd, const char *from, int tofd, const char *to); }
	SYS_SYMLINKAT      = 324 // { int sys_symlinkat(const char *path, int fd, const char *link); }
	SYS_UNLINKAT       = 325 // { int sys_unlinkat(int fd, const char *path, int flag); }
	SYS___SET_TCB      = 329 // { void sys___set_tcb(void *tcb); }
	SYS___GET_TCB      = 330 // { void *sys___get_tcb(void); }
)
```