Response:
Let's break down the thought process to answer the request.

1. **Understanding the Core Request:** The user wants to know the functionality of a Go file (`zsysnum_openbsd_386.go`) containing a series of constants. They specifically want to understand *what* these constants represent in the broader context of Go and operating systems. They also ask for examples, potential pitfalls, and handling of command-line arguments (though this last point is likely a misunderstanding given the file's content).

2. **Analyzing the File Content:** The file is straightforward. It's a Go package (`syscall`) defining a series of `const` declarations. Each constant has a name starting with `SYS_` followed by an uppercase name, and an integer value. Crucially, each constant also has a comment that looks like a C function signature.

3. **Identifying the Pattern:** The `SYS_` prefix strongly suggests these are system call numbers. The C-like comments further reinforce this, as they describe the parameters and return types of what are clearly system calls. The platform name in the file path (`openbsd_386`) confirms this is specific to the OpenBSD operating system on the 386 architecture.

4. **Formulating the Basic Functionality:**  The primary function of this file is to define the numeric identifiers for system calls on the target platform. Go's `syscall` package uses these numbers to invoke the underlying operating system's functionalities.

5. **Connecting to Go Functionality (The "What" it Implements):** The key insight here is that Go's standard library, particularly the `os` and `syscall` packages, provides a higher-level, cross-platform interface to operating system functionalities. The constants in this file are the *underlying mapping* for the OpenBSD/386 platform. When a Go program uses `os.Open()`, for example, the `syscall` package (on OpenBSD/386) will ultimately use the `SYS_OPEN` constant to make the actual system call to the kernel.

6. **Providing Go Code Examples:**  To illustrate this connection, we need examples of Go code that implicitly use these system calls. Good candidates are:
    * File I/O (`os.Open`, `os.Read`, `os.Write`, `os.Close`): These directly map to system calls like `SYS_OPEN`, `SYS_READ`, `SYS_WRITE`, `SYS_CLOSE`.
    * Process Management (`os.Fork`, `os.Exec`, `os.Exit`, `os.Wait`): These use system calls like `SYS_FORK`, `SYS_EXECVE`, `SYS_EXIT`, `SYS_WAIT4`.
    * Network Operations (`net.Dial`, `net.Listen`, `socket` in `syscall`):  These relate to system calls like `SYS_SOCKET`, `SYS_CONNECT`, `SYS_LISTEN`, `SYS_ACCEPT`.
    * File System Operations (`os.Mkdir`, `os.Remove`, `os.Stat`): These use system calls like `SYS_MKDIR`, `SYS_UNLINK`, `SYS_STAT`.

7. **Demonstrating with Code (Including Hypothetical Input/Output):**  For each example, provide a simple Go snippet. Crucially, since we're talking about *system calls*, the output is dependent on the system's state. Therefore, "hypothetical" input and output is important to show a realistic scenario. For instance, `os.Open("test.txt")` might return a file descriptor or an error if the file doesn't exist.

8. **Addressing Command-Line Arguments:**  The file itself doesn't directly handle command-line arguments. This is a misunderstanding. Explain that command-line argument parsing is handled by other parts of the Go standard library (like the `os` package's `Args` variable or the `flag` package), and that this file deals with the lower-level system call numbers.

9. **Identifying Potential Pitfalls:** The most common mistake users might make is trying to use these constants directly without understanding their purpose or the higher-level Go APIs. Emphasize that these are *internal* implementation details and should generally be accessed indirectly through the standard library. Provide an example of *incorrect* direct usage of `syscall.SYS_OPEN` and explain why it's problematic (lack of proper arguments, return value handling, and the existence of safer, higher-level alternatives).

10. **Structuring the Answer:** Organize the answer logically with clear headings: "功能列举," "功能推断和代码举例," "命令行参数处理," and "使用者易犯错的点."  Use bullet points or numbered lists for clarity. Maintain a consistent and clear writing style.

11. **Review and Refine:**  Read through the entire answer to ensure accuracy, clarity, and completeness. Check for any grammatical errors or typos. Make sure the code examples are correct and easy to understand.

By following these steps, we can generate a comprehensive and accurate answer to the user's request, addressing all the specific points raised. The key is to understand the role of this file within the larger Go ecosystem and to connect the low-level constants to the higher-level abstractions that Go developers typically use.
## `go/src/syscall/zsysnum_openbsd_386.go` 的功能列举：

这个 Go 语言文件 `zsysnum_openbsd_386.go` 的主要功能是：

1. **定义 OpenBSD (386 架构) 操作系统上的系统调用号常量:**  文件中定义了一系列的 Go 常量，每个常量都代表 OpenBSD 386 架构下一个特定的系统调用。常量名以 `SYS_` 开头，后跟系统调用名称的大写形式。

2. **为 Go 的 `syscall` 包提供平台特定的系统调用映射:** Go 的 `syscall` 包提供了访问底层操作系统功能的接口。这个文件中的常量定义了在 OpenBSD 386 平台上，Go 程序如何通过 `syscall` 包调用相应的内核函数。

3. **作为 `mksysnum_openbsd.pl` 脚本的输出结果:** 文件开头的注释 `// mksysnum_openbsd.pl` 表明这个文件是通过一个名为 `mksysnum_openbsd.pl` 的 Perl 脚本生成的。这个脚本很可能读取 OpenBSD 的头文件（例如 `sys/syscall.h`），提取系统调用号，并将其转换为 Go 语言的常量定义。

**功能推断和代码举例：**

这个文件定义的是系统调用号，它本身并不直接实现 Go 语言的特定功能。相反，它是 Go 标准库中 `syscall` 包实现底层操作系统交互的基础。  当你使用 Go 的 `os` 包或其他依赖 `syscall` 包的库时，这些库最终会使用这里定义的常量来发起系统调用。

例如，当你使用 `os.Open()` 函数打开一个文件时，在 OpenBSD 386 平台上，`syscall` 包会使用 `SYS_OPEN` 这个常量（其值为 5）来调用 OpenBSD 内核的 `open()` 系统调用。

```go
package main

import (
	"fmt"
	"os"
	"syscall"
)

func main() {
	// 使用 os.Open 打开文件
	file, err := os.Open("test.txt")
	if err != nil {
		fmt.Println("打开文件失败:", err)
		return
	}
	defer file.Close()

	fmt.Println("成功打开文件")

	// 你无法直接观察到 SYS_OPEN 的使用，因为这是在 os.Open 的内部实现的。
	// 但是，我们可以通过 syscall 包直接使用系统调用（不推荐直接使用，仅作演示）。

	fd, err := syscall.Open("test.txt", syscall.O_RDONLY, 0)
	if err != nil {
		fmt.Println("使用 syscall.Open 失败:", err)
		return
	}
	defer syscall.Close(fd)
	fmt.Printf("使用 syscall.Open 成功，文件描述符: %d\n", fd)

	// 理论上，syscall.Open 内部在 OpenBSD 386 上会使用 SYS_OPEN 这个常量。
	// 你可以通过查看 Go 源码的 syscall 包来确认这一点。
}
```

**假设的输入与输出：**

假设当前目录下存在一个名为 `test.txt` 的文件。

**第一次运行 (使用 `os.Open`)：**

```
成功打开文件
使用 syscall.Open 成功，文件描述符: 3  // 文件描述符的值可能会不同
```

**如果 `test.txt` 文件不存在，则输出可能为：**

```
打开文件失败: open test.txt: no such file or directory
使用 syscall.Open 失败: no such file or directory
```

**命令行参数的具体处理：**

这个文件本身不涉及命令行参数的处理。命令行参数的处理通常在 `main` 函数中使用 `os.Args` 切片或者 `flag` 包来完成。  `zsysnum_openbsd_386.go` 只是定义了底层的系统调用号，与命令行参数没有直接关系。

**使用者易犯错的点：**

* **直接使用 `syscall` 包中的常量进行系统调用：** 虽然 Go 提供了 `syscall` 包，允许直接调用系统调用，但这通常是不推荐的。直接使用系统调用会使代码平台依赖性更强，且容易出错（例如，需要手动处理系统调用的各种参数和返回值）。 Go 的标准库（如 `os`、`net` 等）提供了更高级、更安全、更易于使用的跨平台接口。

**示例（不推荐）：**

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	// 尝试直接使用 SYS_WRITE，这需要对系统调用参数有深入理解
	message := "Hello, system call!\n"
	addr := unsafe.Pointer(&[]byte(message)[0])
	n, _, err := syscall.Syscall(syscall.SYS_WRITE, uintptr(1), uintptr(addr), uintptr(len(message)))
	if err != 0 {
		fmt.Println("SYS_WRITE 调用失败:", err)
		return
	}
	fmt.Printf("写入了 %d 字节\n", n)
}
```

在这个例子中，开发者需要知道 `SYS_WRITE` 的参数顺序、类型以及如何将 Go 的数据类型转换为系统调用所需的类型（例如，使用 `unsafe.Pointer`）。这种方式容易出错，且在不同平台上可能会有差异。

**推荐的做法是使用 `os` 包：**

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	// 使用 os.Stdout 的 Write 方法，它在内部会使用系统调用
	_, err := os.Stdout.Write([]byte("Hello, Go!\n"))
	if err != nil {
		fmt.Println("写入失败:", err)
		return
	}
}
```

总结来说，`zsysnum_openbsd_386.go` 文件是 Go 语言 `syscall` 包在 OpenBSD 386 平台上的基础，它定义了系统调用的编号，使得 Go 程序可以通过 `syscall` 包或者更高级的库（如 `os`）来与底层操作系统进行交互。开发者通常不需要直接关心这个文件的内容，而是应该使用 Go 标准库提供的更便捷和跨平台的接口。

Prompt: 
```
这是路径为go/src/syscall/zsysnum_openbsd_386.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// mksysnum_openbsd.pl
// Code generated by the command above; DO NOT EDIT.

package syscall

const (
	SYS_EXIT           = 1   // { void sys_exit(int rval); }
	SYS_FORK           = 2   // { int sys_fork(void); }
	SYS_READ           = 3   // { ssize_t sys_read(int fd, void *buf, size_t nbyte); }
	SYS_WRITE          = 4   // { ssize_t sys_write(int fd, const void *buf, \
	SYS_OPEN           = 5   // { int sys_open(const char *path, \
	SYS_CLOSE          = 6   // { int sys_close(int fd); }
	SYS___TFORK        = 8   // { int sys___tfork(const struct __tfork *param, \
	SYS_LINK           = 9   // { int sys_link(const char *path, const char *link); }
	SYS_UNLINK         = 10  // { int sys_unlink(const char *path); }
	SYS_WAIT4          = 11  // { pid_t sys_wait4(pid_t pid, int *status, \
	SYS_CHDIR          = 12  // { int sys_chdir(const char *path); }
	SYS_FCHDIR         = 13  // { int sys_fchdir(int fd); }
	SYS_MKNOD          = 14  // { int sys_mknod(const char *path, mode_t mode, \
	SYS_CHMOD          = 15  // { int sys_chmod(const char *path, mode_t mode); }
	SYS_CHOWN          = 16  // { int sys_chown(const char *path, uid_t uid, \
	SYS_OBREAK         = 17  // { int sys_obreak(char *nsize); } break
	SYS_GETDTABLECOUNT = 18  // { int sys_getdtablecount(void); }
	SYS_GETRUSAGE      = 19  // { int sys_getrusage(int who, \
	SYS_GETPID         = 20  // { pid_t sys_getpid(void); }
	SYS_MOUNT          = 21  // { int sys_mount(const char *type, const char *path, \
	SYS_UNMOUNT        = 22  // { int sys_unmount(const char *path, int flags); }
	SYS_SETUID         = 23  // { int sys_setuid(uid_t uid); }
	SYS_GETUID         = 24  // { uid_t sys_getuid(void); }
	SYS_GETEUID        = 25  // { uid_t sys_geteuid(void); }
	SYS_PTRACE         = 26  // { int sys_ptrace(int req, pid_t pid, caddr_t addr, \
	SYS_RECVMSG        = 27  // { ssize_t sys_recvmsg(int s, struct msghdr *msg, \
	SYS_SENDMSG        = 28  // { ssize_t sys_sendmsg(int s, \
	SYS_RECVFROM       = 29  // { ssize_t sys_recvfrom(int s, void *buf, size_t len, \
	SYS_ACCEPT         = 30  // { int sys_accept(int s, struct sockaddr *name, \
	SYS_GETPEERNAME    = 31  // { int sys_getpeername(int fdes, struct sockaddr *asa, \
	SYS_GETSOCKNAME    = 32  // { int sys_getsockname(int fdes, struct sockaddr *asa, \
	SYS_ACCESS         = 33  // { int sys_access(const char *path, int flags); }
	SYS_CHFLAGS        = 34  // { int sys_chflags(const char *path, u_int flags); }
	SYS_FCHFLAGS       = 35  // { int sys_fchflags(int fd, u_int flags); }
	SYS_SYNC           = 36  // { void sys_sync(void); }
	SYS_STAT           = 38  // { int sys_stat(const char *path, struct stat *ub); }
	SYS_GETPPID        = 39  // { pid_t sys_getppid(void); }
	SYS_LSTAT          = 40  // { int sys_lstat(const char *path, struct stat *ub); }
	SYS_DUP            = 41  // { int sys_dup(int fd); }
	SYS_FSTATAT        = 42  // { int sys_fstatat(int fd, const char *path, \
	SYS_GETEGID        = 43  // { gid_t sys_getegid(void); }
	SYS_PROFIL         = 44  // { int sys_profil(caddr_t samples, size_t size, \
	SYS_KTRACE         = 45  // { int sys_ktrace(const char *fname, int ops, \
	SYS_SIGACTION      = 46  // { int sys_sigaction(int signum, \
	SYS_GETGID         = 47  // { gid_t sys_getgid(void); }
	SYS_SIGPROCMASK    = 48  // { int sys_sigprocmask(int how, sigset_t mask); }
	SYS_GETLOGIN       = 49  // { int sys_getlogin(char *namebuf, u_int namelen); }
	SYS_SETLOGIN       = 50  // { int sys_setlogin(const char *namebuf); }
	SYS_ACCT           = 51  // { int sys_acct(const char *path); }
	SYS_SIGPENDING     = 52  // { int sys_sigpending(void); }
	SYS_FSTAT          = 53  // { int sys_fstat(int fd, struct stat *sb); }
	SYS_IOCTL          = 54  // { int sys_ioctl(int fd, \
	SYS_REBOOT         = 55  // { int sys_reboot(int opt); }
	SYS_REVOKE         = 56  // { int sys_revoke(const char *path); }
	SYS_SYMLINK        = 57  // { int sys_symlink(const char *path, \
	SYS_READLINK       = 58  // { int sys_readlink(const char *path, char *buf, \
	SYS_EXECVE         = 59  // { int sys_execve(const char *path, \
	SYS_UMASK          = 60  // { mode_t sys_umask(mode_t newmask); }
	SYS_CHROOT         = 61  // { int sys_chroot(const char *path); }
	SYS_GETFSSTAT      = 62  // { int sys_getfsstat(struct statfs *buf, size_t bufsize, \
	SYS_STATFS         = 63  // { int sys_statfs(const char *path, \
	SYS_FSTATFS        = 64  // { int sys_fstatfs(int fd, struct statfs *buf); }
	SYS_FHSTATFS       = 65  // { int sys_fhstatfs(const fhandle_t *fhp, \
	SYS_VFORK          = 66  // { int sys_vfork(void); }
	SYS_GETTIMEOFDAY   = 67  // { int sys_gettimeofday(struct timeval *tp, \
	SYS_SETTIMEOFDAY   = 68  // { int sys_settimeofday(const struct timeval *tv, \
	SYS_SETITIMER      = 69  // { int sys_setitimer(int which, \
	SYS_GETITIMER      = 70  // { int sys_getitimer(int which, \
	SYS_SELECT         = 71  // { int sys_select(int nd, fd_set *in, fd_set *ou, \
	SYS_KEVENT         = 72  // { int sys_kevent(int fd, \
	SYS_MUNMAP         = 73  // { int sys_munmap(void *addr, size_t len); }
	SYS_MPROTECT       = 74  // { int sys_mprotect(void *addr, size_t len, \
	SYS_MADVISE        = 75  // { int sys_madvise(void *addr, size_t len, \
	SYS_UTIMES         = 76  // { int sys_utimes(const char *path, \
	SYS_FUTIMES        = 77  // { int sys_futimes(int fd, \
	SYS_MINCORE        = 78  // { int sys_mincore(void *addr, size_t len, \
	SYS_GETGROUPS      = 79  // { int sys_getgroups(int gidsetsize, \
	SYS_SETGROUPS      = 80  // { int sys_setgroups(int gidsetsize, \
	SYS_GETPGRP        = 81  // { int sys_getpgrp(void); }
	SYS_SETPGID        = 82  // { int sys_setpgid(pid_t pid, int pgid); }
	SYS_UTIMENSAT      = 84  // { int sys_utimensat(int fd, const char *path, \
	SYS_FUTIMENS       = 85  // { int sys_futimens(int fd, \
	SYS_CLOCK_GETTIME  = 87  // { int sys_clock_gettime(clockid_t clock_id, \
	SYS_CLOCK_SETTIME  = 88  // { int sys_clock_settime(clockid_t clock_id, \
	SYS_CLOCK_GETRES   = 89  // { int sys_clock_getres(clockid_t clock_id, \
	SYS_DUP2           = 90  // { int sys_dup2(int from, int to); }
	SYS_NANOSLEEP      = 91  // { int sys_nanosleep(const struct timespec *rqtp, \
	SYS_FCNTL          = 92  // { int sys_fcntl(int fd, int cmd, ... void *arg); }
	SYS_ACCEPT4        = 93  // { int sys_accept4(int s, struct sockaddr *name, \
	SYS___THRSLEEP     = 94  // { int sys___thrsleep(const volatile void *ident, \
	SYS_FSYNC          = 95  // { int sys_fsync(int fd); }
	SYS_SETPRIORITY    = 96  // { int sys_setpriority(int which, id_t who, int prio); }
	SYS_SOCKET         = 97  // { int sys_socket(int domain, int type, int protocol); }
	SYS_CONNECT        = 98  // { int sys_connect(int s, const struct sockaddr *name, \
	SYS_GETDENTS       = 99  // { int sys_getdents(int fd, void *buf, size_t buflen); }
	SYS_GETPRIORITY    = 100 // { int sys_getpriority(int which, id_t who); }
	SYS_PIPE2          = 101 // { int sys_pipe2(int *fdp, int flags); }
	SYS_SIGRETURN      = 103 // { int sys_sigreturn(struct sigcontext *sigcntxp); }
	SYS_BIND           = 104 // { int sys_bind(int s, const struct sockaddr *name, \
	SYS_SETSOCKOPT     = 105 // { int sys_setsockopt(int s, int level, int name, \
	SYS_LISTEN         = 106 // { int sys_listen(int s, int backlog); }
	SYS_PPOLL          = 109 // { int sys_ppoll(struct pollfd *fds, \
	SYS_PSELECT        = 110 // { int sys_pselect(int nd, fd_set *in, fd_set *ou, \
	SYS_SIGSUSPEND     = 111 // { int sys_sigsuspend(int mask); }
	SYS_GETSOCKOPT     = 118 // { int sys_getsockopt(int s, int level, int name, \
	SYS_READV          = 120 // { ssize_t sys_readv(int fd, \
	SYS_WRITEV         = 121 // { ssize_t sys_writev(int fd, \
	SYS_FCHOWN         = 123 // { int sys_fchown(int fd, uid_t uid, gid_t gid); }
	SYS_KILL           = 122 // { int sys_kill(int pid, int signum); }
	SYS_FCHMOD         = 124 // { int sys_fchmod(int fd, mode_t mode); }
	SYS_SETREUID       = 126 // { int sys_setreuid(uid_t ruid, uid_t euid); }
	SYS_SETREGID       = 127 // { int sys_setregid(gid_t rgid, gid_t egid); }
	SYS_RENAME         = 128 // { int sys_rename(const char *from, const char *to); }
	SYS_FLOCK          = 131 // { int sys_flock(int fd, int how); }
	SYS_MKFIFO         = 132 // { int sys_mkfifo(const char *path, mode_t mode); }
	SYS_SENDTO         = 133 // { ssize_t sys_sendto(int s, const void *buf, \
	SYS_SHUTDOWN       = 134 // { int sys_shutdown(int s, int how); }
	SYS_SOCKETPAIR     = 135 // { int sys_socketpair(int domain, int type, \
	SYS_MKDIR          = 136 // { int sys_mkdir(const char *path, mode_t mode); }
	SYS_RMDIR          = 137 // { int sys_rmdir(const char *path); }
	SYS_ADJTIME        = 140 // { int sys_adjtime(const struct timeval *delta, \
	SYS_SETSID         = 147 // { int sys_setsid(void); }
	SYS_QUOTACTL       = 148 // { int sys_quotactl(const char *path, int cmd, \
	SYS_NFSSVC         = 155 // { int sys_nfssvc(int flag, void *argp); }
	SYS_GETFH          = 161 // { int sys_getfh(const char *fname, fhandle_t *fhp); }
	SYS_SYSARCH        = 165 // { int sys_sysarch(int op, void *parms); }
	SYS_PREAD          = 173 // { ssize_t sys_pread(int fd, void *buf, \
	SYS_PWRITE         = 174 // { ssize_t sys_pwrite(int fd, const void *buf, \
	SYS_SETGID         = 181 // { int sys_setgid(gid_t gid); }
	SYS_SETEGID        = 182 // { int sys_setegid(gid_t egid); }
	SYS_SETEUID        = 183 // { int sys_seteuid(uid_t euid); }
	SYS_PATHCONF       = 191 // { long sys_pathconf(const char *path, int name); }
	SYS_FPATHCONF      = 192 // { long sys_fpathconf(int fd, int name); }
	SYS_SWAPCTL        = 193 // { int sys_swapctl(int cmd, const void *arg, int misc); }
	SYS_GETRLIMIT      = 194 // { int sys_getrlimit(int which, \
	SYS_SETRLIMIT      = 195 // { int sys_setrlimit(int which, \
	SYS_MMAP           = 197 // { void *sys_mmap(void *addr, size_t len, int prot, \
	SYS_LSEEK          = 199 // { off_t sys_lseek(int fd, int pad, off_t offset, \
	SYS_TRUNCATE       = 200 // { int sys_truncate(const char *path, int pad, \
	SYS_FTRUNCATE      = 201 // { int sys_ftruncate(int fd, int pad, off_t length); }
	SYS___SYSCTL       = 202 // { int sys___sysctl(const int *name, u_int namelen, \
	SYS_MLOCK          = 203 // { int sys_mlock(const void *addr, size_t len); }
	SYS_MUNLOCK        = 204 // { int sys_munlock(const void *addr, size_t len); }
	SYS_GETPGID        = 207 // { pid_t sys_getpgid(pid_t pid); }
	SYS_UTRACE         = 209 // { int sys_utrace(const char *label, const void *addr, \
	SYS_SEMGET         = 221 // { int sys_semget(key_t key, int nsems, int semflg); }
	SYS_MSGGET         = 225 // { int sys_msgget(key_t key, int msgflg); }
	SYS_MSGSND         = 226 // { int sys_msgsnd(int msqid, const void *msgp, size_t msgsz, \
	SYS_MSGRCV         = 227 // { int sys_msgrcv(int msqid, void *msgp, size_t msgsz, \
	SYS_SHMAT          = 228 // { void *sys_shmat(int shmid, const void *shmaddr, \
	SYS_SHMDT          = 230 // { int sys_shmdt(const void *shmaddr); }
	SYS_MINHERIT       = 250 // { int sys_minherit(void *addr, size_t len, \
	SYS_POLL           = 252 // { int sys_poll(struct pollfd *fds, \
	SYS_ISSETUGID      = 253 // { int sys_issetugid(void); }
	SYS_LCHOWN         = 254 // { int sys_lchown(const char *path, uid_t uid, gid_t gid); }
	SYS_GETSID         = 255 // { pid_t sys_getsid(pid_t pid); }
	SYS_MSYNC          = 256 // { int sys_msync(void *addr, size_t len, int flags); }
	SYS_PIPE           = 263 // { int sys_pipe(int *fdp); }
	SYS_FHOPEN         = 264 // { int sys_fhopen(const fhandle_t *fhp, int flags); }
	SYS_PREADV         = 267 // { ssize_t sys_preadv(int fd, \
	SYS_PWRITEV        = 268 // { ssize_t sys_pwritev(int fd, \
	SYS_KQUEUE         = 269 // { int sys_kqueue(void); }
	SYS_MLOCKALL       = 271 // { int sys_mlockall(int flags); }
	SYS_MUNLOCKALL     = 272 // { int sys_munlockall(void); }
	SYS_GETRESUID      = 281 // { int sys_getresuid(uid_t *ruid, uid_t *euid, \
	SYS_SETRESUID      = 282 // { int sys_setresuid(uid_t ruid, uid_t euid, \
	SYS_GETRESGID      = 283 // { int sys_getresgid(gid_t *rgid, gid_t *egid, \
	SYS_SETRESGID      = 284 // { int sys_setresgid(gid_t rgid, gid_t egid, \
	SYS_MQUERY         = 286 // { void *sys_mquery(void *addr, size_t len, int prot, \
	SYS_CLOSEFROM      = 287 // { int sys_closefrom(int fd); }
	SYS_SIGALTSTACK    = 288 // { int sys_sigaltstack(const struct sigaltstack *nss, \
	SYS_SHMGET         = 289 // { int sys_shmget(key_t key, size_t size, int shmflg); }
	SYS_SEMOP          = 290 // { int sys_semop(int semid, struct sembuf *sops, \
	SYS_FHSTAT         = 294 // { int sys_fhstat(const fhandle_t *fhp, \
	SYS___SEMCTL       = 295 // { int sys___semctl(int semid, int semnum, int cmd, \
	SYS_SHMCTL         = 296 // { int sys_shmctl(int shmid, int cmd, \
	SYS_MSGCTL         = 297 // { int sys_msgctl(int msqid, int cmd, \
	SYS_SCHED_YIELD    = 298 // { int sys_sched_yield(void); }
	SYS_GETTHRID       = 299 // { pid_t sys_getthrid(void); }
	SYS___THRWAKEUP    = 301 // { int sys___thrwakeup(const volatile void *ident, \
	SYS___THREXIT      = 302 // { void sys___threxit(pid_t *notdead); }
	SYS___THRSIGDIVERT = 303 // { int sys___thrsigdivert(sigset_t sigmask, \
	SYS___GETCWD       = 304 // { int sys___getcwd(char *buf, size_t len); }
	SYS_ADJFREQ        = 305 // { int sys_adjfreq(const int64_t *freq, \
	SYS_SETRTABLE      = 310 // { int sys_setrtable(int rtableid); }
	SYS_GETRTABLE      = 311 // { int sys_getrtable(void); }
	SYS_FACCESSAT      = 313 // { int sys_faccessat(int fd, const char *path, \
	SYS_FCHMODAT       = 314 // { int sys_fchmodat(int fd, const char *path, \
	SYS_FCHOWNAT       = 315 // { int sys_fchownat(int fd, const char *path, \
	SYS_LINKAT         = 317 // { int sys_linkat(int fd1, const char *path1, int fd2, \
	SYS_MKDIRAT        = 318 // { int sys_mkdirat(int fd, const char *path, \
	SYS_MKFIFOAT       = 319 // { int sys_mkfifoat(int fd, const char *path, \
	SYS_MKNODAT        = 320 // { int sys_mknodat(int fd, const char *path, \
	SYS_OPENAT         = 321 // { int sys_openat(int fd, const char *path, int flags, \
	SYS_READLINKAT     = 322 // { ssize_t sys_readlinkat(int fd, const char *path, \
	SYS_RENAMEAT       = 323 // { int sys_renameat(int fromfd, const char *from, \
	SYS_SYMLINKAT      = 324 // { int sys_symlinkat(const char *path, int fd, \
	SYS_UNLINKAT       = 325 // { int sys_unlinkat(int fd, const char *path, \
	SYS___SET_TCB      = 329 // { void sys___set_tcb(void *tcb); }
	SYS___GET_TCB      = 330 // { void *sys___get_tcb(void); }
)

"""



```