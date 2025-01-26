Response:
Let's break down the thought process for answering the request about the `zsysnum_openbsd_riscv64.go` file.

**1. Understanding the Core Information:**

The provided text is a Go source file defining constants. The key information is the package name (`syscall`) and the format of the constants: `SYS_<SYSCALL_NAME> = <syscall_number> // { <syscall_signature> }`. The comments clearly indicate this is generated code relating to system calls on OpenBSD for the RISC-V 64-bit architecture.

**2. Identifying the Primary Function:**

The most obvious function is defining the system call numbers for the target architecture. Each constant maps a human-readable system call name (like `SYS_READ`) to its numerical identifier. This is crucial for the Go `syscall` package to interact with the operating system kernel.

**3. Inferring the Broader Go Functionality:**

Knowing this file defines syscall numbers, we can deduce its role in the broader Go ecosystem. The `syscall` package in Go provides low-level access to the operating system's system calls. This file is a *part* of that functionality, specifically tailored for OpenBSD on RISC-V 64.

**4. Constructing a Go Example:**

To illustrate the file's purpose, a simple example of using a system call is necessary. `syscall.Open()` is a good choice as it's a common operation. The example should:

* Import the `syscall` package.
* Attempt to open a file.
* Handle potential errors.
* Close the file descriptor if successful.

This example demonstrates how the constants defined in the target file are used indirectly. The Go standard library uses these constants internally when you call functions like `syscall.Open()`.

**5. Addressing Other Aspects of the Request:**

* **Command-line arguments:**  The provided code itself doesn't handle command-line arguments. The generation script (`mksysnum_openbsd.pl`) *might* take arguments, but that's outside the scope of the given file. It's important to distinguish between the generated code and the code that generates it.
* **Error-prone usage:**  Directly using the constants might be error-prone if a developer tries to use an incorrect number. However, the Go `syscall` package generally abstracts away the direct use of these numbers. A more relevant error is using the wrong system call for a particular task or misinterpreting the system call's parameters. The example illustrates correct usage by leveraging the `syscall` package's higher-level functions.
* **Assumptions, Inputs, and Outputs for Code Reasoning:**  The "code reasoning" aspect refers to how the Go runtime uses these constants. The "input" is the symbolic name of the system call (e.g., `syscall.SYS_OPEN`). The "output" is the corresponding integer value (e.g., `5`). The `syscall` package uses this mapping internally when making system calls.

**6. Structuring the Answer:**

Organize the answer logically using the prompts provided in the request:

* **功能 (Functions):** Start with the most direct function: defining syscall numbers. Then explain its role in the `syscall` package.
* **Go语言功能实现 (Go Functionality Implementation):** Provide the code example to illustrate the concept.
* **代码推理 (Code Reasoning):** Explain how the constants are used internally. Include the input/output example to clarify the mapping.
* **命令行参数 (Command-line Arguments):**  State that the *provided code* doesn't handle them, but the *generator script* might.
* **易犯错的点 (Common Mistakes):** Explain that direct use is discouraged and that misusing syscalls or their parameters is the primary concern.

**7. Refining the Language:**

Use clear and concise Chinese. Avoid jargon where possible, or explain it briefly. Ensure the examples are easy to understand.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe focus on how the `mksysnum_openbsd.pl` script works. **Correction:** The request is about the *generated file*, not the generator script itself. Briefly mention the generator for context, but focus on the constants.
* **Initial thought:**  Provide a complex example of using system calls directly. **Correction:** A simpler example using `syscall.Open()` is more illustrative and less prone to confusion, as it shows the typical usage pattern.
* **Initial thought:**  List all potential errors someone could make when dealing with system calls. **Correction:** Focus on the most relevant errors related to the purpose of this file (mapping syscall names to numbers) and how developers interact with system calls in Go (usually through higher-level functions).

By following these steps, we can arrive at a comprehensive and accurate answer to the request.
这段代码是 Go 语言标准库 `syscall` 包中，针对 OpenBSD 操作系统在 RISC-V 64 位架构下的系统调用号定义。它定义了一系列常量，每个常量代表一个系统调用，并赋予了该系统调用在 OpenBSD RISC-V 64 位架构下的唯一数字标识。

**功能列举:**

1. **定义系统调用号常量:**  该文件的主要功能是为 OpenBSD 操作系统在 RISC-V 64 位架构下的所有已知系统调用定义了对应的常量。例如，`SYS_EXIT` 代表退出程序的系统调用，其值为 `1`。
2. **提供系统调用名称的符号表示:**  通过这些常量，Go 语言的 `syscall` 包可以使用易于理解的符号名称（例如 `SYS_READ`）来指代特定的系统调用，而不是直接使用难以记忆的数字。这提高了代码的可读性和可维护性。
3. **作为 `syscall` 包与操作系统内核交互的基础:**  `syscall` 包在需要执行底层操作系统操作时，会使用这些常量来调用相应的系统调用。 这些常量是 Go 程序与 OpenBSD 内核通信的关键。

**Go 语言功能的实现（推理及举例）:**

这个文件本身并不直接实现某个 Go 语言的功能，而是作为 `syscall` 包的一部分，为其他 Go 语言功能提供底层支持。  `syscall` 包允许 Go 程序直接调用操作系统的系统调用。

假设我们要使用 `syscall` 包打开一个文件，例如读取文件内容。 `syscall.Open` 函数最终会使用到 `SYS_OPEN` 这个常量。

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	path := "/etc/passwd" // 假设要打开的文件路径

	// 调用 syscall.Open 函数，最终会使用 SYS_OPEN 常量
	fd, err := syscall.Open(path, syscall.O_RDONLY, 0)
	if err != nil {
		fmt.Println("打开文件失败:", err)
		return
	}
	defer syscall.Close(fd)

	fmt.Printf("成功打开文件，文件描述符为: %d\n", fd)

	// 读取文件内容 (简化示例)
	buf := make([]byte, 100)
	n, err := syscall.Read(fd, buf)
	if err != nil {
		fmt.Println("读取文件失败:", err)
		return
	}
	fmt.Printf("读取了 %d 字节: %s\n", n, string(buf[:n]))
}
```

**代码推理与假设的输入输出:**

在这个例子中：

* **假设输入:** 文件路径字符串 `"/etc/passwd"`，打开标志 `syscall.O_RDONLY`（只读）。
* **推理过程:** 当 `syscall.Open` 函数被调用时，它会内部使用 `SYS_OPEN` 常量（其值为 5）作为系统调用号，连同文件路径和打开标志等参数一起传递给 OpenBSD 内核。
* **假设输出:**
    * **成功:** 如果文件存在且有读取权限，`syscall.Open` 将返回一个非负整数的文件描述符（例如，3）和一个 `nil` 的错误。  `syscall.Read` 可能会读取文件的前 100 个字节（或更少如果文件小于 100 字节），并返回读取的字节数和 `nil` 的错误。
    * **失败:** 如果文件不存在或没有读取权限，`syscall.Open` 将返回一个错误（例如，`syscall.ENOENT` 表示文件不存在）。

**命令行参数的具体处理:**

这个 `zsysnum_openbsd_riscv64.go` 文件本身不处理任何命令行参数。它只是定义了常量。命令行参数的处理通常发生在程序的 `main` 函数中使用 `os` 包的 `Args` 变量来获取。

**使用者易犯错的点:**

虽然开发者通常不会直接使用这些 `SYS_` 开头的常量，但在使用 `syscall` 包时，仍然可能犯错：

1. **使用了错误的系统调用或参数:**  例如，错误地使用了 `SYS_READ` 来写入文件，或者传递了不正确的参数类型或数量给某个系统调用。Go 语言的类型系统在一定程度上可以避免这种错误，但对于 `unsafe` 包和涉及底层操作的场景，仍然需要谨慎。
2. **没有正确处理系统调用的错误返回值:**  几乎所有的系统调用都可能失败，并且会返回错误码。没有检查和处理这些错误会导致程序行为不可预测。 上面的 `syscall.Open` 和 `syscall.Read` 的例子中都包含了错误检查。
3. **不了解特定系统调用的行为和限制:** 不同的操作系统和架构下的系统调用行为可能有所不同。  例如，某些系统调用可能在 OpenBSD RISC-V 64 位下可用，但在其他平台上不可用。

**总结:**

`go/src/syscall/zsysnum_openbsd_riscv64.go` 文件是 Go 语言 `syscall` 包针对 OpenBSD RISC-V 64 位架构的系统调用号定义文件，它提供了系统调用的符号名称和对应的数字标识，是 Go 程序与底层操作系统进行交互的基础。 开发者通常不会直接操作这些常量，而是通过 `syscall` 包提供的更高级的函数来间接使用它们。 理解这些常量的作用有助于理解 Go 语言如何进行底层系统编程。

Prompt: 
```
这是路径为go/src/syscall/zsysnum_openbsd_riscv64.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	SYS_GETENTROPY     = 7   // { int sys_getentropy(void *buf, size_t nbyte); }
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
	SYS_ACCESS         = 33  // { int sys_access(const char *path, int amode); }
	SYS_CHFLAGS        = 34  // { int sys_chflags(const char *path, u_int flags); }
	SYS_FCHFLAGS       = 35  // { int sys_fchflags(int fd, u_int flags); }
	SYS_SYNC           = 36  // { void sys_sync(void); }
	SYS_MSYSCALL       = 37  // { int sys_msyscall(void *addr, size_t len); }
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
	SYS_MMAP           = 49  // { void *sys_mmap(void *addr, size_t len, int prot, \
	SYS_SETLOGIN       = 50  // { int sys_setlogin(const char *namebuf); }
	SYS_ACCT           = 51  // { int sys_acct(const char *path); }
	SYS_SIGPENDING     = 52  // { int sys_sigpending(void); }
	SYS_FSTAT          = 53  // { int sys_fstat(int fd, struct stat *sb); }
	SYS_IOCTL          = 54  // { int sys_ioctl(int fd, \
	SYS_REBOOT         = 55  // { int sys_reboot(int opt); }
	SYS_REVOKE         = 56  // { int sys_revoke(const char *path); }
	SYS_SYMLINK        = 57  // { int sys_symlink(const char *path, \
	SYS_READLINK       = 58  // { ssize_t sys_readlink(const char *path, \
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
	SYS_MQUERY         = 78  // { void *sys_mquery(void *addr, size_t len, int prot, \
	SYS_GETGROUPS      = 79  // { int sys_getgroups(int gidsetsize, \
	SYS_SETGROUPS      = 80  // { int sys_setgroups(int gidsetsize, \
	SYS_GETPGRP        = 81  // { int sys_getpgrp(void); }
	SYS_SETPGID        = 82  // { int sys_setpgid(pid_t pid, pid_t pgid); }
	SYS_FUTEX          = 83  // { int sys_futex(uint32_t *f, int op, int val, \
	SYS_UTIMENSAT      = 84  // { int sys_utimensat(int fd, const char *path, \
	SYS_FUTIMENS       = 85  // { int sys_futimens(int fd, \
	SYS_KBIND          = 86  // { int sys_kbind(const struct __kbind *param, \
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
	SYS_DUP3           = 102 // { int sys_dup3(int from, int to, int flags); }
	SYS_SIGRETURN      = 103 // { int sys_sigreturn(struct sigcontext *sigcntxp); }
	SYS_BIND           = 104 // { int sys_bind(int s, const struct sockaddr *name, \
	SYS_SETSOCKOPT     = 105 // { int sys_setsockopt(int s, int level, int name, \
	SYS_LISTEN         = 106 // { int sys_listen(int s, int backlog); }
	SYS_CHFLAGSAT      = 107 // { int sys_chflagsat(int fd, const char *path, \
	SYS_PLEDGE         = 108 // { int sys_pledge(const char *promises, \
	SYS_PPOLL          = 109 // { int sys_ppoll(struct pollfd *fds, \
	SYS_PSELECT        = 110 // { int sys_pselect(int nd, fd_set *in, fd_set *ou, \
	SYS_SIGSUSPEND     = 111 // { int sys_sigsuspend(int mask); }
	SYS_SENDSYSLOG     = 112 // { int sys_sendsyslog(const char *buf, size_t nbyte, \
	SYS_UNVEIL         = 114 // { int sys_unveil(const char *path, \
	SYS___REALPATH     = 115 // { int sys___realpath(const char *pathname, \
	SYS_GETSOCKOPT     = 118 // { int sys_getsockopt(int s, int level, int name, \
	SYS_THRKILL        = 119 // { int sys_thrkill(pid_t tid, int signum, void *tcb); }
	SYS_READV          = 120 // { ssize_t sys_readv(int fd, \
	SYS_WRITEV         = 121 // { ssize_t sys_writev(int fd, \
	SYS_KILL           = 122 // { int sys_kill(int pid, int signum); }
	SYS_FCHOWN         = 123 // { int sys_fchown(int fd, uid_t uid, gid_t gid); }
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
	SYS_GETLOGIN_R     = 141 // { int sys_getlogin_r(char *namebuf, u_int namelen); }
	SYS_SETSID         = 147 // { int sys_setsid(void); }
	SYS_QUOTACTL       = 148 // { int sys_quotactl(const char *path, int cmd, \
	SYS_YPCONNECT      = 150 // { int sys_ypconnect(int type); }
	SYS_NFSSVC         = 155 // { int sys_nfssvc(int flag, void *argp); }
	SYS_GETFH          = 161 // { int sys_getfh(const char *fname, fhandle_t *fhp); }
	SYS___TMPFD        = 164 // { int sys___tmpfd(int flags); }
	SYS_SYSARCH        = 165 // { int sys_sysarch(int op, void *parms); }
	SYS_LSEEK          = 166 // { off_t sys_lseek(int fd, off_t offset, int whence); }
	SYS_TRUNCATE       = 167 // { int sys_truncate(const char *path, off_t length); }
	SYS_FTRUNCATE      = 168 // { int sys_ftruncate(int fd, off_t length); }
	SYS_PREAD          = 169 // { ssize_t sys_pread(int fd, void *buf, \
	SYS_PWRITE         = 170 // { ssize_t sys_pwrite(int fd, const void *buf, \
	SYS_PREADV         = 171 // { ssize_t sys_preadv(int fd, \
	SYS_PWRITEV        = 172 // { ssize_t sys_pwritev(int fd, \
	SYS_PAD_PREAD      = 173 // { ssize_t sys_pad_pread(int fd, void *buf, \
	SYS_PAD_PWRITE     = 174 // { ssize_t sys_pad_pwrite(int fd, const void *buf, \
	SYS_SETGID         = 181 // { int sys_setgid(gid_t gid); }
	SYS_SETEGID        = 182 // { int sys_setegid(gid_t egid); }
	SYS_SETEUID        = 183 // { int sys_seteuid(uid_t euid); }
	SYS_PATHCONF       = 191 // { long sys_pathconf(const char *path, int name); }
	SYS_FPATHCONF      = 192 // { long sys_fpathconf(int fd, int name); }
	SYS_SWAPCTL        = 193 // { int sys_swapctl(int cmd, const void *arg, int misc); }
	SYS_GETRLIMIT      = 194 // { int sys_getrlimit(int which, \
	SYS_SETRLIMIT      = 195 // { int sys_setrlimit(int which, \
	SYS_PAD_MMAP       = 197 // { void *sys_pad_mmap(void *addr, size_t len, int prot, \
	SYS_PAD_LSEEK      = 199 // { off_t sys_pad_lseek(int fd, int pad, off_t offset, \
	SYS_PAD_TRUNCATE   = 200 // { int sys_pad_truncate(const char *path, int pad, \
	SYS_PAD_FTRUNCATE  = 201 // { int sys_pad_ftruncate(int fd, int pad, off_t length); }
	SYS_SYSCTL         = 202 // { int sys_sysctl(const int *name, u_int namelen, \
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
	SYS_PAD_PREADV     = 267 // { ssize_t sys_pad_preadv(int fd, \
	SYS_PAD_PWRITEV    = 268 // { ssize_t sys_pad_pwritev(int fd, \
	SYS_KQUEUE         = 269 // { int sys_kqueue(void); }
	SYS_MLOCKALL       = 271 // { int sys_mlockall(int flags); }
	SYS_MUNLOCKALL     = 272 // { int sys_munlockall(void); }
	SYS_GETRESUID      = 281 // { int sys_getresuid(uid_t *ruid, uid_t *euid, \
	SYS_SETRESUID      = 282 // { int sys_setresuid(uid_t ruid, uid_t euid, \
	SYS_GETRESGID      = 283 // { int sys_getresgid(gid_t *rgid, gid_t *egid, \
	SYS_SETRESGID      = 284 // { int sys_setresgid(gid_t rgid, gid_t egid, \
	SYS_PAD_MQUERY     = 286 // { void *sys_pad_mquery(void *addr, size_t len, \
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