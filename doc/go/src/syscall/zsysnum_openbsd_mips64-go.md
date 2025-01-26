Response:
Let's break down the thought process for answering this request.

**1. Understanding the Core Request:**

The core task is to analyze a Go file containing `const` definitions and explain its purpose within the Go ecosystem. The file name `zsysnum_openbsd_mips64.go` gives a huge clue: it's related to system calls on a specific operating system and architecture.

**2. Initial Analysis of the Content:**

The file consists of a series of Go constants. Each constant is named `SYS_SOMETHING` and is assigned an integer value. Following each constant definition is a C-style comment indicating the function signature of the corresponding system call.

**3. Identifying the Purpose:**

The naming convention (`SYS_...`) and the C-style comments strongly suggest that these constants represent system call numbers. Operating systems use numerical identifiers to specify which kernel function to invoke when a program makes a system call. This file appears to be a mapping between symbolic names (like `SYS_READ`) and their numerical equivalents on OpenBSD for the MIPS64 architecture.

**4. Inferring the Go Feature:**

Knowing that these are system call numbers, the next step is to figure out *how* Go uses them. Go's `syscall` package provides a low-level interface to interact directly with the operating system kernel. This file is almost certainly part of that package, providing the necessary constants for making system calls on the target platform.

**5. Constructing the Functionality List:**

Based on the identification of system call numbers, I can list the functionalities provided by this file:

* **定义了OpenBSD MIPS64架构下的系统调用号:** This is the primary function.
* **作为Go语言syscall包的一部分:**  Explains its role in the Go ecosystem.
* **为Go程序进行底层操作系统交互提供基础:**  Highlights the purpose of system calls.
* **每个常量对应一个特定的系统调用:**  Emphasizes the one-to-one mapping.
* **C风格的注释提供了系统调用的原始签名信息:** Explains the meaning of the comments.

**6. Developing a Code Example:**

To illustrate how these constants are used, I need to create a Go program that makes a system call. A simple example is reading from a file. This involves the `SYS_OPEN`, `SYS_READ`, and `SYS_CLOSE` system calls.

* **Choosing relevant system calls:**  `Open`, `Read`, and `Close` are good choices because they are fundamental and relatively easy to demonstrate.
* **Importing necessary packages:** The `syscall` package is essential. `fmt` is needed for output.
* **Using the constants:**  The example should directly use the `SYS_OPEN`, `SYS_READ`, and `SYS_CLOSE` constants.
* **Handling errors:** System calls can fail, so error checking is important.
* **Providing input and output:** A sample file name (`test.txt`) is needed as input. The output will be the content of the file.
* **Explaining the code:**  Clear comments explaining each step are crucial.

**7. Reasoning about Potential Mistakes:**

Common mistakes when working with low-level system calls often involve:

* **Incorrect system call numbers:** This file prevents that by providing the correct definitions.
* **Incorrect arguments:**  The C-style comments help, but developers might still pass the wrong types or number of arguments.
* **Forgetting error handling:** This is a major source of problems in low-level programming.
* **Platform-specific code:**  System calls are OS-specific. Code using these constants will only work on OpenBSD MIPS64.

**8. Structuring the Answer:**

The final step is to organize the information clearly:

* **功能:** Start with a concise list of functionalities.
* **实现的Go语言功能及代码示例:**  Explain what Go feature this file supports and provide a working code example with explanations, assumptions, and input/output.
* **推理过程 (Implicit):**  While not explicitly labeled "推理过程," the explanation of the purpose and the code example demonstrate the reasoning.
* **命令行参数:**  These constants themselves don't involve command-line arguments, so this section can be skipped or briefly mentioned as not applicable.
* **使用者易犯错的点:** List common mistakes developers might make when working with system calls, even with the help of these constants.
* **语言:**  Ensure the entire response is in Chinese, as requested.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file is related to some kind of device driver interface. **Correction:** The system call names clearly indicate a lower-level purpose.
* **Consideration:** Should the code example use the raw `syscall.Syscall` function? **Decision:** Using the higher-level wrappers like `syscall.Open`, `syscall.Read`, and `syscall.Close` makes the example more readable and closer to typical Go usage, even though these wrappers ultimately use the constants.
* **Emphasis:**  Make sure to clearly state that this file is specific to OpenBSD MIPS64.

By following these steps, a comprehensive and accurate answer can be constructed.
这段代码是 Go 语言标准库 `syscall` 包的一部分，专门为 OpenBSD 操作系统下的 MIPS64 架构定义了系统调用号（syscall numbers）。

**功能列举:**

1. **定义了OpenBSD MIPS64架构下的系统调用号:**  每个 `SYS_` 开头的常量都代表一个特定的系统调用，其值是该系统调用在内核中的唯一标识符。
2. **作为Go语言syscall包的一部分:**  这个文件是 `syscall` 包的组成部分，`syscall` 包提供了 Go 程序与操作系统内核进行底层交互的能力。
3. **为Go程序进行底层操作系统交互提供基础:** 通过定义这些常量，Go 程序可以使用 `syscall` 包中的函数来发起相应的系统调用，执行诸如文件操作、进程管理、网络通信等底层操作。
4. **每个常量对应一个特定的系统调用:**  例如，`SYS_READ` 对应的是读取文件的系统调用，`SYS_WRITE` 对应的是写入文件的系统调用，以此类推。
5. **C风格的注释提供了系统调用的原始签名信息:**  每个常量后面的 C 风格注释，例如 `// { ssize_t sys_read(int fd, void *buf, size_t nbyte); }`，  描述了该系统调用在 C 语言层面的函数签名，包括参数类型和返回值类型。这对于理解系统调用的作用和使用方式很有帮助。

**实现的Go语言功能及代码示例:**

这段代码本身并不直接实现某个特定的 Go 语言功能，而是为 `syscall` 包提供了底层的系统调用号定义。`syscall` 包利用这些常量，封装了各种与操作系统交互的功能。

以下代码示例展示了如何使用 `syscall` 包以及这段代码中定义的常量（例如 `SYS_OPEN`, `SYS_READ`, `SYS_WRITE`, `SYS_CLOSE`）来进行文件读写操作：

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	filename := "test.txt"

	// 假设文件 test.txt 存在，内容为 "Hello, OpenBSD!"

	// 打开文件 (对应 SYS_OPEN)
	fd, err := syscall.Open(filename, syscall.O_RDONLY, 0)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer syscall.Close(fd) // 确保文件被关闭 (对应 SYS_CLOSE)

	// 读取文件内容 (对应 SYS_READ)
	buffer := make([]byte, 100)
	n, err := syscall.Read(fd, buffer)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	fmt.Printf("Read %d bytes: %s\n", n, string(buffer[:n]))

	// 创建并写入文件 (使用 SYS_OPEN, SYS_WRITE)
	writeFilename := "output.txt"
	wfd, err := syscall.Open(writeFilename, syscall.O_WRONLY|syscall.O_CREATE|syscall.O_TRUNC, 0644)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer syscall.Close(wfd)

	message := "This is a test write."
	messageBytes := []byte(message)
	_, err = syscall.Write(wfd, messageBytes)
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}
	fmt.Println("Successfully wrote to", writeFilename)
}
```

**假设的输入与输出：**

**假设输入：**  当前目录下存在一个名为 `test.txt` 的文件，内容为 "Hello, OpenBSD!"

**预期输出：**

```
Read 14 bytes: Hello, OpenBSD!
Successfully wrote to output.txt
```

并且会在当前目录下创建一个名为 `output.txt` 的文件，内容为 "This is a test write."。

**代码推理：**

1. **`syscall.Open(filename, syscall.O_RDONLY, 0)`:**  调用了 `syscall` 包中的 `Open` 函数，这个函数在底层会使用 `SYS_OPEN` 这个系统调用号，并传递文件名、打开标志（只读）和权限模式。
2. **`syscall.Read(fd, buffer)`:** 调用了 `syscall` 包中的 `Read` 函数，底层会使用 `SYS_READ` 系统调用，读取文件描述符 `fd` 指向的文件内容到 `buffer` 中。
3. **`syscall.Close(fd)`:** 调用了 `syscall` 包中的 `Close` 函数，底层会使用 `SYS_CLOSE` 系统调用，关闭文件描述符 `fd` 指向的文件。
4. **`syscall.Open(writeFilename, syscall.O_WRONLY|syscall.O_CREATE|syscall.O_TRUNC, 0644)`:**  再次使用 `syscall.Open`，这次使用写模式、创建模式（如果文件不存在则创建）和截断模式（如果文件存在则清空内容），并设置文件权限为 0644。
5. **`syscall.Write(wfd, messageBytes)`:** 调用 `syscall.Write`，底层使用 `SYS_WRITE` 系统调用，将 `messageBytes` 中的内容写入到文件描述符 `wfd` 指向的文件中。

**命令行参数的具体处理：**

这段代码本身不直接处理命令行参数。 命令行参数的处理通常在 `main` 函数中使用 `os.Args` 切片来获取。然而，这些系统调用可能会间接地受到命令行参数的影响。例如，如果一个程序接收一个命令行参数作为文件名，并使用 `syscall.Open` 打开该文件，那么 `SYS_OPEN` 系统调用的行为会受到命令行参数的影响。

**使用者易犯错的点：**

1. **硬编码系统调用号:**  开发者不应该直接使用这段代码中定义的常量值，而应该使用 `syscall` 包提供的封装好的函数，例如 `syscall.Open`、`syscall.Read` 等。直接使用常量值会使代码难以维护且容易出错，因为系统调用号在不同的操作系统和架构上可能不同。
2. **不正确的参数传递:**  直接调用 `syscall.Syscall` 等底层函数时，需要精确地传递符合系统调用要求的参数类型和数量。参考注释中的 C 风格签名可以帮助理解参数类型，但仍然容易出错。例如，传递了错误的指针类型或大小。
3. **忽略错误处理:**  系统调用可能会失败，例如文件不存在、权限不足等。必须检查系统调用的返回值（通常是 error 类型）并进行相应的处理。忽略错误处理可能导致程序崩溃或产生不可预期的行为。
4. **平台依赖性:**  使用 `syscall` 包编写的代码通常是平台相关的。这段代码中的常量是为 OpenBSD MIPS64 架构定义的，不能直接用于其他操作系统或架构。如果需要编写跨平台的底层操作代码，需要使用条件编译或者更高级的抽象层。

总而言之，这段代码是 Go 语言 `syscall` 包在 OpenBSD MIPS64 架构下的基础，它定义了与操作系统内核交互的各种系统调用的编号。开发者应该使用 `syscall` 包提供的更高级别的封装函数，而不是直接操作这些常量，以提高代码的可读性、可维护性和跨平台性。

Prompt: 
```
这是路径为go/src/syscall/zsysnum_openbsd_mips64.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	SYS_NFSSVC         = 155 // { int sys_nfssvc(int flag, void *argp); }
	SYS_GETFH          = 161 // { int sys_getfh(const char *fname, fhandle_t *fhp); }
	SYS___TMPFD        = 164 // { int sys___tmpfd(int flags); }
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