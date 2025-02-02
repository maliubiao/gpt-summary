Response:
Let's break down the thought process for answering the user's request about the `zsysnum_freebsd_riscv64.go` file.

**1. Understanding the Core Request:**

The user wants to understand the *function* of the provided Go code snippet. Specifically, they want:

* A list of its functionalities.
* An explanation of what Go feature it implements, with code examples.
* Details about command-line arguments (if applicable).
* Common mistakes users might make.
* A summary of its overall purpose.

**2. Initial Analysis of the Code:**

The code consists of a Go package declaration (`package syscall`) and a series of `const` declarations. Each constant definition follows a pattern: `SYS_SOMETHING = number // { function signature } description`.

This strongly suggests that the file defines symbolic names for system call numbers on the FreeBSD operating system for the RISC-V 64-bit architecture. The comments provide the C function signature of the corresponding system call.

**3. Identifying the Primary Functionality:**

Based on the initial analysis, the core functionality is clearly the *definition of system call numbers*. This is crucial for the `syscall` package to interact with the operating system kernel.

**4. Inferring the Go Feature:**

The `syscall` package in Go is the primary way to make direct system calls. This file, by defining system call numbers, is a fundamental part of how Go programs can interact with the operating system at a low level.

**5. Developing a Code Example:**

To illustrate the usage, we need to show how these constants are used. The `syscall` package provides functions like `Syscall`, `Syscall6`, etc., which take the system call number as an argument. A simple example would be calling `syscall.Exit`. We can use the `SYS_EXIT` constant defined in the file.

* **Input:**  A Go program calling `syscall.Exit(0)`.
* **Process:**  The Go runtime will use the `SYS_EXIT` constant (which is 1) when making the system call.
* **Output:** The program terminates with an exit code of 0.

**6. Addressing Command-Line Arguments:**

By examining the code, it's clear that this file itself doesn't process command-line arguments. It's a data definition file. It's important to state this explicitly to avoid confusion.

**7. Identifying Potential User Mistakes:**

Users generally won't directly edit this generated file. However, when *using* the `syscall` package, common mistakes include:

* **Incorrect system call numbers:**  While this file *defines* them correctly, users might manually try to use system call numbers without using the constants, which could lead to errors if the number is wrong or for a different architecture.
* **Incorrect arguments:** System calls have specific argument types and counts. Using the wrong arguments with `syscall.Syscall` (or similar) will cause issues.

**8. Summarizing the Functionality:**

The summary should concisely state that the file defines system call numbers for FreeBSD on RISC-V 64-bit, enabling the `syscall` package to interact with the kernel.

**9. Structuring the Answer:**

The answer should be organized clearly, following the user's requested points:

* Function listing (enumerating the defined system calls).
* Go feature explanation with a code example.
* Discussion of command-line arguments (or the lack thereof).
* Common user mistakes when using the `syscall` package.
* A final summary.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this file also contains logic for handling system call arguments. **Correction:**  No, it's purely a definition of constants. Argument handling is in other parts of the `syscall` package.
* **Considering example complexity:**  Should the example involve more complex system calls? **Decision:**  Start with a simple `syscall.Exit` for clarity. More complex examples could be provided if requested.
* **Focusing on user perspective:**  The "common mistakes" section should focus on how users interact with the `syscall` package, not on mistakes in *generating* this file.

By following these steps, including analyzing the code structure, inferring the purpose, and considering the user's perspective, we can arrive at a comprehensive and accurate answer.
这是 `go/src/syscall/zsysnum_freebsd_riscv64.go` 文件的一部分，它定义了一系列常量，这些常量代表了 **FreeBSD 操作系统在 RISC-V 64 位架构上的系统调用号 (syscall numbers)**。

**功能归纳:**

这个文件的主要功能是为 Go 语言的 `syscall` 标准库提供一个 **系统调用号的映射表**。它将每个系统调用的名称（例如 `SYS_EXIT`, `SYS_READ`, `SYS_OPEN` 等）与一个唯一的整数值关联起来。

**更详细的功能解释:**

1. **定义系统调用常量:**  文件中每一行的 `SYS_XXX = NNN` 都定义了一个常量，其中 `SYS_XXX` 是系统调用的符号名称，`NNN` 是该系统调用在 FreeBSD RISC-V 64 位架构下的编号。例如，`SYS_EXIT = 1` 表示退出程序的系统调用号是 1。

2. **提供元数据信息:**  每行常量定义的注释部分，例如 `// { void sys_exit(int rval); } exit sys_exit_args void`，提供了关于该系统调用的元数据信息，包括：
    * C 语言中的函数签名 (`void sys_exit(int rval);`)
    * 系统调用的名称 (`exit`)
    * 参数结构体的名称 (`sys_exit_args`)
    * 返回值类型 (`void`)

3. **作为 `syscall` 包的一部分:** 这个文件是 Go 语言标准库 `syscall` 包的一部分。`syscall` 包允许 Go 程序直接调用操作系统提供的系统调用接口。这个文件提供了 `syscall` 包在 FreeBSD RISC-V 64 位架构下工作所必需的系统调用编号。

**它是什么 go 语言功能的实现？**

这个文件是 Go 语言 **`syscall` 包** 的一部分实现。`syscall` 包是 Go 语言提供的一个低级接口，允许 Go 程序直接与操作系统内核进行交互。通过定义这些系统调用号，`syscall` 包可以调用相应的内核功能。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	// 使用 SYS_WRITE 常量 (值为 4) 调用 write 系统调用
	message := []byte("Hello, syscall!\n")
	fd := uintptr(1) // 标准输出的文件描述符
	ptr := uintptr(unsafe.Pointer(&message[0]))
	nbyte := uintptr(len(message))

	// syscall.Syscall 使用系统调用号和参数进行调用
	_, _, err := syscall.Syscall(syscall.SYS_WRITE, fd, ptr, nbyte)
	if err != 0 {
		fmt.Println("syscall write error:", err)
	}

	// 使用 SYS_EXIT 常量 (值为 1) 调用 exit 系统调用
	syscall.Exit(0)
}
```

**假设的输入与输出:**

在这个例子中，没有明确的“输入”，因为我们直接在代码中构造了要写入的消息。

* **假设输入:**  无。
* **预期输出:**  程序会在标准输出打印 "Hello, syscall!\n" 并正常退出。

**代码推理:**

1. `syscall.SYS_WRITE` 常量的值是 4，这对应于 `zsysnum_freebsd_riscv64.go` 中定义的 `SYS_WRITE`。
2. `syscall.Syscall(syscall.SYS_WRITE, fd, ptr, nbyte)` 会发起一个系统调用，其编号为 4，并将文件描述符 `fd`，指向消息缓冲区的指针 `ptr`，以及要写入的字节数 `nbyte` 作为参数传递给内核。
3. 如果系统调用成功，`write` 系统调用会将 "Hello, syscall!\n" 写入到标准输出。
4. 接着，`syscall.SYS_EXIT` 常量的值是 1，对应于 `SYS_EXIT` 的定义。
5. `syscall.Exit(0)` 会发起一个系统调用，其编号为 1，并传递退出码 0，从而正常终止程序。

**命令行参数的具体处理:**

这个 `zsysnum_freebsd_riscv64.go` 文件本身不处理命令行参数。它只是一个定义常量的文件。命令行参数的处理通常发生在 `main` 函数中，并可以使用 `os` 包的 `os.Args` 获取。

**总结一下它的功能:**

`go/src/syscall/zsysnum_freebsd_riscv64.go` 文件的主要功能是为 Go 语言的 `syscall` 包在 FreeBSD 操作系统和 RISC-V 64 位架构下提供系统调用号的映射。它定义了一系列常量，将系统调用的符号名称与它们在内核中的数字编号关联起来，这是 `syscall` 包能够与操作系统内核进行交互的基础。

Prompt: 
```
这是路径为go/src/syscall/zsysnum_freebsd_riscv64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// mksysnum_freebsd.pl
// Code generated by the command above; DO NOT EDIT.

package syscall

const (
	// SYS_NOSYS = 0;  // { int nosys(void); } syscall nosys_args int
	SYS_EXIT                     = 1   // { void sys_exit(int rval); } exit sys_exit_args void
	SYS_FORK                     = 2   // { int fork(void); }
	SYS_READ                     = 3   // { ssize_t read(int fd, void *buf, size_t nbyte); }
	SYS_WRITE                    = 4   // { ssize_t write(int fd, const void *buf, size_t nbyte); }
	SYS_OPEN                     = 5   // { int open(char *path, int flags, int mode); }
	SYS_CLOSE                    = 6   // { int close(int fd); }
	SYS_WAIT4                    = 7   // { int wait4(int pid, int *status, int options, struct rusage *rusage); }
	SYS_LINK                     = 9   // { int link(char *path, char *link); }
	SYS_UNLINK                   = 10  // { int unlink(char *path); }
	SYS_CHDIR                    = 12  // { int chdir(char *path); }
	SYS_FCHDIR                   = 13  // { int fchdir(int fd); }
	SYS_MKNOD                    = 14  // { int mknod(char *path, int mode, int dev); }
	SYS_CHMOD                    = 15  // { int chmod(char *path, int mode); }
	SYS_CHOWN                    = 16  // { int chown(char *path, int uid, int gid); }
	SYS_OBREAK                   = 17  // { int obreak(char *nsize); } break obreak_args int
	SYS_GETPID                   = 20  // { pid_t getpid(void); }
	SYS_MOUNT                    = 21  // { int mount(char *type, char *path, int flags, caddr_t data); }
	SYS_UNMOUNT                  = 22  // { int unmount(char *path, int flags); }
	SYS_SETUID                   = 23  // { int setuid(uid_t uid); }
	SYS_GETUID                   = 24  // { uid_t getuid(void); }
	SYS_GETEUID                  = 25  // { uid_t geteuid(void); }
	SYS_PTRACE                   = 26  // { int ptrace(int req, pid_t pid, caddr_t addr, int data); }
	SYS_RECVMSG                  = 27  // { int recvmsg(int s, struct msghdr *msg, int flags); }
	SYS_SENDMSG                  = 28  // { int sendmsg(int s, struct msghdr *msg, int flags); }
	SYS_RECVFROM                 = 29  // { int recvfrom(int s, caddr_t buf, size_t len, int flags, struct sockaddr * __restrict from, __socklen_t * __restrict fromlenaddr); }
	SYS_ACCEPT                   = 30  // { int accept(int s, struct sockaddr * __restrict name, __socklen_t * __restrict anamelen); }
	SYS_GETPEERNAME              = 31  // { int getpeername(int fdes, struct sockaddr * __restrict asa, __socklen_t * __restrict alen); }
	SYS_GETSOCKNAME              = 32  // { int getsockname(int fdes, struct sockaddr * __restrict asa, __socklen_t * __restrict alen); }
	SYS_ACCESS                   = 33  // { int access(char *path, int amode); }
	SYS_CHFLAGS                  = 34  // { int chflags(const char *path, u_long flags); }
	SYS_FCHFLAGS                 = 35  // { int fchflags(int fd, u_long flags); }
	SYS_SYNC                     = 36  // { int sync(void); }
	SYS_KILL                     = 37  // { int kill(int pid, int signum); }
	SYS_GETPPID                  = 39  // { pid_t getppid(void); }
	SYS_DUP                      = 41  // { int dup(u_int fd); }
	SYS_PIPE                     = 42  // { int pipe(void); }
	SYS_GETEGID                  = 43  // { gid_t getegid(void); }
	SYS_PROFIL                   = 44  // { int profil(caddr_t samples, size_t size, size_t offset, u_int scale); }
	SYS_KTRACE                   = 45  // { int ktrace(const char *fname, int ops, int facs, int pid); }
	SYS_GETGID                   = 47  // { gid_t getgid(void); }
	SYS_GETLOGIN                 = 49  // { int getlogin(char *namebuf, u_int namelen); }
	SYS_SETLOGIN                 = 50  // { int setlogin(char *namebuf); }
	SYS_ACCT                     = 51  // { int acct(char *path); }
	SYS_SIGALTSTACK              = 53  // { int sigaltstack(stack_t *ss, stack_t *oss); }
	SYS_IOCTL                    = 54  // { int ioctl(int fd, u_long com, caddr_t data); }
	SYS_REBOOT                   = 55  // { int reboot(int opt); }
	SYS_REVOKE                   = 56  // { int revoke(char *path); }
	SYS_SYMLINK                  = 57  // { int symlink(char *path, char *link); }
	SYS_READLINK                 = 58  // { ssize_t readlink(char *path, char *buf, size_t count); }
	SYS_EXECVE                   = 59  // { int execve(char *fname, char **argv, char **envv); }
	SYS_UMASK                    = 60  // { int umask(int newmask); } umask umask_args int
	SYS_CHROOT                   = 61  // { int chroot(char *path); }
	SYS_MSYNC                    = 65  // { int msync(void *addr, size_t len, int flags); }
	SYS_VFORK                    = 66  // { int vfork(void); }
	SYS_SBRK                     = 69  // { int sbrk(int incr); }
	SYS_SSTK                     = 70  // { int sstk(int incr); }
	SYS_OVADVISE                 = 72  // { int ovadvise(int anom); } vadvise ovadvise_args int
	SYS_MUNMAP                   = 73  // { int munmap(void *addr, size_t len); }
	SYS_MPROTECT                 = 74  // { int mprotect(const void *addr, size_t len, int prot); }
	SYS_MADVISE                  = 75  // { int madvise(void *addr, size_t len, int behav); }
	SYS_MINCORE                  = 78  // { int mincore(const void *addr, size_t len, char *vec); }
	SYS_GETGROUPS                = 79  // { int getgroups(u_int gidsetsize, gid_t *gidset); }
	SYS_SETGROUPS                = 80  // { int setgroups(u_int gidsetsize, gid_t *gidset); }
	SYS_GETPGRP                  = 81  // { int getpgrp(void); }
	SYS_SETPGID                  = 82  // { int setpgid(int pid, int pgid); }
	SYS_SETITIMER                = 83  // { int setitimer(u_int which, struct itimerval *itv, struct itimerval *oitv); }
	SYS_SWAPON                   = 85  // { int swapon(char *name); }
	SYS_GETITIMER                = 86  // { int getitimer(u_int which, struct itimerval *itv); }
	SYS_GETDTABLESIZE            = 89  // { int getdtablesize(void); }
	SYS_DUP2                     = 90  // { int dup2(u_int from, u_int to); }
	SYS_FCNTL                    = 92  // { int fcntl(int fd, int cmd, long arg); }
	SYS_SELECT                   = 93  // { int select(int nd, fd_set *in, fd_set *ou, fd_set *ex, struct timeval *tv); }
	SYS_FSYNC                    = 95  // { int fsync(int fd); }
	SYS_SETPRIORITY              = 96  // { int setpriority(int which, int who, int prio); }
	SYS_SOCKET                   = 97  // { int socket(int domain, int type, int protocol); }
	SYS_CONNECT                  = 98  // { int connect(int s, caddr_t name, int namelen); }
	SYS_GETPRIORITY              = 100 // { int getpriority(int which, int who); }
	SYS_BIND                     = 104 // { int bind(int s, caddr_t name, int namelen); }
	SYS_SETSOCKOPT               = 105 // { int setsockopt(int s, int level, int name, caddr_t val, int valsize); }
	SYS_LISTEN                   = 106 // { int listen(int s, int backlog); }
	SYS_GETTIMEOFDAY             = 116 // { int gettimeofday(struct timeval *tp, struct timezone *tzp); }
	SYS_GETRUSAGE                = 117 // { int getrusage(int who, struct rusage *rusage); }
	SYS_GETSOCKOPT               = 118 // { int getsockopt(int s, int level, int name, caddr_t val, int *avalsize); }
	SYS_READV                    = 120 // { int readv(int fd, struct iovec *iovp, u_int iovcnt); }
	SYS_WRITEV                   = 121 // { int writev(int fd, struct iovec *iovp, u_int iovcnt); }
	SYS_SETTIMEOFDAY             = 122 // { int settimeofday(struct timeval *tv, struct timezone *tzp); }
	SYS_FCHOWN                   = 123 // { int fchown(int fd, int uid, int gid); }
	SYS_FCHMOD                   = 124 // { int fchmod(int fd, int mode); }
	SYS_SETREUID                 = 126 // { int setreuid(int ruid, int euid); }
	SYS_SETREGID                 = 127 // { int setregid(int rgid, int egid); }
	SYS_RENAME                   = 128 // { int rename(char *from, char *to); }
	SYS_FLOCK                    = 131 // { int flock(int fd, int how); }
	SYS_MKFIFO                   = 132 // { int mkfifo(char *path, int mode); }
	SYS_SENDTO                   = 133 // { int sendto(int s, caddr_t buf, size_t len, int flags, caddr_t to, int tolen); }
	SYS_SHUTDOWN                 = 134 // { int shutdown(int s, int how); }
	SYS_SOCKETPAIR               = 135 // { int socketpair(int domain, int type, int protocol, int *rsv); }
	SYS_MKDIR                    = 136 // { int mkdir(char *path, int mode); }
	SYS_RMDIR                    = 137 // { int rmdir(char *path); }
	SYS_UTIMES                   = 138 // { int utimes(char *path, struct timeval *tptr); }
	SYS_ADJTIME                  = 140 // { int adjtime(struct timeval *delta, struct timeval *olddelta); }
	SYS_SETSID                   = 147 // { int setsid(void); }
	SYS_QUOTACTL                 = 148 // { int quotactl(char *path, int cmd, int uid, caddr_t arg); }
	SYS_NLM_SYSCALL              = 154 // { int nlm_syscall(int debug_level, int grace_period, int addr_count, char **addrs); }
	SYS_NFSSVC                   = 155 // { int nfssvc(int flag, caddr_t argp); }
	SYS_LGETFH                   = 160 // { int lgetfh(char *fname, struct fhandle *fhp); }
	SYS_GETFH                    = 161 // { int getfh(char *fname, struct fhandle *fhp); }
	SYS_SYSARCH                  = 165 // { int sysarch(int op, char *parms); }
	SYS_RTPRIO                   = 166 // { int rtprio(int function, pid_t pid, struct rtprio *rtp); }
	SYS_SEMSYS                   = 169 // { int semsys(int which, int a2, int a3, int a4, int a5); }
	SYS_MSGSYS                   = 170 // { int msgsys(int which, int a2, int a3, int a4, int a5, int a6); }
	SYS_SHMSYS                   = 171 // { int shmsys(int which, int a2, int a3, int a4); }
	SYS_SETFIB                   = 175 // { int setfib(int fibnum); }
	SYS_NTP_ADJTIME              = 176 // { int ntp_adjtime(struct timex *tp); }
	SYS_SETGID                   = 181 // { int setgid(gid_t gid); }
	SYS_SETEGID                  = 182 // { int setegid(gid_t egid); }
	SYS_SETEUID                  = 183 // { int seteuid(uid_t euid); }
	SYS_PATHCONF                 = 191 // { int pathconf(char *path, int name); }
	SYS_FPATHCONF                = 192 // { int fpathconf(int fd, int name); }
	SYS_GETRLIMIT                = 194 // { int getrlimit(u_int which, struct rlimit *rlp); } getrlimit __getrlimit_args int
	SYS_SETRLIMIT                = 195 // { int setrlimit(u_int which, struct rlimit *rlp); } setrlimit __setrlimit_args int
	SYS___SYSCTL                 = 202 // { int __sysctl(int *name, u_int namelen, void *old, size_t *oldlenp, void *new, size_t newlen); } __sysctl sysctl_args int
	SYS_MLOCK                    = 203 // { int mlock(const void *addr, size_t len); }
	SYS_MUNLOCK                  = 204 // { int munlock(const void *addr, size_t len); }
	SYS_UNDELETE                 = 205 // { int undelete(char *path); }
	SYS_FUTIMES                  = 206 // { int futimes(int fd, struct timeval *tptr); }
	SYS_GETPGID                  = 207 // { int getpgid(pid_t pid); }
	SYS_POLL                     = 209 // { int poll(struct pollfd *fds, u_int nfds, int timeout); }
	SYS_SEMGET                   = 221 // { int semget(key_t key, int nsems, int semflg); }
	SYS_SEMOP                    = 222 // { int semop(int semid, struct sembuf *sops, size_t nsops); }
	SYS_MSGGET                   = 225 // { int msgget(key_t key, int msgflg); }
	SYS_MSGSND                   = 226 // { int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg); }
	SYS_MSGRCV                   = 227 // { int msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg); }
	SYS_SHMAT                    = 228 // { int shmat(int shmid, const void *shmaddr, int shmflg); }
	SYS_SHMDT                    = 230 // { int shmdt(const void *shmaddr); }
	SYS_SHMGET                   = 231 // { int shmget(key_t key, size_t size, int shmflg); }
	SYS_CLOCK_GETTIME            = 232 // { int clock_gettime(clockid_t clock_id, struct timespec *tp); }
	SYS_CLOCK_SETTIME            = 233 // { int clock_settime( clockid_t clock_id, const struct timespec *tp); }
	SYS_CLOCK_GETRES             = 234 // { int clock_getres(clockid_t clock_id, struct timespec *tp); }
	SYS_KTIMER_CREATE            = 235 // { int ktimer_create(clockid_t clock_id, struct sigevent *evp, int *timerid); }
	SYS_KTIMER_DELETE            = 236 // { int ktimer_delete(int timerid); }
	SYS_KTIMER_SETTIME           = 237 // { int ktimer_settime(int timerid, int flags, const struct itimerspec *value, struct itimerspec *ovalue); }
	SYS_KTIMER_GETTIME           = 238 // { int ktimer_gettime(int timerid, struct itimerspec *value); }
	SYS_KTIMER_GETOVERRUN        = 239 // { int ktimer_getoverrun(int timerid); }
	SYS_NANOSLEEP                = 240 // { int nanosleep(const struct timespec *rqtp, struct timespec *rmtp); }
	SYS_FFCLOCK_GETCOUNTER       = 241 // { int ffclock_getcounter(ffcounter *ffcount); }
	SYS_FFCLOCK_SETESTIMATE      = 242 // { int ffclock_setestimate( struct ffclock_estimate *cest); }
	SYS_FFCLOCK_GETESTIMATE      = 243 // { int ffclock_getestimate( struct ffclock_estimate *cest); }
	SYS_CLOCK_NANOSLEEP          = 244 // { int clock_nanosleep(clockid_t clock_id, int flags, const struct timespec *rqtp, struct timespec *rmtp); }
	SYS_CLOCK_GETCPUCLOCKID2     = 247 // { int clock_getcpuclockid2(id_t id,int which, clockid_t *clock_id); }
	SYS_NTP_GETTIME              = 248 // { int ntp_gettime(struct ntptimeval *ntvp); }
	SYS_MINHERIT                 = 250 // { int minherit(void *addr, size_t len, int inherit); }
	SYS_RFORK                    = 251 // { int rfork(int flags); }
	SYS_OPENBSD_POLL             = 252 // { int openbsd_poll(struct pollfd *fds, u_int nfds, int timeout); }
	SYS_ISSETUGID                = 253 // { int issetugid(void); }
	SYS_LCHOWN                   = 254 // { int lchown(char *path, int uid, int gid); }
	SYS_AIO_READ                 = 255 // { int aio_read(struct aiocb *aiocbp); }
	SYS_AIO_WRITE                = 256 // { int aio_write(struct aiocb *aiocbp); }
	SYS_LIO_LISTIO               = 257 // { int lio_listio(int mode, struct aiocb * const *acb_list, int nent, struct sigevent *sig); }
	SYS_GETDENTS                 = 272 // { int getdents(int fd, char *buf, size_t count); }
	SYS_LCHMOD                   = 274 // { int lchmod(char *path, mode_t mode); }
	SYS_LUTIMES                  = 276 // { int lutimes(char *path, struct timeval *tptr); }
	SYS_NSTAT                    = 278 // { int nstat(char *path, struct nstat *ub); }
	SYS_NFSTAT                   = 279 // { int nfstat(int fd, struct nstat *sb); }
	SYS_NLSTAT                   = 280 // { int nlstat(char *path, struct nstat *ub); }
	SYS_PREADV                   = 289 // { ssize_t preadv(int fd, struct iovec *iovp, u_int iovcnt, off_t offset); }
	SYS_PWRITEV                  = 290 // { ssize_t pwritev(int fd, struct iovec *iovp, u_int iovcnt, off_t offset); }
	SYS_FHOPEN                   = 298 // { int fhopen(const struct fhandle *u_fhp, int flags); }
	SYS_FHSTAT                   = 299 // { int fhstat(const struct fhandle *u_fhp, struct stat *sb); }
	SYS_MODNEXT                  = 300 // { int modnext(int modid); }
	SYS_MODSTAT                  = 301 // { int modstat(int modid, struct module_stat *stat); }
	SYS_MODFNEXT                 = 302 // { int modfnext(int modid); }
	SYS_MODFIND                  = 303 // { int modfind(const char *name); }
	SYS_KLDLOAD                  = 304 // { int kldload(const char *file); }
	SYS_KLDUNLOAD                = 305 // { int kldunload(int fileid); }
	SYS_KLDFIND                  = 306 // { int kldfind(const char *file); }
	SYS_KLDNEXT                  = 307 // { int kldnext(int fileid); }
	SYS_KLDSTAT                  = 308 // { int kldstat(int fileid, struct kld_file_stat* stat); }
	SYS_KLDFIRSTMOD              = 309 // { int kldfirstmod(int fileid); }
	SYS_GETSID                   = 310 // { int getsid(pid_t pid); }
	SYS_SETRESUID                = 311 // { int setresuid(uid_t ruid, uid_t euid, uid_t suid); }
	SYS_SETRESGID                = 312 // { int setresgid(gid_t rgid, gid_t egid, gid_t sgid); }
	SYS_AIO_RETURN               = 314 // { ssize_t aio_return(struct aiocb *aiocbp); }
	SYS_AIO_SUSPEND              = 315 // { int aio_suspend( struct aiocb * const * aiocbp, int nent, const struct timespec *timeout); }
	SYS_AIO_CANCEL               = 316 // { int aio_cancel(int fd, struct aiocb *aiocbp); }
	SYS_AIO_ERROR                = 317 // { int aio_error(struct aiocb *aiocbp); }
	SYS_YIELD                    = 321 // { int yield(void); }
	SYS_MLOCKALL                 = 324 // { int mlockall(int how); }
	SYS_MUNLOCKALL               = 325 // { int munlockall(void); }
	SYS___GETCWD                 = 326 // { int __getcwd(char *buf, u_int buflen); }
	SYS_SCHED_SETPARAM           = 327 // { int sched_setparam (pid_t pid, const struct sched_param *param); }
	SYS_SCHED_GETPARAM           = 328 // { int sched_getparam (pid_t pid, struct sched_param *param); }
	SYS_SCHED_SETSCHEDULER       = 329 // { int sched_setscheduler (pid_t pid, int policy, const struct sched_param *param); }
	SYS_SCHED_GETSCHEDULER       = 330 // { int sched_getscheduler (pid_t pid); }
	SYS_SCHED_YIELD              = 331 // { int sched_yield (void); }
	SYS_SCHED_GET_PRIORITY_MAX   = 332 // { int sched_get_priority_max (int policy); }
	SYS_SCHED_GET_PRIORITY_MIN   = 333 // { int sched_get_priority_min (int policy); }
	SYS_SCHED_RR_GET_INTERVAL    = 334 // { int sched_rr_get_interval (pid_t pid, struct timespec *interval); }
	SYS_UTRACE                   = 335 // { int utrace(const void *addr, size_t len); }
	SYS_KLDSYM                   = 337 // { int kldsym(int fileid, int cmd, void *data); }
	SYS_JAIL                     = 338 // { int jail(struct jail *jail); }
	SYS_SIGPROCMASK              = 340 // { int sigprocmask(int how, const sigset_t *set, sigset_t *oset); }
	SYS_SIGSUSPEND               = 341 // { int sigsuspend(const sigset_t *sigmask); }
	SYS_SIGPENDING               = 343 // { int sigpending(sigset_t *set); }
	SYS_SIGTIMEDWAIT             = 345 // { int sigtimedwait(const sigset_t *set, siginfo_t *info, const struct timespec *timeout); }
	SYS_SIGWAITINFO              = 346 // { int sigwaitinfo(const sigset_t *set, siginfo_t *info); }
	SYS___ACL_GET_FILE           = 347 // { int __acl_get_file(const char *path, acl_type_t type, struct acl *aclp); }
	SYS___ACL_SET_FILE           = 348 // { int __acl_set_file(const char *path, acl_type_t type, struct acl *aclp); }
	SYS___ACL_GET_FD             = 349 // { int __acl_get_fd(int filedes, acl_type_t type, struct acl *aclp); }
	SYS___ACL_SET_FD             = 350 // { int __acl_set_fd(int filedes, acl_type_t type, struct acl *aclp); }
	SYS___ACL_DELETE_FILE        = 351 // { int __acl_delete_file(const char *path, acl_type_t type); }
	SYS___ACL_DELETE_FD          = 352 // { int __acl_delete_fd(int filedes, acl_type_t type); }
	SYS___ACL_ACLCHECK_FILE      = 353 // { int __acl_aclcheck_file(const char *path, acl_type_t type, struct acl *aclp); }
	SYS___ACL_ACLCHECK_FD        = 354 // { int __acl_aclcheck_fd(int filedes, acl_type_t type, struct acl *aclp); }
	SYS_EXTATTRCTL               = 355 // { int extattrctl(const char *path, int cmd, const char *filename, int attrnamespace, const char *attrname); }
	SYS_EXTATTR_SET_FILE         = 356 // { ssize_t extattr_set_file( const char *path, int attrnamespace, const char *attrname, void *data, size_t nbytes); }
	SYS_EXTATTR_GET_FILE         = 357 // { ssize_t extattr_get_file( const char *path, int attrnamespace, const char *attrname, void *data, size_t nbytes); }
	SYS_EXTATTR_DELETE_FILE      = 358 // { int extattr_delete_file(const char *path, int attrnamespace, const char *attrname); }
	SYS_AIO_WAITCOMPLETE         = 359 // { ssize_t aio_waitcomplete( struct aiocb **aiocbp, struct timespec *timeout); }
	SYS_GETRESUID                = 360 // { int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid); }
	SYS_GETRESGID                = 361 // { int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid); }
	SYS_KQUEUE                   = 362 // { int kqueue(void); }
	SYS_KEVENT                   = 363 // { int kevent(int fd, struct kevent *changelist, int nchanges, struct kevent *eventlist, int nevents, const struct timespec *timeout); }
	SYS_EXTATTR_SET_FD           = 371 // { ssize_t extattr_set_fd(int fd, int attrnamespace, const char *attrname, void *data, size_t nbytes); }
	SYS_EXTATTR_GET_FD           = 372 // { ssize_t extattr_get_fd(int fd, int attrnamespace, const char *attrname, void *data, size_t nbytes); }
	SYS_EXTATTR_DELETE_FD        = 373 // { int extattr_delete_fd(int fd, int attrnamespace, const char *attrname); }
	SYS___SETUGID                = 374 // { int __setugid(int flag); }
	SYS_EACCESS                  = 376 // { int eaccess(char *path, int amode); }
	SYS_NMOUNT                   = 378 // { int nmount(struct iovec *iovp, unsigned int iovcnt, int flags); }
	SYS___MAC_GET_PROC           = 384 // { int __mac_get_proc(struct mac *mac_p); }
	SYS___MAC_SET_PROC           = 385 // { int __mac_set_proc(struct mac *mac_p); }
	SYS___MAC_GET_FD             = 386 // { int __mac_get_fd(int fd, struct mac *mac_p); }
	SYS___MAC_GET_FILE           = 387 // { int __mac_get_file(const char *path_p, struct mac *mac_p); }
	SYS___MAC_SET_FD             = 388 // { int __mac_set_fd(int fd, struct mac *mac_p); }
	SYS___MAC_SET_FILE           = 389 // { int __mac_set_file(const char *path_p, struct mac *mac_p); }
	SYS_KENV                     = 390 // { int kenv(int what, const char *name, char *value, int len); }
	SYS_LCHFLAGS                 = 391 // { int lchflags(const char *path, u_long flags); }
	SYS_UUIDGEN                  = 392 // { int uuidgen(struct uuid *store, int count); }
	SYS_SENDFILE                 = 393 // { int sendfile(int fd, int s, off_t offset, size_t nbytes, struct sf_hdtr *hdtr, off_t *sbytes, int flags); }
	SYS_MAC_SYSCALL              = 394 // { int mac_syscall(const char *policy, int call, void *arg); }
	SYS_FHSTATFS                 = 398 // { int fhstatfs(const struct fhandle *u_fhp, struct statfs *buf); }
	SYS_KSEM_CLOSE               = 400 // { int ksem_close(semid_t id); }
	SYS_KSEM_POST                = 401 // { int ksem_post(semid_t id); }
	SYS_KSEM_WAIT                = 402 // { int ksem_wait(semid_t id); }
	SYS_KSEM_TRYWAIT             = 403 // { int ksem_trywait(semid_t id); }
	SYS_KSEM_INIT                = 404 // { int ksem_init(semid_t *idp, unsigned int value); }
	SYS_KSEM_OPEN                = 405 // { int ksem_open(semid_t *idp, const char *name, int oflag, mode_t mode, unsigned int value); }
	SYS_KSEM_UNLINK              = 406 // { int ksem_unlink(const char *name); }
	SYS_KSEM_GETVALUE            = 407 // { int ksem_getvalue(semid_t id, int *val); }
	SYS_KSEM_DESTROY             = 408 // { int ksem_destroy(semid_t id); }
	SYS___MAC_GET_PID            = 409 // { int __mac_get_pid(pid_t pid, struct mac *mac_p); }
	SYS___MAC_GET_LINK           = 410 // { int __mac_get_link(const char *path_p, struct mac *mac_p); }
	SYS___MAC_SET_LINK           = 411 // { int __mac_set_link(const char *path_p, struct mac *mac_p); }
	SYS_EXTATTR_SET_LINK         = 412 // { ssize_t extattr_set_link( const char *path, int attrnamespace, const char *attrname, void *data, size_t nbytes); }
	SYS_EXTATTR_GET_LINK         = 413 // { ssize_t extattr_get_link( const char *path, int attrnamespace, const char *attrname, void *data, size_t nbytes); }
	SYS_EXTATTR_DELETE_LINK      = 414 // { int extattr_delete_link( const char *path, int attrnamespace, const char *attrname); }
	SYS___MAC_EXECVE             = 415 // { int __mac_execve(char *fname, char **argv, char **envv, struct mac *mac_p); }
	SYS_SIGACTION                = 416 // { int sigaction(int sig, const struct sigaction *act, struct sigaction *oact); }
	SYS_SIGRETURN                = 417 // { int sigreturn( const struct __ucontext *sigcntxp); }
	SYS_GETCONTEXT               = 421 // { int getcontext(struct __ucontext *ucp); }
	SYS_SETCONTEXT               = 422 // { int setcontext( const struct __ucontext *ucp); }
	SYS_SWAPCONTEXT              = 423 // { int swapcontext(struct __ucontext *oucp, const struct __ucontext *ucp); }
	SYS_SWAPOFF                  = 424 // { int swapoff(const char *name); }
	SYS___ACL_GET_LINK           = 425 // { int __acl_get_link(const char *path, acl_type_t type, struct acl *aclp); }
	SYS___ACL_SET_LINK           = 426 // { int __acl_set_link(const char *path, acl_type_t type, struct acl *aclp); }
	SYS___ACL_DELETE_LINK        = 427 // { int __acl_delete_link(const char *path, acl_type_t type); }
	SYS___ACL_ACLCHECK_LINK      = 428 // { int __acl_aclcheck_link(const char *path, acl_type_t type, struct acl *aclp); }
	SYS_SIGWAIT                  = 429 // { int sigwait(const sigset_t *set, int *sig); }
	SYS_THR_CREATE               = 430 // { int thr_create(ucontext_t *ctx, long *id, int flags); }
	SYS_THR_EXIT                 = 431 // { void thr_exit(long *state); }
	SYS_THR_SELF                 = 432 // { int thr_self(long *id); }
	SYS_THR_KILL                 = 433 // { int thr_kill(long id, int sig); }
	SYS_JAIL_ATTACH              = 436 // { int jail_attach(int jid); }
	SYS_EXTATTR_LIST_FD          = 437 // { ssize_t extattr_list_fd(int fd, int attrnamespace, void *data, size_t nbytes); }
	SYS_EXTATTR_LIST_FILE        = 438 // { ssize_t extattr_list_file( const char *path, int attrnamespace, void *data, size_t nbytes); }
	SYS_EXTATTR_LIST_LINK        = 439 // { ssize_t extattr_list_link( const char *path, int attrnamespace, void *data, size_t nbytes); }
	SYS_KSEM_TIMEDWAIT           = 441 // { int ksem_timedwait(semid_t id, const struct timespec *abstime); }
	SYS_THR_SUSPEND              = 442 // { int thr_suspend( const struct timespec *timeout); }
	SYS_THR_WAKE                 = 443 // { int thr_wake(long id); }
	SYS_KLDUNLOADF               = 444 // { int kldunloadf(int fileid, int flags); }
	SYS_AUDIT                    = 445 // { int audit(const void *record, u_int length); }
	SYS_AUDITON                  = 446 // { int auditon(int cmd, void *data, u_int length); }
	SYS_GETAUID                  = 447 // { int getauid(uid_t *auid); }
	SYS_SETAUID                  = 448 // { int setauid(uid_t *auid); }
	SYS_GETAUDIT                 = 449 // { int getaudit(struct auditinfo *auditinfo); }
	SYS_SETAUDIT                 = 450 // { int setaudit(struct auditinfo *auditinfo); }
	SYS_GETAUDIT_ADDR            = 451 // { int getaudit_addr( struct auditinfo_addr *auditinfo_addr, u_int length); }
	SYS_SETAUDIT_ADDR            = 452 // { int setaudit_addr( struct auditinfo_addr *auditinfo_addr, u_int length); }
	SYS_AUDITCTL                 = 453 // { int auditctl(char *path); }
	SYS__UMTX_OP                 = 454 // { int _umtx_op(void *obj, int op, u_long val, void *uaddr1, void *uaddr2); }
	SYS_THR_NEW                  = 455 // { int thr_new(struct thr_param *param, int param_size); }
	SYS_SIGQUEUE                 = 456 // { int sigqueue(pid_t pid, int signum, void *value); }
	SYS_KMQ_OPEN                 = 457 // { int kmq_open(const char *path, int flags, mode_t mode, const struct mq_attr *attr); }
	SYS_KMQ_SETATTR              = 458 // { int kmq_setattr(int mqd,		const struct mq_attr *attr,		struct mq_attr *oattr); }
	SYS_KMQ_TIMEDRECEIVE         = 459 // { int kmq_timedreceive(int mqd,	char *msg_ptr, size_t msg_len,	unsigned *msg_prio,			const struct timespec *abs_timeout); }
	SYS_KMQ_TIMEDSEND            = 460 // { int kmq_timedsend(int mqd,		const char *msg_ptr, size_t msg_len,unsigned msg_prio,			const struct timespec *abs_timeout);}
	SYS_KMQ_NOTIFY               = 461 // { int kmq_notify(int mqd,		const struct sigevent *sigev); }
	SYS_KMQ_UNLINK               = 462 // { int kmq_unlink(const char *path); }
	SYS_ABORT2                   = 463 // { int abort2(const char *why, int nargs, void **args); }
	SYS_THR_SET_NAME             = 464 // { int thr_set_name(long id, const char *name); }
	SYS_AIO_FSYNC                = 465 // { int aio_fsync(int op, struct aiocb *aiocbp); }
	SYS_RTPRIO_THREAD            = 466 // { int rtprio_thread(int function, lwpid_t lwpid, struct rtprio *rtp); }
	SYS_SCTP_PEELOFF             = 471 // { int sctp_peeloff(int sd, uint32_t name); }
	SYS_SCTP_GENERIC_SENDMSG     = 472 // { int sctp_generic_sendmsg(int sd, caddr_t msg, int mlen, caddr_t to, __socklen_t tolen, struct sctp_sndrcvinfo *sinfo, int flags); }
	SYS_SCTP_GENERIC_SENDMSG_IOV = 473 // { int sctp_generic_sendmsg_iov(int sd, struct iovec *iov, int iovlen, caddr_t to, __socklen_t tolen, struct sctp_sndrcvinfo *sinfo, int flags); }
	SYS_SCTP_GENERIC_RECVMSG     = 474 // { int sctp_generic_recvmsg(int sd, struct iovec *iov, int iovlen, struct sockaddr * from, __socklen_t *fromlenaddr, struct sctp_sndrcvinfo *sinfo, int *msg_flags); }
	SYS_PREAD                    = 475 // { ssize_t pread(int fd, void *buf, size_t nbyte, off_t offset); }
	SYS_PWRITE                   = 476 // { ssize_t pwrite(int fd, const void *buf, size_t nbyte, off_t offset); }
	SYS_MMAP                     = 477 // { caddr_t mmap(caddr_t addr, size_t len, int prot, int flags, int fd, off_t pos); }
	SYS_LSEEK                    = 478 // { off_t lseek(int fd, off_t offset, int whence); }
	SYS_TRUNCATE                 = 479 // { int truncate(char *path, off_t length); }
	SYS_FTRUNCATE                = 480 // { int ftruncate(int fd, off_t length); }
	SYS_THR_KILL2                = 481 // { int thr_kill2(pid_t pid, long id, int sig); }
	SYS_SHM_OPEN                 = 482 // { int shm_open(const char *path, int flags, mode_t mode); }
	SYS_SHM_UNLINK               = 483 // { int shm_unlink(const char *path); }
	SYS_CPUSET                   = 484 // { int cpuset(cpusetid_t *setid); }
	SYS_CPUSET_SETID             = 485 // { int cpuset_setid(cpuwhich_t which, id_t id, cpusetid_t setid); }
	SYS_CPUSET_GETID             = 486 // { int cpuset_getid(cpulevel_t level, cpuwhich_t which, id_t id, cpusetid_t *setid); }
	SYS_CPUSET_GETAFFINITY       = 487 // { int cpuset_getaffinity(cpulevel_t level, cpuwhich_t which, id_t id, size_t cpusetsize, cpuset_t *mask); }
	SYS_CPUSET_SETAFFINITY       = 488 // { int cpuset_setaffinity(cpulevel_t level, cpuwhich_t which, id_t id, size_t cpusetsize, const cpuset_t *mask); }
	SYS_FACCESSAT                = 489 // { int faccessat(int fd, char *path, int amode, int flag); }
	SYS_FCHMODAT                 = 490 // { int fchmodat(int fd, char *path, mode_t mode, int flag); }
	SYS_FCHOWNAT                 = 491 // { int fchownat(int fd, char *path, uid_t uid, gid_t gid, int flag); }
	SYS_FEXECVE                  = 492 // { int fexecve(int fd, char **argv, char **envv); }
	SYS_FUTIMESAT                = 494 // { int futimesat(int fd, char *path, struct timeval *times); }
	SYS_LINKAT                   = 495 // { int linkat(int fd1, char *path1, int fd2, char *path2, int flag); }
	SYS_MKDIRAT                  = 496 // { int mkdirat(int fd, char *path, mode_t mode); }
	SYS_MKFIFOAT                 = 497 // { int mkfifoat(int fd, char *path, mode_t mode); }
	SYS_OPENAT                   = 499 // { int openat(int fd, char *path, int flag, mode_t mode); }
	SYS_READLINKAT               = 500 // { int readlinkat(int fd, char *path, char *buf, size_t bufsize); }
	SYS_RENAMEAT                 = 501 // { int renameat(int oldfd, char *old, int newfd, char *new); }
	SYS_SYMLINKAT                = 502 // { int symlinkat(char *path1, int fd, char *path2); }
	SYS_UNLINKAT                 = 503 // { int unlinkat(int fd, char *path, int flag); }
	SYS_POSIX_OPENPT             = 504 // { int posix_openpt(int flags); }
	SYS_GSSD_SYSCALL             = 505 // { int gssd_syscall(char *path); }
	SYS_JAIL_GET                 = 506 // { int jail_get(struct iovec *iovp, unsigned int iovcnt, int flags); }
	SYS_JAIL_SET                 = 507 // { int jail_set(struct iovec *iovp, unsigned int iovcnt, int flags); }
	SYS_JAIL_REMOVE              = 508 // { int jail_remove(int jid); }
	SYS_CLOSEFROM                = 509 // { int closefrom(int lowfd); }
	SYS___SEMCTL                 = 510 // { int __semctl(int semid, int semnum, int cmd, union semun *arg); }
	SYS_MSGCTL                   = 511 // { int msgctl(int msqid, int cmd, struct msqid_ds *buf); }
	SYS_SHMCTL                   = 512 // { int shmctl(int shmid, int cmd, struct shmid_ds *buf); }
	SYS_LPATHCONF                = 513 // { int lpathconf(char *path, int name); }
	SYS___CAP_RIGHTS_GET         = 515 // { int __cap_rights_get(int version, int fd, cap_rights_t *rightsp); }
	SYS_CAP_ENTER                = 516 // { int cap_enter(void); }
	SYS_CAP_GETMODE              = 517 // { int cap_getmode(u_int *modep); }
	SYS_PDFORK                   = 518 // { int pdfork(int *fdp, int flags); }
	SYS_PDKILL                   = 519 // { int 
"""




```