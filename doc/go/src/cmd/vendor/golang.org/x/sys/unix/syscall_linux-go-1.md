Response:
The user wants a summary of the functionality provided by the Go code snippet. This is the second part of a two-part file. I need to go through each system call wrapper and helper function to understand its purpose. I should also identify any higher-level Go functionalities these wrappers might be implementing.

**Plan:**

1. List all the system calls being wrapped.
2. Group related system calls together.
3. Identify helper functions and their roles.
4. Look for patterns or high-level functionalities being implemented.
5. Summarize the functionalities in a concise manner.
这段Go语言代码片段是 `go/src/cmd/vendor/golang.org/x/sys/unix/syscall_linux.go` 文件的一部分，它主要提供了对 Linux 系统调用的封装，以便 Go 语言程序能够调用底层的操作系统功能。  由于这是第二部分，我将结合上下文（虽然我没有第一部分的内容）来推断其功能。

**归纳其功能：**

总体来说，这段代码片段的主要功能是：

1. **提供对多种 Linux 系统调用的 Go 语言封装。**  这些封装函数以 `//sys` 开头，将底层的 C 风格系统调用转换为更符合 Go 语言习惯的函数调用方式，并处理了错误返回。

2. **提供更高级别的、类型安全的接口。**  例如，对于 `readv` 和 `writev` 系列的系统调用，代码中提供了 `Readv`、`Preadv`、`Preadv2`、`Writev`、`Pwritev` 和 `Pwritev2` 这些函数，它们接收 Go 的 `[]byte` 切片作为输入，并处理了底层的 `Iovec` 结构体的转换。

3. **处理与 I/O 向量操作相关的细节。**  例如，`appendBytes` 函数用于将 `[][]byte` 转换为 `[]Iovec`， `offs2lohi` 函数用于将 64 位偏移量分解为高低位，这都是为了适配 `preadv` 和 `pwritev` 等系统调用的参数格式。

4. **集成了竞态检测机制。**  `readvRacedetect` 和 `writevRacedetect` 函数在启用了竞态检测 (`raceenabled`) 的情况下，会调用 `raceWriteRange` 和 `raceReadRange` 来标记内存访问，帮助开发者发现潜在的并发问题。

5. **提供了内存映射相关的系统调用封装。**  例如 `munmap`、`mremap`、`Madvise`、`Mprotect` 等。

6. **提供了操作文件句柄的系统调用封装。**  例如 `NameToHandleAt` 和 `OpenByHandleAt`，允许通过文件句柄来访问文件，这在某些场景下比通过路径更高效和安全。

7. **提供了进程间通信和控制相关的系统调用封装。** 例如 `ProcessVMReadv`、`ProcessVMWritev`、`PidfdOpen`、`PidfdGetfd`、`PidfdSendSignal` 以及 System V 共享内存相关的调用 (`shmat`, `shmctl`, `shmdt`, `shmget`)。

8. **提供了定时器相关的系统调用封装。** 例如 `getitimer` 和 `setitimer`，并提供了 `MakeItimerval` 辅助函数。

9. **提供了信号处理相关的系统调用封装。** 例如 `rtSigprocmask` (通过 `PthreadSigmask` 封装)。

10. **提供了获取用户和组 ID 相关的系统调用封装。** 例如 `getresuid` 和 `getresgid`。

11. **提供了文件访问控制相关的系统调用封装。** 例如 `faccessat` 和 `Faccessat2`，并且针对 `faccessat` 提供了更符合 POSIX 语义的实现。

12. **提供了 `pselect` 系统调用的封装。**  并处理了 Linux 系统调用会修改 `timeout` 参数的问题。

13. **提供了调度策略相关的系统调用封装。** 例如 `schedSetattr` 和 `schedGetattr`。

14. **提供了缓存状态 (`Cachestat`) 和内存密封 (`Mseal`) 相关的系统调用封装。**

**Go 语言功能的实现举例：**

这段代码是 `golang.org/x/sys/unix` 包的一部分，它为 Go 语言提供了访问底层操作系统功能的基础。  很多 Go 标准库中的功能都依赖于这个包提供的系统调用封装。

**例子 1：文件读取（基于 `readv`）**

```go
package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func main() {
	f, err := os.Open("test.txt")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer f.Close()

	fd := int(f.Fd())
	buf1 := make([]byte, 5)
	buf2 := make([]byte, 3)
	iovs := [][]byte{buf1, buf2}

	n, err := unix.Readv(fd, iovs)
	if err != nil {
		fmt.Println("Error reading with Readv:", err)
		return
	}

	fmt.Printf("Read %d bytes\n", n)
	fmt.Printf("Buffer 1: %s\n", string(buf1))
	fmt.Printf("Buffer 2: %s\n", string(buf2))
}
```

**假设输入 `test.txt` 文件内容为 "Hello World!"**

**输出：**

```
Read 8 bytes
Buffer 1: Hello
Buffer 2:  Wo
```

**例子 2：设置进程调度策略（基于 `schedSetattr`）**

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func main() {
	pid := 0 // 当前进程
	attr := &unix.SchedAttr{
		SchedPolicy: unix.SCHED_FIFO,
		SchedPriority: 50,
	}

	err := unix.SchedSetAttr(pid, attr, 0)
	if err != nil {
		fmt.Println("Error setting scheduling attributes:", err)
		return
	}

	fmt.Println("Successfully set scheduling attributes.")
}
```

这个例子假设你以 root 权限运行，因为修改调度策略通常需要特权。  这个例子没有具体的输入输出，因为它直接修改了进程的调度策略。

**命令行参数的具体处理：**

这段代码本身主要是对系统调用的封装，并不直接处理命令行参数。命令行参数的处理通常发生在更上层的应用程序代码中。不过，一些系统调用可能会影响程序的行为，而这些行为可能由命令行参数控制。例如，如果一个程序接受一个文件路径作为命令行参数，并使用 `os.Open` 打开该文件，那么底层最终会调用到 `open` 系统调用（在 `syscall_linux.go` 的第一部分可能存在），而这段代码提供了 `readv` 等相关的读取操作。

**使用者易犯错的点：**

1. **不正确的参数类型或大小。** 例如，在使用 `Iovec` 结构体时，需要确保 `Base` 指针指向有效的内存，并且 `Len` 字段设置正确。直接使用 `unsafe` 包进行指针操作容易出错。

2. **权限问题。** 许多系统调用需要特定的权限才能执行成功，例如修改进程调度策略或进行某些文件操作。如果程序没有足够的权限，系统调用会返回错误。

3. **错误处理不当。** 系统调用可能会返回错误，必须检查错误并进行适当的处理，否则可能导致程序崩溃或行为异常。

4. **竞态条件。**  在使用 `readv` 和 `writev` 等进行并发 I/O 操作时，如果没有适当的同步机制，可能会出现竞态条件，导致数据不一致。这段代码虽然集成了竞态检测，但并不能阻止竞态条件的发生，只能帮助开发者发现。

总而言之，这段代码是 Go 语言与 Linux 内核交互的重要桥梁，它通过封装系统调用，使得 Go 程序员可以方便地利用操作系统提供的强大功能。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/syscall_linux.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
igmask, _C__NSIG/8, flags)
}

//sys	Setpriority(which int, who int, prio int) (err error)
//sys	Setxattr(path string, attr string, data []byte, flags int) (err error)
//sys	signalfd(fd int, sigmask *Sigset_t, maskSize uintptr, flags int) (newfd int, err error) = SYS_SIGNALFD4
//sys	Statx(dirfd int, path string, flags int, mask int, stat *Statx_t) (err error)
//sys	Sync()
//sys	Syncfs(fd int) (err error)
//sysnb	Sysinfo(info *Sysinfo_t) (err error)
//sys	Tee(rfd int, wfd int, len int, flags int) (n int64, err error)
//sysnb	TimerfdCreate(clockid int, flags int) (fd int, err error)
//sysnb	TimerfdGettime(fd int, currValue *ItimerSpec) (err error)
//sysnb	TimerfdSettime(fd int, flags int, newValue *ItimerSpec, oldValue *ItimerSpec) (err error)
//sysnb	Tgkill(tgid int, tid int, sig syscall.Signal) (err error)
//sysnb	Times(tms *Tms) (ticks uintptr, err error)
//sysnb	Umask(mask int) (oldmask int)
//sysnb	Uname(buf *Utsname) (err error)
//sys	Unmount(target string, flags int) (err error) = SYS_UMOUNT2
//sys	Unshare(flags int) (err error)
//sys	write(fd int, p []byte) (n int, err error)
//sys	exitThread(code int) (err error) = SYS_EXIT
//sys	readv(fd int, iovs []Iovec) (n int, err error) = SYS_READV
//sys	writev(fd int, iovs []Iovec) (n int, err error) = SYS_WRITEV
//sys	preadv(fd int, iovs []Iovec, offs_l uintptr, offs_h uintptr) (n int, err error) = SYS_PREADV
//sys	pwritev(fd int, iovs []Iovec, offs_l uintptr, offs_h uintptr) (n int, err error) = SYS_PWRITEV
//sys	preadv2(fd int, iovs []Iovec, offs_l uintptr, offs_h uintptr, flags int) (n int, err error) = SYS_PREADV2
//sys	pwritev2(fd int, iovs []Iovec, offs_l uintptr, offs_h uintptr, flags int) (n int, err error) = SYS_PWRITEV2

// minIovec is the size of the small initial allocation used by
// Readv, Writev, etc.
//
// This small allocation gets stack allocated, which lets the
// common use case of len(iovs) <= minIovs avoid more expensive
// heap allocations.
const minIovec = 8

// appendBytes converts bs to Iovecs and appends them to vecs.
func appendBytes(vecs []Iovec, bs [][]byte) []Iovec {
	for _, b := range bs {
		var v Iovec
		v.SetLen(len(b))
		if len(b) > 0 {
			v.Base = &b[0]
		} else {
			v.Base = (*byte)(unsafe.Pointer(&_zero))
		}
		vecs = append(vecs, v)
	}
	return vecs
}

// offs2lohi splits offs into its low and high order bits.
func offs2lohi(offs int64) (lo, hi uintptr) {
	const longBits = SizeofLong * 8
	return uintptr(offs), uintptr(uint64(offs) >> (longBits - 1) >> 1) // two shifts to avoid false positive in vet
}

func Readv(fd int, iovs [][]byte) (n int, err error) {
	iovecs := make([]Iovec, 0, minIovec)
	iovecs = appendBytes(iovecs, iovs)
	n, err = readv(fd, iovecs)
	readvRacedetect(iovecs, n, err)
	return n, err
}

func Preadv(fd int, iovs [][]byte, offset int64) (n int, err error) {
	iovecs := make([]Iovec, 0, minIovec)
	iovecs = appendBytes(iovecs, iovs)
	lo, hi := offs2lohi(offset)
	n, err = preadv(fd, iovecs, lo, hi)
	readvRacedetect(iovecs, n, err)
	return n, err
}

func Preadv2(fd int, iovs [][]byte, offset int64, flags int) (n int, err error) {
	iovecs := make([]Iovec, 0, minIovec)
	iovecs = appendBytes(iovecs, iovs)
	lo, hi := offs2lohi(offset)
	n, err = preadv2(fd, iovecs, lo, hi, flags)
	readvRacedetect(iovecs, n, err)
	return n, err
}

func readvRacedetect(iovecs []Iovec, n int, err error) {
	if !raceenabled {
		return
	}
	for i := 0; n > 0 && i < len(iovecs); i++ {
		m := int(iovecs[i].Len)
		if m > n {
			m = n
		}
		n -= m
		if m > 0 {
			raceWriteRange(unsafe.Pointer(iovecs[i].Base), m)
		}
	}
	if err == nil {
		raceAcquire(unsafe.Pointer(&ioSync))
	}
}

func Writev(fd int, iovs [][]byte) (n int, err error) {
	iovecs := make([]Iovec, 0, minIovec)
	iovecs = appendBytes(iovecs, iovs)
	if raceenabled {
		raceReleaseMerge(unsafe.Pointer(&ioSync))
	}
	n, err = writev(fd, iovecs)
	writevRacedetect(iovecs, n)
	return n, err
}

func Pwritev(fd int, iovs [][]byte, offset int64) (n int, err error) {
	iovecs := make([]Iovec, 0, minIovec)
	iovecs = appendBytes(iovecs, iovs)
	if raceenabled {
		raceReleaseMerge(unsafe.Pointer(&ioSync))
	}
	lo, hi := offs2lohi(offset)
	n, err = pwritev(fd, iovecs, lo, hi)
	writevRacedetect(iovecs, n)
	return n, err
}

func Pwritev2(fd int, iovs [][]byte, offset int64, flags int) (n int, err error) {
	iovecs := make([]Iovec, 0, minIovec)
	iovecs = appendBytes(iovecs, iovs)
	if raceenabled {
		raceReleaseMerge(unsafe.Pointer(&ioSync))
	}
	lo, hi := offs2lohi(offset)
	n, err = pwritev2(fd, iovecs, lo, hi, flags)
	writevRacedetect(iovecs, n)
	return n, err
}

func writevRacedetect(iovecs []Iovec, n int) {
	if !raceenabled {
		return
	}
	for i := 0; n > 0 && i < len(iovecs); i++ {
		m := int(iovecs[i].Len)
		if m > n {
			m = n
		}
		n -= m
		if m > 0 {
			raceReadRange(unsafe.Pointer(iovecs[i].Base), m)
		}
	}
}

// mmap varies by architecture; see syscall_linux_*.go.
//sys	munmap(addr uintptr, length uintptr) (err error)
//sys	mremap(oldaddr uintptr, oldlength uintptr, newlength uintptr, flags int, newaddr uintptr) (xaddr uintptr, err error)
//sys	Madvise(b []byte, advice int) (err error)
//sys	Mprotect(b []byte, prot int) (err error)
//sys	Mlock(b []byte) (err error)
//sys	Mlockall(flags int) (err error)
//sys	Msync(b []byte, flags int) (err error)
//sys	Munlock(b []byte) (err error)
//sys	Munlockall() (err error)

const (
	mremapFixed     = MREMAP_FIXED
	mremapDontunmap = MREMAP_DONTUNMAP
	mremapMaymove   = MREMAP_MAYMOVE
)

// Vmsplice splices user pages from a slice of Iovecs into a pipe specified by fd,
// using the specified flags.
func Vmsplice(fd int, iovs []Iovec, flags int) (int, error) {
	var p unsafe.Pointer
	if len(iovs) > 0 {
		p = unsafe.Pointer(&iovs[0])
	}

	n, _, errno := Syscall6(SYS_VMSPLICE, uintptr(fd), uintptr(p), uintptr(len(iovs)), uintptr(flags), 0, 0)
	if errno != 0 {
		return 0, syscall.Errno(errno)
	}

	return int(n), nil
}

func isGroupMember(gid int) bool {
	groups, err := Getgroups()
	if err != nil {
		return false
	}

	for _, g := range groups {
		if g == gid {
			return true
		}
	}
	return false
}

func isCapDacOverrideSet() bool {
	hdr := CapUserHeader{Version: LINUX_CAPABILITY_VERSION_3}
	data := [2]CapUserData{}
	err := Capget(&hdr, &data[0])

	return err == nil && data[0].Effective&(1<<CAP_DAC_OVERRIDE) != 0
}

//sys	faccessat(dirfd int, path string, mode uint32) (err error)
//sys	Faccessat2(dirfd int, path string, mode uint32, flags int) (err error)

func Faccessat(dirfd int, path string, mode uint32, flags int) (err error) {
	if flags == 0 {
		return faccessat(dirfd, path, mode)
	}

	if err := Faccessat2(dirfd, path, mode, flags); err != ENOSYS && err != EPERM {
		return err
	}

	// The Linux kernel faccessat system call does not take any flags.
	// The glibc faccessat implements the flags itself; see
	// https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/unix/sysv/linux/faccessat.c;hb=HEAD
	// Because people naturally expect syscall.Faccessat to act
	// like C faccessat, we do the same.

	if flags & ^(AT_SYMLINK_NOFOLLOW|AT_EACCESS) != 0 {
		return EINVAL
	}

	var st Stat_t
	if err := Fstatat(dirfd, path, &st, flags&AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}

	mode &= 7
	if mode == 0 {
		return nil
	}

	var uid int
	if flags&AT_EACCESS != 0 {
		uid = Geteuid()
		if uid != 0 && isCapDacOverrideSet() {
			// If CAP_DAC_OVERRIDE is set, file access check is
			// done by the kernel in the same way as for root
			// (see generic_permission() in the Linux sources).
			uid = 0
		}
	} else {
		uid = Getuid()
	}

	if uid == 0 {
		if mode&1 == 0 {
			// Root can read and write any file.
			return nil
		}
		if st.Mode&0111 != 0 {
			// Root can execute any file that anybody can execute.
			return nil
		}
		return EACCES
	}

	var fmode uint32
	if uint32(uid) == st.Uid {
		fmode = (st.Mode >> 6) & 7
	} else {
		var gid int
		if flags&AT_EACCESS != 0 {
			gid = Getegid()
		} else {
			gid = Getgid()
		}

		if uint32(gid) == st.Gid || isGroupMember(int(st.Gid)) {
			fmode = (st.Mode >> 3) & 7
		} else {
			fmode = st.Mode & 7
		}
	}

	if fmode&mode == mode {
		return nil
	}

	return EACCES
}

//sys	nameToHandleAt(dirFD int, pathname string, fh *fileHandle, mountID *_C_int, flags int) (err error) = SYS_NAME_TO_HANDLE_AT
//sys	openByHandleAt(mountFD int, fh *fileHandle, flags int) (fd int, err error) = SYS_OPEN_BY_HANDLE_AT

// fileHandle is the argument to nameToHandleAt and openByHandleAt. We
// originally tried to generate it via unix/linux/types.go with "type
// fileHandle C.struct_file_handle" but that generated empty structs
// for mips64 and mips64le. Instead, hard code it for now (it's the
// same everywhere else) until the mips64 generator issue is fixed.
type fileHandle struct {
	Bytes uint32
	Type  int32
}

// FileHandle represents the C struct file_handle used by
// name_to_handle_at (see NameToHandleAt) and open_by_handle_at (see
// OpenByHandleAt).
type FileHandle struct {
	*fileHandle
}

// NewFileHandle constructs a FileHandle.
func NewFileHandle(handleType int32, handle []byte) FileHandle {
	const hdrSize = unsafe.Sizeof(fileHandle{})
	buf := make([]byte, hdrSize+uintptr(len(handle)))
	copy(buf[hdrSize:], handle)
	fh := (*fileHandle)(unsafe.Pointer(&buf[0]))
	fh.Type = handleType
	fh.Bytes = uint32(len(handle))
	return FileHandle{fh}
}

func (fh *FileHandle) Size() int   { return int(fh.fileHandle.Bytes) }
func (fh *FileHandle) Type() int32 { return fh.fileHandle.Type }
func (fh *FileHandle) Bytes() []byte {
	n := fh.Size()
	if n == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(&fh.fileHandle.Type))+4)), n)
}

// NameToHandleAt wraps the name_to_handle_at system call; it obtains
// a handle for a path name.
func NameToHandleAt(dirfd int, path string, flags int) (handle FileHandle, mountID int, err error) {
	var mid _C_int
	// Try first with a small buffer, assuming the handle will
	// only be 32 bytes.
	size := uint32(32 + unsafe.Sizeof(fileHandle{}))
	didResize := false
	for {
		buf := make([]byte, size)
		fh := (*fileHandle)(unsafe.Pointer(&buf[0]))
		fh.Bytes = size - uint32(unsafe.Sizeof(fileHandle{}))
		err = nameToHandleAt(dirfd, path, fh, &mid, flags)
		if err == EOVERFLOW {
			if didResize {
				// We shouldn't need to resize more than once
				return
			}
			didResize = true
			size = fh.Bytes + uint32(unsafe.Sizeof(fileHandle{}))
			continue
		}
		if err != nil {
			return
		}
		return FileHandle{fh}, int(mid), nil
	}
}

// OpenByHandleAt wraps the open_by_handle_at system call; it opens a
// file via a handle as previously returned by NameToHandleAt.
func OpenByHandleAt(mountFD int, handle FileHandle, flags int) (fd int, err error) {
	return openByHandleAt(mountFD, handle.fileHandle, flags)
}

// Klogset wraps the sys_syslog system call; it sets console_loglevel to
// the value specified by arg and passes a dummy pointer to bufp.
func Klogset(typ int, arg int) (err error) {
	var p unsafe.Pointer
	_, _, errno := Syscall(SYS_SYSLOG, uintptr(typ), uintptr(p), uintptr(arg))
	if errno != 0 {
		return errnoErr(errno)
	}
	return nil
}

// RemoteIovec is Iovec with the pointer replaced with an integer.
// It is used for ProcessVMReadv and ProcessVMWritev, where the pointer
// refers to a location in a different process' address space, which
// would confuse the Go garbage collector.
type RemoteIovec struct {
	Base uintptr
	Len  int
}

//sys	ProcessVMReadv(pid int, localIov []Iovec, remoteIov []RemoteIovec, flags uint) (n int, err error) = SYS_PROCESS_VM_READV
//sys	ProcessVMWritev(pid int, localIov []Iovec, remoteIov []RemoteIovec, flags uint) (n int, err error) = SYS_PROCESS_VM_WRITEV

//sys	PidfdOpen(pid int, flags int) (fd int, err error) = SYS_PIDFD_OPEN
//sys	PidfdGetfd(pidfd int, targetfd int, flags int) (fd int, err error) = SYS_PIDFD_GETFD
//sys	PidfdSendSignal(pidfd int, sig Signal, info *Siginfo, flags int) (err error) = SYS_PIDFD_SEND_SIGNAL

//sys	shmat(id int, addr uintptr, flag int) (ret uintptr, err error)
//sys	shmctl(id int, cmd int, buf *SysvShmDesc) (result int, err error)
//sys	shmdt(addr uintptr) (err error)
//sys	shmget(key int, size int, flag int) (id int, err error)

//sys	getitimer(which int, currValue *Itimerval) (err error)
//sys	setitimer(which int, newValue *Itimerval, oldValue *Itimerval) (err error)

// MakeItimerval creates an Itimerval from interval and value durations.
func MakeItimerval(interval, value time.Duration) Itimerval {
	return Itimerval{
		Interval: NsecToTimeval(interval.Nanoseconds()),
		Value:    NsecToTimeval(value.Nanoseconds()),
	}
}

// A value which may be passed to the which parameter for Getitimer and
// Setitimer.
type ItimerWhich int

// Possible which values for Getitimer and Setitimer.
const (
	ItimerReal    ItimerWhich = ITIMER_REAL
	ItimerVirtual ItimerWhich = ITIMER_VIRTUAL
	ItimerProf    ItimerWhich = ITIMER_PROF
)

// Getitimer wraps getitimer(2) to return the current value of the timer
// specified by which.
func Getitimer(which ItimerWhich) (Itimerval, error) {
	var it Itimerval
	if err := getitimer(int(which), &it); err != nil {
		return Itimerval{}, err
	}

	return it, nil
}

// Setitimer wraps setitimer(2) to arm or disarm the timer specified by which.
// It returns the previous value of the timer.
//
// If the Itimerval argument is the zero value, the timer will be disarmed.
func Setitimer(which ItimerWhich, it Itimerval) (Itimerval, error) {
	var prev Itimerval
	if err := setitimer(int(which), &it, &prev); err != nil {
		return Itimerval{}, err
	}

	return prev, nil
}

//sysnb	rtSigprocmask(how int, set *Sigset_t, oldset *Sigset_t, sigsetsize uintptr) (err error) = SYS_RT_SIGPROCMASK

func PthreadSigmask(how int, set, oldset *Sigset_t) error {
	if oldset != nil {
		// Explicitly clear in case Sigset_t is larger than _C__NSIG.
		*oldset = Sigset_t{}
	}
	return rtSigprocmask(how, set, oldset, _C__NSIG/8)
}

//sysnb	getresuid(ruid *_C_int, euid *_C_int, suid *_C_int)
//sysnb	getresgid(rgid *_C_int, egid *_C_int, sgid *_C_int)

func Getresuid() (ruid, euid, suid int) {
	var r, e, s _C_int
	getresuid(&r, &e, &s)
	return int(r), int(e), int(s)
}

func Getresgid() (rgid, egid, sgid int) {
	var r, e, s _C_int
	getresgid(&r, &e, &s)
	return int(r), int(e), int(s)
}

// Pselect is a wrapper around the Linux pselect6 system call.
// This version does not modify the timeout argument.
func Pselect(nfd int, r *FdSet, w *FdSet, e *FdSet, timeout *Timespec, sigmask *Sigset_t) (n int, err error) {
	// Per https://man7.org/linux/man-pages/man2/select.2.html#NOTES,
	// The Linux pselect6() system call modifies its timeout argument.
	// [Not modifying the argument] is the behavior required by POSIX.1-2001.
	var mutableTimeout *Timespec
	if timeout != nil {
		mutableTimeout = new(Timespec)
		*mutableTimeout = *timeout
	}

	// The final argument of the pselect6() system call is not a
	// sigset_t * pointer, but is instead a structure
	var kernelMask *sigset_argpack
	if sigmask != nil {
		wordBits := 32 << (^uintptr(0) >> 63) // see math.intSize

		// A sigset stores one bit per signal,
		// offset by 1 (because signal 0 does not exist).
		// So the number of words needed is ⌈__C_NSIG - 1 / wordBits⌉.
		sigsetWords := (_C__NSIG - 1 + wordBits - 1) / (wordBits)

		sigsetBytes := uintptr(sigsetWords * (wordBits / 8))
		kernelMask = &sigset_argpack{
			ss:    sigmask,
			ssLen: sigsetBytes,
		}
	}

	return pselect6(nfd, r, w, e, mutableTimeout, kernelMask)
}

//sys	schedSetattr(pid int, attr *SchedAttr, flags uint) (err error)
//sys	schedGetattr(pid int, attr *SchedAttr, size uint, flags uint) (err error)

// SchedSetAttr is a wrapper for sched_setattr(2) syscall.
// https://man7.org/linux/man-pages/man2/sched_setattr.2.html
func SchedSetAttr(pid int, attr *SchedAttr, flags uint) error {
	if attr == nil {
		return EINVAL
	}
	attr.Size = SizeofSchedAttr
	return schedSetattr(pid, attr, flags)
}

// SchedGetAttr is a wrapper for sched_getattr(2) syscall.
// https://man7.org/linux/man-pages/man2/sched_getattr.2.html
func SchedGetAttr(pid int, flags uint) (*SchedAttr, error) {
	attr := &SchedAttr{}
	if err := schedGetattr(pid, attr, SizeofSchedAttr, flags); err != nil {
		return nil, err
	}
	return attr, nil
}

//sys	Cachestat(fd uint, crange *CachestatRange, cstat *Cachestat_t, flags uint) (err error)
//sys	Mseal(b []byte, flags uint) (err error)
```