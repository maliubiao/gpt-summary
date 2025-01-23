Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Context:** The first and most crucial step is to recognize the file path: `go/src/cmd/vendor/golang.org/x/sys/unix/syscall_darwin.go`. This immediately tells us several things:
    * It's part of the Go standard library's extended system call interface.
    * It's specific to the Darwin operating system (macOS, iOS, etc.).
    * It deals with low-level interactions with the kernel.
    * The `//sys` comments indicate that `mksyscall` is involved, which generates the actual system call wrappers. This means much of the underlying implementation isn't directly visible in this file.

2. **Identify Key Sections:**  Scan the file for distinct blocks of code or comments that suggest different functionalities. Look for:
    * `//sys` lines: These are the most important as they define the system calls being wrapped.
    * Function definitions with meaningful names (e.g., `fdopendir`, `Getdirentries`, `SockaddrDatalink`).
    * Struct definitions (e.g., `SockaddrDatalink`, `SockaddrCtl`, `SockaddrVM`).
    * Constants (e.g., `SYS___SYSCTL`).
    * Helper functions (e.g., `nametomib`, `direntIno`).
    * Comments explaining the purpose of code blocks.

3. **Analyze `//sys` Lines:**  These lines are the core of the system call interface. For each `//sys` line, try to understand:
    * The system call name (e.g., `closedir`, `readdir_r`).
    * The parameters and their types.
    * The return values and their types (especially `error` or `Errno`).
    * If there's a lowercase version, it likely has a higher-level Go wrapper.

4. **Examine Function Implementations:** For functions *not* directly marked with `//sys`, analyze their logic:
    * **`fdopendir`:** This is a simple wrapper around the underlying system call, but it uses `syscall_syscallPtr` suggesting it's dynamically linked. The `//go:cgo_import_dynamic` comment confirms this.
    * **`Getdirentries`:**  This function stands out as more complex. The comments clearly explain that it *simulates* the `Getdirentries` system call using `fdopendir`, `readdir_r`, and `closedir`. This is a key insight into its functionality. Pay close attention to the logic for handling the `skip` offset and the duplication of the file descriptor.
    * **`Sockaddr` Implementations:** The `SockaddrDatalink`, `SockaddrCtl`, and `SockaddrVM` structs and their `sockaddr()` methods are clearly related to network socket addresses of different families.
    * **`nametomib`:** The comments here are helpful in understanding how it translates a human-readable string like "kern.hostname" into a kernel MIB (Management Information Base) array. The use of `sysctl` internally is important.
    * **`PtraceAttach`, `PtraceDetach`, `PtraceDenyAttach`:** These are straightforward wrappers for the `ptrace` system call with different arguments.
    * **`Pipe`:**  This function wraps the `pipe` system call, converting the `int32` array to a Go `int` slice.
    * **`Getfsstat`:**  This function deals with getting file system statistics.
    * **`xattr` Functions (Getxattr, Setxattr, etc.):**  These functions manage extended attributes of files. Notice the helper function `xattrPointer` and the handling of the `options` parameter which differs from the Linux version.
    * **`Kill`:** A simple wrapper for the `kill` system call.
    * **`IoctlCtlInfo`, `IoctlGetIfreqMTU`, `IoctlSetIfreqMTU`:** These functions demonstrate the use of `ioctl` for specific network-related operations.
    * **`RenamexNp`, `RenameatxNp`:** These functions likely provide extended rename functionality.
    * **`Uname`:**  This function retrieves system information using `sysctl` with specific MIBs.
    * **`Sendfile`:**  This function implements zero-copy file transfer.
    * **`Getsockopt` and `Setsockopt` wrappers:** Several functions are provided to get and set socket options for different protocols (IPMreqn, Xucred, TCPConnectionInfo).
    * **`SysctlKinfoProc`, `SysctlKinfoProcSlice`:** These functions retrieve kernel information about processes using `sysctl`. The `SysctlKinfoProcSlice` function has error handling for `ENOMEM`, indicating it retries if the process table grows.
    * **`PthreadChdir`, `PthreadFchdir`:** These functions change the current working directory for the current thread.
    * **`Connectx`:** A more advanced connect function with more options.
    * **`shm` functions (shmat, shmctl, etc.):** These deal with shared memory.
    * **The final large block of `//sys` lines:** This section lists many standard Unix system calls that are directly exposed through this package.

5. **Infer Go Functionality:** Based on the system calls wrapped and the higher-level functions implemented, deduce the broader Go features being supported:
    * File system operations (reading directories, getting file stats, extended attributes, renaming).
    * Process management (signals, process information).
    * Networking (socket creation, connection, options, interface management).
    * Memory management (shared memory).
    * System information retrieval.

6. **Code Examples (Hypothetical Input/Output):**  Choose a few interesting functions and create illustrative examples. For `Getdirentries`, the "skipping" behavior is worth demonstrating. For `nametomib`, a simple hostname lookup is a good example. For socket-related functions, show basic usage. *Crucially, remember that these examples are operating system dependent.*

7. **Command-Line Arguments:**  Look for functions that might be influenced by command-line arguments. In this specific snippet, there isn't much direct command-line argument processing. However, functions like `Open` or `Chdir` will certainly operate based on file paths that could originate from command-line arguments.

8. **Common Mistakes:** Consider potential pitfalls for users:
    * **`Getdirentries` and `Seek`:** The interaction between `Getdirentries` and `Seek` on the same file descriptor is subtle and could lead to confusion.
    * **Extended Attributes:** The differences between macOS and Linux regarding extended attribute handling are a potential source of errors for cross-platform development.
    * **`sysctl`:**  Using the wrong MIB or incorrect buffer sizes with `sysctl` can cause issues.
    * **File Descriptors:**  Forgetting to close file descriptors opened by functions like `Openat` within `Getdirentries` would be a mistake.

9. **Structure and Refine:** Organize the findings logically, starting with a high-level overview and then diving into specifics for each functional area. Use clear and concise language. Provide code examples that are easy to understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This file just wraps system calls."  **Correction:** While it does wrap system calls, functions like `Getdirentries` provide a higher-level abstraction or simulation. Recognize these distinctions.
* **Misunderstanding:**  "The `//sys` lines are the complete implementation." **Correction:** Remember `mksyscall` generates the underlying stubs. This file provides the Go-level interface and sometimes additional logic.
* **Overlooking details:** "The `+2` in `nametomib` seems arbitrary." **Correction:** The comment explicitly mentions the kernel behavior, so it's an important detail to include.
* **Focusing too narrowly:** "Just describe each function individually." **Correction:** Group related functions by their functionality (file system, networking, etc.) to provide a better overview.

By following these steps and continually refining the analysis, a comprehensive understanding of the code snippet's functionality can be achieved.
这段代码是 Go 语言标准库 `syscall` 包在 Darwin (macOS, iOS 等) 平台上的实现部分。它定义并实现了一些与 Darwin 系统调用交互的函数。

**主要功能列举:**

1. **封装 Darwin 系统调用:**  文件中大量的 `//sys` 注释标记了需要由 `mksyscall` 工具处理的系统调用。这些注释指定了系统调用的名称、参数和返回值。例如：
   ```go
   //sys	closedir(dir uintptr) (err error)
   //sys	readdir_r(dir uintptr, entry *Dirent, result **Dirent) (res Errno)
   ```
   这意味着代码封装了 `closedir` 和 `readdir_r` 这两个 Darwin 系统调用。

2. **提供更友好的 Go 接口:**  有些系统调用直接封装，而有些则提供了更符合 Go 习惯的接口。例如，`Pipe` 函数是对 `pipe` 系统调用的封装，它将返回的 `int32` 数组转换为 Go 的 `int` slice。

3. **模拟系统调用:**  `Getdirentries` 函数就是一个例子。Darwin 系统并没有直接的 `getdirentries` 系统调用，这段代码使用 `fdopendir`, `readdir_r`, 和 `closedir` 来模拟其功能，以便与 Linux 等其他系统的行为保持一致。

4. **定义平台相关的结构体:**  例如 `SockaddrDatalink`, `SockaddrCtl`, `SockaddrVM` 等结构体定义了特定于 Darwin 平台的套接字地址结构。

5. **提供扩展属性 (Extended Attributes) 操作:**  `Getxattr`, `Setxattr`, `Removexattr`, `Listxattr` 等函数提供了访问和修改文件扩展属性的功能。

6. **提供 `sysctl` 接口:** `nametomib` 函数可以将类似 "kern.hostname" 的字符串转换为 `sysctl` 系统调用所需的 MIB (Management Information Base) 数组。`SysctlKinfoProc` 和 `SysctlKinfoProcSlice` 用于获取进程信息。

7. **提供 `ptrace` 接口:** `PtraceAttach`, `PtraceDetach`, `PtraceDenyAttach` 封装了 `ptrace` 系统调用，用于进程跟踪和调试。

8. **提供 `ioctl` 接口:** `IoctlCtlInfo`, `IoctlGetIfreqMTU`, `IoctlSetIfreqMTU` 展示了如何使用 `ioctl` 系统调用进行设备控制和信息获取，例如获取或设置网络接口的 MTU。

9. **提供线程相关的目录操作:** `PthreadChdir` 和 `PthreadFchdir` 允许改变当前线程的工作目录。

10. **提供高级连接功能:** `Connectx` 函数封装了 `connectx` 系统调用，提供了更灵活的连接选项，例如指定源接口和地址。

**Go 语言功能实现举例:**

**1. 读取目录内容 (模拟 `Getdirentries`)**

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
	dir, err := os.Open(".")
	if err != nil {
		fmt.Println("Error opening directory:", err)
		return
	}
	defer dir.Close()

	buf := make([]byte, 4096)
	basep := uintptr(0) // Not fully supported in the simulation

	for {
		n, err := unix.Getdirentries(int(dir.Fd()), buf, &basep)
		if err != nil {
			fmt.Println("Error reading directory:", err)
			return
		}
		if n == 0 {
			break // End of directory
		}

		offset := 0
		for offset < n {
			dirent := (*unix.Dirent)(unsafe.Pointer(&buf[offset]))
			fmt.Println("Inode:", dirent.Ino, "Name:", string(dirent.Name[:dirent.Namlen]))
			offset += int(dirent.Reclen)
		}
	}
}
```

**假设的输入与输出:**

假设当前目录下有文件 `a.txt` 和目录 `subdir`。

**输出:**

```
Inode: 6442451 Name: .
Inode: 6442453 Name: ..
Inode: 6442454 Name: a.txt
Inode: 6442455 Name: subdir
```

**代码推理:**

`Getdirentries` 函数在 Darwin 上通过模拟实现，它首先使用 `fdopendir` 打开目录，然后循环调用 `readdir_r` 读取目录项。读取到的目录项信息被拷贝到提供的 `buf` 中。循环遍历 `buf`，根据 `Dirent` 结构体的定义解析出每个目录项的 inode 和名称。

**2. 获取主机名 (使用 `sysctl`)**

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func main() {
	mib, err := unix.Nametomib("kern.hostname")
	if err != nil {
		fmt.Println("Error getting MIB:", err)
		return
	}

	var buf [256]byte
	n := uintptr(len(buf))

	err = unix.Sysctl(mib, (*byte)(unsafe.Pointer(&buf[0])), &n, nil, 0)
	if err != nil {
		fmt.Println("Error getting hostname:", err)
		return
	}

	hostname := string(buf[:n-1]) // 去掉末尾的 null 字符
	fmt.Println("Hostname:", hostname)
}
```

**假设的输入与输出:**

假设主机名为 `my-macbook`.

**输出:**

```
Hostname: my-macbook
```

**代码推理:**

`Nametomib` 函数将 "kern.hostname" 转换为 `sysctl` 可以理解的 MIB 数组。然后，`Sysctl` 函数被调用，使用该 MIB 来获取主机名。主机名被读取到 `buf` 中，并转换为字符串输出。

**命令行参数的具体处理:**

这段代码本身没有直接处理命令行参数的逻辑。但是，它提供的系统调用接口可以被其他 Go 程序使用来执行与命令行参数相关的操作。例如：

* **`Open`:**  如果一个程序接收一个文件路径作为命令行参数，它可以使用 `unix.Open` 打开该文件。
* **`Chdir`:** 如果程序需要改变工作目录，可以使用 `unix.Chdir`，路径可以来自命令行参数。
* **`Getpriority` / `Setpriority`:**  程序可能根据命令行参数调整自身的优先级。

**使用者易犯错的点:**

1. **`Getdirentries` 的模拟行为:** 用户可能会期望 `Getdirentries` 的 `basep` 参数具有与其他系统相同的行为（设置下一次读取的起始位置），但在 Darwin 的模拟实现中，这种行为可能不完全一致。

   **错误示例:**  假设用户尝试通过多次调用 `Getdirentries` 并期望 `basep` 能精确控制读取位置，可能会遇到与预期不符的情况。

2. **扩展属性操作的权限问题:**  访问和修改扩展属性通常需要特定的权限。用户可能会因为权限不足而导致 `Getxattr`, `Setxattr` 等函数调用失败。

   **错误示例:**  尝试修改系统文件的扩展属性，如果没有足够的权限，会返回错误。

3. **`sysctl` 的使用:**  不正确的 MIB 值或缓冲区大小会导致 `sysctl` 调用失败或返回错误的结果。

   **错误示例:**  使用错误的 MIB 查询 CPU 信息，可能导致程序崩溃或返回无意义的数据。

4. **文件描述符的管理:**  在 `Getdirentries` 的模拟实现中，代码内部会打开和关闭额外的文件描述符。如果用户在复杂的场景下混合使用 `Getdirentries` 和其他文件操作，可能会因为对文件描述符的理解不足而导致错误。

   **错误示例:**  在一个 goroutine 中调用 `Getdirentries`，并在另一个 goroutine 中关闭同一个目录的文件描述符，可能会导致 `Getdirentries` 内部的操作失败。

总而言之，这段代码是 Go 语言在 Darwin 平台上与操作系统底层交互的关键部分，它封装了大量的系统调用，并提供了一些高级的辅助函数，使得 Go 程序能够充分利用 Darwin 系统的功能。理解其功能和潜在的陷阱对于编写健壮的、平台相关的 Go 程序至关重要。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/syscall_darwin.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2009,2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Darwin system calls.
// This file is compiled as ordinary Go code,
// but it is also input to mksyscall,
// which parses the //sys lines and generates system call stubs.
// Note that sometimes we use a lowercase //sys name and wrap
// it in our own nicer implementation, either here or in
// syscall_bsd.go or syscall_unix.go.

package unix

import (
	"fmt"
	"syscall"
	"unsafe"
)

//sys	closedir(dir uintptr) (err error)
//sys	readdir_r(dir uintptr, entry *Dirent, result **Dirent) (res Errno)

func fdopendir(fd int) (dir uintptr, err error) {
	r0, _, e1 := syscall_syscallPtr(libc_fdopendir_trampoline_addr, uintptr(fd), 0, 0)
	dir = uintptr(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

var libc_fdopendir_trampoline_addr uintptr

//go:cgo_import_dynamic libc_fdopendir fdopendir "/usr/lib/libSystem.B.dylib"

func Getdirentries(fd int, buf []byte, basep *uintptr) (n int, err error) {
	// Simulate Getdirentries using fdopendir/readdir_r/closedir.
	// We store the number of entries to skip in the seek
	// offset of fd. See issue #31368.
	// It's not the full required semantics, but should handle the case
	// of calling Getdirentries or ReadDirent repeatedly.
	// It won't handle assigning the results of lseek to *basep, or handle
	// the directory being edited underfoot.
	skip, err := Seek(fd, 0, 1 /* SEEK_CUR */)
	if err != nil {
		return 0, err
	}

	// We need to duplicate the incoming file descriptor
	// because the caller expects to retain control of it, but
	// fdopendir expects to take control of its argument.
	// Just Dup'ing the file descriptor is not enough, as the
	// result shares underlying state. Use Openat to make a really
	// new file descriptor referring to the same directory.
	fd2, err := Openat(fd, ".", O_RDONLY, 0)
	if err != nil {
		return 0, err
	}
	d, err := fdopendir(fd2)
	if err != nil {
		Close(fd2)
		return 0, err
	}
	defer closedir(d)

	var cnt int64
	for {
		var entry Dirent
		var entryp *Dirent
		e := readdir_r(d, &entry, &entryp)
		if e != 0 {
			return n, errnoErr(e)
		}
		if entryp == nil {
			break
		}
		if skip > 0 {
			skip--
			cnt++
			continue
		}

		reclen := int(entry.Reclen)
		if reclen > len(buf) {
			// Not enough room. Return for now.
			// The counter will let us know where we should start up again.
			// Note: this strategy for suspending in the middle and
			// restarting is O(n^2) in the length of the directory. Oh well.
			break
		}

		// Copy entry into return buffer.
		s := unsafe.Slice((*byte)(unsafe.Pointer(&entry)), reclen)
		copy(buf, s)

		buf = buf[reclen:]
		n += reclen
		cnt++
	}
	// Set the seek offset of the input fd to record
	// how many files we've already returned.
	_, err = Seek(fd, cnt, 0 /* SEEK_SET */)
	if err != nil {
		return n, err
	}

	return n, nil
}

// SockaddrDatalink implements the Sockaddr interface for AF_LINK type sockets.
type SockaddrDatalink struct {
	Len    uint8
	Family uint8
	Index  uint16
	Type   uint8
	Nlen   uint8
	Alen   uint8
	Slen   uint8
	Data   [12]int8
	raw    RawSockaddrDatalink
}

// SockaddrCtl implements the Sockaddr interface for AF_SYSTEM type sockets.
type SockaddrCtl struct {
	ID   uint32
	Unit uint32
	raw  RawSockaddrCtl
}

func (sa *SockaddrCtl) sockaddr() (unsafe.Pointer, _Socklen, error) {
	sa.raw.Sc_len = SizeofSockaddrCtl
	sa.raw.Sc_family = AF_SYSTEM
	sa.raw.Ss_sysaddr = AF_SYS_CONTROL
	sa.raw.Sc_id = sa.ID
	sa.raw.Sc_unit = sa.Unit
	return unsafe.Pointer(&sa.raw), SizeofSockaddrCtl, nil
}

// SockaddrVM implements the Sockaddr interface for AF_VSOCK type sockets.
// SockaddrVM provides access to Darwin VM sockets: a mechanism that enables
// bidirectional communication between a hypervisor and its guest virtual
// machines.
type SockaddrVM struct {
	// CID and Port specify a context ID and port address for a VM socket.
	// Guests have a unique CID, and hosts may have a well-known CID of:
	//  - VMADDR_CID_HYPERVISOR: refers to the hypervisor process.
	//  - VMADDR_CID_LOCAL: refers to local communication (loopback).
	//  - VMADDR_CID_HOST: refers to other processes on the host.
	CID  uint32
	Port uint32
	raw  RawSockaddrVM
}

func (sa *SockaddrVM) sockaddr() (unsafe.Pointer, _Socklen, error) {
	sa.raw.Len = SizeofSockaddrVM
	sa.raw.Family = AF_VSOCK
	sa.raw.Port = sa.Port
	sa.raw.Cid = sa.CID

	return unsafe.Pointer(&sa.raw), SizeofSockaddrVM, nil
}

func anyToSockaddrGOOS(fd int, rsa *RawSockaddrAny) (Sockaddr, error) {
	switch rsa.Addr.Family {
	case AF_SYSTEM:
		pp := (*RawSockaddrCtl)(unsafe.Pointer(rsa))
		if pp.Ss_sysaddr == AF_SYS_CONTROL {
			sa := new(SockaddrCtl)
			sa.ID = pp.Sc_id
			sa.Unit = pp.Sc_unit
			return sa, nil
		}
	case AF_VSOCK:
		pp := (*RawSockaddrVM)(unsafe.Pointer(rsa))
		sa := &SockaddrVM{
			CID:  pp.Cid,
			Port: pp.Port,
		}
		return sa, nil
	}
	return nil, EAFNOSUPPORT
}

// Some external packages rely on SYS___SYSCTL being defined to implement their
// own sysctl wrappers. Provide it here, even though direct syscalls are no
// longer supported on darwin.
const SYS___SYSCTL = SYS_SYSCTL

// Translate "kern.hostname" to []_C_int{0,1,2,3}.
func nametomib(name string) (mib []_C_int, err error) {
	const siz = unsafe.Sizeof(mib[0])

	// NOTE(rsc): It seems strange to set the buffer to have
	// size CTL_MAXNAME+2 but use only CTL_MAXNAME
	// as the size. I don't know why the +2 is here, but the
	// kernel uses +2 for its own implementation of this function.
	// I am scared that if we don't include the +2 here, the kernel
	// will silently write 2 words farther than we specify
	// and we'll get memory corruption.
	var buf [CTL_MAXNAME + 2]_C_int
	n := uintptr(CTL_MAXNAME) * siz

	p := (*byte)(unsafe.Pointer(&buf[0]))
	bytes, err := ByteSliceFromString(name)
	if err != nil {
		return nil, err
	}

	// Magic sysctl: "setting" 0.3 to a string name
	// lets you read back the array of integers form.
	if err = sysctl([]_C_int{0, 3}, p, &n, &bytes[0], uintptr(len(name))); err != nil {
		return nil, err
	}
	return buf[0 : n/siz], nil
}

func direntIno(buf []byte) (uint64, bool) {
	return readInt(buf, unsafe.Offsetof(Dirent{}.Ino), unsafe.Sizeof(Dirent{}.Ino))
}

func direntReclen(buf []byte) (uint64, bool) {
	return readInt(buf, unsafe.Offsetof(Dirent{}.Reclen), unsafe.Sizeof(Dirent{}.Reclen))
}

func direntNamlen(buf []byte) (uint64, bool) {
	return readInt(buf, unsafe.Offsetof(Dirent{}.Namlen), unsafe.Sizeof(Dirent{}.Namlen))
}

func PtraceAttach(pid int) (err error) { return ptrace(PT_ATTACH, pid, 0, 0) }
func PtraceDetach(pid int) (err error) { return ptrace(PT_DETACH, pid, 0, 0) }
func PtraceDenyAttach() (err error)    { return ptrace(PT_DENY_ATTACH, 0, 0, 0) }

//sysnb	pipe(p *[2]int32) (err error)

func Pipe(p []int) (err error) {
	if len(p) != 2 {
		return EINVAL
	}
	var x [2]int32
	err = pipe(&x)
	if err == nil {
		p[0] = int(x[0])
		p[1] = int(x[1])
	}
	return
}

func Getfsstat(buf []Statfs_t, flags int) (n int, err error) {
	var _p0 unsafe.Pointer
	var bufsize uintptr
	if len(buf) > 0 {
		_p0 = unsafe.Pointer(&buf[0])
		bufsize = unsafe.Sizeof(Statfs_t{}) * uintptr(len(buf))
	}
	return getfsstat(_p0, bufsize, flags)
}

func xattrPointer(dest []byte) *byte {
	// It's only when dest is set to NULL that the OS X implementations of
	// getxattr() and listxattr() return the current sizes of the named attributes.
	// An empty byte array is not sufficient. To maintain the same behaviour as the
	// linux implementation, we wrap around the system calls and pass in NULL when
	// dest is empty.
	var destp *byte
	if len(dest) > 0 {
		destp = &dest[0]
	}
	return destp
}

//sys	getxattr(path string, attr string, dest *byte, size int, position uint32, options int) (sz int, err error)

func Getxattr(path string, attr string, dest []byte) (sz int, err error) {
	return getxattr(path, attr, xattrPointer(dest), len(dest), 0, 0)
}

func Lgetxattr(link string, attr string, dest []byte) (sz int, err error) {
	return getxattr(link, attr, xattrPointer(dest), len(dest), 0, XATTR_NOFOLLOW)
}

//sys	fgetxattr(fd int, attr string, dest *byte, size int, position uint32, options int) (sz int, err error)

func Fgetxattr(fd int, attr string, dest []byte) (sz int, err error) {
	return fgetxattr(fd, attr, xattrPointer(dest), len(dest), 0, 0)
}

//sys	setxattr(path string, attr string, data *byte, size int, position uint32, options int) (err error)

func Setxattr(path string, attr string, data []byte, flags int) (err error) {
	// The parameters for the OS X implementation vary slightly compared to the
	// linux system call, specifically the position parameter:
	//
	//  linux:
	//      int setxattr(
	//          const char *path,
	//          const char *name,
	//          const void *value,
	//          size_t size,
	//          int flags
	//      );
	//
	//  darwin:
	//      int setxattr(
	//          const char *path,
	//          const char *name,
	//          void *value,
	//          size_t size,
	//          u_int32_t position,
	//          int options
	//      );
	//
	// position specifies the offset within the extended attribute. In the
	// current implementation, only the resource fork extended attribute makes
	// use of this argument. For all others, position is reserved. We simply
	// default to setting it to zero.
	return setxattr(path, attr, xattrPointer(data), len(data), 0, flags)
}

func Lsetxattr(link string, attr string, data []byte, flags int) (err error) {
	return setxattr(link, attr, xattrPointer(data), len(data), 0, flags|XATTR_NOFOLLOW)
}

//sys	fsetxattr(fd int, attr string, data *byte, size int, position uint32, options int) (err error)

func Fsetxattr(fd int, attr string, data []byte, flags int) (err error) {
	return fsetxattr(fd, attr, xattrPointer(data), len(data), 0, 0)
}

//sys	removexattr(path string, attr string, options int) (err error)

func Removexattr(path string, attr string) (err error) {
	// We wrap around and explicitly zero out the options provided to the OS X
	// implementation of removexattr, we do so for interoperability with the
	// linux variant.
	return removexattr(path, attr, 0)
}

func Lremovexattr(link string, attr string) (err error) {
	return removexattr(link, attr, XATTR_NOFOLLOW)
}

//sys	fremovexattr(fd int, attr string, options int) (err error)

func Fremovexattr(fd int, attr string) (err error) {
	return fremovexattr(fd, attr, 0)
}

//sys	listxattr(path string, dest *byte, size int, options int) (sz int, err error)

func Listxattr(path string, dest []byte) (sz int, err error) {
	return listxattr(path, xattrPointer(dest), len(dest), 0)
}

func Llistxattr(link string, dest []byte) (sz int, err error) {
	return listxattr(link, xattrPointer(dest), len(dest), XATTR_NOFOLLOW)
}

//sys	flistxattr(fd int, dest *byte, size int, options int) (sz int, err error)

func Flistxattr(fd int, dest []byte) (sz int, err error) {
	return flistxattr(fd, xattrPointer(dest), len(dest), 0)
}

//sys	utimensat(dirfd int, path string, times *[2]Timespec, flags int) (err error)

/*
 * Wrapped
 */

//sys	fcntl(fd int, cmd int, arg int) (val int, err error)

//sys	kill(pid int, signum int, posix int) (err error)

func Kill(pid int, signum syscall.Signal) (err error) { return kill(pid, int(signum), 1) }

//sys	ioctl(fd int, req uint, arg uintptr) (err error)
//sys	ioctlPtr(fd int, req uint, arg unsafe.Pointer) (err error) = SYS_IOCTL

func IoctlCtlInfo(fd int, ctlInfo *CtlInfo) error {
	return ioctlPtr(fd, CTLIOCGINFO, unsafe.Pointer(ctlInfo))
}

// IfreqMTU is struct ifreq used to get or set a network device's MTU.
type IfreqMTU struct {
	Name [IFNAMSIZ]byte
	MTU  int32
}

// IoctlGetIfreqMTU performs the SIOCGIFMTU ioctl operation on fd to get the MTU
// of the network device specified by ifname.
func IoctlGetIfreqMTU(fd int, ifname string) (*IfreqMTU, error) {
	var ifreq IfreqMTU
	copy(ifreq.Name[:], ifname)
	err := ioctlPtr(fd, SIOCGIFMTU, unsafe.Pointer(&ifreq))
	return &ifreq, err
}

// IoctlSetIfreqMTU performs the SIOCSIFMTU ioctl operation on fd to set the MTU
// of the network device specified by ifreq.Name.
func IoctlSetIfreqMTU(fd int, ifreq *IfreqMTU) error {
	return ioctlPtr(fd, SIOCSIFMTU, unsafe.Pointer(ifreq))
}

//sys	renamexNp(from string, to string, flag uint32) (err error)

func RenamexNp(from string, to string, flag uint32) (err error) {
	return renamexNp(from, to, flag)
}

//sys	renameatxNp(fromfd int, from string, tofd int, to string, flag uint32) (err error)

func RenameatxNp(fromfd int, from string, tofd int, to string, flag uint32) (err error) {
	return renameatxNp(fromfd, from, tofd, to, flag)
}

//sys	sysctl(mib []_C_int, old *byte, oldlen *uintptr, new *byte, newlen uintptr) (err error) = SYS_SYSCTL

func Uname(uname *Utsname) error {
	mib := []_C_int{CTL_KERN, KERN_OSTYPE}
	n := unsafe.Sizeof(uname.Sysname)
	if err := sysctl(mib, &uname.Sysname[0], &n, nil, 0); err != nil {
		return err
	}

	mib = []_C_int{CTL_KERN, KERN_HOSTNAME}
	n = unsafe.Sizeof(uname.Nodename)
	if err := sysctl(mib, &uname.Nodename[0], &n, nil, 0); err != nil {
		return err
	}

	mib = []_C_int{CTL_KERN, KERN_OSRELEASE}
	n = unsafe.Sizeof(uname.Release)
	if err := sysctl(mib, &uname.Release[0], &n, nil, 0); err != nil {
		return err
	}

	mib = []_C_int{CTL_KERN, KERN_VERSION}
	n = unsafe.Sizeof(uname.Version)
	if err := sysctl(mib, &uname.Version[0], &n, nil, 0); err != nil {
		return err
	}

	// The version might have newlines or tabs in it, convert them to
	// spaces.
	for i, b := range uname.Version {
		if b == '\n' || b == '\t' {
			if i == len(uname.Version)-1 {
				uname.Version[i] = 0
			} else {
				uname.Version[i] = ' '
			}
		}
	}

	mib = []_C_int{CTL_HW, HW_MACHINE}
	n = unsafe.Sizeof(uname.Machine)
	if err := sysctl(mib, &uname.Machine[0], &n, nil, 0); err != nil {
		return err
	}

	return nil
}

func Sendfile(outfd int, infd int, offset *int64, count int) (written int, err error) {
	if raceenabled {
		raceReleaseMerge(unsafe.Pointer(&ioSync))
	}
	var length = int64(count)
	err = sendfile(infd, outfd, *offset, &length, nil, 0)
	written = int(length)
	return
}

func GetsockoptIPMreqn(fd, level, opt int) (*IPMreqn, error) {
	var value IPMreqn
	vallen := _Socklen(SizeofIPMreqn)
	errno := getsockopt(fd, level, opt, unsafe.Pointer(&value), &vallen)
	return &value, errno
}

func SetsockoptIPMreqn(fd, level, opt int, mreq *IPMreqn) (err error) {
	return setsockopt(fd, level, opt, unsafe.Pointer(mreq), unsafe.Sizeof(*mreq))
}

// GetsockoptXucred is a getsockopt wrapper that returns an Xucred struct.
// The usual level and opt are SOL_LOCAL and LOCAL_PEERCRED, respectively.
func GetsockoptXucred(fd, level, opt int) (*Xucred, error) {
	x := new(Xucred)
	vallen := _Socklen(SizeofXucred)
	err := getsockopt(fd, level, opt, unsafe.Pointer(x), &vallen)
	return x, err
}

func GetsockoptTCPConnectionInfo(fd, level, opt int) (*TCPConnectionInfo, error) {
	var value TCPConnectionInfo
	vallen := _Socklen(SizeofTCPConnectionInfo)
	err := getsockopt(fd, level, opt, unsafe.Pointer(&value), &vallen)
	return &value, err
}

func SysctlKinfoProc(name string, args ...int) (*KinfoProc, error) {
	mib, err := sysctlmib(name, args...)
	if err != nil {
		return nil, err
	}

	var kinfo KinfoProc
	n := uintptr(SizeofKinfoProc)
	if err := sysctl(mib, (*byte)(unsafe.Pointer(&kinfo)), &n, nil, 0); err != nil {
		return nil, err
	}
	if n != SizeofKinfoProc {
		return nil, EIO
	}
	return &kinfo, nil
}

func SysctlKinfoProcSlice(name string, args ...int) ([]KinfoProc, error) {
	mib, err := sysctlmib(name, args...)
	if err != nil {
		return nil, err
	}

	for {
		// Find size.
		n := uintptr(0)
		if err := sysctl(mib, nil, &n, nil, 0); err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, nil
		}
		if n%SizeofKinfoProc != 0 {
			return nil, fmt.Errorf("sysctl() returned a size of %d, which is not a multiple of %d", n, SizeofKinfoProc)
		}

		// Read into buffer of that size.
		buf := make([]KinfoProc, n/SizeofKinfoProc)
		if err := sysctl(mib, (*byte)(unsafe.Pointer(&buf[0])), &n, nil, 0); err != nil {
			if err == ENOMEM {
				// Process table grew. Try again.
				continue
			}
			return nil, err
		}
		if n%SizeofKinfoProc != 0 {
			return nil, fmt.Errorf("sysctl() returned a size of %d, which is not a multiple of %d", n, SizeofKinfoProc)
		}

		// The actual call may return less than the original reported required
		// size so ensure we deal with that.
		return buf[:n/SizeofKinfoProc], nil
	}
}

//sys	pthread_chdir_np(path string) (err error)

func PthreadChdir(path string) (err error) {
	return pthread_chdir_np(path)
}

//sys	pthread_fchdir_np(fd int) (err error)

func PthreadFchdir(fd int) (err error) {
	return pthread_fchdir_np(fd)
}

// Connectx calls connectx(2) to initiate a connection on a socket.
//
// srcIf, srcAddr, and dstAddr are filled into a [SaEndpoints] struct and passed as the endpoints argument.
//
//   - srcIf is the optional source interface index. 0 means unspecified.
//   - srcAddr is the optional source address. nil means unspecified.
//   - dstAddr is the destination address.
//
// On success, Connectx returns the number of bytes enqueued for transmission.
func Connectx(fd int, srcIf uint32, srcAddr, dstAddr Sockaddr, associd SaeAssocID, flags uint32, iov []Iovec, connid *SaeConnID) (n uintptr, err error) {
	endpoints := SaEndpoints{
		Srcif: srcIf,
	}

	if srcAddr != nil {
		addrp, addrlen, err := srcAddr.sockaddr()
		if err != nil {
			return 0, err
		}
		endpoints.Srcaddr = (*RawSockaddr)(addrp)
		endpoints.Srcaddrlen = uint32(addrlen)
	}

	if dstAddr != nil {
		addrp, addrlen, err := dstAddr.sockaddr()
		if err != nil {
			return 0, err
		}
		endpoints.Dstaddr = (*RawSockaddr)(addrp)
		endpoints.Dstaddrlen = uint32(addrlen)
	}

	err = connectx(fd, &endpoints, associd, flags, iov, &n, connid)
	return
}

//sys	connectx(fd int, endpoints *SaEndpoints, associd SaeAssocID, flags uint32, iov []Iovec, n *uintptr, connid *SaeConnID) (err error)
//sys	sendfile(infd int, outfd int, offset int64, len *int64, hdtr unsafe.Pointer, flags int) (err error)

//sys	shmat(id int, addr uintptr, flag int) (ret uintptr, err error)
//sys	shmctl(id int, cmd int, buf *SysvShmDesc) (result int, err error)
//sys	shmdt(addr uintptr) (err error)
//sys	shmget(key int, size int, flag int) (id int, err error)

/*
 * Exposed directly
 */
//sys	Access(path string, mode uint32) (err error)
//sys	Adjtime(delta *Timeval, olddelta *Timeval) (err error)
//sys	Chdir(path string) (err error)
//sys	Chflags(path string, flags int) (err error)
//sys	Chmod(path string, mode uint32) (err error)
//sys	Chown(path string, uid int, gid int) (err error)
//sys	Chroot(path string) (err error)
//sys	ClockGettime(clockid int32, time *Timespec) (err error)
//sys	Close(fd int) (err error)
//sys	Clonefile(src string, dst string, flags int) (err error)
//sys	Clonefileat(srcDirfd int, src string, dstDirfd int, dst string, flags int) (err error)
//sys	Dup(fd int) (nfd int, err error)
//sys	Dup2(from int, to int) (err error)
//sys	Exchangedata(path1 string, path2 string, options int) (err error)
//sys	Exit(code int)
//sys	Faccessat(dirfd int, path string, mode uint32, flags int) (err error)
//sys	Fchdir(fd int) (err error)
//sys	Fchflags(fd int, flags int) (err error)
//sys	Fchmod(fd int, mode uint32) (err error)
//sys	Fchmodat(dirfd int, path string, mode uint32, flags int) (err error)
//sys	Fchown(fd int, uid int, gid int) (err error)
//sys	Fchownat(dirfd int, path string, uid int, gid int, flags int) (err error)
//sys	Fclonefileat(srcDirfd int, dstDirfd int, dst string, flags int) (err error)
//sys	Flock(fd int, how int) (err error)
//sys	Fpathconf(fd int, name int) (val int, err error)
//sys	Fsync(fd int) (err error)
//sys	Ftruncate(fd int, length int64) (err error)
//sys	Getcwd(buf []byte) (n int, err error)
//sys	Getdtablesize() (size int)
//sysnb	Getegid() (egid int)
//sysnb	Geteuid() (uid int)
//sysnb	Getgid() (gid int)
//sysnb	Getpgid(pid int) (pgid int, err error)
//sysnb	Getpgrp() (pgrp int)
//sysnb	Getpid() (pid int)
//sysnb	Getppid() (ppid int)
//sys	Getpriority(which int, who int) (prio int, err error)
//sysnb	Getrlimit(which int, lim *Rlimit) (err error)
//sysnb	Getrusage(who int, rusage *Rusage) (err error)
//sysnb	Getsid(pid int) (sid int, err error)
//sysnb	Gettimeofday(tp *Timeval) (err error)
//sysnb	Getuid() (uid int)
//sysnb	Issetugid() (tainted bool)
//sys	Kqueue() (fd int, err error)
//sys	Lchown(path string, uid int, gid int) (err error)
//sys	Link(path string, link string) (err error)
//sys	Linkat(pathfd int, path string, linkfd int, link string, flags int) (err error)
//sys	Listen(s int, backlog int) (err error)
//sys	Mkdir(path string, mode uint32) (err error)
//sys	Mkdirat(dirfd int, path string, mode uint32) (err error)
//sys	Mkfifo(path string, mode uint32) (err error)
//sys	Mknod(path string, mode uint32, dev int) (err error)
//sys	Mount(fsType string, dir string, flags int, data unsafe.Pointer) (err error)
//sys	Open(path string, mode int, perm uint32) (fd int, err error)
//sys	Openat(dirfd int, path string, mode int, perm uint32) (fd int, err error)
//sys	Pathconf(path string, name int) (val int, err error)
//sys	pread(fd int, p []byte, offset int64) (n int, err error)
//sys	pwrite(fd int, p []byte, offset int64) (n int, err error)
//sys	read(fd int, p []byte) (n int, err error)
//sys	Readlink(path string, buf []byte) (n int, err error)
//sys	Readlinkat(dirfd int, path string, buf []byte) (n int, err error)
//sys	Rename(from string, to string) (err error)
//sys	Renameat(fromfd int, from string, tofd int, to string) (err error)
//sys	Revoke(path string) (err error)
//sys	Rmdir(path string) (err error)
//sys	Seek(fd int, offset int64, whence int) (newoffset int64, err error) = SYS_LSEEK
//sys	Select(nfd int, r *FdSet, w *FdSet, e *FdSet, timeout *Timeval) (n int, err error)
//sys	Setattrlist(path string, attrlist *Attrlist, attrBuf []byte, options int) (err error)
//sys	Setegid(egid int) (err error)
//sysnb	Seteuid(euid int) (err error)
//sysnb	Setgid(gid int) (err error)
//sys	Setlogin(name string) (err error)
//sysnb	Setpgid(pid int, pgid int) (err error)
//sys	Setpriority(which int, who int, prio int) (err error)
//sys	Setprivexec(flag int) (err error)
//sysnb	Setregid(rgid int, egid int) (err error)
//sysnb	Setreuid(ruid int, euid int) (err error)
//sysnb	Setsid() (pid int, err error)
//sysnb	Settimeofday(tp *Timeval) (err error)
//sysnb	Setuid(uid int) (err error)
//sys	Symlink(path string, link string) (err error)
//sys	Symlinkat(oldpath string, newdirfd int, newpath string) (err error)
//sys	Sync() (err error)
//sys	Truncate(path string, length int64) (err error)
//sys	Umask(newmask int) (oldmask int)
//sys	Undelete(path string) (err error)
//sys	Unlink(path string) (err error)
//sys	Unlinkat(dirfd int, path string, flags int) (err error)
//sys	Unmount(path string, flags int) (err error)
//sys	write(fd int, p []byte) (n int, err error)
//sys	mmap(addr uintptr, length uintptr, prot int, flag int, fd int, pos int64) (ret uintptr, err error)
//sys	munmap(addr uintptr, length uintptr) (err error)
```