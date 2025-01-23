Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Scan and Overall Purpose:**

* **Filename and Build Constraints:** The filename `syscall_bsd.go` and the `//go:build` line immediately signal that this code deals with system calls specific to BSD-based operating systems (Darwin, Dragonfly, FreeBSD, NetBSD, OpenBSD). The `vendor` directory suggests it's an internal part of a larger Go project.
* **Package Name:** `package unix` indicates this code provides low-level Unix system call functionalities, likely used internally by Go's standard library or other low-level packages.
* **Imports:** The `runtime`, `syscall`, and `unsafe` imports confirm the low-level nature and direct interaction with the operating system.

**2. Function-by-Function Analysis (Focusing on Key Functions and Concepts):**

* **`Getwd()`:**  A very common Unix function. The code allocates a buffer, calls `Getcwd`, and then converts the byte slice to a string. This is clearly about getting the current working directory.
* **`Getgroups()` and `Setgroups()`:** These deal with user group IDs. The code shows how to retrieve the list of groups a user belongs to and how to set the group list. The use of `_Gid_t` hints at a platform-specific representation.
* **`WaitStatus` and related methods:** This is about interpreting the status returned by the `wait4` system call. The bitwise operations and constants (`mask`, `core`, `shift`) are typical for decoding status information. Each method (`Exited`, `Signaled`, etc.) extracts a specific piece of information from the raw status.
* **Socket-related functions (`accept`, `bind`, `connect`, `socket`, etc.):**  A large block of code dedicated to socket operations. The functions and their names are standard Unix socket API calls. The `sockaddr()` methods on different `Sockaddr` types (`SockaddrInet4`, `SockaddrInet6`, `SockaddrUnix`, `SockaddrDatalink`) are responsible for converting Go structures to the low-level `sockaddr` structure required by the system calls. The `anyToSockaddr()` function does the reverse, converting a raw `sockaddr` back into a Go `Sockaddr` interface. The `Accept()` function has a special case for Darwin/iOS, indicating a known OS-specific behavior.
* **`GetsockoptString()`:**  A specific helper function to get string-based socket options.
* **`recvfrom`, `sendto`, `recvmsg`, `sendmsg`:**  Functions for sending and receiving data on sockets. The `recvmsgRaw` and `sendmsgN` helper functions handle the details of the `Msghdr` structure, which is used for advanced socket I/O.
* **`kevent()`:**  Indicates support for the `kqueue` event notification mechanism, common on BSD systems.
* **`Sysctl*()` functions:** These functions are for interacting with the system's kernel parameters via the `sysctl` interface. The different variations (`Sysctl`, `SysctlArgs`, `SysctlUint32`, `SysctlRaw`, etc.) demonstrate how to retrieve different types of data.
* **`Utimes`, `UtimesNano`, `UtimesNanoAt`, `Futimes`:** These functions are about modifying file access and modification times. The variations with `Nano` indicate support for nanosecond precision.
* **`Poll()`:**  Implements the `poll` system call for multiplexing I/O operations.
* **Memory management functions (`Madvise`, `Mlock`, `Mprotect`, etc.):**  Functions related to managing memory regions, like locking memory, changing permissions, and providing hints to the kernel.

**3. Identifying Go Language Features:**

* **System Calls:** The core purpose is wrapping system calls. The `//sys` and `//sysnb` comments are key indicators. `//sysnb` likely means "no blocking" in the context of signal handling (though this isn't explicitly demonstrated in the provided snippet).
* **Pointers and `unsafe`:** The extensive use of `unsafe.Pointer` is unavoidable when interacting directly with system calls that expect memory addresses.
* **Slices:**  Slices are used to represent buffers for system calls, like the buffer in `Getwd()` and the `gids` slice in `Getgroups`/`Setgroups`.
* **Structs:** Structures like `WaitStatus`, `SockaddrInet4`, `RawSockaddrAny`, `Msghdr`, `Kevent_t`, etc., mirror the underlying C structures used by the operating system.
* **Methods:**  Methods on the `WaitStatus` and `Sockaddr` types provide a more Go-idiomatic way to interact with the data.
* **Constants:**  Constants like `PathMax`, `AF_INET`, `SIGSTOP`, etc., represent values defined by the operating system.
* **Error Handling:** The consistent use of `error` as the second return value is standard Go error handling.

**4. Code Example and Reasoning (Focusing on a good illustrative case):**

The `Getwd()` function is a simple and clear example to illustrate. The thought process would be:

* **What does `Getwd()` do?** Gets the current working directory.
* **How does the code implement it?** Allocates a buffer, calls `Getcwd`, converts to a string.
* **How can I use this in Go?** Just call `unix.Getwd()`.
* **What are possible inputs and outputs?**  No direct inputs, output is the path or an error.
* **Example Code:**  Write a simple program that calls `unix.Getwd()` and prints the result.
* **Reasoning for Choices:** This function is easily understood, demonstrates basic system call interaction, and doesn't involve complex setup.

**5. Potential Pitfalls (Looking for common errors):**

* **Incorrect Buffer Sizes:** When dealing with system calls that require buffers, providing the wrong size is a common error. The `Getwd()` example implicitly handles this by using `PathMax`, but in other cases, like `recvfrom`, the programmer needs to be careful.
* **Endianness and Data Structures:**  While not explicitly shown as an error in the provided code, issues with byte ordering (endianness) can arise when interacting with low-level structures, especially when dealing with network protocols. The code handles some of this in the `sockaddr()` methods by manually packing bytes.
* **Understanding System Call Semantics:**  Misunderstanding the behavior or requirements of a specific system call is a major source of errors. For instance, not checking the return value of `accept` or not handling potential errors correctly.
* **Incorrectly Interpreting `WaitStatus`:**  The bitwise operations on `WaitStatus` can be tricky. Using the provided helper methods is the recommended way, but manually trying to decode the status without understanding the bit layout is error-prone.

**6. Command Line Arguments:**

The code itself doesn't directly process command-line arguments. This is a higher-level concern handled by the `main` function of a Go program. The system calls wrapped here *might* be used by programs that take command-line arguments (e.g., a program that changes the working directory or interacts with network sockets), but this snippet focuses on the core system call interface.

**7. Refinement and Organization:**

After the initial analysis, the thought process involves organizing the findings into clear categories: functionality, Go features, examples, potential errors, etc. This makes the information easier to understand and use. Adding details and explanations to each point improves clarity.
This Go code snippet from `go/src/cmd/vendor/golang.org/x/sys/unix/syscall_bsd.go` provides low-level system call wrappers for BSD-based operating systems (Darwin/macOS, Dragonfly, FreeBSD, NetBSD, and OpenBSD). It's essentially an interface between Go code and the kernel's system call API.

Here's a breakdown of its functionality:

**Core Functionality:**

1. **System Call Wrappers:**  The primary purpose is to provide Go functions that directly invoke underlying BSD system calls. These are marked with `//sys` or `//sysnb` comments, which are directives for the `mksyscall` tool to generate assembly stubs for the actual system call invocation. Examples include:
   - `getgroups`, `setgroups`: For managing user group IDs.
   - `wait4`: For waiting for a child process to change state.
   - `accept`, `bind`, `connect`, `socket`, `getsockopt`, `setsockopt`, `getpeername`, `getsockname`, `Shutdown`: For network socket operations.
   - `recvfrom`, `sendto`, `recvmsg`, `sendmsg`: For sending and receiving data over sockets.
   - `kevent`: For the kqueue event notification mechanism.
   - `sysctl`: For querying and setting kernel parameters.
   - `utimes`, `futimes`: For modifying file access and modification times.
   - `poll`: For multiplexing I/O operations.
   - `Madvise`, `Mlock`, `Mlockall`, `Mprotect`, `Msync`, `Munlock`, `Munlockall`: For memory management.

2. **Utility Functions:** It includes helper functions to simplify common tasks related to system calls:
   - `Getwd()`: Gets the current working directory.
   - `Getgroups()`: Gets the list of groups the current user belongs to.
   - `Setgroups()`: Sets the list of groups for the current process.
   - `WaitStatus`: A type and associated methods for interpreting the status returned by `wait4`.
   - Functions for converting between Go socket address structures (`SockaddrInet4`, `SockaddrInet6`, `SockaddrUnix`, `SockaddrDatalink`) and the raw `sockaddr` structures used by system calls (`sockaddr()` methods and `anyToSockaddr()`).
   - `GetsockoptString()`: A helper to retrieve string-based socket options.
   - `Sysctl`, `SysctlArgs`, `SysctlUint32`, `SysctlRaw`, `SysctlClockinfo`, `SysctlTimeval`: Functions for interacting with the `sysctl` interface in various ways.
   - `UtimesNano`, `UtimesNanoAt`: Provide nanosecond precision for file timestamp modifications, potentially using `utimensat` if available.
   - `Poll()`: A wrapper for the `poll` system call.

**Go Language Feature Implementation Examples:**

Let's illustrate with a few examples:

**1. Getting the current working directory using `Getwd()`:**

```go
package main

import (
	"fmt"
	"golang.org/x/sys/unix"
	"log"
)

func main() {
	cwd, err := unix.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Current working directory:", cwd)
}
```

**Explanation:**

- This code directly uses the `unix.Getwd()` function provided in the snippet.
- **Assumption:** The program is executed in a directory (e.g., `/home/user/projects`).
- **Output:**
  ```
  Current working directory: /home/user/projects
  ```

**2. Getting the list of group IDs using `Getgroups()`:**

```go
package main

import (
	"fmt"
	"golang.org/x/sys/unix"
	"log"
)

func main() {
	gids, err := unix.Getgroups()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Group IDs:", gids)
}
```

**Explanation:**

- This code uses the `unix.Getgroups()` function.
- **Assumption:** The user executing the program belongs to several groups (e.g., 100, 101, 105).
- **Output:**
  ```
  Group IDs: [100 101 105]
  ```

**3. Waiting for a child process to exit using `Wait4()` (more involved):**

```go
package main

import (
	"fmt"
	"golang.org/x/sys/unix"
	"log"
	"os"
	"syscall"
)

func main() {
	pid, _, err := syscall.ForkExec("/bin/sleep", []string{"sleep", "2"}, &syscall.ProcAttr{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Spawned child process with PID:", pid)

	var wstatus unix.WaitStatus
	var rusage unix.Rusage
	wpid, err := unix.Wait4(pid, &wstatus, 0, &rusage)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Child process exited with PID:", wpid)
	fmt.Println("Exit Status:", wstatus.ExitStatus())
}
```

**Explanation:**

- This example demonstrates using `Wait4()`.
- **Input:** It forks and executes the `sleep` command as a child process.
- **Output:**
  ```
  Spawned child process with PID: 12345
  Child process exited with PID: 12345
  Exit Status: 0
  ```
- **Code Reasoning:**
  - `syscall.ForkExec` creates a new process.
  - `unix.Wait4` waits for the specific child process (with the given `pid`) to change state.
  - The `wstatus` variable of type `unix.WaitStatus` will hold information about how the child process terminated.
  - `wstatus.ExitStatus()` extracts the exit code of the child process.

**Code Reasoning (More Detail):**

- **`Getwd()`:**  It calls the `Getcwd` system call (via the generated stub) to get the current working directory into a byte buffer. The `clen` function (not shown but likely in another file) calculates the length of the null-terminated string in the buffer.
- **`Getgroups()`:** It first calls `getgroups` with `ngid = 0` and `gid = nil` to determine the number of groups the user belongs to. Then, it allocates a slice of `_Gid_t` (a platform-specific integer type for group IDs) and calls `getgroups` again to fill the slice with the actual group IDs.
- **`Setgroups()`:** It takes a slice of Go `int` representing group IDs, converts them to `_Gid_t`, and then calls the `setgroups` system call.
- **`WaitStatus`:** This type and its methods provide a structured way to interpret the raw status integer returned by `wait` system calls. The bitwise operations and constants help extract information like whether the process exited normally, was signaled, or dumped core.
- **Socket Functions:**  The functions like `accept`, `bind`, `connect`, etc., directly map to the corresponding BSD socket system calls. The `sockaddr()` methods on `SockaddrInet4`, `SockaddrInet6`, and `SockaddrUnix` handle the conversion of Go-friendly socket address structures into the raw `sockaddr` structures that the kernel expects. `anyToSockaddr` does the reverse conversion when receiving socket addresses from the kernel.
- **`Sysctl` Functions:** These functions use the `sysctl` system call to retrieve kernel parameters. They often involve translating a string-based name (like "kern.hostname") into a Management Information Base (MIB) array, then calling `sysctl` to get the value.

**Command-Line Parameter Handling:**

This specific code snippet does **not** handle command-line arguments directly. Command-line argument processing is typically done in the `main` function of a Go program using the `os` package (e.g., `os.Args`). However, the system calls wrapped by this code *might be used* by programs that process command-line arguments. For example, a network utility might use the socket functions in this file after parsing command-line arguments specifying the server address and port.

**User Errors:**

Here are some common mistakes users might make when using the functions in this file (or higher-level abstractions that rely on them):

1. **Incorrect Buffer Sizes:** When using functions like `recvfrom` or `getsockopt` that require passing in a buffer, providing an incorrectly sized buffer can lead to errors or data corruption.

   ```go
   // Potential error: buffer too small
   buf := make([]byte, 10)
   var addr unix.RawSockaddrAny
   var addrlen unix._Socklen = unix.SizeofSockaddrAny
   n, _, err := unix.Recvfrom(sockfd, buf, 0, &addr, &addrlen)
   if err != nil {
       // Handle error
   }
   // If the actual message is longer than 10 bytes, it will be truncated.
   ```

2. **Incorrectly Interpreting `WaitStatus`:** Trying to manually decode the `WaitStatus` integer using incorrect bitmasks or shifts can lead to wrong conclusions about how a child process terminated. It's recommended to use the provided methods like `Exited()`, `Signaled()`, `ExitStatus()`, etc.

3. **Misunderstanding Socket Address Structures:** Providing incorrect values in the `Sockaddr` structures (e.g., wrong port numbers, incorrect address family) will cause connection or binding failures.

   ```go
   // Potential error: incorrect port number
   addr := &unix.SockaddrInet4{
       Port: 65536, // Invalid port number
   }
   // ... using addr in bind or connect ...
   ```

4. **Not Handling Errors:**  System calls can fail for various reasons. Ignoring the returned `error` value can lead to unexpected program behavior.

   ```go
   // Potential error: ignoring the error
   unix.Connect(sockfd, unsafe.Pointer(sockaddrPtr), socklen)
   // If connect fails, the program might proceed as if it succeeded.
   ```

5. **Using Blocking vs. Non-blocking Calls Incorrectly:** Some system calls have blocking and non-blocking variants. Misunderstanding which one is being used and not handling the implications (e.g., using non-blocking I/O without proper polling or event notification) can lead to unexpected delays or resource exhaustion.

This code snippet is a fundamental building block for more complex networking, process management, and system-level operations in Go on BSD-based systems. Understanding its functions and potential pitfalls is crucial for writing correct and robust Go programs that interact with the operating system at a low level.

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/syscall_bsd.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin || dragonfly || freebsd || netbsd || openbsd

// BSD system call wrappers shared by *BSD based systems
// including OS X (Darwin) and FreeBSD.  Like the other
// syscall_*.go files it is compiled as Go code but also
// used as input to mksyscall which parses the //sys
// lines and generates system call stubs.

package unix

import (
	"runtime"
	"syscall"
	"unsafe"
)

const ImplementsGetwd = true

func Getwd() (string, error) {
	var buf [PathMax]byte
	_, err := Getcwd(buf[0:])
	if err != nil {
		return "", err
	}
	n := clen(buf[:])
	if n < 1 {
		return "", EINVAL
	}
	return string(buf[:n]), nil
}

/*
 * Wrapped
 */

//sysnb	getgroups(ngid int, gid *_Gid_t) (n int, err error)
//sysnb	setgroups(ngid int, gid *_Gid_t) (err error)

func Getgroups() (gids []int, err error) {
	n, err := getgroups(0, nil)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}

	// Sanity check group count. Max is 16 on BSD.
	if n < 0 || n > 1000 {
		return nil, EINVAL
	}

	a := make([]_Gid_t, n)
	n, err = getgroups(n, &a[0])
	if err != nil {
		return nil, err
	}
	gids = make([]int, n)
	for i, v := range a[0:n] {
		gids[i] = int(v)
	}
	return
}

func Setgroups(gids []int) (err error) {
	if len(gids) == 0 {
		return setgroups(0, nil)
	}

	a := make([]_Gid_t, len(gids))
	for i, v := range gids {
		a[i] = _Gid_t(v)
	}
	return setgroups(len(a), &a[0])
}

// Wait status is 7 bits at bottom, either 0 (exited),
// 0x7F (stopped), or a signal number that caused an exit.
// The 0x80 bit is whether there was a core dump.
// An extra number (exit code, signal causing a stop)
// is in the high bits.

type WaitStatus uint32

const (
	mask  = 0x7F
	core  = 0x80
	shift = 8

	exited  = 0
	killed  = 9
	stopped = 0x7F
)

func (w WaitStatus) Exited() bool { return w&mask == exited }

func (w WaitStatus) ExitStatus() int {
	if w&mask != exited {
		return -1
	}
	return int(w >> shift)
}

func (w WaitStatus) Signaled() bool { return w&mask != stopped && w&mask != 0 }

func (w WaitStatus) Signal() syscall.Signal {
	sig := syscall.Signal(w & mask)
	if sig == stopped || sig == 0 {
		return -1
	}
	return sig
}

func (w WaitStatus) CoreDump() bool { return w.Signaled() && w&core != 0 }

func (w WaitStatus) Stopped() bool { return w&mask == stopped && syscall.Signal(w>>shift) != SIGSTOP }

func (w WaitStatus) Killed() bool { return w&mask == killed && syscall.Signal(w>>shift) != SIGKILL }

func (w WaitStatus) Continued() bool { return w&mask == stopped && syscall.Signal(w>>shift) == SIGSTOP }

func (w WaitStatus) StopSignal() syscall.Signal {
	if !w.Stopped() {
		return -1
	}
	return syscall.Signal(w>>shift) & 0xFF
}

func (w WaitStatus) TrapCause() int { return -1 }

//sys	wait4(pid int, wstatus *_C_int, options int, rusage *Rusage) (wpid int, err error)

func Wait4(pid int, wstatus *WaitStatus, options int, rusage *Rusage) (wpid int, err error) {
	var status _C_int
	wpid, err = wait4(pid, &status, options, rusage)
	if wstatus != nil {
		*wstatus = WaitStatus(status)
	}
	return
}

//sys	accept(s int, rsa *RawSockaddrAny, addrlen *_Socklen) (fd int, err error)
//sys	bind(s int, addr unsafe.Pointer, addrlen _Socklen) (err error)
//sys	connect(s int, addr unsafe.Pointer, addrlen _Socklen) (err error)
//sysnb	socket(domain int, typ int, proto int) (fd int, err error)
//sys	getsockopt(s int, level int, name int, val unsafe.Pointer, vallen *_Socklen) (err error)
//sys	setsockopt(s int, level int, name int, val unsafe.Pointer, vallen uintptr) (err error)
//sysnb	getpeername(fd int, rsa *RawSockaddrAny, addrlen *_Socklen) (err error)
//sysnb	getsockname(fd int, rsa *RawSockaddrAny, addrlen *_Socklen) (err error)
//sys	Shutdown(s int, how int) (err error)

func (sa *SockaddrInet4) sockaddr() (unsafe.Pointer, _Socklen, error) {
	if sa.Port < 0 || sa.Port > 0xFFFF {
		return nil, 0, EINVAL
	}
	sa.raw.Len = SizeofSockaddrInet4
	sa.raw.Family = AF_INET
	p := (*[2]byte)(unsafe.Pointer(&sa.raw.Port))
	p[0] = byte(sa.Port >> 8)
	p[1] = byte(sa.Port)
	sa.raw.Addr = sa.Addr
	return unsafe.Pointer(&sa.raw), _Socklen(sa.raw.Len), nil
}

func (sa *SockaddrInet6) sockaddr() (unsafe.Pointer, _Socklen, error) {
	if sa.Port < 0 || sa.Port > 0xFFFF {
		return nil, 0, EINVAL
	}
	sa.raw.Len = SizeofSockaddrInet6
	sa.raw.Family = AF_INET6
	p := (*[2]byte)(unsafe.Pointer(&sa.raw.Port))
	p[0] = byte(sa.Port >> 8)
	p[1] = byte(sa.Port)
	sa.raw.Scope_id = sa.ZoneId
	sa.raw.Addr = sa.Addr
	return unsafe.Pointer(&sa.raw), _Socklen(sa.raw.Len), nil
}

func (sa *SockaddrUnix) sockaddr() (unsafe.Pointer, _Socklen, error) {
	name := sa.Name
	n := len(name)
	if n >= len(sa.raw.Path) || n == 0 {
		return nil, 0, EINVAL
	}
	sa.raw.Len = byte(3 + n) // 2 for Family, Len; 1 for NUL
	sa.raw.Family = AF_UNIX
	for i := 0; i < n; i++ {
		sa.raw.Path[i] = int8(name[i])
	}
	return unsafe.Pointer(&sa.raw), _Socklen(sa.raw.Len), nil
}

func (sa *SockaddrDatalink) sockaddr() (unsafe.Pointer, _Socklen, error) {
	if sa.Index == 0 {
		return nil, 0, EINVAL
	}
	sa.raw.Len = sa.Len
	sa.raw.Family = AF_LINK
	sa.raw.Index = sa.Index
	sa.raw.Type = sa.Type
	sa.raw.Nlen = sa.Nlen
	sa.raw.Alen = sa.Alen
	sa.raw.Slen = sa.Slen
	sa.raw.Data = sa.Data
	return unsafe.Pointer(&sa.raw), SizeofSockaddrDatalink, nil
}

func anyToSockaddr(fd int, rsa *RawSockaddrAny) (Sockaddr, error) {
	switch rsa.Addr.Family {
	case AF_LINK:
		pp := (*RawSockaddrDatalink)(unsafe.Pointer(rsa))
		sa := new(SockaddrDatalink)
		sa.Len = pp.Len
		sa.Family = pp.Family
		sa.Index = pp.Index
		sa.Type = pp.Type
		sa.Nlen = pp.Nlen
		sa.Alen = pp.Alen
		sa.Slen = pp.Slen
		sa.Data = pp.Data
		return sa, nil

	case AF_UNIX:
		pp := (*RawSockaddrUnix)(unsafe.Pointer(rsa))
		if pp.Len < 2 || pp.Len > SizeofSockaddrUnix {
			return nil, EINVAL
		}
		sa := new(SockaddrUnix)

		// Some BSDs include the trailing NUL in the length, whereas
		// others do not. Work around this by subtracting the leading
		// family and len. The path is then scanned to see if a NUL
		// terminator still exists within the length.
		n := int(pp.Len) - 2 // subtract leading Family, Len
		for i := 0; i < n; i++ {
			if pp.Path[i] == 0 {
				// found early NUL; assume Len included the NUL
				// or was overestimating.
				n = i
				break
			}
		}
		sa.Name = string(unsafe.Slice((*byte)(unsafe.Pointer(&pp.Path[0])), n))
		return sa, nil

	case AF_INET:
		pp := (*RawSockaddrInet4)(unsafe.Pointer(rsa))
		sa := new(SockaddrInet4)
		p := (*[2]byte)(unsafe.Pointer(&pp.Port))
		sa.Port = int(p[0])<<8 + int(p[1])
		sa.Addr = pp.Addr
		return sa, nil

	case AF_INET6:
		pp := (*RawSockaddrInet6)(unsafe.Pointer(rsa))
		sa := new(SockaddrInet6)
		p := (*[2]byte)(unsafe.Pointer(&pp.Port))
		sa.Port = int(p[0])<<8 + int(p[1])
		sa.ZoneId = pp.Scope_id
		sa.Addr = pp.Addr
		return sa, nil
	}
	return anyToSockaddrGOOS(fd, rsa)
}

func Accept(fd int) (nfd int, sa Sockaddr, err error) {
	var rsa RawSockaddrAny
	var len _Socklen = SizeofSockaddrAny
	nfd, err = accept(fd, &rsa, &len)
	if err != nil {
		return
	}
	if (runtime.GOOS == "darwin" || runtime.GOOS == "ios") && len == 0 {
		// Accepted socket has no address.
		// This is likely due to a bug in xnu kernels,
		// where instead of ECONNABORTED error socket
		// is accepted, but has no address.
		Close(nfd)
		return 0, nil, ECONNABORTED
	}
	sa, err = anyToSockaddr(fd, &rsa)
	if err != nil {
		Close(nfd)
		nfd = 0
	}
	return
}

func Getsockname(fd int) (sa Sockaddr, err error) {
	var rsa RawSockaddrAny
	var len _Socklen = SizeofSockaddrAny
	if err = getsockname(fd, &rsa, &len); err != nil {
		return
	}
	// TODO(jsing): DragonFly has a "bug" (see issue 3349), which should be
	// reported upstream.
	if runtime.GOOS == "dragonfly" && rsa.Addr.Family == AF_UNSPEC && rsa.Addr.Len == 0 {
		rsa.Addr.Family = AF_UNIX
		rsa.Addr.Len = SizeofSockaddrUnix
	}
	return anyToSockaddr(fd, &rsa)
}

//sysnb	socketpair(domain int, typ int, proto int, fd *[2]int32) (err error)

// GetsockoptString returns the string value of the socket option opt for the
// socket associated with fd at the given socket level.
func GetsockoptString(fd, level, opt int) (string, error) {
	buf := make([]byte, 256)
	vallen := _Socklen(len(buf))
	err := getsockopt(fd, level, opt, unsafe.Pointer(&buf[0]), &vallen)
	if err != nil {
		return "", err
	}
	return ByteSliceToString(buf[:vallen]), nil
}

//sys	recvfrom(fd int, p []byte, flags int, from *RawSockaddrAny, fromlen *_Socklen) (n int, err error)
//sys	sendto(s int, buf []byte, flags int, to unsafe.Pointer, addrlen _Socklen) (err error)
//sys	recvmsg(s int, msg *Msghdr, flags int) (n int, err error)

func recvmsgRaw(fd int, iov []Iovec, oob []byte, flags int, rsa *RawSockaddrAny) (n, oobn int, recvflags int, err error) {
	var msg Msghdr
	msg.Name = (*byte)(unsafe.Pointer(rsa))
	msg.Namelen = uint32(SizeofSockaddrAny)
	var dummy byte
	if len(oob) > 0 {
		// receive at least one normal byte
		if emptyIovecs(iov) {
			var iova [1]Iovec
			iova[0].Base = &dummy
			iova[0].SetLen(1)
			iov = iova[:]
		}
		msg.Control = (*byte)(unsafe.Pointer(&oob[0]))
		msg.SetControllen(len(oob))
	}
	if len(iov) > 0 {
		msg.Iov = &iov[0]
		msg.SetIovlen(len(iov))
	}
	if n, err = recvmsg(fd, &msg, flags); err != nil {
		return
	}
	oobn = int(msg.Controllen)
	recvflags = int(msg.Flags)
	return
}

//sys	sendmsg(s int, msg *Msghdr, flags int) (n int, err error)

func sendmsgN(fd int, iov []Iovec, oob []byte, ptr unsafe.Pointer, salen _Socklen, flags int) (n int, err error) {
	var msg Msghdr
	msg.Name = (*byte)(unsafe.Pointer(ptr))
	msg.Namelen = uint32(salen)
	var dummy byte
	var empty bool
	if len(oob) > 0 {
		// send at least one normal byte
		empty = emptyIovecs(iov)
		if empty {
			var iova [1]Iovec
			iova[0].Base = &dummy
			iova[0].SetLen(1)
			iov = iova[:]
		}
		msg.Control = (*byte)(unsafe.Pointer(&oob[0]))
		msg.SetControllen(len(oob))
	}
	if len(iov) > 0 {
		msg.Iov = &iov[0]
		msg.SetIovlen(len(iov))
	}
	if n, err = sendmsg(fd, &msg, flags); err != nil {
		return 0, err
	}
	if len(oob) > 0 && empty {
		n = 0
	}
	return n, nil
}

//sys	kevent(kq int, change unsafe.Pointer, nchange int, event unsafe.Pointer, nevent int, timeout *Timespec) (n int, err error)

func Kevent(kq int, changes, events []Kevent_t, timeout *Timespec) (n int, err error) {
	var change, event unsafe.Pointer
	if len(changes) > 0 {
		change = unsafe.Pointer(&changes[0])
	}
	if len(events) > 0 {
		event = unsafe.Pointer(&events[0])
	}
	return kevent(kq, change, len(changes), event, len(events), timeout)
}

// sysctlmib translates name to mib number and appends any additional args.
func sysctlmib(name string, args ...int) ([]_C_int, error) {
	// Translate name to mib number.
	mib, err := nametomib(name)
	if err != nil {
		return nil, err
	}

	for _, a := range args {
		mib = append(mib, _C_int(a))
	}

	return mib, nil
}

func Sysctl(name string) (string, error) {
	return SysctlArgs(name)
}

func SysctlArgs(name string, args ...int) (string, error) {
	buf, err := SysctlRaw(name, args...)
	if err != nil {
		return "", err
	}
	n := len(buf)

	// Throw away terminating NUL.
	if n > 0 && buf[n-1] == '\x00' {
		n--
	}
	return string(buf[0:n]), nil
}

func SysctlUint32(name string) (uint32, error) {
	return SysctlUint32Args(name)
}

func SysctlUint32Args(name string, args ...int) (uint32, error) {
	mib, err := sysctlmib(name, args...)
	if err != nil {
		return 0, err
	}

	n := uintptr(4)
	buf := make([]byte, 4)
	if err := sysctl(mib, &buf[0], &n, nil, 0); err != nil {
		return 0, err
	}
	if n != 4 {
		return 0, EIO
	}
	return *(*uint32)(unsafe.Pointer(&buf[0])), nil
}

func SysctlUint64(name string, args ...int) (uint64, error) {
	mib, err := sysctlmib(name, args...)
	if err != nil {
		return 0, err
	}

	n := uintptr(8)
	buf := make([]byte, 8)
	if err := sysctl(mib, &buf[0], &n, nil, 0); err != nil {
		return 0, err
	}
	if n != 8 {
		return 0, EIO
	}
	return *(*uint64)(unsafe.Pointer(&buf[0])), nil
}

func SysctlRaw(name string, args ...int) ([]byte, error) {
	mib, err := sysctlmib(name, args...)
	if err != nil {
		return nil, err
	}

	// Find size.
	n := uintptr(0)
	if err := sysctl(mib, nil, &n, nil, 0); err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}

	// Read into buffer of that size.
	buf := make([]byte, n)
	if err := sysctl(mib, &buf[0], &n, nil, 0); err != nil {
		return nil, err
	}

	// The actual call may return less than the original reported required
	// size so ensure we deal with that.
	return buf[:n], nil
}

func SysctlClockinfo(name string) (*Clockinfo, error) {
	mib, err := sysctlmib(name)
	if err != nil {
		return nil, err
	}

	n := uintptr(SizeofClockinfo)
	var ci Clockinfo
	if err := sysctl(mib, (*byte)(unsafe.Pointer(&ci)), &n, nil, 0); err != nil {
		return nil, err
	}
	if n != SizeofClockinfo {
		return nil, EIO
	}
	return &ci, nil
}

func SysctlTimeval(name string) (*Timeval, error) {
	mib, err := sysctlmib(name)
	if err != nil {
		return nil, err
	}

	var tv Timeval
	n := uintptr(unsafe.Sizeof(tv))
	if err := sysctl(mib, (*byte)(unsafe.Pointer(&tv)), &n, nil, 0); err != nil {
		return nil, err
	}
	if n != unsafe.Sizeof(tv) {
		return nil, EIO
	}
	return &tv, nil
}

//sys	utimes(path string, timeval *[2]Timeval) (err error)

func Utimes(path string, tv []Timeval) error {
	if tv == nil {
		return utimes(path, nil)
	}
	if len(tv) != 2 {
		return EINVAL
	}
	return utimes(path, (*[2]Timeval)(unsafe.Pointer(&tv[0])))
}

func UtimesNano(path string, ts []Timespec) error {
	if ts == nil {
		err := utimensat(AT_FDCWD, path, nil, 0)
		if err != ENOSYS {
			return err
		}
		return utimes(path, nil)
	}
	if len(ts) != 2 {
		return EINVAL
	}
	err := utimensat(AT_FDCWD, path, (*[2]Timespec)(unsafe.Pointer(&ts[0])), 0)
	if err != ENOSYS {
		return err
	}
	// Not as efficient as it could be because Timespec and
	// Timeval have different types in the different OSes
	tv := [2]Timeval{
		NsecToTimeval(TimespecToNsec(ts[0])),
		NsecToTimeval(TimespecToNsec(ts[1])),
	}
	return utimes(path, (*[2]Timeval)(unsafe.Pointer(&tv[0])))
}

func UtimesNanoAt(dirfd int, path string, ts []Timespec, flags int) error {
	if ts == nil {
		return utimensat(dirfd, path, nil, flags)
	}
	if len(ts) != 2 {
		return EINVAL
	}
	return utimensat(dirfd, path, (*[2]Timespec)(unsafe.Pointer(&ts[0])), flags)
}

//sys	futimes(fd int, timeval *[2]Timeval) (err error)

func Futimes(fd int, tv []Timeval) error {
	if tv == nil {
		return futimes(fd, nil)
	}
	if len(tv) != 2 {
		return EINVAL
	}
	return futimes(fd, (*[2]Timeval)(unsafe.Pointer(&tv[0])))
}

//sys	poll(fds *PollFd, nfds int, timeout int) (n int, err error)

func Poll(fds []PollFd, timeout int) (n int, err error) {
	if len(fds) == 0 {
		return poll(nil, 0, timeout)
	}
	return poll(&fds[0], len(fds), timeout)
}

// TODO: wrap
//	Acct(name nil-string) (err error)
//	Gethostuuid(uuid *byte, timeout *Timespec) (err error)
//	Ptrace(req int, pid int, addr uintptr, data int) (ret uintptr, err error)

//sys	Madvise(b []byte, behav int) (err error)
//sys	Mlock(b []byte) (err error)
//sys	Mlockall(flags int) (err error)
//sys	Mprotect(b []byte, prot int) (err error)
//sys	Msync(b []byte, flags int) (err error)
//sys	Munlock(b []byte) (err error)
//sys	Munlockall() (err error)
```