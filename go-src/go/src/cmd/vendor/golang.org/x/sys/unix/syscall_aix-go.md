Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The request asks for the functionality of the given Go code, its purpose within the larger Go ecosystem, examples of its use, handling of command-line arguments (if any), and potential pitfalls for users.

2. **Initial Scan for Clues:**  The first thing to notice is the package declaration: `package unix`. This immediately suggests that the code interacts with the underlying operating system. The `//go:build aix` directive confirms it's specific to AIX. The comments at the beginning mentioning `mksyscall` are a strong indicator that this code defines system call interfaces.

3. **Identify Key Code Sections:**  The code is organized into distinct sections:
    * **Wrapped Functions:** Functions like `Access`, `Chmod`, `Chown`, `Creat` that call other functions (often ending in `at`). This suggests providing higher-level convenience wrappers.
    * **`//sys` Directives:**  These lines are crucial. They are instructions for `mksyscall` to generate the actual system call implementations. Each `//sys` line defines a direct interface to an AIX system call.
    * **Helper Functions/Methods:** Functions like `Utimes`, `UtimesNano`, `sockaddr()` methods, `Getsockname`, `Getwd`, `Getgroups`, `Setgroups`, `Accept`, `recvmsgRaw`, `sendmsgN`, `anyToSockaddr`, `Gettimeofday`, `Sendfile`, `direntIno`, `direntReclen`, `direntNamlen`, `Getdents`, `Wait4`, and the `WaitStatus` type. These provide more elaborate functionality, often building upon the direct system calls or handling data structure conversions.
    * **Direct Access System Calls:** A large block of `//sys` lines without wrapper functions. This indicates direct exposure of many AIX system calls.
    * **Utility Functions:**  `Pipe`, `Poll`, `Unmount`.

4. **Analyze Each Section in Detail:**

    * **Wrapped Functions:**  These are relatively straightforward. They abstract away the need to use `AT_FDCWD` and simplify common file system operations.

    * **`//sys` Directives:**  Recognize that these are *declarations*, not implementations. `mksyscall` is the tool that will generate the actual low-level code. The comments are important for understanding the mapping between the Go function name and the underlying system call.

    * **Helper Functions/Methods:** This is where the core logic resides. For example:
        * **`Utimes` family:** Handle the `Timeval` and `Timespec` structures, ensuring the input slice has the correct length.
        * **`sockaddr()` methods:**  Demonstrate how Go structures are marshaled into the C-style `sockaddr` structures required for network calls. The byte manipulation for port numbers is a key detail.
        * **`Getsockname`:**  Shows the pattern of calling the underlying syscall and then converting the raw socket address to a more usable Go type.
        * **`Getwd`:**  Illustrates dynamic buffer allocation when the required buffer size isn't known beforehand.
        * **`Accept`:**  Another common pattern: call the syscall, handle errors, and potentially perform cleanup (`Close` if `anyToSockaddr` fails).
        * **`recvmsgRaw` and `sendmsgN`:** These handle the more complex `msghdr` structure used for advanced socket communication.
        * **`anyToSockaddr`:** Crucial for converting the raw C socket address structures back into Go-friendly `Sockaddr` interfaces. The special handling for `AF_UNIX` on AIX is noteworthy.
        * **`Wait4`:** Shows a loop to handle `ERESTART`, a common pattern when dealing with signal handling and system calls.
        * **`WaitStatus`:**  Provides methods for interpreting the integer status returned by `wait` family calls.

    * **Direct Access System Calls:**  These are a direct mapping to AIX system calls. Their names are usually lowercase in the `//sys` directive.

    * **Utility Functions:**  These are thin wrappers around their corresponding system calls, often doing some basic error checking or data structure conversion.

5. **Infer the Go Feature:**  Based on the `package unix` and the direct interaction with system calls, the core feature is **system call access**. This package provides the low-level building blocks for interacting with the AIX operating system kernel. It's fundamental for tasks like file I/O, networking, process management, etc.

6. **Construct Examples:**  Choose a few representative functions to illustrate their usage. Good candidates are `Access`, `Getwd`, `Open`, `Wait4`, and socket-related functions like `socket`, `bind`, and `listen`. Provide basic but functional examples showing how to call these functions and handle potential errors. *Initially, I might just think of simple file operations, but realizing the networking aspect is also prominent leads to including socket examples.*

7. **Consider Command-Line Arguments:** Review the functions. None of them directly process command-line arguments. They operate on files, paths, file descriptors, etc., which are often *derived* from command-line arguments but not handled directly by these functions.

8. **Identify Potential Pitfalls:** Think about common errors when working with system calls:
    * **Incorrect error handling:** Emphasize checking the `err` return value.
    * **Incorrect data structure sizes or types:** Highlight the use of `unsafe.Pointer` and the need for correct marshaling, especially with socket addresses.
    * **Resource leaks:**  Mention the importance of closing file descriptors.
    * **Platform-specific behavior:** Note that this code is for AIX, and using it on other operating systems will lead to problems. The AIX-specific workaround in `anyToSockaddr` is a good example of this.
    * **Incorrect usage of `Utimes` family:** The need for a slice of length 2 is a specific constraint to highlight.

9. **Review and Refine:** Read through the generated explanation. Ensure it's clear, concise, and accurate. Check for any inconsistencies or missing information. For instance, initially, I might focus heavily on file operations, but a second pass would remind me of the networking functionality and the importance of `sockaddr` handling. Also, double-check the `mksyscall` aspect to explain its role correctly. Make sure the examples compile and demonstrate the intended functionality. Ensure the pitfalls section is practical and addresses likely user mistakes.
这份代码是 Go 语言标准库中 `syscall` 包的一部分，专门针对 AIX 操作系统。它提供了 Go 程序与 AIX 系统内核进行交互的底层接口，也就是**系统调用 (system calls)**。

以下是它的主要功能：

**1. 提供 AIX 特定的系统调用接口:**

   - 代码中包含了大量的 `//sys` 注释，这些注释是 `mksyscall` 工具的指令。`mksyscall` 会解析这些注释，并根据它们生成与 AIX 系统调用对应的 Go 函数的底层实现（通常是汇编代码）。
   - 这些 `//sys` 行定义了 Go 语言如何调用 AIX 内核提供的各种功能，例如文件操作、进程管理、网络通信等。
   - 例如，`//sys	open(path string, mode int, perm uint32) (fd int, err error) = open64`  声明了 Go 函数 `Open`，它对应 AIX 的 `open64` 系统调用。

**2. 封装和简化常用的系统调用:**

   - 代码中定义了一些辅助函数，它们是对底层系统调用的封装，提供了更方便易用的接口。
   - **文件操作相关的封装:**
     - `Access`, `Chmod`, `Chown`, `Creat` 等函数是对 `Faccessat`, `Fchmodat`, `Fchownat`, `Open` 等带 `at` 后缀的系统调用的封装，默认使用当前工作目录 (`AT_FDCWD`)。
     - `Utimes` 和 `UtimesNano` 系列函数封装了 `utimes` 和 `utimensat`，用于修改文件的时间戳。
   - **网络操作相关的封装:**
     - `Accept` 函数封装了底层的 `accept` 系统调用，并负责将原始的套接字地址转换为 Go 的 `Sockaddr` 类型。
     - `Getsockname` 函数获取套接字的本地地址。
     - `recvmsgRaw` 和 `sendmsgN` 是对 `recvmsg` 和 `sendmsg` 的辅助函数，用于处理更复杂的网络消息，包括带外数据。
     - `anyToSockaddr` 函数将原始的套接字地址结构 (`RawSockaddrAny`) 转换为 Go 的 `Sockaddr` 接口，支持 IPv4、IPv6 和 Unix 域套接字。
   - **目录操作相关的封装:**
     - `Getdents` 函数封装了 `getdirent` 系统调用，用于读取目录项。
   - **进程管理相关的封装:**
     - `Wait4` 函数封装了 `wait4` 系统调用，用于等待子进程结束。

**3. 提供 Go 特有的功能实现，底层依赖系统调用:**

   - **获取当前工作目录:** `Getwd` 函数通过循环分配更大的缓冲区并调用 `getcwd` 系统调用来获取当前工作目录的完整路径。
   - **获取和设置进程组 ID:** `Getgroups` 和 `Setgroups` 函数分别调用 `getgroups` 和 `setgroups` 系统调用。
   - **创建管道:** `Pipe` 函数封装了 `pipe` 系统调用。
   - **多路复用 I/O:** `Poll` 函数封装了 `poll` 系统调用。
   - **非标准但常用的功能:** `Sendfile` 函数尝试实现高效的文件发送，但在 AIX 上，该实现返回 `ENOSYS` (功能未实现)。

**可以推理出它是什么 Go 语言功能的实现：**

基于以上分析，这份代码是 Go 语言中 **`syscall` 标准库** 在 **AIX 操作系统** 上的具体实现。 `syscall` 包是 Go 语言提供访问操作系统底层接口的核心包，允许 Go 程序执行诸如文件操作、进程控制、网络通信等需要与操作系统内核交互的任务。

**Go 代码举例说明:**

以下是一些使用该文件中定义的功能的 Go 代码示例：

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	// 使用 Access 检查文件权限
	err := syscall.Access("test.txt", syscall.R_OK)
	if err == nil {
		fmt.Println("test.txt 可读")
	} else {
		fmt.Println("test.txt 不可读:", err)
	}

	// 使用 Getwd 获取当前工作目录
	wd, err := syscall.Getwd()
	if err == nil {
		fmt.Println("当前工作目录:", wd)
	} else {
		fmt.Println("获取工作目录失败:", err)
	}

	// 使用 Open 创建文件
	fd, err := syscall.Open("newfile.txt", syscall.O_CREAT|syscall.O_WRONLY|syscall.O_TRUNC, 0644)
	if err == nil {
		fmt.Println("成功创建文件 newfile.txt, 文件描述符:", fd)
		syscall.Close(fd) // 关闭文件
	} else {
		fmt.Println("创建文件失败:", err)
	}

	// 使用 Socket 创建一个 TCP socket
	sockfd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err == nil {
		fmt.Println("成功创建 socket, 文件描述符:", sockfd)
		defer syscall.Close(sockfd)

		// 绑定地址和端口
		addr := syscall.SockaddrInet4{Port: 8080}
		copy(addr.Addr[:], []byte{127, 0, 0, 1}) // 绑定到 127.0.0.1:8080
		rawAddr, _, _ := addr.Sockaddr()
		err = syscall.Bind(sockfd, rawAddr, syscall.SizeofSockaddrInet4)
		if err != nil {
			fmt.Println("绑定地址失败:", err)
		} else {
			fmt.Println("成功绑定到 127.0.0.1:8080")
		}

		// 监听端口
		err = syscall.Listen(sockfd, 5)
		if err != nil {
			fmt.Println("监听失败:", err)
		} else {
			fmt.Println("开始监听...")
		}
	} else {
		fmt.Println("创建 socket 失败:", err)
	}
}
```

**假设的输入与输出 (以 `Getwd` 为例):**

**假设输入:** 当前工作目录为 `/home/user/project`

**输出:**
```
当前工作目录: /home/user/project
```

**代码推理 (以 `UtimesNano` 为例):**

`UtimesNano` 函数用于修改文件的访问和修改时间，精度为纳秒。

```go
func UtimesNano(path string, ts []Timespec) error {
	if len(ts) != 2 {
		return EINVAL
	}
	return utimensat(AT_FDCWD, path, (*[2]Timespec)(unsafe.Pointer(&ts[0])), 0)
}
```

**推理:**

1. **输入校验:** 函数首先检查传入的 `ts` 切片的长度是否为 2。`ts[0]` 代表访问时间，`ts[1]` 代表修改时间。如果长度不是 2，则返回 `syscall.EINVAL` 错误。
2. **类型转换:** 使用 `unsafe.Pointer` 将 `ts` 切片的第一个元素的地址转换为 `*[2]Timespec` 类型的指针。这是因为底层的 `utimensat` 系统调用期望接收一个指向 `Timespec` 结构体数组的指针。
3. **系统调用:** 调用底层的 `utimensat` 系统调用，其中：
   - `AT_FDCWD` 表示操作的是当前工作目录下的文件。
   - `path` 是要修改时间戳的文件路径。
   - `(*[2]Timespec)(unsafe.Pointer(&ts[0]))` 是指向时间戳数组的指针。
   - `0` 是标志位，通常为 0。

**假设输入:**

```go
package main

import (
	"fmt"
	"syscall"
	"time"
)

func main() {
	filename := "test_utimes.txt"
	// 假设文件 test_utimes.txt 存在

	// 获取当前时间
	now := time.Now()
	nsec := now.UnixNano()

	// 构建 Timespec 数组
	ts := []syscall.Timespec{
		{Sec: nsec / 1e9, Nsec: nsec % 1e9}, // 访问时间
		{Sec: nsec / 1e9, Nsec: nsec % 1e9}, // 修改时间
	}

	// 修改文件时间戳
	err := syscall.UtimesNano(filename, ts)
	if err != nil {
		fmt.Println("修改时间戳失败:", err)
	} else {
		fmt.Println("成功修改文件", filename, "的时间戳为当前时间")
	}
}
```

**输出:**  (假设 `test_utimes.txt` 存在且操作成功)

```
成功修改文件 test_utimes.txt 的时间戳为当前时间
```

**命令行参数的具体处理:**

这份代码本身并不直接处理命令行参数。命令行参数的处理通常发生在 `main` 函数中，然后将相关的文件路径、权限模式等信息传递给这里的系统调用封装函数。

例如，如果有一个程序需要修改文件的权限，它可能会这样处理命令行参数：

```go
package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("用法: chmod <mode> <file>")
		return
	}

	modeStr := os.Args[1]
	filename := os.Args[2]

	mode, err := strconv.ParseUint(modeStr, 8, 32) // 将八进制字符串转换为 uint32
	if err != nil {
		fmt.Println("无效的权限模式:", err)
		return
	}

	err = syscall.Chmod(filename, uint32(mode)) // 调用 syscall.Chmod
	if err != nil {
		fmt.Println("修改权限失败:", err)
	} else {
		fmt.Println("成功修改", filename, "的权限为", modeStr)
	}
}
```

在这个例子中，`main` 函数解析命令行参数 `mode` 和 `file`，并将它们传递给 `syscall.Chmod` 函数。

**使用者易犯错的点:**

1. **错误处理不当:**  几乎所有的系统调用都可能返回错误。使用者必须检查 `err` 返回值，并进行适当的处理。忽略错误可能导致程序行为异常甚至崩溃。

   ```go
   fd, err := syscall.Open("nonexistent.txt", syscall.O_RDONLY, 0)
   // 容易犯错：忽略 err
   if fd != -1 { // 即使 Open 失败，fd 的值也可能是 -1，但没有检查 err
       // ... 使用 fd ...
       syscall.Close(fd) // 如果 Open 失败，这里会尝试关闭一个无效的文件描述符
   }

   // 正确的做法：
   fd, err = syscall.Open("nonexistent.txt", syscall.O_RDONLY, 0)
   if err != nil {
       fmt.Println("打开文件失败:", err)
       return
   }
   defer syscall.Close(fd)
   // ... 使用 fd ...
   ```

2. **不理解 `unsafe.Pointer` 的使用:**  很多系统调用需要传递指针，例如 `Utimes` 系列函数和网络相关的函数。使用者需要正确地使用 `unsafe.Pointer` 进行类型转换，否则可能导致内存错误。

   ```go
   // 错误示例：尝试直接传递切片
   ts := []syscall.Timespec{{}, {}}
   // syscall.utimensat(syscall.AT_FDCWD, "file.txt", &ts[0], 0) // 编译错误，类型不匹配

   // 正确示例：使用 unsafe.Pointer
   ts := []syscall.Timespec{{}, {}}
   syscall.Utimensat(syscall.AT_FDCWD, "file.txt", (*[2]syscall.Timespec)(unsafe.Pointer(&ts[0])), 0)
   ```

3. **文件描述符泄漏:**  打开的文件、socket 等资源需要在使用完毕后显式关闭。忘记关闭会导致资源泄漏，最终可能耗尽系统资源。

   ```go
   fd, err := syscall.Open("temp.txt", syscall.O_RDWR|syscall.O_CREAT|syscall.O_TRUNC, 0644)
   if err != nil {
       // ... 错误处理 ...
   }
   // 容易犯错：忘记 syscall.Close(fd)

   // 正确的做法：使用 defer 确保关闭
   fd, err = syscall.Open("temp.txt", syscall.O_RDWR|syscall.O_CREAT|syscall.O_TRUNC, 0644)
   if err != nil {
       // ... 错误处理 ...
       return
   }
   defer syscall.Close(fd)
   // ... 使用 fd ...
   ```

4. **网络编程中的地址结构错误:**  在网络编程中，需要正确地构建 `SockaddrInet4`、`SockaddrInet6`、`SockaddrUnix` 等结构体，并使用 `Sockaddr()` 方法获取底层的 `unsafe.Pointer` 和长度。错误的地址结构会导致连接失败或其他网络错误。

   ```go
   // 错误示例：端口号赋值错误
   addr := syscall.SockaddrInet4{Port: 80} // 应该使用大端字节序
   // ... syscall.Bind(sockfd, unsafe.Pointer(&addr), ...)

   // 正确示例：使用 sockaddr() 方法
   addr := syscall.SockaddrInet4{Port: 80}
   rawAddr, _, err := addr.Sockaddr()
   if err != nil {
       // ... 错误处理 ...
   }
   syscall.Bind(sockfd, rawAddr, syscall.SizeofSockaddrInet4)
   ```

5. **平台差异:**  这份代码是 AIX 特定的。直接在其他操作系统上编译或运行使用这些系统调用的 Go 代码将会失败或产生不可预测的行为。应该使用 `go:build aix` 这样的构建约束来限制代码在特定平台上的编译。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/syscall_aix.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build aix

// Aix system calls.
// This file is compiled as ordinary Go code,
// but it is also input to mksyscall,
// which parses the //sys lines and generates system call stubs.
// Note that sometimes we use a lowercase //sys name and
// wrap it in our own nicer implementation.

package unix

import "unsafe"

/*
 * Wrapped
 */

func Access(path string, mode uint32) (err error) {
	return Faccessat(AT_FDCWD, path, mode, 0)
}

func Chmod(path string, mode uint32) (err error) {
	return Fchmodat(AT_FDCWD, path, mode, 0)
}

func Chown(path string, uid int, gid int) (err error) {
	return Fchownat(AT_FDCWD, path, uid, gid, 0)
}

func Creat(path string, mode uint32) (fd int, err error) {
	return Open(path, O_CREAT|O_WRONLY|O_TRUNC, mode)
}

//sys	utimes(path string, times *[2]Timeval) (err error)

func Utimes(path string, tv []Timeval) error {
	if len(tv) != 2 {
		return EINVAL
	}
	return utimes(path, (*[2]Timeval)(unsafe.Pointer(&tv[0])))
}

//sys	utimensat(dirfd int, path string, times *[2]Timespec, flag int) (err error)

func UtimesNano(path string, ts []Timespec) error {
	if len(ts) != 2 {
		return EINVAL
	}
	return utimensat(AT_FDCWD, path, (*[2]Timespec)(unsafe.Pointer(&ts[0])), 0)
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

func (sa *SockaddrInet4) sockaddr() (unsafe.Pointer, _Socklen, error) {
	if sa.Port < 0 || sa.Port > 0xFFFF {
		return nil, 0, EINVAL
	}
	sa.raw.Family = AF_INET
	p := (*[2]byte)(unsafe.Pointer(&sa.raw.Port))
	p[0] = byte(sa.Port >> 8)
	p[1] = byte(sa.Port)
	sa.raw.Addr = sa.Addr
	return unsafe.Pointer(&sa.raw), SizeofSockaddrInet4, nil
}

func (sa *SockaddrInet6) sockaddr() (unsafe.Pointer, _Socklen, error) {
	if sa.Port < 0 || sa.Port > 0xFFFF {
		return nil, 0, EINVAL
	}
	sa.raw.Family = AF_INET6
	p := (*[2]byte)(unsafe.Pointer(&sa.raw.Port))
	p[0] = byte(sa.Port >> 8)
	p[1] = byte(sa.Port)
	sa.raw.Scope_id = sa.ZoneId
	sa.raw.Addr = sa.Addr
	return unsafe.Pointer(&sa.raw), SizeofSockaddrInet6, nil
}

func (sa *SockaddrUnix) sockaddr() (unsafe.Pointer, _Socklen, error) {
	name := sa.Name
	n := len(name)
	if n > len(sa.raw.Path) {
		return nil, 0, EINVAL
	}
	if n == len(sa.raw.Path) && name[0] != '@' {
		return nil, 0, EINVAL
	}
	sa.raw.Family = AF_UNIX
	for i := 0; i < n; i++ {
		sa.raw.Path[i] = uint8(name[i])
	}
	// length is family (uint16), name, NUL.
	sl := _Socklen(2)
	if n > 0 {
		sl += _Socklen(n) + 1
	}
	if sa.raw.Path[0] == '@' || (sa.raw.Path[0] == 0 && sl > 3) {
		// Check sl > 3 so we don't change unnamed socket behavior.
		sa.raw.Path[0] = 0
		// Don't count trailing NUL for abstract address.
		sl--
	}

	return unsafe.Pointer(&sa.raw), sl, nil
}

func Getsockname(fd int) (sa Sockaddr, err error) {
	var rsa RawSockaddrAny
	var len _Socklen = SizeofSockaddrAny
	if err = getsockname(fd, &rsa, &len); err != nil {
		return
	}
	return anyToSockaddr(fd, &rsa)
}

//sys	getcwd(buf []byte) (err error)

const ImplementsGetwd = true

func Getwd() (ret string, err error) {
	for len := uint64(4096); ; len *= 2 {
		b := make([]byte, len)
		err := getcwd(b)
		if err == nil {
			i := 0
			for b[i] != 0 {
				i++
			}
			return string(b[0:i]), nil
		}
		if err != ERANGE {
			return "", err
		}
	}
}

func Getcwd(buf []byte) (n int, err error) {
	err = getcwd(buf)
	if err == nil {
		i := 0
		for buf[i] != 0 {
			i++
		}
		n = i + 1
	}
	return
}

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

/*
 * Socket
 */

//sys	accept(s int, rsa *RawSockaddrAny, addrlen *_Socklen) (fd int, err error)

func Accept(fd int) (nfd int, sa Sockaddr, err error) {
	var rsa RawSockaddrAny
	var len _Socklen = SizeofSockaddrAny
	nfd, err = accept(fd, &rsa, &len)
	if nfd == -1 {
		return
	}
	sa, err = anyToSockaddr(fd, &rsa)
	if err != nil {
		Close(nfd)
		nfd = 0
	}
	return
}

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
	if n, err = recvmsg(fd, &msg, flags); n == -1 {
		return
	}
	oobn = int(msg.Controllen)
	recvflags = int(msg.Flags)
	return
}

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

func anyToSockaddr(fd int, rsa *RawSockaddrAny) (Sockaddr, error) {
	switch rsa.Addr.Family {

	case AF_UNIX:
		pp := (*RawSockaddrUnix)(unsafe.Pointer(rsa))
		sa := new(SockaddrUnix)

		// Some versions of AIX have a bug in getsockname (see IV78655).
		// We can't rely on sa.Len being set correctly.
		n := SizeofSockaddrUnix - 3 // subtract leading Family, Len, terminating NUL.
		for i := 0; i < n; i++ {
			if pp.Path[i] == 0 {
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
	return nil, EAFNOSUPPORT
}

func Gettimeofday(tv *Timeval) (err error) {
	err = gettimeofday(tv, nil)
	return
}

func Sendfile(outfd int, infd int, offset *int64, count int) (written int, err error) {
	if raceenabled {
		raceReleaseMerge(unsafe.Pointer(&ioSync))
	}
	return sendfile(outfd, infd, offset, count)
}

// TODO
func sendfile(outfd int, infd int, offset *int64, count int) (written int, err error) {
	return -1, ENOSYS
}

func direntIno(buf []byte) (uint64, bool) {
	return readInt(buf, unsafe.Offsetof(Dirent{}.Ino), unsafe.Sizeof(Dirent{}.Ino))
}

func direntReclen(buf []byte) (uint64, bool) {
	return readInt(buf, unsafe.Offsetof(Dirent{}.Reclen), unsafe.Sizeof(Dirent{}.Reclen))
}

func direntNamlen(buf []byte) (uint64, bool) {
	reclen, ok := direntReclen(buf)
	if !ok {
		return 0, false
	}
	return reclen - uint64(unsafe.Offsetof(Dirent{}.Name)), true
}

//sys	getdirent(fd int, buf []byte) (n int, err error)

func Getdents(fd int, buf []byte) (n int, err error) {
	return getdirent(fd, buf)
}

//sys	wait4(pid Pid_t, status *_C_int, options int, rusage *Rusage) (wpid Pid_t, err error)

func Wait4(pid int, wstatus *WaitStatus, options int, rusage *Rusage) (wpid int, err error) {
	var status _C_int
	var r Pid_t
	err = ERESTART
	// AIX wait4 may return with ERESTART errno, while the process is still
	// active.
	for err == ERESTART {
		r, err = wait4(Pid_t(pid), &status, options, rusage)
	}
	wpid = int(r)
	if wstatus != nil {
		*wstatus = WaitStatus(status)
	}
	return
}

/*
 * Wait
 */

type WaitStatus uint32

func (w WaitStatus) Stopped() bool { return w&0x40 != 0 }
func (w WaitStatus) StopSignal() Signal {
	if !w.Stopped() {
		return -1
	}
	return Signal(w>>8) & 0xFF
}

func (w WaitStatus) Exited() bool { return w&0xFF == 0 }
func (w WaitStatus) ExitStatus() int {
	if !w.Exited() {
		return -1
	}
	return int((w >> 8) & 0xFF)
}

func (w WaitStatus) Signaled() bool { return w&0x40 == 0 && w&0xFF != 0 }
func (w WaitStatus) Signal() Signal {
	if !w.Signaled() {
		return -1
	}
	return Signal(w>>16) & 0xFF
}

func (w WaitStatus) Continued() bool { return w&0x01000000 != 0 }

func (w WaitStatus) CoreDump() bool { return w&0x80 == 0x80 }

func (w WaitStatus) TrapCause() int { return -1 }

//sys	ioctl(fd int, req int, arg uintptr) (err error)
//sys	ioctlPtr(fd int, req int, arg unsafe.Pointer) (err error) = ioctl

// fcntl must never be called with cmd=F_DUP2FD because it doesn't work on AIX
// There is no way to create a custom fcntl and to keep //sys fcntl easily,
// Therefore, the programmer must call dup2 instead of fcntl in this case.

// FcntlInt performs a fcntl syscall on fd with the provided command and argument.
//sys	FcntlInt(fd uintptr, cmd int, arg int) (r int,err error) = fcntl

// FcntlFlock performs a fcntl syscall for the F_GETLK, F_SETLK or F_SETLKW command.
//sys	FcntlFlock(fd uintptr, cmd int, lk *Flock_t) (err error) = fcntl

//sys	fcntl(fd int, cmd int, arg int) (val int, err error)

//sys	fsyncRange(fd int, how int, start int64, length int64) (err error) = fsync_range

func Fsync(fd int) error {
	return fsyncRange(fd, O_SYNC, 0, 0)
}

/*
 * Direct access
 */

//sys	Acct(path string) (err error)
//sys	Chdir(path string) (err error)
//sys	Chroot(path string) (err error)
//sys	Close(fd int) (err error)
//sys	Dup(oldfd int) (fd int, err error)
//sys	Exit(code int)
//sys	Faccessat(dirfd int, path string, mode uint32, flags int) (err error)
//sys	Fchdir(fd int) (err error)
//sys	Fchmod(fd int, mode uint32) (err error)
//sys	Fchmodat(dirfd int, path string, mode uint32, flags int) (err error)
//sys	Fchownat(dirfd int, path string, uid int, gid int, flags int) (err error)
//sys	Fdatasync(fd int) (err error)
// readdir_r
//sysnb	Getpgid(pid int) (pgid int, err error)

//sys	Getpgrp() (pid int)

//sysnb	Getpid() (pid int)
//sysnb	Getppid() (ppid int)
//sys	Getpriority(which int, who int) (prio int, err error)
//sysnb	Getrusage(who int, rusage *Rusage) (err error)
//sysnb	Getsid(pid int) (sid int, err error)
//sysnb	Kill(pid int, sig Signal) (err error)
//sys	Klogctl(typ int, buf []byte) (n int, err error) = syslog
//sys	Mkdir(dirfd int, path string, mode uint32) (err error)
//sys	Mkdirat(dirfd int, path string, mode uint32) (err error)
//sys	Mkfifo(path string, mode uint32) (err error)
//sys	Mknod(path string, mode uint32, dev int) (err error)
//sys	Mknodat(dirfd int, path string, mode uint32, dev int) (err error)
//sys	Nanosleep(time *Timespec, leftover *Timespec) (err error)
//sys	Open(path string, mode int, perm uint32) (fd int, err error) = open64
//sys	Openat(dirfd int, path string, flags int, mode uint32) (fd int, err error)
//sys	read(fd int, p []byte) (n int, err error)
//sys	Readlink(path string, buf []byte) (n int, err error)
//sys	Renameat(olddirfd int, oldpath string, newdirfd int, newpath string) (err error)
//sys	Setdomainname(p []byte) (err error)
//sys	Sethostname(p []byte) (err error)
//sysnb	Setpgid(pid int, pgid int) (err error)
//sysnb	Setsid() (pid int, err error)
//sysnb	Settimeofday(tv *Timeval) (err error)

//sys	Setuid(uid int) (err error)
//sys	Setgid(uid int) (err error)

//sys	Setpriority(which int, who int, prio int) (err error)
//sys	Statx(dirfd int, path string, flags int, mask int, stat *Statx_t) (err error)
//sys	Sync()
//sysnb	Times(tms *Tms) (ticks uintptr, err error)
//sysnb	Umask(mask int) (oldmask int)
//sysnb	Uname(buf *Utsname) (err error)
//sys	Unlink(path string) (err error)
//sys	Unlinkat(dirfd int, path string, flags int) (err error)
//sys	Ustat(dev int, ubuf *Ustat_t) (err error)
//sys	write(fd int, p []byte) (n int, err error)

//sys	Dup2(oldfd int, newfd int) (err error)
//sys	Fadvise(fd int, offset int64, length int64, advice int) (err error) = posix_fadvise64
//sys	Fchown(fd int, uid int, gid int) (err error)
//sys	fstat(fd int, stat *Stat_t) (err error)
//sys	fstatat(dirfd int, path string, stat *Stat_t, flags int) (err error) = fstatat
//sys	Fstatfs(fd int, buf *Statfs_t) (err error)
//sys	Ftruncate(fd int, length int64) (err error)
//sysnb	Getegid() (egid int)
//sysnb	Geteuid() (euid int)
//sysnb	Getgid() (gid int)
//sysnb	Getuid() (uid int)
//sys	Lchown(path string, uid int, gid int) (err error)
//sys	Listen(s int, n int) (err error)
//sys	lstat(path string, stat *Stat_t) (err error)
//sys	Pause() (err error)
//sys	pread(fd int, p []byte, offset int64) (n int, err error) = pread64
//sys	pwrite(fd int, p []byte, offset int64) (n int, err error) = pwrite64
//sys	Select(nfd int, r *FdSet, w *FdSet, e *FdSet, timeout *Timeval) (n int, err error)
//sys	Pselect(nfd int, r *FdSet, w *FdSet, e *FdSet, timeout *Timespec, sigmask *Sigset_t) (n int, err error)
//sysnb	Setregid(rgid int, egid int) (err error)
//sysnb	Setreuid(ruid int, euid int) (err error)
//sys	Shutdown(fd int, how int) (err error)
//sys	Splice(rfd int, roff *int64, wfd int, woff *int64, len int, flags int) (n int64, err error)
//sys	stat(path string, statptr *Stat_t) (err error)
//sys	Statfs(path string, buf *Statfs_t) (err error)
//sys	Truncate(path string, length int64) (err error)

//sys	bind(s int, addr unsafe.Pointer, addrlen _Socklen) (err error)
//sys	connect(s int, addr unsafe.Pointer, addrlen _Socklen) (err error)
//sysnb	getgroups(n int, list *_Gid_t) (nn int, err error)
//sysnb	setgroups(n int, list *_Gid_t) (err error)
//sys	getsockopt(s int, level int, name int, val unsafe.Pointer, vallen *_Socklen) (err error)
//sys	setsockopt(s int, level int, name int, val unsafe.Pointer, vallen uintptr) (err error)
//sysnb	socket(domain int, typ int, proto int) (fd int, err error)
//sysnb	socketpair(domain int, typ int, proto int, fd *[2]int32) (err error)
//sysnb	getpeername(fd int, rsa *RawSockaddrAny, addrlen *_Socklen) (err error)
//sysnb	getsockname(fd int, rsa *RawSockaddrAny, addrlen *_Socklen) (err error)
//sys	recvfrom(fd int, p []byte, flags int, from *RawSockaddrAny, fromlen *_Socklen) (n int, err error)
//sys	sendto(s int, buf []byte, flags int, to unsafe.Pointer, addrlen _Socklen) (err error)

// In order to use msghdr structure with Control, Controllen, nrecvmsg and nsendmsg must be used.
//sys	recvmsg(s int, msg *Msghdr, flags int) (n int, err error) = nrecvmsg
//sys	sendmsg(s int, msg *Msghdr, flags int) (n int, err error) = nsendmsg

//sys	munmap(addr uintptr, length uintptr) (err error)
//sys	Madvise(b []byte, advice int) (err error)
//sys	Mprotect(b []byte, prot int) (err error)
//sys	Mlock(b []byte) (err error)
//sys	Mlockall(flags int) (err error)
//sys	Msync(b []byte, flags int) (err error)
//sys	Munlock(b []byte) (err error)
//sys	Munlockall() (err error)

//sysnb	pipe(p *[2]_C_int) (err error)

func Pipe(p []int) (err error) {
	if len(p) != 2 {
		return EINVAL
	}
	var pp [2]_C_int
	err = pipe(&pp)
	if err == nil {
		p[0] = int(pp[0])
		p[1] = int(pp[1])
	}
	return
}

//sys	poll(fds *PollFd, nfds int, timeout int) (n int, err error)

func Poll(fds []PollFd, timeout int) (n int, err error) {
	if len(fds) == 0 {
		return poll(nil, 0, timeout)
	}
	return poll(&fds[0], len(fds), timeout)
}

//sys	gettimeofday(tv *Timeval, tzp *Timezone) (err error)
//sysnb	Time(t *Time_t) (tt Time_t, err error)
//sys	Utime(path string, buf *Utimbuf) (err error)

//sys	Getsystemcfg(label int) (n uint64)

//sys	umount(target string) (err error)

func Unmount(target string, flags int) (err error) {
	if flags != 0 {
		// AIX doesn't have any flags for umount.
		return ENOSYS
	}
	return umount(target)
}

"""



```