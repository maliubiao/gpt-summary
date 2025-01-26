Response:
Let's break down the thought process for analyzing the provided Go code.

**1. Initial Scan and Keyword Spotting:**

The first step is a quick scan to identify key elements and common patterns in Go code. I'm looking for:

* **Package declaration:** `package os` -  This tells me the context of the code. It's part of the standard `os` package, which deals with operating system functionalities.
* **Imports:**  `internal/poll`, `internal/syscall/unix`, `io/fs`, `runtime`, `sync/atomic`, `syscall`, `unsafe` - These indicate dependencies on lower-level functionalities (system calls, runtime aspects, etc.).
* **Function declarations:**  `rename`, `fixLongPath`, `Fd`, `NewFile`, `net_newUnixFile`, `newFile`, `sigpipe`, `epipecheck`, `openFileNolog`, `openDirNolog`, `close`, `seek`, `Truncate`, `Remove`, `tempDir`, `Link`, `Symlink`, `readlink`, and the `unixDirent` struct and its methods. These are the primary units of work.
* **Struct definitions:** `file`, `unixDirent` - These represent data structures used within the code. The `file` struct looks particularly important as it's related to file handling.
* **Constants:** `_UTIME_OMIT`, `DevNull`, various `newFileKind` constants.
* **Comments:**  These provide hints about the purpose of the code. Pay attention to explanations of specific functionalities or historical context.
* **Error handling patterns:** Checking `err != nil` is common, and the use of `*PathError` and `*LinkError` suggests specific error types.
* **System call invocations:**  Functions like `syscall.Rename`, `syscall.Fcntl`, `syscall.SetNonblock`, `syscall.Close`, `syscall.Seek`, `syscall.Truncate`, `syscall.Unlink`, `syscall.Rmdir`, `syscall.Link`, `syscall.Symlink`, `syscall.Readlink`, `syscall.Fstat`, `syscall.Open`. This strongly suggests interaction with the operating system's kernel.
* **Concurrency-related elements:** `sync/atomic`.

**2. Grouping by Functionality:**

Now I start to group the identified functions based on their apparent purpose. This helps to organize the analysis:

* **File Operations:**  `rename`, `Fd`, `NewFile`, `net_newUnixFile`, `newFile`, `close`, `seek`, `Truncate`, `openFileNolog`, `openDirNolog`. These functions seem to be core to interacting with files and directories.
* **File Information:** The `unixDirent` struct and its methods (`Name`, `IsDir`, `Type`, `Info`, `String`) are clearly related to retrieving information about directory entries.
* **Path Manipulation:** `fixLongPath` (though it's a no-op here, the name suggests it's related to handling file paths), `tempDir`.
* **Linking:** `Link`, `Symlink`, `readlink`.
* **Error Handling/Signals:** `epipecheck`, `sigpipe`.
* **Removal:** `Remove`.

**3. Deep Dive into Key Functions (and Structs):**

I select the most prominent functions and structs for a more detailed examination.

* **`file` struct:** This is central to file representation. I note the fields: `pfd` (likely a poll file descriptor), `name`, `dirinfo`, `nonblock`, `stdoutOrErr`, `appendMode`. The comments about finalizers are important.
* **`rename`:** This is a standard file system operation. The logic around checking for existing directories and prioritizing errors is interesting.
* **`Fd`:**  Crucial for getting the underlying OS file descriptor. The comment about non-blocking mode conversion is a key detail.
* **`NewFile` and `net_newUnixFile`:**  These functions create `File` objects from file descriptors. The distinction between them regarding blocking behavior for network connections is significant.
* **`newFile`:** The core logic for creating a `File`, including handling different file "kinds" and managing the pollable status. The platform-specific handling for BSD systems is noteworthy.
* **`openFileNolog` and `openDirNolog`:**  These are the underlying implementations for opening files and directories, making direct system calls.
* **`close`:** The finalizer aspect is important.

**4. Inferring Go Language Features:**

Based on the identified functionalities, I can infer the Go language features being implemented:

* **File I/O:** The core purpose of this code.
* **File System Operations:**  Renaming, truncating, removing files and directories.
* **Hard Links and Symbolic Links:**  Creating and reading them.
* **Directory Operations:** Opening and reading directories (implied by `unixDirent`).
* **File Descriptors:**  Direct interaction with OS file descriptors.
* **Non-blocking I/O (partially):** The code manages the non-blocking state of file descriptors, especially for network connections.
* **Finalizers:** The use of `runtime.SetFinalizer` for closing files during garbage collection.
* **Platform-Specific Handling:** The `#go:build` directive and the BSD-specific checks in `newFile`.

**5. Code Example Construction (with Assumptions):**

Now I start to construct Go code examples to illustrate the inferred functionalities. I make assumptions about the existence of files and their content for demonstration purposes. For example, when demonstrating `rename`, I assume `old.txt` and potentially `new_dir` exist.

**6. Command Line Argument Handling (Analysis):**

I look for code that directly parses or uses command-line arguments. In this specific snippet, there isn't explicit command-line argument handling. However, the `os` package as a whole provides functions for this (e.g., `os.Args`). I note this distinction.

**7. Identifying Common Mistakes:**

I think about common pitfalls when working with file I/O in any language and relate them to the specific Go code:

* **Forgetting to close files:** The finalizer helps, but explicit closing is still good practice.
* **Incorrectly handling file descriptors:**  The warning about not closing file descriptors obtained from `Fd()` directly is important.
* **Race conditions with `rename` and directories:**  The code itself addresses some of these, but users might not be aware of the nuances.

**8. Structuring the Answer:**

Finally, I organize the findings into a clear and structured answer using the requested format: list of functionalities, Go feature identification with examples, command-line argument explanation, and common mistakes. I use clear headings and bullet points to enhance readability. I make sure to translate everything into Chinese as requested.

**Self-Correction/Refinement:**

During the process, I might revisit earlier assumptions or interpretations. For instance, if a comment suggests a historical reason for certain behavior, I'd incorporate that into the explanation. If an example doesn't quite illustrate the point clearly, I'd refine it. I ensure that the Go code examples are runnable (or at least represent correct syntax). I double-check that I've addressed all parts of the prompt.这段Go语言代码是 `os` 标准库中处理文件操作的 Unix 系统特定实现部分 (通过 `//go:build unix || (js && wasm) || wasip1` 编译指令指定)。它提供了在 Unix-like 操作系统上进行文件和目录操作的基础功能。

以下是它的主要功能列表：

1. **重命名文件或目录 (`rename`)**: 允许原子地更改文件或目录的名称。
2. **获取文件描述符 (`Fd`)**: 返回与 `os.File` 关联的 Unix 文件描述符。
3. **根据文件描述符创建 `os.File` 对象 (`NewFile`)**:  允许将一个已有的 Unix 文件描述符包装成 Go 的 `os.File` 对象。
4. **网络连接创建 `os.File` 对象 (`net_newUnixFile`)**: 一个由 `net` 包内部调用的入口点，用于将网络连接的文件描述符转换为 `os.File` 对象，并确保其返回阻塞模式的文件描述符。
5. **创建新的 `os.File` 对象 (`newFile`)**: 内部函数，根据不同的文件打开方式 (`OpenFile`, `Pipe` 等) 创建 `os.File` 对象，并尝试将其添加到运行时 poller 中以支持异步 I/O。
6. **发送 SIGPIPE 信号 (`sigpipe`)**: 当向已关闭的管道或 socket 写入数据时触发。
7. **检查 EPIPE 错误 (`epipecheck`)**: 用于在向标准输出或标准错误写入时遇到 `EPIPE` 错误时触发 `sigpipe` 信号。
8. **打开文件 (`openFileNolog`)**: Unix 系统上 `OpenFile` 函数的底层实现，用于打开或创建文件。
9. **打开目录 (`openDirNolog`)**: 用于打开目录以进行读取操作。
10. **关闭文件 (`close`)**: 关闭 `os.File` 对象关联的文件描述符。
11. **设置文件读写偏移量 (`seek`)**:  改变文件中下一次读写操作的起始位置。
12. **截断文件 (`Truncate`)**:  改变指定文件的尺寸。
13. **移除文件或空目录 (`Remove`)**: 删除指定的文件或空目录。
14. **获取临时目录 (`tempDir`)**: 返回操作系统默认的临时目录路径。
15. **创建硬链接 (`Link`)**: 创建一个新的硬链接指向已存在的文件。
16. **创建符号链接 (`Symlink`)**: 创建一个新的符号链接指向目标文件或目录。
17. **读取符号链接的目标 (`readlink`)**: 返回符号链接指向的路径。
18. **表示目录项 (`unixDirent`)**:  结构体，用于表示目录中的一个条目，包括文件名、类型和元数据。
19. **创建 `unixDirent` 对象 (`newUnixDirent`)**:  根据文件名和类型创建 `unixDirent` 对象。

**推理 Go 语言功能实现并举例说明:**

这段代码主要实现了 Go 语言标准库中关于 **文件 I/O 和文件系统操作** 的核心功能。

**例子 1: 文件打开和读取**

```go
package main

import (
	"fmt"
	"os"
	"io"
)

func main() {
	// 假设存在一个名为 "test.txt" 的文件
	file, err := os.Open("test.txt")
	if err != nil {
		fmt.Println("打开文件失败:", err)
		return
	}
	defer file.Close()

	data := make([]byte, 100)
	count, err := file.Read(data)
	if err != nil && err != io.EOF {
		fmt.Println("读取文件失败:", err)
		return
	}
	fmt.Printf("读取了 %d 字节: %s\n", count, string(data[:count]))
}
```

**假设输入:**

`test.txt` 文件内容为: "Hello, Go!"

**预期输出:**

```
读取了 10 字节: Hello, Go!
```

**解释:** `os.Open` 最终会调用到 `openFileNolog` 这个 Unix 系统特定的实现来打开文件。 `file.Read` 则会利用 `os.File` 结构体中封装的文件描述符进行读取操作。

**例子 2: 文件重命名**

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	// 假设存在一个名为 "old.txt" 的文件
	err := os.Rename("old.txt", "new.txt")
	if err != nil {
		fmt.Println("重命名文件失败:", err)
		return
	}
	fmt.Println("文件重命名成功!")
}
```

**假设输入:**

当前目录下存在一个名为 `old.txt` 的文件。

**预期输出:**

如果重命名成功，控制台会输出 "文件重命名成功!"，并且 `old.txt` 会被重命名为 `new.txt`。

**解释:** `os.Rename` 函数会调用到这段代码中的 `rename` 函数，该函数会使用底层的 `syscall.Rename` 系统调用来执行重命名操作。

**命令行参数的具体处理:**

这段代码本身 **没有直接处理命令行参数**。  命令行参数的处理通常发生在 `main` 函数中，使用 `os.Args` 切片来访问。  `os` 包的其他部分（例如 `flag` 包）提供了更高级的命令行参数解析功能。

**使用者易犯错的点:**

1. **忘记关闭文件:**  `os.File` 代表一个打开的文件，必须在使用完毕后显式调用 `Close()` 方法释放资源。如果不关闭文件描述符，可能会导致资源泄漏。

   ```go
   package main

   import (
       "fmt"
       "os"
   )

   func main() {
       file, err := os.Open("myfile.txt")
       if err != nil {
           fmt.Println("Error opening file:", err)
           return
       }
       // 忘记调用 file.Close()
       // ... 对文件进行操作 ...
   }
   ```
   **正确做法:** 使用 `defer` 语句确保在函数退出时文件被关闭。
   ```go
   package main

   import (
       "fmt"
       "os"
   )

   func main() {
       file, err := os.Open("myfile.txt")
       if err != nil {
           fmt.Println("Error opening file:", err)
           return
       }
       defer file.Close() // 确保函数退出时文件被关闭
       // ... 对文件进行操作 ...
   }
   ```

2. **混淆文件描述符的所有权:**  `Fd()` 方法返回的文件描述符是底层系统资源的一个整数表示。  虽然可以获取它，但不应该直接关闭这个文件描述符，除非你完全理解其生命周期。 `os.File` 对象拥有这个文件描述符，应该通过 `File.Close()` 方法来释放。 直接关闭 `Fd()` 返回的值可能会导致 `os.File` 对象的状态不一致，甚至引发 panic。

   ```go
   package main

   import (
       "fmt"
       "os"
       "syscall"
   )

   func main() {
       file, err := os.Open("myfile.txt")
       if err != nil {
           fmt.Println("Error opening file:", err)
           return
       }
       fd := file.Fd()
       file.Close() // 正确关闭文件

       // 错误的做法：再次关闭已经关闭的文件描述符
       err = syscall.Close(int(fd))
       if err != nil {
           fmt.Println("Error closing fd:", err) // 可能报错
       }
   }
   ```
   **说明:** 在 `file.Close()` 调用后，底层的文件描述符已经被释放。再次尝试用 `syscall.Close` 关闭同一个文件描述符可能会失败，或者更糟，可能会关闭其他被分配到相同文件描述符的资源。

这段代码是 Go 语言 `os` 包在 Unix 系统上的文件操作核心实现，理解它的功能有助于更深入地了解 Go 语言如何与底层操作系统进行交互。

Prompt: 
```
这是路径为go/src/os/file_unix.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build unix || (js && wasm) || wasip1

package os

import (
	"internal/poll"
	"internal/syscall/unix"
	"io/fs"
	"runtime"
	"sync/atomic"
	"syscall"
	_ "unsafe" // for go:linkname
)

const _UTIME_OMIT = unix.UTIME_OMIT

// fixLongPath is a noop on non-Windows platforms.
func fixLongPath(path string) string {
	return path
}

func rename(oldname, newname string) error {
	fi, err := Lstat(newname)
	if err == nil && fi.IsDir() {
		// There are two independent errors this function can return:
		// one for a bad oldname, and one for a bad newname.
		// At this point we've determined the newname is bad.
		// But just in case oldname is also bad, prioritize returning
		// the oldname error because that's what we did historically.
		// However, if the old name and new name are not the same, yet
		// they refer to the same file, it implies a case-only
		// rename on a case-insensitive filesystem, which is ok.
		if ofi, err := Lstat(oldname); err != nil {
			if pe, ok := err.(*PathError); ok {
				err = pe.Err
			}
			return &LinkError{"rename", oldname, newname, err}
		} else if newname == oldname || !SameFile(fi, ofi) {
			return &LinkError{"rename", oldname, newname, syscall.EEXIST}
		}
	}
	err = ignoringEINTR(func() error {
		return syscall.Rename(oldname, newname)
	})
	if err != nil {
		return &LinkError{"rename", oldname, newname, err}
	}
	return nil
}

// file is the real representation of *File.
// The extra level of indirection ensures that no clients of os
// can overwrite this data, which could cause the finalizer
// to close the wrong file descriptor.
type file struct {
	pfd         poll.FD
	name        string
	dirinfo     atomic.Pointer[dirInfo] // nil unless directory being read
	nonblock    bool                    // whether we set nonblocking mode
	stdoutOrErr bool                    // whether this is stdout or stderr
	appendMode  bool                    // whether file is opened for appending
}

// Fd returns the integer Unix file descriptor referencing the open file.
// If f is closed, the file descriptor becomes invalid.
// If f is garbage collected, a finalizer may close the file descriptor,
// making it invalid; see [runtime.SetFinalizer] for more information on when
// a finalizer might be run. On Unix systems this will cause the [File.SetDeadline]
// methods to stop working.
// Because file descriptors can be reused, the returned file descriptor may
// only be closed through the [File.Close] method of f, or by its finalizer during
// garbage collection. Otherwise, during garbage collection the finalizer
// may close an unrelated file descriptor with the same (reused) number.
//
// As an alternative, see the f.SyscallConn method.
func (f *File) Fd() uintptr {
	if f == nil {
		return ^(uintptr(0))
	}

	// If we put the file descriptor into nonblocking mode,
	// then set it to blocking mode before we return it,
	// because historically we have always returned a descriptor
	// opened in blocking mode. The File will continue to work,
	// but any blocking operation will tie up a thread.
	if f.nonblock {
		f.pfd.SetBlocking()
	}

	return uintptr(f.pfd.Sysfd)
}

// NewFile returns a new File with the given file descriptor and
// name. The returned value will be nil if fd is not a valid file
// descriptor. On Unix systems, if the file descriptor is in
// non-blocking mode, NewFile will attempt to return a pollable File
// (one for which the SetDeadline methods work).
//
// After passing it to NewFile, fd may become invalid under the same
// conditions described in the comments of the Fd method, and the same
// constraints apply.
func NewFile(fd uintptr, name string) *File {
	fdi := int(fd)
	if fdi < 0 {
		return nil
	}

	flags, err := unix.Fcntl(fdi, syscall.F_GETFL, 0)
	if err != nil {
		flags = 0
	}
	f := newFile(fdi, name, kindNewFile, unix.HasNonblockFlag(flags))
	f.appendMode = flags&syscall.O_APPEND != 0
	return f
}

// net_newUnixFile is a hidden entry point called by net.conn.File.
// This is used so that a nonblocking network connection will become
// blocking if code calls the Fd method. We don't want that for direct
// calls to NewFile: passing a nonblocking descriptor to NewFile should
// remain nonblocking if you get it back using Fd. But for net.conn.File
// the call to NewFile is hidden from the user. Historically in that case
// the Fd method has returned a blocking descriptor, and we want to
// retain that behavior because existing code expects it and depends on it.
//
//go:linkname net_newUnixFile net.newUnixFile
func net_newUnixFile(fd int, name string) *File {
	if fd < 0 {
		panic("invalid FD")
	}

	return newFile(fd, name, kindSock, true)
}

// newFileKind describes the kind of file to newFile.
type newFileKind int

const (
	// kindNewFile means that the descriptor was passed to us via NewFile.
	kindNewFile newFileKind = iota
	// kindOpenFile means that the descriptor was opened using
	// Open, Create, or OpenFile.
	kindOpenFile
	// kindPipe means that the descriptor was opened using Pipe.
	kindPipe
	// kindSock means that the descriptor is a network file descriptor
	// that was created from net package and was opened using net_newUnixFile.
	kindSock
	// kindNoPoll means that we should not put the descriptor into
	// non-blocking mode, because we know it is not a pipe or FIFO.
	// Used by openDirAt and openDirNolog for directories.
	kindNoPoll
)

// newFile is like NewFile, but if called from OpenFile or Pipe
// (as passed in the kind parameter) it tries to add the file to
// the runtime poller.
func newFile(fd int, name string, kind newFileKind, nonBlocking bool) *File {
	f := &File{&file{
		pfd: poll.FD{
			Sysfd:         fd,
			IsStream:      true,
			ZeroReadIsEOF: true,
		},
		name:        name,
		stdoutOrErr: fd == 1 || fd == 2,
	}}

	pollable := kind == kindOpenFile || kind == kindPipe || kind == kindSock || nonBlocking

	// Things like regular files and FIFOs in kqueue on *BSD/Darwin
	// may not work properly (or accurately according to its manual).
	// As a result, we should avoid adding those to the kqueue-based
	// netpoller. Check out #19093, #24164, and #66239 for more contexts.
	//
	// If the fd was passed to us via any path other than OpenFile,
	// we assume those callers know what they were doing, so we won't
	// perform this check and allow it to be added to the kqueue.
	if kind == kindOpenFile {
		switch runtime.GOOS {
		case "darwin", "ios", "dragonfly", "freebsd", "netbsd", "openbsd":
			var st syscall.Stat_t
			err := ignoringEINTR(func() error {
				return syscall.Fstat(fd, &st)
			})
			typ := st.Mode & syscall.S_IFMT
			// Don't try to use kqueue with regular files on *BSDs.
			// On FreeBSD a regular file is always
			// reported as ready for writing.
			// On Dragonfly, NetBSD and OpenBSD the fd is signaled
			// only once as ready (both read and write).
			// Issue 19093.
			// Also don't add directories to the netpoller.
			if err == nil && (typ == syscall.S_IFREG || typ == syscall.S_IFDIR) {
				pollable = false
			}

			// In addition to the behavior described above for regular files,
			// on Darwin, kqueue does not work properly with fifos:
			// closing the last writer does not cause a kqueue event
			// for any readers. See issue #24164.
			if (runtime.GOOS == "darwin" || runtime.GOOS == "ios") && typ == syscall.S_IFIFO {
				pollable = false
			}
		}
	}

	clearNonBlock := false
	if pollable {
		// The descriptor is already in non-blocking mode.
		// We only set f.nonblock if we put the file into
		// non-blocking mode.
		if nonBlocking {
			// See the comments on net_newUnixFile.
			if kind == kindSock {
				f.nonblock = true // tell Fd to return blocking descriptor
			}
		} else if err := syscall.SetNonblock(fd, true); err == nil {
			f.nonblock = true
			clearNonBlock = true
		} else {
			pollable = false
		}
	}

	// An error here indicates a failure to register
	// with the netpoll system. That can happen for
	// a file descriptor that is not supported by
	// epoll/kqueue; for example, disk files on
	// Linux systems. We assume that any real error
	// will show up in later I/O.
	// We do restore the blocking behavior if it was set by us.
	if pollErr := f.pfd.Init("file", pollable); pollErr != nil && clearNonBlock {
		if err := syscall.SetNonblock(fd, false); err == nil {
			f.nonblock = false
		}
	}

	runtime.SetFinalizer(f.file, (*file).close)
	return f
}

func sigpipe() // implemented in package runtime

// epipecheck raises SIGPIPE if we get an EPIPE error on standard
// output or standard error. See the SIGPIPE docs in os/signal, and
// issue 11845.
func epipecheck(file *File, e error) {
	if e == syscall.EPIPE && file.stdoutOrErr {
		sigpipe()
	}
}

// DevNull is the name of the operating system's “null device.”
// On Unix-like systems, it is "/dev/null"; on Windows, "NUL".
const DevNull = "/dev/null"

// openFileNolog is the Unix implementation of OpenFile.
// Changes here should be reflected in openDirAt and openDirNolog, if relevant.
func openFileNolog(name string, flag int, perm FileMode) (*File, error) {
	setSticky := false
	if !supportsCreateWithStickyBit && flag&O_CREATE != 0 && perm&ModeSticky != 0 {
		if _, err := Stat(name); IsNotExist(err) {
			setSticky = true
		}
	}

	var (
		r int
		s poll.SysFile
		e error
	)
	// We have to check EINTR here, per issues 11180 and 39237.
	ignoringEINTR(func() error {
		r, s, e = open(name, flag|syscall.O_CLOEXEC, syscallMode(perm))
		return e
	})
	if e != nil {
		return nil, &PathError{Op: "open", Path: name, Err: e}
	}

	// open(2) itself won't handle the sticky bit on *BSD and Solaris
	if setSticky {
		setStickyBit(name)
	}

	// There's a race here with fork/exec, which we are
	// content to live with. See ../syscall/exec_unix.go.
	if !supportsCloseOnExec {
		syscall.CloseOnExec(r)
	}

	f := newFile(r, name, kindOpenFile, unix.HasNonblockFlag(flag))
	f.pfd.SysFile = s
	return f, nil
}

func openDirNolog(name string) (*File, error) {
	var (
		r int
		s poll.SysFile
		e error
	)
	ignoringEINTR(func() error {
		r, s, e = open(name, O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY, 0)
		return e
	})
	if e != nil {
		return nil, &PathError{Op: "open", Path: name, Err: e}
	}

	if !supportsCloseOnExec {
		syscall.CloseOnExec(r)
	}

	f := newFile(r, name, kindNoPoll, false)
	f.pfd.SysFile = s
	return f, nil
}

func (file *file) close() error {
	if file == nil {
		return syscall.EINVAL
	}
	if info := file.dirinfo.Swap(nil); info != nil {
		info.close()
	}
	var err error
	if e := file.pfd.Close(); e != nil {
		if e == poll.ErrFileClosing {
			e = ErrClosed
		}
		err = &PathError{Op: "close", Path: file.name, Err: e}
	}

	// no need for a finalizer anymore
	runtime.SetFinalizer(file, nil)
	return err
}

// seek sets the offset for the next Read or Write on file to offset, interpreted
// according to whence: 0 means relative to the origin of the file, 1 means
// relative to the current offset, and 2 means relative to the end.
// It returns the new offset and an error, if any.
func (f *File) seek(offset int64, whence int) (ret int64, err error) {
	if info := f.dirinfo.Swap(nil); info != nil {
		// Free cached dirinfo, so we allocate a new one if we
		// access this file as a directory again. See #35767 and #37161.
		info.close()
	}
	ret, err = f.pfd.Seek(offset, whence)
	runtime.KeepAlive(f)
	return ret, err
}

// Truncate changes the size of the named file.
// If the file is a symbolic link, it changes the size of the link's target.
// If there is an error, it will be of type *PathError.
func Truncate(name string, size int64) error {
	e := ignoringEINTR(func() error {
		return syscall.Truncate(name, size)
	})
	if e != nil {
		return &PathError{Op: "truncate", Path: name, Err: e}
	}
	return nil
}

// Remove removes the named file or (empty) directory.
// If there is an error, it will be of type *PathError.
func Remove(name string) error {
	// System call interface forces us to know
	// whether name is a file or directory.
	// Try both: it is cheaper on average than
	// doing a Stat plus the right one.
	e := ignoringEINTR(func() error {
		return syscall.Unlink(name)
	})
	if e == nil {
		return nil
	}
	e1 := ignoringEINTR(func() error {
		return syscall.Rmdir(name)
	})
	if e1 == nil {
		return nil
	}

	// Both failed: figure out which error to return.
	// OS X and Linux differ on whether unlink(dir)
	// returns EISDIR, so can't use that. However,
	// both agree that rmdir(file) returns ENOTDIR,
	// so we can use that to decide which error is real.
	// Rmdir might also return ENOTDIR if given a bad
	// file path, like /etc/passwd/foo, but in that case,
	// both errors will be ENOTDIR, so it's okay to
	// use the error from unlink.
	if e1 != syscall.ENOTDIR {
		e = e1
	}
	return &PathError{Op: "remove", Path: name, Err: e}
}

func tempDir() string {
	dir := Getenv("TMPDIR")
	if dir == "" {
		if runtime.GOOS == "android" {
			dir = "/data/local/tmp"
		} else {
			dir = "/tmp"
		}
	}
	return dir
}

// Link creates newname as a hard link to the oldname file.
// If there is an error, it will be of type *LinkError.
func Link(oldname, newname string) error {
	e := ignoringEINTR(func() error {
		return syscall.Link(oldname, newname)
	})
	if e != nil {
		return &LinkError{"link", oldname, newname, e}
	}
	return nil
}

// Symlink creates newname as a symbolic link to oldname.
// On Windows, a symlink to a non-existent oldname creates a file symlink;
// if oldname is later created as a directory the symlink will not work.
// If there is an error, it will be of type *LinkError.
func Symlink(oldname, newname string) error {
	e := ignoringEINTR(func() error {
		return syscall.Symlink(oldname, newname)
	})
	if e != nil {
		return &LinkError{"symlink", oldname, newname, e}
	}
	return nil
}

func readlink(name string) (string, error) {
	for len := 128; ; len *= 2 {
		b := make([]byte, len)
		n, err := ignoringEINTR2(func() (int, error) {
			return fixCount(syscall.Readlink(name, b))
		})
		// buffer too small
		if (runtime.GOOS == "aix" || runtime.GOOS == "wasip1") && err == syscall.ERANGE {
			continue
		}
		if err != nil {
			return "", &PathError{Op: "readlink", Path: name, Err: err}
		}
		if n < len {
			return string(b[0:n]), nil
		}
	}
}

type unixDirent struct {
	parent string
	name   string
	typ    FileMode
	info   FileInfo
}

func (d *unixDirent) Name() string   { return d.name }
func (d *unixDirent) IsDir() bool    { return d.typ.IsDir() }
func (d *unixDirent) Type() FileMode { return d.typ }

func (d *unixDirent) Info() (FileInfo, error) {
	if d.info != nil {
		return d.info, nil
	}
	return lstat(d.parent + "/" + d.name)
}

func (d *unixDirent) String() string {
	return fs.FormatDirEntry(d)
}

func newUnixDirent(parent, name string, typ FileMode) (DirEntry, error) {
	ude := &unixDirent{
		parent: parent,
		name:   name,
		typ:    typ,
	}
	if typ != ^FileMode(0) && !testingForceReadDirLstat {
		return ude, nil
	}

	info, err := lstat(parent + "/" + name)
	if err != nil {
		return nil, err
	}

	ude.typ = info.Mode().Type()
	ude.info = info
	return ude, nil
}

"""



```