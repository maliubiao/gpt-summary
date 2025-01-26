Response:
Let's break down the thought process to answer the request about `go/src/os/file_windows.go`.

1. **Understand the Core Request:** The request asks for the functionality of a specific Go file (`file_windows.go`), explanation of the Go features it implements, code examples with input/output, command-line argument handling (if any), and common pitfalls. It emphasizes a Chinese response.

2. **Identify the Purpose of the File:** The file name `file_windows.go` strongly suggests it contains platform-specific implementations related to file operations for Windows. The `package os` declaration confirms it's part of the standard Go `os` package, responsible for OS-level interactions.

3. **Scan the Code for Key Structures and Functions:**  Quickly read through the code, noting down the major data structures and functions. This initial scan reveals:
    * `file` struct:  This is the internal representation of `*File`.
    * `Fd()`: Returns the underlying Windows handle.
    * `newFile()`: Creates a `File` instance from a handle.
    * `NewFile()`: Public constructor for `File`.
    * `openFileNolog()`, `openDirNolog()`:  Internal functions for opening files and directories.
    * `close()`:  Closes a file.
    * `seek()`:  Changes the file pointer.
    * `Truncate()`, `Remove()`, `rename()`: Standard file manipulation operations.
    * `Pipe()`: Creates a pipe.
    * `tempDir()`:  Gets the temporary directory.
    * `Link()`, `Symlink()`:  Creates hard and symbolic links.
    * `openSymlink()`, `readReparseLink()`, `readlink()`:  Functions specifically dealing with symbolic links and reparse points.

4. **Categorize the Functionality:** Based on the identified functions, group them into logical categories:
    * **File Creation and Management:** `newFile`, `NewFile`, `openFileNolog`, `openDirNolog`, `close`
    * **File Information:** `Fd`
    * **File Manipulation:** `seek`, `Truncate`, `Remove`, `rename`
    * **Inter-process Communication:** `Pipe`
    * **System Information:** `tempDir`
    * **Links (Hard and Symbolic):** `Link`, `Symlink`, `openSymlink`, `readReparseLink`, `readlink`

5. **Explain the Go Features Implemented:** For each category, identify the corresponding high-level Go concepts being implemented:
    * **File Operations:**  The `os.File` type and its associated methods directly implement Go's file I/O functionality.
    * **File Descriptors/Handles:** The `Fd()` method exposes the underlying OS-specific file descriptor (Windows handle in this case), demonstrating Go's abstraction while still allowing access to lower-level details.
    * **Error Handling:** The consistent use of `error` as a return value exemplifies Go's error handling conventions. The `PathError` and `LinkError` types provide context-specific error information.
    * **Finalizers:** The use of `runtime.SetFinalizer` demonstrates how Go manages resources (in this case, closing file handles) when objects are garbage collected.
    * **Pipes:** The `Pipe()` function implements Go's mechanism for inter-process communication.
    * **Hard and Symbolic Links:** The `Link()` and `Symlink()` functions directly map to the corresponding OS features.

6. **Craft Code Examples:** For each significant Go feature identified, create a concise and illustrative code example. Crucially:
    * **Choose meaningful scenarios:**  Demonstrate common use cases.
    * **Include necessary imports:** Ensure the code compiles.
    * **Show input and expected output (even if conceptual):** This clarifies the function's behavior. For instance, when creating a file, show the file's name as input and the success or failure as output. For `readlink`, show the symlink path as input and the target path as output.
    * **Keep the examples short and focused:** Avoid unnecessary complexity.

7. **Address Command-Line Arguments:** Carefully examine the code for any interaction with command-line arguments. In this specific file, there's no direct handling of `os.Args`. State this clearly.

8. **Identify Common Pitfalls:**  Think about the potential mistakes developers might make when using these functions:
    * **Forgetting to close files:** This is a classic resource management issue.
    * **Incorrectly handling errors:** Emphasize the importance of checking the `error` return value.
    * **Platform-specific behavior of symlinks:** Highlight the differences between Windows and other systems.

9. **Structure the Answer:** Organize the information logically using clear headings and bullet points. Start with a general summary and then delve into specifics.

10. **Translate to Chinese:**  Ensure all explanations, code comments, and examples are accurately translated into Chinese. Pay attention to technical terms.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus too much on individual function implementations.
* **Correction:** Shift focus to the *overall functionality* and the *Go features* being demonstrated by the code. The individual function details are less important than the broader concepts.
* **Initial thought:**  Provide very detailed explanations of every line of code.
* **Correction:**  Keep the explanations concise and focused on the main purpose of each function or code block.
* **Initial thought:**  Forget to include input/output examples for the code.
* **Correction:** Realize the importance of showing how to use the code and what to expect, even if it's a simple success/failure indication.
* **Initial thought:** Not explicitly mention the absence of command-line argument handling.
* **Correction:**  Realize that explicitly stating the absence of a feature is also important information.

By following this structured approach and incorporating self-correction, the resulting answer will be comprehensive, accurate, and address all aspects of the original request.
这段代码是 Go 语言 `os` 包中针对 Windows 平台的关于文件操作实现的一部分。它提供了在 Windows 系统上进行文件和目录操作的基础功能。

**核心功能列举:**

1. **`File` 类型的定义和管理:**
   - 定义了 `file` 结构体，它是 `*File` 的实际表示，包含了文件句柄 (`pfd`)、文件名 (`name`) 和目录信息 (`dirinfo`) 等。
   - 提供了 `Fd()` 方法，用于获取 Windows 文件句柄。
   - 提供了 `newFile()` 和 `NewFile()` 函数，用于创建 `File` 类型的实例，`newFile` 是内部使用的，`NewFile` 是公开的。
   - 使用 `runtime.SetFinalizer` 设置了垃圾回收时的清理函数 `close()`，确保文件句柄在不再使用时被关闭。

2. **打开文件和目录:**
   - 实现了 `openFileNolog()` 函数，用于在 Windows 上打开文件，它会调用底层的 `syscall.Open`。
   - 实现了 `openDirNolog()` 函数，用于打开目录，它实际上是调用 `openFileNolog` 并指定只读模式。

3. **关闭文件:**
   - 实现了 `close()` 方法，用于关闭文件句柄。

4. **文件指针操作:**
   - 实现了 `seek()` 方法，用于移动文件读写指针。

5. **文件截断:**
   - 实现了 `Truncate()` 函数，用于改变文件的大小。

6. **删除文件和目录:**
   - 实现了 `Remove()` 函数，用于删除指定的文件或目录。它会尝试先删除文件，如果失败再尝试删除目录，并处理只读属性的情况。

7. **重命名文件和目录:**
   - 实现了 `rename()` 函数，用于重命名文件或目录。

8. **创建管道:**
   - 实现了 `Pipe()` 函数，用于创建一对连接的 `File`，用于进程间通信。

9. **获取临时目录:**
   - 实现了 `tempDir()` 函数，用于获取系统的临时目录路径。

10. **创建硬链接:**
    - 实现了 `Link()` 函数，用于创建硬链接。

11. **创建符号链接:**
    - 实现了 `Symlink()` 函数，用于创建符号链接，并处理了 Windows 上符号链接的特殊性，例如区分文件符号链接和目录符号链接。

12. **读取符号链接目标:**
    - 实现了 `readlink()` 函数，用于读取符号链接指向的目标路径。
    - 内部使用了 `openSymlink()` 打开符号链接而不跟随，并使用 `readReparseLink()` 和 `readReparseLinkHandle()` 来获取链接目标。
    - 实现了 `normaliseLinkPath()` 函数，用于规范化 Windows 系统返回的符号链接路径格式。

**它是什么 Go 语言功能的实现：**

这段代码主要实现了 Go 语言 `os` 包中关于文件和目录操作的核心功能，特别是针对 Windows 平台的实现。它利用了 Go 的 `syscall` 包来调用底层的 Windows API，例如 `CreateFile`, `DeleteFile`, `RemoveDirectory` 等。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	// 创建一个文件
	file, err := os.Create("test.txt")
	if err != nil {
		fmt.Println("创建文件失败:", err)
		return
	}
	defer file.Close()

	// 向文件中写入内容
	_, err = file.WriteString("Hello, Go on Windows!\n")
	if err != nil {
		fmt.Println("写入文件失败:", err)
		return
	}

	// 打开文件进行读取
	readFile, err := os.Open("test.txt")
	if err != nil {
		fmt.Println("打开文件失败:", err)
		return
	}
	defer readFile.Close()

	// 读取文件内容 (简化示例，实际应用中需要更完善的读取逻辑)
	buf := make([]byte, 1024)
	n, err := readFile.Read(buf)
	if err != nil && err.Error() != "EOF" { // 忽略文件末尾错误
		fmt.Println("读取文件失败:", err)
		return
	}
	fmt.Printf("读取到的内容: %s", buf[:n])

	// 获取文件信息
	fileInfo, err := os.Stat("test.txt")
	if err != nil {
		fmt.Println("获取文件信息失败:", err)
		return
	}
	fmt.Println("文件名:", fileInfo.Name())
	fmt.Println("文件大小:", fileInfo.Size())

	// 创建一个符号链接
	err = os.Symlink("test.txt", "test_link.txt")
	if err != nil {
		fmt.Println("创建符号链接失败:", err)
		return
	}

	// 读取符号链接的目标
	target, err := os.Readlink("test_link.txt")
	if err != nil {
		fmt.Println("读取符号链接失败:", err)
		return
	}
	fmt.Println("符号链接目标:", target)

	// 删除文件和符号链接
	err = os.Remove("test.txt")
	if err != nil {
		fmt.Println("删除文件失败:", err)
	}
	err = os.Remove("test_link.txt")
	if err != nil {
		fmt.Println("删除符号链接失败:", err)
	}
}
```

**假设的输入与输出:**

假设当前目录下不存在 `test.txt` 和 `test_link.txt` 文件。

**预期输出:**

```
读取到的内容: Hello, Go on Windows!
文件名: test.txt
文件大小: 21
符号链接目标: test.txt
```

**代码推理:**

- `os.Create("test.txt")`:  会调用 `openFileNolog` 函数，并使用 `syscall.CreateFile` 在 Windows 上创建一个新的文件。
- `file.WriteString(...)`: 会通过 `file` 结构体中的 `pfd` (poll.FD) 调用底层的 Windows 文件写入操作。
- `os.Open("test.txt")`: 会调用 `openFileNolog` 函数，并使用 `syscall.CreateFile` 以只读模式打开已存在的文件。
- `readFile.Read(buf)`: 会通过 `readFile` 结构体中的 `pfd` 调用底层的 Windows 文件读取操作。
- `os.Stat("test.txt")`:  会调用 Windows API 获取文件属性。
- `os.Symlink("test.txt", "test_link.txt")`: 会调用 `Symlink` 函数，最终调用 `syscall.CreateSymbolicLinkW` 在 Windows 上创建符号链接。
- `os.Readlink("test_link.txt")`: 会调用 `readlink` 函数，最终通过 `DeviceIoControl` 获取符号链接的目标。
- `os.Remove("test.txt")` 和 `os.Remove("test_link.txt")`: 会调用 `Remove` 函数，最终调用 `syscall.DeleteFile` 来删除文件。

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。命令行参数的处理通常在 `main` 函数中，通过 `os.Args` 切片来获取。这段代码是 `os` 包内部的实现，它提供的功能会被上层调用，而上层可能会根据命令行参数来决定如何使用这些文件操作功能。

**使用者易犯错的点:**

1. **忘记关闭文件:**  在 Go 语言中，打开的文件需要显式关闭，否则会造成资源泄漏。虽然有 finalizer，但依赖 finalizer 进行资源清理不是一个好的实践，因为它执行的时机是不确定的。

   ```go
   file, err := os.Open("myfile.txt")
   if err != nil {
       // ... 错误处理
   }
   // 忘记 file.Close()
   // ... 后续操作
   ```

2. **没有正确处理错误:** 文件操作可能会返回错误，例如文件不存在、权限不足等。没有正确处理这些错误可能导致程序崩溃或行为异常。

   ```go
   file, err := os.Open("nonexistent.txt")
   // 没有检查 err
   file.Close() // 如果文件打开失败，file 为 nil，调用 Close() 会导致 panic
   ```

3. **混淆硬链接和符号链接:** 硬链接和符号链接在 Windows 上的行为和用途有所不同。硬链接指向的是文件的 inode (在 Windows 上可以理解为文件记录)，而符号链接指向的是一个路径。删除符号链接不会影响原始文件，但删除最后一个硬链接会删除文件内容。

4. **Windows 上的路径分隔符:**  虽然 Go 可以自动处理 `/` 和 `\` 作为路径分隔符，但在某些与 Windows API 交互的场景下，可能需要注意使用 `\` 或使用 `filepath.Join` 来构建路径，以避免潜在的问题。

5. **符号链接的权限问题:** 在某些版本的 Windows 上，创建符号链接可能需要管理员权限或启用开发者模式。如果没有相应的权限，`os.Symlink` 可能会失败。

总的来说，这段代码是 Go 语言在 Windows 平台上进行文件操作的重要组成部分，它封装了底层的 Windows API，提供了更高级、更易用的接口供 Go 开发者使用。理解其功能和潜在的陷阱有助于编写更健壮的 Go 程序。

Prompt: 
```
这是路径为go/src/os/file_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package os

import (
	"errors"
	"internal/filepathlite"
	"internal/godebug"
	"internal/poll"
	"internal/syscall/windows"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// This matches the value in syscall/syscall_windows.go.
const _UTIME_OMIT = -1

// file is the real representation of *File.
// The extra level of indirection ensures that no clients of os
// can overwrite this data, which could cause the finalizer
// to close the wrong file descriptor.
type file struct {
	pfd        poll.FD
	name       string
	dirinfo    atomic.Pointer[dirInfo] // nil unless directory being read
	appendMode bool                    // whether file is opened for appending
}

// Fd returns the Windows handle referencing the open file.
// If f is closed, the file descriptor becomes invalid.
// If f is garbage collected, a finalizer may close the file descriptor,
// making it invalid; see [runtime.SetFinalizer] for more information on when
// a finalizer might be run. On Unix systems this will cause the [File.SetDeadline]
// methods to stop working.
func (file *File) Fd() uintptr {
	if file == nil {
		return uintptr(syscall.InvalidHandle)
	}
	return uintptr(file.pfd.Sysfd)
}

// newFile returns a new File with the given file handle and name.
// Unlike NewFile, it does not check that h is syscall.InvalidHandle.
func newFile(h syscall.Handle, name string, kind string) *File {
	if kind == "file" {
		var m uint32
		if syscall.GetConsoleMode(h, &m) == nil {
			kind = "console"
		}
		if t, err := syscall.GetFileType(h); err == nil && t == syscall.FILE_TYPE_PIPE {
			kind = "pipe"
		}
	}

	f := &File{&file{
		pfd: poll.FD{
			Sysfd:         h,
			IsStream:      true,
			ZeroReadIsEOF: true,
		},
		name: name,
	}}
	runtime.SetFinalizer(f.file, (*file).close)

	// Ignore initialization errors.
	// Assume any problems will show up in later I/O.
	f.pfd.Init(kind, false)

	return f
}

// newConsoleFile creates new File that will be used as console.
func newConsoleFile(h syscall.Handle, name string) *File {
	return newFile(h, name, "console")
}

// NewFile returns a new File with the given file descriptor and
// name. The returned value will be nil if fd is not a valid file
// descriptor.
func NewFile(fd uintptr, name string) *File {
	h := syscall.Handle(fd)
	if h == syscall.InvalidHandle {
		return nil
	}
	return newFile(h, name, "file")
}

func epipecheck(file *File, e error) {
}

// DevNull is the name of the operating system's “null device.”
// On Unix-like systems, it is "/dev/null"; on Windows, "NUL".
const DevNull = "NUL"

// openFileNolog is the Windows implementation of OpenFile.
func openFileNolog(name string, flag int, perm FileMode) (*File, error) {
	if name == "" {
		return nil, &PathError{Op: "open", Path: name, Err: syscall.ENOENT}
	}
	path := fixLongPath(name)
	r, err := syscall.Open(path, flag|syscall.O_CLOEXEC, syscallMode(perm))
	if err != nil {
		return nil, &PathError{Op: "open", Path: name, Err: err}
	}
	return newFile(r, name, "file"), nil
}

func openDirNolog(name string) (*File, error) {
	return openFileNolog(name, O_RDONLY, 0)
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
func Truncate(name string, size int64) error {
	f, e := OpenFile(name, O_WRONLY, 0666)
	if e != nil {
		return e
	}
	defer f.Close()
	e1 := f.Truncate(size)
	if e1 != nil {
		return e1
	}
	return nil
}

// Remove removes the named file or directory.
// If there is an error, it will be of type *PathError.
func Remove(name string) error {
	p, e := syscall.UTF16PtrFromString(fixLongPath(name))
	if e != nil {
		return &PathError{Op: "remove", Path: name, Err: e}
	}

	// Go file interface forces us to know whether
	// name is a file or directory. Try both.
	e = syscall.DeleteFile(p)
	if e == nil {
		return nil
	}
	e1 := syscall.RemoveDirectory(p)
	if e1 == nil {
		return nil
	}

	// Both failed: figure out which error to return.
	if e1 != e {
		a, e2 := syscall.GetFileAttributes(p)
		if e2 != nil {
			e = e2
		} else {
			if a&syscall.FILE_ATTRIBUTE_DIRECTORY != 0 {
				e = e1
			} else if a&syscall.FILE_ATTRIBUTE_READONLY != 0 {
				if e1 = syscall.SetFileAttributes(p, a&^syscall.FILE_ATTRIBUTE_READONLY); e1 == nil {
					if e = syscall.DeleteFile(p); e == nil {
						return nil
					}
				}
			}
		}
	}
	return &PathError{Op: "remove", Path: name, Err: e}
}

func rename(oldname, newname string) error {
	e := windows.Rename(fixLongPath(oldname), fixLongPath(newname))
	if e != nil {
		return &LinkError{"rename", oldname, newname, e}
	}
	return nil
}

// Pipe returns a connected pair of Files; reads from r return bytes written to w.
// It returns the files and an error, if any. The Windows handles underlying
// the returned files are marked as inheritable by child processes.
func Pipe() (r *File, w *File, err error) {
	var p [2]syscall.Handle
	e := syscall.Pipe(p[:])
	if e != nil {
		return nil, nil, NewSyscallError("pipe", e)
	}
	return newFile(p[0], "|0", "pipe"), newFile(p[1], "|1", "pipe"), nil
}

var useGetTempPath2 = sync.OnceValue(func() bool {
	return windows.ErrorLoadingGetTempPath2() == nil
})

func tempDir() string {
	getTempPath := syscall.GetTempPath
	if useGetTempPath2() {
		getTempPath = windows.GetTempPath2
	}
	n := uint32(syscall.MAX_PATH)
	for {
		b := make([]uint16, n)
		n, _ = getTempPath(uint32(len(b)), &b[0])
		if n > uint32(len(b)) {
			continue
		}
		if n == 3 && b[1] == ':' && b[2] == '\\' {
			// Do nothing for path, like C:\.
		} else if n > 0 && b[n-1] == '\\' {
			// Otherwise remove terminating \.
			n--
		}
		return syscall.UTF16ToString(b[:n])
	}
}

// Link creates newname as a hard link to the oldname file.
// If there is an error, it will be of type *LinkError.
func Link(oldname, newname string) error {
	n, err := syscall.UTF16PtrFromString(fixLongPath(newname))
	if err != nil {
		return &LinkError{"link", oldname, newname, err}
	}
	o, err := syscall.UTF16PtrFromString(fixLongPath(oldname))
	if err != nil {
		return &LinkError{"link", oldname, newname, err}
	}
	err = syscall.CreateHardLink(n, o, 0)
	if err != nil {
		return &LinkError{"link", oldname, newname, err}
	}
	return nil
}

// Symlink creates newname as a symbolic link to oldname.
// On Windows, a symlink to a non-existent oldname creates a file symlink;
// if oldname is later created as a directory the symlink will not work.
// If there is an error, it will be of type *LinkError.
func Symlink(oldname, newname string) error {
	// '/' does not work in link's content
	oldname = filepathlite.FromSlash(oldname)

	// need the exact location of the oldname when it's relative to determine if it's a directory
	destpath := oldname
	if v := filepathlite.VolumeName(oldname); v == "" {
		if len(oldname) > 0 && IsPathSeparator(oldname[0]) {
			// oldname is relative to the volume containing newname.
			if v = filepathlite.VolumeName(newname); v != "" {
				// Prepend the volume explicitly, because it may be different from the
				// volume of the current working directory.
				destpath = v + oldname
			}
		} else {
			// oldname is relative to newname.
			destpath = dirname(newname) + `\` + oldname
		}
	}

	fi, err := Stat(destpath)
	isdir := err == nil && fi.IsDir()

	n, err := syscall.UTF16PtrFromString(fixLongPath(newname))
	if err != nil {
		return &LinkError{"symlink", oldname, newname, err}
	}
	var o *uint16
	if filepathlite.IsAbs(oldname) {
		o, err = syscall.UTF16PtrFromString(fixLongPath(oldname))
	} else {
		// Do not use fixLongPath on oldname for relative symlinks,
		// as it would turn the name into an absolute path thus making
		// an absolute symlink instead.
		// Notice that CreateSymbolicLinkW does not fail for relative
		// symlinks beyond MAX_PATH, so this does not prevent the
		// creation of an arbitrary long path name.
		o, err = syscall.UTF16PtrFromString(oldname)
	}
	if err != nil {
		return &LinkError{"symlink", oldname, newname, err}
	}

	var flags uint32 = windows.SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
	if isdir {
		flags |= syscall.SYMBOLIC_LINK_FLAG_DIRECTORY
	}
	err = syscall.CreateSymbolicLink(n, o, flags)
	if err != nil {
		// the unprivileged create flag is unsupported
		// below Windows 10 (1703, v10.0.14972). retry without it.
		flags &^= windows.SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
		err = syscall.CreateSymbolicLink(n, o, flags)
		if err != nil {
			return &LinkError{"symlink", oldname, newname, err}
		}
	}
	return nil
}

// openSymlink calls CreateFile Windows API with FILE_FLAG_OPEN_REPARSE_POINT
// parameter, so that Windows does not follow symlink, if path is a symlink.
// openSymlink returns opened file handle.
func openSymlink(path string) (syscall.Handle, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	attrs := uint32(syscall.FILE_FLAG_BACKUP_SEMANTICS)
	// Use FILE_FLAG_OPEN_REPARSE_POINT, otherwise CreateFile will follow symlink.
	// See https://docs.microsoft.com/en-us/windows/desktop/FileIO/symbolic-link-effects-on-file-systems-functions#createfile-and-createfiletransacted
	attrs |= syscall.FILE_FLAG_OPEN_REPARSE_POINT
	h, err := syscall.CreateFile(p, 0, 0, nil, syscall.OPEN_EXISTING, attrs, 0)
	if err != nil {
		return 0, err
	}
	return h, nil
}

var winreadlinkvolume = godebug.New("winreadlinkvolume")

// normaliseLinkPath converts absolute paths returned by
// DeviceIoControl(h, FSCTL_GET_REPARSE_POINT, ...)
// into paths acceptable by all Windows APIs.
// For example, it converts
//
//	\??\C:\foo\bar into C:\foo\bar
//	\??\UNC\foo\bar into \\foo\bar
//	\??\Volume{abc}\ into \\?\Volume{abc}\
func normaliseLinkPath(path string) (string, error) {
	if len(path) < 4 || path[:4] != `\??\` {
		// unexpected path, return it as is
		return path, nil
	}
	// we have path that start with \??\
	s := path[4:]
	switch {
	case len(s) >= 2 && s[1] == ':': // \??\C:\foo\bar
		return s, nil
	case len(s) >= 4 && s[:4] == `UNC\`: // \??\UNC\foo\bar
		return `\\` + s[4:], nil
	}

	// \??\Volume{abc}\
	if winreadlinkvolume.Value() != "0" {
		return `\\?\` + path[4:], nil
	}
	winreadlinkvolume.IncNonDefault()

	h, err := openSymlink(path)
	if err != nil {
		return "", err
	}
	defer syscall.CloseHandle(h)

	buf := make([]uint16, 100)
	for {
		n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), windows.VOLUME_NAME_DOS)
		if err != nil {
			return "", err
		}
		if n < uint32(len(buf)) {
			break
		}
		buf = make([]uint16, n)
	}
	s = syscall.UTF16ToString(buf)
	if len(s) > 4 && s[:4] == `\\?\` {
		s = s[4:]
		if len(s) > 3 && s[:3] == `UNC` {
			// return path like \\server\share\...
			return `\` + s[3:], nil
		}
		return s, nil
	}
	return "", errors.New("GetFinalPathNameByHandle returned unexpected path: " + s)
}

func readReparseLink(path string) (string, error) {
	h, err := openSymlink(path)
	if err != nil {
		return "", err
	}
	defer syscall.CloseHandle(h)
	return readReparseLinkHandle(h)
}

func readReparseLinkHandle(h syscall.Handle) (string, error) {
	rdbbuf := make([]byte, syscall.MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
	var bytesReturned uint32
	err := syscall.DeviceIoControl(h, syscall.FSCTL_GET_REPARSE_POINT, nil, 0, &rdbbuf[0], uint32(len(rdbbuf)), &bytesReturned, nil)
	if err != nil {
		return "", err
	}

	rdb := (*windows.REPARSE_DATA_BUFFER)(unsafe.Pointer(&rdbbuf[0]))
	switch rdb.ReparseTag {
	case syscall.IO_REPARSE_TAG_SYMLINK:
		rb := (*windows.SymbolicLinkReparseBuffer)(unsafe.Pointer(&rdb.DUMMYUNIONNAME))
		s := rb.Path()
		if rb.Flags&windows.SYMLINK_FLAG_RELATIVE != 0 {
			return s, nil
		}
		return normaliseLinkPath(s)
	case windows.IO_REPARSE_TAG_MOUNT_POINT:
		return normaliseLinkPath((*windows.MountPointReparseBuffer)(unsafe.Pointer(&rdb.DUMMYUNIONNAME)).Path())
	default:
		// the path is not a symlink or junction but another type of reparse
		// point
		return "", syscall.ENOENT
	}
}

func readlink(name string) (string, error) {
	s, err := readReparseLink(fixLongPath(name))
	if err != nil {
		return "", &PathError{Op: "readlink", Path: name, Err: err}
	}
	return s, nil
}

"""



```