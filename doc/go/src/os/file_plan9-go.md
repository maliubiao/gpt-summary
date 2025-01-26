Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Scan and Context:**

* **File Path:** `go/src/os/file_plan9.go` immediately tells us this is part of the `os` package and specifically for the Plan 9 operating system. This is crucial as Plan 9 has distinct system calls and concepts compared to Unix-like systems or Windows.
* **Copyright and License:** Standard Go copyright and BSD license information. Not directly functional but important for legal reasons.
* **Imports:** The imported packages provide clues about the functionality:
    * `internal/bytealg`, `internal/poll`, `internal/stringslite`: Indicate lower-level internal Go helpers, likely for string manipulation and file descriptor management.
    * `io`: Standard input/output interfaces.
    * `runtime`: Go runtime functions, important for finalizers and managing the lifecycle of objects.
    * `sync`, `sync/atomic`: Concurrency primitives, suggesting potential thread safety concerns and operations on shared resources.
    * `syscall`: Direct interaction with the Plan 9 kernel.
    * `time`: Time-related operations, potentially for timestamps or deadlines.

**2. Identifying Core Data Structures:**

* **`file` struct:** This is the central data structure representing an open file. Notice the `fdmu` (file descriptor mutex), `fd` (file descriptor), `name`, `dirinfo` (for directories), and `appendMode`. This structure encapsulates the essential state of a file. The `atomic.Pointer[dirInfo]` is interesting, hinting at concurrent access to directory information.
* **`dirInfo` struct:**  Specifically for directories, it holds a mutex, a buffer for directory entries, the length of the buffer, and the current position within the buffer. This screams "directory reading implementation."

**3. Analyzing Key Functions (Iterative Process):**

* **`fixLongPath`:**  A no-op on Plan 9. This is a common pattern in cross-platform code – handling platform-specific quirks. We can infer that path length limitations on Windows are the reason for its existence.
* **`Fd()`:** Returns the underlying Plan 9 file descriptor. The comment about finalizers is important – users need to be aware of when file descriptors might be closed automatically.
* **`NewFile()`:** Creates a `File` struct from a raw file descriptor. The `runtime.SetFinalizer` call is significant. It ensures the file descriptor is eventually closed even if the user forgets to call `Close()`.
* **`DevNull`:**  Defines the path to the null device. Plan 9 uses `/dev/null`, aligning with Unix-like systems.
* **`syscallMode()`:** Converts Go's portable file mode bits to Plan 9's specific mode bits. This is essential for platform-specific file creation and permission handling. The flags like `DMAPPEND`, `DMEXCL`, `DMTMP` point to Plan 9's specific file attributes.
* **`openFileNolog()`:**  The core function for opening files. It handles `O_CREATE`, `O_EXCL`, `O_TRUNC`, and emulates `O_APPEND`. The logic for creating files if they don't exist is important. The use of `syscall.Create` and `syscall.Open` directly interacts with the Plan 9 kernel. The emulation of `O_APPEND` using `syscall.Seek` is a crucial detail.
* **`openDirNolog()`:** A wrapper around `openFileNolog` specifically for opening directories in read-only mode.
* **`Close()` and `file.close()`:** Handles closing the file descriptor. The `fdmu.IncrefAndClose()` suggests reference counting to ensure the file isn't closed prematurely. The comment about "canceling pending I/O" hints at complexities in handling asynchronous operations, though the current implementation seems to lack concrete cancellation logic.
* **`file.destroy()`:**  The function that *actually* closes the file descriptor using `syscall.Close`.
* **`Stat()`:** Retrieves file information using `dirstat` (likely a Plan 9 specific syscall wrapper) and converts it to a generic `FileInfo`.
* **`Truncate()` (both `*File` and top-level):**  Changes the file size using `syscall.Fwstat` and `syscall.Wstat`. The marshaling of the `syscall.Dir` struct is how the size change is communicated to the kernel.
* **`chmod()` (both `*File` and top-level):** Modifies file permissions. It reads the existing permissions, applies the mask, and updates them using `syscall.Fwstat` and `syscall.Wstat`.
* **`Sync()`:**  Flushes file contents to disk using `syscall.Fwstat`. The empty `syscall.Dir` is interesting, implying a sync operation doesn't necessarily involve changing other file attributes.
* **`read()`, `pread()`, `write()`, `pwrite()`:** Implement basic read and write operations, including the use of mutexes (`readLock`, `writeLock`) for thread safety. The note about Plan 9 preserving message boundaries and not allowing zero-byte writes is a Plan 9 specific detail.
* **`seek()`:** Changes the file offset using `syscall.Seek`. The invalidation of `dirinfo` is important when seeking in directories.
* **`Remove()`:** Deletes a file or directory using `syscall.Remove`.
* **`rename()`:** Renames a file. The logic around checking for cross-directory renames and handling existing files is specific to Plan 9's behavior. The use of `syscall.Wstat` to rename is key.
* **`Chtimes()`:** Modifies access and modification times using `syscall.Wstat`.
* **`Pipe()`:** Creates a pipe using `syscall.Pipe`.
* **`Link()`, `Symlink()`, `readlink()`:** Indicate that hard links and symbolic links are *not supported* on Plan 9, returning `syscall.EPLAN9`.
* **`Chown()`, `Lchown()` (both `*File` and top-level):** Indicate that changing ownership is *not supported* on Plan 9, returning `syscall.EPLAN9`.
* **`tempDir()`:**  Determines the temporary directory, falling back to `/tmp`.
* **`Chdir()`:** Changes the current working directory using `syscall.Fchdir`.
* **`setDeadline()`, `setReadDeadline()`, `setWriteDeadline()`:** Indicate that deadlines are *not supported* on Plan 9, returning `poll.ErrNoDeadline`.
* **`checkValid()`:** A utility function to check if a `File` is valid before performing operations.
* **`rawConn`, `newRawConn()`:** Indicate that raw file descriptor control is *not supported* on Plan 9, returning `syscall.EPLAN9`.
* **`ignoringEINTR`, `ignoringEINTR2`:** Simple helper functions; the names suggest they might handle interrupted system calls on other platforms, but on Plan 9, they simply execute the function.

**4. Inferring Go Language Features:**

* **File I/O:** The core purpose is to provide file manipulation functionalities like opening, closing, reading, writing, seeking, truncating, etc.
* **Error Handling:**  Consistent use of `error` return values and the `PathError` and `LinkError` types for reporting file-related errors.
* **Resource Management:** The use of finalizers (`runtime.SetFinalizer`) demonstrates automatic resource cleanup. The reference counting mechanism using `fdmu` ensures safe closing of file descriptors.
* **Concurrency:**  The `sync.Mutex` and `sync/atomic` packages are used to ensure thread safety when accessing shared file resources.
* **Platform Abstraction:** The file is specifically for Plan 9, demonstrating Go's ability to provide platform-specific implementations within a single package.
* **System Calls:** Direct interaction with the Plan 9 kernel through the `syscall` package.

**5. Code Examples and Assumptions:**

For each significant function, I would think of a basic use case and construct a simple Go code snippet demonstrating its usage. This involves making assumptions about file paths and content for input and predicting the output based on the function's purpose.

**6. Identifying Potential User Errors:**

Look for areas where the Plan 9 specific behavior differs from common expectations on other systems (like the lack of hard links, symlinks, or chown) or where resource management is involved (forgetting to close files).

**7. Structuring the Answer:**

Organize the findings logically, starting with a high-level overview of functionality, then delving into specific functions, code examples, and potential pitfalls. Use clear and concise language, explaining technical terms where necessary. Emphasize the Plan 9 specific aspects throughout the explanation.
这段代码是 Go 语言 `os` 包中针对 Plan 9 操作系统实现文件操作相关功能的一部分。它提供了在 Plan 9 系统上进行文件和目录操作的基础接口。

**主要功能列举:**

1. **文件打开与创建:**  实现了 `OpenFile` 的底层逻辑 (`openFileNolog`)，允许打开或创建文件，并支持不同的打开标志（如只读、写入、追加、创建等）和权限模式。
2. **文件关闭:** 实现了 `Close` 方法，用于关闭打开的文件描述符，释放相关资源。使用了互斥锁 (`fdmu`) 和引用计数来确保文件描述符的安全关闭。
3. **文件描述符操作:** 提供了 `Fd` 方法，返回文件对象关联的 Plan 9 文件描述符。
4. **创建 `File` 对象:**  提供了 `NewFile` 函数，从一个已有的文件描述符创建一个 `File` 对象。同时，使用了 `runtime.SetFinalizer` 来确保当 `File` 对象被垃圾回收时，其文件描述符也会被关闭。
5. **文件元数据操作:**
    *   `Stat`: 获取文件的元数据信息（如权限、大小、修改时间等）。
    *   `Truncate`: 修改文件的大小。
    *   `chmod`: 修改文件的权限。
    *   `Sync`: 将文件内容同步到磁盘。
6. **文件读写操作:**
    *   `read`: 从文件中读取数据。
    *   `pread`: 从指定偏移量开始读取数据。
    *   `write`: 向文件中写入数据。
    *   `pwrite`: 从指定偏移量开始写入数据。
7. **文件指针操作:**  `seek`: 移动文件的读写指针。
8. **文件删除和重命名:**
    *   `Remove`: 删除文件或目录。
    *   `rename`: 重命名文件。
9. **修改文件时间戳:** `Chtimes`: 修改文件的访问时间和修改时间。
10. **管道创建:** `Pipe`: 创建一个管道，用于进程间通信。
11. **不支持的操作:** 代码中明确指出了一些在 Plan 9 上不被支持的文件系统操作，例如：
    *   硬链接 (`Link`)
    *   符号链接 (`Symlink`, `readlink`)
    *   修改文件所有者 (`Chown`, `Lchown`)
    *   设置文件操作的截止时间 (`setDeadline`, `setReadDeadline`, `setWriteDeadline`)
    *   获取原始连接 (`newRawConn`)

**Go 语言功能的实现推理与代码示例:**

这段代码主要实现了 Go 语言 `os` 包中 `File` 类型及其相关的文件操作方法在 Plan 9 操作系统上的具体行为。

**示例 1: 文件打开和读取**

```go
package main

import (
	"fmt"
	"os"
	"io"
)

func main() {
	// 假设文件 "test.txt" 存在并包含 "Hello, Plan 9!"
	file, err := os.Open("test.txt")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	data := make([]byte, 100)
	count, err := file.Read(data)
	if err != nil && err != io.EOF {
		fmt.Println("Error reading file:", err)
		return
	}

	fmt.Printf("Read %d bytes: %s\n", count, data[:count])

	// 假设输出: Read 14 bytes: Hello, Plan 9!
}
```

**假设输入:**  当前目录下存在名为 `test.txt` 的文件，内容为 "Hello, Plan 9!"。

**输出:**
```
Read 14 bytes: Hello, Plan 9!
```

**示例 2: 文件创建和写入**

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	file, err := os.Create("output.txt")
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	_, err = file.WriteString("This is written to the file.\n")
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}

	fmt.Println("Successfully wrote to file.")

	// 假设在当前目录下创建了 output.txt 文件，内容为 "This is written to the file.\n"
}
```

**假设输入:**  当前目录下不存在名为 `output.txt` 的文件。

**输出:**
```
Successfully wrote to file.
```

**代码推理:**

*   **`fixLongPath`:** 在 Plan 9 上，文件路径长度没有像 Windows 那样的限制，所以这个函数直接返回原始路径，不做任何处理。
*   **`file` 结构体和 `Fd()`:**  `file` 结构体是 `os.File` 的内部表示，包含文件描述符等信息。`Fd()` 方法直接返回这个描述符的数值。
*   **`NewFile`:**  这个函数接受一个文件描述符和文件名，创建一个新的 `File` 对象，并将文件描述符与该对象关联起来。`runtime.SetFinalizer` 的作用是在 `File` 对象不再被引用时，自动调用 `file.close()` 方法来关闭文件描述符，避免资源泄漏。
*   **`openFileNolog`:**  这个函数根据传入的文件名、标志和权限，调用 Plan 9 的系统调用 `syscall.Open` 或 `syscall.Create` 来打开或创建文件。它处理了 `O_CREATE`, `O_EXCL`, `O_TRUNC` 等标志，并且通过 `syscall.Seek` 模拟了 `O_APPEND` 模式。
*   **`Close` 和 `file.close`:** `Close` 方法调用内部的 `file.close` 方法。`file.close` 使用 `fdmu.IncrefAndClose()` 来确保在关闭文件描述符之前没有其他操作正在进行，并且只有在引用计数降为零时才会真正调用 `file.destroy()` 来执行 `syscall.Close()`。
*   **元数据操作 (`Stat`, `Truncate`, `chmod`, `Sync`):** 这些方法都通过调用 Plan 9 的 `syscall.Fwstat` 系统调用，并构造相应的 `syscall.Dir` 结构体来修改文件的元数据。`syscall.Dir` 结构体包含了文件的大小、权限等信息，通过 `Marshal` 方法将其序列化为字节数组传递给系统调用。
*   **读写操作 (`read`, `pread`, `write`, `pwrite`):** 这些方法直接调用 Plan 9 的 `syscall.Read`, `syscall.Pread`, `syscall.Write`, `syscall.Pwrite` 系统调用进行实际的读写操作。使用了 `readLock` 和 `writeLock` 来保证并发安全。
*   **`seek`:**  调用 Plan 9 的 `syscall.Seek` 系统调用来改变文件偏移量。
*   **`Remove` 和 `rename`:** 分别调用 `syscall.Remove` 和 `syscall.Wstat` (配合构造 `syscall.Dir`) 来删除和重命名文件。`rename` 的实现中，特别注意了跨目录重命名的限制。
*   **`Chtimes`:** 调用 `syscall.Wstat` 并设置 `syscall.Dir` 结构体中的 `Atime` 和 `Mtime` 字段来修改访问和修改时间。
*   **不支持的操作 (`Link`, `Symlink`, `Chown` 等):**  这些方法直接返回 `syscall.EPLAN9` 错误，表明这些功能在 Plan 9 上不被支持。

**命令行参数的具体处理:**

这段代码本身没有直接处理命令行参数。命令行参数的处理通常发生在 `main` 函数或者使用了 `flag` 标准库的程序中。这段代码是 `os` 包的一部分，提供了文件操作的基础接口，供其他程序调用。

**使用者易犯错的点:**

1. **忘记关闭文件:** 虽然 Go 语言有垃圾回收机制，并且使用了 `SetFinalizer` 来自动关闭文件，但在长时间运行的程序中，过多的未关闭文件可能会耗尽文件描述符资源。建议始终使用 `defer file.Close()` 来确保文件在使用完毕后被关闭。

    ```go
    func main() {
        file, err := os.Open("myfile.txt")
        if err != nil {
            // ... handle error
            return
        }
        defer file.Close() // 确保文件被关闭

        // ... 对文件进行操作
    }
    ```

2. **假设所有操作系统行为一致:**  Plan 9 在某些方面的行为与其他操作系统（如 Linux 或 Windows）不同。例如，它不支持硬链接和符号链接。使用者需要了解目标操作系统的特性，避免编写依赖于特定操作系统行为的代码。

    ```go
    err := os.Symlink("existing_file", "link_to_file") // 在 Plan 9 上会返回错误
    if err != nil {
        fmt.Println("Error creating symlink:", err) // 应该预料到 Plan 9 上会出错
    }
    ```

3. **忽略错误处理:**  文件操作是可能失败的，例如文件不存在、权限不足等。必须始终检查文件操作返回的错误，并进行适当的处理。

    ```go
    file, err := os.Open("nonexistent.txt")
    if err != nil {
        fmt.Println("Error opening file:", err)
        // ... 进行错误处理，例如创建文件或返回错误
        return
    }
    defer file.Close()
    ```

总而言之，这段 `go/src/os/file_plan9.go` 代码是 Go 语言 `os` 包在 Plan 9 操作系统上的具体实现，负责提供文件和目录操作的核心功能，并与底层的 Plan 9 系统调用进行交互。使用者需要注意 Plan 9 系统的特性和限制，并正确处理可能出现的错误，以编写健壮的 Go 程序。

Prompt: 
```
这是路径为go/src/os/file_plan9.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package os

import (
	"internal/bytealg"
	"internal/poll"
	"internal/stringslite"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// fixLongPath is a noop on non-Windows platforms.
func fixLongPath(path string) string {
	return path
}

// file is the real representation of *File.
// The extra level of indirection ensures that no clients of os
// can overwrite this data, which could cause the finalizer
// to close the wrong file descriptor.
type file struct {
	fdmu       poll.FDMutex
	fd         int
	name       string
	dirinfo    atomic.Pointer[dirInfo] // nil unless directory being read
	appendMode bool                    // whether file is opened for appending
}

// Fd returns the integer Plan 9 file descriptor referencing the open file.
// If f is closed, the file descriptor becomes invalid.
// If f is garbage collected, a finalizer may close the file descriptor,
// making it invalid; see [runtime.SetFinalizer] for more information on when
// a finalizer might be run. On Unix systems this will cause the [File.SetDeadline]
// methods to stop working.
//
// As an alternative, see the f.SyscallConn method.
func (f *File) Fd() uintptr {
	if f == nil {
		return ^(uintptr(0))
	}
	return uintptr(f.fd)
}

// NewFile returns a new File with the given file descriptor and
// name. The returned value will be nil if fd is not a valid file
// descriptor.
func NewFile(fd uintptr, name string) *File {
	fdi := int(fd)
	if fdi < 0 {
		return nil
	}
	f := &File{&file{fd: fdi, name: name}}
	runtime.SetFinalizer(f.file, (*file).close)
	return f
}

// Auxiliary information if the File describes a directory
type dirInfo struct {
	mu   sync.Mutex
	buf  [syscall.STATMAX]byte // buffer for directory I/O
	nbuf int                   // length of buf; return value from Read
	bufp int                   // location of next record in buf.
}

func epipecheck(file *File, e error) {
}

// DevNull is the name of the operating system's “null device.”
// On Unix-like systems, it is "/dev/null"; on Windows, "NUL".
const DevNull = "/dev/null"

// syscallMode returns the syscall-specific mode bits from Go's portable mode bits.
func syscallMode(i FileMode) (o uint32) {
	o |= uint32(i.Perm())
	if i&ModeAppend != 0 {
		o |= syscall.DMAPPEND
	}
	if i&ModeExclusive != 0 {
		o |= syscall.DMEXCL
	}
	if i&ModeTemporary != 0 {
		o |= syscall.DMTMP
	}
	return
}

// openFileNolog is the Plan 9 implementation of OpenFile.
func openFileNolog(name string, flag int, perm FileMode) (*File, error) {
	var (
		fd     int
		e      error
		create bool
		excl   bool
		trunc  bool
		append bool
	)

	if flag&O_CREATE == O_CREATE {
		flag = flag & ^O_CREATE
		create = true
	}
	if flag&O_EXCL == O_EXCL {
		excl = true
	}
	if flag&O_TRUNC == O_TRUNC {
		trunc = true
	}
	// O_APPEND is emulated on Plan 9
	if flag&O_APPEND == O_APPEND {
		flag = flag &^ O_APPEND
		append = true
	}

	if (create && trunc) || excl {
		fd, e = syscall.Create(name, flag, syscallMode(perm))
	} else {
		fd, e = syscall.Open(name, flag)
		if IsNotExist(e) && create {
			fd, e = syscall.Create(name, flag, syscallMode(perm))
			if e != nil {
				return nil, &PathError{Op: "create", Path: name, Err: e}
			}
		}
	}

	if e != nil {
		return nil, &PathError{Op: "open", Path: name, Err: e}
	}

	if append {
		if _, e = syscall.Seek(fd, 0, io.SeekEnd); e != nil {
			return nil, &PathError{Op: "seek", Path: name, Err: e}
		}
	}

	return NewFile(uintptr(fd), name), nil
}

func openDirNolog(name string) (*File, error) {
	return openFileNolog(name, O_RDONLY, 0)
}

// Close closes the File, rendering it unusable for I/O.
// On files that support SetDeadline, any pending I/O operations will
// be canceled and return immediately with an ErrClosed error.
// Close will return an error if it has already been called.
func (f *File) Close() error {
	if f == nil {
		return ErrInvalid
	}
	return f.file.close()
}

func (file *file) close() error {
	if !file.fdmu.IncrefAndClose() {
		return &PathError{Op: "close", Path: file.name, Err: ErrClosed}
	}

	// At this point we should cancel any pending I/O.
	// How do we do that on Plan 9?

	err := file.decref()

	// no need for a finalizer anymore
	runtime.SetFinalizer(file, nil)
	return err
}

// destroy actually closes the descriptor. This is called when
// there are no remaining references, by the decref, readUnlock,
// and writeUnlock methods.
func (file *file) destroy() error {
	var err error
	if e := syscall.Close(file.fd); e != nil {
		err = &PathError{Op: "close", Path: file.name, Err: e}
	}
	return err
}

// Stat returns the FileInfo structure describing file.
// If there is an error, it will be of type *PathError.
func (f *File) Stat() (FileInfo, error) {
	if f == nil {
		return nil, ErrInvalid
	}
	d, err := dirstat(f)
	if err != nil {
		return nil, err
	}
	return fileInfoFromStat(d), nil
}

// Truncate changes the size of the file.
// It does not change the I/O offset.
// If there is an error, it will be of type *PathError.
func (f *File) Truncate(size int64) error {
	if f == nil {
		return ErrInvalid
	}

	var d syscall.Dir
	d.Null()
	d.Length = size

	var buf [syscall.STATFIXLEN]byte
	n, err := d.Marshal(buf[:])
	if err != nil {
		return &PathError{Op: "truncate", Path: f.name, Err: err}
	}

	if err := f.incref("truncate"); err != nil {
		return err
	}
	defer f.decref()

	if err = syscall.Fwstat(f.fd, buf[:n]); err != nil {
		return &PathError{Op: "truncate", Path: f.name, Err: err}
	}
	return nil
}

const chmodMask = uint32(syscall.DMAPPEND | syscall.DMEXCL | syscall.DMTMP | ModePerm)

func (f *File) chmod(mode FileMode) error {
	if f == nil {
		return ErrInvalid
	}
	var d syscall.Dir

	odir, e := dirstat(f)
	if e != nil {
		return &PathError{Op: "chmod", Path: f.name, Err: e}
	}
	d.Null()
	d.Mode = odir.Mode&^chmodMask | syscallMode(mode)&chmodMask

	var buf [syscall.STATFIXLEN]byte
	n, err := d.Marshal(buf[:])
	if err != nil {
		return &PathError{Op: "chmod", Path: f.name, Err: err}
	}

	if err := f.incref("chmod"); err != nil {
		return err
	}
	defer f.decref()

	if err = syscall.Fwstat(f.fd, buf[:n]); err != nil {
		return &PathError{Op: "chmod", Path: f.name, Err: err}
	}
	return nil
}

// Sync commits the current contents of the file to stable storage.
// Typically, this means flushing the file system's in-memory copy
// of recently written data to disk.
func (f *File) Sync() error {
	if f == nil {
		return ErrInvalid
	}
	var d syscall.Dir
	d.Null()

	var buf [syscall.STATFIXLEN]byte
	n, err := d.Marshal(buf[:])
	if err != nil {
		return &PathError{Op: "sync", Path: f.name, Err: err}
	}

	if err := f.incref("sync"); err != nil {
		return err
	}
	defer f.decref()

	if err = syscall.Fwstat(f.fd, buf[:n]); err != nil {
		return &PathError{Op: "sync", Path: f.name, Err: err}
	}
	return nil
}

// read reads up to len(b) bytes from the File.
// It returns the number of bytes read and an error, if any.
func (f *File) read(b []byte) (n int, err error) {
	if err := f.readLock(); err != nil {
		return 0, err
	}
	defer f.readUnlock()
	n, e := fixCount(syscall.Read(f.fd, b))
	if n == 0 && len(b) > 0 && e == nil {
		return 0, io.EOF
	}
	return n, e
}

// pread reads len(b) bytes from the File starting at byte offset off.
// It returns the number of bytes read and the error, if any.
// EOF is signaled by a zero count with err set to nil.
func (f *File) pread(b []byte, off int64) (n int, err error) {
	if err := f.readLock(); err != nil {
		return 0, err
	}
	defer f.readUnlock()
	n, e := fixCount(syscall.Pread(f.fd, b, off))
	if n == 0 && len(b) > 0 && e == nil {
		return 0, io.EOF
	}
	return n, e
}

// write writes len(b) bytes to the File.
// It returns the number of bytes written and an error, if any.
// Since Plan 9 preserves message boundaries, never allow
// a zero-byte write.
func (f *File) write(b []byte) (n int, err error) {
	if err := f.writeLock(); err != nil {
		return 0, err
	}
	defer f.writeUnlock()
	if len(b) == 0 {
		return 0, nil
	}
	return fixCount(syscall.Write(f.fd, b))
}

// pwrite writes len(b) bytes to the File starting at byte offset off.
// It returns the number of bytes written and an error, if any.
// Since Plan 9 preserves message boundaries, never allow
// a zero-byte write.
func (f *File) pwrite(b []byte, off int64) (n int, err error) {
	if err := f.writeLock(); err != nil {
		return 0, err
	}
	defer f.writeUnlock()
	if len(b) == 0 {
		return 0, nil
	}
	return fixCount(syscall.Pwrite(f.fd, b, off))
}

// seek sets the offset for the next Read or Write on file to offset, interpreted
// according to whence: 0 means relative to the origin of the file, 1 means
// relative to the current offset, and 2 means relative to the end.
// It returns the new offset and an error, if any.
func (f *File) seek(offset int64, whence int) (ret int64, err error) {
	if err := f.incref(""); err != nil {
		return 0, err
	}
	defer f.decref()
	// Free cached dirinfo, so we allocate a new one if we
	// access this file as a directory again. See #35767 and #37161.
	f.dirinfo.Store(nil)
	return syscall.Seek(f.fd, offset, whence)
}

// Truncate changes the size of the named file.
// If the file is a symbolic link, it changes the size of the link's target.
// If there is an error, it will be of type *PathError.
func Truncate(name string, size int64) error {
	var d syscall.Dir

	d.Null()
	d.Length = size

	var buf [syscall.STATFIXLEN]byte
	n, err := d.Marshal(buf[:])
	if err != nil {
		return &PathError{Op: "truncate", Path: name, Err: err}
	}
	if err = syscall.Wstat(name, buf[:n]); err != nil {
		return &PathError{Op: "truncate", Path: name, Err: err}
	}
	return nil
}

// Remove removes the named file or directory.
// If there is an error, it will be of type *PathError.
func Remove(name string) error {
	if e := syscall.Remove(name); e != nil {
		return &PathError{Op: "remove", Path: name, Err: e}
	}
	return nil
}

func rename(oldname, newname string) error {
	dirname := oldname[:bytealg.LastIndexByteString(oldname, '/')+1]
	if stringslite.HasPrefix(newname, dirname) {
		newname = newname[len(dirname):]
	} else {
		return &LinkError{"rename", oldname, newname, ErrInvalid}
	}

	// If newname still contains slashes after removing the oldname
	// prefix, the rename is cross-directory and must be rejected.
	if bytealg.LastIndexByteString(newname, '/') >= 0 {
		return &LinkError{"rename", oldname, newname, ErrInvalid}
	}

	var d syscall.Dir

	d.Null()
	d.Name = newname

	buf := make([]byte, syscall.STATFIXLEN+len(d.Name))
	n, err := d.Marshal(buf[:])
	if err != nil {
		return &LinkError{"rename", oldname, newname, err}
	}

	// If newname already exists and is not a directory, rename replaces it.
	f, err := Stat(dirname + newname)
	if err == nil && !f.IsDir() {
		Remove(dirname + newname)
	}

	if err = syscall.Wstat(oldname, buf[:n]); err != nil {
		return &LinkError{"rename", oldname, newname, err}
	}
	return nil
}

// See docs in file.go:Chmod.
func chmod(name string, mode FileMode) error {
	var d syscall.Dir

	odir, e := dirstat(name)
	if e != nil {
		return &PathError{Op: "chmod", Path: name, Err: e}
	}
	d.Null()
	d.Mode = odir.Mode&^chmodMask | syscallMode(mode)&chmodMask

	var buf [syscall.STATFIXLEN]byte
	n, err := d.Marshal(buf[:])
	if err != nil {
		return &PathError{Op: "chmod", Path: name, Err: err}
	}
	if err = syscall.Wstat(name, buf[:n]); err != nil {
		return &PathError{Op: "chmod", Path: name, Err: err}
	}
	return nil
}

// Chtimes changes the access and modification times of the named
// file, similar to the Unix utime() or utimes() functions.
// A zero time.Time value will leave the corresponding file time unchanged.
//
// The underlying filesystem may truncate or round the values to a
// less precise time unit.
// If there is an error, it will be of type *PathError.
func Chtimes(name string, atime time.Time, mtime time.Time) error {
	var d syscall.Dir

	d.Null()
	d.Atime = uint32(atime.Unix())
	d.Mtime = uint32(mtime.Unix())
	if atime.IsZero() {
		d.Atime = 0xFFFFFFFF
	}
	if mtime.IsZero() {
		d.Mtime = 0xFFFFFFFF
	}

	var buf [syscall.STATFIXLEN]byte
	n, err := d.Marshal(buf[:])
	if err != nil {
		return &PathError{Op: "chtimes", Path: name, Err: err}
	}
	if err = syscall.Wstat(name, buf[:n]); err != nil {
		return &PathError{Op: "chtimes", Path: name, Err: err}
	}
	return nil
}

// Pipe returns a connected pair of Files; reads from r return bytes
// written to w. It returns the files and an error, if any.
func Pipe() (r *File, w *File, err error) {
	var p [2]int

	if e := syscall.Pipe(p[0:]); e != nil {
		return nil, nil, NewSyscallError("pipe", e)
	}

	return NewFile(uintptr(p[0]), "|0"), NewFile(uintptr(p[1]), "|1"), nil
}

// not supported on Plan 9

// Link creates newname as a hard link to the oldname file.
// If there is an error, it will be of type *LinkError.
func Link(oldname, newname string) error {
	return &LinkError{"link", oldname, newname, syscall.EPLAN9}
}

// Symlink creates newname as a symbolic link to oldname.
// On Windows, a symlink to a non-existent oldname creates a file symlink;
// if oldname is later created as a directory the symlink will not work.
// If there is an error, it will be of type *LinkError.
func Symlink(oldname, newname string) error {
	return &LinkError{"symlink", oldname, newname, syscall.EPLAN9}
}

func readlink(name string) (string, error) {
	return "", &PathError{Op: "readlink", Path: name, Err: syscall.EPLAN9}
}

// Chown changes the numeric uid and gid of the named file.
// If the file is a symbolic link, it changes the uid and gid of the link's target.
// A uid or gid of -1 means to not change that value.
// If there is an error, it will be of type *PathError.
//
// On Windows or Plan 9, Chown always returns the syscall.EWINDOWS or
// EPLAN9 error, wrapped in *PathError.
func Chown(name string, uid, gid int) error {
	return &PathError{Op: "chown", Path: name, Err: syscall.EPLAN9}
}

// Lchown changes the numeric uid and gid of the named file.
// If the file is a symbolic link, it changes the uid and gid of the link itself.
// If there is an error, it will be of type *PathError.
func Lchown(name string, uid, gid int) error {
	return &PathError{Op: "lchown", Path: name, Err: syscall.EPLAN9}
}

// Chown changes the numeric uid and gid of the named file.
// If there is an error, it will be of type *PathError.
func (f *File) Chown(uid, gid int) error {
	if f == nil {
		return ErrInvalid
	}
	return &PathError{Op: "chown", Path: f.name, Err: syscall.EPLAN9}
}

func tempDir() string {
	dir := Getenv("TMPDIR")
	if dir == "" {
		dir = "/tmp"
	}
	return dir
}

// Chdir changes the current working directory to the file,
// which must be a directory.
// If there is an error, it will be of type *PathError.
func (f *File) Chdir() error {
	if err := f.incref("chdir"); err != nil {
		return err
	}
	defer f.decref()
	if e := syscall.Fchdir(f.fd); e != nil {
		return &PathError{Op: "chdir", Path: f.name, Err: e}
	}
	return nil
}

// setDeadline sets the read and write deadline.
func (f *File) setDeadline(time.Time) error {
	if err := f.checkValid("SetDeadline"); err != nil {
		return err
	}
	return poll.ErrNoDeadline
}

// setReadDeadline sets the read deadline.
func (f *File) setReadDeadline(time.Time) error {
	if err := f.checkValid("SetReadDeadline"); err != nil {
		return err
	}
	return poll.ErrNoDeadline
}

// setWriteDeadline sets the write deadline.
func (f *File) setWriteDeadline(time.Time) error {
	if err := f.checkValid("SetWriteDeadline"); err != nil {
		return err
	}
	return poll.ErrNoDeadline
}

// checkValid checks whether f is valid for use, but does not prepare
// to actually use it. If f is not ready checkValid returns an appropriate
// error, perhaps incorporating the operation name op.
func (f *File) checkValid(op string) error {
	if f == nil {
		return ErrInvalid
	}
	if err := f.incref(op); err != nil {
		return err
	}
	return f.decref()
}

type rawConn struct{}

func (c *rawConn) Control(f func(uintptr)) error {
	return syscall.EPLAN9
}

func (c *rawConn) Read(f func(uintptr) bool) error {
	return syscall.EPLAN9
}

func (c *rawConn) Write(f func(uintptr) bool) error {
	return syscall.EPLAN9
}

func newRawConn(file *File) (*rawConn, error) {
	return nil, syscall.EPLAN9
}

func ignoringEINTR(fn func() error) error {
	return fn()
}

func ignoringEINTR2[T any](fn func() (T, error)) (T, error) {
	return fn()
}

"""



```