Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Understanding the Context:**

The first line `// 这是路径为go/src/syscall/fs_wasip1.go的go语言实现的一部分` immediately tells us this is a Go source file, specifically part of the `syscall` package, and it's related to the `wasip1` build tag. This strongly suggests it's implementing system call functionalities for the WebAssembly System Interface (WASI), preview 1.

**2. Initial Code Scan - Identifying Key Areas:**

I'd quickly scan the code looking for patterns and significant blocks:

* **`// Copyright ...` and `//go:build wasip1`:** Confirms the context and build constraint.
* **`package syscall` and `import (...)`:**  Shows the package and its dependencies (internal packages, runtime, unsafe).
* **`func init() { ... }`:**  An important initialization function, often used for setup. The comments about setting stdio to non-blocking are a big clue.
* **Type definitions (`type uintptr32 = ...`):** Suggests mapping WASI types to Go types.
* **Constant definitions (`const (...)`):**  These are likely WASI flag and right definitions. The names are very indicative (e.g., `OFLAG_CREATE`, `RIGHT_FD_READ`).
* **`//go:wasmimport ...`:**  This is a crucial pattern. It clearly indicates calls to WASI functions implemented by the WebAssembly runtime. The function names directly correspond to WASI specifications.
* **Function definitions (`func fd_close(...) Errno`, `func Open(...) (int, error)`, etc.):**  These are the core functionalities being implemented. The names often mirror standard Unix/POSIX system calls.
* **Global variables (`var preopens []opendir`, `var cwd string`):**  These store state related to the WASI environment.
* **Helper functions (`appendCleanPath`, `joinPath`, `preparePath`):** These are internal utilities for path manipulation.
* **Structs (`type iovec struct { ... }`, `type fdstat struct { ... }`, etc.):**  Represent data structures used in WASI interactions.

**3. Focusing on Functionality -  Connecting WASI Imports to Go Functions:**

The `//go:wasmimport` directives are the key to understanding the core functionality. I would go through these, noting the WASI function being imported and the corresponding Go function. This creates a direct mapping between WASI concepts and the Go implementation. For instance:

* `//go:wasmimport wasi_snapshot_preview1 fd_close` maps to `func fd_close(fd int32) Errno`. This tells me the Go code is wrapping the WASI `fd_close` function.

I'd repeat this for all the `wasmimport` lines. This builds a mental model of the supported WASI system calls.

**4. Inferring Go Function Implementations:**

With the WASI imports identified, I'd look at the regular Go functions. Many of these functions (like `Open`, `Close`, `Read`, `Write`, `Mkdir`, `Stat`, etc.) have names similar to standard Unix system calls. The code within these functions typically does the following:

* **Path Preparation:** Using `preparePath` to resolve paths in the WASI environment.
* **Mapping Go Flags to WASI Flags:** Converting Go's `os` package flags (like `O_RDONLY`, `O_CREATE`) to the corresponding WASI constants (like `OFLAG_CREATE`).
* **Calling the WASI Import:**  Invoking the appropriate `//go:wasmimport` function.
* **Error Handling:** Converting WASI error codes (`Errno`) to Go `error` types.

**5. Reasoning about Go Feature Implementation:**

Based on the identified functionalities and the WASI imports, it becomes clear that this file is implementing the core file system functionalities of the Go `os` package for the WASI environment. This includes:

* Opening and closing files.
* Reading and writing data.
* Creating and deleting directories.
* Getting file metadata (stat).
* Manipulating paths (rename, link, symlink).
* Changing the current directory.

**6. Code Example Construction:**

To demonstrate the functionality, I'd choose a common file system operation, like opening and reading a file. This would involve:

* Using `os.OpenFile` (which internally would call the `syscall.Open` implemented in this file).
* Providing appropriate flags (e.g., `os.O_RDONLY`).
* Reading from the opened file using `io.ReadFile`.

This leads to the example code provided in the initial good answer.

**7. Identifying Potential Pitfalls:**

By examining the code and understanding WASI's limitations, I can identify potential issues:

* **Lack of full POSIX compatibility:**  WASI is a subset, so features like permissions (chmod, chown) are not fully supported. The code often returns `ENOSYS` or provides default values.
* **Path resolution complexities:** The `preparePath` function and the handling of preopens and the current working directory are areas where misunderstandings could lead to errors.
* **Rights management:** WASI's capability-based security model requires careful management of rights. Requesting too many rights during `path_open` can lead to errors, as demonstrated by the fallback logic for directories.

**8. Review and Refinement:**

Finally, I'd review my understanding and ensure that the explanation is clear, concise, and accurate. I'd check if I've addressed all the prompt's requirements (listing functionalities, providing examples, explaining potential errors).

This step-by-step approach allows for a systematic analysis of the code, starting from the high-level context and drilling down into the specific implementation details. The key is to recognize the connection between the Go code and the underlying WASI system calls.
这段代码是 Go 语言标准库中 `syscall` 包针对 `wasip1` 平台的实现，主要负责提供与文件系统相关的系统调用接口。`wasip1` 指的是 WebAssembly System Interface 的预览版本 1。

**主要功能列举:**

1. **初始化标准 I/O 流的非阻塞模式:**  在 `init()` 函数中，它尝试将文件描述符 0 (标准输入)、1 (标准输出) 和 2 (标准错误) 设置为非阻塞模式。这对于 WebAssembly 模块的并发执行至关重要，因为它允许 Go 运行时利用 WASI 的网络轮询器进行 I/O 操作，而不会阻塞整个模块的执行。

2. **定义 WASI 相关类型:** 定义了与 WASI 规范相对应的各种类型，例如 `uintptr32`, `size`, `fdflags`, `filesize`, `rights` 等，用于与 WebAssembly 运行时进行数据交互。

3. **定义 WASI 常量:** 定义了许多 WASI 中使用的常量，例如文件查找标志 (`LOOKUP_SYMLINK_FOLLOW`)、文件打开标志 (`OFLAG_CREATE`, `OFLAG_DIRECTORY` 等)、文件描述符标志 (`FDFLAG_APPEND`, `FDFLAG_NONBLOCK` 等) 以及文件操作权限 (`RIGHT_FD_READ`, `RIGHT_PATH_CREATE_FILE` 等)。这些常量用于控制文件操作的行为和权限。

4. **声明 WASI 函数导入:** 使用 `//go:wasmimport` 注释声明了需要从 WebAssembly 运行时导入的 WASI 函数。这些函数涵盖了各种文件系统操作，例如：
    * `fd_close`: 关闭文件描述符
    * `fd_filestat_set_size`: 设置文件大小
    * `fd_pread`, `fd_pwrite`, `fd_read`, `fd_write`:  读写文件
    * `fd_readdir`: 读取目录内容
    * `fd_seek`: 移动文件指针
    * `fd_fdstat_set_rights`: 设置文件描述符的权限
    * `fd_filestat_get`: 获取文件状态
    * `fd_sync`: 同步文件到存储
    * `path_create_directory`: 创建目录
    * `path_filestat_get`, `path_filestat_set_times`: 获取和设置文件状态
    * `path_link`, `path_readlink`, `path_remove_directory`, `path_rename`, `path_symlink`, `path_unlink_file`: 文件和目录操作
    * `path_open`: 打开文件或目录
    * `random_get`: 获取随机数
    * `fd_fdstat_get`, `fd_fdstat_set_flags`: 获取和设置文件描述符状态
    * `fd_prestat_get`, `fd_prestat_dir_name`: 获取预打开目录信息

5. **实现 Go 语言的文件系统操作接口:**  提供了与 Go 语言 `os` 包中文件系统操作相对应的函数，例如 `Open`, `Close`, `Mkdir`, `ReadDir`, `Stat`, `Lstat`, `Fstat`, `Unlink`, `Rmdir`, `Rename`, `Truncate`, `Ftruncate`, `Getwd`, `Chdir`, `Readlink`, `Link`, `Symlink`, `Fsync`, `Read`, `Write`, `Pread`, `Pwrite`, `Seek` 等。这些函数内部会调用前面声明的 WASI 导入函数，将 Go 的操作转化为对 WebAssembly 运行时的调用。

6. **处理路径:** 实现了 `joinPath`, `isAbs`, `isDir`, `appendCleanPath`, `preparePath` 等辅助函数，用于处理和解析文件路径，使其能够在 WASI 环境下正确工作。`preparePath` 函数尤其重要，它负责将 Go 的路径转换为 WASI 可以理解的格式，并确定操作应该基于哪个预打开的目录进行。

7. **管理预打开目录:**  维护了一个 `preopens` 列表，存储了 WebAssembly 运行时暴露的预打开目录的信息。这是 WASI 安全模型的基础，它限制了 WebAssembly 模块只能访问运行时明确允许的目录。

8. **维护当前工作目录:**  维护一个全局变量 `cwd` 来跟踪当前工作目录，因为 WASI 本身不直接支持全局的工作目录概念。

**它是什么 Go 语言功能的实现:**

这段代码是 Go 语言 `os` 包中与文件系统操作相关功能在 `wasip1` 平台上的底层实现。当 Go 代码在 WebAssembly 环境中运行时，如果调用了 `os` 包中的文件系统操作函数（例如 `os.Open`, `os.ReadFile`, `os.Mkdir` 等），最终会调用到 `syscall` 包中对应的 `fs_wasip1.go` 文件中实现的函数。

**Go 代码举例说明:**

假设我们要打开一个名为 `test.txt` 的文件并读取它的内容：

```go
package main

import (
	"fmt"
	"os"
	"io/ioutil"
)

func main() {
	file, err := os.OpenFile("test.txt", os.O_RDONLY, 0)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	content, err := ioutil.ReadFile("test.txt") // 或者使用 file 进行读取
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	fmt.Println("File content:", string(content))
}
```

**代码推理 (假设):**

1. 当 `os.OpenFile("test.txt", os.O_RDONLY, 0)` 被调用时，它会最终调用到 `syscall` 包中的 `Open` 函数（在 `fs_wasip1.go` 中）。
2. `Open` 函数会调用 `preparePath("test.txt")` 来解析路径。假设当前工作目录是 `/home/user`，且 WASI 运行时预打开了根目录 `/`。 `preparePath` 可能会返回预打开根目录的文件描述符和一个相对于根目录的路径 `"home/user/test.txt"`。
3. `Open` 函数会将 Go 的 `os.O_RDONLY` 转换为 WASI 的 `O_RDONLY` 标志，并构造相应的权限参数。
4. `Open` 函数会调用 WASI 的 `path_open` 函数 (`go:wasmimport wasi_snapshot_preview1 path_open`)，并将预打开的根目录文件描述符、解析后的路径、打开标志和权限传递给它。
5. WebAssembly 运行时会执行 `path_open`，如果文件存在且权限允许，则会返回一个新的文件描述符。
6. `syscall.Open` 函数会将 WASI 返回的文件描述符包装成 Go 的 `os.File` 对象返回。
7. 同样，`ioutil.ReadFile("test.txt")` 内部也会调用 `os.Open` 和 `file.Read` (最终调用 `syscall.Read`) 等函数，最终通过 WASI 接口读取文件内容。

**假设的输入与输出:**

* **假设输入:**  当前工作目录 `/home/user`，WASI 运行时预打开了根目录 `/`。 `test.txt` 文件存在于 `/home/user/` 目录下，内容为 "Hello WASI!".
* **假设输出:**  控制台输出 "File content: Hello WASI!"

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。命令行参数的处理通常发生在 `main` 函数的 `os.Args` 中，然后程序可能会根据这些参数调用 `os` 包中的文件系统操作函数，从而间接地触发 `fs_wasip1.go` 中的代码。

例如，如果一个 WebAssembly 程序接收一个文件路径作为命令行参数：

```go
package main

import (
	"fmt"
	"os"
	"io/ioutil"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: program <filepath>")
		return
	}
	filepath := os.Args[1]

	content, err := ioutil.ReadFile(filepath)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	fmt.Println("File content:", string(content))
}
```

当以 `program my_data.txt` 运行该程序时，`os.Args[1]` 将会是 `"my_data.txt"`，然后 `ioutil.ReadFile` 会使用这个路径，最终由 `fs_wasip1.go` 中的代码来处理文件的打开和读取操作。

**使用者易犯错的点:**

1. **路径理解差异:**  WASI 的路径模型基于预打开目录，与传统的 Unix 文件系统可能略有不同。使用者可能会错误地假设可以访问任意路径，而实际上只能访问预打开目录及其子目录。例如，直接使用绝对路径 `/foo/bar.txt` 可能无法工作，除非根目录 `/` 被预先打开。

   **例子:** 如果 WASI 运行时只预打开了 `/home` 目录，那么尝试打开 `/etc/passwd` 将会失败，即使该文件在宿主机上存在。

2. **权限限制:** WASI 引入了细粒度的权限控制。使用者可能会遇到权限错误，即使在传统的 Unix 系统上可以执行的操作，在 WASI 中可能由于缺乏相应的权限而被拒绝。

   **例子:**  如果尝试创建一个新文件，但程序启动时没有被赋予 `RIGHT_PATH_CREATE_FILE` 权限，则 `os.Create` 或 `os.OpenFile` 将会失败。

3. **某些系统调用的不支持或部分支持:** WASI 是一个精简的接口，并不支持所有传统的 Unix 系统调用。使用者可能会尝试使用一些在 `fs_wasip1.go` 中返回 `ENOSYS` (功能未实现) 的函数，导致程序出错。

   **例子:**  调用 `os.Chmod` 或 `os.Chown` 在 `wasip1` 上通常不会生效，因为 WASI 没有直接对应的概念，`fs_wasip1.go` 中的实现通常会返回 `ENOSYS`。

4. **假设标准 I/O 的行为与传统系统一致:** 虽然 `fs_wasip1.go` 尝试将标准 I/O 设置为非阻塞，但实际的行为可能仍然受到 WebAssembly 运行时的影响。使用者不应完全依赖非阻塞 I/O 的行为与传统操作系统完全一致。

总而言之，`go/src/syscall/fs_wasip1.go` 是 Go 语言在 WebAssembly 环境下与文件系统交互的桥梁，它将 Go 的文件系统操作映射到 WASI 提供的接口。理解 WASI 的概念和限制对于在该平台上编写 Go 代码至关重要。

Prompt: 
```
这是路径为go/src/syscall/fs_wasip1.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build wasip1

package syscall

import (
	"internal/stringslite"
	"runtime"
	"structs"
	"unsafe"
)

func init() {
	// Try to set stdio to non-blocking mode before the os package
	// calls NewFile for each fd. NewFile queries the non-blocking flag
	// but doesn't change it, even if the runtime supports non-blocking
	// stdio. Since WebAssembly modules are single-threaded, blocking
	// system calls temporarily halt execution of the module. If the
	// runtime supports non-blocking stdio, the Go runtime is able to
	// use the WASI net poller to poll for read/write readiness and is
	// able to schedule goroutines while waiting.
	SetNonblock(0, true)
	SetNonblock(1, true)
	SetNonblock(2, true)
}

type uintptr32 = uint32
type size = uint32
type fdflags = uint32
type filesize = uint64
type filetype = uint8
type lookupflags = uint32
type oflags = uint32
type rights = uint64
type timestamp = uint64
type dircookie = uint64
type filedelta = int64
type fstflags = uint32

type iovec struct {
	_      structs.HostLayout
	buf    uintptr32
	bufLen size
}

const (
	LOOKUP_SYMLINK_FOLLOW = 0x00000001
)

const (
	OFLAG_CREATE    = 0x0001
	OFLAG_DIRECTORY = 0x0002
	OFLAG_EXCL      = 0x0004
	OFLAG_TRUNC     = 0x0008
)

const (
	FDFLAG_APPEND   = 0x0001
	FDFLAG_DSYNC    = 0x0002
	FDFLAG_NONBLOCK = 0x0004
	FDFLAG_RSYNC    = 0x0008
	FDFLAG_SYNC     = 0x0010
)

const (
	RIGHT_FD_DATASYNC = 1 << iota
	RIGHT_FD_READ
	RIGHT_FD_SEEK
	RIGHT_FDSTAT_SET_FLAGS
	RIGHT_FD_SYNC
	RIGHT_FD_TELL
	RIGHT_FD_WRITE
	RIGHT_FD_ADVISE
	RIGHT_FD_ALLOCATE
	RIGHT_PATH_CREATE_DIRECTORY
	RIGHT_PATH_CREATE_FILE
	RIGHT_PATH_LINK_SOURCE
	RIGHT_PATH_LINK_TARGET
	RIGHT_PATH_OPEN
	RIGHT_FD_READDIR
	RIGHT_PATH_READLINK
	RIGHT_PATH_RENAME_SOURCE
	RIGHT_PATH_RENAME_TARGET
	RIGHT_PATH_FILESTAT_GET
	RIGHT_PATH_FILESTAT_SET_SIZE
	RIGHT_PATH_FILESTAT_SET_TIMES
	RIGHT_FD_FILESTAT_GET
	RIGHT_FD_FILESTAT_SET_SIZE
	RIGHT_FD_FILESTAT_SET_TIMES
	RIGHT_PATH_SYMLINK
	RIGHT_PATH_REMOVE_DIRECTORY
	RIGHT_PATH_UNLINK_FILE
	RIGHT_POLL_FD_READWRITE
	RIGHT_SOCK_SHUTDOWN
	RIGHT_SOCK_ACCEPT
)

const (
	WHENCE_SET = 0
	WHENCE_CUR = 1
	WHENCE_END = 2
)

const (
	FILESTAT_SET_ATIM     = 0x0001
	FILESTAT_SET_ATIM_NOW = 0x0002
	FILESTAT_SET_MTIM     = 0x0004
	FILESTAT_SET_MTIM_NOW = 0x0008
)

const (
	// Despite the rights being defined as a 64 bits integer in the spec,
	// wasmtime crashes the program if we set any of the upper 32 bits.
	fullRights  = rights(^uint32(0))
	readRights  = rights(RIGHT_FD_READ | RIGHT_FD_READDIR)
	writeRights = rights(RIGHT_FD_DATASYNC | RIGHT_FD_WRITE | RIGHT_FD_ALLOCATE | RIGHT_PATH_FILESTAT_SET_SIZE)

	// Some runtimes have very strict expectations when it comes to which
	// rights can be enabled on files opened by path_open. The fileRights
	// constant is used as a mask to retain only bits for operations that
	// are supported on files.
	fileRights rights = RIGHT_FD_DATASYNC |
		RIGHT_FD_READ |
		RIGHT_FD_SEEK |
		RIGHT_FDSTAT_SET_FLAGS |
		RIGHT_FD_SYNC |
		RIGHT_FD_TELL |
		RIGHT_FD_WRITE |
		RIGHT_FD_ADVISE |
		RIGHT_FD_ALLOCATE |
		RIGHT_PATH_CREATE_DIRECTORY |
		RIGHT_PATH_CREATE_FILE |
		RIGHT_PATH_LINK_SOURCE |
		RIGHT_PATH_LINK_TARGET |
		RIGHT_PATH_OPEN |
		RIGHT_FD_READDIR |
		RIGHT_PATH_READLINK |
		RIGHT_PATH_RENAME_SOURCE |
		RIGHT_PATH_RENAME_TARGET |
		RIGHT_PATH_FILESTAT_GET |
		RIGHT_PATH_FILESTAT_SET_SIZE |
		RIGHT_PATH_FILESTAT_SET_TIMES |
		RIGHT_FD_FILESTAT_GET |
		RIGHT_FD_FILESTAT_SET_SIZE |
		RIGHT_FD_FILESTAT_SET_TIMES |
		RIGHT_PATH_SYMLINK |
		RIGHT_PATH_REMOVE_DIRECTORY |
		RIGHT_PATH_UNLINK_FILE |
		RIGHT_POLL_FD_READWRITE

	// Runtimes like wasmtime and wasmedge will refuse to open directories
	// if the rights requested by the application exceed the operations that
	// can be performed on a directory.
	dirRights rights = RIGHT_FD_SEEK |
		RIGHT_FDSTAT_SET_FLAGS |
		RIGHT_FD_SYNC |
		RIGHT_PATH_CREATE_DIRECTORY |
		RIGHT_PATH_CREATE_FILE |
		RIGHT_PATH_LINK_SOURCE |
		RIGHT_PATH_LINK_TARGET |
		RIGHT_PATH_OPEN |
		RIGHT_FD_READDIR |
		RIGHT_PATH_READLINK |
		RIGHT_PATH_RENAME_SOURCE |
		RIGHT_PATH_RENAME_TARGET |
		RIGHT_PATH_FILESTAT_GET |
		RIGHT_PATH_FILESTAT_SET_SIZE |
		RIGHT_PATH_FILESTAT_SET_TIMES |
		RIGHT_FD_FILESTAT_GET |
		RIGHT_FD_FILESTAT_SET_TIMES |
		RIGHT_PATH_SYMLINK |
		RIGHT_PATH_REMOVE_DIRECTORY |
		RIGHT_PATH_UNLINK_FILE
)

// https://github.com/WebAssembly/WASI/blob/a2b96e81c0586125cc4dc79a5be0b78d9a059925/legacy/preview1/docs.md#-fd_closefd-fd---result-errno
//
//go:wasmimport wasi_snapshot_preview1 fd_close
//go:noescape
func fd_close(fd int32) Errno

// https://github.com/WebAssembly/WASI/blob/a2b96e81c0586125cc4dc79a5be0b78d9a059925/legacy/preview1/docs.md#-fd_filestat_set_sizefd-fd-size-filesize---result-errno
//
//go:wasmimport wasi_snapshot_preview1 fd_filestat_set_size
//go:noescape
func fd_filestat_set_size(fd int32, set_size filesize) Errno

// https://github.com/WebAssembly/WASI/blob/a2b96e81c0586125cc4dc79a5be0b78d9a059925/legacy/preview1/docs.md#-fd_preadfd-fd-iovs-iovec_array-offset-filesize---resultsize-errno
//
//go:wasmimport wasi_snapshot_preview1 fd_pread
//go:noescape
func fd_pread(fd int32, iovs *iovec, iovsLen size, offset filesize, nread *size) Errno

//go:wasmimport wasi_snapshot_preview1 fd_pwrite
//go:noescape
func fd_pwrite(fd int32, iovs *iovec, iovsLen size, offset filesize, nwritten *size) Errno

//go:wasmimport wasi_snapshot_preview1 fd_read
//go:noescape
func fd_read(fd int32, iovs *iovec, iovsLen size, nread *size) Errno

//go:wasmimport wasi_snapshot_preview1 fd_readdir
//go:noescape
func fd_readdir(fd int32, buf *byte, bufLen size, cookie dircookie, nwritten *size) Errno

//go:wasmimport wasi_snapshot_preview1 fd_seek
//go:noescape
func fd_seek(fd int32, offset filedelta, whence uint32, newoffset *filesize) Errno

// https://github.com/WebAssembly/WASI/blob/a2b96e81c0586125cc4dc79a5be0b78d9a059925/legacy/preview1/docs.md#-fd_fdstat_set_rightsfd-fd-fs_rights_base-rights-fs_rights_inheriting-rights---result-errno
//
//go:wasmimport wasi_snapshot_preview1 fd_fdstat_set_rights
//go:noescape
func fd_fdstat_set_rights(fd int32, rightsBase rights, rightsInheriting rights) Errno

//go:wasmimport wasi_snapshot_preview1 fd_filestat_get
//go:noescape
func fd_filestat_get(fd int32, buf unsafe.Pointer) Errno

//go:wasmimport wasi_snapshot_preview1 fd_write
//go:noescape
func fd_write(fd int32, iovs *iovec, iovsLen size, nwritten *size) Errno

//go:wasmimport wasi_snapshot_preview1 fd_sync
//go:noescape
func fd_sync(fd int32) Errno

//go:wasmimport wasi_snapshot_preview1 path_create_directory
//go:noescape
func path_create_directory(fd int32, path *byte, pathLen size) Errno

//go:wasmimport wasi_snapshot_preview1 path_filestat_get
//go:noescape
func path_filestat_get(fd int32, flags lookupflags, path *byte, pathLen size, buf unsafe.Pointer) Errno

//go:wasmimport wasi_snapshot_preview1 path_filestat_set_times
//go:noescape
func path_filestat_set_times(fd int32, flags lookupflags, path *byte, pathLen size, atim timestamp, mtim timestamp, fstflags fstflags) Errno

//go:wasmimport wasi_snapshot_preview1 path_link
//go:noescape
func path_link(oldFd int32, oldFlags lookupflags, oldPath *byte, oldPathLen size, newFd int32, newPath *byte, newPathLen size) Errno

//go:wasmimport wasi_snapshot_preview1 path_readlink
//go:noescape
func path_readlink(fd int32, path *byte, pathLen size, buf *byte, bufLen size, nwritten *size) Errno

//go:wasmimport wasi_snapshot_preview1 path_remove_directory
//go:noescape
func path_remove_directory(fd int32, path *byte, pathLen size) Errno

//go:wasmimport wasi_snapshot_preview1 path_rename
//go:noescape
func path_rename(oldFd int32, oldPath *byte, oldPathLen size, newFd int32, newPath *byte, newPathLen size) Errno

//go:wasmimport wasi_snapshot_preview1 path_symlink
//go:noescape
func path_symlink(oldPath *byte, oldPathLen size, fd int32, newPath *byte, newPathLen size) Errno

//go:wasmimport wasi_snapshot_preview1 path_unlink_file
//go:noescape
func path_unlink_file(fd int32, path *byte, pathLen size) Errno

//go:wasmimport wasi_snapshot_preview1 path_open
//go:noescape
func path_open(rootFD int32, dirflags lookupflags, path *byte, pathLen size, oflags oflags, fsRightsBase rights, fsRightsInheriting rights, fsFlags fdflags, fd *int32) Errno

//go:wasmimport wasi_snapshot_preview1 random_get
//go:noescape
func random_get(buf *byte, bufLen size) Errno

// https://github.com/WebAssembly/WASI/blob/a2b96e81c0586125cc4dc79a5be0b78d9a059925/legacy/preview1/docs.md#-fdstat-record
// fdflags must be at offset 2, hence the uint16 type rather than the
// fdflags (uint32) type.
type fdstat struct {
	_                structs.HostLayout
	filetype         filetype
	fdflags          uint16
	rightsBase       rights
	rightsInheriting rights
}

//go:wasmimport wasi_snapshot_preview1 fd_fdstat_get
//go:noescape
func fd_fdstat_get(fd int32, buf *fdstat) Errno

//go:wasmimport wasi_snapshot_preview1 fd_fdstat_set_flags
//go:noescape
func fd_fdstat_set_flags(fd int32, flags fdflags) Errno

// fd_fdstat_get_flags is accessed from internal/syscall/unix
//go:linkname fd_fdstat_get_flags

func fd_fdstat_get_flags(fd int) (uint32, error) {
	var stat fdstat
	errno := fd_fdstat_get(int32(fd), &stat)
	return uint32(stat.fdflags), errnoErr(errno)
}

// fd_fdstat_get_type is accessed from net
//go:linkname fd_fdstat_get_type

func fd_fdstat_get_type(fd int) (uint8, error) {
	var stat fdstat
	errno := fd_fdstat_get(int32(fd), &stat)
	return stat.filetype, errnoErr(errno)
}

type preopentype = uint8

const (
	preopentypeDir preopentype = iota
)

type prestatDir struct {
	_         structs.HostLayout
	prNameLen size
}

type prestat struct {
	_   structs.HostLayout
	typ preopentype
	dir prestatDir
}

//go:wasmimport wasi_snapshot_preview1 fd_prestat_get
//go:noescape
func fd_prestat_get(fd int32, prestat *prestat) Errno

//go:wasmimport wasi_snapshot_preview1 fd_prestat_dir_name
//go:noescape
func fd_prestat_dir_name(fd int32, path *byte, pathLen size) Errno

type opendir struct {
	fd   int32
	name string
}

// List of preopen directories that were exposed by the runtime. The first one
// is assumed to the be root directory of the file system, and others are seen
// as mount points at sub paths of the root.
var preopens []opendir

// Current working directory. We maintain this as a string and resolve paths in
// the code because wasmtime does not allow relative path lookups outside of the
// scope of a directory; a previous approach we tried consisted in maintaining
// open a file descriptor to the current directory so we could perform relative
// path lookups from that location, but it resulted in breaking path resolution
// from the current directory to its parent.
var cwd string

func init() {
	dirNameBuf := make([]byte, 256)
	// We start looking for preopens at fd=3 because 0, 1, and 2 are reserved
	// for standard input and outputs.
	for preopenFd := int32(3); ; preopenFd++ {
		var prestat prestat

		errno := fd_prestat_get(preopenFd, &prestat)
		if errno == EBADF {
			break
		}
		if errno == ENOTDIR || prestat.typ != preopentypeDir {
			continue
		}
		if errno != 0 {
			panic("fd_prestat: " + errno.Error())
		}
		if int(prestat.dir.prNameLen) > len(dirNameBuf) {
			dirNameBuf = make([]byte, prestat.dir.prNameLen)
		}

		errno = fd_prestat_dir_name(preopenFd, &dirNameBuf[0], prestat.dir.prNameLen)
		if errno != 0 {
			panic("fd_prestat_dir_name: " + errno.Error())
		}

		preopens = append(preopens, opendir{
			fd:   preopenFd,
			name: string(dirNameBuf[:prestat.dir.prNameLen]),
		})
	}

	if cwd, _ = Getenv("PWD"); cwd != "" {
		cwd = joinPath("/", cwd)
	} else if len(preopens) > 0 {
		cwd = preopens[0].name
	}
}

// Provided by package runtime.
func now() (sec int64, nsec int32)

//go:nosplit
func appendCleanPath(buf []byte, path string, lookupParent bool) ([]byte, bool) {
	i := 0
	for i < len(path) {
		for i < len(path) && path[i] == '/' {
			i++
		}

		j := i
		for j < len(path) && path[j] != '/' {
			j++
		}

		s := path[i:j]
		i = j

		switch s {
		case "":
			continue
		case ".":
			continue
		case "..":
			if !lookupParent {
				k := len(buf)
				for k > 0 && buf[k-1] != '/' {
					k--
				}
				for k > 1 && buf[k-1] == '/' {
					k--
				}
				buf = buf[:k]
				if k == 0 {
					lookupParent = true
				} else {
					s = ""
					continue
				}
			}
		default:
			lookupParent = false
		}

		if len(buf) > 0 && buf[len(buf)-1] != '/' {
			buf = append(buf, '/')
		}
		buf = append(buf, s...)
	}
	return buf, lookupParent
}

// joinPath concatenates dir and file paths, producing a cleaned path where
// "." and ".." have been removed, unless dir is relative and the references
// to parent directories in file represented a location relative to a parent
// of dir.
//
// This function is used for path resolution of all wasi functions expecting
// a path argument; the returned string is heap allocated, which we may want
// to optimize in the future. Instead of returning a string, the function
// could append the result to an output buffer that the functions in this
// file can manage to have allocated on the stack (e.g. initializing to a
// fixed capacity). Since it will significantly increase code complexity,
// we prefer to optimize for readability and maintainability at this time.
func joinPath(dir, file string) string {
	buf := make([]byte, 0, len(dir)+len(file)+1)
	if isAbs(dir) {
		buf = append(buf, '/')
	}
	buf, lookupParent := appendCleanPath(buf, dir, false)
	buf, _ = appendCleanPath(buf, file, lookupParent)
	// The appendCleanPath function cleans the path so it does not inject
	// references to the current directory. If both the dir and file args
	// were ".", this results in the output buffer being empty so we handle
	// this condition here.
	if len(buf) == 0 {
		buf = append(buf, '.')
	}
	// If the file ended with a '/' we make sure that the output also ends
	// with a '/'. This is needed to ensure that programs have a mechanism
	// to represent dereferencing symbolic links pointing to directories.
	if buf[len(buf)-1] != '/' && isDir(file) {
		buf = append(buf, '/')
	}
	return unsafe.String(&buf[0], len(buf))
}

func isAbs(path string) bool {
	return stringslite.HasPrefix(path, "/")
}

func isDir(path string) bool {
	return stringslite.HasSuffix(path, "/")
}

// preparePath returns the preopen file descriptor of the directory to perform
// path resolution from, along with the pair of pointer and length for the
// relative expression of path from the directory.
//
// If the path argument is not absolute, it is first appended to the current
// working directory before resolution.
func preparePath(path string) (int32, *byte, size) {
	var dirFd = int32(-1)
	var dirName string

	dir := "/"
	if !isAbs(path) {
		dir = cwd
	}
	path = joinPath(dir, path)

	for _, p := range preopens {
		if len(p.name) > len(dirName) && stringslite.HasPrefix(path, p.name) {
			dirFd, dirName = p.fd, p.name
		}
	}

	path = path[len(dirName):]
	for isAbs(path) {
		path = path[1:]
	}
	if len(path) == 0 {
		path = "."
	}

	return dirFd, unsafe.StringData(path), size(len(path))
}

func Open(path string, openmode int, perm uint32) (int, error) {
	if path == "" {
		return -1, EINVAL
	}
	dirFd, pathPtr, pathLen := preparePath(path)
	return openat(dirFd, pathPtr, pathLen, openmode, perm)
}

func Openat(dirFd int, path string, openmode int, perm uint32) (int, error) {
	return openat(int32(dirFd), unsafe.StringData(path), size(len(path)), openmode, perm)
}

func openat(dirFd int32, pathPtr *byte, pathLen size, openmode int, perm uint32) (int, error) {
	var oflags oflags
	if (openmode & O_CREATE) != 0 {
		oflags |= OFLAG_CREATE
	}
	if (openmode & O_TRUNC) != 0 {
		oflags |= OFLAG_TRUNC
	}
	if (openmode & O_EXCL) != 0 {
		oflags |= OFLAG_EXCL
	}

	var rights rights
	switch openmode & (O_RDONLY | O_WRONLY | O_RDWR) {
	case O_RDONLY:
		rights = fileRights & ^writeRights
	case O_WRONLY:
		rights = fileRights & ^readRights
	case O_RDWR:
		rights = fileRights
	}

	if (openmode & O_DIRECTORY) != 0 {
		if openmode&(O_WRONLY|O_RDWR) != 0 {
			return -1, EISDIR
		}
		oflags |= OFLAG_DIRECTORY
		rights &= dirRights
	}

	var fdflags fdflags
	if (openmode & O_APPEND) != 0 {
		fdflags |= FDFLAG_APPEND
	}
	if (openmode & O_SYNC) != 0 {
		fdflags |= FDFLAG_SYNC
	}

	var lflags lookupflags
	if openmode&O_NOFOLLOW == 0 {
		lflags = LOOKUP_SYMLINK_FOLLOW
	}

	var fd int32
	errno := path_open(
		dirFd,
		lflags,
		pathPtr,
		pathLen,
		oflags,
		rights,
		fileRights,
		fdflags,
		&fd,
	)
	if errno == EISDIR && oflags == 0 && fdflags == 0 && ((rights & writeRights) == 0) {
		// wasmtime and wasmedge will error if attempting to open a directory
		// because we are asking for too many rights. However, we cannot
		// determine ahead of time if the path we are about to open is a
		// directory, so instead we fallback to a second call to path_open with
		// a more limited set of rights.
		//
		// This approach is subject to a race if the file system is modified
		// concurrently, so we also inject OFLAG_DIRECTORY to ensure that we do
		// not accidentally open a file which is not a directory.
		errno = path_open(
			dirFd,
			LOOKUP_SYMLINK_FOLLOW,
			pathPtr,
			pathLen,
			oflags|OFLAG_DIRECTORY,
			rights&dirRights,
			fileRights,
			fdflags,
			&fd,
		)
	}
	return int(fd), errnoErr(errno)
}

func Close(fd int) error {
	errno := fd_close(int32(fd))
	return errnoErr(errno)
}

func CloseOnExec(fd int) {
	// nothing to do - no exec
}

func Mkdir(path string, perm uint32) error {
	if path == "" {
		return EINVAL
	}
	dirFd, pathPtr, pathLen := preparePath(path)
	errno := path_create_directory(dirFd, pathPtr, pathLen)
	return errnoErr(errno)
}

func ReadDir(fd int, buf []byte, cookie dircookie) (int, error) {
	var nwritten size
	errno := fd_readdir(int32(fd), &buf[0], size(len(buf)), cookie, &nwritten)
	return int(nwritten), errnoErr(errno)
}

type Stat_t struct {
	Dev      uint64
	Ino      uint64
	Filetype uint8
	Nlink    uint64
	Size     uint64
	Atime    uint64
	Mtime    uint64
	Ctime    uint64

	Mode int

	// Uid and Gid are always zero on wasip1 platforms
	Uid uint32
	Gid uint32
}

func Stat(path string, st *Stat_t) error {
	if path == "" {
		return EINVAL
	}
	dirFd, pathPtr, pathLen := preparePath(path)
	errno := path_filestat_get(dirFd, LOOKUP_SYMLINK_FOLLOW, pathPtr, pathLen, unsafe.Pointer(st))
	setDefaultMode(st)
	return errnoErr(errno)
}

func Lstat(path string, st *Stat_t) error {
	if path == "" {
		return EINVAL
	}
	dirFd, pathPtr, pathLen := preparePath(path)
	errno := path_filestat_get(dirFd, 0, pathPtr, pathLen, unsafe.Pointer(st))
	setDefaultMode(st)
	return errnoErr(errno)
}

func Fstat(fd int, st *Stat_t) error {
	errno := fd_filestat_get(int32(fd), unsafe.Pointer(st))
	setDefaultMode(st)
	return errnoErr(errno)
}

func setDefaultMode(st *Stat_t) {
	// WASI does not support unix-like permissions, but Go programs are likely
	// to expect the permission bits to not be zero so we set defaults to help
	// avoid breaking applications that are migrating to WASM.
	if st.Filetype == FILETYPE_DIRECTORY {
		st.Mode = 0700
	} else {
		st.Mode = 0600
	}
}

func Unlink(path string) error {
	if path == "" {
		return EINVAL
	}
	dirFd, pathPtr, pathLen := preparePath(path)
	errno := path_unlink_file(dirFd, pathPtr, pathLen)
	return errnoErr(errno)
}

func Rmdir(path string) error {
	if path == "" {
		return EINVAL
	}
	dirFd, pathPtr, pathLen := preparePath(path)
	errno := path_remove_directory(dirFd, pathPtr, pathLen)
	return errnoErr(errno)
}

func Chmod(path string, mode uint32) error {
	var stat Stat_t
	return Stat(path, &stat)
}

func Fchmod(fd int, mode uint32) error {
	var stat Stat_t
	return Fstat(fd, &stat)
}

func Chown(path string, uid, gid int) error {
	return ENOSYS
}

func Fchown(fd int, uid, gid int) error {
	return ENOSYS
}

func Lchown(path string, uid, gid int) error {
	return ENOSYS
}

func UtimesNano(path string, ts []Timespec) error {
	// UTIME_OMIT value must match internal/syscall/unix/at_wasip1.go
	const UTIME_OMIT = -0x2
	if path == "" {
		return EINVAL
	}
	dirFd, pathPtr, pathLen := preparePath(path)
	atime := TimespecToNsec(ts[0])
	mtime := TimespecToNsec(ts[1])
	if ts[0].Nsec == UTIME_OMIT || ts[1].Nsec == UTIME_OMIT {
		var st Stat_t
		if err := Stat(path, &st); err != nil {
			return err
		}
		if ts[0].Nsec == UTIME_OMIT {
			atime = int64(st.Atime)
		}
		if ts[1].Nsec == UTIME_OMIT {
			mtime = int64(st.Mtime)
		}
	}
	errno := path_filestat_set_times(
		dirFd,
		LOOKUP_SYMLINK_FOLLOW,
		pathPtr,
		pathLen,
		timestamp(atime),
		timestamp(mtime),
		FILESTAT_SET_ATIM|FILESTAT_SET_MTIM,
	)
	return errnoErr(errno)
}

func Rename(from, to string) error {
	if from == "" || to == "" {
		return EINVAL
	}
	oldDirFd, oldPathPtr, oldPathLen := preparePath(from)
	newDirFd, newPathPtr, newPathLen := preparePath(to)
	errno := path_rename(
		oldDirFd,
		oldPathPtr,
		oldPathLen,
		newDirFd,
		newPathPtr,
		newPathLen,
	)
	return errnoErr(errno)
}

func Truncate(path string, length int64) error {
	if path == "" {
		return EINVAL
	}
	fd, err := Open(path, O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer Close(fd)
	return Ftruncate(fd, length)
}

func Ftruncate(fd int, length int64) error {
	errno := fd_filestat_set_size(int32(fd), filesize(length))
	return errnoErr(errno)
}

const ImplementsGetwd = true

func Getwd() (string, error) {
	return cwd, nil
}

func Chdir(path string) error {
	if path == "" {
		return EINVAL
	}

	dir := "/"
	if !isAbs(path) {
		dir = cwd
	}
	path = joinPath(dir, path)

	var stat Stat_t
	dirFd, pathPtr, pathLen := preparePath(path)
	errno := path_filestat_get(dirFd, LOOKUP_SYMLINK_FOLLOW, pathPtr, pathLen, unsafe.Pointer(&stat))
	if errno != 0 {
		return errnoErr(errno)
	}
	if stat.Filetype != FILETYPE_DIRECTORY {
		return ENOTDIR
	}
	cwd = path
	return nil
}

func Readlink(path string, buf []byte) (n int, err error) {
	if path == "" {
		return 0, EINVAL
	}
	if len(buf) == 0 {
		return 0, nil
	}
	dirFd, pathPtr, pathLen := preparePath(path)
	var nwritten size
	errno := path_readlink(
		dirFd,
		pathPtr,
		pathLen,
		&buf[0],
		size(len(buf)),
		&nwritten,
	)
	// For some reason wasmtime returns ERANGE when the output buffer is
	// shorter than the symbolic link value. os.Readlink expects a nil
	// error and uses the fact that n is greater or equal to the buffer
	// length to assume that it needs to try again with a larger size.
	// This condition is handled in os.Readlink.
	return int(nwritten), errnoErr(errno)
}

func Link(path, link string) error {
	if path == "" || link == "" {
		return EINVAL
	}
	oldDirFd, oldPathPtr, oldPathLen := preparePath(path)
	newDirFd, newPathPtr, newPathLen := preparePath(link)
	errno := path_link(
		oldDirFd,
		0,
		oldPathPtr,
		oldPathLen,
		newDirFd,
		newPathPtr,
		newPathLen,
	)
	return errnoErr(errno)
}

func Symlink(path, link string) error {
	if path == "" || link == "" {
		return EINVAL
	}
	dirFd, pathPtr, pathlen := preparePath(link)
	errno := path_symlink(
		unsafe.StringData(path),
		size(len(path)),
		dirFd,
		pathPtr,
		pathlen,
	)
	return errnoErr(errno)
}

func Fsync(fd int) error {
	errno := fd_sync(int32(fd))
	return errnoErr(errno)
}

func makeIOVec(b []byte) *iovec {
	return &iovec{
		buf:    uintptr32(uintptr(unsafe.Pointer(unsafe.SliceData(b)))),
		bufLen: size(len(b)),
	}
}

func Read(fd int, b []byte) (int, error) {
	var nread size
	errno := fd_read(int32(fd), makeIOVec(b), 1, &nread)
	runtime.KeepAlive(b)
	return int(nread), errnoErr(errno)
}

func Write(fd int, b []byte) (int, error) {
	var nwritten size
	errno := fd_write(int32(fd), makeIOVec(b), 1, &nwritten)
	runtime.KeepAlive(b)
	return int(nwritten), errnoErr(errno)
}

func Pread(fd int, b []byte, offset int64) (int, error) {
	var nread size
	errno := fd_pread(int32(fd), makeIOVec(b), 1, filesize(offset), &nread)
	runtime.KeepAlive(b)
	return int(nread), errnoErr(errno)
}

func Pwrite(fd int, b []byte, offset int64) (int, error) {
	var nwritten size
	errno := fd_pwrite(int32(fd), makeIOVec(b), 1, filesize(offset), &nwritten)
	runtime.KeepAlive(b)
	return int(nwritten), errnoErr(errno)
}

func Seek(fd int, offset int64, whence int) (int64, error) {
	var newoffset filesize
	errno := fd_seek(int32(fd), filedelta(offset), uint32(whence), &newoffset)
	return int64(newoffset), errnoErr(errno)
}

func Dup(fd int) (int, error) {
	return 0, ENOSYS
}

func Dup2(fd, newfd int) error {
	return ENOSYS
}

func Pipe(fd []int) error {
	return ENOSYS
}

func RandomGet(b []byte) error {
	errno := random_get(unsafe.SliceData(b), size(len(b)))
	return errnoErr(errno)
}

"""



```