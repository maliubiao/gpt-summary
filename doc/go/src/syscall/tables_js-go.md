Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding and Context:**

* **Language:** The code is in Go. This immediately tells us about syntax, conventions, and standard library usage.
* **Path:** `go/src/syscall/tables_js.go`. This is a key piece of information. The `syscall` package deals with low-level operating system interactions. The `_js` suffix strongly suggests this is a platform-specific implementation, specifically for JavaScript/Wasm environments.
* **`//go:build js && wasm`:** This build constraint confirms that this code is only compiled when the target operating system is `js` and the architecture is `wasm`. This reinforces the platform-specific nature.
* **`package syscall`:** This confirms the package's purpose.

**2. Core Components Analysis:**

* **Constants (`sys_...`)**:  These look like system call numbers. The comment "These were originally used by Nacl, then later also used by js/wasm" provides historical context. The "TODO: delete? replace with something meaningful?" indicates these might be legacy and could be refactored. The key takeaway is that these constants represent identifiers for specific OS-level operations.
* **Constants (`E...`)**: These clearly represent error numbers, consistent with standard Unix/Linux error codes. The comment points to their origin in Native Client's `errno.h`.
* **Variable `errorstr`**: This is an array of strings, indexed by `Errno` values, providing human-readable descriptions for each error code. The comment mentioning `runtime.GOOS` suggests platform-specific error messages might be considered in the future.
* **Variables (`errEAGAIN`, `errEINVAL`, `errENOENT`)**: These are pre-allocated error variables. The comment suggests this is for optimization to reduce runtime allocations.
* **Function `errnoErr(e Errno) error`**: This function takes an `Errno` and returns an `error` interface. It seems to be a utility for converting `Errno` values to standard Go errors, with special handling for common errors to avoid allocations.
* **Variable `errnoByCode`**: This is a map that associates string representations of error codes (e.g., "EPERM") with their corresponding `Errno` values. This allows looking up error codes by their string names.

**3. Inferring Functionality and Go Feature:**

Based on the identified components, the core functionality is clear: **This file defines the mapping between symbolic names and numeric values for system calls and error codes specific to the JavaScript/Wasm environment in Go.**

The Go language feature being implemented is the **`syscall` package's interface for interacting with the underlying "operating system" (in this case, the JS/Wasm runtime environment).**  Since JS/Wasm doesn't have a traditional OS kernel, these system call numbers are essentially calls into the Go runtime or the underlying JavaScript environment.

**4. Code Example Construction (and dealing with uncertainty):**

Since the system call numbers are internal and not directly exposed for typical Go development, a *direct* example of calling `sys_open` with the number `10` is not how users interact with this. Instead, users would use higher-level functions in the `os` package or other standard library components that *internally* rely on these syscall mappings.

Therefore, the example needs to illustrate a scenario where these underlying mappings are used. File I/O is a prime example:

* **Hypothesis:**  The `sys_open` constant likely corresponds to the internal implementation of `os.Open`.
* **Example:** Demonstrate opening a file. The *input* is the file path. The *output* is either a file object or an error. The error case is particularly relevant as it might involve the `Errno` constants.

**5. Command-Line Arguments and Error Handling:**

Since this file deals with internal mappings, it doesn't directly handle command-line arguments. However, *applications* using the `os` package will handle command-line arguments that might lead to these syscalls being invoked.

The error handling aspect is more direct. The `Errno` constants and the `errnoErr` function are explicitly for error handling. The example of a non-existent file highlights how an error defined in this file (`ENOENT`) would be propagated.

**6. Common Mistakes:**

The key mistake users could make is trying to *directly* use these `sys_...` constants or manipulate `Errno` values without going through the standard library. The example shows how the standard library provides a safer and more abstract interface.

**7. Refinement and Language:**

Throughout this process, it's important to use clear and precise language. Emphasize the platform-specific nature, the internal role of the file, and the distinction between internal implementation details and the user-facing standard library. Using phrases like "it's highly probable," "likely," and "under the hood" acknowledges that we're inferring some behavior based on the code structure and context.

By following these steps, we can effectively analyze the provided Go code snippet and generate a comprehensive explanation.
这个文件 `go/src/syscall/tables_js.go` 是 Go 语言标准库中 `syscall` 包的一部分，专门用于 `js` 和 `wasm` 平台。它的主要功能是：

**1. 定义了针对 JavaScript/Wasm 环境的系统调用号 (System Call Numbers):**

   - 文件中定义了一系列常量，以 `sys_` 开头，例如 `sys_open`, `sys_read`, `sys_write` 等。
   - 这些常量代表了在 JavaScript/Wasm 虚拟机中模拟的操作系统调用。
   - 与传统的操作系统不同，JavaScript/Wasm 环境并没有直接的操作系统内核，这些系统调用实际上是 Go 的运行时 (runtime) 或浏览器提供的 API 的桥梁。
   - 注释中提到，这些数字最初用于 Native Client (Nacl)，后来被 JavaScript/Wasm 沿用。目前它们的数值是任意的，将来可能会被更有意义的值替换。

**2. 定义了针对 JavaScript/Wasm 环境的错误码 (Error Codes):**

   - 文件中定义了以 `E` 开头的常量，例如 `EPERM`, `ENOENT`, `EAGAIN` 等。
   - 这些常量对应着在进行系统调用时可能出现的错误。
   - 这些错误码主要来源于 Linux 的错误码定义。

**3. 提供了错误码到错误字符串的映射:**

   - 变量 `errorstr` 是一个字符串数组，它的索引对应着 `Errno` 类型（实际上是 `int`），存储着对应的错误描述信息。
   - 这使得 Go 程序可以将底层的数字错误码转换为更易读的错误信息。

**4. 提供了便捷的 `Errno` 到 `error` 接口的转换:**

   - 函数 `errnoErr(e Errno) error` 用于将 `Errno` 类型的错误码转换为 Go 的 `error` 接口。
   - 为了性能优化，对于一些常见的错误码（例如 `EAGAIN`, `EINVAL`, `ENOENT`），使用了预先分配的 `error` 变量，避免了运行时的内存分配。

**5. 提供了错误码字符串到 `Errno` 的映射:**

   - 变量 `errnoByCode` 是一个 `map[string]Errno`，用于将错误码的字符串表示（例如 "EPERM"）映射回对应的 `Errno` 值。

**它是什么 Go 语言功能的实现？**

这个文件是 Go 语言 `syscall` 包针对 JavaScript/Wasm 平台进行适配和实现的关键部分。`syscall` 包提供了与操作系统底层交互的能力，但在不同的操作系统上，这些交互的方式和具体实现是不同的。  在 JavaScript/Wasm 环境中，并没有真正的操作系统内核，所以 `syscall` 包的实现需要模拟这些系统调用。

**Go 代码举例说明:**

虽然用户通常不会直接使用 `sys_open` 这样的常量，而是会使用更高级别的 Go 标准库，例如 `os` 包中的函数。  `os` 包的函数在 `js/wasm` 平台上会间接地使用这里定义的系统调用号。

假设我们想在 JavaScript/Wasm 环境中打开一个文件：

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	f, err := os.Open("myfile.txt")
	if err != nil {
		// 这里的 err 可能是由 syscall 包中的错误码转换而来
		fmt.Println("Error opening file:", err)
		return
	}
	defer f.Close()

	fmt.Println("File opened successfully.")
}
```

**假设的输入与输出：**

* **假设输入 1：**  当前目录下存在名为 `myfile.txt` 的文件。
* **假设输出 1：**  程序会输出 "File opened successfully."

* **假设输入 2：** 当前目录下不存在名为 `myfile.txt` 的文件。
* **假设输出 2：** 程序可能会输出类似 "Error opening file: syscall: no such file or directory" 的错误信息。这里的 "syscall: no such file or directory" 就是由 `syscall` 包中的 `ENOENT` 错误码转换而来的。

**代码推理：**

当 `os.Open("myfile.txt")` 在 `js/wasm` 环境中被调用时，它底层的实现会涉及到调用与 `sys_open` 相对应的 JavaScript/Wasm 的运行时或浏览器 API。如果文件不存在，底层的 API 会返回一个表示 "文件不存在" 的错误，这个错误会被转换为 `syscall.ENOENT`。 `os` 包会将这个 `syscall.ENOENT` 通过 `errnoErr` 函数转换为一个实现了 `error` 接口的对象，并返回给用户。

**命令行参数的具体处理:**

这个文件本身不涉及命令行参数的处理。命令行参数的处理通常发生在 `main` 函数所在的包中，然后通过调用 `os` 包或者其他处理文件和 I/O 的标准库来间接触发这里定义的系统调用。

例如，一个读取文件内容的命令行程序：

```go
package main

import (
	"fmt"
	"io/ioutil"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: myprogram <filename>")
		os.Exit(1)
	}

	filename := os.Args[1]
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("Error reading file:", err)
		os.Exit(1)
	}
	fmt.Println("File content:\n", string(content))
}
```

在这个例子中，命令行参数 `<filename>` 被传递给 `os.Args`。  `ioutil.ReadFile` 内部会使用 `os.Open` 和 `os.Read` 等函数，这些函数在 `js/wasm` 平台上会依赖于 `tables_js.go` 中定义的系统调用号和错误码。

**使用者易犯错的点:**

虽然用户不会直接操作 `tables_js.go` 中的常量，但理解其背后的含义有助于理解 `js/wasm` 环境下 Go 程序的行为：

1. **误解系统调用的真实含义:**  在传统的操作系统中，系统调用是直接与内核交互。但在 JavaScript/Wasm 中，这些 "系统调用" 实际上是对 Go 运行时或浏览器提供的功能的封装。因此，某些系统调用的行为可能与传统操作系统有所不同或存在限制。例如，直接操作硬件资源的系统调用在 WebAssembly 中通常是不存在的。

2. **期望所有系统调用都可用:**  并非所有传统的操作系统系统调用都在 JavaScript/Wasm 环境中得到了支持。  Go 在 `js/wasm` 平台上的 `syscall` 包只实现了那些在该环境下有意义或可以模拟的系统调用。如果尝试使用未实现的系统调用，将会得到 `ENOSYS` 错误（"Function not implemented"）。

   **举例：** 尝试使用一些底层的网络相关的系统调用，例如 `socket` 或 `bind`，在纯粹的 WebAssembly 环境中可能无法直接工作，需要通过浏览器提供的 Web API 进行间接实现。

3. **混淆错误码的来源:**  虽然 `tables_js.go` 中的错误码很大程度上来源于 Linux，但在 JavaScript/Wasm 环境中，实际的错误可能来自浏览器或 Go 的运行时。理解错误码的来源有助于更好地诊断问题。

总而言之，`go/src/syscall/tables_js.go` 是 Go 在 JavaScript/Wasm 平台上实现底层系统交互的关键组成部分，它定义了系统调用号、错误码以及相关的映射关系，使得 Go 程序可以在这个特殊的运行时环境中进行文件操作、时间获取、线程管理等基本操作。 用户通常不会直接使用这个文件中的常量，而是通过 Go 的标准库间接地使用其功能。

Prompt: 
```
这是路径为go/src/syscall/tables_js.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build js && wasm

package syscall

import "runtime"

// These were originally used by Nacl, then later also used by
// js/wasm. Now that they're only used by js/wasm, these numbers are
// just arbitrary.
//
// TODO: delete? replace with something meaningful?
const (
	sys_null                 = 1
	sys_nameservice          = 2
	sys_dup                  = 8
	sys_dup2                 = 9
	sys_open                 = 10
	sys_close                = 11
	sys_read                 = 12
	sys_write                = 13
	sys_lseek                = 14
	sys_stat                 = 16
	sys_fstat                = 17
	sys_chmod                = 18
	sys_isatty               = 19
	sys_brk                  = 20
	sys_mmap                 = 21
	sys_munmap               = 22
	sys_getdents             = 23
	sys_mprotect             = 24
	sys_list_mappings        = 25
	sys_exit                 = 30
	sys_getpid               = 31
	sys_sched_yield          = 32
	sys_sysconf              = 33
	sys_gettimeofday         = 40
	sys_clock                = 41
	sys_nanosleep            = 42
	sys_clock_getres         = 43
	sys_clock_gettime        = 44
	sys_mkdir                = 45
	sys_rmdir                = 46
	sys_chdir                = 47
	sys_getcwd               = 48
	sys_unlink               = 49
	sys_imc_makeboundsock    = 60
	sys_imc_accept           = 61
	sys_imc_connect          = 62
	sys_imc_sendmsg          = 63
	sys_imc_recvmsg          = 64
	sys_imc_mem_obj_create   = 65
	sys_imc_socketpair       = 66
	sys_mutex_create         = 70
	sys_mutex_lock           = 71
	sys_mutex_trylock        = 72
	sys_mutex_unlock         = 73
	sys_cond_create          = 74
	sys_cond_wait            = 75
	sys_cond_signal          = 76
	sys_cond_broadcast       = 77
	sys_cond_timed_wait_abs  = 79
	sys_thread_create        = 80
	sys_thread_exit          = 81
	sys_tls_init             = 82
	sys_thread_nice          = 83
	sys_tls_get              = 84
	sys_second_tls_set       = 85
	sys_second_tls_get       = 86
	sys_exception_handler    = 87
	sys_exception_stack      = 88
	sys_exception_clear_flag = 89
	sys_sem_create           = 100
	sys_sem_wait             = 101
	sys_sem_post             = 102
	sys_sem_get_value        = 103
	sys_dyncode_create       = 104
	sys_dyncode_modify       = 105
	sys_dyncode_delete       = 106
	sys_test_infoleak        = 109
	sys_test_crash           = 110
	sys_test_syscall_1       = 111
	sys_test_syscall_2       = 112
	sys_futex_wait_abs       = 120
	sys_futex_wake           = 121
	sys_pread                = 130
	sys_pwrite               = 131
	sys_truncate             = 140
	sys_lstat                = 141
	sys_link                 = 142
	sys_rename               = 143
	sys_symlink              = 144
	sys_access               = 145
	sys_readlink             = 146
	sys_utimes               = 147
	sys_get_random_bytes     = 150
)

// TODO: Auto-generate some day. (Hard-coded in binaries so not likely to change.)
const (
	// native_client/src/trusted/service_runtime/include/sys/errno.h
	// The errors are mainly copied from Linux.
	EPERM           Errno = 1       /* Operation not permitted */
	ENOENT          Errno = 2       /* No such file or directory */
	ESRCH           Errno = 3       /* No such process */
	EINTR           Errno = 4       /* Interrupted system call */
	EIO             Errno = 5       /* I/O error */
	ENXIO           Errno = 6       /* No such device or address */
	E2BIG           Errno = 7       /* Argument list too long */
	ENOEXEC         Errno = 8       /* Exec format error */
	EBADF           Errno = 9       /* Bad file number */
	ECHILD          Errno = 10      /* No child processes */
	EAGAIN          Errno = 11      /* Try again */
	ENOMEM          Errno = 12      /* Out of memory */
	EACCES          Errno = 13      /* Permission denied */
	EFAULT          Errno = 14      /* Bad address */
	EBUSY           Errno = 16      /* Device or resource busy */
	EEXIST          Errno = 17      /* File exists */
	EXDEV           Errno = 18      /* Cross-device link */
	ENODEV          Errno = 19      /* No such device */
	ENOTDIR         Errno = 20      /* Not a directory */
	EISDIR          Errno = 21      /* Is a directory */
	EINVAL          Errno = 22      /* Invalid argument */
	ENFILE          Errno = 23      /* File table overflow */
	EMFILE          Errno = 24      /* Too many open files */
	ENOTTY          Errno = 25      /* Not a typewriter */
	EFBIG           Errno = 27      /* File too large */
	ENOSPC          Errno = 28      /* No space left on device */
	ESPIPE          Errno = 29      /* Illegal seek */
	EROFS           Errno = 30      /* Read-only file system */
	EMLINK          Errno = 31      /* Too many links */
	EPIPE           Errno = 32      /* Broken pipe */
	ENAMETOOLONG    Errno = 36      /* File name too long */
	ENOSYS          Errno = 38      /* Function not implemented */
	EDQUOT          Errno = 122     /* Quota exceeded */
	EDOM            Errno = 33      /* Math arg out of domain of func */
	ERANGE          Errno = 34      /* Math result not representable */
	EDEADLK         Errno = 35      /* Deadlock condition */
	ENOLCK          Errno = 37      /* No record locks available */
	ENOTEMPTY       Errno = 39      /* Directory not empty */
	ELOOP           Errno = 40      /* Too many symbolic links */
	ENOMSG          Errno = 42      /* No message of desired type */
	EIDRM           Errno = 43      /* Identifier removed */
	ECHRNG          Errno = 44      /* Channel number out of range */
	EL2NSYNC        Errno = 45      /* Level 2 not synchronized */
	EL3HLT          Errno = 46      /* Level 3 halted */
	EL3RST          Errno = 47      /* Level 3 reset */
	ELNRNG          Errno = 48      /* Link number out of range */
	EUNATCH         Errno = 49      /* Protocol driver not attached */
	ENOCSI          Errno = 50      /* No CSI structure available */
	EL2HLT          Errno = 51      /* Level 2 halted */
	EBADE           Errno = 52      /* Invalid exchange */
	EBADR           Errno = 53      /* Invalid request descriptor */
	EXFULL          Errno = 54      /* Exchange full */
	ENOANO          Errno = 55      /* No anode */
	EBADRQC         Errno = 56      /* Invalid request code */
	EBADSLT         Errno = 57      /* Invalid slot */
	EDEADLOCK       Errno = EDEADLK /* File locking deadlock error */
	EBFONT          Errno = 59      /* Bad font file fmt */
	ENOSTR          Errno = 60      /* Device not a stream */
	ENODATA         Errno = 61      /* No data (for no delay io) */
	ETIME           Errno = 62      /* Timer expired */
	ENOSR           Errno = 63      /* Out of streams resources */
	ENONET          Errno = 64      /* Machine is not on the network */
	ENOPKG          Errno = 65      /* Package not installed */
	EREMOTE         Errno = 66      /* The object is remote */
	ENOLINK         Errno = 67      /* The link has been severed */
	EADV            Errno = 68      /* Advertise error */
	ESRMNT          Errno = 69      /* Srmount error */
	ECOMM           Errno = 70      /* Communication error on send */
	EPROTO          Errno = 71      /* Protocol error */
	EMULTIHOP       Errno = 72      /* Multihop attempted */
	EDOTDOT         Errno = 73      /* Cross mount point (not really error) */
	EBADMSG         Errno = 74      /* Trying to read unreadable message */
	EOVERFLOW       Errno = 75      /* Value too large for defined data type */
	ENOTUNIQ        Errno = 76      /* Given log. name not unique */
	EBADFD          Errno = 77      /* f.d. invalid for this operation */
	EREMCHG         Errno = 78      /* Remote address changed */
	ELIBACC         Errno = 79      /* Can't access a needed shared lib */
	ELIBBAD         Errno = 80      /* Accessing a corrupted shared lib */
	ELIBSCN         Errno = 81      /* .lib section in a.out corrupted */
	ELIBMAX         Errno = 82      /* Attempting to link in too many libs */
	ELIBEXEC        Errno = 83      /* Attempting to exec a shared library */
	EILSEQ          Errno = 84
	EUSERS          Errno = 87
	ENOTSOCK        Errno = 88  /* Socket operation on non-socket */
	EDESTADDRREQ    Errno = 89  /* Destination address required */
	EMSGSIZE        Errno = 90  /* Message too long */
	EPROTOTYPE      Errno = 91  /* Protocol wrong type for socket */
	ENOPROTOOPT     Errno = 92  /* Protocol not available */
	EPROTONOSUPPORT Errno = 93  /* Unknown protocol */
	ESOCKTNOSUPPORT Errno = 94  /* Socket type not supported */
	EOPNOTSUPP      Errno = 95  /* Operation not supported on transport endpoint */
	EPFNOSUPPORT    Errno = 96  /* Protocol family not supported */
	EAFNOSUPPORT    Errno = 97  /* Address family not supported by protocol family */
	EADDRINUSE      Errno = 98  /* Address already in use */
	EADDRNOTAVAIL   Errno = 99  /* Address not available */
	ENETDOWN        Errno = 100 /* Network interface is not configured */
	ENETUNREACH     Errno = 101 /* Network is unreachable */
	ENETRESET       Errno = 102
	ECONNABORTED    Errno = 103 /* Connection aborted */
	ECONNRESET      Errno = 104 /* Connection reset by peer */
	ENOBUFS         Errno = 105 /* No buffer space available */
	EISCONN         Errno = 106 /* Socket is already connected */
	ENOTCONN        Errno = 107 /* Socket is not connected */
	ESHUTDOWN       Errno = 108 /* Can't send after socket shutdown */
	ETOOMANYREFS    Errno = 109
	ETIMEDOUT       Errno = 110 /* Connection timed out */
	ECONNREFUSED    Errno = 111 /* Connection refused */
	EHOSTDOWN       Errno = 112 /* Host is down */
	EHOSTUNREACH    Errno = 113 /* Host is unreachable */
	EALREADY        Errno = 114 /* Socket already connected */
	EINPROGRESS     Errno = 115 /* Connection already in progress */
	ESTALE          Errno = 116
	ENOTSUP         Errno = EOPNOTSUPP /* Not supported */
	ENOMEDIUM       Errno = 123        /* No medium (in tape drive) */
	ECANCELED       Errno = 125        /* Operation canceled. */
	ELBIN           Errno = 2048       /* Inode is remote (not really error) */
	EFTYPE          Errno = 2049       /* Inappropriate file type or format */
	ENMFILE         Errno = 2050       /* No more files */
	EPROCLIM        Errno = 2051
	ENOSHARE        Errno = 2052   /* No such host or network path */
	ECASECLASH      Errno = 2053   /* Filename exists with different case */
	EWOULDBLOCK     Errno = EAGAIN /* Operation would block */
)

// TODO: Auto-generate some day. (Hard-coded in binaries so not likely to change.)
var errorstr = [...]string{
	EPERM:           "Operation not permitted",
	ENOENT:          "No such file or directory",
	ESRCH:           "No such process",
	EINTR:           "Interrupted system call",
	EIO:             "I/O error",
	ENXIO:           "No such device or address",
	E2BIG:           "Argument list too long",
	ENOEXEC:         "Exec format error",
	EBADF:           "Bad file number",
	ECHILD:          "No child processes",
	EAGAIN:          "Try again",
	ENOMEM:          "Out of memory",
	EACCES:          "Permission denied",
	EFAULT:          "Bad address",
	EBUSY:           "Device or resource busy",
	EEXIST:          "File exists",
	EXDEV:           "Cross-device link",
	ENODEV:          "No such device",
	ENOTDIR:         "Not a directory",
	EISDIR:          "Is a directory",
	EINVAL:          "Invalid argument",
	ENFILE:          "File table overflow",
	EMFILE:          "Too many open files",
	ENOTTY:          "Not a typewriter",
	EFBIG:           "File too large",
	ENOSPC:          "No space left on device",
	ESPIPE:          "Illegal seek",
	EROFS:           "Read-only file system",
	EMLINK:          "Too many links",
	EPIPE:           "Broken pipe",
	ENAMETOOLONG:    "File name too long",
	ENOSYS:          "not implemented on " + runtime.GOOS,
	EDQUOT:          "Quota exceeded",
	EDOM:            "Math arg out of domain of func",
	ERANGE:          "Math result not representable",
	EDEADLK:         "Deadlock condition",
	ENOLCK:          "No record locks available",
	ENOTEMPTY:       "Directory not empty",
	ELOOP:           "Too many symbolic links",
	ENOMSG:          "No message of desired type",
	EIDRM:           "Identifier removed",
	ECHRNG:          "Channel number out of range",
	EL2NSYNC:        "Level 2 not synchronized",
	EL3HLT:          "Level 3 halted",
	EL3RST:          "Level 3 reset",
	ELNRNG:          "Link number out of range",
	EUNATCH:         "Protocol driver not attached",
	ENOCSI:          "No CSI structure available",
	EL2HLT:          "Level 2 halted",
	EBADE:           "Invalid exchange",
	EBADR:           "Invalid request descriptor",
	EXFULL:          "Exchange full",
	ENOANO:          "No anode",
	EBADRQC:         "Invalid request code",
	EBADSLT:         "Invalid slot",
	EBFONT:          "Bad font file fmt",
	ENOSTR:          "Device not a stream",
	ENODATA:         "No data (for no delay io)",
	ETIME:           "Timer expired",
	ENOSR:           "Out of streams resources",
	ENONET:          "Machine is not on the network",
	ENOPKG:          "Package not installed",
	EREMOTE:         "The object is remote",
	ENOLINK:         "The link has been severed",
	EADV:            "Advertise error",
	ESRMNT:          "Srmount error",
	ECOMM:           "Communication error on send",
	EPROTO:          "Protocol error",
	EMULTIHOP:       "Multihop attempted",
	EDOTDOT:         "Cross mount point (not really error)",
	EBADMSG:         "Trying to read unreadable message",
	EOVERFLOW:       "Value too large for defined data type",
	ENOTUNIQ:        "Given log. name not unique",
	EBADFD:          "f.d. invalid for this operation",
	EREMCHG:         "Remote address changed",
	ELIBACC:         "Can't access a needed shared lib",
	ELIBBAD:         "Accessing a corrupted shared lib",
	ELIBSCN:         ".lib section in a.out corrupted",
	ELIBMAX:         "Attempting to link in too many libs",
	ELIBEXEC:        "Attempting to exec a shared library",
	ENOTSOCK:        "Socket operation on non-socket",
	EDESTADDRREQ:    "Destination address required",
	EMSGSIZE:        "Message too long",
	EPROTOTYPE:      "Protocol wrong type for socket",
	ENOPROTOOPT:     "Protocol not available",
	EPROTONOSUPPORT: "Unknown protocol",
	ESOCKTNOSUPPORT: "Socket type not supported",
	EOPNOTSUPP:      "Operation not supported on transport endpoint",
	EPFNOSUPPORT:    "Protocol family not supported",
	EAFNOSUPPORT:    "Address family not supported by protocol family",
	EADDRINUSE:      "Address already in use",
	EADDRNOTAVAIL:   "Address not available",
	ENETDOWN:        "Network interface is not configured",
	ENETUNREACH:     "Network is unreachable",
	ECONNABORTED:    "Connection aborted",
	ECONNRESET:      "Connection reset by peer",
	ENOBUFS:         "No buffer space available",
	EISCONN:         "Socket is already connected",
	ENOTCONN:        "Socket is not connected",
	ESHUTDOWN:       "Can't send after socket shutdown",
	ETIMEDOUT:       "Connection timed out",
	ECONNREFUSED:    "Connection refused",
	EHOSTDOWN:       "Host is down",
	EHOSTUNREACH:    "Host is unreachable",
	EALREADY:        "Socket already connected",
	EINPROGRESS:     "Connection already in progress",
	ENOMEDIUM:       "No medium (in tape drive)",
	ECANCELED:       "Operation canceled.",
	ELBIN:           "Inode is remote (not really error)",
	EFTYPE:          "Inappropriate file type or format",
	ENMFILE:         "No more files",
	ENOSHARE:        "No such host or network path",
	ECASECLASH:      "Filename exists with different case",
}

// Do the interface allocations only once for common
// Errno values.
var (
	errEAGAIN error = EAGAIN
	errEINVAL error = EINVAL
	errENOENT error = ENOENT
)

// errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e Errno) error {
	switch e {
	case 0:
		return nil
	case EAGAIN:
		return errEAGAIN
	case EINVAL:
		return errEINVAL
	case ENOENT:
		return errENOENT
	}
	return e
}

var errnoByCode = map[string]Errno{
	"EPERM":           EPERM,
	"ENOENT":          ENOENT,
	"ESRCH":           ESRCH,
	"EINTR":           EINTR,
	"EIO":             EIO,
	"ENXIO":           ENXIO,
	"E2BIG":           E2BIG,
	"ENOEXEC":         ENOEXEC,
	"EBADF":           EBADF,
	"ECHILD":          ECHILD,
	"EAGAIN":          EAGAIN,
	"ENOMEM":          ENOMEM,
	"EACCES":          EACCES,
	"EFAULT":          EFAULT,
	"EBUSY":           EBUSY,
	"EEXIST":          EEXIST,
	"EXDEV":           EXDEV,
	"ENODEV":          ENODEV,
	"ENOTDIR":         ENOTDIR,
	"EISDIR":          EISDIR,
	"EINVAL":          EINVAL,
	"ENFILE":          ENFILE,
	"EMFILE":          EMFILE,
	"ENOTTY":          ENOTTY,
	"EFBIG":           EFBIG,
	"ENOSPC":          ENOSPC,
	"ESPIPE":          ESPIPE,
	"EROFS":           EROFS,
	"EMLINK":          EMLINK,
	"EPIPE":           EPIPE,
	"ENAMETOOLONG":    ENAMETOOLONG,
	"ENOSYS":          ENOSYS,
	"EDQUOT":          EDQUOT,
	"EDOM":            EDOM,
	"ERANGE":          ERANGE,
	"EDEADLK":         EDEADLK,
	"ENOLCK":          ENOLCK,
	"ENOTEMPTY":       ENOTEMPTY,
	"ELOOP":           ELOOP,
	"ENOMSG":          ENOMSG,
	"EIDRM":           EIDRM,
	"ECHRNG":          ECHRNG,
	"EL2NSYNC":        EL2NSYNC,
	"EL3HLT":          EL3HLT,
	"EL3RST":          EL3RST,
	"ELNRNG":          ELNRNG,
	"EUNATCH":         EUNATCH,
	"ENOCSI":          ENOCSI,
	"EL2HLT":          EL2HLT,
	"EBADE":           EBADE,
	"EBADR":           EBADR,
	"EXFULL":          EXFULL,
	"ENOANO":          ENOANO,
	"EBADRQC":         EBADRQC,
	"EBADSLT":         EBADSLT,
	"EDEADLOCK":       EDEADLOCK,
	"EBFONT":          EBFONT,
	"ENOSTR":          ENOSTR,
	"ENODATA":         ENODATA,
	"ETIME":           ETIME,
	"ENOSR":           ENOSR,
	"ENONET":          ENONET,
	"ENOPKG":          ENOPKG,
	"EREMOTE":         EREMOTE,
	"ENOLINK":         ENOLINK,
	"EADV":            EADV,
	"ESRMNT":          ESRMNT,
	"ECOMM":           ECOMM,
	"EPROTO":          EPROTO,
	"EMULTIHOP":       EMULTIHOP,
	"EDOTDOT":         EDOTDOT,
	"EBADMSG":         EBADMSG,
	"EOVERFLOW":       EOVERFLOW,
	"ENOTUNIQ":        ENOTUNIQ,
	"EBADFD":          EBADFD,
	"EREMCHG":         EREMCHG,
	"ELIBACC":         ELIBACC,
	"ELIBBAD":         ELIBBAD,
	"ELIBSCN":         ELIBSCN,
	"ELIBMAX":         ELIBMAX,
	"ELIBEXEC":        ELIBEXEC,
	"EILSEQ":          EILSEQ,
	"EUSERS":          EUSERS,
	"ENOTSOCK":        ENOTSOCK,
	"EDESTADDRREQ":    EDESTADDRREQ,
	"EMSGSIZE":        EMSGSIZE,
	"EPROTOTYPE":      EPROTOTYPE,
	"ENOPROTOOPT":     ENOPROTOOPT,
	"EPROTONOSUPPORT": EPROTONOSUPPORT,
	"ESOCKTNOSUPPORT": ESOCKTNOSUPPORT,
	"EOPNOTSUPP":      EOPNOTSUPP,
	"EPFNOSUPPORT":    EPFNOSUPPORT,
	"EAFNOSUPPORT":    EAFNOSUPPORT,
	"EADDRINUSE":      EADDRINUSE,
	"EADDRNOTAVAIL":   EADDRNOTAVAIL,
	"ENETDOWN":        ENETDOWN,
	"ENETUNREACH":     ENETUNREACH,
	"ENETRESET":       ENETRESET,
	"ECONNABORTED":    ECONNABORTED,
	"ECONNRESET":      ECONNRESET,
	"ENOBUFS":         ENOBUFS,
	"EISCONN":         EISCONN,
	"ENOTCONN":        ENOTCONN,
	"ESHUTDOWN":       ESHUTDOWN,
	"ETOOMANYREFS":    ETOOMANYREFS,
	"ETIMEDOUT":       ETIMEDOUT,
	"ECONNREFUSED":    ECONNREFUSED,
	"EHOSTDOWN":       EHOSTDOWN,
	"EHOSTUNREACH":    EHOSTUNREACH,
	"EALREADY":        EALREADY,
	"EINPROGRESS":     EINPROGRESS,
	"ESTALE":          ESTALE,
	"ENOTSUP":         ENOTSUP,
	"ENOMEDIUM":       ENOMEDIUM,
	"ECANCELED":       ECANCELED,
	"ELBIN":           ELBIN,
	"EFTYPE":          EFTYPE,
	"ENMFILE":         ENMFILE,
	"EPROCLIM":        EPROCLIM,
	"ENOSHARE":        ENOSHARE,
	"ECASECLASH":      ECASECLASH,
	"EWOULDBLOCK":     EWOULDBLOCK,
}

"""



```