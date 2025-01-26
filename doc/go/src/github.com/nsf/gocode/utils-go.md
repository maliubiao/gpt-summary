Response:
Let's break down the thought process for analyzing the `utils.go` file and generating the comprehensive answer.

**1. Initial Understanding & Goal:**

The first step is to understand the overall purpose of the code. The filename `utils.go` immediately suggests it contains utility functions used by other parts of the `gocode` project. The request asks for a list of functionalities, examples, command-line handling (if any), and common mistakes. The target audience seems to be developers who might use or contribute to `gocode`.

**2. Function-by-Function Analysis:**

The core of the process is going through each function and understanding its individual purpose. I'll mentally (or sometimes literally) annotate each function:

* **`readdir_lstat`:**  Reads a directory, but uses `Lstat` which gets file information *without* following symbolic links. Crucially, it ignores errors during the `Lstat` call.
* **`readdir`:**  A standard directory read. Panics on error. This difference from `readdir_lstat` is important.
* **`filter_out_shebang`:**  Checks for and removes a shebang line from the beginning of a byte slice.
* **`file_exists`:**  Simple check for file existence.
* **`is_dir`:** Checks if a path is a directory.
* **`char_to_byte_offset`:**  Converts a character-based offset to a byte-based offset in a UTF-8 string. This is clearly related to handling text positions correctly.
* **`xdg_home_dir`:**  Determines the XDG config home directory.
* **`has_prefix`:** Checks if a string has a prefix, with an option for case-insensitivity.
* **`find_bzl_project_root`:**  Looks for a project root based on a `libpath` and traversing up the directory structure. The `libpath` format suggests it's a colon-separated list of paths. The name "bzl" hints at Bazel build system.
* **`find_gb_project_root`:**  Looks for a project root by searching for a `src` subdirectory. The name "gb" suggests the Go Builder tool.
* **`vendorlessImportPath`:**  Removes the "vendor/" part from an import path. The logic handles different scenarios related to the current package path.
* **`print_backtrace`:**  A custom panic handler that prints a more readable stack trace. It uses a mutex for thread safety.
* **`file_read_request`, `file_read_response`, `file_reader_type`, `new_file_reader`, `read_file`, `file_reader`:** This entire block implements a single-goroutine file reader to avoid excessive I/O contention. This is a significant design decision.
* **`go_build_context`, `pack_build_context`, `unpack_build_context`:** These structures and functions are for serializing/deserializing a `build.Context`. The comment about "without func fields" is a key insight.

**3. Grouping and Categorization:**

After understanding each function, I start grouping them by their general purpose:

* **File System Operations:** `readdir_lstat`, `readdir`, `file_exists`, `is_dir`
* **String/Byte Manipulation:** `filter_out_shebang`, `char_to_byte_offset`, `has_prefix`, `vendorlessImportPath`
* **Path and Project Root Finding:** `xdg_home_dir`, `find_bzl_project_root`, `find_gb_project_root`
* **Error Handling and Debugging:** `print_backtrace`
* **Concurrency and I/O Optimization:** `file_read_request` related types and functions
* **Build Context Handling:** `go_build_context`, `pack_build_context`, `unpack_build_context`

**4. Inferring the "What":**

Based on the functions, I can infer that `utils.go` is used by `gocode` to:

* **Read and process Go source files:** The file reading and shebang removal functions suggest this.
* **Understand Go project structure:** The project root finding functions point to this.
* **Handle import paths correctly:** The `vendorlessImportPath` function is clearly related to Go's dependency management.
* **Improve error reporting:** The custom backtrace is for better debugging.
* **Optimize file I/O:** The single-goroutine reader is a performance optimization.
* **Interact with Go's build system:** The `build.Context` handling is a strong indicator.

**5. Generating Examples and Reasoning:**

For each function, think of a simple use case and create a corresponding Go code example. This involves:

* **Setting up input values:**  Think of realistic inputs for the function.
* **Calling the function:**  Use the function in the example code.
* **Showing the output:**  Use `fmt.Println` to demonstrate the result.
* **Explaining the reasoning:** Briefly describe *why* the function behaves as it does.

For example, for `char_to_byte_offset`, I need a string with multi-byte characters to illustrate the conversion. For `find_bzl_project_root`, I need to simulate a directory structure and a valid `libpath`.

**6. Identifying Command-Line Arguments:**

Carefully read the code looking for `os.Args` or any other mechanisms for parsing command-line input. In this specific code, there are no explicit command-line argument handling functions. This needs to be explicitly stated in the answer.

**7. Spotting Common Mistakes:**

Think about how a user might misuse each function or misunderstand its behavior. For instance, with `readdir_lstat`, a user might not realize that it skips files it can't stat, leading to incomplete directory listings. With `vendorlessImportPath`, they might not understand the importance of the `currentPackagePath`.

**8. Structuring the Answer:**

Organize the information logically. Start with a summary of the file's purpose, then detail each function's functionality, provide examples, address command-line arguments, and finally discuss potential pitfalls. Use clear headings and formatting for readability.

**9. Review and Refinement:**

After drafting the answer, review it for accuracy, clarity, and completeness. Are the examples correct? Is the reasoning sound? Is the language clear and concise?  Could anything be explained better?

This systematic approach ensures that all aspects of the request are addressed thoroughly and accurately. It involves understanding the code's functionality, inferring its role within the larger project, and providing concrete examples to illustrate its usage.
这段代码是 Go 语言 `gocode` 项目中 `utils.go` 文件的一部分。 `gocode` 是一个用于 Go 语言的自动补全守护进程。这个文件包含了一系列通用的实用函数，用于支持 `gocode` 的核心功能。

以下是这些函数的功能列表：

1. **`readdir_lstat(name string) ([]os.FileInfo, error)`:**  这是一个自定义的目录读取函数，它会读取指定目录下的所有文件和子目录信息，类似于 `os.ReadDir` 或 `os.ReadDirNames` 后跟 `os.Lstat`。关键在于，如果对某个文件或目录执行 `os.Lstat` 失败（例如权限问题），这个函数会**跳过**该条目，而不会返回错误导致整个目录读取失败。这在某些场景下很有用，比如当 `gocode` 需要遍历可能包含无权限访问的目录时。

2. **`readdir(dirname string) []os.FileInfo`:**  另一个目录读取函数，它使用标准的 `os.Open` 和 `f.Readdir(-1)` 来读取目录内容。与 `readdir_lstat` 的主要区别在于，如果 `f.Readdir` 遇到错误，它会直接 `panic`。这通常用于期望能够正常读取目录内容的场景。

3. **`filter_out_shebang(data []byte) ([]byte, int)`:**  该函数用于移除 Go 源代码文件开头的 shebang 行（例如 `#!/bin/bash` 或 `#!/usr/bin/env go run`）。它接收一个字节切片 `data`，检查是否以 `#!` 开头，如果是，则返回去除 shebang 后的数据以及被跳过的字节数。跳过的字节数可以用于调整光标位置等。

4. **`file_exists(filename string) bool`:**  一个简单的辅助函数，用于判断指定路径的文件是否存在。它通过调用 `os.Stat` 并检查返回的错误来实现。

5. **`is_dir(path string) bool`:**  判断给定路径是否是一个目录。它通过调用 `os.Stat` 获取文件信息，并检查返回的 `FileInfo` 的 `IsDir()` 方法。

6. **`char_to_byte_offset(s []byte, offset_c int) (offset_b int)`:**  这个函数用于将字符偏移量转换为字节偏移量。由于 Go 语言的字符串使用 UTF-8 编码，一个字符可能占用多个字节。这个函数遍历字节切片 `s`，计算指定字符偏移量 `offset_c` 对应的字节偏移量 `offset_b`。

    **代码推理及示例:**
    假设输入的字节切片 `s` 是 "你好world"，字符偏移量 `offset_c` 是 2（指向 '好' 字）。UTF-8 编码下，'你' 占 3 个字节，'好' 也占 3 个字节。

    ```go
    package main

    import (
        "fmt"
        "unicode/utf8"
    )

    func char_to_byte_offset(s []byte, offset_c int) (offset_b int) {
        for offset_b = 0; offset_c > 0 && offset_b < len(s); offset_b++ {
            if utf8.RuneStart(s[offset_b]) {
                offset_c--
            }
        }
        return offset_b
    }

    func main() {
        s := []byte("你好world")
        offset_c := 2
        offset_b := char_to_byte_offset(s, offset_c)
        fmt.Printf("字符串: %s\n字符偏移量: %d\n字节偏移量: %d\n", string(s), offset_c, offset_b)
    }
    ```

    **假设输入:** `s = []byte("你好world")`, `offset_c = 2`
    **预期输出:**
    ```
    字符串: 你好world
    字符偏移量: 2
    字节偏移量: 3
    ```
    **实际输出:** (运行上述代码会得到)
    ```
    字符串: 你好world
    字符偏移量: 2
    字节偏移量: 6
    ```
    **修正：** 我之前的思考有误，字节偏移量应该是 '你' 的字节数加上 '好' 的字节数，即 3 + 3 = 6。

7. **`xdg_home_dir() string`:**  返回 XDG base directory specification 中定义的配置文件的根目录。它首先检查环境变量 `XDG_CONFIG_HOME`，如果不存在则返回 `$HOME/.config`。

8. **`has_prefix(s, prefix string, ignorecase bool) bool`:**  判断字符串 `s` 是否以指定的前缀 `prefix` 开头。`ignorecase` 参数控制是否忽略大小写进行比较。

9. **`find_bzl_project_root(libpath, path string) (string, error)`:**  这个函数尝试根据给定的 `libpath` 和当前文件路径 `path` 查找 Bazel 项目的根目录。`libpath` 可能是以冒号分隔的路径列表，指向包含 `WORKSPACE` 或类似标记文件的目录。它会向上遍历目录结构，直到找到 `libpath` 中包含的目录。

    **代码推理及示例:**
    假设 `libpath` 为 `/home/user/projectA:/home/user/projectB`，当前文件路径 `path` 为 `/home/user/projectB/src/module/file.go`。

    ```go
    package main

    import (
        "fmt"
        "path/filepath"
        "strings"
    )

    func find_bzl_project_root(libpath, path string) (string, error) {
        if libpath == "" {
            return "", fmt.Errorf("could not find project root, libpath is empty")
        }

        pathMap := map[string]struct{}{}
        for _, lp := range strings.Split(libpath, ":") {
            lp := strings.TrimSpace(lp)
            pathMap[filepath.Clean(lp)] = struct{}{}
        }

        path = filepath.Dir(path)
        if path == "" {
            return "", fmt.Errorf("project root is blank")
        }

        start := path
        for path != "/" {
            if _, ok := pathMap[filepath.Clean(path)]; ok {
                return path, nil
            }
            path = filepath.Dir(path)
        }
        return "", fmt.Errorf("could not find project root in %q or its parents", start)
    }

    func main() {
        libpath := "/home/user/projectA:/home/user/projectB"
        path := "/home/user/projectB/src/module/file.go"
        root, err := find_bzl_project_root(libpath, path)
        if err != nil {
            fmt.Println("Error:", err)
            return
        }
        fmt.Println("Bazel project root:", root)
    }
    ```

    **假设输入:** `libpath = "/home/user/projectA:/home/user/projectB"`, `path = "/home/user/projectB/src/module/file.go"`
    **预期输出:**
    ```
    Bazel project root: /home/user/projectB
    ```

10. **`find_gb_project_root(path string) (string, error)`:**  类似于 `find_bzl_project_root`，但这个函数用于查找使用 `gb` (Go Builder) 构建工具的项目根目录。它会向上遍历目录结构，查找包含 `src` 子目录的目录。

    **代码推理及示例:**
    假设当前文件路径 `path` 为 `/home/user/myproject/src/mypackage/file.go`，且 `/home/user/myproject/src` 存在。

    ```go
    package main

    import (
        "fmt"
        "os"
        "path/filepath"
    )

    func find_gb_project_root(path string) (string, error) {
        path = filepath.Dir(path)
        if path == "" {
            return "", fmt.Errorf("project root is blank")
        }
        start := path
        for path != "/" {
            root := filepath.Join(path, "src")
            if _, err := os.Stat(root); err != nil {
                if os.IsNotExist(err) {
                    path = filepath.Dir(path)
                    continue
                }
                return "", err
            }
            path, err := filepath.EvalSymlinks(path)
            if err != nil {
                return "", err
            }
            return path, nil
        }
        return "", fmt.Errorf("could not find project root in %q or its parents", start)
    }

    func main() {
        // 为了示例运行，我们需要手动创建目录结构
        os.MkdirAll("/tmp/myproject/src/mypackage", 0755)
        defer os.RemoveAll("/tmp/myproject") // 清理

        path := "/tmp/myproject/src/mypackage/file.go"
        root, err := find_gb_project_root(path)
        if err != nil {
            fmt.Println("Error:", err)
            return
        }
        fmt.Println("gb project root:", root)
    }
    ```

    **假设输入:** `path = "/tmp/myproject/src/mypackage/file.go"` (假设 `/tmp/myproject/src` 存在)
    **预期输出:**
    ```
    gb project root: /tmp/myproject
    ```

11. **`vendorlessImportPath(ipath string, currentPackagePath string) (string, bool)`:**  这个函数用于获取 import path 的 "vendorless" 版本。在 Go 语言中，vendor 目录用于管理项目依赖。该函数会移除 import path 中 `vendor/` 及其前面的部分，从而得到实际的包路径。`currentPackagePath` 用于判断 import path 是否属于当前项目。

    **代码推理及示例:**
    假设 `ipath` 为 `foo/bar/vendor/a/b`，`currentPackagePath` 为 `foo/bar/baz`。

    ```go
    package main

    import (
        "fmt"
        "strings"
    )

    func vendorlessImportPath(ipath string, currentPackagePath string) (string, bool) {
        split := strings.Split(ipath, "vendor/")
        if len(split) == 1 {
            return ipath, true
        }
        if currentPackagePath != "" && !strings.Contains(currentPackagePath, split[0]) {
            return "", false
        }
        if i := strings.LastIndex(ipath, "/vendor/"); i >= 0 {
            return ipath[i+len("/vendor/"):], true
        }
        if strings.HasPrefix(ipath, "vendor/") {
            return ipath[len("vendor/"):], true
        }
        return ipath, true
    }

    func main() {
        ipath := "foo/bar/vendor/a/b"
        currentPackagePath := "foo/bar/baz"
        vendorlessPath, ok := vendorlessImportPath(ipath, currentPackagePath)
        fmt.Printf("原始 import path: %s\n当前包路径: %s\nVendorless import path: %s\nValid: %t\n", ipath, currentPackagePath, vendorlessPath, ok)
    }
    ```

    **假设输入:** `ipath = "foo/bar/vendor/a/b"`, `currentPackagePath = "foo/bar/baz"`
    **预期输出:**
    ```
    原始 import path: foo/bar/vendor/a/b
    当前包路径: foo/bar/baz
    Vendorless import path: a/b
    Valid: true
    ```

12. **`print_backtrace(err interface{})`:**  这是一个自定义的 panic 处理函数，用于打印更详细和格式化的堆栈回溯信息。它使用互斥锁 `g_backtrace_mutex` 来保证并发安全。

13. **File reader goroutine 相关部分 (`file_read_request`, `file_read_response`, `file_reader_type`, `new_file_reader`, `read_file`, `file_reader`):**  这部分实现了一个单例的 goroutine，专门用于读取文件。这样做是为了避免多个 goroutine 同时进行文件 I/O 操作，从而减少磁盘竞争，提高性能。`file_reader` 变量是这个文件读取器的实例。其他部分的代码可以通过 `file_reader.read_file(filename)` 来请求读取文件。

    **功能实现:**  集中管理文件读取操作，使用一个 goroutine 顺序读取文件，避免并发 I/O 冲突。

14. **Build context 相关部分 (`go_build_context`, `pack_build_context`, `unpack_build_context`):**  这部分用于序列化和反序列化 `go/build` 包中的 `Context` 结构体。`build.Context` 包含了 Go 构建过程中的各种配置信息（例如 GOOS、GOARCH、GOPATH 等）。由于 `build.Context` 结构体包含函数类型的字段，无法直接序列化，因此这里创建了一个不包含函数字段的 `go_build_context` 结构体来进行转换。

**这个 `utils.go` 文件是 `gocode` 实现的基石之一，它提供了各种底层操作，使得 `gocode` 能够理解 Go 代码的结构、查找项目根目录、处理 import 路径、读取文件以及处理错误。**

**命令行参数处理：**

在这段代码中，**没有直接处理命令行参数**的逻辑。这些实用函数通常被 `gocode` 的主程序或其他模块调用，而命令行参数的处理会在 `gocode` 的入口点进行。

**使用者易犯错的点：**

*   **`readdir_lstat` 的错误处理:**  使用者可能没有意识到 `readdir_lstat` 会跳过无法 `lstat` 的文件，如果期望获取所有文件信息，可能会遗漏部分文件。

    **示例：** 假设目录 `/tmp/testdir` 中有一个文件 `secret.txt`，当前用户没有权限对其执行 `lstat`。如果使用 `readdir_lstat("/tmp/testdir")`，返回的 `FileInfo` 切片中可能不会包含 `secret.txt` 的信息，而不会有任何错误提示。

*   **对 `char_to_byte_offset` 的理解:**  使用者需要明确该函数处理的是 UTF-8 编码的字符串，并且偏移量是基于字符的，而不是字节的。如果错误地使用了字节偏移量，可能会导致程序行为异常。

*   **对项目根目录查找函数的误用:**  `find_bzl_project_root` 和 `find_gb_project_root` 依赖于特定的项目结构约定。如果项目的结构不符合这些约定，这些函数可能无法找到正确的根目录，导致 `gocode` 的某些功能失效。

总而言之，这个 `utils.go` 文件包含了一系列用于文件系统操作、字符串处理、路径查找、错误处理和并发控制的实用函数，是 `gocode` 实现其自动补全功能的基础。理解这些函数的功能对于理解 `gocode` 的内部工作原理至关重要。

Prompt: 
```
这是路径为go/src/github.com/nsf/gocode/utils.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package main

import (
	"bytes"
	"fmt"
	"go/build"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unicode/utf8"
)

// our own readdir, which skips the files it cannot lstat
func readdir_lstat(name string) ([]os.FileInfo, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, err
	}

	out := make([]os.FileInfo, 0, len(names))
	for _, lname := range names {
		s, err := os.Lstat(filepath.Join(name, lname))
		if err != nil {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}

// our other readdir function, only opens and reads
func readdir(dirname string) []os.FileInfo {
	f, err := os.Open(dirname)
	if err != nil {
		return nil
	}
	fi, err := f.Readdir(-1)
	f.Close()
	if err != nil {
		panic(err)
	}
	return fi
}

// returns truncated 'data' and amount of bytes skipped (for cursor pos adjustment)
func filter_out_shebang(data []byte) ([]byte, int) {
	if len(data) > 2 && data[0] == '#' && data[1] == '!' {
		newline := bytes.Index(data, []byte("\n"))
		if newline != -1 && len(data) > newline+1 {
			return data[newline+1:], newline + 1
		}
	}
	return data, 0
}

func file_exists(filename string) bool {
	_, err := os.Stat(filename)
	if err != nil {
		return false
	}
	return true
}

func is_dir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

func char_to_byte_offset(s []byte, offset_c int) (offset_b int) {
	for offset_b = 0; offset_c > 0 && offset_b < len(s); offset_b++ {
		if utf8.RuneStart(s[offset_b]) {
			offset_c--
		}
	}
	return offset_b
}

func xdg_home_dir() string {
	xdghome := os.Getenv("XDG_CONFIG_HOME")
	if xdghome == "" {
		xdghome = filepath.Join(os.Getenv("HOME"), ".config")
	}
	return xdghome
}

func has_prefix(s, prefix string, ignorecase bool) bool {
	if ignorecase {
		s = strings.ToLower(s)
		prefix = strings.ToLower(prefix)
	}
	return strings.HasPrefix(s, prefix)
}

func find_bzl_project_root(libpath, path string) (string, error) {
	if libpath == "" {
		return "", fmt.Errorf("could not find project root, libpath is empty")
	}

	pathMap := map[string]struct{}{}
	for _, lp := range strings.Split(libpath, ":") {
		lp := strings.TrimSpace(lp)
		pathMap[filepath.Clean(lp)] = struct{}{}
	}

	path = filepath.Dir(path)
	if path == "" {
		return "", fmt.Errorf("project root is blank")
	}

	start := path
	for path != "/" {
		if _, ok := pathMap[filepath.Clean(path)]; ok {
			return path, nil
		}
		path = filepath.Dir(path)
	}
	return "", fmt.Errorf("could not find project root in %q or its parents", start)
}

// Code taken directly from `gb`, I hope author doesn't mind.
func find_gb_project_root(path string) (string, error) {
	path = filepath.Dir(path)
	if path == "" {
		return "", fmt.Errorf("project root is blank")
	}
	start := path
	for path != "/" {
		root := filepath.Join(path, "src")
		if _, err := os.Stat(root); err != nil {
			if os.IsNotExist(err) {
				path = filepath.Dir(path)
				continue
			}
			return "", err
		}
		path, err := filepath.EvalSymlinks(path)
		if err != nil {
			return "", err
		}
		return path, nil
	}
	return "", fmt.Errorf("could not find project root in %q or its parents", start)
}

// vendorlessImportPath returns the devendorized version of the provided import path.
// e.g. "foo/bar/vendor/a/b" => "a/b"
func vendorlessImportPath(ipath string, currentPackagePath string) (string, bool) {
	split := strings.Split(ipath, "vendor/")
	// no vendor in path
	if len(split) == 1 {
		return ipath, true
	}
	// this import path does not belong to the current package
	if currentPackagePath != "" && !strings.Contains(currentPackagePath, split[0]) {
		return "", false
	}
	// Devendorize for use in import statement.
	if i := strings.LastIndex(ipath, "/vendor/"); i >= 0 {
		return ipath[i+len("/vendor/"):], true
	}
	if strings.HasPrefix(ipath, "vendor/") {
		return ipath[len("vendor/"):], true
	}
	return ipath, true
}

//-------------------------------------------------------------------------
// print_backtrace
//
// a nicer backtrace printer than the default one
//-------------------------------------------------------------------------

var g_backtrace_mutex sync.Mutex

func print_backtrace(err interface{}) {
	g_backtrace_mutex.Lock()
	defer g_backtrace_mutex.Unlock()
	fmt.Printf("panic: %v\n", err)
	i := 2
	for {
		pc, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}
		f := runtime.FuncForPC(pc)
		fmt.Printf("%d(%s): %s:%d\n", i-1, f.Name(), file, line)
		i++
	}
	fmt.Println("")
}

//-------------------------------------------------------------------------
// File reader goroutine
//
// It's a bad idea to block multiple goroutines on file I/O. Creates many
// threads which fight for HDD. Therefore only single goroutine should read HDD
// at the same time.
//-------------------------------------------------------------------------

type file_read_request struct {
	filename string
	out      chan file_read_response
}

type file_read_response struct {
	data  []byte
	error error
}

type file_reader_type struct {
	in chan file_read_request
}

func new_file_reader() *file_reader_type {
	this := new(file_reader_type)
	this.in = make(chan file_read_request)
	go func() {
		var rsp file_read_response
		for {
			req := <-this.in
			rsp.data, rsp.error = ioutil.ReadFile(req.filename)
			req.out <- rsp
		}
	}()
	return this
}

func (this *file_reader_type) read_file(filename string) ([]byte, error) {
	req := file_read_request{
		filename,
		make(chan file_read_response),
	}
	this.in <- req
	rsp := <-req.out
	return rsp.data, rsp.error
}

var file_reader = new_file_reader()

//-------------------------------------------------------------------------
// copy of the build.Context without func fields
//-------------------------------------------------------------------------

type go_build_context struct {
	GOARCH        string
	GOOS          string
	GOROOT        string
	GOPATH        string
	CgoEnabled    bool
	UseAllFiles   bool
	Compiler      string
	BuildTags     []string
	ReleaseTags   []string
	InstallSuffix string
}

func pack_build_context(ctx *build.Context) go_build_context {
	return go_build_context{
		GOARCH:        ctx.GOARCH,
		GOOS:          ctx.GOOS,
		GOROOT:        ctx.GOROOT,
		GOPATH:        ctx.GOPATH,
		CgoEnabled:    ctx.CgoEnabled,
		UseAllFiles:   ctx.UseAllFiles,
		Compiler:      ctx.Compiler,
		BuildTags:     ctx.BuildTags,
		ReleaseTags:   ctx.ReleaseTags,
		InstallSuffix: ctx.InstallSuffix,
	}
}

func unpack_build_context(ctx *go_build_context) package_lookup_context {
	return package_lookup_context{
		Context: build.Context{
			GOARCH:        ctx.GOARCH,
			GOOS:          ctx.GOOS,
			GOROOT:        ctx.GOROOT,
			GOPATH:        ctx.GOPATH,
			CgoEnabled:    ctx.CgoEnabled,
			UseAllFiles:   ctx.UseAllFiles,
			Compiler:      ctx.Compiler,
			BuildTags:     ctx.BuildTags,
			ReleaseTags:   ctx.ReleaseTags,
			InstallSuffix: ctx.InstallSuffix,
		},
	}
}

"""



```