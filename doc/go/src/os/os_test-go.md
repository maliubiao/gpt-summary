Response:
My thinking process to answer the prompt goes like this:

1. **Understand the Goal:** The request asks for a summary of the functionality of the provided Go code snippet, which is a part of `os_test.go`. It also requests explanations of specific Go features used, code examples with hypothetical inputs/outputs, command-line argument handling (if any), and common mistakes. Finally, it explicitly asks for a summary of the functionality of this *first* part.

2. **Initial Code Scan and Keyword Recognition:** I quickly scan the code looking for keywords and function names that suggest specific functionalities. I see:
    * `TestMain`:  The entry point for tests.
    * `Getenv`:  Interaction with environment variables.
    * `Stdout.Close()`, `io.Copy(io.Discard, Stdin)`, `Exit`:  Handling standard input/output, potentially for a specific test scenario.
    * `log.SetFlags`:  Configuring logging.
    * `Stat`, `Lstat`, `Fstat`:  Functions for getting file information.
    * `Open`, `CreateTemp`, `Close`, `Remove`: File manipulation.
    * `Read`, `Readdirnames`, `Readdir`, `ReadDir`:  Reading file and directory contents.
    * `Symlink`, `Link`, `Readlink`: Operations related to symbolic and hard links.
    * `Rename`:  Renaming files.
    * `StartProcess`: Executing external commands.
    * `Chmod`, `Truncate`, `Chtimes`:  Modifying file attributes.
    * `Pipe`: Creating pipes for inter-process communication.
    * `testing` package usage (`testing.T`, `t.Parallel`, `t.Run`, etc.):  Clearly part of a test suite.
    * Benchmark functions (`Benchmark...`): Performance testing.
    * Platform-specific logic (`runtime.GOOS`):  The tests are aware of operating system differences.

3. **Divide and Conquer (Based on Test Functions):** The code is organized into test functions. I can categorize the functionality by looking at what each test function aims to verify. This provides a natural way to structure the summary.

4. **Analyze `TestMain`:** This function seems to handle a special environment variable `GO_OS_TEST_DRAIN_STDIN`. If set, it closes stdout and reads stdin until EOF, then exits. This suggests a test scenario where stdin needs to be consumed or ignored. The logging setup is standard for test output.

5. **Analyze Data Structures (`sysDir` and `sysdir`):** The `sysDir` struct and the `sysdir` variable define platform-specific directories and files. This is used for testing operations against known system files.

6. **Analyze Helper Functions (`size`, `equal`, `newFile`):** These functions simplify common test setup and assertions, such as getting file size, comparing file names (case-insensitively on Windows), and creating temporary files.

7. **Detailed Examination of Test Functions (Focus on the First Part):**  I go through each test function in the provided snippet and deduce its purpose:
    * `TestStat`: Tests the `Stat` function for retrieving file information. It checks the name and size of an existing system file.
    * `TestStatError`: Tests error handling of `Stat` when a file doesn't exist or when encountering a broken symlink.
    * `TestStatSymlinkLoop`: Tests `Stat`'s behavior when encountering a symlink loop.
    * `TestFstat`: Tests the `Stat` method of an `os.File` (obtained via `Open`).
    * `TestLstat`: Tests the `Lstat` function, which is like `Stat` but doesn't follow symlinks.
    * `TestRead0`: Tests reading 0 bytes from a file.
    * `TestReadClosed`: Tests reading from a closed file, expecting an `ErrClosed` error.
    * `testReaddirnames`, `testReaddir`, `testReadDir`: These are helper functions for testing different directory listing functions.
    * `TestFileReaddirnames`, `TestFileReaddir`, `TestFileReadDir`: These tests call the helper functions to check directory listing on the current directory, a system directory, and a temporary directory.
    * Benchmark functions: These measure the performance of `Readdirnames`, `Readdir`, `ReadDir`, `Stat`, and `Lstat`.

8. **Identify Go Features:** As I analyze the test functions, I note the Go features being tested or utilized: file I/O (`os.Open`, `os.CreateTemp`, `io.Copy`), file information retrieval (`os.Stat`, `os.Lstat`), directory listing (`os.Readdirnames`, `os.Readdir`, `os.ReadDir`), error handling (`errors.Is`, type assertions), platform-specific logic (`runtime.GOOS`), benchmarking (`testing.B`), and temporary file/directory creation (`testing.T.TempDir`).

9. **Code Examples (Where Applicable):** For key functions like `Stat`, `Open`, and directory listing, I create simple Go code examples demonstrating their usage and potential outputs based on typical scenarios. I make sure to include hypothetical inputs.

10. **Command-Line Arguments:** I carefully review the code for any usage of the `flag` package. In this snippet, `flag` is imported but not used directly. However, the `TestMain` function uses `Getenv`, which relates to environment variables, often set from the command line. I need to explain this.

11. **Common Mistakes:** I consider potential pitfalls for users, focusing on areas like error handling (not checking errors), differences between `Stat` and `Lstat`, and not closing files properly.

12. **Structure the Answer:** I organize the information logically, starting with the overall functionality, then detailing specific features, providing code examples, explaining command-line interaction, listing potential mistakes, and finally summarizing the functionality of the provided part. I use clear headings and formatting for readability.

13. **Refine and Review:** I reread my answer and compare it against the code snippet to ensure accuracy and completeness. I check that the code examples are correct and the explanations are clear and concise. I make sure to only address the first part of the code as requested.

This systematic approach allows me to break down the complex code into manageable parts, understand its purpose, and address all aspects of the prompt effectively.
这是对Go语言标准库 `os` 包进行测试的代码。它主要关注文件和目录操作的各种功能。

**以下是代码片段的主要功能归纳：**

1. **测试框架初始化和环境准备 (`TestMain`)：**
   - 处理一个特殊的测试环境变量 `GO_OS_TEST_DRAIN_STDIN`，如果设置，则关闭标准输出并丢弃标准输入，然后退出。这可能用于特定的测试场景，例如测试不需要或干扰标准输入输出的情况。
   - 设置测试日志的格式，包括标准时间和短文件名。
   - 运行测试套件。

2. **定义测试使用的常量和结构体：**
   - `dot`:  一个字符串切片，列出了当前目录下的一些 Go 源文件，可能用于测试目录读取等功能。
   - `sysDir`: 一个结构体，用于描述特定操作系统下的系统目录及其包含的一些文件名。
   - `sysdir`:  一个根据当前操作系统 (`runtime.GOOS`) 初始化的 `sysDir` 变量，包含了不同操作系统下常见的系统目录和文件。这表明测试会根据不同的操作系统执行不同的用例。

3. **定义辅助测试函数：**
   - `size(name string, t *testing.T) int64`:  打开指定名称的文件，读取其所有内容并返回文件大小，用于断言文件大小。
   - `equal(name1, name2 string) bool`:  比较两个文件名是否相等，在 Windows 上进行不区分大小写的比较。
   - `newFile(t *testing.T) *File`:  创建一个临时的文件，并在测试结束后自动清理（关闭和删除），方便测试文件操作。

4. **测试 `Stat` 功能：**
   - `TestStat(t *testing.T)`: 测试 `os.Stat` 函数，用于获取文件或目录的信息。它会尝试获取一个已知的系统文件的信息，并断言返回的文件名和大小是否正确。
   - `TestStatError(t *testing.T)`: 测试 `os.Stat` 函数在文件不存在或遇到断开的符号链接时的错误处理。它断言应该返回 `PathError` 类型的错误。
   - `TestStatSymlinkLoop(t *testing.T)`: 测试 `os.Stat` 函数在遇到符号链接循环时的行为，期望返回 `fs.PathError` 类型的错误。

5. **测试 `Fstat` 功能：**
   - `TestFstat(t *testing.T)`: 测试通过打开的文件句柄使用 `file.Stat()` 方法获取文件信息，与 `os.Stat` 的功能类似，但作用于已打开的文件。

6. **测试 `Lstat` 功能：**
   - `TestLstat(t *testing.T)`: 测试 `os.Lstat` 函数，它类似于 `os.Stat`，但如果目标是符号链接，则返回符号链接自身的信息，而不是链接指向的文件的信息。

7. **测试文件读取 (`Read`) 功能：**
   - `TestRead0(t *testing.T)`: 测试使用 `file.Read` 读取 0 字节数据的情况，期望不会返回 `io.EOF` 错误。
   - `TestReadClosed(t *testing.T)`: 测试从已关闭的文件中读取数据，期望返回 `os.ErrClosed` 错误。

8. **测试目录读取功能：**
   - `testReaddirnames(dir string, contents []string) func(*testing.T)`:  一个辅助函数，用于测试 `file.Readdirnames` 方法，该方法返回目录中所有文件和目录的名字的字符串切片。它会断言返回的名字列表中是否包含预期的文件和目录名。
   - `testReaddir(dir string, contents []string) func(*testing.T)`: 一个辅助函数，用于测试 `file.Readdir` 方法，该方法返回目录中所有文件和目录的 `os.FileInfo` 切片。它会断言返回的信息列表中是否包含预期的文件和目录名。
   - `testReadDir(dir string, contents []string) func(*testing.T)`:  一个辅助函数，用于测试 `file.ReadDir` 方法，该方法返回目录中所有目录条目的 `fs.DirEntry` 切片。它会断言返回的条目列表中是否包含预期的文件和目录名，并检查 `IsDir()` 和 `Type()` 方法的正确性。
   - `TestFileReaddirnames(t *testing.T)`, `TestFileReaddir(t *testing.T)`, `TestFileReadDir(t *testing.T)`:  分别调用上述辅助函数来测试当前目录、系统目录和临时目录的读取功能。

**可以推理出的 Go 语言功能实现：**

这段代码主要测试了 Go 语言 `os` 包中关于文件和目录操作的核心功能，包括：

- **文件和目录的元数据获取：**  `Stat`, `Lstat`, `Fstat` 函数用于获取文件或目录的各种属性，例如名称、大小、修改时间、权限等。
- **文件打开和关闭：** `Open` 函数用于打开文件，`Close` 方法用于关闭文件。
- **文件读取：** `Read` 方法用于从打开的文件中读取数据。
- **目录读取：** `Readdirnames`, `Readdir`, `ReadDir` 方法用于读取目录中的文件和子目录列表。这体现了 Go 语言对文件系统目录结构的访问能力。
- **错误处理：** 代码中大量使用了错误检查 (`if err != nil`)，并且使用了类型断言 (`err.(*PathError)`) 来判断错误的具体类型，这是 Go 语言中常见的错误处理模式。
- **平台差异处理：** 通过 `runtime.GOOS` 检查操作系统类型，并针对不同平台设置不同的测试数据或跳过某些测试，体现了 Go 语言对跨平台的支持和测试的考虑。

**Go 代码举例说明 `Stat` 功能的实现：**

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	fileInfo, err := os.Stat("my_file.txt") // 假设当前目录下有 my_file.txt 文件
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("File Name:", fileInfo.Name())
	fmt.Println("File Size:", fileInfo.Size())
	fmt.Println("Is Directory:", fileInfo.IsDir())
	fmt.Println("Modification Time:", fileInfo.ModTime())
	fmt.Println("Permissions:", fileInfo.Mode())
}
```

**假设输入与输出：**

假设当前目录下有一个名为 `my_file.txt` 的文件，内容为 "Hello, Go!", 则：

**输入：** 运行上述 Go 程序。

**输出：**

```
File Name: my_file.txt
File Size: 10
Is Directory: false
Modification Time: 2023-10-27 10:00:00 +0000 UTC  // 具体时间取决于文件修改时间
Permissions: -rw-r--r--                      // 具体权限取决于文件权限
```

**命令行参数的具体处理：**

在提供的代码片段中，并没有直接使用 `flag` 包来处理命令行参数。但是，`TestMain` 函数中使用了 `os.Getenv("GO_OS_TEST_DRAIN_STDIN")`。这意味着可以通过设置名为 `GO_OS_TEST_DRAIN_STDIN` 的环境变量来影响测试的行为。

**详细介绍：**

如果运行测试时设置了环境变量 `GO_OS_TEST_DRAIN_STDIN=1`，那么 `TestMain` 函数会执行以下操作：

1. `Stdout.Close()`: 关闭标准输出。之后任何写入标准输出的操作都将被忽略。
2. `io.Copy(io.Discard, Stdin)`: 从标准输入读取所有内容并丢弃。这有效地清空了标准输入流。
3. `Exit(0)`:  立即以状态码 0 退出程序，不会执行后续的测试。

这个机制可能用于测试在没有标准输出或者需要忽略标准输入的情况下的程序行为。可以通过以下命令行方式设置环境变量并运行测试（不同的 shell 命令可能略有不同）：

**Unix/Linux/macOS:**

```bash
GO_OS_TEST_DRAIN_STDIN=1 go test ./os
```

**Windows (PowerShell):**

```powershell
$env:GO_OS_TEST_DRAIN_STDIN = "1"
go test ./os
```

**Windows (cmd):**

```cmd
set GO_OS_TEST_DRAIN_STDIN=1
go test ./os
```

**使用者易犯错的点：**

在理解和使用 `os` 包进行文件和目录操作时，一些常见的错误包括：

1. **忘记处理错误：** 文件操作很容易出错（例如，文件不存在、权限不足等），因此必须始终检查 `os` 包函数返回的 `error` 值。
2. **不区分 `Stat` 和 `Lstat` 的使用场景：** `Stat` 会跟随符号链接，而 `Lstat` 不会。在需要获取符号链接自身信息时，必须使用 `Lstat`。
3. **资源泄漏：**  打开文件后忘记关闭（使用 `file.Close()`），会导致文件句柄泄漏，尤其是在循环或长时间运行的程序中。应该使用 `defer file.Close()` 来确保文件在函数退出时被关闭。
4. **目录读取函数的理解偏差：** `Readdirnames` 返回文件名字符串，`Readdir` 返回 `FileInfo` 接口切片，`ReadDir` 返回 `DirEntry` 接口切片。需要根据具体需求选择合适的函数。
5. **对平台差异的忽视：** 某些文件系统操作的行为可能在不同操作系统上有所不同（例如，文件名的大小写敏感性）。

**归纳一下它的功能（针对第1部分）：**

这段代码片段主要负责对 Go 语言 `os` 包中以下核心的文件和目录操作功能进行测试：

- **获取文件和目录的元数据：** 测试 `Stat`, `Lstat`, 和通过文件句柄的 `Stat` 方法。
- **文件读取的基本操作：** 测试 `Read` 方法在读取 0 字节和从已关闭文件读取时的行为。
- **目录内容的读取：** 测试 `Readdirnames`, `Readdir`, 和 `ReadDir` 这三个用于列出目录内容的函数，并针对不同的目录（当前目录、系统目录、临时目录）进行测试。

此外，它还包含了测试框架的初始化、测试环境的准备以及一些辅助的测试函数，为后续更多 `os` 包功能的测试奠定了基础。代码中也体现了对不同操作系统平台差异的考虑。

Prompt: 
```
这是路径为go/src/os/os_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package os_test

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"internal/testenv"
	"io"
	"io/fs"
	"log"
	. "os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/fstest"
	"time"
)

func TestMain(m *testing.M) {
	if Getenv("GO_OS_TEST_DRAIN_STDIN") == "1" {
		Stdout.Close()
		io.Copy(io.Discard, Stdin)
		Exit(0)
	}

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	Exit(m.Run())
}

var dot = []string{
	"dir_unix.go",
	"env.go",
	"error.go",
	"file.go",
	"os_test.go",
	"types.go",
	"stat_darwin.go",
	"stat_linux.go",
}

type sysDir struct {
	name  string
	files []string
}

var sysdir = func() *sysDir {
	switch runtime.GOOS {
	case "android":
		return &sysDir{
			"/system/lib",
			[]string{
				"libmedia.so",
				"libpowermanager.so",
			},
		}
	case "ios":
		wd, err := syscall.Getwd()
		if err != nil {
			wd = err.Error()
		}
		sd := &sysDir{
			filepath.Join(wd, "..", ".."),
			[]string{
				"ResourceRules.plist",
				"Info.plist",
			},
		}
		found := true
		for _, f := range sd.files {
			path := filepath.Join(sd.name, f)
			if _, err := Stat(path); err != nil {
				found = false
				break
			}
		}
		if found {
			return sd
		}
		// In a self-hosted iOS build the above files might
		// not exist. Look for system files instead below.
	case "windows":
		return &sysDir{
			Getenv("SystemRoot") + "\\system32\\drivers\\etc",
			[]string{
				"networks",
				"protocol",
				"services",
			},
		}
	case "plan9":
		return &sysDir{
			"/lib/ndb",
			[]string{
				"common",
				"local",
			},
		}
	case "wasip1":
		// wasmtime has issues resolving symbolic links that are often present
		// in directories like /etc/group below (e.g. private/etc/group on OSX).
		// For this reason we use files in the Go source tree instead.
		return &sysDir{
			runtime.GOROOT(),
			[]string{
				"go.env",
				"LICENSE",
				"CONTRIBUTING.md",
			},
		}
	}
	return &sysDir{
		"/etc",
		[]string{
			"group",
			"hosts",
			"passwd",
		},
	}
}()

func size(name string, t *testing.T) int64 {
	file, err := Open(name)
	if err != nil {
		t.Fatal("open failed:", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	n, err := io.Copy(io.Discard, file)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func equal(name1, name2 string) (r bool) {
	switch runtime.GOOS {
	case "windows":
		r = strings.EqualFold(name1, name2)
	default:
		r = name1 == name2
	}
	return
}

func newFile(t *testing.T) (f *File) {
	t.Helper()
	f, err := CreateTemp("", "_Go_"+t.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil && !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
		if err := Remove(f.Name()); err != nil {
			t.Fatal(err)
		}
	})
	return
}

var sfdir = sysdir.name
var sfname = sysdir.files[0]

func TestStat(t *testing.T) {
	t.Parallel()

	path := sfdir + "/" + sfname
	dir, err := Stat(path)
	if err != nil {
		t.Fatal("stat failed:", err)
	}
	if !equal(sfname, dir.Name()) {
		t.Error("name should be ", sfname, "; is", dir.Name())
	}
	filesize := size(path, t)
	if dir.Size() != filesize {
		t.Error("size should be", filesize, "; is", dir.Size())
	}
}

func TestStatError(t *testing.T) {
	t.Chdir(t.TempDir())

	path := "no-such-file"

	fi, err := Stat(path)
	if err == nil {
		t.Fatal("got nil, want error")
	}
	if fi != nil {
		t.Errorf("got %v, want nil", fi)
	}
	if perr, ok := err.(*PathError); !ok {
		t.Errorf("got %T, want %T", err, perr)
	}

	testenv.MustHaveSymlink(t)

	link := "symlink"
	err = Symlink(path, link)
	if err != nil {
		t.Fatal(err)
	}

	fi, err = Stat(link)
	if err == nil {
		t.Fatal("got nil, want error")
	}
	if fi != nil {
		t.Errorf("got %v, want nil", fi)
	}
	if perr, ok := err.(*PathError); !ok {
		t.Errorf("got %T, want %T", err, perr)
	}
}

func TestStatSymlinkLoop(t *testing.T) {
	testenv.MustHaveSymlink(t)
	t.Chdir(t.TempDir())

	err := Symlink("x", "y")
	if err != nil {
		t.Fatal(err)
	}
	defer Remove("y")

	err = Symlink("y", "x")
	if err != nil {
		t.Fatal(err)
	}
	defer Remove("x")

	_, err = Stat("x")
	if _, ok := err.(*fs.PathError); !ok {
		t.Errorf("expected *PathError, got %T: %v\n", err, err)
	}
}

func TestFstat(t *testing.T) {
	t.Parallel()

	path := sfdir + "/" + sfname
	file, err1 := Open(path)
	if err1 != nil {
		t.Fatal("open failed:", err1)
	}
	defer file.Close()
	dir, err2 := file.Stat()
	if err2 != nil {
		t.Fatal("fstat failed:", err2)
	}
	if !equal(sfname, dir.Name()) {
		t.Error("name should be ", sfname, "; is", dir.Name())
	}
	filesize := size(path, t)
	if dir.Size() != filesize {
		t.Error("size should be", filesize, "; is", dir.Size())
	}
}

func TestLstat(t *testing.T) {
	t.Parallel()

	path := sfdir + "/" + sfname
	dir, err := Lstat(path)
	if err != nil {
		t.Fatal("lstat failed:", err)
	}
	if !equal(sfname, dir.Name()) {
		t.Error("name should be ", sfname, "; is", dir.Name())
	}
	if dir.Mode()&ModeSymlink == 0 {
		filesize := size(path, t)
		if dir.Size() != filesize {
			t.Error("size should be", filesize, "; is", dir.Size())
		}
	}
}

// Read with length 0 should not return EOF.
func TestRead0(t *testing.T) {
	t.Parallel()

	path := sfdir + "/" + sfname
	f, err := Open(path)
	if err != nil {
		t.Fatal("open failed:", err)
	}
	defer f.Close()

	b := make([]byte, 0)
	n, err := f.Read(b)
	if n != 0 || err != nil {
		t.Errorf("Read(0) = %d, %v, want 0, nil", n, err)
	}
	b = make([]byte, 100)
	n, err = f.Read(b)
	if n <= 0 || err != nil {
		t.Errorf("Read(100) = %d, %v, want >0, nil", n, err)
	}
}

// Reading a closed file should return ErrClosed error
func TestReadClosed(t *testing.T) {
	t.Parallel()

	path := sfdir + "/" + sfname
	file, err := Open(path)
	if err != nil {
		t.Fatal("open failed:", err)
	}
	file.Close() // close immediately

	b := make([]byte, 100)
	_, err = file.Read(b)

	e, ok := err.(*PathError)
	if !ok || e.Err != ErrClosed {
		t.Fatalf("Read: got %T(%v), want %T(%v)", err, err, e, ErrClosed)
	}
}

func testReaddirnames(dir string, contents []string) func(*testing.T) {
	return func(t *testing.T) {
		t.Parallel()

		file, err := Open(dir)
		if err != nil {
			t.Fatalf("open %q failed: %v", dir, err)
		}
		defer file.Close()
		s, err2 := file.Readdirnames(-1)
		if err2 != nil {
			t.Fatalf("Readdirnames %q failed: %v", dir, err2)
		}
		for _, m := range contents {
			found := false
			for _, n := range s {
				if n == "." || n == ".." {
					t.Errorf("got %q in directory", n)
				}
				if !equal(m, n) {
					continue
				}
				if found {
					t.Error("present twice:", m)
				}
				found = true
			}
			if !found {
				t.Error("could not find", m)
			}
		}
		if s == nil {
			t.Error("Readdirnames returned nil instead of empty slice")
		}
	}
}

func testReaddir(dir string, contents []string) func(*testing.T) {
	return func(t *testing.T) {
		t.Parallel()

		file, err := Open(dir)
		if err != nil {
			t.Fatalf("open %q failed: %v", dir, err)
		}
		defer file.Close()
		s, err2 := file.Readdir(-1)
		if err2 != nil {
			t.Fatalf("Readdir %q failed: %v", dir, err2)
		}
		for _, m := range contents {
			found := false
			for _, n := range s {
				if n.Name() == "." || n.Name() == ".." {
					t.Errorf("got %q in directory", n.Name())
				}
				if !equal(m, n.Name()) {
					continue
				}
				if found {
					t.Error("present twice:", m)
				}
				found = true
			}
			if !found {
				t.Error("could not find", m)
			}
		}
		if s == nil {
			t.Error("Readdir returned nil instead of empty slice")
		}
	}
}

func testReadDir(dir string, contents []string) func(*testing.T) {
	return func(t *testing.T) {
		t.Parallel()

		file, err := Open(dir)
		if err != nil {
			t.Fatalf("open %q failed: %v", dir, err)
		}
		defer file.Close()
		s, err2 := file.ReadDir(-1)
		if err2 != nil {
			t.Fatalf("ReadDir %q failed: %v", dir, err2)
		}
		for _, m := range contents {
			found := false
			for _, n := range s {
				if n.Name() == "." || n.Name() == ".." {
					t.Errorf("got %q in directory", n)
				}
				if !equal(m, n.Name()) {
					continue
				}
				if found {
					t.Error("present twice:", m)
				}
				found = true
				lstat, err := Lstat(dir + "/" + m)
				if err != nil {
					t.Fatal(err)
				}
				if n.IsDir() != lstat.IsDir() {
					t.Errorf("%s: IsDir=%v, want %v", m, n.IsDir(), lstat.IsDir())
				}
				if n.Type() != lstat.Mode().Type() {
					t.Errorf("%s: IsDir=%v, want %v", m, n.Type(), lstat.Mode().Type())
				}
				info, err := n.Info()
				if err != nil {
					t.Errorf("%s: Info: %v", m, err)
					continue
				}
				if !SameFile(info, lstat) {
					t.Errorf("%s: Info: SameFile(info, lstat) = false", m)
				}
			}
			if !found {
				t.Error("could not find", m)
			}
		}
		if s == nil {
			t.Error("ReadDir returned nil instead of empty slice")
		}
	}
}

func TestFileReaddirnames(t *testing.T) {
	t.Parallel()

	t.Run(".", testReaddirnames(".", dot))
	t.Run("sysdir", testReaddirnames(sysdir.name, sysdir.files))
	t.Run("TempDir", testReaddirnames(t.TempDir(), nil))
}

func TestFileReaddir(t *testing.T) {
	t.Parallel()

	t.Run(".", testReaddir(".", dot))
	t.Run("sysdir", testReaddir(sysdir.name, sysdir.files))
	t.Run("TempDir", testReaddir(t.TempDir(), nil))
}

func TestFileReadDir(t *testing.T) {
	t.Parallel()

	t.Run(".", testReadDir(".", dot))
	t.Run("sysdir", testReadDir(sysdir.name, sysdir.files))
	t.Run("TempDir", testReadDir(t.TempDir(), nil))
}

func benchmarkReaddirname(path string, b *testing.B) {
	var nentries int
	for i := 0; i < b.N; i++ {
		f, err := Open(path)
		if err != nil {
			b.Fatalf("open %q failed: %v", path, err)
		}
		ns, err := f.Readdirnames(-1)
		f.Close()
		if err != nil {
			b.Fatalf("readdirnames %q failed: %v", path, err)
		}
		nentries = len(ns)
	}
	b.Logf("benchmarkReaddirname %q: %d entries", path, nentries)
}

func benchmarkReaddir(path string, b *testing.B) {
	var nentries int
	for i := 0; i < b.N; i++ {
		f, err := Open(path)
		if err != nil {
			b.Fatalf("open %q failed: %v", path, err)
		}
		fs, err := f.Readdir(-1)
		f.Close()
		if err != nil {
			b.Fatalf("readdir %q failed: %v", path, err)
		}
		nentries = len(fs)
	}
	b.Logf("benchmarkReaddir %q: %d entries", path, nentries)
}

func benchmarkReadDir(path string, b *testing.B) {
	var nentries int
	for i := 0; i < b.N; i++ {
		f, err := Open(path)
		if err != nil {
			b.Fatalf("open %q failed: %v", path, err)
		}
		fs, err := f.ReadDir(-1)
		f.Close()
		if err != nil {
			b.Fatalf("readdir %q failed: %v", path, err)
		}
		nentries = len(fs)
	}
	b.Logf("benchmarkReadDir %q: %d entries", path, nentries)
}

func BenchmarkReaddirname(b *testing.B) {
	benchmarkReaddirname(".", b)
}

func BenchmarkReaddir(b *testing.B) {
	benchmarkReaddir(".", b)
}

func BenchmarkReadDir(b *testing.B) {
	benchmarkReadDir(".", b)
}

func benchmarkStat(b *testing.B, path string) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Stat(path)
		if err != nil {
			b.Fatalf("Stat(%q) failed: %v", path, err)
		}
	}
}

func benchmarkLstat(b *testing.B, path string) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Lstat(path)
		if err != nil {
			b.Fatalf("Lstat(%q) failed: %v", path, err)
		}
	}
}

func BenchmarkStatDot(b *testing.B) {
	benchmarkStat(b, ".")
}

func BenchmarkStatFile(b *testing.B) {
	benchmarkStat(b, filepath.Join(runtime.GOROOT(), "src/os/os_test.go"))
}

func BenchmarkStatDir(b *testing.B) {
	benchmarkStat(b, filepath.Join(runtime.GOROOT(), "src/os"))
}

func BenchmarkLstatDot(b *testing.B) {
	benchmarkLstat(b, ".")
}

func BenchmarkLstatFile(b *testing.B) {
	benchmarkLstat(b, filepath.Join(runtime.GOROOT(), "src/os/os_test.go"))
}

func BenchmarkLstatDir(b *testing.B) {
	benchmarkLstat(b, filepath.Join(runtime.GOROOT(), "src/os"))
}

// Read the directory one entry at a time.
func smallReaddirnames(file *File, length int, t *testing.T) []string {
	names := make([]string, length)
	count := 0
	for {
		d, err := file.Readdirnames(1)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("readdirnames %q failed: %v", file.Name(), err)
		}
		if len(d) == 0 {
			t.Fatalf("readdirnames %q returned empty slice and no error", file.Name())
		}
		names[count] = d[0]
		count++
	}
	return names[0:count]
}

// Check that reading a directory one entry at a time gives the same result
// as reading it all at once.
func TestReaddirnamesOneAtATime(t *testing.T) {
	t.Parallel()

	// big directory that doesn't change often.
	dir := "/usr/bin"
	switch runtime.GOOS {
	case "android":
		dir = "/system/bin"
	case "ios", "wasip1":
		wd, err := Getwd()
		if err != nil {
			t.Fatal(err)
		}
		dir = wd
	case "plan9":
		dir = "/bin"
	case "windows":
		dir = Getenv("SystemRoot") + "\\system32"
	}
	file, err := Open(dir)
	if err != nil {
		t.Fatalf("open %q failed: %v", dir, err)
	}
	defer file.Close()
	all, err1 := file.Readdirnames(-1)
	if err1 != nil {
		t.Fatalf("readdirnames %q failed: %v", dir, err1)
	}
	file1, err2 := Open(dir)
	if err2 != nil {
		t.Fatalf("open %q failed: %v", dir, err2)
	}
	defer file1.Close()
	small := smallReaddirnames(file1, len(all)+100, t) // +100 in case we screw up
	if len(small) < len(all) {
		t.Fatalf("len(small) is %d, less than %d", len(small), len(all))
	}
	for i, n := range all {
		if small[i] != n {
			t.Errorf("small read %q mismatch: %v", small[i], n)
		}
	}
}

func TestReaddirNValues(t *testing.T) {
	if testing.Short() {
		t.Skip("test.short; skipping")
	}
	t.Parallel()

	dir := t.TempDir()
	for i := 1; i <= 105; i++ {
		f, err := Create(filepath.Join(dir, fmt.Sprintf("%d", i)))
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		f.Write([]byte(strings.Repeat("X", i)))
		f.Close()
	}

	var d *File
	openDir := func() {
		var err error
		d, err = Open(dir)
		if err != nil {
			t.Fatalf("Open directory: %v", err)
		}
	}

	readdirExpect := func(n, want int, wantErr error) {
		t.Helper()
		fi, err := d.Readdir(n)
		if err != wantErr {
			t.Fatalf("Readdir of %d got error %v, want %v", n, err, wantErr)
		}
		if g, e := len(fi), want; g != e {
			t.Errorf("Readdir of %d got %d files, want %d", n, g, e)
		}
	}

	readDirExpect := func(n, want int, wantErr error) {
		t.Helper()
		de, err := d.ReadDir(n)
		if err != wantErr {
			t.Fatalf("ReadDir of %d got error %v, want %v", n, err, wantErr)
		}
		if g, e := len(de), want; g != e {
			t.Errorf("ReadDir of %d got %d files, want %d", n, g, e)
		}
	}

	readdirnamesExpect := func(n, want int, wantErr error) {
		t.Helper()
		fi, err := d.Readdirnames(n)
		if err != wantErr {
			t.Fatalf("Readdirnames of %d got error %v, want %v", n, err, wantErr)
		}
		if g, e := len(fi), want; g != e {
			t.Errorf("Readdirnames of %d got %d files, want %d", n, g, e)
		}
	}

	for _, fn := range []func(int, int, error){readdirExpect, readdirnamesExpect, readDirExpect} {
		// Test the slurp case
		openDir()
		fn(0, 105, nil)
		fn(0, 0, nil)
		d.Close()

		// Slurp with -1 instead
		openDir()
		fn(-1, 105, nil)
		fn(-2, 0, nil)
		fn(0, 0, nil)
		d.Close()

		// Test the bounded case
		openDir()
		fn(1, 1, nil)
		fn(2, 2, nil)
		fn(105, 102, nil) // and tests buffer >100 case
		fn(3, 0, io.EOF)
		d.Close()
	}
}

func touch(t *testing.T, name string) {
	f, err := Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestReaddirStatFailures(t *testing.T) {
	switch runtime.GOOS {
	case "windows", "plan9":
		// Windows and Plan 9 already do this correctly,
		// but are structured with different syscalls such
		// that they don't use Lstat, so the hook below for
		// testing it wouldn't work.
		t.Skipf("skipping test on %v", runtime.GOOS)
	}

	var xerr error // error to return for x
	*LstatP = func(path string) (FileInfo, error) {
		if xerr != nil && strings.HasSuffix(path, "x") {
			return nil, xerr
		}
		return Lstat(path)
	}
	defer func() { *LstatP = Lstat }()

	dir := t.TempDir()
	touch(t, filepath.Join(dir, "good1"))
	touch(t, filepath.Join(dir, "x")) // will disappear or have an error
	touch(t, filepath.Join(dir, "good2"))
	readDir := func() ([]FileInfo, error) {
		d, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		return d.Readdir(-1)
	}
	mustReadDir := func(testName string) []FileInfo {
		fis, err := readDir()
		if err != nil {
			t.Fatalf("%s: Readdir: %v", testName, err)
		}
		return fis
	}
	names := func(fis []FileInfo) []string {
		s := make([]string, len(fis))
		for i, fi := range fis {
			s[i] = fi.Name()
		}
		slices.Sort(s)
		return s
	}

	if got, want := names(mustReadDir("initial readdir")),
		[]string{"good1", "good2", "x"}; !slices.Equal(got, want) {
		t.Errorf("initial readdir got %q; want %q", got, want)
	}

	xerr = ErrNotExist
	if got, want := names(mustReadDir("with x disappearing")),
		[]string{"good1", "good2"}; !slices.Equal(got, want) {
		t.Errorf("with x disappearing, got %q; want %q", got, want)
	}

	xerr = errors.New("some real error")
	if _, err := readDir(); err != xerr {
		t.Errorf("with a non-ErrNotExist error, got error %v; want %v", err, xerr)
	}
}

// Readdir on a regular file should fail.
func TestReaddirOfFile(t *testing.T) {
	t.Parallel()

	f, err := CreateTemp(t.TempDir(), "_Go_ReaddirOfFile")
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("foo"))
	f.Close()
	reg, err := Open(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	names, err := reg.Readdirnames(-1)
	if err == nil {
		t.Error("Readdirnames succeeded; want non-nil error")
	}
	var pe *PathError
	if !errors.As(err, &pe) || pe.Path != f.Name() {
		t.Errorf("Readdirnames returned %q; want a PathError with path %q", err, f.Name())
	}
	if len(names) > 0 {
		t.Errorf("unexpected dir names in regular file: %q", names)
	}
}

func TestHardLink(t *testing.T) {
	testenv.MustHaveLink(t)
	t.Chdir(t.TempDir())

	from, to := "hardlinktestfrom", "hardlinktestto"
	file, err := Create(to)
	if err != nil {
		t.Fatalf("open %q failed: %v", to, err)
	}
	if err = file.Close(); err != nil {
		t.Errorf("close %q failed: %v", to, err)
	}
	err = Link(to, from)
	if err != nil {
		t.Fatalf("link %q, %q failed: %v", to, from, err)
	}

	none := "hardlinktestnone"
	err = Link(none, none)
	// Check the returned error is well-formed.
	if lerr, ok := err.(*LinkError); !ok || lerr.Error() == "" {
		t.Errorf("link %q, %q failed to return a valid error", none, none)
	}

	tostat, err := Stat(to)
	if err != nil {
		t.Fatalf("stat %q failed: %v", to, err)
	}
	fromstat, err := Stat(from)
	if err != nil {
		t.Fatalf("stat %q failed: %v", from, err)
	}
	if !SameFile(tostat, fromstat) {
		t.Errorf("link %q, %q did not create hard link", to, from)
	}
	// We should not be able to perform the same Link() a second time
	err = Link(to, from)
	switch err := err.(type) {
	case *LinkError:
		if err.Op != "link" {
			t.Errorf("Link(%q, %q) err.Op = %q; want %q", to, from, err.Op, "link")
		}
		if err.Old != to {
			t.Errorf("Link(%q, %q) err.Old = %q; want %q", to, from, err.Old, to)
		}
		if err.New != from {
			t.Errorf("Link(%q, %q) err.New = %q; want %q", to, from, err.New, from)
		}
		if !IsExist(err.Err) {
			t.Errorf("Link(%q, %q) err.Err = %q; want %q", to, from, err.Err, "file exists error")
		}
	case nil:
		t.Errorf("link %q, %q: expected error, got nil", from, to)
	default:
		t.Errorf("link %q, %q: expected %T, got %T %v", from, to, new(LinkError), err, err)
	}
}

func TestSymlink(t *testing.T) {
	testenv.MustHaveSymlink(t)
	t.Chdir(t.TempDir())

	from, to := "symlinktestfrom", "symlinktestto"
	file, err := Create(to)
	if err != nil {
		t.Fatalf("Create(%q) failed: %v", to, err)
	}
	if err = file.Close(); err != nil {
		t.Errorf("Close(%q) failed: %v", to, err)
	}
	err = Symlink(to, from)
	if err != nil {
		t.Fatalf("Symlink(%q, %q) failed: %v", to, from, err)
	}
	tostat, err := Lstat(to)
	if err != nil {
		t.Fatalf("Lstat(%q) failed: %v", to, err)
	}
	if tostat.Mode()&ModeSymlink != 0 {
		t.Fatalf("Lstat(%q).Mode()&ModeSymlink = %v, want 0", to, tostat.Mode()&ModeSymlink)
	}
	fromstat, err := Stat(from)
	if err != nil {
		t.Fatalf("Stat(%q) failed: %v", from, err)
	}
	if !SameFile(tostat, fromstat) {
		t.Errorf("Symlink(%q, %q) did not create symlink", to, from)
	}
	fromstat, err = Lstat(from)
	if err != nil {
		t.Fatalf("Lstat(%q) failed: %v", from, err)
	}
	if fromstat.Mode()&ModeSymlink == 0 {
		t.Fatalf("Lstat(%q).Mode()&ModeSymlink = 0, want %v", from, ModeSymlink)
	}
	fromstat, err = Stat(from)
	if err != nil {
		t.Fatalf("Stat(%q) failed: %v", from, err)
	}
	if fromstat.Name() != from {
		t.Errorf("Stat(%q).Name() = %q, want %q", from, fromstat.Name(), from)
	}
	if fromstat.Mode()&ModeSymlink != 0 {
		t.Fatalf("Stat(%q).Mode()&ModeSymlink = %v, want 0", from, fromstat.Mode()&ModeSymlink)
	}
	s, err := Readlink(from)
	if err != nil {
		t.Fatalf("Readlink(%q) failed: %v", from, err)
	}
	if s != to {
		t.Fatalf("Readlink(%q) = %q, want %q", from, s, to)
	}
	file, err = Open(from)
	if err != nil {
		t.Fatalf("Open(%q) failed: %v", from, err)
	}
	file.Close()
}

func TestLongSymlink(t *testing.T) {
	testenv.MustHaveSymlink(t)
	t.Chdir(t.TempDir())

	s := "0123456789abcdef"
	// Long, but not too long: a common limit is 255.
	s = s + s + s + s + s + s + s + s + s + s + s + s + s + s + s
	from := "longsymlinktestfrom"
	err := Symlink(s, from)
	if err != nil {
		t.Fatalf("symlink %q, %q failed: %v", s, from, err)
	}
	r, err := Readlink(from)
	if err != nil {
		t.Fatalf("readlink %q failed: %v", from, err)
	}
	if r != s {
		t.Fatalf("after symlink %q != %q", r, s)
	}
}

func TestRename(t *testing.T) {
	t.Chdir(t.TempDir())
	from, to := "renamefrom", "renameto"

	file, err := Create(from)
	if err != nil {
		t.Fatalf("open %q failed: %v", from, err)
	}
	if err = file.Close(); err != nil {
		t.Errorf("close %q failed: %v", from, err)
	}
	err = Rename(from, to)
	if err != nil {
		t.Fatalf("rename %q, %q failed: %v", to, from, err)
	}
	_, err = Stat(to)
	if err != nil {
		t.Errorf("stat %q failed: %v", to, err)
	}
}

func TestRenameOverwriteDest(t *testing.T) {
	t.Chdir(t.TempDir())
	from, to := "renamefrom", "renameto"

	toData := []byte("to")
	fromData := []byte("from")

	err := WriteFile(to, toData, 0777)
	if err != nil {
		t.Fatalf("write file %q failed: %v", to, err)
	}

	err = WriteFile(from, fromData, 0777)
	if err != nil {
		t.Fatalf("write file %q failed: %v", from, err)
	}
	err = Rename(from, to)
	if err != nil {
		t.Fatalf("rename %q, %q failed: %v", to, from, err)
	}

	_, err = Stat(from)
	if err == nil {
		t.Errorf("from file %q still exists", from)
	}
	if err != nil && !IsNotExist(err) {
		t.Fatalf("stat from: %v", err)
	}
	toFi, err := Stat(to)
	if err != nil {
		t.Fatalf("stat %q failed: %v", to, err)
	}
	if toFi.Size() != int64(len(fromData)) {
		t.Errorf(`"to" size = %d; want %d (old "from" size)`, toFi.Size(), len(fromData))
	}
}

func TestRenameFailed(t *testing.T) {
	t.Chdir(t.TempDir())
	from, to := "renamefrom", "renameto"

	err := Rename(from, to)
	switch err := err.(type) {
	case *LinkError:
		if err.Op != "rename" {
			t.Errorf("rename %q, %q: err.Op: want %q, got %q", from, to, "rename", err.Op)
		}
		if err.Old != from {
			t.Errorf("rename %q, %q: err.Old: want %q, got %q", from, to, from, err.Old)
		}
		if err.New != to {
			t.Errorf("rename %q, %q: err.New: want %q, got %q", from, to, to, err.New)
		}
	case nil:
		t.Errorf("rename %q, %q: expected error, got nil", from, to)
	default:
		t.Errorf("rename %q, %q: expected %T, got %T %v", from, to, new(LinkError), err, err)
	}
}

func TestRenameNotExisting(t *testing.T) {
	t.Chdir(t.TempDir())
	from, to := "doesnt-exist", "dest"

	Mkdir(to, 0777)

	if err := Rename(from, to); !IsNotExist(err) {
		t.Errorf("Rename(%q, %q) = %v; want an IsNotExist error", from, to, err)
	}
}

func TestRenameToDirFailed(t *testing.T) {
	t.Chdir(t.TempDir())
	from, to := "renamefrom", "renameto"

	Mkdir(from, 0777)
	Mkdir(to, 0777)

	err := Rename(from, to)
	switch err := err.(type) {
	case *LinkError:
		if err.Op != "rename" {
			t.Errorf("rename %q, %q: err.Op: want %q, got %q", from, to, "rename", err.Op)
		}
		if err.Old != from {
			t.Errorf("rename %q, %q: err.Old: want %q, got %q", from, to, from, err.Old)
		}
		if err.New != to {
			t.Errorf("rename %q, %q: err.New: want %q, got %q", from, to, to, err.New)
		}
	case nil:
		t.Errorf("rename %q, %q: expected error, got nil", from, to)
	default:
		t.Errorf("rename %q, %q: expected %T, got %T %v", from, to, new(LinkError), err, err)
	}
}

func TestRenameCaseDifference(pt *testing.T) {
	from, to := "renameFROM", "RENAMEfrom"
	tests := []struct {
		name   string
		create func() error
	}{
		{"dir", func() error {
			return Mkdir(from, 0777)
		}},
		{"file", func() error {
			fd, err := Create(from)
			if err != nil {
				return err
			}
			return fd.Close()
		}},
	}

	for _, test := range tests {
		pt.Run(test.name, func(t *testing.T) {
			t.Chdir(t.TempDir())

			if err := test.create(); err != nil {
				t.Fatalf("failed to create test file: %s", err)
			}

			if _, err := Stat(to); err != nil {
				// Sanity check that the underlying filesystem is not case sensitive.
				if IsNotExist(err) {
					t.Skipf("case sensitive filesystem")
				}
				t.Fatalf("stat %q, got: %q", to, err)
			}

			if err := Rename(from, to); err != nil {
				t.Fatalf("unexpected error when renaming from %q to %q: %s", from, to, err)
			}

			fd, err := Open(".")
			if err != nil {
				t.Fatalf("Open .: %s", err)
			}

			// Stat does not return the real case of the file (it returns what the called asked for)
			// So we have to use readdir to get the real name of the file.
			dirNames, err := fd.Readdirnames(-1)
			fd.Close()
			if err != nil {
				t.Fatalf("readdirnames: %s", err)
			}

			if dirNamesLen := len(dirNames); dirNamesLen != 1 {
				t.Fatalf("unexpected dirNames len, got %q, want %q", dirNamesLen, 1)
			}

			if dirNames[0] != to {
				t.Errorf("unexpected name, got %q, want %q", dirNames[0], to)
			}
		})
	}
}

func testStartProcess(dir, cmd string, args []string, expect string) func(t *testing.T) {
	return func(t *testing.T) {
		t.Parallel()

		r, w, err := Pipe()
		if err != nil {
			t.Fatalf("Pipe: %v", err)
		}
		defer r.Close()
		attr := &ProcAttr{Dir: dir, Files: []*File{nil, w, Stderr}}
		p, err := StartProcess(cmd, args, attr)
		if err != nil {
			t.Fatalf("StartProcess: %v", err)
		}
		w.Close()

		var b strings.Builder
		io.Copy(&b, r)
		output := b.String()

		fi1, _ := Stat(strings.TrimSpace(output))
		fi2, _ := Stat(expect)
		if !SameFile(fi1, fi2) {
			t.Errorf("exec %q returned %q wanted %q",
				strings.Join(append([]string{cmd}, args...), " "), output, expect)
		}
		p.Wait()
	}
}

func TestStartProcess(t *testing.T) {
	testenv.MustHaveExec(t)
	t.Parallel()

	var dir, cmd string
	var args []string
	switch runtime.GOOS {
	case "android":
		t.Skip("android doesn't have /bin/pwd")
	case "windows":
		cmd = Getenv("COMSPEC")
		dir = Getenv("SystemRoot")
		args = []string{"/c", "cd"}
	default:
		var err error
		cmd, err = exec.LookPath("pwd")
		if err != nil {
			t.Fatalf("Can't find pwd: %v", err)
		}
		dir = "/"
		args = []string{}
		t.Logf("Testing with %v", cmd)
	}
	cmddir, cmdbase := filepath.Split(cmd)
	args = append([]string{cmdbase}, args...)
	t.Run("absolute", testStartProcess(dir, cmd, args, dir))
	t.Run("relative", testStartProcess(cmddir, cmdbase, args, cmddir))
}

func checkMode(t *testing.T, path string, mode FileMode) {
	dir, err := Stat(path)
	if err != nil {
		t.Fatalf("Stat %q (looking for mode %#o): %s", path, mode, err)
	}
	if dir.Mode()&ModePerm != mode {
		t.Errorf("Stat %q: mode %#o want %#o", path, dir.Mode(), mode)
	}
}

func TestChmod(t *testing.T) {
	// Chmod is not supported on wasip1.
	if runtime.GOOS == "wasip1" {
		t.Skip("Chmod is not supported on " + runtime.GOOS)
	}
	t.Parallel()

	f := newFile(t)
	// Creation mode is read write

	fm := FileMode(0456)
	if runtime.GOOS == "windows" {
		fm = FileMode(0444) // read-only file
	}
	if err := Chmod(f.Name(), fm); err != nil {
		t.Fatalf("chmod %s %#o: %s", f.Name(), fm, err)
	}
	checkMode(t, f.Name(), fm)

	fm = FileMode(0123)
	if runtime.GOOS == "windows" {
		fm = FileMode(0666) // read-write file
	}
	if err := f.Chmod(fm); err != nil {
		t.Fatalf("chmod %s %#o: %s", f.Name(), fm, err)
	}
	checkMode(t, f.Name(), fm)
}

func checkSize(t *testing.T, f *File, size int64) {
	t.Helper()
	dir, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat %q (looking for size %d): %s", f.Name(), size, err)
	}
	if dir.Size() != size {
		t.Errorf("Stat %q: size %d want %d", f.Name(), dir.Size(), size)
	}
}

func TestFTruncate(t *testing.T) {
	t.Parallel()

	f := newFile(t)

	checkSize(t, f, 0)
	f.Write([]byte("hello, world\n"))
	checkSize(t, f, 13)
	f.Truncate(10)
	checkSize(t, f, 10)
	f.Truncate(1024)
	checkSize(t, f, 1024)
	f.Truncate(0)
	checkSize(t, f, 0)
	_, err := f.Write([]byte("surprise!"))
	if err == nil {
		checkSize(t, f, 13+9) // wrote at offset past where hello, world was.
	}
}

func TestTruncate(t *testing.T) {
	t.Parallel()

	f := newFile(t)

	checkSize(t, f, 0)
	f.Write([]byte("hello, world\n"))
	checkSize(t, f, 13)
	Truncate(f.Name(), 10)
	checkSize(t, f, 10)
	Truncate(f.Name(), 1024)
	checkSize(t, f, 1024)
	Truncate(f.Name(), 0)
	checkSize(t, f, 0)
	_, err := f.Write([]byte("surprise!"))
	if err == nil {
		checkSize(t, f, 13+9) // wrote at offset past where hello, world was.
	}
}

func TestTruncateNonexistentFile(t *testing.T) {
	t.Parallel()

	assertPathError := func(t testing.TB, path string, err error) {
		t.Helper()
		if pe, ok := err.(*PathError); !ok || !IsNotExist(err) || pe.Path != path {
			t.Errorf("got error: %v\nwant an ErrNotExist PathError with path %q", err, path)
		}
	}

	path := filepath.Join(t.TempDir(), "nonexistent")

	err := Truncate(path, 1)
	assertPathError(t, path, err)

	// Truncate shouldn't create any new file.
	_, err = Stat(path)
	assertPathError(t, path, err)
}

var hasNoatime = sync.OnceValue(func() bool {
	// A sloppy way to check if noatime flag is set (as all filesystems are
	// checked, not just the one we're interested in). A correct way
	// would be to use statvfs syscall and check if flags has ST_NOATIME,
	// but the syscall is OS-specific and is not even wired into Go stdlib.
	//
	// Only used on NetBSD (which ignores explicit atime updates with noatime).
	mounts, _ := ReadFile("/proc/mounts")
	return bytes.Contains(mounts, []byte("noatime"))
})

func TestChtimes(t *testing.T) {
	t.Parallel()

	f := newFile(t)
	// This should be an empty file (see #68687, #68663).
	f.Close()

	testChtimes(t, f.Name())
}

func TestChtimesOmit(t *testing.T) {
	t.Parallel()

	testChtimesOmit(t, true, false)
	testChtimesOmit(t, false, true)
	testChtimesOmit(t, true, true)
	testChtimesOmit(t, false, false) // Same as TestChtimes.
}

func testChtimesOmit(t *testing.T, omitAt, omitMt bool) {
	t.Logf("omit atime: %v, mtime: %v", omitAt, omitMt)
	file := newFile(t)
	// This should be an empty file (see #68687, #68663).
	name := file.Name()
	err := file.Close()
	if err != nil {
		t.Error(err)
	}
	fs, err := Stat(name)
	if err != nil {
		t.Fatal(err)
	}

	wantAtime := Atime(fs)
	wantMtime := fs.ModTime()
	switch runtime.GOOS {
	case "js":
		wantAtime = wantAtime.Truncate(time.Second)
		wantMtime = wantMtime.Truncate(time.Second)
	}

	var setAtime, setMtime time.Time // Zero value means omit.
	if !omitAt {
		wantAtime = wantAtime.Add(-1 * time.Second)
		setAtime = wantAtime
	}
	if !omitMt {
		wantMtime = wantMtime.Add(-1 * time.Second)
		setMtime = wantMtime
	}

	// Change the times accordingly.
	if err := Chtimes(name, setAtime, setMtime); err != nil {
		t.Error(err)
	}

	// Verify the expectations.
	fs, err = Stat(name)
	if err != nil {
		t.Error(err)
	}
	gotAtime := Atime(fs)
	gotMtime := fs.ModTime()

	// TODO: remove the dragonfly omitAt && omitMt exceptions below once the
	// fix (https://github.com/DragonFlyBSD/DragonFlyBSD/commit/c7c71870ed0)
	// is available generally and on CI runners.
	if !gotAtime.Equal(wantAtime) {
		errormsg := fmt.Sprintf("atime mismatch, got: %q, want: %q", gotAtime, wantAtime)
		switch runtime.GOOS {
		case "plan9":
			// Mtime is the time of the last change of content.
			// Similarly, atime is set whenever the contents are
			// accessed; also, it is set whenever mtime is set.
		case "dragonfly":
			if omitAt && omitMt {
				t.Log(errormsg)
				t.Log("Known DragonFly BSD issue (won't work when both times are omitted); ignoring.")
			} else {
				// Assume hammer2 fs; https://www.dragonflybsd.org/hammer/ says:
				// > Because HAMMER2 is a block copy-on-write filesystem,
				// > the "atime" field is not supported and will typically
				// > just reflect local system in-memory caches or mtime.
				//
				// TODO: if only can CI define TM
"""




```