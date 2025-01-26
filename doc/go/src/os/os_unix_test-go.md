Response:
The user wants to understand the functionality of the provided Go code snippet. The code is a test file for the `os` package in Go, specifically targeting Unix-like systems.

Here's a breakdown of the functionalities and how to explain them:

1. **`init()` function:**  It initializes a function `isReadonlyError` which checks if an error is a read-only file system error. This is a utility for the tests.

2. **`checkUidGid()` function:**  This is a helper function used in tests to verify the user ID (UID) and group ID (GID) of a file. It uses `Lstat` to get file information and checks the `Uid` and `Gid` fields.

3. **`TestChown()` function:** This test focuses on the `Chown` function, which changes the owner and group of a file. It covers:
    - Creating a new file.
    - Getting the current GID.
    - Attempting to change the file's GID to the current GID.
    - Iterating through auxiliary groups and attempting to change the file's GID to each of them.
    - It also tests `f.Chown` which operates on an open file descriptor.
    - Handling cases where `Chown` is not supported.

4. **`TestFileChown()` function:** Similar to `TestChown`, but specifically tests the `File.Chown` method, which operates on an open file descriptor. It performs the same GID changing tests as `TestChown`.

5. **`TestLchown()` function:** This test focuses on `Lchown`, which changes the owner and group of a symbolic link without following the link. It:
    - Creates a symbolic link.
    - Attempts to change the link's GID to the current GID.
    - Iterates through auxiliary groups and attempts to change the link's GID.
    - Verifies that the target file's ownership remains unchanged.
    - Handles cases where `Lchown` is not supported.

6. **`TestReaddirRemoveRace()` function:** This test addresses a race condition in `Readdir`. It simulates a scenario where a file is removed while `Readdir` is being called. The test verifies that `Readdir` returns a non-empty slice or an error in such situations.

7. **`TestMkdirStickyUmask()` function:** This test examines the interaction between `Mkdir` with the sticky bit and the `umask`. It ensures that the `umask` is respected when creating a directory with the sticky bit set.

8. **`newFileTest()` function:** This is a helper function used by `TestNewFileBlock` and `TestNewFileNonBlock`. It creates a pipe, optionally sets the read end to non-blocking, converts the file descriptor to an `os.File`, and then attempts to read from it with a deadline.

9. **`TestNewFileBlock()` function:** Tests `NewFile` with a blocking file descriptor (from a pipe). It expects the read to succeed after data is written.

10. **`TestNewFileNonBlock()` function:** Tests `NewFile` with a non-blocking file descriptor (from a pipe). It expects the read to fail with a deadline exceeded error.

11. **`TestNewFileInvalid()` function:** Tests `NewFile` with an invalid file descriptor (-1) and verifies that it returns `nil`.

12. **`TestSplitPath()` function:** Tests the `SplitPath` function, which splits a path into its directory and base name components.

13. **`TestIssue60181()` function:** This test checks if writing to a file opened with `O_APPEND` using `io.Copy` works correctly and that the `copy_file_range` syscall is *not* used (which would fail in this scenario on Linux).

Now, let's structure the answer according to the user's request.
这段代码是 Go 语言标准库 `os` 包的一部分，具体来说是 `go/src/os/os_unix_test.go` 文件的一部分，主要用于测试在 Unix-like 操作系统上的文件和目录操作相关的功能。

**主要功能列举：**

1. **文件所有权变更测试 (`TestChown`, `TestFileChown`, `TestLchown`)**: 测试 `os.Chown`, `os.File.Chown`, 和 `os.Lchown` 函数，用于变更文件的用户 ID (UID) 和组 ID (GID)。
2. **`Readdir` 函数竞态条件测试 (`TestReaddirRemoveRace`)**: 测试在调用 `os.File.Readdir` 读取目录项时，如果同时有文件被删除，是否会产生预期的行为（返回非空切片或错误）。
3. **`Mkdir` 和粘滞位以及 `umask` 的交互测试 (`TestMkdirStickyUmask`)**: 测试使用 `os.Mkdir` 创建带有粘滞位 (sticky bit) 的目录时，是否会受到系统 `umask` 的影响。
4. **`NewFile` 函数的测试 (`TestNewFileBlock`, `TestNewFileNonBlock`, `TestNewFileInvalid`)**: 测试 `os.NewFile` 函数，该函数将一个底层的系统文件描述符转换为 `os.File` 对象。测试了阻塞和非阻塞文件描述符的情况以及无效的文件描述符。
5. **路径分割测试 (`TestSplitPath`)**: 测试 `os.SplitPath` 函数，该函数将路径分割为目录和基本文件名。
6. **追加模式写入测试 (`TestIssue60181`)**:  测试以追加模式 (`O_APPEND`) 打开的文件是否能正确使用 `io.Copy` 进行写入，并验证在 Linux 系统上不会错误地使用 `copy_file_range` 系统调用。
7. **辅助函数**: 包含一些辅助函数，例如 `checkUidGid` 用于检查文件的 UID 和 GID。

**Go 语言功能实现推理及代码示例：**

这段代码主要测试了 Go 语言中与文件系统操作相关的系统调用封装。 比如，`Chown`、`Lchown` 等函数是对 Unix 系统调用 `chown` 和 `lchown` 的封装。

**示例 1: `Chown` 函数的实现推理**

`os.Chown` 函数允许修改文件的所有者和所属组。 它底层会调用 Unix 系统的 `chown` 系统调用。

```go
// 假设的 os.Chown 函数实现 (简化)
func Chown(name string, uid, gid int) error {
	return syscall.Chown(name, uid, gid)
}

// 使用示例
package main

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
)

func main() {
	filename := "test.txt"
	// 创建一个测试文件
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println("创建文件失败:", err)
		return
	}
	file.Close()

	// 获取当前用户的 UID 和 GID
	currentUser, err := user.Current()
	if err != nil {
		fmt.Println("获取当前用户信息失败:", err)
		return
	}
	uid, err := strconv.Atoi(currentUser.Uid)
	if err != nil {
		fmt.Println("转换 UID 失败:", err)
		return
	}
	gid, err := strconv.Atoi(currentUser.Gid)
	if err != nil {
		fmt.Println("转换 GID 失败:", err)
		return
	}

	// 尝试将文件的所有者和所属组更改为当前用户
	err = os.Chown(filename, uid, gid)
	if err != nil {
		fmt.Println("修改文件所有者失败:", err)
		return
	}

	fmt.Printf("文件 %s 的所有者已更改为 UID: %d, GID: %d\n", filename, uid, gid)
}
```

**假设输入与输出：**

假设当前用户 UID 为 1000，GID 为 1000。执行上述代码后，如果成功，`test.txt` 文件的所有者和所属组将被更改为 UID 1000 和 GID 1000。输出可能为：`文件 test.txt 的所有者已更改为 UID: 1000, GID: 1000`。 如果由于权限不足等原因失败，则会输出相应的错误信息。

**示例 2: `NewFile` 函数的实现推理**

`os.NewFile` 函数接收一个 `uintptr` 类型的整数（表示文件描述符）和一个字符串（通常是文件名，用于调试和显示）作为参数，并返回一个 `os.File` 指针。

```go
// 假设的 os.NewFile 函数实现 (简化)
func NewFile(fd uintptr, name string) *File {
	if fd == ^uintptr(0) { // 检查是否为无效的文件描述符
		return nil
	}
	return &File{fd: fd, name: name}
}

// 使用示例
package main

import (
	"fmt"
	"os"
	"syscall"
)

func main() {
	// 创建一个管道
	r, w, err := syscall.Pipe()
	if err != nil {
		fmt.Println("创建管道失败:", err)
		return
	}
	defer syscall.Close(r)
	defer syscall.Close(w)

	// 将管道的读取端的文件描述符转换为 os.File
	readFile := os.NewFile(uintptr(r), "/my/pipe/reader")
	if readFile == nil {
		fmt.Println("转换文件描述符失败")
		return
	}
	fmt.Println("成功创建读取文件对象:", readFile.Name())

	// 将管道的写入端的文件描述符转换为 os.File
	writeFile := os.NewFile(uintptr(w), "/my/pipe/writer")
	if writeFile == nil {
		fmt.Println("转换文件描述符失败")
		return
	}
	fmt.Println("成功创建写入文件对象:", writeFile.Name())
}
```

**假设输入与输出：**

执行上述代码后，会创建一个管道，并将管道的读取端和写入端的文件描述符分别转换为 `os.File` 对象。输出可能为：
```
成功创建读取文件对象: /my/pipe/reader
成功创建写入文件对象: /my/pipe/writer
```

**命令行参数处理：**

这段代码本身是测试代码，不直接处理命令行参数。它依赖于 `testing` 包来运行测试用例。 通常使用 `go test` 命令来执行这些测试。 例如，要在当前目录下运行 `os` 包的测试，可以在终端中执行：

```bash
go test -v os
```

`-v` 参数表示显示详细的测试输出。

**使用者易犯错的点：**

1. **权限问题**: 在使用 `Chown` 或 `Lchown` 修改文件所有权时，需要足够的权限（通常是 root 用户）。如果普通用户尝试修改不属于自己的文件的所有权，会遇到权限错误。

   ```go
   package main

   import (
       "fmt"
       "os"
   )

   func main() {
       err := os.Chown("some_file.txt", 1000, 1000) // 尝试将所有者和组都改为 UID/GID 1000
       if err != nil {
           fmt.Println("修改所有者失败:", err) // 可能会输出 "operation not permitted" 等错误
       }
   }
   ```
   **易错点**: 普通用户尝试运行上述代码，如果 `some_file.txt` 的当前所有者不是执行用户，通常会因为权限不足而失败。

2. **`Lchown` 的使用场景**:  `Lchown` 用于修改符号链接的拥有者，而不是链接指向的实际文件。 容易错误地认为 `Lchown` 会修改目标文件的拥有者。

   ```go
   package main

   import (
       "fmt"
       "os"
   )

   func main() {
       // 假设 target.txt 存在
       err := os.Symlink("target.txt", "symlink_to_target.txt")
       if err != nil {
           fmt.Println("创建符号链接失败:", err)
           return
       }

       err = os.Lchown("symlink_to_target.txt", 1000, 1000) // 修改符号链接的所有者
       if err != nil {
           fmt.Println("修改符号链接所有者失败:", err)
       }

       // target.txt 的所有者不受 Lchown 的影响
   }
   ```
   **易错点**:  开发者可能期望 `Lchown` 修改 `target.txt` 的所有者，但实际上它只影响 `symlink_to_target.txt` 这个链接文件本身。

3. **文件描述符的管理**:  使用 `NewFile` 时，需要确保传入的文件描述符是有效的，并且在不再使用返回的 `os.File` 对象时要及时 `Close()`，以避免资源泄露。

   ```go
   package main

   import (
       "fmt"
       "os"
       "syscall"
   )

   func main() {
       r, _, err := syscall.Pipe()
       if err != nil {
           fmt.Println("创建管道失败:", err)
           return
       }

       // 创建 os.File 对象
       readFile := os.NewFile(uintptr(r), "pipe_reader")

       // ... 使用 readFile ...

       // 忘记关闭文件描述符
       // readFile.Close() // 应该调用 Close()

       // 在程序结束前，底层的文件描述符 r 没有被关闭，可能导致资源泄露
   }
   ```
   **易错点**:  忘记调用 `readFile.Close()` 会导致底层的文件描述符没有被释放，特别是在循环或长时间运行的程序中，可能会耗尽文件描述符资源。

这段测试代码覆盖了 `os` 包在 Unix 系统上的关键文件操作功能，并对可能出现的错误场景进行了测试。理解这些测试用例能够帮助开发者更好地理解和使用 `os` 包提供的功能。

Prompt: 
```
这是路径为go/src/os/os_unix_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package os_test

import (
	"internal/testenv"
	"io"
	. "os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func init() {
	isReadonlyError = func(err error) bool { return err == syscall.EROFS }
}

// For TestRawConnReadWrite.
type syscallDescriptor = int

func checkUidGid(t *testing.T, path string, uid, gid int) {
	dir, err := Lstat(path)
	if err != nil {
		t.Fatalf("Lstat %q (looking for uid/gid %d/%d): %s", path, uid, gid, err)
	}
	sys := dir.Sys().(*syscall.Stat_t)
	if int(sys.Uid) != uid {
		t.Errorf("Lstat %q: uid %d want %d", path, sys.Uid, uid)
	}
	if int(sys.Gid) != gid {
		t.Errorf("Lstat %q: gid %d want %d", path, sys.Gid, gid)
	}
}

func TestChown(t *testing.T) {
	if runtime.GOOS == "wasip1" {
		t.Skip("file ownership not supported on " + runtime.GOOS)
	}
	t.Parallel()

	f := newFile(t)
	dir, err := f.Stat()
	if err != nil {
		t.Fatalf("stat %s: %s", f.Name(), err)
	}

	// Can't change uid unless root, but can try
	// changing the group id. First try our current group.
	gid := Getgid()
	t.Log("gid:", gid)
	if err = Chown(f.Name(), -1, gid); err != nil {
		t.Fatalf("chown %s -1 %d: %s", f.Name(), gid, err)
	}
	sys := dir.Sys().(*syscall.Stat_t)
	checkUidGid(t, f.Name(), int(sys.Uid), gid)

	// Then try all the auxiliary groups.
	groups, err := Getgroups()
	if err != nil {
		t.Fatalf("getgroups: %s", err)
	}
	t.Log("groups: ", groups)
	for _, g := range groups {
		if err = Chown(f.Name(), -1, g); err != nil {
			if testenv.SyscallIsNotSupported(err) {
				t.Logf("chown %s -1 %d: %s (error ignored)", f.Name(), g, err)
				// Since the Chown call failed, the file should be unmodified.
				checkUidGid(t, f.Name(), int(sys.Uid), gid)
				continue
			}
			t.Fatalf("chown %s -1 %d: %s", f.Name(), g, err)
		}
		checkUidGid(t, f.Name(), int(sys.Uid), g)

		// change back to gid to test fd.Chown
		if err = f.Chown(-1, gid); err != nil {
			t.Fatalf("fchown %s -1 %d: %s", f.Name(), gid, err)
		}
		checkUidGid(t, f.Name(), int(sys.Uid), gid)
	}
}

func TestFileChown(t *testing.T) {
	if runtime.GOOS == "wasip1" {
		t.Skip("file ownership not supported on " + runtime.GOOS)
	}
	t.Parallel()

	f := newFile(t)
	dir, err := f.Stat()
	if err != nil {
		t.Fatalf("stat %s: %s", f.Name(), err)
	}

	// Can't change uid unless root, but can try
	// changing the group id. First try our current group.
	gid := Getgid()
	t.Log("gid:", gid)
	if err = f.Chown(-1, gid); err != nil {
		t.Fatalf("fchown %s -1 %d: %s", f.Name(), gid, err)
	}
	sys := dir.Sys().(*syscall.Stat_t)
	checkUidGid(t, f.Name(), int(sys.Uid), gid)

	// Then try all the auxiliary groups.
	groups, err := Getgroups()
	if err != nil {
		t.Fatalf("getgroups: %s", err)
	}
	t.Log("groups: ", groups)
	for _, g := range groups {
		if err = f.Chown(-1, g); err != nil {
			if testenv.SyscallIsNotSupported(err) {
				t.Logf("chown %s -1 %d: %s (error ignored)", f.Name(), g, err)
				// Since the Chown call failed, the file should be unmodified.
				checkUidGid(t, f.Name(), int(sys.Uid), gid)
				continue
			}
			t.Fatalf("fchown %s -1 %d: %s", f.Name(), g, err)
		}
		checkUidGid(t, f.Name(), int(sys.Uid), g)

		// change back to gid to test fd.Chown
		if err = f.Chown(-1, gid); err != nil {
			t.Fatalf("fchown %s -1 %d: %s", f.Name(), gid, err)
		}
		checkUidGid(t, f.Name(), int(sys.Uid), gid)
	}
}

func TestLchown(t *testing.T) {
	testenv.MustHaveSymlink(t)
	t.Parallel()

	f := newFile(t)
	dir, err := f.Stat()
	if err != nil {
		t.Fatalf("stat %s: %s", f.Name(), err)
	}

	linkname := f.Name() + "2"
	if err := Symlink(f.Name(), linkname); err != nil {
		if runtime.GOOS == "android" && IsPermission(err) {
			t.Skip("skipping test on Android; permission error creating symlink")
		}
		t.Fatalf("link %s -> %s: %v", f.Name(), linkname, err)
	}
	defer Remove(linkname)

	// Can't change uid unless root, but can try
	// changing the group id. First try our current group.
	gid := Getgid()
	t.Log("gid:", gid)
	if err = Lchown(linkname, -1, gid); err != nil {
		if err, ok := err.(*PathError); ok && err.Err == syscall.ENOSYS {
			t.Skip("lchown is unavailable")
		}
		t.Fatalf("lchown %s -1 %d: %s", linkname, gid, err)
	}
	sys := dir.Sys().(*syscall.Stat_t)
	checkUidGid(t, linkname, int(sys.Uid), gid)

	// Then try all the auxiliary groups.
	groups, err := Getgroups()
	if err != nil {
		t.Fatalf("getgroups: %s", err)
	}
	t.Log("groups: ", groups)
	for _, g := range groups {
		if err = Lchown(linkname, -1, g); err != nil {
			if testenv.SyscallIsNotSupported(err) {
				t.Logf("lchown %s -1 %d: %s (error ignored)", f.Name(), g, err)
				// Since the Lchown call failed, the file should be unmodified.
				checkUidGid(t, f.Name(), int(sys.Uid), gid)
				continue
			}
			t.Fatalf("lchown %s -1 %d: %s", linkname, g, err)
		}
		checkUidGid(t, linkname, int(sys.Uid), g)

		// Check that link target's gid is unchanged.
		checkUidGid(t, f.Name(), int(sys.Uid), int(sys.Gid))

		if err = Lchown(linkname, -1, gid); err != nil {
			t.Fatalf("lchown %s -1 %d: %s", f.Name(), gid, err)
		}
	}
}

// Issue 16919: Readdir must return a non-empty slice or an error.
func TestReaddirRemoveRace(t *testing.T) {
	oldStat := *LstatP
	defer func() { *LstatP = oldStat }()
	*LstatP = func(name string) (FileInfo, error) {
		if strings.HasSuffix(name, "some-file") {
			// Act like it's been deleted.
			return nil, ErrNotExist
		}
		return oldStat(name)
	}
	dir := t.TempDir()
	if err := WriteFile(filepath.Join(dir, "some-file"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	d, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	fis, err := d.Readdir(2) // notably, greater than zero
	if len(fis) == 0 && err == nil {
		// This is what used to happen (Issue 16919)
		t.Fatal("Readdir = empty slice & err == nil")
	}
	if len(fis) != 0 || err != io.EOF {
		t.Errorf("Readdir = %d entries: %v; want 0, io.EOF", len(fis), err)
		for i, fi := range fis {
			t.Errorf("  entry[%d]: %q, %v", i, fi.Name(), fi.Mode())
		}
		t.FailNow()
	}
}

// Issue 23120: respect umask when doing Mkdir with the sticky bit
func TestMkdirStickyUmask(t *testing.T) {
	if runtime.GOOS == "wasip1" {
		t.Skip("file permissions not supported on " + runtime.GOOS)
	}
	// Issue #69788: This test temporarily changes the umask for testing purposes,
	// so it shouldn't be run in parallel with other test cases
	// to avoid other tests (e.g., TestCopyFS) creating files with an unintended umask.

	const umask = 0077
	dir := t.TempDir()

	oldUmask := syscall.Umask(umask)
	defer syscall.Umask(oldUmask)

	// We have set a umask, but if the parent directory happens to have a default
	// ACL, the umask may be ignored. To prevent spurious failures from an ACL,
	// we create a non-sticky directory as a “control case” to compare against our
	// sticky-bit “experiment”.
	control := filepath.Join(dir, "control")
	if err := Mkdir(control, 0755); err != nil {
		t.Fatal(err)
	}
	cfi, err := Stat(control)
	if err != nil {
		t.Fatal(err)
	}

	p := filepath.Join(dir, "dir1")
	if err := Mkdir(p, ModeSticky|0755); err != nil {
		t.Fatal(err)
	}
	fi, err := Stat(p)
	if err != nil {
		t.Fatal(err)
	}

	got := fi.Mode()
	want := cfi.Mode() | ModeSticky
	if got != want {
		t.Errorf("Mkdir(_, ModeSticky|0755) created dir with mode %v; want %v", got, want)
	}
}

// See also issues: 22939, 24331
func newFileTest(t *testing.T, blocking bool) {
	if runtime.GOOS == "js" || runtime.GOOS == "wasip1" {
		t.Skipf("syscall.Pipe is not available on %s.", runtime.GOOS)
	}

	p := make([]int, 2)
	if err := syscall.Pipe(p); err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer syscall.Close(p[1])

	// Set the read-side to non-blocking.
	if !blocking {
		if err := syscall.SetNonblock(p[0], true); err != nil {
			syscall.Close(p[0])
			t.Fatalf("SetNonblock: %v", err)
		}
	}
	// Convert it to a file.
	file := NewFile(uintptr(p[0]), "notapipe")
	if file == nil {
		syscall.Close(p[0])
		t.Fatalf("failed to convert fd to file!")
	}
	defer file.Close()

	timeToWrite := 100 * time.Millisecond
	timeToDeadline := 1 * time.Millisecond
	if !blocking {
		// Use a longer time to avoid flakes.
		// We won't be waiting this long anyhow.
		timeToWrite = 1 * time.Second
	}

	// Try to read with deadline (but don't block forever).
	b := make([]byte, 1)
	timer := time.AfterFunc(timeToWrite, func() { syscall.Write(p[1], []byte("a")) })
	defer timer.Stop()
	file.SetReadDeadline(time.Now().Add(timeToDeadline))
	_, err := file.Read(b)
	if !blocking {
		// We want it to fail with a timeout.
		if !isDeadlineExceeded(err) {
			t.Fatalf("No timeout reading from file: %v", err)
		}
	} else {
		// We want it to succeed after 100ms
		if err != nil {
			t.Fatalf("Error reading from file: %v", err)
		}
	}
}

func TestNewFileBlock(t *testing.T) {
	t.Parallel()
	newFileTest(t, true)
}

func TestNewFileNonBlock(t *testing.T) {
	t.Parallel()
	newFileTest(t, false)
}

func TestNewFileInvalid(t *testing.T) {
	t.Parallel()
	const negOne = ^uintptr(0)
	if f := NewFile(negOne, "invalid"); f != nil {
		t.Errorf("NewFile(-1) got %v want nil", f)
	}
}

func TestSplitPath(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct{ path, wantDir, wantBase string }{
		{"a", ".", "a"},
		{"a/", ".", "a"},
		{"a//", ".", "a"},
		{"a/b", "a", "b"},
		{"a/b/", "a", "b"},
		{"a/b/c", "a/b", "c"},
		{"/a", "/", "a"},
		{"/a/", "/", "a"},
		{"/a/b", "/a", "b"},
		{"/a/b/", "/a", "b"},
		{"/a/b/c", "/a/b", "c"},
		{"//a", "/", "a"},
		{"//a/", "/", "a"},
		{"///a", "/", "a"},
		{"///a/", "/", "a"},
	} {
		if dir, base := SplitPath(tt.path); dir != tt.wantDir || base != tt.wantBase {
			t.Errorf("splitPath(%q) = %q, %q, want %q, %q", tt.path, dir, base, tt.wantDir, tt.wantBase)
		}
	}
}

// Test that copying to files opened with O_APPEND works and
// the copy_file_range syscall isn't used on Linux.
//
// Regression test for go.dev/issue/60181
func TestIssue60181(t *testing.T) {
	t.Chdir(t.TempDir())

	want := "hello gopher"

	a, err := CreateTemp(".", "a")
	if err != nil {
		t.Fatal(err)
	}
	a.WriteString(want[:5])
	a.Close()

	b, err := CreateTemp(".", "b")
	if err != nil {
		t.Fatal(err)
	}
	b.WriteString(want[5:])
	b.Close()

	afd, err := syscall.Open(a.Name(), syscall.O_RDWR|syscall.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}

	bfd, err := syscall.Open(b.Name(), syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}

	aa := NewFile(uintptr(afd), a.Name())
	defer aa.Close()
	bb := NewFile(uintptr(bfd), b.Name())
	defer bb.Close()

	// This would fail on Linux in case the copy_file_range syscall was used because it doesn't
	// support destination files opened with O_APPEND, see
	// https://man7.org/linux/man-pages/man2/copy_file_range.2.html#ERRORS
	_, err = io.Copy(aa, bb)
	if err != nil {
		t.Fatal(err)
	}

	buf, err := ReadFile(aa.Name())
	if err != nil {
		t.Fatal(err)
	}

	if got := string(buf); got != want {
		t.Errorf("files not concatenated: got %q, want %q", got, want)
	}
}

"""



```