Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Scan and Identification of the Core Functionality:**

The first thing I notice is the function name `TestRemoveAll`. The package name is `os_test`, suggesting this is a test file for the `os` package in Go. The presence of `t *testing.T` as a function argument confirms it's a standard Go test function. Therefore, the code's primary function is to *test* the `os.RemoveAll` function.

**2. Understanding the `os.RemoveAll` Function:**

Based on the test names and the operations being performed, I can deduce that `os.RemoveAll` likely has the following characteristics:

* **Removes files:** The tests create files and then call `RemoveAll` on them.
* **Removes directories:**  The tests create directories (potentially with subdirectories and files) and then call `RemoveAll`.
* **Handles non-existent paths:** The test `RemoveAll("")` checks how it behaves with an empty string (likely a non-existent path).
* **Handles errors:** The tests check for errors after calling `RemoveAll`.
* **Potentially handles permissions:**  The code involving `Chmod` suggests testing scenarios where removing files or directories might be prevented due to permissions.

**3. Deconstructing the Test Cases:**

I start examining each individual test function within `TestRemoveAll`.

* **`TestRemoveAll(t *testing.T)`:** This appears to be the main test suite, covering various scenarios:
    * Removing a single file.
    * Removing a directory containing a file.
    * Removing a directory containing a file and a subdirectory.
    * Handling read-only directories (using `Chmod`). This gives a strong clue about a more complex use case.

* **`TestRemoveAllLarge(t *testing.T)`:**  The name clearly indicates testing performance or correctness with a large number of files.

* **`TestRemoveAllLongPath(t *testing.T)`:** This focuses on handling extremely long file paths, likely related to operating system limits. The platform-specific `switch` statement confirms this.

* **`TestRemoveAllDot(t *testing.T)`:** This tests the behavior of `RemoveAll` when given the current directory (`.`). This is an edge case that needs specific handling.

* **`TestRemoveAllDotDot(t *testing.T)`:**  Similar to the above, but tests the parent directory (`..`).

* **`TestRemoveReadOnlyDir(t *testing.T)`:**  Specifically tests removing a read-only directory.

* **`TestRemoveAllButReadOnlyAndPathError(t *testing.T)`:**  A more complex test involving creating a hierarchy of directories, making some read-only, and checking the specific error type returned. This indicates error handling details.

* **`TestRemoveUnreadableDir(t *testing.T)`:** Tests removing a directory that the current process might not have read permissions for.

* **`TestRemoveAllWithMoreErrorThanReqSize(t *testing.T)`:** This is a more advanced test, likely checking how `RemoveAll` handles a large number of errors when trying to remove read-only files within a read-only directory. The name suggests internal error handling optimization.

* **`TestRemoveAllNoFcntl(t *testing.T)`:**  This is a more specialized test, focusing on optimizing system calls. The use of `strace` on Linux points to verifying that `fcntl` system calls are minimized during the removal process.

* **`BenchmarkRemoveAll(b *testing.B)`:** This is a benchmark, measuring the performance of `RemoveAll` when deleting a large directory structure.

**4. Inferring Functionality and Providing Examples:**

Based on the understanding gained from the tests, I can now confidently state the core functionality of `os.RemoveAll`. I can also construct simple Go code examples demonstrating its usage for removing files and directories.

**5. Reasoning about Code and Providing Input/Output (Hypothetical):**

For the more complex tests (like the read-only directory scenarios), I can reason about the expected behavior. For example, in `TestRemoveAllButReadOnlyAndPathError`, I can hypothesize that if a subdirectory is read-only, `RemoveAll` will fail and return a `PathError` specifically pointing to that problematic subdirectory. I can create a mental (or even written-down) input directory structure and predict the output (which files/directories would be removed, what error would be returned).

**6. Analyzing Command-Line Arguments (Not Applicable):**

I review the code and notice that the tests primarily use the standard Go testing framework. There's no direct parsing of command-line arguments within the tested functions themselves. The `TestRemoveAllNoFcntl` test uses `strace`, but this is *within the test*, not part of the core `os.RemoveAll` functionality. So, I can confidently state that there are no direct command-line arguments handled by the code snippet.

**7. Identifying Potential Pitfalls:**

I consider how a user might misuse `os.RemoveAll`. The tests provide clues:

* **Removing the current or parent directory (`.` or `..`):** The tests for `TestRemoveAllDot` and `TestRemoveAllDotDot` highlight the danger of accidentally deleting important directories.
* **Permissions issues:** The tests involving `Chmod` demonstrate that `RemoveAll` can fail or partially succeed if it encounters read-only directories or files. Users need to be aware of file system permissions.

**8. Structuring the Answer:**

Finally, I organize the findings into a clear and structured answer, using headings and bullet points for readability. I ensure to cover all the points requested in the original prompt (functionality, Go example, code reasoning with input/output, command-line arguments, and common mistakes). I use clear, concise language and provide specific examples where possible.
这段代码是 Go 语言标准库 `os` 包中 `RemoveAll` 函数的测试代码。它的主要功能是测试 `os.RemoveAll` 函数在各种场景下的行为，包括成功删除和遇到错误的情况。

**`os.RemoveAll` 功能实现推理及代码举例:**

`os.RemoveAll` 函数用于递归地删除指定路径及其下的所有文件和目录。如果路径不存在，`RemoveAll` 会返回 `nil` (不报错)。如果删除过程中遇到错误（例如权限不足），它会停止删除并返回遇到的第一个错误。

**Go 代码举例说明 `os.RemoveAll` 的功能:**

```go
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	// 创建一个临时目录结构
	tmpDir := "test_removeall"
	os.MkdirAll(filepath.Join(tmpDir, "subdir1", "subdir2"), 0777)
	os.Create(filepath.Join(tmpDir, "file1.txt"))
	os.Create(filepath.Join(tmpDir, "subdir1", "file2.txt"))

	fmt.Println("删除前目录结构:")
	printDirStructure(tmpDir)

	// 使用 RemoveAll 删除整个临时目录
	err := os.RemoveAll(tmpDir)
	if err != nil {
		fmt.Println("删除失败:", err)
		return
	}

	fmt.Println("\n删除后目录结构:")
	printDirStructure(tmpDir) // 应该为空或不存在

	// 尝试删除一个不存在的路径，不会报错
	err = os.RemoveAll("non_existent_path")
	if err != nil {
		fmt.Println("删除不存在路径失败:", err)
	} else {
		fmt.Println("删除不存在路径成功（无报错）")
	}
}

func printDirStructure(dir string) {
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Println("访问出错:", err)
			return err
		}
		fmt.Println(path)
		return nil
	})
}
```

**假设的输入与输出:**

**输入 (执行 `RemoveAll` 前):**

```
test_removeall/
├── file1.txt
└── subdir1/
    └── file2.txt
    └── subdir2/
```

**输出 (执行 `RemoveAll("test_removeall")` 后):**

```
删除前目录结构:
test_removeall
test_removeall/file1.txt
test_removeall/subdir1
test_removeall/subdir1/file2.txt
test_removeall/subdir1/subdir2

删除后目录结构:
访问出错: lstat test_removeall: no such file or directory
删除不存在路径成功（无报错）
```

**代码推理:**

这段测试代码通过创建不同的文件和目录结构，然后调用 `RemoveAll` 来验证其行为。

* **测试删除文件:**  创建单个文件，然后调用 `RemoveAll` 删除。测试会检查删除后文件是否还存在。
* **测试删除包含文件的目录:** 创建包含文件的目录，然后调用 `RemoveAll` 删除。测试会检查删除后目录是否还存在。
* **测试删除包含文件和子目录的目录:** 创建更复杂的目录结构，然后调用 `RemoveAll` 删除，验证其递归删除的能力。
* **测试权限问题:**  在非 Windows 和 wasip1 系统下，代码会尝试修改子目录的权限为只读 (0)，然后调用 `RemoveAll`。这模拟了删除权限受限目录的情况，并验证 `RemoveAll` 在遇到错误时的行为。虽然 `RemoveAll` 可能无法删除权限受限的目录本身，但它应该尝试删除其下的其他文件和目录。
* **测试空字符串路径:** 调用 `RemoveAll("")`，预期不会报错。
* **测试长路径:**  在支持长路径的系统上，创建非常深的目录结构并尝试删除，验证 `RemoveAll` 对长路径的支持。
* **测试 `.` 和 `..`:** 测试删除当前目录 (`.`) 和父目录 (`..`) 的行为，预期会失败，因为这是危险的操作。
* **测试只读目录:** 创建只读目录并尝试删除，验证 `RemoveAll` 在遇到只读目录时的行为。
* **测试部分只读的目录树:** 创建一个目录树，其中部分目录是只读的，验证 `RemoveAll` 在遇到权限问题时的错误处理，并确保只读目录下的内容不会被删除。
* **测试不可读的目录:** 创建一个不可读的目录并尝试删除。
* **压力测试:** 创建大量只读文件，测试 `RemoveAll` 在遇到大量错误时的处理能力，防止挂起。
* **测试不使用 `fcntl`:**  通过环境变量控制，在 Linux 系统上使用 `strace` 验证 `RemoveAll` 在删除大量目录时是否避免了对每个目录都调用 `fcntl`，这是一种性能优化。
* **基准测试:**  衡量 `RemoveAll` 的性能。

**命令行参数的具体处理:**

这段代码本身是测试代码，不直接处理命令行参数。它依赖 Go 的 `testing` 包来运行测试。你可以使用 `go test` 命令来运行这些测试。例如：

```bash
go test -v os
```

这个命令会运行 `os` 包下的所有测试文件，包括 `removeall_test.go`。

**使用者易犯错的点:**

1. **误删重要目录:**  `RemoveAll` 是一个非常强大的函数，如果不小心使用了错误的路径，可能会删除重要的文件或目录。例如，在终端中直接运行 `go run main.go` (假设你的 `main.go` 文件中使用了 `os.RemoveAll(".")`) 可能会导致当前工作目录下的所有内容被删除。

   ```go
   // 错误示例
   err := os.RemoveAll(".") // 非常危险，会删除当前工作目录
   if err != nil {
       fmt.Println("删除失败:", err)
   }
   ```

2. **权限问题:** 如果尝试删除没有足够权限访问的文件或目录，`RemoveAll` 会返回错误。使用者需要确保运行程序的用户具有删除目标路径及其下所有内容的权限。

   ```go
   // 假设尝试删除一个只读目录
   err := os.RemoveAll("/read_only_dir")
   if err != nil {
       fmt.Println("删除失败:", err) // 可能会因为权限不足而失败
   }
   ```

3. **并发问题:**  如果在多个 goroutine 中同时对同一个路径或其子路径调用 `RemoveAll`，可能会导致不可预测的结果和错误。需要进行适当的同步控制。

4. **删除符号链接的目标:** `RemoveAll` 会删除符号链接指向的目标，而不是符号链接本身。这可能不是使用者期望的行为。如果要删除符号链接本身，应该使用 `os.Remove`。

   ```go
   // 假设 link_to_file 是一个指向 existing_file 的符号链接
   err := os.RemoveAll("link_to_file")
   if err == nil {
       // existing_file 会被删除，而不是 link_to_file
   }
   ```

总之，这段测试代码覆盖了 `os.RemoveAll` 函数的各种使用场景和潜在的错误情况，帮助开发者理解和正确使用这个强大的文件操作函数。使用者在使用时需要特别注意路径的正确性以及权限问题，避免误删重要数据。

Prompt: 
```
这是路径为go/src/os/removeall_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package os_test

import (
	"bytes"
	"fmt"
	"internal/testenv"
	. "os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestRemoveAll(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	if err := RemoveAll(""); err != nil {
		t.Errorf("RemoveAll(\"\"): %v; want nil", err)
	}

	file := filepath.Join(tmpDir, "file")
	path := filepath.Join(tmpDir, "_TestRemoveAll_")
	fpath := filepath.Join(path, "file")
	dpath := filepath.Join(path, "dir")

	// Make a regular file and remove
	fd, err := Create(file)
	if err != nil {
		t.Fatalf("create %q: %s", file, err)
	}
	fd.Close()
	if err = RemoveAll(file); err != nil {
		t.Fatalf("RemoveAll %q (first): %s", file, err)
	}
	if _, err = Lstat(file); err == nil {
		t.Fatalf("Lstat %q succeeded after RemoveAll (first)", file)
	}

	// Make directory with 1 file and remove.
	if err := MkdirAll(path, 0777); err != nil {
		t.Fatalf("MkdirAll %q: %s", path, err)
	}
	fd, err = Create(fpath)
	if err != nil {
		t.Fatalf("create %q: %s", fpath, err)
	}
	fd.Close()
	if err = RemoveAll(path); err != nil {
		t.Fatalf("RemoveAll %q (second): %s", path, err)
	}
	if _, err = Lstat(path); err == nil {
		t.Fatalf("Lstat %q succeeded after RemoveAll (second)", path)
	}

	// Make directory with file and subdirectory and remove.
	if err = MkdirAll(dpath, 0777); err != nil {
		t.Fatalf("MkdirAll %q: %s", dpath, err)
	}
	fd, err = Create(fpath)
	if err != nil {
		t.Fatalf("create %q: %s", fpath, err)
	}
	fd.Close()
	fd, err = Create(dpath + "/file")
	if err != nil {
		t.Fatalf("create %q: %s", fpath, err)
	}
	fd.Close()
	if err = RemoveAll(path); err != nil {
		t.Fatalf("RemoveAll %q (third): %s", path, err)
	}
	if _, err := Lstat(path); err == nil {
		t.Fatalf("Lstat %q succeeded after RemoveAll (third)", path)
	}

	// Chmod is not supported under Windows or wasip1 and test fails as root.
	if runtime.GOOS != "windows" && runtime.GOOS != "wasip1" && Getuid() != 0 {
		// Make directory with file and subdirectory and trigger error.
		if err = MkdirAll(dpath, 0777); err != nil {
			t.Fatalf("MkdirAll %q: %s", dpath, err)
		}

		for _, s := range []string{fpath, dpath + "/file1", path + "/zzz"} {
			fd, err = Create(s)
			if err != nil {
				t.Fatalf("create %q: %s", s, err)
			}
			fd.Close()
		}
		if err = Chmod(dpath, 0); err != nil {
			t.Fatalf("Chmod %q 0: %s", dpath, err)
		}

		// No error checking here: either RemoveAll
		// will or won't be able to remove dpath;
		// either way we want to see if it removes fpath
		// and path/zzz. Reasons why RemoveAll might
		// succeed in removing dpath as well include:
		//	* running as root
		//	* running on a file system without permissions (FAT)
		RemoveAll(path)
		Chmod(dpath, 0777)

		for _, s := range []string{fpath, path + "/zzz"} {
			if _, err = Lstat(s); err == nil {
				t.Fatalf("Lstat %q succeeded after partial RemoveAll", s)
			}
		}
	}
	if err = RemoveAll(path); err != nil {
		t.Fatalf("RemoveAll %q after partial RemoveAll: %s", path, err)
	}
	if _, err = Lstat(path); err == nil {
		t.Fatalf("Lstat %q succeeded after RemoveAll (final)", path)
	}
}

// Test RemoveAll on a large directory.
func TestRemoveAllLarge(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	t.Parallel()

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "_TestRemoveAllLarge_")

	// Make directory with 1000 files and remove.
	if err := MkdirAll(path, 0777); err != nil {
		t.Fatalf("MkdirAll %q: %s", path, err)
	}
	for i := 0; i < 1000; i++ {
		fpath := fmt.Sprintf("%s/file%d", path, i)
		fd, err := Create(fpath)
		if err != nil {
			t.Fatalf("create %q: %s", fpath, err)
		}
		fd.Close()
	}
	if err := RemoveAll(path); err != nil {
		t.Fatalf("RemoveAll %q: %s", path, err)
	}
	if _, err := Lstat(path); err == nil {
		t.Fatalf("Lstat %q succeeded after RemoveAll", path)
	}
}

func TestRemoveAllLongPath(t *testing.T) {
	switch runtime.GOOS {
	case "aix", "darwin", "ios", "dragonfly", "freebsd", "linux", "netbsd", "openbsd", "illumos", "solaris":
		break
	default:
		t.Skip("skipping for not implemented platforms")
	}

	startPath := t.TempDir()
	t.Chdir(startPath)

	// Removing paths with over 4096 chars commonly fails.
	name := strings.Repeat("a", 100)
	for i := 0; i < 41; i++ {
		if err := Mkdir(name, 0755); err != nil {
			t.Fatalf("Could not mkdir %s: %s", name, err)
		}
		if err := Chdir(name); err != nil {
			t.Fatalf("Could not chdir %s: %s", name, err)
		}
	}

	// Chdir out of startPath before attempting to remove it,
	// otherwise RemoveAll fails on aix, illumos and solaris.
	err := Chdir(filepath.Join(startPath, ".."))
	if err != nil {
		t.Fatalf("Could not chdir: %s", err)
	}

	err = RemoveAll(startPath)
	if err != nil {
		t.Errorf("RemoveAll could not remove long file path %s: %s", startPath, err)
	}
}

func TestRemoveAllDot(t *testing.T) {
	t.Chdir(t.TempDir())

	if err := RemoveAll("."); err == nil {
		t.Errorf("RemoveAll succeed to remove .")
	}
}

func TestRemoveAllDotDot(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	subdir := filepath.Join(tempDir, "x")
	subsubdir := filepath.Join(subdir, "y")
	if err := MkdirAll(subsubdir, 0777); err != nil {
		t.Fatal(err)
	}
	if err := RemoveAll(filepath.Join(subsubdir, "..")); err != nil {
		t.Error(err)
	}
	for _, dir := range []string{subsubdir, subdir} {
		if _, err := Stat(dir); err == nil {
			t.Errorf("%s: exists after RemoveAll", dir)
		}
	}
}

// Issue #29178.
func TestRemoveReadOnlyDir(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	subdir := filepath.Join(tempDir, "x")
	if err := Mkdir(subdir, 0); err != nil {
		t.Fatal(err)
	}

	// If an error occurs make it more likely that removing the
	// temporary directory will succeed.
	defer Chmod(subdir, 0777)

	if err := RemoveAll(subdir); err != nil {
		t.Fatal(err)
	}

	if _, err := Stat(subdir); err == nil {
		t.Error("subdirectory was not removed")
	}
}

// Issue #29983.
func TestRemoveAllButReadOnlyAndPathError(t *testing.T) {
	switch runtime.GOOS {
	case "js", "wasip1", "windows":
		t.Skipf("skipping test on %s", runtime.GOOS)
	}

	if Getuid() == 0 {
		t.Skip("skipping test when running as root")
	}

	t.Parallel()

	tempDir := t.TempDir()
	dirs := []string{
		"a",
		"a/x",
		"a/x/1",
		"b",
		"b/y",
		"b/y/2",
		"c",
		"c/z",
		"c/z/3",
	}
	readonly := []string{
		"b",
	}
	inReadonly := func(d string) bool {
		for _, ro := range readonly {
			if d == ro {
				return true
			}
			dd, _ := filepath.Split(d)
			if filepath.Clean(dd) == ro {
				return true
			}
		}
		return false
	}

	for _, dir := range dirs {
		if err := Mkdir(filepath.Join(tempDir, dir), 0777); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range readonly {
		d := filepath.Join(tempDir, dir)
		if err := Chmod(d, 0555); err != nil {
			t.Fatal(err)
		}

		// Defer changing the mode back so that the deferred
		// RemoveAll(tempDir) can succeed.
		defer Chmod(d, 0777)
	}

	err := RemoveAll(tempDir)
	if err == nil {
		t.Fatal("RemoveAll succeeded unexpectedly")
	}

	// The error should be of type *PathError.
	// see issue 30491 for details.
	if pathErr, ok := err.(*PathError); ok {
		want := filepath.Join(tempDir, "b", "y")
		if pathErr.Path != want {
			t.Errorf("RemoveAll(%q): err.Path=%q, want %q", tempDir, pathErr.Path, want)
		}
	} else {
		t.Errorf("RemoveAll(%q): error has type %T, want *fs.PathError", tempDir, err)
	}

	for _, dir := range dirs {
		_, err := Stat(filepath.Join(tempDir, dir))
		if inReadonly(dir) {
			if err != nil {
				t.Errorf("file %q was deleted but should still exist", dir)
			}
		} else {
			if err == nil {
				t.Errorf("file %q still exists but should have been deleted", dir)
			}
		}
	}
}

func TestRemoveUnreadableDir(t *testing.T) {
	switch runtime.GOOS {
	case "js":
		t.Skipf("skipping test on %s", runtime.GOOS)
	}

	if Getuid() == 0 {
		t.Skip("skipping test when running as root")
	}

	t.Parallel()

	tempDir := t.TempDir()
	target := filepath.Join(tempDir, "d0", "d1", "d2")
	if err := MkdirAll(target, 0755); err != nil {
		t.Fatal(err)
	}
	if err := Chmod(target, 0300); err != nil {
		t.Fatal(err)
	}
	if err := RemoveAll(filepath.Join(tempDir, "d0")); err != nil {
		t.Fatal(err)
	}
}

// Issue 29921
func TestRemoveAllWithMoreErrorThanReqSize(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	t.Parallel()

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "_TestRemoveAllWithMoreErrorThanReqSize_")

	// Make directory with 1025 read-only files.
	if err := MkdirAll(path, 0777); err != nil {
		t.Fatalf("MkdirAll %q: %s", path, err)
	}
	for i := 0; i < 1025; i++ {
		fpath := filepath.Join(path, fmt.Sprintf("file%d", i))
		fd, err := Create(fpath)
		if err != nil {
			t.Fatalf("create %q: %s", fpath, err)
		}
		fd.Close()
	}

	// Make the parent directory read-only. On some platforms, this is what
	// prevents Remove from removing the files within that directory.
	if err := Chmod(path, 0555); err != nil {
		t.Fatal(err)
	}
	defer Chmod(path, 0755)

	// This call should not hang, even on a platform that disallows file deletion
	// from read-only directories.
	err := RemoveAll(path)

	if Getuid() == 0 {
		// On many platforms, root can remove files from read-only directories.
		return
	}
	if err == nil {
		if runtime.GOOS == "windows" || runtime.GOOS == "wasip1" {
			// Marking a directory as read-only in Windows does not prevent the RemoveAll
			// from creating or removing files within it.
			//
			// For wasip1, there is no support for file permissions so we cannot prevent
			// RemoveAll from removing the files.
			return
		}
		t.Fatal("RemoveAll(<read-only directory>) = nil; want error")
	}

	dir, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()

	names, _ := dir.Readdirnames(1025)
	if len(names) < 1025 {
		t.Fatalf("RemoveAll(<read-only directory>) unexpectedly removed %d read-only files from that directory", 1025-len(names))
	}
}

func TestRemoveAllNoFcntl(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	const env = "GO_TEST_REMOVE_ALL_NO_FCNTL"
	if dir := Getenv(env); dir != "" {
		if err := RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
		return
	}

	// Only test on Linux so that we can assume we have strace.
	// The code is OS-independent so if it passes on Linux
	// it should pass on other Unix systems.
	if runtime.GOOS != "linux" {
		t.Skipf("skipping test on %s", runtime.GOOS)
	}
	if _, err := Stat("/bin/strace"); err != nil {
		t.Skipf("skipping test because /bin/strace not found: %v", err)
	}
	me, err := Executable()
	if err != nil {
		t.Skipf("skipping because Executable failed: %v", err)
	}

	// Create 100 directories.
	// The test is that we can remove them without calling fcntl
	// on each one.
	tmpdir := t.TempDir()
	subdir := filepath.Join(tmpdir, "subdir")
	if err := Mkdir(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		subsubdir := filepath.Join(subdir, strconv.Itoa(i))
		if err := Mkdir(filepath.Join(subdir, strconv.Itoa(i)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := WriteFile(filepath.Join(subsubdir, "file"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	cmd := testenv.Command(t, "/bin/strace", "-f", "-e", "fcntl", me, "-test.run=^TestRemoveAllNoFcntl$")
	cmd = testenv.CleanCmdEnv(cmd)
	cmd.Env = append(cmd.Env, env+"="+subdir)
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		t.Logf("%s", out)
	}
	if err != nil {
		t.Fatal(err)
	}

	if got := bytes.Count(out, []byte("fcntl")); got >= 100 {
		t.Errorf("found %d fcntl calls, want < 100", got)
	}
}

func BenchmarkRemoveAll(b *testing.B) {
	tmpDir := filepath.Join(b.TempDir(), "target")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		err := CopyFS(tmpDir, DirFS("."))
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		if err := RemoveAll(tmpDir); err != nil {
			b.Fatal(err)
		}
	}
}

"""



```