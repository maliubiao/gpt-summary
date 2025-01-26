Response:
Let's break down the thought process for analyzing the provided Go code and generating the answer.

1. **Understanding the Request:** The core request is to analyze a Go test file (`root_test.go`) and explain its purpose, implementation details, potential pitfalls, and illustrate its functionality with examples.

2. **Initial Code Scan - Identifying Key Structures and Functions:**  The first step is to quickly scan the code and identify the major components. I see:
    * Imports:  `os`, `testing`, `io`, `path/filepath`, etc. This immediately tells me it's related to file system operations and testing.
    * `testMaybeRooted` function:  This suggests a core concept of testing with and without an `os.Root`.
    * `makefs` function: This looks like a utility to create a temporary file system structure for testing. The string format for defining files, directories, and symlinks is a key observation.
    * `rootTest` struct: This clearly defines a test case structure, containing file system layout, target paths, and error expectations.
    * `run` method on `rootTest`:  This is the execution logic for each test case.
    * `errEndsTest` function: A helper for checking expected errors in tests.
    * `rootTestCases` variable: A slice of `rootTest` structs, providing various test scenarios.
    * Numerous `TestRoot*` functions:  These test specific methods of the `os.Root` type (Open, Create, Mkdir, Remove, Stat, Lstat, OpenRoot).
    * `rootConsistencyTest` struct and `rootConsistencyTestCases`: This seems to compare the behavior of `os.Root` methods with regular `os` package functions.
    * `TestRootConsistency*` functions:  Test consistency between `os.Root` and `os` functions.
    * `TestRootRaceRenameDir`:  This looks like a test for race conditions involving renaming directories.
    * `TestOpenInRoot`: A test for a specific `os.OpenInRoot` function.

3. **Deconstructing `makefs`:** This is a crucial function to understand. I need to analyze how it creates the file system.
    * It takes a slice of strings as input.
    * It creates a temporary directory named "ROOT".
    * It iterates through the input strings, parsing them to create files, directories, or symlinks.
    * It handles special markers like `$ABS`.
    * It uses `os.MkdirAll`, `os.Symlink`, `os.WriteFile`.

4. **Understanding `os.Root`:** The presence of `os.Root` and the tests around it strongly suggest that Go has introduced a way to operate on a restricted view of the file system. The `testMaybeRooted` function reinforces this idea of testing with and without this restricted view.

5. **Analyzing `rootTest` and `rootTestCases`:** These define the testing methodology. Each test case specifies a miniature file system, an operation to perform (`open`), the expected target file (after symlink resolution), and whether an error is expected. This is classic table-driven testing. The `ltarget` field is important for understanding how operations like `Remove` and `Lstat` handle the final symlink component.

6. **Analyzing the `TestRoot*` functions:** Each of these focuses on testing a specific method of `os.Root`. They use `rootTestCases` to iterate through different scenarios. Key things to note:
    * They set up the file system using `makefs`.
    * They perform the operation on the `os.Root` object.
    * They verify the outcome (success/failure, file content, etc.).
    * The `errEndsTest` function is used for clean error checking.

7. **Analyzing `rootConsistencyTest` and `TestRootConsistency*`:** These are designed to ensure that `os.Root` methods behave similarly to their counterparts in the `os` package when operating on the same files within the restricted root. The `detailedErrorMismatch` field highlights expected platform-specific error differences.

8. **Inferring the Purpose of `os.Root`:** Based on the test structure, the function names, and the emphasis on restricting access, I can infer that `os.Root` is likely a mechanism to create a sandboxed file system view. This would allow a program to operate within a specific directory without being able to access files outside of it, enhancing security.

9. **Crafting the Explanation:** Now, I can start structuring the answer based on the initial request:

    * **功能列举:**  List the functionalities tested by the code, directly mapping to the `TestRoot*` functions (Open, Create, Mkdir, Remove, Stat, Lstat, OpenRoot).
    * **Go语言功能推理:**  Explain the inferred purpose of `os.Root` as a way to create a restricted file system view.
    * **代码举例:** Provide a concise Go code example demonstrating how to use `os.OpenRoot` and perform operations within the restricted root. Include expected output.
    * **代码推理 (within tests):**  Explain how the `rootTestCases` work, focusing on how `makefs` sets up the file system and how the test cases verify behavior, particularly around symlinks and escaping paths. Include an example of a test case with inputs and expected outputs.
    * **命令行参数:**  The provided code doesn't handle command-line arguments, so explicitly state that.
    * **易犯错的点:** Focus on the potential for path escaping when using `os.Root` and how the tests are designed to prevent this. Provide an example of a failing scenario.

10. **Review and Refine:** Finally, review the generated answer for clarity, accuracy, and completeness. Ensure the examples are correct and easy to understand. Make sure the language is clear and concise. For instance, initially, I might have just said "tests file operations," but refining it to list specific operations like "open files," "create files," etc., is more informative. Similarly, clearly explaining the role of `makefs` and how the test cases define expected behavior is important.

This structured approach, starting with a high-level overview and gradually drilling down into the details, allows for a comprehensive understanding and effective explanation of the provided Go code. The key is to identify the core concepts and how the tests are designed to validate them.
这段Go语言代码是 `os` 包的一部分，专门用于测试 `os.Root` 类型的功能。 `os.Root` 是 Go 1.22 引入的一个新特性，它允许程序在一个受限的文件系统根目录下执行操作，类似于 chroot 但更加轻量级。

**功能列举:**

这段代码主要测试了 `os.Root` 类型的以下功能：

1. **创建和打开受限根目录:** 测试 `os.OpenRoot` 函数，用于创建一个指向指定目录的 `os.Root` 实例。
2. **在受限根目录下打开文件和目录:** 测试 `os.Root` 的 `Open` 方法，验证它能在受限的根目录下正确地打开文件和目录。
3. **在受限根目录下创建文件:** 测试 `os.Root` 的 `Create` 方法，验证它能在受限的根目录下创建新文件。
4. **在受限根目录下创建目录:** 测试 `os.Root` 的 `Mkdir` 方法，验证它能在受限的根目录下创建新目录。
5. **在受限根目录下打开新的受限根目录:** 测试 `os.Root` 的 `OpenRoot` 方法，验证它能在当前受限根目录下打开子目录作为新的受限根目录。
6. **在受限根目录下删除文件和目录:** 测试 `os.Root` 的 `Remove` 方法，验证它能在受限的根目录下删除文件和目录。
7. **在受限根目录下获取文件和目录信息:** 测试 `os.Root` 的 `Stat` 和 `Lstat` 方法，验证它们能在受限的根目录下正确获取文件和目录的信息。
8. **与标准 `os` 包函数的行为一致性:** 通过 `rootConsistencyTest` 和相关的测试函数，验证 `os.Root` 的方法与标准 `os` 包中的对应函数（如 `os.Open`, `os.Create`, `os.Mkdir` 等）在行为上是否一致。这包括在不同的文件系统布局和操作下，返回值和错误是否相同。
9. **处理符号链接:** 详细测试了 `os.Root` 在处理符号链接时的行为，包括符号链接的目标解析、符号链接环路、以及尝试通过符号链接逃逸受限根目录的情况。
10. **处理路径中的 `.` 和 `..`:** 测试了 `os.Root` 在处理包含 `.` (当前目录) 和 `..` (父目录) 的路径时的行为，特别是防止路径逃逸受限根目录。
11. **并发关闭:** 测试了在有其他 goroutine 正在使用 `os.Root` 的情况下关闭它的行为。
12. **使用已关闭的 `os.Root`:** 测试了在 `os.Root` 实例被关闭后尝试使用它的行为，预期会返回 `os.ErrClosed` 错误。
13. **权限模式:** 测试了尝试在 `os.Root` 的 `OpenFile` 和 `Mkdir` 中使用非权限相关的模式位（如 `os.ModeSticky`）是否会产生错误。
14. **重命名后打开文件:** 测试了在通过 `os.Root` 打开一个目录后，如果该目录被重命名，是否仍然可以访问该目录下已存在的文件。
15. **防止通过重命名目录逃逸:**  `TestRootRaceRenameDir` 尝试通过在一个 goroutine 中执行 `r.Open` 操作，同时在另一个 goroutine 中重命名路径中的某个目录，来测试 `os.Root` 是否能防止路径逃逸。
16. **`os.OpenInRoot` 函数:** 测试了 `os.OpenInRoot` 函数，该函数在一个指定的根目录下打开文件，并且会阻止打开位于根目录之外的文件。

**`os.Root` 功能实现推理与代码示例:**

`os.Root` 的核心功能是提供一个限定的文件系统视图。当使用 `os.OpenRoot` 打开一个目录时，返回的 `os.Root` 实例上的所有文件操作都将相对于这个目录进行。这通过在系统调用层面上进行路径处理来实现，确保所有操作都限制在该根目录下。

以下代码示例展示了如何使用 `os.Root` 创建和操作受限的文件系统：

```go
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	tempDir, err := os.MkdirTemp("", "root-example")
	if err != nil {
		fmt.Println("创建临时目录失败:", err)
		return
	}
	defer os.RemoveAll(tempDir)

	// 在临时目录下创建一些文件和目录
	os.MkdirAll(filepath.Join(tempDir, "subdir"), 0777)
	os.WriteFile(filepath.Join(tempDir, "file1.txt"), []byte("这是根目录下的文件"), 0666)
	os.WriteFile(filepath.Join(tempDir, "subdir", "file2.txt"), []byte("这是子目录下的文件"), 0666)

	// 打开临时目录作为受限根目录
	root, err := os.OpenRoot(tempDir)
	if err != nil {
		fmt.Println("打开受限根目录失败:", err)
		return
	}
	defer root.Close()

	// 在受限根目录下打开文件
	f1, err := root.Open("file1.txt")
	if err != nil {
		fmt.Println("打开 file1.txt 失败:", err)
		return
	}
	defer f1.Close()
	fmt.Println("成功打开 file1.txt")

	// 尝试在受限根目录下打开子目录下的文件
	f2, err := root.Open("subdir/file2.txt")
	if err != nil {
		fmt.Println("打开 subdir/file2.txt 失败:", err)
		return
	}
	defer f2.Close()
	fmt.Println("成功打开 subdir/file2.txt")

	// 尝试访问受限根目录之外的文件 (预期会失败)
	_, err = root.Open("../file1.txt")
	if err != nil {
		fmt.Println("尝试访问受限根目录之外的文件失败:", err)
	} else {
		fmt.Println("意外地成功访问了受限根目录之外的文件")
	}
}
```

**假设的输入与输出:**

对于上面的代码示例，假设临时目录创建成功，预期的输出如下：

```
成功打开 file1.txt
成功打开 subdir/file2.txt
尝试访问受限根目录之外的文件失败: open ../file1.txt: no such file or directory
```

**命令行参数处理:**

这段代码本身是测试代码，并不直接处理命令行参数。`os.Root` 的使用也不涉及特定的命令行参数。

**使用者易犯错的点:**

1. **路径逃逸:**  使用者容易犯的错误是尝试通过相对路径（如 `..`）或绝对路径访问 `os.OpenRoot` 指定的根目录之外的文件或目录。`os.Root` 的设计目标就是阻止这种行为，因此这类操作会返回错误。

   **示例:**

   假设 `tempDir` 是 `/tmp/myroot`，并且 `/tmp/otherfile.txt` 存在。

   ```go
   root, _ := os.OpenRoot("/tmp/myroot")
   defer root.Close()

   // 尝试访问根目录之外的文件，将会失败
   _, err := root.Open("../otherfile.txt")
   if err != nil {
       fmt.Println(err) // 输出类似 "open ../otherfile.txt: no such file or directory" 的错误
   }
   ```

2. **混淆 `os.Root` 和标准 `os` 包函数的作用域:**  需要明确，通过 `os.OpenRoot` 创建的 `os.Root` 实例上的操作是受限的，而直接使用 `os` 包的函数（如 `os.Open`, `os.ReadFile` 等）则不受此限制。

   **示例:**

   ```go
   tempDir, _ := os.MkdirTemp("", "root-example")
   defer os.RemoveAll(tempDir)
   os.WriteFile(filepath.Join(tempDir, "file.txt"), []byte("content"), 0666)

   root, _ := os.OpenRoot(tempDir)
   defer root.Close()

   // 使用 root.Open 可以访问到 file.txt
   f, _ := root.Open("file.txt")
   f.Close()

   // 使用 os.Open 也可以访问到 file.txt，使用绝对路径
   f2, _ := os.Open(filepath.Join(tempDir, "file.txt"))
   f2.Close()

   // 但尝试用 os.Open 在受限根目录下以相对路径访问会失败
   _, err := os.Open("file.txt") // 假设当前工作目录不是 tempDir
   if err != nil {
       fmt.Println(err) // 输出 "open file.txt: no such file or directory"
   }
   ```

总而言之，这段测试代码详尽地验证了 `os.Root` 提供的受限文件系统操作的各种场景，包括基本的文件和目录操作、符号链接处理、路径解析以及与标准 `os` 包函数的行为一致性，旨在确保 `os.Root` 功能的正确性和可靠性。

Prompt: 
```
这是路径为go/src/os/root_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package os_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// testMaybeRooted calls f in two subtests,
// one with a Root and one with a nil r.
func testMaybeRooted(t *testing.T, f func(t *testing.T, r *os.Root)) {
	t.Run("NoRoot", func(t *testing.T) {
		t.Chdir(t.TempDir())
		f(t, nil)
	})
	t.Run("InRoot", func(t *testing.T) {
		t.Chdir(t.TempDir())
		r, err := os.OpenRoot(".")
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		f(t, r)
	})
}

// makefs creates a test filesystem layout and returns the path to its root.
//
// Each entry in the slice is a file, directory, or symbolic link to create:
//
//   - "d/": directory d
//   - "f": file f with contents f
//   - "a => b": symlink a with target b
//
// The directory containing the filesystem is always named ROOT.
// $ABS is replaced with the absolute path of the directory containing the filesystem.
//
// Parent directories are automatically created as needed.
//
// makefs calls t.Skip if the layout contains features not supported by the current GOOS.
func makefs(t *testing.T, fs []string) string {
	root := path.Join(t.TempDir(), "ROOT")
	if err := os.Mkdir(root, 0o777); err != nil {
		t.Fatal(err)
	}
	for _, ent := range fs {
		ent = strings.ReplaceAll(ent, "$ABS", root)
		base, link, isLink := strings.Cut(ent, " => ")
		if isLink {
			if runtime.GOOS == "wasip1" && path.IsAbs(link) {
				t.Skip("absolute link targets not supported on " + runtime.GOOS)
			}
			if runtime.GOOS == "plan9" {
				t.Skip("symlinks not supported on " + runtime.GOOS)
			}
			ent = base
		}
		if err := os.MkdirAll(path.Join(root, path.Dir(base)), 0o777); err != nil {
			t.Fatal(err)
		}
		if isLink {
			if err := os.Symlink(link, path.Join(root, base)); err != nil {
				t.Fatal(err)
			}
		} else if strings.HasSuffix(ent, "/") {
			if err := os.MkdirAll(path.Join(root, ent), 0o777); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := os.WriteFile(path.Join(root, ent), []byte(ent), 0o666); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}

// A rootTest is a test case for os.Root.
type rootTest struct {
	name string

	// fs is the test filesystem layout. See makefs above.
	fs []string

	// open is the filename to access in the test.
	open string

	// target is the filename that we expect to be accessed, after resolving all symlinks.
	// For test cases where the operation fails due to an escaping path such as ../ROOT/x,
	// the target is the filename that should not have been opened.
	target string

	// ltarget is the filename that we expect to accessed, after resolving all symlinks
	// except the last one. This is the file we expect to be removed by Remove or statted
	// by Lstat.
	//
	// If the last path component in open is not a symlink, ltarget should be "".
	ltarget string

	// wantError is true if accessing the file should fail.
	wantError bool

	// alwaysFails is true if the open operation is expected to fail
	// even when using non-openat operations.
	//
	// This lets us check that tests that are expected to fail because (for example)
	// a path escapes the directory root will succeed when the escaping checks are not
	// performed.
	alwaysFails bool
}

// run sets up the test filesystem layout, os.OpenDirs the root, and calls f.
func (test *rootTest) run(t *testing.T, f func(t *testing.T, target string, d *os.Root)) {
	t.Run(test.name, func(t *testing.T) {
		root := makefs(t, test.fs)
		d, err := os.OpenRoot(root)
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		// The target is a file that will be accessed,
		// or a file that should not be accessed
		// (because doing so escapes the root).
		target := test.target
		if test.target != "" {
			target = filepath.Join(root, test.target)
		}
		f(t, target, d)
	})
}

// errEndsTest checks the error result of a test,
// verifying that it succeeded or failed as expected.
//
// It returns true if the test is done due to encountering an expected error.
// false if the test should continue.
func errEndsTest(t *testing.T, err error, wantError bool, format string, args ...any) bool {
	t.Helper()
	if wantError {
		if err == nil {
			op := fmt.Sprintf(format, args...)
			t.Fatalf("%v = nil; want error", op)
		}
		return true
	} else {
		if err != nil {
			op := fmt.Sprintf(format, args...)
			t.Fatalf("%v = %v; want success", op, err)
		}
		return false
	}
}

var rootTestCases = []rootTest{{
	name:   "plain path",
	fs:     []string{},
	open:   "target",
	target: "target",
}, {
	name: "path in directory",
	fs: []string{
		"a/b/c/",
	},
	open:   "a/b/c/target",
	target: "a/b/c/target",
}, {
	name: "symlink",
	fs: []string{
		"link => target",
	},
	open:    "link",
	target:  "target",
	ltarget: "link",
}, {
	name: "symlink chain",
	fs: []string{
		"link => a/b/c/target",
		"a/b => e",
		"a/e => ../f",
		"f => g/h/i",
		"g/h/i => ..",
		"g/c/",
	},
	open:    "link",
	target:  "g/c/target",
	ltarget: "link",
}, {
	name: "path with dot",
	fs: []string{
		"a/b/",
	},
	open:   "./a/./b/./target",
	target: "a/b/target",
}, {
	name: "path with dotdot",
	fs: []string{
		"a/b/",
	},
	open:   "a/../a/b/../../a/b/../b/target",
	target: "a/b/target",
}, {
	name: "dotdot no symlink",
	fs: []string{
		"a/",
	},
	open:   "a/../target",
	target: "target",
}, {
	name: "dotdot after symlink",
	fs: []string{
		"a => b/c",
		"b/c/",
	},
	open: "a/../target",
	target: func() string {
		if runtime.GOOS == "windows" {
			// On Windows, the path is cleaned before symlink resolution.
			return "target"
		}
		return "b/target"
	}(),
}, {
	name: "dotdot before symlink",
	fs: []string{
		"a => b/c",
		"b/c/",
	},
	open:   "b/../a/target",
	target: "b/c/target",
}, {
	name: "symlink ends in dot",
	fs: []string{
		"a => b/.",
		"b/",
	},
	open:   "a/target",
	target: "b/target",
}, {
	name:        "directory does not exist",
	fs:          []string{},
	open:        "a/file",
	wantError:   true,
	alwaysFails: true,
}, {
	name:        "empty path",
	fs:          []string{},
	open:        "",
	wantError:   true,
	alwaysFails: true,
}, {
	name: "symlink cycle",
	fs: []string{
		"a => a",
	},
	open:        "a",
	ltarget:     "a",
	wantError:   true,
	alwaysFails: true,
}, {
	name:      "path escapes",
	fs:        []string{},
	open:      "../ROOT/target",
	target:    "target",
	wantError: true,
}, {
	name: "long path escapes",
	fs: []string{
		"a/",
	},
	open:      "a/../../ROOT/target",
	target:    "target",
	wantError: true,
}, {
	name: "absolute symlink",
	fs: []string{
		"link => $ABS/target",
	},
	open:      "link",
	ltarget:   "link",
	target:    "target",
	wantError: true,
}, {
	name: "relative symlink",
	fs: []string{
		"link => ../ROOT/target",
	},
	open:      "link",
	target:    "target",
	ltarget:   "link",
	wantError: true,
}, {
	name: "symlink chain escapes",
	fs: []string{
		"link => a/b/c/target",
		"a/b => e",
		"a/e => ../../ROOT",
		"c/",
	},
	open:      "link",
	target:    "c/target",
	ltarget:   "link",
	wantError: true,
}}

func TestRootOpen_File(t *testing.T) {
	want := []byte("target")
	for _, test := range rootTestCases {
		test.run(t, func(t *testing.T, target string, root *os.Root) {
			if target != "" {
				if err := os.WriteFile(target, want, 0o666); err != nil {
					t.Fatal(err)
				}
			}
			f, err := root.Open(test.open)
			if errEndsTest(t, err, test.wantError, "root.Open(%q)", test.open) {
				return
			}
			defer f.Close()
			got, err := io.ReadAll(f)
			if err != nil || !bytes.Equal(got, want) {
				t.Errorf(`Dir.Open(%q): read content %q, %v; want %q`, test.open, string(got), err, string(want))
			}
		})
	}
}

func TestRootOpen_Directory(t *testing.T) {
	for _, test := range rootTestCases {
		test.run(t, func(t *testing.T, target string, root *os.Root) {
			if target != "" {
				if err := os.Mkdir(target, 0o777); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target+"/found", nil, 0o666); err != nil {
					t.Fatal(err)
				}
			}
			f, err := root.Open(test.open)
			if errEndsTest(t, err, test.wantError, "root.Open(%q)", test.open) {
				return
			}
			defer f.Close()
			got, err := f.Readdirnames(-1)
			if err != nil {
				t.Errorf(`Dir.Open(%q).Readdirnames: %v`, test.open, err)
			}
			if want := []string{"found"}; !slices.Equal(got, want) {
				t.Errorf(`Dir.Open(%q).Readdirnames: %q, want %q`, test.open, got, want)
			}
		})
	}
}

func TestRootCreate(t *testing.T) {
	want := []byte("target")
	for _, test := range rootTestCases {
		test.run(t, func(t *testing.T, target string, root *os.Root) {
			f, err := root.Create(test.open)
			if errEndsTest(t, err, test.wantError, "root.Create(%q)", test.open) {
				return
			}
			if _, err := f.Write(want); err != nil {
				t.Fatal(err)
			}
			f.Close()
			got, err := os.ReadFile(target)
			if err != nil {
				t.Fatalf(`reading file created with root.Create(%q): %v`, test.open, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf(`reading file created with root.Create(%q): got %q; want %q`, test.open, got, want)
			}
		})
	}
}

func TestRootMkdir(t *testing.T) {
	for _, test := range rootTestCases {
		test.run(t, func(t *testing.T, target string, root *os.Root) {
			wantError := test.wantError
			if !wantError {
				fi, err := os.Lstat(filepath.Join(root.Name(), test.open))
				if err == nil && fi.Mode().Type() == fs.ModeSymlink {
					// This case is trying to mkdir("some symlink"),
					// which is an error.
					wantError = true
				}
			}

			err := root.Mkdir(test.open, 0o777)
			if errEndsTest(t, err, wantError, "root.Create(%q)", test.open) {
				return
			}
			fi, err := os.Lstat(target)
			if err != nil {
				t.Fatalf(`stat file created with Root.Mkdir(%q): %v`, test.open, err)
			}
			if !fi.IsDir() {
				t.Fatalf(`stat file created with Root.Mkdir(%q): not a directory`, test.open)
			}
		})
	}
}

func TestRootOpenRoot(t *testing.T) {
	for _, test := range rootTestCases {
		test.run(t, func(t *testing.T, target string, root *os.Root) {
			if target != "" {
				if err := os.Mkdir(target, 0o777); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target+"/f", nil, 0o666); err != nil {
					t.Fatal(err)
				}
			}
			rr, err := root.OpenRoot(test.open)
			if errEndsTest(t, err, test.wantError, "root.OpenRoot(%q)", test.open) {
				return
			}
			defer rr.Close()
			f, err := rr.Open("f")
			if err != nil {
				t.Fatalf(`root.OpenRoot(%q).Open("f") = %v`, test.open, err)
			}
			f.Close()
		})
	}
}

func TestRootRemoveFile(t *testing.T) {
	for _, test := range rootTestCases {
		test.run(t, func(t *testing.T, target string, root *os.Root) {
			wantError := test.wantError
			if test.ltarget != "" {
				// Remove doesn't follow symlinks in the final path component,
				// so it will successfully remove ltarget.
				wantError = false
				target = filepath.Join(root.Name(), test.ltarget)
			} else if target != "" {
				if err := os.WriteFile(target, nil, 0o666); err != nil {
					t.Fatal(err)
				}
			}

			err := root.Remove(test.open)
			if errEndsTest(t, err, wantError, "root.Remove(%q)", test.open) {
				return
			}
			_, err = os.Lstat(target)
			if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf(`stat file removed with Root.Remove(%q): %v, want ErrNotExist`, test.open, err)
			}
		})
	}
}

func TestRootRemoveDirectory(t *testing.T) {
	for _, test := range rootTestCases {
		test.run(t, func(t *testing.T, target string, root *os.Root) {
			wantError := test.wantError
			if test.ltarget != "" {
				// Remove doesn't follow symlinks in the final path component,
				// so it will successfully remove ltarget.
				wantError = false
				target = filepath.Join(root.Name(), test.ltarget)
			} else if target != "" {
				if err := os.Mkdir(target, 0o777); err != nil {
					t.Fatal(err)
				}
			}

			err := root.Remove(test.open)
			if errEndsTest(t, err, wantError, "root.Remove(%q)", test.open) {
				return
			}
			_, err = os.Lstat(target)
			if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf(`stat file removed with Root.Remove(%q): %v, want ErrNotExist`, test.open, err)
			}
		})
	}
}

func TestRootOpenFileAsRoot(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	_, err := os.OpenRoot(target)
	if err == nil {
		t.Fatal("os.OpenRoot(file) succeeded; want failure")
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	_, err = r.OpenRoot("target")
	if err == nil {
		t.Fatal("Root.OpenRoot(file) succeeded; want failure")
	}
}

func TestRootStat(t *testing.T) {
	for _, test := range rootTestCases {
		test.run(t, func(t *testing.T, target string, root *os.Root) {
			const content = "content"
			if target != "" {
				if err := os.WriteFile(target, []byte(content), 0o666); err != nil {
					t.Fatal(err)
				}
			}

			fi, err := root.Stat(test.open)
			if errEndsTest(t, err, test.wantError, "root.Stat(%q)", test.open) {
				return
			}
			if got, want := fi.Name(), filepath.Base(test.open); got != want {
				t.Errorf("root.Stat(%q).Name() = %q, want %q", test.open, got, want)
			}
			if got, want := fi.Size(), int64(len(content)); got != want {
				t.Errorf("root.Stat(%q).Size() = %v, want %v", test.open, got, want)
			}
		})
	}
}

func TestRootLstat(t *testing.T) {
	for _, test := range rootTestCases {
		test.run(t, func(t *testing.T, target string, root *os.Root) {
			const content = "content"
			wantError := test.wantError
			if test.ltarget != "" {
				// Lstat will stat the final link, rather than following it.
				wantError = false
			} else if target != "" {
				if err := os.WriteFile(target, []byte(content), 0o666); err != nil {
					t.Fatal(err)
				}
			}

			fi, err := root.Lstat(test.open)
			if errEndsTest(t, err, wantError, "root.Stat(%q)", test.open) {
				return
			}
			if got, want := fi.Name(), filepath.Base(test.open); got != want {
				t.Errorf("root.Stat(%q).Name() = %q, want %q", test.open, got, want)
			}
			if test.ltarget == "" {
				if got := fi.Mode(); got&os.ModeSymlink != 0 {
					t.Errorf("root.Stat(%q).Mode() = %v, want non-symlink", test.open, got)
				}
				if got, want := fi.Size(), int64(len(content)); got != want {
					t.Errorf("root.Stat(%q).Size() = %v, want %v", test.open, got, want)
				}
			} else {
				if got := fi.Mode(); got&os.ModeSymlink == 0 {
					t.Errorf("root.Stat(%q).Mode() = %v, want symlink", test.open, got)
				}
			}
		})
	}
}

// A rootConsistencyTest is a test case comparing os.Root behavior with
// the corresponding non-Root function.
//
// These tests verify that, for example, Root.Open("file/./") and os.Open("file/./")
// have the same result, although the specific result may vary by platform.
type rootConsistencyTest struct {
	name string

	// fs is the test filesystem layout. See makefs above.
	// fsFunc is called to modify the test filesystem, or replace it.
	fs     []string
	fsFunc func(t *testing.T, dir string) string

	// open is the filename to access in the test.
	open string

	// detailedErrorMismatch indicates that os.Root and the corresponding non-Root
	// function return different errors for this test.
	detailedErrorMismatch func(t *testing.T) bool
}

var rootConsistencyTestCases = []rootConsistencyTest{{
	name: "file",
	fs: []string{
		"target",
	},
	open: "target",
}, {
	name: "dir slash dot",
	fs: []string{
		"target/file",
	},
	open: "target/.",
}, {
	name: "dot",
	fs: []string{
		"file",
	},
	open: ".",
}, {
	name: "file slash dot",
	fs: []string{
		"target",
	},
	open: "target/.",
	detailedErrorMismatch: func(t *testing.T) bool {
		// FreeBSD returns EPERM in the non-Root case.
		return runtime.GOOS == "freebsd" && strings.HasPrefix(t.Name(), "TestRootConsistencyRemove")
	},
}, {
	name: "dir slash",
	fs: []string{
		"target/file",
	},
	open: "target/",
}, {
	name: "dot slash",
	fs: []string{
		"file",
	},
	open: "./",
}, {
	name: "file slash",
	fs: []string{
		"target",
	},
	open: "target/",
	detailedErrorMismatch: func(t *testing.T) bool {
		// os.Create returns ENOTDIR or EISDIR depending on the platform.
		return runtime.GOOS == "js"
	},
}, {
	name: "file in path",
	fs: []string{
		"file",
	},
	open: "file/target",
}, {
	name: "directory in path missing",
	open: "dir/target",
}, {
	name: "target does not exist",
	open: "target",
}, {
	name: "symlink slash",
	fs: []string{
		"target/file",
		"link => target",
	},
	open: "link/",
}, {
	name: "symlink slash dot",
	fs: []string{
		"target/file",
		"link => target",
	},
	open: "link/.",
}, {
	name: "file symlink slash",
	fs: []string{
		"target",
		"link => target",
	},
	open: "link/",
	detailedErrorMismatch: func(t *testing.T) bool {
		// os.Create returns ENOTDIR or EISDIR depending on the platform.
		return runtime.GOOS == "js"
	},
}, {
	name: "unresolved symlink",
	fs: []string{
		"link => target",
	},
	open: "link",
}, {
	name: "resolved symlink",
	fs: []string{
		"link => target",
		"target",
	},
	open: "link",
}, {
	name: "dotdot in path after symlink",
	fs: []string{
		"a => b/c",
		"b/c/",
		"b/target",
	},
	open: "a/../target",
}, {
	name: "long file name",
	open: strings.Repeat("a", 500),
}, {
	name: "unreadable directory",
	fs: []string{
		"dir/target",
	},
	fsFunc: func(t *testing.T, dir string) string {
		os.Chmod(filepath.Join(dir, "dir"), 0)
		t.Cleanup(func() {
			os.Chmod(filepath.Join(dir, "dir"), 0o700)
		})
		return dir
	},
	open: "dir/target",
}, {
	name: "unix domain socket target",
	fsFunc: func(t *testing.T, dir string) string {
		return tempDirWithUnixSocket(t, "a")
	},
	open: "a",
}, {
	name: "unix domain socket in path",
	fsFunc: func(t *testing.T, dir string) string {
		return tempDirWithUnixSocket(t, "a")
	},
	open: "a/b",
	detailedErrorMismatch: func(t *testing.T) bool {
		// On Windows, os.Root.Open returns "The directory name is invalid."
		// and os.Open returns "The file cannot be accessed by the system.".
		return runtime.GOOS == "windows"
	},
}, {
	name: "question mark",
	open: "?",
}, {
	name: "nul byte",
	open: "\x00",
}}

func tempDirWithUnixSocket(t *testing.T, name string) string {
	dir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	addr, err := net.ResolveUnixAddr("unix", filepath.Join(dir, name))
	if err != nil {
		t.Skipf("net.ResolveUnixAddr: %v", err)
	}
	conn, err := net.ListenUnix("unix", addr)
	if err != nil {
		t.Skipf("net.ListenUnix: %v", err)
	}
	t.Cleanup(func() {
		conn.Close()
	})
	return dir
}

func (test rootConsistencyTest) run(t *testing.T, f func(t *testing.T, path string, r *os.Root) (string, error)) {
	if runtime.GOOS == "wasip1" {
		// On wasip, non-Root functions clean paths before opening them,
		// resulting in inconsistent behavior.
		// https://go.dev/issue/69509
		t.Skip("#69509: inconsistent results on wasip1")
	}

	t.Run(test.name, func(t *testing.T) {
		dir1 := makefs(t, test.fs)
		dir2 := makefs(t, test.fs)
		if test.fsFunc != nil {
			dir1 = test.fsFunc(t, dir1)
			dir2 = test.fsFunc(t, dir2)
		}

		r, err := os.OpenRoot(dir1)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()

		res1, err1 := f(t, test.open, r)
		res2, err2 := f(t, dir2+"/"+test.open, nil)

		if res1 != res2 || ((err1 == nil) != (err2 == nil)) {
			t.Errorf("with root:    res=%v", res1)
			t.Errorf("              err=%v", err1)
			t.Errorf("without root: res=%v", res2)
			t.Errorf("              err=%v", err2)
			t.Errorf("want consistent results, got mismatch")
		}

		if err1 != nil || err2 != nil {
			e1, ok := err1.(*os.PathError)
			if !ok {
				t.Fatalf("with root, expected PathError; got: %v", err1)
			}
			e2, ok := err2.(*os.PathError)
			if !ok {
				t.Fatalf("without root, expected PathError; got: %v", err1)
			}
			detailedErrorMismatch := false
			if f := test.detailedErrorMismatch; f != nil {
				detailedErrorMismatch = f(t)
			}
			if runtime.GOOS == "plan9" {
				// Plan9 syscall errors aren't comparable.
				detailedErrorMismatch = true
			}
			if !detailedErrorMismatch && e1.Err != e2.Err {
				t.Errorf("with root:    err=%v", e1.Err)
				t.Errorf("without root: err=%v", e2.Err)
				t.Errorf("want consistent results, got mismatch")
			}
		}
	})
}

func TestRootConsistencyOpen(t *testing.T) {
	for _, test := range rootConsistencyTestCases {
		test.run(t, func(t *testing.T, path string, r *os.Root) (string, error) {
			var f *os.File
			var err error
			if r == nil {
				f, err = os.Open(path)
			} else {
				f, err = r.Open(path)
			}
			if err != nil {
				return "", err
			}
			defer f.Close()
			fi, err := f.Stat()
			if err == nil && !fi.IsDir() {
				b, err := io.ReadAll(f)
				return string(b), err
			} else {
				names, err := f.Readdirnames(-1)
				slices.Sort(names)
				return fmt.Sprintf("%q", names), err
			}
		})
	}
}

func TestRootConsistencyCreate(t *testing.T) {
	for _, test := range rootConsistencyTestCases {
		test.run(t, func(t *testing.T, path string, r *os.Root) (string, error) {
			var f *os.File
			var err error
			if r == nil {
				f, err = os.Create(path)
			} else {
				f, err = r.Create(path)
			}
			if err == nil {
				f.Write([]byte("file contents"))
				f.Close()
			}
			return "", err
		})
	}
}

func TestRootConsistencyMkdir(t *testing.T) {
	for _, test := range rootConsistencyTestCases {
		test.run(t, func(t *testing.T, path string, r *os.Root) (string, error) {
			var err error
			if r == nil {
				err = os.Mkdir(path, 0o777)
			} else {
				err = r.Mkdir(path, 0o777)
			}
			return "", err
		})
	}
}

func TestRootConsistencyRemove(t *testing.T) {
	for _, test := range rootConsistencyTestCases {
		if test.open == "." || test.open == "./" {
			continue // can't remove the root itself
		}
		test.run(t, func(t *testing.T, path string, r *os.Root) (string, error) {
			var err error
			if r == nil {
				err = os.Remove(path)
			} else {
				err = r.Remove(path)
			}
			return "", err
		})
	}
}

func TestRootConsistencyStat(t *testing.T) {
	for _, test := range rootConsistencyTestCases {
		test.run(t, func(t *testing.T, path string, r *os.Root) (string, error) {
			var fi os.FileInfo
			var err error
			if r == nil {
				fi, err = os.Stat(path)
			} else {
				fi, err = r.Stat(path)
			}
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("name:%q size:%v mode:%v isdir:%v", fi.Name(), fi.Size(), fi.Mode(), fi.IsDir()), nil
		})
	}
}

func TestRootConsistencyLstat(t *testing.T) {
	for _, test := range rootConsistencyTestCases {
		test.run(t, func(t *testing.T, path string, r *os.Root) (string, error) {
			var fi os.FileInfo
			var err error
			if r == nil {
				fi, err = os.Lstat(path)
			} else {
				fi, err = r.Lstat(path)
			}
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("name:%q size:%v mode:%v isdir:%v", fi.Name(), fi.Size(), fi.Mode(), fi.IsDir()), nil
		})
	}
}

func TestRootRenameAfterOpen(t *testing.T) {
	switch runtime.GOOS {
	case "windows":
		t.Skip("renaming open files not supported on " + runtime.GOOS)
	case "js", "plan9":
		t.Skip("openat not supported on " + runtime.GOOS)
	case "wasip1":
		if os.Getenv("GOWASIRUNTIME") == "wazero" {
			t.Skip("wazero does not track renamed directories")
		}
	}

	dir := t.TempDir()

	// Create directory "a" and open it.
	if err := os.Mkdir(filepath.Join(dir, "a"), 0o777); err != nil {
		t.Fatal(err)
	}
	dirf, err := os.OpenRoot(filepath.Join(dir, "a"))
	if err != nil {
		t.Fatal(err)
	}
	defer dirf.Close()

	// Rename "a" => "b", and create "b/f".
	if err := os.Rename(filepath.Join(dir, "a"), filepath.Join(dir, "b")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b/f"), []byte("hello"), 0o666); err != nil {
		t.Fatal(err)
	}

	// Open "f", and confirm that we see it.
	f, err := dirf.OpenFile("f", os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("reading file after renaming parent: %v", err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(b), "hello"; got != want {
		t.Fatalf("file contents: %q, want %q", got, want)
	}

	// f.Name reflects the original path we opened the directory under (".../a"), not "b".
	if got, want := f.Name(), dirf.Name()+string(os.PathSeparator)+"f"; got != want {
		t.Errorf("f.Name() = %q, want %q", got, want)
	}
}

func TestRootNonPermissionMode(t *testing.T) {
	r, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.OpenFile("file", os.O_RDWR|os.O_CREATE, 0o1777); err == nil {
		t.Errorf("r.OpenFile(file, O_RDWR|O_CREATE, 0o1777) succeeded; want error")
	}
	if err := r.Mkdir("file", 0o1777); err == nil {
		t.Errorf("r.Mkdir(file, 0o1777) succeeded; want error")
	}
}

func TestRootUseAfterClose(t *testing.T) {
	r, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	for _, test := range []struct {
		name string
		f    func(r *os.Root, filename string) error
	}{{
		name: "Open",
		f: func(r *os.Root, filename string) error {
			_, err := r.Open(filename)
			return err
		},
	}, {
		name: "Create",
		f: func(r *os.Root, filename string) error {
			_, err := r.Create(filename)
			return err
		},
	}, {
		name: "OpenFile",
		f: func(r *os.Root, filename string) error {
			_, err := r.OpenFile(filename, os.O_RDWR, 0o666)
			return err
		},
	}, {
		name: "OpenRoot",
		f: func(r *os.Root, filename string) error {
			_, err := r.OpenRoot(filename)
			return err
		},
	}, {
		name: "Mkdir",
		f: func(r *os.Root, filename string) error {
			return r.Mkdir(filename, 0o777)
		},
	}} {
		err := test.f(r, "target")
		pe, ok := err.(*os.PathError)
		if !ok || pe.Path != "target" || pe.Err != os.ErrClosed {
			t.Errorf(`r.%v = %v; want &PathError{Path: "target", Err: ErrClosed}`, test.name, err)
		}
	}
}

func TestRootConcurrentClose(t *testing.T) {
	r, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan error, 1)
	go func() {
		defer close(ch)
		first := true
		for {
			f, err := r.OpenFile("file", os.O_RDWR|os.O_CREATE, 0o666)
			if err != nil {
				ch <- err
				return
			}
			if first {
				ch <- nil
				first = false
			}
			f.Close()
		}
	}()
	if err := <-ch; err != nil {
		t.Errorf("OpenFile: %v, want success", err)
	}
	r.Close()
	if err := <-ch; !errors.Is(err, os.ErrClosed) {
		t.Errorf("OpenFile: %v, want ErrClosed", err)
	}
}

// TestRootRaceRenameDir attempts to escape a Root by renaming a path component mid-parse.
//
// We create a deeply nested directory:
//
//	base/a/a/a/a/ [...] /a
//
// And a path that descends into the tree, then returns to the top using ..:
//
//	base/a/a/a/a/ [...] /a/../../../ [..] /../a/f
//
// While opening this file, we rename base/a/a to base/b.
// A naive lookup operation will resolve the path to base/f.
func TestRootRaceRenameDir(t *testing.T) {
	dir := t.TempDir()
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	const depth = 4

	os.MkdirAll(dir+"/base/"+strings.Repeat("/a", depth), 0o777)

	path := "base/" + strings.Repeat("a/", depth) + strings.Repeat("../", depth) + "a/f"
	os.WriteFile(dir+"/f", []byte("secret"), 0o666)
	os.WriteFile(dir+"/base/a/f", []byte("public"), 0o666)

	// Compute how long it takes to open the path in the common case.
	const tries = 10
	var total time.Duration
	for range tries {
		start := time.Now()
		f, err := r.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(f)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != "public" {
			t.Fatalf("read %q, want %q", b, "public")
		}
		f.Close()
		total += time.Since(start)
	}
	avg := total / tries

	// We're trying to exploit a race, so try this a number of times.
	for range 100 {
		// Start a goroutine to open the file.
		gotc := make(chan []byte)
		go func() {
			f, err := r.Open(path)
			if err != nil {
				gotc <- nil
			}
			defer f.Close()
			b, _ := io.ReadAll(f)
			gotc <- b
		}()

		// Wait for the open operation to partially complete,
		// and then rename a directory near the root.
		time.Sleep(avg / 4)
		if err := os.Rename(dir+"/base/a", dir+"/b"); err != nil {
			// Windows and Plan9 won't let us rename a directory if we have
			// an open handle for it, so an error here is expected.
			switch runtime.GOOS {
			case "windows", "plan9":
			default:
				t.Fatal(err)
			}
		}

		got := <-gotc
		os.Rename(dir+"/b", dir+"/base/a")
		if len(got) > 0 && string(got) != "public" {
			t.Errorf("read file: %q; want error or 'public'", got)
		}
	}
}

func TestOpenInRoot(t *testing.T) {
	dir := makefs(t, []string{
		"file",
		"link => ../ROOT/file",
	})
	f, err := os.OpenInRoot(dir, "file")
	if err != nil {
		t.Fatalf("OpenInRoot(`file`) = %v, want success", err)
	}
	f.Close()
	for _, name := range []string{
		"link",
		"../ROOT/file",
		dir + "/file",
	} {
		f, err := os.OpenInRoot(dir, name)
		if err == nil {
			f.Close()
			t.Fatalf("OpenInRoot(%q) = nil, want error", name)
		}
	}
}

"""



```