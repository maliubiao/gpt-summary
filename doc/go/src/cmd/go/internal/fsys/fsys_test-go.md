Response: Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding and Context:**

The first step is to recognize that this is a test file (`_test.go`) for a Go package named `fsys` located within the `cmd/go` directory. This immediately tells us it's related to file system operations within the Go toolchain itself, likely dealing with how Go manages and interacts with files during compilation and other processes.

**2. Identifying Core Functionality (Keywords and Patterns):**

I scan the code for key function names and patterns that suggest specific functionalities. Some immediately stand out:

* **`initOverlay`:** This function clearly sets up some kind of "overlay" file system. It reads a `txtar` archive (a way to represent file system structures in text) and applies configurations from a JSON comment. The use of `t.TempDir()` and `t.Chdir()` suggests it creates isolated test environments.
* **`resetForTesting`:** This implies the `fsys` package has some global or shared state that needs to be reset between tests.
* **`statInfo`, `TestStatInfo`, `TestIsDir`, `TestReadDir`, `TestGlob`, `TestOpen`, `TestIsGoDir`, `TestWalk`, `TestLstat`, `TestStat`, `TestBindOverlay`, `TestBadOverlay`:** The sheer number of `Test...` functions strongly indicates the file is focused on testing various aspects of the `fsys` package. The names themselves are quite descriptive and hint at the functionality being tested (e.g., `IsDir` checks if a path is a directory, `ReadDir` lists directory contents, etc.).
* **`overlay`, `binds`:** These global variables within the `resetForTesting` function suggest the overlay mechanism is implemented using these data structures. The `initFromJSON` function further reinforces the idea of a JSON-based configuration for the overlay.
* **`txtar.Parse`:** This confirms the use of `txtar` for representing file system layouts in the tests.
* **Keywords like `Replace`, `Delete` (inferred from "") within the JSON strings:** These suggest the overlay system allows for replacing existing files/directories or deleting them.

**3. Inferring the Purpose of the `fsys` Package:**

Based on the identified functionalities, I can infer that the `fsys` package provides an *abstracted or virtualized file system* layer. It allows Go's build tools to work with a view of the file system that might be different from the actual on-disk structure. This is often used for:

* **Overlays:**  Modifying the apparent contents of a directory without changing the underlying files.
* **Bindings:**  Mapping a path in the virtual file system to a different location on disk.
* **Testing:** Creating isolated and reproducible file system environments for tests.

**4. Detailed Analysis of Key Functions (with a focus on examples):**

Now, I start looking deeper into the individual test functions and their associated data structures.

* **`TestStatInfo`:** This test uses the `stat` function (presumably from the `fsys` package) to get information about files and directories. The `statInfoTests` and `statInfoChildrenTests` provide concrete examples of input paths and expected output (`info` struct). The `statInfoOverlay` variable defines a sample overlay configuration. This helps understand how the overlay affects the results of `stat`.
* **`TestIsDir`:**  This directly tests the `IsDir` function. The `testCases` array contains various paths and the expected boolean result, showcasing how the overlay affects whether a path is considered a directory.
* **`TestReadDir`:**  This tests `ReadDir`, and the `testCases` array provides examples of directories and the expected list of files and subdirectories within them. The `readDirOverlay` constant is a complex example of overlay configuration.
* **`TestOpen`:** This tests opening files using `Open`. The `testCases` show how the overlay affects the content of opened files, including cases where files are replaced or deleted.
* **`TestGlob`:** This tests the `Glob` function, which is a pattern-matching function for file paths. The `testCases` demonstrate different glob patterns and the expected matching file paths.
* **`TestWalk` and `TestWalkDir`:** These test the traversal of the file system using `WalkDir`. They illustrate how the overlay affects the files and directories visited during the walk. The `filepath.SkipDir` and `filepath.SkipAll` examples show how to control the traversal.
* **`TestLstat` and `TestStat`:** These test the `Lstat` and `Stat` functions, highlighting the difference in how they handle symbolic links (or lack thereof in this specific test context, as symlink tests are separate).
* **`TestBindOverlay`:** This tests the `Bind` function, which allows dynamically mapping parts of the file system. The example demonstrates how binding affects file access and directory listing.
* **`TestBadOverlay`:**  This tests error handling when the overlay configuration is invalid.

**5. Identifying Potential User Errors:**

Based on the functionality and the test cases, I can identify potential pitfalls for users:

* **Assuming Physical File System:** Users might forget they're working with a virtualized file system and expect changes to be reflected on disk (or vice versa).
* **Path Resolution in Overlays:** Understanding how the `Replace` rules in the overlay JSON affect path resolution is crucial. Mistakes in the JSON can lead to unexpected file access or "not found" errors.
* **Interaction of Overlays and Binds:** When both overlays and binds are used, the order of operations and the resulting file system view can become complex.
* **Case Sensitivity (Platform Dependent):** While not explicitly shown in the code, file system case sensitivity can be an issue, especially when dealing with overlays defined in JSON.

**6. Structuring the Output:**

Finally, I organize the information into the requested format, covering:

* **Functionality Listing:** A bulleted list of the main functions and their purposes.
* **Go Feature Implementation:** Identifying the likely Go feature (virtual file system/file system abstraction) and providing illustrative code examples using the test cases.
* **Code Reasoning (Input/Output):**  Selecting specific test cases to demonstrate the behavior of functions like `Stat`, `IsDir`, `ReadDir`, and `Open`, providing the assumed input (overlay configuration and path) and the expected output.
* **Command-Line Arguments:** Noting that this specific code doesn't directly handle command-line arguments but the underlying `go` command does.
* **Common Mistakes:**  Listing the potential errors users might encounter.

This iterative process of scanning, identifying patterns, inferring purpose, analyzing details, and structuring the output helps to thoroughly understand and explain the provided code snippet.
这段代码是 Go 语言 `cmd/go` 工具中 `internal/fsys` 包的一部分，主要负责实现一个**虚拟文件系统**或者说是**带有 overlay 和 bind 功能的文件系统抽象层**。它的主要目的是为了在 Go 工具链的构建过程中，能够灵活地操作和管理文件，例如支持文件替换、目录绑定等，而无需直接修改实际的磁盘文件。这对于构建可复现的构建环境和进行测试非常有用。

下面列举一下它的功能：

1. **Overlay 文件系统:**
   - 允许定义一个 overlay 配置，将某些路径映射到其他路径或内容。
   - 可以实现文件内容的替换，即当访问某个文件时，实际读取的是 overlay 中指定的文件内容。
   - 可以实现文件的删除，即当访问某个文件时，会表现为文件不存在。
   - 可以实现目录的替换，即访问某个目录时，实际访问的是 overlay 中指定的路径。
   - Overlay 配置通过 JSON 格式指定。

2. **Bind 文件系统:**
   - 允许将一个路径绑定到另一个实际存在的目录。
   - 当访问被绑定的路径时，实际访问的是目标目录下的内容。

3. **文件和目录操作:**
   - 提供了类似于 `os` 包中的 `Stat`, `Lstat`, `IsDir`, `ReadDir`, `OpenFile`, `ReadFile`, `Glob`, `WalkDir` 等函数，但这些函数操作的是虚拟文件系统，而不是真实的磁盘文件系统。

4. **`IsGoDir` 功能:**
   - 提供了一个 `IsGoDir` 函数，用于判断一个目录是否是 Go 源码目录（即包含 `.go` 文件）。这个判断是在虚拟文件系统上进行的。

**推理它是什么 Go 语言功能的实现:**

从代码结构和功能来看，`internal/fsys` 包是 Go 工具链为了实现更灵活的文件系统操作而自定义的一个功能。它不是 Go 语言内置的核心特性，而是 Go 工具链为了自身需求构建的一个抽象层。这种抽象层允许 Go 工具链在构建、测试等过程中，不必直接依赖物理文件系统的状态，从而实现更精细的控制和更好的可移植性。

**Go 代码举例说明:**

假设我们有以下的 overlay 配置：

```json
{
  "Replace": {
    "original_file.txt": "overlay_file.txt",
    "deleted_file.txt": ""
  }
}
```

并且有以下的文件结构：

```
./
├── original_file.txt
└── some_dir/
    └── another_file.txt
```

`original_file.txt` 的内容是 "Original Content"。
`overlay_file.txt` 的内容是 "Overlay Content"。

使用 `fsys` 包的代码可能如下：

```go
package main

import (
	"fmt"
	"internal/fsys"
	"os"
	"testing"
)

func main() {
	// 假设已经通过某种方式初始化了 fsys 的 overlay

	// 模拟测试环境的初始化
	t := &testing.T{}
	fsys.InitOverlay(t, `{
		"Replace": {
			"original_file.txt": "overlay_file.txt",
			"deleted_file.txt": ""
		}
	}
	-- original_file.txt --
	Original Content
	-- overlay_file.txt --
	Overlay Content
	-- deleted_file.txt --
	This file will be deleted
	`)

	// 测试 Stat
	info, err := fsys.Stat("original_file.txt")
	if err != nil {
		fmt.Println("Stat error:", err)
	} else {
		fmt.Println("Stat original_file.txt:", info.Name()) // 输出: original_file.txt
	}

	info, err = fsys.Stat("deleted_file.txt")
	if err != nil {
		fmt.Println("Stat deleted_file.txt error:", err) // 输出: Stat deleted_file.txt error: stat deleted_file.txt: no such file or directory
	} else {
		fmt.Println("Stat deleted_file.txt:", info.Name())
	}

	// 测试 ReadFile
	content, err := fsys.ReadFile("original_file.txt")
	if err != nil {
		fmt.Println("ReadFile error:", err)
	} else {
		fmt.Println("ReadFile original_file.txt:", string(content)) // 输出: ReadFile original_file.txt: Overlay Content
	}

	_, err = fsys.ReadFile("deleted_file.txt")
	if err != nil {
		fmt.Println("ReadFile deleted_file.txt error:", err) // 输出: ReadFile deleted_file.txt error: open deleted_file.txt: file does not exist
	}

	// 测试 IsDir
	isDir, err := fsys.IsDir("some_dir")
	if err != nil {
		fmt.Println("IsDir error:", err)
	} else {
		fmt.Println("IsDir some_dir:", isDir) // 输出: IsDir some_dir: true (假设 some_dir 真实存在)
	}

	isDir, err = fsys.IsDir("deleted_file.txt")
	if err != nil {
		fmt.Println("IsDir deleted_file.txt error:", err) // 输出: IsDir deleted_file.txt error: isdir deleted_file.txt: not a directory
	} else {
		fmt.Println("IsDir deleted_file.txt:", isDir)
	}
}
```

**假设的输入与输出:**

在上面的 `main` 函数中，我们假设 `fsys` 包已经根据提供的 overlay 配置进行了初始化。

- **输入:**
  - 调用 `fsys.Stat("original_file.txt")`
  - 调用 `fsys.Stat("deleted_file.txt")`
  - 调用 `fsys.ReadFile("original_file.txt")`
  - 调用 `fsys.ReadFile("deleted_file.txt")`
  - 调用 `fsys.IsDir("some_dir")` (假设 `some_dir` 在真实文件系统中存在)
  - 调用 `fsys.IsDir("deleted_file.txt")`

- **输出:**
  - `fsys.Stat("original_file.txt")` 返回的 `FileInfo` 对象，其 `Name()` 方法返回 "original_file.txt"。
  - `fsys.Stat("deleted_file.txt")` 返回错误，提示文件不存在。
  - `fsys.ReadFile("original_file.txt")` 返回的内容是 "Overlay Content"。
  - `fsys.ReadFile("deleted_file.txt")` 返回错误，提示文件不存在。
  - `fsys.IsDir("some_dir")` 返回 `true`。
  - `fsys.IsDir("deleted_file.txt")` 返回 `false` 并可能返回一个 `PathError`。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。`internal/fsys` 包是 Go 工具链内部使用的，它的配置通常是通过 Go 工具链的其他部分来完成的，例如通过 `go` 命令的某些标志或配置文件。

然而，`initOverlay` 函数接受一个字符串参数 `config`，这个字符串实际上是一个 `txtar` 格式的文本归档，其中包含了 overlay 的 JSON 配置。在测试用例中，这个配置是硬编码的。在实际的 Go 工具链中，这个配置可能是从某个配置文件或者构建脚本中读取的。

**使用者易犯错的点:**

1. **混淆虚拟文件系统和真实文件系统:** 使用者可能会忘记他们正在操作的是一个虚拟的文件系统，而不是真实的磁盘文件系统。对虚拟文件系统的修改不会影响真实的文件系统，反之亦然。

   **例子:** 如果用户在 overlay 中删除了一个文件，他们可能会误以为真实磁盘上的文件也被删除了。

2. **Overlay 配置错误:**  JSON 配置的格式错误或逻辑错误会导致 `initFromJSON` 失败，从而影响后续的文件系统操作。

   **例子:**  在 `Replace` 中指定了一个不存在的目标文件路径。

3. **路径的理解:** 理解 overlay 和 bind 是如何影响路径解析的很重要。例如，当一个目录被替换时，访问该目录下原本存在的文件将会访问 overlay 中指定的路径下的文件。

   **例子:** 假设 overlay 配置为 `{"Replace": {"dir1": "dir2"}}`，那么访问 `dir1/file.txt` 实际上会尝试访问 `dir2/file.txt`。

4. **忽略错误处理:**  与任何文件系统操作一样，`fsys` 包的函数也可能返回错误。使用者需要正确处理这些错误，例如文件不存在、权限问题等。

这段代码的核心在于提供了一种灵活的方式来模拟和操作文件系统，这对于构建工具链、进行单元测试以及创建可复现的构建环境至关重要。通过 overlay 和 bind 的机制，Go 工具链可以在不修改实际磁盘文件的前提下，改变文件系统的“外观”，从而满足各种构建和测试需求。

### 提示词
```
这是路径为go/src/cmd/go/internal/fsys/fsys_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fsys

import (
	"errors"
	"internal/testenv"
	"internal/txtar"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
)

func resetForTesting() {
	cwd = sync.OnceValue(cwdOnce)
	overlay = nil
	binds = nil
}

// initOverlay resets the overlay state to reflect the config.
// config should be a text archive string. The comment is the overlay config
// json, and the files, in the archive are laid out in a temp directory
// that cwd is set to.
func initOverlay(t *testing.T, config string) {
	t.Helper()
	t.Chdir(t.TempDir())
	resetForTesting()
	t.Cleanup(resetForTesting)
	cwd := cwd()

	a := txtar.Parse([]byte(config))
	for _, f := range a.Files {
		name := filepath.Join(cwd, f.Name)
		if err := os.MkdirAll(filepath.Dir(name), 0777); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, f.Data, 0666); err != nil {
			t.Fatal(err)
		}
	}

	if err := initFromJSON(a.Comment); err != nil {
		t.Fatal(err)
	}
}

var statInfoOverlay = `{"Replace": {
	"x": "replace/x",
	"a/b/c": "replace/c",
	"d/e": ""
}}`

var statInfoTests = []struct {
	path string
	info info
}{
	{"foo", info{abs: "/tmp/foo", actual: "foo"}},
	{"foo/bar/baz/quux", info{abs: "/tmp/foo/bar/baz/quux", actual: "foo/bar/baz/quux"}},
	{"x", info{abs: "/tmp/x", replaced: true, file: true, actual: "/tmp/replace/x"}},
	{"/tmp/x", info{abs: "/tmp/x", replaced: true, file: true, actual: "/tmp/replace/x"}},
	{"x/y", info{abs: "/tmp/x/y", deleted: true}},
	{"a", info{abs: "/tmp/a", replaced: true, dir: true, actual: "a"}},
	{"a/b", info{abs: "/tmp/a/b", replaced: true, dir: true, actual: "a/b"}},
	{"a/b/c", info{abs: "/tmp/a/b/c", replaced: true, file: true, actual: "/tmp/replace/c"}},
	{"d/e", info{abs: "/tmp/d/e", deleted: true}},
	{"d", info{abs: "/tmp/d", replaced: true, dir: true, actual: "d"}},
}

var statInfoChildrenTests = []struct {
	path     string
	children []info
}{
	{"foo", nil},
	{"foo/bar", nil},
	{"foo/bar/baz", nil},
	{"x", nil},
	{"x/y", nil},
	{"a", []info{{abs: "/tmp/a/b", replaced: true, dir: true, actual: ""}}},
	{"a/b", []info{{abs: "/tmp/a/b/c", replaced: true, actual: "/tmp/replace/c"}}},
	{"d", []info{{abs: "/tmp/d/e", deleted: true}}},
	{"d/e", nil},
	{".", []info{
		{abs: "/tmp/a", replaced: true, dir: true, actual: ""},
		// {abs: "/tmp/d", replaced: true, dir: true, actual: ""},
		{abs: "/tmp/x", replaced: true, actual: "/tmp/replace/x"},
	}},
}

func TestStatInfo(t *testing.T) {
	tmp := "/tmp"
	if runtime.GOOS == "windows" {
		tmp = `C:\tmp`
	}
	cwd = sync.OnceValue(func() string { return tmp })

	winFix := func(s string) string {
		if runtime.GOOS == "windows" {
			s = strings.ReplaceAll(s, `/tmp`, tmp) // fix tmp
			s = strings.ReplaceAll(s, `/`, `\`)    // use backslashes
		}
		return s
	}

	overlay := statInfoOverlay
	overlay = winFix(overlay)
	overlay = strings.ReplaceAll(overlay, `\`, `\\`) // JSON escaping
	if err := initFromJSON([]byte(overlay)); err != nil {
		t.Fatal(err)
	}

	for _, tt := range statInfoTests {
		tt.path = winFix(tt.path)
		tt.info.abs = winFix(tt.info.abs)
		tt.info.actual = winFix(tt.info.actual)
		info := stat(tt.path)
		if info != tt.info {
			t.Errorf("stat(%#q):\nhave %+v\nwant %+v", tt.path, info, tt.info)
		}
	}

	for _, tt := range statInfoChildrenTests {
		tt.path = winFix(tt.path)
		for i, info := range tt.children {
			info.abs = winFix(info.abs)
			info.actual = winFix(info.actual)
			tt.children[i] = info
		}
		parent := stat(winFix(tt.path))
		var children []info
		for name, child := range parent.children() {
			if name != filepath.Base(child.abs) {
				t.Errorf("stat(%#q): child %#q has inconsistent abs %#q", tt.path, name, child.abs)
			}
			children = append(children, child)
		}
		slices.SortFunc(children, func(x, y info) int { return cmp(x.abs, y.abs) })
		if !slices.Equal(children, tt.children) {
			t.Errorf("stat(%#q) children:\nhave %+v\nwant %+v", tt.path, children, tt.children)
		}
	}
}

func TestIsDir(t *testing.T) {
	initOverlay(t, `
{
	"Replace": {
		"subdir2/file2.txt":  "overlayfiles/subdir2_file2.txt",
		"subdir4":            "overlayfiles/subdir4",
		"subdir3/file3b.txt": "overlayfiles/subdir3_file3b.txt",
		"subdir5":            "",
		"subdir6":            ""
	}
}
-- subdir1/file1.txt --

-- subdir3/file3a.txt --
33
-- subdir4/file4.txt --
444
-- overlayfiles/subdir2_file2.txt --
2
-- overlayfiles/subdir3_file3b.txt --
66666
-- overlayfiles/subdir4 --
x
-- subdir6/file6.txt --
six
`)

	cwd := cwd()
	testCases := []struct {
		path          string
		want, wantErr bool
	}{
		{"", true, true},
		{".", true, false},
		{cwd, true, false},
		{cwd + string(filepath.Separator), true, false},
		// subdir1 is only on disk
		{filepath.Join(cwd, "subdir1"), true, false},
		{"subdir1", true, false},
		{"subdir1" + string(filepath.Separator), true, false},
		{"subdir1/file1.txt", false, false},
		{"subdir1/doesntexist.txt", false, true},
		{"doesntexist", false, true},
		// subdir2 is only in overlay
		{filepath.Join(cwd, "subdir2"), true, false},
		{"subdir2", true, false},
		{"subdir2" + string(filepath.Separator), true, false},
		{"subdir2/file2.txt", false, false},
		{"subdir2/doesntexist.txt", false, true},
		// subdir3 has files on disk and in overlay
		{filepath.Join(cwd, "subdir3"), true, false},
		{"subdir3", true, false},
		{"subdir3" + string(filepath.Separator), true, false},
		{"subdir3/file3a.txt", false, false},
		{"subdir3/file3b.txt", false, false},
		{"subdir3/doesntexist.txt", false, true},
		// subdir4 is overlaid with a file
		{filepath.Join(cwd, "subdir4"), false, false},
		{"subdir4", false, false},
		{"subdir4" + string(filepath.Separator), false, false},
		{"subdir4/file4.txt", false, false},
		{"subdir4/doesntexist.txt", false, false},
		// subdir5 doesn't exist, and is overlaid with a "delete" entry
		{filepath.Join(cwd, "subdir5"), false, false},
		{"subdir5", false, false},
		{"subdir5" + string(filepath.Separator), false, false},
		{"subdir5/file5.txt", false, false},
		{"subdir5/doesntexist.txt", false, false},
		// subdir6 does exist, and is overlaid with a "delete" entry
		{filepath.Join(cwd, "subdir6"), false, false},
		{"subdir6", false, false},
		{"subdir6" + string(filepath.Separator), false, false},
		{"subdir6/file6.txt", false, false},
		{"subdir6/doesntexist.txt", false, false},
	}

	for _, tc := range testCases {
		got, err := IsDir(tc.path)
		if err != nil {
			if !tc.wantErr {
				t.Errorf("IsDir(%q): got error with string %q, want no error", tc.path, err.Error())
			}
			continue
		}
		if tc.wantErr {
			t.Errorf("IsDir(%q): got no error, want error", tc.path)
		}
		if tc.want != got {
			t.Errorf("IsDir(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

const readDirOverlay = `
{
	"Replace": {
		"subdir2/file2.txt":                 "overlayfiles/subdir2_file2.txt",
		"subdir4":                           "overlayfiles/subdir4",
		"subdir3/file3b.txt":                "overlayfiles/subdir3_file3b.txt",
		"subdir5":                           "",
		"subdir6/asubsubdir/afile.txt":      "overlayfiles/subdir6_asubsubdir_afile.txt",
		"subdir6/asubsubdir/zfile.txt":      "overlayfiles/subdir6_asubsubdir_zfile.txt",
		"subdir6/zsubsubdir/file.txt":       "overlayfiles/subdir6_zsubsubdir_file.txt",
		"subdir7/asubsubdir/file.txt":       "overlayfiles/subdir7_asubsubdir_file.txt",
		"subdir7/zsubsubdir/file.txt":       "overlayfiles/subdir7_zsubsubdir_file.txt",
		"subdir8/doesntexist":               "this_file_doesnt_exist_anywhere",
		"other/pointstodir":                 "overlayfiles/this_is_a_directory",
		"parentoverwritten/subdir1":         "overlayfiles/parentoverwritten_subdir1",
		"subdir9/this_file_is_overlaid.txt": "overlayfiles/subdir9_this_file_is_overlaid.txt",
		"subdir10/only_deleted_file.txt":    "",
		"subdir11/deleted.txt":              "",
		"subdir11":                          "overlayfiles/subdir11",
		"textfile.txt/file.go":              "overlayfiles/textfile_txt_file.go"
	}
}
-- subdir1/file1.txt --

-- subdir3/file3a.txt --
33
-- subdir4/file4.txt --
444
-- subdir6/file.txt --
-- subdir6/asubsubdir/file.txt --
-- subdir6/anothersubsubdir/file.txt --
-- subdir9/this_file_is_overlaid.txt --
-- subdir10/only_deleted_file.txt --
this will be deleted in overlay
-- subdir11/deleted.txt --
-- parentoverwritten/subdir1/subdir2/subdir3/file.txt --
-- textfile.txt --
this will be overridden by textfile.txt/file.go
-- overlayfiles/subdir2_file2.txt --
2
-- overlayfiles/subdir3_file3b.txt --
66666
-- overlayfiles/subdir4 --
x
-- overlayfiles/subdir6_asubsubdir_afile.txt --
-- overlayfiles/subdir6_asubsubdir_zfile.txt --
-- overlayfiles/subdir6_zsubsubdir_file.txt --
-- overlayfiles/subdir7_asubsubdir_file.txt --
-- overlayfiles/subdir7_zsubsubdir_file.txt --
-- overlayfiles/parentoverwritten_subdir1 --
x
-- overlayfiles/subdir9_this_file_is_overlaid.txt --
99999999
-- overlayfiles/subdir11 --
-- overlayfiles/this_is_a_directory/file.txt --
-- overlayfiles/textfile_txt_file.go --
x
`

func TestReadDir(t *testing.T) {
	initOverlay(t, readDirOverlay)

	type entry struct {
		name  string
		size  int64
		isDir bool
	}

	testCases := []struct {
		dir  string
		want []entry
	}{
		{
			".", []entry{
				{"other", 0, true},
				{"overlayfiles", 0, true},
				{"parentoverwritten", 0, true},
				{"subdir1", 0, true},
				{"subdir10", 0, true},
				{"subdir11", 0, false},
				{"subdir2", 0, true},
				{"subdir3", 0, true},
				{"subdir4", 2, false},
				// no subdir5.
				{"subdir6", 0, true},
				{"subdir7", 0, true},
				{"subdir8", 0, true},
				{"subdir9", 0, true},
				{"textfile.txt", 0, true},
			},
		},
		{
			"subdir1", []entry{
				{"file1.txt", 1, false},
			},
		},
		{
			"subdir2", []entry{
				{"file2.txt", 2, false},
			},
		},
		{
			"subdir3", []entry{
				{"file3a.txt", 3, false},
				{"file3b.txt", 6, false},
			},
		},
		{
			"subdir6", []entry{
				{"anothersubsubdir", 0, true},
				{"asubsubdir", 0, true},
				{"file.txt", 0, false},
				{"zsubsubdir", 0, true},
			},
		},
		{
			"subdir6/asubsubdir", []entry{
				{"afile.txt", 0, false},
				{"file.txt", 0, false},
				{"zfile.txt", 0, false},
			},
		},
		{
			"subdir8", []entry{
				{"doesntexist", 0, false}, // entry is returned even if destination file doesn't exist
			},
		},
		{
			// check that read dir actually redirects files that already exist
			// the original this_file_is_overlaid.txt is empty
			"subdir9", []entry{
				{"this_file_is_overlaid.txt", 9, false},
			},
		},
		{
			"subdir10", []entry{},
		},
		{
			"parentoverwritten", []entry{
				{"subdir1", 2, false},
			},
		},
		{
			"textfile.txt", []entry{
				{"file.go", 2, false},
			},
		},
	}

	for _, tc := range testCases {
		dir, want := tc.dir, tc.want
		infos, err := ReadDir(dir)
		if err != nil {
			t.Errorf("ReadDir(%q): %v", dir, err)
			continue
		}
		// Sorted diff of want and infos.
		for len(infos) > 0 || len(want) > 0 {
			switch {
			case len(want) == 0 || len(infos) > 0 && infos[0].Name() < want[0].name:
				t.Errorf("ReadDir(%q): unexpected entry: %s IsDir=%v", dir, infos[0].Name(), infos[0].IsDir())
				infos = infos[1:]
			case len(infos) == 0 || len(want) > 0 && want[0].name < infos[0].Name():
				t.Errorf("ReadDir(%q): missing entry: %s IsDir=%v", dir, want[0].name, want[0].isDir)
				want = want[1:]
			default:
				if infos[0].IsDir() != want[0].isDir {
					t.Errorf("ReadDir(%q): %s: IsDir=%v, want IsDir=%v", dir, want[0].name, infos[0].IsDir(), want[0].isDir)
				}
				infos = infos[1:]
				want = want[1:]
			}
		}
	}

	errCases := []string{
		"subdir1/file1.txt", // regular file on disk
		"subdir2/file2.txt", // regular file in overlay
		"subdir4",           // directory overlaid with regular file
		"subdir5",           // directory deleted in overlay
		"parentoverwritten/subdir1/subdir2/subdir3", // parentoverwritten/subdir1 overlaid with regular file
		"parentoverwritten/subdir1/subdir2",         // parentoverwritten/subdir1 overlaid with regular file
		"subdir11",                                  // directory with deleted child, overlaid with regular file
		"other/pointstodir",
	}

	for _, dir := range errCases {
		_, err := ReadDir(dir)
		if _, ok := err.(*fs.PathError); !ok {
			t.Errorf("ReadDir(%q): err = %T (%v), want fs.PathError", dir, err, err)
		}
	}
}

func TestGlob(t *testing.T) {
	initOverlay(t, readDirOverlay)

	testCases := []struct {
		pattern string
		match   []string
	}{
		{
			"*o*",
			[]string{
				"other",
				"overlayfiles",
				"parentoverwritten",
			},
		},
		{
			"subdir2/file2.txt",
			[]string{
				"subdir2/file2.txt",
			},
		},
		{
			"*/*.txt",
			[]string{
				"overlayfiles/subdir2_file2.txt",
				"overlayfiles/subdir3_file3b.txt",
				"overlayfiles/subdir6_asubsubdir_afile.txt",
				"overlayfiles/subdir6_asubsubdir_zfile.txt",
				"overlayfiles/subdir6_zsubsubdir_file.txt",
				"overlayfiles/subdir7_asubsubdir_file.txt",
				"overlayfiles/subdir7_zsubsubdir_file.txt",
				"overlayfiles/subdir9_this_file_is_overlaid.txt",
				"subdir1/file1.txt",
				"subdir2/file2.txt",
				"subdir3/file3a.txt",
				"subdir3/file3b.txt",
				"subdir6/file.txt",
				"subdir9/this_file_is_overlaid.txt",
			},
		},
	}

	for _, tc := range testCases {
		pattern := tc.pattern
		match, err := Glob(pattern)
		if err != nil {
			t.Errorf("Glob(%q): %v", pattern, err)
			continue
		}
		want := tc.match
		for i, name := range want {
			if name != tc.pattern {
				want[i] = filepath.FromSlash(name)
			}
		}
		for len(match) > 0 || len(want) > 0 {
			switch {
			case len(match) == 0 || len(want) > 0 && want[0] < match[0]:
				t.Errorf("Glob(%q): missing match: %s", pattern, want[0])
				want = want[1:]
			case len(want) == 0 || len(match) > 0 && match[0] < want[0]:
				t.Errorf("Glob(%q): extra match: %s", pattern, match[0])
				match = match[1:]
			default:
				want = want[1:]
				match = match[1:]
			}
		}
	}
}

func TestActual(t *testing.T) {
	initOverlay(t, `
{
	"Replace": {
		"subdir2/file2.txt":                 "overlayfiles/subdir2_file2.txt",
		"subdir3/doesntexist":               "this_file_doesnt_exist_anywhere",
		"subdir4/this_file_is_overlaid.txt": "overlayfiles/subdir4_this_file_is_overlaid.txt",
		"subdir5/deleted.txt":               "",
		"parentoverwritten/subdir1":         ""
	}
}
-- subdir1/file1.txt --
file 1
-- subdir4/this_file_is_overlaid.txt --
these contents are replaced by the overlay
-- parentoverwritten/subdir1/subdir2/subdir3/file.txt --
-- subdir5/deleted.txt --
deleted
-- overlayfiles/subdir2_file2.txt --
file 2
-- overlayfiles/subdir4_this_file_is_overlaid.txt --
99999999
`)

	cwd := cwd()
	testCases := []struct {
		path     string
		wantPath string
		wantOK   bool
	}{
		{"subdir1/file1.txt", "subdir1/file1.txt", false},
		// Actual returns false for directories
		{"subdir2", "subdir2", false},
		{"subdir2/file2.txt", filepath.Join(cwd, "overlayfiles/subdir2_file2.txt"), true},
		// Actual doesn't stat a file to see if it exists, so it happily returns
		// the 'to' path and true even if the 'to' path doesn't exist on disk.
		{"subdir3/doesntexist", filepath.Join(cwd, "this_file_doesnt_exist_anywhere"), true},
		// Like the subdir2/file2.txt case above, but subdir4 exists on disk, but subdir2 does not.
		{"subdir4/this_file_is_overlaid.txt", filepath.Join(cwd, "overlayfiles/subdir4_this_file_is_overlaid.txt"), true},
		{"subdir5", "subdir5", false},
		{"subdir5/deleted.txt", "", true},
	}

	for _, tc := range testCases {
		path := Actual(tc.path)
		ok := Replaced(tc.path)

		if path != tc.wantPath {
			t.Errorf("Actual(%q) = %q, want %q", tc.path, path, tc.wantPath)
		}
		if ok != tc.wantOK {
			t.Errorf("Replaced(%q) = %v, want %v", tc.path, ok, tc.wantOK)
		}
	}
}

func TestOpen(t *testing.T) {
	initOverlay(t, `
{
    "Replace": {
		"subdir2/file2.txt":                  "overlayfiles/subdir2_file2.txt",
		"subdir3/doesntexist":                "this_file_doesnt_exist_anywhere",
		"subdir4/this_file_is_overlaid.txt":  "overlayfiles/subdir4_this_file_is_overlaid.txt",
		"subdir5/deleted.txt":                "",
		"parentoverwritten/subdir1":          "",
		"childoverlay/subdir1.txt/child.txt": "overlayfiles/child.txt",
		"subdir11/deleted.txt":               "",
		"subdir11":                           "overlayfiles/subdir11",
		"parentdeleted":                      "",
		"parentdeleted/file.txt":             "overlayfiles/parentdeleted_file.txt"
	}
}
-- subdir11/deleted.txt --
-- subdir1/file1.txt --
file 1
-- subdir4/this_file_is_overlaid.txt --
these contents are replaced by the overlay
-- parentoverwritten/subdir1/subdir2/subdir3/file.txt --
-- childoverlay/subdir1.txt --
this file doesn't exist because the path
childoverlay/subdir1.txt/child.txt is in the overlay
-- subdir5/deleted.txt --
deleted
-- parentdeleted --
this will be deleted so that parentdeleted/file.txt can exist
-- overlayfiles/subdir2_file2.txt --
file 2
-- overlayfiles/subdir4_this_file_is_overlaid.txt --
99999999
-- overlayfiles/child.txt --
-- overlayfiles/subdir11 --
11
-- overlayfiles/parentdeleted_file.txt --
this can exist because the parent directory is deleted
`)

	testCases := []struct {
		path         string
		wantContents string
		isErr        bool
	}{
		{"subdir1/file1.txt", "file 1\n", false},
		{"subdir2/file2.txt", "file 2\n", false},
		{"subdir3/doesntexist", "", true},
		{"subdir4/this_file_is_overlaid.txt", "99999999\n", false},
		{"subdir5/deleted.txt", "", true},
		{"parentoverwritten/subdir1/subdir2/subdir3/file.txt", "", true},
		{"childoverlay/subdir1.txt", "", true},
		{"subdir11", "11\n", false},
		{"parentdeleted/file.txt", "this can exist because the parent directory is deleted\n", false},
	}

	for _, tc := range testCases {
		f, err := Open(tc.path)
		if tc.isErr {
			if err == nil {
				f.Close()
				t.Errorf("Open(%q): got no error, but want error", tc.path)
			}
			continue
		}
		if err != nil {
			t.Errorf("Open(%q): got error %v, want nil", tc.path, err)
			continue
		}
		contents, err := io.ReadAll(f)
		if err != nil {
			t.Errorf("unexpected error reading contents of file: %v", err)
		}
		if string(contents) != tc.wantContents {
			t.Errorf("contents of file opened with Open(%q): got %q, want %q",
				tc.path, contents, tc.wantContents)
		}
		f.Close()
	}
}

func TestIsGoDir(t *testing.T) {
	initOverlay(t, `
{
	"Replace": {
		"goinoverlay/file.go":       "dummy",
		"directory/removed/by/file": "dummy",
		"directory_with_go_dir/dir.go/file.txt": "dummy",
		"otherdirectory/deleted.go": "",
		"nonexistentdirectory/deleted.go": "",
		"textfile.txt/file.go": "dummy"
	}
}
-- dummy --
a destination file for the overlay entries to point to
contents don't matter for this test
-- nogo/file.txt --
-- goondisk/file.go --
-- goinoverlay/file.txt --
-- directory/removed/by/file/in/overlay/file.go --
-- otherdirectory/deleted.go --
-- textfile.txt --
`)

	testCases := []struct {
		dir     string
		want    bool
		wantErr bool
	}{
		{"nogo", false, false},
		{"goondisk", true, false},
		{"goinoverlay", true, false},
		{"directory/removed/by/file/in/overlay", false, false},
		{"directory_with_go_dir", false, false},
		{"otherdirectory", false, false},
		{"nonexistentdirectory", false, false},
		{"textfile.txt", true, false},
	}

	for _, tc := range testCases {
		got, gotErr := IsGoDir(tc.dir)
		if tc.wantErr {
			if gotErr == nil {
				t.Errorf("IsGoDir(%q): got %v, %v; want non-nil error", tc.dir, got, gotErr)
			}
			continue
		}
		if gotErr != nil {
			t.Errorf("IsGoDir(%q): got %v, %v; want nil error", tc.dir, got, gotErr)
		}
		if got != tc.want {
			t.Errorf("IsGoDir(%q) = %v; want %v", tc.dir, got, tc.want)
		}
	}
}

func TestWalk(t *testing.T) {
	// The root of the walk must be a name with an actual basename, not just ".".
	// Walk uses Lstat to obtain the name of the root, and Lstat on platforms
	// other than Plan 9 reports the name "." instead of the actual base name of
	// the directory. (See https://golang.org/issue/42115.)

	type file struct {
		path  string
		name  string
		size  int64
		mode  fs.FileMode
		isDir bool
	}
	testCases := []struct {
		name      string
		overlay   string
		root      string
		wantFiles []file
	}{
		{"no overlay", `
{}
-- dir/file.txt --
`,
			"dir",
			[]file{
				{"dir", "dir", 0, fs.ModeDir | 0700, true},
				{"dir/file.txt", "file.txt", 0, 0600, false},
			},
		},
		{"overlay with different file", `
{
	"Replace": {
		"dir/file.txt": "dir/other.txt"
	}
}
-- dir/file.txt --
-- dir/other.txt --
contents of other file
`,
			"dir",
			[]file{
				{"dir", "dir", 0, fs.ModeDir | 0500, true},
				{"dir/file.txt", "file.txt", 23, 0600, false},
				{"dir/other.txt", "other.txt", 23, 0600, false},
			},
		},
		{"overlay with new file", `
{
	"Replace": {
		"dir/file.txt": "dir/other.txt"
	}
}
-- dir/other.txt --
contents of other file
`,
			"dir",
			[]file{
				{"dir", "dir", 0, fs.ModeDir | 0500, true},
				{"dir/file.txt", "file.txt", 23, 0600, false},
				{"dir/other.txt", "other.txt", 23, 0600, false},
			},
		},
		{"overlay with new directory", `
{
	"Replace": {
		"dir/subdir/file.txt": "dir/other.txt"
	}
}
-- dir/other.txt --
contents of other file
`,
			"dir",
			[]file{
				{"dir", "dir", 0, fs.ModeDir | 0500, true},
				{"dir/other.txt", "other.txt", 23, 0600, false},
				{"dir/subdir", "subdir", 0, fs.ModeDir | 0500, true},
				{"dir/subdir/file.txt", "file.txt", 23, 0600, false},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			initOverlay(t, tc.overlay)

			var got []file
			WalkDir(tc.root, func(path string, d fs.DirEntry, err error) error {
				info, err := d.Info()
				if err != nil {
					t.Fatal(err)
				}
				if info.Name() != d.Name() {
					t.Errorf("walk %s: d.Name() = %q, but info.Name() = %q", path, d.Name(), info.Name())
				}
				if info.IsDir() != d.IsDir() {
					t.Errorf("walk %s: d.IsDir() = %v, but info.IsDir() = %v", path, d.IsDir(), info.IsDir())
				}
				if info.Mode().Type() != d.Type() {
					t.Errorf("walk %s: d.Type() = %v, but info.Mode().Type() = %v", path, d.Type(), info.Mode().Type())
				}
				got = append(got, file{path, d.Name(), info.Size(), info.Mode(), d.IsDir()})
				return nil
			})

			if len(got) != len(tc.wantFiles) {
				t.Errorf("Walk: saw %#v in walk; want %#v", got, tc.wantFiles)
			}
			for i := 0; i < len(got) && i < len(tc.wantFiles); i++ {
				wantPath := filepath.FromSlash(tc.wantFiles[i].path)
				if got[i].path != wantPath {
					t.Errorf("walk #%d: path = %q, want %q", i, got[i].path, wantPath)
				}
				if got[i].name != tc.wantFiles[i].name {
					t.Errorf("walk %s: Name = %q, want %q", got[i].path, got[i].name, tc.wantFiles[i].name)
				}
				if got[i].mode&(fs.ModeDir|0700) != tc.wantFiles[i].mode {
					t.Errorf("walk %s: Mode = %q, want %q", got[i].path, got[i].mode&(fs.ModeDir|0700), tc.wantFiles[i].mode)
				}
				if got[i].isDir != tc.wantFiles[i].isDir {
					t.Errorf("walk %s: IsDir = %v, want %v", got[i].path, got[i].isDir, tc.wantFiles[i].isDir)
				}
			}
		})
	}
}

func TestWalkSkipDir(t *testing.T) {
	initOverlay(t, `
{
	"Replace": {
		"dir/skip/file.go": "dummy.txt",
		"dir/dontskip/file.go": "dummy.txt",
		"dir/dontskip/skip/file.go": "dummy.txt"
	}
}
-- dummy.txt --
`)

	var seen []string
	WalkDir("dir", func(path string, d fs.DirEntry, err error) error {
		seen = append(seen, filepath.ToSlash(path))
		if d.Name() == "skip" {
			return filepath.SkipDir
		}
		return nil
	})

	wantSeen := []string{"dir", "dir/dontskip", "dir/dontskip/file.go", "dir/dontskip/skip", "dir/skip"}

	if len(seen) != len(wantSeen) {
		t.Errorf("paths seen in walk: got %v entries; want %v entries", len(seen), len(wantSeen))
	}

	for i := 0; i < len(seen) && i < len(wantSeen); i++ {
		if seen[i] != wantSeen[i] {
			t.Errorf("path #%v seen walking tree: want %q, got %q", i, seen[i], wantSeen[i])
		}
	}
}

func TestWalkSkipAll(t *testing.T) {
	initOverlay(t, `
{
	"Replace": {
		"dir/subdir1/foo1": "dummy.txt",
		"dir/subdir1/foo2": "dummy.txt",
		"dir/subdir1/foo3": "dummy.txt",
		"dir/subdir2/foo4": "dummy.txt",
		"dir/zzlast": "dummy.txt"
	}
}
-- dummy.txt --
`)

	var seen []string
	WalkDir("dir", func(path string, d fs.DirEntry, err error) error {
		seen = append(seen, filepath.ToSlash(path))
		if d.Name() == "foo2" {
			return filepath.SkipAll
		}
		return nil
	})

	wantSeen := []string{"dir", "dir/subdir1", "dir/subdir1/foo1", "dir/subdir1/foo2"}

	if len(seen) != len(wantSeen) {
		t.Errorf("paths seen in walk: got %v entries; want %v entries", len(seen), len(wantSeen))
	}

	for i := 0; i < len(seen) && i < len(wantSeen); i++ {
		if seen[i] != wantSeen[i] {
			t.Errorf("path %#v seen walking tree: got %q, want %q", i, seen[i], wantSeen[i])
		}
	}
}

func TestWalkError(t *testing.T) {
	initOverlay(t, "{}")

	alreadyCalled := false
	err := WalkDir("foo", func(path string, d fs.DirEntry, err error) error {
		if alreadyCalled {
			t.Fatal("expected walk function to be called exactly once, but it was called more than once")
		}
		alreadyCalled = true
		return errors.New("returned from function")
	})
	if !alreadyCalled {
		t.Fatal("expected walk function to be called exactly once, but it was never called")

	}
	if err == nil {
		t.Fatalf("Walk: got no error, want error")
	}
	if err.Error() != "returned from function" {
		t.Fatalf("Walk: got error %v, want \"returned from function\" error", err)
	}
}

func TestWalkSymlink(t *testing.T) {
	testenv.MustHaveSymlink(t)

	initOverlay(t, `{
	"Replace": {"overlay_symlink/file": "symlink/file"}
}
-- dir/file --`)

	// Create symlink
	if err := os.Symlink("dir", "symlink"); err != nil {
		t.Error(err)
	}

	testCases := []struct {
		name      string
		dir       string
		wantFiles []string
	}{
		{"control", "dir", []string{"dir", filepath.Join("dir", "file")}},
		// ensure Walk doesn't walk into the directory pointed to by the symlink
		// (because it's supposed to use Lstat instead of Stat).
		{"symlink_to_dir", "symlink", []string{"symlink"}},
		{"overlay_to_symlink_to_dir", "overlay_symlink", []string{"overlay_symlink", filepath.Join("overlay_symlink", "file")}},

		// However, adding filepath.Separator should cause the link to be resolved.
		{"symlink_with_slash", "symlink" + string(filepath.Separator), []string{"symlink" + string(filepath.Separator), filepath.Join("symlink", "file")}},
		{"overlay_to_symlink_to_dir", "overlay_symlink" + string(filepath.Separator), []string{"overlay_symlink" + string(filepath.Separator), filepath.Join("overlay_symlink", "file")}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var got []string

			err := WalkDir(tc.dir, func(path string, d fs.DirEntry, err error) error {
				t.Logf("walk %q", path)
				got = append(got, path)
				if err != nil {
					t.Errorf("walkfn: got non nil err argument: %v, want nil err argument", err)
				}
				return nil
			})
			if err != nil {
				t.Errorf("Walk: got error %q, want nil", err)
			}

			if !reflect.DeepEqual(got, tc.wantFiles) {
				t.Errorf("files examined by walk: got %v, want %v", got, tc.wantFiles)
			}
		})
	}

}

func TestLstat(t *testing.T) {
	type file struct {
		name  string
		size  int64
		mode  fs.FileMode // mode & (fs.ModeDir|0x700): only check 'user' permissions
		isDir bool
	}

	testCases := []struct {
		name    string
		overlay string
		path    string

		want    file
		wantErr bool
	}{
		{
			"regular_file",
			`{}
-- file.txt --
contents`,
			"file.txt",
			file{"file.txt", 9, 0600, false},
			false,
		},
		{
			"new_file_in_overlay",
			`{"Replace": {"file.txt": "dummy.txt"}}
-- dummy.txt --
contents`,
			"file.txt",
			file{"file.txt", 9, 0600, false},
			false,
		},
		{
			"file_replaced_in_overlay",
			`{"Replace": {"file.txt": "dummy.txt"}}
-- file.txt --
-- dummy.txt --
contents`,
			"file.txt",
			file{"file.txt", 9, 0600, false},
			false,
		},
		{
			"file_cant_exist",
			`{"Replace": {"deleted": "dummy.txt"}}
-- deleted/file.txt --
-- dummy.txt --
`,
			"deleted/file.txt",
			file{},
			true,
		},
		{
			"deleted",
			`{"Replace": {"deleted": ""}}
-- deleted --
`,
			"deleted",
			file{},
			true,
		},
		{
			"dir_on_disk",
			`{}
-- dir/foo.txt --
`,
			"dir",
			file{"dir", 0, 0700 | fs.ModeDir, true},
			false,
		},
		{
			"dir_in_overlay",
			`{"Replace": {"dir/file.txt": "dummy.txt"}}
-- dummy.txt --
`,
			"dir",
			file{"dir", 0, 0500 | fs.ModeDir, true},
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			initOverlay(t, tc.overlay)
			got, err := Lstat(tc.path)
			if tc.wantErr {
				if err == nil {
					t.Errorf("lstat(%q): got no error, want error", tc.path)
				}
				return
			}
			if err != nil {
				t.Fatalf("lstat(%q): got error %v, want no error", tc.path, err)
			}
			if got.Name() != tc.want.name {
				t.Errorf("lstat(%q).Name(): got %q, want %q", tc.path, got.Name(), tc.want.name)
			}
			if got.Mode()&(fs.ModeDir|0700) != tc.want.mode {
				t.Errorf("lstat(%q).Mode()&(fs.ModeDir|0700): got %v, want %v", tc.path, got.Mode()&(fs.ModeDir|0700), tc.want.mode)
			}
			if got.IsDir() != tc.want.isDir {
				t.Errorf("lstat(%q).IsDir(): got %v, want %v", tc.path, got.IsDir(), tc.want.isDir)
			}
			if tc.want.isDir {
				return // don't check size for directories
			}
			if got.Size() != tc.want.size {
				t.Errorf("lstat(%q).Size(): got %v, want %v", tc.path, got.Size(), tc.want.size)
			}
		})
	}
}

func TestStat(t *testing.T) {
	testenv.MustHaveSymlink(t)

	type file struct {
		name  string
		size  int64
		mode  os.FileMode // mode & (os.ModeDir|0x700): only check 'user' permissions
		isDir bool
	}

	testCases := []struct {
		name    string
		overlay string
		path    string

		want    file
		wantErr bool
	}{
		{
			"regular_file",
			`{}
-- file.txt --
contents`,
			"file.txt",
			file{"file.txt", 9, 0600, false},
			false,
		},
		{
			"new_file_in_overlay",
			`{"Replace": {"file.txt": "dummy.txt"}}
-- dummy.txt --
contents`,
			"file.txt",
			file{"file.txt", 9, 0600, false},
			false,
		},
		{
			"file_replaced_in_overlay",
			`{"Replace": {"file.txt": "dummy.txt"}}
-- file.txt --
-- dummy.txt --
contents`,
			"file.txt",
			file{"file.txt", 9, 0600, false},
			false,
		},
		{
			"file_cant_exist",
			`{"Replace": {"deleted": "dummy.txt"}}
-- deleted/file.txt --
-- dummy.txt --
`,
			"deleted/file.txt",
			file{},
			true,
		},
		{
			"deleted",
			`{"Replace": {"deleted": ""}}
-- deleted --
`,
			"deleted",
			file{},
			true,
		},
		{
			"dir_on_disk",
			`{}
-- dir/foo.txt --
`,
			"dir",
			file{"dir", 0, 0700 | os.ModeDir, true},
			false,
		},
		{
			"dir_in_overlay",
			`{"Replace": {"dir/file.txt": "dummy.txt"}}
-- dummy.txt --
`,
			"dir",
			file{"dir", 0, 0500 | os.ModeDir, true},
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			initOverlay(t, tc.overlay)
			got, err := Stat(tc.path)
			if tc.wantErr {
				if err == nil {
					t.Errorf("Stat(%q): got no error, want error", tc.path)
				}
				return
			}
			if err != nil {
				t.Fatalf("Stat(%q): got error %v, want no error", tc.path, err)
			}
			if got.Name() != tc.want.name {
				t.Errorf("Stat(%q).Name(): got %q, want %q", tc.path, got.Name(), tc.want.name)
			}
			if got.Mode()&(os.ModeDir|0700) != tc.want.mode {
				t.Errorf("Stat(%q).Mode()&(os.ModeDir|0700): got %v, want %v", tc.path, got.Mode()&(os.ModeDir|0700), tc.want.mode)
			}
			if got.IsDir() != tc.want.isDir {
				t.Errorf("Stat(%q).IsDir(): got %v, want %v", tc.path, got.IsDir(), tc.want.isDir)
			}
			if tc.want.isDir {
				return // don't check size for directories
			}
			if got.Size() != tc.want.size {
				t.Errorf("Stat(%q).Size(): got %v, want %v", tc.path, got.Size(), tc.want.size)
			}
		})
	}
}

func TestStatSymlink(t *testing.T) {
	testenv.MustHaveSymlink(t)

	initOverlay(t, `{
	"Replace": {"file.go": "symlink"}
}
-- to.go --
0123456789
`)

	// Create symlink
	if err := os.Symlink("to.go", "symlink"); err != nil {
		t.Error(err)
	}

	f := "file.go"
	fi, err := Stat(f)
	if err != nil {
		t.Errorf("Stat(%q): got error %q, want nil error", f, err)
	}

	if !fi.Mode().IsRegular() {
		t.Errorf("Stat(%q).Mode(): got %v, want regular mode", f, fi.Mode())
	}

	if fi.Size() != 11 {
		t.Errorf("Stat(%q).Size(): got %v, want 11", f, fi.Size())
	}
}

func TestBindOverlay(t *testing.T) {
	initOverlay(t, `{"Replace": {"mtpt/x.go": "xx.go"}}
-- mtpt/x.go --
mtpt/x.go
-- mtpt/y.go --
mtpt/y.go
-- mtpt2/x.go --
mtpt/x.go
-- replaced/x.go --
replaced/x.go
-- replaced/x/y/z.go --
replaced/x/y/z.go
-- xx.go --
xx.go
`)

	testReadFile(t, "mtpt/x.go", "xx.go\n")

	Bind("replaced", "mtpt")
	testReadFile(t, "mtpt/x.go", "replaced/x.go\n")
	testReadDir(t, "mtpt/x", "y/")
	testReadDir(t, "mtpt/x/y", "z.go")
	testReadFile(t, "mtpt/x/y/z.go", "replaced/x/y/z.go\n")
	testReadFile(t, "mtpt/y.go", "ERROR")

	Bind("replaced", "mtpt2/a/b")
	testReadDir(t, "mtpt2", "a/", "x.go")
	testReadDir(t, "mtpt2/a", "b/")
	testReadDir(t, "mtpt2/a/b", "x/", "x.go")
	testReadFile(t, "mtpt2/a/b/x.go", "replaced/x.go\n")
}

var badOverlayTests = []struct {
	json string
	err  string
}{
	{`{`,
		"parsing overlay JSON: unexpected end of JSON input"},
	{`{"Replace": {"":"a"}}`,
		"empty string key in overlay map"},
	{`{"Replace": {"/tmp/x": "y", "x": "y"}}`,
		`duplicate paths /tmp/x and x in overlay map`},
	{`{"Replace": {"/tmp/x/z": "z", "x":"y"}}`,
		`inconsistent files /tmp/x and /tmp/x/z in overlay map`},
	{`{"Replace": {"/tmp/x/z/z2": "z", "x":"y"}}`,
		`inconsistent files /tmp/x and /tmp/x/z/z2 in overlay map`},
	{`{"Replace": {"/tmp/x": "y", "x/z/z2": "z"}}`,
		`inconsistent files /tmp/x and /tmp/x/z/z2 in overlay map`},
}

func TestBadOverlay(t *testing.T) {
	tmp := "/tmp"
	if runtime.GOOS == "windows" {
		tmp = `C:\tmp`
	}
	cwd = sync.OnceValue(func() string { return tmp })
	defer resetForTesting()

	for i, tt := range badOverlayTests {
		if runtime.GOOS == "windows" {
			tt.json = strings.ReplaceAll(tt.json, `/tmp`, tmp) // fix tmp
			tt.json = strings.ReplaceAll(tt.json, `/`, `\`)    // use backslashes
			tt.json = strings.ReplaceAll(tt.json, `\`, `\\`)   // JSON escaping
			tt.err = strings.ReplaceAll(tt.err, `/tmp`, tmp)   // fix tmp
			tt.err = strings.ReplaceAll(tt.err, `/`, `\`)      // use backslashes
		}
		err := initFromJSON([]byte(tt.json))
		if err == nil || err.Error() != tt.err {
			t.Errorf("#%d: err=%v, want %q", i, err, tt.err)
		}
	}
}

func testReadFile(t *testing.T, name string, want string) {
	t.Helper()
	data, err := ReadFile(name)
	if want == "ERROR" {
		if data != nil || err == nil {
			t.Errorf("ReadFile(%q) = %q, %v, want nil, error", name, data, err)
		}
		return
	}
	if string(data) != want || err != nil {
		t.Errorf("ReadFile(%q) = %q, %v, want %q, nil", name, data, err, want)
	}
}

func testReadDir(t *testing.T, name string, want ...string) {
	t.Helper()
	dirs, err := ReadDir(name)
	var names []string
	for _, d := range dirs {
		name := d.Name()
		if d.IsDir() {
			name += "/"
		}
		names = append(names, name)
	}
	if !slices.Equal(names, want) || err != nil {
		t.Errorf("ReadDir(%q) = %q, %v, want %q, nil", name, names, err, want)
	}
}
```