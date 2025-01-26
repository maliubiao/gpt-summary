Response:
Let's break down the thought process for analyzing the provided Go code snippet and generating the detailed explanation.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the `testfs.go` file, specifically the `TestFS` function, and explain it in a clear, concise, and informative way in Chinese. The request also asks for code examples, explanations of related Go features, handling of command-line arguments (though this file doesn't directly use them), and common pitfalls.

**2. Initial Code Scan and Identifying Key Components:**

I'll start by quickly scanning the code to identify the main functions, data structures, and imported packages.

* **Key Function:** `TestFS` stands out as the main entry point. Its documentation is also a good starting point.
* **Supporting Functions:**  `testFS`, `fsTester` methods (`errorf`, `openDir`, `checkDir`, `checkStat`, etc.). These seem to be helper functions used within the testing logic.
* **Data Structure:** `fsTester` clearly holds the state for the tests.
* **Imports:** `io`, `io/fs`, `maps`, `path`, `slices`, `strings`, `testing/iotest`. These give clues about the file system operations being tested (reading, listing directories, etc.) and the testing utilities being used.

**3. Focusing on `TestFS` and its Purpose:**

The documentation for `TestFS` is crucial. It states that it tests a file system implementation against a set of expected files. The core idea is to walk the file system, open files, and verify their behavior. The mention of `fs.FS` immediately points to the standard Go file system interface.

**4. Deconstructing `TestFS` Step-by-Step:**

Now, I'll go through the `TestFS` function line by line:

* **`testFS(fsys, expected...)`:** It first calls an internal `testFS` function. This suggests a separation of concerns, with `TestFS` potentially handling setup or post-processing.
* **Looping through `expected`:** The `for _, name := range expected` loop indicates that `TestFS` iterates through the expected files.
* **`strings.Index(name, "/")`:** This checks if the expected file is within a subdirectory.
* **`fs.Sub(fsys, dir)`:** If a subdirectory is involved, `fs.Sub` is used to create a sub-filesystem view. This is a key Go `io/fs` feature.
* **Recursive call to `testFS`:**  The function then recursively calls `testFS` on the sub-filesystem. This is important for testing nested directory structures.

**5. Analyzing `testFS`:**

The `testFS` function does the bulk of the work:

* **`fsTester` instantiation:** It creates an `fsTester` to manage the test state.
* **`t.checkDir(".")` and `t.checkOpen(".")`:** It starts by checking the root directory.
* **Tracking found files/directories:** It uses `t.dirs` and `t.files` to keep track of discovered entries.
* **Checking for unexpected files (if `expected` is empty):** This handles the case where an empty file system is expected.
* **Verifying expected files:** It ensures all the `expected` files are found.
* **Error aggregation:** It collects errors in `t.errors`.

**6. Examining `fsTester` Methods:**

The methods of `fsTester` implement the actual testing logic:

* **`openDir`:**  Opens a directory and checks if it's a `fs.ReadDirFile`.
* **`checkDir`:** Reads directory contents using `ReadDir`, checks each entry's `Stat` and `Open` behavior, and recursively calls `checkDir` for subdirectories. It also tests different `ReadDir` call patterns and the `fs.ReadDir` function.
* **`checkStat`:** Compares the results of `file.Stat()` and `entry.Info()`.
* **`checkDirList`:** Compares two directory listings for consistency.
* **`checkFile`:** Reads the content of a file using `Open` and `ReadAll`, and also tests `fs.ReadFile` if available. It uses `iotest.TestReader` for more thorough reader testing.
* **`checkOpen` and `checkBadPath`:** Tests opening files with invalid paths.
* **`checkGlob`:** Tests the `Glob` functionality if the file system implements `fs.GlobFS`.

**7. Identifying Go Feature Implementation:**

The code clearly implements a test suite for the `io/fs` package. It leverages core interfaces like `fs.FS`, `fs.ReadDirFS`, `fs.ReadFileFS`, and `fs.GlobFS`. The use of `fs.Sub` is another important `io/fs` feature being tested.

**8. Constructing Code Examples:**

To illustrate the usage, I'll create a simple example of an in-memory file system and how to use `TestFS` with it. This involves defining a basic file system structure and calling `TestFS` with some expected file names.

**9. Addressing Command-Line Arguments:**

The current code doesn't directly handle command-line arguments. It's important to explicitly state this.

**10. Identifying Common Pitfalls:**

The main pitfall is related to the `expected` list. Users might forget to list an expected file, leading to false positives (the test passes even if the file is missing). Another pitfall is assuming the test will fail immediately on the first error; it collects multiple errors.

**11. Structuring the Answer in Chinese:**

Finally, I'll organize the findings into a clear and well-structured Chinese answer, addressing each point in the request:

* **功能列举:** List the main functions performed by the code.
* **Go 功能实现推理和代码举例:** Explain that it tests `io/fs` implementations and provide a code example.
* **代码推理 (带假设输入与输出):** For the code example, show the expected input (the in-memory file system) and the output (success or failure of the `TestFS` call).
* **命令行参数处理:** Explain that the code doesn't directly handle command-line arguments.
* **使用者易犯错的点:** Describe the common pitfalls related to the `expected` list.

**Self-Correction/Refinement:**

During the process, I might realize:

* **Clarity of Explanation:** Is my explanation of `fs.Sub` clear enough? Do I need to elaborate?
* **Code Example Simplicity:** Is the in-memory file system example too complex? Can I simplify it?
* **Completeness:** Have I addressed all aspects of the prompt?

By following these steps, systematically analyzing the code, and refining the explanation, I can generate a comprehensive and accurate answer to the request.
这段Go语言代码是 `go/src/testing/fstest/testfs.go` 文件的一部分，它提供了一个用于测试 `io/fs` 包中定义的 `fs.FS` 接口实现的功能。 它的主要功能是：

**1. 测试文件系统实现的正确性 (Test File System Implementation Correctness):**

   - `TestFS` 函数是核心，它接受一个 `fs.FS` 接口的实现和一个可选的期望存在的文件列表作为输入。
   - 它会遍历文件系统 `fsys` 中的所有文件和目录。
   - 对于每个文件和目录，它会执行一系列检查，例如：
     - **打开 (Open):** 尝试打开文件和目录。
     - **读取目录 (ReadDir):**  读取目录内容，并验证返回的文件和目录信息是否正确。
     - **获取文件信息 (Stat/Info):**  调用 `Stat` 和 `Info` 方法获取文件和目录的元数据，并进行比较。
     - **读取文件内容 (ReadAll/ReadFile):** 读取文件内容，并进行验证。
     - **处理错误路径 (Bad Path Handling):** 尝试使用无效的路径打开文件，并验证是否返回了预期的错误。
   - 它还会检查文件系统是否至少包含 `expected` 列表中指定的文件。 如果 `expected` 列表为空，则它期望文件系统是空的。

**2. 测试 `fs.Sub` 功能 (Testing `fs.Sub` Functionality):**

   - 如果 `expected` 列表中存在带有斜杠 `/` 的条目，`TestFS` 会使用 `fs.Sub` 函数创建一个子文件系统，并递归地调用 `testFS` 来测试子文件系统的行为。 这确保了 `fs.Sub` 正确地创建了文件系统的视图。

**3. 测试 `fs.Glob` 功能 (Testing `fs.Glob` Functionality):**

   - 如果被测试的文件系统实现了 `fs.GlobFS` 接口，`checkGlob` 函数会使用不同的 glob 模式来匹配文件和目录，并验证返回的结果是否正确。

**推理它是什么Go语言功能的实现:**

这段代码主要实现了 **对 `io/fs` 包中 `fs.FS` 接口实现的集成测试框架。** `io/fs` 包定义了文件系统的抽象接口，允许 Go 程序以统一的方式与不同的文件系统进行交互。 `fstest` 包提供了一套标准的测试用例，用于验证任何实现了 `fs.FS` 接口的文件系统（例如内存文件系统、zip 文件系统、HTTP 文件系统等）是否符合预期行为。

**Go代码举例说明:**

假设我们有一个简单的内存文件系统实现 `memfs` (为了简化，这里只展示基本结构，完整的实现会更复杂):

```go
package memfs

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
)

type memFile struct {
	name    string
	data    []byte
	modTime time.Time
	isDir   bool
}

type MemFS struct {
	mu    sync.RWMutex
	files map[string]*memFile
}

func New() *MemFS {
	return &MemFS{files: make(map[string]*memFile)}
}

func (m *MemFS) Create(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.files[name]; ok {
		return os.ErrExist
	}
	m.files[name] = &memFile{name: name, modTime: time.Now()}
	return nil
}

func (m *MemFS) MkdirAll(path string, perm os.FileMode) error {
    m.mu.Lock()
    defer m.mu.Unlock()
    // Simplified mkdirAll logic
    if _, ok := m.files[path]; ok {
        if !m.files[path].isDir {
            return errors.New("path exists and is not a directory")
        }
        return nil
    }
    m.files[path] = &memFile{name: path, isDir: true, modTime: time.Now()}
    return nil
}

func (m *MemFS) Open(name string) (fs.File, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	f, ok := m.files[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	if f.isDir {
		return &memDirFile{memFile: f, fs: m}, nil
	}
	return &memReadFile{memFile: f}, nil
}

// ... (memReadFile 和 memDirFile 的实现，这里省略)

func (m *MemFS) ReadDir(name string) ([]fs.DirEntry, error) {
    m.mu.RLock()
    defer m.mu.RUnlock()
    var entries []fs.DirEntry
    prefix := name
    if prefix != "." {
        prefix += "/"
    }
    for fileName, file := range m.files {
        if strings.HasPrefix(fileName, prefix) {
            suffix := fileName[len(prefix):]
            if strings.Contains(suffix, "/") { // Only direct children
                continue
            }
            entries = append(entries, &memDirEntry{info: &memFileInfo{f: file}})
        }
    }
    sort.Slice(entries, func(i, j int) bool {
        return entries[i].Name() < entries[j].Name()
    })
    return entries, nil
}

// ... (其他 fs.FS 接口方法的实现，例如 Stat, ReadFile 等)
```

现在，我们可以使用 `fstest.TestFS` 来测试我们的 `MemFS` 实现：

```go
package memfs_test

import (
	"testing"
	"testing/fstest"

	"your_module_path/memfs" // 替换为你的 memfs 模块路径
)

func TestMemFS(t *testing.T) {
	mfs := memfs.New()
	mfs.MkdirAll("dir1", 0755)
	mfs.Create("file1.txt")
	mfs.Create("dir1/file2.txt")

	err := fstest.TestFS(mfs, "file1.txt", "dir1", "dir1/file2.txt")
	if err != nil {
		t.Fatal(err)
	}
}
```

**假设的输入与输出:**

**输入:**

- `fsys`:  我们创建的 `memfs.MemFS` 实例，其中包含以下文件和目录结构:
  ```
  .
  ├── file1.txt
  └── dir1
      └── file2.txt
  ```
- `expected`:  字符串切片 `[]string{"file1.txt", "dir1", "dir1/file2.txt"}`

**输出:**

如果 `memfs` 的实现正确，`fstest.TestFS` 将返回 `nil`，表示测试通过。如果 `memfs` 的实现有错误（例如，`ReadDir` 没有返回 `dir1/file2.txt`，或者 `Open` 无法打开 `file1.txt`），`fstest.TestFS` 将返回一个包含错误信息的 `error` 对象。

**涉及命令行参数的具体处理:**

`fstest.TestFS` 函数本身不直接处理命令行参数。它是一个 Go 语言的测试工具函数，通常在 Go 的测试框架下运行。你可以使用 `go test` 命令来运行包含 `TestMemFS` 函数的测试文件。

例如，在包含 `memfs_test.go` 文件的目录下运行以下命令：

```bash
go test
```

Go 的测试框架会自动发现并执行以 `Test` 开头的函数（例如 `TestMemFS`）。 你可以使用 `go test` 的各种标志来控制测试的执行，例如 `-v` (显示详细输出), `-run` (指定要运行的测试函数) 等。但这些参数是由 `go test` 命令处理的，而不是 `fstest.TestFS`。

**使用者易犯错的点:**

1. **忘记在 `expected` 列表中列出期望存在的文件或目录:** 如果你期望某个文件存在，但没有将其添加到 `expected` 列表中，`TestFS` 并不会报错，因为它只检查 *至少* 存在列表中的文件。 这可能会导致你认为文件系统实现正确，但实际上缺少了一些文件。

   **例如:**

   ```go
   // 假设 memfs 中存在 file1.txt 和 dir1/file2.txt
   err := fstest.TestFS(mfs, "file1.txt") // 忘记列出 "dir1" 和 "dir1/file2.txt"
   if err != nil {
       t.Fatal(err) // 如果 memfs 的基本文件打开功能没问题，这里不会报错，但测试覆盖不完整
   }
   ```

2. **期望 `TestFS` 会自动创建测试文件:** `TestFS` 只是一个测试工具，它不会修改你传入的文件系统。 你需要在调用 `TestFS` 之前，预先在你的文件系统实现中创建好测试所需的文件和目录。

3. **没有正确实现 `fs.FS` 接口的所有方法:** `TestFS` 会调用 `fs.FS` 接口的多个方法（例如 `Open`, `Stat`, `ReadDir` 等）。 如果你的文件系统实现没有正确地实现所有必要的方法，`TestFS` 会报告相应的错误。

4. **并发修改文件系统:** `TestFS` 的文档明确指出，文件系统的内容不应在 `TestFS` 运行期间被并发修改。 这会导致不可预测的测试结果。

总而言之，`fstest.TestFS` 是一个非常有用的工具，可以帮助开发者确保其 `io/fs.FS` 接口的实现是正确且健壮的。 理解其工作原理和常见的错误用法，可以更有效地利用它来提升代码质量。

Prompt: 
```
这是路径为go/src/testing/fstest/testfs.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package fstest implements support for testing implementations and users of file systems.
package fstest

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"
	"testing/iotest"
)

// TestFS tests a file system implementation.
// It walks the entire tree of files in fsys,
// opening and checking that each file behaves correctly.
// It also checks that the file system contains at least the expected files.
// As a special case, if no expected files are listed, fsys must be empty.
// Otherwise, fsys must contain at least the listed files; it can also contain others.
// The contents of fsys must not change concurrently with TestFS.
//
// If TestFS finds any misbehaviors, it returns either the first error or a
// list of errors. Use [errors.Is] or [errors.As] to inspect.
//
// Typical usage inside a test is:
//
//	if err := fstest.TestFS(myFS, "file/that/should/be/present"); err != nil {
//		t.Fatal(err)
//	}
func TestFS(fsys fs.FS, expected ...string) error {
	if err := testFS(fsys, expected...); err != nil {
		return err
	}
	for _, name := range expected {
		if i := strings.Index(name, "/"); i >= 0 {
			dir, dirSlash := name[:i], name[:i+1]
			var subExpected []string
			for _, name := range expected {
				if strings.HasPrefix(name, dirSlash) {
					subExpected = append(subExpected, name[len(dirSlash):])
				}
			}
			sub, err := fs.Sub(fsys, dir)
			if err != nil {
				return err
			}
			if err := testFS(sub, subExpected...); err != nil {
				return fmt.Errorf("testing fs.Sub(fsys, %s): %w", dir, err)
			}
			break // one sub-test is enough
		}
	}
	return nil
}

func testFS(fsys fs.FS, expected ...string) error {
	t := fsTester{fsys: fsys}
	t.checkDir(".")
	t.checkOpen(".")
	found := make(map[string]bool)
	for _, dir := range t.dirs {
		found[dir] = true
	}
	for _, file := range t.files {
		found[file] = true
	}
	delete(found, ".")
	if len(expected) == 0 && len(found) > 0 {
		list := slices.Sorted(maps.Keys(found))
		if len(list) > 15 {
			list = append(list[:10], "...")
		}
		t.errorf("expected empty file system but found files:\n%s", strings.Join(list, "\n"))
	}
	for _, name := range expected {
		if !found[name] {
			t.errorf("expected but not found: %s", name)
		}
	}
	if len(t.errors) == 0 {
		return nil
	}
	return fmt.Errorf("TestFS found errors:\n%w", errors.Join(t.errors...))
}

// An fsTester holds state for running the test.
type fsTester struct {
	fsys   fs.FS
	errors []error
	dirs   []string
	files  []string
}

// errorf adds an error to the list of errors.
func (t *fsTester) errorf(format string, args ...any) {
	t.errors = append(t.errors, fmt.Errorf(format, args...))
}

func (t *fsTester) openDir(dir string) fs.ReadDirFile {
	f, err := t.fsys.Open(dir)
	if err != nil {
		t.errorf("%s: Open: %w", dir, err)
		return nil
	}
	d, ok := f.(fs.ReadDirFile)
	if !ok {
		f.Close()
		t.errorf("%s: Open returned File type %T, not a fs.ReadDirFile", dir, f)
		return nil
	}
	return d
}

// checkDir checks the directory dir, which is expected to exist
// (it is either the root or was found in a directory listing with IsDir true).
func (t *fsTester) checkDir(dir string) {
	// Read entire directory.
	t.dirs = append(t.dirs, dir)
	d := t.openDir(dir)
	if d == nil {
		return
	}
	list, err := d.ReadDir(-1)
	if err != nil {
		d.Close()
		t.errorf("%s: ReadDir(-1): %w", dir, err)
		return
	}

	// Check all children.
	var prefix string
	if dir == "." {
		prefix = ""
	} else {
		prefix = dir + "/"
	}
	for _, info := range list {
		name := info.Name()
		switch {
		case name == ".", name == "..", name == "":
			t.errorf("%s: ReadDir: child has invalid name: %#q", dir, name)
			continue
		case strings.Contains(name, "/"):
			t.errorf("%s: ReadDir: child name contains slash: %#q", dir, name)
			continue
		case strings.Contains(name, `\`):
			t.errorf("%s: ReadDir: child name contains backslash: %#q", dir, name)
			continue
		}
		path := prefix + name
		t.checkStat(path, info)
		t.checkOpen(path)
		if info.IsDir() {
			t.checkDir(path)
		} else {
			t.checkFile(path)
		}
	}

	// Check ReadDir(-1) at EOF.
	list2, err := d.ReadDir(-1)
	if len(list2) > 0 || err != nil {
		d.Close()
		t.errorf("%s: ReadDir(-1) at EOF = %d entries, %w, wanted 0 entries, nil", dir, len(list2), err)
		return
	}

	// Check ReadDir(1) at EOF (different results).
	list2, err = d.ReadDir(1)
	if len(list2) > 0 || err != io.EOF {
		d.Close()
		t.errorf("%s: ReadDir(1) at EOF = %d entries, %w, wanted 0 entries, EOF", dir, len(list2), err)
		return
	}

	// Check that close does not report an error.
	if err := d.Close(); err != nil {
		t.errorf("%s: Close: %w", dir, err)
	}

	// Check that closing twice doesn't crash.
	// The return value doesn't matter.
	d.Close()

	// Reopen directory, read a second time, make sure contents match.
	if d = t.openDir(dir); d == nil {
		return
	}
	defer d.Close()
	list2, err = d.ReadDir(-1)
	if err != nil {
		t.errorf("%s: second Open+ReadDir(-1): %w", dir, err)
		return
	}
	t.checkDirList(dir, "first Open+ReadDir(-1) vs second Open+ReadDir(-1)", list, list2)

	// Reopen directory, read a third time in pieces, make sure contents match.
	if d = t.openDir(dir); d == nil {
		return
	}
	defer d.Close()
	list2 = nil
	for {
		n := 1
		if len(list2) > 0 {
			n = 2
		}
		frag, err := d.ReadDir(n)
		if len(frag) > n {
			t.errorf("%s: third Open: ReadDir(%d) after %d: %d entries (too many)", dir, n, len(list2), len(frag))
			return
		}
		list2 = append(list2, frag...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.errorf("%s: third Open: ReadDir(%d) after %d: %w", dir, n, len(list2), err)
			return
		}
		if n == 0 {
			t.errorf("%s: third Open: ReadDir(%d) after %d: 0 entries but nil error", dir, n, len(list2))
			return
		}
	}
	t.checkDirList(dir, "first Open+ReadDir(-1) vs third Open+ReadDir(1,2) loop", list, list2)

	// If fsys has ReadDir, check that it matches and is sorted.
	if fsys, ok := t.fsys.(fs.ReadDirFS); ok {
		list2, err := fsys.ReadDir(dir)
		if err != nil {
			t.errorf("%s: fsys.ReadDir: %w", dir, err)
			return
		}
		t.checkDirList(dir, "first Open+ReadDir(-1) vs fsys.ReadDir", list, list2)

		for i := 0; i+1 < len(list2); i++ {
			if list2[i].Name() >= list2[i+1].Name() {
				t.errorf("%s: fsys.ReadDir: list not sorted: %s before %s", dir, list2[i].Name(), list2[i+1].Name())
			}
		}
	}

	// Check fs.ReadDir as well.
	list2, err = fs.ReadDir(t.fsys, dir)
	if err != nil {
		t.errorf("%s: fs.ReadDir: %w", dir, err)
		return
	}
	t.checkDirList(dir, "first Open+ReadDir(-1) vs fs.ReadDir", list, list2)

	for i := 0; i+1 < len(list2); i++ {
		if list2[i].Name() >= list2[i+1].Name() {
			t.errorf("%s: fs.ReadDir: list not sorted: %s before %s", dir, list2[i].Name(), list2[i+1].Name())
		}
	}

	t.checkGlob(dir, list2)
}

// formatEntry formats an fs.DirEntry into a string for error messages and comparison.
func formatEntry(entry fs.DirEntry) string {
	return fmt.Sprintf("%s IsDir=%v Type=%v", entry.Name(), entry.IsDir(), entry.Type())
}

// formatInfoEntry formats an fs.FileInfo into a string like the result of formatEntry, for error messages and comparison.
func formatInfoEntry(info fs.FileInfo) string {
	return fmt.Sprintf("%s IsDir=%v Type=%v", info.Name(), info.IsDir(), info.Mode().Type())
}

// formatInfo formats an fs.FileInfo into a string for error messages and comparison.
func formatInfo(info fs.FileInfo) string {
	return fmt.Sprintf("%s IsDir=%v Mode=%v Size=%d ModTime=%v", info.Name(), info.IsDir(), info.Mode(), info.Size(), info.ModTime())
}

// checkGlob checks that various glob patterns work if the file system implements GlobFS.
func (t *fsTester) checkGlob(dir string, list []fs.DirEntry) {
	if _, ok := t.fsys.(fs.GlobFS); !ok {
		return
	}

	// Make a complex glob pattern prefix that only matches dir.
	var glob string
	if dir != "." {
		elem := strings.Split(dir, "/")
		for i, e := range elem {
			var pattern []rune
			for j, r := range e {
				if r == '*' || r == '?' || r == '\\' || r == '[' || r == '-' {
					pattern = append(pattern, '\\', r)
					continue
				}
				switch (i + j) % 5 {
				case 0:
					pattern = append(pattern, r)
				case 1:
					pattern = append(pattern, '[', r, ']')
				case 2:
					pattern = append(pattern, '[', r, '-', r, ']')
				case 3:
					pattern = append(pattern, '[', '\\', r, ']')
				case 4:
					pattern = append(pattern, '[', '\\', r, '-', '\\', r, ']')
				}
			}
			elem[i] = string(pattern)
		}
		glob = strings.Join(elem, "/") + "/"
	}

	// Test that malformed patterns are detected.
	// The error is likely path.ErrBadPattern but need not be.
	if _, err := t.fsys.(fs.GlobFS).Glob(glob + "nonexist/[]"); err == nil {
		t.errorf("%s: Glob(%#q): bad pattern not detected", dir, glob+"nonexist/[]")
	}

	// Try to find a letter that appears in only some of the final names.
	c := rune('a')
	for ; c <= 'z'; c++ {
		have, haveNot := false, false
		for _, d := range list {
			if strings.ContainsRune(d.Name(), c) {
				have = true
			} else {
				haveNot = true
			}
		}
		if have && haveNot {
			break
		}
	}
	if c > 'z' {
		c = 'a'
	}
	glob += "*" + string(c) + "*"

	var want []string
	for _, d := range list {
		if strings.ContainsRune(d.Name(), c) {
			want = append(want, path.Join(dir, d.Name()))
		}
	}

	names, err := t.fsys.(fs.GlobFS).Glob(glob)
	if err != nil {
		t.errorf("%s: Glob(%#q): %w", dir, glob, err)
		return
	}
	if slices.Equal(want, names) {
		return
	}

	if !slices.IsSorted(names) {
		t.errorf("%s: Glob(%#q): unsorted output:\n%s", dir, glob, strings.Join(names, "\n"))
		slices.Sort(names)
	}

	var problems []string
	for len(want) > 0 || len(names) > 0 {
		switch {
		case len(want) > 0 && len(names) > 0 && want[0] == names[0]:
			want, names = want[1:], names[1:]
		case len(want) > 0 && (len(names) == 0 || want[0] < names[0]):
			problems = append(problems, "missing: "+want[0])
			want = want[1:]
		default:
			problems = append(problems, "extra: "+names[0])
			names = names[1:]
		}
	}
	t.errorf("%s: Glob(%#q): wrong output:\n%s", dir, glob, strings.Join(problems, "\n"))
}

// checkStat checks that a direct stat of path matches entry,
// which was found in the parent's directory listing.
func (t *fsTester) checkStat(path string, entry fs.DirEntry) {
	file, err := t.fsys.Open(path)
	if err != nil {
		t.errorf("%s: Open: %w", path, err)
		return
	}
	info, err := file.Stat()
	file.Close()
	if err != nil {
		t.errorf("%s: Stat: %w", path, err)
		return
	}
	fentry := formatEntry(entry)
	fientry := formatInfoEntry(info)
	// Note: mismatch here is OK for symlink, because Open dereferences symlink.
	if fentry != fientry && entry.Type()&fs.ModeSymlink == 0 {
		t.errorf("%s: mismatch:\n\tentry = %s\n\tfile.Stat() = %s", path, fentry, fientry)
	}

	einfo, err := entry.Info()
	if err != nil {
		t.errorf("%s: entry.Info: %w", path, err)
		return
	}
	finfo := formatInfo(info)
	if entry.Type()&fs.ModeSymlink != 0 {
		// For symlink, just check that entry.Info matches entry on common fields.
		// Open deferences symlink, so info itself may differ.
		feentry := formatInfoEntry(einfo)
		if fentry != feentry {
			t.errorf("%s: mismatch\n\tentry = %s\n\tentry.Info() = %s\n", path, fentry, feentry)
		}
	} else {
		feinfo := formatInfo(einfo)
		if feinfo != finfo {
			t.errorf("%s: mismatch:\n\tentry.Info() = %s\n\tfile.Stat() = %s\n", path, feinfo, finfo)
		}
	}

	// Stat should be the same as Open+Stat, even for symlinks.
	info2, err := fs.Stat(t.fsys, path)
	if err != nil {
		t.errorf("%s: fs.Stat: %w", path, err)
		return
	}
	finfo2 := formatInfo(info2)
	if finfo2 != finfo {
		t.errorf("%s: fs.Stat(...) = %s\n\twant %s", path, finfo2, finfo)
	}

	if fsys, ok := t.fsys.(fs.StatFS); ok {
		info2, err := fsys.Stat(path)
		if err != nil {
			t.errorf("%s: fsys.Stat: %w", path, err)
			return
		}
		finfo2 := formatInfo(info2)
		if finfo2 != finfo {
			t.errorf("%s: fsys.Stat(...) = %s\n\twant %s", path, finfo2, finfo)
		}
	}
}

// checkDirList checks that two directory lists contain the same files and file info.
// The order of the lists need not match.
func (t *fsTester) checkDirList(dir, desc string, list1, list2 []fs.DirEntry) {
	old := make(map[string]fs.DirEntry)
	checkMode := func(entry fs.DirEntry) {
		if entry.IsDir() != (entry.Type()&fs.ModeDir != 0) {
			if entry.IsDir() {
				t.errorf("%s: ReadDir returned %s with IsDir() = true, Type() & ModeDir = 0", dir, entry.Name())
			} else {
				t.errorf("%s: ReadDir returned %s with IsDir() = false, Type() & ModeDir = ModeDir", dir, entry.Name())
			}
		}
	}

	for _, entry1 := range list1 {
		old[entry1.Name()] = entry1
		checkMode(entry1)
	}

	var diffs []string
	for _, entry2 := range list2 {
		entry1 := old[entry2.Name()]
		if entry1 == nil {
			checkMode(entry2)
			diffs = append(diffs, "+ "+formatEntry(entry2))
			continue
		}
		if formatEntry(entry1) != formatEntry(entry2) {
			diffs = append(diffs, "- "+formatEntry(entry1), "+ "+formatEntry(entry2))
		}
		delete(old, entry2.Name())
	}
	for _, entry1 := range old {
		diffs = append(diffs, "- "+formatEntry(entry1))
	}

	if len(diffs) == 0 {
		return
	}

	slices.SortFunc(diffs, func(a, b string) int {
		fa := strings.Fields(a)
		fb := strings.Fields(b)
		// sort by name (i < j) and then +/- (j < i, because + < -)
		return strings.Compare(fa[1]+" "+fb[0], fb[1]+" "+fa[0])
	})

	t.errorf("%s: diff %s:\n\t%s", dir, desc, strings.Join(diffs, "\n\t"))
}

// checkFile checks that basic file reading works correctly.
func (t *fsTester) checkFile(file string) {
	t.files = append(t.files, file)

	// Read entire file.
	f, err := t.fsys.Open(file)
	if err != nil {
		t.errorf("%s: Open: %w", file, err)
		return
	}

	data, err := io.ReadAll(f)
	if err != nil {
		f.Close()
		t.errorf("%s: Open+ReadAll: %w", file, err)
		return
	}

	if err := f.Close(); err != nil {
		t.errorf("%s: Close: %w", file, err)
	}

	// Check that closing twice doesn't crash.
	// The return value doesn't matter.
	f.Close()

	// Check that ReadFile works if present.
	if fsys, ok := t.fsys.(fs.ReadFileFS); ok {
		data2, err := fsys.ReadFile(file)
		if err != nil {
			t.errorf("%s: fsys.ReadFile: %w", file, err)
			return
		}
		t.checkFileRead(file, "ReadAll vs fsys.ReadFile", data, data2)

		// Modify the data and check it again. Modifying the
		// returned byte slice should not affect the next call.
		for i := range data2 {
			data2[i]++
		}
		data2, err = fsys.ReadFile(file)
		if err != nil {
			t.errorf("%s: second call to fsys.ReadFile: %w", file, err)
			return
		}
		t.checkFileRead(file, "Readall vs second fsys.ReadFile", data, data2)

		t.checkBadPath(file, "ReadFile",
			func(name string) error { _, err := fsys.ReadFile(name); return err })
	}

	// Check that fs.ReadFile works with t.fsys.
	data2, err := fs.ReadFile(t.fsys, file)
	if err != nil {
		t.errorf("%s: fs.ReadFile: %w", file, err)
		return
	}
	t.checkFileRead(file, "ReadAll vs fs.ReadFile", data, data2)

	// Use iotest.TestReader to check small reads, Seek, ReadAt.
	f, err = t.fsys.Open(file)
	if err != nil {
		t.errorf("%s: second Open: %w", file, err)
		return
	}
	defer f.Close()
	if err := iotest.TestReader(f, data); err != nil {
		t.errorf("%s: failed TestReader:\n\t%s", file, strings.ReplaceAll(err.Error(), "\n", "\n\t"))
	}
}

func (t *fsTester) checkFileRead(file, desc string, data1, data2 []byte) {
	if string(data1) != string(data2) {
		t.errorf("%s: %s: different data returned\n\t%q\n\t%q", file, desc, data1, data2)
		return
	}
}

// checkBadPath checks that various invalid forms of file's name cannot be opened using t.fsys.Open.
func (t *fsTester) checkOpen(file string) {
	t.checkBadPath(file, "Open", func(file string) error {
		f, err := t.fsys.Open(file)
		if err == nil {
			f.Close()
		}
		return err
	})
}

// checkBadPath checks that various invalid forms of file's name cannot be opened using open.
func (t *fsTester) checkBadPath(file string, desc string, open func(string) error) {
	bad := []string{
		"/" + file,
		file + "/.",
	}
	if file == "." {
		bad = append(bad, "/")
	}
	if i := strings.Index(file, "/"); i >= 0 {
		bad = append(bad,
			file[:i]+"//"+file[i+1:],
			file[:i]+"/./"+file[i+1:],
			file[:i]+`\`+file[i+1:],
			file[:i]+"/../"+file,
		)
	}
	if i := strings.LastIndex(file, "/"); i >= 0 {
		bad = append(bad,
			file[:i]+"//"+file[i+1:],
			file[:i]+"/./"+file[i+1:],
			file[:i]+`\`+file[i+1:],
			file+"/../"+file[i+1:],
		)
	}

	for _, b := range bad {
		if err := open(b); err == nil {
			t.errorf("%s: %s(%s) succeeded, want error", file, desc, b)
		}
	}
}

"""



```