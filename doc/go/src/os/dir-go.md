Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The request asks for the functionality of the provided Go code, its purpose within the broader Go language, examples, handling of command-line arguments (if any), potential pitfalls, and all in Chinese.

2. **Initial Code Scan (Keywords and Structure):**  I immediately look for keywords like `package os`, function names like `Readdir`, `Readdirnames`, `ReadDir`, `CopyFS`, and type definitions like `readdirMode` and `DirEntry`. The structure suggests that this code deals with directory operations within the `os` package. The comments are also valuable hints.

3. **Function-by-Function Analysis:** I'll go through each function individually.

    * **`readdirMode` and Constants:**  These seem like internal flags for the `readdir` function. They indicate different modes of retrieving directory information.

    * **`Readdir(n int) ([]FileInfo, error)`:**
        * **Purpose:** Reads directory contents and returns `FileInfo` structs.
        * **Parameter `n`:**  Controls the number of entries to read. Positive `n` reads up to `n`, zero or negative reads all.
        * **Return Values:** A slice of `FileInfo` and an error.
        * **Key Behaviors:** Handles `n > 0` and `n <= 0` cases differently regarding error returns. It explicitly mentions returning an empty slice (not `nil`) for historical reasons.
        * **Internal Call:**  Calls `f.readdir(n, readdirFileInfo)`. This strongly suggests a shared underlying implementation.

    * **`Readdirnames(n int) ([]string, error)`:**
        * **Purpose:** Reads directory contents and returns only the names of the files/directories.
        * **Parameter `n`:** Same as `Readdir`.
        * **Return Values:** A slice of strings (filenames) and an error.
        * **Key Behaviors:** Similar error handling to `Readdir`, including the empty slice behavior.
        * **Internal Call:** Calls `f.readdir(n, readdirName)`. Again, points to shared logic.

    * **`DirEntry = fs.DirEntry`:**  This is a type alias, meaning `DirEntry` is just another name for `fs.DirEntry`. This tells me the code leverages the `io/fs` package for a more general file system abstraction.

    * **`ReadDir(n int) ([]DirEntry, error)` (on `*File`)**:
        * **Purpose:** Reads directory contents and returns `DirEntry` structs.
        * **Parameter `n`:** Same as the other `Read` functions.
        * **Return Values:** A slice of `DirEntry` and an error.
        * **Key Behaviors:**  Similar error handling. Mentions returning an error *explaining why* when `n > 0` and the slice is empty.
        * **Internal Call:** Calls `f.readdir(n, readdirDirEntry)`.

    * **`testingForceReadDirLstat bool`:** This is clearly for internal testing purposes. It forces a specific code path in `ReadDir`. I should mention this as a testing-related detail.

    * **`ReadDir(name string) ([]DirEntry, error)` (top-level function):**
        * **Purpose:** Reads a named directory and returns sorted `DirEntry` structs.
        * **Parameter `name`:** The path to the directory.
        * **Key Behaviors:** Opens the directory using `openDir`, reads all entries using `f.ReadDir(-1)`, sorts them by name using `slices.SortFunc`, and then returns.
        * **Error Handling:** Returns entries read so far along with the error.

    * **`CopyFS(dir string, fsys fs.FS) error`:**
        * **Purpose:** Copies a file system into a directory.
        * **Parameters:** `dir` is the destination directory, `fsys` is the source file system (an `fs.FS` interface).
        * **Key Behaviors:** Uses `fs.WalkDir` to traverse the source. Creates directories using `MkdirAll`. Creates files using `OpenFile` with `O_CREATE|O_EXCL|O_WRONLY` (important for preventing overwrites). Copies file contents using `io.Copy`. Explicitly mentions handling symbolic links (or the lack thereof, noting it's not supported *yet* with a TODO).
        * **Error Handling:** Returns the first error encountered. Specifically mentions `fs.ErrExist` for existing files.

4. **Inferring the Broader Go Functionality:** Based on the function names and types, it's clear this code provides fundamental directory reading and manipulation capabilities within Go's `os` package. It builds on lower-level operating system calls (implicitly, though not shown in this snippet). The introduction of `fs.DirEntry` and `fs.FS` suggests alignment with Go's more recent focus on abstracting file systems.

5. **Code Examples:** For each major function, I'll create a simple example demonstrating its usage. I need to consider:
    * **Input:**  What are the parameters?  What kind of data is needed?
    * **Expected Output:** What should the function return?  What does a successful operation look like?  What do errors look like?
    * **Error Handling:**  Demonstrate how to check for errors.

6. **Command-Line Arguments:**  I carefully reviewed the code. None of the functions directly process command-line arguments. The `ReadDir(name string)` function takes a path string, which could *come from* command-line arguments, but the code itself doesn't handle the parsing. Therefore, the answer here is that the provided snippet doesn't directly deal with command-line arguments.

7. **Common Mistakes:** I think about common scenarios where developers might misuse these functions:
    * **Ignoring Errors:**  Forgetting to check the error return value.
    * **Assuming Sorted Order (early versions of `Readdir`):** While the standalone `ReadDir` now sorts, older versions of `Readdir` didn't guarantee order. The current snippet's `Readdir` and `Readdirnames` mention "directory order," which isn't necessarily alphabetical.
    * **Not Handling `n > 0` Correctly:**  Forgetting that with a positive `n`, an empty slice doesn't always mean the end of the directory, but rather that the limit was reached.
    * **Overwriting Files with `CopyFS`:** The code explicitly prevents this, but it's a common mistake in file copying operations in general. Highlighting this *prevention* is important.
    * **Misunderstanding `DirEntry` vs. `FileInfo`:** Emphasize that `DirEntry` is lighter and generally preferred for performance.

8. **Language and Formatting:** The request specifies Chinese output. I need to translate the explanations, code comments, and examples accordingly. Using clear and concise language is important. Code snippets should be formatted for readability.

9. **Review and Refine:** Before submitting the answer, I'll reread the original request and my generated response to ensure it addresses all points accurately and completely. I'll double-check the code examples and make sure they are correct and illustrative.

This systematic approach, breaking down the problem into smaller, manageable parts, helps to ensure a comprehensive and accurate response. The focus on understanding the purpose, behavior, and potential pitfalls of each function is key.
这段代码是 Go 语言 `os` 标准库中 `dir.go` 文件的一部分，主要负责提供**读取目录内容**的功能。它定义了几个用于读取目录的函数，并提供了一种复制文件系统的方式。

下面详细列举其功能，并用 Go 代码举例说明：

**1. 读取目录内容并返回 `FileInfo` 切片 (`Readdir`)**

* **功能:**  `Readdir` 方法用于读取与 `File` 结构体关联的目录内容，并返回一个包含 `FileInfo` 接口值的切片。`FileInfo` 接口提供了关于文件或目录的元数据信息，例如名称、大小、修改时间、权限等，类似于 `Lstat` 的返回值。
* **参数 `n` 的作用:**
    * 如果 `n > 0`，`Readdir` 最多返回 `n` 个 `FileInfo` 结构。如果在读取到 `n` 个条目之前到达目录末尾，它将返回已读取的条目和一个 `io.EOF` 错误。如果返回一个空切片，则会返回一个非 `nil` 的错误，说明原因。
    * 如果 `n <= 0`，`Readdir` 将返回目录中的所有 `FileInfo` 结构。如果成功读取到目录末尾，它将返回包含所有条目的切片和一个 `nil` 错误。如果在读取过程中遇到错误，它将返回已读取的条目和一个非 `nil` 的错误。
* **实现细节:** 内部调用了 `f.readdir(n, readdirFileInfo)`，这表明实际的读取逻辑可能在 `readdir` 方法中实现。
* **Go 代码示例:**

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	dirName := "test_dir" // 假设存在一个名为 test_dir 的目录

	// 创建一个测试目录
	os.Mkdir(dirName, 0755)
	os.Create(dirName + "/file1.txt")
	os.Mkdir(dirName+"/subdir", 0755)

	f, err := os.Open(dirName)
	if err != nil {
		fmt.Println("打开目录失败:", err)
		return
	}
	defer f.Close()

	// 读取所有文件信息
	fileInfos, err := f.Readdir(-1)
	if err != nil {
		fmt.Println("读取目录失败:", err)
		return
	}

	fmt.Println("目录内容:")
	for _, info := range fileInfos {
		fmt.Printf("  %s (IsDir: %t, Size: %d bytes)\n", info.Name(), info.IsDir(), info.Size())
	}

	// 读取前两个文件信息
	f.Seek(0, 0) // 重置目录读取位置
	fileInfosLimited, err := f.Readdir(2)
	if err != nil && err != io.EOF { // io.EOF 表示已到达目录末尾
		fmt.Println("读取部分目录失败:", err)
		return
	}

	fmt.Println("\n前两个目录条目:")
	for _, info := range fileInfosLimited {
		fmt.Printf("  %s\n", info.Name())
	}

	// 清理测试目录
	os.RemoveAll(dirName)
}

// 假设的输出 (目录顺序可能不同):
// 目录内容:
//   file1.txt (IsDir: false, Size: 0 bytes)
//   subdir (IsDir: true, Size: 4096 bytes)

// 前两个目录条目:
//   file1.txt
//   subdir
```

**2. 读取目录内容并返回文件名切片 (`Readdirnames`)**

* **功能:** `Readdirnames` 方法用于读取与 `File` 结构体关联的目录内容，并返回一个包含目录中文件名的字符串切片。
* **参数 `n` 的作用:**  与 `Readdir` 方法中的 `n` 参数作用相同，用于控制返回的文件名数量。
* **实现细节:** 内部调用了 `f.readdir(n, readdirName)`。
* **Go 代码示例:**

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	dirName := "test_dir_names"
	os.Mkdir(dirName, 0755)
	os.Create(dirName + "/file_a.txt")
	os.Create(dirName + "/file_b.txt")

	f, err := os.Open(dirName)
	if err != nil {
		fmt.Println("打开目录失败:", err)
		return
	}
	defer f.Close()

	// 读取所有文件名
	names, err := f.Readdirnames(-1)
	if err != nil {
		fmt.Println("读取目录名失败:", err)
		return
	}

	fmt.Println("目录中的文件名:")
	for _, name := range names {
		fmt.Println(" ", name)
	}

	// 读取前一个文件名
	f.Seek(0, 0)
	firstNames, err := f.Readdirnames(1)
	if err != nil && err != io.EOF {
		fmt.Println("读取部分目录名失败:", err)
		return
	}
	fmt.Println("\n前一个文件名:", firstNames)

	os.RemoveAll(dirName)
}

// 假设的输出 (目录顺序可能不同):
// 目录中的文件名:
//   file_a.txt
//   file_b.txt

// 前一个文件名: [file_a.txt]
```

**3. 读取目录内容并返回 `DirEntry` 切片 (`ReadDir` on `*File`)**

* **功能:** `ReadDir` 方法（作用于 `*File` 类型）用于读取目录内容，并返回一个包含 `DirEntry` 接口值的切片。`DirEntry` 接口是 `io/fs` 包中定义的，提供了更轻量级的目录条目信息，通常比 `FileInfo` 更高效。
* **参数 `n` 的作用:** 与 `Readdir` 和 `Readdirnames` 类似。
* **实现细节:** 内部调用了 `f.readdir(n, readdirDirEntry)`。
* **Go 代码示例:**

```go
package main

import (
	"fmt"
	"io"
	"os"
	"io/fs"
)

func main() {
	dirName := "test_dir_direntry"
	os.Mkdir(dirName, 0755)
	os.Create(dirName + "/doc.pdf")
	os.Mkdir(dirName+"/images", 0755)

	f, err := os.Open(dirName)
	if err != nil {
		fmt.Println("打开目录失败:", err)
		return
	}
	defer f.Close()

	// 读取所有 DirEntry
	dirEntries, err := f.ReadDir(-1)
	if err != nil {
		fmt.Println("读取目录条目失败:", err)
		return
	}

	fmt.Println("目录条目:")
	for _, entry := range dirEntries {
		fmt.Printf("  %s (IsDir: %t, Type: %s)\n", entry.Name(), entry.IsDir(), entry.Type())
	}

	// 读取前一个 DirEntry
	f.Seek(0, 0)
	firstEntry, err := f.ReadDir(1)
	if err != nil && err != io.EOF {
		fmt.Println("读取部分目录条目失败:", err)
		return
	}
	fmt.Println("\n前一个目录条目:", firstEntry[0].Name())

	os.RemoveAll(dirName)
}

// 假设的输出 (目录顺序可能不同):
// 目录条目:
//   doc.pdf (IsDir: false, Type: -)
//   images (IsDir: true, Type: d)

// 前一个目录条目: doc.pdf
```

**4. 读取指定名称的目录并返回排序后的 `DirEntry` 切片 (`ReadDir` 函数)**

* **功能:** `ReadDir` 函数（顶级函数）用于读取指定名称的目录，并返回一个包含排序后的 `DirEntry` 接口值的切片。它会对读取到的目录条目按文件名进行排序。
* **参数 `name`:**  要读取的目录的路径字符串。
* **实现细节:**
    1. 使用 `openDir(name)` 打开目录。
    2. 调用 `f.ReadDir(-1)` 读取所有目录条目。
    3. 使用 `slices.SortFunc` 对 `DirEntry` 切片按文件名进行排序。
* **Go 代码示例:**

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	dirName := "test_dir_sorted"
	os.Mkdir(dirName, 0755)
	os.Create(dirName + "/zebra.txt")
	os.Create(dirName + "/apple.txt")
	os.Create(dirName + "/banana.txt")

	// 读取并排序目录条目
	dirEntries, err := os.ReadDir(dirName)
	if err != nil {
		fmt.Println("读取目录失败:", err)
		return
	}

	fmt.Println("排序后的目录条目:")
	for _, entry := range dirEntries {
		fmt.Println(" ", entry.Name())
	}

	os.RemoveAll(dirName)
}

// 假设的输出:
// 排序后的目录条目:
//   apple.txt
//   banana.txt
//   zebra.txt
```

**5. 强制 `ReadDir` 调用 `Lstat` 进行测试 (`testingForceReadDirLstat`)**

* **功能:**  这是一个用于测试的全局变量。当设置为 `true` 时，会强制 `ReadDir` 方法在内部调用 `Lstat` 来获取文件信息。这通常用于测试特定的代码路径，在某些 Unix 系统上，不设置此变量很难触发该代码路径。这与用户通常的使用场景无关。

**6. 复制文件系统 (`CopyFS`)**

* **功能:** `CopyFS` 函数将一个文件系统 (`fs.FS` 接口表示) 的内容复制到指定的目录。如果目标目录不存在，它会创建该目录。
* **参数:**
    * `dir`:  目标目录的路径。
    * `fsys`:  要复制的源文件系统，实现了 `fs.FS` 接口。
* **行为:**
    * 文件以 `0o666` 加上源文件的执行权限创建。
    * 目录以 `0o777` 权限创建（受 `umask` 影响）。
    * 不会覆盖已存在的文件。如果目标目录中已存在同名文件，会返回一个 `fs.ErrExist` 错误。
    * **不支持符号链接。** 尝试复制符号链接会返回一个 `ErrInvalid` 错误。
    * 目标目录中的符号链接会被**跟随**，即复制到符号链接指向的实际位置。
    * 复制过程遇到第一个错误会停止并返回该错误。
* **实现细节:** 使用 `fs.WalkDir` 遍历源文件系统，并根据条目的类型创建文件或目录。
* **Go 代码示例 (需要一个实现了 `fs.FS` 接口的源文件系统):**

```go
package main

import (
	"fmt"
	"os"
	"os/fs"
	"path/filepath"
	"testing/fstest"
)

func main() {
	destDir := "copied_fs"

	// 创建一个内存文件系统作为源
	sourceFS := fstest.MapFS{
		"file1.txt": &fstest.MapFile{Data: []byte("内容 1")},
		"subdir/file2.txt": &fstest.MapFile{Data: []byte("内容 2")},
	}

	err := os.CopyFS(destDir, sourceFS)
	if err != nil {
		fmt.Println("复制文件系统失败:", err)
		return
	}

	fmt.Println("文件系统复制成功！")

	// 验证文件是否被复制
	content1, _ := os.ReadFile(filepath.Join(destDir, "file1.txt"))
	fmt.Println("file1.txt 内容:", string(content1))

	content2, _ := os.ReadFile(filepath.Join(destDir, "subdir", "file2.txt"))
	fmt.Println("subdir/file2.txt 内容:", string(content2))

	os.RemoveAll(destDir)
}

// 假设的输出:
// 文件系统复制成功！
// file1.txt 内容: 内容 1
// subdir/file2.txt 内容: 内容 2
```

**涉及代码推理的假设输入与输出:**

上面的代码示例已经包含了假设的输入（例如，创建的目录和文件）以及预期的输出。这些示例展示了在特定条件下，各个函数应该如何工作。

**命令行参数的具体处理:**

这段代码本身**不直接处理命令行参数**。它提供的功能是底层的文件和目录操作，通常会被更上层的应用程序或工具使用，而这些应用程序或工具会负责解析命令行参数。例如，一个用于列出目录内容的命令行工具可能会使用 `os.ReadDir` 函数，并通过 `flag` 包或其他方式来处理用户提供的目录路径参数。

**使用者易犯错的点:**

1. **忽略错误处理:**  调用 `Readdir`, `Readdirnames`, `ReadDir`, `CopyFS` 等函数时，务必检查返回的 `error` 值。忽略错误可能导致程序行为异常甚至崩溃。

   ```go
   // 错误的做法
   files, _ := os.ReadDir("mydir") // 没有检查错误

   // 正确的做法
   files, err := os.ReadDir("mydir")
   if err != nil {
       fmt.Println("读取目录出错:", err)
       return
   }
   ```

2. **混淆 `Readdir` 和 `ReadDir` 的返回值:** `Readdir` 返回 `FileInfo` 切片，提供更详细的文件元数据；而 `ReadDir` 返回 `DirEntry` 切片，更轻量级，通常更高效。根据需求选择合适的函数。

3. **不理解 `Readdir` 的 `n` 参数:**  特别是当 `n > 0` 时，如果返回的切片长度小于 `n`，并不一定意味着到达了目录末尾。需要检查返回的 `error` 是否为 `io.EOF`。

4. **假设 `Readdir` 和 `Readdirnames` 返回排序后的结果:**  在 `os` 包的这个实现中，`Readdir` 和 `Readdirnames` 返回的条目顺序是**目录顺序**，不一定是按文件名排序的。如果需要排序后的结果，应该使用顶级的 `os.ReadDir` 函数，它会进行排序。

5. **在 `CopyFS` 中期望支持符号链接的复制:** `CopyFS` 函数明确指出不支持复制符号链接。使用者需要了解这一点，如果需要处理符号链接，可能需要自定义实现或使用其他工具。

总而言之，`go/src/os/dir.go` 这部分代码提供了核心的目录读取和操作功能，是 Go 语言进行文件系统交互的基础组成部分。理解其各个函数的作用、参数和潜在的错误情况，对于编写健壮的 Go 程序至关重要。

Prompt: 
```
这是路径为go/src/os/dir.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package os

import (
	"internal/bytealg"
	"internal/filepathlite"
	"io"
	"io/fs"
	"slices"
)

type readdirMode int

const (
	readdirName readdirMode = iota
	readdirDirEntry
	readdirFileInfo
)

// Readdir reads the contents of the directory associated with file and
// returns a slice of up to n [FileInfo] values, as would be returned
// by [Lstat], in directory order. Subsequent calls on the same file will yield
// further FileInfos.
//
// If n > 0, Readdir returns at most n FileInfo structures. In this case, if
// Readdir returns an empty slice, it will return a non-nil error
// explaining why. At the end of a directory, the error is [io.EOF].
//
// If n <= 0, Readdir returns all the FileInfo from the directory in
// a single slice. In this case, if Readdir succeeds (reads all
// the way to the end of the directory), it returns the slice and a
// nil error. If it encounters an error before the end of the
// directory, Readdir returns the FileInfo read until that point
// and a non-nil error.
//
// Most clients are better served by the more efficient ReadDir method.
func (f *File) Readdir(n int) ([]FileInfo, error) {
	if f == nil {
		return nil, ErrInvalid
	}
	_, _, infos, err := f.readdir(n, readdirFileInfo)
	if infos == nil {
		// Readdir has historically always returned a non-nil empty slice, never nil,
		// even on error (except misuse with nil receiver above).
		// Keep it that way to avoid breaking overly sensitive callers.
		infos = []FileInfo{}
	}
	return infos, err
}

// Readdirnames reads the contents of the directory associated with file
// and returns a slice of up to n names of files in the directory,
// in directory order. Subsequent calls on the same file will yield
// further names.
//
// If n > 0, Readdirnames returns at most n names. In this case, if
// Readdirnames returns an empty slice, it will return a non-nil error
// explaining why. At the end of a directory, the error is [io.EOF].
//
// If n <= 0, Readdirnames returns all the names from the directory in
// a single slice. In this case, if Readdirnames succeeds (reads all
// the way to the end of the directory), it returns the slice and a
// nil error. If it encounters an error before the end of the
// directory, Readdirnames returns the names read until that point and
// a non-nil error.
func (f *File) Readdirnames(n int) (names []string, err error) {
	if f == nil {
		return nil, ErrInvalid
	}
	names, _, _, err = f.readdir(n, readdirName)
	if names == nil {
		// Readdirnames has historically always returned a non-nil empty slice, never nil,
		// even on error (except misuse with nil receiver above).
		// Keep it that way to avoid breaking overly sensitive callers.
		names = []string{}
	}
	return names, err
}

// A DirEntry is an entry read from a directory
// (using the [ReadDir] function or a [File.ReadDir] method).
type DirEntry = fs.DirEntry

// ReadDir reads the contents of the directory associated with the file f
// and returns a slice of [DirEntry] values in directory order.
// Subsequent calls on the same file will yield later DirEntry records in the directory.
//
// If n > 0, ReadDir returns at most n DirEntry records.
// In this case, if ReadDir returns an empty slice, it will return an error explaining why.
// At the end of a directory, the error is [io.EOF].
//
// If n <= 0, ReadDir returns all the DirEntry records remaining in the directory.
// When it succeeds, it returns a nil error (not io.EOF).
func (f *File) ReadDir(n int) ([]DirEntry, error) {
	if f == nil {
		return nil, ErrInvalid
	}
	_, dirents, _, err := f.readdir(n, readdirDirEntry)
	if dirents == nil {
		// Match Readdir and Readdirnames: don't return nil slices.
		dirents = []DirEntry{}
	}
	return dirents, err
}

// testingForceReadDirLstat forces ReadDir to call Lstat, for testing that code path.
// This can be difficult to provoke on some Unix systems otherwise.
var testingForceReadDirLstat bool

// ReadDir reads the named directory,
// returning all its directory entries sorted by filename.
// If an error occurs reading the directory,
// ReadDir returns the entries it was able to read before the error,
// along with the error.
func ReadDir(name string) ([]DirEntry, error) {
	f, err := openDir(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	dirs, err := f.ReadDir(-1)
	slices.SortFunc(dirs, func(a, b DirEntry) int {
		return bytealg.CompareString(a.Name(), b.Name())
	})
	return dirs, err
}

// CopyFS copies the file system fsys into the directory dir,
// creating dir if necessary.
//
// Files are created with mode 0o666 plus any execute permissions
// from the source, and directories are created with mode 0o777
// (before umask).
//
// CopyFS will not overwrite existing files. If a file name in fsys
// already exists in the destination, CopyFS will return an error
// such that errors.Is(err, fs.ErrExist) will be true.
//
// Symbolic links in fsys are not supported. A *PathError with Err set
// to ErrInvalid is returned when copying from a symbolic link.
//
// Symbolic links in dir are followed.
//
// Copying stops at and returns the first error encountered.
func CopyFS(dir string, fsys fs.FS) error {
	return fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		fpath, err := filepathlite.Localize(path)
		if err != nil {
			return err
		}
		newPath := joinPath(dir, fpath)
		if d.IsDir() {
			return MkdirAll(newPath, 0777)
		}

		// TODO(panjf2000): handle symlinks with the help of fs.ReadLinkFS
		// 		once https://go.dev/issue/49580 is done.
		//		we also need filepathlite.IsLocal from https://go.dev/cl/564295.
		if !d.Type().IsRegular() {
			return &PathError{Op: "CopyFS", Path: path, Err: ErrInvalid}
		}

		r, err := fsys.Open(path)
		if err != nil {
			return err
		}
		defer r.Close()
		info, err := r.Stat()
		if err != nil {
			return err
		}
		w, err := OpenFile(newPath, O_CREATE|O_EXCL|O_WRONLY, 0666|info.Mode()&0777)
		if err != nil {
			return err
		}

		if _, err := io.Copy(w, r); err != nil {
			w.Close()
			return &PathError{Op: "Copy", Path: newPath, Err: err}
		}
		return w.Close()
	})
}

"""



```