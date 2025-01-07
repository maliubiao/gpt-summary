Response:
Let's break down the thought process for analyzing the `embed.go` file.

**1. Understanding the Core Purpose:**

The first thing to do is read the package comment. It clearly states the core purpose: providing access to files embedded within the Go program using the `//go:embed` directive. This immediately tells us this code isn't about file I/O at *runtime* in the traditional sense, but rather about a *compile-time* process.

**2. Identifying Key Data Structures:**

The next step is to look for the primary data structures. The `FS` struct stands out immediately. The comment inside it is crucial: "The compiler knows the layout of this struct." This confirms the compile-time aspect and hints at how the data is populated. The `files` field, a pointer to a slice of `file` structs, is the central storage.

The `file` struct itself is also important. It stores the `name`, `data`, and `hash` of an embedded file. The `name` comment explains the sorting order, which is a significant implementation detail.

**3. Tracing the Functionality:**

Now, we examine the methods associated with `FS` and `file`. Think about how you'd interact with an embedded file system. You'd want to:

* **Open a file:**  The `Open` method is the entry point here. It uses `lookup` to find the file and then returns either an `openFile` or `openDir`.
* **Read a directory:**  `ReadDir` and the internal `readDir` are responsible for listing directory contents. The sorting explained in the `FS` struct comment is clearly relevant here.
* **Read a file's content:** `ReadFile` provides this functionality.
* **Get file information:**  The `file` struct implements `fs.FileInfo` and `fs.DirEntry`, providing methods like `Name`, `Size`, `IsDir`, etc.

**4. Connecting the Dots to the `//go:embed` Directive:**

The package comment extensively explains the `//go:embed` directive. We need to connect how the code implements the behavior described. The key points from the comment are:

* **Directives initialize variables:**  The examples show how `//go:embed` populates `string`, `[]byte`, and `embed.FS` variables.
* **Patterns:** The directive uses `path.Match` patterns. The code doesn't explicitly implement the pattern matching, suggesting that's handled by the Go compiler. The documentation does explain the pattern syntax.
* **Constraints:** The limitations on patterns (no `.` or `..`, etc.) are important to note.
* **Strings and Bytes:** The single-file constraint for `string` and `[]byte` variables is a key difference.
* **File System Interface:** The `FS` type implements `io/fs.FS`, enabling integration with other standard Go packages.

**5. Inferring the Compiler's Role:**

Based on the comments within the `FS` struct and the overall functionality, we can infer that the Go compiler (`cmd/compile/internal/staticdata's WriteEmbed`) plays a crucial role:

* **Parsing the `//go:embed` directives:**  The compiler must identify these directives and extract the patterns.
* **Matching files:** The compiler must implement the pattern matching logic.
* **Populating the `FS` struct:**  The compiler is responsible for creating the `files` slice within the `FS` struct with the correct data from the matched files. The sorting order is likely enforced during this process.
* **Populating `string` and `[]byte` variables:** For these types, the compiler directly embeds the file content into the variable's memory.

**6. Considering Edge Cases and Potential Errors:**

Think about how a user might misuse this feature:

* **Incorrect `//go:embed` syntax:**  Putting the directive in the wrong place, having extra lines, etc.
* **Invalid patterns:** Using `.` or `..`, starting or ending with a slash, or using disallowed characters.
* **Matching no files:**  A pattern that doesn't match anything.
* **Multiple patterns for string/[]byte:**  Violating the single-pattern rule.
* **Trying to embed things outside the module:** Security constraint.

**7. Structuring the Answer:**

Finally, organize the findings into a clear and comprehensive answer, addressing the prompt's specific requests:

* **List the functionality:** Summarize the capabilities of the `embed` package.
* **Infer the Go language feature:** Explain that it's a compile-time mechanism for embedding files.
* **Provide Go code examples:** Illustrate the different ways to use `//go:embed`.
* **Explain code reasoning:** Connect the code's structure and methods to the described functionality. Highlight the compiler's role.
* **Discuss command-line arguments:** Since this is a compile-time feature, there aren't direct command-line arguments *for the embed package itself*. However, the `go build` command triggers the embedding process.
* **Highlight common mistakes:**  List potential pitfalls for users.

This systematic approach, starting with understanding the high-level purpose and then drilling down into the code and its interactions with the compiler, helps to analyze and explain the functionality of the `embed` package effectively.
这段代码是 Go 语言的 `embed` 包的一部分，它提供了一种在编译时将文件嵌入到 Go 可执行文件中的机制。以下是它的功能及其背后的 Go 语言特性：

**功能列举：**

1. **声明 `FS` 类型:** 定义了一个名为 `FS` 的结构体，它代表一个只读的文件集合。这个类型实现了 `io/fs` 包中的 `FS` 接口，使得嵌入的文件系统可以像普通的文件系统一样被操作。
2. **使用 `//go:embed` 指令:**  允许开发者在 Go 源代码中使用 `//go:embed` 指令，将指定的文件或目录的内容嵌入到 `string`、`[]byte` 或 `embed.FS` 类型的变量中。
3. **支持多种嵌入目标类型:**  可以将嵌入的内容赋值给 `string` (单个文件内容), `[]byte` (单个文件内容)，或 `embed.FS` (多个文件或目录的树状结构)。
4. **支持模式匹配:** `//go:embed` 指令支持使用 `path.Match` 风格的模式匹配来选择要嵌入的文件。可以指定单个文件、目录或使用通配符匹配多个文件。
5. **目录递归嵌入:** 如果模式匹配到一个目录，该目录下的所有文件（除了以 `.` 或 `_` 开头的文件）都会被递归地嵌入。
6. **`all:` 前缀:** 提供了 `all:` 前缀，可以包含以 `.` 或 `_` 开头的文件。
7. **与标准库集成:**  `embed.FS` 实现了 `io/fs.FS` 接口，可以无缝地与 `net/http`、`text/template`、`html/template` 等标准库中需要文件系统抽象的包一起使用。
8. **提供文件元数据:** 嵌入的 `file` 结构体实现了 `fs.FileInfo` 和 `fs.DirEntry` 接口，提供了文件名、大小、修改时间、是否为目录等信息。
9. **提供文件读取功能:** `FS` 类型提供了 `Open`、`ReadDir` 和 `ReadFile` 方法，用于打开、读取目录和读取嵌入文件的内容。

**实现的 Go 语言功能 (推断):**

这部分功能的实现依赖于 Go 编译器的特殊处理。`//go:embed` 指令是 Go 编译器识别和处理的特殊指令。编译器会在编译时读取匹配到的文件内容，并将这些内容以某种形式（很可能是在链接阶段）嵌入到最终的可执行文件中。

**Go 代码示例说明:**

假设在 `go/src/embed/` 目录下有以下文件：

* `hello.txt` (内容: "Hello, world!\n")
* `static/image.png` (一个图片文件)
* `static/index.html` (一个 HTML 文件)

```go
package main

import (
	_ "embed"
	"fmt"
	"net/http"
	"text/template"
)

//go:embed hello.txt
var helloString string

//go:embed hello.txt
var helloBytes []byte

//go:embed static/*
var staticFS embed.FS

func main() {
	fmt.Println("Embedded string:", helloString)
	fmt.Println("Embedded bytes:", string(helloBytes))

	// 使用 embed.FS 提供静态文件服务
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	// 使用 embed.FS 解析模板
	tmpl, err := template.ParseFS(staticFS, "index.html")
	if err != nil {
		fmt.Println("Error parsing template:", err)
		return
	}
	// 假设你有一个 http.ResponseWriter 'w'
	// tmpl.Execute(w, nil)

	fmt.Println("Server listening on :8080")
	http.ListenAndServe(":8080", nil)
}
```

**假设的输入与输出:**

* **输入 (编译时):**
    * `hello.txt` 文件内容: "Hello, world!\n"
    * `static/image.png` 文件内容 (二进制数据)
    * `static/index.html` 文件内容 (HTML 代码)
    * 上述 Go 源代码

* **输出 (运行时):**
    * 运行程序后，控制台输出：
        ```
        Embedded string: Hello, world!

        Embedded bytes: Hello, world!
        Server listening on :8080
        ```
    * 访问 `http://localhost:8080/static/image.png` 将会显示 `static/image.png` 的内容。
    * 访问 `http://localhost:8080/static/index.html` (如果模板执行成功) 将会渲染 `static/index.html` 的内容。

**命令行参数的具体处理:**

`embed` 包本身并没有直接处理命令行参数。它的工作机制是在 Go 编译过程中由 Go 编译器 (`go build`) 完成的。

当 `go build` 命令遇到包含 `//go:embed` 指令的代码时，它会：

1. **解析 `//go:embed` 指令:**  识别指令后面的模式字符串。
2. **匹配文件:**  根据模式字符串，在包的源代码目录下查找匹配的文件和目录。
3. **读取文件内容:** 读取匹配到的文件的内容。
4. **生成嵌入数据:** 将读取到的文件内容和元数据以特定的格式编码，并存储在编译后的可执行文件中。这部分具体实现是在 Go 编译器的内部完成的，例如 `cmd/compile/internal/staticdata` 包可能参与了这个过程。
5. **初始化变量:**  在程序运行时，被 `//go:embed` 修饰的变量会被初始化为嵌入的数据。对于 `embed.FS` 类型的变量，会创建一个 `FS` 结构体，其内部的 `files` 字段会指向嵌入的文件列表和内容。

**使用者易犯错的点:**

1. **`//go:embed` 指令的位置错误:**  指令必须紧邻着变量声明，中间只能有空行或 `//` 注释。

   ```go
   // 错误示例
   // 这里有额外的代码
   //go:embed my_file.txt
   var content string

   // 正确示例
   //go:embed my_file.txt
   var content string
   ```

2. **模式匹配错误:**
   * 使用了不允许的字符或路径（如 `.`、`..`、空路径元素、开头或结尾的斜杠）。
   * 模式没有匹配到任何文件或非空目录，导致编译失败。
   * 尝试匹配模块外部的文件（如 `.git/*`, `vendor/` 或包含 `go.mod` 的目录）。

   ```go
   // 错误示例：使用了 ..
   //go:embed ../other_file.txt
   var content string

   // 错误示例：模式没有匹配到任何文件
   //go:embed non_existent_file.txt
   var content string
   ```

3. **`string` 或 `[]byte` 类型嵌入多个文件:**  当目标变量类型为 `string` 或 `[]byte` 时，`//go:embed` 指令只能匹配一个文件。

   ```go
   // 错误示例
   //go:embed file1.txt file2.txt
   var combined string
   ```

4. **忘记导入 `embed` 包:**  即使不直接使用 `embed.FS`，如果使用了 `//go:embed` 指令，也需要在代码中导入 `embed` 包（可以使用空白导入 `import _ "embed"`）。

   ```go
   // 错误示例 (缺少导入)
   //go:embed my_file.txt
   var content string

   func main() {
       println(content)
   }

   // 正确示例
   import _ "embed"

   //go:embed my_file.txt
   var content string

   func main() {
       println(content)
   }
   ```

5. **混淆运行时文件系统操作和嵌入的文件系统:**  `embed.FS` 提供的是编译时嵌入的只读文件系统。不能使用 `os` 包中的函数（如 `os.Open`）直接操作嵌入的文件，反之亦然。需要使用 `embed.FS` 提供的 `Open`、`ReadFile` 等方法。

总而言之，`go/src/embed/embed.go` 定义了 Go 语言中嵌入文件功能的核心类型和接口，而具体的嵌入过程是由 Go 编译器在编译时完成的。开发者通过使用 `//go:embed` 指令可以方便地将静态资源打包到可执行文件中，简化部署和分发。

Prompt: 
```
这是路径为go/src/embed/embed.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package embed provides access to files embedded in the running Go program.
//
// Go source files that import "embed" can use the //go:embed directive
// to initialize a variable of type string, []byte, or [FS] with the contents of
// files read from the package directory or subdirectories at compile time.
//
// For example, here are three ways to embed a file named hello.txt
// and then print its contents at run time.
//
// Embedding one file into a string:
//
//	import _ "embed"
//
//	//go:embed hello.txt
//	var s string
//	print(s)
//
// Embedding one file into a slice of bytes:
//
//	import _ "embed"
//
//	//go:embed hello.txt
//	var b []byte
//	print(string(b))
//
// Embedded one or more files into a file system:
//
//	import "embed"
//
//	//go:embed hello.txt
//	var f embed.FS
//	data, _ := f.ReadFile("hello.txt")
//	print(string(data))
//
// # Directives
//
// A //go:embed directive above a variable declaration specifies which files to embed,
// using one or more path.Match patterns.
//
// The directive must immediately precede a line containing the declaration of a single variable.
// Only blank lines and ‘//’ line comments are permitted between the directive and the declaration.
//
// The type of the variable must be a string type, or a slice of a byte type,
// or [FS] (or an alias of [FS]).
//
// For example:
//
//	package server
//
//	import "embed"
//
//	// content holds our static web server content.
//	//go:embed image/* template/*
//	//go:embed html/index.html
//	var content embed.FS
//
// The Go build system will recognize the directives and arrange for the declared variable
// (in the example above, content) to be populated with the matching files from the file system.
//
// The //go:embed directive accepts multiple space-separated patterns for
// brevity, but it can also be repeated, to avoid very long lines when there are
// many patterns. The patterns are interpreted relative to the package directory
// containing the source file. The path separator is a forward slash, even on
// Windows systems. Patterns may not contain ‘.’ or ‘..’ or empty path elements,
// nor may they begin or end with a slash. To match everything in the current
// directory, use ‘*’ instead of ‘.’. To allow for naming files with spaces in
// their names, patterns can be written as Go double-quoted or back-quoted
// string literals.
//
// If a pattern names a directory, all files in the subtree rooted at that directory are
// embedded (recursively), except that files with names beginning with ‘.’ or ‘_’
// are excluded. So the variable in the above example is almost equivalent to:
//
//	// content is our static web server content.
//	//go:embed image template html/index.html
//	var content embed.FS
//
// The difference is that ‘image/*’ embeds ‘image/.tempfile’ while ‘image’ does not.
// Neither embeds ‘image/dir/.tempfile’.
//
// If a pattern begins with the prefix ‘all:’, then the rule for walking directories is changed
// to include those files beginning with ‘.’ or ‘_’. For example, ‘all:image’ embeds
// both ‘image/.tempfile’ and ‘image/dir/.tempfile’.
//
// The //go:embed directive can be used with both exported and unexported variables,
// depending on whether the package wants to make the data available to other packages.
// It can only be used with variables at package scope, not with local variables.
//
// Patterns must not match files outside the package's module, such as ‘.git/*’, symbolic links,
// 'vendor/', or any directories containing go.mod (these are separate modules).
// Patterns must not match files whose names include the special punctuation characters  " * < > ? ` ' | / \ and :.
// Matches for empty directories are ignored. After that, each pattern in a //go:embed line
// must match at least one file or non-empty directory.
//
// If any patterns are invalid or have invalid matches, the build will fail.
//
// # Strings and Bytes
//
// The //go:embed line for a variable of type string or []byte can have only a single pattern,
// and that pattern can match only a single file. The string or []byte is initialized with
// the contents of that file.
//
// The //go:embed directive requires importing "embed", even when using a string or []byte.
// In source files that don't refer to [embed.FS], use a blank import (import _ "embed").
//
// # File Systems
//
// For embedding a single file, a variable of type string or []byte is often best.
// The [FS] type enables embedding a tree of files, such as a directory of static
// web server content, as in the example above.
//
// FS implements the [io/fs] package's [FS] interface, so it can be used with any package that
// understands file systems, including [net/http], [text/template], and [html/template].
//
// For example, given the content variable in the example above, we can write:
//
//	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(content))))
//
//	template.ParseFS(content, "*.tmpl")
//
// # Tools
//
// To support tools that analyze Go packages, the patterns found in //go:embed lines
// are available in “go list” output. See the EmbedPatterns, TestEmbedPatterns,
// and XTestEmbedPatterns fields in the “go help list” output.
package embed

import (
	"errors"
	"internal/bytealg"
	"internal/stringslite"
	"io"
	"io/fs"
	"time"
)

// An FS is a read-only collection of files, usually initialized with a //go:embed directive.
// When declared without a //go:embed directive, an FS is an empty file system.
//
// An FS is a read-only value, so it is safe to use from multiple goroutines
// simultaneously and also safe to assign values of type FS to each other.
//
// FS implements fs.FS, so it can be used with any package that understands
// file system interfaces, including net/http, text/template, and html/template.
//
// See the package documentation for more details about initializing an FS.
type FS struct {
	// The compiler knows the layout of this struct.
	// See cmd/compile/internal/staticdata's WriteEmbed.
	//
	// The files list is sorted by name but not by simple string comparison.
	// Instead, each file's name takes the form "dir/elem" or "dir/elem/".
	// The optional trailing slash indicates that the file is itself a directory.
	// The files list is sorted first by dir (if dir is missing, it is taken to be ".")
	// and then by base, so this list of files:
	//
	//	p
	//	q/
	//	q/r
	//	q/s/
	//	q/s/t
	//	q/s/u
	//	q/v
	//	w
	//
	// is actually sorted as:
	//
	//	p       # dir=.    elem=p
	//	q/      # dir=.    elem=q
	//	w       # dir=.    elem=w
	//	q/r     # dir=q    elem=r
	//	q/s/    # dir=q    elem=s
	//	q/v     # dir=q    elem=v
	//	q/s/t   # dir=q/s  elem=t
	//	q/s/u   # dir=q/s  elem=u
	//
	// This order brings directory contents together in contiguous sections
	// of the list, allowing a directory read to use binary search to find
	// the relevant sequence of entries.
	files *[]file
}

// split splits the name into dir and elem as described in the
// comment in the FS struct above. isDir reports whether the
// final trailing slash was present, indicating that name is a directory.
func split(name string) (dir, elem string, isDir bool) {
	name, isDir = stringslite.CutSuffix(name, "/")
	i := bytealg.LastIndexByteString(name, '/')
	if i < 0 {
		return ".", name, isDir
	}
	return name[:i], name[i+1:], isDir
}

var (
	_ fs.ReadDirFS  = FS{}
	_ fs.ReadFileFS = FS{}
)

// A file is a single file in the FS.
// It implements fs.FileInfo and fs.DirEntry.
type file struct {
	// The compiler knows the layout of this struct.
	// See cmd/compile/internal/staticdata's WriteEmbed.
	name string
	data string
	hash [16]byte // truncated SHA256 hash
}

var (
	_ fs.FileInfo = (*file)(nil)
	_ fs.DirEntry = (*file)(nil)
)

func (f *file) Name() string               { _, elem, _ := split(f.name); return elem }
func (f *file) Size() int64                { return int64(len(f.data)) }
func (f *file) ModTime() time.Time         { return time.Time{} }
func (f *file) IsDir() bool                { _, _, isDir := split(f.name); return isDir }
func (f *file) Sys() any                   { return nil }
func (f *file) Type() fs.FileMode          { return f.Mode().Type() }
func (f *file) Info() (fs.FileInfo, error) { return f, nil }

func (f *file) Mode() fs.FileMode {
	if f.IsDir() {
		return fs.ModeDir | 0555
	}
	return 0444
}

func (f *file) String() string {
	return fs.FormatFileInfo(f)
}

// dotFile is a file for the root directory,
// which is omitted from the files list in a FS.
var dotFile = &file{name: "./"}

// lookup returns the named file, or nil if it is not present.
func (f FS) lookup(name string) *file {
	if !fs.ValidPath(name) {
		// The compiler should never emit a file with an invalid name,
		// so this check is not strictly necessary (if name is invalid,
		// we shouldn't find a match below), but it's a good backstop anyway.
		return nil
	}
	if name == "." {
		return dotFile
	}
	if f.files == nil {
		return nil
	}

	// Binary search to find where name would be in the list,
	// and then check if name is at that position.
	dir, elem, _ := split(name)
	files := *f.files
	i := sortSearch(len(files), func(i int) bool {
		idir, ielem, _ := split(files[i].name)
		return idir > dir || idir == dir && ielem >= elem
	})
	if i < len(files) && stringslite.TrimSuffix(files[i].name, "/") == name {
		return &files[i]
	}
	return nil
}

// readDir returns the list of files corresponding to the directory dir.
func (f FS) readDir(dir string) []file {
	if f.files == nil {
		return nil
	}
	// Binary search to find where dir starts and ends in the list
	// and then return that slice of the list.
	files := *f.files
	i := sortSearch(len(files), func(i int) bool {
		idir, _, _ := split(files[i].name)
		return idir >= dir
	})
	j := sortSearch(len(files), func(j int) bool {
		jdir, _, _ := split(files[j].name)
		return jdir > dir
	})
	return files[i:j]
}

// Open opens the named file for reading and returns it as an [fs.File].
//
// The returned file implements [io.Seeker] and [io.ReaderAt] when the file is not a directory.
func (f FS) Open(name string) (fs.File, error) {
	file := f.lookup(name)
	if file == nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	if file.IsDir() {
		return &openDir{file, f.readDir(name), 0}, nil
	}
	return &openFile{file, 0}, nil
}

// ReadDir reads and returns the entire named directory.
func (f FS) ReadDir(name string) ([]fs.DirEntry, error) {
	file, err := f.Open(name)
	if err != nil {
		return nil, err
	}
	dir, ok := file.(*openDir)
	if !ok {
		return nil, &fs.PathError{Op: "read", Path: name, Err: errors.New("not a directory")}
	}
	list := make([]fs.DirEntry, len(dir.files))
	for i := range list {
		list[i] = &dir.files[i]
	}
	return list, nil
}

// ReadFile reads and returns the content of the named file.
func (f FS) ReadFile(name string) ([]byte, error) {
	file, err := f.Open(name)
	if err != nil {
		return nil, err
	}
	ofile, ok := file.(*openFile)
	if !ok {
		return nil, &fs.PathError{Op: "read", Path: name, Err: errors.New("is a directory")}
	}
	return []byte(ofile.f.data), nil
}

// An openFile is a regular file open for reading.
type openFile struct {
	f      *file // the file itself
	offset int64 // current read offset
}

var (
	_ io.Seeker   = (*openFile)(nil)
	_ io.ReaderAt = (*openFile)(nil)
)

func (f *openFile) Close() error               { return nil }
func (f *openFile) Stat() (fs.FileInfo, error) { return f.f, nil }

func (f *openFile) Read(b []byte) (int, error) {
	if f.offset >= int64(len(f.f.data)) {
		return 0, io.EOF
	}
	if f.offset < 0 {
		return 0, &fs.PathError{Op: "read", Path: f.f.name, Err: fs.ErrInvalid}
	}
	n := copy(b, f.f.data[f.offset:])
	f.offset += int64(n)
	return n, nil
}

func (f *openFile) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case 0:
		// offset += 0
	case 1:
		offset += f.offset
	case 2:
		offset += int64(len(f.f.data))
	}
	if offset < 0 || offset > int64(len(f.f.data)) {
		return 0, &fs.PathError{Op: "seek", Path: f.f.name, Err: fs.ErrInvalid}
	}
	f.offset = offset
	return offset, nil
}

func (f *openFile) ReadAt(b []byte, offset int64) (int, error) {
	if offset < 0 || offset > int64(len(f.f.data)) {
		return 0, &fs.PathError{Op: "read", Path: f.f.name, Err: fs.ErrInvalid}
	}
	n := copy(b, f.f.data[offset:])
	if n < len(b) {
		return n, io.EOF
	}
	return n, nil
}

// An openDir is a directory open for reading.
type openDir struct {
	f      *file  // the directory file itself
	files  []file // the directory contents
	offset int    // the read offset, an index into the files slice
}

func (d *openDir) Close() error               { return nil }
func (d *openDir) Stat() (fs.FileInfo, error) { return d.f, nil }

func (d *openDir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.f.name, Err: errors.New("is a directory")}
}

func (d *openDir) ReadDir(count int) ([]fs.DirEntry, error) {
	n := len(d.files) - d.offset
	if n == 0 {
		if count <= 0 {
			return nil, nil
		}
		return nil, io.EOF
	}
	if count > 0 && n > count {
		n = count
	}
	list := make([]fs.DirEntry, n)
	for i := range list {
		list[i] = &d.files[d.offset+i]
	}
	d.offset += n
	return list, nil
}

// sortSearch is like sort.Search, avoiding an import.
func sortSearch(n int, f func(int) bool) int {
	// Define f(-1) == false and f(n) == true.
	// Invariant: f(i-1) == false, f(j) == true.
	i, j := 0, n
	for i < j {
		h := int(uint(i+j) >> 1) // avoid overflow when computing h
		// i ≤ h < j
		if !f(h) {
			i = h + 1 // preserves f(i-1) == false
		} else {
			j = h // preserves f(j) == true
		}
	}
	// i == j, f(i-1) == false, and f(j) (= f(i)) == true  =>  answer is i.
	return i
}

"""



```