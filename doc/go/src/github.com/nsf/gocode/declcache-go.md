Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding - What is the Core Purpose?**

The filename `declcache.go` and the presence of structures like `decl_file_cache` and `decl_cache` strongly suggest this code is about caching declarations found in Go source files. The "cache" part is key. Why cache?  Presumably for performance, to avoid repeatedly parsing the same files.

**2. Deconstructing Key Structures and Functions:**

* **`package_import`:**  This is straightforward. It holds information about imported packages: alias, absolute path, and the import path itself.

* **`collect_package_imports`:** This function clearly parses the import statements in a file's AST and populates the `package_import` slice. The loop breaks on the first non-import declaration, which makes sense. Imports should be at the beginning of a file.

* **`decl_file_cache`:** This is the central piece for a *single file*. It stores:
    * `name`: The filename.
    * `mtime`: Modification time for cache invalidation.
    * `decls`: The core cache - a map of top-level declaration names to their information (`*decl`). We don't see the `decl` struct here, but we can infer its purpose.
    * `error`: For storing parsing errors.
    * `packages`: The import information we just saw.
    * `filescope`: A scope for the file (likely related to symbol resolution).
    * `fset`: A `token.FileSet` used during parsing.
    * `context`: A `package_lookup_context` (more on this later).

* **`new_decl_file_cache`:**  A simple constructor.

* **`update`:** This is the cache invalidation logic. It checks the file's modification time. If it hasn't changed, the cache is valid. Otherwise, it calls `read_file`.

* **`read_file`:** Reads the file contents and calls `process_data`.

* **`process_data`:**  The heart of the parsing process. It:
    * Parses the file using `parser.ParseFile`.
    * Creates a new scope.
    * Calls `anonymify_ast` (we don't see this, but it probably manipulates the AST).
    * Calls `collect_package_imports`.
    * Iterates through the declarations and calls `append_to_top_decls`.

* **`append_to_top_decls`:** This function seems to extract declaration information and store it in the `decls` map. It handles both regular declarations and method declarations.

* **`abs_path_for_package`:**  Crucial for resolving import paths to actual file paths. It handles:
    * Relative imports (`.`).
    * Lookups in a "godag" structure.
    * Calls `find_global_file` for other imports.

* **`path_and_alias`:** Extracts the import path and alias from an `ast.ImportSpec`.

* **`find_go_dag_package`:**  Specific logic for a "godag" directory structure.

* **`autobuild` and `build_package`:**  This is interesting! The code tries to automatically rebuild a package if its source files are newer than the compiled `.a` file. It uses `go install`.

* **`find_global_file`:** This is where the tool looks for compiled package files (`.a`). It checks:
    * Special case for "unsafe".
    * `LibPath` configuration.
    * "gb" and "bzl" specific lookup modes.
    * Vendor directories.
    * Standard Go package paths (using `context.Import`).

* **`package_lookup_context`:** This struct holds the build environment information: `GOROOT`, `GOPATH`, `GOOS`, `GOARCH`, and project-specific roots ("bzl" and "gb"). It provides helper functions like `gopath` and `pkg_dirs`.

* **`decl_cache`:** This is the *global* cache, holding `decl_file_cache` instances for multiple files. It uses a mutex for thread safety.

* **`new_decl_cache`:** Constructor for the global cache.

* **`get` and `get_and_update`:** Methods to retrieve and update file caches in the global cache.

**3. Inferring the Go Feature:**

Given that this code caches declarations and resolves import paths, the most likely Go feature this implements is **code completion/IntelliSense** or a similar code analysis tool. It needs to quickly access information about packages and their exported symbols to provide suggestions as the user types.

**4. Code Example (Illustrative):**

To demonstrate the import resolution, I'd create a simple example with two files and a dependency. This helps solidify understanding.

**5. Command-Line Arguments:**

The code mentions `g_config` and flags like `g_debug` and `Autobuild`. This strongly indicates command-line arguments are used to configure the behavior. I'd look for where these flags are defined and how they influence the logic.

**6. Common Mistakes:**

Thinking about how users might misuse this, incorrect `GOPATH` settings or problems with the build environment are likely culprits.

**7. Structuring the Answer:**

Finally, organize the findings logically:

* Start with a high-level overview of the functionality.
* Explain the core structures and their roles.
* Connect it to the probable Go feature (code completion).
* Provide a code example.
* Discuss command-line arguments.
* Point out potential user errors.

This systematic approach, breaking down the code into manageable parts and then putting the pieces back together, allows for a comprehensive understanding of the provided snippet. The iterative process of examining structures, functions, and their interactions is crucial for deducing the overall purpose.
这段代码是 Go 语言工具 `gocode` 的一部分，主要负责**缓存 Go 源代码文件中声明的顶层声明（例如，变量、函数、类型等）以及它们导入的包信息**。 这样做的目的是为了在代码补全等功能中，能够快速地检索和利用这些信息，而无需每次都重新解析源代码。

**功能列表:**

1. **解析 Go 源代码文件:**  读取 Go 源代码文件的内容，并使用 `go/parser` 包将其解析成抽象语法树 (AST)。
2. **提取顶层声明:** 从 AST 中提取出顶层的声明信息，例如变量名、函数名、类型名等。
3. **缓存声明信息:** 将提取出的顶层声明信息存储在内存中，使用 `decl_file_cache` 结构体来表示单个文件的缓存。
4. **管理包导入:** 识别源代码文件中的 `import` 声明，并解析出导入包的路径和别名。
5. **查找导入包的绝对路径:**  根据导入的路径，在 `$GOPATH`、`$GOROOT` 以及可能的项目特定路径（如 gb 和 bazel 项目）中查找已编译的包文件 (`.a` 文件)。
6. **自动构建依赖包 (可选):** 如果配置了 `Autobuild` 选项，并且导入的包的源代码比已编译的包文件新，则会自动尝试构建该包。
7. **缓存管理:** 提供 `decl_cache` 结构体，用于管理多个 `decl_file_cache` 实例，并使用互斥锁 (`sync.Mutex`) 来保证线程安全。
8. **根据文件修改时间更新缓存:**  在访问缓存时，会检查文件的修改时间，如果文件已更改，则会重新读取和解析该文件。

**推理出的 Go 语言功能实现：代码补全 (Code Completion) / 智能提示 (IntelliSense)**

`gocode` 是一个独立的守护进程，编辑器或 IDE 可以通过它来获取代码补全的建议。 当用户在编辑器中输入代码时，编辑器会将当前的文件内容和光标位置发送给 `gocode`。 `gocode` 会使用其缓存的声明信息来推断用户想要输入的内容，并返回补全建议。

**Go 代码举例说明:**

假设我们有以下两个 Go 文件：

**`a.go`:**

```go
package mypackage

// MyVariable is a variable.
var MyVariable int

// MyFunc is a function.
func MyFunc() string {
	return "hello"
}
```

**`b.go`:**

```go
package main

import "fmt"
import "mypackage"

func main() {
	mypackage. // 在这里输入 . 触发代码补全
}
```

**假设的输入与输出 (当在 `b.go` 的注释位置输入 `.`)：**

**输入 (模拟编辑器发送给 gocode 的请求):**

* `filename`: `b.go`
* `cursor_position`:  `b.go` 中 `mypackage.` 后的位置

**`gocode` 的处理过程 (简化):**

1. `gocode` 接收到请求，查找 `b.go` 的 `decl_file_cache`。
2. 如果 `b.go` 的缓存不存在或已过期，则读取并解析 `b.go`。
3. 解析 `b.go` 的 import 声明，找到 `mypackage` 的导入。
4. 调用 `abs_path_for_package` 查找 `mypackage` 的绝对路径，假设找到了 `.../mypackage.a`。
5. 查找或创建 `mypackage` 对应源代码文件（例如 `a.go`）的 `decl_file_cache`。
6. 如果 `a.go` 的缓存不存在或已过期，则读取并解析 `a.go`。
7. 从 `a.go` 的缓存中提取出公开的声明 (以大写字母开头)，例如 `MyVariable` 和 `MyFunc`。

**输出 (gocode 返回给编辑器的补全建议):**

```
[
  { "class": "variable", "name": "MyVariable", "type": "int" },
  { "class": "func", "name": "MyFunc", "type": "func() string" }
]
```

编辑器会根据这些建议，显示 `MyVariable` 和 `MyFunc` 作为 `mypackage.` 后的补全选项。

**代码推理:**

* **`collect_package_imports` 函数:**  负责解析 `b.go` 中的 `import "mypackage"` 声明，提取出包的路径 `mypackage`。
* **`abs_path_for_package` 函数:**  根据 `mypackage` 查找对应的 `.a` 文件或源代码文件，这涉及到在 `$GOPATH` 等路径下搜索。
* **`decl_file_cache` 结构体 (针对 `a.go`)**: 存储了 `a.go` 中 `MyVariable` 和 `MyFunc` 的声明信息。
* **`decl_cache` 结构体:** 存储了 `b.go` 和 `a.go` 的 `decl_file_cache` 实例，以便快速访问。

**涉及的命令行参数的具体处理:**

虽然这段代码本身没有直接处理命令行参数，但它依赖于全局变量 `g_config` 和 `g_debug`，这些变量通常会在 `gocode` 的主程序中通过 `flag` 包来解析命令行参数。

常见的 `gocode` 命令行参数可能包括：

* **`-s|--server`:**  启动 `gocode` 守护进程。
* **`-cgopath`:**  设置用于查找包的 `GOPATH`。
* **`-cgoroot`:**  设置用于查找包的 `GOROOT`。
* **`-lib-path`:**  指定额外的库文件路径。
* **`-debug`:**  启用调试输出。
* **`-package-lookup-mode`:**  设置包查找模式 (例如 "go", "gb", "bzl")。
* **`-autobuild`:**  启用自动构建依赖包的功能。

这些参数会影响 `package_lookup_context` 的构建，进而影响 `find_global_file` 函数查找包的方式。 例如，如果设置了 `-cgopath`，`gocode` 会使用指定的路径来搜索导入的包。 如果启用了 `-autobuild`，`try_autobuild` 函数会被调用，尝试构建过期的依赖包。

**使用者易犯错的点:**

1. **`GOPATH` 设置不正确:**  `gocode` 依赖于正确的 `GOPATH` 环境变量来查找第三方包。 如果 `GOPATH` 未设置或设置错误，`gocode` 将无法找到相应的包，导致代码补全不完整或报错。

   **例如:**  如果你的项目位于 `$HOME/myproject`，并且你使用 `go mod` 管理依赖，但你没有将 `$HOME/myproject` 添加到 `GOPATH` 中，`gocode` 可能无法正确识别你的项目依赖。

2. **依赖包未安装或编译:** 如果代码中导入的包尚未通过 `go install` 或其他方式安装或编译，`gocode` 可能无法找到其 `.a` 文件，从而无法提供关于该包的补全信息。

   **例如:**  你新添加了一个依赖到 `go.mod` 文件中，但还没有运行 `go mod tidy` 或 `go build` 来下载和编译该依赖，此时 `gocode` 可能无法补全该依赖包的符号。

3. **使用了不兼容的 `package-lookup-mode`:**  对于使用特定构建工具（如 gb 或 bazel）的项目，需要设置正确的 `package-lookup-mode`。 如果模式设置错误，`gocode` 可能无法按照项目特定的结构查找依赖包。

   **例如:**  如果你正在使用一个 gb 项目，但 `package-lookup-mode` 仍然是默认的 "go"，`gocode` 可能无法找到 gb 项目中构建生成的包文件。

总而言之，这段代码是 `gocode` 工具的核心组成部分，负责高效地缓存和管理 Go 代码的声明和导入信息，为代码补全等功能提供基础支持。 理解其工作原理有助于我们更好地配置和使用 `gocode`，避免常见的错误。

Prompt: 
```
这是路径为go/src/github.com/nsf/gocode/declcache.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package main

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

//-------------------------------------------------------------------------
// []package_import
//-------------------------------------------------------------------------

type package_import struct {
	alias   string
	abspath string
	path    string
}

// Parses import declarations until the first non-import declaration and fills
// `packages` array with import information.
func collect_package_imports(filename string, decls []ast.Decl, context *package_lookup_context) []package_import {
	pi := make([]package_import, 0, 16)
	for _, decl := range decls {
		if gd, ok := decl.(*ast.GenDecl); ok && gd.Tok == token.IMPORT {
			for _, spec := range gd.Specs {
				imp := spec.(*ast.ImportSpec)
				path, alias := path_and_alias(imp)
				abspath, ok := abs_path_for_package(filename, path, context)
				if ok && alias != "_" {
					pi = append(pi, package_import{alias, abspath, path})
				}
			}
		} else {
			break
		}
	}
	return pi
}

//-------------------------------------------------------------------------
// decl_file_cache
//
// Contains cache for top-level declarations of a file as well as its
// contents, AST and import information.
//-------------------------------------------------------------------------

type decl_file_cache struct {
	name  string // file name
	mtime int64  // last modification time

	decls     map[string]*decl // top-level declarations
	error     error            // last error
	packages  []package_import // import information
	filescope *scope

	fset    *token.FileSet
	context *package_lookup_context
}

func new_decl_file_cache(name string, context *package_lookup_context) *decl_file_cache {
	return &decl_file_cache{
		name:    name,
		context: context,
	}
}

func (f *decl_file_cache) update() {
	stat, err := os.Stat(f.name)
	if err != nil {
		f.decls = nil
		f.error = err
		f.fset = nil
		return
	}

	statmtime := stat.ModTime().UnixNano()
	if f.mtime == statmtime {
		return
	}

	f.mtime = statmtime
	f.read_file()
}

func (f *decl_file_cache) read_file() {
	var data []byte
	data, f.error = file_reader.read_file(f.name)
	if f.error != nil {
		return
	}
	data, _ = filter_out_shebang(data)

	f.process_data(data)
}

func (f *decl_file_cache) process_data(data []byte) {
	var file *ast.File
	f.fset = token.NewFileSet()
	file, f.error = parser.ParseFile(f.fset, "", data, 0)
	f.filescope = new_scope(nil)
	for _, d := range file.Decls {
		anonymify_ast(d, 0, f.filescope)
	}
	f.packages = collect_package_imports(f.name, file.Decls, f.context)
	f.decls = make(map[string]*decl, len(file.Decls))
	for _, decl := range file.Decls {
		append_to_top_decls(f.decls, decl, f.filescope)
	}
}

func append_to_top_decls(decls map[string]*decl, decl ast.Decl, scope *scope) {
	foreach_decl(decl, func(data *foreach_decl_struct) {
		class := ast_decl_class(data.decl)
		for i, name := range data.names {
			typ, v, vi := data.type_value_index(i)

			d := new_decl_full(name.Name, class, ast_decl_flags(data.decl), typ, v, vi, scope)
			if d == nil {
				return
			}

			methodof := method_of(decl)
			if methodof != "" {
				decl, ok := decls[methodof]
				if ok {
					decl.add_child(d)
				} else {
					decl = new_decl(methodof, decl_methods_stub, scope)
					decls[methodof] = decl
					decl.add_child(d)
				}
			} else {
				decl, ok := decls[d.name]
				if ok {
					decl.expand_or_replace(d)
				} else {
					decls[d.name] = d
				}
			}
		}
	})
}

func abs_path_for_package(filename, p string, context *package_lookup_context) (string, bool) {
	dir, _ := filepath.Split(filename)
	if len(p) == 0 {
		return "", false
	}
	if p[0] == '.' {
		return fmt.Sprintf("%s.a", filepath.Join(dir, p)), true
	}
	pkg, ok := find_go_dag_package(p, dir)
	if ok {
		return pkg, true
	}
	return find_global_file(p, context)
}

func path_and_alias(imp *ast.ImportSpec) (string, string) {
	path := ""
	if imp.Path != nil && len(imp.Path.Value) > 0 {
		path = string(imp.Path.Value)
		path = path[1 : len(path)-1]
	}
	alias := ""
	if imp.Name != nil {
		alias = imp.Name.Name
	}
	return path, alias
}

func find_go_dag_package(imp, filedir string) (string, bool) {
	// Support godag directory structure
	dir, pkg := filepath.Split(imp)
	godag_pkg := filepath.Join(filedir, "..", dir, "_obj", pkg+".a")
	if file_exists(godag_pkg) {
		return godag_pkg, true
	}
	return "", false
}

// autobuild compares the mod time of the source files of the package, and if any of them is newer
// than the package object file will rebuild it.
func autobuild(p *build.Package) error {
	if p.Dir == "" {
		return fmt.Errorf("no files to build")
	}
	ps, err := os.Stat(p.PkgObj)
	if err != nil {
		// Assume package file does not exist and build for the first time.
		return build_package(p)
	}
	pt := ps.ModTime()
	fs, err := readdir_lstat(p.Dir)
	if err != nil {
		return err
	}
	for _, f := range fs {
		if f.IsDir() {
			continue
		}
		if f.ModTime().After(pt) {
			// Source file is newer than package file; rebuild.
			return build_package(p)
		}
	}
	return nil
}

// build_package builds the package by calling `go install package/import`. If everything compiles
// correctly, the newly compiled package should then be in the usual place in the `$GOPATH/pkg`
// directory, and gocode will pick it up from there.
func build_package(p *build.Package) error {
	if *g_debug {
		log.Printf("-------------------")
		log.Printf("rebuilding package %s", p.Name)
		log.Printf("package import: %s", p.ImportPath)
		log.Printf("package object: %s", p.PkgObj)
		log.Printf("package source dir: %s", p.Dir)
		log.Printf("package source files: %v", p.GoFiles)
		log.Printf("GOPATH: %v", g_daemon.context.GOPATH)
		log.Printf("GOROOT: %v", g_daemon.context.GOROOT)
	}
	env := os.Environ()
	for i, v := range env {
		if strings.HasPrefix(v, "GOPATH=") {
			env[i] = "GOPATH=" + g_daemon.context.GOPATH
		} else if strings.HasPrefix(v, "GOROOT=") {
			env[i] = "GOROOT=" + g_daemon.context.GOROOT
		}
	}

	cmd := exec.Command("go", "install", p.ImportPath)
	cmd.Env = env

	// TODO: Should read STDERR rather than STDOUT.
	out, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}
	if *g_debug {
		log.Printf("build out: %s\n", string(out))
	}
	return nil
}

// executes autobuild function if autobuild option is enabled, logs error and
// ignores it
func try_autobuild(p *build.Package) {
	if g_config.Autobuild {
		err := autobuild(p)
		if err != nil && *g_debug {
			log.Printf("Autobuild error: %s\n", err)
		}
	}
}

func log_found_package_maybe(imp, pkgpath string) {
	if *g_debug {
		log.Printf("Found %q at %q\n", imp, pkgpath)
	}
}

func log_build_context(context *package_lookup_context) {
	log.Printf(" GOROOT: %s\n", context.GOROOT)
	log.Printf(" GOPATH: %s\n", context.GOPATH)
	log.Printf(" GOOS: %s\n", context.GOOS)
	log.Printf(" GOARCH: %s\n", context.GOARCH)
	log.Printf(" BzlProjectRoot: %q\n", context.BzlProjectRoot)
	log.Printf(" GBProjectRoot: %q\n", context.GBProjectRoot)
	log.Printf(" lib-path: %q\n", g_config.LibPath)
}

// find_global_file returns the file path of the compiled package corresponding to the specified
// import, and a boolean stating whether such path is valid.
// TODO: Return only one value, possibly empty string if not found.
func find_global_file(imp string, context *package_lookup_context) (string, bool) {
	// gocode synthetically generates the builtin package
	// "unsafe", since the "unsafe.a" package doesn't really exist.
	// Thus, when the user request for the package "unsafe" we
	// would return synthetic global file that would be used
	// just as a key name to find this synthetic package
	if imp == "unsafe" {
		return "unsafe", true
	}

	pkgfile := fmt.Sprintf("%s.a", imp)

	// if lib-path is defined, use it
	if g_config.LibPath != "" {
		for _, p := range filepath.SplitList(g_config.LibPath) {
			pkg_path := filepath.Join(p, pkgfile)
			if file_exists(pkg_path) {
				log_found_package_maybe(imp, pkg_path)
				return pkg_path, true
			}
			// Also check the relevant pkg/OS_ARCH dir for the libpath, if provided.
			pkgdir := fmt.Sprintf("%s_%s", context.GOOS, context.GOARCH)
			pkg_path = filepath.Join(p, "pkg", pkgdir, pkgfile)
			if file_exists(pkg_path) {
				log_found_package_maybe(imp, pkg_path)
				return pkg_path, true
			}
		}
	}

	// gb-specific lookup mode, only if the root dir was found
	if g_config.PackageLookupMode == "gb" && context.GBProjectRoot != "" {
		root := context.GBProjectRoot
		pkgdir := filepath.Join(root, "pkg", context.GOOS+"-"+context.GOARCH)
		if !is_dir(pkgdir) {
			pkgdir = filepath.Join(root, "pkg", context.GOOS+"-"+context.GOARCH+"-race")
		}
		pkg_path := filepath.Join(pkgdir, pkgfile)
		if file_exists(pkg_path) {
			log_found_package_maybe(imp, pkg_path)
			return pkg_path, true
		}
	}

	// bzl-specific lookup mode, only if the root dir was found
	if g_config.PackageLookupMode == "bzl" && context.BzlProjectRoot != "" {
		var root, impath string
		if strings.HasPrefix(imp, g_config.CustomPkgPrefix+"/") {
			root = filepath.Join(context.BzlProjectRoot, "bazel-bin")
			impath = imp[len(g_config.CustomPkgPrefix)+1:]
		} else if g_config.CustomVendorDir != "" {
			// Try custom vendor dir.
			root = filepath.Join(context.BzlProjectRoot, "bazel-bin", g_config.CustomVendorDir)
			impath = imp
		}

		if root != "" && impath != "" {
			// There might be more than one ".a" files in the pkg path with bazel.
			// But the best practice is to keep one go_library build target in each
			// pakcage directory so that it follows the standard Go package
			// structure. Thus here we assume there is at most one ".a" file existing
			// in the pkg path.
			if d, err := os.Open(filepath.Join(root, impath)); err == nil {
				defer d.Close()

				if fis, err := d.Readdir(-1); err == nil {
					for _, fi := range fis {
						if !fi.IsDir() && filepath.Ext(fi.Name()) == ".a" {
							pkg_path := filepath.Join(root, impath, fi.Name())
							log_found_package_maybe(imp, pkg_path)
							return pkg_path, true
						}
					}
				}
			}
		}
	}

	if context.CurrentPackagePath != "" {
		// Try vendor path first, see GO15VENDOREXPERIMENT.
		// We don't check this environment variable however, seems like there is
		// almost no harm in doing so (well.. if you experiment with vendoring,
		// gocode will fail after enabling/disabling the flag, and you'll be
		// forced to get rid of vendor binaries). But asking users to set this
		// env var is up will bring more trouble. Because we also need to pass
		// it from client to server, make sure their editors set it, etc.
		// So, whatever, let's just pretend it's always on.
		package_path := context.CurrentPackagePath
		for {
			limp := filepath.Join(package_path, "vendor", imp)
			if p, err := context.Import(limp, "", build.AllowBinary|build.FindOnly); err == nil {
				try_autobuild(p)
				if file_exists(p.PkgObj) {
					log_found_package_maybe(imp, p.PkgObj)
					return p.PkgObj, true
				}
			}
			if package_path == "" {
				break
			}
			next_path := filepath.Dir(package_path)
			// let's protect ourselves from inf recursion here
			if next_path == package_path {
				break
			}
			package_path = next_path
		}
	}

	if p, err := context.Import(imp, "", build.AllowBinary|build.FindOnly); err == nil {
		try_autobuild(p)
		if file_exists(p.PkgObj) {
			log_found_package_maybe(imp, p.PkgObj)
			return p.PkgObj, true
		}
	}

	if *g_debug {
		log.Printf("Import path %q was not resolved\n", imp)
		log.Println("Gocode's build context is:")
		log_build_context(context)
	}
	return "", false
}

func package_name(file *ast.File) string {
	if file.Name != nil {
		return file.Name.Name
	}
	return ""
}

//-------------------------------------------------------------------------
// decl_cache
//
// Thread-safe collection of DeclFileCache entities.
//-------------------------------------------------------------------------

type package_lookup_context struct {
	build.Context
	BzlProjectRoot     string
	GBProjectRoot      string
	CurrentPackagePath string
}

// gopath returns the list of Go path directories.
func (ctxt *package_lookup_context) gopath() []string {
	var all []string
	for _, p := range filepath.SplitList(ctxt.GOPATH) {
		if p == "" || p == ctxt.GOROOT {
			// Empty paths are uninteresting.
			// If the path is the GOROOT, ignore it.
			// People sometimes set GOPATH=$GOROOT.
			// Do not get confused by this common mistake.
			continue
		}
		if strings.HasPrefix(p, "~") {
			// Path segments starting with ~ on Unix are almost always
			// users who have incorrectly quoted ~ while setting GOPATH,
			// preventing it from expanding to $HOME.
			// The situation is made more confusing by the fact that
			// bash allows quoted ~ in $PATH (most shells do not).
			// Do not get confused by this, and do not try to use the path.
			// It does not exist, and printing errors about it confuses
			// those users even more, because they think "sure ~ exists!".
			// The go command diagnoses this situation and prints a
			// useful error.
			// On Windows, ~ is used in short names, such as c:\progra~1
			// for c:\program files.
			continue
		}
		all = append(all, p)
	}
	return all
}

func (ctxt *package_lookup_context) pkg_dirs() (string, []string) {
	pkgdir := fmt.Sprintf("%s_%s", ctxt.GOOS, ctxt.GOARCH)

	var currentPackagePath string
	var all []string
	if ctxt.GOROOT != "" {
		dir := filepath.Join(ctxt.GOROOT, "pkg", pkgdir)
		if is_dir(dir) {
			all = append(all, dir)
		}
	}

	switch g_config.PackageLookupMode {
	case "go":
		currentPackagePath = ctxt.CurrentPackagePath
		for _, p := range ctxt.gopath() {
			dir := filepath.Join(p, "pkg", pkgdir)
			if is_dir(dir) {
				all = append(all, dir)
			}
			dir = filepath.Join(dir, currentPackagePath, "vendor")
			if is_dir(dir) {
				all = append(all, dir)
			}
		}
	case "gb":
		if ctxt.GBProjectRoot != "" {
			pkgdir := fmt.Sprintf("%s-%s", ctxt.GOOS, ctxt.GOARCH)
			if !is_dir(pkgdir) {
				pkgdir = fmt.Sprintf("%s-%s-race", ctxt.GOOS, ctxt.GOARCH)
			}
			dir := filepath.Join(ctxt.GBProjectRoot, "pkg", pkgdir)
			if is_dir(dir) {
				all = append(all, dir)
			}
		}
	case "bzl":
		// TODO: Support bazel mode
	}
	return currentPackagePath, all
}

type decl_cache struct {
	cache   map[string]*decl_file_cache
	context *package_lookup_context
	sync.Mutex
}

func new_decl_cache(context *package_lookup_context) *decl_cache {
	return &decl_cache{
		cache:   make(map[string]*decl_file_cache),
		context: context,
	}
}

func (c *decl_cache) get(filename string) *decl_file_cache {
	c.Lock()
	defer c.Unlock()

	f, ok := c.cache[filename]
	if !ok {
		f = new_decl_file_cache(filename, c.context)
		c.cache[filename] = f
	}
	return f
}

func (c *decl_cache) get_and_update(filename string) *decl_file_cache {
	f := c.get(filename)
	f.update()
	return f
}

"""



```