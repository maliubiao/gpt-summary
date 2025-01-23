Response: The user wants a summary of the functionalities of the provided Go code snippet, which is part of the `pkg.go` file in the `cmd/go/internal/load` package. This file is responsible for loading Go packages.

Here's a breakdown of the thought process to generate the response:

1. **Identify the core purpose:** The file's name (`pkg.go` in the `load` package) strongly suggests its primary function is loading Go packages. This will be the central theme of the summary.

2. **Scan for key functions and data structures:** Look for prominent function names and data types that reveal specific functionalities. Examples include `loadImport`, `PackagesAndErrors`, `PrepareForCoverageBuild`, and the `Package` struct itself. These will become the main points in the feature list.

3. **Analyze function responsibilities:**  For each key function, determine its specific role in the package loading process. For instance, `loadImport` handles the recursive loading of dependencies, while `PackagesAndErrors` manages loading packages based on command-line arguments.

4. **Infer implicit functionalities:**  Consider what else must be happening within the code. For example, if it's loading packages, it likely handles error reporting, determines build targets, and manages dependencies.

5. **Connect to Go language features:**  Think about how the code relates to specific Go language features like modules, `go:embed`, cgo, and code coverage. The code explicitly mentions and handles these features, making them important to include.

6. **Identify command-line interactions:** Look for code that processes configuration (`cfg`) or command-line flags. This will reveal how the loading process can be influenced by user input.

7. **Spot potential pitfalls:** Consider common mistakes developers might make when using the `go` command and see if the code addresses them (e.g., case-insensitive import collisions).

8. **Structure the response:** Organize the findings into a clear and logical structure, covering the requested aspects:
    * List of functionalities.
    * Explanation of the Go language features implemented.
    * Code examples with assumptions and outputs (if applicable).
    * Details on command-line argument handling.
    * Common mistakes (if any).
    * Overall summary.

9. **Refine and elaborate:**   Flesh out each point with more detail. For example, instead of just saying "handles errors," specify the types of errors handled (import errors, build errors, etc.). For command-line arguments, provide examples of how they affect the package loading process.

10. **Self-Correction/Refinement:**  Initially, I might focus too much on the low-level details of individual functions. It's important to step back and ensure the summary captures the *high-level* functionalities and their relevance to the user. For example, while `resolveEmbed` is important, its purpose in the context of `go:embed` is the key takeaway. Similarly, the logic around `useBindir` needs to be related back to the concept of executable output. Ensure the code examples are practical and illustrate the explained functionality. Double-check the command-line parameter descriptions for accuracy and completeness.
```go
// error
			// must be either in an explicit command-line argument,
			// or on the importer side (indicated by a non-empty importPos).
			top, ok := stk.Top()
			if ok && path != top.Pkg && len(importPos) > 0 {
				p.Error.setPos(importPos)
			}
		}
	}

	if err != nil {
		p.Incomplete = true
		p.setLoadPackageDataError(err, path, stk, importPos)
	}

	useBindir := p.Name == "main"
	if !p.Standard {
		switch cfg.BuildBuildmode {
		case "c-archive", "c-shared", "plugin":
			useBindir = false
		}
	}

	if useBindir {
		// Report an error when the old code.google.com/p/go.tools paths are used.
		if InstallTargetDir(p) == StalePath {
			// TODO(matloob): remove this branch, and StalePath itself. code.google.com/p/go is so
			// old, even this code checking for it is stale now!
			newPath := strings.Replace(p.ImportPath, "code.google.com/p/go.", "golang.org/x/", 1)
			e := ImportErrorf(p.ImportPath, "the %v command has moved; use %v instead.", p.ImportPath, newPath)
			setError(e)
			return
		}
		elem := p.DefaultExecName() + cfg.ExeSuffix
		full := filepath.Join(cfg.BuildContext.GOOS+"_"+cfg.BuildContext.GOARCH, elem)
		if cfg.BuildContext.GOOS != runtime.GOOS || cfg.BuildContext.GOARCH != runtime.GOARCH {
			// Install cross-compiled binaries to subdirectories of bin.
			elem = full
		}
		if p.Internal.Build.BinDir == "" && cfg.ModulesEnabled {
			p.Internal.Build.BinDir = modload.BinDir()
		}
		if p.Internal.Build.BinDir != "" {
			// Install to GOBIN or bin of GOPATH entry.
			p.Target = filepath.Join(p.Internal.Build.BinDir, elem)
			if !p.Goroot && strings.Contains(elem, string(filepath.Separator)) && cfg.GOBIN != "" {
				// Do not create $GOBIN/goos_goarch/elem.
				p.Target = ""
				p.Internal.GobinSubdir = true
			}
		}
		if InstallTargetDir(p) == ToTool {
			// This is for 'go tool'.
			// Override all the usual logic and force it into the tool directory.
			if cfg.BuildToolchainName == "gccgo" {
				p.Target = filepath.Join(build.ToolDir, elem)
			} else {
				p.Target = filepath.Join(cfg.GOROOTpkg, "tool", full)
			}
		}
	} else if p.Internal.Local {
		// Local import turned into absolute path.
		// No permanent install target.
		p.Target = ""
	} else if p.Standard && cfg.BuildContext.Compiler == "gccgo" {
		// gccgo has a preinstalled standard library that cmd/go cannot rebuild.
		p.Target = ""
	} else {
		p.Target = p.Internal.Build.PkgObj
		if cfg.BuildBuildmode == "shared" && p.Internal.Build.PkgTargetRoot != "" {
			// TODO(matloob): This shouldn't be necessary, but the cmd/cgo/internal/testshared
			// test fails without Target set for this condition. Figure out why and
			// fix it.
			p.Target = filepath.Join(p.Internal.Build.PkgTargetRoot, p.ImportPath+".a")
		}
		if cfg.BuildLinkshared && p.Internal.Build.PkgTargetRoot != "" {
			// TODO(bcmills): The reliance on PkgTargetRoot implies that -linkshared does
			// not work for any package that lacks a PkgTargetRoot — such as a non-main
			// package in module mode. We should probably fix that.
			targetPrefix := filepath.Join(p.Internal.Build.PkgTargetRoot, p.ImportPath)
			p.Target = targetPrefix + ".a"
			shlibnamefile := targetPrefix + ".shlibname"
			shlib, err := os.ReadFile(shlibnamefile)
			if err != nil && !os.IsNotExist(err) {
				base.Fatalf("reading shlibname: %v", err)
			}
			if err == nil {
				libname := strings.TrimSpace(string(shlib))
				if cfg.BuildContext.Compiler == "gccgo" {
					p.Shlib = filepath.Join(p.Internal.Build.PkgTargetRoot, "shlibs", libname)
				} else {
					p.Shlib = filepath.Join(p.Internal.Build.PkgTargetRoot, libname)
				}
			}
		}
	}

	// Build augmented import list to add implicit dependencies.
	// Be careful not to add imports twice, just to avoid confusion.
	importPaths := p.Imports
	addImport := func(path string, forCompiler bool) {
		for _, p := range importPaths {
			if path == p {
				return
			}
		}
		importPaths = append(importPaths, path)
		if forCompiler {
			p.Internal.CompiledImports = append(p.Internal.CompiledImports, path)
		}
	}

	if !opts.IgnoreImports {
		// Cgo translation adds imports of "unsafe", "runtime/cgo" and "syscall",
		// except for certain packages, to avoid circular dependencies.
		if p.UsesCgo() {
			addImport("unsafe", true)
		}
		if p.UsesCgo() && (!p.Standard || !cgoExclude[p.ImportPath]) && cfg.BuildContext.Compiler != "gccgo" {
			addImport("runtime/cgo", true)
		}
		if p.UsesCgo() && (!p.Standard || !cgoSyscallExclude[p.ImportPath]) {
			addImport("syscall", true)
		}

		// SWIG adds imports of some standard packages.
		if p.UsesSwig() {
			addImport("unsafe", true)
			if cfg.BuildContext.Compiler != "gccgo" {
				addImport("runtime/cgo", true)
			}
			addImport("syscall", true)
			addImport("sync", true)

			// TODO: The .swig and .swigcxx files can use
			// %go_import directives to import other packages.
		}

		// The linker loads implicit dependencies.
		if p.Name == "main" && !p.Internal.ForceLibrary {
			ldDeps, err := LinkerDeps(p)
			if err != nil {
				setError(err)
				return
			}
			for _, dep := range ldDeps {
				addImport(dep, false)
			}
		}
	}

	// Check for case-insensitive collisions of import paths.
	// If modifying, consider changing checkPathCollisions() in
	// src/cmd/go/internal/modcmd/vendor.go
	fold := str.ToFold(p.ImportPath)
	if other := foldPath[fold]; other == "" {
		foldPath[fold] = p.ImportPath
	} else if other != p.ImportPath {
		setError(ImportErrorf(p.ImportPath, "case-insensitive import collision: %q and %q", p.ImportPath, other))
		return
	}

	if !SafeArg(p.ImportPath) {
		setError(ImportErrorf(p.ImportPath, "invalid import path %q", p.ImportPath))
		return
	}

	// Errors after this point are caused by this package, not the importing
	// package. Pushing the path here prevents us from reporting the error
	// with the position of the import declaration.
	stk.Push(ImportInfo{Pkg: path, Pos: extractFirstImport(importPos)})
	defer stk.Pop()

	pkgPath := p.ImportPath
	if p.Internal.CmdlineFiles {
		pkgPath = "command-line-arguments"
	}
	if cfg.ModulesEnabled {
		p.Module = modload.PackageModuleInfo(ctx, pkgPath)
	}
	p.DefaultGODEBUG = defaultGODEBUG(p, nil, nil, nil)

	if !opts.SuppressEmbedFiles {
		p.EmbedFiles, p.Internal.Embed, err = resolveEmbed(p.Dir, p.EmbedPatterns)
		if err != nil {
			p.Incomplete = true
			setError(err)
			embedErr := err.(*EmbedError)
			p.Error.setPos(p.Internal.Build.EmbedPatternPos[embedErr.Pattern])
		}
	}

	// Check for case-insensitive collision of input files.
	// To avoid problems on case-insensitive files, we reject any package
	// where two different input files have equal names under a case-insensitive
	// comparison.
	inputs := p.AllFiles()
	f1, f2 := str.FoldDup(inputs)
	if f1 != "" {
		setError(fmt.Errorf("case-insensitive file name collision: %q and %q", f1, f2))
		return
	}

	// If first letter of input file is ASCII, it must be alphanumeric.
	// This avoids files turning into flags when invoking commands,
	// and other problems we haven't thought of yet.
	// Also, _cgo_ files must be generated by us, not supplied.
	// They are allowed to have //go:cgo_ldflag directives.
	// The directory scan ignores files beginning with _,
	// so we shouldn't see any _cgo_ files anyway, but just be safe.
	for _, file := range inputs {
		if !SafeArg(file) || strings.HasPrefix(file, "_cgo_") {
			setError(fmt.Errorf("invalid input file name %q", file))
			return
		}
	}
	if name := pathpkg.Base(p.ImportPath); !SafeArg(name) {
		setError(fmt.Errorf("invalid input directory name %q", name))
		return
	}
	if strings.ContainsAny(p.Dir, "\r\n") {
		setError(fmt.Errorf("invalid package directory %q", p.Dir))
		return
	}

	// Build list of imported packages and full dependency list.
	imports := make([]*Package, 0, len(p.Imports))
	for i, path := range importPaths {
		if path == "C" {
			continue
		}
		p1, err := loadImport(ctx, opts, nil, path, p.Dir, p, stk, p.Internal.Build.ImportPos[path], ResolveImport)
		if err != nil && p.Error == nil {
			p.Error = err
			p.Incomplete = true
		}

		path = p1.ImportPath
		importPaths[i] = path
		if i < len(p.Imports) {
			p.Imports[i] = path
		}

		imports = append(imports, p1)
		if p1.Incomplete {
			p.Incomplete = true
		}
	}
	p.Internal.Imports = imports
	if p.Error == nil && p.Name == "main" && !p.Internal.ForceLibrary && !p.Incomplete && !opts.SuppressBuildInfo {
		// TODO(bcmills): loading VCS metadata can be fairly slow.
		// Consider starting this as a background goroutine and retrieving the result
		// asynchronously when we're actually ready to build the package, or when we
		// actually need to evaluate whether the package's metadata is stale.
		p.setBuildInfo(ctx, opts.AutoVCS)
	}

	// If cgo is not enabled, ignore cgo supporting sources
	// just as we ignore go files containing import "C".
	if !cfg.BuildContext.CgoEnabled {
		p.CFiles = nil
		p.CXXFiles = nil
		p.MFiles = nil
		p.SwigFiles = nil
		p.SwigCXXFiles = nil
		// Note that SFiles are okay (they go to the Go assembler)
		// and HFiles are okay (they might be used by the SFiles).
		// Also Sysofiles are okay (they might not contain object
		// code; see issue #16050).
	}

	// The gc toolchain only permits C source files with cgo or SWIG.
	if len(p.CFiles) > 0 && !p.UsesCgo() && !p.UsesSwig() && cfg.BuildContext.Compiler == "gc" {
		setError(fmt.Errorf("C source files not allowed when not using cgo or SWIG: %s", strings.Join(p.CFiles, " ")))
		return
	}

	// C++, Objective-C, and Fortran source files are permitted only with cgo or SWIG,
	// regardless of toolchain.
	if len(p.CXXFiles) > 0 && !p.UsesCgo() && !p.UsesSwig() {
		setError(fmt.Errorf("C++ source files not allowed when not using cgo or SWIG: %s", strings.Join(p.CXXFiles, " ")))
		return
	}
	if len(p.MFiles) > 0 && !p.UsesCgo() && !p.UsesSwig() {
		setError(fmt.Errorf("Objective-C source files not allowed when not using cgo or SWIG: %s", strings.Join(p.MFiles, " ")))
		return
	}
	if len(p.FFiles) > 0 && !p.UsesCgo() && !p.UsesSwig() {
		setError(fmt.Errorf("Fortran source files not allowed when not using cgo or SWIG: %s", strings.Join(p.FFiles, " ")))
		return
	}
}
```

### 功能列表

1. **加载 Go 包的信息:**  该部分代码负责加载 Go 包的元数据和依赖关系。这包括解析包的导入路径、源文件、构建标签等信息。
2. **处理构建目标 (Target):**  根据包的类型 (main 包或库包)、构建模式 (buildmode) 和操作系统/架构，确定包的构建输出目标路径。例如，main 包的可执行文件会安装到 `$GOBIN` 或 `$GOPATH/bin` 目录下。
3. **处理 `go:embed` 指令:** 解析和处理 `//go:embed` 指令，将匹配的文件添加到包的元数据中。
4. **处理 Cgo 和 SWIG 依赖:**  如果包使用了 Cgo 或 SWIG，则添加必要的隐式依赖，例如 `unsafe`、`runtime/cgo` 和 `syscall`。
5. **处理链接器依赖:**  对于 `main` 包，确定链接器所需的隐式依赖，例如 `runtime`。
6. **检查导入路径冲突:**  检查是否存在大小写不敏感的导入路径冲突。
7. **校验输入文件名:**  验证输入文件名的合法性，避免特殊字符或以 `_cgo_` 开头的文件名。
8. **处理模块信息:**  如果启用了 Go 模块，则获取包的模块信息。
9. **处理构建信息:**  为 `main` 包收集构建信息，例如编译器版本、构建标签、VCS 信息等，这些信息会被嵌入到最终的可执行文件中。
10. **处理构建约束:**  根据构建约束 (例如是否启用 cgo) 排除特定的源文件。
11. **错误处理:**  在加载包的过程中遇到错误时进行记录和处理，例如导入错误、文件不存在等。

### 实现的 Go 语言功能

这段代码主要实现了 Go 语言中 **包的加载和依赖解析** 功能，这是 `go build`, `go run`, `go install` 等命令的基础。 其中涉及到的具体 Go 语言功能包括：

* **包的导入 (Importing Packages):**  代码的核心是处理 `import` 声明，找到依赖的包。
* **构建约束 (Build Constraints):** 代码通过检查 `cfg.BuildContext.CgoEnabled` 等配置来处理构建约束，决定哪些文件应该被编译。
* **Cgo:** 代码识别并处理使用了 Cgo 的包，添加必要的依赖。
* **SWIG:** 代码识别并处理使用了 SWIG 的包，添加必要的依赖。
* **`go:embed`:** 代码解析和处理 `//go:embed` 指令，将文件嵌入到最终的二进制文件中。
* **Go 模块 (Go Modules):**  代码通过 `cfg.ModulesEnabled` 判断是否启用了 Go 模块，并调用 `modload` 包来处理模块相关的操作。
* **可执行文件构建 (Executable Building):** 代码针对 `main` 包设置构建目标，并考虑了跨平台编译的情况。

**代码示例 (处理 `go:embed`)**

假设有以下 Go 代码 (`main.go`)：

```go
package main

import (
	_ "embed"
	"fmt"
	"net/http"
)

//go:embed static/index.html
var indexHTML string

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, indexHTML)
	})
	http.ListenAndServe(":8080", nil)
}
```

以及一个名为 `static/index.html` 的文件：

```html
<h1>Hello, Embedded World!</h1>
```

**假设的输入与输出：**

当使用 `go build` 命令编译这个包时，`pkg.go` 中的 `resolveEmbed` 函数会被调用，其输入可能是：

* `pkgdir`:  当前包的目录路径 (例如: `/path/to/your/project`)
* `patterns`: `[]string{"static/index.html"}` (从 `//go:embed` 指令中解析得到)

`resolveEmbed` 函数会查找 `static/index.html` 文件，并返回：

* `files`: `[]string{"static/index.html"}`
* `pmap`: `map[string][]string{"static/index.html": {"static/index.html"}}`
* `err`: `nil` (如果没有错误)

然后，`pkg.go` 中的其他代码会把 `indexHTML` 变量与 `static/index.html` 文件的内容关联起来，最终编译到可执行文件中。

**命令行参数处理**

这段代码中涉及到对构建模式 (`-buildmode`) 和 `-linkshared` 命令行参数的处理：

* **`-buildmode`:**
    * 对于 `main` 包，默认会将 `useBindir` 设置为 `true`，表示可执行文件会安装到 `$GOBIN` 或 `$GOPATH/bin` 目录下。
    * 如果 `-buildmode` 设置为 `"c-archive"`, `"c-shared"` 或 `"plugin"`，则会将 `useBindir` 设置为 `false`，表示不会安装到可执行文件目录。
* **`-linkshared`:**
    * 如果设置了 `-linkshared`，并且 `p.Internal.Build.PkgTargetRoot` 不为空，则会尝试读取 `.shlibname` 文件来确定共享库的名称和路径。

**易犯错的点 (示例)**

假设开发者在一个项目中错误地创建了两个仅大小写不同的导入路径的包，例如：

* `mypackage` 目录
* `myPackage` 目录

如果代码中同时导入了这两个包，这段代码中的以下逻辑会检测到这种冲突并报错：

```go
	// Check for case-insensitive collisions of import paths.
	// If modifying, consider changing checkPathCollisions() in
	// src/cmd/go/internal/modcmd/vendor.go
	fold := str.ToFold(p.ImportPath)
	if other := foldPath[fold]; other == "" {
		foldPath[fold] = p.ImportPath
	} else if other != p.ImportPath {
		setError(ImportErrorf(p.ImportPath, "case-insensitive import collision: %q and %q", p.ImportPath, other))
		return
	}
```

例如，如果当前正在加载 `mypackage`，并且之前已经加载了 `myPackage`，则会产生类似以下的错误信息：

```
case-insensitive import collision: "mypackage" and "myPackage"
```

### 功能归纳

这段代码是 `go` 命令中负责 **加载和预处理 Go 包** 的核心逻辑之一。它根据不同的构建配置、依赖关系和语言特性，为后续的编译、链接等操作准备必要的包信息，包括确定构建目标、处理 `go:embed` 指令、处理 Cgo/SWIG 依赖、检查导入路径冲突等。 它的主要职责是确保在构建过程开始之前，所有相关的包信息都得到正确加载和校验。

### 提示词
```
这是路径为go/src/cmd/go/internal/load/pkg.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
error
			// must be either in an explicit command-line argument,
			// or on the importer side (indicated by a non-empty importPos).
			top, ok := stk.Top()
			if ok && path != top.Pkg && len(importPos) > 0 {
				p.Error.setPos(importPos)
			}
		}
	}

	if err != nil {
		p.Incomplete = true
		p.setLoadPackageDataError(err, path, stk, importPos)
	}

	useBindir := p.Name == "main"
	if !p.Standard {
		switch cfg.BuildBuildmode {
		case "c-archive", "c-shared", "plugin":
			useBindir = false
		}
	}

	if useBindir {
		// Report an error when the old code.google.com/p/go.tools paths are used.
		if InstallTargetDir(p) == StalePath {
			// TODO(matloob): remove this branch, and StalePath itself. code.google.com/p/go is so
			// old, even this code checking for it is stale now!
			newPath := strings.Replace(p.ImportPath, "code.google.com/p/go.", "golang.org/x/", 1)
			e := ImportErrorf(p.ImportPath, "the %v command has moved; use %v instead.", p.ImportPath, newPath)
			setError(e)
			return
		}
		elem := p.DefaultExecName() + cfg.ExeSuffix
		full := filepath.Join(cfg.BuildContext.GOOS+"_"+cfg.BuildContext.GOARCH, elem)
		if cfg.BuildContext.GOOS != runtime.GOOS || cfg.BuildContext.GOARCH != runtime.GOARCH {
			// Install cross-compiled binaries to subdirectories of bin.
			elem = full
		}
		if p.Internal.Build.BinDir == "" && cfg.ModulesEnabled {
			p.Internal.Build.BinDir = modload.BinDir()
		}
		if p.Internal.Build.BinDir != "" {
			// Install to GOBIN or bin of GOPATH entry.
			p.Target = filepath.Join(p.Internal.Build.BinDir, elem)
			if !p.Goroot && strings.Contains(elem, string(filepath.Separator)) && cfg.GOBIN != "" {
				// Do not create $GOBIN/goos_goarch/elem.
				p.Target = ""
				p.Internal.GobinSubdir = true
			}
		}
		if InstallTargetDir(p) == ToTool {
			// This is for 'go tool'.
			// Override all the usual logic and force it into the tool directory.
			if cfg.BuildToolchainName == "gccgo" {
				p.Target = filepath.Join(build.ToolDir, elem)
			} else {
				p.Target = filepath.Join(cfg.GOROOTpkg, "tool", full)
			}
		}
	} else if p.Internal.Local {
		// Local import turned into absolute path.
		// No permanent install target.
		p.Target = ""
	} else if p.Standard && cfg.BuildContext.Compiler == "gccgo" {
		// gccgo has a preinstalled standard library that cmd/go cannot rebuild.
		p.Target = ""
	} else {
		p.Target = p.Internal.Build.PkgObj
		if cfg.BuildBuildmode == "shared" && p.Internal.Build.PkgTargetRoot != "" {
			// TODO(matloob): This shouldn't be necessary, but the cmd/cgo/internal/testshared
			// test fails without Target set for this condition. Figure out why and
			// fix it.
			p.Target = filepath.Join(p.Internal.Build.PkgTargetRoot, p.ImportPath+".a")
		}
		if cfg.BuildLinkshared && p.Internal.Build.PkgTargetRoot != "" {
			// TODO(bcmills): The reliance on PkgTargetRoot implies that -linkshared does
			// not work for any package that lacks a PkgTargetRoot — such as a non-main
			// package in module mode. We should probably fix that.
			targetPrefix := filepath.Join(p.Internal.Build.PkgTargetRoot, p.ImportPath)
			p.Target = targetPrefix + ".a"
			shlibnamefile := targetPrefix + ".shlibname"
			shlib, err := os.ReadFile(shlibnamefile)
			if err != nil && !os.IsNotExist(err) {
				base.Fatalf("reading shlibname: %v", err)
			}
			if err == nil {
				libname := strings.TrimSpace(string(shlib))
				if cfg.BuildContext.Compiler == "gccgo" {
					p.Shlib = filepath.Join(p.Internal.Build.PkgTargetRoot, "shlibs", libname)
				} else {
					p.Shlib = filepath.Join(p.Internal.Build.PkgTargetRoot, libname)
				}
			}
		}
	}

	// Build augmented import list to add implicit dependencies.
	// Be careful not to add imports twice, just to avoid confusion.
	importPaths := p.Imports
	addImport := func(path string, forCompiler bool) {
		for _, p := range importPaths {
			if path == p {
				return
			}
		}
		importPaths = append(importPaths, path)
		if forCompiler {
			p.Internal.CompiledImports = append(p.Internal.CompiledImports, path)
		}
	}

	if !opts.IgnoreImports {
		// Cgo translation adds imports of "unsafe", "runtime/cgo" and "syscall",
		// except for certain packages, to avoid circular dependencies.
		if p.UsesCgo() {
			addImport("unsafe", true)
		}
		if p.UsesCgo() && (!p.Standard || !cgoExclude[p.ImportPath]) && cfg.BuildContext.Compiler != "gccgo" {
			addImport("runtime/cgo", true)
		}
		if p.UsesCgo() && (!p.Standard || !cgoSyscallExclude[p.ImportPath]) {
			addImport("syscall", true)
		}

		// SWIG adds imports of some standard packages.
		if p.UsesSwig() {
			addImport("unsafe", true)
			if cfg.BuildContext.Compiler != "gccgo" {
				addImport("runtime/cgo", true)
			}
			addImport("syscall", true)
			addImport("sync", true)

			// TODO: The .swig and .swigcxx files can use
			// %go_import directives to import other packages.
		}

		// The linker loads implicit dependencies.
		if p.Name == "main" && !p.Internal.ForceLibrary {
			ldDeps, err := LinkerDeps(p)
			if err != nil {
				setError(err)
				return
			}
			for _, dep := range ldDeps {
				addImport(dep, false)
			}
		}
	}

	// Check for case-insensitive collisions of import paths.
	// If modifying, consider changing checkPathCollisions() in
	// src/cmd/go/internal/modcmd/vendor.go
	fold := str.ToFold(p.ImportPath)
	if other := foldPath[fold]; other == "" {
		foldPath[fold] = p.ImportPath
	} else if other != p.ImportPath {
		setError(ImportErrorf(p.ImportPath, "case-insensitive import collision: %q and %q", p.ImportPath, other))
		return
	}

	if !SafeArg(p.ImportPath) {
		setError(ImportErrorf(p.ImportPath, "invalid import path %q", p.ImportPath))
		return
	}

	// Errors after this point are caused by this package, not the importing
	// package. Pushing the path here prevents us from reporting the error
	// with the position of the import declaration.
	stk.Push(ImportInfo{Pkg: path, Pos: extractFirstImport(importPos)})
	defer stk.Pop()

	pkgPath := p.ImportPath
	if p.Internal.CmdlineFiles {
		pkgPath = "command-line-arguments"
	}
	if cfg.ModulesEnabled {
		p.Module = modload.PackageModuleInfo(ctx, pkgPath)
	}
	p.DefaultGODEBUG = defaultGODEBUG(p, nil, nil, nil)

	if !opts.SuppressEmbedFiles {
		p.EmbedFiles, p.Internal.Embed, err = resolveEmbed(p.Dir, p.EmbedPatterns)
		if err != nil {
			p.Incomplete = true
			setError(err)
			embedErr := err.(*EmbedError)
			p.Error.setPos(p.Internal.Build.EmbedPatternPos[embedErr.Pattern])
		}
	}

	// Check for case-insensitive collision of input files.
	// To avoid problems on case-insensitive files, we reject any package
	// where two different input files have equal names under a case-insensitive
	// comparison.
	inputs := p.AllFiles()
	f1, f2 := str.FoldDup(inputs)
	if f1 != "" {
		setError(fmt.Errorf("case-insensitive file name collision: %q and %q", f1, f2))
		return
	}

	// If first letter of input file is ASCII, it must be alphanumeric.
	// This avoids files turning into flags when invoking commands,
	// and other problems we haven't thought of yet.
	// Also, _cgo_ files must be generated by us, not supplied.
	// They are allowed to have //go:cgo_ldflag directives.
	// The directory scan ignores files beginning with _,
	// so we shouldn't see any _cgo_ files anyway, but just be safe.
	for _, file := range inputs {
		if !SafeArg(file) || strings.HasPrefix(file, "_cgo_") {
			setError(fmt.Errorf("invalid input file name %q", file))
			return
		}
	}
	if name := pathpkg.Base(p.ImportPath); !SafeArg(name) {
		setError(fmt.Errorf("invalid input directory name %q", name))
		return
	}
	if strings.ContainsAny(p.Dir, "\r\n") {
		setError(fmt.Errorf("invalid package directory %q", p.Dir))
		return
	}

	// Build list of imported packages and full dependency list.
	imports := make([]*Package, 0, len(p.Imports))
	for i, path := range importPaths {
		if path == "C" {
			continue
		}
		p1, err := loadImport(ctx, opts, nil, path, p.Dir, p, stk, p.Internal.Build.ImportPos[path], ResolveImport)
		if err != nil && p.Error == nil {
			p.Error = err
			p.Incomplete = true
		}

		path = p1.ImportPath
		importPaths[i] = path
		if i < len(p.Imports) {
			p.Imports[i] = path
		}

		imports = append(imports, p1)
		if p1.Incomplete {
			p.Incomplete = true
		}
	}
	p.Internal.Imports = imports
	if p.Error == nil && p.Name == "main" && !p.Internal.ForceLibrary && !p.Incomplete && !opts.SuppressBuildInfo {
		// TODO(bcmills): loading VCS metadata can be fairly slow.
		// Consider starting this as a background goroutine and retrieving the result
		// asynchronously when we're actually ready to build the package, or when we
		// actually need to evaluate whether the package's metadata is stale.
		p.setBuildInfo(ctx, opts.AutoVCS)
	}

	// If cgo is not enabled, ignore cgo supporting sources
	// just as we ignore go files containing import "C".
	if !cfg.BuildContext.CgoEnabled {
		p.CFiles = nil
		p.CXXFiles = nil
		p.MFiles = nil
		p.SwigFiles = nil
		p.SwigCXXFiles = nil
		// Note that SFiles are okay (they go to the Go assembler)
		// and HFiles are okay (they might be used by the SFiles).
		// Also Sysofiles are okay (they might not contain object
		// code; see issue #16050).
	}

	// The gc toolchain only permits C source files with cgo or SWIG.
	if len(p.CFiles) > 0 && !p.UsesCgo() && !p.UsesSwig() && cfg.BuildContext.Compiler == "gc" {
		setError(fmt.Errorf("C source files not allowed when not using cgo or SWIG: %s", strings.Join(p.CFiles, " ")))
		return
	}

	// C++, Objective-C, and Fortran source files are permitted only with cgo or SWIG,
	// regardless of toolchain.
	if len(p.CXXFiles) > 0 && !p.UsesCgo() && !p.UsesSwig() {
		setError(fmt.Errorf("C++ source files not allowed when not using cgo or SWIG: %s", strings.Join(p.CXXFiles, " ")))
		return
	}
	if len(p.MFiles) > 0 && !p.UsesCgo() && !p.UsesSwig() {
		setError(fmt.Errorf("Objective-C source files not allowed when not using cgo or SWIG: %s", strings.Join(p.MFiles, " ")))
		return
	}
	if len(p.FFiles) > 0 && !p.UsesCgo() && !p.UsesSwig() {
		setError(fmt.Errorf("Fortran source files not allowed when not using cgo or SWIG: %s", strings.Join(p.FFiles, " ")))
		return
	}
}

// An EmbedError indicates a problem with a go:embed directive.
type EmbedError struct {
	Pattern string
	Err     error
}

func (e *EmbedError) Error() string {
	return fmt.Sprintf("pattern %s: %v", e.Pattern, e.Err)
}

func (e *EmbedError) Unwrap() error {
	return e.Err
}

// ResolveEmbed resolves //go:embed patterns and returns only the file list.
// For use by go mod vendor to find embedded files it should copy into the
// vendor directory.
// TODO(#42504): Once go mod vendor uses load.PackagesAndErrors, just
// call (*Package).ResolveEmbed
func ResolveEmbed(dir string, patterns []string) ([]string, error) {
	files, _, err := resolveEmbed(dir, patterns)
	return files, err
}

// resolveEmbed resolves //go:embed patterns to precise file lists.
// It sets files to the list of unique files matched (for go list),
// and it sets pmap to the more precise mapping from
// patterns to files.
func resolveEmbed(pkgdir string, patterns []string) (files []string, pmap map[string][]string, err error) {
	var pattern string
	defer func() {
		if err != nil {
			err = &EmbedError{
				Pattern: pattern,
				Err:     err,
			}
		}
	}()

	// TODO(rsc): All these messages need position information for better error reports.
	pmap = make(map[string][]string)
	have := make(map[string]int)
	dirOK := make(map[string]bool)
	pid := 0 // pattern ID, to allow reuse of have map
	for _, pattern = range patterns {
		pid++

		glob, all := strings.CutPrefix(pattern, "all:")
		// Check pattern is valid for //go:embed.
		if _, err := pathpkg.Match(glob, ""); err != nil || !validEmbedPattern(glob) {
			return nil, nil, fmt.Errorf("invalid pattern syntax")
		}

		// Glob to find matches.
		match, err := fsys.Glob(str.QuoteGlob(str.WithFilePathSeparator(pkgdir)) + filepath.FromSlash(glob))
		if err != nil {
			return nil, nil, err
		}

		// Filter list of matches down to the ones that will still exist when
		// the directory is packaged up as a module. (If p.Dir is in the module cache,
		// only those files exist already, but if p.Dir is in the current module,
		// then there may be other things lying around, like symbolic links or .git directories.)
		var list []string
		for _, file := range match {
			// relative path to p.Dir which begins without prefix slash
			rel := filepath.ToSlash(str.TrimFilePathPrefix(file, pkgdir))

			what := "file"
			info, err := fsys.Lstat(file)
			if err != nil {
				return nil, nil, err
			}
			if info.IsDir() {
				what = "directory"
			}

			// Check that directories along path do not begin a new module
			// (do not contain a go.mod).
			for dir := file; len(dir) > len(pkgdir)+1 && !dirOK[dir]; dir = filepath.Dir(dir) {
				if _, err := fsys.Stat(filepath.Join(dir, "go.mod")); err == nil {
					return nil, nil, fmt.Errorf("cannot embed %s %s: in different module", what, rel)
				}
				if dir != file {
					if info, err := fsys.Lstat(dir); err == nil && !info.IsDir() {
						return nil, nil, fmt.Errorf("cannot embed %s %s: in non-directory %s", what, rel, dir[len(pkgdir)+1:])
					}
				}
				dirOK[dir] = true
				if elem := filepath.Base(dir); isBadEmbedName(elem) {
					if dir == file {
						return nil, nil, fmt.Errorf("cannot embed %s %s: invalid name %s", what, rel, elem)
					} else {
						return nil, nil, fmt.Errorf("cannot embed %s %s: in invalid directory %s", what, rel, elem)
					}
				}
			}

			switch {
			default:
				return nil, nil, fmt.Errorf("cannot embed irregular file %s", rel)

			case info.Mode().IsRegular():
				if have[rel] != pid {
					have[rel] = pid
					list = append(list, rel)
				}

			case info.IsDir():
				// Gather all files in the named directory, stopping at module boundaries
				// and ignoring files that wouldn't be packaged into a module.
				count := 0
				err := fsys.WalkDir(file, func(path string, d fs.DirEntry, err error) error {
					if err != nil {
						return err
					}
					rel := filepath.ToSlash(str.TrimFilePathPrefix(path, pkgdir))
					name := d.Name()
					if path != file && (isBadEmbedName(name) || ((name[0] == '.' || name[0] == '_') && !all)) {
						// Ignore bad names, assuming they won't go into modules.
						// Also avoid hidden files that user may not know about.
						// See golang.org/issue/42328.
						if d.IsDir() {
							return fs.SkipDir
						}
						return nil
					}
					if d.IsDir() {
						if _, err := fsys.Stat(filepath.Join(path, "go.mod")); err == nil {
							return filepath.SkipDir
						}
						return nil
					}
					if !d.Type().IsRegular() {
						return nil
					}
					count++
					if have[rel] != pid {
						have[rel] = pid
						list = append(list, rel)
					}
					return nil
				})
				if err != nil {
					return nil, nil, err
				}
				if count == 0 {
					return nil, nil, fmt.Errorf("cannot embed directory %s: contains no embeddable files", rel)
				}
			}
		}

		if len(list) == 0 {
			return nil, nil, fmt.Errorf("no matching files found")
		}
		sort.Strings(list)
		pmap[pattern] = list
	}

	for file := range have {
		files = append(files, file)
	}
	sort.Strings(files)
	return files, pmap, nil
}

func validEmbedPattern(pattern string) bool {
	return pattern != "." && fs.ValidPath(pattern)
}

// isBadEmbedName reports whether name is the base name of a file that
// can't or won't be included in modules and therefore shouldn't be treated
// as existing for embedding.
func isBadEmbedName(name string) bool {
	if err := module.CheckFilePath(name); err != nil {
		return true
	}
	switch name {
	// Empty string should be impossible but make it bad.
	case "":
		return true
	// Version control directories won't be present in module.
	case ".bzr", ".hg", ".git", ".svn":
		return true
	}
	return false
}

// vcsStatusCache maps repository directories (string)
// to their VCS information.
var vcsStatusCache par.ErrCache[string, vcs.Status]

func appendBuildSetting(info *debug.BuildInfo, key, value string) {
	value = strings.ReplaceAll(value, "\n", " ") // make value safe
	info.Settings = append(info.Settings, debug.BuildSetting{Key: key, Value: value})
}

// setBuildInfo gathers build information and sets it into
// p.Internal.BuildInfo, which will later be formatted as a string and embedded
// in the binary. setBuildInfo should only be called on a main package with no
// errors.
//
// This information can be retrieved using debug.ReadBuildInfo.
//
// Note that the GoVersion field is not set here to avoid encoding it twice.
// It is stored separately in the binary, mostly for historical reasons.
func (p *Package) setBuildInfo(ctx context.Context, autoVCS bool) {
	setPkgErrorf := func(format string, args ...any) {
		if p.Error == nil {
			p.Error = &PackageError{Err: fmt.Errorf(format, args...)}
			p.Incomplete = true
		}
	}

	var debugModFromModinfo func(*modinfo.ModulePublic) *debug.Module
	debugModFromModinfo = func(mi *modinfo.ModulePublic) *debug.Module {
		version := mi.Version
		if version == "" {
			version = "(devel)"
		}
		dm := &debug.Module{
			Path:    mi.Path,
			Version: version,
		}
		if mi.Replace != nil {
			dm.Replace = debugModFromModinfo(mi.Replace)
		} else if mi.Version != "" && cfg.BuildMod != "vendor" {
			dm.Sum = modfetch.Sum(ctx, module.Version{Path: mi.Path, Version: mi.Version})
		}
		return dm
	}

	var main debug.Module
	if p.Module != nil {
		main = *debugModFromModinfo(p.Module)
	}

	visited := make(map[*Package]bool)
	mdeps := make(map[module.Version]*debug.Module)
	var q []*Package
	q = append(q, p.Internal.Imports...)
	for len(q) > 0 {
		p1 := q[0]
		q = q[1:]
		if visited[p1] {
			continue
		}
		visited[p1] = true
		if p1.Module != nil {
			m := module.Version{Path: p1.Module.Path, Version: p1.Module.Version}
			if p1.Module.Path != main.Path && mdeps[m] == nil {
				mdeps[m] = debugModFromModinfo(p1.Module)
			}
		}
		q = append(q, p1.Internal.Imports...)
	}
	sortedMods := make([]module.Version, 0, len(mdeps))
	for mod := range mdeps {
		sortedMods = append(sortedMods, mod)
	}
	gover.ModSort(sortedMods)
	deps := make([]*debug.Module, len(sortedMods))
	for i, mod := range sortedMods {
		deps[i] = mdeps[mod]
	}

	pkgPath := p.ImportPath
	if p.Internal.CmdlineFiles {
		pkgPath = "command-line-arguments"
	}
	info := &debug.BuildInfo{
		Path: pkgPath,
		Main: main,
		Deps: deps,
	}
	appendSetting := func(key, value string) {
		appendBuildSetting(info, key, value)
	}

	// Add command-line flags relevant to the build.
	// This is informational, not an exhaustive list.
	// Please keep the list sorted.
	if cfg.BuildASan {
		appendSetting("-asan", "true")
	}
	if BuildAsmflags.present {
		appendSetting("-asmflags", BuildAsmflags.String())
	}
	buildmode := cfg.BuildBuildmode
	if buildmode == "default" {
		if p.Name == "main" {
			buildmode = "exe"
		} else {
			buildmode = "archive"
		}
	}
	appendSetting("-buildmode", buildmode)
	appendSetting("-compiler", cfg.BuildContext.Compiler)
	if gccgoflags := BuildGccgoflags.String(); gccgoflags != "" && cfg.BuildContext.Compiler == "gccgo" {
		appendSetting("-gccgoflags", gccgoflags)
	}
	if gcflags := BuildGcflags.String(); gcflags != "" && cfg.BuildContext.Compiler == "gc" {
		appendSetting("-gcflags", gcflags)
	}
	if ldflags := BuildLdflags.String(); ldflags != "" {
		// https://go.dev/issue/52372: only include ldflags if -trimpath is not set,
		// since it can include system paths through various linker flags (notably
		// -extar, -extld, and -extldflags).
		//
		// TODO: since we control cmd/link, in theory we can parse ldflags to
		// determine whether they may refer to system paths. If we do that, we can
		// redact only those paths from the recorded -ldflags setting and still
		// record the system-independent parts of the flags.
		if !cfg.BuildTrimpath {
			appendSetting("-ldflags", ldflags)
		}
	}
	if cfg.BuildCover {
		appendSetting("-cover", "true")
	}
	if cfg.BuildMSan {
		appendSetting("-msan", "true")
	}
	// N.B. -pgo added later by setPGOProfilePath.
	if cfg.BuildRace {
		appendSetting("-race", "true")
	}
	if tags := cfg.BuildContext.BuildTags; len(tags) > 0 {
		appendSetting("-tags", strings.Join(tags, ","))
	}
	if cfg.BuildTrimpath {
		appendSetting("-trimpath", "true")
	}
	if p.DefaultGODEBUG != "" {
		appendSetting("DefaultGODEBUG", p.DefaultGODEBUG)
	}
	cgo := "0"
	if cfg.BuildContext.CgoEnabled {
		cgo = "1"
	}
	appendSetting("CGO_ENABLED", cgo)
	// https://go.dev/issue/52372: only include CGO flags if -trimpath is not set.
	// (If -trimpath is set, it is possible that these flags include system paths.)
	// If cgo is involved, reproducibility is already pretty well ruined anyway,
	// given that we aren't stamping header or library versions.
	//
	// TODO(bcmills): perhaps we could at least parse the flags and stamp the
	// subset of flags that are known not to be paths?
	if cfg.BuildContext.CgoEnabled && !cfg.BuildTrimpath {
		for _, name := range []string{"CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_LDFLAGS"} {
			appendSetting(name, cfg.Getenv(name))
		}
	}
	appendSetting("GOARCH", cfg.BuildContext.GOARCH)
	if cfg.RawGOEXPERIMENT != "" {
		appendSetting("GOEXPERIMENT", cfg.RawGOEXPERIMENT)
	}
	if fips140.Enabled() {
		appendSetting("GOFIPS140", fips140.Version())
	}
	appendSetting("GOOS", cfg.BuildContext.GOOS)
	if key, val, _ := cfg.GetArchEnv(); key != "" && val != "" {
		appendSetting(key, val)
	}

	// Add VCS status if all conditions are true:
	//
	// - -buildvcs is enabled.
	// - p is a non-test contained within a main module (there may be multiple
	//   main modules in a workspace, but local replacements don't count).
	// - Both the current directory and p's module's root directory are contained
	//   in the same local repository.
	// - We know the VCS commands needed to get the status.
	setVCSError := func(err error) {
		setPkgErrorf("error obtaining VCS status: %v\n\tUse -buildvcs=false to disable VCS stamping.", err)
	}

	var repoDir string
	var vcsCmd *vcs.Cmd
	var err error
	const allowNesting = true

	wantVCS := false
	switch cfg.BuildBuildvcs {
	case "true":
		wantVCS = true // Include VCS metadata even for tests if requested explicitly; see https://go.dev/issue/52648.
	case "auto":
		wantVCS = autoVCS && !p.IsTestOnly()
	case "false":
	default:
		panic(fmt.Sprintf("unexpected value for cfg.BuildBuildvcs: %q", cfg.BuildBuildvcs))
	}

	if wantVCS && p.Module != nil && p.Module.Version == "" && !p.Standard {
		if p.Module.Path == "bootstrap" && cfg.GOROOT == os.Getenv("GOROOT_BOOTSTRAP") {
			// During bootstrapping, the bootstrap toolchain is built in module
			// "bootstrap" (instead of "std"), with GOROOT set to GOROOT_BOOTSTRAP
			// (so the bootstrap toolchain packages don't even appear to be in GOROOT).
			goto omitVCS
		}
		repoDir, vcsCmd, err = vcs.FromDir(base.Cwd(), "", allowNesting)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			setVCSError(err)
			return
		}
		if !str.HasFilePathPrefix(p.Module.Dir, repoDir) &&
			!str.HasFilePathPrefix(repoDir, p.Module.Dir) {
			// The module containing the main package does not overlap with the
			// repository containing the working directory. Don't include VCS info.
			// If the repo contains the module or vice versa, but they are not
			// the same directory, it's likely an error (see below).
			goto omitVCS
		}
		if cfg.BuildBuildvcs == "auto" && vcsCmd != nil && vcsCmd.Cmd != "" {
			if _, err := pathcache.LookPath(vcsCmd.Cmd); err != nil {
				// We fould a repository, but the required VCS tool is not present.
				// "-buildvcs=auto" means that we should silently drop the VCS metadata.
				goto omitVCS
			}
		}
	}
	if repoDir != "" && vcsCmd.Status != nil {
		// Check that the current directory, package, and module are in the same
		// repository. vcs.FromDir allows nested Git repositories, but nesting
		// is not allowed for other VCS tools. The current directory may be outside
		// p.Module.Dir when a workspace is used.
		pkgRepoDir, _, err := vcs.FromDir(p.Dir, "", allowNesting)
		if err != nil {
			setVCSError(err)
			return
		}
		if pkgRepoDir != repoDir {
			if cfg.BuildBuildvcs != "auto" {
				setVCSError(fmt.Errorf("main package is in repository %q but current directory is in repository %q", pkgRepoDir, repoDir))
				return
			}
			goto omitVCS
		}
		modRepoDir, _, err := vcs.FromDir(p.Module.Dir, "", allowNesting)
		if err != nil {
			setVCSError(err)
			return
		}
		if modRepoDir != repoDir {
			if cfg.BuildBuildvcs != "auto" {
				setVCSError(fmt.Errorf("main module is in repository %q but current directory is in repository %q", modRepoDir, repoDir))
				return
			}
			goto omitVCS
		}

		st, err := vcsStatusCache.Do(repoDir, func() (vcs.Status, error) {
			return vcsCmd.Status(vcsCmd, repoDir)
		})
		if err != nil {
			setVCSError(err)
			return
		}

		appendSetting("vcs", vcsCmd.Cmd)
		if st.Revision != "" {
			appendSetting("vcs.revision", st.Revision)
		}
		if !st.CommitTime.IsZero() {
			stamp := st.CommitTime.UTC().Format(time.RFC3339Nano)
			appendSetting("vcs.time", stamp)
		}
		appendSetting("vcs.modified", strconv.FormatBool(st.Uncommitted))
		// Determine the correct version of this module at the current revision and update the build metadata accordingly.
		repo := modfetch.LookupLocal(ctx, repoDir)
		revInfo, err := repo.Stat(ctx, st.Revision)
		if err != nil {
			goto omitVCS
		}
		vers := revInfo.Version
		if vers != "" {
			if st.Uncommitted {
				vers += "+dirty"
			}
			info.Main.Version = vers
		}
	}
omitVCS:

	p.Internal.BuildInfo = info
}

// SafeArg reports whether arg is a "safe" command-line argument,
// meaning that when it appears in a command-line, it probably
// doesn't have some special meaning other than its own name.
// Obviously args beginning with - are not safe (they look like flags).
// Less obviously, args beginning with @ are not safe (they look like
// GNU binutils flagfile specifiers, sometimes called "response files").
// To be conservative, we reject almost any arg beginning with non-alphanumeric ASCII.
// We accept leading . _ and / as likely in file system paths.
// There is a copy of this function in cmd/compile/internal/gc/noder.go.
func SafeArg(name string) bool {
	if name == "" {
		return false
	}
	c := name[0]
	return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || c == '.' || c == '_' || c == '/' || c >= utf8.RuneSelf
}

// LinkerDeps returns the list of linker-induced dependencies for main package p.
func LinkerDeps(p *Package) ([]string, error) {
	// Everything links runtime.
	deps := []string{"runtime"}

	// External linking mode forces an import of runtime/cgo.
	if what := externalLinkingReason(p); what != "" && cfg.BuildContext.Compiler != "gccgo" {
		if !cfg.BuildContext.CgoEnabled {
			return nil, fmt.Errorf("%s requires external (cgo) linking, but cgo is not enabled", what)
		}
		deps = append(deps, "runtime/cgo")
	}
	// On ARM with GOARM=5, it forces an import of math, for soft floating point.
	if cfg.Goarch == "arm" {
		deps = append(deps, "math")
	}
	// Using the race detector forces an import of runtime/race.
	if cfg.BuildRace {
		deps = append(deps, "runtime/race")
	}
	// Using memory sanitizer forces an import of runtime/msan.
	if cfg.BuildMSan {
		deps = append(deps, "runtime/msan")
	}
	// Using address sanitizer forces an import of runtime/asan.
	if cfg.BuildASan {
		deps = append(deps, "runtime/asan")
	}
	// Building for coverage forces an import of runtime/coverage.
	if cfg.BuildCover && cfg.Experiment.CoverageRedesign {
		deps = append(deps, "runtime/coverage")
	}

	return deps, nil
}

// externalLinkingReason reports the reason external linking is required
// even for programs that do not use cgo, or the empty string if external
// linking is not required.
func externalLinkingReason(p *Package) (what string) {
	// Some targets must use external linking even inside GOROOT.
	if platform.MustLinkExternal(cfg.Goos, cfg.Goarch, false) {
		return cfg.Goos + "/" + cfg.Goarch
	}

	// Some build modes always require external linking.
	switch cfg.BuildBuildmode {
	case "c-shared":
		if cfg.BuildContext.GOARCH == "wasm" {
			break
		}
		fallthrough
	case "plugin":
		return "-buildmode=" + cfg.BuildBuildmode
	}

	// Using -linkshared always requires external linking.
	if cfg.BuildLinkshared {
		return "-linkshared"
	}

	// Decide whether we are building a PIE,
	// bearing in mind that some systems default to PIE.
	isPIE := false
	if cfg.BuildBuildmode == "pie" {
		isPIE = true
	} else if cfg.BuildBuildmode == "default" && platform.DefaultPIE(cfg.BuildContext.GOOS, cfg.BuildContext.GOARCH, cfg.BuildRace) {
		isPIE = true
	}
	// If we are building a PIE, and we are on a system
	// that does not support PIE with internal linking mode,
	// then we must use external linking.
	if isPIE && !platform.InternalLinkPIESupported(cfg.BuildContext.GOOS, cfg.BuildContext.GOARCH) {
		if cfg.BuildBuildmode == "pie" {
			return "-buildmode=pie"
		}
		return "default PIE binary"
	}

	// Using -ldflags=-linkmode=external forces external linking.
	// If there are multiple -linkmode options, the last one wins.
	if p != nil {
		ldflags := BuildLdflags.For(p)
		for i := len(ldflags) - 1; i >= 0; i-- {
			a := ldflags[i]
			if a == "-linkmode=external" ||
				a == "-linkmode" && i+1 < len(ldflags) && ldflags[i+1] == "external" {
				return a
			} else if a == "-linkmode=internal" ||
				a == "-linkmode" && i+1 < len(ldflags) && ldflags[i+1] == "internal" {
				return ""
			}
		}
	}

	return ""
}

// mkAbs rewrites list, which must be paths relative to p.Dir,
// into a sorted list of absolute paths. It edits list in place but for
// convenience also returns list back to its caller.
func (p *Package) mkAbs(list []string) []string {
	for i, f := range list {
		list[i] = filepath.Join(p.Dir, f)
	}
	sort.Strings(list)
	return list
}

// InternalGoFiles returns the list of Go files being built for the package,
// using absolute paths.
func (p *Package) InternalGoFiles() []string {
	return p.mkAbs(str.StringList(p.GoFiles, p.CgoFiles, p.TestGoFiles))
}

// InternalXGoFiles returns the list of Go files being built for the XTest package,
// using absolute paths.
func (p *Package) InternalXGoFiles() []string {
	return p.mkAbs(p.XTestGoFiles)
}

// InternalAllGoFiles returns the list of all Go files possibly relevant for the package,
// using absolute paths. "Possibly relevant" means that files are not excluded
// due to build tags, but files with names beginning with . or _ are still excluded.
func (p *Package) InternalAllGoFiles() []string {
	return p.mkAbs(str.StringList(p.IgnoredGoFiles, p.GoFiles, p.CgoFiles, p.TestGoFiles, p.XTestGoFiles))
}

// UsesSwig reports whether the package needs to run SWIG.
func (p *Package) UsesSwig() bool {
	return len(p.SwigFiles) > 0 || len(p.SwigCXXFiles) > 0
}

// UsesCgo reports whether the package needs to run cgo
func (p *Package) UsesCgo() bool {
	return len(p.CgoFiles) > 0
}

// PackageList returns the list of packages in the dag rooted at roots
// as visited in a depth-first post-order traversal.
func PackageList(roots []*Package) []*Package {
	seen := map[*Package]bool{}
	all := []*Package{}
	var walk func(*Package)
	walk = func(p *Package) {
		if seen[p] {
			return
		}
		seen[p] = true
		for _, p1 := range p.Internal.Imports {
			walk(p1)
		}
		all = append(all, p)
	}
	for _, root := range roots {
		walk(root)
	}
	return all
}

// TestPackageList returns the list of packages in the dag rooted at roots
// as visited in a depth-first post-order traversal, including the test
// imports of the roots. This ignores errors in test packages.
func TestPackageList(ctx context.Context, opts PackageOpts, roots []*Package) []*Package {
	seen := map[*Package]bool{}
	all := []*Package{}
	var walk func(*Package)
	walk = func(p *Package) {
		if seen[p] {
			return
		}
		seen[p] = true
		for _, p1 := range p.Internal.Imports {
			walk(p1)
		}
		all = append(all, p)
	}
	walkTest := func(root *Package, path string) {
		var stk ImportStack
		p1, err := loadImport(ctx, opts, nil, path, root.Dir, root, &stk, root.Internal.Build.TestImportPos[path], ResolveImport)
		if err != nil && root.Error == nil {
			// Assign error importing the package to the importer.
			root.Error = err
			root.Incomplete = true
		}
		if p1.Error == nil {
			walk(p1)
		}
	}
	for _, root := range roots {
		walk(root)
		for _, path := range root.TestImports {
			walkTest(root, path)
		}
		for _, path := range root.XTestImports {
			walkTest(root, path)
		}
	}
	return all
}

// LoadImportWithFlags loads the package with the given import path and
// sets tool flags on that package. This function is useful loading implicit
// dependencies (like sync/atomic for coverage).
// TODO(jayconrod): delete this function and set flags automatically
// in LoadImport instead.
func LoadImportWithFlags(path, srcDir string, parent *Package, stk *ImportStack, importPos []token.Position, mode int) (*Package, *PackageError) {
	p, err := loadImport(context.TODO(), PackageOpts{}, nil, path, srcDir, parent, stk, importPos, mode)
	setToolFlags(p)
	return p, err
}

// LoadPackageWithFlags is the same as LoadImportWithFlags but without a parent.
// It's then guaranteed to not return an error
func LoadPackageWithFlags(path, srcDir string, stk *ImportStack, importPos []token.Position, mode int) *Package {
	p := LoadPackage(context.TODO(), PackageOpts{}, path, srcDir, stk, importPos, mode)
	setToolFlags(p)
	return p
}

// PackageOpts control the behavior of PackagesAndErrors and other package
// loading functions.
type PackageOpts struct {
	// IgnoreImports controls whether we ignore explicit and implicit imports
	// when loading packages.  Implicit imports are added when supporting Cgo
	// or SWIG and when linking main packages.
	IgnoreImports bool

	// ModResolveTests indicates whether calls to the module loader should also
	// resolve test dependencies of the requested packages.
	//
	// If ModResolveTests is true, then the module loader needs to resolve test
	// dependencies at the same time as packages; otherwise, the test dependencies
	// of those packages could be missing, and resolving those missing dependencies
	// could change the selected versions of modules that provide other packages.
	ModResolveTests bool

	// MainOnly is true if the caller only wants to load main packages.
	// For a literal argument matching a non-main package, a stub may be returned
	// with an error. For a non-literal argument (with "..."), non-main packages
	// are not be matched, and their dependencies may not be loaded. A warning
	// may be printed for non-literal arguments that match no main packages.
	MainOnly bool

	// AutoVCS controls whether we also load version-control metadata for main packages
	// when -buildvcs=auto (the default).
	AutoVCS bool

	// SuppressBuildInfo is true if the caller does not need p.Stale, p.StaleReason, or p.Internal.BuildInfo
	// to be populated on the package.
	SuppressBuildInfo bool

	// SuppressEmbedFiles is true if the caller does not need any embed files to be populated on the
	// package.
	SuppressEmbedFiles bool
}

// PackagesAndErrors returns the packages named by the command line arguments
// 'patterns'. If a named package cannot be loaded, PackagesAndErrors returns
// a *Package with the Error field describing the failure. If errors are found
// loading imported packages, the DepsErrors field is set. The Incomplete field
// may be set as well.
//
// To obtain a flat list of packages, use PackageList.
// To report errors loading packages, use ReportPackageErrors.
func PackagesAndErrors(ctx context.Context, opts PackageOpts, patterns []string) []*Package {
	ctx, span := trace.StartSpan(ctx, "load.PackagesAndErrors")
	defer span.Done()

	for _, p := range patterns {
		// Listing is only supported with all patterns referring to either:
		// - Files that are part of the same directory.
		// - Explicit package paths or patterns.
		if strings.HasSuffix(p, ".go") {
			// We need to test whether the path is an actual Go file and not a
			// package path or pattern ending in '.go' (see golang.org/issue/34653).
			if fi, err := fsys.Stat(p); err == nil && !fi.IsDir() {
				pkgs := []*Package{GoFilesPackage(ctx, opts, patterns)}
				setPGOProfilePath(pkgs)
				return pkgs
			}
		}
	}

	var matches []*search.Match
	if modload.Init(); cfg.ModulesEnabled {
		modOpts := modload.PackageOpts{
			ResolveMissingImports: true,
			LoadTests:             opts.ModResolveTests,
			SilencePackageErrors:  true,
		}
		matches, _ = modload.LoadPackages(ctx, modOpts, patterns...)
	} else {
		noModRoots := []string{}
		matches = search.ImportPaths(patterns, noModRoots)
	}

	var (
		pkgs    []*Package
		stk     ImportStack
		seenPkg = make(map[*Package]bool)
	)

	pre := newPreload()
	defer pre.flush()
	pre.preloadMatches(ctx, opts, matches)

	for _, m := range matches {
		for _, pkg := range m.Pkgs {
			if pkg == "" {
				panic(fmt.Sprintf("ImportPaths returned empty package for pattern %s", m.Pattern()))
			}
			mode := cmdlinePkg
			if m.IsLiteral() {
				// Note: do not set = m.IsLiteral unconditionally
				// because maybe we'll see p matching both
				// a literal and also a non-literal pattern.
				mode |= cmdlinePkgLiteral
			}
			p, perr := loadImport(ctx, opts, pre, pkg, base.Cwd(), nil, &stk, nil, mode)
			if perr != nil {
				base.Fatalf("internal error: loadImport of %q with nil parent returned an error", pkg)
			}
			p.Match = append(p.Match, m.Pattern())
			if seenPkg[p] {
				continue
			}
			seenPkg[p] = true
			pkgs = append(pkgs, p)
		}

		if len(m.Errs) > 0 {
			// In addition to any packages that were actually resolved from the
			// pattern, there was some error in resolving the pattern itself.
			// Report it as a synthetic package.
			p := new(Package)
			p.ImportPath = m.Pattern()
			// Pass an empty ImportStack and nil importPos: the error arose from a pattern, not an import.
			var stk ImportStack
			var importPos []token.Position
			p.setLoadPackageDataError(m.Errs[0], m.Pattern(), &stk, importPos)
			p.Incomplete = true
			p.Match = append(p.Match, m.Pattern())
			p.Internal.CmdlinePkg = true
			if m.IsLiteral() {
				p.Internal.CmdlinePkgLiteral = true
			}
			pkgs = append(pkgs, p)
		}
	}

	if opts.MainOnly {
		pkgs = mainPackagesOnly(pkgs, matches)
	}

	// Now that CmdlinePkg is set correctly,
	// compute the effective flags for all loaded packages
	// (not just the ones matching the patterns but also
	// their dependencies).
	setToolFlags(pkgs...)

	setPGOProfilePath(pkgs)

	return pkgs
}

// setPGOProfilePath sets the PGO profile path for pkgs.
// In -pgo=auto mode, it finds the default PGO profile.
func setPGOProfilePath(pkgs []*Package) {
	updateBuildInfo := func(p *Package, file string) {
		// Don't create BuildInfo for packages that didn't already have it.
		if p.Internal.BuildInfo == nil {
			return
		}

		if cfg.BuildTrimpath {
			appendBuildSetting(p.Internal.BuildInfo, "-pgo", filepath.Base(file))
		} else {
			appendBuildSetting(p.Internal.BuildInfo, "-pgo", file)
		}
		// Adding -pgo breaks the sort order in BuildInfo.Settings. Restore it.
		slices.SortFunc(p.Internal.BuildInfo.Settings, func(x, y debug.BuildSetting) int {
			return strings.Compare(x.Key, y.Key)
		})
	}

	switch cfg.BuildPGO {
	case "off":
		return

	case "auto":
		// Locate PGO profiles from the main packages, and
		// attach the profile to the main package and its
		// dependencies.
		// If we're building multiple main packages, they may
		// have different profiles. We may need to split (unshare)
		// the dependency graph so they can attach different
		// profiles.
		for _, p := range pkgs {
			if p.Name != "main" {
				continue
			}
			pmain := p
			file := filepath.Join(pmain.Dir, "default.pgo")
			if _, err := os.Stat(file); err != nil {
				continue // no profile
			}

			// Packages already visited. The value should replace
			// the key, as it may be a forked copy of the original
			// Package.
			visited := make(map[*Package]*Package)
			var split func(p *Package) *Package
			split = func(p *Package) *Package {
				if p1 := visited[p]; p1 != nil {
					return p1
				}

				if len(pkgs) > 1 && p != pmain {
					// Make a copy, then attach profile.
					// No need to copy if there is only one root package (we can
					// attach profile directly in-place).
					// Also no need to copy the main package.
					if p.Internal.PGOProfile != "" {
						panic("setPGOProfilePath: already have profile")
					}
					p1 := new(Package)
					*p1 = *p
					// Unalias the Imports and Internal.Imports slices,
					// which we're going to modify. We don't copy other slices as
					// we don't change them.
					p1.Imports = slices.Clone(p.Imports)
					p1.Internal.Imports = slices.Clone(p.Internal.Imports)
					p1.Internal.ForMain = pmain.ImportPath
					visited[p] = p1
					p = p1
				} else {
					visited[p] = p
				}
				p.Internal.PGOProfile = file
				updateBuildInfo(p, file)
				// Recurse to dependencies.
				for i, pp := range p.Internal.Imports {
					p.Internal.Imports[i] = split(pp)
				}
				return p
			}

			// Replace the package and imports with the PGO version.
			split(pmain)
		}

	default:
		// Profile specified from the command line.
		// Make it absolute path, as the compiler runs on various directories.
		file, err := filepath.Abs(cfg.BuildPGO)
		if err != nil {
			base.Fatalf("fail to get absolute path of PGO file %s: %v", cfg.BuildPGO, err)
		}

		for _, p := range PackageList(pkgs) {
			p.Internal.PGOProfile = file
			updateBuildInfo(p, file)
		}
	}
}

// CheckPackageErrors prints errors encountered loading pkgs and their
// dependencies, then exits with a non-zero status if any errors were found.
func CheckPackageErrors(pkgs []*Package) {
	PackageErrors(pkgs, func(p *Package) {
		DefaultPrinter().Errorf(p, "%v", p.Error)
	})
	base.ExitIfErrors()
}

// PackageErrors calls report for errors encountered loading pkgs and their dependencies.
func PackageErrors(pkgs []*Package, report func(*Package)) {
	var anyIncomplete, anyErrors bool
	for _, pkg := range pkgs {
		if pkg.Incomplete {
			anyIncomplete = true
		}
	}
	if anyIncomplete {
		all := PackageList(pkgs)
		for _, p := range all {
			if p.Error != nil {
				report(p)
				anyErrors = true
			}
		}
	}
	if anyErrors {
		return
	}

	// Check for duplicate loads of the same package.
	// That should be impossible, but if it does happen then
	// we end up trying to build the same package twice,
	// usually in parallel overwriting the same files,
	// which doesn't work very well.
	seen := map[string]bool{}
	reported := map[string]bool{}
	for _, pkg := range PackageList(pkgs) {
		// -pgo=auto with multiple main packages can cause a package being
		// built multiple times (with different profiles).
		// We check that package import path + profile path is unique.
		key := pkg.ImportPath
		if pkg.Internal.PGOProfile != "" {
			key += " pgo:" + pkg.Internal.PGOProfile
		}
		if seen[key] && !reported[key] {
			reported[key] = true
			base.Errorf("internal error: duplicate loads of %s", pkg.ImportPath)
		}
		seen[key] = true
	}
	if len(reported) > 0 {
		base.ExitIfErrors()
	}
}

// mainPackagesOnly filters out non-main packages matched only by arguments
// containing "..." and returns the remaining main packages.
//
// Packages with missing, invalid, or ambiguous names may be treated as
// possibly-main packages.
//
// mainPackagesOnly sets a non-main package's Error field and returns it if it
// is named by a literal argument.
//
// mainPackagesOnly prints warnings for non-literal arguments that only match
// non-main packages.
func mainPackagesOnly(pkgs []*Package, matches []*search.Match) []*Package {
	treatAsMain := map[string]bool{}
	for _, m := range matches {
		if m.IsLiteral() {
			for _, path := range m.Pkgs {
				treatAsMain[path] = true
			}
		}
	}

	var mains []*Package
	for _, pkg := range pkgs {
		if pkg.Name == "main" || (pkg.Name == "" && pkg.Error != nil) {
			treatAsMain[pkg.ImportPath] = true
			mains = append(mains, pkg)
			continue
		}

		if len(pkg.InvalidGoFiles) > 0 { // TODO(#45999): && pkg.Name == "", but currently go/build sets pkg.Name arbitrarily if it is ambiguous.
			// The package has (or may have) conflicting names, and we can't easily
			// tell whether one of them is "main". So assume that it could be, and
			// report an error for the package.
			treatAsMain[pkg.ImportPath] = true
		}
		if treatAsMain[pkg.ImportPath] {
			if pkg.Error == nil {
				pkg.Error = &PackageError{Err: &mainPackageError{importPath: pkg.ImportPath}}
				pkg.Incomplete = true
			}
			mains = append(mains, pkg)
		}
	}

	for _, m := range matches {
		if m.IsLiteral() || len(m.Pkgs) == 0 {
			continue
		}
		foundMain := false
		for _, path := range m.Pkgs {
			if treatAsMain[path] {
				foundMain = true
				break
			}
		}
		if !foundMain {
			fmt.Fprintf(os.Stderr, "go: warning: %q matched only non-main packages\n", m.Pattern())
		}
	}

	return mains
}

type mainPackageError struct {
	importPath string
}

func (e *mainPackageError) Error() string {
	return fmt.Sprintf("package %s is not a main package", e.importPath)
}

func (e *mainPackageError) ImportPath() string {
	return e.importPath
}

func setToolFlags(pkgs ...*Package) {
	for _, p := range PackageList(pkgs) {
		p.Internal.Asmflags = BuildAsmflags.For(p)
		p.Internal.Gcflags = BuildGcflags.For(p)
		p.Internal.Ldflags = BuildLdflags.For(p)
		p.Internal.Gccgoflags = BuildGccgoflags.For(p)
	}
}

// GoFilesPackage creates a package for building a collection of Go files
// (typically named on the command line). The target is named p.a for
// package p or named after the first Go file for package main.
func GoFilesPackage(ctx context.Context, opts PackageOpts, gofiles []string) *Package {
	modload.Init()

	for _, f := range gofiles {
		if !strings.HasSuffix(f, ".go") {
			pkg := new(Package)
			pkg.Internal.Local = true
			pkg.Internal.CmdlineFiles = true
			pkg.Name = f
			pkg.Error = &PackageError{
				Err: fmt.Errorf("named files must be .go files: %s", pkg.Name),
			}
			pkg.Incomplete = true
			return pkg
		}
	}

	var stk ImportStack
	ctxt := cfg.BuildContext
	ctxt.UseAllFiles = true

	// Synthesize fake "directory" that only shows the named files,
	// to make it look like this is a standard package or
	// command directory. So that local imports resolve
	// consistently, the files must all be in the same directory.
	var dirent []fs.FileInfo
	var dir string
	for _, file := range gofiles {
		fi, err := fsys.Stat(file)
		if err != nil {
			base.Fatalf("%s", err)
		}
		if fi.IsDir() {
			base.Fatalf("%s is a directory, should be a Go file", file)
		}
		dir1 := filepath.Dir(file)
		if dir == "" {
			dir = dir1
		} else if dir != dir1 {
			base.Fatalf("named files must all be in one directory; have %s and %s", dir, dir1)
		}
		dirent = append(dirent, fi)
	}
	ctxt.ReadDir = func(string) ([]fs.FileInfo, error) { return dirent, nil }

	if cfg.ModulesEnabled {
		modload.ImportFromFiles(ctx, gofiles)
	}

	var err error
	if dir == "" {
		dir = base.Cwd()
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		base.Fatalf("%s", err)
	}

	bp, err := ctxt.ImportDir(dir, 0)
	pkg := new(Package)
	pkg.Internal.Local = true
	pkg.Internal.CmdlineFiles = true
	pkg.load(ctx, opts, "command-line-arguments", &stk, nil, bp, err)
	if !cfg.ModulesEnabled {
		pkg.Internal.LocalPrefix = dirToImportPath(dir)
	}
	pkg.ImportPath = "command-line-arguments"
	pkg.Target = ""
	pkg.Match = gofiles

	if pkg.Name == "main" {
		exe := pkg.DefaultExecName() + cfg.ExeSuffix

		if cfg.GOBIN != "" {
			pkg.Target = filepath.Join(cfg.GOBIN, exe)
		} else if cfg.ModulesEnabled {
			pkg.Target = filepath.Join(modload.BinDir(), exe)
		}
	}

	if opts.MainOnly && pkg.Name != "main" && pkg.Error == nil {
		pkg.Error = &PackageError{Err: &mainPackageError{importPath: pkg.ImportPath}}
		pkg.Incomplete = true
	}
	setToolFlags(pkg)

	return pkg
}

// PackagesAndErrorsOutsideModule is like PackagesAndErrors but runs in
// module-aware mode and ignores the go.mod file in the current directory or any
// parent directory, if there is one. This is used in the implementation of 'go
// install pkg@version' and other commands that support similar forms.
//
// modload.ForceUseModules must be true, and modload.RootMode must be NoRoot
// before calling this function.
//
// PackagesAndErrorsOutsideModule imposes several constraints to avoid
// ambiguity. All arguments must have the same version suffix (not just a suffix
// that resolves to the same version). They must refer to packages in the same
// module, which must not be std or cmd. That module is not considered the main
// module, but its go.mod file (if it has one) must not contain directives that
// would cause it to be interpreted differently if it were the main module
// (replace, exclude).
func PackagesAndErrorsOutsideModule(ctx context.Context, opts PackageOpts, args []string) ([]*Package, error) {
	if !modload.ForceUseModules {
		panic("modload.ForceUseModules must be true")
	}
	if modload.RootMode != modload.NoRoot {
		panic("modload.RootMode must be NoRoot")
	}

	// Check that the arguments satisfy syntactic constraints.
	var version string
	var firstPath string
	for _, arg := range args {
		if i := strings.Index(arg, "@"); i >= 0 {
			firstPath, version = arg[:i], arg[i+1:]
			if version == "" {
				return nil, fmt.Errorf("%s: version must not be empty", arg)
			}
			break
		}
	}
	patterns := make([]string, len(args))
	for i, arg := range args {
		p, found := strings.CutSuffix(arg, "@"+version)
		if !found {
			return nil, fmt.Errorf("%s: all arguments must refer to packages in the same module at the same version (@%s)", arg, version)
		}
		switch {
		case build.IsLocalImport(p):
			return nil, fmt.Errorf("%s: argument must be a package path, not a relative path", arg)
		case filepath.IsAbs(p):
			return nil, fmt.Errorf("%s: argument must be a package path, not an absolute path", arg)
		case search.IsMetaPackage(p):
			return nil, fmt.Errorf("%s: argument must be a package path, not a meta-package", arg)
		case pathpkg.Clean(p) != p:
			return nil, fmt.Errorf("%s: argument must be a clean package path", arg)
		case !strings.Contains(p, "...") && search.IsStandardImportPath(p) && modindex.IsStandardPackage(cfg.GOROOT, cfg.BuildContext.Compiler, p):
			return nil, fmt.Errorf("%s: argument must not be a package in the standard library", arg)
		default:
			patterns[i] = p
		}
	}

	// Query the module providing the first argument, load its go.mod file, and
	// check that it doesn't contain directives that would cause it to be
	// interpreted differently if it were the main module.
	//
	// If multiple modules match the first argument, accept the longest match
	// (first result). It's possible this module won't provide packages named by
	// later arguments, and other modules would. Let's not try to be too
	// magical though.
	allowed := modload.CheckAllowed
	if modload.IsRevisionQuery(firstPath, version) {
		// Don't check for retractions if a specific revision is requested.
		allowed = nil
	}
	noneSelected := func(path string) (version string) { return "none" }
	qrs, err := modload.QueryPackages(ctx, patterns[0], version, noneSelected, allowed)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", args[0], err)
	}
	rootMod := qrs[0].Mod
	deprecation, err := modload.CheckDeprecation(ctx, rootMod)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", args[0], err)
	}
	if deprecation != "" {
		fmt.Fprintf(os.Stderr, "go: module %s is deprecated: %s\n", rootMod.Path, modload.ShortMessage(deprecation, ""))
	}
	data, err := modfetch.GoMod(ctx, rootMod.Path, rootMod.Version)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", args[0], err)
	}
	f, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		return nil, fmt.Errorf("%s (in %s): %w", args[0], rootMod, err)
	}
	directiveFmt := "%s (in %s):\n" +
		"\tThe go.mod file for the module providing named packages contains one or\n" +
		"\tmore %s directives. It must not contain directives that would cause\n" +
		"\tit to be interpreted differently than if it were the main module."
	if len(f.Replace) > 0 {
		return nil, fmt.Errorf(directiveFmt, args[0], rootMod, "replace")
	}
	if len(f.Exclude) > 0 {
		return nil, fmt.Errorf(directiveFmt, args[0], rootMod, "exclude")
	}

	// Since we are in NoRoot mode, the build list initially contains only
	// the dummy command-line-arguments module. Add a requirement on the
	// module that provides the packages named on the command line.
	if _, err := modload.EditBuildList(ctx, nil, []module.Version{rootMod}); err != nil {
		return nil, fmt.Errorf("%s: %w", args[0], err)
	}

	// Load packages for all arguments.
	pkgs := PackagesAndErrors(ctx, opts, patterns)

	// Check that named packages are all provided by the same module.
	for _, pkg := range pkgs {
		var pkgErr error
		if pkg.Module == nil {
			// Packages in std, cmd, and their vendored dependencies
			// don't have this field set.
			pkgErr = fmt.Errorf("package %s not provided by module %s", pkg.ImportPath, rootMod)
		} else if pkg.Module.Path != rootMod.Path || pkg.Module.Version != rootMod.Version {
			pkgErr = fmt.Errorf("package %s provided by module %s@%s\n\tAll packages must be provided by the same module (%s).", pkg.ImportPath, pkg.Module.Path, pkg.Module.Version, rootMod)
		}
		if pkgErr != nil && pkg.Error == nil {
			pkg.Error = &PackageError{Err: pkgErr}
			pkg.Incomplete = true
		}
	}

	matchers := make([]func(string) bool, len(patterns))
	for i, p := range patterns {
		if strings.Contains(p, "...") {
			matchers[i] = pkgpattern.MatchPattern(p)
		}
	}
	return pkgs, nil
}

// EnsureImport ensures that package p imports the named package.
func EnsureImport(p *Package, pkg string) {
	for _, d := range p.Internal.Imports {
		if d.Name == pkg {
			return
		}
	}

	p1, err := LoadImportWithFlags(pkg, p.Dir, p, &ImportStack{}, nil, 0)
	if err != nil {
		base.Fatalf("load %s: %v", pkg, err)
	}
	if p1.Error != nil {
		base.Fatalf("load %s: %v", pkg, p1.Error)
	}

	p.Internal.Imports = append(p.Internal.Imports, p1)
}

// PrepareForCoverageBuild is a helper invoked for "go install
// -cover", "go run -cover", and "go build -cover" (but not used by
// "go test -cover"). It walks through the packages being built (and
// dependencies) and marks them for coverage instrumentation when
// appropriate, and possibly adding additional deps where needed.
func PrepareForCoverageBuild(pkgs []*Package) {
	var match []func(*Package) bool

	matchMainModAndCommandLine := func(p *Package) bool {
		// note that p.Standard implies p.Module == nil below.
		return p.Internal.CmdlineFiles || p.Internal.CmdlinePkg || (p.Module != nil && p.Module.Main)
	}

	if len(cfg.BuildCoverPkg) != 0 {
		// If -coverpkg has been specified, then we instrument only
		// the specific packages selected by the user-specified pattern(s).
		match = make([]func(*Package) bool, len(cfg.BuildCoverPkg))
		for i := range cfg.BuildCoverPkg {
			match[i] = MatchPackage(cfg.BuildCoverPkg[i], base.Cwd())
		}
	} else {
		// Without -coverpkg, instrument only packages in the main module
		// (if any), as well as packages/files specifically named on the
		// command line.
		match = []func(*Package) bool{matchMainModAndCommandLine}
	}

	// Visit the packages being built or installed, along with all of
	// their dependencies, and mark them to be instrumented, taking
	// into account the matchers we've set up in the sequence above.
	SelectCoverPackages(PackageList(pkgs), match, "build")
}

func SelectCoverPackages(roots []*Package, match []func(*Package) bool, op string) []*Package {
	var warntag string
	var includeMain bool
	switch op {
	case "build":
		warntag = "built"
		includeMain = true
	case "test":
		warntag = "tested"
	default:
		panic("internal error, bad mode passed to SelectCoverPackages")
	}

	covered := []*Package{}
	matched := make([]bool, len(match))
	for _, p := range roots {
		haveMatch := false
		for i := range match {
			if match[i](p) {
				matched[i] = true
				haveMatch = true
			}
		}
		if !haveMatch {
			continue
		}

		// There is nothing to cover in package unsafe; it comes from
		// the compiler.
		if p.ImportPath == "unsafe" {
			continue
		}

		// A package which only has test files can't be imported as a
		// dependency, and at the moment we don't try to instrument it
		// for coverage. There isn't any technical reason why
		// *_test.go files couldn't be instrumented, but it probably
		// doesn't make much sense to lump together coverage metrics
		// (ex: percent stmts covered) of *_test.go files with
		// non-test Go code.
		if len(p.GoFiles)+len(p.CgoFiles) == 0 {
			continue
		}

		// Silently ignore attempts to run coverage on sync/atomic
		// and/or internal/runtime/atomic when using atomic coverage
		// mode. Atomic coverage mode uses sync/atomic, so we can't
		// also do coverage on it.
		if cfg.BuildCoverMode == "atomic" && p.Standard &&
			(p.ImportPath == "sync/atomic" || p.ImportPath == "internal/runtime/atomic") {
			continue
		}

		// If using the race detector, silently ignore attempts to run
		// coverage on the runtime packages. It will cause the race
		// detector to be invoked before it has been initialized. Note
		// the use of "regonly" instead of just ignoring the package
		// completely-- we do this due to the requirements of the
		// package ID numbering scheme. See the comment in
		// $GOROOT/src/internal/coverage/pkid.go dealing with
		// hard-coding of runtime package IDs.
		cmode := cfg.BuildCoverMode
		if cfg.BuildRace && p.Standard && (p.ImportPath == "runtime" || strings.HasPrefix(p.ImportPath, "runtime/internal")) {
			cmode = "regonly"
		}

		// If -coverpkg is in effect and for some reason we don't want
		// coverage data for the main package, make sure that we at
		// least process it for registration hooks.
		if includeMain && p.Name == "main" && !haveMatch {
			haveMatch = true
			cmode = "regonly"
		}

		// Mark package for instrumentation.
		p.Internal.Cover.Mode = cmode
		covered = append(covered, p)

		// Force import of sync/atomic into package if atomic mode.
		if cfg.BuildCoverMode == "atomic" {
			EnsureImport(p, "sync/atomic")
		}

		// Generate covervars if using legacy coverage design.
		if !cfg.Experiment.CoverageRedesign {
			var coverFiles []string
			coverFiles = append(coverFiles, p.GoFiles...)
			coverFiles = append(coverFiles, p.CgoFiles...)
			p.Internal.CoverVars = DeclareCoverVars(p, coverFiles...)
		}
	}

	// Warn about -coverpkg arguments that are not actually used.
	for i := range cfg.BuildCoverPkg {
		if !matched[i] {
			fmt.Fprintf(os.Stderr, "warning: no packages being %s depend on matches for pattern %s\n", warntag, cfg.BuildCoverPkg[i])
		}
	}

	return covered
}

// DeclareCoverVars attaches the required cover variables names
// to the files, to be used when annotating the files. This
// function only called when using legacy coverage test/build
// (e.g. GOEXPERIMENT=coverageredesign is off).
func DeclareCoverVars(p *Package, files ...string) map[string]*CoverVar {
	coverVars := make(map[string]*CoverVar)
	coverIndex := 0
	// We create the cover counters as new top-level variables in the package.
	// We need to avoid collisions with user variables (GoCover_0 is unlikely but still)
	// and more importantly with dot imports of other covered packages,
	// so we append 12 hex digits from the SHA-256 of the import path.
	// The point is only to avoid accidents, not to defeat users determined to
	// break things.
	sum := sha256.Sum256([]byte(p.ImportPath))
	h := fmt.Sprintf("%x", sum[:6])
	for _, file := range files {
		if base.IsTestFile(file) {
			continue
		}
		// For a package that is "local" (imported via ./ import or command line, outside GOPATH),
		// we record the full path to the file name.
		// Otherwise we record the import path, then a forward slash, then the file name.
		// This makes profiles within GOPATH file system-independent.
		// These names appear in the cmd/cover HTML interface.
		var longFile string
		if p.Internal.Local {
			longFile = filepath.Join(p.Dir, file)
		} else {
			longFile = pathpkg.Join(p.ImportPath, file)
		}
		coverVars[file] = &CoverVar{
			File: longFile,
			Var:  fmt.Sprintf("GoCover_%d_%x", coverIndex, h),
		}
		coverIndex++
	}
	return coverVars
}
```