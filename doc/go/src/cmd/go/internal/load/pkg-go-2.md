Response:
这是关于 Go 语言构建过程 `go build` 中加载包 (`load`) 功能的一部分代码。我的目标是理解这段代码的功能，并给出相应的 Go 代码示例，命令行参数处理，以及可能出现的错误。由于这是第 3 部分，我需要总结前两部分的功能，并结合当前部分进行归纳。

**思考过程：**

1. **通读代码，识别关键功能点：**  这段代码主要处理了加载包过程中的一些后续处理，包括错误处理、目标文件路径设置、依赖添加（cgo, swig, linker）、案例不敏感的路径和文件名冲突检查、go:embed 指令处理、构建信息收集 (build info) 和一些辅助函数 (SafeArg, LinkerDeps 等)。

2. **错误处理：** 代码检查加载过程中发生的错误，并设置 `p.Incomplete` 和 `p.Error`。特别注意了从哪里报告错误 (导入路径或导入位置)。

3. **目标文件路径：** 根据包的类型 (main, standard, local) 和构建模式 (buildmode) 设置 `p.Target` (最终生成的可执行文件或包文件路径)。 `useBindir` 变量决定了是否将可执行文件放到 `GOBIN` 目录下。 处理了旧的 `code.google.com/p/go.tools` 路径。

4. **依赖添加：** 对于使用 cgo 或 swig 的包，添加 `unsafe`, `runtime/cgo`, `syscall` 等依赖。对于 main 包，添加链接器依赖 (runtime, runtime/cgo, math, runtime/race 等)。

5. **案例不敏感冲突：** 检查导入路径和输入文件名是否存在案例不敏感的冲突。

6. **`go:embed` 处理：**  `resolveEmbed` 函数处理 `//go:embed` 指令，查找匹配的文件，并进行一些有效性检查 (例如，是否跨模块)。

7. **构建信息收集：** `setBuildInfo` 函数收集构建相关的元数据，如依赖模块版本、构建标志、VCS 信息等，并将其存储在 `p.Internal.BuildInfo` 中。这部分代码很复杂，需要仔细理解其逻辑，特别是关于 VCS 信息的获取和条件。

8. **辅助函数：**
    - `SafeArg`: 判断一个字符串是否是安全的命令行参数。
    - `LinkerDeps`: 获取 main 包的链接器依赖。
    - `externalLinkingReason`: 判断是否需要外部链接。

9. **与前两部分的联系（推测）：**  由于是第 3 部分，前两部分可能涉及：
    - 第 1 部分：包的初步加载，例如从文件系统读取包信息，解析 go 文件等。
    - 第 2 部分：处理导入语句，递归加载依赖包，可能包含符号解析等初步处理。

10. **Go 代码示例：**  针对 `go:embed` 和构建信息收集给出示例。

11. **命令行参数：**  与目标文件路径和构建信息相关的参数是关键，例如 `-o`, `-buildmode`, `-trimpath`, `-buildvcs` 等。

12. **易犯错误：** 主要集中在 `go:embed` 的使用上，例如跨模块引用，使用了非法的文件名或目录名。

13. **总结功能：**  结合以上分析，总结该部分代码在 Go 构建过程中的作用。

**预推演和自我纠正：**

- 最初可能会忽略一些细节，例如 `gccgo` 的特殊处理，以及各种 `buildmode` 对目标路径的影响。需要仔细阅读代码中的 `if` 和 `switch` 语句。
- 对 VCS 信息的收集逻辑可能会感到困惑，需要仔细分析 `setBuildInfo` 函数中关于 `cfg.BuildBuildvcs` 的判断条件和 `vcs.FromDir` 的使用。
-  `go:embed` 的路径匹配和错误处理需要仔细理解 `resolveEmbed` 函数的实现。

通过以上分析和预演，我对这段代码的功能有了较为清晰的理解，可以开始组织答案。
这是 Go 语言 `go build` 命令在加载包的过程中，处理已加载包 (`Package` 结构体) 的后续操作的代码片段。它主要负责完善包的信息，例如设置构建目标路径，添加隐式依赖，并进行一些完整性检查。

**功能归纳：**

总的来说，这段代码片段在包加载的后期阶段，主要负责以下功能：

1. **错误处理和标记不完整:**  检查在加载过程中是否发生了错误，并根据错误来源设置 `p.Incomplete` 标志和 `p.Error` 字段。
2. **设置构建目标路径 (`p.Target`)**:  根据包的类型（`main` 包或普通库包），构建模式 (`buildmode`)，以及是否为标准库等因素，决定最终生成的可执行文件或包归档文件的存放路径。
3. **处理旧的 `code.google.com/p/go.tools` 路径**: 如果发现使用了旧的 import 路径，会提示用户使用新的路径。
4. **添加隐式依赖**:  根据包的特性（是否使用 cgo，swig，是否为 `main` 包），自动添加一些必要的依赖包，例如 `unsafe`, `runtime/cgo`, `syscall` 等。
5. **检查导入路径和文件名的案例不敏感冲突**:  防止在不区分大小写的文件系统中出现冲突。
6. **处理 `//go:embed` 指令**:  解析 `//go:embed` 指令中指定的模式，找到匹配的文件，并将这些文件添加到包的信息中。
7. **收集构建信息 (build info)**:  对于 `main` 包，收集构建相关的元数据，例如依赖模块的版本，构建时使用的 flags，以及 VCS 信息等。

**Go 代码举例说明 (关于 `//go:embed` 功能):**

假设我们有以下目录结构：

```
myproject/
├── main.go
└── embedded/
    ├── file1.txt
    └── file2.txt
```

`main.go` 文件的内容如下：

```go
package main

import (
	_ "embed"
	"fmt"
	"strings"
)

//go:embed embedded/*
var files map[string][]byte

func main() {
	for name, content := range files {
		fmt.Printf("File: %s\nContent:\n%s\n", name, strings.TrimSpace(string(content)))
	}
}
```

**假设输入：**  执行 `go build` 命令。

**代码推理：**

在加载 `main` 包时，这段代码会执行 `resolveEmbed` 函数来处理 `//go:embed embedded/*` 指令。

1. `resolveEmbed` 函数会根据模式 `embedded/*` 在 `myproject` 目录下查找匹配的文件。
2. 找到 `embedded/file1.txt` 和 `embedded/file2.txt`。
3. 将文件名（相对于包目录）和文件内容存储在 `p.EmbedFiles` 和 `p.Internal.Embed` 中。

**预期输出：** 编译后的可执行文件运行时，会输出 `file1.txt` 和 `file2.txt` 的内容。

**命令行参数的具体处理：**

这段代码中涉及的命令行参数主要影响构建目标路径的设置和构建信息的收集：

* **`-o <output>`**:  指定输出文件的名称。虽然这段代码本身不直接处理这个参数，但它计算出的 `p.Target` 会受到这个参数的影响（如果用户指定了输出路径）。
* **`-buildmode=<mode>`**:  影响 `useBindir` 的值，以及最终的目标文件路径。例如，如果 `buildmode` 是 `c-archive`, `c-shared`, 或 `plugin`，则 `useBindir` 会被设置为 `false`。
* **`-trimpath`**:  如果设置，会影响构建信息的收集，特别是 `-ldflags` 和 CGO 相关的环境变量将不会被包含在构建信息中，以提高构建的可重现性。
* **`-buildvcs=<auto|true|false>`**: 控制是否在构建信息中包含 VCS (版本控制系统) 的信息。
    * `auto`:  自动检测，仅在当前目录处于 Git 或其他支持的 VCS 仓库中，且构建的是非测试的 `main` 包时包含。
    * `true`:  强制包含 VCS 信息。
    * `false`:  强制不包含 VCS 信息。

**使用者易犯错的点 (关于 `//go:embed` 功能):**

* **跨模块引用**:  `//go:embed` 中指定的路径不能引用到当前模块之外的文件。例如，如果 `file1.txt` 在 `myproject` 的父目录中，则会报错。
* **使用了不合法的模式**:  `//go:embed` 的模式需要符合一定的语法规则，例如不能以 `/` 开头，不能包含 `..` 等。
* **案例不敏感的文件名冲突**: 如果在 `embedded` 目录下同时存在 `file.txt` 和 `FILE.txt`，由于案例不敏感的文件系统可能会导致冲突，`go build` 会报错。
* **嵌入的目录中包含不应嵌入的文件**:  默认情况下，以 `.` 或 `_` 开头的文件和目录不会被嵌入，除非使用了 `all:` 前缀。用户可能不清楚这个规则，导致嵌入的文件不完整。

**第3部分功能归纳：**

这是 `go build` 过程中加载包的第三部分，主要负责 **完善已加载包的信息，包括设置构建目标路径，添加隐式依赖，进行案例不敏感的冲突检查，处理 `//go:embed` 指令，并收集构建信息**。它确保了在后续的编译和链接阶段，`go build` 命令能够拥有构建目标所需的所有必要信息。

结合前两部分，我们可以推测：

* **第一部分** 可能负责包的基本加载，例如根据 import 路径查找包的源文件，解析 Go 代码，提取 import 语句等基本信息。
* **第二部分** 可能负责处理包的依赖关系，递归地加载依赖的包，并进行一些初步的类型检查和符号解析。

而本部分则是在前两部分的基础上，对已加载的包进行更深入的处理和完善，为后续的构建步骤做好准备。

### 提示词
```
这是路径为go/src/cmd/go/internal/load/pkg.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共4部分，请归纳一下它的功能
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
// TODO(jayconrod): delete this function and set flags
```