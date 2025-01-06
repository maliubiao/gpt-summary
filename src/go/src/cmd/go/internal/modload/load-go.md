Response: My thinking process to analyze the provided Go code snippet went through these steps:

1. **Understand the Context:** The first step is always to understand where this code fits within the larger system. The comment at the top clearly states it's part of the `go` command, specifically the module loading mechanism (`go/src/cmd/go/internal/modload/load.go`). This tells me the code is responsible for figuring out which packages are needed, where they come from (which modules), and handling dependencies in a module-aware Go environment.

2. **Identify Key Data Structures:**  I scanned the code for prominent type definitions. `loader`, `PackageOpts`, `loadPkg`, and `Requirements` stood out. The comments associated with these types provide immediate insights into their purpose.

    * `loader`: The central object that manages the loading process. It holds state and orchestrates the loading of packages.
    * `PackageOpts`: Configuration options for the loading process, allowing customization (e.g., build tags, tidy mode).
    * `loadPkg`: Represents a single package being loaded, storing information like its path, module, dependencies, and any errors.
    * `Requirements`: Represents the module dependencies as defined in `go.mod`.

3. **Pinpoint Exported Entry Points:** The initial comments mention `LoadPackages` and `ImportFromFiles`. These are likely the primary ways external code interacts with this module to initiate package loading. I made a mental note to examine these functions closely.

4. **Analyze `LoadPackages`:** I delved into the `LoadPackages` function. I noted the following key aspects:

    * **Pattern Matching:** It takes a list of patterns as input and uses the `search` package to find matching packages. It handles different pattern types ("all", wildcards, literals).
    * **`loader` Initialization:** It creates an instance of the `loader` struct.
    * **Iterative Loading:** The comments and the structure of `loadFromRoots` suggest an iterative process to resolve dependencies.
    * **Tidy Functionality:**  It includes logic for "tidy" operations (`go mod tidy`), including diff generation.
    * **Committing Requirements:** It updates the `go.mod` and `go.sum` files.
    * **Error Handling:** It manages and reports errors encountered during the loading process.
    * **Return Values:**  It returns a list of `search.Match` and the loaded package names.

5. **Analyze `ImportFromFiles`:**  This function seems simpler, focusing on loading dependencies based on imports found in specific Go files.

6. **Examine `loadFromRoots`:** This appears to be the core loading logic. I observed:

    * **Iterative Loop:** The `for` loop indicates the iterative nature of the loading process.
    * **Root Package Identification:**  It uses `params.listRoots` to determine the initial set of packages.
    * **Work Queue:**  It employs a `par.Queue` for parallel processing of package loading.
    * **`pkg` Function:** The `ld.pkg` function seems responsible for fetching or creating `loadPkg` instances and kicking off the loading process for a single package.
    * **`applyPkgFlags`:** This function handles the propagation of flags (like `pkgInAll`) and might trigger loading of tests based on the flags.
    * **`updateRequirements`:** This function seems crucial for synchronizing the loaded package information with the `Requirements` struct, potentially updating `go.mod`.
    * **`resolveMissingImports`:**  Handles the case where imported packages are not found and attempts to add necessary module dependencies.

7. **Infer Functionality and Purpose:** Based on the analysis, I concluded that this code is the heart of Go's module-aware package loading mechanism. Its primary functions are:

    * **Resolving package names to their source locations.**
    * **Determining the module dependencies required for a given set of packages.**
    * **Managing the loading of these dependencies, including transitive dependencies and tests.**
    * **Updating the `go.mod` and `go.sum` files to reflect the resolved dependencies.**
    * **Supporting the `go mod tidy` command to minimize dependencies.**

8. **Consider Edge Cases and Potential Errors:** I looked for areas where users might make mistakes. The interaction with the "all" pattern, especially its behavior in different Go versions and with `-mod=vendor`, seemed like a potential source of confusion. The comments themselves highlighted some of these complexities.

9. **Structure the Output:** Finally, I organized my findings into the requested categories: functionality listing, code examples (where applicable and inferable), command-line parameter handling, potential errors, and a summary. I prioritized the most significant aspects and tried to express them clearly and concisely. Since the prompt specifically requested focusing on the provided code *part*, I avoided making assumptions about parts not shown.

This detailed step-by-step analysis, focusing on understanding the code's structure, key data, and control flow, allowed me to accurately identify the functionality of the provided Go code snippet.
这段代码是 Go 语言 `go` 命令中负责模块加载的核心部分，路径为 `go/src/cmd/go/internal/modload/load.go`。 它实现了在模块模式下加载 Go 包的功能，并处理与模块相关的依赖管理。

**功能归纳:**

这段代码的主要功能可以归纳为以下几点：

1. **根据给定的模式 (patterns) 查找和加载 Go 包:**  它能处理不同的包模式，例如具体的包路径、通配符 (`...`) 和特殊的元模式 `"all"`。
2. **管理模块依赖关系:**  它负责确定哪些模块包含了所需的包，并在必要时更新 `go.mod` 和 `go.sum` 文件以添加或修改依赖。
3. **处理 "all" 元模式:**  它实现了 `"all"` 模式的特殊逻辑，该模式会加载主模块及其所有依赖（包括测试依赖，具体行为取决于 Go 版本和 `-mod` 标志）。
4. **支持 `go mod tidy` 命令:**  它提供了清理 `go.mod` 和 `go.sum` 文件，移除不必要的依赖的功能。
5. **处理 `-mod` 标志:**  虽然代码本身没有直接处理命令行参数，但其行为受到全局配置 `cfg.BuildMod` 的影响，例如在 `-mod=vendor` 模式下的行为。
6. **处理构建标签 (build tags):**  它允许根据构建标签加载不同的包。
7. **处理模块替换 (replace directives):**  代码中涉及到 `Replacement` 函数，说明它能处理 `go.mod` 文件中的 `replace` 指令。
8. **处理工作区 (workspaces):**  代码中有 `inWorkspaceMode()` 的判断，表明它支持 Go 1.18 引入的工作区功能。
9. **处理 Go 版本兼容性:**  代码考虑了不同 Go 版本下 `"all"` 模式的行为差异，以及 `go mod tidy` 的兼容性。
10. **处理缺失的依赖:**  它能尝试解析缺失的导入，并建议添加相应的模块依赖。
11. **使用并行工作队列:**  为了提高加载效率，它使用了并行工作队列 `par.Queue`。
12. **错误处理:**  它负责收集和报告在包加载过程中遇到的错误。

**Go 语言功能实现推理和代码示例:**

这段代码的核心功能是实现 Go 模块的依赖解析和加载。可以将其理解为 `go` 命令中处理 `import` 语句，并确保所有依赖的包都可用的引擎。

**示例场景:** 假设你的 `go.mod` 文件内容如下：

```go
module mymodule

go 1.18

require (
	github.com/gin-gonic/gin v1.8.1
	golang.org/x/sync v0.1.0
)
```

你的 `main.go` 文件内容如下：

```go
package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/errgroup"
)

func main() {
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
	r.Run() // 监听并在 0.0.0.0:8080 上启动服务

	var g errgroup.Group
	g.Go(func() error {
		fmt.Println("Running in goroutine")
		return nil
	})
	if err := g.Wait(); err != nil {
		fmt.Println("Error:", err)
	}
}
```

当你运行 `go build` 或 `go run main.go` 时，`LoadPackages` 函数会被调用来加载 `main` 包及其依赖。

**假设的输入与输出 (基于 `go run main.go`)：**

* **假设输入 `patterns`:** `["."]` (当前目录，代表 `main` 包)
* **`PackageOpts`:**  可能是默认值，或者根据环境变量和命令行参数进行设置。例如，`ResolveMissingImports` 可能为 `true`。
* **推理过程:**
    1. `LoadPackages` 函数首先会解析 `go.mod` 文件，构建初始的模块依赖图。
    2. 它会创建一个 `loader` 实例。
    3. `loadFromRoots` 函数会被调用，以 `main` 包作为根节点开始加载。
    4. `loader` 会分析 `main.go` 中的 `import` 语句，发现依赖 `github.com/gin-gonic/gin` 和 `golang.org/x/sync/errgroup`。
    5. 它会检查 `go.mod` 文件，确认这些依赖已经存在。
    6. `loader` 会继续加载 `gin` 包及其依赖，以及 `errgroup` 包。
    7. 如果某个依赖的包在已知的模块版本中找不到，并且 `ResolveMissingImports` 为 `true`，`loader` 可能会尝试查询新的模块版本来解决依赖。
* **假设输出 `loadedPackages`:**  `main` 包以及 `gin` 和 `errgroup` 及其所有传递依赖的包路径。 例如：`["mymodule", "github.com/gin-gonic/gin", "github.com/ugorji/go/codec", "google.golang.org/protobuf/reflect/protoreflect", "golang.org/x/net/http2/hpack", "golang.org/x/sys/cpu", "golang.org/x/text/unicode/bidi", "golang.org/x/text/unicode/norm", "gopkg.in/yaml.v2", "golang.org/x/sync", "golang.org/x/sync/errgroup"]` (顺序可能不同)
* **`matches`:**  会包含一个 `search.Match` 结构，表示匹配到的 `main` 包。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。命令行参数的解析发生在 `cmd/go/internal/base` 和其他更上层的模块中。  `LoadPackages` 函数接收的 `PackageOpts` 结构体已经包含了处理后的参数信息，例如：

* **`-tags`:**  通过 `PackageOpts.Tags` 传递。
* **`-mod`:**  影响全局变量 `cfg.BuildMod`，进而影响 `LoadPackages` 的行为，例如是否允许修改 `go.mod` 文件。
* **`-vendor`:**  也通过设置 `cfg.BuildMod` 为 `"vendor"` 来影响行为，例如在解析本地路径时的处理。

**使用者易犯错的点:**

由于这段代码涉及模块加载的核心逻辑，使用者在模块使用过程中一些常见的错误都与此相关，例如：

* **`go.mod` 文件不正确或缺失:**  如果 `go.mod` 文件不存在或者内容有误（例如依赖版本冲突），`LoadPackages` 会报错。
* **依赖版本不匹配:**  如果代码中 `import` 的包版本与 `go.mod` 中声明的依赖版本不一致，可能会导致加载错误。
* **网络问题:**  在需要下载模块时，网络连接问题会导致加载失败。
* **使用了被 `replace` 指令替换的模块:**  用户可能不清楚某些依赖被替换到了本地路径或其他仓库，导致混淆。
* **不理解 `"all"` 模式的行为:**  特别是在不同的 Go 版本和 `-mod` 标志下，`"all"` 模式加载的包集合可能超出预期。例如，在 Go 1.16 之前，`"all"` 会包含测试依赖，之后默认不包含。

**这是第1部分，共2部分，请归纳一下它的功能:**

这段代码 (第 1 部分) 主要是 **`LoadPackages` 函数的实现**，它负责根据给定的包模式加载 Go 包，并构建出依赖关系图。  它涉及到了模式匹配、`loader` 实例的创建、初始模块依赖的加载、以及预加载根模块以优化加载过程。 它为后续的模块依赖更新、缺失依赖解析和 `go mod tidy` 操作奠定了基础。 关键在于它确定了需要加载哪些包，并为这些包的加载过程做好了准备。

Prompt: 
```
这是路径为go/src/cmd/go/internal/modload/load.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package modload

// This file contains the module-mode package loader, as well as some accessory
// functions pertaining to the package import graph.
//
// There are two exported entry points into package loading — LoadPackages and
// ImportFromFiles — both implemented in terms of loadFromRoots, which itself
// manipulates an instance of the loader struct.
//
// Although most of the loading state is maintained in the loader struct,
// one key piece - the build list - is a global, so that it can be modified
// separate from the loading operation, such as during "go get"
// upgrades/downgrades or in "go mod" operations.
// TODO(#40775): It might be nice to make the loader take and return
// a buildList rather than hard-coding use of the global.
//
// Loading is an iterative process. On each iteration, we try to load the
// requested packages and their transitive imports, then try to resolve modules
// for any imported packages that are still missing.
//
// The first step of each iteration identifies a set of “root” packages.
// Normally the root packages are exactly those matching the named pattern
// arguments. However, for the "all" meta-pattern, the final set of packages is
// computed from the package import graph, and therefore cannot be an initial
// input to loading that graph. Instead, the root packages for the "all" pattern
// are those contained in the main module, and allPatternIsRoot parameter to the
// loader instructs it to dynamically expand those roots to the full "all"
// pattern as loading progresses.
//
// The pkgInAll flag on each loadPkg instance tracks whether that
// package is known to match the "all" meta-pattern.
// A package matches the "all" pattern if:
// 	- it is in the main module, or
// 	- it is imported by any test in the main module, or
// 	- it is imported by a tool of the main module, or
// 	- it is imported by another package in "all", or
// 	- the main module specifies a go version ≤ 1.15, and the package is imported
// 	  by a *test of* another package in "all".
//
// When graph pruning is in effect, we want to spot-check the graph-pruning
// invariants — which depend on which packages are known to be in "all" — even
// when we are only loading individual packages, so we set the pkgInAll flag
// regardless of the whether the "all" pattern is a root.
// (This is necessary to maintain the “import invariant” described in
// https://golang.org/design/36460-lazy-module-loading.)
//
// Because "go mod vendor" prunes out the tests of vendored packages, the
// behavior of the "all" pattern with -mod=vendor in Go 1.11–1.15 is the same
// as the "all" pattern (regardless of the -mod flag) in 1.16+.
// The loader uses the GoVersion parameter to determine whether the "all"
// pattern should close over tests (as in Go 1.11–1.15) or stop at only those
// packages transitively imported by the packages and tests in the main module
// ("all" in Go 1.16+ and "go mod vendor" in Go 1.11+).
//
// Note that it is possible for a loaded package NOT to be in "all" even when we
// are loading the "all" pattern. For example, packages that are transitive
// dependencies of other roots named on the command line must be loaded, but are
// not in "all". (The mod_notall test illustrates this behavior.)
// Similarly, if the LoadTests flag is set but the "all" pattern does not close
// over test dependencies, then when we load the test of a package that is in
// "all" but outside the main module, the dependencies of that test will not
// necessarily themselves be in "all". (That configuration does not arise in Go
// 1.11–1.15, but it will be possible in Go 1.16+.)
//
// Loading proceeds from the roots, using a parallel work-queue with a limit on
// the amount of active work (to avoid saturating disks, CPU cores, and/or
// network connections). Each package is added to the queue the first time it is
// imported by another package. When we have finished identifying the imports of
// a package, we add the test for that package if it is needed. A test may be
// needed if:
// 	- the package matches a root pattern and tests of the roots were requested, or
// 	- the package is in the main module and the "all" pattern is requested
// 	  (because the "all" pattern includes the dependencies of tests in the main
// 	  module), or
// 	- the package is in "all" and the definition of "all" we are using includes
// 	  dependencies of tests (as is the case in Go ≤1.15).
//
// After all available packages have been loaded, we examine the results to
// identify any requested or imported packages that are still missing, and if
// so, which modules we could add to the module graph in order to make the
// missing packages available. We add those to the module graph and iterate,
// until either all packages resolve successfully or we cannot identify any
// module that would resolve any remaining missing package.
//
// If the main module is “tidy” (that is, if "go mod tidy" is a no-op for it)
// and all requested packages are in "all", then loading completes in a single
// iteration.
// TODO(bcmills): We should also be able to load in a single iteration if the
// requested packages all come from modules that are themselves tidy, regardless
// of whether those packages are in "all". Today, that requires two iterations
// if those packages are not found in existing dependencies of the main module.

import (
	"context"
	"errors"
	"fmt"
	"go/build"
	"internal/diff"
	"io/fs"
	"maps"
	"os"
	"path"
	pathpkg "path"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"cmd/go/internal/base"
	"cmd/go/internal/cfg"
	"cmd/go/internal/fips140"
	"cmd/go/internal/fsys"
	"cmd/go/internal/gover"
	"cmd/go/internal/imports"
	"cmd/go/internal/modfetch"
	"cmd/go/internal/modindex"
	"cmd/go/internal/mvs"
	"cmd/go/internal/search"
	"cmd/go/internal/str"
	"cmd/internal/par"

	"golang.org/x/mod/module"
)

// loaded is the most recently-used package loader.
// It holds details about individual packages.
//
// This variable should only be accessed directly in top-level exported
// functions. All other functions that require or produce a *loader should pass
// or return it as an explicit parameter.
var loaded *loader

// PackageOpts control the behavior of the LoadPackages function.
type PackageOpts struct {
	// TidyGoVersion is the Go version to which the go.mod file should be updated
	// after packages have been loaded.
	//
	// An empty TidyGoVersion means to use the Go version already specified in the
	// main module's go.mod file, or the latest Go version if there is no main
	// module.
	TidyGoVersion string

	// Tags are the build tags in effect (as interpreted by the
	// cmd/go/internal/imports package).
	// If nil, treated as equivalent to imports.Tags().
	Tags map[string]bool

	// Tidy, if true, requests that the build list and go.sum file be reduced to
	// the minimal dependencies needed to reproducibly reload the requested
	// packages.
	Tidy bool

	// TidyDiff, if true, causes tidy not to modify go.mod or go.sum but
	// instead print the necessary changes as a unified diff. It exits
	// with a non-zero code if the diff is not empty.
	TidyDiff bool

	// TidyCompatibleVersion is the oldest Go version that must be able to
	// reproducibly reload the requested packages.
	//
	// If empty, the compatible version is the Go version immediately prior to the
	// 'go' version listed in the go.mod file.
	TidyCompatibleVersion string

	// VendorModulesInGOROOTSrc indicates that if we are within a module in
	// GOROOT/src, packages in the module's vendor directory should be resolved as
	// actual module dependencies (instead of standard-library packages).
	VendorModulesInGOROOTSrc bool

	// ResolveMissingImports indicates that we should attempt to add module
	// dependencies as needed to resolve imports of packages that are not found.
	//
	// For commands that support the -mod flag, resolving imports may still fail
	// if the flag is set to "readonly" (the default) or "vendor".
	ResolveMissingImports bool

	// AssumeRootsImported indicates that the transitive dependencies of the root
	// packages should be treated as if those roots will be imported by the main
	// module.
	AssumeRootsImported bool

	// AllowPackage, if non-nil, is called after identifying the module providing
	// each package. If AllowPackage returns a non-nil error, that error is set
	// for the package, and the imports and test of that package will not be
	// loaded.
	//
	// AllowPackage may be invoked concurrently by multiple goroutines,
	// and may be invoked multiple times for a given package path.
	AllowPackage func(ctx context.Context, path string, mod module.Version) error

	// LoadTests loads the test dependencies of each package matching a requested
	// pattern. If ResolveMissingImports is also true, test dependencies will be
	// resolved if missing.
	LoadTests bool

	// UseVendorAll causes the "all" package pattern to be interpreted as if
	// running "go mod vendor" (or building with "-mod=vendor").
	//
	// This is a no-op for modules that declare 'go 1.16' or higher, for which this
	// is the default (and only) interpretation of the "all" pattern in module mode.
	UseVendorAll bool

	// AllowErrors indicates that LoadPackages should not terminate the process if
	// an error occurs.
	AllowErrors bool

	// SilencePackageErrors indicates that LoadPackages should not print errors
	// that occur while matching or loading packages, and should not terminate the
	// process if such an error occurs.
	//
	// Errors encountered in the module graph will still be reported.
	//
	// The caller may retrieve the silenced package errors using the Lookup
	// function, and matching errors are still populated in the Errs field of the
	// associated search.Match.)
	SilencePackageErrors bool

	// SilenceMissingStdImports indicates that LoadPackages should not print
	// errors or terminate the process if an imported package is missing, and the
	// import path looks like it might be in the standard library (perhaps in a
	// future version).
	SilenceMissingStdImports bool

	// SilenceNoGoErrors indicates that LoadPackages should not print
	// imports.ErrNoGo errors.
	// This allows the caller to invoke LoadPackages (and report other errors)
	// without knowing whether the requested packages exist for the given tags.
	//
	// Note that if a requested package does not exist *at all*, it will fail
	// during module resolution and the error will not be suppressed.
	SilenceNoGoErrors bool

	// SilenceUnmatchedWarnings suppresses the warnings normally emitted for
	// patterns that did not match any packages.
	SilenceUnmatchedWarnings bool

	// Resolve the query against this module.
	MainModule module.Version

	// If Switcher is non-nil, then LoadPackages passes all encountered errors
	// to Switcher.Error and tries Switcher.Switch before base.ExitIfErrors.
	Switcher gover.Switcher
}

// LoadPackages identifies the set of packages matching the given patterns and
// loads the packages in the import graph rooted at that set.
func LoadPackages(ctx context.Context, opts PackageOpts, patterns ...string) (matches []*search.Match, loadedPackages []string) {
	if opts.Tags == nil {
		opts.Tags = imports.Tags()
	}

	patterns = search.CleanPatterns(patterns)
	matches = make([]*search.Match, 0, len(patterns))
	allPatternIsRoot := false
	for _, pattern := range patterns {
		matches = append(matches, search.NewMatch(pattern))
		if pattern == "all" {
			allPatternIsRoot = true
		}
	}

	updateMatches := func(rs *Requirements, ld *loader) {
		for _, m := range matches {
			switch {
			case m.IsLocal():
				// Evaluate list of file system directories on first iteration.
				if m.Dirs == nil {
					matchModRoots := modRoots
					if opts.MainModule != (module.Version{}) {
						matchModRoots = []string{MainModules.ModRoot(opts.MainModule)}
					}
					matchLocalDirs(ctx, matchModRoots, m, rs)
				}

				// Make a copy of the directory list and translate to import paths.
				// Note that whether a directory corresponds to an import path
				// changes as the build list is updated, and a directory can change
				// from not being in the build list to being in it and back as
				// the exact version of a particular module increases during
				// the loader iterations.
				m.Pkgs = m.Pkgs[:0]
				for _, dir := range m.Dirs {
					pkg, err := resolveLocalPackage(ctx, dir, rs)
					if err != nil {
						if !m.IsLiteral() && (err == errPkgIsBuiltin || err == errPkgIsGorootSrc) {
							continue // Don't include "builtin" or GOROOT/src in wildcard patterns.
						}

						// If we're outside of a module, ensure that the failure mode
						// indicates that.
						if !HasModRoot() {
							die()
						}

						if ld != nil {
							m.AddError(err)
						}
						continue
					}
					m.Pkgs = append(m.Pkgs, pkg)
				}

			case m.IsLiteral():
				m.Pkgs = []string{m.Pattern()}

			case strings.Contains(m.Pattern(), "..."):
				m.Errs = m.Errs[:0]
				mg, err := rs.Graph(ctx)
				if err != nil {
					// The module graph is (or may be) incomplete — perhaps we failed to
					// load the requirements of some module. This is an error in matching
					// the patterns to packages, because we may be missing some packages
					// or we may erroneously match packages in the wrong versions of
					// modules. However, for cases like 'go list -e', the error should not
					// necessarily prevent us from loading the packages we could find.
					m.Errs = append(m.Errs, err)
				}
				matchPackages(ctx, m, opts.Tags, includeStd, mg.BuildList())

			case m.Pattern() == "all":
				if ld == nil {
					// The initial roots are the packages and tools in the main module.
					// loadFromRoots will expand that to "all".
					m.Errs = m.Errs[:0]
					matchModules := MainModules.Versions()
					if opts.MainModule != (module.Version{}) {
						matchModules = []module.Version{opts.MainModule}
					}
					matchPackages(ctx, m, opts.Tags, omitStd, matchModules)
					for tool := range MainModules.Tools() {
						m.Pkgs = append(m.Pkgs, tool)
					}
				} else {
					// Starting with the packages in the main module,
					// enumerate the full list of "all".
					m.Pkgs = ld.computePatternAll()
				}

			case m.Pattern() == "std" || m.Pattern() == "cmd":
				if m.Pkgs == nil {
					m.MatchPackages() // Locate the packages within GOROOT/src.
				}

			case m.Pattern() == "tool":
				for tool := range MainModules.Tools() {
					m.Pkgs = append(m.Pkgs, tool)
				}
			default:
				panic(fmt.Sprintf("internal error: modload missing case for pattern %s", m.Pattern()))
			}
		}
	}

	initialRS, err := loadModFile(ctx, &opts)
	if err != nil {
		base.Fatal(err)
	}

	ld := loadFromRoots(ctx, loaderParams{
		PackageOpts:  opts,
		requirements: initialRS,

		allPatternIsRoot: allPatternIsRoot,

		listRoots: func(rs *Requirements) (roots []string) {
			updateMatches(rs, nil)
			for _, m := range matches {
				roots = append(roots, m.Pkgs...)
			}
			return roots
		},
	})

	// One last pass to finalize wildcards.
	updateMatches(ld.requirements, ld)

	// List errors in matching patterns (such as directory permission
	// errors for wildcard patterns).
	if !ld.SilencePackageErrors {
		for _, match := range matches {
			for _, err := range match.Errs {
				ld.error(err)
			}
		}
	}
	ld.exitIfErrors(ctx)

	if !opts.SilenceUnmatchedWarnings {
		search.WarnUnmatched(matches)
	}

	if opts.Tidy {
		if cfg.BuildV {
			mg, _ := ld.requirements.Graph(ctx)
			for _, m := range initialRS.rootModules {
				var unused bool
				if ld.requirements.pruning == unpruned {
					// m is unused if it was dropped from the module graph entirely. If it
					// was only demoted from direct to indirect, it may still be in use via
					// a transitive import.
					unused = mg.Selected(m.Path) == "none"
				} else {
					// m is unused if it was dropped from the roots. If it is still present
					// as a transitive dependency, that transitive dependency is not needed
					// by any package or test in the main module.
					_, ok := ld.requirements.rootSelected(m.Path)
					unused = !ok
				}
				if unused {
					fmt.Fprintf(os.Stderr, "unused %s\n", m.Path)
				}
			}
		}

		keep := keepSums(ctx, ld, ld.requirements, loadedZipSumsOnly)
		compatVersion := ld.TidyCompatibleVersion
		goVersion := ld.requirements.GoVersion()
		if compatVersion == "" {
			if gover.Compare(goVersion, gover.GoStrictVersion) < 0 {
				compatVersion = gover.Prev(goVersion)
			} else {
				// Starting at GoStrictVersion, we no longer maintain compatibility with
				// versions older than what is listed in the go.mod file.
				compatVersion = goVersion
			}
		}
		if gover.Compare(compatVersion, goVersion) > 0 {
			// Each version of the Go toolchain knows how to interpret go.mod and
			// go.sum files produced by all previous versions, so a compatibility
			// version higher than the go.mod version adds nothing.
			compatVersion = goVersion
		}
		if compatPruning := pruningForGoVersion(compatVersion); compatPruning != ld.requirements.pruning {
			compatRS := newRequirements(compatPruning, ld.requirements.rootModules, ld.requirements.direct)
			ld.checkTidyCompatibility(ctx, compatRS, compatVersion)

			for m := range keepSums(ctx, ld, compatRS, loadedZipSumsOnly) {
				keep[m] = true
			}
		}

		if opts.TidyDiff {
			cfg.BuildMod = "readonly"
			loaded = ld
			requirements = loaded.requirements
			currentGoMod, updatedGoMod, _, err := UpdateGoModFromReqs(ctx, WriteOpts{})
			if err != nil {
				base.Fatal(err)
			}
			goModDiff := diff.Diff("current/go.mod", currentGoMod, "tidy/go.mod", updatedGoMod)

			modfetch.TrimGoSum(keep)
			// Dropping compatibility for 1.16 may result in a strictly smaller go.sum.
			// Update the keep map with only the loaded.requirements.
			if gover.Compare(compatVersion, "1.16") > 0 {
				keep = keepSums(ctx, loaded, requirements, addBuildListZipSums)
			}
			currentGoSum, tidyGoSum := modfetch.TidyGoSum(keep)
			goSumDiff := diff.Diff("current/go.sum", currentGoSum, "tidy/go.sum", tidyGoSum)

			if len(goModDiff) > 0 {
				fmt.Println(string(goModDiff))
				base.SetExitStatus(1)
			}
			if len(goSumDiff) > 0 {
				fmt.Println(string(goSumDiff))
				base.SetExitStatus(1)
			}
			base.Exit()
		}

		if !ExplicitWriteGoMod {
			modfetch.TrimGoSum(keep)

			// commitRequirements below will also call WriteGoSum, but the "keep" map
			// we have here could be strictly larger: commitRequirements only commits
			// loaded.requirements, but here we may have also loaded (and want to
			// preserve checksums for) additional entities from compatRS, which are
			// only needed for compatibility with ld.TidyCompatibleVersion.
			if err := modfetch.WriteGoSum(ctx, keep, mustHaveCompleteRequirements()); err != nil {
				base.Fatal(err)
			}
		}
	}

	if opts.TidyDiff && !opts.Tidy {
		panic("TidyDiff is set but Tidy is not.")
	}

	// Success! Update go.mod and go.sum (if needed) and return the results.
	// We'll skip updating if ExplicitWriteGoMod is true (the caller has opted
	// to call WriteGoMod itself) or if ResolveMissingImports is false (the
	// command wants to examine the package graph as-is).
	loaded = ld
	requirements = loaded.requirements

	for _, pkg := range ld.pkgs {
		if !pkg.isTest() {
			loadedPackages = append(loadedPackages, pkg.path)
		}
	}
	sort.Strings(loadedPackages)

	if !ExplicitWriteGoMod && opts.ResolveMissingImports {
		if err := commitRequirements(ctx, WriteOpts{}); err != nil {
			base.Fatal(err)
		}
	}

	return matches, loadedPackages
}

// matchLocalDirs is like m.MatchDirs, but tries to avoid scanning directories
// outside of the standard library and active modules.
func matchLocalDirs(ctx context.Context, modRoots []string, m *search.Match, rs *Requirements) {
	if !m.IsLocal() {
		panic(fmt.Sprintf("internal error: resolveLocalDirs on non-local pattern %s", m.Pattern()))
	}

	if i := strings.Index(m.Pattern(), "..."); i >= 0 {
		// The pattern is local, but it is a wildcard. Its packages will
		// only resolve to paths if they are inside of the standard
		// library, the main module, or some dependency of the main
		// module. Verify that before we walk the filesystem: a filesystem
		// walk in a directory like /var or /etc can be very expensive!
		dir := filepath.Dir(filepath.Clean(m.Pattern()[:i+3]))
		absDir := dir
		if !filepath.IsAbs(dir) {
			absDir = filepath.Join(base.Cwd(), dir)
		}

		modRoot := findModuleRoot(absDir)
		if !slices.Contains(modRoots, modRoot) && search.InDir(absDir, cfg.GOROOTsrc) == "" && pathInModuleCache(ctx, absDir, rs) == "" {
			m.Dirs = []string{}
			scope := "main module or its selected dependencies"
			if inWorkspaceMode() {
				scope = "modules listed in go.work or their selected dependencies"
			}
			m.AddError(fmt.Errorf("directory prefix %s does not contain %s", base.ShortPath(absDir), scope))
			return
		}
	}

	m.MatchDirs(modRoots)
}

// resolveLocalPackage resolves a filesystem path to a package path.
func resolveLocalPackage(ctx context.Context, dir string, rs *Requirements) (string, error) {
	var absDir string
	if filepath.IsAbs(dir) {
		absDir = filepath.Clean(dir)
	} else {
		absDir = filepath.Join(base.Cwd(), dir)
	}

	bp, err := cfg.BuildContext.ImportDir(absDir, 0)
	if err != nil && (bp == nil || len(bp.IgnoredGoFiles) == 0) {
		// golang.org/issue/32917: We should resolve a relative path to a
		// package path only if the relative path actually contains the code
		// for that package.
		//
		// If the named directory does not exist or contains no Go files,
		// the package does not exist.
		// Other errors may affect package loading, but not resolution.
		if _, err := fsys.Stat(absDir); err != nil {
			if os.IsNotExist(err) {
				// Canonicalize OS-specific errors to errDirectoryNotFound so that error
				// messages will be easier for users to search for.
				return "", &fs.PathError{Op: "stat", Path: absDir, Err: errDirectoryNotFound}
			}
			return "", err
		}
		if _, noGo := err.(*build.NoGoError); noGo {
			// A directory that does not contain any Go source files — even ignored
			// ones! — is not a Go package, and we can't resolve it to a package
			// path because that path could plausibly be provided by some other
			// module.
			//
			// Any other error indicates that the package “exists” (at least in the
			// sense that it cannot exist in any other module), but has some other
			// problem (such as a syntax error).
			return "", err
		}
	}

	for _, mod := range MainModules.Versions() {
		modRoot := MainModules.ModRoot(mod)
		if modRoot != "" && absDir == modRoot {
			if absDir == cfg.GOROOTsrc {
				return "", errPkgIsGorootSrc
			}
			return MainModules.PathPrefix(mod), nil
		}
	}

	// Note: The checks for @ here are just to avoid misinterpreting
	// the module cache directories (formerly GOPATH/src/mod/foo@v1.5.2/bar).
	// It's not strictly necessary but helpful to keep the checks.
	var pkgNotFoundErr error
	pkgNotFoundLongestPrefix := ""
	for _, mainModule := range MainModules.Versions() {
		modRoot := MainModules.ModRoot(mainModule)
		if modRoot != "" && str.HasFilePathPrefix(absDir, modRoot) && !strings.Contains(absDir[len(modRoot):], "@") {
			suffix := filepath.ToSlash(str.TrimFilePathPrefix(absDir, modRoot))
			if pkg, found := strings.CutPrefix(suffix, "vendor/"); found {
				if cfg.BuildMod != "vendor" {
					return "", fmt.Errorf("without -mod=vendor, directory %s has no package path", absDir)
				}

				readVendorList(VendorDir())
				if _, ok := vendorPkgModule[pkg]; !ok {
					return "", fmt.Errorf("directory %s is not a package listed in vendor/modules.txt", absDir)
				}
				return pkg, nil
			}

			mainModulePrefix := MainModules.PathPrefix(mainModule)
			if mainModulePrefix == "" {
				pkg := suffix
				if pkg == "builtin" {
					// "builtin" is a pseudo-package with a real source file.
					// It's not included in "std", so it shouldn't resolve from "."
					// within module "std" either.
					return "", errPkgIsBuiltin
				}
				return pkg, nil
			}

			pkg := pathpkg.Join(mainModulePrefix, suffix)
			if _, ok, err := dirInModule(pkg, mainModulePrefix, modRoot, true); err != nil {
				return "", err
			} else if !ok {
				// This main module could contain the directory but doesn't. Other main
				// modules might contain the directory, so wait till we finish the loop
				// to see if another main module contains directory. But if not,
				// return an error.
				if len(mainModulePrefix) > len(pkgNotFoundLongestPrefix) {
					pkgNotFoundLongestPrefix = mainModulePrefix
					pkgNotFoundErr = &PackageNotInModuleError{MainModules: []module.Version{mainModule}, Pattern: pkg}
				}
				continue
			}
			return pkg, nil
		}
	}
	if pkgNotFoundErr != nil {
		return "", pkgNotFoundErr
	}

	if sub := search.InDir(absDir, cfg.GOROOTsrc); sub != "" && sub != "." && !strings.Contains(sub, "@") {
		pkg := filepath.ToSlash(sub)
		if pkg == "builtin" {
			return "", errPkgIsBuiltin
		}
		return pkg, nil
	}

	pkg := pathInModuleCache(ctx, absDir, rs)
	if pkg == "" {
		dirstr := fmt.Sprintf("directory %s", base.ShortPath(absDir))
		if dirstr == "directory ." {
			dirstr = "current directory"
		}
		if inWorkspaceMode() {
			if mr := findModuleRoot(absDir); mr != "" {
				return "", fmt.Errorf("%s is contained in a module that is not one of the workspace modules listed in go.work. You can add the module to the workspace using:\n\tgo work use %s", dirstr, base.ShortPath(mr))
			}
			return "", fmt.Errorf("%s outside modules listed in go.work or their selected dependencies", dirstr)
		}
		return "", fmt.Errorf("%s outside main module or its selected dependencies", dirstr)
	}
	return pkg, nil
}

var (
	errDirectoryNotFound = errors.New("directory not found")
	errPkgIsGorootSrc    = errors.New("GOROOT/src is not an importable package")
	errPkgIsBuiltin      = errors.New(`"builtin" is a pseudo-package, not an importable package`)
)

// pathInModuleCache returns the import path of the directory dir,
// if dir is in the module cache copy of a module in our build list.
func pathInModuleCache(ctx context.Context, dir string, rs *Requirements) string {
	tryMod := func(m module.Version) (string, bool) {
		if gover.IsToolchain(m.Path) {
			return "", false
		}
		var root string
		var err error
		if repl := Replacement(m); repl.Path != "" && repl.Version == "" {
			root = repl.Path
			if !filepath.IsAbs(root) {
				root = filepath.Join(replaceRelativeTo(), root)
			}
		} else if repl.Path != "" {
			root, err = modfetch.DownloadDir(ctx, repl)
		} else {
			root, err = modfetch.DownloadDir(ctx, m)
		}
		if err != nil {
			return "", false
		}

		sub := search.InDir(dir, root)
		if sub == "" {
			return "", false
		}
		sub = filepath.ToSlash(sub)
		if strings.Contains(sub, "/vendor/") || strings.HasPrefix(sub, "vendor/") || strings.Contains(sub, "@") {
			return "", false
		}

		return path.Join(m.Path, filepath.ToSlash(sub)), true
	}

	if rs.pruning == pruned {
		for _, m := range rs.rootModules {
			if v, _ := rs.rootSelected(m.Path); v != m.Version {
				continue // m is a root, but we have a higher root for the same path.
			}
			if importPath, ok := tryMod(m); ok {
				// checkMultiplePaths ensures that a module can be used for at most one
				// requirement, so this must be it.
				return importPath
			}
		}
	}

	// None of the roots contained dir, or the graph is unpruned (so we don't want
	// to distinguish between roots and transitive dependencies). Either way,
	// check the full graph to see if the directory is a non-root dependency.
	//
	// If the roots are not consistent with the full module graph, the selected
	// versions of root modules may differ from what we already checked above.
	// Re-check those paths too.

	mg, _ := rs.Graph(ctx)
	var importPath string
	for _, m := range mg.BuildList() {
		var found bool
		importPath, found = tryMod(m)
		if found {
			break
		}
	}
	return importPath
}

// ImportFromFiles adds modules to the build list as needed
// to satisfy the imports in the named Go source files.
//
// Errors in missing dependencies are silenced.
//
// TODO(bcmills): Silencing errors seems off. Take a closer look at this and
// figure out what the error-reporting actually ought to be.
func ImportFromFiles(ctx context.Context, gofiles []string) {
	rs := LoadModFile(ctx)

	tags := imports.Tags()
	imports, testImports, err := imports.ScanFiles(gofiles, tags)
	if err != nil {
		base.Fatal(err)
	}

	loaded = loadFromRoots(ctx, loaderParams{
		PackageOpts: PackageOpts{
			Tags:                  tags,
			ResolveMissingImports: true,
			SilencePackageErrors:  true,
		},
		requirements: rs,
		listRoots: func(*Requirements) (roots []string) {
			roots = append(roots, imports...)
			roots = append(roots, testImports...)
			return roots
		},
	})
	requirements = loaded.requirements

	if !ExplicitWriteGoMod {
		if err := commitRequirements(ctx, WriteOpts{}); err != nil {
			base.Fatal(err)
		}
	}
}

// DirImportPath returns the effective import path for dir,
// provided it is within a main module, or else returns ".".
func (mms *MainModuleSet) DirImportPath(ctx context.Context, dir string) (path string, m module.Version) {
	if !HasModRoot() {
		return ".", module.Version{}
	}
	LoadModFile(ctx) // Sets targetPrefix.

	if !filepath.IsAbs(dir) {
		dir = filepath.Join(base.Cwd(), dir)
	} else {
		dir = filepath.Clean(dir)
	}

	var longestPrefix string
	var longestPrefixPath string
	var longestPrefixVersion module.Version
	for _, v := range mms.Versions() {
		modRoot := mms.ModRoot(v)
		if dir == modRoot {
			return mms.PathPrefix(v), v
		}
		if str.HasFilePathPrefix(dir, modRoot) {
			pathPrefix := MainModules.PathPrefix(v)
			if pathPrefix > longestPrefix {
				longestPrefix = pathPrefix
				longestPrefixVersion = v
				suffix := filepath.ToSlash(str.TrimFilePathPrefix(dir, modRoot))
				if strings.HasPrefix(suffix, "vendor/") {
					longestPrefixPath = suffix[len("vendor/"):]
					continue
				}
				longestPrefixPath = pathpkg.Join(mms.PathPrefix(v), suffix)
			}
		}
	}
	if len(longestPrefix) > 0 {
		return longestPrefixPath, longestPrefixVersion
	}

	return ".", module.Version{}
}

// PackageModule returns the module providing the package named by the import path.
func PackageModule(path string) module.Version {
	pkg, ok := loaded.pkgCache.Get(path)
	if !ok {
		return module.Version{}
	}
	return pkg.mod
}

// Lookup returns the source directory, import path, and any loading error for
// the package at path as imported from the package in parentDir.
// Lookup requires that one of the Load functions in this package has already
// been called.
func Lookup(parentPath string, parentIsStd bool, path string) (dir, realPath string, err error) {
	if path == "" {
		panic("Lookup called with empty package path")
	}

	if parentIsStd {
		path = loaded.stdVendor(parentPath, path)
	}
	pkg, ok := loaded.pkgCache.Get(path)
	if !ok {
		// The loader should have found all the relevant paths.
		// There are a few exceptions, though:
		//	- during go list without -test, the p.Resolve calls to process p.TestImports and p.XTestImports
		//	  end up here to canonicalize the import paths.
		//	- during any load, non-loaded packages like "unsafe" end up here.
		//	- during any load, build-injected dependencies like "runtime/cgo" end up here.
		//	- because we ignore appengine/* in the module loader,
		//	  the dependencies of any actual appengine/* library end up here.
		dir := findStandardImportPath(path)
		if dir != "" {
			return dir, path, nil
		}
		return "", "", errMissing
	}
	return pkg.dir, pkg.path, pkg.err
}

// A loader manages the process of loading information about
// the required packages for a particular build,
// checking that the packages are available in the module set,
// and updating the module set if needed.
type loader struct {
	loaderParams

	// allClosesOverTests indicates whether the "all" pattern includes
	// dependencies of tests outside the main module (as in Go 1.11–1.15).
	// (Otherwise — as in Go 1.16+ — the "all" pattern includes only the packages
	// transitively *imported by* the packages and tests in the main module.)
	allClosesOverTests bool

	// skipImportModFiles indicates whether we may skip loading go.mod files
	// for imported packages (as in 'go mod tidy' in Go 1.17–1.20).
	skipImportModFiles bool

	work *par.Queue

	// reset on each iteration
	roots    []*loadPkg
	pkgCache *par.Cache[string, *loadPkg]
	pkgs     []*loadPkg // transitive closure of loaded packages and tests; populated in buildStacks
}

// loaderParams configure the packages loaded by, and the properties reported
// by, a loader instance.
type loaderParams struct {
	PackageOpts
	requirements *Requirements

	allPatternIsRoot bool // Is the "all" pattern an additional root?

	listRoots func(rs *Requirements) []string
}

func (ld *loader) reset() {
	select {
	case <-ld.work.Idle():
	default:
		panic("loader.reset when not idle")
	}

	ld.roots = nil
	ld.pkgCache = new(par.Cache[string, *loadPkg])
	ld.pkgs = nil
}

// error reports an error via either os.Stderr or base.Error,
// according to whether ld.AllowErrors is set.
func (ld *loader) error(err error) {
	if ld.AllowErrors {
		fmt.Fprintf(os.Stderr, "go: %v\n", err)
	} else if ld.Switcher != nil {
		ld.Switcher.Error(err)
	} else {
		base.Error(err)
	}
}

// switchIfErrors switches toolchains if a switch is needed.
func (ld *loader) switchIfErrors(ctx context.Context) {
	if ld.Switcher != nil {
		ld.Switcher.Switch(ctx)
	}
}

// exitIfErrors switches toolchains if a switch is needed
// or else exits if any errors have been reported.
func (ld *loader) exitIfErrors(ctx context.Context) {
	ld.switchIfErrors(ctx)
	base.ExitIfErrors()
}

// goVersion reports the Go version that should be used for the loader's
// requirements: ld.TidyGoVersion if set, or ld.requirements.GoVersion()
// otherwise.
func (ld *loader) goVersion() string {
	if ld.TidyGoVersion != "" {
		return ld.TidyGoVersion
	}
	return ld.requirements.GoVersion()
}

// A loadPkg records information about a single loaded package.
type loadPkg struct {
	// Populated at construction time:
	path   string // import path
	testOf *loadPkg

	// Populated at construction time and updated by (*loader).applyPkgFlags:
	flags atomicLoadPkgFlags

	// Populated by (*loader).load:
	mod         module.Version // module providing package
	dir         string         // directory containing source code
	err         error          // error loading package
	imports     []*loadPkg     // packages imported by this one
	testImports []string       // test-only imports, saved for use by pkg.test.
	inStd       bool
	altMods     []module.Version // modules that could have contained the package but did not

	// Populated by (*loader).pkgTest:
	testOnce sync.Once
	test     *loadPkg

	// Populated by postprocessing in (*loader).buildStacks:
	stack *loadPkg // package importing this one in minimal import stack for this pkg
}

// loadPkgFlags is a set of flags tracking metadata about a package.
type loadPkgFlags int8

const (
	// pkgInAll indicates that the package is in the "all" package pattern,
	// regardless of whether we are loading the "all" package pattern.
	//
	// When the pkgInAll flag and pkgImportsLoaded flags are both set, the caller
	// who set the last of those flags must propagate the pkgInAll marking to all
	// of the imports of the marked package.
	//
	// A test is marked with pkgInAll if that test would promote the packages it
	// imports to be in "all" (such as when the test is itself within the main
	// module, or when ld.allClosesOverTests is true).
	pkgInAll loadPkgFlags = 1 << iota

	// pkgIsRoot indicates that the package matches one of the root package
	// patterns requested by the caller.
	//
	// If LoadTests is set, then when pkgIsRoot and pkgImportsLoaded are both set,
	// the caller who set the last of those flags must populate a test for the
	// package (in the pkg.test field).
	//
	// If the "all" pattern is included as a root, then non-test packages in "all"
	// are also roots (and must be marked pkgIsRoot).
	pkgIsRoot

	// pkgFromRoot indicates that the package is in the transitive closure of
	// imports starting at the roots. (Note that every package marked as pkgIsRoot
	// is also trivially marked pkgFromRoot.)
	pkgFromRoot

	// pkgImportsLoaded indicates that the imports and testImports fields of a
	// loadPkg have been populated.
	pkgImportsLoaded
)

// has reports whether all of the flags in cond are set in f.
func (f loadPkgFlags) has(cond loadPkgFlags) bool {
	return f&cond == cond
}

// An atomicLoadPkgFlags stores a loadPkgFlags for which individual flags can be
// added atomically.
type atomicLoadPkgFlags struct {
	bits atomic.Int32
}

// update sets the given flags in af (in addition to any flags already set).
//
// update returns the previous flag state so that the caller may determine which
// flags were newly-set.
func (af *atomicLoadPkgFlags) update(flags loadPkgFlags) (old loadPkgFlags) {
	for {
		old := af.bits.Load()
		new := old | int32(flags)
		if new == old || af.bits.CompareAndSwap(old, new) {
			return loadPkgFlags(old)
		}
	}
}

// has reports whether all of the flags in cond are set in af.
func (af *atomicLoadPkgFlags) has(cond loadPkgFlags) bool {
	return loadPkgFlags(af.bits.Load())&cond == cond
}

// isTest reports whether pkg is a test of another package.
func (pkg *loadPkg) isTest() bool {
	return pkg.testOf != nil
}

// fromExternalModule reports whether pkg was loaded from a module other than
// the main module.
func (pkg *loadPkg) fromExternalModule() bool {
	if pkg.mod.Path == "" {
		return false // loaded from the standard library, not a module
	}
	return !MainModules.Contains(pkg.mod.Path)
}

var errMissing = errors.New("cannot find package")

// loadFromRoots attempts to load the build graph needed to process a set of
// root packages and their dependencies.
//
// The set of root packages is returned by the params.listRoots function, and
// expanded to the full set of packages by tracing imports (and possibly tests)
// as needed.
func loadFromRoots(ctx context.Context, params loaderParams) *loader {
	ld := &loader{
		loaderParams: params,
		work:         par.NewQueue(runtime.GOMAXPROCS(0)),
	}

	if ld.requirements.pruning == unpruned {
		// If the module graph does not support pruning, we assume that we will need
		// the full module graph in order to load package dependencies.
		//
		// This might not be strictly necessary, but it matches the historical
		// behavior of the 'go' command and keeps the go.mod file more consistent in
		// case of erroneous hand-edits — which are less likely to be detected by
		// spot-checks in modules that do not maintain the expanded go.mod
		// requirements needed for graph pruning.
		var err error
		ld.requirements, _, err = expandGraph(ctx, ld.requirements)
		if err != nil {
			ld.error(err)
		}
	}
	ld.exitIfErrors(ctx)

	updateGoVersion := func() {
		goVersion := ld.goVersion()

		if ld.requirements.pruning != workspace {
			var err error
			ld.requirements, err = convertPruning(ctx, ld.requirements, pruningForGoVersion(goVersion))
			if err != nil {
				ld.error(err)
				ld.exitIfErrors(ctx)
			}
		}

		// If the module's Go version omits go.sum entries for go.mod files for test
		// dependencies of external packages, avoid loading those files in the first
		// place.
		ld.skipImportModFiles = ld.Tidy && gover.Compare(goVersion, gover.TidyGoModSumVersion) < 0

		// If the module's go version explicitly predates the change in "all" for
		// graph pruning, continue to use the older interpretation.
		ld.allClosesOverTests = gover.Compare(goVersion, gover.NarrowAllVersion) < 0 && !ld.UseVendorAll
	}

	for {
		ld.reset()
		updateGoVersion()

		// Load the root packages and their imports.
		// Note: the returned roots can change on each iteration,
		// since the expansion of package patterns depends on the
		// build list we're using.
		rootPkgs := ld.listRoots(ld.requirements)

		if ld.requirements.pruning == pruned && cfg.BuildMod == "mod" {
			// Before we start loading transitive imports of packages, locate all of
			// the root packages and promote their containing modules to root modules
			// dependencies. If their go.mod files are tidy (the common case) and the
			// set of root packages does not change then we can select the correct
			// versions of all transitive imports on the first try and complete
			// loading in a single iteration.
			changedBuildList := ld.preloadRootModules(ctx, rootPkgs)
			if changedBuildList {
				// The build list has changed, so the set of root packages may have also
				// changed. Start over to pick up the changes. (Preloading roots is much
				// cheaper than loading the full import graph, so we would rather pay
				// for an extra iteration of preloading than potentially end up
				// discarding the result of a full iteration of loading.)
				continue
			}
		}

		inRoots := map[*loadPkg]bool{}
		for _, path := range rootPkgs {
			root := ld.pkg(ctx, path, pkgIsRoot)
			if !inRoots[root] {
				ld.roots = append(ld.roots, root)
				inRoots[root] = true
			}
		}

		// ld.pkg adds imported packages to the work queue and calls applyPkgFlags,
		// which adds tests (and test dependencies) as needed.
		//
		// When all of the work in the queue has completed, we'll know that the
		// transitive closure of dependencies has been loaded.
		<-ld.work.Idle()

		ld.buildStacks()

		changed, err := ld.updateRequirements(ctx)
		if err != nil {
			ld.error(err)
			break
		}
		if changed {
			// Don't resolve missing imports until the module graph has stabilized.
			// If the roots are still changing, they may turn out to specify a
			// requirement on the missing package(s), and we would rather use a
			// version specified by a new root than add a new dependency on an
			// unrelated version.
			continue
		}

		if !ld.ResolveMissingImports || (!HasModRoot() && !allowMissingModuleImports) {
			// We've loaded as much as we can without resolving missing imports.
			break
		}

		modAddedBy, err := ld.resolveMissingImports(ctx)
		if err != nil {
			ld.error(err)
			break
		}
		if len(modAddedBy) == 0 {
			// The roots are stable, and we've resolved all of the missing packages
			// that we can.
			break
		}

		toAdd := make([]module.Version, 0, len(modAddedBy))
		for m := range modAddedBy {
			toAdd = append(toAdd, m)
		}
		gover.ModSort(toAdd) // to make errors deterministic

		// We ran updateRequirements before resolving missing imports and it didn't
		// make any changes, so we know that the requirement graph is already
		// consistent with ld.pkgs: we don't need to pass ld.pkgs to updateRoots
		// again. (That would waste time looking for changes that we have already
		// applied.)
		var noPkgs []*loadPkg
		// We also know that we're going to call updateRequirements again next
		// iteration so we don't need to also update it here. (That would waste time
		// computing a "direct" map that we'll have to recompute later anyway.)
		direct := ld.requirements.direct
		rs, err := updateRoots(ctx, direct, ld.requirements, noPkgs, toAdd, ld.AssumeRootsImported)
		if err != nil {
			// If an error was found in a newly added module, report the package
			// import stack instead of the module requirement stack. Packages
			// are more descriptive.
			if err, ok := err.(*mvs.BuildListError); ok {
				if pkg := modAddedBy[err.Module()]; pkg != nil {
					ld.error(fmt.Errorf("%s: %w", pkg.stackText(), err.Err))
					break
				}
			}
			ld.error(err)
			break
		}
		if slices.Equal(rs.rootModules, ld.requirements.rootModules) {
			// Something is deeply wrong. resolveMissingImports gave us a non-empty
			// set of modules to add to the graph, but adding those modules had no
			// effect — either they were already in the graph, or updateRoots did not
			// add them as requested.
			panic(fmt.Sprintf("internal error: adding %v to module graph had no effect on root requirements (%v)", toAdd, rs.rootModules))
		}
		ld.requirements = rs
	}
	ld.exitIfErrors(ctx)

	// Tidy the build list, if applicable, before we report errors.
	// (The process of tidying may remove errors from irrelevant dependencies.)
	if ld.Tidy {
		rs, err := tidyRoots(ctx, ld.requirements, ld.pkgs)
		if err != nil {
			ld.error(err)
		} else {
			if ld.TidyGoVersion != "" {
				// Attempt to switch to the requested Go version. We have been using its
				// pruning and semantics all along, but there may have been — and may
				// still be — requirements on higher versions in the graph.
				tidy := overrideRoots(ctx, rs, []module.Version{{Path: "go", Version: ld.TidyGoVersion}})
				mg, err := tidy.Graph(ctx)
				if err != nil {
					ld.error(err)
				}
				if v := mg.Selected("go"); v == ld.TidyGoVersion {
					rs = tidy
				} else {
					conflict := Conflict{
						Path: mg.g.FindPath(func(m module.Version) bool {
							return m.Path == "go" && m.Version == v
						})[1:],
						Constraint: module.Version{Path: "go", Version: ld.TidyGoVersion},
					}
					msg := conflict.Summary()
					if cfg.BuildV {
						msg = conflict.String()
					}
					ld.error(errors.New(msg))
				}
			}

			if ld.requirements.pruning == pruned {
				// We continuously add tidy roots to ld.requirements during loading, so
				// at this point the tidy roots (other than possibly the "go" version
				// edited above) should be a subset of the roots of ld.requirements,
				// ensuring that no new dependencies are brought inside the
				// graph-pruning horizon.
				// If that is not the case, there is a bug in the loading loop above.
				for _, m := range rs.rootModules {
					if m.Path == "go" && ld.TidyGoVersion != "" {
						continue
					}
					if v, ok := ld.requirements.rootSelected(m.Path); !ok || v != m.Version {
						ld.error(fmt.Errorf("internal error: a requirement on %v is needed but was not added during package loading (selected %s)", m, v))
					}
				}
			}

			ld.requirements = rs
		}

		ld.exitIfErrors(ctx)
	}

	// Report errors, if any.
	for _, pkg := range ld.pkgs {
		if pkg.err == nil {
			continue
		}

		// Add importer information to checksum errors.
		if sumErr := (*ImportMissingSumError)(nil); errors.As(pkg.err, &sumErr) {
			if importer := pkg.stack; importer != nil {
				sumErr.importer = importer.path
				sumErr.importerVersion = importer.mod.Version
				sumErr.importerIsTest = importer.testOf != nil
			}
		}

		if stdErr := (*ImportMissingError)(nil); errors.As(pkg.err, &stdErr) && stdErr.isStd {
			// Add importer go version information to import errors of standard
			// library packages arising from newer releases.
			if importer := pkg.stack; importer != nil {
				if v, ok := rawGoVersion.Load(importer.mod); ok && gover.Compare(gover.Local(), v.(string)) < 0 {
					stdErr.importerGoVersion = v.(string)
				}
			}
			if ld.SilenceMissingStdImports {
				continue
			}
		}
		if ld.SilencePackageErrors {
			continue
		}
		if ld.SilenceNoGoErrors && errors.Is(pkg.err, imports.ErrNoGo) {
			continue
		}

		ld.error(fmt.Errorf("%s: %w", pkg.stackText(), pkg.err))
	}

	ld.checkMultiplePaths()
	return ld
}

// updateRequirements ensures that ld.requirements is consistent with the
// information gained from ld.pkgs.
//
// In particular:
//
//   - Modules that provide packages directly imported from the main module are
//     marked as direct, and are promoted to explicit roots. If a needed root
//     cannot be promoted due to -mod=readonly or -mod=vendor, the importing
//     package is marked with an error.
//
//   - If ld scanned the "all" pattern independent of build constraints, it is
//     guaranteed to have seen every direct import. Module dependencies that did
//     not provide any directly-imported package are then marked as indirect.
//
//   - Root dependencies are updated to their selected versions.
//
// The "changed" return value reports whether the update changed the selected
// version of any module that either provided a loaded package or may now
// provide a package that was previously unresolved.
func (ld *loader) updateRequirements(ctx context.Context) (changed bool, err error) {
	rs := ld.requirements

	// direct contains the set of modules believed to provide packages directly
	// imported by the main module.
	var direct map[string]bool

	// If we didn't scan all of the imports from the main module, or didn't use
	// imports.AnyTags, then we didn't necessarily load every package that
	// contributes “direct” imports — so we can't safely mark existing direct
	// dependencies in ld.requirements as indirect-only. Propagate them as direct.
	loadedDirect := ld.allPatternIsRoot && maps.Equal(ld.Tags, imports.AnyTags())
	if loadedDirect {
		direct = make(map[string]bool)
	} else {
		// TODO(bcmills): It seems like a shame to allocate and copy a map here when
		// it will only rarely actually vary from rs.direct. Measure this cost and
		// maybe avoid the copy.
		direct = make(map[string]bool, len(rs.direct))
		for mPath := range rs.direct {
			direct[mPath] = true
		}
	}

	var maxTooNew *gover.TooNewError
	for _, pkg := range ld.pkgs {
		if pkg.err != nil {
			if tooNew := (*gover.TooNewError)(nil); errors.As(pkg.err, &tooNew) {
				if maxTooNew == nil || gover.Compare(tooNew.GoVersion, maxTooNew.GoVersion) > 0 {
					maxTooNew = tooNew
				}
			}
		}
		if pkg.mod.Version != "" || !MainModules.Contains(pkg.mod.Path) {
			continue
		}

		for _, dep := range pkg.imports {
			if !dep.fromExternalModule() {
				continue
			}

			if inWorkspaceMode() {
				// In workspace mode / workspace pruning mode, the roots are the main modules
				// rather than the main module's direct dependencies. The check below on the selected
				// roots does not apply.
				if cfg.BuildMod == "vendor" {
					// In workspace vendor mode, we don't need to load the requirements of the workspace
					// modules' dependencies so the check below doesn't work. But that's okay, because
					// checking whether modules are required directly for the purposes of pruning is
					// less important in vendor mode: if we were able to load the package, we have
					// everything we need  to build the package, and dependencies' tests are pruned out
					// of the vendor directory anyway.
					continue
				}
				if mg, err := rs.Graph(ctx); err != nil {
					return false, err
				} else if _, ok := mg.RequiredBy(dep.mod); !ok {
					// dep.mod is not an explicit dependency, but needs to be.
					// See comment on error returned below.
					pkg.err = &DirectImportFromImplicitDependencyError{
						ImporterPath: pkg.path,
						ImportedPath: dep.path,
						Module:       dep.mod,
					}
				}
			} else if pkg.err == nil && cfg.BuildMod != "mod" {
				if v, ok := rs.rootSelected(dep.mod.Path); !ok || v != dep.mod.Version {
					// dep.mod is not an explicit dependency, but needs to be.
					// Because we are not in "mod" mode, we will not be able to update it.
					// Instead, mark the importing package with an error.
					//
					// TODO(#41688): The resulting error message fails to include the file
					// position of the import statement (because that information is not
					// tracked by the module loader). Figure out how to plumb the import
					// position through.
					pkg.err = &DirectImportFromImplicitDependencyError{
						ImporterPath: pkg.path,
						ImportedPath: dep.path,
						Module:       dep.mod,
					}
					// cfg.BuildMod does not allow us to change dep.mod to be a direct
					// dependency, so don't mark it as such.
					continue
				}
			}

			// dep is a package directly imported by a package or test in the main
			// module and loaded from some other module (not the standard library).
			// Mark its module as a direct dependency.
			direct[dep.mod.Path] = true
		}
	}
	if maxTooNew != nil {
		return false, maxTooNew
	}

	var addRoots []module.Version
	if ld.Tidy {
		// When we are tidying a module with a pruned dependency graph, we may need
		// to add roots to preserve the versions of indirect, test-only dependencies
		// that are upgraded above or otherwise missing from the go.mod files of
		// direct dependencies. (For example, the direct dependency might be a very
		// stable codebase that predates modules and thus lacks a go.mod file, or
		// the author of the direct dependency may have forgotten to commit a change
		// to the go.mod file, or may have made an erroneous hand-edit that causes
		// it to be untidy.)
		//
		// Promoting an indirect dependency to a root adds the next layer of its
		// dependencies to the module graph, which may increase the selected
		// versions of other modules from which we have already loaded packages.
		// So after we promote an indirect dependency to a root, we need to reload
		// packages, which means another iteration of loading.
		//
		// As an extra wrinkle, the upgrades due to promoting a root can cause
		// previously-resolved packages to become unresolved. For example, the
		// module providing an unstable package might be upgraded to a version
		// that no longer contains that package. If we then resolve the missing
		// package, we might add yet another root that upgrades away some other
		// dependency. (The tests in mod_tidy_convergence*.txt illustrate some
		// particularly worrisome cases.)
		//
		// To ensure that this process of promoting, adding, and upgrading roots
		// eventually terminates, during iteration we only ever add modules to the
		// root set — we only remove irrelevant roots at the very end of
		// iteration, after we have already added every root that we plan to need
		// in the (eventual) tidy root set.
		//
		// Since we do not remove any roots during iteration, even if they no
		// longer provide any imported packages, the selected versions of the
		// roots can only increase and the set of roots can only expand. The set
		// of extant root paths is finite and the set of versions of each path is
		// finite, so the iteration *must* reach a stable fixed-point.
		tidy, err := tidyRoots(ctx, rs, ld.pkgs)
		if err != nil {
			return false, err
		}
		addRoots = tidy.rootModules
	}

	rs, err = updateRoots(ctx, direct, rs, ld.pkgs, addRoots, ld.AssumeRootsImported)
	if err != nil {
		// We don't actually know what even the root requirements are supposed to be,
		// so we can't proceed with loading. Return the error to the caller
		return false, err
	}

	if rs.GoVersion() != ld.requirements.GoVersion() {
		// A change in the selected Go version may or may not affect the set of
		// loaded packages, but in some cases it can change the meaning of the "all"
		// pattern, the level of pruning in the module graph, and even the set of
		// packages present in the standard library. If it has changed, it's best to
		// reload packages once more to be sure everything is stable.
		changed = true
	} else if rs != ld.requirements && !slices.Equal(rs.rootModules, ld.requirements.rootModules) {
		// The roots of the module graph have changed in some way (not just the
		// "direct" markings). Check whether the changes affected any of the loaded
		// packages.
		mg, err := rs.Graph(ctx)
		if err != nil {
			return false, err
		}
		for _, pkg := range ld.pkgs {
			if pkg.fromExternalModule() && mg.Selected(pkg.mod.Path) != pkg.mod.Version {
				changed = true
				break
			}
			if pkg.err != nil {
				// Promoting a module to a root may resolve an import that was
				// previously missing (by pulling in a previously-prune dependency that
				// provides it) or ambiguous (by promoting exactly one of the
				// alternatives to a root and ignoring the second-level alternatives) or
				// otherwise errored out (by upgrading from a version that cannot be
				// fetched to one that can be).
				//
				// Instead of enumerating all of the possible errors, we'll just check
				// whether importFromModules returns nil for the package.
				// False-positives are ok: if we have a false-positive here, we'll do an
				// extra iteration of package loading this time, but we'll still
				// converge when the root set stops changing.
				//
				// In some sense, we can think of this as ‘upgraded the module providing
				// pkg.path from "none" to a version higher than "none"’.
				if _, _, _, _, err = importFromModules(ctx, pkg.path, rs, nil, ld.skipImportModFiles); err == nil {
					changed = true
					break
				}
			}
		}
	}

	ld.requirements = rs
	return changed, nil
}

// resolveMissingImports returns a set of modules that could be added as
// dependencies in order to resolve missing packages from pkgs.
//
// The newly-resolved packages are added to the addedModuleFor map, and
// resolveMissingImports returns a map from each new module version to
// the first missing package that module would resolve.
func (ld *loader) resolveMissingImports(ctx context.Context) (modAddedBy map[module.Version]*loadPkg, err error) {
	type pkgMod struct {
		pkg *loadPkg
		mod *module.Version
	}
	var pkgMods []pkgMod
	for _, pkg := range ld.pkgs {
		if pkg.err == nil {
			continue
		}
		if pkg.isTest() {
			// If we are missing a test, we are also missing its non-test version, and
			// we should only add the missing import once.
			continue
		}
		if !errors.As(pkg.err, new(*ImportMissingError)) {
			// Leave other errors for Import or load.Packages to report.
			continue
		}

		pkg := pkg
		var mod module.Version
		ld.work.Add(func() {
			var err error
			mod, err = queryImport(ctx, pkg.path, ld.requirements)
			if err != nil {
				var ime *ImportMissingError
				if errors.As(err, &ime) {
					for curstack := pkg.stack; curstack != nil; curstack = curstack.stack {
						if MainModules.Contains(curstack.mod.Path) {
							ime.ImportingMainModule = curstack.mod
							break
						}
					}
				}
				// pkg.err was already non-nil, so we can reasonably attribute the error
				// for pkg to either the original error or the one returned by
				// queryImport. The existing error indicates only that we couldn't find
				// the package, whereas the query error also explains why we didn't fix
				// the problem — so we prefer the latter.
				pkg.err = err
			}

			// err is nil, but we intentionally leave pkg.err non-nil and pkg.mod
			// unset: we still haven't satisfied other invariants of a
			// successfully-loaded package, such as scanning and loading the imports
			// of that package. If we succeed in resolving the new dependency graph,
			// the caller can reload pkg and update the error at that point.
			//
			// Even then, the package might not be loaded from the version we've
			// identified here. The module may be upgraded by some other dependency,
			// or by a transitive dependency of mod itself, or — less likely — the
			// package may be rejected by an AllowPackage hook or rendered ambiguous
			// by some other newly-added or newly-upgraded dependency.
		})

		pkgMods = append(pkgMods, pkgMod{pkg: pkg, mod: &mod})
	}
	<-ld.work.Idle()

	modAddedBy = map[module.Version]*loadPkg{}

	var (
		maxTooNew    *gover.TooNewError
		maxTooNewPkg *loadPkg
	)
	for _, pm := range pkgMods {
		if tooNew := (*gover.TooNewError)(nil); errors.As(pm.pkg.err, &tooNew) {
			if maxTooNew == nil || gover.Compare(tooNew.GoVersion, maxTooNew.GoVersion) > 0 {
				maxTooNew = tooNew
				maxTooNewPkg = pm.pkg
			}
		}
	}
	if maxTooNew != nil {
		fmt.Fprintf(os.Stderr, "go: toolchain upgrade needed to resolve %s\n", maxTooNewPkg.path)
		return nil, maxTooNew
	}

	for _, pm := range pkgMods {
		pkg, mod := pm.pkg, *pm.mod
		if mod.Path == "" {
			continue
		}

		fmt.Fprintf(os.Stderr, "go: found %s in %s %s\n", pkg.path, mod.Path, mod.Version)
		if modAddedBy[mod] == nil {
			modAddedBy[mod] = pkg
		}
	}

	return modAddedBy, nil
}

// pkg locates the *loadPkg for path, creating and queuing it for loading if
// needed, and updates its state to reflect the given flags.
//
// The imports of the returned *loadPkg will be loaded asynchronously in the
// ld.work queue, and its test (if requested) will also be populated once
// imports have been resolved. When ld.work goes idle, all transitive imports of
// the requested package (and its test, if requested) will have been loaded.
func (ld *loader) pkg(ctx context.Context, path string, flags loadPkgFlags) *loadPkg {
	if flags.has(pkgImportsLoaded) {
		panic("internal error: (*loader).pkg called with pkgImportsLoaded flag set")
	}

	pkg := ld.pkgCache.Do(path, func() *loadPkg {
		pkg := &loadPkg{
			path: path,
		}
		ld.applyPkgFlags(ctx, pkg, flags)

		ld.work.Add(func() { ld.load(ctx, pkg) })
		return pkg
	})

	ld.applyPkgFlags(ctx, pkg, flags)
	return pkg
}

// applyPkgFlags updates pkg.flags to set the given flags and propagate the
// (transitive) effects of those flags, possibly loading or enqueueing further
// packages as a result.
func (ld *loader) applyPkgFlags(ctx context.Context, pkg *loadPkg, flags loadPkgFlags) {
	if flags == 0 {
		return
	}

	if flags.has(pkgInAll) && ld.allPatternIsRoot && !pkg.isTest() {
		// This package matches a root pattern by virtue of being in "all".
		flags |= pkgIsRoot
	}
	if flags.has(pkgIsRoot) {
		flags |= pkgFromRoot
	}

	old := pkg.flags.update(flags)
	new := old | flags
	if new == old || !new.has(pkgImportsLoaded) {
		// We either didn't change the state of pkg, or we don't know anything about
		// its dependencies yet. Either way, we can't usefully load its test or
		// update its dependencies.
		return
	}

	if !pkg.isTest() {
		// Check whether we should add (or update the flags for) a test for pkg.
		// ld.pkgTest is idempotent and extra invocations are inexpensive,
		// so it's ok if we call it more than is strictly necessary.
		wantTest := false
		switch {
		case ld.allPatternIsRoot && MainModules.Contains(pkg.mod.Path):
			// We are loading the "all" pattern, which includes packages imported by
			// tests in the main module. This package is in the main module, so we
			// need to identify the imports of its test even if LoadTests is not set.
			//
			// (We will filter out the extra tests explicitly in computePatternAll.)
			wantTest = true

		case ld.allPatternIsRoot && ld.allClosesOverTests && new.has(pkgInAll):
			// This variant of the "all" pattern includes imports of tests of every
			// package that is itself in "all", and pkg is in "all", so its test is
			// also in "all" (as above).
			wantTest = true

		case ld.LoadTests && new.has(pkgIsRoot):
			// LoadTest explicitly requests tests of “the root packages”.
			wantTest = true
		}

		if wantTest {
			var testFlags loadPkgFlags
			if MainModules.Contains(pkg.mod.Path) || (ld.allClosesOverTests && new.has(pkgInAll)) {
				// Tests of packages in the main module are in "all", in the sense that
				// they cause the packages they import to also be in "all". So are tests
				// of packages in "all" if "all" closes over test dependencies.
				testFlags |= pkgInAll
			}
			ld.pkgTest(ctx, pkg, testFlags)
		}
	}

	if new.has(pkgInAll) && !old.has(pkgInAll|pkgImportsLoaded) {
		// We have just marked pkg with pkgInAll, or we have just loaded its
		// imports, or both. Now is the time to propagate pkgInAll to the imports.
		for _, dep := range pkg.imports {
			ld.applyPkgFlags(ctx, dep, pkgInAll)
		}
	}

	if new.has(pkgFromRoot) && !old.has(pkgFromRoot|pkgImportsLoaded) {
		for _, dep := range pkg.imports {
			ld.applyPkgFlags(ctx, dep, pkgFromRoot)
		}
	}
}

// preloadRootModules loads the module requirements needed to identify the
// selected version of each module providing a package in rootPkgs,
// adding new root modules to the module graph if needed.
func (ld *loader) preloadRootModules(ctx context.Context, rootPkgs []string) (changedBuildList bool) {
	needc := make(chan map[module.Version]bool, 1)
	needc <- map[module.Version]bool{}
	for _, path := range rootPkgs {
		path := path
		ld.work.Add(func() {
			// First, try to identify the module containing the package using only roots.
			//
			// If the main module is tidy and the package is in "all" — or if we're
			// lucky — we can identify all of its imports without actually loading the
			// full module graph.
			m, _, _, _, err := importFromModules(ctx, path, ld.requirements, nil, ld.skipImportModFiles)
			if err != nil {
				var missing *ImportMissingError
				if errors.As(err, &missing) && ld.ResolveMissingImports {
					// This package isn't provided by any selected module.
					// If we can find it, it will be a new root dependency.
					m, err = queryImport(ctx, path, ld.requirements)
				}
				if err != nil {
					// We couldn't identify the root module containing this package.
					// Leave it unresolved; we will report it during loading.
					return
				}
			}
			if m.Path == "" {
				// The package is in std or cmd. We don't need to change the root set.
				return
			}

			v, ok := ld.requirements.rootSelected(m.Path)
			if !ok || v != m.Version {
				// We found the requested package in m, but m is not a root, so
				// loadModGraph will not load its requirements. We need to promote the
				// module to a root to ensure that any other packages this package
				// imports are resolved from correct dependency versions.
				//
				// (This is the “argument invariant” from
				// https://golang.org/design/36460-lazy-module-loading.)
				need := <-needc
				need[m] = true
				needc <- need
			}
		})
	}
	<-ld.work.Idle()

	need := <-needc
	if len(need) == 0 {
		return false // No roots to add.
"""




```