Response: The user wants to understand the functionality of the provided Go code snippet. This file seems to be part of the Go compiler toolchain, specifically handling the compilation and linking steps.

Here's a breakdown of how to approach this:

1. **Identify the main struct:** The code defines `gcToolchain`, which seems to encapsulate the methods for the standard Go compiler.

2. **Analyze the methods of `gcToolchain`:** Each method likely corresponds to a specific step in the compilation/linking process. Look for keywords like "compile", "link", "asm", "pack", "ld".

3. **Examine helper functions:** Functions like `pkgPath`, `gcBackendConcurrency`, `trimpath`, `asmArgs`, `pluginPath`, `setextld` are likely used to configure or prepare arguments for the compiler and linker.

4. **Look for interaction with `cfg` and `base` packages:** These likely provide configuration and utility functions for the `go` command.

5. **Infer the overall purpose:** Based on the individual function functionalities, deduce the high-level role of this code.

6. **Provide examples (if possible):**  Illustrate how the functions might be used with concrete Go code. This requires understanding the inputs and outputs of the compilation process.

7. **Explain command-line argument handling:** Look for how the code uses configurations from `cfg` or processes external inputs.

8. **Identify potential pitfalls:** Think about common mistakes developers might make when using the Go toolchain, especially concerning the options handled by this code.
这段代码是Go语言 `go` 命令的一部分，位于 `go/src/cmd/go/internal/work/gc.go` 文件中。它的主要功能是定义和实现了使用 **标准 Go 工具链**（即 `gc` 编译器和 `link` 链接器）来编译和链接 Go 代码的过程。

下面列举一下它的主要功能：

1. **定义了 `gcToolchain` 结构体:** 这个结构体实现了 `Toolchain` 接口（虽然代码中没有显式声明接口，但根据其方法可以推断），代表了使用标准 Go 工具链进行构建的能力。

2. **提供了获取编译器和链接器路径的方法:** `compiler()` 和 `linker()` 方法分别返回 `compile` 和 `link` 工具的完整路径。

3. **实现了 `gc` 方法 (核心编译功能):**  这个方法负责调用 Go 编译器 (`compile`) 来编译 Go 源文件。它处理了以下方面：
    * **构建编译器参数:**  根据包的属性（如是否是标准库、是否包含 C/C++ 代码等）以及构建配置 (`cfg`) 生成传递给编译器的参数，例如包路径 (`-p`)、Go 语言版本 (`-lang`)、安装后缀 (`-installsuffix`)、构建 ID (`-buildid`)、是否省略调试信息 (`-dwarf=false`)、覆盖率配置 (`-coveragecfg`)、PGO profile (`-pgoprofile`)、符号 ABI 文件 (`-symabis`) 等。
    * **处理 importcfg 和 embedcfg 文件:** 如果存在 importcfg (用于指定导入包的路径) 和 embedcfg (用于嵌入文件) 的内容，则将其写入临时文件，并作为参数传递给编译器。
    * **处理汇编头文件:** 如果需要生成汇编头文件，则添加 `-asmhdr` 参数。
    * **处理 Go 源文件列表:** 将需要编译的 Go 源文件路径添加到编译器参数中。
    * **执行编译器命令:** 使用 `Builder` 提供的 `Shell` 功能执行编译器命令，并返回编译生成的对象文件路径和输出信息。
    * **处理并发编译:**  根据环境变量 `GO19CONCURRENTCOMPILATION` 和构建配置决定是否启用并发后端编译，并通过 `-c=N` 参数控制并发级别。

4. **实现了 `asm` 方法 (汇编功能):**  这个方法负责调用汇编器 (`asm`) 来汇编 `.s` 汇编源文件。它构建了传递给汇编器的参数，包括包路径、包含路径、预定义的宏等。

5. **实现了 `symabis` 方法 (生成符号 ABI 功能):** 这个方法负责调用汇编器生成符号 ABI 文件，用于描述汇编代码中定义的符号的接口。

6. **实现了 `pack` 方法 (打包对象文件功能):** 这个方法负责调用 `pack` 工具将编译生成的 `.o` 对象文件打包成 `.a` 归档文件（静态库）。

7. **实现了 `ld` 方法 (链接功能):**  这个方法负责调用链接器 (`link`) 将编译生成的对象文件和依赖库链接成最终的可执行文件或共享库。它处理了以下方面：
    * **构建链接器参数:** 根据构建模式 (`cfg.BuildBuildmode`)、是否省略调试信息、是否是插件、FIPS 140 模式等生成链接器参数，例如安装后缀 (`-installsuffix`)、是否去除符号表 (`-s`, `-w`)、插件路径 (`-pluginpath`)、FIPS 对象文件 (`-fipso`)、构建 ID (`-buildid`)、强制链接标志 (`forcedLdflags`) 等。
    * **设置外部链接器:** 根据是否存在 C++ 代码，选择合适的外部链接器 (`-extld`)，通常是 `gcc` 或 `g++`。
    * **处理输出路径:**  对于 `c-shared` 和 `plugin` 构建模式，会在目标目录中执行链接命令，以正确设置输出路径。
    * **执行链接器命令:** 使用 `Builder` 提供的 `Shell` 功能执行链接器命令。

8. **实现了 `ldShared` 方法 (链接共享库功能):**  这个方法类似于 `ld`，但专门用于链接共享库。

9. **实现了 `cc` 方法 (C 编译功能):**  这个方法目前会返回错误，表明在没有 cgo 的情况下不支持直接编译 C 源文件。

10. **定义了辅助函数:**
    * **`pkgPath`:**  根据构建模式和包的属性，返回包的路径。
    * **`gcBackendConcurrency`:**  根据环境变量和构建配置，计算并返回编译器后端并发级别。
    * **`trimpath`:**  生成 `-trimpath` 参数，用于在编译输出中去除文件路径前缀，提高构建的可重现性。
    * **`asmArgs`:** 构建汇编器的通用参数列表。
    * **`pluginPath`:** 计算插件包的路径，用于插件构建。
    * **`setextld`:**  设置 `-extld` 链接器参数。
    * **`packInternal`:** 实现了将对象文件打包成归档文件的具体逻辑。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言构建过程的核心部分，负责将 Go 源代码编译和链接成可执行文件、库或插件。它是 `go build`、`go install` 等命令的基础。

**Go 代码举例说明:**

假设我们有一个简单的 Go 程序 `main.go`:

```go
package main

import "fmt"

func main() {
	fmt.Println("Hello, world!")
}
```

当我们执行 `go build main.go` 时，`gc.go` 中的相关方法会被调用。

**假设的输入与输出 (针对 `gc` 方法):**

* **假设输入:**
    * `a`:  一个 `Action` 结构体，包含了 `main` 包的信息，如源文件路径、输出目录等。
    * `archive`: 空字符串 (因为这里不是打包成库)。
    * `importcfg`, `embedcfg`:  `nil` (假设没有复杂的导入配置和嵌入文件)。
    * `symabis`: 空字符串 (假设没有汇编代码需要生成符号 ABI)。
    * `asmhdr`: `false` (不需要生成汇编头文件)。
    * `pgoProfile`: 空字符串 (假设没有使用 PGO)。
    * `gofiles`: `[]string{"main.go"}`

* **可能的输出:**
    * `ofile`:  类似于 `_obj/main.o` 的对象文件路径。
    * `output`: 编译器输出的字节流，可能包含编译信息或错误信息。
    * `err`:  如果编译成功则为 `nil`，否则包含错误信息。

**代码推理:**

`gc` 方法会根据 `a` 中的信息和构建配置，构建类似以下的编译器命令：

```bash
$TOOLExEC go tool compile -o _obj/main.o -trimpath <trimpath_value> -p main -lang=go1.21 -complete main.go
```

其中 `<trimpath_value>` 会根据 `cfg.BuildTrimpath` 的值生成。

**命令行参数的具体处理:**

`gc.go` 主要通过 `cfg` 包来获取和处理 `go` 命令的命令行参数和环境变量。例如：

* **`-buildmode`:**  影响 `ld` 方法中链接器的参数，例如设置为 `c-shared` 时会构建共享库。
* **`-installsuffix`:**  添加到编译和链接的输出路径中，用于区分不同的构建配置。
* **`-trimpath`:**  影响 `gc` 和 `asm` 方法中 `-trimpath` 参数的生成。
* **`-gcflags` 和 `-asmflags` 和 `-ldflags`:**  分别对应 `forcedGcflags`、`p.Internal.Gcflags`，`forcedAsmflags`、`p.Internal.Asmflags`，以及 `forcedLdflags`、`root.Package.Internal.Ldflags`，允许用户传递自定义的编译器、汇编器和链接器标志。
* **环境变量 `GOOS` 和 `GOARCH`:**  影响预定义的宏，例如在 `asmArgs` 中会定义 `GOOS_linux` 或 `GOARCH_amd64`。
* **环境变量 `GO19CONCURRENTCOMPILATION`:**  控制编译器是否启用并发后端编译。

**使用者易犯错的点:**

1. **错误理解 `-gcflags`, `-asmflags`, `-ldflags` 的作用域:**  用户可能会不清楚这些标志是全局生效还是只对特定的包生效。`p.Internal.Gcflags` 等是针对特定包的，而 `forcedGcflags` 等是全局的。

   **错误示例:**  假设用户想要为 `mypackage` 设置特定的优化选项，可能会直接使用 `go build -gcflags='-l -N' mypackage`，但这会将 `-l -N` 应用于所有被编译的包，而不仅仅是 `mypackage`。正确的做法是在 `mypackage` 的构建约束或 `go build` 命令中指定。

2. **混淆构建模式:** 用户可能会不清楚不同的构建模式 (`-buildmode`) (如 `default`, `c-shared`, `plugin`) 会如何影响编译和链接过程，以及最终的输出。

   **错误示例:**  尝试使用默认的构建模式编译一个需要作为 C 共享库使用的 Go 包，会导致链接错误。必须使用 `-buildmode=c-shared`。

3. **不了解 `-trimpath` 的影响:**  用户可能会在不理解其作用的情况下使用 `-trimpath`，导致构建输出路径与预期不符，或者在调试时遇到困难。

   **易错点:**  使用 `-trimpath` 后，错误信息中的路径可能会被修改，需要注意。

4. **错误配置 C/C++ 编译环境:**  当 Go 代码中包含 C/C++ 代码时，用户可能会没有正确配置 `CC` 和 `CXX` 环境变量，导致链接失败。

   **错误示例:**  在包含 C++ 代码的 Go 项目中，如果没有设置 `CXX` 环境变量，`go build` 可能会尝试使用 `gcc` 进行 C++ 链接，导致错误。

这段代码是 Go 工具链中非常核心的部分，理解它的功能有助于深入理解 Go 语言的构建过程。

Prompt: 
```
这是路径为go/src/cmd/go/internal/work/gc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package work

import (
	"bufio"
	"bytes"
	"fmt"
	"internal/buildcfg"
	"internal/platform"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"cmd/go/internal/base"
	"cmd/go/internal/cfg"
	"cmd/go/internal/fips140"
	"cmd/go/internal/fsys"
	"cmd/go/internal/gover"
	"cmd/go/internal/load"
	"cmd/go/internal/str"
	"cmd/internal/quoted"
	"crypto/sha1"
)

// Tests can override this by setting $TESTGO_TOOLCHAIN_VERSION.
var ToolchainVersion = runtime.Version()

// The Go toolchain.

type gcToolchain struct{}

func (gcToolchain) compiler() string {
	return base.Tool("compile")
}

func (gcToolchain) linker() string {
	return base.Tool("link")
}

func pkgPath(a *Action) string {
	p := a.Package
	ppath := p.ImportPath
	if cfg.BuildBuildmode == "plugin" {
		ppath = pluginPath(a)
	} else if p.Name == "main" && !p.Internal.ForceLibrary {
		ppath = "main"
	}
	return ppath
}

func (gcToolchain) gc(b *Builder, a *Action, archive string, importcfg, embedcfg []byte, symabis string, asmhdr bool, pgoProfile string, gofiles []string) (ofile string, output []byte, err error) {
	p := a.Package
	sh := b.Shell(a)
	objdir := a.Objdir
	if archive != "" {
		ofile = archive
	} else {
		out := "_go_.o"
		ofile = objdir + out
	}

	pkgpath := pkgPath(a)
	defaultGcFlags := []string{"-p", pkgpath}
	vers := gover.Local()
	if p.Module != nil {
		v := p.Module.GoVersion
		if v == "" {
			v = gover.DefaultGoModVersion
		}
		// TODO(samthanawalla): Investigate when allowedVersion is not true.
		if allowedVersion(v) {
			vers = v
		}
	}
	defaultGcFlags = append(defaultGcFlags, "-lang=go"+gover.Lang(vers))
	if p.Standard {
		defaultGcFlags = append(defaultGcFlags, "-std")
	}

	// If we're giving the compiler the entire package (no C etc files), tell it that,
	// so that it can give good error messages about forward declarations.
	// Exceptions: a few standard packages have forward declarations for
	// pieces supplied behind-the-scenes by package runtime.
	extFiles := len(p.CgoFiles) + len(p.CFiles) + len(p.CXXFiles) + len(p.MFiles) + len(p.FFiles) + len(p.SFiles) + len(p.SysoFiles) + len(p.SwigFiles) + len(p.SwigCXXFiles)
	if p.Standard {
		switch p.ImportPath {
		case "bytes", "internal/poll", "net", "os":
			fallthrough
		case "runtime/metrics", "runtime/pprof", "runtime/trace":
			fallthrough
		case "sync", "syscall", "time":
			extFiles++
		}
	}
	if extFiles == 0 {
		defaultGcFlags = append(defaultGcFlags, "-complete")
	}
	if cfg.BuildContext.InstallSuffix != "" {
		defaultGcFlags = append(defaultGcFlags, "-installsuffix", cfg.BuildContext.InstallSuffix)
	}
	if a.buildID != "" {
		defaultGcFlags = append(defaultGcFlags, "-buildid", a.buildID)
	}
	if p.Internal.OmitDebug || cfg.Goos == "plan9" || cfg.Goarch == "wasm" {
		defaultGcFlags = append(defaultGcFlags, "-dwarf=false")
	}
	if strings.HasPrefix(ToolchainVersion, "go1") && !strings.Contains(os.Args[0], "go_bootstrap") {
		defaultGcFlags = append(defaultGcFlags, "-goversion", ToolchainVersion)
	}
	if p.Internal.Cover.Cfg != "" {
		defaultGcFlags = append(defaultGcFlags, "-coveragecfg="+p.Internal.Cover.Cfg)
	}
	if pgoProfile != "" {
		defaultGcFlags = append(defaultGcFlags, "-pgoprofile="+pgoProfile)
	}
	if symabis != "" {
		defaultGcFlags = append(defaultGcFlags, "-symabis", symabis)
	}

	gcflags := str.StringList(forcedGcflags, p.Internal.Gcflags)
	if p.Internal.FuzzInstrument {
		gcflags = append(gcflags, fuzzInstrumentFlags()...)
	}
	// Add -c=N to use concurrent backend compilation, if possible.
	if c := gcBackendConcurrency(gcflags); c > 1 {
		defaultGcFlags = append(defaultGcFlags, fmt.Sprintf("-c=%d", c))
	}

	args := []any{cfg.BuildToolexec, base.Tool("compile"), "-o", ofile, "-trimpath", a.trimpath(), defaultGcFlags, gcflags}
	if p.Internal.LocalPrefix == "" {
		args = append(args, "-nolocalimports")
	} else {
		args = append(args, "-D", p.Internal.LocalPrefix)
	}
	if importcfg != nil {
		if err := sh.writeFile(objdir+"importcfg", importcfg); err != nil {
			return "", nil, err
		}
		args = append(args, "-importcfg", objdir+"importcfg")
	}
	if embedcfg != nil {
		if err := sh.writeFile(objdir+"embedcfg", embedcfg); err != nil {
			return "", nil, err
		}
		args = append(args, "-embedcfg", objdir+"embedcfg")
	}
	if ofile == archive {
		args = append(args, "-pack")
	}
	if asmhdr {
		args = append(args, "-asmhdr", objdir+"go_asm.h")
	}

	for _, f := range gofiles {
		f := mkAbs(p.Dir, f)

		// Handle overlays. Convert path names using fsys.Actual
		// so these paths can be handed directly to tools.
		// Deleted files won't show up in when scanning directories earlier,
		// so Actual will never return "" (meaning a deleted file) here.
		// TODO(#39958): Handle cases where the package directory
		// doesn't exist on disk (this can happen when all the package's
		// files are in an overlay): the code expects the package directory
		// to exist and runs some tools in that directory.
		// TODO(#39958): Process the overlays when the
		// gofiles, cgofiles, cfiles, sfiles, and cxxfiles variables are
		// created in (*Builder).build. Doing that requires rewriting the
		// code that uses those values to expect absolute paths.
		args = append(args, fsys.Actual(f))
	}

	output, err = sh.runOut(base.Cwd(), nil, args...)
	return ofile, output, err
}

// gcBackendConcurrency returns the backend compiler concurrency level for a package compilation.
func gcBackendConcurrency(gcflags []string) int {
	// First, check whether we can use -c at all for this compilation.
	canDashC := concurrentGCBackendCompilationEnabledByDefault

	switch e := os.Getenv("GO19CONCURRENTCOMPILATION"); e {
	case "0":
		canDashC = false
	case "1":
		canDashC = true
	case "":
		// Not set. Use default.
	default:
		log.Fatalf("GO19CONCURRENTCOMPILATION must be 0, 1, or unset, got %q", e)
	}

	// TODO: Test and delete these conditions.
	if cfg.ExperimentErr != nil || cfg.Experiment.FieldTrack || cfg.Experiment.PreemptibleLoops {
		canDashC = false
	}

	if !canDashC {
		return 1
	}

	// Decide how many concurrent backend compilations to allow.
	//
	// If we allow too many, in theory we might end up with p concurrent processes,
	// each with c concurrent backend compiles, all fighting over the same resources.
	// However, in practice, that seems not to happen too much.
	// Most build graphs are surprisingly serial, so p==1 for much of the build.
	// Furthermore, concurrent backend compilation is only enabled for a part
	// of the overall compiler execution, so c==1 for much of the build.
	// So don't worry too much about that interaction for now.
	//
	// However, in practice, setting c above 4 tends not to help very much.
	// See the analysis in CL 41192.
	//
	// TODO(josharian): attempt to detect whether this particular compilation
	// is likely to be a bottleneck, e.g. when:
	//   - it has no successor packages to compile (usually package main)
	//   - all paths through the build graph pass through it
	//   - critical path scheduling says it is high priority
	// and in such a case, set c to runtime.GOMAXPROCS(0).
	// By default this is the same as runtime.NumCPU.
	// We do this now when p==1.
	// To limit parallelism, set GOMAXPROCS below numCPU; this may be useful
	// on a low-memory builder, or if a deterministic build order is required.
	c := runtime.GOMAXPROCS(0)
	if cfg.BuildP == 1 {
		// No process parallelism, do not cap compiler parallelism.
		return c
	}
	// Some process parallelism. Set c to min(4, maxprocs).
	if c > 4 {
		c = 4
	}
	return c
}

// trimpath returns the -trimpath argument to use
// when compiling the action.
func (a *Action) trimpath() string {
	// Keep in sync with Builder.ccompile
	// The trimmed paths are a little different, but we need to trim in the
	// same situations.

	// Strip the object directory entirely.
	objdir := strings.TrimSuffix(a.Objdir, string(filepath.Separator))
	rewrite := ""

	rewriteDir := a.Package.Dir
	if cfg.BuildTrimpath {
		importPath := a.Package.Internal.OrigImportPath
		if m := a.Package.Module; m != nil && m.Version != "" {
			rewriteDir = m.Path + "@" + m.Version + strings.TrimPrefix(importPath, m.Path)
		} else {
			rewriteDir = importPath
		}
		rewrite += a.Package.Dir + "=>" + rewriteDir + ";"
	}

	// Add rewrites for overlays. The 'from' and 'to' paths in overlays don't need to have
	// same basename, so go from the overlay contents file path (passed to the compiler)
	// to the path the disk path would be rewritten to.

	cgoFiles := make(map[string]bool)
	for _, f := range a.Package.CgoFiles {
		cgoFiles[f] = true
	}

	// TODO(matloob): Higher up in the stack, when the logic for deciding when to make copies
	// of c/c++/m/f/hfiles is consolidated, use the same logic that Build uses to determine
	// whether to create the copies in objdir to decide whether to rewrite objdir to the
	// package directory here.
	var overlayNonGoRewrites string // rewrites for non-go files
	hasCgoOverlay := false
	if fsys.OverlayFile != "" {
		for _, filename := range a.Package.AllFiles() {
			path := filename
			if !filepath.IsAbs(path) {
				path = filepath.Join(a.Package.Dir, path)
			}
			base := filepath.Base(path)
			isGo := strings.HasSuffix(filename, ".go") || strings.HasSuffix(filename, ".s")
			isCgo := cgoFiles[filename] || !isGo
			if fsys.Replaced(path) {
				if isCgo {
					hasCgoOverlay = true
				} else {
					rewrite += fsys.Actual(path) + "=>" + filepath.Join(rewriteDir, base) + ";"
				}
			} else if isCgo {
				// Generate rewrites for non-Go files copied to files in objdir.
				if filepath.Dir(path) == a.Package.Dir {
					// This is a file copied to objdir.
					overlayNonGoRewrites += filepath.Join(objdir, base) + "=>" + filepath.Join(rewriteDir, base) + ";"
				}
			} else {
				// Non-overlay Go files are covered by the a.Package.Dir rewrite rule above.
			}
		}
	}
	if hasCgoOverlay {
		rewrite += overlayNonGoRewrites
	}
	rewrite += objdir + "=>"

	return rewrite
}

func asmArgs(a *Action, p *load.Package) []any {
	// Add -I pkg/GOOS_GOARCH so #include "textflag.h" works in .s files.
	inc := filepath.Join(cfg.GOROOT, "pkg", "include")
	pkgpath := pkgPath(a)
	args := []any{cfg.BuildToolexec, base.Tool("asm"), "-p", pkgpath, "-trimpath", a.trimpath(), "-I", a.Objdir, "-I", inc, "-D", "GOOS_" + cfg.Goos, "-D", "GOARCH_" + cfg.Goarch, forcedAsmflags, p.Internal.Asmflags}
	if p.ImportPath == "runtime" && cfg.Goarch == "386" {
		for _, arg := range forcedAsmflags {
			if arg == "-dynlink" {
				args = append(args, "-D=GOBUILDMODE_shared=1")
			}
		}
	}

	if cfg.Goarch == "386" {
		// Define GO386_value from cfg.GO386.
		args = append(args, "-D", "GO386_"+cfg.GO386)
	}

	if cfg.Goarch == "amd64" {
		// Define GOAMD64_value from cfg.GOAMD64.
		args = append(args, "-D", "GOAMD64_"+cfg.GOAMD64)
	}

	if cfg.Goarch == "mips" || cfg.Goarch == "mipsle" {
		// Define GOMIPS_value from cfg.GOMIPS.
		args = append(args, "-D", "GOMIPS_"+cfg.GOMIPS)
	}

	if cfg.Goarch == "mips64" || cfg.Goarch == "mips64le" {
		// Define GOMIPS64_value from cfg.GOMIPS64.
		args = append(args, "-D", "GOMIPS64_"+cfg.GOMIPS64)
	}

	if cfg.Goarch == "ppc64" || cfg.Goarch == "ppc64le" {
		// Define GOPPC64_power8..N from cfg.PPC64.
		// We treat each powerpc version as a superset of functionality.
		switch cfg.GOPPC64 {
		case "power10":
			args = append(args, "-D", "GOPPC64_power10")
			fallthrough
		case "power9":
			args = append(args, "-D", "GOPPC64_power9")
			fallthrough
		default: // This should always be power8.
			args = append(args, "-D", "GOPPC64_power8")
		}
	}

	if cfg.Goarch == "riscv64" {
		// Define GORISCV64_value from cfg.GORISCV64.
		args = append(args, "-D", "GORISCV64_"+cfg.GORISCV64)
	}

	if cfg.Goarch == "arm" {
		// Define GOARM_value from cfg.GOARM, which can be either a version
		// like "6", or a version and a FP mode, like "7,hardfloat".
		switch {
		case strings.Contains(cfg.GOARM, "7"):
			args = append(args, "-D", "GOARM_7")
			fallthrough
		case strings.Contains(cfg.GOARM, "6"):
			args = append(args, "-D", "GOARM_6")
			fallthrough
		default:
			args = append(args, "-D", "GOARM_5")
		}
	}

	if cfg.Goarch == "arm64" {
		g, err := buildcfg.ParseGoarm64(cfg.GOARM64)
		if err == nil && g.LSE {
			args = append(args, "-D", "GOARM64_LSE")
		}
	}

	return args
}

func (gcToolchain) asm(b *Builder, a *Action, sfiles []string) ([]string, error) {
	p := a.Package
	args := asmArgs(a, p)

	var ofiles []string
	for _, sfile := range sfiles {
		ofile := a.Objdir + sfile[:len(sfile)-len(".s")] + ".o"
		ofiles = append(ofiles, ofile)
		args1 := append(args, "-o", ofile, fsys.Actual(mkAbs(p.Dir, sfile)))
		if err := b.Shell(a).run(p.Dir, p.ImportPath, nil, args1...); err != nil {
			return nil, err
		}
	}
	return ofiles, nil
}

func (gcToolchain) symabis(b *Builder, a *Action, sfiles []string) (string, error) {
	sh := b.Shell(a)

	mkSymabis := func(p *load.Package, sfiles []string, path string) error {
		args := asmArgs(a, p)
		args = append(args, "-gensymabis", "-o", path)
		for _, sfile := range sfiles {
			if p.ImportPath == "runtime/cgo" && strings.HasPrefix(sfile, "gcc_") {
				continue
			}
			args = append(args, fsys.Actual(mkAbs(p.Dir, sfile)))
		}

		// Supply an empty go_asm.h as if the compiler had been run.
		// -gensymabis parsing is lax enough that we don't need the
		// actual definitions that would appear in go_asm.h.
		if err := sh.writeFile(a.Objdir+"go_asm.h", nil); err != nil {
			return err
		}

		return sh.run(p.Dir, p.ImportPath, nil, args...)
	}

	var symabis string // Only set if we actually create the file
	p := a.Package
	if len(sfiles) != 0 {
		symabis = a.Objdir + "symabis"
		if err := mkSymabis(p, sfiles, symabis); err != nil {
			return "", err
		}
	}

	return symabis, nil
}

// toolVerify checks that the command line args writes the same output file
// if run using newTool instead.
// Unused now but kept around for future use.
func toolVerify(a *Action, b *Builder, p *load.Package, newTool string, ofile string, args []any) error {
	newArgs := make([]any, len(args))
	copy(newArgs, args)
	newArgs[1] = base.Tool(newTool)
	newArgs[3] = ofile + ".new" // x.6 becomes x.6.new
	if err := b.Shell(a).run(p.Dir, p.ImportPath, nil, newArgs...); err != nil {
		return err
	}
	data1, err := os.ReadFile(ofile)
	if err != nil {
		return err
	}
	data2, err := os.ReadFile(ofile + ".new")
	if err != nil {
		return err
	}
	if !bytes.Equal(data1, data2) {
		return fmt.Errorf("%s and %s produced different output files:\n%s\n%s", filepath.Base(args[1].(string)), newTool, strings.Join(str.StringList(args...), " "), strings.Join(str.StringList(newArgs...), " "))
	}
	os.Remove(ofile + ".new")
	return nil
}

func (gcToolchain) pack(b *Builder, a *Action, afile string, ofiles []string) error {
	absOfiles := make([]string, 0, len(ofiles))
	for _, f := range ofiles {
		absOfiles = append(absOfiles, mkAbs(a.Objdir, f))
	}
	absAfile := mkAbs(a.Objdir, afile)

	// The archive file should have been created by the compiler.
	// Since it used to not work that way, verify.
	if !cfg.BuildN {
		if _, err := os.Stat(absAfile); err != nil {
			base.Fatalf("os.Stat of archive file failed: %v", err)
		}
	}

	p := a.Package
	sh := b.Shell(a)
	if cfg.BuildN || cfg.BuildX {
		cmdline := str.StringList(base.Tool("pack"), "r", absAfile, absOfiles)
		sh.ShowCmd(p.Dir, "%s # internal", joinUnambiguously(cmdline))
	}
	if cfg.BuildN {
		return nil
	}
	if err := packInternal(absAfile, absOfiles); err != nil {
		return sh.reportCmd("", "", nil, err)
	}
	return nil
}

func packInternal(afile string, ofiles []string) error {
	dst, err := os.OpenFile(afile, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	defer dst.Close() // only for error returns or panics
	w := bufio.NewWriter(dst)

	for _, ofile := range ofiles {
		src, err := os.Open(ofile)
		if err != nil {
			return err
		}
		fi, err := src.Stat()
		if err != nil {
			src.Close()
			return err
		}
		// Note: Not using %-16.16s format because we care
		// about bytes, not runes.
		name := fi.Name()
		if len(name) > 16 {
			name = name[:16]
		} else {
			name += strings.Repeat(" ", 16-len(name))
		}
		size := fi.Size()
		fmt.Fprintf(w, "%s%-12d%-6d%-6d%-8o%-10d`\n",
			name, 0, 0, 0, 0644, size)
		n, err := io.Copy(w, src)
		src.Close()
		if err == nil && n < size {
			err = io.ErrUnexpectedEOF
		} else if err == nil && n > size {
			err = fmt.Errorf("file larger than size reported by stat")
		}
		if err != nil {
			return fmt.Errorf("copying %s to %s: %v", ofile, afile, err)
		}
		if size&1 != 0 {
			w.WriteByte(0)
		}
	}

	if err := w.Flush(); err != nil {
		return err
	}
	return dst.Close()
}

// setextld sets the appropriate linker flags for the specified compiler.
func setextld(ldflags []string, compiler []string) ([]string, error) {
	for _, f := range ldflags {
		if f == "-extld" || strings.HasPrefix(f, "-extld=") {
			// don't override -extld if supplied
			return ldflags, nil
		}
	}
	joined, err := quoted.Join(compiler)
	if err != nil {
		return nil, err
	}
	return append(ldflags, "-extld="+joined), nil
}

// pluginPath computes the package path for a plugin main package.
//
// This is typically the import path of the main package p, unless the
// plugin is being built directly from source files. In that case we
// combine the package build ID with the contents of the main package
// source files. This allows us to identify two different plugins
// built from two source files with the same name.
func pluginPath(a *Action) string {
	p := a.Package
	if p.ImportPath != "command-line-arguments" {
		return p.ImportPath
	}
	h := sha1.New()
	buildID := a.buildID
	if a.Mode == "link" {
		// For linking, use the main package's build ID instead of
		// the binary's build ID, so it is the same hash used in
		// compiling and linking.
		// When compiling, we use actionID/actionID (instead of
		// actionID/contentID) as a temporary build ID to compute
		// the hash. Do the same here. (See buildid.go:useCache)
		// The build ID matters because it affects the overall hash
		// in the plugin's pseudo-import path returned below.
		// We need to use the same import path when compiling and linking.
		id := strings.Split(buildID, buildIDSeparator)
		buildID = id[1] + buildIDSeparator + id[1]
	}
	fmt.Fprintf(h, "build ID: %s\n", buildID)
	for _, file := range str.StringList(p.GoFiles, p.CgoFiles, p.SFiles) {
		data, err := os.ReadFile(filepath.Join(p.Dir, file))
		if err != nil {
			base.Fatalf("go: %s", err)
		}
		h.Write(data)
	}
	return fmt.Sprintf("plugin/unnamed-%x", h.Sum(nil))
}

func (gcToolchain) ld(b *Builder, root *Action, targetPath, importcfg, mainpkg string) error {
	cxx := len(root.Package.CXXFiles) > 0 || len(root.Package.SwigCXXFiles) > 0
	for _, a := range root.Deps {
		if a.Package != nil && (len(a.Package.CXXFiles) > 0 || len(a.Package.SwigCXXFiles) > 0) {
			cxx = true
		}
	}
	var ldflags []string
	if cfg.BuildContext.InstallSuffix != "" {
		ldflags = append(ldflags, "-installsuffix", cfg.BuildContext.InstallSuffix)
	}
	if root.Package.Internal.OmitDebug {
		ldflags = append(ldflags, "-s", "-w")
	}
	if cfg.BuildBuildmode == "plugin" {
		ldflags = append(ldflags, "-pluginpath", pluginPath(root))
	}
	if fips140.Enabled() {
		ldflags = append(ldflags, "-fipso", filepath.Join(root.Objdir, "fips.o"))
	}

	// Store BuildID inside toolchain binaries as a unique identifier of the
	// tool being run, for use by content-based staleness determination.
	if root.Package.Goroot && strings.HasPrefix(root.Package.ImportPath, "cmd/") {
		// External linking will include our build id in the external
		// linker's build id, which will cause our build id to not
		// match the next time the tool is built.
		// Rely on the external build id instead.
		if !platform.MustLinkExternal(cfg.Goos, cfg.Goarch, false) {
			ldflags = append(ldflags, "-X=cmd/internal/objabi.buildID="+root.buildID)
		}
	}

	// Store default GODEBUG in binaries.
	if root.Package.DefaultGODEBUG != "" {
		ldflags = append(ldflags, "-X=runtime.godebugDefault="+root.Package.DefaultGODEBUG)
	}

	// If the user has not specified the -extld option, then specify the
	// appropriate linker. In case of C++ code, use the compiler named
	// by the CXX environment variable or defaultCXX if CXX is not set.
	// Else, use the CC environment variable and defaultCC as fallback.
	var compiler []string
	if cxx {
		compiler = envList("CXX", cfg.DefaultCXX(cfg.Goos, cfg.Goarch))
	} else {
		compiler = envList("CC", cfg.DefaultCC(cfg.Goos, cfg.Goarch))
	}
	ldflags = append(ldflags, "-buildmode="+ldBuildmode)
	if root.buildID != "" {
		ldflags = append(ldflags, "-buildid="+root.buildID)
	}
	ldflags = append(ldflags, forcedLdflags...)
	ldflags = append(ldflags, root.Package.Internal.Ldflags...)
	ldflags, err := setextld(ldflags, compiler)
	if err != nil {
		return err
	}

	// On OS X when using external linking to build a shared library,
	// the argument passed here to -o ends up recorded in the final
	// shared library in the LC_ID_DYLIB load command.
	// To avoid putting the temporary output directory name there
	// (and making the resulting shared library useless),
	// run the link in the output directory so that -o can name
	// just the final path element.
	// On Windows, DLL file name is recorded in PE file
	// export section, so do like on OS X.
	// On Linux, for a shared object, at least with the Gold linker,
	// the output file path is recorded in the .gnu.version_d section.
	dir := "."
	if cfg.BuildBuildmode == "c-shared" || cfg.BuildBuildmode == "plugin" {
		dir, targetPath = filepath.Split(targetPath)
	}

	env := []string{}
	// When -trimpath is used, GOROOT is cleared
	if cfg.BuildTrimpath {
		env = append(env, "GOROOT=")
	} else {
		env = append(env, "GOROOT="+cfg.GOROOT)
	}
	return b.Shell(root).run(dir, root.Package.ImportPath, env, cfg.BuildToolexec, base.Tool("link"), "-o", targetPath, "-importcfg", importcfg, ldflags, mainpkg)
}

func (gcToolchain) ldShared(b *Builder, root *Action, toplevelactions []*Action, targetPath, importcfg string, allactions []*Action) error {
	ldflags := []string{"-installsuffix", cfg.BuildContext.InstallSuffix}
	ldflags = append(ldflags, "-buildmode=shared")
	ldflags = append(ldflags, forcedLdflags...)
	ldflags = append(ldflags, root.Package.Internal.Ldflags...)
	cxx := false
	for _, a := range allactions {
		if a.Package != nil && (len(a.Package.CXXFiles) > 0 || len(a.Package.SwigCXXFiles) > 0) {
			cxx = true
		}
	}
	// If the user has not specified the -extld option, then specify the
	// appropriate linker. In case of C++ code, use the compiler named
	// by the CXX environment variable or defaultCXX if CXX is not set.
	// Else, use the CC environment variable and defaultCC as fallback.
	var compiler []string
	if cxx {
		compiler = envList("CXX", cfg.DefaultCXX(cfg.Goos, cfg.Goarch))
	} else {
		compiler = envList("CC", cfg.DefaultCC(cfg.Goos, cfg.Goarch))
	}
	ldflags, err := setextld(ldflags, compiler)
	if err != nil {
		return err
	}
	for _, d := range toplevelactions {
		if !strings.HasSuffix(d.Target, ".a") { // omit unsafe etc and actions for other shared libraries
			continue
		}
		ldflags = append(ldflags, d.Package.ImportPath+"="+d.Target)
	}

	// On OS X when using external linking to build a shared library,
	// the argument passed here to -o ends up recorded in the final
	// shared library in the LC_ID_DYLIB load command.
	// To avoid putting the temporary output directory name there
	// (and making the resulting shared library useless),
	// run the link in the output directory so that -o can name
	// just the final path element.
	// On Windows, DLL file name is recorded in PE file
	// export section, so do like on OS X.
	// On Linux, for a shared object, at least with the Gold linker,
	// the output file path is recorded in the .gnu.version_d section.
	dir, targetPath := filepath.Split(targetPath)

	return b.Shell(root).run(dir, targetPath, nil, cfg.BuildToolexec, base.Tool("link"), "-o", targetPath, "-importcfg", importcfg, ldflags)
}

func (gcToolchain) cc(b *Builder, a *Action, ofile, cfile string) error {
	return fmt.Errorf("%s: C source files not supported without cgo", mkAbs(a.Package.Dir, cfile))
}

"""



```