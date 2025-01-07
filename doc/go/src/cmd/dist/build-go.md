Response: Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding - Context is Key**

The first line `// go/src/cmd/dist/build.go` immediately tells us this is part of the Go distribution's build system. The `cmd/dist` package is responsible for building the Go toolchain itself. This is a crucial piece of information. It means the code is low-level, deals with bootstrapping, cross-compilation, and interacting with the operating system directly.

**2. High-Level Skim - Identifying Major Components**

I'd quickly skim through the code, looking for:

* **Package and Imports:**  `package main` and the import list (`"os"`, `"flag"`, `"fmt"`, etc.). These hint at command-line tool functionality and system interactions.
* **Global Variables:**  The large block of `var` declarations. These usually represent configurable options, environment settings, and core state of the program. Keywords like `goarch`, `goos`, `goroot` stand out as related to the build process. The `okgoarch` and `okgoos` slices suggest validation.
* **Functions:**  The various `func` declarations. I'd look for functions with suggestive names like `xinit`, `setup`, `install`, `clean`, and command-like prefixes like `cmd`.
* **Comments:** Pay attention to the comments, especially those explaining the purpose of variables or functions.

**3. Deeper Dive into Key Areas**

Based on the initial skim, I'd focus on the following:

* **`xinit()`:**  The name suggests initialization. I'd look for how it sets up the environment, reads environment variables, and performs basic validation. The checks for `GOROOT`, `GOOS`, `GOARCH`, and the `okgoos`/`okgoarch` slices confirm its role in setting up the build environment.
* **Global Variables (again):**  I'd go back and more carefully analyze the global variables, understanding what each one represents and how it's likely used. The `defaultcc`, `defaultcxx`, etc., suggest compiler settings. `rebuildall`, `noOpt`, `isRelease` point to build options.
* **`install()` and `runInstall()`:** These seem central to the build process. The `installed` map and the use of channels (`chan struct{}`) suggest managing concurrent installations. The logic within `runInstall` – compiling, linking, handling dependencies – is key to understanding the build process.
* **Command Functions (`cmd...`)**: The presence of `cmdenv`, `cmdbootstrap`, `cmdinstall`, `cmdclean`, etc., clearly indicates this is a command-line tool with different subcommands.
* **`cmdbootstrap()`:** Given the file path and the name, this is likely the core function for bootstrapping the Go toolchain. I'd look for how it orchestrates the build process, including the multiple stages (toolchain1, go_bootstrap, toolchain2, toolchain3).
* **`packagefile()`:**  A utility function for determining the output path of compiled packages.
* **`shouldbuild()`:** This function is crucial for understanding build tags and conditional compilation.
* **`compilerEnv()` and `compilerEnvLookup()`:** These manage compiler selection based on OS and architecture, highlighting the cross-compilation capabilities.

**4. Inferring Go Language Features**

As I analyze the code, I'd identify the Go features in use:

* **Environment Variables:**  The extensive use of `os.Getenv()` and `os.Setenv()` is prominent.
* **Command-Line Flags:** The `flag` package is used to parse command-line arguments.
* **File System Operations:**  Functions like `os.MkdirAll()`, `os.RemoveAll()`, `os.ReadFile()`, `filepath.Join()`, etc., are common for build systems.
* **Concurrency:** The use of `sync.Mutex` and channels in the `install` logic indicates concurrent operations.
* **String Manipulation:**  The `strings` package is heavily used for parsing paths, versions, and other text-based data.
* **Regular Expressions:** The `regexp` package is used for parsing version information and `go.mod` files.
* **External Commands:** The `os/exec` package is used to execute external commands like `git`, the compiler, and the linker.
* **Build Tags:** The `shouldbuild` function demonstrates the use of build tags for conditional compilation.

**5. Reasoning About Functionality and Examples**

Based on the analysis, I'd start to articulate the functionality of the code. For example, I'd reason:

* **Bootstrapping:** `cmdbootstrap` seems to build the Go toolchain in stages, starting with a minimal toolchain and gradually building more complete versions.
* **Cross-Compilation:** The variables like `goos`, `goarch`, `gohostos`, `gohostarch`, and the logic in `install` and `cmdbootstrap` strongly suggest support for building Go programs for different target operating systems and architectures.
* **Dependency Management:**  The `install` function and its handling of imports indicate a basic form of dependency management within the build process.

Then, I'd construct Go code examples to illustrate these features:

* **Environment Variables:** A simple example showing how to get and set environment variables.
* **Command-Line Flags:** An example demonstrating the use of `flag.Bool`, `flag.String`, and `flag.Parse()`.
* **Executing External Commands:** An example using `exec.Command` to run a simple shell command.

**6. Considering Command-Line Arguments**

I'd review the command functions (`cmd...`) and the `flag` package usage to identify the available command-line arguments and their effects. For example, in `cmdbootstrap`, I see flags like `-a`, `-d`, `-force`, `-no-banner`.

**7. Identifying Potential Pitfalls**

I'd think about common mistakes users might make when interacting with this kind of build system:

* **Incorrectly set environment variables:**  Emphasize the importance of `GOROOT`, `GOOS`, `GOARCH`.
* **Modifying files in `GOROOT`:**  Highlight the potential for causing inconsistencies.
* **Not understanding the bootstrapping process:** Explain the different stages and their implications.
* **Issues with C compiler setup:**  Point out the necessity of a working C compiler for cgo.

**8. Iteration and Refinement**

Throughout the process, I'd revisit my understanding and refine my explanations. I might look for more specific details within the code to support my claims. For instance, the `compilerEnv` function provides concrete details on how compiler selection works based on environment variables.

By following this systematic approach, combining code analysis with domain knowledge about build systems, I can effectively understand and explain the functionality of the provided Go code snippet.
这段代码是 Go 语言 `cmd/dist` 包中 `build.go` 文件的一部分，该文件是 Go 发行版构建过程的核心。它定义了构建 Go 工具链和标准库的逻辑。

以下是它的一些主要功能：

**1. 初始化构建环境 (`xinit` 函数):**

*   **读取和验证环境变量:**  它会读取并验证如 `GOROOT`, `GOOS`, `GOARCH` 等重要的环境变量，确保构建过程在一个正确的环境中进行。如果必要的环境变量未设置或值不合法，会直接报错退出。
*   **设置默认值:** 为一些环境变量设置默认值，例如 `GOARM`, `GOAMD64` 等，如果用户没有显式设置。
*   **确定主机和目标平台信息:**  确定构建主机 (`gohostos`, `gohostarch`) 和目标平台 (`goos`, `goarch`)。
*   **创建必要的目录:** 例如 `GOROOT/bin` 和 `GOROOT/pkg`。
*   **设置用于构建工具链的临时工作目录。**
*   **确定要使用的 Go 版本。**

**2. 管理构建依赖和安装 (`install`, `startInstall`, `runInstall` 函数):**

*   **构建和安装 Go 包:**  `install` 函数负责构建和安装指定的 Go 包。它会检查包的依赖关系，并确保所有依赖都已安装。
*   **并发构建:** 使用 `sync.Mutex` 和 channel (`chan struct{}`) 来管理并发的包安装过程，提高构建效率。
*   **处理不同类型的目标:** 可以构建 Go 库（package）或 Go 命令。
*   **处理 C 依赖:** 虽然这段代码没有直接展示 cgo 的构建细节，但它在 `runInstall` 中会检查是否导入了 "C" 包，并会设置一些与 C 编译器相关的环境变量。
*   **处理汇编文件:**  支持编译汇编源文件 (`.s`)。
*   **生成代码:**  能够生成一些特定的 Go 源文件，例如 `zcgo.go`, `zdefaultcc.go`, `zversion.go`, `zzipdata.go`，这些文件通常包含一些编译时生成的常量或数据。
*   **检查构建缓存:**  会检查目标是否是最新的，避免不必要的重复构建。

**3. 处理命令行参数和执行构建命令 (`cmdbootstrap`, `cmdinstall`, `cmdclean`, 等 `cmd` 前缀的函数):**

*   **定义和解析命令行参数:** 使用 `flag` 包来定义和解析 `dist` 命令的各种命令行参数，例如 `-a` (rebuildall), `-d` (debug), `-force`, 等等。
*   **实现不同的构建命令:**
    *   `cmdbootstrap`:  执行从头开始的引导构建过程，构建出一个可以用于构建后续版本的 `go` 命令。这是一个非常关键的步骤。
    *   `cmdinstall`:  安装指定的 Go 包。
    *   `cmdclean`:  清理构建过程中产生的临时文件。
    *   `cmdenv`:  打印构建环境信息。
    *   `cmdversion`:  打印 Go 版本信息。
    *   `cmdlist`:  列出所有支持的 Go 平台。
*   **执行外部命令:** 使用 `os/exec` 包来执行构建工具链所需的外部命令，例如编译器、汇编器、链接器等。

**4. 管理工具链 (`toolchain` 变量, `bootstrapBuildTools` 函数):**

*   **定义工具链组件:** `toolchain` 变量定义了构建 Go 语言核心工具链所需的包，例如 `cmd/asm`, `cmd/cgo`, `cmd/compile`, `cmd/link`。
*   **引导构建工具:** `bootstrapBuildTools` 函数负责使用一个已存在的 Go 工具链（通常是系统上已安装的 Go 版本或一个预编译的版本）来构建新的工具链。

**5. 平台支持和条件编译 (`okgoos`, `okgoarch`, `shouldbuild`, `matchtag` 函数):**

*   **定义支持的平台:** `okgoos` 和 `okgoarch` 变量定义了 Go 支持的目标操作系统和架构列表。
*   **条件编译:** `shouldbuild` 函数根据文件名和文件内容中的构建标签 (`//go:build`)来判断是否应该编译某个文件。`matchtag` 函数用于匹配构建标签。
*   **处理特定平台的差异:** 代码中可以看到针对不同操作系统和架构的特殊处理逻辑，例如设置不同的链接器参数等。

**6. 版本管理和发布 (`findgoversion` 函数):**

*   **确定 Go 版本:** `findgoversion` 函数负责确定当前正在构建的 Go 版本的字符串表示。它会尝试从 `GOROOT/VERSION` 文件、`GOROOT/VERSION.cache` 文件或 Git 仓库信息中获取版本信息.

**7. 其他辅助功能:**

*   **错误处理:**  使用 `fatalf` 函数来报告致命错误并退出程序。
*   **日志输出:** 使用 `errprintf` 和 `xprintf` 函数进行日志输出，可以通过 `-v` 参数控制日志的详细程度。
*   **文件操作:**  提供了一些封装的文件操作函数，例如 `isfile`, `isdir`, `readfile`, `writefile`, `xmkdir`, `xremove`, 等等。

**推理它是什么 Go 语言功能的实现:**

这段代码是 Go 语言**构建系统**的核心实现。它负责将 Go 源代码编译成可执行的工具和库。更具体地说，它实现了 **`cmd/dist`** 工具的功能，该工具是 Go 发行版的一部分，用于从源代码构建完整的 Go 发行版。

**Go 代码举例说明 (构建和安装一个包):**

假设我们要构建并安装 `fmt` 包。`cmd/dist/build.go` 中的 `install("fmt")` 函数会被调用。

```go
// 假设在 cmd/dist/build.go 中

func main() {
    // ... 初始化 ...

    if needsInstall("fmt") { // 一个假设的函数，用于判断是否需要安装
        install("fmt")
    }

    // ... 其他操作 ...
}

func install(pkg string) {
    startInstall(pkg)
}

func startInstall(dir string) chan struct{} {
    // ... (管理并发安装) ...
    ch := make(chan struct{})
    go runInstall(dir, ch)
    return ch
}

func runInstall(pkg string, ch chan struct{}) {
    defer close(ch)

    if vflag > 0 {
        errprintf("installing %s\n", pkg)
    }

    dir := pathf("%s/src/%s", goroot, pkg)
    packageFile := packagefile(pkg) // 获取目标 .a 文件路径

    // ... (检查文件，判断是否需要重新编译) ...

    // 执行编译命令 (简化)
    compileCmd := []string{pathf("%s/compile", tooldir), "-pack", "-o", packageFile, pathf("%s/*.go", dir)}
    run(dir, CheckExit, compileCmd[0], compileCmd[1:]...)

    if vflag > 0 {
        errprintf("installed %s to %s\n", pkg, packageFile)
    }
}

func packagefile(pkg string) string {
    return pathf("%s/pkg/obj/go-bootstrap/%s_%s/%s.a", goroot, goos, goarch, pkg)
}

// ... (其他辅助函数) ...
```

**假设的输入与输出:**

*   **输入:**  调用 `dist install fmt` 命令。
*   **假设的中间过程:**
    *   `xinit` 函数会初始化构建环境，读取 `GOROOT` 等环境变量。
    *   `needsInstall("fmt")` 函数判断 `fmt` 包是否需要重新构建或安装。
    *   `install("fmt")` 调用 `startInstall` 和 `runInstall`。
    *   `runInstall` 函数会确定 `fmt` 包的源代码路径和目标 `.a` 文件路径。
    *   如果需要编译，会构造并执行类似于 `GOROOT/pkg/tool/linux_amd64/compile -pack -o GOROOT/pkg/obj/go-bootstrap/linux_amd64/fmt.a GOROOT/src/fmt/*.go` 的命令。
*   **输出:**  如果在详细模式下 (`-v` 参数)，可能会输出 "installing fmt" 和 "installed fmt to GOROOT/pkg/obj/go-bootstrap/linux_amd64/fmt.a" 等信息。最终会在 `GOROOT/pkg/obj/go-bootstrap/linux_amd64/` 目录下生成 `fmt.a` 文件。

**命令行参数的具体处理:**

这段代码使用 `flag` 包来处理命令行参数。以下是一些常见的参数及其作用（在 `cmdbootstrap` 函数中定义）：

*   **`-a` (rebuildall):** 强制重新构建所有内容，忽略已有的构建缓存。
*   **`-d` (debug):**  启用构建过程的调试输出。
*   **`-distpack`:**  构建完成后，将分发文件写入 `pkg/distpack` 目录。
*   **`-force`:** 即使目标平台被标记为 broken，也强制构建。
*   **`-no-banner`:**  构建完成后不显示完成横幅。
*   **`-no-clean`:** （已废弃）不再有实际作用。

在 `cmdbootstrap` 函数中，可以看到如何使用 `flag.BoolVar` 来定义这些布尔类型的命令行参数，并在 `xflagparse(0)` 调用后检查这些标志的值，从而执行相应的操作。

**使用者易犯错的点:**

1. **`GOROOT` 设置不正确:**  `cmd/dist` 依赖于 `GOROOT` 环境变量来定位 Go 的源代码和其他必要的文件。如果 `GOROOT` 没有正确设置，构建过程会失败。
    ```bash
    # 错误示例：GOROOT 指向了错误的目录
    export GOROOT=/path/to/wrong/go
    cd go/src
    ./all.bash  # 构建会失败
    ```

2. **依赖系统环境:** Go 的某些功能（特别是涉及到 cgo 时）会依赖于系统的 C 编译器和其他库。如果系统环境不满足要求，构建可能会出错。
    ```bash
    # 错误示例：缺少 C 编译器
    # (假设在一个没有安装 GCC 或 Clang 的系统上)
    export CGO_ENABLED=1
    cd go/src
    ./all.bash  # 构建可能会因为找不到 C 编译器而失败
    ```

3. **在错误的目录下执行构建命令:**  通常需要在 Go 源代码的根目录（即包含 `src` 目录的目录）下执行 `all.bash` 或类似的构建脚本。如果在其他目录下执行，可能会找不到必要的文件。
    ```bash
    # 错误示例：在 src 目录下执行 all.bash
    cd go/src
    ./all.bash # 可能会因为找不到上级目录的某些文件而失败
    ```

4. **不理解 `-a` 参数的含义:**  `rebuildall` 参数会强制重新构建所有内容，这通常需要更长的时间。如果不清楚其作用，可能会在不必要的情况下使用，导致构建时间过长。

5. **修改 `GOROOT` 目录下的文件:**  手动修改 `GOROOT` 目录下的文件（特别是源代码）可能会导致构建过程出现不可预测的错误。`cmd/dist` 的构建过程假设源代码处于一个干净的状态。

这段代码是 Go 语言构建系统的基石，理解它的功能对于想要深入了解 Go 语言内部机制或者参与 Go 语言开发的开发者来说非常重要。

Prompt: 
```
这是路径为go/src/cmd/dist/build.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Initialization for any invocation.

// The usual variables.
var (
	goarch           string
	gorootBin        string
	gorootBinGo      string
	gohostarch       string
	gohostos         string
	goos             string
	goarm            string
	goarm64          string
	go386            string
	goamd64          string
	gomips           string
	gomips64         string
	goppc64          string
	goriscv64        string
	goroot           string
	goextlinkenabled string
	gogcflags        string // For running built compiler
	goldflags        string
	goexperiment     string
	gofips140        string
	workdir          string
	tooldir          string
	oldgoos          string
	oldgoarch        string
	oldgocache       string
	exe              string
	defaultcc        map[string]string
	defaultcxx       map[string]string
	defaultpkgconfig string
	defaultldso      string

	rebuildall bool
	noOpt      bool
	isRelease  bool

	vflag int // verbosity
)

// The known architectures.
var okgoarch = []string{
	"386",
	"amd64",
	"arm",
	"arm64",
	"loong64",
	"mips",
	"mipsle",
	"mips64",
	"mips64le",
	"ppc64",
	"ppc64le",
	"riscv64",
	"s390x",
	"sparc64",
	"wasm",
}

// The known operating systems.
var okgoos = []string{
	"darwin",
	"dragonfly",
	"illumos",
	"ios",
	"js",
	"wasip1",
	"linux",
	"android",
	"solaris",
	"freebsd",
	"nacl", // keep;
	"netbsd",
	"openbsd",
	"plan9",
	"windows",
	"aix",
}

// find reports the first index of p in l[0:n], or else -1.
func find(p string, l []string) int {
	for i, s := range l {
		if p == s {
			return i
		}
	}
	return -1
}

// xinit handles initialization of the various global state, like goroot and goarch.
func xinit() {
	b := os.Getenv("GOROOT")
	if b == "" {
		fatalf("$GOROOT must be set")
	}
	goroot = filepath.Clean(b)
	gorootBin = pathf("%s/bin", goroot)

	// Don't run just 'go' because the build infrastructure
	// runs cmd/dist inside go/bin often, and on Windows
	// it will be found in the current directory and refuse to exec.
	// All exec calls rewrite "go" into gorootBinGo.
	gorootBinGo = pathf("%s/bin/go", goroot)

	b = os.Getenv("GOOS")
	if b == "" {
		b = gohostos
	}
	goos = b
	if find(goos, okgoos) < 0 {
		fatalf("unknown $GOOS %s", goos)
	}

	b = os.Getenv("GOARM")
	if b == "" {
		b = xgetgoarm()
	}
	goarm = b

	b = os.Getenv("GOARM64")
	if b == "" {
		b = "v8.0"
	}
	goarm64 = b

	b = os.Getenv("GO386")
	if b == "" {
		b = "sse2"
	}
	go386 = b

	b = os.Getenv("GOAMD64")
	if b == "" {
		b = "v1"
	}
	goamd64 = b

	b = os.Getenv("GOMIPS")
	if b == "" {
		b = "hardfloat"
	}
	gomips = b

	b = os.Getenv("GOMIPS64")
	if b == "" {
		b = "hardfloat"
	}
	gomips64 = b

	b = os.Getenv("GOPPC64")
	if b == "" {
		b = "power8"
	}
	goppc64 = b

	b = os.Getenv("GORISCV64")
	if b == "" {
		b = "rva20u64"
	}
	goriscv64 = b

	b = os.Getenv("GOFIPS140")
	if b == "" {
		b = "off"
	}
	gofips140 = b

	if p := pathf("%s/src/all.bash", goroot); !isfile(p) {
		fatalf("$GOROOT is not set correctly or not exported\n"+
			"\tGOROOT=%s\n"+
			"\t%s does not exist", goroot, p)
	}

	b = os.Getenv("GOHOSTARCH")
	if b != "" {
		gohostarch = b
	}
	if find(gohostarch, okgoarch) < 0 {
		fatalf("unknown $GOHOSTARCH %s", gohostarch)
	}

	b = os.Getenv("GOARCH")
	if b == "" {
		b = gohostarch
	}
	goarch = b
	if find(goarch, okgoarch) < 0 {
		fatalf("unknown $GOARCH %s", goarch)
	}

	b = os.Getenv("GO_EXTLINK_ENABLED")
	if b != "" {
		if b != "0" && b != "1" {
			fatalf("unknown $GO_EXTLINK_ENABLED %s", b)
		}
		goextlinkenabled = b
	}

	goexperiment = os.Getenv("GOEXPERIMENT")
	// TODO(mdempsky): Validate known experiments?

	gogcflags = os.Getenv("BOOT_GO_GCFLAGS")
	goldflags = os.Getenv("BOOT_GO_LDFLAGS")

	defaultcc = compilerEnv("CC", "")
	defaultcxx = compilerEnv("CXX", "")

	b = os.Getenv("PKG_CONFIG")
	if b == "" {
		b = "pkg-config"
	}
	defaultpkgconfig = b

	defaultldso = os.Getenv("GO_LDSO")

	// For tools being invoked but also for os.ExpandEnv.
	os.Setenv("GO386", go386)
	os.Setenv("GOAMD64", goamd64)
	os.Setenv("GOARCH", goarch)
	os.Setenv("GOARM", goarm)
	os.Setenv("GOARM64", goarm64)
	os.Setenv("GOHOSTARCH", gohostarch)
	os.Setenv("GOHOSTOS", gohostos)
	os.Setenv("GOOS", goos)
	os.Setenv("GOMIPS", gomips)
	os.Setenv("GOMIPS64", gomips64)
	os.Setenv("GOPPC64", goppc64)
	os.Setenv("GORISCV64", goriscv64)
	os.Setenv("GOROOT", goroot)
	os.Setenv("GOFIPS140", gofips140)

	// Set GOBIN to GOROOT/bin. The meaning of GOBIN has drifted over time
	// (see https://go.dev/issue/3269, https://go.dev/cl/183058,
	// https://go.dev/issue/31576). Since we want binaries installed by 'dist' to
	// always go to GOROOT/bin anyway.
	os.Setenv("GOBIN", gorootBin)

	// Make the environment more predictable.
	os.Setenv("LANG", "C")
	os.Setenv("LANGUAGE", "en_US.UTF8")
	os.Unsetenv("GO111MODULE")
	os.Setenv("GOENV", "off")
	os.Unsetenv("GOFLAGS")
	os.Setenv("GOWORK", "off")

	// Create the go.mod for building toolchain2 and toolchain3. Toolchain1 and go_bootstrap are built with
	// a separate go.mod (with a lower required go version to allow all allowed bootstrap toolchain versions)
	// in bootstrapBuildTools.
	modVer := goModVersion()
	workdir = xworkdir()
	if err := os.WriteFile(pathf("%s/go.mod", workdir), []byte("module bootstrap\n\ngo "+modVer+"\n"), 0666); err != nil {
		fatalf("cannot write stub go.mod: %s", err)
	}
	xatexit(rmworkdir)

	tooldir = pathf("%s/pkg/tool/%s_%s", goroot, gohostos, gohostarch)

	goversion := findgoversion()
	isRelease = strings.HasPrefix(goversion, "release.") || strings.HasPrefix(goversion, "go")
}

// compilerEnv returns a map from "goos/goarch" to the
// compiler setting to use for that platform.
// The entry for key "" covers any goos/goarch not explicitly set in the map.
// For example, compilerEnv("CC", "gcc") returns the C compiler settings
// read from $CC, defaulting to gcc.
//
// The result is a map because additional environment variables
// can be set to change the compiler based on goos/goarch settings.
// The following applies to all envNames but CC is assumed to simplify
// the presentation.
//
// If no environment variables are set, we use def for all goos/goarch.
// $CC, if set, applies to all goos/goarch but is overridden by the following.
// $CC_FOR_TARGET, if set, applies to all goos/goarch except gohostos/gohostarch,
// but is overridden by the following.
// If gohostos=goos and gohostarch=goarch, then $CC_FOR_TARGET applies even for gohostos/gohostarch.
// $CC_FOR_goos_goarch, if set, applies only to goos/goarch.
func compilerEnv(envName, def string) map[string]string {
	m := map[string]string{"": def}

	if env := os.Getenv(envName); env != "" {
		m[""] = env
	}
	if env := os.Getenv(envName + "_FOR_TARGET"); env != "" {
		if gohostos != goos || gohostarch != goarch {
			m[gohostos+"/"+gohostarch] = m[""]
		}
		m[""] = env
	}

	for _, goos := range okgoos {
		for _, goarch := range okgoarch {
			if env := os.Getenv(envName + "_FOR_" + goos + "_" + goarch); env != "" {
				m[goos+"/"+goarch] = env
			}
		}
	}

	return m
}

// clangos lists the operating systems where we prefer clang to gcc.
var clangos = []string{
	"darwin", "ios", // macOS 10.9 and later require clang
	"freebsd", // FreeBSD 10 and later do not ship gcc
	"openbsd", // OpenBSD ships with GCC 4.2, which is now quite old.
}

// compilerEnvLookup returns the compiler settings for goos/goarch in map m.
// kind is "CC" or "CXX".
func compilerEnvLookup(kind string, m map[string]string, goos, goarch string) string {
	if !needCC() {
		return ""
	}
	if cc := m[goos+"/"+goarch]; cc != "" {
		return cc
	}
	if cc := m[""]; cc != "" {
		return cc
	}
	for _, os := range clangos {
		if goos == os {
			if kind == "CXX" {
				return "clang++"
			}
			return "clang"
		}
	}
	if kind == "CXX" {
		return "g++"
	}
	return "gcc"
}

// rmworkdir deletes the work directory.
func rmworkdir() {
	if vflag > 1 {
		errprintf("rm -rf %s\n", workdir)
	}
	xremoveall(workdir)
}

// Remove trailing spaces.
func chomp(s string) string {
	return strings.TrimRight(s, " \t\r\n")
}

// findgoversion determines the Go version to use in the version string.
// It also parses any other metadata found in the version file.
func findgoversion() string {
	// The $GOROOT/VERSION file takes priority, for distributions
	// without the source repo.
	path := pathf("%s/VERSION", goroot)
	if isfile(path) {
		b := chomp(readfile(path))

		// Starting in Go 1.21 the VERSION file starts with the
		// version on a line by itself but then can contain other
		// metadata about the release, one item per line.
		if i := strings.Index(b, "\n"); i >= 0 {
			rest := b[i+1:]
			b = chomp(b[:i])
			for _, line := range strings.Split(rest, "\n") {
				f := strings.Fields(line)
				if len(f) == 0 {
					continue
				}
				switch f[0] {
				default:
					fatalf("VERSION: unexpected line: %s", line)
				case "time":
					if len(f) != 2 {
						fatalf("VERSION: unexpected time line: %s", line)
					}
					_, err := time.Parse(time.RFC3339, f[1])
					if err != nil {
						fatalf("VERSION: bad time: %s", err)
					}
				}
			}
		}

		// Commands such as "dist version > VERSION" will cause
		// the shell to create an empty VERSION file and set dist's
		// stdout to its fd. dist in turn looks at VERSION and uses
		// its content if available, which is empty at this point.
		// Only use the VERSION file if it is non-empty.
		if b != "" {
			return b
		}
	}

	// The $GOROOT/VERSION.cache file is a cache to avoid invoking
	// git every time we run this command. Unlike VERSION, it gets
	// deleted by the clean command.
	path = pathf("%s/VERSION.cache", goroot)
	if isfile(path) {
		return chomp(readfile(path))
	}

	// Show a nicer error message if this isn't a Git repo.
	if !isGitRepo() {
		fatalf("FAILED: not a Git repo; must put a VERSION file in $GOROOT")
	}

	// Otherwise, use Git.
	//
	// Include 1.x base version, hash, and date in the version.
	//
	// Note that we lightly parse internal/goversion/goversion.go to
	// obtain the base version. We can't just import the package,
	// because cmd/dist is built with a bootstrap GOROOT which could
	// be an entirely different version of Go. We assume
	// that the file contains "const Version = <Integer>".
	goversionSource := readfile(pathf("%s/src/internal/goversion/goversion.go", goroot))
	m := regexp.MustCompile(`(?m)^const Version = (\d+)`).FindStringSubmatch(goversionSource)
	if m == nil {
		fatalf("internal/goversion/goversion.go does not contain 'const Version = ...'")
	}
	version := fmt.Sprintf("devel go1.%s-", m[1])
	version += chomp(run(goroot, CheckExit, "git", "log", "-n", "1", "--format=format:%h %cd", "HEAD"))

	// Cache version.
	writefile(version, path, 0)

	return version
}

// goModVersion returns the go version declared in src/go.mod. This is the
// go version to use in the go.mod building go_bootstrap, toolchain2, and toolchain3.
// (toolchain1 must be built with requiredBootstrapVersion(goModVersion))
func goModVersion() string {
	goMod := readfile(pathf("%s/src/go.mod", goroot))
	m := regexp.MustCompile(`(?m)^go (1.\d+)$`).FindStringSubmatch(goMod)
	if m == nil {
		fatalf("std go.mod does not contain go 1.X")
	}
	return m[1]
}

func requiredBootstrapVersion(v string) string {
	minorstr, ok := strings.CutPrefix(v, "1.")
	if !ok {
		fatalf("go version %q in go.mod does not start with %q", v, "1.")
	}
	minor, err := strconv.Atoi(minorstr)
	if err != nil {
		fatalf("invalid go version minor component %q: %v", minorstr, err)
	}
	// Per go.dev/doc/install/source, for N >= 22, Go version 1.N will require a Go 1.M compiler,
	// where M is N-2 rounded down to an even number. Example: Go 1.24 and 1.25 require Go 1.22.
	requiredMinor := minor - 2 - minor%2
	return "1." + strconv.Itoa(requiredMinor)
}

// isGitRepo reports whether the working directory is inside a Git repository.
func isGitRepo() bool {
	// NB: simply checking the exit code of `git rev-parse --git-dir` would
	// suffice here, but that requires deviating from the infrastructure
	// provided by `run`.
	gitDir := chomp(run(goroot, 0, "git", "rev-parse", "--git-dir"))
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(goroot, gitDir)
	}
	return isdir(gitDir)
}

/*
 * Initial tree setup.
 */

// The old tools that no longer live in $GOBIN or $GOROOT/bin.
var oldtool = []string{
	"5a", "5c", "5g", "5l",
	"6a", "6c", "6g", "6l",
	"8a", "8c", "8g", "8l",
	"9a", "9c", "9g", "9l",
	"6cov",
	"6nm",
	"6prof",
	"cgo",
	"ebnflint",
	"goapi",
	"gofix",
	"goinstall",
	"gomake",
	"gopack",
	"gopprof",
	"gotest",
	"gotype",
	"govet",
	"goyacc",
	"quietgcc",
}

// Unreleased directories (relative to $GOROOT) that should
// not be in release branches.
var unreleased = []string{
	"src/cmd/newlink",
	"src/cmd/objwriter",
	"src/debug/goobj",
	"src/old",
}

// setup sets up the tree for the initial build.
func setup() {
	// Create bin directory.
	if p := pathf("%s/bin", goroot); !isdir(p) {
		xmkdir(p)
	}

	// Create package directory.
	if p := pathf("%s/pkg", goroot); !isdir(p) {
		xmkdir(p)
	}

	goosGoarch := pathf("%s/pkg/%s_%s", goroot, gohostos, gohostarch)
	if rebuildall {
		xremoveall(goosGoarch)
	}
	xmkdirall(goosGoarch)
	xatexit(func() {
		if files := xreaddir(goosGoarch); len(files) == 0 {
			xremove(goosGoarch)
		}
	})

	if goos != gohostos || goarch != gohostarch {
		p := pathf("%s/pkg/%s_%s", goroot, goos, goarch)
		if rebuildall {
			xremoveall(p)
		}
		xmkdirall(p)
	}

	// Create object directory.
	// We used to use it for C objects.
	// Now we use it for the build cache, to separate dist's cache
	// from any other cache the user might have, and for the location
	// to build the bootstrap versions of the standard library.
	obj := pathf("%s/pkg/obj", goroot)
	if !isdir(obj) {
		xmkdir(obj)
	}
	xatexit(func() { xremove(obj) })

	// Create build cache directory.
	objGobuild := pathf("%s/pkg/obj/go-build", goroot)
	if rebuildall {
		xremoveall(objGobuild)
	}
	xmkdirall(objGobuild)
	xatexit(func() { xremoveall(objGobuild) })

	// Create directory for bootstrap versions of standard library .a files.
	objGoBootstrap := pathf("%s/pkg/obj/go-bootstrap", goroot)
	if rebuildall {
		xremoveall(objGoBootstrap)
	}
	xmkdirall(objGoBootstrap)
	xatexit(func() { xremoveall(objGoBootstrap) })

	// Create tool directory.
	// We keep it in pkg/, just like the object directory above.
	if rebuildall {
		xremoveall(tooldir)
	}
	xmkdirall(tooldir)

	// Remove tool binaries from before the tool/gohostos_gohostarch
	xremoveall(pathf("%s/bin/tool", goroot))

	// Remove old pre-tool binaries.
	for _, old := range oldtool {
		xremove(pathf("%s/bin/%s", goroot, old))
	}

	// Special release-specific setup.
	if isRelease {
		// Make sure release-excluded things are excluded.
		for _, dir := range unreleased {
			if p := pathf("%s/%s", goroot, dir); isdir(p) {
				fatalf("%s should not exist in release build", p)
			}
		}
	}
}

/*
 * Tool building
 */

// mustLinkExternal is a copy of internal/platform.MustLinkExternal,
// duplicated here to avoid version skew in the MustLinkExternal function
// during bootstrapping.
func mustLinkExternal(goos, goarch string, cgoEnabled bool) bool {
	if cgoEnabled {
		switch goarch {
		case "loong64", "mips", "mipsle", "mips64", "mips64le":
			// Internally linking cgo is incomplete on some architectures.
			// https://golang.org/issue/14449
			return true
		case "arm64":
			if goos == "windows" {
				// windows/arm64 internal linking is not implemented.
				return true
			}
		case "ppc64":
			// Big Endian PPC64 cgo internal linking is not implemented for aix or linux.
			if goos == "aix" || goos == "linux" {
				return true
			}
		}

		switch goos {
		case "android":
			return true
		case "dragonfly":
			// It seems that on Dragonfly thread local storage is
			// set up by the dynamic linker, so internal cgo linking
			// doesn't work. Test case is "go test runtime/cgo".
			return true
		}
	}

	switch goos {
	case "android":
		if goarch != "arm64" {
			return true
		}
	case "ios":
		if goarch == "arm64" {
			return true
		}
	}
	return false
}

// depsuffix records the allowed suffixes for source files.
var depsuffix = []string{
	".s",
	".go",
}

// gentab records how to generate some trivial files.
// Files listed here should also be listed in ../distpack/pack.go's srcArch.Remove list.
var gentab = []struct {
	pkg  string // Relative to $GOROOT/src
	file string
	gen  func(dir, file string)
}{
	{"go/build", "zcgo.go", mkzcgo},
	{"cmd/go/internal/cfg", "zdefaultcc.go", mkzdefaultcc},
	{"internal/runtime/sys", "zversion.go", mkzversion},
	{"time/tzdata", "zzipdata.go", mktzdata},
}

// installed maps from a dir name (as given to install) to a chan
// closed when the dir's package is installed.
var installed = make(map[string]chan struct{})
var installedMu sync.Mutex

func install(dir string) {
	<-startInstall(dir)
}

func startInstall(dir string) chan struct{} {
	installedMu.Lock()
	ch := installed[dir]
	if ch == nil {
		ch = make(chan struct{})
		installed[dir] = ch
		go runInstall(dir, ch)
	}
	installedMu.Unlock()
	return ch
}

// runInstall installs the library, package, or binary associated with pkg,
// which is relative to $GOROOT/src.
func runInstall(pkg string, ch chan struct{}) {
	if pkg == "net" || pkg == "os/user" || pkg == "crypto/x509" {
		fatalf("go_bootstrap cannot depend on cgo package %s", pkg)
	}

	defer close(ch)

	if pkg == "unsafe" {
		return
	}

	if vflag > 0 {
		if goos != gohostos || goarch != gohostarch {
			errprintf("%s (%s/%s)\n", pkg, goos, goarch)
		} else {
			errprintf("%s\n", pkg)
		}
	}

	workdir := pathf("%s/%s", workdir, pkg)
	xmkdirall(workdir)

	var clean []string
	defer func() {
		for _, name := range clean {
			xremove(name)
		}
	}()

	// dir = full path to pkg.
	dir := pathf("%s/src/%s", goroot, pkg)
	name := filepath.Base(dir)

	// ispkg predicts whether the package should be linked as a binary, based
	// on the name. There should be no "main" packages in vendor, since
	// 'go mod vendor' will only copy imported packages there.
	ispkg := !strings.HasPrefix(pkg, "cmd/") || strings.Contains(pkg, "/internal/") || strings.Contains(pkg, "/vendor/")

	// Start final link command line.
	// Note: code below knows that link.p[targ] is the target.
	var (
		link      []string
		targ      int
		ispackcmd bool
	)
	if ispkg {
		// Go library (package).
		ispackcmd = true
		link = []string{"pack", packagefile(pkg)}
		targ = len(link) - 1
		xmkdirall(filepath.Dir(link[targ]))
	} else {
		// Go command.
		elem := name
		if elem == "go" {
			elem = "go_bootstrap"
		}
		link = []string{pathf("%s/link", tooldir)}
		if goos == "android" {
			link = append(link, "-buildmode=pie")
		}
		if goldflags != "" {
			link = append(link, goldflags)
		}
		link = append(link, "-extld="+compilerEnvLookup("CC", defaultcc, goos, goarch))
		link = append(link, "-L="+pathf("%s/pkg/obj/go-bootstrap/%s_%s", goroot, goos, goarch))
		link = append(link, "-o", pathf("%s/%s%s", tooldir, elem, exe))
		targ = len(link) - 1
	}
	ttarg := mtime(link[targ])

	// Gather files that are sources for this target.
	// Everything in that directory, and any target-specific
	// additions.
	files := xreaddir(dir)

	// Remove files beginning with . or _,
	// which are likely to be editor temporary files.
	// This is the same heuristic build.ScanDir uses.
	// There do exist real C files beginning with _,
	// so limit that check to just Go files.
	files = filter(files, func(p string) bool {
		return !strings.HasPrefix(p, ".") && (!strings.HasPrefix(p, "_") || !strings.HasSuffix(p, ".go"))
	})

	// Add generated files for this package.
	for _, gt := range gentab {
		if gt.pkg == pkg {
			files = append(files, gt.file)
		}
	}
	files = uniq(files)

	// Convert to absolute paths.
	for i, p := range files {
		if !filepath.IsAbs(p) {
			files[i] = pathf("%s/%s", dir, p)
		}
	}

	// Is the target up-to-date?
	var gofiles, sfiles []string
	stale := rebuildall
	files = filter(files, func(p string) bool {
		for _, suf := range depsuffix {
			if strings.HasSuffix(p, suf) {
				goto ok
			}
		}
		return false
	ok:
		t := mtime(p)
		if !t.IsZero() && !strings.HasSuffix(p, ".a") && !shouldbuild(p, pkg) {
			return false
		}
		if strings.HasSuffix(p, ".go") {
			gofiles = append(gofiles, p)
		} else if strings.HasSuffix(p, ".s") {
			sfiles = append(sfiles, p)
		}
		if t.After(ttarg) {
			stale = true
		}
		return true
	})

	// If there are no files to compile, we're done.
	if len(files) == 0 {
		return
	}

	if !stale {
		return
	}

	// For package runtime, copy some files into the work space.
	if pkg == "runtime" {
		xmkdirall(pathf("%s/pkg/include", goroot))
		// For use by assembly and C files.
		copyfile(pathf("%s/pkg/include/textflag.h", goroot),
			pathf("%s/src/runtime/textflag.h", goroot), 0)
		copyfile(pathf("%s/pkg/include/funcdata.h", goroot),
			pathf("%s/src/runtime/funcdata.h", goroot), 0)
		copyfile(pathf("%s/pkg/include/asm_ppc64x.h", goroot),
			pathf("%s/src/runtime/asm_ppc64x.h", goroot), 0)
		copyfile(pathf("%s/pkg/include/asm_amd64.h", goroot),
			pathf("%s/src/runtime/asm_amd64.h", goroot), 0)
		copyfile(pathf("%s/pkg/include/asm_riscv64.h", goroot),
			pathf("%s/src/runtime/asm_riscv64.h", goroot), 0)
	}

	// Generate any missing files; regenerate existing ones.
	for _, gt := range gentab {
		if gt.pkg != pkg {
			continue
		}
		p := pathf("%s/%s", dir, gt.file)
		if vflag > 1 {
			errprintf("generate %s\n", p)
		}
		gt.gen(dir, p)
		// Do not add generated file to clean list.
		// In runtime, we want to be able to
		// build the package with the go tool,
		// and it assumes these generated files already
		// exist (it does not know how to build them).
		// The 'clean' command can remove
		// the generated files.
	}

	// Resolve imported packages to actual package paths.
	// Make sure they're installed.
	importMap := make(map[string]string)
	for _, p := range gofiles {
		for _, imp := range readimports(p) {
			if imp == "C" {
				fatalf("%s imports C", p)
			}
			importMap[imp] = resolveVendor(imp, dir)
		}
	}
	sortedImports := make([]string, 0, len(importMap))
	for imp := range importMap {
		sortedImports = append(sortedImports, imp)
	}
	sort.Strings(sortedImports)

	for _, dep := range importMap {
		if dep == "C" {
			fatalf("%s imports C", pkg)
		}
		startInstall(dep)
	}
	for _, dep := range importMap {
		install(dep)
	}

	if goos != gohostos || goarch != gohostarch {
		// We've generated the right files; the go command can do the build.
		if vflag > 1 {
			errprintf("skip build for cross-compile %s\n", pkg)
		}
		return
	}

	asmArgs := []string{
		pathf("%s/asm", tooldir),
		"-I", workdir,
		"-I", pathf("%s/pkg/include", goroot),
		"-D", "GOOS_" + goos,
		"-D", "GOARCH_" + goarch,
		"-D", "GOOS_GOARCH_" + goos + "_" + goarch,
		"-p", pkg,
	}
	if goarch == "mips" || goarch == "mipsle" {
		// Define GOMIPS_value from gomips.
		asmArgs = append(asmArgs, "-D", "GOMIPS_"+gomips)
	}
	if goarch == "mips64" || goarch == "mips64le" {
		// Define GOMIPS64_value from gomips64.
		asmArgs = append(asmArgs, "-D", "GOMIPS64_"+gomips64)
	}
	if goarch == "ppc64" || goarch == "ppc64le" {
		// We treat each powerpc version as a superset of functionality.
		switch goppc64 {
		case "power10":
			asmArgs = append(asmArgs, "-D", "GOPPC64_power10")
			fallthrough
		case "power9":
			asmArgs = append(asmArgs, "-D", "GOPPC64_power9")
			fallthrough
		default: // This should always be power8.
			asmArgs = append(asmArgs, "-D", "GOPPC64_power8")
		}
	}
	if goarch == "riscv64" {
		// Define GORISCV64_value from goriscv64
		asmArgs = append(asmArgs, "-D", "GORISCV64_"+goriscv64)
	}
	if goarch == "arm" {
		// Define GOARM_value from goarm, which can be either a version
		// like "6", or a version and a FP mode, like "7,hardfloat".
		switch {
		case strings.Contains(goarm, "7"):
			asmArgs = append(asmArgs, "-D", "GOARM_7")
			fallthrough
		case strings.Contains(goarm, "6"):
			asmArgs = append(asmArgs, "-D", "GOARM_6")
			fallthrough
		default:
			asmArgs = append(asmArgs, "-D", "GOARM_5")
		}
	}
	goasmh := pathf("%s/go_asm.h", workdir)

	// Collect symabis from assembly code.
	var symabis string
	if len(sfiles) > 0 {
		symabis = pathf("%s/symabis", workdir)
		var wg sync.WaitGroup
		asmabis := append(asmArgs[:len(asmArgs):len(asmArgs)], "-gensymabis", "-o", symabis)
		asmabis = append(asmabis, sfiles...)
		if err := os.WriteFile(goasmh, nil, 0666); err != nil {
			fatalf("cannot write empty go_asm.h: %s", err)
		}
		bgrun(&wg, dir, asmabis...)
		bgwait(&wg)
	}

	// Build an importcfg file for the compiler.
	buf := &bytes.Buffer{}
	for _, imp := range sortedImports {
		if imp == "unsafe" {
			continue
		}
		dep := importMap[imp]
		if imp != dep {
			fmt.Fprintf(buf, "importmap %s=%s\n", imp, dep)
		}
		fmt.Fprintf(buf, "packagefile %s=%s\n", dep, packagefile(dep))
	}
	importcfg := pathf("%s/importcfg", workdir)
	if err := os.WriteFile(importcfg, buf.Bytes(), 0666); err != nil {
		fatalf("cannot write importcfg file: %v", err)
	}

	var archive string
	// The next loop will compile individual non-Go files.
	// Hand the Go files to the compiler en masse.
	// For packages containing assembly, this writes go_asm.h, which
	// the assembly files will need.
	pkgName := pkg
	if strings.HasPrefix(pkg, "cmd/") && strings.Count(pkg, "/") == 1 {
		pkgName = "main"
	}
	b := pathf("%s/_go_.a", workdir)
	clean = append(clean, b)
	if !ispackcmd {
		link = append(link, b)
	} else {
		archive = b
	}

	// Compile Go code.
	compile := []string{pathf("%s/compile", tooldir), "-std", "-pack", "-o", b, "-p", pkgName, "-importcfg", importcfg}
	if gogcflags != "" {
		compile = append(compile, strings.Fields(gogcflags)...)
	}
	if len(sfiles) > 0 {
		compile = append(compile, "-asmhdr", goasmh)
	}
	if symabis != "" {
		compile = append(compile, "-symabis", symabis)
	}
	if goos == "android" {
		compile = append(compile, "-shared")
	}

	compile = append(compile, gofiles...)
	var wg sync.WaitGroup
	// We use bgrun and immediately wait for it instead of calling run() synchronously.
	// This executes all jobs through the bgwork channel and allows the process
	// to exit cleanly in case an error occurs.
	bgrun(&wg, dir, compile...)
	bgwait(&wg)

	// Compile the files.
	for _, p := range sfiles {
		// Assembly file for a Go package.
		compile := asmArgs[:len(asmArgs):len(asmArgs)]

		doclean := true
		b := pathf("%s/%s", workdir, filepath.Base(p))

		// Change the last character of the output file (which was c or s).
		b = b[:len(b)-1] + "o"
		compile = append(compile, "-o", b, p)
		bgrun(&wg, dir, compile...)

		link = append(link, b)
		if doclean {
			clean = append(clean, b)
		}
	}
	bgwait(&wg)

	if ispackcmd {
		xremove(link[targ])
		dopack(link[targ], archive, link[targ+1:])
		return
	}

	// Remove target before writing it.
	xremove(link[targ])
	bgrun(&wg, "", link...)
	bgwait(&wg)
}

// packagefile returns the path to a compiled .a file for the given package
// path. Paths may need to be resolved with resolveVendor first.
func packagefile(pkg string) string {
	return pathf("%s/pkg/obj/go-bootstrap/%s_%s/%s.a", goroot, goos, goarch, pkg)
}

// unixOS is the set of GOOS values matched by the "unix" build tag.
// This is the same list as in internal/syslist/syslist.go.
var unixOS = map[string]bool{
	"aix":       true,
	"android":   true,
	"darwin":    true,
	"dragonfly": true,
	"freebsd":   true,
	"hurd":      true,
	"illumos":   true,
	"ios":       true,
	"linux":     true,
	"netbsd":    true,
	"openbsd":   true,
	"solaris":   true,
}

// matchtag reports whether the tag matches this build.
func matchtag(tag string) bool {
	switch tag {
	case "gc", "cmd_go_bootstrap", "go1.1":
		return true
	case "linux":
		return goos == "linux" || goos == "android"
	case "solaris":
		return goos == "solaris" || goos == "illumos"
	case "darwin":
		return goos == "darwin" || goos == "ios"
	case goos, goarch:
		return true
	case "unix":
		return unixOS[goos]
	default:
		return false
	}
}

// shouldbuild reports whether we should build this file.
// It applies the same rules that are used with context tags
// in package go/build, except it's less picky about the order
// of GOOS and GOARCH.
// We also allow the special tag cmd_go_bootstrap.
// See ../go/bootstrap.go and package go/build.
func shouldbuild(file, pkg string) bool {
	// Check file name for GOOS or GOARCH.
	name := filepath.Base(file)
	excluded := func(list []string, ok string) bool {
		for _, x := range list {
			if x == ok || (ok == "android" && x == "linux") || (ok == "illumos" && x == "solaris") || (ok == "ios" && x == "darwin") {
				continue
			}
			i := strings.Index(name, x)
			if i <= 0 || name[i-1] != '_' {
				continue
			}
			i += len(x)
			if i == len(name) || name[i] == '.' || name[i] == '_' {
				return true
			}
		}
		return false
	}
	if excluded(okgoos, goos) || excluded(okgoarch, goarch) {
		return false
	}

	// Omit test files.
	if strings.Contains(name, "_test") {
		return false
	}

	// Check file contents for //go:build lines.
	for _, p := range strings.Split(readfile(file), "\n") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		code := p
		i := strings.Index(code, "//")
		if i > 0 {
			code = strings.TrimSpace(code[:i])
		}
		if code == "package documentation" {
			return false
		}
		if code == "package main" && pkg != "cmd/go" && pkg != "cmd/cgo" {
			return false
		}
		if !strings.HasPrefix(p, "//") {
			break
		}
		if strings.HasPrefix(p, "//go:build ") {
			matched, err := matchexpr(p[len("//go:build "):])
			if err != nil {
				errprintf("%s: %v", file, err)
			}
			return matched
		}
	}

	return true
}

// copyfile copies the file src to dst, via memory (so only good for small files).
func copyfile(dst, src string, flag int) {
	if vflag > 1 {
		errprintf("cp %s %s\n", src, dst)
	}
	writefile(readfile(src), dst, flag)
}

// dopack copies the package src to dst,
// appending the files listed in extra.
// The archive format is the traditional Unix ar format.
func dopack(dst, src string, extra []string) {
	bdst := bytes.NewBufferString(readfile(src))
	for _, file := range extra {
		b := readfile(file)
		// find last path element for archive member name
		i := strings.LastIndex(file, "/") + 1
		j := strings.LastIndex(file, `\`) + 1
		if i < j {
			i = j
		}
		fmt.Fprintf(bdst, "%-16.16s%-12d%-6d%-6d%-8o%-10d`\n", file[i:], 0, 0, 0, 0644, len(b))
		bdst.WriteString(b)
		if len(b)&1 != 0 {
			bdst.WriteByte(0)
		}
	}
	writefile(bdst.String(), dst, 0)
}

func clean() {
	generated := []byte(generatedHeader)

	// Remove generated source files.
	filepath.WalkDir(pathf("%s/src", goroot), func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			// ignore
		case d.IsDir() && (d.Name() == "vendor" || d.Name() == "testdata"):
			return filepath.SkipDir
		case d.IsDir() && d.Name() != "dist":
			// Remove generated binary named for directory, but not dist out from under us.
			exe := filepath.Join(path, d.Name())
			if info, err := os.Stat(exe); err == nil && !info.IsDir() {
				xremove(exe)
			}
			xremove(exe + ".exe")
		case !d.IsDir() && strings.HasPrefix(d.Name(), "z"):
			// Remove generated file, identified by marker string.
			head := make([]byte, 512)
			if f, err := os.Open(path); err == nil {
				io.ReadFull(f, head)
				f.Close()
			}
			if bytes.HasPrefix(head, generated) {
				xremove(path)
			}
		}
		return nil
	})

	if rebuildall {
		// Remove object tree.
		xremoveall(pathf("%s/pkg/obj/%s_%s", goroot, gohostos, gohostarch))

		// Remove installed packages and tools.
		xremoveall(pathf("%s/pkg/%s_%s", goroot, gohostos, gohostarch))
		xremoveall(pathf("%s/pkg/%s_%s", goroot, goos, goarch))
		xremoveall(pathf("%s/pkg/%s_%s_race", goroot, gohostos, gohostarch))
		xremoveall(pathf("%s/pkg/%s_%s_race", goroot, goos, goarch))
		xremoveall(tooldir)

		// Remove cached version info.
		xremove(pathf("%s/VERSION.cache", goroot))

		// Remove distribution packages.
		xremoveall(pathf("%s/pkg/distpack", goroot))
	}
}

/*
 * command implementations
 */

// The env command prints the default environment.
func cmdenv() {
	path := flag.Bool("p", false, "emit updated PATH")
	plan9 := flag.Bool("9", gohostos == "plan9", "emit plan 9 syntax")
	windows := flag.Bool("w", gohostos == "windows", "emit windows syntax")
	xflagparse(0)

	format := "%s=\"%s\";\n" // Include ; to separate variables when 'dist env' output is used with eval.
	switch {
	case *plan9:
		format = "%s='%s'\n"
	case *windows:
		format = "set %s=%s\r\n"
	}

	xprintf(format, "GO111MODULE", "")
	xprintf(format, "GOARCH", goarch)
	xprintf(format, "GOBIN", gorootBin)
	xprintf(format, "GODEBUG", os.Getenv("GODEBUG"))
	xprintf(format, "GOENV", "off")
	xprintf(format, "GOFLAGS", "")
	xprintf(format, "GOHOSTARCH", gohostarch)
	xprintf(format, "GOHOSTOS", gohostos)
	xprintf(format, "GOOS", goos)
	xprintf(format, "GOPROXY", os.Getenv("GOPROXY"))
	xprintf(format, "GOROOT", goroot)
	xprintf(format, "GOTMPDIR", os.Getenv("GOTMPDIR"))
	xprintf(format, "GOTOOLDIR", tooldir)
	if goarch == "arm" {
		xprintf(format, "GOARM", goarm)
	}
	if goarch == "arm64" {
		xprintf(format, "GOARM64", goarm64)
	}
	if goarch == "386" {
		xprintf(format, "GO386", go386)
	}
	if goarch == "amd64" {
		xprintf(format, "GOAMD64", goamd64)
	}
	if goarch == "mips" || goarch == "mipsle" {
		xprintf(format, "GOMIPS", gomips)
	}
	if goarch == "mips64" || goarch == "mips64le" {
		xprintf(format, "GOMIPS64", gomips64)
	}
	if goarch == "ppc64" || goarch == "ppc64le" {
		xprintf(format, "GOPPC64", goppc64)
	}
	if goarch == "riscv64" {
		xprintf(format, "GORISCV64", goriscv64)
	}
	xprintf(format, "GOWORK", "off")

	if *path {
		sep := ":"
		if gohostos == "windows" {
			sep = ";"
		}
		xprintf(format, "PATH", fmt.Sprintf("%s%s%s", gorootBin, sep, os.Getenv("PATH")))

		// Also include $DIST_UNMODIFIED_PATH with the original $PATH
		// for the internal needs of "dist banner", along with export
		// so that it reaches the dist process. See its comment below.
		var exportFormat string
		if !*windows && !*plan9 {
			exportFormat = "export " + format
		} else {
			exportFormat = format
		}
		xprintf(exportFormat, "DIST_UNMODIFIED_PATH", os.Getenv("PATH"))
	}
}

var (
	timeLogEnabled = os.Getenv("GOBUILDTIMELOGFILE") != ""
	timeLogMu      sync.Mutex
	timeLogFile    *os.File
	timeLogStart   time.Time
)

func timelog(op, name string) {
	if !timeLogEnabled {
		return
	}
	timeLogMu.Lock()
	defer timeLogMu.Unlock()
	if timeLogFile == nil {
		f, err := os.OpenFile(os.Getenv("GOBUILDTIMELOGFILE"), os.O_RDWR|os.O_APPEND, 0666)
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, 100)
		n, _ := f.Read(buf)
		s := string(buf[:n])
		if i := strings.Index(s, "\n"); i >= 0 {
			s = s[:i]
		}
		i := strings.Index(s, " start")
		if i < 0 {
			log.Fatalf("time log %s does not begin with start line", os.Getenv("GOBUILDTIMELOGFILE"))
		}
		t, err := time.Parse(time.UnixDate, s[:i])
		if err != nil {
			log.Fatalf("cannot parse time log line %q: %v", s, err)
		}
		timeLogStart = t
		timeLogFile = f
	}
	t := time.Now()
	fmt.Fprintf(timeLogFile, "%s %+.1fs %s %s\n", t.Format(time.UnixDate), t.Sub(timeLogStart).Seconds(), op, name)
}

// toolenv returns the environment to use when building commands in cmd.
//
// This is a function instead of a variable because the exact toolenv depends
// on the GOOS and GOARCH, and (at least for now) those are modified in place
// to switch between the host and target configurations when cross-compiling.
func toolenv() []string {
	var env []string
	if !mustLinkExternal(goos, goarch, false) {
		// Unless the platform requires external linking,
		// we disable cgo to get static binaries for cmd/go and cmd/pprof,
		// so that they work on systems without the same dynamic libraries
		// as the original build system.
		env = append(env, "CGO_ENABLED=0")
	}
	if isRelease || os.Getenv("GO_BUILDER_NAME") != "" {
		// Add -trimpath for reproducible builds of releases.
		// Include builders so that -trimpath is well-tested ahead of releases.
		// Do not include local development, so that people working in the
		// main branch for day-to-day work on the Go toolchain itself can
		// still have full paths for stack traces for compiler crashes and the like.
		env = append(env, "GOFLAGS=-trimpath -ldflags=-w -gcflags=cmd/...=-dwarf=false")
	}
	return env
}

var toolchain = []string{"cmd/asm", "cmd/cgo", "cmd/compile", "cmd/link", "cmd/preprofile"}

// The bootstrap command runs a build from scratch,
// stopping at having installed the go_bootstrap command.
//
// WARNING: This command runs after cmd/dist is built with the Go bootstrap toolchain.
// It rebuilds and installs cmd/dist with the new toolchain, so other
// commands (like "go tool dist test" in run.bash) can rely on bug fixes
// made since the Go bootstrap version, but this function cannot.
func cmdbootstrap() {
	timelog("start", "dist bootstrap")
	defer timelog("end", "dist bootstrap")

	var debug, distpack, force, noBanner, noClean bool
	flag.BoolVar(&rebuildall, "a", rebuildall, "rebuild all")
	flag.BoolVar(&debug, "d", debug, "enable debugging of bootstrap process")
	flag.BoolVar(&distpack, "distpack", distpack, "write distribution files to pkg/distpack")
	flag.BoolVar(&force, "force", force, "build even if the port is marked as broken")
	flag.BoolVar(&noBanner, "no-banner", noBanner, "do not print banner")
	flag.BoolVar(&noClean, "no-clean", noClean, "print deprecation warning")

	xflagparse(0)

	if noClean {
		xprintf("warning: --no-clean is deprecated and has no effect; use 'go install std cmd' instead\n")
	}

	// Don't build broken ports by default.
	if broken[goos+"/"+goarch] && !force {
		fatalf("build stopped because the port %s/%s is marked as broken\n\n"+
			"Use the -force flag to build anyway.\n", goos, goarch)
	}

	// Set GOPATH to an internal directory. We shouldn't actually
	// need to store files here, since the toolchain won't
	// depend on modules outside of vendor directories, but if
	// GOPATH points somewhere else (e.g., to GOROOT), the
	// go tool may complain.
	os.Setenv("GOPATH", pathf("%s/pkg/obj/gopath", goroot))

	// Set GOPROXY=off to avoid downloading modules to the modcache in
	// the GOPATH set above to be inside GOROOT. The modcache is read
	// only so if we downloaded to the modcache, we'd create readonly
	// files in GOROOT, which is undesirable. See #67463)
	os.Setenv("GOPROXY", "off")

	// Use a build cache separate from the default user one.
	// Also one that will be wiped out during startup, so that
	// make.bash really does start from a clean slate.
	oldgocache = os.Getenv("GOCACHE")
	os.Setenv("GOCACHE", pathf("%s/pkg/obj/go-build", goroot))

	// Disable GOEXPERIMENT when building toolchain1 and
	// go_bootstrap. We don't need any experiments for the
	// bootstrap toolchain, and this lets us avoid duplicating the
	// GOEXPERIMENT-related build logic from cmd/go here. If the
	// bootstrap toolchain is < Go 1.17, it will ignore this
	// anyway since GOEXPERIMENT is baked in; otherwise it will
	// pick it up from the environment we set here. Once we're
	// using toolchain1 with dist as the build system, we need to
	// override this to keep the experiments assumed by the
	// toolchain and by dist consistent. Once go_bootstrap takes
	// over the build process, we'll set this back to the original
	// GOEXPERIMENT.
	os.Setenv("GOEXPERIMENT", "none")

	if debug {
		// cmd/buildid is used in debug mode.
		toolchain = append(toolchain, "cmd/buildid")
	}

	if isdir(pathf("%s/src/pkg", goroot)) {
		fatalf("\n\n"+
			"The Go package sources have moved to $GOROOT/src.\n"+
			"*** %s still exists. ***\n"+
			"It probably contains stale files that may confuse the build.\n"+
			"Please (check what's there and) remove it and try again.\n"+
			"See https://golang.org/s/go14nopkg\n",
			pathf("%s/src/pkg", goroot))
	}

	if rebuildall {
		clean()
	}

	setup()

	timelog("build", "toolchain1")
	checkCC()
	bootstrapBuildTools()

	// Remember old content of $GOROOT/bin for comparison below.
	oldBinFiles, err := filepath.Glob(pathf("%s/bin/*", goroot))
	if err != nil {
		fatalf("glob: %v", err)
	}

	// For the main bootstrap, building for host os/arch.
	oldgoos = goos
	oldgoarch = goarch
	goos = gohostos
	goarch = gohostarch
	os.Setenv("GOHOSTARCH", gohostarch)
	os.Setenv("GOHOSTOS", gohostos)
	os.Setenv("GOARCH", goarch)
	os.Setenv("GOOS", goos)

	timelog("build", "go_bootstrap")
	xprintf("Building Go bootstrap cmd/go (go_bootstrap) using Go toolchain1.\n")
	install("runtime")     // dependency not visible in sources; also sets up textflag.h
	install("time/tzdata") // no dependency in sources; creates generated file
	install("cmd/go")
	if vflag > 0 {
		xprintf("\n")
	}

	gogcflags = os.Getenv("GO_GCFLAGS") // we were using $BOOT_GO_GCFLAGS until now
	setNoOpt()
	goldflags = os.Getenv("GO_LDFLAGS") // we were using $BOOT_GO_LDFLAGS until now
	goBootstrap := pathf("%s/go_bootstrap", tooldir)
	if debug {
		run("", ShowOutput|CheckExit, pathf("%s/compile", tooldir), "-V=full")
		copyfile(pathf("%s/compile1", tooldir), pathf("%s/compile", tooldir), writeExec)
	}

	// To recap, so far we have built the new toolchain
	// (cmd/asm, cmd/cgo, cmd/compile, cmd/link)
	// using the Go bootstrap toolchain and go command.
	// Then we built the new go command (as go_bootstrap)
	// using the new toolchain and our own build logic (above).
	//
	//	toolchain1 = mk(new toolchain, go1.17 toolchain, go1.17 cmd/go)
	//	go_bootstrap = mk(new cmd/go, toolchain1, cmd/dist)
	//
	// The toolchain1 we built earlier is built from the new sources,
	// but because it was built using cmd/go it has no build IDs.
	// The eventually installed toolchain needs build IDs, so we need
	// to do another round:
	//
	//	toolchain2 = mk(new toolchain, toolchain1, go_bootstrap)
	//
	timelog("build", "toolchain2")
	if vflag > 0 {
		xprintf("\n")
	}
	xprintf("Building Go toolchain2 using go_bootstrap and Go toolchain1.\n")
	os.Setenv("CC", compilerEnvLookup("CC", defaultcc, goos, goarch))
	// Now that cmd/go is in charge of the build process, enable GOEXPERIMENT.
	os.Setenv("GOEXPERIMENT", goexperiment)
	// No need to enable PGO for toolchain2.
	goInstall(toolenv(), goBootstrap, append([]string{"-pgo=off"}, toolchain...)...)
	if debug {
		run("", ShowOutput|CheckExit, pathf("%s/compile", tooldir), "-V=full")
		copyfile(pathf("%s/compile2", tooldir), pathf("%s/compile", tooldir), writeExec)
	}

	// Toolchain2 should be semantically equivalent to toolchain1,
	// but it was built using the newly built compiler instead of the Go bootstrap compiler,
	// so it should at the least run faster. Also, toolchain1 had no build IDs
	// in the binaries, while toolchain2 does. In non-release builds, the
	// toolchain's build IDs feed into constructing the build IDs of built targets,
	// so in non-release builds, everything now looks out-of-date due to
	// toolchain2 having build IDs - that is, due to the go command seeing
	// that there are new compilers. In release builds, the toolchain's reported
	// version is used in place of the build ID, and the go command does not
	// see that change from toolchain1 to toolchain2, so in release builds,
	// nothing looks out of date.
	// To keep the behavior the same in both non-release and release builds,
	// we force-install everything here.
	//
	//	toolchain3 = mk(new toolchain, toolchain2, go_bootstrap)
	//
	timelog("build", "toolchain3")
	if vflag > 0 {
		xprintf("\n")
	}
	xprintf("Building Go toolchain3 using go_bootstrap and Go toolchain2.\n")
	goInstall(toolenv(), goBootstrap, append([]string{"-a"}, toolchain...)...)
	if debug {
		run("", ShowOutput|CheckExit, pathf("%s/compile", tooldir), "-V=full")
		copyfile(pathf("%s/compile3", tooldir), pathf("%s/compile", tooldir), writeExec)
	}

	// Now that toolchain3 has been built from scratch, its compiler and linker
	// should have accurate build IDs suitable for caching.
	// Now prime the build cache with the rest of the standard library for
	// testing, and so that the user can run 'go install std cmd' to quickly
	// iterate on local changes without waiting for a full rebuild.
	if _, err := os.Stat(pathf("%s/VERSION", goroot)); err == nil {
		// If we have a VERSION file, then we use the Go version
		// instead of build IDs as a cache key, and there is no guarantee
		// that code hasn't changed since the last time we ran a build
		// with this exact VERSION file (especially if someone is working
		// on a release branch). We must not fall back to the shared build cache
		// in this case. Leave $GOCACHE alone.
	} else {
		os.Setenv("GOCACHE", oldgocache)
	}

	if goos == oldgoos && goarch == oldgoarch {
		// Common case - not setting up for cross-compilation.
		timelog("build", "toolchain")
		if vflag > 0 {
			xprintf("\n")
		}
		xprintf("Building packages and commands for %s/%s.\n", goos, goarch)
	} else {
		// GOOS/GOARCH does not match GOHOSTOS/GOHOSTARCH.
		// Finish GOHOSTOS/GOHOSTARCH installation and then
		// run GOOS/GOARCH installation.
		timelog("build", "host toolchain")
		if vflag > 0 {
			xprintf("\n")
		}
		xprintf("Building commands for host, %s/%s.\n", goos, goarch)
		goInstall(toolenv(), goBootstrap, "cmd")
		checkNotStale(toolenv(), goBootstrap, "cmd")
		checkNotStale(toolenv(), gorootBinGo, "cmd")

		timelog("build", "target toolchain")
		if vflag > 0 {
			xprintf("\n")
		}
		goos = oldgoos
		goarch = oldgoarch
		os.Setenv("GOOS", goos)
		os.Setenv("GOARCH", goarch)
		os.Setenv("CC", compilerEnvLookup("CC", defaultcc, goos, goarch))
		xprintf("Building packages and commands for target, %s/%s.\n", goos, goarch)
	}
	goInstall(nil, goBootstrap, "std")
	goInstall(toolenv(), goBootstrap, "cmd")
	checkNotStale(toolenv(), goBootstrap, toolchain...)
	checkNotStale(nil, goBootstrap, "std")
	checkNotStale(toolenv(), goBootstrap, "cmd")
	checkNotStale(nil, gorootBinGo, "std")
	checkNotStale(toolenv(), gorootBinGo, "cmd")
	if debug {
		run("", ShowOutput|CheckExit, pathf("%s/compile", tooldir), "-V=full")
		checkNotStale(toolenv(), goBootstrap, toolchain...)
		copyfile(pathf("%s/compile4", tooldir), pathf("%s/compile", tooldir), writeExec)
	}

	// Check that there are no new files in $GOROOT/bin other than
	// go and gofmt and $GOOS_$GOARCH (target bin when cross-compiling).
	binFiles, err := filepath.Glob(pathf("%s/bin/*", goroot))
	if err != nil {
		fatalf("glob: %v", err)
	}

	ok := map[string]bool{}
	for _, f := range oldBinFiles {
		ok[f] = true
	}
	for _, f := range binFiles {
		if gohostos == "darwin" && filepath.Base(f) == ".DS_Store" {
			continue // unfortunate but not unexpected
		}
		elem := strings.TrimSuffix(filepath.Base(f), ".exe")
		if !ok[f] && elem != "go" && elem != "gofmt" && elem != goos+"_"+goarch {
			fatalf("unexpected new file in $GOROOT/bin: %s", elem)
		}
	}

	// Remove go_bootstrap now that we're done.
	xremove(pathf("%s/go_bootstrap"+exe, tooldir))

	if goos == "android" {
		// Make sure the exec wrapper will sync a fresh $GOROOT to the device.
		xremove(pathf("%s/go_android_exec-adb-sync-status", os.TempDir()))
	}

	if wrapperPath := wrapperPathFor(goos, goarch); wrapperPath != "" {
		oldcc := os.Getenv("CC")
		os.Setenv("GOOS", gohostos)
		os.Setenv("GOARCH", gohostarch)
		os.Setenv("CC", compilerEnvLookup("CC", defaultcc, gohostos, gohostarch))
		goCmd(nil, gorootBinGo, "build", "-o", pathf("%s/go_%s_%s_exec%s", gorootBin, goos, goarch, exe), wrapperPath)
		// Restore environment.
		// TODO(elias.naur): support environment variables in goCmd?
		os.Setenv("GOOS", goos)
		os.Setenv("GOARCH", goarch)
		os.Setenv("CC", oldcc)
	}

	if distpack {
		xprintf("Packaging archives for %s/%s.\n", goos, goarch)
		run("", ShowOutput|CheckExit, pathf("%s/distpack", tooldir))
	}

	// Print trailing banner unless instructed otherwise.
	if !noBanner {
		banner()
	}
}

func wrapperPathFor(goos, goarch string) string {
	switch {
	case goos == "android":
		if gohostos != "android" {
			return pathf("%s/misc/go_android_exec/main.go", goroot)
		}
	case goos == "ios":
		if gohostos != "ios" {
			return pathf("%s/misc/ios/go_ios_exec.go", goroot)
		}
	}
	return ""
}

func goInstall(env []string, goBinary string, args ...string) {
	goCmd(env, goBinary, "install", args...)
}

func appendCompilerFlags(args []string) []string {
	if gogcflags != "" {
		args = append(args, "-gcflags=all="+gogcflags)
	}
	if goldflags != "" {
		args = append(args, "-ldflags=all="+goldflags)
	}
	return args
}

func goCmd(env []string, goBinary string, cmd string, args ...string) {
	goCmd := []string{goBinary, cmd}
	if noOpt {
		goCmd = append(goCmd, "-tags=noopt")
	}
	goCmd = appendCompilerFlags(goCmd)
	if vflag > 0 {
		goCmd = append(goCmd, "-v")
	}

	// Force only one process at a time on vx32 emulation.
	if gohostos == "plan9" && os.Getenv("sysname") == "vx32" {
		goCmd = append(goCmd, "-p=1")
	}

	runEnv(workdir, ShowOutput|CheckExit, env, append(goCmd, args...)...)
}

func checkNotStale(env []string, goBinary string, targets ...string) {
	goCmd := []string{goBinary, "list"}
	if noOpt {
		goCmd = append(goCmd, "-tags=noopt")
	}
	goCmd = appendCompilerFlags(goCmd)
	goCmd = append(goCmd, "-f={{if .Stale}}\tSTALE {{.ImportPath}}: {{.StaleReason}}{{end}}")

	out := runEnv(workdir, CheckExit, env, append(goCmd, targets...)...)
	if strings.Contains(out, "\tSTALE ") {
		os.Setenv("GODEBUG", "gocachehash=1")
		for _, target := range []string{"internal/runtime/sys", "cmd/dist", "cmd/link"} {
			if strings.Contains(out, "STALE "+target) {
				run(workdir, ShowOutput|CheckExit, goBinary, "list", "-f={{.ImportPath}} {{.Stale}}", target)
				break
			}
		}
		fatalf("unexpected stale targets reported by %s list -gcflags=\"%s\" -ldflags=\"%s\" for %v (consider rerunning with GOMAXPROCS=1 GODEBUG=gocachehash=1):\n%s", goBinary, gogcflags, goldflags, targets, out)
	}
}

// Cannot use go/build directly because cmd/dist for a new release
// builds against an old release's go/build, which may be out of sync.
// To reduce duplication, we generate the list for go/build from this.
//
// We list all supported platforms in this list, so that this is the
// single point of truth for supported platforms. This list is used
// by 'go tool dist list'.
var cgoEnabled = map[string]bool{
	"aix/ppc64":       true,
	"darwin/amd64":    true,
	"darwin/arm64":    true,
	"dragonfly/amd64": true,
	"freebsd/386":     true,
	"freebsd/amd64":   true,
	"freebsd/arm":     true,
	"freebsd/arm64":   true,
	"freebsd/riscv64": true,
	"illumos/amd64":   true,
	"linux/386":       true,
	"linux/amd64":     true,
	"linux/arm":       true,
	"linux/arm64":     true,
	"linux/loong64":   true,
	"linux/ppc64":     false,
	"linux/ppc64le":   true,
	"linux/mips":      true,
	"linux/mipsle":    true,
	"linux/mips64":    true,
	"linux/mips64le":  true,
	"linux/riscv64":   true,
	"linux/s390x":     true,
	"linux/sparc64":   true,
	"android/386":     true,
	"android/amd64":   true,
	"android/arm":     true,
	"android/arm64":   true,
	"ios/arm64":       true,
	"ios/amd64":       true,
	"js/wasm":         false,
	"wasip1/wasm":     false,
	"netbsd/386":      true,
	"netbsd/amd64":    true,
	"netbsd/arm":      true,
	"netbsd/arm64":    true,
	"openbsd/386":     true,
	"openbsd/amd64":   true,
	"openbsd/arm":     true,
	"openbsd/arm64":   true,
	"openbsd/mips64":  true,
	"openbsd/ppc64":   false,
	"openbsd/riscv64": true,
	"plan9/386":       false,
	"plan9/amd64":     false,
	"plan9/arm":       false,
	"solaris/amd64":   true,
	"windows/386":     true,
	"windows/amd64":   true,
	"windows/arm":     false,
	"windows/arm64":   true,
}

// List of platforms that are marked as broken ports.
// These require -force flag to build, and also
// get filtered out of cgoEnabled for 'dist list'.
// See go.dev/issue/56679.
var broken = map[string]bool{
	"linux/sparc64":  true, // An incomplete port. See CL 132155.
	"openbsd/mips64": true, // Broken: go.dev/issue/58110.
	"windows/arm":    true, // Broken: go.dev/issue/68552.
}

// List of platforms which are first class ports. See go.dev/issue/38874.
var firstClass = map[string]bool{
	"darwin/amd64":  true,
	"darwin/arm64":  true,
	"linux/386":     true,
	"linux/amd64":   true,
	"linux/arm":     true,
	"linux/arm64":   true,
	"windows/386":   true,
	"windows/amd64": true,
}

// We only need CC if cgo is forced on, or if the platform requires external linking.
// Otherwise the go command will automatically disable it.
func needCC() bool {
	return os.Getenv("CGO_ENABLED") == "1" || mustLinkExternal(gohostos, gohostarch, false)
}

func checkCC() {
	if !needCC() {
		return
	}
	cc1 := defaultcc[""]
	if cc1 == "" {
		cc1 = "gcc"
		for _, os := range clangos {
			if gohostos == os {
				cc1 = "clang"
				break
			}
		}
	}
	cc, err := quotedSplit(cc1)
	if err != nil {
		fatalf("split CC: %v", err)
	}
	var ccHelp = append(cc, "--help")

	if output, err := exec.Command(ccHelp[0], ccHelp[1:]...).CombinedOutput(); err != nil {
		outputHdr := ""
		if len(output) > 0 {
			outputHdr = "\nCommand output:\n\n"
		}
		fatalf("cannot invoke C compiler %q: %v\n\n"+
			"Go needs a system C compiler for use with cgo.\n"+
			"To set a C compiler, set CC=the-compiler.\n"+
			"To disable cgo, set CGO_ENABLED=0.\n%s%s", cc, err, outputHdr, output)
	}
}

func defaulttarg() string {
	// xgetwd might return a path with symlinks fully resolved, and if
	// there happens to be symlinks in goroot, then the hasprefix test
	// will never succeed. Instead, we use xrealwd to get a canonical
	// goroot/src before the comparison to avoid this problem.
	pwd := xgetwd()
	src := pathf("%s/src/", goroot)
	real_src := xrealwd(src)
	if !strings.HasPrefix(pwd, real_src) {
		fatalf("current directory %s is not under %s", pwd, real_src)
	}
	pwd = pwd[len(real_src):]
	// guard against xrealwd returning the directory without the trailing /
	pwd = strings.TrimPrefix(pwd, "/")

	return pwd
}

// Install installs the list of packages named on the command line.
func cmdinstall() {
	xflagparse(-1)

	if flag.NArg() == 0 {
		install(defaulttarg())
	}

	for _, arg := range flag.Args() {
		install(arg)
	}
}

// Clean deletes temporary objects.
func cmdclean() {
	xflagparse(0)
	clean()
}

// Banner prints the 'now you've installed Go' banner.
func cmdbanner() {
	xflagparse(0)
	banner()
}

func banner() {
	if vflag > 0 {
		xprintf("\n")
	}
	xprintf("---\n")
	xprintf("Installed Go for %s/%s in %s\n", goos, goarch, goroot)
	xprintf("Installed commands in %s\n", gorootBin)

	if gohostos == "plan9" {
		// Check that GOROOT/bin is bound before /bin.
		pid := strings.Replace(readfile("#c/pid"), " ", "", -1)
		ns := fmt.Sprintf("/proc/%s/ns", pid)
		if !strings.Contains(readfile(ns), fmt.Sprintf("bind -b %s /bin", gorootBin)) {
			xprintf("*** You need to bind %s before /bin.\n", gorootBin)
		}
	} else {
		// Check that GOROOT/bin appears in $PATH.
		pathsep := ":"
		if gohostos == "windows" {
			pathsep = ";"
		}
		path := os.Getenv("PATH")
		if p, ok := os.LookupEnv("DIST_UNMODIFIED_PATH"); ok {
			// Scripts that modify $PATH and then run dist should also provide
			// dist with an unmodified copy of $PATH via $DIST_UNMODIFIED_PATH.
			// Use it here when determining if the user still needs to update
			// their $PATH. See go.dev/issue/42563.
			path = p
		}
		if !strings.Contains(pathsep+path+pathsep, pathsep+gorootBin+pathsep) {
			xprintf("*** You need to add %s to your PATH.\n", gorootBin)
		}
	}
}

// Version prints the Go version.
func cmdversion() {
	xflagparse(0)
	xprintf("%s\n", findgoversion())
}

// cmdlist lists all supported platforms.
func cmdlist() {
	jsonFlag := flag.Bool("json", false, "produce JSON output")
	brokenFlag := flag.Bool("broken", false, "include broken ports")
	xflagparse(0)

	var plats []string
	for p := range cgoEnabled {
		if broken[p] && !*brokenFlag {
			continue
		}
		plats = append(plats, p)
	}
	sort.Strings(plats)

	if !*jsonFlag {
		for _, p := range plats {
			xprintf("%s\n", p)
		}
		return
	}

	type jsonResult struct {
		GOOS         string
		GOARCH       string
		CgoSupported bool
		FirstClass   bool
		Broken       bool `json:",omitempty"`
	}
	var results []jsonResult
	for _, p := range plats {
		fields := strings.Split(p, "/")
		results = append(results, jsonResult{
			GOOS:         fields[0],
			GOARCH:       fields[1],
			CgoSupported: cgoEnabled[p],
			FirstClass:   firstClass[p],
			Broken:       broken[p],
		})
	}
	out, err := json.MarshalIndent(results, "", "\t")
	if err != nil {
		fatalf("json marshal error: %v", err)
	}
	if _, err := os.Stdout.Write(out); err != nil {
		fatalf("write failed: %v", err)
	}
}

func setNoOpt() {
	for _, gcflag := range strings.Split(gogcflags, " ") {
		if gcflag == "-N" || gcflag == "-l" {
			noOpt = true
			break
		}
	}
}

"""



```