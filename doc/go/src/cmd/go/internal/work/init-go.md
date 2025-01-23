Response: Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Context:** The first line, `// go/src/cmd/go/internal/work/init.go`, immediately tells us this is part of the `go` command's internal workings, specifically within the `work` package, and it's responsible for initialization. This suggests it runs early in the `go` command's execution.

2. **Identify the Core Function:** The most prominent function is `BuildInit()`. The comment `// Build initialization (after flag parsing).` confirms its purpose. This means it executes *after* the command-line flags have been processed.

3. **Analyze `BuildInit()` Step-by-Step:**  Go through the code line by line, understanding the purpose of each call:
    * `buildInitStarted` check: Ensures `BuildInit` isn't called multiple times, indicating a potential internal error.
    * `base.AtExit(closeBuilders)`:  Registers a function to be called when the program exits. Without seeing `closeBuilders`, we can infer it handles resource cleanup.
    * `modload.Init()`: Initializes the module loading system. Important for dependency management.
    * `instrumentInit()`:  Likely deals with instrumentation for tools like `go test -race` or code coverage.
    * `buildModeInit()`: Configures the build process based on the `-buildmode` flag.
    * `fsys.Init()`: Initializes the file system abstraction layer.
    * `-pkgdir` handling:  Ensures the package installation directory is absolute. This is crucial because build commands are executed in various directories.
    * `-p` handling: Validates the parallelism flag.
    * `CC`, `CXX`, `FC` handling: Checks if the compiler environment variables are absolute paths. This is important for build reproducibility and security.
    * `-covermode` and `-race` interaction:  Sets the default coverage mode and ensures compatibility with the race detector.

4. **Analyze Supporting Functions Called by `BuildInit()`:**

    * **`instrumentInit()`:** Focus on the conditional checks for `-race`, `-msan`, and `-asan`. Note the mutual exclusivity of these flags and the platform support checks. The call to `compilerRequiredAsanVersion()` is key.
    * **`buildModeInit()`:** This function is a large `switch` statement. Analyze each `case` for `-buildmode`. Pay attention to:
        * The `pkgsFilter` variable, suggesting different build modes have restrictions on the types of packages built (main vs. library).
        * The handling of `codegenArg`, which seems to pass flags to the compiler/linker based on the build mode.
        * The special handling for `gccgo`.
        * The interaction with `-linkshared`.
        * The `-mod` related flags and module awareness.

5. **Analyze Supporting Functions Not Directly Called by `BuildInit()` (but relevant):**

    * **`fuzzInstrumentFlags()`:**  Straightforward – returns compiler flags for fuzzing instrumentation if supported.
    * **`compilerVersion()`:**  This is about detecting the version of the C compiler. Note the use of `exec.Command` and regular expressions. The caching mechanism using `sync.Once` is also worth noting.
    * **`compilerRequiredAsanVersion()`:**  Checks if the detected compiler version is compatible with ASan.

6. **Infer Go Language Features:** Based on the function names and logic, deduce the relevant Go features:
    * **Build Process Customization:**  The `-buildmode` flag directly relates to this.
    * **Race Detection:** The `-race` flag and the `instrumentInit` function are key.
    * **Memory Sanitizers:** `-msan` and `-asan` flags, and their handling in `instrumentInit`.
    * **Code Coverage:** The `-covermode` flag.
    * **Fuzzing:** The `fuzzInstrumentFlags` function points to this.
    * **Module Management:** The `-mod` flag and `modload.Init()`.
    * **C Interoperability (cgo):** The checks for `CgoEnabled` in `instrumentInit`.

7. **Construct Examples:**  For each inferred feature, create a concise Go code example demonstrating its usage. Keep the examples simple and focused.

8. **Identify Command-Line Arguments:**  List the command-line arguments explicitly mentioned in the code (e.g., `-pkgdir`, `-p`, `-buildmode`, `-race`, `-covermode`, `-msan`, `-asan`, `-mod`, `-modcacherw`, `-modfile`, `-o`, `-linkshared`). Explain their purpose based on the code's logic.

9. **Pinpoint Potential User Errors:** Look for error conditions in the code that users might encounter. Examples:
    * Providing a relative path for `-pkgdir`, `CC`, `CXX`, or `FC`.
    * Using incompatible flags like `-race` with `-msan` or an invalid `-covermode`.
    * Using `-buildmode=pie` with `-race` on unsupported platforms.
    * Combining `-buildmode=shared` with `-o`.
    * Using `-mod` related flags without modules enabled.

10. **Review and Refine:**  Read through the entire analysis, ensuring clarity, accuracy, and completeness. Check if the examples are correct and the explanations are easy to understand. Ensure the flow is logical. For example, make sure the explanation of `BuildInit` comes before the explanation of functions it calls.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "This file just initializes things."  **Correction:** It's more than just *initialization*. It's *configuration* and *validation* of the build process based on user inputs and the environment.
* **Realization:** The `instrumentInit` function is heavily focused on sanitizers. Initially, I might have just labeled it "instrumentation," but specifying "for sanitizers and race detection" is more accurate.
* **Focusing on the "why":**  Instead of just saying "checks `-pkgdir`," explain *why* it needs to be absolute.
* **Connecting code to features:**  Explicitly linking code sections to the corresponding Go language features makes the analysis more valuable. For instance, explicitly mentioning how the `switch` statement in `buildModeInit` implements the different `-buildmode` options.

By following this systematic approach, we can thoroughly understand the functionality of the given Go code snippet and provide a comprehensive explanation.
这是 `go/src/cmd/go/internal/work/init.go` 文件中 `work` 包的一部分，它的主要功能是执行 Go 语言构建过程的初始化工作，发生在命令行参数解析之后。

以下是它更具体的功能分解：

**1. 全局初始化和单次执行保证:**

*   `buildInitStarted` 变量和 `BuildInit()` 函数开头的检查机制确保 `BuildInit()` 函数只被调用一次。这避免了重复初始化可能导致的问题。
*   `base.AtExit(closeBuilders)` 注册了一个在程序退出时调用的函数 `closeBuilders`（虽然代码中未提供，但推测其功能是清理构建相关的资源）。

**2. 模块加载初始化:**

*   `modload.Init()` 调用初始化了 Go 模块加载系统。这对于处理项目依赖至关重要，尤其是在使用了 Go Modules 的项目中。

**3. 代码插桩初始化:**

*   `instrumentInit()` 函数负责处理与代码插桩相关的配置，例如启用 `-race` (竞态检测), `-msan` (内存检测), `-asan` (地址检测)。它会检查这些选项的兼容性，平台支持，以及是否需要启用 cgo。

**4. 构建模式初始化:**

*   `buildModeInit()` 函数根据 `-buildmode` 命令行参数来配置构建模式，例如 `archive`, `c-shared`, `exe`, `pie`, `shared`, `plugin` 等。它会根据选择的构建模式设置不同的编译器和链接器标志，以及输出文件的后缀。

**5. 文件系统初始化:**

*   `fsys.Init()` 初始化了文件系统相关的操作，可能涉及到虚拟文件系统或缓存机制。

**6. `-pkgdir` 参数处理:**

*   确保 `-pkgdir` 参数指定的是绝对路径。由于构建过程可能在不同的目录下执行命令，使用绝对路径可以避免路径解析错误。

**7. `-p` 参数处理:**

*   验证 `-p` 参数（指定并行编译的 goroutine 数量）是否为正整数。

**8. 编译器路径处理:**

*   检查环境变量 `CC`, `CXX`, `FC` (分别代表 C, C++, Fortran 编译器) 指定的路径是否为绝对路径。这有助于构建过程的可预测性和安全性。

**9. 代码覆盖率模式处理:**

*   如果 `-covermode` 没有被显式设置，则默认设置为 "set"。
*   如果启用了 `-race`，则代码覆盖率模式会被强制设置为 "atomic"，因为竞态检测需要更精确的覆盖率信息。
*   检查 `-race` 和 `-covermode` 的兼容性。

**10. Fuzzing 插桩标志:**

*   `fuzzInstrumentFlags()` 函数根据目标平台返回用于启用 fuzzing 插桩的编译器标志（例如 `-d=libfuzzer`）。

**11. 编译器版本检测 (针对 ASan):**

*   `compilerVersion()` 函数尝试检测环境变量 `CC` 指定的 C 编译器的版本。
*   `compilerRequiredAsanVersion()` 函数检查检测到的编译器版本是否满足 ASan 的最低版本要求。

**推理事例：构建模式初始化**

假设用户执行了以下命令：

```bash
go build -buildmode=c-shared -o mylib.so ./mypackage
```

**输入 (基于代码的逻辑推断):**

*   `cfg.BuildBuildmode` 将被设置为 "c-shared"。
*   `cfg.Goos` 和 `cfg.Goarch` 将根据当前操作系统和架构设置（例如 "linux", "amd64"）。
*   `cfg.BuildToolchainName` 可能是 "gc" (Go 的默认编译器)。

**`buildModeInit()` 函数的执行过程 (简化):**

1. 进入 `switch cfg.BuildBuildmode` 的 "c-shared" 分支。
2. `pkgsFilter` 被设置为 `oneMainPkg`，表示只允许构建包含 `main` 函数的包。
3. 根据 `cfg.Goos` 的值，`codegenArg` 可能会被设置为 "-shared" (对于 Linux)。
4. `cfg.ExeSuffix` 被设置为 "" (对于 Windows，避免添加到 .dll 文件名)。
5. `ldBuildmode` 被设置为 "c-shared"。

**输出 (影响全局变量):**

*   `pkgsFilter` 将限制构建过程只处理包含 `main` 函数的包。
*   `codegenArg` 将包含 "-shared" (或其他平台特定的值)，这个标志会被传递给编译器。
*   `cfg.ExeSuffix` 可能被修改。
*   `ldBuildmode` 将被设置为 "c-shared"，影响链接器的行为。

**命令行参数的具体处理 (在 `BuildInit` 涉及的部分):**

*   **`-pkgdir`:** 指定安装包的目录。`BuildInit` 确保这个路径是绝对的。如果用户提供了相对路径，Go 会尝试将其转换为绝对路径。
*   **`-p`:** 指定并行编译的 goroutine 数量。`BuildInit` 检查它是否为正整数。
*   **`-buildmode`:** 指定要构建的输出类型（例如，可执行文件、共享库、插件）。`buildModeInit` 函数会根据这个参数设置构建过程。
*   **`-race`:** 启用竞态检测。`instrumentInit` 函数会处理这个标志，并可能强制设置代码覆盖率模式。
*   **`-covermode`:** 指定代码覆盖率的模式。`BuildInit` 会设置默认值，并检查与 `-race` 的兼容性。
*   **`-msan`:** 启用内存检测器。`instrumentInit` 函数会处理这个标志，检查平台支持和与其他 sanitizer 的冲突。
*   **`-asan`:** 启用地址检测器。`instrumentInit` 函数会处理这个标志，检查平台支持、与其他 sanitizer 的冲突以及编译器版本。
*   **`-mod`:** 控制是否使用 Go Modules。`buildModeInit` 会检查这个标志的有效性。
*   **`-modcacherw`:** 允许读写模块缓存。`buildModeInit` 会检查这个标志的有效性。
*   **`-modfile`:** 指定一个备用的 `go.mod` 文件路径。`buildModeInit` 会检查这个标志的有效性。
*   **`-o`:** 指定输出文件的名称。虽然 `BuildInit` 本身没有直接处理 `-o` 的赋值，但在 `buildModeInit` 中，如果 `-buildmode=exe` 且指定了 `-o`，`pkgsFilter` 会被设置为 `oneMainPkg` 以提供更好的错误信息。
*   **`-linkshared`:**  使用共享库链接。`buildModeInit` 会处理这个标志，设置相关的编译器和链接器标志。

**使用者易犯错的点:**

1. **`-pkgdir` 使用相对路径:**  用户可能会不小心提供一个相对路径给 `-pkgdir`，导致构建结果不符合预期，或者在不同的工作目录下构建时出现问题。

    ```bash
    # 错误示例：假设当前目录是 /home/user/project
    go build -pkgdir=./bin  # 应该使用绝对路径，例如 -pkgdir=/home/user/project/bin
    ```

2. **`-race` 和 `-covermode` 的不兼容设置:** 用户可能会尝试使用与 `-race` 不兼容的 `-covermode` 值。

    ```bash
    go test -race -covermode=count  # 错误：-covermode 必须是 "atomic"
    ```

3. **同时使用不兼容的 sanitizer:** 用户可能会尝试同时启用多个互斥的 sanitizer。

    ```bash
    go build -race -msan ./mypackage # 错误：不能同时使用 -race 和 -msan
    ```

4. **在不支持的平台上使用 `-buildmode` 或 sanitizer:** 用户可能会在不支持特定构建模式或 sanitizer 的操作系统/架构上尝试使用它们。

    ```bash
    go build -buildmode=plugin ./mypackage # 如果目标平台不支持 plugin 构建模式，则会出错
    go build -asan ./mypackage # 如果目标平台不支持 ASan，则会出错
    ```

5. **在未使用 Go Modules 时使用 `-mod` 相关标志:** 用户可能会在传统的 GOPATH 模式下使用 `-mod`，导致错误。

    ```bash
    go build -mod=vendor ./mypackage # 如果当前项目未使用 Go Modules，则会出错
    ```

理解 `go/src/cmd/go/internal/work/init.go` 的功能对于深入了解 Go 语言的构建过程至关重要。它负责在构建开始时进行各种关键的初始化和配置，确保后续的编译和链接步骤能够正确执行。

### 提示词
```
这是路径为go/src/cmd/go/internal/work/init.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Build initialization (after flag parsing).

package work

import (
	"bytes"
	"cmd/go/internal/base"
	"cmd/go/internal/cfg"
	"cmd/go/internal/fsys"
	"cmd/go/internal/modload"
	"cmd/internal/quoted"
	"fmt"
	"internal/platform"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"sync"
)

var buildInitStarted = false

func BuildInit() {
	if buildInitStarted {
		base.Fatalf("go: internal error: work.BuildInit called more than once")
	}
	buildInitStarted = true
	base.AtExit(closeBuilders)

	modload.Init()
	instrumentInit()
	buildModeInit()
	if err := fsys.Init(); err != nil {
		base.Fatal(err)
	}

	// Make sure -pkgdir is absolute, because we run commands
	// in different directories.
	if cfg.BuildPkgdir != "" && !filepath.IsAbs(cfg.BuildPkgdir) {
		p, err := filepath.Abs(cfg.BuildPkgdir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "go: evaluating -pkgdir: %v\n", err)
			base.SetExitStatus(2)
			base.Exit()
		}
		cfg.BuildPkgdir = p
	}

	if cfg.BuildP <= 0 {
		base.Fatalf("go: -p must be a positive integer: %v\n", cfg.BuildP)
	}

	// Make sure CC, CXX, and FC are absolute paths.
	for _, key := range []string{"CC", "CXX", "FC"} {
		value := cfg.Getenv(key)
		args, err := quoted.Split(value)
		if err != nil {
			base.Fatalf("go: %s environment variable could not be parsed: %v", key, err)
		}
		if len(args) == 0 {
			continue
		}
		path := args[0]
		if !filepath.IsAbs(path) && path != filepath.Base(path) {
			base.Fatalf("go: %s environment variable is relative; must be absolute path: %s\n", key, path)
		}
	}

	// Set covermode if not already set.
	// Ensure that -race and -covermode are compatible.
	if cfg.BuildCoverMode == "" {
		cfg.BuildCoverMode = "set"
		if cfg.BuildRace {
			// Default coverage mode is atomic when -race is set.
			cfg.BuildCoverMode = "atomic"
		}
	}
	if cfg.BuildRace && cfg.BuildCoverMode != "atomic" {
		base.Fatalf(`-covermode must be "atomic", not %q, when -race is enabled`, cfg.BuildCoverMode)
	}
}

// fuzzInstrumentFlags returns compiler flags that enable fuzzing instrumentation
// on supported platforms.
//
// On unsupported platforms, fuzzInstrumentFlags returns nil, meaning no
// instrumentation is added. 'go test -fuzz' still works without coverage,
// but it generates random inputs without guidance, so it's much less effective.
func fuzzInstrumentFlags() []string {
	if !platform.FuzzInstrumented(cfg.Goos, cfg.Goarch) {
		return nil
	}
	return []string{"-d=libfuzzer"}
}

func instrumentInit() {
	if !cfg.BuildRace && !cfg.BuildMSan && !cfg.BuildASan {
		return
	}
	if cfg.BuildRace && cfg.BuildMSan {
		fmt.Fprintf(os.Stderr, "go: may not use -race and -msan simultaneously\n")
		base.SetExitStatus(2)
		base.Exit()
	}
	if cfg.BuildRace && cfg.BuildASan {
		fmt.Fprintf(os.Stderr, "go: may not use -race and -asan simultaneously\n")
		base.SetExitStatus(2)
		base.Exit()
	}
	if cfg.BuildMSan && cfg.BuildASan {
		fmt.Fprintf(os.Stderr, "go: may not use -msan and -asan simultaneously\n")
		base.SetExitStatus(2)
		base.Exit()
	}
	if cfg.BuildMSan && !platform.MSanSupported(cfg.Goos, cfg.Goarch) {
		fmt.Fprintf(os.Stderr, "-msan is not supported on %s/%s\n", cfg.Goos, cfg.Goarch)
		base.SetExitStatus(2)
		base.Exit()
	}
	if cfg.BuildRace && !platform.RaceDetectorSupported(cfg.Goos, cfg.Goarch) {
		fmt.Fprintf(os.Stderr, "-race is not supported on %s/%s\n", cfg.Goos, cfg.Goarch)
		base.SetExitStatus(2)
		base.Exit()
	}
	if cfg.BuildASan && !platform.ASanSupported(cfg.Goos, cfg.Goarch) {
		fmt.Fprintf(os.Stderr, "-asan is not supported on %s/%s\n", cfg.Goos, cfg.Goarch)
		base.SetExitStatus(2)
		base.Exit()
	}
	// The current implementation is only compatible with the ASan library from version
	// v7 to v9 (See the description in src/runtime/asan/asan.go). Therefore, using the
	// -asan option must use a compatible version of ASan library, which requires that
	// the gcc version is not less than 7 and the clang version is not less than 9,
	// otherwise a segmentation fault will occur.
	if cfg.BuildASan {
		if err := compilerRequiredAsanVersion(); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			base.SetExitStatus(2)
			base.Exit()
		}
	}

	mode := "race"
	if cfg.BuildMSan {
		mode = "msan"
		// MSAN needs PIE on all platforms except linux/amd64.
		// https://github.com/llvm/llvm-project/blob/llvmorg-13.0.1/clang/lib/Driver/SanitizerArgs.cpp#L621
		if cfg.BuildBuildmode == "default" && (cfg.Goos != "linux" || cfg.Goarch != "amd64") {
			cfg.BuildBuildmode = "pie"
		}
	}
	if cfg.BuildASan {
		mode = "asan"
	}
	modeFlag := "-" + mode

	// Check that cgo is enabled.
	// Note: On macOS, -race does not require cgo. -asan and -msan still do.
	if !cfg.BuildContext.CgoEnabled && (cfg.Goos != "darwin" || cfg.BuildASan || cfg.BuildMSan) {
		if runtime.GOOS != cfg.Goos || runtime.GOARCH != cfg.Goarch {
			fmt.Fprintf(os.Stderr, "go: %s requires cgo\n", modeFlag)
		} else {
			fmt.Fprintf(os.Stderr, "go: %s requires cgo; enable cgo by setting CGO_ENABLED=1\n", modeFlag)
		}

		base.SetExitStatus(2)
		base.Exit()
	}
	forcedGcflags = append(forcedGcflags, modeFlag)
	forcedLdflags = append(forcedLdflags, modeFlag)

	if cfg.BuildContext.InstallSuffix != "" {
		cfg.BuildContext.InstallSuffix += "_"
	}
	cfg.BuildContext.InstallSuffix += mode
	cfg.BuildContext.ToolTags = append(cfg.BuildContext.ToolTags, mode)
}

func buildModeInit() {
	gccgo := cfg.BuildToolchainName == "gccgo"
	var codegenArg string

	// Configure the build mode first, then verify that it is supported.
	// That way, if the flag is completely bogus we will prefer to error out with
	// "-buildmode=%s not supported" instead of naming the specific platform.

	switch cfg.BuildBuildmode {
	case "archive":
		pkgsFilter = pkgsNotMain
	case "c-archive":
		pkgsFilter = oneMainPkg
		if gccgo {
			codegenArg = "-fPIC"
		} else {
			switch cfg.Goos {
			case "darwin", "ios":
				switch cfg.Goarch {
				case "arm64":
					codegenArg = "-shared"
				}

			case "dragonfly", "freebsd", "illumos", "linux", "netbsd", "openbsd", "solaris":
				// Use -shared so that the result is
				// suitable for inclusion in a PIE or
				// shared library.
				codegenArg = "-shared"
			}
		}
		cfg.ExeSuffix = ".a"
		ldBuildmode = "c-archive"
	case "c-shared":
		pkgsFilter = oneMainPkg
		if gccgo {
			codegenArg = "-fPIC"
		} else {
			switch cfg.Goos {
			case "linux", "android", "freebsd":
				codegenArg = "-shared"
			case "windows":
				// Do not add usual .exe suffix to the .dll file.
				cfg.ExeSuffix = ""
			}
		}
		ldBuildmode = "c-shared"
	case "default":
		ldBuildmode = "exe"
		if platform.DefaultPIE(cfg.Goos, cfg.Goarch, cfg.BuildRace) {
			ldBuildmode = "pie"
			if cfg.Goos != "windows" && !gccgo {
				codegenArg = "-shared"
			}
		}
	case "exe":
		pkgsFilter = pkgsMain
		ldBuildmode = "exe"
		// Set the pkgsFilter to oneMainPkg if the user passed a specific binary output
		// and is using buildmode=exe for a better error message.
		// See issue #20017.
		if cfg.BuildO != "" {
			pkgsFilter = oneMainPkg
		}
	case "pie":
		if cfg.BuildRace && !platform.DefaultPIE(cfg.Goos, cfg.Goarch, cfg.BuildRace) {
			base.Fatalf("-buildmode=pie not supported when -race is enabled on %s/%s", cfg.Goos, cfg.Goarch)
		}
		if gccgo {
			codegenArg = "-fPIE"
		} else {
			switch cfg.Goos {
			case "aix", "windows":
			default:
				codegenArg = "-shared"
			}
		}
		ldBuildmode = "pie"
	case "shared":
		pkgsFilter = pkgsNotMain
		if gccgo {
			codegenArg = "-fPIC"
		} else {
			codegenArg = "-dynlink"
		}
		if cfg.BuildO != "" {
			base.Fatalf("-buildmode=shared and -o not supported together")
		}
		ldBuildmode = "shared"
	case "plugin":
		pkgsFilter = oneMainPkg
		if gccgo {
			codegenArg = "-fPIC"
		} else {
			codegenArg = "-dynlink"
		}
		cfg.ExeSuffix = ".so"
		ldBuildmode = "plugin"
	default:
		base.Fatalf("buildmode=%s not supported", cfg.BuildBuildmode)
	}

	if cfg.BuildBuildmode != "default" && !platform.BuildModeSupported(cfg.BuildToolchainName, cfg.BuildBuildmode, cfg.Goos, cfg.Goarch) {
		base.Fatalf("-buildmode=%s not supported on %s/%s\n", cfg.BuildBuildmode, cfg.Goos, cfg.Goarch)
	}

	if cfg.BuildLinkshared {
		if !platform.BuildModeSupported(cfg.BuildToolchainName, "shared", cfg.Goos, cfg.Goarch) {
			base.Fatalf("-linkshared not supported on %s/%s\n", cfg.Goos, cfg.Goarch)
		}
		if gccgo {
			codegenArg = "-fPIC"
		} else {
			forcedAsmflags = append(forcedAsmflags, "-D=GOBUILDMODE_shared=1",
				"-linkshared")
			codegenArg = "-dynlink"
			forcedGcflags = append(forcedGcflags, "-linkshared")
			// TODO(mwhudson): remove -w when that gets fixed in linker.
			forcedLdflags = append(forcedLdflags, "-linkshared", "-w")
		}
	}
	if codegenArg != "" {
		if gccgo {
			forcedGccgoflags = append([]string{codegenArg}, forcedGccgoflags...)
		} else {
			forcedAsmflags = append([]string{codegenArg}, forcedAsmflags...)
			forcedGcflags = append([]string{codegenArg}, forcedGcflags...)
		}
		// Don't alter InstallSuffix when modifying default codegen args.
		if cfg.BuildBuildmode != "default" || cfg.BuildLinkshared {
			if cfg.BuildContext.InstallSuffix != "" {
				cfg.BuildContext.InstallSuffix += "_"
			}
			cfg.BuildContext.InstallSuffix += codegenArg[1:]
		}
	}

	switch cfg.BuildMod {
	case "":
		// Behavior will be determined automatically, as if no flag were passed.
	case "readonly", "vendor", "mod":
		if !cfg.ModulesEnabled && !base.InGOFLAGS("-mod") {
			base.Fatalf("build flag -mod=%s only valid when using modules", cfg.BuildMod)
		}
	default:
		base.Fatalf("-mod=%s not supported (can be '', 'mod', 'readonly', or 'vendor')", cfg.BuildMod)
	}
	if !cfg.ModulesEnabled {
		if cfg.ModCacheRW && !base.InGOFLAGS("-modcacherw") {
			base.Fatalf("build flag -modcacherw only valid when using modules")
		}
		if cfg.ModFile != "" && !base.InGOFLAGS("-mod") {
			base.Fatalf("build flag -modfile only valid when using modules")
		}
	}
}

type version struct {
	name         string
	major, minor int
}

var compiler struct {
	sync.Once
	version
	err error
}

// compilerVersion detects the version of $(go env CC).
// It returns a non-nil error if the compiler matches a known version schema but
// the version could not be parsed, or if $(go env CC) could not be determined.
func compilerVersion() (version, error) {
	compiler.Once.Do(func() {
		compiler.err = func() error {
			compiler.name = "unknown"
			cc := os.Getenv("CC")
			cmd := exec.Command(cc, "--version")
			cmd.Env = append(cmd.Environ(), "LANG=C")
			out, err := cmd.Output()
			if err != nil {
				// Compiler does not support "--version" flag: not Clang or GCC.
				return err
			}

			var match [][]byte
			if bytes.HasPrefix(out, []byte("gcc")) {
				compiler.name = "gcc"
				cmd := exec.Command(cc, "-v")
				cmd.Env = append(cmd.Environ(), "LANG=C")
				out, err := cmd.CombinedOutput()
				if err != nil {
					// gcc, but does not support gcc's "-v" flag?!
					return err
				}
				gccRE := regexp.MustCompile(`gcc version (\d+)\.(\d+)`)
				match = gccRE.FindSubmatch(out)
			} else {
				clangRE := regexp.MustCompile(`clang version (\d+)\.(\d+)`)
				if match = clangRE.FindSubmatch(out); len(match) > 0 {
					compiler.name = "clang"
				}
			}

			if len(match) < 3 {
				return nil // "unknown"
			}
			if compiler.major, err = strconv.Atoi(string(match[1])); err != nil {
				return err
			}
			if compiler.minor, err = strconv.Atoi(string(match[2])); err != nil {
				return err
			}
			return nil
		}()
	})
	return compiler.version, compiler.err
}

// compilerRequiredAsanVersion is a copy of the function defined in
// cmd/cgo/internal/testsanitizers/cc_test.go
// compilerRequiredAsanVersion reports whether the compiler is the version
// required by Asan.
func compilerRequiredAsanVersion() error {
	compiler, err := compilerVersion()
	if err != nil {
		return fmt.Errorf("-asan: the version of $(go env CC) could not be parsed")
	}

	switch compiler.name {
	case "gcc":
		if runtime.GOARCH == "ppc64le" && compiler.major < 9 {
			return fmt.Errorf("-asan is not supported with %s compiler %d.%d\n", compiler.name, compiler.major, compiler.minor)
		}
		if compiler.major < 7 {
			return fmt.Errorf("-asan is not supported with %s compiler %d.%d\n", compiler.name, compiler.major, compiler.minor)
		}
	case "clang":
		if compiler.major < 9 {
			return fmt.Errorf("-asan is not supported with %s compiler %d.%d\n", compiler.name, compiler.major, compiler.minor)
		}
	default:
		return fmt.Errorf("-asan: C compiler is not gcc or clang")
	}
	return nil
}
```