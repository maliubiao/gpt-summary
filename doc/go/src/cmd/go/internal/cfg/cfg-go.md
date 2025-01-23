Response: Let's break down the thought process for analyzing the `cfg.go` file.

1. **Understand the Purpose:** The package comment at the top is the first and most crucial piece of information: "Package cfg holds configuration shared by multiple parts of the go command."  This immediately tells us the file is about *configuration management* within the `go` tool.

2. **Identify Key Data Structures:**  Scan the file for variable declarations, especially global ones. Look for `var (...)` blocks. These are the primary configuration settings.

    * `Goos`, `Goarch`, `ExeSuffix`, `ModulesEnabled`: These are fundamental environment and mode settings.
    * `installedGOOS`, `installedGOARCH`, `ToolExeSuffix`:  Related to the tools within the Go installation.
    * `BuildA`, `BuildBuildmode`, etc.:  A large set of variables prefixed with "Build". This strongly suggests they correspond to `go` command build flags.
    * `ModCacheRW`, `ModFile`:  Module-related settings.
    * `CmdName`:  Indicates the specific `go` subcommand being executed.
    * `DebugActiongraph`, `DebugTrace`, `DebugRuntimeTrace`:  Debug flags.
    * `GoPathError`, `GOPATHChanged`, `CGOChanged`: State indicators related to environment configuration.
    * `Experiment`, `ExperimentErr`, `RawGOEXPERIMENT`, `CleanGOEXPERIMENT`:  Features under development or requiring explicit enabling.
    * `OrigEnv`, `CmdEnv`:  Represent the environment in which the `go` command operates.
    * `envCache`:  A struct to cache environment variable values.
    * `GOROOT`, `GOROOTbin`, `GOROOTpkg`, `GOROOTsrc`, `GOBIN`, `GOMODCACHE`, etc.:  Standard Go environment variables.

3. **Analyze Functions:** Examine the functions defined in the file. Consider their names and parameters.

    * `exeSuffix()`: Clearly determines the executable suffix based on `Goos`.
    * `ToolExeSuffix()`: Similar to `exeSuffix()` but uses `installedGOOS`.
    * `defaultContext()`:  Sets up the default `build.Context`, overriding some defaults and handling `GOPATH`, `GOOS`, `GOARCH`, and CGO settings. This is very important for understanding how the `go` command's build environment is initialized.
    * `init()`:  Initializes `GOROOT`.
    * `SetGOROOT()`:  Allows programmatic setting of `GOROOT`, crucial for testing and potentially internal tooling.
    * `initEnvCache()`, `readEnvFile()`, `EnvFile()`: Functions related to loading environment variables from the OS and the `go/env` file.
    * `Getenv()`:  Retrieves the value of a configuration key, prioritizing OS environment and then the `go/env` file.
    * `CanGetenv()`: Checks if a key is a valid `go/env` setting.
    * `EnvOrAndChanged()`:  Gets an environment variable value and indicates if it differs from the default.
    * `GetArchEnv()`:  Returns the relevant architecture-specific environment variable.
    * `envOr()`:  Returns the environment variable or a default value.
    * `findGOROOT()`, `isSameDir()`, `isGOROOT()`:  Logic for determining the Go installation root directory. These are utility functions.
    * `gopath()`, `gopathDir()`:  Functions related to calculating GOPATH-related paths.
    * `WithBuildXWriter()`, `BuildXWriter()`:  Manage a context for writing `-x` (command execution tracing) output.
    * `dirInfo`:  A helper struct implementing `fs.FileInfo` from `fs.DirEntry`.

4. **Identify Relationships and Interactions:** Think about how the different variables and functions relate to each other.

    * The "Build" variables are clearly tied to command-line flags.
    * `defaultContext()` uses environment variables (through `EnvOrAndChanged` and direct calls to `os.Getenv`) to initialize the build context.
    * `initEnvCache` and `Getenv` work together to manage the layered environment variable settings.
    * `SetGOROOT` affects the paths used to find tools and packages.

5. **Infer Functionality:** Based on the identified data structures and functions, start inferring the high-level functionality of the file.

    * **Configuration Loading:** Reads environment variables from the OS and a configuration file (`go/env`).
    * **Build Context Setup:** Initializes the `build.Context` with appropriate settings, considering OS, architecture, and environment variables.
    * **Command-Line Flag Handling:**  Stores the values of various `go` command flags.
    * **Path Management:**  Defines and manages important paths like `GOROOT`, `GOBIN`, and `GOMODCACHE`.
    * **Experiment Management:** Handles enabling and tracking experimental features.
    * **Environment Manipulation:** Provides ways to access and potentially modify the environment in which `go` tools are executed.

6. **Connect to Go Features (Infer and Provide Examples):**  Think about how the configuration managed by this file relates to the user-facing features of the `go` command.

    * **`go build`:** The `Build...` variables directly map to flags of the `go build` command.
    * **Modules:** `ModulesEnabled`, `GOMODCACHE`, `GOPROXY`, etc., are crucial for Go modules functionality.
    * **`go env`:** The functions related to reading and managing environment variables underpin the `go env` command.
    * **Cross-compilation:** The handling of `GOOS` and `GOARCH`, along with `installedGOOS` and `installedGOARCH`, is essential for cross-compilation.
    * **CGO:** The logic for determining and enabling CGO is present.
    * **Debugging:** `BuildX`, `DebugTrace`, etc., relate to debugging capabilities.
    * **GOROOT and GOPATH:** The code explicitly manages these fundamental Go environment variables.

7. **Identify Potential Pitfalls:** Consider common errors users might make when interacting with these configurations.

    * **Incorrect GOROOT/GOPATH:** Directly related to the `gopath()` and `findGOROOT()` logic.
    * **Conflicting Environment Variables:**  Mentioning how environment variables override defaults.
    * **Misunderstanding Module vs. GOPATH mode:**  Relating to `ModulesEnabled`.
    * **Incorrect use of build flags:**  Highlighting the connection between `Build...` variables and command-line flags.

8. **Structure the Output:** Organize the findings logically, starting with the main purpose and then drilling down into details. Use clear headings and examples.

This structured approach allows for a comprehensive understanding of the `cfg.go` file and its role within the `go` command. It involves understanding the code itself, inferring its purpose, and connecting it to the larger Go ecosystem.
这个 `cfg.go` 文件是 Go 语言 `cmd/go` 工具的核心组成部分，它负责管理和维护 Go 命令在执行过程中所需的各种配置信息。简单来说，它的主要功能是 **管理 `go` 命令的全局配置**。

以下是该文件列举的功能和更详细的说明：

**1. 存储和管理全局构建参数 (Global build parameters):**

   - **操作系统和架构 (`Goos`, `Goarch`):**  存储目标操作系统的名称和架构，默认为当前系统的操作系统和架构，可以通过环境变量 `GOOS` 和 `GOARCH` 覆盖。
   - **可执行文件后缀 (`ExeSuffix`):**  根据目标操作系统确定可执行文件的后缀名（例如 Windows 下是 `.exe`）。
   - **模块模式开关 (`ModulesEnabled`):**  指示 `go` 命令是否以模块感知模式运行。

   **代码示例:**

   ```go
   package main

   import (
       "fmt"
       "cmd/go/internal/cfg"
   )

   func main() {
       fmt.Println("Target OS:", cfg.Goos)
       fmt.Println("Target Arch:", cfg.Goarch)
       fmt.Println("Executable Suffix:", cfg.ExeSuffix)
       fmt.Println("Modules Enabled:", cfg.ModulesEnabled)
   }
   ```

   **假设输入与输出:** 如果在 Linux 系统上运行，且未设置 `GOOS` 和 `GOARCH` 环境变量，则输出可能如下：

   ```
   Target OS: linux
   Target Arch: amd64
   Executable Suffix:
   Modules Enabled: true
   ```

**2. 存储和管理工具链配置 (Configuration for tools installed to GOROOT/bin):**

   - **已安装的操作系统和架构 (`installedGOOS`, `installedGOARCH`):**  表示 Go 工具链安装时的操作系统和架构。这通常与 `runtime.GOOS` 和 `runtime.GOARCH` 相同，但在交叉编译 `cmd/go` 进行测试时可能会不同。
   - **工具可执行文件后缀 (`ToolExeSuffix`):**  根据已安装的操作系统确定工具链中可执行文件的后缀名。

   **代码推理:**  这些变量的存在是为了支持测试交叉编译的 `cmd/go` 工具。例如，当在一个 Linux 系统上测试为 Windows 构建的 `cmd/go` 时，`installedGOOS` 会是 `windows`，而 `runtime.GOOS` 仍然是 `linux`。

**3. 存储和管理构建标志 (General "build flags"):**

   这里列出了一系列以 `Build` 开头的变量，它们对应于 `go build`, `go install` 等命令的各种命令行标志。

   - **`-a` (`BuildA`):** 强制重新构建所有依赖包。
   - **`-buildmode` (`BuildBuildmode`):** 设置要构建的输出类型 (例如 `default`, `c-shared`, `plugin`)。
   - **`-buildvcs` (`BuildBuildvcs`):**  控制是否将版本控制信息嵌入到二进制文件中。
   - **`-mod` (`BuildMod`):**  控制是否允许更新 `go.mod` 文件。
   - **`-o` (`BuildO`):**  指定输出文件的名称。
   - **`-p` (`BuildP`):**  并行构建使用的 CPU 核心数。
   - **`-race` (`BuildRace`):**  启用数据竞争检测器。
   - **`-v` (`BuildV`):**  显示被编译的包的名称。
   - **`-work` (`BuildWork`):**  在构建后保留临时工作目录。
   - **`-x` (`BuildX`):**  打印执行的外部命令。

   **命令行参数处理示例:**

   当用户执行 `go build -o myapp main.go` 命令时：

   - `CmdName` 将被设置为 `"build"`。
   - `BuildO` 将被设置为 `"myapp"`。

   当用户执行 `go build -race main.go` 命令时：

   - `CmdName` 将被设置为 `"build"`。
   - `BuildRace` 将被设置为 `true`。

**4. 存储和管理模块相关的配置 (Module related configuration):**

   - **`-modcacherw` (`ModCacheRW`):**  允许读写模块缓存。
   - **`-modfile` (`ModFile`):**  指定一个备用的 `go.mod` 文件路径。

**5. 存储当前执行的命令名称 (`CmdName`):**

   - 用于标识当前正在执行的 `go` 命令 (例如 "build", "install", "list", "mod tidy")。

**6. 存储调试标志 (Debug flags):**

   - 一些用于调试 `go` 命令自身的标志，通常是非公开的或不稳定的。

**7. 存储与 `GOPATH` 相关的错误信息 (`GoPathError`, `GOPATHChanged`, `CGOChanged`):**

   - `GoPathError`:  当 `GOPATH` 未设置时，存储解释原因的错误消息。
   - `GOPATHChanged`:  指示 `GOPATH` 是否与默认值不同。
   - `CGOChanged`: 指示 CGO 是否被显式启用或禁用。

**8. 提供默认的 `build.Context` (`BuildContext`):**

   -  这是 `go/build` 包中用于配置构建过程的核心结构。`defaultContext()` 函数会初始化这个结构，包括设置 `GOPATH`, `GOOS`, `GOARCH`, 以及 CGO 的启用状态等。

**9. 管理 `GOROOT` 和其他相关路径:**

   - `GOROOT`: Go 安装根目录。
   - `GOROOTbin`, `GOROOTpkg`, `GOROOTsrc`:  `GOROOT` 下的 `bin`, `pkg`, `src` 目录。
   - `GOBIN`: 用户自定义的存放可执行文件的目录。
   - `GOMODCACHE`: 模块缓存目录。

**10. 管理实验性功能 (`Experiment`):**

    - `RawGOEXPERIMENT`: 用户设置的 `GOEXPERIMENT` 环境变量的值。
    - `CleanGOEXPERIMENT`:  规范化后的 `GOEXPERIMENT` 值。
    - `Experiment`:  解析后的实验性功能配置。

**11. 管理环境变量 (`OrigEnv`, `CmdEnv`):**

    - `OrigEnv`:  程序启动时的原始环境变量。
    - `CmdEnv`:  用于运行 `go tool` 命令的新环境变量。用户程序在 `go test` 或 `go run` 中会使用 `OrigEnv`。

**12. 读取和管理 `go/env` 配置文件:**

    - 提供函数 (`EnvFile`, `initEnvCache`, `readEnvFile`, `Getenv`, `CanGetenv`) 来读取和访问用户级别的 Go 环境变量配置，这些配置存储在 `$HOME/.config/go/env` (或相应的平台特定路径) 文件中。

**13. 获取特定架构的环境变量 (`GetArchEnv`):**

    -  例如，对于 `GOARCH=arm`，会返回 `GOARM` 及其当前值。

**14. 提供辅助函数:**

    - `envOr`:  如果环境变量已设置则返回其值，否则返回默认值。
    - `findGOROOT`, `isSameDir`, `isGOROOT`:  用于查找和验证 `GOROOT` 路径。
    - `gopath`, `gopathDir`:  用于处理 `GOPATH` 相关的路径。
    - `WithBuildXWriter`, `BuildXWriter`:  用于管理 `-x` 标志的输出流。

**使用者易犯错的点举例:**

1. **误解 `GOROOT` 和 `GOPATH` 的作用:**  新手容易混淆 `GOROOT` (Go 安装目录，不应轻易修改) 和 `GOPATH` (用户工作空间，用于存放项目代码和依赖)。

   **错误示例:**  尝试将项目代码放在 `GOROOT/src` 下。

2. **忘记设置或设置错误的 `GOPATH`:**  在 GOPATH 模式下，没有正确设置 `GOPATH` 会导致 `go` 命令找不到依赖包。

   **错误示例:**  在终端执行 `go get` 命令时出现 "cannot find package ..." 的错误，原因是没有设置 `GOPATH` 或设置的路径不正确。

3. **在模块模式下仍然依赖 `GOPATH` 结构:**  在启用了模块模式后，项目的组织结构不再严格依赖 `GOPATH`，但一些用户可能仍然按照 `GOPATH` 的方式组织代码，导致不必要的困扰。

4. **不理解环境变量的优先级:** 用户可能不清楚操作系统环境变量、`go/env` 文件配置以及命令行标志之间的优先级关系，导致配置与预期不符。 例如，环境变量会覆盖 `go/env` 中的设置，而命令行标志又会覆盖环境变量。

总而言之，`cfg.go` 文件是 `go` 命令的核心配置中心，它负责加载、存储和管理各种影响 `go` 命令行为的设置，是理解 `go` 命令工作原理的关键部分。

### 提示词
```
这是路径为go/src/cmd/go/internal/cfg/cfg.go的go语言实现的一部分， 请列举一下它的功能, 　
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

// Package cfg holds configuration shared by multiple parts
// of the go command.
package cfg

import (
	"bytes"
	"context"
	"fmt"
	"go/build"
	"internal/buildcfg"
	"internal/cfg"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"cmd/go/internal/fsys"
	"cmd/internal/pathcache"
)

// Global build parameters (used during package load)
var (
	Goos   = envOr("GOOS", build.Default.GOOS)
	Goarch = envOr("GOARCH", build.Default.GOARCH)

	ExeSuffix = exeSuffix()

	// ModulesEnabled specifies whether the go command is running
	// in module-aware mode (as opposed to GOPATH mode).
	// It is equal to modload.Enabled, but not all packages can import modload.
	ModulesEnabled bool
)

func exeSuffix() string {
	if Goos == "windows" {
		return ".exe"
	}
	return ""
}

// Configuration for tools installed to GOROOT/bin.
// Normally these match runtime.GOOS and runtime.GOARCH,
// but when testing a cross-compiled cmd/go they will
// indicate the GOOS and GOARCH of the installed cmd/go
// rather than the test binary.
var (
	installedGOOS   string
	installedGOARCH string
)

// ToolExeSuffix returns the suffix for executables installed
// in build.ToolDir.
func ToolExeSuffix() string {
	if installedGOOS == "windows" {
		return ".exe"
	}
	return ""
}

// These are general "build flags" used by build and other commands.
var (
	BuildA                 bool     // -a flag
	BuildBuildmode         string   // -buildmode flag
	BuildBuildvcs          = "auto" // -buildvcs flag: "true", "false", or "auto"
	BuildContext           = defaultContext()
	BuildMod               string                  // -mod flag
	BuildModExplicit       bool                    // whether -mod was set explicitly
	BuildModReason         string                  // reason -mod was set, if set by default
	BuildLinkshared        bool                    // -linkshared flag
	BuildMSan              bool                    // -msan flag
	BuildASan              bool                    // -asan flag
	BuildCover             bool                    // -cover flag
	BuildCoverMode         string                  // -covermode flag
	BuildCoverPkg          []string                // -coverpkg flag
	BuildJSON              bool                    // -json flag
	BuildN                 bool                    // -n flag
	BuildO                 string                  // -o flag
	BuildP                 = runtime.GOMAXPROCS(0) // -p flag
	BuildPGO               string                  // -pgo flag
	BuildPkgdir            string                  // -pkgdir flag
	BuildRace              bool                    // -race flag
	BuildToolexec          []string                // -toolexec flag
	BuildToolchainName     string
	BuildToolchainCompiler func() string
	BuildToolchainLinker   func() string
	BuildTrimpath          bool // -trimpath flag
	BuildV                 bool // -v flag
	BuildWork              bool // -work flag
	BuildX                 bool // -x flag

	ModCacheRW bool   // -modcacherw flag
	ModFile    string // -modfile flag

	CmdName string // "build", "install", "list", "mod tidy", etc.

	DebugActiongraph  string // -debug-actiongraph flag (undocumented, unstable)
	DebugTrace        string // -debug-trace flag
	DebugRuntimeTrace string // -debug-runtime-trace flag (undocumented, unstable)

	// GoPathError is set when GOPATH is not set. it contains an
	// explanation why GOPATH is unset.
	GoPathError   string
	GOPATHChanged bool
	CGOChanged    bool
)

func defaultContext() build.Context {
	ctxt := build.Default

	ctxt.JoinPath = filepath.Join // back door to say "do not use go command"

	// Override defaults computed in go/build with defaults
	// from go environment configuration file, if known.
	ctxt.GOPATH, GOPATHChanged = EnvOrAndChanged("GOPATH", gopath(ctxt))
	ctxt.GOOS = Goos
	ctxt.GOARCH = Goarch

	// Clear the GOEXPERIMENT-based tool tags, which we will recompute later.
	var save []string
	for _, tag := range ctxt.ToolTags {
		if !strings.HasPrefix(tag, "goexperiment.") {
			save = append(save, tag)
		}
	}
	ctxt.ToolTags = save

	// The go/build rule for whether cgo is enabled is:
	//  1. If $CGO_ENABLED is set, respect it.
	//  2. Otherwise, if this is a cross-compile, disable cgo.
	//  3. Otherwise, use built-in default for GOOS/GOARCH.
	//
	// Recreate that logic here with the new GOOS/GOARCH setting.
	// We need to run steps 2 and 3 to determine what the default value
	// of CgoEnabled would be for computing CGOChanged.
	defaultCgoEnabled := ctxt.CgoEnabled
	if ctxt.GOOS != runtime.GOOS || ctxt.GOARCH != runtime.GOARCH {
		defaultCgoEnabled = false
	} else {
		// Use built-in default cgo setting for GOOS/GOARCH.
		// Note that ctxt.GOOS/GOARCH are derived from the preference list
		// (1) environment, (2) go/env file, (3) runtime constants,
		// while go/build.Default.GOOS/GOARCH are derived from the preference list
		// (1) environment, (2) runtime constants.
		//
		// We know ctxt.GOOS/GOARCH == runtime.GOOS/GOARCH;
		// no matter how that happened, go/build.Default will make the
		// same decision (either the environment variables are set explicitly
		// to match the runtime constants, or else they are unset, in which
		// case go/build falls back to the runtime constants), so
		// go/build.Default.GOOS/GOARCH == runtime.GOOS/GOARCH.
		// So ctxt.CgoEnabled (== go/build.Default.CgoEnabled) is correct
		// as is and can be left unmodified.
		//
		// All that said, starting in Go 1.20 we layer one more rule
		// on top of the go/build decision: if CC is unset and
		// the default C compiler we'd look for is not in the PATH,
		// we automatically default cgo to off.
		// This makes go builds work automatically on systems
		// without a C compiler installed.
		if ctxt.CgoEnabled {
			if os.Getenv("CC") == "" {
				cc := DefaultCC(ctxt.GOOS, ctxt.GOARCH)
				if _, err := pathcache.LookPath(cc); err != nil {
					defaultCgoEnabled = false
				}
			}
		}
	}
	ctxt.CgoEnabled = defaultCgoEnabled
	if v := Getenv("CGO_ENABLED"); v == "0" || v == "1" {
		ctxt.CgoEnabled = v[0] == '1'
	}
	CGOChanged = ctxt.CgoEnabled != defaultCgoEnabled

	ctxt.OpenFile = func(path string) (io.ReadCloser, error) {
		return fsys.Open(path)
	}
	ctxt.ReadDir = func(path string) ([]fs.FileInfo, error) {
		// Convert []fs.DirEntry to []fs.FileInfo using dirInfo.
		dirs, err := fsys.ReadDir(path)
		infos := make([]fs.FileInfo, len(dirs))
		for i, dir := range dirs {
			infos[i] = &dirInfo{dir}
		}
		return infos, err
	}
	ctxt.IsDir = func(path string) bool {
		isDir, err := fsys.IsDir(path)
		return err == nil && isDir
	}

	return ctxt
}

func init() {
	SetGOROOT(Getenv("GOROOT"), false)
}

// SetGOROOT sets GOROOT and associated variables to the given values.
//
// If isTestGo is true, build.ToolDir is set based on the TESTGO_GOHOSTOS and
// TESTGO_GOHOSTARCH environment variables instead of runtime.GOOS and
// runtime.GOARCH.
func SetGOROOT(goroot string, isTestGo bool) {
	BuildContext.GOROOT = goroot

	GOROOT = goroot
	if goroot == "" {
		GOROOTbin = ""
		GOROOTpkg = ""
		GOROOTsrc = ""
	} else {
		GOROOTbin = filepath.Join(goroot, "bin")
		GOROOTpkg = filepath.Join(goroot, "pkg")
		GOROOTsrc = filepath.Join(goroot, "src")
	}

	installedGOOS = runtime.GOOS
	installedGOARCH = runtime.GOARCH
	if isTestGo {
		if testOS := os.Getenv("TESTGO_GOHOSTOS"); testOS != "" {
			installedGOOS = testOS
		}
		if testArch := os.Getenv("TESTGO_GOHOSTARCH"); testArch != "" {
			installedGOARCH = testArch
		}
	}

	if runtime.Compiler != "gccgo" {
		if goroot == "" {
			build.ToolDir = ""
		} else {
			// Note that we must use the installed OS and arch here: the tool
			// directory does not move based on environment variables, and even if we
			// are testing a cross-compiled cmd/go all of the installed packages and
			// tools would have been built using the native compiler and linker (and
			// would spuriously appear stale if we used a cross-compiled compiler and
			// linker).
			//
			// This matches the initialization of ToolDir in go/build, except for
			// using ctxt.GOROOT and the installed GOOS and GOARCH rather than the
			// GOROOT, GOOS, and GOARCH reported by the runtime package.
			build.ToolDir = filepath.Join(GOROOTpkg, "tool", installedGOOS+"_"+installedGOARCH)
		}
	}
}

// Experiment configuration.
var (
	// RawGOEXPERIMENT is the GOEXPERIMENT value set by the user.
	RawGOEXPERIMENT = envOr("GOEXPERIMENT", buildcfg.DefaultGOEXPERIMENT)
	// CleanGOEXPERIMENT is the minimal GOEXPERIMENT value needed to reproduce the
	// experiments enabled by RawGOEXPERIMENT.
	CleanGOEXPERIMENT = RawGOEXPERIMENT

	Experiment    *buildcfg.ExperimentFlags
	ExperimentErr error
)

func init() {
	Experiment, ExperimentErr = buildcfg.ParseGOEXPERIMENT(Goos, Goarch, RawGOEXPERIMENT)
	if ExperimentErr != nil {
		return
	}

	// GOEXPERIMENT is valid, so convert it to canonical form.
	CleanGOEXPERIMENT = Experiment.String()

	// Add build tags based on the experiments in effect.
	exps := Experiment.Enabled()
	expTags := make([]string, 0, len(exps)+len(BuildContext.ToolTags))
	for _, exp := range exps {
		expTags = append(expTags, "goexperiment."+exp)
	}
	BuildContext.ToolTags = append(expTags, BuildContext.ToolTags...)
}

// An EnvVar is an environment variable Name=Value.
type EnvVar struct {
	Name    string
	Value   string
	Changed bool // effective Value differs from default
}

// OrigEnv is the original environment of the program at startup.
var OrigEnv []string

// CmdEnv is the new environment for running go tool commands.
// User binaries (during go test or go run) are run with OrigEnv,
// not CmdEnv.
var CmdEnv []EnvVar

var envCache struct {
	once   sync.Once
	m      map[string]string
	goroot map[string]string
}

// EnvFile returns the name of the Go environment configuration file,
// and reports whether the effective value differs from the default.
func EnvFile() (string, bool, error) {
	if file := os.Getenv("GOENV"); file != "" {
		if file == "off" {
			return "", false, fmt.Errorf("GOENV=off")
		}
		return file, true, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", false, err
	}
	if dir == "" {
		return "", false, fmt.Errorf("missing user-config dir")
	}
	return filepath.Join(dir, "go/env"), false, nil
}

func initEnvCache() {
	envCache.m = make(map[string]string)
	envCache.goroot = make(map[string]string)
	if file, _, _ := EnvFile(); file != "" {
		readEnvFile(file, "user")
	}
	goroot := findGOROOT(envCache.m["GOROOT"])
	if goroot != "" {
		readEnvFile(filepath.Join(goroot, "go.env"), "GOROOT")
	}

	// Save the goroot for func init calling SetGOROOT,
	// and also overwrite anything that might have been in go.env.
	// It makes no sense for GOROOT/go.env to specify
	// a different GOROOT.
	envCache.m["GOROOT"] = goroot
}

func readEnvFile(file string, source string) {
	if file == "" {
		return
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return
	}

	for len(data) > 0 {
		// Get next line.
		line := data
		i := bytes.IndexByte(data, '\n')
		if i >= 0 {
			line, data = line[:i], data[i+1:]
		} else {
			data = nil
		}

		i = bytes.IndexByte(line, '=')
		if i < 0 || line[0] < 'A' || 'Z' < line[0] {
			// Line is missing = (or empty) or a comment or not a valid env name. Ignore.
			// This should not happen in the user file, since the file should be maintained almost
			// exclusively by "go env -w", but better to silently ignore than to make
			// the go command unusable just because somehow the env file has
			// gotten corrupted.
			// In the GOROOT/go.env file, we expect comments.
			continue
		}
		key, val := line[:i], line[i+1:]

		if source == "GOROOT" {
			envCache.goroot[string(key)] = string(val)
			// In the GOROOT/go.env file, do not overwrite fields loaded from the user's go/env file.
			if _, ok := envCache.m[string(key)]; ok {
				continue
			}
		}
		envCache.m[string(key)] = string(val)
	}
}

// Getenv gets the value for the configuration key.
// It consults the operating system environment
// and then the go/env file.
// If Getenv is called for a key that cannot be set
// in the go/env file (for example GODEBUG), it panics.
// This ensures that CanGetenv is accurate, so that
// 'go env -w' stays in sync with what Getenv can retrieve.
func Getenv(key string) string {
	if !CanGetenv(key) {
		switch key {
		case "CGO_TEST_ALLOW", "CGO_TEST_DISALLOW", "CGO_test_ALLOW", "CGO_test_DISALLOW":
			// used by internal/work/security_test.go; allow
		default:
			panic("internal error: invalid Getenv " + key)
		}
	}
	val := os.Getenv(key)
	if val != "" {
		return val
	}
	envCache.once.Do(initEnvCache)
	return envCache.m[key]
}

// CanGetenv reports whether key is a valid go/env configuration key.
func CanGetenv(key string) bool {
	envCache.once.Do(initEnvCache)
	if _, ok := envCache.m[key]; ok {
		// Assume anything in the user file or go.env file is valid.
		return true
	}
	return strings.Contains(cfg.KnownEnv, "\t"+key+"\n")
}

var (
	GOROOT string

	// Either empty or produced by filepath.Join(GOROOT, …).
	GOROOTbin string
	GOROOTpkg string
	GOROOTsrc string

	GOBIN                         = Getenv("GOBIN")
	GOMODCACHE, GOMODCACHEChanged = EnvOrAndChanged("GOMODCACHE", gopathDir("pkg/mod"))

	// Used in envcmd.MkEnv and build ID computations.
	GOARM64, goARM64Changed     = EnvOrAndChanged("GOARM64", buildcfg.DefaultGOARM64)
	GOARM, goARMChanged         = EnvOrAndChanged("GOARM", buildcfg.DefaultGOARM)
	GO386, go386Changed         = EnvOrAndChanged("GO386", buildcfg.DefaultGO386)
	GOAMD64, goAMD64Changed     = EnvOrAndChanged("GOAMD64", buildcfg.DefaultGOAMD64)
	GOMIPS, goMIPSChanged       = EnvOrAndChanged("GOMIPS", buildcfg.DefaultGOMIPS)
	GOMIPS64, goMIPS64Changed   = EnvOrAndChanged("GOMIPS64", buildcfg.DefaultGOMIPS64)
	GOPPC64, goPPC64Changed     = EnvOrAndChanged("GOPPC64", buildcfg.DefaultGOPPC64)
	GORISCV64, goRISCV64Changed = EnvOrAndChanged("GORISCV64", buildcfg.DefaultGORISCV64)
	GOWASM, goWASMChanged       = EnvOrAndChanged("GOWASM", fmt.Sprint(buildcfg.GOWASM))

	GOFIPS140, GOFIPS140Changed = EnvOrAndChanged("GOFIPS140", buildcfg.DefaultGOFIPS140)
	GOPROXY, GOPROXYChanged     = EnvOrAndChanged("GOPROXY", "")
	GOSUMDB, GOSUMDBChanged     = EnvOrAndChanged("GOSUMDB", "")
	GOPRIVATE                   = Getenv("GOPRIVATE")
	GONOPROXY, GONOPROXYChanged = EnvOrAndChanged("GONOPROXY", GOPRIVATE)
	GONOSUMDB, GONOSUMDBChanged = EnvOrAndChanged("GONOSUMDB", GOPRIVATE)
	GOINSECURE                  = Getenv("GOINSECURE")
	GOVCS                       = Getenv("GOVCS")
	GOAUTH, GOAUTHChanged       = EnvOrAndChanged("GOAUTH", "netrc")
)

// EnvOrAndChanged returns the environment variable value
// and reports whether it differs from the default value.
func EnvOrAndChanged(name, def string) (v string, changed bool) {
	val := Getenv(name)
	if val != "" {
		v = val
		if g, ok := envCache.goroot[name]; ok {
			changed = val != g
		} else {
			changed = val != def
		}
		return v, changed
	}
	return def, false
}

var SumdbDir = gopathDir("pkg/sumdb")

// GetArchEnv returns the name and setting of the
// GOARCH-specific architecture environment variable.
// If the current architecture has no GOARCH-specific variable,
// GetArchEnv returns empty key and value.
func GetArchEnv() (key, val string, changed bool) {
	switch Goarch {
	case "arm":
		return "GOARM", GOARM, goARMChanged
	case "arm64":
		return "GOARM64", GOARM64, goARM64Changed
	case "386":
		return "GO386", GO386, go386Changed
	case "amd64":
		return "GOAMD64", GOAMD64, goAMD64Changed
	case "mips", "mipsle":
		return "GOMIPS", GOMIPS, goMIPSChanged
	case "mips64", "mips64le":
		return "GOMIPS64", GOMIPS64, goMIPS64Changed
	case "ppc64", "ppc64le":
		return "GOPPC64", GOPPC64, goPPC64Changed
	case "riscv64":
		return "GORISCV64", GORISCV64, goRISCV64Changed
	case "wasm":
		return "GOWASM", GOWASM, goWASMChanged
	}
	return "", "", false
}

// envOr returns Getenv(key) if set, or else def.
func envOr(key, def string) string {
	val := Getenv(key)
	if val == "" {
		val = def
	}
	return val
}

// There is a copy of findGOROOT, isSameDir, and isGOROOT in
// x/tools/cmd/godoc/goroot.go.
// Try to keep them in sync for now.

// findGOROOT returns the GOROOT value, using either an explicitly
// provided environment variable, a GOROOT that contains the current
// os.Executable value, or else the GOROOT that the binary was built
// with from runtime.GOROOT().
//
// There is a copy of this code in x/tools/cmd/godoc/goroot.go.
func findGOROOT(env string) string {
	if env == "" {
		// Not using Getenv because findGOROOT is called
		// to find the GOROOT/go.env file. initEnvCache
		// has passed in the setting from the user go/env file.
		env = os.Getenv("GOROOT")
	}
	if env != "" {
		return filepath.Clean(env)
	}
	def := ""
	if r := runtime.GOROOT(); r != "" {
		def = filepath.Clean(r)
	}
	if runtime.Compiler == "gccgo" {
		// gccgo has no real GOROOT, and it certainly doesn't
		// depend on the executable's location.
		return def
	}

	// canonical returns a directory path that represents
	// the same directory as dir,
	// preferring the spelling in def if the two are the same.
	canonical := func(dir string) string {
		if isSameDir(def, dir) {
			return def
		}
		return dir
	}

	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.Abs(exe)
		if err == nil {
			// cmd/go may be installed in GOROOT/bin or GOROOT/bin/GOOS_GOARCH,
			// depending on whether it was cross-compiled with a different
			// GOHOSTOS (see https://go.dev/issue/62119). Try both.
			if dir := filepath.Join(exe, "../.."); isGOROOT(dir) {
				return canonical(dir)
			}
			if dir := filepath.Join(exe, "../../.."); isGOROOT(dir) {
				return canonical(dir)
			}

			// Depending on what was passed on the command line, it is possible
			// that os.Executable is a symlink (like /usr/local/bin/go) referring
			// to a binary installed in a real GOROOT elsewhere
			// (like /usr/lib/go/bin/go).
			// Try to find that GOROOT by resolving the symlinks.
			exe, err = filepath.EvalSymlinks(exe)
			if err == nil {
				if dir := filepath.Join(exe, "../.."); isGOROOT(dir) {
					return canonical(dir)
				}
				if dir := filepath.Join(exe, "../../.."); isGOROOT(dir) {
					return canonical(dir)
				}
			}
		}
	}
	return def
}

// isSameDir reports whether dir1 and dir2 are the same directory.
func isSameDir(dir1, dir2 string) bool {
	if dir1 == dir2 {
		return true
	}
	info1, err1 := os.Stat(dir1)
	info2, err2 := os.Stat(dir2)
	return err1 == nil && err2 == nil && os.SameFile(info1, info2)
}

// isGOROOT reports whether path looks like a GOROOT.
//
// It does this by looking for the path/pkg/tool directory,
// which is necessary for useful operation of the cmd/go tool,
// and is not typically present in a GOPATH.
//
// There is a copy of this code in x/tools/cmd/godoc/goroot.go.
func isGOROOT(path string) bool {
	stat, err := os.Stat(filepath.Join(path, "pkg", "tool"))
	if err != nil {
		return false
	}
	return stat.IsDir()
}

func gopathDir(rel string) string {
	list := filepath.SplitList(BuildContext.GOPATH)
	if len(list) == 0 || list[0] == "" {
		return ""
	}
	return filepath.Join(list[0], rel)
}

// Keep consistent with go/build.defaultGOPATH.
func gopath(ctxt build.Context) string {
	if len(ctxt.GOPATH) > 0 {
		return ctxt.GOPATH
	}
	env := "HOME"
	if runtime.GOOS == "windows" {
		env = "USERPROFILE"
	} else if runtime.GOOS == "plan9" {
		env = "home"
	}
	if home := os.Getenv(env); home != "" {
		def := filepath.Join(home, "go")
		if filepath.Clean(def) == filepath.Clean(runtime.GOROOT()) {
			GoPathError = "cannot set GOROOT as GOPATH"
		}
		return ""
	}
	GoPathError = fmt.Sprintf("%s is not set", env)
	return ""
}

// WithBuildXWriter returns a Context in which BuildX output is written
// to given io.Writer.
func WithBuildXWriter(ctx context.Context, xLog io.Writer) context.Context {
	return context.WithValue(ctx, buildXContextKey{}, xLog)
}

type buildXContextKey struct{}

// BuildXWriter returns nil if BuildX is false, or
// the writer to which BuildX output should be written otherwise.
func BuildXWriter(ctx context.Context) (io.Writer, bool) {
	if !BuildX {
		return nil, false
	}
	if v := ctx.Value(buildXContextKey{}); v != nil {
		return v.(io.Writer), true
	}
	return os.Stderr, true
}

// A dirInfo implements fs.FileInfo from fs.DirEntry.
// We know that go/build doesn't use the non-DirEntry parts,
// so we can panic instead of doing difficult work.
type dirInfo struct {
	dir fs.DirEntry
}

func (d *dirInfo) Name() string      { return d.dir.Name() }
func (d *dirInfo) IsDir() bool       { return d.dir.IsDir() }
func (d *dirInfo) Mode() fs.FileMode { return d.dir.Type() }

func (d *dirInfo) Size() int64        { panic("dirInfo.Size") }
func (d *dirInfo) ModTime() time.Time { panic("dirInfo.ModTime") }
func (d *dirInfo) Sys() any           { panic("dirInfo.Sys") }
```