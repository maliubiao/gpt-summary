Response: Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The initial request asks for the functionality of the `select.go` file within the `cmd/go/internal/toolchain` package. The prompt specifically mentions Go toolchain switching. This is the core focus.

2. **Identify Key Functions and Data Structures:**  A quick scan reveals the primary function `Select()`. Other interesting elements include:
    * Constants like `gotoolchainModule`, `gotoolchainVersion`, `targetEnv`, `countEnv`, `maxSwitch`. These hint at the mechanism of toolchain management.
    * The `FilterEnv()` function, suggesting environment variable manipulation.
    * Global variables like `counterErrorsInvalidToolchainInFile` and `toolchainTrace`, indicating metrics and debugging features.
    * The `Exec()` function, likely responsible for the actual execution of a different toolchain.
    * `TestVersionSwitch`, a clear indicator of testing infrastructure.
    * Helper functions like `raceSafeCopy`, `modGoToolchain`, and `goInstallVersion`.

3. **Analyze `Select()` in Detail:** This is the entry point, so understanding its flow is crucial. Here's a step-by-step analysis:
    * **Early Exits:** The function starts with checks for `modload.WillBeEnabled()` and specific `go env` commands. This suggests certain operations should bypass toolchain switching.
    * **GOTOOLCHAIN Interpretation:**  The code reads the `GOTOOLCHAIN` environment variable and parses it for different modes ("auto", "path", explicit versions). This is central to the toolchain selection logic.
    * **"auto" and "path" Modes:** The code checks for these modes and calls `modGoToolchain()`. This implies that `go.mod` or `go.work` files can influence toolchain selection.
    * **Target Toolchain Check (`targetEnv`):**  The code checks for `targetEnv`. This variable seems to be used to verify that a child process invoked for a specific toolchain is indeed the correct one.
    * **Local Toolchain Check:** If the determined toolchain is "local" or matches the current one, the function returns.
    * **Toolchain Execution (`Exec()`):**  If a different toolchain is required, the `Exec()` function is called.

4. **Analyze `Exec()` in Detail:** This function handles the actual execution of a selected toolchain.
    * **Loop Detection:** The `countEnv` variable and `maxSwitch` constant suggest a mechanism to prevent infinite toolchain switching loops.
    * **Testing Hooks (`TestVersionSwitch`):**  The code checks `TestVersionSwitch` for testing scenarios.
    * **PATH Lookup:** The code searches the `PATH` for the specified toolchain.
    * **Downloading Toolchains:** If the toolchain isn't in the `PATH` (and `pathOnly` is not set), the code downloads it as a module. This involves `modload` and `modfetch`.
    * **Setting Execute Bits:** For non-Windows systems, the code sets execute permissions on the downloaded toolchain binaries.
    * **Copying `_go.mod` to `go.mod`:**  The code handles a potential race condition when multiple Go commands are downloading the same toolchain.
    * **Reinvocation:**  Finally, `execGoToolchain()` is called to execute the downloaded toolchain.

5. **Analyze Helper Functions:**
    * **`FilterEnv()`:** Removes internal `GOTOOLCHAIN` related environment variables.
    * **`raceSafeCopy()`:**  Safely copies files in a concurrent environment, crucial for the module cache.
    * **`modGoToolchain()`:** Reads `go.mod` or `go.work` to get the `go` and `toolchain` directives.
    * **`goInstallVersion()`:** Detects `go install` or `go run` commands with version specifiers (`@version`) and might trigger an early toolchain switch.

6. **Infer Go Language Feature:** Based on the analysis, the primary function is **dynamic Go toolchain switching**. This allows developers to use different Go versions for different projects or even within the same project based on `go.mod` requirements.

7. **Construct Examples:** Create clear and concise examples to illustrate the different scenarios, including `GOTOOLCHAIN` settings, `go.mod` directives, and command-line usage. Include assumed inputs and expected outputs.

8. **Address Command-Line Parameter Handling:** Focus on how `GOTOOLCHAIN` is used and how `go install` and `go run` with version specifiers are handled.

9. **Identify Common Mistakes:** Think about potential pitfalls for users. For example, setting `GOTOOLCHAIN` incorrectly or not understanding how `auto` mode works.

10. **Review and Refine:** Read through the entire explanation to ensure accuracy, clarity, and completeness. Make sure the examples are easy to understand and the explanations are logical.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this is about managing different Go SDK installations.
* **Correction:** The code explicitly talks about downloading toolchains as modules, so it's more about on-the-fly switching rather than pre-installed SDKs.
* **Initial thought:** The `TestVersionSwitch` is just for basic unit testing.
* **Refinement:**  The values "mismatch" and "loop" suggest more sophisticated testing of error conditions and edge cases in the switching mechanism.
* **Initial thought:**  The `raceSafeCopy` is just a normal file copy.
* **Refinement:** The comments clearly indicate that it's designed to handle concurrent access and avoid corruption in the module cache. Understanding the "open without truncate" detail is important.

By following this structured approach, breaking down the code into manageable parts, and constantly refining the understanding, we can arrive at a comprehensive and accurate explanation of the `select.go` file's functionality.
这段代码是 Go 语言 `cmd/go` 工具链中用于**动态选择和切换 Go 工具链版本**的一部分。它实现了 `go` 命令能够根据环境变量 `GOTOOLCHAIN` 或项目 `go.mod` 文件的配置，自动切换到指定的 Go 版本来执行操作。

**功能列举:**

1. **读取和解析 `GOTOOLCHAIN` 环境变量:**  `Select()` 函数首先会读取 `GOTOOLCHAIN` 环境变量的值。这个变量可以显式指定要使用的 Go 工具链版本（例如 `go1.20`），也可以设置为 `auto` 或 `path` 来指示自动或仅在 `PATH` 中查找。
2. **处理特定的 `go env` 命令:**  为了避免循环依赖或兼容性问题，代码特殊处理了 `go env GOTOOLCHAIN` 和 `go env -w GOTOOLCHAIN=...` 命令，确保它们始终由当前工具链处理。同时，`go env GOMOD` 和 `go env GOWORK` 也被特殊处理。
3. **根据 `GOTOOLCHAIN` 决定工具链选择模式:**
    * **显式版本 (例如 `go1.20`):**  直接使用指定的版本。
    * **`auto`:**  首先检查项目的 `go.mod` 文件中的 `go` 和 `toolchain` 指令。如果 `go.mod` 中指定的 Go 版本或 `toolchain` 版本高于当前 Go 版本，则会尝试切换到更高的版本。如果没有找到，则在 `PATH` 中查找，最后尝试下载。
    * **`path`:**  仅在 `PATH` 环境变量中查找指定的 Go 工具链。
4. **读取 `go.mod` 文件中的 `go` 和 `toolchain` 指令:** 当 `GOTOOLCHAIN` 设置为 `auto` 时，`modGoToolchain()` 函数会查找并读取项目或其父目录中的 `go.mod` 或 `go.work` 文件，获取 `go` 和 `toolchain` 指令指定的版本信息。
5. **下载和安装指定的 Go 工具链:** 如果需要的 Go 工具链在本地不存在，并且 `GOTOOLCHAIN` 不是 `path` 模式，`Exec()` 函数会使用 `modfetch` 包下载预打包的 Go 工具链模块 `golang.org/toolchain`。
6. **执行指定的 Go 工具链:**  `Exec()` 函数会找到或下载指定的 Go 工具链的可执行文件 (`bin/go`)，并使用 `os/exec` 包来启动它，并将当前的命令行参数传递给它。
7. **防止工具链切换循环:**  通过 `countEnv` 环境变量和 `maxSwitch` 常量，代码会跟踪工具链切换的深度，并在达到一定阈值时输出警告，超过最大值时会报错退出，防止无限循环切换。
8. **处理 `go install` 和 `go run` 命令带版本的情况 (`m@v`):** `goInstallVersion()` 函数会检测 `go install` 或 `go run` 命令是否指定了模块版本（例如 `go install example.org/foo@v1.2.3`）。在这种情况下，即使 `GOTOOLCHAIN` 是 `auto` 或 `path`，也应该优先使用当前工具链处理，因为用户显式指定了版本。但代码中也做了优化，如果 `go.mod` 中指定的版本高于当前版本，仍然可能触发切换。
9. **测试支持:** 通过 `TestVersionSwitch` 变量，代码提供了用于测试工具链切换逻辑的钩子，可以模拟切换成功、版本不匹配或切换循环等情况。

**Go 语言功能实现推断：动态 Go 工具链切换**

这段代码的核心是实现了 Go 1.21 引入的**动态 Go 工具链切换**功能。这个功能允许项目根据自身的需求选择合适的 Go 版本，而无需全局地更改用户的 Go 安装。

**Go 代码示例:**

假设我们有一个项目，其 `go.mod` 文件内容如下：

```go
module example.com/myproject

go 1.20

toolchain go1.21.0
```

当我们在这个项目目录下执行 `go build` 命令时，如果我们的本地 Go 版本低于 1.21.0，那么 `select.go` 中的逻辑会起作用：

1. `Select()` 函数被调用。
2. 假设 `GOTOOLCHAIN` 环境变量没有设置或设置为 `auto`。
3. `modGoToolchain()` 读取 `go.mod` 文件，发现 `toolchain go1.21.0`。
4. 由于本地 Go 版本低于 1.21.0，并且允许自动切换 (因为 `GOTOOLCHAIN` 是 `auto` 或未设置)，`Exec("go1.21.0")` 被调用。
5. `Exec()` 函数检查本地是否安装了 `go1.21.0` 工具链。如果没有，则下载并安装。
6. 最后，使用下载的 `go1.21.0` 工具链重新执行 `go build` 命令。

**假设的输入与输出 (基于上述示例):**

**输入:**

* 当前本地 Go 版本: go1.19
* `GOTOOLCHAIN` 环境变量: 未设置 或 "auto"
* 项目目录下存在 `go.mod` 文件，内容如上所示
* 执行命令: `go build`

**输出 (部分，可能包含下载过程):**

```
go: downloading golang.org/toolchain v0.0.1-go1.21.0.darwin-amd64  // 如果本地没有 go1.21.0
go: switching to go toolchain go1.21.0
// ... 使用 go1.21.0 构建项目的输出 ...
```

**命令行参数的具体处理:**

这段代码主要关注 `GOTOOLCHAIN` 环境变量的处理，以及对特定 `go env` 命令的拦截。

* **`GOTOOLCHAIN` 环境变量:**  `Select()` 函数通过 `cfg.Getenv("GOTOOLCHAIN")` 读取该变量的值，并根据其值决定工具链选择的策略。不同的值会触发不同的代码分支，例如 `auto` 会导致读取 `go.mod`，而显式版本会直接尝试执行该版本。
* **`go env GOTOOLCHAIN` 和 `go env -w GOTOOLCHAIN=...`:** 这两个命令会被当前 Go 工具链拦截并处理，不会触发工具链切换。这是为了避免在旧版本 Go 工具链中尝试解释新版本的 `GOTOOLCHAIN` 设置。
* **`go env GOMOD` 和 `go env GOWORK`:** 这两个命令也会被当前 Go 工具链拦截，因为它们需要确定 `go.mod` 和 `go.work` 文件的位置，这对于后续的工具链选择至关重要。
* **`go install <package>@<version>` 和 `go run <package>@<version>`:** `goInstallVersion()` 函数会解析这些命令，提取模块路径和版本信息。这部分逻辑旨在确保在用户显式指定版本的情况下，即使 `GOTOOLCHAIN` 设置为 `auto`，也能优先使用当前工具链或根据 `go.mod` 进行切换。代码会尝试解析命令行的 flag，以更准确地定位 `@` 符号前的包名。

**使用者易犯错的点:**

1. **误解 `GOTOOLCHAIN=auto` 的行为:**  用户可能认为 `auto` 只是简单地选择最新的 Go 版本。但实际上，它会优先查看 `go.mod` 文件，并根据 `go` 和 `toolchain` 指令进行选择。如果 `go.mod` 中指定了旧版本，即使本地有更新的版本，也会切换到旧版本。
    * **示例:** 用户本地安装了 Go 1.22，但项目的 `go.mod` 文件中有 `go 1.20` 和 `toolchain go1.21.0`。如果 `GOTOOLCHAIN=auto`，则会切换到 Go 1.21.0。

2. **`GOTOOLCHAIN=path` 的限制:**  用户可能忘记将所需的 Go 工具链添加到 `PATH` 环境变量中，导致 `go` 命令报错找不到指定的工具链。
    * **示例:** 用户设置了 `GOTOOLCHAIN=go1.20`，但 `go1.20` 的可执行文件不在 `PATH` 中，执行 `go build` 会报错。

3. **在不理解的情况下显式设置 `GOTOOLCHAIN`:**  用户可能随意设置 `GOTOOLCHAIN` 为某个版本，而没有考虑项目实际需要的版本，导致编译错误或运行时问题。

4. **忽略 `go.mod` 中的 `toolchain` 指令:**  用户可能只关注 `go` 指令，而忽略了 `toolchain` 指令。`toolchain` 指令具有更高的优先级，会覆盖 `go` 指令的影响。

5. **在 `go install` 或 `go run` 命令中使用 `@` 版本时与 `GOTOOLCHAIN` 的交互:**  用户可能不清楚当使用 `go install example.org/foo@v1.2.3` 时，`GOTOOLCHAIN` 的作用。虽然代码会尝试处理这种情况，但复杂的 flag 组合可能会导致行为不符合预期。

总而言之，这段代码实现了 Go 语言强大的工具链动态切换功能，使得项目可以更加灵活地管理其依赖的 Go 版本。理解 `GOTOOLCHAIN` 环境变量和 `go.mod` 文件中相关指令的作用对于正确使用这个功能至关重要。

### 提示词
```
这是路径为go/src/cmd/go/internal/toolchain/select.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package toolchain implements dynamic switching of Go toolchains.
package toolchain

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"go/build"
	"internal/godebug"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"cmd/go/internal/base"
	"cmd/go/internal/cfg"
	"cmd/go/internal/gover"
	"cmd/go/internal/modfetch"
	"cmd/go/internal/modload"
	"cmd/go/internal/run"
	"cmd/go/internal/work"
	"cmd/internal/pathcache"
	"cmd/internal/telemetry/counter"

	"golang.org/x/mod/module"
)

const (
	// We download golang.org/toolchain version v0.0.1-<gotoolchain>.<goos>-<goarch>.
	// If the 0.0.1 indicates anything at all, its the version of the toolchain packaging:
	// if for some reason we needed to change the way toolchains are packaged into
	// module zip files in a future version of Go, we could switch to v0.0.2 and then
	// older versions expecting the old format could use v0.0.1 and newer versions
	// would use v0.0.2. Of course, then we'd also have to publish two of each
	// module zip file. It's not likely we'll ever need to change this.
	gotoolchainModule  = "golang.org/toolchain"
	gotoolchainVersion = "v0.0.1"

	// targetEnv is a special environment variable set to the expected
	// toolchain version during the toolchain switch by the parent
	// process and cleared in the child process. When set, that indicates
	// to the child to confirm that it provides the expected toolchain version.
	targetEnv = "GOTOOLCHAIN_INTERNAL_SWITCH_VERSION"

	// countEnv is a special environment variable
	// that is incremented during each toolchain switch, to detect loops.
	// It is cleared before invoking programs in 'go run', 'go test', 'go generate', and 'go tool'
	// by invoking them in an environment filtered with FilterEnv,
	// so user programs should not see this in their environment.
	countEnv = "GOTOOLCHAIN_INTERNAL_SWITCH_COUNT"

	// maxSwitch is the maximum toolchain switching depth.
	// Most uses should never see more than three.
	// (Perhaps one for the initial GOTOOLCHAIN dispatch,
	// a second for go get doing an upgrade, and a third if
	// for some reason the chosen upgrade version is too small
	// by a little.)
	// When the count reaches maxSwitch - 10, we start logging
	// the switched versions for debugging before crashing with
	// a fatal error upon reaching maxSwitch.
	// That should be enough to see the repetition.
	maxSwitch = 100
)

// FilterEnv returns a copy of env with internal GOTOOLCHAIN environment
// variables filtered out.
func FilterEnv(env []string) []string {
	// Note: Don't need to filter out targetEnv because Switch does that.
	var out []string
	for _, e := range env {
		if strings.HasPrefix(e, countEnv+"=") {
			continue
		}
		out = append(out, e)
	}
	return out
}

var counterErrorsInvalidToolchainInFile = counter.New("go/errors:invalid-toolchain-in-file")
var toolchainTrace = godebug.New("#toolchaintrace").Value() == "1"

// Select invokes a different Go toolchain if directed by
// the GOTOOLCHAIN environment variable or the user's configuration
// or go.mod file.
// It must be called early in startup.
// See https://go.dev/doc/toolchain#select.
func Select() {
	log.SetPrefix("go: ")
	defer log.SetPrefix("")

	if !modload.WillBeEnabled() {
		return
	}

	// As a special case, let "go env GOTOOLCHAIN" and "go env -w GOTOOLCHAIN=..."
	// be handled by the local toolchain, since an older toolchain may not understand it.
	// This provides an easy way out of "go env -w GOTOOLCHAIN=go1.19" and makes
	// sure that "go env GOTOOLCHAIN" always prints the local go command's interpretation of it.
	// We look for these specific command lines in order to avoid mishandling
	//
	//	GOTOOLCHAIN=go1.999 go env -newflag GOTOOLCHAIN
	//
	// where -newflag is a flag known to Go 1.999 but not known to us.
	if (len(os.Args) == 3 && os.Args[1] == "env" && os.Args[2] == "GOTOOLCHAIN") ||
		(len(os.Args) == 4 && os.Args[1] == "env" && os.Args[2] == "-w" && strings.HasPrefix(os.Args[3], "GOTOOLCHAIN=")) {
		return
	}

	// As a special case, let "go env GOMOD" and "go env GOWORK" be handled by
	// the local toolchain. Users expect to be able to look up GOMOD and GOWORK
	// since the go.mod and go.work file need to be determined to determine
	// the minimum toolchain. See issue #61455.
	if len(os.Args) == 3 && os.Args[1] == "env" && (os.Args[2] == "GOMOD" || os.Args[2] == "GOWORK") {
		return
	}

	// Interpret GOTOOLCHAIN to select the Go toolchain to run.
	gotoolchain := cfg.Getenv("GOTOOLCHAIN")
	gover.Startup.GOTOOLCHAIN = gotoolchain
	if gotoolchain == "" {
		// cfg.Getenv should fall back to $GOROOT/go.env,
		// so this should not happen, unless a packager
		// has deleted the GOTOOLCHAIN line from go.env.
		// It can also happen if GOROOT is missing or broken,
		// in which case best to let the go command keep running
		// and diagnose the problem.
		return
	}

	// Note: minToolchain is what https://go.dev/doc/toolchain#select calls the default toolchain.
	minToolchain := gover.LocalToolchain()
	minVers := gover.Local()
	var mode string
	var toolchainTraceBuffer bytes.Buffer
	if gotoolchain == "auto" {
		mode = "auto"
	} else if gotoolchain == "path" {
		mode = "path"
	} else {
		min, suffix, plus := strings.Cut(gotoolchain, "+") // go1.2.3+auto
		if min != "local" {
			v := gover.FromToolchain(min)
			if v == "" {
				if plus {
					base.Fatalf("invalid GOTOOLCHAIN %q: invalid minimum toolchain %q", gotoolchain, min)
				}
				base.Fatalf("invalid GOTOOLCHAIN %q", gotoolchain)
			}
			minToolchain = min
			minVers = v
		}
		if plus && suffix != "auto" && suffix != "path" {
			base.Fatalf("invalid GOTOOLCHAIN %q: only version suffixes are +auto and +path", gotoolchain)
		}
		mode = suffix
		if toolchainTrace {
			fmt.Fprintf(&toolchainTraceBuffer, "go: default toolchain set to %s from GOTOOLCHAIN=%s\n", minToolchain, gotoolchain)
		}
	}

	gotoolchain = minToolchain
	if (mode == "auto" || mode == "path") && !goInstallVersion(minVers) {
		// Read go.mod to find new minimum and suggested toolchain.
		file, goVers, toolchain := modGoToolchain()
		gover.Startup.AutoFile = file
		if toolchain == "default" {
			// "default" means always use the default toolchain,
			// which is already set, so nothing to do here.
			// Note that if we have Go 1.21 installed originally,
			// GOTOOLCHAIN=go1.30.0+auto or GOTOOLCHAIN=go1.30.0,
			// and the go.mod  says "toolchain default", we use Go 1.30, not Go 1.21.
			// That is, default overrides the "auto" part of the calculation
			// but not the minimum that the user has set.
			// Of course, if the go.mod also says "go 1.35", using Go 1.30
			// will provoke an error about the toolchain being too old.
			// That's what people who use toolchain default want:
			// only ever use the toolchain configured by the user
			// (including its environment and go env -w file).
			gover.Startup.AutoToolchain = toolchain
		} else {
			if toolchain != "" {
				// Accept toolchain only if it is > our min.
				// (If it is equal, then min satisfies it anyway: that can matter if min
				// has a suffix like "go1.21.1-foo" and toolchain is "go1.21.1".)
				toolVers := gover.FromToolchain(toolchain)
				if toolVers == "" || (!strings.HasPrefix(toolchain, "go") && !strings.Contains(toolchain, "-go")) {
					counterErrorsInvalidToolchainInFile.Inc()
					base.Fatalf("invalid toolchain %q in %s", toolchain, base.ShortPath(file))
				}
				if gover.Compare(toolVers, minVers) > 0 {
					if toolchainTrace {
						modeFormat := mode
						if strings.Contains(cfg.Getenv("GOTOOLCHAIN"), "+") { // go1.2.3+auto
							modeFormat = fmt.Sprintf("<name>+%s", mode)
						}
						fmt.Fprintf(&toolchainTraceBuffer, "go: upgrading toolchain to %s (required by toolchain line in %s; upgrade allowed by GOTOOLCHAIN=%s)\n", toolchain, base.ShortPath(file), modeFormat)
					}
					gotoolchain = toolchain
					minVers = toolVers
					gover.Startup.AutoToolchain = toolchain
				}
			}
			if gover.Compare(goVers, minVers) > 0 {
				gotoolchain = "go" + goVers
				// Starting with Go 1.21, the first released version has a .0 patch version suffix.
				// Don't try to download a language version (sans patch component), such as go1.22.
				// Instead, use the first toolchain of that language version, such as 1.22.0.
				// See golang.org/issue/62278.
				if gover.IsLang(goVers) && gover.Compare(goVers, "1.21") >= 0 {
					gotoolchain += ".0"
				}
				gover.Startup.AutoGoVersion = goVers
				gover.Startup.AutoToolchain = "" // in case we are overriding it for being too old
				if toolchainTrace {
					modeFormat := mode
					if strings.Contains(cfg.Getenv("GOTOOLCHAIN"), "+") { // go1.2.3+auto
						modeFormat = fmt.Sprintf("<name>+%s", mode)
					}
					fmt.Fprintf(&toolchainTraceBuffer, "go: upgrading toolchain to %s (required by go line in %s; upgrade allowed by GOTOOLCHAIN=%s)\n", gotoolchain, base.ShortPath(file), modeFormat)
				}
			}
		}
	}

	// If we are invoked as a target toolchain, confirm that
	// we provide the expected version and then run.
	// This check is delayed until after the handling of auto and path
	// so that we have initialized gover.Startup for use in error messages.
	if target := os.Getenv(targetEnv); target != "" && TestVersionSwitch != "loop" {
		if gover.LocalToolchain() != target {
			base.Fatalf("toolchain %v invoked to provide %v", gover.LocalToolchain(), target)
		}
		os.Unsetenv(targetEnv)

		// Note: It is tempting to check that if gotoolchain != "local"
		// then target == gotoolchain here, as a sanity check that
		// the child has made the same version determination as the parent.
		// This turns out not always to be the case. Specifically, if we are
		// running Go 1.21 with GOTOOLCHAIN=go1.22+auto, which invokes
		// Go 1.22, then 'go get go@1.23.0' or 'go get needs_go_1_23'
		// will invoke Go 1.23, but as the Go 1.23 child the reason for that
		// will not be apparent here: it will look like we should be using Go 1.22.
		// We rely on the targetEnv being set to know not to downgrade.
		// A longer term problem with the sanity check is that the exact details
		// may change over time: there may be other reasons that a future Go
		// version might invoke an older one, and the older one won't know why.
		// Best to just accept that we were invoked to provide a specific toolchain
		// (which we just checked) and leave it at that.
		return
	}

	if toolchainTrace {
		// Flush toolchain tracing buffer only in the parent process (targetEnv is unset).
		io.Copy(os.Stderr, &toolchainTraceBuffer)
	}

	if gotoolchain == "local" || gotoolchain == gover.LocalToolchain() {
		// Let the current binary handle the command.
		if toolchainTrace {
			fmt.Fprintf(os.Stderr, "go: using local toolchain %s\n", gover.LocalToolchain())
		}
		return
	}

	// Minimal sanity check of GOTOOLCHAIN setting before search.
	// We want to allow things like go1.20.3 but also gccgo-go1.20.3.
	// We want to disallow mistakes / bad ideas like GOTOOLCHAIN=bash,
	// since we will find that in the path lookup.
	if !strings.HasPrefix(gotoolchain, "go1") && !strings.Contains(gotoolchain, "-go1") {
		base.Fatalf("invalid GOTOOLCHAIN %q", gotoolchain)
	}

	counterSelectExec.Inc()
	Exec(gotoolchain)
}

var counterSelectExec = counter.New("go/toolchain/select-exec")

// TestVersionSwitch is set in the test go binary to the value in $TESTGO_VERSION_SWITCH.
// Valid settings are:
//
//	"switch" - simulate version switches by reinvoking the test go binary with a different TESTGO_VERSION.
//	"mismatch" - like "switch" but forget to set TESTGO_VERSION, so it looks like we invoked a mismatched toolchain
//	"loop" - like "mismatch" but forget the target check, causing a toolchain switching loop
var TestVersionSwitch string

// Exec invokes the specified Go toolchain or else prints an error and exits the process.
// If $GOTOOLCHAIN is set to path or min+path, Exec only considers the PATH
// as a source of Go toolchains. Otherwise Exec tries the PATH but then downloads
// a toolchain if necessary.
func Exec(gotoolchain string) {
	log.SetPrefix("go: ")

	writeBits = sysWriteBits()

	count, _ := strconv.Atoi(os.Getenv(countEnv))
	if count >= maxSwitch-10 {
		fmt.Fprintf(os.Stderr, "go: switching from go%v to %v [depth %d]\n", gover.Local(), gotoolchain, count)
	}
	if count >= maxSwitch {
		base.Fatalf("too many toolchain switches")
	}
	os.Setenv(countEnv, fmt.Sprint(count+1))

	env := cfg.Getenv("GOTOOLCHAIN")
	pathOnly := env == "path" || strings.HasSuffix(env, "+path")

	// For testing, if TESTGO_VERSION is already in use
	// (only happens in the cmd/go test binary)
	// and TESTGO_VERSION_SWITCH=switch is set,
	// "switch" toolchains by changing TESTGO_VERSION
	// and reinvoking the current binary.
	// The special cases =loop and =mismatch skip the
	// setting of TESTGO_VERSION so that it looks like we
	// accidentally invoked the wrong toolchain,
	// to test detection of that failure mode.
	switch TestVersionSwitch {
	case "switch":
		os.Setenv("TESTGO_VERSION", gotoolchain)
		fallthrough
	case "loop", "mismatch":
		exe, err := os.Executable()
		if err != nil {
			base.Fatalf("%v", err)
		}
		execGoToolchain(gotoolchain, os.Getenv("GOROOT"), exe)
	}

	// Look in PATH for the toolchain before we download one.
	// This allows custom toolchains as well as reuse of toolchains
	// already installed using go install golang.org/dl/go1.2.3@latest.
	if exe, err := pathcache.LookPath(gotoolchain); err == nil {
		execGoToolchain(gotoolchain, "", exe)
	}

	// GOTOOLCHAIN=auto looks in PATH and then falls back to download.
	// GOTOOLCHAIN=path only looks in PATH.
	if pathOnly {
		base.Fatalf("cannot find %q in PATH", gotoolchain)
	}

	// Set up modules without an explicit go.mod, to download distribution.
	modload.Reset()
	modload.ForceUseModules = true
	modload.RootMode = modload.NoRoot
	modload.Init()

	// Download and unpack toolchain module into module cache.
	// Note that multiple go commands might be doing this at the same time,
	// and that's OK: the module cache handles that case correctly.
	m := module.Version{
		Path:    gotoolchainModule,
		Version: gotoolchainVersion + "-" + gotoolchain + "." + runtime.GOOS + "-" + runtime.GOARCH,
	}
	dir, err := modfetch.Download(context.Background(), m)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			toolVers := gover.FromToolchain(gotoolchain)
			if gover.IsLang(toolVers) && gover.Compare(toolVers, "1.21") >= 0 {
				base.Fatalf("invalid toolchain: %s is a language version but not a toolchain version (%s.x)", gotoolchain, gotoolchain)
			}
			base.Fatalf("download %s for %s/%s: toolchain not available", gotoolchain, runtime.GOOS, runtime.GOARCH)
		}
		base.Fatalf("download %s: %v", gotoolchain, err)
	}

	// On first use after download, set the execute bits on the commands
	// so that we can run them. Note that multiple go commands might be
	// doing this at the same time, but if so no harm done.
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(dir, "bin/go"))
		if err != nil {
			base.Fatalf("download %s: %v", gotoolchain, err)
		}
		if info.Mode()&0111 == 0 {
			// allowExec sets the exec permission bits on all files found in dir if pattern is the empty string,
			// or only those files that match the pattern if it's non-empty.
			allowExec := func(dir, pattern string) {
				err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if !d.IsDir() {
						if pattern != "" {
							if matched, _ := filepath.Match(pattern, d.Name()); !matched {
								// Skip file.
								return nil
							}
						}
						info, err := os.Stat(path)
						if err != nil {
							return err
						}
						if err := os.Chmod(path, info.Mode()&0777|0111); err != nil {
							return err
						}
					}
					return nil
				})
				if err != nil {
					base.Fatalf("download %s: %v", gotoolchain, err)
				}
			}

			// Set the bits in pkg/tool before bin/go.
			// If we are racing with another go command and do bin/go first,
			// then the check of bin/go above might succeed, the other go command
			// would skip its own mode-setting, and then the go command might
			// try to run a tool before we get to setting the bits on pkg/tool.
			// Setting pkg/tool and lib before bin/go avoids that ordering problem.
			// The only other tool the go command invokes is gofmt,
			// so we set that one explicitly before handling bin (which will include bin/go).
			allowExec(filepath.Join(dir, "pkg/tool"), "")
			allowExec(filepath.Join(dir, "lib"), "go_?*_?*_exec")
			allowExec(filepath.Join(dir, "bin/gofmt"), "")
			allowExec(filepath.Join(dir, "bin"), "")
		}
	}

	srcUGoMod := filepath.Join(dir, "src/_go.mod")
	srcGoMod := filepath.Join(dir, "src/go.mod")
	if size(srcGoMod) != size(srcUGoMod) {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if path == srcUGoMod {
				// Leave for last, in case we are racing with another go command.
				return nil
			}
			if pdir, name := filepath.Split(path); name == "_go.mod" {
				if err := raceSafeCopy(path, pdir+"go.mod"); err != nil {
					return err
				}
			}
			return nil
		})
		// Handle src/go.mod; this is the signal to other racing go commands
		// that everything is okay and they can skip this step.
		if err == nil {
			err = raceSafeCopy(srcUGoMod, srcGoMod)
		}
		if err != nil {
			base.Fatalf("download %s: %v", gotoolchain, err)
		}
	}

	// Reinvoke the go command.
	execGoToolchain(gotoolchain, dir, filepath.Join(dir, "bin/go"))
}

func size(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return -1
	}
	return info.Size()
}

var writeBits fs.FileMode

// raceSafeCopy copies the file old to the file new, being careful to ensure
// that if multiple go commands call raceSafeCopy(old, new) at the same time,
// they don't interfere with each other: both will succeed and return and
// later observe the correct content in new. Like in the build cache, we arrange
// this by opening new without truncation and then writing the content.
// Both go commands can do this simultaneously and will write the same thing
// (old never changes content).
func raceSafeCopy(old, new string) error {
	oldInfo, err := os.Stat(old)
	if err != nil {
		return err
	}
	newInfo, err := os.Stat(new)
	if err == nil && newInfo.Size() == oldInfo.Size() {
		return nil
	}
	data, err := os.ReadFile(old)
	if err != nil {
		return err
	}
	// The module cache has unwritable directories by default.
	// Restore the user write bit in the directory so we can create
	// the new go.mod file. We clear it again at the end on a
	// best-effort basis (ignoring failures).
	dir := filepath.Dir(old)
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if err := os.Chmod(dir, info.Mode()|writeBits); err != nil {
		return err
	}
	defer os.Chmod(dir, info.Mode())
	// Note: create the file writable, so that a racing go command
	// doesn't get an error before we store the actual data.
	f, err := os.OpenFile(new, os.O_CREATE|os.O_WRONLY, writeBits&^0o111)
	if err != nil {
		// If OpenFile failed because a racing go command completed our work
		// (and then OpenFile failed because the directory or file is now read-only),
		// count that as a success.
		if size(old) == size(new) {
			return nil
		}
		return err
	}
	defer os.Chmod(new, oldInfo.Mode())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// modGoToolchain finds the enclosing go.work or go.mod file
// and returns the go version and toolchain lines from the file.
// The toolchain line overrides the version line
func modGoToolchain() (file, goVers, toolchain string) {
	wd := base.UncachedCwd()
	file = modload.FindGoWork(wd)
	// $GOWORK can be set to a file that does not yet exist, if we are running 'go work init'.
	// Do not try to load the file in that case
	if _, err := os.Stat(file); err != nil {
		file = ""
	}
	if file == "" {
		file = modload.FindGoMod(wd)
	}
	if file == "" {
		return "", "", ""
	}

	data, err := os.ReadFile(file)
	if err != nil {
		base.Fatalf("%v", err)
	}
	return file, gover.GoModLookup(data, "go"), gover.GoModLookup(data, "toolchain")
}

// goInstallVersion reports whether the command line is go install m@v or go run m@v.
// If so, Select must not read the go.mod or go.work file in "auto" or "path" mode.
func goInstallVersion(minVers string) bool {
	// Note: We assume there are no flags between 'go' and 'install' or 'run'.
	// During testing there are some debugging flags that are accepted
	// in that position, but in production go binaries there are not.
	if len(os.Args) < 3 {
		return false
	}

	var cmdFlags *flag.FlagSet
	switch os.Args[1] {
	default:
		// Command doesn't support a pkg@version as the main module.
		return false
	case "install":
		cmdFlags = &work.CmdInstall.Flag
	case "run":
		cmdFlags = &run.CmdRun.Flag
	}

	// The modcachrw flag is unique, in that it affects how we fetch the
	// requested module to even figure out what toolchain it needs.
	// We need to actually set it before we check the toolchain version.
	// (See https://go.dev/issue/64282.)
	modcacherwFlag := cmdFlags.Lookup("modcacherw")
	if modcacherwFlag == nil {
		base.Fatalf("internal error: modcacherw flag not registered for command")
	}
	modcacherwVal, ok := modcacherwFlag.Value.(interface {
		IsBoolFlag() bool
		flag.Value
	})
	if !ok || !modcacherwVal.IsBoolFlag() {
		base.Fatalf("internal error: modcacherw is not a boolean flag")
	}

	// Make a best effort to parse the command's args to find the pkg@version
	// argument and the -modcacherw flag.
	var (
		pkgArg         string
		modcacherwSeen bool
	)
	for args := os.Args[2:]; len(args) > 0; {
		a := args[0]
		args = args[1:]
		if a == "--" {
			if len(args) == 0 {
				return false
			}
			pkgArg = args[0]
			break
		}

		a, ok := strings.CutPrefix(a, "-")
		if !ok {
			// Not a flag argument. Must be a package.
			pkgArg = a
			break
		}
		a = strings.TrimPrefix(a, "-") // Treat --flag as -flag.

		name, val, hasEq := strings.Cut(a, "=")

		if name == "modcacherw" {
			if !hasEq {
				val = "true"
			}
			if err := modcacherwVal.Set(val); err != nil {
				return false
			}
			modcacherwSeen = true
			continue
		}

		if hasEq {
			// Already has a value; don't bother parsing it.
			continue
		}

		f := run.CmdRun.Flag.Lookup(a)
		if f == nil {
			// We don't know whether this flag is a boolean.
			if os.Args[1] == "run" {
				// We don't know where to find the pkg@version argument.
				// For run, the pkg@version can be anywhere on the command line,
				// because it is preceded by run flags and followed by arguments to the
				// program being run. Since we don't know whether this flag takes
				// an argument, we can't reliably identify the end of the run flags.
				// Just give up and let the user clarify using the "=" form..
				return false
			}

			// We would like to let 'go install -newflag pkg@version' work even
			// across a toolchain switch. To make that work, assume by default that
			// the pkg@version is the last argument and skip the remaining args unless
			// we spot a plausible "-modcacherw" flag.
			for len(args) > 0 {
				a := args[0]
				name, _, _ := strings.Cut(a, "=")
				if name == "-modcacherw" || name == "--modcacherw" {
					break
				}
				if len(args) == 1 && !strings.HasPrefix(a, "-") {
					pkgArg = a
				}
				args = args[1:]
			}
			continue
		}

		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); !ok || !bf.IsBoolFlag() {
			// The next arg is the value for this flag. Skip it.
			args = args[1:]
			continue
		}
	}

	if !strings.Contains(pkgArg, "@") || build.IsLocalImport(pkgArg) || filepath.IsAbs(pkgArg) {
		return false
	}
	path, version, _ := strings.Cut(pkgArg, "@")
	if path == "" || version == "" || gover.IsToolchain(path) {
		return false
	}

	if !modcacherwSeen && base.InGOFLAGS("-modcacherw") {
		fs := flag.NewFlagSet("goInstallVersion", flag.ExitOnError)
		fs.Var(modcacherwVal, "modcacherw", modcacherwFlag.Usage)
		base.SetFromGOFLAGS(fs)
	}

	// It would be correct to simply return true here, bypassing use
	// of the current go.mod or go.work, and let "go run" or "go install"
	// do the rest, including a toolchain switch.
	// Our goal instead is, since we have gone to the trouble of handling
	// unknown flags to some degree, to run the switch now, so that
	// these commands can switch to a newer toolchain directed by the
	// go.mod which may actually understand the flag.
	// This was brought up during the go.dev/issue/57001 proposal discussion
	// and may end up being common in self-contained "go install" or "go run"
	// command lines if we add new flags in the future.

	// Set up modules without an explicit go.mod, to download go.mod.
	modload.ForceUseModules = true
	modload.RootMode = modload.NoRoot
	modload.Init()
	defer modload.Reset()

	// See internal/load.PackagesAndErrorsOutsideModule
	ctx := context.Background()
	allowed := modload.CheckAllowed
	if modload.IsRevisionQuery(path, version) {
		// Don't check for retractions if a specific revision is requested.
		allowed = nil
	}
	noneSelected := func(path string) (version string) { return "none" }
	_, err := modload.QueryPackages(ctx, path, version, noneSelected, allowed)
	if errors.Is(err, gover.ErrTooNew) {
		// Run early switch, same one go install or go run would eventually do,
		// if it understood all the command-line flags.
		var s Switcher
		s.Error(err)
		if s.TooNew != nil && gover.Compare(s.TooNew.GoVersion, minVers) > 0 {
			SwitchOrFatal(ctx, err)
		}
	}

	return true // pkg@version found
}
```