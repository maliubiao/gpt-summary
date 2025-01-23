Response: Let's break down the thought process for analyzing the `main.go` file.

**1. Understanding the Request:**

The core request is to understand the functionality of this Go file, specifically `go/src/cmd/go/main.go`. The prompt asks for:

* Listing of functionalities.
* Inference of specific Go language feature implementations with Go code examples.
* Explanation of code reasoning, including hypothetical inputs and outputs.
* Detailed handling of command-line arguments.
* Identification of common user errors.

**2. Initial Analysis -  High-Level Overview:**

The path `go/src/cmd/go/main.go` immediately suggests that this is the main entry point for the `go` command-line tool. This tool is central to the Go development experience. Therefore, the file likely orchestrates various subcommands related to building, testing, managing dependencies, and more.

**3. Examining Imports:**

The `import` statements are the first significant clue to the file's functionalities. Let's categorize them:

* **Standard Library:**  `context`, `flag`, `fmt`, `internal/buildcfg`, `log`, `os`, `path/filepath`, `runtime/trace`, `slices`, `strings`. These provide fundamental building blocks like argument parsing, I/O, string manipulation, and runtime tracing.
* **Internal Packages (cmd/go/internal/...):** These are the core components of the `go` tool itself. Looking at names like `base`, `bug`, `clean`, `doc`, `envcmd`, `fix`, `fmtcmd`, `generate`, `help`, `list`, `modcmd`, `modfetch`, `modget`, `modload`, `run`, `telemetrycmd`, `telemetrystats`, `test`, `tool`, `toolchain`, `trace`, `version`, `vet`, `work`, `workcmd`. These clearly map to various `go` subcommands.
* **Internal Packages (cmd/internal/...):** `telemetry`, `telemetry/counter`. These indicate functionality related to collecting and reporting usage data.

**4. Analyzing the `init()` Functions:**

The first `init()` function is crucial. It populates `base.Go.Commands` with a list of `base.Command` structs. This confirms the presence of numerous subcommands and provides a concrete list of what the `go` tool can do: `bug`, `build`, `clean`, `doc`, `env`, `fix`, `fmt`, `generate`, `get`, `install`, `list`, `mod`, `work`, `run`, `telemetry`, `test`, `tool`, `version`, `vet`. It also includes help topics.

**5. Examining the `main()` Function:**

The `main()` function is the heart of the program. Let's break down its actions step-by-step:

* **Logging setup:** `log.SetFlags(0)` suggests basic logging without timestamps or source file information.
* **Telemetry:** Calls to `telemetry.MaybeChild()`, `counter.Open()`, `telemetry.MaybeParent()` hint at telemetry collection, potentially as a separate process. The `cmdIsGoTelemetryOff()` function suggests a way to disable this.
* **`-C` flag handling:** `handleChdirFlag()` is explicitly called early, indicating special handling for changing the working directory.
* **Toolchain selection:** `toolchain.Select()` points to the process of choosing the appropriate Go toolchain.
* **Flag parsing:** `flag.Usage = base.Usage`, `flag.Parse()` indicate standard command-line argument parsing.
* **Subcommand dispatch:** The code iterates through arguments (`args`), looks up the command using `lookupCmd`, and then calls the `invoke` function.
* **Error handling:** Checks for empty arguments, unknown commands, and issues with `GOROOT` and `GOPATH`.
* **GOPATH validation:**  Includes checks for relative paths and the problematic case where `GOPATH` equals `GOROOT`.
* **Subcommand execution:** The `invoke` function sets up the environment and calls the `Run` method of the selected subcommand.
* **Tracing:** `maybeStartTrace` suggests the ability to enable tracing for debugging.

**6. Deeper Dive into Specific Functionalities (Inferring Go Features):**

Based on the imported packages and the subcommand list, we can infer the Go language features being implemented:

* **`go build`:** Compiling Go packages and producing executables. (Implemented in `cmd/go/internal/work`)
* **`go run`:** Compiling and running Go programs. (Implemented in `cmd/go/internal/run`)
* **`go test`:** Running Go tests. (Implemented in `cmd/go/internal/test`)
* **`go get`:** Downloading and installing Go packages and their dependencies. (Implemented in `cmd/go/internal/modget`)
* **`go mod`:** Managing Go modules (dependencies). (Implemented in `cmd/go/internal/modcmd`, `modfetch`, `modload`)
* **`go fmt`:** Formatting Go code according to standard conventions. (Implemented in `cmd/go/internal/fmtcmd`)
* **`go vet`:** Analyzing Go code for potential errors. (Implemented in `cmd/go/internal/vet`)
* **`go doc`:** Displaying documentation for Go packages and symbols. (Implemented in `cmd/go/internal/doc`)
* **`go env`:** Displaying Go environment information. (Implemented in `cmd/go/internal/envcmd`)

**7. Code Examples and Reasoning:**

For each inferred feature, we can construct simple Go code examples and explain how the `go` command would interact with them. The key is to connect the subcommand to the actions it performs on the provided code.

**8. Command-Line Argument Handling:**

The code explicitly uses the `flag` package. The `-C` flag is handled separately. We need to examine how flags are defined and used within the subcommands (although the provided snippet doesn't show that level of detail). However, we can infer common flags like `-o` for output, `-v` for verbose output, etc., based on general knowledge of the `go` tool.

**9. Identifying Common User Errors:**

Based on the code's checks and common Go development issues, we can identify potential errors:

* **Incorrect `GOPATH`:**  Relative paths, `GOPATH` being the same as `GOROOT`.
* **Forgetting to initialize modules:**  Especially relevant with `go mod`.
* **Misunderstanding import paths:**  Leading to "package not found" errors.
* **Incorrect usage of `go get`:**  Especially with module-aware mode.

**10. Structuring the Output:**

Finally, the information needs to be organized logically, addressing each point in the original request. Using headings, bullet points, and code blocks improves readability.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe focus too much on the low-level details of each subcommand.
* **Correction:** Realize the request is about the *main entry point*, so focus on the overall orchestration and dispatching of commands. Mention the subcommands and their purpose, but don't try to implement them.
* **Initial thought:**  Overlook the telemetry aspects.
* **Correction:** Notice the `telemetry` package imports and the `cmdIsGoTelemetryOff` function, and include that in the analysis.
* **Initial thought:**  Not explicitly mention the `-C` flag.
* **Correction:** The `handleChdirFlag` function is prominent, so highlight its special handling and purpose.

By following this structured approach, combining code analysis, domain knowledge of the Go toolchain, and addressing the specifics of the prompt, we can generate a comprehensive and accurate explanation of the `go/src/cmd/go/main.go` file.
这段代码是 Go 语言 `go` 命令的入口点 (`main` 函数所在的文件)，它负责解析命令行参数，根据用户输入的子命令调用相应的内部模块来执行各种 Go 语言相关的操作。

**主要功能列表:**

1. **命令解析和分发:**  接收用户在命令行输入的 `go` 命令及其子命令和参数，例如 `go build`, `go run`, `go test` 等，并将这些请求分发到相应的内部处理模块。
2. **子命令实现:**  它定义和注册了 `go` 命令支持的各种子命令，例如：
    * **构建 (`build`)**: 编译 Go 代码。
    * **清理 (`clean`)**: 删除构建产生的文件。
    * **文档 (`doc`)**: 查看 Go 包或符号的文档。
    * **环境变量 (`env`)**: 显示 Go 环境变量。
    * **代码修复 (`fix`)**: 自动调整代码以适应 Go 版本更新。
    * **格式化 (`fmt`)**: 格式化 Go 代码。
    * **代码生成 (`generate`)**: 执行代码生成器。
    * **获取依赖 (`get`)**: 下载并安装 Go 包及其依赖。
    * **安装 (`install`)**: 编译并将包及其依赖安装到 `$GOPATH/bin`。
    * **列表 (`list`)**: 列出包的信息。
    * **模块管理 (`mod`)**: 管理 Go 模块依赖。
    * **工作区管理 (`work`)**: 管理 Go 工作区 (Go 1.18 引入)。
    * **运行 (`run`)**: 编译并运行 Go 程序。
    * **遥测 (`telemetry`)**: 控制 Go 遥测功能。
    * **测试 (`test`)**: 运行 Go 测试。
    * **工具 (`tool`)**: 运行 Go 工具。
    * **版本 (`version`)**: 显示 Go 版本信息。
    * **静态分析 (`vet`)**: 对 Go 代码进行静态分析。
    * **帮助 (`help`)**: 显示帮助信息。
3. **环境配置:**  读取和校验 Go 语言的环境变量，例如 `GOROOT`, `GOPATH` 等，并进行一些预处理和检查。
4. **错误处理:**  处理用户输入的错误，例如未知的子命令、错误的参数等，并给出相应的提示信息。
5. **遥测功能:**  包含收集 Go 工具使用情况的遥测功能 (可以通过 `go telemetry off` 关闭)。
6. **运行时追踪:**  支持通过 `-tracereport` 标志生成运行时追踪信息。
7. **工作目录切换:**  支持使用 `-C` 标志在执行命令前切换工作目录。
8. **实验性功能管理:**  检查并处理实验性功能配置。

**推断的 Go 语言功能实现及其示例:**

这段代码是 `go` 命令本身的主入口，它并非直接实现某个特定的 Go 语言功能，而是作为 orchestrator，调用其他内部模块来实现各种功能。 我们可以通过它调用的内部包来推断它涉及的 Go 语言功能。

**示例 1: `go build` (编译 Go 代码)**

* **推理:** 代码中导入了 `cmd/go/internal/work` 包，并且 `init()` 函数中注册了 `work.CmdBuild` 命令。这表明它处理 `go build` 命令。
* **Go 代码示例 (假设输入):**
  ```go
  // example.go
  package main

  import "fmt"

  func main() {
    fmt.Println("Hello, Go!")
  }
  ```
* **命令行输入:** `go build example.go`
* **内部处理 (推测):**  `main.go` 的 `main` 函数会解析命令行，识别出 `build` 子命令，然后调用 `cmd/go/internal/work` 包中的 `CmdBuild.Run` 函数，该函数会编译 `example.go` 并生成可执行文件。
* **输出 (假设):**  在当前目录下生成一个名为 `example` (或 `example.exe` 在 Windows 上) 的可执行文件。

**示例 2: `go run` (编译并运行 Go 代码)**

* **推理:** 代码中导入了 `cmd/go/internal/run` 包，并且 `init()` 函数中注册了 `run.CmdRun` 命令。
* **Go 代码示例 (假设输入):**  使用上面的 `example.go` 文件。
* **命令行输入:** `go run example.go`
* **内部处理 (推测):** `main.go` 会解析命令行，识别出 `run` 子命令，然后调用 `cmd/go/internal/run` 包中的 `CmdRun.Run` 函数，该函数会先编译 `example.go`，然后在内存中运行编译后的代码。
* **输出 (假设):**
  ```
  Hello, Go!
  ```

**示例 3: `go mod init` (初始化 Go 模块)**

* **推理:** 代码中导入了 `cmd/go/internal/modcmd` 和 `cmd/go/internal/modload` 等包，并且 `init()` 函数中注册了 `modcmd.CmdMod` 命令，这意味着它处理 `go mod` 相关的命令。
* **Go 代码示例 (假设当前目录下没有 `go.mod` 文件):**
  ```go
  // 假设当前目录下没有 go.mod 文件
  ```
* **命令行输入:** `go mod init mymodule`
* **内部处理 (推测):** `main.go` 会解析命令行，识别出 `mod init` 子命令，然后调用 `cmd/go/internal/modcmd` 包中处理 `init` 子命令的逻辑 (可能在 `CmdMod.Run` 中)。 该逻辑会创建 `go.mod` 文件，其中包含模块的名称。
* **输出 (假设):**
  在当前目录下生成一个 `go.mod` 文件，内容可能如下：
  ```
  module mymodule

  go 1.xx
  ```

**命令行参数的具体处理:**

1. **顶级标志 (flags):** `main` 函数中使用 `flag` 包来处理顶级标志。
   * `flag.Usage = base.Usage`: 设置了默认的帮助信息显示函数。
   * `flag.Parse()`: 解析命令行参数。
   * `handleChdirFlag()`: 特殊处理 `-C` 标志，用于切换工作目录。这个标志必须在所有其他标志之前。
   * 代码中还检查了一些环境变量，例如 `GOROOT`。

2. **子命令及其标志:**  每个子命令都有自己的标志集合，这些标志在各自的 `Run` 函数中定义和解析。
   * `base.Go.Commands` 中注册的每个 `base.Command` 结构体都可能包含 `Flag` 字段，用于定义该子命令的特定标志。
   * 例如，`go build` 命令有 `-o` (指定输出文件名), `-v` (显示详细输出) 等标志。这些标志的解析逻辑在 `cmd/go/internal/work.CmdBuild.Run` 中。

3. **`-C` 标志的特殊处理 (`handleChdirFlag`):**
   * 这个函数在 `main` 函数的最开始被调用，目的是在任何其他操作之前切换工作目录。
   * 它检查命令行参数中是否包含 `-C` 或 `--C` 标志，以及其后的目录路径。
   * 如果找到，它会使用 `os.Chdir()` 切换到指定的目录，并将 `-C` 及其路径从 `os.Args` 中移除，这样后续的参数解析就不会受到影响。
   * **示例:** `go -C /tmp build` 会先切换到 `/tmp` 目录，然后在该目录下执行 `go build` 命令。

**使用者易犯错的点:**

1. **`GOPATH` 和 `GOROOT` 配置错误:**
   * **错误示例:**  `GOPATH` 没有正确设置，导致 `go get` 无法下载包，或者 `go build` 找不到依赖。
   * **代码体现:** `main` 函数中检查了 `cfg.GOROOT` 的存在性和有效性，以及 `cfg.BuildContext.GOPATH` 的配置。
   * **错误信息 (代码中输出):**
     ```
     go: cannot find GOROOT directory: 'go' binary is trimmed and GOROOT is not set
     go: cannot find GOROOT directory: <GOROOT路径>
     warning: both GOPATH and GOROOT are the same directory (<路径>); see https://go.dev/wiki/InstallTroubleshooting
     go: GOPATH entry cannot start with shell metacharacter '~': "<路径>"
     go: GOPATH entry is relative; must be absolute path: "<路径>".
     For more details see: 'go help gopath'
     ```

2. **在模块外部使用 `go get` 或其他模块相关的命令:**
   * **错误示例:**  在一个没有 `go.mod` 文件的目录下运行 `go get some/package`，可能会导致意外的行为或错误。
   * **代码体现:** 虽然这段代码本身不直接处理模块逻辑，但它加载了 `cmd/go/internal/modcmd`, `cmd/go/internal/modfetch` 等模块相关的包，意味着 `go` 命令会根据当前目录是否存在 `go.mod` 文件来决定是否以模块模式运行。

3. **混淆包路径和文件路径:**
   * **错误示例:**  在 `go build` 命令中使用了具体的文件路径，而不是包的导入路径。
   * **代码体现:** `cmd/go/internal/work.CmdBuild` 等子命令的处理逻辑会解析用户提供的参数，并将其解释为包的导入路径。

4. **`-C` 标志的位置错误:**
   * **错误示例:** `go build -C /tmp` (`-C` 标志应该在 `build` 之前)。
   * **代码体现:** `handleChdirFlag` 函数只在 `main` 函数开始时被调用，并且它期望 `-C` 标志出现在子命令之前。

5. **对实验性功能的误解或错误使用:**
   * **错误示例:**  不了解实验性功能的风险，在生产环境中使用。
   * **代码体现:**  `buildcfg.Check()` 和 `cfg.ExperimentErr` 相关的处理表明 `go` 命令会检查和处理实验性功能配置。

总而言之，`go/src/cmd/go/main.go` 是 Go 语言工具链的核心入口，它像一个指挥中心，接收用户的指令，并调度各个功能模块来完成相应的任务，是理解 Go 语言工作原理的关键部分。

### 提示词
```
这是路径为go/src/cmd/go/main.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate go test cmd/go -v -run=^TestDocsUpToDate$ -fixdocs

package main

import (
	"context"
	"flag"
	"fmt"
	"internal/buildcfg"
	"log"
	"os"
	"path/filepath"
	rtrace "runtime/trace"
	"slices"
	"strings"

	"cmd/go/internal/base"
	"cmd/go/internal/bug"
	"cmd/go/internal/cfg"
	"cmd/go/internal/clean"
	"cmd/go/internal/doc"
	"cmd/go/internal/envcmd"
	"cmd/go/internal/fix"
	"cmd/go/internal/fmtcmd"
	"cmd/go/internal/generate"
	"cmd/go/internal/help"
	"cmd/go/internal/list"
	"cmd/go/internal/modcmd"
	"cmd/go/internal/modfetch"
	"cmd/go/internal/modget"
	"cmd/go/internal/modload"
	"cmd/go/internal/run"
	"cmd/go/internal/telemetrycmd"
	"cmd/go/internal/telemetrystats"
	"cmd/go/internal/test"
	"cmd/go/internal/tool"
	"cmd/go/internal/toolchain"
	"cmd/go/internal/trace"
	"cmd/go/internal/version"
	"cmd/go/internal/vet"
	"cmd/go/internal/work"
	"cmd/go/internal/workcmd"
	"cmd/internal/telemetry"
	"cmd/internal/telemetry/counter"
)

func init() {
	base.Go.Commands = []*base.Command{
		bug.CmdBug,
		work.CmdBuild,
		clean.CmdClean,
		doc.CmdDoc,
		envcmd.CmdEnv,
		fix.CmdFix,
		fmtcmd.CmdFmt,
		generate.CmdGenerate,
		modget.CmdGet,
		work.CmdInstall,
		list.CmdList,
		modcmd.CmdMod,
		workcmd.CmdWork,
		run.CmdRun,
		telemetrycmd.CmdTelemetry,
		test.CmdTest,
		tool.CmdTool,
		version.CmdVersion,
		vet.CmdVet,

		help.HelpBuildConstraint,
		help.HelpBuildJSON,
		help.HelpBuildmode,
		help.HelpC,
		help.HelpCache,
		help.HelpEnvironment,
		help.HelpFileType,
		help.HelpGoAuth,
		modload.HelpGoMod,
		help.HelpGopath,
		modfetch.HelpGoproxy,
		help.HelpImportPath,
		modload.HelpModules,
		modfetch.HelpModuleAuth,
		help.HelpPackages,
		modfetch.HelpPrivate,
		test.HelpTestflag,
		test.HelpTestfunc,
		modget.HelpVCS,
	}
}

var _ = go11tag

var counterErrorsGOPATHEntryRelative = counter.New("go/errors:gopath-entry-relative")

func main() {
	log.SetFlags(0)
	telemetry.MaybeChild() // Run in child mode if this is the telemetry sidecar child process.
	cmdIsGoTelemetryOff := cmdIsGoTelemetryOff()
	if !cmdIsGoTelemetryOff {
		counter.Open() // Open the telemetry counter file so counters can be written to it.
	}
	handleChdirFlag()
	toolchain.Select()

	if !cmdIsGoTelemetryOff {
		telemetry.MaybeParent() // Run the upload process. Opening the counter file is idempotent.
	}
	flag.Usage = base.Usage
	flag.Parse()
	counter.Inc("go/invocations")
	counter.CountFlags("go/flag:", *flag.CommandLine)

	args := flag.Args()
	if len(args) < 1 {
		base.Usage()
	}

	cfg.CmdName = args[0] // for error messages
	if args[0] == "help" {
		counter.Inc("go/subcommand:" + strings.Join(append([]string{"help"}, args[1:]...), "-"))
		help.Help(os.Stdout, args[1:])
		return
	}

	if cfg.GOROOT == "" {
		fmt.Fprintf(os.Stderr, "go: cannot find GOROOT directory: 'go' binary is trimmed and GOROOT is not set\n")
		os.Exit(2)
	}
	if fi, err := os.Stat(cfg.GOROOT); err != nil || !fi.IsDir() {
		fmt.Fprintf(os.Stderr, "go: cannot find GOROOT directory: %v\n", cfg.GOROOT)
		os.Exit(2)
	}
	switch strings.ToLower(cfg.GOROOT) {
	case "/usr/local/go": // Location recommended for installation on Linux and Darwin and used by Mac installer.
		counter.Inc("go/goroot:usr-local-go")
	case "/usr/lib/go": // A typical location used by Linux package managers.
		counter.Inc("go/goroot:usr-lib-go")
	case "/usr/lib/golang": // Another typical location used by Linux package managers.
		counter.Inc("go/goroot:usr-lib-golang")
	case `c:\program files\go`: // Location used by Windows installer.
		counter.Inc("go/goroot:program-files-go")
	case `c:\program files (x86)\go`: // Location used by 386 Windows installer on amd64 platform.
		counter.Inc("go/goroot:program-files-x86-go")
	default:
		counter.Inc("go/goroot:other")
	}

	// Diagnose common mistake: GOPATH==GOROOT.
	// This setting is equivalent to not setting GOPATH at all,
	// which is not what most people want when they do it.
	if gopath := cfg.BuildContext.GOPATH; filepath.Clean(gopath) == filepath.Clean(cfg.GOROOT) {
		fmt.Fprintf(os.Stderr, "warning: both GOPATH and GOROOT are the same directory (%s); see https://go.dev/wiki/InstallTroubleshooting\n", gopath)
	} else {
		for _, p := range filepath.SplitList(gopath) {
			// Some GOPATHs have empty directory elements - ignore them.
			// See issue 21928 for details.
			if p == "" {
				continue
			}
			// Note: using HasPrefix instead of Contains because a ~ can appear
			// in the middle of directory elements, such as /tmp/git-1.8.2~rc3
			// or C:\PROGRA~1. Only ~ as a path prefix has meaning to the shell.
			if strings.HasPrefix(p, "~") {
				fmt.Fprintf(os.Stderr, "go: GOPATH entry cannot start with shell metacharacter '~': %q\n", p)
				os.Exit(2)
			}
			if !filepath.IsAbs(p) {
				if cfg.Getenv("GOPATH") == "" {
					// We inferred $GOPATH from $HOME and did a bad job at it.
					// Instead of dying, uninfer it.
					cfg.BuildContext.GOPATH = ""
				} else {
					counterErrorsGOPATHEntryRelative.Inc()
					fmt.Fprintf(os.Stderr, "go: GOPATH entry is relative; must be absolute path: %q.\nFor more details see: 'go help gopath'\n", p)
					os.Exit(2)
				}
			}
		}
	}

	cmd, used := lookupCmd(args)
	cfg.CmdName = strings.Join(args[:used], " ")
	if len(cmd.Commands) > 0 {
		if used >= len(args) {
			help.PrintUsage(os.Stderr, cmd)
			base.SetExitStatus(2)
			base.Exit()
		}
		if args[used] == "help" {
			// Accept 'go mod help' and 'go mod help foo' for 'go help mod' and 'go help mod foo'.
			counter.Inc("go/subcommand:" + strings.ReplaceAll(cfg.CmdName, " ", "-") + "-" + strings.Join(args[used:], "-"))
			help.Help(os.Stdout, append(slices.Clip(args[:used]), args[used+1:]...))
			base.Exit()
		}
		helpArg := ""
		if used > 0 {
			helpArg += " " + strings.Join(args[:used], " ")
		}
		cmdName := cfg.CmdName
		if cmdName == "" {
			cmdName = args[0]
		}
		counter.Inc("go/subcommand:unknown")
		fmt.Fprintf(os.Stderr, "go %s: unknown command\nRun 'go help%s' for usage.\n", cmdName, helpArg)
		base.SetExitStatus(2)
		base.Exit()
	}
	// Increment a subcommand counter for the subcommand we're running.
	// Don't increment the counter for the tool subcommand here: we'll
	// increment in the tool subcommand's Run function because we need
	// to do the flag processing in invoke first.
	if cfg.CmdName != "tool" {
		counter.Inc("go/subcommand:" + strings.ReplaceAll(cfg.CmdName, " ", "-"))
	}
	telemetrystats.Increment()
	invoke(cmd, args[used-1:])
	base.Exit()
}

// cmdIsGoTelemetryOff reports whether the command is "go telemetry off". This
// is used to decide whether to disable the opening of counter files. See #69269.
func cmdIsGoTelemetryOff() bool {
	restArgs := os.Args[1:]
	// skipChdirFlag skips the -C flag, which is the only flag that can appear
	// in a valid 'go telemetry off' command, and which hasn't been processed
	// yet. We need to determine if the command is 'go telemetry off' before we open
	// the counter file, but we want to process -C after we open counters so that
	// we can increment the flag counter for it.
	skipChdirFlag := func() {
		if len(restArgs) == 0 {
			return
		}
		switch a := restArgs[0]; {
		case a == "-C", a == "--C":
			if len(restArgs) < 2 {
				restArgs = nil
				return
			}
			restArgs = restArgs[2:]

		case strings.HasPrefix(a, "-C="), strings.HasPrefix(a, "--C="):
			restArgs = restArgs[1:]
		}
	}
	skipChdirFlag()
	cmd, used := lookupCmd(restArgs)
	if cmd != telemetrycmd.CmdTelemetry {
		return false
	}
	restArgs = restArgs[used:]
	skipChdirFlag()
	return len(restArgs) == 1 && restArgs[0] == "off"
}

// lookupCmd interprets the initial elements of args
// to find a command to run (cmd.Runnable() == true)
// or else a command group that ran out of arguments
// or had an unknown subcommand (len(cmd.Commands) > 0).
// It returns that command and the number of elements of args
// that it took to arrive at that command.
func lookupCmd(args []string) (cmd *base.Command, used int) {
	cmd = base.Go
	for used < len(args) {
		c := cmd.Lookup(args[used])
		if c == nil {
			break
		}
		if c.Runnable() {
			cmd = c
			used++
			break
		}
		if len(c.Commands) > 0 {
			cmd = c
			used++
			if used >= len(args) || args[0] == "help" {
				break
			}
			continue
		}
		// len(c.Commands) == 0 && !c.Runnable() => help text; stop at "help"
		break
	}
	return cmd, used
}

func invoke(cmd *base.Command, args []string) {
	// 'go env' handles checking the build config
	if cmd != envcmd.CmdEnv {
		buildcfg.Check()
		if cfg.ExperimentErr != nil {
			base.Fatal(cfg.ExperimentErr)
		}
	}

	// Set environment (GOOS, GOARCH, etc) explicitly.
	// In theory all the commands we invoke should have
	// the same default computation of these as we do,
	// but in practice there might be skew
	// This makes sure we all agree.
	cfg.OrigEnv = toolchain.FilterEnv(os.Environ())
	cfg.CmdEnv = envcmd.MkEnv()
	for _, env := range cfg.CmdEnv {
		if os.Getenv(env.Name) != env.Value {
			os.Setenv(env.Name, env.Value)
		}
	}

	cmd.Flag.Usage = func() { cmd.Usage() }
	if cmd.CustomFlags {
		args = args[1:]
	} else {
		base.SetFromGOFLAGS(&cmd.Flag)
		cmd.Flag.Parse(args[1:])
		flagCounterPrefix := "go/" + strings.ReplaceAll(cfg.CmdName, " ", "-") + "/flag"
		counter.CountFlags(flagCounterPrefix+":", cmd.Flag)
		counter.CountFlagValue(flagCounterPrefix+"/", cmd.Flag, "buildmode")
		args = cmd.Flag.Args()
	}

	if cfg.DebugRuntimeTrace != "" {
		f, err := os.Create(cfg.DebugRuntimeTrace)
		if err != nil {
			base.Fatalf("creating trace file: %v", err)
		}
		if err := rtrace.Start(f); err != nil {
			base.Fatalf("starting event trace: %v", err)
		}
		defer func() {
			rtrace.Stop()
			f.Close()
		}()
	}

	ctx := maybeStartTrace(context.Background())
	ctx, span := trace.StartSpan(ctx, fmt.Sprint("Running ", cmd.Name(), " command"))
	cmd.Run(ctx, cmd, args)
	span.Done()
}

func init() {
	base.Usage = mainUsage
}

func mainUsage() {
	help.PrintUsage(os.Stderr, base.Go)
	os.Exit(2)
}

func maybeStartTrace(pctx context.Context) context.Context {
	if cfg.DebugTrace == "" {
		return pctx
	}

	ctx, close, err := trace.Start(pctx, cfg.DebugTrace)
	if err != nil {
		base.Fatalf("failed to start trace: %v", err)
	}
	base.AtExit(func() {
		if err := close(); err != nil {
			base.Fatalf("failed to stop trace: %v", err)
		}
	})

	return ctx
}

// handleChdirFlag handles the -C flag before doing anything else.
// The -C flag must be the first flag on the command line, to make it easy to find
// even with commands that have custom flag parsing.
// handleChdirFlag handles the flag by chdir'ing to the directory
// and then removing that flag from the command line entirely.
//
// We have to handle the -C flag this way for two reasons:
//
//  1. Toolchain selection needs to be in the right directory to look for go.mod and go.work.
//
//  2. A toolchain switch later on reinvokes the new go command with the same arguments.
//     The parent toolchain has already done the chdir; the child must not try to do it again.
func handleChdirFlag() {
	_, used := lookupCmd(os.Args[1:])
	used++ // because of [1:]
	if used >= len(os.Args) {
		return
	}

	var dir string
	switch a := os.Args[used]; {
	default:
		return

	case a == "-C", a == "--C":
		if used+1 >= len(os.Args) {
			return
		}
		dir = os.Args[used+1]
		os.Args = slices.Delete(os.Args, used, used+2)

	case strings.HasPrefix(a, "-C="), strings.HasPrefix(a, "--C="):
		_, dir, _ = strings.Cut(a, "=")
		os.Args = slices.Delete(os.Args, used, used+1)
	}
	counter.Inc("go/flag:C")

	if err := os.Chdir(dir); err != nil {
		base.Fatalf("go: %v", err)
	}
}
```