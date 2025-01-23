Response: My thinking process to analyze the `download.go` code and generate the response went through these stages:

1. **Understand the Goal:** The core purpose is to analyze the provided Go code snippet (`download.go`) and explain its functionality, related Go features, usage, and potential pitfalls.

2. **Identify Key Components:** I started by looking at the major elements within the code:
    * **Package Declaration:** `package modcmd` - This immediately tells me it's part of the `go mod` command suite.
    * **Imports:**  The imported packages (`context`, `encoding/json`, `errors`, `os`, `runtime`, `sync`, and `cmd/go/internal` packages) provide hints about the operations involved (context management, JSON handling, error handling, OS interactions, concurrency, and interaction with internal Go command functionalities). Crucially, the `cmd/go/internal/modfetch` and `cmd/go/internal/modload` packages are strong indicators of module downloading and loading.
    * **`cmdDownload` Variable:**  This `base.Command` struct defines the `go mod download` subcommand, including its usage, short and long descriptions, and flags.
    * **Flags:** `downloadJSON` and `downloadReuse` clearly indicate command-line options for JSON output and reusing previous download information.
    * **`init()` Function:** This sets up the command's `Run` function (`runDownload`) and adds flags.
    * **`ModuleJSON` Struct:**  This structure defines the JSON output format, revealing the information tracked for each downloaded module.
    * **`runDownload()` Function:** This is the core logic of the `go mod download` command. I noted the different execution paths depending on whether arguments are provided, whether it's within a module, and the Go version specified in `go.mod`.
    * **`DownloadModule()` Function:** This function performs the actual download of a specific module version.

3. **Deconstruct Functionality Step-by-Step:** I then went through the `runDownload` function logically:
    * **Initialization:**  Setting up module loading (`modload.InitWorkfile`, `modload.ForceUseModules`, `modload.ExplicitWriteGoMod`).
    * **Argument Handling:** Checking for explicit module arguments and handling the case where no arguments are provided. Special attention to main module skipping.
    * **Go Version Awareness:**  Noting the conditional logic based on the `go` directive in `go.mod` (handling differences between Go 1.16 and Go 1.17+).
    * **Module Listing:**  The use of `modload.ListModules` is central to determining the modules to download.
    * **Concurrency:** The use of a semaphore (`sem`) suggests concurrent downloading of modules.
    * **Error Handling and Toolchain Switching:**  The code handles `TooNewError` and attempts to switch Go toolchains if necessary.
    * **JSON Output:** The `-json` flag triggers the output of `ModuleJSON` structs.
    * **Saving Checksums:**  Updating `go.mod` and `go.sum` (or `go.work.sum` in workspace mode) after downloads.
    * **Actual Downloading:** The call to `DownloadModule`.

4. **Identify Go Features Implemented:** Based on the analysis above, I could pinpoint the key Go features:
    * **Command-line Flags:**  The use of `flag` package to define and parse command-line arguments.
    * **Modules:** The entire code revolves around Go modules, including downloading, dependency resolution, and managing `go.mod` and `go.sum`.
    * **Concurrency:** The use of goroutines and a semaphore for parallel downloads.
    * **JSON Encoding/Decoding:**  The `encoding/json` package is used to serialize download information.
    * **Error Handling:**  Standard Go error handling patterns.
    * **Context:**  Using `context.Context` for managing the lifecycle of operations.

5. **Construct Code Examples:** To illustrate the functionality, I devised simple Go code examples that would trigger the `go mod download` command with different options:
    * No arguments:  Illustrates downloading dependencies.
    * Specific module: Shows downloading a particular module and version.
    * `-json` flag: Demonstrates the JSON output.
    * `-reuse` flag:  Illustrates reusing previous download information (though this is more complex to fully demonstrate programmatically).

6. **Infer Assumptions and Inputs/Outputs:**  For the code examples, I made assumptions about the existence of a `go.mod` file and the expected output based on the flags used.

7. **Detail Command-Line Parameter Handling:** I explained the purpose and effect of the `-x`, `-json`, and `-reuse` flags.

8. **Identify Potential Pitfalls:** Based on my understanding of Go modules and the code, I identified common mistakes users might make, such as using `-reuse` within a module or misunderstanding the default behavior of `go mod download` without arguments in different Go versions.

9. **Structure the Response:** Finally, I organized my findings into a clear and logical structure, covering each of the requested points: functionality, implemented Go features, code examples, command-line parameters, and potential pitfalls. I used clear headings and formatting to make the information easy to read and understand.

Throughout this process, I referred back to the code snippet to ensure accuracy and completeness. I also considered the broader context of Go modules to provide a more comprehensive explanation. For instance, recognizing the different behavior before and after Go 1.17 regarding dependency downloads was crucial.
这段代码是 Go 语言 `go` 命令的一部分，具体来说，实现了 `go mod download` 子命令的功能。

**功能概览:**

`go mod download` 命令的主要功能是将指定的 Go 模块及其依赖下载到本地模块缓存中。它有以下几个核心功能：

1. **下载指定的模块:** 可以通过模块路径（如 `golang.org/x/text`）或带有版本查询的模块（如 `golang.org/x/text@v0.3.7`）来指定要下载的模块。
2. **下载主模块的依赖:** 如果不提供任何参数，它会下载构建和测试当前主模块所需的依赖。这个行为会根据 `go.mod` 文件中声明的 Go 版本有所不同。
3. **预填充本地缓存:**  即使在常规构建过程中 Go 命令也会自动下载模块，但 `go mod download` 可以用于提前填充本地模块缓存，这在某些场景下很有用，例如构建环境预热或者为 Go 模块代理提供服务。
4. **提供 JSON 输出:**  通过 `-json` 标志，可以将下载结果以 JSON 格式输出到标准输出，方便程序解析和自动化处理。
5. **复用之前的下载信息:** 通过 `-reuse` 标志，可以指定一个之前 `go mod download -json` 的输出文件，`go` 命令会尝试复用之前下载的模块信息，避免重复下载。
6. **显示执行的命令:** 通过 `-x` 标志，可以打印 `go mod download` 内部执行的命令。

**实现的 Go 语言功能:**

这段代码主要使用了以下 Go 语言功能：

* **标准库:**
    * `context`: 用于控制操作的生命周期，例如超时和取消。
    * `encoding/json`: 用于将下载结果序列化为 JSON 格式。
    * `errors`: 用于创建和处理错误。
    * `os`: 用于进行文件和操作系统相关的操作，例如写入标准错误输出。
    * `runtime`: 用于获取运行时信息，例如 `runtime.GOMAXPROCS` 用于控制并发下载的 Goroutine 数量。
    * `sync`: 用于提供同步机制，例如 `sync.WaitGroup`（虽然这段代码中未使用，但在实际下载场景中可能会用到）和 `sync.Map` 用于并发安全的存储下载错误。
* **`cmd/go/internal` 包:**  这些是 Go 工具链内部的包，提供了与模块管理相关的核心功能：
    * `cmd/go/internal/base`: 提供了 `Command` 结构体，用于定义 `go` 命令的子命令。
    * `cmd/go/internal/cfg`: 提供了 Go 命令的配置管理。
    * `cmd/go/internal/gover`: 提供了 Go 版本比较的功能。
    * `cmd/go/internal/modfetch`: 提供了下载模块、获取模块信息等功能。
    * `cmd/go/internal/modfetch/codehost`:  提供了与代码托管平台交互的相关功能。
    * `cmd/go/internal/modload`: 提供了加载和操作 `go.mod` 文件、解析依赖关系等功能。
    * `cmd/go/internal/toolchain`: 提供了切换 Go 工具链的功能（例如，当需要下载的模块要求更高的 Go 版本时）。
* **第三方库:**
    * `golang.org/x/mod/module`: 提供了与 Go 模块相关的类型定义和工具函数。

**Go 代码举例说明:**

以下是一些使用 `go mod download` 命令的示例，以及可能的输出（假设当前目录下存在一个 `go.mod` 文件）：

**示例 1: 下载所有主模块的依赖 (假设 go.mod 中 `go` 版本低于 1.17)**

```bash
go mod download
```

**假设的输出 (标准错误):**

```
go: downloading golang.org/x/text v0.3.7
go: downloading golang.org/x/crypto v0.0.0-20210817164053-32db79468dac
...
```

**示例 2: 下载特定的模块及其版本**

```bash
go mod download golang.org/x/net@v0.0.0-20220520000938-00093c0c64e6
```

**假设的输出 (标准错误):**

```
go: downloading golang.org/x/net v0.0.0-20220520000938-00093c0c64e6
```

**示例 3: 下载所有主模块的依赖并输出 JSON 格式**

```bash
go mod download -json
```

**假设的输出 (标准输出):**

```json
{
	"Path": "golang.org/x/text",
	"Query": "v0.3.7",
	"Version": "v0.3.7",
	"Info": "/Users/user/go/pkg/mod/cache/download/golang.org/x/text/@v/v0.3.7.info",
	"GoMod": "/Users/user/go/pkg/mod/cache/download/golang.org/x/text/@v/v0.3.7.mod",
	"Zip": "/Users/user/go/pkg/mod/cache/download/golang.org/x/text/@v/v0.3.7.zip",
	"Dir": "/Users/user/go/pkg/mod/cache/download/golang.org/x/text@v0.3.7",
	"Sum": "h1:ool+P54kG1cRmI479xaBlX8RZxT6uLaL6w=="
}
{
	"Path": "golang.org/x/crypto",
	"Query": "v0.0.0-20210817164053-32db79468dac",
	"Version": "v0.0.0-20210817164053-32db79468dac",
	"Info": "/Users/user/go/pkg/mod/cache/download/golang.org/x/crypto/@v/v0.0.0-20210817164053-32db79468dac.info",
	"GoMod": "/Users/user/go/pkg/mod/cache/download/golang.org/x/crypto/@v/v0.0.0-20210817164053-32db79468dac.mod",
	"Zip": "/Users/user/go/pkg/mod/cache/download/golang.org/x/crypto/@v/v0.0.0-20210817164053-32db79468dac.zip",
	"Dir": "/Users/user/go/pkg/mod/cache/download/golang.org/x/crypto@v0.0.0-20210817164053-32db79468dac",
	"Sum": "h1:ABCDEFG..."
}
...
```

**命令行参数的具体处理:**

* **`go mod download`**:  没有参数时，根据 `go.mod` 文件中声明的 Go 版本下载依赖。
    * **Go 1.17 及更高版本:**  只下载 `go.mod` 文件中显式 `require` 的模块。
    * **Go 1.16 及更低版本:** 下载所有传递依赖的模块。
* **`modules`**:  可以指定一个或多个要下载的模块。可以是模块路径（例如 `golang.org/x/sync`）或带有版本查询的模块（例如 `golang.org/x/tools@latest`）。
* **`-x`**: 启用命令执行的追踪，会将 `go mod download` 内部执行的命令打印到标准错误输出。这对于调试很有用。
* **`-json`**: 将下载结果以 JSON 格式输出到标准输出。每个下载成功或失败的模块都会对应一个 JSON 对象。JSON 对象的结构体定义在代码中为 `ModuleJSON`。
* **`-reuse=old.json`**: 指定一个包含之前 `go mod download -json` 输出的文件。`go` 命令会读取这个文件，并尝试复用之前下载的模块信息，避免重复下载。如果一个模块在新的下载过程中没有变化，其对应的 JSON 对象的 `Reuse` 字段会被设置为 `true`。

**使用者易犯错的点:**

1. **在模块内部使用 `-reuse` 标志:**  代码中明确禁止在模块内部（即存在 `go.mod` 文件时）使用 `-reuse` 标志，因为模块缓存已经提供了类似的复用机制。

   ```bash
   # 假设当前目录下有 go.mod 文件
   go mod download -reuse=old.json  # 错误：go mod download -reuse cannot be used inside a module
   ```

2. **对主模块进行下载操作:**  当显式指定要下载的模块时，如果指定的模块解析为主模块自身，`go mod download` 会跳过该操作并输出警告。这通常不是用户想要做的。

   ```bash
   # 假设当前模块路径为 example.com/mymodule
   go mod download example.com/mymodule  # 输出：go: skipping download of example.com/mymodule that resolves to the main module
   go mod download example.com/mymodule@upgrade # 输出类似警告
   go mod download example.com/mymodule@patch   # 输出类似警告
   ```

3. **不理解不同 Go 版本下 `go mod download` 无参数时的行为差异:**  用户可能没有意识到，在 Go 1.17 之前，`go mod download` 不带参数会下载更多的模块（所有传递依赖），而在 Go 1.17 及之后，只会下载 `go.mod` 中显式声明的依赖。这可能会导致在不同 Go 版本下运行相同的命令得到不同的结果。

这段代码的核心逻辑在于与 `modload` 和 `modfetch` 包的交互，它们负责解析模块依赖、从模块源拉取数据以及管理本地模块缓存。`runDownload` 函数 orchestrates these operations，处理命令行参数，并根据不同的场景执行相应的下载逻辑。

### 提示词
```
这是路径为go/src/cmd/go/internal/modcmd/download.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package modcmd

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"sync"

	"cmd/go/internal/base"
	"cmd/go/internal/cfg"
	"cmd/go/internal/gover"
	"cmd/go/internal/modfetch"
	"cmd/go/internal/modfetch/codehost"
	"cmd/go/internal/modload"
	"cmd/go/internal/toolchain"

	"golang.org/x/mod/module"
)

var cmdDownload = &base.Command{
	UsageLine: "go mod download [-x] [-json] [-reuse=old.json] [modules]",
	Short:     "download modules to local cache",
	Long: `
Download downloads the named modules, which can be module patterns selecting
dependencies of the main module or module queries of the form path@version.

With no arguments, download applies to the modules needed to build and test
the packages in the main module: the modules explicitly required by the main
module if it is at 'go 1.17' or higher, or all transitively-required modules
if at 'go 1.16' or lower.

The go command will automatically download modules as needed during ordinary
execution. The "go mod download" command is useful mainly for pre-filling
the local cache or to compute the answers for a Go module proxy.

By default, download writes nothing to standard output. It may print progress
messages and errors to standard error.

The -json flag causes download to print a sequence of JSON objects
to standard output, describing each downloaded module (or failure),
corresponding to this Go struct:

    type Module struct {
        Path     string // module path
        Query    string // version query corresponding to this version
        Version  string // module version
        Error    string // error loading module
        Info     string // absolute path to cached .info file
        GoMod    string // absolute path to cached .mod file
        Zip      string // absolute path to cached .zip file
        Dir      string // absolute path to cached source root directory
        Sum      string // checksum for path, version (as in go.sum)
        GoModSum string // checksum for go.mod (as in go.sum)
        Origin   any    // provenance of module
        Reuse    bool   // reuse of old module info is safe
    }

The -reuse flag accepts the name of file containing the JSON output of a
previous 'go mod download -json' invocation. The go command may use this
file to determine that a module is unchanged since the previous invocation
and avoid redownloading it. Modules that are not redownloaded will be marked
in the new output by setting the Reuse field to true. Normally the module
cache provides this kind of reuse automatically; the -reuse flag can be
useful on systems that do not preserve the module cache.

The -x flag causes download to print the commands download executes.

See https://golang.org/ref/mod#go-mod-download for more about 'go mod download'.

See https://golang.org/ref/mod#version-queries for more about version queries.
	`,
}

var (
	downloadJSON  = cmdDownload.Flag.Bool("json", false, "")
	downloadReuse = cmdDownload.Flag.String("reuse", "", "")
)

func init() {
	cmdDownload.Run = runDownload // break init cycle

	// TODO(jayconrod): https://golang.org/issue/35849 Apply -x to other 'go mod' commands.
	cmdDownload.Flag.BoolVar(&cfg.BuildX, "x", false, "")
	base.AddChdirFlag(&cmdDownload.Flag)
	base.AddModCommonFlags(&cmdDownload.Flag)
}

// A ModuleJSON describes the result of go mod download.
type ModuleJSON struct {
	Path     string `json:",omitempty"`
	Version  string `json:",omitempty"`
	Query    string `json:",omitempty"`
	Error    string `json:",omitempty"`
	Info     string `json:",omitempty"`
	GoMod    string `json:",omitempty"`
	Zip      string `json:",omitempty"`
	Dir      string `json:",omitempty"`
	Sum      string `json:",omitempty"`
	GoModSum string `json:",omitempty"`

	Origin *codehost.Origin `json:",omitempty"`
	Reuse  bool             `json:",omitempty"`
}

func runDownload(ctx context.Context, cmd *base.Command, args []string) {
	modload.InitWorkfile()

	// Check whether modules are enabled and whether we're in a module.
	modload.ForceUseModules = true
	modload.ExplicitWriteGoMod = true
	haveExplicitArgs := len(args) > 0

	if modload.HasModRoot() || modload.WorkFilePath() != "" {
		modload.LoadModFile(ctx) // to fill MainModules

		if haveExplicitArgs {
			for _, mainModule := range modload.MainModules.Versions() {
				targetAtUpgrade := mainModule.Path + "@upgrade"
				targetAtPatch := mainModule.Path + "@patch"
				for _, arg := range args {
					switch arg {
					case mainModule.Path, targetAtUpgrade, targetAtPatch:
						os.Stderr.WriteString("go: skipping download of " + arg + " that resolves to the main module\n")
					}
				}
			}
		} else if modload.WorkFilePath() != "" {
			// TODO(#44435): Think about what the correct query is to download the
			// right set of modules. Also see code review comment at
			// https://go-review.googlesource.com/c/go/+/359794/comments/ce946a80_6cf53992.
			args = []string{"all"}
		} else {
			mainModule := modload.MainModules.Versions()[0]
			modFile := modload.MainModules.ModFile(mainModule)
			if modFile.Go == nil || gover.Compare(modFile.Go.Version, gover.ExplicitIndirectVersion) < 0 {
				if len(modFile.Require) > 0 {
					args = []string{"all"}
				}
			} else {
				// As of Go 1.17, the go.mod file explicitly requires every module
				// that provides any package imported by the main module.
				// 'go mod download' is typically run before testing packages in the
				// main module, so by default we shouldn't download the others
				// (which are presumed irrelevant to the packages in the main module).
				// See https://golang.org/issue/44435.
				//
				// However, we also need to load the full module graph, to ensure that
				// we have downloaded enough of the module graph to run 'go list all',
				// 'go mod graph', and similar commands.
				_, err := modload.LoadModGraph(ctx, "")
				if err != nil {
					// TODO(#64008): call base.Fatalf instead of toolchain.SwitchOrFatal
					// here, since we can only reach this point with an outdated toolchain
					// if the go.mod file is inconsistent.
					toolchain.SwitchOrFatal(ctx, err)
				}

				for _, m := range modFile.Require {
					args = append(args, m.Mod.Path)
				}
			}
		}
	}

	if len(args) == 0 {
		if modload.HasModRoot() {
			os.Stderr.WriteString("go: no module dependencies to download\n")
		} else {
			base.Errorf("go: no modules specified (see 'go help mod download')")
		}
		base.Exit()
	}

	if *downloadReuse != "" && modload.HasModRoot() {
		base.Fatalf("go mod download -reuse cannot be used inside a module")
	}

	var mods []*ModuleJSON
	type token struct{}
	sem := make(chan token, runtime.GOMAXPROCS(0))
	infos, infosErr := modload.ListModules(ctx, args, 0, *downloadReuse)

	// There is a bit of a chicken-and-egg problem here: ideally we need to know
	// which Go version to switch to download the requested modules, but if we
	// haven't downloaded the module's go.mod file yet the GoVersion field of its
	// info struct is not yet populated.
	//
	// We also need to be careful to only print the info for each module once
	// if the -json flag is set.
	//
	// In theory we could go through each module in the list, attempt to download
	// its go.mod file, and record the maximum version (either from the file or
	// from the resulting TooNewError), all before we try the actual full download
	// of each module.
	//
	// For now, we go ahead and try all the downloads and collect the errors, and
	// if any download failed due to a TooNewError, we switch toolchains and try
	// again. Any downloads that already succeeded will still be in cache.
	// That won't give optimal concurrency (we'll do two batches of concurrent
	// downloads instead of all in one batch), and it might add a little overhead
	// to look up the downloads from the first batch in the module cache when
	// we see them again in the second batch. On the other hand, it's way simpler
	// to implement, and not really any more expensive if the user is requesting
	// no explicit arguments (their go.mod file should already list an appropriate
	// toolchain version) or only one module (as is used by the Go Module Proxy).

	if infosErr != nil {
		var sw toolchain.Switcher
		sw.Error(infosErr)
		if sw.NeedSwitch() {
			sw.Switch(ctx)
		}
		// Otherwise, wait to report infosErr after we have downloaded
		// when we can.
	}

	if !haveExplicitArgs && modload.WorkFilePath() == "" {
		// 'go mod download' is sometimes run without arguments to pre-populate the
		// module cache. In modules that aren't at go 1.17 or higher, it may fetch
		// modules that aren't needed to build packages in the main module. This is
		// usually not intended, so don't save sums for downloaded modules
		// (golang.org/issue/45332). We do still fix inconsistencies in go.mod
		// though.
		//
		// TODO(#64008): In the future, report an error if go.mod or go.sum need to
		// be updated after loading the build list. This may require setting
		// the mode to "mod" or "readonly" depending on haveExplicitArgs.
		if err := modload.WriteGoMod(ctx, modload.WriteOpts{}); err != nil {
			base.Fatal(err)
		}
	}

	var downloadErrs sync.Map
	for _, info := range infos {
		if info.Replace != nil {
			info = info.Replace
		}
		if info.Version == "" && info.Error == nil {
			// main module or module replaced with file path.
			// Nothing to download.
			continue
		}
		m := &ModuleJSON{
			Path:    info.Path,
			Version: info.Version,
			Query:   info.Query,
			Reuse:   info.Reuse,
			Origin:  info.Origin,
		}
		mods = append(mods, m)
		if info.Error != nil {
			m.Error = info.Error.Err
			continue
		}
		if m.Reuse {
			continue
		}
		sem <- token{}
		go func() {
			err := DownloadModule(ctx, m)
			if err != nil {
				downloadErrs.Store(m, err)
				m.Error = err.Error()
			}
			<-sem
		}()
	}

	// Fill semaphore channel to wait for goroutines to finish.
	for n := cap(sem); n > 0; n-- {
		sem <- token{}
	}

	// If there were explicit arguments
	// (like 'go mod download golang.org/x/tools@latest'),
	// check whether we need to upgrade the toolchain in order to download them.
	//
	// (If invoked without arguments, we expect the module graph to already
	// be tidy and the go.mod file to declare a 'go' version that satisfies
	// transitive requirements. If that invariant holds, then we should have
	// already upgraded when we loaded the module graph, and should not need
	// an additional check here. See https://go.dev/issue/45551.)
	//
	// We also allow upgrades if in a workspace because in workspace mode
	// with no arguments we download the module pattern "all",
	// which may include dependencies that are normally pruned out
	// of the individual modules in the workspace.
	if haveExplicitArgs || modload.WorkFilePath() != "" {
		var sw toolchain.Switcher
		// Add errors to the Switcher in deterministic order so that they will be
		// logged deterministically.
		for _, m := range mods {
			if erri, ok := downloadErrs.Load(m); ok {
				sw.Error(erri.(error))
			}
		}
		// Only call sw.Switch if it will actually switch.
		// Otherwise, we may want to write the errors as JSON
		// (instead of using base.Error as sw.Switch would),
		// and we may also have other errors to report from the
		// initial infos returned by ListModules.
		if sw.NeedSwitch() {
			sw.Switch(ctx)
		}
	}

	if *downloadJSON {
		for _, m := range mods {
			b, err := json.MarshalIndent(m, "", "\t")
			if err != nil {
				base.Fatal(err)
			}
			os.Stdout.Write(append(b, '\n'))
			if m.Error != "" {
				base.SetExitStatus(1)
			}
		}
	} else {
		for _, m := range mods {
			if m.Error != "" {
				base.Error(errors.New(m.Error))
			}
		}
		base.ExitIfErrors()
	}

	// If there were explicit arguments, update go.mod and especially go.sum.
	// 'go mod download mod@version' is a useful way to add a sum without using
	// 'go get mod@version', which may have other side effects. We print this in
	// some error message hints.
	//
	// If we're in workspace mode, update go.work.sum with checksums for all of
	// the modules we downloaded that aren't already recorded. Since a requirement
	// in one module may upgrade a dependency of another, we can't be sure that
	// the import graph matches the import graph of any given module in isolation,
	// so we may end up needing to load packages from modules that wouldn't
	// otherwise be relevant.
	//
	// TODO(#44435): If we adjust the set of modules downloaded in workspace mode,
	// we may also need to adjust the logic for saving checksums here.
	//
	// Don't save sums for 'go mod download' without arguments unless we're in
	// workspace mode; see comment above.
	if haveExplicitArgs || modload.WorkFilePath() != "" {
		if err := modload.WriteGoMod(ctx, modload.WriteOpts{}); err != nil {
			base.Error(err)
		}
	}

	// If there was an error matching some of the requested packages, emit it now
	// (after we've written the checksums for the modules that were downloaded
	// successfully).
	if infosErr != nil {
		base.Error(infosErr)
	}
}

// DownloadModule runs 'go mod download' for m.Path@m.Version,
// leaving the results (including any error) in m itself.
func DownloadModule(ctx context.Context, m *ModuleJSON) error {
	var err error
	_, file, err := modfetch.InfoFile(ctx, m.Path, m.Version)
	if err != nil {
		return err
	}
	m.Info = file
	m.GoMod, err = modfetch.GoModFile(ctx, m.Path, m.Version)
	if err != nil {
		return err
	}
	m.GoModSum, err = modfetch.GoModSum(ctx, m.Path, m.Version)
	if err != nil {
		return err
	}
	mod := module.Version{Path: m.Path, Version: m.Version}
	m.Zip, err = modfetch.DownloadZip(ctx, mod)
	if err != nil {
		return err
	}
	m.Sum = modfetch.Sum(ctx, mod)
	m.Dir, err = modfetch.Download(ctx, mod)
	return err
}
```