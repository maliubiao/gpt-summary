Response: Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding of the Goal:**

The request asks for the functionality of `action.go`, its relation to Go features, code examples, command-line parameter handling, and common mistakes. The core is understanding the "action graph" concept.

**2. Keyword Recognition and Core Concepts:**

Scanning the code immediately reveals key terms:

* `Action`, `Builder`:  These are central data structures.
* `Deps`:  Suggests dependencies between actions.
* `Actor`:  An interface for executing actions.
* `cache`:  Indicates optimization and avoiding redundant work.
* `CompileAction`, `LinkAction`, `VetAction`, `installAction`: These strongly suggest the core phases of the Go build process.
* `BuildMode`, `ModeInstall`, `ModeBuild`: Different ways of handling the output.
* `WorkDir`:  A temporary directory for build artifacts.

This suggests the file is about orchestrating the build process by creating a dependency graph of tasks (actions).

**3. Analyzing the `Builder` struct:**

The `Builder` struct holds global build state. Key fields:

* `WorkDir`:  Confirms the temporary directory idea.
* `actionCache`:  Crucial for understanding how actions are reused.
* `flagCache`, `gccCompilerIDCache`, `toolIDCache`, `buildIDCache`: More caches, hinting at performance optimizations and tracking build artifacts.
* `IsCmdList`, `NeedError`, etc.: Flags related to `go list`, showing integration with other Go tools.
* `readySema`, `ready`:  Suggests concurrent execution of actions.

**4. Analyzing the `Action` struct:**

The `Action` struct represents a single build step. Key fields:

* `Mode`: The type of action (compile, link, vet, etc.).
* `Package`: The Go package the action operates on.
* `Deps`:  The dependency relationship.
* `Actor`:  The actual code to run for this action.
* `Objdir`, `Target`, `built`:  File system paths associated with the action.
* `actionID`, `buildID`:  Cache keys and identifiers for build outputs.

**5. Identifying Key Functions and Their Roles:**

* `NewBuilder`: Initializes the build process. The handling of `workDir` and the creation of the temporary directory are important.
* `Close`: Cleans up the temporary directory.
* `cacheAction`: The core caching mechanism. The `cacheKey` struct is important to note.
* `AutoAction`:  Chooses the correct action (compile or link) based on whether it's a `main` package.
* `CompileAction`: Responsible for compiling Go packages. The handling of dependencies is crucial.
* `LinkAction`:  Responsible for linking compiled packages into an executable.
* `VetAction`:  Responsible for running `go vet`.
* `installAction`:  Handles the installation of the built artifacts.
* `addTransitiveLinkDeps`:  Ensures all necessary dependencies are included in the linking process.
* `linkSharedAction`:  Deals with building shared libraries.

**6. Connecting to Go Features:**

By understanding the key functions, we can directly connect them to Go features:

* **`go build`**:  `CompileAction` and `LinkAction` are the heart of `go build`. The handling of `main` packages is directly relevant.
* **`go install`**: `installAction` handles placing the built binaries or packages in the correct locations.
* **`go vet`**:  `VetAction` directly implements the static analysis tool.
* **Build Modes (`-buildmode`)**:  `linkSharedAction` illustrates the handling of shared libraries. The `BuildMode` enum itself is relevant here.
* **Caching**:  The `actionCache` and the various ID fields (`actionID`, `buildID`) are fundamental to Go's build caching.

**7. Constructing Code Examples:**

Based on the identified functions, it becomes relatively straightforward to create examples:

* **`go build` (library)**:  Illustrate `CompileAction`.
* **`go build` (executable)**: Illustrate `CompileAction` and `LinkAction`.
* **`go install`**:  Show how `installAction` is triggered.
* **`go vet`**: Demonstrate the usage of `VetAction`.
* **`go build -buildmode=shared`**:  Highlight `linkSharedAction`.

**8. Analyzing Command-Line Parameter Handling:**

Focus on areas where command-line flags influence the behavior:

* The `Builder` struct has fields like `IsCmdList`, which are clearly tied to command-line flags.
* The `NewBuilder` function's logic for creating `WorkDir` depends on `cfg.BuildN` and `cfg.BuildWork`.
* The logic in `linkSharedAction` is explicitly conditional on `cfg.BuildLinkshared`.
* The `installAction` and `addInstallHeaderAction` consider `cfg.BuildBuildmode`.

**9. Identifying Potential User Mistakes:**

Think about common errors users make related to these build steps:

* **Forgetting to import dependencies:** This would likely surface during the `CompileAction` phase.
* **Incorrect `GOOS`/`GOARCH` settings:** The `CheckGOOSARCHPair` function is a clear indicator of this issue.
* **Problems with shared libraries:**  The complexity around `linkSharedAction` suggests potential issues with its usage.

**10. Iterative Refinement and Review:**

After the initial analysis, review the code again to ensure all key aspects have been covered. For instance, notice the `Actor` interface and its `Act` method. This confirms the action graph execution model. Pay attention to comments like "NOTE: Much of Action would not need to be exported if not for test." This hints at the testing strategy.

This systematic approach of identifying keywords, analyzing data structures and functions, connecting to Go features, and thinking about practical usage leads to a comprehensive understanding of the code's functionality.
这段代码是 Go 语言 `cmd/go` 工具中负责**构建动作图（Action Graph）**的核心部分。它定义了构建过程中的各种操作以及它们之间的依赖关系，最终形成一个可以被执行的任务队列。

以下是其主要功能：

**1. 定义构建的核心数据结构：**

* **`Builder`:**  存储全局构建状态，例如临时工作目录、已创建的动作缓存、编译器标志缓存等。它不存储每个包的状态，因为包是并行构建的。
* **`Action`:**  代表构建过程中的一个单独的动作，例如编译一个包、链接生成可执行文件、运行 vet 工具等。它包含了动作的类型 (`Mode`)、操作的包 (`Package`)、依赖的动作 (`Deps`)、实际执行者 (`Actor`)、目标文件 (`Target`) 等信息。
* **`Actor` 和 `ActorFunc`:**  定义了执行 `Action` 的接口和实现方式。
* **`actionQueue`:**  一个优先级队列，用于存储待执行的 `Action`，优先级高的先执行。

**2. 实现构建动作的创建和缓存：**

* **`NewBuilder(workDir string)`:** 创建一个新的 `Builder` 实例，负责初始化构建环境，包括创建临时工作目录。
* **`cacheAction(mode string, p *load.Package, f func() *Action) *Action`:**  核心的缓存机制。它根据 `mode` 和 `Package` 查找已存在的 `Action`。如果不存在，则调用 `f()` 创建新的 `Action` 并缓存。这避免了重复创建相同的构建步骤。

**3. 定义各种构建动作的创建函数：**

* **`AutoAction(mode, depMode BuildMode, p *load.Package) *Action`:**  根据包的类型（`main` 包或普通包）选择合适的动作（链接或编译）。
* **`CompileAction(mode, depMode BuildMode, p *load.Package) *Action`:**  创建编译指定包的 `Action`。它会处理依赖关系，确保依赖的包先被编译。
* **`VetAction(mode, depMode BuildMode, p *load.Package) *Action` 和 `vetAction(...)`:** 创建运行 `go vet` 工具检查指定包的 `Action`。它依赖于包的编译动作。
* **`LinkAction(mode, depMode BuildMode, p *load.Package) *Action`:** 创建链接指定 `main` 包生成可执行文件的 `Action`。它依赖于包的编译动作以及所有传递依赖的包。
* **`installAction(a1 *Action, mode BuildMode) *Action`:**  创建安装构建结果的 `Action`。它依赖于构建动作。
* **`linkSharedAction(mode, depMode BuildMode, shlib string, a1 *Action) *Action`:** 创建构建共享库的 `Action`。
* **`addTransitiveLinkDeps(a, a1 *Action, shlib string)`:**  为链接动作添加所有传递依赖的包，确保链接器能找到所有必要的代码。
* **`addInstallHeaderAction(a *Action)`:** 为安装动作添加安装头文件的步骤（用于 C 代码互操作）。

**4. 处理构建模式：**

* **`BuildMode` 枚举：** 定义了构建的模式，例如 `ModeBuild` (仅构建)、`ModeInstall` (构建并安装) 等。 这些模式会影响 `Action` 的创建和执行。

**5. 处理临时工作目录：**

* **`NewObjdir() string`:** 在临时工作目录下创建一个新的子目录，用于存放构建中间产物。
* **`Close() error`:**  清理临时工作目录。

**推理其实现的 Go 语言功能：**

这段代码主要实现了 `go build` 和 `go install` 命令的核心逻辑，以及 `go vet` 的集成。它负责规划构建过程，确定哪些包需要编译、链接，以及它们之间的顺序依赖关系。

**Go 代码举例说明：**

假设我们有一个简单的 Go 项目结构：

```
myproject/
├── main.go
└── pkg/
    └── util.go
```

`main.go`:

```go
package main

import (
	"fmt"
	"myproject/pkg"
)

func main() {
	fmt.Println(pkg.Hello())
}
```

`pkg/util.go`:

```go
package pkg

func Hello() string {
	return "Hello, World!"
}
```

当我们执行 `go build` 命令时，`action.go` 中的代码会生成如下的动作图（简化版）：

1. **编译 `myproject/pkg`:**
   * `Action.Mode`: "build"
   * `Action.Package`: 指向 `myproject/pkg` 的 `load.Package`
   * `Action.Actor`: `buildActor` 实例，负责执行编译操作
   * `Action.Target`:  指向编译生成的 `.a` 文件（例如在 `$WORK/b001/_pkg_.a`）

2. **编译 `myproject` (main 包):**
   * `Action.Mode`: "build"
   * `Action.Package`: 指向 `myproject` 的 `load.Package`
   * `Action.Actor`: `buildActor` 实例
   * `Action.Deps`: 包含上一步编译 `myproject/pkg` 的 `Action`

3. **链接 `myproject`:**
   * `Action.Mode`: "link"
   * `Action.Package`: 指向 `myproject` 的 `load.Package`
   * `Action.Actor`: 指向 `(*Builder).link` 方法的 `ActorFunc`
   * `Action.Deps`: 包含上一步编译 `myproject` 和 `myproject/pkg` 的 `Action`
   * `Action.Target`: 指向最终生成的可执行文件（例如在 `$WORK/b001/exe/myproject`）

**假设的输入与输出 (代码推理)：**

假设 `CompileAction` 函数处理 `myproject/pkg` 包：

* **输入:**
    * `mode`: `ModeBuild`
    * `depMode`: `ModeBuild`
    * `p`: 指向 `myproject/pkg` 的 `load.Package` 实例

* **输出:**
    * 一个 `Action` 实例，其关键字段如下：
        * `Mode`: "build"
        * `Package`:  与输入 `p` 相同
        * `Actor`:  `newBuildActor(p, false)` 的返回值
        * `Objdir`: 例如 `$WORK/b001/`
        * `Target`: 例如 `$WORK/b001/_pkg_.a`
        * `Deps`:  如果 `myproject/pkg` 还有其他依赖，则包含其他 `CompileAction` 的 `Action` 实例。

**命令行参数的具体处理：**

这段代码本身不直接处理命令行参数，而是依赖于 `cmd/go/internal/cfg` 包来获取和解析命令行参数。但是，从代码中可以看出命令行参数如何影响构建过程：

* **`-n` (BuildN):**  如果设置了 `-n` (只打印命令不执行)，`NewBuilder` 创建的 `WorkDir` 将是 "$WORK"。
* **`-x` (BuildX):** 如果设置了 `-x` (打印执行的命令)，`NewBuilder` 会打印 `WORK` 环境变量。
* **`-work` (BuildWork):** 如果设置了 `-work` (保留工作目录)，`Close` 函数不会删除临时工作目录。
* **`-tags`:**  `NewBuilder` 中会检查 `-tags` 参数的格式。
* **`-buildmode`:** `linkSharedAction` 的调用和 `addInstallHeaderAction` 的逻辑会根据 `-buildmode` 的值进行调整。
* **`-ldflags` 和 `-gcflags`:**  这些标志会影响 `Action` 中 `Args` 的值，并最终传递给编译器和链接器。

**使用者易犯错的点：**

虽然用户不直接与这段代码交互，但理解其背后的逻辑有助于避免一些常见的构建错误：

* **依赖管理问题:**  如果一个包缺少必要的依赖，`CompileAction` 会因为无法加载依赖包而失败。这通常会导致 "package not found" 类似的错误。
* **`GOOS` 和 `GOARCH` 设置错误:** `CheckGOOSARCHPair` 函数会在构建开始时检查目标操作系统和架构的配置是否有效。配置错误会导致构建失败。
* **交叉编译问题:**  如果交叉编译环境配置不当，可能会导致构建工具链找不到或不兼容，从而导致构建失败。
* **共享库构建的复杂性:**  使用 `-buildmode=shared` 构建共享库需要对依赖关系和链接过程有更深入的理解，容易出错。例如，忘记包含必要的依赖包会导致运行时链接错误。

总而言之，`action.go` 是 `go build` 和相关命令的核心大脑，负责组织和规划构建过程。理解它的功能有助于深入理解 Go 的构建机制。

### 提示词
```
这是路径为go/src/cmd/go/internal/work/action.go的go语言实现的一部分， 请列举一下它的功能, 　
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

// Action graph creation (planning).

package work

import (
	"bufio"
	"bytes"
	"cmd/internal/cov/covcmd"
	"container/heap"
	"context"
	"debug/elf"
	"encoding/json"
	"fmt"
	"internal/platform"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cmd/go/internal/base"
	"cmd/go/internal/cache"
	"cmd/go/internal/cfg"
	"cmd/go/internal/load"
	"cmd/go/internal/str"
	"cmd/go/internal/trace"
	"cmd/internal/buildid"
	"cmd/internal/robustio"
)

// A Builder holds global state about a build.
// It does not hold per-package state, because we
// build packages in parallel, and the builder is shared.
type Builder struct {
	WorkDir            string                    // the temporary work directory (ends in filepath.Separator)
	actionCache        map[cacheKey]*Action      // a cache of already-constructed actions
	flagCache          map[[2]string]bool        // a cache of supported compiler flags
	gccCompilerIDCache map[string]cache.ActionID // cache for gccCompilerID

	IsCmdList           bool // running as part of go list; set p.Stale and additional fields below
	NeedError           bool // list needs p.Error
	NeedExport          bool // list needs p.Export
	NeedCompiledGoFiles bool // list needs p.CompiledGoFiles
	AllowErrors         bool // errors don't immediately exit the program

	objdirSeq int // counter for NewObjdir
	pkgSeq    int

	backgroundSh *Shell // Shell that per-Action Shells are derived from

	exec      sync.Mutex
	readySema chan bool
	ready     actionQueue

	id           sync.Mutex
	toolIDCache  map[string]string // tool name -> tool ID
	buildIDCache map[string]string // file name -> build ID
}

// NOTE: Much of Action would not need to be exported if not for test.
// Maybe test functionality should move into this package too?

// An Actor runs an action.
type Actor interface {
	Act(*Builder, context.Context, *Action) error
}

// An ActorFunc is an Actor that calls the function.
type ActorFunc func(*Builder, context.Context, *Action) error

func (f ActorFunc) Act(b *Builder, ctx context.Context, a *Action) error {
	return f(b, ctx, a)
}

// An Action represents a single action in the action graph.
type Action struct {
	Mode       string        // description of action operation
	Package    *load.Package // the package this action works on
	Deps       []*Action     // actions that must happen before this one
	Actor      Actor         // the action itself (nil = no-op)
	IgnoreFail bool          // whether to run f even if dependencies fail
	TestOutput *bytes.Buffer // test output buffer
	Args       []string      // additional args for runProgram

	triggers []*Action // inverse of deps

	buggyInstall bool // is this a buggy install (see -linkshared)?

	TryCache func(*Builder, *Action) bool // callback for cache bypass

	CacheExecutable bool // Whether to cache executables produced by link steps

	// Generated files, directories.
	Objdir   string         // directory for intermediate objects
	Target   string         // goal of the action: the created package or executable
	built    string         // the actual created package or executable
	actionID cache.ActionID // cache ID of action input
	buildID  string         // build ID of action output

	VetxOnly  bool       // Mode=="vet": only being called to supply info about dependencies
	needVet   bool       // Mode=="build": need to fill in vet config
	needBuild bool       // Mode=="build": need to do actual build (can be false if needVet is true)
	vetCfg    *vetConfig // vet config
	output    []byte     // output redirect buffer (nil means use b.Print)

	sh *Shell // lazily created per-Action shell; see Builder.Shell

	// Execution state.
	pending      int               // number of deps yet to complete
	priority     int               // relative execution priority
	Failed       *Action           // set to root cause if the action failed
	json         *actionJSON       // action graph information
	nonGoOverlay map[string]string // map from non-.go source files to copied files in objdir. Nil if no overlay is used.
	traceSpan    *trace.Span
}

// BuildActionID returns the action ID section of a's build ID.
func (a *Action) BuildActionID() string { return actionID(a.buildID) }

// BuildContentID returns the content ID section of a's build ID.
func (a *Action) BuildContentID() string { return contentID(a.buildID) }

// BuildID returns a's build ID.
func (a *Action) BuildID() string { return a.buildID }

// BuiltTarget returns the actual file that was built. This differs
// from Target when the result was cached.
func (a *Action) BuiltTarget() string { return a.built }

// An actionQueue is a priority queue of actions.
type actionQueue []*Action

// Implement heap.Interface
func (q *actionQueue) Len() int           { return len(*q) }
func (q *actionQueue) Swap(i, j int)      { (*q)[i], (*q)[j] = (*q)[j], (*q)[i] }
func (q *actionQueue) Less(i, j int) bool { return (*q)[i].priority < (*q)[j].priority }
func (q *actionQueue) Push(x any)         { *q = append(*q, x.(*Action)) }
func (q *actionQueue) Pop() any {
	n := len(*q) - 1
	x := (*q)[n]
	*q = (*q)[:n]
	return x
}

func (q *actionQueue) push(a *Action) {
	if a.json != nil {
		a.json.TimeReady = time.Now()
	}
	heap.Push(q, a)
}

func (q *actionQueue) pop() *Action {
	return heap.Pop(q).(*Action)
}

type actionJSON struct {
	ID         int
	Mode       string
	Package    string
	Deps       []int     `json:",omitempty"`
	IgnoreFail bool      `json:",omitempty"`
	Args       []string  `json:",omitempty"`
	Link       bool      `json:",omitempty"`
	Objdir     string    `json:",omitempty"`
	Target     string    `json:",omitempty"`
	Priority   int       `json:",omitempty"`
	Failed     bool      `json:",omitempty"`
	Built      string    `json:",omitempty"`
	VetxOnly   bool      `json:",omitempty"`
	NeedVet    bool      `json:",omitempty"`
	NeedBuild  bool      `json:",omitempty"`
	ActionID   string    `json:",omitempty"`
	BuildID    string    `json:",omitempty"`
	TimeReady  time.Time `json:",omitempty"`
	TimeStart  time.Time `json:",omitempty"`
	TimeDone   time.Time `json:",omitempty"`

	Cmd     []string      // `json:",omitempty"`
	CmdReal time.Duration `json:",omitempty"`
	CmdUser time.Duration `json:",omitempty"`
	CmdSys  time.Duration `json:",omitempty"`
}

// cacheKey is the key for the action cache.
type cacheKey struct {
	mode string
	p    *load.Package
}

func actionGraphJSON(a *Action) string {
	var workq []*Action
	var inWorkq = make(map[*Action]int)

	add := func(a *Action) {
		if _, ok := inWorkq[a]; ok {
			return
		}
		inWorkq[a] = len(workq)
		workq = append(workq, a)
	}
	add(a)

	for i := 0; i < len(workq); i++ {
		for _, dep := range workq[i].Deps {
			add(dep)
		}
	}

	list := make([]*actionJSON, 0, len(workq))
	for id, a := range workq {
		if a.json == nil {
			a.json = &actionJSON{
				Mode:       a.Mode,
				ID:         id,
				IgnoreFail: a.IgnoreFail,
				Args:       a.Args,
				Objdir:     a.Objdir,
				Target:     a.Target,
				Failed:     a.Failed != nil,
				Priority:   a.priority,
				Built:      a.built,
				VetxOnly:   a.VetxOnly,
				NeedBuild:  a.needBuild,
				NeedVet:    a.needVet,
			}
			if a.Package != nil {
				// TODO(rsc): Make this a unique key for a.Package somehow.
				a.json.Package = a.Package.ImportPath
			}
			for _, a1 := range a.Deps {
				a.json.Deps = append(a.json.Deps, inWorkq[a1])
			}
		}
		list = append(list, a.json)
	}

	js, err := json.MarshalIndent(list, "", "\t")
	if err != nil {
		fmt.Fprintf(os.Stderr, "go: writing debug action graph: %v\n", err)
		return ""
	}
	return string(js)
}

// BuildMode specifies the build mode:
// are we just building things or also installing the results?
type BuildMode int

const (
	ModeBuild BuildMode = iota
	ModeInstall
	ModeBuggyInstall

	ModeVetOnly = 1 << 8
)

// NewBuilder returns a new Builder ready for use.
//
// If workDir is the empty string, NewBuilder creates a WorkDir if needed
// and arranges for it to be removed in case of an unclean exit.
// The caller must Close the builder explicitly to clean up the WorkDir
// before a clean exit.
func NewBuilder(workDir string) *Builder {
	b := new(Builder)

	b.actionCache = make(map[cacheKey]*Action)
	b.toolIDCache = make(map[string]string)
	b.buildIDCache = make(map[string]string)

	printWorkDir := false
	if workDir != "" {
		b.WorkDir = workDir
	} else if cfg.BuildN {
		b.WorkDir = "$WORK"
	} else {
		if !buildInitStarted {
			panic("internal error: NewBuilder called before BuildInit")
		}
		tmp, err := os.MkdirTemp(cfg.Getenv("GOTMPDIR"), "go-build")
		if err != nil {
			base.Fatalf("go: creating work dir: %v", err)
		}
		if !filepath.IsAbs(tmp) {
			abs, err := filepath.Abs(tmp)
			if err != nil {
				os.RemoveAll(tmp)
				base.Fatalf("go: creating work dir: %v", err)
			}
			tmp = abs
		}
		b.WorkDir = tmp
		builderWorkDirs.Store(b, b.WorkDir)
		printWorkDir = cfg.BuildX || cfg.BuildWork
	}

	b.backgroundSh = NewShell(b.WorkDir, nil)

	if printWorkDir {
		b.BackgroundShell().Printf("WORK=%s\n", b.WorkDir)
	}

	if err := CheckGOOSARCHPair(cfg.Goos, cfg.Goarch); err != nil {
		fmt.Fprintf(os.Stderr, "go: %v\n", err)
		base.SetExitStatus(2)
		base.Exit()
	}

	for _, tag := range cfg.BuildContext.BuildTags {
		if strings.Contains(tag, ",") {
			fmt.Fprintf(os.Stderr, "go: -tags space-separated list contains comma\n")
			base.SetExitStatus(2)
			base.Exit()
		}
	}

	return b
}

var builderWorkDirs sync.Map // *Builder → WorkDir

func (b *Builder) Close() error {
	wd, ok := builderWorkDirs.Load(b)
	if !ok {
		return nil
	}
	defer builderWorkDirs.Delete(b)

	if b.WorkDir != wd.(string) {
		base.Errorf("go: internal error: Builder WorkDir unexpectedly changed from %s to %s", wd, b.WorkDir)
	}

	if !cfg.BuildWork {
		if err := robustio.RemoveAll(b.WorkDir); err != nil {
			return err
		}
	}
	b.WorkDir = ""
	return nil
}

func closeBuilders() {
	leakedBuilders := 0
	builderWorkDirs.Range(func(bi, _ any) bool {
		leakedBuilders++
		if err := bi.(*Builder).Close(); err != nil {
			base.Error(err)
		}
		return true
	})

	if leakedBuilders > 0 && base.GetExitStatus() == 0 {
		fmt.Fprintf(os.Stderr, "go: internal error: Builder leaked on successful exit\n")
		base.SetExitStatus(1)
	}
}

func CheckGOOSARCHPair(goos, goarch string) error {
	if !platform.BuildModeSupported(cfg.BuildContext.Compiler, "default", goos, goarch) {
		return fmt.Errorf("unsupported GOOS/GOARCH pair %s/%s", goos, goarch)
	}
	return nil
}

// NewObjdir returns the name of a fresh object directory under b.WorkDir.
// It is up to the caller to call b.Mkdir on the result at an appropriate time.
// The result ends in a slash, so that file names in that directory
// can be constructed with direct string addition.
//
// NewObjdir must be called only from a single goroutine at a time,
// so it is safe to call during action graph construction, but it must not
// be called during action graph execution.
func (b *Builder) NewObjdir() string {
	b.objdirSeq++
	return str.WithFilePathSeparator(filepath.Join(b.WorkDir, fmt.Sprintf("b%03d", b.objdirSeq)))
}

// readpkglist returns the list of packages that were built into the shared library
// at shlibpath. For the native toolchain this list is stored, newline separated, in
// an ELF note with name "Go\x00\x00" and type 1. For GCCGO it is extracted from the
// .go_export section.
func readpkglist(shlibpath string) (pkgs []*load.Package) {
	var stk load.ImportStack
	if cfg.BuildToolchainName == "gccgo" {
		f, err := elf.Open(shlibpath)
		if err != nil {
			base.Fatal(fmt.Errorf("failed to open shared library: %v", err))
		}
		defer f.Close()
		sect := f.Section(".go_export")
		if sect == nil {
			base.Fatal(fmt.Errorf("%s: missing .go_export section", shlibpath))
		}
		data, err := sect.Data()
		if err != nil {
			base.Fatal(fmt.Errorf("%s: failed to read .go_export section: %v", shlibpath, err))
		}
		pkgpath := []byte("pkgpath ")
		for _, line := range bytes.Split(data, []byte{'\n'}) {
			if path, found := bytes.CutPrefix(line, pkgpath); found {
				path = bytes.TrimSuffix(path, []byte{';'})
				pkgs = append(pkgs, load.LoadPackageWithFlags(string(path), base.Cwd(), &stk, nil, 0))
			}
		}
	} else {
		pkglistbytes, err := buildid.ReadELFNote(shlibpath, "Go\x00\x00", 1)
		if err != nil {
			base.Fatalf("readELFNote failed: %v", err)
		}
		scanner := bufio.NewScanner(bytes.NewBuffer(pkglistbytes))
		for scanner.Scan() {
			t := scanner.Text()
			pkgs = append(pkgs, load.LoadPackageWithFlags(t, base.Cwd(), &stk, nil, 0))
		}
	}
	return
}

// cacheAction looks up {mode, p} in the cache and returns the resulting action.
// If the cache has no such action, f() is recorded and returned.
// TODO(rsc): Change the second key from *load.Package to interface{},
// to make the caching in linkShared less awkward?
func (b *Builder) cacheAction(mode string, p *load.Package, f func() *Action) *Action {
	a := b.actionCache[cacheKey{mode, p}]
	if a == nil {
		a = f()
		b.actionCache[cacheKey{mode, p}] = a
	}
	return a
}

// AutoAction returns the "right" action for go build or go install of p.
func (b *Builder) AutoAction(mode, depMode BuildMode, p *load.Package) *Action {
	if p.Name == "main" {
		return b.LinkAction(mode, depMode, p)
	}
	return b.CompileAction(mode, depMode, p)
}

// buildActor implements the Actor interface for package build
// actions. For most package builds this simply means invoking th
// *Builder.build method; in the case of "go test -cover" for
// a package with no test files, we stores some additional state
// information in the build actor to help with reporting.
type buildActor struct {
	// name of static meta-data file fragment emitted by the cover
	// tool as part of the package build action, for selected
	// "go test -cover" runs.
	covMetaFileName string
}

// newBuildActor returns a new buildActor object, setting up the
// covMetaFileName field if 'genCoverMeta' flag is set.
func newBuildActor(p *load.Package, genCoverMeta bool) *buildActor {
	ba := &buildActor{}
	if genCoverMeta {
		ba.covMetaFileName = covcmd.MetaFileForPackage(p.ImportPath)
	}
	return ba
}

func (ba *buildActor) Act(b *Builder, ctx context.Context, a *Action) error {
	return b.build(ctx, a)
}

// pgoActionID computes the action ID for a preprocess PGO action.
func (b *Builder) pgoActionID(input string) cache.ActionID {
	h := cache.NewHash("preprocess PGO profile " + input)

	fmt.Fprintf(h, "preprocess PGO profile\n")
	fmt.Fprintf(h, "preprofile %s\n", b.toolID("preprofile"))
	fmt.Fprintf(h, "input %q\n", b.fileHash(input))

	return h.Sum()
}

// pgoActor implements the Actor interface for preprocessing PGO profiles.
type pgoActor struct {
	// input is the path to the original pprof profile.
	input string
}

func (p *pgoActor) Act(b *Builder, ctx context.Context, a *Action) error {
	if b.useCache(a, b.pgoActionID(p.input), a.Target, !b.IsCmdList) || b.IsCmdList {
		return nil
	}
	defer b.flushOutput(a)

	sh := b.Shell(a)

	if err := sh.Mkdir(a.Objdir); err != nil {
		return err
	}

	if err := sh.run(".", p.input, nil, cfg.BuildToolexec, base.Tool("preprofile"), "-o", a.Target, "-i", p.input); err != nil {
		return err
	}

	// N.B. Builder.build looks for the out in a.built, regardless of
	// whether this came from cache.
	a.built = a.Target

	if !cfg.BuildN {
		// Cache the output.
		//
		// N.B. We don't use updateBuildID here, as preprocessed PGO profiles
		// do not contain a build ID. updateBuildID is typically responsible
		// for adding to the cache, thus we must do so ourselves instead.

		r, err := os.Open(a.Target)
		if err != nil {
			return fmt.Errorf("error opening target for caching: %w", err)
		}

		c := cache.Default()
		outputID, _, err := c.Put(a.actionID, r)
		r.Close()
		if err != nil {
			return fmt.Errorf("error adding target to cache: %w", err)
		}
		if cfg.BuildX {
			sh.ShowCmd("", "%s # internal", joinUnambiguously(str.StringList("cp", a.Target, c.OutputFile(outputID))))
		}
	}

	return nil
}

// CompileAction returns the action for compiling and possibly installing
// (according to mode) the given package. The resulting action is only
// for building packages (archives), never for linking executables.
// depMode is the action (build or install) to use when building dependencies.
// To turn package main into an executable, call b.Link instead.
func (b *Builder) CompileAction(mode, depMode BuildMode, p *load.Package) *Action {
	vetOnly := mode&ModeVetOnly != 0
	mode &^= ModeVetOnly

	if mode != ModeBuild && p.Target == "" {
		// No permanent target.
		mode = ModeBuild
	}
	if mode != ModeBuild && p.Name == "main" {
		// We never install the .a file for a main package.
		mode = ModeBuild
	}

	// Construct package build action.
	a := b.cacheAction("build", p, func() *Action {
		a := &Action{
			Mode:    "build",
			Package: p,
			Actor:   newBuildActor(p, p.Internal.Cover.GenMeta),
			Objdir:  b.NewObjdir(),
		}

		if p.Error == nil || !p.Error.IsImportCycle {
			for _, p1 := range p.Internal.Imports {
				a.Deps = append(a.Deps, b.CompileAction(depMode, depMode, p1))
			}
		}

		if p.Internal.PGOProfile != "" {
			pgoAction := b.cacheAction("preprocess PGO profile "+p.Internal.PGOProfile, nil, func() *Action {
				a := &Action{
					Mode:   "preprocess PGO profile",
					Actor:  &pgoActor{input: p.Internal.PGOProfile},
					Objdir: b.NewObjdir(),
				}
				a.Target = filepath.Join(a.Objdir, "pgo.preprofile")

				return a
			})
			a.Deps = append(a.Deps, pgoAction)
		}

		if p.Standard {
			switch p.ImportPath {
			case "builtin", "unsafe":
				// Fake packages - nothing to build.
				a.Mode = "built-in package"
				a.Actor = nil
				return a
			}

			// gccgo standard library is "fake" too.
			if cfg.BuildToolchainName == "gccgo" {
				// the target name is needed for cgo.
				a.Mode = "gccgo stdlib"
				a.Target = p.Target
				a.Actor = nil
				return a
			}
		}

		return a
	})

	// Find the build action; the cache entry may have been replaced
	// by the install action during (*Builder).installAction.
	buildAction := a
	switch buildAction.Mode {
	case "build", "built-in package", "gccgo stdlib":
		// ok
	case "build-install":
		buildAction = a.Deps[0]
	default:
		panic("lost build action: " + buildAction.Mode)
	}
	buildAction.needBuild = buildAction.needBuild || !vetOnly

	// Construct install action.
	if mode == ModeInstall || mode == ModeBuggyInstall {
		a = b.installAction(a, mode)
	}

	return a
}

// VetAction returns the action for running go vet on package p.
// It depends on the action for compiling p.
// If the caller may be causing p to be installed, it is up to the caller
// to make sure that the install depends on (runs after) vet.
func (b *Builder) VetAction(mode, depMode BuildMode, p *load.Package) *Action {
	a := b.vetAction(mode, depMode, p)
	a.VetxOnly = false
	return a
}

func (b *Builder) vetAction(mode, depMode BuildMode, p *load.Package) *Action {
	// Construct vet action.
	a := b.cacheAction("vet", p, func() *Action {
		a1 := b.CompileAction(mode|ModeVetOnly, depMode, p)

		// vet expects to be able to import "fmt".
		var stk load.ImportStack
		stk.Push(load.NewImportInfo("vet", nil))
		p1, err := load.LoadImportWithFlags("fmt", p.Dir, p, &stk, nil, 0)
		if err != nil {
			base.Fatalf("unexpected error loading fmt package from package %s: %v", p.ImportPath, err)
		}
		stk.Pop()
		aFmt := b.CompileAction(ModeBuild, depMode, p1)

		var deps []*Action
		if a1.buggyInstall {
			// (*Builder).vet expects deps[0] to be the package
			// and deps[1] to be "fmt". If we see buggyInstall
			// here then a1 is an install of a shared library,
			// and the real package is a1.Deps[0].
			deps = []*Action{a1.Deps[0], aFmt, a1}
		} else {
			deps = []*Action{a1, aFmt}
		}
		for _, p1 := range p.Internal.Imports {
			deps = append(deps, b.vetAction(mode, depMode, p1))
		}

		a := &Action{
			Mode:       "vet",
			Package:    p,
			Deps:       deps,
			Objdir:     a1.Objdir,
			VetxOnly:   true,
			IgnoreFail: true, // it's OK if vet of dependencies "fails" (reports problems)
		}
		if a1.Actor == nil {
			// Built-in packages like unsafe.
			return a
		}
		deps[0].needVet = true
		a.Actor = ActorFunc((*Builder).vet)
		return a
	})
	return a
}

// LinkAction returns the action for linking p into an executable
// and possibly installing the result (according to mode).
// depMode is the action (build or install) to use when compiling dependencies.
func (b *Builder) LinkAction(mode, depMode BuildMode, p *load.Package) *Action {
	// Construct link action.
	a := b.cacheAction("link", p, func() *Action {
		a := &Action{
			Mode:    "link",
			Package: p,
		}

		a1 := b.CompileAction(ModeBuild, depMode, p)
		a.Actor = ActorFunc((*Builder).link)
		a.Deps = []*Action{a1}
		a.Objdir = a1.Objdir

		// An executable file. (This is the name of a temporary file.)
		// Because we run the temporary file in 'go run' and 'go test',
		// the name will show up in ps listings. If the caller has specified
		// a name, use that instead of a.out. The binary is generated
		// in an otherwise empty subdirectory named exe to avoid
		// naming conflicts. The only possible conflict is if we were
		// to create a top-level package named exe.
		name := "a.out"
		if p.Internal.ExeName != "" {
			name = p.Internal.ExeName
		} else if (cfg.Goos == "darwin" || cfg.Goos == "windows") && cfg.BuildBuildmode == "c-shared" && p.Target != "" {
			// On OS X, the linker output name gets recorded in the
			// shared library's LC_ID_DYLIB load command.
			// The code invoking the linker knows to pass only the final
			// path element. Arrange that the path element matches what
			// we'll install it as; otherwise the library is only loadable as "a.out".
			// On Windows, DLL file name is recorded in PE file
			// export section, so do like on OS X.
			_, name = filepath.Split(p.Target)
		}
		a.Target = a.Objdir + filepath.Join("exe", name) + cfg.ExeSuffix
		a.built = a.Target
		b.addTransitiveLinkDeps(a, a1, "")

		// Sequence the build of the main package (a1) strictly after the build
		// of all other dependencies that go into the link. It is likely to be after
		// them anyway, but just make sure. This is required by the build ID-based
		// shortcut in (*Builder).useCache(a1), which will call b.linkActionID(a).
		// In order for that linkActionID call to compute the right action ID, all the
		// dependencies of a (except a1) must have completed building and have
		// recorded their build IDs.
		a1.Deps = append(a1.Deps, &Action{Mode: "nop", Deps: a.Deps[1:]})
		return a
	})

	if mode == ModeInstall || mode == ModeBuggyInstall {
		a = b.installAction(a, mode)
	}

	return a
}

// installAction returns the action for installing the result of a1.
func (b *Builder) installAction(a1 *Action, mode BuildMode) *Action {
	// Because we overwrite the build action with the install action below,
	// a1 may already be an install action fetched from the "build" cache key,
	// and the caller just doesn't realize.
	if strings.HasSuffix(a1.Mode, "-install") {
		if a1.buggyInstall && mode == ModeInstall {
			//  Congratulations! The buggy install is now a proper install.
			a1.buggyInstall = false
		}
		return a1
	}

	// If there's no actual action to build a1,
	// there's nothing to install either.
	// This happens if a1 corresponds to reusing an already-built object.
	if a1.Actor == nil {
		return a1
	}

	p := a1.Package
	return b.cacheAction(a1.Mode+"-install", p, func() *Action {
		// The install deletes the temporary build result,
		// so we need all other actions, both past and future,
		// that attempt to depend on the build to depend instead
		// on the install.

		// Make a private copy of a1 (the build action),
		// no longer accessible to any other rules.
		buildAction := new(Action)
		*buildAction = *a1

		// Overwrite a1 with the install action.
		// This takes care of updating past actions that
		// point at a1 for the build action; now they will
		// point at a1 and get the install action.
		// We also leave a1 in the action cache as the result
		// for "build", so that actions not yet created that
		// try to depend on the build will instead depend
		// on the install.
		*a1 = Action{
			Mode:    buildAction.Mode + "-install",
			Actor:   ActorFunc(BuildInstallFunc),
			Package: p,
			Objdir:  buildAction.Objdir,
			Deps:    []*Action{buildAction},
			Target:  p.Target,
			built:   p.Target,

			buggyInstall: mode == ModeBuggyInstall,
		}

		b.addInstallHeaderAction(a1)
		return a1
	})
}

// addTransitiveLinkDeps adds to the link action a all packages
// that are transitive dependencies of a1.Deps.
// That is, if a is a link of package main, a1 is the compile of package main
// and a1.Deps is the actions for building packages directly imported by
// package main (what the compiler needs). The linker needs all packages
// transitively imported by the whole program; addTransitiveLinkDeps
// makes sure those are present in a.Deps.
// If shlib is non-empty, then a corresponds to the build and installation of shlib,
// so any rebuild of shlib should not be added as a dependency.
func (b *Builder) addTransitiveLinkDeps(a, a1 *Action, shlib string) {
	// Expand Deps to include all built packages, for the linker.
	// Use breadth-first search to find rebuilt-for-test packages
	// before the standard ones.
	// TODO(rsc): Eliminate the standard ones from the action graph,
	// which will require doing a little bit more rebuilding.
	workq := []*Action{a1}
	haveDep := map[string]bool{}
	if a1.Package != nil {
		haveDep[a1.Package.ImportPath] = true
	}
	for i := 0; i < len(workq); i++ {
		a1 := workq[i]
		for _, a2 := range a1.Deps {
			// TODO(rsc): Find a better discriminator than the Mode strings, once the dust settles.
			if a2.Package == nil || (a2.Mode != "build-install" && a2.Mode != "build") || haveDep[a2.Package.ImportPath] {
				continue
			}
			haveDep[a2.Package.ImportPath] = true
			a.Deps = append(a.Deps, a2)
			if a2.Mode == "build-install" {
				a2 = a2.Deps[0] // walk children of "build" action
			}
			workq = append(workq, a2)
		}
	}

	// If this is go build -linkshared, then the link depends on the shared libraries
	// in addition to the packages themselves. (The compile steps do not.)
	if cfg.BuildLinkshared {
		haveShlib := map[string]bool{shlib: true}
		for _, a1 := range a.Deps {
			p1 := a1.Package
			if p1 == nil || p1.Shlib == "" || haveShlib[filepath.Base(p1.Shlib)] {
				continue
			}
			haveShlib[filepath.Base(p1.Shlib)] = true
			// TODO(rsc): The use of ModeInstall here is suspect, but if we only do ModeBuild,
			// we'll end up building an overall library or executable that depends at runtime
			// on other libraries that are out-of-date, which is clearly not good either.
			// We call it ModeBuggyInstall to make clear that this is not right.
			a.Deps = append(a.Deps, b.linkSharedAction(ModeBuggyInstall, ModeBuggyInstall, p1.Shlib, nil))
		}
	}
}

// addInstallHeaderAction adds an install header action to a, if needed.
// The action a should be an install action as generated by either
// b.CompileAction or b.LinkAction with mode=ModeInstall,
// and so a.Deps[0] is the corresponding build action.
func (b *Builder) addInstallHeaderAction(a *Action) {
	// Install header for cgo in c-archive and c-shared modes.
	p := a.Package
	if p.UsesCgo() && (cfg.BuildBuildmode == "c-archive" || cfg.BuildBuildmode == "c-shared") {
		hdrTarget := a.Target[:len(a.Target)-len(filepath.Ext(a.Target))] + ".h"
		if cfg.BuildContext.Compiler == "gccgo" && cfg.BuildO == "" {
			// For the header file, remove the "lib"
			// added by go/build, so we generate pkg.h
			// rather than libpkg.h.
			dir, file := filepath.Split(hdrTarget)
			file = strings.TrimPrefix(file, "lib")
			hdrTarget = filepath.Join(dir, file)
		}
		ah := &Action{
			Mode:    "install header",
			Package: a.Package,
			Deps:    []*Action{a.Deps[0]},
			Actor:   ActorFunc((*Builder).installHeader),
			Objdir:  a.Deps[0].Objdir,
			Target:  hdrTarget,
		}
		a.Deps = append(a.Deps, ah)
	}
}

// buildmodeShared takes the "go build" action a1 into the building of a shared library of a1.Deps.
// That is, the input a1 represents "go build pkgs" and the result represents "go build -buildmode=shared pkgs".
func (b *Builder) buildmodeShared(mode, depMode BuildMode, args []string, pkgs []*load.Package, a1 *Action) *Action {
	name, err := libname(args, pkgs)
	if err != nil {
		base.Fatalf("%v", err)
	}
	return b.linkSharedAction(mode, depMode, name, a1)
}

// linkSharedAction takes a grouping action a1 corresponding to a list of built packages
// and returns an action that links them together into a shared library with the name shlib.
// If a1 is nil, shlib should be an absolute path to an existing shared library,
// and then linkSharedAction reads that library to find out the package list.
func (b *Builder) linkSharedAction(mode, depMode BuildMode, shlib string, a1 *Action) *Action {
	fullShlib := shlib
	shlib = filepath.Base(shlib)
	a := b.cacheAction("build-shlib "+shlib, nil, func() *Action {
		if a1 == nil {
			// TODO(rsc): Need to find some other place to store config,
			// not in pkg directory. See golang.org/issue/22196.
			pkgs := readpkglist(fullShlib)
			a1 = &Action{
				Mode: "shlib packages",
			}
			for _, p := range pkgs {
				a1.Deps = append(a1.Deps, b.CompileAction(mode, depMode, p))
			}
		}

		// Fake package to hold ldflags.
		// As usual shared libraries are a kludgy, abstraction-violating special case:
		// we let them use the flags specified for the command-line arguments.
		p := &load.Package{}
		p.Internal.CmdlinePkg = true
		p.Internal.Ldflags = load.BuildLdflags.For(p)
		p.Internal.Gccgoflags = load.BuildGccgoflags.For(p)

		// Add implicit dependencies to pkgs list.
		// Currently buildmode=shared forces external linking mode, and
		// external linking mode forces an import of runtime/cgo (and
		// math on arm). So if it was not passed on the command line and
		// it is not present in another shared library, add it here.
		// TODO(rsc): Maybe this should only happen if "runtime" is in the original package set.
		// TODO(rsc): This should probably be changed to use load.LinkerDeps(p).
		// TODO(rsc): We don't add standard library imports for gccgo
		// because they are all always linked in anyhow.
		// Maybe load.LinkerDeps should be used and updated.
		a := &Action{
			Mode:    "go build -buildmode=shared",
			Package: p,
			Objdir:  b.NewObjdir(),
			Actor:   ActorFunc((*Builder).linkShared),
			Deps:    []*Action{a1},
		}
		a.Target = filepath.Join(a.Objdir, shlib)
		if cfg.BuildToolchainName != "gccgo" {
			add := func(a1 *Action, pkg string, force bool) {
				for _, a2 := range a1.Deps {
					if a2.Package != nil && a2.Package.ImportPath == pkg {
						return
					}
				}
				var stk load.ImportStack
				p := load.LoadPackageWithFlags(pkg, base.Cwd(), &stk, nil, 0)
				if p.Error != nil {
					base.Fatalf("load %s: %v", pkg, p.Error)
				}
				// Assume that if pkg (runtime/cgo or math)
				// is already accounted for in a different shared library,
				// then that shared library also contains runtime,
				// so that anything we do will depend on that library,
				// so we don't need to include pkg in our shared library.
				if force || p.Shlib == "" || filepath.Base(p.Shlib) == pkg {
					a1.Deps = append(a1.Deps, b.CompileAction(depMode, depMode, p))
				}
			}
			add(a1, "runtime/cgo", false)
			if cfg.Goarch == "arm" {
				add(a1, "math", false)
			}

			// The linker step still needs all the usual linker deps.
			// (For example, the linker always opens runtime.a.)
			ldDeps, err := load.LinkerDeps(nil)
			if err != nil {
				base.Error(err)
			}
			for _, dep := range ldDeps {
				add(a, dep, true)
			}
		}
		b.addTransitiveLinkDeps(a, a1, shlib)
		return a
	})

	// Install result.
	if (mode == ModeInstall || mode == ModeBuggyInstall) && a.Actor != nil {
		buildAction := a

		a = b.cacheAction("install-shlib "+shlib, nil, func() *Action {
			// Determine the eventual install target.
			// The install target is root/pkg/shlib, where root is the source root
			// in which all the packages lie.
			// TODO(rsc): Perhaps this cross-root check should apply to the full
			// transitive package dependency list, not just the ones named
			// on the command line?
			pkgDir := a1.Deps[0].Package.Internal.Build.PkgTargetRoot
			for _, a2 := range a1.Deps {
				if dir := a2.Package.Internal.Build.PkgTargetRoot; dir != pkgDir {
					base.Fatalf("installing shared library: cannot use packages %s and %s from different roots %s and %s",
						a1.Deps[0].Package.ImportPath,
						a2.Package.ImportPath,
						pkgDir,
						dir)
				}
			}
			// TODO(rsc): Find out and explain here why gccgo is different.
			if cfg.BuildToolchainName == "gccgo" {
				pkgDir = filepath.Join(pkgDir, "shlibs")
			}
			target := filepath.Join(pkgDir, shlib)

			a := &Action{
				Mode:   "go install -buildmode=shared",
				Objdir: buildAction.Objdir,
				Actor:  ActorFunc(BuildInstallFunc),
				Deps:   []*Action{buildAction},
				Target: target,
			}
			for _, a2 := range buildAction.Deps[0].Deps {
				p := a2.Package
				pkgTargetRoot := p.Internal.Build.PkgTargetRoot
				if pkgTargetRoot == "" {
					continue
				}
				a.Deps = append(a.Deps, &Action{
					Mode:    "shlibname",
					Package: p,
					Actor:   ActorFunc((*Builder).installShlibname),
					Target:  filepath.Join(pkgTargetRoot, p.ImportPath+".shlibname"),
					Deps:    []*Action{a.Deps[0]},
				})
			}
			return a
		})
	}

	return a
}
```