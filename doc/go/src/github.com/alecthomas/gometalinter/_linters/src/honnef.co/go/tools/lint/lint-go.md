Response:
Let's break down the thought process for analyzing the provided Go code.

1. **Understanding the Goal:** The request asks for the functionality of a specific Go file (`lint.go`), its role in the broader context, examples of its usage, handling of command-line arguments (if any), and potential pitfalls for users.

2. **Initial Scan and High-Level Understanding:** I started by reading the package comment: `// Package lint provides the foundation for tools like staticcheck`. This immediately tells me the file defines core types and logic for static analysis of Go code. The `import` statements confirm it interacts with Go's AST, type system, and SSA representation.

3. **Identifying Key Data Structures:**  I looked for the main types defined in the file. The most prominent ones are:
    * `Job`: Represents a single linting task.
    * `Ignore` (and its implementations `LineIgnore`, `FileIgnore`, `GlobIgnore`):  Handles ignoring specific linting issues.
    * `Program`:  Holds the parsed and analyzed Go code.
    * `Problem`:  Represents a detected issue.
    * `Checker`:  An interface for individual linters.
    * `Check`:  Represents a specific check performed by a `Checker`.
    * `Linter`: The main orchestrator of the linting process.
    * `PerfStats`:  Collects performance metrics.

4. **Analyzing the `Linter` Type and its `Lint` Method:** The `Linter` struct and its `Lint` method are central to the file's functionality. I focused on what `Lint` does:
    * Takes `[]*packages.Package` as input, representing the Go packages to analyze.
    * Builds the SSA representation of the code.
    * Initializes the registered `Checker`s.
    * Creates `Job`s for each check provided by the `Checker`s.
    * Executes these `Job`s concurrently.
    * Collects the `Problem`s found by the checks.
    * Applies the configured `Ignore` rules.
    * Filters the results based on enabled/disabled checks.
    * Sorts and deduplicates the `Problem`s.

5. **Understanding the `Ignore` Mechanisms:**  The different `Ignore` types (`LineIgnore`, `FileIgnore`, `GlobIgnore`) provide flexibility in suppressing linting results. The code for each `Match` method clarifies how the ignoring works (matching file, line, check name, or package/filename patterns). The `//lint:` directive parsing within `Lint` further highlights how in-code ignore directives are processed.

6. **Inferring Functionality from Method Names and Signatures:**  Methods like `Errorf`, `File`, `Package`, `DisplayPosition`, `isGenerated`, and `FilterChecks` suggest their roles in reporting errors, accessing file information, handling generated code, and filtering checks based on configuration.

7. **Formulating the Functionality Summary:** Based on the analysis above, I could list the key functions of the code:
    * Defining core data structures for linting.
    * Loading and processing Go packages.
    * Building SSA representation.
    * Providing a framework for implementing and registering linters (`Checker` interface).
    * Executing linters and collecting problems.
    * Supporting various mechanisms for ignoring linting issues.
    * Filtering and managing the output of the linting process.
    * Collecting performance statistics.

8. **Considering "What Go Feature is Implemented?":**  The code clearly implements a *static analysis framework* or *linter*. It leverages Go's reflection indirectly through the `go/packages`, `go/ast`, `go/types`, and `honnef.co/go/tools/ssa` libraries to inspect and reason about Go code.

9. **Crafting Code Examples:**  To illustrate the usage, I focused on demonstrating how a `Checker` would be implemented and how the `Linter` would be used to run it. This involved creating a simple `Checker` and `Check` that looks for a specific pattern. I included input and expected output to make the example concrete.

10. **Analyzing Command-Line Arguments:** I carefully read the code for any explicit handling of `os.Args` or a similar mechanism for processing command-line flags. I noticed no such code in the provided snippet, leading to the conclusion that this specific file doesn't handle command-line arguments directly. The higher-level tool (`staticcheck`) would be responsible for that.

11. **Identifying Potential User Errors:** I focused on the `Ignore` mechanisms, as those are often a source of confusion. I highlighted the possibility of typos in ignore directives, incorrect file paths, and misunderstandings about the scope of different ignore types. The "this linter directive didn't match anything" warning logic in the `Lint` function provides a clue about a common mistake.

12. **Structuring the Answer:** I organized the answer into clear sections based on the request's prompts: Functionality, Implemented Go Feature, Code Example, Command-Line Arguments, and Common Mistakes. I used clear and concise language, and I provided specific code snippets and explanations where needed. I also ensured the answer was in Chinese as requested.

13. **Review and Refinement:** I reread my answer to ensure accuracy, clarity, and completeness. I checked that the code examples were correct and the explanations were easy to understand. For instance, initially I might have only focused on the core linting logic, but realizing the request explicitly asked about command-line arguments, I went back and specifically confirmed their absence in *this* file.
这段代码是 `honnef.co/go/tools/lint` 包的核心部分，它为一个静态代码分析工具（比如 `staticcheck`）提供了基础框架。以下是它的主要功能：

**1. 定义核心数据结构：**

* **`Job`**: 代表一个独立的检查任务，包含要检查的程序、执行的检查器、具体的检查项以及发现的问题。
* **`Ignore` 接口和其实现 (`LineIgnore`, `FileIgnore`, `GlobIgnore`)**:  定义了忽略特定代码问题的机制。用户可以通过这些结构来指定哪些问题在哪些代码行、文件或包路径下被忽略。
* **`Program`**:  表示被分析的 Go 程序，包含 SSA 中间表示、抽象语法树 (AST)、类型信息等。
* **`Problem`**:  描述在代码中发现的一个问题，包括问题的位置、文本描述、检查器名称、检查项 ID 和严重程度。
* **`Checker` 接口**:  定义了代码检查器的基本行为，包括名称、前缀、初始化方法和提供的检查项。
* **`Check` 结构**:  代表一个具体的代码检查，包含执行的函数和唯一的 ID。
* **`Linter` 结构**:  作为整个 lint 过程的协调者，管理注册的检查器、忽略规则、Go 版本和配置信息。
* **`PerfStats` 结构**:  用于收集 lint 过程的性能统计信息。

**2. 提供 lint 运行的核心逻辑 (`Linter.Lint` 方法):**

* **加载和解析 Go 包**: 使用 `golang.org/x/tools/go/packages` 加载需要分析的 Go 代码包。
* **构建 SSA 中间表示**: 使用 `honnef.co/go/tools/ssa` 将 Go 代码转换为静态单赋值 (SSA) 形式，方便进行更深入的分析。
* **初始化检查器**: 调用所有注册的 `Checker` 的 `Init` 方法，让检查器进行初始化。
* **创建和执行检查任务**: 为每个注册的 `Check` 创建一个 `Job`，并并发地执行这些任务。
* **收集问题**: 每个 `Job` 执行后，将其发现的 `Problem` 收集起来。
* **应用忽略规则**: 根据配置的 `Ignore` 规则，过滤掉被忽略的问题。
* **过滤检查项**: 根据包级别的配置，决定是否允许某个检查项报告问题。
* **对问题进行排序和去重**:  对最终的问题列表进行排序，并去除重复的问题。
* **输出性能统计**: 如果配置了 `PrintStats`，则将 lint 过程的性能统计信息输出到标准错误。

**3. 支持多种忽略问题的方式：**

* **行级忽略 (`LineIgnore`)**: 通过 `//lint:ignore <checks> <reason>` 注释，忽略特定代码行上的指定检查项。
* **文件级忽略 (`FileIgnore`)**: 通过 `//lint:file-ignore <checks> <reason>` 注释，忽略整个文件中的指定检查项。
* **全局模式忽略 (`GlobIgnore`)**:  通过配置，根据包路径和文件名模式忽略指定检查项。

**4. 定义问题报告机制 (`Job.Errorf` 方法):**

* 检查器可以使用 `Job.Errorf` 方法来报告发现的问题，该方法会创建 `Problem` 结构体，并将其添加到 `Job` 的问题列表中。
* 在报告问题时，会考虑是否是生成的代码，以及该检查项是否需要过滤生成代码。

**5. 提供获取代码结构信息的方法：**

* `Program` 提供了访问 AST 节点、Token 位置、包信息等的方法，方便检查器进行代码分析。

**它是什么 Go 语言功能的实现？**

这段代码实现了一个 **静态代码分析框架** 或者更具体地说，是一个 **linter 框架**。它没有直接实现特定的 Go 语言功能，而是构建了一个用于分析 Go 代码的平台，允许开发者在其上实现各种代码检查规则。

**Go 代码举例说明：**

假设我们有一个简单的检查器，用于查找代码中使用了 `fmt.Println` 函数。

```go
package mylinter

import (
	"go/ast"
	"go/token"

	"honnef.co/go/tools/lint"
)

type PrintlnChecker struct{}

func NewPrintlnChecker() lint.Checker {
	return &PrintlnChecker{}
}

func (c *PrintlnChecker) Name() string {
	return "PrintlnChecker"
}

func (c *PrintlnChecker) Prefix() string {
	return "PL"
}

func (c *PrintlnChecker) Init(prog *lint.Program) {}

func (c *PrintlnChecker) Checks() []lint.Check {
	return []lint.Check{
		{Fn: c.checkPrintln, ID: "PL1000"},
	}
}

func (c *PrintlnChecker) checkPrintln(job *lint.Job) {
	for _, pkgInfo := range job.Program.InitialPackages {
		for _, file := range pkgInfo.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				callExpr, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				selectorExpr, ok := callExpr.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				ident, ok := selectorExpr.Sel.(*ast.Ident)
				if !ok {
					return true
				}
				if ident.Name == "Println" {
					packageIdent, ok := selectorExpr.X.(*ast.Ident)
					if ok && packageIdent.Name == "fmt" {
						job.Errorf(callExpr, "使用了 fmt.Println，建议使用日志库")
					}
				}
				return true
			})
		}
	}
}
```

**假设的输入与输出：**

**输入 (待检查的 Go 代码 `main.go`):**

```go
package main

import "fmt"

func main() {
	fmt.Println("Hello, world!")
}
```

**输出 (lint 工具的输出):**

```
main.go:5:2: 使用了 fmt.Println，建议使用日志库 (PL1000)
```

**命令行参数的具体处理：**

这段代码本身 **没有直接处理命令行参数**。它是一个框架库，负责定义 lint 的核心逻辑。具体的命令行参数处理通常由使用这个框架的工具（例如 `staticcheck`）来完成。这些工具会解析命令行参数，然后配置 `Linter` 对象，例如指定要检查的包、要启用的检查器、忽略规则等。

**使用者易犯错的点：**

1. **忽略指令的语法错误：**  `//lint:ignore` 和 `//lint:file-ignore` 指令的格式必须正确，包括检查项 ID 和原因。如果格式错误，lint 工具可能会给出警告，或者忽略该指令。

   **错误示例：** `//lint:ignore PL1000` (缺少原因) 或 `//lint: ignorePL1000 reason` (冒号后面缺少空格)。

2. **忽略指令的作用域理解错误：**

   * **行级忽略** 只对当前行有效。
   * **文件级忽略** 对整个文件有效。
   * **全局模式忽略** 根据配置的模式匹配包或文件路径。

   **易错点：** 认为行级忽略会影响到多行代码，或者文件级忽略会影响到其他文件。

3. **检查项 ID 的拼写错误：**  在忽略指令或配置文件中，如果检查项 ID 拼写错误，那么该忽略规则将不会生效。

   **错误示例：**  `//lint:ignore PL0001 reason` (假设实际的 ID 是 `PL1000`)。

4. **配置文件的加载和合并规则不熟悉：**  `honnef.co/go/tools/config` 提供了配置文件加载和合并的功能。用户可能不熟悉不同层级配置文件的优先级和合并方式，导致某些配置没有生效。

5. **对通配符 `*` 的使用不当：**  在忽略指令或配置文件中使用通配符 `*` 时，需要理解其匹配规则。例如，`SA*` 会匹配 `SA1000`，但不会匹配 `S1000`。

这段代码是构建强大的 Go 静态分析工具的基础，理解其功能对于开发和使用这些工具至关重要。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/honnef.co/go/tools/lint/lint.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Package lint provides the foundation for tools like staticcheck
package lint // import "honnef.co/go/tools/lint"

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/tools/go/packages"
	"honnef.co/go/tools/config"
	"honnef.co/go/tools/ssa"
	"honnef.co/go/tools/ssa/ssautil"
)

type Job struct {
	Program *Program

	checker  string
	check    Check
	problems []Problem

	duration time.Duration
}

type Ignore interface {
	Match(p Problem) bool
}

type LineIgnore struct {
	File    string
	Line    int
	Checks  []string
	matched bool
	pos     token.Pos
}

func (li *LineIgnore) Match(p Problem) bool {
	if p.Position.Filename != li.File || p.Position.Line != li.Line {
		return false
	}
	for _, c := range li.Checks {
		if m, _ := filepath.Match(c, p.Check); m {
			li.matched = true
			return true
		}
	}
	return false
}

func (li *LineIgnore) String() string {
	matched := "not matched"
	if li.matched {
		matched = "matched"
	}
	return fmt.Sprintf("%s:%d %s (%s)", li.File, li.Line, strings.Join(li.Checks, ", "), matched)
}

type FileIgnore struct {
	File   string
	Checks []string
}

func (fi *FileIgnore) Match(p Problem) bool {
	if p.Position.Filename != fi.File {
		return false
	}
	for _, c := range fi.Checks {
		if m, _ := filepath.Match(c, p.Check); m {
			return true
		}
	}
	return false
}

type GlobIgnore struct {
	Pattern string
	Checks  []string
}

func (gi *GlobIgnore) Match(p Problem) bool {
	if gi.Pattern != "*" {
		pkgpath := p.Package.Types.Path()
		if strings.HasSuffix(pkgpath, "_test") {
			pkgpath = pkgpath[:len(pkgpath)-len("_test")]
		}
		name := filepath.Join(pkgpath, filepath.Base(p.Position.Filename))
		if m, _ := filepath.Match(gi.Pattern, name); !m {
			return false
		}
	}
	for _, c := range gi.Checks {
		if m, _ := filepath.Match(c, p.Check); m {
			return true
		}
	}
	return false
}

type Program struct {
	SSA              *ssa.Program
	InitialPackages  []*Pkg
	InitialFunctions []*ssa.Function
	AllPackages      []*packages.Package
	AllFunctions     []*ssa.Function
	Files            []*ast.File
	GoVersion        int

	tokenFileMap map[*token.File]*ast.File
	astFileMap   map[*ast.File]*Pkg
	packagesMap  map[string]*packages.Package

	genMu        sync.RWMutex
	generatedMap map[string]bool
}

func (prog *Program) Fset() *token.FileSet {
	return prog.InitialPackages[0].Fset
}

type Func func(*Job)

type Severity uint8

const (
	Error Severity = iota
	Warning
	Ignored
)

// Problem represents a problem in some source code.
type Problem struct {
	Position token.Position // position in source file
	Text     string         // the prose that describes the problem
	Check    string
	Checker  string
	Package  *Pkg
	Severity Severity
}

func (p *Problem) String() string {
	if p.Check == "" {
		return p.Text
	}
	return fmt.Sprintf("%s (%s)", p.Text, p.Check)
}

type Checker interface {
	Name() string
	Prefix() string
	Init(*Program)
	Checks() []Check
}

type Check struct {
	Fn              Func
	ID              string
	FilterGenerated bool
}

// A Linter lints Go source code.
type Linter struct {
	Checkers      []Checker
	Ignores       []Ignore
	GoVersion     int
	ReturnIgnored bool
	Config        config.Config

	MaxConcurrentJobs int
	PrintStats        bool

	automaticIgnores []Ignore
}

func (l *Linter) ignore(p Problem) bool {
	ignored := false
	for _, ig := range l.automaticIgnores {
		// We cannot short-circuit these, as we want to record, for
		// each ignore, whether it matched or not.
		if ig.Match(p) {
			ignored = true
		}
	}
	if ignored {
		// no need to execute other ignores if we've already had a
		// match.
		return true
	}
	for _, ig := range l.Ignores {
		// We can short-circuit here, as we aren't tracking any
		// information.
		if ig.Match(p) {
			return true
		}
	}

	return false
}

func (prog *Program) File(node Positioner) *ast.File {
	return prog.tokenFileMap[prog.SSA.Fset.File(node.Pos())]
}

func (j *Job) File(node Positioner) *ast.File {
	return j.Program.File(node)
}

func parseDirective(s string) (cmd string, args []string) {
	if !strings.HasPrefix(s, "//lint:") {
		return "", nil
	}
	s = strings.TrimPrefix(s, "//lint:")
	fields := strings.Split(s, " ")
	return fields[0], fields[1:]
}

type PerfStats struct {
	PackageLoading time.Duration
	SSABuild       time.Duration
	OtherInitWork  time.Duration
	CheckerInits   map[string]time.Duration
	Jobs           []JobStat
}

type JobStat struct {
	Job      string
	Duration time.Duration
}

func (stats *PerfStats) Print(w io.Writer) {
	fmt.Fprintln(w, "Package loading:", stats.PackageLoading)
	fmt.Fprintln(w, "SSA build:", stats.SSABuild)
	fmt.Fprintln(w, "Other init work:", stats.OtherInitWork)

	fmt.Fprintln(w, "Checker inits:")
	for checker, d := range stats.CheckerInits {
		fmt.Fprintf(w, "\t%s: %s\n", checker, d)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Jobs:")
	sort.Slice(stats.Jobs, func(i, j int) bool {
		return stats.Jobs[i].Duration < stats.Jobs[j].Duration
	})
	var total time.Duration
	for _, job := range stats.Jobs {
		fmt.Fprintf(w, "\t%s: %s\n", job.Job, job.Duration)
		total += job.Duration
	}
	fmt.Fprintf(w, "\tTotal: %s\n", total)
}

func (l *Linter) Lint(initial []*packages.Package, stats *PerfStats) []Problem {
	allPkgs := allPackages(initial)
	t := time.Now()
	ssaprog, _ := ssautil.Packages(allPkgs, ssa.GlobalDebug)
	ssaprog.Build()
	if stats != nil {
		stats.SSABuild = time.Since(t)
	}

	t = time.Now()
	pkgMap := map[*ssa.Package]*Pkg{}
	var pkgs []*Pkg
	for _, pkg := range initial {
		ssapkg := ssaprog.Package(pkg.Types)
		var cfg config.Config
		if len(pkg.GoFiles) != 0 {
			path := pkg.GoFiles[0]
			dir := filepath.Dir(path)
			var err error
			// OPT(dh): we're rebuilding the entire config tree for
			// each package. for example, if we check a/b/c and
			// a/b/c/d, we'll process a, a/b, a/b/c, a, a/b, a/b/c,
			// a/b/c/d – we should cache configs per package and only
			// load the new levels.
			cfg, err = config.Load(dir)
			if err != nil {
				// FIXME(dh): we couldn't load the config, what are we
				// supposed to do? probably tell the user somehow
			}
			cfg = cfg.Merge(l.Config)
		}

		pkg := &Pkg{
			SSA:     ssapkg,
			Package: pkg,
			Config:  cfg,
		}
		pkgMap[ssapkg] = pkg
		pkgs = append(pkgs, pkg)
	}

	prog := &Program{
		SSA:             ssaprog,
		InitialPackages: pkgs,
		AllPackages:     allPkgs,
		GoVersion:       l.GoVersion,
		tokenFileMap:    map[*token.File]*ast.File{},
		astFileMap:      map[*ast.File]*Pkg{},
		generatedMap:    map[string]bool{},
	}
	prog.packagesMap = map[string]*packages.Package{}
	for _, pkg := range allPkgs {
		prog.packagesMap[pkg.Types.Path()] = pkg
	}

	isInitial := map[*types.Package]struct{}{}
	for _, pkg := range pkgs {
		isInitial[pkg.Types] = struct{}{}
	}
	for fn := range ssautil.AllFunctions(ssaprog) {
		if fn.Pkg == nil {
			continue
		}
		prog.AllFunctions = append(prog.AllFunctions, fn)
		if _, ok := isInitial[fn.Pkg.Pkg]; ok {
			prog.InitialFunctions = append(prog.InitialFunctions, fn)
		}
	}
	for _, pkg := range pkgs {
		prog.Files = append(prog.Files, pkg.Syntax...)

		ssapkg := ssaprog.Package(pkg.Types)
		for _, f := range pkg.Syntax {
			prog.astFileMap[f] = pkgMap[ssapkg]
		}
	}

	for _, pkg := range allPkgs {
		for _, f := range pkg.Syntax {
			tf := pkg.Fset.File(f.Pos())
			prog.tokenFileMap[tf] = f
		}
	}

	var out []Problem
	l.automaticIgnores = nil
	for _, pkg := range initial {
		for _, f := range pkg.Syntax {
			cm := ast.NewCommentMap(pkg.Fset, f, f.Comments)
			for node, cgs := range cm {
				for _, cg := range cgs {
					for _, c := range cg.List {
						if !strings.HasPrefix(c.Text, "//lint:") {
							continue
						}
						cmd, args := parseDirective(c.Text)
						switch cmd {
						case "ignore", "file-ignore":
							if len(args) < 2 {
								// FIXME(dh): this causes duplicated warnings when using megacheck
								p := Problem{
									Position: prog.DisplayPosition(c.Pos()),
									Text:     "malformed linter directive; missing the required reason field?",
									Check:    "",
									Checker:  "lint",
									Package:  nil,
								}
								out = append(out, p)
								continue
							}
						default:
							// unknown directive, ignore
							continue
						}
						checks := strings.Split(args[0], ",")
						pos := prog.DisplayPosition(node.Pos())
						var ig Ignore
						switch cmd {
						case "ignore":
							ig = &LineIgnore{
								File:   pos.Filename,
								Line:   pos.Line,
								Checks: checks,
								pos:    c.Pos(),
							}
						case "file-ignore":
							ig = &FileIgnore{
								File:   pos.Filename,
								Checks: checks,
							}
						}
						l.automaticIgnores = append(l.automaticIgnores, ig)
					}
				}
			}
		}
	}

	sizes := struct {
		types      int
		defs       int
		uses       int
		implicits  int
		selections int
		scopes     int
	}{}
	for _, pkg := range pkgs {
		sizes.types += len(pkg.TypesInfo.Types)
		sizes.defs += len(pkg.TypesInfo.Defs)
		sizes.uses += len(pkg.TypesInfo.Uses)
		sizes.implicits += len(pkg.TypesInfo.Implicits)
		sizes.selections += len(pkg.TypesInfo.Selections)
		sizes.scopes += len(pkg.TypesInfo.Scopes)
	}

	if stats != nil {
		stats.OtherInitWork = time.Since(t)
	}

	for _, checker := range l.Checkers {
		t := time.Now()
		checker.Init(prog)
		if stats != nil {
			stats.CheckerInits[checker.Name()] = time.Since(t)
		}
	}

	var jobs []*Job
	var allChecks []string

	for _, checker := range l.Checkers {
		checks := checker.Checks()
		for _, check := range checks {
			allChecks = append(allChecks, check.ID)
			j := &Job{
				Program: prog,
				checker: checker.Name(),
				check:   check,
			}
			jobs = append(jobs, j)
		}
	}

	max := len(jobs)
	if l.MaxConcurrentJobs > 0 {
		max = l.MaxConcurrentJobs
	}

	sem := make(chan struct{}, max)
	wg := &sync.WaitGroup{}
	for _, j := range jobs {
		wg.Add(1)
		go func(j *Job) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			fn := j.check.Fn
			if fn == nil {
				return
			}
			t := time.Now()
			fn(j)
			j.duration = time.Since(t)
		}(j)
	}
	wg.Wait()

	for _, j := range jobs {
		if stats != nil {
			stats.Jobs = append(stats.Jobs, JobStat{j.check.ID, j.duration})
		}
		for _, p := range j.problems {
			allowedChecks := FilterChecks(allChecks, p.Package.Config.Checks)

			if l.ignore(p) {
				p.Severity = Ignored
			}
			// TODO(dh): support globs in check white/blacklist
			// OPT(dh): this approach doesn't actually disable checks,
			// it just discards their results. For the moment, that's
			// fine. None of our checks are super expensive. In the
			// future, we may want to provide opt-in expensive
			// analysis, which shouldn't run at all. It may be easiest
			// to implement this in the individual checks.
			if (l.ReturnIgnored || p.Severity != Ignored) && allowedChecks[p.Check] {
				out = append(out, p)
			}
		}
	}

	for _, ig := range l.automaticIgnores {
		ig, ok := ig.(*LineIgnore)
		if !ok {
			continue
		}
		if ig.matched {
			continue
		}

		couldveMatched := false
		for f, pkg := range prog.astFileMap {
			if prog.Fset().Position(f.Pos()).Filename != ig.File {
				continue
			}
			allowedChecks := FilterChecks(allChecks, pkg.Config.Checks)
			for _, c := range ig.Checks {
				if !allowedChecks[c] {
					continue
				}
				couldveMatched = true
				break
			}
			break
		}

		if !couldveMatched {
			// The ignored checks were disabled for the containing package.
			// Don't flag the ignore for not having matched.
			continue
		}
		p := Problem{
			Position: prog.DisplayPosition(ig.pos),
			Text:     "this linter directive didn't match anything; should it be removed?",
			Check:    "",
			Checker:  "lint",
			Package:  nil,
		}
		out = append(out, p)
	}

	sort.Slice(out, func(i int, j int) bool {
		pi, pj := out[i].Position, out[j].Position

		if pi.Filename != pj.Filename {
			return pi.Filename < pj.Filename
		}
		if pi.Line != pj.Line {
			return pi.Line < pj.Line
		}
		if pi.Column != pj.Column {
			return pi.Column < pj.Column
		}

		return out[i].Text < out[j].Text
	})

	if l.PrintStats && stats != nil {
		stats.Print(os.Stderr)
	}

	if len(out) < 2 {
		return out
	}

	uniq := make([]Problem, 0, len(out))
	uniq = append(uniq, out[0])
	prev := out[0]
	for _, p := range out[1:] {
		if prev.Position == p.Position && prev.Text == p.Text {
			continue
		}
		prev = p
		uniq = append(uniq, p)
	}

	return uniq
}

func FilterChecks(allChecks []string, checks []string) map[string]bool {
	// OPT(dh): this entire computation could be cached per package
	allowedChecks := map[string]bool{}

	for _, check := range checks {
		b := true
		if len(check) > 1 && check[0] == '-' {
			b = false
			check = check[1:]
		}
		if check == "*" || check == "all" {
			// Match all
			for _, c := range allChecks {
				allowedChecks[c] = b
			}
		} else if strings.HasSuffix(check, "*") {
			// Glob
			prefix := check[:len(check)-1]
			isCat := strings.IndexFunc(prefix, func(r rune) bool { return unicode.IsNumber(r) }) == -1

			for _, c := range allChecks {
				idx := strings.IndexFunc(c, func(r rune) bool { return unicode.IsNumber(r) })
				if isCat {
					// Glob is S*, which should match S1000 but not SA1000
					cat := c[:idx]
					if prefix == cat {
						allowedChecks[c] = b
					}
				} else {
					// Glob is S1*
					if strings.HasPrefix(c, prefix) {
						allowedChecks[c] = b
					}
				}
			}
		} else {
			// Literal check name
			allowedChecks[check] = b
		}
	}
	return allowedChecks
}

func (prog *Program) Package(path string) *packages.Package {
	return prog.packagesMap[path]
}

// Pkg represents a package being linted.
type Pkg struct {
	SSA *ssa.Package
	*packages.Package
	Config config.Config
}

type Positioner interface {
	Pos() token.Pos
}

func (prog *Program) DisplayPosition(p token.Pos) token.Position {
	// Only use the adjusted position if it points to another Go file.
	// This means we'll point to the original file for cgo files, but
	// we won't point to a YACC grammar file.

	pos := prog.Fset().PositionFor(p, false)
	adjPos := prog.Fset().PositionFor(p, true)

	if filepath.Ext(adjPos.Filename) == ".go" {
		return adjPos
	}
	return pos
}

func (prog *Program) isGenerated(path string) bool {
	// This function isn't very efficient in terms of lock contention
	// and lack of parallelism, but it really shouldn't matter.
	// Projects consists of thousands of files, and have hundreds of
	// errors. That's not a lot of calls to isGenerated.

	prog.genMu.RLock()
	if b, ok := prog.generatedMap[path]; ok {
		prog.genMu.RUnlock()
		return b
	}
	prog.genMu.RUnlock()
	prog.genMu.Lock()
	defer prog.genMu.Unlock()
	// recheck to avoid doing extra work in case of race
	if b, ok := prog.generatedMap[path]; ok {
		return b
	}

	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	b := isGenerated(f)
	prog.generatedMap[path] = b
	return b
}

func (j *Job) Errorf(n Positioner, format string, args ...interface{}) *Problem {
	tf := j.Program.SSA.Fset.File(n.Pos())
	f := j.Program.tokenFileMap[tf]
	pkg := j.Program.astFileMap[f]

	pos := j.Program.DisplayPosition(n.Pos())
	if j.Program.isGenerated(pos.Filename) && j.check.FilterGenerated {
		return nil
	}
	problem := Problem{
		Position: pos,
		Text:     fmt.Sprintf(format, args...),
		Check:    j.check.ID,
		Checker:  j.checker,
		Package:  pkg,
	}
	j.problems = append(j.problems, problem)
	return &j.problems[len(j.problems)-1]
}

func (j *Job) NodePackage(node Positioner) *Pkg {
	f := j.File(node)
	return j.Program.astFileMap[f]
}

func allPackages(pkgs []*packages.Package) []*packages.Package {
	var out []*packages.Package
	packages.Visit(
		pkgs,
		func(pkg *packages.Package) bool {
			out = append(out, pkg)
			return true
		},
		nil,
	)
	return out
}

"""



```