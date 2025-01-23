Response:
Let's break down the thought process to analyze the provided Go code snippet.

**1. Understanding the Goal:**

The initial request asks for the functionalities of the `unitchecker.go` file, its role in the Go ecosystem, example usage (code and command-line), and potential pitfalls. The core is to understand *what* this code does and *how* it fits into the larger Go analysis landscape.

**2. Initial Skim and Keywords:**

A quick read-through highlights key terms: `unitchecker`, `go vet`, `analysis`, `compilation unit`, `config`, `analyzer`, `facts`, `types`, `JSON`, `flags`, `Run`, `Main`. These immediately suggest that this code is about performing static analysis on a single Go package within a build environment, likely driven by `go vet`.

**3. Identifying Core Functionalities (High-Level):**

Based on the keywords and the structure of the `Main` function, the primary functionalities emerge:

* **Configuration Handling:**  Reading and interpreting configuration files (`.cfg`).
* **Analysis Execution:** Running a set of static analyzers on the code.
* **Input Data Preparation:**  Parsing source code, type-checking.
* **Fact and Type Information Management:**  Importing and exporting facts and type information.
* **Reporting Results:**  Formatting and outputting diagnostics and errors.
* **Command-Line Interface:** Handling specific command-line arguments (`-flags`, `-V=full`, `.cfg` files).

**4. Deep Dive into Key Functions and Data Structures:**

Now, let's analyze the important parts more closely:

* **`Config` struct:**  This is crucial. It defines the input to the `unitchecker`. Each field needs to be understood (e.g., `GoFiles`, `ImportPath`, `PackageFile`, `VetxOutput`). The comments within the struct definition are helpful.
* **`Main` function:** This is the entry point. Notice the distinct handling of `-flags`, `-V=full`, and `.cfg` file arguments. This reveals the command-line protocol.
* **`Run` function:** This is where the core logic resides. It reads the config, runs the analysis (the `run` function), and handles output formatting.
* **`readConfig` function:**  Simple JSON parsing of the `.cfg` file.
* **`run` function:**  This is the most complex part. Break it down step by step:
    * **Parsing:** Parsing Go files using `go/parser`.
    * **Type Checking:** Using `go/types` for semantic analysis. The `makeTypesImporter` is important here for resolving imports.
    * **Fact Handling:**  The `makeFactImporter` and `exportFacts` functions manage the loading and saving of analysis facts. The concept of "facts" needs to be understood as extra information produced or consumed by analyzers.
    * **Analyzer Execution:**  The nested `exec` and `execAll` functions handle the execution of analyzers and their dependencies. The `sync.Once` and `sync.WaitGroup` suggest concurrent execution. The `analysis.Pass` struct is the container for information passed to analyzers.
    * **Result Aggregation:**  Collecting the diagnostics and errors from the analyzers.

**5. Connecting the Dots - The "Go Vet" Integration:**

The comments in the header are vital: `"...invoked by a build system such as "go vet": ..."` and the description of the command-line protocol. This clarifies that `unitchecker` is *not* a standalone tool typically run directly by the user. Instead, it's a component invoked by `go vet`.

**6. Code Examples and Reasoning:**

To solidify understanding, examples are essential:

* **`.cfg` file:** Create a simple example demonstrating the structure and key fields. This helps visualize the input to `unitchecker`.
* **Analyzer Example (Conceptual):** Briefly illustrate how an analyzer might use the information provided in the `analysis.Pass`. No need for a full implementation, just the core idea of accessing `TypesInfo`, reporting diagnostics, etc.
* **Command-Line Example:** Show how `go vet` uses `-vettool` to invoke the `unitchecker` executable and passes the `.cfg` file.

**7. Identifying Potential Pitfalls:**

Consider common user errors:

* **Direct invocation:** The code explicitly discourages this. Explain *why* (it lacks the necessary build context).
* **Incorrect `.cfg` file:** Highlight the importance of the file's format and contents.

**8. Structuring the Output:**

Organize the findings logically:

* **Functionality Summary:**  A concise overview.
* **Go Language Feature:** Explain the role of `go vet` and static analysis.
* **Code Example:** Show the `.cfg` content and a simplified analyzer interaction.
* **Command-Line Usage:** Demonstrate the `go vet` command.
* **Potential Pitfalls:**  Explain common mistakes.

**Self-Correction/Refinement During Analysis:**

* **Initial thought:** "Is this a general-purpose analysis tool?"  Correction: The comments and the `-vettool` mechanism strongly suggest it's tied to the `go vet` ecosystem.
* **Initial thought:** "How are analyzers defined and plugged in?" Correction: The `Main` function takes a `...*analysis.Analyzer` argument, indicating the analyzers are defined elsewhere and passed in.
* **Focus on the "unit" aspect:** The name "unitchecker" and the emphasis on a "single compilation unit" are key. This distinguishes it from tools that analyze entire packages or projects.

By following this systematic approach, combining skimming, deep dives, example creation, and error consideration, a comprehensive understanding of the `unitchecker.go` file can be achieved.
这段代码是 Go 语言工具链 `golang.org/x/tools` 中的 `unitchecker` 包的一部分，它的主要功能是**作为一个分析驱动程序，在构建过程中分析单个编译单元（通常是一个 Go 包）**。

更具体地说，`unitchecker` 实现了 `go vet` 工具用来执行静态分析的机制。它不依赖于 `go/packages` 包，因此更加轻量级，专注于对单个编译单元的分析。

以下是其主要功能点的详细说明：

**1. 作为 `go vet` 的后端分析执行器:**

   -   当使用 `go vet -vettool=$(which your_custom_vet_tool)` 时，`your_custom_vet_tool` 可能就是基于 `unitchecker` 构建的。
   -   `unitchecker` 接收来自 `go vet` 的指令和配置信息，并执行注册的分析器。

**2. 处理 `go vet` 的命令行协议:**

   -   **`-V=full`**:  当接收到这个参数时，`unitchecker` 会输出其可执行文件的完整描述，这主要用于构建工具的缓存机制。
   -   **`-flags`**:  当接收到这个参数时，`unitchecker` 会输出其支持的标志（flags）的描述，通常以 JSON 格式呈现，供构建工具使用。
   -   **`foo.cfg`**:  这是最核心的参数。`unitchecker` 接收一个以 `.cfg` 结尾的文件名，该文件包含了描述要分析的单个编译单元的 JSON 配置信息。

**3. 读取和解析编译单元配置 (Config):**

   -   `unitchecker` 定义了一个 `Config` 结构体，用于表示编译单元的配置信息。
   -   `readConfig` 函数负责读取 `.cfg` 文件的内容，并将其反序列化到 `Config` 结构体中。
   -   `Config` 包含了诸如包 ID、编译器类型、源文件列表、导入路径、模块信息、类型信息文件路径 (`PackageFile`)、事实信息文件路径 (`PackageVetx`) 等重要信息。

**4. 加载、解析和类型检查 Go 代码:**

   -   `run` 函数首先使用 `go/parser` 解析 `Config` 中指定的 Go 源文件。
   -   然后，它使用 `go/types` 包进行类型检查。`makeTypesImporter` 函数负责创建类型导入器，以便在类型检查过程中解析依赖包的类型信息。
   -   `Config` 中的 `PackageFile` 字段用于指定依赖包的类型信息文件的路径，这使得 `unitchecker` 能够在没有完整构建上下文的情况下进行类型检查。

**5. 执行注册的分析器 (Analyzers):**

   -   `Main` 函数接收一个或多个 `analysis.Analyzer` 类型的参数。这些是具体的静态分析逻辑的实现。
   -   `run` 函数会遍历这些分析器，并为每个分析器创建一个 `analysis.Pass` 实例，该实例包含了分析器运行所需的上下文信息，例如文件集、抽象语法树、类型信息等。
   -   分析器通过 `pass.Report` 方法报告诊断信息（例如，潜在的错误或代码风格问题）。
   -   `unitchecker` 并行地执行分析器，以提高效率。

**6. 处理分析事实 (Facts):**

   -   `unitchecker` 支持分析事实的概念。分析事实是分析器产生或消费的关于代码的额外信息，可以跨分析器共享。
   -   `makeFactImporter` 函数负责创建事实导入器，从 `Config` 中指定的 `.vetx` 文件加载依赖包的分析事实。
   -   `exportFacts` 函数负责将当前编译单元的分析事实导出到指定的文件中 (`Config.VetxOutput`)。
   -   `VetxOnly` 字段允许只运行产生事实的分析器。

**7. 输出分析结果:**

   -   如果 `analysisflags.JSON` 为 true，则将分析结果以 JSON 格式输出到标准输出。
   -   否则，将分析结果以纯文本格式输出到标准错误，包括错误信息和诊断信息。

**Go 语言功能实现示例 (推理):**

`unitchecker` 的核心是静态分析框架，它利用了 Go 语言标准库提供的 `go/ast` (抽象语法树)、`go/types` (类型检查) 和 `go/importer` (导入) 包。

**假设我们有一个简单的分析器，用于检查函数是否过长：**

```go
// myanalyzer/myanalyzer.go
package myanalyzer

import (
	"go/ast"
	"go/token"

	"golang.org/x/tools/go/analysis"
)

var Analyzer = &analysis.Analyzer{
	Name: "funclength",
	Doc:  "Checks if functions are too long",
	Run:  run,
}

const maxLines = 50

func run(pass *analysis.Pass) (interface{}, error) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			start := pass.Fset.Position(fn.Body.Lbrace)
			end := pass.Fset.Position(fn.Body.Rbrace)
			if end.Line-start.Line > maxLines {
				pass.Report(analysis.Diagnostic{
					Pos:     fn.Pos(),
					Message: "function is too long",
				})
			}
			return true
		})
	}
	return nil, nil
}
```

**假设的输入 `.cfg` 文件 (用于 `go vet`):**

```json
{
  "ID": "mypackage [mypackage.go]",
  "Compiler": "gc",
  "Dir": "/path/to/mypackage",
  "ImportPath": "mypackage",
  "GoVersion": "go1.16",
  "GoFiles": ["mypackage.go"],
  "NonGoFiles": [],
  "IgnoredFiles": [],
  "ModulePath": "mymodule",
  "ModuleVersion": "v1.0.0",
  "ImportMap": {},
  "PackageFile": {},
  "Standard": {},
  "PackageVetx": {},
  "VetxOnly": false
}
```

**假设 `mypackage.go` 内容如下：**

```go
package mypackage

import "fmt"

func veryLongFunction() {
	fmt.Println("line 1")
	fmt.Println("line 2")
	// ... (假设这里有超过 50 行的代码)
	fmt.Println("line 51")
}

func shortFunction() {
	fmt.Println("short")
}
```

**执行 `go vet` 命令:**

```bash
go vet -vettool=$(which myvet) mypackage
```

**其中 `myvet` 是基于 `unitchecker` 构建的，并且注册了 `myanalyzer.Analyzer`。**

**假设的输出 (如果 `veryLongFunction` 超过 50 行):**

```
/path/to/mypackage/mypackage.go:5:1: function is too long
```

**命令行参数的具体处理:**

-   当 `unitchecker` 启动时，它会检查 `os.Args`。
-   如果第一个参数是 `-V=full`，它会输出可执行文件信息并退出。
-   如果第一个参数是 `-flags`，它会解析并输出所有注册分析器的标志信息（通过 `analysisflags.Parse` 和 `analysisflags.Help`）。
-   如果第一个参数是以 `.cfg` 结尾的文件名，它会将其视为编译单元配置文件，并调用 `Run` 函数开始分析。
-   如果参数是 `help`，则显示帮助信息，可以列出所有可用的分析器及其标志。

**使用者易犯错的点:**

1. **直接调用 `unitchecker` 可执行文件:**  用户可能会尝试直接运行编译后的 `unitchecker` 程序，并传递一些 Go 文件。这是错误的，因为 `unitchecker` 设计为由 `go vet` 等构建系统驱动，它需要 `.cfg` 文件来获取必要的上下文信息，例如导入路径、依赖包的类型信息路径等。

    **错误示例:**

    ```bash
    ./myvet mypackage.go  # 错误！缺少 .cfg 文件
    ```

    **正确方式 (通过 `go vet`):**

    ```bash
    go vet -vettool=$(which myvet) mypackage
    ```

2. **`.cfg` 文件配置错误:**  如果 `.cfg` 文件中的信息不正确（例如，`GoFiles` 列表不正确，或者 `PackageFile` 中指定的类型信息文件不存在），`unitchecker` 将无法正确加载和分析代码。

    **错误示例 (`.cfg` 文件中的 `GoFiles` 错误):**

    ```json
    {
      // ...
      "GoFiles": ["wrong_file.go"],
      // ...
    }
    ```

    在这种情况下，`unitchecker` 可能会报告找不到文件或者类型检查失败。

3. **不理解 `VetxOnly` 模式:**  用户可能错误地设置了 `VetxOnly: true`，导致只运行生成事实的分析器，而忽略了其他诊断分析器。这会导致一些潜在的问题没有被报告。

**总结:**

`unitchecker` 是 Go 工具链中一个关键的组件，它为 `go vet` 提供了执行静态分析的基础设施。它负责处理与构建系统的交互，加载代码和元数据，以及驱动各种静态分析器的运行。理解其工作原理对于开发自定义的 `go vet` 扩展工具至关重要。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/tools/go/analysis/unitchecker/unitchecker.go的go语言实现的一部分， 请列举一下它的功能, 　
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

// The unitchecker package defines the main function for an analysis
// driver that analyzes a single compilation unit during a build.
// It is invoked by a build system such as "go vet":
//
//	$ go vet -vettool=$(which vet)
//
// It supports the following command-line protocol:
//
//	-V=full         describe executable               (to the build tool)
//	-flags          describe flags                    (to the build tool)
//	foo.cfg         description of compilation unit (from the build tool)
//
// This package does not depend on go/packages.
// If you need a standalone tool, use multichecker,
// which supports this mode but can also load packages
// from source using go/packages.
package unitchecker

// TODO(adonovan):
// - with gccgo, go build does not build standard library,
//   so we will not get to analyze it. Yet we must in order
//   to create base facts for, say, the fmt package for the
//   printf checker.

import (
	"encoding/gob"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/internal/analysisflags"
	"golang.org/x/tools/internal/analysisinternal"
	"golang.org/x/tools/internal/facts"
)

// A Config describes a compilation unit to be analyzed.
// It is provided to the tool in a JSON-encoded file
// whose name ends with ".cfg".
type Config struct {
	ID                        string // e.g. "fmt [fmt.test]"
	Compiler                  string // gc or gccgo, provided to MakeImporter
	Dir                       string // (unused)
	ImportPath                string // package path
	GoVersion                 string // minimum required Go version, such as "go1.21.0"
	GoFiles                   []string
	NonGoFiles                []string
	IgnoredFiles              []string
	ModulePath                string            // module path
	ModuleVersion             string            // module version
	ImportMap                 map[string]string // maps import path to package path
	PackageFile               map[string]string // maps package path to file of type information
	Standard                  map[string]bool   // package belongs to standard library
	PackageVetx               map[string]string // maps package path to file of fact information
	VetxOnly                  bool              // run analysis only for facts, not diagnostics
	VetxOutput                string            // where to write file of fact information
	SucceedOnTypecheckFailure bool
}

// Main is the main function of a vet-like analysis tool that must be
// invoked by a build system to analyze a single package.
//
// The protocol required by 'go vet -vettool=...' is that the tool must support:
//
//	-flags          describe flags in JSON
//	-V=full         describe executable for build caching
//	foo.cfg         perform separate modular analyze on the single
//	                unit described by a JSON config file foo.cfg.
func Main(analyzers ...*analysis.Analyzer) {
	progname := filepath.Base(os.Args[0])
	log.SetFlags(0)
	log.SetPrefix(progname + ": ")

	if err := analysis.Validate(analyzers); err != nil {
		log.Fatal(err)
	}

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `%[1]s is a tool for static analysis of Go programs.

Usage of %[1]s:
	%.16[1]s unit.cfg	# execute analysis specified by config file
	%.16[1]s help    	# general help, including listing analyzers and flags
	%.16[1]s help name	# help on specific analyzer and its flags
`, progname)
		os.Exit(1)
	}

	analyzers = analysisflags.Parse(analyzers, true)

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
	}
	if args[0] == "help" {
		analysisflags.Help(progname, analyzers, args[1:])
		os.Exit(0)
	}
	if len(args) != 1 || !strings.HasSuffix(args[0], ".cfg") {
		log.Fatalf(`invoking "go tool vet" directly is unsupported; use "go vet"`)
	}
	Run(args[0], analyzers)
}

// Run reads the *.cfg file, runs the analysis,
// and calls os.Exit with an appropriate error code.
// It assumes flags have already been set.
func Run(configFile string, analyzers []*analysis.Analyzer) {
	cfg, err := readConfig(configFile)
	if err != nil {
		log.Fatal(err)
	}

	fset := token.NewFileSet()
	results, err := run(fset, cfg, analyzers)
	if err != nil {
		log.Fatal(err)
	}

	// In VetxOnly mode, the analysis is run only for facts.
	if !cfg.VetxOnly {
		if analysisflags.JSON {
			// JSON output
			tree := make(analysisflags.JSONTree)
			for _, res := range results {
				tree.Add(fset, cfg.ID, res.a.Name, res.diagnostics, res.err)
			}
			tree.Print(os.Stdout)
		} else {
			// plain text
			exit := 0
			for _, res := range results {
				if res.err != nil {
					log.Println(res.err)
					exit = 1
				}
			}
			for _, res := range results {
				for _, diag := range res.diagnostics {
					analysisflags.PrintPlain(os.Stderr, fset, analysisflags.Context, diag)
					exit = 1
				}
			}
			os.Exit(exit)
		}
	}

	os.Exit(0)
}

func readConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	cfg := new(Config)
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("cannot decode JSON config file %s: %v", filename, err)
	}
	if len(cfg.GoFiles) == 0 {
		// The go command disallows packages with no files.
		// The only exception is unsafe, but the go command
		// doesn't call vet on it.
		return nil, fmt.Errorf("package has no files: %s", cfg.ImportPath)
	}
	return cfg, nil
}

type factImporter = func(pkgPath string) ([]byte, error)

// These four hook variables are a proof of concept of a future
// parameterization of a unitchecker API that allows the client to
// determine how and where facts and types are produced and consumed.
// (Note that the eventual API will likely be quite different.)
//
// The defaults honor a Config in a manner compatible with 'go vet'.
var (
	makeTypesImporter = func(cfg *Config, fset *token.FileSet) types.Importer {
		compilerImporter := importer.ForCompiler(fset, cfg.Compiler, func(path string) (io.ReadCloser, error) {
			// path is a resolved package path, not an import path.
			file, ok := cfg.PackageFile[path]
			if !ok {
				if cfg.Compiler == "gccgo" && cfg.Standard[path] {
					return nil, nil // fall back to default gccgo lookup
				}
				return nil, fmt.Errorf("no package file for %q", path)
			}
			return os.Open(file)
		})
		return importerFunc(func(importPath string) (*types.Package, error) {
			path, ok := cfg.ImportMap[importPath] // resolve vendoring, etc
			if !ok {
				return nil, fmt.Errorf("can't resolve import %q", path)
			}
			return compilerImporter.Import(path)
		})
	}

	exportTypes = func(*Config, *token.FileSet, *types.Package) error {
		// By default this is a no-op, because "go vet"
		// makes the compiler produce type information.
		return nil
	}

	makeFactImporter = func(cfg *Config) factImporter {
		return func(pkgPath string) ([]byte, error) {
			if vetx, ok := cfg.PackageVetx[pkgPath]; ok {
				return os.ReadFile(vetx)
			}
			return nil, nil // no .vetx file, no facts
		}
	}

	exportFacts = func(cfg *Config, data []byte) error {
		return os.WriteFile(cfg.VetxOutput, data, 0666)
	}
)

func run(fset *token.FileSet, cfg *Config, analyzers []*analysis.Analyzer) ([]result, error) {
	// Load, parse, typecheck.
	var files []*ast.File
	for _, name := range cfg.GoFiles {
		f, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			if cfg.SucceedOnTypecheckFailure {
				// Silently succeed; let the compiler
				// report parse errors.
				err = nil
			}
			return nil, err
		}
		files = append(files, f)
	}
	tc := &types.Config{
		Importer:  makeTypesImporter(cfg, fset),
		Sizes:     types.SizesFor("gc", build.Default.GOARCH), // TODO(adonovan): use cfg.Compiler
		GoVersion: cfg.GoVersion,
	}
	info := &types.Info{
		Types:        make(map[ast.Expr]types.TypeAndValue),
		Defs:         make(map[*ast.Ident]types.Object),
		Uses:         make(map[*ast.Ident]types.Object),
		Implicits:    make(map[ast.Node]types.Object),
		Instances:    make(map[*ast.Ident]types.Instance),
		Scopes:       make(map[ast.Node]*types.Scope),
		Selections:   make(map[*ast.SelectorExpr]*types.Selection),
		FileVersions: make(map[*ast.File]string),
	}

	pkg, err := tc.Check(cfg.ImportPath, fset, files, info)
	if err != nil {
		if cfg.SucceedOnTypecheckFailure {
			// Silently succeed; let the compiler
			// report type errors.
			err = nil
		}
		return nil, err
	}

	// Register fact types with gob.
	// In VetxOnly mode, analyzers are only for their facts,
	// so we can skip any analysis that neither produces facts
	// nor depends on any analysis that produces facts.
	//
	// TODO(adonovan): fix: the command (and logic!) here are backwards.
	// It should say "...nor is required by any...". (Issue 443099)
	//
	// Also build a map to hold working state and result.
	type action struct {
		once        sync.Once
		result      interface{}
		err         error
		usesFacts   bool // (transitively uses)
		diagnostics []analysis.Diagnostic
	}
	actions := make(map[*analysis.Analyzer]*action)
	var registerFacts func(a *analysis.Analyzer) bool
	registerFacts = func(a *analysis.Analyzer) bool {
		act, ok := actions[a]
		if !ok {
			act = new(action)
			var usesFacts bool
			for _, f := range a.FactTypes {
				usesFacts = true
				gob.Register(f)
			}
			for _, req := range a.Requires {
				if registerFacts(req) {
					usesFacts = true
				}
			}
			act.usesFacts = usesFacts
			actions[a] = act
		}
		return act.usesFacts
	}
	var filtered []*analysis.Analyzer
	for _, a := range analyzers {
		if registerFacts(a) || !cfg.VetxOnly {
			filtered = append(filtered, a)
		}
	}
	analyzers = filtered

	// Read facts from imported packages.
	facts, err := facts.NewDecoder(pkg).Decode(makeFactImporter(cfg))
	if err != nil {
		return nil, err
	}

	// In parallel, execute the DAG of analyzers.
	var exec func(a *analysis.Analyzer) *action
	var execAll func(analyzers []*analysis.Analyzer)
	exec = func(a *analysis.Analyzer) *action {
		act := actions[a]
		act.once.Do(func() {
			execAll(a.Requires) // prefetch dependencies in parallel

			// The inputs to this analysis are the
			// results of its prerequisites.
			inputs := make(map[*analysis.Analyzer]interface{})
			var failed []string
			for _, req := range a.Requires {
				reqact := exec(req)
				if reqact.err != nil {
					failed = append(failed, req.String())
					continue
				}
				inputs[req] = reqact.result
			}

			// Report an error if any dependency failed.
			if failed != nil {
				sort.Strings(failed)
				act.err = fmt.Errorf("failed prerequisites: %s", strings.Join(failed, ", "))
				return
			}

			factFilter := make(map[reflect.Type]bool)
			for _, f := range a.FactTypes {
				factFilter[reflect.TypeOf(f)] = true
			}

			module := &analysis.Module{
				Path:      cfg.ModulePath,
				Version:   cfg.ModuleVersion,
				GoVersion: cfg.GoVersion,
			}

			pass := &analysis.Pass{
				Analyzer:          a,
				Fset:              fset,
				Files:             files,
				OtherFiles:        cfg.NonGoFiles,
				IgnoredFiles:      cfg.IgnoredFiles,
				Pkg:               pkg,
				TypesInfo:         info,
				TypesSizes:        tc.Sizes,
				TypeErrors:        nil, // unitchecker doesn't RunDespiteErrors
				ResultOf:          inputs,
				Report:            func(d analysis.Diagnostic) { act.diagnostics = append(act.diagnostics, d) },
				ImportObjectFact:  facts.ImportObjectFact,
				ExportObjectFact:  facts.ExportObjectFact,
				AllObjectFacts:    func() []analysis.ObjectFact { return facts.AllObjectFacts(factFilter) },
				ImportPackageFact: facts.ImportPackageFact,
				ExportPackageFact: facts.ExportPackageFact,
				AllPackageFacts:   func() []analysis.PackageFact { return facts.AllPackageFacts(factFilter) },
				Module:            module,
			}
			pass.ReadFile = analysisinternal.MakeReadFile(pass)

			t0 := time.Now()
			act.result, act.err = a.Run(pass)

			if act.err == nil { // resolve URLs on diagnostics.
				for i := range act.diagnostics {
					if url, uerr := analysisflags.ResolveURL(a, act.diagnostics[i]); uerr == nil {
						act.diagnostics[i].URL = url
					} else {
						act.err = uerr // keep the last error
					}
				}
			}
			if false {
				log.Printf("analysis %s = %s", pass, time.Since(t0))
			}
		})
		return act
	}
	execAll = func(analyzers []*analysis.Analyzer) {
		var wg sync.WaitGroup
		for _, a := range analyzers {
			wg.Add(1)
			go func(a *analysis.Analyzer) {
				_ = exec(a)
				wg.Done()
			}(a)
		}
		wg.Wait()
	}

	execAll(analyzers)

	// Return diagnostics and errors from root analyzers.
	results := make([]result, len(analyzers))
	for i, a := range analyzers {
		act := actions[a]
		results[i].a = a
		results[i].err = act.err
		results[i].diagnostics = act.diagnostics
	}

	data := facts.Encode()
	if err := exportFacts(cfg, data); err != nil {
		return nil, fmt.Errorf("failed to export analysis facts: %v", err)
	}
	if err := exportTypes(cfg, fset, pkg); err != nil {
		return nil, fmt.Errorf("failed to export type information: %v", err)
	}

	return results, nil
}

type result struct {
	a           *analysis.Analyzer
	diagnostics []analysis.Diagnostic
	err         error
}

type importerFunc func(path string) (*types.Package, error)

func (f importerFunc) Import(path string) (*types.Package, error) { return f(path) }
```