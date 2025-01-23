Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding of the Context:**

The first line is crucial: `// Path: go/src/cmd/vendor/golang.org/x/tools/go/analysis/internal/analysisflags/flags.go`. This immediately tells us this code is part of the Go analysis tooling, specifically related to handling flags for analysis drivers. The `internal` package suggests it's not meant for public consumption and likely has specific usage within the `go/analysis` framework.

**2. High-Level Purpose from the Package Comment:**

The package comment `// Package analysisflags defines helpers for processing flags of analysis driver tools.` confirms the initial understanding. It's about managing command-line flags for tools that run static analysis.

**3. Identifying Key Functions and Variables:**

Scanning the code, the following immediately stand out:

* **`Parse` function:**  The core of the logic. The comment describes its role in creating flags, parsing them, and filtering analyzers.
* **Global variables:** `JSON` and `Context`. The comments `// -json` and `// -c=N` directly link these to command-line flags.
* **`triState` type:**  The comment explains its purpose: tracking if a boolean flag was explicitly set.
* **`printFlags` function:**  Likely for debugging or internal use, printing flag information.
* **`addVersionFlag` function:**  Handles the `-V` version flag.
* **`versionFlag` type:**  The custom type for the version flag.
* **`vetLegacyFlags` map:**  Clearly for compatibility with the `go vet` tool.
* **`PrintPlain` function:** For formatted plain-text output of analysis results.
* **`JSONTree`, `JSONTextEdit`, `JSONSuggestedFix`, `JSONDiagnostic`, `JSONRelatedInformation` types:**  Represent the JSON output format for analysis results.
* **`Add` and `Print` methods on `JSONTree`:**  Methods to build and output the JSON results.

**4. Analyzing the `Parse` Function in Detail:**

This is the most complex part, so let's break it down step by step:

* **Flag Creation Loop:** The code iterates through the provided `analyzers`. If `multi` is true, it creates a flag `-AnalyzerName` to enable/disable individual analyzers. It also registers each analyzer's own flags with a prefix `AnalyzerName.`. This explains how analyzer-specific flags are exposed.
* **Standard Flags:** It then registers the common flags `-flags`, `-V`, `-json`, and `-c`.
* **Legacy Vet Flags:**  It handles compatibility with older `go vet` flags by aliasing them to the new analyzer flag names. This is important for maintaining existing workflows.
* **`flag.Parse()`:**  Crucially, this is where the command-line arguments are actually processed.
* **`-flags` Handling:** If `-flags` is set, it calls `printFlags` and exits.
* **Analyzer Filtering:** This is the core logic for enabling/disabling analyzers based on the `-AnalyzerName` flags. It handles cases where some are explicitly enabled, some are explicitly disabled, or none are explicitly set.
* **Fact Registration:**  This part is a bit more subtle. It registers the types of "facts" produced by *skipped* analyzers. This is essential for inter-analyzer communication when some analyzers are disabled. The comment explains the reason for this complexity.

**5. Understanding `triState`:**

The comments and methods of `triState` clearly show it's a way to distinguish between a flag being unset and explicitly set to false. This is a common pattern when you need to know if a user provided a value.

**6. Analyzing Output Functions:**

* **`PrintPlain`:** Straightforward formatting of diagnostic messages with optional context lines.
* **JSON Structures and `JSONTree` methods:**  These describe the structured JSON output format, including diagnostics, suggested fixes, and related information. The `Add` method populates the `JSONTree`, and `Print` outputs it.

**7. Inferring Go Language Features:**

Based on the code, we can identify these Go features in use:

* **`flag` package:** For command-line argument parsing.
* **`go/token` package:**  For representing source code positions.
* **`encoding/json` and `encoding/gob`:** For serialization (JSON for output, Gob for internal analyzer communication).
* **`fmt` package:** For formatted output.
* **`log` package:** For error logging.
* **`os` package:** For interacting with the operating system (reading files, getting executable name).
* **`strings` package:** For string manipulation.
* **`strconv` package:** For string to boolean conversion.
* **`crypto/sha256`:** For calculating the executable's hash in the version flag.

**8. Identifying Potential User Errors:**

The "易犯错的点" section comes from understanding how the flag parsing logic works. The main pitfall is the interaction between driver flags and analyzer flags, especially in single-checker mode. If an analyzer's flag name conflicts with a standard driver flag, it will be skipped, potentially confusing the user.

**9. Structuring the Answer:**

Finally, the thought process involves organizing the findings into a clear and structured answer, covering:

* **Functionality:** A high-level overview.
* **Go Feature Implementation (with examples):** Demonstrating the usage of key packages and concepts.
* **Code Reasoning (with assumptions):**  Providing concrete examples of input and output for the `Parse` function.
* **Command-Line Parameter Handling:** Detailing the purpose and usage of key flags.
* **Common Mistakes:** Highlighting potential user errors.

This iterative process of reading the code, understanding its context, identifying key components, analyzing their behavior, and drawing inferences allows for a comprehensive understanding of the code's functionality.
这段代码是 Go 语言 `go/analysis` 框架中用于处理分析器工具命令行标志的一部分。它主要负责以下功能：

1. **定义通用标志:** 定义了所有分析器工具都可能用到的通用命令行标志，例如 `-json` 和 `-c`（用于控制输出格式和上下文行数）。
2. **解析分析器特定的标志:**  它能够解析每个分析器自定义的标志。在多分析器模式下，它会将这些标志注册为 `-分析器名称.标志名称` 的形式，避免命名冲突。
3. **启用/禁用分析器:** 在多分析器模式下，允许用户通过命令行标志显式地启用或禁用特定的分析器。
4. **处理标准标志:**  处理一些标准的辅助标志，例如 `-flags` (用于打印所有分析器标志的 JSON 表示) 和 `-V` (用于打印版本信息)。
5. **兼容旧的 `go vet` 标志:**  为了向后兼容，它会将一些旧的 `go vet` 命令的标志映射到新的分析器标志上。
6. **注册 Fact 类型:**  为了保证不同分析器之间可以共享信息（Facts），它会在内部注册所有涉及到的 Fact 类型，即使某些分析器被禁用了。
7. **提供输出辅助函数:**  提供了一些辅助函数，用于以纯文本或 JSON 格式打印分析结果。

**推理它是什么 Go 语言功能的实现：**

这段代码是 Go 静态分析功能的实现基础。 `go/analysis` 框架允许开发者编写自定义的静态分析器来检查 Go 代码中的潜在问题。`analysisflags` 包就是为了方便这些分析器工具处理命令行参数而设计的。它使得开发者不必从头开始处理复杂的标志解析和管理逻辑，可以专注于编写分析逻辑。

**Go 代码举例说明:**

假设我们有一个自定义的分析器名为 `myanalyzer`，它有一个标志 `-max-complexity` 用于设置代码复杂度的阈值。

```go
package main

import (
	"flag"
	"fmt"
	"os"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/internal/analysisflags"
)

var MyAnalyzer = &analysis.Analyzer{
	Name: "myanalyzer",
	Doc:  "My custom analyzer.",
	Run:  runMyAnalyzer,
}

var maxComplexity int

func init() {
	MyAnalyzer.Flags.IntVar(&maxComplexity, "max-complexity", 10, "Maximum allowed code complexity")
}

func runMyAnalyzer(pass *analysis.Pass) (interface{}, error) {
	// 分析逻辑，使用 maxComplexity 的值
	fmt.Println("Running myanalyzer with max complexity:", maxComplexity)
	return nil, nil
}

func main() {
	analyzers := []*analysis.Analyzer{MyAnalyzer}
	enabledAnalyzers := analysisflags.Parse(analyzers, true) // true 表示是多分析器模式

	if len(enabledAnalyzers) > 0 {
		// 这里通常会调用一个驱动程序来运行这些分析器
		fmt.Println("Enabled analyzers:")
		for _, a := range enabledAnalyzers {
			fmt.Println("-", a.Name)
		}
	}
}
```

**假设的输入与输出:**

假设我们编译并运行上述代码，并使用以下命令行参数：

**输入:**

```bash
./mytool -myanalyzer.max-complexity=20 myanalyzer
```

**输出:**

```
Running myanalyzer with max complexity: 20
Enabled analyzers:
- myanalyzer
```

**解释:**

* `-myanalyzer.max-complexity=20`：  通过 `analysisflags.Parse`，`myanalyzer` 分析器的 `maxComplexity` 标志被成功解析并设置为 20。
* `myanalyzer`： 这个参数启用了名为 `myanalyzer` 的分析器。

如果我们只运行 `./mytool myanalyzer`，输出将会是：

```
Running myanalyzer with max complexity: 10
Enabled analyzers:
- myanalyzer
```

因为没有显式设置 `-myanalyzer.max-complexity`，所以使用了默认值 10。

**命令行参数的具体处理:**

`analysisflags.Parse` 函数会根据 `multi` 参数的值来决定如何处理命令行参数：

* **`multi = true` (多分析器模式):**
    * 对于每个传入的 `analysis.Analyzer`，它会创建一个名为 `analyzer.Name` 的布尔标志。用户可以使用 `-analyzer.Name` 或 `-analyzer.Name=true` 来启用该分析器，使用 `-analyzer.Name=false` 来禁用它。
    * 它会将分析器自身的 `Flags` 中的所有标志都注册为 `analyzer.Name.flagName` 的形式。这样可以避免不同分析器之间的标志名称冲突。
    * 例如，如果有一个名为 `nilness` 的分析器，并且它定义了一个名为 `compact` 的标志，那么在命令行中可以使用 `-nilness.compact` 来设置这个标志。

* **`multi = false` (单分析器模式):**
    * 它不会创建以分析器名称为前缀的标志。
    * 它会直接注册分析器 `Flags` 中的标志，如果标志名称与驱动程序自身的标志冲突，会打印警告信息并跳过。

**`analysisflags.Parse` 处理的通用标志:**

* **`-json`:**  如果设置，分析结果将以 JSON 格式输出。
* **`-c=N`:** 设置上下文行数。如果 `N > 0`，在输出错误信息时，会显示出错代码行以及前后 `N` 行的代码。
* **`-flags`:** 如果设置，程序会打印所有分析器标志的 JSON 表示，然后退出。这对于 `go vet` 等工具了解可用的分析器标志很有用。
* **`-V` 或 `-V=full`:** 打印工具的版本信息并退出。

**兼容旧的 `go vet` 标志:**

`vetLegacyFlags` 变量定义了一个映射关系，将一些旧的 `go vet` 命令使用的标志名映射到新的分析器标志名。例如，旧的 `-bool` 标志会被映射到新的 `bools` 分析器。这样做是为了保持与旧脚本的兼容性。

**使用者易犯错的点:**

1. **单分析器模式下的标志冲突:**  在单分析器模式下 (`multi = false`)，如果分析器定义的标志名称与驱动程序自身或其他库使用的标志名称冲突，`analysisflags.Parse` 会打印警告并跳过注册该标志。这会导致用户设置的标志无效，且不容易被发现。

   **例子:** 假设你的分析器定义了一个名为 `v` 的布尔标志，而驱动程序或者 `flag` 包本身也使用了 `v` 作为其他用途的标志，那么你的分析器的 `v` 标志将不会被注册。用户可能会误以为 `-v` 标志会影响你的分析器，但实际上并没有。

2. **多分析器模式下忘记添加分析器名称前缀:** 在多分析器模式下，访问分析器特定的标志时，必须使用 `分析器名称.标志名称` 的格式。如果用户忘记添加前缀，直接使用标志名称，则该标志不会被识别为特定分析器的标志。

   **例子:**  假设你启用了 `shadow` 分析器，并且想要设置它的 `strict` 标志。正确的做法是使用 `-shadow.strict=true`。如果用户只使用了 `-strict=true`，那么这个标志不会被 `shadow` 分析器识别。

这段代码的核心目标是提供一个统一且方便的方式来管理和解析分析器工具的命令行标志，同时兼顾了向后兼容性和多分析器场景下的复杂性。理解其功能和使用方式对于开发和使用 Go 静态分析工具至关重要。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/tools/go/analysis/internal/analysisflags/flags.go的go语言实现的一部分， 请列举一下它的功能, 　
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

// Package analysisflags defines helpers for processing flags of
// analysis driver tools.
package analysisflags

import (
	"crypto/sha256"
	"encoding/gob"
	"encoding/json"
	"flag"
	"fmt"
	"go/token"
	"io"
	"log"
	"os"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// flags common to all {single,multi,unit}checkers.
var (
	JSON    = false // -json
	Context = -1    // -c=N: if N>0, display offending line plus N lines of context
)

// Parse creates a flag for each of the analyzer's flags,
// including (in multi mode) a flag named after the analyzer,
// parses the flags, then filters and returns the list of
// analyzers enabled by flags.
//
// The result is intended to be passed to unitchecker.Run or checker.Run.
// Use in unitchecker.Run will gob.Register all fact types for the returned
// graph of analyzers but of course not the ones only reachable from
// dropped analyzers. To avoid inconsistency about which gob types are
// registered from run to run, Parse itself gob.Registers all the facts
// only reachable from dropped analyzers.
// This is not a particularly elegant API, but this is an internal package.
func Parse(analyzers []*analysis.Analyzer, multi bool) []*analysis.Analyzer {
	// Connect each analysis flag to the command line as -analysis.flag.
	enabled := make(map[*analysis.Analyzer]*triState)
	for _, a := range analyzers {
		var prefix string

		// Add -NAME flag to enable it.
		if multi {
			prefix = a.Name + "."

			enable := new(triState)
			enableUsage := "enable " + a.Name + " analysis"
			flag.Var(enable, a.Name, enableUsage)
			enabled[a] = enable
		}

		a.Flags.VisitAll(func(f *flag.Flag) {
			if !multi && flag.Lookup(f.Name) != nil {
				log.Printf("%s flag -%s would conflict with driver; skipping", a.Name, f.Name)
				return
			}

			name := prefix + f.Name
			flag.Var(f.Value, name, f.Usage)
		})
	}

	// standard flags: -flags, -V.
	printflags := flag.Bool("flags", false, "print analyzer flags in JSON")
	addVersionFlag()

	// flags common to all checkers
	flag.BoolVar(&JSON, "json", JSON, "emit JSON output")
	flag.IntVar(&Context, "c", Context, `display offending line with this many lines of context`)

	// Add shims for legacy vet flags to enable existing
	// scripts that run vet to continue to work.
	_ = flag.Bool("source", false, "no effect (deprecated)")
	_ = flag.Bool("v", false, "no effect (deprecated)")
	_ = flag.Bool("all", false, "no effect (deprecated)")
	_ = flag.String("tags", "", "no effect (deprecated)")
	for old, new := range vetLegacyFlags {
		newFlag := flag.Lookup(new)
		if newFlag != nil && flag.Lookup(old) == nil {
			flag.Var(newFlag.Value, old, "deprecated alias for -"+new)
		}
	}

	flag.Parse() // (ExitOnError)

	// -flags: print flags so that go vet knows which ones are legitimate.
	if *printflags {
		printFlags()
		os.Exit(0)
	}

	everything := expand(analyzers)

	// If any -NAME flag is true,  run only those analyzers. Otherwise,
	// if any -NAME flag is false, run all but those analyzers.
	if multi {
		var hasTrue, hasFalse bool
		for _, ts := range enabled {
			switch *ts {
			case setTrue:
				hasTrue = true
			case setFalse:
				hasFalse = true
			}
		}

		var keep []*analysis.Analyzer
		if hasTrue {
			for _, a := range analyzers {
				if *enabled[a] == setTrue {
					keep = append(keep, a)
				}
			}
			analyzers = keep
		} else if hasFalse {
			for _, a := range analyzers {
				if *enabled[a] != setFalse {
					keep = append(keep, a)
				}
			}
			analyzers = keep
		}
	}

	// Register fact types of skipped analyzers
	// in case we encounter them in imported files.
	kept := expand(analyzers)
	for a := range everything {
		if !kept[a] {
			for _, f := range a.FactTypes {
				gob.Register(f)
			}
		}
	}

	return analyzers
}

func expand(analyzers []*analysis.Analyzer) map[*analysis.Analyzer]bool {
	seen := make(map[*analysis.Analyzer]bool)
	var visitAll func([]*analysis.Analyzer)
	visitAll = func(analyzers []*analysis.Analyzer) {
		for _, a := range analyzers {
			if !seen[a] {
				seen[a] = true
				visitAll(a.Requires)
			}
		}
	}
	visitAll(analyzers)
	return seen
}

func printFlags() {
	type jsonFlag struct {
		Name  string
		Bool  bool
		Usage string
	}
	var flags []jsonFlag = nil
	flag.VisitAll(func(f *flag.Flag) {
		// Don't report {single,multi}checker debugging
		// flags or fix as these have no effect on unitchecker
		// (as invoked by 'go vet').
		switch f.Name {
		case "debug", "cpuprofile", "memprofile", "trace", "fix":
			return
		}

		b, ok := f.Value.(interface{ IsBoolFlag() bool })
		isBool := ok && b.IsBoolFlag()
		flags = append(flags, jsonFlag{f.Name, isBool, f.Usage})
	})
	data, err := json.MarshalIndent(flags, "", "\t")
	if err != nil {
		log.Fatal(err)
	}
	os.Stdout.Write(data)
}

// addVersionFlag registers a -V flag that, if set,
// prints the executable version and exits 0.
//
// If the -V flag already exists — for example, because it was already
// registered by a call to cmd/internal/objabi.AddVersionFlag — then
// addVersionFlag does nothing.
func addVersionFlag() {
	if flag.Lookup("V") == nil {
		flag.Var(versionFlag{}, "V", "print version and exit")
	}
}

// versionFlag minimally complies with the -V protocol required by "go vet".
type versionFlag struct{}

func (versionFlag) IsBoolFlag() bool { return true }
func (versionFlag) Get() interface{} { return nil }
func (versionFlag) String() string   { return "" }
func (versionFlag) Set(s string) error {
	if s != "full" {
		log.Fatalf("unsupported flag value: -V=%s (use -V=full)", s)
	}

	// This replicates the minimal subset of
	// cmd/internal/objabi.AddVersionFlag, which is private to the
	// go tool yet forms part of our command-line interface.
	// TODO(adonovan): clarify the contract.

	// Print the tool version so the build system can track changes.
	// Formats:
	//   $progname version devel ... buildID=...
	//   $progname version go1.9.1
	progname, err := os.Executable()
	if err != nil {
		return err
	}
	f, err := os.Open(progname)
	if err != nil {
		log.Fatal(err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}
	f.Close()
	fmt.Printf("%s version devel comments-go-here buildID=%02x\n",
		progname, string(h.Sum(nil)))
	os.Exit(0)
	return nil
}

// A triState is a boolean that knows whether
// it has been set to either true or false.
// It is used to identify whether a flag appears;
// the standard boolean flag cannot
// distinguish missing from unset.
// It also satisfies flag.Value.
type triState int

const (
	unset triState = iota
	setTrue
	setFalse
)

func triStateFlag(name string, value triState, usage string) *triState {
	flag.Var(&value, name, usage)
	return &value
}

// triState implements flag.Value, flag.Getter, and flag.boolFlag.
// They work like boolean flags: we can say vet -printf as well as vet -printf=true
func (ts *triState) Get() interface{} {
	return *ts == setTrue
}

func (ts triState) isTrue() bool {
	return ts == setTrue
}

func (ts *triState) Set(value string) error {
	b, err := strconv.ParseBool(value)
	if err != nil {
		// This error message looks poor but package "flag" adds
		// "invalid boolean value %q for -NAME: %s"
		return fmt.Errorf("want true or false")
	}
	if b {
		*ts = setTrue
	} else {
		*ts = setFalse
	}
	return nil
}

func (ts *triState) String() string {
	switch *ts {
	case unset:
		return "true"
	case setTrue:
		return "true"
	case setFalse:
		return "false"
	}
	panic("not reached")
}

func (ts triState) IsBoolFlag() bool {
	return true
}

// Legacy flag support

// vetLegacyFlags maps flags used by legacy vet to their corresponding
// new names. The old names will continue to work.
var vetLegacyFlags = map[string]string{
	// Analyzer name changes
	"bool":       "bools",
	"buildtags":  "buildtag",
	"methods":    "stdmethods",
	"rangeloops": "loopclosure",

	// Analyzer flags
	"compositewhitelist":  "composites.whitelist",
	"printfuncs":          "printf.funcs",
	"shadowstrict":        "shadow.strict",
	"unusedfuncs":         "unusedresult.funcs",
	"unusedstringmethods": "unusedresult.stringmethods",
}

// ---- output helpers common to all drivers ----
//
// These functions should not depend on global state (flags)!
// Really they belong in a different package.

// TODO(adonovan): don't accept an io.Writer if we don't report errors.
// Either accept a bytes.Buffer (infallible), or return a []byte.

// PrintPlain prints a diagnostic in plain text form.
// If contextLines is nonnegative, it also prints the
// offending line plus this many lines of context.
func PrintPlain(out io.Writer, fset *token.FileSet, contextLines int, diag analysis.Diagnostic) {
	posn := fset.Position(diag.Pos)
	fmt.Fprintf(out, "%s: %s\n", posn, diag.Message)

	// show offending line plus N lines of context.
	if contextLines >= 0 {
		posn := fset.Position(diag.Pos)
		end := fset.Position(diag.End)
		if !end.IsValid() {
			end = posn
		}
		data, _ := os.ReadFile(posn.Filename)
		lines := strings.Split(string(data), "\n")
		for i := posn.Line - contextLines; i <= end.Line+contextLines; i++ {
			if 1 <= i && i <= len(lines) {
				fmt.Fprintf(out, "%d\t%s\n", i, lines[i-1])
			}
		}
	}
}

// A JSONTree is a mapping from package ID to analysis name to result.
// Each result is either a jsonError or a list of JSONDiagnostic.
type JSONTree map[string]map[string]interface{}

// A TextEdit describes the replacement of a portion of a file.
// Start and End are zero-based half-open indices into the original byte
// sequence of the file, and New is the new text.
type JSONTextEdit struct {
	Filename string `json:"filename"`
	Start    int    `json:"start"`
	End      int    `json:"end"`
	New      string `json:"new"`
}

// A JSONSuggestedFix describes an edit that should be applied as a whole or not
// at all. It might contain multiple TextEdits/text_edits if the SuggestedFix
// consists of multiple non-contiguous edits.
type JSONSuggestedFix struct {
	Message string         `json:"message"`
	Edits   []JSONTextEdit `json:"edits"`
}

// A JSONDiagnostic describes the JSON schema of an analysis.Diagnostic.
//
// TODO(matloob): include End position if present.
type JSONDiagnostic struct {
	Category       string                   `json:"category,omitempty"`
	Posn           string                   `json:"posn"` // e.g. "file.go:line:column"
	Message        string                   `json:"message"`
	SuggestedFixes []JSONSuggestedFix       `json:"suggested_fixes,omitempty"`
	Related        []JSONRelatedInformation `json:"related,omitempty"`
}

// A JSONRelated describes a secondary position and message related to
// a primary diagnostic.
//
// TODO(adonovan): include End position if present.
type JSONRelatedInformation struct {
	Posn    string `json:"posn"` // e.g. "file.go:line:column"
	Message string `json:"message"`
}

// Add adds the result of analysis 'name' on package 'id'.
// The result is either a list of diagnostics or an error.
func (tree JSONTree) Add(fset *token.FileSet, id, name string, diags []analysis.Diagnostic, err error) {
	var v interface{}
	if err != nil {
		type jsonError struct {
			Err string `json:"error"`
		}
		v = jsonError{err.Error()}
	} else if len(diags) > 0 {
		diagnostics := make([]JSONDiagnostic, 0, len(diags))
		for _, f := range diags {
			var fixes []JSONSuggestedFix
			for _, fix := range f.SuggestedFixes {
				var edits []JSONTextEdit
				for _, edit := range fix.TextEdits {
					edits = append(edits, JSONTextEdit{
						Filename: fset.Position(edit.Pos).Filename,
						Start:    fset.Position(edit.Pos).Offset,
						End:      fset.Position(edit.End).Offset,
						New:      string(edit.NewText),
					})
				}
				fixes = append(fixes, JSONSuggestedFix{
					Message: fix.Message,
					Edits:   edits,
				})
			}
			var related []JSONRelatedInformation
			for _, r := range f.Related {
				related = append(related, JSONRelatedInformation{
					Posn:    fset.Position(r.Pos).String(),
					Message: r.Message,
				})
			}
			jdiag := JSONDiagnostic{
				Category:       f.Category,
				Posn:           fset.Position(f.Pos).String(),
				Message:        f.Message,
				SuggestedFixes: fixes,
				Related:        related,
			}
			diagnostics = append(diagnostics, jdiag)
		}
		v = diagnostics
	}
	if v != nil {
		m, ok := tree[id]
		if !ok {
			m = make(map[string]interface{})
			tree[id] = m
		}
		m[name] = v
	}
}

func (tree JSONTree) Print(out io.Writer) error {
	data, err := json.MarshalIndent(tree, "", "\t")
	if err != nil {
		log.Panicf("internal error: JSON marshaling failed: %v", err)
	}
	_, err = fmt.Fprintf(out, "%s\n", data)
	return err
}
```