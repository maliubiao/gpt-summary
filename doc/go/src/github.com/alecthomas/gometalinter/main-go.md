Response:
Let's break down the thought process to analyze the provided Go code.

1. **Identify the Core Purpose:** The filename `main.go` and the package declaration `package main` immediately suggest this is the entry point of an executable program. The presence of `kingpin` imports hints at command-line argument parsing. The overall structure and numerous flags suggest a tool that analyzes Go code. The name "gometalinter" itself is a strong clue.

2. **Scan for Key Functionalities by Keyword/Import Analysis:**

   * **`kingpin`:** This is crucial. Look for `app.Flag(...)` calls. Each of these defines a command-line option. List them out and try to understand their purpose based on the flag name and help text.
   * **`os/exec`:**  This indicates the program runs external commands. It's likely the tool is orchestrating other linters.
   * **`regexp`:**  Regular expressions are used for pattern matching, probably to filter or format linter output.
   * **`encoding/json`:** The ability to output JSON is explicitly present.
   * **`text/template`:**  This suggests a customizable output format.
   * **`time`:**  Likely used for timeouts or performance measurement.
   * **Mentions of "linter":** Search for the word "linter" to understand how they are defined, enabled, disabled, and run.

3. **Analyze `setupFlags` Function:** This function is the heart of command-line parsing. Go through each `app.Flag` call:
    * Note the flag name (e.g., "config", "disable", "enable").
    * Note the short flag (e.g., '-D', '-E').
    * Note the environment variable (e.g., "GOMETALINTER_CONFIG").
    * Pay attention to the `Action` functions (e.g., `loadConfig`, `disableAction`). These define what happens when a flag is encountered.

4. **Analyze Action Functions (e.g., `loadConfig`, `disableAction`):**  These functions implement the logic associated with specific flags. Understand what each one does. For example, `loadConfig` reads a configuration file. `disableAction` modifies the list of enabled linters.

5. **Look for Core Execution Logic (`main` function):**
    * Argument parsing using `kingpin.Parse()`.
    * Conditional logic based on flags (e.g., `if config.Install`).
    * Calls to functions like `resolvePaths`, `lintersFromConfig`, `runLinters`, and output functions (`outputToJSON`, `outputToConsole`, `outputToCheckstyle`). This outlines the main workflow of the program.

6. **Infer the Overall Functionality:** Based on the above, it's clear that `gometalinter` is a tool that:
    * Runs multiple Go linters.
    * Aggregates and normalizes their output.
    * Provides extensive configuration options via command-line flags and configuration files.
    * Supports different output formats (text, JSON, Checkstyle).

7. **Identify Go Language Features:**

    * **Command-line argument parsing:** Demonstrated by the `kingpin` library.
    * **Running external commands:**  Used to execute individual linters.
    * **Regular expressions:**  For filtering output.
    * **JSON encoding/decoding:** For structured output.
    * **Text templating:** For customizable output formats.
    * **Concurrency:**  The `concurrency` flag and likely use of goroutines in the `runLinters` function indicate this.

8. **Construct Code Examples:**  Based on the identified features, create simplified Go code snippets to illustrate them. Focus on the core concepts (e.g., using `os/exec`, `regexp`, `encoding/json`). Keep the examples concise and easy to understand.

9. **Analyze Command-Line Argument Handling:**  Go through the flags defined in `setupFlags` and explain each one. Pay attention to the data types, environment variables, and default values (where implied).

10. **Identify Potential User Errors:** Think about common mistakes someone might make when using such a tool. Consider things like:
    * Incorrect configuration.
    * Misunderstanding how to enable/disable linters.
    * Confusion about path handling.
    * Problems with regular expressions.

11. **Structure the Answer:** Organize the findings into logical sections as requested by the prompt (functionality, Go features with examples, command-line arguments, common errors). Use clear and concise language, especially when explaining code. Use code blocks for examples.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "Is this just a wrapper around other linters?"  **Correction:** Yes, but it also provides significant configuration and output management.
* **Overlooking details:**  Go back and carefully read the help text for each flag. It provides valuable insights.
* **Ambiguity:**  If a flag's purpose isn't immediately clear, look for where it's used in the code. For example, seeing `config.Format` being used with a template clarifies its function.
* **Code Example Relevance:** Ensure the code examples directly relate to the functionality being described. Avoid overly complex examples.

By following these steps, and constantly refining the understanding based on the code, it's possible to arrive at a comprehensive analysis of the provided Go code.
这段代码是 `gometalinter` 工具的 `main.go` 文件的一部分。`gometalinter` 是一个 Go 语言静态代码分析工具，它可以聚合多个独立的 Go 语言代码检查工具（linters）的输出，并将其规范化为统一的格式。

以下是其主要功能：

1. **集成多个 Go 语言代码检查工具 (Linters):**  `gometalinter` 的核心功能是运行多个不同的 linters，例如 `golint`, `vet`, `errcheck`, `staticcheck` 等，并收集它们的输出结果。

2. **统一输出格式:**  不同的 linters 有不同的输出格式。`gometalinter` 将这些输出解析并转换为统一的、易于阅读的格式。它支持多种输出格式，包括默认的文本格式、JSON 格式和 Checkstyle XML 格式。

3. **配置灵活性:**  用户可以通过命令行参数或配置文件来定制 `gometalinter` 的行为，例如：
    * **启用/禁用特定的 linters:** 用户可以选择运行哪些 linters。
    * **自定义 linter 命令和正则表达式:** 用户可以添加或修改已有的 linters 定义。
    * **消息覆盖:**  可以修改特定 linter 输出的消息。
    * **严重级别映射:** 可以为不同 linters 的输出指定严重级别 (warning, error)。
    * **排除/包含特定消息:** 可以使用正则表达式过滤输出结果。
    * **跳过特定目录:**  在分析时排除某些目录。
    * **设置并发数:** 控制同时运行的 linters 数量。
    * **自定义输出格式:**  使用 Go 模板自定义输出格式。

4. **支持 vendoring:**  可以处理使用了 Go modules 或 vendor 目录的项目。

5. **安装 linters (已废弃):**  早期版本支持自动安装所需的 linters，但这段代码中可以看到相关的 Flag 标记为 DEPRECATED，推荐使用二进制包的方式安装。

6. **性能优化:**  支持并发运行 linters，以提高分析速度。可以配置只运行速度较快的 linters。

**它是什么 Go 语言功能的实现？**

`gometalinter` 主要利用以下 Go 语言功能实现：

* **`os/exec` 包:**  用于执行外部命令，即运行各个 Go linters。
* **`flag` (或更高级的 `kingpin`) 包:**  用于解析命令行参数。这里使用了 `gopkg.in/alecthomas/kingpin.v3-unstable`，一个功能更强大的命令行解析库。
* **`io` 包:**  用于处理输入输出，例如读取 linter 的输出。
* **`regexp` 包:**  用于匹配和过滤 linter 输出的消息。
* **`strings` 包:**  用于处理字符串，例如解析 linter 输出、处理路径等。
* **`encoding/json` 包:**  用于生成 JSON 格式的输出。
* **`text/template` 包:**  用于自定义输出格式。
* **`path/filepath` 包:**  用于处理文件路径。
* **`runtime` 包:**  用于获取 CPU 核心数等运行时信息，用于设置并发。
* **`time` 包:**  用于设置超时时间。

**Go 代码举例说明 (运行外部命令):**

假设我们想用 Go 代码模拟 `gometalinter` 运行 `golint` 的过程。

```go
package main

import (
	"fmt"
	"os/exec"
)

func main() {
	// 假设我们要检查当前目录下的 main.go 文件
	cmd := exec.Command("golint", "main.go")

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running golint: %v\n", err)
	}
	fmt.Println(string(output))
}
```

**假设输入与输出:**

* **输入:**  当前目录下有一个名为 `main.go` 的文件，其中包含以下代码：

```go
package main

import "fmt"

func main() {
	x := 1
	fmt.Println(x)
}
```

* **输出:**  如果 `golint` 检查到任何问题，它会输出相应的警告或错误信息。例如，如果 `golint` 认为变量名 `x` 应该更具描述性，它可能会输出：

```
main.go:5:2: exported var main should have comment or be unexported
```

**命令行参数的具体处理:**

`setupFlags` 函数定义了 `gometalinter` 的所有命令行参数。以下是一些重要参数的解释：

* **`--config` (Envar: `GOMETALINTER_CONFIG`)**:  指定加载 JSON 配置文件的路径。如果设置了环境变量 `GOMETALINTER_CONFIG`，也会使用该环境变量的值。
* **`--no-config`**: 禁用自动加载配置文件。
* **`--disable LINTER` (-D)**:  禁用指定的 linter。可以多次使用以禁用多个 linter。
* **`--enable LINTER` (-E)**:  启用指定的 linter。可以多次使用以启用多个 linter。
* **`--linter NAME:COMMAND:PATTERN`**:  自定义 linter 的定义。`NAME` 是 linter 的名称，`COMMAND` 是执行的命令，`PATTERN` 是用于解析输出的正则表达式。
* **`--message-overrides LINTER:MESSAGE`**:  覆盖特定 linter 的消息。`{message}` 占位符会被替换为原始消息。
* **`--severity LINTER:SEVERITY`**:  设置特定 linter 的严重级别（例如 `warning` 或 `error`）。
* **`--disable-all`**: 禁用所有 linter。
* **`--enable-all`**: 启用所有 linter。
* **`--format FORMAT`**:  指定输出格式。可以使用 Go 模板语法自定义格式。
* **`--vendored-linters` (DEPRECATED)**:  使用 vendor 目录下的 linter。
* **`--fast`**:  只运行速度较快的 linter。
* **`--install` (-i) (DEPRECATED)**: 尝试安装所有已知的 linter。
* **`--update` (-u) (DEPRECATED)**: 在安装时传递 `-u` 标志给 `go tool`。
* **`--force` (-f) (DEPRECATED)**: 在安装时传递 `-f` 标志给 `go tool`。
* **`--download-only` (DEPRECATED)**: 在安装时传递 `-d` 标志给 `go tool`。
* **`--debug` (-d)**:  显示失败的 linter 的调试信息。
* **`--concurrency` (-j) N**:  设置并发运行的 linter 数量。默认为 CPU 核心数。
* **`--exclude REGEXP` (-e)**:  排除匹配指定正则表达式的消息。可以多次使用。
* **`--include REGEXP` (-I)**:  只包含匹配指定正则表达式的消息。可以多次使用。
* **`--skip DIR...` (-s)**:  跳过指定的目录。可以多次使用。
* **`--vendor`**:  启用 vendoring 支持 (跳过 'vendor' 目录并设置 `GO15VENDOREXPERIMENT=1`)。
* **`--cyclo-over N`**:  报告圈复杂度超过 `N` 的函数 (使用 `gocyclo`)。
* **`--line-length N`**:  报告长度超过 `N` 的行 (使用 `lll`)。
* **`--misspell-locale LOCALE`**:  指定使用的 locale (使用 `misspell`)。
* **`--min-confidence N`**:  传递给 `golint` 的最小置信度。
* **`--min-occurrences N`**:  传递给 `goconst` 的最小出现次数。
* **`--min-const-length N`**:  传递给 `goconst` 的最小常量长度。
* **`--dupl-threshold N`**:  `dupl` 的最小 token 序列克隆阈值。
* **`--sort KEY`**:  指定输出排序的键 (例如 `path`, `line`, `severity`, `linter`)。
* **`--tests` (-t)**:  包含测试文件。
* **`--deadline DURATION`**:  设置 linter 的超时时间。
* **`--errors`**:  只显示错误。
* **`--json`**:  生成 JSON 格式的输出。
* **`--checkstyle`**: 生成 Checkstyle XML 格式的输出。
* **`--enable-gc`**:  为 linters 启用 GC (在大型代码库上可能有用)。
* **`--aggregate`**:  聚合多个 linter 报告的问题。
* **`--warn-unmatched-nolint`**:  警告 `nolint` 指令没有匹配到任何问题。
* **`path`**: 要检查的目录。默认为当前目录 `.`。可以使用 `...` 表示递归检查子目录。

**使用者易犯错的点:**

* **配置文件覆盖:**  如果同时使用了命令行参数和配置文件，需要理解它们的优先级。命令行参数会覆盖配置文件中的设置。
* **linter 名称拼写错误:**  在启用或禁用 linter 时，如果 linter 名称拼写错误，`gometalinter` 可能不会按预期工作，并且可能不会给出明确的错误提示。
* **正则表达式错误:**  在配置 `exclude` 或 `include` 参数时，如果正则表达式写错，可能会导致意外的过滤结果。
* **不理解 linters 的作用:**  不同的 linters 检查不同的代码问题。使用者可能不清楚某个 linter 的作用，导致启用或禁用了不合适的 linter。
* **路径问题:**  在使用 `...` 递归检查目录时，需要注意当前工作目录，避免检查了不希望检查的目录。
* **依赖未安装:** 虽然代码中包含安装 linters 的逻辑，但由于其已废弃，使用者可能会忘记手动安装某些依赖的 linter，导致 `gometalinter` 无法正常运行。
* **误用已废弃的参数:**  使用带有 `DEPRECATED` 标记的参数可能会导致混淆，因为这些功能可能不再按预期工作或已被移除。例如，依赖内置的安装功能可能会遇到问题，建议使用二进制包管理 linters。

总的来说，这段代码定义了一个功能强大的 Go 代码静态分析工具的核心逻辑，它通过组合和管理多个独立的 linters，为开发者提供全面的代码质量检查能力。理解其命令行参数和配置方式对于有效使用该工具至关重要。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/main.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"text/template"
	"time"

	kingpin "gopkg.in/alecthomas/kingpin.v3-unstable"
)

var (
	// Locations to look for vendored linters.
	vendoredSearchPaths = [][]string{
		{"github.com", "alecthomas", "gometalinter", "_linters"},
		{"gopkg.in", "alecthomas", "gometalinter.v2", "_linters"},
	}
	defaultConfigPath = ".gometalinter.json"

	// Populated by goreleaser.
	version = "master"
	commit  = "?"
	date    = ""
)

func setupFlags(app *kingpin.Application) {
	app.Flag("config", "Load JSON configuration from file.").Envar("GOMETALINTER_CONFIG").Action(loadConfig).String()
	app.Flag("no-config", "Disable automatic loading of config file.").Bool()
	app.Flag("disable", "Disable previously enabled linters.").PlaceHolder("LINTER").Short('D').Action(disableAction).Strings()
	app.Flag("enable", "Enable previously disabled linters.").PlaceHolder("LINTER").Short('E').Action(enableAction).Strings()
	app.Flag("linter", "Define a linter.").PlaceHolder("NAME:COMMAND:PATTERN").Action(cliLinterOverrides).StringMap()
	app.Flag("message-overrides", "Override message from linter. {message} will be expanded to the original message.").PlaceHolder("LINTER:MESSAGE").StringMapVar(&config.MessageOverride)
	app.Flag("severity", "Map of linter severities.").PlaceHolder("LINTER:SEVERITY").StringMapVar(&config.Severity)
	app.Flag("disable-all", "Disable all linters.").Action(disableAllAction).Bool()
	app.Flag("enable-all", "Enable all linters.").Action(enableAllAction).Bool()
	app.Flag("format", "Output format.").PlaceHolder(config.Format).StringVar(&config.Format)
	app.Flag("vendored-linters", "Use vendored linters (recommended) (DEPRECATED - use binary packages).").BoolVar(&config.VendoredLinters)
	app.Flag("fast", "Only run fast linters.").BoolVar(&config.Fast)
	app.Flag("install", "Attempt to install all known linters (DEPRECATED - use binary packages).").Short('i').BoolVar(&config.Install)
	app.Flag("update", "Pass -u to go tool when installing (DEPRECATED - use binary packages).").Short('u').BoolVar(&config.Update)
	app.Flag("force", "Pass -f to go tool when installing (DEPRECATED - use binary packages).").Short('f').BoolVar(&config.Force)
	app.Flag("download-only", "Pass -d to go tool when installing (DEPRECATED - use binary packages).").BoolVar(&config.DownloadOnly)
	app.Flag("debug", "Display messages for failed linters, etc.").Short('d').BoolVar(&config.Debug)
	app.Flag("concurrency", "Number of concurrent linters to run.").PlaceHolder(fmt.Sprintf("%d", runtime.NumCPU())).Short('j').IntVar(&config.Concurrency)
	app.Flag("exclude", "Exclude messages matching these regular expressions.").Short('e').PlaceHolder("REGEXP").StringsVar(&config.Exclude)
	app.Flag("include", "Include messages matching these regular expressions.").Short('I').PlaceHolder("REGEXP").StringsVar(&config.Include)
	app.Flag("skip", "Skip directories with this name when expanding '...'.").Short('s').PlaceHolder("DIR...").StringsVar(&config.Skip)
	app.Flag("vendor", "Enable vendoring support (skips 'vendor' directories and sets GO15VENDOREXPERIMENT=1).").BoolVar(&config.Vendor)
	app.Flag("cyclo-over", "Report functions with cyclomatic complexity over N (using gocyclo).").PlaceHolder("10").IntVar(&config.Cyclo)
	app.Flag("line-length", "Report lines longer than N (using lll).").PlaceHolder("80").IntVar(&config.LineLength)
	app.Flag("misspell-locale", "Specify locale to use (using misspell).").PlaceHolder("").StringVar(&config.MisspellLocale)
	app.Flag("min-confidence", "Minimum confidence interval to pass to golint.").PlaceHolder(".80").FloatVar(&config.MinConfidence)
	app.Flag("min-occurrences", "Minimum occurrences to pass to goconst.").PlaceHolder("3").IntVar(&config.MinOccurrences)
	app.Flag("min-const-length", "Minimum constant length.").PlaceHolder("3").IntVar(&config.MinConstLength)
	app.Flag("dupl-threshold", "Minimum token sequence as a clone for dupl.").PlaceHolder("50").IntVar(&config.DuplThreshold)
	app.Flag("sort", fmt.Sprintf("Sort output by any of %s.", strings.Join(sortKeys, ", "))).PlaceHolder("none").EnumsVar(&config.Sort, sortKeys...)
	app.Flag("tests", "Include test files for linters that support this option.").Short('t').BoolVar(&config.Test)
	app.Flag("deadline", "Cancel linters if they have not completed within this duration.").PlaceHolder("30s").DurationVar((*time.Duration)(&config.Deadline))
	app.Flag("errors", "Only show errors.").BoolVar(&config.Errors)
	app.Flag("json", "Generate structured JSON rather than standard line-based output.").BoolVar(&config.JSON)
	app.Flag("checkstyle", "Generate checkstyle XML rather than standard line-based output.").BoolVar(&config.Checkstyle)
	app.Flag("enable-gc", "Enable GC for linters (useful on large repositories).").BoolVar(&config.EnableGC)
	app.Flag("aggregate", "Aggregate issues reported by several linters.").BoolVar(&config.Aggregate)
	app.Flag("warn-unmatched-nolint", "Warn if a nolint directive is not matched with an issue.").BoolVar(&config.WarnUnmatchedDirective)
	app.GetFlag("help").Short('h')
}

func cliLinterOverrides(app *kingpin.Application, element *kingpin.ParseElement, ctx *kingpin.ParseContext) error {
	// expected input structure - <name>:<command-spec>
	parts := strings.SplitN(*element.Value, ":", 2)
	if len(parts) < 2 {
		return fmt.Errorf("incorrectly formatted input: %s", *element.Value)
	}
	name := parts[0]
	spec := parts[1]
	conf, err := parseLinterConfigSpec(name, spec)
	if err != nil {
		return fmt.Errorf("incorrectly formatted input: %s", *element.Value)
	}
	config.Linters[name] = StringOrLinterConfig(conf)
	return nil
}

func loadDefaultConfig(app *kingpin.Application, element *kingpin.ParseElement, ctx *kingpin.ParseContext) error {
	if element != nil {
		return nil
	}

	for _, elem := range ctx.Elements {
		if f := elem.OneOf.Flag; f == app.GetFlag("config") || f == app.GetFlag("no-config") {
			return nil
		}
	}

	configFile, found, err := findDefaultConfigFile()
	if err != nil || !found {
		return err
	}

	return loadConfigFile(configFile)
}

func loadConfig(app *kingpin.Application, element *kingpin.ParseElement, ctx *kingpin.ParseContext) error {
	return loadConfigFile(*element.Value)
}

func disableAction(app *kingpin.Application, element *kingpin.ParseElement, ctx *kingpin.ParseContext) error {
	out := []string{}
	for _, linter := range config.Enable {
		if linter != *element.Value {
			out = append(out, linter)
		}
	}
	config.Enable = out
	return nil
}

func enableAction(app *kingpin.Application, element *kingpin.ParseElement, ctx *kingpin.ParseContext) error {
	config.Enable = append(config.Enable, *element.Value)
	return nil
}

func disableAllAction(app *kingpin.Application, element *kingpin.ParseElement, ctx *kingpin.ParseContext) error {
	config.Enable = []string{}
	return nil
}

func enableAllAction(app *kingpin.Application, element *kingpin.ParseElement, ctx *kingpin.ParseContext) error {
	for linter := range defaultLinters {
		config.Enable = append(config.Enable, linter)
	}
	config.EnableAll = true
	return nil
}

type debugFunction func(format string, args ...interface{})

func debug(format string, args ...interface{}) {
	if config.Debug {
		t := time.Now().UTC()
		fmt.Fprintf(os.Stderr, "DEBUG: [%s] ", t.Format(time.StampMilli))
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}
}

func namespacedDebug(prefix string) debugFunction {
	return func(format string, args ...interface{}) {
		debug(prefix+format, args...)
	}
}

func warning(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "WARNING: "+format+"\n", args...)
}

func formatLinters() string {
	nameToLinter := map[string]*Linter{}
	var linterNames []string
	for _, linter := range getDefaultLinters() {
		linterNames = append(linterNames, linter.Name)
		nameToLinter[linter.Name] = linter
	}
	sort.Strings(linterNames)

	w := bytes.NewBuffer(nil)
	for _, linterName := range linterNames {
		linter := nameToLinter[linterName]

		install := "(" + linter.InstallFrom + ")"
		if install == "()" {
			install = ""
		}
		fmt.Fprintf(w, "  %s: %s\n\tcommand: %s\n\tregex: %s\n\tfast: %t\n\tdefault enabled: %t\n\n",
			linter.Name, install, linter.Command, linter.Pattern, linter.IsFast, linter.defaultEnabled)
	}
	return w.String()
}

func formatSeverity() string {
	w := bytes.NewBuffer(nil)
	for name, severity := range config.Severity {
		fmt.Fprintf(w, "  %s -> %s\n", name, severity)
	}
	return w.String()
}

func main() {
	kingpin.Version(fmt.Sprintf("gometalinter version %s built from %s on %s", version, commit, date))
	pathsArg := kingpin.Arg("path", "Directories to lint. Defaults to \".\". <path>/... will recurse.").Strings()
	app := kingpin.CommandLine
	app.Action(loadDefaultConfig)
	setupFlags(app)
	app.Help = fmt.Sprintf(`Aggregate and normalise the output of a whole bunch of Go linters.

PlaceHolder linters:

%s

Severity override map (default is "warning"):

%s
`, formatLinters(), formatSeverity())
	kingpin.Parse()

	if config.Install {
		if config.VendoredLinters {
			configureEnvironmentForInstall()
		}
		installLinters()
		return
	}

	configureEnvironment()
	include, exclude := processConfig(config)

	start := time.Now()
	paths := resolvePaths(*pathsArg, config.Skip)

	linters := lintersFromConfig(config)
	err := validateLinters(linters, config)
	kingpin.FatalIfError(err, "")

	issues, errch := runLinters(linters, paths, config.Concurrency, exclude, include)
	status := 0
	if config.JSON {
		status |= outputToJSON(issues)
	} else if config.Checkstyle {
		status |= outputToCheckstyle(issues)
	} else {
		status |= outputToConsole(issues)
	}
	for err := range errch {
		warning("%s", err)
		status |= 2
	}
	elapsed := time.Since(start)
	debug("total elapsed time %s", elapsed)
	os.Exit(status)
}

// nolint: gocyclo
func processConfig(config *Config) (include *regexp.Regexp, exclude *regexp.Regexp) {
	tmpl, err := template.New("output").Parse(config.Format)
	kingpin.FatalIfError(err, "invalid format %q", config.Format)
	config.formatTemplate = tmpl

	// Ensure that gometalinter manages threads, not linters.
	os.Setenv("GOMAXPROCS", "1")
	// Force sorting by path if checkstyle mode is selected
	// !jsonFlag check is required to handle:
	// 	gometalinter --json --checkstyle --sort=severity
	if config.Checkstyle && !config.JSON {
		config.Sort = []string{"path"}
	}

	// PlaceHolder to skipping "vendor" directory if GO15VENDOREXPERIMENT=1 is enabled.
	// TODO(alec): This will probably need to be enabled by default at a later time.
	if os.Getenv("GO15VENDOREXPERIMENT") == "1" || config.Vendor {
		if err := os.Setenv("GO15VENDOREXPERIMENT", "1"); err != nil {
			warning("setenv GO15VENDOREXPERIMENT: %s", err)
		}
		config.Skip = append(config.Skip, "vendor")
		config.Vendor = true
	}
	if len(config.Exclude) > 0 {
		exclude = regexp.MustCompile(strings.Join(config.Exclude, "|"))
	}

	if len(config.Include) > 0 {
		include = regexp.MustCompile(strings.Join(config.Include, "|"))
	}

	runtime.GOMAXPROCS(config.Concurrency)
	return include, exclude
}

func outputToConsole(issues chan *Issue) int {
	status := 0
	for issue := range issues {
		if config.Errors && issue.Severity != Error {
			continue
		}
		fmt.Println(issue.String())
		status = 1
	}
	return status
}

func outputToJSON(issues chan *Issue) int {
	fmt.Println("[")
	status := 0
	for issue := range issues {
		if config.Errors && issue.Severity != Error {
			continue
		}
		if status != 0 {
			fmt.Printf(",\n")
		}
		d, err := json.Marshal(issue)
		kingpin.FatalIfError(err, "")
		fmt.Printf("  %s", d)
		status = 1
	}
	fmt.Printf("\n]\n")
	return status
}

func resolvePaths(paths, skip []string) []string {
	if len(paths) == 0 {
		return []string{"."}
	}

	skipPath := newPathFilter(skip)
	dirs := newStringSet()
	for _, path := range paths {
		if strings.HasSuffix(path, "/...") {
			root := filepath.Dir(path)
			if lstat, err := os.Lstat(root); err == nil && (lstat.Mode()&os.ModeSymlink) != 0 {
				// if we have a symlink append os.PathSeparator to force a dereference of the symlink
				// to workaround bug in filepath.Walk that won't dereference a root path that
				// is a dir symlink
				root = root + string(os.PathSeparator)
			}
			_ = filepath.Walk(root, func(p string, i os.FileInfo, err error) error {
				if err != nil {
					warning("invalid path %q: %s", p, err)
					return err
				}

				skip := skipPath(p)
				switch {
				case i.IsDir() && skip:
					return filepath.SkipDir
				case !i.IsDir() && !skip && strings.HasSuffix(p, ".go"):
					dirs.add(filepath.Clean(filepath.Dir(p)))
				}
				return nil
			})
		} else {
			dirs.add(filepath.Clean(path))
		}
	}
	out := make([]string, 0, dirs.size())
	for _, d := range dirs.asSlice() {
		out = append(out, relativePackagePath(d))
	}
	sort.Strings(out)
	for _, d := range out {
		debug("linting path %s", d)
	}
	return out
}

func newPathFilter(skip []string) func(string) bool {
	filter := map[string]bool{}
	for _, name := range skip {
		filter[name] = true
	}

	return func(path string) bool {
		base := filepath.Base(path)
		if filter[base] || filter[path] {
			return true
		}
		return base != "." && base != ".." && strings.ContainsAny(base[0:1], "_.")
	}
}

func relativePackagePath(dir string) string {
	if filepath.IsAbs(dir) || strings.HasPrefix(dir, ".") {
		return dir
	}
	// package names must start with a ./
	return "./" + dir
}

func lintersFromConfig(config *Config) map[string]*Linter {
	out := map[string]*Linter{}
	for _, name := range config.Enable {
		linter := getLinterByName(name, LinterConfig(config.Linters[name]))
		if config.Fast && !linter.IsFast {
			continue
		}
		out[name] = linter
	}
	for _, linter := range config.Disable {
		delete(out, linter)
	}
	return out
}

func findVendoredLinters() string {
	gopaths := getGoPathList()
	for _, home := range vendoredSearchPaths {
		for _, p := range gopaths {
			joined := append([]string{p, "src"}, home...)
			vendorRoot := filepath.Join(joined...)
			if _, err := os.Stat(vendorRoot); err == nil {
				return vendorRoot
			}
		}
	}
	return ""
}

// Go 1.8 compatible GOPATH.
func getGoPath() string {
	path := os.Getenv("GOPATH")
	if path == "" {
		user, err := user.Current()
		kingpin.FatalIfError(err, "")
		path = filepath.Join(user.HomeDir, "go")
	}
	return path
}

func getGoPathList() []string {
	return strings.Split(getGoPath(), string(os.PathListSeparator))
}

// addPath appends path to paths if path does not already exist in paths. Returns
// the new paths.
func addPath(paths []string, path string) []string {
	for _, existingpath := range paths {
		if path == existingpath {
			return paths
		}
	}
	return append(paths, path)
}

// configureEnvironment adds all `bin/` directories from $GOPATH to $PATH
func configureEnvironment() {
	paths := addGoBinsToPath(getGoPathList())
	setEnv("PATH", strings.Join(paths, string(os.PathListSeparator)))
	setEnv("GOROOT", discoverGoRoot())
	debugPrintEnv()
}

func discoverGoRoot() string {
	goroot := os.Getenv("GOROOT")
	if goroot == "" {
		output, err := exec.Command("go", "env", "GOROOT").Output()
		kingpin.FatalIfError(err, "could not find go binary")
		goroot = string(output)
	}
	return strings.TrimSpace(goroot)
}

func addGoBinsToPath(gopaths []string) []string {
	paths := strings.Split(os.Getenv("PATH"), string(os.PathListSeparator))
	for _, p := range gopaths {
		paths = addPath(paths, filepath.Join(p, "bin"))
	}
	gobin := os.Getenv("GOBIN")
	if gobin != "" {
		paths = addPath(paths, gobin)
	}
	return paths
}

// configureEnvironmentForInstall sets GOPATH and GOBIN so that vendored linters
// can be installed
func configureEnvironmentForInstall() {
	if config.Update {
		warning(`Linters are now vendored by default, --update ignored. The original
behaviour can be re-enabled with --no-vendored-linters.

To request an update for a vendored linter file an issue at:
https://github.com/alecthomas/gometalinter/issues/new
`)
	}
	gopaths := getGoPathList()
	vendorRoot := findVendoredLinters()
	if vendorRoot == "" {
		kingpin.Fatalf("could not find vendored linters in GOPATH=%q", getGoPath())
	}
	debug("found vendored linters at %s, updating environment", vendorRoot)

	gobin := os.Getenv("GOBIN")
	if gobin == "" {
		gobin = filepath.Join(gopaths[0], "bin")
	}
	setEnv("GOBIN", gobin)

	// "go install" panics when one GOPATH element is beneath another, so set
	// GOPATH to the vendor root
	setEnv("GOPATH", vendorRoot)
	debugPrintEnv()
}

func setEnv(key, value string) {
	if err := os.Setenv(key, value); err != nil {
		warning("setenv %s: %s", key, err)
	} else {
		debug("setenv %s=%q", key, value)
	}
}

func debugPrintEnv() {
	debug("Current environment:")
	debug("PATH=%q", os.Getenv("PATH"))
	debug("GOPATH=%q", os.Getenv("GOPATH"))
	debug("GOBIN=%q", os.Getenv("GOBIN"))
	debug("GOROOT=%q", os.Getenv("GOROOT"))
}

"""



```