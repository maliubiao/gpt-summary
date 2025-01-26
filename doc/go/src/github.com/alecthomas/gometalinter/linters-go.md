Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding - What is this code about?**

The first step is to identify the core purpose. The package name `main` and the presence of `import` statements like `os/exec` and `gopkg.in/alecthomas/kingpin.v3-unstable` (a command-line parsing library) strongly suggest this is an executable tool, likely for linting Go code. The file name `linters.go` further reinforces this idea, indicating it manages different linters.

**2. Key Data Structures - What are the fundamental building blocks?**

Next, focus on the defined types: `LinterConfig` and `Linter`.

*   `LinterConfig`: This struct holds configuration information *for* a linter. The fields (`Command`, `Pattern`, `InstallFrom`, `PartitionStrategy`, `IsFast`, `defaultEnabled`) hint at how a linter is executed, how its output is parsed, and how it's managed. The `partitionStrategy` is intriguing and suggests handling of input files.

*   `Linter`: This struct represents an actual linter instance. It embeds `LinterConfig` and adds a `Name` and a compiled regular expression (`regex`). This makes sense – you need a name to identify the linter and a regex to extract meaningful information from its output.

**3. Core Functions - What are the primary actions?**

Scan the functions and group them by their apparent purpose:

*   **Linter Creation and Management:**
    *   `NewLinter`:  Crucial for creating `Linter` instances. It handles pattern preprocessing and regex compilation.
    *   `getLinterByName`:  Retrieves a linter configuration (likely from a default set) and allows for overrides.
    *   `getDefaultLinters`:  Loads all the predefined linters.
    *   `defaultEnabled`: Returns a list of linters that are enabled by default.
    *   `validateLinters`: Checks if provided linter names are valid.

*   **Linter Configuration:**
    *   `parseLinterConfigSpec`:  Parses a string representation of a linter's configuration.

*   **Linter Installation:**
    *   `makeInstallCommand`: Constructs the `go get` or `go install` command to install linters.
    *   `installLintersWithOneCommand`, `installLintersIndividually`, `installLinters`: Implement different strategies for installing linters.

*   **Utility/Helper:**
    *   `String` (on `Linter`):  Provides a string representation of a linter.

*   **Data Initialization:**
    *   `predefinedPatterns`:  A map of common output patterns for linters.
    *   `defaultLinters`:  A map containing the default configuration for various linters. This is a *huge* clue about the core functionality.

**4. Putting it Together - Forming the Big Picture**

Connecting the dots, it becomes clear that this code defines the structure and logic for managing and executing various Go linters. The `defaultLinters` map is the central repository of information for each supported linter, including how to run it (`Command`), how to interpret its output (`Pattern`), and how to install it (`InstallFrom`). The code provides mechanisms to override these defaults and install linters.

**5. Answering the Specific Questions:**

Now, armed with a good understanding, address the prompt's questions:

*   **Functionality:**  List the deduced functions in plain English.
*   **Go Feature (Structs):** The `LinterConfig` and `Linter` structs are the obvious examples. Provide a simple code illustration.
*   **Code Reasoning (Regex):** The `NewLinter` function compiling the `Pattern` into a `regexp.Regexp` is a good example. Create a hypothetical input and output scenario.
*   **Command-Line Arguments:** The import of `kingpin` is the key. Explain its role in handling command-line flags (though the specific flags aren't defined in this snippet).
*   **Common Mistakes:** Focus on configuration errors, specifically related to incorrect patterns or command names, as these are directly handled by this code.

**6. Refinement and Language:**

Finally, review the generated answer for clarity, accuracy, and completeness. Use clear and concise language, and ensure the Go code examples are correct and easy to understand. Use proper formatting and bullet points for readability.

This systematic approach of identifying key structures, functions, and their relationships allows for a comprehensive understanding of the code and enables accurate answering of the specific questions. The key is to start broad and gradually narrow the focus to specific details.
这段代码是 `gometalinter` 工具中负责定义和管理各种 Go 语言代码检查器（linters）的部分。它的主要功能是：

1. **定义 Linters 的配置:**  通过 `LinterConfig` 结构体定义了每个 linter 的基本属性，例如：
    *   `Command`:  执行 linter 的命令。
    *   `Pattern`:  用于解析 linter 输出的正则表达式。
    *   `InstallFrom`:  如何安装该 linter（通常是 `go get` 的路径）。
    *   `PartitionStrategy`:  如何将待检查的文件/目录分配给 linter 执行（例如，按文件、按目录、按包）。
    *   `IsFast`:  标记 linter 是否执行速度快。
    *   `defaultEnabled`:  标记 linter 是否默认启用。

2. **表示 Linter 实例:**  `Linter` 结构体包含了 `LinterConfig` 以及 linter 的名称和编译后的正则表达式对象。

3. **创建 Linter 实例:** `NewLinter` 函数根据给定的名称和配置创建 `Linter` 实例，并编译配置中的正则表达式。

4. **管理预定义的输出模式:** `predefinedPatterns` 存储了一些常见的 linter 输出模式，方便配置。

5. **根据名称获取 Linter:** `getLinterByName` 函数根据 linter 的名称获取其配置，并允许通过 `overrideConf` 参数覆盖默认配置。

6. **解析 Linter 配置字符串:** `parseLinterConfigSpec` 函数用于解析命令行或配置文件中指定的 linter 配置字符串。

7. **生成安装命令:** `makeInstallCommand` 函数根据配置生成用于安装 linter 的 `go get` 或 `go install` 命令。

8. **安装 Linters:** `installLintersWithOneCommand` 和 `installLintersIndividually` 函数分别实现了用单个命令或逐个命令安装多个 linter 的逻辑。 `installLinters` 函数则负责安装 `defaultLinters` 中配置了 `InstallFrom` 的所有 linter。

9. **获取默认启用的 Linters:** `defaultEnabled` 函数返回默认启用的 linter 名称列表。

10. **验证 Linters:** `validateLinters` 函数检查用户指定的 linter 是否是已知（默认或自定义）的 linter。

11. **定义默认的 Linters:** `defaultLinters` 变量是一个 map，存储了所有支持的 linter 的默认配置。 这部分定义了 `gometalinter` 支持的所有内置检查器，以及它们的执行方式和输出格式。

**它是什么 Go 语言功能的实现？**

这段代码主要使用了以下 Go 语言功能：

*   **结构体 (struct):** `LinterConfig` 和 `Linter` 用于组织和表示 linter 的配置和实例。
*   **方法 (method):**  例如 `(l *Linter) String()` 定义了 `Linter` 类型的方法。
*   **Map (map):** `predefinedPatterns` 和 `defaultLinters` 使用 map 来存储键值对数据。
*   **正则表达式 (regexp):** 使用 `regexp` 包来编译和匹配 linter 的输出。
*   **字符串操作 (strings):** 使用 `strings` 包进行字符串的分割和连接等操作.
*   **命令执行 (os/exec):** 使用 `os/exec` 包来执行外部命令，即各个 linter。
*   **错误处理 (error):** 函数返回 `error` 类型来表示操作是否成功。
*   **导入 (import):**  导入了其他包，例如 `fmt`、`os`、`sort` 和 `gopkg.in/alecthomas/kingpin.v3-unstable` (用于处理命令行参数)。

**Go 代码举例说明:**

**1. 创建和使用 Linter 实例:**

```go
package main

import (
	"fmt"
	"regexp"
)

type LinterConfig struct {
	Command string
	Pattern string
}

type Linter struct {
	LinterConfig
	Name  string
	regex *regexp.Regexp
}

func NewLinter(name string, config LinterConfig) (*Linter, error) {
	regex, err := regexp.Compile(config.Pattern)
	if err != nil {
		return nil, err
	}
	return &Linter{
		LinterConfig: config,
		Name:         name,
		regex:        regex,
	}, nil
}

func main() {
	config := LinterConfig{
		Command: "echo 'file.go:10:20: This is a warning'",
		Pattern: `^(?P<path>.*?\.go):(?P<line>\d+):(?P<col>\d+):\s*(?P<message>.*)$`,
	}
	linter, err := NewLinter("example", config)
	if err != nil {
		fmt.Println("Error creating linter:", err)
		return
	}
	fmt.Printf("Linter Name: %s\n", linter.Name)
	fmt.Printf("Linter Command: %s\n", linter.Command)

	// 假设我们执行了 linter 的命令并获得了输出
	output := "file.go:10:20: This is a warning"
	matches := linter.regex.FindStringSubmatch(output)
	if len(matches) > 0 {
		fmt.Printf("Path: %s, Line: %s, Column: %s, Message: %s\n", matches[1], matches[2], matches[3], matches[4])
	}
}
```

**假设输入与输出:**

在这个例子中，`NewLinter` 函数接收一个 `LinterConfig`，其中 `Pattern` 是一个正则表达式。

**假设输入:**

```go
config := LinterConfig{
    Command: "echo 'file.go:10:20: This is a warning'",
    Pattern: `^(?P<path>.*?\.go):(?P<line>\d+):(?P<col>\d+):\s*(?P<message>.*)$`,
}
```

**预期输出:**

```
Linter Name: example
Linter Command: echo 'file.go:10:20: This is a warning'
Path: file.go, Line: 10, Column: 20, Message: This is a warning
```

**2. 使用预定义的 Pattern:**

```go
package main

import (
	"fmt"
	"regexp"
)

type LinterConfig struct {
	Command string
	Pattern string
}

type Linter struct {
	LinterConfig
	Name  string
	regex *regexp.Regexp
}

var predefinedPatterns = map[string]string{
	"PATH:LINE:COL:MESSAGE": `^(?P<path>.*?\.go):(?P<line>\d+):(?P<col>\d+):\s*(?P<message>.*)$`,
}

func NewLinter(name string, config LinterConfig) (*Linter, error) {
	if p, ok := predefinedPatterns[config.Pattern]; ok {
		config.Pattern = p
	}
	regex, err := regexp.Compile(config.Pattern)
	if err != nil {
		return nil, err
	}
	return &Linter{
		LinterConfig: config,
		Name:         name,
		regex:        regex,
	}, nil
}

func main() {
	config := LinterConfig{
		Command: "echo 'another.go:5:1: Another issue'",
		Pattern: "PATH:LINE:COL:MESSAGE", // 使用预定义的模式名称
	}
	linter, err := NewLinter("another_example", config)
	if err != nil {
		fmt.Println("Error creating linter:", err)
		return
	}

	output := "another.go:5:1: Another issue"
	matches := linter.regex.FindStringSubmatch(output)
	if len(matches) > 0 {
		fmt.Printf("Path: %s, Line: %s, Column: %s, Message: %s\n", matches[1], matches[2], matches[3], matches[4])
	}
}
```

**假设输入与输出:**

**假设输入:**

```go
config := LinterConfig{
    Command: "echo 'another.go:5:1: Another issue'",
    Pattern: "PATH:LINE:COL:MESSAGE",
}
```

**预期输出:**

```
Path: another.go, Line: 5, Column: 1, Message: Another issue
```

**命令行参数的具体处理:**

这段代码片段中，关于命令行参数的处理主要体现在 `kingpin` 包的使用上。 `kingpin` 是一个 Go 语言的命令行解析库。虽然这段代码没有直接展示 `kingpin` 如何定义和解析具体的命令行参数，但可以推断出它被用于配置 `gometalinter` 的行为，例如：

*   **启用/禁用特定的 linters:** 用户可以通过命令行参数指定要运行哪些 linters。
*   **覆盖 linter 的配置:** 用户可以修改特定 linter 的命令或正则表达式。
*   **控制安装行为:** 用户可能可以使用参数来控制是否更新 linter，是否只下载而不安装等。
*   **设置全局配置:** 例如，代码中出现的 `config.VendoredLinters`、`config.Update`、`config.Force`、`config.DownloadOnly` 和 `config.Debug` 很可能就是通过 `kingpin` 定义的命令行 flag 来设置的。

**例子:**

假设 `gometalinter` 定义了以下命令行参数：

*   `--enable=LINTER1,LINTER2`: 启用指定的 linters。
*   `--linter=NAME:COMMAND:PATTERN`:  覆盖特定 linter 的配置。
*   `--install`:  安装缺失的 linters。
*   `--update`:  更新已安装的 linters。

那么，用户可以通过以下方式运行 `gometalinter`：

```bash
gometalinter --enable=golint,vet ./...
gometalinter --linter=golint:"golint -min_confidence 0.9":"PATH:LINE:COL:MESSAGE" ./...
gometalinter --install
gometalinter --update
```

**使用者易犯错的点:**

1. **错误的正则表达式 (Pattern):**  配置 linter 时，如果 `Pattern` 正则表达式写的不正确，`gometalinter` 将无法正确解析 linter 的输出，导致无法显示错误信息或显示错误的信息。

    **例如:**  如果 `golint` 的输出格式是 `file.go:10:20: message`，但 `Pattern` 配置成了 `^(?P<path>.*?\.go):(?P<line>\d+):\s*(?P<message>.*)$` (缺少了列号的匹配)，那么列号信息将无法被提取。

2. **Linter 命令不存在或路径不正确:** 如果 `Command` 中指定的 linter 命令不存在于系统的 PATH 环境变量中，或者路径配置错误，`gometalinter` 将无法执行该 linter。

    **例如:**  如果用户错误地将 `Command` 配置为 `"golin"` 而不是 `"golint"`，或者该 linter 没有安装，`gometalinter` 将会报错。

3. **不理解 PartitionStrategy 的作用:**  `PartitionStrategy` 决定了如何将文件分配给 linter 执行。如果理解不当，可能会导致某些 linter 没有被应用到所有预期的文件上，或者导致不必要的重复执行。

    **例如:**  如果一个 linter 的 `PartitionStrategy` 是 `partitionPathsAsPackages`，但用户只指定了一个文件路径作为输入，那么这个 linter 可能会检查包含该文件的整个包，而不是仅仅那个文件。

4. **忘记安装所需的 Linters:**  一些 linter 并非 Go 语言自带的工具，需要单独安装。如果用户尝试启用一个未安装的 linter，`gometalinter` 通常会尝试安装，但如果网络有问题或配置不当，安装可能会失败。

这段代码的核心在于定义了一种灵活的方式来集成和管理各种 Go 代码检查工具，使得 `gometalinter` 能够统一调用它们并解析它们的输出，为开发者提供一致的代码质量反馈。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/linters.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package main

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"

	kingpin "gopkg.in/alecthomas/kingpin.v3-unstable"
)

type LinterConfig struct {
	Command           string
	Pattern           string
	InstallFrom       string
	PartitionStrategy partitionStrategy
	IsFast            bool
	defaultEnabled    bool
}

type Linter struct {
	LinterConfig
	Name  string
	regex *regexp.Regexp
}

// NewLinter returns a new linter from a config
func NewLinter(name string, config LinterConfig) (*Linter, error) {
	if p, ok := predefinedPatterns[config.Pattern]; ok {
		config.Pattern = p
	}
	regex, err := regexp.Compile("(?m:" + config.Pattern + ")")
	if err != nil {
		return nil, err
	}
	if config.PartitionStrategy == nil {
		config.PartitionStrategy = partitionPathsAsDirectories
	}
	return &Linter{
		LinterConfig: config,
		Name:         name,
		regex:        regex,
	}, nil
}

func (l *Linter) String() string {
	return l.Name
}

var predefinedPatterns = map[string]string{
	"PATH:LINE:COL:MESSAGE": `^(?P<path>.*?\.go):(?P<line>\d+):(?P<col>\d+):\s*(?P<message>.*)$`,
	"PATH:LINE:MESSAGE":     `^(?P<path>.*?\.go):(?P<line>\d+):\s*(?P<message>.*)$`,
}

func getLinterByName(name string, overrideConf LinterConfig) *Linter {
	conf := defaultLinters[name]
	if val := overrideConf.Command; val != "" {
		conf.Command = val
	}
	if val := overrideConf.Pattern; val != "" {
		conf.Pattern = val
	}
	if val := overrideConf.InstallFrom; val != "" {
		conf.InstallFrom = val
	}
	if overrideConf.IsFast {
		conf.IsFast = true
	}
	if val := overrideConf.PartitionStrategy; val != nil {
		conf.PartitionStrategy = val
	}

	linter, _ := NewLinter(name, conf)
	return linter
}

func parseLinterConfigSpec(name string, spec string) (LinterConfig, error) {
	parts := strings.SplitN(spec, ":", 2)
	if len(parts) < 2 {
		return LinterConfig{}, fmt.Errorf("linter spec needs at least two components")
	}

	config := defaultLinters[name]
	config.Command, config.Pattern = parts[0], parts[1]
	if predefined, ok := predefinedPatterns[config.Pattern]; ok {
		config.Pattern = predefined
	}

	return config, nil
}

func makeInstallCommand(linters ...string) []string {
	cmd := []string{"get"}
	if config.VendoredLinters {
		cmd = []string{"install"}
	} else {
		if config.Update {
			cmd = append(cmd, "-u")
		}
		if config.Force {
			cmd = append(cmd, "-f")
		}
		if config.DownloadOnly {
			cmd = append(cmd, "-d")
		}
	}
	if config.Debug {
		cmd = append(cmd, "-v")
	}
	cmd = append(cmd, linters...)
	return cmd
}

func installLintersWithOneCommand(targets []string) error {
	cmd := makeInstallCommand(targets...)
	debug("go %s", strings.Join(cmd, " "))
	c := exec.Command("go", cmd...) // nolint: gosec
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

func installLintersIndividually(targets []string) {
	failed := []string{}
	for _, target := range targets {
		cmd := makeInstallCommand(target)
		debug("go %s", strings.Join(cmd, " "))
		c := exec.Command("go", cmd...) // nolint: gosec
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			warning("failed to install %s: %s", target, err)
			failed = append(failed, target)
		}
	}
	if len(failed) > 0 {
		kingpin.Fatalf("failed to install the following linters: %s", strings.Join(failed, ", "))
	}
}

func installLinters() {
	names := make([]string, 0, len(defaultLinters))
	targets := make([]string, 0, len(defaultLinters))
	for name, config := range defaultLinters {
		if config.InstallFrom == "" {
			continue
		}
		names = append(names, name)
		targets = append(targets, config.InstallFrom)
	}
	sort.Strings(names)
	namesStr := strings.Join(names, "\n  ")
	if config.DownloadOnly {
		fmt.Printf("Downloading:\n  %s\n", namesStr)
	} else {
		fmt.Printf("Installing:\n  %s\n", namesStr)
	}
	err := installLintersWithOneCommand(targets)
	if err == nil {
		return
	}
	warning("failed to install one or more linters: %s (installing individually)", err)
	installLintersIndividually(targets)
}

func getDefaultLinters() []*Linter {
	out := []*Linter{}
	for name, config := range defaultLinters {
		linter, err := NewLinter(name, config)
		kingpin.FatalIfError(err, "invalid linter %q", name)
		out = append(out, linter)
	}
	return out
}

func defaultEnabled() []string {
	enabled := []string{}
	for name, config := range defaultLinters {
		if config.defaultEnabled {
			enabled = append(enabled, name)
		}
	}
	return enabled
}

func validateLinters(linters map[string]*Linter, config *Config) error {
	var unknownLinters []string
	for name := range linters {
		if _, isDefault := defaultLinters[name]; !isDefault {
			if _, isCustom := config.Linters[name]; !isCustom {
				unknownLinters = append(unknownLinters, name)
			}
		}
	}
	if len(unknownLinters) > 0 {
		return fmt.Errorf("unknown linters: %s", strings.Join(unknownLinters, ", "))
	}
	return nil
}

const vetPattern = `^(?:vet:.*?\.go:\s+(?P<path>.*?\.go):(?P<line>\d+):(?P<col>\d+):\s*(?P<message>.*))|((?P<path>.*?\.go):(?P<line>\d+):(?P<col>\d+):\s*(?P<message>.*))|(?:(?P<path>.*?\.go):(?P<line>\d+):\s*(?P<message>.*))$`

var defaultLinters = map[string]LinterConfig{
	"maligned": {
		Command:           "maligned",
		Pattern:           `^(?:[^:]+: )?(?P<path>.*?\.go):(?P<line>\d+):(?P<col>\d+):\s*(?P<message>.+)$`,
		InstallFrom:       "github.com/mdempsky/maligned",
		PartitionStrategy: partitionPathsAsPackages,
		defaultEnabled:    true,
	},
	"deadcode": {
		Command:           "deadcode",
		Pattern:           `^deadcode: (?P<path>.*?\.go):(?P<line>\d+):(?P<col>\d+):\s*(?P<message>.*)$`,
		InstallFrom:       "github.com/tsenart/deadcode",
		PartitionStrategy: partitionPathsAsDirectories,
		defaultEnabled:    true,
	},
	"dupl": {
		Command:           `dupl -plumbing -threshold {duplthreshold}`,
		Pattern:           `^(?P<path>.*?\.go):(?P<line>\d+)-\d+:\s*(?P<message>.*)$`,
		InstallFrom:       "github.com/mibk/dupl",
		PartitionStrategy: partitionPathsAsFiles,
		IsFast:            true,
	},
	"errcheck": {
		Command:           `errcheck -abspath {not_tests=-ignoretests}`,
		Pattern:           `PATH:LINE:COL:MESSAGE`,
		InstallFrom:       "github.com/kisielk/errcheck",
		PartitionStrategy: partitionPathsAsPackages,
		defaultEnabled:    true,
	},
	"gosec": {
		Command:           `gosec -fmt=csv`,
		Pattern:           `^(?P<path>.*?\.go),(?P<line>\d+)(-\d+)?,(?P<message>[^,]+,[^,]+,[^,]+)`,
		InstallFrom:       "github.com/securego/gosec/cmd/gosec",
		PartitionStrategy: partitionPathsAsPackages,
		defaultEnabled:    true,
		IsFast:            true,
	},
	"gochecknoinits": {
		Command:           `gochecknoinits`,
		Pattern:           `^(?P<path>.*?\.go):(?P<line>\d+) (?P<message>.*)`,
		InstallFrom:       "4d63.com/gochecknoinits",
		PartitionStrategy: partitionPathsAsDirectories,
		defaultEnabled:    false,
		IsFast:            true,
	},
	"gochecknoglobals": {
		Command:           `gochecknoglobals`,
		Pattern:           `^(?P<path>.*?\.go):(?P<line>\d+) (?P<message>.*)`,
		InstallFrom:       "4d63.com/gochecknoglobals",
		PartitionStrategy: partitionPathsAsDirectories,
		defaultEnabled:    false,
		IsFast:            true,
	},
	"goconst": {
		Command:           `goconst -min-occurrences {min_occurrences} -min-length {min_const_length}`,
		Pattern:           `PATH:LINE:COL:MESSAGE`,
		InstallFrom:       "github.com/jgautheron/goconst/cmd/goconst",
		PartitionStrategy: partitionPathsAsDirectories,
		defaultEnabled:    true,
		IsFast:            true,
	},
	"gocyclo": {
		Command:           `gocyclo -over {mincyclo}`,
		Pattern:           `^(?P<cyclo>\d+)\s+\S+\s(?P<function>\S+)\s+(?P<path>.*?\.go):(?P<line>\d+):(\d+)$`,
		InstallFrom:       "github.com/alecthomas/gocyclo",
		PartitionStrategy: partitionPathsAsDirectories,
		defaultEnabled:    true,
		IsFast:            true,
	},
	"gofmt": {
		Command:           `gofmt -l -s`,
		Pattern:           `^(?P<path>.*?\.go)$`,
		PartitionStrategy: partitionPathsAsFiles,
		IsFast:            true,
	},
	"goimports": {
		Command:           `goimports -l`,
		Pattern:           `^(?P<path>.*?\.go)$`,
		InstallFrom:       "golang.org/x/tools/cmd/goimports",
		PartitionStrategy: partitionPathsAsFiles,
		IsFast:            true,
	},
	"golint": {
		Command:           `golint -min_confidence {min_confidence}`,
		Pattern:           `PATH:LINE:COL:MESSAGE`,
		InstallFrom:       "github.com/golang/lint/golint",
		PartitionStrategy: partitionPathsAsDirectories,
		defaultEnabled:    true,
		IsFast:            true,
	},
	"gotype": {
		Command:           `gotype -e {tests=-t}`,
		Pattern:           `PATH:LINE:COL:MESSAGE`,
		InstallFrom:       "golang.org/x/tools/cmd/gotype",
		PartitionStrategy: partitionPathsByDirectory,
		defaultEnabled:    true,
		IsFast:            true,
	},
	"gotypex": {
		Command:           `gotype -e -x`,
		Pattern:           `PATH:LINE:COL:MESSAGE`,
		InstallFrom:       "golang.org/x/tools/cmd/gotype",
		PartitionStrategy: partitionPathsByDirectory,
		defaultEnabled:    true,
		IsFast:            true,
	},
	"ineffassign": {
		Command:           `ineffassign -n`,
		Pattern:           `PATH:LINE:COL:MESSAGE`,
		InstallFrom:       "github.com/gordonklaus/ineffassign",
		PartitionStrategy: partitionPathsAsDirectories,
		defaultEnabled:    true,
		IsFast:            true,
	},
	"interfacer": {
		Command:           `interfacer`,
		Pattern:           `PATH:LINE:COL:MESSAGE`,
		InstallFrom:       "mvdan.cc/interfacer",
		PartitionStrategy: partitionPathsAsPackages,
		defaultEnabled:    true,
	},
	"lll": {
		Command:           `lll -g -l {maxlinelength}`,
		Pattern:           `PATH:LINE:MESSAGE`,
		InstallFrom:       "github.com/walle/lll/cmd/lll",
		PartitionStrategy: partitionPathsAsFiles,
		IsFast:            true,
	},
	"misspell": {
		Command:           `misspell -j 1 --locale "{misspelllocale}"`,
		Pattern:           `PATH:LINE:COL:MESSAGE`,
		InstallFrom:       "github.com/client9/misspell/cmd/misspell",
		PartitionStrategy: partitionPathsAsFiles,
		IsFast:            true,
	},
	"nakedret": {
		Command:           `nakedret`,
		Pattern:           `^(?P<path>.*?\.go):(?P<line>\d+)\s*(?P<message>.*)$`,
		InstallFrom:       "github.com/alexkohler/nakedret",
		PartitionStrategy: partitionPathsAsDirectories,
	},
	"safesql": {
		Command:           `safesql`,
		Pattern:           `^- (?P<path>.*?\.go):(?P<line>\d+):(?P<col>\d+)$`,
		InstallFrom:       "github.com/stripe/safesql",
		PartitionStrategy: partitionPathsAsPackages,
	},
	"staticcheck": {
		Command:           `staticcheck`,
		Pattern:           `PATH:LINE:COL:MESSAGE`,
		InstallFrom:       "honnef.co/go/tools/cmd/staticcheck",
		PartitionStrategy: partitionPathsAsPackages,
		defaultEnabled: true,
	},
	"structcheck": {
		Command:           `structcheck {tests=-t}`,
		Pattern:           `^(?:[^:]+: )?(?P<path>.*?\.go):(?P<line>\d+):(?P<col>\d+):\s*(?P<message>.+)$`,
		InstallFrom:       "github.com/opennota/check/cmd/structcheck",
		PartitionStrategy: partitionPathsAsPackages,
		defaultEnabled:    true,
	},
	"test": {
		Command:           `go test`,
		Pattern:           `(?m:^\t(?P<path>.*?\.go):(?P<line>\d+): (?P<message>.+)$)`,
		PartitionStrategy: partitionPathsAsPackages,
	},
	"testify": {
		Command:           `go test`,
		Pattern:           `(?m:^\s+Error Trace:\s+(?P<path>.+?.go):(?P<line>\d+)\n\s+Error:\s+(?P<message>.+?)[:\s]*$)`,
		PartitionStrategy: partitionPathsAsPackages,
	},
	"unconvert": {
		Command:           `unconvert`,
		Pattern:           `PATH:LINE:COL:MESSAGE`,
		InstallFrom:       "github.com/mdempsky/unconvert",
		PartitionStrategy: partitionPathsAsPackages,
		defaultEnabled:    true,
	},
	"unparam": {
		Command:           `unparam {not_tests=-tests=false}`,
		Pattern:           `PATH:LINE:COL:MESSAGE`,
		InstallFrom:       "mvdan.cc/unparam",
		PartitionStrategy: partitionPathsAsPackages,
	},
	"varcheck": {
		Command:           `varcheck`,
		Pattern:           `^(?:[^:]+: )?(?P<path>.*?\.go):(?P<line>\d+):(?P<col>\d+):\s*(?P<message>.*)$`,
		InstallFrom:       "github.com/opennota/check/cmd/varcheck",
		PartitionStrategy: partitionPathsAsPackages,
		defaultEnabled:    true,
	},
	"vet": {
		Command:           `go vet`,
		Pattern:           vetPattern,
		PartitionStrategy: partitionPathsAsPackages,
		defaultEnabled:    true,
		IsFast:            true,
	},
	"vetshadow": {
		Command:           `go vet --shadow`,
		Pattern:           vetPattern,
		PartitionStrategy: partitionPathsAsPackages,
		defaultEnabled:    true,
		IsFast:            true,
	},
}

"""



```