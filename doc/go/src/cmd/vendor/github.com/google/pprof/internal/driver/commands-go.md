Response:
我的思考过程如下：

1. **理解目标：** 目标是分析 `commands.go` 文件，理解其功能，并用 Go 代码示例、命令行参数解释、易错点等进行说明。

2. **识别核心数据结构：**  快速浏览代码，我注意到了关键的数据结构 `commands` (一个 `map[string]*command`) 和 `command` 结构体。这表明代码的核心是定义和管理不同的命令。

3. **分析 `command` 结构体：**  仔细阅读 `command` 结构体的每个字段：
    * `format`:  报告的格式 (int)。
    * `postProcess`:  报告生成后的处理函数 (`PostProcessor` 类型)。
    * `visualizer`:  用于显示报告的函数 (`PostProcessor` 类型)。
    * `hasParam`:  命令是否接受正则表达式参数 (bool)。
    * `description`:  命令的简短描述 (string)。
    * `usage`:  命令的详细用法说明 (string)。

4. **分析 `pprofCommands` 变量：**  这是一个 `commands` 类型的变量，并被初始化了很多键值对。每个键是一个命令名（如 "comments", "dot", "web"），每个值是一个 `command` 结构体实例。 这部分是理解 `commands.go` 核心功能的最重要部分，因为它列出了 `pprof` 支持的所有命令及其属性。

5. **识别关键函数：**
    * `help()`:  生成命令的帮助信息。
    * `AddCommand()`:  允许动态添加新的命令。
    * `SetVariableDefault()`:  设置 `pprof` 变量的默认值（虽然在这个文件中没有直接使用，但它提供了一种扩展配置的方式）。
    * `PostProcessor` 类型：这是一个函数类型，代表报告的后处理逻辑。
    * `usage()`: 生成 `pprof` 的总体用法信息，包括命令和选项。
    * `reportHelp()` 和 `listHelp()`:  生成特定类型命令的帮助信息。
    * `browsers()`:  获取可用的浏览器列表。
    * `awayFromTTY()`:  如果输出是终端，则将输出重定向到文件。
    * `invokeDot()`:  调用 `dot` 命令生成图形。
    * `massageDotSVG()`:  调用 `dot` 生成 SVG 并进行后处理。
    * `invokeVisualizer()`:  调用外部程序来可视化报告。
    * `stringToBool()`:  自定义的字符串转布尔值函数。

6. **归纳功能：** 基于以上的分析，我可以总结出 `commands.go` 的主要功能：
    * 定义和管理 `pprof` 工具支持的所有命令。
    * 为每个命令指定报告格式、后处理方式、是否接受参数、描述和用法。
    * 提供注册和扩展命令的能力。
    * 提供生成各种报告格式 (文本、DOT、SVG、PNG 等) 的能力。
    * 提供调用外部工具 (如 `dot` 和浏览器) 来可视化报告的能力。
    * 提供一些辅助函数来处理输出、查找浏览器等。

7. **编写 Go 代码示例：**  选择一个具有代表性的命令 (例如 "web")，并演示如何在 `pprofCommands` 中找到它，并访问其属性。  也考虑演示如何使用 `AddCommand` 添加自定义命令。

8. **解释命令行参数处理：**  关注 `command` 结构体中的 `hasParam` 字段，以及像 `reportHelp` 和 `listHelp` 这样的函数，它们展示了如何构建带有可选参数（如正则表达式）的命令的帮助信息。

9. **识别易错点：**  重点考虑用户在使用 `pprof` 命令时容易犯的错误：
    * 误解命令的用途。
    * 忘记或错误使用正则表达式参数。
    * 不知道如何使用选项。
    * 对于需要外部工具的命令 (如 "web" 或图形格式)，没有安装相应的软件。

10. **组织答案：**  将以上分析和示例组织成清晰的中文回答，包括功能列表、Go 代码示例（带输入输出）、命令行参数解释和易错点说明。  确保使用代码块和清晰的格式来提高可读性。  在描述命令行参数时，要详细说明参数的含义和用法。

11. **审阅和完善：**  最后，仔细检查答案的准确性、完整性和清晰度。确保所有要点都已涵盖，并且语言流畅易懂。  例如，最初我可能只关注了 `pprofCommands` 的静态定义，但后来意识到 `AddCommand` 提供了动态扩展的能力，这需要补充说明。  同时，对于命令行参数的解释，要考虑到参数的可选性以及不同命令参数的差异。

通过以上步骤，我能够系统地分析 `commands.go` 文件的功能，并提供详细且有用的中文解释。

这段Go语言代码是 `pprof` 工具中用于管理和定义可用命令的部分。它定义了 `pprof` 支持的各种报告生成和分析命令，以及如何处理这些命令。

**功能列举:**

1. **定义 `pprof` 命令:**  核心功能是定义 `pprof` 工具可以执行的各种命令，例如 `top`、`tree`、`web`、`disasm` 等。
2. **关联命令属性:**  为每个命令关联了一系列属性，包括：
    * **`format` (报告格式):**  指定命令生成的报告的格式，例如文本、DOT、protobuf 等。这通过 `report` 包中的常量来定义。
    * **`postProcess` (后处理函数):**  定义命令生成报告后需要执行的后处理函数。例如，将 DOT 格式转换为图片格式 (PNG, PDF)。
    * **`visualizer` (可视化工具):**  定义用于可视化报告的工具或函数。例如，使用浏览器显示 SVG 图形。
    * **`hasParam` (是否有参数):**  指示命令是否接受一个正则表达式参数，通常用于过滤函数名。
    * **`description` (描述):**  提供命令的简短描述，用于帮助信息。
    * **`usage` (用法):**  提供命令的详细用法说明，包括语法和示例。
3. **提供命令帮助信息:**  定义了 `help()` 方法，用于生成特定命令的帮助信息。
4. **允许扩展命令:**  提供了 `AddCommand()` 函数，允许其他部分的代码（例如插件）向 `pprof` 添加新的命令。这使得 `pprof` 可以通过扩展来支持新的可视化格式或分析功能。
5. **设置变量默认值:**  提供了 `SetVariableDefault()` 函数，允许设置 `pprof` 配置变量的默认值。
6. **管理交互模式:**  通过 `interactiveMode` 变量跟踪 `pprof` 是否在交互模式下运行。
7. **定义后处理函数类型:**  定义了 `PostProcessor` 函数类型，用于处理报告的后处理逻辑。
8. **定义内置命令集合:** 初始化了 `pprofCommands` 变量，这是一个 `commands` 类型的 map，包含了 `pprof` 默认支持的所有命令及其属性。

**Go语言功能实现示例:**

这段代码主要使用了以下 Go 语言特性：

* **结构体 (struct):**  `command` 结构体用于组织和表示命令的各种属性。
* **Map:** `commands` 类型是一个 map，用于存储命令名到 `command` 结构体的映射。
* **函数类型:** `PostProcessor` 是一个函数类型，用于定义报告后处理函数的签名。
* **函数作为值:**  `postProcess` 和 `visualizer` 字段存储的是函数，这允许将不同的处理逻辑与不同的命令关联起来。
* **字符串操作:**  使用了 `strings` 包进行字符串的分割、连接等操作，用于处理帮助信息和命令行参数。
* **调用外部命令:**  使用了 `os/exec` 包来执行外部命令，例如 `dot` 和浏览器。

**代码推理示例:**

假设用户在 `pprof` 交互式终端中输入 `web` 命令。

**输入 (假设):** 用户输入 "web"

**推理过程:**

1. `pprof` 会查找 `pprofCommands` map 中是否存在键为 "web" 的条目。
2. 找到了对应的 `command` 结构体，其 `format` 为 `report.Dot`，`postProcess` 为 `massageDotSVG()`，`visualizer` 为 `invokeVisualizer("svg", browsers())`。
3. `pprof` 会先使用 `report.Dot` 格式生成报告。
4. 然后，将生成的 DOT 格式的报告传递给 `massageDotSVG()` 函数进行后处理。这个函数会调用 `dot -Tsvg` 将 DOT 转换为 SVG 格式，并对 SVG 进行一些调整以支持浏览器中的平移。
5. 最后，将处理后的 SVG 数据传递给 `invokeVisualizer("svg", browsers())` 函数。这个函数会创建一个临时 SVG 文件，并尝试使用系统上可用的浏览器打开这个文件。

**输出 (推测):**  用户的默认浏览器会被启动，并显示生成的性能分析图。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数的解析。命令行参数的解析通常在 `pprof` 的主入口文件中进行。但是，这段代码通过以下方式与命令行参数处理相关：

* **`hasParam` 字段:**  指示命令是否需要一个正则表达式参数。当命令行解析器遇到这样的命令时，它会尝试提取后续的参数作为正则表达式。例如，对于 `list <func_regex>` 命令，`hasParam` 为 `true`。
* **`usage` 字符串:**  提供了命令的使用说明，这会显示给用户，帮助他们理解命令所需的参数。
* **`reportHelp` 和 `listHelp` 函数:**  这些函数用于生成带有参数说明的帮助信息，例如 `top [n] [focus_regex]* [-ignore_regex]*`。

例如，对于 `top` 命令，`reportHelp` 函数会生成类似以下的用法说明：

```
top [n] [focus_regex]* [-ignore_regex]*
Include up to n samples
Include samples matching focus_regex, and exclude ignore_regex.
```

这告诉用户 `top` 命令可以接受一个可选的数字 `n` (限制显示的样本数量)，以及零个或多个 `focus_regex` (用于包含匹配的样本) 和 `ignore_regex` (用于排除匹配的样本)。

**使用者易犯错的点:**

1. **混淆命令名称或参数:** 用户可能会记错命令的名称或忘记命令是否需要参数。例如，误以为 `list` 命令不需要正则表达式参数。
2. **不理解正则表达式的用法:**  许多命令使用正则表达式进行过滤，用户可能不熟悉正则表达式的语法，导致过滤结果不符合预期。例如，想要匹配包含 "main" 的函数，可能会错误地使用 "main"，而正确的可能是 ".*main.*"。
3. **忘记某些命令会生成文件:**  像 `dot`, `pdf`, `png` 等命令默认会将输出保存到文件中，用户可能没有注意到这一点，导致找不到生成的报告。 `awayFromTTY` 函数在这里起到一定的帮助作用，如果输出是终端，则会将二进制格式的输出保存到临时文件中。
4. **没有安装必要的外部工具:**  像 `web`, `gif`, `pdf` 等命令依赖于外部工具（如 `dot`，浏览器）的支持。如果用户没有安装这些工具，命令会执行失败。例如，运行 `web` 命令但没有安装 Graphviz，就会报错。
5. **不了解选项的用法:**  这段代码也涉及到了配置选项，用户可能不清楚如何设置和使用这些选项来定制报告的生成方式。虽然 `commands.go` 本身不直接处理选项，但它定义了选项的帮助信息。

**易错点示例:**

* **错误使用 `list` 命令:**  用户尝试运行 `list` 命令，但是忘记提供函数名或地址的正则表达式，例如直接输入 `list`，导致 `pprof` 无法知道要显示哪个函数的源代码。
* **使用 `web` 命令但未安装 Graphviz:** 用户运行 `web` 命令，期望在浏览器中看到图形，但由于没有安装 Graphviz，`invokeDot` 函数会报错。
* **误解 `focus` 和 `ignore` 的作用:** 用户可能不清楚 `focus` 和 `ignore` 选项的作用域，导致过滤结果不符合预期。例如，以为 `ignore` 会排除包含某个函数的所有调用栈，但实际上它只会排除包含该函数的 *路径*。

总而言之，这段代码是 `pprof` 工具的核心组成部分，负责定义和管理命令，并为每个命令关联了生成和可视化报告所需的各种属性和处理逻辑。理解这段代码有助于深入了解 `pprof` 的工作原理和如何扩展其功能。

Prompt: 
```
这是路径为go/src/cmd/vendor/github.com/google/pprof/internal/driver/commands.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2014 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package driver

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/google/pprof/internal/plugin"
	"github.com/google/pprof/internal/report"
)

// commands describes the commands accepted by pprof.
type commands map[string]*command

// command describes the actions for a pprof command. Includes a
// function for command-line completion, the report format to use
// during report generation, any postprocessing functions, and whether
// the command expects a regexp parameter (typically a function name).
type command struct {
	format      int           // report format to generate
	postProcess PostProcessor // postprocessing to run on report
	visualizer  PostProcessor // display output using some callback
	hasParam    bool          // collect a parameter from the CLI
	description string        // single-line description text saying what the command does
	usage       string        // multi-line help text saying how the command is used
}

// help returns a help string for a command.
func (c *command) help(name string) string {
	message := c.description + "\n"
	if c.usage != "" {
		message += "  Usage:\n"
		lines := strings.Split(c.usage, "\n")
		for _, line := range lines {
			message += fmt.Sprintf("    %s\n", line)
		}
	}
	return message + "\n"
}

// AddCommand adds an additional command to the set of commands
// accepted by pprof. This enables extensions to add new commands for
// specialized visualization formats. If the command specified already
// exists, it is overwritten.
func AddCommand(cmd string, format int, post PostProcessor, desc, usage string) {
	pprofCommands[cmd] = &command{format, post, nil, false, desc, usage}
}

// SetVariableDefault sets the default value for a pprof
// variable. This enables extensions to set their own defaults.
func SetVariableDefault(variable, value string) {
	configure(variable, value)
}

// PostProcessor is a function that applies post-processing to the report output
type PostProcessor func(input io.Reader, output io.Writer, ui plugin.UI) error

// interactiveMode is true if pprof is running on interactive mode, reading
// commands from its shell.
var interactiveMode = false

// pprofCommands are the report generation commands recognized by pprof.
var pprofCommands = commands{
	// Commands that require no post-processing.
	"comments": {report.Comments, nil, nil, false, "Output all profile comments", ""},
	"disasm":   {report.Dis, nil, nil, true, "Output assembly listings annotated with samples", listHelp("disasm", true)},
	"dot":      {report.Dot, nil, nil, false, "Outputs a graph in DOT format", reportHelp("dot", false, true)},
	"list":     {report.List, nil, nil, true, "Output annotated source for functions matching regexp", listHelp("list", false)},
	"peek":     {report.Tree, nil, nil, true, "Output callers/callees of functions matching regexp", "peek func_regex\nDisplay callers and callees of functions matching func_regex."},
	"raw":      {report.Raw, nil, nil, false, "Outputs a text representation of the raw profile", ""},
	"tags":     {report.Tags, nil, nil, false, "Outputs all tags in the profile", "tags [tag_regex]* [-ignore_regex]* [>file]\nList tags with key:value matching tag_regex and exclude ignore_regex."},
	"text":     {report.Text, nil, nil, false, "Outputs top entries in text form", reportHelp("text", true, true)},
	"top":      {report.Text, nil, nil, false, "Outputs top entries in text form", reportHelp("top", true, true)},
	"traces":   {report.Traces, nil, nil, false, "Outputs all profile samples in text form", ""},
	"tree":     {report.Tree, nil, nil, false, "Outputs a text rendering of call graph", reportHelp("tree", true, true)},

	// Save binary formats to a file
	"callgrind": {report.Callgrind, nil, awayFromTTY("callgraph.out"), false, "Outputs a graph in callgrind format", reportHelp("callgrind", false, true)},
	"proto":     {report.Proto, nil, awayFromTTY("pb.gz"), false, "Outputs the profile in compressed protobuf format", ""},
	"topproto":  {report.TopProto, nil, awayFromTTY("pb.gz"), false, "Outputs top entries in compressed protobuf format", ""},

	// Generate report in DOT format and postprocess with dot
	"gif": {report.Dot, invokeDot("gif"), awayFromTTY("gif"), false, "Outputs a graph image in GIF format", reportHelp("gif", false, true)},
	"pdf": {report.Dot, invokeDot("pdf"), awayFromTTY("pdf"), false, "Outputs a graph in PDF format", reportHelp("pdf", false, true)},
	"png": {report.Dot, invokeDot("png"), awayFromTTY("png"), false, "Outputs a graph image in PNG format", reportHelp("png", false, true)},
	"ps":  {report.Dot, invokeDot("ps"), awayFromTTY("ps"), false, "Outputs a graph in PS format", reportHelp("ps", false, true)},

	// Save SVG output into a file
	"svg": {report.Dot, massageDotSVG(), awayFromTTY("svg"), false, "Outputs a graph in SVG format", reportHelp("svg", false, true)},

	// Visualize postprocessed dot output
	"eog":    {report.Dot, invokeDot("svg"), invokeVisualizer("svg", []string{"eog"}), false, "Visualize graph through eog", reportHelp("eog", false, false)},
	"evince": {report.Dot, invokeDot("pdf"), invokeVisualizer("pdf", []string{"evince"}), false, "Visualize graph through evince", reportHelp("evince", false, false)},
	"gv":     {report.Dot, invokeDot("ps"), invokeVisualizer("ps", []string{"gv --noantialias"}), false, "Visualize graph through gv", reportHelp("gv", false, false)},
	"web":    {report.Dot, massageDotSVG(), invokeVisualizer("svg", browsers()), false, "Visualize graph through web browser", reportHelp("web", false, false)},

	// Visualize callgrind output
	"kcachegrind": {report.Callgrind, nil, invokeVisualizer("grind", kcachegrind), false, "Visualize report in KCachegrind", reportHelp("kcachegrind", false, false)},

	// Visualize HTML directly generated by report.
	"weblist": {report.WebList, nil, invokeVisualizer("html", browsers()), true, "Display annotated source in a web browser", listHelp("weblist", false)},
}

// configHelp contains help text per configuration parameter.
var configHelp = map[string]string{
	// Filename for file-based output formats, stdout by default.
	"output": helpText("Output filename for file-based outputs"),

	// Comparisons.
	"drop_negative": helpText(
		"Ignore negative differences",
		"Do not show any locations with values <0."),

	// Graph handling options.
	"call_tree": helpText(
		"Create a context-sensitive call tree",
		"Treat locations reached through different paths as separate."),

	// Display options.
	"relative_percentages": helpText(
		"Show percentages relative to focused subgraph",
		"If unset, percentages are relative to full graph before focusing",
		"to facilitate comparison with original graph."),
	"unit": helpText(
		"Measurement units to display",
		"Scale the sample values to this unit.",
		"For time-based profiles, use seconds, milliseconds, nanoseconds, etc.",
		"For memory profiles, use megabytes, kilobytes, bytes, etc.",
		"Using auto will scale each value independently to the most natural unit."),
	"compact_labels": "Show minimal headers",
	"source_path":    "Search path for source files",
	"trim_path":      "Path to trim from source paths before search",
	"intel_syntax": helpText(
		"Show assembly in Intel syntax",
		"Only applicable to commands `disasm` and `weblist`"),

	// Filtering options
	"nodecount": helpText(
		"Max number of nodes to show",
		"Uses heuristics to limit the number of locations to be displayed.",
		"On graphs, dotted edges represent paths through nodes that have been removed."),
	"nodefraction": "Hide nodes below <f>*total",
	"edgefraction": "Hide edges below <f>*total",
	"trim": helpText(
		"Honor nodefraction/edgefraction/nodecount defaults",
		"Set to false to get the full profile, without any trimming."),
	"focus": helpText(
		"Restricts to samples going through a node matching regexp",
		"Discard samples that do not include a node matching this regexp.",
		"Matching includes the function name, filename or object name."),
	"ignore": helpText(
		"Skips paths going through any nodes matching regexp",
		"If set, discard samples that include a node matching this regexp.",
		"Matching includes the function name, filename or object name."),
	"prune_from": helpText(
		"Drops any functions below the matched frame.",
		"If set, any frames matching the specified regexp and any frames",
		"below it will be dropped from each sample."),
	"hide": helpText(
		"Skips nodes matching regexp",
		"Discard nodes that match this location.",
		"Other nodes from samples that include this location will be shown.",
		"Matching includes the function name, filename or object name."),
	"show": helpText(
		"Only show nodes matching regexp",
		"If set, only show nodes that match this location.",
		"Matching includes the function name, filename or object name."),
	"show_from": helpText(
		"Drops functions above the highest matched frame.",
		"If set, all frames above the highest match are dropped from every sample.",
		"Matching includes the function name, filename or object name."),
	"tagroot": helpText(
		"Adds pseudo stack frames for labels key/value pairs at the callstack root.",
		"A comma-separated list of label keys.",
		"The first key creates frames at the new root."),
	"tagleaf": helpText(
		"Adds pseudo stack frames for labels key/value pairs at the callstack leaf.",
		"A comma-separated list of label keys.",
		"The last key creates frames at the new leaf."),
	"tagfocus": helpText(
		"Restricts to samples with tags in range or matched by regexp",
		"Use name=value syntax to limit the matching to a specific tag.",
		"Numeric tag filter examples: 1kb, 1kb:10kb, memory=32mb:",
		"String tag filter examples: foo, foo.*bar, mytag=foo.*bar"),
	"tagignore": helpText(
		"Discard samples with tags in range or matched by regexp",
		"Use name=value syntax to limit the matching to a specific tag.",
		"Numeric tag filter examples: 1kb, 1kb:10kb, memory=32mb:",
		"String tag filter examples: foo, foo.*bar, mytag=foo.*bar"),
	"tagshow": helpText(
		"Only consider tags matching this regexp",
		"Discard tags that do not match this regexp"),
	"taghide": helpText(
		"Skip tags matching this regexp",
		"Discard tags that match this regexp"),
	// Heap profile options
	"divide_by": helpText(
		"Ratio to divide all samples before visualization",
		"Divide all samples values by a constant, eg the number of processors or jobs."),
	"mean": helpText(
		"Average sample value over first value (count)",
		"For memory profiles, report average memory per allocation.",
		"For time-based profiles, report average time per event."),
	"sample_index": helpText(
		"Sample value to report (0-based index or name)",
		"Profiles contain multiple values per sample.",
		"Use sample_index=i to select the ith value (starting at 0)."),
	"normalize": helpText(
		"Scales profile based on the base profile."),

	// Data sorting criteria
	"flat": helpText("Sort entries based on own weight"),
	"cum":  helpText("Sort entries based on cumulative weight"),

	// Output granularity
	"functions": helpText(
		"Aggregate at the function level.",
		"Ignores the filename where the function was defined."),
	"filefunctions": helpText(
		"Aggregate at the function level.",
		"Takes into account the filename where the function was defined."),
	"files": "Aggregate at the file level.",
	"lines": "Aggregate at the source code line level.",
	"addresses": helpText(
		"Aggregate at the address level.",
		"Includes functions' addresses in the output."),
	"noinlines": helpText(
		"Ignore inlines.",
		"Attributes inlined functions to their first out-of-line caller."),
	"showcolumns": helpText(
		"Show column numbers at the source code line level."),
}

func helpText(s ...string) string {
	return strings.Join(s, "\n") + "\n"
}

// usage returns a string describing the pprof commands and configuration
// options.  if commandLine is set, the output reflect cli usage.
func usage(commandLine bool) string {
	var prefix string
	if commandLine {
		prefix = "-"
	}
	fmtHelp := func(c, d string) string {
		return fmt.Sprintf("    %-16s %s", c, strings.SplitN(d, "\n", 2)[0])
	}

	var commands []string
	for name, cmd := range pprofCommands {
		commands = append(commands, fmtHelp(prefix+name, cmd.description))
	}
	sort.Strings(commands)

	var help string
	if commandLine {
		help = "  Output formats (select at most one):\n"
	} else {
		help = "  Commands:\n"
		commands = append(commands, fmtHelp("o/options", "List options and their current values"))
		commands = append(commands, fmtHelp("q/quit/exit/^D", "Exit pprof"))
	}

	help = help + strings.Join(commands, "\n") + "\n\n" +
		"  Options:\n"

	// Print help for configuration options after sorting them.
	// Collect choices for multi-choice options print them together.
	var variables []string
	var radioStrings []string
	for _, f := range configFields {
		if len(f.choices) == 0 {
			variables = append(variables, fmtHelp(prefix+f.name, configHelp[f.name]))
			continue
		}
		// Format help for for this group.
		s := []string{fmtHelp(f.name, "")}
		for _, choice := range f.choices {
			s = append(s, "  "+fmtHelp(prefix+choice, configHelp[choice]))
		}
		radioStrings = append(radioStrings, strings.Join(s, "\n"))
	}
	sort.Strings(variables)
	sort.Strings(radioStrings)
	return help + strings.Join(variables, "\n") + "\n\n" +
		"  Option groups (only set one per group):\n" +
		strings.Join(radioStrings, "\n")
}

func reportHelp(c string, cum, redirect bool) string {
	h := []string{
		c + " [n] [focus_regex]* [-ignore_regex]*",
		"Include up to n samples",
		"Include samples matching focus_regex, and exclude ignore_regex.",
	}
	if cum {
		h[0] += " [-cum]"
		h = append(h, "-cum sorts the output by cumulative weight")
	}
	if redirect {
		h[0] += " >f"
		h = append(h, "Optionally save the report on the file f")
	}
	return strings.Join(h, "\n")
}

func listHelp(c string, redirect bool) string {
	h := []string{
		c + "<func_regex|address> [-focus_regex]* [-ignore_regex]*",
		"Include functions matching func_regex, or including the address specified.",
		"Include samples matching focus_regex, and exclude ignore_regex.",
	}
	if redirect {
		h[0] += " >f"
		h = append(h, "Optionally save the report on the file f")
	}
	return strings.Join(h, "\n")
}

// browsers returns a list of commands to attempt for web visualization.
func browsers() []string {
	var cmds []string
	if userBrowser := os.Getenv("BROWSER"); userBrowser != "" {
		cmds = append(cmds, userBrowser)
	}
	switch runtime.GOOS {
	case "darwin":
		cmds = append(cmds, "/usr/bin/open")
	case "windows":
		cmds = append(cmds, "cmd /c start")
	default:
		// Commands opening browsers are prioritized over xdg-open, so browser()
		// command can be used on linux to open the .svg file generated by the -web
		// command (the .svg file includes embedded javascript so is best viewed in
		// a browser).
		cmds = append(cmds, []string{"chrome", "google-chrome", "chromium", "firefox", "sensible-browser"}...)
		if os.Getenv("DISPLAY") != "" {
			// xdg-open is only for use in a desktop environment.
			cmds = append(cmds, "xdg-open")
		}
	}
	return cmds
}

var kcachegrind = []string{"kcachegrind"}

// awayFromTTY saves the output in a file if it would otherwise go to
// the terminal screen. This is used to avoid dumping binary data on
// the screen.
func awayFromTTY(format string) PostProcessor {
	return func(input io.Reader, output io.Writer, ui plugin.UI) error {
		if output == os.Stdout && (ui.IsTerminal() || interactiveMode) {
			tempFile, err := newTempFile("", "profile", "."+format)
			if err != nil {
				return err
			}
			ui.PrintErr("Generating report in ", tempFile.Name())
			output = tempFile
		}
		_, err := io.Copy(output, input)
		return err
	}
}

func invokeDot(format string) PostProcessor {
	return func(input io.Reader, output io.Writer, ui plugin.UI) error {
		cmd := exec.Command("dot", "-T"+format)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = input, output, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to execute dot. Is Graphviz installed? Error: %v", err)
		}
		return nil
	}
}

// massageDotSVG invokes the dot tool to generate an SVG image and alters
// the image to have panning capabilities when viewed in a browser.
func massageDotSVG() PostProcessor {
	generateSVG := invokeDot("svg")
	return func(input io.Reader, output io.Writer, ui plugin.UI) error {
		baseSVG := new(bytes.Buffer)
		if err := generateSVG(input, baseSVG, ui); err != nil {
			return err
		}
		_, err := output.Write([]byte(massageSVG(baseSVG.String())))
		return err
	}
}

func invokeVisualizer(suffix string, visualizers []string) PostProcessor {
	return func(input io.Reader, output io.Writer, ui plugin.UI) error {
		tempFile, err := newTempFile(os.TempDir(), "pprof", "."+suffix)
		if err != nil {
			return err
		}
		deferDeleteTempFile(tempFile.Name())
		if _, err := io.Copy(tempFile, input); err != nil {
			return err
		}
		tempFile.Close()
		// Try visualizers until one is successful
		for _, v := range visualizers {
			// Separate command and arguments for exec.Command.
			args := strings.Split(v, " ")
			if len(args) == 0 {
				continue
			}
			viewer := exec.Command(args[0], append(args[1:], tempFile.Name())...)
			viewer.Stderr = os.Stderr
			if err = viewer.Start(); err == nil {
				// Wait for a second so that the visualizer has a chance to
				// open the input file. This needs to be done even if we're
				// waiting for the visualizer as it can be just a wrapper that
				// spawns a browser tab and returns right away.
				defer func(t <-chan time.Time) {
					<-t
				}(time.After(time.Second))
				// On interactive mode, let the visualizer run in the background
				// so other commands can be issued.
				if !interactiveMode {
					return viewer.Wait()
				}
				return nil
			}
		}
		return err
	}
}

// stringToBool is a custom parser for bools. We avoid using strconv.ParseBool
// to remain compatible with old pprof behavior (e.g., treating "" as true).
func stringToBool(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "true", "t", "yes", "y", "1", "":
		return true, nil
	case "false", "f", "no", "n", "0":
		return false, nil
	default:
		return false, fmt.Errorf(`illegal value "%s" for bool variable`, s)
	}
}

"""



```