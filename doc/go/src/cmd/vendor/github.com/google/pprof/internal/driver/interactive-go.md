Response:
Let's break down the thought process for analyzing this Go code snippet and fulfilling the request.

**1. Understanding the Goal:**

The core request is to analyze the `interactive.go` file within the `pprof` tool and describe its functionality, provide examples, and highlight potential pitfalls for users. The key is to understand the *purpose* of this specific file within the larger `pprof` context.

**2. Initial Scan and Keywords:**

First, I'd quickly scan the code for keywords and structural elements:

* **`package driver`**: This immediately tells me it's part of the `driver` component of `pprof`. Drivers often handle the main execution logic or user interaction.
* **`interactive` function**: The name strongly suggests this function manages an interactive user session.
* **`plugin.Options`, `plugin.UI`**: These indicate interaction with a plugin system and a user interface abstraction, likely for handling input/output.
* **`profile.Profile`**:  The function takes a `profile.Profile` as input, confirming it's working with profiling data.
* **`ReadLine`, `Print`, `PrintErr`**:  These are UI interaction methods, solidifying the interactive shell idea.
* **`parseCommandLine`**:  This suggests processing user commands entered in the shell.
* **`generateReportWrapper`**: This hints at generating reports based on commands.
* **`shortcuts`, `profileShortcuts`**:  These likely provide aliases or shorthand for common commands.
* **`configure`, `printCurrentOptions`**: These relate to setting and viewing configuration options for the interactive session.
* **`commandHelp`, `newCompleter`**: These clearly deal with help functionality and command completion.

**3. Deeper Dive into Key Functions:**

Next, I would focus on the most important functions:

* **`interactive(p *profile.Profile, o *plugin.Options) error`**: This is the entry point. I'd analyze the loop:
    * Reading input (`o.UI.ReadLine`).
    * Handling errors (EOF, other errors).
    * Expanding shortcuts.
    * Checking for variable assignments (`name=value`).
    * Processing built-in commands (`o`, `exit`, `help`).
    * Calling `parseCommandLine` and `generateReportWrapper`.
* **`parseCommandLine(input []string) ([]string, config, error)`**:  I'd pay attention to how it splits the input, handles digits in commands (like `top10`), parses options (using `-` prefix), and sets `Focus` and `Ignore`. The handling of the output redirection (`>`) is also important.
* **`greetings(p *profile.Profile, ui plugin.UI)`**:  This is for initial setup and displaying profile information.
* **`profileShortcuts(p *profile.Profile) shortcuts`**:  How it creates shortcuts based on sample types.
* **`printCurrentOptions(p *profile.Profile, ui plugin.UI)`**: How it displays the current configuration.
* **`commandHelp(args string, ui plugin.UI)`**: How help is provided for commands and options.
* **`newCompleter(fns []string) func(string) string`**: How command autocompletion is implemented.

**4. Identifying Core Functionality:**

From the function analysis, the core functionalities become clear:

* **Interactive Command Shell:**  The main loop reads and processes user commands.
* **Command Parsing:**  `parseCommandLine` interprets the commands and their arguments.
* **Report Generation:**  `generateReportWrapper` (and its underlying `generateReport`) is responsible for creating reports based on the commands.
* **Configuration Management:**  The code handles setting and displaying configuration options.
* **Shortcuts/Aliases:**  Provides a way to simplify common command sequences.
* **Help System:**  Offers guidance on available commands and options.
* **Autocompletion:** Enhances the user experience by suggesting completions.

**5. Constructing Examples and Explanations:**

Based on the understanding of the functionalities, I would then construct concrete examples:

* **Configuration:** Showing how to set options like `focus`, `ignore`, `sample_index`. Illustrating the syntax and the effect.
* **Commands:** Demonstrating common commands like `top`, `web`, and how they use the configuration.
* **Shortcuts:** Explaining how the shortcuts for sample types work.
* **Command Line Parsing:** Providing examples of how `parseCommandLine` interprets input.

**6. Identifying Potential User Errors:**

I'd think about common mistakes a user might make:

* **Incorrect option syntax:**  Forgetting the `=` in assignments.
* **Invalid option values:**  Providing incorrect values for options like `sample_index`.
* **Misunderstanding shortcuts:** Not realizing how shortcuts expand into multiple commands.
* **Forgetting required arguments:**  Using a command like `top` without specifying the number of entries.

**7. Structuring the Answer:**

Finally, I'd organize the information into a clear and structured answer, following the prompt's requirements:

* **List of functionalities.**
* **Go code examples:**  Focus on illustrating the configuration and command execution aspects.
* **Code reasoning with input/output:** Demonstrate how `parseCommandLine` works.
* **Command-line parameter handling:** Explain how different parts of the command line are processed.
* **Common user errors:** Provide specific examples.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe the `interactive` function directly generates reports.
* **Correction:** Realizing that `generateReportWrapper` is called, indicating a separation of concerns.
* **Initial thought:**  Focus heavily on low-level details of the `plugin` interface.
* **Correction:**  Recognizing that the focus should be on the user-facing aspects of the interactive shell.
* **Ensuring clarity in examples:** Making sure the input and expected output for `parseCommandLine` are clearly defined.

By following these steps, breaking down the code, and thinking about the user's perspective, I can effectively analyze the `interactive.go` file and generate a comprehensive and helpful response.
这段代码是 Go 语言 `pprof` 工具中交互式命令行界面的实现。它允许用户在 `pprof` 分析性能数据时，通过输入命令与工具进行交互，执行各种报告生成和数据分析操作。

**主要功能:**

1. **启动交互式 Shell:** `interactive` 函数是这个交互式界面的入口点。它会进入一个循环，不断读取用户的输入。
2. **命令解析和执行:**  用户输入的每一行都被视为一个命令。代码会解析这些命令，并根据命令调用相应的报告生成或其他操作。
3. **配置管理:**  用户可以在交互式界面中设置和修改各种配置选项，例如聚焦特定的函数、忽略某些函数、设置排序方式、输出格式等。这些选项会影响后续生成的报告。
4. **命令补全:**  代码提供了基本的命令和选项名称的自动补全功能，提升用户体验。
5. **快捷方式（Shortcuts）:**  定义了一些快捷方式，可以将一个简短的输入扩展成一系列命令，方便用户快速执行常用操作。例如，可以直接输入样本类型名称来查看该类型的统计信息。
6. **帮助信息:**  提供了 `help` 命令，用户可以查看可用命令和选项的说明。
7. **与 Profile 数据交互:**  这个界面直接操作 `profile.Profile` 对象，可以基于 Profile 数据生成各种类型的报告。

**它是什么 Go 语言功能的实现？**

从代码结构来看，它主要利用了以下 Go 语言功能：

* **循环和条件语句:**  `for` 循环用于持续读取用户输入， `switch` 语句用于根据不同的命令执行不同的操作。
* **字符串处理:** `strings` 包用于处理用户输入的字符串，例如分割命令和参数，去除空格等。
* **正则表达式:** `regexp` 包用于匹配和处理特定的模式，例如匹配命令中的数字部分。
* **错误处理:**  使用 `error` 类型来处理可能发生的错误，例如无效的命令或参数。
* **函数调用:**  通过调用其他函数（例如 `parseCommandLine`, `generateReportWrapper`, `configure`) 来完成具体的功能。
* **结构体和方法:**  定义了 `shortcuts` 结构体以及相关的方法，用于管理命令的快捷方式。
* **变量和常量:** 定义了一些全局变量和常量，例如 `commentStart`， `pprofShortcuts` 等。

**Go 代码举例说明:**

假设用户想要查看占用 CPU 时间最多的前 10 个函数。在交互式界面中，用户可以输入命令：

```
top 10
```

以下是 `parseCommandLine` 函数如何解析这个命令的示例：

```go
package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var tailDigitsRE = regexp.MustCompile("[0-9]+$")

func parseCommandLineExample(input string) ([]string, error) {
	tokens := strings.Fields(input)
	if len(tokens) == 0 {
		return nil, fmt.Errorf("empty input")
	}

	cmdName := tokens[0]
	args := tokens[1:]

	// 模拟 pprofCommands，实际代码中会根据命令名查找对应的处理函数
	pprofCommands := map[string]struct{ hasParam bool }{
		"top": {hasParam: true},
		// ... 其他命令
	}

	c, ok := pprofCommands[cmdName]
	if !ok {
		// 尝试分割数字
		if d := tailDigitsRE.FindString(cmdName); d != "" && d != cmdName {
			cmdName = cmdName[:len(cmdName)-len(d)]
			args = append([]string{d}, args...)
			c, ok = pprofCommands[cmdName]
		}
		if !ok {
			return nil, fmt.Errorf("unrecognized command: %q", tokens[0])
		}
	}

	if c.hasParam {
		if len(args) == 0 {
			return nil, fmt.Errorf("command %s requires an argument", cmdName)
		}
	}

	return tokens, nil
}

func main() {
	input := "top 10"
	cmd, err := parseCommandLineExample(input)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Parsed command:", cmd) // Output: Parsed command: [top 10]

	inputWithAbbreviation := "top10"
	cmd2, err := parseCommandLineExample(inputWithAbbreviation)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Parsed command with abbreviation:", cmd2) // Output: Parsed command with abbreviation: [top 10]
}
```

**假设的输入与输出:**

* **输入:** `focus=runtime.malloc`
* **`parseCommandLine` 输出的 `cfg` (config 结构体) 中的 `Focus` 字段值:** `runtime.malloc`
* **输入:** `top 20 -foo`
* **`parseCommandLine` 输出的 `cmd`:** `["top", "20"]`
* **`parseCommandLine` 输出的 `cfg` 中的 `Ignore` 字段值:** `foo`

**命令行参数的具体处理:**

`parseCommandLine` 函数负责解析用户输入的命令和参数。它的处理流程如下：

1. **分割输入:** 使用 `strings.Fields` 将输入字符串分割成一个个 token。
2. **识别命令:**  第一个 token 被认为是命令名。
3. **处理带数字的缩写命令:**  尝试识别类似 `top10` 这样的缩写命令，并将其拆分为命令和参数。
4. **检查参数:**  对于需要参数的命令（例如 `top`），检查是否提供了参数。
5. **处理配置选项:**  识别以等号 `=` 分隔的配置选项，例如 `focus=xxx`。
6. **处理数字参数:**  如果 token 可以解析为数字，则将其作为 `NodeCount` 配置项的值。
7. **处理输出重定向:**  识别以 `>` 开头的 token，将其作为输出文件名。
8. **处理 `-` 开头的忽略项:** 识别以 `-` 开头的 token，将其添加到 `Ignore` 配置项中。
9. **处理其他聚焦项:**  将其他非选项的 token 添加到 `Focus` 配置项中。
10. **特定命令的特殊处理:** 例如，对于 `tags` 命令，会将 `focus` 和 `ignore` 的值分别赋给 `TagFocus` 和 `TagIgnore`。
11. **设置默认 NodeCount:** 对于 `text` 或 `top` 命令，如果没有指定 `NodeCount`，则默认设置为 10。

**使用者易犯错的点:**

1. **错误的选项语法:**  用户可能会忘记使用等号来赋值配置选项，例如输入 `focus runtime.malloc` 而不是 `focus=runtime.malloc`。这会导致命令被解析为要聚焦的函数名，而不是设置配置。

   **示例:**

   * **错误输入:** `focus runtime.malloc`
   * **预期效果:** 设置 `focus` 配置项为 `runtime.malloc`。
   * **实际效果:**  `runtime.malloc` 被认为是 `top` 等命令的过滤条件。

2. **无效的 `sample_index` 值:** 当使用 `sample_index` 选项来选择不同的样本类型时，用户可能会输入不存在的类型名称。

   **示例:**

   * **假设 Profile 中只有 "cpu" 和 "memory" 两种样本类型。**
   * **错误输入:** `sample_index=heap`
   * **预期效果:**  切换到 "heap" 样本类型的分析。
   * **实际效果:**  会输出错误信息，提示 `heap` 不是有效的样本类型。

3. **混淆命令和配置选项:** 用户可能会将配置选项名当作命令来使用，导致解析错误。

   **示例:**

   * **错误输入:** `focus`
   * **预期效果:** 查看当前的 `focus` 配置项。
   * **实际效果:**  `focus` 被识别为未知命令，会输出错误信息。应该使用 `o` 或 `options` 命令来查看所有配置。

4. **不理解快捷方式的展开:** 用户可能不清楚某些快捷方式会展开成多个命令，导致意外的行为。

   **示例:**

   * **假设 Profile 中有 "alloc_space" 样本类型。**
   * **输入:** `alloc_space`
   * **实际效果:**  会被展开成 `sample_index=alloc_space`，从而切换到该样本类型。如果用户不了解这个快捷方式，可能会感到困惑。

总而言之，这段代码是 `pprof` 工具交互式界面的核心实现，它负责接收用户命令、解析命令参数、管理配置选项，并最终调用相应的函数来生成性能分析报告，为用户提供灵活的交互式分析体验。

Prompt: 
```
这是路径为go/src/cmd/vendor/github.com/google/pprof/internal/driver/interactive.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/google/pprof/internal/plugin"
	"github.com/google/pprof/internal/report"
	"github.com/google/pprof/profile"
)

var commentStart = "//:" // Sentinel for comments on options
var tailDigitsRE = regexp.MustCompile("[0-9]+$")

// interactive starts a shell to read pprof commands.
func interactive(p *profile.Profile, o *plugin.Options) error {
	// Enter command processing loop.
	o.UI.SetAutoComplete(newCompleter(functionNames(p)))
	configure("compact_labels", "true")
	configHelp["sample_index"] += fmt.Sprintf("Or use sample_index=name, with name in %v.\n", sampleTypes(p))

	// Do not wait for the visualizer to complete, to allow multiple
	// graphs to be visualized simultaneously.
	interactiveMode = true
	shortcuts := profileShortcuts(p)

	copier := makeProfileCopier(p)
	greetings(p, o.UI)
	for {
		input, err := o.UI.ReadLine("(pprof) ")
		if err != nil {
			if err != io.EOF {
				return err
			}
			if input == "" {
				return nil
			}
		}

		for _, input := range shortcuts.expand(input) {
			// Process assignments of the form variable=value
			if s := strings.SplitN(input, "=", 2); len(s) > 0 {
				name := strings.TrimSpace(s[0])
				var value string
				if len(s) == 2 {
					value = s[1]
					if comment := strings.LastIndex(value, commentStart); comment != -1 {
						value = value[:comment]
					}
					value = strings.TrimSpace(value)
				}
				if isConfigurable(name) {
					// All non-bool options require inputs
					if len(s) == 1 && !isBoolConfig(name) {
						o.UI.PrintErr(fmt.Errorf("please specify a value, e.g. %s=<val>", name))
						continue
					}
					if name == "sample_index" {
						// Error check sample_index=xxx to ensure xxx is a valid sample type.
						index, err := p.SampleIndexByName(value)
						if err != nil {
							o.UI.PrintErr(err)
							continue
						}
						if index < 0 || index >= len(p.SampleType) {
							o.UI.PrintErr(fmt.Errorf("invalid sample_index %q", value))
							continue
						}
						value = p.SampleType[index].Type
					}
					if err := configure(name, value); err != nil {
						o.UI.PrintErr(err)
					}
					continue
				}
			}

			tokens := strings.Fields(input)
			if len(tokens) == 0 {
				continue
			}

			switch tokens[0] {
			case "o", "options":
				printCurrentOptions(p, o.UI)
				continue
			case "exit", "quit", "q":
				return nil
			case "help":
				commandHelp(strings.Join(tokens[1:], " "), o.UI)
				continue
			}

			args, cfg, err := parseCommandLine(tokens)
			if err == nil {
				err = generateReportWrapper(copier.newCopy(), args, cfg, o)
			}

			if err != nil {
				o.UI.PrintErr(err)
			}
		}
	}
}

var generateReportWrapper = generateReport // For testing purposes.

// greetings prints a brief welcome and some overall profile
// information before accepting interactive commands.
func greetings(p *profile.Profile, ui plugin.UI) {
	numLabelUnits := identifyNumLabelUnits(p, ui)
	ropt, err := reportOptions(p, numLabelUnits, currentConfig())
	if err == nil {
		rpt := report.New(p, ropt)
		ui.Print(strings.Join(report.ProfileLabels(rpt), "\n"))
		if rpt.Total() == 0 && len(p.SampleType) > 1 {
			ui.Print(`No samples were found with the default sample value type.`)
			ui.Print(`Try "sample_index" command to analyze different sample values.`, "\n")
		}
	}
	ui.Print(`Entering interactive mode (type "help" for commands, "o" for options)`)
}

// shortcuts represents composite commands that expand into a sequence
// of other commands.
type shortcuts map[string][]string

func (a shortcuts) expand(input string) []string {
	input = strings.TrimSpace(input)
	if a != nil {
		if r, ok := a[input]; ok {
			return r
		}
	}
	return []string{input}
}

var pprofShortcuts = shortcuts{
	":": []string{"focus=", "ignore=", "hide=", "tagfocus=", "tagignore="},
}

// profileShortcuts creates macros for convenience and backward compatibility.
func profileShortcuts(p *profile.Profile) shortcuts {
	s := pprofShortcuts
	// Add shortcuts for sample types
	for _, st := range p.SampleType {
		command := fmt.Sprintf("sample_index=%s", st.Type)
		s[st.Type] = []string{command}
		s["total_"+st.Type] = []string{"mean=0", command}
		s["mean_"+st.Type] = []string{"mean=1", command}
	}
	return s
}

func sampleTypes(p *profile.Profile) []string {
	types := make([]string, len(p.SampleType))
	for i, t := range p.SampleType {
		types[i] = t.Type
	}
	return types
}

func printCurrentOptions(p *profile.Profile, ui plugin.UI) {
	var args []string
	current := currentConfig()
	for _, f := range configFields {
		n := f.name
		v := current.get(f)
		comment := ""
		switch {
		case len(f.choices) > 0:
			values := append([]string{}, f.choices...)
			sort.Strings(values)
			comment = "[" + strings.Join(values, " | ") + "]"
		case n == "sample_index":
			st := sampleTypes(p)
			if v == "" {
				// Apply default (last sample index).
				v = st[len(st)-1]
			}
			// Add comments for all sample types in profile.
			comment = "[" + strings.Join(st, " | ") + "]"
		case n == "source_path":
			continue
		case n == "nodecount" && v == "-1":
			comment = "default"
		case v == "":
			// Add quotes for empty values.
			v = `""`
		}
		if n == "granularity" && v == "" {
			v = "(default)"
		}
		if comment != "" {
			comment = commentStart + " " + comment
		}
		args = append(args, fmt.Sprintf("  %-25s = %-20s %s", n, v, comment))
	}
	sort.Strings(args)
	ui.Print(strings.Join(args, "\n"))
}

// parseCommandLine parses a command and returns the pprof command to
// execute and the configuration to use for the report.
func parseCommandLine(input []string) ([]string, config, error) {
	cmd, args := input[:1], input[1:]
	name := cmd[0]

	c := pprofCommands[name]
	if c == nil {
		// Attempt splitting digits on abbreviated commands (eg top10)
		if d := tailDigitsRE.FindString(name); d != "" && d != name {
			name = name[:len(name)-len(d)]
			cmd[0], args = name, append([]string{d}, args...)
			c = pprofCommands[name]
		}
	}
	if c == nil {
		if _, ok := configHelp[name]; ok {
			value := "<val>"
			if len(args) > 0 {
				value = args[0]
			}
			return nil, config{}, fmt.Errorf("did you mean: %s=%s", name, value)
		}
		return nil, config{}, fmt.Errorf("unrecognized command: %q", name)
	}

	if c.hasParam {
		if len(args) == 0 {
			return nil, config{}, fmt.Errorf("command %s requires an argument", name)
		}
		cmd = append(cmd, args[0])
		args = args[1:]
	}

	// Copy config since options set in the command line should not persist.
	vcopy := currentConfig()

	var focus, ignore string
	for i := 0; i < len(args); i++ {
		t := args[i]
		if n, err := strconv.ParseInt(t, 10, 32); err == nil {
			vcopy.NodeCount = int(n)
			continue
		}
		switch t[0] {
		case '>':
			outputFile := t[1:]
			if outputFile == "" {
				i++
				if i >= len(args) {
					return nil, config{}, fmt.Errorf("unexpected end of line after >")
				}
				outputFile = args[i]
			}
			vcopy.Output = outputFile
		case '-':
			if t == "--cum" || t == "-cum" {
				vcopy.Sort = "cum"
				continue
			}
			ignore = catRegex(ignore, t[1:])
		default:
			focus = catRegex(focus, t)
		}
	}

	if name == "tags" {
		if focus != "" {
			vcopy.TagFocus = focus
		}
		if ignore != "" {
			vcopy.TagIgnore = ignore
		}
	} else {
		if focus != "" {
			vcopy.Focus = focus
		}
		if ignore != "" {
			vcopy.Ignore = ignore
		}
	}
	if vcopy.NodeCount == -1 && (name == "text" || name == "top") {
		vcopy.NodeCount = 10
	}

	return cmd, vcopy, nil
}

func catRegex(a, b string) string {
	if a != "" && b != "" {
		return a + "|" + b
	}
	return a + b
}

// commandHelp displays help and usage information for all Commands
// and Variables or a specific Command or Variable.
func commandHelp(args string, ui plugin.UI) {
	if args == "" {
		help := usage(false)
		help = help + `
  :   Clear focus/ignore/hide/tagfocus/tagignore

  type "help <cmd|option>" for more information
`

		ui.Print(help)
		return
	}

	if c := pprofCommands[args]; c != nil {
		ui.Print(c.help(args))
		return
	}

	if help, ok := configHelp[args]; ok {
		ui.Print(help + "\n")
		return
	}

	ui.PrintErr("Unknown command: " + args)
}

// newCompleter creates an autocompletion function for a set of commands.
func newCompleter(fns []string) func(string) string {
	return func(line string) string {
		switch tokens := strings.Fields(line); len(tokens) {
		case 0:
			// Nothing to complete
		case 1:
			// Single token -- complete command name
			if match := matchVariableOrCommand(tokens[0]); match != "" {
				return match
			}
		case 2:
			if tokens[0] == "help" {
				if match := matchVariableOrCommand(tokens[1]); match != "" {
					return tokens[0] + " " + match
				}
				return line
			}
			fallthrough
		default:
			// Multiple tokens -- complete using functions, except for tags
			if cmd := pprofCommands[tokens[0]]; cmd != nil && tokens[0] != "tags" {
				lastTokenIdx := len(tokens) - 1
				lastToken := tokens[lastTokenIdx]
				if strings.HasPrefix(lastToken, "-") {
					lastToken = "-" + functionCompleter(lastToken[1:], fns)
				} else {
					lastToken = functionCompleter(lastToken, fns)
				}
				return strings.Join(append(tokens[:lastTokenIdx], lastToken), " ")
			}
		}
		return line
	}
}

// matchVariableOrCommand attempts to match a string token to the prefix of a Command.
func matchVariableOrCommand(token string) string {
	token = strings.ToLower(token)
	var matches []string
	for cmd := range pprofCommands {
		if strings.HasPrefix(cmd, token) {
			matches = append(matches, cmd)
		}
	}
	matches = append(matches, completeConfig(token)...)
	if len(matches) == 1 {
		return matches[0]
	}
	return ""
}

// functionCompleter replaces provided substring with a function
// name retrieved from a profile if a single match exists. Otherwise,
// it returns unchanged substring. It defaults to no-op if the profile
// is not specified.
func functionCompleter(substring string, fns []string) string {
	found := ""
	for _, fName := range fns {
		if strings.Contains(fName, substring) {
			if found != "" {
				return substring
			}
			found = fName
		}
	}
	if found != "" {
		return found
	}
	return substring
}

func functionNames(p *profile.Profile) []string {
	var fns []string
	for _, fn := range p.Function {
		fns = append(fns, fn.Name)
	}
	return fns
}

"""



```