Response:
Let's break down the thought process for analyzing the provided Go code and generating the comprehensive answer.

1. **Understand the Goal:** The primary goal is to understand the functionality of the `cli.go` file within the `pprof` tool, explain it in detail, provide code examples where relevant, and highlight potential user errors.

2. **Initial Code Scan (Keywords and Structure):**  Quickly scan the code for keywords and the overall structure. Notice the `package driver`, imports like `errors`, `fmt`, `os`, and external libraries (`github.com/google/pprof/internal/binutils`, `github.com/google/pprof/internal/plugin`). The presence of a `source` struct and a `parseFlags` function immediately suggests this file is involved in handling command-line arguments. The `usageMsgHdr`, `usageMsgSrc`, and `usageMsgVars` variables indicate it's also responsible for displaying usage information.

3. **Focus on `parseFlags`:** This function is the core of the file's logic. Analyze its steps:
    * **Flag Definition:** It uses `o.Flagset` to define various command-line flags. Categorize these flags (comparisons, source options, CPU/Heap/Contention profiles, HTTP, configuration). Note the data types of the flag values (string, int, bool, string list).
    * **Executable/Build ID Recognition:** Observe the logic that tries to identify the first argument as either an executable or a build ID. This is a key piece of functionality.
    * **Configuration Handling:**  Identify the interaction with a `config` type and the `installConfigFlags` function. This suggests the file manages various configuration settings.
    * **Output Format Selection:** Examine the `outputFormat` function and how it uses `flagCommands` and `flagParamCommands` to determine the desired output format. The error checking for multiple output formats is important.
    * **Sample Index Handling:** Understand how flags like `-inuse_space` are mapped to the `SampleIndex` configuration option.
    * **Base/Diff Base Profiles:** Analyze the `addBaseProfiles` function and how it handles `-base` and `-diff_base`.
    * **Final `source` struct:**  See how the parsed flag values are collected into the `source` struct.
    * **Error Handling:** Notice the various `errors.New()` calls for invalid input.

4. **Analyze Helper Functions:**
    * **`addBaseProfiles`:**  Understands the logic for mutually exclusive `-base` and `-diff_base`.
    * **`dropEmpty`:**  Recognizes its purpose in filtering out empty strings from flag lists.
    * **`installConfigFlags`:** This is more complex. Realize it dynamically creates flags based on a `configFields` structure (though the structure itself isn't in this code snippet). Focus on the different `case` statements for `bool`, `int`, `float64`, and `string` types. Pay attention to the handling of choice-based string flags.
    * **`sampleIndex`:** Understands the logic for mapping convenience flags to the `SampleIndex`.
    * **`outputFormat`:**  Reiterates the logic for selecting the output format.

5. **Interpret Usage Messages:** Carefully read `usageMsgHdr`, `usageMsgSrc`, and `usageMsgVars` to understand the basic ways to invoke the `pprof` tool. Note the different invocation patterns (with format, without format for interactive shell, with `-http` for web UI).

6. **Synthesize Functionality:** Based on the analysis, list the core functionalities: parsing command-line flags, identifying profile sources, handling base profiles, setting configuration options, determining output format, and displaying usage information.

7. **Infer Go Features:**
    * **Flag Parsing:** The code heavily utilizes the `flag` package for defining and parsing command-line arguments.
    * **Structs:** The `source` struct is used to group related data.
    * **Slices:**  Used for storing lists of strings (e.g., `Sources`, `Base`).
    * **Maps:**  Used for associating commands with their corresponding flags (`flagCommands`, `flagParamCommands`).
    * **Error Handling:**  The use of `errors.New()` and returning `error` values is standard Go error handling.
    * **Closures:** The function returned by `installConfigFlags` is a closure, capturing the `cfg` and `setters` variables.
    * **Type Switching:** Used in `installConfigFlags` to handle different data types of configuration options.

8. **Create Code Examples:**  For key functionalities, create simple Go code examples demonstrating their usage. This involves:
    * **Flag Definition and Parsing:** Show how to define and parse a basic flag.
    * **Struct Usage:** Demonstrate how to create and access fields of the `source` struct.

9. **Identify User Mistakes:** Think about common errors users might make based on the flags and their interactions:
    * Providing no profile source.
    * Using `-http` with an output format.
    * Using `-no_browser` without `-http`.
    * Conflicting output formats.
    * Missing base profile when using `-normalize`.
    * Specifying both `-base` and `-diff_base`.

10. **Structure the Answer:** Organize the findings into clear sections: Functionality, Go Features, Code Examples, Command-line Argument Details, and Potential User Mistakes. Use clear and concise language, and provide concrete examples. Use formatting (like bolding and code blocks) to enhance readability.

11. **Review and Refine:**  Read through the generated answer to ensure accuracy, completeness, and clarity. Check for any grammatical errors or typos. Ensure the code examples are correct and illustrate the intended point. Make sure the explanation of command-line arguments is detailed enough.

By following this structured approach, we can systematically analyze the Go code and generate a comprehensive and informative answer that addresses all the requirements of the prompt.
这段Go语言代码是 `pprof` 工具中用于解析命令行参数的部分。 `pprof` 是一个用于可视化和分析性能剖析数据的工具。  `cli.go` 文件中的这段代码主要负责处理用户在命令行中输入的各种选项和参数，并将它们转换为程序可以理解的数据结构。

**主要功能:**

1. **定义 `source` 结构体:**  `source` 结构体用于存储解析后的命令行参数，包括：
    * `Sources`:  一个字符串切片，存储要分析的性能剖析数据源的路径或 URL。
    * `ExecName`: 可执行文件的路径。
    * `BuildID`:  可执行文件的构建 ID。
    * `Base`:  用于比较或减去的基准性能剖析数据源。
    * `DiffBase`:  一个布尔值，指示是否将 `Base` 视为用于比较的基准。
    * `Normalize`:  一个布尔值，指示是否需要对剖析数据进行标准化。
    * `Seconds`:  对于动态剖析，指定收集剖析数据的时间长度（秒）。
    * `Timeout`:  获取剖析数据的超时时间（秒）。
    * `Symbolize`:  符号化选项，控制如何进行符号解析。
    * `HTTPHostport`:  指定启动 Web UI 的主机和端口。
    * `HTTPDisableBrowser`:  一个布尔值，指示是否禁用自动打开浏览器。
    * `Comment`:  添加到剖析数据的注释字符串。

2. **解析命令行标志 (flags):** `parseFlags` 函数是核心功能，它使用 `plugin.Options` 中提供的 `Flagset` 来定义和解析各种命令行标志。这些标志可以分为以下几类：
    * **比较选项:**
        * `-diff_base`:  指定用于比较的基准性能剖析数据源。
        * `-base`:  指定用于减去的基准性能剖析数据源。
    * **数据源选项:**
        * `-symbolize`:  控制符号化的方式（none, local, fastlocal, remote, force）。
        * `-buildid`:  覆盖第一个映射的构建 ID。
        * `-timeout`:  设置获取剖析数据的超时时间。
        * `-add_comment`:  向剖析数据添加注释。
    * **CPU 剖析选项:**
        * `-seconds`:  指定动态 CPU 剖析的持续时间。
    * **堆剖析选项:**
        * `-inuse_space`:  显示正在使用的内存大小。
        * `-inuse_objects`:  显示正在使用的对象数量。
        * `-alloc_space`:  显示已分配的内存大小。
        * `-alloc_objects`:  显示已分配的对象数量。
    * **锁竞争剖析选项:**
        * `-total_delay`:  显示每个区域的总延迟。
        * `-contentions`:  显示每个区域的延迟次数。
        * `-mean_delay`:  显示每个区域的平均延迟。
    * **工具路径选项:**
        * `-tools`:  指定对象工具的路径。
    * **HTTP 界面选项:**
        * `-http`:  指定启动交互式 Web UI 的主机和端口。
        * `-no_browser`:  禁用自动打开浏览器。
    * **输出格式选项:**  根据 `pprofCommands` 定义，例如 `-pdf`, `-svg`, `-text` 等，用于指定输出报告的格式。

3. **识别可执行文件或构建 ID:** `parseFlags` 尝试将命令行参数中的第一个参数识别为可执行文件的路径或构建 ID。

4. **处理配置:**  `installConfigFlags` 函数用于安装与配置相关的命令行标志，并将解析后的值应用到 `cfg` 变量上。

5. **确定输出格式:** `outputFormat` 函数根据用户指定的标志来确定所需的输出报告格式。

6. **处理便捷选项:**  代码中包含一些便捷选项，例如 `-inuse_space` 等，它们实际上是设置了 `sample_index` 配置项。

7. **构建 `source` 结构体:** 将解析后的标志值填充到 `source` 结构体中。

8. **处理基准剖析文件:** `addBaseProfiles` 函数处理 `-base` 和 `-diff_base` 标志，确保它们不会同时被指定。

9. **处理标准化:**  如果指定了 `-normalize`，则需要至少提供一个基准剖析文件。

**Go 语言功能示例:**

* **命令行标志解析 (flag parsing):**

```go
package main

import (
	"flag"
	"fmt"
)

func main() {
	var name string
	var age int

	flag.StringVar(&name, "name", "World", "Your name")
	flag.IntVar(&age, "age", 0, "Your age")

	flag.Parse()

	fmt.Printf("Hello, %s! You are %d years old.\n", name, age)
}
```

**假设输入:** `go run main.go -name="Alice" -age=30`
**预期输出:** `Hello, Alice! You are 30 years old.`

这个例子展示了如何使用 `flag` 包定义和解析字符串和整数类型的命令行标志。 `parseFlags` 函数内部使用了类似的方法，但定义了更多的标志并使用了 `plugin.FlagSet`。

* **结构体 (struct):**

```go
package main

import "fmt"

type Person struct {
	Name string
	Age  int
}

func main() {
	person := Person{Name: "Bob", Age: 25}
	fmt.Println(person.Name)
	fmt.Println(person.Age)
}
```

**预期输出:**
```
Bob
25
```

`source` 结构体就是用来组织和存储命令行参数的。

**命令行参数的具体处理:**

`parseFlags` 函数遍历所有定义的命令行标志，并将用户在命令行中提供的值解析出来。  例如：

* 如果用户使用了 `-seconds 10`，那么 `source.Seconds` 的值将被设置为 `10`。
* 如果用户使用了 `-http localhost:8080`，那么 `source.HTTPHostport` 的值将被设置为 `"localhost:8080"`。
* 如果用户使用了 `-base profile.pb.gz`，那么 `"profile.pb.gz"` 将会被添加到 `source.Base` 切片中。

`installConfigFlags` 函数更进一步，它根据 `configFields` 中定义的配置项动态创建命令行标志，并将解析后的值设置到 `cfg` 变量对应的字段上。这允许用户通过命令行修改 `pprof` 的各种配置行为。

**使用者易犯错的点:**

1. **同时指定 `-base` 和 `-diff_base`:**  代码中明确指出这两个标志不能同时使用。使用者可能会混淆它们的功能，导致错误。
    * **错误示例:** `pprof -base old.pb.gz -diff_base new.pb.gz profile.pb.gz`
    * **错误信息:** `-base and -diff_base flags cannot both be specified`

2. **在指定输出格式的同时使用 `-http`:**  交互式的 Web UI 和命令行输出格式是互斥的。如果用户指定了输出格式（例如 `-pdf`），同时又使用了 `-http`，则会报错。
    * **错误示例:** `pprof -pdf -http localhost:8080 profile.pb.gz`
    * **错误信息:** `-http is not compatible with an output format on the command line`

3. **单独使用 `-no_browser`:** `-no_browser` 只有在使用 `-http` 启动 Web UI 时才有意义，用于阻止自动打开浏览器。如果单独使用 `-no_browser`，则会报错。
    * **错误示例:** `pprof -no_browser profile.pb.gz`
    * **错误信息:** `-no_browser only makes sense with -http`

4. **使用 `-normalize` 但没有提供基准剖析文件:** 如果用户想要标准化剖析数据，必须通过 `-base` 提供一个基准剖析文件。否则，标准化操作无法进行。
    * **假设存在一个名为 `pprof.cfg` 的配置文件，其中 `Normalize` 被设置为 `true`。**
    * **错误示例:** `pprof profile.pb.gz`  (假设配置文件中 `Normalize` 为 true，但命令行没有提供 `-base`)
    * **错误信息:** `must have base profile to normalize by`

总而言之，这段代码是 `pprof` 工具解析命令行参数的核心部分，它定义了各种选项和参数，并将其转换为程序内部使用的 `source` 结构体，以便后续的剖析数据处理和报告生成。理解这段代码有助于理解 `pprof` 工具的命令行使用方式和配置选项。

### 提示词
```
这是路径为go/src/cmd/vendor/github.com/google/pprof/internal/driver/cli.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
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
	"errors"
	"fmt"
	"os"

	"github.com/google/pprof/internal/binutils"
	"github.com/google/pprof/internal/plugin"
)

type source struct {
	Sources   []string
	ExecName  string
	BuildID   string
	Base      []string
	DiffBase  bool
	Normalize bool

	Seconds            int
	Timeout            int
	Symbolize          string
	HTTPHostport       string
	HTTPDisableBrowser bool
	Comment            string
}

// parseFlags parses the command lines through the specified flags package
// and returns the source of the profile and optionally the command
// for the kind of report to generate (nil for interactive use).
func parseFlags(o *plugin.Options) (*source, []string, error) {
	flag := o.Flagset
	// Comparisons.
	flagDiffBase := flag.StringList("diff_base", "", "Source of base profile for comparison")
	flagBase := flag.StringList("base", "", "Source of base profile for profile subtraction")
	// Source options.
	flagSymbolize := flag.String("symbolize", "", "Options for profile symbolization")
	flagBuildID := flag.String("buildid", "", "Override build id for first mapping")
	flagTimeout := flag.Int("timeout", -1, "Timeout in seconds for fetching a profile")
	flagAddComment := flag.String("add_comment", "", "Annotation string to record in the profile")
	// CPU profile options
	flagSeconds := flag.Int("seconds", -1, "Length of time for dynamic profiles")
	// Heap profile options
	flagInUseSpace := flag.Bool("inuse_space", false, "Display in-use memory size")
	flagInUseObjects := flag.Bool("inuse_objects", false, "Display in-use object counts")
	flagAllocSpace := flag.Bool("alloc_space", false, "Display allocated memory size")
	flagAllocObjects := flag.Bool("alloc_objects", false, "Display allocated object counts")
	// Contention profile options
	flagTotalDelay := flag.Bool("total_delay", false, "Display total delay at each region")
	flagContentions := flag.Bool("contentions", false, "Display number of delays at each region")
	flagMeanDelay := flag.Bool("mean_delay", false, "Display mean delay at each region")
	flagTools := flag.String("tools", os.Getenv("PPROF_TOOLS"), "Path for object tool pathnames")

	flagHTTP := flag.String("http", "", "Present interactive web UI at the specified http host:port")
	flagNoBrowser := flag.Bool("no_browser", false, "Skip opening a browser for the interactive web UI")

	// Flags that set configuration properties.
	cfg := currentConfig()
	configFlagSetter := installConfigFlags(flag, &cfg)

	flagCommands := make(map[string]*bool)
	flagParamCommands := make(map[string]*string)
	for name, cmd := range pprofCommands {
		if cmd.hasParam {
			flagParamCommands[name] = flag.String(name, "", "Generate a report in "+name+" format, matching regexp")
		} else {
			flagCommands[name] = flag.Bool(name, false, "Generate a report in "+name+" format")
		}
	}

	args := flag.Parse(func() {
		o.UI.Print(usageMsgHdr +
			usage(true) +
			usageMsgSrc +
			flag.ExtraUsage() +
			usageMsgVars)
	})
	if len(args) == 0 {
		return nil, nil, errors.New("no profile source specified")
	}

	var execName string
	// Recognize first argument as an executable or buildid override.
	if len(args) > 1 {
		arg0 := args[0]
		if file, err := o.Obj.Open(arg0, 0, ^uint64(0), 0, ""); err == nil {
			file.Close()
			execName = arg0
			args = args[1:]
		}
	}

	// Apply any specified flags to cfg.
	if err := configFlagSetter(); err != nil {
		return nil, nil, err
	}

	cmd, err := outputFormat(flagCommands, flagParamCommands)
	if err != nil {
		return nil, nil, err
	}
	if cmd != nil && *flagHTTP != "" {
		return nil, nil, errors.New("-http is not compatible with an output format on the command line")
	}

	if *flagNoBrowser && *flagHTTP == "" {
		return nil, nil, errors.New("-no_browser only makes sense with -http")
	}

	si := cfg.SampleIndex
	si = sampleIndex(flagTotalDelay, si, "delay", "-total_delay", o.UI)
	si = sampleIndex(flagMeanDelay, si, "delay", "-mean_delay", o.UI)
	si = sampleIndex(flagContentions, si, "contentions", "-contentions", o.UI)
	si = sampleIndex(flagInUseSpace, si, "inuse_space", "-inuse_space", o.UI)
	si = sampleIndex(flagInUseObjects, si, "inuse_objects", "-inuse_objects", o.UI)
	si = sampleIndex(flagAllocSpace, si, "alloc_space", "-alloc_space", o.UI)
	si = sampleIndex(flagAllocObjects, si, "alloc_objects", "-alloc_objects", o.UI)
	cfg.SampleIndex = si

	if *flagMeanDelay {
		cfg.Mean = true
	}

	source := &source{
		Sources:            args,
		ExecName:           execName,
		BuildID:            *flagBuildID,
		Seconds:            *flagSeconds,
		Timeout:            *flagTimeout,
		Symbolize:          *flagSymbolize,
		HTTPHostport:       *flagHTTP,
		HTTPDisableBrowser: *flagNoBrowser,
		Comment:            *flagAddComment,
	}

	if err := source.addBaseProfiles(*flagBase, *flagDiffBase); err != nil {
		return nil, nil, err
	}

	normalize := cfg.Normalize
	if normalize && len(source.Base) == 0 {
		return nil, nil, errors.New("must have base profile to normalize by")
	}
	source.Normalize = normalize

	if bu, ok := o.Obj.(*binutils.Binutils); ok {
		bu.SetTools(*flagTools)
	}

	setCurrentConfig(cfg)
	return source, cmd, nil
}

// addBaseProfiles adds the list of base profiles or diff base profiles to
// the source. This function will return an error if both base and diff base
// profiles are specified.
func (source *source) addBaseProfiles(flagBase, flagDiffBase []*string) error {
	base, diffBase := dropEmpty(flagBase), dropEmpty(flagDiffBase)
	if len(base) > 0 && len(diffBase) > 0 {
		return errors.New("-base and -diff_base flags cannot both be specified")
	}

	source.Base = base
	if len(diffBase) > 0 {
		source.Base, source.DiffBase = diffBase, true
	}
	return nil
}

// dropEmpty list takes a slice of string pointers, and outputs a slice of
// non-empty strings associated with the flag.
func dropEmpty(list []*string) []string {
	var l []string
	for _, s := range list {
		if *s != "" {
			l = append(l, *s)
		}
	}
	return l
}

// installConfigFlags creates command line flags for configuration
// fields and returns a function which can be called after flags have
// been parsed to copy any flags specified on the command line to
// *cfg.
func installConfigFlags(flag plugin.FlagSet, cfg *config) func() error {
	// List of functions for setting the different parts of a config.
	var setters []func()
	var err error // Holds any errors encountered while running setters.

	for _, field := range configFields {
		n := field.name
		help := configHelp[n]
		var setter func()
		switch ptr := cfg.fieldPtr(field).(type) {
		case *bool:
			f := flag.Bool(n, *ptr, help)
			setter = func() { *ptr = *f }
		case *int:
			f := flag.Int(n, *ptr, help)
			setter = func() { *ptr = *f }
		case *float64:
			f := flag.Float64(n, *ptr, help)
			setter = func() { *ptr = *f }
		case *string:
			if len(field.choices) == 0 {
				f := flag.String(n, *ptr, help)
				setter = func() { *ptr = *f }
			} else {
				// Make a separate flag per possible choice.
				// Set all flags to initially false so we can
				// identify conflicts.
				bools := make(map[string]*bool)
				for _, choice := range field.choices {
					bools[choice] = flag.Bool(choice, false, configHelp[choice])
				}
				setter = func() {
					var set []string
					for k, v := range bools {
						if *v {
							set = append(set, k)
						}
					}
					switch len(set) {
					case 0:
						// Leave as default value.
					case 1:
						*ptr = set[0]
					default:
						err = fmt.Errorf("conflicting options set: %v", set)
					}
				}
			}
		}
		setters = append(setters, setter)
	}

	return func() error {
		// Apply the setter for every flag.
		for _, setter := range setters {
			setter()
			if err != nil {
				return err
			}
		}
		return nil
	}
}

func sampleIndex(flag *bool, si string, sampleType, option string, ui plugin.UI) string {
	if *flag {
		if si == "" {
			return sampleType
		}
		ui.PrintErr("Multiple value selections, ignoring ", option)
	}
	return si
}

func outputFormat(bcmd map[string]*bool, acmd map[string]*string) (cmd []string, err error) {
	for n, b := range bcmd {
		if *b {
			if cmd != nil {
				return nil, errors.New("must set at most one output format")
			}
			cmd = []string{n}
		}
	}
	for n, s := range acmd {
		if *s != "" {
			if cmd != nil {
				return nil, errors.New("must set at most one output format")
			}
			cmd = []string{n, *s}
		}
	}
	return cmd, nil
}

var usageMsgHdr = `usage:

Produce output in the specified format.

   pprof <format> [options] [binary] <source> ...

Omit the format to get an interactive shell whose commands can be used
to generate various views of a profile

   pprof [options] [binary] <source> ...

Omit the format and provide the "-http" flag to get an interactive web
interface at the specified host:port that can be used to navigate through
various views of a profile.

   pprof -http [host]:[port] [options] [binary] <source> ...

Details:
`

var usageMsgSrc = "\n\n" +
	"  Source options:\n" +
	"    -seconds              Duration for time-based profile collection\n" +
	"    -timeout              Timeout in seconds for profile collection\n" +
	"    -buildid              Override build id for main binary\n" +
	"    -add_comment          Free-form annotation to add to the profile\n" +
	"                          Displayed on some reports or with pprof -comments\n" +
	"    -diff_base source     Source of base profile for comparison\n" +
	"    -base source          Source of base profile for profile subtraction\n" +
	"    profile.pb.gz         Profile in compressed protobuf format\n" +
	"    legacy_profile        Profile in legacy pprof format\n" +
	"    http://host/profile   URL for profile handler to retrieve\n" +
	"    -symbolize=           Controls source of symbol information\n" +
	"      none                  Do not attempt symbolization\n" +
	"      local                 Examine only local binaries\n" +
	"      fastlocal             Only get function names from local binaries\n" +
	"      remote                Do not examine local binaries\n" +
	"      force                 Force re-symbolization\n" +
	"    Binary                  Local path or build id of binary for symbolization\n"

var usageMsgVars = "\n\n" +
	"  Misc options:\n" +
	"   -http              Provide web interface at host:port.\n" +
	"                      Host is optional and 'localhost' by default.\n" +
	"                      Port is optional and a randomly available port by default.\n" +
	"   -no_browser        Skip opening a browser for the interactive web UI.\n" +
	"   -tools             Search path for object tools\n" +
	"\n" +
	"  Legacy convenience options:\n" +
	"   -inuse_space           Same as -sample_index=inuse_space\n" +
	"   -inuse_objects         Same as -sample_index=inuse_objects\n" +
	"   -alloc_space           Same as -sample_index=alloc_space\n" +
	"   -alloc_objects         Same as -sample_index=alloc_objects\n" +
	"   -total_delay           Same as -sample_index=delay\n" +
	"   -contentions           Same as -sample_index=contentions\n" +
	"   -mean_delay            Same as -mean -sample_index=delay\n" +
	"\n" +
	"  Environment Variables:\n" +
	"   PPROF_TMPDIR       Location for saved profiles (default $HOME/pprof)\n" +
	"   PPROF_TOOLS        Search path for object-level tools\n" +
	"   PPROF_BINARY_PATH  Search path for local binary files\n" +
	"                      default: $HOME/pprof/binaries\n" +
	"                      searches $buildid/$name, $buildid/*, $path/$buildid,\n" +
	"                      ${buildid:0:2}/${buildid:2}.debug, $name, $path,\n" +
	"                      ${name}.debug, $dir/.debug/${name}.debug,\n" +
	"                      usr/lib/debug/$dir/${name}.debug\n" +
	"   * On Windows, %USERPROFILE% is used instead of $HOME"
```