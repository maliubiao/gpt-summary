Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Scan and Purpose Identification:**

The first step is a quick skim of the code. Keywords like `Application`, `Flag`, `Command`, `Parse`, `Usage`, and the package name `kingpin` strongly suggest this code is for command-line argument parsing. The presence of `vendor` in the path indicates it's a third-party library.

**2. Core Functionality Deduction:**

Based on the initial scan, I can hypothesize the primary functions:

* **Defining command-line interfaces:**  The `Application` struct likely holds definitions for flags, arguments, and subcommands.
* **Parsing command-line input:** The `Parse` and `ParseContext` functions seem responsible for processing the user's input.
* **Generating help and usage information:** The `Usage`, `UsageTemplate`, and related methods likely handle the `--help` functionality.
* **Handling actions:** The `Action` and `PreAction` methods suggest the ability to execute code based on parsed input.
* **Supporting environment variables:** The `DefaultEnvars` and `EnvarSeparator` methods point to integration with environment variables.
* **Completion:** The presence of `completion-bash` and `completion-zsh` flags indicates support for shell completion.

**3. Detailed Examination of Key Components:**

Now, I'd delve deeper into specific parts of the code:

* **`Application` struct:**  I'd look at the fields. `Name`, `Help`, `author`, `version` are clearly metadata. `output`, `errors`, `terminate` handle I/O and exit behavior. `flagGroup`, `argGroup`, `cmdGroup` are likely responsible for managing the different parts of the command-line interface. The `resolvers` field suggests a mechanism for resolving values from different sources.
* **`New` function:** This is the constructor. I'd note how it initializes the `Application` struct, sets default values, and defines the built-in `help` and completion flags.
* **`Parse` and `ParseContext`:**  I'd pay attention to how these functions process arguments, tokenize them, and build a `ParseContext`. The call to `a.init()` before parsing is important.
* **`Usage` related functions:**  I'd look for how templates are used and how the output is generated.
* **`Action` and `PreAction`:**  I'd observe how these are added and how they are applied during parsing.
* **Completion-related functions (`generateBashCompletionScript`, `generateZSHCompletionScript`, `completionOptions`, `generateBashCompletion`):**  These are clearly for shell completion. I'd note the use of different templates for bash and zsh.
* **Error handling:**  The `Errorf`, `Fatalf`, and `FatalIfError` methods are standard error handling patterns.

**4. Inferring Go Language Features:**

Based on the code, I'd identify the following Go features in use:

* **Structs:**  `Application`, `UsageContext`, etc.
* **Methods:** Functions associated with structs (e.g., `a.Parse(args)`).
* **Interfaces:**  The `io.Writer` interface for output and error streams, and the `Resolver` and `Action` interfaces (though the latter is likely a `type Action func(...) error`).
* **Variadic functions:** Functions like `Resolver(resolvers ...Resolver)`.
* **Closures:** The anonymous functions used for flag actions (`func(a *Application, e *ParseElement, c *ParseContext) error { ... }`).
* **Error handling:** The use of the `error` interface and returning errors from functions.
* **String manipulation:** The `strings` package is used for joining strings and checking prefixes.
* **Standard library packages:**  `fmt`, `io`, `os`, `strings`.

**5. Constructing Examples and Identifying Potential Issues:**

With a good understanding of the code, I'd create examples to illustrate its usage. I'd focus on:

* Basic flag and argument definitions.
* Subcommand usage.
* The `--help` flag.
* The `--version` flag.
* Environment variable usage.
* Shell completion.

To identify potential errors, I'd consider common pitfalls:

* **Duplicate flags:** The `checkDuplicateFlags` function highlights this.
* **Required flags/arguments not provided.**
* **Mixing arguments and flags when `Interspersed(false)` is used.**
* **Forgetting to define an action for a command.**

**6. Structuring the Answer:**

Finally, I'd organize the findings into a clear and structured answer, addressing all the points in the prompt:

* **Functionality:**  A high-level summary.
* **Go Language Features:**  Concrete examples using the provided code.
* **Code Inference Example:**  A simple example showcasing basic usage with input and output.
* **Command-line Parameter Processing:**  Detailed explanation of flags, arguments, and subcommands.
* **Common Mistakes:**  Specific examples of potential errors users might make.

**Self-Correction/Refinement:**

During the process, I'd constantly review my understanding and refine my analysis. For instance, initially, I might not have fully grasped the role of `resolvers`. By examining the `buildResolvers` function, I'd realize their importance in providing default values and handling environment variables. Similarly, I might initially overlook the `PreAction` functionality and would need to revisit the code to understand its purpose. The process is iterative, involving continuous reading, understanding, and synthesizing information.
这段代码是 Go 语言库 `kingpin` 的一部分，主要实现了 **命令行应用程序的定义和解析** 功能。`kingpin` 允许开发者以声明式的方式定义应用程序的命令行接口，包括标志（flags）、参数（arguments）和子命令（subcommands），并负责解析用户输入的命令行参数。

**功能列表:**

1. **应用程序定义:**  `Application` 结构体是定义一个命令行应用程序的核心。它包含了应用程序的名称、帮助信息、版本、作者等元数据，以及用于存储标志、参数和子命令的结构体。
2. **标志（Flags）定义:**  允许定义带有长名称（例如 `--help`）、短名称（例如 `-h`）、帮助信息、默认值等属性的标志。
3. **参数（Arguments）定义:** 允许定义位置参数，并指定其帮助信息。
4. **子命令（Commands）定义:**  支持定义子命令，使得应用程序可以拥有多层级的命令结构。每个子命令可以有自己的标志和参数。
5. **命令行解析:** `Parse` 和 `ParseContext` 方法负责解析用户输入的命令行参数，并将其映射到已定义的标志、参数和子命令。
6. **帮助信息生成:**  自动生成应用程序和子命令的帮助信息，包括标志、参数和子命令的说明，以及使用示例。可以通过 `--help` 标志触发。
7. **版本信息显示:**  可以通过 `Version` 方法添加 `--version` 标志，用于显示应用程序的版本信息。
8. **自定义操作（Actions）:**  允许为应用程序、标志、参数和子命令定义在解析成功后执行的回调函数（Action）。
9. **预处理操作（PreActions）:**  允许定义在解析特定元素之前执行的回调函数（PreAction）。
10. **环境变量支持:**  可以配置自动将环境变量映射到标志，方便用户通过环境变量配置应用程序。
11. **完成（Completion）支持:**  支持生成 Bash 和 Zsh 的自动补全脚本，提升用户体验。
12. **自定义 Usage 模板:**  允许自定义帮助信息的展示模板。
13. **错误处理:**  提供方法用于输出错误信息，并在发生错误时退出程序。
14. **结构体绑定:**  可以通过 `Struct` 方法将结构体的字段标签与命令行标志绑定，简化标志的定义。
15. **解析器（Resolvers）:** 允许添加自定义的解析器，用于从不同的来源（如配置文件）获取标志和参数的值。

**Go 语言功能示例:**

这段代码大量使用了 Go 语言的以下特性：

* **结构体 (Structs):**  `Application`、`UsageContext` 等都是结构体，用于组织和存储数据。
* **方法 (Methods):**  例如 `New`、`Parse`、`Flag` 等都是与 `Application` 结构体关联的方法。
* **接口 (Interfaces):** `io.Writer` 接口用于处理输出流（例如 `os.Stdout` 和 `os.Stderr`）。`Resolver` 接口定义了解析器的行为。`Action` 可能是一个函数类型的别名，用于表示回调函数。
* **变量 (Variables):**  `errCommandNotSpecified` 是一个包级别的错误变量。
* **函数 (Functions):**  例如 `generateBashCompletionScript`、`checkDuplicateFlags` 等。
* **变长参数 (Variadic Functions):**  例如 `Resolver(resolvers ...Resolver)` 允许传入多个解析器。
* **匿名函数 (Anonymous Functions):**  例如在 `New` 函数中定义 `--help` 标志的 Action 时使用的 `func(a *Application, e *ParseElement, c *ParseContext) error { ... }`。
* **错误处理 (Error Handling):**  函数通常会返回 `error` 类型的值来表示是否发生了错误。
* **字符串操作 (String Manipulation):** 使用 `strings` 包进行字符串的拼接和处理。
* **标准库 (Standard Library):**  使用了 `fmt`、`io`、`os` 和 `strings` 等标准库。

**代码推理示例:**

假设我们定义了一个简单的应用程序，它有一个名为 `name` 的参数和一个名为 `count` 的标志：

```go
package main

import (
	"fmt"
	"os"

	"gopkg.in/alecthomas/kingpin.v3-unstable"
)

func main() {
	app := kingpin.New("myapp", "A simple application.")
	name := app.Arg("name", "The name to say hello to.").Required().String()
	count := app.Flag("count", "Number of times to say hello.").Default("1").Int()

	_, err := app.Parse(os.Args[1:])
	if err != nil {
		app.Fatalf("Error parsing command line: %v", err)
	}

	for i := 0; i < *count; i++ {
		fmt.Printf("Hello, %s!\n", *name)
	}
}
```

**假设输入：** `myapp John --count 3`

**推理过程：**

1. `app.Parse(os.Args[1:])` 会接收命令行参数 `["John", "--count", "3"]`。
2. `kingpin` 库会识别 `"John"` 是位置参数，并将其赋值给 `name` 变量。由于 `name` 使用了 `Required()`, 如果没有提供该参数，解析会失败。
3. `kingpin` 库会识别 `--count` 是一个标志，并将其后面的值 `"3"` 转换为整数并赋值给 `count` 变量。由于 `count` 有默认值 "1"，即使不提供 `--count`，也会使用默认值。
4. 解析成功后，`*name` 的值将是 `"John"`，`*count` 的值将是 `3`。
5. 循环会执行 3 次，输出 "Hello, John!" 三次。

**预期输出：**

```
Hello, John!
Hello, John!
Hello, John!
```

**命令行参数的具体处理:**

* **标志 (Flags):**  以 `-` 或 `--` 开头的参数。例如，`--count 3` 或 `-c 3` (如果定义了短名称)。标志通常用于传递选项和配置信息。
* **参数 (Arguments):**  不以 `-` 或 `--` 开头的参数，并且按照在代码中定义的顺序进行匹配。例如，在上面的例子中，`John` 就是一个参数。参数通常用于传递主要的操作对象或数据。
* **子命令 (Commands):**  用于将应用程序的功能模块化。用户需要先输入子命令的名称，然后再输入该子命令的标志和参数。例如：

```go
package main

import (
	"fmt"
	"os"

	"gopkg.in/alecthomas/kingpin.v3-unstable"
)

func main() {
	app := kingpin.New("myapp", "A simple application with subcommands.")

	greetCmd := app.Command("greet", "Say hello.")
	greetName := greetCmd.Arg("name", "The name to say hello to.").Required().String()
	greetCount := greetCmd.Flag("count", "Number of times to say hello.").Default("1").Int()

	farewellCmd := app.Command("farewell", "Say goodbye.")
	farewellName := farewellCmd.Arg("name", "The name to say goodbye to.").Required().String()

	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	switch command {
	case greetCmd.FullCommand():
		for i := 0; i < *greetCount; i++ {
			fmt.Printf("Hello, %s!\n", *greetName)
		}
	case farewellCmd.FullCommand():
		fmt.Printf("Goodbye, %s!\n", *farewellName)
	}
}
```

在这个例子中，`greet` 和 `farewell` 是子命令。要执行 `greet` 子命令，需要输入 `myapp greet John --count 2`。`kingpin` 会将 `greet` 识别为子命令，并将后续的参数和标志解析到 `greetCmd` 中定义的变量。

**使用者易犯错的点:**

1. **标志和参数的名称冲突:**  如果定义的标志名称与参数名称相同，可能会导致解析时的歧义。`kingpin` 会尝试避免这种情况，但最好还是保持名称的唯一性。
2. **忘记设置必需的参数或标志:**  如果使用了 `.Required()` 来标记参数或标志为必需，但用户在命令行中没有提供，程序会报错并退出。
3. **子命令的使用不明确:**  用户可能不清楚应用程序有哪些子命令，或者子命令的参数和标志。清晰的帮助信息非常重要。
4. **标志值的类型错误:**  如果标志被定义为整数类型，但用户提供了非数字的值，解析会失败。
5. **混淆短名称和长名称:**  用户可能不记得标志的短名称或长名称，或者错误地使用了大小写。`kingpin` 通常是大小写敏感的。
6. **在使用 `Interspersed(false)` 的情况下，将标志放在参数后面:**  如果配置了不允许标志和参数交错出现，那么所有标志必须在第一个参数之前出现。否则，`kingpin` 会将后面的标志视为参数。

**示例说明 `Interspersed(false)` 的易错点:**

```go
package main

import (
	"fmt"
	"os"

	"gopkg.in/alecthomas/kingpin.v3-unstable"
)

func main() {
	app := kingpin.New("myapp", "An application with strict flag order.").Interspersed(false)
	name := app.Arg("name", "The name.").String()
	verbose := app.Flag("verbose", "Enable verbose output.").Bool()

	kingpin.MustParse(app.Parse(os.Args[1:]))

	fmt.Printf("Name: %s, Verbose: %v\n", *name, *verbose)
}
```

**正确用法:** `myapp --verbose John`

**错误用法 (会被解析为 `name="--verbose"`, `verbose=false`):** `myapp John --verbose`

在这个例子中，如果 `Interspersed(false)` 被设置，那么 `--verbose` 标志必须出现在 `John` 参数之前。如果用户输入 `myapp John --verbose`，`kingpin` 会将 `--verbose` 错误地解析为 `name` 参数的值。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/vendor/gopkg.in/alecthomas/kingpin.v3-unstable/app.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package kingpin

import (
	"fmt"
	"io"
	"os"
	"strings"
)

var (
	errCommandNotSpecified = TError("command not specified")
)

// An Application contains the definitions of flags, arguments and commands
// for an application.
type Application struct {
	cmdMixin
	initialized bool

	Name string
	Help string

	author         string
	version        string
	output         io.Writer // Destination for usage.
	errors         io.Writer
	terminate      func(status int) // See Terminate()
	noInterspersed bool             // can flags be interspersed with args (or must they come first)
	envarSeparator string
	defaultEnvars  bool
	resolvers      []Resolver
	completion     bool
	helpFlag       *Clause
	helpCommand    *CmdClause
	defaultUsage   *UsageContext
}

// New creates a new Kingpin application instance.
func New(name, help string) *Application {
	a := &Application{
		Name:           name,
		Help:           help,
		output:         os.Stdout,
		errors:         os.Stderr,
		terminate:      os.Exit,
		envarSeparator: string(os.PathListSeparator),
		defaultUsage: &UsageContext{
			Template: DefaultUsageTemplate,
		},
	}
	a.flagGroup = newFlagGroup()
	a.argGroup = newArgGroup()
	a.cmdGroup = newCmdGroup(a)
	a.helpFlag = a.Flag("help", T("Show context-sensitive help.")).Action(func(a *Application, e *ParseElement, c *ParseContext) error {
		a.UsageForContext(c)
		a.terminate(0)
		return nil
	})
	a.helpFlag.Bool()
	a.Flag("completion-bash", T("Output possible completions for the given args.")).Hidden().BoolVar(&a.completion)
	a.Flag("completion-script-bash", T("Generate completion script for bash.")).Hidden().PreAction(a.generateBashCompletionScript).Bool()
	a.Flag("completion-script-zsh", T("Generate completion script for ZSH.")).Hidden().PreAction(a.generateZSHCompletionScript).Bool()

	return a
}

// Struct allows applications to define flags with struct tags.
//
// Supported struct tags are: help, placeholder, default, short, long, required, hidden, env,
// enum, and arg.
//
// The name of the flag will default to the CamelCase name transformed to camel-case. This can
// be overridden with the "long" tag.
//
// All basic Go types are supported including floats, ints, strings, time.Duration,
// and slices of same.
//
// For compatibility, also supports the tags used by https://github.com/jessevdk/go-flags
func (a *Application) Struct(v interface{}) error {
	return a.fromStruct(nil, v)
}

func (a *Application) generateBashCompletionScript(_ *Application, e *ParseElement, c *ParseContext) error {
	usageContext := &UsageContext{
		Template: BashCompletionTemplate,
	}
	a.Writers(os.Stdout, os.Stderr)
	if err := a.UsageForContextWithTemplate(usageContext, c); err != nil {
		return err
	}
	a.terminate(0)
	return nil
}

func (a *Application) generateZSHCompletionScript(_ *Application, e *ParseElement, c *ParseContext) error {
	usageContext := &UsageContext{
		Template: ZshCompletionTemplate,
	}
	a.Writers(os.Stdout, os.Stderr)
	if err := a.UsageForContextWithTemplate(usageContext, c); err != nil {
		return err
	}
	a.terminate(0)
	return nil
}

// Action is an application-wide callback. It is used in two situations: first, with a nil "element"
// parameter when parsing is complete, and second whenever a command, argument or flag is
// encountered.
func (a *Application) Action(action Action) *Application {
	a.addAction(action)
	return a
}

// PreAction is an application-wide callback. It is in two situations: first, with a nil "element"
// parameter, and second, whenever a command, argument or flag is encountered.
func (a *Application) PreAction(action Action) *Application {
	a.addPreAction(action)
	return a
}

// DefaultEnvars configures all flags (that do not already have an associated
// envar) to use a default environment variable in the form "<app>_<flag>".
//
// For example, if the application is named "foo" and a flag is named "bar-
// waz" the environment variable: "FOO_BAR_WAZ".
func (a *Application) DefaultEnvars() *Application {
	a.defaultEnvars = true
	return a
}

// EnvarSeparator sets the string that is used for separating values in environment variables.
//
// This defaults to the current OS's path list separator (typically : or ;).
func (a *Application) EnvarSeparator(sep string) *Application {
	a.envarSeparator = sep
	return a

}

// Resolver adds an ordered set of flag/argument resolvers.
//
// Resolvers provide default flag/argument values, from environment variables, configuration files, etc. Multiple
// resolvers may be added, and they are processed in order.
//
// The last Resolver to return a value always wins. Values returned from resolvers are not cumulative.
func (a *Application) Resolver(resolvers ...Resolver) *Application {
	a.resolvers = append(a.resolvers, resolvers...)
	return a
}

// Terminate specifies the termination handler. Defaults to os.Exit(status).
// If nil is passed, a no-op function will be used.
func (a *Application) Terminate(terminate func(int)) *Application {
	if terminate == nil {
		terminate = func(int) {}
	}
	a.terminate = terminate
	return a
}

// Writers specifies the writers to use for usage and errors. Defaults to os.Stderr.
func (a *Application) Writers(out, err io.Writer) *Application {
	a.output = out
	a.errors = err
	return a
}

// UsageTemplate specifies the text template to use when displaying usage
// information via --help. The default is DefaultUsageTemplate.
func (a *Application) UsageTemplate(template string) *Application {
	a.defaultUsage.Template = template
	return a
}

// UsageContext specifies the UsageContext to use when displaying usage
// information via --help.
func (a *Application) UsageContext(context *UsageContext) *Application {
	a.defaultUsage = context
	return a
}

// ParseContext parses the given command line and returns the fully populated
// ParseContext.
func (a *Application) ParseContext(args []string) (*ParseContext, error) {
	return a.parseContext(false, args)
}

func (a *Application) parseContext(ignoreDefault bool, args []string) (*ParseContext, error) {
	if err := a.init(); err != nil {
		return nil, err
	}
	context := tokenize(args, ignoreDefault, a.buildResolvers())
	err := parse(context, a)
	return context, err
}

// Build resolvers to emulate the envar and defaults behaviour that was previously hard-coded.
func (a *Application) buildResolvers() []Resolver {

	// .Default() has lowest priority...
	resolvers := []Resolver{defaultsResolver()}
	// Then custom resolvers...
	resolvers = append(resolvers, a.resolvers...)
	// Finally, envars are highest priority behind direct flag parsing.
	if a.defaultEnvars {
		resolvers = append(resolvers, PrefixedEnvarResolver(a.Name+"_", a.envarSeparator))
	}
	resolvers = append(resolvers, envarResolver(a.envarSeparator))

	return resolvers
}

// Parse parses command-line arguments. It returns the selected command and an
// error. The selected command will be a space separated subcommand, if
// subcommands have been configured.
//
// This will populate all flag and argument values, call all callbacks, and so
// on.
func (a *Application) Parse(args []string) (command string, err error) {
	context, parseErr := a.ParseContext(args)
	if context == nil {
		// Since we do not throw error immediately, there could be a case
		// where a context returns nil. Protect against that.
		return "", parseErr
	}

	if err = a.setDefaults(context); err != nil {
		return "", err
	}

	selected, setValuesErr := a.setValues(context)

	if err = a.applyPreActions(context, !a.completion); err != nil {
		return "", err
	}

	if a.completion {
		a.generateBashCompletion(context)
		a.terminate(0)
	} else {
		if parseErr != nil {
			return "", parseErr
		}

		a.maybeHelp(context)
		if !context.EOL() {
			return "", TError("unexpected argument '{{.Arg0}}'", V{"Arg0": context.Peek()})
		}

		if setValuesErr != nil {
			return "", setValuesErr
		}

		command, err = a.execute(context, selected)
		if err == errCommandNotSpecified {
			a.writeUsage(context, nil)
		}
	}
	return command, err
}

func (a *Application) writeUsage(context *ParseContext, err error) {
	if err != nil {
		a.Errorf("%s", err)
	}
	if err := a.UsageForContext(context); err != nil {
		panic(err)
	}
	a.terminate(1)
}

func (a *Application) maybeHelp(context *ParseContext) {
	for _, element := range context.Elements {
		if element.OneOf.Flag == a.helpFlag {
			// Re-parse the command-line ignoring defaults, so that help works correctly.
			context, _ = a.parseContext(true, context.rawArgs)
			a.writeUsage(context, nil)
		}
	}
}

// Version adds a --version flag for displaying the application version.
func (a *Application) Version(version string) *Application {
	a.version = version
	a.Flag("version", T("Show application version.")).
		PreAction(func(*Application, *ParseElement, *ParseContext) error {
			fmt.Fprintln(a.output, version)
			a.terminate(0)
			return nil
		}).
		Bool()
	return a
}

// Author sets the author name for usage templates.
func (a *Application) Author(author string) *Application {
	a.author = author
	return a
}

// Command adds a new top-level command.
func (a *Application) Command(name, help string) *CmdClause {
	return a.addCommand(name, help)
}

// Interspersed control if flags can be interspersed with positional arguments
//
// true (the default) means that they can, false means that all the flags must appear before the first positional arguments.
func (a *Application) Interspersed(interspersed bool) *Application {
	a.noInterspersed = !interspersed
	return a
}

func (a *Application) init() error {
	if a.initialized {
		return nil
	}
	if err := a.checkArgCommandMixing(); err != nil {
		return err
	}

	// If we have subcommands, add a help command at the top-level.
	if a.cmdGroup.have() {
		var command []string
		a.helpCommand = a.Command("help", T("Show help.")).
			PreAction(func(_ *Application, element *ParseElement, context *ParseContext) error {
				a.Usage(command)
				command = []string{}
				a.terminate(0)
				return nil
			})
		a.helpCommand.
			Arg("command", T("Show help on command.")).
			StringsVar(&command)
		// Make help first command.
		l := len(a.commandOrder)
		a.commandOrder = append(a.commandOrder[l-1:l], a.commandOrder[:l-1]...)
	}

	if err := a.flagGroup.init(); err != nil {
		return err
	}
	if err := a.cmdGroup.init(); err != nil {
		return err
	}
	if err := a.argGroup.init(); err != nil {
		return err
	}
	for _, cmd := range a.commands {
		if err := cmd.init(); err != nil {
			return err
		}
	}
	flagGroups := []*flagGroup{a.flagGroup}
	for _, cmd := range a.commandOrder {
		if err := checkDuplicateFlags(cmd, flagGroups); err != nil {
			return err
		}
	}
	a.initialized = true
	return nil
}

// Recursively check commands for duplicate flags.
func checkDuplicateFlags(current *CmdClause, flagGroups []*flagGroup) error {
	// Check for duplicates.
	for _, flags := range flagGroups {
		for _, flag := range current.flagOrder {
			if flag.shorthand != 0 {
				if _, ok := flags.short[string(flag.shorthand)]; ok {
					return TError("duplicate short flag -{{.Arg0}}", V{"Arg0": flag.shorthand})
				}
			}
			if _, ok := flags.long[flag.name]; ok {
				return TError("duplicate long flag --{{.Arg0}}", V{"Arg0": flag.name})
			}
		}
	}
	flagGroups = append(flagGroups, current.flagGroup)
	// Check subcommands.
	for _, subcmd := range current.commandOrder {
		if err := checkDuplicateFlags(subcmd, flagGroups); err != nil {
			return err
		}
	}
	return nil
}

func (a *Application) execute(context *ParseContext, selected []string) (string, error) {
	var err error

	if err = a.validateRequired(context); err != nil {
		return "", err
	}

	if err = a.applyActions(context); err != nil {
		return "", err
	}

	command := strings.Join(selected, " ")
	if command == "" && a.cmdGroup.have() {
		return "", errCommandNotSpecified
	}
	return command, err
}

func (a *Application) setDefaults(context *ParseContext) error {
	flagElements := context.Elements.FlagMap()
	argElements := context.Elements.ArgMap()

	// Check required flags and set defaults.
	for _, flag := range context.flags.long {
		if flagElements[flag.name] == nil {
			if err := flag.setDefault(context); err != nil {
				return err
			}
		} else {
			flag.reset()
		}
	}

	for _, arg := range context.arguments.args {
		if argElements[arg.name] == nil {
			if err := arg.setDefault(context); err != nil {
				return err
			}
		} else {
			arg.reset()
		}
	}

	return nil
}

func (a *Application) validateRequired(context *ParseContext) error {
	flagElements := context.Elements.FlagMap()
	argElements := context.Elements.ArgMap()

	// Check required flags and set defaults.
	for _, flag := range context.flags.long {
		if flagElements[flag.name] == nil {
			// Check required flags were provided.
			if flag.needsValue(context) {
				return TError("required flag --{{.Arg0}} not provided", V{"Arg0": flag.name})
			}
		}
	}

	for _, arg := range context.arguments.args {
		if argElements[arg.name] == nil {
			if arg.needsValue(context) {
				return TError("required argument '{{.Arg0}}' not provided", V{"Arg0": arg.name})
			}
		}
	}
	return nil
}

func (a *Application) setValues(context *ParseContext) (selected []string, err error) {
	// Set all arg and flag values.
	var (
		lastCmd *CmdClause
		flagSet = map[string]struct{}{}
	)
	for _, element := range context.Elements {
		switch {
		case element.OneOf.Flag != nil:
			clause := element.OneOf.Flag
			if _, ok := flagSet[clause.name]; ok {
				if v, ok := clause.value.(cumulativeValue); !ok || !v.IsCumulative() {
					return nil, TError("flag '{{.Arg0}}' cannot be repeated", V{"Arg0": clause.name})
				}
			}
			if err = clause.value.Set(*element.Value); err != nil {
				return
			}
			flagSet[clause.name] = struct{}{}

		case element.OneOf.Arg != nil:
			clause := element.OneOf.Arg
			if err = clause.value.Set(*element.Value); err != nil {
				return
			}

		case element.OneOf.Cmd != nil:
			clause := element.OneOf.Cmd
			if clause.validator != nil {
				if err = clause.validator(clause); err != nil {
					return
				}
			}
			selected = append(selected, clause.name)
			lastCmd = clause
		}
	}

	if lastCmd == nil || lastCmd.optionalSubcommands {
		return
	}
	if len(lastCmd.commands) > 0 {
		return nil, TError("must select a subcommand of '{{.Arg0}}'", V{"Arg0": lastCmd.FullCommand()})
	}

	return
}

// Errorf prints an error message to w in the format "<appname>: error: <message>".
func (a *Application) Errorf(format string, args ...interface{}) {
	fmt.Fprintf(a.errors, a.Name+T(": error: ")+format+"\n", args...)
}

// Fatalf writes a formatted error to w then terminates with exit status 1.
func (a *Application) Fatalf(format string, args ...interface{}) {
	a.Errorf(format, args...)
	a.terminate(1)
}

// FatalUsage prints an error message followed by usage information, then
// exits with a non-zero status.
func (a *Application) FatalUsage(format string, args ...interface{}) {
	a.Errorf(format, args...)
	a.Usage([]string{})
	a.terminate(1)
}

// FatalUsageContext writes a printf formatted error message to w, then usage
// information for the given ParseContext, before exiting.
func (a *Application) FatalUsageContext(context *ParseContext, format string, args ...interface{}) {
	a.Errorf(format, args...)
	if err := a.UsageForContext(context); err != nil {
		panic(err)
	}
	a.terminate(1)
}

// FatalIfError prints an error and exits if err is not nil. The error is printed
// with the given formatted string, if any.
func (a *Application) FatalIfError(err error, format string, args ...interface{}) {
	if err != nil {
		prefix := ""
		if format != "" {
			prefix = fmt.Sprintf(format, args...) + ": "
		}
		a.Errorf(prefix+"%s", err)
		a.terminate(1)
	}
}

func (a *Application) completionOptions(context *ParseContext) []string {
	args := context.rawArgs

	var (
		currArg string
		prevArg string
		target  cmdMixin
	)

	numArgs := len(args)
	if numArgs > 1 {
		args = args[1:]
		currArg = args[len(args)-1]
	}
	if numArgs > 2 {
		prevArg = args[len(args)-2]
	}

	target = a.cmdMixin
	if context.SelectedCommand != nil {
		// A subcommand was in use. We will use it as the target
		target = context.SelectedCommand.cmdMixin
	}

	if (currArg != "" && strings.HasPrefix(currArg, "--")) || strings.HasPrefix(prevArg, "--") {
		// Perform completion for A flag. The last/current argument started with "-"
		var (
			flagName  string // The name of a flag if given (could be half complete)
			flagValue string // The value assigned to a flag (if given) (could be half complete)
		)

		if strings.HasPrefix(prevArg, "--") && !strings.HasPrefix(currArg, "--") {
			// Matches: 	./myApp --flag value
			// Wont Match: 	./myApp --flag --
			flagName = prevArg[2:] // Strip the "--"
			flagValue = currArg
		} else if strings.HasPrefix(currArg, "--") {
			// Matches: 	./myApp --flag --
			// Matches:		./myApp --flag somevalue --
			// Matches: 	./myApp --
			flagName = currArg[2:] // Strip the "--"
		}

		options, flagMatched, valueMatched := target.FlagCompletion(flagName, flagValue)
		if valueMatched {
			// Value Matched. Show cmdCompletions
			return target.CmdCompletion(context)
		}

		// Add top level flags if we're not at the top level and no match was found.
		if context.SelectedCommand != nil && !flagMatched {
			topOptions, topFlagMatched, topValueMatched := a.FlagCompletion(flagName, flagValue)
			if topValueMatched {
				// Value Matched. Back to cmdCompletions
				return target.CmdCompletion(context)
			}

			if topFlagMatched {
				// Top level had a flag which matched the input. Return it's options.
				options = topOptions
			} else {
				// Add top level flags
				options = append(options, topOptions...)
			}
		}
		return options
	}

	// Perform completion for sub commands and arguments.
	return target.CmdCompletion(context)
}

func (a *Application) generateBashCompletion(context *ParseContext) {
	options := a.completionOptions(context)
	fmt.Printf("%s", strings.Join(options, "\n"))
}

func (a *Application) applyPreActions(context *ParseContext, dispatch bool) error {
	if !dispatch {
		return nil
	}
	if err := a.actionMixin.applyPreActions(a, nil, context); err != nil {
		return err
	}
	for _, element := range context.Elements {
		if err := a.actionMixin.applyPreActions(a, element, context); err != nil {
			return err
		}
		var applier actionApplier
		switch {
		case element.OneOf.Arg != nil:
			applier = element.OneOf.Arg
		case element.OneOf.Flag != nil:
			applier = element.OneOf.Flag
		case element.OneOf.Cmd != nil:
			applier = element.OneOf.Cmd
		}
		if err := applier.applyPreActions(a, element, context); err != nil {
			return err
		}
	}
	return nil
}

func (a *Application) applyActions(context *ParseContext) error {
	if err := a.actionMixin.applyActions(a, nil, context); err != nil {
		return err
	}
	// Dispatch to actions.
	for _, element := range context.Elements {
		if err := a.actionMixin.applyActions(a, element, context); err != nil {
			return err
		}
		var applier actionApplier
		switch {
		case element.OneOf.Arg != nil:
			applier = element.OneOf.Arg
		case element.OneOf.Flag != nil:
			applier = element.OneOf.Flag
		case element.OneOf.Cmd != nil:
			applier = element.OneOf.Cmd
		}
		if err := applier.applyActions(a, element, context); err != nil {
			return err
		}
	}
	return nil
}

"""



```