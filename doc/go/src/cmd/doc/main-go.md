Response:
Let's break down the thought process for analyzing this Go code snippet for `go doc`.

1. **Understand the Core Functionality:** The initial comment block is key. It clearly states the purpose: `go doc` shows documentation. It then lists the different argument patterns the command accepts (zero, one, or two arguments) and describes what each pattern does. This is the absolute starting point for understanding.

2. **Identify Key Flags:**  The `var` block after the imports defines several boolean and string variables. The comments clearly indicate these are command-line flags (`-u`, `-c`, `-C`, etc.). Recognizing these flags is crucial because they modify the behavior of `go doc`.

3. **Trace the `main` Function:** The `main` function is the entry point. It's relatively simple:
    * Initializes logging.
    * Calls `dirsInit()`. Although the code for this isn't provided, the name suggests it initializes directory-related information needed for finding packages.
    * Calls the core logic function `do()`, passing standard input/output and command-line arguments.
    * Handles any errors returned by `do()`.

4. **Analyze the `do` Function (The Heart of the Logic):**  This is where the real work happens. Go through it step by step:
    * **Flag Handling:**  It sets the `Usage` function, resets the flag variables, defines the flags using `flagSet.StringVar` and `flagSet.BoolVar`, and parses the arguments with `flagSet.Parse(args)`. This confirms the earlier observation about the flags.
    * **Directory Change (`-C`):** It checks for the `-C` flag and changes the working directory if provided.
    * **Argument Parsing Loop:**  The `for` loop is central. It repeatedly calls `parseArgs`. The `more` return value suggests a mechanism for finding symbols across multiple potential packages.
    * **Special Handling for "builtin":**  The code explicitly handles the `builtin` package, setting `unexported` to `true`.
    * **Symbol and Method Parsing:**  `parseSymbol` is called to separate the symbol name from a potential method name.
    * **Package Processing:**  `parsePackage` is called. Again, the implementation of `parsePackage` isn't here, but its name clearly indicates its role.
    * **Documentation Display Logic:** The `switch` statement based on whether `symbol` and `method` are empty dictates which documentation to display: package-level, symbol-level, method-level, or field-level.
    * **Error Handling with `recover`:** The `defer func()` block uses `recover` to catch `PackageError` (presumably a custom error type) and handle it. Other panics are re-panicked.

5. **Examine Helper Functions:**
    * **`usage()`:**  Prints the usage instructions.
    * **`failMessage()`:** Creates an error message when no documentation is found.
    * **`parseArgs()`:**  This function is crucial for understanding how `go doc` interprets the arguments. It handles various cases: zero, one, or two arguments, absolute paths, relative paths, symbols, and package/symbol combinations. It uses `build.Import` and `build.ImportDir` to find packages. The logic for handling uppercase first letters for symbols in the current directory is interesting.
    * **`isDotSlash()`:** Checks for "./" or "../" prefixes.
    * **`importDir()`:**  A simple wrapper for `build.ImportDir`.
    * **`parseSymbol()`:**  Splits the symbol string into symbol and method parts.
    * **`isExported()`:**  Determines if a symbol is exported, respecting the `-u` flag.
    * **`findNextPackage()`:**  Used when a partial package path is given, allowing `go doc` to search for matching packages.
    * **`splitGopath()`:** Splits the `GOPATH` environment variable.

6. **Infer Go Language Features:** Based on the code:
    * **Reflection (Implicit):** Although not explicitly used with `reflect` package, the ability to retrieve documentation for arbitrary symbols and methods suggests an underlying mechanism that likely involves reflection or similar introspection capabilities within the `go/doc` or `go/types` packages (not shown here).
    * **Package Management:** The heavy reliance on `go/build` indicates strong ties to Go's package management system for finding and loading package information.
    * **Command-Line Argument Parsing:** The `flag` package is used for handling command-line arguments.
    * **Error Handling:** Standard Go error handling (`error` interface) and `log` package are used.
    * **String Manipulation:** The `strings` package is used extensively for parsing arguments and manipulating paths.
    * **File System Operations:**  `os` and `path/filepath` are used for interacting with the file system (changing directories, finding packages).

7. **Develop Example Scenarios (Input/Output):**  Based on the identified functionality and flags, create examples to illustrate different use cases. Think about the different argument patterns and the effect of the flags.

8. **Identify Potential User Errors:** Consider common mistakes users might make when using `go doc`. For example, case sensitivity without the `-c` flag, ambiguity in package/symbol names, and incorrect package paths.

9. **Structure the Output:** Organize the analysis into clear sections (functionality, Go features, examples, command-line arguments, common errors) for better readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe the code directly parses Go source files. **Correction:** The use of `go/build` strongly suggests it leverages Go's built-in tooling for understanding package structure, rather than directly parsing source.
* **Focus on `do`:** Realized that the `do` function is the core logic and requires detailed examination.
* **Importance of `parseArgs`:**  Understood that `parseArgs` is the key to how `go doc` interprets user input and decides what to look for.
* **Connecting Flags to Behavior:**  Actively linked each flag to the specific code that handles it within the `do` function.
* **Realizing the Limits:** Recognized that without the implementations of `parsePackage` and `dirsInit`, some aspects are based on inference.

By following this structured approach, breaking down the code into smaller, manageable parts, and making logical connections, we can effectively understand the functionality of this Go code snippet.
这段代码是 Go 语言 `go doc` 工具的主要逻辑实现，用于显示 Go 包、符号（如函数、类型、变量）及其方法或字段的文档。

**功能列举:**

1. **显示当前目录的包文档:** 当不带任何参数运行时 (`go doc`)，显示当前工作目录下 Go 包的文档。
2. **显示指定包的文档:** 当带一个参数时 (`go doc <pkg>`)，显示指定包路径的文档。
3. **显示指定符号的文档:** 当带一个参数时 (`go doc <sym>`)，在当前目录的包中查找并显示该符号的文档。如果符号以大写字母开头，则始终假定为当前目录的符号。
4. **显示指定包中指定符号的文档:** 当带一个参数时 (`go doc [<pkg>.]<sym>`)，显示指定包中指定符号的文档。
5. **显示指定包中指定符号的特定方法或字段的文档:** 当带一个参数时 (`go doc [<pkg>.][<sym>.]<methodOrField>`)，显示指定包中指定符号的特定方法或字段的文档。
6. **显示指定包中指定符号的特定方法或字段的文档 (两参数形式):** 当带两个参数时 (`go doc <pkg> <sym>[.<methodOrField>]`)，第一个参数必须是完整的包路径，显示该包中指定符号的特定方法或字段的文档。
7. **处理命令包:** 默认情况下，对于命令包 (`main` 包)，`go doc command` 只显示包级别的文档。可以使用 `-cmd` 标志来显示命令包中的符号文档。
8. **显示符号的源代码:** 使用 `-src` 标志可以显示指定符号的完整源代码，例如结构体、函数或方法的代码体。
9. **显示包的所有文档:** 使用 `-all` 标志可以显示指定包及其所有可见符号的全部文档。
10. **更改工作目录:** 使用 `-C` 标志可以在运行 `go doc` 之前切换到指定的目录。
11. **显示未导出符号:** 使用 `-u` 标志可以显示未导出的符号以及导出的符号。
12. **区分大小写匹配:** 使用 `-c` 标志可以使符号匹配区分大小写（对路径没有影响）。
13. **显示符号的单行表示:** 使用 `-short` 标志可以显示每个符号的单行表示。

**实现的 Go 语言功能推理及代码示例:**

这段代码主要利用了 Go 语言的以下功能：

* **`go/build` 包:** 用于查找、导入和加载 Go 包的信息。例如，`build.Import` 和 `build.ImportDir` 函数被用来根据用户提供的参数定位到对应的 Go 包。
* **`go/token` 包:** 用于处理 Go 语言的词法单元，例如判断标识符是否已导出（`token.IsExported`）。
* **`flag` 包:** 用于处理命令行参数，例如定义和解析 `-u`, `-c`, `-C`, `-all`, `-cmd`, `-src`, `-short` 等标志。
* **`strings` 包:** 用于字符串操作，例如分割字符串 (`strings.Split`)，检查前缀 (`strings.HasPrefix`)，查找子串 (`strings.Index`, `strings.LastIndex`) 等，主要用于解析用户输入的参数。
* **`fmt` 包:** 用于格式化输出，例如打印帮助信息和文档内容。
* **`os` 包:** 用于与操作系统交互，例如获取当前工作目录 (`os.Getwd`)，切换目录 (`os.Chdir`)，以及访问命令行参数 (`os.Args`)。
* **`io` 包:** 用于处理输入输出流，例如将文档内容写入 `os.Stdout`。
* **`log` 包:** 用于记录日志信息和错误。
* **错误处理:** 使用 `error` 接口来表示和传递错误。

**Go 代码示例 (推理解释 `parseArgs` 函数的功能):**

`parseArgs` 函数负责解析用户提供的命令行参数，确定要显示文档的包和符号。

**假设输入:** `go doc encoding/json Marshal`

**代码推理:**

1. `parseArgs` 函数接收 `["encoding/json", "Marshal"]` 作为 `args`。
2. `len(args)` 为 2，进入 `case 2` 分支。
3. 尝试使用 `build.Import("encoding/json", wd, build.ImportComment)` 导入 `encoding/json` 包。
4. 如果导入成功，则返回 `pkg` (表示 `encoding/json` 包的信息), `"encoding/json"` (用户提供的包路径), `"Marshal"` (用户提供的符号), `false` (表示不需要进一步查找其他可能的包)。

**假设输出:** (假设导入成功) `pkg` (表示 `encoding/json` 包的 `build.Package` 结构体), `"encoding/json"`, `"Marshal"`, `false`

**Go 代码示例 (推理解释 `-src` 标志的功能):**

当用户使用 `-src` 标志时，`showSrc` 变量会被设置为 `true`。在 `do` 函数的后续处理中（代码片段中未完全展示），会根据 `showSrc` 的值来决定是打印文档还是打印源代码。

```go
// 假设在 `pkg` 结构体中有一个方法可以打印源代码
func (p *Package) printSymbolSource(symbol string) bool {
	// ... 查找符号的定义 ...
	if found {
		fmt.Fprintln(p.w, "// Source code for", symbol)
		fmt.Fprintln(p.w, sourceCode) // 实际的源代码
		return true
	}
	return false
}

// 在 `do` 函数中 (简化)
func do(writer io.Writer, flagSet *flag.FlagSet, args []string) error {
	// ...
	flagSet.BoolVar(&showSrc, "src", false, "show source code for symbol")
	flagSet.Parse(args)
	// ...

	switch {
	case symbol == "":
		pkg.packageDoc()
		return
	case method == "":
		if showSrc {
			if pkg.printSymbolSource(symbol) {
				return nil
			}
		} else if pkg.symbolDoc(symbol) {
			return nil
		}
	// ...
	}
	return nil
}
```

**假设输入:** `go doc -src fmt Println`

**代码推理:**

1. `flagSet.Parse` 会将 `showSrc` 设置为 `true`。
2. `parseArgs` 会解析出包 `fmt` 和符号 `Println`。
3. 进入 `do` 函数的 `switch` 语句。
4. 因为 `method` 为空，且 `showSrc` 为 `true`，所以会调用 `pkg.printSymbolSource("Println")`。
5. `printSymbolSource` 方法会查找 `fmt.Println` 的源代码并打印到 `writer` (这里是 `os.Stdout`)。

**假设输出:**

```
// Source code for Println
func Println(a ...interface{}) (n int, err error) {
	return Fprintln(os.Stdout, a...)
}
```

**命令行参数的具体处理:**

* **`-u` (unexported):**  布尔值。如果设置，`isExported` 函数会始终返回 `true`，从而显示未导出的符号。
* **`-c` (matchCase):** 布尔值。如果设置，符号匹配时会区分大小写。这会影响 `parseSymbol` 和后续的符号查找逻辑。
* **`-C` (chdir):** 字符串。指定一个目录路径。在 `do` 函数开始时，如果此参数不为空，程序会使用 `os.Chdir` 切换到该目录。
* **`-all`:** 布尔值。如果设置，`go doc` 会显示指定包的所有文档，包括包级别的文档和所有可见符号的文档。这会影响 `do` 函数中调用 `pkg.packageDoc()` 和符号文档打印的逻辑。
* **`-cmd`:** 布尔值。对于命令包，默认只显示包级别的文档。设置此标志后，也会显示命令包中的符号文档。这会影响 `do` 函数中处理命令包的逻辑。
* **`-src`:** 布尔值。如果设置，`go doc` 会尝试打印指定符号的源代码而不是文档。这会修改 `do` 函数中调用的打印函数。
* **`-short`:** 布尔值。如果设置，会使用更简洁的单行格式显示每个符号的信息，这会影响文档的格式化输出部分。

**使用者易犯错的点:**

1. **大小写敏感性:** 在没有使用 `-c` 标志的情况下，符号匹配通常是不区分大小写的。用户可能会因为大小写问题而找不到预期的符号文档。
   * **例如:** 如果一个包中有一个函数名为 `readFile`，用户使用 `go doc ReadFile` 可能无法找到文档，除非加上 `-c` 标志或者使用正确的 `go doc readFile`。

2. **不明确的符号或包名:** 当只有一个参数时，`go doc` 需要根据一定的规则来判断是包名还是符号名。如果当前目录存在一个与标准库或其他导入路径相同的包名，可能会导致混淆。
   * **例如:** 如果当前目录下有一个名为 `fmt` 的包，执行 `go doc fmt.Println` 可能会引发歧义，`go doc` 可能会优先查找当前目录下的 `fmt` 包。为了避免歧义，可以使用完整的导入路径，例如 `go doc 标准库名/fmt.Println`。

3. **对命令包的理解:** 默认情况下，`go doc command` 只显示包级别的文档，这可能会让用户误以为无法查看命令包中函数的文档。需要使用 `-cmd` 标志才能查看命令包中的符号文档。
   * **例如:** 执行 `go doc os` 可能只会显示 `os` 包的概要信息，而不会显示 `os.OpenFile` 的文档，除非使用 `go doc -cmd os OpenFile` 或将 `os` 包作为普通库包引用。

4. **路径的理解:**  当指定包名时，需要理解 Go 的包路径规则。相对路径和绝对路径的处理方式不同。
   * **例如:**  如果当前目录是 `$GOPATH/src/mypkg`，执行 `go doc .` 和 `go doc mypkg` 的效果是相同的。但是，如果执行 `go doc ./subpkg` 则需要确保 `subpkg` 是 `mypkg` 的子目录。

这段代码的核心在于解析用户输入，利用 `go/build` 包找到对应的 Go 包信息，并根据不同的标志和参数选择性地输出包、符号或源代码的文档。理解其参数解析逻辑和与 `go/build` 包的交互是理解其功能的关键。

### 提示词
```
这是路径为go/src/cmd/doc/main.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Doc (usually run as go doc) accepts zero, one or two arguments.
//
// Zero arguments:
//
//	go doc
//
// Show the documentation for the package in the current directory.
//
// One argument:
//
//	go doc <pkg>
//	go doc <sym>[.<methodOrField>]
//	go doc [<pkg>.]<sym>[.<methodOrField>]
//	go doc [<pkg>.][<sym>.]<methodOrField>
//
// The first item in this list that succeeds is the one whose documentation
// is printed. If there is a symbol but no package, the package in the current
// directory is chosen. However, if the argument begins with a capital
// letter it is always assumed to be a symbol in the current directory.
//
// Two arguments:
//
//	go doc <pkg> <sym>[.<methodOrField>]
//
// Show the documentation for the package, symbol, and method or field. The
// first argument must be a full package path. This is similar to the
// command-line usage for the godoc command.
//
// For commands, unless the -cmd flag is present "go doc command"
// shows only the package-level docs for the package.
//
// The -src flag causes doc to print the full source code for the symbol, such
// as the body of a struct, function or method.
//
// The -all flag causes doc to print all documentation for the package and
// all its visible symbols. The argument must identify a package.
//
// For complete documentation, run "go help doc".
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/build"
	"go/token"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"cmd/internal/telemetry/counter"
)

var (
	unexported bool   // -u flag
	matchCase  bool   // -c flag
	chdir      string // -C flag
	showAll    bool   // -all flag
	showCmd    bool   // -cmd flag
	showSrc    bool   // -src flag
	short      bool   // -short flag
)

// usage is a replacement usage function for the flags package.
func usage() {
	fmt.Fprintf(os.Stderr, "Usage of [go] doc:\n")
	fmt.Fprintf(os.Stderr, "\tgo doc\n")
	fmt.Fprintf(os.Stderr, "\tgo doc <pkg>\n")
	fmt.Fprintf(os.Stderr, "\tgo doc <sym>[.<methodOrField>]\n")
	fmt.Fprintf(os.Stderr, "\tgo doc [<pkg>.]<sym>[.<methodOrField>]\n")
	fmt.Fprintf(os.Stderr, "\tgo doc [<pkg>.][<sym>.]<methodOrField>\n")
	fmt.Fprintf(os.Stderr, "\tgo doc <pkg> <sym>[.<methodOrField>]\n")
	fmt.Fprintf(os.Stderr, "For more information run\n")
	fmt.Fprintf(os.Stderr, "\tgo help doc\n\n")
	fmt.Fprintf(os.Stderr, "Flags:\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("doc: ")
	counter.Open()
	dirsInit()
	err := do(os.Stdout, flag.CommandLine, os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}
}

// do is the workhorse, broken out of main to make testing easier.
func do(writer io.Writer, flagSet *flag.FlagSet, args []string) (err error) {
	flagSet.Usage = usage
	unexported = false
	matchCase = false
	flagSet.StringVar(&chdir, "C", "", "change to `dir` before running command")
	flagSet.BoolVar(&unexported, "u", false, "show unexported symbols as well as exported")
	flagSet.BoolVar(&matchCase, "c", false, "symbol matching honors case (paths not affected)")
	flagSet.BoolVar(&showAll, "all", false, "show all documentation for package")
	flagSet.BoolVar(&showCmd, "cmd", false, "show symbols with package docs even if package is a command")
	flagSet.BoolVar(&showSrc, "src", false, "show source code for symbol")
	flagSet.BoolVar(&short, "short", false, "one-line representation for each symbol")
	flagSet.Parse(args)
	counter.Inc("doc/invocations")
	counter.CountFlags("doc/flag:", *flag.CommandLine)
	if chdir != "" {
		if err := os.Chdir(chdir); err != nil {
			return err
		}
	}
	var paths []string
	var symbol, method string
	// Loop until something is printed.
	dirs.Reset()
	for i := 0; ; i++ {
		buildPackage, userPath, sym, more := parseArgs(flagSet.Args())
		if i > 0 && !more { // Ignore the "more" bit on the first iteration.
			return failMessage(paths, symbol, method)
		}
		if buildPackage == nil {
			return fmt.Errorf("no such package: %s", userPath)
		}

		// The builtin package needs special treatment: its symbols are lower
		// case but we want to see them, always.
		if buildPackage.ImportPath == "builtin" {
			unexported = true
		}

		symbol, method = parseSymbol(sym)
		pkg := parsePackage(writer, buildPackage, userPath)
		paths = append(paths, pkg.prettyPath())

		defer func() {
			pkg.flush()
			e := recover()
			if e == nil {
				return
			}
			pkgError, ok := e.(PackageError)
			if ok {
				err = pkgError
				return
			}
			panic(e)
		}()

		switch {
		case symbol == "":
			pkg.packageDoc() // The package exists, so we got some output.
			return
		case method == "":
			if pkg.symbolDoc(symbol) {
				return
			}
		case pkg.printMethodDoc(symbol, method):
			return
		case pkg.printFieldDoc(symbol, method):
			return
		}
	}
}

// failMessage creates a nicely formatted error message when there is no result to show.
func failMessage(paths []string, symbol, method string) error {
	var b bytes.Buffer
	if len(paths) > 1 {
		b.WriteString("s")
	}
	b.WriteString(" ")
	for i, path := range paths {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(path)
	}
	if method == "" {
		return fmt.Errorf("no symbol %s in package%s", symbol, &b)
	}
	return fmt.Errorf("no method or field %s.%s in package%s", symbol, method, &b)
}

// parseArgs analyzes the arguments (if any) and returns the package
// it represents, the part of the argument the user used to identify
// the path (or "" if it's the current package) and the symbol
// (possibly with a .method) within that package.
// parseSymbol is used to analyze the symbol itself.
// The boolean final argument reports whether it is possible that
// there may be more directories worth looking at. It will only
// be true if the package path is a partial match for some directory
// and there may be more matches. For example, if the argument
// is rand.Float64, we must scan both crypto/rand and math/rand
// to find the symbol, and the first call will return crypto/rand, true.
func parseArgs(args []string) (pkg *build.Package, path, symbol string, more bool) {
	wd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	if len(args) == 0 {
		// Easy: current directory.
		return importDir(wd), "", "", false
	}
	arg := args[0]
	// We have an argument. If it is a directory name beginning with . or ..,
	// use the absolute path name. This discriminates "./errors" from "errors"
	// if the current directory contains a non-standard errors package.
	if isDotSlash(arg) {
		arg = filepath.Join(wd, arg)
	}
	switch len(args) {
	default:
		usage()
	case 1:
		// Done below.
	case 2:
		// Package must be findable and importable.
		pkg, err := build.Import(args[0], wd, build.ImportComment)
		if err == nil {
			return pkg, args[0], args[1], false
		}
		for {
			packagePath, ok := findNextPackage(arg)
			if !ok {
				break
			}
			if pkg, err := build.ImportDir(packagePath, build.ImportComment); err == nil {
				return pkg, arg, args[1], true
			}
		}
		return nil, args[0], args[1], false
	}
	// Usual case: one argument.
	// If it contains slashes, it begins with either a package path
	// or an absolute directory.
	// First, is it a complete package path as it is? If so, we are done.
	// This avoids confusion over package paths that have other
	// package paths as their prefix.
	var importErr error
	if filepath.IsAbs(arg) {
		pkg, importErr = build.ImportDir(arg, build.ImportComment)
		if importErr == nil {
			return pkg, arg, "", false
		}
	} else {
		pkg, importErr = build.Import(arg, wd, build.ImportComment)
		if importErr == nil {
			return pkg, arg, "", false
		}
	}
	// Another disambiguator: If the argument starts with an upper
	// case letter, it can only be a symbol in the current directory.
	// Kills the problem caused by case-insensitive file systems
	// matching an upper case name as a package name.
	if !strings.ContainsAny(arg, `/\`) && token.IsExported(arg) {
		pkg, err := build.ImportDir(".", build.ImportComment)
		if err == nil {
			return pkg, "", arg, false
		}
	}
	// If it has a slash, it must be a package path but there is a symbol.
	// It's the last package path we care about.
	slash := strings.LastIndex(arg, "/")
	// There may be periods in the package path before or after the slash
	// and between a symbol and method.
	// Split the string at various periods to see what we find.
	// In general there may be ambiguities but this should almost always
	// work.
	var period int
	// slash+1: if there's no slash, the value is -1 and start is 0; otherwise
	// start is the byte after the slash.
	for start := slash + 1; start < len(arg); start = period + 1 {
		period = strings.Index(arg[start:], ".")
		symbol := ""
		if period < 0 {
			period = len(arg)
		} else {
			period += start
			symbol = arg[period+1:]
		}
		// Have we identified a package already?
		pkg, err := build.Import(arg[0:period], wd, build.ImportComment)
		if err == nil {
			return pkg, arg[0:period], symbol, false
		}
		// See if we have the basename or tail of a package, as in json for encoding/json
		// or ivy/value for robpike.io/ivy/value.
		pkgName := arg[:period]
		for {
			path, ok := findNextPackage(pkgName)
			if !ok {
				break
			}
			if pkg, err = build.ImportDir(path, build.ImportComment); err == nil {
				return pkg, arg[0:period], symbol, true
			}
		}
		dirs.Reset() // Next iteration of for loop must scan all the directories again.
	}
	// If it has a slash, we've failed.
	if slash >= 0 {
		// build.Import should always include the path in its error message,
		// and we should avoid repeating it. Unfortunately, build.Import doesn't
		// return a structured error. That can't easily be fixed, since it
		// invokes 'go list' and returns the error text from the loaded package.
		// TODO(golang.org/issue/34750): load using golang.org/x/tools/go/packages
		// instead of go/build.
		importErrStr := importErr.Error()
		if strings.Contains(importErrStr, arg[:period]) {
			log.Fatal(importErrStr)
		} else {
			log.Fatalf("no such package %s: %s", arg[:period], importErrStr)
		}
	}
	// Guess it's a symbol in the current directory.
	return importDir(wd), "", arg, false
}

// dotPaths lists all the dotted paths legal on Unix-like and
// Windows-like file systems. We check them all, as the chance
// of error is minute and even on Windows people will use ./
// sometimes.
var dotPaths = []string{
	`./`,
	`../`,
	`.\`,
	`..\`,
}

// isDotSlash reports whether the path begins with a reference
// to the local . or .. directory.
func isDotSlash(arg string) bool {
	if arg == "." || arg == ".." {
		return true
	}
	for _, dotPath := range dotPaths {
		if strings.HasPrefix(arg, dotPath) {
			return true
		}
	}
	return false
}

// importDir is just an error-catching wrapper for build.ImportDir.
func importDir(dir string) *build.Package {
	pkg, err := build.ImportDir(dir, build.ImportComment)
	if err != nil {
		log.Fatal(err)
	}
	return pkg
}

// parseSymbol breaks str apart into a symbol and method.
// Both may be missing or the method may be missing.
// If present, each must be a valid Go identifier.
func parseSymbol(str string) (symbol, method string) {
	if str == "" {
		return
	}
	elem := strings.Split(str, ".")
	switch len(elem) {
	case 1:
	case 2:
		method = elem[1]
	default:
		log.Printf("too many periods in symbol specification")
		usage()
	}
	symbol = elem[0]
	return
}

// isExported reports whether the name is an exported identifier.
// If the unexported flag (-u) is true, isExported returns true because
// it means that we treat the name as if it is exported.
func isExported(name string) bool {
	return unexported || token.IsExported(name)
}

// findNextPackage returns the next full file name path that matches the
// (perhaps partial) package path pkg. The boolean reports if any match was found.
func findNextPackage(pkg string) (string, bool) {
	if filepath.IsAbs(pkg) {
		if dirs.offset == 0 {
			dirs.offset = -1
			return pkg, true
		}
		return "", false
	}
	if pkg == "" || token.IsExported(pkg) { // Upper case symbol cannot be a package name.
		return "", false
	}
	pkg = path.Clean(pkg)
	pkgSuffix := "/" + pkg
	for {
		d, ok := dirs.Next()
		if !ok {
			return "", false
		}
		if d.importPath == pkg || strings.HasSuffix(d.importPath, pkgSuffix) {
			return d.dir, true
		}
	}
}

var buildCtx = build.Default

// splitGopath splits $GOPATH into a list of roots.
func splitGopath() []string {
	return filepath.SplitList(buildCtx.GOPATH)
}
```