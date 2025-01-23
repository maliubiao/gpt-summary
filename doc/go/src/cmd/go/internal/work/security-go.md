Response: Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding - Skimming and Context:**

* **File Path:** `go/src/cmd/go/internal/work/security.go`. This immediately tells us it's part of the `go` command's internal workings, specifically related to the build process (`work` package). The `security.go` name strongly suggests it deals with preventing potentially harmful build configurations.
* **Copyright and Comments:**  The initial comments emphasize security, preventing arbitrary code execution via compiler/linker flags. Keywords like `-fplugin=`, arbitrary code execution, and the mention of `security.go` being isolated reinforce this. The comments also hint at complexities like `-Wl,foo` and `@foo` expansion.
* **Package Declaration:** `package work`. Confirms the package context.
* **Imports:**  Standard Go library imports like `fmt`, `strings`, and the internal `cmd/go` packages `cfg` and `load`. These suggest functionalities like string manipulation, formatted output, and accessing Go build configuration and loading mechanisms. `internal/lazyregexp` indicates performance optimization for regular expressions.

**2. Identifying Key Data Structures:**

* **`validCompilerFlags` and `validLinkerFlags`:** These are slices of `*lazyregexp.Regexp`. This is the core of the security mechanism. They define the *allowed* patterns for compiler and linker flags. Regular expressions are used for flexible matching.
* **`validCompilerFlagsWithNextArg` and `validLinkerFlagsWithNextArg`:** These are slices of strings listing flags that *require* an additional argument.
* **`invalidLinkerFlags`:** A slice of `*lazyregexp.Regexp` defining *disallowed* linker flags (specifically mentioning `-lto_library`).

**3. Analyzing the Core Functions:**

* **`checkCompilerFlags` and `checkLinkerFlags`:**  These functions take a list of flags and validate them against the respective `valid...` lists. They seem to be the main entry points for checking. The `checkOverrides := true` suggests environment variable overrides.
* **`checkCompilerFlagsForInternalLink`:** This function seems more restrictive, specifically for internal linking within the Go toolchain. It calls `checkFlags` and then adds an extra check for `-flto`. The `checkOverrides := false` is a key difference.
* **`checkFlags`:** This is the workhorse function. Let's break down its logic step-by-step:
    * **Environment Variable Overrides:**  It checks for `CGO_<name>_ALLOW` and `CGO_<name>_DISALLOW` to potentially override the built-in rules.
    * **Disallow Check:** It first iterates through the `disallow` regexps (if any) and immediately flags an error if a match is found.
    * **Allow Check:** If an `allow` regexp matches, the flag is considered valid, and the loop continues.
    * **Invalid Check:** It then checks against the `invalid` regexps.
    * **Valid Check:** It checks against the `valid` regexps.
    * **`-Wl,--push-state` Handling:**  This looks like a special case for handling comma-separated arguments within `-Wl,--push-state`. It splits the string and checks each sub-argument.
    * **Flags with Next Argument:** It iterates through `validNext`. If a matching flag is found:
        * It checks if there's a *next* argument and if it's considered "safe" by `load.SafeArg`.
        * It handles the `-Wl,-framework -Wl,name` pattern.
        * It handles `-I= /path` or `-I $SYSROOT` patterns.
        * If no valid next argument is found, it reports an error.
    * **Default Bad Case:** If none of the above conditions are met, the flag is considered invalid.

**4. Inferring Go Feature Implementation:**

The code is clearly implementing **security checks for CGO flags**. CGO allows Go programs to call C code, and this involves passing flags to the C compiler and linker. Without these checks, a malicious C library or carefully crafted flags could lead to security vulnerabilities.

**5. Generating Example Code and Inferring I/O:**

To demonstrate, we need to simulate the `go` command invoking CGO. The examples focus on:
* **Valid flags:** Showing how allowed flags pass.
* **Invalid flags:** Demonstrating the error reporting.
* **`-Wl` handling:** Highlighting the special comma splitting.
* **Flags with next arguments:** Showing how those are handled.
* **Environment variable overrides:** Demonstrating the `ALLOW` and `DISALLOW` mechanisms.

The "input" is the list of flags, and the "output" is either `nil` (success) or an `error`.

**6. Command-Line Parameter Handling:**

The code itself doesn't *directly* handle command-line parameters. It *validates* flags that are assumed to have been parsed from the command line elsewhere in the `go` toolchain. The example explains how these flags would typically be passed via CGO-related environment variables or potentially through `// #cgo CFLAGS:` and `// #cgo LDFLAGS:` directives.

**7. Identifying Common Mistakes:**

The most obvious mistakes revolve around using disallowed or incorrectly formatted flags. The examples highlight this. The `-Wl` comma issue is also a potential pitfall. The environment variable overrides can be both powerful and dangerous if used incorrectly.

**8. Refinement and Organization:**

After the initial analysis, the next step is to organize the information logically:

* Start with a high-level summary of the functionality.
* Explain the core data structures.
* Detail the functions and their logic.
* Clearly link the code to the CGO feature.
* Provide practical Go code examples with expected outputs.
* Explain the command-line context (even if it's indirect).
* Point out common mistakes.

This systematic approach ensures a comprehensive understanding and clear explanation of the code.
这段代码是 Go 语言 `cmd/go` 工具链中 `work` 包下 `security.go` 文件的一部分，它的主要功能是**检查传递给 C 编译器和链接器的标志 (flags)，以防止潜在的安全风险**。

更具体地说，这段代码通过一系列正则表达式来定义哪些编译器和链接器标志是允许的，哪些是不允许的。其目的是避免使用可能导致任意代码执行的危险标志，例如 `-fplugin=`。

**主要功能列举:**

1. **定义允许的编译器标志:**  `validCompilerFlags` 变量是一个正则表达式切片，包含了所有被认为是安全的 C 编译器标志的模式。
2. **定义允许的链接器标志:** `validLinkerFlags` 变量类似地定义了安全的链接器标志。
3. **定义不允许的链接器标志:** `invalidLinkerFlags` 变量定义了明确禁止的链接器标志，例如 macOS 上可能导致代码执行的 `-lto_library`。
4. **处理需要下一个参数的标志:** `validCompilerFlagsWithNextArg` 和 `validLinkerFlagsWithNextArg` 字符串切片列出了那些需要紧跟一个额外参数的合法标志。
5. **`checkCompilerFlags` 函数:** 接收编译器标志列表，并使用 `validCompilerFlags` 和 `validCompilerFlagsWithNextArg` 进行校验。
6. **`checkLinkerFlags` 函数:** 接收链接器标志列表，并使用 `invalidLinkerFlags`，`validLinkerFlags` 和 `validLinkerFlagsWithNextArg` 进行校验。
7. **`checkCompilerFlagsForInternalLink` 函数:**  一个更严格的编译器标志检查，用于内部链接场景，可能会禁止某些在外部链接中允许的标志（例如 `-flto`）。
8. **`checkFlags` 函数:**  这是一个核心的通用标志检查函数，被 `checkCompilerFlags` 和 `checkLinkerFlags` 调用。它遍历标志列表，并根据预定义的正则表达式进行匹配，判断标志是否合法。
9. **支持环境变量覆盖:**  `checkFlags` 函数还支持通过环境变量 `CGO_<name>_ALLOW` 和 `CGO_<name>_DISALLOW` 来动态地允许或禁止某些标志，从而提供一定的灵活性。

**Go 语言功能实现 (CGO 安全检查):**

这段代码是 Go 语言中 CGO (C语言互操作) 功能安全实现的一部分。当 Go 代码中使用 `import "C"` 导入 C 代码时，可以通过特殊的注释 (`// #cgo CFLAGS: ...` 和 `// #cgo LDFLAGS: ...`) 来指定传递给 C 编译器和链接器的标志。  `security.go` 中的代码就是用来验证这些标志的安全性。

**Go 代码示例:**

假设我们有一个 Go 文件 `myprogram.go`，它使用了 CGO：

```go
package main

/*
#cgo CFLAGS: -O2 -Wall -DDEBUG_MODE
#cgo LDFLAGS: -lm -L/usr/local/lib
*/
import "C"

func main() {
	println("Hello, CGO!")
}
```

当使用 `go build myprogram.go` 构建这个程序时，`cmd/go` 工具会解析 `#cgo CFLAGS` 和 `#cgo LDFLAGS` 中的标志，并调用 `work.checkCompilerFlags` 和 `work.checkLinkerFlags` 来验证这些标志是否安全。

**代码推理 (假设的输入与输出):**

**场景 1: 合法的编译器标志**

* **输入 (`checkCompilerFlags` 的 `list` 参数):** `[]string{"-O2", "-Wall", "-DDEBUG_MODE"}`
* **输出:** `nil` (没有错误，标志被认为是合法的)
* **推理:**  `checkCompilerFlags` 会遍历这些标志，并使用 `validCompilerFlags` 中的正则表达式进行匹配。 `-O2`, `-Wall`, 和 `-DDEBUG_MODE` 都能找到匹配的模式，因此返回 `nil`。

**场景 2: 不合法的编译器标志**

* **输入 ( `checkCompilerFlags` 的 `list` 参数):** `[]string{"-O2", "-fplugin=/path/to/evil.so"}`
* **输出:** `error` (例如: `invalid flag in package/path/myprogram.go: -fplugin=/path/to/evil.so`)
* **推理:** `-fplugin=/path/to/evil.so`  与 `validCompilerFlags` 中的任何模式都不匹配，因此 `checkCompilerFlags` 会返回一个错误，指出该标志不合法。

**场景 3: 合法的链接器标志**

* **输入 (`checkLinkerFlags` 的 `list` 参数):** `[]string{"-lm", "-L/usr/local/lib"}`
* **输出:** `nil`
* **推理:** `-lm` 和 `-L/usr/local/lib` 都能在 `validLinkerFlags` 中找到匹配的模式。

**场景 4: 不合法的链接器标志**

* **输入 (`checkLinkerFlags` 的 `list` 参数):** `[]string{"-Wl,-pie,", "-lto_library"}`
* **输出:** `error` (例如: `invalid flag in package/path/myprogram.go: -lto_library`)
* **推理:** `-lto_library` 会被 `invalidLinkerFlags` 中的正则表达式匹配到，因此 `checkLinkerFlags` 会返回一个错误。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。它接收的是已经从 `#cgo` 指令或者其他配置中提取出来的标志列表。

在 `go build` 过程中，`cmd/go` 工具会解析 Go 源文件中的 `#cgo` 指令，并将 `CFLAGS` 和 `LDFLAGS` 的值分割成字符串切片。然后，这些切片会被传递给 `work.checkCompilerFlags` 和 `work.checkLinkerFlags` 进行安全检查。

例如，在上面的 `myprogram.go` 示例中，`go build myprogram.go` 命令执行时，`cmd/go` 会：

1. 解析 `#cgo CFLAGS: -O2 -Wall -DDEBUG_MODE` 并得到 `[]string{"-O2", "-Wall", "-DDEBUG_MODE"}`。
2. 解析 `#cgo LDFLAGS: -lm -L/usr/local/lib` 并得到 `[]string{"-lm", "-L/usr/local/lib"}`。
3. 调用 `work.checkCompilerFlags("CFLAGS", "package/path/myprogram.go", []string{"-O2", "-Wall", "-DDEBUG_MODE"})`。
4. 调用 `work.checkLinkerFlags("LDFLAGS", "package/path/myprogram.go", []string{"-lm", "-L/usr/local/lib"})`。

**使用者易犯错的点:**

1. **使用未被 `validCompilerFlags` 或 `validLinkerFlags` 允许的标志:**  如果使用者在 `#cgo CFLAGS` 或 `#cgo LDFLAGS` 中使用了不被安全策略允许的标志，构建过程将会失败，并显示相应的错误信息。例如，使用 `-fplugin=`。
2. **错误地组合 `-Wl` 标志:**  `-Wl` 用于将后面的参数传递给链接器。这段代码对 `-Wl` 的参数有特殊的处理，例如，它会分割逗号分隔的参数。使用者可能会错误地认为所有传递给 `-Wl` 的参数都会被原样传递，而忽略了逗号分割的规则，从而导致意外的行为或安全问题。 例如，误用 `-Wl,-rpath,/some/path,otherflag` 可能会导致 `otherflag` 也被当作 `-rpath` 的一部分。
3. **忽略错误信息:** 构建失败时，仔细阅读错误信息非常重要。错误信息会明确指出哪个标志被认为是不合法的，以及来自哪个源文件。
4. **不理解环境变量覆盖的影响:**  虽然可以通过 `CGO_<name>_ALLOW` 和 `CGO_<name>_DISALLOW` 来覆盖默认的安全策略，但不理解其含义和潜在风险就使用可能会引入安全漏洞。例如，错误地允许所有以 `-f` 开头的标志。
5. **在内部链接场景下使用外部链接允许的标志:**  `checkCompilerFlagsForInternalLink` 比 `checkCompilerFlags` 更严格。使用者可能会在依赖内部链接的情况下，使用了仅在外部链接中才允许的标志，导致构建失败。例如，使用了 `-flto` 但期望内部链接。

总而言之，`go/src/cmd/go/internal/work/security.go` 这部分代码是 Go 工具链中一个关键的安全组件，它通过白名单的方式严格控制传递给 C 编译器和链接器的标志，以防止潜在的安全风险，确保构建过程的安全性。理解其工作原理有助于开发者在使用 CGO 功能时避免常见的错误，并构建更安全的 Go 应用程序。

### 提示词
```
这是路径为go/src/cmd/go/internal/work/security.go的go语言实现的一部分， 请列举一下它的功能, 　
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

// Checking of compiler and linker flags.
// We must avoid flags like -fplugin=, which can allow
// arbitrary code execution during the build.
// Do not make changes here without carefully
// considering the implications.
// (That's why the code is isolated in a file named security.go.)
//
// Note that -Wl,foo means split foo on commas and pass to
// the linker, so that -Wl,-foo,bar means pass -foo bar to
// the linker. Similarly -Wa,foo for the assembler and so on.
// If any of these are permitted, the wildcard portion must
// disallow commas.
//
// Note also that GNU binutils accept any argument @foo
// as meaning "read more flags from the file foo", so we must
// guard against any command-line argument beginning with @,
// even things like "-I @foo".
// We use load.SafeArg (which is even more conservative)
// to reject these.
//
// Even worse, gcc -I@foo (one arg) turns into cc1 -I @foo (two args),
// so although gcc doesn't expand the @foo, cc1 will.
// So out of paranoia, we reject @ at the beginning of every
// flag argument that might be split into its own argument.

package work

import (
	"fmt"
	"internal/lazyregexp"
	"regexp"
	"strings"

	"cmd/go/internal/cfg"
	"cmd/go/internal/load"
)

var re = lazyregexp.New

var validCompilerFlags = []*lazyregexp.Regexp{
	re(`-D([A-Za-z_][A-Za-z0-9_]*)(=[^@\-]*)?`),
	re(`-U([A-Za-z_][A-Za-z0-9_]*)`),
	re(`-F([^@\-].*)`),
	re(`-I([^@\-].*)`),
	re(`-O`),
	re(`-O([^@\-].*)`),
	re(`-W`),
	re(`-W([^@,]+)`), // -Wall but not -Wa,-foo.
	re(`-Wa,-mbig-obj`),
	re(`-Wp,-D([A-Za-z_][A-Za-z0-9_]*)(=[^@,\-]*)?`),
	re(`-Wp,-U([A-Za-z_][A-Za-z0-9_]*)`),
	re(`-ansi`),
	re(`-f(no-)?asynchronous-unwind-tables`),
	re(`-f(no-)?blocks`),
	re(`-f(no-)builtin-[a-zA-Z0-9_]*`),
	re(`-f(no-)?common`),
	re(`-f(no-)?constant-cfstrings`),
	re(`-fdebug-prefix-map=([^@]+)=([^@]+)`),
	re(`-fdiagnostics-show-note-include-stack`),
	re(`-ffile-prefix-map=([^@]+)=([^@]+)`),
	re(`-fno-canonical-system-headers`),
	re(`-f(no-)?eliminate-unused-debug-types`),
	re(`-f(no-)?exceptions`),
	re(`-f(no-)?fast-math`),
	re(`-f(no-)?inline-functions`),
	re(`-finput-charset=([^@\-].*)`),
	re(`-f(no-)?fat-lto-objects`),
	re(`-f(no-)?keep-inline-dllexport`),
	re(`-f(no-)?lto`),
	re(`-fmacro-backtrace-limit=(.+)`),
	re(`-fmessage-length=(.+)`),
	re(`-f(no-)?modules`),
	re(`-f(no-)?objc-arc`),
	re(`-f(no-)?objc-nonfragile-abi`),
	re(`-f(no-)?objc-legacy-dispatch`),
	re(`-f(no-)?omit-frame-pointer`),
	re(`-f(no-)?openmp(-simd)?`),
	re(`-f(no-)?permissive`),
	re(`-f(no-)?(pic|PIC|pie|PIE)`),
	re(`-f(no-)?plt`),
	re(`-f(no-)?rtti`),
	re(`-f(no-)?split-stack`),
	re(`-f(no-)?stack-(.+)`),
	re(`-f(no-)?strict-aliasing`),
	re(`-f(un)signed-char`),
	re(`-f(no-)?use-linker-plugin`), // safe if -B is not used; we don't permit -B
	re(`-f(no-)?visibility-inlines-hidden`),
	re(`-fsanitize=(.+)`),
	re(`-ftemplate-depth-(.+)`),
	re(`-ftls-model=(global-dynamic|local-dynamic|initial-exec|local-exec)`),
	re(`-fvisibility=(.+)`),
	re(`-g([^@\-].*)?`),
	re(`-m32`),
	re(`-m64`),
	re(`-m(abi|arch|cpu|fpu|tune)=([^@\-].*)`),
	re(`-m(no-)?v?aes`),
	re(`-marm`),
	re(`-m(no-)?avx[0-9a-z]*`),
	re(`-mcmodel=[0-9a-z-]+`),
	re(`-mfloat-abi=([^@\-].*)`),
	re(`-mfpmath=[0-9a-z,+]*`),
	re(`-m(no-)?avx[0-9a-z.]*`),
	re(`-m(no-)?ms-bitfields`),
	re(`-m(no-)?stack-(.+)`),
	re(`-mmacosx-(.+)`),
	re(`-mios-simulator-version-min=(.+)`),
	re(`-miphoneos-version-min=(.+)`),
	re(`-mlarge-data-threshold=[0-9]+`),
	re(`-mtvos-simulator-version-min=(.+)`),
	re(`-mtvos-version-min=(.+)`),
	re(`-mwatchos-simulator-version-min=(.+)`),
	re(`-mwatchos-version-min=(.+)`),
	re(`-mnop-fun-dllimport`),
	re(`-m(no-)?sse[0-9.]*`),
	re(`-m(no-)?ssse3`),
	re(`-mthumb(-interwork)?`),
	re(`-mthreads`),
	re(`-mwindows`),
	re(`-no-canonical-prefixes`),
	re(`--param=ssp-buffer-size=[0-9]*`),
	re(`-pedantic(-errors)?`),
	re(`-pipe`),
	re(`-pthread`),
	re(`-?-std=([^@\-].*)`),
	re(`-?-stdlib=([^@\-].*)`),
	re(`--sysroot=([^@\-].*)`),
	re(`-w`),
	re(`-x([^@\-].*)`),
	re(`-v`),
}

var validCompilerFlagsWithNextArg = []string{
	"-arch",
	"-D",
	"-U",
	"-I",
	"-F",
	"-framework",
	"-include",
	"-isysroot",
	"-isystem",
	"--sysroot",
	"-target",
	"-x",
}

var invalidLinkerFlags = []*lazyregexp.Regexp{
	// On macOS this means the linker loads and executes the next argument.
	// Have to exclude separately because -lfoo is allowed in general.
	re(`-lto_library`),
}

var validLinkerFlags = []*lazyregexp.Regexp{
	re(`-F([^@\-].*)`),
	re(`-l([^@\-].*)`),
	re(`-L([^@\-].*)`),
	re(`-O`),
	re(`-O([^@\-].*)`),
	re(`-f(no-)?(pic|PIC|pie|PIE)`),
	re(`-f(no-)?openmp(-simd)?`),
	re(`-fsanitize=([^@\-].*)`),
	re(`-flat_namespace`),
	re(`-g([^@\-].*)?`),
	re(`-headerpad_max_install_names`),
	re(`-m(abi|arch|cpu|fpu|tune)=([^@\-].*)`),
	re(`-mfloat-abi=([^@\-].*)`),
	re(`-mmacosx-(.+)`),
	re(`-mios-simulator-version-min=(.+)`),
	re(`-miphoneos-version-min=(.+)`),
	re(`-mthreads`),
	re(`-mwindows`),
	re(`-(pic|PIC|pie|PIE)`),
	re(`-pthread`),
	re(`-rdynamic`),
	re(`-shared`),
	re(`-?-static([-a-z0-9+]*)`),
	re(`-?-stdlib=([^@\-].*)`),
	re(`-v`),

	// Note that any wildcards in -Wl need to exclude comma,
	// since -Wl splits its argument at commas and passes
	// them all to the linker uninterpreted. Allowing comma
	// in a wildcard would allow tunneling arbitrary additional
	// linker arguments through one of these.
	re(`-Wl,--(no-)?allow-multiple-definition`),
	re(`-Wl,--(no-)?allow-shlib-undefined`),
	re(`-Wl,--(no-)?as-needed`),
	re(`-Wl,-Bdynamic`),
	re(`-Wl,-berok`),
	re(`-Wl,-Bstatic`),
	re(`-Wl,-Bsymbolic-functions`),
	re(`-Wl,-O[0-9]+`),
	re(`-Wl,-d[ny]`),
	re(`-Wl,--disable-new-dtags`),
	re(`-Wl,-e[=,][a-zA-Z0-9]+`),
	re(`-Wl,--enable-new-dtags`),
	re(`-Wl,--end-group`),
	re(`-Wl,--(no-)?export-dynamic`),
	re(`-Wl,-E`),
	re(`-Wl,-framework,[^,@\-][^,]*`),
	re(`-Wl,--hash-style=(sysv|gnu|both)`),
	re(`-Wl,-headerpad_max_install_names`),
	re(`-Wl,--no-undefined`),
	re(`-Wl,--pop-state`),
	re(`-Wl,--push-state`),
	re(`-Wl,-R,?([^@\-,][^,@]*$)`),
	re(`-Wl,--just-symbols[=,]([^,@\-][^,@]*)`),
	re(`-Wl,-rpath(-link)?[=,]([^,@\-][^,]*)`),
	re(`-Wl,-s`),
	re(`-Wl,-search_paths_first`),
	re(`-Wl,-sectcreate,([^,@\-][^,]*),([^,@\-][^,]*),([^,@\-][^,]*)`),
	re(`-Wl,--start-group`),
	re(`-Wl,-?-static`),
	re(`-Wl,-?-subsystem,(native|windows|console|posix|xbox)`),
	re(`-Wl,-syslibroot[=,]([^,@\-][^,]*)`),
	re(`-Wl,-undefined[=,]([^,@\-][^,]*)`),
	re(`-Wl,-?-unresolved-symbols=[^,]+`),
	re(`-Wl,--(no-)?warn-([^,]+)`),
	re(`-Wl,-?-wrap[=,][^,@\-][^,]*`),
	re(`-Wl(,-z,(relro|now|(no)?execstack))+`),

	re(`[a-zA-Z0-9_/].*\.(a|o|obj|dll|dylib|so|tbd)`), // direct linker inputs: x.o or libfoo.so (but not -foo.o or @foo.o)
	re(`\./.*\.(a|o|obj|dll|dylib|so|tbd)`),
}

var validLinkerFlagsWithNextArg = []string{
	"-arch",
	"-F",
	"-l",
	"-L",
	"-framework",
	"-isysroot",
	"--sysroot",
	"-target",
	"-Wl,-framework",
	"-Wl,-rpath",
	"-Wl,-R",
	"-Wl,--just-symbols",
	"-Wl,-undefined",
}

func checkCompilerFlags(name, source string, list []string) error {
	checkOverrides := true
	return checkFlags(name, source, list, nil, validCompilerFlags, validCompilerFlagsWithNextArg, checkOverrides)
}

func checkLinkerFlags(name, source string, list []string) error {
	checkOverrides := true
	return checkFlags(name, source, list, invalidLinkerFlags, validLinkerFlags, validLinkerFlagsWithNextArg, checkOverrides)
}

// checkCompilerFlagsForInternalLink returns an error if 'list'
// contains a flag or flags that may not be fully supported by
// internal linking (meaning that we should punt the link to the
// external linker).
func checkCompilerFlagsForInternalLink(name, source string, list []string) error {
	checkOverrides := false
	if err := checkFlags(name, source, list, nil, validCompilerFlags, validCompilerFlagsWithNextArg, checkOverrides); err != nil {
		return err
	}
	// Currently the only flag on the allow list that causes problems
	// for the linker is "-flto"; check for it manually here.
	for _, fl := range list {
		if strings.HasPrefix(fl, "-flto") {
			return fmt.Errorf("flag %q triggers external linking", fl)
		}
	}
	return nil
}

func checkFlags(name, source string, list []string, invalid, valid []*lazyregexp.Regexp, validNext []string, checkOverrides bool) error {
	// Let users override rules with $CGO_CFLAGS_ALLOW, $CGO_CFLAGS_DISALLOW, etc.
	var (
		allow    *regexp.Regexp
		disallow *regexp.Regexp
	)
	if checkOverrides {
		if env := cfg.Getenv("CGO_" + name + "_ALLOW"); env != "" {
			r, err := regexp.Compile(env)
			if err != nil {
				return fmt.Errorf("parsing $CGO_%s_ALLOW: %v", name, err)
			}
			allow = r
		}
		if env := cfg.Getenv("CGO_" + name + "_DISALLOW"); env != "" {
			r, err := regexp.Compile(env)
			if err != nil {
				return fmt.Errorf("parsing $CGO_%s_DISALLOW: %v", name, err)
			}
			disallow = r
		}
	}

Args:
	for i := 0; i < len(list); i++ {
		arg := list[i]
		if disallow != nil && disallow.FindString(arg) == arg {
			goto Bad
		}
		if allow != nil && allow.FindString(arg) == arg {
			continue Args
		}
		for _, re := range invalid {
			if re.FindString(arg) == arg { // must be complete match
				goto Bad
			}
		}
		for _, re := range valid {
			if match := re.FindString(arg); match == arg { // must be complete match
				continue Args
			} else if strings.HasPrefix(arg, "-Wl,--push-state,") {
				// Examples for --push-state are written
				//     -Wl,--push-state,--as-needed
				// Support other commands in the same -Wl arg.
				args := strings.Split(arg, ",")
				for _, a := range args[1:] {
					a = "-Wl," + a
					var found bool
					for _, re := range valid {
						if re.FindString(a) == a {
							found = true
							break
						}
					}
					if !found {
						goto Bad
					}
					for _, re := range invalid {
						if re.FindString(a) == a {
							goto Bad
						}
					}
				}
				continue Args
			}
		}
		for _, x := range validNext {
			if arg == x {
				if i+1 < len(list) && load.SafeArg(list[i+1]) {
					i++
					continue Args
				}

				// Permit -Wl,-framework -Wl,name.
				if i+1 < len(list) &&
					strings.HasPrefix(arg, "-Wl,") &&
					strings.HasPrefix(list[i+1], "-Wl,") &&
					load.SafeArg(list[i+1][4:]) &&
					!strings.Contains(list[i+1][4:], ",") {
					i++
					continue Args
				}

				// Permit -I= /path, -I $SYSROOT.
				if i+1 < len(list) && arg == "-I" {
					if (strings.HasPrefix(list[i+1], "=") || strings.HasPrefix(list[i+1], "$SYSROOT")) &&
						load.SafeArg(list[i+1][1:]) {
						i++
						continue Args
					}
				}

				if i+1 < len(list) {
					return fmt.Errorf("invalid flag in %s: %s %s (see https://golang.org/s/invalidflag)", source, arg, list[i+1])
				}
				return fmt.Errorf("invalid flag in %s: %s without argument (see https://golang.org/s/invalidflag)", source, arg)
			}
		}
	Bad:
		return fmt.Errorf("invalid flag in %s: %s", source, arg)
	}
	return nil
}
```