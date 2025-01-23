Response:
Let's break down the thought process for analyzing the provided Go documentation excerpt.

**1. Understanding the Goal:**

The request asks for the functionality of `go/src/cmd/go/alldocs.go` *based on the given text*. It also asks for Go feature identification, code examples, command-line argument explanations, common mistakes, and a summary. The "Part 4 of 5" indicates we're only analyzing a specific section.

**2. Initial Reading and Keyword Identification:**

The first step is to read through the text and identify recurring themes and keywords. Immediately, "environment variables" stands out as a major topic. Other keywords that jump out include:

* `GO...` (numerous environment variables starting with `GO`)
* `CGO...`
* Architecture-specific terms (`GOARCH`, `GOARM`, etc.)
* Code coverage (`GOCOVERDIR`)
* Special-purpose variables (`GOEXPERIMENT`, `GOFIPS140`, etc.)
* File types (`.go`, `.c`, `.h`, etc.)
* `GOAUTH` (with detailed explanation)
* `go.mod` file
* `GOPATH`
* Internal directories
* Vendor directories
* Module proxy protocol
* Import path syntax (relative, remote)
* Import path checking
* Modules and module versions
* Module authentication (`go.sum`)
* Package lists and patterns

**3. Categorization and Grouping:**

The text itself provides a helpful structure by categorizing the environment variables. We can follow this structure:

* General-purpose environment variables
* Environment variables for use with cgo
* Architecture-specific environment variables
* Environment variables for use with code coverage
* Special-purpose environment variables

Beyond environment variables, we see distinct sections on file types, `GOAUTH`, `go.mod`, `GOPATH`, internal/vendor directories, module proxies, import paths, modules, and package lists. These become natural groupings for summarizing the functionality.

**4. Inferring Functionality of `alldocs.go`:**

Since this is a *documentation* file (`alldocs.go`), its primary function is to *document* the Go toolchain. Specifically, this excerpt documents various aspects of the `go` command, its environment variables, file conventions, module system, and package management. It's a comprehensive reference guide embedded within the source code.

**5. Identifying Go Language Features:**

Based on the documented information, we can identify several key Go language features:

* **Environment Variables:**  A standard operating system feature used to configure the Go toolchain.
* **Cgo:** The mechanism for interoperability with C code. The `CGO_*` variables are directly related.
* **Build Tags/Constraints:** Mentioned in the context of file types.
* **Modules:**  The modern dependency management system in Go, heavily referenced by `go.mod`, `GOPROXY`, `GOSUMDB`, etc.
* **Packages:** The fundamental unit of code organization in Go, discussed in the "Package lists and patterns" section.
* **Import Paths:** The way packages are referenced, including remote imports and the role of `go-import` meta tags.
* **Vendoring:**  A mechanism for including dependencies directly within a project.
* **Internal Packages:**  A mechanism for controlling the visibility of packages within a project.
* **Code Coverage:**  A tool for measuring the test coverage of Go code.

**6. Developing Code Examples (and Recognizing Limitations):**

The request asks for code examples. However, `alldocs.go` itself *doesn't contain executable code*. It's documentation. Therefore, the code examples need to demonstrate the *features being documented*.

* **Environment Variables:**  The example shows how to access environment variables within a Go program using `os.Getenv`.
* **Cgo:** A minimal example showing how to import a C library and call a C function. This demonstrates the concept even if `alldocs.go` doesn't implement cgo itself.
* **Modules:**  Showing a basic `go.mod` file is crucial for illustrating the module system.

**7. Explaining Command-Line Arguments:**

The documentation describes many environment variables that *affect* the behavior of `go` commands. It also mentions specific `go` commands like `go mod init`, `go get`, etc. The focus here is on how environment variables influence the command-line tool. Specific command-line argument parsing isn't explicitly detailed in this excerpt.

**8. Identifying Common Mistakes:**

The text itself hints at potential issues:

* Incorrectly setting or understanding `GOPATH`.
* Confusion between module mode and GOPATH mode.
* Misunderstanding the visibility rules of `internal` and `vendor` directories.
* Issues with `GOAUTH` configuration.
* Problems with import paths and vendoring.

**9. Structuring the Answer:**

Organize the information logically, following the categories identified earlier. Use clear headings and bullet points for readability. Address each part of the request (functionality, features, examples, arguments, mistakes, summary).

**10. Drafting and Refining:**

Write a first draft, then review and refine it for clarity, accuracy, and completeness. Ensure the answer directly addresses the prompt and uses the provided text as the basis for the analysis. For example, avoid introducing external knowledge about the Go toolchain unless it directly supports the interpretation of the provided text.

**Self-Correction/Refinement Example during the process:**

Initially, I might have thought about providing more complex cgo examples. However, realizing the focus is on what the *documentation* reveals, a simple example suffices to illustrate the *concept* of cgo as described by the environment variables. Similarly, I initially might have tried to explain every single environment variable in detail. But the request asks for the *functionality* of the *file*, which is primarily to document these variables, not to implement their behavior. Therefore, summarizing the categories of environment variables is more appropriate.
好的，让我们继续分析提供的 Go 语言文档的这一部分（第 4 部分）。

**功能归纳：**

这部分文档详细描述了 Go 语言构建工具 `go` 命令所使用的各种**环境变量**和所识别的**文件类型**。

**具体功能点：**

1. **环境变量说明:**
   - 列举了大量的环境变量，并对它们的作用进行了详细解释。这些环境变量影响着 Go 程序的编译、构建、依赖管理、代码覆盖率、调试等各个方面。
   - 将环境变量按用途进行了分类：通用、cgo 相关、架构特定、代码覆盖率相关以及特殊用途。
   - 明确指出哪些环境变量可以通过 `go env -w` 设置，哪些不可以。

2. **文件类型识别:**
   -  列出了 `go` 命令能够识别的不同类型的文件扩展名，例如 `.go`, `.c`, `.h`, `.s` 等。
   -  说明了不同类型文件在 Go 构建过程中的作用，例如 Go 源码、C 源码、汇编源码等。
   -  提到了构建约束（build constraints）的概念，并说明了 `go` 命令如何扫描这些约束。

3. **`GOAUTH` 环境变量详解:**
   -  专门详细解释了 `GOAUTH` 环境变量，用于控制 `go-import` 和 HTTPS 模块镜像交互的身份验证。
   -  列出了 `GOAUTH` 支持的认证命令：`off`、`netrc`、`git dir` 和自定义 `command`。
   -  详细描述了每种认证命令的工作方式，特别是自定义 `command` 的输入输出格式。

4. **`go.mod` 文件介绍:**
   -  简要介绍了 `go.mod` 文件在 Go 模块化管理中的作用，它是模块的根标识。
   -  提及了与 `go.mod` 文件相关的常用 `go mod` 子命令：`init`、`tidy`、`get`、`edit`。

5. **`GOPATH` 环境变量详解:**
   -  深入解释了 `GOPATH` 环境变量的作用，它用于定位 Go 代码的位置。
   -  描述了 `GOPATH` 目录下的 `src`、`pkg` 和 `bin` 目录的结构和用途。
   -  强调了在使用模块时，`GOPATH` 的部分作用（存储下载的源码和编译的命令）。

6. **`internal` 和 `vendor` 目录:**
   -  详细解释了 `internal` 目录的访问控制规则，即只能被父目录树中的代码导入。
   -  详细解释了 `vendor` 目录的 vendoring 机制，以及导入路径的规则。

7. **模块代理协议:**
   -  简要介绍了 Go 模块代理的概念，以及它如何响应特定格式的 GET 请求。
   -  提供了指向 GOPROXY 协议详细说明的链接。

8. **导入路径语法:**
   -  解释了导入路径的概念，包括标准库包和工作区中的包。
   -  详细说明了相对导入路径的用法和限制。
   -  着重讲解了远程导入路径的语法，包括常见代码托管站点（GitHub, Bitbucket, Launchpad 等）的特殊格式。
   -  介绍了通过 `<meta>` 标签发现代码位置的方法。

9. **导入路径检查:**
   -  解释了导入注释（import comment）的作用，以及 `go` 命令如何进行导入路径检查。
   -  说明了 vendor 目录和模块化管理下禁用导入路径检查的原因。

10. **模块和模块版本:**
    - 简要介绍了 Go 模块的概念，以及如何下载和使用模块。
    - 提及了默认的模块代理和校验和数据库。

11. **使用 `go.sum` 进行模块身份验证:**
    - 解释了 `go.sum` 文件的作用，以及 Go 命令如何使用它来验证下载的模块。

12. **包列表和模式:**
    -  详细解释了 `go` 命令中包的表示方法，包括导入路径和文件系统路径。
    -  列举了几个保留的包名："main"、"all"、"std"、"cmd"、"tool"。
    -  详细讲解了包路径的模式匹配规则，包括 "..." 通配符的用法和特殊情况。
    -  强调了包的唯一导入路径约定。

**推断的 Go 语言功能实现及代码示例：**

基于文档内容，我们可以推断出以下 Go 语言功能的实现：

1. **环境变量处理:** `go` 命令需要读取和解析操作系统中的环境变量。Go 的 `os` 包提供了相关功能。

   ```go
   package main

   import (
       "fmt"
       "os"
   )

   func main() {
       gopath := os.Getenv("GOPATH")
       fmt.Println("GOPATH:", gopath)

       goarch := os.Getenv("GOARCH")
       fmt.Println("GOARCH:", goarch)
   }
   ```

   **假设输入：** 环境变量 `GOPATH` 设置为 `/home/user/go`，`GOARCH` 设置为 `amd64`。

   **预期输出：**
   ```
   GOPATH: /home/user/go
   GOARCH: amd64
   ```

2. **文件类型识别和构建约束解析:** `go` 命令需要读取文件内容，根据扩展名判断文件类型，并解析 Go 源码中的构建约束注释。Go 的 `go/build` 包提供了这方面的支持。

   ```go
   package main

   import (
       "fmt"
       "go/build/constraint"
       "log"
       "os"
   )

   func main() {
       content := `//go:build linux && amd64

       package main

       import "fmt"

       func main() {
           fmt.Println("Hello from linux amd64")
       }
       `

       expr, err := constraint.Parse("//go:build linux && amd64")
       if err != nil {
           log.Fatal(err)
       }

       tags := map[string]bool{"linux": true, "amd64": true}
       match := expr.Eval(func(tag string) bool {
           return tags[tag]
       })

       fmt.Println("Build constraints match:", match)
   }
   ```

   **假设输入：**  代码中的构建约束是 `//go:build linux && amd64`，当前操作系统是 Linux，架构是 amd64。

   **预期输出：**
   ```
   Build constraints match: true
   ```

3. **远程导入路径处理 (`go get` 的一部分):** `go` 命令需要能够解析远程导入路径，发起 HTTP/HTTPS 请求，解析 `<meta>` 标签，并根据标签信息执行版本控制操作（如 `git clone`）。Go 的 `net/http` 包和一些版本控制相关的库会参与其中。

   由于涉及网络请求和版本控制操作，用一个简单的代码示例很难完全展示其实现，这里只展示获取 URL 内容的片段：

   ```go
   package main

   import (
       "fmt"
       "io/ioutil"
       "log"
       "net/http"
   )

   func main() {
       url := "https://example.org/pkg/foo?go-get=1"
       resp, err := http.Get(url)
       if err != nil {
           log.Fatal(err)
       }
       defer resp.Body.Close()

       body, err := ioutil.ReadAll(resp.Body)
       if err != nil {
           log.Fatal(err)
       }

       fmt.Println("Response body:", string(body[:100])) // 打印部分响应内容
   }
   ```

   **假设输入：** `https://example.org/pkg/foo?go-get=1` 返回包含 `<meta name="go-import" content="example.org git https://code.org/r/p/exproj">` 的 HTML 内容。

   **预期输出：** 会打印出以 "Response body:" 开头的 HTML 内容片段。后续 `go get` 会根据 meta 标签执行 `git clone` 操作，这部分不在示例代码中。

**命令行参数的具体处理：**

这部分文档主要关注环境变量和文件类型，并没有详细涉及 `go` 命令本身的命令行参数处理。 `go` 命令的参数处理逻辑通常在 `go/src/cmd/go/` 目录下的其他文件中实现，例如 `main.go` 和各个子命令对应的文件（如 `build.go`, `get.go` 等）。

如果要详细了解命令行参数的处理，需要查看 `go` 命令的源代码。通常会使用 Go 的 `flag` 包来解析命令行参数。

**使用者易犯错的点：**

1. **`GOPATH` 设置不当:** 初学者容易混淆 `GOPATH` 的作用和设置方式，导致包导入错误或者命令安装位置错误。例如，忘记设置 `GOPATH` 或者设置了多个 `GOPATH` 路径但理解有误。

   **错误示例：** 用户期望安装的二进制文件在 `/usr/local/bin` 下，但 `GOBIN` 或 `GOPATH` 的 `bin` 目录没有添加到 `PATH` 环境变量中，导致无法直接运行。

2. **模块模式和 `GOPATH` 模式混淆:**  不理解模块模式下 `GOPATH` 的作用变化，例如在模块模式下仍然尝试将依赖包放在 `GOPATH/src` 下。

   **错误示例：** 在启用了模块模式的项目中，尝试手动创建 `GOPATH/src/github.com/someuser/somerepo` 目录来放置依赖包，而不是使用 `go get` 或在 `go.mod` 中声明依赖。

3. **`internal` 和 `vendor` 目录的可见性规则理解错误:**  在不符合规则的情况下尝试导入 `internal` 或 `vendor` 目录下的包。

   **错误示例：** 在项目根目录下的一个包中，尝试导入 `some/project/internal/mypackage`，这是不允许的。

4. **`GOAUTH` 配置错误:**  配置自定义 `GOAUTH` 命令时，输出格式不正确，导致身份验证失败。

   **错误示例：** 自定义认证命令的输出缺少必要的空行分隔符，或者 HeaderLine 的格式不符合 HTTP 请求头的规范。

5. **远程导入路径的理解偏差:**  不理解 `go get` 如何根据远程导入路径查找代码，或者不了解 `<meta>` 标签的作用。

   **错误示例：**  尝试 `go get` 一个没有提供正确 `<meta>` 标签的私有仓库，导致 `go` 命令无法找到仓库位置。

**总结（针对第 4 部分的功能）：**

这部分文档是 `go` 命令的重要组成部分，它详细记录了影响 `go` 命令行为的**环境变量**、`go` 命令能够识别的**文件类型**，以及与依赖管理和身份验证相关的 `GOAUTH`、`go.mod` 和 `GOPATH` 的详细信息。  它为 Go 语言开发者提供了理解和配置 Go 构建环境的关键参考，同时也解释了 Go 语言中包管理和导入机制的核心概念。理解这部分内容对于有效地使用 `go` 命令进行项目构建、依赖管理和代码组织至关重要。

### 提示词
```
这是路径为go/src/cmd/go/alldocs.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```go
eral-purpose environment variables:
//
//	GCCGO
//		The gccgo command to run for 'go build -compiler=gccgo'.
//	GO111MODULE
//		Controls whether the go command runs in module-aware mode or GOPATH mode.
//		May be "off", "on", or "auto".
//		See https://golang.org/ref/mod#mod-commands.
//	GOARCH
//		The architecture, or processor, for which to compile code.
//		Examples are amd64, 386, arm, ppc64.
//	GOAUTH
//		Controls authentication for go-import and HTTPS module mirror interactions.
//		See 'go help goauth'.
//	GOBIN
//		The directory where 'go install' will install a command.
//	GOCACHE
//		The directory where the go command will store cached
//		information for reuse in future builds.
//	GODEBUG
//		Enable various debugging facilities. See https://go.dev/doc/godebug
//		for details.
//	GOENV
//		The location of the Go environment configuration file.
//		Cannot be set using 'go env -w'.
//		Setting GOENV=off in the environment disables the use of the
//		default configuration file.
//	GOFLAGS
//		A space-separated list of -flag=value settings to apply
//		to go commands by default, when the given flag is known by
//		the current command. Each entry must be a standalone flag.
//		Because the entries are space-separated, flag values must
//		not contain spaces. Flags listed on the command line
//		are applied after this list and therefore override it.
//	GOINSECURE
//		Comma-separated list of glob patterns (in the syntax of Go's path.Match)
//		of module path prefixes that should always be fetched in an insecure
//		manner. Only applies to dependencies that are being fetched directly.
//		GOINSECURE does not disable checksum database validation. GOPRIVATE or
//		GONOSUMDB may be used to achieve that.
//	GOMODCACHE
//		The directory where the go command will store downloaded modules.
//	GOOS
//		The operating system for which to compile code.
//		Examples are linux, darwin, windows, netbsd.
//	GOPATH
//		Controls where various files are stored. See: 'go help gopath'.
//	GOPRIVATE, GONOPROXY, GONOSUMDB
//		Comma-separated list of glob patterns (in the syntax of Go's path.Match)
//		of module path prefixes that should always be fetched directly
//		or that should not be compared against the checksum database.
//		See https://golang.org/ref/mod#private-modules.
//	GOPROXY
//		URL of Go module proxy. See https://golang.org/ref/mod#environment-variables
//		and https://golang.org/ref/mod#module-proxy for details.
//	GOROOT
//		The root of the go tree.
//	GOSUMDB
//		The name of checksum database to use and optionally its public key and
//		URL. See https://golang.org/ref/mod#authenticating.
//	GOTMPDIR
//		The directory where the go command will write
//		temporary source files, packages, and binaries.
//	GOTOOLCHAIN
//		Controls which Go toolchain is used. See https://go.dev/doc/toolchain.
//	GOVCS
//		Lists version control commands that may be used with matching servers.
//		See 'go help vcs'.
//	GOWORK
//		In module aware mode, use the given go.work file as a workspace file.
//		By default or when GOWORK is "auto", the go command searches for a
//		file named go.work in the current directory and then containing directories
//		until one is found. If a valid go.work file is found, the modules
//		specified will collectively be used as the main modules. If GOWORK
//		is "off", or a go.work file is not found in "auto" mode, workspace
//		mode is disabled.
//
// Environment variables for use with cgo:
//
//	AR
//		The command to use to manipulate library archives when
//		building with the gccgo compiler.
//		The default is 'ar'.
//	CC
//		The command to use to compile C code.
//	CGO_CFLAGS
//		Flags that cgo will pass to the compiler when compiling
//		C code.
//	CGO_CFLAGS_ALLOW
//		A regular expression specifying additional flags to allow
//		to appear in #cgo CFLAGS source code directives.
//		Does not apply to the CGO_CFLAGS environment variable.
//	CGO_CFLAGS_DISALLOW
//		A regular expression specifying flags that must be disallowed
//		from appearing in #cgo CFLAGS source code directives.
//		Does not apply to the CGO_CFLAGS environment variable.
//	CGO_CPPFLAGS, CGO_CPPFLAGS_ALLOW, CGO_CPPFLAGS_DISALLOW
//		Like CGO_CFLAGS, CGO_CFLAGS_ALLOW, and CGO_CFLAGS_DISALLOW,
//		but for the C preprocessor.
//	CGO_CXXFLAGS, CGO_CXXFLAGS_ALLOW, CGO_CXXFLAGS_DISALLOW
//		Like CGO_CFLAGS, CGO_CFLAGS_ALLOW, and CGO_CFLAGS_DISALLOW,
//		but for the C++ compiler.
//	CGO_ENABLED
//		Whether the cgo command is supported. Either 0 or 1.
//	CGO_FFLAGS, CGO_FFLAGS_ALLOW, CGO_FFLAGS_DISALLOW
//		Like CGO_CFLAGS, CGO_CFLAGS_ALLOW, and CGO_CFLAGS_DISALLOW,
//		but for the Fortran compiler.
//	CGO_LDFLAGS, CGO_LDFLAGS_ALLOW, CGO_LDFLAGS_DISALLOW
//		Like CGO_CFLAGS, CGO_CFLAGS_ALLOW, and CGO_CFLAGS_DISALLOW,
//		but for the linker.
//	CXX
//		The command to use to compile C++ code.
//	FC
//		The command to use to compile Fortran code.
//	PKG_CONFIG
//		Path to pkg-config tool.
//
// Architecture-specific environment variables:
//
//	GO386
//		For GOARCH=386, how to implement floating point instructions.
//		Valid values are sse2 (default), softfloat.
//	GOAMD64
//		For GOARCH=amd64, the microarchitecture level for which to compile.
//		Valid values are v1 (default), v2, v3, v4.
//		See https://golang.org/wiki/MinimumRequirements#amd64
//	GOARM
//		For GOARCH=arm, the ARM architecture for which to compile.
//		Valid values are 5, 6, 7.
//		The value can be followed by an option specifying how to implement floating point instructions.
//		Valid options are ,softfloat (default for 5) and ,hardfloat (default for 6 and 7).
//	GOARM64
//		For GOARCH=arm64, the ARM64 architecture for which to compile.
//		Valid values are v8.0 (default), v8.{1-9}, v9.{0-5}.
//		The value can be followed by an option specifying extensions implemented by target hardware.
//		Valid options are ,lse and ,crypto.
//		Note that some extensions are enabled by default starting from a certain GOARM64 version;
//		for example, lse is enabled by default starting from v8.1.
//	GOMIPS
//		For GOARCH=mips{,le}, whether to use floating point instructions.
//		Valid values are hardfloat (default), softfloat.
//	GOMIPS64
//		For GOARCH=mips64{,le}, whether to use floating point instructions.
//		Valid values are hardfloat (default), softfloat.
//	GOPPC64
//		For GOARCH=ppc64{,le}, the target ISA (Instruction Set Architecture).
//		Valid values are power8 (default), power9, power10.
//	GORISCV64
//		For GOARCH=riscv64, the RISC-V user-mode application profile for which
//		to compile. Valid values are rva20u64 (default), rva22u64.
//		See https://github.com/riscv/riscv-profiles/blob/main/src/profiles.adoc
//	GOWASM
//		For GOARCH=wasm, comma-separated list of experimental WebAssembly features to use.
//		Valid values are satconv, signext.
//
// Environment variables for use with code coverage:
//
//	GOCOVERDIR
//		Directory into which to write code coverage data files
//		generated by running a "go build -cover" binary.
//		Requires that GOEXPERIMENT=coverageredesign is enabled.
//
// Special-purpose environment variables:
//
//	GCCGOTOOLDIR
//		If set, where to find gccgo tools, such as cgo.
//		The default is based on how gccgo was configured.
//	GOEXPERIMENT
//		Comma-separated list of toolchain experiments to enable or disable.
//		The list of available experiments may change arbitrarily over time.
//		See GOROOT/src/internal/goexperiment/flags.go for currently valid values.
//		Warning: This variable is provided for the development and testing
//		of the Go toolchain itself. Use beyond that purpose is unsupported.
//	GOFIPS140
//		The FIPS-140 cryptography mode to use when building binaries.
//		The default is GOFIPS140=off, which makes no FIPS-140 changes at all.
//		Other values enable FIPS-140 compliance measures and select alternate
//		versions of the cryptography source code.
//		See https://go.dev/security/fips140 for details.
//	GO_EXTLINK_ENABLED
//		Whether the linker should use external linking mode
//		when using -linkmode=auto with code that uses cgo.
//		Set to 0 to disable external linking mode, 1 to enable it.
//	GIT_ALLOW_PROTOCOL
//		Defined by Git. A colon-separated list of schemes that are allowed
//		to be used with git fetch/clone. If set, any scheme not explicitly
//		mentioned will be considered insecure by 'go get'.
//		Because the variable is defined by Git, the default value cannot
//		be set using 'go env -w'.
//
// Additional information available from 'go env' but not read from the environment:
//
//	GOEXE
//		The executable file name suffix (".exe" on Windows, "" on other systems).
//	GOGCCFLAGS
//		A space-separated list of arguments supplied to the CC command.
//	GOHOSTARCH
//		The architecture (GOARCH) of the Go toolchain binaries.
//	GOHOSTOS
//		The operating system (GOOS) of the Go toolchain binaries.
//	GOMOD
//		The absolute path to the go.mod of the main module.
//		If module-aware mode is enabled, but there is no go.mod, GOMOD will be
//		os.DevNull ("/dev/null" on Unix-like systems, "NUL" on Windows).
//		If module-aware mode is disabled, GOMOD will be the empty string.
//	GOTELEMETRY
//		The current Go telemetry mode ("off", "local", or "on").
//		See "go help telemetry" for more information.
//	GOTELEMETRYDIR
//		The directory Go telemetry data is written is written to.
//	GOTOOLDIR
//		The directory where the go tools (compile, cover, doc, etc...) are installed.
//	GOVERSION
//		The version of the installed Go tree, as reported by runtime.Version.
//
// # File types
//
// The go command examines the contents of a restricted set of files
// in each directory. It identifies which files to examine based on
// the extension of the file name. These extensions are:
//
//	.go
//		Go source files.
//	.c, .h
//		C source files.
//		If the package uses cgo or SWIG, these will be compiled with the
//		OS-native compiler (typically gcc); otherwise they will
//		trigger an error.
//	.cc, .cpp, .cxx, .hh, .hpp, .hxx
//		C++ source files. Only useful with cgo or SWIG, and always
//		compiled with the OS-native compiler.
//	.m
//		Objective-C source files. Only useful with cgo, and always
//		compiled with the OS-native compiler.
//	.s, .S, .sx
//		Assembler source files.
//		If the package uses cgo or SWIG, these will be assembled with the
//		OS-native assembler (typically gcc (sic)); otherwise they
//		will be assembled with the Go assembler.
//	.swig, .swigcxx
//		SWIG definition files.
//	.syso
//		System object files.
//
// Files of each of these types except .syso may contain build
// constraints, but the go command stops scanning for build constraints
// at the first item in the file that is not a blank line or //-style
// line comment. See the go/build package documentation for
// more details.
//
// # GOAUTH environment variable
//
// GOAUTH is a semicolon-separated list of authentication commands for go-import and
// HTTPS module mirror interactions. The default is netrc.
//
// The supported authentication commands are:
//
// off
//
//	Disables authentication.
//
// netrc
//
//	Uses credentials from NETRC or the .netrc file in your home directory.
//
// git dir
//
//	Runs 'git credential fill' in dir and uses its credentials. The
//	go command will run 'git credential approve/reject' to update
//	the credential helper's cache.
//
// command
//
//	Executes the given command (a space-separated argument list) and attaches
//	the provided headers to HTTPS requests.
//	The command must produce output in the following format:
//		Response      = { CredentialSet } .
//		CredentialSet = URLLine { URLLine } BlankLine { HeaderLine } BlankLine .
//		URLLine       = /* URL that starts with "https://" */ '\n' .
//		HeaderLine    = /* HTTP Request header */ '\n' .
//		BlankLine     = '\n' .
//
//	Example:
//		https://example.com/
//		https://example.net/api/
//
//		Authorization: Basic <token>
//
//		https://another-example.org/
//
//		Example: Data
//
//	If the server responds with any 4xx code, the go command will write the
//	following to the programs' stdin:
//		Response      = StatusLine { HeaderLine } BlankLine .
//		StatusLine    = Protocol Space Status '\n' .
//		Protocol      = /* HTTP protocol */ .
//		Space         = ' ' .
//		Status        = /* HTTP status code */ .
//		BlankLine     = '\n' .
//		HeaderLine    = /* HTTP Response's header */ '\n' .
//
//	Example:
//		HTTP/1.1 401 Unauthorized
//		Content-Length: 19
//		Content-Type: text/plain; charset=utf-8
//		Date: Thu, 07 Nov 2024 18:43:09 GMT
//
//	Note: at least for HTTP 1.1, the contents written to stdin can be parsed
//	as an HTTP response.
//
// Before the first HTTPS fetch, the go command will invoke each GOAUTH
// command in the list with no additional arguments and no input.
// If the server responds with any 4xx code, the go command will invoke the
// GOAUTH commands again with the URL as an additional command-line argument
// and the HTTP Response to the program's stdin.
// If the server responds with an error again, the fetch fails: a URL-specific
// GOAUTH will only be attempted once per fetch.
//
// # The go.mod file
//
// A module version is defined by a tree of source files, with a go.mod
// file in its root. When the go command is run, it looks in the current
// directory and then successive parent directories to find the go.mod
// marking the root of the main (current) module.
//
// The go.mod file format is described in detail at
// https://golang.org/ref/mod#go-mod-file.
//
// To create a new go.mod file, use 'go mod init'. For details see
// 'go help mod init' or https://golang.org/ref/mod#go-mod-init.
//
// To add missing module requirements or remove unneeded requirements,
// use 'go mod tidy'. For details, see 'go help mod tidy' or
// https://golang.org/ref/mod#go-mod-tidy.
//
// To add, upgrade, downgrade, or remove a specific module requirement, use
// 'go get'. For details, see 'go help module-get' or
// https://golang.org/ref/mod#go-get.
//
// To make other changes or to parse go.mod as JSON for use by other tools,
// use 'go mod edit'. See 'go help mod edit' or
// https://golang.org/ref/mod#go-mod-edit.
//
// # GOPATH environment variable
//
// The Go path is used to resolve import statements.
// It is implemented by and documented in the go/build package.
//
// The GOPATH environment variable lists places to look for Go code.
// On Unix, the value is a colon-separated string.
// On Windows, the value is a semicolon-separated string.
// On Plan 9, the value is a list.
//
// If the environment variable is unset, GOPATH defaults
// to a subdirectory named "go" in the user's home directory
// ($HOME/go on Unix, %USERPROFILE%\go on Windows),
// unless that directory holds a Go distribution.
// Run "go env GOPATH" to see the current GOPATH.
//
// See https://golang.org/wiki/SettingGOPATH to set a custom GOPATH.
//
// Each directory listed in GOPATH must have a prescribed structure:
//
// The src directory holds source code. The path below src
// determines the import path or executable name.
//
// The pkg directory holds installed package objects.
// As in the Go tree, each target operating system and
// architecture pair has its own subdirectory of pkg
// (pkg/GOOS_GOARCH).
//
// If DIR is a directory listed in the GOPATH, a package with
// source in DIR/src/foo/bar can be imported as "foo/bar" and
// has its compiled form installed to "DIR/pkg/GOOS_GOARCH/foo/bar.a".
//
// The bin directory holds compiled commands.
// Each command is named for its source directory, but only
// the final element, not the entire path. That is, the
// command with source in DIR/src/foo/quux is installed into
// DIR/bin/quux, not DIR/bin/foo/quux. The "foo/" prefix is stripped
// so that you can add DIR/bin to your PATH to get at the
// installed commands. If the GOBIN environment variable is
// set, commands are installed to the directory it names instead
// of DIR/bin. GOBIN must be an absolute path.
//
// Here's an example directory layout:
//
//	GOPATH=/home/user/go
//
//	/home/user/go/
//	    src/
//	        foo/
//	            bar/               (go code in package bar)
//	                x.go
//	            quux/              (go code in package main)
//	                y.go
//	    bin/
//	        quux                   (installed command)
//	    pkg/
//	        linux_amd64/
//	            foo/
//	                bar.a          (installed package object)
//
// Go searches each directory listed in GOPATH to find source code,
// but new packages are always downloaded into the first directory
// in the list.
//
// See https://golang.org/doc/code.html for an example.
//
// # GOPATH and Modules
//
// When using modules, GOPATH is no longer used for resolving imports.
// However, it is still used to store downloaded source code (in GOPATH/pkg/mod)
// and compiled commands (in GOPATH/bin).
//
// # Internal Directories
//
// Code in or below a directory named "internal" is importable only
// by code in the directory tree rooted at the parent of "internal".
// Here's an extended version of the directory layout above:
//
//	/home/user/go/
//	    src/
//	        crash/
//	            bang/              (go code in package bang)
//	                b.go
//	        foo/                   (go code in package foo)
//	            f.go
//	            bar/               (go code in package bar)
//	                x.go
//	            internal/
//	                baz/           (go code in package baz)
//	                    z.go
//	            quux/              (go code in package main)
//	                y.go
//
// The code in z.go is imported as "foo/internal/baz", but that
// import statement can only appear in source files in the subtree
// rooted at foo. The source files foo/f.go, foo/bar/x.go, and
// foo/quux/y.go can all import "foo/internal/baz", but the source file
// crash/bang/b.go cannot.
//
// See https://golang.org/s/go14internal for details.
//
// # Vendor Directories
//
// Go 1.6 includes support for using local copies of external dependencies
// to satisfy imports of those dependencies, often referred to as vendoring.
//
// Code below a directory named "vendor" is importable only
// by code in the directory tree rooted at the parent of "vendor",
// and only using an import path that omits the prefix up to and
// including the vendor element.
//
// Here's the example from the previous section,
// but with the "internal" directory renamed to "vendor"
// and a new foo/vendor/crash/bang directory added:
//
//	/home/user/go/
//	    src/
//	        crash/
//	            bang/              (go code in package bang)
//	                b.go
//	        foo/                   (go code in package foo)
//	            f.go
//	            bar/               (go code in package bar)
//	                x.go
//	            vendor/
//	                crash/
//	                    bang/      (go code in package bang)
//	                        b.go
//	                baz/           (go code in package baz)
//	                    z.go
//	            quux/              (go code in package main)
//	                y.go
//
// The same visibility rules apply as for internal, but the code
// in z.go is imported as "baz", not as "foo/vendor/baz".
//
// Code in vendor directories deeper in the source tree shadows
// code in higher directories. Within the subtree rooted at foo, an import
// of "crash/bang" resolves to "foo/vendor/crash/bang", not the
// top-level "crash/bang".
//
// Code in vendor directories is not subject to import path
// checking (see 'go help importpath').
//
// When 'go get' checks out or updates a git repository, it now also
// updates submodules.
//
// Vendor directories do not affect the placement of new repositories
// being checked out for the first time by 'go get': those are always
// placed in the main GOPATH, never in a vendor subtree.
//
// See https://golang.org/s/go15vendor for details.
//
// # Module proxy protocol
//
// A Go module proxy is any web server that can respond to GET requests for
// URLs of a specified form. The requests have no query parameters, so even
// a site serving from a fixed file system (including a file:/// URL)
// can be a module proxy.
//
// For details on the GOPROXY protocol, see
// https://golang.org/ref/mod#goproxy-protocol.
//
// # Import path syntax
//
// An import path (see 'go help packages') denotes a package stored in the local
// file system. In general, an import path denotes either a standard package (such
// as "unicode/utf8") or a package found in one of the work spaces (For more
// details see: 'go help gopath').
//
// # Relative import paths
//
// An import path beginning with ./ or ../ is called a relative path.
// The toolchain supports relative import paths as a shortcut in two ways.
//
// First, a relative path can be used as a shorthand on the command line.
// If you are working in the directory containing the code imported as
// "unicode" and want to run the tests for "unicode/utf8", you can type
// "go test ./utf8" instead of needing to specify the full path.
// Similarly, in the reverse situation, "go test .." will test "unicode" from
// the "unicode/utf8" directory. Relative patterns are also allowed, like
// "go test ./..." to test all subdirectories. See 'go help packages' for details
// on the pattern syntax.
//
// Second, if you are compiling a Go program not in a work space,
// you can use a relative path in an import statement in that program
// to refer to nearby code also not in a work space.
// This makes it easy to experiment with small multipackage programs
// outside of the usual work spaces, but such programs cannot be
// installed with "go install" (there is no work space in which to install them),
// so they are rebuilt from scratch each time they are built.
// To avoid ambiguity, Go programs cannot use relative import paths
// within a work space.
//
// # Remote import paths
//
// Certain import paths also
// describe how to obtain the source code for the package using
// a revision control system.
//
// A few common code hosting sites have special syntax:
//
//	Bitbucket (Git, Mercurial)
//
//		import "bitbucket.org/user/project"
//		import "bitbucket.org/user/project/sub/directory"
//
//	GitHub (Git)
//
//		import "github.com/user/project"
//		import "github.com/user/project/sub/directory"
//
//	Launchpad (Bazaar)
//
//		import "launchpad.net/project"
//		import "launchpad.net/project/series"
//		import "launchpad.net/project/series/sub/directory"
//
//		import "launchpad.net/~user/project/branch"
//		import "launchpad.net/~user/project/branch/sub/directory"
//
//	IBM DevOps Services (Git)
//
//		import "hub.jazz.net/git/user/project"
//		import "hub.jazz.net/git/user/project/sub/directory"
//
// For code hosted on other servers, import paths may either be qualified
// with the version control type, or the go tool can dynamically fetch
// the import path over https/http and discover where the code resides
// from a <meta> tag in the HTML.
//
// To declare the code location, an import path of the form
//
//	repository.vcs/path
//
// specifies the given repository, with or without the .vcs suffix,
// using the named version control system, and then the path inside
// that repository. The supported version control systems are:
//
//	Bazaar      .bzr
//	Fossil      .fossil
//	Git         .git
//	Mercurial   .hg
//	Subversion  .svn
//
// For example,
//
//	import "example.org/user/foo.hg"
//
// denotes the root directory of the Mercurial repository at
// example.org/user/foo or foo.hg, and
//
//	import "example.org/repo.git/foo/bar"
//
// denotes the foo/bar directory of the Git repository at
// example.org/repo or repo.git.
//
// When a version control system supports multiple protocols,
// each is tried in turn when downloading. For example, a Git
// download tries https://, then git+ssh://.
//
// By default, downloads are restricted to known secure protocols
// (e.g. https, ssh). To override this setting for Git downloads, the
// GIT_ALLOW_PROTOCOL environment variable can be set (For more details see:
// 'go help environment').
//
// If the import path is not a known code hosting site and also lacks a
// version control qualifier, the go tool attempts to fetch the import
// over https/http and looks for a <meta> tag in the document's HTML
// <head>.
//
// The meta tag has the form:
//
//	<meta name="go-import" content="import-prefix vcs repo-root">
//
// The import-prefix is the import path corresponding to the repository
// root. It must be a prefix or an exact match of the package being
// fetched with "go get". If it's not an exact match, another http
// request is made at the prefix to verify the <meta> tags match.
//
// The meta tag should appear as early in the file as possible.
// In particular, it should appear before any raw JavaScript or CSS,
// to avoid confusing the go command's restricted parser.
//
// The vcs is one of "bzr", "fossil", "git", "hg", "svn".
//
// The repo-root is the root of the version control system
// containing a scheme and not containing a .vcs qualifier.
//
// For example,
//
//	import "example.org/pkg/foo"
//
// will result in the following requests:
//
//	https://example.org/pkg/foo?go-get=1 (preferred)
//	http://example.org/pkg/foo?go-get=1  (fallback, only with use of correctly set GOINSECURE)
//
// If that page contains the meta tag
//
//	<meta name="go-import" content="example.org git https://code.org/r/p/exproj">
//
// the go tool will verify that https://example.org/?go-get=1 contains the
// same meta tag and then git clone https://code.org/r/p/exproj into
// GOPATH/src/example.org.
//
// When using GOPATH, downloaded packages are written to the first directory
// listed in the GOPATH environment variable.
// (See 'go help gopath-get' and 'go help gopath'.)
//
// When using modules, downloaded packages are stored in the module cache.
// See https://golang.org/ref/mod#module-cache.
//
// When using modules, an additional variant of the go-import meta tag is
// recognized and is preferred over those listing version control systems.
// That variant uses "mod" as the vcs in the content value, as in:
//
//	<meta name="go-import" content="example.org mod https://code.org/moduleproxy">
//
// This tag means to fetch modules with paths beginning with example.org
// from the module proxy available at the URL https://code.org/moduleproxy.
// See https://golang.org/ref/mod#goproxy-protocol for details about the
// proxy protocol.
//
// # Import path checking
//
// When the custom import path feature described above redirects to a
// known code hosting site, each of the resulting packages has two possible
// import paths, using the custom domain or the known hosting site.
//
// A package statement is said to have an "import comment" if it is immediately
// followed (before the next newline) by a comment of one of these two forms:
//
//	package math // import "path"
//	package math /* import "path" */
//
// The go command will refuse to install a package with an import comment
// unless it is being referred to by that import path. In this way, import comments
// let package authors make sure the custom import path is used and not a
// direct path to the underlying code hosting site.
//
// Import path checking is disabled for code found within vendor trees.
// This makes it possible to copy code into alternate locations in vendor trees
// without needing to update import comments.
//
// Import path checking is also disabled when using modules.
// Import path comments are obsoleted by the go.mod file's module statement.
//
// See https://golang.org/s/go14customimport for details.
//
// # Modules, module versions, and more
//
// Modules are how Go manages dependencies.
//
// A module is a collection of packages that are released, versioned, and
// distributed together. Modules may be downloaded directly from version control
// repositories or from module proxy servers.
//
// For a series of tutorials on modules, see
// https://golang.org/doc/tutorial/create-module.
//
// For a detailed reference on modules, see https://golang.org/ref/mod.
//
// By default, the go command may download modules from https://proxy.golang.org.
// It may authenticate modules using the checksum database at
// https://sum.golang.org. Both services are operated by the Go team at Google.
// The privacy policies for these services are available at
// https://proxy.golang.org/privacy and https://sum.golang.org/privacy,
// respectively.
//
// The go command's download behavior may be configured using GOPROXY, GOSUMDB,
// GOPRIVATE, and other environment variables. See 'go help environment'
// and https://golang.org/ref/mod#private-module-privacy for more information.
//
// # Module authentication using go.sum
//
// When the go command downloads a module zip file or go.mod file into the
// module cache, it computes a cryptographic hash and compares it with a known
// value to verify the file hasn't changed since it was first downloaded. Known
// hashes are stored in a file in the module root directory named go.sum. Hashes
// may also be downloaded from the checksum database depending on the values of
// GOSUMDB, GOPRIVATE, and GONOSUMDB.
//
// For details, see https://golang.org/ref/mod#authenticating.
//
// # Package lists and patterns
//
// Many commands apply to a set of packages:
//
//	go <action> [packages]
//
// Usually, [packages] is a list of import paths.
//
// An import path that is a rooted path or that begins with
// a . or .. element is interpreted as a file system path and
// denotes the package in that directory.
//
// Otherwise, the import path P denotes the package found in
// the directory DIR/src/P for some DIR listed in the GOPATH
// environment variable (For more details see: 'go help gopath').
//
// If no import paths are given, the action applies to the
// package in the current directory.
//
// There are five reserved names for paths that should not be used
// for packages to be built with the go tool:
//
// - "main" denotes the top-level package in a stand-alone executable.
//
// - "all" expands to all packages in the main module (or workspace modules) and
// their dependencies, including dependencies needed by tests of any of those. In
// GOPATH mode, "all" expands to all packages found in all the GOPATH trees.
//
// - "std" is like all but expands to just the packages in the standard
// Go library.
//
// - "cmd" expands to the Go repository's commands and their
// internal libraries.
//
// - "tool" expands to the tools defined in the current module's go.mod file.
//
// Package names match against fully-qualified import paths or patterns that
// match against any number of import paths. For instance, "fmt" refers to the
// standard library's package fmt, but "http" alone for package http would not
// match the import path "net/http" from the standard library. Instead, the
// complete import path "net/http" must be used.
//
// Import paths beginning with "cmd/" only match source code in
// the Go repository.
//
// An import path is a pattern if it includes one or more "..." wildcards,
// each of which can match any string, including the empty string and
// strings containing slashes. Such a pattern expands to all package
// directories found in the GOPATH trees with names matching the
// patterns.
//
// To make common patterns more convenient, there are two special cases.
// First, /... at the end of the pattern can match an empty string,
// so that net/... matches both net and packages in its subdirectories, like net/http.
// Second, any slash-separated pattern element containing a wildcard never
// participates in a match of the "vendor" element in the path of a vendored
// package, so that ./... does not match packages in subdirectories of
// ./vendor or ./mycode/vendor, but ./vendor/... and ./mycode/vendor/... do.
// Note, however, that a directory named vendor that itself contains code
// is not a vendored package: cmd/vendor would be a command named vendor,
// and the pattern cmd/... matches it.
// See golang.org/s/go15vendor for more about vendoring.
//
// An import path can also name a package to be downloaded from
// a remote repository. Run 'go help importpath' for details.
//
// Every package in a program must have a unique import path.
// By convention, this is arranged by starting each path with a
// unique prefix that belongs to you. For example, paths used
// internally at Google all begin with 'google', and paths
// denoting remote repositories begin with the path to the code,
// such as 'github.com/user/repo'. Package patterns should include this prefix.
// For instance, a package called 'http' residing under 'github.com/user/repo',
// would be addressed with the fully-qualified
```