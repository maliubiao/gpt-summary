Response:
Let's break down the thought process to analyze the provided Go documentation snippet.

**1. Initial Read-Through & Keyword Identification:**

The first step is to read through the text to get a general understanding. I'm looking for keywords and phrases that indicate the topic being discussed. Some immediately stand out:

* `go-get` (appears multiple times)
* `meta tag`
* `go-import`
* `GOPATH`
* `modules` (frequent mention)
* `go.mod`
* `require`
* `go get`
* `go mod`
* `vendor`
* `checksum`
* `GOPROXY`
* `GOPRIVATE`
* `Package lists and patterns`

These keywords strongly suggest the section is about how `go get` and the module system work, including dependency management, downloading packages, and how to handle custom import paths.

**2. Section Segmentation and Topic Identification:**

I can start to break down the text into logical sections based on the keywords and the flow of information:

* **Custom Import Paths and `go-get`:** The initial paragraphs discuss how the `go get` command resolves import paths that don't directly map to a known code hosting site. The `go-import` meta tag and the fallback mechanism are key here.
* **GOPATH vs. Modules:**  The text clearly distinguishes between the older GOPATH-based approach and the newer module-based approach for dependency management.
* **Module Basics:**  This covers creating `go.mod` files, the `module` and `require` directives, and the concept of a module path.
* **Main Module and Build List:** Explanation of the main module, how dependencies are resolved, and the concept of the build list.
* **Maintaining Module Requirements:** How `go mod tidy` and `go get` update the `go.mod` file.
* **`-mod` build flag:** Details on the different behaviors controlled by the `-mod` flag (`readonly`, `vendor`, `mod`).
* **Pseudo-versions:** Explanation of how to refer to untagged commits.
* **Module Queries:**  How to specify versions using semantic versioning and other query syntax in `go get` and `go.mod`.
* **Module Compatibility and Semantic Versioning:** The importance of semantic versions, the import compatibility rule, and semantic import versioning (major version in the path for v2+).
* **Module Downloading and Verification:**  How `go get` downloads modules using proxies (GOPROXY), the role of the checksum database (GOSUMDB), and how verification works.
* **Modules and Vendoring:** The purpose and usage of the `vendor` directory and the `go mod vendor` command.
* **Module Authentication using go.sum:** Details about the `go.sum` file and how it's used for verifying module integrity.
* **Module Configuration for Non-Public Modules:** Explanation of `GOPRIVATE`, `GONOPROXY`, and `GONOSUMDB` for handling private modules.
* **Package Lists and Patterns:** How to specify packages for commands like `go build` and `go test`, including wildcards.

**3. Identifying the Core Functionality:**

The central theme of this section is **package management and dependency resolution in Go**. It covers:

* **Resolving import paths:**  Both standard paths and custom domain names.
* **Dependency management:**  Using either GOPATH or modules (with a strong emphasis on modules).
* **Version control:**  Specifying and managing module versions.
* **Downloading packages:** How `go get` retrieves packages from various sources.
* **Ensuring build reproducibility and security:**  Through the use of `go.sum` and checksum verification.
* **Handling private modules:**  Configuration options for non-public code.

**4. Inferring the Go Language Feature:**

Based on the keywords and functionality, the core Go language feature being described is the **Go module system**. While it also touches upon the older GOPATH approach, the emphasis is clearly on modules as the modern and preferred way to manage dependencies.

**5. Code Example (Illustrative):**

To illustrate the module system, a simple example would involve creating a `go.mod` file and adding a dependency:

```go
// Assuming you are in a new project directory
// Run: go mod init myproject

// myproject/main.go
package main

import (
	"fmt"

	"github.com/google/uuid" // This will trigger the module system
)

func main() {
	id := uuid.New()
	fmt.Println("Generated UUID:", id)
}
```

**Assumptions:**

* You have Go installed.
* You are in a directory where you want to create the project.

**Input:** Running `go run main.go` for the first time.

**Output:**

```
go: finding module for package github.com/google/uuid
go: downloading github.com/google/uuid v1.3.0
go: found github.com/google/uuid v1.3.0
Generated UUID: some-uuid-here
```

This example demonstrates how the `go` command automatically fetches and manages the `github.com/google/uuid` dependency when it's imported in the code. The `go.mod` file would be updated to include this dependency.

**6. Command-Line Argument Handling:**

The text mentions several commands and flags:

* `go get`: Downloads packages and updates `go.mod`. Handles `@` notation for version specifications.
* `go mod init`: Creates a `go.mod` file.
* `go build`: Builds Go programs, automatically managing dependencies.
* `go test`: Runs tests, also managing dependencies.
* `go list`:  Provides information about packages and modules (e.g., `go list -m all`).
* `go mod tidy`: Cleans up the `go.mod` file.
* `go mod vendor`: Creates the `vendor` directory.
* `go mod verify`: Verifies cached module downloads against `go.sum`.
* `-mod` flag (`readonly`, `vendor`, `mod`): Controls how the `go` command interacts with modules and the vendor directory.
* `-insecure` flag with `go get`: Bypasses HTTPS and checksum verification (use with caution).

**7. Potential Pitfalls:**

* **Mixing GOPATH and Modules:**  Users might be confused about when modules are active and when GOPATH is used. The `GO111MODULE` environment variable adds complexity.
* **Incorrect `go.mod` Edits:** Manually editing `go.mod` without understanding its syntax can lead to errors. It's generally better to use `go get` and `go mod` commands.
* **Checksum Mismatches:**  Users might not understand the security implications of `go.sum` mismatches and might be tempted to disable checksum verification without investigation.
* **Private Module Configuration:**  Setting up `GOPRIVATE`, `GONOPROXY`, and `GONOSUMDB` correctly for private repositories can be confusing.

**8. Self-Correction/Refinement:**

Initially, I might have focused too much on just `go get`. However, as I analyzed the text further, it became clear that the broader topic is the entire Go module ecosystem. The various commands and flags work together to provide a comprehensive solution for dependency management. Also, the emphasis on security (checksums) is an important aspect to highlight.

By following these steps, I arrived at the detailed analysis provided in the initial good answer, covering the functionalities, the underlying feature, code examples, command-line arguments, and potential pitfalls.
这是 `go/src/cmd/go/alldocs-1.go` 文件的第四部分，主要涵盖了 Go 语言的 **模块（Modules）** 功能的详细介绍，并涉及到与模块相关的各种操作、概念和配置。

**功能归纳：**

这部分文档的主要功能是 **全面解释 Go 语言的模块系统**。它从模块的基本概念开始，逐步深入到模块的使用方法、依赖管理、版本控制、下载验证、以及与旧有 GOPATH 模式的对比和过渡。

**它是什么 Go 语言功能的实现：**

这部分文档描述的是 Go 语言中用于 **依赖管理和版本控制** 的核心功能：**Go Modules**。

**Go 代码举例说明：**

**场景：** 创建一个新的 Go 模块并添加一个依赖。

**假设输入：**

1. 在一个空目录下执行 `go mod init example.com/myproject`
2. 创建一个 `main.go` 文件，导入 `github.com/google/uuid` 包。

**main.go 内容：**

```go
package main

import (
	"fmt"

	"github.com/google/uuid"
)

func main() {
	id := uuid.New()
	fmt.Println("Generated UUID:", id)
}
```

**执行命令：** `go run main.go`

**输出：**

```
go: finding module for package github.com/google/uuid
go: downloading github.com/google/uuid v1.3.0
go: found github.com/google/uuid v1.3.0
Generated UUID: a1b2c3d4-e5f6-7890-1234-567890abcdef // 具体的 UUID 会不同
```

**代码推理：**

1. `go mod init example.com/myproject` 命令初始化了一个新的模块，创建了一个 `go.mod` 文件，声明了模块的路径为 `example.com/myproject`。
2. `main.go` 中导入了 `github.com/google/uuid` 包，这是一个外部依赖。
3. 执行 `go run main.go` 时，Go 工具链会检测到该依赖项。由于 `go.mod` 中没有记录该依赖，它会自动查找并下载 `github.com/google/uuid` 的最新版本（或者根据其他配置，如 `go get` 的版本指定）。
4. 下载完成后，`go.mod` 文件会被更新，添加了 `require github.com/google/uuid v1.3.0` (版本号可能会变化) 这样的条目。
5. 同时，`go.sum` 文件也会被更新，记录了 `github.com/google/uuid` 的校验和，用于后续验证依赖的完整性。

**命令行参数的具体处理：**

这部分文档详细介绍了与模块相关的多个命令行参数和环境变量：

*   **`go mod init [module path]`**: 初始化一个新的模块，创建 `go.mod` 文件。`module path` 指定了模块的路径。
*   **`go get [-u] [package@version]`**:  用于添加、更新或降级模块的依赖。
    *   不指定版本时，默认获取最新版本。
    *   可以使用 `@` 符号指定版本，例如 `@latest`, `@v1.2.3`, `@commit-hash`, `@branch-name`。
    *   `-u` 标志用于更新依赖项。
*   **`go mod tidy`**: 清理 `go.mod` 文件，移除不再需要的依赖，添加缺失的依赖。
*   **`go mod vendor`**: 将项目依赖复制到项目的 `vendor` 目录下。
*   **`go mod verify`**: 验证本地缓存的模块是否与 `go.sum` 文件中的校验和匹配。
*   **`go list -m [all|path]`**: 列出模块信息。
    *   `go list -m`: 显示主模块的路径。
    *   `go list -m all`: 显示构建列表中的所有模块。
*   **`-mod=[readonly|vendor|mod]` 构建标志**: 控制 `go` 命令如何处理模块。
    *   `-mod=readonly`: 禁止自动更新 `go.mod`，如果需要更新则会报错。
    *   `-mod=vendor`: 从 `vendor` 目录加载包，而不是从模块缓存。
    *   `-mod=mod`: 从模块缓存加载包，即使存在 `vendor` 目录。
*   **`GO111MODULE=[off|on|auto]` 环境变量**: 控制是否启用模块支持。
    *   `on`: 强制使用模块，忽略 GOPATH。
    *   `off`: 禁用模块，使用 GOPATH。
    *   `auto` (默认):  在包含 `go.mod` 文件的目录或其子目录中启用模块。
*   **`GOPATH` 环境变量**:  定义了 Go 工作区，在非模块模式下用于查找包。在模块模式下，仍然用于存储下载的依赖（在 `GOPATH/pkg/mod` 中）和安装的命令（在 `GOPATH/bin` 中，除非设置了 `GOBIN`）。
*   **`GOPROXY` 环境变量**:  指定模块代理的 URL，用于下载模块。默认为 `https://proxy.golang.org,direct`。
*   **`GOPRIVATE` 环境变量**:  指定哪些模块被认为是私有的，不应通过公共代理下载或校验。
*   **`GONOPROXY` 环境变量**:  更细粒度地控制哪些模块不使用代理下载。
*   **`GOSUMDB` 环境变量**:  指定 Go 校验和数据库的名称和公钥。默认为 `sum.golang.org`。
*   **`GONOSUMDB` 环境变量**:  更细粒度地控制哪些模块不进行校验和验证。

**使用者易犯错的点：**

*   **混淆模块模式和 GOPATH 模式：**  不理解 `GO111MODULE` 的作用，导致在不同的项目或环境下行为不一致。例如，在一个包含 `go.mod` 的项目中使用依赖，可能会自动下载并更新 `go.mod`，但在没有 `go.mod` 的项目中则需要在 `GOPATH` 中手动管理。
*   **手动编辑 `go.mod` 导致不一致：**  直接修改 `go.mod` 文件而不使用 `go get` 或 `go mod` 命令，可能导致依赖版本不匹配或者格式错误。
*   **不理解 `go.sum` 的作用：**  忽略 `go.sum` 文件或在出现校验和错误时不进行排查，可能导致构建不稳定或者引入安全风险。
*   **对版本控制理解不足：**  不了解语义版本控制 (Semantic Versioning) 的含义，随意升级或降级依赖，可能导致兼容性问题。
*   **私有模块配置错误：**  未能正确配置 `GOPRIVATE` 等环境变量，导致私有模块下载失败或被公开代理处理。
*   **误用 `-mod=vendor`：**  在不了解其含义的情况下使用 `-mod=vendor`，可能会导致构建使用过时的 `vendor` 目录，而不是最新的依赖。

**总结：**

这部分文档是关于 Go 语言模块功能的权威解释。它涵盖了模块的定义、使用、依赖管理、版本控制、下载验证以及与旧有系统的对比。理解这部分内容对于有效地使用 Go 语言进行项目开发至关重要，特别是对于涉及外部依赖的项目。它强调了使用模块进行依赖管理的好处，例如可重复构建、版本控制和更好的依赖隔离。

Prompt: 
```
这是路径为go/src/cmd/go/alldocs-1.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第4部分，共5部分，请归纳一下它的功能

"""
 "example.org/pkg/foo"
//
// will result in the following requests:
//
// 	https://example.org/pkg/foo?go-get=1 (preferred)
// 	http://example.org/pkg/foo?go-get=1  (fallback, only with -insecure)
//
// If that page contains the meta tag
//
// 	<meta name="go-import" content="example.org git https://code.org/r/p/exproj">
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
// (See 'go help module-get' and 'go help goproxy'.)
//
// When using modules, an additional variant of the go-import meta tag is
// recognized and is preferred over those listing version control systems.
// That variant uses "mod" as the vcs in the content value, as in:
//
// 	<meta name="go-import" content="example.org mod https://code.org/moduleproxy">
//
// This tag means to fetch modules with paths beginning with example.org
// from the module proxy available at the URL https://code.org/moduleproxy.
// See 'go help goproxy' for details about the proxy protocol.
//
// Import path checking
//
// When the custom import path feature described above redirects to a
// known code hosting site, each of the resulting packages has two possible
// import paths, using the custom domain or the known hosting site.
//
// A package statement is said to have an "import comment" if it is immediately
// followed (before the next newline) by a comment of one of these two forms:
//
// 	package math // import "path"
// 	package math /* import "path" */
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
//
// Modules, module versions, and more
//
// A module is a collection of related Go packages.
// Modules are the unit of source code interchange and versioning.
// The go command has direct support for working with modules,
// including recording and resolving dependencies on other modules.
// Modules replace the old GOPATH-based approach to specifying
// which source files are used in a given build.
//
// Module support
//
// The go command includes support for Go modules. Module-aware mode is active
// by default whenever a go.mod file is found in the current directory or in
// any parent directory.
//
// The quickest way to take advantage of module support is to check out your
// repository, create a go.mod file (described in the next section) there, and run
// go commands from within that file tree.
//
// For more fine-grained control, the go command continues to respect
// a temporary environment variable, GO111MODULE, which can be set to one
// of three string values: off, on, or auto (the default).
// If GO111MODULE=on, then the go command requires the use of modules,
// never consulting GOPATH. We refer to this as the command
// being module-aware or running in "module-aware mode".
// If GO111MODULE=off, then the go command never uses
// module support. Instead it looks in vendor directories and GOPATH
// to find dependencies; we now refer to this as "GOPATH mode."
// If GO111MODULE=auto or is unset, then the go command enables or disables
// module support based on the current directory.
// Module support is enabled only when the current directory contains a
// go.mod file or is below a directory containing a go.mod file.
//
// In module-aware mode, GOPATH no longer defines the meaning of imports
// during a build, but it still stores downloaded dependencies (in GOPATH/pkg/mod)
// and installed commands (in GOPATH/bin, unless GOBIN is set).
//
// Defining a module
//
// A module is defined by a tree of Go source files with a go.mod file
// in the tree's root directory. The directory containing the go.mod file
// is called the module root. Typically the module root will also correspond
// to a source code repository root (but in general it need not).
// The module is the set of all Go packages in the module root and its
// subdirectories, but excluding subtrees with their own go.mod files.
//
// The "module path" is the import path prefix corresponding to the module root.
// The go.mod file defines the module path and lists the specific versions
// of other modules that should be used when resolving imports during a build,
// by giving their module paths and versions.
//
// For example, this go.mod declares that the directory containing it is the root
// of the module with path example.com/m, and it also declares that the module
// depends on specific versions of golang.org/x/text and gopkg.in/yaml.v2:
//
// 	module example.com/m
//
// 	require (
// 		golang.org/x/text v0.3.0
// 		gopkg.in/yaml.v2 v2.1.0
// 	)
//
// The go.mod file can also specify replacements and excluded versions
// that only apply when building the module directly; they are ignored
// when the module is incorporated into a larger build.
// For more about the go.mod file, see 'go help go.mod'.
//
// To start a new module, simply create a go.mod file in the root of the
// module's directory tree, containing only a module statement.
// The 'go mod init' command can be used to do this:
//
// 	go mod init example.com/m
//
// In a project already using an existing dependency management tool like
// godep, glide, or dep, 'go mod init' will also add require statements
// matching the existing configuration.
//
// Once the go.mod file exists, no additional steps are required:
// go commands like 'go build', 'go test', or even 'go list' will automatically
// add new dependencies as needed to satisfy imports.
//
// The main module and the build list
//
// The "main module" is the module containing the directory where the go command
// is run. The go command finds the module root by looking for a go.mod in the
// current directory, or else the current directory's parent directory,
// or else the parent's parent directory, and so on.
//
// The main module's go.mod file defines the precise set of packages available
// for use by the go command, through require, replace, and exclude statements.
// Dependency modules, found by following require statements, also contribute
// to the definition of that set of packages, but only through their go.mod
// files' require statements: any replace and exclude statements in dependency
// modules are ignored. The replace and exclude statements therefore allow the
// main module complete control over its own build, without also being subject
// to complete control by dependencies.
//
// The set of modules providing packages to builds is called the "build list".
// The build list initially contains only the main module. Then the go command
// adds to the list the exact module versions required by modules already
// on the list, recursively, until there is nothing left to add to the list.
// If multiple versions of a particular module are added to the list,
// then at the end only the latest version (according to semantic version
// ordering) is kept for use in the build.
//
// The 'go list' command provides information about the main module
// and the build list. For example:
//
// 	go list -m              # print path of main module
// 	go list -m -f={{.Dir}}  # print root directory of main module
// 	go list -m all          # print build list
//
// Maintaining module requirements
//
// The go.mod file is meant to be readable and editable by both
// programmers and tools. The go command itself automatically updates the go.mod file
// to maintain a standard formatting and the accuracy of require statements.
//
// Any go command that finds an unfamiliar import will look up the module
// containing that import and add the latest version of that module
// to go.mod automatically. In most cases, therefore, it suffices to
// add an import to source code and run 'go build', 'go test', or even 'go list':
// as part of analyzing the package, the go command will discover
// and resolve the import and update the go.mod file.
//
// Any go command can determine that a module requirement is
// missing and must be added, even when considering only a single
// package from the module. On the other hand, determining that a module requirement
// is no longer necessary and can be deleted requires a full view of
// all packages in the module, across all possible build configurations
// (architectures, operating systems, build tags, and so on).
// The 'go mod tidy' command builds that view and then
// adds any missing module requirements and removes unnecessary ones.
//
// As part of maintaining the require statements in go.mod, the go command
// tracks which ones provide packages imported directly by the current module
// and which ones provide packages only used indirectly by other module
// dependencies. Requirements needed only for indirect uses are marked with a
// "// indirect" comment in the go.mod file. Indirect requirements are
// automatically removed from the go.mod file once they are implied by other
// direct requirements. Indirect requirements only arise when using modules
// that fail to state some of their own dependencies or when explicitly
// upgrading a module's dependencies ahead of its own stated requirements.
//
// Because of this automatic maintenance, the information in go.mod is an
// up-to-date, readable description of the build.
//
// The 'go get' command updates go.mod to change the module versions used in a
// build. An upgrade of one module may imply upgrading others, and similarly a
// downgrade of one module may imply downgrading others. The 'go get' command
// makes these implied changes as well. If go.mod is edited directly, commands
// like 'go build' or 'go list' will assume that an upgrade is intended and
// automatically make any implied upgrades and update go.mod to reflect them.
//
// The 'go mod' command provides other functionality for use in maintaining
// and understanding modules and go.mod files. See 'go help mod'.
//
// The -mod build flag provides additional control over updating and use of go.mod.
//
// If invoked with -mod=readonly, the go command is disallowed from the implicit
// automatic updating of go.mod described above. Instead, it fails when any changes
// to go.mod are needed. This setting is most useful to check that go.mod does
// not need updates, such as in a continuous integration and testing system.
// The "go get" command remains permitted to update go.mod even with -mod=readonly,
// and the "go mod" commands do not take the -mod flag (or any other build flags).
//
// If invoked with -mod=vendor, the go command loads packages from the main
// module's vendor directory instead of downloading modules to and loading packages
// from the module cache. The go command assumes the vendor directory holds
// correct copies of dependencies, and it does not compute the set of required
// module versions from go.mod files. However, the go command does check that
// vendor/modules.txt (generated by 'go mod vendor') contains metadata consistent
// with go.mod.
//
// If invoked with -mod=mod, the go command loads modules from the module cache
// even if there is a vendor directory present.
//
// If the go command is not invoked with a -mod flag and the vendor directory
// is present and the "go" version in go.mod is 1.14 or higher, the go command
// will act as if it were invoked with -mod=vendor.
//
// Pseudo-versions
//
// The go.mod file and the go command more generally use semantic versions as
// the standard form for describing module versions, so that versions can be
// compared to determine which should be considered earlier or later than another.
// A module version like v1.2.3 is introduced by tagging a revision in the
// underlying source repository. Untagged revisions can be referred to
// using a "pseudo-version" like v0.0.0-yyyymmddhhmmss-abcdefabcdef,
// where the time is the commit time in UTC and the final suffix is the prefix
// of the commit hash. The time portion ensures that two pseudo-versions can
// be compared to determine which happened later, the commit hash identifes
// the underlying commit, and the prefix (v0.0.0- in this example) is derived from
// the most recent tagged version in the commit graph before this commit.
//
// There are three pseudo-version forms:
//
// vX.0.0-yyyymmddhhmmss-abcdefabcdef is used when there is no earlier
// versioned commit with an appropriate major version before the target commit.
// (This was originally the only form, so some older go.mod files use this form
// even for commits that do follow tags.)
//
// vX.Y.Z-pre.0.yyyymmddhhmmss-abcdefabcdef is used when the most
// recent versioned commit before the target commit is vX.Y.Z-pre.
//
// vX.Y.(Z+1)-0.yyyymmddhhmmss-abcdefabcdef is used when the most
// recent versioned commit before the target commit is vX.Y.Z.
//
// Pseudo-versions never need to be typed by hand: the go command will accept
// the plain commit hash and translate it into a pseudo-version (or a tagged
// version if available) automatically. This conversion is an example of a
// module query.
//
// Module queries
//
// The go command accepts a "module query" in place of a module version
// both on the command line and in the main module's go.mod file.
// (After evaluating a query found in the main module's go.mod file,
// the go command updates the file to replace the query with its result.)
//
// A fully-specified semantic version, such as "v1.2.3",
// evaluates to that specific version.
//
// A semantic version prefix, such as "v1" or "v1.2",
// evaluates to the latest available tagged version with that prefix.
//
// A semantic version comparison, such as "<v1.2.3" or ">=v1.5.6",
// evaluates to the available tagged version nearest to the comparison target
// (the latest version for < and <=, the earliest version for > and >=).
//
// The string "latest" matches the latest available tagged version,
// or else the underlying source repository's latest untagged revision.
//
// The string "upgrade" is like "latest", but if the module is
// currently required at a later version than the version "latest"
// would select (for example, a newer pre-release version), "upgrade"
// will select the later version instead.
//
// The string "patch" matches the latest available tagged version
// of a module with the same major and minor version numbers as the
// currently required version. If no version is currently required,
// "patch" is equivalent to "latest".
//
// A revision identifier for the underlying source repository, such as
// a commit hash prefix, revision tag, or branch name, selects that
// specific code revision. If the revision is also tagged with a
// semantic version, the query evaluates to that semantic version.
// Otherwise the query evaluates to a pseudo-version for the commit.
// Note that branches and tags with names that are matched by other
// query syntax cannot be selected this way. For example, the query
// "v2" means the latest version starting with "v2", not the branch
// named "v2".
//
// All queries prefer release versions to pre-release versions.
// For example, "<v1.2.3" will prefer to return "v1.2.2"
// instead of "v1.2.3-pre1", even though "v1.2.3-pre1" is nearer
// to the comparison target.
//
// Module versions disallowed by exclude statements in the
// main module's go.mod are considered unavailable and cannot
// be returned by queries.
//
// For example, these commands are all valid:
//
// 	go get github.com/gorilla/mux@latest    # same (@latest is default for 'go get')
// 	go get github.com/gorilla/mux@v1.6.2    # records v1.6.2
// 	go get github.com/gorilla/mux@e3702bed2 # records v1.6.2
// 	go get github.com/gorilla/mux@c856192   # records v0.0.0-20180517173623-c85619274f5d
// 	go get github.com/gorilla/mux@master    # records current meaning of master
//
// Module compatibility and semantic versioning
//
// The go command requires that modules use semantic versions and expects that
// the versions accurately describe compatibility: it assumes that v1.5.4 is a
// backwards-compatible replacement for v1.5.3, v1.4.0, and even v1.0.0.
// More generally the go command expects that packages follow the
// "import compatibility rule", which says:
//
// "If an old package and a new package have the same import path,
// the new package must be backwards compatible with the old package."
//
// Because the go command assumes the import compatibility rule,
// a module definition can only set the minimum required version of one
// of its dependencies: it cannot set a maximum or exclude selected versions.
// Still, the import compatibility rule is not a guarantee: it may be that
// v1.5.4 is buggy and not a backwards-compatible replacement for v1.5.3.
// Because of this, the go command never updates from an older version
// to a newer version of a module unasked.
//
// In semantic versioning, changing the major version number indicates a lack
// of backwards compatibility with earlier versions. To preserve import
// compatibility, the go command requires that modules with major version v2
// or later use a module path with that major version as the final element.
// For example, version v2.0.0 of example.com/m must instead use module path
// example.com/m/v2, and packages in that module would use that path as
// their import path prefix, as in example.com/m/v2/sub/pkg. Including the
// major version number in the module path and import paths in this way is
// called "semantic import versioning". Pseudo-versions for modules with major
// version v2 and later begin with that major version instead of v0, as in
// v2.0.0-20180326061214-4fc5987536ef.
//
// As a special case, module paths beginning with gopkg.in/ continue to use the
// conventions established on that system: the major version is always present,
// and it is preceded by a dot instead of a slash: gopkg.in/yaml.v1
// and gopkg.in/yaml.v2, not gopkg.in/yaml and gopkg.in/yaml/v2.
//
// The go command treats modules with different module paths as unrelated:
// it makes no connection between example.com/m and example.com/m/v2.
// Modules with different major versions can be used together in a build
// and are kept separate by the fact that their packages use different
// import paths.
//
// In semantic versioning, major version v0 is for initial development,
// indicating no expectations of stability or backwards compatibility.
// Major version v0 does not appear in the module path, because those
// versions are preparation for v1.0.0, and v1 does not appear in the
// module path either.
//
// Code written before the semantic import versioning convention
// was introduced may use major versions v2 and later to describe
// the same set of unversioned import paths as used in v0 and v1.
// To accommodate such code, if a source code repository has a
// v2.0.0 or later tag for a file tree with no go.mod, the version is
// considered to be part of the v1 module's available versions
// and is given an +incompatible suffix when converted to a module
// version, as in v2.0.0+incompatible. The +incompatible tag is also
// applied to pseudo-versions derived from such versions, as in
// v2.0.1-0.yyyymmddhhmmss-abcdefabcdef+incompatible.
//
// In general, having a dependency in the build list (as reported by 'go list -m all')
// on a v0 version, pre-release version, pseudo-version, or +incompatible version
// is an indication that problems are more likely when upgrading that
// dependency, since there is no expectation of compatibility for those.
//
// See https://research.swtch.com/vgo-import for more information about
// semantic import versioning, and see https://semver.org/ for more about
// semantic versioning.
//
// Module code layout
//
// For now, see https://research.swtch.com/vgo-module for information
// about how source code in version control systems is mapped to
// module file trees.
//
// Module downloading and verification
//
// The go command can fetch modules from a proxy or connect to source control
// servers directly, according to the setting of the GOPROXY environment
// variable (see 'go help env'). The default setting for GOPROXY is
// "https://proxy.golang.org,direct", which means to try the
// Go module mirror run by Google and fall back to a direct connection
// if the proxy reports that it does not have the module (HTTP error 404 or 410).
// See https://proxy.golang.org/privacy for the service's privacy policy.
//
// If GOPROXY is set to the string "direct", downloads use a direct connection to
// source control servers. Setting GOPROXY to "off" disallows downloading modules
// from any source. Otherwise, GOPROXY is expected to be list of module proxy URLs
// separated by either comma (,) or pipe (|) characters, which control error
// fallback behavior. For each request, the go command tries each proxy in
// sequence. If there is an error, the go command will try the next proxy in the
// list if the error is a 404 or 410 HTTP response or if the current proxy is
// followed by a pipe character, indicating it is safe to fall back on any error.
//
// The GOPRIVATE and GONOPROXY environment variables allow bypassing
// the proxy for selected modules. See 'go help module-private' for details.
//
// No matter the source of the modules, the go command checks downloads against
// known checksums, to detect unexpected changes in the content of any specific
// module version from one day to the next. This check first consults the current
// module's go.sum file but falls back to the Go checksum database, controlled by
// the GOSUMDB and GONOSUMDB environment variables. See 'go help module-auth'
// for details.
//
// See 'go help goproxy' for details about the proxy protocol and also
// the format of the cached downloaded packages.
//
// Modules and vendoring
//
// When using modules, the go command typically satisfies dependencies by
// downloading modules from their sources and using those downloaded copies
// (after verification, as described in the previous section). Vendoring may
// be used to allow interoperation with older versions of Go, or to ensure
// that all files used for a build are stored together in a single file tree.
//
// The command 'go mod vendor' constructs a directory named vendor in the main
// module's root directory that contains copies of all packages needed to support
// builds and tests of packages in the main module. 'go mod vendor' also
// creates the file vendor/modules.txt that contains metadata about vendored
// packages and module versions. This file should be kept consistent with go.mod:
// when vendoring is used, 'go mod vendor' should be run after go.mod is updated.
//
// If the vendor directory is present in the main module's root directory, it will
// be used automatically if the "go" version in the main module's go.mod file is
// 1.14 or higher. Build commands like 'go build' and 'go test' will load packages
// from the vendor directory instead of accessing the network or the local module
// cache. To explicitly enable vendoring, invoke the go command with the flag
// -mod=vendor. To disable vendoring, use the flag -mod=mod.
//
// Unlike vendoring in GOPATH, the go command ignores vendor directories in
// locations other than the main module's root directory.
//
//
// Module authentication using go.sum
//
// The go command tries to authenticate every downloaded module,
// checking that the bits downloaded for a specific module version today
// match bits downloaded yesterday. This ensures repeatable builds
// and detects introduction of unexpected changes, malicious or not.
//
// In each module's root, alongside go.mod, the go command maintains
// a file named go.sum containing the cryptographic checksums of the
// module's dependencies.
//
// The form of each line in go.sum is three fields:
//
// 	<module> <version>[/go.mod] <hash>
//
// Each known module version results in two lines in the go.sum file.
// The first line gives the hash of the module version's file tree.
// The second line appends "/go.mod" to the version and gives the hash
// of only the module version's (possibly synthesized) go.mod file.
// The go.mod-only hash allows downloading and authenticating a
// module version's go.mod file, which is needed to compute the
// dependency graph, without also downloading all the module's source code.
//
// The hash begins with an algorithm prefix of the form "h<N>:".
// The only defined algorithm prefix is "h1:", which uses SHA-256.
//
// Module authentication failures
//
// The go command maintains a cache of downloaded packages and computes
// and records the cryptographic checksum of each package at download time.
// In normal operation, the go command checks the main module's go.sum file
// against these precomputed checksums instead of recomputing them on
// each command invocation. The 'go mod verify' command checks that
// the cached copies of module downloads still match both their recorded
// checksums and the entries in go.sum.
//
// In day-to-day development, the checksum of a given module version
// should never change. Each time a dependency is used by a given main
// module, the go command checks its local cached copy, freshly
// downloaded or not, against the main module's go.sum. If the checksums
// don't match, the go command reports the mismatch as a security error
// and refuses to run the build. When this happens, proceed with caution:
// code changing unexpectedly means today's build will not match
// yesterday's, and the unexpected change may not be beneficial.
//
// If the go command reports a mismatch in go.sum, the downloaded code
// for the reported module version does not match the one used in a
// previous build of the main module. It is important at that point
// to find out what the right checksum should be, to decide whether
// go.sum is wrong or the downloaded code is wrong. Usually go.sum is right:
// you want to use the same code you used yesterday.
//
// If a downloaded module is not yet included in go.sum and it is a publicly
// available module, the go command consults the Go checksum database to fetch
// the expected go.sum lines. If the downloaded code does not match those
// lines, the go command reports the mismatch and exits. Note that the
// database is not consulted for module versions already listed in go.sum.
//
// If a go.sum mismatch is reported, it is always worth investigating why
// the code downloaded today differs from what was downloaded yesterday.
//
// The GOSUMDB environment variable identifies the name of checksum database
// to use and optionally its public key and URL, as in:
//
// 	GOSUMDB="sum.golang.org"
// 	GOSUMDB="sum.golang.org+<publickey>"
// 	GOSUMDB="sum.golang.org+<publickey> https://sum.golang.org"
//
// The go command knows the public key of sum.golang.org, and also that the name
// sum.golang.google.cn (available inside mainland China) connects to the
// sum.golang.org checksum database; use of any other database requires giving
// the public key explicitly.
// The URL defaults to "https://" followed by the database name.
//
// GOSUMDB defaults to "sum.golang.org", the Go checksum database run by Google.
// See https://sum.golang.org/privacy for the service's privacy policy.
//
// If GOSUMDB is set to "off", or if "go get" is invoked with the -insecure flag,
// the checksum database is not consulted, and all unrecognized modules are
// accepted, at the cost of giving up the security guarantee of verified repeatable
// downloads for all modules. A better way to bypass the checksum database
// for specific modules is to use the GOPRIVATE or GONOSUMDB environment
// variables. See 'go help module-private' for details.
//
// The 'go env -w' command (see 'go help env') can be used to set these variables
// for future go command invocations.
//
//
// Module configuration for non-public modules
//
// The go command defaults to downloading modules from the public Go module
// mirror at proxy.golang.org. It also defaults to validating downloaded modules,
// regardless of source, against the public Go checksum database at sum.golang.org.
// These defaults work well for publicly available source code.
//
// The GOPRIVATE environment variable controls which modules the go command
// considers to be private (not available publicly) and should therefore not use the
// proxy or checksum database. The variable is a comma-separated list of
// glob patterns (in the syntax of Go's path.Match) of module path prefixes.
// For example,
//
// 	GOPRIVATE=*.corp.example.com,rsc.io/private
//
// causes the go command to treat as private any module with a path prefix
// matching either pattern, including git.corp.example.com/xyzzy, rsc.io/private,
// and rsc.io/private/quux.
//
// The GOPRIVATE environment variable may be used by other tools as well to
// identify non-public modules. For example, an editor could use GOPRIVATE
// to decide whether to hyperlink a package import to a godoc.org page.
//
// For fine-grained control over module download and validation, the GONOPROXY
// and GONOSUMDB environment variables accept the same kind of glob list
// and override GOPRIVATE for the specific decision of whether to use the proxy
// and checksum database, respectively.
//
// For example, if a company ran a module proxy serving private modules,
// users would configure go using:
//
// 	GOPRIVATE=*.corp.example.com
// 	GOPROXY=proxy.example.com
// 	GONOPROXY=none
//
// This would tell the go command and other tools that modules beginning with
// a corp.example.com subdomain are private but that the company proxy should
// be used for downloading both public and private modules, because
// GONOPROXY has been set to a pattern that won't match any modules,
// overriding GOPRIVATE.
//
// The 'go env -w' command (see 'go help env') can be used to set these variables
// for future go command invocations.
//
//
// Package lists and patterns
//
// Many commands apply to a set of packages:
//
// 	go action [packages]
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
// There are four reserved names for paths that should not be used
// for packages to be built with the go tool:
//
// - "main" denotes the top-level package in a stand-alone executable.
//
// - "all" expands to all packages found in all the GOPATH
// trees. For example, 'go list all' lists all the packages on the local
// system. When using modules, "all" expands to all packages in
// the main module and their dependencies, including dependencies
// needed by tests of any of those.
//
// - "std" is like all but expands to just the packages in the standard
// Go library.
//
// - "cmd" expands to the Go repository's commands and their
// internal libraries.
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
// ./vendor or ./mycode/vend
"""




```