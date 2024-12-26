Response: The user wants me to summarize the functionality of the provided Go code documentation. This is the second part of a three-part document.

I need to carefully read through the text and identify the main topics covered. The text seems to be a comprehensive guide to using the `go` command, covering various aspects of building, testing, and managing Go projects, including:

- Different build modes
- Interfacing with C code (cgo and SWIG)
- Build and test caching mechanisms
- Environment variables used by the `go` command
- File types recognized by the `go` command
- The `go.mod` file and Go modules
- The `GOPATH` environment variable and its structure
- Internal and vendor directories for dependency management
- The legacy `go get` command
- The module proxy protocol
- Import path syntax and resolution
- Go modules: their definition, main module, build list, and maintenance
- Pseudo-versions for unreleased code
- Module queries for specifying dependencies
- Module compatibility and semantic versioning
- Module code layout
- Module downloading and verification, including checksums
- Configuration for non-public modules
- Package lists and patterns

I should group these related concepts into broader categories for a concise summary.
这个 Go 语言文档的第 2 部分主要涵盖了以下功能：

1. **Go 模块 (Modules) 的详细介绍：**
   - 解释了什么是 Go 模块，以及如何使用 `go.mod` 文件定义和管理模块依赖。
   - 描述了主模块 (main module) 和构建列表 (build list) 的概念。
   - 详细说明了如何维护模块依赖，包括自动更新 `go.mod`，以及 `go mod tidy` 命令的作用。
   - 介绍了间接依赖 (indirect dependencies) 的概念。
   - 解释了 `-mod` 构建标志的不同选项 (`readonly`, `vendor`, `mod`) 及其作用。
   - 阐述了伪版本 (pseudo-versions) 的概念及其格式，用于引用未发布的代码版本。
   - 讲解了模块查询 (module queries) 的语法，用于在 `go.mod` 文件和命令行中指定模块版本。

2. **模块的兼容性和语义化版本控制 (Semantic Versioning)：**
   - 强调了 Go 模块需要遵循语义化版本控制，并期望新版本向后兼容旧版本。
   - 解释了语义导入版本控制 (Semantic Import Versioning) 的概念，即主版本号大于等于 v2 的模块需要将主版本号添加到模块路径中。
   - 提到了 `+incompatible` 后缀，用于标记没有 `go.mod` 文件的仓库的 v2 或更高版本。

3. **模块代码布局 (Module Code Layout)：**
   -  指出当前文档中关于模块代码布局的信息暂未提供，建议参考其他资源。

4. **模块的下载和验证 (Module Downloading and Verification)：**
   - 介绍了 Go 如何通过模块代理 (module proxy) 或直接连接到版本控制服务器下载模块。
   - 解释了 `GOPROXY` 环境变量的作用以及其不同的配置选项。
   - 详细描述了 Go 如何通过 `go.sum` 文件和 Go checksum database 来验证下载的模块，确保构建的可重复性。
   - 解释了模块认证失败时的处理方式和 `GOSUMDB` 环境变量的作用。

5. **非公共模块的配置 (Module Configuration for Non-Public Modules)：**
   - 介绍了 `GOPRIVATE`, `GONOPROXY`, 和 `GONOSUMDB` 环境变量，用于配置如何处理私有模块，以及是否使用代理和校验和数据库。

6. **包列表和模式 (Package Lists and Patterns)：**
   - 描述了在 `go` 命令中如何指定要操作的包，包括导入路径、文件系统路径以及通配符模式 (`...`)。
   - 解释了 `main`, `all`, `std`, `cmd` 这几个保留的包名。

总而言之，这部分文档的核心是详细介绍了 Go 模块系统的各个方面，包括模块的定义、依赖管理、版本控制、下载验证以及如何处理私有模块，是理解和使用 Go 模块的关键信息。

Prompt: 
```
这是路径为go/src/cmd/go/alldocs-1.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共3部分，请归纳一下它的功能

"""
n-main packages are built into .a files (the default
// 		behavior).
//
// 	-buildmode=shared
// 		Combine all the listed non-main packages into a single shared
// 		library that will be used when building with the -linkshared
// 		option. Packages named main are ignored.
//
// 	-buildmode=exe
// 		Build the listed main packages and everything they import into
// 		executables. Packages not named main are ignored.
//
// 	-buildmode=pie
// 		Build the listed main packages and everything they import into
// 		position independent executables (PIE). Packages not named
// 		main are ignored.
//
// 	-buildmode=plugin
// 		Build the listed main packages, plus all packages that they
// 		import, into a Go plugin. Packages not named main are ignored.
//
// On AIX, when linking a C program that uses a Go archive built with
// -buildmode=c-archive, you must pass -Wl,-bnoobjreorder to the C compiler.
//
//
// Calling between Go and C
//
// There are two different ways to call between Go and C/C++ code.
//
// The first is the cgo tool, which is part of the Go distribution. For
// information on how to use it see the cgo documentation (go doc cmd/cgo).
//
// The second is the SWIG program, which is a general tool for
// interfacing between languages. For information on SWIG see
// http://swig.org/. When running go build, any file with a .swig
// extension will be passed to SWIG. Any file with a .swigcxx extension
// will be passed to SWIG with the -c++ option.
//
// When either cgo or SWIG is used, go build will pass any .c, .m, .s, .S
// or .sx files to the C compiler, and any .cc, .cpp, .cxx files to the C++
// compiler. The CC or CXX environment variables may be set to determine
// the C or C++ compiler, respectively, to use.
//
//
// Build and test caching
//
// The go command caches build outputs for reuse in future builds.
// The default location for cache data is a subdirectory named go-build
// in the standard user cache directory for the current operating system.
// Setting the GOCACHE environment variable overrides this default,
// and running 'go env GOCACHE' prints the current cache directory.
//
// The go command periodically deletes cached data that has not been
// used recently. Running 'go clean -cache' deletes all cached data.
//
// The build cache correctly accounts for changes to Go source files,
// compilers, compiler options, and so on: cleaning the cache explicitly
// should not be necessary in typical use. However, the build cache
// does not detect changes to C libraries imported with cgo.
// If you have made changes to the C libraries on your system, you
// will need to clean the cache explicitly or else use the -a build flag
// (see 'go help build') to force rebuilding of packages that
// depend on the updated C libraries.
//
// The go command also caches successful package test results.
// See 'go help test' for details. Running 'go clean -testcache' removes
// all cached test results (but not cached build results).
//
// The GODEBUG environment variable can enable printing of debugging
// information about the state of the cache:
//
// GODEBUG=gocacheverify=1 causes the go command to bypass the
// use of any cache entries and instead rebuild everything and check
// that the results match existing cache entries.
//
// GODEBUG=gocachehash=1 causes the go command to print the inputs
// for all of the content hashes it uses to construct cache lookup keys.
// The output is voluminous but can be useful for debugging the cache.
//
// GODEBUG=gocachetest=1 causes the go command to print details of its
// decisions about whether to reuse a cached test result.
//
//
// Environment variables
//
// The go command and the tools it invokes consult environment variables
// for configuration. If an environment variable is unset, the go command
// uses a sensible default setting. To see the effective setting of the
// variable <NAME>, run 'go env <NAME>'. To change the default setting,
// run 'go env -w <NAME>=<VALUE>'. Defaults changed using 'go env -w'
// are recorded in a Go environment configuration file stored in the
// per-user configuration directory, as reported by os.UserConfigDir.
// The location of the configuration file can be changed by setting
// the environment variable GOENV, and 'go env GOENV' prints the
// effective location, but 'go env -w' cannot change the default location.
// See 'go help env' for details.
//
// General-purpose environment variables:
//
// 	GCCGO
// 		The gccgo command to run for 'go build -compiler=gccgo'.
// 	GOARCH
// 		The architecture, or processor, for which to compile code.
// 		Examples are amd64, 386, arm, ppc64.
// 	GOBIN
// 		The directory where 'go install' will install a command.
// 	GOCACHE
// 		The directory where the go command will store cached
// 		information for reuse in future builds.
// 	GODEBUG
// 		Enable various debugging facilities. See 'go doc runtime'
// 		for details.
// 	GOENV
// 		The location of the Go environment configuration file.
// 		Cannot be set using 'go env -w'.
// 	GOFLAGS
// 		A space-separated list of -flag=value settings to apply
// 		to go commands by default, when the given flag is known by
// 		the current command. Each entry must be a standalone flag.
// 		Because the entries are space-separated, flag values must
// 		not contain spaces. Flags listed on the command line
// 		are applied after this list and therefore override it.
// 	GOINSECURE
// 		Comma-separated list of glob patterns (in the syntax of Go's path.Match)
// 		of module path prefixes that should always be fetched in an insecure
// 		manner. Only applies to dependencies that are being fetched directly.
// 		Unlike the -insecure flag on 'go get', GOINSECURE does not disable
// 		checksum database validation. GOPRIVATE or GONOSUMDB may be used
// 		to achieve that.
// 	GOOS
// 		The operating system for which to compile code.
// 		Examples are linux, darwin, windows, netbsd.
// 	GOPATH
// 		For more details see: 'go help gopath'.
// 	GOPROXY
// 		URL of Go module proxy. See 'go help modules'.
// 	GOPRIVATE, GONOPROXY, GONOSUMDB
// 		Comma-separated list of glob patterns (in the syntax of Go's path.Match)
// 		of module path prefixes that should always be fetched directly
// 		or that should not be compared against the checksum database.
// 		See 'go help module-private'.
// 	GOROOT
// 		The root of the go tree.
// 	GOSUMDB
// 		The name of checksum database to use and optionally its public key and
// 		URL. See 'go help module-auth'.
// 	GOTMPDIR
// 		The directory where the go command will write
// 		temporary source files, packages, and binaries.
//
// Environment variables for use with cgo:
//
// 	AR
// 		The command to use to manipulate library archives when
// 		building with the gccgo compiler.
// 		The default is 'ar'.
// 	CC
// 		The command to use to compile C code.
// 	CGO_ENABLED
// 		Whether the cgo command is supported. Either 0 or 1.
// 	CGO_CFLAGS
// 		Flags that cgo will pass to the compiler when compiling
// 		C code.
// 	CGO_CFLAGS_ALLOW
// 		A regular expression specifying additional flags to allow
// 		to appear in #cgo CFLAGS source code directives.
// 		Does not apply to the CGO_CFLAGS environment variable.
// 	CGO_CFLAGS_DISALLOW
// 		A regular expression specifying flags that must be disallowed
// 		from appearing in #cgo CFLAGS source code directives.
// 		Does not apply to the CGO_CFLAGS environment variable.
// 	CGO_CPPFLAGS, CGO_CPPFLAGS_ALLOW, CGO_CPPFLAGS_DISALLOW
// 		Like CGO_CFLAGS, CGO_CFLAGS_ALLOW, and CGO_CFLAGS_DISALLOW,
// 		but for the C preprocessor.
// 	CGO_CXXFLAGS, CGO_CXXFLAGS_ALLOW, CGO_CXXFLAGS_DISALLOW
// 		Like CGO_CFLAGS, CGO_CFLAGS_ALLOW, and CGO_CFLAGS_DISALLOW,
// 		but for the C++ compiler.
// 	CGO_FFLAGS, CGO_FFLAGS_ALLOW, CGO_FFLAGS_DISALLOW
// 		Like CGO_CFLAGS, CGO_CFLAGS_ALLOW, and CGO_CFLAGS_DISALLOW,
// 		but for the Fortran compiler.
// 	CGO_LDFLAGS, CGO_LDFLAGS_ALLOW, CGO_LDFLAGS_DISALLOW
// 		Like CGO_CFLAGS, CGO_CFLAGS_ALLOW, and CGO_CFLAGS_DISALLOW,
// 		but for the linker.
// 	CXX
// 		The command to use to compile C++ code.
// 	FC
// 		The command to use to compile Fortran code.
// 	PKG_CONFIG
// 		Path to pkg-config tool.
//
// Architecture-specific environment variables:
//
// 	GOARM
// 		For GOARCH=arm, the ARM architecture for which to compile.
// 		Valid values are 5, 6, 7.
// 	GO386
// 		For GOARCH=386, the floating point instruction set.
// 		Valid values are 387, sse2.
// 	GOAMD64
// 		For GOARCH=amd64, jumps can be optionally be aligned such that they do not end on
// 		or cross 32 byte boundaries.  Valid values are alignedjumps (default), normaljumps.
// 	GOMIPS
// 		For GOARCH=mips{,le}, whether to use floating point instructions.
// 		Valid values are hardfloat (default), softfloat.
// 	GOMIPS64
// 		For GOARCH=mips64{,le}, whether to use floating point instructions.
// 		Valid values are hardfloat (default), softfloat.
// 	GOWASM
// 		For GOARCH=wasm, comma-separated list of experimental WebAssembly features to use.
// 		Valid values are satconv, signext.
//
// Special-purpose environment variables:
//
// 	GCCGOTOOLDIR
// 		If set, where to find gccgo tools, such as cgo.
// 		The default is based on how gccgo was configured.
// 	GOROOT_FINAL
// 		The root of the installed Go tree, when it is
// 		installed in a location other than where it is built.
// 		File names in stack traces are rewritten from GOROOT to
// 		GOROOT_FINAL.
// 	GO_EXTLINK_ENABLED
// 		Whether the linker should use external linking mode
// 		when using -linkmode=auto with code that uses cgo.
// 		Set to 0 to disable external linking mode, 1 to enable it.
// 	GIT_ALLOW_PROTOCOL
// 		Defined by Git. A colon-separated list of schemes that are allowed
// 		to be used with git fetch/clone. If set, any scheme not explicitly
// 		mentioned will be considered insecure by 'go get'.
// 		Because the variable is defined by Git, the default value cannot
// 		be set using 'go env -w'.
//
// Additional information available from 'go env' but not read from the environment:
//
// 	GOEXE
// 		The executable file name suffix (".exe" on Windows, "" on other systems).
// 	GOGCCFLAGS
// 		A space-separated list of arguments supplied to the CC command.
// 	GOHOSTARCH
// 		The architecture (GOARCH) of the Go toolchain binaries.
// 	GOHOSTOS
// 		The operating system (GOOS) of the Go toolchain binaries.
// 	GOMOD
// 		The absolute path to the go.mod of the main module.
// 		If module-aware mode is enabled, but there is no go.mod, GOMOD will be
// 		os.DevNull ("/dev/null" on Unix-like systems, "NUL" on Windows).
// 		If module-aware mode is disabled, GOMOD will be the empty string.
// 	GOTOOLDIR
// 		The directory where the go tools (compile, cover, doc, etc...) are installed.
//
//
// File types
//
// The go command examines the contents of a restricted set of files
// in each directory. It identifies which files to examine based on
// the extension of the file name. These extensions are:
//
// 	.go
// 		Go source files.
// 	.c, .h
// 		C source files.
// 		If the package uses cgo or SWIG, these will be compiled with the
// 		OS-native compiler (typically gcc); otherwise they will
// 		trigger an error.
// 	.cc, .cpp, .cxx, .hh, .hpp, .hxx
// 		C++ source files. Only useful with cgo or SWIG, and always
// 		compiled with the OS-native compiler.
// 	.m
// 		Objective-C source files. Only useful with cgo, and always
// 		compiled with the OS-native compiler.
// 	.s, .S, .sx
// 		Assembler source files.
// 		If the package uses cgo or SWIG, these will be assembled with the
// 		OS-native assembler (typically gcc (sic)); otherwise they
// 		will be assembled with the Go assembler.
// 	.swig, .swigcxx
// 		SWIG definition files.
// 	.syso
// 		System object files.
//
// Files of each of these types except .syso may contain build
// constraints, but the go command stops scanning for build constraints
// at the first item in the file that is not a blank line or //-style
// line comment. See the go/build package documentation for
// more details.
//
//
// The go.mod file
//
// A module version is defined by a tree of source files, with a go.mod
// file in its root. When the go command is run, it looks in the current
// directory and then successive parent directories to find the go.mod
// marking the root of the main (current) module.
//
// The go.mod file itself is line-oriented, with // comments but
// no /* */ comments. Each line holds a single directive, made up of a
// verb followed by arguments. For example:
//
// 	module my/thing
// 	go 1.12
// 	require other/thing v1.0.2
// 	require new/thing/v2 v2.3.4
// 	exclude old/thing v1.2.3
// 	replace bad/thing v1.4.5 => good/thing v1.4.5
//
// The verbs are
// 	module, to define the module path;
// 	go, to set the expected language version;
// 	require, to require a particular module at a given version or later;
// 	exclude, to exclude a particular module version from use; and
// 	replace, to replace a module version with a different module version.
// Exclude and replace apply only in the main module's go.mod and are ignored
// in dependencies.  See https://research.swtch.com/vgo-mvs for details.
//
// The leading verb can be factored out of adjacent lines to create a block,
// like in Go imports:
//
// 	require (
// 		new/thing v2.3.4
// 		old/thing v1.2.3
// 	)
//
// The go.mod file is designed both to be edited directly and to be
// easily updated by tools. The 'go mod edit' command can be used to
// parse and edit the go.mod file from programs and tools.
// See 'go help mod edit'.
//
// The go command automatically updates go.mod each time it uses the
// module graph, to make sure go.mod always accurately reflects reality
// and is properly formatted. For example, consider this go.mod file:
//
//         module M
//
//         require (
//                 A v1
//                 B v1.0.0
//                 C v1.0.0
//                 D v1.2.3
//                 E dev
//         )
//
//         exclude D v1.2.3
//
// The update rewrites non-canonical version identifiers to semver form,
// so A's v1 becomes v1.0.0 and E's dev becomes the pseudo-version for the
// latest commit on the dev branch, perhaps v0.0.0-20180523231146-b3f5c0f6e5f1.
//
// The update modifies requirements to respect exclusions, so the
// requirement on the excluded D v1.2.3 is updated to use the next
// available version of D, perhaps D v1.2.4 or D v1.3.0.
//
// The update removes redundant or misleading requirements.
// For example, if A v1.0.0 itself requires B v1.2.0 and C v1.0.0,
// then go.mod's requirement of B v1.0.0 is misleading (superseded by
// A's need for v1.2.0), and its requirement of C v1.0.0 is redundant
// (implied by A's need for the same version), so both will be removed.
// If module M contains packages that directly import packages from B or
// C, then the requirements will be kept but updated to the actual
// versions being used.
//
// Finally, the update reformats the go.mod in a canonical formatting, so
// that future mechanical changes will result in minimal diffs.
//
// Because the module graph defines the meaning of import statements, any
// commands that load packages also use and therefore update go.mod,
// including go build, go get, go install, go list, go test, go mod graph,
// go mod tidy, and go mod why.
//
// The expected language version, set by the go directive, determines
// which language features are available when compiling the module.
// Language features available in that version will be available for use.
// Language features removed in earlier versions, or added in later versions,
// will not be available. Note that the language version does not affect
// build tags, which are determined by the Go release being used.
//
//
// GOPATH environment variable
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
//     GOPATH=/home/user/go
//
//     /home/user/go/
//         src/
//             foo/
//                 bar/               (go code in package bar)
//                     x.go
//                 quux/              (go code in package main)
//                     y.go
//         bin/
//             quux                   (installed command)
//         pkg/
//             linux_amd64/
//                 foo/
//                     bar.a          (installed package object)
//
// Go searches each directory listed in GOPATH to find source code,
// but new packages are always downloaded into the first directory
// in the list.
//
// See https://golang.org/doc/code.html for an example.
//
// GOPATH and Modules
//
// When using modules, GOPATH is no longer used for resolving imports.
// However, it is still used to store downloaded source code (in GOPATH/pkg/mod)
// and compiled commands (in GOPATH/bin).
//
// Internal Directories
//
// Code in or below a directory named "internal" is importable only
// by code in the directory tree rooted at the parent of "internal".
// Here's an extended version of the directory layout above:
//
//     /home/user/go/
//         src/
//             crash/
//                 bang/              (go code in package bang)
//                     b.go
//             foo/                   (go code in package foo)
//                 f.go
//                 bar/               (go code in package bar)
//                     x.go
//                 internal/
//                     baz/           (go code in package baz)
//                         z.go
//                 quux/              (go code in package main)
//                     y.go
//
//
// The code in z.go is imported as "foo/internal/baz", but that
// import statement can only appear in source files in the subtree
// rooted at foo. The source files foo/f.go, foo/bar/x.go, and
// foo/quux/y.go can all import "foo/internal/baz", but the source file
// crash/bang/b.go cannot.
//
// See https://golang.org/s/go14internal for details.
//
// Vendor Directories
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
//     /home/user/go/
//         src/
//             crash/
//                 bang/              (go code in package bang)
//                     b.go
//             foo/                   (go code in package foo)
//                 f.go
//                 bar/               (go code in package bar)
//                     x.go
//                 vendor/
//                     crash/
//                         bang/      (go code in package bang)
//                             b.go
//                     baz/           (go code in package baz)
//                         z.go
//                 quux/              (go code in package main)
//                     y.go
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
//
// Legacy GOPATH go get
//
// The 'go get' command changes behavior depending on whether the
// go command is running in module-aware mode or legacy GOPATH mode.
// This help text, accessible as 'go help gopath-get' even in module-aware mode,
// describes 'go get' as it operates in legacy GOPATH mode.
//
// Usage: go get [-d] [-f] [-t] [-u] [-v] [-fix] [-insecure] [build flags] [packages]
//
// Get downloads the packages named by the import paths, along with their
// dependencies. It then installs the named packages, like 'go install'.
//
// The -d flag instructs get to stop after downloading the packages; that is,
// it instructs get not to install the packages.
//
// The -f flag, valid only when -u is set, forces get -u not to verify that
// each package has been checked out from the source control repository
// implied by its import path. This can be useful if the source is a local fork
// of the original.
//
// The -fix flag instructs get to run the fix tool on the downloaded packages
// before resolving dependencies or building the code.
//
// The -insecure flag permits fetching from repositories and resolving
// custom domains using insecure schemes such as HTTP. Use with caution.
//
// The -t flag instructs get to also download the packages required to build
// the tests for the specified packages.
//
// The -u flag instructs get to use the network to update the named packages
// and their dependencies. By default, get uses the network to check out
// missing packages but does not use it to look for updates to existing packages.
//
// The -v flag enables verbose progress and debug output.
//
// Get also accepts build flags to control the installation. See 'go help build'.
//
// When checking out a new package, get creates the target directory
// GOPATH/src/<import-path>. If the GOPATH contains multiple entries,
// get uses the first one. For more details see: 'go help gopath'.
//
// When checking out or updating a package, get looks for a branch or tag
// that matches the locally installed version of Go. The most important
// rule is that if the local installation is running version "go1", get
// searches for a branch or tag named "go1". If no such version exists
// it retrieves the default branch of the package.
//
// When go get checks out or updates a Git repository,
// it also updates any git submodules referenced by the repository.
//
// Get never checks out or updates code stored in vendor directories.
//
// For more about specifying packages, see 'go help packages'.
//
// For more about how 'go get' finds source code to
// download, see 'go help importpath'.
//
// This text describes the behavior of get when using GOPATH
// to manage source code and dependencies.
// If instead the go command is running in module-aware mode,
// the details of get's flags and effects change, as does 'go help get'.
// See 'go help modules' and 'go help module-get'.
//
// See also: go build, go install, go clean.
//
//
// Module proxy protocol
//
// A Go module proxy is any web server that can respond to GET requests for
// URLs of a specified form. The requests have no query parameters, so even
// a site serving from a fixed file system (including a file:/// URL)
// can be a module proxy.
//
// The GET requests sent to a Go module proxy are:
//
// GET $GOPROXY/<module>/@v/list returns a list of known versions of the given
// module, one per line.
//
// GET $GOPROXY/<module>/@v/<version>.info returns JSON-formatted metadata
// about that version of the given module.
//
// GET $GOPROXY/<module>/@v/<version>.mod returns the go.mod file
// for that version of the given module.
//
// GET $GOPROXY/<module>/@v/<version>.zip returns the zip archive
// for that version of the given module.
//
// GET $GOPROXY/<module>/@latest returns JSON-formatted metadata about the
// latest known version of the given module in the same format as
// <module>/@v/<version>.info. The latest version should be the version of
// the module the go command may use if <module>/@v/list is empty or no
// listed version is suitable. <module>/@latest is optional and may not
// be implemented by a module proxy.
//
// When resolving the latest version of a module, the go command will request
// <module>/@v/list, then, if no suitable versions are found, <module>/@latest.
// The go command prefers, in order: the semantically highest release version,
// the semantically highest pre-release version, and the chronologically
// most recent pseudo-version. In Go 1.12 and earlier, the go command considered
// pseudo-versions in <module>/@v/list to be pre-release versions, but this is
// no longer true since Go 1.13.
//
// To avoid problems when serving from case-sensitive file systems,
// the <module> and <version> elements are case-encoded, replacing every
// uppercase letter with an exclamation mark followed by the corresponding
// lower-case letter: github.com/Azure encodes as github.com/!azure.
//
// The JSON-formatted metadata about a given module corresponds to
// this Go data structure, which may be expanded in the future:
//
//     type Info struct {
//         Version string    // version string
//         Time    time.Time // commit time
//     }
//
// The zip archive for a specific version of a given module is a
// standard zip file that contains the file tree corresponding
// to the module's source code and related files. The archive uses
// slash-separated paths, and every file path in the archive must
// begin with <module>@<version>/, where the module and version are
// substituted directly, not case-encoded. The root of the module
// file tree corresponds to the <module>@<version>/ prefix in the
// archive.
//
// Even when downloading directly from version control systems,
// the go command synthesizes explicit info, mod, and zip files
// and stores them in its local cache, $GOPATH/pkg/mod/cache/download,
// the same as if it had downloaded them directly from a proxy.
// The cache layout is the same as the proxy URL space, so
// serving $GOPATH/pkg/mod/cache/download at (or copying it to)
// https://example.com/proxy would let other users access those
// cached module versions with GOPROXY=https://example.com/proxy.
//
//
// Import path syntax
//
// An import path (see 'go help packages') denotes a package stored in the local
// file system. In general, an import path denotes either a standard package (such
// as "unicode/utf8") or a package found in one of the work spaces (For more
// details see: 'go help gopath').
//
// Relative import paths
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
// Remote import paths
//
// Certain import paths also
// describe how to obtain the source code for the package using
// a revision control system.
//
// A few common code hosting sites have special syntax:
//
// 	Bitbucket (Git, Mercurial)
//
// 		import "bitbucket.org/user/project"
// 		import "bitbucket.org/user/project/sub/directory"
//
// 	GitHub (Git)
//
// 		import "github.com/user/project"
// 		import "github.com/user/project/sub/directory"
//
// 	Launchpad (Bazaar)
//
// 		import "launchpad.net/project"
// 		import "launchpad.net/project/series"
// 		import "launchpad.net/project/series/sub/directory"
//
// 		import "launchpad.net/~user/project/branch"
// 		import "launchpad.net/~user/project/branch/sub/directory"
//
// 	IBM DevOps Services (Git)
//
// 		import "hub.jazz.net/git/user/project"
// 		import "hub.jazz.net/git/user/project/sub/directory"
//
// For code hosted on other servers, import paths may either be qualified
// with the version control type, or the go tool can dynamically fetch
// the import path over https/http and discover where the code resides
// from a <meta> tag in the HTML.
//
// To declare the code location, an import path of the form
//
// 	repository.vcs/path
//
// specifies the given repository, with or without the .vcs suffix,
// using the named version control system, and then the path inside
// that repository. The supported version control systems are:
//
// 	Bazaar      .bzr
// 	Fossil      .fossil
// 	Git         .git
// 	Mercurial   .hg
// 	Subversion  .svn
//
// For example,
//
// 	import "example.org/user/foo.hg"
//
// denotes the root directory of the Mercurial repository at
// example.org/user/foo or foo.hg, and
//
// 	import "example.org/repo.git/foo/bar"
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
// 	<meta name="go-import" content="import-prefix vcs repo-root">
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
// 	import "example.org/pkg/foo"
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