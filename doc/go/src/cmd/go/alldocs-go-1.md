Response: The user provided a snippet of Go code documentation for the `go` command, specifically the `go work` subcommand and several other top-level commands. I need to analyze the provided text, focusing on the `go work` section, and summarize its functionalities. The request also asks to identify the Go language feature it implements and provide a code example if possible, along with details on command-line arguments, potential pitfalls, and an overall summary.

**Plan:**

1. **Identify the core functionality:** Focus on the `go work` command and its subcommands.
2. **List the functionalities of `go work`:** Extract the purpose of each subcommand (`edit`, `init`, `sync`, `use`, `vendor`).
3. **Determine the Go language feature:**  The documentation explicitly mentions "workspace mode" and the `go.work` file, indicating the implementation of Go Workspaces.
4. **Provide a Go code example:** Demonstrate how to use `go work init` and `go work use`.
5. **Explain command-line arguments:** Detail the flags and arguments for each `go work` subcommand, especially `go work edit`.
6. **Identify potential pitfalls:**  Based on the documentation, highlight common mistakes users might make.
7. **Summarize the functionality:**  Concisely describe the overall purpose of the `go work` command.
Based on the provided text, which is a part of the documentation for the `go` command in Go, here's a breakdown of the functionalities described in this section, focusing on the `go work` command:

**Functionalities Described:**

1. **`go work` command:**
    *   **Purpose:** Primarily intended to manage conflicting `replace` directives across different modules within a workspace.
    *   **Workspace Mode Detection:** Explains how to determine if the `go` command is operating in workspace mode using `go env GOWORK`.
    *   **Subcommands:** Introduces the subcommands available for `go work`: `edit`, `init`, `sync`, `use`, and `vendor`.

2. **`go work edit`:**
    *   **Purpose:** Provides a command-line interface for editing the `go.work` file, mainly intended for tools or scripts. It only reads the `go.work` file and doesn't interact with module information.
    *   **File Location:** Explains how `edit` locates the `go.work` file.
    *   **Editing Flags:** Lists and describes various flags for modifying the `go.work` file:
        *   `-fmt`: Reformats the `go.work` file.
        *   `-godebug=key=value`: Adds or replaces a `godebug` setting.
        *   `-dropgodebug=key`: Removes a `godebug` setting.
        *   `-use=path`: Adds a module directory to the `go.work` file.
        *   `-dropuse=path`: Removes a module directory from the `go.work` file.
        *   `-replace=old[@v]=new[@v]`: Adds a module replacement directive.
        *   `-dropreplace=old[@v]`: Removes a module replacement directive.
        *   `-go=version`: Sets the Go language version for the workspace.
        *   `-toolchain=name`: Sets the Go toolchain for the workspace.
        *   `-print`: Prints the final `go.work` content to standard output.
        *   `-json`: Prints the final `go.work` content in JSON format.
    *   **JSON Output Format:** Defines the Go types that the `-json` flag's output corresponds to (`GoWork`, `Godebug`, `Use`, `Replace`, `Module`).

3. **`go work init`:**
    *   **Purpose:** Initializes and writes a new `go.work` file in the current directory, creating a new workspace.
    *   **Module Arguments:** Allows specifying paths to workspace modules during initialization. If omitted, an empty workspace is created.
    *   **`use` Directive:** Explains that each argument path is added as a `use` directive in the `go.work` file.
    *   **Go Version:**  Mentions that the current Go version is also added to the `go.work` file.

4. **`go work sync`:**
    *   **Purpose:** Synchronizes the workspace's build list back to the modules specified in the `go.work` file's `use` directives.
    *   **Build List Generation:** Describes how the build list is generated using Minimal Version Selection.
    *   **Dependency Upgrades:** Explains that the syncing involves upgrading dependencies in workspace modules to match the versions in the build list.

5. **`go work use`:**
    *   **Purpose:** Adds or removes module directories from the `go.work` file.
    *   **`-r` flag:** Enables recursive searching for modules in the specified directories.
    *   **`use` Directive Management:**  Adds a `use` directive for existing directories and removes it for non-existent ones.
    *   **Go Version Update:** Updates the `go` line in `go.work` to be at least as new as the Go versions in the used modules.
    *   **No Arguments Behavior:** Explains that with no arguments, it only updates the Go version in `go.work`.

6. **`go work vendor`:**
    *   **Purpose:** Creates a vendored copy of dependencies for the workspace.
    *   **Exclusion of Test Code:** Notes that test code for vendored packages is not included.
    *   **Flags:** Describes the `-v` (verbose output), `-e` (continue on errors), and `-o outdir` (specify output directory) flags.
    *   **Output Directory Limitation:** Emphasizes that the `go` command can only use a vendor directory named "vendor" within the module root.

**Go Language Feature Implementation:**

The `go work` command implements **Go Workspaces**. This feature allows you to work with multiple Go modules together, especially useful for developing projects that consist of several interconnected modules or for making changes across multiple modules simultaneously. The `go.work` file acts as a central configuration file for the workspace, defining the set of modules included.

**Go Code Example:**

Let's say you have two modules, `moduleA` and `moduleB`, in the same directory.

```bash
# Initialize a workspace
go work init moduleA moduleB

# The go.work file will look something like this:
# go 1.21
#
# use ./moduleA
# use ./moduleB
```

Now, within either `moduleA` or `moduleB`, you can refer to packages in the other module without needing to publish them.

**Assumptions and Outputs:**

*   **Input:** Executing `go work init moduleA moduleB` in a directory containing subdirectories `moduleA` and `moduleB`, each being a valid Go module (containing a `go.mod` file).
*   **Output:** A `go.work` file is created in the current directory with `use` directives pointing to `moduleA` and `moduleB`. The `go` version in the `go.work` file will reflect the current Go version.

**Command-Line Argument Details:**

The `go work` command has several subcommands, each with its own set of arguments and flags:

*   **`go work edit [editing flags] [go.work]`**:
    *   `[go.work]`:  Optional. Specifies the path to the `go.work` file. If omitted, it searches for one.
    *   `[editing flags]`: A sequence of flags like `-fmt`, `-godebug`, `-use`, `-dropuse`, `-replace`, `-dropreplace`, `-go`, `-toolchain`, `-print`, `-json`. These flags modify the `go.work` file content. For example:
        *   `go work edit -use=./moduleC`: Adds `./moduleC` to the `use` directives.
        *   `go work edit -replace=example.com/old=./replacement`: Adds a replacement directive.
        *   `go work edit -go=1.20`: Sets the Go version to 1.20.
*   **`go work init [moddirs]`**:
    *   `[moddirs]`: Optional. A space-separated list of paths to module directories to include in the workspace. For example:
        *   `go work init ./moduleA ./moduleB`: Initializes a workspace including `moduleA` and `moduleB`.
*   **`go work sync`**:
    *   Takes no arguments or flags in this part of the documentation.
*   **`go work use [-r] [moddirs]`**:
    *   `-r`: Optional. Flag for recursive search of modules.
    *   `[moddirs]`: Optional. A space-separated list of paths to module directories to add or remove. For example:
        *   `go work use ./moduleC`: Adds `./moduleC` to the workspace.
        *   `go work use -r ./parentDir`: Recursively adds modules found under `parentDir`.
*   **`go work vendor [-e] [-v] [-o outdir]`**:
    *   `-e`: Optional. Flag to attempt to proceed despite errors.
    *   `-v`: Optional. Flag for verbose output.
    *   `-o outdir`: Optional. Specifies the output directory for the vendored dependencies.

**User Mistakes:**

A common mistake is to manually edit the `go.work` file without using `go work edit`, which can lead to syntax errors or inconsistencies. For example, users might incorrectly format the `use` or `replace` directives.

**归纳一下它的功能 (Summary of its functionality):**

This section of the `go` command documentation primarily describes the functionalities related to **Go Workspaces**. The `go work` command and its subcommands (`edit`, `init`, `sync`, `use`, `vendor`) provide tools to manage and configure multi-module development environments. It allows developers to define a workspace with a `go.work` file, including multiple local Go modules, and manage dependencies and replacements across those modules. This simplifies development and testing when working on related modules simultaneously.

### 提示词
```
这是路径为go/src/cmd/go/alldocs.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```go
is
// primarily intended to override conflicting replaces in different workspace
// modules.
//
// To determine whether the go command is operating in workspace mode, use
// the "go env GOWORK" command. This will specify the workspace file being
// used.
//
// Usage:
//
//	go work <command> [arguments]
//
// The commands are:
//
//	edit        edit go.work from tools or scripts
//	init        initialize workspace file
//	sync        sync workspace build list to modules
//	use         add modules to workspace file
//	vendor      make vendored copy of dependencies
//
// Use "go help work <command>" for more information about a command.
//
// # Edit go.work from tools or scripts
//
// Usage:
//
//	go work edit [editing flags] [go.work]
//
// Edit provides a command-line interface for editing go.work,
// for use primarily by tools or scripts. It only reads go.work;
// it does not look up information about the modules involved.
// If no file is specified, Edit looks for a go.work file in the current
// directory and its parent directories
//
// The editing flags specify a sequence of editing operations.
//
// The -fmt flag reformats the go.work file without making other changes.
// This reformatting is also implied by any other modifications that use or
// rewrite the go.mod file. The only time this flag is needed is if no other
// flags are specified, as in 'go work edit -fmt'.
//
// The -godebug=key=value flag adds a godebug key=value line,
// replacing any existing godebug lines with the given key.
//
// The -dropgodebug=key flag drops any existing godebug lines
// with the given key.
//
// The -use=path and -dropuse=path flags
// add and drop a use directive from the go.work file's set of module directories.
//
// The -replace=old[@v]=new[@v] flag adds a replacement of the given
// module path and version pair. If the @v in old@v is omitted, a
// replacement without a version on the left side is added, which applies
// to all versions of the old module path. If the @v in new@v is omitted,
// the new path should be a local module root directory, not a module
// path. Note that -replace overrides any redundant replacements for old[@v],
// so omitting @v will drop existing replacements for specific versions.
//
// The -dropreplace=old[@v] flag drops a replacement of the given
// module path and version pair. If the @v is omitted, a replacement without
// a version on the left side is dropped.
//
// The -use, -dropuse, -replace, and -dropreplace,
// editing flags may be repeated, and the changes are applied in the order given.
//
// The -go=version flag sets the expected Go language version.
//
// The -toolchain=name flag sets the Go toolchain to use.
//
// The -print flag prints the final go.work in its text format instead of
// writing it back to go.mod.
//
// The -json flag prints the final go.work file in JSON format instead of
// writing it back to go.mod. The JSON output corresponds to these Go types:
//
//	type GoWork struct {
//		Go        string
//		Toolchain string
//		Godebug   []Godebug
//		Use       []Use
//		Replace   []Replace
//	}
//
//	type Godebug struct {
//		Key   string
//		Value string
//	}
//
//	type Use struct {
//		DiskPath   string
//		ModulePath string
//	}
//
//	type Replace struct {
//		Old Module
//		New Module
//	}
//
//	type Module struct {
//		Path    string
//		Version string
//	}
//
// See the workspaces reference at https://go.dev/ref/mod#workspaces
// for more information.
//
// # Initialize workspace file
//
// Usage:
//
//	go work init [moddirs]
//
// Init initializes and writes a new go.work file in the
// current directory, in effect creating a new workspace at the current
// directory.
//
// go work init optionally accepts paths to the workspace modules as
// arguments. If the argument is omitted, an empty workspace with no
// modules will be created.
//
// Each argument path is added to a use directive in the go.work file. The
// current go version will also be listed in the go.work file.
//
// See the workspaces reference at https://go.dev/ref/mod#workspaces
// for more information.
//
// # Sync workspace build list to modules
//
// Usage:
//
//	go work sync
//
// Sync syncs the workspace's build list back to the
// workspace's modules
//
// The workspace's build list is the set of versions of all the
// (transitive) dependency modules used to do builds in the workspace. go
// work sync generates that build list using the Minimal Version Selection
// algorithm, and then syncs those versions back to each of modules
// specified in the workspace (with use directives).
//
// The syncing is done by sequentially upgrading each of the dependency
// modules specified in a workspace module to the version in the build list
// if the dependency module's version is not already the same as the build
// list's version. Note that Minimal Version Selection guarantees that the
// build list's version of each module is always the same or higher than
// that in each workspace module.
//
// See the workspaces reference at https://go.dev/ref/mod#workspaces
// for more information.
//
// # Add modules to workspace file
//
// Usage:
//
//	go work use [-r] [moddirs]
//
// Use provides a command-line interface for adding
// directories, optionally recursively, to a go.work file.
//
// A use directive will be added to the go.work file for each argument
// directory listed on the command line go.work file, if it exists,
// or removed from the go.work file if it does not exist.
// Use fails if any remaining use directives refer to modules that
// do not exist.
//
// Use updates the go line in go.work to specify a version at least as
// new as all the go lines in the used modules, both preexisting ones
// and newly added ones. With no arguments, this update is the only
// thing that go work use does.
//
// The -r flag searches recursively for modules in the argument
// directories, and the use command operates as if each of the directories
// were specified as arguments.
//
// See the workspaces reference at https://go.dev/ref/mod#workspaces
// for more information.
//
// # Make vendored copy of dependencies
//
// Usage:
//
//	go work vendor [-e] [-v] [-o outdir]
//
// Vendor resets the workspace's vendor directory to include all packages
// needed to build and test all the workspace's packages.
// It does not include test code for vendored packages.
//
// The -v flag causes vendor to print the names of vendored
// modules and packages to standard error.
//
// The -e flag causes vendor to attempt to proceed despite errors
// encountered while loading packages.
//
// The -o flag causes vendor to create the vendor directory at the given
// path instead of "vendor". The go command can only use a vendor directory
// named "vendor" within the module root directory, so this flag is
// primarily useful for other tools.
//
// # Compile and run Go program
//
// Usage:
//
//	go run [build flags] [-exec xprog] package [arguments...]
//
// Run compiles and runs the named main Go package.
// Typically the package is specified as a list of .go source files from a single
// directory, but it may also be an import path, file system path, or pattern
// matching a single known package, as in 'go run .' or 'go run my/cmd'.
//
// If the package argument has a version suffix (like @latest or @v1.0.0),
// "go run" builds the program in module-aware mode, ignoring the go.mod file in
// the current directory or any parent directory, if there is one. This is useful
// for running programs without affecting the dependencies of the main module.
//
// If the package argument doesn't have a version suffix, "go run" may run in
// module-aware mode or GOPATH mode, depending on the GO111MODULE environment
// variable and the presence of a go.mod file. See 'go help modules' for details.
// If module-aware mode is enabled, "go run" runs in the context of the main
// module.
//
// By default, 'go run' runs the compiled binary directly: 'a.out arguments...'.
// If the -exec flag is given, 'go run' invokes the binary using xprog:
//
//	'xprog a.out arguments...'.
//
// If the -exec flag is not given, GOOS or GOARCH is different from the system
// default, and a program named go_$GOOS_$GOARCH_exec can be found
// on the current search path, 'go run' invokes the binary using that program,
// for example 'go_js_wasm_exec a.out arguments...'. This allows execution of
// cross-compiled programs when a simulator or other execution method is
// available.
//
// By default, 'go run' compiles the binary without generating the information
// used by debuggers, to reduce build time. To include debugger information in
// the binary, use 'go build'.
//
// The exit status of Run is not the exit status of the compiled binary.
//
// For more about build flags, see 'go help build'.
// For more about specifying packages, see 'go help packages'.
//
// See also: go build.
//
// # Manage telemetry data and settings
//
// Usage:
//
//	go telemetry [off|local|on]
//
// Telemetry is used to manage Go telemetry data and settings.
//
// Telemetry can be in one of three modes: off, local, or on.
//
// When telemetry is in local mode, counter data is written to the local file
// system, but will not be uploaded to remote servers.
//
// When telemetry is off, local counter data is neither collected nor uploaded.
//
// When telemetry is on, telemetry data is written to the local file system
// and periodically sent to https://telemetry.go.dev/. Uploaded data is used to
// help improve the Go toolchain and related tools, and it will be published as
// part of a public dataset.
//
// For more details, see https://telemetry.go.dev/privacy.
// This data is collected in accordance with the Google Privacy Policy
// (https://policies.google.com/privacy).
//
// To view the current telemetry mode, run "go telemetry".
// To disable telemetry uploading, but keep local data collection, run
// "go telemetry local".
// To enable both collection and uploading, run “go telemetry on”.
// To disable both collection and uploading, run "go telemetry off".
//
// The current telemetry mode is also available as the value of the
// non-settable "GOTELEMETRY" go env variable. The directory in the
// local file system that telemetry data is written to is available
// as the value of the non-settable "GOTELEMETRYDIR" go env variable.
//
// See https://go.dev/doc/telemetry for more information on telemetry.
//
// # Test packages
//
// Usage:
//
//	go test [build/test flags] [packages] [build/test flags & test binary flags]
//
// 'Go test' automates testing the packages named by the import paths.
// It prints a summary of the test results in the format:
//
//	ok   archive/tar   0.011s
//	FAIL archive/zip   0.022s
//	ok   compress/gzip 0.033s
//	...
//
// followed by detailed output for each failed package.
//
// 'Go test' recompiles each package along with any files with names matching
// the file pattern "*_test.go".
// These additional files can contain test functions, benchmark functions, fuzz
// tests and example functions. See 'go help testfunc' for more.
// Each listed package causes the execution of a separate test binary.
// Files whose names begin with "_" (including "_test.go") or "." are ignored.
//
// Test files that declare a package with the suffix "_test" will be compiled as a
// separate package, and then linked and run with the main test binary.
//
// The go tool will ignore a directory named "testdata", making it available
// to hold ancillary data needed by the tests.
//
// As part of building a test binary, go test runs go vet on the package
// and its test source files to identify significant problems. If go vet
// finds any problems, go test reports those and does not run the test
// binary. Only a high-confidence subset of the default go vet checks are
// used. That subset is: atomic, bool, buildtags, directive, errorsas,
// ifaceassert, nilfunc, printf, stringintconv, and tests. You can see
// the documentation for these and other vet tests via "go doc cmd/vet".
// To disable the running of go vet, use the -vet=off flag. To run all
// checks, use the -vet=all flag.
//
// All test output and summary lines are printed to the go command's
// standard output, even if the test printed them to its own standard
// error. (The go command's standard error is reserved for printing
// errors building the tests.)
//
// The go command places $GOROOT/bin at the beginning of $PATH
// in the test's environment, so that tests that execute
// 'go' commands use the same 'go' as the parent 'go test' command.
//
// Go test runs in two different modes:
//
// The first, called local directory mode, occurs when go test is
// invoked with no package arguments (for example, 'go test' or 'go
// test -v'). In this mode, go test compiles the package sources and
// tests found in the current directory and then runs the resulting
// test binary. In this mode, caching (discussed below) is disabled.
// After the package test finishes, go test prints a summary line
// showing the test status ('ok' or 'FAIL'), package name, and elapsed
// time.
//
// The second, called package list mode, occurs when go test is invoked
// with explicit package arguments (for example 'go test math', 'go
// test ./...', and even 'go test .'). In this mode, go test compiles
// and tests each of the packages listed on the command line. If a
// package test passes, go test prints only the final 'ok' summary
// line. If a package test fails, go test prints the full test output.
// If invoked with the -bench or -v flag, go test prints the full
// output even for passing package tests, in order to display the
// requested benchmark results or verbose logging. After the package
// tests for all of the listed packages finish, and their output is
// printed, go test prints a final 'FAIL' status if any package test
// has failed.
//
// In package list mode only, go test caches successful package test
// results to avoid unnecessary repeated running of tests. When the
// result of a test can be recovered from the cache, go test will
// redisplay the previous output instead of running the test binary
// again. When this happens, go test prints '(cached)' in place of the
// elapsed time in the summary line.
//
// The rule for a match in the cache is that the run involves the same
// test binary and the flags on the command line come entirely from a
// restricted set of 'cacheable' test flags, defined as -benchtime, -cpu,
// -list, -parallel, -run, -short, -timeout, -failfast, -fullpath and -v.
// If a run of go test has any test or non-test flags outside this set,
// the result is not cached. To disable test caching, use any test flag
// or argument other than the cacheable flags. The idiomatic way to disable
// test caching explicitly is to use -count=1. Tests that open files within
// the package's module or that consult environment variables only
// match future runs in which the files and environment variables are
// unchanged. A cached test result is treated as executing in no time
// at all, so a successful package test result will be cached and
// reused regardless of -timeout setting.
//
// In addition to the build flags, the flags handled by 'go test' itself are:
//
//	-args
//	    Pass the remainder of the command line (everything after -args)
//	    to the test binary, uninterpreted and unchanged.
//	    Because this flag consumes the remainder of the command line,
//	    the package list (if present) must appear before this flag.
//
//	-c
//	    Compile the test binary to pkg.test in the current directory but do not run it
//	    (where pkg is the last element of the package's import path).
//	    The file name or target directory can be changed with the -o flag.
//
//	-exec xprog
//	    Run the test binary using xprog. The behavior is the same as
//	    in 'go run'. See 'go help run' for details.
//
//	-json
//	    Convert test output to JSON suitable for automated processing.
//	    See 'go doc test2json' for the encoding details.
//	    Also emits build output in JSON. See 'go help buildjson'.
//
//	-o file
//	    Compile the test binary to the named file.
//	    The test still runs (unless -c or -i is specified).
//	    If file ends in a slash or names an existing directory,
//	    the test is written to pkg.test in that directory.
//
// The test binary also accepts flags that control execution of the test; these
// flags are also accessible by 'go test'. See 'go help testflag' for details.
//
// For more about build flags, see 'go help build'.
// For more about specifying packages, see 'go help packages'.
//
// See also: go build, go vet.
//
// # Run specified go tool
//
// Usage:
//
//	go tool [-n] command [args...]
//
// Tool runs the go tool command identified by the arguments.
//
// Go ships with a number of builtin tools, and additional tools
// may be defined in the go.mod of the current module.
//
// With no arguments it prints the list of known tools.
//
// The -n flag causes tool to print the command that would be
// executed but not execute it.
//
// For more about each builtin tool command, see 'go doc cmd/<command>'.
//
// # Print Go version
//
// Usage:
//
//	go version [-m] [-v] [file ...]
//
// Version prints the build information for Go binary files.
//
// Go version reports the Go version used to build each of the named files.
//
// If no files are named on the command line, go version prints its own
// version information.
//
// If a directory is named, go version walks that directory, recursively,
// looking for recognized Go binaries and reporting their versions.
// By default, go version does not report unrecognized files found
// during a directory scan. The -v flag causes it to report unrecognized files.
//
// The -m flag causes go version to print each file's embedded
// module version information, when available. In the output, the module
// information consists of multiple lines following the version line, each
// indented by a leading tab character.
//
// See also: go doc runtime/debug.BuildInfo.
//
// # Report likely mistakes in packages
//
// Usage:
//
//	go vet [build flags] [-vettool prog] [vet flags] [packages]
//
// Vet runs the Go vet command on the packages named by the import paths.
//
// For more about vet and its flags, see 'go doc cmd/vet'.
// For more about specifying packages, see 'go help packages'.
// For a list of checkers and their flags, see 'go tool vet help'.
// For details of a specific checker such as 'printf', see 'go tool vet help printf'.
//
// The -vettool=prog flag selects a different analysis tool with alternative
// or additional checks.
// For example, the 'shadow' analyzer can be built and run using these commands:
//
//	go install golang.org/x/tools/go/analysis/passes/shadow/cmd/shadow@latest
//	go vet -vettool=$(which shadow)
//
// The build flags supported by go vet are those that control package resolution
// and execution, such as -C, -n, -x, -v, -tags, and -toolexec.
// For more about these flags, see 'go help build'.
//
// See also: go fmt, go fix.
//
// # Build constraints
//
// A build constraint, also known as a build tag, is a condition under which a
// file should be included in the package. Build constraints are given by a
// line comment that begins
//
//	//go:build
//
// Build constraints can also be used to downgrade the language version
// used to compile a file.
//
// Constraints may appear in any kind of source file (not just Go), but
// they must appear near the top of the file, preceded
// only by blank lines and other comments. These rules mean that in Go
// files a build constraint must appear before the package clause.
//
// To distinguish build constraints from package documentation,
// a build constraint should be followed by a blank line.
//
// A build constraint comment is evaluated as an expression containing
// build tags combined by ||, &&, and ! operators and parentheses.
// Operators have the same meaning as in Go.
//
// For example, the following build constraint constrains a file to
// build when the "linux" and "386" constraints are satisfied, or when
// "darwin" is satisfied and "cgo" is not:
//
//	//go:build (linux && 386) || (darwin && !cgo)
//
// It is an error for a file to have more than one //go:build line.
//
// During a particular build, the following build tags are satisfied:
//
//   - the target operating system, as spelled by runtime.GOOS, set with the
//     GOOS environment variable.
//   - the target architecture, as spelled by runtime.GOARCH, set with the
//     GOARCH environment variable.
//   - any architecture features, in the form GOARCH.feature
//     (for example, "amd64.v2"), as detailed below.
//   - "unix", if GOOS is a Unix or Unix-like system.
//   - the compiler being used, either "gc" or "gccgo"
//   - "cgo", if the cgo command is supported (see CGO_ENABLED in
//     'go help environment').
//   - a term for each Go major release, through the current version:
//     "go1.1" from Go version 1.1 onward, "go1.12" from Go 1.12, and so on.
//   - any additional tags given by the -tags flag (see 'go help build').
//
// There are no separate build tags for beta or minor releases.
//
// If a file's name, after stripping the extension and a possible _test suffix,
// matches any of the following patterns:
//
//	*_GOOS
//	*_GOARCH
//	*_GOOS_GOARCH
//
// (example: source_windows_amd64.go) where GOOS and GOARCH represent
// any known operating system and architecture values respectively, then
// the file is considered to have an implicit build constraint requiring
// those terms (in addition to any explicit constraints in the file).
//
// Using GOOS=android matches build tags and files as for GOOS=linux
// in addition to android tags and files.
//
// Using GOOS=illumos matches build tags and files as for GOOS=solaris
// in addition to illumos tags and files.
//
// Using GOOS=ios matches build tags and files as for GOOS=darwin
// in addition to ios tags and files.
//
// The defined architecture feature build tags are:
//
//   - For GOARCH=386, GO386=387 and GO386=sse2
//     set the 386.387 and 386.sse2 build tags, respectively.
//   - For GOARCH=amd64, GOAMD64=v1, v2, and v3
//     correspond to the amd64.v1, amd64.v2, and amd64.v3 feature build tags.
//   - For GOARCH=arm, GOARM=5, 6, and 7
//     correspond to the arm.5, arm.6, and arm.7 feature build tags.
//   - For GOARCH=arm64, GOARM64=v8.{0-9} and v9.{0-5}
//     correspond to the arm64.v8.{0-9} and arm64.v9.{0-5} feature build tags.
//   - For GOARCH=mips or mipsle,
//     GOMIPS=hardfloat and softfloat
//     correspond to the mips.hardfloat and mips.softfloat
//     (or mipsle.hardfloat and mipsle.softfloat) feature build tags.
//   - For GOARCH=mips64 or mips64le,
//     GOMIPS64=hardfloat and softfloat
//     correspond to the mips64.hardfloat and mips64.softfloat
//     (or mips64le.hardfloat and mips64le.softfloat) feature build tags.
//   - For GOARCH=ppc64 or ppc64le,
//     GOPPC64=power8, power9, and power10 correspond to the
//     ppc64.power8, ppc64.power9, and ppc64.power10
//     (or ppc64le.power8, ppc64le.power9, and ppc64le.power10)
//     feature build tags.
//   - For GOARCH=riscv64,
//     GORISCV64=rva20u64 and rva22u64 correspond to the riscv64.rva20u64
//     and riscv64.rva22u64 build tags.
//   - For GOARCH=wasm, GOWASM=satconv and signext
//     correspond to the wasm.satconv and wasm.signext feature build tags.
//
// For GOARCH=amd64, arm, ppc64, ppc64le, and riscv64, a particular feature level
// sets the feature build tags for all previous levels as well.
// For example, GOAMD64=v2 sets the amd64.v1 and amd64.v2 feature flags.
// This ensures that code making use of v2 features continues to compile
// when, say, GOAMD64=v4 is introduced.
// Code handling the absence of a particular feature level
// should use a negation:
//
//	//go:build !amd64.v2
//
// To keep a file from being considered for any build:
//
//	//go:build ignore
//
// (Any other unsatisfied word will work as well, but "ignore" is conventional.)
//
// To build a file only when using cgo, and only on Linux and OS X:
//
//	//go:build cgo && (linux || darwin)
//
// Such a file is usually paired with another file implementing the
// default functionality for other systems, which in this case would
// carry the constraint:
//
//	//go:build !(cgo && (linux || darwin))
//
// Naming a file dns_windows.go will cause it to be included only when
// building the package for Windows; similarly, math_386.s will be included
// only when building the package for 32-bit x86.
//
// Go versions 1.16 and earlier used a different syntax for build constraints,
// with a "// +build" prefix. The gofmt command will add an equivalent //go:build
// constraint when encountering the older syntax.
//
// In modules with a Go version of 1.21 or later, if a file's build constraint
// has a term for a Go major release, the language version used when compiling
// the file will be the minimum version implied by the build constraint.
//
// # Build -json encoding
//
// The 'go build', 'go install', and 'go test' commands take a -json flag that
// reports build output and failures as structured JSON output on standard
// output.
//
// The JSON stream is a newline-separated sequence of BuildEvent objects
// corresponding to the Go struct:
//
//	type BuildEvent struct {
//		ImportPath string
//		Action     string
//		Output     string
//	}
//
// The ImportPath field gives the package ID of the package being built.
// This matches the Package.ImportPath field of go list -json and the
// TestEvent.FailedBuild field of go test -json. Note that it does not
// match TestEvent.Package.
//
// The Action field is one of the following:
//
//	build-output - The toolchain printed output
//	build-fail - The build failed
//
// The Output field is set for Action == "build-output" and is a portion of
// the build's output. The concatenation of the Output fields of all output
// events is the exact output of the build. A single event may contain one
// or more lines of output and there may be more than one output event for
// a given ImportPath. This matches the definition of the TestEvent.Output
// field produced by go test -json.
//
// For go test -json, this struct is designed so that parsers can distinguish
// interleaved TestEvents and BuildEvents by inspecting the Action field.
// Furthermore, as with TestEvent, parsers can simply concatenate the Output
// fields of all events to reconstruct the text format output, as it would
// have appeared from go build without the -json flag.
//
// Note that there may also be non-JSON error text on stdnard error, even
// with the -json flag. Typically, this indicates an early, serious error.
// Consumers should be robust to this.
//
// # Build modes
//
// The 'go build' and 'go install' commands take a -buildmode argument which
// indicates which kind of object file is to be built. Currently supported values
// are:
//
//	-buildmode=archive
//		Build the listed non-main packages into .a files. Packages named
//		main are ignored.
//
//	-buildmode=c-archive
//		Build the listed main package, plus all packages it imports,
//		into a C archive file. The only callable symbols will be those
//		functions exported using a cgo //export comment. Requires
//		exactly one main package to be listed.
//
//	-buildmode=c-shared
//		Build the listed main package, plus all packages it imports,
//		into a C shared library. The only callable symbols will
//		be those functions exported using a cgo //export comment.
//		On wasip1, this mode builds it to a WASI reactor/library,
//		of which the callable symbols are those functions exported
//		using a //go:wasmexport directive. Requires exactly one
//		main package to be listed.
//
//	-buildmode=default
//		Listed main packages are built into executables and listed
//		non-main packages are built into .a files (the default
//		behavior).
//
//	-buildmode=shared
//		Combine all the listed non-main packages into a single shared
//		library that will be used when building with the -linkshared
//		option. Packages named main are ignored.
//
//	-buildmode=exe
//		Build the listed main packages and everything they import into
//		executables. Packages not named main are ignored.
//
//	-buildmode=pie
//		Build the listed main packages and everything they import into
//		position independent executables (PIE). Packages not named
//		main are ignored.
//
//	-buildmode=plugin
//		Build the listed main packages, plus all packages that they
//		import, into a Go plugin. Packages not named main are ignored.
//
// On AIX, when linking a C program that uses a Go archive built with
// -buildmode=c-archive, you must pass -Wl,-bnoobjreorder to the C compiler.
//
// # Calling between Go and C
//
// There are two different ways to call between Go and C/C++ code.
//
// The first is the cgo tool, which is part of the Go distribution. For
// information on how to use it see the cgo documentation (go doc cmd/cgo).
//
// The second is the SWIG program, which is a general tool for
// interfacing between languages. For information on SWIG see
// https://swig.org/. When running go build, any file with a .swig
// extension will be passed to SWIG. Any file with a .swigcxx extension
// will be passed to SWIG with the -c++ option.
//
// When either cgo or SWIG is used, go build will pass any .c, .m, .s, .S
// or .sx files to the C compiler, and any .cc, .cpp, .cxx files to the C++
// compiler. The CC or CXX environment variables may be set to determine
// the C or C++ compiler, respectively, to use.
//
// # Build and test caching
//
// The go command caches build outputs for reuse in future builds.
// The default location for cache data is a subdirectory named go-build
// in the standard user cache directory for the current operating system.
// The cache is safe for concurrent invocations of the go command.
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
// The go command also caches values used in fuzzing with 'go test -fuzz',
// specifically, values that expanded code coverage when passed to a
// fuzz function. These values are not used for regular building and
// testing, but they're stored in a subdirectory of the build cache.
// Running 'go clean -fuzzcache' removes all cached fuzzing values.
// This may make fuzzing less effective, temporarily.
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
// # Environment variables
//
// The go command and the tools it invokes consult environment variables
// for configuration. If an environment variable is unset or empty, the go
// command uses a sensible default setting. To see the effective setting of
// the variable <NAME>, run 'go env <NAME>'. To change the default setting,
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