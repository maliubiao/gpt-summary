Response:
Let's break down the thought process for summarizing the provided Go code snippet.

1. **Understand the Goal:** The request asks for a summary of the functionality of the given Go code, which is a part of `go/src/cmd/dist/build.go`. This means we need to identify the main tasks and purposes of this code section within the larger Go build system.

2. **Initial Scan for Keywords and Structure:**  A quick scan reveals important function names like `cmdbootstrap`, `cmdinstall`, `cmdclean`, `cmdbanner`, `cmdversion`, `cmdlist`, `toolenv`, `goInstall`, `goCmd`, and variables like `cgoEnabled`, `broken`, `firstClass`. The presence of `flag` package usage suggests command-line argument handling. The `timelog` function and the related variables indicate logging of build times.

3. **Focus on the Core Function: `cmdbootstrap`:**  The name `cmdbootstrap` strongly suggests the primary function is related to bootstrapping the Go toolchain. Reading through this function reveals a multi-step process:
    * It sets up the environment (GOPATH, GOCACHE, GOPROXY, GOEXPERIMENT).
    * It builds the initial Go toolchain (`toolchain1`).
    * It builds `cmd/go` using this initial toolchain (as `go_bootstrap`).
    * It then uses `go_bootstrap` and `toolchain1` to build a more complete toolchain (`toolchain2` and `toolchain3`). This iterative building suggests correcting for potential discrepancies or limitations in the initially built toolchain.
    * It installs standard libraries and commands.
    * It checks for unexpected files in `$GOROOT/bin`.
    * It handles cross-compilation scenarios.
    * It can optionally create distribution packages.
    * It prints a final banner.

4. **Identify Supporting Functions:** Once the core function is understood, the supporting functions become easier to categorize:
    * **Environment Setup:** `setEnv`, `xprintf` (for formatted output with environment vars), `toolenv` (specifically for tool building environment).
    * **Build Execution:** `goInstall`, `goCmd`, `runEnv` (these clearly deal with executing Go commands and other processes). `appendCompilerFlags` modifies command arguments.
    * **Dependency Management/Checking:** `checkNotStale` (verifies if targets need rebuilding).
    * **Information and Listing:** `cmdlist` (lists supported platforms), `cmdversion`, `cmdbanner`. The variables `cgoEnabled`, `broken`, and `firstClass` are used by `cmdlist`.
    * **Maintenance:** `cmdclean`.
    * **Logging:** `timelog`.
    * **Platform Specifics:** `wrapperPathFor`, checks for Plan 9 and PATH environment variables in `cmdbanner`.
    * **Helper Functions:** `defaulttarg` (determines the default target for installation), `needCC`, `checkCC`.

5. **Look for Patterns and Themes:**  Several recurring themes emerge:
    * **Bootstrapping:** The process of building the Go toolchain using successively built versions of itself.
    * **Toolchain Management:** Building, installing, and verifying the Go toolchain components.
    * **Environment Control:** Carefully managing environment variables like `GOPATH`, `GOCACHE`, `GOOS`, `GOARCH`, `CC`, etc.
    * **Cross-Compilation:** Handling builds for different target operating systems and architectures.
    * **Reproducibility (Implied):**  The use of `-trimpath` suggests an effort towards creating reproducible builds.
    * **Error Handling:** The use of `fatalf` indicates a focus on reporting critical errors.

6. **Synthesize the Summary:**  Combine the identified functions, themes, and the core purpose of `cmdbootstrap` into a coherent summary. Start with the most important function and then branch out to describe the related functionalities. Use clear and concise language. Mention the command-line arguments and environment variables involved where relevant.

7. **Refine and Organize:**  Review the summary for clarity, completeness, and accuracy. Organize the information logically. For instance, group functions related to building, listing, or environment setup together.

By following these steps, we can systematically analyze the code snippet and produce a comprehensive summary of its functionality, as demonstrated in the provided example answer. The key is to start with the central function and then progressively understand the roles of the other components in supporting that function.
这是 `go/src/cmd/dist/build.go` 文件的一部分，主要负责构建 Go 语言本身。这段代码主要关注于 **构建过程中的环境变量设置** 和 **时间日志记录**，以及一个核心的 **bootstrap 构建流程**。

**功能归纳:**

这段代码主要负责以下功能：

1. **设置构建环境变量:**
   -  它定义了一个 `printEnv` 函数，用于打印构建过程中使用的环境变量。这些环境变量对 Go 编译器的行为至关重要，包括目标操作系统和架构、Go 的根目录、工具目录等。
   -  根据不同的目标架构 (`goarch`)，设置特定的环境变量，例如 `GOARM`、`GOAMD64` 等。
   -  如果设置了 `-path` 命令行参数，它会设置 `PATH` 环境变量，确保 Go 的可执行文件能够被找到。同时，它还会设置 `DIST_UNMODIFIED_PATH`，用于记录原始的 `PATH` 值。

2. **实现时间日志记录:**
   -  它定义了一组用于记录构建过程耗时的变量和函数 (`timeLogEnabled`, `timeLogMu`, `timeLogFile`, `timeLogStart`, `timelog`)。
   -  如果设置了 `GOBUILDTIMELOGFILE` 环境变量，`timelog` 函数会将操作名称和耗时记录到指定的文件中，方便分析构建性能。

3. **定义工具链构建环境:**
   -  `toolenv` 函数返回一个用于构建 `cmd` 目录下命令的环境变量切片。
   -  默认情况下，除非平台需要外部链接，否则会禁用 cgo (`CGO_ENABLED=0`)，以生成静态链接的 `cmd/go` 和 `cmd/pprof`。
   -  在发布版本或者通过 `GO_BUILDER_NAME` 环境变量指定为构建器时，会添加 `-trimpath` 和 `-ldflags=-w -gcflags=cmd/...=-dwarf=false`，以提高构建的可重现性并减小二进制文件大小。

4. **实现 Bootstrap 构建流程 (`cmdbootstrap` 函数):**
   -  这是一个关键的函数，负责从头开始构建 Go 语言环境，直到安装 `go_bootstrap` 命令。
   -  它处理一些命令行参数，例如 `-a` (重建所有)、`-d` (调试)、`-force` (强制构建) 等。
   -  它会检查目标平台是否被标记为 broken，如果被标记且没有 `-force` 参数，则会停止构建。
   -  它设置临时的 `GOPATH`、禁用 `GOPROXY`，并使用单独的构建缓存。
   -  它分阶段构建 Go 工具链：
      -  首先使用已有的 Go 环境构建一个初始的工具链 (`toolchain1`)。
      -  然后使用 `toolchain1` 构建新的 `cmd/go` 命令，命名为 `go_bootstrap`。
      -  接下来，使用 `go_bootstrap` 和 `toolchain1` 构建更完整的工具链 (`toolchain2` 和 `toolchain3`)，确保构建的工具链拥有正确的 build ID。
      -  最后，使用构建好的工具链和 `go_bootstrap` 命令安装标准库和命令。
   -  它会检查 `$GOROOT/bin` 目录下是否有不期望出现的新文件。
   -  它会处理特定平台（例如 Android）的执行包装器。
   -  如果指定了 `-distpack`，它会打包发布文件。
   -  最后，它会打印构建成功的横幅信息。

5. **其他辅助命令的实现:**
   -  `cmdinstall`: 安装指定的包或当前目录的包。
   -  `cmdclean`: 清理临时构建文件。
   -  `cmdbanner`: 打印构建完成的横幅信息。
   -  `cmdversion`: 打印 Go 版本信息。
   -  `cmdlist`: 列出所有支持的平台。

**可以推理出的 Go 语言功能实现:**

这段代码是 Go 语言构建过程的核心部分，体现了 Go 语言的自举特性（bootstrapping）。Go 编译器本身就是用 Go 编写的，因此需要一个已有的 Go 环境来构建新的 Go 编译器。`cmdbootstrap` 函数就是实现了这个自举的过程。

**Go 代码示例 (基于 `printEnv` 函数的推断):**

假设我们运行 `go tool dist env -p` 命令，这会调用到 `printEnv` 函数。

```go
// 假设的 printEnv 函数实现
func printEnv(format string, withPath bool) {
	goos := "linux"  // 假设的 GOOS
	goarch := "amd64" // 假设的 GOARCH
	goroot := "/usr/local/go" // 假设的 GOROOT
	gorootBin := "/usr/local/go/bin"
	tooldir := "/usr/local/go/pkg/tool/linux_amd64"
	gohostos := "linux"
	gohostarch := "amd64"

	xprintf := func(format string, args ...interface{}) {
		fmt.Printf(format+"\n", args...)
	}

	xprintf(format, "GOARCH", goarch)
	xprintf(format, "GOBIN", gorootBin)
	xprintf(format, "GOROOT", goroot)
	xprintf(format, "GOTOOLDIR", tooldir)
	xprintf(format, "GOHOSTARCH", gohostarch)
	xprintf(format, "GOHOSTOS", gohostos)
	xprintf(format, "GOOS", goos)

	if withPath {
		sep := ":"
		xprintf(format, "PATH", fmt.Sprintf("%s%s%s", gorootBin, sep, os.Getenv("PATH")))
	}
}

func main() {
	printEnv("%s=\"%s\"", true) // 模拟带 -p 参数的调用
}

// 假设的输出：
// GOARCH="amd64"
// GOBIN="/usr/local/go/bin"
// GOROOT="/usr/local/go"
// GOTOOLDIR="/usr/local/go/pkg/tool/linux_amd64"
// GOHOSTARCH="amd64"
// GOHOSTOS="linux"
// GOOS="linux"
// PATH="/usr/local/go/bin:/usr/bin:/bin" // 假设的 PATH 环境变量
```

**假设的输入与输出 (基于 `timelog` 函数的推断):**

假设设置了环境变量 `GOBUILDTIMELOGFILE=/tmp/go_build_time.log`，并且在构建过程中调用了 `timelog` 函数。

```go
// 假设的 timelog 函数实现
var (
	timeLogEnabled = os.Getenv("GOBUILDTIMELOGFILE") != ""
	timeLogMu      sync.Mutex
	timeLogFile    *os.File
	timeLogStart   time.Time
)

func timelog(op, name string) {
	if !timeLogEnabled {
		return
	}
	timeLogMu.Lock()
	defer timeLogMu.Unlock()
	if timeLogFile == nil {
		f, err := os.OpenFile(os.Getenv("GOBUILDTIMELOGFILE"), os.O_RDWR|os.O_APPEND|os.O_CREATE, 0666)
		if err != nil {
			log.Fatal(err)
		}
		timeLogFile = f
		timeLogStart = time.Now()
		fmt.Fprintf(timeLogFile, "%s start\n", timeLogStart.Format(time.UnixDate))
	}
	t := time.Now()
	fmt.Fprintf(timeLogFile, "%s %+.1fs %s %s\n", t.Format(time.UnixDate), t.Sub(timeLogStart).Seconds(), op, name)
}

func main() {
	os.Setenv("GOBUILDTIMELOGFILE", "/tmp/go_build_time.log")
	timelog("build", "runtime")
	time.Sleep(1 * time.Second)
	timelog("build", "cmd/compile")
}
```

**`/tmp/go_build_time.log` 的内容 (可能的输出):**

```
Mon Jan  1 00:00:00 UTC 0000 start
Mon Jan  1 00:00:00 UTC 0000 +0.0s build runtime
Mon Jan  1 00:00:01 UTC 0000 +1.0s build cmd/compile
```

**命令行参数的具体处理 (基于 `cmdbootstrap` 函数的推断):**

在 `cmdbootstrap` 函数中，使用了 `flag` 包来处理命令行参数：

- `-a`:  `flag.BoolVar(&rebuildall, "a", rebuildall, "rebuild all")` - 如果指定，`rebuildall` 变量将被设置为 `true`，表示需要重建所有内容。
- `-d`:  `flag.BoolVar(&debug, "d", debug, "enable debugging of bootstrap process")` - 如果指定，`debug` 变量将被设置为 `true`，启用 bootstrap 过程的调试。
- `-distpack`: `flag.BoolVar(&distpack, "distpack", distpack, "write distribution files to pkg/distpack")` - 如果指定，`distpack` 变量将被设置为 `true`，表示需要将分发文件写入 `pkg/distpack` 目录。
- `-force`: `flag.BoolVar(&force, "force", force, "build even if the port is marked as broken")` - 如果指定，`force` 变量将被设置为 `true`，即使目标平台被标记为 broken 也会继续构建。
- `-no-banner`: `flag.BoolVar(&noBanner, "no-banner", noBanner, "do not print banner")` - 如果指定，`noBanner` 变量将被设置为 `true`，阻止打印构建完成的横幅信息。
- `-no-clean`: `flag.BoolVar(&noClean, "no-clean", noClean, "print deprecation warning")` - 如果指定，`noClean` 变量将被设置为 `true`，虽然这个参数已经废弃，但代码中仍然会打印一个警告。

`xflagparse(0)` 用于解析这些命令行参数。`0` 表示期望的参数数量下限，这里表示允许没有额外的参数。

**使用者易犯错的点 (基于 `cmdbootstrap` 函数的推断):**

1. **在 broken 平台上构建不加 `-force` 标志:**  如果尝试在 `broken` 变量中标记的平台上构建 Go，并且没有使用 `-force` 标志，构建会因为检测到平台被标记为 broken 而停止，并提示用户使用 `-force` 标志。

   ```bash
   # 假设 linux/sparc64 是 broken 的
   go tool dist build
   # 输出类似：build stopped because the port linux/sparc64 is marked as broken
   #
   # Use the -force flag to build anyway.

   go tool dist build -force # 正确的做法
   ```

2. **误解 `-no-clean` 的作用:**  `--no-clean` 参数已经废弃，不会阻止清理操作。用户可能会误认为加上这个参数可以避免清理，但实际上它没有任何效果，只会打印一个警告。

   ```bash
   go tool dist build --no-clean # 会打印警告，但不会阻止清理
   ```

**这是第2部分，共2部分，请归纳一下它的功能**

综合来看，这段代码是 Go 语言构建工具 `cmd/dist` 的核心组成部分，**负责执行 Go 语言自身的 bootstrap 构建过程，并提供了一些辅助命令来管理构建环境和查看构建信息。** 它细致地管理构建过程中需要的各种环境变量，确保构建过程的正确性。同时，它也提供了时间日志功能，方便开发者分析构建性能。`cmdbootstrap` 函数是这段代码的灵魂，它通过多阶段的构建过程，使用已有的 Go 环境来构建新的 Go 工具链，体现了 Go 语言强大的自举能力。其他命令如 `cmdinstall`、`cmdclean` 等则提供了构建和维护 Go 环境的常用功能。

### 提示词
```
这是路径为go/src/cmd/dist/build.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
"GO111MODULE", "")
	xprintf(format, "GOARCH", goarch)
	xprintf(format, "GOBIN", gorootBin)
	xprintf(format, "GODEBUG", os.Getenv("GODEBUG"))
	xprintf(format, "GOENV", "off")
	xprintf(format, "GOFLAGS", "")
	xprintf(format, "GOHOSTARCH", gohostarch)
	xprintf(format, "GOHOSTOS", gohostos)
	xprintf(format, "GOOS", goos)
	xprintf(format, "GOPROXY", os.Getenv("GOPROXY"))
	xprintf(format, "GOROOT", goroot)
	xprintf(format, "GOTMPDIR", os.Getenv("GOTMPDIR"))
	xprintf(format, "GOTOOLDIR", tooldir)
	if goarch == "arm" {
		xprintf(format, "GOARM", goarm)
	}
	if goarch == "arm64" {
		xprintf(format, "GOARM64", goarm64)
	}
	if goarch == "386" {
		xprintf(format, "GO386", go386)
	}
	if goarch == "amd64" {
		xprintf(format, "GOAMD64", goamd64)
	}
	if goarch == "mips" || goarch == "mipsle" {
		xprintf(format, "GOMIPS", gomips)
	}
	if goarch == "mips64" || goarch == "mips64le" {
		xprintf(format, "GOMIPS64", gomips64)
	}
	if goarch == "ppc64" || goarch == "ppc64le" {
		xprintf(format, "GOPPC64", goppc64)
	}
	if goarch == "riscv64" {
		xprintf(format, "GORISCV64", goriscv64)
	}
	xprintf(format, "GOWORK", "off")

	if *path {
		sep := ":"
		if gohostos == "windows" {
			sep = ";"
		}
		xprintf(format, "PATH", fmt.Sprintf("%s%s%s", gorootBin, sep, os.Getenv("PATH")))

		// Also include $DIST_UNMODIFIED_PATH with the original $PATH
		// for the internal needs of "dist banner", along with export
		// so that it reaches the dist process. See its comment below.
		var exportFormat string
		if !*windows && !*plan9 {
			exportFormat = "export " + format
		} else {
			exportFormat = format
		}
		xprintf(exportFormat, "DIST_UNMODIFIED_PATH", os.Getenv("PATH"))
	}
}

var (
	timeLogEnabled = os.Getenv("GOBUILDTIMELOGFILE") != ""
	timeLogMu      sync.Mutex
	timeLogFile    *os.File
	timeLogStart   time.Time
)

func timelog(op, name string) {
	if !timeLogEnabled {
		return
	}
	timeLogMu.Lock()
	defer timeLogMu.Unlock()
	if timeLogFile == nil {
		f, err := os.OpenFile(os.Getenv("GOBUILDTIMELOGFILE"), os.O_RDWR|os.O_APPEND, 0666)
		if err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, 100)
		n, _ := f.Read(buf)
		s := string(buf[:n])
		if i := strings.Index(s, "\n"); i >= 0 {
			s = s[:i]
		}
		i := strings.Index(s, " start")
		if i < 0 {
			log.Fatalf("time log %s does not begin with start line", os.Getenv("GOBUILDTIMELOGFILE"))
		}
		t, err := time.Parse(time.UnixDate, s[:i])
		if err != nil {
			log.Fatalf("cannot parse time log line %q: %v", s, err)
		}
		timeLogStart = t
		timeLogFile = f
	}
	t := time.Now()
	fmt.Fprintf(timeLogFile, "%s %+.1fs %s %s\n", t.Format(time.UnixDate), t.Sub(timeLogStart).Seconds(), op, name)
}

// toolenv returns the environment to use when building commands in cmd.
//
// This is a function instead of a variable because the exact toolenv depends
// on the GOOS and GOARCH, and (at least for now) those are modified in place
// to switch between the host and target configurations when cross-compiling.
func toolenv() []string {
	var env []string
	if !mustLinkExternal(goos, goarch, false) {
		// Unless the platform requires external linking,
		// we disable cgo to get static binaries for cmd/go and cmd/pprof,
		// so that they work on systems without the same dynamic libraries
		// as the original build system.
		env = append(env, "CGO_ENABLED=0")
	}
	if isRelease || os.Getenv("GO_BUILDER_NAME") != "" {
		// Add -trimpath for reproducible builds of releases.
		// Include builders so that -trimpath is well-tested ahead of releases.
		// Do not include local development, so that people working in the
		// main branch for day-to-day work on the Go toolchain itself can
		// still have full paths for stack traces for compiler crashes and the like.
		env = append(env, "GOFLAGS=-trimpath -ldflags=-w -gcflags=cmd/...=-dwarf=false")
	}
	return env
}

var toolchain = []string{"cmd/asm", "cmd/cgo", "cmd/compile", "cmd/link", "cmd/preprofile"}

// The bootstrap command runs a build from scratch,
// stopping at having installed the go_bootstrap command.
//
// WARNING: This command runs after cmd/dist is built with the Go bootstrap toolchain.
// It rebuilds and installs cmd/dist with the new toolchain, so other
// commands (like "go tool dist test" in run.bash) can rely on bug fixes
// made since the Go bootstrap version, but this function cannot.
func cmdbootstrap() {
	timelog("start", "dist bootstrap")
	defer timelog("end", "dist bootstrap")

	var debug, distpack, force, noBanner, noClean bool
	flag.BoolVar(&rebuildall, "a", rebuildall, "rebuild all")
	flag.BoolVar(&debug, "d", debug, "enable debugging of bootstrap process")
	flag.BoolVar(&distpack, "distpack", distpack, "write distribution files to pkg/distpack")
	flag.BoolVar(&force, "force", force, "build even if the port is marked as broken")
	flag.BoolVar(&noBanner, "no-banner", noBanner, "do not print banner")
	flag.BoolVar(&noClean, "no-clean", noClean, "print deprecation warning")

	xflagparse(0)

	if noClean {
		xprintf("warning: --no-clean is deprecated and has no effect; use 'go install std cmd' instead\n")
	}

	// Don't build broken ports by default.
	if broken[goos+"/"+goarch] && !force {
		fatalf("build stopped because the port %s/%s is marked as broken\n\n"+
			"Use the -force flag to build anyway.\n", goos, goarch)
	}

	// Set GOPATH to an internal directory. We shouldn't actually
	// need to store files here, since the toolchain won't
	// depend on modules outside of vendor directories, but if
	// GOPATH points somewhere else (e.g., to GOROOT), the
	// go tool may complain.
	os.Setenv("GOPATH", pathf("%s/pkg/obj/gopath", goroot))

	// Set GOPROXY=off to avoid downloading modules to the modcache in
	// the GOPATH set above to be inside GOROOT. The modcache is read
	// only so if we downloaded to the modcache, we'd create readonly
	// files in GOROOT, which is undesirable. See #67463)
	os.Setenv("GOPROXY", "off")

	// Use a build cache separate from the default user one.
	// Also one that will be wiped out during startup, so that
	// make.bash really does start from a clean slate.
	oldgocache = os.Getenv("GOCACHE")
	os.Setenv("GOCACHE", pathf("%s/pkg/obj/go-build", goroot))

	// Disable GOEXPERIMENT when building toolchain1 and
	// go_bootstrap. We don't need any experiments for the
	// bootstrap toolchain, and this lets us avoid duplicating the
	// GOEXPERIMENT-related build logic from cmd/go here. If the
	// bootstrap toolchain is < Go 1.17, it will ignore this
	// anyway since GOEXPERIMENT is baked in; otherwise it will
	// pick it up from the environment we set here. Once we're
	// using toolchain1 with dist as the build system, we need to
	// override this to keep the experiments assumed by the
	// toolchain and by dist consistent. Once go_bootstrap takes
	// over the build process, we'll set this back to the original
	// GOEXPERIMENT.
	os.Setenv("GOEXPERIMENT", "none")

	if debug {
		// cmd/buildid is used in debug mode.
		toolchain = append(toolchain, "cmd/buildid")
	}

	if isdir(pathf("%s/src/pkg", goroot)) {
		fatalf("\n\n"+
			"The Go package sources have moved to $GOROOT/src.\n"+
			"*** %s still exists. ***\n"+
			"It probably contains stale files that may confuse the build.\n"+
			"Please (check what's there and) remove it and try again.\n"+
			"See https://golang.org/s/go14nopkg\n",
			pathf("%s/src/pkg", goroot))
	}

	if rebuildall {
		clean()
	}

	setup()

	timelog("build", "toolchain1")
	checkCC()
	bootstrapBuildTools()

	// Remember old content of $GOROOT/bin for comparison below.
	oldBinFiles, err := filepath.Glob(pathf("%s/bin/*", goroot))
	if err != nil {
		fatalf("glob: %v", err)
	}

	// For the main bootstrap, building for host os/arch.
	oldgoos = goos
	oldgoarch = goarch
	goos = gohostos
	goarch = gohostarch
	os.Setenv("GOHOSTARCH", gohostarch)
	os.Setenv("GOHOSTOS", gohostos)
	os.Setenv("GOARCH", goarch)
	os.Setenv("GOOS", goos)

	timelog("build", "go_bootstrap")
	xprintf("Building Go bootstrap cmd/go (go_bootstrap) using Go toolchain1.\n")
	install("runtime")     // dependency not visible in sources; also sets up textflag.h
	install("time/tzdata") // no dependency in sources; creates generated file
	install("cmd/go")
	if vflag > 0 {
		xprintf("\n")
	}

	gogcflags = os.Getenv("GO_GCFLAGS") // we were using $BOOT_GO_GCFLAGS until now
	setNoOpt()
	goldflags = os.Getenv("GO_LDFLAGS") // we were using $BOOT_GO_LDFLAGS until now
	goBootstrap := pathf("%s/go_bootstrap", tooldir)
	if debug {
		run("", ShowOutput|CheckExit, pathf("%s/compile", tooldir), "-V=full")
		copyfile(pathf("%s/compile1", tooldir), pathf("%s/compile", tooldir), writeExec)
	}

	// To recap, so far we have built the new toolchain
	// (cmd/asm, cmd/cgo, cmd/compile, cmd/link)
	// using the Go bootstrap toolchain and go command.
	// Then we built the new go command (as go_bootstrap)
	// using the new toolchain and our own build logic (above).
	//
	//	toolchain1 = mk(new toolchain, go1.17 toolchain, go1.17 cmd/go)
	//	go_bootstrap = mk(new cmd/go, toolchain1, cmd/dist)
	//
	// The toolchain1 we built earlier is built from the new sources,
	// but because it was built using cmd/go it has no build IDs.
	// The eventually installed toolchain needs build IDs, so we need
	// to do another round:
	//
	//	toolchain2 = mk(new toolchain, toolchain1, go_bootstrap)
	//
	timelog("build", "toolchain2")
	if vflag > 0 {
		xprintf("\n")
	}
	xprintf("Building Go toolchain2 using go_bootstrap and Go toolchain1.\n")
	os.Setenv("CC", compilerEnvLookup("CC", defaultcc, goos, goarch))
	// Now that cmd/go is in charge of the build process, enable GOEXPERIMENT.
	os.Setenv("GOEXPERIMENT", goexperiment)
	// No need to enable PGO for toolchain2.
	goInstall(toolenv(), goBootstrap, append([]string{"-pgo=off"}, toolchain...)...)
	if debug {
		run("", ShowOutput|CheckExit, pathf("%s/compile", tooldir), "-V=full")
		copyfile(pathf("%s/compile2", tooldir), pathf("%s/compile", tooldir), writeExec)
	}

	// Toolchain2 should be semantically equivalent to toolchain1,
	// but it was built using the newly built compiler instead of the Go bootstrap compiler,
	// so it should at the least run faster. Also, toolchain1 had no build IDs
	// in the binaries, while toolchain2 does. In non-release builds, the
	// toolchain's build IDs feed into constructing the build IDs of built targets,
	// so in non-release builds, everything now looks out-of-date due to
	// toolchain2 having build IDs - that is, due to the go command seeing
	// that there are new compilers. In release builds, the toolchain's reported
	// version is used in place of the build ID, and the go command does not
	// see that change from toolchain1 to toolchain2, so in release builds,
	// nothing looks out of date.
	// To keep the behavior the same in both non-release and release builds,
	// we force-install everything here.
	//
	//	toolchain3 = mk(new toolchain, toolchain2, go_bootstrap)
	//
	timelog("build", "toolchain3")
	if vflag > 0 {
		xprintf("\n")
	}
	xprintf("Building Go toolchain3 using go_bootstrap and Go toolchain2.\n")
	goInstall(toolenv(), goBootstrap, append([]string{"-a"}, toolchain...)...)
	if debug {
		run("", ShowOutput|CheckExit, pathf("%s/compile", tooldir), "-V=full")
		copyfile(pathf("%s/compile3", tooldir), pathf("%s/compile", tooldir), writeExec)
	}

	// Now that toolchain3 has been built from scratch, its compiler and linker
	// should have accurate build IDs suitable for caching.
	// Now prime the build cache with the rest of the standard library for
	// testing, and so that the user can run 'go install std cmd' to quickly
	// iterate on local changes without waiting for a full rebuild.
	if _, err := os.Stat(pathf("%s/VERSION", goroot)); err == nil {
		// If we have a VERSION file, then we use the Go version
		// instead of build IDs as a cache key, and there is no guarantee
		// that code hasn't changed since the last time we ran a build
		// with this exact VERSION file (especially if someone is working
		// on a release branch). We must not fall back to the shared build cache
		// in this case. Leave $GOCACHE alone.
	} else {
		os.Setenv("GOCACHE", oldgocache)
	}

	if goos == oldgoos && goarch == oldgoarch {
		// Common case - not setting up for cross-compilation.
		timelog("build", "toolchain")
		if vflag > 0 {
			xprintf("\n")
		}
		xprintf("Building packages and commands for %s/%s.\n", goos, goarch)
	} else {
		// GOOS/GOARCH does not match GOHOSTOS/GOHOSTARCH.
		// Finish GOHOSTOS/GOHOSTARCH installation and then
		// run GOOS/GOARCH installation.
		timelog("build", "host toolchain")
		if vflag > 0 {
			xprintf("\n")
		}
		xprintf("Building commands for host, %s/%s.\n", goos, goarch)
		goInstall(toolenv(), goBootstrap, "cmd")
		checkNotStale(toolenv(), goBootstrap, "cmd")
		checkNotStale(toolenv(), gorootBinGo, "cmd")

		timelog("build", "target toolchain")
		if vflag > 0 {
			xprintf("\n")
		}
		goos = oldgoos
		goarch = oldgoarch
		os.Setenv("GOOS", goos)
		os.Setenv("GOARCH", goarch)
		os.Setenv("CC", compilerEnvLookup("CC", defaultcc, goos, goarch))
		xprintf("Building packages and commands for target, %s/%s.\n", goos, goarch)
	}
	goInstall(nil, goBootstrap, "std")
	goInstall(toolenv(), goBootstrap, "cmd")
	checkNotStale(toolenv(), goBootstrap, toolchain...)
	checkNotStale(nil, goBootstrap, "std")
	checkNotStale(toolenv(), goBootstrap, "cmd")
	checkNotStale(nil, gorootBinGo, "std")
	checkNotStale(toolenv(), gorootBinGo, "cmd")
	if debug {
		run("", ShowOutput|CheckExit, pathf("%s/compile", tooldir), "-V=full")
		checkNotStale(toolenv(), goBootstrap, toolchain...)
		copyfile(pathf("%s/compile4", tooldir), pathf("%s/compile", tooldir), writeExec)
	}

	// Check that there are no new files in $GOROOT/bin other than
	// go and gofmt and $GOOS_$GOARCH (target bin when cross-compiling).
	binFiles, err := filepath.Glob(pathf("%s/bin/*", goroot))
	if err != nil {
		fatalf("glob: %v", err)
	}

	ok := map[string]bool{}
	for _, f := range oldBinFiles {
		ok[f] = true
	}
	for _, f := range binFiles {
		if gohostos == "darwin" && filepath.Base(f) == ".DS_Store" {
			continue // unfortunate but not unexpected
		}
		elem := strings.TrimSuffix(filepath.Base(f), ".exe")
		if !ok[f] && elem != "go" && elem != "gofmt" && elem != goos+"_"+goarch {
			fatalf("unexpected new file in $GOROOT/bin: %s", elem)
		}
	}

	// Remove go_bootstrap now that we're done.
	xremove(pathf("%s/go_bootstrap"+exe, tooldir))

	if goos == "android" {
		// Make sure the exec wrapper will sync a fresh $GOROOT to the device.
		xremove(pathf("%s/go_android_exec-adb-sync-status", os.TempDir()))
	}

	if wrapperPath := wrapperPathFor(goos, goarch); wrapperPath != "" {
		oldcc := os.Getenv("CC")
		os.Setenv("GOOS", gohostos)
		os.Setenv("GOARCH", gohostarch)
		os.Setenv("CC", compilerEnvLookup("CC", defaultcc, gohostos, gohostarch))
		goCmd(nil, gorootBinGo, "build", "-o", pathf("%s/go_%s_%s_exec%s", gorootBin, goos, goarch, exe), wrapperPath)
		// Restore environment.
		// TODO(elias.naur): support environment variables in goCmd?
		os.Setenv("GOOS", goos)
		os.Setenv("GOARCH", goarch)
		os.Setenv("CC", oldcc)
	}

	if distpack {
		xprintf("Packaging archives for %s/%s.\n", goos, goarch)
		run("", ShowOutput|CheckExit, pathf("%s/distpack", tooldir))
	}

	// Print trailing banner unless instructed otherwise.
	if !noBanner {
		banner()
	}
}

func wrapperPathFor(goos, goarch string) string {
	switch {
	case goos == "android":
		if gohostos != "android" {
			return pathf("%s/misc/go_android_exec/main.go", goroot)
		}
	case goos == "ios":
		if gohostos != "ios" {
			return pathf("%s/misc/ios/go_ios_exec.go", goroot)
		}
	}
	return ""
}

func goInstall(env []string, goBinary string, args ...string) {
	goCmd(env, goBinary, "install", args...)
}

func appendCompilerFlags(args []string) []string {
	if gogcflags != "" {
		args = append(args, "-gcflags=all="+gogcflags)
	}
	if goldflags != "" {
		args = append(args, "-ldflags=all="+goldflags)
	}
	return args
}

func goCmd(env []string, goBinary string, cmd string, args ...string) {
	goCmd := []string{goBinary, cmd}
	if noOpt {
		goCmd = append(goCmd, "-tags=noopt")
	}
	goCmd = appendCompilerFlags(goCmd)
	if vflag > 0 {
		goCmd = append(goCmd, "-v")
	}

	// Force only one process at a time on vx32 emulation.
	if gohostos == "plan9" && os.Getenv("sysname") == "vx32" {
		goCmd = append(goCmd, "-p=1")
	}

	runEnv(workdir, ShowOutput|CheckExit, env, append(goCmd, args...)...)
}

func checkNotStale(env []string, goBinary string, targets ...string) {
	goCmd := []string{goBinary, "list"}
	if noOpt {
		goCmd = append(goCmd, "-tags=noopt")
	}
	goCmd = appendCompilerFlags(goCmd)
	goCmd = append(goCmd, "-f={{if .Stale}}\tSTALE {{.ImportPath}}: {{.StaleReason}}{{end}}")

	out := runEnv(workdir, CheckExit, env, append(goCmd, targets...)...)
	if strings.Contains(out, "\tSTALE ") {
		os.Setenv("GODEBUG", "gocachehash=1")
		for _, target := range []string{"internal/runtime/sys", "cmd/dist", "cmd/link"} {
			if strings.Contains(out, "STALE "+target) {
				run(workdir, ShowOutput|CheckExit, goBinary, "list", "-f={{.ImportPath}} {{.Stale}}", target)
				break
			}
		}
		fatalf("unexpected stale targets reported by %s list -gcflags=\"%s\" -ldflags=\"%s\" for %v (consider rerunning with GOMAXPROCS=1 GODEBUG=gocachehash=1):\n%s", goBinary, gogcflags, goldflags, targets, out)
	}
}

// Cannot use go/build directly because cmd/dist for a new release
// builds against an old release's go/build, which may be out of sync.
// To reduce duplication, we generate the list for go/build from this.
//
// We list all supported platforms in this list, so that this is the
// single point of truth for supported platforms. This list is used
// by 'go tool dist list'.
var cgoEnabled = map[string]bool{
	"aix/ppc64":       true,
	"darwin/amd64":    true,
	"darwin/arm64":    true,
	"dragonfly/amd64": true,
	"freebsd/386":     true,
	"freebsd/amd64":   true,
	"freebsd/arm":     true,
	"freebsd/arm64":   true,
	"freebsd/riscv64": true,
	"illumos/amd64":   true,
	"linux/386":       true,
	"linux/amd64":     true,
	"linux/arm":       true,
	"linux/arm64":     true,
	"linux/loong64":   true,
	"linux/ppc64":     false,
	"linux/ppc64le":   true,
	"linux/mips":      true,
	"linux/mipsle":    true,
	"linux/mips64":    true,
	"linux/mips64le":  true,
	"linux/riscv64":   true,
	"linux/s390x":     true,
	"linux/sparc64":   true,
	"android/386":     true,
	"android/amd64":   true,
	"android/arm":     true,
	"android/arm64":   true,
	"ios/arm64":       true,
	"ios/amd64":       true,
	"js/wasm":         false,
	"wasip1/wasm":     false,
	"netbsd/386":      true,
	"netbsd/amd64":    true,
	"netbsd/arm":      true,
	"netbsd/arm64":    true,
	"openbsd/386":     true,
	"openbsd/amd64":   true,
	"openbsd/arm":     true,
	"openbsd/arm64":   true,
	"openbsd/mips64":  true,
	"openbsd/ppc64":   false,
	"openbsd/riscv64": true,
	"plan9/386":       false,
	"plan9/amd64":     false,
	"plan9/arm":       false,
	"solaris/amd64":   true,
	"windows/386":     true,
	"windows/amd64":   true,
	"windows/arm":     false,
	"windows/arm64":   true,
}

// List of platforms that are marked as broken ports.
// These require -force flag to build, and also
// get filtered out of cgoEnabled for 'dist list'.
// See go.dev/issue/56679.
var broken = map[string]bool{
	"linux/sparc64":  true, // An incomplete port. See CL 132155.
	"openbsd/mips64": true, // Broken: go.dev/issue/58110.
	"windows/arm":    true, // Broken: go.dev/issue/68552.
}

// List of platforms which are first class ports. See go.dev/issue/38874.
var firstClass = map[string]bool{
	"darwin/amd64":  true,
	"darwin/arm64":  true,
	"linux/386":     true,
	"linux/amd64":   true,
	"linux/arm":     true,
	"linux/arm64":   true,
	"windows/386":   true,
	"windows/amd64": true,
}

// We only need CC if cgo is forced on, or if the platform requires external linking.
// Otherwise the go command will automatically disable it.
func needCC() bool {
	return os.Getenv("CGO_ENABLED") == "1" || mustLinkExternal(gohostos, gohostarch, false)
}

func checkCC() {
	if !needCC() {
		return
	}
	cc1 := defaultcc[""]
	if cc1 == "" {
		cc1 = "gcc"
		for _, os := range clangos {
			if gohostos == os {
				cc1 = "clang"
				break
			}
		}
	}
	cc, err := quotedSplit(cc1)
	if err != nil {
		fatalf("split CC: %v", err)
	}
	var ccHelp = append(cc, "--help")

	if output, err := exec.Command(ccHelp[0], ccHelp[1:]...).CombinedOutput(); err != nil {
		outputHdr := ""
		if len(output) > 0 {
			outputHdr = "\nCommand output:\n\n"
		}
		fatalf("cannot invoke C compiler %q: %v\n\n"+
			"Go needs a system C compiler for use with cgo.\n"+
			"To set a C compiler, set CC=the-compiler.\n"+
			"To disable cgo, set CGO_ENABLED=0.\n%s%s", cc, err, outputHdr, output)
	}
}

func defaulttarg() string {
	// xgetwd might return a path with symlinks fully resolved, and if
	// there happens to be symlinks in goroot, then the hasprefix test
	// will never succeed. Instead, we use xrealwd to get a canonical
	// goroot/src before the comparison to avoid this problem.
	pwd := xgetwd()
	src := pathf("%s/src/", goroot)
	real_src := xrealwd(src)
	if !strings.HasPrefix(pwd, real_src) {
		fatalf("current directory %s is not under %s", pwd, real_src)
	}
	pwd = pwd[len(real_src):]
	// guard against xrealwd returning the directory without the trailing /
	pwd = strings.TrimPrefix(pwd, "/")

	return pwd
}

// Install installs the list of packages named on the command line.
func cmdinstall() {
	xflagparse(-1)

	if flag.NArg() == 0 {
		install(defaulttarg())
	}

	for _, arg := range flag.Args() {
		install(arg)
	}
}

// Clean deletes temporary objects.
func cmdclean() {
	xflagparse(0)
	clean()
}

// Banner prints the 'now you've installed Go' banner.
func cmdbanner() {
	xflagparse(0)
	banner()
}

func banner() {
	if vflag > 0 {
		xprintf("\n")
	}
	xprintf("---\n")
	xprintf("Installed Go for %s/%s in %s\n", goos, goarch, goroot)
	xprintf("Installed commands in %s\n", gorootBin)

	if gohostos == "plan9" {
		// Check that GOROOT/bin is bound before /bin.
		pid := strings.Replace(readfile("#c/pid"), " ", "", -1)
		ns := fmt.Sprintf("/proc/%s/ns", pid)
		if !strings.Contains(readfile(ns), fmt.Sprintf("bind -b %s /bin", gorootBin)) {
			xprintf("*** You need to bind %s before /bin.\n", gorootBin)
		}
	} else {
		// Check that GOROOT/bin appears in $PATH.
		pathsep := ":"
		if gohostos == "windows" {
			pathsep = ";"
		}
		path := os.Getenv("PATH")
		if p, ok := os.LookupEnv("DIST_UNMODIFIED_PATH"); ok {
			// Scripts that modify $PATH and then run dist should also provide
			// dist with an unmodified copy of $PATH via $DIST_UNMODIFIED_PATH.
			// Use it here when determining if the user still needs to update
			// their $PATH. See go.dev/issue/42563.
			path = p
		}
		if !strings.Contains(pathsep+path+pathsep, pathsep+gorootBin+pathsep) {
			xprintf("*** You need to add %s to your PATH.\n", gorootBin)
		}
	}
}

// Version prints the Go version.
func cmdversion() {
	xflagparse(0)
	xprintf("%s\n", findgoversion())
}

// cmdlist lists all supported platforms.
func cmdlist() {
	jsonFlag := flag.Bool("json", false, "produce JSON output")
	brokenFlag := flag.Bool("broken", false, "include broken ports")
	xflagparse(0)

	var plats []string
	for p := range cgoEnabled {
		if broken[p] && !*brokenFlag {
			continue
		}
		plats = append(plats, p)
	}
	sort.Strings(plats)

	if !*jsonFlag {
		for _, p := range plats {
			xprintf("%s\n", p)
		}
		return
	}

	type jsonResult struct {
		GOOS         string
		GOARCH       string
		CgoSupported bool
		FirstClass   bool
		Broken       bool `json:",omitempty"`
	}
	var results []jsonResult
	for _, p := range plats {
		fields := strings.Split(p, "/")
		results = append(results, jsonResult{
			GOOS:         fields[0],
			GOARCH:       fields[1],
			CgoSupported: cgoEnabled[p],
			FirstClass:   firstClass[p],
			Broken:       broken[p],
		})
	}
	out, err := json.MarshalIndent(results, "", "\t")
	if err != nil {
		fatalf("json marshal error: %v", err)
	}
	if _, err := os.Stdout.Write(out); err != nil {
		fatalf("write failed: %v", err)
	}
}

func setNoOpt() {
	for _, gcflag := range strings.Split(gogcflags, " ") {
		if gcflag == "-N" || gcflag == "-l" {
			noOpt = true
			break
		}
	}
}
```