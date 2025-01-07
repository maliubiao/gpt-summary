Response:
The user wants a summary of the functionality of the provided Go code snippet, which is the second part of a larger file. I need to analyze the functions and data structures to understand what the code does.

Key functions in this snippet include:
- `runPending`: Executes pending test commands in parallel.
- `hasBash`, `hasParallelism`, `raceDetectorSupported`, `isAlpineLinux`: Check system capabilities.
- `registerRaceTests`: Registers tests related to the race detector.
- `packageHasBenchmarks`: Checks if a package contains benchmarks.
- `makeGOROOTUnwritable`: Makes the Go root directory read-only for testing purposes.
- `raceDetectorSupported` (standalone function): Determines if the race detector is supported for a given OS and architecture.
- `buildModeSupported` (standalone function): Determines if a given build mode is supported for a given compiler, OS, and architecture.
- `isUnsupportedVMASize`: Checks if a test failure is due to an unsupported VMA size.
- `isEnvSet`: Checks if an environment variable is set.
- `fipsSupported`, `fipsVersions`: Functions related to FIPS support.

Based on these functions, the code seems to be responsible for:
1. **Executing tests in parallel and managing their output.**
2. **Checking for system capabilities relevant to testing (like bash, parallelism, race detector).**
3. **Registering and running tests specifically for the race detector.**
4. **Optimizing benchmark tests by checking if a package has benchmarks before running them with the race detector.**
5. **Implementing a safety mechanism to prevent tests from writing to the Go root directory.**
6. **Determining platform-specific support for the race detector and various build modes.**
7. **Identifying specific test failure reasons (like unsupported VMA size).**
8. **Checking for the presence of environment variables.**
9. **Handling FIPS compliance testing.**
这段代码片段主要负责**执行和管理测试用例，特别是与并发竞争检测（race detector）和FIPS相关的测试**。它也包含了一些辅助功能，用于检查系统能力和配置。

总的来说，这段代码是 `go/src/cmd/dist/test.go` 文件中负责运行特定类型测试的核心逻辑。

以下是功能的归纳：

1. **并行执行测试用例 (runPending)**：
   -  维护一个待执行的测试用例队列 (`t.worklist`)。
   -  以并行方式运行这些测试用例，并控制并发数量 (`maxbg`)。
   -  捕获每个测试用例的输出 (stdout 和 stderr)。
   -  处理测试用例的执行结果（成功或失败）。
   -  在执行前后打印测试用例的头部信息，方便用户查看。
   -  如果测试失败并且没有设置 `keepGoing` 标志，则会立即终止测试。

2. **系统能力检查 (hasBash, hasParallelism, raceDetectorSupported, isAlpineLinux)**：
   -  提供一些辅助函数来判断当前操作系统是否支持某些功能，例如 `bash` 命令，并行执行能力，以及竞争检测器。`isAlpineLinux` 用于判断是否是 Alpine Linux 系统。

3. **注册并发竞争检测相关的测试用例 (registerRaceTests)**：
   -  专门注册用于检测并发问题的测试用例。
   -  可以设置 `-race` 标志来启用竞争检测。
   -  可以针对特定的包或测试函数运行竞争检测。
   -  支持在外部链接模式下运行竞争检测测试。

4. **判断包是否包含性能测试 (packageHasBenchmarks)**：
   -  提供一个优化手段，在运行竞争检测时，可以先检查包中是否存在性能测试函数（以 `Benchmark` 开头），如果不存在则跳过，从而节省时间。这主要是为了避免在竞争检测模式下编译和运行没有性能测试的包。

5. **使 GOROOT 目录不可写 (makeGOROOTUnwritable)**：
   -  提供一个安全机制，在运行某些测试前，将 `$GOROOT` 目录及其子目录和文件设置为只读，以防止测试代码意外修改 Go 语言的安装目录。执行后会返回一个 `undo` 函数，用于恢复原来的权限。

6. **判断平台是否支持竞争检测 (raceDetectorSupported - 独立函数)**：
   -  提供一个独立的函数，用于判断给定的操作系统和架构是否支持竞争检测器。

7. **判断平台是否支持特定的构建模式 (buildModeSupported - 独立函数)**：
   -  提供一个独立的函数，用于判断给定的编译器、构建模式、操作系统和架构是否支持特定的构建模式（例如 `c-archive`, `c-shared`, `pie` 等）。

8. **判断测试失败是否由于不支持的 VMA 大小引起 (isUnsupportedVMASize)**：
   -  当运行竞争检测测试时，如果出现 "unsupported VMA range" 的错误信息，该函数会判断是否是由于当前系统的虚拟内存地址空间大小不满足竞争检测器的要求导致的。

9. **判断环境变量是否已设置 (isEnvSet)**：
   -  一个简单的辅助函数，用于检查指定的环境变量是否已经设置。

10. **FIPS 支持相关功能 (fipsSupported, fipsVersions)**：
    -  `fipsSupported` 函数判断当前环境是否支持 FIPS (Federal Information Processing Standard) 相关的测试。会考虑 `GOFIPS140` 环境变量和 `GOEXPERIMENT=boringcrypto` 的设置。
    -  `fipsVersions` 函数列出 `lib/fips140` 目录下可用的 FIPS 版本文件。

**总结来说，这段代码是 `go tool dist test` 命令中处理复杂测试场景（如并发测试和 FIPS 测试）的核心组成部分，它负责管理测试的执行流程、检查系统环境、以及提供安全保障。**

Prompt: 
```
这是路径为go/src/cmd/dist/test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
 &w.out, &w.out)
			t.worklist = append(t.worklist, w)
			return nil
		})
	}
	if test.pkg != "" && len(test.pkgs) == 0 {
		// Common case. Avoid copying.
		register1(test)
		return
	}
	// TODO(dmitshur,austin): It might be better to unify the execution of 'go test pkg'
	// invocations for the same variant to be done with a single 'go test pkg1 pkg2 pkg3'
	// command, just like it's already done in registerStdTest and registerRaceBenchTest.
	// Those methods accumulate matched packages in stdMatches and benchMatches slices,
	// and we can extend that mechanism to work for all other equal variant registrations.
	// Do the simple thing to start with.
	for _, pkg := range test.packages() {
		test1 := *test
		test1.pkg, test1.pkgs = pkg, nil
		register1(&test1)
	}
}

// dirCmd constructs a Cmd intended to be run in the foreground.
// The command will be run in dir, and Stdout and Stderr will go to os.Stdout
// and os.Stderr.
func (t *tester) dirCmd(dir string, cmdline ...interface{}) *exec.Cmd {
	bin, args := flattenCmdline(cmdline)
	cmd := exec.Command(bin, args...)
	if filepath.IsAbs(dir) {
		setDir(cmd, dir)
	} else {
		setDir(cmd, filepath.Join(goroot, dir))
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if vflag > 1 {
		errprintf("%s\n", strings.Join(cmd.Args, " "))
	}
	return cmd
}

// flattenCmdline flattens a mixture of string and []string as single list
// and then interprets it as a command line: first element is binary, then args.
func flattenCmdline(cmdline []interface{}) (bin string, args []string) {
	var list []string
	for _, x := range cmdline {
		switch x := x.(type) {
		case string:
			list = append(list, x)
		case []string:
			list = append(list, x...)
		default:
			panic("invalid dirCmd argument type: " + reflect.TypeOf(x).String())
		}
	}

	bin = list[0]
	if !filepath.IsAbs(bin) {
		panic("command is not absolute: " + bin)
	}
	return bin, list[1:]
}

func (t *tester) iOS() bool {
	return goos == "ios"
}

func (t *tester) out(v string) {
	if t.json {
		return
	}
	if t.banner == "" {
		return
	}
	fmt.Println("\n" + t.banner + v)
}

// extLink reports whether the current goos/goarch supports
// external linking.
func (t *tester) extLink() bool {
	if !cgoEnabled[goos+"/"+goarch] {
		return false
	}
	if goarch == "ppc64" && goos != "aix" {
		return false
	}
	return true
}

func (t *tester) internalLink() bool {
	if gohostos == "dragonfly" {
		// linkmode=internal fails on dragonfly since errno is a TLS relocation.
		return false
	}
	if goos == "android" {
		return false
	}
	if goos == "ios" {
		return false
	}
	if goos == "windows" && goarch == "arm64" {
		return false
	}
	// Internally linking cgo is incomplete on some architectures.
	// https://golang.org/issue/10373
	// https://golang.org/issue/14449
	if goarch == "loong64" || goarch == "mips64" || goarch == "mips64le" || goarch == "mips" || goarch == "mipsle" || goarch == "riscv64" {
		return false
	}
	if goos == "aix" {
		// linkmode=internal isn't supported.
		return false
	}
	if t.msan || t.asan {
		// linkmode=internal isn't supported by msan or asan.
		return false
	}
	return true
}

func (t *tester) internalLinkPIE() bool {
	if t.msan || t.asan {
		// linkmode=internal isn't supported by msan or asan.
		return false
	}
	switch goos + "-" + goarch {
	case "darwin-amd64", "darwin-arm64",
		"linux-amd64", "linux-arm64", "linux-ppc64le",
		"android-arm64",
		"windows-amd64", "windows-386", "windows-arm":
		return true
	}
	return false
}

func (t *tester) externalLinkPIE() bool {
	// General rule is if -buildmode=pie and -linkmode=external both work, then they work together.
	// Handle exceptions and then fall back to the general rule.
	switch goos + "-" + goarch {
	case "linux-s390x":
		return true
	}
	return t.internalLinkPIE() && t.extLink()
}

// supportedBuildMode reports whether the given build mode is supported.
func (t *tester) supportedBuildmode(mode string) bool {
	switch mode {
	case "c-archive", "c-shared", "shared", "plugin", "pie":
	default:
		fatalf("internal error: unknown buildmode %s", mode)
		return false
	}

	return buildModeSupported("gc", mode, goos, goarch)
}

func (t *tester) registerCgoTests(heading string) {
	cgoTest := func(variant string, subdir, linkmode, buildmode string, opts ...registerTestOpt) *goTest {
		gt := &goTest{
			variant:   variant,
			pkg:       "cmd/cgo/internal/" + subdir,
			buildmode: buildmode,
		}
		var ldflags []string
		if linkmode != "auto" {
			// "auto" is the default, so avoid cluttering the command line for "auto"
			ldflags = append(ldflags, "-linkmode="+linkmode)
		}

		if linkmode == "internal" {
			gt.tags = append(gt.tags, "internal")
			if buildmode == "pie" {
				gt.tags = append(gt.tags, "internal_pie")
			}
		}
		if buildmode == "static" {
			// This isn't actually a Go buildmode, just a convenient way to tell
			// cgoTest we want static linking.
			gt.buildmode = ""
			if linkmode == "external" {
				ldflags = append(ldflags, `-extldflags "-static -pthread"`)
			} else if linkmode == "auto" {
				gt.env = append(gt.env, "CGO_LDFLAGS=-static -pthread")
			} else {
				panic("unknown linkmode with static build: " + linkmode)
			}
			gt.tags = append(gt.tags, "static")
		}
		gt.ldflags = strings.Join(ldflags, " ")

		t.registerTest(heading, gt, opts...)
		return gt
	}

	// test, testtls, and testnocgo are run with linkmode="auto", buildmode=""
	// as part of go test cmd. Here we only have to register the non-default
	// build modes of these tests.

	// Stub out various buildmode=pie tests  on alpine until 54354 resolved.
	builderName := os.Getenv("GO_BUILDER_NAME")
	disablePIE := strings.HasSuffix(builderName, "-alpine")

	if t.internalLink() {
		cgoTest("internal", "test", "internal", "")
	}

	os := gohostos
	p := gohostos + "/" + goarch
	switch {
	case os == "darwin", os == "windows":
		if !t.extLink() {
			break
		}
		// test linkmode=external, but __thread not supported, so skip testtls.
		cgoTest("external", "test", "external", "")

		gt := cgoTest("external-s", "test", "external", "")
		gt.ldflags += " -s"

		if t.supportedBuildmode("pie") && !disablePIE {
			cgoTest("auto-pie", "test", "auto", "pie")
			if t.internalLink() && t.internalLinkPIE() {
				cgoTest("internal-pie", "test", "internal", "pie")
			}
		}

	case os == "aix", os == "android", os == "dragonfly", os == "freebsd", os == "linux", os == "netbsd", os == "openbsd":
		gt := cgoTest("external-g0", "test", "external", "")
		gt.env = append(gt.env, "CGO_CFLAGS=-g0 -fdiagnostics-color")

		cgoTest("external", "testtls", "external", "")
		switch {
		case os == "aix":
			// no static linking
		case p == "freebsd/arm":
			// -fPIC compiled tls code will use __tls_get_addr instead
			// of __aeabi_read_tp, however, on FreeBSD/ARM, __tls_get_addr
			// is implemented in rtld-elf, so -fPIC isn't compatible with
			// static linking on FreeBSD/ARM with clang. (cgo depends on
			// -fPIC fundamentally.)
		default:
			// Check for static linking support
			var staticCheck rtSkipFunc
			ccName := compilerEnvLookup("CC", defaultcc, goos, goarch)
			cc, err := exec.LookPath(ccName)
			if err != nil {
				staticCheck.skip = func(*distTest) (string, bool) {
					return fmt.Sprintf("$CC (%q) not found, skip cgo static linking test.", ccName), true
				}
			} else {
				cmd := t.dirCmd("src/cmd/cgo/internal/test", cc, "-xc", "-o", "/dev/null", "-static", "-")
				cmd.Stdin = strings.NewReader("int main() {}")
				cmd.Stdout, cmd.Stderr = nil, nil // Discard output
				if err := cmd.Run(); err != nil {
					// Skip these tests
					staticCheck.skip = func(*distTest) (string, bool) {
						return "No support for static linking found (lacks libc.a?), skip cgo static linking test.", true
					}
				}
			}

			// Doing a static link with boringcrypto gets
			// a C linker warning on Linux.
			// in function `bio_ip_and_port_to_socket_and_addr':
			// warning: Using 'getaddrinfo' in statically linked applications requires at runtime the shared libraries from the glibc version used for linking
			if staticCheck.skip == nil && goos == "linux" && strings.Contains(goexperiment, "boringcrypto") {
				staticCheck.skip = func(*distTest) (string, bool) {
					return "skipping static linking check on Linux when using boringcrypto to avoid C linker warning about getaddrinfo", true
				}
			}

			// Static linking tests
			if goos != "android" && p != "netbsd/arm" && !t.msan && !t.asan {
				// TODO(#56629): Why does this fail on netbsd-arm?
				// TODO(#70080): Why does this fail with msan?
				// asan doesn't support static linking (this is an explicit build error on the C side).
				cgoTest("static", "testtls", "external", "static", staticCheck)
			}
			cgoTest("external", "testnocgo", "external", "", staticCheck)
			if goos != "android" && !t.msan && !t.asan {
				// TODO(#70080): Why does this fail with msan?
				// asan doesn't support static linking (this is an explicit build error on the C side).
				cgoTest("static", "testnocgo", "external", "static", staticCheck)
				cgoTest("static", "test", "external", "static", staticCheck)
				// -static in CGO_LDFLAGS triggers a different code path
				// than -static in -extldflags, so test both.
				// See issue #16651.
				if goarch != "loong64" && !t.msan && !t.asan {
					// TODO(#56623): Why does this fail on loong64?
					cgoTest("auto-static", "test", "auto", "static", staticCheck)
				}
			}

			// PIE linking tests
			if t.supportedBuildmode("pie") && !disablePIE {
				cgoTest("auto-pie", "test", "auto", "pie")
				if t.internalLink() && t.internalLinkPIE() {
					cgoTest("internal-pie", "test", "internal", "pie")
				}
				cgoTest("auto-pie", "testtls", "auto", "pie")
				cgoTest("auto-pie", "testnocgo", "auto", "pie")
			}
		}
	}
}

// runPending runs pending test commands, in parallel, emitting headers as appropriate.
// When finished, it emits header for nextTest, which is going to run after the
// pending commands are done (and runPending returns).
// A test should call runPending if it wants to make sure that it is not
// running in parallel with earlier tests, or if it has some other reason
// for needing the earlier tests to be done.
func (t *tester) runPending(nextTest *distTest) {
	worklist := t.worklist
	t.worklist = nil
	for _, w := range worklist {
		w.start = make(chan bool)
		w.end = make(chan struct{})
		// w.cmd must be set up to write to w.out. We can't check that, but we
		// can check for easy mistakes.
		if w.cmd.Stdout == nil || w.cmd.Stdout == os.Stdout || w.cmd.Stderr == nil || w.cmd.Stderr == os.Stderr {
			panic("work.cmd.Stdout/Stderr must be redirected")
		}
		go func(w *work) {
			if !<-w.start {
				timelog("skip", w.dt.name)
				w.printSkip(t, "skipped due to earlier error")
			} else {
				timelog("start", w.dt.name)
				w.err = w.cmd.Run()
				if w.flush != nil {
					w.flush()
				}
				if w.err != nil {
					if isUnsupportedVMASize(w) {
						timelog("skip", w.dt.name)
						w.out.Reset()
						w.printSkip(t, "skipped due to unsupported VMA")
						w.err = nil
					}
				}
			}
			timelog("end", w.dt.name)
			w.end <- struct{}{}
		}(w)
	}

	maxbg := maxbg
	// for runtime.NumCPU() < 4 ||  runtime.GOMAXPROCS(0) == 1, do not change maxbg.
	// Because there is not enough CPU to parallel the testing of multiple packages.
	if runtime.NumCPU() > 4 && runtime.GOMAXPROCS(0) != 1 {
		for _, w := range worklist {
			// See go.dev/issue/65164
			// because GOMAXPROCS=2 runtime CPU usage is low,
			// so increase maxbg to avoid slowing down execution with low CPU usage.
			// This makes testing a single package slower,
			// but testing multiple packages together faster.
			if strings.Contains(w.dt.heading, "GOMAXPROCS=2 runtime") {
				maxbg = runtime.NumCPU()
				break
			}
		}
	}

	started := 0
	ended := 0
	var last *distTest
	for ended < len(worklist) {
		for started < len(worklist) && started-ended < maxbg {
			w := worklist[started]
			started++
			w.start <- !t.failed || t.keepGoing
		}
		w := worklist[ended]
		dt := w.dt
		if t.lastHeading != dt.heading {
			t.lastHeading = dt.heading
			t.out(dt.heading)
		}
		if dt != last {
			// Assumes all the entries for a single dt are in one worklist.
			last = w.dt
			if vflag > 0 {
				fmt.Printf("# go tool dist test -run=^%s$\n", dt.name)
			}
		}
		if vflag > 1 {
			errprintf("%s\n", strings.Join(w.cmd.Args, " "))
		}
		ended++
		<-w.end
		os.Stdout.Write(w.out.Bytes())
		// We no longer need the output, so drop the buffer.
		w.out = bytes.Buffer{}
		if w.err != nil {
			log.Printf("Failed: %v", w.err)
			t.failed = true
		}
	}
	if t.failed && !t.keepGoing {
		fatalf("FAILED")
	}

	if dt := nextTest; dt != nil {
		if t.lastHeading != dt.heading {
			t.lastHeading = dt.heading
			t.out(dt.heading)
		}
		if vflag > 0 {
			fmt.Printf("# go tool dist test -run=^%s$\n", dt.name)
		}
	}
}

func (t *tester) hasBash() bool {
	switch gohostos {
	case "windows", "plan9":
		return false
	}
	return true
}

// hasParallelism is a copy of the function
// internal/testenv.HasParallelism, which can't be used here
// because cmd/dist can not import internal packages during bootstrap.
func (t *tester) hasParallelism() bool {
	switch goos {
	case "js", "wasip1":
		return false
	}
	return true
}

func (t *tester) raceDetectorSupported() bool {
	if gohostos != goos {
		return false
	}
	if !t.cgoEnabled {
		return false
	}
	if !raceDetectorSupported(goos, goarch) {
		return false
	}
	// The race detector doesn't work on Alpine Linux:
	// golang.org/issue/14481
	if isAlpineLinux() {
		return false
	}
	// NetBSD support is unfinished.
	// golang.org/issue/26403
	if goos == "netbsd" {
		return false
	}
	return true
}

func isAlpineLinux() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	fi, err := os.Lstat("/etc/alpine-release")
	return err == nil && fi.Mode().IsRegular()
}

func (t *tester) registerRaceTests() {
	hdr := "Testing race detector"
	t.registerTest(hdr,
		&goTest{
			variant:  "race",
			race:     true,
			runTests: "Output",
			pkg:      "runtime/race",
		})
	t.registerTest(hdr,
		&goTest{
			variant:  "race",
			race:     true,
			runTests: "TestParse|TestEcho|TestStdinCloseRace|TestClosedPipeRace|TestTypeRace|TestFdRace|TestFdReadRace|TestFileCloseRace",
			pkgs:     []string{"flag", "net", "os", "os/exec", "encoding/gob"},
		})
	// We don't want the following line, because it
	// slows down all.bash (by 10 seconds on my laptop).
	// The race builder should catch any error here, but doesn't.
	// TODO(iant): Figure out how to catch this.
	// t.registerTest(hdr, &goTest{variant: "race", race: true, runTests: "TestParallelTest", pkg: "cmd/go"})
	if t.cgoEnabled {
		// Building cmd/cgo/internal/test takes a long time.
		// There are already cgo-enabled packages being tested with the race detector.
		// We shouldn't need to redo all of cmd/cgo/internal/test too.
		// The race builder will take care of this.
		// t.registerTest(hdr, &goTest{variant: "race", race: true, env: []string{"GOTRACEBACK=2"}, pkg: "cmd/cgo/internal/test"})
	}
	if t.extLink() {
		// Test with external linking; see issue 9133.
		t.registerTest(hdr,
			&goTest{
				variant:  "race-external",
				race:     true,
				ldflags:  "-linkmode=external",
				runTests: "TestParse|TestEcho|TestStdinCloseRace",
				pkgs:     []string{"flag", "os/exec"},
			})
	}
}

// cgoPackages is the standard packages that use cgo.
var cgoPackages = []string{
	"net",
	"os/user",
}

var funcBenchmark = []byte("\nfunc Benchmark")

// packageHasBenchmarks reports whether pkg has benchmarks.
// On any error, it conservatively returns true.
//
// This exists just to eliminate work on the builders, since compiling
// a test in race mode just to discover it has no benchmarks costs a
// second or two per package, and this function returns false for
// about 100 packages.
func (t *tester) packageHasBenchmarks(pkg string) bool {
	pkgDir := filepath.Join(goroot, "src", pkg)
	d, err := os.Open(pkgDir)
	if err != nil {
		return true // conservatively
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return true // conservatively
	}
	for _, name := range names {
		if !strings.HasSuffix(name, "_test.go") {
			continue
		}
		slurp, err := os.ReadFile(filepath.Join(pkgDir, name))
		if err != nil {
			return true // conservatively
		}
		if bytes.Contains(slurp, funcBenchmark) {
			return true
		}
	}
	return false
}

// makeGOROOTUnwritable makes all $GOROOT files & directories non-writable to
// check that no tests accidentally write to $GOROOT.
func (t *tester) makeGOROOTUnwritable() (undo func()) {
	dir := os.Getenv("GOROOT")
	if dir == "" {
		panic("GOROOT not set")
	}

	type pathMode struct {
		path string
		mode os.FileMode
	}
	var dirs []pathMode // in lexical order

	undo = func() {
		for i := range dirs {
			os.Chmod(dirs[i].path, dirs[i].mode) // best effort
		}
	}

	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if suffix := strings.TrimPrefix(path, dir+string(filepath.Separator)); suffix != "" {
			if suffix == ".git" {
				// Leave Git metadata in whatever state it was in. It may contain a lot
				// of files, and it is highly unlikely that a test will try to modify
				// anything within that directory.
				return filepath.SkipDir
			}
		}
		if err != nil {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}

		mode := info.Mode()
		if mode&0222 != 0 && (mode.IsDir() || mode.IsRegular()) {
			dirs = append(dirs, pathMode{path, mode})
		}
		return nil
	})

	// Run over list backward to chmod children before parents.
	for i := len(dirs) - 1; i >= 0; i-- {
		err := os.Chmod(dirs[i].path, dirs[i].mode&^0222)
		if err != nil {
			dirs = dirs[i:] // Only undo what we did so far.
			undo()
			fatalf("failed to make GOROOT read-only: %v", err)
		}
	}

	return undo
}

// raceDetectorSupported is a copy of the function
// internal/platform.RaceDetectorSupported, which can't be used here
// because cmd/dist can not import internal packages during bootstrap.
// The race detector only supports 48-bit VMA on arm64. But we don't have
// a good solution to check VMA size (see https://go.dev/issue/29948).
// raceDetectorSupported will always return true for arm64. But race
// detector tests may abort on non 48-bit VMA configuration, the tests
// will be marked as "skipped" in this case.
func raceDetectorSupported(goos, goarch string) bool {
	switch goos {
	case "linux":
		return goarch == "amd64" || goarch == "ppc64le" || goarch == "arm64" || goarch == "s390x"
	case "darwin":
		return goarch == "amd64" || goarch == "arm64"
	case "freebsd", "netbsd", "windows":
		return goarch == "amd64"
	default:
		return false
	}
}

// buildModeSupported is a copy of the function
// internal/platform.BuildModeSupported, which can't be used here
// because cmd/dist can not import internal packages during bootstrap.
func buildModeSupported(compiler, buildmode, goos, goarch string) bool {
	if compiler == "gccgo" {
		return true
	}

	platform := goos + "/" + goarch

	switch buildmode {
	case "archive":
		return true

	case "c-archive":
		switch goos {
		case "aix", "darwin", "ios", "windows":
			return true
		case "linux":
			switch goarch {
			case "386", "amd64", "arm", "armbe", "arm64", "arm64be", "loong64", "ppc64le", "riscv64", "s390x":
				// linux/ppc64 not supported because it does
				// not support external linking mode yet.
				return true
			default:
				// Other targets do not support -shared,
				// per ParseFlags in
				// cmd/compile/internal/base/flag.go.
				// For c-archive the Go tool passes -shared,
				// so that the result is suitable for inclusion
				// in a PIE or shared library.
				return false
			}
		case "freebsd":
			return goarch == "amd64"
		}
		return false

	case "c-shared":
		switch platform {
		case "linux/amd64", "linux/arm", "linux/arm64", "linux/loong64", "linux/386", "linux/ppc64le", "linux/riscv64", "linux/s390x",
			"android/amd64", "android/arm", "android/arm64", "android/386",
			"freebsd/amd64",
			"darwin/amd64", "darwin/arm64",
			"windows/amd64", "windows/386", "windows/arm64",
			"wasip1/wasm":
			return true
		}
		return false

	case "default":
		return true

	case "exe":
		return true

	case "pie":
		switch platform {
		case "linux/386", "linux/amd64", "linux/arm", "linux/arm64", "linux/loong64", "linux/ppc64le", "linux/riscv64", "linux/s390x",
			"android/amd64", "android/arm", "android/arm64", "android/386",
			"freebsd/amd64",
			"darwin/amd64", "darwin/arm64",
			"ios/amd64", "ios/arm64",
			"aix/ppc64",
			"openbsd/arm64",
			"windows/386", "windows/amd64", "windows/arm", "windows/arm64":
			return true
		}
		return false

	case "shared":
		switch platform {
		case "linux/386", "linux/amd64", "linux/arm", "linux/arm64", "linux/ppc64le", "linux/s390x":
			return true
		}
		return false

	case "plugin":
		switch platform {
		case "linux/amd64", "linux/arm", "linux/arm64", "linux/386", "linux/loong64", "linux/s390x", "linux/ppc64le",
			"android/amd64", "android/386",
			"darwin/amd64", "darwin/arm64",
			"freebsd/amd64":
			return true
		}
		return false

	default:
		return false
	}
}

// isUnsupportedVMASize reports whether the failure is caused by an unsupported
// VMA for the race detector (for example, running the race detector on an
// arm64 machine configured with 39-bit VMA).
func isUnsupportedVMASize(w *work) bool {
	unsupportedVMA := []byte("unsupported VMA range")
	return strings.Contains(w.dt.name, ":race") && bytes.Contains(w.out.Bytes(), unsupportedVMA)
}

// isEnvSet reports whether the environment variable evar is
// set in the environment.
func isEnvSet(evar string) bool {
	evarEq := evar + "="
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, evarEq) {
			return true
		}
	}
	return false
}

func (t *tester) fipsSupported() bool {
	// Use GOFIPS140 or GOEXPERIMENT=boringcrypto, but not both.
	if strings.Contains(goexperiment, "boringcrypto") {
		return false
	}

	// If this goos/goarch does not support FIPS at all, return no versions.
	// The logic here matches crypto/internal/fips140/check.Supported for now.
	// In the future, if some snapshots add support for these, we will have
	// to make a decision on a per-version basis.
	switch {
	case goarch == "wasm",
		goos == "windows" && goarch == "386",
		goos == "windows" && goarch == "arm",
		goos == "aix":
		return false
	}

	// For now, FIPS+ASAN doesn't need to work.
	// If this is made to work, also re-enable the test in check_test.go.
	if t.asan {
		return false
	}

	return true
}

// fipsVersions returns the list of versions available in lib/fips140.
func fipsVersions(short bool) []string {
	var versions []string
	zips, err := filepath.Glob(filepath.Join(goroot, "lib/fips140/*.zip"))
	if err != nil {
		fatalf("%v", err)
	}
	for _, zip := range zips {
		versions = append(versions, strings.TrimSuffix(filepath.Base(zip), ".zip"))
	}
	txts, err := filepath.Glob(filepath.Join(goroot, "lib/fips140/*.txt"))
	if err != nil {
		fatalf("%v", err)
	}
	for _, txt := range txts {
		versions = append(versions, strings.TrimSuffix(filepath.Base(txt), ".txt"))
	}
	return versions
}

"""




```