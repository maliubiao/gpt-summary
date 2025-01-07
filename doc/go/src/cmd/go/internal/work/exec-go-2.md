Response:
The user wants me to summarize the functionality of the provided Go code snippet, which is part of `go/src/cmd/go/internal/work/exec.go`. This file seems to be responsible for executing external commands during the Go build process, particularly those related to C/C++ compilation and linking.

Based on the function names and their parameters, I can infer the following:

- `ccompile`: Compiles a C source file into an object file using a C compiler (likely gcc or clang).
- `gccld`: Links object files into an executable using the gcc linker.
- `GccCmd`, `GxxCmd`, `gfortranCmd`:  Return the command prefixes for invoking gcc, g++, and gfortran, respectively.
- `ccExe`, `cxxExe`, `fcExe`: Return the configured paths for the C, C++, and Fortran compilers.
- `compilerCmd`:  Constructs the base command line for a compiler, including include paths, architecture-specific flags, and other common settings.
- `gccNoPie`:  Determines the correct flag to use for disabling Position Independent Executables (PIE) during linking.
- `gccSupportsFlag`: Checks if a given compiler supports a specific flag by attempting to compile a minimal program with that flag.
- `gccCompilerID`:  Generates a unique identifier for a specific compiler version, used for build caching.
- `gccArchArgs`: Returns architecture-specific compiler flags.
- `envList`: Parses an environment variable into a list of arguments.
- `CFlags`: Retrieves C preprocessor flags, C compiler flags, C++ compiler flags, Fortran compiler flags, and linker flags based on environment variables and package-specific `#cgo` directives.
- `buildFlags`:  Helper function for parsing and combining compiler/linker flags.
- `cgo`: Handles the execution of the `cgo` tool, which generates Go and C/C++ code for interoperability. It also compiles the generated C/C++ code.
- `flagsNotCompatibleWithInternalLinking`: Checks if the provided compiler flags are compatible with internal linking in Go.
- `dynimport`:  Extracts information about dynamically linked libraries and generates Go code to import them.
- `swig`:  Executes the SWIG (Simplified Wrapper and Interface Generator) tool to generate Go bindings for C/C++ code.

Therefore, the overall functionality seems to be focused on orchestrating the compilation and linking of C/C++/Fortran code that is part of a Go project, especially when using `cgo` or `swig`. It also involves sophisticated handling of compiler flags, build caching, and architecture-specific settings.
这是 `go/src/cmd/go/internal/work/exec.go` 文件的第三部分，主要负责执行与 C/C++ 和 Fortran 代码编译链接相关的外部命令，这些命令是 Go 构建过程的一部分，特别是当使用 `cgo` 或 `swig` 时。

**归纳其功能如下：**

1. **C/C++/Fortran 代码的编译：**
   - 提供了 `ccompile` 函数，用于使用 C 编译器（通常是 gcc 或 clang）编译单个 C 源文件。
   - 提供了 `gcc`、`gxx` 和 `gfortran` 函数，它们分别调用 `ccompile` 函数，但使用不同的编译器命令前缀（gcc、g++、gfortran）。
   - 这些函数会处理各种编译器标志，包括路径修剪 (`-trimpath`) 和随机种子设置 (`-frandom-seed`)，以确保构建的可重复性。

2. **链接可执行文件：**
   - 提供了 `gccld` 函数，使用 gcc 连接器将多个目标文件链接成一个可执行文件。
   - 该函数根据项目中是否存在 C++ 或 SWIG 生成的 C++ 文件来选择使用 `GccCmd` 或 `GxxCmd`。

3. **构建编译器命令：**
   - 提供了 `GccCmd`、`GxxCmd` 和 `gfortranCmd` 函数，用于构建调用 gcc、g++ 和 gfortran 的基本命令前缀，包括默认的 include 目录。
   - 提供了 `ccExe`、`cxxExe` 和 `fcExe` 函数，用于获取配置的 C、C++ 和 Fortran 编译器的可执行文件路径。
   - 提供了 `compilerCmd` 函数，用于构建更完整的编译器命令行，包括架构特定的参数 (`gccArchArgs`) 和线程相关的标志 (`-pthread` 或 `-mthreads`)。

4. **处理编译器特性和标志：**
   - 提供了 `gccSupportsFlag` 函数，用于检查指定的编译器是否支持某个特定的标志。这对于根据不同的编译器版本或功能启用/禁用某些编译选项非常重要。
   - 提供了 `gccNoPie` 函数，用于确定在链接时禁用位置无关可执行文件 (PIE) 的正确标志。
   - 提供了 `gccArchArgs` 函数，根据目标架构返回需要添加到编译器命令中的参数（例如，`-m32`、`-m64`、`-arch` 等）。

5. **管理编译器的标识和缓存：**
   - 提供了 `gccCompilerID` 函数，用于生成当前 gcc 编译器的唯一标识符。此标识符用于构建缓存，以便在编译器版本未更改时重用之前的构建结果。

6. **处理 C 编译器的环境变量和标志：**
   - 提供了 `envList` 函数，用于将环境变量的值分割成一个字符串列表。
   - 提供了 `CFlags` 函数，用于获取 C 预处理器标志 (CPPFLAGS)、C 编译器标志 (CFLAGS)、C++ 编译器标志 (CXXFLAGS)、Fortran 编译器标志 (FFLAGS) 和链接器标志 (LDFLAGS)，这些标志可能来自环境变量和 Go 包中的 `#cgo` 指令。
   - 提供了 `buildFlags` 函数，作为 `CFlags` 的辅助函数，用于组合和检查编译器/链接器标志。

7. **执行 `cgo` 工具：**
   - 提供了 `cgo` 函数，用于执行 `cgo` 工具，该工具用于生成 Go 和 C/C++ 代码以实现 Go 和 C 代码的互操作性。
   - 该函数负责处理 `cgo` 的各种标志和环境变量，并编译生成的 C/C++ 代码。
   - 它还会检测可能与内部链接不兼容的 C 编译器标志，并生成一个 "preferlinkext" 文件来指示链接器使用外部链接。

8. **处理动态链接库导入：**
   - 提供了 `dynimport` 函数，用于生成包含 `//go:cgo_import_dynamic` 指令的 Go 源代码文件，这些指令用于声明由目标文件动态导入的符号或库。

9. **执行 SWIG 工具：**
   - 提供了 `swig` 函数，用于执行 SWIG (Simplified Wrapper and Interface Generator)，以生成用于与 C/C++ 代码进行交互的 Go 绑定。

10. **版本检查：**
    - 提供了 `swigDoVersionCheck` 函数，用于检查 SWIG 的版本是否足够新。

**代码示例和推理：**

假设我们有一个简单的 Go 包，其中包含一个 C 源文件 `hello.c`：

```c
// hello.c
#include <stdio.h>

void say_hello() {
    printf("Hello from C!\n");
}
```

以及一个 Go 文件 `main.go`，它使用 `cgo` 调用 C 函数：

```go
package main

// #cgo CFLAGS: -Wall
// #include "hello.h"
import "C"

import "fmt"

func main() {
	C.say_hello()
	fmt.Println("Hello from Go!")
}
```

我们需要一个头文件 `hello.h`：

```c
// hello.h
void say_hello();
```

当执行 `go build` 命令时，`ccompile` 函数会被调用来编译 `hello.c`。

**假设的输入和输出 (对于 `ccompile` 函数):**

* **输入 `a` (Action):**  代表当前编译操作的 Action 结构体，包含有关包的信息。
* **输入 `outfile`:**  例如，`./_obj/hello.o` (编译后的目标文件路径)。
* **输入 `flags`:**  例如，`["-Wall", "-fdebug-prefix-map=...", ...]` (从 `#cgo CFLAGS` 和其他配置中获取的编译器标志)。
* **输入 `file`:**  例如，`./hello.c` (C 源文件路径)。
* **输入 `compiler`:**  例如，`["gcc"]` (C 编译器命令)。

* **输出:**  如果编译成功，则返回 `nil` 错误。如果编译失败，则返回包含错误信息的 `error`。

**命令行参数处理：**

该部分代码中处理的命令行参数主要是通过环境变量和 `#cgo` 指令来配置传递给 C/C++ 编译器的标志。 例如：

* **`CGO_CFLAGS` 环境变量：**  用于设置传递给 C 编译器的标志。
* **`CGO_LDFLAGS` 环境变量：**  用于设置传递给连接器的标志。
* **`#cgo CFLAGS: -Wall -O2`：**  在 Go 代码中指定传递给 C 编译器的标志。
* **`-trimpath` 构建标志：**  通过 `cfg.BuildTrimpath` 变量访问，用于指示编译器在调试信息中省略源目录路径。

**使用者易犯错的点 (不在本代码片段中直接体现，但与 `cgo` 相关):**

* **忘记包含必要的头文件：**  如果 C 代码使用了未声明的函数或类型，编译器会报错。
* **`#cgo` 指令的语法错误：**  例如，标志之间没有空格，或者使用了错误的关键字。
* **链接器错误：**  例如，缺少必要的库，或者库的路径配置不正确。

总的来说，这部分代码是 Go 构建过程中与 C/C++/Fortran 代码交互的核心，它负责调用外部工具链来完成编译和链接任务，并处理各种平台和编译器特定的细节。

Prompt: 
```
这是路径为go/src/cmd/go/internal/work/exec.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共4部分，请归纳一下它的功能

"""
, compiler []string) error {
	p := a.Package
	sh := b.Shell(a)
	file = mkAbs(p.Dir, file)
	outfile = mkAbs(p.Dir, outfile)

	// Elide source directory paths if -trimpath is set.
	// This is needed for source files (e.g., a .c file in a package directory).
	// TODO(golang.org/issue/36072): cgo also generates files with #line
	// directives pointing to the source directory. It should not generate those
	// when -trimpath is enabled.
	if b.gccSupportsFlag(compiler, "-fdebug-prefix-map=a=b") {
		if cfg.BuildTrimpath || p.Goroot {
			prefixMapFlag := "-fdebug-prefix-map"
			if b.gccSupportsFlag(compiler, "-ffile-prefix-map=a=b") {
				prefixMapFlag = "-ffile-prefix-map"
			}
			// Keep in sync with Action.trimpath.
			// The trimmed paths are a little different, but we need to trim in mostly the
			// same situations.
			var from, toPath string
			if m := p.Module; m == nil {
				if p.Root == "" { // command-line-arguments in GOPATH mode, maybe?
					from = p.Dir
					toPath = p.ImportPath
				} else if p.Goroot {
					from = p.Root
					toPath = "GOROOT"
				} else {
					from = p.Root
					toPath = "GOPATH"
				}
			} else if m.Dir == "" {
				// The module is in the vendor directory. Replace the entire vendor
				// directory path, because the module's Dir is not filled in.
				from = modload.VendorDir()
				toPath = "vendor"
			} else {
				from = m.Dir
				toPath = m.Path
				if m.Version != "" {
					toPath += "@" + m.Version
				}
			}
			// -fdebug-prefix-map (or -ffile-prefix-map) requires an absolute "to"
			// path (or it joins the path  with the working directory). Pick something
			// that makes sense for the target platform.
			var to string
			if cfg.BuildContext.GOOS == "windows" {
				to = filepath.Join(`\\_\_`, toPath)
			} else {
				to = filepath.Join("/_", toPath)
			}
			flags = append(slices.Clip(flags), prefixMapFlag+"="+from+"="+to)
		}
	}

	// Tell gcc to not insert truly random numbers into the build process
	// this ensures LTO won't create random numbers for symbols.
	if b.gccSupportsFlag(compiler, "-frandom-seed=1") {
		flags = append(flags, "-frandom-seed="+buildid.HashToString(a.actionID))
	}

	overlayPath := file
	if p, ok := a.nonGoOverlay[overlayPath]; ok {
		overlayPath = p
	}
	output, err := sh.runOut(filepath.Dir(overlayPath), b.cCompilerEnv(), compiler, flags, "-o", outfile, "-c", filepath.Base(overlayPath))

	// On FreeBSD 11, when we pass -g to clang 3.8 it
	// invokes its internal assembler with -dwarf-version=2.
	// When it sees .section .note.GNU-stack, it warns
	// "DWARF2 only supports one section per compilation unit".
	// This warning makes no sense, since the section is empty,
	// but it confuses people.
	// We work around the problem by detecting the warning
	// and dropping -g and trying again.
	if bytes.Contains(output, []byte("DWARF2 only supports one section per compilation unit")) {
		newFlags := make([]string, 0, len(flags))
		for _, f := range flags {
			if !strings.HasPrefix(f, "-g") {
				newFlags = append(newFlags, f)
			}
		}
		if len(newFlags) < len(flags) {
			return b.ccompile(a, outfile, newFlags, file, compiler)
		}
	}

	if len(output) > 0 && err == nil && os.Getenv("GO_BUILDER_NAME") != "" {
		output = append(output, "C compiler warning promoted to error on Go builders\n"...)
		err = errors.New("warning promoted to error")
	}

	return sh.reportCmd("", "", output, err)
}

// gccld runs the gcc linker to create an executable from a set of object files.
func (b *Builder) gccld(a *Action, objdir, outfile string, flags []string, objs []string) error {
	p := a.Package
	sh := b.Shell(a)
	var cmd []string
	if len(p.CXXFiles) > 0 || len(p.SwigCXXFiles) > 0 {
		cmd = b.GxxCmd(p.Dir, objdir)
	} else {
		cmd = b.GccCmd(p.Dir, objdir)
	}

	cmdargs := []any{cmd, "-o", outfile, objs, flags}
	_, err := sh.runOut(base.Cwd(), b.cCompilerEnv(), cmdargs...)

	// Note that failure is an expected outcome here, so we report output only
	// in debug mode and don't report the error.
	if cfg.BuildN || cfg.BuildX {
		saw := "succeeded"
		if err != nil {
			saw = "failed"
		}
		sh.ShowCmd("", "%s # test for internal linking errors (%s)", joinUnambiguously(str.StringList(cmdargs...)), saw)
	}

	return err
}

// GccCmd returns a gcc command line prefix
// defaultCC is defined in zdefaultcc.go, written by cmd/dist.
func (b *Builder) GccCmd(incdir, workdir string) []string {
	return b.compilerCmd(b.ccExe(), incdir, workdir)
}

// GxxCmd returns a g++ command line prefix
// defaultCXX is defined in zdefaultcc.go, written by cmd/dist.
func (b *Builder) GxxCmd(incdir, workdir string) []string {
	return b.compilerCmd(b.cxxExe(), incdir, workdir)
}

// gfortranCmd returns a gfortran command line prefix.
func (b *Builder) gfortranCmd(incdir, workdir string) []string {
	return b.compilerCmd(b.fcExe(), incdir, workdir)
}

// ccExe returns the CC compiler setting without all the extra flags we add implicitly.
func (b *Builder) ccExe() []string {
	return envList("CC", cfg.DefaultCC(cfg.Goos, cfg.Goarch))
}

// cxxExe returns the CXX compiler setting without all the extra flags we add implicitly.
func (b *Builder) cxxExe() []string {
	return envList("CXX", cfg.DefaultCXX(cfg.Goos, cfg.Goarch))
}

// fcExe returns the FC compiler setting without all the extra flags we add implicitly.
func (b *Builder) fcExe() []string {
	return envList("FC", "gfortran")
}

// compilerCmd returns a command line prefix for the given environment
// variable and using the default command when the variable is empty.
func (b *Builder) compilerCmd(compiler []string, incdir, workdir string) []string {
	a := append(compiler, "-I", incdir)

	// Definitely want -fPIC but on Windows gcc complains
	// "-fPIC ignored for target (all code is position independent)"
	if cfg.Goos != "windows" {
		a = append(a, "-fPIC")
	}
	a = append(a, b.gccArchArgs()...)
	// gcc-4.5 and beyond require explicit "-pthread" flag
	// for multithreading with pthread library.
	if cfg.BuildContext.CgoEnabled {
		switch cfg.Goos {
		case "windows":
			a = append(a, "-mthreads")
		default:
			a = append(a, "-pthread")
		}
	}

	if cfg.Goos == "aix" {
		// mcmodel=large must always be enabled to allow large TOC.
		a = append(a, "-mcmodel=large")
	}

	// disable ASCII art in clang errors, if possible
	if b.gccSupportsFlag(compiler, "-fno-caret-diagnostics") {
		a = append(a, "-fno-caret-diagnostics")
	}
	// clang is too smart about command-line arguments
	if b.gccSupportsFlag(compiler, "-Qunused-arguments") {
		a = append(a, "-Qunused-arguments")
	}

	// zig cc passes --gc-sections to the underlying linker, which then causes
	// undefined symbol errors when compiling with cgo but without C code.
	// https://github.com/golang/go/issues/52690
	if b.gccSupportsFlag(compiler, "-Wl,--no-gc-sections") {
		a = append(a, "-Wl,--no-gc-sections")
	}

	// disable word wrapping in error messages
	a = append(a, "-fmessage-length=0")

	// Tell gcc not to include the work directory in object files.
	if b.gccSupportsFlag(compiler, "-fdebug-prefix-map=a=b") {
		if workdir == "" {
			workdir = b.WorkDir
		}
		workdir = strings.TrimSuffix(workdir, string(filepath.Separator))
		if b.gccSupportsFlag(compiler, "-ffile-prefix-map=a=b") {
			a = append(a, "-ffile-prefix-map="+workdir+"=/tmp/go-build")
		} else {
			a = append(a, "-fdebug-prefix-map="+workdir+"=/tmp/go-build")
		}
	}

	// Tell gcc not to include flags in object files, which defeats the
	// point of -fdebug-prefix-map above.
	if b.gccSupportsFlag(compiler, "-gno-record-gcc-switches") {
		a = append(a, "-gno-record-gcc-switches")
	}

	// On OS X, some of the compilers behave as if -fno-common
	// is always set, and the Mach-O linker in 6l/8l assumes this.
	// See https://golang.org/issue/3253.
	if cfg.Goos == "darwin" || cfg.Goos == "ios" {
		a = append(a, "-fno-common")
	}

	return a
}

// gccNoPie returns the flag to use to request non-PIE. On systems
// with PIE (position independent executables) enabled by default,
// -no-pie must be passed when doing a partial link with -Wl,-r.
// But -no-pie is not supported by all compilers, and clang spells it -nopie.
func (b *Builder) gccNoPie(linker []string) string {
	if b.gccSupportsFlag(linker, "-no-pie") {
		return "-no-pie"
	}
	if b.gccSupportsFlag(linker, "-nopie") {
		return "-nopie"
	}
	return ""
}

// gccSupportsFlag checks to see if the compiler supports a flag.
func (b *Builder) gccSupportsFlag(compiler []string, flag string) bool {
	// We use the background shell for operations here because, while this is
	// triggered by some Action, it's not really about that Action, and often we
	// just get the results from the global cache.
	sh := b.BackgroundShell()

	key := [2]string{compiler[0], flag}

	// We used to write an empty C file, but that gets complicated with go
	// build -n. We tried using a file that does not exist, but that fails on
	// systems with GCC version 4.2.1; that is the last GPLv2 version of GCC,
	// so some systems have frozen on it. Now we pass an empty file on stdin,
	// which should work at least for GCC and clang.
	//
	// If the argument is "-Wl,", then it is testing the linker. In that case,
	// skip "-c". If it's not "-Wl,", then we are testing the compiler and can
	// omit the linking step with "-c".
	//
	// Using the same CFLAGS/LDFLAGS here and for building the program.

	// On the iOS builder the command
	//   $CC -Wl,--no-gc-sections -x c - -o /dev/null < /dev/null
	// is failing with:
	//   Unable to remove existing file: Invalid argument
	tmp := os.DevNull
	if runtime.GOOS == "windows" || runtime.GOOS == "ios" {
		f, err := os.CreateTemp(b.WorkDir, "")
		if err != nil {
			return false
		}
		f.Close()
		tmp = f.Name()
		defer os.Remove(tmp)
	}

	cmdArgs := str.StringList(compiler, flag)
	if strings.HasPrefix(flag, "-Wl,") /* linker flag */ {
		ldflags, err := buildFlags("LDFLAGS", DefaultCFlags, nil, checkLinkerFlags)
		if err != nil {
			return false
		}
		cmdArgs = append(cmdArgs, ldflags...)
	} else { /* compiler flag, add "-c" */
		cflags, err := buildFlags("CFLAGS", DefaultCFlags, nil, checkCompilerFlags)
		if err != nil {
			return false
		}
		cmdArgs = append(cmdArgs, cflags...)
		cmdArgs = append(cmdArgs, "-c")
	}

	cmdArgs = append(cmdArgs, "-x", "c", "-", "-o", tmp)

	if cfg.BuildN {
		sh.ShowCmd(b.WorkDir, "%s || true", joinUnambiguously(cmdArgs))
		return false
	}

	// gccCompilerID acquires b.exec, so do before acquiring lock.
	compilerID, cacheOK := b.gccCompilerID(compiler[0])

	b.exec.Lock()
	defer b.exec.Unlock()
	if b, ok := b.flagCache[key]; ok {
		return b
	}
	if b.flagCache == nil {
		b.flagCache = make(map[[2]string]bool)
	}

	// Look in build cache.
	var flagID cache.ActionID
	if cacheOK {
		flagID = cache.Subkey(compilerID, "gccSupportsFlag "+flag)
		if data, _, err := cache.GetBytes(cache.Default(), flagID); err == nil {
			supported := string(data) == "true"
			b.flagCache[key] = supported
			return supported
		}
	}

	if cfg.BuildX {
		sh.ShowCmd(b.WorkDir, "%s || true", joinUnambiguously(cmdArgs))
	}
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Dir = b.WorkDir
	cmd.Env = append(cmd.Environ(), "LC_ALL=C")
	out, _ := cmd.CombinedOutput()
	// GCC says "unrecognized command line option".
	// clang says "unknown argument".
	// tcc says "unsupported"
	// AIX says "not recognized"
	// Older versions of GCC say "unrecognised debug output level".
	// For -fsplit-stack GCC says "'-fsplit-stack' is not supported".
	supported := !bytes.Contains(out, []byte("unrecognized")) &&
		!bytes.Contains(out, []byte("unknown")) &&
		!bytes.Contains(out, []byte("unrecognised")) &&
		!bytes.Contains(out, []byte("is not supported")) &&
		!bytes.Contains(out, []byte("not recognized")) &&
		!bytes.Contains(out, []byte("unsupported"))

	if cacheOK {
		s := "false"
		if supported {
			s = "true"
		}
		cache.PutBytes(cache.Default(), flagID, []byte(s))
	}

	b.flagCache[key] = supported
	return supported
}

// statString returns a string form of an os.FileInfo, for serializing and comparison.
func statString(info os.FileInfo) string {
	return fmt.Sprintf("stat %d %x %v %v\n", info.Size(), uint64(info.Mode()), info.ModTime(), info.IsDir())
}

// gccCompilerID returns a build cache key for the current gcc,
// as identified by running 'compiler'.
// The caller can use subkeys of the key.
// Other parts of cmd/go can use the id as a hash
// of the installed compiler version.
func (b *Builder) gccCompilerID(compiler string) (id cache.ActionID, ok bool) {
	// We use the background shell for operations here because, while this is
	// triggered by some Action, it's not really about that Action, and often we
	// just get the results from the global cache.
	sh := b.BackgroundShell()

	if cfg.BuildN {
		sh.ShowCmd(b.WorkDir, "%s || true", joinUnambiguously([]string{compiler, "--version"}))
		return cache.ActionID{}, false
	}

	b.exec.Lock()
	defer b.exec.Unlock()

	if id, ok := b.gccCompilerIDCache[compiler]; ok {
		return id, ok
	}

	// We hash the compiler's full path to get a cache entry key.
	// That cache entry holds a validation description,
	// which is of the form:
	//
	//	filename \x00 statinfo \x00
	//	...
	//	compiler id
	//
	// If os.Stat of each filename matches statinfo,
	// then the entry is still valid, and we can use the
	// compiler id without any further expense.
	//
	// Otherwise, we compute a new validation description
	// and compiler id (below).
	exe, err := pathcache.LookPath(compiler)
	if err != nil {
		return cache.ActionID{}, false
	}

	h := cache.NewHash("gccCompilerID")
	fmt.Fprintf(h, "gccCompilerID %q", exe)
	key := h.Sum()
	data, _, err := cache.GetBytes(cache.Default(), key)
	if err == nil && len(data) > len(id) {
		stats := strings.Split(string(data[:len(data)-len(id)]), "\x00")
		if len(stats)%2 != 0 {
			goto Miss
		}
		for i := 0; i+2 <= len(stats); i++ {
			info, err := os.Stat(stats[i])
			if err != nil || statString(info) != stats[i+1] {
				goto Miss
			}
		}
		copy(id[:], data[len(data)-len(id):])
		return id, true
	Miss:
	}

	// Validation failed. Compute a new description (in buf) and compiler ID (in h).
	// For now, there are only at most two filenames in the stat information.
	// The first one is the compiler executable we invoke.
	// The second is the underlying compiler as reported by -v -###
	// (see b.gccToolID implementation in buildid.go).
	toolID, exe2, err := b.gccToolID(compiler, "c")
	if err != nil {
		return cache.ActionID{}, false
	}

	exes := []string{exe, exe2}
	str.Uniq(&exes)
	fmt.Fprintf(h, "gccCompilerID %q %q\n", exes, toolID)
	id = h.Sum()

	var buf bytes.Buffer
	for _, exe := range exes {
		if exe == "" {
			continue
		}
		info, err := os.Stat(exe)
		if err != nil {
			return cache.ActionID{}, false
		}
		buf.WriteString(exe)
		buf.WriteString("\x00")
		buf.WriteString(statString(info))
		buf.WriteString("\x00")
	}
	buf.Write(id[:])

	cache.PutBytes(cache.Default(), key, buf.Bytes())
	if b.gccCompilerIDCache == nil {
		b.gccCompilerIDCache = make(map[string]cache.ActionID)
	}
	b.gccCompilerIDCache[compiler] = id
	return id, true
}

// gccArchArgs returns arguments to pass to gcc based on the architecture.
func (b *Builder) gccArchArgs() []string {
	switch cfg.Goarch {
	case "386":
		return []string{"-m32"}
	case "amd64":
		if cfg.Goos == "darwin" {
			return []string{"-arch", "x86_64", "-m64"}
		}
		return []string{"-m64"}
	case "arm64":
		if cfg.Goos == "darwin" {
			return []string{"-arch", "arm64"}
		}
	case "arm":
		return []string{"-marm"} // not thumb
	case "s390x":
		return []string{"-m64", "-march=z196"}
	case "mips64", "mips64le":
		args := []string{"-mabi=64"}
		if cfg.GOMIPS64 == "hardfloat" {
			return append(args, "-mhard-float")
		} else if cfg.GOMIPS64 == "softfloat" {
			return append(args, "-msoft-float")
		}
	case "mips", "mipsle":
		args := []string{"-mabi=32", "-march=mips32"}
		if cfg.GOMIPS == "hardfloat" {
			return append(args, "-mhard-float", "-mfp32", "-mno-odd-spreg")
		} else if cfg.GOMIPS == "softfloat" {
			return append(args, "-msoft-float")
		}
	case "loong64":
		return []string{"-mabi=lp64d"}
	case "ppc64":
		if cfg.Goos == "aix" {
			return []string{"-maix64"}
		}
	}
	return nil
}

// envList returns the value of the given environment variable broken
// into fields, using the default value when the variable is empty.
//
// The environment variable must be quoted correctly for
// quoted.Split. This should be done before building
// anything, for example, in BuildInit.
func envList(key, def string) []string {
	v := cfg.Getenv(key)
	if v == "" {
		v = def
	}
	args, err := quoted.Split(v)
	if err != nil {
		panic(fmt.Sprintf("could not parse environment variable %s with value %q: %v", key, v, err))
	}
	return args
}

// CFlags returns the flags to use when invoking the C, C++ or Fortran compilers, or cgo.
func (b *Builder) CFlags(p *load.Package) (cppflags, cflags, cxxflags, fflags, ldflags []string, err error) {
	if cppflags, err = buildFlags("CPPFLAGS", "", p.CgoCPPFLAGS, checkCompilerFlags); err != nil {
		return
	}
	if cflags, err = buildFlags("CFLAGS", DefaultCFlags, p.CgoCFLAGS, checkCompilerFlags); err != nil {
		return
	}
	if cxxflags, err = buildFlags("CXXFLAGS", DefaultCFlags, p.CgoCXXFLAGS, checkCompilerFlags); err != nil {
		return
	}
	if fflags, err = buildFlags("FFLAGS", DefaultCFlags, p.CgoFFLAGS, checkCompilerFlags); err != nil {
		return
	}
	if ldflags, err = buildFlags("LDFLAGS", DefaultCFlags, p.CgoLDFLAGS, checkLinkerFlags); err != nil {
		return
	}

	return
}

func buildFlags(name, defaults string, fromPackage []string, check func(string, string, []string) error) ([]string, error) {
	if err := check(name, "#cgo "+name, fromPackage); err != nil {
		return nil, err
	}
	return str.StringList(envList("CGO_"+name, defaults), fromPackage), nil
}

var cgoRe = lazyregexp.New(`[/\\:]`)

func (b *Builder) cgo(a *Action, cgoExe, objdir string, pcCFLAGS, pcLDFLAGS, cgofiles, gccfiles, gxxfiles, mfiles, ffiles []string) (outGo, outObj []string, err error) {
	p := a.Package
	sh := b.Shell(a)

	cgoCPPFLAGS, cgoCFLAGS, cgoCXXFLAGS, cgoFFLAGS, cgoLDFLAGS, err := b.CFlags(p)
	if err != nil {
		return nil, nil, err
	}

	cgoCPPFLAGS = append(cgoCPPFLAGS, pcCFLAGS...)
	cgoLDFLAGS = append(cgoLDFLAGS, pcLDFLAGS...)
	// If we are compiling Objective-C code, then we need to link against libobjc
	if len(mfiles) > 0 {
		cgoLDFLAGS = append(cgoLDFLAGS, "-lobjc")
	}

	// Likewise for Fortran, except there are many Fortran compilers.
	// Support gfortran out of the box and let others pass the correct link options
	// via CGO_LDFLAGS
	if len(ffiles) > 0 {
		fc := cfg.Getenv("FC")
		if fc == "" {
			fc = "gfortran"
		}
		if strings.Contains(fc, "gfortran") {
			cgoLDFLAGS = append(cgoLDFLAGS, "-lgfortran")
		}
	}

	// Scrutinize CFLAGS and related for flags that might cause
	// problems if we are using internal linking (for example, use of
	// plugins, LTO, etc) by calling a helper routine that builds on
	// the existing CGO flags allow-lists. If we see anything
	// suspicious, emit a special token file "preferlinkext" (known to
	// the linker) in the object file to signal the that it should not
	// try to link internally and should revert to external linking.
	// The token we pass is a suggestion, not a mandate; if a user is
	// explicitly asking for a specific linkmode via the "-linkmode"
	// flag, the token will be ignored. NB: in theory we could ditch
	// the token approach and just pass a flag to the linker when we
	// eventually invoke it, and the linker flag could then be
	// documented (although coming up with a simple explanation of the
	// flag might be challenging). For more context see issues #58619,
	// #58620, and #58848.
	flagSources := []string{"CGO_CFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS"}
	flagLists := [][]string{cgoCFLAGS, cgoCXXFLAGS, cgoFFLAGS}
	if flagsNotCompatibleWithInternalLinking(flagSources, flagLists) {
		tokenFile := objdir + "preferlinkext"
		if err := sh.writeFile(tokenFile, nil); err != nil {
			return nil, nil, err
		}
		outObj = append(outObj, tokenFile)
	}

	if cfg.BuildMSan {
		cgoCFLAGS = append([]string{"-fsanitize=memory"}, cgoCFLAGS...)
		cgoLDFLAGS = append([]string{"-fsanitize=memory"}, cgoLDFLAGS...)
	}
	if cfg.BuildASan {
		cgoCFLAGS = append([]string{"-fsanitize=address"}, cgoCFLAGS...)
		cgoLDFLAGS = append([]string{"-fsanitize=address"}, cgoLDFLAGS...)
	}

	// Allows including _cgo_export.h, as well as the user's .h files,
	// from .[ch] files in the package.
	cgoCPPFLAGS = append(cgoCPPFLAGS, "-I", objdir)

	// cgo
	// TODO: CGO_FLAGS?
	gofiles := []string{objdir + "_cgo_gotypes.go"}
	cfiles := []string{"_cgo_export.c"}
	for _, fn := range cgofiles {
		f := strings.TrimSuffix(filepath.Base(fn), ".go")
		gofiles = append(gofiles, objdir+f+".cgo1.go")
		cfiles = append(cfiles, f+".cgo2.c")
	}

	// TODO: make cgo not depend on $GOARCH?

	cgoflags := []string{}
	if p.Standard && p.ImportPath == "runtime/cgo" {
		cgoflags = append(cgoflags, "-import_runtime_cgo=false")
	}
	if p.Standard && (p.ImportPath == "runtime/race" || p.ImportPath == "runtime/msan" || p.ImportPath == "runtime/cgo" || p.ImportPath == "runtime/asan") {
		cgoflags = append(cgoflags, "-import_syscall=false")
	}

	// cgoLDFLAGS, which includes p.CgoLDFLAGS, can be very long.
	// Pass it to cgo on the command line, so that we use a
	// response file if necessary.
	//
	// These flags are recorded in the generated _cgo_gotypes.go file
	// using //go:cgo_ldflag directives, the compiler records them in the
	// object file for the package, and then the Go linker passes them
	// along to the host linker. At this point in the code, cgoLDFLAGS
	// consists of the original $CGO_LDFLAGS (unchecked) and all the
	// flags put together from source code (checked).
	cgoenv := b.cCompilerEnv()
	var ldflagsOption []string
	if len(cgoLDFLAGS) > 0 {
		flags := make([]string, len(cgoLDFLAGS))
		for i, f := range cgoLDFLAGS {
			flags[i] = strconv.Quote(f)
		}
		ldflagsOption = []string{"-ldflags=" + strings.Join(flags, " ")}

		// Remove CGO_LDFLAGS from the environment.
		cgoenv = append(cgoenv, "CGO_LDFLAGS=")
	}

	if cfg.BuildToolchainName == "gccgo" {
		if b.gccSupportsFlag([]string{BuildToolchain.compiler()}, "-fsplit-stack") {
			cgoCFLAGS = append(cgoCFLAGS, "-fsplit-stack")
		}
		cgoflags = append(cgoflags, "-gccgo")
		if pkgpath := gccgoPkgpath(p); pkgpath != "" {
			cgoflags = append(cgoflags, "-gccgopkgpath="+pkgpath)
		}
		if !BuildToolchain.(gccgoToolchain).supportsCgoIncomplete(b, a) {
			cgoflags = append(cgoflags, "-gccgo_define_cgoincomplete")
		}
	}

	switch cfg.BuildBuildmode {
	case "c-archive", "c-shared":
		// Tell cgo that if there are any exported functions
		// it should generate a header file that C code can
		// #include.
		cgoflags = append(cgoflags, "-exportheader="+objdir+"_cgo_install.h")
	}

	// Rewrite overlaid paths in cgo files.
	// cgo adds //line and #line pragmas in generated files with these paths.
	var trimpath []string
	for i := range cgofiles {
		path := mkAbs(p.Dir, cgofiles[i])
		if fsys.Replaced(path) {
			actual := fsys.Actual(path)
			cgofiles[i] = actual
			trimpath = append(trimpath, actual+"=>"+path)
		}
	}
	if len(trimpath) > 0 {
		cgoflags = append(cgoflags, "-trimpath", strings.Join(trimpath, ";"))
	}

	if err := sh.run(p.Dir, p.ImportPath, cgoenv, cfg.BuildToolexec, cgoExe, "-objdir", objdir, "-importpath", p.ImportPath, cgoflags, ldflagsOption, "--", cgoCPPFLAGS, cgoCFLAGS, cgofiles); err != nil {
		return nil, nil, err
	}
	outGo = append(outGo, gofiles...)

	// Use sequential object file names to keep them distinct
	// and short enough to fit in the .a header file name slots.
	// We no longer collect them all into _all.o, and we'd like
	// tools to see both the .o suffix and unique names, so
	// we need to make them short enough not to be truncated
	// in the final archive.
	oseq := 0
	nextOfile := func() string {
		oseq++
		return objdir + fmt.Sprintf("_x%03d.o", oseq)
	}

	// gcc
	cflags := str.StringList(cgoCPPFLAGS, cgoCFLAGS)
	for _, cfile := range cfiles {
		ofile := nextOfile()
		if err := b.gcc(a, a.Objdir, ofile, cflags, objdir+cfile); err != nil {
			return nil, nil, err
		}
		outObj = append(outObj, ofile)
	}

	for _, file := range gccfiles {
		ofile := nextOfile()
		if err := b.gcc(a, a.Objdir, ofile, cflags, file); err != nil {
			return nil, nil, err
		}
		outObj = append(outObj, ofile)
	}

	cxxflags := str.StringList(cgoCPPFLAGS, cgoCXXFLAGS)
	for _, file := range gxxfiles {
		ofile := nextOfile()
		if err := b.gxx(a, a.Objdir, ofile, cxxflags, file); err != nil {
			return nil, nil, err
		}
		outObj = append(outObj, ofile)
	}

	for _, file := range mfiles {
		ofile := nextOfile()
		if err := b.gcc(a, a.Objdir, ofile, cflags, file); err != nil {
			return nil, nil, err
		}
		outObj = append(outObj, ofile)
	}

	fflags := str.StringList(cgoCPPFLAGS, cgoFFLAGS)
	for _, file := range ffiles {
		ofile := nextOfile()
		if err := b.gfortran(a, a.Objdir, ofile, fflags, file); err != nil {
			return nil, nil, err
		}
		outObj = append(outObj, ofile)
	}

	switch cfg.BuildToolchainName {
	case "gc":
		importGo := objdir + "_cgo_import.go"
		dynOutGo, dynOutObj, err := b.dynimport(a, objdir, importGo, cgoExe, cflags, cgoLDFLAGS, outObj)
		if err != nil {
			return nil, nil, err
		}
		if dynOutGo != "" {
			outGo = append(outGo, dynOutGo)
		}
		if dynOutObj != "" {
			outObj = append(outObj, dynOutObj)
		}

	case "gccgo":
		defunC := objdir + "_cgo_defun.c"
		defunObj := objdir + "_cgo_defun.o"
		if err := BuildToolchain.cc(b, a, defunObj, defunC); err != nil {
			return nil, nil, err
		}
		outObj = append(outObj, defunObj)

	default:
		noCompiler()
	}

	// Double check the //go:cgo_ldflag comments in the generated files.
	// The compiler only permits such comments in files whose base name
	// starts with "_cgo_". Make sure that the comments in those files
	// are safe. This is a backstop against people somehow smuggling
	// such a comment into a file generated by cgo.
	if cfg.BuildToolchainName == "gc" && !cfg.BuildN {
		var flags []string
		for _, f := range outGo {
			if !strings.HasPrefix(filepath.Base(f), "_cgo_") {
				continue
			}

			src, err := os.ReadFile(f)
			if err != nil {
				return nil, nil, err
			}

			const cgoLdflag = "//go:cgo_ldflag"
			idx := bytes.Index(src, []byte(cgoLdflag))
			for idx >= 0 {
				// We are looking at //go:cgo_ldflag.
				// Find start of line.
				start := bytes.LastIndex(src[:idx], []byte("\n"))
				if start == -1 {
					start = 0
				}

				// Find end of line.
				end := bytes.Index(src[idx:], []byte("\n"))
				if end == -1 {
					end = len(src)
				} else {
					end += idx
				}

				// Check for first line comment in line.
				// We don't worry about /* */ comments,
				// which normally won't appear in files
				// generated by cgo.
				commentStart := bytes.Index(src[start:], []byte("//"))
				commentStart += start
				// If that line comment is //go:cgo_ldflag,
				// it's a match.
				if bytes.HasPrefix(src[commentStart:], []byte(cgoLdflag)) {
					// Pull out the flag, and unquote it.
					// This is what the compiler does.
					flag := string(src[idx+len(cgoLdflag) : end])
					flag = strings.TrimSpace(flag)
					flag = strings.Trim(flag, `"`)
					flags = append(flags, flag)
				}
				src = src[end:]
				idx = bytes.Index(src, []byte(cgoLdflag))
			}
		}

		// We expect to find the contents of cgoLDFLAGS in flags.
		if len(cgoLDFLAGS) > 0 {
		outer:
			for i := range flags {
				for j, f := range cgoLDFLAGS {
					if f != flags[i+j] {
						continue outer
					}
				}
				flags = append(flags[:i], flags[i+len(cgoLDFLAGS):]...)
				break
			}
		}

		if err := checkLinkerFlags("LDFLAGS", "go:cgo_ldflag", flags); err != nil {
			return nil, nil, err
		}
	}

	return outGo, outObj, nil
}

// flagsNotCompatibleWithInternalLinking scans the list of cgo
// compiler flags (C/C++/Fortran) looking for flags that might cause
// problems if the build in question uses internal linking. The
// primary culprits are use of plugins or use of LTO, but we err on
// the side of caution, supporting only those flags that are on the
// allow-list for safe flags from security perspective. Return is TRUE
// if a sensitive flag is found, FALSE otherwise.
func flagsNotCompatibleWithInternalLinking(sourceList []string, flagListList [][]string) bool {
	for i := range sourceList {
		sn := sourceList[i]
		fll := flagListList[i]
		if err := checkCompilerFlagsForInternalLink(sn, sn, fll); err != nil {
			return true
		}
	}
	return false
}

// dynimport creates a Go source file named importGo containing
// //go:cgo_import_dynamic directives for each symbol or library
// dynamically imported by the object files outObj.
// dynOutGo, if not empty, is a new Go file to build as part of the package.
// dynOutObj, if not empty, is a new file to add to the generated archive.
func (b *Builder) dynimport(a *Action, objdir, importGo, cgoExe string, cflags, cgoLDFLAGS, outObj []string) (dynOutGo, dynOutObj string, err error) {
	p := a.Package
	sh := b.Shell(a)

	cfile := objdir + "_cgo_main.c"
	ofile := objdir + "_cgo_main.o"
	if err := b.gcc(a, objdir, ofile, cflags, cfile); err != nil {
		return "", "", err
	}

	// Gather .syso files from this package and all (transitive) dependencies.
	var syso []string
	seen := make(map[*Action]bool)
	var gatherSyso func(*Action)
	gatherSyso = func(a1 *Action) {
		if seen[a1] {
			return
		}
		seen[a1] = true
		if p1 := a1.Package; p1 != nil {
			syso = append(syso, mkAbsFiles(p1.Dir, p1.SysoFiles)...)
		}
		for _, a2 := range a1.Deps {
			gatherSyso(a2)
		}
	}
	gatherSyso(a)
	sort.Strings(syso)
	str.Uniq(&syso)
	linkobj := str.StringList(ofile, outObj, syso)
	dynobj := objdir + "_cgo_.o"

	ldflags := cgoLDFLAGS
	if (cfg.Goarch == "arm" && cfg.Goos == "linux") || cfg.Goos == "android" {
		if !slices.Contains(ldflags, "-no-pie") {
			// we need to use -pie for Linux/ARM to get accurate imported sym (added in https://golang.org/cl/5989058)
			// this seems to be outdated, but we don't want to break existing builds depending on this (Issue 45940)
			ldflags = append(ldflags, "-pie")
		}
		if slices.Contains(ldflags, "-pie") && slices.Contains(ldflags, "-static") {
			// -static -pie doesn't make sense, and causes link errors.
			// Issue 26197.
			n := make([]string, 0, len(ldflags)-1)
			for _, flag := range ldflags {
				if flag != "-static" {
					n = append(n, flag)
				}
			}
			ldflags = n
		}
	}
	if err := b.gccld(a, objdir, dynobj, ldflags, linkobj); err != nil {
		// We only need this information for internal linking.
		// If this link fails, mark the object as requiring
		// external linking. This link can fail for things like
		// syso files that have unexpected dependencies.
		// cmd/link explicitly looks for the name "dynimportfail".
		// See issue #52863.
		fail := objdir + "dynimportfail"
		if err := sh.writeFile(fail, nil); err != nil {
			return "", "", err
		}
		return "", fail, nil
	}

	// cgo -dynimport
	var cgoflags []string
	if p.Standard && p.ImportPath == "runtime/cgo" {
		cgoflags = []string{"-dynlinker"} // record path to dynamic linker
	}
	err = sh.run(base.Cwd(), p.ImportPath, b.cCompilerEnv(), cfg.BuildToolexec, cgoExe, "-dynpackage", p.Name, "-dynimport", dynobj, "-dynout", importGo, cgoflags)
	if err != nil {
		return "", "", err
	}
	return importGo, "", nil
}

// Run SWIG on all SWIG input files.
// TODO: Don't build a shared library, once SWIG emits the necessary
// pragmas for external linking.
func (b *Builder) swig(a *Action, objdir string, pcCFLAGS []string) (outGo, outC, outCXX []string, err error) {
	p := a.Package

	if err := b.swigVersionCheck(); err != nil {
		return nil, nil, nil, err
	}

	intgosize, err := b.swigIntSize(objdir)
	if err != nil {
		return nil, nil, nil, err
	}

	for _, f := range p.SwigFiles {
		goFile, cFile, err := b.swigOne(a, f, objdir, pcCFLAGS, false, intgosize)
		if err != nil {
			return nil, nil, nil, err
		}
		if goFile != "" {
			outGo = append(outGo, goFile)
		}
		if cFile != "" {
			outC = append(outC, cFile)
		}
	}
	for _, f := range p.SwigCXXFiles {
		goFile, cxxFile, err := b.swigOne(a, f, objdir, pcCFLAGS, true, intgosize)
		if err != nil {
			return nil, nil, nil, err
		}
		if goFile != "" {
			outGo = append(outGo, goFile)
		}
		if cxxFile != "" {
			outCXX = append(outCXX, cxxFile)
		}
	}
	return outGo, outC, outCXX, nil
}

// Make sure SWIG is new enough.
var (
	swigCheckOnce sync.Once
	swigCheck     error
)

func (b *Builder) swigDoVersionCheck() error {
	sh := b.BackgroundShell()
	out, err := sh.runOut(".", nil, "swig", "-version")
	if err != nil {
		return err
	}
	re := regexp.MustCompile(`[vV]ersion +(\d+)([.]\d+)?([.]\d+)?`)
	matches := re.FindSubmatch(out)
	if matches == nil {
		// Can't find version
"""




```