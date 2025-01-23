Response: The user wants to understand the functionality of the provided Go code snippet, which is part of `go/src/cmd/go/internal/work/exec.go`. This file seems to handle the execution of external commands like compilers (gcc, g++), linkers, and other tools involved in the Go build process.

Here's a plan to address the user's request:

1. **Identify the main functionalities:** Scan the code for key functions and their roles. Focus on functions like `ccompile`, `gccld`, `GccCmd`, `GxxCmd`, `cgo`, `swig`, and related helper functions.
2. **Explain each functionality:** Describe what each identified function does in the build process.
3. **Provide Go code examples:** For significant functionalities, create simplified Go examples that illustrate the underlying concept. This will likely involve demonstrating how the `go` command might interact with these internal functions.
4. **Address command-line parameters:** Explain how the code handles and uses command-line arguments for external tools. Look for manipulation of `flags` variables.
5. **Highlight potential user errors:** Analyze the code for areas where users might make mistakes when interacting with the `go` build process, which indirectly relates to these internal functions.
6. **Summarize the overall functionality:** Provide a concise summary of the code's purpose.

**Detailed breakdown of the thought process for each section:**

* **`ccompile`:** This function clearly compiles a C source file using a given compiler. The interesting parts are the handling of `-trimpath` and `-fdebug-prefix-map` for debugging information and the workaround for a FreeBSD/clang issue.
* **`gccld`:** This function links object files using the appropriate linker (gcc or g++). It seems to be a wrapper around the actual linker execution.
* **`GccCmd`, `GxxCmd`, `gfortranCmd`, `ccExe`, `cxxExe`, `fcExe`, `compilerCmd`:** These functions are about constructing the command-line prefixes for different compilers. They manage default flags and environment variables.
* **`gccSupportsFlag`:** This is a crucial helper function that determines if a specific compiler supports a given flag. It uses background execution and caching to optimize this check.
* **`gccCompilerID`:** This function aims to create a unique identifier for a specific compiler version, which is important for build caching. It involves checking file stats and using the compiler's version information.
* **`cgo`:**  This is a complex function dealing with the integration of C/C++ code through cgo. It manages the execution of the `cgo` tool, compilation of C/C++ files, and handling of linker flags.
* **`swig` and `swigOne`:** These functions handle the integration of code using SWIG (Simplified Wrapper and Interface Generator). They involve running the `swig` tool and managing the generated files.
* **`disableBuildID`:** This function seems to address a specific issue where build IDs are unwanted for object files.
* **`passLongArgsInResponseFiles`:** This function handles situations where the command line arguments become too long, especially on Windows, by using response files.

**Self-correction/Refinement during thought process:**

* Initially, I might have just listed the functions. However, the prompt asks for "functionality," so I need to explain *what* each function does in the broader context of the Go build process.
* For the code examples, I realized I can't directly call these internal functions from a normal Go program. Instead, I'll demonstrate the *effect* of these functions by showing how the `go` command behaves when C/C++ code or SWIG is involved.
* When explaining command-line parameters, I need to be specific about how the code constructs and manipulates the `flags` slices.
* For user errors, I need to think about common pitfalls when working with cgo or SWIG, as these functions directly manage those processes. For example, incorrect CFLAGS or LDFLAGS are common issues.
* The "第2部分" instruction suggests that this is part of a larger code file. The summarization should focus on the functionalities covered in this specific snippet.

By following this thought process, I can systematically analyze the code and provide a comprehensive and helpful answer to the user's request.
这是 `go/src/cmd/go/internal/work/exec.go` 文件的一部分，主要负责执行编译和链接 C/C++ 代码相关的操作，这些操作通常是通过 cgo 或 SWIG 集成到 Go 程序中的。

以下是其主要功能的归纳：

**核心功能：编译和链接 C/C++ 代码**

这部分代码定义了 `Builder` 结构体的一些方法，这些方法用于调用外部的 C/C++ 编译器（如 gcc, g++）和链接器来编译和链接与 Go 代码集成的 C/C++ 代码。

**具体功能详解：**

1. **`ccompile(a *Action, outfile string, flags []string, file string, compiler []string) error`:**
   - **功能:** 编译单个 C 源代码文件。
   - **详细:**
     - 接收一个 `Action` 结构体，包含了构建的上下文信息。
     - `outfile`：指定编译生成的目标文件路径。
     - `flags`：传递给 C 编译器的编译选项。
     - `file`：要编译的 C 源代码文件路径。
     - `compiler`：C 编译器可执行文件的路径（例如，`gcc`）。
     - **`-trimpath` 和 `-fdebug-prefix-map` 处理:**  当设置了 `-trimpath` 或当前包位于 Go SDK 内部时，会添加 `-fdebug-prefix-map` 或 `-ffile-prefix-map` 选项，用于在调试信息中移除源码路径的前缀，使得构建产物在不同环境中更具可比性。
     - **随机种子:** 为了确保 LTO (Link-Time Optimization) 不会产生随机符号，会传递 `-frandom-seed` 选项。
     - **FreeBSD 11 clang 警告处理:**  针对 FreeBSD 11 上 clang 3.8 版本在开启 `-g` 调试信息时可能出现的 DWARF 版本警告进行特殊处理，如果检测到该警告，会尝试移除 `-g` 选项并重新编译。
     - **`GO_BUILDER_NAME` 环境变量处理:** 如果设置了 `GO_BUILDER_NAME` 环境变量，C 编译器的警告会被提升为错误。

2. **`gccld(a *Action, objdir, outfile string, flags []string, objs []string) error`:**
   - **功能:** 使用 gcc 或 g++ 链接器将多个目标文件链接成一个可执行文件。
   - **详细:**
     - 接收一个 `Action` 结构体，包含了构建的上下文信息。
     - `objdir`：目标文件所在的目录。
     - `outfile`：最终生成的可执行文件路径。
     - `flags`：传递给链接器的链接选项。
     - `objs`：需要链接的目标文件列表。
     - 根据包中是否包含 C++ 文件 (`p.CXXFiles` 或 `p.SwigCXXFiles`)，选择使用 `b.GccCmd` 或 `b.GxxCmd` 获取相应的编译器命令前缀。
     - 在调试模式下 (`cfg.BuildN` 或 `cfg.BuildX`)，会打印链接命令，并指示链接是否成功。

3. **`GccCmd(incdir, workdir string) []string` 和 `GxxCmd(incdir, workdir string) []string`:**
   - **功能:** 分别返回 gcc 和 g++ 的命令行前缀，包括必要的 include 路径和架构相关的选项。
   - **详细:**
     - `incdir`：指定头文件搜索路径。
     - `workdir`：工作目录。
     - 使用 `b.compilerCmd` 构建命令，包含 `-I` 指定头文件路径、`-fPIC` (除非是 Windows)、架构相关参数 (`b.gccArchArgs()`)、pthread 支持等。

4. **`gfortranCmd(incdir, workdir string) []string`:**
   - **功能:** 返回 gfortran 的命令行前缀。

5. **`ccExe() []string`, `cxxExe() []string`, `fcExe() []string`:**
   - **功能:** 分别获取 C、C++ 和 Fortran 编译器的可执行文件路径，这些路径通常从环境变量 (`CC`, `CXX`, `FC`) 或默认配置中获取。

6. **`compilerCmd(compiler []string, incdir, workdir string) []string`:**
   - **功能:** 构建通用的编译器命令行前缀，包含架构相关的选项、pthread 支持、以及禁用 clang 错误信息中的 ASCII 艺术等。
   - **详细:**
     - 处理 `-fdebug-prefix-map` 和 `-ffile-prefix-map` 以移除工作目录信息。
     - 使用 `-gno-record-gcc-switches` 避免在目标文件中记录 gcc 开关。
     - 在 macOS 和 iOS 上添加 `-fno-common` 选项。

7. **`gccNoPie(linker []string) string`:**
   - **功能:** 返回用于请求非 PIE (Position Independent Executable) 的链接器标志 (`-no-pie` 或 `-nopie`)，这在进行部分链接时可能需要。

8. **`gccSupportsFlag(compiler []string, flag string) bool`:**
   - **功能:** 检查指定的编译器是否支持某个特定的编译选项。
   - **详细:**
     - 通过执行编译器命令并检查输出中是否包含 "unrecognized" 或 "unknown" 等关键词来判断。
     - 使用缓存 (`b.flagCache`) 来避免重复检查。

9. **`statString(info os.FileInfo) string`:**
   - **功能:** 将 `os.FileInfo` 转换为字符串形式，用于缓存和比较文件状态。

10. **`gccCompilerID(compiler string) (id cache.ActionID, ok bool)`:**
    - **功能:** 为特定的 gcc 编译器版本生成一个构建缓存键。
    - **详细:**
        - 通过执行 `compiler --version` 获取编译器信息。
        - 缓存编译器的可执行文件路径和其状态信息，以便在下次构建时快速判断编译器是否发生变化。

11. **`gccArchArgs() []string`:**
    - **功能:** 根据目标架构 (`cfg.Goarch`) 返回传递给 gcc 的架构相关参数，例如 `-m32`、`-m64`、`-arch x86_64` 等。

12. **`envList(key, def string) []string`:**
    - **功能:** 获取指定环境变量的值，如果为空则使用默认值，并将值按照空格分隔成字符串列表。

13. **`CFlags(p *load.Package) (cppflags, cflags, cxxflags, fflags, ldflags []string, err error)`:**
    - **功能:** 获取构建 C/C++/Fortran 代码和 cgo 时需要使用的各种 flags（CPPFLAGS, CFLAGS, CXXFLAGS, FFLAGS, LDFLAGS），这些 flags 可能来自环境变量或包内的 `#cgo` 指令。

14. **`buildFlags(name, defaults string, fromPackage []string, check func(string, string, []string) error) ([]string, error)`:**
    - **功能:**  构建特定类型的 flags 列表，结合环境变量和包内的 `#cgo` 指令。

15. **`cgo(a *Action, cgoExe, objdir string, pcCFLAGS, pcLDFLAGS, cgofiles, gccfiles, gxxfiles, mfiles, ffiles []string) (outGo, outObj []string, err error)`:**
    - **功能:** 处理 cgo 集成，包括运行 `cgo` 工具生成 Go 代码，编译 C/C++/Objective-C/Fortran 代码。
    - **详细:**
        - 构建传递给 `cgo` 工具的参数，包括 include 路径、import 路径等。
        - 调用 `gcc`、`gxx` 和 `gfortran` 方法编译 C、C++、Objective-C 和 Fortran 代码。
        - 处理与内部链接不兼容的 CFLAGS/CXXFLAGS/FFLAGS，如果发现不兼容的 flags，会生成一个 `preferlinkext` 文件，指示链接器使用外部链接。
        - 处理 MSan 和 ASan 的 flags。
        - 调用 `dynimport` 处理动态链接的库。
        - 针对 gccgo 工具链的特殊处理。
        - 检查 `//go:cgo_ldflag` 注释的安全性。

16. **`flagsNotCompatibleWithInternalLinking(sourceList []string, flagListList [][]string) bool`:**
    - **功能:** 检查 C/C++/Fortran 的编译选项中是否存在与内部链接不兼容的 flags（例如，使用了插件或 LTO）。

17. **`dynimport(a *Action, objdir, importGo, cgoExe string, cflags, cgoLDFLAGS, outObj []string) (dynOutGo, dynOutObj string, err error)`:**
    - **功能:** 处理动态导入的符号或库，生成包含 `//go:cgo_import_dynamic` 指令的 Go 源代码文件。

18. **`swig(a *Action, objdir string, pcCFLAGS []string) (outGo, outC, outCXX []string, err error)` 和 `swigOne(a *Action, file, objdir string, pcCFLAGS []string, cxx bool, intgosize string) (outGo, outC string, err error)`:**
    - **功能:** 处理 SWIG 集成，运行 SWIG 工具生成 Go 和 C/C++ 代码。
    - **详细:**
        - `swig` 方法遍历所有 SWIG 输入文件。
        - `swigOne` 方法处理单个 SWIG 输入文件，调用 `swig` 命令，并处理生成的 Go 和 C/C++ 文件。

19. **`swigVersionCheck() error` 和 `swigDoVersionCheck() error`:**
    - **功能:** 检查 SWIG 的版本是否满足最低要求 (>= 3.0.6)。

20. **`swigIntSize(objdir string) (intsize string, err error)` 和 `swigDoIntSize(objdir string) (intsize string, err error)`:**
    - **功能:** 确定目标系统上 `int` 类型的大小，用于传递给 SWIG 的 `-intgosize` 选项。

21. **`disableBuildID(ldflags []string) []string`:**
    - **功能:** 修改链接器命令行，避免在创建目标文件时生成 build ID。

22. **`mkAbsFiles(dir string, files []string) []string`:**
    - **功能:** 将相对于指定目录的文件路径转换为绝对路径。

23. **`actualFiles(files []string) []string`:**
    - **功能:**  使用 `fsys.Actual` 获取文件的实际路径，这在处理文件系统 overlay 时可能有用。

24. **`passLongArgsInResponseFiles(cmd *exec.Cmd) (cleanup func())` 和 `useResponseFile(path string, argLen int) bool`, `encodeArg(arg string) string`:**
    - **功能:** 处理命令行参数过长的问题，特别是在 Windows 上，通过将参数写入“response file”传递给程序。

**可以推理出的 Go 语言功能实现：**

这部分代码是 Go 工具链中处理与 C/C++ 代码交互的核心部分，主要与以下 Go 语言功能相关：

* **`cgo`:**  这部分代码直接实现了 `cgo` 功能背后的编译和链接逻辑。
* **`//go:cgo_*` 指令:** 代码中解析和处理了 `#cgo CFLAGS`, `#cgo LDFLAGS` 等指令。
* **SWIG 集成:**  支持使用 SWIG 工具生成 Go 语言绑定。
* **构建模式 (Build Modes):** 代码中根据不同的构建模式（例如 `c-archive`, `c-shared`) 执行不同的操作。
* **交叉编译:**  代码中考虑了不同操作系统和架构下的编译选项。

**Go 代码示例 (体现 `cgo` 功能):**

假设我们有一个简单的 C 头文件 `hello.h`：

```c
// hello.h
#ifndef HELLO_H
#define HELLO_H

void say_hello(const char *name);

#endif
```

和一个 C 源代码文件 `hello.c`:

```c
// hello.c
#include <stdio.h>
#include "hello.h"

void say_hello(const char *name) {
    printf("Hello, %s from C!\n", name);
}
```

以及一个 Go 文件 `main.go`，使用 cgo 调用 C 代码：

```go
package main

// #cgo CFLAGS: -I.
// #cgo LDFLAGS: -L. -lhello
// #include "hello.h"
import "C"
import "fmt"

func main() {
    name := "Go User"
    C.say_hello(C.CString(name))
    fmt.Println("Hello from Go!")
}
```

要构建和运行这个程序，你需要在 `main.go` 所在的目录下，将 `hello.h` 和 `hello.c` 编译成一个共享库（例如 `libhello.so` 或 `libhello.dylib` 或 `hello.dll`，具体取决于操作系统）。

**假设的输入与输出：**

1. **输入:** 上述的 `main.go`, `hello.h`, `hello.c` 文件。
2. **操作:** 运行 `go build main.go`。
3. **`exec.go` 中的相关函数会被调用，例如：**
   - `cgo` 函数会被调用处理 `main.go` 中的 cgo 指令。
   - `gcc` 函数会被调用编译 `_cgo_export.c` 和其他由 `cgo` 生成的 C 代码。
   - `gccld` 函数会被调用链接 Go 代码和 C 代码生成的共享库。
4. **输出:**  生成一个可执行文件 `main` (或 `main.exe` 在 Windows 上)。
5. **运行可执行文件 `main` 的输出:**
   ```
   Hello, Go User from C!
   Hello from Go!
   ```

**命令行参数的具体处理：**

- **`ccompile` 和 `gccld` 等函数接收 `flags []string` 参数，这些参数包含了要传递给 C 编译器和链接器的各种选项。** 这些选项可能来自：
    - **`#cgo CFLAGS`, `#cgo LDFLAGS` 等指令:**  Go 编译器会解析这些指令并将相应的选项添加到 `flags` 中。
    - **环境变量:** 例如 `CGO_CFLAGS`, `CGO_LDFLAGS` 等。
    - **Go 工具链自身的配置:** 例如 `-trimpath` 等构建选项。
- **代码中会根据不同的条件添加或修改这些 flags。** 例如，根据目标操作系统和架构添加 `-fPIC`、`-pthread` 等选项。
- **`gccSupportsFlag` 函数用于检查编译器是否支持特定的 flag。** 这允许代码在添加某些 flag 之前进行能力检测。

**易犯错的点 (使用者角度):**

当使用 cgo 或 SWIG 时，用户容易犯以下错误，这些错误可能会导致 `exec.go` 中调用的外部命令失败：

1. **错误的 `#cgo CFLAGS` 或 `#cgo LDFLAGS`:** 例如，指定了不存在的头文件路径、链接了错误的库、使用了不被目标编译器支持的选项等。
   ```go
   package main

   // #cgo CFLAGS: -I/path/to/nowhere
   // #include <stdio.h>
   import "C"

   func main() {
       C.puts(C.CString("Hello"))
   }
   ```
   **错误原因:** `-I/path/to/nowhere` 指定了一个不存在的头文件路径。

2. **忘记链接 C 代码生成的库:**  在使用 cgo 调用 C 函数时，需要确保 C 代码被编译成库，并且在 `LDFLAGS` 中指定了正确的库路径和名称。
   ```go
   package main

   // #cgo LDFLAGS: -L. -lmylib  // 假设没有编译出 libmylib.so
   // #include "mylib.h"
   import "C"

   func main() {
       // ... 调用 mylib.h 中定义的函数
   }
   ```
   **错误原因:**  `libmylib.so` 不存在或路径不正确。

3. **SWIG 接口定义文件错误:**  如果使用 SWIG，接口定义文件 (.swig 或 .i) 中的错误会导致 SWIG 工具生成不正确的代码，进而导致编译或链接错误。

**第2部分功能归纳:**

这部分 `exec.go` 的代码主要负责 Go 程序构建过程中与 C/C++ 代码编译和链接相关的底层操作。它封装了调用外部编译器和链接器的细节，并处理了与 cgo 和 SWIG 集成相关的复杂性，包括选项处理、错误处理和平台兼容性。它的核心目标是确保 Go 程序能够正确地与 C/C++ 代码进行交互。

### 提示词
```
这是路径为go/src/cmd/go/internal/work/exec.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
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
		// Can't find version number; hope for the best.
		return nil
	}

	major, err := strconv.Atoi(string(matches[1]))
	if err != nil {
		// Can't find version number; hope for the best.
		return nil
	}
	const errmsg = "must have SWIG version >= 3.0.6"
	if major < 3 {
		return errors.New(errmsg)
	}
	if major > 3 {
		// 4.0 or later
		return nil
	}

	// We have SWIG version 3.x.
	if len(matches[2]) > 0 {
		minor, err := strconv.Atoi(string(matches[2][1:]))
		if err != nil {
			return nil
		}
		if minor > 0 {
			// 3.1 or later
			return nil
		}
	}

	// We have SWIG version 3.0.x.
	if len(matches[3]) > 0 {
		patch, err := strconv.Atoi(string(matches[3][1:]))
		if err != nil {
			return nil
		}
		if patch < 6 {
			// Before 3.0.6.
			return errors.New(errmsg)
		}
	}

	return nil
}

func (b *Builder) swigVersionCheck() error {
	swigCheckOnce.Do(func() {
		swigCheck = b.swigDoVersionCheck()
	})
	return swigCheck
}

// Find the value to pass for the -intgosize option to swig.
var (
	swigIntSizeOnce  sync.Once
	swigIntSize      string
	swigIntSizeError error
)

// This code fails to build if sizeof(int) <= 32
const swigIntSizeCode = `
package main
const i int = 1 << 32
`

// Determine the size of int on the target system for the -intgosize option
// of swig >= 2.0.9. Run only once.
func (b *Builder) swigDoIntSize(objdir string) (intsize string, err error) {
	if cfg.BuildN {
		return "$INTBITS", nil
	}
	src := filepath.Join(b.WorkDir, "swig_intsize.go")
	if err = os.WriteFile(src, []byte(swigIntSizeCode), 0666); err != nil {
		return
	}
	srcs := []string{src}

	p := load.GoFilesPackage(context.TODO(), load.PackageOpts{}, srcs)

	if _, _, e := BuildToolchain.gc(b, &Action{Mode: "swigDoIntSize", Package: p, Objdir: objdir}, "", nil, nil, "", false, "", srcs); e != nil {
		return "32", nil
	}
	return "64", nil
}

// Determine the size of int on the target system for the -intgosize option
// of swig >= 2.0.9.
func (b *Builder) swigIntSize(objdir string) (intsize string, err error) {
	swigIntSizeOnce.Do(func() {
		swigIntSize, swigIntSizeError = b.swigDoIntSize(objdir)
	})
	return swigIntSize, swigIntSizeError
}

// Run SWIG on one SWIG input file.
func (b *Builder) swigOne(a *Action, file, objdir string, pcCFLAGS []string, cxx bool, intgosize string) (outGo, outC string, err error) {
	p := a.Package
	sh := b.Shell(a)

	cgoCPPFLAGS, cgoCFLAGS, cgoCXXFLAGS, _, _, err := b.CFlags(p)
	if err != nil {
		return "", "", err
	}

	var cflags []string
	if cxx {
		cflags = str.StringList(cgoCPPFLAGS, pcCFLAGS, cgoCXXFLAGS)
	} else {
		cflags = str.StringList(cgoCPPFLAGS, pcCFLAGS, cgoCFLAGS)
	}

	n := 5 // length of ".swig"
	if cxx {
		n = 8 // length of ".swigcxx"
	}
	base := file[:len(file)-n]
	goFile := base + ".go"
	gccBase := base + "_wrap."
	gccExt := "c"
	if cxx {
		gccExt = "cxx"
	}

	gccgo := cfg.BuildToolchainName == "gccgo"

	// swig
	args := []string{
		"-go",
		"-cgo",
		"-intgosize", intgosize,
		"-module", base,
		"-o", objdir + gccBase + gccExt,
		"-outdir", objdir,
	}

	for _, f := range cflags {
		if len(f) > 3 && f[:2] == "-I" {
			args = append(args, f)
		}
	}

	if gccgo {
		args = append(args, "-gccgo")
		if pkgpath := gccgoPkgpath(p); pkgpath != "" {
			args = append(args, "-go-pkgpath", pkgpath)
		}
	}
	if cxx {
		args = append(args, "-c++")
	}

	out, err := sh.runOut(p.Dir, nil, "swig", args, file)
	if err != nil && (bytes.Contains(out, []byte("-intgosize")) || bytes.Contains(out, []byte("-cgo"))) {
		return "", "", errors.New("must have SWIG version >= 3.0.6")
	}
	if err := sh.reportCmd("", "", out, err); err != nil {
		return "", "", err
	}

	// If the input was x.swig, the output is x.go in the objdir.
	// But there might be an x.go in the original dir too, and if it
	// uses cgo as well, cgo will be processing both and will
	// translate both into x.cgo1.go in the objdir, overwriting one.
	// Rename x.go to _x_swig.go to avoid this problem.
	// We ignore files in the original dir that begin with underscore
	// so _x_swig.go cannot conflict with an original file we were
	// going to compile.
	goFile = objdir + goFile
	newGoFile := objdir + "_" + base + "_swig.go"
	if cfg.BuildX || cfg.BuildN {
		sh.ShowCmd("", "mv %s %s", goFile, newGoFile)
	}
	if !cfg.BuildN {
		if err := os.Rename(goFile, newGoFile); err != nil {
			return "", "", err
		}
	}
	return newGoFile, objdir + gccBase + gccExt, nil
}

// disableBuildID adjusts a linker command line to avoid creating a
// build ID when creating an object file rather than an executable or
// shared library. Some systems, such as Ubuntu, always add
// --build-id to every link, but we don't want a build ID when we are
// producing an object file. On some of those system a plain -r (not
// -Wl,-r) will turn off --build-id, but clang 3.0 doesn't support a
// plain -r. I don't know how to turn off --build-id when using clang
// other than passing a trailing --build-id=none. So that is what we
// do, but only on systems likely to support it, which is to say,
// systems that normally use gold or the GNU linker.
func (b *Builder) disableBuildID(ldflags []string) []string {
	switch cfg.Goos {
	case "android", "dragonfly", "linux", "netbsd":
		ldflags = append(ldflags, "-Wl,--build-id=none")
	}
	return ldflags
}

// mkAbsFiles converts files into a list of absolute files,
// assuming they were originally relative to dir,
// and returns that new list.
func mkAbsFiles(dir string, files []string) []string {
	abs := make([]string, len(files))
	for i, f := range files {
		if !filepath.IsAbs(f) {
			f = filepath.Join(dir, f)
		}
		abs[i] = f
	}
	return abs
}

// actualFiles applies fsys.Actual to the list of files.
func actualFiles(files []string) []string {
	a := make([]string, len(files))
	for i, f := range files {
		a[i] = fsys.Actual(f)
	}
	return a
}

// passLongArgsInResponseFiles modifies cmd such that, for
// certain programs, long arguments are passed in "response files", a
// file on disk with the arguments, with one arg per line. An actual
// argument starting with '@' means that the rest of the argument is
// a filename of arguments to expand.
//
// See issues 18468 (Windows) and 37768 (Darwin).
func passLongArgsInResponseFiles(cmd *exec.Cmd) (cleanup func()) {
	cleanup = func() {} // no cleanup by default

	var argLen int
	for _, arg := range cmd.Args {
		argLen += len(arg)
	}

	// If we're not approaching 32KB of args, just pass args normally.
	// (use 30KB instead to be conservative; not sure how accounting is done)
	if !useResponseFile(cmd.Path, argLen) {
		return
	}

	tf, err := os.CreateTemp("", "args")
	if err != nil {
		log.Fatalf("error writing long arguments to response file: %v", err)
	}
	cleanup = func() { os.Remove(tf.Name()) }
	var buf bytes.Buffer
	for _, arg := range cmd.Args[1:] {
		fmt.Fprintf(&buf, "%s\n", encodeArg(arg))
	}
	if _, err := tf.Write(buf.Bytes()); err != nil {
		tf.Close()
		cleanup()
		log.Fatalf("error writing long arguments to response file: %v", err)
	}
	if err := tf.Close(); err != nil {
		cleanup()
		log.Fatalf("error writing long arguments to response file: %v", err)
	}
	cmd.Args = []string{cmd.Args[0], "@" + tf.Name()}
	return cleanup
}

func useResponseFile(path string, argLen int) bool {
	// Unless the program uses objabi.Flagparse, which understands
	// response files, don't use response files.
	// TODO: Note that other toolchains like CC are missing here for now.
	prog := strings.TrimSuffix(filepath.Base(path), ".exe")
	switch prog {
	case "compile", "link", "cgo", "asm", "cover":
	default:
		return false
	}

	if argLen > sys.ExecArgLengthLimit {
		return true
	}

	// On the Go build system, use response files about 10% of the
	// time, just to exercise this codepath.
	isBuilder := os.Getenv("GO_BUILDER_NAME") != ""
	if isBuilder && rand.Intn(10) == 0 {
		return true
	}

	return false
}

// encodeArg encodes an argument for response file writing.
func encodeArg(arg string) string {
	// If there aren't any characters we need to reencode, fastpath out.
	if !strings.ContainsAny(arg, "\\\n") {
		return arg
	}
	var b strings.Builder
	for _, r := range arg {
		switch r {
		case '\\':
			b.WriteByte('\\')
			b.WriteByte('\\')
		case '\n':
			b.WriteByte('\\')
			b.WriteByte('n')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
```