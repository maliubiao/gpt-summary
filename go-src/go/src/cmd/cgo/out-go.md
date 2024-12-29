Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The request asks for the functionality of the `out.go` file within the `cmd/cgo` package. It also requests examples, reasoning, handling of command-line arguments, and common mistakes (though this last one turned out to be not applicable in this specific snippet).

2. **Identify the Core Function:** The function `writeDefs()` stands out as the central piece of logic in this snippet. Its name suggests it's responsible for writing definition files.

3. **Analyze `writeDefs()` Step-by-Step:**
    * **File Creation:** The function starts by creating several files in a directory specified by `*objDir`. The filenames (`_cgo_gotypes.go`, `_cgo_defun.c` (conditional), `_cgo_main.c`, `_cgo_flags` (conditional), `_cgo_export.c`, `_cgo_export.h`) hint at the different types of output being generated: Go code, C code, and header files.
    * **Conditional Logic (`*gccgo`):** The presence of `*gccgo` checks suggests different code paths for the standard `gc` compiler and `gccgo`. This is a crucial distinction for understanding the function's behavior.
    * **LD Flags:** The code iterates through `p.LdFlags` and writes them into the output files, with variations depending on `*gccgo`. This points to handling linker flags required for the C code.
    * **C Main File (`_cgo_main.c`):**  The content written to `fm` is a minimal `main` function in C. This is likely used as a stub for compiling C code with `gcc` or `clang`. The `crosscall2` and other `_cgo_` functions are declared or defined here, hinting at the mechanism for communication between Go and C. The `*importRuntimeCgo` condition further clarifies that this file's content depends on whether the current package *is* `runtime/cgo` or *imports* it.
    * **Go Definitions File (`_cgo_gotypes.go`):**  The code writes a Go file containing type definitions (prefixed with `_Ctype_`). The `//go:linkname` directives are significant, indicating how Go symbols are linked to C symbols. The handling of `typedef` and the `_Ctype_void` special case are important details. The conditional inclusion of `gccgoGoProlog` or `goProlog` again shows the distinction between the compilers.
    * **C Variables:** The code iterates through `p.Name` to find C variables and declares them in both the Go and C output files. The `//go:cgo_import_static` directive is crucial for how Go imports C symbols.
    * **C Constants:** C constants are written to the Go output.
    * **Function Definitions (`writeDefsFunc`):** This nested function handles the generation of Go wrappers for C functions.
    * **Exports (`writeExports`, `writeGccgoExports`):** The creation of `_cgo_export.c` and `_cgo_export.h` and the calls to `writeExports` and `writeGccgoExports` indicate the mechanism for exporting Go functions to be called from C. Again, the `*gccgo` conditional is present.
    * **Memory Allocation (`callsMalloc`, `cMallocDefGo`, `cMallocDefC`):** The code conditionally includes definitions for `malloc` if it detects that C functions requiring allocation are being used.
    * **Export Header Handling (`*exportHeader`):** The code allows copying the generated header to a specified location.
    * **Initialization Function (`gccgoInit`):**  For `gccgo`, a static `init` function is generated in the C code to perform initial assignments.

4. **Identify Related Functions:**  While `writeDefs()` is central, other functions like `elfImportedSymbols`, `dynimport`, `checkImportSymName`, `structType`, `writeOutput`, `writeOutputFunc`, `writeGccgoOutputFunc`, `writeExports`, `writeGccgoExports`, `writeExportHeader`, and helper functions like `forFieldList` and `cgoType` contribute to the overall functionality. Briefly skimming these gives more context. For example, `dynimport` deals with extracting dynamic library imports.

5. **Infer the Overall Goal (cgo):** Based on the filenames, the handling of C and Go code, linker flags, and the concept of exports/imports, it becomes clear that this code is part of the `cgo` tool. `cgo` enables Go programs to interact with C code.

6. **Reason About the Code's Role in cgo:**
    * **`_cgo_gotypes.go`:** Provides Go type aliases for C types and declarations for C variables and functions, enabling Go code to interact with C.
    * **`_cgo_main.c`:**  A small C program used for linking against C libraries and resolving symbols. It also provides stub implementations for certain `runtime/cgo` functions when the current package *is not* `runtime/cgo`.
    * **`_cgo_export.c` and `_cgo_export.h`:** Enable C code to call Go functions. The `.h` file provides the necessary declarations.
    * **`_cgo_defun.c` (gccgo):** Contains definitions specific to `gccgo`.
    * **`_cgo_flags` (gccgo):** Holds linker flags for `gccgo`.

7. **Construct Examples:**  Based on the inferred functionality, create illustrative Go code snippets demonstrating the interaction between Go and C using `cgo`. Include comments to explain what's happening.

8. **Address Command-Line Arguments:**  Scan the code for variables that look like command-line flags (variables declared at the top with names starting with lowercase and used in conditional statements, like `*gccgo`, `*objDir`, `*importRuntimeCgo`, etc.). Explain their purpose based on how they influence the generated output.

9. **Consider Potential Mistakes:**  Think about common pitfalls when using `cgo`. For *this specific snippet*, there weren't many direct user-facing error points within the code itself. The error handling focuses on internal issues (like recursive types or unsupported Go types). Therefore, the "common mistakes" section remained empty, which is a valid outcome of the analysis.

10. **Review and Refine:** Read through the analysis and examples to ensure clarity, accuracy, and completeness. Check for consistency and proper terminology. For instance, ensuring the explanation differentiates between `gc` and `gccgo` when needed.

This structured approach, starting with the core function and progressively understanding the surrounding code and its implications, leads to a comprehensive analysis of the provided `cgo` code snippet.
这段代码是 Go 语言的 `cgo` 工具中用于生成输出文件的部分，路径为 `go/src/cmd/cgo/out.go`。它的主要功能是根据解析得到的 C 代码和 Go 代码的交互信息，生成一系列中间文件，这些文件会被 Go 编译器 (`gc`) 和 C 编译器 (`gcc` 或其他) 用于最终的编译和链接。

**核心功能列举:**

1. **生成 Go 类型定义文件 (`_cgo_gotypes.go`):**
   - 定义了与 C 类型对应的 Go 类型别名（例如 `_Ctype_int`）。
   - 声明了需要从 C 导入的全局变量（使用 `//go:linkname` 和 `//go:cgo_import_static` 指令）。
   - 定义了用于调用 C 函数的 Go 函数包装器。
   - 处理 `typedef` 声明，将 C 的 `typedef` 转换为 Go 的类型别名。

2. **生成 C 主文件 (`_cgo_main.c`):**
   - 包含一个空的 `main` 函数，主要用于在链接阶段解析 C 的符号。
   - 根据是否导入 `runtime/cgo`，提供 `crosscall2` 等函数的声明或简单的定义，这些函数是 Go 运行时与 C 代码交互的关键。

3. **生成 C 定义文件 (`_cgo_defun.c`, 仅当使用 `gccgo` 时):**
   - 声明了需要从 C 导入的全局变量。
   - 包含一个静态的 `init` 函数，用于初始化全局变量。

4. **生成链接器标志文件 (`_cgo_flags`, 仅当使用 `gccgo` 时):**
   - 记录了需要传递给 C 链接器的标志（通过 `//go:cgo_ldflag` 注释指定）。

5. **生成 C 导出文件 (`_cgo_export.c` 和 `_cgo_export.h`):**
   - 实现了将 Go 函数暴露给 C 代码调用的包装器函数。
   - 定义了 C 头文件 (`_cgo_export.h`)，其中声明了可以从 C 代码调用的 Go 函数。

6. **处理动态链接库导入 (`dynimport` 函数):**
   - 读取目标对象文件（ELF, Mach-O, PE, XCOFF），提取需要动态链接的符号和库。
   - 生成带有 `//go:cgo_import_dynamic` 指令的 Go 代码，指示链接器在运行时动态链接这些符号。

7. **生成特定 Go 源文件的 C 代码 (`writeOutput` 函数):**
   - 将原始的 Go 代码复制到 `*.cgo1.go` 文件中，并将其中对 `C.xxx` 的调用替换为内部的 `_C_xxx`。
   - 生成对应的 C 代码文件 (`*.cgo2.c`)，包含必要的 `#include` 和 C 函数的包装器实现。

**实现的 Go 语言功能推断与代码示例:**

这段代码主要实现了 `cgo` 工具的核心功能：**允许 Go 代码调用 C 代码，以及允许 C 代码调用 Go 代码。**

**Go 代码调用 C 代码示例:**

假设我们有一个名为 `hello.go` 的 Go 文件，其中包含以下代码：

```go
package main

/*
#include <stdio.h>

void say_hello(const char *name) {
    printf("Hello, %s!\n", name);
}
*/
import "C"

import "unsafe"

func main() {
    name := "Go"
    cName := C.CString(name)
    defer C.free(unsafe.Pointer(cName)) // 记得释放 C 分配的内存
    C.say_hello(cName)
}
```

当 `cgo` 处理 `hello.go` 时，`writeDefs` 和 `writeOutput` 函数会生成类似以下的中间文件（简化示例）：

**`_cgo_gotypes.go` (部分):**

```go
package main

import "unsafe"

// ... 其他定义 ...

//go:linkname __cgofn_say_hello say_hello
//go:cgo_import_static say_hello
var __cgofn_say_hello byte
var _Cfunc_say_hello = unsafe.Pointer(&__cgofn_say_hello)

func _Cfunc_say_hello(p0 *_Ctype_char) {
	_cgo_runtime_cgocall(_Cfunc_say_hello, uintptr(unsafe.Pointer(&p0)))
}

// ... CString 和 free 的定义 ...
```

**`hello.cgo2.c` (部分):**

```c
/* ... 头文件和宏定义 ... */

void _cgo_Cfunc_say_hello(void *v) {
	struct {
		char *p0;
	} *a = v;
	say_hello(a->p0);
}

/* ... CString 和 free 的实现 ... */
```

**假设的输入与输出:**

**输入:**  包含上述 `hello.go` 文件的目录。

**输出:**  在 `*objDir` 指定的目录下生成 `_cgo_gotypes.go`, `_cgo_main.c`, `hello.cgo1.go`, `hello.cgo2.c` 等文件。

**C 代码调用 Go 代码示例:**

假设我们有一个名为 `export.go` 的 Go 文件，它导出一个函数给 C 调用：

```go
package main

import "C"
import "fmt"

//export SayHiFromGo
func SayHiFromGo(name *C.char) {
	goName := C.GoString(name)
	fmt.Printf("Hello from Go, %s!\n", goName)
}

func main() {}
```

`writeDefs` 和 `writeExports` 函数会生成类似以下的中间文件（简化示例）：

**`_cgo_export.h` (部分):**

```c
/* ... 头文件 ... */

extern void SayHiFromGo(char* p0);

/* ... */
```

**`_cgo_export.c` (部分):**

```c
/* ... 头文件 ... */

extern void crosscall2(void (*fn)(void *), void *, int, size_t);
extern size_t _cgo_wait_runtime_init_done(void);
extern void _cgo_release_context(size_t);

extern void _cgoexp_SayHiFromGo(void *);

struct _cgo_export_SayHiFromGo_arg {
	char* p0;
};

void SayHiFromGo(char* p0) {
	size_t _cgo_ctxt = _cgo_wait_runtime_init_done();
	struct _cgo_export_SayHiFromGo_arg _cgo_a = { p0 };
	crosscall2(_cgoexp_SayHiFromGo, &_cgo_a, sizeof(_cgo_a), _cgo_ctxt);
	_cgo_release_context(_cgo_ctxt);
}
```

**`_cgo_gotypes.go` (部分):**

```go
package main

import "unsafe"

// ... 其他定义 ...

//go:cgo_export_dynamic SayHiFromGo
//go:linkname _cgoexp_SayHiFromGo _cgoexp_SayHiFromGo
//go:cgo_export_static _cgoexp_SayHiFromGo
func _cgoexp_SayHiFromGo(a *struct { p0 *_Ctype_char }) {
	SayHiFromGo(a.p0)
}

// ...
```

**命令行参数的具体处理:**

代码中使用了全局变量来存储命令行参数，这些参数会影响生成的代码：

- **`*objDir`:**  指定生成中间文件的输出目录。例如，可以通过 `-objdir` 命令行参数设置。
- **`*gccgo`:**  一个布尔值，指示是否使用 `gccgo` 编译器。如果为 `true`，则会生成针对 `gccgo` 的代码。可以通过 `-gccgo` 命令行参数设置。
- **`*importRuntimeCgo`:**  一个布尔值，指示当前编译的包是否导入了 `runtime/cgo`。这会影响 `_cgo_main.c` 中 `crosscall2` 等函数的处理。
- **`*importSyscall`:**  一个布尔值，指示是否导入了 `syscall` 包。
- **`*gccgoDefineCgoIncomplete`:**  一个布尔值，用于 `gccgo`，控制是否定义不完整的 `_cgopackage` 类型。
- **`*exportHeader`:**  指定一个路径，如果设置，则会将生成的 `_cgo_export.h` 文件复制到该路径。
- **`*dynout`:**  指定一个输出文件路径，用于存储 `dynimport` 函数生成的动态链接库导入信息。
- **`*dynpackage`:**  指定 `dynimport` 生成的 Go 代码的包名。
- **`*dynlinker`:**  一个布尔值，用于 `dynimport`，指示是否输出动态链接器的路径。
- **`*gccgopkgpath`:**  用于 `gccgo`，指定包的路径。
- **`*gccgoprefix`:**  用于 `gccgo`，指定符号的前缀。

这些参数通常在 `cgo` 命令执行时通过命令行标志传递，例如：

```bash
go tool cgo -objdir tmp -gccgo export.go
```

在这个例子中，`-objdir tmp` 将设置 `*objDir` 为 "tmp"，`-gccgo` 将设置 `*gccgo` 为 `true`。

**使用者易犯错的点 (基于代码推理):**

从这段代码本身来看，它主要处理代码生成逻辑，使用者直接与之交互较少。易犯错的点更多在于 `cgo` 的使用方式，而不是这段代码的错误。但是，基于代码的逻辑，可以推断出一些潜在的易错点：

1. **忘记释放 C 分配的内存:**  在 Go 中调用 `C.malloc` 或 `C.CString` 等函数分配的内存需要在 C 代码中释放，通常通过调用 `C.free`。使用者容易忘记执行 `defer C.free(unsafe.Pointer(ptr))`。

2. **C 和 Go 类型不匹配:**  `cgo` 需要 C 和 Go 之间的数据类型对应。如果传递了不兼容的类型，可能会导致运行时错误或数据损坏。这段代码中的 `cgoType` 函数负责进行类型映射，但使用者需要确保 Go 侧的类型与 C 侧的声明一致。

3. **`//go:cgo_ldflag` 使用错误:**  传递给 C 链接器的标志不正确可能导致链接失败。例如，库的路径不正确或缺少必要的库。

4. **在 C 代码中不正确地调用 Go 导出的函数:**  使用者需要遵循 `_cgo_export.h` 中声明的函数签名来调用 Go 函数。参数传递错误可能导致崩溃或其他未定义行为。

5. **多线程环境下的同步问题:** `cgo` 调用涉及到 Go 运行时和 C 代码的交互。在多线程环境下，需要仔细处理同步问题，避免数据竞争。代码中出现的 `CGO_NO_SANITIZE_THREAD`, `_cgo_tsan_acquire`, `_cgo_tsan_release` 以及 `_cgo_wait_runtime_init_done` 等机制都与此相关，使用者需要理解其背后的含义。

总而言之，这段 `out.go` 文件是 `cgo` 工具的核心组成部分，负责将 Go 和 C 代码的交互意图转化为实际的中间代码，为后续的编译和链接过程奠定基础。理解其功能有助于深入理解 `cgo` 的工作原理。

Prompt: 
```
这是路径为go/src/cmd/cgo/out.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"cmd/internal/pkgpath"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"go/ast"
	"go/printer"
	"go/token"
	"internal/xcoff"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

var (
	conf         = printer.Config{Mode: printer.SourcePos, Tabwidth: 8}
	noSourceConf = printer.Config{Tabwidth: 8}
)

// writeDefs creates output files to be compiled by gc and gcc.
func (p *Package) writeDefs() {
	var fgo2, fc io.Writer
	f := creat(*objDir + "_cgo_gotypes.go")
	defer f.Close()
	fgo2 = f
	if *gccgo {
		f := creat(*objDir + "_cgo_defun.c")
		defer f.Close()
		fc = f
	}
	fm := creat(*objDir + "_cgo_main.c")

	var gccgoInit strings.Builder

	if !*gccgo {
		for _, arg := range p.LdFlags {
			fmt.Fprintf(fgo2, "//go:cgo_ldflag %q\n", arg)
		}
	} else {
		fflg := creat(*objDir + "_cgo_flags")
		for _, arg := range p.LdFlags {
			fmt.Fprintf(fflg, "_CGO_LDFLAGS=%s\n", arg)
		}
		fflg.Close()
	}

	// Write C main file for using gcc to resolve imports.
	fmt.Fprintf(fm, "#include <stddef.h>\n") // For size_t below.
	fmt.Fprintf(fm, "int main(int argc __attribute__((unused)), char **argv __attribute__((unused))) { return 0; }\n")
	if *importRuntimeCgo {
		fmt.Fprintf(fm, "void crosscall2(void(*fn)(void*) __attribute__((unused)), void *a __attribute__((unused)), int c __attribute__((unused)), size_t ctxt __attribute__((unused))) { }\n")
		fmt.Fprintf(fm, "size_t _cgo_wait_runtime_init_done(void) { return 0; }\n")
		fmt.Fprintf(fm, "void _cgo_release_context(size_t ctxt __attribute__((unused))) { }\n")
		fmt.Fprintf(fm, "char* _cgo_topofstack(void) { return (char*)0; }\n")
	} else {
		// If we're not importing runtime/cgo, we *are* runtime/cgo,
		// which provides these functions. We just need a prototype.
		fmt.Fprintf(fm, "void crosscall2(void(*fn)(void*), void *a, int c, size_t ctxt);\n")
		fmt.Fprintf(fm, "size_t _cgo_wait_runtime_init_done(void);\n")
		fmt.Fprintf(fm, "void _cgo_release_context(size_t);\n")
	}
	fmt.Fprintf(fm, "void _cgo_allocate(void *a __attribute__((unused)), int c __attribute__((unused))) { }\n")
	fmt.Fprintf(fm, "void _cgo_panic(void *a __attribute__((unused)), int c __attribute__((unused))) { }\n")
	fmt.Fprintf(fm, "void _cgo_reginit(void) { }\n")

	// Write second Go output: definitions of _C_xxx.
	// In a separate file so that the import of "unsafe" does not
	// pollute the original file.
	fmt.Fprintf(fgo2, "// Code generated by cmd/cgo; DO NOT EDIT.\n\n")
	fmt.Fprintf(fgo2, "package %s\n\n", p.PackageName)
	fmt.Fprintf(fgo2, "import \"unsafe\"\n\n")
	if *importSyscall {
		fmt.Fprintf(fgo2, "import \"syscall\"\n\n")
	}
	if *importRuntimeCgo {
		if !*gccgoDefineCgoIncomplete {
			fmt.Fprintf(fgo2, "import _cgopackage \"runtime/cgo\"\n\n")
			fmt.Fprintf(fgo2, "type _ _cgopackage.Incomplete\n") // prevent import-not-used error
		} else {
			fmt.Fprintf(fgo2, "//go:notinheap\n")
			fmt.Fprintf(fgo2, "type _cgopackage_Incomplete struct{ _ struct{ _ struct{} } }\n")
		}
	}
	if *importSyscall {
		fmt.Fprintf(fgo2, "var _ syscall.Errno\n")
	}
	fmt.Fprintf(fgo2, "func _Cgo_ptr(ptr unsafe.Pointer) unsafe.Pointer { return ptr }\n\n")

	if !*gccgo {
		fmt.Fprintf(fgo2, "//go:linkname _Cgo_always_false runtime.cgoAlwaysFalse\n")
		fmt.Fprintf(fgo2, "var _Cgo_always_false bool\n")
		fmt.Fprintf(fgo2, "//go:linkname _Cgo_use runtime.cgoUse\n")
		fmt.Fprintf(fgo2, "func _Cgo_use(interface{})\n")
		fmt.Fprintf(fgo2, "//go:linkname _Cgo_keepalive runtime.cgoKeepAlive\n")
		fmt.Fprintf(fgo2, "//go:noescape\n")
		fmt.Fprintf(fgo2, "func _Cgo_keepalive(interface{})\n")
	}
	fmt.Fprintf(fgo2, "//go:linkname _Cgo_no_callback runtime.cgoNoCallback\n")
	fmt.Fprintf(fgo2, "func _Cgo_no_callback(bool)\n")

	typedefNames := make([]string, 0, len(typedef))
	for name := range typedef {
		if name == "_Ctype_void" {
			// We provide an appropriate declaration for
			// _Ctype_void below (#39877).
			continue
		}
		typedefNames = append(typedefNames, name)
	}
	sort.Strings(typedefNames)
	for _, name := range typedefNames {
		def := typedef[name]
		fmt.Fprintf(fgo2, "type %s ", name)
		// We don't have source info for these types, so write them out without source info.
		// Otherwise types would look like:
		//
		// type _Ctype_struct_cb struct {
		// //line :1
		//        on_test *[0]byte
		// //line :1
		// }
		//
		// Which is not useful. Moreover we never override source info,
		// so subsequent source code uses the same source info.
		// Moreover, empty file name makes compile emit no source debug info at all.
		var buf bytes.Buffer
		noSourceConf.Fprint(&buf, fset, def.Go)
		if bytes.HasPrefix(buf.Bytes(), []byte("_Ctype_")) ||
			strings.HasPrefix(name, "_Ctype_enum_") ||
			strings.HasPrefix(name, "_Ctype_union_") {
			// This typedef is of the form `typedef a b` and should be an alias.
			fmt.Fprintf(fgo2, "= ")
		}
		fmt.Fprintf(fgo2, "%s", buf.Bytes())
		fmt.Fprintf(fgo2, "\n\n")
	}
	if *gccgo {
		fmt.Fprintf(fgo2, "type _Ctype_void byte\n")
	} else {
		fmt.Fprintf(fgo2, "type _Ctype_void [0]byte\n")
	}

	if *gccgo {
		fmt.Fprint(fgo2, gccgoGoProlog)
		fmt.Fprint(fc, p.cPrologGccgo())
	} else {
		fmt.Fprint(fgo2, goProlog)
	}

	if fc != nil {
		fmt.Fprintf(fc, "#line 1 \"cgo-generated-wrappers\"\n")
	}
	if fm != nil {
		fmt.Fprintf(fm, "#line 1 \"cgo-generated-wrappers\"\n")
	}

	gccgoSymbolPrefix := p.gccgoSymbolPrefix()

	cVars := make(map[string]bool)
	for _, key := range nameKeys(p.Name) {
		n := p.Name[key]
		if !n.IsVar() {
			continue
		}

		if !cVars[n.C] {
			if *gccgo {
				fmt.Fprintf(fc, "extern byte *%s;\n", n.C)
			} else {
				// Force a reference to all symbols so that
				// the external linker will add DT_NEEDED
				// entries as needed on ELF systems.
				// Treat function variables differently
				// to avoid type conflict errors from LTO
				// (Link Time Optimization).
				if n.Kind == "fpvar" {
					fmt.Fprintf(fm, "extern void %s();\n", n.C)
				} else {
					fmt.Fprintf(fm, "extern char %s[];\n", n.C)
					fmt.Fprintf(fm, "void *_cgohack_%s = %s;\n\n", n.C, n.C)
				}
				fmt.Fprintf(fgo2, "//go:linkname __cgo_%s %s\n", n.C, n.C)
				fmt.Fprintf(fgo2, "//go:cgo_import_static %s\n", n.C)
				fmt.Fprintf(fgo2, "var __cgo_%s byte\n", n.C)
			}
			cVars[n.C] = true
		}

		var node ast.Node
		if n.Kind == "var" {
			node = &ast.StarExpr{X: n.Type.Go}
		} else if n.Kind == "fpvar" {
			node = n.Type.Go
		} else {
			panic(fmt.Errorf("invalid var kind %q", n.Kind))
		}
		if *gccgo {
			fmt.Fprintf(fc, `extern void *%s __asm__("%s.%s");`, n.Mangle, gccgoSymbolPrefix, gccgoToSymbol(n.Mangle))
			fmt.Fprintf(&gccgoInit, "\t%s = &%s;\n", n.Mangle, n.C)
			fmt.Fprintf(fc, "\n")
		}

		fmt.Fprintf(fgo2, "var %s ", n.Mangle)
		conf.Fprint(fgo2, fset, node)
		if !*gccgo {
			fmt.Fprintf(fgo2, " = (")
			conf.Fprint(fgo2, fset, node)
			fmt.Fprintf(fgo2, ")(unsafe.Pointer(&__cgo_%s))", n.C)
		}
		fmt.Fprintf(fgo2, "\n")
	}
	if *gccgo {
		fmt.Fprintf(fc, "\n")
	}

	for _, key := range nameKeys(p.Name) {
		n := p.Name[key]
		if n.Const != "" {
			fmt.Fprintf(fgo2, "const %s = %s\n", n.Mangle, n.Const)
		}
	}
	fmt.Fprintf(fgo2, "\n")

	callsMalloc := false
	for _, key := range nameKeys(p.Name) {
		n := p.Name[key]
		if n.FuncType != nil {
			p.writeDefsFunc(fgo2, n, &callsMalloc)
		}
	}

	fgcc := creat(*objDir + "_cgo_export.c")
	fgcch := creat(*objDir + "_cgo_export.h")
	if *gccgo {
		p.writeGccgoExports(fgo2, fm, fgcc, fgcch)
	} else {
		p.writeExports(fgo2, fm, fgcc, fgcch)
	}

	if callsMalloc && !*gccgo {
		fmt.Fprint(fgo2, strings.Replace(cMallocDefGo, "PREFIX", cPrefix, -1))
		fmt.Fprint(fgcc, strings.Replace(strings.Replace(cMallocDefC, "PREFIX", cPrefix, -1), "PACKED", p.packedAttribute(), -1))
	}

	if err := fgcc.Close(); err != nil {
		fatalf("%s", err)
	}
	if err := fgcch.Close(); err != nil {
		fatalf("%s", err)
	}

	if *exportHeader != "" && len(p.ExpFunc) > 0 {
		fexp := creat(*exportHeader)
		fgcch, err := os.Open(*objDir + "_cgo_export.h")
		if err != nil {
			fatalf("%s", err)
		}
		defer fgcch.Close()
		_, err = io.Copy(fexp, fgcch)
		if err != nil {
			fatalf("%s", err)
		}
		if err = fexp.Close(); err != nil {
			fatalf("%s", err)
		}
	}

	init := gccgoInit.String()
	if init != "" {
		// The init function does nothing but simple
		// assignments, so it won't use much stack space, so
		// it's OK to not split the stack. Splitting the stack
		// can run into a bug in clang (as of 2018-11-09):
		// this is a leaf function, and when clang sees a leaf
		// function it won't emit the split stack prologue for
		// the function. However, if this function refers to a
		// non-split-stack function, which will happen if the
		// cgo code refers to a C function not compiled with
		// -fsplit-stack, then the linker will think that it
		// needs to adjust the split stack prologue, but there
		// won't be one. Marking the function explicitly
		// no_split_stack works around this problem by telling
		// the linker that it's OK if there is no split stack
		// prologue.
		fmt.Fprintln(fc, "static void init(void) __attribute__ ((constructor, no_split_stack));")
		fmt.Fprintln(fc, "static void init(void) {")
		fmt.Fprint(fc, init)
		fmt.Fprintln(fc, "}")
	}
}

// elfImportedSymbols is like elf.File.ImportedSymbols, but it
// includes weak symbols.
//
// A bug in some versions of LLD (at least LLD 8) cause it to emit
// several pthreads symbols as weak, but we need to import those. See
// issue #31912 or https://bugs.llvm.org/show_bug.cgi?id=42442.
//
// When doing external linking, we hand everything off to the external
// linker, which will create its own dynamic symbol tables. For
// internal linking, this may turn weak imports into strong imports,
// which could cause dynamic linking to fail if a symbol really isn't
// defined. However, the standard library depends on everything it
// imports, and this is the primary use of dynamic symbol tables with
// internal linking.
func elfImportedSymbols(f *elf.File) []elf.ImportedSymbol {
	syms, _ := f.DynamicSymbols()
	var imports []elf.ImportedSymbol
	for _, s := range syms {
		if (elf.ST_BIND(s.Info) == elf.STB_GLOBAL || elf.ST_BIND(s.Info) == elf.STB_WEAK) && s.Section == elf.SHN_UNDEF {
			imports = append(imports, elf.ImportedSymbol{
				Name:    s.Name,
				Library: s.Library,
				Version: s.Version,
			})
		}
	}
	return imports
}

func dynimport(obj string) {
	stdout := os.Stdout
	if *dynout != "" {
		f, err := os.Create(*dynout)
		if err != nil {
			fatalf("%s", err)
		}
		defer func() {
			if err = f.Close(); err != nil {
				fatalf("error closing %s: %v", *dynout, err)
			}
		}()

		stdout = f
	}

	fmt.Fprintf(stdout, "package %s\n", *dynpackage)

	if f, err := elf.Open(obj); err == nil {
		defer f.Close()
		if *dynlinker {
			// Emit the cgo_dynamic_linker line.
			if sec := f.Section(".interp"); sec != nil {
				if data, err := sec.Data(); err == nil && len(data) > 1 {
					// skip trailing \0 in data
					fmt.Fprintf(stdout, "//go:cgo_dynamic_linker %q\n", string(data[:len(data)-1]))
				}
			}
		}
		sym := elfImportedSymbols(f)
		for _, s := range sym {
			targ := s.Name
			if s.Version != "" {
				targ += "#" + s.Version
			}
			checkImportSymName(s.Name)
			checkImportSymName(targ)
			fmt.Fprintf(stdout, "//go:cgo_import_dynamic %s %s %q\n", s.Name, targ, s.Library)
		}
		lib, _ := f.ImportedLibraries()
		for _, l := range lib {
			fmt.Fprintf(stdout, "//go:cgo_import_dynamic _ _ %q\n", l)
		}
		return
	}

	if f, err := macho.Open(obj); err == nil {
		defer f.Close()
		sym, _ := f.ImportedSymbols()
		for _, s := range sym {
			s = strings.TrimPrefix(s, "_")
			checkImportSymName(s)
			fmt.Fprintf(stdout, "//go:cgo_import_dynamic %s %s %q\n", s, s, "")
		}
		lib, _ := f.ImportedLibraries()
		for _, l := range lib {
			fmt.Fprintf(stdout, "//go:cgo_import_dynamic _ _ %q\n", l)
		}
		return
	}

	if f, err := pe.Open(obj); err == nil {
		defer f.Close()
		sym, _ := f.ImportedSymbols()
		for _, s := range sym {
			ss := strings.Split(s, ":")
			name := strings.Split(ss[0], "@")[0]
			checkImportSymName(name)
			checkImportSymName(ss[0])
			fmt.Fprintf(stdout, "//go:cgo_import_dynamic %s %s %q\n", name, ss[0], strings.ToLower(ss[1]))
		}
		return
	}

	if f, err := xcoff.Open(obj); err == nil {
		defer f.Close()
		sym, err := f.ImportedSymbols()
		if err != nil {
			fatalf("cannot load imported symbols from XCOFF file %s: %v", obj, err)
		}
		for _, s := range sym {
			if s.Name == "runtime_rt0_go" || s.Name == "_rt0_ppc64_aix_lib" {
				// These symbols are imported by runtime/cgo but
				// must not be added to _cgo_import.go as there are
				// Go symbols.
				continue
			}
			checkImportSymName(s.Name)
			fmt.Fprintf(stdout, "//go:cgo_import_dynamic %s %s %q\n", s.Name, s.Name, s.Library)
		}
		lib, err := f.ImportedLibraries()
		if err != nil {
			fatalf("cannot load imported libraries from XCOFF file %s: %v", obj, err)
		}
		for _, l := range lib {
			fmt.Fprintf(stdout, "//go:cgo_import_dynamic _ _ %q\n", l)
		}
		return
	}

	fatalf("cannot parse %s as ELF, Mach-O, PE or XCOFF", obj)
}

// checkImportSymName checks a symbol name we are going to emit as part
// of a //go:cgo_import_dynamic pragma. These names come from object
// files, so they may be corrupt. We are going to emit them unquoted,
// so while they don't need to be valid symbol names (and in some cases,
// involving symbol versions, they won't be) they must contain only
// graphic characters and must not contain Go comments.
func checkImportSymName(s string) {
	for _, c := range s {
		if !unicode.IsGraphic(c) || unicode.IsSpace(c) {
			fatalf("dynamic symbol %q contains unsupported character", s)
		}
	}
	if strings.Contains(s, "//") || strings.Contains(s, "/*") {
		fatalf("dynamic symbol %q contains Go comment", s)
	}
}

// Construct a gcc struct matching the gc argument frame.
// Assumes that in gcc, char is 1 byte, short 2 bytes, int 4 bytes, long long 8 bytes.
// These assumptions are checked by the gccProlog.
// Also assumes that gc convention is to word-align the
// input and output parameters.
func (p *Package) structType(n *Name) (string, int64) {
	var buf strings.Builder
	fmt.Fprint(&buf, "struct {\n")
	off := int64(0)
	for i, t := range n.FuncType.Params {
		if off%t.Align != 0 {
			pad := t.Align - off%t.Align
			fmt.Fprintf(&buf, "\t\tchar __pad%d[%d];\n", off, pad)
			off += pad
		}
		c := t.Typedef
		if c == "" {
			c = t.C.String()
		}
		fmt.Fprintf(&buf, "\t\t%s p%d;\n", c, i)
		off += t.Size
	}
	if off%p.PtrSize != 0 {
		pad := p.PtrSize - off%p.PtrSize
		fmt.Fprintf(&buf, "\t\tchar __pad%d[%d];\n", off, pad)
		off += pad
	}
	if t := n.FuncType.Result; t != nil {
		if off%t.Align != 0 {
			pad := t.Align - off%t.Align
			fmt.Fprintf(&buf, "\t\tchar __pad%d[%d];\n", off, pad)
			off += pad
		}
		fmt.Fprintf(&buf, "\t\t%s r;\n", t.C)
		off += t.Size
	}
	if off%p.PtrSize != 0 {
		pad := p.PtrSize - off%p.PtrSize
		fmt.Fprintf(&buf, "\t\tchar __pad%d[%d];\n", off, pad)
		off += pad
	}
	if off == 0 {
		fmt.Fprintf(&buf, "\t\tchar unused;\n") // avoid empty struct
	}
	fmt.Fprintf(&buf, "\t}")
	return buf.String(), off
}

func (p *Package) writeDefsFunc(fgo2 io.Writer, n *Name, callsMalloc *bool) {
	name := n.Go
	gtype := n.FuncType.Go
	void := gtype.Results == nil || len(gtype.Results.List) == 0
	if n.AddError {
		// Add "error" to return type list.
		// Type list is known to be 0 or 1 element - it's a C function.
		err := &ast.Field{Type: ast.NewIdent("error")}
		l := gtype.Results.List
		if len(l) == 0 {
			l = []*ast.Field{err}
		} else {
			l = []*ast.Field{l[0], err}
		}
		t := new(ast.FuncType)
		*t = *gtype
		t.Results = &ast.FieldList{List: l}
		gtype = t
	}

	// Go func declaration.
	d := &ast.FuncDecl{
		Name: ast.NewIdent(n.Mangle),
		Type: gtype,
	}

	// Builtins defined in the C prolog.
	inProlog := builtinDefs[name] != ""
	cname := fmt.Sprintf("_cgo%s%s", cPrefix, n.Mangle)
	paramnames := []string(nil)
	if d.Type.Params != nil {
		for i, param := range d.Type.Params.List {
			paramName := fmt.Sprintf("p%d", i)
			param.Names = []*ast.Ident{ast.NewIdent(paramName)}
			paramnames = append(paramnames, paramName)
		}
	}

	if *gccgo {
		// Gccgo style hooks.
		fmt.Fprint(fgo2, "\n")
		conf.Fprint(fgo2, fset, d)
		fmt.Fprint(fgo2, " {\n")
		if !inProlog {
			fmt.Fprint(fgo2, "\tdefer syscall.CgocallDone()\n")
			fmt.Fprint(fgo2, "\tsyscall.Cgocall()\n")
		}
		if n.AddError {
			fmt.Fprint(fgo2, "\tsyscall.SetErrno(0)\n")
		}
		fmt.Fprint(fgo2, "\t")
		if !void {
			fmt.Fprint(fgo2, "r := ")
		}
		fmt.Fprintf(fgo2, "%s(%s)\n", cname, strings.Join(paramnames, ", "))

		if n.AddError {
			fmt.Fprint(fgo2, "\te := syscall.GetErrno()\n")
			fmt.Fprint(fgo2, "\tif e != 0 {\n")
			fmt.Fprint(fgo2, "\t\treturn ")
			if !void {
				fmt.Fprint(fgo2, "r, ")
			}
			fmt.Fprint(fgo2, "e\n")
			fmt.Fprint(fgo2, "\t}\n")
			fmt.Fprint(fgo2, "\treturn ")
			if !void {
				fmt.Fprint(fgo2, "r, ")
			}
			fmt.Fprint(fgo2, "nil\n")
		} else if !void {
			fmt.Fprint(fgo2, "\treturn r\n")
		}

		fmt.Fprint(fgo2, "}\n")

		// declare the C function.
		fmt.Fprintf(fgo2, "//extern %s\n", cname)
		d.Name = ast.NewIdent(cname)
		if n.AddError {
			l := d.Type.Results.List
			d.Type.Results.List = l[:len(l)-1]
		}
		conf.Fprint(fgo2, fset, d)
		fmt.Fprint(fgo2, "\n")

		return
	}

	if inProlog {
		fmt.Fprint(fgo2, builtinDefs[name])
		if strings.Contains(builtinDefs[name], "_cgo_cmalloc") {
			*callsMalloc = true
		}
		return
	}

	// Wrapper calls into gcc, passing a pointer to the argument frame.
	fmt.Fprintf(fgo2, "//go:cgo_import_static %s\n", cname)
	fmt.Fprintf(fgo2, "//go:linkname __cgofn_%s %s\n", cname, cname)
	fmt.Fprintf(fgo2, "var __cgofn_%s byte\n", cname)
	fmt.Fprintf(fgo2, "var %s = unsafe.Pointer(&__cgofn_%s)\n", cname, cname)

	nret := 0
	if !void {
		d.Type.Results.List[0].Names = []*ast.Ident{ast.NewIdent("r1")}
		nret = 1
	}
	if n.AddError {
		d.Type.Results.List[nret].Names = []*ast.Ident{ast.NewIdent("r2")}
	}

	fmt.Fprint(fgo2, "\n")
	fmt.Fprint(fgo2, "//go:cgo_unsafe_args\n")
	conf.Fprint(fgo2, fset, d)
	fmt.Fprint(fgo2, " {\n")

	// NOTE: Using uintptr to hide from escape analysis.
	arg := "0"
	if len(paramnames) > 0 {
		arg = "uintptr(unsafe.Pointer(&p0))"
	} else if !void {
		arg = "uintptr(unsafe.Pointer(&r1))"
	}

	noCallback := p.noCallbacks[n.C]
	if noCallback {
		// disable cgocallback, will check it in runtime.
		fmt.Fprintf(fgo2, "\t_Cgo_no_callback(true)\n")
	}

	prefix := ""
	if n.AddError {
		prefix = "errno := "
	}
	fmt.Fprintf(fgo2, "\t%s_cgo_runtime_cgocall(%s, %s)\n", prefix, cname, arg)
	if n.AddError {
		fmt.Fprintf(fgo2, "\tif errno != 0 { r2 = syscall.Errno(errno) }\n")
	}
	if noCallback {
		fmt.Fprintf(fgo2, "\t_Cgo_no_callback(false)\n")
	}

	// Use _Cgo_keepalive instead of _Cgo_use when noescape & nocallback exist,
	// so that the compiler won't force to escape them to heap.
	// Instead, make the compiler keep them alive by using _Cgo_keepalive.
	touchFunc := "_Cgo_use"
	if p.noEscapes[n.C] && p.noCallbacks[n.C] {
		touchFunc = "_Cgo_keepalive"
	}
	fmt.Fprintf(fgo2, "\tif _Cgo_always_false {\n")
	if d.Type.Params != nil {
		for _, name := range paramnames {
			fmt.Fprintf(fgo2, "\t\t%s(%s)\n", touchFunc, name)
		}
	}
	fmt.Fprintf(fgo2, "\t}\n")
	fmt.Fprintf(fgo2, "\treturn\n")
	fmt.Fprintf(fgo2, "}\n")
}

// writeOutput creates stubs for a specific source file to be compiled by gc
func (p *Package) writeOutput(f *File, srcfile string) {
	base := srcfile
	base = strings.TrimSuffix(base, ".go")
	base = filepath.Base(base)
	fgo1 := creat(*objDir + base + ".cgo1.go")
	fgcc := creat(*objDir + base + ".cgo2.c")

	p.GoFiles = append(p.GoFiles, base+".cgo1.go")
	p.GccFiles = append(p.GccFiles, base+".cgo2.c")

	// Write Go output: Go input with rewrites of C.xxx to _C_xxx.
	fmt.Fprintf(fgo1, "// Code generated by cmd/cgo; DO NOT EDIT.\n\n")
	if strings.ContainsAny(srcfile, "\r\n") {
		// This should have been checked when the file path was first resolved,
		// but we double check here just to be sure.
		fatalf("internal error: writeOutput: srcfile contains unexpected newline character: %q", srcfile)
	}
	fmt.Fprintf(fgo1, "//line %s:1:1\n", srcfile)
	fgo1.Write(f.Edit.Bytes())

	// While we process the vars and funcs, also write gcc output.
	// Gcc output starts with the preamble.
	fmt.Fprintf(fgcc, "%s\n", builtinProlog)
	fmt.Fprintf(fgcc, "%s\n", f.Preamble)
	fmt.Fprintf(fgcc, "%s\n", gccProlog)
	fmt.Fprintf(fgcc, "%s\n", tsanProlog)
	fmt.Fprintf(fgcc, "%s\n", msanProlog)

	for _, key := range nameKeys(f.Name) {
		n := f.Name[key]
		if n.FuncType != nil {
			p.writeOutputFunc(fgcc, n)
		}
	}

	fgo1.Close()
	fgcc.Close()
}

// fixGo converts the internal Name.Go field into the name we should show
// to users in error messages. There's only one for now: on input we rewrite
// C.malloc into C._CMalloc, so change it back here.
func fixGo(name string) string {
	if name == "_CMalloc" {
		return "malloc"
	}
	return name
}

var isBuiltin = map[string]bool{
	"_Cfunc_CString":   true,
	"_Cfunc_CBytes":    true,
	"_Cfunc_GoString":  true,
	"_Cfunc_GoStringN": true,
	"_Cfunc_GoBytes":   true,
	"_Cfunc__CMalloc":  true,
}

func (p *Package) writeOutputFunc(fgcc *os.File, n *Name) {
	name := n.Mangle
	if isBuiltin[name] || p.Written[name] {
		// The builtins are already defined in the C prolog, and we don't
		// want to duplicate function definitions we've already done.
		return
	}
	p.Written[name] = true

	if *gccgo {
		p.writeGccgoOutputFunc(fgcc, n)
		return
	}

	ctype, _ := p.structType(n)

	// Gcc wrapper unpacks the C argument struct
	// and calls the actual C function.
	fmt.Fprintf(fgcc, "CGO_NO_SANITIZE_THREAD\n")
	if n.AddError {
		fmt.Fprintf(fgcc, "int\n")
	} else {
		fmt.Fprintf(fgcc, "void\n")
	}
	fmt.Fprintf(fgcc, "_cgo%s%s(void *v)\n", cPrefix, n.Mangle)
	fmt.Fprintf(fgcc, "{\n")
	if n.AddError {
		fmt.Fprintf(fgcc, "\tint _cgo_errno;\n")
	}
	// We're trying to write a gcc struct that matches gc's layout.
	// Use packed attribute to force no padding in this struct in case
	// gcc has different packing requirements.
	fmt.Fprintf(fgcc, "\t%s %v *_cgo_a = v;\n", ctype, p.packedAttribute())
	if n.FuncType.Result != nil {
		// Save the stack top for use below.
		fmt.Fprintf(fgcc, "\tchar *_cgo_stktop = _cgo_topofstack();\n")
	}
	tr := n.FuncType.Result
	if tr != nil {
		fmt.Fprintf(fgcc, "\t__typeof__(_cgo_a->r) _cgo_r;\n")
	}
	fmt.Fprintf(fgcc, "\t_cgo_tsan_acquire();\n")
	if n.AddError {
		fmt.Fprintf(fgcc, "\terrno = 0;\n")
	}
	fmt.Fprintf(fgcc, "\t")
	if tr != nil {
		fmt.Fprintf(fgcc, "_cgo_r = ")
		if c := tr.C.String(); c[len(c)-1] == '*' {
			fmt.Fprint(fgcc, "(__typeof__(_cgo_a->r)) ")
		}
	}
	if n.Kind == "macro" {
		fmt.Fprintf(fgcc, "%s;\n", n.C)
	} else {
		fmt.Fprintf(fgcc, "%s(", n.C)
		for i := range n.FuncType.Params {
			if i > 0 {
				fmt.Fprintf(fgcc, ", ")
			}
			fmt.Fprintf(fgcc, "_cgo_a->p%d", i)
		}
		fmt.Fprintf(fgcc, ");\n")
	}
	if n.AddError {
		fmt.Fprintf(fgcc, "\t_cgo_errno = errno;\n")
	}
	fmt.Fprintf(fgcc, "\t_cgo_tsan_release();\n")
	if n.FuncType.Result != nil {
		// The cgo call may have caused a stack copy (via a callback).
		// Adjust the return value pointer appropriately.
		fmt.Fprintf(fgcc, "\t_cgo_a = (void*)((char*)_cgo_a + (_cgo_topofstack() - _cgo_stktop));\n")
		// Save the return value.
		fmt.Fprintf(fgcc, "\t_cgo_a->r = _cgo_r;\n")
		// The return value is on the Go stack. If we are using msan,
		// and if the C value is partially or completely uninitialized,
		// the assignment will mark the Go stack as uninitialized.
		// The Go compiler does not update msan for changes to the
		// stack. It is possible that the stack will remain
		// uninitialized, and then later be used in a way that is
		// visible to msan, possibly leading to a false positive.
		// Mark the stack space as written, to avoid this problem.
		// See issue 26209.
		fmt.Fprintf(fgcc, "\t_cgo_msan_write(&_cgo_a->r, sizeof(_cgo_a->r));\n")
	}
	if n.AddError {
		fmt.Fprintf(fgcc, "\treturn _cgo_errno;\n")
	}
	fmt.Fprintf(fgcc, "}\n")
	fmt.Fprintf(fgcc, "\n")
}

// Write out a wrapper for a function when using gccgo. This is a
// simple wrapper that just calls the real function. We only need a
// wrapper to support static functions in the prologue--without a
// wrapper, we can't refer to the function, since the reference is in
// a different file.
func (p *Package) writeGccgoOutputFunc(fgcc *os.File, n *Name) {
	fmt.Fprintf(fgcc, "CGO_NO_SANITIZE_THREAD\n")
	if t := n.FuncType.Result; t != nil {
		fmt.Fprintf(fgcc, "%s\n", t.C.String())
	} else {
		fmt.Fprintf(fgcc, "void\n")
	}
	fmt.Fprintf(fgcc, "_cgo%s%s(", cPrefix, n.Mangle)
	for i, t := range n.FuncType.Params {
		if i > 0 {
			fmt.Fprintf(fgcc, ", ")
		}
		c := t.Typedef
		if c == "" {
			c = t.C.String()
		}
		fmt.Fprintf(fgcc, "%s p%d", c, i)
	}
	fmt.Fprintf(fgcc, ")\n")
	fmt.Fprintf(fgcc, "{\n")
	if t := n.FuncType.Result; t != nil {
		fmt.Fprintf(fgcc, "\t%s _cgo_r;\n", t.C.String())
	}
	fmt.Fprintf(fgcc, "\t_cgo_tsan_acquire();\n")
	fmt.Fprintf(fgcc, "\t")
	if t := n.FuncType.Result; t != nil {
		fmt.Fprintf(fgcc, "_cgo_r = ")
		// Cast to void* to avoid warnings due to omitted qualifiers.
		if c := t.C.String(); c[len(c)-1] == '*' {
			fmt.Fprintf(fgcc, "(void*)")
		}
	}
	if n.Kind == "macro" {
		fmt.Fprintf(fgcc, "%s;\n", n.C)
	} else {
		fmt.Fprintf(fgcc, "%s(", n.C)
		for i := range n.FuncType.Params {
			if i > 0 {
				fmt.Fprintf(fgcc, ", ")
			}
			fmt.Fprintf(fgcc, "p%d", i)
		}
		fmt.Fprintf(fgcc, ");\n")
	}
	fmt.Fprintf(fgcc, "\t_cgo_tsan_release();\n")
	if t := n.FuncType.Result; t != nil {
		fmt.Fprintf(fgcc, "\treturn ")
		// Cast to void* to avoid warnings due to omitted qualifiers
		// and explicit incompatible struct types.
		if c := t.C.String(); c[len(c)-1] == '*' {
			fmt.Fprintf(fgcc, "(void*)")
		}
		fmt.Fprintf(fgcc, "_cgo_r;\n")
	}
	fmt.Fprintf(fgcc, "}\n")
	fmt.Fprintf(fgcc, "\n")
}

// packedAttribute returns host compiler struct attribute that will be
// used to match gc's struct layout. For example, on 386 Windows,
// gcc wants to 8-align int64s, but gc does not.
// Use __gcc_struct__ to work around https://gcc.gnu.org/PR52991 on x86,
// and https://golang.org/issue/5603.
func (p *Package) packedAttribute() string {
	s := "__attribute__((__packed__"
	if !p.GccIsClang && (goarch == "amd64" || goarch == "386") {
		s += ", __gcc_struct__"
	}
	return s + "))"
}

// exportParamName returns the value of param as it should be
// displayed in a c header file. If param contains any non-ASCII
// characters, this function will return the character p followed by
// the value of position; otherwise, this function will return the
// value of param.
func exportParamName(param string, position int) string {
	if param == "" {
		return fmt.Sprintf("p%d", position)
	}

	pname := param

	for i := 0; i < len(param); i++ {
		if param[i] > unicode.MaxASCII {
			pname = fmt.Sprintf("p%d", position)
			break
		}
	}

	return pname
}

// Write out the various stubs we need to support functions exported
// from Go so that they are callable from C.
func (p *Package) writeExports(fgo2, fm, fgcc, fgcch io.Writer) {
	p.writeExportHeader(fgcch)

	fmt.Fprintf(fgcc, "/* Code generated by cmd/cgo; DO NOT EDIT. */\n\n")
	fmt.Fprintf(fgcc, "#include <stdlib.h>\n")
	fmt.Fprintf(fgcc, "#include \"_cgo_export.h\"\n\n")

	// We use packed structs, but they are always aligned.
	// The pragmas and address-of-packed-member are only recognized as
	// warning groups in clang 4.0+, so ignore unknown pragmas first.
	fmt.Fprintf(fgcc, "#pragma GCC diagnostic ignored \"-Wunknown-pragmas\"\n")
	fmt.Fprintf(fgcc, "#pragma GCC diagnostic ignored \"-Wpragmas\"\n")
	fmt.Fprintf(fgcc, "#pragma GCC diagnostic ignored \"-Waddress-of-packed-member\"\n")
	fmt.Fprintf(fgcc, "#pragma GCC diagnostic ignored \"-Wunknown-warning-option\"\n")
	fmt.Fprintf(fgcc, "#pragma GCC diagnostic ignored \"-Wunaligned-access\"\n")

	fmt.Fprintf(fgcc, "extern void crosscall2(void (*fn)(void *), void *, int, size_t);\n")
	fmt.Fprintf(fgcc, "extern size_t _cgo_wait_runtime_init_done(void);\n")
	fmt.Fprintf(fgcc, "extern void _cgo_release_context(size_t);\n\n")
	fmt.Fprintf(fgcc, "extern char* _cgo_topofstack(void);")
	fmt.Fprintf(fgcc, "%s\n", tsanProlog)
	fmt.Fprintf(fgcc, "%s\n", msanProlog)

	for _, exp := range p.ExpFunc {
		fn := exp.Func

		// Construct a struct that will be used to communicate
		// arguments from C to Go. The C and Go definitions
		// just have to agree. The gcc struct will be compiled
		// with __attribute__((packed)) so all padding must be
		// accounted for explicitly.
		ctype := "struct {\n"
		gotype := new(bytes.Buffer)
		fmt.Fprintf(gotype, "struct {\n")
		off := int64(0)
		npad := 0
		argField := func(typ ast.Expr, namePat string, args ...interface{}) {
			name := fmt.Sprintf(namePat, args...)
			t := p.cgoType(typ)
			if off%t.Align != 0 {
				pad := t.Align - off%t.Align
				ctype += fmt.Sprintf("\t\tchar __pad%d[%d];\n", npad, pad)
				off += pad
				npad++
			}
			ctype += fmt.Sprintf("\t\t%s %s;\n", t.C, name)
			fmt.Fprintf(gotype, "\t\t%s ", name)
			noSourceConf.Fprint(gotype, fset, typ)
			fmt.Fprintf(gotype, "\n")
			off += t.Size
		}
		if fn.Recv != nil {
			argField(fn.Recv.List[0].Type, "recv")
		}
		fntype := fn.Type
		forFieldList(fntype.Params,
			func(i int, aname string, atype ast.Expr) {
				argField(atype, "p%d", i)
			})
		forFieldList(fntype.Results,
			func(i int, aname string, atype ast.Expr) {
				argField(atype, "r%d", i)
			})
		if ctype == "struct {\n" {
			ctype += "\t\tchar unused;\n" // avoid empty struct
		}
		ctype += "\t}"
		fmt.Fprintf(gotype, "\t}")

		// Get the return type of the wrapper function
		// compiled by gcc.
		gccResult := ""
		if fntype.Results == nil || len(fntype.Results.List) == 0 {
			gccResult = "void"
		} else if len(fntype.Results.List) == 1 && len(fntype.Results.List[0].Names) <= 1 {
			gccResult = p.cgoType(fntype.Results.List[0].Type).C.String()
		} else {
			fmt.Fprintf(fgcch, "\n/* Return type for %s */\n", exp.ExpName)
			fmt.Fprintf(fgcch, "struct %s_return {\n", exp.ExpName)
			forFieldList(fntype.Results,
				func(i int, aname string, atype ast.Expr) {
					fmt.Fprintf(fgcch, "\t%s r%d;", p.cgoType(atype).C, i)
					if len(aname) > 0 {
						fmt.Fprintf(fgcch, " /* %s */", aname)
					}
					fmt.Fprint(fgcch, "\n")
				})
			fmt.Fprintf(fgcch, "};\n")
			gccResult = "struct " + exp.ExpName + "_return"
		}

		// Build the wrapper function compiled by gcc.
		gccExport := ""
		if goos == "windows" {
			gccExport = "__declspec(dllexport) "
		}
		s := fmt.Sprintf("%s%s %s(", gccExport, gccResult, exp.ExpName)
		if fn.Recv != nil {
			s += p.cgoType(fn.Recv.List[0].Type).C.String()
			s += " recv"
		}
		forFieldList(fntype.Params,
			func(i int, aname string, atype ast.Expr) {
				if i > 0 || fn.Recv != nil {
					s += ", "
				}
				s += fmt.Sprintf("%s %s", p.cgoType(atype).C, exportParamName(aname, i))
			})
		s += ")"

		if len(exp.Doc) > 0 {
			fmt.Fprintf(fgcch, "\n%s", exp.Doc)
			if !strings.HasSuffix(exp.Doc, "\n") {
				fmt.Fprint(fgcch, "\n")
			}
		}
		fmt.Fprintf(fgcch, "extern %s;\n", s)

		fmt.Fprintf(fgcc, "extern void _cgoexp%s_%s(void *);\n", cPrefix, exp.ExpName)
		fmt.Fprintf(fgcc, "\nCGO_NO_SANITIZE_THREAD")
		fmt.Fprintf(fgcc, "\n%s\n", s)
		fmt.Fprintf(fgcc, "{\n")
		fmt.Fprintf(fgcc, "\tsize_t _cgo_ctxt = _cgo_wait_runtime_init_done();\n")
		// The results part of the argument structure must be
		// initialized to 0 so the write barriers generated by
		// the assignments to these fields in Go are safe.
		//
		// We use a local static variable to get the zeroed
		// value of the argument type. This avoids including
		// string.h for memset, and is also robust to C++
		// types with constructors. Both GCC and LLVM optimize
		// this into just zeroing _cgo_a.
		fmt.Fprintf(fgcc, "\ttypedef %s %v _cgo_argtype;\n", ctype, p.packedAttribute())
		fmt.Fprintf(fgcc, "\tstatic _cgo_argtype _cgo_zero;\n")
		fmt.Fprintf(fgcc, "\t_cgo_argtype _cgo_a = _cgo_zero;\n")
		if gccResult != "void" && (len(fntype.Results.List) > 1 || len(fntype.Results.List[0].Names) > 1) {
			fmt.Fprintf(fgcc, "\t%s r;\n", gccResult)
		}
		if fn.Recv != nil {
			fmt.Fprintf(fgcc, "\t_cgo_a.recv = recv;\n")
		}
		forFieldList(fntype.Params,
			func(i int, aname string, atype ast.Expr) {
				fmt.Fprintf(fgcc, "\t_cgo_a.p%d = %s;\n", i, exportParamName(aname, i))
			})
		fmt.Fprintf(fgcc, "\t_cgo_tsan_release();\n")
		fmt.Fprintf(fgcc, "\tcrosscall2(_cgoexp%s_%s, &_cgo_a, %d, _cgo_ctxt);\n", cPrefix, exp.ExpName, off)
		fmt.Fprintf(fgcc, "\t_cgo_tsan_acquire();\n")
		fmt.Fprintf(fgcc, "\t_cgo_release_context(_cgo_ctxt);\n")
		if gccResult != "void" {
			if len(fntype.Results.List) == 1 && len(fntype.Results.List[0].Names) <= 1 {
				fmt.Fprintf(fgcc, "\treturn _cgo_a.r0;\n")
			} else {
				forFieldList(fntype.Results,
					func(i int, aname string, atype ast.Expr) {
						fmt.Fprintf(fgcc, "\tr.r%d = _cgo_a.r%d;\n", i, i)
					})
				fmt.Fprintf(fgcc, "\treturn r;\n")
			}
		}
		fmt.Fprintf(fgcc, "}\n")

		// In internal linking mode, the Go linker sees both
		// the C wrapper written above and the Go wrapper it
		// references. Hence, export the C wrapper (e.g., for
		// if we're building a shared object). The Go linker
		// will resolve the C wrapper's reference to the Go
		// wrapper without a separate export.
		fmt.Fprintf(fgo2, "//go:cgo_export_dynamic %s\n", exp.ExpName)
		// cgo_export_static refers to a symbol by its linker
		// name, so set the linker name of the Go wrapper.
		fmt.Fprintf(fgo2, "//go:linkname _cgoexp%s_%s _cgoexp%s_%s\n", cPrefix, exp.ExpName, cPrefix, exp.ExpName)
		// In external linking mode, the Go linker sees the Go
		// wrapper, but not the C wrapper. For this case,
		// export the Go wrapper so the host linker can
		// resolve the reference from the C wrapper to the Go
		// wrapper.
		fmt.Fprintf(fgo2, "//go:cgo_export_static _cgoexp%s_%s\n", cPrefix, exp.ExpName)

		// Build the wrapper function compiled by cmd/compile.
		// This unpacks the argument struct above and calls the Go function.
		fmt.Fprintf(fgo2, "func _cgoexp%s_%s(a *%s) {\n", cPrefix, exp.ExpName, gotype)

		fmt.Fprintf(fm, "void _cgoexp%s_%s(void* p){}\n", cPrefix, exp.ExpName)

		fmt.Fprintf(fgo2, "\t")

		if gccResult != "void" {
			// Write results back to frame.
			forFieldList(fntype.Results,
				func(i int, aname string, atype ast.Expr) {
					if i > 0 {
						fmt.Fprintf(fgo2, ", ")
					}
					fmt.Fprintf(fgo2, "a.r%d", i)
				})
			fmt.Fprintf(fgo2, " = ")
		}
		if fn.Recv != nil {
			fmt.Fprintf(fgo2, "a.recv.")
		}
		fmt.Fprintf(fgo2, "%s(", exp.Func.Name)
		forFieldList(fntype.Params,
			func(i int, aname string, atype ast.Expr) {
				if i > 0 {
					fmt.Fprint(fgo2, ", ")
				}
				fmt.Fprintf(fgo2, "a.p%d", i)
			})
		fmt.Fprint(fgo2, ")\n")
		if gccResult != "void" {
			// Verify that any results don't contain any
			// Go pointers.
			forFieldList(fntype.Results,
				func(i int, aname string, atype ast.Expr) {
					if !p.hasPointer(nil, atype, false) {
						return
					}
					fmt.Fprintf(fgo2, "\t_cgoCheckResult(a.r%d)\n", i)
				})
		}
		fmt.Fprint(fgo2, "}\n")
	}

	fmt.Fprintf(fgcch, "%s", gccExportHeaderEpilog)
}

// Write out the C header allowing C code to call exported gccgo functions.
func (p *Package) writeGccgoExports(fgo2, fm, fgcc, fgcch io.Writer) {
	gccgoSymbolPrefix := p.gccgoSymbolPrefix()

	p.writeExportHeader(fgcch)

	fmt.Fprintf(fgcc, "/* Code generated by cmd/cgo; DO NOT EDIT. */\n\n")
	fmt.Fprintf(fgcc, "#include \"_cgo_export.h\"\n")

	fmt.Fprintf(fgcc, "%s\n", gccgoExportFileProlog)
	fmt.Fprintf(fgcc, "%s\n", tsanProlog)
	fmt.Fprintf(fgcc, "%s\n", msanProlog)

	for _, exp := range p.ExpFunc {
		fn := exp.Func
		fntype := fn.Type

		cdeclBuf := new(strings.Builder)
		resultCount := 0
		forFieldList(fntype.Results,
			func(i int, aname string, atype ast.Expr) { resultCount++ })
		switch resultCount {
		case 0:
			fmt.Fprintf(cdeclBuf, "void")
		case 1:
			forFieldList(fntype.Results,
				func(i int, aname string, atype ast.Expr) {
					t := p.cgoType(atype)
					fmt.Fprintf(cdeclBuf, "%s", t.C)
				})
		default:
			// Declare a result struct.
			fmt.Fprintf(fgcch, "\n/* Return type for %s */\n", exp.ExpName)
			fmt.Fprintf(fgcch, "struct %s_return {\n", exp.ExpName)
			forFieldList(fntype.Results,
				func(i int, aname string, atype ast.Expr) {
					t := p.cgoType(atype)
					fmt.Fprintf(fgcch, "\t%s r%d;", t.C, i)
					if len(aname) > 0 {
						fmt.Fprintf(fgcch, " /* %s */", aname)
					}
					fmt.Fprint(fgcch, "\n")
				})
			fmt.Fprintf(fgcch, "};\n")
			fmt.Fprintf(cdeclBuf, "struct %s_return", exp.ExpName)
		}

		cRet := cdeclBuf.String()

		cdeclBuf = new(strings.Builder)
		fmt.Fprintf(cdeclBuf, "(")
		if fn.Recv != nil {
			fmt.Fprintf(cdeclBuf, "%s recv", p.cgoType(fn.Recv.List[0].Type).C.String())
		}
		// Function parameters.
		forFieldList(fntype.Params,
			func(i int, aname string, atype ast.Expr) {
				if i > 0 || fn.Recv != nil {
					fmt.Fprintf(cdeclBuf, ", ")
				}
				t := p.cgoType(atype)
				fmt.Fprintf(cdeclBuf, "%s p%d", t.C, i)
			})
		fmt.Fprintf(cdeclBuf, ")")
		cParams := cdeclBuf.String()

		if len(exp.Doc) > 0 {
			fmt.Fprintf(fgcch, "\n%s", exp.Doc)
		}

		fmt.Fprintf(fgcch, "extern %s %s%s;\n", cRet, exp.ExpName, cParams)

		// We need to use a name that will be exported by the
		// Go code; otherwise gccgo will make it static and we
		// will not be able to link against it from the C
		// code.
		goName := "Cgoexp_" + exp.ExpName
		fmt.Fprintf(fgcc, `extern %s %s %s __asm__("%s.%s");`, cRet, goName, cParams, gccgoSymbolPrefix, gccgoToSymbol(goName))
		fmt.Fprint(fgcc, "\n")

		fmt.Fprint(fgcc, "\nCGO_NO_SANITIZE_THREAD\n")
		fmt.Fprintf(fgcc, "%s %s %s {\n", cRet, exp.ExpName, cParams)
		if resultCount > 0 {
			fmt.Fprintf(fgcc, "\t%s r;\n", cRet)
		}
		fmt.Fprintf(fgcc, "\tif(_cgo_wait_runtime_init_done)\n")
		fmt.Fprintf(fgcc, "\t\t_cgo_wait_runtime_init_done();\n")
		fmt.Fprintf(fgcc, "\t_cgo_tsan_release();\n")
		fmt.Fprint(fgcc, "\t")
		if resultCount > 0 {
			fmt.Fprint(fgcc, "r = ")
		}
		fmt.Fprintf(fgcc, "%s(", goName)
		if fn.Recv != nil {
			fmt.Fprint(fgcc, "recv")
		}
		forFieldList(fntype.Params,
			func(i int, aname string, atype ast.Expr) {
				if i > 0 || fn.Recv != nil {
					fmt.Fprintf(fgcc, ", ")
				}
				fmt.Fprintf(fgcc, "p%d", i)
			})
		fmt.Fprint(fgcc, ");\n")
		fmt.Fprintf(fgcc, "\t_cgo_tsan_acquire();\n")
		if resultCount > 0 {
			fmt.Fprint(fgcc, "\treturn r;\n")
		}
		fmt.Fprint(fgcc, "}\n")

		// Dummy declaration for _cgo_main.c
		fmt.Fprintf(fm, `char %s[1] __asm__("%s.%s");`, goName, gccgoSymbolPrefix, gccgoToSymbol(goName))
		fmt.Fprint(fm, "\n")

		// For gccgo we use a wrapper function in Go, in order
		// to call CgocallBack and CgocallBackDone.

		// This code uses printer.Fprint, not conf.Fprint,
		// because we don't want //line comments in the middle
		// of the function types.
		fmt.Fprint(fgo2, "\n")
		fmt.Fprintf(fgo2, "func %s(", goName)
		if fn.Recv != nil {
			fmt.Fprint(fgo2, "recv ")
			printer.Fprint(fgo2, fset, fn.Recv.List[0].Type)
		}
		forFieldList(fntype.Params,
			func(i int, aname string, atype ast.Expr) {
				if i > 0 || fn.Recv != nil {
					fmt.Fprintf(fgo2, ", ")
				}
				fmt.Fprintf(fgo2, "p%d ", i)
				printer.Fprint(fgo2, fset, atype)
			})
		fmt.Fprintf(fgo2, ")")
		if resultCount > 0 {
			fmt.Fprintf(fgo2, " (")
			forFieldList(fntype.Results,
				func(i int, aname string, atype ast.Expr) {
					if i > 0 {
						fmt.Fprint(fgo2, ", ")
					}
					printer.Fprint(fgo2, fset, atype)
				})
			fmt.Fprint(fgo2, ")")
		}
		fmt.Fprint(fgo2, " {\n")
		fmt.Fprint(fgo2, "\tsyscall.CgocallBack()\n")
		fmt.Fprint(fgo2, "\tdefer syscall.CgocallBackDone()\n")
		fmt.Fprint(fgo2, "\t")
		if resultCount > 0 {
			fmt.Fprint(fgo2, "return ")
		}
		if fn.Recv != nil {
			fmt.Fprint(fgo2, "recv.")
		}
		fmt.Fprintf(fgo2, "%s(", exp.Func.Name)
		forFieldList(fntype.Params,
			func(i int, aname string, atype ast.Expr) {
				if i > 0 {
					fmt.Fprint(fgo2, ", ")
				}
				fmt.Fprintf(fgo2, "p%d", i)
			})
		fmt.Fprint(fgo2, ")\n")
		fmt.Fprint(fgo2, "}\n")
	}

	fmt.Fprintf(fgcch, "%s", gccExportHeaderEpilog)
}

// writeExportHeader writes out the start of the _cgo_export.h file.
func (p *Package) writeExportHeader(fgcch io.Writer) {
	fmt.Fprintf(fgcch, "/* Code generated by cmd/cgo; DO NOT EDIT. */\n\n")
	pkg := *importPath
	if pkg == "" {
		pkg = p.PackagePath
	}
	fmt.Fprintf(fgcch, "/* package %s */\n\n", pkg)
	fmt.Fprintf(fgcch, "%s\n", builtinExportProlog)

	// Remove absolute paths from #line comments in the preamble.
	// They aren't useful for people using the header file,
	// and they mean that the header files change based on the
	// exact location of GOPATH.
	re := regexp.MustCompile(`(?m)^(#line\s+\d+\s+")[^"]*[/\\]([^"]*")`)
	preamble := re.ReplaceAllString(p.Preamble, "$1$2")

	fmt.Fprintf(fgcch, "/* Start of preamble from import \"C\" comments.  */\n\n")
	fmt.Fprintf(fgcch, "%s\n", preamble)
	fmt.Fprintf(fgcch, "\n/* End of preamble from import \"C\" comments.  */\n\n")

	fmt.Fprintf(fgcch, "%s\n", p.gccExportHeaderProlog())
}

// gccgoToSymbol converts a name to a mangled symbol for gccgo.
func gccgoToSymbol(ppath string) string {
	if gccgoMangler == nil {
		var err error
		cmd := os.Getenv("GCCGO")
		if cmd == "" {
			cmd, err = exec.LookPath("gccgo")
			if err != nil {
				fatalf("unable to locate gccgo: %v", err)
			}
		}
		gccgoMangler, err = pkgpath.ToSymbolFunc(cmd, *objDir)
		if err != nil {
			fatalf("%v", err)
		}
	}
	return gccgoMangler(ppath)
}

// Return the package prefix when using gccgo.
func (p *Package) gccgoSymbolPrefix() string {
	if !*gccgo {
		return ""
	}

	if *gccgopkgpath != "" {
		return gccgoToSymbol(*gccgopkgpath)
	}
	if *gccgoprefix == "" && p.PackageName == "main" {
		return "main"
	}
	prefix := gccgoToSymbol(*gccgoprefix)
	if prefix == "" {
		prefix = "go"
	}
	return prefix + "." + p.PackageName
}

// Call a function for each entry in an ast.FieldList, passing the
// index into the list, the name if any, and the type.
func forFieldList(fl *ast.FieldList, fn func(int, string, ast.Expr)) {
	if fl == nil {
		return
	}
	i := 0
	for _, r := range fl.List {
		if r.Names == nil {
			fn(i, "", r.Type)
			i++
		} else {
			for _, n := range r.Names {
				fn(i, n.Name, r.Type)
				i++
			}
		}
	}
}

func c(repr string, args ...interface{}) *TypeRepr {
	return &TypeRepr{repr, args}
}

// Map predeclared Go types to Type.
var goTypes = map[string]*Type{
	"bool":       {Size: 1, Align: 1, C: c("GoUint8")},
	"byte":       {Size: 1, Align: 1, C: c("GoUint8")},
	"int":        {Size: 0, Align: 0, C: c("GoInt")},
	"uint":       {Size: 0, Align: 0, C: c("GoUint")},
	"rune":       {Size: 4, Align: 4, C: c("GoInt32")},
	"int8":       {Size: 1, Align: 1, C: c("GoInt8")},
	"uint8":      {Size: 1, Align: 1, C: c("GoUint8")},
	"int16":      {Size: 2, Align: 2, C: c("GoInt16")},
	"uint16":     {Size: 2, Align: 2, C: c("GoUint16")},
	"int32":      {Size: 4, Align: 4, C: c("GoInt32")},
	"uint32":     {Size: 4, Align: 4, C: c("GoUint32")},
	"int64":      {Size: 8, Align: 8, C: c("GoInt64")},
	"uint64":     {Size: 8, Align: 8, C: c("GoUint64")},
	"float32":    {Size: 4, Align: 4, C: c("GoFloat32")},
	"float64":    {Size: 8, Align: 8, C: c("GoFloat64")},
	"complex64":  {Size: 8, Align: 4, C: c("GoComplex64")},
	"complex128": {Size: 16, Align: 8, C: c("GoComplex128")},
}

// Map an ast type to a Type.
func (p *Package) cgoType(e ast.Expr) *Type {
	return p.doCgoType(e, make(map[ast.Expr]bool))
}

// Map an ast type to a Type, avoiding cycles.
func (p *Package) doCgoType(e ast.Expr, m map[ast.Expr]bool) *Type {
	if m[e] {
		fatalf("%s: invalid recursive type", fset.Position(e.Pos()))
	}
	m[e] = true
	switch t := e.(type) {
	case *ast.StarExpr:
		x := p.doCgoType(t.X, m)
		return &Type{Size: p.PtrSize, Align: p.PtrSize, C: c("%s*", x.C)}
	case *ast.ArrayType:
		if t.Len == nil {
			// Slice: pointer, len, cap.
			return &Type{Size: p.PtrSize * 3, Align: p.PtrSize, C: c("GoSlice")}
		}
		// Non-slice array types are not supported.
	case *ast.StructType:
		// Not supported.
	case *ast.FuncType:
		return &Type{Size: p.PtrSize, Align: p.PtrSize, C: c("void*")}
	case *ast.InterfaceType:
		return &Type{Size: 2 * p.PtrSize, Align: p.PtrSize, C: c("GoInterface")}
	case *ast.MapType:
		return &Type{Size: p.PtrSize, Align: p.PtrSize, C: c("GoMap")}
	case *ast.ChanType:
		return &Type{Size: p.PtrSize, Align: p.PtrSize, C: c("GoChan")}
	case *ast.Ident:
		goTypesFixup := func(r *Type) *Type {
			if r.Size == 0 { // int or uint
				rr := new(Type)
				*rr = *r
				rr.Size = p.IntSize
				rr.Align = p.IntSize
				r = rr
			}
			if r.Align > p.PtrSize {
				r.Align = p.PtrSize
			}
			return r
		}
		// Look up the type in the top level declarations.
		// TODO: Handle types defined within a function.
		for _, d := range p.Decl {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				if ts.Name.Name == t.Name {
					// Give a better error than the one
					// above if we detect a recursive type.
					if m[ts.Type] {
						fatalf("%s: invalid recursive type: %s refers to itself", fset.Position(e.Pos()), t.Name)
					}
					return p.doCgoType(ts.Type, m)
				}
			}
		}
		if def := typedef[t.Name]; def != nil {
			if defgo, ok := def.Go.(*ast.Ident); ok {
				switch defgo.Name {
				case "complex64", "complex128":
					// MSVC does not support the _Complex keyword
					// nor the complex macro.
					// Use GoComplex64 and GoComplex128 instead,
					// which are typedef-ed to a compatible type.
					// See go.dev/issues/36233.
					return goTypesFixup(goTypes[defgo.Name])
				}
			}
			return def
		}
		if t.Name == "uintptr" {
			return &Type{Size: p.PtrSize, Align: p.PtrSize, C: c("GoUintptr")}
		}
		if t.Name == "string" {
			// The string data is 1 pointer + 1 (pointer-sized) int.
			return &Type{Size: 2 * p.PtrSize, Align: p.PtrSize, C: c("GoString")}
		}
		if t.Name == "error" {
			return &Type{Size: 2 * p.PtrSize, Align: p.PtrSize, C: c("GoInterface")}
		}
		if r, ok := goTypes[t.Name]; ok {
			return goTypesFixup(r)
		}
		error_(e.Pos(), "unrecognized Go type %s", t.Name)
		return &Type{Size: 4, Align: 4, C: c("int")}
	case *ast.SelectorExpr:
		id, ok := t.X.(*ast.Ident)
		if ok && id.Name == "unsafe" && t.Sel.Name == "Pointer" {
			return &Type{Size: p.PtrSize, Align: p.PtrSize, C: c("void*")}
		}
	}
	error_(e.Pos(), "Go type not supported in export: %s", gofmt(e))
	return &Type{Size: 4, Align: 4, C: c("int")}
}

const gccProlog = `
#line 1 "cgo-gcc-prolog"
/*
  If x and y are not equal, the type will be invalid
  (have a negative array count) and an inscrutable error will come
  out of the compiler and hopefully mention "name".
*/
#define __cgo_compile_assert_eq(x, y, name) typedef char name[(x-y)*(x-y)*-2UL+1UL];

/* Check at compile time that the sizes we use match our expectations. */
#define __cgo_size_assert(t, n) __cgo_compile_assert_eq(sizeof(t), (size_t)n, _cgo_sizeof_##t##_is_not_##n)

__cgo_size_assert(char, 1)
__cgo_size_assert(short, 2)
__cgo_size_assert(int, 4)
typedef long long __cgo_long_long;
__cgo_size_assert(__cgo_long_long, 8)
__cgo_size_assert(float, 4)
__cgo_size_assert(double, 8)

extern char* _cgo_topofstack(void);

/*
  We use packed structs, but they are always aligned.
  The pragmas and address-of-packed-member are only recognized as warning
  groups in clang 4.0+, so ignore unknown pragmas first.
*/
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
#pragma GCC diagnostic ignored "-Wunknown-warning-option"
#pragma GCC diagnostic ignored "-Wunaligned-access"

#include <errno.h>
#include <string.h>
`

// Prologue defining TSAN functions in C.
const noTsanProlog = `
#define CGO_NO_SANITIZE_THREAD
#define _cgo_tsan_acquire()
#define _cgo_tsan_release()
`

// This must match the TSAN code in runtime/cgo/libcgo.h.
// This is used when the code is built with the C/C++ Thread SANitizer,
// which is not the same as the Go race detector.
// __tsan_acquire tells TSAN that we are acquiring a lock on a variable,
// in this case _cgo_sync. __tsan_release releases the lock.
// (There is no actual lock, we are just telling TSAN that there is.)
//
// When we call from Go to C we call _cgo_tsan_acquire.
// When the C function returns we call _cgo_tsan_release.
// Similarly, when C calls back into Go we call _cgo_tsan_release
// and then call _cgo_tsan_acquire when we return to C.
// These calls tell TSAN that there is a serialization point at the C call.
//
// This is necessary because TSAN, which is a C/C++ tool, can not see
// the synchronization in the Go code. Without these calls, when
// multiple goroutines call into C code, TSAN does not understand
// that the calls are properly synchronized on the Go side.
//
// To be clear, if the calls are not properly synchronized on the Go side,
// we will be hiding races. But when using TSAN on mixed Go C/C++ code
// it is more important to avoid false positives, which reduce confidence
// in the tool, than to avoid false negatives.
const yesTsanProlog = `
#line 1 "cgo-tsan-prolog"
#define CGO_NO_SANITIZE_THREAD __attribute__ ((no_sanitize_thread))

long long _cgo_sync __attribute__ ((common));

extern void __tsan_acquire(void*);
extern void __tsan_release(void*);

__attribute__ ((unused))
static void _cgo_tsan_acquire() {
	__tsan_acquire(&_cgo_sync);
}

__attribute__ ((unused))
static void _cgo_tsan_release() {
	__tsan_release(&_cgo_sync);
}
`

// Set to yesTsanProlog if we see -fsanitize=thread in the flags for gcc.
var tsanProlog = noTsanProlog

// noMsanProlog is a prologue defining an MSAN function in C.
// This is used when not compiling with -fsanitize=memory.
const noMsanProlog = `
#define _cgo_msan_write(addr, sz)
`

// yesMsanProlog is a prologue defining an MSAN function in C.
// This is used when compiling with -fsanitize=memory.
// See the comment above where _cgo_msan_write is called.
const yesMsanProlog = `
extern void __msan_unpoison(const volatile void *, size_t);

#define _cgo_msan_write(addr, sz) __msan_unpoison((addr), (sz))
`

// msanProlog is set to yesMsanProlog if we see -fsanitize=memory in the flags
// for the C compiler.
var msanProlog = noMsanProlog

const builtinProlog = `
#line 1 "cgo-builtin-prolog"
#include <stddef.h>

/* Define intgo when compiling with GCC.  */
typedef ptrdiff_t intgo;

#define GO_CGO_GOSTRING_TYPEDEF
typedef struct { const char *p; intgo n; } _GoString_;
typedef struct { char *p; intgo n; intgo c; } _GoBytes_;
_GoString_ GoString(char *p);
_GoString_ GoStringN(char *p, int l);
_GoBytes_ GoBytes(void *p, int n);
char *CString(_GoString_);
void *CBytes(_GoBytes_);
void *_CMalloc(size_t);

__attribute__ ((unused))
static size_t _GoStringLen(_GoString_ s) { return (size_t)s.n; }

__attribute__ ((unused))
static const char *_GoStringPtr(_GoString_ s) { return s.p; }
`

const goProlog = `
//go:linkname _cgo_runtime_cgocall runtime.cgocall
func _cgo_runtime_cgocall(unsafe.Pointer, uintptr) int32

//go:linkname _cgoCheckPointer runtime.cgoCheckPointer
//go:noescape
func _cgoCheckPointer(interface{}, interface{})

//go:linkname _cgoCheckResult runtime.cgoCheckResult
//go:noescape
func _cgoCheckResult(interface{})
`

const gccgoGoProlog = `
func _cgoCheckPointer(interface{}, interface{})

func _cgoCheckResult(interface{})
`

const goStringDef = `
//go:linkname _cgo_runtime_gostring runtime.gostring
func _cgo_runtime_gostring(*_Ctype_char) string

// GoString converts the C string p into a Go string.
func _Cfunc_GoString(p *_Ctype_char) string {
	return _cgo_runtime_gostring(p)
}
`

const goStringNDef = `
//go:linkname _cgo_runtime_gostringn runtime.gostringn
func _cgo_runtime_gostringn(*_Ctype_char, int) string

// GoStringN converts the C data p with explicit length l to a Go string.
func _Cfunc_GoStringN(p *_Ctype_char, l _Ctype_int) string {
	return _cgo_runtime_gostringn(p, int(l))
}
`

const goBytesDef = `
//go:linkname _cgo_runtime_gobytes runtime.gobytes
func _cgo_runtime_gobytes(unsafe.Pointer, int) []byte

// GoBytes converts the C data p with explicit length l to a Go []byte.
func _Cfunc_GoBytes(p unsafe.Pointer, l _Ctype_int) []byte {
	return _cgo_runtime_gobytes(p, int(l))
}
`

const cStringDef = `
// CString converts the Go string s to a C string.
//
// The C string is allocated in the C heap using malloc.
// It is the caller's responsibility to arrange for it to be
// freed, such as by calling C.free (be sure to include stdlib.h
// if C.free is needed).
func _Cfunc_CString(s string) *_Ctype_char {
	if len(s)+1 <= 0 {
		panic("string too large")
	}
	p := _cgo_cmalloc(uint64(len(s)+1))
	sliceHeader := struct {
		p   unsafe.Pointer
		len int
		cap int
	}{p, len(s)+1, len(s)+1}
	b := *(*[]byte)(unsafe.Pointer(&sliceHeader))
	copy(b, s)
	b[len(s)] = 0
	return (*_Ctype_char)(p)
}
`

const cBytesDef = `
// CBytes converts the Go []byte slice b to a C array.
//
// The C array is allocated in the C heap using malloc.
// It is the caller's responsibility to arrange for it to be
// freed, such as by calling C.free (be sure to include stdlib.h
// if C.free is needed).
func _Cfunc_CBytes(b []byte) unsafe.Pointer {
	p := _cgo_cmalloc(uint64(len(b)))
	sliceHeader := struct {
		p   unsafe.Pointer
		len int
		cap int
	}{p, len(b), len(b)}
	s := *(*[]byte)(unsafe.Pointer(&sliceHeader))
	copy(s, b)
	return p
}
`

const cMallocDef = `
func _Cfunc__CMalloc(n _Ctype_size_t) unsafe.Pointer {
	return _cgo_cmalloc(uint64(n))
}
`

var builtinDefs = map[string]string{
	"GoString":  goStringDef,
	"GoStringN": goStringNDef,
	"GoBytes":   goBytesDef,
	"CString":   cStringDef,
	"CBytes":    cBytesDef,
	"_CMalloc":  cMallocDef,
}

// Definitions for C.malloc in Go and in C. We define it ourselves
// since we call it from functions we define, such as C.CString.
// Also, we have historically ensured that C.malloc does not return
// nil even for an allocation of 0.

const cMallocDefGo = `
//go:cgo_import_static _cgoPREFIX_Cfunc__Cmalloc
//go:linkname __cgofn__cgoPREFIX_Cfunc__Cmalloc _cgoPREFIX_Cfunc__Cmalloc
var __cgofn__cgoPREFIX_Cfunc__Cmalloc byte
var _cgoPREFIX_Cfunc__Cmalloc = unsafe.Pointer(&__cgofn__cgoPREFIX_Cfunc__Cmalloc)

//go:linkname runtime_throw runtime.throw
func runtime_throw(string)

//go:cgo_unsafe_args
func _cgo_cmalloc(p0 uint64) (r1 unsafe.Pointer) {
	_cgo_runtime_cgocall(_cgoPREFIX_Cfunc__Cmalloc, uintptr(unsafe.Pointer(&p0)))
	if r1 == nil {
		runtime_throw("runtime: C malloc failed")
	}
	return
}
`

// cMallocDefC defines the C version of C.malloc for the gc compiler.
// It is defined here because C.CString and friends need a definition.
// We define it by hand, rather than simply inventing a reference to
// C.malloc, because <stdlib.h> may not have been included.
// This is approximately what writeOutputFunc would generate, but
// skips the cgo_topofstack code (which is only needed if the C code
// calls back into Go). This also avoids returning nil for an
// allocation of 0 bytes.
const cMallocDefC = `
CGO_NO_SANITIZE_THREAD
void _cgoPREFIX_Cfunc__Cmalloc(void *v) {
	struct {
		unsigned long long p0;
		void *r1;
	} PACKED *a = v;
	void *ret;
	_cgo_tsan_acquire();
	ret = malloc(a->p0);
	if (ret == 0 && a->p0 == 0) {
		ret = malloc(1);
	}
	a->r1 = ret;
	_cgo_tsan_release();
}
`

func (p *Package) cPrologGccgo() string {
	r := strings.NewReplacer(
		"PREFIX", cPrefix,
		"GCCGOSYMBOLPREF", p.gccgoSymbolPrefix(),
		"_cgoCheckPointer", gccgoToSymbol("_cgoCheckPointer"),
		"_cgoCheckResult", gccgoToSymbol("_cgoCheckResult"))
	return r.Replace(cPrologGccgo)
}

const cPrologGccgo = `
#line 1 "cgo-c-prolog-gccgo"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char byte;
typedef intptr_t intgo;

struct __go_string {
	const unsigned char *__data;
	intgo __length;
};

typedef struct __go_open_array {
	void* __values;
	intgo __count;
	intgo __capacity;
} Slice;

struct __go_string __go_byte_array_to_string(const void* p, intgo len);
struct __go_open_array __go_string_to_byte_array (struct __go_string str);

extern void runtime_throw(const char *);

const char *_cgoPREFIX_Cfunc_CString(struct __go_string s) {
	char *p = malloc(s.__length+1);
	if(p == NULL)
		runtime_throw("runtime: C malloc failed");
	memmove(p, s.__data, s.__length);
	p[s.__length] = 0;
	return p;
}

void *_cgoPREFIX_Cfunc_CBytes(struct __go_open_array b) {
	char *p = malloc(b.__count);
	if(p == NULL)
		runtime_throw("runtime: C malloc failed");
	memmove(p, b.__values, b.__count);
	return p;
}

struct __go_string _cgoPREFIX_Cfunc_GoString(char *p) {
	intgo len = (p != NULL) ? strlen(p) : 0;
	return __go_byte_array_to_string(p, len);
}

struct __go_string _cgoPREFIX_Cfunc_GoStringN(char *p, int32_t n) {
	return __go_byte_array_to_string(p, n);
}

Slice _cgoPREFIX_Cfunc_GoBytes(char *p, int32_t n) {
	struct __go_string s = { (const unsigned char *)p, n };
	return __go_string_to_byte_array(s);
}

void *_cgoPREFIX_Cfunc__CMalloc(size_t n) {
	void *p = malloc(n);
	if(p == NULL && n == 0)
		p = malloc(1);
	if(p == NULL)
		runtime_throw("runtime: C malloc failed");
	return p;
}

struct __go_type_descriptor;
typedef struct __go_empty_interface {
	const struct __go_type_descriptor *__type_descriptor;
	void *__object;
} Eface;

extern void runtimeCgoCheckPointer(Eface, Eface)
	__asm__("runtime.cgoCheckPointer")
	__attribute__((weak));

extern void localCgoCheckPointer(Eface, Eface)
	__asm__("GCCGOSYMBOLPREF._cgoCheckPointer");

void localCgoCheckPointer(Eface ptr, Eface arg) {
	if(runtimeCgoCheckPointer) {
		runtimeCgoCheckPointer(ptr, arg);
	}
}

extern void runtimeCgoCheckResult(Eface)
	__asm__("runtime.cgoCheckResult")
	__attribute__((weak));

extern void localCgoCheckResult(Eface)
	__asm__("GCCGOSYMBOLPREF._cgoCheckResult");

void localCgoCheckResult(Eface val) {
	if(runtimeCgoCheckResult) {
		runtimeCgoCheckResult(val);
	}
}
`

// builtinExportProlog is a shorter version of builtinProlog,
// to be put into the _cgo_export.h file.
// For historical reasons we can't use builtinProlog in _cgo_export.h,
// because _cgo_export.h defines GoString as a struct while builtinProlog
// defines it as a function. We don't change this to avoid unnecessarily
// breaking existing code.
// The test of GO_CGO_GOSTRING_TYPEDEF avoids a duplicate definition
// error if a Go file with a cgo comment #include's the export header
// generated by a different package.
const builtinExportProlog = `
#line 1 "cgo-builtin-export-prolog"

#include <stddef.h>

#ifndef GO_CGO_EXPORT_PROLOGUE_H
#define GO_CGO_EXPORT_PROLOGUE_H

#ifndef GO_CGO_GOSTRING_TYPEDEF
typedef struct { const char *p; ptrdiff_t n; } _GoString_;
#endif

#endif
`

func (p *Package) gccExportHeaderProlog() string {
	return strings.Replace(gccExportHeaderProlog, "GOINTBITS", fmt.Sprint(8*p.IntSize), -1)
}

// gccExportHeaderProlog is written to the exported header, after the
// import "C" comment preamble but before the generated declarations
// of exported functions. This permits the generated declarations to
// use the type names that appear in goTypes, above.
//
// The test of GO_CGO_GOSTRING_TYPEDEF avoids a duplicate definition
// error if a Go file with a cgo comment #include's the export header
// generated by a different package. Unfortunately GoString means two
// different things: in this prolog it means a C name for the Go type,
// while in the prolog written into the start of the C code generated
// from a cgo-using Go file it means the C.GoString function. There is
// no way to resolve this conflict, but it also doesn't make much
// difference, as Go code never wants to refer to the latter meaning.
const gccExportHeaderProlog = `
/* Start of boilerplate cgo prologue.  */
#line 1 "cgo-gcc-export-header-prolog"

#ifndef GO_CGO_PROLOGUE_H
#define GO_CGO_PROLOGUE_H

typedef signed char GoInt8;
typedef unsigned char GoUint8;
typedef short GoInt16;
typedef unsigned short GoUint16;
typedef int GoInt32;
typedef unsigned int GoUint32;
typedef long long GoInt64;
typedef unsigned long long GoUint64;
typedef GoIntGOINTBITS GoInt;
typedef GoUintGOINTBITS GoUint;
typedef size_t GoUintptr;
typedef float GoFloat32;
typedef double GoFloat64;
#ifdef _MSC_VER
#include <complex.h>
typedef _Fcomplex GoComplex64;
typedef _Dcomplex GoComplex128;
#else
typedef float _Complex GoComplex64;
typedef double _Complex GoComplex128;
#endif

/*
  static assertion to make sure the file is being used on architecture
  at least with matching size of GoInt.
*/
typedef char _check_for_GOINTBITS_bit_pointer_matching_GoInt[sizeof(void*)==GOINTBITS/8 ? 1:-1];

#ifndef GO_CGO_GOSTRING_TYPEDEF
typedef _GoString_ GoString;
#endif
typedef void *GoMap;
typedef void *GoChan;
typedef struct { void *t; void *v; } GoInterface;
typedef struct { void *data; GoInt len; GoInt cap; } GoSlice;

#endif

/* End of boilerplate cgo prologue.  */

#ifdef __cplusplus
extern "C" {
#endif
`

// gccExportHeaderEpilog goes at the end of the generated header file.
const gccExportHeaderEpilog = `
#ifdef __cplusplus
}
#endif
`

// gccgoExportFileProlog is written to the _cgo_export.c file when
// using gccgo.
// We use weak declarations, and test the addresses, so that this code
// works with older versions of gccgo.
const gccgoExportFileProlog = `
#line 1 "cgo-gccgo-export-file-prolog"
extern _Bool runtime_iscgo __attribute__ ((weak));

static void GoInit(void) __attribute__ ((constructor));
static void GoInit(void) {
	if(&runtime_iscgo)
		runtime_iscgo = 1;
}

extern size_t _cgo_wait_runtime_init_done(void) __attribute__ ((weak));
`

"""



```