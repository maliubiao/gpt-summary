Response:
My thinking process to analyze the provided Go code snippet and answer the user's request goes like this:

1. **Understand the Goal:** The user wants to understand the functionality of the `go.go` file within the Go linker (`cmd/link/internal/ld`). Specifically, they want a summary of its functions, potential Go feature implementations, code examples, handling of command-line arguments, and common mistakes.

2. **Initial Code Scan:** I first skimmed the code to get a general idea of its purpose. Keywords like `ldpkg`, `loadcgo`, `setCgoAttr`, `adddynlib`, `Adddynsym`, `fieldtrack`, and `addexport` immediately stood out as potential functions to focus on. The package declaration `package ld` confirms it's part of the linker. The comments mentioning "go-specific code shared across loaders" reinforce this.

3. **Function-by-Function Analysis:** I went through each function, trying to decipher its role.

    * **`ldpkg`:** The name suggests "load package". The code reads data from a `bio.Reader`, checks for "main", and looks for a "cgo" section. This points towards processing package information, likely including CGO directives.

    * **`loadcgo`:** This function clearly deals with loading and decoding CGO directives. It uses `encoding/json` to parse the directives. The `ctxt.cgodata` suggests it's storing these directives for later processing.

    * **`setCgoAttr`:**  The name strongly suggests setting attributes based on CGO directives. The switch statement handles various directives like `cgo_import_dynamic`, `cgo_import_static`, `cgo_export_static`, `cgo_export_dynamic`, `cgo_dynamic_linker`, and `cgo_ldflag`. This seems crucial for integrating C code with Go.

    * **`openbsdTrimLibVersion` and `dedupLibrariesOpenBSD`:** These functions seem specific to OpenBSD and deal with handling versioned shared libraries.

    * **`dedupLibraries`:** This function acts as a dispatcher, calling the OpenBSD-specific function or doing nothing for other systems. It's about avoiding redundant entries in the dynamic linking information.

    * **`adddynlib`:**  This function adds a dynamic library dependency. The use of `elf.DT_NEEDED` indicates it's likely for ELF-based systems.

    * **`Adddynsym`:** This function adds a dynamic symbol to the dynamic symbol table. Again, the ELF-specific code suggests its main focus.

    * **`fieldtrack`:** This function seems related to debugging or profiling, potentially tracking how certain fields are accessed. The "go:track." prefix in symbol names is a strong hint.

    * **`addexport`:**  This function appears to handle the process of adding symbols to the export table, both dynamic and static. It also deals with undefined external symbols during external linking.

4. **Identifying Go Feature Implementations:** Based on the function analysis, CGO integration is the most prominent feature being implemented in this code. The functions `ldpkg`, `loadcgo`, and `setCgoAttr` directly handle CGO directives. Dynamic linking, especially the management of shared libraries, is also a key area, reflected in functions like `adddynlib` and `Adddynsym`. The `fieldtrack` function suggests a debugging or profiling feature.

5. **Crafting Code Examples:**  For CGO, I created a basic example demonstrating how to import a C function and a C variable, reflecting the `cgo_import_dynamic` and `cgo_import_static` directives. For dynamic linking, I showed a hypothetical scenario where `cgo_ldflag` is used to specify a linker flag.

6. **Analyzing Command-Line Arguments:** I scanned the code for references to `flag` and `*flag...`. The code mentions `-G` (skipping `ldpkg`), `-d` (disabling dynamic imports), and `--interpreter` (for setting the dynamic linker). I explained these. The presence of `*flagFieldTrack` also indicates a command-line flag for field tracking.

7. **Identifying Common Mistakes:** I focused on potential pitfalls related to CGO, like incorrect directive syntax, conflicting export directives, and issues with dynamic imports and the `-d` flag.

8. **Structuring the Answer:** I organized the information into logical sections as requested: Functionality Summary, Go Feature Implementation, Code Examples, Command-Line Arguments, and Common Mistakes. I used clear and concise language.

9. **Refinement and Review:** I reviewed my answer to ensure accuracy, completeness, and clarity. I made sure the code examples were valid (even if simplified) and that the explanations were easy to understand. I also paid attention to the specific phrasing requested by the user (e.g., "带上假设的输入与输出" for code examples).

This systematic approach allowed me to break down the complex code into manageable parts and provide a comprehensive answer to the user's request. The key was to connect the code snippets to the broader context of the Go linker and its role in the compilation and linking process, especially regarding CGO and dynamic linking.
这个 `go/src/cmd/link/internal/ld/go.go` 文件是 Go 链接器 (`cmd/link`) 中处理 Go 语言特定逻辑的一部分。它主要负责解析和处理 Go 包的信息，特别是与 CGO 相关的指令，以及管理动态链接相关的符号和库。

以下是该文件的一些主要功能：

**1. 解析和加载 Go 包信息 (`ldpkg`)：**

* **功能:**  读取 `.a` 归档文件中的 Go 包信息，这些信息通常包含在特殊的数据段中。
* **处理 `main` 标识:**  检查包是否是 `main` 包。
* **提取 CGO 指令:**  查找并提取 `$$ // cgo` 和 `$$` 或 `!\n` 之间的 CGO 指令。
* **跳过编译:** 如果设置了 `-G` 标志，则跳过包加载。
* **错误处理:**  检查包数据长度，以及读取包数据时的错误。

**2. 加载 CGO 指令 (`loadcgo`)：**

* **功能:**  解析从 Go 包中提取的 JSON 格式的 CGO 指令。
* **存储 CGO 数据:** 将解析后的 CGO 指令（包含文件名、包名和指令列表）存储在链接器上下文 (`ctxt`) 的 `cgodata` 字段中，以便后续处理。
* **错误处理:**  处理 JSON 解码失败的情况。

**3. 设置基于 CGO 指令的符号属性 (`setCgoAttr`)：**

* **功能:**  根据解析出的 CGO 指令，设置 Go 符号的属性和标志。
* **处理 `cgo_import_dynamic`:**  处理动态链接导入的符号，包括本地符号名、远程符号名和动态库名。
    * 设置符号的 `Dynimplib` (动态库名), `Extname` (外部名称), `Dynimpvers` (动态库版本)。
    * 将符号类型设置为 `SDYNIMPORT`。
    * 处理 `#pragma dynimport _ _ "foo.so"` 形式的指令，强制链接动态库。
    * 如果指定了动态库且目标平台是 Darwin (macOS)，则使用 `machoadddynlib` 添加动态库。
* **处理 `cgo_import_static`:**  处理静态链接导入的符号，将符号类型设置为 `SHOSTOBJ`。
* **处理 `cgo_export_static` 和 `cgo_export_dynamic`:** 处理静态和动态导出的符号。
    * 设置符号的外部名称 (`Extname`)。
    * 标记符号为可导出 (`AttrCgoExportStatic` 或 `AttrCgoExportDynamic`)。
    * 对于内部链接 (`LinkInternal`)，将导出的符号添加到 CGO 导出列表 (`ctxt.cgoexport`)。
    * 对于外部链接 (`LinkExternal`)，静态导出的符号添加到动态导出列表 (`ctxt.dynexp`)。
    * 处理函数符号的 ABI (Application Binary Interface)。
* **处理 `cgo_dynamic_linker`:**  设置动态链接器的路径。
* **处理 `cgo_ldflag`:**  添加额外的链接器标志。
* **错误处理:**  处理无效的 CGO 指令，动态导入与 `-d` 标志冲突的情况，以及冲突的导出指令。

**4. 处理动态链接库 (`adddynlib`, `dedupLibraries`, `dedupLibrariesOpenBSD`)：**

* **`adddynlib`:**  向动态链接器添加一个需要链接的共享库。
    * 对于 ELF 格式的目标文件，会向 `.dynamic` 段添加 `DT_NEEDED` 条目。
    * 避免重复添加相同的库。
    * 外部链接模式下不添加。
* **`dedupLibraries`:**  对动态链接库列表进行去重。
    * 对于 OpenBSD 系统，使用 `dedupLibrariesOpenBSD` 进行特殊处理，以处理版本化的库名。
* **`dedupLibrariesOpenBSD`:**  专门针对 OpenBSD 系统，去重动态链接库，将版本化和非版本化的库视为等价，并优先保留版本化的库。

**5. 添加动态符号 (`Adddynsym`)：**

* **功能:**  将符号添加到动态符号表，以便动态链接器在运行时解析。
* **处理 ELF 格式:**  对于 ELF 格式的目标文件，调用 `elfadddynsym` 添加动态符号。
* **避免重复添加:**  检查符号是否已添加到动态符号表。
* **外部链接模式下不添加。**

**6. 字段跟踪 (`fieldtrack`)：**

* **功能:**  根据特定的符号前缀 (`go:track.`) 跟踪字段的使用情况。
* **输出信息:**  如果找到匹配的符号并且可达，则输出符号名称及其可达路径。
* **命令行标志:**  使用 `--fieldtrack` 标志指定要跟踪的特定符号。

**7. 添加导出符号 (`addexport`)：**

* **功能:**  负责添加需要导出的符号到目标文件的符号表。
* **外部链接处理:**  在外部链接模式下，跟踪未定义的外部符号，并将其类型设置为 `SUNDEFEXT`。
* **添加动态符号:**  遍历 `ctxt.dynexp` 中的符号，调用 `Adddynsym` 将它们添加到动态符号表。
* **添加动态链接库:**  调用 `dedupLibraries` 去重动态库列表，并调用 `adddynlib` 添加这些库。

**可以推理出它是什么 Go 语言功能的实现：**

这个文件是 Go 语言中 **CGO (C bindings for Go)** 和 **动态链接** 功能实现的关键部分。

* **CGO:**  `ldpkg`, `loadcgo`, 和 `setCgoAttr` 函数共同处理 CGO 的指令，这些指令允许 Go 代码调用 C 代码，以及允许 C 代码调用 Go 代码。
* **动态链接:** `adddynlib`, `Adddynsym`, `dedupLibraries` 和 `addexport` 等函数负责管理动态链接所需的符号和库信息，这使得 Go 程序可以依赖于在运行时加载的共享库。

**Go 代码举例说明 (CGO)：**

假设我们有一个包含 C 代码的 Go 包，其中 C 代码定义了一个函数 `c_function` 和一个变量 `c_variable`。

```go
// +build cgo

package mypackage

//#include <stdio.h>
//
//void c_function() {
//  printf("Hello from C!\n");
//}
//
//int c_variable = 42;
import "C"

func CallCFunction() {
	C.c_function()
}

func GetCVariable() int {
	return int(C.c_variable)
}
```

当链接器处理这个包时，`ldpkg` 会读取包信息，并提取类似以下的 CGO 指令：

```json
[["cgo_import_dynamic", "c_function"], ["cgo_import_static", "c_variable"]]
```

* **假设输入 (`ldpkg`):**  包含上述 JSON 指令的包数据。
* **`loadcgo` 处理:** `loadcgo` 会将这些 JSON 指令解码并存储到 `ctxt.cgodata` 中。
* **`setCgoAttr` 处理:** `setCgoAttr` 会根据这些指令创建或查找名为 `c_function` 和 `c_variable` 的符号，并设置相应的属性：
    * `c_function`:  类型设置为 `SDYNIMPORT`，可能设置 `Dynimplib` 如果指定了动态库。
    * `c_variable`: 类型设置为 `SHOSTOBJ`，表示来自宿主对象 (C 代码)。

**Go 代码举例说明 (动态链接)：**

假设我们的 Go 代码需要链接一个外部动态库 `mylib.so`。可以通过 CGO 的 `#cgo LDFLAGS:` 指令来实现：

```go
// +build cgo

package mypackage

//#cgo LDFLAGS: -lmylib

import "C"

// ... 一些使用 mylib.so 中函数的代码
```

* **`ldpkg` 处理:** `ldpkg` 可能会提取类似以下的 CGO 指令：
   ```json
   [["cgo_ldflag", "-lmylib"]]
   ```
* **`setCgoAttr` 处理:** `setCgoAttr` 会将 `-lmylib` 添加到链接器的 `ldflag` 列表中。
* **`addexport` 处理:** 在链接的最后阶段，`addexport` 会遍历 `ldflag`，并根据需要调用 `adddynlib("mylib.so")` 将 `mylib.so` 添加到需要链接的动态库列表中。

**命令行参数的具体处理：**

* **`-G`:** 如果在链接时指定了 `-G` 标志，`ldpkg` 函数会直接返回，跳过加载包数据的过程。这通常用于某些特殊的链接场景，可能用于增量编译或调试。
* **`-d`:**  `setCgoAttr` 中会检查 `-d` 标志。如果设置了 `-d` (表示禁用动态链接)，并且 CGO 指令中存在 `cgo_import_dynamic`，则会报错，因为 `-d` 与动态导入不兼容。
* **`--interpreter <path>`:**  `setCgoAttr` 处理 `cgo_dynamic_linker` 指令时，会将指定的路径设置为动态链接器的路径。如果命令行中也指定了 `--interpreter`，则会进行冲突检查。
* **`--fieldtrack <symbol>`:** `fieldtrack` 函数使用 `--fieldtrack` 标志来指定要跟踪的符号。

**使用者易犯错的点：**

* **CGO 指令错误:**  在 Go 代码中使用 CGO 时，`// #cgo` 指令的语法非常严格，容易出错。例如，`LDFLAGS` 和 `CFLAGS` 的位置、格式等不正确会导致链接错误。
* **动态链接库路径问题:**  当使用 `cgo_import_dynamic` 或 `#cgo LDFLAGS: -lxxx` 时，确保动态链接库在运行时能够被找到（例如，在 `LD_LIBRARY_PATH` 中）。
* **`-d` 标志与动态导入冲突:**  如果在使用了 `cgo_import_dynamic` 的情况下使用了 `-d` 标志进行链接，会导致链接错误。用户可能不清楚这个限制。
* **OpenBSD 版本化库的处理:** 在 OpenBSD 上使用 CGO 时，如果手动指定动态库名，可能会遇到版本化库的问题。例如，代码可能需要 `libc.so.X.Y`，但用户可能只指定了 `libc.so`。`dedupLibrariesOpenBSD` 尝试解决这个问题，但用户仍然需要理解 OpenBSD 的库命名约定。

总而言之，`go/src/cmd/link/internal/ld/go.go` 是 Go 链接器中一个核心的文件，它专注于处理 Go 语言特有的信息，特别是与 C 代码集成和动态链接相关的部分。理解这个文件的功能有助于深入理解 Go 的编译和链接过程，尤其是在涉及到 CGO 或动态链接时。

### 提示词
```
这是路径为go/src/cmd/link/internal/ld/go.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// go-specific code shared across loaders (5l, 6l, 8l).

package ld

import (
	"cmd/internal/bio"
	"cmd/internal/obj"
	"cmd/internal/objabi"
	"cmd/internal/sys"
	"cmd/link/internal/loader"
	"cmd/link/internal/sym"
	"debug/elf"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// go-specific code shared across loaders (5l, 6l, 8l).

// TODO:
//	generate debugging section in binary.
//	once the dust settles, try to move some code to
//		libmach, so that other linkers and ar can share.

func ldpkg(ctxt *Link, f *bio.Reader, lib *sym.Library, length int64, filename string) {
	if *flagG {
		return
	}

	if int64(int(length)) != length {
		fmt.Fprintf(os.Stderr, "%s: too much pkg data in %s\n", os.Args[0], filename)
		return
	}

	bdata := make([]byte, length)
	if _, err := io.ReadFull(f, bdata); err != nil {
		fmt.Fprintf(os.Stderr, "%s: short pkg read %s\n", os.Args[0], filename)
		return
	}
	data := string(bdata)

	// process header lines
	for data != "" {
		var line string
		line, data, _ = strings.Cut(data, "\n")
		if line == "main" {
			lib.Main = true
		}
		if line == "" {
			break
		}
	}

	// look for cgo section
	p0 := strings.Index(data, "\n$$  // cgo")
	var p1 int
	if p0 >= 0 {
		p0 += p1
		i := strings.IndexByte(data[p0+1:], '\n')
		if i < 0 {
			fmt.Fprintf(os.Stderr, "%s: found $$ // cgo but no newline in %s\n", os.Args[0], filename)
			return
		}
		p0 += 1 + i

		p1 = strings.Index(data[p0:], "\n$$")
		if p1 < 0 {
			p1 = strings.Index(data[p0:], "\n!\n")
		}
		if p1 < 0 {
			fmt.Fprintf(os.Stderr, "%s: cannot find end of // cgo section in %s\n", os.Args[0], filename)
			return
		}
		p1 += p0
		loadcgo(ctxt, filename, objabi.PathToPrefix(lib.Pkg), data[p0:p1])
	}
}

func loadcgo(ctxt *Link, file string, pkg string, p string) {
	var directives [][]string
	if err := json.NewDecoder(strings.NewReader(p)).Decode(&directives); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s: failed decoding cgo directives: %v\n", os.Args[0], file, err)
		nerrors++
		return
	}

	// Record the directives. We'll process them later after Symbols are created.
	ctxt.cgodata = append(ctxt.cgodata, cgodata{file, pkg, directives})
}

// Set symbol attributes or flags based on cgo directives.
// Any newly discovered HOSTOBJ syms are added to 'hostObjSyms'.
func setCgoAttr(ctxt *Link, file string, pkg string, directives [][]string, hostObjSyms map[loader.Sym]struct{}) {
	l := ctxt.loader
	for _, f := range directives {
		switch f[0] {
		case "cgo_import_dynamic":
			if len(f) < 2 || len(f) > 4 {
				break
			}

			local := f[1]
			remote := local
			if len(f) > 2 {
				remote = f[2]
			}
			lib := ""
			if len(f) > 3 {
				lib = f[3]
			}

			if *FlagD {
				fmt.Fprintf(os.Stderr, "%s: %s: cannot use dynamic imports with -d flag\n", os.Args[0], file)
				nerrors++
				return
			}

			if local == "_" && remote == "_" {
				// allow #pragma dynimport _ _ "foo.so"
				// to force a link of foo.so.
				havedynamic = 1

				if ctxt.HeadType == objabi.Hdarwin {
					machoadddynlib(lib, ctxt.LinkMode)
				} else {
					dynlib = append(dynlib, lib)
				}
				continue
			}

			q := ""
			if before, after, found := strings.Cut(remote, "#"); found {
				remote, q = before, after
			}
			s := l.LookupOrCreateSym(local, 0)
			st := l.SymType(s)
			if st == 0 || st == sym.SXREF || st == sym.SBSS || st == sym.SNOPTRBSS || st == sym.SHOSTOBJ {
				l.SetSymDynimplib(s, lib)
				l.SetSymExtname(s, remote)
				l.SetSymDynimpvers(s, q)
				if st != sym.SHOSTOBJ {
					su := l.MakeSymbolUpdater(s)
					su.SetType(sym.SDYNIMPORT)
				} else {
					hostObjSyms[s] = struct{}{}
				}
				havedynamic = 1
				if lib != "" && ctxt.IsDarwin() {
					machoadddynlib(lib, ctxt.LinkMode)
				}
			}

			continue

		case "cgo_import_static":
			if len(f) != 2 {
				break
			}
			local := f[1]

			s := l.LookupOrCreateSym(local, 0)
			su := l.MakeSymbolUpdater(s)
			su.SetType(sym.SHOSTOBJ)
			su.SetSize(0)
			hostObjSyms[s] = struct{}{}
			continue

		case "cgo_export_static", "cgo_export_dynamic":
			if len(f) < 2 || len(f) > 4 {
				break
			}
			local := f[1]
			remote := local
			if len(f) > 2 {
				remote = f[2]
			}
			// The compiler adds a fourth argument giving
			// the definition ABI of function symbols.
			abi := obj.ABI0
			if len(f) > 3 {
				var ok bool
				abi, ok = obj.ParseABI(f[3])
				if !ok {
					fmt.Fprintf(os.Stderr, "%s: bad ABI in cgo_export directive %s\n", os.Args[0], f)
					nerrors++
					return
				}
			}

			s := l.LookupOrCreateSym(local, sym.ABIToVersion(abi))

			if l.SymType(s) == sym.SHOSTOBJ {
				hostObjSyms[s] = struct{}{}
			}

			switch ctxt.BuildMode {
			case BuildModeCShared, BuildModeCArchive, BuildModePlugin:
				if s == l.Lookup("main", 0) {
					continue
				}
			}

			// export overrides import, for openbsd/cgo.
			// see issue 4878.
			if l.SymDynimplib(s) != "" {
				l.SetSymDynimplib(s, "")
				l.SetSymDynimpvers(s, "")
				l.SetSymExtname(s, "")
				var su *loader.SymbolBuilder
				su = l.MakeSymbolUpdater(s)
				su.SetType(0)
			}

			if !(l.AttrCgoExportStatic(s) || l.AttrCgoExportDynamic(s)) {
				l.SetSymExtname(s, remote)
			} else if l.SymExtname(s) != remote {
				fmt.Fprintf(os.Stderr, "%s: conflicting cgo_export directives: %s as %s and %s\n", os.Args[0], l.SymName(s), l.SymExtname(s), remote)
				nerrors++
				return
			}

			// Mark exported symbols and also add them to
			// the lists used for roots in the deadcode pass.
			if f[0] == "cgo_export_static" {
				if ctxt.LinkMode == LinkExternal && !l.AttrCgoExportStatic(s) {
					// Static cgo exports appear
					// in the exported symbol table.
					ctxt.dynexp = append(ctxt.dynexp, s)
				}
				if ctxt.LinkMode == LinkInternal {
					// For internal linking, we're
					// responsible for resolving
					// relocations from host objects.
					// Record the right Go symbol
					// version to use.
					l.AddCgoExport(s)
				}
				l.SetAttrCgoExportStatic(s, true)
			} else {
				if ctxt.LinkMode == LinkInternal && !l.AttrCgoExportDynamic(s) {
					// Dynamic cgo exports appear
					// in the exported symbol table.
					ctxt.dynexp = append(ctxt.dynexp, s)
				}
				l.SetAttrCgoExportDynamic(s, true)
			}

			continue

		case "cgo_dynamic_linker":
			if len(f) != 2 {
				break
			}

			if *flagInterpreter == "" {
				if interpreter != "" && interpreter != f[1] {
					fmt.Fprintf(os.Stderr, "%s: conflict dynlinker: %s and %s\n", os.Args[0], interpreter, f[1])
					nerrors++
					return
				}

				interpreter = f[1]
			}
			continue

		case "cgo_ldflag":
			if len(f) != 2 {
				break
			}
			ldflag = append(ldflag, f[1])
			continue
		}

		fmt.Fprintf(os.Stderr, "%s: %s: invalid cgo directive: %q\n", os.Args[0], file, f)
		nerrors++
	}
	return
}

// openbsdTrimLibVersion indicates whether a shared library is
// versioned and if it is, returns the unversioned name. The
// OpenBSD library naming scheme is lib<name>.so.<major>.<minor>
func openbsdTrimLibVersion(lib string) (string, bool) {
	parts := strings.Split(lib, ".")
	if len(parts) != 4 {
		return "", false
	}
	if parts[1] != "so" {
		return "", false
	}
	if _, err := strconv.Atoi(parts[2]); err != nil {
		return "", false
	}
	if _, err := strconv.Atoi(parts[3]); err != nil {
		return "", false
	}
	return fmt.Sprintf("%s.%s", parts[0], parts[1]), true
}

// dedupLibrariesOpenBSD dedups a list of shared libraries, treating versioned
// and unversioned libraries as equivalents. Versioned libraries are preferred
// and retained over unversioned libraries. This avoids the situation where
// the use of cgo results in a DT_NEEDED for a versioned library (for example,
// libc.so.96.1), while a dynamic import specifies an unversioned library (for
// example, libc.so) - this would otherwise result in two DT_NEEDED entries
// for the same library, resulting in a failure when ld.so attempts to load
// the Go binary.
func dedupLibrariesOpenBSD(ctxt *Link, libs []string) []string {
	libraries := make(map[string]string)
	for _, lib := range libs {
		if name, ok := openbsdTrimLibVersion(lib); ok {
			// Record unversioned name as seen.
			seenlib[name] = true
			libraries[name] = lib
		} else if _, ok := libraries[lib]; !ok {
			libraries[lib] = lib
		}
	}

	libs = nil
	for _, lib := range libraries {
		libs = append(libs, lib)
	}
	sort.Strings(libs)

	return libs
}

func dedupLibraries(ctxt *Link, libs []string) []string {
	if ctxt.Target.IsOpenbsd() {
		return dedupLibrariesOpenBSD(ctxt, libs)
	}
	return libs
}

var seenlib = make(map[string]bool)

func adddynlib(ctxt *Link, lib string) {
	if seenlib[lib] || ctxt.LinkMode == LinkExternal {
		return
	}
	seenlib[lib] = true

	if ctxt.IsELF {
		dsu := ctxt.loader.MakeSymbolUpdater(ctxt.DynStr)
		if dsu.Size() == 0 {
			dsu.Addstring("")
		}
		du := ctxt.loader.MakeSymbolUpdater(ctxt.Dynamic)
		Elfwritedynent(ctxt.Arch, du, elf.DT_NEEDED, uint64(dsu.Addstring(lib)))
	} else {
		Errorf("adddynlib: unsupported binary format")
	}
}

func Adddynsym(ldr *loader.Loader, target *Target, syms *ArchSyms, s loader.Sym) {
	if ldr.SymDynid(s) >= 0 || target.LinkMode == LinkExternal {
		return
	}

	if target.IsELF {
		elfadddynsym(ldr, target, syms, s)
	} else if target.HeadType == objabi.Hdarwin {
		ldr.Errorf(s, "adddynsym: missed symbol (Extname=%s)", ldr.SymExtname(s))
	} else if target.HeadType == objabi.Hwindows {
		// already taken care of
	} else {
		ldr.Errorf(s, "adddynsym: unsupported binary format")
	}
}

func fieldtrack(arch *sys.Arch, l *loader.Loader) {
	var buf strings.Builder
	for i := loader.Sym(1); i < loader.Sym(l.NSym()); i++ {
		if name := l.SymName(i); strings.HasPrefix(name, "go:track.") {
			if l.AttrReachable(i) {
				l.SetAttrSpecial(i, true)
				l.SetAttrNotInSymbolTable(i, true)
				buf.WriteString(name[9:])
				for p := l.Reachparent[i]; p != 0; p = l.Reachparent[p] {
					buf.WriteString("\t")
					buf.WriteString(l.SymName(p))
				}
				buf.WriteString("\n")
			}
		}
	}
	l.Reachparent = nil // we are done with it
	if *flagFieldTrack == "" {
		return
	}
	s := l.Lookup(*flagFieldTrack, 0)
	if s == 0 || !l.AttrReachable(s) {
		return
	}
	bld := l.MakeSymbolUpdater(s)
	bld.SetType(sym.SDATA)
	addstrdata(arch, l, *flagFieldTrack, buf.String())
}

func (ctxt *Link) addexport() {
	// Track undefined external symbols during external link.
	if ctxt.LinkMode == LinkExternal {
		for _, s := range ctxt.Textp {
			if ctxt.loader.AttrSpecial(s) || ctxt.loader.AttrSubSymbol(s) {
				continue
			}
			relocs := ctxt.loader.Relocs(s)
			for i := 0; i < relocs.Count(); i++ {
				if rs := relocs.At(i).Sym(); rs != 0 {
					if ctxt.loader.SymType(rs) == sym.Sxxx && !ctxt.loader.AttrLocal(rs) {
						// sanity check
						if len(ctxt.loader.Data(rs)) != 0 {
							panic("expected no data on undef symbol")
						}
						su := ctxt.loader.MakeSymbolUpdater(rs)
						su.SetType(sym.SUNDEFEXT)
					}
				}
			}
		}
	}

	// TODO(aix)
	if ctxt.HeadType == objabi.Hdarwin || ctxt.HeadType == objabi.Haix {
		return
	}

	// Add dynamic symbols.
	for _, s := range ctxt.dynexp {
		// Consistency check.
		if !ctxt.loader.AttrReachable(s) {
			panic("dynexp entry not reachable")
		}

		Adddynsym(ctxt.loader, &ctxt.Target, &ctxt.ArchSyms, s)
	}

	for _, lib := range dedupLibraries(ctxt, dynlib) {
		adddynlib(ctxt, lib)
	}
}
```