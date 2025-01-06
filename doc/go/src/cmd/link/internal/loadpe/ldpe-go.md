Response:
Let's break down the thought process for analyzing the `ldpe.go` file.

1. **Understand the Context:** The file path `go/src/cmd/link/internal/loadpe/ldpe.go` immediately tells us this is part of the Go linker (`cmd/link`). Specifically, it's within the `loadpe` package, suggesting its purpose is related to loading Portable Executable (PE) files. PE files are the standard executable format on Windows.

2. **Initial Code Scan - Imports:**  Look at the `import` statements. This gives a high-level overview of the functionalities involved:
    * `bytes`, `encoding/binary`, `errors`, `fmt`, `io`, `strings`: Standard Go libraries for basic data handling, binary parsing, error management, formatting, input/output, and string manipulation.
    * `cmd/internal/bio`: Likely a custom buffered I/O implementation within the Go toolchain.
    * `cmd/internal/objabi`:  Deals with object file ABI (Application Binary Interface) details, like relocation types.
    * `cmd/internal/sys`: Provides system-related information, particularly architecture details.
    * `cmd/link/internal/loader`: The core of the linker, responsible for managing symbols and sections.
    * `cmd/link/internal/sym`: Defines symbol types and attributes used in the linker.
    * `debug/pe`: A standard Go library for parsing PE files.

3. **Constants Analysis:** Examine the declared constants. These are often crucial for understanding the file format being handled.
    * `IMAGE_SYM_*`, `IMAGE_REL_*`:  These prefixes strongly suggest definitions related to PE/COFF symbol table entries and relocation types. Cross-referencing with PE/COFF documentation (or even just searching for these constants online) confirms this. The sheer number of them indicates a detailed understanding and handling of various PE features.
    * `CreateImportStubPltToken`, `RedirectToDynImportGotToken`: These suggest specific linker-related tokens for handling DLL imports. The comments provide valuable context here about how they are used during linking.

4. **Struct Analysis:**  Identify the key data structures:
    * `peBiobuf`: A wrapper around `bio.Reader` to implement `io.ReaderAt`. This points to the need for random access to the PE file data.
    * `peImportSymsState`:  Manages the state of DLL import symbols encountered across multiple object files. This suggests a need to handle inter-object dependencies related to imports.
    * `peLoaderState`: Holds per-PE file loading state, including the `loader.Loader`, architecture, the parsed `pe.File`, section symbols, and COMDAT information. This struct encapsulates the context for loading a single PE file.
    * `Symbols`:  Aggregates important symbols loaded from the PE file (text, resources, PData, XData). This represents the output of the loading process.

5. **Function Analysis - `Load` function:** This is the most important function. Its signature `Load(l *loader.Loader, arch *sys.Arch, localSymVersion int, input *bio.Reader, pkg string, length int64, pn string) (*Symbols, error)` reveals its primary purpose: to load a PE file (`pn`) from the given `input` using the provided linker (`l`) and architecture (`arch`).
    * **Step-by-step walkthrough:** Read through the `Load` function's logic. Notice the key operations:
        * Creating `peLoaderState`.
        * Using `pe.NewFile` to parse the PE structure.
        * Iterating through sections and creating linker symbols. Pay attention to how section characteristics are mapped to linker symbol types (e.g., `.text` to `sym.STEXT`).
        * Handling COMDAT sections through `preprocessSymbols`.
        * Processing relocations, which involves iterating through relocation entries and creating corresponding linker relocations. The switch statements based on `arch.Family` and `r.Type` are crucial for understanding how different architectures and relocation types are handled.
        * Processing COFF symbols and creating linker symbols.
        * Sorting symbols and adding to the `ls.Textp`.
        * Calling `processSEH` (which is not defined in the provided snippet but its name suggests it handles Structured Exception Handling).

6. **Function Analysis - Other Functions:** Examine the purpose of other functions:
    * `makeUpdater`:  Lazy creation of `loader.SymbolBuilder`.
    * `createImportSymsState`: Initializes the global `importSymsState`.
    * `PostProcessImports`:  Handles post-processing of DLL import symbols, addressing issues with modern compilers. The logic involving `SDYNIMPORT` and `__imp_` prefixes is key.
    * `issehsect`, `issect`: Helper functions to identify specific section types.
    * `readpesym`: Reads a COFF symbol and creates a corresponding linker symbol. The handling of name mangling (e.g., removing leading underscores) is notable.
    * `preprocessSymbols`: Collects information about COMDAT sections and symbols.
    * `LookupBaseFromImport`: Resolves the underlying symbol for an import symbol (e.g., resolves `__imp_CreateEventA` to `CreateEventA`).

7. **Inferring Functionality:** Based on the analysis above, it becomes clear that `ldpe.go` is responsible for:
    * **Parsing PE files:**  Using the `debug/pe` package.
    * **Creating linker symbols:** Representing PE sections and symbols within the linker's internal data structures.
    * **Processing relocations:** Applying fixups required to link the PE file.
    * **Handling COMDAT:** Managing duplicate symbols across different object files.
    * **Managing DLL imports:**  Addressing complexities introduced by modern compilers.
    * **Supporting multiple architectures:**  With specific relocation handling for x86, AMD64, ARM, and ARM64.

8. **Code Example - DLL Import Handling:**  Focus on the `PostProcessImports` function and the constants related to import handling. This suggests an example involving a function imported from a DLL.

9. **Command-Line Arguments:**  The `Load` function doesn't directly parse command-line arguments. However, the presence of parameters like `pkg` hints at how this code might be used within a larger context where package information is available (likely from the `go build` or `go link` process).

10. **Common Mistakes:** Think about potential errors a user of this *internal* package might make (though direct usage is unlikely). The complexity of handling relocations and symbol types suggests that incorrect interpretation or handling of PE structures could lead to errors. The DLL import post-processing also seems like an area where subtle issues could arise.

This systematic approach of examining imports, constants, structs, and functions, combined with understanding the overall context of the Go linker and PE file format, allows for a comprehensive understanding of the `ldpe.go` file's functionality.
`go/src/cmd/link/internal/loadpe/ldpe.go` 是 Go 语言链接器 (`cmd/link`) 中负责加载 PE (Portable Executable) 和 COFF (Common Object File Format) 文件的模块。PE 格式是 Windows 操作系统上可执行文件和动态链接库的标准格式，COFF 格式则是一种更通用的目标文件格式，PE 格式在很大程度上基于 COFF。

以下是 `ldpe.go` 的主要功能：

1. **读取 PE/COFF 文件结构:** 该代码使用 `debug/pe` 标准库来解析 PE/COFF 文件的头部、节区表、符号表、重定位信息等结构。

2. **创建链接器符号 (loader.Sym):**  对于 PE/COFF 文件中的各种实体（如节区、导出的函数、全局变量等），`ldpe.go` 会在链接器的内部数据结构中创建相应的符号 (`loader.Sym`)。这些符号是链接过程中进行地址解析、重定位等操作的基础。

3. **加载节区数据:** 它会读取 PE/COFF 文件中各个节区的数据，并将其存储在链接器符号中，以便后续链接器可以将这些数据组合成最终的可执行文件。

4. **处理重定位信息:**  PE/COFF 文件包含重定位信息，指示在链接时需要修改的地址。`ldpe.go` 会读取这些信息，并在链接过程中根据目标地址更新这些位置的值。它支持多种架构 (x86, AMD64, ARM, ARM64) 的不同重定位类型。

5. **处理 COMDAT (COMDAT Data):** COMDAT 是一种机制，允许在多个目标文件中定义相同的符号，链接器会选择其中一个定义，并丢弃其他的。`ldpe.go` 负责识别和处理 COMDAT 节区和符号。

6. **处理 DLL 导入符号:**  当链接一个依赖于 DLL 的程序时，PE/COFF 文件中会包含导入符号，指示需要从哪些 DLL 中导入哪些函数或变量。`ldpe.go` 负责识别和处理这些导入符号，并在链接过程中创建必要的引用。

7. **支持 Structured Exception Handling (SEH):**  对于支持 SEH 的架构 (如 AMD64)，`ldpe.go` 会处理 `.pdata` 和 `.xdata` 节区，这些节区包含了 SEH 相关的信息。

**它是什么 Go 语言功能的实现？**

`ldpe.go` 实现了 Go 语言链接器加载和处理 PE/COFF 目标文件的功能。这是 Go 语言工具链中 `go build` 和 `go link` 命令的关键部分，用于将 Go 代码和 C/C++ 代码（通过 cgo）编译生成 Windows 可执行文件和动态链接库。

**Go 代码举例说明:**

虽然 `ldpe.go` 本身是链接器的一部分，不直接被用户代码调用，但我们可以模拟链接器在处理 PE 文件时可能涉及的一些操作。假设我们有一个简单的 C 文件 `hello.c`：

```c
// hello.c
#include <stdio.h>

int global_var = 10;

int add(int a, int b) {
  return a + b;
}
```

将 `hello.c` 编译成目标文件 `hello.o` (或在 Windows 上是 `hello.obj`)。当 Go 链接器处理这个目标文件时，`ldpe.go` 会执行以下类似的操作：

**假设输入:**  `ldpe.go` 接收到表示 `hello.o` 文件的 `bio.Reader`。

**模拟 `ldpe.go` 中的部分逻辑:**

```go
package main

import (
	"bytes"
	"cmd/internal/objabi"
	"cmd/link/internal/loader"
	"cmd/link/internal/sym"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"log"
	"os"
)

func main() {
	// 模拟读取目标文件 (假设已经读取到内存)
	objData, err := os.ReadFile("hello.o") // 或者 hello.obj
	if err != nil {
		log.Fatal(err)
	}
	reader := bytes.NewReader(objData)

	// 模拟链接器的 loader
	l := loader.NewLoader() // 实际的 loader 初始化更复杂

	// 模拟架构信息
	arch := &objabi.LinkArch{
		Name:   "amd64", // 假设是 AMD64 架构
		Family: objabi.AMD64,
	}

	// 模拟 peLoaderState (部分)
	// 在真实的 ldpe.go 中，这个结构体会被完整填充
	state := &peLoaderState{
		l:    l,
		arch: arch,
		// ... 其他字段
	}

	// 模拟解析 PE 文件头和节区表
	peFile, err := pe.NewReader(reader)
	if err != nil {
		log.Fatal(err)
	}
	defer peFile.Close()

	// 模拟创建节区符号
	for _, sect := range peFile.Sections {
		name := fmt.Sprintf("hello.o(%s)", sect.Name)
		s := l.CreateSymForUpdate(name, true) // 创建一个符号
		if sect.Characteristics&pe.IMAGE_SCN_CNT_CODE != 0 {
			s.SetType(sym.STEXT)
		} else if sect.Characteristics&pe.IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
			s.SetType(sym.SNOPTRDATA)
		}
		// ... 设置其他属性
		fmt.Printf("创建节区符号: %s, 类型: %v\n", name, s.Type())
	}

	// 模拟读取符号表 (部分)
	for _, symbol := range peFile.COFFSymbols {
		symName, _ := symbol.FullName(peFile.StringTable)
		if symName == "global_var" || symName == "add" {
			s := l.CreateSymForUpdate(symName, true)
			if symName == "add" {
				s.SetType(sym.STEXT)
			} else {
				s.SetType(sym.SNOPTRDATA)
			}
			fmt.Printf("创建符号: %s, 类型: %v\n", symName, s.Type())
		}
	}

	// ... 模拟处理重定位等其他操作
}

// peLoaderState 结构体 (简化)
type peLoaderState struct {
	l    *loader.Loader
	arch *objabi.LinkArch
	// ...
}
```

**假设输出:**

```
创建节区符号: hello.o(.text), 类型: STEXT
创建节区符号: hello.o(.data), 类型: SNOPTRDATA
创建符号: global_var, 类型: SNOPTRDATA
创建符号: add, 类型: STEXT
```

**注意:** 这只是一个简化的示例，真实的 `ldpe.go` 的逻辑要复杂得多，涉及到更详细的 PE/COFF 结构解析和链接器的内部操作。

**命令行参数的具体处理:**

`ldpe.go` 本身并不直接处理命令行参数。命令行参数的处理发生在 `cmd/link` 包的其他部分，例如 `main.go` 或相关的参数解析逻辑中。

当 `go build` 或 `go link` 命令执行时，会解析命令行参数，并根据参数调用相应的链接器功能。`ldpe.go` 会被 `cmd/link` 的主逻辑调用，接收已经处理过的文件路径等信息。

例如，当链接器需要加载一个 PE 格式的目标文件时，它会将文件路径传递给 `ldpe.Load` 函数。`ldpe.Load` 函数接收的参数包括：

* `l *loader.Loader`:  链接器的主对象，用于创建和管理符号。
* `arch *sys.Arch`:  目标架构的信息。
* `localSymVersion int`:  用于区分本地符号的版本。
* `input *bio.Reader`:  表示要加载的 PE 文件的输入流。
* `pkg string`:  当前正在链接的包的名称。
* `length int64`:  输入流的长度。
* `pn string`:  PE 文件的路径名称。

这些参数通常是在命令行参数解析和文件查找等步骤之后确定的。

**使用者易犯错的点 (通常是 `cgo` 使用者或编写底层工具的开发者):**

由于 `ldpe.go` 是链接器内部模块，普通 Go 开发者不会直接使用它。然而，在使用 `cgo` 调用 C/C++ 代码时，或者在编写与链接过程相关的底层工具时，可能会遇到一些与 PE/COFF 加载相关的错误。

1. **不正确的 C/C++ 代码编译选项:** 如果 C/C++ 代码编译生成的目标文件格式不符合 PE/COFF 规范，或者与目标架构不匹配，链接器在加载时可能会报错。例如，使用了不兼容的 ABI 或生成了错误的重定位信息。

2. **符号冲突:**  如果多个目标文件中定义了相同的全局符号，且没有使用 COMDAT 或其他机制来解决冲突，链接器会报错。

3. **DLL 导入问题:**  在使用 `cgo` 链接 DLL 时，如果导入符号的定义不正确，或者依赖的 DLL 没有找到，链接器可能会报错。例如，函数名拼写错误、调用约定不匹配等。

4. **SEH 相关错误 (对于使用 SEH 的 C++ 代码):** 如果 C++ 代码使用了异常处理，但目标文件中的 SEH 信息不正确，链接器或运行时可能会出现错误。

**举例说明易犯错的点:**

假设有一个使用了 `cgo` 的 Go 程序，它链接了一个包含全局变量的 C 库。如果 C 代码编译时没有正确导出全局变量，或者导出的名称与 Go 代码中引用的名称不一致，链接器在加载目标文件时可能会找不到该符号。

**C 代码 (mylib.c):**

```c
// mylib.c
int my_global_var = 123;
```

**Go 代码 (main.go):**

```go
package main

/*
#cgo LDFLAGS: -lmylib
extern int my_global_var;
*/
import "C"
import "fmt"

func main() {
	fmt.Println(C.my_global_var)
}
```

如果在编译 `mylib.c` 时，没有使用正确的选项来导出 `my_global_var`，或者链接器在加载 `mylib.o` 时无法找到 `my_global_var` 的定义，就会导致链接错误。 错误信息可能类似于 "undefined symbol: my_global_var"。

总结来说，`go/src/cmd/link/internal/loadpe/ldpe.go` 是 Go 语言链接器中至关重要的模块，负责解析和加载 PE/COFF 格式的目标文件，为后续的链接过程提供必要的信息和数据。虽然普通 Go 开发者不会直接使用它，但理解其功能有助于理解 Go 语言与 C/C++ 代码的互操作性以及 Windows 平台下可执行文件的生成过程。

Prompt: 
```
这是路径为go/src/cmd/link/internal/loadpe/ldpe.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package loadpe implements a PE/COFF file reader.
package loadpe

import (
	"bytes"
	"cmd/internal/bio"
	"cmd/internal/objabi"
	"cmd/internal/sys"
	"cmd/link/internal/loader"
	"cmd/link/internal/sym"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	IMAGE_SYM_UNDEFINED              = 0
	IMAGE_SYM_ABSOLUTE               = -1
	IMAGE_SYM_DEBUG                  = -2
	IMAGE_SYM_TYPE_NULL              = 0
	IMAGE_SYM_TYPE_VOID              = 1
	IMAGE_SYM_TYPE_CHAR              = 2
	IMAGE_SYM_TYPE_SHORT             = 3
	IMAGE_SYM_TYPE_INT               = 4
	IMAGE_SYM_TYPE_LONG              = 5
	IMAGE_SYM_TYPE_FLOAT             = 6
	IMAGE_SYM_TYPE_DOUBLE            = 7
	IMAGE_SYM_TYPE_STRUCT            = 8
	IMAGE_SYM_TYPE_UNION             = 9
	IMAGE_SYM_TYPE_ENUM              = 10
	IMAGE_SYM_TYPE_MOE               = 11
	IMAGE_SYM_TYPE_BYTE              = 12
	IMAGE_SYM_TYPE_WORD              = 13
	IMAGE_SYM_TYPE_UINT              = 14
	IMAGE_SYM_TYPE_DWORD             = 15
	IMAGE_SYM_TYPE_PCODE             = 32768
	IMAGE_SYM_DTYPE_NULL             = 0
	IMAGE_SYM_DTYPE_POINTER          = 1
	IMAGE_SYM_DTYPE_FUNCTION         = 2
	IMAGE_SYM_DTYPE_ARRAY            = 3
	IMAGE_SYM_CLASS_END_OF_FUNCTION  = -1
	IMAGE_SYM_CLASS_NULL             = 0
	IMAGE_SYM_CLASS_AUTOMATIC        = 1
	IMAGE_SYM_CLASS_EXTERNAL         = 2
	IMAGE_SYM_CLASS_STATIC           = 3
	IMAGE_SYM_CLASS_REGISTER         = 4
	IMAGE_SYM_CLASS_EXTERNAL_DEF     = 5
	IMAGE_SYM_CLASS_LABEL            = 6
	IMAGE_SYM_CLASS_UNDEFINED_LABEL  = 7
	IMAGE_SYM_CLASS_MEMBER_OF_STRUCT = 8
	IMAGE_SYM_CLASS_ARGUMENT         = 9
	IMAGE_SYM_CLASS_STRUCT_TAG       = 10
	IMAGE_SYM_CLASS_MEMBER_OF_UNION  = 11
	IMAGE_SYM_CLASS_UNION_TAG        = 12
	IMAGE_SYM_CLASS_TYPE_DEFINITION  = 13
	IMAGE_SYM_CLASS_UNDEFINED_STATIC = 14
	IMAGE_SYM_CLASS_ENUM_TAG         = 15
	IMAGE_SYM_CLASS_MEMBER_OF_ENUM   = 16
	IMAGE_SYM_CLASS_REGISTER_PARAM   = 17
	IMAGE_SYM_CLASS_BIT_FIELD        = 18
	IMAGE_SYM_CLASS_FAR_EXTERNAL     = 68 /* Not in PECOFF v8 spec */
	IMAGE_SYM_CLASS_BLOCK            = 100
	IMAGE_SYM_CLASS_FUNCTION         = 101
	IMAGE_SYM_CLASS_END_OF_STRUCT    = 102
	IMAGE_SYM_CLASS_FILE             = 103
	IMAGE_SYM_CLASS_SECTION          = 104
	IMAGE_SYM_CLASS_WEAK_EXTERNAL    = 105
	IMAGE_SYM_CLASS_CLR_TOKEN        = 107
	IMAGE_REL_I386_ABSOLUTE          = 0x0000
	IMAGE_REL_I386_DIR16             = 0x0001
	IMAGE_REL_I386_REL16             = 0x0002
	IMAGE_REL_I386_DIR32             = 0x0006
	IMAGE_REL_I386_DIR32NB           = 0x0007
	IMAGE_REL_I386_SEG12             = 0x0009
	IMAGE_REL_I386_SECTION           = 0x000A
	IMAGE_REL_I386_SECREL            = 0x000B
	IMAGE_REL_I386_TOKEN             = 0x000C
	IMAGE_REL_I386_SECREL7           = 0x000D
	IMAGE_REL_I386_REL32             = 0x0014
	IMAGE_REL_AMD64_ABSOLUTE         = 0x0000
	IMAGE_REL_AMD64_ADDR64           = 0x0001
	IMAGE_REL_AMD64_ADDR32           = 0x0002
	IMAGE_REL_AMD64_ADDR32NB         = 0x0003
	IMAGE_REL_AMD64_REL32            = 0x0004
	IMAGE_REL_AMD64_REL32_1          = 0x0005
	IMAGE_REL_AMD64_REL32_2          = 0x0006
	IMAGE_REL_AMD64_REL32_3          = 0x0007
	IMAGE_REL_AMD64_REL32_4          = 0x0008
	IMAGE_REL_AMD64_REL32_5          = 0x0009
	IMAGE_REL_AMD64_SECTION          = 0x000A
	IMAGE_REL_AMD64_SECREL           = 0x000B
	IMAGE_REL_AMD64_SECREL7          = 0x000C
	IMAGE_REL_AMD64_TOKEN            = 0x000D
	IMAGE_REL_AMD64_SREL32           = 0x000E
	IMAGE_REL_AMD64_PAIR             = 0x000F
	IMAGE_REL_AMD64_SSPAN32          = 0x0010
	IMAGE_REL_ARM_ABSOLUTE           = 0x0000
	IMAGE_REL_ARM_ADDR32             = 0x0001
	IMAGE_REL_ARM_ADDR32NB           = 0x0002
	IMAGE_REL_ARM_BRANCH24           = 0x0003
	IMAGE_REL_ARM_BRANCH11           = 0x0004
	IMAGE_REL_ARM_SECTION            = 0x000E
	IMAGE_REL_ARM_SECREL             = 0x000F
	IMAGE_REL_ARM_MOV32              = 0x0010
	IMAGE_REL_THUMB_MOV32            = 0x0011
	IMAGE_REL_THUMB_BRANCH20         = 0x0012
	IMAGE_REL_THUMB_BRANCH24         = 0x0014
	IMAGE_REL_THUMB_BLX23            = 0x0015
	IMAGE_REL_ARM_PAIR               = 0x0016
	IMAGE_REL_ARM64_ABSOLUTE         = 0x0000
	IMAGE_REL_ARM64_ADDR32           = 0x0001
	IMAGE_REL_ARM64_ADDR32NB         = 0x0002
	IMAGE_REL_ARM64_BRANCH26         = 0x0003
	IMAGE_REL_ARM64_PAGEBASE_REL21   = 0x0004
	IMAGE_REL_ARM64_REL21            = 0x0005
	IMAGE_REL_ARM64_PAGEOFFSET_12A   = 0x0006
	IMAGE_REL_ARM64_PAGEOFFSET_12L   = 0x0007
	IMAGE_REL_ARM64_SECREL           = 0x0008
	IMAGE_REL_ARM64_SECREL_LOW12A    = 0x0009
	IMAGE_REL_ARM64_SECREL_HIGH12A   = 0x000A
	IMAGE_REL_ARM64_SECREL_LOW12L    = 0x000B
	IMAGE_REL_ARM64_TOKEN            = 0x000C
	IMAGE_REL_ARM64_SECTION          = 0x000D
	IMAGE_REL_ARM64_ADDR64           = 0x000E
	IMAGE_REL_ARM64_BRANCH19         = 0x000F
	IMAGE_REL_ARM64_BRANCH14         = 0x0010
	IMAGE_REL_ARM64_REL32            = 0x0011
)

const (
	// When stored into the PLT value for a symbol, this token tells
	// windynrelocsym to redirect direct references to this symbol to a stub
	// that loads from the corresponding import symbol and then does
	// a jump to the loaded value.
	CreateImportStubPltToken = -2

	// When stored into the GOT value for an import symbol __imp_X this
	// token tells windynrelocsym to redirect references to the
	// underlying DYNIMPORT symbol X.
	RedirectToDynImportGotToken = -2
)

// TODO(brainman): maybe just add ReadAt method to bio.Reader instead of creating peBiobuf

// peBiobuf makes bio.Reader look like io.ReaderAt.
type peBiobuf bio.Reader

func (f *peBiobuf) ReadAt(p []byte, off int64) (int, error) {
	ret := ((*bio.Reader)(f)).MustSeek(off, 0)
	if ret < 0 {
		return 0, errors.New("fail to seek")
	}
	n, err := f.Read(p)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// makeUpdater creates a loader.SymbolBuilder if one hasn't been created previously.
// We use this to lazily make SymbolBuilders as we don't always need a builder, and creating them for all symbols might be an error.
func makeUpdater(l *loader.Loader, bld *loader.SymbolBuilder, s loader.Sym) *loader.SymbolBuilder {
	if bld != nil {
		return bld
	}
	bld = l.MakeSymbolUpdater(s)
	return bld
}

// peImportSymsState tracks the set of DLL import symbols we've seen
// while reading host objects. We create a singleton instance of this
// type, which will persist across multiple host objects.
type peImportSymsState struct {

	// Text and non-text sections read in by the host object loader.
	secSyms []loader.Sym

	// Loader and arch, for use in postprocessing.
	l    *loader.Loader
	arch *sys.Arch
}

var importSymsState *peImportSymsState

func createImportSymsState(l *loader.Loader, arch *sys.Arch) {
	if importSymsState != nil {
		return
	}
	importSymsState = &peImportSymsState{
		l:    l,
		arch: arch,
	}
}

// peLoaderState holds various bits of useful state information needed
// while loading a single PE object file.
type peLoaderState struct {
	l               *loader.Loader
	arch            *sys.Arch
	f               *pe.File
	pn              string
	sectsyms        map[*pe.Section]loader.Sym
	comdats         map[uint16]int64 // key is section index, val is size
	sectdata        map[*pe.Section][]byte
	localSymVersion int
}

// comdatDefinitions records the names of symbols for which we've
// previously seen a definition in COMDAT. Key is symbol name, value
// is symbol size (or -1 if we're using the "any" strategy).
var comdatDefinitions map[string]int64

// Symbols contains the symbols that can be loaded from a PE file.
type Symbols struct {
	Textp     []loader.Sym // text symbols
	Resources []loader.Sym // .rsrc section or set of .rsrc$xx sections
	PData     loader.Sym
	XData     loader.Sym
}

// Load loads the PE file pn from input.
// Symbols from the object file are created via the loader 'l'.
func Load(l *loader.Loader, arch *sys.Arch, localSymVersion int, input *bio.Reader, pkg string, length int64, pn string) (*Symbols, error) {
	state := &peLoaderState{
		l:               l,
		arch:            arch,
		sectsyms:        make(map[*pe.Section]loader.Sym),
		sectdata:        make(map[*pe.Section][]byte),
		localSymVersion: localSymVersion,
		pn:              pn,
	}
	createImportSymsState(state.l, state.arch)
	if comdatDefinitions == nil {
		comdatDefinitions = make(map[string]int64)
	}

	// Some input files are archives containing multiple of
	// object files, and pe.NewFile seeks to the start of
	// input file and get confused. Create section reader
	// to stop pe.NewFile looking before current position.
	sr := io.NewSectionReader((*peBiobuf)(input), input.Offset(), 1<<63-1)

	// TODO: replace pe.NewFile with pe.Load (grep for "add Load function" in debug/pe for details)
	f, err := pe.NewFile(sr)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	state.f = f

	var ls Symbols

	// TODO return error if found .cormeta

	// create symbols for mapped sections
	for _, sect := range f.Sections {
		if sect.Characteristics&pe.IMAGE_SCN_MEM_DISCARDABLE != 0 {
			continue
		}

		if sect.Characteristics&(pe.IMAGE_SCN_CNT_CODE|pe.IMAGE_SCN_CNT_INITIALIZED_DATA|pe.IMAGE_SCN_CNT_UNINITIALIZED_DATA) == 0 {
			// This has been seen for .idata sections, which we
			// want to ignore. See issues 5106 and 5273.
			continue
		}

		name := fmt.Sprintf("%s(%s)", pkg, sect.Name)
		s := state.l.LookupOrCreateCgoExport(name, localSymVersion)
		bld := l.MakeSymbolUpdater(s)

		switch sect.Characteristics & (pe.IMAGE_SCN_CNT_UNINITIALIZED_DATA | pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_WRITE | pe.IMAGE_SCN_CNT_CODE | pe.IMAGE_SCN_MEM_EXECUTE) {
		case pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ: //.rdata
			if issehsect(arch, sect) {
				bld.SetType(sym.SSEHSECT)
				bld.SetAlign(4)
			} else {
				bld.SetType(sym.SRODATA)
			}

		case pe.IMAGE_SCN_CNT_UNINITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_WRITE: //.bss
			bld.SetType(sym.SNOPTRBSS)

		case pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ | pe.IMAGE_SCN_MEM_WRITE: //.data
			bld.SetType(sym.SNOPTRDATA)

		case pe.IMAGE_SCN_CNT_CODE | pe.IMAGE_SCN_MEM_EXECUTE | pe.IMAGE_SCN_MEM_READ: //.text
			bld.SetType(sym.STEXT)

		default:
			return nil, fmt.Errorf("unexpected flags %#06x for PE section %s", sect.Characteristics, sect.Name)
		}

		if bld.Type() != sym.SNOPTRBSS {
			data, err := sect.Data()
			if err != nil {
				return nil, err
			}
			state.sectdata[sect] = data
			bld.SetData(data)
		}
		bld.SetSize(int64(sect.Size))
		state.sectsyms[sect] = s
		if sect.Name == ".rsrc" || strings.HasPrefix(sect.Name, ".rsrc$") {
			ls.Resources = append(ls.Resources, s)
		} else if bld.Type() == sym.SSEHSECT {
			if sect.Name == ".pdata" {
				ls.PData = s
			} else if sect.Name == ".xdata" {
				ls.XData = s
			}
		}
	}

	// Make a prepass over the symbols to collect info about COMDAT symbols.
	if err := state.preprocessSymbols(); err != nil {
		return nil, err
	}

	// load relocations
	for _, rsect := range f.Sections {
		if _, found := state.sectsyms[rsect]; !found {
			continue
		}
		if rsect.NumberOfRelocations == 0 {
			continue
		}
		if rsect.Characteristics&pe.IMAGE_SCN_MEM_DISCARDABLE != 0 {
			continue
		}
		if rsect.Characteristics&(pe.IMAGE_SCN_CNT_CODE|pe.IMAGE_SCN_CNT_INITIALIZED_DATA|pe.IMAGE_SCN_CNT_UNINITIALIZED_DATA) == 0 {
			// This has been seen for .idata sections, which we
			// want to ignore. See issues 5106 and 5273.
			continue
		}

		splitResources := strings.HasPrefix(rsect.Name, ".rsrc$")
		issehsect := issehsect(arch, rsect)
		sb := l.MakeSymbolUpdater(state.sectsyms[rsect])
		for j, r := range rsect.Relocs {
			if int(r.SymbolTableIndex) >= len(f.COFFSymbols) {
				return nil, fmt.Errorf("relocation number %d symbol index idx=%d cannot be large then number of symbols %d", j, r.SymbolTableIndex, len(f.COFFSymbols))
			}
			pesym := &f.COFFSymbols[r.SymbolTableIndex]
			_, gosym, err := state.readpesym(pesym)
			if err != nil {
				return nil, err
			}
			if gosym == 0 {
				name, err := pesym.FullName(f.StringTable)
				if err != nil {
					name = string(pesym.Name[:])
				}
				return nil, fmt.Errorf("reloc of invalid sym %s idx=%d type=%d", name, r.SymbolTableIndex, pesym.Type)
			}

			rSym := gosym
			rSize := uint8(4)
			rOff := int32(r.VirtualAddress)
			var rAdd int64
			var rType objabi.RelocType
			switch arch.Family {
			default:
				return nil, fmt.Errorf("%s: unsupported arch %v", pn, arch.Family)
			case sys.I386, sys.AMD64:
				switch r.Type {
				default:
					return nil, fmt.Errorf("%s: %v: unknown relocation type %v", pn, state.sectsyms[rsect], r.Type)

				case IMAGE_REL_I386_REL32, IMAGE_REL_AMD64_REL32,
					IMAGE_REL_AMD64_ADDR32, // R_X86_64_PC32
					IMAGE_REL_AMD64_ADDR32NB:
					if r.Type == IMAGE_REL_AMD64_ADDR32NB {
						rType = objabi.R_PEIMAGEOFF
					} else {
						rType = objabi.R_PCREL
					}

					rAdd = int64(int32(binary.LittleEndian.Uint32(state.sectdata[rsect][rOff:])))

				case IMAGE_REL_I386_DIR32NB, IMAGE_REL_I386_DIR32:
					if r.Type == IMAGE_REL_I386_DIR32NB {
						rType = objabi.R_PEIMAGEOFF
					} else {
						rType = objabi.R_ADDR
					}

					// load addend from image
					rAdd = int64(int32(binary.LittleEndian.Uint32(state.sectdata[rsect][rOff:])))

				case IMAGE_REL_AMD64_ADDR64: // R_X86_64_64
					rSize = 8

					rType = objabi.R_ADDR

					// load addend from image
					rAdd = int64(binary.LittleEndian.Uint64(state.sectdata[rsect][rOff:]))
				}

			case sys.ARM:
				switch r.Type {
				default:
					return nil, fmt.Errorf("%s: %v: unknown ARM relocation type %v", pn, state.sectsyms[rsect], r.Type)

				case IMAGE_REL_ARM_SECREL:
					rType = objabi.R_PCREL

					rAdd = int64(int32(binary.LittleEndian.Uint32(state.sectdata[rsect][rOff:])))

				case IMAGE_REL_ARM_ADDR32, IMAGE_REL_ARM_ADDR32NB:
					if r.Type == IMAGE_REL_ARM_ADDR32NB {
						rType = objabi.R_PEIMAGEOFF
					} else {
						rType = objabi.R_ADDR
					}

					rAdd = int64(int32(binary.LittleEndian.Uint32(state.sectdata[rsect][rOff:])))

				case IMAGE_REL_ARM_BRANCH24:
					rType = objabi.R_CALLARM

					rAdd = int64(int32(binary.LittleEndian.Uint32(state.sectdata[rsect][rOff:])))
				}

			case sys.ARM64:
				switch r.Type {
				default:
					return nil, fmt.Errorf("%s: %v: unknown ARM64 relocation type %v", pn, state.sectsyms[rsect], r.Type)

				case IMAGE_REL_ARM64_ADDR32, IMAGE_REL_ARM64_ADDR32NB:
					if r.Type == IMAGE_REL_ARM64_ADDR32NB {
						rType = objabi.R_PEIMAGEOFF
					} else {
						rType = objabi.R_ADDR
					}

					rAdd = int64(int32(binary.LittleEndian.Uint32(state.sectdata[rsect][rOff:])))
				}
			}

			// ld -r could generate multiple section symbols for the
			// same section but with different values, we have to take
			// that into account, or in the case of split resources,
			// the section and its symbols are split into two sections.
			if issect(pesym) || splitResources {
				rAdd += int64(pesym.Value)
			}
			if issehsect {
				// .pdata and .xdata sections can contain records
				// associated to functions that won't be used in
				// the final binary, in which case the relocation
				// target symbol won't be reachable.
				rType |= objabi.R_WEAK
			}

			rel, _ := sb.AddRel(rType)
			rel.SetOff(rOff)
			rel.SetSiz(rSize)
			rel.SetSym(rSym)
			rel.SetAdd(rAdd)

		}

		sb.SortRelocs()
	}

	// enter sub-symbols into symbol table.
	for i, numaux := 0, 0; i < len(f.COFFSymbols); i += numaux + 1 {
		pesym := &f.COFFSymbols[i]

		numaux = int(pesym.NumberOfAuxSymbols)

		name, err := pesym.FullName(f.StringTable)
		if err != nil {
			return nil, err
		}
		if name == "" {
			continue
		}
		if issect(pesym) {
			continue
		}
		if int(pesym.SectionNumber) > len(f.Sections) {
			continue
		}
		if pesym.SectionNumber == IMAGE_SYM_DEBUG {
			continue
		}
		if pesym.SectionNumber == IMAGE_SYM_ABSOLUTE && bytes.Equal(pesym.Name[:], []byte("@feat.00")) {
			// The PE documentation says that, on x86 platforms, the absolute symbol named @feat.00
			// is used to indicate that the COFF object supports SEH.
			// Go doesn't support SEH on windows/386, so we can ignore this symbol.
			// See https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-sxdata-section
			continue
		}
		var sect *pe.Section
		if pesym.SectionNumber > 0 {
			sect = f.Sections[pesym.SectionNumber-1]
			if _, found := state.sectsyms[sect]; !found {
				continue
			}
		}

		bld, s, err := state.readpesym(pesym)
		if err != nil {
			return nil, err
		}

		if pesym.SectionNumber == 0 { // extern
			if l.SymType(s) == sym.SXREF && pesym.Value > 0 { // global data
				bld = makeUpdater(l, bld, s)
				bld.SetType(sym.SNOPTRDATA)
				bld.SetSize(int64(pesym.Value))
			}

			continue
		} else if pesym.SectionNumber > 0 && int(pesym.SectionNumber) <= len(f.Sections) {
			sect = f.Sections[pesym.SectionNumber-1]
			if _, found := state.sectsyms[sect]; !found {
				return nil, fmt.Errorf("%s: %v: missing sect.sym", pn, s)
			}
		} else {
			return nil, fmt.Errorf("%s: %v: sectnum < 0!", pn, s)
		}

		if sect == nil {
			return nil, nil
		}

		// Check for COMDAT symbol.
		if sz, ok1 := state.comdats[uint16(pesym.SectionNumber-1)]; ok1 {
			if psz, ok2 := comdatDefinitions[l.SymName(s)]; ok2 {
				if sz == psz {
					//  OK to discard, we've seen an instance
					// already.
					continue
				}
			}
		}
		if l.OuterSym(s) != 0 {
			if l.AttrDuplicateOK(s) {
				continue
			}
			outerName := l.SymName(l.OuterSym(s))
			sectName := l.SymName(state.sectsyms[sect])
			return nil, fmt.Errorf("%s: duplicate symbol reference: %s in both %s and %s", pn, l.SymName(s), outerName, sectName)
		}

		bld = makeUpdater(l, bld, s)
		sectsym := state.sectsyms[sect]
		bld.SetType(l.SymType(sectsym))
		l.AddInteriorSym(sectsym, s)
		bld.SetValue(int64(pesym.Value))
		bld.SetSize(4)
		if l.SymType(sectsym).IsText() {
			if bld.External() && !bld.DuplicateOK() {
				return nil, fmt.Errorf("%s: duplicate symbol definition", l.SymName(s))
			}
			bld.SetExternal(true)
		}
		if sz, ok := state.comdats[uint16(pesym.SectionNumber-1)]; ok {
			// This is a COMDAT definition. Record that we're picking
			// this instance so that we can ignore future defs.
			if _, ok := comdatDefinitions[l.SymName(s)]; ok {
				return nil, fmt.Errorf("internal error: preexisting COMDAT definition for %q", name)
			}
			comdatDefinitions[l.SymName(s)] = sz
		}
	}

	// Sort outer lists by address, adding to textp.
	// This keeps textp in increasing address order.
	for _, sect := range f.Sections {
		s := state.sectsyms[sect]
		if s == 0 {
			continue
		}
		l.SortSub(s)
		importSymsState.secSyms = append(importSymsState.secSyms, s)
		if l.SymType(s).IsText() {
			for ; s != 0; s = l.SubSym(s) {
				if l.AttrOnList(s) {
					return nil, fmt.Errorf("symbol %s listed multiple times", l.SymName(s))
				}
				l.SetAttrOnList(s, true)
				ls.Textp = append(ls.Textp, s)
			}
		}
	}

	if ls.PData != 0 {
		processSEH(l, arch, ls.PData, ls.XData)
	}

	return &ls, nil
}

// PostProcessImports works to resolve inconsistencies with DLL import
// symbols; it is needed when building with more "modern" C compilers
// with internal linkage.
//
// Background: DLL import symbols are data (SNOPTRDATA) symbols whose
// name is of the form "__imp_XXX", which contain a pointer/reference
// to symbol XXX. It's possible to have import symbols for both data
// symbols ("__imp__fmode") and text symbols ("__imp_CreateEventA").
// In some case import symbols are just references to some external
// thing, and in other cases we see actual definitions of import
// symbols when reading host objects.
//
// Previous versions of the linker would in most cases immediately
// "forward" import symbol references, e.g. treat a references to
// "__imp_XXX" a references to "XXX", however this doesn't work well
// with more modern compilers, where you can sometimes see import
// symbols that are defs (as opposed to external refs).
//
// The main actions taken below are to search for references to
// SDYNIMPORT symbols in host object text/data sections and flag the
// symbols for later fixup. When we see a reference to an import
// symbol __imp_XYZ where XYZ corresponds to some SDYNIMPORT symbol,
// we flag the symbol (via GOT setting) so that it can be redirected
// to XYZ later in windynrelocsym. When we see a direct reference to
// an SDYNIMPORT symbol XYZ, we also flag the symbol (via PLT setting)
// to indicated that the reference will need to be redirected to a
// stub.
func PostProcessImports() error {
	ldr := importSymsState.l
	arch := importSymsState.arch
	keeprelocneeded := make(map[loader.Sym]loader.Sym)
	for _, s := range importSymsState.secSyms {
		isText := ldr.SymType(s).IsText()
		relocs := ldr.Relocs(s)
		for i := 0; i < relocs.Count(); i++ {
			r := relocs.At(i)
			rs := r.Sym()
			if ldr.SymType(rs) == sym.SDYNIMPORT {
				// Tag the symbol for later stub generation.
				ldr.SetPlt(rs, CreateImportStubPltToken)
				continue
			}
			isym, err := LookupBaseFromImport(rs, ldr, arch)
			if err != nil {
				return err
			}
			if isym == 0 {
				continue
			}
			if ldr.SymType(isym) != sym.SDYNIMPORT {
				continue
			}
			// For non-text symbols, forward the reference from __imp_X to
			// X immediately.
			if !isText {
				r.SetSym(isym)
				continue
			}
			// Flag this imp symbol to be processed later in windynrelocsym.
			ldr.SetGot(rs, RedirectToDynImportGotToken)
			// Consistency check: should be no PLT token here.
			splt := ldr.SymPlt(rs)
			if splt != -1 {
				return fmt.Errorf("internal error: import symbol %q has invalid PLT setting %d", ldr.SymName(rs), splt)
			}
			// Flag for dummy relocation.
			keeprelocneeded[rs] = isym
		}
	}
	for k, v := range keeprelocneeded {
		sb := ldr.MakeSymbolUpdater(k)
		r, _ := sb.AddRel(objabi.R_KEEP)
		r.SetSym(v)
	}
	importSymsState = nil
	return nil
}

func issehsect(arch *sys.Arch, s *pe.Section) bool {
	return arch.Family == sys.AMD64 && (s.Name == ".pdata" || s.Name == ".xdata")
}

func issect(s *pe.COFFSymbol) bool {
	return s.StorageClass == IMAGE_SYM_CLASS_STATIC && s.Type == 0 && s.Name[0] == '.'
}

func (state *peLoaderState) readpesym(pesym *pe.COFFSymbol) (*loader.SymbolBuilder, loader.Sym, error) {
	symname, err := pesym.FullName(state.f.StringTable)
	if err != nil {
		return nil, 0, err
	}
	var name string
	if issect(pesym) {
		name = state.l.SymName(state.sectsyms[state.f.Sections[pesym.SectionNumber-1]])
	} else {
		name = symname
		// A note on the "_main" exclusion below: the main routine
		// defined by the Go runtime is named "_main", not "main", so
		// when reading references to _main from a host object we want
		// to avoid rewriting "_main" to "main" in this specific
		// instance. See #issuecomment-1143698749 on #35006 for more
		// details on this problem.
		if state.arch.Family == sys.I386 && name[0] == '_' && name != "_main" && !strings.HasPrefix(name, "__imp_") {
			name = name[1:] // _Name => Name
		}
	}

	// remove last @XXX
	if i := strings.LastIndex(name, "@"); i >= 0 {
		name = name[:i]
	}

	var s loader.Sym
	var bld *loader.SymbolBuilder
	// Microsoft's PE documentation is contradictory. It says that the symbol's complex type
	// is stored in the pesym.Type most significant byte, but MSVC, LLVM, and mingw store it
	// in the 4 high bits of the less significant byte.
	switch uint8(pesym.Type&0xf0) >> 4 {
	default:
		return nil, 0, fmt.Errorf("%s: invalid symbol type %d", symname, pesym.Type)

	case IMAGE_SYM_DTYPE_FUNCTION, IMAGE_SYM_DTYPE_NULL:
		switch pesym.StorageClass {
		case IMAGE_SYM_CLASS_EXTERNAL: //global
			s = state.l.LookupOrCreateCgoExport(name, 0)

		case IMAGE_SYM_CLASS_NULL, IMAGE_SYM_CLASS_STATIC, IMAGE_SYM_CLASS_LABEL:
			s = state.l.LookupOrCreateCgoExport(name, state.localSymVersion)
			bld = makeUpdater(state.l, bld, s)
			bld.SetDuplicateOK(true)

		default:
			return nil, 0, fmt.Errorf("%s: invalid symbol binding %d", symname, pesym.StorageClass)
		}
	}

	if s != 0 && state.l.SymType(s) == 0 && (pesym.StorageClass != IMAGE_SYM_CLASS_STATIC || pesym.Value != 0) {
		bld = makeUpdater(state.l, bld, s)
		bld.SetType(sym.SXREF)
	}

	return bld, s, nil
}

// preprocessSymbols walks the COFF symbols for the PE file we're
// reading and looks for cases where we have both a symbol definition
// for "XXX" and an "__imp_XXX" symbol, recording these cases in a map
// in the state struct. This information will be used in readpesym()
// above to give such symbols special treatment. This function also
// gathers information about COMDAT sections/symbols for later use
// in readpesym().
func (state *peLoaderState) preprocessSymbols() error {

	// Locate comdat sections.
	state.comdats = make(map[uint16]int64)
	for i, s := range state.f.Sections {
		if s.Characteristics&uint32(pe.IMAGE_SCN_LNK_COMDAT) != 0 {
			state.comdats[uint16(i)] = int64(s.Size)
		}
	}

	// Examine symbol defs.
	for i, numaux := 0, 0; i < len(state.f.COFFSymbols); i += numaux + 1 {
		pesym := &state.f.COFFSymbols[i]
		numaux = int(pesym.NumberOfAuxSymbols)
		if pesym.SectionNumber == 0 { // extern
			continue
		}
		symname, err := pesym.FullName(state.f.StringTable)
		if err != nil {
			return err
		}
		if _, isc := state.comdats[uint16(pesym.SectionNumber-1)]; !isc {
			continue
		}
		if pesym.StorageClass != uint8(IMAGE_SYM_CLASS_STATIC) {
			continue
		}
		// This symbol corresponds to a COMDAT section. Read the
		// aux data for it.
		auxsymp, err := state.f.COFFSymbolReadSectionDefAux(i)
		if err != nil {
			return fmt.Errorf("unable to read aux info for section def symbol %d %s: pe.COFFSymbolReadComdatInfo returns %v", i, symname, err)
		}
		if auxsymp.Selection == pe.IMAGE_COMDAT_SELECT_SAME_SIZE {
			// This is supported.
		} else if auxsymp.Selection == pe.IMAGE_COMDAT_SELECT_ANY {
			// Also supported.
			state.comdats[uint16(pesym.SectionNumber-1)] = int64(-1)
		} else {
			// We don't support any of the other strategies at the
			// moment. I suspect that we may need to also support
			// "associative", we'll see.
			return fmt.Errorf("internal error: unsupported COMDAT selection strategy found in path=%s sec=%d strategy=%d idx=%d, please file a bug", state.pn, auxsymp.SecNum, auxsymp.Selection, i)
		}
	}
	return nil
}

// LookupBaseFromImport examines the symbol "s" to see if it
// corresponds to an import symbol (name of the form "__imp_XYZ") and
// if so, it looks up the underlying target of the import symbol and
// returns it. An error is returned if the symbol is of the form
// "__imp_XYZ" but no XYZ can be found.
func LookupBaseFromImport(s loader.Sym, ldr *loader.Loader, arch *sys.Arch) (loader.Sym, error) {
	sname := ldr.SymName(s)
	if !strings.HasPrefix(sname, "__imp_") {
		return 0, nil
	}
	basename := sname[len("__imp_"):]
	if arch.Family == sys.I386 && basename[0] == '_' {
		basename = basename[1:] // _Name => Name
	}
	isym := ldr.Lookup(basename, 0)
	if isym == 0 {
		return 0, fmt.Errorf("internal error: import symbol %q with no underlying sym", sname)
	}
	return isym, nil
}

"""



```