Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Functionality:** The file name `deadcode.go` immediately suggests the purpose: dead code elimination. The package `ld` further hints that this is part of the linker (`link`).

2. **Examine the `deadcodePass` struct:**  This structure holds the state for the dead code elimination process. Key fields to notice are:
    * `ctxt *Link`, `ldr *loader.Loader`: Linker context and symbol loader – essential for interacting with the linking process and the symbols being linked.
    * `wq heap`:  A work queue, likely used for a graph traversal.
    * `ifaceMethod`, `genericIfaceMethod`: Maps to track interface methods called. This suggests handling of dynamic dispatch.
    * `markableMethods`:  A list of methods that *could* be called.
    * `reflectSeen`: A flag indicating whether reflection was encountered. This is a strong indicator of how reflection impacts dead code elimination.
    * `pkginits`: A list of package initialization functions.
    * `mapinitnoop`: A symbol representing a no-op function for map initialization.

3. **Analyze the `init` method:**  This method initializes the `deadcodePass`. Key actions:
    * Initializes reachability tracking within the loader (`d.ldr.InitReachable()`).
    * Handles different build modes (shared libraries, executables, plugins).
    * Identifies entry points (e.g., `main.main`, plugin entry points).
    * Marks initial symbols as reachable (entry points, `runtime.unreachableMethod`, plugin exports).
    * Handles dynamic exports and wasm exports.

4. **Analyze the `flood` method:** This is the core of the reachability analysis.
    * It uses the work queue (`d.wq`) to process reachable symbols.
    * **Key Logic:**  Iterates through relocations of a symbol to find other reachable symbols.
    * **Interface Method Handling:** Pays special attention to `R_METHODOFF`, `R_USEIFACE`, `R_USEIFACEMETHOD`, and `R_USENAMEDMETHOD` relocations, indicating interface usage.
    * **Reflection Handling:** Detects `d.ldr.IsReflectMethod(symIdx)` and sets `d.reflectSeen`.
    * **Type Information:**  Handles `R_USETYPE` and the `AuxGotype` auxiliary symbol type.
    * **Package Initialization:** Identifies and records package initialization functions.
    * **Outer/Sub Symbols:** Handles symbols with "carrier" or section-like behavior.
    * **Method Decoding:**  Decodes method signatures (`decodetypeMethods`).

5. **Analyze the `mapinitcleanup` method:**  This function specifically handles weak relocations to map initialization functions, rewriting them to a no-op if the target is unreachable. This highlights a specific optimization.

6. **Analyze the `mark` method:**  This is the workhorse for marking symbols as reachable and adding them to the work queue. It also handles dependency tracking if `flagDumpDep` is enabled.

7. **Analyze the `markMethod` method:**  Marks all parts of a method (mtyp, ifn, tfn) as reachable.

8. **Analyze the `deadcode` function:**  This is the main entry point for the dead code elimination pass.
    * Creates a `deadcodePass` instance.
    * Calls `init` and `flood` to perform the initial reachability analysis.
    * **Iterative Method Marking:**  It enters a loop that repeatedly checks and marks methods based on interface usage and reflection. This iterative approach is crucial because new types and methods might become reachable during the process.
    * Calls `mapinitcleanup` to handle weak map initialization relocations.

9. **Analyze Supporting Structures and Functions:**
    * `methodsig`: Represents a method signature (name and type).
    * `methodref`:  Holds information about a method and its location within a type's data.
    * `decode*` functions: Functions like `decodeMethodSig`, `decodeIfaceMethod`, `decodeGenericIfaceMethod`, and `decodetypeMethods` are responsible for extracting information from the symbol data based on Go's type layout.

10. **Infer Overall Functionality:** Based on the analysis, the core functionality is a **mark-and-sweep garbage collection algorithm specifically tailored for the linking phase of Go compilation**. It identifies and removes unused functions and data by starting from known entry points and recursively marking everything reachable. Special handling is included for interfaces, reflection, and package initialization.

11. **Consider Examples and Edge Cases:**
    * **Direct Function Call:** Easy to track through relocations.
    * **Interface Call:**  Requires identifying the interface type and then matching methods of concrete types against the interface's method set.
    * **Reflection:** Forces a more conservative approach, potentially keeping more code.
    * **Dynamic Linking:**  Similar to reflection, requires more conservative marking.
    * **Plugins:**  Need to consider symbols exported by plugins.
    * **Weak Relocations to Map Initialization:** A specific optimization to clean up unused map initialization code.

12. **Address Specific Questions from the Prompt:**
    * **Functionality Listing:** Summarize the main actions of the code.
    * **Go Feature Implementation:**  Focus on the interface and reflection handling aspects.
    * **Code Examples:**  Create simple Go code snippets demonstrating direct calls, interface calls, and reflection, showing how the dead code elimination might behave. Provide hypothetical inputs and outputs.
    * **Command-Line Arguments:** Look for usage of `flag` package variables (e.g., `*flagEntrySymbol`, `*flagPluginPath`, `*flagDumpDep`, `*flagPruneWeakMap`) and explain their purpose.
    * **Common Mistakes:**  Consider scenarios where the dead code elimination might behave unexpectedly (e.g., relying on reflection that the linker can't see).

This detailed breakdown allows for a comprehensive understanding of the code and the ability to answer the specific questions in the prompt. The process involves understanding the data structures, control flow, and how the code interacts with the Go linking process.
这段代码是 Go 语言链接器 `cmd/link` 的一部分，位于 `go/src/cmd/link/internal/ld/deadcode.go` 文件中。它的主要功能是**执行死代码消除（Dead Code Elimination）**，这是一个优化步骤，用于移除最终可执行文件中不会被执行到的代码和数据，从而减小文件大小并提高性能。

以下是该文件中的关键组成部分和功能的详细解释：

**1. `deadcodePass` 结构体：**

这个结构体用于存储死代码消除过程中的状态和数据。它包含了：

*   `ctxt *Link`:  链接器的上下文信息。
*   `ldr *loader.Loader`: 用于加载和访问程序符号的加载器。
*   `wq heap`:  一个工作队列（最小堆），用于存储待处理的符号索引，以进行广度优先或深度优先的遍历。
*   `ifaceMethod map[methodsig]bool`:  记录通过已访问的接口调用点调用的方法签名。
*   `genericIfaceMethod map[string]bool`: 记录通过已访问的泛型接口调用点调用的方法名称。
*   `markableMethods []methodref`:  存储已访问类型的可标记方法信息。
*   `reflectSeen bool`:  一个标志，指示是否遇到了反射相关的调用。
*   `dynlink bool`: 一个标志，指示是否正在进行动态链接。
*   `methodsigstmp []methodsig`:  用于解码方法签名的临时缓冲区。
*   `pkginits []loader.Sym`: 存储包初始化函数的符号索引。
*   `mapinitnoop loader.Sym`:  一个表示空操作的 map 初始化函数的符号索引。

**2. `init()` 方法：**

该方法初始化 `deadcodePass` 结构体，并标记程序执行的起始点。

*   初始化符号的可达性追踪 (`d.ldr.InitReachable()`)。
*   根据构建模式（共享库、可执行文件、插件等）确定初始可达符号。
*   对于普通的可执行文件，通常从 `main.main` 和 `main..inittask` 开始。
*   处理插件的入口点和导出符号。
*   标记 `runtime.unreachableMethod` 为可达，这是一个在调用到不可达方法时会抛出错误的函数。
*   标记动态导出和 WASM 导出符号为可达。

**3. `flood()` 方法：**

这是死代码消除的核心算法实现，它使用广度优先搜索（或类似机制）来遍历符号图，标记所有可达的符号。

*   从工作队列 `d.wq` 中取出待处理的符号。
*   **反射处理：** 如果遇到反射方法调用 (`d.ldr.IsReflectMethod(symIdx)`)，则设置 `d.reflectSeen` 标志。如果设置了此标志，则后续会保守地标记更多方法为可达。
*   **接口处理：**
    *   对于类型符号 (`isgotype`)，检查是否被用于接口 (`d.ldr.AttrUsedInIface(symIdx)`)。
    *   处理 `R_METHODOFF` 重定位，记录可标记的方法。
    *   处理 `R_USEIFACE` 重定位，标记作为接口使用的类型。
    *   处理 `R_USEIFACEMETHOD` 重定位，记录接口方法签名。
    *   处理 `R_USENAMEDMETHOD` 重定位，记录泛型接口方法名称。
*   **其他重定位处理：**  遍历符号的重定位信息，标记引用的其他符号为可达。
*   **辅助符号处理：** 遍历辅助符号，标记其引用的符号为可达。
*   **包初始化函数记录：** 记录包初始化函数。
*   **外部符号处理：** 处理外部对象符号。

**4. `mapinitcleanup()` 方法：**

此方法专门用于清理不再需要的 map 初始化代码。

*   遍历所有包初始化函数。
*   查找指向 `map.init` 函数的弱重定位。
*   如果 `map.init` 函数不可达，则将该弱重定位的目标重写为 `runtime.mapinitnoop`，这是一个空操作函数。这可以避免链接器保留未使用的 map 初始化代码。

**5. `mark()` 方法：**

用于将一个符号标记为可达，并将其添加到工作队列中，以便后续处理其重定位。

**6. `dumpDepAddFlags()` 方法：**

在调试模式下，用于向依赖关系输出添加额外的标志信息。

**7. `markMethod()` 方法：**

用于标记与方法相关的符号（方法类型、函数实现等）为可达。

**8. `deadcode()` 函数：**

这是死代码消除的主要入口点。

*   创建 `deadcodePass` 实例。
*   调用 `init()` 初始化。
*   调用 `flood()` 执行初始的可达性分析。
*   **迭代的方法标记：**  进入一个循环，迭代地标记可以通过接口调用的方法。这是因为在最初的 `flood()` 过程中，可能只标记了接口类型，而没有标记实现该接口的具体方法。这个循环会检查所有已访问类型的可标记方法，如果其签名与已访问的接口方法签名匹配，则将其标记为可达。
*   如果启用了弱 map 清理 (`*flagPruneWeakMap`)，则调用 `mapinitcleanup()`。
*   最终，所有未被标记为可达的文本符号（通常是函数）将被从链接器的文本段中移除。

**9. 其他辅助函数：**

*   `methodsig`:  表示方法签名的结构体。
*   `methodref`: 表示方法引用的结构体，包含方法签名、接收者类型符号和重定位索引。
*   `decodeMethodSig`, `decodeIfaceMethod`, `decodeGenericIfaceMethod`, `decodetypeMethods`: 这些函数用于解码符号数据，提取方法签名信息。这些解码操作依赖于 Go 语言的类型布局和元数据编码方式。

**它可以推理出是什么 Go 语言功能的实现：**

从代码中对接口（`R_USEIFACE`, `R_USEIFACEMETHOD`, `R_USENAMEDMETHOD`) 和反射 (`d.reflectSeen`, `d.ldr.IsReflectMethod`) 的处理来看，这段代码直接参与了 Go 语言**接口**和**反射**的实现。

**Go 代码示例说明：**

假设有以下 Go 代码：

```go
package main

import "fmt"

type MyInterface interface {
	MethodA()
}

type MyType struct{}

func (m MyType) MethodA() {
	fmt.Println("Method A called")
}

func unusedFunction() {
	fmt.Println("This function is never called")
}

func main() {
	var iface MyInterface = MyType{}
	iface.MethodA()
}
```

**假设输入：**  链接器正在处理编译后的 `main.o` 文件。

**推理和输出：**

1. **`init()`:** 链接器会标记 `main.main` 为可达的起点。
2. **`flood()`:**
    *   从 `main.main` 开始，会遍历其重定位信息。
    *   会找到创建 `MyType` 实例的指令，并标记 `MyType` 的类型信息为可达。
    *   会找到将 `MyType` 赋值给 `MyInterface` 的操作，并标记 `MyInterface` 的类型信息为可达 (通过 `R_USEIFACE` 重定位)。
    *   会找到调用 `iface.MethodA()` 的指令 (`R_CALLINTERFACE` 或类似的重定位)。这会触发对接口方法的分析。
    *   由于 `MyType` 实现了 `MyInterface` 的 `MethodA` 方法，`deadcodePass` 会记录 `MyType.MethodA` 的签名信息。
3. **迭代的方法标记：**
    *   在迭代过程中，`deadcodePass` 会检查 `MyType` 的可标记方法 (`MethodA`)。
    *   由于 `MethodA` 的签名与已记录的接口方法签名匹配，`MethodA` 会被标记为可达。
4. **最终结果：**
    *   `main.main`、`MyType` 的类型信息、`MyInterface` 的类型信息、`MyType.MethodA` 会被保留在最终的可执行文件中。
    *   `unusedFunction` 因为没有被任何可达的代码引用，会被识别为死代码并被移除。

**命令行参数的具体处理：**

在 `deadcode.go` 文件中，可以看到对一些全局变量（通常通过 `flag` 包定义）的使用，这些变量可能对应于链接器的命令行参数：

*   `*flagEntrySymbol`:  指定程序入口点的符号名称，通常是 "main.main"。
*   `*flagPluginPath`:  指定插件路径，用于处理插件相关的符号。
*   `*flagDumpDep`:  一个布尔标志，如果设置，会在死代码消除过程中输出符号依赖关系。
*   `*flagPruneWeakMap`: 一个布尔标志，如果设置，会启用弱 map 初始化代码的清理。

例如，如果用户使用以下命令进行链接：

```bash
go build -ldflags="-entry=my_custom_main" main.go
```

链接器会读取 `-entry=my_custom_main`，并将 `flagEntrySymbol` 的值设置为 `"my_custom_main"`。然后，`deadcodePass` 的 `init()` 方法会从 `my_custom_main` 开始进行可达性分析。

**使用者易犯错的点：**

虽然 `deadcode.go` 的代码本身是链接器的内部实现，普通 Go 开发者通常不会直接与之交互，但其背后的死代码消除机制的行为可能会导致一些误解或“错误”。

一个典型的例子是**过度依赖反射导致的意外代码保留**。

假设有以下代码：

```go
package main

import (
	"fmt"
	"reflect"
)

type MyType struct {
	Value string
}

func (m MyType) PublicMethod() {
	fmt.Println("Public method called")
}

func (m MyType) privateMethod() {
	fmt.Println("Private method called")
}

func main() {
	t := reflect.TypeOf(MyType{})
	method, _ := t.MethodByName("PublicMethod") // 使用常量字符串
	fmt.Println(method.Name)

	// 假设这里还有其他使用 MyType 的代码，但没有直接调用 privateMethod
}
```

在这个例子中，由于使用了 `reflect.TypeOf` 和 `MethodByName`，链接器的死代码消除器会更加保守：

*   如果 `MethodByName` 的参数是**常量字符串**（如 `"PublicMethod"`），链接器可以静态地分析出要调用的方法，并保留 `PublicMethod`。
*   但是，如果 `MethodByName` 的参数是**变量**，链接器通常无法在链接时确定具体要调用的方法。在这种情况下，为了保证程序的正确性，链接器可能会**保留 `MyType` 中所有导出的方法**。

**易犯错的点：**  开发者可能会认为 `privateMethod` 没有被直接调用，应该被死代码消除器移除。但在某些反射场景下，链接器可能会选择保留它，即使它在代码中看起来是“死的”。这可能会导致最终的可执行文件比预期的大。

总而言之，`deadcode.go` 文件实现了 Go 语言链接器中的死代码消除功能，通过静态分析程序的符号和重定位信息，识别并移除不会被执行到的代码和数据，从而优化最终的可执行文件。它对接口和反射的处理至关重要，并受到链接器命令行参数的影响。了解其工作原理可以帮助开发者更好地理解 Go 程序的构建过程和潜在的优化机会。

### 提示词
```
这是路径为go/src/cmd/link/internal/ld/deadcode.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ld

import (
	"cmd/internal/goobj"
	"cmd/internal/objabi"
	"cmd/internal/sys"
	"cmd/link/internal/loader"
	"cmd/link/internal/sym"
	"fmt"
	"internal/abi"
	"internal/buildcfg"
	"strings"
	"unicode"
)

var _ = fmt.Print

type deadcodePass struct {
	ctxt *Link
	ldr  *loader.Loader
	wq   heap // work queue, using min-heap for better locality

	ifaceMethod        map[methodsig]bool // methods called from reached interface call sites
	genericIfaceMethod map[string]bool    // names of methods called from reached generic interface call sites
	markableMethods    []methodref        // methods of reached types
	reflectSeen        bool               // whether we have seen a reflect method call
	dynlink            bool

	methodsigstmp []methodsig // scratch buffer for decoding method signatures
	pkginits      []loader.Sym
	mapinitnoop   loader.Sym
}

func (d *deadcodePass) init() {
	d.ldr.InitReachable()
	d.ifaceMethod = make(map[methodsig]bool)
	d.genericIfaceMethod = make(map[string]bool)
	if buildcfg.Experiment.FieldTrack {
		d.ldr.Reachparent = make([]loader.Sym, d.ldr.NSym())
	}
	d.dynlink = d.ctxt.DynlinkingGo()

	if d.ctxt.BuildMode == BuildModeShared {
		// Mark all symbols defined in this library as reachable when
		// building a shared library.
		n := d.ldr.NDef()
		for i := 1; i < n; i++ {
			s := loader.Sym(i)
			if d.ldr.SymType(s).IsText() && d.ldr.SymSize(s) == 0 {
				// Zero-sized text symbol is a function deadcoded by the
				// compiler. It doesn't really get compiled, and its
				// metadata may be missing.
				continue
			}
			d.mark(s, 0)
		}
		d.mark(d.ctxt.mainInittasks, 0)
		return
	}

	var names []string

	// In a normal binary, start at main.main and the init
	// functions and mark what is reachable from there.
	if d.ctxt.linkShared && (d.ctxt.BuildMode == BuildModeExe || d.ctxt.BuildMode == BuildModePIE) {
		names = append(names, "main.main", "main..inittask")
	} else {
		// The external linker refers main symbol directly.
		if d.ctxt.LinkMode == LinkExternal && (d.ctxt.BuildMode == BuildModeExe || d.ctxt.BuildMode == BuildModePIE) {
			if d.ctxt.HeadType == objabi.Hwindows && d.ctxt.Arch.Family == sys.I386 {
				*flagEntrySymbol = "_main"
			} else {
				*flagEntrySymbol = "main"
			}
		}
		names = append(names, *flagEntrySymbol)
	}
	// runtime.unreachableMethod is a function that will throw if called.
	// We redirect unreachable methods to it.
	names = append(names, "runtime.unreachableMethod")
	if d.ctxt.BuildMode == BuildModePlugin {
		names = append(names, objabi.PathToPrefix(*flagPluginPath)+"..inittask", objabi.PathToPrefix(*flagPluginPath)+".main", "go:plugin.tabs")

		// We don't keep the go.plugin.exports symbol,
		// but we do keep the symbols it refers to.
		exportsIdx := d.ldr.Lookup("go:plugin.exports", 0)
		if exportsIdx != 0 {
			relocs := d.ldr.Relocs(exportsIdx)
			for i := 0; i < relocs.Count(); i++ {
				d.mark(relocs.At(i).Sym(), 0)
			}
		}
	}

	if d.ctxt.Debugvlog > 1 {
		d.ctxt.Logf("deadcode start names: %v\n", names)
	}

	for _, name := range names {
		// Mark symbol as a data/ABI0 symbol.
		d.mark(d.ldr.Lookup(name, 0), 0)
		if abiInternalVer != 0 {
			// Also mark any Go functions (internal ABI).
			d.mark(d.ldr.Lookup(name, abiInternalVer), 0)
		}
	}

	// All dynamic exports are roots.
	for _, s := range d.ctxt.dynexp {
		if d.ctxt.Debugvlog > 1 {
			d.ctxt.Logf("deadcode start dynexp: %s<%d>\n", d.ldr.SymName(s), d.ldr.SymVersion(s))
		}
		d.mark(s, 0)
	}
	// So are wasmexports.
	for _, s := range d.ldr.WasmExports {
		if d.ctxt.Debugvlog > 1 {
			d.ctxt.Logf("deadcode start wasmexport: %s<%d>\n", d.ldr.SymName(s), d.ldr.SymVersion(s))
		}
		d.mark(s, 0)
	}

	d.mapinitnoop = d.ldr.Lookup("runtime.mapinitnoop", abiInternalVer)
	if d.mapinitnoop == 0 {
		panic("could not look up runtime.mapinitnoop")
	}
	if d.ctxt.mainInittasks != 0 {
		d.mark(d.ctxt.mainInittasks, 0)
	}
}

func (d *deadcodePass) flood() {
	var methods []methodref
	for !d.wq.empty() {
		symIdx := d.wq.pop()

		// Methods may be called via reflection. Give up on static analysis,
		// and mark all exported methods of all reachable types as reachable.
		d.reflectSeen = d.reflectSeen || d.ldr.IsReflectMethod(symIdx)

		isgotype := d.ldr.IsGoType(symIdx)
		relocs := d.ldr.Relocs(symIdx)
		var usedInIface bool

		if isgotype {
			if d.dynlink {
				// When dynamic linking, a type may be passed across DSO
				// boundary and get converted to interface at the other side.
				d.ldr.SetAttrUsedInIface(symIdx, true)
			}
			usedInIface = d.ldr.AttrUsedInIface(symIdx)
		}

		methods = methods[:0]
		for i := 0; i < relocs.Count(); i++ {
			r := relocs.At(i)
			if r.Weak() {
				convertWeakToStrong := false
				// When build with "-linkshared", we can't tell if the
				// interface method in itab will be used or not.
				// Ignore the weak attribute.
				if d.ctxt.linkShared && d.ldr.IsItab(symIdx) {
					convertWeakToStrong = true
				}
				// If the program uses plugins, we can no longer treat
				// relocs from pkg init functions to outlined map init
				// fragments as weak, since doing so can cause package
				// init clashes between the main program and the
				// plugin. See #62430 for more details.
				if d.ctxt.canUsePlugins && r.Type().IsDirectCall() {
					convertWeakToStrong = true
				}
				if !convertWeakToStrong {
					// skip this reloc
					continue
				}
			}
			t := r.Type()
			switch t {
			case objabi.R_METHODOFF:
				if i+2 >= relocs.Count() {
					panic("expect three consecutive R_METHODOFF relocs")
				}
				if usedInIface {
					methods = append(methods, methodref{src: symIdx, r: i})
					// The method descriptor is itself a type descriptor, and
					// it can be used to reach other types, e.g. by using
					// reflect.Type.Method(i).Type.In(j). We need to traverse
					// its child types with UsedInIface set. (See also the
					// comment below.)
					rs := r.Sym()
					if !d.ldr.AttrUsedInIface(rs) {
						d.ldr.SetAttrUsedInIface(rs, true)
						if d.ldr.AttrReachable(rs) {
							d.ldr.SetAttrReachable(rs, false)
							d.mark(rs, symIdx)
						}
					}
				}
				i += 2
				continue
			case objabi.R_USETYPE:
				// type symbol used for DWARF. we need to load the symbol but it may not
				// be otherwise reachable in the program.
				// do nothing for now as we still load all type symbols.
				continue
			case objabi.R_USEIFACE:
				// R_USEIFACE is a marker relocation that tells the linker the type is
				// converted to an interface, i.e. should have UsedInIface set. See the
				// comment below for why we need to unset the Reachable bit and re-mark it.
				rs := r.Sym()
				if d.ldr.IsItab(rs) {
					// This relocation can also point at an itab, in which case it
					// means "the Type field of that itab".
					rs = decodeItabType(d.ldr, d.ctxt.Arch, rs)
				}
				if !d.ldr.IsGoType(rs) && !d.ctxt.linkShared {
					panic(fmt.Sprintf("R_USEIFACE in %s references %s which is not a type or itab", d.ldr.SymName(symIdx), d.ldr.SymName(rs)))
				}
				if !d.ldr.AttrUsedInIface(rs) {
					d.ldr.SetAttrUsedInIface(rs, true)
					if d.ldr.AttrReachable(rs) {
						d.ldr.SetAttrReachable(rs, false)
						d.mark(rs, symIdx)
					}
				}
				continue
			case objabi.R_USEIFACEMETHOD:
				// R_USEIFACEMETHOD is a marker relocation that marks an interface
				// method as used.
				rs := r.Sym()
				if d.ctxt.linkShared && (d.ldr.SymType(rs) == sym.SDYNIMPORT || d.ldr.SymType(rs) == sym.Sxxx) {
					// Don't decode symbol from shared library (we'll mark all exported methods anyway).
					// We check for both SDYNIMPORT and Sxxx because name-mangled symbols haven't
					// been resolved at this point.
					continue
				}
				m := d.decodeIfaceMethod(d.ldr, d.ctxt.Arch, rs, r.Add())
				if d.ctxt.Debugvlog > 1 {
					d.ctxt.Logf("reached iface method: %v\n", m)
				}
				d.ifaceMethod[m] = true
				continue
			case objabi.R_USENAMEDMETHOD:
				name := d.decodeGenericIfaceMethod(d.ldr, r.Sym())
				if d.ctxt.Debugvlog > 1 {
					d.ctxt.Logf("reached generic iface method: %s\n", name)
				}
				d.genericIfaceMethod[name] = true
				continue // don't mark referenced symbol - it is not needed in the final binary.
			case objabi.R_INITORDER:
				// inittasks has already run, so any R_INITORDER links are now
				// superfluous - the only live inittask records are those which are
				// in a scheduled list somewhere (e.g. runtime.moduledata.inittasks).
				continue
			}
			rs := r.Sym()
			if isgotype && usedInIface && d.ldr.IsGoType(rs) && !d.ldr.AttrUsedInIface(rs) {
				// If a type is converted to an interface, it is possible to obtain an
				// interface with a "child" type of it using reflection (e.g. obtain an
				// interface of T from []chan T). We need to traverse its "child" types
				// with UsedInIface attribute set.
				// When visiting the child type (chan T in the example above), it will
				// have UsedInIface set, so it in turn will mark and (re)visit its children
				// (e.g. T above).
				// We unset the reachable bit here, so if the child type is already visited,
				// it will be visited again.
				// Note that a type symbol can be visited at most twice, one without
				// UsedInIface and one with. So termination is still guaranteed.
				d.ldr.SetAttrUsedInIface(rs, true)
				d.ldr.SetAttrReachable(rs, false)
			}
			d.mark(rs, symIdx)
		}
		naux := d.ldr.NAux(symIdx)
		for i := 0; i < naux; i++ {
			a := d.ldr.Aux(symIdx, i)
			if a.Type() == goobj.AuxGotype {
				// A symbol being reachable doesn't imply we need its
				// type descriptor. Don't mark it.
				continue
			}
			d.mark(a.Sym(), symIdx)
		}
		// Record sym if package init func (here naux != 0 is a cheap way
		// to check first if it is a function symbol).
		if naux != 0 && d.ldr.IsPkgInit(symIdx) {

			d.pkginits = append(d.pkginits, symIdx)
		}
		// Some host object symbols have an outer object, which acts like a
		// "carrier" symbol, or it holds all the symbols for a particular
		// section. We need to mark all "referenced" symbols from that carrier,
		// so we make sure we're pulling in all outer symbols, and their sub
		// symbols. This is not ideal, and these carrier/section symbols could
		// be removed.
		if d.ldr.IsExternal(symIdx) {
			d.mark(d.ldr.OuterSym(symIdx), symIdx)
			d.mark(d.ldr.SubSym(symIdx), symIdx)
		}

		if len(methods) != 0 {
			if !isgotype {
				panic("method found on non-type symbol")
			}
			// Decode runtime type information for type methods
			// to help work out which methods can be called
			// dynamically via interfaces.
			methodsigs := d.decodetypeMethods(d.ldr, d.ctxt.Arch, symIdx, &relocs)
			if len(methods) != len(methodsigs) {
				panic(fmt.Sprintf("%q has %d method relocations for %d methods", d.ldr.SymName(symIdx), len(methods), len(methodsigs)))
			}
			for i, m := range methodsigs {
				methods[i].m = m
				if d.ctxt.Debugvlog > 1 {
					d.ctxt.Logf("markable method: %v of sym %v %s\n", m, symIdx, d.ldr.SymName(symIdx))
				}
			}
			d.markableMethods = append(d.markableMethods, methods...)
		}
	}
}

// mapinitcleanup walks all pkg init functions and looks for weak relocations
// to mapinit symbols that are no longer reachable. It rewrites
// the relocs to target a new no-op routine in the runtime.
func (d *deadcodePass) mapinitcleanup() {
	for _, idx := range d.pkginits {
		relocs := d.ldr.Relocs(idx)
		var su *loader.SymbolBuilder
		for i := 0; i < relocs.Count(); i++ {
			r := relocs.At(i)
			rs := r.Sym()
			if r.Weak() && r.Type().IsDirectCall() && !d.ldr.AttrReachable(rs) {
				// double check to make sure target is indeed map.init
				rsn := d.ldr.SymName(rs)
				if !strings.Contains(rsn, "map.init") {
					panic(fmt.Sprintf("internal error: expected map.init sym for weak call reloc, got %s -> %s", d.ldr.SymName(idx), rsn))
				}
				d.ldr.SetAttrReachable(d.mapinitnoop, true)
				if d.ctxt.Debugvlog > 1 {
					d.ctxt.Logf("deadcode: %s rewrite %s ref to %s\n",
						d.ldr.SymName(idx), rsn,
						d.ldr.SymName(d.mapinitnoop))
				}
				if su == nil {
					su = d.ldr.MakeSymbolUpdater(idx)
				}
				su.SetRelocSym(i, d.mapinitnoop)
			}
		}
	}
}

func (d *deadcodePass) mark(symIdx, parent loader.Sym) {
	if symIdx != 0 && !d.ldr.AttrReachable(symIdx) {
		d.wq.push(symIdx)
		d.ldr.SetAttrReachable(symIdx, true)
		if buildcfg.Experiment.FieldTrack && d.ldr.Reachparent[symIdx] == 0 {
			d.ldr.Reachparent[symIdx] = parent
		}
		if *flagDumpDep {
			to := d.ldr.SymName(symIdx)
			if to != "" {
				to = d.dumpDepAddFlags(to, symIdx)
				from := "_"
				if parent != 0 {
					from = d.ldr.SymName(parent)
					from = d.dumpDepAddFlags(from, parent)
				}
				fmt.Printf("%s -> %s\n", from, to)
			}
		}
	}
}

func (d *deadcodePass) dumpDepAddFlags(name string, symIdx loader.Sym) string {
	var flags strings.Builder
	if d.ldr.AttrUsedInIface(symIdx) {
		flags.WriteString("<UsedInIface>")
	}
	if d.ldr.IsReflectMethod(symIdx) {
		flags.WriteString("<ReflectMethod>")
	}
	if flags.Len() > 0 {
		return name + " " + flags.String()
	}
	return name
}

func (d *deadcodePass) markMethod(m methodref) {
	relocs := d.ldr.Relocs(m.src)
	d.mark(relocs.At(m.r).Sym(), m.src)
	d.mark(relocs.At(m.r+1).Sym(), m.src)
	d.mark(relocs.At(m.r+2).Sym(), m.src)
}

// deadcode marks all reachable symbols.
//
// The basis of the dead code elimination is a flood fill of symbols,
// following their relocations, beginning at *flagEntrySymbol.
//
// This flood fill is wrapped in logic for pruning unused methods.
// All methods are mentioned by relocations on their receiver's *rtype.
// These relocations are specially defined as R_METHODOFF by the compiler
// so we can detect and manipulated them here.
//
// There are three ways a method of a reachable type can be invoked:
//
//  1. direct call
//  2. through a reachable interface type
//  3. reflect.Value.Method (or MethodByName), or reflect.Type.Method
//     (or MethodByName)
//
// The first case is handled by the flood fill, a directly called method
// is marked as reachable.
//
// The second case is handled by decomposing all reachable interface
// types into method signatures. Each encountered method is compared
// against the interface method signatures, if it matches it is marked
// as reachable. This is extremely conservative, but easy and correct.
//
// The third case is handled by looking for functions that compiler flagged
// as REFLECTMETHOD. REFLECTMETHOD on a function F means that F does a method
// lookup with reflection, but the compiler was not able to statically determine
// the method name.
//
// All functions that call reflect.Value.Method or reflect.Type.Method are REFLECTMETHODs.
// Functions that call reflect.Value.MethodByName or reflect.Type.MethodByName with
// a non-constant argument are REFLECTMETHODs, too. If we find a REFLECTMETHOD,
// we give up on static analysis, and mark all exported methods of all reachable
// types as reachable.
//
// If the argument to MethodByName is a compile-time constant, the compiler
// emits a relocation with the method name. Matching methods are kept in all
// reachable types.
//
// Any unreached text symbols are removed from ctxt.Textp.
func deadcode(ctxt *Link) {
	ldr := ctxt.loader
	d := deadcodePass{ctxt: ctxt, ldr: ldr}
	d.init()
	d.flood()

	if ctxt.DynlinkingGo() {
		// Exported methods may satisfy interfaces we don't know
		// about yet when dynamically linking.
		d.reflectSeen = true
	}

	for {
		// Mark all methods that could satisfy a discovered
		// interface as reachable. We recheck old marked interfaces
		// as new types (with new methods) may have been discovered
		// in the last pass.
		rem := d.markableMethods[:0]
		for _, m := range d.markableMethods {
			if (d.reflectSeen && (m.isExported() || d.dynlink)) || d.ifaceMethod[m.m] || d.genericIfaceMethod[m.m.name] {
				d.markMethod(m)
			} else {
				rem = append(rem, m)
			}
		}
		d.markableMethods = rem

		if d.wq.empty() {
			// No new work was discovered. Done.
			break
		}
		d.flood()
	}
	if *flagPruneWeakMap {
		d.mapinitcleanup()
	}
}

// methodsig is a typed method signature (name + type).
type methodsig struct {
	name string
	typ  loader.Sym // type descriptor symbol of the function
}

// methodref holds the relocations from a receiver type symbol to its
// method. There are three relocations, one for each of the fields in
// the reflect.method struct: mtyp, ifn, and tfn.
type methodref struct {
	m   methodsig
	src loader.Sym // receiver type symbol
	r   int        // the index of R_METHODOFF relocations
}

func (m methodref) isExported() bool {
	for _, r := range m.m.name {
		return unicode.IsUpper(r)
	}
	panic("methodref has no signature")
}

// decodeMethodSig decodes an array of method signature information.
// Each element of the array is size bytes. The first 4 bytes is a
// nameOff for the method name, and the next 4 bytes is a typeOff for
// the function type.
//
// Conveniently this is the layout of both runtime.method and runtime.imethod.
func (d *deadcodePass) decodeMethodSig(ldr *loader.Loader, arch *sys.Arch, symIdx loader.Sym, relocs *loader.Relocs, off, size, count int) []methodsig {
	if cap(d.methodsigstmp) < count {
		d.methodsigstmp = append(d.methodsigstmp[:0], make([]methodsig, count)...)
	}
	var methods = d.methodsigstmp[:count]
	for i := 0; i < count; i++ {
		methods[i].name = decodetypeName(ldr, symIdx, relocs, off)
		methods[i].typ = decodeRelocSym(ldr, symIdx, relocs, int32(off+4))
		off += size
	}
	return methods
}

// Decode the method of interface type symbol symIdx at offset off.
func (d *deadcodePass) decodeIfaceMethod(ldr *loader.Loader, arch *sys.Arch, symIdx loader.Sym, off int64) methodsig {
	p := ldr.Data(symIdx)
	if p == nil {
		panic(fmt.Sprintf("missing symbol %q", ldr.SymName(symIdx)))
	}
	if decodetypeKind(arch, p) != abi.Interface {
		panic(fmt.Sprintf("symbol %q is not an interface", ldr.SymName(symIdx)))
	}
	relocs := ldr.Relocs(symIdx)
	var m methodsig
	m.name = decodetypeName(ldr, symIdx, &relocs, int(off))
	m.typ = decodeRelocSym(ldr, symIdx, &relocs, int32(off+4))
	return m
}

// Decode the method name stored in symbol symIdx. The symbol should contain just the bytes of a method name.
func (d *deadcodePass) decodeGenericIfaceMethod(ldr *loader.Loader, symIdx loader.Sym) string {
	return ldr.DataString(symIdx)
}

func (d *deadcodePass) decodetypeMethods(ldr *loader.Loader, arch *sys.Arch, symIdx loader.Sym, relocs *loader.Relocs) []methodsig {
	p := ldr.Data(symIdx)
	if !decodetypeHasUncommon(arch, p) {
		panic(fmt.Sprintf("no methods on %q", ldr.SymName(symIdx)))
	}
	off := commonsize(arch) // reflect.rtype
	switch decodetypeKind(arch, p) {
	case abi.Struct: // reflect.structType
		off += 4 * arch.PtrSize
	case abi.Pointer: // reflect.ptrType
		off += arch.PtrSize
	case abi.Func: // reflect.funcType
		off += arch.PtrSize // 4 bytes, pointer aligned
	case abi.Slice: // reflect.sliceType
		off += arch.PtrSize
	case abi.Array: // reflect.arrayType
		off += 3 * arch.PtrSize
	case abi.Chan: // reflect.chanType
		off += 2 * arch.PtrSize
	case abi.Map:
		if buildcfg.Experiment.SwissMap {
			off += 7*arch.PtrSize + 4 // internal/abi.SwissMapType
			if arch.PtrSize == 8 {
				off += 4 // padding for final uint32 field (Flags).
			}
		} else {
			off += 4*arch.PtrSize + 8 // internal/abi.OldMapType
		}
	case abi.Interface: // reflect.interfaceType
		off += 3 * arch.PtrSize
	default:
		// just Sizeof(rtype)
	}

	mcount := int(decodeInuxi(arch, p[off+4:], 2))
	moff := int(decodeInuxi(arch, p[off+4+2+2:], 4))
	off += moff                // offset to array of reflect.method values
	const sizeofMethod = 4 * 4 // sizeof reflect.method in program
	return d.decodeMethodSig(ldr, arch, symIdx, relocs, off, sizeofMethod, mcount)
}
```